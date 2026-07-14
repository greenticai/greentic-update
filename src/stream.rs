//! Server-Sent Events (SSE) transport for plan-update notifications.
//!
//! A blocking SSE client that receives `"plan"` events pushed by the update
//! server and hands each parsed [`PlanEvent`] to a caller-supplied callback.
//! The event is a **hint** — it carries no plan bytes. The caller reacts by
//! running its normal verified fetch.
//!
//! ## Why `build_stream_client` exists
//!
//! greentic-start's poll loop builds `reqwest::blocking::Client::builder()
//! .timeout(30s)`. In reqwest, `.timeout()` is a **total-request** timeout
//! that includes body read. Reusing that client for an SSE stream kills the
//! connection every 30 seconds, forever, presenting as a flaky server rather
//! than a client bug. `build_stream_client` therefore disables the total
//! timeout and sets only a connect timeout, so the long-lived body read is
//! never artificially interrupted.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::io::{self, BufRead, Read};
use std::ops::ControlFlow;
use std::time::Duration;

use serde::Deserialize;
use thiserror::Error;

/// Schema identifier carried by every [`PlanEvent`]. Receivers must ignore
/// events whose schema does not match this constant so that forward-compatible
/// schema bumps degrade gracefully.
pub const UPDATE_EVENT_SCHEMA_V1: &str = "greentic.update-event.v1";

/// Maximum accumulated `data:` bytes per frame before the frame is discarded.
/// Guards against a rogue or buggy server growing memory without bound.
const MAX_FRAME_DATA_BYTES: usize = 64 * 1024;

/// Maximum bytes in a single SSE line before it is treated as oversize and
/// discarded.  The reader never buffers more than this + 1 bytes for any
/// single line, so a server sending an unterminated multi-gigabyte line
/// cannot OOM the runtime.
const MAX_LINE_BYTES: usize = 64 * 1024;

// ── Public types ────────────────────────────────────────────────────

/// A plan-update notification pushed by the server.
///
/// Deliberately carries **no** plan bytes — the receiver treats it as a hint
/// and re-runs its normal verified fetch.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct PlanEvent {
    /// Schema identifier (expected: [`UPDATE_EVENT_SCHEMA_V1`]).
    pub schema: String,
    /// Environment this event applies to.
    pub env_id: String,
    /// Monotonically increasing sequence number (server-assigned).
    pub sequence: u64,
    /// Hex-encoded SHA-256 of the canonical plan bytes.
    pub plan_sha256: String,
}

/// A single parsed SSE frame, dispatched on a blank line.
#[derive(Clone, Debug, Default)]
pub struct SseFrame {
    /// The `id:` field, if present.
    pub id: Option<String>,
    /// The `event:` field, if present.
    pub event: Option<String>,
    /// Accumulated `data:` payload (multiple `data:` lines joined with `\n`).
    pub data: String,
}

/// Why a stream operation failed.
#[derive(Debug, Error)]
pub enum StreamError {
    /// The server returned a non-2xx status.
    #[error("server returned HTTP {status}")]
    Status { status: u16 },
    /// The server does not implement the stream endpoint (HTTP 404 or 501).
    /// This is terminal — the caller should fall back to polling rather than
    /// retrying.
    #[error("stream endpoint not supported by this server (HTTP {status})")]
    Unsupported { status: u16 },
    /// HTTP transport failure (connect, TLS, DNS).
    #[error("HTTP request failed: {0}")]
    Http(String),
}

/// Exponential backoff with jitter, capped at a configured maximum.
///
/// Call [`Backoff::reset`] after a successful connect to return to the floor.
pub struct Backoff {
    max: Duration,
    current: Duration,
    /// Per-instance seed derived from `RandomState` so that concurrent
    /// processes jitter independently without a PRNG dependency.
    jitter_seed: u64,
}

impl Backoff {
    /// Create a new backoff starting at 1 second, capped at `max`.
    pub fn new(max: Duration) -> Self {
        // `RandomState::new()` is seeded per-process from the OS, so each
        // `Backoff` instance gets an independent jitter seed.
        let seed = RandomState::new().build_hasher().finish();
        Self {
            max,
            current: Duration::from_secs(1),
            jitter_seed: seed,
        }
    }

    /// Reset the delay back to the 1-second floor.
    pub fn reset(&mut self) {
        self.current = Duration::from_secs(1);
    }

    /// Return the next delay and advance the internal state.
    ///
    /// The raw delay doubles each call (capped at `max`). A jitter of up to
    /// 25 % of the raw delay is added to avoid thundering-herd reconnects.
    pub fn next_delay(&mut self) -> Duration {
        let base = self.current.min(self.max);
        self.current = (self.current * 2).min(self.max);
        // Mix the per-instance seed with the current step to produce jitter
        // that varies across processes without pulling in a PRNG crate.
        self.jitter_seed = self
            .jitter_seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1);
        let frac = (self.jitter_seed >> 33) % 250; // 0..249 → 0.0%..24.9%
        let jitter = base * frac as u32 / 1000;
        base + jitter
    }
}

// ── Client construction ─────────────────────────────────────────────

/// Build a dedicated blocking HTTP client for long-lived SSE streams.
///
/// **DO NOT** reuse the caller's request client here. reqwest's `.timeout()`
/// is a *total-request* timeout that includes body read — a 30-second timeout
/// kills the stream every 30 seconds, forever. This client sets NO total
/// timeout and only a connect timeout so the long-lived body read proceeds
/// uninterrupted. reqwest 0.13's blocking builder does not expose a separate
/// read timeout, so idle-stream detection relies on the server's keepalive
/// comments (`:` lines every ~20 s) and the OS TCP keepalive.
pub fn build_stream_client() -> Result<reqwest::blocking::Client, StreamError> {
    reqwest::blocking::Client::builder()
        .timeout(None) // no total-request timeout — the stream is unbounded
        .connect_timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| StreamError::Http(e.to_string()))
}

// ── Frame parsing ───────────────────────────────────────────────────

/// Parse SSE frames from a byte reader until EOF or the callback breaks.
///
/// Implements the subset of the SSE spec required by this protocol:
/// - `data:`, `id:`, `event:` fields (one leading space after colon stripped).
/// - Lines starting with `:` are comments (keepalive) and are ignored.
/// - Unknown field names are ignored.
/// - A blank line dispatches the accumulated frame.
/// - Multiple `data:` lines are joined with `\n`.
/// - Frames whose accumulated data exceeds [`MAX_FRAME_DATA_BYTES`] are
///   discarded (not dispatched).
///
/// Each line is read with a bounded `read_until` capped at
/// [`MAX_LINE_BYTES`], so a server sending an unterminated multi-gigabyte
/// line cannot grow the reader's buffer past ~64 KiB.  Lines that exceed
/// the cap are drained to the next newline in bounded chunks and the
/// current frame is marked oversize.  Non-UTF-8 lines are silently
/// skipped rather than erroring the stream.
pub fn read_frames<R: BufRead>(
    mut reader: R,
    mut on_frame: impl FnMut(SseFrame) -> ControlFlow<()>,
) -> io::Result<()> {
    let mut frame = SseFrame::default();
    let mut oversize = false;
    let mut line_buf = Vec::with_capacity(1024);

    loop {
        line_buf.clear();
        let n = reader
            .by_ref()
            .take(MAX_LINE_BYTES as u64 + 1)
            .read_until(b'\n', &mut line_buf)?;
        if n == 0 {
            break;
        }

        if line_buf.len() > MAX_LINE_BYTES && !line_buf.ends_with(b"\n") {
            loop {
                let buf = reader.fill_buf()?;
                if buf.is_empty() {
                    break;
                }
                if let Some(pos) = buf.iter().position(|&b| b == b'\n') {
                    reader.consume(pos + 1);
                    break;
                }
                let len = buf.len();
                reader.consume(len);
            }
            oversize = true;
            frame = SseFrame::default();
            continue;
        }

        if line_buf.last() == Some(&b'\n') {
            line_buf.pop();
        }
        if line_buf.last() == Some(&b'\r') {
            line_buf.pop();
        }

        let Ok(line) = std::str::from_utf8(&line_buf) else {
            continue;
        };

        // Blank line → dispatch accumulated frame.
        if line.is_empty() {
            if !oversize && !frame.data.is_empty() && on_frame(frame) == ControlFlow::Break(()) {
                return Ok(());
            }
            frame = SseFrame::default();
            oversize = false;
            continue;
        }

        // Comment line (keepalive).
        if line.starts_with(':') {
            continue;
        }

        // Split on the first colon.
        let Some(colon) = line.find(':') else {
            // No colon — ignore per spec.
            continue;
        };
        let field = &line[..colon];
        // Strip exactly one leading space after the colon, if present.
        let value = &line[colon + 1..];
        let value = value.strip_prefix(' ').unwrap_or(value);

        if oversize {
            // Already oversize — keep draining lines until the blank-line reset.
            continue;
        }

        match field {
            "data" => {
                if !frame.data.is_empty() {
                    frame.data.push('\n');
                }
                frame.data.push_str(value);
                if frame.data.len() > MAX_FRAME_DATA_BYTES {
                    oversize = true;
                    frame = SseFrame::default();
                }
            }
            "id" => {
                frame.id = Some(value.to_string());
            }
            "event" => {
                frame.event = Some(value.to_string());
            }
            _ => {
                // Unknown field — ignore.
            }
        }
    }
    Ok(())
}

// ── Connect-and-read ────────────────────────────────────────────────

/// Execute one connect-and-read pass against the SSE endpoint.
///
/// Sends `Accept: text/event-stream` and, when `last_event_id` is `Some`,
/// the `Last-Event-ID` header so the server can replay missed events.
///
/// Only frames with `event: plan` are acted upon. Malformed JSON or a
/// mismatched `schema` causes the individual event to be skipped — the
/// stream stays open.
pub fn connect_and_read(
    client: &reqwest::blocking::Client,
    endpoint: &str,
    last_event_id: Option<u64>,
    mut on_plan: impl FnMut(PlanEvent) -> ControlFlow<()>,
) -> Result<(), StreamError> {
    let mut req = client.get(endpoint).header("Accept", "text/event-stream");

    if let Some(id) = last_event_id {
        req = req.header("Last-Event-ID", id.to_string());
    }

    let resp = req.send().map_err(|e| StreamError::Http(e.to_string()))?;

    let status = resp.status();
    if !status.is_success() {
        let code = status.as_u16();
        if code == 404 || code == 501 {
            return Err(StreamError::Unsupported { status: code });
        }
        return Err(StreamError::Status { status: code });
    }

    let reader = io::BufReader::new(resp);
    read_frames(reader, |frame| {
        // Only act on `event: plan` frames.
        if frame.event.as_deref() != Some("plan") {
            return ControlFlow::Continue(());
        }
        // Parse the JSON payload; skip on failure.
        let Ok(event) = serde_json::from_str::<PlanEvent>(&frame.data) else {
            return ControlFlow::Continue(());
        };
        // Skip events whose schema we don't understand.
        if event.schema != UPDATE_EVENT_SCHEMA_V1 {
            return ControlFlow::Continue(());
        }
        on_plan(event)
    })
    .map_err(|e| StreamError::Http(e.to_string()))?;

    Ok(())
}

// ── Reconnect loop ─────────────────────────────────────────────

/// Reconnecting SSE event loop that owns the resume cursor and backoff.
///
/// Each iteration calls [`connect_and_read`], advancing `cursor` to the
/// highest `sequence` seen.  On any return (error, timeout, clean EOF):
///
/// 1. If `on_plan` returned [`ControlFlow::Break`], return `Ok(())`.
/// 2. Reset the backoff if at least one event was delivered (a connection
///    that fails immediately does **not** reset — this prevents a flapping
///    server from resetting the backoff on every failed handshake).
/// 3. If `should_stop()`, return `Ok(())`.
/// 4. Sleep `Backoff::next_delay()`, then reconnect with the cursor as
///    `Last-Event-ID`.
pub fn run_stream(
    client: &reqwest::blocking::Client,
    endpoint: &str,
    from_sequence: Option<u64>,
    should_stop: impl Fn() -> bool,
    mut on_plan: impl FnMut(PlanEvent) -> ControlFlow<()>,
) -> Result<(), StreamError> {
    let mut cursor = from_sequence;
    let mut backoff = Backoff::new(Duration::from_secs(60));

    loop {
        if should_stop() {
            return Ok(());
        }

        let mut delivered_any = false;
        let mut consumer_break = false;

        let result = connect_and_read(client, endpoint, cursor, |event| {
            cursor = Some(cursor.map_or(event.sequence, |c| c.max(event.sequence)));
            delivered_any = true;
            match on_plan(event) {
                ControlFlow::Continue(()) => ControlFlow::Continue(()),
                ControlFlow::Break(()) => {
                    consumer_break = true;
                    ControlFlow::Break(())
                }
            }
        });

        if consumer_break {
            return Ok(());
        }

        if result.is_err() {
            return result;
        }

        if delivered_any {
            backoff.reset();
        }

        if should_stop() {
            return Ok(());
        }

        std::thread::sleep(backoff.next_delay());
    }
}

// ── Tests ───────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    // ── Frame parsing ───────────────────────────────────────────────

    #[test]
    fn single_frame() {
        let input = "data: hello\n\n";
        let mut frames = Vec::new();
        read_frames(Cursor::new(input), |f| {
            frames.push(f);
            ControlFlow::Continue(())
        })
        .unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].data, "hello");
        assert!(frames[0].id.is_none());
        assert!(frames[0].event.is_none());
    }

    #[test]
    fn multi_line_data() {
        let input = "data: line1\ndata: line2\ndata: line3\n\n";
        let mut frames = Vec::new();
        read_frames(Cursor::new(input), |f| {
            frames.push(f);
            ControlFlow::Continue(())
        })
        .unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].data, "line1\nline2\nline3");
    }

    #[test]
    fn comment_and_keepalive_ignored() {
        let input = ": keepalive\ndata: payload\n: another comment\n\n";
        let mut frames = Vec::new();
        read_frames(Cursor::new(input), |f| {
            frames.push(f);
            ControlFlow::Continue(())
        })
        .unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].data, "payload");
    }

    #[test]
    fn id_and_event_captured() {
        let input = "id: 42\nevent: plan\ndata: {}\n\n";
        let mut frames = Vec::new();
        read_frames(Cursor::new(input), |f| {
            frames.push(f);
            ControlFlow::Continue(())
        })
        .unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].id.as_deref(), Some("42"));
        assert_eq!(frames[0].event.as_deref(), Some("plan"));
        assert_eq!(frames[0].data, "{}");
    }

    #[test]
    fn one_leading_space_stripped() {
        // Exactly one leading space after the colon must be stripped.
        let input = "data:  two spaces\n\n";
        let mut frames = Vec::new();
        read_frames(Cursor::new(input), |f| {
            frames.push(f);
            ControlFlow::Continue(())
        })
        .unwrap();
        assert_eq!(frames[0].data, " two spaces");
    }

    #[test]
    fn no_space_after_colon() {
        let input = "data:nospace\n\n";
        let mut frames = Vec::new();
        read_frames(Cursor::new(input), |f| {
            frames.push(f);
            ControlFlow::Continue(())
        })
        .unwrap();
        assert_eq!(frames[0].data, "nospace");
    }

    #[test]
    fn unknown_fields_ignored() {
        let input = "data: hello\nfoo: bar\nbaz: qux\n\n";
        let mut frames = Vec::new();
        read_frames(Cursor::new(input), |f| {
            frames.push(f);
            ControlFlow::Continue(())
        })
        .unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].data, "hello");
    }

    #[test]
    fn blank_line_dispatches_and_resets() {
        let input = "data: first\n\ndata: second\n\n";
        let mut frames = Vec::new();
        read_frames(Cursor::new(input), |f| {
            frames.push(f);
            ControlFlow::Continue(())
        })
        .unwrap();
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].data, "first");
        assert_eq!(frames[1].data, "second");
    }

    #[test]
    fn frame_split_across_read_chunks_one_byte_at_a_time() {
        // Feed `read_frames` a Read impl that yields ONE BYTE AT A TIME.
        // This is the classic SSE parsing bug: a naive parser that reads until
        // newline in a single `read_line` call may silently lose data when the
        // OS delivers a partial line.
        struct OneByteReader<'a> {
            data: &'a [u8],
            pos: usize,
        }
        impl io::Read for OneByteReader<'_> {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                if self.pos >= self.data.len() {
                    return Ok(0);
                }
                buf[0] = self.data[self.pos];
                self.pos += 1;
                Ok(1)
            }
        }

        let raw = b"id: 7\nevent: plan\ndata: {\"schema\":\"greentic.update-event.v1\",\"env_id\":\"prod\",\"sequence\":7,\"plan_sha256\":\"abcd\"}\n\n";
        let reader = io::BufReader::new(OneByteReader { data: raw, pos: 0 });

        let mut frames = Vec::new();
        read_frames(reader, |f| {
            frames.push(f);
            ControlFlow::Continue(())
        })
        .unwrap();

        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].id.as_deref(), Some("7"));
        assert_eq!(frames[0].event.as_deref(), Some("plan"));
        let event: PlanEvent = serde_json::from_str(&frames[0].data).unwrap();
        assert_eq!(event.env_id, "prod");
        assert_eq!(event.sequence, 7);
    }

    #[test]
    fn oversize_frame_skipped() {
        // Build a frame whose data exceeds MAX_FRAME_DATA_BYTES.
        let big = "x".repeat(MAX_FRAME_DATA_BYTES + 1);
        let input = format!("data: {big}\n\ndata: ok\n\n");
        let mut frames = Vec::new();
        read_frames(Cursor::new(input.as_bytes()), |f| {
            frames.push(f);
            ControlFlow::Continue(())
        })
        .unwrap();
        // The oversize frame is skipped; the follow-up frame is delivered.
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].data, "ok");
    }

    #[test]
    fn plan_event_deserialization() {
        let json = r#"{"schema":"greentic.update-event.v1","env_id":"staging","sequence":42,"plan_sha256":"deadbeef"}"#;
        let event: PlanEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.schema, UPDATE_EVENT_SCHEMA_V1);
        assert_eq!(event.env_id, "staging");
        assert_eq!(event.sequence, 42);
        assert_eq!(event.plan_sha256, "deadbeef");
    }

    #[test]
    fn wrong_schema_skipped_stream_continues() {
        // Simulate `connect_and_read`'s filtering logic via `read_frames` +
        // the same closure pattern.
        let input = concat!(
            "event: plan\n",
            "data: {\"schema\":\"greentic.update-event.v2\",\"env_id\":\"a\",\"sequence\":1,\"plan_sha256\":\"aa\"}\n",
            "\n",
            "event: plan\n",
            "data: {\"schema\":\"greentic.update-event.v1\",\"env_id\":\"b\",\"sequence\":2,\"plan_sha256\":\"bb\"}\n",
            "\n",
        );
        let mut events = Vec::new();
        read_frames(Cursor::new(input), |frame| {
            if frame.event.as_deref() != Some("plan") {
                return ControlFlow::Continue(());
            }
            let Ok(ev) = serde_json::from_str::<PlanEvent>(&frame.data) else {
                return ControlFlow::Continue(());
            };
            if ev.schema != UPDATE_EVENT_SCHEMA_V1 {
                return ControlFlow::Continue(());
            }
            events.push(ev);
            ControlFlow::Continue(())
        })
        .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].env_id, "b");
    }

    // ── Backoff ─────────────────────────────────────────────────────

    #[test]
    fn backoff_grows_exponentially_and_is_capped() {
        let max = Duration::from_secs(30);
        let mut b = Backoff::new(max);
        let mut delays = Vec::new();
        for _ in 0..20 {
            delays.push(b.next_delay());
        }
        // The first few base values are 1, 2, 4, 8, 16 (before hitting cap).
        // With up to 25% jitter, delay N must be >= its base (no negative jitter)
        // and delay after 3 calls must exceed 4 s (proves doubling).
        assert!(
            delays[0] >= Duration::from_secs(1),
            "first delay too low: {:?}",
            delays[0]
        );
        assert!(
            delays[2] >= Duration::from_secs(4),
            "third delay must be >= 4s (base 4s + jitter): {:?}",
            delays[2]
        );
        // All delays must stay within cap + 25% jitter headroom.
        for d in &delays {
            assert!(
                *d <= max + max / 4,
                "delay must not exceed cap + jitter headroom: {d:?}"
            );
        }
        // The first 4 steps (bases 1, 2, 4, 8) must be strictly increasing.
        for i in 0..4 {
            assert!(
                delays[i + 1] > delays[i],
                "delays[{}]={:?} must be < delays[{}]={:?}",
                i,
                delays[i],
                i + 1,
                delays[i + 1]
            );
        }
    }

    #[test]
    fn backoff_reset_returns_to_floor() {
        let max = Duration::from_secs(60);
        let mut b = Backoff::new(max);
        // Advance several times.
        for _ in 0..5 {
            b.next_delay();
        }
        b.reset();
        let d = b.next_delay();
        // After reset the first delay must be close to 1 s (floor + jitter).
        assert!(
            d <= Duration::from_secs(2),
            "post-reset delay too high: {d:?}"
        );
    }

    // ── break from on_frame stops reading ───────────────────────────

    #[test]
    fn break_stops_reading() {
        let input = "data: a\n\ndata: b\n\ndata: c\n\n";
        let mut count = 0u32;
        read_frames(Cursor::new(input), |_| {
            count += 1;
            if count == 2 {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        })
        .unwrap();
        assert_eq!(count, 2);
    }

    // ── data-only frame (no event/id) dispatches ────────────────────

    #[test]
    fn data_only_frame_dispatches() {
        let input = "data: bare\n\n";
        let mut frames = Vec::new();
        read_frames(Cursor::new(input), |f| {
            frames.push(f);
            ControlFlow::Continue(())
        })
        .unwrap();
        assert_eq!(frames.len(), 1);
        assert!(frames[0].event.is_none());
        assert!(frames[0].id.is_none());
        assert_eq!(frames[0].data, "bare");
    }

    // ── empty data-only blank lines do not dispatch ─────────────────

    #[test]
    fn empty_data_lines_do_not_dispatch() {
        // Two blank lines in a row — only one frame boundary, and no data was
        // accumulated so nothing is dispatched.
        let input = "\n\ndata: real\n\n";
        let mut frames = Vec::new();
        read_frames(Cursor::new(input), |f| {
            frames.push(f);
            ControlFlow::Continue(())
        })
        .unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].data, "real");
    }

    // ── Bounded line reader ────────────────────────────────────────

    #[test]
    fn unterminated_oversize_line_no_oom() {
        let big = "x".repeat(1024 * 1024);
        let mut frames = Vec::new();
        read_frames(Cursor::new(big.as_bytes()), |f| {
            frames.push(f);
            ControlFlow::Continue(())
        })
        .unwrap();
        assert!(frames.is_empty(), "no frame should be dispatched");
    }

    #[test]
    fn oversize_line_resync_delivers_next_frame() {
        let prefix = "x".repeat(MAX_LINE_BYTES);
        let input = format!("event: {prefix}\ndata: wrong\n\ndata: ok\n\n");
        let mut frames = Vec::new();
        read_frames(Cursor::new(input.as_bytes()), |f| {
            frames.push(f);
            ControlFlow::Continue(())
        })
        .unwrap();
        assert_eq!(
            frames.len(),
            1,
            "the valid frame after the oversize line must be delivered"
        );
        assert_eq!(frames[0].data, "ok");
    }

    #[test]
    fn line_at_exact_cap_accepted() {
        let padding = "x".repeat(MAX_LINE_BYTES - 6); // "data: " is 6 bytes
        let input = format!("data: {padding}\n\n");
        let mut frames = Vec::new();
        read_frames(Cursor::new(input.as_bytes()), |f| {
            frames.push(f);
            ControlFlow::Continue(())
        })
        .unwrap();
        assert_eq!(
            frames.len(),
            1,
            "a line of exactly MAX_LINE_BYTES must be accepted"
        );
        assert_eq!(frames[0].data.len(), MAX_LINE_BYTES - 6);
    }

    #[test]
    fn line_at_cap_plus_one_skipped() {
        let padding = "x".repeat(MAX_LINE_BYTES - 5); // total line = MAX_LINE_BYTES + 1
        let input = format!("data: {padding}\n\ndata: ok\n\n");
        let mut frames = Vec::new();
        read_frames(Cursor::new(input.as_bytes()), |f| {
            frames.push(f);
            ControlFlow::Continue(())
        })
        .unwrap();
        assert_eq!(frames.len(), 1, "the oversize frame must be skipped");
        assert_eq!(frames[0].data, "ok");
    }

    #[test]
    fn invalid_utf8_line_skipped_stream_continues() {
        let mut input = Vec::new();
        input.extend_from_slice(b"data: hello\n");
        input.extend_from_slice(b"data: \xff\xfe\n");
        input.extend_from_slice(b"\n");
        input.extend_from_slice(b"data: world\n");
        input.extend_from_slice(b"\n");

        let mut frames = Vec::new();
        read_frames(Cursor::new(&input[..]), |f| {
            frames.push(f);
            ControlFlow::Continue(())
        })
        .unwrap();

        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].data, "hello");
        assert_eq!(frames[1].data, "world");
    }
}
