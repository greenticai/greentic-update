#![cfg(feature = "stream")]

//! Integration tests for the SSE stream transport against a mock server.

use greentic_update::stream::{
    StreamError, UPDATE_EVENT_SCHEMA_V1, build_stream_client, connect_and_read, run_stream,
};
use httpmock::prelude::*;
use std::ops::ControlFlow;
use std::panic;

fn start_server() -> Option<MockServer> {
    panic::catch_unwind(MockServer::start).ok()
}

fn plan_event_json(env_id: &str, seq: u64, sha: &str) -> String {
    serde_json::to_string(&serde_json::json!({
        "schema": UPDATE_EVENT_SCHEMA_V1,
        "env_id": env_id,
        "sequence": seq,
        "plan_sha256": sha,
    }))
    .unwrap()
}

fn sse_body(events: &[(Option<&str>, &str, &str)]) -> String {
    let mut body = String::new();
    for (id, event, data) in events {
        if let Some(id) = id {
            body.push_str(&format!("id: {id}\n"));
        }
        body.push_str(&format!("event: {event}\n"));
        body.push_str(&format!("data: {data}\n"));
        body.push('\n');
    }
    body
}

#[test]
fn two_plan_events_delivered_in_order() {
    let Some(server) = start_server() else {
        eprintln!("skipping: unable to bind mock server in this environment");
        return;
    };

    let ev1 = plan_event_json("prod", 1, "aaa");
    let ev2 = plan_event_json("staging", 2, "bbb");
    let body = sse_body(&[(Some("1"), "plan", &ev1), (Some("2"), "plan", &ev2)]);

    let mock = server.mock(|when, then| {
        when.method(GET).path("/v1/events");
        then.status(200)
            .header("Content-Type", "text/event-stream")
            .body(body);
    });

    let client = build_stream_client().unwrap();
    let url = format!("{}/v1/events", server.base_url());
    let mut received = Vec::new();
    connect_and_read(&client, &url, None, |ev| {
        received.push(ev);
        ControlFlow::Continue(())
    })
    .unwrap();
    mock.assert();

    assert_eq!(received.len(), 2);
    assert_eq!(received[0].env_id, "prod");
    assert_eq!(received[0].sequence, 1);
    assert_eq!(received[1].env_id, "staging");
    assert_eq!(received[1].sequence, 2);
}

#[test]
fn last_event_id_header_sent() {
    let Some(server) = start_server() else {
        eprintln!("skipping: unable to bind mock server in this environment");
        return;
    };

    let ev = plan_event_json("prod", 7, "ccc");
    let body = sse_body(&[(Some("7"), "plan", &ev)]);

    let mock = server.mock(|when, then| {
        when.method(GET)
            .path("/v1/events")
            .header("Last-Event-ID", "6");
        then.status(200)
            .header("Content-Type", "text/event-stream")
            .body(body);
    });

    let client = build_stream_client().unwrap();
    let url = format!("{}/v1/events", server.base_url());
    let mut received = Vec::new();
    connect_and_read(&client, &url, Some(6), |ev| {
        received.push(ev);
        ControlFlow::Continue(())
    })
    .unwrap();
    mock.assert();

    assert_eq!(received.len(), 1);
    assert_eq!(received[0].sequence, 7);
}

#[test]
fn non_plan_event_and_wrong_schema_filtered_by_connect_and_read() {
    let Some(server) = start_server() else {
        eprintln!("skipping: unable to bind mock server in this environment");
        return;
    };

    let v1_plan = plan_event_json("prod", 3, "ddd");
    // heartbeat event with valid PlanEvent JSON -- must be filtered by event type.
    let heartbeat_json = plan_event_json("prod", 1, "aaa");
    // plan event with v2 schema -- must be filtered by schema check.
    let v2_plan = serde_json::to_string(&serde_json::json!({
        "schema": "greentic.update-event.v2",
        "env_id": "prod",
        "sequence": 2,
        "plan_sha256": "bbb",
    }))
    .unwrap();

    let body = sse_body(&[
        (Some("1"), "heartbeat", &heartbeat_json),
        (Some("2"), "plan", &v2_plan),
        (Some("3"), "plan", &v1_plan),
    ]);

    let mock = server.mock(|when, then| {
        when.method(GET).path("/v1/events");
        then.status(200)
            .header("Content-Type", "text/event-stream")
            .body(body);
    });

    let client = build_stream_client().unwrap();
    let url = format!("{}/v1/events", server.base_url());
    let mut received = Vec::new();
    connect_and_read(&client, &url, None, |ev| {
        received.push(ev);
        ControlFlow::Continue(())
    })
    .unwrap();
    mock.assert();

    assert_eq!(received.len(), 1, "only the v1 plan event should pass");
    assert_eq!(received[0].env_id, "prod");
    assert_eq!(received[0].sequence, 3);
}

#[test]
fn non_2xx_returns_stream_error() {
    let Some(server) = start_server() else {
        eprintln!("skipping: unable to bind mock server in this environment");
        return;
    };

    let mock = server.mock(|when, then| {
        when.method(GET).path("/v1/events");
        then.status(503).body("service unavailable");
    });

    let client = build_stream_client().unwrap();
    let url = format!("{}/v1/events", server.base_url());
    let err = connect_and_read(&client, &url, None, |_| ControlFlow::Continue(())).unwrap_err();
    mock.assert();

    assert!(
        matches!(err, StreamError::Status { status: 503 }),
        "unexpected error: {err:?}"
    );
}

// ── run_stream reconnect loop ──────────────────────────────────────

#[test]
fn run_stream_reconnects_with_cursor() {
    let Some(server) = start_server() else {
        eprintln!("skipping: unable to bind mock server in this environment");
        return;
    };

    let ev1 = plan_event_json("prod", 7, "aaa");
    let body1 = sse_body(&[(Some("7"), "plan", &ev1)]);

    let ev2 = plan_event_json("prod", 8, "bbb");
    let body2 = sse_body(&[(Some("8"), "plan", &ev2)]);

    // First request: no Last-Event-ID header present.
    let _mock1 = server.mock(|when, then| {
        when.method(GET)
            .path("/v1/events")
            .header_missing("Last-Event-ID");
        then.status(200)
            .header("Content-Type", "text/event-stream")
            .body(body1);
    });

    // Second request: must carry Last-Event-ID: 7.
    let mock2 = server.mock(|when, then| {
        when.method(GET)
            .path("/v1/events")
            .header("Last-Event-ID", "7");
        then.status(200)
            .header("Content-Type", "text/event-stream")
            .body(body2);
    });

    let client = build_stream_client().unwrap();
    let url = format!("{}/v1/events", server.base_url());
    let mut received = Vec::new();

    run_stream(
        &client,
        &url,
        None,
        || false,
        |ev| {
            received.push(ev);
            if received.len() >= 2 {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        },
    )
    .unwrap();

    assert_eq!(received.len(), 2);
    assert_eq!(received[0].sequence, 7);
    assert_eq!(received[1].sequence, 8);
    mock2.assert_calls(1);
}

#[test]
fn run_stream_should_stop_ends_loop() {
    let Some(server) = start_server() else {
        eprintln!("skipping: unable to bind mock server in this environment");
        return;
    };

    let ev = plan_event_json("prod", 1, "aaa");
    let body = sse_body(&[(Some("1"), "plan", &ev)]);

    let mock = server.mock(|when, then| {
        when.method(GET).path("/v1/events");
        then.status(200)
            .header("Content-Type", "text/event-stream")
            .body(body);
    });

    let client = build_stream_client().unwrap();
    let url = format!("{}/v1/events", server.base_url());

    run_stream(&client, &url, None, || true, |_| ControlFlow::Continue(())).unwrap();

    mock.assert_calls(0);
}

#[test]
fn run_stream_404_is_terminal_no_retry() {
    let Some(server) = start_server() else {
        eprintln!("skipping: unable to bind mock server in this environment");
        return;
    };

    let mock = server.mock(|when, then| {
        when.method(GET).path("/v1/events");
        then.status(404).body("not found");
    });

    let client = build_stream_client().unwrap();
    let url = format!("{}/v1/events", server.base_url());

    let err = run_stream(&client, &url, None, || false, |_| ControlFlow::Continue(())).unwrap_err();

    assert!(
        matches!(err, StreamError::Unsupported { status: 404 }),
        "expected Unsupported(404), got: {err:?}"
    );
    mock.assert_calls(1);
}

/// A retryable error status (503) must be RETRIED, not treated as terminal.
///
/// This is the decoy that keeps `run_stream_404_is_terminal_no_retry` honest. Without
/// it, "return on *any* `Err`" passes the whole suite: the other reconnect test
/// (`run_stream_reconnects_with_cursor`) reconnects after a clean EOF — which is
/// `Ok(())`, not an error — so it cannot distinguish "retries errors" from "gives up on
/// them". Only a failing *status* followed by a success can.
///
/// Uses a raw TCP listener rather than httpmock: httpmock's matchers are stateless, so
/// making one path answer 503-then-200 requires fighting the library. Sequencing two
/// accepts is simply what this test means.
#[test]
fn run_stream_retries_a_retryable_status_then_succeeds() {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_srv = Arc::clone(&hits);

    let body = sse_body(&[(Some("1"), "plan", &plan_event_json("prod", 1, "aaa"))]);

    let server = std::thread::spawn(move || {
        for _ in 0..2 {
            let Ok((mut sock, _)) = listener.accept() else {
                return;
            };
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf); // drain the request head
            let attempt = hits_srv.fetch_add(1, Ordering::SeqCst);
            let response = if attempt == 0 {
                // Transient: a live server having a bad moment.
                "HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                    .to_string()
            } else {
                format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    body.len(),
                    body
                )
            };
            let _ = sock.write_all(response.as_bytes());
            let _ = sock.flush();
        }
    });

    let client = build_stream_client().unwrap();
    let url = format!("http://{addr}/v1/events");
    let mut received = Vec::new();

    let result = run_stream(
        &client,
        &url,
        None,
        || false,
        |ev| {
            received.push(ev);
            ControlFlow::Break(())
        },
    );

    let _ = server.join();

    assert!(result.is_ok(), "503 must be retried, got: {result:?}");
    assert_eq!(received.len(), 1, "the event after the retry must arrive");
    assert_eq!(received[0].sequence, 1);
    assert_eq!(
        hits.load(Ordering::SeqCst),
        2,
        "expected exactly two attempts (503 then 200) — one attempt means the 503 was treated as terminal"
    );
}
