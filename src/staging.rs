//! Update staging state machine.
//!
//! An on-disk state machine that holds an update plan and its downloaded
//! artifacts between *fetch* (Phase 2, `op get-updates`) and *apply* (Phase 3,
//! `op apply-updates`). It is deliberately **transport- and identity-agnostic**:
//! the caller verifies the plan ([`crate::plan::verify_update_plan`]) and
//! downloads the artifacts (via the distributor client) — this module only owns
//! the durable state, the transition rules, and a mechanical audit trail.
//!
//! ## Layout
//!
//! Rooted at `~/.greentic/updates/` (override with `GREENTIC_UPDATES_DIR`),
//! consistent with `~/.greentic/environments`:
//!
//! ```text
//! <root>/<env_id>/
//!   .lock                    # fs4 exclusive flock, held for state transitions
//!   audit/events.jsonl       # append-only, its own per-file flock
//!   <plan_id>/
//!     state.json             # the stage marker (atomically rewritten)
//!     plan.json              # exact verified plan bytes
//!     plan.json.sig          # the DSSE envelope sidecar
//!     artifacts/
//!       sha256-<hex>/blob    # one downloaded artifact, keyed by content digest
//! ```
//!
//! ## Stages
//!
//! `Downloading → Inbox → Staged → Applying → {Applied}` on the happy path, with
//! `Failed`/`Rejected` terminal off-ramps. State is a single `state.json` marker
//! rewritten atomically (write-tmp → fsync → rename) — **not** a directory
//! rename — so a crash leaves either the old or the new stage, never a partial
//! move. Transitions are gated by [`is_valid_transition`] and serialized by the
//! per-env `.lock` flock.
//!
//! ## Trust boundary
//!
//! [`StagedPlan::put_artifact`] re-verifies each artifact's SHA-256 against the
//! plan's declared digest before writing it, so the staging tree is
//! self-defending even though the download client already verifies digests.
//! Operator-identity auditing (who ran the verb) belongs to the caller's audit
//! ledger; this module records only the mechanical stage transitions.

use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use fs4::fs_std::FileExt;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::plan::{PlanArtifact, VerifiedUpdatePlan};

/// Environment variable overriding the updates root directory.
pub const UPDATES_DIR_VAR: &str = "GREENTIC_UPDATES_DIR";
/// Schema discriminator for the per-plan `state.json` marker.
pub const STAGE_STATE_SCHEMA_V1: &str = "greentic.update-stage-state.v1";
/// Schema discriminator for an audit-log line. Structurally compatible (by
/// convention, not type sharing) with the deployer's `greentic.audit-event.v1`.
pub const UPDATE_AUDIT_SCHEMA_V1: &str = "greentic.update-audit.v1";

const STATE_FILE: &str = "state.json";
const PLAN_FILE: &str = "plan.json";
const SIG_FILE: &str = "plan.json.sig";
const ARTIFACTS_DIR: &str = "artifacts";
const AUDIT_DIR: &str = "audit";
const AUDIT_FILE: &str = "events.jsonl";
const LOCK_FILE: &str = ".lock";
const BLOB_FILE: &str = "blob";

// ---------------------------------------------------------------------------
// Stage state machine
// ---------------------------------------------------------------------------

/// One stage in the update staging pipeline.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateStage {
    /// Artifacts are being fetched into the plan directory.
    Downloading,
    /// All artifacts landed; awaiting verification/promotion.
    Inbox,
    /// Verified and ready for `apply-updates` to consume.
    Staged,
    /// An apply is in progress (Phase 3).
    Applying,
    /// Applied successfully. Terminal.
    Applied,
    /// A download or apply step failed operationally. Terminal.
    Failed,
    /// Rejected on integrity/policy grounds (bad digest, failed re-verify,
    /// downgrade). Terminal.
    Rejected,
}

impl UpdateStage {
    /// Stable lowercase identifier (matches the serde representation).
    pub fn as_str(self) -> &'static str {
        match self {
            UpdateStage::Downloading => "downloading",
            UpdateStage::Inbox => "inbox",
            UpdateStage::Staged => "staged",
            UpdateStage::Applying => "applying",
            UpdateStage::Applied => "applied",
            UpdateStage::Failed => "failed",
            UpdateStage::Rejected => "rejected",
        }
    }

    /// Whether this stage has no outgoing transitions.
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            UpdateStage::Applied | UpdateStage::Failed | UpdateStage::Rejected
        )
    }
}

impl std::fmt::Display for UpdateStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Whether `from → to` is a legal stage transition. Mirrors the flat
/// enum + `matches!` matrix used by the deployer's `RevisionLifecycle`.
pub fn is_valid_transition(from: UpdateStage, to: UpdateStage) -> bool {
    use UpdateStage::*;
    matches!(
        (from, to),
        (Downloading, Inbox)
            | (Downloading, Failed)
            | (Downloading, Rejected)
            | (Inbox, Staged)
            | (Inbox, Failed)
            | (Inbox, Rejected)
            | (Staged, Applying)
            | (Staged, Rejected)
            | (Applying, Applied)
            | (Applying, Failed)
    )
}

// ---------------------------------------------------------------------------
// Persisted shapes
// ---------------------------------------------------------------------------

/// The per-plan `state.json` marker.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StageState {
    /// Always [`STAGE_STATE_SCHEMA_V1`].
    pub schema: String,
    pub plan_id: String,
    pub env_id: String,
    /// The plan's monotonic sequence (mirrored for downgrade queries without
    /// reparsing the whole plan).
    pub sequence: u64,
    /// Lowercase-hex SHA-256 of the verified plan bytes (bare, no prefix).
    pub plan_sha256: String,
    pub stage: UpdateStage,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// One append-only audit line recording a mechanical stage transition.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateAuditEvent {
    /// Always [`UPDATE_AUDIT_SCHEMA_V1`].
    pub schema: String,
    /// Unique-per-line id (`<plan_id>-<unix_nanos>`; unique under the env lock,
    /// where events for one plan are serialized).
    pub event_id: String,
    pub ts: DateTime<Utc>,
    pub env_id: String,
    pub plan_id: String,
    /// The action: `begin`, a target-stage name for a transition, or `evicted`.
    pub verb: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_stage: Option<UpdateStage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to_stage: Option<UpdateStage>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub detail: Value,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why a staging operation failed.
#[derive(Debug, Error)]
pub enum StagingError {
    /// Neither `GREENTIC_UPDATES_DIR` nor a home directory could be resolved.
    #[error("updates root unavailable: {0}")]
    RootUnavailable(String),
    /// A path segment (`env_id`, `plan_id`) is empty, `.`/`..`, or contains a
    /// separator — it would escape the updates root.
    #[error("unsafe {kind} segment `{segment}`: {reason}")]
    UnsafeSegment {
        kind: &'static str,
        segment: String,
        reason: &'static str,
    },
    /// The plan targets a different environment than this root.
    #[error("plan targets env `{plan_env}` but this root is `{root_env}`")]
    EnvMismatch { plan_env: String, root_env: String },
    /// The artifact digest is not a well-formed `sha256:<64 hex>`.
    #[error("malformed artifact digest `{digest}` (expected `sha256:<64 hex>`)")]
    MalformedDigest { digest: String },
    /// The downloaded bytes do not hash to the plan's declared digest.
    #[error("artifact `{name}` digest mismatch: plan declares {expected}, content is {actual}")]
    DigestMismatch {
        name: String,
        expected: String,
        actual: String,
    },
    /// A plan directory already exists for this `plan_id`.
    #[error("plan `{plan_id}` already staged (stage `{stage}`)")]
    PlanExists { plan_id: String, stage: UpdateStage },
    /// No plan directory exists for this `plan_id`.
    #[error("plan `{plan_id}` not found under env `{env_id}`")]
    PlanNotFound { plan_id: String, env_id: String },
    /// The requested stage transition is not allowed from the current stage.
    #[error("illegal transition for plan `{plan_id}`: {from} → {to}")]
    InvalidTransition {
        plan_id: String,
        from: UpdateStage,
        to: UpdateStage,
    },
    #[error("io error on {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("state (de)serialize on {path}: {source}")]
    State {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("could not persist temp file over {target}: {source}")]
    Persist {
        target: PathBuf,
        #[source]
        source: tempfile::PersistError,
    },
    /// A path component under the staging root is a pre-existing symlink — a
    /// write through it could escape the root, so it is refused.
    #[error("path component `{}` is a symlink (escape risk)", .path.display())]
    SymlinkAncestor { path: PathBuf },
    /// Artifacts may only be written while the plan is `Downloading`.
    #[error("cannot add artifacts to plan `{plan_id}` in stage `{stage}` (must be downloading)")]
    ArtifactNotDownloading { plan_id: String, stage: UpdateStage },
}

// ---------------------------------------------------------------------------
// UpdatesRoot — the per-environment staging area
// ---------------------------------------------------------------------------

/// The staging area for one environment: `<root>/<env_id>/`.
#[derive(Clone, Debug)]
pub struct UpdatesRoot {
    env_dir: PathBuf,
    env_id: String,
}

impl UpdatesRoot {
    /// Open (creating if needed) the staging area for `env_id` under the default
    /// root — `GREENTIC_UPDATES_DIR` if set, else `$HOME/.greentic/updates`.
    pub fn open(env_id: &str) -> Result<Self, StagingError> {
        Self::open_in(&resolve_root()?, env_id)
    }

    /// Open (creating if needed) the staging area for `env_id` under an explicit
    /// root. Used by tests and by callers that resolve the root themselves.
    pub fn open_in(root: &Path, env_id: &str) -> Result<Self, StagingError> {
        safe_segment(env_id, "env_id")?;
        let env_dir = root.join(env_id);
        fs::create_dir_all(&env_dir).map_err(|source| StagingError::Io {
            path: env_dir.clone(),
            source,
        })?;
        if let Some(parent) = env_dir.parent() {
            assert_no_symlink_ancestors(parent, &env_dir)?;
        }
        Ok(Self {
            env_dir,
            env_id: env_id.to_string(),
        })
    }

    /// The environment's staging directory (`<root>/<env_id>`).
    pub fn env_dir(&self) -> &Path {
        &self.env_dir
    }

    /// The environment id.
    pub fn env_id(&self) -> &str {
        &self.env_id
    }

    /// Begin staging a verified plan: create its directory, persist the exact
    /// plan bytes + DSSE sidecar, mark it `Downloading`, and audit `begin`.
    ///
    /// `plan_bytes`/`envelope_bytes` are the exact bytes the caller verified, so
    /// the stored `plan.json` + `plan.json.sig` re-verify together at apply time.
    /// Fails with [`StagingError::PlanExists`] if the plan is already staged —
    /// the caller should [`UpdatesRoot::load`] and resume instead.
    pub fn begin(
        &self,
        verified: &VerifiedUpdatePlan,
        plan_bytes: &[u8],
        envelope_bytes: &[u8],
    ) -> Result<StagedPlan, StagingError> {
        let plan = &verified.plan;
        validate_plan_id(&plan.plan_id)?;
        if plan.env_id != self.env_id {
            return Err(StagingError::EnvMismatch {
                plan_env: plan.env_id.clone(),
                root_env: self.env_id.clone(),
            });
        }

        let _lock = acquire_lock(&self.env_dir)?;
        let plan_dir = self.env_dir.join(&plan.plan_id);
        if let Some(existing) = read_state(&plan_dir)? {
            return Err(StagingError::PlanExists {
                plan_id: plan.plan_id.clone(),
                stage: existing.stage,
            });
        }

        let artifacts_dir = plan_dir.join(ARTIFACTS_DIR);
        // Refuse to write through a pre-planted symlink at any component
        // (env/plan/artifacts). Runs under the env lock, immediately before the
        // writes below, so the TOCTOU window is bounded to the lock scope.
        assert_no_symlink_ancestors(&self.env_dir, &artifacts_dir)?;
        fs::create_dir_all(&artifacts_dir).map_err(|source| StagingError::Io {
            path: artifacts_dir,
            source,
        })?;
        atomic_write_bytes(&plan_dir.join(PLAN_FILE), plan_bytes)?;
        atomic_write_bytes(&plan_dir.join(SIG_FILE), envelope_bytes)?;

        let now = Utc::now();
        let state = StageState {
            schema: STAGE_STATE_SCHEMA_V1.to_string(),
            plan_id: plan.plan_id.clone(),
            env_id: self.env_id.clone(),
            sequence: plan.sequence,
            plan_sha256: verified.plan_sha256.clone(),
            stage: UpdateStage::Downloading,
            created_at: now,
            updated_at: now,
        };
        write_state(&plan_dir, &state)?;
        append_audit(
            &self.env_dir,
            &make_event(
                &self.env_id,
                &plan.plan_id,
                "begin",
                None,
                Some(UpdateStage::Downloading),
                serde_json::json!({
                    "sequence": plan.sequence,
                    "plan_sha256": verified.plan_sha256,
                    "artifacts": plan.artifacts.len(),
                }),
            ),
        )?;

        Ok(StagedPlan {
            env_dir: self.env_dir.clone(),
            env_id: self.env_id.clone(),
            plan_dir,
            plan: verified.plan.clone(),
            plan_sha256: verified.plan_sha256.clone(),
        })
    }

    /// Load a previously-staged plan by id, or `None` if not staged.
    pub fn load(&self, plan_id: &str) -> Result<Option<StagedPlan>, StagingError> {
        validate_plan_id(plan_id)?;
        let plan_dir = self.env_dir.join(plan_id);
        let Some(state) = read_state(&plan_dir)? else {
            return Ok(None);
        };
        let plan_path = plan_dir.join(PLAN_FILE);
        let plan_bytes = fs::read(&plan_path).map_err(|source| StagingError::Io {
            path: plan_path.clone(),
            source,
        })?;
        let plan = serde_json::from_slice(&plan_bytes).map_err(|source| StagingError::State {
            path: plan_path,
            source,
        })?;
        Ok(Some(StagedPlan {
            env_dir: self.env_dir.clone(),
            env_id: self.env_id.clone(),
            plan_dir,
            plan,
            plan_sha256: state.plan_sha256,
        }))
    }

    /// The `state.json` of every staged plan. Order is filesystem-dependent.
    ///
    /// `state.json` is treated as untrusted: an entry is included only if its
    /// directory name is a valid plan id (this also skips `audit/` and `.lock`)
    /// **and** the marker's own `plan_id` equals that directory name. A corrupt,
    /// foreign, or unreadable marker is skipped rather than trusted — so an
    /// attacker-controlled `plan_id` can never drive a filesystem path in
    /// [`latest_applied_sequence`](Self::latest_applied_sequence) or
    /// [`apply_retention`](Self::apply_retention).
    pub fn list(&self) -> Result<Vec<StageState>, StagingError> {
        let mut out = Vec::new();
        let entries = match fs::read_dir(&self.env_dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(source) => {
                return Err(StagingError::Io {
                    path: self.env_dir.clone(),
                    source,
                });
            }
        };
        for entry in entries {
            let entry = entry.map_err(|source| StagingError::Io {
                path: self.env_dir.clone(),
                source,
            })?;
            if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                continue;
            }
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if validate_plan_id(&name).is_err() {
                continue;
            }
            // Anchor the marker to its directory: ignore a `state.json` whose
            // `plan_id` disagrees with the directory it lives in (corrupt or
            // foreign), and swallow per-entry read errors so one bad directory
            // cannot break enumeration.
            if let Ok(Some(state)) = read_state(&entry.path())
                && state.plan_id == name
            {
                out.push(state);
            }
        }
        Ok(out)
    }

    /// The highest `sequence` among plans that reached [`UpdateStage::Applied`],
    /// or `None` if none have. Feeds the caller's downgrade guard
    /// ([`crate::plan::ensure_not_downgrade`]).
    pub fn latest_applied_sequence(&self) -> Result<Option<u64>, StagingError> {
        Ok(self
            .list()?
            .into_iter()
            .filter(|s| s.stage == UpdateStage::Applied)
            .map(|s| s.sequence)
            .max())
    }

    /// Evict the oldest terminal plans (`Applied`/`Failed`/`Rejected`), keeping
    /// at most `policy.keep_terminal` of them by `updated_at`. Active plans
    /// (`Downloading`/`Inbox`/`Staged`/`Applying`) are never evicted.
    pub fn apply_retention(
        &self,
        policy: &RetentionPolicy,
    ) -> Result<RetentionReport, StagingError> {
        let _lock = acquire_lock(&self.env_dir)?;
        let all = self.list()?;
        let scanned = all.len();
        let mut terminal: Vec<StageState> =
            all.into_iter().filter(|s| s.stage.is_terminal()).collect();
        // Newest first; keep the head, evict the tail beyond the budget.
        terminal.sort_by_key(|s| std::cmp::Reverse(s.updated_at));

        let mut evicted = Vec::new();
        for state in terminal.into_iter().skip(policy.keep_terminal) {
            // `state.plan_id` came through `list`, which requires it to equal a
            // validated directory name, so this join cannot escape the env dir.
            // Guard against a symlinked plan dir before the recursive delete.
            let plan_dir = self.env_dir.join(&state.plan_id);
            assert_no_symlink_ancestors(&self.env_dir, &plan_dir)?;
            fs::remove_dir_all(&plan_dir).map_err(|source| StagingError::Io {
                path: plan_dir,
                source,
            })?;
            append_audit(
                &self.env_dir,
                &make_event(
                    &self.env_id,
                    &state.plan_id,
                    "evicted",
                    Some(state.stage),
                    None,
                    Value::Null,
                ),
            )?;
            evicted.push(state.plan_id);
        }
        Ok(RetentionReport {
            scanned,
            evicted_count: evicted.len(),
            evicted,
        })
    }
}

// ---------------------------------------------------------------------------
// StagedPlan — a handle to one plan's directory
// ---------------------------------------------------------------------------

/// A handle to one staged plan's on-disk directory.
#[derive(Clone, Debug)]
pub struct StagedPlan {
    env_dir: PathBuf,
    env_id: String,
    plan_dir: PathBuf,
    plan: crate::plan::UpdatePlan,
    plan_sha256: String,
}

impl StagedPlan {
    /// The verified plan document.
    pub fn plan(&self) -> &crate::plan::UpdatePlan {
        &self.plan
    }

    /// Lowercase-hex SHA-256 of the verified plan bytes.
    pub fn plan_sha256(&self) -> &str {
        &self.plan_sha256
    }

    /// This plan's directory (`<root>/<env_id>/<plan_id>`).
    pub fn dir(&self) -> &Path {
        &self.plan_dir
    }

    /// Read the current on-disk stage.
    pub fn stage(&self) -> Result<UpdateStage, StagingError> {
        Ok(self.state()?.stage)
    }

    /// Read the current on-disk `state.json`.
    pub fn state(&self) -> Result<StageState, StagingError> {
        read_state(&self.plan_dir)?.ok_or_else(|| StagingError::PlanNotFound {
            plan_id: self.plan.plan_id.clone(),
            env_id: self.env_id.clone(),
        })
    }

    /// Verify `bytes` against `artifact.digest`, then write them to
    /// `artifacts/sha256-<hex>/blob`. Content-addressed and idempotent (a
    /// re-download of the same digest overwrites identical bytes). Rejects a
    /// malformed digest or a hash mismatch **before** writing. Takes the per-env
    /// lock and requires the plan to still be `Downloading` — an artifact must
    /// not land in a promoted or terminal plan.
    pub fn put_artifact(
        &self,
        artifact: &PlanArtifact,
        bytes: &[u8],
    ) -> Result<PathBuf, StagingError> {
        let dir_name = digest_dir_name(&artifact.digest)?;
        let expected_hex = artifact
            .digest
            .strip_prefix("sha256:")
            .expect("digest_dir_name validated the prefix")
            .to_ascii_lowercase();
        let actual_hex = hex::encode(Sha256::digest(bytes));
        if actual_hex != expected_hex {
            return Err(StagingError::DigestMismatch {
                name: artifact.name.clone(),
                expected: artifact.digest.clone(),
                actual: format!("sha256:{actual_hex}"),
            });
        }
        // Serialize with transitions/retention and refuse to write into a plan
        // that has already left `Downloading`.
        let _lock = acquire_lock(&self.env_dir)?;
        let stage = read_state(&self.plan_dir)?
            .ok_or_else(|| StagingError::PlanNotFound {
                plan_id: self.plan.plan_id.clone(),
                env_id: self.env_id.clone(),
            })?
            .stage;
        if stage != UpdateStage::Downloading {
            return Err(StagingError::ArtifactNotDownloading {
                plan_id: self.plan.plan_id.clone(),
                stage,
            });
        }
        let blob = self
            .plan_dir
            .join(ARTIFACTS_DIR)
            .join(&dir_name)
            .join(BLOB_FILE);
        assert_no_symlink_ancestors(&self.env_dir, &blob)?;
        atomic_write_bytes(&blob, bytes)?;
        Ok(blob)
    }

    /// Move the plan to `to`, gated by [`is_valid_transition`], rewriting
    /// `state.json` atomically and appending an audit line. Serialized by the
    /// per-env `.lock`. Returns the new state.
    pub fn transition(&self, to: UpdateStage) -> Result<StageState, StagingError> {
        let _lock = acquire_lock(&self.env_dir)?;
        let mut state = read_state(&self.plan_dir)?.ok_or_else(|| StagingError::PlanNotFound {
            plan_id: self.plan.plan_id.clone(),
            env_id: self.env_id.clone(),
        })?;
        let from = state.stage;
        if !is_valid_transition(from, to) {
            return Err(StagingError::InvalidTransition {
                plan_id: self.plan.plan_id.clone(),
                from,
                to,
            });
        }
        state.stage = to;
        state.updated_at = Utc::now();
        assert_no_symlink_ancestors(&self.env_dir, &self.plan_dir.join(STATE_FILE))?;
        write_state(&self.plan_dir, &state)?;
        // State is committed before the audit line: if the append or its fsync
        // fails, the transition is already durable and this returns Err (a retry
        // then hits InvalidTransition). This is the same commit-then-audit gap
        // the deployer's `audit_and_record` documents and accepts — the on-disk
        // backend has no cross-file transaction, and the stage marker is the
        // source of truth. A crash in this window likewise leaves a committed
        // transition with no audit line.
        append_audit(
            &self.env_dir,
            &make_event(
                &self.env_id,
                &self.plan.plan_id,
                to.as_str(),
                Some(from),
                Some(to),
                Value::Null,
            ),
        )?;
        Ok(state)
    }
}

// ---------------------------------------------------------------------------
// Retention
// ---------------------------------------------------------------------------

/// Retention policy for terminal plan directories.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetentionPolicy {
    /// Keep at most this many terminal plans (newest by `updated_at`); evict the
    /// rest. Active plans are always kept.
    pub keep_terminal: usize,
}

/// Outcome of [`UpdatesRoot::apply_retention`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetentionReport {
    /// Total plan directories scanned.
    pub scanned: usize,
    /// Ids of evicted plans.
    pub evicted: Vec<String>,
    /// Number evicted (== `evicted.len()`).
    pub evicted_count: usize,
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

fn resolve_root() -> Result<PathBuf, StagingError> {
    resolve_root_from(
        std::env::var_os(UPDATES_DIR_VAR),
        std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")),
    )
}

/// Pure resolution of the updates root — factored out so it is testable without
/// mutating process environment.
fn resolve_root_from(
    updates_dir: Option<OsString>,
    home: Option<OsString>,
) -> Result<PathBuf, StagingError> {
    if let Some(dir) = updates_dir
        && !dir.is_empty()
    {
        return Ok(PathBuf::from(dir));
    }
    let home = home.ok_or_else(|| {
        StagingError::RootUnavailable(
            "neither GREENTIC_UPDATES_DIR nor HOME/USERPROFILE is set".to_string(),
        )
    })?;
    Ok(PathBuf::from(home).join(".greentic").join("updates"))
}

/// Reject a path segment that could escape the updates root. Mirrors the
/// deployer's `safe_env_segment`.
fn safe_segment(segment: &str, kind: &'static str) -> Result<(), StagingError> {
    let bad = segment.is_empty()
        || segment == "."
        || segment == ".."
        || segment.contains(['/', '\\', ':', '\0']);
    if bad {
        return Err(StagingError::UnsafeSegment {
            kind,
            segment: segment.to_string(),
            reason: "empty, `.`/`..`, or contains a path separator",
        });
    }
    Ok(())
}

/// Validate a plan id: a [`safe_segment`] that is not a reserved name colliding
/// with the staging infrastructure (`audit/`, `.lock`). Used everywhere a
/// `plan_id` becomes a directory under the env root, and to filter directory
/// enumeration.
fn validate_plan_id(plan_id: &str) -> Result<(), StagingError> {
    safe_segment(plan_id, "plan_id")?;
    if plan_id == AUDIT_DIR || plan_id == LOCK_FILE {
        return Err(StagingError::UnsafeSegment {
            kind: "plan_id",
            segment: plan_id.to_string(),
            reason: "reserved name that collides with staging infrastructure",
        });
    }
    Ok(())
}

/// Reject a write whose path traverses a pre-existing symlink between `root` and
/// `target` (inclusive of `target`). Only existing components are checked; the
/// guard must run under the env `.lock`, immediately before the write, so the
/// TOCTOU window is bounded to the lock scope. Mirrors the deployer's
/// `path_safety::assert_no_symlink_ancestors`. No-op when `target` is not under
/// `root`.
fn assert_no_symlink_ancestors(root: &Path, target: &Path) -> Result<(), StagingError> {
    let Ok(suffix) = target.strip_prefix(root) else {
        return Ok(());
    };
    let mut current = root.to_path_buf();
    for component in suffix.components() {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(meta) if meta.is_symlink() => {
                return Err(StagingError::SymlinkAncestor { path: current });
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => break,
            Err(source) => {
                return Err(StagingError::Io {
                    path: current,
                    source,
                });
            }
        }
    }
    Ok(())
}

/// Validate a `sha256:<64 hex>` digest and derive its directory name
/// (`sha256-<lowercase hex>`).
fn digest_dir_name(digest: &str) -> Result<String, StagingError> {
    let hex = digest
        .strip_prefix("sha256:")
        .filter(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or_else(|| StagingError::MalformedDigest {
            digest: digest.to_string(),
        })?;
    Ok(format!("sha256-{}", hex.to_ascii_lowercase()))
}

fn read_state(plan_dir: &Path) -> Result<Option<StageState>, StagingError> {
    let path = plan_dir.join(STATE_FILE);
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(StagingError::Io { path, source }),
    };
    let state =
        serde_json::from_slice(&bytes).map_err(|source| StagingError::State { path, source })?;
    Ok(Some(state))
}

fn write_state(plan_dir: &Path, state: &StageState) -> Result<(), StagingError> {
    let mut bytes = serde_json::to_vec_pretty(state).map_err(|source| StagingError::State {
        path: plan_dir.join(STATE_FILE),
        source,
    })?;
    bytes.push(b'\n');
    atomic_write_bytes(&plan_dir.join(STATE_FILE), &bytes)
}

/// Write-tmp → flush → fsync → rename → fsync-parent. Mirrors the deployer's
/// `atomic_write_bytes`.
fn atomic_write_bytes(target: &Path, bytes: &[u8]) -> Result<(), StagingError> {
    let parent = target.parent().ok_or_else(|| StagingError::Io {
        path: target.to_path_buf(),
        source: std::io::Error::new(std::io::ErrorKind::InvalidInput, "target has no parent"),
    })?;
    fs::create_dir_all(parent).map_err(|source| StagingError::Io {
        path: parent.to_path_buf(),
        source,
    })?;
    let mut tmp = tempfile::NamedTempFile::new_in(parent).map_err(|source| StagingError::Io {
        path: parent.to_path_buf(),
        source,
    })?;
    tmp.write_all(bytes)
        .and_then(|_| tmp.flush())
        .and_then(|_| tmp.as_file().sync_all())
        .map_err(|source| StagingError::Io {
            path: tmp.path().to_path_buf(),
            source,
        })?;
    tmp.persist(target)
        .map_err(|source| StagingError::Persist {
            target: target.to_path_buf(),
            source,
        })?;
    fsync_parent(parent)
}

#[cfg(unix)]
fn fsync_parent(parent: &Path) -> Result<(), StagingError> {
    let dir = File::open(parent).map_err(|source| StagingError::Io {
        path: parent.to_path_buf(),
        source,
    })?;
    dir.sync_all().map_err(|source| StagingError::Io {
        path: parent.to_path_buf(),
        source,
    })
}

#[cfg(not(unix))]
fn fsync_parent(_parent: &Path) -> Result<(), StagingError> {
    Ok(())
}

/// RAII exclusive lock on `<env_dir>/.lock`. Dropping releases the OS lock.
struct Flock {
    _file: File,
}

fn acquire_lock(env_dir: &Path) -> Result<Flock, StagingError> {
    fs::create_dir_all(env_dir).map_err(|source| StagingError::Io {
        path: env_dir.to_path_buf(),
        source,
    })?;
    let lock_path = env_dir.join(LOCK_FILE);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|source| StagingError::Io {
            path: lock_path.clone(),
            source,
        })?;
    file.lock_exclusive().map_err(|source| StagingError::Io {
        path: lock_path,
        source,
    })?;
    Ok(Flock { _file: file })
}

fn make_event(
    env_id: &str,
    plan_id: &str,
    verb: &str,
    from_stage: Option<UpdateStage>,
    to_stage: Option<UpdateStage>,
    detail: Value,
) -> UpdateAuditEvent {
    let ts = Utc::now();
    let event_id = format!("{plan_id}-{}", ts.timestamp_nanos_opt().unwrap_or_default());
    UpdateAuditEvent {
        schema: UPDATE_AUDIT_SCHEMA_V1.to_string(),
        event_id,
        ts,
        env_id: env_id.to_string(),
        plan_id: plan_id.to_string(),
        verb: verb.to_string(),
        from_stage,
        to_stage,
        detail,
    }
}

/// Append one audit line to `<env_dir>/audit/events.jsonl` under a per-file
/// flock that is independent of the env `.lock` (so it can be called while the
/// env lock is held without deadlock — the lock order is always env-then-audit).
fn append_audit(env_dir: &Path, event: &UpdateAuditEvent) -> Result<(), StagingError> {
    let audit_dir = env_dir.join(AUDIT_DIR);
    fs::create_dir_all(&audit_dir).map_err(|source| StagingError::Io {
        path: audit_dir.clone(),
        source,
    })?;
    let path = audit_dir.join(AUDIT_FILE);
    let line = serde_json::to_string(event).map_err(|source| StagingError::State {
        path: path.clone(),
        source,
    })?;
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|source| StagingError::Io {
            path: path.clone(),
            source,
        })?;
    file.lock_exclusive().map_err(|source| StagingError::Io {
        path: path.clone(),
        source,
    })?;
    let mut handle = &file;
    let res = handle
        .write_all(line.as_bytes())
        .and_then(|_| handle.write_all(b"\n"))
        .and_then(|_| file.sync_data());
    FileExt::unlock(&file).ok();
    res.map_err(|source| StagingError::Io { path, source })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::{CompatRequirements, OnFail, RollbackKind, RollbackPolicy, UpdatePlan};
    use tempfile::TempDir;

    fn digest_of(bytes: &[u8]) -> String {
        format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
    }

    fn plan_with(
        plan_id: &str,
        env_id: &str,
        sequence: u64,
        artifacts: Vec<PlanArtifact>,
    ) -> UpdatePlan {
        UpdatePlan {
            schema: crate::plan::UPDATE_PLAN_SCHEMA_V1.to_string(),
            plan_id: plan_id.to_string(),
            env_id: env_id.to_string(),
            sequence,
            created_at: Utc::now(),
            nonce: "test-nonce".to_string(),
            target: serde_json::json!({}),
            artifacts,
            compat: CompatRequirements::default(),
            rollback: RollbackPolicy {
                policy: RollbackKind::Auto,
                health_timeout_s: 60,
                on_fail: OnFail::Restore,
            },
        }
    }

    fn verified(plan: UpdatePlan) -> VerifiedUpdatePlan {
        VerifiedUpdatePlan {
            plan,
            plan_sha256: "0".repeat(64),
            verified_key_ids: vec!["k1".to_string()],
        }
    }

    fn artifact(name: &str, bytes: &[u8]) -> PlanArtifact {
        PlanArtifact {
            name: name.to_string(),
            version: "1.0.0".to_string(),
            digest: digest_of(bytes),
            source: Some(format!("oci://example/{name}:1.0.0")),
        }
    }

    #[test]
    fn transition_matrix_matches_happy_path_and_offramps() {
        use UpdateStage::*;
        // Happy path.
        assert!(is_valid_transition(Downloading, Inbox));
        assert!(is_valid_transition(Inbox, Staged));
        assert!(is_valid_transition(Staged, Applying));
        assert!(is_valid_transition(Applying, Applied));
        // Off-ramps.
        assert!(is_valid_transition(Downloading, Failed));
        assert!(is_valid_transition(Inbox, Rejected));
        assert!(is_valid_transition(Staged, Rejected));
        assert!(is_valid_transition(Applying, Failed));
        // Illegal jumps.
        assert!(!is_valid_transition(Downloading, Staged));
        assert!(!is_valid_transition(Downloading, Applied));
        assert!(!is_valid_transition(Staged, Applied));
        assert!(!is_valid_transition(Inbox, Applying));
        // Terminal states have no outgoing transitions.
        for term in [Applied, Failed, Rejected] {
            assert!(term.is_terminal());
            for to in [
                Downloading,
                Inbox,
                Staged,
                Applying,
                Applied,
                Failed,
                Rejected,
            ] {
                assert!(
                    !is_valid_transition(term, to),
                    "{term} -> {to} must be illegal"
                );
            }
        }
    }

    #[test]
    fn resolve_root_prefers_updates_dir_then_home() {
        assert_eq!(
            resolve_root_from(Some("/custom/updates".into()), Some("/home/u".into())).unwrap(),
            PathBuf::from("/custom/updates")
        );
        assert_eq!(
            resolve_root_from(None, Some("/home/u".into())).unwrap(),
            PathBuf::from("/home/u/.greentic/updates")
        );
        // Empty override falls through to home.
        assert_eq!(
            resolve_root_from(Some("".into()), Some("/home/u".into())).unwrap(),
            PathBuf::from("/home/u/.greentic/updates")
        );
        assert!(matches!(
            resolve_root_from(None, None),
            Err(StagingError::RootUnavailable(_))
        ));
    }

    #[test]
    fn open_in_rejects_unsafe_env_id() {
        let tmp = TempDir::new().unwrap();
        for bad in ["", ".", "..", "a/b", "a:b", "a\\b"] {
            assert!(
                matches!(
                    UpdatesRoot::open_in(tmp.path(), bad),
                    Err(StagingError::UnsafeSegment { .. })
                ),
                "env_id `{bad}` should be rejected"
            );
        }
    }

    #[test]
    fn begin_persists_plan_sig_and_state() {
        let tmp = TempDir::new().unwrap();
        let root = UpdatesRoot::open_in(tmp.path(), "prod").unwrap();
        let plan = plan_with("plan-1", "prod", 5, vec![]);
        let v = verified(plan);
        let plan_bytes = b"{\"canonical\":\"plan bytes\"}";
        let sig_bytes = b"dsse-envelope";

        let staged = root.begin(&v, plan_bytes, sig_bytes).unwrap();
        assert_eq!(staged.stage().unwrap(), UpdateStage::Downloading);

        let dir = staged.dir();
        assert_eq!(fs::read(dir.join(PLAN_FILE)).unwrap(), plan_bytes);
        assert_eq!(fs::read(dir.join(SIG_FILE)).unwrap(), sig_bytes);
        assert!(dir.join(ARTIFACTS_DIR).is_dir());

        let state = staged.state().unwrap();
        assert_eq!(state.schema, STAGE_STATE_SCHEMA_V1);
        assert_eq!(state.plan_id, "plan-1");
        assert_eq!(state.env_id, "prod");
        assert_eq!(state.sequence, 5);
    }

    #[test]
    fn begin_rejects_duplicate_and_env_mismatch() {
        let tmp = TempDir::new().unwrap();
        let root = UpdatesRoot::open_in(tmp.path(), "prod").unwrap();
        let v = verified(plan_with("plan-1", "prod", 1, vec![]));
        root.begin(&v, b"p", b"s").unwrap();
        assert!(matches!(
            root.begin(&v, b"p", b"s"),
            Err(StagingError::PlanExists { .. })
        ));

        let wrong = verified(plan_with("plan-2", "staging", 1, vec![]));
        assert!(matches!(
            root.begin(&wrong, b"p", b"s"),
            Err(StagingError::EnvMismatch { .. })
        ));
    }

    #[test]
    fn begin_rejects_unsafe_plan_id() {
        let tmp = TempDir::new().unwrap();
        let root = UpdatesRoot::open_in(tmp.path(), "prod").unwrap();
        let v = verified(plan_with("../escape", "prod", 1, vec![]));
        assert!(matches!(
            root.begin(&v, b"p", b"s"),
            Err(StagingError::UnsafeSegment {
                kind: "plan_id",
                ..
            })
        ));
    }

    #[test]
    fn begin_rejects_reserved_plan_ids() {
        // Reserved names would collide with the staging infrastructure: a plan
        // dir named `audit` clobbers the audit-log dir, `.lock` the env lock.
        let tmp = TempDir::new().unwrap();
        let root = UpdatesRoot::open_in(tmp.path(), "prod").unwrap();
        for reserved in ["audit", ".lock"] {
            let v = verified(plan_with(reserved, "prod", 1, vec![]));
            assert!(
                matches!(
                    root.begin(&v, b"p", b"s"),
                    Err(StagingError::UnsafeSegment {
                        kind: "plan_id",
                        ..
                    })
                ),
                "plan_id `{reserved}` must be rejected"
            );
        }
    }

    #[test]
    fn put_artifact_requires_downloading_stage() {
        let tmp = TempDir::new().unwrap();
        let root = UpdatesRoot::open_in(tmp.path(), "prod").unwrap();
        let payload = b"payload";
        let art = artifact("pack-a", payload);
        let staged = root
            .begin(
                &verified(plan_with("plan-1", "prod", 1, vec![art.clone()])),
                b"p",
                b"s",
            )
            .unwrap();
        // Fine while Downloading.
        staged.put_artifact(&art, payload).unwrap();
        // After promotion out of Downloading, artifact writes are refused.
        staged.transition(UpdateStage::Inbox).unwrap();
        assert!(matches!(
            staged.put_artifact(&art, payload),
            Err(StagingError::ArtifactNotDownloading { .. })
        ));
    }

    #[test]
    fn list_ignores_marker_whose_plan_id_mismatches_its_dir() {
        let tmp = TempDir::new().unwrap();
        let root = UpdatesRoot::open_in(tmp.path(), "prod").unwrap();
        // One legit plan.
        root.begin(&verified(plan_with("real", "prod", 1, vec![])), b"p", b"s")
            .unwrap();
        // A decoy directory whose state.json claims a traversal plan_id — the
        // finding-1 attack: retention must not join this untrusted value.
        let decoy = root.env_dir().join("decoy");
        fs::create_dir_all(&decoy).unwrap();
        let now = Utc::now();
        let forged = StageState {
            schema: STAGE_STATE_SCHEMA_V1.to_string(),
            plan_id: "../escape".to_string(),
            env_id: "prod".to_string(),
            sequence: 99,
            plan_sha256: "0".repeat(64),
            stage: UpdateStage::Failed,
            created_at: now,
            updated_at: now,
        };
        write_state(&decoy, &forged).unwrap();

        // `list` surfaces only the plan whose marker matches its directory.
        let ids: Vec<String> = root
            .list()
            .unwrap()
            .into_iter()
            .map(|s| s.plan_id)
            .collect();
        assert_eq!(ids, vec!["real".to_string()]);

        // Retention operates on that validated set only; the forged terminal
        // marker is ignored, so no path is ever built from its plan_id.
        let report = root
            .apply_retention(&RetentionPolicy { keep_terminal: 0 })
            .unwrap();
        assert!(report.evicted.is_empty(), "only `real` (active) remained");
        assert!(
            decoy.exists(),
            "decoy must not be deleted via its forged plan_id"
        );
    }

    #[cfg(unix)]
    #[test]
    fn begin_rejects_symlinked_plan_dir() {
        use std::os::unix::fs::symlink;
        let tmp = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        let root = UpdatesRoot::open_in(tmp.path(), "prod").unwrap();
        // Pre-plant <env>/evil as a symlink to a dir outside the staging root.
        symlink(outside.path(), root.env_dir().join("evil")).unwrap();
        let v = verified(plan_with("evil", "prod", 1, vec![]));
        assert!(matches!(
            root.begin(&v, b"p", b"s"),
            Err(StagingError::SymlinkAncestor { .. })
        ));
    }

    #[test]
    fn put_artifact_verifies_digest() {
        let tmp = TempDir::new().unwrap();
        let root = UpdatesRoot::open_in(tmp.path(), "prod").unwrap();
        let payload = b"artifact payload";
        let art = artifact("pack-a", payload);
        let v = verified(plan_with("plan-1", "prod", 1, vec![art.clone()]));
        let staged = root.begin(&v, b"p", b"s").unwrap();

        // Good digest writes the blob.
        let blob = staged.put_artifact(&art, payload).unwrap();
        assert_eq!(fs::read(&blob).unwrap(), payload);
        assert!(blob.ends_with(BLOB_FILE));

        // Wrong content for the declared digest is rejected.
        assert!(matches!(
            staged.put_artifact(&art, b"tampered"),
            Err(StagingError::DigestMismatch { .. })
        ));

        // Malformed digest is rejected before hashing.
        let bad = PlanArtifact {
            digest: "sha1:deadbeef".to_string(),
            ..art.clone()
        };
        assert!(matches!(
            staged.put_artifact(&bad, payload),
            Err(StagingError::MalformedDigest { .. })
        ));
    }

    #[test]
    fn transition_enforces_matrix_and_persists() {
        let tmp = TempDir::new().unwrap();
        let root = UpdatesRoot::open_in(tmp.path(), "prod").unwrap();
        let v = verified(plan_with("plan-1", "prod", 1, vec![]));
        let staged = root.begin(&v, b"p", b"s").unwrap();

        // Illegal jump is refused.
        assert!(matches!(
            staged.transition(UpdateStage::Applied),
            Err(StagingError::InvalidTransition { .. })
        ));
        assert_eq!(staged.stage().unwrap(), UpdateStage::Downloading);

        // Walk the happy path.
        staged.transition(UpdateStage::Inbox).unwrap();
        staged.transition(UpdateStage::Staged).unwrap();
        staged.transition(UpdateStage::Applying).unwrap();
        let final_state = staged.transition(UpdateStage::Applied).unwrap();
        assert_eq!(final_state.stage, UpdateStage::Applied);

        // Terminal: no further transitions.
        assert!(matches!(
            staged.transition(UpdateStage::Failed),
            Err(StagingError::InvalidTransition { .. })
        ));
    }

    #[test]
    fn load_reconstructs_a_staged_plan() {
        let tmp = TempDir::new().unwrap();
        let root = UpdatesRoot::open_in(tmp.path(), "prod").unwrap();
        // `load` reparses `plan.json`, so the persisted bytes must be the
        // canonical plan JSON (as they are in production).
        let plan = plan_with("plan-1", "prod", 7, vec![]);
        let bytes = serde_json::to_vec(&plan).unwrap();
        let v = verified(plan);
        let staged = root.begin(&v, &bytes, b"s").unwrap();
        staged.transition(UpdateStage::Inbox).unwrap();

        let loaded = root.load("plan-1").unwrap().expect("plan present");
        assert_eq!(loaded.plan().plan_id, "plan-1");
        assert_eq!(loaded.plan().sequence, 7);
        assert_eq!(loaded.stage().unwrap(), UpdateStage::Inbox);
        assert!(root.load("missing").unwrap().is_none());
    }

    #[test]
    fn audit_log_records_each_transition_as_jsonl() {
        let tmp = TempDir::new().unwrap();
        let root = UpdatesRoot::open_in(tmp.path(), "prod").unwrap();
        let v = verified(plan_with("plan-1", "prod", 1, vec![]));
        let staged = root.begin(&v, b"p", b"s").unwrap();
        staged.transition(UpdateStage::Inbox).unwrap();
        staged.transition(UpdateStage::Staged).unwrap();

        let log = fs::read_to_string(root.env_dir().join(AUDIT_DIR).join(AUDIT_FILE)).unwrap();
        let lines: Vec<&str> = log.lines().collect();
        assert_eq!(lines.len(), 3, "begin + 2 transitions");
        let verbs: Vec<String> = lines
            .iter()
            .map(|l| {
                let e: UpdateAuditEvent = serde_json::from_str(l).unwrap();
                assert_eq!(e.schema, UPDATE_AUDIT_SCHEMA_V1);
                assert_eq!(e.plan_id, "plan-1");
                e.verb
            })
            .collect();
        assert_eq!(verbs, vec!["begin", "inbox", "staged"]);
    }

    #[test]
    fn list_and_latest_applied_sequence() {
        let tmp = TempDir::new().unwrap();
        let root = UpdatesRoot::open_in(tmp.path(), "prod").unwrap();

        // plan-a: staged only (not applied).
        let a = root
            .begin(
                &verified(plan_with("plan-a", "prod", 3, vec![])),
                b"p",
                b"s",
            )
            .unwrap();
        a.transition(UpdateStage::Inbox).unwrap();
        a.transition(UpdateStage::Staged).unwrap();

        // plan-b: driven all the way to Applied at sequence 5.
        let b = root
            .begin(
                &verified(plan_with("plan-b", "prod", 5, vec![])),
                b"p",
                b"s",
            )
            .unwrap();
        b.transition(UpdateStage::Inbox).unwrap();
        b.transition(UpdateStage::Staged).unwrap();
        b.transition(UpdateStage::Applying).unwrap();
        b.transition(UpdateStage::Applied).unwrap();

        assert_eq!(root.list().unwrap().len(), 2);
        assert_eq!(root.latest_applied_sequence().unwrap(), Some(5));
    }

    #[test]
    fn retention_evicts_oldest_terminal_and_spares_active() {
        let tmp = TempDir::new().unwrap();
        let root = UpdatesRoot::open_in(tmp.path(), "prod").unwrap();

        // Three terminal (Failed) plans + one active (Staged).
        for (id, seq) in [("t1", 1), ("t2", 2), ("t3", 3)] {
            let p = root
                .begin(&verified(plan_with(id, "prod", seq, vec![])), b"p", b"s")
                .unwrap();
            p.transition(UpdateStage::Failed).unwrap();
        }
        let active = root
            .begin(
                &verified(plan_with("active", "prod", 9, vec![])),
                b"p",
                b"s",
            )
            .unwrap();
        active.transition(UpdateStage::Inbox).unwrap();
        active.transition(UpdateStage::Staged).unwrap();

        let report = root
            .apply_retention(&RetentionPolicy { keep_terminal: 1 })
            .unwrap();
        assert_eq!(report.scanned, 4);
        assert_eq!(report.evicted_count, 2, "3 terminal, keep 1 => evict 2");

        // The active plan and exactly one terminal plan survive.
        let survivors: Vec<String> = root
            .list()
            .unwrap()
            .into_iter()
            .map(|s| s.plan_id)
            .collect();
        assert!(survivors.contains(&"active".to_string()));
        assert_eq!(survivors.len(), 2);
    }

    #[test]
    fn digest_dir_name_validates_format() {
        let hex = "a".repeat(64);
        assert_eq!(
            digest_dir_name(&format!("sha256:{hex}")).unwrap(),
            format!("sha256-{hex}")
        );
        // Uppercase hex is normalized to lowercase.
        assert_eq!(
            digest_dir_name(&format!("sha256:{}", "A".repeat(64))).unwrap(),
            format!("sha256-{}", "a".repeat(64))
        );
        for bad in [
            "sha256:short",
            "abc",
            "sha1:aaaa",
            &format!("sha256:{}", "g".repeat(64)),
        ] {
            assert!(matches!(
                digest_dir_name(bad),
                Err(StagingError::MalformedDigest { .. })
            ));
        }
    }
}
