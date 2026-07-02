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

use std::cell::RefCell;
use std::collections::HashSet;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use fs4::fs_std::FileExt;
use serde::{Deserialize, Serialize};
use serde_json::Value;
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
    /// write or read through it could escape the root, so it is refused.
    #[error("path component `{}` is a symlink (escape risk)", .path.display())]
    SymlinkAncestor { path: PathBuf },
    /// A staging file that must be read back is not a regular file (a FIFO,
    /// device, socket, or directory) — reading it could block or return
    /// non-file bytes, so it is refused before any read.
    #[error("staging path `{}` is not a regular file", .path.display())]
    NotRegularFile { path: PathBuf },
    /// Artifacts may only be written while the plan is `Downloading`.
    #[error("cannot add artifacts to plan `{plan_id}` in stage `{stage}` (must be downloading)")]
    ArtifactNotDownloading { plan_id: String, stage: UpdateStage },
    /// A strict admission scan (`begin_checked`) found a plan directory whose
    /// `state.json` is unreadable, corrupt, or names a different plan than its
    /// directory. Unlike the best-effort [`list`](UpdatesRoot::list), admission
    /// fails **closed** rather than silently omit a possibly-`Applied` plan from
    /// the downgrade/compat snapshot.
    #[error("cannot trust state for plan `{plan_id}` during admission: {reason}")]
    CorruptAdmissionState { plan_id: String, reason: String },
    /// The current thread already holds this env's `.lock`. The flock is not
    /// reentrant, so re-acquiring would deadlock — this is returned instead of
    /// hanging. It signals a staging method was called from inside a
    /// [`begin_checked`](UpdatesRoot::begin_checked) admission predicate, which
    /// already holds the lock; predicates must only read [`AdmissionFacts`].
    #[error("env lock at {path} re-entered by the same thread (would deadlock)")]
    LockReentered { path: PathBuf },
}

/// Error from [`UpdatesRoot::begin_checked`]: either the caller's admission
/// predicate rejected the plan, or a staging-layer operation failed.
#[derive(Debug, Error)]
pub enum BeginCheckedError<E> {
    /// The admission predicate rejected the plan (e.g. a downgrade or compat
    /// gate). Carries the caller's own error verbatim.
    #[error("plan admission rejected: {0}")]
    Rejected(E),
    /// A staging-layer failure (lock, IO, `PlanExists`, …).
    #[error(transparent)]
    Staging(#[from] StagingError),
}

/// Error from [`UpdatesRoot::begin_apply_checked`]: the caller's admission
/// predicate rejected the plan, another plan is already applying (the
/// single-flight gate), or a staging-layer operation failed.
#[derive(Debug, Error)]
pub enum BeginApplyError<E> {
    /// The admission predicate rejected the plan (e.g. an apply-time downgrade
    /// or compat gate). Carries the caller's own error verbatim.
    #[error("apply admission rejected: {0}")]
    Rejected(E),
    /// Another plan in this environment is already in [`UpdateStage::Applying`].
    /// At most one apply may be in flight per env; the caller should retry once
    /// the in-flight apply reaches a terminal stage.
    #[error("plan `{applying}` is already applying in env `{env_id}`")]
    AlreadyApplying { env_id: String, applying: String },
    /// A staging-layer failure (lock, IO, `PlanNotFound`, `InvalidTransition`,
    /// `CorruptAdmissionState`, …).
    #[error(transparent)]
    Staging(#[from] StagingError),
}

// ---------------------------------------------------------------------------
// UpdatesRoot — the per-environment staging area
// ---------------------------------------------------------------------------

/// A race-free snapshot of the applied-plan set, handed to a
/// [`UpdatesRoot::begin_checked`] admission predicate while the env `.lock` is
/// held — everything a caller needs to run downgrade and compat gates without
/// racing a concurrent apply.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AdmissionFacts {
    /// Highest `sequence` among `Applied` plans (`None` if none) — the downgrade
    /// guard input ([`crate::plan::ensure_not_downgrade`]).
    pub latest_applied_sequence: Option<u64>,
    /// `plan_id`s of all `Applied` plans — a compat `requires` input.
    pub applied_plan_ids: Vec<String>,
}

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
        // Guard before the mutation (consistent with begin/put_artifact/retention):
        // refuse if `env_id` resolves through a pre-existing symlink.
        assert_no_symlink_ancestors(root, &env_dir)?;
        fs::create_dir_all(&env_dir).map_err(|source| StagingError::Io {
            path: env_dir.clone(),
            source,
        })?;
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
    ///
    /// This admits the plan unconditionally. To run a downgrade/compat check
    /// atomically with the begin writes (no TOCTOU against a concurrent apply),
    /// use [`UpdatesRoot::begin_checked`].
    pub fn begin(
        &self,
        verified: &VerifiedUpdatePlan,
        plan_bytes: &[u8],
        envelope_bytes: &[u8],
    ) -> Result<StagedPlan, StagingError> {
        let plan = &verified.plan;
        validate_plan_id(&plan.plan_id)?;
        self.check_targets_env(plan)?;

        let _lock = acquire_lock(&self.env_dir)?;
        let plan_dir = self.env_dir.join(&plan.plan_id);
        if let Some(existing) = read_state(&plan_dir)? {
            return Err(StagingError::PlanExists {
                plan_id: plan.plan_id.clone(),
                stage: existing.stage,
            });
        }
        self.write_new_plan(verified, plan_bytes, envelope_bytes, &plan_dir)
    }

    /// Like [`UpdatesRoot::begin`], but evaluates a caller-supplied `admission`
    /// predicate **under the same env-lock hold** as the begin writes, closing
    /// the TOCTOU gap between reading the applied set (for downgrade/compat
    /// gates) and committing the plan. The predicate receives an
    /// [`AdmissionFacts`] snapshot — the highest applied `sequence` and the ids
    /// of every `Applied` plan — computed while the lock is held, so a
    /// concurrent apply cannot slip a newer sequence in between the check and
    /// the write.
    ///
    /// Return `Ok(())` from `admission` to proceed, or `Err(E)` to reject the
    /// plan: the rejection surfaces as [`BeginCheckedError::Rejected`] and
    /// nothing is written. Staging-layer failures surface as
    /// [`BeginCheckedError::Staging`]. A plan that already exists is rejected
    /// with `PlanExists` before the predicate runs.
    pub fn begin_checked<E>(
        &self,
        verified: &VerifiedUpdatePlan,
        plan_bytes: &[u8],
        envelope_bytes: &[u8],
        admission: impl FnOnce(&AdmissionFacts) -> Result<(), E>,
    ) -> Result<StagedPlan, BeginCheckedError<E>> {
        let plan = &verified.plan;
        validate_plan_id(&plan.plan_id)?;
        self.check_targets_env(plan)?;

        let _lock = acquire_lock(&self.env_dir)?;
        let plan_dir = self.env_dir.join(&plan.plan_id);
        if let Some(existing) = read_state(&plan_dir)? {
            return Err(StagingError::PlanExists {
                plan_id: plan.plan_id.clone(),
                stage: existing.stage,
            }
            .into());
        }

        // Snapshot the applied set under the held lock, then let the caller gate
        // on it. `admission_facts_locked` uses the lock-free `scan_plans`, so it
        // does not re-enter `acquire_lock` (fs4 flock is not reentrant).
        let facts = self.admission_facts_locked()?;
        admission(&facts).map_err(BeginCheckedError::Rejected)?;

        self.write_new_plan(verified, plan_bytes, envelope_bytes, &plan_dir)
            .map_err(BeginCheckedError::Staging)
    }

    /// Atomically admit a **staged** plan into [`UpdateStage::Applying`] under
    /// one env-lock hold — the apply-time analogue of [`begin_checked`]. This is
    /// the single-flight gate that closes the concurrent-apply TOCTOU: with the
    /// lock held it (1) confirms the target plan is still `Staged`, (2) rejects
    /// with [`BeginApplyError::AlreadyApplying`] if any *other* plan in this env
    /// is already `Applying`, (3) runs the caller's `admission` predicate against
    /// a race-free [`AdmissionFacts`] snapshot (the same downgrade/compat inputs
    /// [`begin_checked`] gets), and only then (4) commits `Staged → Applying`.
    ///
    /// The predicate must not call a *locking* staging method — it runs while
    /// the env lock is held, so doing so surfaces as [`BeginApplyError::Staging`]
    /// with [`StagingError::LockReentered`] rather than a deadlock. The lock-free
    /// reads on a [`StagedPlan`] handle (`plan_bytes`, `envelope_bytes`,
    /// `verify_artifact_on_disk`) are safe to call from the predicate for
    /// apply-time re-verification.
    ///
    /// On any rejection nothing is written and the plan stays `Staged`. A
    /// non-`Staged` target is [`StagingError::InvalidTransition`]; a missing one
    /// is [`StagingError::PlanNotFound`] (both via [`BeginApplyError::Staging`]).
    /// The returned handle is at `Applying`; the caller drives it on to `Applied`
    /// or `Failed`.
    ///
    /// [`begin_checked`]: UpdatesRoot::begin_checked
    pub fn begin_apply_checked<E>(
        &self,
        plan_id: &str,
        admission: impl FnOnce(&AdmissionFacts) -> Result<(), E>,
    ) -> Result<StagedPlan, BeginApplyError<E>> {
        validate_plan_id(plan_id)?;

        let _lock = acquire_lock(&self.env_dir)?;
        let plan_dir = self.env_dir.join(plan_id);

        // The target must exist and still be `Staged` — re-read under the lock so
        // a transition that landed since the caller's `load` cannot be applied
        // over.
        let state = read_state(&plan_dir)?.ok_or_else(|| StagingError::PlanNotFound {
            plan_id: plan_id.to_string(),
            env_id: self.env_id.clone(),
        })?;
        if state.stage != UpdateStage::Staged {
            return Err(StagingError::InvalidTransition {
                plan_id: plan_id.to_string(),
                from: state.stage,
                to: UpdateStage::Applying,
            }
            .into());
        }

        // Single-flight: at most one plan may be `Applying` per env. The target
        // is `Staged` (checked above), so any `Applying` plan is another one.
        let (applying, facts) = self.apply_admission_locked()?;
        if let Some(applying) = applying {
            return Err(BeginApplyError::AlreadyApplying {
                env_id: self.env_id.clone(),
                applying,
            });
        }

        // Downgrade/compat gate, atomic with the commit below (no TOCTOU against
        // a concurrent apply that could raise the applied sequence).
        admission(&facts).map_err(BeginApplyError::Rejected)?;

        // Build the returned handle BEFORE committing, so the only fallible step
        // after the state advances to `Applying` is the accepted commit-then-
        // audit gap (see `transition_locked`) — never a handle-build failure
        // (e.g. a corrupt `plan.json`) that would strand the plan at `Applying`
        // while the caller sees `Err` and cannot retry.
        let handle = self.staged_handle(plan_dir.clone(), &state)?;

        // Commit `Staged → Applying`. The lock is already held, so transition
        // inline rather than through `StagedPlan::transition` (which re-enters
        // it and would trip the non-reentrant flock guard).
        transition_locked(
            &self.env_dir,
            &self.env_id,
            plan_id,
            &plan_dir,
            UpdateStage::Applying,
        )?;

        Ok(handle)
    }

    /// Reject a plan whose `env_id` does not match this root.
    fn check_targets_env(&self, plan: &crate::plan::UpdatePlan) -> Result<(), StagingError> {
        if plan.env_id != self.env_id {
            return Err(StagingError::EnvMismatch {
                plan_env: plan.env_id.clone(),
                root_env: self.env_id.clone(),
            });
        }
        Ok(())
    }

    /// The applied-plan facts an admission predicate needs. **Must be called
    /// with the env `.lock` held** so the snapshot is race-free against a
    /// concurrent apply; it relies on the lock-free `scan_plans` (see its doc)
    /// to avoid re-entering the non-reentrant flock. Uses the **strict** scan:
    /// a corrupt or directory-mismatched `Applied` marker fails admission closed
    /// rather than lowering the visible `latest_applied_sequence`.
    fn admission_facts_locked(&self) -> Result<AdmissionFacts, StagingError> {
        let applied: Vec<StageState> = self
            .scan_plans(true)?
            .into_iter()
            .filter(|s| s.stage == UpdateStage::Applied)
            .collect();
        Ok(AdmissionFacts {
            latest_applied_sequence: applied.iter().map(|s| s.sequence).max(),
            applied_plan_ids: applied.into_iter().map(|s| s.plan_id).collect(),
        })
    }

    /// The apply-admission inputs, from a single strict scan under the held env
    /// `.lock`: the id of a plan already in [`UpdateStage::Applying`] (the
    /// single-flight input) and the applied-set [`AdmissionFacts`] the caller's
    /// downgrade/compat predicate needs. Like
    /// [`admission_facts_locked`](Self::admission_facts_locked) it relies on the
    /// lock-free strict [`scan_plans`](Self::scan_plans) to avoid re-entering the
    /// non-reentrant flock, and a corrupt marker fails admission closed.
    ///
    /// Single-flight and the applied-set both key off a plan's `state.json`
    /// marker. Per [`scan_plans`](Self::scan_plans)'s contract, a plan-id
    /// directory with an *absent* marker is treated as a legitimately-incomplete
    /// `begin` and skipped in both modes — deliberately, so a crashed mid-`begin`
    /// (dir + `plan.json` written, `state.json` not yet) does not wedge the whole
    /// env's admission by failing closed forever. The FSM only reaches `Applying`
    /// or `Applied` *after* writing the marker, so an active plan is always
    /// visible here; only external deletion of a live marker (outside the staging
    /// trust model, which defends path/segment integrity, not arbitrary FS
    /// writes) could hide one.
    fn apply_admission_locked(&self) -> Result<(Option<String>, AdmissionFacts), StagingError> {
        let states = self.scan_plans(true)?;
        let applying = states
            .iter()
            .find(|s| s.stage == UpdateStage::Applying)
            .map(|s| s.plan_id.clone());
        let applied: Vec<&StageState> = states
            .iter()
            .filter(|s| s.stage == UpdateStage::Applied)
            .collect();
        let facts = AdmissionFacts {
            latest_applied_sequence: applied.iter().map(|s| s.sequence).max(),
            applied_plan_ids: applied.iter().map(|s| s.plan_id.clone()).collect(),
        };
        Ok((applying, facts))
    }

    /// Write a brand-new plan's directory, bytes, `Downloading` marker, and
    /// `begin` audit line. **The caller must hold the env `.lock` and must have
    /// confirmed the plan does not already exist.** Shared by [`begin`] and
    /// [`begin_checked`].
    ///
    /// [`begin`]: UpdatesRoot::begin
    /// [`begin_checked`]: UpdatesRoot::begin_checked
    fn write_new_plan(
        &self,
        verified: &VerifiedUpdatePlan,
        plan_bytes: &[u8],
        envelope_bytes: &[u8],
        plan_dir: &Path,
    ) -> Result<StagedPlan, StagingError> {
        let plan = &verified.plan;
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
        write_state(plan_dir, &state)?;
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
            plan_dir: plan_dir.to_path_buf(),
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
        Ok(Some(self.staged_handle(plan_dir, &state)?))
    }

    /// Build a [`StagedPlan`] handle for `plan_dir` from an already-read `state`,
    /// reparsing `plan.json` from disk. Does **not** acquire the env `.lock`, so
    /// it is safe to call from a context that already holds it (e.g.
    /// [`begin_apply_checked`](Self::begin_apply_checked)). Shared with
    /// [`load`](Self::load).
    fn staged_handle(
        &self,
        plan_dir: PathBuf,
        state: &StageState,
    ) -> Result<StagedPlan, StagingError> {
        let plan_path = plan_dir.join(PLAN_FILE);
        let plan_bytes = fs::read(&plan_path).map_err(|source| StagingError::Io {
            path: plan_path.clone(),
            source,
        })?;
        let plan = serde_json::from_slice(&plan_bytes).map_err(|source| StagingError::State {
            path: plan_path,
            source,
        })?;
        Ok(StagedPlan {
            env_dir: self.env_dir.clone(),
            env_id: self.env_id.clone(),
            plan_dir,
            plan,
            plan_sha256: state.plan_sha256.clone(),
        })
    }

    /// The `state.json` of every staged plan. Order is filesystem-dependent.
    /// Best-effort (forgiving) enumeration — see [`scan_plans`] for the
    /// lock-free contract and the strict admission variant.
    ///
    /// `state.json` is treated as untrusted: an entry is included only if its
    /// directory name is a valid plan id (this also skips `audit/` and `.lock`)
    /// **and** the marker's own `plan_id` equals that directory name. A corrupt,
    /// foreign, or unreadable marker is skipped rather than trusted — so an
    /// attacker-controlled `plan_id` can never drive a filesystem path in
    /// [`latest_applied_sequence`](Self::latest_applied_sequence) or
    /// [`apply_retention`](Self::apply_retention).
    ///
    /// [`scan_plans`]: Self::scan_plans
    pub fn list(&self) -> Result<Vec<StageState>, StagingError> {
        self.scan_plans(false)
    }

    /// Enumerate plan markers under the env dir. Deliberately **does not**
    /// acquire the env `.lock`, so it can be called by callers that already hold
    /// it (`apply_retention`, `begin_checked` via `admission_facts_locked`) —
    /// the flock is not reentrant, so acquiring one here would deadlock them.
    ///
    /// With `strict == false` this is the forgiving [`list`](Self::list)
    /// behavior: a present-but-unreadable, corrupt, or directory-mismatched
    /// `state.json` is silently skipped. With `strict == true` (admission scans)
    /// any such marker is a hard [`StagingError::CorruptAdmissionState`], so a
    /// safety decision never runs against a snapshot that silently dropped a
    /// possibly-`Applied` plan. An *absent* `state.json` is a legitimately
    /// incomplete plan and is skipped in both modes.
    fn scan_plans(&self, strict: bool) -> Result<Vec<StageState>, StagingError> {
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
            // Non-plan-id dirs (`audit/`, `.lock`, anything unsafe) are
            // infrastructure, not plans — skipped in both modes.
            if validate_plan_id(&name).is_err() {
                continue;
            }
            // Anchor the marker to its directory. An unreadable, corrupt, or
            // directory-mismatched marker is untrusted: `list()` skips it
            // (best-effort), but a strict admission scan fails closed rather
            // than silently omit a possibly-`Applied` plan.
            match read_state(&entry.path()) {
                Ok(Some(state)) if state.plan_id == name => out.push(state),
                Ok(Some(state)) if strict => {
                    return Err(StagingError::CorruptAdmissionState {
                        plan_id: name,
                        reason: format!(
                            "state.json plan_id `{}` disagrees with its directory",
                            state.plan_id
                        ),
                    });
                }
                Err(source) if strict => {
                    return Err(StagingError::CorruptAdmissionState {
                        plan_id: name,
                        reason: format!("state.json is unreadable: {source}"),
                    });
                }
                // Absent marker, or non-strict skip of an untrusted one.
                Ok(None) | Ok(Some(_)) | Err(_) => {}
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
        Ok(RetentionReport { scanned, evicted })
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
    /// The `PlanNotFound` error for this handle, shared by the state readers,
    /// `put_artifact`, and `transition`.
    fn plan_not_found(&self) -> StagingError {
        StagingError::PlanNotFound {
            plan_id: self.plan.plan_id.clone(),
            env_id: self.env_id.clone(),
        }
    }

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
        read_state(&self.plan_dir)?.ok_or_else(|| self.plan_not_found())
    }

    /// Read the raw bytes of the staged `plan.json` — the DSSE statement body,
    /// the first input to [`crate::plan::verify_update_plan`]. Callers re-verify
    /// the signature at apply-time as defense-in-depth: the bytes on disk are
    /// untrusted even though they were verified when the plan was staged.
    pub fn plan_bytes(&self) -> Result<Vec<u8>, StagingError> {
        read_regular_file_in(&self.env_dir, &self.plan_dir.join(PLAN_FILE))
    }

    /// Read the raw bytes of the staged `plan.json.sig` — the DSSE envelope
    /// sidecar, the second input to [`crate::plan::verify_update_plan`].
    pub fn envelope_bytes(&self) -> Result<Vec<u8>, StagingError> {
        read_regular_file_in(&self.env_dir, &self.plan_dir.join(SIG_FILE))
    }

    /// The content-addressed blob path for `artifact`
    /// (`artifacts/sha256-<hex>/blob`). Validates the digest format first, so a
    /// malformed `artifact.digest` is rejected before any filesystem access.
    pub fn artifact_blob_path(&self, artifact: &PlanArtifact) -> Result<PathBuf, StagingError> {
        let (dir_name, _) = digest_dir_name(&artifact.digest)?;
        Ok(self
            .plan_dir
            .join(ARTIFACTS_DIR)
            .join(dir_name)
            .join(BLOB_FILE))
    }

    /// Re-read a staged artifact's blob and re-verify its SHA-256 against
    /// `artifact.digest`, returning the bytes on match. [`Self::put_artifact`]
    /// hashes on ingest, but the bytes on disk are untrusted at apply-time —
    /// this closes the read-side integrity check and fails closed with
    /// [`StagingError::DigestMismatch`].
    pub fn verify_artifact_on_disk(
        &self,
        artifact: &PlanArtifact,
    ) -> Result<Vec<u8>, StagingError> {
        let (dir_name, expected_hex) = digest_dir_name(&artifact.digest)?;
        let blob = self
            .plan_dir
            .join(ARTIFACTS_DIR)
            .join(dir_name)
            .join(BLOB_FILE);
        // The staging tree is untrusted at apply time: refuse a symlinked or
        // non-regular blob before reading, so the integrity check can't be
        // tricked into following a symlink out of the tree or blocking on a FIFO.
        let bytes = read_regular_file_in(&self.env_dir, &blob)?;
        let actual_hex = crate::plan::sha256_hex(&bytes);
        if actual_hex != expected_hex {
            return Err(StagingError::DigestMismatch {
                name: artifact.name.clone(),
                expected: artifact.digest.clone(),
                actual: format!("sha256:{actual_hex}"),
            });
        }
        Ok(bytes)
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
        let (dir_name, expected_hex) = digest_dir_name(&artifact.digest)?;
        let actual_hex = crate::plan::sha256_hex(bytes);
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
            .ok_or_else(|| self.plan_not_found())?
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
        transition_locked(
            &self.env_dir,
            &self.env_id,
            &self.plan.plan_id,
            &self.plan_dir,
            to,
        )
    }
}

/// Commit a `from → to` stage transition for the plan at `plan_dir`, **assuming
/// the env `.lock` is already held**. Gated by [`is_valid_transition`]; rewrites
/// `state.json` atomically, then appends the audit line. Shared by
/// [`StagedPlan::transition`] (which acquires the lock first) and
/// [`UpdatesRoot::begin_apply_checked`] (which holds it across the admission
/// predicate, so it cannot re-acquire the non-reentrant flock).
fn transition_locked(
    env_dir: &Path,
    env_id: &str,
    plan_id: &str,
    plan_dir: &Path,
    to: UpdateStage,
) -> Result<StageState, StagingError> {
    let mut state = read_state(plan_dir)?.ok_or_else(|| StagingError::PlanNotFound {
        plan_id: plan_id.to_string(),
        env_id: env_id.to_string(),
    })?;
    let from = state.stage;
    if !is_valid_transition(from, to) {
        return Err(StagingError::InvalidTransition {
            plan_id: plan_id.to_string(),
            from,
            to,
        });
    }
    state.stage = to;
    state.updated_at = Utc::now();
    assert_no_symlink_ancestors(env_dir, &plan_dir.join(STATE_FILE))?;
    write_state(plan_dir, &state)?;
    // State is committed before the audit line: if the append or its fsync
    // fails, the transition is already durable and this returns Err (a retry
    // then hits InvalidTransition). This is the same commit-then-audit gap the
    // deployer's `audit_and_record` documents and accepts — the on-disk backend
    // has no cross-file transaction, and the stage marker is the source of
    // truth. A crash in this window likewise leaves a committed transition with
    // no audit line.
    append_audit(
        env_dir,
        &make_event(
            env_id,
            plan_id,
            to.as_str(),
            Some(from),
            Some(to),
            Value::Null,
        ),
    )?;
    Ok(state)
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
    /// Ids of evicted plans (count via `evicted.len()`).
    pub evicted: Vec<String>,
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

/// Read a file under the staging `root`, failing closed if the path is unsafe
/// to follow. The staging tree is untrusted at read time (apply re-verifies its
/// contents), so — mirroring the write path's [`assert_no_symlink_ancestors`]
/// guard — reject a symlink at any path component (an escape) and a non-regular
/// final file (a FIFO/device/socket/directory would block or return non-file
/// bytes) *before* `fs::read` follows anything dangerous.
fn read_regular_file_in(root: &Path, path: &Path) -> Result<Vec<u8>, StagingError> {
    assert_no_symlink_ancestors(root, path)?;
    let meta = fs::symlink_metadata(path).map_err(|source| StagingError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if !meta.file_type().is_file() {
        return Err(StagingError::NotRegularFile {
            path: path.to_path_buf(),
        });
    }
    fs::read(path).map_err(|source| StagingError::Io {
        path: path.to_path_buf(),
        source,
    })
}

/// Validate a `sha256:<64 hex>` digest, returning its directory name
/// (`sha256-<lowercase hex>`) and the validated lowercase hex — so callers that
/// need both parse the digest once.
fn digest_dir_name(digest: &str) -> Result<(String, String), StagingError> {
    let hex = digest
        .strip_prefix("sha256:")
        .filter(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or_else(|| StagingError::MalformedDigest {
            digest: digest.to_string(),
        })?
        .to_ascii_lowercase();
    Ok((format!("sha256-{hex}"), hex))
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

thread_local! {
    /// Env dirs whose `.lock` this thread currently holds. The fs4 flock is per
    /// open-file-description, so a *second* `acquire_lock` on the same thread
    /// would block forever waiting on a lock the thread itself already holds. We
    /// detect that re-entry and fail fast with [`StagingError::LockReentered`].
    /// Only same-thread re-entry is caught; other threads and processes still
    /// contend on the OS flock as normal.
    static HELD_ENV_LOCKS: RefCell<HashSet<PathBuf>> = RefCell::new(HashSet::new());
}

/// RAII exclusive lock on `<env_dir>/.lock`. Dropping releases the OS lock and
/// clears this thread's re-entry guard for the env.
struct Flock {
    _file: File,
    env_dir: PathBuf,
}

impl Drop for Flock {
    fn drop(&mut self) {
        HELD_ENV_LOCKS.with(|held| {
            held.borrow_mut().remove(&self.env_dir);
        });
        // The `_file` field drops next, releasing the OS flock.
    }
}

fn acquire_lock(env_dir: &Path) -> Result<Flock, StagingError> {
    let key = env_dir.to_path_buf();
    // Same-thread re-entry would deadlock on the non-reentrant flock — fail fast
    // rather than hang. Checked (not inserted) here so failed acquisitions below
    // never leave a stale guard entry; ownership is recorded only once the OS
    // lock is actually held.
    if HELD_ENV_LOCKS.with(|held| held.borrow().contains(&key)) {
        return Err(StagingError::LockReentered {
            path: env_dir.join(LOCK_FILE),
        });
    }
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
    HELD_ENV_LOCKS.with(|held| {
        held.borrow_mut().insert(key.clone());
    });
    Ok(Flock {
        _file: file,
        env_dir: key,
    })
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
    use std::convert::Infallible;
    use tempfile::TempDir;

    fn digest_of(bytes: &[u8]) -> String {
        format!("sha256:{}", crate::plan::sha256_hex(bytes))
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

    // Drive a freshly-begun plan all the way to `Applied` (for admission tests).
    fn apply_plan(root: &UpdatesRoot, plan_id: &str, sequence: u64) {
        let staged = root
            .begin(
                &verified(plan_with(plan_id, "prod", sequence, vec![])),
                b"p",
                b"s",
            )
            .unwrap();
        staged.transition(UpdateStage::Inbox).unwrap();
        staged.transition(UpdateStage::Staged).unwrap();
        staged.transition(UpdateStage::Applying).unwrap();
        staged.transition(UpdateStage::Applied).unwrap();
    }

    // Begin a plan and drive it to `Staged` — ready for apply admission. Writes
    // the canonical plan JSON as the plan bytes so the handle `begin_apply_checked`
    // rebuilds (which reparses `plan.json`) round-trips.
    fn stage_plan(root: &UpdatesRoot, plan_id: &str, sequence: u64) -> StagedPlan {
        let plan = plan_with(plan_id, "prod", sequence, vec![]);
        let plan_bytes = serde_json::to_vec(&plan).unwrap();
        let staged = root.begin(&verified(plan), &plan_bytes, b"s").unwrap();
        staged.transition(UpdateStage::Inbox).unwrap();
        staged.transition(UpdateStage::Staged).unwrap();
        staged
    }

    #[test]
    fn begin_checked_admits_when_predicate_accepts() {
        let tmp = TempDir::new().unwrap();
        let root = UpdatesRoot::open_in(tmp.path(), "prod").unwrap();
        let plan = plan_with("plan-1", "prod", 3, vec![]);
        let plan_bytes = serde_json::to_vec(&plan).unwrap();
        let v = verified(plan);

        let staged = root
            .begin_checked(&v, &plan_bytes, b"s", |_facts| Ok::<(), Infallible>(()))
            .unwrap();

        // Identical outcome to `begin`: admitted at `Downloading`, loadable.
        assert_eq!(staged.stage().unwrap(), UpdateStage::Downloading);
        assert_eq!(
            root.load("plan-1").unwrap().unwrap().stage().unwrap(),
            UpdateStage::Downloading
        );
    }

    #[test]
    fn begin_checked_rejection_writes_nothing() {
        let tmp = TempDir::new().unwrap();
        let root = UpdatesRoot::open_in(tmp.path(), "prod").unwrap();
        let v = verified(plan_with("plan-1", "prod", 3, vec![]));

        let err = root
            .begin_checked(&v, b"p", b"s", |_facts| Err::<(), &str>("nope"))
            .unwrap_err();

        assert!(matches!(err, BeginCheckedError::Rejected("nope")));
        // A rejected plan leaves nothing half-staged.
        assert!(root.load("plan-1").unwrap().is_none());
        assert!(!tmp.path().join("prod").join("plan-1").exists());
    }

    #[test]
    fn begin_checked_snapshots_applied_set_under_lock() {
        let tmp = TempDir::new().unwrap();
        let root = UpdatesRoot::open_in(tmp.path(), "prod").unwrap();
        apply_plan(&root, "old", 5);

        // The predicate must see the applied set (seq 5, id "old"), proving the
        // downgrade/compat inputs are read atomically with the begin writes.
        let mut seen: Option<AdmissionFacts> = None;
        root.begin_checked(
            &verified(plan_with("new", "prod", 6, vec![])),
            b"p",
            b"s",
            |facts| {
                seen = Some(facts.clone());
                Ok::<(), Infallible>(())
            },
        )
        .unwrap();

        let facts = seen.expect("predicate ran");
        assert_eq!(facts.latest_applied_sequence, Some(5));
        assert_eq!(facts.applied_plan_ids, vec!["old".to_string()]);
    }

    #[test]
    fn begin_checked_downgrade_gate_composes_with_ensure_not_downgrade() {
        // The intended caller shape: reject a plan whose sequence is not newer
        // than the highest applied sequence — inside the lock, no TOCTOU.
        let tmp = TempDir::new().unwrap();
        let root = UpdatesRoot::open_in(tmp.path(), "prod").unwrap();
        apply_plan(&root, "old", 5);

        let stale = verified(plan_with("stale", "prod", 5, vec![]));
        let err = root
            .begin_checked(&stale, b"p", b"s", |facts| {
                crate::plan::ensure_not_downgrade(&stale.plan, facts.latest_applied_sequence)
            })
            .unwrap_err();

        assert!(matches!(
            err,
            BeginCheckedError::Rejected(crate::plan::PlanError::Downgrade { plan: 5, last: 5 })
        ));
        assert!(root.load("stale").unwrap().is_none());
    }

    #[test]
    fn begin_checked_rejects_duplicate_before_predicate() {
        let tmp = TempDir::new().unwrap();
        let root = UpdatesRoot::open_in(tmp.path(), "prod").unwrap();
        let v = verified(plan_with("plan-1", "prod", 1, vec![]));
        root.begin(&v, b"p", b"s").unwrap();

        let mut called = false;
        let err = root
            .begin_checked(&v, b"p", b"s", |_facts| {
                called = true;
                Ok::<(), Infallible>(())
            })
            .unwrap_err();

        assert!(matches!(
            err,
            BeginCheckedError::Staging(StagingError::PlanExists { .. })
        ));
        assert!(!called, "predicate must not run for an already-staged plan");
    }

    #[test]
    fn begin_checked_fails_closed_on_corrupt_applied_marker() {
        let tmp = TempDir::new().unwrap();
        let root = UpdatesRoot::open_in(tmp.path(), "prod").unwrap();
        apply_plan(&root, "old", 5);

        // Corrupt the applied plan's marker (disk corruption / local tamper).
        let marker = tmp.path().join("prod").join("old").join(STATE_FILE);
        fs::write(&marker, b"{ not valid json").unwrap();

        // Admission must fail CLOSED — not silently drop `old` (lowering the
        // visible latest sequence) and admit a stale plan.
        let err = root
            .begin_checked(
                &verified(plan_with("new", "prod", 6, vec![])),
                b"p",
                b"s",
                |_facts| Ok::<(), Infallible>(()),
            )
            .unwrap_err();
        assert!(matches!(
            err,
            BeginCheckedError::Staging(StagingError::CorruptAdmissionState { .. })
        ));
        // The best-effort `list()` still tolerates the corrupt marker.
        assert!(root.list().is_ok());
    }

    #[test]
    fn begin_checked_predicate_reentering_lock_fails_fast_not_deadlock() {
        let tmp = TempDir::new().unwrap();
        let root = UpdatesRoot::open_in(tmp.path(), "prod").unwrap();

        // A predicate that misuses the API by calling a locking method while the
        // env lock is held must get `LockReentered` — never hang.
        let err = root
            .begin_checked(
                &verified(plan_with("plan-1", "prod", 1, vec![])),
                b"p",
                b"s",
                |_facts| {
                    root.apply_retention(&RetentionPolicy { keep_terminal: 1 })
                        .map(|_| ())
                },
            )
            .unwrap_err();
        assert!(matches!(
            err,
            BeginCheckedError::Rejected(StagingError::LockReentered { .. })
        ));
    }

    #[test]
    fn begin_apply_checked_admits_staged_with_no_other_applying() {
        let tmp = TempDir::new().unwrap();
        let root = UpdatesRoot::open_in(tmp.path(), "prod").unwrap();
        stage_plan(&root, "plan-1", 3);

        let staged = root
            .begin_apply_checked("plan-1", |_facts| Ok::<(), Infallible>(()))
            .unwrap();

        // The returned handle — and the on-disk marker — are now `Applying`.
        assert_eq!(staged.stage().unwrap(), UpdateStage::Applying);
        assert_eq!(
            root.load("plan-1").unwrap().unwrap().stage().unwrap(),
            UpdateStage::Applying
        );
    }

    #[test]
    fn begin_apply_checked_rejects_when_another_plan_applying() {
        let tmp = TempDir::new().unwrap();
        let root = UpdatesRoot::open_in(tmp.path(), "prod").unwrap();
        // One plan already in flight.
        stage_plan(&root, "in-flight", 4)
            .transition(UpdateStage::Applying)
            .unwrap();
        // A second, staged plan cannot begin applying while the first is Applying.
        stage_plan(&root, "waiting", 5);

        let mut called = false;
        let err = root
            .begin_apply_checked("waiting", |_facts| {
                called = true;
                Ok::<(), Infallible>(())
            })
            .unwrap_err();

        assert!(matches!(
            err,
            BeginApplyError::AlreadyApplying { ref applying, .. } if applying == "in-flight"
        ));
        assert!(!called, "single-flight rejects before the predicate runs");
        // The waiting plan is untouched — still Staged.
        assert_eq!(
            root.load("waiting").unwrap().unwrap().stage().unwrap(),
            UpdateStage::Staged
        );
    }

    #[test]
    fn begin_apply_checked_rejection_leaves_plan_staged() {
        let tmp = TempDir::new().unwrap();
        let root = UpdatesRoot::open_in(tmp.path(), "prod").unwrap();
        stage_plan(&root, "plan-1", 3);

        let err = root
            .begin_apply_checked("plan-1", |_facts| Err::<(), &str>("nope"))
            .unwrap_err();

        assert!(matches!(err, BeginApplyError::Rejected("nope")));
        // A rejected apply does not transition the plan out of Staged.
        assert_eq!(
            root.load("plan-1").unwrap().unwrap().stage().unwrap(),
            UpdateStage::Staged
        );
    }

    #[test]
    fn begin_apply_checked_rejects_non_staged_target() {
        let tmp = TempDir::new().unwrap();
        let root = UpdatesRoot::open_in(tmp.path(), "prod").unwrap();

        // Downloading (fresh begin) is not applyable.
        root.begin(&verified(plan_with("fresh", "prod", 1, vec![])), b"p", b"s")
            .unwrap();
        let err = root
            .begin_apply_checked("fresh", |_facts| Ok::<(), Infallible>(()))
            .unwrap_err();
        assert!(matches!(
            err,
            BeginApplyError::Staging(StagingError::InvalidTransition {
                from: UpdateStage::Downloading,
                to: UpdateStage::Applying,
                ..
            })
        ));

        // An already-applied (terminal) plan is likewise refused.
        apply_plan(&root, "done", 2);
        let err = root
            .begin_apply_checked("done", |_facts| Ok::<(), Infallible>(()))
            .unwrap_err();
        assert!(matches!(
            err,
            BeginApplyError::Staging(StagingError::InvalidTransition {
                from: UpdateStage::Applied,
                to: UpdateStage::Applying,
                ..
            })
        ));
    }

    #[test]
    fn begin_apply_checked_plan_not_found() {
        let tmp = TempDir::new().unwrap();
        let root = UpdatesRoot::open_in(tmp.path(), "prod").unwrap();
        let err = root
            .begin_apply_checked("ghost", |_facts| Ok::<(), Infallible>(()))
            .unwrap_err();
        assert!(matches!(
            err,
            BeginApplyError::Staging(StagingError::PlanNotFound { .. })
        ));
    }

    #[test]
    fn begin_apply_checked_fails_closed_on_corrupt_marker() {
        let tmp = TempDir::new().unwrap();
        let root = UpdatesRoot::open_in(tmp.path(), "prod").unwrap();
        apply_plan(&root, "old", 5);
        stage_plan(&root, "new", 6);

        // Corrupt an *other* plan's marker: the strict apply-admission scan must
        // fail closed rather than silently drop a possibly-Applied plan.
        let marker = tmp.path().join("prod").join("old").join(STATE_FILE);
        fs::write(&marker, b"{ not valid json").unwrap();

        let err = root
            .begin_apply_checked("new", |_facts| Ok::<(), Infallible>(()))
            .unwrap_err();
        assert!(matches!(
            err,
            BeginApplyError::Staging(StagingError::CorruptAdmissionState { .. })
        ));
        // The target plan is not transitioned when admission fails closed.
        assert_eq!(
            root.load("new").unwrap().unwrap().stage().unwrap(),
            UpdateStage::Staged
        );
    }

    #[test]
    fn begin_apply_checked_predicate_runs_under_lock() {
        let tmp = TempDir::new().unwrap();
        let root = UpdatesRoot::open_in(tmp.path(), "prod").unwrap();
        stage_plan(&root, "plan-1", 3);

        // A predicate that misuses the API by calling a *locking* method while
        // the env lock is held must get `LockReentered` — proving the predicate
        // runs under the same lock hold as the commit (never a deadlock).
        let err = root
            .begin_apply_checked("plan-1", |_facts| {
                root.apply_retention(&RetentionPolicy { keep_terminal: 1 })
                    .map(|_| ())
            })
            .unwrap_err();
        assert!(matches!(
            err,
            BeginApplyError::Rejected(StagingError::LockReentered { .. })
        ));
    }

    #[test]
    fn begin_apply_checked_snapshots_applied_set() {
        let tmp = TempDir::new().unwrap();
        let root = UpdatesRoot::open_in(tmp.path(), "prod").unwrap();
        apply_plan(&root, "old", 5);
        stage_plan(&root, "new", 6);

        // The predicate sees the applied set atomically (seq 5, id "old") — the
        // downgrade/compat inputs, read under the same lock as the commit.
        let mut seen: Option<AdmissionFacts> = None;
        root.begin_apply_checked("new", |facts| {
            seen = Some(facts.clone());
            Ok::<(), Infallible>(())
        })
        .unwrap();

        let facts = seen.expect("predicate ran");
        assert_eq!(facts.latest_applied_sequence, Some(5));
        assert_eq!(facts.applied_plan_ids, vec!["old".to_string()]);
    }

    #[test]
    fn begin_apply_checked_handle_build_failure_does_not_commit_applying() {
        let tmp = TempDir::new().unwrap();
        let root = UpdatesRoot::open_in(tmp.path(), "prod").unwrap();
        stage_plan(&root, "plan-1", 3);

        // Corrupt plan.json so building the returned handle fails. The handle is
        // built BEFORE the Staged->Applying commit, so the failure must leave the
        // plan at Staged — never a half-applied marker that strands it while the
        // caller only sees Err.
        let plan_json = tmp.path().join("prod").join("plan-1").join(PLAN_FILE);
        fs::write(&plan_json, b"{ not json").unwrap();

        let err = root
            .begin_apply_checked("plan-1", |_facts| Ok::<(), Infallible>(()))
            .unwrap_err();
        assert!(matches!(
            err,
            BeginApplyError::Staging(StagingError::State { .. })
        ));

        // The marker was NOT advanced. `load` would reparse the now-corrupt
        // plan.json, so read state.json directly.
        let state_raw =
            fs::read_to_string(tmp.path().join("prod").join("plan-1").join(STATE_FILE)).unwrap();
        assert!(
            state_raw.contains("\"staged\""),
            "plan must remain Staged when the handle build fails: {state_raw}"
        );
    }

    #[test]
    fn begin_apply_checked_result_can_transition_to_applied() {
        let tmp = TempDir::new().unwrap();
        let root = UpdatesRoot::open_in(tmp.path(), "prod").unwrap();
        stage_plan(&root, "plan-1", 3);

        let staged = root
            .begin_apply_checked("plan-1", |_facts| Ok::<(), Infallible>(()))
            .unwrap();
        // The Applying handle drives on to a terminal stage via the existing FSM.
        staged.transition(UpdateStage::Applied).unwrap();
        assert_eq!(
            root.load("plan-1").unwrap().unwrap().stage().unwrap(),
            UpdateStage::Applied
        );
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
    fn plan_bytes_reads_staged_plan() {
        let tmp = TempDir::new().unwrap();
        let root = UpdatesRoot::open_in(tmp.path(), "prod").unwrap();
        let plan_bytes = br#"{"canonical":"plan"}"#;
        let staged = root
            .begin(
                &verified(plan_with("plan-1", "prod", 1, vec![])),
                plan_bytes,
                b"sig",
            )
            .unwrap();
        assert_eq!(staged.plan_bytes().unwrap(), plan_bytes);
    }

    #[test]
    fn envelope_bytes_reads_sidecar() {
        let tmp = TempDir::new().unwrap();
        let root = UpdatesRoot::open_in(tmp.path(), "prod").unwrap();
        let sig_bytes = b"dsse-envelope-bytes";
        let staged = root
            .begin(
                &verified(plan_with("plan-1", "prod", 1, vec![])),
                b"plan",
                sig_bytes,
            )
            .unwrap();
        assert_eq!(staged.envelope_bytes().unwrap(), sig_bytes);
    }

    #[test]
    fn verify_artifact_on_disk_returns_bytes_on_match() {
        let tmp = TempDir::new().unwrap();
        let root = UpdatesRoot::open_in(tmp.path(), "prod").unwrap();
        let payload = b"artifact-payload";
        let art = artifact("pack-a", payload);
        let staged = root
            .begin(
                &verified(plan_with("plan-1", "prod", 1, vec![art.clone()])),
                b"p",
                b"s",
            )
            .unwrap();
        staged.put_artifact(&art, payload).unwrap();
        assert_eq!(staged.verify_artifact_on_disk(&art).unwrap(), payload);
    }

    #[test]
    fn verify_artifact_on_disk_rejects_tampered_blob() {
        let tmp = TempDir::new().unwrap();
        let root = UpdatesRoot::open_in(tmp.path(), "prod").unwrap();
        let payload = b"artifact-payload";
        let art = artifact("pack-a", payload);
        let staged = root
            .begin(
                &verified(plan_with("plan-1", "prod", 1, vec![art.clone()])),
                b"p",
                b"s",
            )
            .unwrap();
        staged.put_artifact(&art, payload).unwrap();
        // Corrupt the blob after it was hash-verified on ingest: the read-side
        // check must fail closed.
        let blob = staged.artifact_blob_path(&art).unwrap();
        fs::write(&blob, b"tampered-bytes").unwrap();
        assert!(matches!(
            staged.verify_artifact_on_disk(&art),
            Err(StagingError::DigestMismatch { .. })
        ));
    }

    #[test]
    fn artifact_blob_path_rejects_malformed_digest() {
        let tmp = TempDir::new().unwrap();
        let root = UpdatesRoot::open_in(tmp.path(), "prod").unwrap();
        let staged = root
            .begin(
                &verified(plan_with("plan-1", "prod", 1, vec![])),
                b"p",
                b"s",
            )
            .unwrap();
        let bad = PlanArtifact {
            name: "pack-a".to_string(),
            version: "1.0.0".to_string(),
            digest: "sha256:not-hex".to_string(),
            source: None,
        };
        // Both the path builder and the verifier reject before touching disk.
        assert!(matches!(
            staged.artifact_blob_path(&bad),
            Err(StagingError::MalformedDigest { .. })
        ));
        assert!(matches!(
            staged.verify_artifact_on_disk(&bad),
            Err(StagingError::MalformedDigest { .. })
        ));
    }

    #[test]
    fn verify_artifact_on_disk_rejects_non_regular_blob() {
        let tmp = TempDir::new().unwrap();
        let root = UpdatesRoot::open_in(tmp.path(), "prod").unwrap();
        let payload = b"artifact-payload";
        let art = artifact("pack-a", payload);
        let staged = root
            .begin(
                &verified(plan_with("plan-1", "prod", 1, vec![art.clone()])),
                b"p",
                b"s",
            )
            .unwrap();
        staged.put_artifact(&art, payload).unwrap();
        // Replace the blob with a directory (a non-regular file): the read must
        // fail closed before hashing, not block or descend.
        let blob = staged.artifact_blob_path(&art).unwrap();
        fs::remove_file(&blob).unwrap();
        fs::create_dir(&blob).unwrap();
        assert!(matches!(
            staged.verify_artifact_on_disk(&art),
            Err(StagingError::NotRegularFile { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn verify_artifact_on_disk_rejects_symlinked_blob() {
        let tmp = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        let target = outside.path().join("secret");
        fs::write(&target, b"out-of-tree bytes").unwrap();
        let root = UpdatesRoot::open_in(tmp.path(), "prod").unwrap();
        let payload = b"artifact-payload";
        let art = artifact("pack-a", payload);
        let staged = root
            .begin(
                &verified(plan_with("plan-1", "prod", 1, vec![art.clone()])),
                b"p",
                b"s",
            )
            .unwrap();
        staged.put_artifact(&art, payload).unwrap();
        // Swap the blob for a symlink pointing OUT of the staging tree: the
        // verifier must refuse to follow it (not read the escaped file).
        let blob = staged.artifact_blob_path(&art).unwrap();
        fs::remove_file(&blob).unwrap();
        std::os::unix::fs::symlink(&target, &blob).unwrap();
        assert!(matches!(
            staged.verify_artifact_on_disk(&art),
            Err(StagingError::SymlinkAncestor { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn plan_bytes_rejects_symlinked_plan_file() {
        let tmp = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        let target = outside.path().join("evil");
        fs::write(&target, b"not a plan").unwrap();
        let root = UpdatesRoot::open_in(tmp.path(), "prod").unwrap();
        let staged = root
            .begin(
                &verified(plan_with("plan-1", "prod", 1, vec![])),
                b"plan",
                b"sig",
            )
            .unwrap();
        // Swap plan.json for a symlink pointing out of the tree.
        let plan_file = staged.dir().join(PLAN_FILE);
        fs::remove_file(&plan_file).unwrap();
        std::os::unix::fs::symlink(&target, &plan_file).unwrap();
        assert!(matches!(
            staged.plan_bytes(),
            Err(StagingError::SymlinkAncestor { .. })
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
        assert_eq!(report.evicted.len(), 2, "3 terminal, keep 1 => evict 2");

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
            (format!("sha256-{hex}"), hex.clone())
        );
        // Uppercase hex is normalized to lowercase.
        assert_eq!(
            digest_dir_name(&format!("sha256:{}", "A".repeat(64))).unwrap(),
            (format!("sha256-{}", "a".repeat(64)), "a".repeat(64))
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
