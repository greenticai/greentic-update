//! Signed update plan (`greentic.update-plan.v1`).
//!
//! An update plan is the canonical, signed instruction that tells an
//! environment what to become. It is a DSSE-signed in-toto `Statement` whose
//! subject pins the SHA-256 of the canonical plan document and whose predicate
//! mirrors the plan's identity so a reader of the envelope alone can see what
//! the signature covers.
//!
//! The plan document carries the update intent: the target environment
//! manifest (a `greentic.env-manifest.v1`, kept here as opaque JSON so this
//! crate stays free of a `greentic-deploy-spec` dependency), the content
//! artifact set, compatibility constraints, a rollback policy, and a monotonic
//! `sequence` for downgrade protection.
//!
//! ## Reuse and boundaries
//!
//! Signing and verification reuse `greentic_distributor_client::signing` — the
//! same DSSE/in-toto core the pack and revenue-policy signers use — so the wire
//! format cannot drift. [`build_update_plan`] takes **raw key material**
//! (`signing_key_pkcs8_pem` + `key_id`) rather than a deployer-side key holder,
//! so this crate does not pull in `greentic-operator-trust`/`greentic-deploy-spec`.
//! The deployer-side caller passes its `OperatorKey`'s `private_pem`/`key_id`.
//!
//! ## Refusal + self-verify contract
//!
//! Like the revenue-policy builder, [`build_update_plan`] refuses to sign when
//! the signing key is not already trusted by the target environment's trust
//! root, and self-verifies the freshly-signed envelope before returning — a
//! plan the environment could not verify fails the build rather than reaching a
//! client.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use greentic_distributor_client::signing::{
    INTOTO_STATEMENT_TYPE, InTotoStatement, SigningError, Subject, TrustRoot, sign_statement,
    verify_artifact_dsse,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Schema discriminator for the plan document (`vN.json`-equivalent).
pub const UPDATE_PLAN_SCHEMA_V1: &str = "greentic.update-plan.v1";

/// Predicate-type discriminator recorded in the DSSE statement. Distinct from
/// the document schema so a verifier can reject a same-hash artifact signed
/// under a different predicate type (type confusion).
pub const UPDATE_PLAN_PREDICATE_TYPE_V1: &str = "greentic.update-plan-predicate.v1";

/// The full update plan document — the canonical artifact whose SHA-256 the
/// DSSE subject pins.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdatePlan {
    /// Schema discriminator, always [`UPDATE_PLAN_SCHEMA_V1`].
    pub schema: String,
    /// Unique plan identifier (assigned by the planner).
    pub plan_id: String,
    /// Target environment id this plan applies to.
    pub env_id: String,
    /// Monotonic sequence for downgrade protection — strictly increasing per
    /// environment. See [`ensure_not_downgrade`].
    pub sequence: u64,
    /// When the plan was created/signed (planner clock).
    pub created_at: DateTime<Utc>,
    /// Single-use nonce, echoed by the notify/webhook layer for replay
    /// rejection (the plan-level replay guard is the `sequence` check).
    pub nonce: String,
    /// Target environment manifest (`greentic.env-manifest.v1`), carried as
    /// opaque JSON so this crate does not depend on `greentic-deploy-spec`.
    pub target: serde_json::Value,
    /// Content artifacts the plan references (packs / bundles / components).
    pub artifacts: Vec<PlanArtifact>,
    /// Binary self-update artifacts — an additive, platform-keyed list of
    /// binaries the plan authorizes the environment to install. Each entry
    /// carries a Rust target triple so the runtime can select the binary for
    /// its host. The plan's DSSE signature covers this list transitively (the
    /// subject pins `sha256(plan_bytes)`, which includes the serialized
    /// `binaries`). Empty when the plan carries no binary updates — the field
    /// is omitted from JSON in that case to keep existing plan shapes (and
    /// their signatures) byte-identical.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub binaries: Vec<BinaryArtifact>,
    /// Compatibility constraints the environment must satisfy before apply.
    pub compat: CompatRequirements,
    /// Rollback policy applied if an apply fails its health gate.
    pub rollback: RollbackPolicy,
}

/// One content-addressed artifact referenced by a plan.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanArtifact {
    /// Logical artifact name (e.g. a pack id).
    pub name: String,
    /// Artifact version (semver or opaque, depending on artifact kind).
    pub version: String,
    /// Content digest, `sha256:<hex>`.
    pub digest: String,
    /// Where to fetch it (registry coordinate / URL). Absent for artifacts
    /// already carried in-band by an airgap envelope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

/// One binary artifact in the plan's self-update set.
///
/// Each entry describes a single platform-specific binary that the plan
/// authorizes the environment to install. Trustworthiness comes from the plan's
/// DSSE signature: the subject pins `sha256(plan_bytes)`, which transitively
/// covers every `BinaryArtifact` (including its `digest`). There is no
/// separate per-binary signature — the operator pins `digest` at plan-build
/// time, and the DSSE envelope is the single trust anchor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinaryArtifact {
    /// Logical binary name (`"gtc"`, `"greentic-runner"`, `"greentic-start"`).
    pub name: String,
    /// Binary version (semver).
    pub version: String,
    /// Rust target triple (e.g. `"x86_64-unknown-linux-gnu"`).
    pub target: String,
    /// Content digest of the inner binary, `sha256:<hex>`. This is the trust
    /// anchor pinned by the operator at plan-build time; the plan's DSSE
    /// signature covers it transitively.
    pub digest: String,
    /// Download URL or registry coordinate. Absent when the binary is carried
    /// in-band by an airgap envelope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

/// Compatibility constraints a plan declares against the target environment.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatRequirements {
    /// Minimum runtime version required (semver). Absent = no floor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_runtime: Option<String>,
    /// Required component ABI (e.g. `greentic:component@0.6.0`). Must match
    /// exactly. Absent = unconstrained.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub abi: Option<String>,
    /// Other plan ids that must already be applied before this one.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requires: Vec<String>,
}

/// What to do when an apply fails its health gate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackPolicy {
    /// How the rollback is driven.
    pub policy: RollbackKind,
    /// Seconds to wait for the post-apply health gate before declaring failure.
    pub health_timeout_s: u32,
    /// The action taken on failure.
    pub on_fail: OnFail,
}

/// How a rollback is driven.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RollbackKind {
    /// Automatically restore the pre-apply snapshot on failure.
    Auto,
    /// Leave the failed state for an operator to resolve manually.
    Manual,
}

/// The action taken when an apply fails.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnFail {
    /// Restore the environment to its pre-apply snapshot.
    Restore,
    /// Halt and surface the error without restoring.
    Halt,
}

/// Compact identity mirror recorded inside the DSSE statement's predicate, so a
/// reader of the `.sig` envelope alone sees what the signature covers without
/// opening the (potentially large) plan document. [`verify_update_plan`]
/// cross-checks every field against the document.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdatePlanPredicate {
    /// Always [`UPDATE_PLAN_PREDICATE_TYPE_V1`].
    pub schema: String,
    pub plan_id: String,
    pub env_id: String,
    pub sequence: u64,
    pub created_at: DateTime<Utc>,
    pub nonce: String,
}

/// What [`build_update_plan`] produced: the canonical document bytes and the
/// DSSE sidecar, plus the pinned digest and signing key id.
#[derive(Clone, Debug)]
pub struct BuiltUpdatePlan {
    /// Exact bytes of the plan document (pretty canonical JSON). The DSSE
    /// subject pins their SHA-256.
    pub plan_bytes: Vec<u8>,
    /// Exact bytes of the DSSE envelope sidecar.
    pub envelope_bytes: Vec<u8>,
    /// Lowercase-hex SHA-256 of `plan_bytes` (bare, no `sha256:` prefix).
    pub plan_sha256: String,
    /// `keyid` recorded in the envelope.
    pub key_id: String,
}

/// A plan whose signature, subject digest, predicate type, and predicate
/// identity have all been verified against a trust root.
#[derive(Clone, Debug)]
pub struct VerifiedUpdatePlan {
    /// The verified plan document.
    pub plan: UpdatePlan,
    /// Lowercase-hex SHA-256 of the verified plan bytes.
    pub plan_sha256: String,
    /// Key ids whose signatures actually verified.
    pub verified_key_ids: Vec<String>,
}

/// Why building or verifying an update plan failed.
#[derive(Debug, Error)]
pub enum PlanError {
    #[error("update-plan signing: {0}")]
    Sign(#[from] SigningError),
    #[error("update-plan JSON: {0}")]
    Json(serde_json::Error),
    /// The signing key's id is not in the target environment's trust root.
    /// Refused before any bytes are produced — a plan the environment cannot
    /// verify is worse than no plan.
    #[error("signing key `{key_id}` is not trusted in the env trust root")]
    KeyNotTrusted { key_id: String },
    #[error("update-plan schema mismatch: expected `{expected}`, found `{found}`")]
    SchemaMismatch { expected: String, found: String },
    /// The verified DSSE predicate does not match the plan document (wrong
    /// predicate type, or an identity field diverges from the document).
    #[error("update-plan predicate does not match document: {0}")]
    PredicateMismatch(String),
    /// The plan's `sequence` is not strictly newer than the last applied one.
    /// Also blocks re-applying an already-applied plan (replay).
    #[error("update-plan downgrade refused: sequence {plan} is not newer than last applied {last}")]
    Downgrade { plan: u64, last: u64 },
    /// More than one binary artifact matches the same target triple — the plan
    /// is ambiguous and cannot be applied (fail-closed, never guess).
    #[error("ambiguous binary selection: {count} entries match target `{target}`")]
    AmbiguousBinary { target: String, count: usize },
}

/// Why a plan's compatibility requirements were not satisfied by the runtime.
#[derive(Debug, Error)]
pub enum CompatError {
    #[error("invalid version `{value}`: {source}")]
    InvalidVersion {
        value: String,
        #[source]
        source: semver::Error,
    },
    #[error("runtime too old: plan requires >= {required}, runtime is {actual:?}")]
    RuntimeTooOld {
        required: String,
        actual: Option<String>,
    },
    #[error("abi mismatch: plan requires `{required}`, runtime is {actual:?}")]
    AbiMismatch {
        required: String,
        actual: Option<String>,
    },
    #[error("unmet prerequisite plan `{0}`")]
    MissingRequirement(String),
}

/// Build and sign an update plan.
///
/// Mirrors `greentic-operator-trust`'s `build_revenue_policy_version`: refuse
/// if the key is untrusted, serialize the document, pin its SHA-256 in the DSSE
/// subject, sign, then self-verify against the same trust root before
/// returning. Pure: no storage, no clock, no key I/O.
///
/// `signing_key_pkcs8_pem` is an Ed25519 PKCS#8 private key PEM and `key_id`
/// its canonical id (`greentic_distributor_client::signing::key_id_for_public_key_pem`);
/// the deployer-side caller passes its `OperatorKey`'s `private_pem`/`key_id`.
pub fn build_update_plan(
    plan: &UpdatePlan,
    signing_key_pkcs8_pem: &str,
    key_id: &str,
    trust_root: &TrustRoot,
) -> Result<BuiltUpdatePlan, PlanError> {
    // Refusal runs first so a failed precondition yields NO bytes for the
    // caller to half-persist.
    // Match `TrustRoot::find`'s contract: an empty key id never resolves to a
    // trusted key on either side. Without the guard an empty/empty match would
    // pass here and only fail later in the self-verify with a confusing
    // `NoTrustedKey` instead of a clear refusal.
    let trusted = !key_id.is_empty()
        && trust_root
            .keys
            .iter()
            .any(|k| !k.key_id.is_empty() && k.key_id.eq_ignore_ascii_case(key_id));
    if !trusted {
        return Err(PlanError::KeyNotTrusted {
            key_id: key_id.to_string(),
        });
    }

    if plan.schema != UPDATE_PLAN_SCHEMA_V1 {
        return Err(PlanError::SchemaMismatch {
            expected: UPDATE_PLAN_SCHEMA_V1.to_string(),
            found: plan.schema.clone(),
        });
    }

    let plan_bytes = serde_json::to_vec_pretty(plan).map_err(PlanError::Json)?;
    let plan_sha256 = sha256_hex(&plan_bytes);

    let predicate = UpdatePlanPredicate {
        schema: UPDATE_PLAN_PREDICATE_TYPE_V1.to_string(),
        plan_id: plan.plan_id.clone(),
        env_id: plan.env_id.clone(),
        sequence: plan.sequence,
        created_at: plan.created_at,
        nonce: plan.nonce.clone(),
    };
    let predicate_value = serde_json::to_value(&predicate).map_err(PlanError::Json)?;

    let mut digest = BTreeMap::new();
    digest.insert("sha256".to_string(), plan_sha256.clone());
    let statement = InTotoStatement {
        type_: INTOTO_STATEMENT_TYPE.to_string(),
        subject: vec![Subject {
            name: format!("update-plan/{}", plan.plan_id),
            digest,
        }],
        predicate_type: UPDATE_PLAN_PREDICATE_TYPE_V1.to_string(),
        predicate: predicate_value,
    };

    let envelope = sign_statement(&statement, signing_key_pkcs8_pem, key_id)?;
    let envelope_bytes = serde_json::to_vec_pretty(&envelope).map_err(PlanError::Json)?;

    // Self-verify before returning — a key/trust mismatch fails the build, not
    // a later reader.
    verify_artifact_dsse(&envelope_bytes, &plan_sha256, trust_root)?;

    Ok(BuiltUpdatePlan {
        plan_bytes,
        envelope_bytes,
        plan_sha256,
        key_id: key_id.to_string(),
    })
}

/// Verify an update plan: the envelope must be signed by a trusted key, its
/// subject must pin exactly `plan_bytes`, it must be an update-plan predicate
/// type, and its predicate identity must mirror the document.
///
/// On success the deserialized [`UpdatePlan`] is returned. This does **not**
/// evaluate the downgrade guard or compatibility — call [`ensure_not_downgrade`]
/// and [`check_compat`] with the verified plan.
pub fn verify_update_plan(
    plan_bytes: &[u8],
    envelope_bytes: &[u8],
    trust_root: &TrustRoot,
) -> Result<VerifiedUpdatePlan, PlanError> {
    let plan_sha256 = sha256_hex(plan_bytes);

    // Trusted signature + the subject pins exactly these plan bytes.
    let verified = verify_artifact_dsse(envelope_bytes, &plan_sha256, trust_root)?;

    // Confirm this is an update-plan statement, not some other DSSE artifact
    // that happens to pin the same digest.
    if verified.statement.predicate_type != UPDATE_PLAN_PREDICATE_TYPE_V1 {
        return Err(PlanError::PredicateMismatch(format!(
            "unexpected predicate type `{}`",
            verified.statement.predicate_type
        )));
    }
    let predicate: UpdatePlanPredicate =
        serde_json::from_value(verified.statement.predicate.clone()).map_err(PlanError::Json)?;

    let plan: UpdatePlan = serde_json::from_slice(plan_bytes).map_err(PlanError::Json)?;
    if plan.schema != UPDATE_PLAN_SCHEMA_V1 {
        return Err(PlanError::SchemaMismatch {
            expected: UPDATE_PLAN_SCHEMA_V1.to_string(),
            found: plan.schema.clone(),
        });
    }

    // The document is the source of truth (its bytes are what the subject
    // pins); a divergent predicate signals a malformed or hostile signer. The
    // predicate's own `schema` mirror is pinned to the predicate-type constant
    // (the statement-level `predicate_type` checked above is the authoritative
    // type guard; this closes the doc-promised "every field" cross-check).
    if predicate.schema != UPDATE_PLAN_PREDICATE_TYPE_V1
        || predicate.plan_id != plan.plan_id
        || predicate.env_id != plan.env_id
        || predicate.sequence != plan.sequence
        || predicate.nonce != plan.nonce
        || predicate.created_at != plan.created_at
    {
        return Err(PlanError::PredicateMismatch(
            "predicate identity does not match plan document".to_string(),
        ));
    }

    Ok(VerifiedUpdatePlan {
        plan,
        plan_sha256,
        verified_key_ids: verified.verified_key_ids,
    })
}

/// Reject a plan whose `sequence` is not strictly newer than the last applied
/// one. `last_applied_sequence` is `None` when nothing has been applied yet
/// (any plan is accepted). Re-applying an already-applied plan (equal sequence)
/// is refused — this is the plan-level replay guard. Callers may override with
/// an explicit `--force` at the CLI layer.
pub fn ensure_not_downgrade(
    plan: &UpdatePlan,
    last_applied_sequence: Option<u64>,
) -> Result<(), PlanError> {
    match last_applied_sequence {
        Some(last) if plan.sequence <= last => Err(PlanError::Downgrade {
            plan: plan.sequence,
            last,
        }),
        _ => Ok(()),
    }
}

/// The runtime facts a plan's compatibility requirements are checked against.
#[derive(Clone, Copy, Debug)]
pub struct RuntimeFacts<'a> {
    /// Current runtime version (semver), if known.
    pub runtime_version: Option<&'a str>,
    /// Current component ABI, if known.
    pub abi: Option<&'a str>,
    /// Plan ids already applied to this environment.
    pub applied_plan_ids: &'a [String],
}

/// Evaluate a plan's [`CompatRequirements`] against the runtime. Returns the
/// first unmet constraint as an error.
pub fn check_compat(
    compat: &CompatRequirements,
    facts: &RuntimeFacts<'_>,
) -> Result<(), CompatError> {
    if let Some(min) = &compat.min_runtime {
        let required =
            semver::Version::parse(min).map_err(|source| CompatError::InvalidVersion {
                value: min.clone(),
                source,
            })?;
        match facts.runtime_version {
            Some(actual_str) => {
                let actual = semver::Version::parse(actual_str).map_err(|source| {
                    CompatError::InvalidVersion {
                        value: actual_str.to_string(),
                        source,
                    }
                })?;
                if actual < required {
                    return Err(CompatError::RuntimeTooOld {
                        required: min.clone(),
                        actual: Some(actual_str.to_string()),
                    });
                }
            }
            None => {
                return Err(CompatError::RuntimeTooOld {
                    required: min.clone(),
                    actual: None,
                });
            }
        }
    }

    if let Some(required_abi) = &compat.abi
        && facts.abi != Some(required_abi.as_str())
    {
        return Err(CompatError::AbiMismatch {
            required: required_abi.clone(),
            actual: facts.abi.map(str::to_string),
        });
    }

    for req in &compat.requires {
        if !facts.applied_plan_ids.iter().any(|p| p == req) {
            return Err(CompatError::MissingRequirement(req.clone()));
        }
    }

    Ok(())
}

/// Select the binary artifact for a given target triple from the plan's
/// `binaries` list.
///
/// Returns `Ok(Some(&art))` when exactly one binary matches `target`,
/// `Ok(None)` when no binary targets this host (no update available — not an
/// error), or `Err(PlanError::AmbiguousBinary)` when more than one entry
/// shares the same triple (fail-closed — never guess).
///
/// `target` is the Rust target triple of the running host (e.g. from
/// `binswap::current_target()`). This function is pure and does not depend on
/// the binswap module or build.rs — callers pass the triple in.
pub fn select_binary_for_target<'a>(
    binaries: &'a [BinaryArtifact],
    target: &str,
) -> Result<Option<&'a BinaryArtifact>, PlanError> {
    let mut matched: Option<&'a BinaryArtifact> = None;
    let mut count = 0usize;
    for b in binaries {
        if b.target == target {
            if matched.is_none() {
                matched = Some(b);
            }
            count += 1;
        }
    }
    if count > 1 {
        return Err(PlanError::AmbiguousBinary {
            target: target.to_string(),
            count,
        });
    }
    Ok(matched)
}

/// Lowercase-hex SHA-256 of `bytes` — the digest form pinned in the DSSE
/// subject (bare, no `sha256:` prefix).
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use ed25519_dalek::pkcs8::EncodePrivateKey;
    use ed25519_dalek::pkcs8::EncodePublicKey;
    use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
    use greentic_distributor_client::signing::{
        DsseEnvelope, Subject as DsseSubject, TrustedKey, key_id_for_public_key_pem, sign_statement,
    };

    /// Deterministic Ed25519 test key: returns its PKCS#8 private PEM and the
    /// matching [`TrustedKey`] (SPKI PEM + canonical id).
    fn test_key(seed: u8) -> (String, TrustedKey) {
        let sk = SigningKey::from_bytes(&[seed; 32]);
        let priv_pem = sk.to_pkcs8_pem(LineEnding::LF).unwrap().to_string();
        let pub_pem = sk
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .unwrap();
        let key_id = key_id_for_public_key_pem(&pub_pem).unwrap();
        (
            priv_pem,
            TrustedKey {
                key_id,
                public_key_pem: pub_pem,
            },
        )
    }

    fn sample_plan(seq: u64) -> UpdatePlan {
        UpdatePlan {
            schema: UPDATE_PLAN_SCHEMA_V1.to_string(),
            plan_id: "plan-abc".to_string(),
            env_id: "local".to_string(),
            sequence: seq,
            created_at: DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
            nonce: "nonce-1".to_string(),
            target: serde_json::json!({"schema": "greentic.env-manifest.v1", "name": "local"}),
            artifacts: vec![PlanArtifact {
                name: "weather-pack".to_string(),
                version: "1.2.3".to_string(),
                digest: "sha256:deadbeef".to_string(),
                source: Some("oci://ghcr.io/greenticai/packs/weather:1.2.3".to_string()),
            }],
            binaries: vec![],
            compat: CompatRequirements {
                min_runtime: Some("1.1.0".to_string()),
                abi: Some("greentic:component@0.6.0".to_string()),
                requires: vec![],
            },
            rollback: RollbackPolicy {
                policy: RollbackKind::Auto,
                health_timeout_s: 120,
                on_fail: OnFail::Restore,
            },
        }
    }

    #[test]
    fn builds_and_verifies_roundtrip() {
        let (priv_pem, tk) = test_key(7);
        let trust = TrustRoot::new(vec![tk.clone()]);
        let plan = sample_plan(5);

        let built = build_update_plan(&plan, &priv_pem, &tk.key_id, &trust).expect("trusted build");
        assert_eq!(built.key_id, tk.key_id);
        assert_eq!(built.plan_sha256, sha256_hex(&built.plan_bytes));

        let verified =
            verify_update_plan(&built.plan_bytes, &built.envelope_bytes, &trust).expect("verifies");
        assert_eq!(verified.plan, plan);
        assert_eq!(verified.plan_sha256, built.plan_sha256);
        assert!(verified.verified_key_ids.contains(&tk.key_id));
    }

    #[test]
    fn untrusted_key_is_refused_before_any_bytes() {
        let (priv_pem, tk) = test_key(7);
        let plan = sample_plan(1);
        let err = build_update_plan(&plan, &priv_pem, &tk.key_id, &TrustRoot::default())
            .expect_err("untrusted key refused");
        assert!(matches!(err, PlanError::KeyNotTrusted { .. }));
    }

    #[test]
    fn build_rejects_wrong_schema() {
        let (priv_pem, tk) = test_key(7);
        let trust = TrustRoot::new(vec![tk.clone()]);
        let mut plan = sample_plan(1);
        plan.schema = "greentic.update-plan.v0".to_string();
        let err = build_update_plan(&plan, &priv_pem, &tk.key_id, &trust).expect_err("bad schema");
        assert!(matches!(err, PlanError::SchemaMismatch { .. }));
    }

    #[test]
    fn tampered_plan_bytes_fail_verification() {
        let (priv_pem, tk) = test_key(7);
        let trust = TrustRoot::new(vec![tk.clone()]);
        let built = build_update_plan(&sample_plan(5), &priv_pem, &tk.key_id, &trust).unwrap();

        let mut tampered = built.plan_bytes.clone();
        // Flip a byte well inside the document.
        tampered[10] ^= 0xff;
        let err = verify_update_plan(&tampered, &built.envelope_bytes, &trust)
            .expect_err("tampered bytes rejected");
        // The subject digest no longer matches the recomputed hash.
        assert!(matches!(
            err,
            PlanError::Sign(SigningError::SubjectDigestMismatch { .. })
        ));
    }

    #[test]
    fn envelope_from_a_different_plan_is_rejected() {
        let (priv_pem, tk) = test_key(7);
        let trust = TrustRoot::new(vec![tk.clone()]);
        let built_a = build_update_plan(&sample_plan(5), &priv_pem, &tk.key_id, &trust).unwrap();
        let mut plan_b = sample_plan(6);
        plan_b.plan_id = "plan-xyz".to_string();
        let built_b = build_update_plan(&plan_b, &priv_pem, &tk.key_id, &trust).unwrap();

        // Plan A's bytes against plan B's envelope: subject pins B's hash.
        let err = verify_update_plan(&built_a.plan_bytes, &built_b.envelope_bytes, &trust)
            .expect_err("subject mismatch");
        assert!(matches!(
            err,
            PlanError::Sign(SigningError::SubjectDigestMismatch { .. })
        ));
    }

    #[test]
    fn signature_from_untrusted_key_fails_verification() {
        let (priv_pem, tk_signer) = test_key(7);
        // Built and self-verified against the signer's own trust root.
        let signer_trust = TrustRoot::new(vec![tk_signer.clone()]);
        let built = build_update_plan(&sample_plan(5), &priv_pem, &tk_signer.key_id, &signer_trust)
            .unwrap();

        // A different trust root that does not list the signer.
        let (_other_priv, tk_other) = test_key(9);
        let other_trust = TrustRoot::new(vec![tk_other]);
        let err = verify_update_plan(&built.plan_bytes, &built.envelope_bytes, &other_trust)
            .expect_err("untrusted signer rejected");
        assert!(matches!(
            err,
            PlanError::Sign(SigningError::NoTrustedKey(_))
        ));
    }

    /// A statement whose subject correctly pins the plan bytes but whose
    /// predicate identity diverges from the document must be rejected even
    /// though the signature itself is valid and trusted.
    #[test]
    fn divergent_predicate_identity_is_rejected() {
        let (priv_pem, tk) = test_key(7);
        let trust = TrustRoot::new(vec![tk.clone()]);
        let plan = sample_plan(5);
        let plan_bytes = serde_json::to_vec_pretty(&plan).unwrap();
        let plan_sha = sha256_hex(&plan_bytes);

        // Hand-build a statement with the correct subject but a LYING predicate.
        let lying_predicate = UpdatePlanPredicate {
            schema: UPDATE_PLAN_PREDICATE_TYPE_V1.to_string(),
            plan_id: "totally-different".to_string(),
            env_id: plan.env_id.clone(),
            sequence: plan.sequence,
            created_at: plan.created_at,
            nonce: plan.nonce.clone(),
        };
        let mut digest = BTreeMap::new();
        digest.insert("sha256".to_string(), plan_sha.clone());
        let statement = InTotoStatement {
            type_: INTOTO_STATEMENT_TYPE.to_string(),
            subject: vec![DsseSubject {
                name: "update-plan/plan-abc".to_string(),
                digest,
            }],
            predicate_type: UPDATE_PLAN_PREDICATE_TYPE_V1.to_string(),
            predicate: serde_json::to_value(&lying_predicate).unwrap(),
        };
        let envelope = sign_statement(&statement, &priv_pem, &tk.key_id).unwrap();
        let envelope_bytes = serde_json::to_vec_pretty(&envelope).unwrap();

        let err = verify_update_plan(&plan_bytes, &envelope_bytes, &trust)
            .expect_err("predicate identity mismatch rejected");
        assert!(matches!(err, PlanError::PredicateMismatch(_)));
    }

    /// An envelope that pins the right digest under a foreign predicate type
    /// (DSSE type confusion) must be rejected.
    #[test]
    fn foreign_predicate_type_is_rejected() {
        let (priv_pem, tk) = test_key(7);
        let trust = TrustRoot::new(vec![tk.clone()]);
        let plan = sample_plan(5);
        let plan_bytes = serde_json::to_vec_pretty(&plan).unwrap();
        let plan_sha = sha256_hex(&plan_bytes);

        let mut digest = BTreeMap::new();
        digest.insert("sha256".to_string(), plan_sha);
        let statement = InTotoStatement {
            type_: INTOTO_STATEMENT_TYPE.to_string(),
            subject: vec![DsseSubject {
                name: "update-plan/plan-abc".to_string(),
                digest,
            }],
            predicate_type: "greentic.revenue-policy-predicate.v1".to_string(),
            predicate: serde_json::json!({"unrelated": true}),
        };
        let envelope: DsseEnvelope = sign_statement(&statement, &priv_pem, &tk.key_id).unwrap();
        let envelope_bytes = serde_json::to_vec_pretty(&envelope).unwrap();

        let err = verify_update_plan(&plan_bytes, &envelope_bytes, &trust)
            .expect_err("foreign predicate type rejected");
        assert!(matches!(err, PlanError::PredicateMismatch(_)));
    }

    #[test]
    fn downgrade_guard_blocks_equal_and_lower_sequences() {
        // No prior apply: anything goes.
        assert!(ensure_not_downgrade(&sample_plan(1), None).is_ok());
        // Strictly newer: ok.
        assert!(ensure_not_downgrade(&sample_plan(6), Some(5)).is_ok());
        // Equal (replay of the already-applied plan): refused.
        assert!(matches!(
            ensure_not_downgrade(&sample_plan(5), Some(5)),
            Err(PlanError::Downgrade { plan: 5, last: 5 })
        ));
        // Older: refused.
        assert!(matches!(
            ensure_not_downgrade(&sample_plan(4), Some(5)),
            Err(PlanError::Downgrade { plan: 4, last: 5 })
        ));
    }

    #[test]
    fn compat_runtime_floor() {
        let compat = CompatRequirements {
            min_runtime: Some("1.1.0".to_string()),
            abi: None,
            requires: vec![],
        };
        // Satisfied.
        assert!(
            check_compat(
                &compat,
                &RuntimeFacts {
                    runtime_version: Some("1.2.0"),
                    abi: None,
                    applied_plan_ids: &[],
                }
            )
            .is_ok()
        );
        // Too old.
        assert!(matches!(
            check_compat(
                &compat,
                &RuntimeFacts {
                    runtime_version: Some("1.0.9"),
                    abi: None,
                    applied_plan_ids: &[],
                }
            ),
            Err(CompatError::RuntimeTooOld { .. })
        ));
        // Unknown runtime cannot satisfy a floor.
        assert!(matches!(
            check_compat(
                &compat,
                &RuntimeFacts {
                    runtime_version: None,
                    abi: None,
                    applied_plan_ids: &[],
                }
            ),
            Err(CompatError::RuntimeTooOld { actual: None, .. })
        ));
    }

    #[test]
    fn compat_abi_and_requires() {
        let compat = CompatRequirements {
            min_runtime: None,
            abi: Some("greentic:component@0.6.0".to_string()),
            requires: vec!["plan-prereq".to_string()],
        };
        let applied = vec!["plan-prereq".to_string()];
        // All satisfied.
        assert!(
            check_compat(
                &compat,
                &RuntimeFacts {
                    runtime_version: None,
                    abi: Some("greentic:component@0.6.0"),
                    applied_plan_ids: &applied,
                }
            )
            .is_ok()
        );
        // ABI mismatch.
        assert!(matches!(
            check_compat(
                &compat,
                &RuntimeFacts {
                    runtime_version: None,
                    abi: Some("greentic:component@0.5.0"),
                    applied_plan_ids: &applied,
                }
            ),
            Err(CompatError::AbiMismatch { .. })
        ));
        // Missing prerequisite.
        assert!(matches!(
            check_compat(
                &compat,
                &RuntimeFacts {
                    runtime_version: None,
                    abi: Some("greentic:component@0.6.0"),
                    applied_plan_ids: &[],
                }
            ),
            Err(CompatError::MissingRequirement(_))
        ));
    }

    #[test]
    fn plan_json_roundtrips() {
        let plan = sample_plan(3);
        let bytes = serde_json::to_vec_pretty(&plan).unwrap();
        let back: UpdatePlan = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(plan, back);
    }

    /// A predicate whose inner `schema` mirror is wrong — but whose
    /// statement-level `predicateType` and every identity field are correct —
    /// must still be rejected. Guards the defense-in-depth schema cross-check.
    #[test]
    fn wrong_inner_predicate_schema_is_rejected() {
        let (priv_pem, tk) = test_key(7);
        let trust = TrustRoot::new(vec![tk.clone()]);
        let plan = sample_plan(5);
        let plan_bytes = serde_json::to_vec_pretty(&plan).unwrap();
        let plan_sha = sha256_hex(&plan_bytes);

        let lying_predicate = UpdatePlanPredicate {
            schema: "greentic.revenue-policy-predicate.v1".to_string(), // wrong mirror
            plan_id: plan.plan_id.clone(),
            env_id: plan.env_id.clone(),
            sequence: plan.sequence,
            created_at: plan.created_at,
            nonce: plan.nonce.clone(),
        };
        let mut digest = BTreeMap::new();
        digest.insert("sha256".to_string(), plan_sha);
        let statement = InTotoStatement {
            type_: INTOTO_STATEMENT_TYPE.to_string(),
            subject: vec![DsseSubject {
                name: "update-plan/plan-abc".to_string(),
                digest,
            }],
            // Statement-level type is correct, so only the inner-schema check
            // can reject this.
            predicate_type: UPDATE_PLAN_PREDICATE_TYPE_V1.to_string(),
            predicate: serde_json::to_value(&lying_predicate).unwrap(),
        };
        let envelope = sign_statement(&statement, &priv_pem, &tk.key_id).unwrap();
        let envelope_bytes = serde_json::to_vec_pretty(&envelope).unwrap();

        let err = verify_update_plan(&plan_bytes, &envelope_bytes, &trust)
            .expect_err("wrong inner predicate schema rejected");
        assert!(matches!(err, PlanError::PredicateMismatch(_)));
    }

    /// An empty signing key id is refused with a clear `KeyNotTrusted` even when
    /// the trust root is misconfigured with an empty-key-id entry — rather than
    /// signing and then failing the self-verify with a confusing `NoTrustedKey`.
    #[test]
    fn empty_key_id_is_refused_even_with_empty_trust_entry() {
        let (priv_pem, tk) = test_key(7);
        let trust = TrustRoot::new(vec![TrustedKey {
            key_id: String::new(),
            public_key_pem: tk.public_key_pem.clone(),
        }]);
        let err = build_update_plan(&sample_plan(1), &priv_pem, "", &trust)
            .expect_err("empty key id refused");
        assert!(matches!(err, PlanError::KeyNotTrusted { .. }));
    }

    // ---- BinaryArtifact / binaries field tests ----

    fn sample_binary(name: &str, target: &str) -> BinaryArtifact {
        BinaryArtifact {
            name: name.to_string(),
            version: "1.1.5".to_string(),
            target: target.to_string(),
            digest: format!("sha256:{name}_{target}_cafe"),
            source: Some(format!("https://example.com/{name}-{target}.tar.gz")),
        }
    }

    /// A plan with an empty `binaries` vec serializes to JSON that does NOT
    /// contain a `"binaries"` key (proves `skip_serializing_if` omits it),
    /// and re-serializing the deserialized result produces byte-identical
    /// output. This means existing DSSE signatures (whose subject pins
    /// `sha256(plan_bytes)`) remain valid after the schema addition.
    #[test]
    fn empty_binaries_is_byte_identical_to_absent_field() {
        let plan = sample_plan(1);
        assert!(plan.binaries.is_empty());

        let bytes_a = serde_json::to_vec_pretty(&plan).unwrap();
        let json_str = String::from_utf8_lossy(&bytes_a);

        // The key must not appear in the serialized JSON at all.
        assert!(
            !json_str.contains("\"binaries\""),
            "empty binaries must be omitted from JSON"
        );

        // Deserialize (binaries defaults to empty) and re-serialize — bytes
        // must be identical (the struct round-trips without gaining a key).
        let back: UpdatePlan = serde_json::from_slice(&bytes_a).unwrap();
        assert!(back.binaries.is_empty());
        let bytes_b = serde_json::to_vec_pretty(&back).unwrap();
        assert_eq!(bytes_a, bytes_b, "struct round-trip must be byte-stable");
    }

    /// An existing-format plan (no `binaries` key at all) still deserializes
    /// and build/verify round-trips without any change.
    #[test]
    fn old_format_plan_without_binaries_still_verifies() {
        let (priv_pem, tk) = test_key(7);
        let trust = TrustRoot::new(vec![tk.clone()]);
        let plan = sample_plan(3);

        // Build and sign: since binaries is empty, the JSON never contains
        // a "binaries" key — so the signed bytes are identical to what a
        // pre-P7 signer would have produced.
        let built = build_update_plan(&plan, &priv_pem, &tk.key_id, &trust)
            .expect("builds without binaries");
        let json_str = String::from_utf8_lossy(&built.plan_bytes);
        assert!(
            !json_str.contains("\"binaries\""),
            "signed plan bytes must not contain a binaries key"
        );

        // Verify: the signed bytes verify, and the deserialized plan has
        // empty binaries (defaulted from the absent key).
        let verified = verify_update_plan(&built.plan_bytes, &built.envelope_bytes, &trust)
            .expect("old-format plan verifies");
        assert!(verified.plan.binaries.is_empty());
        assert_eq!(verified.plan, plan);
    }

    /// A plan carrying binary artifacts builds, self-verifies, and JSON
    /// round-trips with equality.
    #[test]
    fn roundtrip_with_binaries() {
        let (priv_pem, tk) = test_key(7);
        let trust = TrustRoot::new(vec![tk.clone()]);
        let mut plan = sample_plan(10);
        plan.binaries = vec![
            sample_binary("gtc", "x86_64-unknown-linux-gnu"),
            sample_binary("greentic-runner", "aarch64-apple-darwin"),
        ];

        let built =
            build_update_plan(&plan, &priv_pem, &tk.key_id, &trust).expect("builds with binaries");
        let verified = verify_update_plan(&built.plan_bytes, &built.envelope_bytes, &trust)
            .expect("verifies with binaries");
        assert_eq!(verified.plan, plan);
        assert_eq!(verified.plan.binaries.len(), 2);
        assert_eq!(verified.plan.binaries[0].name, "gtc");
        assert_eq!(verified.plan.binaries[1].target, "aarch64-apple-darwin");

        // JSON round-trip.
        let bytes = serde_json::to_vec_pretty(&plan).unwrap();
        let back: UpdatePlan = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(plan, back);
    }

    #[test]
    fn select_binary_for_target_picks_matching_triple() {
        let bins = vec![
            sample_binary("gtc", "x86_64-unknown-linux-gnu"),
            sample_binary("gtc", "aarch64-apple-darwin"),
        ];
        let picked = select_binary_for_target(&bins, "aarch64-apple-darwin")
            .expect("no error")
            .expect("found");
        assert_eq!(picked.target, "aarch64-apple-darwin");
        assert_eq!(picked.name, "gtc");
    }

    #[test]
    fn select_binary_for_target_returns_none_on_no_match() {
        let bins = vec![sample_binary("gtc", "x86_64-unknown-linux-gnu")];
        let result =
            select_binary_for_target(&bins, "aarch64-unknown-linux-gnu").expect("no error");
        assert!(result.is_none());
    }

    #[test]
    fn select_binary_for_target_returns_none_on_empty_list() {
        let result = select_binary_for_target(&[], "x86_64-unknown-linux-gnu").expect("no error");
        assert!(result.is_none());
    }

    #[test]
    fn select_binary_for_target_errors_on_ambiguous_triple() {
        let bins = vec![
            sample_binary("gtc", "x86_64-unknown-linux-gnu"),
            sample_binary("greentic-runner", "x86_64-unknown-linux-gnu"),
        ];
        let err = select_binary_for_target(&bins, "x86_64-unknown-linux-gnu")
            .expect_err("ambiguous triple");
        assert!(matches!(err, PlanError::AmbiguousBinary { count: 2, .. }));
    }
}
