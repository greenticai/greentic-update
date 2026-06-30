//! Signed update plan (`greentic.update-plan.v1`).
//!
//! A DSSE-signed in-toto `Statement` whose subject pins the SHA-256 of the
//! canonical plan document and whose predicate carries the update intent: the
//! target env-manifest (opaque JSON), the artifact set, compatibility
//! constraints, rollback policy, and a monotonic `sequence` for downgrade
//! protection.
//!
//! Builds on `greentic_distributor_client::signing` (the same DSSE/in-toto core
//! the pack and revenue-policy signers use) and self-verifies against the
//! per-environment trust root before emitting.
//!
//! Implemented in Phase 0 (P0a).
