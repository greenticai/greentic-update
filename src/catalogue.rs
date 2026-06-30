//! Installed-artifact catalogue and plan diff.
//!
//! A lightweight, domain-agnostic view of what is currently installed in an
//! environment, plus the diff against a plan's declared artifact set that
//! produces the download/apply work-list. To keep this crate free of a
//! `greentic-deploy-spec` dependency, callers project their own domain types
//! (revisions, pack-list entries, bundle digests) into the simple artifact
//! view defined here.
//!
//! Implemented in Phase 0 (P0c).
