//! Update staging state machine.
//!
//! The on-disk `{downloading,inbox,staged,applying,applied,failed,rejected,audit}`
//! pipeline rooted at `~/.greentic/updates/<env_id>/` (override with
//! `GREENTIC_UPDATES_DIR`). Transitions are atomic renames with an append-only
//! audit trail and path-safety guards on every import.
//!
//! Implemented in Phase 2.
