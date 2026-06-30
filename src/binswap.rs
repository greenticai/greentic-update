//! Verified on-disk binary swap (binary self-update track).
//!
//! Swaps a verified, staged `gtc` / `greentic-runner` / `greentic-start` binary
//! into the launcher-resolved target path with a `.prev` rollback copy. The
//! binary is treated as just another signed artifact in the update plan, so it
//! flows through the same download + DSSE/digest verification as content
//! artifacts before the swap.
//!
//! Implemented in Phase 7 (P7).
