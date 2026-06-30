//! Airgap update-bundle envelope and import scanner.
//!
//! A signed wrapper carrying a plan plus its referenced artifacts for transfer
//! across an air gap, and the import-side scanner that re-verifies the envelope
//! signature, SBOM, and path safety before admitting the bundle to the staging
//! pipeline. Once imported, the airgapped and connected paths converge on the
//! same staging FSM and `apply-updates` verb.
//!
//! Implemented in Phase 5.
