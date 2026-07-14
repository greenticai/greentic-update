//! # greentic-update
//!
//! Foundation library for the Greentic update platform — the transport-agnostic
//! core shared by the operator CLI (`greentic-deployer`), the airgap Public
//! Updater Bridge, and the cloud Update Planner.
//!
//! This crate is deliberately lean and **does not depend on `greentic-deploy-spec`**:
//! a plan's `target` environment manifest is carried as opaque JSON, and callers
//! project their own domain types into this crate's lightweight artifact view.
//! Its only workspace dependency is `greentic-distributor-client`, for DSSE /
//! in-toto signing and the content-addressed download client.
//!
//! ## Modules
//! - [`plan`] — the signed `greentic.update-plan.v1` (DSSE envelope) build/verify.
//! - [`catalogue`] — installed-artifact view + diff against a plan's artifacts.
//! - [`staging`] — the on-disk staging state machine.
//! - [`envelope`] — airgap update-bundle wrapper + import scanner.
//! - [`binswap`] — verified on-disk binary swap + rollback (binary self-update track).
//! - [`stream`] — SSE transport for plan-update notifications (feature `stream`).
//! - [`tls`] — client-cert (mTLS) transport + X.509 preflight (feature `mtls`).
//! - [`enroll`] — client-side cert enrollment against the Cert-CA (feature `enroll`).

#[cfg(feature = "binswap")]
pub mod binswap;
pub mod catalogue;
#[cfg(feature = "enroll")]
pub mod enroll;
pub mod envelope;
pub mod plan;
pub mod staging;
#[cfg(feature = "stream")]
pub mod stream;
#[cfg(feature = "mtls")]
pub mod tls;
