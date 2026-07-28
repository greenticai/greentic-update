//! Airgap update envelope (`.gtupdate`) — builder, scanner, and import receipts.
//!
//! A `.gtupdate` file is a **zstd-compressed tar stream** carrying a signed
//! update plan plus its content-addressed artifacts and binary blobs, sealed
//! inside a DSSE-signed envelope manifest. It is the on-the-wire format for
//! transferring updates across an air gap — sneakernet, removable media, or an
//! offline staging area.
//!
//! ## Wire format
//!
//! Entry order is fixed and enforced during scanning:
//!
//! ```text
//! manifest.json              # EnvelopeManifest — always the first entry
//! manifest.json.sig          # DSSE sidecar for the manifest
//! plan.json                  # exact plan document bytes
//! plan.json.sig              # DSSE sidecar for the plan
//! blobs/sha256-<64hex>       # one per content artifact or binary blob
//! trust-rotation.json        # reserved for Phase D (accepted, not consumed)
//! trust-rotation.json.sig    # reserved for Phase D
//! ```
//!
//! `manifest.json` and `manifest.json.sig` are **not** listed inside the
//! manifest's entries (self-reference). Every other archive entry must be
//! listed with matching digest and size, and every manifest entry must appear
//! exactly once in the archive (completeness both ways).
//!
//! ## Security model
//!
//! The scanner ([`scan_envelope_to_dir`]) processes **untrusted removable
//! media** before authentication completes. It enforces a strict archive
//! grammar during streaming:
//!
//! - Manifest must be entry #1, bounded by [`ScanLimits::max_manifest_bytes`]
//!   before parsing.
//! - Manifest signature verified against the trust root before any later entry
//!   is trusted.
//! - Plan signature verified via [`crate::plan::verify_update_plan`].
//! - Regular files only — symlinks, hardlinks, devices, FIFOs, GNU sparse,
//!   directories, and any path outside the exact allowlist are rejected.
//! - Per-entry, total, and compression-ratio bounds enforced during
//!   decompression (not after).
//! - Disk-space reservation checked before extraction begins.
//! - Blob digests must be referenced by the verified plan — unknown blobs are
//!   rejected.
//! - On failure the quarantine directory is left safe to delete with no
//!   partial trust.
//!
//! ## Import receipts
//!
//! After a successful import the operator writes a DSSE-signed import receipt
//! listing the content-addressed digests the environment holds. A subsequent
//! export can accept `--base-receipt` to produce a delta envelope that omits
//! already-held blobs.

use std::cell::Cell;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::rc::Rc;

use chrono::{DateTime, Utc};
use greentic_distributor_client::signing::{
    INTOTO_STATEMENT_TYPE, InTotoStatement, SigningError, Subject, TrustRoot, sign_statement,
    verify_artifact_dsse,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::plan::{self, PlanError};
use crate::staging::{self, StagingError};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema discriminator for the envelope manifest document.
pub const MANIFEST_SCHEMA_V1: &str = "greentic.update-envelope.v1";

/// Schema discriminator for the import receipt document.
pub const RECEIPT_SCHEMA_V1: &str = "greentic.import-receipt.v1";

// Fixed archive entry paths.
const MANIFEST_PATH: &str = "manifest.json";
const MANIFEST_SIG_PATH: &str = "manifest.json.sig";
const PLAN_PATH: &str = "plan.json";
const PLAN_SIG_PATH: &str = "plan.json.sig";
const BLOBS_PREFIX: &str = "blobs/";
const TRUST_ROTATION_PATH: &str = "trust-rotation.json";
const TRUST_ROTATION_SIG_PATH: &str = "trust-rotation.json.sig";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// The envelope manifest — a JSON document listing every entry in the archive
/// (except itself and its own signature). Signed via the same DSSE path as
/// [`crate::plan::build_update_plan`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvelopeManifest {
    /// Always [`MANIFEST_SCHEMA_V1`].
    pub schema: String,
    /// Plan id this envelope carries (from `plan.json`).
    pub plan_id: String,
    /// Target environment id (from `plan.json`).
    pub env_id: String,
    /// When the envelope was built (builder clock).
    pub created_at: DateTime<Utc>,
    /// Every archive entry except `manifest.json` and `manifest.json.sig`.
    pub entries: Vec<ManifestEntry>,
}

/// One archive entry described by the envelope manifest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestEntry {
    /// Archive-relative path (`plan.json`, `blobs/sha256-<hex>`, etc.).
    pub path: String,
    /// Content digest, `sha256:<64 lowercase hex>`.
    pub digest: String,
    /// Content size in bytes (decompressed).
    pub size: u64,
    /// MIME media type (`application/json`, `application/octet-stream`, etc.).
    pub media_type: String,
    /// Rust target triple for binary blobs; absent for content artifacts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
}

/// Resource limits enforced during [`scan_envelope_to_dir`]. All fields are
/// public and overridable; the [`Default`] impl provides safe production
/// defaults.
#[derive(Clone, Debug, PartialEq)]
pub struct ScanLimits {
    /// Maximum number of entries in the archive.
    pub max_entry_count: usize,
    /// Maximum decompressed size of any single entry (bytes).
    pub max_entry_bytes: u64,
    /// Maximum total decompressed bytes across all entries.
    pub max_total_bytes: u64,
    /// Maximum decompressed size of `manifest.json` (bytes).
    pub max_manifest_bytes: u64,
    /// Maximum ratio of decompressed to compressed bytes. A zstd bomb
    /// typically exceeds 1000:1; the default limit of 100.0 rejects such
    /// payloads while allowing normal archives (~3–10:1).
    pub max_compression_ratio: f64,
}

impl Default for ScanLimits {
    fn default() -> Self {
        Self {
            max_entry_count: 10_000,
            max_entry_bytes: 4 * 1024 * 1024 * 1024,  // 4 GiB
            max_total_bytes: 64 * 1024 * 1024 * 1024, // 64 GiB
            max_manifest_bytes: 1024 * 1024,          // 1 MiB
            max_compression_ratio: 100.0,
        }
    }
}

/// The result of a successful [`scan_envelope_to_dir`]: a verified manifest
/// plus paths into the quarantine directory for the plan, plan signature, and
/// every blob extracted.
#[derive(Clone, Debug)]
pub struct ScannedEnvelopeRef {
    /// The verified envelope manifest.
    pub manifest: EnvelopeManifest,
    /// Key ids whose signatures verified (from the manifest envelope).
    pub verified_key_ids: Vec<String>,
    /// Path to the extracted `plan.json` inside the quarantine directory.
    pub plan_path: PathBuf,
    /// Path to the extracted `plan.json.sig` inside the quarantine directory.
    pub sig_path: PathBuf,
    /// Content-addressed blob paths in the quarantine directory, keyed by
    /// digest (`sha256:<hex>`).
    pub blob_paths: HashMap<String, PathBuf>,
    /// Path to an extracted `trust-rotation.json`, if present (Phase D).
    pub trust_rotation_path: Option<PathBuf>,
    /// Path to an extracted `trust-rotation.json.sig`, if present (Phase D).
    pub trust_rotation_sig_path: Option<PathBuf>,
}

/// A signed import receipt listing the content-addressed digests an
/// environment currently holds. Carried back out of the gap for delta
/// exports.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportReceipt {
    /// Always [`RECEIPT_SCHEMA_V1`].
    pub schema: String,
    /// Environment id this receipt covers.
    pub env_id: String,
    /// When the receipt was written (importer clock).
    pub created_at: DateTime<Utc>,
    /// Digests of all content-addressed blobs the environment holds (artifacts
    /// + binaries), in `sha256:<hex>` form.
    pub held_digests: Vec<String>,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why an envelope operation failed.
#[derive(Debug, Error)]
pub enum EnvelopeError {
    /// A DSSE signing or verification failure.
    #[error("envelope signing: {0}")]
    Sign(#[from] SigningError),

    /// JSON serialization / deserialization failure.
    #[error("envelope JSON: {0}")]
    Json(serde_json::Error),

    /// A plan verification failure (signature, schema, predicate).
    #[error("envelope plan: {0}")]
    Plan(#[from] PlanError),

    /// A staging-layer failure (digest format, symlink guard).
    #[error("envelope staging: {0}")]
    Staging(#[from] StagingError),

    /// Filesystem I/O on a specific path.
    #[error("envelope I/O on `{}`: {source}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    /// Archive-level I/O (no path — the error originates from the compressed
    /// stream itself).
    #[error("archive I/O: {0}")]
    ArchiveIo(#[source] io::Error),

    /// [`EnvelopeBuilder::finish`] called without [`EnvelopeBuilder::add_plan`].
    #[error("no plan added to the envelope builder")]
    NoPlan,

    /// The same blob digest was added to the builder twice.
    #[error("duplicate blob digest `{digest}`")]
    DuplicateBlob { digest: String },

    /// Blob bytes do not hash to the declared digest.
    #[error("blob `{digest}` content mismatch: expected {expected_hex}, got {actual_hex}")]
    BlobDigestMismatch {
        digest: String,
        expected_hex: String,
        actual_hex: String,
    },

    // -- Scanner errors --------------------------------------------------
    /// An entry appeared at the wrong position in the fixed entry order.
    #[error("entry #{index} must be `{expected}`, found `{found}`")]
    WrongEntryOrder {
        index: usize,
        expected: &'static str,
        found: String,
    },

    /// `manifest.json` exceeds [`ScanLimits::max_manifest_bytes`].
    #[error("manifest is {size} bytes, exceeds limit of {limit} bytes")]
    OversizedManifest { size: u64, limit: u64 },

    /// The manifest's `schema` field is not [`MANIFEST_SCHEMA_V1`].
    #[error("manifest schema mismatch: expected `{expected}`, found `{found}`")]
    WrongSchema { expected: String, found: String },

    /// The DSSE predicate type is not the expected schema constant.
    #[error("predicate type mismatch: expected `{expected}`, found `{found}`")]
    WrongPredicateType { expected: String, found: String },

    /// A path contains `..` components.
    #[error("path traversal in entry `{path}`")]
    PathTraversal { path: String },

    /// An entry path is absolute.
    #[error("absolute path in entry `{path}`")]
    AbsolutePath { path: String },

    /// An entry path is not in the envelope's fixed allowlist.
    #[error("unknown entry path `{path}`: not in the envelope allowlist")]
    UnknownPath { path: String },

    /// A path appeared more than once in the archive.
    #[error("duplicate entry path `{path}`")]
    DuplicatePath { path: String },

    /// A non-regular-file entry type was encountered.
    #[error("forbidden entry type `{type_name}` for `{path}`: only regular files allowed")]
    ForbiddenEntryType { path: String, type_name: String },

    /// A single entry exceeds [`ScanLimits::max_entry_bytes`].
    #[error("entry `{path}` is {size} bytes, exceeds limit of {limit} bytes")]
    OversizedEntry { path: String, size: u64, limit: u64 },

    /// Total decompressed bytes exceed [`ScanLimits::max_total_bytes`].
    #[error("total decompressed {total} bytes exceeds limit of {limit} bytes")]
    OversizedTotal { total: u64, limit: u64 },

    /// The archive has more entries than [`ScanLimits::max_entry_count`].
    #[error("{count} entries exceeds limit of {limit}")]
    TooManyEntries { count: usize, limit: usize },

    /// The decompressed/compressed ratio exceeds
    /// [`ScanLimits::max_compression_ratio`].
    #[error("decompression ratio {ratio:.1}:1 exceeds limit of {limit:.1}:1")]
    DecompressionBomb { ratio: f64, limit: f64 },

    /// A blob's content does not hash to the manifest-declared digest.
    #[error("blob `{path}` tampered: manifest declares {expected}, content is {actual}")]
    TamperedBlob {
        path: String,
        expected: String,
        actual: String,
    },

    /// A blob digest is not referenced by the verified plan.
    #[error("blob digest `{digest}` is not referenced by the verified plan")]
    UnreferencedBlob { digest: String },

    /// A manifest entry has no corresponding archive entry.
    #[error("manifest entry `{path}` was not found in the archive")]
    MissingEntry { path: String },

    /// An archive entry has no corresponding manifest entry.
    #[error("archive entry `{path}` has no manifest entry")]
    ExtraEntry { path: String },

    /// An entry's actual byte count does not match the manifest-declared size.
    #[error("entry `{path}` is {actual} bytes but manifest declares {declared} bytes")]
    SizeMismatch {
        path: String,
        declared: u64,
        actual: u64,
    },

    /// Available disk space is insufficient for the manifest-declared total.
    #[error("need {needed} bytes but only {available} bytes available")]
    InsufficientSpace { needed: u64, available: u64 },

    /// An entry path is not valid UTF-8.
    #[error("entry path is not valid UTF-8")]
    InvalidPath,

    /// The archive ended before all required entries were read.
    #[error("archive ended early: expected entry `{expected}`")]
    UnexpectedEof { expected: &'static str },
}

// Manual From<serde_json::Error> avoids the blanket From conflict with
// PlanError's own Json variant (only one `#[from]` per source type).
impl From<serde_json::Error> for EnvelopeError {
    fn from(e: serde_json::Error) -> Self {
        EnvelopeError::Json(e)
    }
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Incrementally constructs a `.gtupdate` envelope, spooling blob content to a
/// temp directory so memory usage stays flat for multi-GiB envelopes.
///
/// Usage:
/// ```ignore
/// let mut builder = EnvelopeBuilder::new(file, &priv_pem, &key_id)?;
/// builder.add_plan(&plan_bytes, &sig_bytes)?;
/// builder.add_blob(&digest, &blob_bytes, "application/octet-stream", None)?;
/// let manifest = builder.finish()?;
/// ```
pub struct EnvelopeBuilder<W: Write> {
    writer: W,
    signing_key_pem: String,
    key_id: String,
    spool_dir: tempfile::TempDir,
    plan_bytes: Option<Vec<u8>>,
    plan_sig_bytes: Option<Vec<u8>>,
    plan_id: Option<String>,
    env_id: Option<String>,
    blobs: Vec<BlobRecord>,
    seen_digests: HashSet<String>,
}

/// One blob spooled to the temp directory, awaiting assembly in
/// [`EnvelopeBuilder::finish`].
struct BlobRecord {
    digest: String,
    temp_path: PathBuf,
    size: u64,
    media_type: String,
    target: Option<String>,
}

impl<W: Write> EnvelopeBuilder<W> {
    /// Create a new builder that will write the compressed archive to `writer`.
    ///
    /// `signing_key_pkcs8_pem` and `key_id` are the Ed25519 private key and its
    /// canonical id — the same parameters [`crate::plan::build_update_plan`]
    /// takes. The manifest is signed at [`finish`](Self::finish) time.
    pub fn new(
        writer: W,
        signing_key_pkcs8_pem: &str,
        key_id: &str,
    ) -> Result<Self, EnvelopeError> {
        let spool_dir = tempfile::TempDir::new().map_err(|source| EnvelopeError::Io {
            path: PathBuf::from("<tempdir>"),
            source,
        })?;
        Ok(Self {
            writer,
            signing_key_pem: signing_key_pkcs8_pem.to_string(),
            key_id: key_id.to_string(),
            spool_dir,
            plan_bytes: None,
            plan_sig_bytes: None,
            plan_id: None,
            env_id: None,
            blobs: Vec::new(),
            seen_digests: HashSet::new(),
        })
    }

    /// Add the update plan and its DSSE sidecar. Must be called exactly once
    /// before [`finish`](Self::finish). The plan bytes are parsed to extract
    /// `plan_id` and `env_id` for the manifest.
    pub fn add_plan(&mut self, plan_bytes: &[u8], sig_bytes: &[u8]) -> Result<(), EnvelopeError> {
        let plan: plan::UpdatePlan = serde_json::from_slice(plan_bytes)?;
        self.plan_id = Some(plan.plan_id);
        self.env_id = Some(plan.env_id);
        self.plan_bytes = Some(plan_bytes.to_vec());
        self.plan_sig_bytes = Some(sig_bytes.to_vec());
        Ok(())
    }

    /// Add a content-addressed blob (artifact or binary). The blob bytes are
    /// verified against `digest` and spooled to a temp file. `media_type` is
    /// recorded in the manifest; `target` is the Rust target triple (set for
    /// binary blobs, `None` for content artifacts).
    ///
    /// Blobs carry the **raw inner executable** for binaries (content-addressed
    /// by the existing [`crate::plan::BinaryArtifact::digest`] which hashes the
    /// inner binary) — never release archives.
    pub fn add_blob(
        &mut self,
        digest: &str,
        bytes: &[u8],
        media_type: &str,
        target: Option<&str>,
    ) -> Result<(), EnvelopeError> {
        // Validate and normalize the digest.
        let (dir_name, expected_hex) = staging::digest_dir_name(digest)?;
        let actual_hex = plan::sha256_hex(bytes);
        if actual_hex != expected_hex {
            return Err(EnvelopeError::BlobDigestMismatch {
                digest: digest.to_string(),
                expected_hex,
                actual_hex,
            });
        }
        if !self.seen_digests.insert(digest.to_string()) {
            return Err(EnvelopeError::DuplicateBlob {
                digest: digest.to_string(),
            });
        }
        // Spool to temp file.
        let temp_path = self.spool_dir.path().join(&dir_name);
        std::fs::write(&temp_path, bytes).map_err(|source| EnvelopeError::Io {
            path: temp_path.clone(),
            source,
        })?;
        self.blobs.push(BlobRecord {
            digest: digest.to_string(),
            temp_path,
            size: bytes.len() as u64,
            media_type: media_type.to_string(),
            target: target.map(str::to_string),
        });
        Ok(())
    }

    /// Assemble the archive: build the manifest, sign it, write the
    /// zstd-compressed tar stream to the writer provided in [`new`](Self::new),
    /// and return the signed manifest. Consumes the builder (the temp directory
    /// is cleaned up on drop).
    pub fn finish(self) -> Result<EnvelopeManifest, EnvelopeError> {
        let plan_bytes = self.plan_bytes.ok_or(EnvelopeError::NoPlan)?;
        let plan_sig_bytes = self.plan_sig_bytes.ok_or(EnvelopeError::NoPlan)?;
        let plan_id = self.plan_id.ok_or(EnvelopeError::NoPlan)?;
        let env_id = self.env_id.ok_or(EnvelopeError::NoPlan)?;

        // Build the manifest entries. Manifest.json/.sig are NOT listed
        // (self-reference). Plan + blobs are listed.
        let mut entries = Vec::with_capacity(2 + self.blobs.len());
        entries.push(ManifestEntry {
            path: PLAN_PATH.to_string(),
            digest: format!("sha256:{}", plan::sha256_hex(&plan_bytes)),
            size: plan_bytes.len() as u64,
            media_type: "application/json".to_string(),
            target: None,
        });
        entries.push(ManifestEntry {
            path: PLAN_SIG_PATH.to_string(),
            digest: format!("sha256:{}", plan::sha256_hex(&plan_sig_bytes)),
            size: plan_sig_bytes.len() as u64,
            media_type: "application/json".to_string(),
            target: None,
        });
        for blob in &self.blobs {
            let (dir_name, _) = staging::digest_dir_name(&blob.digest)?;
            entries.push(ManifestEntry {
                path: format!("{BLOBS_PREFIX}{dir_name}"),
                digest: blob.digest.clone(),
                size: blob.size,
                media_type: blob.media_type.clone(),
                target: blob.target.clone(),
            });
        }

        let manifest = EnvelopeManifest {
            schema: MANIFEST_SCHEMA_V1.to_string(),
            plan_id,
            env_id,
            created_at: Utc::now(),
            entries,
        };

        let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
        let manifest_sig_bytes = sign_envelope_payload(
            &manifest_bytes,
            MANIFEST_SCHEMA_V1,
            "envelope-manifest",
            &self.signing_key_pem,
            &self.key_id,
        )?;

        // Assemble the zstd-compressed tar.
        let encoder = zstd::Encoder::new(self.writer, 3).map_err(EnvelopeError::ArchiveIo)?;
        let mut tar = tar::Builder::new(encoder);

        append_bytes_entry(&mut tar, MANIFEST_PATH, &manifest_bytes)?;
        append_bytes_entry(&mut tar, MANIFEST_SIG_PATH, &manifest_sig_bytes)?;
        append_bytes_entry(&mut tar, PLAN_PATH, &plan_bytes)?;
        append_bytes_entry(&mut tar, PLAN_SIG_PATH, &plan_sig_bytes)?;

        for blob in &self.blobs {
            let (dir_name, _) = staging::digest_dir_name(&blob.digest)?;
            let archive_path = format!("{BLOBS_PREFIX}{dir_name}");
            let file =
                std::fs::File::open(&blob.temp_path).map_err(|source| EnvelopeError::Io {
                    path: blob.temp_path.clone(),
                    source,
                })?;
            let mut header = tar::Header::new_gnu();
            header.set_size(blob.size);
            header.set_mode(0o644);
            header.set_mtime(0);
            header.set_entry_type(tar::EntryType::file());
            header.set_cksum();
            tar.append_data(&mut header, &archive_path, file)
                .map_err(EnvelopeError::ArchiveIo)?;
        }

        let encoder = tar.into_inner().map_err(EnvelopeError::ArchiveIo)?;
        encoder.finish().map_err(EnvelopeError::ArchiveIo)?;

        Ok(manifest)
    }
}

// ---------------------------------------------------------------------------
// Scanner
// ---------------------------------------------------------------------------

/// Scan a `.gtupdate` envelope, extracting verified content into
/// `quarantine_dir`.
///
/// This is the primary security boundary for airgapped updates: it processes
/// **untrusted removable media** and must be hardened against hostile archives.
/// The strict archive grammar is enforced **during streaming** — never after.
///
/// On success the returned [`ScannedEnvelopeRef`] references only verified
/// content inside the quarantine directory. On failure the quarantine directory
/// is left in whatever state the scanner reached — the caller should delete it.
pub fn scan_envelope_to_dir<R: Read>(
    reader: R,
    trust_root: &TrustRoot,
    limits: &ScanLimits,
    quarantine_dir: &Path,
) -> Result<ScannedEnvelopeRef, EnvelopeError> {
    // Wrap the compressed reader to track consumed bytes for the ratio check.
    let compressed_count = Rc::new(Cell::new(0u64));
    let counting = CountingReader {
        inner: reader,
        count: compressed_count.clone(),
    };
    let decoder = zstd::Decoder::new(counting).map_err(EnvelopeError::ArchiveIo)?;
    let mut archive = tar::Archive::new(decoder);
    let mut entries_iter = archive.entries().map_err(EnvelopeError::ArchiveIo)?;

    let mut entry_count: usize = 0;
    let mut decompressed_total: u64 = 0;
    let mut seen_paths = HashSet::new();

    // ---- Entry #1: manifest.json ----------------------------------------
    let manifest_bytes = {
        let mut entry = next_required(&mut entries_iter, MANIFEST_PATH)?;
        entry_count += 1;
        let path_str = entry_path_str(&entry)?;
        reject_if_not_regular(&path_str, &entry)?;
        if path_str != MANIFEST_PATH {
            return Err(EnvelopeError::WrongEntryOrder {
                index: 1,
                expected: MANIFEST_PATH,
                found: path_str,
            });
        }
        let size = entry.header().size().map_err(EnvelopeError::ArchiveIo)?;
        if size > limits.max_manifest_bytes {
            return Err(EnvelopeError::OversizedManifest {
                size,
                limit: limits.max_manifest_bytes,
            });
        }
        seen_paths.insert(path_str);
        let data = read_entry_bytes(&mut entry, size)?;
        decompressed_total += data.len() as u64;
        data
    };

    // ---- Entry #2: manifest.json.sig ------------------------------------
    let manifest_sig_bytes = {
        let mut entry = next_required(&mut entries_iter, MANIFEST_SIG_PATH)?;
        entry_count += 1;
        let path_str = entry_path_str(&entry)?;
        reject_if_not_regular(&path_str, &entry)?;
        if path_str != MANIFEST_SIG_PATH {
            return Err(EnvelopeError::WrongEntryOrder {
                index: 2,
                expected: MANIFEST_SIG_PATH,
                found: path_str,
            });
        }
        seen_paths.insert(path_str);
        let size = entry.header().size().map_err(EnvelopeError::ArchiveIo)?;
        let data = read_entry_bytes(&mut entry, size)?;
        decompressed_total += data.len() as u64;
        data
    };

    // Verify manifest signature before trusting any later entry.
    let manifest_sha = plan::sha256_hex(&manifest_bytes);
    let verified_manifest = verify_artifact_dsse(&manifest_sig_bytes, &manifest_sha, trust_root)?;
    if verified_manifest.statement.predicate_type != MANIFEST_SCHEMA_V1 {
        return Err(EnvelopeError::WrongPredicateType {
            expected: MANIFEST_SCHEMA_V1.to_string(),
            found: verified_manifest.statement.predicate_type,
        });
    }
    let verified_key_ids = verified_manifest.verified_key_ids;

    let manifest: EnvelopeManifest = serde_json::from_slice(&manifest_bytes)?;
    if manifest.schema != MANIFEST_SCHEMA_V1 {
        return Err(EnvelopeError::WrongSchema {
            expected: MANIFEST_SCHEMA_V1.to_string(),
            found: manifest.schema,
        });
    }

    // Build the expected-entries map from the manifest (keyed by path).
    let mut expected: HashMap<String, &ManifestEntry> = HashMap::new();
    for me in &manifest.entries {
        expected.insert(me.path.clone(), me);
    }

    // Disk-space reservation: sum declared sizes and check available space.
    let needed: u64 = manifest.entries.iter().map(|e| e.size).sum();
    let available = fs4::available_space(quarantine_dir).map_err(|source| EnvelopeError::Io {
        path: quarantine_dir.to_path_buf(),
        source,
    })?;
    if available < needed {
        return Err(EnvelopeError::InsufficientSpace { needed, available });
    }

    // ---- Entry #3: plan.json --------------------------------------------
    let plan_path = quarantine_dir.join(PLAN_PATH);
    let plan_bytes = {
        let mut entry = next_required(&mut entries_iter, PLAN_PATH)?;
        entry_count += 1;
        let path_str = entry_path_str(&entry)?;
        reject_if_not_regular(&path_str, &entry)?;
        if path_str != PLAN_PATH {
            return Err(EnvelopeError::WrongEntryOrder {
                index: 3,
                expected: PLAN_PATH,
                found: path_str,
            });
        }
        check_entry_limits(
            &path_str,
            &entry,
            limits,
            &mut entry_count,
            decompressed_total,
        )?;
        seen_paths.insert(path_str.clone());
        let size = entry.header().size().map_err(EnvelopeError::ArchiveIo)?;
        let data = read_entry_bytes(&mut entry, size)?;
        verify_manifest_entry(&path_str, &data, &expected)?;
        decompressed_total += data.len() as u64;
        std::fs::write(&plan_path, &data).map_err(|source| EnvelopeError::Io {
            path: plan_path.clone(),
            source,
        })?;
        data
    };

    // ---- Entry #4: plan.json.sig ----------------------------------------
    let sig_path = quarantine_dir.join(PLAN_SIG_PATH);
    let plan_sig_bytes = {
        let mut entry = next_required(&mut entries_iter, PLAN_SIG_PATH)?;
        entry_count += 1;
        let path_str = entry_path_str(&entry)?;
        reject_if_not_regular(&path_str, &entry)?;
        if path_str != PLAN_SIG_PATH {
            return Err(EnvelopeError::WrongEntryOrder {
                index: 4,
                expected: PLAN_SIG_PATH,
                found: path_str,
            });
        }
        check_entry_limits(
            &path_str,
            &entry,
            limits,
            &mut entry_count,
            decompressed_total,
        )?;
        seen_paths.insert(path_str.clone());
        let size = entry.header().size().map_err(EnvelopeError::ArchiveIo)?;
        let data = read_entry_bytes(&mut entry, size)?;
        verify_manifest_entry(&path_str, &data, &expected)?;
        decompressed_total += data.len() as u64;
        std::fs::write(&sig_path, &data).map_err(|source| EnvelopeError::Io {
            path: sig_path.clone(),
            source,
        })?;
        data
    };

    // Verify the plan before extracting blobs.
    let verified_plan = plan::verify_update_plan(&plan_bytes, &plan_sig_bytes, trust_root)?;

    // Build the set of allowed blob digests from the verified plan.
    let mut plan_digests: HashSet<String> = HashSet::new();
    for a in &verified_plan.plan.artifacts {
        plan_digests.insert(a.digest.clone());
    }
    for b in &verified_plan.plan.binaries {
        plan_digests.insert(b.digest.clone());
    }

    // ---- Remaining entries: blobs and optional trust-rotation ------------
    let blobs_dir = quarantine_dir.join("blobs");
    let mut blob_paths: HashMap<String, PathBuf> = HashMap::new();
    let mut trust_rotation_path: Option<PathBuf> = None;
    let mut trust_rotation_sig_path: Option<PathBuf> = None;
    let mut seen_trust_rotation = false;

    for entry_result in &mut entries_iter {
        let mut entry = entry_result.map_err(EnvelopeError::ArchiveIo)?;
        entry_count += 1;
        if entry_count > limits.max_entry_count {
            return Err(EnvelopeError::TooManyEntries {
                count: entry_count,
                limit: limits.max_entry_count,
            });
        }
        let path_str = entry_path_str(&entry)?;
        reject_if_not_regular(&path_str, &entry)?;
        validate_path(&path_str)?;

        if !seen_paths.insert(path_str.clone()) {
            return Err(EnvelopeError::DuplicatePath { path: path_str });
        }

        let header_size = entry.header().size().map_err(EnvelopeError::ArchiveIo)?;
        if header_size > limits.max_entry_bytes {
            return Err(EnvelopeError::OversizedEntry {
                path: path_str,
                size: header_size,
                limit: limits.max_entry_bytes,
            });
        }

        if let Some(blob_name) = path_str.strip_prefix(BLOBS_PREFIX) {
            // After trust-rotation, no more blobs.
            if seen_trust_rotation {
                return Err(EnvelopeError::WrongEntryOrder {
                    index: entry_count,
                    expected: TRUST_ROTATION_SIG_PATH,
                    found: path_str,
                });
            }
            // Validate the blob name is "sha256-<64 lowercase hex>".
            validate_blob_name(blob_name)?;
            let digest = format!("sha256:{}", &blob_name["sha256-".len()..]);

            // The blob must be in the manifest.
            if !expected.contains_key(&path_str) {
                return Err(EnvelopeError::ExtraEntry { path: path_str });
            }
            // The blob must be referenced by the plan.
            if !plan_digests.contains(&digest) {
                return Err(EnvelopeError::UnreferencedBlob { digest });
            }

            // Stream to quarantine, compute SHA-256 during the copy.
            std::fs::create_dir_all(&blobs_dir).map_err(|source| EnvelopeError::Io {
                path: blobs_dir.clone(),
                source,
            })?;
            staging::assert_no_symlink_ancestors(quarantine_dir, &blobs_dir)?;
            let dest = blobs_dir.join(blob_name);
            let actual_hex = stream_entry_to_file(
                &mut entry,
                &dest,
                header_size,
                limits,
                &mut decompressed_total,
                &compressed_count,
            )?;

            // Verify content digest.
            let me = expected.get(&path_str).unwrap();
            let (_, expected_hex) = staging::digest_dir_name(&me.digest)?;
            if actual_hex != expected_hex {
                return Err(EnvelopeError::TamperedBlob {
                    path: path_str,
                    expected: me.digest.clone(),
                    actual: format!("sha256:{actual_hex}"),
                });
            }
            // Verify size.
            let actual_size = std::fs::metadata(&dest)
                .map_err(|source| EnvelopeError::Io {
                    path: dest.clone(),
                    source,
                })?
                .len();
            if actual_size != me.size {
                return Err(EnvelopeError::SizeMismatch {
                    path: path_str,
                    declared: me.size,
                    actual: actual_size,
                });
            }

            blob_paths.insert(digest, dest);
        } else if path_str == TRUST_ROTATION_PATH {
            seen_trust_rotation = true;
            let me = expected.get(&path_str);
            let data = read_entry_bytes(&mut entry, header_size)?;
            decompressed_total += data.len() as u64;
            if let Some(me) = me {
                verify_entry_digest_size(&path_str, &data, me)?;
            }
            let dest = quarantine_dir.join(TRUST_ROTATION_PATH);
            std::fs::write(&dest, &data).map_err(|source| EnvelopeError::Io {
                path: dest.clone(),
                source,
            })?;
            trust_rotation_path = Some(dest);
        } else if path_str == TRUST_ROTATION_SIG_PATH {
            if !seen_trust_rotation {
                return Err(EnvelopeError::WrongEntryOrder {
                    index: entry_count,
                    expected: TRUST_ROTATION_PATH,
                    found: path_str,
                });
            }
            let me = expected.get(&path_str);
            let data = read_entry_bytes(&mut entry, header_size)?;
            decompressed_total += data.len() as u64;
            if let Some(me) = me {
                verify_entry_digest_size(&path_str, &data, me)?;
            }
            let dest = quarantine_dir.join(TRUST_ROTATION_SIG_PATH);
            std::fs::write(&dest, &data).map_err(|source| EnvelopeError::Io {
                path: dest.clone(),
                source,
            })?;
            trust_rotation_sig_path = Some(dest);
        } else {
            return Err(EnvelopeError::UnknownPath { path: path_str });
        }
    }

    // Completeness: every manifest entry must have been seen in the archive.
    for me in &manifest.entries {
        if !seen_paths.contains(&me.path) {
            return Err(EnvelopeError::MissingEntry {
                path: me.path.clone(),
            });
        }
    }

    Ok(ScannedEnvelopeRef {
        manifest,
        verified_key_ids,
        plan_path,
        sig_path,
        blob_paths,
        trust_rotation_path,
        trust_rotation_sig_path,
    })
}

// ---------------------------------------------------------------------------
// Receipts
// ---------------------------------------------------------------------------

/// Build and sign an import receipt listing the digests the environment holds.
///
/// Returns `(receipt_bytes, sig_bytes)` — both serialized as pretty JSON.
/// The signing uses the same DSSE path as
/// [`crate::plan::build_update_plan`]; `signing_key_pkcs8_pem` and `key_id`
/// are the caller's operator key. Which trust root governs receipts is the
/// **caller's** policy — this function just signs.
pub fn build_import_receipt(
    env_id: &str,
    held_digests: Vec<String>,
    signing_key_pkcs8_pem: &str,
    key_id: &str,
) -> Result<(Vec<u8>, Vec<u8>), EnvelopeError> {
    let receipt = ImportReceipt {
        schema: RECEIPT_SCHEMA_V1.to_string(),
        env_id: env_id.to_string(),
        created_at: Utc::now(),
        held_digests,
    };
    let receipt_bytes = serde_json::to_vec_pretty(&receipt)?;
    let sig_bytes = sign_envelope_payload(
        &receipt_bytes,
        RECEIPT_SCHEMA_V1,
        &format!("import-receipt/{env_id}"),
        signing_key_pkcs8_pem,
        key_id,
    )?;
    Ok((receipt_bytes, sig_bytes))
}

/// Verify an import receipt's DSSE signature and schema, returning the parsed
/// receipt on success. Which trust root governs receipts is the **caller's**
/// policy.
pub fn verify_import_receipt(
    receipt_bytes: &[u8],
    sig_bytes: &[u8],
    trust_root: &TrustRoot,
) -> Result<ImportReceipt, EnvelopeError> {
    let sha = plan::sha256_hex(receipt_bytes);
    let verified = verify_artifact_dsse(sig_bytes, &sha, trust_root)?;
    if verified.statement.predicate_type != RECEIPT_SCHEMA_V1 {
        return Err(EnvelopeError::WrongPredicateType {
            expected: RECEIPT_SCHEMA_V1.to_string(),
            found: verified.statement.predicate_type,
        });
    }
    let receipt: ImportReceipt = serde_json::from_slice(receipt_bytes)?;
    if receipt.schema != RECEIPT_SCHEMA_V1 {
        return Err(EnvelopeError::WrongSchema {
            expected: RECEIPT_SCHEMA_V1.to_string(),
            found: receipt.schema,
        });
    }
    Ok(receipt)
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

/// Sign `payload_bytes` as a DSSE in-toto statement whose subject pins its
/// SHA-256. Shared by the manifest builder and receipt builder.
fn sign_envelope_payload(
    payload_bytes: &[u8],
    predicate_type: &str,
    subject_name: &str,
    signing_key_pem: &str,
    key_id: &str,
) -> Result<Vec<u8>, EnvelopeError> {
    let sha = plan::sha256_hex(payload_bytes);
    let mut digest = BTreeMap::new();
    digest.insert("sha256".to_string(), sha);
    let statement = InTotoStatement {
        type_: INTOTO_STATEMENT_TYPE.to_string(),
        subject: vec![Subject {
            name: subject_name.to_string(),
            digest,
        }],
        predicate_type: predicate_type.to_string(),
        predicate: serde_json::json!({}),
    };
    let envelope = sign_statement(&statement, signing_key_pem, key_id)?;
    Ok(serde_json::to_vec_pretty(&envelope)?)
}

/// Append a regular-file entry to a tar builder from in-memory bytes.
fn append_bytes_entry<W: Write>(
    builder: &mut tar::Builder<W>,
    path: &str,
    data: &[u8],
) -> Result<(), EnvelopeError> {
    let mut header = tar::Header::new_gnu();
    header.set_size(data.len() as u64);
    header.set_mode(0o644);
    header.set_mtime(0);
    header.set_entry_type(tar::EntryType::file());
    header.set_cksum();
    builder
        .append_data(&mut header, path, data)
        .map_err(EnvelopeError::ArchiveIo)?;
    Ok(())
}

/// A [`Read`] wrapper that counts bytes consumed, using a shared
/// [`Rc<Cell<u64>>`] so the caller can inspect the count while the reader is
/// owned by a zstd decoder + tar archive.
struct CountingReader<R> {
    inner: R,
    count: Rc<Cell<u64>>,
}

impl<R: Read> Read for CountingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.count.set(self.count.get() + n as u64);
        Ok(n)
    }
}

/// Get the next entry from the iterator or return [`EnvelopeError::UnexpectedEof`].
fn next_required<'a, R: Read>(
    entries: &mut tar::Entries<'a, R>,
    expected: &'static str,
) -> Result<tar::Entry<'a, R>, EnvelopeError> {
    entries
        .next()
        .ok_or(EnvelopeError::UnexpectedEof { expected })?
        .map_err(EnvelopeError::ArchiveIo)
}

/// Extract a UTF-8 path string from a tar entry.
fn entry_path_str<R: Read>(entry: &tar::Entry<'_, R>) -> Result<String, EnvelopeError> {
    let path = entry.path().map_err(EnvelopeError::ArchiveIo)?;
    let s = path.to_str().ok_or(EnvelopeError::InvalidPath)?;
    // Strip leading "./" that some tar writers prepend.
    Ok(s.strip_prefix("./").unwrap_or(s).to_string())
}

/// Reject any entry that is not a regular file — the only type allowed in a
/// `.gtupdate` archive.
fn reject_if_not_regular<R: Read>(
    path: &str,
    entry: &tar::Entry<'_, R>,
) -> Result<(), EnvelopeError> {
    let et = entry.header().entry_type();
    if !et.is_file() {
        return Err(EnvelopeError::ForbiddenEntryType {
            path: path.to_string(),
            type_name: entry_type_label(et),
        });
    }
    Ok(())
}

/// Human-readable label for a tar entry type (error messages).
fn entry_type_label(et: tar::EntryType) -> String {
    if et.is_hard_link() {
        "hardlink".to_string()
    } else if et.is_symlink() {
        "symlink".to_string()
    } else if et.is_dir() {
        "directory".to_string()
    } else if et == tar::EntryType::Char {
        "character device".to_string()
    } else if et == tar::EntryType::Block {
        "block device".to_string()
    } else if et == tar::EntryType::Fifo {
        "fifo".to_string()
    } else if et == tar::EntryType::GNUSparse {
        "gnu sparse".to_string()
    } else {
        format!("type 0x{:02x}", et.as_byte())
    }
}

/// Validate a path against the envelope allowlist. Called for entries after the
/// first four (which are checked positionally).
fn validate_path(path: &str) -> Result<(), EnvelopeError> {
    if path.starts_with('/') {
        return Err(EnvelopeError::AbsolutePath {
            path: path.to_string(),
        });
    }
    if path.split('/').any(|c| c == "..") {
        return Err(EnvelopeError::PathTraversal {
            path: path.to_string(),
        });
    }
    // Check against the fixed allowlist.
    if path == TRUST_ROTATION_PATH || path == TRUST_ROTATION_SIG_PATH {
        return Ok(());
    }
    if let Some(blob_name) = path.strip_prefix(BLOBS_PREFIX) {
        validate_blob_name(blob_name)?;
        return Ok(());
    }
    Err(EnvelopeError::UnknownPath {
        path: path.to_string(),
    })
}

/// Validate that a blob entry name matches `sha256-<64 lowercase hex>`.
fn validate_blob_name(name: &str) -> Result<(), EnvelopeError> {
    let Some(hex) = name.strip_prefix("sha256-") else {
        return Err(EnvelopeError::UnknownPath {
            path: format!("{BLOBS_PREFIX}{name}"),
        });
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(EnvelopeError::UnknownPath {
            path: format!("{BLOBS_PREFIX}{name}"),
        });
    }
    Ok(())
}

/// Check per-entry size and entry-count limits (used for entries after the
/// manifest).
fn check_entry_limits<R: Read>(
    path: &str,
    entry: &tar::Entry<'_, R>,
    limits: &ScanLimits,
    entry_count: &mut usize,
    _decompressed_total: u64,
) -> Result<(), EnvelopeError> {
    if *entry_count > limits.max_entry_count {
        return Err(EnvelopeError::TooManyEntries {
            count: *entry_count,
            limit: limits.max_entry_count,
        });
    }
    let size = entry.header().size().map_err(EnvelopeError::ArchiveIo)?;
    if size > limits.max_entry_bytes {
        return Err(EnvelopeError::OversizedEntry {
            path: path.to_string(),
            size,
            limit: limits.max_entry_bytes,
        });
    }
    Ok(())
}

/// Read an entry's full content into memory (for small entries: manifest, plan,
/// signatures).
fn read_entry_bytes<R: Read>(entry: &mut R, size: u64) -> Result<Vec<u8>, EnvelopeError> {
    let mut buf = Vec::with_capacity(size as usize);
    entry
        .read_to_end(&mut buf)
        .map_err(EnvelopeError::ArchiveIo)?;
    Ok(buf)
}

/// Verify an archive entry's content against the manifest (digest + size).
fn verify_manifest_entry(
    path: &str,
    data: &[u8],
    expected: &HashMap<String, &ManifestEntry>,
) -> Result<(), EnvelopeError> {
    let me = expected
        .get(path)
        .ok_or_else(|| EnvelopeError::ExtraEntry {
            path: path.to_string(),
        })?;
    verify_entry_digest_size(path, data, me)
}

/// Check a read entry's SHA-256 and length against its manifest entry.
fn verify_entry_digest_size(
    path: &str,
    data: &[u8],
    me: &ManifestEntry,
) -> Result<(), EnvelopeError> {
    let actual_hex = plan::sha256_hex(data);
    let (_, expected_hex) = staging::digest_dir_name(&me.digest)?;
    if actual_hex != expected_hex {
        return Err(EnvelopeError::TamperedBlob {
            path: path.to_string(),
            expected: me.digest.clone(),
            actual: format!("sha256:{actual_hex}"),
        });
    }
    if data.len() as u64 != me.size {
        return Err(EnvelopeError::SizeMismatch {
            path: path.to_string(),
            declared: me.size,
            actual: data.len() as u64,
        });
    }
    Ok(())
}

/// Stream a tar entry to a file inside the quarantine directory, computing
/// SHA-256 during the copy and enforcing resource limits during decompression.
/// Returns the lowercase-hex content digest.
fn stream_entry_to_file<R: Read>(
    entry: &mut R,
    dest: &Path,
    entry_size: u64,
    limits: &ScanLimits,
    decompressed_total: &mut u64,
    compressed_count: &Rc<Cell<u64>>,
) -> Result<String, EnvelopeError> {
    let mut hasher = Sha256::new();
    let mut file = std::fs::File::create(dest).map_err(|source| EnvelopeError::Io {
        path: dest.to_path_buf(),
        source,
    })?;
    let mut remaining = entry_size;
    let mut buf = [0u8; 65536];
    loop {
        let to_read = std::cmp::min(remaining, buf.len() as u64) as usize;
        if to_read == 0 {
            break;
        }
        let n = entry
            .read(&mut buf[..to_read])
            .map_err(EnvelopeError::ArchiveIo)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        file.write_all(&buf[..n])
            .map_err(|source| EnvelopeError::Io {
                path: dest.to_path_buf(),
                source,
            })?;
        remaining -= n as u64;
        *decompressed_total += n as u64;

        if *decompressed_total > limits.max_total_bytes {
            return Err(EnvelopeError::OversizedTotal {
                total: *decompressed_total,
                limit: limits.max_total_bytes,
            });
        }
        let compressed = compressed_count.get();
        if compressed > 0 {
            let ratio = *decompressed_total as f64 / compressed as f64;
            if ratio > limits.max_compression_ratio {
                return Err(EnvelopeError::DecompressionBomb {
                    ratio,
                    limit: limits.max_compression_ratio,
                });
            }
        }
    }
    file.sync_all().map_err(|source| EnvelopeError::Io {
        path: dest.to_path_buf(),
        source,
    })?;
    Ok(hex::encode(hasher.finalize()))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::{
        BinaryArtifact, CompatRequirements, OnFail, PlanArtifact, RollbackKind, RollbackPolicy,
        UpdatePlan,
    };
    use ed25519_dalek::SigningKey;
    use ed25519_dalek::pkcs8::EncodePrivateKey;
    use ed25519_dalek::pkcs8::EncodePublicKey;
    use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
    use greentic_distributor_client::signing::{TrustedKey, key_id_for_public_key_pem};
    use tempfile::TempDir;

    // -- Fixtures ---------------------------------------------------------

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

    fn test_plan(artifacts: Vec<PlanArtifact>, binaries: Vec<BinaryArtifact>) -> UpdatePlan {
        UpdatePlan {
            schema: plan::UPDATE_PLAN_SCHEMA_V1.to_string(),
            plan_id: "plan-test".to_string(),
            env_id: "env-test".to_string(),
            sequence: 1,
            created_at: chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
            nonce: "nonce-1".to_string(),
            target: serde_json::json!({}),
            artifacts,
            binaries,
            compat: CompatRequirements::default(),
            rollback: RollbackPolicy {
                policy: RollbackKind::Auto,
                health_timeout_s: 60,
                on_fail: OnFail::Restore,
            },
        }
    }

    fn test_artifact(name: &str, content: &[u8]) -> PlanArtifact {
        PlanArtifact {
            name: name.to_string(),
            version: "1.0.0".to_string(),
            digest: format!("sha256:{}", plan::sha256_hex(content)),
            source: None,
        }
    }

    fn test_binary(name: &str, content: &[u8], target: &str) -> BinaryArtifact {
        BinaryArtifact {
            name: name.to_string(),
            version: "1.0.0".to_string(),
            target: target.to_string(),
            digest: format!("sha256:{}", plan::sha256_hex(content)),
            source: None,
        }
    }

    /// Build a signed plan using the given key and trust root.
    fn signed_plan(
        plan: &UpdatePlan,
        priv_pem: &str,
        key_id: &str,
        trust_root: &TrustRoot,
    ) -> (Vec<u8>, Vec<u8>) {
        let built = plan::build_update_plan(plan, priv_pem, key_id, trust_root).unwrap();
        (built.plan_bytes, built.envelope_bytes)
    }

    /// Build a complete valid .gtupdate archive, returning the compressed bytes.
    fn build_valid_envelope(
        plan: &UpdatePlan,
        priv_pem: &str,
        key_id: &str,
        trust_root: &TrustRoot,
        blobs: &[(&str, &[u8], &str, Option<&str>)], // (digest, content, media_type, target)
    ) -> Vec<u8> {
        let (plan_bytes, sig_bytes) = signed_plan(plan, priv_pem, key_id, trust_root);
        let mut output = Vec::new();
        let mut builder = EnvelopeBuilder::new(&mut output, priv_pem, key_id).unwrap();
        builder.add_plan(&plan_bytes, &sig_bytes).unwrap();
        for (digest, content, media_type, target) in blobs {
            builder
                .add_blob(digest, content, media_type, *target)
                .unwrap();
        }
        builder.finish().unwrap();
        output
    }

    /// Build a hostile tar archive from raw entries, then compress with zstd.
    /// Each entry is (header, path, content).
    fn build_hostile_archive(entries: Vec<(tar::Header, &str, &[u8])>) -> Vec<u8> {
        let mut tar_bytes = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_bytes);
            for (mut header, path, content) in entries {
                builder.append_data(&mut header, path, content).unwrap();
            }
            builder.into_inner().unwrap();
        }
        zstd::encode_all(std::io::Cursor::new(&tar_bytes), 3).unwrap()
    }

    /// Build a hostile tar archive where the LAST entry bypasses the tar builder's
    /// path validation by writing its header bytes directly. This is needed for
    /// entries the builder refuses to produce (e.g. `..` path components). All
    /// entries except the last are written through the builder normally.
    fn build_hostile_archive_raw_last(
        normal: Vec<(tar::Header, &str, &[u8])>,
        raw_header: tar::Header,
        raw_content: &[u8],
    ) -> Vec<u8> {
        let mut tar_bytes = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_bytes);
            for (mut header, path, content) in normal {
                builder.append_data(&mut header, path, content).unwrap();
            }
            // `into_inner` calls `finish` which writes two 512-byte zero blocks
            // (the end-of-archive trailer). Strip them so we can append the raw
            // entry before the real trailer.
            builder.into_inner().unwrap();
        }
        // Remove the 1024-byte trailer the builder wrote.
        tar_bytes.truncate(tar_bytes.len() - 1024);
        // Append the raw entry.
        tar_bytes.extend_from_slice(raw_header.as_bytes());
        tar_bytes.extend_from_slice(&tar_content_padded(raw_content));
        // Write a fresh end-of-archive trailer.
        tar_bytes.extend_from_slice(&[0u8; 1024]);
        zstd::encode_all(std::io::Cursor::new(&tar_bytes), 3).unwrap()
    }

    /// Pad content to the next 512-byte boundary (tar record alignment).
    fn tar_content_padded(content: &[u8]) -> Vec<u8> {
        let mut buf = content.to_vec();
        let padding = (512 - (content.len() % 512)) % 512;
        buf.extend(std::iter::repeat_n(0u8, padding));
        buf
    }

    /// Write a path directly into a GNU tar header's name field, bypassing the
    /// builder's path validation.
    fn set_header_path_raw(header: &mut tar::Header, path: &str) {
        let name = &mut header.as_gnu_mut().unwrap().name;
        let path_bytes = path.as_bytes();
        // Zero-fill then copy.
        for b in name.iter_mut() {
            *b = 0;
        }
        name[..path_bytes.len()].copy_from_slice(path_bytes);
        header.set_cksum();
    }

    fn regular_header(size: u64) -> tar::Header {
        let mut h = tar::Header::new_gnu();
        h.set_size(size);
        h.set_mode(0o644);
        h.set_mtime(0);
        h.set_entry_type(tar::EntryType::file());
        h.set_cksum();
        h
    }

    /// Build a valid set of signed manifest, plan, and blobs for hostile tests.
    struct TestFixture {
        priv_pem: String,
        key_id: String,
        trust_root: TrustRoot,
        plan: UpdatePlan,
        plan_bytes: Vec<u8>,
        plan_sig_bytes: Vec<u8>,
        manifest_bytes: Vec<u8>,
        manifest_sig_bytes: Vec<u8>,
        blob_content: Vec<u8>,
        blob_digest: String,
    }

    impl TestFixture {
        fn new() -> Self {
            let blob_content = b"pack-data-here".to_vec();
            let (priv_pem, tk) = test_key(42);
            let trust_root = TrustRoot::new(vec![tk.clone()]);
            let plan = test_plan(vec![test_artifact("weather-pack", &blob_content)], vec![]);
            let (plan_bytes, plan_sig_bytes) =
                signed_plan(&plan, &priv_pem, &tk.key_id, &trust_root);
            let blob_digest = format!("sha256:{}", plan::sha256_hex(&blob_content));
            let (dir_name, _) = staging::digest_dir_name(&blob_digest).unwrap();

            // Build manifest entries (mirrors builder logic).
            let entries = vec![
                ManifestEntry {
                    path: PLAN_PATH.to_string(),
                    digest: format!("sha256:{}", plan::sha256_hex(&plan_bytes)),
                    size: plan_bytes.len() as u64,
                    media_type: "application/json".to_string(),
                    target: None,
                },
                ManifestEntry {
                    path: PLAN_SIG_PATH.to_string(),
                    digest: format!("sha256:{}", plan::sha256_hex(&plan_sig_bytes)),
                    size: plan_sig_bytes.len() as u64,
                    media_type: "application/json".to_string(),
                    target: None,
                },
                ManifestEntry {
                    path: format!("{BLOBS_PREFIX}{dir_name}"),
                    digest: blob_digest.clone(),
                    size: blob_content.len() as u64,
                    media_type: "application/octet-stream".to_string(),
                    target: None,
                },
            ];

            let manifest = EnvelopeManifest {
                schema: MANIFEST_SCHEMA_V1.to_string(),
                plan_id: plan.plan_id.clone(),
                env_id: plan.env_id.clone(),
                created_at: Utc::now(),
                entries,
            };
            let manifest_bytes = serde_json::to_vec_pretty(&manifest).unwrap();
            let manifest_sig_bytes = sign_envelope_payload(
                &manifest_bytes,
                MANIFEST_SCHEMA_V1,
                "envelope-manifest",
                &priv_pem,
                &tk.key_id,
            )
            .unwrap();

            Self {
                priv_pem,
                key_id: tk.key_id,
                trust_root,
                plan,
                plan_bytes,
                plan_sig_bytes,
                manifest_bytes,
                manifest_sig_bytes,
                blob_content,
                blob_digest,
            }
        }

        /// Build a valid compressed archive from the fixture.
        fn valid_archive(&self) -> Vec<u8> {
            let (dir_name, _) = staging::digest_dir_name(&self.blob_digest).unwrap();
            build_hostile_archive(vec![
                (
                    regular_header(self.manifest_bytes.len() as u64),
                    MANIFEST_PATH,
                    &self.manifest_bytes,
                ),
                (
                    regular_header(self.manifest_sig_bytes.len() as u64),
                    MANIFEST_SIG_PATH,
                    &self.manifest_sig_bytes,
                ),
                (
                    regular_header(self.plan_bytes.len() as u64),
                    PLAN_PATH,
                    &self.plan_bytes,
                ),
                (
                    regular_header(self.plan_sig_bytes.len() as u64),
                    PLAN_SIG_PATH,
                    &self.plan_sig_bytes,
                ),
                (
                    regular_header(self.blob_content.len() as u64),
                    &format!("{BLOBS_PREFIX}{dir_name}"),
                    &self.blob_content,
                ),
            ])
        }

        /// Blob archive path.
        fn blob_archive_path(&self) -> String {
            let (dir_name, _) = staging::digest_dir_name(&self.blob_digest).unwrap();
            format!("{BLOBS_PREFIX}{dir_name}")
        }
    }

    // -- Round-trip -------------------------------------------------------

    #[test]
    fn round_trip_build_scan_verify() {
        let blob_content = b"artifact-bytes-here";
        let binary_content = b"binary-executable-bytes";
        let (priv_pem, tk) = test_key(42);
        let trust = TrustRoot::new(vec![tk.clone()]);
        let plan = test_plan(
            vec![test_artifact("weather-pack", blob_content)],
            vec![test_binary(
                "gtc",
                binary_content,
                "x86_64-unknown-linux-gnu",
            )],
        );
        let art_digest = format!("sha256:{}", plan::sha256_hex(blob_content));
        let bin_digest = format!("sha256:{}", plan::sha256_hex(binary_content));

        let archive = build_valid_envelope(
            &plan,
            &priv_pem,
            &tk.key_id,
            &trust,
            &[
                (&art_digest, blob_content, "application/octet-stream", None),
                (
                    &bin_digest,
                    binary_content,
                    "application/octet-stream",
                    Some("x86_64-unknown-linux-gnu"),
                ),
            ],
        );

        let quarantine = TempDir::new().unwrap();
        let scanned = scan_envelope_to_dir(
            std::io::Cursor::new(&archive),
            &trust,
            &ScanLimits::default(),
            quarantine.path(),
        )
        .unwrap();

        assert_eq!(scanned.manifest.plan_id, "plan-test");
        assert_eq!(scanned.manifest.env_id, "env-test");
        assert!(!scanned.verified_key_ids.is_empty());
        assert!(scanned.plan_path.exists());
        assert!(scanned.sig_path.exists());
        assert_eq!(scanned.blob_paths.len(), 2);
        assert!(scanned.blob_paths.contains_key(&art_digest));
        assert!(scanned.blob_paths.contains_key(&bin_digest));

        // Verify the plan from quarantine matches the original.
        let q_plan_bytes = std::fs::read(&scanned.plan_path).unwrap();
        let q_sig_bytes = std::fs::read(&scanned.sig_path).unwrap();
        let verified = plan::verify_update_plan(&q_plan_bytes, &q_sig_bytes, &trust).unwrap();
        assert_eq!(verified.plan.plan_id, "plan-test");
    }

    // -- Scanner rejection battery ----------------------------------------

    #[test]
    fn scan_rejects_bad_manifest_sig() {
        let fix = TestFixture::new();
        // Replace the manifest sig with one from a different key.
        let (other_pem, other_tk) = test_key(99);
        let bad_sig = sign_envelope_payload(
            &fix.manifest_bytes,
            MANIFEST_SCHEMA_V1,
            "envelope-manifest",
            &other_pem,
            &other_tk.key_id,
        )
        .unwrap();
        let archive = build_hostile_archive(vec![
            (
                regular_header(fix.manifest_bytes.len() as u64),
                MANIFEST_PATH,
                &fix.manifest_bytes,
            ),
            (
                regular_header(bad_sig.len() as u64),
                MANIFEST_SIG_PATH,
                &bad_sig,
            ),
            (
                regular_header(fix.plan_bytes.len() as u64),
                PLAN_PATH,
                &fix.plan_bytes,
            ),
            (
                regular_header(fix.plan_sig_bytes.len() as u64),
                PLAN_SIG_PATH,
                &fix.plan_sig_bytes,
            ),
            (
                regular_header(fix.blob_content.len() as u64),
                &fix.blob_archive_path(),
                &fix.blob_content,
            ),
        ]);
        let quarantine = TempDir::new().unwrap();
        let err = scan_envelope_to_dir(
            std::io::Cursor::new(&archive),
            &fix.trust_root,
            &ScanLimits::default(),
            quarantine.path(),
        )
        .unwrap_err();
        assert!(
            matches!(err, EnvelopeError::Sign(_)),
            "expected Sign, got: {err}"
        );
    }

    #[test]
    fn scan_rejects_bad_plan_sig() {
        let fix = TestFixture::new();
        // Use a valid manifest but tamper with the plan sig.
        let mut bad_plan_sig = fix.plan_sig_bytes.clone();
        // Flip a byte in the signature.
        if let Some(b) = bad_plan_sig.get_mut(50) {
            *b ^= 0xff;
        }
        // Rebuild manifest to include the tampered plan sig digest/size.
        let (dir_name, _) = staging::digest_dir_name(&fix.blob_digest).unwrap();
        let manifest = EnvelopeManifest {
            schema: MANIFEST_SCHEMA_V1.to_string(),
            plan_id: fix.plan.plan_id.clone(),
            env_id: fix.plan.env_id.clone(),
            created_at: Utc::now(),
            entries: vec![
                ManifestEntry {
                    path: PLAN_PATH.to_string(),
                    digest: format!("sha256:{}", plan::sha256_hex(&fix.plan_bytes)),
                    size: fix.plan_bytes.len() as u64,
                    media_type: "application/json".to_string(),
                    target: None,
                },
                ManifestEntry {
                    path: PLAN_SIG_PATH.to_string(),
                    digest: format!("sha256:{}", plan::sha256_hex(&bad_plan_sig)),
                    size: bad_plan_sig.len() as u64,
                    media_type: "application/json".to_string(),
                    target: None,
                },
                ManifestEntry {
                    path: format!("{BLOBS_PREFIX}{dir_name}"),
                    digest: fix.blob_digest.clone(),
                    size: fix.blob_content.len() as u64,
                    media_type: "application/octet-stream".to_string(),
                    target: None,
                },
            ],
        };
        let manifest_bytes = serde_json::to_vec_pretty(&manifest).unwrap();
        let manifest_sig = sign_envelope_payload(
            &manifest_bytes,
            MANIFEST_SCHEMA_V1,
            "envelope-manifest",
            &fix.priv_pem,
            &fix.key_id,
        )
        .unwrap();
        let archive = build_hostile_archive(vec![
            (
                regular_header(manifest_bytes.len() as u64),
                MANIFEST_PATH,
                &manifest_bytes,
            ),
            (
                regular_header(manifest_sig.len() as u64),
                MANIFEST_SIG_PATH,
                &manifest_sig,
            ),
            (
                regular_header(fix.plan_bytes.len() as u64),
                PLAN_PATH,
                &fix.plan_bytes,
            ),
            (
                regular_header(bad_plan_sig.len() as u64),
                PLAN_SIG_PATH,
                &bad_plan_sig,
            ),
            (
                regular_header(fix.blob_content.len() as u64),
                &fix.blob_archive_path(),
                &fix.blob_content,
            ),
        ]);
        let quarantine = TempDir::new().unwrap();
        let err = scan_envelope_to_dir(
            std::io::Cursor::new(&archive),
            &fix.trust_root,
            &ScanLimits::default(),
            quarantine.path(),
        )
        .unwrap_err();
        assert!(
            matches!(err, EnvelopeError::Plan(_)),
            "expected Plan, got: {err}"
        );
    }

    #[test]
    fn scan_rejects_tampered_blob() {
        let fix = TestFixture::new();
        let mut tampered = fix.blob_content.clone();
        tampered[0] ^= 0xff;
        // Use the valid archive but with tampered blob bytes.
        let archive = build_hostile_archive(vec![
            (
                regular_header(fix.manifest_bytes.len() as u64),
                MANIFEST_PATH,
                &fix.manifest_bytes,
            ),
            (
                regular_header(fix.manifest_sig_bytes.len() as u64),
                MANIFEST_SIG_PATH,
                &fix.manifest_sig_bytes,
            ),
            (
                regular_header(fix.plan_bytes.len() as u64),
                PLAN_PATH,
                &fix.plan_bytes,
            ),
            (
                regular_header(fix.plan_sig_bytes.len() as u64),
                PLAN_SIG_PATH,
                &fix.plan_sig_bytes,
            ),
            (
                regular_header(tampered.len() as u64),
                &fix.blob_archive_path(),
                &tampered,
            ),
        ]);
        let quarantine = TempDir::new().unwrap();
        let err = scan_envelope_to_dir(
            std::io::Cursor::new(&archive),
            &fix.trust_root,
            &ScanLimits::default(),
            quarantine.path(),
        )
        .unwrap_err();
        assert!(
            matches!(err, EnvelopeError::TamperedBlob { .. }),
            "expected TamperedBlob, got: {err}"
        );
    }

    #[test]
    fn scan_rejects_path_traversal() {
        let fix = TestFixture::new();
        let evil_content = b"evil!";
        let mut raw_header = regular_header(evil_content.len() as u64);
        set_header_path_raw(&mut raw_header, "../escape");
        let archive = build_hostile_archive_raw_last(
            vec![
                (
                    regular_header(fix.manifest_bytes.len() as u64),
                    MANIFEST_PATH,
                    &fix.manifest_bytes,
                ),
                (
                    regular_header(fix.manifest_sig_bytes.len() as u64),
                    MANIFEST_SIG_PATH,
                    &fix.manifest_sig_bytes,
                ),
                (
                    regular_header(fix.plan_bytes.len() as u64),
                    PLAN_PATH,
                    &fix.plan_bytes,
                ),
                (
                    regular_header(fix.plan_sig_bytes.len() as u64),
                    PLAN_SIG_PATH,
                    &fix.plan_sig_bytes,
                ),
            ],
            raw_header,
            evil_content,
        );
        let quarantine = TempDir::new().unwrap();
        let err = scan_envelope_to_dir(
            std::io::Cursor::new(&archive),
            &fix.trust_root,
            &ScanLimits::default(),
            quarantine.path(),
        )
        .unwrap_err();
        assert!(
            matches!(err, EnvelopeError::PathTraversal { .. }),
            "expected PathTraversal, got: {err}"
        );
    }

    #[test]
    fn scan_rejects_symlink_entry() {
        let fix = TestFixture::new();
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Symlink);
        h.set_size(0);
        h.set_mode(0o644);
        h.set_mtime(0);
        // Set the link name on the header.
        h.set_link_name("/etc/passwd").unwrap();
        h.set_cksum();
        let archive = build_hostile_archive(vec![
            (
                regular_header(fix.manifest_bytes.len() as u64),
                MANIFEST_PATH,
                &fix.manifest_bytes,
            ),
            (
                regular_header(fix.manifest_sig_bytes.len() as u64),
                MANIFEST_SIG_PATH,
                &fix.manifest_sig_bytes,
            ),
            (
                regular_header(fix.plan_bytes.len() as u64),
                PLAN_PATH,
                &fix.plan_bytes,
            ),
            (
                regular_header(fix.plan_sig_bytes.len() as u64),
                PLAN_SIG_PATH,
                &fix.plan_sig_bytes,
            ),
            (h, &fix.blob_archive_path(), b""),
        ]);
        let quarantine = TempDir::new().unwrap();
        let err = scan_envelope_to_dir(
            std::io::Cursor::new(&archive),
            &fix.trust_root,
            &ScanLimits::default(),
            quarantine.path(),
        )
        .unwrap_err();
        assert!(
            matches!(err, EnvelopeError::ForbiddenEntryType { ref type_name, .. } if type_name == "symlink"),
            "expected ForbiddenEntryType(symlink), got: {err}"
        );
    }

    #[test]
    fn scan_rejects_hardlink_entry() {
        let fix = TestFixture::new();
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::hard_link());
        h.set_size(0);
        h.set_mode(0o644);
        h.set_mtime(0);
        h.set_link_name("plan.json").unwrap();
        h.set_cksum();
        let archive = build_hostile_archive(vec![
            (
                regular_header(fix.manifest_bytes.len() as u64),
                MANIFEST_PATH,
                &fix.manifest_bytes,
            ),
            (
                regular_header(fix.manifest_sig_bytes.len() as u64),
                MANIFEST_SIG_PATH,
                &fix.manifest_sig_bytes,
            ),
            (
                regular_header(fix.plan_bytes.len() as u64),
                PLAN_PATH,
                &fix.plan_bytes,
            ),
            (
                regular_header(fix.plan_sig_bytes.len() as u64),
                PLAN_SIG_PATH,
                &fix.plan_sig_bytes,
            ),
            (h, &fix.blob_archive_path(), b""),
        ]);
        let quarantine = TempDir::new().unwrap();
        let err = scan_envelope_to_dir(
            std::io::Cursor::new(&archive),
            &fix.trust_root,
            &ScanLimits::default(),
            quarantine.path(),
        )
        .unwrap_err();
        assert!(
            matches!(err, EnvelopeError::ForbiddenEntryType { ref type_name, .. } if type_name == "hardlink"),
            "expected ForbiddenEntryType(hardlink), got: {err}"
        );
    }

    #[test]
    fn scan_rejects_device_entry() {
        let fix = TestFixture::new();
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Char);
        h.set_size(0);
        h.set_mode(0o644);
        h.set_mtime(0);
        h.set_device_major(1).unwrap();
        h.set_device_minor(3).unwrap();
        h.set_cksum();
        let archive = build_hostile_archive(vec![
            (
                regular_header(fix.manifest_bytes.len() as u64),
                MANIFEST_PATH,
                &fix.manifest_bytes,
            ),
            (
                regular_header(fix.manifest_sig_bytes.len() as u64),
                MANIFEST_SIG_PATH,
                &fix.manifest_sig_bytes,
            ),
            (
                regular_header(fix.plan_bytes.len() as u64),
                PLAN_PATH,
                &fix.plan_bytes,
            ),
            (
                regular_header(fix.plan_sig_bytes.len() as u64),
                PLAN_SIG_PATH,
                &fix.plan_sig_bytes,
            ),
            (h, &fix.blob_archive_path(), b""),
        ]);
        let quarantine = TempDir::new().unwrap();
        let err = scan_envelope_to_dir(
            std::io::Cursor::new(&archive),
            &fix.trust_root,
            &ScanLimits::default(),
            quarantine.path(),
        )
        .unwrap_err();
        assert!(
            matches!(err, EnvelopeError::ForbiddenEntryType { ref type_name, .. } if type_name == "character device"),
            "expected ForbiddenEntryType(character device), got: {err}"
        );
    }

    #[test]
    fn scan_rejects_fifo_entry() {
        let fix = TestFixture::new();
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Fifo);
        h.set_size(0);
        h.set_mode(0o644);
        h.set_mtime(0);
        h.set_cksum();
        let archive = build_hostile_archive(vec![
            (
                regular_header(fix.manifest_bytes.len() as u64),
                MANIFEST_PATH,
                &fix.manifest_bytes,
            ),
            (
                regular_header(fix.manifest_sig_bytes.len() as u64),
                MANIFEST_SIG_PATH,
                &fix.manifest_sig_bytes,
            ),
            (
                regular_header(fix.plan_bytes.len() as u64),
                PLAN_PATH,
                &fix.plan_bytes,
            ),
            (
                regular_header(fix.plan_sig_bytes.len() as u64),
                PLAN_SIG_PATH,
                &fix.plan_sig_bytes,
            ),
            (h, &fix.blob_archive_path(), b""),
        ]);
        let quarantine = TempDir::new().unwrap();
        let err = scan_envelope_to_dir(
            std::io::Cursor::new(&archive),
            &fix.trust_root,
            &ScanLimits::default(),
            quarantine.path(),
        )
        .unwrap_err();
        assert!(
            matches!(err, EnvelopeError::ForbiddenEntryType { ref type_name, .. } if type_name == "fifo"),
            "expected ForbiddenEntryType(fifo), got: {err}"
        );
    }

    #[test]
    fn scan_rejects_sparse_entry() {
        let fix = TestFixture::new();
        // GNUSparse headers have special fields the tar crate can't produce
        // through the builder, so write the entry raw. The scanner should
        // reject it based on the entry type byte alone.
        let mut h = regular_header(0);
        h.set_entry_type(tar::EntryType::GNUSparse);
        // Write the real_size field that the tar crate expects for sparse
        // entries. It lives at offset 483 in the GNU header (12 bytes, octal).
        // Write the real_size field that the tar crate expects for sparse
        // entries. Access it through the public `realsize` field.
        let gnu = h.as_gnu_mut().unwrap();
        gnu.realsize = *b"00000000000\0";
        set_header_path_raw(&mut h, &fix.blob_archive_path());
        let archive = build_hostile_archive_raw_last(
            vec![
                (
                    regular_header(fix.manifest_bytes.len() as u64),
                    MANIFEST_PATH,
                    &fix.manifest_bytes,
                ),
                (
                    regular_header(fix.manifest_sig_bytes.len() as u64),
                    MANIFEST_SIG_PATH,
                    &fix.manifest_sig_bytes,
                ),
                (
                    regular_header(fix.plan_bytes.len() as u64),
                    PLAN_PATH,
                    &fix.plan_bytes,
                ),
                (
                    regular_header(fix.plan_sig_bytes.len() as u64),
                    PLAN_SIG_PATH,
                    &fix.plan_sig_bytes,
                ),
            ],
            h,
            b"",
        );
        let quarantine = TempDir::new().unwrap();
        let err = scan_envelope_to_dir(
            std::io::Cursor::new(&archive),
            &fix.trust_root,
            &ScanLimits::default(),
            quarantine.path(),
        )
        .unwrap_err();
        assert!(
            matches!(err, EnvelopeError::ForbiddenEntryType { ref type_name, .. } if type_name == "gnu sparse"),
            "expected ForbiddenEntryType(gnu sparse), got: {err}"
        );
    }

    #[test]
    fn scan_rejects_duplicate_path() {
        let fix = TestFixture::new();
        let blob_path = fix.blob_archive_path();
        let archive = build_hostile_archive(vec![
            (
                regular_header(fix.manifest_bytes.len() as u64),
                MANIFEST_PATH,
                &fix.manifest_bytes,
            ),
            (
                regular_header(fix.manifest_sig_bytes.len() as u64),
                MANIFEST_SIG_PATH,
                &fix.manifest_sig_bytes,
            ),
            (
                regular_header(fix.plan_bytes.len() as u64),
                PLAN_PATH,
                &fix.plan_bytes,
            ),
            (
                regular_header(fix.plan_sig_bytes.len() as u64),
                PLAN_SIG_PATH,
                &fix.plan_sig_bytes,
            ),
            (
                regular_header(fix.blob_content.len() as u64),
                &blob_path,
                &fix.blob_content,
            ),
            (
                regular_header(fix.blob_content.len() as u64),
                &blob_path,
                &fix.blob_content,
            ),
        ]);
        let quarantine = TempDir::new().unwrap();
        let err = scan_envelope_to_dir(
            std::io::Cursor::new(&archive),
            &fix.trust_root,
            &ScanLimits::default(),
            quarantine.path(),
        )
        .unwrap_err();
        assert!(
            matches!(err, EnvelopeError::DuplicatePath { .. }),
            "expected DuplicatePath, got: {err}"
        );
    }

    #[test]
    fn scan_rejects_manifest_not_first() {
        let fix = TestFixture::new();
        // Swap manifest and plan positions.
        let archive = build_hostile_archive(vec![
            (
                regular_header(fix.plan_bytes.len() as u64),
                PLAN_PATH,
                &fix.plan_bytes,
            ),
            (
                regular_header(fix.manifest_bytes.len() as u64),
                MANIFEST_PATH,
                &fix.manifest_bytes,
            ),
            (
                regular_header(fix.manifest_sig_bytes.len() as u64),
                MANIFEST_SIG_PATH,
                &fix.manifest_sig_bytes,
            ),
            (
                regular_header(fix.plan_sig_bytes.len() as u64),
                PLAN_SIG_PATH,
                &fix.plan_sig_bytes,
            ),
            (
                regular_header(fix.blob_content.len() as u64),
                &fix.blob_archive_path(),
                &fix.blob_content,
            ),
        ]);
        let quarantine = TempDir::new().unwrap();
        let err = scan_envelope_to_dir(
            std::io::Cursor::new(&archive),
            &fix.trust_root,
            &ScanLimits::default(),
            quarantine.path(),
        )
        .unwrap_err();
        assert!(
            matches!(err, EnvelopeError::WrongEntryOrder { index: 1, .. }),
            "expected WrongEntryOrder at index 1, got: {err}"
        );
    }

    #[test]
    fn scan_rejects_unknown_path() {
        let fix = TestFixture::new();
        let archive = build_hostile_archive(vec![
            (
                regular_header(fix.manifest_bytes.len() as u64),
                MANIFEST_PATH,
                &fix.manifest_bytes,
            ),
            (
                regular_header(fix.manifest_sig_bytes.len() as u64),
                MANIFEST_SIG_PATH,
                &fix.manifest_sig_bytes,
            ),
            (
                regular_header(fix.plan_bytes.len() as u64),
                PLAN_PATH,
                &fix.plan_bytes,
            ),
            (
                regular_header(fix.plan_sig_bytes.len() as u64),
                PLAN_SIG_PATH,
                &fix.plan_sig_bytes,
            ),
            (regular_header(5), "evil.sh", b"evil!"),
        ]);
        let quarantine = TempDir::new().unwrap();
        let err = scan_envelope_to_dir(
            std::io::Cursor::new(&archive),
            &fix.trust_root,
            &ScanLimits::default(),
            quarantine.path(),
        )
        .unwrap_err();
        assert!(
            matches!(err, EnvelopeError::UnknownPath { .. }),
            "expected UnknownPath, got: {err}"
        );
    }

    #[test]
    fn scan_rejects_oversized_manifest() {
        let fix = TestFixture::new();
        let archive = fix.valid_archive();
        let quarantine = TempDir::new().unwrap();
        let limits = ScanLimits {
            max_manifest_bytes: 10, // absurdly small
            ..ScanLimits::default()
        };
        let err = scan_envelope_to_dir(
            std::io::Cursor::new(&archive),
            &fix.trust_root,
            &limits,
            quarantine.path(),
        )
        .unwrap_err();
        assert!(
            matches!(err, EnvelopeError::OversizedManifest { .. }),
            "expected OversizedManifest, got: {err}"
        );
    }

    #[test]
    fn scan_rejects_decompression_bomb() {
        // A large blob of zeros compresses to almost nothing with zstd.
        let bomb_content: Vec<u8> = vec![0u8; 64 * 1024]; // 64 KiB of zeros
        let (priv_pem, tk) = test_key(42);
        let trust = TrustRoot::new(vec![tk.clone()]);
        let plan = test_plan(vec![test_artifact("bomb", &bomb_content)], vec![]);
        let bomb_digest = format!("sha256:{}", plan::sha256_hex(&bomb_content));
        let archive = build_valid_envelope(
            &plan,
            &priv_pem,
            &tk.key_id,
            &trust,
            &[(
                &bomb_digest,
                &bomb_content,
                "application/octet-stream",
                None,
            )],
        );
        let quarantine = TempDir::new().unwrap();
        let limits = ScanLimits {
            max_compression_ratio: 2.0, // very restrictive
            ..ScanLimits::default()
        };
        let err = scan_envelope_to_dir(
            std::io::Cursor::new(&archive),
            &trust,
            &limits,
            quarantine.path(),
        )
        .unwrap_err();
        assert!(
            matches!(err, EnvelopeError::DecompressionBomb { .. }),
            "expected DecompressionBomb, got: {err}"
        );
    }

    #[test]
    fn scan_rejects_oversized_total() {
        let fix = TestFixture::new();
        let archive = fix.valid_archive();
        let quarantine = TempDir::new().unwrap();
        let limits = ScanLimits {
            max_total_bytes: 10, // smaller than even the plan
            ..ScanLimits::default()
        };
        let err = scan_envelope_to_dir(
            std::io::Cursor::new(&archive),
            &fix.trust_root,
            &limits,
            quarantine.path(),
        )
        .unwrap_err();
        // The scanner reads manifest entries (which count toward total
        // internally only for blobs via stream_entry_to_file, but manifest
        // bytes also accumulate); the first entry that pushes past the limit
        // triggers the error. The exact variant depends on which entry
        // pushes past; accept either OversizedTotal or OversizedEntry.
        assert!(
            matches!(
                err,
                EnvelopeError::OversizedTotal { .. } | EnvelopeError::OversizedEntry { .. }
            ),
            "expected OversizedTotal or OversizedEntry, got: {err}"
        );
    }

    #[test]
    fn scan_rejects_too_many_entries() {
        let fix = TestFixture::new();
        let archive = fix.valid_archive();
        let quarantine = TempDir::new().unwrap();
        let limits = ScanLimits {
            max_entry_count: 3, // fewer than the 5 required entries
            ..ScanLimits::default()
        };
        let err = scan_envelope_to_dir(
            std::io::Cursor::new(&archive),
            &fix.trust_root,
            &limits,
            quarantine.path(),
        )
        .unwrap_err();
        assert!(
            matches!(err, EnvelopeError::TooManyEntries { .. }),
            "expected TooManyEntries, got: {err}"
        );
    }

    // -- Receipt tests ----------------------------------------------------

    #[test]
    fn receipt_round_trip() {
        let (priv_pem, tk) = test_key(42);
        let trust = TrustRoot::new(vec![tk.clone()]);
        let digests = vec!["sha256:aabb".to_string(), "sha256:ccdd".to_string()];
        let (receipt_bytes, sig_bytes) =
            build_import_receipt("env-1", digests.clone(), &priv_pem, &tk.key_id).unwrap();
        let receipt = verify_import_receipt(&receipt_bytes, &sig_bytes, &trust).unwrap();
        assert_eq!(receipt.schema, RECEIPT_SCHEMA_V1);
        assert_eq!(receipt.env_id, "env-1");
        assert_eq!(receipt.held_digests, digests);
    }

    #[test]
    fn receipt_rejects_bad_sig() {
        let (priv_pem, tk) = test_key(42);
        let trust = TrustRoot::new(vec![tk.clone()]);
        let (receipt_bytes, mut sig_bytes) =
            build_import_receipt("env-1", vec![], &priv_pem, &tk.key_id).unwrap();
        // Tamper with the sig.
        if let Some(b) = sig_bytes.get_mut(50) {
            *b ^= 0xff;
        }
        let err = verify_import_receipt(&receipt_bytes, &sig_bytes, &trust).unwrap_err();
        assert!(
            matches!(err, EnvelopeError::Sign(_)),
            "expected Sign, got: {err}"
        );
    }
}
