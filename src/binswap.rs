//! Verified on-disk binary swap (binary self-update track).
//!
//! Swaps a verified, staged `gtc` / `greentic-runner` / `greentic-start` binary
//! into the launcher-resolved target path with a `.prev` rollback copy. The
//! binary is treated as just another signed artifact in the update plan, so it
//! flows through the same download + DSSE/digest verification as content
//! artifacts before the swap.
//!
//! ## Safety model
//!
//! * **Digest-first**: if an expected digest is supplied, the new binary is
//!   verified *before* any filesystem mutation — a mismatch fails without
//!   touching the target.
//! * **Atomic commit point**: the rename over the target is the single commit
//!   point. Any failure before the rename leaves the original target intact.
//! * **Rollback**: the original target is copied to a `.prev` sibling before
//!   the swap, enabling [`restore_prev`] recovery.
//! * **Archive guards**: [`unpack_release_binary`] rejects zip-slip / path
//!   traversal entries and enforces a decompression-bomb size cap.
//! * **Container refusal**: [`is_container_environment`] detects container
//!   runtimes so the consumer can skip the swap inside immutable images.

use std::fs;
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};

use sha2::{Digest, Sha256};
use thiserror::Error;

/// Maximum decompressed bytes allowed during archive extraction (512 MiB).
///
/// Guards against decompression bombs in both gzip and zip streams by tracking
/// declared entry sizes and capping actual extracted bytes.
pub const MAX_UNPACK_BYTES: u64 = 512 * 1024 * 1024;

/// Environment variable that overrides container detection (`1`/`true` → yes).
const CONTAINER_ENV_VAR: &str = "GREENTIC_CONTAINER";

// ---------------------------------------------------------------------------
// Target triple
// ---------------------------------------------------------------------------

/// The target triple this binary was compiled for (e.g.
/// `x86_64-unknown-linux-gnu`).
///
/// Set by `build.rs` from Cargo's `TARGET` env at compile time. Used to select
/// the correct architecture-specific binary from a release archive and to
/// fail-closed on a triple mismatch.
pub fn current_target() -> &'static str {
    env!("BINSWAP_TARGET")
}

// ---------------------------------------------------------------------------
// Error taxonomy
// ---------------------------------------------------------------------------

/// Why a binary swap operation failed.
///
/// Fail-closed: a half-applied state is never left behind. Digest verification
/// rejects before any filesystem mutation; the atomic rename is the commit
/// point, so a failure before it leaves the original target intact.
#[derive(Debug, Error)]
pub enum BinSwapError {
    /// The new binary's content digest does not match the expected value.
    #[error("digest mismatch: expected {expected}, got {actual}")]
    DigestMismatch { expected: String, actual: String },

    /// The target binary (or its `.prev` backup) does not exist.
    #[error("target not found: {}", .0.display())]
    TargetNotFound(PathBuf),

    /// The target path or its parent directory is not writable.
    #[error("not writable: {}", path.display())]
    NotWritable {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    /// The temp file and target are on different filesystems. Same-directory
    /// staging prevents this in normal use; the variant exists for fail-closed
    /// reporting if the assumption is violated.
    #[error("cross-device rename (source and target must be on the same filesystem)")]
    CrossDevice {
        #[source]
        source: io::Error,
    },

    /// An archive is malformed, unsupported, or failed to read.
    #[error("archive error: {0}")]
    Archive(String),

    /// An archive entry's path escapes the extraction directory (zip-slip).
    #[error("path traversal in archive entry: {0}")]
    PathTraversal(String),

    /// The archive's target triple does not match [`current_target`].
    #[error("triple mismatch: binary is for `{binary}`, current target is `{current}`")]
    TripleMismatch { binary: String, current: String },

    /// The requested binary was not found in the archive.
    #[error("binary `{name}` not found in archive")]
    BinaryNotFound { name: String },

    /// Extracted (or declared) content exceeds the decompression-bomb cap.
    #[error("decompression bomb: extracted size exceeds {cap} byte cap")]
    DecompressionBomb { cap: u64 },

    /// A generic I/O error with the path that triggered it.
    #[error("io on {}: {source}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

// ---------------------------------------------------------------------------
// Swap options + outcome
// ---------------------------------------------------------------------------

/// Options for [`swap_binary`].
#[derive(Clone, Debug, Default)]
pub struct SwapOptions {
    /// Expected content digest of the new binary in `sha256:<hex>` or bare
    /// `<hex>` form. When set, the new binary is verified BEFORE any
    /// filesystem mutation — a mismatch fails the swap without touching the
    /// target. Hex comparison is case-insensitive, matching
    /// [`crate::catalogue`] semantics.
    pub expected_digest: Option<String>,
}

/// Outcome of a successful [`swap_binary`] call.
#[derive(Clone, Debug)]
pub struct SwapOutcome {
    /// Path to the `.prev` rollback copy of the original target.
    pub prev_path: PathBuf,
}

// ---------------------------------------------------------------------------
// Core swap
// ---------------------------------------------------------------------------

/// Atomically replace the binary at `target` with `new_binary`, keeping a
/// `.prev` rollback copy of the original.
///
/// 1. Read `new_binary` content into memory (single read eliminates TOCTOU
///    between digest check and install).
/// 2. Verify digest (if `opts.expected_digest` is set) against the in-memory
///    bytes — fail BEFORE touching `target` on mismatch.
/// 3. Copy `target` to `<target>.prev` (preserving mode, fsynced).
/// 4. Write the in-memory content to a temp file in the SAME directory as
///    `target` (same FS, no EXDEV), fsync, set 0755 (unix), rename over
///    `target` atomically.
///
/// On unix the rename is safe even when `target` is the running executable
/// (the old inode stays open). On Windows, if `target` is the currently
/// running exe, the rename-away pattern (`self-replace` crate) is used
/// instead.
///
/// Any failure after step 3 leaves the ORIGINAL `target` intact — the rename
/// is the single atomic commit point.
pub fn swap_binary(
    new_binary: &Path,
    target: &Path,
    opts: &SwapOptions,
) -> Result<SwapOutcome, BinSwapError> {
    // Step 0: read new binary content once into memory so the same bytes are
    // both digest-verified and installed (eliminates TOCTOU window).
    let new_bytes = fs::read(new_binary).map_err(|source| BinSwapError::Io {
        path: new_binary.to_path_buf(),
        source,
    })?;

    // Step 1: digest verification (fail-closed before any mutation).
    if let Some(expected) = &opts.expected_digest {
        verify_digest_bytes(&new_bytes, expected)?;
    }

    // Step 2: target must exist.
    if !target.exists() {
        return Err(BinSwapError::TargetNotFound(target.to_path_buf()));
    }

    let parent = target.parent().ok_or_else(|| BinSwapError::Io {
        path: target.to_path_buf(),
        source: io::Error::new(
            io::ErrorKind::InvalidInput,
            "target has no parent directory",
        ),
    })?;

    // Step 3: rollback copy (target -> target.prev, preserving mode).
    let prev_path = prev_path_for(target);
    fs::copy(target, &prev_path).map_err(|source| {
        if source.kind() == io::ErrorKind::PermissionDenied {
            BinSwapError::NotWritable {
                path: prev_path.clone(),
                source,
            }
        } else {
            BinSwapError::Io {
                path: target.to_path_buf(),
                source,
            }
        }
    })?;

    // Fsync the .prev file so it is durable on disk before the rename
    // commits the swap — ensures rollback is safe even on power loss.
    fs::File::open(&prev_path)
        .and_then(|f| f.sync_all())
        .map_err(|source| BinSwapError::Io {
            path: prev_path.clone(),
            source,
        })?;

    // Step 4: atomic install (temp -> fsync -> chmod -> rename).
    atomic_install(&new_bytes, target, parent)?;

    Ok(SwapOutcome { prev_path })
}

/// Roll the `.prev` backup back over `target` (undo a swap).
///
/// `.prev` is always a sibling of `target` (same directory, same filesystem),
/// so the rename is atomic and EXDEV-free.
pub fn restore_prev(target: &Path) -> Result<(), BinSwapError> {
    let prev = prev_path_for(target);
    if !prev.exists() {
        return Err(BinSwapError::TargetNotFound(prev));
    }
    fs::rename(&prev, target).map_err(|source| BinSwapError::Io { path: prev, source })
}

// ---------------------------------------------------------------------------
// Release archive unpack
// ---------------------------------------------------------------------------

/// Extract the inner binary from a release archive to `dest_dir`.
///
/// Supports `.tgz` / `.tar.gz` (tar + gzip) and `.zip` archives in the GitHub
/// release layout: `{name}-v{ver}-{target}/{name}` inside the archive. The
/// entry is selected by exact `binary_name` match on the file-name component,
/// not "first executable."
///
/// Security guards:
/// - **Zip-slip / path traversal**: every entry path is validated — absolute
///   paths, `..` components, and symlink/hardlink entries (tar) are rejected.
/// - **Decompression bomb**: total declared extraction size is capped at
///   [`MAX_UNPACK_BYTES`]; actual extracted bytes are independently capped as
///   defense-in-depth against lying headers.
///
/// The extracted binary gets executable mode (0755 on unix). This function
/// does NOT verify a digest or perform a swap — the caller composes
/// `unpack -> verify -> swap`.
pub fn unpack_release_binary(
    archive: &Path,
    binary_name: &str,
    dest_dir: &Path,
) -> Result<PathBuf, BinSwapError> {
    unpack_capped(archive, binary_name, dest_dir, MAX_UNPACK_BYTES)
}

/// Inner unpack with an explicit cap (testable with small values).
fn unpack_capped(
    archive: &Path,
    binary_name: &str,
    dest_dir: &Path,
    cap: u64,
) -> Result<PathBuf, BinSwapError> {
    let name = archive.to_str().unwrap_or("");
    if name.ends_with(".tgz") || name.ends_with(".tar.gz") {
        unpack_tgz(archive, binary_name, dest_dir, cap)
    } else if name.ends_with(".zip") {
        unpack_zip(archive, binary_name, dest_dir, cap)
    } else {
        Err(BinSwapError::Archive(format!(
            "unsupported archive format: {}",
            archive.display()
        )))
    }
}

/// Unpack a `.tgz` / `.tar.gz` archive.
fn unpack_tgz(
    archive: &Path,
    binary_name: &str,
    dest_dir: &Path,
    cap: u64,
) -> Result<PathBuf, BinSwapError> {
    let file = fs::File::open(archive).map_err(|source| BinSwapError::Io {
        path: archive.to_path_buf(),
        source,
    })?;
    let gz = flate2::read::GzDecoder::new(file);
    let mut ar = tar::Archive::new(gz);

    let dest = dest_dir.join(binary_name);
    let mut total_size: u64 = 0;

    for entry_result in ar
        .entries()
        .map_err(|e| BinSwapError::Archive(e.to_string()))?
    {
        let mut entry = entry_result.map_err(|e| BinSwapError::Archive(e.to_string()))?;
        let raw_path = entry
            .path()
            .map_err(|e| BinSwapError::Archive(e.to_string()))?
            .into_owned();

        // Path-traversal guard (rejects .., absolute, root).
        validate_archive_path(&raw_path)?;

        // Reject symlinks / hardlinks as potential traversal vectors.
        let etype = entry.header().entry_type();
        if etype == tar::EntryType::Symlink || etype == tar::EntryType::Link {
            return Err(BinSwapError::PathTraversal(format!(
                "symlink/hardlink entry in archive: {}",
                raw_path.display()
            )));
        }

        // Size cap (declared size from tar header).
        let entry_size = entry
            .header()
            .size()
            .map_err(|e| BinSwapError::Archive(e.to_string()))?;
        total_size = total_size
            .checked_add(entry_size)
            .ok_or(BinSwapError::DecompressionBomb { cap })?;
        if total_size > cap {
            return Err(BinSwapError::DecompressionBomb { cap });
        }

        // Match the binary by exact file-name component.
        let file_name = raw_path.file_name().and_then(|n| n.to_str());
        if file_name == Some(binary_name) && etype == tar::EntryType::Regular {
            extract_to(&mut entry, &dest, cap)?;
            return Ok(dest);
        }
    }

    Err(BinSwapError::BinaryNotFound {
        name: binary_name.to_string(),
    })
}

/// Unpack a `.zip` archive.
fn unpack_zip(
    archive: &Path,
    binary_name: &str,
    dest_dir: &Path,
    cap: u64,
) -> Result<PathBuf, BinSwapError> {
    let file = fs::File::open(archive).map_err(|source| BinSwapError::Io {
        path: archive.to_path_buf(),
        source,
    })?;
    let mut zip = zip::ZipArchive::new(file).map_err(|e| BinSwapError::Archive(e.to_string()))?;

    let dest = dest_dir.join(binary_name);
    let mut total_size: u64 = 0;

    for i in 0..zip.len() {
        let mut entry = zip
            .by_index(i)
            .map_err(|e| BinSwapError::Archive(e.to_string()))?;
        let raw_path = PathBuf::from(entry.name());

        validate_archive_path(&raw_path)?;

        // Size cap (declared uncompressed size).
        let entry_size = entry.size();
        total_size = total_size
            .checked_add(entry_size)
            .ok_or(BinSwapError::DecompressionBomb { cap })?;
        if total_size > cap {
            return Err(BinSwapError::DecompressionBomb { cap });
        }

        let file_name = raw_path.file_name().and_then(|n| n.to_str());
        if file_name == Some(binary_name) && entry.is_file() {
            extract_to(&mut entry, &dest, cap)?;
            return Ok(dest);
        }
    }

    Err(BinSwapError::BinaryNotFound {
        name: binary_name.to_string(),
    })
}

/// Copy a reader's content to `dest`, capping actual extracted bytes at `cap`
/// (defense-in-depth against lying archive headers). Sets executable mode
/// (0755) on unix.
fn extract_to(reader: &mut impl Read, dest: &Path, cap: u64) -> Result<(), BinSwapError> {
    let mut out = fs::File::create(dest).map_err(|source| BinSwapError::Io {
        path: dest.to_path_buf(),
        source,
    })?;

    // Read at most cap+1 bytes: if we get more than cap, the entry lied about
    // its size (or the cap was lowered for the extraction step).
    let mut limited = reader.take(cap.saturating_add(1));
    let written = io::copy(&mut limited, &mut out).map_err(|source| BinSwapError::Io {
        path: dest.to_path_buf(),
        source,
    })?;
    if written > cap {
        let _ = fs::remove_file(dest);
        return Err(BinSwapError::DecompressionBomb { cap });
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dest, fs::Permissions::from_mode(0o755)).map_err(|source| {
            BinSwapError::Io {
                path: dest.to_path_buf(),
                source,
            }
        })?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Container detection
// ---------------------------------------------------------------------------

/// Detect whether the process is running inside a container (Docker, Podman,
/// Kubernetes, etc.).
///
/// Detection order:
/// 1. `GREENTIC_CONTAINER` env var (`1` / `true` / `yes` forces yes).
/// 2. `/.dockerenv` exists (Docker).
/// 3. `/run/.containerenv` exists (Podman).
/// 4. `/proc/1/cgroup` mentions `docker`, `kubepods`, or `containerd` (Linux).
///
/// This is detection only — the refusal **policy** lives in the consumer (the
/// gtc or greentic-start binary-update verb), which decides whether to skip
/// the swap inside a container image.
pub fn is_container_environment() -> bool {
    // 1. Explicit override (case-insensitive: "True", "YES", "1" all match).
    if let Ok(val) = std::env::var(CONTAINER_ENV_VAR) {
        let lc = val.to_ascii_lowercase();
        return matches!(lc.as_str(), "1" | "true" | "yes");
    }

    // 2. Docker sentinel file.
    if Path::new("/.dockerenv").exists() {
        return true;
    }

    // 3. Podman sentinel file.
    if Path::new("/run/.containerenv").exists() {
        return true;
    }

    // 4. Cgroup markers (Linux only — other unixes lack /proc/1/cgroup).
    #[cfg(target_os = "linux")]
    if let Ok(cgroup) = fs::read_to_string("/proc/1/cgroup")
        && (cgroup.contains("docker")
            || cgroup.contains("kubepods")
            || cgroup.contains("containerd"))
    {
        return true;
    }

    false
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

/// Append `.prev` to the target path to form the rollback sibling path.
fn prev_path_for(target: &Path) -> PathBuf {
    let mut name = target.as_os_str().to_owned();
    name.push(".prev");
    PathBuf::from(name)
}

/// Verify that in-memory `bytes` match the expected digest. Tolerates the
/// `sha256:` prefix and hex case, matching [`crate::catalogue`] semantics.
fn verify_digest_bytes(bytes: &[u8], expected: &str) -> Result<(), BinSwapError> {
    let actual_hex = hex::encode(Sha256::digest(bytes));
    let expected_hex = expected
        .trim()
        .strip_prefix("sha256:")
        .unwrap_or(expected.trim())
        .to_ascii_lowercase();

    if actual_hex != expected_hex {
        Err(BinSwapError::DigestMismatch {
            expected: expected.to_string(),
            actual: format!("sha256:{actual_hex}"),
        })
    } else {
        Ok(())
    }
}

/// Validate an archive entry path against zip-slip / path-traversal attacks.
/// Rejects absolute paths, `..` components, and root-dir components.
fn validate_archive_path(path: &Path) -> Result<(), BinSwapError> {
    if path.is_absolute() {
        return Err(BinSwapError::PathTraversal(format!(
            "absolute path in archive: {}",
            path.display()
        )));
    }
    for component in path.components() {
        match component {
            Component::ParentDir => {
                return Err(BinSwapError::PathTraversal(format!(
                    "parent-dir traversal (..) in archive: {}",
                    path.display()
                )));
            }
            Component::RootDir => {
                return Err(BinSwapError::PathTraversal(format!(
                    "root-dir in archive path: {}",
                    path.display()
                )));
            }
            _ => {}
        }
    }
    Ok(())
}

/// Write `bytes` to `target` atomically: temp file in `parent` -> write ->
/// flush -> fsync -> chmod 0755 (unix) -> rename over `target` -> fsync
/// parent.
fn atomic_install(bytes: &[u8], target: &Path, parent: &Path) -> Result<(), BinSwapError> {
    let mut tmp = tempfile::NamedTempFile::new_in(parent).map_err(|source| {
        if source.kind() == io::ErrorKind::PermissionDenied {
            BinSwapError::NotWritable {
                path: parent.to_path_buf(),
                source,
            }
        } else {
            BinSwapError::Io {
                path: parent.to_path_buf(),
                source,
            }
        }
    })?;

    tmp.write_all(bytes)
        .and_then(|_| tmp.flush())
        .and_then(|_| tmp.as_file().sync_all())
        .map_err(|source| BinSwapError::Io {
            path: tmp.path().to_path_buf(),
            source,
        })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tmp.as_file()
            .set_permissions(fs::Permissions::from_mode(0o755))
            .map_err(|source| BinSwapError::Io {
                path: tmp.path().to_path_buf(),
                source,
            })?;
    }

    // Windows: if target is the currently running exe, use self-replace
    // (rename-away pattern) since a running exe cannot be renamed-over.
    #[cfg(windows)]
    if is_current_exe(target) {
        return self_replace_install(tmp, target);
    }

    // Normal atomic rename (safe on unix even for a running exe — the old
    // inode stays open until every fd is closed).
    tmp.persist(target).map_err(|e| {
        let source = e.error;
        if is_cross_device(&source) {
            BinSwapError::CrossDevice { source }
        } else if source.kind() == io::ErrorKind::PermissionDenied {
            BinSwapError::NotWritable {
                path: target.to_path_buf(),
                source,
            }
        } else {
            BinSwapError::Io {
                path: target.to_path_buf(),
                source,
            }
        }
    })?;

    fsync_parent(parent)?;
    Ok(())
}

/// Check if an IO error indicates a cross-device rename.
fn is_cross_device(err: &io::Error) -> bool {
    // EXDEV = 18 on all major unix platforms; ERROR_NOT_SAME_DEVICE = 17 on
    // Windows.
    #[cfg(unix)]
    const CROSS_DEVICE_CODE: i32 = 18;
    #[cfg(windows)]
    const CROSS_DEVICE_CODE: i32 = 17;
    #[cfg(not(any(unix, windows)))]
    const CROSS_DEVICE_CODE: i32 = -1; // never matches

    err.raw_os_error() == Some(CROSS_DEVICE_CODE)
}

#[cfg(unix)]
fn fsync_parent(parent: &Path) -> Result<(), BinSwapError> {
    let dir = fs::File::open(parent).map_err(|source| BinSwapError::Io {
        path: parent.to_path_buf(),
        source,
    })?;
    dir.sync_all().map_err(|source| BinSwapError::Io {
        path: parent.to_path_buf(),
        source,
    })
}

#[cfg(not(unix))]
fn fsync_parent(_parent: &Path) -> Result<(), BinSwapError> {
    Ok(())
}

/// Check whether `path` points at the currently running executable.
#[cfg(windows)]
fn is_current_exe(path: &Path) -> bool {
    let Ok(current) = std::env::current_exe() else {
        return false;
    };
    let target = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let current = current.canonicalize().unwrap_or(current);
    target == current
}

/// Use the `self-replace` crate to replace the currently running Windows exe.
#[cfg(windows)]
fn self_replace_install(tmp: tempfile::NamedTempFile, target: &Path) -> Result<(), BinSwapError> {
    let tmp_path = tmp.into_temp_path();
    self_replace::self_replace(&tmp_path).map_err(|source| BinSwapError::Io {
        path: target.to_path_buf(),
        source,
    })?;
    // TempPath drop is a no-op since self_replace already moved the file.
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a fake "target" binary in `dir`.
    fn setup_target(dir: &Path, content: &[u8]) -> PathBuf {
        let target = dir.join("my-binary");
        fs::write(&target, content).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&target, fs::Permissions::from_mode(0o755)).unwrap();
        }
        target
    }

    /// Create a "new binary" file in `dir`.
    fn setup_new(dir: &Path, content: &[u8]) -> PathBuf {
        let path = dir.join("new-binary");
        fs::write(&path, content).unwrap();
        path
    }

    fn sha256_digest(bytes: &[u8]) -> String {
        format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
    }

    // --- Swap tests ---

    #[test]
    fn swap_installs_new_and_creates_prev() {
        let dir = tempfile::tempdir().unwrap();
        let old_content = b"old-binary-content";
        let new_content = b"new-binary-content";
        let target = setup_target(dir.path(), old_content);
        let new_bin = setup_new(dir.path(), new_content);

        let outcome = swap_binary(&new_bin, &target, &SwapOptions::default()).unwrap();

        assert_eq!(fs::read(&target).unwrap(), new_content);
        assert_eq!(fs::read(&outcome.prev_path).unwrap(), old_content);
        assert_eq!(outcome.prev_path, prev_path_for(&target));
    }

    #[test]
    fn digest_mismatch_refuses_before_touching_target() {
        let dir = tempfile::tempdir().unwrap();
        let old_content = b"original";
        let new_content = b"replacement";
        let target = setup_target(dir.path(), old_content);
        let new_bin = setup_new(dir.path(), new_content);

        let opts = SwapOptions {
            expected_digest: Some(
                "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                    .to_string(),
            ),
        };
        let err = swap_binary(&new_bin, &target, &opts).unwrap_err();
        assert!(matches!(err, BinSwapError::DigestMismatch { .. }));

        // Target untouched, no .prev created.
        assert_eq!(fs::read(&target).unwrap(), old_content);
        assert!(!prev_path_for(&target).exists());
    }

    #[test]
    fn digest_match_with_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let target = setup_target(dir.path(), b"old");
        let new_content = b"new";
        let new_bin = setup_new(dir.path(), new_content);

        let opts = SwapOptions {
            expected_digest: Some(sha256_digest(new_content)),
        };
        swap_binary(&new_bin, &target, &opts).unwrap();
        assert_eq!(fs::read(&target).unwrap(), new_content);
    }

    #[test]
    fn digest_match_without_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let target = setup_target(dir.path(), b"old");
        let new_content = b"new";
        let new_bin = setup_new(dir.path(), new_content);

        let bare_hex = hex::encode(Sha256::digest(new_content));
        let opts = SwapOptions {
            expected_digest: Some(bare_hex),
        };
        swap_binary(&new_bin, &target, &opts).unwrap();
        assert_eq!(fs::read(&target).unwrap(), new_content);
    }

    #[test]
    fn digest_match_is_case_insensitive() {
        let dir = tempfile::tempdir().unwrap();
        let target = setup_target(dir.path(), b"old");
        let new_content = b"new";
        let new_bin = setup_new(dir.path(), new_content);

        let upper = hex::encode(Sha256::digest(new_content)).to_uppercase();
        let opts = SwapOptions {
            expected_digest: Some(format!("sha256:{upper}")),
        };
        swap_binary(&new_bin, &target, &opts).unwrap();
        assert_eq!(fs::read(&target).unwrap(), new_content);
    }

    #[test]
    fn restore_prev_rolls_back() {
        let dir = tempfile::tempdir().unwrap();
        let old_content = b"original-binary";
        let new_content = b"updated-binary";
        let target = setup_target(dir.path(), old_content);
        let new_bin = setup_new(dir.path(), new_content);

        swap_binary(&new_bin, &target, &SwapOptions::default()).unwrap();
        assert_eq!(fs::read(&target).unwrap(), new_content);

        restore_prev(&target).unwrap();
        assert_eq!(fs::read(&target).unwrap(), old_content);
        // .prev is consumed by the rename.
        assert!(!prev_path_for(&target).exists());
    }

    #[test]
    #[cfg(unix)]
    fn permission_denied_fails_closed() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let old_content = b"protected-binary";
        let new_content = b"attacker-binary";
        let target = setup_target(dir.path(), old_content);
        let new_bin = setup_new(dir.path(), new_content);

        // Make the directory non-writable so the .prev copy fails.
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o555)).unwrap();

        let result = swap_binary(&new_bin, &target, &SwapOptions::default());
        assert!(result.is_err());

        // Restore permissions for cleanup + verification.
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();

        // Target untouched.
        assert_eq!(fs::read(&target).unwrap(), old_content);
    }

    #[test]
    fn same_dir_staging_no_exdev() {
        // The temp file is created in the same directory as the target.
        // If it tried a cross-device rename, the swap would fail.
        let dir = tempfile::tempdir().unwrap();
        let target = setup_target(dir.path(), b"original");
        let new_bin = setup_new(dir.path(), b"replacement");

        swap_binary(&new_bin, &target, &SwapOptions::default()).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"replacement");
    }

    #[test]
    #[cfg(unix)]
    fn mode_is_0755_after_swap() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let target = setup_target(dir.path(), b"old");
        // Give target a non-0755 mode to prove the swap resets it.
        fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).unwrap();

        let new_bin = setup_new(dir.path(), b"new");
        swap_binary(&new_bin, &target, &SwapOptions::default()).unwrap();

        let mode = fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o755);
    }

    #[test]
    fn target_not_found_errors() {
        let dir = tempfile::tempdir().unwrap();
        let new_bin = setup_new(dir.path(), b"new");
        let target = dir.path().join("nonexistent");

        let err = swap_binary(&new_bin, &target, &SwapOptions::default()).unwrap_err();
        assert!(matches!(err, BinSwapError::TargetNotFound(_)));
    }

    #[test]
    fn restore_prev_missing_errors() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("no-prev");
        fs::write(&target, b"binary").unwrap();

        let err = restore_prev(&target).unwrap_err();
        assert!(matches!(err, BinSwapError::TargetNotFound(_)));
    }

    // --- Archive helpers ---

    /// Build a `.tgz` archive with one regular-file entry.
    fn build_tgz(dest: &Path, inner_path: &str, content: &[u8]) {
        let file = fs::File::create(dest).unwrap();
        let enc = flate2::write::GzEncoder::new(file, flate2::Compression::fast());
        let mut ar = tar::Builder::new(enc);

        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o755);
        header.set_entry_type(tar::EntryType::Regular);

        // Write the path directly into the GNU header's name field. This
        // bypasses tar's own `..` validation (which would reject our
        // zip-slip test fixtures). Safe: test-only helper.
        let gnu = header.as_gnu_mut().unwrap();
        let path_bytes = inner_path.as_bytes();
        let len = path_bytes.len().min(gnu.name.len());
        gnu.name[..len].copy_from_slice(&path_bytes[..len]);
        for b in &mut gnu.name[len..] {
            *b = 0;
        }

        header.set_cksum();
        ar.append(&header, content).unwrap();
        ar.into_inner().unwrap().finish().unwrap();
    }

    /// Build a `.zip` archive with one regular-file entry.
    fn build_zip(dest: &Path, inner_path: &str, content: &[u8]) {
        let file = fs::File::create(dest).unwrap();
        let mut zw = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        zw.start_file(inner_path, options).unwrap();
        zw.write_all(content).unwrap();
        zw.finish().unwrap();
    }

    // --- Unpack tests ---

    #[test]
    fn unpack_tgz_extracts_binary() {
        let dir = tempfile::tempdir().unwrap();
        let content = b"#!/bin/sh\necho hello";
        let archive = dir.path().join("test.tgz");
        build_tgz(&archive, "gtc-v1.0.0-x86_64/gtc", content);

        let out_dir = dir.path().join("out");
        fs::create_dir(&out_dir).unwrap();
        let result = unpack_release_binary(&archive, "gtc", &out_dir).unwrap();

        assert_eq!(result, out_dir.join("gtc"));
        assert_eq!(fs::read(&result).unwrap(), content);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&result).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o755);
        }
    }

    #[test]
    fn unpack_zip_extracts_binary() {
        let dir = tempfile::tempdir().unwrap();
        let content = b"MZ...windows-binary";
        let archive = dir.path().join("test.zip");
        build_zip(&archive, "runner-v2.0.0-x86_64/runner", content);

        let out_dir = dir.path().join("out");
        fs::create_dir(&out_dir).unwrap();
        let result = unpack_release_binary(&archive, "runner", &out_dir).unwrap();

        assert_eq!(result, out_dir.join("runner"));
        assert_eq!(fs::read(&result).unwrap(), content);
    }

    #[test]
    fn unpack_binary_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("test.tgz");
        build_tgz(&archive, "gtc-v1.0.0/gtc", b"binary");

        let out_dir = dir.path().join("out");
        fs::create_dir(&out_dir).unwrap();
        let err = unpack_release_binary(&archive, "nonexistent", &out_dir).unwrap_err();
        assert!(matches!(err, BinSwapError::BinaryNotFound { .. }));
    }

    #[test]
    fn zip_slip_tgz_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("evil.tgz");
        build_tgz(&archive, "../../etc/passwd", b"root:x:0:0");

        let out_dir = dir.path().join("out");
        fs::create_dir(&out_dir).unwrap();
        let err = unpack_release_binary(&archive, "passwd", &out_dir).unwrap_err();
        assert!(matches!(err, BinSwapError::PathTraversal(_)));
    }

    #[test]
    fn zip_slip_zip_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("evil.zip");
        build_zip(&archive, "../../../tmp/evil", b"evil-content");

        let out_dir = dir.path().join("out");
        fs::create_dir(&out_dir).unwrap();
        let err = unpack_release_binary(&archive, "evil", &out_dir).unwrap_err();
        assert!(matches!(err, BinSwapError::PathTraversal(_)));
    }

    #[test]
    fn over_cap_tgz_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let content = b"small-content";
        let archive = dir.path().join("big.tgz");
        build_tgz(&archive, "dir/binary", content);

        let out_dir = dir.path().join("out");
        fs::create_dir(&out_dir).unwrap();
        // Use a cap smaller than the content to trigger the bomb guard.
        let err = unpack_capped(&archive, "binary", &out_dir, 5).unwrap_err();
        assert!(matches!(err, BinSwapError::DecompressionBomb { .. }));
    }

    #[test]
    fn over_cap_zip_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let content = b"some-binary-content-that-is-big";
        let archive = dir.path().join("big.zip");
        build_zip(&archive, "dir/binary", content);

        let out_dir = dir.path().join("out");
        fs::create_dir(&out_dir).unwrap();
        let err = unpack_capped(&archive, "binary", &out_dir, 10).unwrap_err();
        assert!(matches!(err, BinSwapError::DecompressionBomb { .. }));
    }

    // --- Misc tests ---

    #[test]
    fn current_target_is_nonempty() {
        let t = current_target();
        assert!(!t.is_empty());
        assert!(t.contains('-'), "target `{t}` should look like a triple");
    }

    #[test]
    fn container_detection_does_not_panic() {
        // Exercise the detection function without asserting a specific result
        // (depends on the host environment).
        let _ = is_container_environment();
    }

    #[test]
    fn validate_path_rejects_parent_dir() {
        let err = validate_archive_path(Path::new("foo/../../bar")).unwrap_err();
        assert!(matches!(err, BinSwapError::PathTraversal(_)));
    }

    #[test]
    fn validate_path_accepts_normal() {
        validate_archive_path(Path::new("dir/subdir/file")).unwrap();
    }

    #[test]
    fn validate_path_rejects_absolute() {
        let err = validate_archive_path(Path::new("/etc/passwd")).unwrap_err();
        assert!(matches!(err, BinSwapError::PathTraversal(_)));
    }

    #[test]
    fn unsupported_archive_format() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("test.rar");
        fs::write(&archive, b"not-an-archive").unwrap();

        let out_dir = dir.path().join("out");
        fs::create_dir(&out_dir).unwrap();
        let err = unpack_release_binary(&archive, "binary", &out_dir).unwrap_err();
        assert!(matches!(err, BinSwapError::Archive(_)));
    }
}
