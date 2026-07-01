//! Client-certificate (mTLS) support and X.509 preflight checks.
//!
//! Builds a [`reqwest::Client`] configured for mutual TLS: a custom CA root
//! certificate and a client identity (cert + key). Before the TLS handshake
//! the caller can run a lightweight preflight that rejects expired or
//! CRL-revoked client certificates without reaching the network.
//!
//! ## Distributor-client injection (follow-up PR)
//!
//! The built [`reqwest::Client`] is intended to be passed into
//! `HttpDistributorClient::with_client(reqwest::Client)` so the update
//! channel uses mTLS for all distributor calls. That wiring lives in the
//! caller (greentic-deployer), not here.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// PEM material needed to build an mTLS-capable HTTP client.
///
/// `Debug` is manually implemented to redact certificate and key material.
#[derive(Clone)]
pub struct MtlsConfig {
    /// PEM-encoded CA certificate (trust anchor for the server).
    pub ca_pem: String,
    /// PEM-encoded client certificate.
    pub client_cert_pem: String,
    /// PEM-encoded client private key (PKCS#8).
    pub client_key_pem: String,
}

impl std::fmt::Debug for MtlsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MtlsConfig")
            .field("ca_pem", &"<redacted>")
            .field("client_cert_pem", &"<redacted>")
            .field("client_key_pem", &"<REDACTED>")
            .finish()
    }
}

/// Extracted identity fields from a parsed X.509 certificate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertInfo {
    /// Lowercase hex serial with no separators (e.g. `"00000000000003e8"`).
    pub serial_hex: String,
    /// `notBefore` as a Unix epoch (seconds).
    pub not_before_epoch: i64,
    /// `notAfter` as a Unix epoch (seconds).
    pub not_after_epoch: i64,
}

/// Compact CRL replacement: a list of revoked serial hex strings plus an
/// issuance timestamp. Distributed as JSON by the update server.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrlLite {
    /// Revoked certificate serial numbers (lowercase hex, no separators).
    pub revoked: Vec<String>,
    /// When this CRL-lite snapshot was issued (RFC 3339).
    pub issued_at: String,
}

/// Why an mTLS operation failed.
#[derive(Debug, Error)]
pub enum TlsError {
    #[error("bad PEM input: {0}")]
    BadPem(String),
    #[error("invalid X.509 certificate: {0}")]
    InvalidCert(String),
    #[error("client certificate not yet valid")]
    NotYetValid,
    #[error("client certificate expired")]
    Expired,
    #[error("client certificate revoked (serial {serial})")]
    Revoked { serial: String },
    #[error("failed to build mTLS client: {0}")]
    Build(String),
}

/// Encode raw serial bytes as lowercase hex with no separators.
///
/// This is the canonical wire format for certificate serial numbers across the
/// update protocol. Both client and server MUST use this function (or an
/// identical implementation) — **not** the colon-separated display format
/// emitted by `rcgen::SerialNumber::Display`.
pub fn serial_to_hex(raw: &[u8]) -> String {
    hex::encode(raw)
}

/// Parse identity fields (`serial`, `notBefore`, `notAfter`) from a
/// PEM-encoded X.509 certificate.
pub fn parse_cert_info(cert_pem: &str) -> Result<CertInfo, TlsError> {
    let (_, pem) = x509_parser::pem::parse_x509_pem(cert_pem.as_bytes())
        .map_err(|e| TlsError::BadPem(format!("{e}")))?;
    let (_, x509) = x509_parser::parse_x509_certificate(&pem.contents)
        .map_err(|e| TlsError::InvalidCert(format!("{e}")))?;
    let serial_hex = serial_to_hex(x509.tbs_certificate.raw_serial());
    let validity = x509.tbs_certificate.validity();
    let not_before_epoch = validity.not_before.timestamp();
    let not_after_epoch = validity.not_after.timestamp();
    Ok(CertInfo {
        serial_hex,
        not_before_epoch,
        not_after_epoch,
    })
}

/// Returns `true` if `serial_hex` appears in the CRL-lite revocation list.
pub fn is_revoked(serial_hex: &str, crl: &CrlLite) -> bool {
    crl.revoked.iter().any(|s| s == serial_hex)
}

/// Pre-flight check: parse the certificate, reject if expired or revoked.
///
/// `now_epoch` is the current Unix timestamp (seconds). Pass `None` for `crl`
/// when no CRL-lite snapshot is available (revocation check is skipped).
pub fn preflight_cert(
    cert_pem: &str,
    now_epoch: i64,
    crl: Option<&CrlLite>,
) -> Result<CertInfo, TlsError> {
    let info = parse_cert_info(cert_pem)?;
    // Reject not-yet-valid certs (notBefore in the future).
    if now_epoch < info.not_before_epoch {
        return Err(TlsError::NotYetValid);
    }
    // Intentionally strict: reject at exact notAfter (1-second conservative
    // vs RFC 5280 inclusive endpoint). Fail-closed for an update channel.
    if now_epoch >= info.not_after_epoch {
        return Err(TlsError::Expired);
    }
    if let Some(crl) = crl
        && is_revoked(&info.serial_hex, crl)
    {
        return Err(TlsError::Revoked {
            serial: info.serial_hex.clone(),
        });
    }
    Ok(info)
}

/// Build a [`reqwest::Client`] configured for mutual TLS.
///
/// The client trusts only the provided CA certificate and presents the client
/// identity (cert + key) on every connection. Uses the rustls backend.
pub fn build_mtls_client(cfg: &MtlsConfig) -> Result<reqwest::Client, TlsError> {
    let ca = reqwest::Certificate::from_pem(cfg.ca_pem.as_bytes())
        .map_err(|e| TlsError::BadPem(format!("CA cert: {e}")))?;
    // Ensure a newline separates END CERTIFICATE / BEGIN PRIVATE KEY markers,
    // even if the cert PEM lacks a trailing newline.
    let identity_pem = if cfg.client_cert_pem.ends_with('\n') {
        format!("{}{}", cfg.client_cert_pem, cfg.client_key_pem)
    } else {
        format!("{}\n{}", cfg.client_cert_pem, cfg.client_key_pem)
    };
    let identity = reqwest::Identity::from_pem(identity_pem.as_bytes())
        .map_err(|e| TlsError::BadPem(format!("client identity: {e}")))?;
    reqwest::Client::builder()
        .use_rustls_tls()
        .tls_certs_only([ca])
        .identity(identity)
        .build()
        .map_err(|e| TlsError::Build(format!("{e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use ed25519_dalek::pkcs8::EncodePrivateKey;
    use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose,
        IsCa, KeyPair, KeyUsagePurpose, SerialNumber,
    };
    use time::OffsetDateTime;

    // ── Test fixture helper ──────────────────────────────────────────

    /// Deterministic dev-CA fixture built from seeded Ed25519 keys.
    struct DevCaFixture {
        ca_cert_pem: String,
        #[allow(dead_code)]
        ca_key_pem: String,
        client_cert_pem: String,
        client_key_pem: String,
        client_serial_hex: String,
        client_not_after_epoch: i64,
    }

    const DEV_CA_SEED: [u8; 32] = [0xCA; 32];
    const DEV_CLIENT_SEED: [u8; 32] = [0xC1; 32];

    fn ed25519_keypair_pem(seed: [u8; 32]) -> (String, KeyPair) {
        let sk = SigningKey::from_bytes(&seed);
        let pkcs8_pem = sk.to_pkcs8_pem(LineEnding::LF).unwrap().to_string();
        let kp = KeyPair::from_pem(&pkcs8_pem).unwrap();
        (pkcs8_pem, kp)
    }

    fn build_dev_ca_fixture(
        ca_seed: [u8; 32],
        client_seed: [u8; 32],
        _tenant: &str,
        _env: &str,
        client_serial: u64,
    ) -> DevCaFixture {
        let (ca_key_pem, ca_kp) = ed25519_keypair_pem(ca_seed);

        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "dev-update-ca");
        ca_params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::CrlSign,
        ];
        let ca_issuer = CertifiedIssuer::self_signed(ca_params, ca_kp).unwrap();
        let ca_cert_pem = ca_issuer.pem();

        let (_client_key_pem_raw, client_kp) = ed25519_keypair_pem(client_seed);

        let mut client_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        client_params
            .distinguished_name
            .push(DnType::CommonName, "dev-update-client");
        client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        client_params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        client_params.serial_number = Some(SerialNumber::from(client_serial));
        // Set not_after to 1 year from now for valid tests.
        let not_after = OffsetDateTime::now_utc() + time::Duration::days(365);
        client_params.not_after = not_after;

        let client_cert = client_params.signed_by(&client_kp, &*ca_issuer).unwrap();
        let client_cert_pem = client_cert.pem();
        let client_key_pem = client_kp.serialize_pem();

        // Derive serial hex from the generated cert (what x509-parser sees),
        // not from the raw u64 bytes — DER strips leading zero bytes.
        let info = parse_cert_info(&client_cert_pem).unwrap();
        let client_not_after_epoch = not_after.unix_timestamp();

        DevCaFixture {
            ca_cert_pem,
            ca_key_pem,
            client_cert_pem,
            client_key_pem,
            client_serial_hex: info.serial_hex,
            client_not_after_epoch,
        }
    }

    fn build_expired_fixture(client_serial: u64) -> DevCaFixture {
        let (ca_key_pem, ca_kp) = ed25519_keypair_pem(DEV_CA_SEED);

        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "dev-update-ca");
        ca_params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::CrlSign,
        ];
        let ca_issuer = CertifiedIssuer::self_signed(ca_params, ca_kp).unwrap();

        let (_client_key_pem_raw, client_kp) = ed25519_keypair_pem(DEV_CLIENT_SEED);

        let mut client_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        client_params
            .distinguished_name
            .push(DnType::CommonName, "dev-expired-client");
        client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        client_params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        client_params.serial_number = Some(SerialNumber::from(client_serial));
        // Already expired: not_after in the past.
        let not_after = OffsetDateTime::now_utc() - time::Duration::days(1);
        let not_before = OffsetDateTime::now_utc() - time::Duration::days(365);
        client_params.not_after = not_after;
        client_params.not_before = not_before;

        let client_cert = client_params.signed_by(&client_kp, &*ca_issuer).unwrap();
        let client_cert_pem = client_cert.pem();
        let client_key_pem = client_kp.serialize_pem();

        let info = parse_cert_info(&client_cert_pem).unwrap();
        let client_not_after_epoch = not_after.unix_timestamp();

        DevCaFixture {
            ca_cert_pem: ca_issuer.pem(),
            ca_key_pem,
            client_cert_pem,
            client_key_pem,
            client_serial_hex: info.serial_hex,
            client_not_after_epoch,
        }
    }

    // ── Unit tests ───────────────────────────────────────────────────

    #[test]
    fn serial_to_hex_golden_value() {
        // u64 1000 as big-endian bytes = 8 bytes.
        let sn = 1000_u64.to_be_bytes();
        assert_eq!(serial_to_hex(&sn), "00000000000003e8");
    }

    #[test]
    fn serial_to_hex_variable_length() {
        // A 3-byte serial (no padding to 8 bytes — variable length).
        assert_eq!(serial_to_hex(&[0x01, 0x02, 0x03]), "010203");
    }

    #[test]
    fn parse_cert_info_golden() {
        let fx = build_dev_ca_fixture(DEV_CA_SEED, DEV_CLIENT_SEED, "acme", "prod", 1000);
        let info = parse_cert_info(&fx.client_cert_pem).unwrap();
        assert_eq!(info.serial_hex, fx.client_serial_hex);
        // Allow 2-second tolerance for test runtime.
        assert!((info.not_after_epoch - fx.client_not_after_epoch).abs() <= 2);
    }

    #[test]
    fn parse_cert_info_bad_pem() {
        let err = parse_cert_info("not a pem").unwrap_err();
        assert!(matches!(err, TlsError::BadPem(_)));
    }

    #[test]
    fn preflight_passes_valid_cert() {
        let fx = build_dev_ca_fixture(DEV_CA_SEED, DEV_CLIENT_SEED, "acme", "prod", 2000);
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let info = preflight_cert(&fx.client_cert_pem, now, None).unwrap();
        assert_eq!(info.serial_hex, fx.client_serial_hex);
    }

    #[test]
    fn preflight_rejects_expired() {
        let fx = build_expired_fixture(3000);
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let err = preflight_cert(&fx.client_cert_pem, now, None).unwrap_err();
        assert!(matches!(err, TlsError::Expired));
    }

    #[test]
    fn preflight_rejects_revoked() {
        let fx = build_dev_ca_fixture(DEV_CA_SEED, DEV_CLIENT_SEED, "acme", "prod", 4000);
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let crl = CrlLite {
            revoked: vec![fx.client_serial_hex.clone()],
            issued_at: "2026-07-01T12:00:00Z".to_string(),
        };
        let err = preflight_cert(&fx.client_cert_pem, now, Some(&crl)).unwrap_err();
        assert!(matches!(err, TlsError::Revoked { .. }));
    }

    #[test]
    fn preflight_passes_when_serial_not_in_crl() {
        let fx = build_dev_ca_fixture(DEV_CA_SEED, DEV_CLIENT_SEED, "acme", "prod", 5000);
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let crl = CrlLite {
            revoked: vec!["deadbeef".to_string()],
            issued_at: "2026-07-01T12:00:00Z".to_string(),
        };
        let info = preflight_cert(&fx.client_cert_pem, now, Some(&crl)).unwrap();
        assert_eq!(info.serial_hex, fx.client_serial_hex);
    }

    #[test]
    fn is_revoked_hit_and_miss() {
        let crl = CrlLite {
            revoked: vec![
                "00000000000003e8".to_string(),
                "00000000000003e9".to_string(),
            ],
            issued_at: "2026-07-01T12:00:00Z".to_string(),
        };
        assert!(is_revoked("00000000000003e8", &crl));
        assert!(!is_revoked("00000000000003ea", &crl));
    }

    #[test]
    fn crl_lite_json_roundtrip() {
        let crl = CrlLite {
            revoked: vec!["aabb".to_string(), "ccdd".to_string()],
            issued_at: "2026-07-01T00:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&crl).unwrap();
        let back: CrlLite = serde_json::from_str(&json).unwrap();
        assert_eq!(crl, back);
    }

    #[test]
    fn build_mtls_client_valid() {
        let fx = build_dev_ca_fixture(DEV_CA_SEED, DEV_CLIENT_SEED, "acme", "prod", 6000);
        let cfg = MtlsConfig {
            ca_pem: fx.ca_cert_pem,
            client_cert_pem: fx.client_cert_pem,
            client_key_pem: fx.client_key_pem,
        };
        let client = build_mtls_client(&cfg);
        assert!(client.is_ok(), "build_mtls_client failed: {client:?}");
    }

    #[test]
    fn build_mtls_client_bad_identity_pem() {
        let fx = build_dev_ca_fixture(DEV_CA_SEED, DEV_CLIENT_SEED, "acme", "prod", 7000);
        let cfg = MtlsConfig {
            ca_pem: fx.ca_cert_pem,
            client_cert_pem: "not a cert".to_string(),
            client_key_pem: "not a key".to_string(),
        };
        let err = build_mtls_client(&cfg).unwrap_err();
        assert!(matches!(err, TlsError::BadPem(_)));
    }

    #[test]
    fn build_mtls_client_missing_key_in_identity() {
        // A valid cert PEM but no private key — Identity::from_pem should fail.
        let fx = build_dev_ca_fixture(DEV_CA_SEED, DEV_CLIENT_SEED, "acme", "prod", 8000);
        let cfg = MtlsConfig {
            ca_pem: fx.ca_cert_pem.clone(),
            client_cert_pem: fx.client_cert_pem,
            client_key_pem: String::new(),
        };
        let err = build_mtls_client(&cfg).unwrap_err();
        assert!(matches!(err, TlsError::BadPem(_)));
    }

    #[test]
    fn mtls_config_debug_redacts_key_material() {
        let cfg = MtlsConfig {
            ca_pem: "SECRET-CA".to_string(),
            client_cert_pem: "SECRET-CERT".to_string(),
            client_key_pem: "SECRET-KEY".to_string(),
        };
        let dbg = format!("{cfg:?}");
        assert!(
            !dbg.contains("SECRET"),
            "Debug output must not contain key material: {dbg}"
        );
        assert!(dbg.contains("<redacted>"));
        assert!(dbg.contains("<REDACTED>"));
    }

    #[test]
    fn preflight_rejects_at_exact_not_after_boundary() {
        // When now == not_after, the cert is treated as expired (fail-closed).
        let fx = build_dev_ca_fixture(DEV_CA_SEED, DEV_CLIENT_SEED, "acme", "prod", 9000);
        let err = preflight_cert(&fx.client_cert_pem, fx.client_not_after_epoch, None).unwrap_err();
        assert!(matches!(err, TlsError::Expired));
    }

    #[test]
    fn preflight_passes_one_second_before_not_after() {
        let fx = build_dev_ca_fixture(DEV_CA_SEED, DEV_CLIENT_SEED, "acme", "prod", 9001);
        let info =
            preflight_cert(&fx.client_cert_pem, fx.client_not_after_epoch - 1, None).unwrap();
        assert_eq!(info.serial_hex, fx.client_serial_hex);
    }

    #[test]
    fn preflight_rejects_not_yet_valid() {
        // Build a cert whose notBefore is 1 day in the future.
        let (_ca_key_pem, ca_kp) = ed25519_keypair_pem(DEV_CA_SEED);

        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "dev-update-ca");
        ca_params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::CrlSign,
        ];
        let ca_issuer = CertifiedIssuer::self_signed(ca_params, ca_kp).unwrap();

        let (_client_key_pem_raw, client_kp) = ed25519_keypair_pem(DEV_CLIENT_SEED);

        let mut client_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        client_params
            .distinguished_name
            .push(DnType::CommonName, "dev-future-client");
        client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        client_params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        client_params.serial_number = Some(SerialNumber::from(9002_u64));
        let not_before = OffsetDateTime::now_utc() + time::Duration::days(1);
        let not_after = OffsetDateTime::now_utc() + time::Duration::days(365);
        client_params.not_before = not_before;
        client_params.not_after = not_after;

        let client_cert = client_params.signed_by(&client_kp, &*ca_issuer).unwrap();
        let client_cert_pem = client_cert.pem();

        let now = OffsetDateTime::now_utc().unix_timestamp();
        let err = preflight_cert(&client_cert_pem, now, None).unwrap_err();
        assert!(matches!(err, TlsError::NotYetValid));
    }
}
