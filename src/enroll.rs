//! Client-side certificate enrollment against the Greentic update Cert-CA.
//!
//! Enrollment is the bootstrap step that runs *before* the client holds a
//! client certificate, so it cannot use the mTLS channel itself. The caller
//! supplies the transport ([`reqwest::Client`]); this module generates a fresh
//! key pair + CSR (via [`rcgen`]), POSTs it to the CA's `/v1/enroll` endpoint,
//! and returns the signed certificate alongside the locally-generated key.
//!
//! The returned key/cert material is meant to be persisted by the caller (e.g.
//! into the Greentic secrets backend) and then fed into
//! [`crate::tls::build_mtls_client`] for subsequent update-channel calls. This
//! crate deliberately does **not** depend on `greentic-secrets`: persistence
//! and pre-expiry rotation are caller concerns, not part of the transport core.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Request body for `POST /v1/enroll`. Mirrors the update server's wire
/// contract (`greentic-updates-server::wire::EnrollRequest`) byte-for-byte.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnrollRequest {
    /// Tenant identifier (charset `[a-zA-Z0-9._-]`, non-empty, ≤128; enforced
    /// server-side — a violation returns [`EnrollError::Status`]).
    pub tenant: String,
    /// Environment identifier (same constraints as `tenant`).
    pub env: String,
    /// PEM-encoded PKCS#10 certificate signing request.
    pub csr_pem: String,
}

/// Response body from `POST /v1/enroll`. Mirrors the update server's wire
/// contract (`greentic-updates-server::wire::EnrollResponse`) byte-for-byte.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollResponse {
    /// PEM of the signed client certificate.
    pub cert_pem: String,
    /// PEM of the issuing CA certificate (trust anchor for the update server).
    pub ca_pem: String,
    /// Issued certificate serial (lowercase hex, no separators — see
    /// [`crate::tls::serial_to_hex`]).
    pub serial: String,
    /// `notAfter` as RFC 3339.
    pub not_after: String,
}

/// Outcome of a successful enrollment: the CA's response plus the private key
/// generated locally for the CSR. The private key never leaves this process
/// except via the value the caller chooses to persist.
#[derive(Clone)]
pub struct Enrollment {
    /// PKCS#8 PEM of the freshly generated client private key.
    pub client_key_pem: String,
    /// PEM of the signed client certificate.
    pub client_cert_pem: String,
    /// PEM of the issuing CA certificate (trust anchor for the update server).
    pub ca_pem: String,
    /// Issued certificate serial (lowercase hex, no separators).
    pub serial: String,
    /// `notAfter` as RFC 3339.
    pub not_after: String,
}

/// `Debug` is manually implemented to redact certificate and key material.
impl std::fmt::Debug for Enrollment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Enrollment")
            .field("client_key_pem", &"<REDACTED>")
            .field("client_cert_pem", &"<redacted>")
            .field("ca_pem", &"<redacted>")
            .field("serial", &self.serial)
            .field("not_after", &self.not_after)
            .finish()
    }
}

/// Why enrollment failed.
#[derive(Debug, Error)]
pub enum EnrollError {
    /// A supplied identifier was empty.
    #[error("empty {0} identifier")]
    EmptyIdentity(&'static str),
    /// Key-pair generation or CSR serialization failed.
    #[error("failed to generate key pair / CSR: {0}")]
    Csr(String),
    /// The HTTP request could not be sent (connection, TLS, timeout).
    #[error("enrollment request failed: {0}")]
    Http(String),
    /// The CA returned a non-success status.
    #[error("enrollment rejected: HTTP {status}: {body}")]
    Status { status: u16, body: String },
    /// The response body could not be decoded as an [`EnrollResponse`].
    #[error("invalid enrollment response: {0}")]
    Decode(String),
}

/// Generate a fresh key pair and a PEM-encoded PKCS#10 CSR for `{tenant}/{env}`.
///
/// Returns `(client_key_pem, csr_pem)`. The CSR subject CN is set to
/// `{tenant}/{env}` for readability, but the CA discards the CSR subject/SAN/EKU
/// and derives the leaf identity from the request fields — only the public key
/// and the CSR self-signature are used server-side.
pub fn generate_keypair_and_csr(tenant: &str, env: &str) -> Result<(String, String), EnrollError> {
    let key_pair = rcgen::KeyPair::generate().map_err(|e| EnrollError::Csr(e.to_string()))?;
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new())
        .map_err(|e| EnrollError::Csr(e.to_string()))?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, format!("{tenant}/{env}"));
    let csr = params
        .serialize_request(&key_pair)
        .map_err(|e| EnrollError::Csr(e.to_string()))?;
    let csr_pem = csr.pem().map_err(|e| EnrollError::Csr(e.to_string()))?;
    let key_pem = key_pair.serialize_pem();
    Ok((key_pem, csr_pem))
}

/// Enroll with the Cert-CA: generate a key pair + CSR, POST to
/// `{base_url}/v1/enroll`, and return the signed certificate + private key.
///
/// `client` supplies the transport. Because enrollment happens *before* the
/// client holds a certificate, `client` is typically a plain server-auth client
/// (optionally pinned to a known bootstrap CA) rather than an mTLS one. The
/// caller is responsible for persisting [`Enrollment`] and, later, for building
/// the mTLS client from it via [`crate::tls::build_mtls_client`].
pub async fn enroll(
    client: &reqwest::Client,
    base_url: &str,
    tenant: &str,
    env: &str,
) -> Result<Enrollment, EnrollError> {
    if tenant.is_empty() {
        return Err(EnrollError::EmptyIdentity("tenant"));
    }
    if env.is_empty() {
        return Err(EnrollError::EmptyIdentity("env"));
    }
    let (client_key_pem, csr_pem) = generate_keypair_and_csr(tenant, env)?;
    let req = EnrollRequest {
        tenant: tenant.to_string(),
        env: env.to_string(),
        csr_pem,
    };
    let url = format!("{}/v1/enroll", base_url.trim_end_matches('/'));
    let resp = client
        .post(url)
        .json(&req)
        .send()
        .await
        .map_err(|e| EnrollError::Http(e.to_string()))?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(EnrollError::Status {
            status: status.as_u16(),
            body,
        });
    }
    let body: EnrollResponse = resp
        .json()
        .await
        .map_err(|e| EnrollError::Decode(e.to_string()))?;
    Ok(Enrollment {
        client_key_pem,
        client_cert_pem: body.cert_pem,
        ca_pem: body.ca_pem,
        serial: body.serial,
        not_after: body.not_after,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_csr_is_verifiable_by_the_server_api() {
        // The update server verifies enrollment CSRs with
        // `rcgen::CertificateSigningRequestParams::from_pem`, which checks the
        // PKCS#10 self-signature. Parse our CSR through the same API to prove
        // compatibility without a running server.
        let (key_pem, csr_pem) = generate_keypair_and_csr("acme", "prod").unwrap();
        assert!(key_pem.contains("PRIVATE KEY"), "key PEM: {key_pem}");
        assert!(
            csr_pem.contains("CERTIFICATE REQUEST"),
            "csr PEM: {csr_pem}"
        );
        let parsed = rcgen::CertificateSigningRequestParams::from_pem(&csr_pem)
            .expect("server-side CSR verification (from_pem) must accept our CSR");
        // The CA ignores the subject, but a well-formed CN aids debugging.
        let cn = parsed
            .params
            .distinguished_name
            .get(&rcgen::DnType::CommonName);
        assert!(matches!(cn, Some(rcgen::DnValue::Utf8String(s)) if s == "acme/prod"));
    }

    #[test]
    fn each_enrollment_generates_a_distinct_key() {
        let (k1, c1) = generate_keypair_and_csr("acme", "prod").unwrap();
        let (k2, c2) = generate_keypair_and_csr("acme", "prod").unwrap();
        assert_ne!(k1, k2, "each enrollment must mint a fresh private key");
        assert_ne!(c1, c2, "distinct keys must produce distinct CSRs");
    }

    #[test]
    fn enroll_response_deserializes_from_server_shape() {
        // Exact JSON the server emits (greentic-updates-server::wire).
        let json = r#"{
            "cert_pem": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
            "ca_pem": "-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----\n",
            "serial": "00000000000003e8",
            "not_after": "2027-07-01T00:00:00Z"
        }"#;
        let resp: EnrollResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.serial, "00000000000003e8");
        assert_eq!(resp.not_after, "2027-07-01T00:00:00Z");
        // Round-trips back to the same value.
        let back: EnrollResponse =
            serde_json::from_str(&serde_json::to_string(&resp).unwrap()).unwrap();
        assert_eq!(resp, back);
    }

    #[test]
    fn enrollment_debug_redacts_key_material() {
        let e = Enrollment {
            client_key_pem: "SECRET-KEY".to_string(),
            client_cert_pem: "SECRET-CERT".to_string(),
            ca_pem: "SECRET-CA".to_string(),
            serial: "00000000000003e8".to_string(),
            not_after: "2027-07-01T00:00:00Z".to_string(),
        };
        let dbg = format!("{e:?}");
        assert!(
            !dbg.contains("SECRET"),
            "Debug output must not contain key/cert material: {dbg}"
        );
        assert!(dbg.contains("<REDACTED>"));
        // Non-sensitive fields remain visible for diagnostics.
        assert!(dbg.contains("00000000000003e8"));
    }

    #[tokio::test]
    async fn enroll_rejects_empty_identity_before_network() {
        // An unreachable base_url proves no request is attempted.
        let client = reqwest::Client::new();
        let err = enroll(&client, "http://127.0.0.1:1", "", "prod")
            .await
            .unwrap_err();
        assert!(matches!(err, EnrollError::EmptyIdentity("tenant")));
        let err = enroll(&client, "http://127.0.0.1:1", "acme", "")
            .await
            .unwrap_err();
        assert!(matches!(err, EnrollError::EmptyIdentity("env")));
    }
}
