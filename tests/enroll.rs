#![cfg(feature = "enroll")]

//! Integration tests for the enrollment client against a mock Cert-CA.
//!
//! Mirrors the `greentic-distributor-client` httpmock house style, including the
//! bind-failure skip guard for sandboxed CI environments.

use greentic_update::enroll::{EnrollError, EnrollResponse, enroll};
use httpmock::prelude::*;
use std::panic;

fn start_server() -> Option<MockServer> {
    panic::catch_unwind(MockServer::start).ok()
}

fn sample_response() -> EnrollResponse {
    EnrollResponse {
        cert_pem: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n".into(),
        ca_pem: "-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----\n".into(),
        serial: "00000000000003e8".into(),
        not_after: "2027-07-01T00:00:00Z".into(),
    }
}

#[tokio::test]
async fn enroll_happy_path_posts_csr_and_returns_signed_material() {
    let Some(server) = start_server() else {
        eprintln!("skipping: unable to bind mock server in this environment");
        return;
    };
    // The CSR is random per run, so match on stable request substrings rather
    // than an exact body: the request must carry tenant, env, and a real CSR.
    let mock = server.mock(|when, then| {
        when.method(POST)
            .path("/v1/enroll")
            .body_includes("\"tenant\":\"acme\"")
            .body_includes("\"env\":\"prod\"")
            .body_includes("CERTIFICATE REQUEST");
        then.status(200)
            .json_body(serde_json::to_value(sample_response()).unwrap());
    });

    let client = reqwest::Client::new();
    let out = enroll(&client, &server.base_url(), "acme", "prod")
        .await
        .unwrap();
    mock.assert();

    // Server response fields threaded through.
    assert_eq!(out.serial, "00000000000003e8");
    assert_eq!(out.not_after, "2027-07-01T00:00:00Z");
    assert!(out.client_cert_pem.contains("BEGIN CERTIFICATE"));
    assert!(out.ca_pem.contains("BEGIN CERTIFICATE"));
    // The locally-generated private key is returned but was never sent upstream.
    assert!(out.client_key_pem.contains("PRIVATE KEY"));
}

#[tokio::test]
async fn enroll_trims_trailing_slash_on_base_url() {
    let Some(server) = start_server() else {
        eprintln!("skipping: unable to bind mock server in this environment");
        return;
    };
    let mock = server.mock(|when, then| {
        when.method(POST).path("/v1/enroll");
        then.status(200)
            .json_body(serde_json::to_value(sample_response()).unwrap());
    });

    let base = format!("{}/", server.base_url()); // trailing slash
    let client = reqwest::Client::new();
    let out = enroll(&client, &base, "acme", "prod").await.unwrap();
    mock.assert(); // reached /v1/enroll, not /v1/enroll//... or //v1/enroll
    assert_eq!(out.serial, "00000000000003e8");
}

#[tokio::test]
async fn enroll_maps_rejection_status() {
    let Some(server) = start_server() else {
        eprintln!("skipping: unable to bind mock server in this environment");
        return;
    };
    let mock = server.mock(|when, then| {
        when.method(POST).path("/v1/enroll");
        then.status(400).body("invalid tenant identifier");
    });

    let client = reqwest::Client::new();
    let err = enroll(&client, &server.base_url(), "acme", "prod")
        .await
        .unwrap_err();
    mock.assert();
    assert!(
        matches!(err, EnrollError::Status { status: 400, ref body } if body.contains("invalid tenant")),
        "unexpected error: {err:?}"
    );
}

#[tokio::test]
async fn enroll_maps_undecodable_response() {
    let Some(server) = start_server() else {
        eprintln!("skipping: unable to bind mock server in this environment");
        return;
    };
    let mock = server.mock(|when, then| {
        when.method(POST).path("/v1/enroll");
        then.status(200).body("not-json");
    });

    let client = reqwest::Client::new();
    let err = enroll(&client, &server.base_url(), "acme", "prod")
        .await
        .unwrap_err();
    mock.assert();
    assert!(matches!(err, EnrollError::Decode(_)), "unexpected: {err:?}");
}
