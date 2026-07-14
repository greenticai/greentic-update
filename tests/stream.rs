#![cfg(feature = "stream")]

//! Integration tests for the SSE stream transport against a mock server.

use greentic_update::stream::{StreamError, UPDATE_EVENT_SCHEMA_V1, connect_and_read};
use httpmock::prelude::*;
use std::ops::ControlFlow;
use std::panic;

fn start_server() -> Option<MockServer> {
    panic::catch_unwind(MockServer::start).ok()
}

fn plan_event_json(env_id: &str, seq: u64, sha: &str) -> String {
    serde_json::to_string(&serde_json::json!({
        "schema": UPDATE_EVENT_SCHEMA_V1,
        "env_id": env_id,
        "sequence": seq,
        "plan_sha256": sha,
    }))
    .unwrap()
}

fn sse_body(events: &[(Option<&str>, &str, &str)]) -> String {
    let mut body = String::new();
    for (id, event, data) in events {
        if let Some(id) = id {
            body.push_str(&format!("id: {id}\n"));
        }
        body.push_str(&format!("event: {event}\n"));
        body.push_str(&format!("data: {data}\n"));
        body.push('\n');
    }
    body
}

#[test]
fn two_plan_events_delivered_in_order() {
    let Some(server) = start_server() else {
        eprintln!("skipping: unable to bind mock server in this environment");
        return;
    };

    let ev1 = plan_event_json("prod", 1, "aaa");
    let ev2 = plan_event_json("staging", 2, "bbb");
    let body = sse_body(&[(Some("1"), "plan", &ev1), (Some("2"), "plan", &ev2)]);

    let mock = server.mock(|when, then| {
        when.method(GET).path("/v1/events");
        then.status(200)
            .header("Content-Type", "text/event-stream")
            .body(body);
    });

    let client = greentic_update::stream::build_stream_client().unwrap();
    let url = format!("{}/v1/events", server.base_url());
    let mut received = Vec::new();
    connect_and_read(&client, &url, None, |ev| {
        received.push(ev);
        ControlFlow::Continue(())
    })
    .unwrap();
    mock.assert();

    assert_eq!(received.len(), 2);
    assert_eq!(received[0].env_id, "prod");
    assert_eq!(received[0].sequence, 1);
    assert_eq!(received[1].env_id, "staging");
    assert_eq!(received[1].sequence, 2);
}

#[test]
fn last_event_id_header_sent() {
    let Some(server) = start_server() else {
        eprintln!("skipping: unable to bind mock server in this environment");
        return;
    };

    let ev = plan_event_json("prod", 7, "ccc");
    let body = sse_body(&[(Some("7"), "plan", &ev)]);

    let mock = server.mock(|when, then| {
        when.method(GET)
            .path("/v1/events")
            .header("Last-Event-ID", "6");
        then.status(200)
            .header("Content-Type", "text/event-stream")
            .body(body);
    });

    let client = greentic_update::stream::build_stream_client().unwrap();
    let url = format!("{}/v1/events", server.base_url());
    let mut received = Vec::new();
    connect_and_read(&client, &url, Some(6), |ev| {
        received.push(ev);
        ControlFlow::Continue(())
    })
    .unwrap();
    mock.assert();

    assert_eq!(received.len(), 1);
    assert_eq!(received[0].sequence, 7);
}

#[test]
fn non_2xx_returns_stream_error() {
    let Some(server) = start_server() else {
        eprintln!("skipping: unable to bind mock server in this environment");
        return;
    };

    let mock = server.mock(|when, then| {
        when.method(GET).path("/v1/events");
        then.status(503).body("service unavailable");
    });

    let client = greentic_update::stream::build_stream_client().unwrap();
    let url = format!("{}/v1/events", server.base_url());
    let err = connect_and_read(&client, &url, None, |_| ControlFlow::Continue(())).unwrap_err();
    mock.assert();

    assert!(
        matches!(err, StreamError::Status { status: 503 }),
        "unexpected error: {err:?}"
    );
}
