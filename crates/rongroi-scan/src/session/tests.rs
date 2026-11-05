// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! Tests for the sidecar session, with an in-memory pipe.

use rongroi_collectors::scan::{self, ScanContext};
use rongroi_core::bundle::Bundle;
use rongroi_host::{FixtureHost, Host};
use serde_json::{Value, json};

use super::*;

const TICKET: &str = "0123456789abcdef0123456789abcdef";
const NONCE: &str = "SENTINELNONCE";
const ORIGIN: &str = "http://203.0.113.10:30130";

struct MemoryTransport {
    input: Vec<u8>,
    written: Vec<Vec<u8>>,
    fail_write: bool,
}

impl MemoryTransport {
    fn new(input: Vec<u8>) -> Self {
        Self {
            input,
            written: Vec::new(),
            fail_write: false,
        }
    }

    fn failing_write(input: Vec<u8>) -> Self {
        Self {
            fail_write: true,
            ..Self::new(input)
        }
    }
}

impl Transport for MemoryTransport {
    fn read_line(&mut self, max: usize) -> Result<Vec<u8>, TransportError> {
        let Some(end) = self.input.iter().position(|byte| *byte == b'\n') else {
            return Err(TransportError::NoNewline);
        };
        if end > max {
            return Err(TransportError::LineTooLong);
        }
        let line = self.input[..end].to_vec();
        self.input.drain(..=end).for_each(drop);
        Ok(line)
    }

    fn write_all(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
        if self.fail_write {
            return Err(TransportError::Io(std::io::Error::from(
                std::io::ErrorKind::BrokenPipe,
            )));
        }
        self.written.push(bytes.to_vec());
        Ok(())
    }
}

fn request_value(collectors: &[&str]) -> Value {
    let mut policy = json!({
        "profile": "custom",
        "required_collectors": collectors,
        "require_elevation": false,
        "server_name": "Example City",
        "policy_hash": "0000000000000000",
    });
    let hash = rongroi_core::canonical::policy_hash(&policy).expect("policy hashes");
    policy["policy_hash"] = json!(hash);
    json!({
        "binding": {
            "ticket": TICKET,
            "nonce": NONCE,
            "server_origin": ORIGIN,
            "issued_at": "2026-10-31T14:30:00Z",
            "expires_at": "2026-10-31T14:35:00Z",
        },
        "policy": policy,
        "producer": { "name": "rongroi-connect", "version": "0.1.0", "mode": "single-shot" },
    })
}

fn line_of(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).expect("request serialises")
}

fn with_newline(mut line: Vec<u8>) -> Vec<u8> {
    line.push(b'\n');
    line
}

fn at() -> jiff::Timestamp {
    "2026-11-05T12:00:00Z".parse().expect("timestamp")
}

fn host() -> FixtureHost {
    FixtureHost::from_yaml_str("platform: windows\n", "inline").expect("fixture host")
}

fn prefetch_host() -> FixtureHost {
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/hosts/prefetch-files-present");
    FixtureHost::load(&dir).expect("prefetch fixture loads")
}

fn run_transport(mut transport: MemoryTransport, host: &dyn Host) -> (ExitKind, MemoryTransport) {
    let scan_host = |bundle: &Bundle, context: ScanContext, ids: &[&str]| {
        scan::run_selected(host, bundle, context, ids)
    };
    let exit = run(&mut transport, scan_host, at);
    (exit, transport)
}

fn run_input(input: Vec<u8>, host: &dyn Host) -> (ExitKind, MemoryTransport) {
    run_transport(MemoryTransport::new(input), host)
}

fn run_request(request: &Value, host: &dyn Host) -> (ExitKind, MemoryTransport) {
    run_input(with_newline(line_of(request)), host)
}

fn record_of(transport: &MemoryTransport) -> Value {
    let bytes = &transport.written[0];
    serde_json::from_slice(&bytes[..bytes.len() - 1]).expect("record is JSON")
}

#[test]
fn a_valid_request_writes_one_schema_2_record() {
    let request = request_value(&["posture"]);
    let (exit, transport) = run_request(&request, &host());
    assert_eq!(exit, ExitKind::Success);
    assert_eq!(exit.code(), 0);
    assert_eq!(transport.written.len(), 1);
    let bytes = &transport.written[0];
    assert_eq!(bytes.last(), Some(&b'\n'));
    assert!(!bytes[..bytes.len() - 1].contains(&b'\n'));

    let record = record_of(&transport);
    assert_eq!(record["schema"], json!(2));
    assert_eq!(record["binding"], request["binding"]);
    assert_eq!(record["policy"], request["policy"]);
    assert_eq!(record["producer"], request["producer"]);
    assert!(record.get("case_code").is_none());
    let hash = record["visual_hash"].as_str().expect("hash is text");
    assert_eq!(hash.len(), 16);
    assert!(
        hash.bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    );
    let recomputed = rongroi_core::canonical::visual_hash(&record).expect("record hashes");
    assert_eq!(hash, recomputed);
}

#[test]
fn a_binding_with_only_ticket_and_nonce_keeps_only_those_two() {
    let mut request = request_value(&["posture"]);
    request["binding"] = json!({ "ticket": TICKET, "nonce": NONCE });
    let (exit, transport) = run_request(&request, &host());
    assert_eq!(exit, ExitKind::Success);
    let record = record_of(&transport);
    assert_eq!(
        record["binding"],
        json!({ "ticket": TICKET, "nonce": NONCE })
    );
    assert_eq!(record["binding"].as_object().expect("binding").len(), 2);
}

#[test]
fn an_invalid_request_writes_nothing() {
    for input in [
        with_newline(b"{}".to_vec()),
        with_newline(vec![0xff, 0xfe]),
        b"{}".to_vec(),
    ] {
        let (exit, transport) = run_input(input, &host());
        assert_eq!(exit, ExitKind::Failed);
        assert_eq!(exit.code(), 1);
        assert!(transport.written.is_empty());
    }
}

#[test]
fn a_line_over_the_limit_fails_without_writing() {
    let mut line = vec![b' '; MAX_LINE_BYTES + 1];
    line.push(b'\n');
    let (exit, transport) = run_input(line, &host());
    assert_eq!(exit, ExitKind::Failed);
    assert!(transport.written.is_empty());
}

#[test]
fn a_failed_write_is_failed() {
    let request = request_value(&["posture"]);
    let transport = MemoryTransport::failing_write(with_newline(line_of(&request)));
    let (exit, transport) = run_transport(transport, &host());
    assert_eq!(exit, ExitKind::Failed);
    assert!(transport.written.is_empty());
}

#[test]
fn the_ticket_appears_only_at_binding_ticket() {
    let (_, transport) = run_request(&request_value(&["posture"]), &host());
    let bytes = &transport.written[0];
    let text = std::str::from_utf8(bytes).expect("record is UTF-8");
    assert_eq!(text.matches(TICKET).count(), 1);

    let record = record_of(&transport);
    assert_eq!(record["binding"]["ticket"], TICKET);
}

#[test]
fn collectors_outside_the_policy_are_not_called() {
    let fixture = prefetch_host();
    let (_, posture_only) = run_request(&request_value(&["posture"]), &fixture);
    let posture_record = record_of(&posture_only);
    let (_, with_prefetch) = run_request(&request_value(&["posture", "prefetch"]), &fixture);
    let prefetch_record = record_of(&with_prefetch);

    let evidence = posture_record["view"]["evidence"]
        .as_array()
        .expect("evidence list");
    assert!(
        evidence
            .iter()
            .all(|item| item["collector"].as_str() != Some("prefetch"))
    );
    let hidden = |record: &Value| {
        record["view"]["hidden"]["unmatched"]
            .as_u64()
            .expect("unmatched count")
    };
    assert!(hidden(&prefetch_record) > hidden(&posture_record));
}
