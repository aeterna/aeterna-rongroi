// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! Tests for the request line validator.

use serde_json::{Value, json};

use super::*;

macro_rules! cases {
    ($(($name:literal, $value:expr)),* $(,)?) => {
        vec![$(($name, $value)),*]
    };
}

const SENTINEL_TICKET: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SENTINEL_NONCE: &str = "SENTINELNONCE";
const SENTINEL_ORIGIN: &str = "http://sentinel.invalid:1";

fn valid_value() -> Value {
    let mut policy = json!({
        "profile": "posture",
        "required_collectors": ["posture", "os_image", "prefetch"],
        "require_elevation": true,
        "server_name": "Example City",
        "policy_hash": "0000000000000000",
    });
    refresh_hash(&mut policy);
    json!({
        "binding": {
            "ticket": SENTINEL_TICKET,
            "nonce": SENTINEL_NONCE,
            "server_origin": SENTINEL_ORIGIN,
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

fn refresh_hash(policy: &mut Value) {
    let hash = rongroi_core::canonical::policy_hash(policy).expect("policy hashes");
    policy["policy_hash"] = json!(hash);
}

fn mutate(change: impl FnOnce(&mut Value)) -> Value {
    let mut value = valid_value();
    change(&mut value);
    value
}

fn changed(pointer: &str, replacement: Value) -> Value {
    mutate(|root| {
        *root.pointer_mut(pointer).expect("member exists") = replacement;
    })
}

fn binding(member: &str, replacement: Value) -> Value {
    changed(&format!("/binding/{member}"), replacement)
}

fn policy(member: &str, replacement: Value) -> Value {
    let mut value = changed(&format!("/policy/{member}"), replacement);
    refresh_hash(&mut value["policy"]);
    value
}

fn producer(member: &str, replacement: Value) -> Value {
    changed(&format!("/producer/{member}"), replacement)
}

fn hashed(replacement: Value) -> Value {
    changed("/policy/policy_hash", replacement)
}

fn inserted(pointer: &str, member: &str, value: Value) -> Value {
    mutate(|root| {
        root.pointer_mut(pointer).expect("object exists")[member] = value;
    })
}

fn removed(pointer: &str, member: &str) -> Value {
    mutate(|root| {
        let object = root
            .pointer_mut(pointer)
            .and_then(Value::as_object_mut)
            .expect("object exists");
        let _ = object.remove(member);
    })
}

fn different_hash(value: &Value) -> String {
    let hash = value["policy"]["policy_hash"]
        .as_str()
        .expect("policy hash is text");
    let mut characters: Vec<char> = hash.chars().collect();
    characters[0] = if characters[0] == '0' { '1' } else { '0' };
    characters.into_iter().collect()
}

fn mutation_values() -> Vec<(&'static str, Value)> {
    cases![
        ("unknown top-level member", inserted("", "extra", json!(1))),
        ("missing top-level member", removed("", "producer")),
        (
            "unknown binding member",
            inserted("/binding", "extra", json!(1))
        ),
        (
            "unknown policy member",
            inserted("/policy", "extra", json!(1))
        ),
        (
            "unknown producer member",
            inserted("/producer", "extra", json!(1))
        ),
        (
            "ticket uppercase",
            binding("ticket", json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
        ),
        ("ticket 31 chars", binding("ticket", json!("a".repeat(31)))),
        ("nonce empty", binding("nonce", json!(""))),
        ("nonce 129 chars", binding("nonce", json!("n".repeat(129)))),
        (
            "nonce with space",
            binding("nonce", json!(format!("{SENTINEL_NONCE} ")))
        ),
        (
            "issued_at yesterday",
            binding("issued_at", json!("yesterday"))
        ),
        ("origin ftp", binding("server_origin", json!("ftp://x"))),
        (
            "origin with user information",
            binding("server_origin", json!("http://u:p@h"))
        ),
        (
            "origin with path",
            binding("server_origin", json!("http://h/path"))
        ),
        (
            "origin without host",
            binding("server_origin", json!("http://"))
        ),
        ("profile other", policy("profile", json!("other"))),
        (
            "require_elevation not bool",
            policy("require_elevation", json!("true"))
        ),
        ("server_name empty", policy("server_name", json!(""))),
        (
            "server_name 129 chars",
            policy("server_name", json!("x".repeat(129)))
        ),
        (
            "policy_hash wrong",
            hashed(json!(different_hash(&valid_value())))
        ),
        ("policy_hash uppercase", hashed(json!("AAAAAAAAAAAAAAAA"))),
        ("policy_hash 15 chars", hashed(json!("0123456789abcde"))),
        ("collectors empty", policy("required_collectors", json!([]))),
        (
            "collectors unknown id",
            policy("required_collectors", json!(["x"]))
        ),
        (
            "collectors duplicate id",
            policy("required_collectors", json!(["posture", "posture"]))
        ),
        (
            "collectors 65 ids",
            policy(
                "required_collectors",
                Value::Array(vec![json!("posture"); 65]),
            )
        ),
        (
            "collectors non-string",
            policy("required_collectors", json!(["posture", 1]))
        ),
        (
            "producer name wrong",
            producer("name", json!("rongroi-offline"))
        ),
        (
            "producer mode wrong",
            producer("mode", json!("interactive"))
        ),
        ("producer version empty", producer("version", json!(""))),
        (
            "producer version 33 chars",
            producer("version", json!("v".repeat(33)))
        ),
    ]
}

fn mutation_lines() -> Vec<(&'static str, Vec<u8>)> {
    let mut lines: Vec<(&'static str, Vec<u8>)> = mutation_values()
        .into_iter()
        .map(|(name, value)| (name, line_of(&value)))
        .collect();
    let mut newline = line_of(&valid_value());
    newline.push(b'\n');
    lines.push(("line with newline", newline));
    lines.push(("invalid UTF-8", vec![0xff, 0xfe]));
    lines.push(("JSON array", b"[]".to_vec()));
    lines
}

#[test]
fn valid_request_parses_to_the_core_types() {
    let value = valid_value();
    let request = parse_request(&line_of(&value)).expect("valid request is accepted");
    assert_eq!(
        serde_json::to_value(&request.binding).expect("binding serialises"),
        value["binding"]
    );
    assert_eq!(
        serde_json::to_value(&request.policy).expect("policy serialises"),
        value["policy"]
    );
    assert_eq!(
        serde_json::to_value(&request.producer).expect("producer serialises"),
        value["producer"]
    );
}

#[test]
fn known_collector_ids_are_exactly_the_built_collectors_sorted() {
    let expected: Vec<&str> = concat!(
        "antivirus_product autostart bam defender_exclusion driver_service event_fields ",
        "evtx fivem_dir fivem_servers hid_device install_marker net_config os_image pca ",
        "pci_device posture powershell_text prefetch process ",
        "recorded_files userassist usn windows_start",
    )
    .split(' ')
    .collect();
    assert_eq!(known_collector_ids(), expected);
}

#[test]
fn full_tier_collectors_are_refused_and_a_standard_one_is_accepted() {
    for id in ["powershell_text", "fivem_servers", "recorded_files"] {
        let value = policy("required_collectors", json!([id]));
        assert_eq!(
            parse_request(&line_of(&value)).expect_err("a full-tier collector is refused"),
            RequestError::FullTierCollector,
            "{id} is refused"
        );
    }
    let standard = policy("required_collectors", json!(["posture"]));
    assert!(
        parse_request(&line_of(&standard)).is_ok(),
        "a standard-tier collector is accepted"
    );
}

#[test]
fn invalid_requests_are_refused() {
    for (name, line) in mutation_lines() {
        assert!(parse_request(&line).is_err(), "{name} is refused");
    }
}

#[test]
fn errors_never_echo_input_values() {
    for (name, line) in mutation_lines() {
        let error = parse_request(&line).expect_err("mutation is refused");
        let display = error.to_string();
        let debug = format!("{error:?}");
        for sentinel in [SENTINEL_TICKET, SENTINEL_NONCE, SENTINEL_ORIGIN] {
            assert!(
                !display.contains(sentinel),
                "{name} leaked a value in Display"
            );
            assert!(!debug.contains(sentinel), "{name} leaked a value in Debug");
        }
    }
}

#[test]
fn line_size_limit_is_checked_before_json() {
    let mut at_limit = line_of(&valid_value());
    at_limit.resize(MAX_LINE_BYTES, b' ');
    assert_eq!(at_limit.len(), MAX_LINE_BYTES);
    assert!(parse_request(&at_limit).is_ok());

    let mut too_long = at_limit;
    too_long.push(b' ');
    assert_eq!(
        parse_request(&too_long).unwrap_err(),
        RequestError::LineTooLong
    );
}
