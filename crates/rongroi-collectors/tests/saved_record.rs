// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! ADR 0073: a saved record holds the SS view and every device, and its bytes are what its digest is of.
//! ADR 0089 §2: every record is schema 2, with a producer, and a `visual_hash` over the bytes without it.

#![allow(clippy::unwrap_used)]

use std::path::PathBuf;

use rongroi_collectors::scan::{self, ScanContext};
use rongroi_core::bundle::Bundle;
use rongroi_core::engine::SelfIdentity;
use rongroi_core::model::{Mode, ScanTier};
use rongroi_core::provenance::Provenance;
use rongroi_core::view::{self, Binding, Policy, Profile, SavedTimes, SsOptions};
use rongroi_host::FixtureHost;

fn report(host: &str) -> rongroi_core::model::Report {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/hosts")
        .join(host);
    let host = FixtureHost::load(&dir).unwrap();
    let context = ScanContext {
        provenance: Provenance::from_parts(None, "0.0.0-test", None, None),
        generated_at: "2026-01-01T00:00:00Z".to_owned(),
        self_identity: SelfIdentity::default(),
        tier: ScanTier::Standard,
    };
    scan::run(&host, &Bundle::embedded().unwrap(), context)
}

fn times() -> SavedTimes {
    SavedTimes {
        scan_finished_at: "2026-01-01T00:00:09Z".to_owned(),
        saved_at: "2026-01-01T00:02:00Z".to_owned(),
    }
}

/// The Offline tool as the producer, as the app and the CLI pass it (ADR 0089 §2): the version is
/// the provenance's, and the app runs interactively.
fn producer() -> view::Producer {
    view::Producer {
        name: view::ProducerName::RongroiOffline,
        version: "0.0.0-test".to_owned(),
        mode: view::ProducerMode::Interactive,
    }
}

/// `saved_record`'s two optional context arguments, offline: no binding, no policy (ADR 0089 §2).
fn no_binding_no_policy() -> (Option<Binding>, Option<Policy>) {
    (None, None)
}

/// The record of `host` as JSON, over the bytes a save writes.
fn record_of(
    host: &str,
    case_code: Option<String>,
    (binding, policy): (Option<Binding>, Option<Policy>),
) -> serde_json::Value {
    let report = report(host);
    serde_json::from_slice(
        &view::saved_record(
            &report,
            SsOptions::default(),
            case_code,
            producer(),
            binding,
            policy,
            times(),
        )
        .unwrap()
        .to_bytes()
        .unwrap(),
    )
    .unwrap()
}

#[test]
fn the_record_holds_the_ss_view_every_device_and_its_header_fields() {
    let report = report("baseline-consumer-win11");
    let record = view::saved_record(
        &report,
        SsOptions::default(),
        Some("K7Q2MX".to_owned()),
        producer(),
        None,
        None,
        times(),
    )
    .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&record.to_bytes().unwrap()).unwrap();

    assert_eq!(json["kind"], "rongroi-saved-report");
    assert_eq!(
        json["schema"], 2,
        "every new record is schema 2 (ADR 0089 §2)"
    );
    assert_eq!(json["case_code"], "K7Q2MX");
    assert_eq!(json["rongroi_version"], "0.0.0-test");
    assert_eq!(json["producer"]["name"], "rongroi-offline");
    assert_eq!(
        json["producer"]["version"], "0.0.0-test",
        "the version from provenance"
    );
    assert_eq!(json["producer"]["mode"], "interactive");
    // Offline: the record was not produced for one paired server, so it says nothing about one.
    assert!(json.get("binding").is_none(), "no binding when unset");
    assert!(json.get("policy").is_none(), "no policy when unset");
    assert_eq!(json["scan_started_at"], "2026-01-01T00:00:00Z");
    assert_eq!(json["scan_finished_at"], "2026-01-01T00:00:09Z");
    assert_eq!(
        json["view"],
        serde_json::to_value(view::for_mode(&report, Mode::Ss)).unwrap(),
        "the view is the SS view, nothing more"
    );
    // The SS view drops the profiles folder and lists no unmatched observation; the record keeps both rules.
    assert!(json["view"]["header"].get("profiles_directory").is_none());
    assert_eq!(json["view"]["unmatched"], serde_json::json!([]));

    // The consumer baseline has ten PCI and six HID devices, none matched by a rule: every one is carried.
    let devices = json["devices"].as_array().unwrap();
    let count = |c: &str| devices.iter().filter(|d| d["collector"] == c).count();
    assert_eq!(count("pci_device"), 10);
    assert_eq!(count("hid_device"), 6);
    assert_eq!(devices.len(), 16);
}

#[test]
fn the_same_report_and_choices_give_the_same_bytes_and_digest() {
    let report = report("baseline-consumer-win11");
    let a = view::saved_record(
        &report,
        SsOptions::default(),
        None,
        producer(),
        None,
        None,
        times(),
    )
    .unwrap()
    .to_bytes()
    .unwrap();
    let b = view::saved_record(
        &report,
        SsOptions::default(),
        None,
        producer(),
        None,
        None,
        times(),
    )
    .unwrap()
    .to_bytes()
    .unwrap();
    assert_eq!(a, b);
    assert_eq!(view::digest(&a), view::digest(&b));
    assert!(!a.starts_with(&[0xEF, 0xBB, 0xBF]), "no byte-order mark");
    assert!(
        !String::from_utf8(a.clone()).unwrap().contains('\n'),
        "compact"
    );
    let json: serde_json::Value = serde_json::from_slice(&a).unwrap();
    assert!(json.get("case_code").is_none(), "no code typed, no field");
}

#[test]
fn the_written_visual_hash_is_the_hash_of_the_written_bytes_without_itself() {
    let json = record_of(
        "baseline-consumer-win11",
        Some("K7Q2MX".to_owned()),
        no_binding_no_policy(),
    );
    // As a reader recomputes it: over the record without its own member, so it never covers itself
    // (ADR 0089 §2). 16 lowercase hex characters — compared on screen by a person, not for collision
    // resistance.
    let hash = rongroi_core::canonical::visual_hash(&json).unwrap();
    assert_eq!(
        json["visual_hash"].as_str().unwrap(),
        hash,
        "the member is the hash of the record without it"
    );
    assert_eq!(hash.len(), 16);
    assert!(
        hash.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    );

    // A changed field is a changed record, and so a changed hash.
    let changed = record_of("baseline-consumer-win11", None, no_binding_no_policy());
    assert_ne!(
        json["visual_hash"], changed["visual_hash"],
        "the case code counts in the hash"
    );
}

#[test]
fn a_set_binding_and_policy_are_carried_whole_and_count_in_the_visual_hash() {
    let binding = Binding {
        server_origin: Some("http://203.0.113.10:30130".to_owned()),
        ticket: "9f82c4e1b07a412891d604e38a291bf0".to_owned(),
        nonce: "c4b82e91024a".to_owned(),
        issued_at: Some("2026-01-01T00:00:00Z".to_owned()),
        expires_at: Some("2026-01-01T00:05:00Z".to_owned()),
    };
    let policy = Policy {
        profile: Profile::Posture,
        required_collectors: vec!["posture".to_owned()],
        require_elevation: true,
        server_name: "Example Test Range".to_owned(),
        policy_hash: "01aa5ff1c6cebb14".to_owned(),
    };
    let json = record_of(
        "baseline-consumer-win11",
        None,
        (Some(binding), Some(policy)),
    );
    assert_eq!(
        json["binding"],
        serde_json::json!({
            "server_origin": "http://203.0.113.10:30130",
            "ticket": "9f82c4e1b07a412891d604e38a291bf0",
            "nonce": "c4b82e91024a",
            "issued_at": "2026-01-01T00:00:00Z",
            "expires_at": "2026-01-01T00:05:00Z",
        })
    );
    assert_eq!(
        json["policy"],
        serde_json::json!({
            "profile": "posture",
            "required_collectors": ["posture"],
            "require_elevation": true,
            "server_name": "Example Test Range",
            "policy_hash": "01aa5ff1c6cebb14",
        })
    );
    // The same record without them is a different record, and so has a different hash: and its own
    // hash is still the hash of its own bytes without the member.
    let unbound = record_of("baseline-consumer-win11", None, no_binding_no_policy());
    assert_ne!(json["visual_hash"], unbound["visual_hash"]);
    assert_eq!(
        rongroi_core::canonical::visual_hash(&json).unwrap(),
        json["visual_hash"].as_str().unwrap(),
        "the hash stays over the record as written"
    );
}
