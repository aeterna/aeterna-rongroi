// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! ADR 0073: a saved record holds the SS view and every device, and its bytes are what its digest is of.

#![allow(clippy::unwrap_used)]

use std::path::PathBuf;

use rongroi_collectors::scan::{self, ScanContext};
use rongroi_core::bundle::Bundle;
use rongroi_core::engine::SelfIdentity;
use rongroi_core::model::{Mode, ScanTier};
use rongroi_core::provenance::Provenance;
use rongroi_core::view::{self, SavedTimes, SsOptions};
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

#[test]
fn the_record_holds_the_ss_view_every_device_and_its_header_fields() {
    let report = report("baseline-consumer-win11");
    let record = view::saved_record(
        &report,
        SsOptions::default(),
        Some("K7Q2MX".to_owned()),
        times(),
    );
    let json: serde_json::Value = serde_json::from_slice(&record.to_bytes().unwrap()).unwrap();

    assert_eq!(json["kind"], "rongroi-saved-report");
    assert_eq!(json["schema"], 1);
    assert_eq!(json["case_code"], "K7Q2MX");
    assert_eq!(json["rongroi_version"], "0.0.0-test");
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
    let a = view::saved_record(&report, SsOptions::default(), None, times())
        .to_bytes()
        .unwrap();
    let b = view::saved_record(&report, SsOptions::default(), None, times())
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
