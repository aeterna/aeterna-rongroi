// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! L3: the full pipeline (fixture host → collectors → embedded bundle → report → views) as snapshots.

// A failing fixture load should stop the test loudly; `allow-unwrap-in-tests` does not cover helpers.
#![allow(clippy::unwrap_used)]

use std::path::PathBuf;

use rongroi_collectors::scan::{self, ScanContext};
use rongroi_core::bundle::Bundle;
use rongroi_core::engine::SelfIdentity;
use rongroi_core::model::Mode;
use rongroi_core::provenance::Provenance;
use rongroi_core::view;
use rongroi_host::FixtureHost;

/// A scan whose own identity matches nothing the fixture describes, so every observation is evidence
/// about the machine.
fn report_for(host: &str) -> rongroi_core::model::Report {
    report_for_self(host, SelfIdentity::default())
}

fn report_for_self(host: &str, self_identity: SelfIdentity) -> rongroi_core::model::Report {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/hosts")
        .join(host);
    let host = FixtureHost::load(&dir).unwrap();
    let bundle = Bundle::embedded().unwrap();
    let context = ScanContext {
        provenance: Provenance::from_parts(None, "0.0.0-test", None, None),
        generated_at: "2026-01-01T00:00:00Z".to_owned(),
        self_identity,
    };
    scan::run(&host, &bundle, context)
}

#[test]
fn secure_boot_off_self_view() {
    let view = view::for_mode(&report_for("secure-boot-off"), Mode::SelfCheck);
    insta::assert_json_snapshot!(view, { ".header.rules_bundle.sha256" => "[bundle sha256]" });
}

#[test]
fn secure_boot_off_ss_view() {
    let view = view::for_mode(&report_for("secure-boot-off"), Mode::Ss);
    insta::assert_json_snapshot!(view, { ".header.rules_bundle.sha256" => "[bundle sha256]" });
}

#[test]
fn unreported_secure_boot_is_unmeasured_not_not_found() {
    let view = view::for_mode(&report_for("secure-boot-unreported"), Mode::SelfCheck);
    insta::assert_json_snapshot!(view, { ".header.rules_bundle.sha256" => "[bundle sha256]" });
}

/// No rule reads `fivem_dir` (ADR 0009), so every file it saw is an unmatched observation. Self
/// mode is where a person reads them — which is what ADR 0009 claimed and what, until ADR 0014,
/// nothing in the code did: an observation reached a view only inside `Found` evidence.
#[test]
fn fivem_dir_plugin_present_self_view() {
    let view = view::for_mode(&report_for("fivem-dir-plugin-present"), Mode::SelfCheck);
    let json = serde_json::to_string(&view).unwrap();
    assert!(json.contains(r"plugins\\example-plugin.dll"), "{json}");
    insta::assert_json_snapshot!(view, { ".header.rules_bundle.sha256" => "[bundle sha256]" });
}

#[test]
fn fivem_dir_plugin_present_ss_view() {
    let view = view::for_mode(&report_for("fivem-dir-plugin-present"), Mode::Ss);
    // The fixture's files live under `C:\Users\fixtureuser\...`. SS mode counts unmatched
    // observations and lists none of them, so neither the user name nor the file names reach the
    // person watching. This is the assertion the earlier version of this test could not make,
    // because nothing of this collector reached a view at all (ADR 0014).
    let json = serde_json::to_string(&view).unwrap();
    assert!(!json.contains("fixtureuser"), "{json}");
    assert!(!json.contains("example-plugin.dll"), "{json}");
    insta::assert_json_snapshot!(view, { ".header.rules_bundle.sha256" => "[bundle sha256]" });
}

/// Where the `process-own-trace` fixture says this program is running from.
const OWN_EXE: &str = r"C:\Users\fixtureuser\Downloads\aeterna-rongroi.exe";

fn scanning_ourselves() -> SelfIdentity {
    SelfIdentity {
        exe_path: Some(OWN_EXE.to_owned()),
        exe_sha256: None,
    }
}

/// The program's own process is in the list it read. That observation belongs in `own_traces`, where
/// a reader can see it, and never in evidence about the machine (ADR 0010).
#[test]
fn process_own_trace_self_view() {
    let report = report_for_self("process-own-trace", scanning_ourselves());
    // One of the three processes the fixture describes is ours; the other two stayed in the run.
    assert_eq!(report.own_traces.len(), 1);
    // Those other two are unmatched observations — no rule reads `process`. Own traces are taken
    // out before any rule runs, so the one that is ours is not repeated among them (ADR 0014).
    assert_eq!(report.unmatched.len(), 1, "{:?}", report.unmatched);
    assert_eq!(report.unmatched[0].collector, "process");
    assert_eq!(report.unmatched[0].observations.len(), 2);
    let unmatched = serde_json::to_string(&report.unmatched).unwrap();
    assert!(!unmatched.contains("aeterna-rongroi"), "{unmatched}");
    let view = view::for_mode(&report, Mode::SelfCheck);
    let evidence = serde_json::to_string(&view.evidence).unwrap();
    assert!(!evidence.contains("aeterna-rongroi"), "{evidence}");
    insta::assert_json_snapshot!(view, { ".header.rules_bundle.sha256" => "[bundle sha256]" });
}

/// SS mode shows own traces as well, with the same path redaction as `Found` evidence.
#[test]
fn process_own_trace_ss_view() {
    let view = view::for_mode(
        &report_for_self("process-own-trace", scanning_ourselves()),
        Mode::Ss,
    );
    assert_eq!(view.own_traces.len(), 1);
    let json = serde_json::to_string(&view).unwrap();
    assert!(!json.contains("fixtureuser"), "{json}");
    insta::assert_json_snapshot!(view, { ".header.rules_bundle.sha256" => "[bundle sha256]" });
}

#[test]
fn unofficial_provenance_is_reported() {
    let report = report_for("secure-boot-on");
    assert!(!report.header.provenance.official);
}
