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
use rongroi_core::model::{Mode, ScanTier};
use rongroi_core::provenance::Provenance;
use rongroi_core::view;
use rongroi_host::FixtureHost;

/// A scan whose own identity matches nothing the fixture describes, so every observation is evidence
/// about the machine.
fn report_for(host: &str) -> rongroi_core::model::Report {
    report_for_self(host, SelfIdentity::default())
}

fn report_for_self(host: &str, self_identity: SelfIdentity) -> rongroi_core::model::Report {
    report_at(host, self_identity, ScanTier::Standard)
}

fn report_at(
    host: &str,
    self_identity: SelfIdentity,
    tier: ScanTier,
) -> rongroi_core::model::Report {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/hosts")
        .join(host);
    let host = FixtureHost::load(&dir).unwrap();
    let bundle = Bundle::embedded().unwrap();
    let context = ScanContext {
        provenance: Provenance::from_parts(None, "0.0.0-test", None, None),
        generated_at: "2026-01-01T00:00:00Z".to_owned(),
        self_identity,
        tier,
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

/// Rules read `fivem_dir` since ADR 0036. The fixture's readable plugin file has no embedded signature
/// and matches the Legacy plugins rule; the file whose hash and signature could not be read matches the
/// rule that says its signature could not be checked. Self mode shows both paths as they were read,
/// and the folder observations, which no rule matches, as unmatched observations (ADR 0014).
#[test]
fn fivem_dir_plugin_present_self_view() {
    let view = view::for_mode(&report_for("fivem-dir-plugin-present"), Mode::SelfCheck);
    let json = serde_json::to_string(&view).unwrap();
    assert!(json.contains(r"plugins\\example-plugin.dll"), "{json}");
    insta::assert_json_snapshot!(view, { ".header.rules_bundle.sha256" => "[bundle sha256]" });
}

/// Until ADR 0036 no plugin file reached an SS view, and this test asserted the file name was absent.
/// Now each file matches a rule and is `found`, so its path **is** shown to the person watching — which
/// is what the consent question names — and the property that carries the weight is redaction: the
/// fixture's files live under `C:\Users\fixtureuser\...`, and the user name must not survive while
/// the rest of the path does.
#[test]
fn fivem_dir_plugin_present_ss_view() {
    let view = view::for_mode(&report_for("fivem-dir-plugin-present"), Mode::Ss);
    let json = serde_json::to_string(&view).unwrap();
    assert!(!json.contains("fixtureuser"), "{json}");
    for redacted in [
        r"%USERPROFILE%\\AppData\\Local\\FiveM\\FiveM.app\\plugins\\example-plugin.dll",
        r"%USERPROFILE%\\AppData\\Local\\FiveM\\FiveM.app\\plugins\\unreadable-plugin.dll",
    ] {
        assert!(json.contains(redacted), "{redacted} is not in {json}");
    }
    insta::assert_json_snapshot!(view, { ".header.rules_bundle.sha256" => "[bundle sha256]" });
}

/// Both editions' `FiveM.exe` reach an SS view through the client rules, with the user name redacted
/// out of both paths, the signer's name shown beside a certificate the rule does not know, and nothing
/// else from either program folder — `modify.exe` and the folder's other entries are listed to find
/// the executable and are never observations (ADR 0036).
#[test]
fn fivem_dir_client_exe_ss_view_redacts_both_programs_and_shows_nothing_else() {
    const WITHOUT_VERIFIED_SIGNATURE: &str = "148cbcdd-8d18-4af6-a541-71cc7f21b2eb";
    const ANOTHER_CERTIFICATE: &str = "2dc11b64-72a2-48f5-a273-985e906d5a9e";

    let report = report_for("fivem-dir-client-exe");
    let everything = serde_json::to_string(&report).unwrap();
    for never in ["modify.exe", "VisualElementsManifest", "products"] {
        assert!(!everything.contains(never), "{never} reached the report");
    }

    let view = view::for_mode(&report, Mode::Ss);
    let json = serde_json::to_string(&view).unwrap();
    assert!(!json.contains("fixtureuser"), "{json}");
    let found = |rule: &str| {
        view.evidence
            .iter()
            .find(|evidence| evidence.rule_id == rule)
            .map(|evidence| serde_json::to_string(&evidence.state).unwrap())
            .unwrap_or_default()
    };
    let unsigned = found(WITHOUT_VERIFIED_SIGNATURE);
    assert!(
        unsigned.contains(r"%USERPROFILE%\\AppData\\Local\\FiveM for GTAV Enhanced\\FiveM.exe"),
        "{unsigned}"
    );
    let other = found(ANOTHER_CERTIFICATE);
    assert!(
        other.contains(r"%USERPROFILE%\\AppData\\Local\\FiveM\\fivem.exe"),
        "{other}"
    );
    assert!(other.contains("Example Signer"), "{other}");
}

/// A folder nobody could list is a gap in every field **for the rules that could match there**
/// (ADR 0044). Those rules are `unmeasured` — the one asking for an absent `signature` included, whose
/// `exists: false` would otherwise be satisfied by a folder with nothing read in it — and none of them
/// declares `access_denied`, so SS mode lists each (ADR 0027, ADR 0029, ADR 0036). A rule whose
/// `location` rules that folder out keeps the answer the folders that were read give it: until
/// ADR 0044 an unreadable program folder made the plugin rules `unmeasured` too.
#[test]
fn a_fivem_folder_that_could_not_be_listed_leaves_the_rules_that_could_match_there_unmeasured() {
    use rongroi_core::model::{EvidenceState, UnmeasuredReason};

    const PLUGINS_NOT_VERIFIED: &str = "061797d3-161d-4783-89e6-caf658973436";
    const PLUGINS_VALID: &str = "d5531c55-1a65-4698-9f39-7cf79bbbb7ba";
    const ASI_NOT_VERIFIED: &str = "0999422f-8709-4d85-80e3-39410a85ed6b";
    const ASI_VALID: &str = "53528a11-5af7-4e75-94bf-fca07eec6fcc";
    const CLIENT_NOT_VERIFIED: &str = "148cbcdd-8d18-4af6-a541-71cc7f21b2eb";
    const CLIENT_OTHER_CERTIFICATE: &str = "2dc11b64-72a2-48f5-a273-985e906d5a9e";
    const NOT_CHECKED: &str = "282115fe-863d-4e2e-9cf5-4eaf8e7545e4";

    // `true`: unmeasured / access_denied. `false`: not_found.
    let expectations: [(&str, &[(&str, bool)]); 2] = [
        // Legacy's plugins folder denied; Enhanced not installed, no program folder.
        (
            "fivem-dir-access-denied",
            &[
                (PLUGINS_NOT_VERIFIED, true),
                (PLUGINS_VALID, true),
                (ASI_NOT_VERIFIED, false),
                (ASI_VALID, false),
                (CLIENT_NOT_VERIFIED, false),
                (CLIENT_OTHER_CERTIFICATE, false),
                (NOT_CHECKED, true),
            ],
        ),
        // Legacy's program folder denied; its plugins folder listed and empty.
        (
            "fivem-dir-client-folder-denied",
            &[
                (PLUGINS_NOT_VERIFIED, false),
                (PLUGINS_VALID, false),
                (ASI_NOT_VERIFIED, false),
                (ASI_VALID, false),
                (CLIENT_NOT_VERIFIED, true),
                (CLIENT_OTHER_CERTIFICATE, true),
                (NOT_CHECKED, true),
            ],
        ),
    ];
    for (host, rules) in expectations {
        let report = report_for(host);
        let fivem = report
            .evidence
            .iter()
            .filter(|evidence| evidence.collector == "fivem_dir")
            .count();
        assert_eq!(
            fivem,
            rules.len(),
            "{host}: a fivem_dir rule is not accounted for"
        );
        for (rule, unmeasured) in rules {
            let evidence = report
                .evidence
                .iter()
                .find(|evidence| evidence.rule_id == *rule)
                .unwrap();
            let ok = if *unmeasured {
                matches!(
                    evidence.state,
                    EvidenceState::Unmeasured {
                        reason: UnmeasuredReason::AccessDenied,
                        expected: false,
                    }
                )
            } else {
                matches!(evidence.state, EvidenceState::NotFound { .. })
            };
            assert!(ok, "{host}: {rule} is {:?}", evidence.state);
        }
    }
}

/// **A refusal no rule declares is a row a reviewer sees** (ADR 0032, amended 2026-09-14). Since the
/// review of every `access_denied` declaration, no rule names it: on `evtx` and `prefetch` it is a
/// refusal with administrator rights, and on `posture` a refusal of a key every account may read or a
/// query that never reports one. On each of these hosts the rules the refusal reaches are
/// `unmeasured / access_denied` with `expected: false`, and SS mode lists every one of them.
#[test]
fn a_refusal_no_rule_expects_is_listed_in_ss_mode() {
    use rongroi_core::model::{EvidenceState, UnmeasuredReason};

    for (host, rules) in [
        ("evtx-access-denied-elevated", 4),
        ("prefetch-access-denied-elevated", 1),
        // `secure-boot-disabled` and `secure-boot-firmware-disagrees`: the fixture denies the
        // registry's Secure Boot key.
        ("registry-access-denied", 2),
    ] {
        let report = report_for(host);
        let refused: Vec<_> = report
            .evidence
            .iter()
            .filter(|evidence| {
                matches!(
                    evidence.state,
                    EvidenceState::Unmeasured {
                        reason: UnmeasuredReason::AccessDenied,
                        ..
                    }
                )
            })
            .collect();
        assert_eq!(refused.len(), rules, "{host}: {refused:?}");
        let ss = view::for_mode(&report, Mode::Ss);
        for evidence in refused {
            assert!(
                matches!(
                    evidence.state,
                    EvidenceState::Unmeasured {
                        expected: false,
                        ..
                    }
                ),
                "{host}: {} still expects a refusal",
                evidence.rule_id
            );
            assert!(
                ss.evidence
                    .iter()
                    .any(|row| row.rule_id == evidence.rule_id),
                "{host}: SS mode does not list {}",
                evidence.rule_id
            );
        }
    }
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
    // The fixture describes no registry, so `posture` also has one unmatched observation: its
    // four `script_block_logging` fields, each `not_configured`, which is an answer rather than a gap
    // (ADR 0038).
    let process = report
        .unmatched
        .iter()
        .find(|group| group.collector == "process")
        .unwrap_or_else(|| panic!("{:?}", report.unmatched));
    assert_eq!(process.observations.len(), 2);
    let collectors: Vec<&str> = report
        .unmatched
        .iter()
        .map(|group| group.collector.as_str())
        .collect();
    assert_eq!(collectors, ["posture", "process"]);
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

/// No rule reads `pca` either (ADR 0020), so every launch record and every per-file account of what
/// parsed is an unmatched observation. This is the whole of the collector's route to a screen, and it
/// needs no change to the CLI or the app: both render the bucket by collector id (ADR 0014).
#[test]
fn pca_files_present_self_view() {
    let view = view::for_mode(&report_for("pca-files-present"), Mode::SelfCheck);
    let json = serde_json::to_string(&view).unwrap();
    assert!(json.contains("game.exe"), "{json}");
    assert!(json.contains(r"Users\\alex\\Downloads\\game.exe"), "{json}");
    insta::assert_json_snapshot!(view, { ".header.rules_bundle.sha256" => "[bundle sha256]" });
}

/// PCA records the paths of programs that ran, which is a list of what a person has on their
/// computer. SS mode lists no unmatched observation at all, so none of it reaches the person watching
/// the screenshare — neither the account name in the paths nor the names of the programs.
#[test]
fn pca_files_present_ss_view() {
    let view = view::for_mode(&report_for("pca-files-present"), Mode::Ss);
    let json = serde_json::to_string(&view).unwrap();
    assert!(!json.contains("alex"), "{json}");
    assert!(!json.contains("game.exe"), "{json}");
    // The viewer is told how many were withheld rather than being told nothing (ADR 0014).
    assert!(view.hidden.unmatched > 0);
    insta::assert_json_snapshot!(view, { ".header.rules_bundle.sha256" => "[bundle sha256]" });
}

/// The one rule on `prefetch` asks whether a `.pf` file is read-only (ADR 0037), and here none is. The
/// programs it saw, the account of what the folder held and Prefetch's configuration reach Self mode
/// through the unmatched bucket with no change to the CLI or the app.
#[test]
fn prefetch_files_present_self_view() {
    let view = view::for_mode(&report_for("prefetch-files-present"), Mode::SelfCheck);
    let json = serde_json::to_string(&view).unwrap();
    assert!(json.contains("cmd.exe"), "{json}");
    insta::assert_json_snapshot!(view, { ".header.rules_bundle.sha256" => "[bundle sha256]" });
}

/// No rule reads `bam` either (ADR 0023). The programs it saw, and the account of what BAM held,
/// reach Self mode through the unmatched bucket with no change to the CLI or the app.
#[test]
fn bam_entries_present_self_view() {
    let view = view::for_mode(&report_for("bam-entries-present"), Mode::SelfCheck);
    let json = serde_json::to_string(&view).unwrap();
    assert!(json.contains("example.exe"), "{json}");
    insta::assert_json_snapshot!(view, { ".header.rules_bundle.sha256" => "[bundle sha256]" });
}

/// BAM is keyed by a SID, and the fixture writes a whole one out so that this assertion has
/// something to bite on. A real machine's account name may be a single character — the vendored
/// Prefetch corpus's is — so the assertion that carries the weight is on the *shapes* an account or
/// an installation leaves behind, and it is made against the whole report rather than only the view:
/// neither mode has anything to redact here, because the collector never emits them.
#[test]
fn bam_entries_present_ss_view() {
    let report = report_for("bam-entries-present");
    let everything = serde_json::to_string(&report).unwrap().to_uppercase();
    for leaked in ["S-1-5-", "USERSETTINGS", "HARDDISKVOLUME"] {
        assert!(!everything.contains(leaked), "{leaked} reached the report");
    }

    let view = view::for_mode(&report, Mode::Ss);
    let json = serde_json::to_string(&view).unwrap();
    assert!(!json.contains("example.exe"), "{json}");
    assert!(!json.contains("fixtureuser"), "{json}");
    assert!(view.hidden.unmatched > 0);
    insta::assert_json_snapshot!(view, { ".header.rules_bundle.sha256" => "[bundle sha256]" });
}

/// A `.pf` file lists every file the program loaded and the volumes it touched. The fixture's own
/// `.pf` carries the upstream author's profile paths and his machine's volume serial numbers
/// (`fixtures/prefetch/PROVENANCE.md`), and **neither mode has anything to redact**, because the
/// collector never emits them. What SS mode adds on top is that it lists no unmatched observation at
/// all, so not even the program's name reaches the person watching.
#[test]
fn prefetch_files_present_ss_view() {
    let report = report_for("prefetch-files-present");
    let everything = serde_json::to_string(&report).unwrap().to_uppercase();
    for leaked in ["VOLUME{", "HARDDISKVOLUME", "\\\\USERS\\\\", ".DLL"] {
        assert!(!everything.contains(leaked), "{leaked} reached the report");
    }

    let view = view::for_mode(&report, Mode::Ss);
    let json = serde_json::to_string(&view).unwrap();
    assert!(!json.contains("cmd.exe"), "{json}");
    assert!(view.hidden.unmatched > 0);
    insta::assert_json_snapshot!(view, { ".header.rules_bundle.sha256" => "[bundle sha256]" });
}

/// Two log-clearing rules read `evtx` (ADR 0031), and this host holds neither channel they name, so both are
/// `not_found` here — which is the false green that ADR records: the one vendored sample is a
/// `LanguagePackSetup` log, so no fixture in this repository can make either of them match. Everything
/// else each log held reaches Self mode through the unmatched bucket, counted by kind of event rather
/// than one observation per record — a real log holds tens of thousands of them.
#[test]
fn evtx_logs_present_self_view() {
    let view = view::for_mode(&report_for("evtx-logs-present"), Mode::SelfCheck);
    let json = serde_json::to_string(&view).unwrap();
    assert!(
        json.contains("Microsoft-Windows-LanguagePackSetup"),
        "{json}"
    );
    insta::assert_json_snapshot!(view, { ".header.rules_bundle.sha256" => "[bundle sha256]" });
}

/// One Event Log record can carry a user name, a host name, an address, a SID and a command line.
/// The parser drops every record's payload and its `Computer` field (ADR 0018), so **neither mode has
/// anything to redact** — the host name of the machine that wrote the vendored sample reaches no part
/// of the report. What SS mode adds on top is that it lists no unmatched observation at all, so the
/// names of the channels on this PC reach the person watching only where a rule matched and the name
/// is part of the evidence: here both logs hold records of a channel the service writes to another
/// file, and that file's path — which names the channel — is what the row shows (ADR 0042). The two
/// log-clearing rules are `tamper`, not `posture`, so their `not_found` is counted here rather than
/// listed — a rule whose negative result means almost nothing does not get a row in front of a
/// reviewer (ADR 0031).
#[test]
fn evtx_logs_present_ss_view() {
    let report = report_for("evtx-logs-present");
    let everything = serde_json::to_string(&report).unwrap();
    assert!(
        !everything.contains("DESKTOP-1N4R894"),
        "the host name reached the report"
    );

    let view = view::for_mode(&report, Mode::Ss);
    let outside_the_evidence: Vec<_> = view
        .evidence
        .iter()
        .filter(|row| row.rule_id != "87a53c8f-b0e4-477d-91e7-93b904ba965f")
        .collect();
    let json = serde_json::to_string(&outside_the_evidence).unwrap();
    assert!(!json.contains("LanguagePackSetup"), "{json}");
    assert!(view.hidden.unmatched > 0);
    insta::assert_json_snapshot!(view, { ".header.rules_bundle.sha256" => "[bundle sha256]" });
}

/// The two log-clearing rules (ADR 0031) are `unmeasured` on an Event Log that could not be read,
/// never `not_found`.
///
/// This is the property that protects a player and the one a rule cannot state about itself. A
/// `not_found` row is shown as "this was looked for over that window and was not there"; saying it
/// about a log nobody read would be this program asserting that the Security log was never cleared on
/// evidence it never saw (ADR 0002). The `evtx` collector's `gaps` are folder-wide, so **one**
/// unreadable log is enough — which is why `evtx-log-unreadable`, where the folder listed fine and a
/// single file did not, is the case worth pinning rather than the wholly denied one.
#[test]
fn a_log_that_could_not_be_read_leaves_the_clearing_rules_unmeasured() {
    const SECURITY_LOG_CLEARED: &str = "ff967b28-984b-4de0-b361-58367ae0c2d5";
    const EVENT_LOG_FILE_CLEARED: &str = "f4c99b57-02c8-4e53-82d0-dba8bdc13dda";

    for host in ["evtx-log-unreadable", "evtx-access-denied"] {
        let report = report_for(host);
        let mut seen = 0;
        for evidence in &report.evidence {
            if evidence.rule_id != SECURITY_LOG_CLEARED
                && evidence.rule_id != EVENT_LOG_FILE_CLEARED
            {
                continue;
            }
            seen += 1;
            assert!(
                matches!(
                    evidence.state,
                    rongroi_core::model::EvidenceState::Unmeasured { .. }
                ),
                "{host}: {} is {:?}, which tells a player a cleared log was looked for and was not there",
                evidence.rule_id,
                evidence.state
            );
        }
        assert_eq!(seen, 2, "{host}: both rules must reach the report");
    }
}

/// The whole `HKLM\SYSTEM\CurrentControlSet\Services` key refused makes `driver_service` itself
/// `Unmeasured` (ADR 0048), which every rule reading that collector inherits — here the one
/// vulnerable-driver rule. Self mode carries it as an ordinary unmeasured row (Minor 6 of the PR 3
/// review).
#[test]
fn driver_service_refused_self_view() {
    let view = view::for_mode(&report_for("driver-service-refused"), Mode::SelfCheck);
    insta::assert_json_snapshot!(view, { ".header.rules_bundle.sha256" => "[bundle sha256]" });
}

/// The same refusal in SS mode: `access_denied` is not in this rule's `unmeasured_when`
/// (`rules/driver_service/vulnerable-driver/loldrivers-listed/rule.yaml`), so it is an unexpected
/// reason and SS mode lists it rather than only counting it (Minor 6 of the PR 3 review).
#[test]
fn driver_service_refused_ss_view() {
    use rongroi_core::model::{EvidenceState, UnmeasuredReason};

    const VULNERABLE_DRIVER_LISTED: &str = "98f6e2b8-6d23-4202-bc7f-06587ebdd2f3";

    let report = report_for("driver-service-refused");
    let evidence = report
        .evidence
        .iter()
        .find(|evidence| evidence.rule_id == VULNERABLE_DRIVER_LISTED)
        .unwrap_or_else(|| panic!("{VULNERABLE_DRIVER_LISTED} did not reach the report"));
    assert!(
        matches!(
            evidence.state,
            EvidenceState::Unmeasured {
                reason: UnmeasuredReason::AccessDenied,
                expected: false,
            }
        ),
        "{:?}",
        evidence.state
    );

    let view = view::for_mode(&report, Mode::Ss);
    assert!(
        view.evidence
            .iter()
            .any(|row| row.rule_id == VULNERABLE_DRIVER_LISTED),
        "SS mode does not list {VULNERABLE_DRIVER_LISTED}"
    );
    insta::assert_json_snapshot!(view, { ".header.rules_bundle.sha256" => "[bundle sha256]" });
}

/// A driver service whose file's SHA-256 is the vendored data file's first row is `Found`, with that
/// hash on the row, and SS mode lists it — `ss_lists` admits every match whatever the rule's
/// `strength`, and this rule is `posture` (Minor 6 of the PR 3 review).
#[test]
fn driver_service_listed_ss_view() {
    use rongroi_core::model::EvidenceState;

    const VULNERABLE_DRIVER_LISTED: &str = "98f6e2b8-6d23-4202-bc7f-06587ebdd2f3";
    const LISTED_SHA256: &str = "000547560fea0dd4b477eb28bf781ea67bf83c748945ce8923f90fdd14eb7a4b";

    let report = report_for("driver-service-listed");
    let evidence = report
        .evidence
        .iter()
        .find(|evidence| evidence.rule_id == VULNERABLE_DRIVER_LISTED)
        .unwrap_or_else(|| panic!("{VULNERABLE_DRIVER_LISTED} did not reach the report"));
    let EvidenceState::Found { observations } = &evidence.state else {
        panic!("expected Found, got {:?}", evidence.state);
    };
    assert!(
        observations.iter().any(|observation| {
            observation
                .fields
                .get("sha256")
                .and_then(|value| value.as_str())
                == Some(LISTED_SHA256)
        }),
        "{observations:?}"
    );

    let view = view::for_mode(&report, Mode::Ss);
    let json = serde_json::to_string(&view).unwrap();
    assert!(json.contains(LISTED_SHA256), "{json}");
    insta::assert_json_snapshot!(view, { ".header.rules_bundle.sha256" => "[bundle sha256]" });
}

/// A hosts line for a listed name is `Found`. SS mode lists it with the kind of address and without the
/// address itself, which Self mode shows (ADR 0054, owner decision 2); the proxy's server and the
/// firewall rules reach neither view as evidence, since no rule reads them.
#[test]
fn net_config_listed_name_ss_view() {
    const HOSTS_RULE: &str = "65ee0ec1-bcda-47a3-a401-98632b42e75f";

    let report = report_for("net-config-listed-name");
    let evidence = report
        .evidence
        .iter()
        .find(|evidence| evidence.rule_id == HOSTS_RULE)
        .unwrap_or_else(|| panic!("{HOSTS_RULE} did not reach the report"));
    assert!(
        matches!(&evidence.state, rongroi_core::model::EvidenceState::Found { observations } if observations.len() == 2),
        "{evidence:?}"
    );

    let own = serde_json::to_string(&view::for_mode(&report, Mode::SelfCheck)).unwrap();
    assert!(own.contains("192.0.2.10"), "{own}");
    let view = view::for_mode(&report, Mode::Ss);
    let json = serde_json::to_string(&view).unwrap();
    for withheld in ["192.0.2.10", "proxy.example.test", "Example"] {
        assert!(
            !json.contains(withheld),
            "{withheld} reached the SS view: {json}"
        );
    }
    assert!(json.contains("\"address_kind\":\"public\""), "{json}");
    insta::assert_json_snapshot!(view, { ".header.rules_bundle.sha256" => "[bundle sha256]" });
}

/// The boot time is a fact about the scan's context, so both views carry it unchanged: SS mode's
/// filter is about evidence, and staff read the times on the rows they are shown against it
/// (ADR 0039). A report written before the field existed reads back as never having tried, not as a
/// start time nobody measured.
#[test]
fn the_boot_time_reaches_both_views_and_an_older_report_reads_back_not_attempted() {
    use rongroi_core::model::{BootTime, UnmeasuredReason};

    let report = report_for("secure-boot-off");
    let expected = BootTime::Measured {
        booted_at: "2025-12-28T21:56:56Z".to_owned(),
        seconds_since_boot: 266_584,
    };
    assert_eq!(report.header.boot_time, expected);
    for mode in [Mode::SelfCheck, Mode::Ss] {
        assert_eq!(view::for_mode(&report, mode).header.boot_time, expected);
    }

    let mut older = serde_json::to_value(&report).unwrap();
    older["header"]
        .as_object_mut()
        .unwrap()
        .remove("boot_time")
        .unwrap();
    let older: rongroi_core::model::Report = serde_json::from_value(older).unwrap();
    assert_eq!(
        older.header.boot_time,
        BootTime::Unmeasured {
            reason: UnmeasuredReason::NotAttempted
        }
    );
}
