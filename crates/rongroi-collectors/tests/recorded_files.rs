// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! C1 acceptance tests for `recorded_files`: discovery and `identity_read` (ADR 0079 amendment 7).

#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::path::PathBuf;

use rongroi_collectors::scan::{self, ScanContext};
use rongroi_collectors::{Collector, all};
use rongroi_core::bundle::Bundle;
use rongroi_core::engine::SelfIdentity;
use rongroi_core::model::{CollectorRun, EvidenceState, Observation, ScanTier, UnmeasuredReason};
use rongroi_core::provenance::Provenance;
use rongroi_core::view;
use rongroi_host::FixtureHost;

const BAM_KEY: &str =
    r"HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\S-1-5-21-0-0-0-1001";
const PCA_DIR: &str = r"C:\Windows\appcompat\pca";

/// The collector registered under the id `recorded_files`, or a failure that names the missing
/// registration rather than making every assertion below look like a broken field.
fn recorded_files() -> Box<dyn Collector> {
    all()
        .into_iter()
        .find(|collector| collector.id() == "recorded_files")
        .unwrap_or_else(|| panic!("no `recorded_files` collector is registered in all()"))
}

/// A host whose three path sources are all readable: BAM holds `bam_paths`, PCA's launch dictionary
/// holds `pca_line` (or is empty), and the process list holds `processes`. `files` are the files on
/// disk, by folder and name, with readable bytes.
///
/// Every source has to be described, because a source this collector cannot read is a gap for its
/// whole run even when another source gave it a path.
fn host(
    env: &str,
    bam_paths: &[&str],
    pca_line: Option<&str>,
    processes: &str,
    files: &[(&str, &str)],
) -> FixtureHost {
    let mut yaml = String::from("platform: windows\nos_build: \"26100\"\n");
    yaml.push_str(env);
    yaml.push_str("registry:\n");
    yaml.push_str(&format!(
        "  '{BAM_KEY}':\n    Version: 1\n    SequenceNumber: 1\n"
    ));
    for path in bam_paths {
        yaml.push_str(&format!(
            "    '{path}':\n      content: '012345678901234567890123'\n"
        ));
    }
    yaml.push_str("filesystem:\n");
    yaml.push_str(&format!(
        "  '{PCA_DIR}':\n    - name: PcaAppLaunchDic.txt\n"
    ));
    match pca_line {
        Some(line) => {
            yaml.push_str("      content: |\n        ");
            yaml.push_str(line);
            yaml.push('\n');
        }
        None => yaml.push_str("      content: ''\n"),
    }
    for (dir, name) in files {
        yaml.push_str(&format!(
            "  '{dir}':\n    - name: '{name}'\n      content: 'fixture bytes'\n"
        ));
    }
    yaml.push_str("processes:\n");
    yaml.push_str(processes);
    FixtureHost::from_yaml_str(&yaml, "inline").unwrap()
}

fn measured(run: &CollectorRun) -> (&[Observation], &BTreeMap<String, UnmeasuredReason>) {
    match run {
        CollectorRun::Measured {
            observations, gaps, ..
        } => (observations, gaps),
        CollectorRun::Unmeasured { .. } => panic!("expected a measured run, got {run:?}"),
    }
}

fn text<'a>(observation: &'a Observation, name: &str) -> Option<&'a str> {
    observation
        .fields
        .get(name)
        .and_then(serde_json::Value::as_str)
}

fn flag(observation: &Observation, name: &str) -> Option<bool> {
    observation
        .fields
        .get(name)
        .and_then(serde_json::Value::as_bool)
}

fn observation_named<'a>(observations: &'a [Observation], name: &str) -> &'a Observation {
    observations
        .iter()
        .find(|observation| {
            text(observation, "name").is_some_and(|seen| seen.eq_ignore_ascii_case(name))
        })
        .unwrap_or_else(|| panic!("no observation named {name}: {observations:?}"))
}

/// (k1) The same file recorded by BAM and PCA in two cases is one observation, and both sources are
/// named on it.
#[test]
fn k1_the_same_file_in_bam_and_pca_in_different_case_is_one_observation() {
    let fixture = host(
        "env:\n  WinDir: 'C:\\Windows'\n  SystemDrive: 'C:'\n  SystemRoot: 'C:\\Windows'\n",
        &[r"C:\Program Files\Fixture\Shared.exe"],
        Some(r"c:\program files\fixture\shared.exe|2026-09-12T10:23:46Z"),
        "  - pid: 4\n    name: System\n",
        &[(r"C:\Program Files\Fixture", "Shared.exe")],
    );

    let collector = recorded_files();
    let run = collector.collect(&fixture);
    let (observations, gaps) = measured(&run);

    assert!(gaps.is_empty(), "{gaps:?}");
    assert_eq!(observations.len(), 1, "{observations:?}");
    let observation = &observations[0];
    assert_eq!(flag(observation, "by_bam"), Some(true), "{observation:?}");
    assert_eq!(flag(observation, "by_pca"), Some(true), "{observation:?}");
    assert_eq!(
        flag(observation, "by_process"),
        Some(false),
        "{observation:?}"
    );
    assert_eq!(text(observation, "identity_read"), Some("read"));
    assert!(
        text(observation, "name").is_some_and(|name| name.eq_ignore_ascii_case("shared.exe")),
        "{observation:?}"
    );
}

/// (k2) A path the source recorded but the file is gone is `missing`; a path whose form this program
/// refuses is `refused_form` without a read; a path that is not drive-rooted is not observed at all.
/// None of the three is a gap.
#[test]
fn k2_a_gone_file_is_missing_a_refused_form_is_refused_and_a_non_drive_rooted_path_is_ignored() {
    const GONE: &str = r"C:\Users\fixtureuser\Gone\gone.exe";
    const REFUSED: &str = r"C:\Users\..\refused.exe";
    const UNC: &str = r"\\server\share\unc.exe";

    let fixture = host(
        "env:\n  WinDir: 'C:\\Windows'\n  SystemDrive: 'C:'\n  SystemRoot: 'C:\\Windows'\n",
        &[GONE, REFUSED],
        None,
        "  - pid: 4\n    name: System\n  - pid: 5\n    name: unc.exe\n    path: '\\\\server\\share\\unc.exe'\n",
        &[],
    );

    let collector = recorded_files();
    let run = collector.collect(&fixture);
    let (observations, gaps) = measured(&run);

    assert!(gaps.is_empty(), "{gaps:?}");
    assert_eq!(observations.len(), 2, "{observations:?}");

    let gone = observation_named(observations, "gone.exe");
    assert_eq!(text(gone, "identity_read"), Some("missing"), "{gone:?}");
    assert_eq!(flag(gone, "by_bam"), Some(true), "{gone:?}");

    let refused = observation_named(observations, "refused.exe");
    assert_eq!(
        text(refused, "identity_read"),
        Some("refused_form"),
        "{refused:?}"
    );
    assert_eq!(flag(refused, "by_bam"), Some(true), "{refused:?}");

    assert!(
        observations
            .iter()
            .all(|observation| text(observation, "path") != Some(UNC)),
        "a UNC path must not be observed: {observations:?}"
    );
    assert!(
        observations.iter().all(|observation| {
            text(observation, "name").is_none_or(|name| !name.eq_ignore_ascii_case("unc.exe"))
        }),
        "a UNC path must not be observed: {observations:?}"
    );
}

/// (k3) A file that is there is `read`, and the two root flags are read from the fixture's
/// `SystemDrive` and `SystemRoot`. Without those variables the flags are absent, not guessed.
#[test]
fn k3_a_present_file_is_read_and_the_root_flags_follow_the_environment() {
    let with_roots = host(
        "env:\n  WinDir: 'C:\\Windows'\n  SystemDrive: 'C:'\n  SystemRoot: 'C:\\Windows'\n",
        &[r"C:\Windows\System32\inside.exe"],
        None,
        "  - pid: 4\n    name: System\n  - pid: 5\n    name: inside.exe\n    path: 'C:\\Windows\\System32\\inside.exe'\n  - pid: 6\n    name: outside.exe\n    path: 'D:\\Tools\\outside.exe'\n",
        &[
            (r"C:\Windows\System32", "inside.exe"),
            (r"D:\Tools", "outside.exe"),
        ],
    );

    let collector = recorded_files();
    let run = collector.collect(&with_roots);
    let (observations, gaps) = measured(&run);
    assert!(gaps.is_empty(), "{gaps:?}");
    assert_eq!(observations.len(), 2, "{observations:?}");

    let inside = observation_named(observations, "inside.exe");
    assert_eq!(text(inside, "identity_read"), Some("read"), "{inside:?}");
    assert_eq!(flag(inside, "on_system_drive"), Some(true), "{inside:?}");
    assert_eq!(flag(inside, "under_system_root"), Some(true), "{inside:?}");

    let outside = observation_named(observations, "outside.exe");
    assert_eq!(text(outside, "identity_read"), Some("read"), "{outside:?}");
    assert_eq!(flag(outside, "on_system_drive"), Some(false), "{outside:?}");
    assert_eq!(
        flag(outside, "under_system_root"),
        Some(false),
        "{outside:?}"
    );

    let without_roots = host(
        "env:\n  WinDir: 'C:\\Windows'\n",
        &[r"C:\Tools\unknown.exe"],
        None,
        "  - pid: 4\n    name: System\n  - pid: 5\n    name: unknown.exe\n    path: 'C:\\Tools\\unknown.exe'\n",
        &[(r"C:\Tools", "unknown.exe")],
    );
    let run = collector.collect(&without_roots);
    let (observations, gaps) = measured(&run);
    assert!(gaps.is_empty(), "{gaps:?}");
    let observation = observation_named(observations, "unknown.exe");
    assert_eq!(text(observation, "identity_read"), Some("read"));
    assert_eq!(
        flag(observation, "on_system_drive"),
        None,
        "{observation:?}"
    );
    assert_eq!(
        flag(observation, "under_system_root"),
        None,
        "{observation:?}"
    );
}

/// One test-only rule, so that a scan has something to report the collector's tier on. No rule ships
/// with this collector in C1.
fn rule_on_recorded_files() -> Bundle {
    let yaml = r#"
id: 1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d
title: Test rule for recorded_files
description: A test-only rule so a scan reports the recorded_files collector's tier.
status: experimental
collector: recorded_files
strength: context
match:
  identity_read: read
retention: The scan.
falsepositives:
  - A test fixture.
author: aeterna-rongroi contributors
date: 2026-10-21
"#;
    let json = serde_json::json!({
        "rules": [{
            "path": "recorded_files/test/consent/rule.yaml",
            "yaml": yaml,
        }],
        "i18n": [],
        "ages": [],
    });
    Bundle::from_bundle_json(&json.to_string()).unwrap()
}

/// (k4) The collector is `full`, it is in the core's order, and a standard scan reports it
/// `not_consented` rather than calling it.
#[test]
fn k4_the_collector_is_full_tier_and_a_standard_scan_reports_it_not_consented() {
    let collector = recorded_files();
    assert_eq!(collector.tier(), ScanTier::Full);
    assert!(
        view::COLLECTOR_ORDER.contains(&"recorded_files"),
        "recorded_files is missing from COLLECTOR_ORDER"
    );

    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/hosts")
        .join("secure-boot-off");
    let host = FixtureHost::load(&dir).unwrap();
    let report = scan::run(
        &host,
        &rule_on_recorded_files(),
        ScanContext {
            provenance: Provenance::from_parts(None, "0.0.0-test", None, None),
            generated_at: "2026-01-01T00:00:00Z".to_owned(),
            self_identity: SelfIdentity::default(),
            tier: ScanTier::Standard,
        },
    );

    let evidence = report
        .evidence
        .iter()
        .find(|evidence| evidence.collector == "recorded_files")
        .unwrap_or_else(|| panic!("no evidence for recorded_files: {:?}", report.evidence));
    assert!(
        matches!(
            evidence.state,
            EvidenceState::Unmeasured {
                reason: UnmeasuredReason::NotConsented,
                expected: true,
            }
        ),
        "{:?}",
        evidence.state
    );
}
