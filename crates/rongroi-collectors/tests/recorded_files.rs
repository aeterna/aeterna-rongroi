// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! C1 and C2 acceptance tests for `recorded_files`: discovery, identity fields, budget and order,
//! and `bam`'s presence check (ADR 0079 amendment 7).

#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::path::PathBuf;

use rongroi_collectors::bam::Bam;
use rongroi_collectors::recorded_files::RecordedFiles;
use rongroi_collectors::scan::{self, ScanContext};
use rongroi_collectors::{Collector, all};
use rongroi_core::bundle::Bundle;
use rongroi_core::engine::SelfIdentity;
use rongroi_core::model::{
    CollectorRun, EvidenceState, Observation, ScanTier, SensitiveKind, UnmeasuredReason,
};
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

/// A host with the same three readable sources as [`host`], whose BAM key holds one value per
/// `(path, value_yaml)`. `value_yaml` is the body written under the path key, so a test can give the
/// value bytes with `content_hex:` — which is how a `FILETIME` reaches a fixture without a binary
/// file. `files` is the YAML body under `filesystem:`.
fn bam_host(env: &str, values: &[(&str, &str)], files: &str) -> FixtureHost {
    let mut yaml = String::from("platform: windows\nos_build: \"26100\"\n");
    yaml.push_str(env);
    yaml.push_str("registry:\n");
    yaml.push_str(&format!(
        "  '{BAM_KEY}':\n    Version: 1\n    SequenceNumber: 1\n"
    ));
    for (path, value) in values {
        yaml.push_str(&format!("    '{path}':\n      {value}\n"));
    }
    yaml.push_str("filesystem:\n");
    yaml.push_str(&format!(
        "  '{PCA_DIR}':\n    - name: PcaAppLaunchDic.txt\n      content: ''\n"
    ));
    yaml.push_str(files);
    yaml.push_str("processes:\n  - pid: 4\n    name: System\n");
    FixtureHost::from_yaml_str(&yaml, "inline").unwrap()
}

/// A PE32 executable carrying a version resource whose `OriginalFilename` is `loader.exe`, as hex so
/// a fixture can describe bytes YAML cannot hold. Built from the same fields the parser's own tests
/// use: MZ, `PE\0\0`, one `.rsrc` section, and the four-level resource tree down to `RT_VERSION`.
const PE_HEX: &str = concat!(
    "4d5a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "000000000000000000000000800000000000000000000000000000000000000000000000000000000000000000000000",
    "000000000000000000000000000000000000000000000000000000000000000050450000648601000000000000000000",
    "00000000e00000000b010000000000000000000000000000000000000000000000000000000000000000000000000000",
    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "000000001000000000000000000000000000000000000000001000003001000000000000000000000000000000000000",
    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "000000000000000000000000000000000000000000000000000000000000000000000000000000002e72737263000000",
    "300100000010000000020000000200000000000000000000000000000000000000000000000000000000000000000000",
    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100",
    "100000001800008000000000000000000000000000000100010000003000008000000000000000000000000000000100",
    "090400004800000058100000d80000000000000000000000d80034000000560053005f00560045005200530049004f00",
    "4e005f0049004e0046004f0000000000bd04effe00000000000000000000000000000000000000000000000000000000",
    "00000000000000000000000000000000000000007c000000010053007400720069006e006700460069006c0065004900",
    "6e0066006f00000058000000010030003400300039003000340042003000000040000b0001004f007200690067006900",
    "6e0061006c00460069006c0065006e0061006d00650000006c006f0061006400650072002e0065007800650000000000",
    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "00000000000000000000000000000000",
);

/// The hash the fixture declares for [`PE_HEX`]; the collector reports what the host gives it.
const PE_SHA256: &str = "1111111111111111111111111111111111111111111111111111111111111111";

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

/// (k5) A PE read from a path BAM recorded carries what its bytes say: `content_kind` and the
/// version resource's `OriginalFilename`, beside the SHA-256 the host gave and the zone the
/// `Zone.Identifier` stream names — `zone_id` and the reduced `download_host`, never the URL.
#[test]
fn k5_a_recorded_pe_carries_its_content_identity_and_zone() {
    let path = r"C:\Users\fixtureuser\Downloads\downloaded.exe";
    let files = format!(
        "  'C:\\Users\\fixtureuser\\Downloads':\n    - name: 'downloaded.exe'\n      content_hex: \"{}\"\n      sha256: \"{}\"\n      zone_identifier: \"[ZoneTransfer]\\r\\nZoneId=3\\r\\nHostUrl=https://dl.example.com/a/b.exe?t=1\\r\\n\"\n",
        PE_HEX, PE_SHA256
    );
    let fixture = bam_host(
        "env:\n  WinDir: 'C:\\Windows'\n  SystemDrive: 'C:'\n  SystemRoot: 'C:\\Windows'\n",
        &[(path, "content_hex: \"0000056936c0d501\"")],
        &files,
    );

    let run = recorded_files().collect(&fixture);
    let (observations, _) = measured(&run);
    let observation = observation_named(observations, "downloaded.exe");

    assert_eq!(
        text(observation, "identity_read"),
        Some("read"),
        "{observation:?}"
    );
    assert_eq!(
        text(observation, "content_kind"),
        Some("pe_executable"),
        "{observation:?}"
    );
    assert_eq!(
        text(observation, "original_filename"),
        Some("loader.exe"),
        "{observation:?}"
    );
    assert_eq!(
        observation
            .fields
            .get("zone_id")
            .and_then(serde_json::Value::as_u64),
        Some(3),
        "{observation:?}"
    );
    assert_eq!(
        text(observation, "download_host"),
        Some("dl.example.com"),
        "{observation:?}"
    );
    assert_eq!(
        text(observation, "sha256"),
        Some(PE_SHA256),
        "{observation:?}"
    );
}

/// (k6) The file limit is checked between paths in the order the collector reads them: the path
/// nearest the newest FiveM record goes first, so the newest record's own path is read and the
/// others say the limit — not the clock — stopped them. The newest record here is `Newest.exe`, so
/// a newest-first order would read that one instead.
#[test]
fn k6_the_file_limit_reads_the_path_nearest_the_newest_fivem_time_first() {
    const FIVEM: &str = r"C:\Users\fixtureuser\AppData\Local\FiveM\FiveM.exe";
    const NEAR: &str = r"C:\Users\fixtureuser\Downloads\Near.exe";
    const NEWEST: &str = r"C:\Users\fixtureuser\Downloads\Newest.exe";
    let files = r"  'C:\Users\fixtureuser\AppData\Local\FiveM':
    - name: FiveM.exe
      content: 'fixture bytes'
  'C:\Users\fixtureuser\Downloads':
    - name: Near.exe
      content: 'fixture bytes'
    - name: Newest.exe
      content: 'fixture bytes'
";
    let fixture = bam_host(
        "env:\n  WinDir: 'C:\\Windows'\n  SystemDrive: 'C:'\n  SystemRoot: 'C:\\Windows'\n",
        &[
            // FiveM at 2026-01-01T00:00:00Z, Near five minutes before it, Newest two hours after.
            (FIVEM, "content_hex: \"00008192b17adc01\""),
            (NEAR, "content_hex: \"00a2b0dfb07adc01\""),
            (NEWEST, "content_hex: \"00d00956c27adc01\""),
        ],
        files,
    );

    let run = RecordedFiles {
        file_limit: Some(1),
        ..RecordedFiles::default()
    }
    .collect(&fixture);
    let (observations, _) = measured(&run);

    let fivem = observation_named(observations, "FiveM.exe");
    assert_eq!(
        text(fivem, "identity_read"),
        Some("read"),
        "the path nearest the newest FiveM time must be the one read: {fivem:?}"
    );
    for name in ["Near.exe", "Newest.exe"] {
        let observation = observation_named(observations, name);
        assert_eq!(
            text(observation, "identity_read"),
            Some("budget_spent"),
            "{name} must not be read after the limit: {observation:?}"
        );
    }
    assert_eq!(
        observations
            .iter()
            .filter(|observation| text(observation, "identity_read") == Some("read"))
            .count(),
        1,
        "a limit of one must stop after one read: {observations:?}"
    );
}

/// (k7) `download_host` is one of the fields SS mode asks about, so the collector must declare it
/// as `SensitiveKind::DownloadHost` — the same kind `powershell_text` uses (ADR 0064, ADR 0079).
#[test]
fn k7_download_host_is_declared_as_a_download_host() {
    let field = recorded_files()
        .fields()
        .iter()
        .find(|field| field.name == "download_host")
        .unwrap_or_else(|| panic!("recorded_files does not declare `download_host`"));
    assert_eq!(
        field.sensitive,
        Some(SensitiveKind::DownloadHost),
        "{field:?}"
    );
}

/// (k8) BAM's presence check asks only the host. A host that cannot answer for an ephemeral path
/// has not said the file is gone, so the observation carries no `disappeared_from_disk` field —
/// neither a claim that it went nor a claim that it is still there (ADR 0079 amendment 7).
#[test]
fn k8_a_host_that_cannot_answer_makes_no_disappeared_claim() {
    let path = r"C:\Users\fixtureuser\AppData\Local\Temp\gone-loader.exe";
    let fixture = FixtureHost::from_yaml_str(
        &format!(
            "platform: windows\naccess_denied:\n  - '{path}'\nregistry:\n  '{BAM_KEY}':\n    Version: 1\n    SequenceNumber: 1\n    '{path}':\n      content: '012345678901234567890123'\n"
        ),
        "inline",
    )
    .unwrap();

    let run = Bam.collect(&fixture);
    let (observations, _) = measured(&run);
    let record = observations
        .iter()
        .find(|observation| text(observation, "name") == Some("gone-loader.exe"))
        .unwrap_or_else(|| panic!("BAM did not report the ephemeral path: {observations:?}"));
    assert_eq!(
        record.fields.get("disappeared_from_disk"),
        None,
        "a host answer that is not `Ok` must not become a claim: {record:?}"
    );
}
