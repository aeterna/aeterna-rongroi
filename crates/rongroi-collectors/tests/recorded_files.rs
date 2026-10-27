// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! C1 and C2 acceptance tests for `recorded_files`: discovery, identity fields, budget and order,
//! and `bam`'s presence check (ADR 0079 amendment 7).

#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::PathBuf;
use std::time::Duration;

use rongroi_collectors::bam::Bam;
use rongroi_collectors::recorded_files::RecordedFiles;
use rongroi_collectors::scan::{self, ScanContext};
use rongroi_collectors::{Collector, all};
use rongroi_core::bundle::Bundle;
use rongroi_core::engine::SelfIdentity;
use rongroi_core::model::{
    CollectorRun, EvidenceState, Mode, Observation, ScanTier, SensitiveKind, UnmeasuredReason,
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
        .unwrap()
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
    FixtureHost::from_yaml_str(
        &host_yaml(env, bam_paths, pca_line, processes, files),
        "inline",
    )
    .unwrap()
}

/// The YAML [`host`] describes, before a `usn_journal:` block is appended by [`with_usn_journal`].
fn host_yaml(
    env: &str,
    bam_paths: &[&str],
    pca_line: Option<&str>,
    processes: &str,
    files: &[(&str, &str)],
) -> String {
    let mut yaml = String::from("platform: windows\nos_build: \"26100\"\n");
    yaml.push_str(env);
    yaml.push_str("registry:\n");
    let _ = writeln!(
        yaml,
        "  '{BAM_KEY}':\n    Version: 1\n    SequenceNumber: 1"
    );
    for path in bam_paths {
        let _ = writeln!(
            yaml,
            "    '{path}':\n      content: '012345678901234567890123'"
        );
    }
    yaml.push_str("filesystem:\n");
    let _ = writeln!(yaml, "  '{PCA_DIR}':\n    - name: PcaAppLaunchDic.txt");
    match pca_line {
        Some(line) => {
            yaml.push_str("      content: |\n        ");
            yaml.push_str(line);
            yaml.push('\n');
        }
        None => yaml.push_str("      content: ''\n"),
    }
    for (dir, name) in files {
        let _ = writeln!(
            yaml,
            "  '{dir}':\n    - name: '{name}'\n      content: 'fixture bytes'"
        );
    }
    yaml.push_str("processes:\n");
    yaml.push_str(processes);
    yaml
}

/// Appends a `usn_journal:` block for the system volume to `yaml` and builds the host. `folders` are
/// path → number pairs; `other_volume` names the folders among them whose identifier carries another
/// volume's serial, as a junction's does; `records` is one record group each, as a YAML flow mapping
/// in the fixture's `records:` shape; `extra` is any further journal keys (`state:`, `ends:`), as YAML
/// lines indented two spaces.
fn with_usn_journal(
    mut yaml: String,
    folders: &[(&str, u64)],
    other_volume: &[&str],
    records: &[&str],
    extra: &str,
) -> FixtureHost {
    yaml.push_str("usn_journal:\n");
    yaml.push_str(extra);
    yaml.push_str("  folders:\n");
    for (path, number) in folders {
        let _ = writeln!(yaml, "    '{path}': {number}");
    }
    if !other_volume.is_empty() {
        yaml.push_str("  other_volume_folders:\n");
        for path in other_volume {
            let _ = writeln!(yaml, "    - '{path}'");
        }
    }
    yaml.push_str("  records:\n");
    for record in records {
        let _ = writeln!(yaml, "    - {record}");
    }
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
    let _ = writeln!(
        yaml,
        "  '{BAM_KEY}':\n    Version: 1\n    SequenceNumber: 1"
    );
    for (path, value) in values {
        let _ = writeln!(yaml, "    '{path}':\n      {value}");
    }
    yaml.push_str("filesystem:\n");
    let _ = writeln!(
        yaml,
        "  '{PCA_DIR}':\n    - name: PcaAppLaunchDic.txt\n      content: ''"
    );
    yaml.push_str(files);
    yaml.push_str("processes:\n  - pid: 4\n    name: System\n");
    FixtureHost::from_yaml_str(&yaml, "inline").unwrap()
}

/// A PE32 executable carrying a version resource whose `OriginalFilename` is `loader.exe`, as hex so
/// a fixture can describe bytes YAML cannot hold. Built from the same fields the parser's own tests
/// use: MZ, `PE\0\0`, one `.rsrc` section, and the four-level resource tree down to `RT_VERSION`.
const PE_HEX: &str = concat!(
    "4d5a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
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

fn measured_parts(
    run: &CollectorRun,
) -> Option<(&[Observation], &BTreeMap<String, UnmeasuredReason>)> {
    if let CollectorRun::Measured {
        observations, gaps, ..
    } = run
    {
        Some((observations, gaps))
    } else {
        None
    }
}

fn measured(run: &CollectorRun) -> (&[Observation], &BTreeMap<String, UnmeasuredReason>) {
    measured_parts(run).unwrap()
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

/// The six fields the change journal feeds (ADR 0086 section 3). A gap on one of them is about the
/// journal, not the file, so a test about the other fields ignores it.
const JOURNAL_FIELDS: [&str; 6] = [
    "journal_match",
    "journal_deleted",
    "journal_renamed_from",
    "journal_renamed_to",
    "journal_more",
    "journal_from",
];

/// The gaps on fields other than the journal's. A host with no `usn_journal:` block gaps the journal
/// fields for its whole run, which says nothing about the sources a test describes.
fn non_journal_gaps(
    gaps: &BTreeMap<String, UnmeasuredReason>,
) -> Vec<(&String, &UnmeasuredReason)> {
    gaps.iter()
        .filter(|(field, _)| !JOURNAL_FIELDS.contains(&field.as_str()))
        .collect()
}

fn observation_named<'a>(observations: &'a [Observation], name: &str) -> &'a Observation {
    let found = observations.iter().find(|observation| {
        text(observation, "name").is_some_and(|seen| seen.eq_ignore_ascii_case(name))
    });
    assert!(
        found.is_some(),
        "no observation named {name}: {observations:?}"
    );
    found.unwrap()
}

/// (k1) The same file recorded by BAM and PCA in two cases is one observation, and both sources are
/// named on it.
#[test]
fn k1_the_same_file_in_bam_and_pca_in_different_case_is_one_observation() {
    let fixture = host(
        "env:\n  WinDir: 'C:\\Windows'\n  SystemDrive: 'C:'\n  SystemRoot: 'C:\\Windows'\n",
        &[r"C:\Program Files\Fixture\Shared.exe"],
        Some(r"c:\program files\fixture\shared.exe|2026-09-12 10:23:46"),
        "  - pid: 4\n    name: System\n",
        &[(r"C:\Program Files\Fixture", "Shared.exe")],
    );

    let collector = recorded_files();
    let run = collector.collect(&fixture);
    let (observations, gaps) = measured(&run);

    assert!(non_journal_gaps(gaps).is_empty(), "{gaps:?}");
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

    assert!(non_journal_gaps(gaps).is_empty(), "{gaps:?}");
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
    assert!(non_journal_gaps(gaps).is_empty(), "{gaps:?}");
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
    assert!(non_journal_gaps(gaps).is_empty(), "{gaps:?}");
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
    let yaml = r"
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
";
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
        "  'C:\\Users\\fixtureuser\\Downloads':\n    - name: 'downloaded.exe'\n      content_hex: \"{PE_HEX}\"\n      sha256: \"{PE_SHA256}\"\n      zone_identifier: \"[ZoneTransfer]\\r\\nZoneId=3\\r\\nHostUrl=https://dl.example.com/a/b.exe?t=1\\r\\n\"\n"
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
/// nearest the newest `FiveM` record goes first, so the newest record's own path is read and the
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

/// (k9) A rejected or undelimited PCA line loses no parsed path: the launch entries the PCA collector
/// itself emits are kept, the source is reported `partial`, and the rejected line's text never
/// becomes a path (ADR 0079 amendment 7, Q3 M5 and M6).
#[test]
fn k9_rejected_pca_lines_keep_the_parsed_paths_and_gap_the_source_as_partial() {
    let fixture = FixtureHost::from_yaml_str(
        r#"
platform: windows
os_build: "26100"
env:
  WinDir: 'C:\Windows'
registry:
  'HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\S-1-5-21-0-0-0-1001':
    Version: 1
    SequenceNumber: 1
filesystem:
  'C:\Windows\appcompat\pca':
    - name: PcaAppLaunchDic.txt
      content: |
        C:\Users\fixtureuser\Downloads\good.exe|2026-09-12 10:23:46
        this line has no delimiter at all
        C:\Users\fixtureuser\Downloads\second.exe|2026-13-45 99:99:99
        |2026-09-12 10:23:46
        C:\Users\fixtureuser\Downloads\last.exe|2026-09-12 11:00:00
processes:
  - pid: 4
    name: System
"#,
        "inline",
    )
    .unwrap();

    let run = recorded_files().collect(&fixture);
    let (observations, gaps) = measured(&run);

    for name in ["good.exe", "last.exe"] {
        assert!(
            observations
                .iter()
                .any(|observation| text(observation, "name") == Some(name)),
            "the parsed path {name} must survive the rejected lines: {observations:?}"
        );
    }
    assert!(
        observations.iter().all(|observation| !matches!(
            text(observation, "name"),
            Some("second.exe" | "this line has no delimiter at all")
        )),
        "a rejected line's text must never become a path: {observations:?}"
    );
    // This fixture has no change journal, so the six journal fields carry the journal's own gap, which
    // is not PCA's partial reason (ADR 0086 section 4). The PCA gap is on the other fields.
    let source_gaps = non_journal_gaps(gaps);
    assert!(
        source_gaps
            .iter()
            .all(|(_, reason)| **reason == UnmeasuredReason::Partial),
        "{gaps:?}"
    );
    assert!(
        !source_gaps.is_empty(),
        "a partly read PCA file is a gap: {gaps:?}"
    );
}

/// (k10) `not_on_this_os` is PCA's answer for a Windows that never kept these files, not a reason
/// `recorded_files` reports, and PCA adds neither a path nor a gap when it says it (ADR 0030, Q3).
#[test]
fn k10_not_on_this_os_is_pca_only_and_adds_no_gap() {
    let collector = recorded_files();
    assert!(
        !collector
            .unmeasured_reasons()
            .contains(&UnmeasuredReason::NotOnThisOs),
        "recorded_files must not report PCA's not_on_this_os"
    );

    let fixture = FixtureHost::from_yaml_str(
        &format!(
            r#"platform: windows
os_build: "19045"
env:
  WinDir: 'C:\Windows'
registry:
  '{BAM_KEY}':
    Version: 1
    SequenceNumber: 1
filesystem:
  'C:\Windows\appcompat\pca': []
processes:
  - pid: 4
    name: System
"#
        ),
        "inline",
    )
    .unwrap();

    let run = collector.collect(&fixture);
    let (observations, gaps) = measured(&run);
    assert!(observations.is_empty(), "{observations:?}");
    assert!(non_journal_gaps(gaps).is_empty(), "{gaps:?}");
}

/// (k11) A run whose every source is unmeasured is `Unmeasured` with the first source's reason, not
/// a `Measured` run with no observation (Q3 m4).
#[test]
fn k11_a_run_with_no_readable_source_is_unmeasured_with_the_first_reason() {
    let fixture = FixtureHost::from_yaml_str("platform: windows\n", "inline").unwrap();
    assert_eq!(
        recorded_files().collect(&fixture),
        CollectorRun::Unmeasured {
            collector: "recorded_files".to_owned(),
            reason: UnmeasuredReason::SourceAbsent,
        }
    );
}

/// (k12) The budget clock starts before the source reads: a source read that spends the budget
/// leaves the identity reads with `budget_spent` (Q3 m1).
#[test]
fn k12_the_budget_clock_starts_before_the_source_reads() {
    // A long process list is a source read that takes measurably longer than the budget, and it
    // yields no path of its own, so the only path read is the PCA one.
    let mut yaml = format!(
        "platform: windows\nos_build: \"26100\"\nenv:\n  WinDir: 'C:\\Windows'\nregistry:\n  '{BAM_KEY}':\n    Version: 1\n    SequenceNumber: 1\nfilesystem:\n  'C:\\Windows\\appcompat\\pca':\n    - name: PcaAppLaunchDic.txt\n      content: |\n        C:\\Users\\fixtureuser\\Downloads\\after-source.exe|2026-09-12 10:23:46\n  'C:\\Users\\fixtureuser\\Downloads':\n    - name: after-source.exe\n      content: 'fixture bytes'\nprocesses:\n"
    );
    for pid in 0..40_000 {
        let _ = writeln!(yaml, "  - pid: {pid}\n    name: System");
    }
    let fixture = FixtureHost::from_yaml_str(&yaml, "inline").unwrap();

    let run = RecordedFiles {
        budget: Duration::from_millis(5),
        ..RecordedFiles::default()
    }
    .collect(&fixture);
    let (observations, _) = measured(&run);
    let observation = observation_named(observations, "after-source.exe");
    assert_eq!(
        text(observation, "identity_read"),
        Some("budget_spent"),
        "the source read must count against the budget: {observation:?}"
    );
}

/// (k13) The newest-time anchor accepts each GTA V program name as well as `FiveM`'s, so the read
/// order centres on the newest of either (Q3 m5).
#[test]
fn k13_the_ordering_anchor_accepts_the_gta_v_names() {
    const NEAR: &str = r"C:\Users\fixtureuser\Downloads\Near.exe";
    const NEWEST: &str = r"C:\Users\fixtureuser\Downloads\Newest.exe";
    for name in [
        "fivem.exe",
        "fivem_b2699_gtaprocess.exe",
        "gta5.exe",
        "gta5_enhanced.exe",
        "playgtav.exe",
    ] {
        let anchor = format!(r"C:\Program Files\Rockstar Games\Grand Theft Auto V\{name}");
        let files = format!(
            "  'C:\\Users\\fixtureuser\\Downloads':\n    - name: Near.exe\n      content: 'fixture bytes'\n    - name: Newest.exe\n      content: 'fixture bytes'\n  'C:\\Program Files\\Rockstar Games\\Grand Theft Auto V':\n    - name: '{name}'\n      content: 'fixture bytes'\n"
        );
        let fixture = bam_host(
            "env:\n  WinDir: 'C:\\Windows'\n  SystemDrive: 'C:'\n  SystemRoot: 'C:\\Windows'\n",
            &[
                // The anchor at 2026-01-01T00:00:00Z, Near five minutes before it, Newest two hours
                // after.
                (anchor.as_str(), "content_hex: \"00008192b17adc01\""),
                (NEAR, "content_hex: \"00a2b0dfb07adc01\""),
                (NEWEST, "content_hex: \"00d00956c27adc01\""),
            ],
            &files,
        );

        let run = RecordedFiles {
            file_limit: Some(1),
            ..RecordedFiles::default()
        }
        .collect(&fixture);
        let (observations, _) = measured(&run);
        let anchor = observation_named(observations, name);
        assert_eq!(
            text(anchor, "identity_read"),
            Some("read"),
            "the newest {name} time must anchor the order: {anchor:?}"
        );
        for other in ["Near.exe", "Newest.exe"] {
            let observation = observation_named(observations, other);
            assert_eq!(
                text(observation, "identity_read"),
                Some("budget_spent"),
                "{other} must not be read before the anchor: {observation:?}"
            );
        }
    }
}

/// (k14) An observation no rule matched is listed in Self mode and only counted in SS mode: Self mode
/// shows the file and its download host, SS mode shows neither and counts the observation in
/// `hidden.unmatched` (the same check `bam_entries_present_ss_view` makes for `bam`).
#[test]
fn k14_an_unmatched_recorded_file_is_listed_in_self_mode_and_only_counted_in_ss_mode() {
    let path = r"C:\Users\fixtureuser\Downloads\downloaded.exe";
    let files = format!(
        "  'C:\\Users\\fixtureuser\\Downloads':\n    - name: 'downloaded.exe'\n      content_hex: \"{PE_HEX}\"\n      sha256: \"{PE_SHA256}\"\n      zone_identifier: \"[ZoneTransfer]\\r\\nZoneId=3\\r\\nHostUrl=https://dl.example.com/a/b.exe?t=1\\r\\n\"\n"
    );
    let fixture = bam_host(
        "env:\n  WinDir: 'C:\\Windows'\n  SystemDrive: 'C:'\n  SystemRoot: 'C:\\Windows'\n",
        &[(path, "content_hex: \"0000056936c0d501\"")],
        &files,
    );

    let report = scan::run(
        &fixture,
        &Bundle::embedded().unwrap(),
        ScanContext {
            provenance: Provenance::from_parts(None, "0.0.0-test", None, None),
            generated_at: "2026-01-01T00:00:00Z".to_owned(),
            self_identity: SelfIdentity::default(),
            tier: ScanTier::Full,
        },
    );

    let self_view = view::for_mode(&report, Mode::SelfCheck);
    let self_json = serde_json::to_string(&self_view).unwrap();
    assert!(self_json.contains("downloaded.exe"), "{self_json}");
    assert!(self_json.contains("dl.example.com"), "{self_json}");

    let ss_view = view::for_mode(&report, Mode::Ss);
    let ss_json = serde_json::to_string(&ss_view).unwrap();
    for leaked in [
        "downloaded.exe",
        "fixtureuser",
        "dl.example.com",
        "loader.exe",
        PE_SHA256,
    ] {
        assert!(
            !ss_json.contains(leaked),
            "{leaked} reached the SS view: {ss_json}"
        );
    }
    assert!(ss_view.hidden.unmatched > 0);
}

/// The key Explorer's `UserAssist` entries are read from (ADR 0080 section 1).
const USERASSIST_COUNT_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count";

/// 2020-01-01T00:00:00Z as a `FILETIME`, old enough that these fixtures do not disturb the order.
const USERASSIST_FILETIME: u64 = 132_223_104_000_000_000;

/// ROT13 over ASCII letters only, the form Explorer stores a value name in.
fn rot13(text: &str) -> String {
    text.chars()
        .map(|character| match character {
            'a'..='z' => (((character as u8 - b'a' + 13) % 26) + b'a') as char,
            'A'..='Z' => (((character as u8 - b'A' + 13) % 26) + b'A') as char,
            other => other,
        })
        .collect()
}

/// A 72-byte `UserAssist` entry with `filetime` at offset 60, as hex so a fixture can hold it. Offset
/// 4 is non-zero so that a test can see it never reaches an observation.
fn userassist_entry_hex() -> String {
    let mut bytes = [0_u8; 72];
    bytes[4..8].copy_from_slice(&7_u32.to_le_bytes());
    bytes[60..68].copy_from_slice(&USERASSIST_FILETIME.to_le_bytes());
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// A host whose BAM, PCA and process sources are readable, plus a `UserAssist` `Count` key holding
/// one entry per path when `userassist_paths` is `Some`. `Some(&[])` is an empty key; `None` is the
/// key absent, which is a count of zero rather than a gap (ADR 0080 section 4).
fn userassist_host(
    bam_paths: &[&str],
    processes: &str,
    userassist_paths: Option<&[&str]>,
    files: &[(&str, &str)],
) -> FixtureHost {
    let mut yaml = String::from(
        "platform: windows\nos_build: \"26100\"\nenv:\n  WinDir: 'C:\\Windows'\n  SystemDrive: 'C:'\n  SystemRoot: 'C:\\Windows'\nregistry:\n",
    );
    let _ = writeln!(
        yaml,
        "  '{BAM_KEY}':\n    Version: 1\n    SequenceNumber: 1"
    );
    for path in bam_paths {
        let _ = writeln!(
            yaml,
            "    '{path}':\n      content: '012345678901234567890123'"
        );
    }
    if let Some(paths) = userassist_paths {
        let _ = writeln!(yaml, "  '{USERASSIST_COUNT_KEY}':");
        let entry = userassist_entry_hex();
        for path in paths {
            let _ = writeln!(
                yaml,
                "    '{}':\n      content_hex: \"{entry}\"",
                rot13(path)
            );
        }
    }
    let _ = writeln!(
        yaml,
        "filesystem:\n  '{PCA_DIR}':\n    - name: PcaAppLaunchDic.txt\n      content: ''"
    );
    for (dir, name) in files {
        let _ = writeln!(
            yaml,
            "  '{dir}':\n    - name: '{name}'\n      content: 'fixture bytes'"
        );
    }
    yaml.push_str("processes:\n");
    yaml.push_str(processes);
    FixtureHost::from_yaml_str(&yaml, "inline").unwrap()
}

/// (r1a) A path only `UserAssist` holds is one observation, flagged `by_userassist` and by none of
/// the three older sources (ADR 0080 section 4).
#[test]
fn u4_r1_a_path_only_userassist_holds_is_an_observation() {
    const PATH: &str = r"C:\Users\fixtureuser\Downloads\u4-only.exe";
    let fixture = userassist_host(
        &[],
        "  - pid: 4\n    name: System\n",
        Some(&[PATH]),
        &[(r"C:\Users\fixtureuser\Downloads", "u4-only.exe")],
    );

    let run = recorded_files().collect(&fixture);
    let (observations, gaps) = measured(&run);

    assert!(non_journal_gaps(gaps).is_empty(), "{gaps:?}");
    assert_eq!(observations.len(), 1, "{observations:?}");
    let observation = &observations[0];
    assert_eq!(text(observation, "path"), Some(PATH), "{observation:?}");
    assert_eq!(
        flag(observation, "by_userassist"),
        Some(true),
        "{observation:?}"
    );
    for name in ["by_bam", "by_pca", "by_process"] {
        assert_eq!(flag(observation, name), Some(false), "{observation:?}");
    }
}

/// (r1b) The same path in BAM and `UserAssist`, in different ASCII case, is one observation naming
/// both sources (ADR 0080 section 4).
#[test]
fn u4_r1_a_path_in_bam_and_userassist_names_both_sources() {
    const BAM_PATH: &str = r"C:\Users\fixtureuser\Downloads\u4-both.exe";
    const USERASSIST_PATH: &str = r"c:\users\fixtureuser\downloads\U4-BOTH.EXE";
    let fixture = userassist_host(
        &[BAM_PATH],
        "  - pid: 4\n    name: System\n",
        Some(&[USERASSIST_PATH]),
        &[(r"C:\Users\fixtureuser\Downloads", "u4-both.exe")],
    );

    let run = recorded_files().collect(&fixture);
    let (observations, gaps) = measured(&run);

    assert!(non_journal_gaps(gaps).is_empty(), "{gaps:?}");
    assert_eq!(observations.len(), 1, "{observations:?}");
    let observation = &observations[0];
    assert_eq!(flag(observation, "by_bam"), Some(true), "{observation:?}");
    assert_eq!(
        flag(observation, "by_userassist"),
        Some(true),
        "{observation:?}"
    );
    assert_eq!(flag(observation, "by_pca"), Some(false), "{observation:?}");
    assert_eq!(
        flag(observation, "by_process"),
        Some(false),
        "{observation:?}"
    );
}

/// (r1c) A host with no `UserAssist` key is a source that holds nothing, not a gap, and its absence
/// does not hide the paths another source gave (ADR 0080 section 4).
#[test]
fn u4_r1_an_absent_userassist_key_adds_no_gap() {
    const PATH: &str = r"C:\Users\fixtureuser\Downloads\u4-bam-only.exe";
    let fixture = userassist_host(
        &[PATH],
        "  - pid: 4\n    name: System\n",
        None,
        &[(r"C:\Users\fixtureuser\Downloads", "u4-bam-only.exe")],
    );

    let run = recorded_files().collect(&fixture);
    let (observations, gaps) = measured(&run);

    assert!(non_journal_gaps(gaps).is_empty(), "{gaps:?}");
    let observation = observation_named(observations, "u4-bam-only.exe");
    assert_eq!(flag(observation, "by_bam"), Some(true), "{observation:?}");
    assert_eq!(
        flag(observation, "by_userassist"),
        Some(false),
        "{observation:?}"
    );
}

/// The environment the journal tests run under: `%SystemRoot%` and `%SystemDrive%` name the system
/// volume `C:`, whose journal the fixture describes.
const SYSTEM_ENV: &str =
    "env:\n  WinDir: 'C:\\Windows'\n  SystemDrive: 'C:'\n  SystemRoot: 'C:\\Windows'\n";

/// A process list with only the System process, for tests whose paths come from BAM alone.
const SYSTEM_PROCESS: &str = "  - pid: 4\n    name: System\n";

/// The times in one list field (`journal_deleted` and its siblings), or `None` when it is absent.
fn times<'a>(observation: &'a Observation, name: &str) -> Option<Vec<&'a str>> {
    observation
        .fields
        .get(name)?
        .as_array()?
        .iter()
        .map(serde_json::Value::as_str)
        .collect()
}

/// Asserts a path the journal matched: `journal_match` is `matched`, each list holds exactly the given
/// times, `journal_more` is false and `journal_from` is `from` (ADR 0086 section 3).
fn assert_matched(
    observation: &Observation,
    deleted: &[&str],
    renamed_from: &[&str],
    renamed_to: &[&str],
    from: &str,
) {
    assert_eq!(
        text(observation, "journal_match"),
        Some("matched"),
        "{observation:?}"
    );
    assert_eq!(
        times(observation, "journal_deleted"),
        Some(deleted.to_vec()),
        "{observation:?}"
    );
    assert_eq!(
        times(observation, "journal_renamed_from"),
        Some(renamed_from.to_vec()),
        "{observation:?}"
    );
    assert_eq!(
        times(observation, "journal_renamed_to"),
        Some(renamed_to.to_vec()),
        "{observation:?}"
    );
    assert_eq!(
        flag(observation, "journal_more"),
        Some(false),
        "{observation:?}"
    );
    assert_eq!(
        text(observation, "journal_from"),
        Some(from),
        "{observation:?}"
    );
}

/// Asserts a path the journal did not match: `journal_match` says `reason`, no list and no
/// `journal_more` is emitted, and `journal_from` is `from` (ADR 0086 section 3).
fn assert_unmatched(observation: &Observation, reason: &str, from: &str) {
    assert_eq!(
        text(observation, "journal_match"),
        Some(reason),
        "{observation:?}"
    );
    for name in [
        "journal_deleted",
        "journal_renamed_from",
        "journal_renamed_to",
        "journal_more",
    ] {
        assert_eq!(
            observation.fields.get(name),
            None,
            "{name} must not be emitted: {observation:?}"
        );
    }
    assert_eq!(
        text(observation, "journal_from"),
        Some(from),
        "{observation:?}"
    );
}

/// (j2-1) A file BAM recorded that is gone, in a folder whose journal holds its deletion, is
/// `matched`: the deletion's time is listed, and the journal's first record time is `journal_from`
/// (ADR 0086 sections 2 and 3).
#[test]
fn j2_a_gone_file_whose_deletion_the_journal_holds_is_matched_as_deleted() {
    let fixture = with_usn_journal(
        host_yaml(
            SYSTEM_ENV,
            &[r"C:\Tools\helper.exe"],
            None,
            SYSTEM_PROCESS,
            &[],
        ),
        &[(r"C:\Tools", 1)],
        &[],
        &[
            r"{ parent: 'C:\Tools', reasons: [file_delete, close], name: helper.exe, first: '2026-09-13T09:30:00Z' }",
        ],
        "",
    );

    let run = recorded_files().collect(&fixture);
    let (observations, gaps) = measured(&run);

    assert!(non_journal_gaps(gaps).is_empty(), "{gaps:?}");
    let observation = observation_named(observations, "helper.exe");
    assert_eq!(
        text(observation, "identity_read"),
        Some("missing"),
        "{observation:?}"
    );
    assert_matched(
        observation,
        &["2026-09-13T09:30:00Z"],
        &[],
        &[],
        "2026-09-13T09:30:00Z",
    );
}

/// (j2-2) An old-name rename record matches a target by its parent folder and its name, ignoring
/// ASCII case, so `HELPER.EXE` in the folder is the file BAM recorded (ADR 0086 section 2).
#[test]
fn j2_a_rename_away_from_the_name_in_the_parent_folder_is_matched_as_renamed_from() {
    let fixture = with_usn_journal(
        host_yaml(
            SYSTEM_ENV,
            &[r"C:\Tools\helper.exe"],
            None,
            SYSTEM_PROCESS,
            &[],
        ),
        &[(r"C:\Tools", 1)],
        &[],
        &[
            r"{ parent: 'C:\Tools', reasons: [rename_old_name, close], name: HELPER.EXE, first: '2026-09-14T10:00:00Z' }",
        ],
        "",
    );

    let run = recorded_files().collect(&fixture);
    let (observations, gaps) = measured(&run);

    assert!(non_journal_gaps(gaps).is_empty(), "{gaps:?}");
    let observation = observation_named(observations, "helper.exe");
    assert_matched(
        observation,
        &[],
        &["2026-09-14T10:00:00Z"],
        &[],
        "2026-09-14T10:00:00Z",
    );
}

/// (j2-3) A new-name rename record matches a target the same way, and lists under
/// `journal_renamed_to` (ADR 0086 sections 2 and 3).
#[test]
fn j2_a_rename_to_the_name_in_the_parent_folder_is_matched_as_renamed_to() {
    let fixture = with_usn_journal(
        host_yaml(
            SYSTEM_ENV,
            &[r"C:\Tools\helper.exe"],
            None,
            SYSTEM_PROCESS,
            &[],
        ),
        &[(r"C:\Tools", 1)],
        &[],
        &[
            r"{ parent: 'C:\Tools', reasons: [rename_new_name, close], name: HELPER.EXE, first: '2026-09-14T10:00:01Z' }",
        ],
        "",
    );

    let run = recorded_files().collect(&fixture);
    let (observations, gaps) = measured(&run);

    assert!(non_journal_gaps(gaps).is_empty(), "{gaps:?}");
    let observation = observation_named(observations, "helper.exe");
    assert_matched(
        observation,
        &[],
        &[],
        &["2026-09-14T10:00:01Z"],
        "2026-09-14T10:00:01Z",
    );
}

/// (j2-4) A record whose own file reference is the target's matches it under any name, even when its
/// parent is another folder and its name is different: the file still exists under the name it had
/// then (ADR 0086 section 2).
#[test]
fn j2_a_rename_of_a_file_that_still_exists_is_matched_by_its_own_reference() {
    let fixture = with_usn_journal(
        host_yaml(
            SYSTEM_ENV,
            &[r"C:\Tools\helper.exe"],
            None,
            SYSTEM_PROCESS,
            &[(r"C:\Tools", "helper.exe")],
        ),
        &[
            (r"C:\Tools", 1),
            (r"C:\Tools\helper.exe", 2),
            (r"C:\Users\fixtureuser\Downloads", 3),
        ],
        &[],
        &[
            r"{ parent: 'C:\Users\fixtureuser\Downloads', file: 'C:\Tools\helper.exe', reasons: [rename_old_name, close], name: other.exe, first: '2026-09-14T10:00:00Z' }",
        ],
        "",
    );

    let run = recorded_files().collect(&fixture);
    let (observations, gaps) = measured(&run);

    assert!(non_journal_gaps(gaps).is_empty(), "{gaps:?}");
    let observation = observation_named(observations, "helper.exe");
    assert_eq!(
        text(observation, "identity_read"),
        Some("read"),
        "{observation:?}"
    );
    assert_matched(
        observation,
        &[],
        &["2026-09-14T10:00:00Z"],
        &[],
        "2026-09-14T10:00:00Z",
    );
}

/// (j2-5) A path on another drive letter than the system volume is `other_volume`: the journal of
/// `C:` holds nothing about it, even a deletion of the same name in a folder of `C:` (ADR 0086
/// section 2).
#[test]
fn j2_a_path_on_another_drive_is_other_volume_and_lists_nothing() {
    let fixture = with_usn_journal(
        host_yaml(
            SYSTEM_ENV,
            &[r"D:\Tools\outside.exe"],
            None,
            SYSTEM_PROCESS,
            &[],
        ),
        &[(r"C:\Tools", 1)],
        &[],
        &[
            r"{ parent: 'C:\Tools', reasons: [file_delete, close], name: outside.exe, first: '2026-09-13T09:30:00Z' }",
        ],
        "",
    );

    let run = recorded_files().collect(&fixture);
    let (observations, gaps) = measured(&run);

    assert!(non_journal_gaps(gaps).is_empty(), "{gaps:?}");
    let observation = observation_named(observations, "outside.exe");
    assert_unmatched(observation, "other_volume", "2026-09-13T09:30:00Z");
}

/// (j2-6) A folder listed in `other_volume_folders` is reached through a junction to another volume,
/// so its records are not credited to a file in it: the path is `other_volume` (ADR 0086 section 2).
#[test]
fn j2_a_file_in_a_folder_on_another_volume_is_other_volume_and_lists_nothing() {
    let fixture = with_usn_journal(
        host_yaml(
            SYSTEM_ENV,
            &[r"C:\Junction\helper.exe"],
            None,
            SYSTEM_PROCESS,
            &[],
        ),
        &[(r"C:\Tools", 1), (r"C:\Junction", 2)],
        &[r"C:\Junction"],
        &[
            r"{ parent: 'C:\Junction', reasons: [file_delete, close], name: helper.exe, first: '2026-09-13T09:30:00Z' }",
        ],
        "",
    );

    let run = recorded_files().collect(&fixture);
    let (observations, gaps) = measured(&run);

    assert!(non_journal_gaps(gaps).is_empty(), "{gaps:?}");
    let observation = observation_named(observations, "helper.exe");
    assert_unmatched(observation, "other_volume", "2026-09-13T09:30:00Z");
}

/// (j2-7) A file whose folder is not under `folders:` cannot be identified, so it is
/// `folder_unknown`, and a same-named deletion in another folder does not match it (ADR 0086
/// section 2).
#[test]
fn j2_a_file_in_a_folder_the_journal_does_not_name_is_folder_unknown() {
    let fixture = with_usn_journal(
        host_yaml(
            SYSTEM_ENV,
            &[r"C:\Unlisted\helper.exe"],
            None,
            SYSTEM_PROCESS,
            &[],
        ),
        &[(r"C:\Tools", 1)],
        &[],
        &[
            r"{ parent: 'C:\Tools', reasons: [file_delete, close], name: helper.exe, first: '2026-09-13T09:30:00Z' }",
        ],
        "",
    );

    let run = recorded_files().collect(&fixture);
    let (observations, gaps) = measured(&run);

    assert!(non_journal_gaps(gaps).is_empty(), "{gaps:?}");
    let observation = observation_named(observations, "helper.exe");
    assert_unmatched(observation, "folder_unknown", "2026-09-13T09:30:00Z");
}

/// One deletion of `helper.exe` in `C:\Tools`, written at 09:30 on 2026-09-13.
const DELETE_HELPER: &str = r"{ parent: 'C:\Tools', reasons: [file_delete, close], name: helper.exe, first: '2026-09-13T09:30:00Z' }";

/// A host with `helper.exe` on disk and BAM's record of it, whose journal is `DELETE_HELPER` alone.
/// `top` is YAML written before the rest of the host (`elevated:`), and `extra` the journal's own
/// keys (`state:`, `ends:`), as [`with_usn_journal`] takes them.
fn helper_deletion_host(top: &str, extra: &str) -> FixtureHost {
    with_usn_journal(
        format!(
            "{top}{}",
            host_yaml(
                SYSTEM_ENV,
                &[r"C:\Tools\helper.exe"],
                None,
                SYSTEM_PROCESS,
                &[(r"C:\Tools", "helper.exe")],
            )
        ),
        &[(r"C:\Tools", 1)],
        &[],
        &[DELETE_HELPER],
        extra,
    )
}

/// Asserts each of the six journal fields is gapped with `reason` (ADR 0086 section 4).
fn assert_journal_gapped(gaps: &BTreeMap<String, UnmeasuredReason>, reason: UnmeasuredReason) {
    for field in JOURNAL_FIELDS {
        assert_eq!(gaps.get(field), Some(&reason), "{field}: {gaps:?}");
    }
}

/// Asserts no observation carries any of the six journal fields.
fn assert_no_journal_field(observations: &[Observation]) {
    for observation in observations {
        for field in JOURNAL_FIELDS {
            assert_eq!(
                observation.fields.get(field),
                None,
                "{field} must not be emitted: {observation:?}"
            );
        }
    }
}

/// (j2-8) A list keeps at most eight times, the newest first, and `journal_more` says some were cut.
/// Ten deletions of one file, written an hour apart, list 09:00 down to 02:00, and the journal's first
/// record time is 00:00 (ADR 0086 section 3).
#[test]
fn j2_a_list_keeps_the_eight_newest_times_newest_first_and_says_more_were_cut() {
    let records: Vec<String> = (0..10)
        .map(|hour| {
            format!(
                r"{{ parent: 'C:\Tools', reasons: [file_delete, close], name: helper.exe, first: '2026-09-13T{hour:02}:00:00Z' }}"
            )
        })
        .collect();
    let record_refs: Vec<&str> = records.iter().map(String::as_str).collect();
    let fixture = with_usn_journal(
        host_yaml(
            SYSTEM_ENV,
            &[r"C:\Tools\helper.exe"],
            None,
            SYSTEM_PROCESS,
            &[],
        ),
        &[(r"C:\Tools", 1)],
        &[],
        &record_refs,
        "",
    );

    let run = recorded_files().collect(&fixture);
    let (observations, gaps) = measured(&run);

    assert!(non_journal_gaps(gaps).is_empty(), "{gaps:?}");
    let observation = observation_named(observations, "helper.exe");
    let newest_first: Vec<String> = (2..10)
        .rev()
        .map(|hour| format!("2026-09-13T{hour:02}:00:00Z"))
        .collect();
    let deleted: Vec<&str> = newest_first.iter().map(String::as_str).collect();
    assert_eq!(
        text(observation, "journal_match"),
        Some("matched"),
        "{observation:?}"
    );
    assert_eq!(
        times(observation, "journal_deleted"),
        Some(deleted),
        "{observation:?}"
    );
    assert_eq!(
        times(observation, "journal_renamed_from"),
        Some(Vec::new()),
        "{observation:?}"
    );
    assert_eq!(
        times(observation, "journal_renamed_to"),
        Some(Vec::new()),
        "{observation:?}"
    );
    assert_eq!(
        flag(observation, "journal_more"),
        Some(true),
        "{observation:?}"
    );
    assert_eq!(
        text(observation, "journal_from"),
        Some("2026-09-13T00:00:00Z"),
        "{observation:?}"
    );
}

/// (j2-9) A journal that is not active gaps the six journal fields as `source_absent` and emits none
/// of them; the file's own identity is read as before (ADR 0086 section 4).
#[test]
fn j2_a_journal_that_is_not_active_gaps_the_six_fields_as_source_absent() {
    let fixture = helper_deletion_host("", "  state: not_active\n");

    let run = recorded_files().collect(&fixture);
    let (observations, gaps) = measured(&run);

    assert!(non_journal_gaps(gaps).is_empty(), "{gaps:?}");
    assert_journal_gapped(gaps, UnmeasuredReason::SourceAbsent);
    assert_no_journal_field(observations);
    let observation = observation_named(observations, "helper.exe");
    assert_eq!(
        text(observation, "identity_read"),
        Some("read"),
        "{observation:?}"
    );
}

/// (j2-10) A journal whose handle Windows refuses, on an elevated host, gaps the six journal fields as
/// `access_denied`, and the file's identity is unchanged (ADR 0086 section 4).
#[test]
fn j2_a_refused_journal_on_an_elevated_host_gaps_the_six_fields_as_access_denied() {
    let fixture = helper_deletion_host("elevated: true\n", "  state: access_denied\n");

    let run = recorded_files().collect(&fixture);
    let (observations, gaps) = measured(&run);

    assert!(non_journal_gaps(gaps).is_empty(), "{gaps:?}");
    assert_journal_gapped(gaps, UnmeasuredReason::AccessDenied);
    assert_no_journal_field(observations);
    let observation = observation_named(observations, "helper.exe");
    assert_eq!(
        text(observation, "identity_read"),
        Some("read"),
        "{observation:?}"
    );
}

/// (j2-11) A journal that changed while it was read is `partial`: the path is still matched, but no
/// list is emitted, because a list read from a changing journal is not the whole of it (ADR 0086
/// sections 3 and 4).
#[test]
fn j2_a_journal_that_changed_while_read_is_partial_and_lists_nothing() {
    let fixture = helper_deletion_host("", "  ends: journal_changed\n");

    let run = recorded_files().collect(&fixture);
    let (observations, gaps) = measured(&run);

    assert!(non_journal_gaps(gaps).is_empty(), "{gaps:?}");
    assert_journal_gapped(gaps, UnmeasuredReason::Partial);
    let observation = observation_named(observations, "helper.exe");
    assert_eq!(
        text(observation, "journal_match"),
        Some("matched"),
        "{observation:?}"
    );
    for field in [
        "journal_deleted",
        "journal_renamed_from",
        "journal_renamed_to",
    ] {
        assert_eq!(observation.fields.get(field), None, "{observation:?}");
    }
    assert_eq!(flag(observation, "journal_more"), None, "{observation:?}");
    assert_eq!(
        text(observation, "identity_read"),
        Some("read"),
        "{observation:?}"
    );
}

/// (j2-12) A journal read that the journal budget stops is `budget_spent` for the six fields, with no
/// list (ADR 0086 sections 3 and 4).
#[test]
fn j2_a_journal_read_the_journal_budget_stops_is_budget_spent() {
    let fixture = helper_deletion_host("", "");

    let run = RecordedFiles {
        journal_budget: Duration::ZERO,
        ..RecordedFiles::default()
    }
    .collect(&fixture);
    let (observations, gaps) = measured(&run);

    assert!(non_journal_gaps(gaps).is_empty(), "{gaps:?}");
    assert_journal_gapped(gaps, UnmeasuredReason::BudgetSpent);
    let observation = observation_named(observations, "helper.exe");
    assert_eq!(
        observation.fields.get("journal_deleted"),
        None,
        "{observation:?}"
    );
    assert_eq!(
        text(observation, "identity_read"),
        Some("read"),
        "{observation:?}"
    );
}

/// (j2-13) The file budget and the journal budget are separate clocks. With no file budget every
/// identity read says `budget_spent`, yet the journal, which has its own budget, is still read in full
/// and ungapped (ADR 0086 section 3, budget).
#[test]
fn j2_the_file_budget_and_the_journal_budget_never_share_time() {
    let fixture = helper_deletion_host("", "");

    let run = RecordedFiles {
        budget: Duration::ZERO,
        ..RecordedFiles::default()
    }
    .collect(&fixture);
    let (observations, gaps) = measured(&run);

    for field in JOURNAL_FIELDS {
        assert!(
            !gaps.contains_key(field),
            "{field} must not be gapped by the file budget: {gaps:?}"
        );
    }
    let observation = observation_named(observations, "helper.exe");
    assert_eq!(
        text(observation, "identity_read"),
        Some("budget_spent"),
        "{observation:?}"
    );
    assert_matched(
        observation,
        &["2026-09-13T09:30:00Z"],
        &[],
        &[],
        "2026-09-13T09:30:00Z",
    );
}

/// (j2-14) No journal name, USN or file reference reaches the run: twenty deletions of `secret-NN.exe`
/// sit in the same folder as the one that matches, and none of their names is in any output, though
/// the journal was read (ADR 0086 section 8).
#[test]
fn j2_no_journal_name_reaches_the_run() {
    let mut records: Vec<String> = (0..20)
        .map(|number| {
            format!(
                r"{{ parent: 'C:\Tools', reasons: [file_delete, close], name: secret-{number:02}.exe, first: '2026-09-13T09:31:00Z' }}"
            )
        })
        .collect();
    records.push(DELETE_HELPER.to_owned());
    let record_refs: Vec<&str> = records.iter().map(String::as_str).collect();
    let fixture = with_usn_journal(
        host_yaml(
            SYSTEM_ENV,
            &[r"C:\Tools\helper.exe"],
            None,
            SYSTEM_PROCESS,
            &[(r"C:\Tools", "helper.exe")],
        ),
        &[(r"C:\Tools", 1)],
        &[],
        &record_refs,
        "",
    );

    let run = recorded_files().collect(&fixture);
    let (observations, _) = measured(&run);
    assert_matched(
        observation_named(observations, "helper.exe"),
        &["2026-09-13T09:30:00Z"],
        &[],
        &[],
        "2026-09-13T09:30:00Z",
    );
    let json = serde_json::to_string(&run).unwrap();
    assert!(
        !json.contains("secret"),
        "a journal name reached the run: {json}"
    );
}

/// (j2-15) The three lists are timestamp lists kept off the timeline, as `run_times` is (ADR 0086
/// section 6). `journal_from` is a timestamp, `journal_match` text and `journal_more` a boolean.
#[test]
fn j2_the_journal_fields_are_declared_with_their_kinds() {
    let fields = recorded_files().fields();
    let declared = |name: &str| {
        fields
            .iter()
            .find(|field| field.name == name)
            .unwrap_or_else(|| panic!("recorded_files does not declare `{name}`"))
    };
    for name in [
        "journal_deleted",
        "journal_renamed_from",
        "journal_renamed_to",
    ] {
        let field = declared(name);
        assert_eq!(format!("{:?}", field.kind), "TimestampList", "{name}");
        assert!(
            !field.on_timeline,
            "{name} must not put its up to eight times on the timeline"
        );
    }
    assert_eq!(format!("{:?}", declared("journal_from").kind), "Timestamp");
    assert_eq!(format!("{:?}", declared("journal_match").kind), "Text");
    assert_eq!(format!("{:?}", declared("journal_more").kind), "Bool");
}

/// (j2-16) `journal_from` is off the timeline too: it repeats the oldest record time `usn` already
/// puts on the timeline, and a journal gap on a timeline field would leave `recorded_files` among the
/// timeline's unmeasured sources on every scan without a journal (ADR 0086 section 6).
#[test]
fn j2_journal_from_is_declared_off_the_timeline() {
    let fields = recorded_files().fields();
    let field = fields
        .iter()
        .find(|field| field.name == "journal_from")
        .unwrap_or_else(|| panic!("recorded_files does not declare `journal_from`"));
    assert!(
        !field.on_timeline,
        "journal_from must not put the oldest record time on the timeline a second time"
    );
}

/// (j2-17) A PCA source that cannot be read gaps the fields PCA feeds and none of the journal's: the
/// journal is complete here, so its six fields carry no gap, and their lists are emitted (ADR 0086
/// section 4, and "These gaps cover the journal fields only" in section 3).
#[test]
fn j2_a_pca_source_gap_leaves_the_journal_fields_ungapped() {
    let fixture = helper_deletion_host(
        "elevated: true\naccess_denied:\n  - 'C:\\Windows\\appcompat\\pca\\PcaAppLaunchDic.txt'\n",
        "",
    );

    let run = recorded_files().collect(&fixture);
    let (observations, gaps) = measured(&run);

    for field in JOURNAL_FIELDS {
        assert!(
            !gaps.contains_key(field),
            "{field} must not be gapped by PCA: {gaps:?}"
        );
    }
    let source_gaps = non_journal_gaps(gaps);
    assert!(
        !source_gaps.is_empty(),
        "PCA's gap must reach the fields it feeds: {gaps:?}"
    );
    assert!(
        source_gaps
            .iter()
            .all(|(_, reason)| **reason == UnmeasuredReason::AccessDenied),
        "PCA's fields carry PCA's reason: {gaps:?}"
    );
    assert_matched(
        observation_named(observations, "helper.exe"),
        &["2026-09-13T09:30:00Z"],
        &[],
        &[],
        "2026-09-13T09:30:00Z",
    );
}

/// (j2-18) A PCA source whose read fails, with a journal that is refused on a host that is not
/// elevated: the six journal fields carry `not_admin`, the journal's own reason, and the other fields
/// carry PCA's `read_failed`. PCA's file has no bytes recorded, so its read fails as `read_failed`; a
/// refused PCA read on this host would say `not_admin` as well, and could not show the two were kept
/// apart (ADR 0086 section 4).
#[test]
fn j2_a_pca_source_gap_does_not_give_the_journal_fields_its_reason() {
    let yaml = format!(
        r#"platform: windows
os_build: "26100"
elevated: false
{SYSTEM_ENV}registry:
  '{BAM_KEY}':
    Version: 1
    SequenceNumber: 1
    'C:\Tools\helper.exe':
      content: '012345678901234567890123'
filesystem:
  '{PCA_DIR}':
    - name: PcaAppLaunchDic.txt
  'C:\Tools':
    - name: helper.exe
      content: 'fixture bytes'
processes:
{SYSTEM_PROCESS}"#
    );
    let fixture = with_usn_journal(
        yaml,
        &[(r"C:\Tools", 1)],
        &[],
        &[DELETE_HELPER],
        "  state: access_denied\n",
    );

    let run = recorded_files().collect(&fixture);
    let (observations, gaps) = measured(&run);

    assert_journal_gapped(gaps, UnmeasuredReason::NotAdmin);
    let source_gaps = non_journal_gaps(gaps);
    assert!(
        !source_gaps.is_empty()
            && source_gaps
                .iter()
                .all(|(_, reason)| **reason == UnmeasuredReason::ReadFailed),
        "PCA's fields carry PCA's reason: {gaps:?}"
    );
    assert_no_journal_field(observations);
    observation_named(observations, "helper.exe");
}

/// (j2-19) A journal that runs to a second buffer, 501 records, still gives `journal_from` the time of
/// its first record: the first buffer's oldest record is that time, and the second buffer does not
/// change it (ADR 0086 section 3).
#[test]
fn j2_journal_from_is_the_first_record_time_when_the_journal_runs_to_two_buffers() {
    let fixture = with_usn_journal(
        host_yaml(
            SYSTEM_ENV,
            &[r"C:\Tools\helper.exe"],
            None,
            SYSTEM_PROCESS,
            &[],
        ),
        &[(r"C:\Tools", 1)],
        &[],
        &[
            r"{ reasons: [close], count: 501, first: '2026-09-13T08:00:00Z', last: '2026-09-13T10:00:00Z' }",
            DELETE_HELPER,
        ],
        "",
    );

    let run = recorded_files().collect(&fixture);
    let (observations, gaps) = measured(&run);

    assert!(non_journal_gaps(gaps).is_empty(), "{gaps:?}");
    assert_matched(
        observation_named(observations, "helper.exe"),
        &["2026-09-13T09:30:00Z"],
        &[],
        &[],
        "2026-09-13T08:00:00Z",
    );
}

/// (j2-21) A path at a drive root, `C:\root.exe`, is matched by the root folder. The root is answered
/// with NTFS's root directory record, number 5, so the `folders:` entry for `C:\` carries 5 too; the
/// deletion's parent is that entry (ADR 0086 section 2).
#[test]
fn j2_a_path_at_a_drive_root_is_matched_by_the_root_folder() {
    let fixture = with_usn_journal(
        host_yaml(SYSTEM_ENV, &[r"C:\root.exe"], None, SYSTEM_PROCESS, &[]),
        &[(r"C:\", 5)],
        &[],
        &[
            r"{ parent: 'C:\', reasons: [file_delete, close], name: root.exe, first: '2026-09-13T09:30:00Z' }",
        ],
        "",
    );

    let run = recorded_files().collect(&fixture);
    let (observations, gaps) = measured(&run);

    assert!(non_journal_gaps(gaps).is_empty(), "{gaps:?}");
    assert_matched(
        observation_named(observations, "root.exe"),
        &["2026-09-13T09:30:00Z"],
        &[],
        &[],
        "2026-09-13T09:30:00Z",
    );
}

/// (j2-22) A path recorded with `/` separators is matched like the `\` form: its folder is the one the
/// journal names with `\`, so `C:/Tools/helper.exe` is `C:\Tools\helper.exe` to the journal (ADR 0086
/// section 2).
#[test]
fn j2_a_path_recorded_with_slashes_is_matched_like_backslashes() {
    let fixture = with_usn_journal(
        host_yaml(
            SYSTEM_ENV,
            &["C:/Tools/helper.exe"],
            None,
            SYSTEM_PROCESS,
            &[],
        ),
        &[(r"C:\Tools", 1)],
        &[],
        &[DELETE_HELPER],
        "",
    );

    let run = recorded_files().collect(&fixture);
    let (observations, gaps) = measured(&run);

    assert!(non_journal_gaps(gaps).is_empty(), "{gaps:?}");
    assert_matched(
        observation_named(observations, "helper.exe"),
        &["2026-09-13T09:30:00Z"],
        &[],
        &[],
        "2026-09-13T09:30:00Z",
    );
}
