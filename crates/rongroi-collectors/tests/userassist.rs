// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! U2 acceptance tests for the `userassist` collector: names, paths, the account row and the
//! outcomes (ADR 0080 sections 1 and 2, owner decisions 1–3 and 5).

#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::fmt::Write as _;

use rongroi_collectors::userassist::UserAssist;
use rongroi_collectors::{Collector, ScanTier};
use rongroi_core::model::{CollectorRun, Observation, UnmeasuredReason};
use rongroi_host::{FixtureHost, NonWindowsHost};

/// The key holding one value per executable Explorer recorded.
const COUNT_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count";
/// The key holding one value per shortcut Explorer recorded. Only its value names are counted.
const SHORTCUT_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}\Count";
/// Where Windows keeps the account signed in at the keyboard.
const LOGON_UI_KEY: &str = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI";

/// 2020-01-01T00:00:00Z as a `FILETIME`.
const FILETIME_2020: u64 = 132_223_104_000_000_000;

fn measured(run: &CollectorRun) -> (&[Observation], &BTreeMap<String, UnmeasuredReason>) {
    match run {
        CollectorRun::Measured {
            observations, gaps, ..
        } => (observations, gaps),
        CollectorRun::Unmeasured { reason, .. } => {
            panic!("expected a measured run, got {reason:?}")
        }
    }
}

fn field<'a>(observation: &'a Observation, name: &str) -> Option<&'a serde_json::Value> {
    observation.fields.get(name)
}

fn text<'a>(observation: &'a Observation, name: &str) -> Option<&'a str> {
    field(observation, name).and_then(serde_json::Value::as_str)
}

/// The programs Explorer recorded, told apart from the account row by carrying a name.
fn entries(observations: &[Observation]) -> Vec<&Observation> {
    observations
        .iter()
        .filter(|observation| observation.fields.contains_key("name"))
        .collect()
}

/// The one observation that counts what the keys held.
fn account(observations: &[Observation]) -> &Observation {
    observations
        .iter()
        .find(|observation| observation.fields.contains_key("shortcuts"))
        .expect("every measured run has an account row")
}

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

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// A 72-byte entry with `filetime` at offset 60. Offset 4 is non-zero so that a test can see it never
/// reaches an observation.
fn entry_hex(filetime: u64) -> String {
    let mut bytes = [0_u8; 72];
    bytes[4..8].copy_from_slice(&7_u32.to_le_bytes());
    bytes[60..68].copy_from_slice(&filetime.to_le_bytes());
    hex(&bytes)
}

fn entry_body(filetime: u64) -> String {
    format!("content_hex: \"{}\"", entry_hex(filetime))
}

/// The `Count` key with one value per `(name, YAML body)`.
fn count_key(values: &[(&str, String)]) -> String {
    let mut out = format!("  '{COUNT_KEY}':\n");
    for (name, body) in values {
        let _ = writeln!(out, "    '{name}':\n      {body}");
    }
    out
}

/// The shortcuts key with one value per name. The values are never read, only counted.
fn shortcut_key(names: &[&str]) -> String {
    let mut out = format!("  '{SHORTCUT_KEY}':\n");
    for name in names {
        let _ = writeln!(out, "    '{name}': {{}}");
    }
    out
}

fn logon_sid(sid: &str) -> String {
    format!("  '{LOGON_UI_KEY}':\n    LastLoggedOnUserSID: '{sid}'\n")
}

/// A host whose registry is exactly `registry`, with `env` already indented under `env:` and the
/// scan's own SID at the top level when one is given.
fn host_with_registry(
    registry: &str,
    env: &str,
    account_sid: Option<&str>,
    platform: &str,
) -> FixtureHost {
    let mut yaml = format!("platform: {platform}\n");
    if let Some(sid) = account_sid {
        let _ = writeln!(yaml, "account_sid: {sid}");
    }
    if !env.is_empty() {
        yaml.push_str("env:\n");
        yaml.push_str(env);
    }
    if !registry.is_empty() {
        yaml.push_str("registry:\n");
        yaml.push_str(registry);
    }
    FixtureHost::from_yaml_str(&yaml, "inline").unwrap()
}

/// (a1) A value name that is a drive-letter path is one entry: its last segment is the name, the
/// decoded path is emitted as it was spelled, and the non-zero `FILETIME` is `last_run`.
#[test]
fn a1_a_drive_letter_name_is_an_entry_with_its_path_and_last_run() {
    let path = r"C:\Users\fixtureuser\Downloads\cheat.png.exe";
    let name = rot13(path);
    let registry = count_key(&[(name.as_str(), entry_body(FILETIME_2020))]);
    let host = host_with_registry(&registry, "", None, "windows");

    let run = UserAssist.collect(&host);
    let (observations, gaps) = measured(&run);
    assert!(gaps.is_empty(), "{gaps:?}");

    let records = entries(observations);
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0].collector, "userassist");
    assert_eq!(text(records[0], "name"), Some("cheat.png.exe"));
    assert_eq!(text(records[0], "path"), Some(path));
    assert_eq!(text(records[0], "path_withheld"), None);
    assert_eq!(text(records[0], "last_run"), Some("2020-01-01T00:00:00Z"));

    // No shortcuts key on this host, which is a count of zero and not an absence.
    assert_eq!(
        field(account(observations), "shortcuts"),
        Some(&0_u64.into())
    );
}

/// (a2) A known-folder prefix is replaced from the environment, or withheld when the variable is
/// missing or the GUID is not one of the five. A withheld path keeps only the last segment.
#[test]
fn a2_known_folder_prefixes_resolve_from_the_environment_or_are_withheld() {
    let path = r"{6D809377-6AF0-444B-8957-A3773F02200E}\Tool\t.exe";
    let name = rot13(path);

    let registry = count_key(&[(name.as_str(), entry_body(FILETIME_2020))]);
    let host = host_with_registry(
        &registry,
        "  'ProgramW6432': 'C:\\Program Files'\n",
        None,
        "windows",
    );
    let run = UserAssist.collect(&host);
    let (observations, gaps) = measured(&run);
    assert!(gaps.is_empty(), "{gaps:?}");
    let records = entries(observations);
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(text(records[0], "name"), Some("t.exe"));
    assert_eq!(
        text(records[0], "path"),
        Some(r"C:\Program Files\Tool\t.exe")
    );
    assert_eq!(text(records[0], "path_withheld"), None);

    // Neither `ProgramW6432` nor `ProgramFiles`: the prefix cannot be resolved, so the path is
    // withheld and no part of the decoded name beyond the last segment reaches the report.
    let registry = count_key(&[(name.as_str(), entry_body(FILETIME_2020))]);
    let host = host_with_registry(&registry, "", None, "windows");
    let run = UserAssist.collect(&host);
    let (observations, gaps) = measured(&run);
    assert!(gaps.is_empty(), "{gaps:?}");
    let records = entries(observations);
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(text(records[0], "name"), Some("t.exe"));
    assert_eq!(text(records[0], "path"), None);
    assert_eq!(
        text(records[0], "path_withheld"),
        Some("unresolved_known_folder")
    );
    let json = serde_json::to_string(&records).unwrap();
    assert!(!json.contains("Tool"), "the withheld name leaked: {json}");

    // A GUID this collector does not resolve is withheld rather than guessed.
    let unknown = rot13(r"{74439963-DECC-4EAC-80D4-6AE69B413749}\x.exe");
    let registry = count_key(&[(unknown.as_str(), entry_body(FILETIME_2020))]);
    let host = host_with_registry(&registry, "", None, "windows");
    let run = UserAssist.collect(&host);
    let (observations, gaps) = measured(&run);
    assert!(gaps.is_empty(), "{gaps:?}");
    let records = entries(observations);
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(text(records[0], "name"), Some("x.exe"));
    assert_eq!(text(records[0], "path"), None);
    assert_eq!(
        text(records[0], "path_withheld"),
        Some("unresolved_known_folder")
    );
}

/// (a3) A decoded name with no separator is an app identity: the identity is the name unchanged,
/// and it is emitted as an entry with no path (ADR 0080 owner decision 3).
#[test]
fn a3_an_app_identity_is_an_entry_with_no_path() {
    let identity = "CitizenFX.FiveM.Client";
    let name = rot13(identity);
    let registry = count_key(&[(name.as_str(), entry_body(FILETIME_2020))]);
    let host = host_with_registry(&registry, "", None, "windows");

    let run = UserAssist.collect(&host);
    let (observations, gaps) = measured(&run);
    assert!(gaps.is_empty(), "{gaps:?}");

    let records = entries(observations);
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(text(records[0], "name"), Some(identity));
    assert_eq!(text(records[0], "path"), None);
    assert_eq!(text(records[0], "path_withheld"), Some("app_id"));
    assert_eq!(text(records[0], "last_run"), Some("2020-01-01T00:00:00Z"));
}

/// (a4) A `UEME_` counter is skipped, a value shorter than an entry is rejected, a zero `FILETIME`
/// yields no `last_run`, and neither offset 4 nor the unparsed tail reaches any observation
/// (ADR 0080 owner decision 5).
#[test]
fn a4_counters_short_values_and_a_zero_filetime_are_told_apart_from_an_entry() {
    let counter = rot13("UEME_CTLSESSION");
    let short = rot13(r"C:\short.exe");
    let zero = rot13(r"C:\zero\never.exe");
    let registry = count_key(&[
        (
            counter.as_str(),
            format!("content_hex: \"{}\"", "00".repeat(1612)),
        ),
        (
            short.as_str(),
            format!("content_hex: \"{}\"", "00".repeat(10)),
        ),
        (zero.as_str(), entry_body(0)),
    ]);
    let host = host_with_registry(&registry, "", None, "windows");

    let run = UserAssist.collect(&host);
    let (observations, _) = measured(&run);

    let records = entries(observations);
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(text(records[0], "name"), Some("never.exe"));
    assert_eq!(text(records[0], "path"), Some(r"C:\zero\never.exe"));
    assert_eq!(text(records[0], "last_run"), None);

    let account = account(observations);
    assert_eq!(field(account, "entries"), Some(&1_u64.into()));
    assert_eq!(field(account, "skipped"), Some(&1_u64.into()));
    assert_eq!(field(account, "rejected"), Some(&1_u64.into()));

    for observation in observations {
        for forbidden in ["offset4", "unparsed"] {
            assert!(
                !observation.fields.contains_key(forbidden),
                "`{forbidden}` reached an observation: {observation:?}"
            );
        }
    }
}

/// (a5) The shortcuts key contributes a count and is never decoded, and the account is `same`,
/// `other` or `unknown` by `powershell_text`'s comparison with the signed-in SID.
#[test]
fn a5_shortcuts_are_counted_and_the_account_is_compared_with_the_signed_in_sid() {
    let path = r"C:\Users\fixtureuser\Downloads\opened.exe";
    let name = rot13(path);
    let shortcuts = [
        rot13(r"C:\Users\fixtureuser\Desktop\one.lnk"),
        rot13(r"C:\Users\fixtureuser\Desktop\two.lnk"),
        rot13(r"C:\Users\fixtureuser\Desktop\three.lnk"),
    ];
    let shortcut_names: Vec<&str> = shortcuts.iter().map(String::as_str).collect();
    let shortcuts = shortcut_key(&shortcut_names);

    let assert_account = |own: Option<&str>, signed_in: Option<&str>, expected: &str| {
        let registry = format!(
            "{}{}{}",
            count_key(&[(name.as_str(), entry_body(FILETIME_2020))]),
            shortcuts,
            signed_in.map(logon_sid).unwrap_or_default()
        );
        let host = host_with_registry(&registry, "", own, "windows");
        let run = UserAssist.collect(&host);
        let (observations, gaps) = measured(&run);
        assert!(gaps.is_empty(), "{gaps:?}");
        let account = account(observations);
        assert_eq!(field(account, "shortcuts"), Some(&3_u64.into()));
        assert_eq!(text(account, "account"), Some(expected));
    };

    assert_account(
        Some("S-1-5-21-0-0-0-1001"),
        Some("S-1-5-21-0-0-0-1001"),
        "same",
    );
    assert_account(
        Some("S-1-5-21-0-0-0-1001"),
        Some("S-1-5-21-0-0-0-1002"),
        "other",
    );
    assert_account(Some("S-1-5-21-0-0-0-1001"), None, "unknown");
}

/// (a6) The Count key absent is unmeasured rather than "nothing ran"; one unreadable value beside a
/// good one is `partial` and loses no other entry; a non-Windows host is `not_windows`; the tier is
/// standard (ADR 0080 section 1 and owner decision 1).
#[test]
fn a6_absent_partial_and_not_windows_are_told_apart_and_the_tier_is_standard() {
    let absent = host_with_registry("", "", None, "windows");
    assert_eq!(
        UserAssist.collect(&absent),
        CollectorRun::Unmeasured {
            collector: "userassist".to_owned(),
            reason: UnmeasuredReason::SourceAbsent,
        }
    );

    let good = rot13(r"C:\Users\fixtureuser\Downloads\good.exe");
    let unreadable = rot13(r"C:\Users\fixtureuser\Downloads\unreadable.exe");
    let registry = count_key(&[
        (good.as_str(), entry_body(FILETIME_2020)),
        (unreadable.as_str(), "{}".to_owned()),
    ]);
    let host = host_with_registry(&registry, "", None, "windows");
    let run = UserAssist.collect(&host);
    let (observations, gaps) = measured(&run);
    assert_eq!(
        gaps.get("name"),
        Some(&UnmeasuredReason::Partial),
        "{gaps:?}"
    );
    assert!(
        gaps.values()
            .all(|reason| *reason == UnmeasuredReason::Partial),
        "{gaps:?}"
    );
    let records = entries(observations);
    assert!(
        records
            .iter()
            .any(|record| text(record, "name") == Some("good.exe")),
        "the readable value beside it must still be an entry: {records:?}"
    );
    assert_eq!(
        field(account(observations), "shortcuts"),
        Some(&0_u64.into())
    );

    assert_eq!(
        UserAssist.collect(&NonWindowsHost),
        CollectorRun::Unmeasured {
            collector: "userassist".to_owned(),
            reason: UnmeasuredReason::NotWindows,
        }
    );

    assert_eq!(UserAssist.tier(), ScanTier::Standard);
}
