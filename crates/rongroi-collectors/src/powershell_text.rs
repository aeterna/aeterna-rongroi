// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! Which kinds of words PowerShell's commands held, never the commands (ADR 0064). **A full-scan
//! collector**, and the one exception to "no credentials, tokens or unrelated personal files" in this
//! crate's `AGENTS.md`: it reads what a person typed into a PowerShell window, the text of the script
//! blocks Windows PowerShell flagged, and the command lines Windows PowerShell was started with.
//!
//! **No text reaches this module.** It hands bytes to `rongroi_parsers::powershell_text::parse_history`
//! and `rongroi_parsers::evtx::powershell_text`, which classify inside the parsers crate and return
//! booleans, counts, times and at most a download host. The host is the one value kept, and it is a
//! sensitive field (`download_host`, [`SensitiveKind::DownloadHost`]) that SS mode shows only after its
//! own question; an address is reported by its kind alone.
//!
//! Three sources, told apart by `source`, the discriminator (ADR 0044):
//!
//! - `history`: every `*_history.txt` file `PSReadLine` keeps for the account running the scan, under
//!   `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine`. A line has no time; `newest_from_end` says how
//!   many commands ago the newest line of a group was. `PSReadLine` keeps out of the file any line with
//!   `password`, `asplaintext`, `token`, `key` or `secret` in it (ADR 0064), so the file is incomplete by
//!   construction.
//! - `script_block`: 4104 at level 3 in `Microsoft-Windows-PowerShell/Operational`, parts joined.
//! - `engine_start`: 400 in `Windows PowerShell`, its `HostApplication`.
//!
//! One observation per source and file says whether it was read (`read`) and how much (`examined`,
//! `lines`); one per group of entries with the same kinds and the same host carries the booleans and
//! `count`. A source that could not be read is a gap for that source alone.

use std::collections::BTreeMap;

use jiff::Timestamp;
use rongroi_core::model::{CollectorRun, DiscriminatorGaps, Observation, UnmeasuredReason};
use rongroi_host::{Host, Platform, SourceError};
use rongroi_parsers::evtx::{PowerShellSource, powershell_text};
use rongroi_parsers::powershell_text::{Classification, DownloadHost, Kinds, parse_history};
use serde_json::Value;

use crate::failure::{read_failure, reason_for};
use crate::{Collector, Field, ScanTier, SensitiveKind, evtx, fivem_dir, usn};

const ID: &str = "powershell_text";
const DISCRIMINATOR: &str = "source";

/// The `source` of `PSReadLine`'s history files.
pub const HISTORY: &str = "history";
/// The `source` of the script blocks Windows `PowerShell` flagged.
pub const SCRIPT_BLOCK: &str = "script_block";
/// The `source` of Windows `PowerShell`'s starts.
pub const ENGINE_START: &str = "engine_start";

/// The operational log's file name in the Event Log folder.
pub const OPERATIONAL_LOG: &str = "Microsoft-Windows-PowerShell%4Operational.evtx";
/// The classic log's file name in the Event Log folder.
pub const CLASSIC_LOG: &str = "Windows PowerShell.evtx";

/// Where Windows' sign-in screen keeps the account last signed in at the keyboard. Every account
/// can read it, a non-elevated one included (measured 2026-10-09, ADR 0064 "Amendment").
pub const LOGON_UI_KEY: &str =
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI";
/// The value under [`LOGON_UI_KEY`] holding that account's SID. Compared, never reported.
pub const LAST_LOGGED_ON_USER_SID: &str = "LastLoggedOnUserSID";

const FIELDS: [Field; 26] = [
    Field::text("account"),
    Field::number("count"),
    Field::boolean("decoded"),
    Field::boolean("defender_tamper"),
    Field::text("download_address_kind"),
    Field::text("download_host").sensitive(SensitiveKind::DownloadHost),
    Field::boolean("download_then_execute"),
    Field::boolean("encoded_command"),
    Field::number("examined"),
    Field::boolean("execution_policy_bypass"),
    Field::text("file"),
    Field::timestamp("first_seen"),
    Field::boolean("game_process"),
    Field::boolean("hidden_window"),
    Field::number("incomplete"),
    Field::boolean("invoke_expression"),
    Field::timestamp("last_seen"),
    Field::number("lines"),
    Field::number("lossy_lines"),
    Field::boolean("native_interop"),
    Field::number("newest_from_end"),
    Field::text("read"),
    Field::number("rejected"),
    Field::boolean("remote_download"),
    Field::text("source"),
    Field::boolean("trace_cleanup"),
];

static REASONS: [UnmeasuredReason; 5] = [
    UnmeasuredReason::NotWindows,
    UnmeasuredReason::NotAdmin,
    UnmeasuredReason::AccessDenied,
    UnmeasuredReason::SourceAbsent,
    UnmeasuredReason::ReadFailed,
];

/// Reads `PSReadLine`'s history and the two Windows `PowerShell` logs, keeping kinds (ADR 0064).
#[derive(Debug, Clone, Copy, Default)]
pub struct PowershellText;

impl Collector for PowershellText {
    fn id(&self) -> &'static str {
        ID
    }

    fn fields(&self) -> &'static [Field] {
        &FIELDS
    }

    fn unmeasured_reasons(&self) -> &'static [UnmeasuredReason] {
        &REASONS
    }

    fn discriminator(&self) -> Option<&'static str> {
        Some(DISCRIMINATOR)
    }

    fn tier(&self) -> ScanTier {
        ScanTier::Full
    }

    fn collect(&self, host: &dyn Host) -> CollectorRun {
        if host.platform() != Platform::Windows {
            return CollectorRun::Unmeasured {
                collector: ID.to_owned(),
                reason: UnmeasuredReason::NotWindows,
            };
        }
        let mut run = Run::default();
        read_history(host, &mut run);
        let account = history_account(host);
        for history in run
            .observations
            .iter_mut()
            .filter(|o| o.fields[DISCRIMINATOR] == HISTORY)
        {
            history
                .fields
                .insert("account".to_owned(), Value::from(account));
        }
        read_logs(host, &mut run);
        CollectorRun::Measured {
            collector: ID.to_owned(),
            observations: run.observations,
            gaps: BTreeMap::new(),
            discriminator_gaps: run.discriminator_gaps,
        }
    }
}

#[derive(Default)]
struct Run {
    observations: Vec<Observation>,
    discriminator_gaps: Vec<DiscriminatorGaps>,
}

impl Run {
    /// One source's `read` observation, and when it was not read, the gap for that source alone.
    fn not_read(&mut self, source: &str, read: &str, reason: UnmeasuredReason) {
        self.observations.push(observation([
            ("source", Value::from(source)),
            ("read", Value::from(read)),
        ]));
        self.discriminator_gaps.push(DiscriminatorGaps {
            discriminator: DISCRIMINATOR.to_owned(),
            value: Value::from(source),
            gaps: FIELDS
                .iter()
                .filter(|f| !matches!(f.name, DISCRIMINATOR | "read" | "account"))
                .map(|f| (f.name.to_owned(), reason))
                .collect(),
        });
    }
}

fn observation<const N: usize>(fields: [(&str, Value); N]) -> Observation {
    Observation {
        collector: ID.to_owned(),
        fields: fields.into_iter().map(|(k, v)| (k.to_owned(), v)).collect(),
    }
}

/// Whether the history read is the one of the account signed in at the keyboard: `same`, `other`, or
/// `unknown` when either SID could not be read. The history is always that of the account this
/// program runs as, and after a restart with another administrator's password that is the other
/// administrator (ADR 0064, "Amendment"). Neither SID is reported.
fn history_account(host: &dyn Host) -> &'static str {
    let Ok(own) = host.account_sid() else {
        return "unknown";
    };
    match host.read_string(LOGON_UI_KEY, LAST_LOGGED_ON_USER_SID) {
        Ok(Some(signed_in)) if signed_in.trim().eq_ignore_ascii_case(&own) => "same",
        Ok(Some(signed_in)) if !signed_in.trim().is_empty() => "other",
        _ => "unknown",
    }
}

/// `ConsoleHost_history.txt` is the console's; `PSReadLine` names other hosts' files after the host. A
/// fixed word, never the file's name.
fn file_word(name: &str) -> &'static str {
    let lower = name.to_ascii_lowercase();
    if lower == "consolehost_history.txt" {
        "console_host"
    } else if lower.starts_with("visual studio code host") {
        "visual_studio_code"
    } else {
        "other"
    }
}

fn read_history(host: &dyn Host, run: &mut Run) {
    let Some(base) = host
        .env_var(fivem_dir::ROAMING_APP_DATA)
        .map(|b| b.trim_end_matches(['\\', '/']).to_owned())
        .filter(|b| !b.is_empty())
    else {
        run.not_read(HISTORY, "failed", UnmeasuredReason::ReadFailed);
        return;
    };
    let folder = format!(r"{base}\{}", usn::PSREADLINE_RELATIVE_PATH);
    let entries = match host.list_dir(&folder) {
        Ok(Some(entries)) => entries,
        Ok(None) => return run.not_read(HISTORY, "absent", UnmeasuredReason::SourceAbsent),
        Err(error) => return run.not_read(HISTORY, read_failure(&error), reason_for(host, &error)),
    };
    let mut files: Vec<_> = entries
        .into_iter()
        .filter(|e| e.is_file && e.name.to_ascii_lowercase().ends_with("_history.txt"))
        .collect();
    files.sort_by(|a, b| a.name.cmp(&b.name));
    if files.is_empty() {
        return run.not_read(HISTORY, "absent", UnmeasuredReason::SourceAbsent);
    }
    for file in files {
        let word = file_word(&file.name);
        let bytes = match host.read_file(&format!(r"{folder}\{}", file.name)) {
            Ok(Some(bytes)) => bytes,
            Ok(None) => continue,
            Err(error) => {
                history_failed(host, run, word, &error);
                continue;
            }
        };
        // `parse_history` never refuses a file; the `Result` is the parsers crate's contract.
        let Ok(history) = parse_history(&bytes) else {
            run.not_read(HISTORY, "failed", UnmeasuredReason::ReadFailed);
            continue;
        };
        run.observations.push(observation([
            ("source", Value::from(HISTORY)),
            ("file", Value::from(word)),
            ("read", Value::from("ok")),
            ("lines", Value::from(history.lines)),
            ("lossy_lines", Value::from(history.lossy_lines)),
        ]));
        let mut groups: BTreeMap<GroupKey, Group> = BTreeMap::new();
        for (from_end, classification) in history.classified {
            let group = groups.entry(GroupKey::of(&classification)).or_default();
            group.count += 1;
            group.newest_from_end = Some(
                group
                    .newest_from_end
                    .map_or(from_end, |n: usize| n.min(from_end)),
            );
        }
        for (key, group) in groups {
            run.observations
                .push(key.observation(HISTORY, Some(word), &group));
        }
    }
}

fn history_failed(host: &dyn Host, run: &mut Run, word: &str, error: &SourceError) {
    run.not_read(HISTORY, read_failure(error), reason_for(host, error));
    if let Some(last) = run.observations.last_mut() {
        last.fields.insert("file".to_owned(), Value::from(word));
    }
}

fn read_logs(host: &dyn Host, run: &mut Run) {
    let Some(root) = host
        .env_var(evtx::SYSTEM_ROOT)
        .map(|r| r.trim_end_matches(['\\', '/']).to_owned())
        .filter(|r| !r.is_empty())
    else {
        run.not_read(SCRIPT_BLOCK, "failed", UnmeasuredReason::ReadFailed);
        run.not_read(ENGINE_START, "failed", UnmeasuredReason::ReadFailed);
        return;
    };
    let dir = format!(r"{root}\{}", evtx::LOGS_RELATIVE_PATH);
    for (source, name, wanted) in [
        (SCRIPT_BLOCK, OPERATIONAL_LOG, PowerShellSource::ScriptBlock),
        (ENGINE_START, CLASSIC_LOG, PowerShellSource::EngineStart),
    ] {
        let bytes = match host.read_file(&format!(r"{dir}\{name}")) {
            Ok(Some(bytes)) => bytes,
            Ok(None) => {
                run.not_read(source, "absent", UnmeasuredReason::SourceAbsent);
                continue;
            }
            Err(error) => {
                run.not_read(source, read_failure(&error), reason_for(host, &error));
                continue;
            }
        };
        let Ok(text) = powershell_text(&bytes) else {
            run.not_read(source, "failed", UnmeasuredReason::ReadFailed);
            continue;
        };
        run.observations.push(observation([
            ("source", Value::from(source)),
            ("read", Value::from("ok")),
            ("examined", Value::from(text.examined)),
            ("rejected", Value::from(text.rejected.len())),
        ]));
        let mut groups: BTreeMap<GroupKey, Group> = BTreeMap::new();
        for entry in text
            .entries
            .into_iter()
            .filter(|e| e.source == wanted && e.classification.kinds.any())
        {
            let group = groups
                .entry(GroupKey::of(&entry.classification))
                .or_default();
            group.count += 1;
            group.incomplete += usize::from(!entry.complete);
            group.first_seen = Some(
                group
                    .first_seen
                    .map_or(entry.written, |t: Timestamp| t.min(entry.written)),
            );
            group.last_seen = Some(
                group
                    .last_seen
                    .map_or(entry.written, |t: Timestamp| t.max(entry.written)),
            );
        }
        for (key, group) in groups {
            run.observations.push(key.observation(source, None, &group));
        }
    }
}

/// What makes two entries one group: the same kinds, and the same host.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct GroupKey {
    kinds: [bool; 11],
    host: Option<(bool, String)>,
}

impl GroupKey {
    fn of(c: &Classification) -> Self {
        let k: &Kinds = &c.kinds;
        Self {
            kinds: [
                k.invoke_expression,
                k.remote_download,
                k.download_then_execute,
                k.encoded_command,
                k.decoded,
                k.execution_policy_bypass,
                k.hidden_window,
                k.native_interop,
                k.defender_tamper,
                k.trace_cleanup,
                k.game_process,
            ],
            host: c.download_host.as_ref().map(|h| match h {
                DownloadHost::Name(name) => (true, name.clone()),
                DownloadHost::Address(kind) => (false, kind.as_str().to_owned()),
            }),
        }
    }

    fn observation(&self, source: &str, file: Option<&str>, group: &Group) -> Observation {
        const NAMES: [&str; 11] = [
            "invoke_expression",
            "remote_download",
            "download_then_execute",
            "encoded_command",
            "decoded",
            "execution_policy_bypass",
            "hidden_window",
            "native_interop",
            "defender_tamper",
            "trace_cleanup",
            "game_process",
        ];
        let mut fields: BTreeMap<String, Value> = NAMES
            .iter()
            .zip(self.kinds)
            .map(|(name, value)| ((*name).to_owned(), Value::from(value)))
            .collect();
        fields.insert("source".to_owned(), Value::from(source));
        fields.insert("count".to_owned(), Value::from(group.count));
        if let Some(file) = file {
            fields.insert("file".to_owned(), Value::from(file));
        }
        if let Some(n) = group.newest_from_end {
            fields.insert("newest_from_end".to_owned(), Value::from(n));
        }
        if let (Some(first), Some(last)) = (group.first_seen, group.last_seen) {
            fields.insert("first_seen".to_owned(), Value::from(first.to_string()));
            fields.insert("last_seen".to_owned(), Value::from(last.to_string()));
            fields.insert("incomplete".to_owned(), Value::from(group.incomplete));
        }
        match &self.host {
            Some((true, name)) => {
                fields.insert("download_host".to_owned(), Value::from(name.as_str()));
            }
            Some((false, kind)) => {
                fields.insert(
                    "download_address_kind".to_owned(),
                    Value::from(kind.as_str()),
                );
            }
            None => {}
        }
        Observation {
            collector: ID.to_owned(),
            fields,
        }
    }
}

#[derive(Debug, Default)]
struct Group {
    count: usize,
    incomplete: usize,
    newest_from_end: Option<usize>,
    first_seen: Option<Timestamp>,
    last_seen: Option<Timestamp>,
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use rongroi_host::{FixtureHost, NonWindowsHost};

    use super::*;

    fn fixture(name: &str) -> FixtureHost {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/hosts")
            .join(name);
        FixtureHost::load(&dir).unwrap()
    }

    fn measured(run: &CollectorRun) -> (&[Observation], &[DiscriminatorGaps]) {
        match run {
            CollectorRun::Measured {
                observations,
                discriminator_gaps,
                ..
            } => (observations, discriminator_gaps),
            CollectorRun::Unmeasured { .. } => panic!("expected a measured run, got {run:?}"),
        }
    }

    fn of<'a>(observations: &'a [Observation], source: &str) -> Vec<&'a Observation> {
        observations
            .iter()
            .filter(|o| o.fields["source"] == source)
            .collect()
    }

    #[test]
    fn it_is_read_only_in_a_full_scan_and_the_host_is_a_download_host() {
        assert_eq!(PowershellText.tier(), ScanTier::Full);
        let host = FIELDS.iter().find(|f| f.name == "download_host").unwrap();
        assert_eq!(host.sensitive, Some(SensitiveKind::DownloadHost));
        assert_eq!(FIELDS.iter().filter(|f| f.sensitive.is_some()).count(), 1);
    }

    #[test]
    fn history_is_read_by_kinds_and_logs_by_record() {
        let run = PowershellText.collect(&fixture("powershell-text-present"));
        let (observations, gaps) = measured(&run);

        let history = of(observations, HISTORY);
        let reads: Vec<_> = history
            .iter()
            .filter(|o| o.fields.contains_key("read"))
            .collect();
        assert_eq!(reads.len(), 2, "two history files, notes.txt is not one");
        let console = reads
            .iter()
            .find(|o| o.fields["file"] == "console_host")
            .unwrap();
        assert_eq!(
            (
                console.fields["lines"].clone(),
                console.fields["read"].clone()
            ),
            (Value::from(6), Value::from("ok"))
        );
        assert!(
            reads
                .iter()
                .any(|o| o.fields["file"] == "visual_studio_code")
        );

        let dte: Vec<_> = history
            .iter()
            .filter(|o| o.fields.get("download_then_execute") == Some(&Value::from(true)))
            .collect();
        assert_eq!(dte.len(), 1);
        assert_eq!(dte[0].fields["download_host"], "loader.example.invalid");
        assert_eq!(dte[0].fields["newest_from_end"], 4);
        assert_eq!(dte[0].fields["count"], 1);
        assert!(
            !dte[0].fields.contains_key("first_seen"),
            "a history line has no time"
        );

        let private: Vec<_> = history
            .iter()
            .filter(|o| o.fields.get("download_address_kind") == Some(&Value::from("private")))
            .collect();
        assert_eq!(private.len(), 1);
        assert!(!private[0].fields.contains_key("download_host"));
        assert!(
            history
                .iter()
                .any(|o| o.fields.get("defender_tamper") == Some(&Value::from(true)))
        );
        assert!(
            history
                .iter()
                .any(|o| o.fields.get("trace_cleanup") == Some(&Value::from(true)))
        );

        // The operational log parses and holds no PowerShell record; the classic log is absent.
        let blocks = of(observations, SCRIPT_BLOCK);
        assert_eq!(blocks.len(), 1);
        assert_eq!(
            (
                blocks[0].fields["read"].clone(),
                blocks[0].fields["examined"].clone()
            ),
            (Value::from("ok"), Value::from(0))
        );
        let starts = of(observations, ENGINE_START);
        assert_eq!(starts[0].fields["read"], "absent");
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0].value, ENGINE_START);
        assert_eq!(
            gaps[0].gaps["download_then_execute"],
            UnmeasuredReason::SourceAbsent
        );
    }

    #[test]
    fn no_text_of_what_was_typed_reaches_an_observation() {
        let run = PowershellText.collect(&fixture("powershell-text-present"));
        let all = format!("{:?}", measured(&run).0);
        for text in [
            "correct horse",
            "private-project",
            "fixtureuser",
            "tool.ps1",
            "10.1.2.3",
            "/x",
            "git status",
            "Clear-History",
            "Visual Studio Code Host",
            "ConsoleHost_history",
            "notes",
        ] {
            assert!(!all.contains(text), "{text} leaked: {all}");
        }
    }

    #[test]
    fn a_refused_log_without_rights_is_not_admin_for_that_source_alone() {
        let run = PowershellText.collect(&fixture("powershell-text-denied"));
        let (observations, gaps) = measured(&run);
        let refused: Vec<_> = gaps
            .iter()
            .map(|g| (g.value.clone(), g.gaps["count"]))
            .collect();
        assert_eq!(
            refused,
            [
                (Value::from(SCRIPT_BLOCK), UnmeasuredReason::NotAdmin),
                (Value::from(ENGINE_START), UnmeasuredReason::NotAdmin),
            ]
        );
        let history = of(observations, HISTORY);
        assert!(
            history
                .iter()
                .any(|o| o.fields.get("trace_cleanup") == Some(&Value::from(true)))
        );
        assert!(
            of(observations, SCRIPT_BLOCK)
                .iter()
                .all(|o| o.fields["read"] == "access_denied")
        );
    }

    #[test]
    fn a_host_without_the_folder_or_the_logs_says_so_for_each_source() {
        let host = FixtureHost::from_yaml_str(
            "platform: windows\nelevated: true\nenv:\n  SystemRoot: 'C:\\Windows'\n  APPDATA: 'C:\\Users\\u\\AppData\\Roaming'\n",
            "inline",
        )
        .unwrap();
        let run = PowershellText.collect(&host);
        let (observations, gaps) = measured(&run);
        assert_eq!(gaps.len(), 3);
        assert!(
            gaps.iter()
                .all(|g| g.gaps["count"] == UnmeasuredReason::SourceAbsent)
        );
        assert!(observations.iter().all(|o| o.fields["read"] == "absent"));
    }

    /// The history is the scanning account's; after a restart with another administrator's password
    /// that account is not the one signed in at the keyboard, and every history observation says so.
    /// Measured on a runner on 2026-10-09: a second administrator started in the runner's own session
    /// read `LastLoggedOnUserSID` as another account's.
    #[test]
    fn the_history_says_whether_it_is_the_signed_in_accounts() {
        let account = |own: Option<&str>, signed_in: Option<&str>| {
            let own = own.map_or(String::new(), |own| format!("account_sid: {own}\n"));
            let registry = signed_in.map_or(String::new(), |signed_in| {
                format!(
                    "registry:\n  '{LOGON_UI_KEY}':\n    {LAST_LOGGED_ON_USER_SID}: '{signed_in}'\n"
                )
            });
            let yaml = format!(
                "platform: windows\nenv:\n  APPDATA: 'C:\\Users\\u\\AppData\\Roaming'\n{own}{registry}"
            );
            let host = FixtureHost::from_yaml_str(&yaml, "inline").unwrap();
            let run = PowershellText.collect(&host);
            let (observations, gaps) = measured(&run);
            assert!(gaps.iter().all(|g| !g.gaps.contains_key("account")));
            let history = of(observations, HISTORY);
            assert_eq!(history.len(), 1);
            assert!(
                of(observations, ENGINE_START)
                    .iter()
                    .all(|o| !o.fields.contains_key("account"))
            );
            history[0].fields["account"].clone()
        };
        assert_eq!(
            account(Some("S-1-5-21-1-2-3-1001"), Some("S-1-5-21-1-2-3-1001")),
            "same"
        );
        assert_eq!(
            account(Some("S-1-5-21-1-2-3-1001"), Some("s-1-5-21-1-2-3-1001")),
            "same"
        );
        assert_eq!(
            account(Some("S-1-5-21-1-2-3-1002"), Some("S-1-5-21-1-2-3-1001")),
            "other"
        );
        assert_eq!(account(Some("S-1-5-21-1-2-3-1001"), None), "unknown");
        assert_eq!(account(Some("S-1-5-21-1-2-3-1001"), Some("")), "unknown");
        assert_eq!(account(None, Some("S-1-5-21-1-2-3-1001")), "unknown");
    }

    #[test]
    fn off_windows_it_does_not_look() {
        assert!(matches!(
            PowershellText.collect(&NonWindowsHost),
            CollectorRun::Unmeasured {
                reason: UnmeasuredReason::NotWindows,
                ..
            }
        ));
    }
}
