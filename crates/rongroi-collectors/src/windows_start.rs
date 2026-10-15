// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! How Windows started, each time its `System` log remembers (ADR 0071).
//!
//! One observation per start: when Windows wrote it (`started_at`) and the number Windows gave the way
//! it started (`boot_type`), read by `rongroi_parsers::evtx::windows_starts` from 27 of
//! `Microsoft-Windows-Kernel-Boot`. No other value of that event, or of any other event, is read.
//!
//! **This module gives the number no meaning**; the rules that select on it do (ADR 0002). What was
//! measured, in a virtual machine (ADR 0071): 0 after a full shutdown or a restart, 1 after a Fast
//! Startup shutdown. A device removed while Windows was shut down with Fast Startup has a
//! `last_removal_at` (ADR 0069); after a full shutdown it has none, so this is what tells the two
//! apart.
//!
//! The log is the same `System.evtx` the `evtx` collector reads; a denial without an elevated token is
//! `not_admin`, as `evtx` reports one (ADR 0024). It is parsed on its own thread
//! within `evtx`'s budget, for the reason `evtx` gives (ADR 0024).

use std::collections::BTreeMap;

use rongroi_core::model::{CollectorRun, Observation, UnmeasuredReason};
use rongroi_host::{Host, Platform};
use rongroi_parsers::evtx::{WindowsStarts, windows_starts};
use serde_json::Value;

use crate::failure::reason_for;
use crate::{Collector, Field, evtx};

const ID: &str = "windows_start";

/// The `System` log's file name in the Event Log folder.
pub const SYSTEM_LOG: &str = "System.evtx";

const FIELDS: [Field; 2] = [Field::number("boot_type"), Field::timestamp("started_at")];

const REASONS: [UnmeasuredReason; 5] = [
    UnmeasuredReason::NotWindows,
    UnmeasuredReason::NotAdmin,
    UnmeasuredReason::AccessDenied,
    UnmeasuredReason::SourceAbsent,
    UnmeasuredReason::ReadFailed,
];

/// The `windows_start` collector.
#[derive(Debug, Default, Clone, Copy)]
pub struct WindowsStart;

impl Collector for WindowsStart {
    fn id(&self) -> &'static str {
        ID
    }

    fn fields(&self) -> &'static [Field] {
        &FIELDS
    }

    fn unmeasured_reasons(&self) -> &'static [UnmeasuredReason] {
        &REASONS
    }

    fn collect(&self, host: &dyn Host) -> CollectorRun {
        if host.platform() != Platform::Windows {
            return unmeasured(UnmeasuredReason::NotWindows);
        }
        let Some(root) = host
            .env_var(evtx::SYSTEM_ROOT)
            .map(|r| r.trim_end_matches(['\\', '/']).to_owned())
            .filter(|r| !r.is_empty())
        else {
            return unmeasured(UnmeasuredReason::ReadFailed);
        };
        let path = format!(r"{root}\{}\{SYSTEM_LOG}", evtx::LOGS_RELATIVE_PATH);
        let bytes = match host.read_file(&path) {
            Ok(Some(bytes)) => bytes,
            Ok(None) => return unmeasured(UnmeasuredReason::SourceAbsent),
            Err(error) => return unmeasured(reason_for(host, &error)),
        };
        match parse_within(bytes, evtx::PARSE_BUDGET) {
            Some(Ok(starts)) => measured(&starts),
            Some(Err(_)) | None => unmeasured(UnmeasuredReason::ReadFailed),
        }
    }
}

/// Parses on a thread of its own and waits at most `within`, so a parse that does not return costs
/// this collector its run rather than the whole scan (ADR 0024). `None` when the budget ran out or no
/// thread was given; a thread left behind is dropped without being joined, as `evtx`'s is.
fn parse_within(
    bytes: Vec<u8>,
    within: std::time::Duration,
) -> Option<Result<WindowsStarts, rongroi_parsers::error::ParseError>> {
    let (answer, result) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("windows-start-parse".to_owned())
        .spawn(move || {
            let _ = answer.send(windows_starts(&bytes));
        })
        .ok()?;
    result.recv_timeout(within).ok()
}

fn unmeasured(reason: UnmeasuredReason) -> CollectorRun {
    CollectorRun::Unmeasured {
        collector: ID.to_owned(),
        reason,
    }
}

/// One observation per start. A start whose `boot_type` was not a number is kept without it.
fn measured(starts: &WindowsStarts) -> CollectorRun {
    let observations = starts
        .starts
        .iter()
        .map(|start| {
            let mut fields = BTreeMap::new();
            fields.insert(
                "started_at".to_owned(),
                Value::from(start.written.to_string()),
            );
            if let Some(boot_type) = start.boot_type {
                fields.insert("boot_type".to_owned(), Value::from(boot_type));
            }
            Observation {
                collector: ID.to_owned(),
                fields,
            }
        })
        .collect();
    CollectorRun::Measured {
        collector: ID.to_owned(),
        observations,
        gaps: BTreeMap::new(),
        discriminator_gaps: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use jiff::Timestamp;
    use rongroi_host::{FixtureHost, NonWindowsHost};
    use rongroi_parsers::evtx::WindowsStart as Start;

    use super::*;

    fn host(yaml: &str) -> FixtureHost {
        FixtureHost::from_yaml_str(yaml, "inline").unwrap()
    }

    #[test]
    fn each_start_is_one_observation_with_its_time_and_number() {
        let at = |s: i64| Timestamp::from_second(s).unwrap();
        let run = measured(&WindowsStarts {
            starts: vec![
                Start {
                    written: at(1_791_000_000),
                    boot_type: Some(0),
                },
                Start {
                    written: at(1_791_000_600),
                    boot_type: None,
                },
            ],
            rejected: Vec::new(),
        });
        let CollectorRun::Measured { observations, .. } = run else {
            panic!("expected a measured run");
        };
        assert_eq!(observations.len(), 2);
        assert_eq!(observations[0].fields["boot_type"], Value::from(0));
        assert_eq!(
            observations[0].fields["started_at"],
            Value::from(at(1_791_000_000).to_string())
        );
        assert!(!observations[1].fields.contains_key("boot_type"));
    }

    #[test]
    fn a_log_that_is_not_there_or_not_readable_is_unmeasured() {
        let windows = "platform: windows\nenv:\n  SystemRoot: 'C:\\Windows'\n";
        assert_eq!(
            WindowsStart.collect(&host(windows)),
            unmeasured(UnmeasuredReason::SourceAbsent)
        );
        let denied = format!(
            "{windows}elevated: false\naccess_denied: ['C:\\Windows\\System32\\winevt\\Logs\\{SYSTEM_LOG}']\n"
        );
        assert_eq!(
            WindowsStart.collect(&host(&denied)),
            unmeasured(UnmeasuredReason::NotAdmin)
        );
        assert_eq!(
            WindowsStart.collect(&host("platform: windows\n")),
            unmeasured(UnmeasuredReason::ReadFailed)
        );
        assert_eq!(
            WindowsStart.collect(&NonWindowsHost),
            unmeasured(UnmeasuredReason::NotWindows)
        );
    }
}
