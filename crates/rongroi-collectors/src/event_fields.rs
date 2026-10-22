// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! Three payload fields read from three Event Logs near a game session (ADR 0081, sections 1 to 3).
//!
//! `System.evtx` gives the service installs (7045) and the clock changes (Kernel-General 1). The Code
//! Integrity and Security logs are read and summarised here; their observations come with ADR 0081
//! section 4. Each log is parsed once, on its own thread, within its own limit (ADR 0024).

use std::collections::BTreeMap;
use std::sync::mpsc;
use std::time::Duration;

use rongroi_core::model::{CollectorRun, DiscriminatorGaps, Observation, UnmeasuredReason};
use rongroi_host::{Host, Platform};
use rongroi_parsers::error::ParseError;
use rongroi_parsers::evtx::{
    CodeIntegrityFields, SecurityFields, SystemFields, refused_images, security_fields,
    system_fields,
};
use serde_json::Value;

use crate::evtx::{LOGS_RELATIVE_PATH, SYSTEM_ROOT};
use crate::failure::{read_failure, reason_for};
use crate::{Collector, Field, ScanTier};

const ID: &str = "event_fields";

/// The field that says which log an observation is about.
const DISCRIMINATOR: &str = "log";

/// The disk's clock and its service installs.
const SYSTEM: &str = "system";
/// Code Integrity's record of an image it refused.
const CODE_INTEGRITY: &str = "code_integrity";
/// The Security audit of a clock change.
const SECURITY: &str = "security";

const SYSTEM_LOG: &str = "System.evtx";
const CODE_INTEGRITY_LOG: &str = "Microsoft-Windows-CodeIntegrity%4Operational.evtx";
const SECURITY_LOG: &str = "Security.evtx";

/// Value of `read` for a log that was parsed.
const READ: &str = "read";
/// Value of `read` for a log whose file was not there.
const ABSENT: &str = "absent";
/// Value of `read` for a log whose parse ran out of time.
const BUDGET_EXHAUSTED: &str = "budget_exhausted";
/// Value of `read` for a log whose bytes could not be parsed or whose parse did not run.
const FAILED: &str = "failed";

/// How long one log may take to parse (ADR 0081 section 1).
///
/// A limit per log rather than for all three: one slow log must not take the others' time, and a
/// parse that does not return cannot be cancelled, so each log gets its own thread (ADR 0024).
pub const LOG_BUDGET: Duration = Duration::from_secs(20);

/// Every field this collector can emit, sorted by name.
const FIELDS: [Field; 21] = [
    Field::text("by"),
    Field::timestamp("changed_at"),
    Field::number("events"),
    Field::timestamp("first_seen"),
    Field::timestamp("installed_at"),
    Field::text("kind"),
    Field::timestamp("last_seen"),
    Field::text("log"),
    Field::timestamp("new_time").off_timeline(),
    Field::timestamp("old_time").off_timeline(),
    Field::text("path_digest"),
    Field::text("read"),
    Field::number("reason"),
    Field::number("rejected"),
    Field::number("small_clock_changes"),
    Field::timestamp("small_first").off_timeline(),
    Field::timestamp("small_last").off_timeline(),
    Field::number("unreadable_clock_changes"),
    Field::number("unresolved_images"),
    Field::number("unresolved_installs"),
    Field::text("volume_path_digest"),
];

/// Every reason this collector gives for not having looked at a log.
const REASONS: [UnmeasuredReason; 6] = [
    UnmeasuredReason::NotWindows,
    UnmeasuredReason::NotAdmin,
    UnmeasuredReason::AccessDenied,
    UnmeasuredReason::SourceAbsent,
    UnmeasuredReason::BudgetSpent,
    UnmeasuredReason::ReadFailed,
];

/// The three Event Log payload fields ADR 0081 reads.
#[derive(Debug, Default, Clone, Copy)]
pub struct EventFields;

impl Collector for EventFields {
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
        ScanTier::Standard
    }

    fn collect(&self, host: &dyn Host) -> CollectorRun {
        if host.platform() != Platform::Windows {
            return unmeasured(UnmeasuredReason::NotWindows);
        }
        let Some(root) = host
            .env_var(SYSTEM_ROOT)
            .map(|root| root.trim_end_matches(['\\', '/']).to_owned())
            .filter(|root| !root.is_empty())
        else {
            return unmeasured(UnmeasuredReason::ReadFailed);
        };
        let dir = format!(r"{root}\{LOGS_RELATIVE_PATH}");

        let mut observations = Vec::new();
        let mut discriminator_gaps = Vec::new();
        let mut first_failure = None;
        let mut any_read = false;

        match read_log(host, &dir, SYSTEM, SYSTEM_LOG, system_fields) {
            Read::Parsed(fields) => {
                any_read = true;
                observations.push(summary(SYSTEM, READ));
                observations.extend(system_observations(host, &fields, &root));
            }
            Read::Unread { read, reason } => {
                first_failure.get_or_insert(reason);
                observations.push(summary(SYSTEM, read));
                discriminator_gaps.push(place_gaps(SYSTEM, reason));
            }
        }
        match read_log(
            host,
            &dir,
            CODE_INTEGRITY,
            CODE_INTEGRITY_LOG,
            refused_images,
        ) {
            Read::Parsed(fields) => {
                any_read = true;
                observations.push(summary(CODE_INTEGRITY, READ));
                observations.extend(code_integrity_observations(&fields));
            }
            Read::Unread { read, reason } => {
                first_failure.get_or_insert(reason);
                observations.push(summary(CODE_INTEGRITY, read));
                discriminator_gaps.push(place_gaps(CODE_INTEGRITY, reason));
            }
        }
        match read_log(host, &dir, SECURITY, SECURITY_LOG, security_fields) {
            Read::Parsed(fields) => {
                any_read = true;
                observations.push(summary(SECURITY, READ));
                observations.extend(security_observations(&fields));
            }
            Read::Unread { read, reason } => {
                first_failure.get_or_insert(reason);
                observations.push(summary(SECURITY, read));
                discriminator_gaps.push(place_gaps(SECURITY, reason));
            }
        }

        // All three logs unread: there is no measurement to report, only the first log's reason, as
        // the order in ADR 0081 makes it the one that explains the run.
        match first_failure {
            Some(reason) if !any_read => unmeasured(reason),
            _ => CollectorRun::Measured {
                collector: ID.to_owned(),
                observations,
                gaps: BTreeMap::new(),
                discriminator_gaps,
            },
        }
    }
}

/// What reading one log produced.
enum Read<T> {
    /// The log was read and parsed.
    Parsed(T),
    /// The log was not read, with the word its summary carries and the reason its place gaps with.
    Unread {
        read: &'static str,
        reason: UnmeasuredReason,
    },
}

/// Reads and parses one log. The summary and the gap are the caller's to place, so this can stay
/// generic over the three readers.
fn read_log<T: Send + 'static>(
    host: &dyn Host,
    dir: &str,
    log: &'static str,
    file: &str,
    parse: fn(&[u8]) -> Result<T, ParseError>,
) -> Read<T> {
    let path = format!(r"{dir}\{file}");
    let bytes = match host.read_file(&path) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => {
            return Read::Unread {
                read: ABSENT,
                reason: UnmeasuredReason::SourceAbsent,
            };
        }
        Err(error) => {
            return Read::Unread {
                read: read_failure(&error),
                reason: reason_for(host, &error),
            };
        }
    };
    match parse_within(bytes, LOG_BUDGET, parse, log) {
        Parsed::Done(Ok(fields)) => Read::Parsed(fields),
        Parsed::Done(Err(_)) | Parsed::Unavailable => Read::Unread {
            read: FAILED,
            reason: UnmeasuredReason::ReadFailed,
        },
        Parsed::OutOfBudget => Read::Unread {
            read: BUDGET_EXHAUSTED,
            reason: UnmeasuredReason::BudgetSpent,
        },
    }
}

/// What one call to a parser produced, or why it produced nothing.
enum Parsed<T> {
    /// The parser returned, with fields or with a reason the bytes are not that log.
    Done(Result<T, ParseError>),
    /// The limit ran out before the parse returned.
    OutOfBudget,
    /// No thread was given, or the one given stopped without answering.
    Unavailable,
}

/// Parses on a thread of its own and waits at most `within`, as `windows_start` does (ADR 0024).
fn parse_within<T: Send + 'static>(
    bytes: Vec<u8>,
    within: Duration,
    parse: fn(&[u8]) -> Result<T, ParseError>,
    log: &'static str,
) -> Parsed<T> {
    if within.is_zero() {
        return Parsed::OutOfBudget;
    }
    let (answer, result) = mpsc::channel();
    let worker = std::thread::Builder::new()
        .name(format!("{log}-parse"))
        .spawn(move || {
            let _ = answer.send(parse(&bytes));
        });
    if worker.is_err() {
        return Parsed::Unavailable;
    }
    match result.recv_timeout(within) {
        Ok(parsed) => Parsed::Done(parsed),
        Err(mpsc::RecvTimeoutError::Timeout) => Parsed::OutOfBudget,
        Err(mpsc::RecvTimeoutError::Disconnected) => Parsed::Unavailable,
    }
}

/// The summary observation of one log: its place and whether it was read.
fn summary(log: &'static str, read: &'static str) -> Observation {
    let mut fields = BTreeMap::new();
    fields.insert(DISCRIMINATOR.to_owned(), Value::from(log));
    fields.insert("read".to_owned(), Value::from(read));
    Observation {
        collector: ID.to_owned(),
        fields,
    }
}

/// The gaps of one unread log, for its place only (ADR 0044).
fn place_gaps(log: &'static str, reason: UnmeasuredReason) -> DiscriminatorGaps {
    DiscriminatorGaps {
        discriminator: DISCRIMINATOR.to_owned(),
        value: Value::from(log),
        gaps: FIELDS
            .iter()
            .map(|field| (field.name.to_owned(), reason))
            .collect(),
    }
}

fn unmeasured(reason: UnmeasuredReason) -> CollectorRun {
    CollectorRun::Unmeasured {
        collector: ID.to_owned(),
        reason,
    }
}

/// The observations of `System.evtx`. Filled by E3b; the parameters are the signature the tests call.
fn system_observations(
    host: &dyn Host,
    fields: &SystemFields,
    system_root: &str,
) -> Vec<Observation> {
    let _ = (host, fields, system_root);
    Vec::new()
}

/// The observations of the Code Integrity log. Filled by E4.
fn code_integrity_observations(fields: &CodeIntegrityFields) -> Vec<Observation> {
    let _ = fields;
    Vec::new()
}

/// The observations of `Security.evtx`. Filled by E4.
fn security_observations(fields: &SecurityFields) -> Vec<Observation> {
    let _ = fields;
    Vec::new()
}

#[cfg(test)]
mod tests {
    use jiff::Timestamp;
    use rongroi_core::digest::{path_digest, volume_path_digest};
    use rongroi_core::model::{CollectorRun, Observation, UnmeasuredReason};
    use rongroi_host::{FixtureHost, NonWindowsHost};
    use rongroi_parsers::evtx::{
        ClockChange, CodeIntegrityFields, ImageRefusal, SecurityFields, ServiceInstall, SystemFields,
    };
    use serde_json::Value;

    use super::*;
    use crate::{Collector, FieldKind, ScanTier};

    const ROOT: &str = r"C:\Windows";
    const START: i64 = 1_791_000_000;

    fn at(seconds: i64) -> Timestamp {
        Timestamp::from_second(seconds).unwrap()
    }

    fn windows_host() -> FixtureHost {
        FixtureHost::from_yaml_str(
            "platform: windows\nenv:\n  SystemRoot: 'C:\\Windows'\n",
            "inline",
        )
        .unwrap()
    }

    /// A clock change whose new time is `new`, with the old time `old` when it is readable.
    fn clock(old: Option<i64>, new: i64, process: Option<&str>, reason: Option<u32>) -> ClockChange {
        ClockChange {
            written: at(new),
            old_time: old.map(at),
            new_time: Some(at(new)),
            reason,
            process: process.map(str::to_owned),
        }
    }

    fn system_with(clock_changes: Vec<ClockChange>) -> SystemFields {
        SystemFields {
            installs: Vec::new(),
            clock_changes,
            rejected: Vec::new(),
        }
    }

    /// The one observation that describes an install, which is the only kind with `installed_at`.
    fn install_of(observations: &[Observation]) -> &Observation {
        observations
            .iter()
            .find(|observation| observation.fields.contains_key("installed_at"))
            .expect("one install observation")
    }

    fn clocks_of(observations: &[Observation]) -> Vec<&Observation> {
        observations
            .iter()
            .filter(|observation| observation.fields.contains_key("changed_at"))
            .collect()
    }

    /// The summary of the log: the one observation that carries its `read` word.
    fn summary_of(observations: &[Observation]) -> &Observation {
        observations
            .iter()
            .find(|observation| observation.fields.contains_key("read"))
            .expect("one summary observation")
    }

    // (f1) Service installs: a driver's path resolves to a digest; an empty image path does not, and no
    // observation names the path, the image-path text or the service-type text.

    #[test]
    fn f1a_driver_install_is_digested_at_its_resolved_path() {
        let system = SystemFields {
            installs: vec![ServiceInstall {
                written: at(START),
                image_path: Some(r"\SystemRoot\System32\drivers\x.sys".to_owned()),
                service_type: Some("kernel mode driver".to_owned()),
            }],
            clock_changes: Vec::new(),
            rejected: Vec::new(),
        };
        let observations = system_observations(&windows_host(), &system, ROOT);
        let install = install_of(&observations);
        assert_eq!(install.fields["log"], Value::from("system"));
        assert_eq!(install.fields["kind"], Value::from("driver"));
        assert_eq!(
            install.fields["installed_at"],
            Value::from(at(START).to_string())
        );
        assert_eq!(
            install.fields["path_digest"],
            Value::from(path_digest(r"C:\Windows\System32\drivers\x.sys").unwrap())
        );
        assert_eq!(
            summary_of(&observations).fields["unresolved_installs"],
            Value::from(0)
        );
        let json = serde_json::to_string(&observations).unwrap();
        assert!(!json.contains("x.sys"), "{json}");
        assert!(!json.contains("kernel mode driver"), "{json}");
    }

    #[test]
    fn f1b_empty_or_absent_image_path_is_unresolved_and_has_no_digest() {
        for image_path in [Some(String::new()), None] {
            let system = SystemFields {
                installs: vec![ServiceInstall {
                    written: at(START),
                    image_path,
                    service_type: Some("kernel mode driver".to_owned()),
                }],
                clock_changes: Vec::new(),
                rejected: Vec::new(),
            };
            let observations = system_observations(&windows_host(), &system, ROOT);
            let install = install_of(&observations);
            assert!(!install.fields.contains_key("path_digest"), "{install:?}");
            assert_eq!(
                summary_of(&observations).fields["unresolved_installs"],
                Value::from(1)
            );
            let json = serde_json::to_string(&observations).unwrap();
            assert!(!json.contains("kernel mode driver"), "{json}");
        }
    }

    #[test]
    fn f1c_user_mode_service_is_a_program_whose_type_text_is_not_emitted() {
        let system = SystemFields {
            installs: vec![ServiceInstall {
                written: at(START),
                image_path: None,
                service_type: Some("User Mode Service".to_owned()),
            }],
            clock_changes: Vec::new(),
            rejected: Vec::new(),
        };
        let observations = system_observations(&windows_host(), &system, ROOT);
        assert_eq!(
            install_of(&observations).fields["kind"],
            Value::from("program")
        );
        let json = serde_json::to_string(&observations).unwrap();
        assert!(!json.to_ascii_lowercase().contains("user mode service"), "{json}");
    }

    // (f2) Clock changes: the threshold, the category `by`, and no process name ever emitted.

    #[test]
    fn f2a_one_hour_change_with_no_process_is_by_none_with_both_times_and_reason() {
        let system = system_with(vec![clock(Some(START), START + 3600, None, Some(2))]);
        let observations = system_observations(&windows_host(), &system, ROOT);
        let changes = clocks_of(&observations);
        assert_eq!(changes.len(), 1);
        let change = changes[0];
        assert_eq!(change.fields["log"], Value::from("system"));
        assert_eq!(
            change.fields["changed_at"],
            Value::from(at(START + 3600).to_string())
        );
        assert_eq!(
            change.fields["old_time"],
            Value::from(at(START).to_string())
        );
        assert_eq!(
            change.fields["new_time"],
            Value::from(at(START + 3600).to_string())
        );
        assert_eq!(change.fields["reason"], Value::from(2));
        assert_eq!(change.fields["by"], Value::from("none"));
        assert_eq!(
            summary_of(&observations).fields["small_clock_changes"],
            Value::from(0)
        );
    }

    #[test]
    fn f2b_sixty_one_seconds_by_a_windows_system32_process_is_by_windows() {
        let process = r"\Device\HarddiskVolume3\Windows\System32\svchost.exe";
        let system = system_with(vec![clock(Some(START), START + 61, Some(process), Some(1))]);
        let observations = system_observations(&windows_host(), &system, ROOT);
        let changes = clocks_of(&observations);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].fields["by"], Value::from("windows"));
        let json = serde_json::to_string(&observations).unwrap();
        assert!(!json.contains("svchost"), "{json}");
    }

    #[test]
    fn f2c_two_hour_change_by_a_user_program_is_by_other_and_names_no_one() {
        let process = r"\Device\HarddiskVolume3\Users\bob\t.exe";
        let system = system_with(vec![clock(Some(START), START + 7200, Some(process), Some(2))]);
        let observations = system_observations(&windows_host(), &system, ROOT);
        let changes = clocks_of(&observations);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].fields["by"], Value::from("other"));
        let json = serde_json::to_string(&observations).unwrap();
        assert!(!json.contains("bob"), "{json}");
        assert!(!json.contains("t.exe"), "{json}");
    }

    #[test]
    fn f2d_changes_under_the_threshold_are_counted_not_drawn() {
        let system = system_with(vec![
            clock(Some(START), START + 30, None, None),
            clock(Some(START + 100), START + 130, None, None),
        ]);
        let observations = system_observations(&windows_host(), &system, ROOT);
        assert!(clocks_of(&observations).is_empty(), "{observations:?}");
        let summary = summary_of(&observations);
        assert_eq!(summary.fields["small_clock_changes"], Value::from(2));
        assert_eq!(
            summary.fields["small_first"],
            Value::from(at(START + 30).to_string())
        );
        assert_eq!(
            summary.fields["small_last"],
            Value::from(at(START + 130).to_string())
        );
    }

    #[test]
    fn f2e_a_change_with_a_missing_time_is_counted_as_unreadable_not_drawn() {
        let system = system_with(vec![clock(None, START + 3600, None, Some(2))]);
        let observations = system_observations(&windows_host(), &system, ROOT);
        assert!(clocks_of(&observations).is_empty(), "{observations:?}");
        assert_eq!(
            summary_of(&observations).fields["unreadable_clock_changes"],
            Value::from(1)
        );
    }

    // (f3) Outcomes through FixtureHost, and the declarations the crate binds to the code.

    #[test]
    fn f3a_no_logs_is_unmeasured_as_source_absent() {
        assert_eq!(
            EventFields.collect(&windows_host()),
            CollectorRun::Unmeasured {
                collector: "event_fields".to_owned(),
                reason: UnmeasuredReason::SourceAbsent,
            }
        );
    }

    /// `System.evtx` is the first log, so with it absent the run takes its reason, even though the
    /// Security log was refused for want of an elevated token.
    #[test]
    fn f3b_all_three_unread_takes_the_first_logs_reason() {
        let host = FixtureHost::from_yaml_str(
            "platform: windows\nenv:\n  SystemRoot: 'C:\\Windows'\nelevated: false\naccess_denied: ['C:\\Windows\\System32\\winevt\\Logs\\Security.evtx']\n",
            "inline",
        )
        .unwrap();
        assert_eq!(
            EventFields.collect(&host),
            CollectorRun::Unmeasured {
                collector: "event_fields".to_owned(),
                reason: UnmeasuredReason::SourceAbsent,
            }
        );
    }

    #[test]
    fn f3c_non_windows_is_not_windows() {
        assert_eq!(
            EventFields.collect(&NonWindowsHost),
            CollectorRun::Unmeasured {
                collector: "event_fields".to_owned(),
                reason: UnmeasuredReason::NotWindows,
            }
        );
    }

    #[test]
    fn f3d_the_collector_is_standard_tier_and_discriminated_by_log() {
        assert_eq!(EventFields.tier(), ScanTier::Standard);
        assert_eq!(EventFields.discriminator(), Some("log"));
    }

    #[test]
    fn f3e_old_and_new_time_are_off_the_timeline_and_changed_at_is_on_it() {
        let field = |name: &str| {
            *EventFields
                .fields()
                .iter()
                .find(|field| field.name == name)
                .unwrap_or_else(|| panic!("`{name}` is declared"))
        };
        for name in ["old_time", "new_time"] {
            assert_eq!(field(name).kind, FieldKind::Timestamp, "{name}");
            assert!(!field(name).on_timeline, "{name} is off the timeline");
        }
        assert_eq!(field("changed_at").kind, FieldKind::Timestamp);
        assert!(field("changed_at").on_timeline);
    }

    // (f4) Refused images (Code Integrity 3033): one observation per volume-path digest, so a device path and
    // a drive-letter path to the same file are one row; a name with no digest is only counted.

    /// A 3033 that refused `file_name` at `seconds`; `None` when the event carried no file name.
    fn refusal(seconds: i64, file_name: Option<&str>) -> ImageRefusal {
        ImageRefusal {
            written: at(seconds),
            file_name: file_name.map(str::to_owned),
        }
    }

    fn code_integrity_with(refusals: Vec<ImageRefusal>) -> CodeIntegrityFields {
        CodeIntegrityFields {
            refusals,
            rejected: Vec::new(),
        }
    }

    /// The observations that describe a refused image, the only kind with `volume_path_digest`.
    fn refusals_of(observations: &[Observation]) -> Vec<&Observation> {
        observations
            .iter()
            .filter(|observation| observation.fields.contains_key("volume_path_digest"))
            .collect()
    }

    #[test]
    fn f4a_refusals_of_one_file_under_two_spellings_are_one_observation_per_digest() {
        let code_integrity = code_integrity_with(vec![
            refusal(START + 5, Some(r"\Device\HarddiskVolume5\Tools\x.dll")),
            refusal(START + 20, Some(r"D:\Tools\X.DLL")),
            refusal(START + 50, Some(r"D:\Tools\X.DLL")),
            refusal(START + 100, Some(r"\Device\HarddiskVolume5\Tools\y.dll")),
        ]);
        let observations = code_integrity_observations(&code_integrity);
        let refusals = refusals_of(&observations);
        assert_eq!(refusals.len(), 2, "{observations:?}");

        let x_digest = volume_path_digest(r"\Device\HarddiskVolume5\Tools\x.dll").unwrap();
        let y_digest = volume_path_digest(r"\Device\HarddiskVolume5\Tools\y.dll").unwrap();
        let x = refusals
            .iter()
            .find(|observation| observation.fields["volume_path_digest"] == x_digest.clone())
            .expect("one observation for x.dll");
        let y = refusals
            .iter()
            .find(|observation| observation.fields["volume_path_digest"] == y_digest.clone())
            .expect("one observation for y.dll");

        assert_eq!(x.fields["log"], Value::from("code_integrity"));
        assert_eq!(x.fields["events"], Value::from(3));
        assert_eq!(x.fields["first_seen"], Value::from(at(START + 5).to_string()));
        assert_eq!(x.fields["last_seen"], Value::from(at(START + 50).to_string()));
        assert_eq!(y.fields["log"], Value::from("code_integrity"));
        assert_eq!(y.fields["events"], Value::from(1));
        assert_eq!(y.fields["first_seen"], Value::from(at(START + 100).to_string()));
        assert_eq!(y.fields["last_seen"], Value::from(at(START + 100).to_string()));
        assert_eq!(
            summary_of(&observations).fields["unresolved_images"],
            Value::from(0)
        );

        let json = serde_json::to_string(&observations).unwrap();
        assert!(!json.to_ascii_lowercase().contains("x.dll"), "{json}");
        assert!(!json.contains("Tools"), "{json}");
    }

    #[test]
    fn f4b_a_refusal_with_no_digest_is_counted_as_unresolved_and_its_name_is_not_emitted() {
        for file_name in [Some("x.dll"), None] {
            let code_integrity = code_integrity_with(vec![refusal(START, file_name)]);
            let observations = code_integrity_observations(&code_integrity);
            assert!(refusals_of(&observations).is_empty(), "{observations:?}");
            assert_eq!(
                summary_of(&observations).fields["unresolved_images"],
                Value::from(1)
            );
            let json = serde_json::to_string(&observations).unwrap();
            assert!(!json.to_ascii_lowercase().contains("x.dll"), "{json}");
            assert!(!json.contains("Tools"), "{json}");
        }
    }

    // (f5) Security clock changes (4616): a change at or over the threshold is drawn with both times and no
    // reason and no `by`; a smaller one is only counted.

    fn security_with(clock_changes: Vec<ClockChange>) -> SecurityFields {
        SecurityFields {
            clock_changes,
            rejected: Vec::new(),
        }
    }

    #[test]
    fn f5a_two_hour_security_change_is_one_observation_with_both_times_and_no_reason_or_by() {
        let process = r"\Device\HarddiskVolume3\Users\bob\t.exe";
        let security = security_with(vec![clock(Some(START), START + 7200, Some(process), Some(2))]);
        let observations = security_observations(&security);
        let changes = clocks_of(&observations);
        assert_eq!(changes.len(), 1, "{observations:?}");
        let change = changes[0];
        assert_eq!(change.fields["log"], Value::from("security"));
        assert_eq!(
            change.fields["changed_at"],
            Value::from(at(START + 7200).to_string())
        );
        assert_eq!(change.fields["old_time"], Value::from(at(START).to_string()));
        assert_eq!(
            change.fields["new_time"],
            Value::from(at(START + 7200).to_string())
        );
        assert!(!change.fields.contains_key("reason"), "{change:?}");
        assert!(!change.fields.contains_key("by"), "{change:?}");
        assert_eq!(
            summary_of(&observations).fields["small_clock_changes"],
            Value::from(0)
        );
        let json = serde_json::to_string(&observations).unwrap();
        assert!(!json.contains("bob"), "{json}");
        assert!(!json.contains("t.exe"), "{json}");
    }

    #[test]
    fn f5b_ten_second_security_change_is_counted_as_small_and_not_drawn() {
        let security = security_with(vec![clock(Some(START), START + 10, None, None)]);
        let observations = security_observations(&security);
        assert!(clocks_of(&observations).is_empty(), "{observations:?}");
        let summary = summary_of(&observations);
        assert_eq!(summary.fields["small_clock_changes"], Value::from(1));
        assert_eq!(
            summary.fields["small_first"],
            Value::from(at(START + 10).to_string())
        );
        assert_eq!(
            summary.fields["small_last"],
            Value::from(at(START + 10).to_string())
        );
    }
}
