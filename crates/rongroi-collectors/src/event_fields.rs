// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! Three payload fields read from three Event Logs near a game session (ADR 0081, sections 1 to 3).
//!
//! `System.evtx` gives the service installs (7045) and the clock changes (Kernel-General 1). The Code
//! Integrity and Security logs are read and summarised here; their observations come with ADR 0081
//! section 4. Each log is parsed once, on its own thread, within its own limit (ADR 0024).

#[cfg(test)]
mod tests {
    use jiff::Timestamp;
    use rongroi_core::digest::path_digest;
    use rongroi_core::model::{CollectorRun, Observation, UnmeasuredReason};
    use rongroi_host::{FixtureHost, NonWindowsHost};
    use rongroi_parsers::evtx::{ClockChange, ServiceInstall, SystemFields};
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
            process_name: process.map(str::to_owned),
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
}
