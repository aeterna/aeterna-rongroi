// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! One full scan: run every collector, evaluate the bundle, freeze the report.
//! The CLI and the desktop app both call [`run`], so they cannot disagree about a result.

use rongroi_core::bundle::Bundle;
use rongroi_core::engine::{self, SelfIdentity};
use rongroi_core::model::{
    BootTime, CollectorRun, REPORT_SCHEMA_VERSION, Report, ReportHeader, UnmeasuredReason,
};
use rongroi_core::provenance::Provenance;
use rongroi_host::{Host, Platform, RegistryData};

/// Inputs that come from outside the scan: build provenance, the clock, and what this program is.
#[derive(Debug, Clone)]
pub struct ScanContext {
    /// Provenance of the running binary.
    pub provenance: Provenance,
    /// Scan time, UTC, RFC 3339.
    pub generated_at: String,
    /// What this program is, so that the engine can tell its own traces from evidence about the
    /// machine (ADR 0010). Computed by the caller's `main`, never read from the running process
    /// here, so that a fixture can exercise the whole path.
    pub self_identity: SelfIdentity,
}

/// Runs every collector against `host` and evaluates `bundle`.
pub fn run(host: &dyn Host, bundle: &Bundle, context: ScanContext) -> Report {
    // Before the collectors, so that the count is read as close as possible to `generated_at`, which
    // the caller took just before this call: the `evtx` collector alone may run for 30 seconds, and
    // reading the count after it would move the start that much earlier (ADR 0039).
    let boot_time = boot_time(host, &context.generated_at);
    let profiles_directory = profiles_directory(host);
    let runs: Vec<CollectorRun> = crate::all()
        .iter()
        .map(|collector| collector.collect(host))
        .collect();
    let header = ReportHeader {
        schema_version: REPORT_SCHEMA_VERSION,
        provenance: context.provenance,
        rules_bundle: bundle.info().clone(),
        platform: host.platform().as_str().to_owned(),
        os_build: host.os_build(),
        elevated: host.is_elevated(),
        generated_at: context.generated_at,
        boot_time,
        profiles_directory,
    };
    engine::evaluate(bundle, &runs, header, &context.self_identity)
}

/// When the running Windows kernel started counting, or why there is no value (ADR 0039).
///
/// Every failure is `read_failed`, as the `posture` collector reports a platform read that failed:
/// on a live host `GetTickCount64` has no failure to report, so this is reached by a fixture that did
/// not describe the count, never by a machine.
fn boot_time(host: &dyn Host, generated_at: &str) -> BootTime {
    if host.platform() != Platform::Windows {
        return BootTime::Unmeasured {
            reason: UnmeasuredReason::NotWindows,
        };
    }
    match host.since_boot() {
        Ok(since_boot) => BootTime::from_elapsed(generated_at, since_boot),
        Err(_) => BootTime::Unmeasured {
            reason: UnmeasuredReason::ReadFailed,
        },
    }
}

/// Where Windows keeps `ProfilesDirectory`, the folder new profiles are created in.
const PROFILE_LIST: &str = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";

/// The machine's profile root, for SS-mode redaction and nothing else (ADR 0049).
///
/// Every reason there is no value — not Windows, absent, unreadable, another type, not expandable —
/// is `None`: the view then redacts with the roots every machine has, and a reason would be a field
/// nothing reads.
fn profiles_directory(host: &dyn Host) -> Option<String> {
    if host.platform() != Platform::Windows {
        return None;
    }
    let Ok(Some(RegistryData::Text(stored))) = host.read_value(PROFILE_LIST, "ProfilesDirectory")
    else {
        return None;
    };
    expand_profiles_directory(&stored, host.env_var("SystemDrive").as_deref())
}

/// `stored` with a leading `%SystemDrive%` replaced by `system_drive`, kept only when the result is
/// drive-rooted and holds no other variable.
fn expand_profiles_directory(stored: &str, system_drive: Option<&str>) -> Option<String> {
    const VARIABLE: &str = "%SystemDrive%";
    let expanded = match stored.get(..VARIABLE.len()) {
        Some(head) if head.eq_ignore_ascii_case(VARIABLE) => {
            let drive = system_drive.filter(|drive| {
                let bytes = drive.as_bytes();
                bytes.len() == 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
            })?;
            format!("{drive}{}", &stored[VARIABLE.len()..])
        }
        _ => stored.to_owned(),
    };
    (crate::paths::is_drive_rooted(&expanded) && !expanded.contains('%')).then_some(expanded)
}

#[cfg(test)]
mod tests {
    use rongroi_host::FixtureHost;

    use super::*;

    fn host(yaml: &str) -> FixtureHost {
        FixtureHost::from_yaml_str(yaml, "inline").unwrap()
    }

    #[test]
    fn a_windows_host_that_answers_gives_a_measured_boot_time() {
        assert_eq!(
            boot_time(
                &host("platform: windows\nmilliseconds_since_boot: 3600000\n"),
                "2026-01-01T00:00:00Z"
            ),
            BootTime::Measured {
                booted_at: "2025-12-31T23:00:00Z".to_owned(),
                seconds_since_boot: 3600,
            }
        );
    }

    /// Not a value, and not the failure a Windows host would report: there is no Windows to ask.
    #[test]
    fn a_host_that_is_not_windows_is_not_windows_even_with_a_count() {
        assert_eq!(
            boot_time(
                &host("platform: other\nmilliseconds_since_boot: 3600000\n"),
                "2026-01-01T00:00:00Z"
            ),
            BootTime::Unmeasured {
                reason: UnmeasuredReason::NotWindows
            }
        );
        assert_eq!(
            boot_time(&rongroi_host::NonWindowsHost, "2026-01-01T00:00:00Z"),
            BootTime::Unmeasured {
                reason: UnmeasuredReason::NotWindows
            }
        );
    }

    #[test]
    fn a_windows_host_that_cannot_answer_is_read_failed_never_a_guess() {
        assert_eq!(
            boot_time(&host("platform: windows\n"), "2026-01-01T00:00:00Z"),
            BootTime::Unmeasured {
                reason: UnmeasuredReason::ReadFailed
            }
        );
    }

    #[test]
    fn the_stored_profiles_directory_is_expanded_with_the_system_drive() {
        assert_eq!(
            profiles_directory(&host(
                "platform: windows\nenv:\n  SystemDrive: 'D:'\nregistry:\n  'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList':\n    ProfilesDirectory: '%SystemDrive%\\Profiles'\n"
            ))
            .as_deref(),
            Some(r"D:\Profiles")
        );
        assert_eq!(
            expand_profiles_directory(r"%systemdrive%\Users", Some("C:")).as_deref(),
            Some(r"C:\Users")
        );
        assert_eq!(
            expand_profiles_directory(r"E:\Profiles", None).as_deref(),
            Some(r"E:\Profiles")
        );
    }

    /// Each is a value that names no folder this program can match, so redaction keeps to the roots
    /// every machine has.
    #[test]
    fn a_profiles_directory_that_is_not_a_drive_rooted_folder_is_none() {
        for (stored, system_drive) in [
            (r"%SystemDrive%\Users", None),
            (r"%SystemDrive%\Users", Some("")),
            (r"%SystemDrive%\Users", Some(r"C:\")),
            (r"%SystemRoot%\Profiles", Some("C:")),
            (r"C:\Users\%USERNAME%", Some("C:")),
            (r"\\server\profiles", Some("C:")),
            ("Users", Some("C:")),
            ("", Some("C:")),
        ] {
            assert_eq!(
                expand_profiles_directory(stored, system_drive),
                None,
                "{stored:?} with {system_drive:?}"
            );
        }
    }

    #[test]
    fn no_profiles_directory_without_windows_or_without_the_value() {
        let key =
            "registry:\n  'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList':\n";
        assert_eq!(
            profiles_directory(&host(&format!(
                "platform: other\n{key}    ProfilesDirectory: 'C:\\Users'\n"
            ))),
            None
        );
        assert_eq!(profiles_directory(&host("platform: windows\n")), None);
        assert_eq!(
            profiles_directory(&host(&format!(
                "platform: windows\n{key}    ProfilesDirectory: 1\n"
            ))),
            None
        );
    }
}
