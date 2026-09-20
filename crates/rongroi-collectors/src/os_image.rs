// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! What Windows says this installation is, and how the services Windows ships with are set to start
//! (ADR 0056).
//!
//! One run produces one observation, in the shape `posture` uses (ADR 0011): every value that could be
//! read is a field, every value that could not is a `gaps` entry under that field's own name, so a rule
//! that needs it is `unmeasured` rather than `not_found`.
//!
//! - **Identity**, from [`CURRENT_VERSION_KEY`]: the edition, the build, and `RegisteredOrganization`,
//!   which is where `winver` shows a name and where two published Windows-modification playbooks write
//!   their own.
//! - **OEM information**, from [`OEM_INFORMATION_KEY`]: what Settings shows as the manufacturer, the
//!   model and the support link. An ordinary retail PC carries all three — a board vendor's name was
//!   measured there — so only the specific strings a rule names mean anything (ADR 0056).
//! - **Services Windows ships with**, from [`SERVICES_KEY`]: how each of [`SERVICES`] is set to start,
//!   or `absent` when its key is not there at all. A key that is not there is a statement about the
//!   machine — an image that removed the component — and so a value rather than a gap. That reading
//!   depends on having listed [`SERVICES_KEY`] itself: when that key could not be listed, every
//!   service field is a gap instead, because "not registered" would otherwise be said about a place
//!   nobody read.
//!
//! `RegisteredOwner` is not read: it holds the name of the person who set the PC up and answers neither
//! question (ADR 0056).

use std::collections::BTreeMap;

use rongroi_core::model::{CollectorRun, Observation, UnmeasuredReason};
use rongroi_host::{Host, Platform, SourceError};

use crate::{Collector, Field};

const ID: &str = "os_image";

/// Where Windows keeps what this installation is.
pub const CURRENT_VERSION_KEY: &str = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion";
/// Where Windows keeps what Settings shows as the manufacturer and the model.
pub const OEM_INFORMATION_KEY: &str =
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation";
/// The key whose subkeys are the services Windows knows, as `driver_service` reads it (ADR 0046).
pub const SERVICES_KEY: &str = r"HKLM\SYSTEM\CurrentControlSet\Services";
/// The value under a service's key that says when Windows starts it.
pub const START_VALUE: &str = "Start";

/// The identity values read from [`CURRENT_VERSION_KEY`], as `(field, value name)`.
///
/// `UBR` is the one number among them and is read separately.
const IDENTITY_TEXT: [(&str, &str); 8] = [
    ("build_lab_ex", "BuildLabEx"),
    ("composition_edition_id", "CompositionEditionID"),
    ("current_build", "CurrentBuild"),
    ("display_version", "DisplayVersion"),
    ("edition_id", "EditionID"),
    ("installation_type", "InstallationType"),
    ("product_name", "ProductName"),
    ("registered_organization", "RegisteredOrganization"),
];

/// The OEM values read from [`OEM_INFORMATION_KEY`], as `(field, value name)`.
const OEM_TEXT: [(&str, &str); 3] = [
    ("oem_manufacturer", "Manufacturer"),
    ("oem_model", "Model"),
    ("oem_support_url", "SupportURL"),
];

/// The services Windows ships with that this collector reads, as `(field, service key name)`.
///
/// Each one is a component a pre-modified image is sold for removing, and each one's absence or
/// disabled state has an ordinary explanation a rule has to name (ADR 0056). `EventLog` is here
/// because this program's own evidence comes from the log that service writes.
pub const SERVICES: [(&str, &str); 8] = [
    ("service_diagtrack", "DiagTrack"),
    ("service_dps", "DPS"),
    ("service_eventlog", "EventLog"),
    ("service_sysmain", "SysMain"),
    ("service_wersvc", "WerSvc"),
    ("service_windefend", "WinDefend"),
    ("service_wsearch", "WSearch"),
    ("service_wuauserv", "wuauserv"),
];

/// The word a service field takes when the service's key is not under [`SERVICES_KEY`] at all.
pub const SERVICE_ABSENT: &str = "absent";

static FIELDS: [Field; 20] = [
    Field::text("build_lab_ex"),
    Field::text("composition_edition_id"),
    Field::text("current_build"),
    Field::text("display_version"),
    Field::text("edition_id"),
    Field::text("installation_type"),
    Field::text("oem_manufacturer"),
    Field::text("oem_model"),
    Field::text("oem_support_url"),
    Field::text("product_name"),
    Field::text("registered_organization"),
    Field::text("service_diagtrack"),
    Field::text("service_dps"),
    Field::text("service_eventlog"),
    Field::text("service_sysmain"),
    Field::text("service_wersvc"),
    Field::text("service_windefend"),
    Field::text("service_wsearch"),
    Field::text("service_wuauserv"),
    Field::number("ubr"),
];

/// Every reason this collector gives for not having looked.
///
/// No administrator rights are needed for any of the three places on the machine ADR 0056 measured, but
/// that was measured with an elevated token alone, so a refusal is `access_denied` and not `not_admin`.
/// `source_absent` is a value that is not there under a key that is — never a service key that is not
/// there, which is a value this collector reports.
static REASONS: [UnmeasuredReason; 4] = [
    UnmeasuredReason::NotWindows,
    UnmeasuredReason::AccessDenied,
    UnmeasuredReason::SourceAbsent,
    UnmeasuredReason::ReadFailed,
];

/// Reads what Windows says this installation is.
#[derive(Debug, Default, Clone, Copy)]
pub struct OsImage;

impl Collector for OsImage {
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
            return CollectorRun::Unmeasured {
                collector: ID.to_owned(),
                reason: UnmeasuredReason::NotWindows,
            };
        }

        let mut fields = BTreeMap::new();
        let mut gaps = BTreeMap::new();

        for (field, value) in IDENTITY_TEXT {
            record_text(
                &mut fields,
                &mut gaps,
                field,
                host.read_string(CURRENT_VERSION_KEY, value),
            );
        }
        for (field, value) in OEM_TEXT {
            record_text(
                &mut fields,
                &mut gaps,
                field,
                host.read_string(OEM_INFORMATION_KEY, value),
            );
        }
        match host.read_u32(CURRENT_VERSION_KEY, "UBR") {
            Ok(Some(number)) => {
                fields.insert("ubr".to_owned(), serde_json::Value::from(number));
            }
            Ok(None) => {
                gaps.insert("ubr".to_owned(), UnmeasuredReason::SourceAbsent);
            }
            Err(error) => {
                gaps.insert("ubr".to_owned(), reason_for(&error));
            }
        }
        // The service keys are only read when the key they live under is itself there. Without that,
        // "this service is not registered" and "nothing under here was read" would be the same
        // answer, and the first is the reading this collector exists for (ADR 0056).
        let services_readable = match host.subkeys(SERVICES_KEY) {
            Ok(Some(_)) => Ok(()),
            Ok(None) => Err(UnmeasuredReason::SourceAbsent),
            Err(error) => Err(reason_for(&error)),
        };
        for (field, service) in SERVICES {
            let state = match services_readable {
                Ok(()) => service_start(host, service),
                Err(reason) => Err(reason),
            };
            match state {
                Ok(state) => {
                    fields.insert(field.to_owned(), serde_json::Value::from(state));
                }
                Err(reason) => {
                    gaps.insert(field.to_owned(), reason);
                }
            }
        }

        let observations = if fields.is_empty() {
            Vec::new()
        } else {
            vec![Observation {
                collector: ID.to_owned(),
                fields,
            }]
        };
        CollectorRun::Measured {
            collector: ID.to_owned(),
            observations,
            gaps,
            discriminator_gaps: Vec::new(),
        }
    }
}

/// Puts one string value in `fields`, or the reason it could not be read in `gaps`.
///
/// A value that is not there is `source_absent` rather than an empty string: "Windows keeps no such
/// value here" and "the value is there and empty" are different statements, and the machine ADR 0056
/// measured made the second one.
fn record_text(
    fields: &mut BTreeMap<String, serde_json::Value>,
    gaps: &mut BTreeMap<String, UnmeasuredReason>,
    name: &str,
    read: Result<Option<String>, SourceError>,
) {
    match read {
        Ok(Some(text)) => {
            fields.insert(name.to_owned(), serde_json::Value::from(text));
        }
        Ok(None) => {
            gaps.insert(name.to_owned(), UnmeasuredReason::SourceAbsent);
        }
        Err(error) => {
            gaps.insert(name.to_owned(), reason_for(&error));
        }
    }
}

/// How one service Windows ships with is set to start.
///
/// The service's key is looked for first, because its absence is the reading this collector exists for
/// and is not the same answer as a `Start` value that is not there under a key that is (ADR 0056).
fn service_start(host: &dyn Host, service: &str) -> Result<&'static str, UnmeasuredReason> {
    let key = format!(r"{SERVICES_KEY}\{service}");
    match host.value_names(&key) {
        Ok(None) => return Ok(SERVICE_ABSENT),
        Ok(Some(_)) => {}
        Err(error) => return Err(reason_for(&error)),
    }
    match host.read_u32(&key, START_VALUE) {
        Ok(Some(0)) => Ok("boot"),
        Ok(Some(1)) => Ok("system"),
        Ok(Some(2)) => Ok("automatic"),
        Ok(Some(3)) => Ok("manual"),
        Ok(Some(4)) => Ok("disabled"),
        // A number Windows does not define is not named here, and nothing is guessed from it.
        Ok(Some(_)) => Err(UnmeasuredReason::ReadFailed),
        Ok(None) => Err(UnmeasuredReason::SourceAbsent),
        Err(error) => Err(reason_for(&error)),
    }
}

/// How a failed source read is reported, as `posture` reports one.
fn reason_for(error: &SourceError) -> UnmeasuredReason {
    match error {
        SourceError::AccessDenied => UnmeasuredReason::AccessDenied,
        SourceError::Unsupported(_) | SourceError::Failed(_) | SourceError::TooLarge { .. } => {
            UnmeasuredReason::ReadFailed
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use rongroi_host::{FixtureHost, NonWindowsHost};

    use super::*;

    fn fixture(name: &str) -> FixtureHost {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/hosts")
            .join(name);
        FixtureHost::load(&dir).unwrap()
    }

    /// A fixture host written inline, for a machine no named fixture describes.
    fn inline(yaml: &str) -> FixtureHost {
        FixtureHost::from_yaml_str(yaml, "inline").unwrap()
    }

    /// The three places this collector reads, as they were measured on an ordinary Windows 11 PC
    /// (ADR 0056), with one service key left out of every other test's way.
    const ORDINARY: &str = r#"platform: windows
registry:
  'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion':
    ProductName: "Windows 10 Home"
    EditionID: "Core"
    CompositionEditionID: "Core"
    DisplayVersion: "25H2"
    CurrentBuild: "26220"
    BuildLabEx: "26100.6.amd64fre.ge_release_flt.260716-1700"
    InstallationType: "Client"
    RegisteredOrganization: ""
    UBR: 9492
  'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation':
    Manufacturer: "Msi"
    Model: "MS-7A36"
    SupportURL: "http://www.msi.com/"
  'HKLM\SYSTEM\CurrentControlSet\Services\WinDefend':
    Start: 2
  'HKLM\SYSTEM\CurrentControlSet\Services\EventLog':
    Start: 2
  'HKLM\SYSTEM\CurrentControlSet\Services\wuauserv':
    Start: 3
"#;

    fn field<'a>(run: &'a CollectorRun, name: &str) -> Option<&'a str> {
        match run {
            CollectorRun::Measured { observations, .. } => observations
                .first()
                .and_then(|observation| observation.fields.get(name))
                .and_then(serde_json::Value::as_str),
            CollectorRun::Unmeasured { .. } => None,
        }
    }

    fn gap_for(run: &CollectorRun, name: &str) -> Option<UnmeasuredReason> {
        match run {
            CollectorRun::Measured { gaps, .. } => gaps.get(name).copied(),
            CollectorRun::Unmeasured { .. } => None,
        }
    }

    #[test]
    fn identity_is_read_as_windows_spells_it() {
        let run = OsImage.collect(&inline(ORDINARY));
        assert_eq!(field(&run, "product_name"), Some("Windows 10 Home"));
        assert_eq!(field(&run, "edition_id"), Some("Core"));
        assert_eq!(field(&run, "display_version"), Some("25H2"));
        assert_eq!(field(&run, "current_build"), Some("26220"));
        assert_eq!(field(&run, "installation_type"), Some("Client"));
        assert_eq!(
            field(&run, "build_lab_ex"),
            Some("26100.6.amd64fre.ge_release_flt.260716-1700")
        );
    }

    /// The measured machine has the value and it is empty, which is not the same statement as having
    /// no such value (ADR 0056).
    #[test]
    fn an_empty_registered_organization_is_a_value_and_not_a_gap() {
        let run = OsImage.collect(&inline(ORDINARY));
        assert_eq!(field(&run, "registered_organization"), Some(""));
        assert_eq!(gap_for(&run, "registered_organization"), None);
    }

    #[test]
    fn ubr_is_a_number() {
        let run = OsImage.collect(&inline(ORDINARY));
        let CollectorRun::Measured { observations, .. } = &run else {
            panic!("a Windows host is measured");
        };
        assert_eq!(
            observations[0]
                .fields
                .get("ubr")
                .and_then(serde_json::Value::as_u64),
            Some(9492)
        );
    }

    #[test]
    fn oem_information_is_read_as_an_ordinary_pc_carries_it() {
        let run = OsImage.collect(&inline(ORDINARY));
        assert_eq!(field(&run, "oem_manufacturer"), Some("Msi"));
        assert_eq!(field(&run, "oem_model"), Some("MS-7A36"));
        assert_eq!(field(&run, "oem_support_url"), Some("http://www.msi.com/"));
    }

    #[test]
    fn a_playbook_that_named_itself_is_read_from_the_two_places_it_writes() {
        let run = OsImage.collect(&inline(
            r#"platform: windows
registry:
  'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion':
    RegisteredOrganization: "Atlas Playbook 0.4.1"
  'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation':
    Manufacturer: "Atlas Team"
    Model: "Atlas Playbook 0.4.1"
"#,
        ));
        assert_eq!(
            field(&run, "registered_organization"),
            Some("Atlas Playbook 0.4.1")
        );
        assert_eq!(field(&run, "oem_manufacturer"), Some("Atlas Team"));
        assert_eq!(field(&run, "oem_model"), Some("Atlas Playbook 0.4.1"));
    }

    #[test]
    fn each_start_number_has_its_word() {
        for (number, word) in [
            (0, "boot"),
            (1, "system"),
            (2, "automatic"),
            (3, "manual"),
            (4, "disabled"),
        ] {
            let run = OsImage.collect(&inline(&format!(
                "platform: windows\nregistry:\n  'HKLM\\SYSTEM\\CurrentControlSet\\Services\\WinDefend':\n    Start: {number}\n"
            )));
            assert_eq!(field(&run, "service_windefend"), Some(word));
        }
    }

    /// The reading this collector exists for: a component an image removed has no key at all, and that
    /// is a value rather than a gap (ADR 0056).
    #[test]
    fn a_service_key_that_is_not_there_is_absent_and_not_a_gap() {
        let run = OsImage.collect(&inline(ORDINARY));
        assert_eq!(field(&run, "service_sysmain"), Some(SERVICE_ABSENT));
        assert_eq!(gap_for(&run, "service_sysmain"), None);
    }

    /// A key that is there without a `Start` is a different answer, and nothing is guessed from it.
    #[test]
    fn a_service_key_without_a_start_value_is_a_gap() {
        let run = OsImage.collect(&inline(
            r"platform: windows
registry:
  'HKLM\SYSTEM\CurrentControlSet\Services\WinDefend':
    Type: 16
",
        ));
        assert_eq!(field(&run, "service_windefend"), None);
        assert_eq!(
            gap_for(&run, "service_windefend"),
            Some(UnmeasuredReason::SourceAbsent)
        );
    }

    #[test]
    fn a_start_number_windows_does_not_define_is_a_gap() {
        let run = OsImage.collect(&inline(
            r"platform: windows
registry:
  'HKLM\SYSTEM\CurrentControlSet\Services\WinDefend':
    Start: 9
",
        ));
        assert_eq!(
            gap_for(&run, "service_windefend"),
            Some(UnmeasuredReason::ReadFailed)
        );
    }

    #[test]
    fn a_value_that_is_not_there_is_a_gap_in_that_field_alone() {
        let run = OsImage.collect(&inline(
            r#"platform: windows
registry:
  'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion':
    EditionID: "Core"
"#,
        ));
        assert_eq!(field(&run, "edition_id"), Some("Core"));
        assert_eq!(
            gap_for(&run, "product_name"),
            Some(UnmeasuredReason::SourceAbsent)
        );
        assert_eq!(gap_for(&run, "ubr"), Some(UnmeasuredReason::SourceAbsent));
    }

    #[test]
    fn a_refused_key_is_a_gap_and_not_an_answer() {
        let run = OsImage.collect(&inline(
            r"platform: windows
registry:
  'HKLM\SYSTEM\CurrentControlSet\Services\WinDefend':
    Start: 2
access_denied:
  - 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
",
        ));
        assert_eq!(field(&run, "service_windefend"), Some("automatic"));
        assert_eq!(
            gap_for(&run, "product_name"),
            Some(UnmeasuredReason::AccessDenied)
        );
    }

    /// Without the key the service keys live under, "not registered" would be said about a place
    /// nobody read (ADR 0056).
    #[test]
    fn services_are_gaps_when_the_key_they_live_under_was_not_listed() {
        let run = OsImage.collect(&inline(
            r#"platform: windows
registry:
  'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion':
    EditionID: "Core"
"#,
        ));
        assert_eq!(field(&run, "service_windefend"), None);
        assert_eq!(
            gap_for(&run, "service_windefend"),
            Some(UnmeasuredReason::SourceAbsent)
        );
    }

    #[test]
    fn a_machine_that_is_not_windows_is_unmeasured() {
        let run = OsImage.collect(&NonWindowsHost);
        assert!(matches!(
            run,
            CollectorRun::Unmeasured {
                reason: UnmeasuredReason::NotWindows,
                ..
            }
        ));
    }

    /// A baseline host reads this collector, as a new collector must have one (ADR 0026).
    #[test]
    fn a_baseline_host_is_measured() {
        let run = OsImage.collect(&fixture("baseline-consumer-win11"));
        assert_eq!(field(&run, "edition_id"), Some("Core"));
        assert_eq!(field(&run, "service_windefend"), Some("automatic"));
    }
}
