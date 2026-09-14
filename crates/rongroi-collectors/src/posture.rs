// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! Machine settings that make cheating easier: Secure Boot — as Windows reports it and as the
//! firmware reports it — test signing, memory integrity (HVCI), the TPM, and whether a machine policy
//! turns PowerShell script block logging off.
//!
//! One run produces one observation holding every setting that could be read, so a rule can match on
//! more than one at a time. A setting that could not be read is a `gaps` entry instead, never a
//! guessed value: a rule that needs it is then `Unmeasured` rather than `NotFound` (ADR 0011).

use std::collections::BTreeMap;

use rongroi_core::model::{CollectorRun, Observation, UnmeasuredReason};
use rongroi_host::{FirmwareSecureBoot, Host, Platform, SourceError};

use crate::{Collector, Field};

/// Registry key where Windows reports the UEFI Secure Boot state.
pub const SECURE_BOOT_KEY: &str = r"HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State";
/// DWORD value: 1 = on, 0 = off.
pub const SECURE_BOOT_VALUE: &str = "UEFISecureBootEnabled";

/// Registry key holding the *configured* memory-integrity (HVCI) policy.
///
/// This is what Windows was told to enforce, which is not the same as a confirmation that the
/// hypervisor is enforcing it: hardware without the necessary virtualisation support can carry this
/// setting and enforce nothing (ADR 0011).
pub const HVCI_KEY: &str =
    r"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity";
/// DWORD value: 1 = configured on, 0 = configured off.
pub const HVCI_VALUE: &str = "Enabled";

/// Registry key holding the Windows PowerShell script block logging policy (ADR 0038).
///
/// Only a machine policy is read. The same policy under `HKCU` is a per-user one, and a machine policy
/// takes precedence over it, so the value read here is decisive when it is set. When it is not set,
/// a per-user policy this program does not read may still apply, which is why an absent value is
/// reported as `not_configured` and never as "on" or "off". PowerShell 7 keeps its own policy under
/// `…\Policies\Microsoft\PowerShellCore`, which is not read either.
pub const SCRIPT_BLOCK_LOGGING_KEY: &str =
    r"HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging";
/// DWORD value: 1 = policy on, 0 = policy off, absent = policy not configured.
pub const SCRIPT_BLOCK_LOGGING_VALUE: &str = "EnableScriptBlockLogging";

const ID: &str = "posture";

/// Every reason this collector gives for not having looked (`Collector::unmeasured_reasons`).
///
/// A value the machine does not report, or a registry or platform read that was denied or
/// failed. `not_admin` is the firmware's Secure Boot variable alone: every other setting here is one
/// any account may read, and reading a firmware variable needs a privilege only an elevated token
/// holds (ADR 0038).
const REASONS: [UnmeasuredReason; 5] = [
    UnmeasuredReason::NotWindows,
    UnmeasuredReason::NotAdmin,
    UnmeasuredReason::AccessDenied,
    UnmeasuredReason::SourceAbsent,
    UnmeasuredReason::ReadFailed,
];

/// Every field this collector can emit.
///
/// Unlike the collectors that read one artifact, a setting this one could not read is a gap in that
/// setting alone and in nothing else: one observation carries every setting that was readable, and
/// each name below is both a field and a `gaps` key (ADR 0011). `tpm_spec_version` is the one name
/// that is never a gap — an absent TPM has no version, and that is not a failure to measure.
///
/// `secure_boot` and `secure_boot_firmware` are two readings of one setting from two places, kept as
/// two fields so a rule can compare them (ADR 0038). `script_block_logging` has three values, because
/// a policy nobody wrote and a policy written to off are different statements about a machine.
const FIELDS: [Field; 7] = [
    Field::text("hvci"),
    Field::text("script_block_logging"),
    Field::text("secure_boot"),
    Field::text("secure_boot_firmware"),
    Field::text("test_signing"),
    Field::text("tpm"),
    Field::text("tpm_spec_version"),
];

/// The posture collector.
#[derive(Debug, Default, Clone, Copy)]
pub struct Posture;

impl Collector for Posture {
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
        record(&mut fields, &mut gaps, "secure_boot", secure_boot(host));
        record(&mut fields, &mut gaps, "hvci", hvci(host));
        record(&mut fields, &mut gaps, "test_signing", test_signing(host));
        record(
            &mut fields,
            &mut gaps,
            "secure_boot_firmware",
            secure_boot_firmware(host),
        );
        record(
            &mut fields,
            &mut gaps,
            "script_block_logging",
            script_block_logging(host),
        );

        match host.tpm_info() {
            Ok(info) => {
                let present = if info.present { "present" } else { "absent" };
                fields.insert("tpm".to_owned(), serde_json::Value::from(present));
                // An absent TPM has no version, and a version this program cannot name is left out
                // rather than guessed. The field's absence is not a gap: `tpm` itself was measured.
                if let Some(version) = info.spec_version {
                    fields.insert(
                        "tpm_spec_version".to_owned(),
                        serde_json::Value::from(version),
                    );
                }
            }
            Err(error) => {
                gaps.insert("tpm".to_owned(), reason_for(&error));
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

/// Puts one setting in `fields`, or the reason it could not be read in `gaps`.
fn record(
    fields: &mut BTreeMap<String, serde_json::Value>,
    gaps: &mut BTreeMap<String, UnmeasuredReason>,
    name: &str,
    value: Result<&'static str, UnmeasuredReason>,
) {
    match value {
        Ok(state) => {
            fields.insert(name.to_owned(), serde_json::Value::from(state));
        }
        Err(reason) => {
            gaps.insert(name.to_owned(), reason);
        }
    }
}

/// How a failed source read is reported.
///
/// `Unsupported` and `TooLarge` are reported the same way as `Failed`, as `fivem_dir` already does:
/// in every case the setting was not read, and nothing about it may be presented as "not found".
fn reason_for(error: &SourceError) -> UnmeasuredReason {
    match error {
        SourceError::AccessDenied => UnmeasuredReason::AccessDenied,
        SourceError::Unsupported(_) | SourceError::Failed(_) | SourceError::TooLarge { .. } => {
            UnmeasuredReason::ReadFailed
        }
    }
}

/// Reads a DWORD that means on at 1 and off at 0.
///
/// An absent value is not the same statement as "off" — on many machines the key is simply not there
/// — so it becomes a gap rather than a guess.
fn registry_switch(
    read: Result<Option<u32>, SourceError>,
) -> Result<&'static str, UnmeasuredReason> {
    match read {
        Ok(Some(1)) => Ok("enabled"),
        Ok(Some(0)) => Ok("disabled"),
        Ok(None) => Err(UnmeasuredReason::SourceAbsent),
        Ok(Some(_)) => Err(UnmeasuredReason::ReadFailed),
        Err(error) => Err(reason_for(&error)),
    }
}

/// Whether UEFI Secure Boot is on. Not reported at all on e.g. legacy BIOS/CSM boot, which is a gap.
fn secure_boot(host: &dyn Host) -> Result<&'static str, UnmeasuredReason> {
    registry_switch(host.read_u32(SECURE_BOOT_KEY, SECURE_BOOT_VALUE))
}

/// What the firmware's own `SecureBoot` variable says (ADR 0038).
///
/// A denial is split by elevation, as the artifact collectors split it: the privilege the read needs
/// is one only an elevated token holds, so on an ordinary scan this is `not_admin` and restarting as
/// administrator is what would answer it. Legacy BIOS boot, and UEFI firmware without the variable,
/// are both a place the setting is not kept — `source_absent`, as the registry reading reports it.
fn secure_boot_firmware(host: &dyn Host) -> Result<&'static str, UnmeasuredReason> {
    match host.firmware_secure_boot() {
        Ok(FirmwareSecureBoot::Enabled) => Ok("enabled"),
        Ok(FirmwareSecureBoot::Disabled) => Ok("disabled"),
        Ok(FirmwareSecureBoot::VariableAbsent | FirmwareSecureBoot::NotUefi) => {
            Err(UnmeasuredReason::SourceAbsent)
        }
        Err(error) => Err(crate::failure::reason_for(host, &error)),
    }
}

/// Whether a machine policy turns Windows PowerShell script block logging on or off (ADR 0038).
///
/// Unlike the other registry settings here, an absent value is an answer: Windows ships with no such
/// policy, and "nobody configured this" is what most machines say. It is `not_configured`, which is
/// neither `enabled` nor `disabled`. A value of another type or another number is there and means
/// nothing this program can name, so it is a gap rather than a guess.
fn script_block_logging(host: &dyn Host) -> Result<&'static str, UnmeasuredReason> {
    match host.read_u32(SCRIPT_BLOCK_LOGGING_KEY, SCRIPT_BLOCK_LOGGING_VALUE) {
        Ok(Some(1)) => Ok("enabled"),
        Ok(Some(0)) => Ok("disabled"),
        Ok(None) => Ok("not_configured"),
        Ok(Some(_)) => Err(UnmeasuredReason::ReadFailed),
        Err(error) => Err(reason_for(&error)),
    }
}

/// Whether memory integrity (HVCI) is configured on. See [`HVCI_KEY`] for what that does not say.
fn hvci(host: &dyn Host) -> Result<&'static str, UnmeasuredReason> {
    registry_switch(host.read_u32(HVCI_KEY, HVCI_VALUE))
}

/// Whether the kernel accepts self-signed drivers.
fn test_signing(host: &dyn Host) -> Result<&'static str, UnmeasuredReason> {
    match host.code_integrity_options() {
        Ok(options) if options.test_signing => Ok("enabled"),
        Ok(_) => Ok("disabled"),
        Err(error) => Err(reason_for(&error)),
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

    /// A fixture host written inline, for the cases where what matters is a setting a named fixture
    /// deliberately does not have.
    fn inline(yaml: &str) -> FixtureHost {
        FixtureHost::from_yaml_str(yaml, "inline").unwrap()
    }

    /// An ordinary Windows machine, against which one setting at a time can be varied.
    const ORDINARY: &str = "platform: windows
registry:
  'HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State':
    UEFISecureBootEnabled: 1
  'HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity':
    Enabled: 1
code_integrity:
  enabled: true
  test_signing: false
tpm:
  present: true
  spec_version: \"2.0\"
firmware:
  secure_boot: enabled
";

    fn field<'a>(run: &'a CollectorRun, name: &str) -> Option<&'a str> {
        match run {
            CollectorRun::Measured { observations, .. } => observations
                .first()
                .and_then(|o| o.fields.get(name))
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
    fn secure_boot_on() {
        let run = Posture.collect(&fixture("secure-boot-on"));
        assert_eq!(field(&run, "secure_boot"), Some("enabled"));
    }

    #[test]
    fn secure_boot_off() {
        let run = Posture.collect(&fixture("secure-boot-off"));
        assert_eq!(field(&run, "secure_boot"), Some("disabled"));
    }

    #[test]
    fn secure_boot_not_reported_is_a_gap() {
        let run = Posture.collect(&fixture("secure-boot-unreported"));
        assert_eq!(field(&run, "secure_boot"), None);
        assert_eq!(
            gap_for(&run, "secure_boot"),
            Some(UnmeasuredReason::SourceAbsent)
        );
    }

    #[test]
    fn access_denied_is_a_gap() {
        let run = Posture.collect(&fixture("registry-access-denied"));
        assert_eq!(
            gap_for(&run, "secure_boot"),
            Some(UnmeasuredReason::AccessDenied)
        );
    }

    #[test]
    fn test_signing_off_is_reported_as_disabled() {
        let run = Posture.collect(&fixture("secure-boot-on"));
        assert_eq!(field(&run, "test_signing"), Some("disabled"));
    }

    #[test]
    fn test_signing_on_is_reported_as_enabled() {
        let run = Posture.collect(&fixture("test-signing-on"));
        assert_eq!(field(&run, "test_signing"), Some("enabled"));
    }

    /// A host that cannot describe code integrity must leave a gap, so that a rule reading
    /// `test_signing` comes out `Unmeasured` rather than `NotFound`.
    #[test]
    fn code_integrity_that_cannot_be_read_is_a_gap() {
        let run = Posture.collect(&inline("platform: windows\n"));
        assert_eq!(field(&run, "test_signing"), None);
        assert_eq!(
            gap_for(&run, "test_signing"),
            Some(UnmeasuredReason::ReadFailed)
        );
    }

    #[test]
    fn hvci_configured_on_is_reported_as_enabled() {
        let run = Posture.collect(&fixture("secure-boot-on"));
        assert_eq!(field(&run, "hvci"), Some("enabled"));
    }

    #[test]
    fn hvci_configured_off_is_reported_as_disabled() {
        let run = Posture.collect(&inline(&ORDINARY.replace("Enabled: 1", "Enabled: 0")));
        assert_eq!(field(&run, "hvci"), Some("disabled"));
    }

    /// The policy key is absent on machines where it was never configured. That is not the same
    /// statement as "off", so the collector reports a gap rather than guessing.
    #[test]
    fn hvci_not_configured_is_a_gap() {
        let yaml = "platform: windows
code_integrity:
  enabled: true
  test_signing: false
tpm:
  present: true
";
        let run = Posture.collect(&inline(yaml));
        assert_eq!(field(&run, "hvci"), None);
        assert_eq!(gap_for(&run, "hvci"), Some(UnmeasuredReason::SourceAbsent));
    }

    #[test]
    fn a_present_tpm_reports_its_specification_version() {
        let run = Posture.collect(&fixture("secure-boot-on"));
        assert_eq!(field(&run, "tpm"), Some("present"));
        assert_eq!(field(&run, "tpm_spec_version"), Some("2.0"));
    }

    /// No TPM is an answer, not a gap — and an absent TPM has no version to report.
    #[test]
    fn an_absent_tpm_is_measured_and_has_no_version() {
        let run = Posture.collect(&fixture("tpm-absent"));
        assert_eq!(field(&run, "tpm"), Some("absent"));
        assert_eq!(field(&run, "tpm_spec_version"), None);
        assert_eq!(gap_for(&run, "tpm"), None);
    }

    #[test]
    fn a_tpm_that_cannot_be_read_is_a_gap() {
        let run = Posture.collect(&inline("platform: windows\n"));
        assert_eq!(field(&run, "tpm"), None);
        assert_eq!(gap_for(&run, "tpm"), Some(UnmeasuredReason::ReadFailed));
    }

    /// One run, one observation: every setting the collector read sits in the same observation, so a
    /// rule can match on more than one of them at once.
    #[test]
    fn every_setting_lands_in_one_observation() {
        let run = Posture.collect(&inline(ORDINARY));
        let CollectorRun::Measured { observations, .. } = &run else {
            panic!("expected a measured run, got {run:?}");
        };
        assert_eq!(observations.len(), 1);
        let names: Vec<&str> = observations[0].fields.keys().map(String::as_str).collect();
        assert_eq!(
            names,
            [
                "hvci",
                "script_block_logging",
                "secure_boot",
                "secure_boot_firmware",
                "test_signing",
                "tpm",
                "tpm_spec_version"
            ]
        );
    }

    /// The named fixtures describe a scan without administrator rights, which is what a limited token
    /// gets from the firmware.
    #[test]
    fn a_limited_fixture_host_cannot_read_the_firmware() {
        let run = Posture.collect(&fixture("secure-boot-on"));
        assert_eq!(
            gap_for(&run, "secure_boot_firmware"),
            Some(UnmeasuredReason::NotAdmin)
        );
        let run = Posture.collect(&fixture("secure-boot-unreported"));
        assert_eq!(
            gap_for(&run, "secure_boot_firmware"),
            Some(UnmeasuredReason::SourceAbsent)
        );
    }

    #[test]
    fn firmware_secure_boot_on_and_off_are_reported() {
        let run = Posture.collect(&inline(ORDINARY));
        assert_eq!(field(&run, "secure_boot_firmware"), Some("enabled"));
        let run = Posture.collect(&inline(
            &ORDINARY.replace("secure_boot: enabled", "secure_boot: disabled"),
        ));
        assert_eq!(field(&run, "secure_boot_firmware"), Some("disabled"));
        // The registry reading is its own field and is not overwritten by the firmware's.
        assert_eq!(field(&run, "secure_boot"), Some("enabled"));
    }

    /// Legacy BIOS boot and UEFI firmware without the variable are both a place the setting is not
    /// kept. Neither is "off".
    #[test]
    fn no_firmware_variable_to_read_is_source_absent() {
        for state in ["not_uefi", "variable_absent"] {
            let run = Posture.collect(&inline(
                &ORDINARY.replace("secure_boot: enabled", &format!("secure_boot: {state}")),
            ));
            assert_eq!(field(&run, "secure_boot_firmware"), None, "{state}");
            assert_eq!(
                gap_for(&run, "secure_boot_firmware"),
                Some(UnmeasuredReason::SourceAbsent),
                "{state}"
            );
        }
    }

    /// The privilege a firmware read needs is one only an elevated token holds, so a denial without
    /// administrator rights is `not_admin` — and the other settings, which need no elevation, are
    /// still read.
    #[test]
    fn a_firmware_read_denied_without_admin_rights_is_not_admin() {
        let denied = ORDINARY.replace("secure_boot: enabled", "secure_boot: access_denied");
        let run = Posture.collect(&inline(&format!("elevated: false\n{denied}")));
        assert_eq!(
            gap_for(&run, "secure_boot_firmware"),
            Some(UnmeasuredReason::NotAdmin)
        );
        assert_eq!(field(&run, "secure_boot"), Some("enabled"));
        assert_eq!(gap_for(&run, "secure_boot"), None);

        let run = Posture.collect(&inline(&format!("elevated: true\n{denied}")));
        assert_eq!(
            gap_for(&run, "secure_boot_firmware"),
            Some(UnmeasuredReason::AccessDenied)
        );
    }

    #[test]
    fn a_firmware_read_that_fails_or_is_not_described_is_read_failed() {
        let run = Posture.collect(&inline(
            &ORDINARY.replace("secure_boot: enabled", "secure_boot: read_failed"),
        ));
        assert_eq!(
            gap_for(&run, "secure_boot_firmware"),
            Some(UnmeasuredReason::ReadFailed)
        );
        let run = Posture.collect(&inline("platform: windows\n"));
        assert_eq!(
            gap_for(&run, "secure_boot_firmware"),
            Some(UnmeasuredReason::ReadFailed)
        );
    }

    fn with_script_block_logging(value: &str) -> FixtureHost {
        inline(&ORDINARY.replace(
            "registry:\n",
            &format!(
                "registry:\n  'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging':\n    EnableScriptBlockLogging: {value}\n"
            ),
        ))
    }

    /// Windows ships with no such policy. That is an answer about the machine, not a gap, and it is a
    /// different answer from a policy written to off.
    #[test]
    fn script_block_logging_not_configured_is_its_own_value() {
        let run = Posture.collect(&inline(ORDINARY));
        assert_eq!(field(&run, "script_block_logging"), Some("not_configured"));
        assert_eq!(gap_for(&run, "script_block_logging"), None);
    }

    #[test]
    fn script_block_logging_policy_on_and_off_are_reported() {
        let run = Posture.collect(&with_script_block_logging("1"));
        assert_eq!(field(&run, "script_block_logging"), Some("enabled"));
        let run = Posture.collect(&with_script_block_logging("0"));
        assert_eq!(field(&run, "script_block_logging"), Some("disabled"));
    }

    /// A number other than 0 or 1, or a value of another type, is there and names nothing this program
    /// can name — never "off", and never "not configured".
    #[test]
    fn a_script_block_logging_value_that_means_nothing_known_is_a_gap() {
        for value in ["2", "'0'"] {
            let run = Posture.collect(&with_script_block_logging(value));
            assert_eq!(field(&run, "script_block_logging"), None, "{value}");
            assert_eq!(
                gap_for(&run, "script_block_logging"),
                Some(UnmeasuredReason::ReadFailed),
                "{value}"
            );
        }
    }

    #[test]
    fn a_script_block_logging_policy_that_cannot_be_read_is_access_denied() {
        let yaml = format!(
            "{ORDINARY}access_denied:\n  - 'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging'\n"
        );
        let run = Posture.collect(&inline(&yaml));
        assert_eq!(
            gap_for(&run, "script_block_logging"),
            Some(UnmeasuredReason::AccessDenied)
        );
    }

    #[test]
    fn non_windows_is_unmeasured() {
        let run = Posture.collect(&NonWindowsHost);
        assert_eq!(
            run,
            CollectorRun::Unmeasured {
                collector: "posture".to_owned(),
                reason: UnmeasuredReason::NotWindows
            }
        );
    }
}
