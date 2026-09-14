// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! Machine settings that make cheating easier: Secure Boot — as Windows reports it and as the
//! firmware reports it — test signing, memory integrity (HVCI), the TPM, and whether a policy turns
//! script block logging off for Windows PowerShell or PowerShell 7.
//!
//! One run produces one observation holding every setting that could be read, so a rule can match on
//! more than one at a time. A setting that could not be read is a `gaps` entry instead, never a
//! guessed value: a rule that needs it is then `Unmeasured` rather than `NotFound` (ADR 0011).

use std::collections::BTreeMap;

use rongroi_core::model::{CollectorRun, Observation, UnmeasuredReason};
use rongroi_host::{FirmwareSecureBoot, Host, Platform, RegistryData, SourceError};

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

/// Registry key holding Windows PowerShell's script block logging policy for the machine (ADR 0038).
pub const SCRIPT_BLOCK_LOGGING_KEY: &str =
    r"HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging";
/// The same policy for the account this program runs as. After a restart with another administrator's
/// credentials that is the administrator, not the person at the keyboard (ADR 0038).
pub const SCRIPT_BLOCK_LOGGING_USER_KEY: &str =
    r"HKCU\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging";
/// Registry key holding PowerShell 7's script block logging policy for the machine (ADR 0038).
pub const PWSH_SCRIPT_BLOCK_LOGGING_KEY: &str =
    r"HKLM\SOFTWARE\Policies\Microsoft\PowerShellCore\ScriptBlockLogging";
/// PowerShell 7's policy for the account this program runs as.
pub const PWSH_SCRIPT_BLOCK_LOGGING_USER_KEY: &str =
    r"HKCU\SOFTWARE\Policies\Microsoft\PowerShellCore\ScriptBlockLogging";
/// The value that turns script block logging on (1) or off (0), in all four keys.
pub const SCRIPT_BLOCK_LOGGING_VALUE: &str = "EnableScriptBlockLogging";
/// The other value PowerShell 7 reads from its policy key. Not reported: whether it is set decides
/// whether PowerShell 7 goes on to the per-user key (ADR 0038).
pub const SCRIPT_BLOCK_INVOCATION_LOGGING_VALUE: &str = "EnableScriptBlockInvocationLogging";
/// In PowerShell 7's policy key, a non-zero `REG_DWORD` sends PowerShell 7 to Windows PowerShell's key
/// under the same root instead (ADR 0038).
pub const USE_WINDOWS_POWERSHELL_POLICY_VALUE: &str = "UseWindowsPowerShellPolicySetting";

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
/// two fields so a rule can compare them (ADR 0038). The four `script_block_logging` fields are one
/// policy as each PowerShell applies it, per engine and per hive; a policy nobody wrote and a policy
/// written to off are different statements about a machine, so none of them is a gap when absent.
const FIELDS: [Field; 10] = [
    Field::text("hvci"),
    Field::text("script_block_logging"),
    Field::text("script_block_logging_pwsh"),
    Field::text("script_block_logging_pwsh_user"),
    Field::text("script_block_logging_user"),
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
        let windows_powershell = windows_powershell_script_block_logging(host);
        record(
            &mut fields,
            &mut gaps,
            "script_block_logging",
            windows_powershell.machine,
        );
        record(
            &mut fields,
            &mut gaps,
            "script_block_logging_user",
            windows_powershell.user,
        );
        let pwsh = pwsh_script_block_logging(host);
        record(
            &mut fields,
            &mut gaps,
            "script_block_logging_pwsh",
            pwsh.machine,
        );
        record(
            &mut fields,
            &mut gaps,
            "script_block_logging_pwsh_user",
            pwsh.user,
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

/// What one PowerShell takes from the machine hive and from the account's own, as two field values.
struct ScriptBlockLoggingPolicy {
    machine: Result<&'static str, UnmeasuredReason>,
    user: Result<&'static str, UnmeasuredReason>,
}

/// The value a per-user field takes when PowerShell never reads the per-user key, because what it found
/// under `HKLM` settles where the policy comes from (ADR 0038).
const MACHINE_TAKES_PRECEDENCE: &str = "machine_takes_precedence";

/// Names an on/off answer.
fn switch(on: bool) -> &'static str {
    if on { "enabled" } else { "disabled" }
}

/// Windows PowerShell 5.1's script block logging policy, as measured on one CI runner (ADR 0038).
///
/// - The value counts when its data reads as the text `1` or `0`: a `REG_DWORD`, a `REG_QWORD` and a
///   `REG_SZ` holding 1 each turned logging on, and each holding 0 turned it off — the automatic record
///   of suspicious script blocks included. A `REG_DWORD` 2, and the key with no value, did neither.
/// - The machine key decides once it **exists**, whatever it holds: with it present and holding no
///   value, or 2, a per-user 0 was not applied. Only with no machine key did a per-user 1 or 0 apply.
///
/// Anything that does neither is `not_configured`: no policy this PowerShell applies from that hive.
fn windows_powershell_script_block_logging(host: &dyn Host) -> ScriptBlockLoggingPolicy {
    let machine = windows_powershell_switch(host, SCRIPT_BLOCK_LOGGING_KEY);
    let user = match host.value_names(SCRIPT_BLOCK_LOGGING_KEY) {
        Ok(Some(_)) => Ok(MACHINE_TAKES_PRECEDENCE),
        Ok(None) => windows_powershell_switch(host, SCRIPT_BLOCK_LOGGING_USER_KEY),
        // Whether the machine key is there decides whether the user's applies, so not knowing it is
        // not knowing the answer.
        Err(error) => Err(reason_for(&error)),
    };
    ScriptBlockLoggingPolicy { machine, user }
}

/// One Windows PowerShell policy key's `EnableScriptBlockLogging`, read the way 5.1 was measured to.
fn windows_powershell_switch(host: &dyn Host, key: &str) -> Result<&'static str, UnmeasuredReason> {
    let data = host
        .read_value(key, SCRIPT_BLOCK_LOGGING_VALUE)
        .map_err(|error| reason_for(&error))?;
    Ok(match windows_powershell_text(data) {
        Some("1") => "enabled",
        Some("0") => "disabled",
        _ => "not_configured",
    })
}

/// A value as the text 5.1's comparison would see: a number in decimal, a string as it is stored, and
/// nothing for a type whose data is not a number or a string.
fn windows_powershell_text(data: Option<RegistryData>) -> Option<&'static str> {
    match data {
        Some(RegistryData::Dword(1) | RegistryData::Qword(1)) => Some("1"),
        Some(RegistryData::Dword(0) | RegistryData::Qword(0)) => Some("0"),
        Some(RegistryData::Text(text)) if text == "1" => Some("1"),
        Some(RegistryData::Text(text)) if text == "0" => Some("0"),
        _ => None,
    }
}

/// PowerShell 7's script block logging policy (ADR 0038).
///
/// Read from PowerShell 7's source (`Utils.GetPolicySettingFromGPOImpl`) and measured on one CI runner:
///
/// - Only a `REG_DWORD` 1 or 0 counts. A `REG_SZ` 0 and a `REG_QWORD` 0 were ignored.
/// - A non-zero `REG_DWORD` `UseWindowsPowerShellPolicySetting` in PowerShell 7's key sends it to
///   Windows PowerShell's key under the same root, and PowerShell 7's own `EnableScriptBlockLogging` is
///   then not read — but Windows PowerShell's value still counts only as a `REG_DWORD`.
/// - The machine hive decides when the key it leads to sets `EnableScriptBlockLogging` or
///   `EnableScriptBlockInvocationLogging` to a `REG_DWORD` 1 or 0. Otherwise PowerShell 7 goes on to the
///   account's key, and after that to its configuration file, which this program does not read.
fn pwsh_script_block_logging(host: &dyn Host) -> ScriptBlockLoggingPolicy {
    match pwsh_scope(
        host,
        PWSH_SCRIPT_BLOCK_LOGGING_KEY,
        SCRIPT_BLOCK_LOGGING_KEY,
    ) {
        Ok(PwshScope::Decides(logging)) => ScriptBlockLoggingPolicy {
            machine: Ok(logging.map_or("not_configured", switch)),
            user: Ok(MACHINE_TAKES_PRECEDENCE),
        },
        Ok(PwshScope::MovesOn) => ScriptBlockLoggingPolicy {
            machine: Ok("not_configured"),
            user: pwsh_scope(
                host,
                PWSH_SCRIPT_BLOCK_LOGGING_USER_KEY,
                SCRIPT_BLOCK_LOGGING_USER_KEY,
            )
            .map(|scope| match scope {
                PwshScope::Decides(logging) => logging.map_or("not_configured", switch),
                PwshScope::MovesOn => "not_configured",
            }),
        },
        Err(reason) => ScriptBlockLoggingPolicy {
            machine: Err(reason),
            user: Err(reason),
        },
    }
}

/// What PowerShell 7 takes from one root.
enum PwshScope {
    /// Nothing it reads is set here, so it goes on to the next root.
    MovesOn,
    /// This root decides: it sets `EnableScriptBlockLogging` to on or off, or sets only
    /// `EnableScriptBlockInvocationLogging` and leaves script block logging as it is by default.
    Decides(Option<bool>),
}

/// What PowerShell 7 takes from one root.
fn pwsh_scope(
    host: &dyn Host,
    pwsh_key: &str,
    windows_powershell_key: &str,
) -> Result<PwshScope, UnmeasuredReason> {
    let read = |key: &str, value: &str| {
        host.read_value(key, value)
            .map_err(|error| reason_for(&error))
    };
    if host
        .value_names(pwsh_key)
        .map_err(|error| reason_for(&error))?
        .is_none()
    {
        return Ok(PwshScope::MovesOn);
    }
    let key = match read(pwsh_key, USE_WINDOWS_POWERSHELL_POLICY_VALUE)? {
        None | Some(RegistryData::Dword(0)) => pwsh_key,
        Some(RegistryData::Dword(_)) => {
            if host
                .value_names(windows_powershell_key)
                .map_err(|error| reason_for(&error))?
                .is_none()
            {
                return Ok(PwshScope::MovesOn);
            }
            windows_powershell_key
        }
        // PowerShell 7 casts this value to an integer, and what it does with one of another type was
        // not measured. It is there and names nothing this program can name.
        Some(_) => return Err(UnmeasuredReason::ReadFailed),
    };
    let dword = |data: Option<RegistryData>| match data {
        Some(RegistryData::Dword(1)) => Some(true),
        Some(RegistryData::Dword(0)) => Some(false),
        _ => None,
    };
    let logging = dword(read(key, SCRIPT_BLOCK_LOGGING_VALUE)?);
    let invocation = dword(read(key, SCRIPT_BLOCK_INVOCATION_LOGGING_VALUE)?);
    Ok(if logging.is_some() || invocation.is_some() {
        PwshScope::Decides(logging)
    } else {
        PwshScope::MovesOn
    })
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
                "script_block_logging_pwsh",
                "script_block_logging_pwsh_user",
                "script_block_logging_user",
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

    const NOT_CONFIGURED: &str = "not_configured";
    const ENABLED: &str = "enabled";
    const DISABLED: &str = "disabled";
    const MACHINE: &str = MACHINE_TAKES_PRECEDENCE;

    const WIN: &str = SCRIPT_BLOCK_LOGGING_KEY;
    const WIN_USER: &str = SCRIPT_BLOCK_LOGGING_USER_KEY;
    const PWSH: &str = PWSH_SCRIPT_BLOCK_LOGGING_KEY;
    const PWSH_USER: &str = PWSH_SCRIPT_BLOCK_LOGGING_USER_KEY;
    const ON: &str = "EnableScriptBlockLogging: 1";
    const OFF: &str = "EnableScriptBlockLogging: 0";
    const FALLBACK: &str = "UseWindowsPowerShellPolicySetting: 1";

    /// A name, the registry keys it writes with the YAML of their values, and the four fields expected.
    type Case = (
        &'static str,
        &'static [(&'static str, &'static str)],
        [&'static str; 4],
    );

    /// Every case the Windows CI runner measured (ADR 0038), in its order, with what Windows PowerShell
    /// 5.1 and PowerShell 7 did there, written as the four fields: Windows PowerShell's machine and
    /// per-user policy, then PowerShell 7's. A field that says `enabled` or `disabled` is one whose
    /// engine logged, or stopped logging, the marker blocks in that case. The last six were added from
    /// PowerShell 7's source and the first run's results, and measured in the second run.
    #[rustfmt::skip]
    const MEASURED: &[Case] = &[
        ("no policy", &[], [NOT_CONFIGURED, NOT_CONFIGURED, NOT_CONFIGURED, NOT_CONFIGURED]),
        ("machine DWORD 1", &[(WIN, ON)], [ENABLED, MACHINE, NOT_CONFIGURED, NOT_CONFIGURED]),
        ("machine DWORD 0", &[(WIN, OFF)], [DISABLED, MACHINE, NOT_CONFIGURED, NOT_CONFIGURED]),
        ("machine DWORD 2", &[(WIN, "EnableScriptBlockLogging: 2")], [NOT_CONFIGURED, MACHINE, NOT_CONFIGURED, NOT_CONFIGURED]),
        ("machine REG_SZ 1", &[(WIN, "EnableScriptBlockLogging: '1'")], [ENABLED, MACHINE, NOT_CONFIGURED, NOT_CONFIGURED]),
        ("machine REG_SZ 0", &[(WIN, "EnableScriptBlockLogging: '0'")], [DISABLED, MACHINE, NOT_CONFIGURED, NOT_CONFIGURED]),
        ("machine REG_QWORD 1", &[(WIN, "EnableScriptBlockLogging: { qword: 1 }")], [ENABLED, MACHINE, NOT_CONFIGURED, NOT_CONFIGURED]),
        ("machine REG_QWORD 0", &[(WIN, "EnableScriptBlockLogging: { qword: 0 }")], [DISABLED, MACHINE, NOT_CONFIGURED, NOT_CONFIGURED]),
        ("machine key with no value", &[(WIN, "")], [NOT_CONFIGURED, MACHINE, NOT_CONFIGURED, NOT_CONFIGURED]),
        ("user DWORD 1", &[(WIN_USER, ON)], [NOT_CONFIGURED, ENABLED, NOT_CONFIGURED, NOT_CONFIGURED]),
        ("user DWORD 0", &[(WIN_USER, OFF)], [NOT_CONFIGURED, DISABLED, NOT_CONFIGURED, NOT_CONFIGURED]),
        ("user REG_SZ 0", &[(WIN_USER, "EnableScriptBlockLogging: '0'")], [NOT_CONFIGURED, DISABLED, NOT_CONFIGURED, NOT_CONFIGURED]),
        ("machine DWORD 1, user DWORD 0", &[(WIN, ON), (WIN_USER, OFF)], [ENABLED, MACHINE, NOT_CONFIGURED, NOT_CONFIGURED]),
        ("machine DWORD 0, user DWORD 1", &[(WIN, OFF), (WIN_USER, ON)], [DISABLED, MACHINE, NOT_CONFIGURED, NOT_CONFIGURED]),
        ("machine key with no value, user DWORD 0", &[(WIN, ""), (WIN_USER, OFF)], [NOT_CONFIGURED, MACHINE, NOT_CONFIGURED, NOT_CONFIGURED]),
        ("machine DWORD 2, user DWORD 0", &[(WIN, "EnableScriptBlockLogging: 2"), (WIN_USER, OFF)], [NOT_CONFIGURED, MACHINE, NOT_CONFIGURED, NOT_CONFIGURED]),
        ("pwsh machine DWORD 1", &[(PWSH, ON)], [NOT_CONFIGURED, NOT_CONFIGURED, ENABLED, MACHINE]),
        ("pwsh machine DWORD 0", &[(PWSH, OFF)], [NOT_CONFIGURED, NOT_CONFIGURED, DISABLED, MACHINE]),
        ("pwsh machine REG_SZ 0", &[(PWSH, "EnableScriptBlockLogging: '0'")], [NOT_CONFIGURED, NOT_CONFIGURED, NOT_CONFIGURED, NOT_CONFIGURED]),
        ("pwsh machine REG_QWORD 0", &[(PWSH, "EnableScriptBlockLogging: { qword: 0 }")], [NOT_CONFIGURED, NOT_CONFIGURED, NOT_CONFIGURED, NOT_CONFIGURED]),
        ("pwsh machine fallback 1, machine DWORD 0", &[(PWSH, FALLBACK), (WIN, OFF)], [DISABLED, MACHINE, DISABLED, MACHINE]),
        ("pwsh machine fallback 1, machine DWORD 1", &[(PWSH, FALLBACK), (WIN, ON)], [ENABLED, MACHINE, ENABLED, MACHINE]),
        ("pwsh machine fallback 1, no machine policy", &[(PWSH, FALLBACK)], [NOT_CONFIGURED, NOT_CONFIGURED, NOT_CONFIGURED, NOT_CONFIGURED]),
        ("pwsh machine fallback 1 and DWORD 0, machine DWORD 1", &[(PWSH, "UseWindowsPowerShellPolicySetting: 1; EnableScriptBlockLogging: 0"), (WIN, ON)], [ENABLED, MACHINE, ENABLED, MACHINE]),
        ("pwsh user DWORD 0", &[(PWSH_USER, OFF)], [NOT_CONFIGURED, NOT_CONFIGURED, NOT_CONFIGURED, DISABLED]),
        ("pwsh machine DWORD 1, pwsh user DWORD 0", &[(PWSH, ON), (PWSH_USER, OFF)], [NOT_CONFIGURED, NOT_CONFIGURED, ENABLED, MACHINE]),
        ("pwsh user fallback 1, user DWORD 0", &[(PWSH_USER, FALLBACK), (WIN_USER, OFF)], [NOT_CONFIGURED, DISABLED, NOT_CONFIGURED, DISABLED]),
        ("machine REG_SZ 01", &[(WIN, "EnableScriptBlockLogging: '01'")], [NOT_CONFIGURED, MACHINE, NOT_CONFIGURED, NOT_CONFIGURED]),
        ("pwsh machine REG_SZ 0, pwsh user DWORD 0", &[(PWSH, "EnableScriptBlockLogging: '0'"), (PWSH_USER, OFF)], [NOT_CONFIGURED, NOT_CONFIGURED, NOT_CONFIGURED, DISABLED]),
        ("pwsh machine DWORD 2, pwsh user DWORD 0", &[(PWSH, "EnableScriptBlockLogging: 2"), (PWSH_USER, OFF)], [NOT_CONFIGURED, NOT_CONFIGURED, NOT_CONFIGURED, DISABLED]),
        ("pwsh machine invocation logging 1 only, pwsh user DWORD 0", &[(PWSH, "EnableScriptBlockInvocationLogging: 1"), (PWSH_USER, OFF)], [NOT_CONFIGURED, NOT_CONFIGURED, NOT_CONFIGURED, MACHINE]),
        ("pwsh machine fallback 1 with no machine key, pwsh user DWORD 0", &[(PWSH, FALLBACK), (PWSH_USER, OFF)], [NOT_CONFIGURED, NOT_CONFIGURED, NOT_CONFIGURED, DISABLED]),
        ("pwsh machine fallback 1, machine REG_SZ 0", &[(PWSH, FALLBACK), (WIN, "EnableScriptBlockLogging: '0'")], [DISABLED, MACHINE, NOT_CONFIGURED, NOT_CONFIGURED]),
    ];

    /// `ORDINARY` with registry keys added. Each entry is a key and the YAML of its values, `;` between
    /// two: `0` is a `REG_DWORD`, `'0'` a `REG_SZ`, `{ qword: 0 }` a `REG_QWORD`, and nothing a key with
    /// no value.
    fn with_policy(entries: &[(&str, &str)]) -> FixtureHost {
        use std::fmt::Write as _;
        let mut registry = String::from("registry:\n");
        for (key, values) in entries {
            if values.is_empty() {
                let _ = writeln!(registry, "  '{key}': {{}}");
            } else {
                let _ = writeln!(registry, "  '{key}':");
                for line in values.split(';') {
                    let _ = writeln!(registry, "    {}", line.trim());
                }
            }
        }
        inline(&ORDINARY.replace("registry:\n", &registry))
    }

    fn script_block_logging_fields(run: &CollectorRun) -> [Option<&str>; 4] {
        [
            field(run, "script_block_logging"),
            field(run, "script_block_logging_user"),
            field(run, "script_block_logging_pwsh"),
            field(run, "script_block_logging_pwsh_user"),
        ]
    }

    #[test]
    fn script_block_logging_follows_what_each_powershell_was_measured_to_do() {
        for (case, entries, expected) in MEASURED {
            let run = Posture.collect(&with_policy(entries));
            assert_eq!(
                script_block_logging_fields(&run),
                expected.map(Some),
                "{case}"
            );
        }
    }

    /// Of a value of a type that is not a number or a string, neither PowerShell reads a 1 or a 0.
    #[test]
    fn a_policy_value_of_another_type_turns_nothing_on_or_off() {
        let run = Posture.collect(&with_policy(&[
            (
                SCRIPT_BLOCK_LOGGING_KEY,
                "EnableScriptBlockLogging: { content: '0' }",
            ),
            (
                PWSH_SCRIPT_BLOCK_LOGGING_KEY,
                "EnableScriptBlockLogging: { content: '0' }",
            ),
        ]));
        assert_eq!(
            script_block_logging_fields(&run),
            [NOT_CONFIGURED, MACHINE, NOT_CONFIGURED, NOT_CONFIGURED].map(Some)
        );
    }

    /// PowerShell 7 casts `UseWindowsPowerShellPolicySetting` to an integer; what it does with a string
    /// there was not established, so both of its fields are a gap rather than a guess.
    #[test]
    fn a_pwsh_fallback_switch_that_is_not_a_dword_is_a_gap() {
        let run = Posture.collect(&with_policy(&[(
            PWSH_SCRIPT_BLOCK_LOGGING_KEY,
            "UseWindowsPowerShellPolicySetting: '1'",
        )]));
        for name in [
            "script_block_logging_pwsh",
            "script_block_logging_pwsh_user",
        ] {
            assert_eq!(field(&run, name), None, "{name}");
            assert_eq!(
                gap_for(&run, name),
                Some(UnmeasuredReason::ReadFailed),
                "{name}"
            );
        }
        assert_eq!(field(&run, "script_block_logging"), Some(NOT_CONFIGURED));
    }

    /// A machine key that cannot be opened leaves its own field and the per-user field unanswered:
    /// whether the machine key is there is what decides whether the per-user policy applies.
    #[test]
    fn a_denied_machine_key_leaves_the_per_user_policy_unanswered_too() {
        for (denied, names) in [
            (
                SCRIPT_BLOCK_LOGGING_KEY,
                ["script_block_logging", "script_block_logging_user"],
            ),
            (
                PWSH_SCRIPT_BLOCK_LOGGING_KEY,
                [
                    "script_block_logging_pwsh",
                    "script_block_logging_pwsh_user",
                ],
            ),
        ] {
            let run = Posture.collect(&inline(&format!(
                "{ORDINARY}access_denied:\n  - '{denied}'\n"
            )));
            for name in names {
                assert_eq!(
                    gap_for(&run, name),
                    Some(UnmeasuredReason::AccessDenied),
                    "{name}"
                );
            }
        }
    }

    #[test]
    fn a_denied_per_user_key_leaves_only_the_per_user_field_unanswered() {
        let run = Posture.collect(&inline(&format!(
            "{ORDINARY}access_denied:\n  - '{SCRIPT_BLOCK_LOGGING_USER_KEY}'\n  - '{PWSH_SCRIPT_BLOCK_LOGGING_USER_KEY}'\n"
        )));
        assert_eq!(field(&run, "script_block_logging"), Some(NOT_CONFIGURED));
        assert_eq!(
            field(&run, "script_block_logging_pwsh"),
            Some(NOT_CONFIGURED)
        );
        for name in [
            "script_block_logging_user",
            "script_block_logging_pwsh_user",
        ] {
            assert_eq!(
                gap_for(&run, name),
                Some(UnmeasuredReason::AccessDenied),
                "{name}"
            );
        }
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
