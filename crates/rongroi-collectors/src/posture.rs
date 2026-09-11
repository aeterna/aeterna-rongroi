// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! Machine settings that make cheating easier. M0 reads Secure Boot; test-signing, HVCI and TPM follow in M1.

use std::collections::BTreeMap;

use rongroi_core::model::{CollectorRun, Observation, UnmeasuredReason};
use rongroi_host::{Host, Platform, SourceError};

use crate::Collector;

/// Registry key where Windows reports the UEFI Secure Boot state.
pub const SECURE_BOOT_KEY: &str = r"HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State";
/// DWORD value: 1 = on, 0 = off.
pub const SECURE_BOOT_VALUE: &str = "UEFISecureBootEnabled";

const ID: &str = "posture";

/// The posture collector.
#[derive(Debug, Default, Clone, Copy)]
pub struct Posture;

impl Collector for Posture {
    fn id(&self) -> &'static str {
        ID
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
        match secure_boot(host) {
            Ok(state) => {
                fields.insert("secure_boot".to_owned(), serde_json::Value::from(state));
            }
            Err(reason) => {
                gaps.insert("secure_boot".to_owned(), reason);
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
        }
    }
}

fn secure_boot(host: &dyn Host) -> Result<&'static str, UnmeasuredReason> {
    match host.read_u32(SECURE_BOOT_KEY, SECURE_BOOT_VALUE) {
        Ok(Some(1)) => Ok("enabled"),
        Ok(Some(0)) => Ok("disabled"),
        // Not reported, e.g. legacy BIOS/CSM boot. We do not guess which.
        Ok(None) => Err(UnmeasuredReason::SourceMissing),
        Err(SourceError::AccessDenied) => Err(UnmeasuredReason::AccessDenied),
        Ok(Some(_)) | Err(_) => Err(UnmeasuredReason::ReadFailed),
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

    fn secure_boot_field(run: &CollectorRun) -> Option<&str> {
        match run {
            CollectorRun::Measured { observations, .. } => observations
                .first()
                .and_then(|o| o.fields.get("secure_boot"))
                .and_then(serde_json::Value::as_str),
            CollectorRun::Unmeasured { .. } => None,
        }
    }

    fn gap(run: &CollectorRun) -> Option<UnmeasuredReason> {
        match run {
            CollectorRun::Measured { gaps, .. } => gaps.get("secure_boot").copied(),
            CollectorRun::Unmeasured { .. } => None,
        }
    }

    #[test]
    fn secure_boot_on() {
        let run = Posture.collect(&fixture("secure-boot-on"));
        assert_eq!(secure_boot_field(&run), Some("enabled"));
    }

    #[test]
    fn secure_boot_off() {
        let run = Posture.collect(&fixture("secure-boot-off"));
        assert_eq!(secure_boot_field(&run), Some("disabled"));
    }

    #[test]
    fn secure_boot_not_reported_is_a_gap() {
        let run = Posture.collect(&fixture("secure-boot-unreported"));
        assert_eq!(secure_boot_field(&run), None);
        assert_eq!(gap(&run), Some(UnmeasuredReason::SourceMissing));
    }

    #[test]
    fn access_denied_is_a_gap() {
        let run = Posture.collect(&fixture("registry-access-denied"));
        assert_eq!(gap(&run), Some(UnmeasuredReason::AccessDenied));
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
