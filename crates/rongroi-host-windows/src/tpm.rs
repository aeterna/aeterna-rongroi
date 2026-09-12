// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! Whether this machine has a TPM, and which specification family it implements (ADR 0011).
//!
//! Nothing is submitted to the device: only the identity TBS already reports is read.

/// `TBS_SUCCESS`: TBS filled in the device info.
///
/// These codes are written out rather than imported from `windows` so that the classification below
/// compiles and is tested on every operating system. The values are those declared in that crate
/// (0.62.2): the TBS result codes in `Win32::Foundation`, the version numbers in
/// `Win32::System::TpmBaseServices`.
pub const TBS_SUCCESS: u32 = 0;

/// `TBS_E_TPM_NOT_FOUND`: TBS answered that this machine has no TPM.
pub const TBS_E_TPM_NOT_FOUND: u32 = 0x8028_400F;

/// `TPM_VERSION_UNKNOWN`.
pub const TPM_VERSION_UNKNOWN: u32 = 0;

/// `TPM_VERSION_12`.
pub const TPM_VERSION_12: u32 = 1;

/// `TPM_VERSION_20`.
pub const TPM_VERSION_20: u32 = 2;

/// What a TBS result code says about whether a TPM could be described.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceInfoOutcome {
    /// TBS filled in the device info.
    Answered,
    /// TBS reports that there is no TPM. That is an answer, not a failure to look (ADR 0011).
    NoTpm,
    /// Anything else: TBS could not answer, so nothing about a TPM was measured.
    Failed,
}

/// Classifies the result code `Tbsi_GetDeviceInfo` returns.
pub fn classify(result: u32) -> DeviceInfoOutcome {
    match result {
        TBS_SUCCESS => DeviceInfoOutcome::Answered,
        TBS_E_TPM_NOT_FOUND => DeviceInfoOutcome::NoTpm,
        _ => DeviceInfoOutcome::Failed,
    }
}

/// Names the specification family TBS reports.
///
/// `None` for a version this program cannot name: reporting an unrecognised number as though it were
/// a known family would be a guess, and a later rule compares this value literally.
pub fn spec_version(tpm_version: u32) -> Option<String> {
    match tpm_version {
        TPM_VERSION_12 => Some("1.2".to_owned()),
        TPM_VERSION_20 => Some("2.0".to_owned()),
        _ => None,
    }
}

#[cfg(windows)]
impl rongroi_host::TpmSource for crate::LiveHost {
    #[allow(unsafe_code)]
    fn tpm_info(&self) -> Result<rongroi_host::TpmInfo, rongroi_host::SourceError> {
        use windows::Win32::System::TpmBaseServices::{TPM_DEVICE_INFO, Tbsi_GetDeviceInfo};

        let Ok(size) = u32::try_from(size_of::<TPM_DEVICE_INFO>()) else {
            return Err(rongroi_host::SourceError::Failed(
                "TPM_DEVICE_INFO does not fit in a u32".to_owned(),
            ));
        };
        let mut info = TPM_DEVICE_INFO::default();

        // SAFETY: `info` is a fully initialised `TPM_DEVICE_INFO` that outlives the call and `size`
        // is its own size in bytes, which is the buffer TBS writes into. This asks TBS for the
        // device's identity only; no command is submitted to the TPM and nothing is changed.
        let result = unsafe { Tbsi_GetDeviceInfo(size, (&raw mut info).cast()) };

        match classify(result) {
            DeviceInfoOutcome::Answered => Ok(rongroi_host::TpmInfo {
                present: true,
                spec_version: spec_version(info.tpmVersion),
            }),
            // A machine with no TPM is an answer the collector can report, not a gap (ADR 0011).
            DeviceInfoOutcome::NoTpm => Ok(rongroi_host::TpmInfo {
                present: false,
                spec_version: None,
            }),
            DeviceInfoOutcome::Failed => Err(rongroi_host::SourceError::Failed(format!(
                "Tbsi_GetDeviceInfo returned {result:#x}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_success_code_means_tbs_answered() {
        assert_eq!(classify(TBS_SUCCESS), DeviceInfoOutcome::Answered);
    }

    /// A machine with no TPM is an answer, not a failure to look (ADR 0011).
    #[test]
    fn no_tpm_is_an_answer_rather_than_a_failure() {
        assert_eq!(classify(TBS_E_TPM_NOT_FOUND), DeviceInfoOutcome::NoTpm);
    }

    #[test]
    fn any_other_result_code_is_a_failure() {
        // TBS_E_SERVICE_NOT_RUNNING, TBS_E_ACCESS_DENIED, TBS_E_INTERNAL_ERROR.
        for code in [0x8028_4008_u32, 0x8028_4012_u32, 0x8028_4001_u32] {
            assert_eq!(classify(code), DeviceInfoOutcome::Failed, "{code:#x}");
        }
    }

    #[test]
    fn a_tpm_2_0_is_named() {
        assert_eq!(spec_version(TPM_VERSION_20).as_deref(), Some("2.0"));
    }

    #[test]
    fn a_tpm_1_2_is_named() {
        assert_eq!(spec_version(TPM_VERSION_12).as_deref(), Some("1.2"));
    }

    /// A version this program cannot name is reported as no version at all, never as a guess.
    #[test]
    fn an_unknown_version_is_not_guessed() {
        assert_eq!(spec_version(TPM_VERSION_UNKNOWN), None);
        assert_eq!(spec_version(99), None);
    }
}
