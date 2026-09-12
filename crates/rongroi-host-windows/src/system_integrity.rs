// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! What the running kernel reports about code integrity and test signing (ADR 0011).

use rongroi_host::CodeIntegrityOptions;

/// `CODEINTEGRITY_OPTION_ENABLED`: kernel-mode code integrity is enforcing driver signatures.
///
/// Written out rather than imported from `windows` so that the decoding below compiles and is tested
/// on every operating system. The value is the one declared in that crate's
/// `Win32::System::WindowsProgramming` (0.62.2).
pub const CODEINTEGRITY_OPTION_ENABLED: u32 = 0x1;

/// `CODEINTEGRITY_OPTION_TESTSIGN`: the kernel also accepts self-signed drivers.
pub const CODEINTEGRITY_OPTION_TESTSIGN: u32 = 0x2;

/// Decodes the options word the kernel reports.
///
/// The two bits are read by masking. The kernel sets a dozen other flags in the same word, so
/// comparing the whole value would make an unrelated setting change these answers.
pub fn options_from_bits(bits: u32) -> CodeIntegrityOptions {
    CodeIntegrityOptions {
        enabled: bits & CODEINTEGRITY_OPTION_ENABLED != 0,
        test_signing: bits & CODEINTEGRITY_OPTION_TESTSIGN != 0,
    }
}

#[cfg(windows)]
impl rongroi_host::SystemIntegritySource for crate::LiveHost {
    #[allow(unsafe_code)]
    fn code_integrity_options(&self) -> Result<CodeIntegrityOptions, rongroi_host::SourceError> {
        use windows::Wdk::System::SystemInformation::{
            NtQuerySystemInformation, SystemCodeIntegrityInformation,
        };
        use windows::Win32::System::WindowsProgramming::SYSTEM_CODEINTEGRITY_INFORMATION;

        let Ok(length) = u32::try_from(size_of::<SYSTEM_CODEINTEGRITY_INFORMATION>()) else {
            return Err(rongroi_host::SourceError::Failed(
                "SYSTEM_CODEINTEGRITY_INFORMATION does not fit in a u32".to_owned(),
            ));
        };
        // The caller states the size of its own buffer in `Length`; the kernel fills the rest.
        let mut info = SYSTEM_CODEINTEGRITY_INFORMATION {
            Length: length,
            CodeIntegrityOptions: 0,
        };
        let mut returned = 0_u32;

        // SAFETY: `info` is a fully initialised `SYSTEM_CODEINTEGRITY_INFORMATION` that outlives the
        // call, `length` is its own size in bytes and matches its `Length` field, and `returned` is a
        // valid out-pointer. The call only reads kernel state; it changes nothing on this machine.
        let status = unsafe {
            NtQuerySystemInformation(
                SystemCodeIntegrityInformation,
                (&raw mut info).cast(),
                length,
                &raw mut returned,
            )
        };

        if status.is_ok() {
            Ok(options_from_bits(info.CodeIntegrityOptions))
        } else {
            Err(rongroi_host::SourceError::Failed(format!(
                "NtQuerySystemInformation(SystemCodeIntegrityInformation) returned {:#x}",
                status.0
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_kernel_with_nothing_set_reports_neither() {
        let options = options_from_bits(0);
        assert!(!options.enabled);
        assert!(!options.test_signing);
    }

    #[test]
    fn the_enabled_bit_is_read_on_its_own() {
        let options = options_from_bits(CODEINTEGRITY_OPTION_ENABLED);
        assert!(options.enabled);
        assert!(!options.test_signing);
    }

    #[test]
    fn the_test_signing_bit_is_read_on_its_own() {
        let options = options_from_bits(CODEINTEGRITY_OPTION_TESTSIGN);
        assert!(!options.enabled);
        assert!(options.test_signing);
    }

    #[test]
    fn both_bits_can_be_set_at_once() {
        let options =
            options_from_bits(CODEINTEGRITY_OPTION_ENABLED | CODEINTEGRITY_OPTION_TESTSIGN);
        assert!(options.enabled);
        assert!(options.test_signing);
    }

    /// The kernel sets many other bits in the same word. Reading these two by masking, rather than by
    /// comparing the whole value, is what keeps an unrelated bit from changing the answer.
    #[test]
    fn unrelated_bits_do_not_change_either_answer() {
        // CODEINTEGRITY_OPTION_UMCI_ENABLED (0x4) and CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED (0x400).
        let noise = 0x4 | 0x400;
        let options = options_from_bits(CODEINTEGRITY_OPTION_ENABLED | noise);
        assert!(options.enabled);
        assert!(!options.test_signing);

        let options = options_from_bits(noise);
        assert!(!options.enabled);
        assert!(!options.test_signing);
    }
}
