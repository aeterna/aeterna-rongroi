// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! What the platform firmware itself reports about UEFI Secure Boot (ADR 0038).
//!
//! The registry value `UEFISecureBootEnabled` is what Windows wrote about Secure Boot. This reads the
//! UEFI `SecureBoot` variable instead, through `GetFirmwareEnvironmentVariableExW`, so the two can be
//! compared. Nothing is written to the firmware and nothing on the machine is changed: the one thing
//! this touches is this program's own token, where `SeSystemEnvironmentPrivilege` is enabled for the
//! read — the documented requirement for reading a firmware variable — and put back as it was.

use rongroi_host::{FirmwareSecureBoot, SourceError};

/// The UEFI variable that says whether the firmware is enforcing Secure Boot.
pub const SECURE_BOOT_VARIABLE: &str = "SecureBoot";

/// The EFI global-variable namespace `SecureBoot` lives in, in the form `lpGuid` takes. The same GUID
/// Microsoft's own Secure Boot scripts pass as `$efi_guid` (ADR 0038).
pub const EFI_GLOBAL_VARIABLE_GUID: &str = "{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}";

/// `FirmwareTypeBios`. These values are written out rather than imported from `windows` so that the
/// classification below compiles and is tested on every operating system; each is the one declared
/// in that crate (0.62.2): the firmware types in `Win32::System::SystemInformation`, the error codes
/// in `Win32::Foundation`.
pub const FIRMWARE_TYPE_BIOS: i32 = 1;

/// `FirmwareTypeUefi`.
pub const FIRMWARE_TYPE_UEFI: i32 = 2;

/// `ERROR_INVALID_FUNCTION`: what Microsoft documents a firmware-variable read returning on a system
/// Windows started through legacy BIOS.
pub const ERROR_INVALID_FUNCTION: u32 = 1;

/// `ERROR_ENVVAR_NOT_FOUND`: the firmware holds no variable of that name in that namespace.
pub const ERROR_ENVVAR_NOT_FOUND: u32 = 203;

/// `ERROR_NOT_ALL_ASSIGNED`: `AdjustTokenPrivileges` succeeded and the token does not hold the
/// privilege, so nothing was enabled.
pub const ERROR_NOT_ALL_ASSIGNED: u32 = 1300;

/// `ERROR_PRIVILEGE_NOT_HELD`: the read needed a privilege this process does not have enabled.
pub const ERROR_PRIVILEGE_NOT_HELD: u32 = 1314;

/// What `GetFirmwareType` says about how Windows was started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirmwareKind {
    /// UEFI: firmware variables can be read.
    Uefi,
    /// Legacy BIOS: there are none.
    Bios,
    /// A value this program cannot name.
    Unknown,
}

/// Classifies the `FIRMWARE_TYPE` value `GetFirmwareType` fills in.
pub fn firmware_kind(value: i32) -> FirmwareKind {
    match value {
        FIRMWARE_TYPE_UEFI => FirmwareKind::Uefi,
        FIRMWARE_TYPE_BIOS => FirmwareKind::Bios,
        _ => FirmwareKind::Unknown,
    }
}

/// Turns the result of one `GetFirmwareEnvironmentVariableExW` call into an answer.
///
/// `returned` is the function's return value — the number of bytes it stored, or 0 on failure —
/// `buffer` the bytes it was handed, and `last_error` what `GetLastError` said straight afterwards,
/// which is only consulted when `returned` is 0.
///
/// The variable is one byte, 1 or 0. Any other length or value is a failure and never read as either
/// state: a later rule compares this answer literally, and a guess would be a finding this program
/// invented.
pub fn secure_boot_from_read(
    returned: u32,
    buffer: &[u8],
    last_error: u32,
) -> Result<FirmwareSecureBoot, SourceError> {
    if returned == 0 {
        return match last_error {
            ERROR_ENVVAR_NOT_FOUND => Ok(FirmwareSecureBoot::VariableAbsent),
            ERROR_INVALID_FUNCTION => Ok(FirmwareSecureBoot::NotUefi),
            ERROR_PRIVILEGE_NOT_HELD => Err(SourceError::AccessDenied),
            other => Err(SourceError::Failed(format!(
                "GetFirmwareEnvironmentVariableExW(SecureBoot) failed with error {other}"
            ))),
        };
    }
    let length = usize::try_from(returned).unwrap_or(usize::MAX);
    match buffer.get(..length) {
        Some([1]) => Ok(FirmwareSecureBoot::Enabled),
        Some([0]) => Ok(FirmwareSecureBoot::Disabled),
        Some(bytes) => Err(SourceError::Failed(format!(
            "the SecureBoot variable holds {} byte(s) that are not a single 0 or 1",
            bytes.len()
        ))),
        None => Err(SourceError::Failed(format!(
            "GetFirmwareEnvironmentVariableExW reported {returned} bytes for a {}-byte buffer",
            buffer.len()
        ))),
    }
}

#[cfg(windows)]
impl rongroi_host::FirmwareSource for crate::LiveHost {
    #[allow(unsafe_code)]
    fn firmware_secure_boot(&self) -> Result<FirmwareSecureBoot, SourceError> {
        use windows::Win32::System::SystemInformation::{FIRMWARE_TYPE, GetFirmwareType};

        let mut kind = FIRMWARE_TYPE::default();
        // SAFETY: `kind` is an initialised `FIRMWARE_TYPE` that outlives the call and is the one
        // out-pointer the function takes. It only reports how Windows was started.
        unsafe { GetFirmwareType(&raw mut kind) }
            .map_err(|error| SourceError::Failed(format!("GetFirmwareType failed: {error}")))?;
        match firmware_kind(kind.0) {
            // No firmware variables exist to read, and asking for a privilege to read none would
            // report a missing right where the answer is that there is nothing there.
            FirmwareKind::Bios => return Ok(FirmwareSecureBoot::NotUefi),
            FirmwareKind::Unknown => {
                return Err(SourceError::Failed(format!(
                    "GetFirmwareType returned {}, which is not a firmware type this program can name",
                    kind.0
                )));
            }
            FirmwareKind::Uefi => {}
        }

        let privilege = SystemEnvironmentPrivilege::enable()?;
        let result = read_secure_boot_variable();
        privilege.restore();
        result
    }
}

/// Reads the `SecureBoot` variable. The caller has already enabled the privilege the read needs.
#[cfg(windows)]
#[allow(unsafe_code)]
fn read_secure_boot_variable() -> Result<FirmwareSecureBoot, SourceError> {
    use windows::Win32::Foundation::GetLastError;
    use windows::Win32::System::WindowsProgramming::GetFirmwareEnvironmentVariableExW;
    use windows::core::HSTRING;

    let name = HSTRING::from(SECURE_BOOT_VARIABLE);
    let guid = HSTRING::from(EFI_GLOBAL_VARIABLE_GUID);
    // Larger than the one byte the variable holds, so that a firmware answering with more is refused
    // by `secure_boot_from_read` as the wrong shape rather than failing as a buffer too small.
    let mut buffer = [0_u8; 8];
    let Ok(size) = u32::try_from(buffer.len()) else {
        return Err(SourceError::Failed(
            "the variable buffer does not fit in a u32".to_owned(),
        ));
    };
    // SAFETY: `name` and `guid` are NUL-terminated wide strings that outlive the call, `buffer` is
    // `size` writable bytes that outlive it, and no attribute pointer is passed. The call reads one
    // firmware variable and writes nothing to the firmware.
    let returned = unsafe {
        GetFirmwareEnvironmentVariableExW(
            &name,
            &guid,
            Some(buffer.as_mut_ptr().cast()),
            size,
            None,
        )
    };
    let last_error = if returned == 0 {
        // SAFETY: no call has been made on this thread since the one whose error this reads.
        unsafe { GetLastError() }.0
    } else {
        0
    };
    secure_boot_from_read(returned, &buffer, last_error)
}

/// `SeSystemEnvironmentPrivilege`, enabled in this process's token for one read and then put back.
#[cfg(windows)]
struct SystemEnvironmentPrivilege {
    token: windows::Win32::Foundation::HANDLE,
    previous: windows::Win32::Security::TOKEN_PRIVILEGES,
}

#[cfg(windows)]
impl SystemEnvironmentPrivilege {
    /// Enables the privilege, or reports [`SourceError::AccessDenied`] when the token does not hold
    /// it — which is the case for every process without administrator rights.
    #[allow(unsafe_code)]
    fn enable() -> Result<Self, SourceError> {
        use windows::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, LUID};
        use windows::Win32::Security::{
            AdjustTokenPrivileges, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW,
            SE_PRIVILEGE_ENABLED, SE_SYSTEM_ENVIRONMENT_NAME, TOKEN_ADJUST_PRIVILEGES,
            TOKEN_PRIVILEGES, TOKEN_QUERY,
        };
        use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

        let mut luid = LUID::default();
        // SAFETY: the privilege name is a static wide string, `None` means this machine, and `luid`
        // is a valid out-pointer.
        unsafe { LookupPrivilegeValueW(None, SE_SYSTEM_ENVIRONMENT_NAME, &raw mut luid) }.map_err(
            |error| SourceError::Failed(format!("LookupPrivilegeValueW failed: {error}")),
        )?;

        let mut token = HANDLE::default();
        // SAFETY: `GetCurrentProcess` returns a pseudo-handle for this process, and `token` is a
        // valid out-pointer. The access asked for is to query and adjust privileges, nothing more.
        unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                &raw mut token,
            )
        }
        .map_err(|error| SourceError::Failed(format!("OpenProcessToken failed: {error}")))?;

        let wanted = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        let mut previous = TOKEN_PRIVILEGES::default();
        let mut returned = 0_u32;
        let Ok(length) = u32::try_from(size_of::<TOKEN_PRIVILEGES>()) else {
            // SAFETY: `token` was opened above and is closed once.
            let _ = unsafe { CloseHandle(token) };
            return Err(SourceError::Failed(
                "TOKEN_PRIVILEGES does not fit in a u32".to_owned(),
            ));
        };
        // SAFETY: `token` is open with TOKEN_ADJUST_PRIVILEGES, `wanted` is a one-entry
        // `TOKEN_PRIVILEGES`, `previous` is `length` writable bytes — room for the one privilege this
        // can change — and `returned` is a valid out-pointer. Only this process's token changes.
        let adjusted = unsafe {
            AdjustTokenPrivileges(
                token,
                false,
                Some(&raw const wanted),
                length,
                Some(&raw mut previous),
                Some(&raw mut returned),
            )
        };
        // `AdjustTokenPrivileges` succeeds when the token does not hold the privilege at all and says
        // so only through the last error, so the error is read even on success.
        // SAFETY: no call has been made on this thread since `AdjustTokenPrivileges`.
        let last_error = unsafe { GetLastError() }.0;
        match adjusted {
            Ok(()) if last_error != ERROR_NOT_ALL_ASSIGNED => Ok(Self { token, previous }),
            Ok(()) => {
                // SAFETY: `token` was opened above and is closed once.
                let _ = unsafe { CloseHandle(token) };
                Err(SourceError::AccessDenied)
            }
            Err(error) => {
                // SAFETY: as above.
                let _ = unsafe { CloseHandle(token) };
                Err(SourceError::Failed(format!(
                    "AdjustTokenPrivileges failed: {error}"
                )))
            }
        }
    }

    /// Puts the privilege back as it was and closes the token.
    ///
    /// `previous` holds only the privileges the enabling call changed, so a privilege that was already
    /// enabled is left enabled. A failure here changes no answer and leaves nothing on the machine —
    /// the token is this process's and ends with it — so it is not reported.
    #[allow(unsafe_code)]
    fn restore(self) {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::Security::AdjustTokenPrivileges;

        if self.previous.PrivilegeCount > 0 {
            // SAFETY: `self.token` is still open with TOKEN_ADJUST_PRIVILEGES and `self.previous` is
            // the state the enabling call returned.
            let _ = unsafe {
                AdjustTokenPrivileges(
                    self.token,
                    false,
                    Some(&raw const self.previous),
                    0,
                    None,
                    None,
                )
            };
        }
        // SAFETY: `self.token` was opened in `enable` and is closed once, here.
        let _ = unsafe { CloseHandle(self.token) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The attributes `SeSystemEnvironmentPrivilege` has in this process's token right now, or `None`
    /// when the token does not hold it.
    #[cfg(windows)]
    #[allow(unsafe_code)]
    fn system_environment_privilege_attributes() -> Option<u32> {
        use windows::Win32::Foundation::{CloseHandle, HANDLE, LUID};
        use windows::Win32::Security::{
            GetTokenInformation, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW,
            SE_SYSTEM_ENVIRONMENT_NAME, TOKEN_QUERY, TokenPrivileges,
        };
        use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

        let mut luid = LUID::default();
        // SAFETY: a static privilege name, this machine, and a valid out-pointer.
        unsafe { LookupPrivilegeValueW(None, SE_SYSTEM_ENVIRONMENT_NAME, &raw mut luid) }.unwrap();
        let mut token = HANDLE::default();
        // SAFETY: this process's pseudo-handle, query access only, and a valid out-pointer.
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) }.unwrap();
        // u32 words keep the DWORD fields of TOKEN_PRIVILEGES aligned; 4096 words is far more than
        // the few dozen privileges a token holds.
        let mut buffer = vec![0_u32; 4096];
        let mut needed = 0_u32;
        let bytes = u32::try_from(buffer.len() * 4).unwrap();
        // SAFETY: `buffer` is `bytes` writable bytes that outlive the call.
        let result = unsafe {
            GetTokenInformation(
                token,
                TokenPrivileges,
                Some(buffer.as_mut_ptr().cast()),
                bytes,
                &raw mut needed,
            )
        };
        // SAFETY: `token` was opened above and is closed once.
        let _ = unsafe { CloseHandle(token) };
        result.unwrap();
        let count = usize::try_from(buffer[0]).unwrap();
        // SAFETY: the kernel wrote `count` LUID_AND_ATTRIBUTES entries straight after the count, and
        // the buffer is large enough for them, as `GetTokenInformation` succeeding says.
        let entries = unsafe {
            std::slice::from_raw_parts(buffer.as_ptr().add(1).cast::<LUID_AND_ATTRIBUTES>(), count)
        };
        entries
            .iter()
            .find(|entry| entry.Luid == luid)
            .map(|entry| entry.Attributes.0)
    }

    /// Run by the Windows CI job (ADR 0038). The read enables a privilege in this process's own token
    /// and must put it back as it found it: an answer that left the token changed would be this
    /// program changing something it said it only reads.
    #[cfg(windows)]
    #[test]
    #[ignore = "reads this machine's firmware; run by the Windows CI job"]
    fn live_firmware_read_leaves_the_privilege_as_it_found_it() {
        use rongroi_host::FirmwareSource as _;

        let before = system_environment_privilege_attributes();
        let answer = crate::LiveHost.firmware_secure_boot();
        let after = system_environment_privilege_attributes();
        println!("firmware_secure_boot: {answer:?} · privilege before {before:?} after {after:?}");
        assert_eq!(before, after);
        // An elevated runner holds the privilege, so the read itself must not be the missing-rights
        // answer there.
        if before.is_some() {
            assert_ne!(answer, Err(SourceError::AccessDenied));
        }
    }

    #[test]
    fn firmware_types_are_named() {
        assert_eq!(firmware_kind(FIRMWARE_TYPE_UEFI), FirmwareKind::Uefi);
        assert_eq!(firmware_kind(FIRMWARE_TYPE_BIOS), FirmwareKind::Bios);
        // `FirmwareTypeUnknown` and `FirmwareTypeMax` are not firmware this program can name.
        assert_eq!(firmware_kind(0), FirmwareKind::Unknown);
        assert_eq!(firmware_kind(3), FirmwareKind::Unknown);
    }

    #[test]
    fn one_byte_holding_one_or_zero_is_the_state() {
        assert_eq!(
            secure_boot_from_read(1, &[1, 0, 0, 0], 0),
            Ok(FirmwareSecureBoot::Enabled)
        );
        assert_eq!(
            secure_boot_from_read(1, &[0, 0, 0, 0], 0),
            Ok(FirmwareSecureBoot::Disabled)
        );
    }

    /// Anything else is refused rather than read as either state.
    #[test]
    fn any_other_shape_is_a_failure_not_a_state() {
        for (returned, buffer) in [
            (1_u32, [2_u8, 0, 0, 0]),
            (2, [1, 0, 0, 0]),
            (4, [0, 0, 0, 0]),
        ] {
            assert!(
                matches!(
                    secure_boot_from_read(returned, &buffer, 0),
                    Err(SourceError::Failed(_))
                ),
                "{returned} {buffer:?}"
            );
        }
        // A byte count larger than the buffer handed over cannot be trusted either.
        assert!(matches!(
            secure_boot_from_read(9, &[1; 8], 0),
            Err(SourceError::Failed(_))
        ));
    }

    #[test]
    fn a_failed_read_is_classified_by_its_error() {
        assert_eq!(
            secure_boot_from_read(0, &[0; 8], ERROR_ENVVAR_NOT_FOUND),
            Ok(FirmwareSecureBoot::VariableAbsent)
        );
        assert_eq!(
            secure_boot_from_read(0, &[0; 8], ERROR_INVALID_FUNCTION),
            Ok(FirmwareSecureBoot::NotUefi)
        );
        assert_eq!(
            secure_boot_from_read(0, &[0; 8], ERROR_PRIVILEGE_NOT_HELD),
            Err(SourceError::AccessDenied)
        );
        // ERROR_NOACCESS (998) and ERROR_INSUFFICIENT_BUFFER (122) are failures, not answers.
        for code in [998_u32, 122] {
            assert!(
                matches!(
                    secure_boot_from_read(0, &[0; 8], code),
                    Err(SourceError::Failed(_))
                ),
                "{code}"
            );
        }
    }

    /// The error code is only read when the call failed: a stale error left from an earlier call must
    /// not turn a successful read into a failure.
    #[test]
    fn a_successful_read_ignores_the_last_error() {
        assert_eq!(
            secure_boot_from_read(1, &[1; 8], ERROR_PRIVILEGE_NOT_HELD),
            Ok(FirmwareSecureBoot::Enabled)
        );
    }
}
