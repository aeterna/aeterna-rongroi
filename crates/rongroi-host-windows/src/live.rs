// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! Reads the real machine. Registry keys are opened read-only; nothing is written.

use rongroi_host::{Host, Platform, RegistrySource, SourceError};

const HRESULT_FILE_NOT_FOUND: i32 = 0x8007_0002_u32.cast_signed();
const HRESULT_PATH_NOT_FOUND: i32 = 0x8007_0003_u32.cast_signed();
const HRESULT_ACCESS_DENIED: i32 = 0x8007_0005_u32.cast_signed();
const CURRENT_VERSION_KEY: &str = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion";

/// The real Windows machine.
#[derive(Debug, Default, Clone, Copy)]
pub struct LiveHost;

fn hklm_subkey(key: &str) -> Result<&str, SourceError> {
    key.strip_prefix(r"HKLM\").ok_or_else(|| {
        SourceError::Unsupported(format!("only HKLM keys are supported, got `{key}`"))
    })
}

fn classify<T>(result: windows_registry::Result<T>) -> Result<Option<T>, SourceError> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(error) => match error.code().0 {
            HRESULT_FILE_NOT_FOUND | HRESULT_PATH_NOT_FOUND => Ok(None),
            HRESULT_ACCESS_DENIED => Err(SourceError::AccessDenied),
            _ => Err(SourceError::Failed(error.message())),
        },
    }
}

impl RegistrySource for LiveHost {
    fn read_u32(&self, key: &str, value: &str) -> Result<Option<u32>, SourceError> {
        // `open` requests read access only.
        let Some(opened) = classify(windows_registry::LOCAL_MACHINE.open(hklm_subkey(key)?))?
        else {
            return Ok(None);
        };
        classify(opened.get_u32(value))
    }

    fn read_string(&self, key: &str, value: &str) -> Result<Option<String>, SourceError> {
        let Some(opened) = classify(windows_registry::LOCAL_MACHINE.open(hklm_subkey(key)?))?
        else {
            return Ok(None);
        };
        classify(opened.get_string(value))
    }

    fn subkeys(&self, key: &str) -> Result<Option<Vec<String>>, SourceError> {
        let Some(opened) = classify(windows_registry::LOCAL_MACHINE.open(hklm_subkey(key)?))?
        else {
            return Ok(None);
        };
        let Some(names) = classify(opened.keys())? else {
            return Ok(None);
        };
        Ok(Some(names.collect()))
    }

    /// The names only. `Key::values` also hands back each value's data, which is dropped here so
    /// that every byte a collector reads goes through `read_bytes` and its limit.
    fn value_names(&self, key: &str) -> Result<Option<Vec<String>>, SourceError> {
        let Some(opened) = classify(windows_registry::LOCAL_MACHINE.open(hklm_subkey(key)?))?
        else {
            return Ok(None);
        };
        let Some(values) = classify(opened.values())? else {
            return Ok(None);
        };
        Ok(Some(values.map(|(name, _)| name).collect()))
    }

    fn read_bytes(&self, key: &str, value: &str) -> Result<Option<Vec<u8>>, SourceError> {
        let Some(opened) = classify(windows_registry::LOCAL_MACHINE.open(hklm_subkey(key)?))?
        else {
            return Ok(None);
        };
        // `get_bytes` refuses a value that is not `REG_BINARY`, which arrives here as a failure
        // rather than as a conversion nobody asked for.
        let Some(bytes) = classify(opened.get_bytes(value))? else {
            return Ok(None);
        };
        // The limit lives in `rongroi-host`, so this host refuses exactly what the fixture host does.
        rongroi_host::bound_registry_value(bytes, rongroi_host::MAX_REGISTRY_VALUE_BYTES).map(Some)
    }
}

impl Host for LiveHost {
    fn platform(&self) -> Platform {
        Platform::Windows
    }

    fn os_build(&self) -> Option<String> {
        self.read_string(CURRENT_VERSION_KEY, "CurrentBuild")
            .ok()
            .flatten()
    }

    fn is_elevated(&self) -> Option<bool> {
        has_admin_rights()
    }
}

/// Whether the Administrators group is *enabled* in this process's token.
///
/// `TokenElevation` is not enough: a restricted (SAFER) token derived from an elevated one still reports
/// "elevated" while Administrators is deny-only, so the process cannot use admin rights. Checked on
/// Windows 11 build 26220 with `runas /trustlevel:0x20000`. `CheckTokenMembership` ignores deny-only
/// groups, so it is false both for UAC-filtered and for restricted tokens.
#[allow(unsafe_code)]
fn has_admin_rights() -> Option<bool> {
    use windows::Win32::Security::{
        CheckTokenMembership, CreateWellKnownSid, PSID, WinBuiltinAdministratorsSid,
    };
    use windows::core::BOOL;

    // SECURITY_MAX_SID_SIZE is 68 bytes; u32 words keep the SID's DWORD fields aligned.
    let mut sid_buffer = [0_u32; 17];
    let mut sid_size = u32::try_from(size_of_val(&sid_buffer)).ok()?;
    let sid = PSID(sid_buffer.as_mut_ptr().cast());
    // SAFETY: `sid` points to `sid_size` writable bytes that outlive the call, and `sid_size` is a valid
    // in/out pointer.
    unsafe {
        CreateWellKnownSid(
            WinBuiltinAdministratorsSid,
            None,
            Some(sid),
            &raw mut sid_size,
        )
    }
    .ok()?;

    let mut is_member = BOOL::default();
    // SAFETY: `None` makes the function use this thread's effective token; `sid` was initialised above
    // and `is_member` is a valid out-pointer.
    unsafe { CheckTokenMembership(None, sid, &raw mut is_member) }.ok()?;
    Some(is_member.as_bool())
}
