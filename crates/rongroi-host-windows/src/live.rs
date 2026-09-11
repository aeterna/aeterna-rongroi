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
        token_is_elevated()
    }
}

#[allow(unsafe_code)]
fn token_is_elevated() -> Option<bool> {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{
        GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token = HANDLE::default();
    // SAFETY: GetCurrentProcess returns a pseudo-handle that is always valid for this process, and
    // `token` is a valid, writable out-pointer for the lifetime of the call.
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) }.ok()?;

    let mut elevation = TOKEN_ELEVATION::default();
    let mut returned = 0_u32;
    let size = u32::try_from(size_of::<TOKEN_ELEVATION>()).ok()?;
    // SAFETY: `token` was opened with TOKEN_QUERY above; the buffer is a TOKEN_ELEVATION of exactly
    // `size` bytes and `returned` is a valid out-pointer.
    let queried = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            Some((&raw mut elevation).cast()),
            size,
            &raw mut returned,
        )
    };
    // SAFETY: `token` is a handle this function opened and closes exactly once.
    let _ = unsafe { CloseHandle(token) };

    queried.ok()?;
    Some(elevation.TokenIsElevated != 0)
}
