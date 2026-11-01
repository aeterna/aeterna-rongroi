// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! Reads the real machine. Registry keys are opened read-only; nothing is written.

use rongroi_host::{Host, Platform, RegistryData, RegistrySource, SourceError};
use windows::Win32::Foundation::GetLastError;
use windows::Win32::Storage::FileSystem::{GetDriveTypeW, GetFileAttributesW};
use windows::core::PCWSTR;

use crate::usn_journal::{
    ERROR_DIRECTORY, ERROR_FILE_NOT_FOUND, ERROR_INVALID_NAME, ERROR_PATH_NOT_FOUND,
};

const HRESULT_FILE_NOT_FOUND: i32 = 0x8007_0002_u32.cast_signed();
const HRESULT_PATH_NOT_FOUND: i32 = 0x8007_0003_u32.cast_signed();
const HRESULT_ACCESS_DENIED: i32 = 0x8007_0005_u32.cast_signed();
const CURRENT_VERSION_KEY: &str = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion";
/// `GetFileAttributesW`'s value for a path it could not read.
const INVALID_FILE_ATTRIBUTES: u32 = u32::MAX;
/// `FILE_ATTRIBUTE_REPARSE_POINT`: the path is a reparse point (a link or another tagged record).
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;

/// The real Windows machine.
#[derive(Debug, Default, Clone, Copy)]
pub struct LiveHost;

/// The root a key is written under and the path inside it.
///
/// `HKLM` is the machine. `HKCU` is the account this process runs as, which after a restart with
/// another administrator's credentials is that administrator and not the person at the keyboard; it is
/// opened for one policy family that has a per-user half (ADR 0038). Every other root is refused.
fn open_root(key: &str) -> Result<(&'static windows_registry::Key, &str), SourceError> {
    if let Some(path) = key.strip_prefix(r"HKLM\") {
        Ok((windows_registry::LOCAL_MACHINE, path))
    } else if let Some(path) = key.strip_prefix(r"HKCU\") {
        Ok((windows_registry::CURRENT_USER, path))
    } else {
        Err(SourceError::Unsupported(format!(
            "only HKLM and HKCU keys are supported, got `{key}`"
        )))
    }
}

/// Opens `key` for reading, or `Ok(None)` when it is not there.
fn open(key: &str) -> Result<Option<windows_registry::Key>, SourceError> {
    let (root, path) = open_root(key)?;
    // `open` requests read access only.
    classify(root.open(path))
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

/// `text` as NUL-terminated UTF-16, for a Windows wide-string call.
fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

impl RegistrySource for LiveHost {
    fn read_u32(&self, key: &str, value: &str) -> Result<Option<u32>, SourceError> {
        let Some(opened) = open(key)? else {
            return Ok(None);
        };
        classify(opened.get_u32(value))
    }

    fn read_string(&self, key: &str, value: &str) -> Result<Option<String>, SourceError> {
        let Some(opened) = open(key)? else {
            return Ok(None);
        };
        classify(opened.get_string(value))
    }

    fn subkeys(&self, key: &str) -> Result<Option<Vec<String>>, SourceError> {
        let Some(opened) = open(key)? else {
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
        let Some(opened) = open(key)? else {
            return Ok(None);
        };
        let Some(values) = classify(opened.values())? else {
            return Ok(None);
        };
        Ok(Some(values.map(|(name, _)| name).collect()))
    }

    fn read_bytes(&self, key: &str, value: &str) -> Result<Option<Vec<u8>>, SourceError> {
        let Some(opened) = open(key)? else {
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

    fn read_value(&self, key: &str, value: &str) -> Result<Option<RegistryData>, SourceError> {
        let Some(opened) = open(key)? else {
            return Ok(None);
        };
        let Some(kind) = classify(opened.get_type(value))? else {
            return Ok(None);
        };
        // The type and the data are two calls. A value rewritten between them is read as it is at the
        // second call, through the reader for the type the first call named.
        let data = match kind {
            windows_registry::Type::U32 => {
                classify(opened.get_u32(value))?.map(RegistryData::Dword)
            }
            windows_registry::Type::U64 => {
                classify(opened.get_u64(value))?.map(RegistryData::Qword)
            }
            windows_registry::Type::String | windows_registry::Type::ExpandString => {
                classify(opened.get_string(value))?.map(RegistryData::Text)
            }
            _ => Some(RegistryData::OtherType),
        };
        data.map(|data| {
            rongroi_host::bound_registry_data(data, rongroi_host::MAX_REGISTRY_VALUE_BYTES)
        })
        .transpose()
    }
}

impl LiveHost {
    /// The one gate before a read by path (ADR 0091 section 1): [`rongroi_host::local_read_check`] on
    /// this host, with a refusal reported as [`SourceError::NotLocal`] so a collector can say the path
    /// was not opened rather than missing.
    pub(crate) fn local_read_check(self, path: &str) -> Result<(), SourceError> {
        rongroi_host::local_read_check(&self, path).map_err(SourceError::NotLocal)
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

    /// Every drive letter Windows has now, with the device and volume serial a device path is mapped
    /// through (ADR 0087 section 1). Read once, without administrator rights, and no file is opened.
    fn drive_map(&self) -> Result<rongroi_host::DriveMap, SourceError> {
        crate::drive_map::read()
    }

    /// `GetDriveTypeW` on the letter's root, through the same mapping the drive map uses (ADR 0091
    /// section 2).
    #[allow(unsafe_code)]
    fn drive_kind(&self, letter: char) -> Result<rongroi_host::DriveKind, SourceError> {
        let root = wide(&format!("{letter}:\\"));
        // SAFETY: `root` is NUL-terminated UTF-16 that outlives the call, and the call only reads
        // what kind of drive Windows reports; it opens nothing.
        let code = unsafe { GetDriveTypeW(PCWSTR(root.as_ptr())) };
        Ok(crate::drive_map::drive_kind(code))
    }

    /// `GetFileAttributesW`, then the link's own record when the path is a reparse point (ADR 0091
    /// section 2). `reparse_buffer` opens the link itself and asks for its attributes only, so the
    /// read never follows it.
    ///
    /// This is deliberately not gated by `LiveHost::local_read_check`: that gate calls this for every
    /// component of a path, so calling it back would recurse.
    ///
    /// A cloud placeholder whose read would fetch its data is [`rongroi_host::LinkKind::Other`] before
    /// anything is opened: the placeholder compatibility mode can hide `FILE_ATTRIBUTE_REPARSE_POINT`,
    /// so the recall and offline bits are checked first ([`crate::reparse::would_fetch`]).
    #[allow(unsafe_code)]
    fn link_target(&self, path: &str) -> Result<Option<rongroi_host::LinkTarget>, SourceError> {
        let name = wide(path);
        // SAFETY: `name` is NUL-terminated UTF-16 that outlives the call, and the call only reads
        // the attributes Windows keeps for the path; it opens nothing. `GetFileAttributesW` does
        // follow links in intermediate components, which is safe here because
        // `rongroi_host::resolved_local_path` asks prefixes top-down and stops at the first link, so
        // no link is crossed unchecked.
        let attributes = unsafe { GetFileAttributesW(PCWSTR(name.as_ptr())) };
        if attributes == INVALID_FILE_ATTRIBUTES {
            // SAFETY: no other call has run on this thread since the one whose error this reads.
            let last_error = unsafe { GetLastError() }.0;
            return match last_error {
                ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND | ERROR_INVALID_NAME
                | ERROR_DIRECTORY => Ok(None),
                _ => Err(SourceError::Failed(format!(
                    "GetFileAttributesW returned {last_error:#010x}"
                ))),
            };
        }
        if crate::reparse::would_fetch(attributes) {
            return Ok(Some(rongroi_host::LinkTarget {
                kind: rongroi_host::LinkKind::Other,
                target: String::new(),
                relative: false,
            }));
        }
        if attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0 {
            return Ok(None);
        }
        let bytes = crate::usn_journal::reparse_buffer(path).map_err(|error| {
            SourceError::Failed(format!(
                "FSCTL_GET_REPARSE_POINT returned {:#010x}",
                error.code().0.cast_unsigned()
            ))
        })?;
        crate::reparse::parse_reparse(&bytes, attributes).map_err(SourceError::Failed)
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
