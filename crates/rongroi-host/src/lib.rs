// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! Hosts: where collectors read artifacts from.
//!
//! Collectors only ever see the [`Host`] trait. The real machine is `rongroi_host_windows::LiveHost`;
//! tests use [`FixtureHost`] (feature `fixture`), a fake machine described in YAML, so collectors can
//! be tested on any operating system. Every method only reads.

#[cfg(feature = "fixture")]
mod fixture;

#[cfg(feature = "fixture")]
pub use fixture::{FixtureError, FixtureHost};

/// Operating system family of a host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "fixture", derive(serde::Deserialize))]
#[cfg_attr(feature = "fixture", serde(rename_all = "snake_case"))]
pub enum Platform {
    /// Windows.
    Windows,
    /// Anything else. Collectors report `not_windows`.
    Other,
}

impl Platform {
    /// Stable identifier used in reports.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Windows => "windows",
            Self::Other => "other",
        }
    }
}

/// Why a source could not be read. Collectors turn these into `Unmeasured` reasons.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SourceError {
    /// The operating system denied access.
    #[error("access denied")]
    AccessDenied,
    /// The request is not supported by this host.
    #[error("unsupported: {0}")]
    Unsupported(String),
    /// Anything else.
    #[error("read failed: {0}")]
    Failed(String),
}

/// Read-only access to the registry. Keys are written as `HKLM\...`.
pub trait RegistrySource {
    /// Reads a `REG_DWORD`. `Ok(None)` when the key or value does not exist.
    fn read_u32(&self, key: &str, value: &str) -> Result<Option<u32>, SourceError>;
    /// Reads a `REG_SZ`. `Ok(None)` when the key or value does not exist.
    fn read_string(&self, key: &str, value: &str) -> Result<Option<String>, SourceError>;
}

/// A machine that collectors can read. More source traits are added as collectors need them.
pub trait Host: RegistrySource {
    /// Operating system family.
    fn platform(&self) -> Platform;
    /// Windows build number, when known.
    fn os_build(&self) -> Option<String>;
    /// Whether the process can use administrator rights, when known. False when the Administrators group
    /// is only deny-only in the token (UAC-filtered or restricted tokens).
    fn is_elevated(&self) -> Option<bool>;
}

/// The host used when the program runs on something other than Windows: every read is unsupported.
#[derive(Debug, Default, Clone, Copy)]
pub struct NonWindowsHost;

impl RegistrySource for NonWindowsHost {
    fn read_u32(&self, _key: &str, _value: &str) -> Result<Option<u32>, SourceError> {
        Err(SourceError::Unsupported(
            "no registry on this platform".to_owned(),
        ))
    }

    fn read_string(&self, _key: &str, _value: &str) -> Result<Option<String>, SourceError> {
        Err(SourceError::Unsupported(
            "no registry on this platform".to_owned(),
        ))
    }
}

impl Host for NonWindowsHost {
    fn platform(&self) -> Platform {
        Platform::Other
    }

    fn os_build(&self) -> Option<String> {
        None
    }

    fn is_elevated(&self) -> Option<bool> {
        None
    }
}
