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

impl SourceError {
    /// Classifies an I/O error from a file-system read, so that every host that reads real files
    /// reports the same problem the same way.
    ///
    /// A caller for which a missing path is a fact rather than a failure — `list_dir` — checks
    /// [`std::io::ErrorKind::NotFound`] itself before calling this.
    pub fn from_io(error: &std::io::Error) -> Self {
        match error.kind() {
            std::io::ErrorKind::PermissionDenied => Self::AccessDenied,
            _ => Self::Failed(error.to_string()),
        }
    }
}

/// Read-only access to the registry. Keys are written as `HKLM\...`.
pub trait RegistrySource {
    /// Reads a `REG_DWORD`. `Ok(None)` when the key or value does not exist.
    fn read_u32(&self, key: &str, value: &str) -> Result<Option<u32>, SourceError>;
    /// Reads a `REG_SZ`. `Ok(None)` when the key or value does not exist.
    fn read_string(&self, key: &str, value: &str) -> Result<Option<String>, SourceError>;
}

/// One entry directly inside a directory. Only what collectors need: nothing about times, size or ACLs
/// is read (ADR 0009).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntryInfo {
    /// Name inside the directory, without any parent path.
    pub name: String,
    /// `true` for a regular file; `false` for a directory or anything else.
    pub is_file: bool,
}

/// Read-only access to the file system. Paths are absolute and Windows-style, e.g. `C:\Users\a\x.dll`.
pub trait FilesystemSource {
    /// Lists what is directly inside `dir`; it never recurses.
    ///
    /// `Ok(None)` means the directory does not exist, which is something the collector looked at and
    /// saw — not a failure to look. An error means the directory could not be read at all.
    fn list_dir(&self, dir: &str) -> Result<Option<Vec<DirEntryInfo>>, SourceError>;

    /// SHA-256 of one file, as lowercase hex.
    ///
    /// The error is about that one file. A collector that cannot hash a file still reports the file.
    fn file_sha256(&self, path: &str) -> Result<String, SourceError>;
}

/// Read-only access to the process environment. Names are case-insensitive, like Windows.
pub trait EnvironmentSource {
    /// Value of `name`, or `None` when it is not set or is not valid Unicode.
    fn env_var(&self, name: &str) -> Option<String>;
}

/// What the running kernel reports about code integrity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodeIntegrityOptions {
    /// Kernel-mode code integrity is enforcing driver signatures.
    pub enabled: bool,
    /// Test signing is on, so the kernel also accepts self-signed drivers.
    pub test_signing: bool,
}

/// Read-only access to the kernel's own code-integrity state (ADR 0011).
pub trait SystemIntegritySource {
    /// What the running kernel reports about code integrity and test signing.
    fn code_integrity_options(&self) -> Result<CodeIntegrityOptions, SourceError>;
}

/// What the platform reports about the TPM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TpmInfo {
    /// Whether a TPM is present at all.
    pub present: bool,
    /// Specification family, e.g. `2.0`, when the platform reports one it recognises. `None` when
    /// there is no TPM, or when its version is not one this program can name.
    pub spec_version: Option<String>,
}

/// Read-only access to the TPM's identity (ADR 0011). No command is ever submitted to the device.
pub trait TpmSource {
    /// Whether a TPM is present and, when known, which specification family it implements.
    ///
    /// A machine with no TPM is an answer (`present: false`), not a failure to look.
    fn tpm_info(&self) -> Result<TpmInfo, SourceError>;
}

/// One process that was running when the process list was read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessRecord {
    /// Process id, as the operating system reported it at that moment.
    pub pid: u32,
    /// Name of the image file, without a path, e.g. `FiveM.exe`.
    pub name: String,
    /// Full path of the image file, when it could be resolved.
    pub path: Option<String>,
}

/// Read-only access to the list of running processes (ADR 0010).
pub trait ProcessSource {
    /// Every process running at the moment of the call.
    ///
    /// A process whose image path cannot be resolved — a protected process, or one that exited
    /// between the list being taken and the query — is still returned, with `path` as `None`.
    /// Dropping it would understate what is running.
    fn running_processes(&self) -> Result<Vec<ProcessRecord>, SourceError>;
}

/// Size of one read when a file is streamed through SHA-256.
const READ_BLOCK: usize = 64 * 1024;

/// Streams `reader` through SHA-256 and returns the digest as lowercase hex.
///
/// Streaming, not `read_to_end`: a plugin can be tens of megabytes and only its digest is kept.
pub fn sha256_reader<R: std::io::Read>(mut reader: R) -> std::io::Result<String> {
    use std::fmt::Write as _;

    use sha2::{Digest as _, Sha256};

    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; READ_BLOCK];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => hasher.update(&buffer[..read]),
            // A signal interrupted the read; the same block is read again.
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for byte in &digest {
        let _ = write!(hex, "{byte:02x}");
    }
    Ok(hex)
}

/// Streams the file at `path` through SHA-256. Opens it for reading only.
///
/// It lives here rather than in one host implementation so that every [`FilesystemSource`] that reads
/// real files produces the same digest in the same form, and so that the streaming loop is covered by
/// tests that run on any operating system.
pub fn sha256_file(path: &std::path::Path) -> std::io::Result<String> {
    sha256_reader(std::io::BufReader::new(std::fs::File::open(path)?))
}

/// A machine that collectors can read. More source traits are added as collectors need them.
pub trait Host:
    RegistrySource
    + FilesystemSource
    + EnvironmentSource
    + SystemIntegritySource
    + TpmSource
    + ProcessSource
{
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

impl FilesystemSource for NonWindowsHost {
    fn list_dir(&self, _dir: &str) -> Result<Option<Vec<DirEntryInfo>>, SourceError> {
        Err(SourceError::Unsupported(
            "no Windows file system on this platform".to_owned(),
        ))
    }

    fn file_sha256(&self, _path: &str) -> Result<String, SourceError> {
        Err(SourceError::Unsupported(
            "no Windows file system on this platform".to_owned(),
        ))
    }
}

impl EnvironmentSource for NonWindowsHost {
    fn env_var(&self, _name: &str) -> Option<String> {
        None
    }
}

impl SystemIntegritySource for NonWindowsHost {
    fn code_integrity_options(&self) -> Result<CodeIntegrityOptions, SourceError> {
        Err(SourceError::Unsupported(
            "no Windows code integrity on this platform".to_owned(),
        ))
    }
}

impl TpmSource for NonWindowsHost {
    fn tpm_info(&self) -> Result<TpmInfo, SourceError> {
        Err(SourceError::Unsupported(
            "no TPM base services on this platform".to_owned(),
        ))
    }
}

impl ProcessSource for NonWindowsHost {
    fn running_processes(&self) -> Result<Vec<ProcessRecord>, SourceError> {
        Err(SourceError::Unsupported(
            "no Windows process list on this platform".to_owned(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_windows_host_reads_no_files_and_no_environment() {
        assert!(matches!(
            NonWindowsHost.list_dir(r"C:\Users\a"),
            Err(SourceError::Unsupported(_))
        ));
        assert!(matches!(
            NonWindowsHost.file_sha256(r"C:\Users\a\x.dll"),
            Err(SourceError::Unsupported(_))
        ));
        assert_eq!(NonWindowsHost.env_var("LOCALAPPDATA"), None);
    }

    #[test]
    fn non_windows_host_reports_no_code_integrity_and_no_tpm() {
        assert!(matches!(
            NonWindowsHost.code_integrity_options(),
            Err(SourceError::Unsupported(_))
        ));
        assert!(matches!(
            NonWindowsHost.tpm_info(),
            Err(SourceError::Unsupported(_))
        ));
    }

    /// Not an empty list: "nothing is running" would be a claim about the machine, and this host
    /// cannot look at all.
    #[test]
    fn non_windows_host_lists_no_processes_rather_than_an_empty_list() {
        assert!(matches!(
            NonWindowsHost.running_processes(),
            Err(SourceError::Unsupported(_))
        ));
    }

    #[test]
    fn io_errors_are_classified_for_every_host_the_same_way() {
        use std::io::{Error, ErrorKind};

        assert_eq!(
            SourceError::from_io(&Error::from(ErrorKind::PermissionDenied)),
            SourceError::AccessDenied
        );
        // A path that is gone is a fact for `list_dir`, which checks `NotFound` itself; anything that
        // reaches this function is a read that failed.
        for kind in [
            ErrorKind::NotFound,
            ErrorKind::InvalidData,
            ErrorKind::UnexpectedEof,
        ] {
            assert!(matches!(
                SourceError::from_io(&Error::from(kind)),
                SourceError::Failed(_)
            ));
        }
    }

    #[test]
    fn sha256_of_a_reader_matches_the_known_digests() {
        assert_eq!(
            sha256_reader(&b""[..]).unwrap(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_reader(&b"abc"[..]).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sha256_of_a_reader_spans_many_blocks() {
        // More than one read buffer, so a bug that hashes only the first block shows up here.
        let bytes = vec![b'a'; READ_BLOCK * 3 + 1];
        assert_eq!(
            sha256_reader(bytes.as_slice()).unwrap(),
            sha256_reader(bytes.as_slice()).unwrap()
        );
        assert_ne!(
            sha256_reader(bytes.as_slice()).unwrap(),
            sha256_reader(&bytes[..READ_BLOCK]).unwrap()
        );
    }
}
