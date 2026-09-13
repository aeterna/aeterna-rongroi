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
    /// The file holds more bytes than a host will read into memory in one piece (ADR 0019).
    ///
    /// A separate variant rather than a `Failed`: the file was found and was readable, and the limit
    /// is this program's, not the machine's. It carries the limit and never the size, because the
    /// reader stops one byte past the limit and so never learns how large the file really is.
    #[error("larger than the {limit} bytes this host reads in one piece")]
    TooLarge {
        /// Most bytes this host reads for one file.
        limit: usize,
    },
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

    /// Names of the keys directly inside `key`; it never recurses (ADR 0022).
    ///
    /// `Ok(None)` means the key does not exist, which is something the collector looked at and saw —
    /// the same distinction [`FilesystemSource::list_dir`] makes for a directory. A key that is there
    /// and holds no subkey is `Ok(Some(vec![]))`, which is a different statement.
    ///
    /// The count is not bounded, for the reason `list_dir` does not bound a directory listing: a
    /// truncated enumeration would read as "there was nothing else", which is the one wrong answer.
    fn subkeys(&self, key: &str) -> Result<Option<Vec<String>>, SourceError>;

    /// Names of the values directly under `key`, as the registry spells them (ADR 0022).
    ///
    /// `Ok(None)` when the key does not exist; `Ok(Some(vec![]))` when it is there and holds no
    /// value. The names are returned, never the data: a value's bytes are read one at a time with
    /// [`RegistrySource::read_bytes`], so that the bound below applies to each of them.
    fn value_names(&self, key: &str) -> Result<Option<Vec<String>>, SourceError>;

    /// The bytes of one `REG_BINARY` value, at most [`MAX_REGISTRY_VALUE_BYTES`] of them (ADR 0022).
    ///
    /// `Ok(None)` when the key or the value does not exist, like [`RegistrySource::read_u32`]. A
    /// value of another type is an error rather than an answer: a caller that wanted a number or a
    /// string has a method for it, and guessing a conversion here would hand a parser bytes that
    /// mean something else.
    ///
    /// A value larger than the limit is [`SourceError::TooLarge`]; nothing is truncated, because a
    /// truncated artifact parses as a damaged one.
    fn read_bytes(&self, key: &str, value: &str) -> Result<Option<Vec<u8>>, SourceError>;
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

    /// The bytes of one file, at most [`MAX_FILE_BYTES`] of them (ADR 0019).
    ///
    /// `Ok(None)` means the file does not exist, which is something the collector looked at and saw —
    /// the same distinction [`FilesystemSource::list_dir`] makes for a directory. A file enumerated a
    /// moment ago and gone by the time it is read is that case, not a failure.
    ///
    /// A file larger than the limit is [`SourceError::TooLarge`]: nothing is truncated, because a
    /// truncated artifact parses as a damaged one and would show damage this program caused.
    ///
    /// The path must name a regular file; `list_dir` already says which entries are files. Anything
    /// else is an error rather than an answer.
    fn read_file(&self, path: &str) -> Result<Option<Vec<u8>>, SourceError>;
}

/// What Windows says about the Authenticode signature **embedded in** one file, checked without the
/// network (ADR 0035).
///
/// Four answers, because "not valid" is three different statements and a reviewer has to be able to
/// tell them apart. None of them is a finding on its own: most files in a plugin folder are unsigned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureCheck {
    /// The signature is intact and chains to a root this machine trusts.
    Valid {
        /// Simple display name of the signing certificate's subject, for a person to read. Never
        /// compared by `allow`: a stolen certificate carries the same name as the real one.
        signer: String,
        /// SHA-256 of the signing certificate's encoded bytes, as lowercase hex — the identity `allow`
        /// compares.
        signer_cert_sha256: String,
    },
    /// The file carries no embedded signature, or is not a kind of file one can be embedded in.
    ///
    /// Not "unsigned": a file can be signed through a Windows catalog instead, and this check does not
    /// look there.
    NoEmbeddedSignature,
    /// A signature is there and Windows does not trust it: the file changed after signing, the
    /// certificate chains to a root this machine does not trust, it expired without a timestamp, or it
    /// is explicitly distrusted.
    Invalid,
    /// The answer needed something this machine does not hold locally — an intermediate certificate or
    /// revocation data — and this program does not fetch it. A fact about the check, not the file.
    UnverifiableOffline,
}

/// Read-only access to the Authenticode signature embedded in a file (ADR 0035).
pub trait SignatureSource {
    /// Checks the signature embedded in the file at `path`, without the network.
    ///
    /// The error is about that one file, like [`FilesystemSource::file_sha256`]: a collector that
    /// cannot check one file still reports the file.
    fn file_signature(&self, path: &str) -> Result<SignatureCheck, SourceError>;
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

/// Read-only access to how long the running Windows kernel has been counting since it started
/// (ADR 0039).
///
/// Context for the report header, never evidence: a person reads the times other rows carry against
/// it. What "started" means is Windows' own, and it is not what a person means by "I turned the PC
/// on": a "Shut down" with Fast Startup — the default — hibernates the kernel instead of ending it,
/// and sleep and hibernation do not reset the count either. Only a restart, or a shutdown with Fast
/// Startup off, starts it again.
pub trait BootTimeSource {
    /// Time elapsed since the system started, sleep and hibernation included.
    ///
    /// Nothing about who is logged on is read: it is one number about the machine.
    fn since_boot(&self) -> Result<std::time::Duration, SourceError>;
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

/// Most bytes [`FilesystemSource::read_file`] returns for one file (ADR 0019).
///
/// Every file a collector reads is on the machine being examined, so its size is chosen by whoever
/// put it there. Without a limit, `read_to_end` on a hostile path sizes an allocation from the file —
/// the defect this project patched in the vendored `evtx` crate (ADR 0018), one layer lower.
///
/// 64 MiB is four times the 16 MiB cap `rongroi_parsers::prefetch` already applies to a declared
/// decompressed size, and far above the artifacts this program reads: the vendored Event Log sample is
/// 69 632 bytes and the largest vendored Prefetch file decompresses to 25 KiB. It is also far below a
/// size that costs a player's machine anything to refuse.
pub const MAX_FILE_BYTES: usize = 64 * 1024 * 1024;

/// Reads at most `limit` bytes from `reader`, or reports [`SourceError::TooLarge`].
///
/// It reads one byte past the limit deliberately: that is what tells a file of exactly `limit` bytes,
/// which is returned whole, from a larger one, which is refused. Nothing is ever truncated.
///
/// The buffer grows as bytes arrive rather than being reserved from a size the file declares, so the
/// largest allocation this makes is the program's choice and not the file's. It lives here next to the
/// trait, as [`sha256_file`] does, so every host that reads real files applies the same limit the same
/// way and so the loop is covered by tests that need no Windows.
pub fn read_bounded<R: std::io::Read>(reader: R, limit: usize) -> Result<Vec<u8>, SourceError> {
    use std::io::Read as _;

    let one_past = u64::try_from(limit.saturating_add(1)).unwrap_or(u64::MAX);
    let mut bytes = Vec::new();
    reader
        .take(one_past)
        .read_to_end(&mut bytes)
        .map_err(|error| SourceError::from_io(&error))?;
    if bytes.len() > limit {
        return Err(SourceError::TooLarge { limit });
    }
    Ok(bytes)
}

/// Most bytes [`RegistrySource::read_bytes`] returns for one registry value (ADR 0022).
///
/// Every value a collector reads is on the machine being examined, so its size is chosen by whoever
/// put it there — the same argument [`MAX_FILE_BYTES`] rests on, one source over.
///
/// 64 KiB is far above the artifact this exists for: the BAM layout `rongroi_parsers::bam` describes
/// is 24 bytes, so the limit is some 2 700 times it, and a value that is longer is kept whole by that
/// parser rather than trimmed. It is also a thousandth of what a file may be, which is the ratio
/// between the two sources: the registry is a settings store, and a value in it is small by design.
/// A machine with a larger value is answered with [`SourceError::TooLarge`], which is a fact about
/// that value rather than a failure to look.
pub const MAX_REGISTRY_VALUE_BYTES: usize = 64 * 1024;

/// Refuses a registry value larger than `limit`, as [`read_bounded`] refuses a file.
///
/// It takes bytes rather than a reader, and that difference is the honest part: a platform registry
/// API hands back a whole value in one call, sized from the length the value declares, so this bounds
/// what crosses the trait boundary and reaches a parser — not the allocation the platform already
/// made. [`read_bounded`] can bound both because it owns the reading loop.
///
/// It lives here next to the trait so that every host refuses exactly the same values.
pub fn bound_registry_value(bytes: Vec<u8>, limit: usize) -> Result<Vec<u8>, SourceError> {
    if bytes.len() > limit {
        return Err(SourceError::TooLarge { limit });
    }
    Ok(bytes)
}

/// A machine that collectors can read. More source traits are added as collectors need them.
pub trait Host:
    RegistrySource
    + FilesystemSource
    + SignatureSource
    + EnvironmentSource
    + SystemIntegritySource
    + TpmSource
    + ProcessSource
    + BootTimeSource
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

    fn subkeys(&self, _key: &str) -> Result<Option<Vec<String>>, SourceError> {
        Err(SourceError::Unsupported(
            "no registry on this platform".to_owned(),
        ))
    }

    fn value_names(&self, _key: &str) -> Result<Option<Vec<String>>, SourceError> {
        Err(SourceError::Unsupported(
            "no registry on this platform".to_owned(),
        ))
    }

    fn read_bytes(&self, _key: &str, _value: &str) -> Result<Option<Vec<u8>>, SourceError> {
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

    fn read_file(&self, _path: &str) -> Result<Option<Vec<u8>>, SourceError> {
        Err(SourceError::Unsupported(
            "no Windows file system on this platform".to_owned(),
        ))
    }
}

impl SignatureSource for NonWindowsHost {
    fn file_signature(&self, _path: &str) -> Result<SignatureCheck, SourceError> {
        Err(SourceError::Unsupported(
            "no Authenticode verification on this platform".to_owned(),
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

impl BootTimeSource for NonWindowsHost {
    fn since_boot(&self) -> Result<std::time::Duration, SourceError> {
        Err(SourceError::Unsupported(
            "no Windows boot time on this platform".to_owned(),
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
        assert!(matches!(
            NonWindowsHost.read_file(r"C:\Users\a\x.dll"),
            Err(SourceError::Unsupported(_))
        ));
        assert!(matches!(
            NonWindowsHost.file_signature(r"C:\Users\a\x.dll"),
            Err(SourceError::Unsupported(_))
        ));
        assert_eq!(NonWindowsHost.env_var("LOCALAPPDATA"), None);
    }

    #[test]
    fn non_windows_host_reads_no_registry_at_all() {
        let key = r"HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings";
        assert!(matches!(
            NonWindowsHost.read_u32(key, "Anything"),
            Err(SourceError::Unsupported(_))
        ));
        assert!(matches!(
            NonWindowsHost.subkeys(key),
            Err(SourceError::Unsupported(_))
        ));
        assert!(matches!(
            NonWindowsHost.value_names(key),
            Err(SourceError::Unsupported(_))
        ));
        assert!(matches!(
            NonWindowsHost.read_bytes(key, r"C:\x.exe"),
            Err(SourceError::Unsupported(_))
        ));
    }

    #[test]
    fn non_windows_host_reports_no_boot_time_rather_than_zero() {
        assert!(matches!(
            NonWindowsHost.since_boot(),
            Err(SourceError::Unsupported(_))
        ));
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

    /// A reader that fails on the first call, so the classification of a mid-read failure is covered
    /// without a real file and without Windows.
    struct FailingReader(std::io::ErrorKind);

    impl std::io::Read for FailingReader {
        fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::from(self.0))
        }
    }

    #[test]
    fn a_bounded_read_returns_everything_up_to_and_including_the_limit() {
        assert_eq!(read_bounded(&b""[..], 4), Ok(Vec::new()));
        assert_eq!(read_bounded(&b"abc"[..], 4), Ok(b"abc".to_vec()));
        // Exactly the limit is a file this host reads, not one it refuses.
        assert_eq!(read_bounded(&b"abcd"[..], 4), Ok(b"abcd".to_vec()));
    }

    /// One byte over the limit is refused as a whole. Returning the first four bytes instead would
    /// hand a parser a damaged artifact and let the report describe damage this program caused.
    #[test]
    fn a_file_over_the_limit_is_refused_rather_than_truncated() {
        assert_eq!(
            read_bounded(&b"abcde"[..], 4),
            Err(SourceError::TooLarge { limit: 4 })
        );
        assert_eq!(
            read_bounded(vec![b'a'; READ_BLOCK * 3].as_slice(), READ_BLOCK),
            Err(SourceError::TooLarge { limit: READ_BLOCK })
        );
        // A limit of zero still reads: it refuses every file that has any bytes in it.
        assert_eq!(read_bounded(&b""[..], 0), Ok(Vec::new()));
        assert_eq!(
            read_bounded(&b"a"[..], 0),
            Err(SourceError::TooLarge { limit: 0 })
        );
    }

    #[test]
    fn a_bounded_read_classifies_its_failures_like_every_other_file_read() {
        assert_eq!(
            read_bounded(FailingReader(std::io::ErrorKind::PermissionDenied), 16),
            Err(SourceError::AccessDenied)
        );
        assert!(matches!(
            read_bounded(FailingReader(std::io::ErrorKind::InvalidData), 16),
            Err(SourceError::Failed(_))
        ));
    }

    /// The limit is a documented decision (ADR 0019), not an implementation detail: changing it
    /// changes which artifacts this program can read at all, so it is pinned here.
    #[test]
    fn the_file_size_limit_is_the_one_the_adr_states() {
        assert_eq!(MAX_FILE_BYTES, 64 * 1024 * 1024);
    }

    /// The same for the registry (ADR 0022), and the boundary itself: a value of exactly the limit
    /// is read whole, one byte more is refused whole rather than trimmed to fit.
    #[test]
    fn a_registry_value_over_the_limit_is_refused_rather_than_truncated() {
        assert_eq!(MAX_REGISTRY_VALUE_BYTES, 64 * 1024);

        assert_eq!(bound_registry_value(Vec::new(), 4), Ok(Vec::new()));
        assert_eq!(
            bound_registry_value(vec![1, 2, 3, 4], 4),
            Ok(vec![1, 2, 3, 4])
        );
        assert_eq!(
            bound_registry_value(vec![1, 2, 3, 4, 5], 4),
            Err(SourceError::TooLarge { limit: 4 })
        );
        assert_eq!(
            bound_registry_value(
                vec![0; MAX_REGISTRY_VALUE_BYTES + 1],
                MAX_REGISTRY_VALUE_BYTES
            ),
            Err(SourceError::TooLarge {
                limit: MAX_REGISTRY_VALUE_BYTES
            })
        );
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
