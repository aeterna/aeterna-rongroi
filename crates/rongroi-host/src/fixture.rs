// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! A fake machine described in `fixtures/hosts/<name>/host.yaml`. See `fixtures/hosts/PROVENANCE.md`.

use std::collections::BTreeMap;
use std::path::Path;

use serde::Deserialize;

use crate::{
    CodeIntegrityOptions, DirEntryInfo, EnvironmentSource, FilesystemSource, Host, Platform,
    ProcessRecord, ProcessSource, RegistrySource, SourceError, SystemIntegritySource, TpmInfo,
    TpmSource,
};

/// Why a fixture host could not be loaded.
#[derive(Debug, thiserror::Error)]
pub enum FixtureError {
    /// The file could not be read.
    #[error("cannot read {path}: {source}")]
    Io {
        /// Path of the fixture file.
        path: String,
        /// Underlying error.
        #[source]
        source: std::io::Error,
    },
    /// The file is not a valid fixture host.
    #[error("invalid fixture host {path}: {message}")]
    Parse {
        /// Path of the fixture file.
        path: String,
        /// Parser message.
        message: String,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostFile {
    platform: Platform,
    #[serde(default)]
    os_build: Option<String>,
    #[serde(default)]
    elevated: Option<bool>,
    #[serde(default)]
    registry: BTreeMap<String, BTreeMap<String, RegistryValue>>,
    #[serde(default)]
    env: BTreeMap<String, String>,
    #[serde(default)]
    filesystem: BTreeMap<String, Vec<FixtureFile>>,
    #[serde(default)]
    access_denied: Vec<String>,
    #[serde(default)]
    code_integrity: Option<FixtureCodeIntegrity>,
    #[serde(default)]
    tpm: Option<FixtureTpm>,
    #[serde(default)]
    processes: Option<Vec<FixtureProcess>>,
}

/// Code-integrity settings a fixture describes. Absent means the fixture never modelled them, which
/// the accessor reports as `Unsupported` rather than inventing a value (ADR 0011).
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureCodeIntegrity {
    enabled: bool,
    test_signing: bool,
}

/// The TPM a fixture describes. Absent means the fixture never modelled one.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureTpm {
    present: bool,
    #[serde(default)]
    spec_version: Option<String>,
}

/// One process a fixture describes. An absent `path` describes a process whose image path cannot be
/// resolved, which a collector reports by omitting that one field — never by dropping the process.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureProcess {
    pid: u32,
    name: String,
    #[serde(default)]
    path: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum RegistryValue {
    Dword(u32),
    Text(String),
}

/// One entry in a fixture directory, as the YAML writes it. A file unless `directory: true`; an
/// absent `sha256` describes a file whose hash cannot be read, which a collector must report by
/// omitting the field.
///
/// Its bytes are written one of two ways, and never both: `content:` holds them inline as text, and
/// `from:` names a file under `fixtures/`, relative to the directory holding this `host.yaml`. An
/// entry with neither describes a file that is listed and whose bytes cannot be read (ADR 0019).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureFile {
    name: String,
    #[serde(default)]
    sha256: Option<String>,
    #[serde(default)]
    directory: bool,
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    from: Option<String>,
}

/// One entry in a fixture directory with its `from:` already read from disk, so that a fixture with a
/// path that does not resolve fails when it is loaded rather than looking like an unreadable file.
#[derive(Debug, Clone)]
struct FixtureEntry {
    name: String,
    sha256: Option<String>,
    directory: bool,
    /// The file's bytes. `None` describes a file that exists and cannot be read.
    content: Option<Vec<u8>>,
}

/// Paths and registry keys are compared case-insensitively and without a trailing separator, like Windows.
fn normalise_path(path: &str) -> String {
    path.trim_end_matches(['\\', '/']).to_ascii_lowercase()
}

/// Splits a normalised path into its parent directory and the last segment.
fn split_parent(path: &str) -> (&str, &str) {
    path.rfind(['\\', '/'])
        .map_or(("", path), |index| (&path[..index], &path[index + 1..]))
}

/// Turns one described file into a stored entry, reading a `from:` file now rather than later.
///
/// `content:` and `from:` are two ways of writing the same thing, so a file that uses both is
/// rejected instead of one of them being picked: a fixture that says two things about one file is a
/// fixture whose reader has to guess.
fn resolve_file(
    described: FixtureFile,
    origin: &str,
    base: Option<&Path>,
) -> Result<FixtureEntry, FixtureError> {
    let content = match (described.content, described.from) {
        (Some(_), Some(_)) => {
            return Err(FixtureError::Parse {
                path: origin.to_owned(),
                message: format!(
                    "file `{}` uses both `content:` and `from:`; it must use one",
                    described.name
                ),
            });
        }
        (Some(inline), None) => Some(inline.into_bytes()),
        (None, Some(relative)) => {
            let Some(base) = base else {
                return Err(FixtureError::Parse {
                    path: origin.to_owned(),
                    message: format!(
                        "file `{}` uses `from:`, which needs a fixture directory to start from; \
                         an inline fixture writes its bytes with `content:`",
                        described.name
                    ),
                });
            };
            let path = base.join(&relative);
            Some(std::fs::read(&path).map_err(|source| FixtureError::Io {
                path: path.display().to_string(),
                source,
            })?)
        }
        (None, None) => None,
    };
    Ok(FixtureEntry {
        name: described.name,
        sha256: described.sha256,
        directory: described.directory,
        content,
    })
}

/// A fake machine for tests. Registry keys, value names, directory paths and environment variable names
/// are case-insensitive, like Windows.
#[derive(Debug, Clone)]
pub struct FixtureHost {
    platform: Platform,
    os_build: Option<String>,
    elevated: Option<bool>,
    registry: BTreeMap<String, BTreeMap<String, RegistryValue>>,
    env: BTreeMap<String, String>,
    filesystem: BTreeMap<String, Vec<FixtureEntry>>,
    access_denied: Vec<String>,
    code_integrity: Option<FixtureCodeIntegrity>,
    tpm: Option<FixtureTpm>,
    processes: Option<Vec<FixtureProcess>>,
}

impl FixtureHost {
    /// Loads `<dir>/host.yaml`. A `from:` in it is read relative to `dir`.
    pub fn load(dir: &Path) -> Result<Self, FixtureError> {
        let path = dir.join("host.yaml");
        let text = std::fs::read_to_string(&path).map_err(|source| FixtureError::Io {
            path: path.display().to_string(),
            source,
        })?;
        Self::parse(&text, &path.display().to_string(), Some(dir))
    }

    /// Parses a fixture host from YAML; `origin` is used in error messages.
    ///
    /// An inline fixture has no directory for a relative path to start from, so a file entry that
    /// uses `from:` is rejected here and must use `content:` instead.
    pub fn from_yaml_str(yaml: &str, origin: &str) -> Result<Self, FixtureError> {
        Self::parse(yaml, origin, None)
    }

    /// `base` is the directory a `from:` resolves against, or `None` for an inline fixture.
    fn parse(yaml: &str, origin: &str, base: Option<&Path>) -> Result<Self, FixtureError> {
        let file: HostFile = serde_saphyr::from_str(yaml).map_err(|e| FixtureError::Parse {
            path: origin.to_owned(),
            message: e.to_string(),
        })?;
        let registry = file
            .registry
            .into_iter()
            .map(|(key, values)| {
                let values = values
                    .into_iter()
                    .map(|(name, value)| (name.to_ascii_lowercase(), value))
                    .collect();
                (key.to_ascii_lowercase(), values)
            })
            .collect();
        let env = file
            .env
            .into_iter()
            .map(|(name, value)| (name.to_ascii_lowercase(), value))
            .collect();
        let mut filesystem = BTreeMap::new();
        for (dir, files) in file.filesystem {
            let mut entries = Vec::with_capacity(files.len());
            for described in files {
                entries.push(resolve_file(described, origin, base)?);
            }
            filesystem.insert(normalise_path(&dir), entries);
        }
        Ok(Self {
            platform: file.platform,
            os_build: file.os_build,
            elevated: file.elevated,
            registry,
            env,
            filesystem,
            access_denied: file
                .access_denied
                .iter()
                .map(|key| normalise_path(key))
                .collect(),
            code_integrity: file.code_integrity,
            tpm: file.tpm,
            processes: file.processes,
        })
    }

    /// The file system is only described for Windows fixtures.
    fn windows_filesystem(&self) -> Result<(), SourceError> {
        if self.platform == Platform::Windows {
            Ok(())
        } else {
            Err(SourceError::Unsupported(
                "no Windows file system on this platform".to_owned(),
            ))
        }
    }

    fn is_denied(&self, path: &str) -> bool {
        self.access_denied.iter().any(|denied| denied == path)
    }

    fn lookup(&self, key: &str, value: &str) -> Result<Option<&RegistryValue>, SourceError> {
        if self.platform != Platform::Windows {
            return Err(SourceError::Unsupported(
                "no registry on this platform".to_owned(),
            ));
        }
        let key = key.to_ascii_lowercase();
        if self.access_denied.contains(&key) {
            return Err(SourceError::AccessDenied);
        }
        Ok(self
            .registry
            .get(&key)
            .and_then(|values| values.get(&value.to_ascii_lowercase())))
    }
}

impl RegistrySource for FixtureHost {
    fn read_u32(&self, key: &str, value: &str) -> Result<Option<u32>, SourceError> {
        match self.lookup(key, value)? {
            Some(RegistryValue::Dword(number)) => Ok(Some(*number)),
            Some(RegistryValue::Text(_)) => Err(SourceError::Failed(
                "expected a DWORD, found a string".to_owned(),
            )),
            None => Ok(None),
        }
    }

    fn read_string(&self, key: &str, value: &str) -> Result<Option<String>, SourceError> {
        match self.lookup(key, value)? {
            Some(RegistryValue::Text(text)) => Ok(Some(text.clone())),
            Some(RegistryValue::Dword(_)) => Err(SourceError::Failed(
                "expected a string, found a DWORD".to_owned(),
            )),
            None => Ok(None),
        }
    }
}

impl FilesystemSource for FixtureHost {
    fn list_dir(&self, dir: &str) -> Result<Option<Vec<DirEntryInfo>>, SourceError> {
        self.windows_filesystem()?;
        let dir = normalise_path(dir);
        if self.is_denied(&dir) {
            return Err(SourceError::AccessDenied);
        }
        Ok(self.filesystem.get(&dir).map(|files| {
            files
                .iter()
                .map(|file| DirEntryInfo {
                    name: file.name.clone(),
                    is_file: !file.directory,
                })
                .collect()
        }))
    }

    fn file_sha256(&self, path: &str) -> Result<String, SourceError> {
        self.windows_filesystem()?;
        let normalised = normalise_path(path);
        let (dir, name) = split_parent(&normalised);
        if self.is_denied(&normalised) || self.is_denied(dir) {
            return Err(SourceError::AccessDenied);
        }
        let file = self
            .filesystem
            .get(dir)
            .and_then(|files| {
                files
                    .iter()
                    .find(|file| file.name.eq_ignore_ascii_case(name))
            })
            .ok_or_else(|| SourceError::Failed(format!("no such file: {path}")))?;
        file.sha256
            .clone()
            .ok_or_else(|| SourceError::Failed(format!("no sha256 recorded for {path}")))
    }

    /// The bytes the fixture wrote for that file, through the same limit a live host applies.
    ///
    /// A file the fixture never listed does not exist, which is `Ok(None)`. A file it listed without
    /// `content:` or `from:` exists and cannot be read, which is the per-file failure `sha256` already
    /// models the same way — not `Unsupported`, which is reserved for a whole block the fixture never
    /// described.
    fn read_file(&self, path: &str) -> Result<Option<Vec<u8>>, SourceError> {
        self.windows_filesystem()?;
        let normalised = normalise_path(path);
        let (dir, name) = split_parent(&normalised);
        if self.is_denied(&normalised) || self.is_denied(dir) {
            return Err(SourceError::AccessDenied);
        }
        let Some(file) = self.filesystem.get(dir).and_then(|files| {
            files
                .iter()
                .find(|file| file.name.eq_ignore_ascii_case(name))
        }) else {
            return Ok(None);
        };
        if file.directory {
            return Err(SourceError::Failed(format!("not a file: {path}")));
        }
        let content = file
            .content
            .as_ref()
            .ok_or_else(|| SourceError::Failed(format!("no content recorded for {path}")))?;
        crate::read_bounded(content.as_slice(), crate::MAX_FILE_BYTES).map(Some)
    }
}

impl EnvironmentSource for FixtureHost {
    fn env_var(&self, name: &str) -> Option<String> {
        self.env.get(&name.to_ascii_lowercase()).cloned()
    }
}

impl SystemIntegritySource for FixtureHost {
    fn code_integrity_options(&self) -> Result<CodeIntegrityOptions, SourceError> {
        let described = self.code_integrity.ok_or_else(|| {
            SourceError::Unsupported(
                "this fixture host does not describe code integrity".to_owned(),
            )
        })?;
        Ok(CodeIntegrityOptions {
            enabled: described.enabled,
            test_signing: described.test_signing,
        })
    }
}

impl TpmSource for FixtureHost {
    fn tpm_info(&self) -> Result<TpmInfo, SourceError> {
        let described = self.tpm.as_ref().ok_or_else(|| {
            SourceError::Unsupported("this fixture host does not describe a TPM".to_owned())
        })?;
        Ok(TpmInfo {
            present: described.present,
            spec_version: described.spec_version.clone(),
        })
    }
}

impl ProcessSource for FixtureHost {
    /// The processes the fixture lists, in file order.
    ///
    /// A fixture with no `processes:` block never modelled a process list, so it is `Unsupported`
    /// rather than an empty list: an empty list is the claim that nothing was running (ADR 0010).
    /// A fixture that writes `processes: []` makes that claim deliberately.
    fn running_processes(&self) -> Result<Vec<ProcessRecord>, SourceError> {
        let described = self.processes.as_ref().ok_or_else(|| {
            SourceError::Unsupported(
                "this fixture host does not describe running processes".to_owned(),
            )
        })?;
        Ok(described
            .iter()
            .map(|process| ProcessRecord {
                pid: process.pid,
                name: process.name.clone(),
                path: process.path.clone(),
            })
            .collect())
    }
}

impl Host for FixtureHost {
    fn platform(&self) -> Platform {
        self.platform
    }

    fn os_build(&self) -> Option<String> {
        self.os_build.clone()
    }

    fn is_elevated(&self) -> Option<bool> {
        self.elevated
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOST: &str = r#"
platform: windows
os_build: "26100"
elevated: false
registry:
  'HKLM\SYSTEM\Example':
    Enabled: 1
    Name: "hello"
env:
  LOCALAPPDATA: 'C:\Users\fixtureuser\AppData\Local'
filesystem:
  'C:\Users\fixtureuser\AppData\Local\Example':
    - name: readable.dll
      sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
      content: "the bytes of readable.dll"
    - name: unreadable.dll
    - name: cache
      directory: true
access_denied:
  - 'HKLM\SYSTEM\Locked'
  - 'C:\Users\fixtureuser\AppData\Local\Locked'
code_integrity:
  enabled: true
  test_signing: true
tpm:
  present: true
  spec_version: "2.0"
processes:
  - pid: 4
    name: System
  - pid: 1200
    name: FiveM.exe
    path: 'C:\Users\fixtureuser\AppData\Local\FiveM\FiveM.exe'
"#;

    const EMPTY_HASH: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    #[test]
    fn reads_values_case_insensitively() {
        let host = FixtureHost::from_yaml_str(HOST, "inline").unwrap();
        assert_eq!(
            host.read_u32(r"hklm\system\EXAMPLE", "enabled"),
            Ok(Some(1))
        );
        assert_eq!(
            host.read_string(r"HKLM\SYSTEM\Example", "Name"),
            Ok(Some("hello".to_owned()))
        );
        assert_eq!(host.read_u32(r"HKLM\SYSTEM\Example", "Missing"), Ok(None));
        assert_eq!(host.os_build().as_deref(), Some("26100"));
    }

    #[test]
    fn access_denied_and_type_mismatch() {
        let host = FixtureHost::from_yaml_str(HOST, "inline").unwrap();
        assert_eq!(
            host.read_u32(r"HKLM\SYSTEM\Locked", "Anything"),
            Err(SourceError::AccessDenied)
        );
        assert!(matches!(
            host.read_u32(r"HKLM\SYSTEM\Example", "Name"),
            Err(SourceError::Failed(_))
        ));
    }

    #[test]
    fn unknown_fields_are_rejected() {
        assert!(FixtureHost::from_yaml_str("platform: windows\nbogus: 1\n", "inline").is_err());
        assert!(
            FixtureHost::from_yaml_str(
                "platform: windows\nfilesystem:\n  'C:\\x':\n    - name: a.dll\n      bogus: 1\n",
                "inline"
            )
            .is_err()
        );
    }

    #[test]
    fn the_four_existing_fields_still_load_without_the_new_ones() {
        let host = FixtureHost::from_yaml_str("platform: windows\nos_build: \"26100\"\n", "inline")
            .unwrap();
        assert_eq!(host.env_var("LOCALAPPDATA"), None);
        assert_eq!(host.list_dir(r"C:\anything"), Ok(None));
    }

    #[test]
    fn environment_variables_are_case_insensitive() {
        let host = FixtureHost::from_yaml_str(HOST, "inline").unwrap();
        assert_eq!(
            host.env_var("localappdata").as_deref(),
            Some(r"C:\Users\fixtureuser\AppData\Local")
        );
        assert_eq!(host.env_var("NOT_SET"), None);
    }

    #[test]
    fn directories_are_listed_case_insensitively_and_mark_subdirectories() {
        let host = FixtureHost::from_yaml_str(HOST, "inline").unwrap();
        assert_eq!(
            host.list_dir(r"c:\users\FIXTUREUSER\appdata\local\example"),
            Ok(Some(vec![
                DirEntryInfo {
                    name: "readable.dll".to_owned(),
                    is_file: true,
                },
                DirEntryInfo {
                    name: "unreadable.dll".to_owned(),
                    is_file: true,
                },
                DirEntryInfo {
                    name: "cache".to_owned(),
                    is_file: false,
                },
            ]))
        );
    }

    #[test]
    fn a_directory_that_is_not_described_is_none() {
        let host = FixtureHost::from_yaml_str(HOST, "inline").unwrap();
        assert_eq!(
            host.list_dir(r"C:\Users\fixtureuser\AppData\Local\Absent"),
            Ok(None)
        );
    }

    #[test]
    fn a_file_hash_is_read_and_an_absent_one_fails() {
        let host = FixtureHost::from_yaml_str(HOST, "inline").unwrap();
        let dir = r"C:\Users\fixtureuser\AppData\Local\Example";
        assert_eq!(
            host.file_sha256(&format!(r"{dir}\READABLE.dll")),
            Ok(EMPTY_HASH.to_owned())
        );
        assert!(matches!(
            host.file_sha256(&format!(r"{dir}\unreadable.dll")),
            Err(SourceError::Failed(_))
        ));
        assert!(matches!(
            host.file_sha256(&format!(r"{dir}\absent.dll")),
            Err(SourceError::Failed(_))
        ));
    }

    #[test]
    fn access_denied_covers_directories_too() {
        let host = FixtureHost::from_yaml_str(HOST, "inline").unwrap();
        let dir = r"C:\Users\fixtureuser\AppData\Local\Locked";
        assert_eq!(host.list_dir(dir), Err(SourceError::AccessDenied));
        assert_eq!(
            host.file_sha256(&format!(r"{dir}\x.dll")),
            Err(SourceError::AccessDenied)
        );
        assert_eq!(
            host.read_file(&format!(r"{dir}\x.dll")),
            Err(SourceError::AccessDenied)
        );
    }

    #[test]
    fn file_content_is_read_case_insensitively() {
        let host = FixtureHost::from_yaml_str(HOST, "inline").unwrap();
        let dir = r"C:\Users\fixtureuser\AppData\Local\Example";
        assert_eq!(
            host.read_file(&format!(r"{dir}\READABLE.dll")),
            Ok(Some(b"the bytes of readable.dll".to_vec()))
        );
    }

    /// The two shapes a fixture can describe without writing bytes, and they are different answers:
    /// a file nobody listed is not on this machine, while one listed without bytes is there and
    /// cannot be read.
    #[test]
    fn an_absent_file_is_none_and_a_listed_one_without_bytes_fails() {
        let host = FixtureHost::from_yaml_str(HOST, "inline").unwrap();
        let dir = r"C:\Users\fixtureuser\AppData\Local\Example";
        assert_eq!(host.read_file(&format!(r"{dir}\absent.dll")), Ok(None));
        assert_eq!(host.read_file(r"C:\Nowhere\at\all.dll"), Ok(None));
        assert!(matches!(
            host.read_file(&format!(r"{dir}\unreadable.dll")),
            Err(SourceError::Failed(_))
        ));
    }

    /// `list_dir` says which entries are files; asking for a directory's bytes is a caller's mistake
    /// and is reported as one rather than as an empty file.
    #[test]
    fn a_directory_has_no_bytes() {
        let host = FixtureHost::from_yaml_str(HOST, "inline").unwrap();
        assert!(matches!(
            host.read_file(r"C:\Users\fixtureuser\AppData\Local\Example\cache"),
            Err(SourceError::Failed(_))
        ));
    }

    #[test]
    fn a_file_describing_its_bytes_twice_is_rejected() {
        let error = FixtureHost::from_yaml_str(
            "platform: windows\nfilesystem:\n  'C:\\x':\n    - name: a.txt\n      content: \"a\"\n      from: 'b.txt'\n",
            "inline",
        )
        .unwrap_err();
        assert!(error.to_string().contains("content"), "{error}");
    }

    /// An inline fixture has no directory for a relative path to start from, so `from:` is refused
    /// there instead of being resolved against whatever the test's working directory happens to be.
    #[test]
    fn from_needs_a_fixture_directory() {
        let error = FixtureHost::from_yaml_str(
            "platform: windows\nfilesystem:\n  'C:\\x':\n    - name: a.txt\n      from: 'b.txt'\n",
            "inline",
        )
        .unwrap_err();
        assert!(error.to_string().contains("from"), "{error}");
    }

    #[test]
    fn code_integrity_and_tpm_are_read_from_the_fixture() {
        let host = FixtureHost::from_yaml_str(HOST, "inline").unwrap();
        assert_eq!(
            host.code_integrity_options(),
            Ok(CodeIntegrityOptions {
                enabled: true,
                test_signing: true,
            })
        );
        assert_eq!(
            host.tpm_info(),
            Ok(TpmInfo {
                present: true,
                spec_version: Some("2.0".to_owned()),
            })
        );
    }

    /// A fixture written before these settings existed must not silently claim one: silence is
    /// "never modelled", which is `Unsupported`, and never a made-up "disabled" or "absent".
    #[test]
    fn a_fixture_without_the_new_blocks_is_unsupported_not_a_default() {
        let host = FixtureHost::from_yaml_str("platform: windows\n", "inline").unwrap();
        assert!(matches!(
            host.code_integrity_options(),
            Err(SourceError::Unsupported(_))
        ));
        assert!(matches!(host.tpm_info(), Err(SourceError::Unsupported(_))));
        assert!(matches!(
            host.running_processes(),
            Err(SourceError::Unsupported(_))
        ));
    }

    #[test]
    fn processes_are_returned_in_file_order() {
        let host = FixtureHost::from_yaml_str(HOST, "inline").unwrap();
        assert_eq!(
            host.running_processes(),
            Ok(vec![
                ProcessRecord {
                    pid: 4,
                    name: "System".to_owned(),
                    path: None,
                },
                ProcessRecord {
                    pid: 1200,
                    name: "FiveM.exe".to_owned(),
                    path: Some(r"C:\Users\fixtureuser\AppData\Local\FiveM\FiveM.exe".to_owned()),
                },
            ])
        );
    }

    /// Writing the block with nothing in it is a deliberate statement, unlike leaving it out.
    #[test]
    fn an_explicitly_empty_process_list_is_an_answer() {
        let host =
            FixtureHost::from_yaml_str("platform: windows\nprocesses: []\n", "inline").unwrap();
        assert_eq!(host.running_processes(), Ok(vec![]));
    }

    #[test]
    fn an_absent_tpm_has_no_spec_version() {
        let host =
            FixtureHost::from_yaml_str("platform: windows\ntpm:\n  present: false\n", "inline")
                .unwrap();
        assert_eq!(
            host.tpm_info(),
            Ok(TpmInfo {
                present: false,
                spec_version: None,
            })
        );
    }

    #[test]
    fn unknown_fields_in_the_new_blocks_are_rejected() {
        assert!(
            FixtureHost::from_yaml_str(
                "platform: windows\ncode_integrity:\n  enabled: true\n  bogus: 1\n",
                "inline"
            )
            .is_err()
        );
        assert!(
            FixtureHost::from_yaml_str(
                "platform: windows\ntpm:\n  present: true\n  bogus: 1\n",
                "inline"
            )
            .is_err()
        );
        assert!(
            FixtureHost::from_yaml_str(
                "platform: windows\nprocesses:\n  - pid: 4\n    name: System\n    bogus: 1\n",
                "inline"
            )
            .is_err()
        );
    }

    #[test]
    fn a_non_windows_fixture_has_no_file_system() {
        let host = FixtureHost::from_yaml_str("platform: other\n", "inline").unwrap();
        assert!(matches!(
            host.list_dir(r"C:\x"),
            Err(SourceError::Unsupported(_))
        ));
        assert!(matches!(
            host.file_sha256(r"C:\x\y.dll"),
            Err(SourceError::Unsupported(_))
        ));
        assert!(matches!(
            host.read_file(r"C:\x\y.dll"),
            Err(SourceError::Unsupported(_))
        ));
    }
}
