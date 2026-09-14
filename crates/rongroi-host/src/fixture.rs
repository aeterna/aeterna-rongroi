// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! A fake machine described in `fixtures/hosts/<name>/host.yaml`. See `fixtures/hosts/PROVENANCE.md`.

use std::collections::BTreeMap;
use std::path::Path;

use serde::Deserialize;

use crate::{
    BootTimeSource, ChannelConfig, ChannelConfigReader, CodeIntegrityOptions, DirEntryInfo,
    EnvironmentSource, EventLogConfigSource, FilesystemSource, FirmwareSecureBoot, FirmwareSource,
    Host, Platform, ProcessRecord, ProcessSource, RegistryData, RegistrySource, SignatureCheck,
    SignatureSource, SourceError, SystemIntegritySource, TpmInfo, TpmSource,
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
    firmware: Option<FixtureFirmware>,
    #[serde(default)]
    processes: Option<Vec<FixtureProcess>>,
    /// What `GetTickCount64` would answer. Absent means the fixture never modelled it, which the
    /// accessor reports as `Unsupported` rather than inventing a value (ADR 0039).
    #[serde(default)]
    milliseconds_since_boot: Option<u64>,
    #[serde(default)]
    event_log_channels: Option<BTreeMap<String, FixtureChannel>>,
}

/// What a fixture says the Event Log service states about one channel (ADR 0042). A fixture with no
/// `event_log_channels:` block never modelled the service, which the accessor reports as
/// `Unsupported`; a block that does not name a channel describes a service with no such channel.
///
/// `never_answers: true`, and nothing else, describes a service that accepts the question about this
/// channel and never replies — the case a collector has to survive, and one no real machine can be
/// made to produce on demand. A reader asked about it blocks for as long as the process lives.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureChannel {
    #[serde(default)]
    log_file_path: Option<String>,
    #[serde(default)]
    max_size_bytes: Option<u64>,
    #[serde(default)]
    never_answers: bool,
}

/// One channel as the fixture's reader answers it.
#[derive(Debug, Clone)]
enum StoredChannel {
    Answers(ChannelConfig),
    NeverAnswers,
}

/// Turns what a fixture wrote for one channel into what its reader answers, refusing a channel that
/// both answers and does not.
fn resolve_channel(
    name: &str,
    described: FixtureChannel,
    origin: &str,
) -> Result<StoredChannel, FixtureError> {
    match (
        described.never_answers,
        described.log_file_path,
        described.max_size_bytes,
    ) {
        (true, None, None) => Ok(StoredChannel::NeverAnswers),
        (false, Some(log_file_path), Some(max_size_bytes)) => {
            Ok(StoredChannel::Answers(ChannelConfig {
                log_file_path,
                max_size_bytes,
            }))
        }
        _ => Err(FixtureError::Parse {
            path: origin.to_owned(),
            message: format!(
                "channel `{name}`: write `log_file_path` and `max_size_bytes`, or `never_answers: true` alone"
            ),
        }),
    }
}

/// The reader a fixture host hands out: its channels and its denials, owned, so it can move to
/// another thread.
#[derive(Debug, Clone)]
struct FixtureChannelReader {
    channels: BTreeMap<String, StoredChannel>,
    access_denied: Vec<String>,
}

impl ChannelConfigReader for FixtureChannelReader {
    fn channel_config(&self, channel: &str) -> Result<Option<ChannelConfig>, SourceError> {
        let key = channel.to_ascii_lowercase();
        if self.access_denied.contains(&key) {
            return Err(SourceError::AccessDenied);
        }
        match self.channels.get(&key) {
            None => Ok(None),
            Some(StoredChannel::Answers(config)) => Ok(Some(config.clone())),
            // Blocks without spinning. `park` may return spuriously, so it is asked again; nothing
            // ever unparks this thread on purpose.
            Some(StoredChannel::NeverAnswers) => loop {
                std::thread::park();
            },
        }
    }
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

/// The firmware a fixture describes (ADR 0038). Absent means the fixture never modelled it, which the
/// accessor reports as `Unsupported` rather than inventing a Secure Boot state.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureFirmware {
    secure_boot: FixtureFirmwareSecureBoot,
}

/// Every answer a live host gives about the firmware's `SecureBoot` variable, including the two that
/// are not answers: a process without the privilege to read it, and a read that failed.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum FixtureFirmwareSecureBoot {
    Enabled,
    Disabled,
    VariableAbsent,
    NotUefi,
    AccessDenied,
    ReadFailed,
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

/// One registry value as the YAML writes it. A number is a `REG_DWORD`, a string is a `REG_SZ`, a map
/// with the one key `qword:` is a `REG_QWORD` (ADR 0038), and any other map is a `REG_BINARY` whose
/// bytes are written the two ways a file's bytes are (ADR 0019): `content:` inline, or `from:` a file
/// under `fixtures/`. None can be confused for another — both maps refuse each other's keys — which
/// is what makes the untagged enum safe to extend.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum RegistryValue {
    Dword(u32),
    Text(String),
    Qword(FixtureQword),
    Binary(FixtureBinary),
}

/// A `REG_QWORD`, written `{ qword: 0 }`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureQword {
    qword: u64,
}

/// The bytes of one `REG_BINARY` value. Neither `content:` nor `from:` describes a value that is
/// there and whose bytes cannot be read, as a file entry with neither does (ADR 0019).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureBinary {
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    from: Option<String>,
}

/// One registry value with its `from:` already read from disk and the spelling the fixture used for
/// its name, so that enumeration can hand back what a real registry would.
#[derive(Debug, Clone)]
struct StoredValue {
    /// The name as the fixture wrote it; the map key is its lower-cased form.
    name: String,
    data: StoredData,
}

#[derive(Debug, Clone)]
enum StoredData {
    Dword(u32),
    Qword(u64),
    Text(String),
    /// `None` describes a value that is there and cannot be read.
    Binary(Option<Vec<u8>>),
}

/// One registry key a fixture describes, with the spelling it used for the key's own path.
#[derive(Debug, Clone)]
struct StoredKey {
    /// The full key path as the fixture wrote it; the map key is its lower-cased form.
    path: String,
    values: BTreeMap<String, StoredValue>,
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
    signature: Option<FixtureSignature>,
    #[serde(default)]
    directory: bool,
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    from: Option<String>,
    #[serde(default)]
    read_only: Option<bool>,
}

/// What a fixture says Windows would report about a file's embedded signature (ADR 0035). An absent
/// `signature:` describes a file whose signature cannot be checked, which a collector reports by
/// omitting the fields — the same shape an absent `sha256` has.
///
/// `signer` and `signer_cert_sha256` belong to `state: valid` and to nothing else, and a fixture that
/// writes them anywhere else fails to load: a live host never reports a signer it did not trust.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureSignature {
    state: FixtureSignatureState,
    #[serde(default)]
    signer: Option<String>,
    #[serde(default)]
    signer_cert_sha256: Option<String>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum FixtureSignatureState {
    Valid,
    NoEmbeddedSignature,
    Invalid,
    UnverifiableOffline,
}

/// Turns what a fixture wrote into what a host reports, refusing a combination no host produces.
fn resolve_signature(
    described: FixtureSignature,
    file: &str,
    origin: &str,
) -> Result<SignatureCheck, FixtureError> {
    let invalid = |message: String| FixtureError::Parse {
        path: origin.to_owned(),
        message: format!("file `{file}`: {message}"),
    };
    let names_signer = described.signer.is_some() || described.signer_cert_sha256.is_some();
    let quiet = |check: SignatureCheck| {
        if names_signer {
            Err(invalid(
                "only a valid signature names a `signer` or a `signer_cert_sha256`".to_owned(),
            ))
        } else {
            Ok(check)
        }
    };
    match described.state {
        FixtureSignatureState::NoEmbeddedSignature => quiet(SignatureCheck::NoEmbeddedSignature),
        FixtureSignatureState::Invalid => quiet(SignatureCheck::Invalid),
        FixtureSignatureState::UnverifiableOffline => quiet(SignatureCheck::UnverifiableOffline),
        FixtureSignatureState::Valid => {
            let (Some(signer), Some(cert)) = (described.signer, described.signer_cert_sha256)
            else {
                return Err(invalid(
                    "a valid signature needs both `signer` and `signer_cert_sha256`".to_owned(),
                ));
            };
            if signer.trim().is_empty() {
                return Err(invalid(
                    "a valid signature needs a non-empty `signer`".to_owned(),
                ));
            }
            if cert.len() != 64 || !cert.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(invalid(format!(
                    "`signer_cert_sha256` `{cert}` must be 64 hex characters"
                )));
            }
            Ok(SignatureCheck::Valid {
                signer,
                signer_cert_sha256: cert.to_ascii_lowercase(),
            })
        }
    }
}

/// One entry in a fixture directory with its `from:` already read from disk, so that a fixture with a
/// path that does not resolve fails when it is loaded rather than looking like an unreadable file.
#[derive(Debug, Clone)]
struct FixtureEntry {
    name: String,
    sha256: Option<String>,
    /// `None` describes a file whose signature cannot be checked.
    signature: Option<SignatureCheck>,
    directory: bool,
    /// The file's bytes. `None` describes a file that exists and cannot be read.
    content: Option<Vec<u8>>,
    /// Whether the file carries the read-only attribute. `None` describes a fixture that never said,
    /// which is not the same as saying it does not (ADR 0037).
    read_only: Option<bool>,
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

/// Reads the bytes a fixture described, resolving a `from:` now rather than later.
///
/// `content:` and `from:` are two ways of writing the same thing, so an entry that uses both is
/// rejected instead of one of them being picked: a fixture that says two things about one entry is a
/// fixture whose reader has to guess. `what` names the entry in an error message.
fn resolve_content(
    content: Option<String>,
    from: Option<String>,
    what: &str,
    origin: &str,
    base: Option<&Path>,
) -> Result<Option<Vec<u8>>, FixtureError> {
    match (content, from) {
        (Some(_), Some(_)) => Err(FixtureError::Parse {
            path: origin.to_owned(),
            message: format!("{what} uses both `content:` and `from:`; it must use one"),
        }),
        (Some(inline), None) => Ok(Some(inline.into_bytes())),
        (None, Some(relative)) => {
            let Some(base) = base else {
                return Err(FixtureError::Parse {
                    path: origin.to_owned(),
                    message: format!(
                        "{what} uses `from:`, which needs a fixture directory to start from; \
                         an inline fixture writes its bytes with `content:`"
                    ),
                });
            };
            let path = base.join(&relative);
            Ok(Some(std::fs::read(&path).map_err(|source| {
                FixtureError::Io {
                    path: path.display().to_string(),
                    source,
                }
            })?))
        }
        (None, None) => Ok(None),
    }
}

/// Turns one described file into a stored entry, reading a `from:` file now rather than later.
fn resolve_file(
    described: FixtureFile,
    origin: &str,
    base: Option<&Path>,
) -> Result<FixtureEntry, FixtureError> {
    let content = resolve_content(
        described.content,
        described.from,
        &format!("file `{}`", described.name),
        origin,
        base,
    )?;
    let signature = described
        .signature
        .map(|signature| resolve_signature(signature, &described.name, origin))
        .transpose()?;
    Ok(FixtureEntry {
        name: described.name,
        sha256: described.sha256,
        signature,
        directory: described.directory,
        content,
        read_only: described.read_only,
    })
}

/// Turns one described registry value into a stored one, reading a `from:` file now rather than
/// later, and keeping the name as the fixture spelled it.
fn resolve_value(
    name: String,
    described: RegistryValue,
    origin: &str,
    base: Option<&Path>,
) -> Result<StoredValue, FixtureError> {
    let data = match described {
        RegistryValue::Dword(number) => StoredData::Dword(number),
        RegistryValue::Text(text) => StoredData::Text(text),
        RegistryValue::Qword(qword) => StoredData::Qword(qword.qword),
        RegistryValue::Binary(binary) => StoredData::Binary(resolve_content(
            binary.content,
            binary.from,
            &format!("registry value `{name}`"),
            origin,
            base,
        )?),
    };
    Ok(StoredValue { name, data })
}

/// A fake machine for tests. Registry keys, value names, directory paths and environment variable names
/// are case-insensitive, like Windows.
#[derive(Debug, Clone)]
pub struct FixtureHost {
    platform: Platform,
    os_build: Option<String>,
    elevated: Option<bool>,
    registry: BTreeMap<String, StoredKey>,
    env: BTreeMap<String, String>,
    filesystem: BTreeMap<String, Vec<FixtureEntry>>,
    access_denied: Vec<String>,
    code_integrity: Option<FixtureCodeIntegrity>,
    tpm: Option<FixtureTpm>,
    firmware: Option<FixtureFirmware>,
    processes: Option<Vec<FixtureProcess>>,
    milliseconds_since_boot: Option<u64>,
    /// Keyed by the lower-cased channel name, like every other name this host compares.
    event_log_channels: Option<BTreeMap<String, StoredChannel>>,
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
        let mut registry = BTreeMap::new();
        for (key, values) in file.registry {
            let mut stored = BTreeMap::new();
            for (name, value) in values {
                let lowercased = name.to_ascii_lowercase();
                stored.insert(lowercased, resolve_value(name, value, origin, base)?);
            }
            registry.insert(
                key.to_ascii_lowercase(),
                StoredKey {
                    path: key,
                    values: stored,
                },
            );
        }
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
            firmware: file.firmware,
            processes: file.processes,
            milliseconds_since_boot: file.milliseconds_since_boot,
            event_log_channels: file
                .event_log_channels
                .map(|channels| {
                    channels
                        .into_iter()
                        .map(|(name, channel)| {
                            let stored = resolve_channel(&name, channel, origin)?;
                            Ok((name.to_ascii_lowercase(), stored))
                        })
                        .collect::<Result<BTreeMap<_, _>, FixtureError>>()
                })
                .transpose()?,
        })
    }

    /// The entry the fixture wrote for one file, after the access checks every per-file read makes.
    /// A file it never listed is a failure here, which is what hashing or checking one means.
    fn described_file(&self, path: &str) -> Result<&FixtureEntry, SourceError> {
        let normalised = normalise_path(path);
        let (dir, name) = split_parent(&normalised);
        if self.is_denied(&normalised) || self.is_denied(dir) {
            return Err(SourceError::AccessDenied);
        }
        self.filesystem
            .get(dir)
            .and_then(|files| {
                files
                    .iter()
                    .find(|file| file.name.eq_ignore_ascii_case(name))
            })
            .ok_or_else(|| SourceError::Failed(format!("no such file: {path}")))
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

    /// The lower-cased key a fixture would have stored, once this host is known to have a registry
    /// and the key is known not to be one the fixture denies.
    fn registry_key(&self, key: &str) -> Result<String, SourceError> {
        if self.platform != Platform::Windows {
            return Err(SourceError::Unsupported(
                "no registry on this platform".to_owned(),
            ));
        }
        let key = key.to_ascii_lowercase();
        if self.access_denied.contains(&key) {
            return Err(SourceError::AccessDenied);
        }
        Ok(key)
    }

    fn lookup(&self, key: &str, value: &str) -> Result<Option<&StoredValue>, SourceError> {
        let key = self.registry_key(key)?;
        Ok(self
            .registry
            .get(&key)
            .and_then(|stored| stored.values.get(&value.to_ascii_lowercase())))
    }

    /// Whether a fixture described this key at all — either by writing it, or by writing a key
    /// underneath it. A key with subkeys and no values of its own is still a key that is there.
    fn registry_key_exists(&self, key: &str) -> bool {
        let prefix = format!(r"{key}\");
        self.registry.contains_key(key)
            || self
                .registry
                .keys()
                .any(|stored| stored.starts_with(&prefix))
    }
}

impl RegistrySource for FixtureHost {
    fn read_u32(&self, key: &str, value: &str) -> Result<Option<u32>, SourceError> {
        match self.lookup(key, value)?.map(|stored| &stored.data) {
            Some(StoredData::Dword(number)) => Ok(Some(*number)),
            // A live host's reader accepts a `REG_QWORD` that fits, so this one does too.
            Some(StoredData::Qword(number)) => u32::try_from(*number)
                .map(Some)
                .map_err(|_| SourceError::Failed("a QWORD too large for a DWORD".to_owned())),
            Some(StoredData::Text(_)) => Err(SourceError::Failed(
                "expected a DWORD, found a string".to_owned(),
            )),
            Some(StoredData::Binary(_)) => Err(SourceError::Failed(
                "expected a DWORD, found a binary value".to_owned(),
            )),
            None => Ok(None),
        }
    }

    fn read_string(&self, key: &str, value: &str) -> Result<Option<String>, SourceError> {
        match self.lookup(key, value)?.map(|stored| &stored.data) {
            Some(StoredData::Text(text)) => Ok(Some(text.clone())),
            Some(StoredData::Dword(_) | StoredData::Qword(_)) => Err(SourceError::Failed(
                "expected a string, found a number".to_owned(),
            )),
            Some(StoredData::Binary(_)) => Err(SourceError::Failed(
                "expected a string, found a binary value".to_owned(),
            )),
            None => Ok(None),
        }
    }

    /// The keys the fixture wrote directly underneath this one, in a stable order and spelled as it
    /// wrote them.
    ///
    /// A fixture describes a key by writing its values, so the subkeys of a key are found by
    /// scanning for the keys whose path starts with it — which is also why a key nobody wrote and
    /// nothing sits under is `Ok(None)`, the same answer `read_u32` gives for a key that is not
    /// there.
    fn subkeys(&self, key: &str) -> Result<Option<Vec<String>>, SourceError> {
        let key = self.registry_key(key)?;
        if !self.registry_key_exists(&key) {
            return Ok(None);
        }
        let prefix = format!(r"{key}\");
        let mut children: BTreeMap<String, String> = BTreeMap::new();
        for stored in self.registry.values() {
            // Lower-casing is length-preserving, so the prefix that matched the lower-cased path
            // covers the same bytes of the path as the fixture spelled it.
            let lowercased = stored.path.to_ascii_lowercase();
            let Some(rest) = lowercased.strip_prefix(&prefix) else {
                continue;
            };
            let length = rest.find('\\').unwrap_or(rest.len());
            let child = &stored.path[prefix.len()..prefix.len() + length];
            children.insert(child.to_ascii_lowercase(), child.to_owned());
        }
        Ok(Some(children.into_values().collect()))
    }

    /// The names of this key's values, in a stable order and spelled as the fixture wrote them.
    fn value_names(&self, key: &str) -> Result<Option<Vec<String>>, SourceError> {
        let key = self.registry_key(key)?;
        if !self.registry_key_exists(&key) {
            return Ok(None);
        }
        Ok(Some(
            self.registry
                .get(&key)
                .map(|stored| {
                    stored
                        .values
                        .values()
                        .map(|value| value.name.clone())
                        .collect()
                })
                .unwrap_or_default(),
        ))
    }

    /// The bytes the fixture wrote for that value, through the same limit a live host applies.
    ///
    /// A value written with neither `content:` nor `from:` is there and cannot be read, which is the
    /// per-value failure a file entry without bytes already models the same way (ADR 0019).
    fn read_bytes(&self, key: &str, value: &str) -> Result<Option<Vec<u8>>, SourceError> {
        match self.lookup(key, value)?.map(|stored| &stored.data) {
            Some(StoredData::Binary(Some(bytes))) => {
                crate::bound_registry_value(bytes.clone(), crate::MAX_REGISTRY_VALUE_BYTES)
                    .map(Some)
            }
            Some(StoredData::Binary(None)) => Err(SourceError::Failed(format!(
                "no bytes recorded for {key}\\{value}"
            ))),
            Some(StoredData::Dword(_) | StoredData::Qword(_) | StoredData::Text(_)) => {
                Err(SourceError::Failed(
                    "expected a binary value, found a number or a string".to_owned(),
                ))
            }
            None => Ok(None),
        }
    }

    /// The type and data the fixture wrote, through the same limit a live host applies to a string.
    /// A binary value is a type whose data this method does not read.
    fn read_value(&self, key: &str, value: &str) -> Result<Option<RegistryData>, SourceError> {
        let data = match self.lookup(key, value)?.map(|stored| &stored.data) {
            Some(StoredData::Dword(number)) => RegistryData::Dword(*number),
            Some(StoredData::Qword(number)) => RegistryData::Qword(*number),
            Some(StoredData::Text(text)) => RegistryData::Text(text.clone()),
            Some(StoredData::Binary(_)) => RegistryData::OtherType,
            None => return Ok(None),
        };
        crate::bound_registry_data(data, crate::MAX_REGISTRY_VALUE_BYTES).map(Some)
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
        let file = self.described_file(path)?;
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

    /// What the fixture wrote under `read_only:` for that file, behind the same access checks
    /// `read_file` makes.
    ///
    /// A file the fixture never listed does not exist, which is `Ok(None)`. A file it listed without
    /// `read_only:` is `Unsupported`: silence in a fixture is "never modelled", and answering `false`
    /// for it would put a value in the report nobody wrote (ADR 0037).
    fn is_read_only(&self, path: &str) -> Result<Option<bool>, SourceError> {
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
        file.read_only.map(Some).ok_or_else(|| {
            SourceError::Unsupported(format!(
                "this fixture host does not describe the attributes of {path}"
            ))
        })
    }
}

impl EventLogConfigSource for FixtureHost {
    /// A reader over what the fixture wrote under `event_log_channels:`.
    ///
    /// No block at all is `Unsupported`, never a reader that knows no channel: a fixture written
    /// before this source existed must not claim that the service knows none. A channel named in
    /// `access_denied` is refused, as a key or a folder named there is.
    fn channel_config_reader(&self) -> Result<Box<dyn ChannelConfigReader>, SourceError> {
        if self.platform != Platform::Windows {
            return Err(SourceError::Unsupported(
                "no Windows Event Log on this platform".to_owned(),
            ));
        }
        let channels = self.event_log_channels.clone().ok_or_else(|| {
            SourceError::Unsupported(
                "this fixture host does not describe the Event Log service".to_owned(),
            )
        })?;
        Ok(Box::new(FixtureChannelReader {
            channels,
            access_denied: self.access_denied.clone(),
        }))
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

impl BootTimeSource for FixtureHost {
    fn since_boot(&self) -> Result<std::time::Duration, SourceError> {
        self.milliseconds_since_boot
            .map(std::time::Duration::from_millis)
            .ok_or_else(|| {
                SourceError::Unsupported(
                    "this fixture host does not describe a boot time".to_owned(),
                )
            })
    }
}

impl FirmwareSource for FixtureHost {
    fn firmware_secure_boot(&self) -> Result<FirmwareSecureBoot, SourceError> {
        let described = self.firmware.ok_or_else(|| {
            SourceError::Unsupported("this fixture host does not describe its firmware".to_owned())
        })?;
        match described.secure_boot {
            FixtureFirmwareSecureBoot::Enabled => Ok(FirmwareSecureBoot::Enabled),
            FixtureFirmwareSecureBoot::Disabled => Ok(FirmwareSecureBoot::Disabled),
            FixtureFirmwareSecureBoot::VariableAbsent => Ok(FirmwareSecureBoot::VariableAbsent),
            FixtureFirmwareSecureBoot::NotUefi => Ok(FirmwareSecureBoot::NotUefi),
            FixtureFirmwareSecureBoot::AccessDenied => Err(SourceError::AccessDenied),
            FixtureFirmwareSecureBoot::ReadFailed => Err(SourceError::Failed(
                "this fixture host describes a firmware read that failed".to_owned(),
            )),
        }
    }
}

impl SignatureSource for FixtureHost {
    /// What the fixture wrote under `signature:` for that file, behind the same access checks
    /// `file_sha256` makes.
    fn file_signature(&self, path: &str) -> Result<SignatureCheck, SourceError> {
        self.windows_filesystem()?;
        let file = self.described_file(path)?;
        file.signature
            .clone()
            .ok_or_else(|| SourceError::Failed(format!("no signature recorded for {path}")))
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

    const CERT: &str = "ABCDEF0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789";

    fn signed(signature: &str) -> Result<FixtureHost, FixtureError> {
        FixtureHost::from_yaml_str(
            &format!(
                "platform: windows\nfilesystem:\n  'C:\\p':\n    - name: a.dll\n      signature: {signature}\n    - name: b.dll\n"
            ),
            "inline",
        )
    }

    #[test]
    fn a_valid_signature_reports_its_signer_and_a_lowercased_certificate_hash() {
        let host = signed(&format!(
            "{{ state: valid, signer: Example Corp, signer_cert_sha256: {CERT} }}"
        ))
        .unwrap();
        assert_eq!(
            host.file_signature(r"C:\P\A.DLL"),
            Ok(SignatureCheck::Valid {
                signer: "Example Corp".to_owned(),
                signer_cert_sha256: CERT.to_ascii_lowercase(),
            })
        );
    }

    #[test]
    fn the_three_other_states_carry_no_signer() {
        for (written, expected) in [
            ("no_embedded_signature", SignatureCheck::NoEmbeddedSignature),
            ("invalid", SignatureCheck::Invalid),
            ("unverifiable_offline", SignatureCheck::UnverifiableOffline),
        ] {
            let host = signed(&format!("{{ state: {written} }}")).unwrap();
            assert_eq!(host.file_signature(r"C:\p\a.dll"), Ok(expected));
        }
    }

    /// A live host never reports a signer it did not trust, so a fixture cannot describe one.
    #[test]
    fn a_fixture_cannot_describe_a_signature_no_host_would_report() {
        for signature in [
            "{ state: valid, signer: Example Corp }".to_owned(),
            format!("{{ state: valid, signer_cert_sha256: {CERT} }}"),
            format!("{{ state: valid, signer: '  ', signer_cert_sha256: {CERT} }}"),
            "{ state: valid, signer: Example Corp, signer_cert_sha256: abc }".to_owned(),
            "{ state: invalid, signer: Example Corp }".to_owned(),
            format!("{{ state: unverifiable_offline, signer_cert_sha256: {CERT} }}"),
            "{ state: unsigned }".to_owned(),
        ] {
            assert!(signed(&signature).is_err(), "{signature} loaded");
        }
    }

    #[test]
    fn a_file_with_no_signature_written_could_not_be_checked() {
        let host = signed("{ state: invalid }").unwrap();
        assert!(matches!(
            host.file_signature(r"C:\p\b.dll"),
            Err(SourceError::Failed(_))
        ));
        assert!(matches!(
            host.file_signature(r"C:\p\absent.dll"),
            Err(SourceError::Failed(_))
        ));
    }

    #[test]
    fn a_denied_folder_denies_its_signatures_too() {
        let host = FixtureHost::from_yaml_str(
            "platform: windows\naccess_denied: ['C:\\p']\nfilesystem:\n  'C:\\p':\n    - name: a.dll\n      signature: { state: invalid }\n",
            "inline",
        )
        .unwrap();
        assert_eq!(
            host.file_signature(r"C:\p\a.dll"),
            Err(SourceError::AccessDenied)
        );
    }

    const HOST: &str = r#"
platform: windows
os_build: "26100"
elevated: false
registry:
  'HKLM\SYSTEM\Example':
    Enabled: 1
    Name: "hello"
    Blob:
      content: "eight or more bytes"
    Unwritten: {}
  'HKLM\SYSTEM\Example\Inner':
    Enabled: 0
  'HKLM\SYSTEM\Example\Inner\Deeper':
    Enabled: 0
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

    /// `read_value` hands back each type the fixture can write, and a `{ qword: }` map is neither a
    /// binary value nor a number `read_u32` refuses: a live host's reader accepts a QWORD that fits.
    #[test]
    fn read_value_names_the_type_the_fixture_wrote() {
        let host = FixtureHost::from_yaml_str(
            "platform: windows\nregistry:\n  'HKCU\\Software\\Example':\n    Dword: 0\n    Text: '0'\n    Qword: { qword: 1 }\n    Large: { qword: 4294967296 }\n    Blob: { content: 'x' }\n",
            "inline",
        )
        .unwrap();
        let key = r"HKCU\Software\Example";
        assert_eq!(
            host.read_value(key, "Dword"),
            Ok(Some(RegistryData::Dword(0)))
        );
        assert_eq!(
            host.read_value(key, "Text"),
            Ok(Some(RegistryData::Text("0".to_owned())))
        );
        assert_eq!(
            host.read_value(key, "Qword"),
            Ok(Some(RegistryData::Qword(1)))
        );
        assert_eq!(
            host.read_value(key, "Blob"),
            Ok(Some(RegistryData::OtherType))
        );
        assert_eq!(host.read_value(key, "Absent"), Ok(None));
        assert_eq!(host.read_value(r"HKCU\Software\Absent", "Dword"), Ok(None));
        assert_eq!(host.read_u32(key, "Qword"), Ok(Some(1)));
        assert!(matches!(
            host.read_u32(key, "Large"),
            Err(SourceError::Failed(_))
        ));
        assert!(matches!(
            host.read_bytes(key, "Qword"),
            Err(SourceError::Failed(_))
        ));
        assert!(matches!(
            host.read_string(key, "Qword"),
            Err(SourceError::Failed(_))
        ));
    }

    #[test]
    fn a_denied_key_denies_read_value_too() {
        let host = FixtureHost::from_yaml_str(
            "platform: windows\naccess_denied: ['HKCU\\Software\\Locked']\n",
            "inline",
        )
        .unwrap();
        assert_eq!(
            host.read_value(r"HKCU\Software\Locked", "Anything"),
            Err(SourceError::AccessDenied)
        );
    }

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

    /// Enumeration answers with the spelling the fixture used, not the lower-cased form the lookup
    /// map is keyed by: a collector that emits a value name would otherwise report a path the
    /// machine does not have.
    #[test]
    fn subkeys_and_value_names_are_listed_as_the_fixture_spelled_them() {
        let host = FixtureHost::from_yaml_str(HOST, "inline").unwrap();
        assert_eq!(
            host.subkeys(r"hklm\system\EXAMPLE"),
            Ok(Some(vec!["Inner".to_owned()]))
        );
        assert_eq!(
            host.value_names(r"HKLM\SYSTEM\Example"),
            Ok(Some(vec![
                "Blob".to_owned(),
                "Enabled".to_owned(),
                "Name".to_owned(),
                "Unwritten".to_owned(),
            ]))
        );
    }

    /// Only the keys directly inside, as `list_dir` lists only what is directly inside a directory.
    #[test]
    fn subkeys_never_recurse() {
        let host = FixtureHost::from_yaml_str(HOST, "inline").unwrap();
        assert_eq!(
            host.subkeys(r"HKLM\SYSTEM\Example\Inner"),
            Ok(Some(vec!["Deeper".to_owned()]))
        );
        assert_eq!(
            host.subkeys(r"HKLM\SYSTEM\Example\Inner\Deeper"),
            Ok(Some(vec![]))
        );
    }

    /// The three answers a key can give, and they are three different statements: the key is not
    /// there, the key is there and holds nothing, the key cannot be read.
    #[test]
    fn an_absent_key_is_none_and_an_empty_one_is_an_empty_list() {
        let host = FixtureHost::from_yaml_str(HOST, "inline").unwrap();
        assert_eq!(host.subkeys(r"HKLM\SYSTEM\Absent"), Ok(None));
        assert_eq!(host.value_names(r"HKLM\SYSTEM\Absent"), Ok(None));
        assert_eq!(host.read_bytes(r"HKLM\SYSTEM\Absent", "Anything"), Ok(None));
        assert_eq!(host.read_bytes(r"HKLM\SYSTEM\Example", "Absent"), Ok(None));
        assert_eq!(
            host.subkeys(r"HKLM\SYSTEM\Locked"),
            Err(SourceError::AccessDenied)
        );
        assert_eq!(
            host.value_names(r"HKLM\SYSTEM\Locked"),
            Err(SourceError::AccessDenied)
        );
        assert_eq!(
            host.read_bytes(r"HKLM\SYSTEM\Locked", "Anything"),
            Err(SourceError::AccessDenied)
        );
    }

    /// A key that only has subkeys was never written as a key of its own, and it is there all the
    /// same: a fixture describes a key by writing its values, and this one has none.
    #[test]
    fn a_key_that_only_holds_subkeys_is_there_and_holds_no_value() {
        let host = FixtureHost::from_yaml_str(
            "platform: windows\nregistry:\n  'HKLM\\SYSTEM\\Parent\\Child':\n    Enabled: 1\n",
            "inline",
        )
        .unwrap();
        assert_eq!(
            host.subkeys(r"HKLM\SYSTEM\Parent"),
            Ok(Some(vec!["Child".to_owned()]))
        );
        assert_eq!(host.value_names(r"HKLM\SYSTEM\Parent"), Ok(Some(vec![])));
    }

    #[test]
    fn binary_value_bytes_are_read_and_a_value_without_them_fails() {
        let host = FixtureHost::from_yaml_str(HOST, "inline").unwrap();
        assert_eq!(
            host.read_bytes(r"HKLM\SYSTEM\Example", "blob"),
            Ok(Some(b"eight or more bytes".to_vec()))
        );
        assert!(matches!(
            host.read_bytes(r"HKLM\SYSTEM\Example", "Unwritten"),
            Err(SourceError::Failed(_))
        ));
    }

    /// Asking for the wrong type is a caller's mistake and is reported as one, in both directions,
    /// rather than being converted into something the caller did not ask for.
    #[test]
    fn a_value_of_another_type_is_not_converted() {
        let host = FixtureHost::from_yaml_str(HOST, "inline").unwrap();
        assert!(matches!(
            host.read_bytes(r"HKLM\SYSTEM\Example", "Enabled"),
            Err(SourceError::Failed(_))
        ));
        assert!(matches!(
            host.read_u32(r"HKLM\SYSTEM\Example", "Blob"),
            Err(SourceError::Failed(_))
        ));
        assert!(matches!(
            host.read_string(r"HKLM\SYSTEM\Example", "Blob"),
            Err(SourceError::Failed(_))
        ));
    }

    /// The limit is the host's, so it is applied by the fixture host as well as the live one; a
    /// value of exactly the limit is still read.
    #[test]
    fn a_registry_value_over_the_limit_is_refused() {
        let over = "a".repeat(crate::MAX_REGISTRY_VALUE_BYTES + 1);
        let host = FixtureHost::from_yaml_str(
            &format!(
                "platform: windows\nregistry:\n  'HKLM\\SYSTEM\\Example':\n    Blob:\n      content: \"{over}\"\n"
            ),
            "inline",
        )
        .unwrap();
        assert_eq!(
            host.read_bytes(r"HKLM\SYSTEM\Example", "Blob"),
            Err(SourceError::TooLarge {
                limit: crate::MAX_REGISTRY_VALUE_BYTES
            })
        );
    }

    /// `from:` reaches the artifact corpora for a registry value exactly as it does for a file, and
    /// it is tested against a real one: these bytes are a fuzz seed and a parser fixture.
    #[test]
    fn a_loaded_fixture_resolves_a_registry_from_against_its_own_directory() {
        let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures");
        let host = FixtureHost::load(&fixtures.join("hosts/registry-bytes-present")).unwrap();
        let key = r"HKLM\SYSTEM\CurrentControlSet\Services\fixture\State";

        let on_disk =
            std::fs::read(fixtures.join("parsers/bam/documented-24-byte-value.bin")).unwrap();
        assert_eq!(host.read_bytes(key, "from-disk"), Ok(Some(on_disk)));
        assert_eq!(
            host.read_bytes(key, "inline"),
            Ok(Some(b"hello\n".to_vec()))
        );
        assert!(matches!(
            host.read_bytes(key, "unreadable"),
            Err(SourceError::Failed(_))
        ));
    }

    #[test]
    fn a_registry_value_describing_its_bytes_twice_is_rejected() {
        let error = FixtureHost::from_yaml_str(
            "platform: windows\nregistry:\n  'HKLM\\SYSTEM\\Example':\n    Blob:\n      content: \"a\"\n      from: 'b.bin'\n",
            "inline",
        )
        .unwrap_err();
        assert!(error.to_string().contains("content"), "{error}");
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

    /// `from:` is how a fixture reaches the artifact corpora in `fixtures/`, so it is tested against
    /// a real one: the file is CRLF-terminated, which a read that went through text would change.
    #[test]
    fn a_loaded_fixture_resolves_from_against_its_own_directory() {
        let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures");
        let host = FixtureHost::load(&fixtures.join("hosts/file-content-present")).unwrap();
        let dir = r"C:\ProgramData\fixture";

        let on_disk = std::fs::read(fixtures.join("parsers/pca-app-launch/normal.txt")).unwrap();
        assert_eq!(
            host.read_file(&format!(r"{dir}\from-disk.txt")),
            Ok(Some(on_disk))
        );
        assert_eq!(
            host.read_file(&format!(r"{dir}\inline.txt")),
            Ok(Some(b"hello\n".to_vec()))
        );
        assert!(matches!(
            host.read_file(&format!(r"{dir}\unreadable.bin")),
            Err(SourceError::Failed(_))
        ));
    }

    /// A `from:` that does not resolve is a broken fixture, and it says so when it is loaded rather
    /// than looking like a file whose bytes cannot be read.
    #[test]
    fn a_from_path_that_does_not_exist_fails_at_load() {
        let error = FixtureHost::parse(
            "platform: windows\nfilesystem:\n  'C:\\x':\n    - name: a.txt\n      from: 'no-such-file'\n",
            "inline",
            Some(Path::new(env!("CARGO_MANIFEST_DIR"))),
        )
        .unwrap_err();
        assert!(matches!(error, FixtureError::Io { .. }), "{error}");
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
            host.firmware_secure_boot(),
            Err(SourceError::Unsupported(_))
        ));
        assert!(matches!(
            host.running_processes(),
            Err(SourceError::Unsupported(_))
        ));
        assert!(matches!(
            host.since_boot(),
            Err(SourceError::Unsupported(_))
        ));
    }

    /// A fixture writes what `GetTickCount64` would answer, in its unit, and the host hands it back
    /// unchanged. Zero is an answer — a machine that has only just started — not a missing value.
    #[test]
    fn the_time_since_boot_is_read_from_the_fixture() {
        let host = FixtureHost::from_yaml_str(
            "platform: windows\nmilliseconds_since_boot: 93784005\n",
            "inline",
        )
        .unwrap();
        assert_eq!(
            host.since_boot(),
            Ok(std::time::Duration::from_millis(93_784_005))
        );
        let host =
            FixtureHost::from_yaml_str("platform: windows\nmilliseconds_since_boot: 0\n", "inline")
                .unwrap();
        assert_eq!(host.since_boot(), Ok(std::time::Duration::ZERO));
    }

    /// Three answers, and they are three statements: the attribute is set, it is not, and the
    /// fixture never said. The third must not read as the second (ADR 0037).
    #[test]
    fn the_read_only_attribute_is_what_the_fixture_wrote_and_silence_is_unsupported() {
        let host = FixtureHost::from_yaml_str(
            "platform: windows\nfilesystem:\n  'C:\\p':\n    - name: set.pf\n      read_only: true\n    - name: clear.pf\n      read_only: false\n    - name: silent.pf\n",
            "inline",
        )
        .unwrap();
        assert_eq!(host.is_read_only(r"C:\P\SET.PF"), Ok(Some(true)));
        assert_eq!(host.is_read_only(r"C:\p\clear.pf"), Ok(Some(false)));
        assert!(matches!(
            host.is_read_only(r"C:\p\silent.pf"),
            Err(SourceError::Unsupported(_))
        ));
        assert_eq!(host.is_read_only(r"C:\p\absent.pf"), Ok(None));
    }

    #[test]
    fn a_denied_folder_denies_the_read_only_attribute_too() {
        let host = FixtureHost::from_yaml_str(
            "platform: windows\naccess_denied: ['C:\\p']\nfilesystem:\n  'C:\\p':\n    - name: a.pf\n      read_only: false\n",
            "inline",
        )
        .unwrap();
        assert_eq!(
            host.is_read_only(r"C:\p\a.pf"),
            Err(SourceError::AccessDenied)
        );
    }

    /// A block that does not name a channel describes a service that has none of that name; no
    /// block at all describes nothing, and must not be read as "no such channel" (ADR 0042).
    #[test]
    fn a_channel_is_what_the_fixture_wrote_and_no_block_is_unsupported() {
        let host = FixtureHost::from_yaml_str(
            "platform: windows\naccess_denied: ['Locked/Operational']\nevent_log_channels:\n  Security:\n    log_file_path: '%SystemRoot%\\System32\\Winevt\\Logs\\Security.evtx'\n    max_size_bytes: 20971520\n",
            "inline",
        )
        .unwrap();
        let reader = host.channel_config_reader().unwrap();
        assert_eq!(
            reader.channel_config("security"),
            Ok(Some(ChannelConfig {
                log_file_path: r"%SystemRoot%\System32\Winevt\Logs\Security.evtx".to_owned(),
                max_size_bytes: 20_971_520,
            }))
        );
        assert_eq!(reader.channel_config("No-Such/Channel"), Ok(None));
        assert_eq!(
            reader.channel_config("locked/operational"),
            Err(SourceError::AccessDenied)
        );

        let silent = FixtureHost::from_yaml_str("platform: windows\n", "inline").unwrap();
        assert!(matches!(
            silent.channel_config_reader(),
            Err(SourceError::Unsupported(_))
        ));
        let other = FixtureHost::from_yaml_str("platform: other\n", "inline").unwrap();
        assert!(matches!(
            other.channel_config_reader(),
            Err(SourceError::Unsupported(_))
        ));
    }

    /// A channel either answers or never does, and a fixture that says both, or neither, fails to load.
    #[test]
    fn a_channel_that_never_answers_is_written_alone() {
        let with = |channel: &str| {
            FixtureHost::from_yaml_str(
                &format!("platform: windows\nevent_log_channels:\n  A/B:\n    {channel}\n"),
                "inline",
            )
        };
        assert!(with("never_answers: true").is_ok());
        for refused in [
            "{ never_answers: true, max_size_bytes: 1 }",
            "{ never_answers: false }",
            "{ log_file_path: 'C:\\x.evtx' }",
        ] {
            let yaml = format!("platform: windows\nevent_log_channels:\n  A/B: {refused}\n");
            assert!(
                FixtureHost::from_yaml_str(&yaml, "inline").is_err(),
                "{refused} loaded"
            );
        }
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

    /// Every state a fixture can write reaches the collector as the host reports it: four answers,
    /// and the two ways of not getting one.
    #[test]
    fn firmware_secure_boot_is_read_from_the_fixture() {
        let read = |state: &str| {
            FixtureHost::from_yaml_str(
                &format!("platform: windows\nfirmware:\n  secure_boot: {state}\n"),
                "inline",
            )
            .unwrap()
            .firmware_secure_boot()
        };
        assert_eq!(read("enabled"), Ok(FirmwareSecureBoot::Enabled));
        assert_eq!(read("disabled"), Ok(FirmwareSecureBoot::Disabled));
        assert_eq!(
            read("variable_absent"),
            Ok(FirmwareSecureBoot::VariableAbsent)
        );
        assert_eq!(read("not_uefi"), Ok(FirmwareSecureBoot::NotUefi));
        assert_eq!(read("access_denied"), Err(SourceError::AccessDenied));
        assert!(matches!(read("read_failed"), Err(SourceError::Failed(_))));
    }

    #[test]
    fn unknown_fields_and_states_in_the_firmware_block_are_rejected() {
        for yaml in [
            "platform: windows\nfirmware:\n  secure_boot: enabled\n  bogus: 1\n",
            "platform: windows\nfirmware:\n  secure_boot: on\n",
            "platform: windows\nfirmware: {}\n",
        ] {
            assert!(
                FixtureHost::from_yaml_str(yaml, "inline").is_err(),
                "{yaml}"
            );
        }
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
