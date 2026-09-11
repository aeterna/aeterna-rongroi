// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! A fake machine described in `fixtures/hosts/<name>/host.yaml`. See `fixtures/hosts/PROVENANCE.md`.

use std::collections::BTreeMap;
use std::path::Path;

use serde::Deserialize;

use crate::{Host, Platform, RegistrySource, SourceError};

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
    access_denied: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum RegistryValue {
    Dword(u32),
    Text(String),
}

/// A fake machine for tests. Registry keys and value names are case-insensitive, like Windows.
#[derive(Debug, Clone)]
pub struct FixtureHost {
    platform: Platform,
    os_build: Option<String>,
    elevated: Option<bool>,
    registry: BTreeMap<String, BTreeMap<String, RegistryValue>>,
    access_denied: Vec<String>,
}

impl FixtureHost {
    /// Loads `<dir>/host.yaml`.
    pub fn load(dir: &Path) -> Result<Self, FixtureError> {
        let path = dir.join("host.yaml");
        let text = std::fs::read_to_string(&path).map_err(|source| FixtureError::Io {
            path: path.display().to_string(),
            source,
        })?;
        Self::from_yaml_str(&text, &path.display().to_string())
    }

    /// Parses a fixture host from YAML; `origin` is used in error messages.
    pub fn from_yaml_str(yaml: &str, origin: &str) -> Result<Self, FixtureError> {
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
        Ok(Self {
            platform: file.platform,
            os_build: file.os_build,
            elevated: file.elevated,
            registry,
            access_denied: file
                .access_denied
                .iter()
                .map(|key| key.to_ascii_lowercase())
                .collect(),
        })
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
access_denied:
  - 'HKLM\SYSTEM\Locked'
"#;

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
    }
}
