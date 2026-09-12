// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! Files that sit in `FiveM`'s own plugin folder, which `FiveM` loads at start-up.
//!
//! The collector reports what is in the folder and nothing about it: no timestamps, no size, no
//! recursion, no owner (ADR 0009). Legitimate software puts files here too, which is why no rule reads
//! this collector yet — the observations are shown in Self mode and read by a person.

use std::collections::BTreeMap;

use rongroi_core::model::{CollectorRun, Observation, UnmeasuredReason};
use rongroi_host::{DirEntryInfo, Host, Platform, SourceError};

use crate::Collector;

/// Environment variable holding the per-user local application data folder.
pub const LOCAL_APP_DATA: &str = "LOCALAPPDATA";
/// `FiveM`'s plugin folder, relative to `%LOCALAPPDATA%`; confirmed on Windows 11 (ADR 0009).
pub const PLUGINS_RELATIVE_PATH: &str = r"FiveM\FiveM.app\plugins";
/// Value of the `location` field for a file seen in the plugin folder.
pub const PLUGINS_LOCATION: &str = "plugins";

const ID: &str = "fivem_dir";

/// Every field this collector can emit. A folder it could not read is a gap in all of them: a rule
/// that matches on any one of them must come out `Unmeasured`, never `NotFound`.
const FIELDS: [&str; 3] = ["location", "path", "sha256"];

/// The `fivem_dir` collector.
#[derive(Debug, Default, Clone, Copy)]
pub struct FivemDir;

impl Collector for FivemDir {
    fn id(&self) -> &'static str {
        ID
    }

    fn fields(&self) -> &'static [&'static str] {
        &FIELDS
    }

    fn collect(&self, host: &dyn Host) -> CollectorRun {
        if host.platform() != Platform::Windows {
            return CollectorRun::Unmeasured {
                collector: ID.to_owned(),
                reason: UnmeasuredReason::NotWindows,
            };
        }
        let Some(dir) = plugins_dir(host) else {
            // Without `%LOCALAPPDATA%` there is no folder to look in, so nothing was looked at.
            return CollectorRun::Unmeasured {
                collector: ID.to_owned(),
                reason: UnmeasuredReason::ReadFailed,
            };
        };

        match host.list_dir(&dir) {
            // The folder is not there — FiveM is not installed for this user. The collector *did*
            // look, so this is `Measured` with nothing in it, which the engine reads as `NotFound`.
            Ok(None) => measured(Vec::new(), BTreeMap::new()),
            Ok(Some(entries)) => measured(observations(host, &dir, entries), BTreeMap::new()),
            Err(SourceError::AccessDenied) => {
                measured(Vec::new(), gaps(UnmeasuredReason::AccessDenied))
            }
            Err(
                SourceError::Failed(_) | SourceError::Unsupported(_) | SourceError::TooLarge { .. },
            ) => measured(Vec::new(), gaps(UnmeasuredReason::ReadFailed)),
        }
    }
}

fn measured(
    observations: Vec<Observation>,
    gaps: BTreeMap<String, UnmeasuredReason>,
) -> CollectorRun {
    CollectorRun::Measured {
        collector: ID.to_owned(),
        observations,
        gaps,
    }
}

fn gaps(reason: UnmeasuredReason) -> BTreeMap<String, UnmeasuredReason> {
    FIELDS
        .iter()
        .map(|field| ((*field).to_owned(), reason))
        .collect()
}

fn plugins_dir(host: &dyn Host) -> Option<String> {
    let local = host.env_var(LOCAL_APP_DATA)?;
    let local = local.trim_end_matches(['\\', '/']);
    (!local.is_empty()).then(|| format!(r"{local}\{PLUGINS_RELATIVE_PATH}"))
}

fn observations(host: &dyn Host, dir: &str, entries: Vec<DirEntryInfo>) -> Vec<Observation> {
    let mut files: Vec<DirEntryInfo> = entries.into_iter().filter(|entry| entry.is_file).collect();
    // A directory listing has no defined order; sorting keeps two reads of the same folder comparable.
    files.sort_by(|left, right| left.name.cmp(&right.name));
    files
        .into_iter()
        .map(|entry| {
            let path = format!(r"{dir}\{}", entry.name);
            let mut fields = BTreeMap::new();
            if let Some(sha256) = file_sha256(host, &path) {
                fields.insert("sha256".to_owned(), serde_json::Value::from(sha256));
            }
            fields.insert(
                "location".to_owned(),
                serde_json::Value::from(PLUGINS_LOCATION),
            );
            fields.insert("path".to_owned(), serde_json::Value::from(path));
            Observation {
                collector: ID.to_owned(),
                fields,
            }
        })
        .collect()
}

/// The hash of one file, or `None` when that one file could not be hashed.
///
/// The file is still reported with its path. `gaps` describes the whole run, so a single unreadable
/// file must not land there, and a fabricated hash is never an option.
fn file_sha256(host: &dyn Host, path: &str) -> Option<String> {
    let digest = host.file_sha256(path).ok()?.to_ascii_lowercase();
    // A rule's `allow` compares this field literally (rongroi-core's engine), so only a digest of the
    // expected shape may be emitted.
    (digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())).then_some(digest)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use rongroi_host::{FixtureHost, NonWindowsHost};

    use super::*;

    const PLUGINS_DIR: &str = r"C:\Users\fixtureuser\AppData\Local\FiveM\FiveM.app\plugins";
    const EMPTY_FILE_HASH: &str =
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    fn fixture(name: &str) -> FixtureHost {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/hosts")
            .join(name);
        FixtureHost::load(&dir).unwrap()
    }

    fn measured(run: &CollectorRun) -> (&[Observation], &BTreeMap<String, UnmeasuredReason>) {
        match run {
            CollectorRun::Measured {
                observations, gaps, ..
            } => (observations, gaps),
            CollectorRun::Unmeasured { .. } => panic!("expected a measured run, got {run:?}"),
        }
    }

    fn field<'a>(observation: &'a Observation, name: &str) -> Option<&'a str> {
        observation
            .fields
            .get(name)
            .and_then(serde_json::Value::as_str)
    }

    fn path_of(observation: &Observation) -> &str {
        field(observation, "path").unwrap_or_default()
    }

    #[test]
    fn plugin_file_is_observed() {
        let run = FivemDir.collect(&fixture("fivem-dir-plugin-present"));
        let (observations, gaps) = measured(&run);
        assert!(gaps.is_empty(), "{gaps:?}");
        let observation = &observations[0];
        assert_eq!(observation.collector, "fivem_dir");
        assert_eq!(
            path_of(observation),
            format!(r"{PLUGINS_DIR}\example-plugin.dll")
        );
        assert_eq!(field(observation, "location"), Some("plugins"));
        assert_eq!(field(observation, "sha256"), Some(EMPTY_FILE_HASH));
    }

    #[test]
    fn not_installed_is_measured_with_no_observations() {
        // The folder is absent, so the collector looked and saw nothing. `Measured` with no
        // observations is what the engine turns into `NotFound`; `Unmeasured` would claim the
        // collector could not look, which is not what happened.
        assert_eq!(
            FivemDir.collect(&fixture("fivem-dir-not-installed")),
            CollectorRun::Measured {
                collector: "fivem_dir".to_owned(),
                observations: vec![],
                gaps: BTreeMap::new(),
            }
        );
    }

    #[test]
    fn empty_plugins_folder_is_measured_empty() {
        assert_eq!(
            FivemDir.collect(&fixture("fivem-dir-empty-plugins")),
            CollectorRun::Measured {
                collector: "fivem_dir".to_owned(),
                observations: vec![],
                gaps: BTreeMap::new(),
            }
        );
    }

    #[test]
    fn access_denied_is_a_gap() {
        let run = FivemDir.collect(&fixture("fivem-dir-access-denied"));
        let (observations, gaps) = measured(&run);
        assert!(observations.is_empty());
        // Nothing in the folder could be read, so every field a rule might match on is a gap and no
        // rule may read this run as "not found".
        for name in FIELDS {
            assert_eq!(
                gaps.get(name),
                Some(&UnmeasuredReason::AccessDenied),
                "{name}"
            );
        }
    }

    #[test]
    fn non_windows_is_unmeasured() {
        assert_eq!(
            FivemDir.collect(&NonWindowsHost),
            CollectorRun::Unmeasured {
                collector: "fivem_dir".to_owned(),
                reason: UnmeasuredReason::NotWindows,
            }
        );
    }

    #[test]
    fn localappdata_unset_is_unmeasured() {
        let host = FixtureHost::from_yaml_str("platform: windows\n", "inline").unwrap();
        assert_eq!(
            FivemDir.collect(&host),
            CollectorRun::Unmeasured {
                collector: "fivem_dir".to_owned(),
                reason: UnmeasuredReason::ReadFailed,
            }
        );
    }

    #[test]
    fn missing_hash_omits_the_sha256_field_but_keeps_path() {
        let run = FivemDir.collect(&fixture("fivem-dir-plugin-present"));
        let (observations, gaps) = measured(&run);
        let observation = observations
            .iter()
            .find(|observation| path_of(observation).ends_with("unreadable-plugin.dll"))
            .expect("the file itself is still observed");
        assert_eq!(observation.fields.get("sha256"), None);
        assert_eq!(field(observation, "location"), Some("plugins"));
        // One file whose hash cannot be read is not a gap: `gaps` is about the whole run.
        assert!(gaps.is_empty(), "{gaps:?}");
    }

    #[test]
    fn subdirectories_are_not_observed() {
        let run = FivemDir.collect(&fixture("fivem-dir-plugin-present"));
        let (observations, _) = measured(&run);
        let paths: Vec<&str> = observations.iter().map(path_of).collect();
        assert_eq!(
            paths,
            [
                format!(r"{PLUGINS_DIR}\example-plugin.dll"),
                format!(r"{PLUGINS_DIR}\unreadable-plugin.dll"),
            ]
        );
    }
}
