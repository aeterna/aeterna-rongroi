// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! Files in the folders `FiveM` loads plugins from, for both of its editions.
//!
//! `FiveM` for GTA V Legacy keeps them under `%LOCALAPPDATA%`; `FiveM` for GTA V Enhanced is a separate
//! install whose user data lives under `%APPDATA%` instead, with an `asi` folder where Legacy has
//! `plugins` (ADR 0035, measured on one Windows 11 machine). That the Enhanced client loads what is in
//! that folder is **not established**: the folder exists and is named for it, and nothing more was
//! found. Its observations carry their own `location` so a reader never mistakes one edition's folder
//! for the other's.
//!
//! Of each folder the collector reports whether it is there and how many files it holds, and of each
//! file its path, its SHA-256 and what Windows says about the signature embedded in it. Nothing about
//! timestamps, size, owner or subfolders (ADR 0009).
//!
//! It also reads **`FiveM.exe` itself**, in each edition's program folder, with the same four facts, so
//! that a rule can ask whether the client carries the signature FiveM is published with (ADR 0036). Of
//! the program folder it reads only the names of its entries, to find that one file; nothing else in
//! it is reported. Legitimate software puts files in the plugin folders too, which is why the rules on
//! them describe a file and its signature and never what the file is (ADR 0036).

use std::collections::BTreeMap;

use rongroi_core::model::{CollectorRun, Observation, UnmeasuredReason};
use rongroi_host::{DirEntryInfo, Host, Platform, SignatureCheck, SourceError};

use crate::{Collector, Field};

/// Environment variable holding the per-user local application data folder.
pub const LOCAL_APP_DATA: &str = "LOCALAPPDATA";
/// Environment variable holding the per-user roaming application data folder.
pub const ROAMING_APP_DATA: &str = "APPDATA";
/// `FiveM`'s plugin folder, relative to `%LOCALAPPDATA%`; confirmed on Windows 11 (ADR 0009).
pub const PLUGINS_RELATIVE_PATH: &str = r"FiveM\FiveM.app\plugins";
/// Value of the `location` field for the Legacy plugin folder.
pub const PLUGINS_LOCATION: &str = "plugins";
/// The Enhanced edition's `asi` folder, relative to `%APPDATA%` (ADR 0035). Present on one measured
/// install; not established to be a folder the client loads from.
pub const ENHANCED_ASI_RELATIVE_PATH: &str = r"FiveM for GTAV Enhanced\gta5enhanced\asi";
/// Value of the `location` field for the Enhanced `asi` folder.
pub const ENHANCED_ASI_LOCATION: &str = "enhanced_asi";
/// FiveM for GTA V Legacy's program folder, relative to `%LOCALAPPDATA%`; `FiveM.exe` is directly
/// inside it. Measured on one Windows 11 machine (ADR 0035, ADR 0036).
pub const LEGACY_PROGRAM_RELATIVE_PATH: &str = "FiveM";
/// FiveM for GTA V Enhanced's program folder, relative to `%LOCALAPPDATA%` — local, although its user
/// data is roaming. Measured on one Windows 11 machine (ADR 0035, ADR 0036).
pub const ENHANCED_PROGRAM_RELATIVE_PATH: &str = "FiveM for GTAV Enhanced";
/// The client executable's file name in both program folders (ADR 0036).
pub const CLIENT_EXE_NAME: &str = "FiveM.exe";
/// Value of the `location` field for Legacy's `FiveM.exe`.
pub const LEGACY_EXE_LOCATION: &str = "legacy_exe";
/// Value of the `location` field for Enhanced's `FiveM.exe`.
pub const ENHANCED_EXE_LOCATION: &str = "enhanced_exe";

const ID: &str = "fivem_dir";

/// What the collector reports of one folder it looks in.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Reads {
    /// A plugin folder: an observation for the folder, and one for every file directly inside it.
    EveryFile,
    /// A program folder: an observation for the one file of this name, when it is there, and nothing
    /// about the folder or anything else in it (ADR 0036).
    OneFile(&'static str),
}

/// One folder this collector looks in.
struct Location {
    /// Value of the `location` field.
    name: &'static str,
    /// The environment variable the folder is relative to.
    base: &'static str,
    /// The folder, relative to that variable.
    relative: &'static str,
    /// What is reported of it.
    reads: Reads,
}

/// Every folder this collector looks in, in the order observations are reported.
const LOCATIONS: [Location; 4] = [
    Location {
        name: PLUGINS_LOCATION,
        base: LOCAL_APP_DATA,
        relative: PLUGINS_RELATIVE_PATH,
        reads: Reads::EveryFile,
    },
    Location {
        name: ENHANCED_ASI_LOCATION,
        base: ROAMING_APP_DATA,
        relative: ENHANCED_ASI_RELATIVE_PATH,
        reads: Reads::EveryFile,
    },
    Location {
        name: LEGACY_EXE_LOCATION,
        base: LOCAL_APP_DATA,
        relative: LEGACY_PROGRAM_RELATIVE_PATH,
        reads: Reads::OneFile(CLIENT_EXE_NAME),
    },
    Location {
        name: ENHANCED_EXE_LOCATION,
        base: LOCAL_APP_DATA,
        relative: ENHANCED_PROGRAM_RELATIVE_PATH,
        reads: Reads::OneFile(CLIENT_EXE_NAME),
    },
];

/// Every reason this collector gives for not having looked (`Collector::unmeasured_reasons`).
///
/// Neither environment variable is set, or listing a folder was denied or failed. An absent folder is
/// not here: that edition is not installed, and the collector did look.
const REASONS: [UnmeasuredReason; 3] = [
    UnmeasuredReason::NotWindows,
    UnmeasuredReason::AccessDenied,
    UnmeasuredReason::ReadFailed,
];

/// Every field this collector can emit. A folder it could not read is a gap in all of them: a rule
/// that matches on any one of them must come out `Unmeasured`, never `NotFound`.
///
/// Two kinds of observation, disjoint by the fields they carry, as `pca`'s are (ADR 0020): **a folder**
/// (`location`, `folder`, and `files` when it was listed) and **a file** (`location`, `path`, and
/// whichever of `sha256`, `signature`, `signer` and `signer_cert_sha256` could be read). A program
/// folder produces only the second kind, for `FiveM.exe` (ADR 0036).
const FIELDS: [Field; 8] = [
    Field::number("files"),
    Field::text("folder"),
    Field::text("location"),
    Field::text("path"),
    Field::text("sha256"),
    Field::text("signature"),
    Field::text("signer"),
    Field::text("signer_cert_sha256"),
];

/// The `folder` value of a folder that is there and was listed.
const FOLDER_LISTED: &str = "listed";
/// The `folder` value of a folder that is not there: that edition is not installed for this user.
const FOLDER_ABSENT: &str = "absent";
/// The `folder` value of a folder that could not be listed; the reason is in the run's `gaps`.
const FOLDER_UNREADABLE: &str = "unreadable";

/// The `fivem_dir` collector.
#[derive(Debug, Default, Clone, Copy)]
pub struct FivemDir;

impl Collector for FivemDir {
    fn id(&self) -> &'static str {
        ID
    }

    fn fields(&self) -> &'static [Field] {
        &FIELDS
    }

    fn unmeasured_reasons(&self) -> &'static [UnmeasuredReason] {
        &REASONS
    }

    fn collect(&self, host: &dyn Host) -> CollectorRun {
        if host.platform() != Platform::Windows {
            return CollectorRun::Unmeasured {
                collector: ID.to_owned(),
                reason: UnmeasuredReason::NotWindows,
            };
        }
        let folders: Vec<(&Location, Option<String>)> = LOCATIONS
            .iter()
            .map(|location| (location, folder_of(host, location)))
            .collect();
        if folders.iter().all(|(_, folder)| folder.is_none()) {
            // With neither variable set there is no folder to look in, so nothing was looked at.
            return CollectorRun::Unmeasured {
                collector: ID.to_owned(),
                reason: UnmeasuredReason::ReadFailed,
            };
        }

        let mut observations = Vec::new();
        // The worst reason any folder gave. `access_denied` outranks `read_failed` because it is the
        // one a rule may declare as expected; a run that met both is not better than its denial.
        let mut unread: Option<UnmeasuredReason> = None;
        for (location, folder) in folders {
            let listing = match folder {
                None => Err(UnmeasuredReason::ReadFailed),
                Some(folder) => match host.list_dir(&folder) {
                    Ok(None) => Ok(None),
                    Ok(Some(entries)) => Ok(Some((folder, entries))),
                    Err(SourceError::AccessDenied) => Err(UnmeasuredReason::AccessDenied),
                    Err(
                        SourceError::Failed(_)
                        | SourceError::Unsupported(_)
                        | SourceError::TooLarge { .. },
                    ) => Err(UnmeasuredReason::ReadFailed),
                },
            };
            match (listing, location.reads) {
                // Not there — this edition is not installed for this user. The collector *did* look.
                (Ok(None), Reads::EveryFile) => {
                    observations.push(folder_observation(location, FOLDER_ABSENT, None));
                }
                (Ok(Some((folder, entries))), Reads::EveryFile) => {
                    let files = file_observations(host, location, &folder, entries);
                    observations.push(folder_observation(
                        location,
                        FOLDER_LISTED,
                        Some(files.len()),
                    ));
                    observations.extend(files);
                }
                // A program folder that is not there, or holds no file of that name, is nothing to
                // report: the plugin folders' own observations already say which editions are
                // installed, and an observation per absent executable would be a second way of saying
                // it that no rule reads (ADR 0036).
                (Ok(None), Reads::OneFile(_)) => {}
                (Ok(Some((folder, entries))), Reads::OneFile(name)) => {
                    let named: Vec<DirEntryInfo> = entries
                        .into_iter()
                        .filter(|entry| entry.name.eq_ignore_ascii_case(name))
                        .collect();
                    observations.extend(file_observations(host, location, &folder, named));
                }
                (Err(reason), reads) => {
                    // A program folder carries no folder observation, so the gap is what says it could
                    // not be read, as it does for every field of the run.
                    if reads == Reads::EveryFile {
                        observations.push(folder_observation(location, FOLDER_UNREADABLE, None));
                    }
                    unread = Some(match (unread, reason) {
                        (Some(UnmeasuredReason::AccessDenied), _) => UnmeasuredReason::AccessDenied,
                        (_, reason) => reason,
                    });
                }
            }
        }
        CollectorRun::Measured {
            collector: ID.to_owned(),
            observations,
            gaps: unread.map(gaps).unwrap_or_default(),
        }
    }
}

fn gaps(reason: UnmeasuredReason) -> BTreeMap<String, UnmeasuredReason> {
    FIELDS
        .iter()
        .map(|field| (field.name.to_owned(), reason))
        .collect()
}

/// The folder for one location, or `None` when its environment variable is not set.
fn folder_of(host: &dyn Host, location: &Location) -> Option<String> {
    let base = host.env_var(location.base)?;
    let base = base.trim_end_matches(['\\', '/']);
    (!base.is_empty()).then(|| format!(r"{base}\{}", location.relative))
}

/// What was seen of one folder as a whole. No path: `location` already says which folder, and a path
/// under a user profile is one more string for SS mode to redact.
fn folder_observation(location: &Location, state: &str, files: Option<usize>) -> Observation {
    let mut fields = BTreeMap::new();
    fields.insert(
        "location".to_owned(),
        serde_json::Value::from(location.name),
    );
    fields.insert("folder".to_owned(), serde_json::Value::from(state));
    if let Some(files) = files {
        fields.insert("files".to_owned(), serde_json::Value::from(files));
    }
    Observation {
        collector: ID.to_owned(),
        fields,
    }
}

fn file_observations(
    host: &dyn Host,
    location: &Location,
    dir: &str,
    entries: Vec<DirEntryInfo>,
) -> Vec<Observation> {
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
            if let Ok(signature) = host.file_signature(&path) {
                insert_signature(&mut fields, signature);
            }
            fields.insert(
                "location".to_owned(),
                serde_json::Value::from(location.name),
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
    lowercase_digest(&host.file_sha256(path).ok()?)
}

/// What Windows said about one file's embedded signature, as fields (ADR 0035).
///
/// A file whose signature could not be checked carries none of them, for the reason a file whose hash
/// could not be read carries no `sha256`. A signer is reported only beside a certificate hash of the
/// shape `allow` compares; a live host that returned anything else reported a signature this program
/// cannot identify, which is not `valid`.
fn insert_signature(fields: &mut BTreeMap<String, serde_json::Value>, signature: SignatureCheck) {
    let state = match signature {
        SignatureCheck::Valid {
            signer,
            signer_cert_sha256,
        } => {
            let Some(cert) = lowercase_digest(&signer_cert_sha256) else {
                return;
            };
            fields.insert("signer".to_owned(), serde_json::Value::from(signer));
            fields.insert(
                "signer_cert_sha256".to_owned(),
                serde_json::Value::from(cert),
            );
            "valid"
        }
        SignatureCheck::NoEmbeddedSignature => "no_embedded_signature",
        SignatureCheck::Invalid => "invalid",
        SignatureCheck::UnverifiableOffline => "unverifiable_offline",
    };
    fields.insert("signature".to_owned(), serde_json::Value::from(state));
}

/// A SHA-256 digest in the one spelling `allow` compares against, or `None` when it is not one.
fn lowercase_digest(digest: &str) -> Option<String> {
    let digest = digest.to_ascii_lowercase();
    (digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())).then_some(digest)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use rongroi_host::{FixtureHost, NonWindowsHost};

    use super::*;

    const PLUGINS_DIR: &str = r"C:\Users\fixtureuser\AppData\Local\FiveM\FiveM.app\plugins";
    const ENHANCED_ASI_DIR: &str =
        r"C:\Users\fixtureuser\AppData\Roaming\FiveM for GTAV Enhanced\gta5enhanced\asi";
    const EMPTY_FILE_HASH: &str =
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    fn fixture(name: &str) -> FixtureHost {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/hosts")
            .join(name);
        FixtureHost::load(&dir).unwrap()
    }

    fn inline(yaml: &str) -> FixtureHost {
        FixtureHost::from_yaml_str(yaml, "inline").unwrap()
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

    /// The file observations of a run, which are the ones carrying a `path`.
    fn files(observations: &[Observation]) -> Vec<&Observation> {
        observations
            .iter()
            .filter(|observation| observation.fields.contains_key("path"))
            .collect()
    }

    /// The folder observation for `location`: its `folder` value and, when listed, its `files` count.
    fn folder(observations: &[Observation], location: &str) -> (String, Option<u64>) {
        let observation = observations
            .iter()
            .find(|observation| {
                field(observation, "location") == Some(location)
                    && observation.fields.contains_key("folder")
            })
            .unwrap_or_else(|| panic!("no folder observation for {location}: {observations:?}"));
        (
            field(observation, "folder").unwrap_or_default().to_owned(),
            observation
                .fields
                .get("files")
                .and_then(serde_json::Value::as_u64),
        )
    }

    fn by_name<'a>(observations: &'a [Observation], name: &str) -> &'a Observation {
        files(observations)
            .into_iter()
            .find(|observation| path_of(observation).ends_with(name))
            .unwrap_or_else(|| panic!("{name} was not observed"))
    }

    #[test]
    fn plugin_file_is_observed() {
        let run = FivemDir.collect(&fixture("fivem-dir-plugin-present"));
        let (observations, gaps) = measured(&run);
        assert!(gaps.is_empty(), "{gaps:?}");
        let observation = by_name(observations, "example-plugin.dll");
        assert_eq!(observation.collector, "fivem_dir");
        assert_eq!(
            path_of(observation),
            format!(r"{PLUGINS_DIR}\example-plugin.dll")
        );
        assert_eq!(field(observation, "location"), Some("plugins"));
        assert_eq!(field(observation, "sha256"), Some(EMPTY_FILE_HASH));
        assert_eq!(
            field(observation, "signature"),
            Some("no_embedded_signature")
        );
        assert_eq!(
            folder(observations, PLUGINS_LOCATION),
            ("listed".to_owned(), Some(2))
        );
    }

    /// Neither edition is installed. Both folders were looked for and are absent, which is two things
    /// seen rather than nothing looked at, and says so for each edition by name.
    #[test]
    fn not_installed_reports_both_folders_absent() {
        let run = FivemDir.collect(&fixture("fivem-dir-not-installed"));
        let (observations, gaps) = measured(&run);
        assert!(gaps.is_empty(), "{gaps:?}");
        assert!(files(observations).is_empty());
        assert_eq!(
            folder(observations, PLUGINS_LOCATION),
            ("absent".to_owned(), None)
        );
        assert_eq!(
            folder(observations, ENHANCED_ASI_LOCATION),
            ("absent".to_owned(), None)
        );
    }

    #[test]
    fn empty_plugins_folder_is_listed_with_no_files() {
        let run = FivemDir.collect(&fixture("fivem-dir-empty-plugins"));
        let (observations, gaps) = measured(&run);
        assert!(gaps.is_empty(), "{gaps:?}");
        assert!(files(observations).is_empty());
        assert_eq!(
            folder(observations, PLUGINS_LOCATION),
            ("listed".to_owned(), Some(0))
        );
    }

    #[test]
    fn access_denied_is_a_gap_and_the_folder_says_it_was_unreadable() {
        let run = FivemDir.collect(&fixture("fivem-dir-access-denied"));
        let (observations, gaps) = measured(&run);
        assert!(files(observations).is_empty());
        assert_eq!(
            folder(observations, PLUGINS_LOCATION),
            ("unreadable".to_owned(), None)
        );
        // Nothing in the folder could be read, so every field a rule might match on is a gap and no
        // rule may read this run as "not found".
        for field in FIELDS {
            let name = field.name;
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
    fn neither_app_data_folder_set_is_unmeasured() {
        assert_eq!(
            FivemDir.collect(&inline("platform: windows\n")),
            CollectorRun::Unmeasured {
                collector: "fivem_dir".to_owned(),
                reason: UnmeasuredReason::ReadFailed,
            }
        );
    }

    /// One variable missing is one folder nobody could look in: a gap, not a quiet absence, and the
    /// other edition's folder is still read.
    #[test]
    fn one_app_data_folder_unset_is_a_gap_and_the_other_is_still_read() {
        let host = inline(
            "platform: windows\nenv:\n  LOCALAPPDATA: 'C:\\Users\\a\\AppData\\Local'\nfilesystem:\n  'C:\\Users\\a\\AppData\\Local\\FiveM\\FiveM.app\\plugins':\n    - name: x.dll\n",
        );
        let run = FivemDir.collect(&host);
        let (observations, gaps) = measured(&run);
        assert_eq!(gaps.get("path"), Some(&UnmeasuredReason::ReadFailed));
        assert_eq!(
            folder(observations, PLUGINS_LOCATION),
            ("listed".to_owned(), Some(1))
        );
        assert_eq!(
            folder(observations, ENHANCED_ASI_LOCATION),
            ("unreadable".to_owned(), None)
        );
    }

    /// A denial outranks a failed read in `gaps`, because it is the reason a rule may declare.
    #[test]
    fn a_denied_folder_and_an_unset_variable_report_the_denial() {
        let host = inline(
            "platform: windows\nenv:\n  LOCALAPPDATA: 'C:\\Users\\a\\AppData\\Local'\naccess_denied:\n  - 'C:\\Users\\a\\AppData\\Local\\FiveM\\FiveM.app\\plugins'\n",
        );
        let run = FivemDir.collect(&host);
        let (_, gaps) = measured(&run);
        assert_eq!(gaps.get("sha256"), Some(&UnmeasuredReason::AccessDenied));
    }

    #[test]
    fn the_enhanced_asi_folder_is_read_under_its_own_location_and_mods_is_not() {
        let run = FivemDir.collect(&fixture("fivem-dir-enhanced-asi"));
        let (observations, gaps) = measured(&run);
        assert!(gaps.is_empty(), "{gaps:?}");
        let paths: Vec<&str> = files(observations).into_iter().map(path_of).collect();
        assert_eq!(paths, [format!(r"{ENHANCED_ASI_DIR}\example.asi")]);
        let observation = by_name(observations, "example.asi");
        assert_eq!(field(observation, "location"), Some("enhanced_asi"));
        assert_eq!(field(observation, "sha256"), Some(EMPTY_FILE_HASH));
        assert_eq!(
            folder(observations, PLUGINS_LOCATION),
            ("absent".to_owned(), None)
        );
        assert_eq!(
            folder(observations, ENHANCED_ASI_LOCATION),
            ("listed".to_owned(), Some(1))
        );
    }

    #[test]
    fn each_signature_answer_becomes_its_own_value_and_only_valid_names_a_signer() {
        let run = FivemDir.collect(&fixture("fivem-dir-signatures"));
        let (observations, _) = measured(&run);
        let signed = by_name(observations, "signed.dll");
        assert_eq!(field(signed, "signature"), Some("valid"));
        assert_eq!(field(signed, "signer"), Some("Example Signer"));
        assert_eq!(
            field(signed, "signer_cert_sha256"),
            Some("a".repeat(64).as_str()),
            "the certificate hash is lowercased, as `allow` compares it"
        );
        for (name, state) in [
            ("tampered.dll", "invalid"),
            ("unsigned.asi", "no_embedded_signature"),
            ("unchained.dll", "unverifiable_offline"),
        ] {
            let observation = by_name(observations, name);
            assert_eq!(field(observation, "signature"), Some(state), "{name}");
            assert_eq!(observation.fields.get("signer"), None, "{name}");
            assert_eq!(observation.fields.get("signer_cert_sha256"), None, "{name}");
        }
    }

    #[test]
    fn a_file_that_cannot_be_hashed_or_checked_keeps_its_path_and_is_not_a_gap() {
        let run = FivemDir.collect(&fixture("fivem-dir-plugin-present"));
        let (observations, gaps) = measured(&run);
        let observation = by_name(observations, "unreadable-plugin.dll");
        assert_eq!(observation.fields.get("sha256"), None);
        assert_eq!(observation.fields.get("signature"), None);
        assert_eq!(field(observation, "location"), Some("plugins"));
        // One file that cannot be read is not a gap: `gaps` is about the whole run.
        assert!(gaps.is_empty(), "{gaps:?}");
    }

    /// A signer beside a certificate hash `allow` could never compare is not a signature this program
    /// can identify, so none of the three fields is emitted.
    #[test]
    fn a_valid_signature_with_a_malformed_certificate_hash_emits_nothing() {
        let mut fields = BTreeMap::new();
        insert_signature(
            &mut fields,
            SignatureCheck::Valid {
                signer: "Example Signer".to_owned(),
                signer_cert_sha256: "not a digest".to_owned(),
            },
        );
        assert!(fields.is_empty(), "{fields:?}");
    }

    /// Each edition's `FiveM.exe` is one file observation under its own `location`, with the same four
    /// facts a plugin file has. Nothing else in a program folder is reported, and a program folder has
    /// no folder observation (ADR 0036).
    #[test]
    fn each_editions_executable_is_observed_and_nothing_else_in_its_program_folder() {
        let run = FivemDir.collect(&fixture("fivem-dir-client-exe"));
        let (observations, gaps) = measured(&run);
        assert!(gaps.is_empty(), "{gaps:?}");
        let paths: Vec<&str> = files(observations).into_iter().map(path_of).collect();
        assert_eq!(
            paths,
            [
                r"C:\Users\fixtureuser\AppData\Local\FiveM\fivem.exe",
                r"C:\Users\fixtureuser\AppData\Local\FiveM for GTAV Enhanced\FiveM.exe",
            ]
        );
        let legacy = by_name(observations, r"\fivem.exe");
        assert_eq!(field(legacy, "location"), Some(LEGACY_EXE_LOCATION));
        assert_eq!(field(legacy, "signature"), Some("valid"));
        assert_eq!(field(legacy, "signer"), Some("Example Signer"));
        assert_eq!(
            field(legacy, "signer_cert_sha256"),
            Some("b".repeat(64).as_str())
        );
        assert_eq!(field(legacy, "sha256"), Some("5".repeat(64).as_str()));
        let enhanced = by_name(observations, r"Enhanced\FiveM.exe");
        assert_eq!(field(enhanced, "location"), Some(ENHANCED_EXE_LOCATION));
        assert_eq!(field(enhanced, "signature"), Some("no_embedded_signature"));
        let locations: Vec<&str> = observations
            .iter()
            .filter(|observation| observation.fields.contains_key("folder"))
            .filter_map(|observation| field(observation, "location"))
            .collect();
        assert_eq!(locations, [PLUGINS_LOCATION, ENHANCED_ASI_LOCATION]);
    }

    /// No program folder, or one without `FiveM.exe`, reports nothing: the plugin folders' own
    /// observations say whether an edition is installed.
    #[test]
    fn an_absent_executable_is_no_observation_and_no_gap() {
        let host = inline(
            "platform: windows\nenv:\n  LOCALAPPDATA: 'C:\\Users\\a\\AppData\\Local'\n  APPDATA: 'C:\\Users\\a\\AppData\\Roaming'\nfilesystem:\n  'C:\\Users\\a\\AppData\\Local\\FiveM':\n    - name: FiveM.exe.old\n    - name: FiveM.exe\n      directory: true\n",
        );
        let run = FivemDir.collect(&host);
        let (observations, gaps) = measured(&run);
        assert!(gaps.is_empty(), "{gaps:?}");
        assert!(files(observations).is_empty(), "{observations:?}");
    }

    /// A program folder that cannot be listed is a gap in every field, like a plugin folder that cannot
    /// be: whether `FiveM.exe` is there was never answered, so no rule may read it as absent.
    #[test]
    fn an_unreadable_program_folder_is_a_gap() {
        let run = FivemDir.collect(&fixture("fivem-dir-client-folder-denied"));
        let (observations, gaps) = measured(&run);
        assert!(files(observations).is_empty());
        assert_eq!(gaps.get("signature"), Some(&UnmeasuredReason::AccessDenied));
        assert_eq!(gaps.get("path"), Some(&UnmeasuredReason::AccessDenied));
        assert_eq!(
            folder(observations, PLUGINS_LOCATION),
            ("listed".to_owned(), Some(0))
        );
    }

    #[test]
    fn subdirectories_are_not_observed() {
        let run = FivemDir.collect(&fixture("fivem-dir-plugin-present"));
        let (observations, _) = measured(&run);
        let paths: Vec<&str> = files(observations).into_iter().map(path_of).collect();
        assert_eq!(
            paths,
            [
                format!(r"{PLUGINS_DIR}\example-plugin.dll"),
                format!(r"{PLUGINS_DIR}\unreadable-plugin.dll"),
            ]
        );
    }
}
