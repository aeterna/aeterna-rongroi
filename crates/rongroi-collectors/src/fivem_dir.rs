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
//! Of each plugin folder the collector reports whether it is there and how many files it holds, and of
//! each file its path, its SHA-256 and what Windows says about the signature embedded in it. Nothing
//! about timestamps, size, owner or subfolders there (ADR 0009).
//!
//! It also reads **`FiveM.exe` itself**, in each edition's program folder, with the same four facts, so
//! that a rule can ask whether the client carries the signature `FiveM` is published with (ADR 0036). Of
//! the program folder it reads only the names of its entries, to find that one file; nothing else in
//! it is reported. Legitimate software puts files in the plugin folders too, which is why the rules on
//! them describe a file and its signature and never what the file is (ADR 0036).
//!
//! And it reports **`FiveM`'s log, crash and cache folders** in both editions as *folder activity*: how
//! many files and subfolders the listing holds, the files' total size, the earliest and latest of their
//! creation and last-write times, and the folder's own times — never a file name, and no file is opened
//! (ADR 0050, ADR 0053). Of each Enhanced per-server cache folder it reports when it was created and
//! last changed and how many entries it holds, and not its name, which identifies a server (ADR 0053).
//! These times are what the file system recorded; programs set them as they copy and extract files,
//! and a small or recent folder is also what a new install or a cleared cache leaves.

use std::collections::BTreeMap;

use jiff::Timestamp;
use rongroi_core::model::{CollectorRun, DiscriminatorGaps, Observation, UnmeasuredReason};
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
/// `FiveM` for GTA V Legacy's program folder, relative to `%LOCALAPPDATA%`; `FiveM.exe` is directly
/// inside it. Measured on one Windows 11 machine (ADR 0035, ADR 0036).
pub const LEGACY_PROGRAM_RELATIVE_PATH: &str = "FiveM";
/// `FiveM` for GTA V Enhanced's program folder, relative to `%LOCALAPPDATA%` — local, although its user
/// data is roaming. Measured on one Windows 11 machine (ADR 0035, ADR 0036).
pub const ENHANCED_PROGRAM_RELATIVE_PATH: &str = "FiveM for GTAV Enhanced";
/// The client executable's file name in both program folders (ADR 0036).
pub const CLIENT_EXE_NAME: &str = "FiveM.exe";
/// Value of the `location` field for Legacy's `FiveM.exe`.
pub const LEGACY_EXE_LOCATION: &str = "legacy_exe";
/// Value of the `location` field for Enhanced's `FiveM.exe`.
pub const ENHANCED_EXE_LOCATION: &str = "enhanced_exe";

// FiveM's own log, crash and cache folders (ADR 0053), measured on one Windows 11 machine. The Legacy
// cache names also appear in FiveM's public source; the Enhanced client's source is not public.

/// Value of the `location` field for Legacy's log folder, `%LOCALAPPDATA%\FiveM\FiveM.app\logs`.
pub const LEGACY_LOGS_LOCATION: &str = "legacy_logs";
/// Value of the `location` field for Legacy's crash folder.
pub const LEGACY_CRASHES_LOCATION: &str = "legacy_crashes";
/// Value of the `location` field for Legacy's `data\cache` folder.
pub const LEGACY_CACHE_LOCATION: &str = "legacy_cache";
/// Value of the `location` field for Legacy's resource caches, one per launch mode (`variant`).
pub const LEGACY_SERVER_CACHE_LOCATION: &str = "legacy_server_cache";
/// Value of the `location` field for Enhanced's log folder, `%APPDATA%\FiveM for GTAV Enhanced\logs`.
pub const ENHANCED_LOGS_LOCATION: &str = "enhanced_logs";
/// Value of the `location` field for Enhanced's game crash folder.
pub const ENHANCED_CRASHES_LOCATION: &str = "enhanced_crashes";
/// Value of the `location` field for Enhanced's launcher crash folder.
pub const ENHANCED_LAUNCHER_CRASHES_LOCATION: &str = "enhanced_launcher_crashes";
/// Value of the `location` field for Enhanced's per-server cache folder,
/// `%LOCALAPPDATA%\FiveM for GTAV Enhanced\servercache`, and for each server folder inside it.
pub const ENHANCED_SERVER_CACHE_LOCATION: &str = "enhanced_server_cache";

const ID: &str = "fivem_dir";

/// The field that says which place an observation is about: every observation carries it, and a place
/// that could not be read is a gap for the observations carrying its value only (ADR 0044).
const DISCRIMINATOR: &str = "location";

/// What the collector reports of one folder it looks in.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Reads {
    /// A plugin folder: an observation for the folder, and one for every file directly inside it.
    EveryFile,
    /// A program folder: an observation for the one file of this name, when it is there, and nothing
    /// about the folder or anything else in it (ADR 0036).
    OneFile(&'static str),
    /// A log, crash or cache folder: one folder-activity observation, and nothing about any file by
    /// name (ADR 0053).
    FolderActivity,
    /// Enhanced's server cache: folder activity, and one observation per server folder inside it with
    /// its times and entry count, never its name (ADR 0053).
    FolderActivityAndServers,
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
    /// `FiveM`'s launch-mode suffix, for the places that exist once per mode (ADR 0053). A place with a
    /// variant that is not there is not reported: most machines hold only the default one.
    variant: Option<&'static str>,
}

/// Every folder this collector looks in, in the order observations are reported.
const LOCATIONS: [Location; 14] = [
    Location {
        name: PLUGINS_LOCATION,
        base: LOCAL_APP_DATA,
        relative: PLUGINS_RELATIVE_PATH,
        reads: Reads::EveryFile,
        variant: None,
    },
    Location {
        name: ENHANCED_ASI_LOCATION,
        base: ROAMING_APP_DATA,
        relative: ENHANCED_ASI_RELATIVE_PATH,
        reads: Reads::EveryFile,
        variant: None,
    },
    Location {
        name: LEGACY_EXE_LOCATION,
        base: LOCAL_APP_DATA,
        relative: LEGACY_PROGRAM_RELATIVE_PATH,
        reads: Reads::OneFile(CLIENT_EXE_NAME),
        variant: None,
    },
    Location {
        name: ENHANCED_EXE_LOCATION,
        base: LOCAL_APP_DATA,
        relative: ENHANCED_PROGRAM_RELATIVE_PATH,
        reads: Reads::OneFile(CLIENT_EXE_NAME),
        variant: None,
    },
    Location {
        name: LEGACY_LOGS_LOCATION,
        base: LOCAL_APP_DATA,
        relative: r"FiveM\FiveM.app\logs",
        reads: Reads::FolderActivity,
        variant: None,
    },
    Location {
        name: LEGACY_CRASHES_LOCATION,
        base: LOCAL_APP_DATA,
        relative: r"FiveM\FiveM.app\crashes",
        reads: Reads::FolderActivity,
        variant: None,
    },
    Location {
        name: LEGACY_CACHE_LOCATION,
        base: LOCAL_APP_DATA,
        relative: r"FiveM\FiveM.app\data\cache",
        reads: Reads::FolderActivity,
        variant: None,
    },
    Location {
        name: LEGACY_SERVER_CACHE_LOCATION,
        base: LOCAL_APP_DATA,
        relative: r"FiveM\FiveM.app\data\server-cache",
        reads: Reads::FolderActivity,
        variant: Some("default"),
    },
    Location {
        name: LEGACY_SERVER_CACHE_LOCATION,
        base: LOCAL_APP_DATA,
        relative: r"FiveM\FiveM.app\data\server-cache-priv",
        reads: Reads::FolderActivity,
        variant: Some("priv"),
    },
    Location {
        name: LEGACY_SERVER_CACHE_LOCATION,
        base: LOCAL_APP_DATA,
        relative: r"FiveM\FiveM.app\data\server-cache-fxdk",
        reads: Reads::FolderActivity,
        variant: Some("fxdk"),
    },
    Location {
        name: ENHANCED_LOGS_LOCATION,
        base: ROAMING_APP_DATA,
        relative: r"FiveM for GTAV Enhanced\logs",
        reads: Reads::FolderActivity,
        variant: None,
    },
    Location {
        name: ENHANCED_CRASHES_LOCATION,
        base: ROAMING_APP_DATA,
        relative: r"FiveM for GTAV Enhanced\gta5enhanced\crashes",
        reads: Reads::FolderActivity,
        variant: None,
    },
    Location {
        name: ENHANCED_LAUNCHER_CRASHES_LOCATION,
        base: ROAMING_APP_DATA,
        relative: r"FiveM for GTAV Enhanced\launcher_crashes",
        reads: Reads::FolderActivity,
        variant: None,
    },
    Location {
        name: ENHANCED_SERVER_CACHE_LOCATION,
        base: LOCAL_APP_DATA,
        relative: r"FiveM for GTAV Enhanced\servercache",
        reads: Reads::FolderActivityAndServers,
        variant: None,
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

/// Every field this collector can emit. A folder it could not read is a gap in all of them, for the
/// observations about that folder (ADR 0044): a rule that could match there and matches on any one of
/// them must come out `Unmeasured`, never `NotFound`.
///
/// Three kinds of observation, disjoint by the fields they carry, as `pca`'s are (ADR 0020):
///
/// - **a folder** (`location`, `folder`, `variant` for a place that has one, and — when it was listed —
///   `files`; a log, crash or cache folder also carries its folder activity: `folders`, `size_bytes`,
///   `files_without_times`, the four `earliest_*`/`latest_*` bounds and its own `created_at` and
///   `modified_at`, each only when the listing provided it);
/// - **a file** (`location`, `path`, and whichever of `sha256`, `signature`, `signer` and
///   `signer_cert_sha256` could be read). A program folder produces only this kind, for `FiveM.exe`
///   (ADR 0036);
/// - **a server cache folder** (`location: enhanced_server_cache`, `created_at`, `modified_at` and
///   `entries`, each when it could be read) — told apart from its parent's folder observation by having
///   no `folder` field (ADR 0053).
const FIELDS: [Field; 19] = [
    Field::timestamp("created_at"),
    Field::timestamp("earliest_created_at"),
    Field::timestamp("earliest_modified_at"),
    Field::number("entries"),
    Field::number("files"),
    Field::number("files_without_times"),
    Field::text("folder"),
    Field::number("folders"),
    Field::timestamp("latest_created_at"),
    Field::timestamp("latest_modified_at"),
    Field::text("location"),
    Field::timestamp("modified_at"),
    Field::text("path"),
    Field::text("sha256"),
    Field::text("signature"),
    Field::text("signer"),
    Field::text("signer_cert_sha256"),
    Field::number("size_bytes"),
    Field::text("variant"),
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

    fn discriminator(&self) -> Option<&'static str> {
        Some(DISCRIMINATOR)
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
        // Every place that could not be read, with its reason, in the order `LOCATIONS` lists them.
        let mut unread: Vec<(&Location, UnmeasuredReason)> = Vec::new();
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
                // A launch-mode cache that is not there is the ordinary case for all but one mode, so it
                // is not reported; a place with no variant says it is absent, as a plugin folder does.
                (Ok(None), Reads::FolderActivity | Reads::FolderActivityAndServers) => {
                    if location.variant.is_none() {
                        observations.push(folder_observation(location, FOLDER_ABSENT, None));
                    }
                }
                (Ok(Some((folder, entries))), Reads::FolderActivity) => {
                    observations.push(activity_observation(host, location, &folder, &entries));
                }
                (Ok(Some((folder, entries))), Reads::FolderActivityAndServers) => {
                    observations.push(activity_observation(host, location, &folder, &entries));
                    observations.extend(server_observations(host, location, &folder, &entries));
                }
                (Err(reason), reads) => {
                    // A program folder carries no folder observation, so the gap is what says it could
                    // not be read.
                    if !matches!(reads, Reads::OneFile(_)) {
                        observations.push(folder_observation(location, FOLDER_UNREADABLE, None));
                    }
                    unread.push((location, reason));
                }
            }
        }
        let (gaps, discriminator_gaps) = unread_gaps(unread);
        CollectorRun::Measured {
            collector: ID.to_owned(),
            observations,
            gaps,
            discriminator_gaps,
        }
    }
}

/// The gaps of a run, from the places that could not be read.
///
/// **Some places read, some not:** each unread place is a gap in every field for the observations
/// about that place only — `location` is the discriminator — so a rule whose `match` rules that place
/// out keeps the answer the places that were read give it (ADR 0044). Until ADR 0044 this was a gap
/// in every field for the whole run, and an unreadable Enhanced program folder made the Legacy plugin
/// rules `unmeasured` although that folder was read (ADR 0036).
///
/// **No place read:** a gap in every field for the whole run, as before. Nothing was read, so there
/// is no answer from any place for a discriminator to keep apart, and a rule naming a `location` this
/// collector never emits stays `unmeasured` rather than becoming `not_found`.
///
/// `access_denied` is listed before `read_failed`, and wins the run-wide reason, because it is the
/// reason a rule may declare as expected; a run that met both is not better than its denial
/// (ADR 0035). The engine takes the first place that reaches a rule, so the order is the ranking.
fn unread_gaps(
    unread: Vec<(&Location, UnmeasuredReason)>,
) -> (BTreeMap<String, UnmeasuredReason>, Vec<DiscriminatorGaps>) {
    let denied_first = |reason: &UnmeasuredReason| *reason != UnmeasuredReason::AccessDenied;
    if unread.len() == LOCATIONS.len() {
        let worst = unread
            .iter()
            .map(|(_, reason)| *reason)
            .min_by_key(denied_first)
            .map(gaps)
            .unwrap_or_default();
        return (worst, Vec::new());
    }
    let mut places: Vec<DiscriminatorGaps> = unread
        .into_iter()
        .map(|(location, reason)| DiscriminatorGaps {
            discriminator: DISCRIMINATOR.to_owned(),
            value: serde_json::Value::from(location.name),
            gaps: gaps(reason),
        })
        .collect();
    // Stable, so places with the same reason keep the order `LOCATIONS` lists them in.
    places.sort_by_key(|place| place.gaps.values().any(denied_first));
    (BTreeMap::new(), places)
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
    if let Some(variant) = location.variant {
        fields.insert("variant".to_owned(), serde_json::Value::from(variant));
    }
    Observation {
        collector: ID.to_owned(),
        fields,
    }
}

/// A timestamp as the report writes every time: RFC 3339 in UTC.
fn time_value(time: Timestamp) -> serde_json::Value {
    serde_json::Value::from(time.to_string())
}

/// What the listing of one log, crash or cache folder holds, as one observation (ADR 0053).
///
/// Only the folder's own entries: nothing below them is listed and no file is opened. A file whose
/// size or a time the listing did not provide is left out of the sum and the bounds and counted in
/// `files_without_times`, so a bound never claims a file it did not see. An empty folder has no
/// bounds, rather than bounds that describe nothing.
fn activity_observation(
    host: &dyn Host,
    location: &Location,
    folder: &str,
    entries: &[DirEntryInfo],
) -> Observation {
    let files: Vec<&DirEntryInfo> = entries.iter().filter(|entry| entry.is_file).collect();
    let mut observation = folder_observation(location, FOLDER_LISTED, Some(files.len()));
    let fields = &mut observation.fields;
    fields.insert(
        "folders".to_owned(),
        serde_json::Value::from(entries.len() - files.len()),
    );
    let size: u64 = files.iter().filter_map(|file| file.size).sum();
    fields.insert("size_bytes".to_owned(), serde_json::Value::from(size));
    let without = files
        .iter()
        .filter(|file| file.size.is_none() || file.created.is_none() || file.modified.is_none())
        .count();
    fields.insert(
        "files_without_times".to_owned(),
        serde_json::Value::from(without),
    );
    let created = files.iter().filter_map(|file| file.created);
    let modified = files.iter().filter_map(|file| file.modified);
    for (name, value) in [
        ("earliest_created_at", created.clone().min()),
        ("latest_created_at", created.max()),
        ("earliest_modified_at", modified.clone().min()),
        ("latest_modified_at", modified.max()),
    ] {
        if let Some(value) = value {
            fields.insert(name.to_owned(), time_value(value));
        }
    }
    let (created_at, modified_at) = own_times(host, folder);
    insert_times(fields, created_at, modified_at);
    observation
}

fn insert_times(
    fields: &mut BTreeMap<String, serde_json::Value>,
    created_at: Option<Timestamp>,
    modified_at: Option<Timestamp>,
) {
    if let Some(time) = created_at {
        fields.insert("created_at".to_owned(), time_value(time));
    }
    if let Some(time) = modified_at {
        fields.insert("modified_at".to_owned(), time_value(time));
    }
}

/// A folder's own creation and last-write times, from its parent's listing (ADR 0050). Either is `None`
/// when the parent could not be listed or did not provide it: that is one missing value, not a gap,
/// because the folder itself was read.
fn own_times(host: &dyn Host, folder: &str) -> (Option<Timestamp>, Option<Timestamp>) {
    let Some((parent, name)) = folder.rsplit_once('\\') else {
        return (None, None);
    };
    let Ok(Some(entries)) = host.list_dir(parent) else {
        return (None, None);
    };
    entries
        .into_iter()
        .find(|entry| !entry.is_file && entry.name.eq_ignore_ascii_case(name))
        .map_or((None, None), |entry| (entry.created, entry.modified))
}

/// Whether a folder in Enhanced's server cache has the shape `FiveM` gives a server's folder: 40
/// hexadecimal characters. Anything else there — a folder someone renamed — is counted by the folder
/// activity only (ADR 0053).
fn is_server_folder(name: &str) -> bool {
    name.len() == 40 && name.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// One observation per server folder: its times and how many entries its own listing holds. Never
/// its name or path, which identify a server (ADR 0053). Ordered by time, not by name, so the order
/// says nothing the fields do not.
fn server_observations(
    host: &dyn Host,
    location: &Location,
    folder: &str,
    entries: &[DirEntryInfo],
) -> Vec<Observation> {
    let mut servers: Vec<(Option<Timestamp>, Option<Timestamp>, Option<usize>)> = entries
        .iter()
        .filter(|entry| !entry.is_file && is_server_folder(&entry.name))
        .map(|entry| {
            // One listing of that folder and nothing below it. A folder that cannot be listed keeps its
            // times and carries no count; it is one item, not a gap in the run.
            let count = host
                .list_dir(&format!(r"{folder}\{}", entry.name))
                .ok()
                .flatten()
                .map(|inside| inside.len());
            (entry.created, entry.modified, count)
        })
        .collect();
    servers.sort();
    servers
        .into_iter()
        .map(|(created_at, modified_at, count)| {
            let mut fields = BTreeMap::new();
            fields.insert(
                "location".to_owned(),
                serde_json::Value::from(location.name),
            );
            insert_times(&mut fields, created_at, modified_at);
            if let Some(count) = count {
                fields.insert("entries".to_owned(), serde_json::Value::from(count));
            }
            Observation {
                collector: ID.to_owned(),
                fields,
            }
        })
        .collect()
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

    /// The places a run could not read, as `(location, reason of every field)`, in the run's order.
    /// Each place must be a gap in every declared field with one reason, which this asserts.
    fn unread_places(run: &CollectorRun) -> Vec<(String, UnmeasuredReason)> {
        let CollectorRun::Measured {
            discriminator_gaps, ..
        } = run
        else {
            panic!("expected a measured run, got {run:?}");
        };
        discriminator_gaps
            .iter()
            .map(|place| {
                assert_eq!(place.discriminator, "location");
                let mut reasons: Vec<UnmeasuredReason> = place.gaps.values().copied().collect();
                reasons.dedup();
                let fields: Vec<&str> = place.gaps.keys().map(String::as_str).collect();
                let declared: Vec<&str> = FIELDS.iter().map(|field| field.name).collect();
                assert_eq!(fields, declared, "{place:?}");
                assert_eq!(reasons.len(), 1, "{place:?}");
                (
                    place.value.as_str().unwrap_or_default().to_owned(),
                    reasons.into_iter().next().unwrap(),
                )
            })
            .collect()
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

    /// The plugins folder is denied and the other three places were looked at. What could not be read
    /// is a gap in every field for the observations about the plugins folder only, so a rule about
    /// another place keeps the answer that place gives (ADR 0044).
    #[test]
    fn access_denied_is_a_gap_for_that_folder_and_the_folder_says_it_was_unreadable() {
        let run = FivemDir.collect(&fixture("fivem-dir-access-denied"));
        let (observations, gaps) = measured(&run);
        assert!(files(observations).is_empty());
        assert_eq!(
            folder(observations, PLUGINS_LOCATION),
            ("unreadable".to_owned(), None)
        );
        assert_eq!(
            folder(observations, ENHANCED_ASI_LOCATION),
            ("absent".to_owned(), None)
        );
        assert!(gaps.is_empty(), "{gaps:?}");
        assert_eq!(
            unread_places(&run),
            [(PLUGINS_LOCATION.to_owned(), UnmeasuredReason::AccessDenied)]
        );
    }

    /// Nothing the collector looks in could be read: then no place answered anything, and the gap is
    /// every field of the whole run with the worst reason — exactly as before ADR 0044.
    #[test]
    fn every_place_unreadable_is_a_gap_for_the_whole_run() {
        let host = inline(
            "platform: windows\nenv:\n  LOCALAPPDATA: 'C:\\Users\\a\\AppData\\Local'\naccess_denied:\n  - 'C:\\Users\\a\\AppData\\Local\\FiveM\\FiveM.app\\plugins'\n  - 'C:\\Users\\a\\AppData\\Local\\FiveM'\n  - 'C:\\Users\\a\\AppData\\Local\\FiveM for GTAV Enhanced'\n  - 'C:\\Users\\a\\AppData\\Local\\FiveM\\FiveM.app\\logs'\n  - 'C:\\Users\\a\\AppData\\Local\\FiveM\\FiveM.app\\crashes'\n  - 'C:\\Users\\a\\AppData\\Local\\FiveM\\FiveM.app\\data\\cache'\n  - 'C:\\Users\\a\\AppData\\Local\\FiveM\\FiveM.app\\data\\server-cache'\n  - 'C:\\Users\\a\\AppData\\Local\\FiveM\\FiveM.app\\data\\server-cache-priv'\n  - 'C:\\Users\\a\\AppData\\Local\\FiveM\\FiveM.app\\data\\server-cache-fxdk'\n  - 'C:\\Users\\a\\AppData\\Local\\FiveM for GTAV Enhanced\\servercache'\n",
        );
        let run = FivemDir.collect(&host);
        let (observations, gaps) = measured(&run);
        assert!(unread_places(&run).is_empty());
        for field in FIELDS {
            assert_eq!(
                gaps.get(field.name),
                Some(&UnmeasuredReason::AccessDenied),
                "{}",
                field.name
            );
        }
        assert_eq!(
            folder(observations, PLUGINS_LOCATION),
            ("unreadable".to_owned(), None)
        );
        assert_eq!(
            folder(observations, ENHANCED_ASI_LOCATION),
            ("unreadable".to_owned(), None)
        );
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

    /// One variable missing is one folder nobody could look in: a gap for that folder, not a quiet
    /// absence, and the other edition's folder is still read.
    #[test]
    fn one_app_data_folder_unset_is_a_gap_and_the_other_is_still_read() {
        let host = inline(
            "platform: windows\nenv:\n  LOCALAPPDATA: 'C:\\Users\\a\\AppData\\Local'\nfilesystem:\n  'C:\\Users\\a\\AppData\\Local\\FiveM\\FiveM.app\\plugins':\n    - name: x.dll\n",
        );
        let run = FivemDir.collect(&host);
        let (observations, gaps) = measured(&run);
        assert!(gaps.is_empty(), "{gaps:?}");
        // `%APPDATA%` holds every Enhanced place but its program and server cache folders.
        assert_eq!(
            unread_places(&run),
            [
                (
                    ENHANCED_ASI_LOCATION.to_owned(),
                    UnmeasuredReason::ReadFailed
                ),
                (
                    ENHANCED_LOGS_LOCATION.to_owned(),
                    UnmeasuredReason::ReadFailed
                ),
                (
                    ENHANCED_CRASHES_LOCATION.to_owned(),
                    UnmeasuredReason::ReadFailed
                ),
                (
                    ENHANCED_LAUNCHER_CRASHES_LOCATION.to_owned(),
                    UnmeasuredReason::ReadFailed
                ),
            ]
        );
        assert_eq!(
            folder(observations, PLUGINS_LOCATION),
            ("listed".to_owned(), Some(1))
        );
        assert_eq!(
            folder(observations, ENHANCED_ASI_LOCATION),
            ("unreadable".to_owned(), None)
        );
    }

    /// A denial is listed before a failed read, because it is the reason a rule may declare and the
    /// engine takes the first place that reaches a rule (ADR 0035, ADR 0044).
    #[test]
    fn a_denied_folder_and_an_unset_variable_list_the_denial_first() {
        let host = inline(
            "platform: windows\nenv:\n  LOCALAPPDATA: 'C:\\Users\\a\\AppData\\Local'\naccess_denied:\n  - 'C:\\Users\\a\\AppData\\Local\\FiveM\\FiveM.app\\plugins'\n",
        );
        let run = FivemDir.collect(&host);
        assert_eq!(
            unread_places(&run),
            [
                (PLUGINS_LOCATION.to_owned(), UnmeasuredReason::AccessDenied),
                (
                    ENHANCED_ASI_LOCATION.to_owned(),
                    UnmeasuredReason::ReadFailed
                ),
                (
                    ENHANCED_LOGS_LOCATION.to_owned(),
                    UnmeasuredReason::ReadFailed
                ),
                (
                    ENHANCED_CRASHES_LOCATION.to_owned(),
                    UnmeasuredReason::ReadFailed
                ),
                (
                    ENHANCED_LAUNCHER_CRASHES_LOCATION.to_owned(),
                    UnmeasuredReason::ReadFailed
                ),
            ]
        );
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
        // Every place but the two program folders has a folder observation (ADR 0053).
        assert_eq!(
            locations,
            [
                PLUGINS_LOCATION,
                ENHANCED_ASI_LOCATION,
                LEGACY_LOGS_LOCATION,
                LEGACY_CRASHES_LOCATION,
                LEGACY_CACHE_LOCATION,
                ENHANCED_LOGS_LOCATION,
                ENHANCED_CRASHES_LOCATION,
                ENHANCED_LAUNCHER_CRASHES_LOCATION,
                ENHANCED_SERVER_CACHE_LOCATION,
            ]
        );
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

    /// A program folder that cannot be listed is a gap in every field for its own `location`, like a
    /// plugin folder that cannot be: whether `FiveM.exe` is there was never answered, so no rule that
    /// could match there may read it as absent (ADR 0044).
    #[test]
    fn an_unreadable_program_folder_is_a_gap() {
        let run = FivemDir.collect(&fixture("fivem-dir-client-folder-denied"));
        let (observations, gaps) = measured(&run);
        assert!(files(observations).is_empty());
        assert!(gaps.is_empty(), "{gaps:?}");
        assert_eq!(
            unread_places(&run),
            [(
                LEGACY_EXE_LOCATION.to_owned(),
                UnmeasuredReason::AccessDenied
            )]
        );
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

    /// The observation that is a folder's own, for `location` and, when given, `variant`.
    fn activity<'a>(
        observations: &'a [Observation],
        location: &str,
        variant: Option<&str>,
    ) -> &'a Observation {
        observations
            .iter()
            .find(|observation| {
                field(observation, "location") == Some(location)
                    && observation.fields.contains_key("folder")
                    && field(observation, "variant") == variant
            })
            .unwrap_or_else(|| panic!("no folder observation for {location}: {observations:?}"))
    }

    fn number(observation: &Observation, name: &str) -> Option<u64> {
        observation
            .fields
            .get(name)
            .and_then(serde_json::Value::as_u64)
    }

    /// A log folder's activity: counts, the size of the files that have one, the bounds over the files
    /// that have times, how many were left out, and the folder's own times from its parent's listing.
    /// No file name reaches the report (ADR 0053).
    #[test]
    fn a_log_folder_is_reported_as_activity_and_never_file_by_file() {
        let run = FivemDir.collect(&fixture("fivem-dir-folder-activity"));
        let (observations, gaps) = measured(&run);
        assert!(gaps.is_empty(), "{gaps:?}");
        assert!(unread_places(&run).is_empty());
        let logs = activity(observations, LEGACY_LOGS_LOCATION, None);
        assert_eq!(field(logs, "folder"), Some("listed"));
        assert_eq!(number(logs, "files"), Some(3));
        assert_eq!(number(logs, "folders"), Some(1));
        assert_eq!(number(logs, "size_bytes"), Some(350));
        assert_eq!(number(logs, "files_without_times"), Some(1));
        for (name, value) in [
            ("earliest_created_at", "2026-09-07T05:40:00Z"),
            ("latest_created_at", "2026-09-13T12:37:00Z"),
            ("earliest_modified_at", "2026-09-07T05:41:00Z"),
            ("latest_modified_at", "2026-09-13T12:38:00Z"),
            ("created_at", "2026-06-11T13:18:00Z"),
            ("modified_at", "2026-09-13T12:37:00Z"),
        ] {
            assert_eq!(field(logs, name), Some(value), "{name}");
        }
        let text = serde_json::to_string(observations).unwrap();
        for name in [
            "first.log",
            "untimed.log",
            "archive",
            "aaaaaaaa",
            "bbbbbbbb",
        ] {
            assert!(!text.contains(name), "{name} reached the report");
        }
        assert!(files(observations).is_empty());
    }

    /// An empty folder has counts and no bounds; a parent with no times for it gives no own times.
    #[test]
    fn an_empty_folder_has_no_bounds_and_an_unlisted_parent_gives_no_own_times() {
        let run = FivemDir.collect(&fixture("fivem-dir-folder-activity"));
        let (observations, _) = measured(&run);
        let crashes = activity(observations, LEGACY_CRASHES_LOCATION, None);
        assert_eq!(number(crashes, "files"), Some(0));
        assert_eq!(number(crashes, "size_bytes"), Some(0));
        for name in [
            "earliest_created_at",
            "latest_modified_at",
            "created_at",
            "modified_at",
        ] {
            assert_eq!(field(crashes, name), None, "{name}");
        }
        let server_cache = activity(observations, LEGACY_SERVER_CACHE_LOCATION, Some("default"));
        assert_eq!(number(server_cache, "folders"), Some(2));
        assert_eq!(field(server_cache, "created_at"), None);
    }

    /// A place with a launch mode that is not there says nothing; a place without one says it is absent.
    #[test]
    fn an_absent_launch_mode_cache_is_not_reported_and_an_absent_folder_is() {
        let run = FivemDir.collect(&fixture("fivem-dir-folder-activity"));
        let (observations, _) = measured(&run);
        let variants: Vec<&str> = observations
            .iter()
            .filter(|observation| {
                field(observation, "location") == Some(LEGACY_SERVER_CACHE_LOCATION)
            })
            .filter_map(|observation| field(observation, "variant"))
            .collect();
        assert_eq!(variants, ["default"]);
        assert_eq!(
            folder(observations, LEGACY_CACHE_LOCATION),
            ("absent".to_owned(), None)
        );
        assert_eq!(
            folder(observations, ENHANCED_LOGS_LOCATION),
            ("absent".to_owned(), None)
        );
    }

    /// Each server folder: its times and entry count, ordered by time, never its name. A folder that
    /// cannot be listed keeps its times and loses its count without becoming a gap; a folder whose name
    /// is not a server folder's is counted by the folder activity only.
    #[test]
    fn each_server_folder_is_dated_and_counted_and_not_named() {
        let run = FivemDir.collect(&fixture("fivem-dir-folder-activity"));
        let (observations, gaps) = measured(&run);
        assert!(gaps.is_empty(), "{gaps:?}");
        assert!(unread_places(&run).is_empty());
        let parent = activity(observations, ENHANCED_SERVER_CACHE_LOCATION, None);
        assert_eq!(number(parent, "folders"), Some(3));
        let servers: Vec<(Option<&str>, Option<&str>, Option<u64>)> = observations
            .iter()
            .filter(|observation| {
                field(observation, "location") == Some(ENHANCED_SERVER_CACHE_LOCATION)
                    && !observation.fields.contains_key("folder")
            })
            .map(|observation| {
                let keys: Vec<&str> = observation.fields.keys().map(String::as_str).collect();
                assert!(
                    keys.iter().all(|key| {
                        ["created_at", "entries", "location", "modified_at"].contains(key)
                    }),
                    "{keys:?}"
                );
                (
                    field(observation, "created_at"),
                    field(observation, "modified_at"),
                    number(observation, "entries"),
                )
            })
            .collect();
        assert_eq!(
            servers,
            [
                (
                    Some("2026-09-09T14:32:00Z"),
                    Some("2026-09-15T09:18:00Z"),
                    Some(3)
                ),
                (
                    Some("2026-09-15T11:03:00Z"),
                    Some("2026-09-15T11:05:00Z"),
                    None
                ),
            ]
        );
    }

    /// An unreadable log folder is a gap for its own observations only, and says it was unreadable.
    #[test]
    fn an_unreadable_log_folder_is_a_gap_for_that_place_only() {
        let run = FivemDir.collect(&fixture("fivem-dir-folder-activity-denied"));
        let (observations, gaps) = measured(&run);
        assert!(gaps.is_empty(), "{gaps:?}");
        assert_eq!(
            unread_places(&run),
            [(
                LEGACY_LOGS_LOCATION.to_owned(),
                UnmeasuredReason::AccessDenied
            )]
        );
        assert_eq!(
            folder(observations, LEGACY_LOGS_LOCATION),
            ("unreadable".to_owned(), None)
        );
        assert_eq!(
            folder(observations, PLUGINS_LOCATION),
            ("listed".to_owned(), Some(0))
        );
    }

    #[test]
    fn a_server_folder_name_is_forty_hex_characters() {
        assert!(is_server_folder(&"a".repeat(40)));
        assert!(is_server_folder(&"0F".repeat(20)));
        assert!(!is_server_folder(&"a".repeat(39)));
        assert!(!is_server_folder(&"g".repeat(40)));
        assert!(!is_server_folder(&format!("{}.bak", "a".repeat(40))));
    }
}
