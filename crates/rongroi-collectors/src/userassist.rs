// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! What Windows Explorer recorded about programs the person opened through the shell.
//!
//! Explorer keeps one value per program under the executables key of
//! `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist`; the value's name is the
//! path or app identity in ROT13, and the collector hands its bytes to
//! `rongroi_parsers::userassist` (ADR 0080).
//!
//! A path is emitted only when `is_drive_rooted` holds and `is_refused_form` does not refuse it; a
//! known-folder prefix is resolved from `Host::env_var`, never an OS call, and is withheld as
//! `unresolved_known_folder` when its variable is missing. An app identity — a name with none of
//! `\`, `/` and `:` — is emitted unchanged with `path_withheld: app_id`, and any other withheld path
//! keeps only its last segment. The run count at
//! offset 4 and the unparsed tail are never emitted (owner decision 5), and the shortcuts key is
//! counted, never decoded (owner decision 2).
//!
//! No rule reads this collector (ADR 0034, amended); Self mode lists its observations, SS mode counts
//! them (ADR 0014).

use std::collections::BTreeMap;

use rongroi_core::model::{CollectorRun, Observation, UnmeasuredReason};
use rongroi_host::{Host, Platform};
use rongroi_parsers::filetime::to_timestamp;
use rongroi_parsers::userassist::{UserAssistEntry, decode_name, parse_entry};

use crate::failure::{read_failure, reason_for};
use crate::paths::{RecordedPath, UNREDACTABLE_FORM, file_name, is_drive_rooted};
use crate::powershell_text::history_account;
use crate::{Age, AgeCount, AgeRows, Collector, Field};

/// The `Count` key holding one value per executable Explorer recorded.
pub const COUNT_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count";

/// The `Count` key holding one value per shortcut Explorer recorded. Only its value names are counted.
pub const SHORTCUT_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}\Count";

const ID: &str = "userassist";

/// Why a path carrying a known-folder GUID is not in the report.
const UNRESOLVED_KNOWN_FOLDER: &str = "unresolved_known_folder";

/// Why an app identity has no path: it never named one.
const APP_ID: &str = "app_id";

/// Length of a `{…}` GUID, braces included.
const GUID_LEN: usize = 38;

/// Every reason this collector gives for not having looked (`Collector::unmeasured_reasons`).
///
/// `source_empty` is deliberately absent: a key holding no value is a measured zero.
const REASONS: [UnmeasuredReason; 6] = [
    UnmeasuredReason::NotWindows,
    UnmeasuredReason::NotAdmin,
    UnmeasuredReason::AccessDenied,
    UnmeasuredReason::SourceAbsent,
    UnmeasuredReason::Partial,
    UnmeasuredReason::ReadFailed,
];

/// Every field this collector can emit.
const FIELDS: [Field; 10] = [
    Field::text("account"),
    Field::number("entries"),
    Field::timestamp("last_run"),
    Field::text("name"),
    Field::text("path"),
    Field::text("path_withheld"),
    Field::text("read"),
    Field::number("rejected"),
    Field::number("shortcuts"),
    Field::number("skipped"),
];

/// The fields a value whose bytes did not arrive leaves uncertain: the four that describe one
/// program, and `entries`, whose count is then only a lower bound rather than what the key held.
const ENTRY_FIELDS: [&str; 5] = ["entries", "last_run", "name", "path", "path_withheld"];

/// The `userassist` collector.
#[derive(Debug, Default, Clone, Copy)]
pub struct UserAssist;

impl Collector for UserAssist {
    fn id(&self) -> &'static str {
        ID
    }

    fn fields(&self) -> &'static [Field] {
        &FIELDS
    }

    fn unmeasured_reasons(&self) -> &'static [UnmeasuredReason] {
        &REASONS
    }

    /// One row: the oldest `last_run` `UserAssist` still holds and how many entries it holds (ADR 0061).
    fn age(&self) -> Option<Age> {
        Some(Age {
            oldest: &["last_run"],
            count: AgeCount::Field("entries"),
            rows: AgeRows::One,
            places: &[],
            extra: &[],
            by_place: &[],
        })
    }

    fn collect(&self, host: &dyn Host) -> CollectorRun {
        if host.platform() != Platform::Windows {
            return CollectorRun::Unmeasured {
                collector: ID.to_owned(),
                reason: UnmeasuredReason::NotWindows,
            };
        }

        let names = match host.value_names(COUNT_KEY) {
            // The key is not on this machine. That is the absence of the record, not the statement
            // that the person opened nothing (ADR 0080 section 1).
            Ok(None) => {
                return CollectorRun::Unmeasured {
                    collector: ID.to_owned(),
                    reason: UnmeasuredReason::SourceAbsent,
                };
            }
            Ok(Some(names)) => names,
            Err(error) => {
                // The key is there and Windows would not hand it over. It is emitted as an
                // observation as well as gapped, as `bam` does, because no rule reads this collector
                // and a `gaps` entry alone would reach no screen.
                return CollectorRun::Measured {
                    collector: ID.to_owned(),
                    observations: vec![status(read_failure(&error))],
                    gaps: gaps(reason_for(host, &error)),
                    discriminator_gaps: Vec::new(),
                };
            }
        };

        let mut observations = Vec::new();
        let mut counts = Counts::default();
        let mut partial = false;

        for name in &names {
            let decoded = decode_name(name);
            // A session counter is not a program the person opened.
            if decoded.starts_with("UEME_") {
                counts.skipped += 1;
                continue;
            }
            let bytes = match host.read_bytes(COUNT_KEY, name) {
                // Listed a moment ago and gone now. Explorer writes this key while a scan runs, so
                // this is ordinary and is neither an entry nor a failure (ADR 0019).
                Ok(None) => continue,
                Ok(Some(bytes)) => bytes,
                Err(error) => {
                    partial = true;
                    observations.push(status(read_failure(&error)));
                    continue;
                }
            };
            // `decode_name` is total, so a name never fails; a value shorter than the 72-byte entry
            // is the one rejection that is about the value rather than a read.
            let Ok(entry) = parse_entry(&bytes) else {
                counts.rejected += 1;
                continue;
            };
            counts.entries += 1;
            observations.push(program(host, &decoded, &entry));
        }

        // Never decoded: the names are `.lnk` paths, and a shortcut is not the program it started.
        // A key that is not there contributes zero rather than making the whole run unmeasured; a key
        // Windows would not list is a gap on the count, and the field is left out rather than
        // reported as a zero.
        let mut gaps = BTreeMap::new();
        let shortcuts = match host.value_names(SHORTCUT_KEY) {
            Ok(Some(names)) => Some(names.len()),
            Ok(None) => Some(0),
            Err(error) => {
                gaps.insert("shortcuts".to_owned(), reason_for(host, &error));
                None
            }
        };
        observations.push(account(&counts, shortcuts, history_account(host)));

        if partial {
            gaps.extend(entry_gaps(UnmeasuredReason::Partial));
        }
        CollectorRun::Measured {
            collector: ID.to_owned(),
            observations,
            gaps,
            discriminator_gaps: Vec::new(),
        }
    }
}

/// The program paths `UserAssist` recorded, and when Explorer last ran each, for `recorded_files`
/// (ADR 0080 section 4).
///
/// This runs the same collection [`UserAssist::collect`] does and keeps the `path` and `last_run` each
/// entry observation carries, so the two collectors cannot disagree about which paths are emitted or
/// when they ran. An entry that names no path — an app identity, or a path withheld for another
/// reason — contributes nothing: there is nothing for `recorded_files` to join or read. A status row
/// that names neither a path nor a withheld path is a value whose bytes did not arrive: an unknown
/// number of paths is missing, so the source is a gap for the whole run and the paths that were read
/// are returned beside it. A key that is absent is `source_absent`, which the caller reads as an
/// account that opened nothing through the shell.
pub(crate) fn recorded_paths(
    host: &dyn Host,
) -> Result<(Vec<RecordedPath>, Option<UnmeasuredReason>), UnmeasuredReason> {
    match UserAssist.collect(host) {
        CollectorRun::Unmeasured { reason, .. } => Err(reason),
        CollectorRun::Measured {
            observations, gaps, ..
        } => {
            let lost_names = observations.iter().any(|observation| {
                observation.fields.contains_key("read")
                    && !observation.fields.contains_key("path")
                    && !observation.fields.contains_key("path_withheld")
            });
            let paths = observations
                .iter()
                .filter_map(|observation| {
                    let path = observation.fields.get("path")?.as_str()?.to_owned();
                    let at = observation
                        .fields
                        .get("last_run")
                        .and_then(serde_json::Value::as_str)
                        .and_then(|text| text.parse().ok());
                    Some(RecordedPath { path, at })
                })
                .collect();
            let gap = lost_names.then(|| {
                gaps.values()
                    .next()
                    .copied()
                    .unwrap_or(UnmeasuredReason::ReadFailed)
            });
            Ok((paths, gap))
        }
    }
}

/// The five known folders Windows writes into a `UserAssist` name (ADR 0080 section 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KnownFolder {
    /// `{6D809377-6AF0-444B-8957-A3773F02200E}`, resolved from `ProgramW6432`, then `ProgramFiles`.
    ProgramFiles,
    /// `{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}`, resolved from `ProgramFiles(x86)`.
    ProgramFilesX86,
    /// `{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}`, `SystemRoot` + `\System32`.
    System32,
    /// `{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}`, `SystemRoot` + `\SysWOW64`.
    SysWow64,
    /// `{F38BF404-1D43-42F2-9305-67DE0B28FC23}`, `SystemRoot`.
    Windows,
}

/// What of one decoded name is emitted: the name, and either a path or why there is none.
struct Location {
    name: Option<String>,
    path: Option<String>,
    withheld: Option<&'static str>,
}

/// One program Explorer recorded, from one value that decoded.
fn program(host: &dyn Host, decoded: &str, entry: &UserAssistEntry) -> Observation {
    let location = location(host, decoded);
    let mut fields = BTreeMap::new();
    if let Some(name) = location.name {
        fields.insert("name".to_owned(), serde_json::Value::from(name));
    }
    if let Some(path) = location.path {
        fields.insert("path".to_owned(), serde_json::Value::from(path));
    }
    if let Some(withheld) = location.withheld {
        fields.insert(
            "path_withheld".to_owned(),
            serde_json::Value::from(withheld),
        );
    }
    // A zero `FILETIME` means no last run was recorded; it is not 1601 and is not emitted. A value
    // too large for `jiff` to represent is reported as no timestamp rather than a wrong instant.
    if entry.last_run_filetime != 0
        && let Some(at) = to_timestamp(entry.last_run_filetime)
    {
        fields.insert(
            "last_run".to_owned(),
            serde_json::Value::from(at.to_string()),
        );
    }
    Observation {
        collector: ID.to_owned(),
        fields,
    }
}

/// Decides whether a decoded name is a path, an app identity, or a path this program withholds.
fn location(host: &dyn Host, decoded: &str) -> Location {
    if is_drive_rooted(decoded) {
        return emit(decoded);
    }
    if let Some((folder, rest)) = known_folder(decoded) {
        return match resolve(host, folder) {
            Some(base) => emit(&join(&base, rest)),
            None => withheld(decoded, UNRESOLVED_KNOWN_FOLDER),
        };
    }
    // No path separator and no drive or scheme marker: it is an app identity, emitted as it was
    // written.
    if !decoded.contains(['\\', '/', ':']) {
        return Location {
            name: Some(decoded.to_owned()),
            path: None,
            withheld: Some(APP_ID),
        };
    }
    // A brace-delimited prefix this collector does not resolve is a known folder it cannot name; any
    // other shape is a path redaction cannot reach. Neither keeps any part but the last segment.
    if is_unresolved_folder(decoded) {
        withheld(decoded, UNRESOLVED_KNOWN_FOLDER)
    } else {
        // A URL's query is not part of its last path segment and may carry a token, so it is not
        // kept either.
        let path = decoded.split(['?', '#']).next().unwrap_or(decoded);
        withheld(path, UNREDACTABLE_FORM)
    }
}

/// The folder a decoded name begins with, and the rest of the path after its separator.
fn known_folder(decoded: &str) -> Option<(KnownFolder, &str)> {
    let prefix = decoded.get(..GUID_LEN)?;
    let rest = decoded.get(GUID_LEN..)?.strip_prefix('\\')?;
    let folder = match prefix.to_ascii_uppercase().as_str() {
        "{6D809377-6AF0-444B-8957-A3773F02200E}" => KnownFolder::ProgramFiles,
        "{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}" => KnownFolder::ProgramFilesX86,
        "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}" => KnownFolder::System32,
        "{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}" => KnownFolder::SysWow64,
        "{F38BF404-1D43-42F2-9305-67DE0B28FC23}" => KnownFolder::Windows,
        _ => return None,
    };
    Some((folder, rest))
}

/// Whether a decoded name begins with a `{…}` prefix this collector does not resolve.
fn is_unresolved_folder(decoded: &str) -> bool {
    let Some(rest) = decoded.strip_prefix('{') else {
        return false;
    };
    rest.find('}').is_some_and(|end| {
        rest.get(end + 1..)
            .is_some_and(|tail| tail.starts_with('\\'))
    })
}

/// Resolves a known folder through the environment, or `None` when the variable is absent or empty.
fn resolve(host: &dyn Host, folder: KnownFolder) -> Option<String> {
    match folder {
        KnownFolder::ProgramFiles => host
            .env_var("ProgramW6432")
            .filter(|value| !value.is_empty())
            .or_else(|| {
                host.env_var("ProgramFiles")
                    .filter(|value| !value.is_empty())
            }),
        KnownFolder::ProgramFilesX86 => host
            .env_var("ProgramFiles(x86)")
            .filter(|value| !value.is_empty()),
        KnownFolder::System32 => system_root(host, Some("System32")),
        KnownFolder::SysWow64 => system_root(host, Some("SysWOW64")),
        KnownFolder::Windows => system_root(host, None),
    }
}

/// `SystemRoot`, with `child` appended when the folder names one.
fn system_root(host: &dyn Host, child: Option<&str>) -> Option<String> {
    let root = host
        .env_var("SystemRoot")
        .filter(|value| !value.is_empty())?;
    Some(match child {
        Some(child) => join(&root, child),
        None => root.trim_end_matches(['\\', '/']).to_owned(),
    })
}

/// Joins a resolved folder and the name below it without doubling a separator.
fn join(base: &str, rest: &str) -> String {
    format!(
        "{}\\{}",
        base.trim_end_matches(['\\', '/']),
        rest.trim_start_matches('\\')
    )
}

/// Emits a path when it is one redaction can reach, and withholds it otherwise.
fn emit(path: &str) -> Location {
    if !rongroi_host::is_refused_form(path) && is_drive_rooted(path) {
        Location {
            name: file_name(path),
            path: Some(path.to_owned()),
            withheld: None,
        }
    } else {
        withheld(path, UNREDACTABLE_FORM)
    }
}

/// Keeps only the last segment of a path whose rest is withheld.
fn withheld(path: &str, reason: &'static str) -> Location {
    Location {
        name: file_name(path),
        path: None,
        withheld: Some(reason),
    }
}

/// What the key held, as the account observation counts it.
#[derive(Debug, Default, Clone, Copy)]
struct Counts {
    /// Values emitted as one program each.
    entries: usize,
    /// `UEME_` session counters, which are not programs.
    skipped: usize,
    /// Values shorter than the 72-byte entry.
    rejected: usize,
}

/// What the key held, how much of it was understood, and whose entries these are not.
fn account(counts: &Counts, shortcuts: Option<usize>, account: &'static str) -> Observation {
    let mut fields = BTreeMap::new();
    fields.insert(
        "entries".to_owned(),
        serde_json::Value::from(counts.entries),
    );
    fields.insert(
        "skipped".to_owned(),
        serde_json::Value::from(counts.skipped),
    );
    fields.insert(
        "rejected".to_owned(),
        serde_json::Value::from(counts.rejected),
    );
    if let Some(shortcuts) = shortcuts {
        fields.insert("shortcuts".to_owned(), serde_json::Value::from(shortcuts));
    }
    fields.insert("account".to_owned(), serde_json::Value::from(account));
    Observation {
        collector: ID.to_owned(),
        fields,
    }
}

/// One thing that yielded nothing: a key or a value whose bytes did not arrive.
///
/// It carries no `name`, so a rule written for a program that was opened never matches it, and it
/// carries `read`, which no entry observation does.
fn status(read: &'static str) -> Observation {
    let mut fields = BTreeMap::new();
    fields.insert("read".to_owned(), serde_json::Value::from(read));
    Observation {
        collector: ID.to_owned(),
        fields,
    }
}

fn gaps(reason: UnmeasuredReason) -> BTreeMap<String, UnmeasuredReason> {
    FIELDS
        .iter()
        .map(|field| (field.name.to_owned(), reason))
        .collect()
}

/// A gap in what one program would have said, leaving what the key held measured.
fn entry_gaps(reason: UnmeasuredReason) -> BTreeMap<String, UnmeasuredReason> {
    ENTRY_FIELDS
        .iter()
        .map(|field| ((*field).to_owned(), reason))
        .collect()
}
