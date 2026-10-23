// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! What Windows Prefetch recorded about programs that ran.
//!
//! Windows writes one `.pf` file per program under `%SystemRoot%\Prefetch`, holding the program's
//! name, how many times it ran, up to the eight most recent run times, the volumes it touched and
//! every file it loaded. The collector lists that folder, hands each `.pf` file's bytes to
//! `rongroi_parsers::prefetch`, and decodes nothing itself (ADR 0015). Reading the folder normally
//! needs an elevated token, so `not_admin` is an expected outcome of an ordinary scan rather than a
//! defect (ADR 0012, ADR 0021).
//!
//! One rule reads this collector, and it asks whether a `.pf` file is marked read-only, never what the
//! file records (ADR 0037); no rule names a program (ADR 0034). Everything else it sees is listed in
//! Self mode as unmatched observations and counted, never listed, in SS mode (ADR 0014).
//!
//! # Two of the parser's fields never reach a report
//!
//! A `.pf` file's string table is the sharpest privacy boundary in this program:
//!
//! - **`loaded_files` is withheld whole, but one count is derived from it.** It is normally hundreds
//!   of paths, some of them under a user's profile, and Prefetch writes them as
//!   `\VOLUME{…}\USERS\<account>\…` — a shape `rongroi_core::view::redact_profile_paths` does not
//!   touch, because it has no drive letter. It is also, on its own, a list of what a person has on
//!   their computer, which ADR 0014 already refused to let redaction stand in for withholding. The
//!   list is still never emitted. For the programs ADR 0082 names, `loaded_outside` is how many of
//!   its executable files were loaded from outside Windows' and the installers' folders: a number,
//!   with no path or name in it.
//! - **`volumes` is withheld whole**, device path, serial number and creation time alike. A volume
//!   serial is not a person's name, but it identifies one machine across two reports, no rule can
//!   express a question about it, and the device path is the prefix of the list above.
//!
//! What is left — the program's name, how many times it ran and when it last ran — is what a rule
//! could use and is what this collector emits.
//!
//! One word is read **from** the string table without any of it being emitted: `fivem_edition`
//! (`legacy` or `enhanced`), when the executable's own entry — the entry whose last segment is the
//! program's name — is below one of `FiveM`'s two program folders (ADR 0062, owner decision 6 of
//! 2026-10-02; `crate::fivem_edition`). It is omitted for every other file.
//!
//! # The configuration, beside the records
//!
//! Since ADR 0037 each run that could look also says two things about Prefetch's own setup, as one
//! observation of their own: whether the folder is there (`folder`, the vocabulary `fivem_dir` uses
//! for its folders) and the `EnablePrefetcher` value, which is **absent from the observation when
//! the value is absent from the registry**. Before, both facts reached the report only as the reason
//! a rule was unmeasured, which no rule can match. Neither is a finding and no rule reads either: the
//! observation is shown in Self mode and counted in SS mode (ADR 0014). And each `.pf` file carries
//! `read_only`, the one attribute bit a rule reads.

use std::collections::BTreeMap;

use rongroi_core::loaded_files::{counts_loaded_files, has_pe_extension};
use rongroi_core::model::{CollectorRun, Observation, UnmeasuredReason};
use rongroi_host::{Host, Platform};
use rongroi_parsers::error::ParseError;
use rongroi_parsers::prefetch::{self, PrefetchRecord};

use crate::failure::{read_failure, reason_for};
use crate::{Age, AgeCount, AgeRows, Collector, Field, fivem_edition};

/// Environment variable holding the Windows directory.
///
/// `SystemRoot` rather than `WinDir`, which `pca` uses: both are set by Windows and name the same
/// directory, and this is the one the artifact is documented under, in `rongroi_parsers::prefetch`
/// and in ADR 0015. A path in the code should be checkable against the document that describes it.
pub const SYSTEM_ROOT: &str = "SystemRoot";
/// Prefetch's folder, relative to `%SystemRoot%`.
pub const PREFETCH_RELATIVE_PATH: &str = "Prefetch";
/// Extension of the files Windows writes there, lower-cased for comparison.
const PREFETCH_EXTENSION: &str = ".pf";
/// The prefix of a device path in a string table, before the volume's identifier.
const VOLUME_PREFIX: &str = r"\VOLUME{";
/// The system library whose entry names the system volume: every Windows install has one.
const SYSTEM_LIBRARY: &str = r"\Windows\System32\ntdll.dll";
/// Folders on the system volume whose files Windows or an installer put there, as `rest` begins.
const SYSTEM_FOLDERS: [&str; 3] = [r"\Windows\", r"\Program Files\", r"\Program Files (x86)\"];
/// Why `loaded_outside` gives no count: there is no single system volume to compare entries with.
const NO_SYSTEM_VOLUME: &str = "no_system_volume";

/// The key holding the switch that decides whether Windows writes these files at all.
pub const PREFETCH_PARAMETERS_KEY: &str =
    r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters";
/// The switch itself: `0` off, `1` application launch only, `2` boot only, `3` both.
pub const ENABLE_PREFETCHER: &str = "EnablePrefetcher";

const ID: &str = "prefetch";

/// Why `loaded_files` is not in the report, as the account observation states it.
const LOADED_FILES_WITHHELD: &str = "user_file_list";
/// Why `volumes` is not in the report, as the account observation states it.
const VOLUMES_WITHHELD: &str = "machine_identifier";

/// Every reason this collector gives for not having looked (`Collector::unmeasured_reasons`).
///
/// `%SystemRoot%` is not set; the folder is absent, or present and holding no `.pf` file; Windows
/// is not writing application-launch records at all; some of the folder was read and some was not;
/// or the read was denied, denied without administrator rights, or failed.
const REASONS: [UnmeasuredReason; 8] = [
    UnmeasuredReason::NotWindows,
    UnmeasuredReason::NotAdmin,
    UnmeasuredReason::AccessDenied,
    UnmeasuredReason::ServiceDisabled,
    UnmeasuredReason::SourceAbsent,
    UnmeasuredReason::SourceEmpty,
    UnmeasuredReason::Partial,
    UnmeasuredReason::ReadFailed,
];

/// Every field this collector can emit.
///
/// A folder it could not list is a gap in all of them. One `.pf` file it could not read is not: see
/// the comment on [`Prefetch::collect`].
const FIELDS: [Field; 20] = [
    Field::number("enable_prefetcher"),
    Field::number("entries"),
    Field::number("files"),
    Field::text(fivem_edition::FIELD),
    Field::text("folder"),
    Field::boolean("intact"),
    Field::timestamp("last_run"),
    Field::text("loaded_files_withheld"),
    Field::number("loaded_outside"),
    Field::text("loaded_outside_unknown"),
    Field::text("name"),
    Field::text("path"),
    Field::text("read"),
    Field::boolean("read_only"),
    Field::number("recorded_runs"),
    Field::number("rejected"),
    Field::number("run_count"),
    Field::timestamp_list("run_times"),
    Field::number("scca_version"),
    Field::text("volumes_withheld"),
];

/// The fields that describe one program Prefetch recorded, as opposed to what the folder held.
///
/// This is the subset a content-level reason gaps: `source_empty`, `service_disabled` and `partial`
/// all describe a folder this collector **did** read, so gapping `files`, `entries`, `rejected` or
/// `intact` — which were measured — would claim it had not. The reasons that describe a folder
/// nothing was read from keep gapping every field (ADR 0030).
const RECORD_FIELDS: [&str; 10] = [
    fivem_edition::FIELD,
    "last_run",
    "loaded_outside",
    "loaded_outside_unknown",
    "name",
    "path",
    "recorded_runs",
    "run_count",
    "run_times",
    "scca_version",
];

/// The fields of the configuration observation, which a reason about the folder's **contents** never
/// gaps (ADR 0037).
///
/// `folder` is the answer to "is the folder there", so a folder that is absent, unlistable or empty
/// leaves it measured. `enable_prefetcher` is a registry read of its own; it is gapped only when that
/// read fails, and then with that read's reason.
const CONFIG_FIELDS: [&str; 2] = ["enable_prefetcher", "folder"];

/// Value of `folder` when the folder is there and was listed.
const FOLDER_LISTED: &str = "listed";
/// Value of `folder` when the folder is not there.
const FOLDER_ABSENT: &str = "absent";
/// Value of `folder` when the folder is there and could not be listed; why is in `gaps` and in the
/// `read` observation beside it.
const FOLDER_UNREADABLE: &str = "unreadable";

/// The `prefetch` collector.
#[derive(Debug, Default, Clone, Copy)]
pub struct Prefetch;

impl Collector for Prefetch {
    fn id(&self) -> &'static str {
        ID
    }

    fn fields(&self) -> &'static [Field] {
        &FIELDS
    }

    fn unmeasured_reasons(&self) -> &'static [UnmeasuredReason] {
        &REASONS
    }

    /// One row: the oldest of the newest run times each `.pf` file still holds, how many files were
    /// read, and whether Prefetch is switched on beside it (ADR 0061).
    fn age(&self) -> Option<Age> {
        Some(Age {
            oldest: &["last_run"],
            count: AgeCount::Field("entries"),
            rows: AgeRows::One,
            places: &[],
            extra: &["enable_prefetcher"],
            by_place: &[],
        })
    }

    /// Lists `%SystemRoot%\Prefetch` and reads every `.pf` file in it.
    ///
    /// A failure to list the folder gaps every field: nothing was read, so no rule may conclude a
    /// program did not run. A failure on **one** `.pf` file does not, which is where this differs
    /// from `pca` and follows `fivem_dir` instead (ADR 0009): one `.pf` file is one program's
    /// record, not the record of a class of launches, so losing it loses that program and says
    /// nothing about the others. It is still emitted as an observation naming the file, and counted
    /// in the account's `rejected` and `intact`, so it is visible either way.
    fn collect(&self, host: &dyn Host) -> CollectorRun {
        if host.platform() != Platform::Windows {
            return CollectorRun::Unmeasured {
                collector: ID.to_owned(),
                reason: UnmeasuredReason::NotWindows,
            };
        }
        let Some(dir) = prefetch_dir(host) else {
            // Without `%SystemRoot%` there is no folder to look in, so nothing was looked at.
            return CollectorRun::Unmeasured {
                collector: ID.to_owned(),
                reason: UnmeasuredReason::ReadFailed,
            };
        };

        // Read before the folder is interpreted. A machine whose `EnablePrefetcher` says Windows is
        // not writing application-launch records has no such record to be missing, so the folder's
        // state is not the answer to "did this program run" on it either way (ADR 0030).
        let setting = enable_prefetcher(host);
        let launches_recorded = setting.value.map(|value| value & 1 == 1);

        let names = match host.list_dir(&dir) {
            // Prefetch's folder is not on this machine. That is not the statement "no program ran" —
            // it is the absence of the record that would have said either way, so every field about
            // a record stays a gap (ADR 0021). Whether the folder is there, and what the switch says,
            // were both measured, and since ADR 0037 they are reported rather than only turned into
            // a reason.
            Ok(None) => {
                let reason = if launches_recorded == Some(false) {
                    UnmeasuredReason::ServiceDisabled
                } else {
                    UnmeasuredReason::SourceAbsent
                };
                return CollectorRun::Measured {
                    collector: ID.to_owned(),
                    observations: vec![configuration(FOLDER_ABSENT, setting.value)],
                    gaps: with_setting_gap(content_gaps(reason), &setting),
                    discriminator_gaps: Vec::new(),
                };
            }
            Ok(Some(entries)) => prefetch_files(entries),
            Err(error) => {
                // The folder is there and Windows would not hand it over — the ordinary outcome of
                // a scan without an elevated token (ADR 0015). It is emitted as an observation as
                // well as gapped, because a `gaps` entry reaches no screen unless a rule reads the
                // field, and "could not read the artifact" is what a reviewer needs.
                return CollectorRun::Measured {
                    collector: ID.to_owned(),
                    observations: vec![
                        status(None, read_failure(&error), None),
                        configuration(FOLDER_UNREADABLE, setting.value),
                    ],
                    gaps: with_setting_gap(content_gaps(reason_for(host, &error)), &setting),
                    discriminator_gaps: Vec::new(),
                };
            }
        };

        let mut observations = Vec::with_capacity(names.len() + 2);
        let mut parsed = 0_usize;
        let mut rejected = 0_usize;
        // The first reason the attribute of some `.pf` file could not be read. One file whose
        // attribute is unknown makes "no `.pf` file here is read-only" a claim nobody measured, so it
        // gaps `read_only` for the run, as an unreadable folder gaps everything.
        let mut attribute_gap: Option<UnmeasuredReason> = None;
        for name in &names {
            let path = format!(r"{dir}\{name}");
            let read_only = match host.is_read_only(&path) {
                Ok(read_only) => read_only,
                Err(error) => {
                    attribute_gap = attribute_gap.or(Some(reason_for(host, &error)));
                    None
                }
            };
            match host.read_file(&path) {
                // Listed a moment ago and gone now. Windows rewrites this folder while a scan runs,
                // so this is ordinary (ADR 0019) and is counted as neither read nor refused.
                Ok(None) => {}
                Ok(Some(bytes)) => match prefetch::parse(&bytes) {
                    Ok(record) => {
                        parsed += 1;
                        observations.push(execution(&path, &record, read_only));
                    }
                    // A `.pf` this parser cannot decode — an older Windows's version, a payload that
                    // does not decompress, bytes that are not a Prefetch file at all. Each is a
                    // legitimate input rather than a defect, and each is named rather than counted.
                    Err(error) => {
                        rejected += 1;
                        observations.push(status(Some(&path), parse_failure(&error), read_only));
                    }
                },
                Err(error) => {
                    rejected += 1;
                    observations.push(status(Some(&path), read_failure(&error), read_only));
                }
            }
        }
        observations.push(account(names.len(), parsed, rejected));
        observations.push(configuration(FOLDER_LISTED, setting.value));

        let mut gaps = content_gap(launches_recorded, names.len(), rejected)
            .map_or_else(BTreeMap::new, record_gaps);
        if let Some(reason) = attribute_gap {
            gaps.insert("read_only".to_owned(), reason);
        }
        CollectorRun::Measured {
            collector: ID.to_owned(),
            observations,
            gaps: with_setting_gap(gaps, &setting),
            discriminator_gaps: Vec::new(),
        }
    }
}

/// The reason a folder this collector **read** still cannot answer "did this program run".
///
/// Three of them, most specific first, and each is ordinary on a machine nobody has touched:
///
/// - Windows is not writing application-launch records, so there is no record to have kept. This
///   outranks the other two because it explains them: it is the answer whatever the folder holds,
///   including a boot-only machine's folder of `NTOSBOOT` and layout files, which is not empty and
///   holds nothing about an application (ADR 0030).
/// - the folder is there and holds no `.pf` file at all.
/// - some of the `.pf` files did not yield a record. Before ADR 0030 this gapped nothing, so a rule
///   over a folder that was half read was `NotFound` — "the collector looked and nothing matched".
fn content_gap(
    launches_recorded: Option<bool>,
    files: usize,
    rejected: usize,
) -> Option<UnmeasuredReason> {
    if launches_recorded == Some(false) {
        Some(UnmeasuredReason::ServiceDisabled)
    } else if files == 0 {
        Some(UnmeasuredReason::SourceEmpty)
    } else if rejected > 0 {
        Some(UnmeasuredReason::Partial)
    } else {
        None
    }
}

/// What the registry held for `EnablePrefetcher`, and why nothing, when it held nothing readable.
struct Setting {
    /// The value, when there is one and it could be read.
    value: Option<u32>,
    /// Why it could not be read. `None` together with no value means the value is not there — a
    /// different statement, and the one `enable_prefetcher|exists: false` asks about.
    unread: Option<UnmeasuredReason>,
}

/// Reads `EnablePrefetcher`: `0` off, `1` application launch only, `2` boot only and `3` both.
///
/// A value that is not there is an answer; a value that could not be read — denied, or of a type that
/// is not a number — is not, and a guess in its place would put a value in the report nobody read.
fn enable_prefetcher(host: &dyn Host) -> Setting {
    match host.read_u32(PREFETCH_PARAMETERS_KEY, ENABLE_PREFETCHER) {
        Ok(value) => Setting {
            value,
            unread: None,
        },
        Err(error) => Setting {
            value: None,
            unread: Some(reason_for(host, &error)),
        },
    }
}

/// Whether Windows writes a `.pf` file when an application is launched on this machine: the low bit
/// of `EnablePrefetcher`, and `None` when there is no value to read it from.
#[cfg(test)]
fn application_launches_recorded(host: &dyn Host) -> Option<bool> {
    enable_prefetcher(host).value.map(|value| value & 1 == 1)
}

/// Adds the gap a failed `EnablePrefetcher` read leaves, to whatever else the run gapped.
fn with_setting_gap(
    mut gaps: BTreeMap<String, UnmeasuredReason>,
    setting: &Setting,
) -> BTreeMap<String, UnmeasuredReason> {
    if let Some(reason) = setting.unread {
        gaps.insert("enable_prefetcher".to_owned(), reason);
    }
    gaps
}

/// Every field but the configuration's, for a folder nothing was read from (ADR 0037).
fn content_gaps(reason: UnmeasuredReason) -> BTreeMap<String, UnmeasuredReason> {
    FIELDS
        .iter()
        .filter(|field| !CONFIG_FIELDS.contains(&field.name))
        .map(|field| (field.name.to_owned(), reason))
        .collect()
}

/// A gap in what one `.pf` file would have said, leaving what the folder held measured.
fn record_gaps(reason: UnmeasuredReason) -> BTreeMap<String, UnmeasuredReason> {
    RECORD_FIELDS
        .iter()
        .map(|field| ((*field).to_owned(), reason))
        .collect()
}

fn prefetch_dir(host: &dyn Host) -> Option<String> {
    let root = host.env_var(SYSTEM_ROOT)?;
    let root = root.trim_end_matches(['\\', '/']);
    (!root.is_empty()).then(|| format!(r"{root}\{PREFETCH_RELATIVE_PATH}"))
}

/// The names of the `.pf` files directly inside the folder, in a stable order.
///
/// A real Prefetch folder also holds `ReadyBoot`, a database and a statistics file. They are not
/// this artifact and are not read; nothing about them is reported either, because "there is a file
/// here this collector does not read" is not evidence about anything.
fn prefetch_files(entries: Vec<rongroi_host::DirEntryInfo>) -> Vec<String> {
    let mut names: Vec<String> = entries
        .into_iter()
        .filter(|entry| {
            entry.is_file
                && entry
                    .name
                    .to_ascii_lowercase()
                    .ends_with(PREFETCH_EXTENSION)
        })
        .map(|entry| entry.name)
        .collect();
    // A directory listing has no defined order; sorting keeps two reads of the same folder
    // comparable, as `fivem_dir` does.
    names.sort();
    names
}

/// One program Prefetch recorded, from one `.pf` file that decoded.
fn execution(path: &str, record: &PrefetchRecord, read_only: Option<bool>) -> Observation {
    let mut fields = BTreeMap::new();
    if let Some(read_only) = read_only {
        fields.insert("read_only".to_owned(), serde_json::Value::from(read_only));
    }
    if let Some(name) = executable_name(&record.executable) {
        fields.insert("name".to_owned(), serde_json::Value::from(name));
    }
    fields.insert("path".to_owned(), serde_json::Value::from(path));
    // From the executable's own entry in the string table, which is not emitted: one word, never a
    // path.
    if let Some(edition) = fivem_edition::of_prefetch(&record.executable, &record.loaded_files) {
        fields.insert(
            fivem_edition::FIELD.to_owned(),
            serde_json::Value::from(edition.as_str()),
        );
    }
    // Only for the programs ADR 0082 names. The count is derived from `loaded_files`, and nothing
    // else of that list reaches the observation.
    if counts_loaded_files(&record.executable) {
        match loaded_outside(&record.loaded_files) {
            Ok(count) => {
                fields.insert("loaded_outside".to_owned(), serde_json::Value::from(count));
            }
            Err(word) => {
                fields.insert(
                    "loaded_outside_unknown".to_owned(),
                    serde_json::Value::from(word),
                );
            }
        }
    }
    fields.insert(
        "run_count".to_owned(),
        serde_json::Value::from(record.run_count),
    );
    fields.insert(
        "recorded_runs".to_owned(),
        serde_json::Value::from(record.last_runs.len()),
    );
    // The newest run Prefetch kept. A run whose raw `FILETIME` names no instant this program can
    // represent omits the field rather than inventing one; the other fields still stand.
    if let Some(at) = record.last_runs.first().and_then(|run| run.at) {
        fields.insert(
            "last_run".to_owned(),
            serde_json::Value::from(at.to_string()),
        );
    }
    // Every run time the file still holds, newest first and at most eight. The unrepresentable ones
    // are left out rather than invented; the representable ones stay, in time order. Read only by
    // the game-windows view, never put on the timeline (ADR 0078 section 6).
    let mut run_times: Vec<jiff::Timestamp> =
        record.last_runs.iter().filter_map(|run| run.at).collect();
    // The file's order is not always the clock's: one fixture holds two runs a fraction of a second
    // out of place, so the list is ordered here rather than trusted as read.
    run_times.sort_unstable_by(|left, right| right.cmp(left));
    let run_times: Vec<serde_json::Value> = run_times
        .into_iter()
        .map(|at| serde_json::Value::from(at.to_string()))
        .collect();
    fields.insert("run_times".to_owned(), serde_json::Value::Array(run_times));
    fields.insert(
        "scca_version".to_owned(),
        serde_json::Value::from(record.scca_version),
    );
    Observation {
        collector: ID.to_owned(),
        fields,
    }
}

/// How many of a program's loaded files are executable and sit outside the folders Windows and the
/// installers use, or why there is no count.
///
/// Every entry's device prefix is compared with the system volume's, which is the one the system's
/// own `ntdll.dll` is on. Without exactly one such volume the entries cannot be told apart by
/// volume, so no count is given rather than a guess (ADR 0082 section 2). An entry with no device
/// prefix, and NTFS metadata (`\$`), is not a file a program loaded and is skipped.
fn loaded_outside(loaded_files: &[String]) -> Result<usize, &'static str> {
    let mut system: Option<&str> = None;
    for entry in loaded_files {
        let Some((volume, rest)) = split_volume(entry) else {
            continue;
        };
        if !rest.eq_ignore_ascii_case(SYSTEM_LIBRARY) {
            continue;
        }
        match system {
            None => system = Some(volume),
            Some(known) if !known.eq_ignore_ascii_case(volume) => {
                return Err(NO_SYSTEM_VOLUME);
            }
            Some(_) => {}
        }
    }
    let system = system.ok_or(NO_SYSTEM_VOLUME)?;

    let mut outside = 0;
    for entry in loaded_files {
        let Some((volume, rest)) = split_volume(entry) else {
            continue;
        };
        if rest.starts_with(r"\$") {
            continue;
        }
        // A `FiveM` program folder is expected on any volume, because it is the program's own.
        let expected = (volume.eq_ignore_ascii_case(system) && in_system_folder(rest))
            || fivem_edition::of_path(entry).is_some();
        if !expected && has_pe_extension(entry) {
            outside += 1;
        }
    }
    Ok(outside)
}

/// Splits an entry `\VOLUME{…}\rest` into its device prefix and its rest, which keeps the backslash
/// that follows the closing brace. `None` for an entry of any other shape.
fn split_volume(entry: &str) -> Option<(&str, &str)> {
    let head = entry.get(..VOLUME_PREFIX.len())?;
    if !head.eq_ignore_ascii_case(VOLUME_PREFIX) {
        return None;
    }
    let close = entry.find('}')?;
    let volume = entry.get(..=close)?;
    let rest = entry.get(close + 1..)?;
    rest.starts_with('\\').then_some((volume, rest))
}

/// Whether `rest` lies below one of `SYSTEM_FOLDERS`, ignoring ASCII case.
fn in_system_folder(rest: &str) -> bool {
    SYSTEM_FOLDERS.iter().any(|folder| {
        rest.get(..folder.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(folder))
    })
}

/// What the folder held, how much of it decoded, and what this collector did not report.
///
/// `files: 0` on a folder that exists is the one question about Prefetch that exact equality can
/// ask, and it is worth asking: an emptied Prefetch folder is a machine whose execution history was
/// removed. `intact` is `rejected == 0`, the same field and the same meaning `pca` gives it — every
/// file this collector read yielded a record, and nothing was refused.
fn account(files: usize, parsed: usize, rejected: usize) -> Observation {
    let mut fields = BTreeMap::new();
    fields.insert("files".to_owned(), serde_json::Value::from(files));
    fields.insert("entries".to_owned(), serde_json::Value::from(parsed));
    fields.insert("rejected".to_owned(), serde_json::Value::from(rejected));
    fields.insert("intact".to_owned(), serde_json::Value::from(rejected == 0));
    // Said out loud once per run rather than left out: a reader who knows what a `.pf` file holds
    // would otherwise have to guess whether this program read those parts and dropped them, or
    // never read them. It read them and does not report them, for two different reasons.
    fields.insert(
        "loaded_files_withheld".to_owned(),
        serde_json::Value::from(LOADED_FILES_WITHHELD),
    );
    fields.insert(
        "volumes_withheld".to_owned(),
        serde_json::Value::from(VOLUMES_WITHHELD),
    );
    Observation {
        collector: ID.to_owned(),
        fields,
    }
}

/// One thing that yielded nothing, with what stopped it: a `.pf` file when `path` is given, and the
/// whole folder when it is not.
///
/// It carries no `name` and no `run_count`, so a rule written for a program that ran never matches
/// one of these, and it carries `read`, which no other observation does, so a rule written for it
/// never matches a program that ran.
fn status(path: Option<&str>, read: &'static str, read_only: Option<bool>) -> Observation {
    let mut fields = BTreeMap::new();
    if let Some(path) = path {
        fields.insert("path".to_owned(), serde_json::Value::from(path));
    }
    if let Some(read_only) = read_only {
        fields.insert("read_only".to_owned(), serde_json::Value::from(read_only));
    }
    fields.insert("read".to_owned(), serde_json::Value::from(read));
    Observation {
        collector: ID.to_owned(),
        fields,
    }
}

/// How Prefetch is set up on this machine: whether its folder is there, and the switch.
///
/// It carries `folder`, which no other observation of this collector does, so a rule scopes itself to
/// this one with `folder|exists: true`. The switch is **left out when the registry holds no value**,
/// rather than written as `null` or a default: `enable_prefetcher|exists: false` is then the one
/// question "the value is absent", and it is a different question from `enable_prefetcher: 0`, which
/// is Prefetch switched off (ADR 0037).
fn configuration(folder: &'static str, enable_prefetcher: Option<u32>) -> Observation {
    let mut fields = BTreeMap::new();
    fields.insert("folder".to_owned(), serde_json::Value::from(folder));
    if let Some(value) = enable_prefetcher {
        fields.insert(
            "enable_prefetcher".to_owned(),
            serde_json::Value::from(value),
        );
    }
    Observation {
        collector: ID.to_owned(),
        fields,
    }
}

/// Value of the `read` field for a `.pf` file whose bytes arrived and are not a readable Prefetch
/// file.
///
/// Finer than the one word `gaps` would carry, because these are four different machines to a
/// reviewer: a `.pf` from an older Windows is ordinary on a machine that was upgraded, while a
/// payload that does not decompress is a file something has written over.
fn parse_failure(error: &ParseError) -> &'static str {
    match error {
        ParseError::Truncated { .. } => "truncated",
        ParseError::Malformed { field, .. } => match *field {
            "signature" => "not_prefetch",
            "compressed_payload" => "not_decompressible",
            "decompressed_size" => "implausible_size",
            "scca_version" => "unsupported_version",
            // `record`, and anything a later version of the parser adds. A name invented here for a
            // field this collector has not seen would be a guess in evidence, so the general word
            // is used and the finer one is added when there is something to add.
            _ => "malformed",
        },
    }
}

/// The program's name, lower-cased.
///
/// Prefetch already stores a base name with no path in it, and Windows upper-cases it. Lower-casing
/// is what makes it the same string a `pca` launch record emits as `name`, so a rule author learns
/// one spelling rather than two, and a reader sees one. Since ADR 0025 it is not what makes a rule
/// match `CMD.EXE`: `match` folds ASCII case.
fn executable_name(executable: &str) -> Option<String> {
    let name = executable.trim();
    (!name.is_empty()).then(|| name.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use rongroi_host::{FixtureHost, NonWindowsHost};
    use rongroi_parsers::prefetch::PrefetchRun;

    use super::*;

    const PREFETCH_DIR: &str = r"C:\Windows\Prefetch";

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

    fn field<'a>(observation: &'a Observation, name: &str) -> Option<&'a serde_json::Value> {
        observation.fields.get(name)
    }

    fn text<'a>(observation: &'a Observation, name: &str) -> Option<&'a str> {
        field(observation, name).and_then(serde_json::Value::as_str)
    }

    /// Every run time the observation carries, in the order it emitted them.
    fn run_times_of(observation: &Observation) -> Vec<String> {
        field(observation, "run_times")
            .and_then(serde_json::Value::as_array)
            .expect("an execution observation carries run_times")
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .expect("every run time is an RFC 3339 string")
                    .to_owned()
            })
            .collect()
    }

    /// The one observation that says what the folder held.
    fn account_of(observations: &[Observation]) -> &Observation {
        observations
            .iter()
            .find(|observation| observation.fields.contains_key("files"))
            .expect("every measured run that listed the folder has an account")
    }

    /// The programs Prefetch recorded: the observations that carry a name.
    fn executions(observations: &[Observation]) -> Vec<&Observation> {
        observations
            .iter()
            .filter(|observation| observation.fields.contains_key("name"))
            .collect()
    }

    /// The things that yielded nothing: the observations that carry a `read`.
    fn refusals(observations: &[Observation]) -> Vec<&Observation> {
        observations
            .iter()
            .filter(|observation| observation.fields.contains_key("read"))
            .collect()
    }

    #[test]
    fn a_prefetch_file_is_observed() {
        let run = Prefetch.collect(&fixture("prefetch-files-present"));
        let (observations, gaps) = measured(&run);
        assert!(gaps.is_empty(), "{gaps:?}");

        let records = executions(observations);
        assert_eq!(records.len(), 1, "{records:?}");
        assert_eq!(records[0].collector, "prefetch");
        assert_eq!(text(records[0], "name"), Some("cmd.exe"));
        assert_eq!(
            text(records[0], "path"),
            Some(format!(r"{PREFETCH_DIR}\CMD.EXE-D269B812.pf").as_str())
        );
        assert_eq!(field(records[0], "run_count"), Some(&55_u64.into()));
        assert_eq!(field(records[0], "recorded_runs"), Some(&8_u64.into()));
        assert_eq!(field(records[0], "scca_version"), Some(&30_u64.into()));
        assert_eq!(
            text(records[0], "last_run"),
            Some("2016-01-12T20:07:03.9810694Z")
        );
    }

    /// Every run time the Windows 10 fixture holds is representable, so `run_times` carries all
    /// eight, newest first, and its first entry is the `last_run` the collector already emitted
    /// (ADR 0078 section 6).
    #[test]
    fn the_windows_10_fixture_emits_every_run_time_newest_first() {
        let run = Prefetch.collect(&fixture("prefetch-files-present"));
        let (observations, gaps) = measured(&run);
        assert!(gaps.is_empty(), "{gaps:?}");
        let record = executions(observations)[0];

        let times = run_times_of(record);
        assert!(!times.is_empty(), "{times:?}");
        assert_eq!(
            field(record, "recorded_runs").and_then(serde_json::Value::as_u64),
            Some(times.len() as u64),
            "every recorded run in this fixture is representable: {times:?}"
        );
        assert_eq!(Some(times[0].as_str()), text(record, "last_run"));
        let instants: Vec<jiff::Timestamp> = times
            .iter()
            .map(|time| time.parse().expect("an RFC 3339 timestamp"))
            .collect();
        assert!(
            instants.windows(2).all(|pair| pair[0] >= pair[1]),
            "run_times is not newest first: {times:?}"
        );

        let declared = FIELDS
            .iter()
            .find(|field| field.name == "run_times")
            .expect("the collector declares run_times");
        // The ADR names the new variant; `Debug` keeps this test independent of `as_str`'s wording.
        assert_eq!(format!("{:?}", declared.kind), "TimestampList");
        assert!(
            !declared.on_timeline,
            "run_times must not put its up to eight times on the timeline"
        );
    }

    /// A raw `FILETIME` that names no representable instant is left out, and the older runs that
    /// are representable stay in order. `last_run` stays absent, as it was before the list existed.
    #[test]
    fn an_unrepresentable_newest_run_is_left_out_and_the_older_runs_are_kept() {
        let newest = "2016-01-12T20:07:03.9810694Z".to_owned();
        let older = "2016-01-11T20:07:03.9810694Z".to_owned();
        let instant = |value: &str| Some(value.parse::<jiff::Timestamp>().expect("test instant"));
        let record = PrefetchRecord {
            scca_version: 30,
            executable: "CMD.EXE".to_owned(),
            run_count: 3,
            last_runs: vec![
                PrefetchRun {
                    filetime: u64::MAX,
                    at: None,
                },
                PrefetchRun {
                    filetime: 2,
                    at: instant(&newest),
                },
                PrefetchRun {
                    filetime: 1,
                    at: instant(&older),
                },
            ],
            volumes: Vec::new(),
            loaded_files: Vec::new(),
        };

        let observation = execution(r"C:\Windows\Prefetch\CMD.EXE-D269B812.pf", &record, None);
        assert_eq!(text(&observation, "last_run"), None);
        assert_eq!(run_times_of(&observation), vec![newest, older]);
    }

    /// The account is what a rule can ask a question of: an emptied folder is `files: 0`, and a
    /// folder holding a file this program could not decode is `intact: false`.
    #[test]
    fn the_folder_says_what_it_held_and_how_much_of_it_decoded() {
        let run = Prefetch.collect(&fixture("prefetch-files-present"));
        let (observations, _) = measured(&run);
        let account = account_of(observations);
        assert_eq!(field(account, "files"), Some(&1_u64.into()));
        assert_eq!(field(account, "entries"), Some(&1_u64.into()));
        assert_eq!(field(account, "rejected"), Some(&0_u64.into()));
        assert_eq!(field(account, "intact"), Some(&true.into()));
    }

    /// A real Prefetch folder holds a `ReadyBoot` directory and files that are not `.pf` at all.
    /// Neither is this artifact, so neither is read and neither is counted.
    #[test]
    fn only_pf_files_are_read() {
        let run = Prefetch.collect(&fixture("prefetch-files-present"));
        let (observations, _) = measured(&run);
        let json = serde_json::to_string(&observations).unwrap();
        assert!(!json.contains("ReadyBoot"), "{json}");
        assert!(!json.contains("AgAppLaunch"), "{json}");
        assert_eq!(
            field(account_of(observations), "files"),
            Some(&1_u64.into())
        );
    }

    /// **The whole point of this collector's field list.** A `.pf` file's string table holds the
    /// paths of every file the program loaded, the volumes it touched and their serial numbers. The
    /// Windows 10 fixture's account name is a single letter (`fixtures/prefetch/PROVENANCE.md`), so
    /// asserting that one letter is absent would assert nothing — the honest assertion is that none
    /// of the *shapes* those paths take reaches an observation, and that the two fields that carry
    /// them are not emitted under any name.
    #[test]
    fn no_loaded_file_and_no_volume_reaches_an_observation() {
        let run = Prefetch.collect(&fixture("prefetch-files-present"));
        let (observations, _) = measured(&run);
        let json = serde_json::to_string(&observations).unwrap().to_uppercase();

        for leaked in [
            "\\\\USERS\\\\",
            "VOLUME{",
            "HARDDISKVOLUME",
            "APPDATA",
            "SYSTEM32",
            ".DLL",
            "LOADED_FILES\"",
            "VOLUMES\"",
            "SERIAL",
            "DEVICE_PATH",
        ] {
            assert!(
                !json.contains(leaked),
                "{leaked} reached an observation: {json}"
            );
        }

        // And the run says so, rather than leaving a reader to infer it from an absence.
        let account = account_of(observations);
        assert_eq!(
            text(account, "loaded_files_withheld"),
            Some(LOADED_FILES_WITHHELD)
        );
        assert_eq!(text(account, "volumes_withheld"), Some(VOLUMES_WITHHELD));
    }

    /// The one observation that says how Prefetch is set up.
    /// Each edition's `FiveM.exe` has its own Prefetch file, and the edition comes from the
    /// executable's own entry in each one's string table. `PlayGTAV.exe`'s own entry is below neither
    /// folder, so it has no edition although another of its entries is below one. Only the word
    /// leaves the string table (ADR 0062, owner decision 6 of 2026-10-02).
    #[test]
    fn a_prefetch_file_says_which_edition_from_the_executables_own_entry() {
        let run = Prefetch.collect(&fixture("prefetch-fivem-editions"));
        let (observations, gaps) = measured(&run);
        assert!(gaps.is_empty(), "{gaps:?}");

        let records: Vec<(Option<&str>, Option<&str>, Option<&str>)> = executions(observations)
            .iter()
            .map(|record| {
                (
                    text(record, "path"),
                    text(record, "name"),
                    text(record, "fivem_edition"),
                )
            })
            .collect();
        assert_eq!(
            records,
            [
                (
                    Some(format!(r"{PREFETCH_DIR}\FIVEM.EXE-1A2B3C4D.pf").as_str()),
                    Some("fivem.exe"),
                    Some("legacy")
                ),
                (
                    Some(format!(r"{PREFETCH_DIR}\FIVEM.EXE-5E6F7A8B.pf").as_str()),
                    Some("fivem.exe"),
                    Some("enhanced")
                ),
                (
                    Some(format!(r"{PREFETCH_DIR}\PLAYGTAV.EXE-0C1D2E3F.pf").as_str()),
                    Some("playgtav.exe"),
                    None
                ),
            ]
        );
        assert_eq!(
            field(executions(observations)[0], "scca_version"),
            Some(&31_u64.into())
        );

        let json = serde_json::to_string(&observations).unwrap().to_uppercase();
        for leaked in [
            "VOLUME{",
            "\\USERS\\",
            "ALEX",
            "APPDATA",
            "FIVEM.APP",
            "FOR GTAV",
            "ROCKSTAR",
            "EXAMPLE.DLL",
            "NTDLL",
        ] {
            assert!(
                !json.contains(leaked),
                "{leaked} reached an observation: {json}"
            );
        }
    }

    fn configuration_of(observations: &[Observation]) -> &Observation {
        observations
            .iter()
            .find(|observation| observation.fields.contains_key("folder"))
            .expect("every run that could look says how Prefetch is set up")
    }

    /// Prefetch's folder is not here. Nothing about a program was read, so every field about one is
    /// a gap and a rule must not read this as "the program did not run" (ADR 0021). What **was**
    /// measured — that the folder is absent, and that the registry holds no switch either — is an
    /// observation since ADR 0037, and neither of its fields is gapped.
    #[test]
    fn no_prefetch_folder_is_a_measured_absence_and_gaps_every_record_field() {
        let run = Prefetch.collect(&fixture("prefetch-not-present"));
        let (observations, gaps) = measured(&run);

        assert_eq!(observations.len(), 1, "{observations:?}");
        let configuration = configuration_of(observations);
        assert_eq!(text(configuration, "folder"), Some(FOLDER_ABSENT));
        // The value is not in the registry, so it is not in the observation — not `null`, not `0`.
        assert_eq!(field(configuration, "enable_prefetcher"), None);
        for field in FIELDS {
            let name = field.name;
            if CONFIG_FIELDS.contains(&name) {
                assert_eq!(gaps.get(name), None, "{name}");
            } else {
                assert_eq!(
                    gaps.get(name),
                    Some(&UnmeasuredReason::SourceAbsent),
                    "{name}"
                );
            }
        }
    }

    /// The switch as the registry holds it, on every run that could look — and nothing when there is
    /// nothing, which is a different statement from `0`.
    #[test]
    fn the_configuration_reports_the_switch_as_read() {
        let run = Prefetch.collect(&fixture("prefetch-folder-empty"));
        let (observations, gaps) = measured(&run);
        let configuration = configuration_of(observations);
        assert_eq!(text(configuration, "folder"), Some(FOLDER_LISTED));
        assert_eq!(
            field(configuration, "enable_prefetcher"),
            Some(&3_u64.into())
        );
        assert_eq!(gaps.get("folder"), None);
        assert_eq!(gaps.get("enable_prefetcher"), None);
    }

    /// A switch this program could not read is not a switch that is absent: the field is gapped with
    /// the read's reason, so `enable_prefetcher|exists: false` comes out unmeasured, not found.
    #[test]
    fn a_switch_that_could_not_be_read_is_a_gap_not_an_absence() {
        let host = FixtureHost::from_yaml_str(
            "platform: windows\nelevated: true\nenv:\n  SystemRoot: 'C:\\Windows'\nfilesystem:\n  'C:\\Windows\\Prefetch': []\naccess_denied:\n  - 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters'\n",
            "inline",
        )
        .unwrap();
        let run = Prefetch.collect(&host);
        let (observations, gaps) = measured(&run);
        assert_eq!(
            field(configuration_of(observations), "enable_prefetcher"),
            None
        );
        assert_eq!(
            gaps.get("enable_prefetcher"),
            Some(&UnmeasuredReason::AccessDenied)
        );
        assert_eq!(gaps.get("folder"), None);
    }

    /// The folder is there and holds no `.pf` file. Opposite statements, which one word used to make
    /// one statement: `source_absent` says this PC keeps no such record, and this says it keeps one
    /// and the record is empty. What the folder held is still measured, so only the fields that
    /// describe a program are gapped (ADR 0030).
    #[test]
    fn an_empty_prefetch_folder_is_source_empty_and_still_says_what_it_held() {
        let run = Prefetch.collect(&fixture("prefetch-folder-empty"));
        let (observations, gaps) = measured(&run);

        let account = account_of(observations);
        assert_eq!(field(account, "files"), Some(&0_u64.into()));
        assert_eq!(field(account, "intact"), Some(&true.into()));
        for name in RECORD_FIELDS {
            assert_eq!(
                gaps.get(name),
                Some(&UnmeasuredReason::SourceEmpty),
                "{name}"
            );
        }
        // Measured, so not gapped: a rule asking what the folder held gets an answer.
        assert_eq!(gaps.get("files"), None);
        assert_eq!(gaps.get("intact"), None);
    }

    /// `EnablePrefetcher` says Windows writes no application-launch record on this machine, so the
    /// folder's state answers nothing about what ran — whatever it holds. A boot-only machine's
    /// folder is not empty and still holds nothing about an application (ADR 0030).
    #[test]
    fn prefetching_switched_off_is_service_disabled_whatever_the_folder_holds() {
        let run = Prefetch.collect(&fixture("prefetch-service-disabled"));
        let (observations, gaps) = measured(&run);

        // The boot file is there and was read: this is not an empty folder.
        assert_eq!(
            field(account_of(observations), "files"),
            Some(&1_u64.into())
        );
        for name in RECORD_FIELDS {
            assert_eq!(
                gaps.get(name),
                Some(&UnmeasuredReason::ServiceDisabled),
                "{name}"
            );
        }
    }

    /// With no folder at all and the switch off, the more truthful of the two is the one that says
    /// why there is nothing to read.
    #[test]
    fn no_folder_with_prefetching_switched_off_is_service_disabled_not_source_absent() {
        let host = FixtureHost::from_yaml_str(
            "platform: windows\nenv:\n  SystemRoot: 'C:\\Windows'\nfilesystem:\n  'C:\\Windows': []\nregistry:\n  'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters':\n    EnablePrefetcher: 0\n",
            "inline",
        )
        .unwrap();
        let run = Prefetch.collect(&host);
        let (observations, gaps) = measured(&run);
        assert_eq!(gaps.get("name"), Some(&UnmeasuredReason::ServiceDisabled));
        assert_eq!(gaps.get("files"), Some(&UnmeasuredReason::ServiceDisabled));
        let configuration = configuration_of(observations);
        assert_eq!(text(configuration, "folder"), Some(FOLDER_ABSENT));
        assert_eq!(
            field(configuration, "enable_prefetcher"),
            Some(&0_u64.into())
        );
    }

    /// The switch is the low bit of `EnablePrefetcher`, and a value this program could not read is
    /// not an answer about what Windows records.
    #[test]
    fn the_switch_is_read_from_the_registry_and_never_guessed() {
        let with = |value: &str| {
            FixtureHost::from_yaml_str(
                &format!("platform: windows\nregistry:\n  'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters':\n    EnablePrefetcher: {value}\n"),
                "inline",
            )
            .unwrap()
        };
        assert_eq!(application_launches_recorded(&with("0")), Some(false));
        assert_eq!(application_launches_recorded(&with("1")), Some(true));
        assert_eq!(application_launches_recorded(&with("2")), Some(false));
        assert_eq!(application_launches_recorded(&with("3")), Some(true));
        // Not there at all, and a key that holds a string where a number belongs.
        let absent = FixtureHost::from_yaml_str("platform: windows\n", "inline").unwrap();
        assert_eq!(application_launches_recorded(&absent), None);
        assert_eq!(application_launches_recorded(&with("'three'")), None);
    }

    /// The ordinary outcome of a scan without an elevated token, which ADR 0015 says is what reading
    /// this folder needs. It is the signal that makes the restart-as-administrator offer worth
    /// taking (ADR 0012).
    #[test]
    fn access_denied_without_admin_rights_is_a_not_admin_gap_and_is_still_shown() {
        let run = Prefetch.collect(&fixture("prefetch-access-denied"));
        let (observations, gaps) = measured(&run);

        let refused = refusals(observations);
        assert_eq!(refused.len(), 1, "{observations:?}");
        assert_eq!(text(refused[0], "read"), Some("access_denied"));
        assert_eq!(refused[0].fields.get("path"), None);
        // The folder is there — Windows refused it — and that much was measured (ADR 0037).
        assert_eq!(
            text(configuration_of(observations), "folder"),
            Some(FOLDER_UNREADABLE)
        );
        for field in FIELDS {
            let name = field.name;
            let expected = (!CONFIG_FIELDS.contains(&name)).then_some(&UnmeasuredReason::NotAdmin);
            assert_eq!(gaps.get(name), expected, "{name}");
        }
    }

    /// Denied while the rights were already held is a different fact: restarting would not help, and
    /// the report must not suggest it would.
    #[test]
    fn access_denied_with_admin_rights_is_an_access_denied_gap() {
        let run = Prefetch.collect(&fixture("prefetch-access-denied-elevated"));
        let (observations, gaps) = measured(&run);

        assert_eq!(
            text(refusals(observations)[0], "read"),
            Some("access_denied")
        );
        for field in FIELDS {
            let name = field.name;
            let expected =
                (!CONFIG_FIELDS.contains(&name)).then_some(&UnmeasuredReason::AccessDenied);
            assert_eq!(gaps.get(name), expected, "{name}");
        }
    }

    /// One `.pf` file is listed and has no bytes; the other is readable. The readable one is still
    /// reported and the run is not gapped — one `.pf` file is one program's record, so losing it
    /// says nothing about the others (ADR 0009). The loss is visible: the file is named, and the
    /// account is no longer `intact`.
    #[test]
    fn one_unreadable_file_is_named_and_does_not_gap_the_run() {
        let run = Prefetch.collect(&fixture("prefetch-file-unreadable"));
        let (observations, gaps) = measured(&run);
        // Part of the folder was read and part of it was not, so a rule over a program that ran is
        // `partial` and not `not_found`. Until ADR 0030 this gapped nothing, and the engine called a
        // half-read folder "the collector looked and nothing matched".
        for name in RECORD_FIELDS {
            assert_eq!(gaps.get(name), Some(&UnmeasuredReason::Partial), "{name}");
        }
        assert_eq!(gaps.get("files"), None);

        let refused = refusals(observations);
        assert_eq!(refused.len(), 1, "{refused:?}");
        assert_eq!(text(refused[0], "read"), Some("failed"));
        assert_eq!(
            text(refused[0], "path"),
            Some(format!(r"{PREFETCH_DIR}\UNREADABLE.EXE-11111111.pf").as_str())
        );
        assert_eq!(executions(observations).len(), 1);

        let account = account_of(observations);
        assert_eq!(field(account, "files"), Some(&2_u64.into()));
        assert_eq!(field(account, "entries"), Some(&1_u64.into()));
        assert_eq!(field(account, "rejected"), Some(&1_u64.into()));
        assert_eq!(field(account, "intact"), Some(&false.into()));
    }

    /// A `.pf` from an older Windows is a legitimate input this parser cannot decode, never a defect
    /// and never a tamper signal on its own (ADR 0015). It is named rather than dropped.
    #[test]
    fn an_unsupported_scca_version_is_reported_as_such() {
        let run = Prefetch.collect(&fixture("prefetch-unsupported-version"));
        let (observations, gaps) = measured(&run);
        assert_eq!(
            gaps.get("name"),
            Some(&UnmeasuredReason::Partial),
            "{gaps:?}"
        );

        let refused = refusals(observations);
        assert_eq!(refused.len(), 1, "{refused:?}");
        assert_eq!(text(refused[0], "read"), Some("unsupported_version"));
        assert!(executions(observations).is_empty());
        assert_eq!(
            field(account_of(observations), "intact"),
            Some(&false.into())
        );
    }

    /// Two ways a `.pf` file is not readable content: bytes that are no Prefetch container at all,
    /// and an intact `MAM` container whose compressed payload does not decode. The second is the
    /// only branch in this program that reaches the third-party decompressor with bad input.
    #[test]
    fn a_corrupt_file_is_reported_with_what_stopped_it() {
        let run = Prefetch.collect(&fixture("prefetch-corrupt-files"));
        let (observations, gaps) = measured(&run);
        assert_eq!(
            gaps.get("name"),
            Some(&UnmeasuredReason::Partial),
            "{gaps:?}"
        );

        let reads: Vec<Option<&str>> = refusals(observations)
            .into_iter()
            .map(|observation| text(observation, "read"))
            .collect();
        assert_eq!(
            reads,
            [Some("not_decompressible"), Some("not_prefetch")],
            "{observations:?}"
        );

        let account = account_of(observations);
        assert_eq!(field(account, "files"), Some(&2_u64.into()));
        assert_eq!(field(account, "entries"), Some(&0_u64.into()));
        assert_eq!(field(account, "rejected"), Some(&2_u64.into()));
        assert_eq!(field(account, "intact"), Some(&false.into()));
    }

    /// The one attribute bit a rule reads, on the file the observation is about (ADR 0037).
    #[test]
    fn each_prefetch_file_says_whether_it_is_read_only() {
        let run = Prefetch.collect(&fixture("prefetch-files-present"));
        let (observations, gaps) = measured(&run);
        assert_eq!(
            field(executions(observations)[0], "read_only"),
            Some(&false.into())
        );
        assert_eq!(gaps.get("read_only"), None);

        let host = FixtureHost::from_yaml_str(
            "platform: windows\nelevated: true\nenv:\n  SystemRoot: 'C:\\Windows'\nfilesystem:\n  'C:\\Windows\\Prefetch':\n    - name: A.EXE-11111111.pf\n      read_only: true\n",
            "inline",
        )
        .unwrap();
        let run = Prefetch.collect(&host);
        let (observations, _) = measured(&run);
        // The file has no bytes, so it is a refusal — and it still says what its attribute is.
        assert_eq!(
            field(refusals(observations)[0], "read_only"),
            Some(&true.into())
        );
    }

    /// A file whose attribute could not be read carries no `read_only`, and the run gaps the field:
    /// "no `.pf` file here is read-only" was not measured about that file (ADR 0037).
    #[test]
    fn an_attribute_that_could_not_be_read_gaps_read_only() {
        let host = FixtureHost::from_yaml_str(
            "platform: windows\nelevated: true\nenv:\n  SystemRoot: 'C:\\Windows'\nfilesystem:\n  'C:\\Windows\\Prefetch':\n    - name: A.EXE-11111111.pf\n",
            "inline",
        )
        .unwrap();
        let run = Prefetch.collect(&host);
        let (observations, gaps) = measured(&run);
        assert_eq!(field(refusals(observations)[0], "read_only"), None);
        assert_eq!(gaps.get("read_only"), Some(&UnmeasuredReason::ReadFailed));
    }

    #[test]
    fn non_windows_is_unmeasured() {
        assert_eq!(
            Prefetch.collect(&NonWindowsHost),
            CollectorRun::Unmeasured {
                collector: "prefetch".to_owned(),
                reason: UnmeasuredReason::NotWindows,
            }
        );
    }

    #[test]
    fn systemroot_unset_is_unmeasured() {
        let host = FixtureHost::from_yaml_str("platform: windows\n", "inline").unwrap();
        assert_eq!(
            Prefetch.collect(&host),
            CollectorRun::Unmeasured {
                collector: "prefetch".to_owned(),
                reason: UnmeasuredReason::ReadFailed,
            }
        );
    }

    #[test]
    fn the_folder_is_built_from_the_environment_and_not_hardcoded() {
        let host = FixtureHost::from_yaml_str(
            "platform: windows\nenv:\n  SystemRoot: 'D:\\Windows\\'\n",
            "inline",
        )
        .unwrap();
        assert_eq!(prefetch_dir(&host).as_deref(), Some(r"D:\Windows\Prefetch"));
        // And the fixture hosts describe the folder this builds on an ordinary machine.
        let ordinary = fixture("prefetch-files-present");
        assert_eq!(prefetch_dir(&ordinary).as_deref(), Some(PREFETCH_DIR));
    }

    #[test]
    fn a_name_is_the_stored_base_name_lower_cased() {
        assert_eq!(executable_name("CMD.EXE").as_deref(), Some("cmd.exe"));
        assert_eq!(executable_name("Cheat.exe").as_deref(), Some("cheat.exe"));
        assert_eq!(executable_name("   ").as_deref(), None);
        assert_eq!(executable_name("").as_deref(), None);
    }

    /// Every way a `.pf` file's bytes can fail to decode has a word of its own, so that a reviewer
    /// is not told "malformed" about four different machines.
    #[test]
    fn every_parse_failure_has_its_own_word() {
        assert_eq!(
            parse_failure(&ParseError::Truncated {
                expected: 8,
                found: 0
            }),
            "truncated"
        );
        for (field, expected) in [
            ("signature", "not_prefetch"),
            ("compressed_payload", "not_decompressible"),
            ("decompressed_size", "implausible_size"),
            ("scca_version", "unsupported_version"),
            ("record", "malformed"),
        ] {
            assert_eq!(
                parse_failure(&ParseError::Malformed {
                    field,
                    detail: String::new()
                }),
                expected,
                "{field}"
            );
        }
    }

    /// The device prefix of the system volume, as Prefetch writes it in a string table (ADR 0082).
    const SYSTEM: &str = r"\VOLUME{01d0000000000000-aaaaaaaa}";
    /// The device prefix of a second volume on the same machine.
    const OTHER: &str = r"\VOLUME{01d0000000000000-bbbbbbbb}";

    /// `ntdll.dll` in `\Windows\System32` on the given volume: the entry that names the system volume.
    fn ntdll_on(volume: &str) -> String {
        format!(r"{volume}\WINDOWS\SYSTEM32\NTDLL.DLL")
    }

    /// A record for `executable` that loaded `loaded_files` and nothing else.
    fn record_loading(executable: &str, loaded_files: Vec<String>) -> PrefetchRecord {
        PrefetchRecord {
            scca_version: 30,
            executable: executable.to_owned(),
            run_count: 1,
            last_runs: Vec::new(),
            volumes: Vec::new(),
            loaded_files,
        }
    }

    /// A library in a user's profile on the system volume is outside what Windows put there; the
    /// system volume's own `ntdll.dll` is not.
    #[test]
    fn a_profile_library_on_the_system_volume_is_outside() {
        let loaded = vec![
            ntdll_on(SYSTEM),
            format!(r"{SYSTEM}\USERS\U\APPDATA\LOCAL\TEMP\X.DLL"),
        ];
        assert_eq!(loaded_outside(&loaded), Ok(1));
    }

    /// Rest below `\Windows\`, `\Program Files\` and `\Program Files (x86)\` on the system volume is
    /// expected, whatever the case of the folder names.
    #[test]
    fn the_windows_and_program_folders_of_the_system_volume_are_expected() {
        let loaded = vec![
            ntdll_on(SYSTEM),
            format!(r"{SYSTEM}\Windows\System32\x.dll"),
            format!(r"{SYSTEM}\Program Files\A\b.dll"),
            format!(r"{SYSTEM}\Program Files (x86)\A\c.ocx"),
        ];
        assert_eq!(loaded_outside(&loaded), Ok(0));
    }

    /// The same folder on another volume is not the system's: a `\Windows\` elsewhere is outside.
    #[test]
    fn a_windows_folder_on_another_volume_is_outside() {
        let loaded = vec![ntdll_on(SYSTEM), format!(r"{OTHER}\Windows\x.dll")];
        assert_eq!(loaded_outside(&loaded), Ok(1));
    }

    /// Both `FiveM` program folders are expected on any volume, because the whole entry is below one.
    #[test]
    fn the_fivem_program_folders_are_expected_on_any_volume() {
        let loaded = vec![
            ntdll_on(SYSTEM),
            format!(r"{SYSTEM}\USERS\U\APPDATA\LOCAL\FIVEM\FIVEM.APP\x.dll"),
            format!(r"{OTHER}\Users\V\AppData\Local\FiveM for GTAV Enhanced\y.dll"),
        ];
        assert_eq!(loaded_outside(&loaded), Ok(0));
    }

    /// Only entries with an executable extension are counted: a picture and an ini file outside the
    /// expected folders are not.
    #[test]
    fn outside_entries_without_an_executable_extension_are_not_counted() {
        let loaded = vec![
            ntdll_on(SYSTEM),
            format!(r"{SYSTEM}\USERS\U\DOWNLOADS\a.png"),
            format!(r"{SYSTEM}\USERS\U\APPDATA\x.ini"),
        ];
        assert_eq!(loaded_outside(&loaded), Ok(0));
    }

    /// Without exactly one system volume there is no answer: none, two different ones, and an empty
    /// list are all `no_system_volume`, while two entries naming the same volume in another case agree.
    #[test]
    fn no_single_system_volume_gives_the_unknown_word() {
        assert_eq!(
            loaded_outside(&[format!(r"{SYSTEM}\Windows\x.dll")]),
            Err("no_system_volume")
        );
        assert_eq!(
            loaded_outside(&[ntdll_on(SYSTEM), ntdll_on(OTHER)]),
            Err("no_system_volume")
        );
        assert_eq!(loaded_outside(&[]), Err("no_system_volume"));
        assert_eq!(
            loaded_outside(&[
                ntdll_on(SYSTEM),
                format!(r"{SYSTEM}\Windows\System32\ntdll.dll"),
            ]),
            Ok(0)
        );
    }

    /// NTFS metadata (`\$`) and entries with no volume prefix are skipped, not counted as outside.
    #[test]
    fn ntfs_metadata_and_unprefixed_entries_are_skipped() {
        let loaded = vec![
            ntdll_on(SYSTEM),
            format!(r"{SYSTEM}\$MFT"),
            r"C:\x.dll".to_owned(),
        ];
        assert_eq!(loaded_outside(&loaded), Ok(0));
    }

    /// The program's own executable is not special: outside the expected folders it is counted.
    #[test]
    fn the_programs_own_executable_is_counted_when_it_is_outside() {
        let loaded = vec![
            ntdll_on(SYSTEM),
            format!(r"{SYSTEM}\STEAMLIBRARY\GAME\PLAYGTAV.EXE"),
        ];
        assert_eq!(loaded_outside(&loaded), Ok(1));
    }

    /// The count appears only for an executable that passes `counts_loaded_files`, and the unknown word
    /// only in place of it. Neither appears for another executable, and never both.
    #[test]
    fn the_observation_carries_the_count_or_the_unknown_word() {
        let outside = vec![
            ntdll_on(SYSTEM),
            format!(r"{SYSTEM}\USERS\U\APPDATA\LOCAL\TEMP\X.DLL"),
        ];

        let counted = execution(
            r"C:\Windows\Prefetch\RUNDLL32.EXE-12345678.pf",
            &record_loading("RUNDLL32.EXE", outside.clone()),
            None,
        );
        assert_eq!(field(&counted, "loaded_outside"), Some(&1_u64.into()));
        assert_eq!(field(&counted, "loaded_outside_unknown"), None);

        let not_counted = execution(
            r"C:\Windows\Prefetch\CMD.EXE-D269B812.pf",
            &record_loading("CMD.EXE", outside),
            None,
        );
        assert_eq!(field(&not_counted, "loaded_outside"), None);
        assert_eq!(field(&not_counted, "loaded_outside_unknown"), None);

        let unknown = execution(
            r"C:\Windows\Prefetch\FIVEM.EXE-11111111.pf",
            &record_loading("FIVEM.EXE", vec![format!(r"{SYSTEM}\Windows\x.dll")]),
            None,
        );
        assert_eq!(
            text(&unknown, "loaded_outside_unknown"),
            Some("no_system_volume")
        );
        assert_eq!(field(&unknown, "loaded_outside"), None);
    }

    /// **Nothing `loaded_files` holds is emitted.** The count is a number, and the observation's `Debug`
    /// text — the form a report's diagnostics take — carries no entry's path, name or volume identifier.
    #[test]
    fn no_loaded_path_or_volume_identifier_reaches_the_observation() {
        let observation = execution(
            r"C:\Windows\Prefetch\RUNDLL32.EXE-12345678.pf",
            &record_loading(
                "RUNDLL32.EXE",
                vec![
                    ntdll_on(SYSTEM),
                    format!(r"{SYSTEM}\USERS\U\APPDATA\LOCAL\TEMP\X.DLL"),
                ],
            ),
            None,
        );
        let debug = format!("{observation:?}");
        for withheld in ["TEMP", "X.DLL", "aaaaaaaa", "VOLUME"] {
            assert!(!debug.contains(withheld), "{withheld} in {debug}");
        }
        // The count is there, so this is not passing only because nothing was emitted.
        assert_eq!(field(&observation, "loaded_outside"), Some(&1_u64.into()));
    }
}
