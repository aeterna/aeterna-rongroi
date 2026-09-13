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
//! - **`loaded_files` is withheld whole.** It is normally hundreds of paths, some of them under a
//!   user's profile, and Prefetch writes them as `\VOLUME{…}\USERS\<account>\…` — a shape
//!   `rongroi_core::view::redact_user_paths` does not touch, because it has no drive letter. It is
//!   also, on its own, a list of what a person has on their computer, which ADR 0014 already refused
//!   to let redaction stand in for withholding.
//! - **`volumes` is withheld whole**, device path, serial number and creation time alike. A volume
//!   serial is not a person's name, but it identifies one machine across two reports, no rule can
//!   express a question about it, and the device path is the prefix of the list above.
//!
//! What is left — the program's name, how many times it ran and when it last ran — is what a rule
//! could use and is what this collector emits.
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

use rongroi_core::model::{CollectorRun, Observation, UnmeasuredReason};
use rongroi_host::{Host, Platform};
use rongroi_parsers::error::ParseError;
use rongroi_parsers::prefetch::{self, PrefetchRecord};

use crate::failure::{read_failure, reason_for};
use crate::{Collector, Field};

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
const FIELDS: [Field; 16] = [
    Field::number("enable_prefetcher"),
    Field::number("entries"),
    Field::number("files"),
    Field::text("folder"),
    Field::boolean("intact"),
    Field::timestamp("last_run"),
    Field::text("loaded_files_withheld"),
    Field::text("name"),
    Field::text("path"),
    Field::text("read"),
    Field::boolean("read_only"),
    Field::number("recorded_runs"),
    Field::number("rejected"),
    Field::number("run_count"),
    Field::number("scca_version"),
    Field::text("volumes_withheld"),
];

/// The fields that describe one program Prefetch recorded, as opposed to what the folder held.
///
/// This is the subset a content-level reason gaps: `source_empty`, `service_disabled` and `partial`
/// all describe a folder this collector **did** read, so gapping `files`, `entries`, `rejected` or
/// `intact` — which were measured — would claim it had not. The reasons that describe a folder
/// nothing was read from keep gapping every field (ADR 0030).
const RECORD_FIELDS: [&str; 6] = [
    "last_run",
    "name",
    "path",
    "recorded_runs",
    "run_count",
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
    fields.insert(
        "scca_version".to_owned(),
        serde_json::Value::from(record.scca_version),
    );
    Observation {
        collector: ID.to_owned(),
        fields,
    }
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
}
