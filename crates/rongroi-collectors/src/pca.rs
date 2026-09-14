// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! What the Program Compatibility Assistant recorded about programs that ran.
//!
//! PCA keeps three text files under `%WinDir%\appcompat\pca`. `PcaAppLaunchDic.txt` is a list of
//! `<full executable path>|<UTC timestamp>` lines; `PcaGeneralDb0.txt` and `PcaGeneralDb1.txt` hold
//! `|`-delimited records whose layout is reverse-engineered and whose positions
//! `rongroi_parsers::pca` deliberately does not name. The collector reads the bytes through the
//! `Host` and hands them to that parser; it decodes nothing itself (ADR 0013).
//!
//! No rule reads this collector yet (ADR 0020), so what it sees is listed in Self mode as unmatched
//! observations and counted, never listed, in SS mode (ADR 0014).
//!
//! # This is a list of what a person has on their computer
//!
//! Every launch record names a program the owner of the machine ran, so the fields are chosen to be
//! matchable by a rule and as little else as possible:
//!
//! - a full path is emitted **only when it begins with a drive letter**, which is the one shape
//!   `rongroi_core::view::redact_user_paths` can reach. Any other shape — a UNC share, a device
//!   path — is withheld, because a path carrying `\Users\<name>\` with no drive letter in front of
//!   it would reach an SS viewer unredacted while the code around it says paths are redacted;
//! - the general databases contribute **no record content at all**, only how many records they held
//!   and whether every line parsed. A field there has no established meaning, and field 1 of the
//!   lines this repository has is a user path;
//! - a rejected line's text is never emitted. `rongroi_parsers::pca::RejectedLine` says why: it
//!   normally contains a full user path, and the count carries the signal.

use std::collections::BTreeMap;

use rongroi_core::model::{CollectorRun, Observation, UnmeasuredReason};
use rongroi_host::{Host, Platform};
use rongroi_parsers::error::ParseError;
use rongroi_parsers::pca::{self, PcaLaunchEntry};

use crate::failure::{read_failure, reason_for};
use crate::paths::{UNREDACTABLE_FORM, file_name, is_drive_rooted};
use crate::{Collector, Field};

/// Environment variable holding the Windows directory.
pub const WINDOWS_DIR: &str = "WinDir";
/// PCA's folder, relative to `%WinDir%`.
pub const PCA_RELATIVE_PATH: &str = r"appcompat\pca";

/// Value of the `source` field for `PcaAppLaunchDic.txt`.
pub const APP_LAUNCH_DIC: &str = "app_launch_dic";

const ID: &str = "pca";

/// The three files PCA writes, each with the `source` value that names it in an observation.
///
/// The order is the order they are read in, and it is what decides which reason a run with more than
/// one unreadable file reports.
const SOURCES: [(&str, &str); 3] = [
    (APP_LAUNCH_DIC, "PcaAppLaunchDic.txt"),
    ("general_db0", "PcaGeneralDb0.txt"),
    ("general_db1", "PcaGeneralDb1.txt"),
];

/// First Windows build that keeps `%WinDir%\appcompat\pca` at all: Windows 11 22H2.
///
/// Tested present on 22621 and absent on 21H2 by the practitioner write-up ADR 0020 cites, and
/// corroborated by three others. Below it the folder has never existed, which is why the absence of
/// these files on a Windows 10 machine carries no information whatsoever (ADR 0030).
///
/// The PCA *feature* dates to Windows Vista; only the files are new. "PCA is on my Windows 10 box"
/// is true of the service and false of the artifact this collector reads.
pub const FIRST_BUILD_WITH_PCA_FILES: u32 = 22621;

/// Every reason this collector gives for not having looked (`Collector::unmeasured_reasons`).
///
/// `%WinDir%` is not set; this Windows is too old to keep the files; the folder is absent, or
/// present and holding none of them; some of the lines in a file did not yield a record; or a file
/// was denied, denied without administrator rights, or could not be read.
const REASONS: [UnmeasuredReason; 8] = [
    UnmeasuredReason::NotWindows,
    UnmeasuredReason::NotOnThisOs,
    UnmeasuredReason::NotAdmin,
    UnmeasuredReason::AccessDenied,
    UnmeasuredReason::SourceAbsent,
    UnmeasuredReason::SourceEmpty,
    UnmeasuredReason::Partial,
    UnmeasuredReason::ReadFailed,
];

/// Every field this collector can emit.
///
/// One PCA file that could not be read is a gap in all of them, unlike `fivem_dir`, where one
/// unreadable file among many omits one field of one observation. A PCA file is not one item in a
/// listing: it is the whole record of a class of launches, and losing it loses an unknown number of
/// entries. A rule that read a PCA absence as "not found" after that would be saying a program did
/// not run, on evidence that was never read.
const FIELDS: [Field; 9] = [
    Field::number("entries"),
    Field::boolean("intact"),
    Field::timestamp("last_run"),
    Field::text("name"),
    Field::text("path"),
    Field::text("path_withheld"),
    Field::text("read"),
    Field::number("rejected"),
    Field::text("source"),
];

/// The fields that describe one launch PCA recorded, as opposed to what a file held.
///
/// The subset a content-level reason gaps: `source_empty` and `partial` both describe files this
/// collector **did** reach, so gapping `entries`, `rejected`, `intact` or `source` — which were
/// measured — would claim it had not (ADR 0030).
const RECORD_FIELDS: [&str; 4] = ["last_run", "name", "path", "path_withheld"];

/// The `pca` collector.
#[derive(Debug, Default, Clone, Copy)]
pub struct Pca;

impl Collector for Pca {
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
        let Some(dir) = pca_dir(host) else {
            // Without `%WinDir%` there is no folder to look in, so nothing was looked at.
            return CollectorRun::Unmeasured {
                collector: ID.to_owned(),
                reason: UnmeasuredReason::ReadFailed,
            };
        };

        let mut observations = Vec::new();
        let mut first_failure = None;
        let mut anything_there = false;
        let mut rejected_lines = 0_usize;

        for (source, file) in SOURCES {
            let path = format!(r"{dir}\{file}");
            let failure = match host.read_file(&path) {
                // This file is not on the machine. Nothing is emitted for it and nothing is a gap:
                // the other two are still an honest reading of what PCA kept.
                Ok(None) => None,
                Ok(Some(bytes)) => {
                    anything_there = true;
                    read_source(source, &bytes, &mut observations, &mut rejected_lines)
                }
                Err(error) => {
                    // The file is there and Windows would not hand it over, or it is larger than a
                    // host will read. Either way it is emitted as an observation rather than only
                    // counted, because "unreadable" is exactly what an evader would arrange.
                    anything_there = true;
                    observations.push(status(source, read_failure(&error)));
                    Some(reason_for(host, &error))
                }
            };
            first_failure = first_failure.or(failure);
        }

        if !anything_there {
            // None of the three files is on this machine, and there are three different reasons for
            // that which used to be one word. Most specific first (ADR 0030).
            return CollectorRun::Unmeasured {
                collector: ID.to_owned(),
                reason: absence_of(host, &dir),
            };
        }

        let gaps = match first_failure {
            Some(reason) => gaps(reason),
            // Every file that was there was read, and some of its lines were not records. That is
            // not "nothing matched": an unknown number of launches is missing from what was read.
            None if rejected_lines > 0 => record_gaps(UnmeasuredReason::Partial),
            None => BTreeMap::new(),
        };
        CollectorRun::Measured {
            collector: ID.to_owned(),
            observations,
            gaps,
            discriminator_gaps: Vec::new(),
        }
    }
}

/// Why none of PCA's three files was there, most specific answer first.
///
/// - **This Windows is older than 22H2**, so the folder has never existed on it and its absence
///   carries no information. ADR 0020 chose `source_missing` here because the collector could not
///   tell that case apart from a Windows 11 machine that had written nothing; the build number was
///   in the report header the whole time and no collector read it (ADR 0030).
/// - **The folder is not there** on a build that would have kept it.
/// - **The folder is there and holds none of the three files**, which is a different statement:
///   OVAL will not call an absence meaningful until the structure that would hold it is present.
///
/// A folder that could not be listed answers `source_absent`, which is what this collector said
/// before it asked the question at all: guessing `source_empty` from a failed listing would claim
/// the folder was reached.
fn absence_of(host: &dyn Host, dir: &str) -> UnmeasuredReason {
    if predates_pca_files(host) {
        return UnmeasuredReason::NotOnThisOs;
    }
    match host.list_dir(dir) {
        Ok(Some(_)) => UnmeasuredReason::SourceEmpty,
        Ok(None) | Err(_) => UnmeasuredReason::SourceAbsent,
    }
}

/// Whether this Windows is older than the build that first kept PCA's files.
///
/// `false` when the build is not reported or is not a number: an absent header field is not evidence
/// about the operating system, and answering `true` from it would put a guess where the report says
/// it read something.
fn predates_pca_files(host: &dyn Host) -> bool {
    host.os_build()
        .and_then(|build| build.parse::<u32>().ok())
        .is_some_and(|build| build < FIRST_BUILD_WITH_PCA_FILES)
}

fn gaps(reason: UnmeasuredReason) -> BTreeMap<String, UnmeasuredReason> {
    FIELDS
        .iter()
        .map(|field| (field.name.to_owned(), reason))
        .collect()
}

/// A gap in what one launch record would have said, leaving what each file held measured.
fn record_gaps(reason: UnmeasuredReason) -> BTreeMap<String, UnmeasuredReason> {
    RECORD_FIELDS
        .iter()
        .map(|field| ((*field).to_owned(), reason))
        .collect()
}

fn pca_dir(host: &dyn Host) -> Option<String> {
    let windows = host.env_var(WINDOWS_DIR)?;
    let windows = windows.trim_end_matches(['\\', '/']);
    (!windows.is_empty()).then(|| format!(r"{windows}\{PCA_RELATIVE_PATH}"))
}

/// Parses one file's bytes and pushes what it yielded. Returns the reason a rule may not read this
/// collector as "not found", when the file could not be parsed at all, and adds the lines that were
/// not records to `rejected_lines`, which is what makes a partly-read file `partial` (ADR 0030).
fn read_source(
    source: &str,
    bytes: &[u8],
    observations: &mut Vec<Observation>,
    rejected_lines: &mut usize,
) -> Option<UnmeasuredReason> {
    if source == APP_LAUNCH_DIC {
        match pca::parse_app_launch_dic(bytes) {
            Ok(file) => {
                *rejected_lines += file.rejected.len();
                observations.push(integrity(source, file.entries.len(), file.rejected.len()));
                observations.extend(file.entries.iter().map(|entry| launch(source, entry)));
                None
            }
            Err(error) => {
                observations.push(status(source, parse_failure(&error)));
                Some(UnmeasuredReason::ReadFailed)
            }
        }
    } else {
        match pca::parse_general_db(bytes) {
            // Only how many records there were and whether they all parsed. `PcaGeneralEntry`
            // assigns no meaning to any position, so naming one here would put a guess into a
            // report a server admin is asked to trust — and one of the positions is a user path.
            Ok(file) => {
                *rejected_lines += file.rejected.len();
                observations.push(integrity(source, file.entries.len(), file.rejected.len()));
                None
            }
            Err(error) => {
                observations.push(status(source, parse_failure(&error)));
                Some(UnmeasuredReason::ReadFailed)
            }
        }
    }
}

/// One launch record: which file it came from, the program's name, where it ran from, and when.
fn launch(source: &str, entry: &PcaLaunchEntry) -> Observation {
    let mut fields = BTreeMap::new();
    fields.insert("source".to_owned(), serde_json::Value::from(source));
    if let Some(name) = file_name(&entry.path) {
        fields.insert("name".to_owned(), serde_json::Value::from(name));
    }
    if is_drive_rooted(&entry.path) {
        fields.insert(
            "path".to_owned(),
            serde_json::Value::from(entry.path.clone()),
        );
    } else {
        // Said out loud rather than left out: an absent `path` would read as "PCA recorded no path",
        // which is not what happened.
        fields.insert(
            "path_withheld".to_owned(),
            serde_json::Value::from(UNREDACTABLE_FORM),
        );
    }
    fields.insert(
        "last_run".to_owned(),
        serde_json::Value::from(entry.last_run.to_string()),
    );
    Observation {
        collector: ID.to_owned(),
        fields,
    }
}

/// How much one file held and whether all of it parsed.
///
/// `intact` is `rejected == 0` as a value of its own because a rule matches by exact equality and
/// cannot say "more than none" (ADR 0020). The counts are there for the person reading Self mode.
fn integrity(source: &str, entries: usize, rejected: usize) -> Observation {
    let mut fields = BTreeMap::new();
    fields.insert("source".to_owned(), serde_json::Value::from(source));
    fields.insert("entries".to_owned(), serde_json::Value::from(entries));
    fields.insert("rejected".to_owned(), serde_json::Value::from(rejected));
    fields.insert("intact".to_owned(), serde_json::Value::from(rejected == 0));
    Observation {
        collector: ID.to_owned(),
        fields,
    }
}

/// One file that is on the machine and yielded nothing, with what stopped it.
///
/// It carries no `name`, `path` or `last_run`, so a rule written for a launch record never matches
/// one of these and a rule written for this never matches a launch record.
fn status(source: &str, read: &'static str) -> Observation {
    let mut fields = BTreeMap::new();
    fields.insert("source".to_owned(), serde_json::Value::from(source));
    fields.insert("read".to_owned(), serde_json::Value::from(read));
    Observation {
        collector: ID.to_owned(),
        fields,
    }
}

/// Value of the `read` field for a file whose bytes arrived and are not this artifact.
///
/// Finer than the `gaps` reason on purpose: a reviewer needs to tell "Windows would not let me read
/// it" from "it is not the format it should be", and only the second of those is a machine that has
/// something odd in `appcompat\pca`.
fn parse_failure(error: &ParseError) -> &'static str {
    match error {
        ParseError::Truncated { .. } => "truncated",
        ParseError::Malformed { .. } => "not_pca_text",
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use rongroi_host::{FixtureHost, NonWindowsHost};

    use super::*;

    const PCA_DIR: &str = r"C:\Windows\appcompat\pca";

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

    /// Every observation of one source, in the order the collector emitted them.
    fn of_source<'a>(observations: &'a [Observation], source: &str) -> Vec<&'a Observation> {
        observations
            .iter()
            .filter(|observation| text(observation, "source") == Some(source))
            .collect()
    }

    /// The launch records of one source: the observations that carry a time.
    fn launches<'a>(observations: &'a [Observation], source: &str) -> Vec<&'a Observation> {
        of_source(observations, source)
            .into_iter()
            .filter(|observation| observation.fields.contains_key("last_run"))
            .collect()
    }

    #[test]
    fn launch_records_are_observed() {
        let run = Pca.collect(&fixture("pca-files-present"));
        let (observations, gaps) = measured(&run);
        assert!(gaps.is_empty(), "{gaps:?}");

        let entries = launches(observations, APP_LAUNCH_DIC);
        assert_eq!(entries.len(), 3, "{entries:?}");
        assert_eq!(entries[0].collector, "pca");
        assert_eq!(
            text(entries[0], "path"),
            Some(r"C:\Users\alex\Downloads\game.exe")
        );
        assert_eq!(text(entries[0], "name"), Some("game.exe"));
        assert_eq!(text(entries[0], "last_run"), Some("2026-09-12T10:23:46Z"));
        assert_eq!(entries[0].fields.get("path_withheld"), None);
    }

    /// A file that parsed says so, with what it held.
    #[test]
    fn each_file_reports_how_much_it_held_and_whether_it_was_intact() {
        let run = Pca.collect(&fixture("pca-files-present"));
        let (observations, _) = measured(&run);

        for (source, entries) in [
            (APP_LAUNCH_DIC, 3_u64),
            ("general_db0", 2),
            ("general_db1", 2),
        ] {
            let integrity = of_source(observations, source)
                .into_iter()
                .find(|observation| observation.fields.contains_key("entries"))
                .unwrap_or_else(|| panic!("no integrity observation for {source}"));
            assert_eq!(field(integrity, "entries"), Some(&entries.into()));
            assert_eq!(field(integrity, "rejected"), Some(&0_u64.into()));
            assert_eq!(field(integrity, "intact"), Some(&true.into()));
        }
    }

    /// The general databases' positions have no established meaning and one of them is a user path,
    /// so nothing of their records is emitted — not even under a made-up field name.
    #[test]
    fn the_general_databases_contribute_no_record_content() {
        let run = Pca.collect(&fixture("pca-files-present"));
        let (observations, _) = measured(&run);

        assert!(launches(observations, "general_db0").is_empty());
        assert!(launches(observations, "general_db1").is_empty());
        let json = serde_json::to_string(&observations).unwrap();
        // `Example Ltd` and `Cfx.re` are only in the general-database fixtures.
        assert!(!json.contains("Example Ltd"), "{json}");
        assert!(!json.contains("Cfx.re"), "{json}");
    }

    /// **The single largest false-positive class this collector has.** `C:\Windows\appcompat\pca`
    /// arrived in Windows 11 22H2, so on a Windows 10 machine — still a large share of gaming PCs —
    /// its absence carries no information at all. ADR 0020 could not tell that apart from a Windows
    /// 11 machine that had written nothing and said `source_missing` for both; the build number was
    /// in the report header the whole time (ADR 0030).
    #[test]
    fn a_windows_older_than_22h2_has_never_had_these_files() {
        assert_eq!(
            Pca.collect(&fixture("pca-not-present")),
            CollectorRun::Unmeasured {
                collector: "pca".to_owned(),
                reason: UnmeasuredReason::NotOnThisOs,
            }
        );
    }

    /// The same absence on a build that does keep the files, with the folder itself not there.
    #[test]
    fn no_pca_folder_on_a_build_that_keeps_it_is_source_absent() {
        assert_eq!(
            Pca.collect(&fixture("pca-folder-absent")),
            CollectorRun::Unmeasured {
                collector: "pca".to_owned(),
                reason: UnmeasuredReason::SourceAbsent,
            }
        );
    }

    /// And the third statement the one word used to make: the folder is there and holds none of the
    /// three files. OVAL will not call an absence meaningful until the structure that would hold it
    /// is present, and this is the case where it is.
    #[test]
    fn a_pca_folder_holding_none_of_the_files_is_source_empty() {
        assert_eq!(
            Pca.collect(&fixture("pca-folder-empty")),
            CollectorRun::Unmeasured {
                collector: "pca".to_owned(),
                reason: UnmeasuredReason::SourceEmpty,
            }
        );
    }

    /// The build number decides it, and a build this program cannot read is not an answer about the
    /// operating system.
    #[test]
    fn the_build_number_is_read_and_never_guessed() {
        let with = |build: &str| {
            FixtureHost::from_yaml_str(&format!("platform: windows\nos_build: {build}\n"), "inline")
                .unwrap()
        };
        assert!(predates_pca_files(&with("'19045'")));
        assert!(predates_pca_files(&with("'22000'")));
        assert!(!predates_pca_files(&with("'22621'")));
        assert!(!predates_pca_files(&with("'26100'")));
        // Not reported, and reported as something that is not a build number.
        let unknown = FixtureHost::from_yaml_str("platform: windows\n", "inline").unwrap();
        assert!(!predates_pca_files(&unknown));
        assert!(!predates_pca_files(&with("'22H2'")));
    }

    /// Denied, and this program could have asked for administrator rights and did not have them.
    #[test]
    fn access_denied_without_admin_rights_is_a_not_admin_gap_and_is_still_shown() {
        let run = Pca.collect(&fixture("pca-access-denied"));
        let (observations, gaps) = measured(&run);

        // Every file says, in the report a person reads, that it could not be read.
        assert_eq!(observations.len(), 3, "{observations:?}");
        for observation in observations {
            assert_eq!(text(observation, "read"), Some("access_denied"));
            assert_eq!(observation.fields.get("path"), None);
        }
        for field in FIELDS {
            let name = field.name;
            assert_eq!(gaps.get(name), Some(&UnmeasuredReason::NotAdmin), "{name}");
        }
    }

    /// One file is listed and has no bytes; the other two are readable. What was read is still
    /// reported, and the whole run is still a gap — a PCA file is a record of launches, so losing one
    /// loses an unknown number of them.
    #[test]
    fn one_unreadable_file_is_reported_and_gaps_the_run() {
        let run = Pca.collect(&fixture("pca-file-unreadable"));
        let (observations, gaps) = measured(&run);

        let denied = of_source(observations, APP_LAUNCH_DIC);
        assert_eq!(denied.len(), 1, "{denied:?}");
        assert_eq!(text(denied[0], "read"), Some("failed"));
        // The readable file was still read.
        assert_eq!(of_source(observations, "general_db0").len(), 1);
        for field in FIELDS {
            let name = field.name;
            assert_eq!(
                gaps.get(name),
                Some(&UnmeasuredReason::ReadFailed),
                "{name}"
            );
        }
    }

    /// Both halves of what the parser hands back: the lines that parsed, and an account of the ones
    /// that did not. A file with a bad line in it is not a file that was lost.
    #[test]
    fn a_malformed_file_reports_what_parsed_and_what_did_not() {
        let run = Pca.collect(&fixture("pca-malformed-lines"));
        let (observations, gaps) = measured(&run);
        // The file was read and three of its lines were not records, so an unknown number of
        // launches is missing from what was read: that is `partial`, not "nothing matched"
        // (ADR 0030). What each file held is still measured and is not gapped.
        for name in RECORD_FIELDS {
            assert_eq!(gaps.get(name), Some(&UnmeasuredReason::Partial), "{name}");
        }
        assert_eq!(gaps.get("entries"), None);
        assert_eq!(gaps.get("intact"), None);

        let integrity = of_source(observations, APP_LAUNCH_DIC)
            .into_iter()
            .find(|observation| observation.fields.contains_key("entries"))
            .expect("an integrity observation");
        assert_eq!(field(integrity, "entries"), Some(&2_u64.into()));
        assert_eq!(field(integrity, "rejected"), Some(&3_u64.into()));
        assert_eq!(field(integrity, "intact"), Some(&false.into()));

        let entries = launches(observations, APP_LAUNCH_DIC);
        assert_eq!(entries.len(), 2, "{entries:?}");
        assert_eq!(text(entries[0], "name"), Some("first.exe"));
        assert_eq!(text(entries[1], "name"), Some("third.exe"));
    }

    /// The text of a rejected line normally holds a full user path, so it is never emitted.
    #[test]
    fn a_rejected_lines_text_never_reaches_an_observation() {
        let run = Pca.collect(&fixture("pca-malformed-lines"));
        let (observations, _) = measured(&run);
        let json = serde_json::to_string(&observations).unwrap();
        assert!(!json.contains("this line has no delimiter"), "{json}");
        assert!(!json.contains("second.exe"), "{json}");
    }

    /// A path that SS-mode redaction cannot reach is withheld, and the observation says it was.
    #[test]
    fn a_path_redaction_cannot_reach_is_withheld() {
        let run = Pca.collect(&fixture("pca-unredactable-path"));
        let (observations, _) = measured(&run);
        let entries = launches(observations, APP_LAUNCH_DIC);
        assert_eq!(entries.len(), 3, "{entries:?}");

        // A drive-rooted path is the shape `redact_user_paths` was written for, so it is emitted.
        assert_eq!(
            text(entries[0], "path"),
            Some(r"C:\Users\fixtureuser\Downloads\drive-rooted.exe")
        );

        // A UNC path carries an account name that redaction would walk straight past.
        assert_eq!(entries[1].fields.get("path"), None);
        assert_eq!(text(entries[1], "path_withheld"), Some(UNREDACTABLE_FORM));
        assert_eq!(text(entries[1], "name"), Some("unc.exe"));

        // A device path has no drive letter either.
        assert_eq!(entries[2].fields.get("path"), None);
        assert_eq!(text(entries[2], "path_withheld"), Some(UNREDACTABLE_FORM));

        let json = serde_json::to_string(&observations).unwrap();
        assert!(!json.contains("shareduser"), "{json}");
        assert!(!json.contains("deviceuser"), "{json}");
    }

    #[test]
    fn a_file_that_is_not_pca_text_is_reported_as_such() {
        let run = Pca.collect(&fixture("pca-utf16-file"));
        let (observations, gaps) = measured(&run);
        let refused = of_source(observations, APP_LAUNCH_DIC);
        assert_eq!(refused.len(), 1, "{refused:?}");
        assert_eq!(text(refused[0], "read"), Some("not_pca_text"));
        for field in FIELDS {
            let name = field.name;
            assert_eq!(
                gaps.get(name),
                Some(&UnmeasuredReason::ReadFailed),
                "{name}"
            );
        }
    }

    #[test]
    fn non_windows_is_unmeasured() {
        assert_eq!(
            Pca.collect(&NonWindowsHost),
            CollectorRun::Unmeasured {
                collector: "pca".to_owned(),
                reason: UnmeasuredReason::NotWindows,
            }
        );
    }

    #[test]
    fn windir_unset_is_unmeasured() {
        let host = FixtureHost::from_yaml_str("platform: windows\n", "inline").unwrap();
        assert_eq!(
            Pca.collect(&host),
            CollectorRun::Unmeasured {
                collector: "pca".to_owned(),
                reason: UnmeasuredReason::ReadFailed,
            }
        );
    }

    #[test]
    fn the_folder_is_built_from_the_environment_and_not_hardcoded() {
        let host = FixtureHost::from_yaml_str(
            "platform: windows\nenv:\n  WinDir: 'D:\\Windows\\'\n",
            "inline",
        )
        .unwrap();
        assert_eq!(pca_dir(&host).as_deref(), Some(r"D:\Windows\appcompat\pca"));
        // And the fixture hosts describe the folder this builds on an ordinary machine.
        let ordinary = fixture("pca-files-present");
        assert_eq!(pca_dir(&ordinary).as_deref(), Some(PCA_DIR));
    }
}
