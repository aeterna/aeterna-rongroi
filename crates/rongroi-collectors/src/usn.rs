// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! The system volume's NTFS change journal, counted for the folders other collectors read (ADR 0047).
//!
//! The journal records every file created, changed, renamed or deleted on a volume, by name. This
//! collector reads it to the end and keeps, of each record, only whether its parent folder is one of
//! five this program already reads — Prefetch, the Event Log folder, the Program Compatibility
//! Assistant folder and `FiveM`'s two plugin folders — and why the record was written. **No file name
//! reaches this module**: `rongroi_parsers::usn` never reads one. No journal identifier, USN or file
//! reference number reaches an observation either, because each identifies one machine or one file
//! across two reports (ADR 0021).
//!
//! Records are counted, never listed. A count of deletions is not evidence of cleaning: Prefetch keeps
//! a bounded number of files and removes the rest itself, and a player removes a `ReShade` preset. No rule
//! reads this collector (ADR 0047, "Rules").
//!
//! A version 3 record is attributed to a folder by its 128-bit identifier, which ADR 0047 measured on a
//! GitHub-hosted runner. A version 2 record is attributed by the folder's 64-bit index, which was not
//! measured, because the runner returned no version 2 record. Either comparison can fail to attribute a
//! record; neither attributes one to the wrong folder on the **system volume**, because two files on one
//! volume never share an identifier. Attribution only ever compares identifiers read from that one
//! volume: this collector reads the system volume's own identifier once, from its root (`X:\`), and a
//! watched folder whose identifier names a different volume — the shape a junction to another drive
//! produces — is reported `other_volume` rather than counted, because its number could otherwise collide
//! with an unrelated file's on the volume the journal belongs to.
//!
//! This program's own launch writes a Prefetch record where Prefetch is on, and the Prefetch counts
//! include it: a count carries neither a path nor a SHA-256 for ADR 0010 to separate it by.

use std::collections::BTreeMap;
use std::ops::ControlFlow;
use std::time::{Duration, Instant};

use jiff::Timestamp;
use rongroi_core::model::{CollectorRun, DiscriminatorGaps, Observation, UnmeasuredReason};
use rongroi_host::{FileId, Host, Platform, UsnReadEnd};
use rongroi_parsers::usn::{self, ParentReference, UsnRecord};

use crate::failure::reason_for;
use crate::{Collector, Coverage, Field, evtx, fivem_dir, pca, prefetch};

const ID: &str = "usn";
/// The field that says which place an observation is about (ADR 0044): a watched folder, or the journal.
const DISCRIMINATOR: &str = "location";
/// Value of `location` for the observation about the journal itself.
pub const JOURNAL_LOCATION: &str = "journal";
/// Value of `location` for `%SystemRoot%\Prefetch`.
pub const PREFETCH_LOCATION: &str = "prefetch";
/// Value of `location` for `%SystemRoot%\System32\winevt\Logs`.
pub const WINEVT_LOGS_LOCATION: &str = "winevt_logs";
/// Value of `location` for `%WinDir%\appcompat\pca`.
pub const APPCOMPAT_PCA_LOCATION: &str = "appcompat_pca";

/// `folder` when the folder's identifiers were read and its records counted.
pub const FOLDER_IDENTIFIED: &str = "identified";
/// `folder` when nothing is at the folder's path.
pub const FOLDER_ABSENT: &str = "absent";
/// `folder` when the folder's path or identifiers could not be read.
pub const FOLDER_UNREADABLE: &str = "unreadable";
/// `folder` when the folder is on another volume than the one whose journal was read.
pub const FOLDER_OTHER_VOLUME: &str = "other_volume";

/// How long this collector reads the journal before it stops and says so. Checked between buffers.
/// ADR 0047 measured about one second for a 32 MiB journal; an administrator can make one larger.
pub const BUDGET: Duration = Duration::from_secs(30);

static FIELDS: [Field; 13] = [
    Field::number("created"),
    Field::number("data_changed"),
    Field::number("deleted"),
    Field::timestamp("first_seen"),
    Field::text("folder"),
    Field::timestamp("last_seen"),
    Field::text("location"),
    Field::number("maximum_size"),
    Field::number("records"),
    Field::number("records_version_2"),
    Field::number("records_version_3"),
    Field::number("renamed"),
    Field::boolean("trimmed"),
];

/// The fields a read that did not finish leaves unanswered.
const COUNTED: [&str; 9] = [
    "created",
    "data_changed",
    "deleted",
    "first_seen",
    "last_seen",
    "records",
    "records_version_2",
    "records_version_3",
    "renamed",
];

static REASONS: [UnmeasuredReason; 7] = [
    UnmeasuredReason::NotWindows,
    UnmeasuredReason::NotAdmin,
    UnmeasuredReason::AccessDenied,
    UnmeasuredReason::SourceAbsent,
    UnmeasuredReason::Partial,
    UnmeasuredReason::BudgetSpent,
    UnmeasuredReason::ReadFailed,
];

/// One folder this collector counts records for.
struct Place {
    location: &'static str,
    base: &'static str,
    relative: &'static str,
}

const PLACES: [Place; 5] = [
    Place {
        location: PREFETCH_LOCATION,
        base: prefetch::SYSTEM_ROOT,
        relative: prefetch::PREFETCH_RELATIVE_PATH,
    },
    Place {
        location: WINEVT_LOGS_LOCATION,
        base: evtx::SYSTEM_ROOT,
        relative: evtx::LOGS_RELATIVE_PATH,
    },
    Place {
        location: APPCOMPAT_PCA_LOCATION,
        base: pca::WINDOWS_DIR,
        relative: pca::PCA_RELATIVE_PATH,
    },
    Place {
        location: fivem_dir::PLUGINS_LOCATION,
        base: fivem_dir::LOCAL_APP_DATA,
        relative: fivem_dir::PLUGINS_RELATIVE_PATH,
    },
    Place {
        location: fivem_dir::ENHANCED_ASI_LOCATION,
        base: fivem_dir::ROAMING_APP_DATA,
        relative: fivem_dir::ENHANCED_ASI_RELATIVE_PATH,
    },
];

/// Reads the system volume's change journal.
#[derive(Debug, Clone, Copy)]
pub struct Usn {
    /// How long a read may take before it stops with `budget_spent`.
    pub budget: Duration,
}

impl Default for Usn {
    fn default() -> Self {
        Self { budget: BUDGET }
    }
}

impl Collector for Usn {
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

    /// The journal's own oldest and newest record (ADR 0051). The watched folders carry the same two
    /// fields about their own records, which is activity rather than what the journal could see.
    fn coverage(&self) -> Option<Coverage> {
        Some(Coverage {
            from: "first_seen",
            to: "last_seen",
            place: Some(JOURNAL_LOCATION),
        })
    }

    fn collect(&self, host: &dyn Host) -> CollectorRun {
        let unmeasured = |reason| CollectorRun::Unmeasured {
            collector: ID.to_owned(),
            reason,
        };
        if host.platform() != Platform::Windows {
            return unmeasured(UnmeasuredReason::NotWindows);
        }
        let Some(volume) = host
            .env_var(prefetch::SYSTEM_ROOT)
            .as_deref()
            .and_then(drive_letter)
        else {
            // Without `%SystemRoot%` there is no system volume to read, so nothing was looked at.
            return unmeasured(UnmeasuredReason::ReadFailed);
        };
        // The system volume's own identifier, read once, so every watched folder's identifier can be
        // checked against it: a folder reached through a junction to another volume answers with a
        // different `volume_serial`, and its records must not be counted as this volume's own.
        let root_serial = match host.file_id(&format!(r"{volume}:\")) {
            Ok(Some(id)) => id.volume_serial,
            Ok(None) => return unmeasured(UnmeasuredReason::ReadFailed),
            Err(error) => return unmeasured(reason_for(host, &error)),
        };

        let places: Vec<(&Place, Located)> = PLACES
            .iter()
            .map(|place| (place, locate(host, place, volume, root_serial)))
            .collect();
        let watched: Vec<(&'static str, FileId)> = places
            .iter()
            .filter_map(|(place, located)| match located {
                Located::Identified(id) => Some((place.location, *id)),
                _ => None,
            })
            .collect();

        let mut tally = Tally::new(&watched);
        let started = Instant::now();
        let read = host.read_usn_journal(volume, &mut |bytes| {
            if started.elapsed() >= self.budget {
                return ControlFlow::Break(());
            }
            tally.add(bytes);
            ControlFlow::Continue(())
        });
        let read = match read {
            Ok(Some(read)) => read,
            Ok(None) => return unmeasured(UnmeasuredReason::SourceAbsent),
            Err(error) => return unmeasured(reason_for(host, &error)),
        };

        let mut observations = vec![tally.journal_observation(
            read.state.first_usn != read.state.lowest_valid_usn,
            read.state.maximum_size,
        )];
        let mut discriminator_gaps = Vec::new();
        for (place, located) in &places {
            let (observation, gap) = tally.folder_observation(place.location, located);
            observations.push(observation);
            if let Some(reason) = gap {
                discriminator_gaps.push(DiscriminatorGaps {
                    discriminator: DISCRIMINATOR.to_owned(),
                    value: serde_json::Value::from(place.location),
                    gaps: every_field_but_location(reason),
                });
            }
        }

        CollectorRun::Measured {
            collector: ID.to_owned(),
            observations,
            gaps: counted_gaps(tally.damaged, read.end),
            discriminator_gaps,
        }
    }
}

/// The run's gaps on the fields a read that did not finish leaves unanswered. A damaged buffer
/// outranks how the read ended: records after the damage were never parsed, whatever came next.
fn counted_gaps(damaged: bool, end: UsnReadEnd) -> BTreeMap<String, UnmeasuredReason> {
    let unfinished = if damaged {
        Some(UnmeasuredReason::ReadFailed)
    } else {
        match end {
            UsnReadEnd::Complete => None,
            UsnReadEnd::JournalChanged => Some(UnmeasuredReason::Partial),
            UsnReadEnd::Stopped => Some(UnmeasuredReason::BudgetSpent),
        }
    };
    unfinished
        .map(|reason| {
            COUNTED
                .iter()
                .map(|field| ((*field).to_owned(), reason))
                .collect()
        })
        .unwrap_or_default()
}

/// The drive letter a path begins with, upper-cased.
fn drive_letter(path: &str) -> Option<char> {
    let mut chars = path.chars();
    let letter = chars.next().filter(char::is_ascii_alphabetic)?;
    (chars.next() == Some(':')).then(|| letter.to_ascii_uppercase())
}

/// What was learned of one watched folder before the journal was read.
enum Located {
    Identified(FileId),
    Absent,
    Unreadable(UnmeasuredReason),
    OtherVolume,
}

fn locate(host: &dyn Host, place: &Place, volume: char, root_serial: u64) -> Located {
    let Some(base) = host.env_var(place.base) else {
        return Located::Unreadable(UnmeasuredReason::ReadFailed);
    };
    let base = base.trim_end_matches(['\\', '/']);
    if base.is_empty() {
        return Located::Unreadable(UnmeasuredReason::ReadFailed);
    }
    if drive_letter(base) != Some(volume) {
        return Located::OtherVolume;
    }
    match host.file_id(&format!(r"{base}\{}", place.relative)) {
        // A folder can share the volume's drive letter and still be on another volume, reached through
        // a junction: its identifier is only unique within its own volume, so this is the check that
        // keeps a record from being credited to a folder that was never read (ADR 0047 amendment).
        Ok(Some(id)) if id.volume_serial != root_serial => Located::OtherVolume,
        Ok(Some(id)) => Located::Identified(id),
        Ok(None) => Located::Absent,
        Err(error) => Located::Unreadable(reason_for(host, &error)),
    }
}

fn every_field_but_location(reason: UnmeasuredReason) -> BTreeMap<String, UnmeasuredReason> {
    FIELDS
        .iter()
        .filter(|field| field.name != DISCRIMINATOR)
        .map(|field| (field.name.to_owned(), reason))
        .collect()
}

/// What one folder's records add up to.
#[derive(Default)]
struct Counts {
    records: usize,
    created: usize,
    deleted: usize,
    renamed: usize,
    data_changed: usize,
    first: Option<Timestamp>,
    last: Option<Timestamp>,
}

impl Counts {
    fn add(&mut self, record: &UsnRecord) {
        self.records += 1;
        let has = |flags: u32| record.reason & flags != 0;
        self.created += usize::from(has(usn::REASON_FILE_CREATE));
        self.deleted += usize::from(has(usn::REASON_FILE_DELETE));
        self.renamed += usize::from(has(
            usn::REASON_RENAME_OLD_NAME | usn::REASON_RENAME_NEW_NAME
        ));
        self.data_changed += usize::from(has(usn::REASON_DATA_OVERWRITE
            | usn::REASON_DATA_EXTEND
            | usn::REASON_DATA_TRUNCATION));
        if let Some(written) = record.written {
            self.first = Some(self.first.map_or(written, |first| first.min(written)));
            self.last = Some(self.last.map_or(written, |last| last.max(written)));
        }
    }

    fn times(&self, fields: &mut BTreeMap<String, serde_json::Value>) {
        if let (Some(first), Some(last)) = (self.first, self.last) {
            fields.insert(
                "first_seen".to_owned(),
                serde_json::Value::from(first.to_string()),
            );
            fields.insert(
                "last_seen".to_owned(),
                serde_json::Value::from(last.to_string()),
            );
        }
    }
}

/// Everything counted while the journal was read.
struct Tally {
    watched: Vec<(&'static str, FileId, Counts)>,
    all: Counts,
    version_2: usize,
    version_3: usize,
    damaged: bool,
}

impl Tally {
    fn new(watched: &[(&'static str, FileId)]) -> Self {
        Self {
            watched: watched
                .iter()
                .map(|(location, id)| (*location, *id, Counts::default()))
                .collect(),
            all: Counts::default(),
            version_2: 0,
            version_3: 0,
            damaged: false,
        }
    }

    fn add(&mut self, bytes: &[u8]) {
        let Ok(buffer) = usn::parse_buffer(bytes) else {
            self.damaged = true;
            return;
        };
        self.damaged |= buffer.damage.is_some();
        for record in &buffer.records {
            match record.major_version {
                2 => self.version_2 += 1,
                _ => self.version_3 += 1,
            }
            self.all.add(record);
            for (_, id, counts) in &mut self.watched {
                let here = match record.parent {
                    ParentReference::Id128(parent) => parent == id.id_128,
                    ParentReference::Index64(parent) => parent == id.index_64,
                };
                if here {
                    counts.add(record);
                }
            }
        }
    }

    fn journal_observation(&self, trimmed: bool, maximum_size: u64) -> Observation {
        let mut fields = BTreeMap::new();
        fields.insert(
            "location".to_owned(),
            serde_json::Value::from(JOURNAL_LOCATION),
        );
        fields.insert(
            "records".to_owned(),
            serde_json::Value::from(self.all.records),
        );
        fields.insert(
            "records_version_2".to_owned(),
            serde_json::Value::from(self.version_2),
        );
        fields.insert(
            "records_version_3".to_owned(),
            serde_json::Value::from(self.version_3),
        );
        fields.insert("trimmed".to_owned(), serde_json::Value::from(trimmed));
        fields.insert(
            "maximum_size".to_owned(),
            serde_json::Value::from(maximum_size),
        );
        self.all.times(&mut fields);
        Observation {
            collector: ID.to_owned(),
            fields,
        }
    }

    fn folder_observation(
        &self,
        location: &'static str,
        located: &Located,
    ) -> (Observation, Option<UnmeasuredReason>) {
        let mut fields = BTreeMap::new();
        fields.insert("location".to_owned(), serde_json::Value::from(location));
        let gap = match located {
            Located::Identified(_) => {
                fields.insert(
                    "folder".to_owned(),
                    serde_json::Value::from(FOLDER_IDENTIFIED),
                );
                if let Some((_, _, counts)) = self
                    .watched
                    .iter()
                    .find(|(watched, _, _)| *watched == location)
                {
                    fields.insert(
                        "records".to_owned(),
                        serde_json::Value::from(counts.records),
                    );
                    fields.insert(
                        "created".to_owned(),
                        serde_json::Value::from(counts.created),
                    );
                    fields.insert(
                        "deleted".to_owned(),
                        serde_json::Value::from(counts.deleted),
                    );
                    fields.insert(
                        "renamed".to_owned(),
                        serde_json::Value::from(counts.renamed),
                    );
                    fields.insert(
                        "data_changed".to_owned(),
                        serde_json::Value::from(counts.data_changed),
                    );
                    counts.times(&mut fields);
                }
                None
            }
            Located::Absent => {
                fields.insert("folder".to_owned(), serde_json::Value::from(FOLDER_ABSENT));
                Some(UnmeasuredReason::SourceAbsent)
            }
            Located::Unreadable(reason) => {
                fields.insert(
                    "folder".to_owned(),
                    serde_json::Value::from(FOLDER_UNREADABLE),
                );
                Some(*reason)
            }
            Located::OtherVolume => {
                fields.insert(
                    "folder".to_owned(),
                    serde_json::Value::from(FOLDER_OTHER_VOLUME),
                );
                // Not `not_attempted`: that reason's fixed wording ("this was not read — the scan
                // stopped before reaching it") and its scope-statement handling in `rongroi-core::view`
                // both say this program stopped short of something it otherwise would have reached.
                // A folder on another volume was never reachable from the one journal this collector
                // reads at all — `folder: other_volume` already says why — so this is a read this
                // collector could not do, `read_failed`, not one it deferred.
                Some(UnmeasuredReason::ReadFailed)
            }
        };
        (
            Observation {
                collector: ID.to_owned(),
                fields,
            },
            gap,
        )
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use rongroi_host::{FixtureHost, NonWindowsHost};

    use super::*;

    fn fixture(name: &str) -> FixtureHost {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/hosts")
            .join(name);
        FixtureHost::load(&dir).unwrap()
    }

    fn measured(
        run: &CollectorRun,
    ) -> (
        &[Observation],
        &BTreeMap<String, UnmeasuredReason>,
        &[DiscriminatorGaps],
    ) {
        match run {
            CollectorRun::Measured {
                observations,
                gaps,
                discriminator_gaps,
                ..
            } => (observations, gaps, discriminator_gaps),
            CollectorRun::Unmeasured { .. } => panic!("expected a measured run, got {run:?}"),
        }
    }

    fn at<'a>(observations: &'a [Observation], location: &str) -> &'a Observation {
        observations
            .iter()
            .find(|observation| observation.fields["location"] == location)
            .unwrap_or_else(|| panic!("no observation for {location}"))
    }

    fn unmeasured(run: &CollectorRun) -> UnmeasuredReason {
        match run {
            CollectorRun::Unmeasured { reason, .. } => *reason,
            CollectorRun::Measured { .. } => panic!("expected an unmeasured run, got {run:?}"),
        }
    }

    #[test]
    fn counts_records_per_watched_folder_and_names_none() {
        let run = Usn::default().collect(&fixture("usn-journal-read"));
        let (observations, gaps, discriminator_gaps) = measured(&run);
        assert!(gaps.is_empty());

        let journal = at(observations, JOURNAL_LOCATION);
        assert_eq!(journal.fields["records"], 710);
        assert_eq!(journal.fields["records_version_3"], 710);
        assert_eq!(journal.fields["records_version_2"], 0);
        assert_eq!(journal.fields["trimmed"], true);
        assert_eq!(journal.fields["maximum_size"], 33_554_432);
        assert_eq!(journal.fields["first_seen"], "2026-09-08T01:11:56Z");

        let prefetch = at(observations, PREFETCH_LOCATION);
        assert_eq!(prefetch.fields["folder"], FOLDER_IDENTIFIED);
        assert_eq!(prefetch.fields["records"], 3);
        assert_eq!(prefetch.fields["created"], 2);
        assert_eq!(prefetch.fields["deleted"], 1);
        assert_eq!(prefetch.fields["data_changed"], 2);
        assert_eq!(prefetch.fields["renamed"], 0);
        assert_eq!(prefetch.fields["first_seen"], "2026-09-10T08:00:00Z");
        assert_eq!(prefetch.fields["last_seen"], "2026-09-13T09:30:00Z");

        assert_eq!(
            at(observations, WINEVT_LOGS_LOCATION).fields["records"],
            700
        );
        let pca = at(observations, APPCOMPAT_PCA_LOCATION);
        assert_eq!(pca.fields["records"], 0);
        assert!(!pca.fields.contains_key("first_seen"));
        assert_eq!(
            at(observations, fivem_dir::PLUGINS_LOCATION).fields["renamed"],
            2
        );

        let enhanced = at(observations, fivem_dir::ENHANCED_ASI_LOCATION);
        assert_eq!(enhanced.fields["folder"], FOLDER_ABSENT);
        assert!(!enhanced.fields.contains_key("records"));
        assert_eq!(discriminator_gaps.len(), 1);
        assert_eq!(
            discriminator_gaps[0].value,
            fivem_dir::ENHANCED_ASI_LOCATION
        );
        assert_eq!(
            discriminator_gaps[0].gaps["records"],
            UnmeasuredReason::SourceAbsent
        );

        // Nothing a name could hide in: every value is a number, a boolean, a fixed word or a time.
        for observation in observations {
            for value in observation.fields.values() {
                if let Some(text) = value.as_str() {
                    assert!(!text.contains('\\') && !text.contains("fx"), "{text}");
                }
            }
        }
    }

    #[test]
    fn a_volume_without_a_journal_is_source_absent() {
        assert_eq!(
            unmeasured(&Usn::default().collect(&fixture("usn-journal-not-active"))),
            UnmeasuredReason::SourceAbsent
        );
    }

    #[test]
    fn a_refused_volume_is_not_admin_without_elevation_and_access_denied_with_it() {
        assert_eq!(
            unmeasured(&Usn::default().collect(&fixture("usn-journal-access-denied"))),
            UnmeasuredReason::NotAdmin
        );
        assert_eq!(
            unmeasured(&Usn::default().collect(&fixture("usn-journal-access-denied-elevated"))),
            UnmeasuredReason::AccessDenied
        );
    }

    #[test]
    fn a_journal_that_changed_during_the_read_leaves_the_counts_partial() {
        let run = Usn::default().collect(&fixture("usn-journal-changed"));
        let (observations, gaps, _) = measured(&run);
        assert_eq!(gaps["records"], UnmeasuredReason::Partial);
        assert_eq!(gaps["created"], UnmeasuredReason::Partial);
        assert!(!gaps.contains_key("maximum_size"));
        assert_eq!(
            at(observations, PREFETCH_LOCATION).fields["folder"],
            FOLDER_IDENTIFIED
        );
    }

    #[test]
    fn a_read_past_the_budget_stops_and_says_so() {
        let run = Usn {
            budget: Duration::ZERO,
        }
        .collect(&fixture("usn-journal-read"));
        let (_, gaps, _) = measured(&run);
        assert_eq!(gaps["records"], UnmeasuredReason::BudgetSpent);
    }

    #[test]
    fn version_2_records_are_attributed_by_the_64_bit_index() {
        let run = Usn::default().collect(&fixture("usn-version-2-records"));
        let (observations, gaps, _) = measured(&run);
        assert!(gaps.is_empty());
        assert_eq!(
            at(observations, JOURNAL_LOCATION).fields["records_version_2"],
            3
        );
        let prefetch = at(observations, PREFETCH_LOCATION);
        assert_eq!(prefetch.fields["records"], 3);
        assert_eq!(prefetch.fields["deleted"], 3);
    }

    #[test]
    fn a_folder_that_cannot_be_read_or_is_elsewhere_is_a_gap_for_that_place_only() {
        let run = Usn::default().collect(&fixture("usn-folders-unreadable"));
        let (observations, gaps, discriminator_gaps) = measured(&run);
        assert!(gaps.is_empty());
        assert_eq!(
            at(observations, PREFETCH_LOCATION).fields["folder"],
            FOLDER_UNREADABLE
        );
        assert_eq!(
            at(observations, fivem_dir::PLUGINS_LOCATION).fields["folder"],
            FOLDER_OTHER_VOLUME
        );
        assert_eq!(
            at(observations, fivem_dir::ENHANCED_ASI_LOCATION).fields["folder"],
            FOLDER_UNREADABLE
        );
        assert_eq!(at(observations, WINEVT_LOGS_LOCATION).fields["records"], 1);
        let reason = |location: &str| {
            discriminator_gaps
                .iter()
                .find(|gap| gap.value == location)
                .map(|gap| gap.gaps["records"])
        };
        assert_eq!(
            reason(PREFETCH_LOCATION),
            Some(UnmeasuredReason::AccessDenied)
        );
        assert_eq!(
            reason(fivem_dir::PLUGINS_LOCATION),
            Some(UnmeasuredReason::ReadFailed)
        );
        assert_eq!(
            reason(fivem_dir::ENHANCED_ASI_LOCATION),
            Some(UnmeasuredReason::ReadFailed)
        );
        assert_eq!(reason(WINEVT_LOGS_LOCATION), None);
    }

    /// A folder reached through a junction to another volume shares a drive letter with the system
    /// volume, so the drive-letter check alone cannot tell it apart: it is the `volume_serial` mismatch
    /// that keeps its records from being credited to it (the review finding this test closes).
    #[test]
    fn a_folder_behind_a_junction_to_another_volume_is_not_credited_with_its_records() {
        let run = Usn::default().collect(&fixture("usn-folder-on-other-volume"));
        let (observations, gaps, discriminator_gaps) = measured(&run);
        assert!(gaps.is_empty());

        let plugins = at(observations, fivem_dir::PLUGINS_LOCATION);
        assert_eq!(plugins.fields["folder"], FOLDER_OTHER_VOLUME);
        assert!(!plugins.fields.contains_key("records"));
        let reason = discriminator_gaps
            .iter()
            .find(|gap| gap.value == fivem_dir::PLUGINS_LOCATION)
            .map(|gap| gap.gaps["records"]);
        assert_eq!(reason, Some(UnmeasuredReason::ReadFailed));

        let prefetch = at(observations, PREFETCH_LOCATION);
        assert_eq!(prefetch.fields["folder"], FOLDER_IDENTIFIED);
        assert_eq!(prefetch.fields["records"], 2);

        // The journal itself was read in full; only attribution to `plugins` was withheld, so its
        // three records still count toward the journal's total.
        assert_eq!(at(observations, JOURNAL_LOCATION).fields["records"], 5);
    }

    #[test]
    fn a_fixture_that_never_modelled_the_journal_is_read_failed_and_another_os_is_not_windows() {
        assert_eq!(
            unmeasured(&Usn::default().collect(&fixture("usn-not-described"))),
            UnmeasuredReason::ReadFailed
        );
        assert_eq!(
            unmeasured(&Usn::default().collect(&NonWindowsHost)),
            UnmeasuredReason::NotWindows
        );
    }

    /// The two non-elevated baselines set no `%SystemRoot%`, so there is no system volume to read and
    /// the collector stops before it looks at any journal, as `prefetch` and `evtx` do there.
    #[test]
    fn the_non_elevated_baselines_are_read_failed_for_want_of_a_system_root() {
        for name in ["baseline-consumer-win11", "baseline-hardened-win11"] {
            assert_eq!(
                unmeasured(&Usn::default().collect(&fixture(name))),
                UnmeasuredReason::ReadFailed,
                "{name}"
            );
        }
    }

    /// A version 3 record of 80 bytes whose parent is `parent`, with a two-character name.
    fn v3_record(parent: [u8; 16], reason: u32) -> Vec<u8> {
        let mut record = vec![0u8; 80];
        record[0..4].copy_from_slice(&80u32.to_le_bytes());
        record[4..6].copy_from_slice(&3u16.to_le_bytes());
        record[24..40].copy_from_slice(&parent);
        record[48..56].copy_from_slice(&133_000_000_000_000_000u64.to_le_bytes());
        record[56..60].copy_from_slice(&reason.to_le_bytes());
        record[72..74].copy_from_slice(&4u16.to_le_bytes());
        record[74..76].copy_from_slice(&76u16.to_le_bytes());
        record[76..80].copy_from_slice(&[b'a', 0, b'b', 0]);
        record
    }

    /// A buffer as `FSCTL_READ_USN_JOURNAL` returns it: the next USN, then the records.
    fn usn_buffer(records: &[Vec<u8>]) -> Vec<u8> {
        let mut bytes = 1i64.to_le_bytes().to_vec();
        for record in records {
            bytes.extend_from_slice(record);
        }
        bytes
    }

    #[test]
    fn a_record_length_of_zero_after_a_valid_record_leaves_the_counts_read_failed_and_keeps_the_record()
     {
        let mut zero = v3_record([2; 16], usn::REASON_FILE_DELETE);
        zero[0..4].copy_from_slice(&0u32.to_le_bytes());
        let mut tally = Tally::new(&[]);
        tally.add(&usn_buffer(&[
            v3_record([1; 16], usn::REASON_FILE_CREATE),
            zero,
        ]));

        assert!(tally.damaged);
        assert_eq!(tally.journal_observation(false, 0).fields["records"], 1);
        let gaps = counted_gaps(tally.damaged, UsnReadEnd::Complete);
        assert_eq!(gaps.len(), COUNTED.len());
        assert!(
            gaps.values()
                .all(|reason| *reason == UnmeasuredReason::ReadFailed)
        );
    }

    #[test]
    fn a_buffer_shorter_than_its_eight_byte_header_leaves_the_counts_read_failed() {
        let mut tally = Tally::new(&[]);
        tally.add(&[0; 7]);

        assert!(tally.damaged);
        assert_eq!(tally.journal_observation(false, 0).fields["records"], 0);
        let gaps = counted_gaps(tally.damaged, UsnReadEnd::Complete);
        assert_eq!(gaps["records"], UnmeasuredReason::ReadFailed);
        assert_eq!(gaps["created"], UnmeasuredReason::ReadFailed);
    }

    /// Damage outranks a journal that changed during the read: the records past the damage were never
    /// parsed, so the counts are not merely `partial`.
    #[test]
    fn damage_in_a_read_that_ended_journal_changed_is_read_failed_not_partial() {
        let mut tally = Tally::new(&[]);
        tally.add(&[0; 7]);

        let gaps = counted_gaps(tally.damaged, UsnReadEnd::JournalChanged);
        assert_eq!(gaps.len(), COUNTED.len());
        assert!(
            gaps.values()
                .all(|reason| *reason == UnmeasuredReason::ReadFailed)
        );
        assert_eq!(
            counted_gaps(false, UsnReadEnd::JournalChanged)["records"],
            UnmeasuredReason::Partial
        );
    }

    /// `baseline-elevated-win11`'s `usn_journal:` block is rebuilt from the `usn` collector's own
    /// reading of a GitHub-hosted runner (`windows.yml` run 34930942657, 2026-09-15,
    /// `fixtures/hosts/PROVENANCE.md`). This asserts the rebuild reproduces every value that run
    /// printed, so the reproduction is enforced rather than eyeballed.
    #[test]
    fn baseline_elevated_win11_reproduces_the_runners_usn_reading() {
        let run = Usn::default().collect(&fixture("baseline-elevated-win11"));
        let (observations, gaps, discriminator_gaps) = measured(&run);
        assert!(gaps.is_empty());
        // Enhanced is not installed on this baseline, so its plugin folder is absent, as on the
        // runner — the one discriminator gap this reading has.
        assert_eq!(discriminator_gaps.len(), 1);
        assert_eq!(
            discriminator_gaps[0].value,
            fivem_dir::ENHANCED_ASI_LOCATION
        );

        let journal = at(observations, JOURNAL_LOCATION);
        assert_eq!(journal.fields["records"], 381_333);
        assert_eq!(journal.fields["records_version_2"], 0);
        assert_eq!(journal.fields["records_version_3"], 381_333);
        assert_eq!(journal.fields["trimmed"], true);
        assert_eq!(journal.fields["maximum_size"], 33_554_432);
        assert_eq!(journal.fields["first_seen"], "2026-09-08T01:12:08.3678392Z");
        assert_eq!(journal.fields["last_seen"], "2026-09-15T05:07:08.7795416Z");

        let prefetch = at(observations, PREFETCH_LOCATION);
        assert_eq!(prefetch.fields["folder"], FOLDER_IDENTIFIED);
        assert_eq!(prefetch.fields["records"], 0);
        assert_eq!(prefetch.fields["created"], 0);
        assert_eq!(prefetch.fields["deleted"], 0);
        assert_eq!(prefetch.fields["renamed"], 0);
        assert_eq!(prefetch.fields["data_changed"], 0);

        let winevt = at(observations, WINEVT_LOGS_LOCATION);
        assert_eq!(winevt.fields["folder"], FOLDER_IDENTIFIED);
        assert_eq!(winevt.fields["records"], 733);
        assert_eq!(winevt.fields["created"], 13);
        assert_eq!(winevt.fields["deleted"], 0);
        assert_eq!(winevt.fields["renamed"], 0);
        assert_eq!(winevt.fields["data_changed"], 729);
        assert_eq!(winevt.fields["first_seen"], "2026-09-08T01:12:16.383425Z");
        assert_eq!(winevt.fields["last_seen"], "2026-09-15T05:05:28.2865607Z");

        let pca = at(observations, APPCOMPAT_PCA_LOCATION);
        assert_eq!(pca.fields["folder"], FOLDER_IDENTIFIED);
        assert_eq!(pca.fields["records"], 0);

        let plugins = at(observations, fivem_dir::PLUGINS_LOCATION);
        assert_eq!(plugins.fields["folder"], FOLDER_IDENTIFIED);
        assert_eq!(plugins.fields["records"], 0);

        let enhanced = at(observations, fivem_dir::ENHANCED_ASI_LOCATION);
        assert_eq!(enhanced.fields["folder"], FOLDER_ABSENT);
    }
}
