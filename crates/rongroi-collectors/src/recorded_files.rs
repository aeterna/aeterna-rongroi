// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! The files a program recorded by BAM, PCA, the process list or `UserAssist` ran from.
//!
//! BAM and PCA record a program's path because it ran; the process list holds the path of an image
//! that is running now; `UserAssist` holds the path of a program Explorer opened through the shell.
//! This collector gathers those paths through the same host calls and the same path logic their own
//! collectors use ([`crate::bam::recorded_paths`], [`crate::pca::recorded_paths`],
//! [`crate::process::recorded_paths`], [`crate::userassist::recorded_paths`]), keeps the drive-rooted
//! ones only, and reports one observation per distinct path ignoring ASCII case (ADR 0079 amendment 7,
//! ADR 0080 section 4).
//!
//! It is `full`: reading a file's bytes is beyond what a standard scan asks for (ADR 0052).
//! `identity_read` says what happened to that read, and a `read` carries what the bytes, the hash, the
//! signature and the `Zone.Identifier` stream say. Reads run nearest the newest `FiveM` or GTA V time
//! first, under a 90-second budget checked between files. An unreadable file is never a gap — the
//! whole run is gapped only when one of its sources could not be read at all, and then with that
//! source's reason.
//!
//! It also reads the system volume's change journal once, before any file's bytes are read (ADR 0086).
//! For each path it says whether the journal holds a deletion or a rename of that file: `journal_match`
//! says whether the path could be looked for at all, `journal_deleted`, `journal_renamed_from` and
//! `journal_renamed_to` list the times of such records, newest first and at most eight of each, and
//! `journal_from` is the oldest record time of that read. The comparison happens inside
//! `rongroi_parsers::usn::match_buffer`, which returns an index, a kind and a time and no name, USN or
//! file reference, so none of those reaches an observation or a gap. The journal read has its own
//! budget, `journal_budget`, and the file reads keep their 90 seconds.

use std::cmp::{Ordering, Reverse};
use std::collections::BTreeMap;
use std::ops::ControlFlow;
use std::time::{Duration, Instant};

use jiff::Timestamp;
use rongroi_core::model::{CollectorRun, Observation, UnmeasuredReason};
use rongroi_host::{Host, Platform, SourceError, UsnReadEnd, is_refused_form};
use rongroi_parsers::content_kind::{self, FileKind};
use rongroi_parsers::powershell_text::DownloadHost;
use rongroi_parsers::usn::{ChangeKind, JournalMatch, MatchTarget, match_buffer, parse_buffer};
use rongroi_parsers::{pe_version, zone_identifier};

use crate::failure::{read_failure, reason_for};
use crate::paths::{file_name, is_drive_rooted};
use crate::{Collector, Field, ScanTier, SensitiveKind};

const ID: &str = "recorded_files";

/// How long this collector may spend reading file identities before the rest say `budget_spent`.
///
/// Checked between files. ADR 0079 amendment 7 sets it to the whole 90 seconds a full scan may add.
pub const BUDGET: Duration = Duration::from_secs(90);

/// Every reason this collector gives for not having looked (`Collector::unmeasured_reasons`).
///
/// `not_windows` is its own answer. The rest are what one of its sources gives when that source could
/// not be read: this collector adds no vocabulary of its own, because a gap here means exactly what
/// the same reason means in `bam`, `pca`, `process` or `userassist`. `budget_spent` is the change
/// journal's own read stopping at its budget, which `usn` gives for the same read. `not_on_this_os` is
/// not here: PCA says it for a Windows that never kept these files, and PCA then contributes neither a
/// path nor a gap.
const REASONS: [UnmeasuredReason; 8] = [
    UnmeasuredReason::NotWindows,
    UnmeasuredReason::NotAdmin,
    UnmeasuredReason::AccessDenied,
    UnmeasuredReason::SourceAbsent,
    UnmeasuredReason::SourceEmpty,
    UnmeasuredReason::Partial,
    UnmeasuredReason::ReadFailed,
    UnmeasuredReason::BudgetSpent,
];

/// Every field this collector can emit.
///
/// A path is kept only when it begins with a drive letter, as `bam` and `pca` already keep theirs:
/// that is the shape `rongroi_core::view::redact_profile_paths` can reach. The four source flags are
/// always present, so a rule can ask which record pointed at the file. The two root flags are absent
/// when the environment does not say what the system drive or root is. The identity fields follow
/// `identity_read`: a `read` carries all that apply, a `too_large` still carries the hash and
/// signature, and every other answer carries none (ADR 0079 section 3). `download_host` is the one
/// sensitive field, behind its own SS-mode question (ADR 0064).
///
/// The journal fields (ADR 0086 section 3) are present only when the journal was read. `journal_match`
/// is on every path that read gives it for. All four time fields are kept off the timeline, as
/// `run_times` is: the three lists hold up to eight times each, and `journal_from` repeats the oldest
/// record time `usn` already puts on the timeline, so a journal gap on any of them would leave
/// `recorded_files` in the timeline's unmeasured sources on every scan without a journal (ADR 0086
/// section 6). `journal_more` says that one of the lists was cut.
const FIELDS: [Field; 25] = [
    Field::boolean("by_bam"),
    Field::boolean("by_pca"),
    Field::boolean("by_process"),
    Field::boolean("by_userassist"),
    Field::text("content_kind"),
    Field::text("download_host").sensitive(SensitiveKind::DownloadHost),
    Field::boolean("embedded_pe"),
    Field::text("identity_read"),
    Field::timestamp_list("journal_deleted").off_timeline(),
    Field::timestamp("journal_from").off_timeline(),
    Field::text("journal_match"),
    Field::boolean("journal_more"),
    Field::timestamp_list("journal_renamed_from").off_timeline(),
    Field::timestamp_list("journal_renamed_to").off_timeline(),
    Field::text("name"),
    Field::boolean("on_system_drive"),
    Field::text("original_filename"),
    Field::text("path"),
    Field::text("sha256"),
    Field::text("signature"),
    Field::text("signer"),
    Field::text("signer_cert_sha256"),
    Field::boolean("trailing_data"),
    Field::boolean("under_system_root"),
    Field::number("zone_id"),
];

/// The six fields the change journal feeds. A journal gap covers these and no other field.
const JOURNAL_FIELDS: [&str; 6] = [
    "journal_deleted",
    "journal_from",
    "journal_match",
    "journal_more",
    "journal_renamed_from",
    "journal_renamed_to",
];

/// The most times one list holds, newest first. A list cut at this bound sets `journal_more` (ADR 0086
/// section 3, decision D5).
const JOURNAL_TIMES_CAP: usize = 8;

/// The source that recorded a path.
#[derive(Debug, Clone, Copy)]
enum Source {
    Bam,
    Pca,
    Process,
    UserAssist,
}

/// One distinct path, which of the four records named it, and the newest time any gave it.
#[allow(clippy::struct_excessive_bools)]
struct Candidate {
    /// The path as the first source that named it spelled it.
    path: String,
    by_bam: bool,
    by_pca: bool,
    by_process: bool,
    by_userassist: bool,
    /// The newest instant the sources recorded for this path, when any gave one.
    at: Option<Timestamp>,
}

impl Candidate {
    fn new(path: String) -> Self {
        Self {
            path,
            by_bam: false,
            by_pca: false,
            by_process: false,
            by_userassist: false,
            at: None,
        }
    }

    fn mark(&mut self, source: Source) {
        match source {
            Source::Bam => self.by_bam = true,
            Source::Pca => self.by_pca = true,
            Source::Process => self.by_process = true,
            Source::UserAssist => self.by_userassist = true,
        }
    }
}

/// The `recorded_files` collector.
#[derive(Debug, Clone, Copy)]
pub struct RecordedFiles {
    /// How long the identity reads may take before the remaining paths say `budget_spent`.
    ///
    /// Checked between files, as `autostart` checks its own budget (ADR 0079 amendment 7).
    pub budget: Duration,
    /// How long the change journal read may take before the journal fields say `budget_spent`.
    ///
    /// Checked between buffers, as the `usn` collector checks its own (ADR 0086 section 4). It is a clock
    /// of its own: the time the read takes is given back to the file clock, so the two never share time.
    pub journal_budget: Duration,
    /// How many files this run may read before the rest say `budget_spent`; `None` reads every one.
    ///
    /// A test-only limit, so that order is testable without a clock. The identity read applies it
    /// between files, like the budget.
    pub file_limit: Option<usize>,
}

impl Default for RecordedFiles {
    fn default() -> Self {
        Self {
            budget: BUDGET,
            journal_budget: crate::usn::BUDGET,
            file_limit: None,
        }
    }
}

impl RecordedFiles {
    /// One observation per path, in order, each with its identity read and its journal fields. A path
    /// that comes after the budget or the file limit is not read, and says `budget_spent`.
    fn observations(
        &self,
        host: &dyn Host,
        ordered: Vec<Candidate>,
        journal: Vec<BTreeMap<String, serde_json::Value>>,
        started: Instant,
    ) -> Vec<Observation> {
        let system_drive = system_drive(host);
        let system_root = system_root(host);
        let mut attempted = 0_usize;
        ordered
            .into_iter()
            .zip(journal)
            .map(|(candidate, journal_fields)| {
                let spent = started.elapsed() >= self.budget
                    || self.file_limit.is_some_and(|limit| attempted >= limit);
                let identity = if spent {
                    Identity::alone("budget_spent")
                } else {
                    attempted += 1;
                    identity(host, &candidate.path)
                };
                observation(
                    &candidate,
                    system_drive,
                    system_root.as_deref(),
                    identity,
                    journal_fields,
                )
            })
            .collect()
    }
}

impl Collector for RecordedFiles {
    fn id(&self) -> &'static str {
        ID
    }

    fn fields(&self) -> &'static [Field] {
        &FIELDS
    }

    fn unmeasured_reasons(&self) -> &'static [UnmeasuredReason] {
        &REASONS
    }

    /// A file's location is part of what a program's record can only be read with a full scan.
    fn tier(&self) -> ScanTier {
        ScanTier::Full
    }

    fn collect(&self, host: &dyn Host) -> CollectorRun {
        if host.platform() != Platform::Windows {
            return CollectorRun::Unmeasured {
                collector: ID.to_owned(),
                reason: UnmeasuredReason::NotWindows,
            };
        }

        let mut candidates: BTreeMap<String, Candidate> = BTreeMap::new();
        let mut source_gap = None;
        let mut first_failure = None;
        let mut measured_sources = 0_usize;
        let mut fivem_at: Option<Timestamp> = None;
        // The budget covers the source reads too: a source that spends most of the 90 seconds leaves
        // less for the identity reads that follow it (ADR 0079 amendment 7).
        let started = Instant::now();
        for (source, paths) in [
            (Source::Bam, crate::bam::recorded_paths(host)),
            (Source::Pca, crate::pca::recorded_paths(host)),
            (Source::Process, crate::process::recorded_paths(host)),
            (Source::UserAssist, crate::userassist::recorded_paths(host)),
        ] {
            match paths {
                Ok((paths, partial)) => {
                    measured_sources += 1;
                    if let Some(reason) = partial {
                        source_gap = source_gap.or(Some(reason));
                    }
                    for recorded in paths {
                        if !is_drive_rooted(&recorded.path) {
                            continue;
                        }
                        let key = recorded.path.to_ascii_lowercase();
                        let candidate = candidates
                            .entry(key)
                            .or_insert_with(|| Candidate::new(recorded.path.clone()));
                        candidate.mark(source);
                        candidate.at = newest(candidate.at, recorded.at);
                        if is_fivem_program(&recorded.path) {
                            fivem_at = newest(fivem_at, recorded.at);
                        }
                    }
                }
                // PCA says this Windows never kept its files, so it contributes no path and no gap.
                Err(UnmeasuredReason::NotOnThisOs) if matches!(source, Source::Pca) => {
                    measured_sources += 1;
                }
                // An absent `UserAssist` key holds no path, so no path can be missing from it: a
                // measured source with no paths, not a gap (ADR 0080 section 4). It says nothing
                // about what the account did. It does not by itself make a run whose every other
                // source failed a measured one.
                Err(UnmeasuredReason::SourceAbsent) if matches!(source, Source::UserAssist) => {
                    if measured_sources > 0 {
                        measured_sources += 1;
                    }
                }
                // One source that could not be read loses an unknown number of paths, so the whole
                // run is a gap. The paths the other sources gave are still reported.
                Err(reason) => {
                    first_failure = first_failure.or(Some(reason));
                    source_gap = source_gap.or(Some(reason));
                }
            }
        }

        // Nothing was read at all: a `Measured` run with no observation would say the machine had no
        // such record, which is not what happened. The first source's reason is the run's answer,
        // as it is in every collector that reads its sources in one order.
        if measured_sources == 0 {
            return CollectorRun::Unmeasured {
                collector: ID.to_owned(),
                reason: first_failure.unwrap_or(UnmeasuredReason::ReadFailed),
            };
        }

        let mut ordered: Vec<Candidate> = candidates.into_values().collect();
        ordered.sort_by(|left, right| order(left, right, fivem_at));

        // The journal is read before any file's bytes, so this program's own reads are never among the
        // records it compares (ADR 0086 section 1).
        let journal_started = Instant::now();
        let journal = read_journal(host, &ordered, self.journal_budget);
        // The journal has its own budget, so the time its read took is given back to the file clock:
        // the two never share time (ADR 0086 section 4).
        let started = started
            .checked_add(journal_started.elapsed())
            .unwrap_or(started);
        let observations = self.observations(host, ordered, journal.fields, started);
        let mut gaps = source_gap.map(gaps).unwrap_or_default();
        if let Some(reason) = journal.gap {
            gap_journal_fields(&mut gaps, reason);
        }
        CollectorRun::Measured {
            collector: ID.to_owned(),
            observations,
            gaps,
            discriminator_gaps: Vec::new(),
        }
    }
}

fn gaps(reason: UnmeasuredReason) -> BTreeMap<String, UnmeasuredReason> {
    FIELDS
        .iter()
        .map(|field| (field.name.to_owned(), reason))
        .collect()
}

/// One recorded file: its path and name, which records pointed at it, what the read of it did, whether
/// it lies on the system drive and under the system root, and what the change journal says of it.
fn observation(
    candidate: &Candidate,
    system_drive: Option<u8>,
    system_root: Option<&str>,
    identity: Identity,
    journal: BTreeMap<String, serde_json::Value>,
) -> Observation {
    let mut fields = BTreeMap::new();
    if let Some(name) = file_name(&candidate.path) {
        fields.insert("name".to_owned(), serde_json::Value::from(name));
    }
    fields.insert(
        "path".to_owned(),
        serde_json::Value::from(candidate.path.clone()),
    );
    fields.insert(
        "by_bam".to_owned(),
        serde_json::Value::from(candidate.by_bam),
    );
    fields.insert(
        "by_pca".to_owned(),
        serde_json::Value::from(candidate.by_pca),
    );
    fields.insert(
        "by_process".to_owned(),
        serde_json::Value::from(candidate.by_process),
    );
    fields.insert(
        "by_userassist".to_owned(),
        serde_json::Value::from(candidate.by_userassist),
    );
    fields.insert(
        "identity_read".to_owned(),
        serde_json::Value::from(identity.read),
    );
    fields.extend(identity.fields);
    if let Some(drive) = system_drive {
        fields.insert(
            "on_system_drive".to_owned(),
            serde_json::Value::from(same_drive(&candidate.path, drive)),
        );
    }
    if let Some(root) = system_root {
        fields.insert(
            "under_system_root".to_owned(),
            serde_json::Value::from(is_under_root(&candidate.path, root)),
        );
    }
    fields.extend(journal);
    Observation {
        collector: ID.to_owned(),
        fields,
    }
}

/// What one read came to: the word ADR 0079 section 3 gives it, and the identity fields it carries.
struct Identity {
    /// The value of `identity_read`.
    read: &'static str,
    /// The identity fields, empty for every answer but `read` and `too_large`.
    fields: BTreeMap<String, serde_json::Value>,
}

impl Identity {
    fn alone(read: &'static str) -> Self {
        Self {
            read,
            fields: BTreeMap::new(),
        }
    }

    fn read(host: &dyn Host, path: &str, bytes: &[u8]) -> Self {
        let mut fields = BTreeMap::new();
        insert_hash_and_signature(host, path, &mut fields);
        insert_content(&mut fields, bytes);
        insert_zone(host, path, &mut fields);
        Self {
            read: "read",
            fields,
        }
    }
}

/// What happened to the read of one file, in the words ADR 0079 section 3 gives.
///
/// A form this program refuses is not read at all. A file that is gone or refused is never a gap: one
/// file's absence says nothing about the paths the other records gave.
fn identity(host: &dyn Host, path: &str) -> Identity {
    if is_refused_form(path) {
        return Identity::alone("refused_form");
    }
    match host.read_file(path) {
        Ok(Some(bytes)) => Identity::read(host, path, &bytes),
        Ok(None) => Identity::alone("missing"),
        Err(error) => {
            // A file over the size bound still has a hash and a signature, and ADR 0079 section 3
            // keeps both beside `too_large` so a rule can still ask what the file was.
            if matches!(error, SourceError::TooLarge { .. }) {
                let mut fields = BTreeMap::new();
                insert_hash_and_signature(host, path, &mut fields);
                Identity {
                    read: "too_large",
                    fields,
                }
            } else {
                Identity::alone(read_failure(&error))
            }
        }
    }
}

/// The hash and the signature of one file, as `fivem_dir` emits them.
fn insert_hash_and_signature(
    host: &dyn Host,
    path: &str,
    fields: &mut BTreeMap<String, serde_json::Value>,
) {
    if let Some(sha256) = crate::fivem_dir::file_sha256(host, path) {
        fields.insert("sha256".to_owned(), serde_json::Value::from(sha256));
    }
    if let Ok(signature) = host.file_signature(path) {
        crate::fivem_dir::insert_signature(fields, signature);
    }
}

/// What the file's own bytes say about it (ADR 0078 section 8).
fn insert_content(fields: &mut BTreeMap<String, serde_json::Value>, bytes: &[u8]) {
    let Ok(description) = content_kind::parse(bytes) else {
        return;
    };
    fields.insert(
        "content_kind".to_owned(),
        serde_json::Value::from(description.kind.as_str()),
    );
    if let Some(trailing) = description.trailing_data {
        fields.insert(
            "trailing_data".to_owned(),
            serde_json::Value::from(trailing),
        );
    }
    if let Some(embedded) = description.embedded_pe {
        fields.insert("embedded_pe".to_owned(), serde_json::Value::from(embedded));
    }
    if matches!(
        description.kind,
        FileKind::PeExecutable | FileKind::PeDll | FileKind::PeDriver
    ) && let Ok(Some(name)) = pe_version::original_filename(bytes)
    {
        fields.insert(
            "original_filename".to_owned(),
            serde_json::Value::from(name),
        );
    }
}

/// The zone and download host of one file, from its `Zone.Identifier` stream (ADR 0079 section 2).
fn insert_zone(host: &dyn Host, path: &str, fields: &mut BTreeMap<String, serde_json::Value>) {
    let Ok(Some(bytes)) = host.zone_identifier(path) else {
        return;
    };
    let Ok(zone) = zone_identifier::parse(&bytes) else {
        return;
    };
    if let Some(zone_id) = zone.zone_id {
        fields.insert("zone_id".to_owned(), serde_json::Value::from(zone_id));
    }
    if let Some(download_host) = zone.host {
        let host = match download_host {
            DownloadHost::Name(name) => name,
            DownloadHost::Address(kind) => kind.as_str().to_owned(),
        };
        fields.insert("download_host".to_owned(), serde_json::Value::from(host));
    }
}

/// The newer of two recorded times, treating a missing time as older than every instant.
fn newest(left: Option<Timestamp>, right: Option<Timestamp>) -> Option<Timestamp> {
    match (left, right) {
        (Some(left), Some(right)) => Some(if left >= right { left } else { right }),
        (Some(at), None) | (None, Some(at)) => Some(at),
        (None, None) => None,
    }
}

/// Whether a recorded path names one of `FiveM`'s or GTA V's programs, the anchors the read order
/// centres on.
fn is_fivem_program(path: &str) -> bool {
    let Some(name) = file_name(path) else {
        return false;
    };
    name == "fivem.exe"
        || (name.starts_with("fivem_b") && name.ends_with("_gtaprocess.exe"))
        || matches!(
            name.as_str(),
            "gta5.exe" | "gta5_enhanced.exe" | "playgtav.exe"
        )
}

/// Nearest to the newest `FiveM` or GTA V time first, newest first when there is none, and stable by
/// path.
///
/// A path with no time has no distance from the anchor record, so it sorts after every path whose
/// time is known rather than being read first on the strength of a missing answer.
fn order(left: &Candidate, right: &Candidate, fivem_at: Option<Timestamp>) -> Ordering {
    let by_time = match fivem_at {
        Some(center) => {
            let distance = |at: Option<Timestamp>| {
                at.map_or(u128::MAX, |at| {
                    center.as_nanosecond().abs_diff(at.as_nanosecond())
                })
            };
            distance(left.at).cmp(&distance(right.at))
        }
        None => right.at.cmp(&left.at),
    };
    by_time.then_with(|| {
        left.path
            .to_ascii_lowercase()
            .cmp(&right.path.to_ascii_lowercase())
    })
}

/// What the change journal says about the run's paths (ADR 0086 sections 2 to 4).
struct Journal {
    /// The reason the journal fields are gapped, when the journal was not read whole.
    gap: Option<UnmeasuredReason>,
    /// The journal fields of each path, in the order of the candidates.
    fields: Vec<BTreeMap<String, serde_json::Value>>,
}

impl Journal {
    /// A journal that could not be read: every path has `reason` as its gap and no journal field.
    fn unread(paths: usize, reason: UnmeasuredReason) -> Self {
        Self {
            gap: Some(reason),
            fields: vec![BTreeMap::new(); paths],
        }
    }
}

/// What the journal can say about one path, as `journal_match` names it (ADR 0086 section 3).
#[derive(Clone, Copy)]
enum Reach {
    /// On the system volume, under a folder the journal identifies: its records are compared.
    Matched,
    /// On another drive, or in a folder reached through a junction to another volume.
    OtherVolume,
    /// On the system volume, but its folder is missing or could not be identified.
    FolderUnknown,
}

impl Reach {
    /// The value of `journal_match`.
    fn word(self) -> &'static str {
        match self {
            Self::Matched => "matched",
            Self::OtherVolume => "other_volume",
            Self::FolderUnknown => "folder_unknown",
        }
    }
}

/// Reads the system volume's change journal once and says what it holds for each path (ADR 0086).
///
/// Nothing is read when the volume or its identifier cannot be had: the whole journal is then gapped
/// with the reason `usn` would give, and no path is looked for. The targets are built before the read,
/// so no file's bytes are read before the journal (ADR 0086 section 1).
fn read_journal(host: &dyn Host, candidates: &[Candidate], budget: Duration) -> Journal {
    let (volume, root_serial) = match journal_volume(host) {
        Ok(found) => found,
        Err(reason) => return Journal::unread(candidates.len(), reason),
    };
    let mut reach = Vec::with_capacity(candidates.len());
    let mut targets = Vec::new();
    for (index, candidate) in candidates.iter().enumerate() {
        let (found, target) = reach_of(host, &candidate.path, index, volume, root_serial);
        reach.push(found);
        targets.extend(target);
    }

    let mut scan = JournalScan::new(&targets);
    let started = Instant::now();
    let read = host.read_usn_journal(volume, &mut |bytes| {
        // Checked before each buffer, as `usn` checks its own budget.
        if started.elapsed() >= budget {
            return ControlFlow::Break(());
        }
        scan.add(bytes);
        ControlFlow::Continue(())
    });
    let read = match read {
        Ok(Some(read)) => read,
        Ok(None) => return Journal::unread(candidates.len(), UnmeasuredReason::SourceAbsent),
        Err(error) => return Journal::unread(candidates.len(), reason_for(host, &error)),
    };

    let gap = journal_gap(scan.damaged, read.end);
    let whole = gap.is_none();
    let from = scan.from;
    let mut hits = scan.hits;
    let fields = reach
        .into_iter()
        .enumerate()
        .map(|(index, reach)| {
            let matches = hits.remove(&index).unwrap_or_default();
            journal_fields(reach, &matches, from, whole)
        })
        .collect();
    Journal { gap, fields }
}

/// The system volume's drive letter and the identifier of its root, as the journal is read from them.
/// `%SystemRoot%` names the drive, as `usn` reads it; either one missing is the reason for the whole
/// journal, which `usn` gives for the same failure.
fn journal_volume(host: &dyn Host) -> Result<(char, u64), UnmeasuredReason> {
    let volume = host
        .env_var(crate::prefetch::SYSTEM_ROOT)
        .as_deref()
        .and_then(drive_of)
        .ok_or(UnmeasuredReason::ReadFailed)?;
    match host.file_id(&format!(r"{volume}:\")) {
        Ok(Some(id)) => Ok((volume, id.volume_serial)),
        Ok(None) => Err(UnmeasuredReason::ReadFailed),
        Err(error) => Err(reason_for(host, &error)),
    }
}

/// Where the journal would hold the records of one path, and the target that compares them when the
/// path is on the system volume under a folder the journal identifies (ADR 0086 section 2).
///
/// A file that is gone has no identifier of its own; then only its folder and its name can match it.
fn reach_of(
    host: &dyn Host,
    path: &str,
    index: usize,
    volume: char,
    root_serial: u64,
) -> (Reach, Option<MatchTarget>) {
    if drive_of(path) != Some(volume) {
        return (Reach::OtherVolume, None);
    }
    let Some(parent) = parent_of(path) else {
        return (Reach::FolderUnknown, None);
    };
    // A folder reached through a junction to another volume answers with another serial, and its
    // records are not this volume's, so it is not compared (ADR 0047 amendment).
    let folder = match host.file_id(&parent) {
        Ok(Some(id)) if id.volume_serial == root_serial => id,
        Ok(Some(_)) => return (Reach::OtherVolume, None),
        Ok(None) | Err(_) => return (Reach::FolderUnknown, None),
    };
    let file = host
        .file_id(path)
        .ok()
        .flatten()
        .filter(|id| id.volume_serial == root_serial)
        .map(|id| (id.index_64, id.id_128));
    let name: Vec<u16> = file_name(path).unwrap_or_default().encode_utf16().collect();
    let target = MatchTarget {
        index,
        parent_index_64: folder.index_64,
        parent_id_128: folder.id_128,
        file,
        name,
    };
    (Reach::Matched, Some(target))
}

/// The folder a path names: the path up to its last separator. A drive's root is spelled `X:\`, the
/// form `file_id` answers for the root, rather than the bare `X:`, which Windows reads as the current
/// folder of that drive.
fn parent_of(path: &str) -> Option<String> {
    let cut = path.rfind(['\\', '/'])?;
    let folder = &path[..cut];
    Some(if folder.ends_with(':') {
        format!(r"{folder}\")
    } else {
        folder.to_owned()
    })
}

/// The drive letter a path begins with, upper-cased, as `usn` reads `%SystemRoot%`.
fn drive_of(path: &str) -> Option<char> {
    let mut chars = path.chars();
    let letter = chars.next().filter(char::is_ascii_alphabetic)?;
    (chars.next() == Some(':')).then(|| letter.to_ascii_uppercase())
}

/// The journal's buffers as `read_journal` hands them over: each buffer's matches for the targets, and
/// the oldest record time of the first buffer.
struct JournalScan<'a> {
    targets: &'a [MatchTarget],
    /// The matches of each target, by the target's index, in buffer order.
    hits: BTreeMap<usize, Vec<JournalMatch>>,
    /// The oldest record time of the first buffer, when that buffer has a timed record.
    from: Option<Timestamp>,
    /// Whether a buffer has been handed over, so that `from` comes from the first one only.
    seen_first: bool,
    /// Whether a buffer was damaged or could not be read at all.
    damaged: bool,
}

impl<'a> JournalScan<'a> {
    fn new(targets: &'a [MatchTarget]) -> Self {
        Self {
            targets,
            hits: BTreeMap::new(),
            from: None,
            seen_first: false,
            damaged: false,
        }
    }

    /// Takes one buffer. Its matches are kept even when it is damaged, as the records before the damage
    /// are (ADR 0086 section 3).
    fn add(&mut self, bytes: &[u8]) {
        if !self.seen_first {
            self.seen_first = true;
            // A real journal is written in time order, so the first buffer's oldest record is the
            // oldest of the read (ADR 0086 section 3).
            self.from = parse_buffer(bytes).ok().and_then(|buffer| {
                buffer
                    .records
                    .iter()
                    .filter_map(|record| record.written)
                    .min()
            });
        }
        let Ok(found) = match_buffer(bytes, self.targets) else {
            self.damaged = true;
            return;
        };
        self.damaged |= found.damage.is_some();
        for hit in found.matches {
            self.hits.entry(hit.target).or_default().push(hit);
        }
    }
}

/// Why the journal's matches are not whole, when they are not. Damage outranks how the read ended, as
/// it does in `usn`: the records after the damage were never compared (ADR 0086 section 4).
fn journal_gap(damaged: bool, end: UsnReadEnd) -> Option<UnmeasuredReason> {
    if damaged {
        return Some(UnmeasuredReason::ReadFailed);
    }
    match end {
        UsnReadEnd::Complete => None,
        UsnReadEnd::JournalChanged => Some(UnmeasuredReason::Partial),
        UsnReadEnd::Stopped => Some(UnmeasuredReason::BudgetSpent),
    }
}

/// The journal fields of one path. `journal_match` is on every path the journal was read for, and
/// `journal_from` whenever the first buffer had a timed record. The three lists and `journal_more` are
/// only for a matched path whose read was whole, so a list is never read from a changing or cut journal
/// (ADR 0086 section 3).
fn journal_fields(
    reach: Reach,
    matches: &[JournalMatch],
    from: Option<Timestamp>,
    whole: bool,
) -> BTreeMap<String, serde_json::Value> {
    let mut fields = BTreeMap::new();
    fields.insert(
        "journal_match".to_owned(),
        serde_json::Value::from(reach.word()),
    );
    if let Some(from) = from {
        fields.insert(
            "journal_from".to_owned(),
            serde_json::Value::from(from.to_string()),
        );
    }
    if matches!(reach, Reach::Matched) && whole {
        let mut more = false;
        for (name, kind) in [
            ("journal_deleted", ChangeKind::Deleted),
            ("journal_renamed_from", ChangeKind::RenamedFrom),
            ("journal_renamed_to", ChangeKind::RenamedTo),
        ] {
            let (times, cut) = newest_times(matches, kind);
            more |= cut;
            fields.insert(name.to_owned(), serde_json::Value::from(times));
        }
        fields.insert("journal_more".to_owned(), serde_json::Value::from(more));
    }
    fields
}

/// The newest `JOURNAL_TIMES_CAP` times of one kind of match, newest first, and whether any were cut.
/// A match with no time is dropped (ADR 0086 section 3).
fn newest_times(matches: &[JournalMatch], kind: ChangeKind) -> (Vec<String>, bool) {
    let mut times: Vec<Timestamp> = matches
        .iter()
        .filter(|found| found.kind == kind)
        .filter_map(|found| found.written)
        .collect();
    times.sort_by_key(|time| Reverse(*time));
    let cut = times.len() > JOURNAL_TIMES_CAP;
    times.truncate(JOURNAL_TIMES_CAP);
    (times.iter().map(ToString::to_string).collect(), cut)
}

/// Gaps the journal fields with `reason`, except the ones an earlier gap already names: a source's gap
/// was given first, and a field keeps the first reason it was given (ADR 0086 section 4).
fn gap_journal_fields(gaps: &mut BTreeMap<String, UnmeasuredReason>, reason: UnmeasuredReason) {
    for field in JOURNAL_FIELDS {
        gaps.entry(field.to_owned()).or_insert(reason);
    }
}

/// The system drive's uppercased letter, when the environment names one.
fn system_drive(host: &dyn Host) -> Option<u8> {
    let drive = host.env_var("SystemDrive")?;
    let bytes = drive.trim().as_bytes();
    let first = *bytes.first()?;
    if !first.is_ascii_alphabetic() {
        return None;
    }
    if bytes.len() > 1 && !matches!(bytes[1], b':' | b'\\' | b'/') {
        return None;
    }
    Some(first.to_ascii_uppercase())
}

/// The system root without a trailing separator, when the environment names one.
fn system_root(host: &dyn Host) -> Option<String> {
    let root = host.env_var("SystemRoot")?;
    let root = root.trim_end_matches(['\\', '/']);
    (!root.is_empty()).then(|| root.to_owned())
}

fn same_drive(path: &str, drive: u8) -> bool {
    path.as_bytes()
        .first()
        .is_some_and(|first| first.to_ascii_uppercase() == drive)
}

/// Whether `path` is below `root`, comparing ASCII case and requiring a separator at the boundary.
fn is_under_root(path: &str, root: &str) -> bool {
    let path = path.to_ascii_lowercase();
    let root = root.to_ascii_lowercase();
    path.len() > root.len()
        && path.starts_with(&root)
        && matches!(path.as_bytes()[root.len()], b'\\' | b'/')
}
