// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! The files a program recorded by BAM, PCA or the process list ran from.
//!
//! BAM and PCA record a program's path because it ran; the process list holds the path of an image
//! that is running now. This collector gathers those paths through the same host calls and the same
//! path logic their own collectors use ([`crate::bam::recorded_paths`],
//! [`crate::pca::recorded_paths`], [`crate::process::recorded_paths`]), keeps the drive-rooted ones
//! only, and reports one observation per distinct path ignoring ASCII case (ADR 0079 amendment 7).
//!
//! It is `full`: reading a file's bytes is beyond what a standard scan asks for (ADR 0052).
//! `identity_read` says what happened to that read, and a `read` carries what the bytes, the hash, the
//! signature and the `Zone.Identifier` stream say. Reads run nearest the newest `FiveM` or GTA V time
//! first, under a 90-second budget checked between files. An unreadable file is never a gap — the
//! whole run is gapped only when one of its sources could not be read at all, and then with that
//! source's reason.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use jiff::Timestamp;
use rongroi_core::model::{CollectorRun, Observation, UnmeasuredReason};
use rongroi_host::{Host, Platform, SourceError, is_refused_form};
use rongroi_parsers::content_kind::{self, FileKind};
use rongroi_parsers::powershell_text::DownloadHost;
use rongroi_parsers::{pe_version, zone_identifier};

use crate::failure::read_failure;
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
/// the same reason means in `bam`, `pca` or `process`. `not_on_this_os` is not here: PCA says it for a
/// Windows that never kept these files, and PCA then contributes neither a path nor a gap.
const REASONS: [UnmeasuredReason; 7] = [
    UnmeasuredReason::NotWindows,
    UnmeasuredReason::NotAdmin,
    UnmeasuredReason::AccessDenied,
    UnmeasuredReason::SourceAbsent,
    UnmeasuredReason::SourceEmpty,
    UnmeasuredReason::Partial,
    UnmeasuredReason::ReadFailed,
];

/// Every field this collector can emit.
///
/// A path is kept only when it begins with a drive letter, as `bam` and `pca` already keep theirs:
/// that is the shape `rongroi_core::view::redact_profile_paths` can reach. The three source flags are
/// always present, so a rule can ask which record pointed at the file. The two root flags are absent
/// when the environment does not say what the system drive or root is. The identity fields follow
/// `identity_read`: a `read` carries all that apply, a `too_large` still carries the hash and
/// signature, and every other answer carries none (ADR 0079 section 3). `download_host` is the one
/// sensitive field, behind its own SS-mode question (ADR 0064).
const FIELDS: [Field; 18] = [
    Field::boolean("by_bam"),
    Field::boolean("by_pca"),
    Field::boolean("by_process"),
    Field::text("content_kind"),
    Field::text("download_host").sensitive(SensitiveKind::DownloadHost),
    Field::boolean("embedded_pe"),
    Field::text("identity_read"),
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

/// The source that recorded a path.
#[derive(Debug, Clone, Copy)]
enum Source {
    Bam,
    Pca,
    Process,
}

/// One distinct path, which of the three records named it, and the newest time any gave it.
struct Candidate {
    /// The path as the first source that named it spelled it.
    path: String,
    by_bam: bool,
    by_pca: bool,
    by_process: bool,
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
            at: None,
        }
    }

    fn mark(&mut self, source: Source) {
        match source {
            Source::Bam => self.by_bam = true,
            Source::Pca => self.by_pca = true,
            Source::Process => self.by_process = true,
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
            file_limit: None,
        }
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

        let system_drive = system_drive(host);
        let system_root = system_root(host);
        let mut attempted = 0_usize;
        let observations = ordered
            .into_iter()
            .map(|candidate| {
                let spent = started.elapsed() >= self.budget
                    || self.file_limit.is_some_and(|limit| attempted >= limit);
                let identity = if spent {
                    Identity::alone("budget_spent")
                } else {
                    attempted += 1;
                    identity(host, &candidate.path)
                };
                observation(&candidate, system_drive, system_root.as_deref(), identity)
            })
            .collect();
        let gaps = source_gap.map(gaps).unwrap_or_default();
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

/// One recorded file: its path and name, which records pointed at it, what the read of it did, and
/// whether it lies on the system drive and under the system root.
fn observation(
    candidate: &Candidate,
    system_drive: Option<u8>,
    system_root: Option<&str>,
    identity: Identity,
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
