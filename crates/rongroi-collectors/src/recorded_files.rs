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
//! It is `full`: reading a file's bytes is beyond what a standard scan asks for (ADR 0052). In C1 an
//! observation says only whether those bytes arrived, as `identity_read`; the identity fields built
//! from them come with the read budget in C2. An unreadable file is never a gap — the whole run is
//! gapped only when one of its sources could not be read at all, and then with that source's reason.

use std::collections::BTreeMap;

use rongroi_core::model::{CollectorRun, Observation, UnmeasuredReason};
use rongroi_host::{Host, Platform, is_refused_form};

use crate::failure::read_failure;
use crate::paths::{file_name, is_drive_rooted};
use crate::{Collector, Field, ScanTier};

const ID: &str = "recorded_files";

/// Every reason this collector gives for not having looked (`Collector::unmeasured_reasons`).
///
/// `not_windows` is its own answer. The rest are what one of its sources gives when that source could
/// not be read: this collector adds no vocabulary of its own, because a gap here means exactly what
/// the same reason means in `bam`, `pca` or `process`.
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
/// A path is kept only when it begins with a drive letter, as `bam` and `pca` already keep theirs:
/// that is the shape `rongroi_core::view::redact_profile_paths` can reach. The three source flags are
/// always present, so a rule can ask which record pointed at the file. The two root flags are absent
/// when the environment does not say what the system drive or root is. `identity_read` is present on
/// every observation, including a standard scan's (ADR 0079 section 3).
const FIELDS: [Field; 8] = [
    Field::boolean("by_bam"),
    Field::boolean("by_pca"),
    Field::boolean("by_process"),
    Field::text("identity_read"),
    Field::text("name"),
    Field::boolean("on_system_drive"),
    Field::text("path"),
    Field::boolean("under_system_root"),
];

/// The source that recorded a path.
#[derive(Debug, Clone, Copy)]
enum Source {
    Bam,
    Pca,
    Process,
}

/// One distinct path, and which of the three records named it.
struct Candidate {
    /// The path as the first source that named it spelled it.
    path: String,
    by_bam: bool,
    by_pca: bool,
    by_process: bool,
}

impl Candidate {
    fn at(path: String) -> Self {
        Self {
            path,
            by_bam: false,
            by_pca: false,
            by_process: false,
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
#[derive(Debug, Default, Clone, Copy)]
pub struct RecordedFiles {
    /// How many files this run may read before the rest say `budget_spent`; `None` reads every one.
    ///
    /// The discovery read this change adds reads every path. The identity read applies this limit
    /// between files (ADR 0079 section 4).
    pub file_limit: Option<usize>,
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
        for (source, paths) in [
            (Source::Bam, crate::bam::recorded_paths(host)),
            (Source::Pca, crate::pca::recorded_paths(host)),
            (Source::Process, crate::process::recorded_paths(host)),
        ] {
            match paths {
                Ok(paths) => {
                    for path in paths {
                        if !is_drive_rooted(&path) {
                            continue;
                        }
                        let key = path.to_ascii_lowercase();
                        candidates
                            .entry(key)
                            .or_insert_with(|| Candidate::at(path))
                            .mark(source);
                    }
                }
                // One source that could not be read loses an unknown number of paths, so the whole
                // run is a gap. The paths the other sources gave are still reported.
                Err(reason) => source_gap = source_gap.or(Some(reason)),
            }
        }

        let system_drive = system_drive(host);
        let system_root = system_root(host);
        let observations = candidates
            .into_values()
            .map(|candidate| observation(host, &candidate, system_drive, system_root.as_deref()))
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
    host: &dyn Host,
    candidate: &Candidate,
    system_drive: Option<u8>,
    system_root: Option<&str>,
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
        serde_json::Value::from(identity_read(host, &candidate.path)),
    );
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

/// What happened to the read of one file, in the words ADR 0079 section 3 gives.
///
/// A form this program refuses is not read at all. `read` means only that the bytes arrived; C2 adds
/// what they say. A file that is gone or refused is never a gap: one file's absence says nothing
/// about the paths the other records gave.
fn identity_read(host: &dyn Host, path: &str) -> &'static str {
    if is_refused_form(path) {
        return "refused_form";
    }
    match host.read_file(path) {
        Ok(Some(_)) => "read",
        Ok(None) => "missing",
        Err(error) => read_failure(&error),
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
