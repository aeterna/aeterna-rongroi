// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! The session statement: each `FiveM` edition's last session beside its own folders (ADR 0062, as
//! amended on 2026-10-02).
//!
//! A session has a start and an end, each from one record: a running process of the edition gives the
//! start and "still running"; otherwise Prefetch's latest run of the edition's anchor names gives the
//! start and BAM's latest its end. Each of the edition's sources is compared with the start only, and
//! "before the start" means earlier than it by more than [`MARGIN_SECONDS`]; one source, Enhanced's
//! log folder, is also compared with the end. Nothing is compared with the scan's own time, nothing is
//! stored between scans, and the statement is never evidence.

use serde::{Deserialize, Serialize};

use super::{observations_of, scan_time, time_of, unmeasured_reason, utc_date};
use crate::model::{Observation, Report, UnmeasuredReason};

/// The margin: a time earlier than the start by more than this is "before the start", and one earlier
/// than the end by more than this is "before the end" (ADR 0062 section 3, kept by the amendment).
pub const MARGIN_SECONDS: i64 = 600;

/// The editions, in the order their statements are shown.
const EDITIONS: [&str; 2] = ["legacy", "enhanced"];

/// The observation field `process`, `bam` and `prefetch` carry the edition in (ADR 0062).
const EDITION_FIELD: &str = "fivem_edition";

/// `fivem_dir`'s places this statement reads (ADR 0053).
const LEGACY_LOGS: &str = "legacy_logs";
const LEGACY_CACHE: &str = "legacy_cache";
/// Legacy's resource caches, one per launch mode (`variant`).
pub(super) const LEGACY_SERVER_CACHE: &str = "legacy_server_cache";
const ENHANCED_LOGS: &str = "enhanced_logs";
/// The launch modes of Legacy's resource cache, in the order they are shown.
const VARIANTS: [&str; 3] = ["default", "priv", "fxdk"];

/// One edition's last session beside its own folders (ADR 0062). Not evidence: no state, no rule, no
/// strength, never counted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionStatement {
    /// `legacy` or `enhanced`.
    pub edition: String,
    /// The session and its lines, or that when `FiveM` last ran is not known.
    #[serde(flatten)]
    pub state: SessionState,
}

/// What is known of one edition's last session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "session", rename_all = "snake_case")]
pub enum SessionState {
    /// A start or an end was recorded.
    Known {
        /// Where the start came from, or why there is none.
        start: SessionStart,
        /// Where the end came from, or why there is none.
        end: SessionEnd,
        /// How long before the scan the session ended — or began, when its end is not recorded. Absent
        /// while it is still running.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        before_scan: Option<Duration>,
        /// One line per source of the edition, in a fixed order.
        lines: Vec<SessionLine>,
        /// The ordinary causes, as locale keys, in the order they are printed; always printed in full.
        causes: Vec<String>,
    },
    /// Nothing of the edition is running, and neither Prefetch nor BAM was read: no comparison, and
    /// never one with the scan's time (ADR 0062 section 5). Only for an edition whose `FiveM.exe` is
    /// present.
    NotKnown {
        /// Why Prefetch was not read.
        prefetch: UnmeasuredReason,
        /// Why BAM was not read.
        bam: UnmeasuredReason,
    },
}

/// Which of the anchor names a session's time came from (ADR 0062 section 2, "Which names").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnchorName {
    /// `FiveM.exe`, the client of both editions.
    FivemExe,
    /// `FiveM_b…_GTAProcess.exe`, Legacy's game process.
    GtaProcess,
}

/// The start of a session, or why there is none.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "from", rename_all = "snake_case")]
pub enum SessionStart {
    /// A process of the edition is running: the earliest creation time among them.
    Process {
        /// The time, as the report holds it.
        at: String,
        /// Which name.
        name: AnchorName,
    },
    /// Prefetch's latest run of the edition.
    Prefetch {
        /// The time, as the report holds it.
        at: String,
        /// Which name.
        name: AnchorName,
    },
    /// Prefetch is switched off on this PC, so when this run began is not recorded.
    SwitchedOff,
    /// Prefetch was not read.
    NotRead {
        /// Why.
        reason: UnmeasuredReason,
    },
    /// Prefetch was read and holds no run of the edition's names.
    NotRecorded,
}

/// The end of a session, or why there is none.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "from", rename_all = "snake_case")]
pub enum SessionEnd {
    /// A process of the edition is running now.
    StillRunning,
    /// BAM's latest time for the edition, not earlier than the start.
    Bam {
        /// The time, as the report holds it.
        at: String,
    },
    /// BAM holds no time for the edition at or after the start.
    NotRecorded,
    /// BAM was not read.
    NotRead {
        /// Why.
        reason: UnmeasuredReason,
    },
}

/// A duration as it is shown: whole minutes under an hour, whole hours under two days, whole days
/// after that, each rounded down. `0` minutes is "less than a minute".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Duration {
    /// How many.
    pub amount: i64,
    /// Of what.
    pub unit: DurationUnit,
}

/// The unit of a [`Duration`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DurationUnit {
    /// Minutes.
    Minutes,
    /// Hours.
    Hours,
    /// Days.
    Days,
}

impl Duration {
    /// `seconds`, at least 0, in the unit it is shown in.
    pub fn of_seconds(seconds: i64) -> Self {
        let seconds = seconds.max(0);
        if seconds < 3_600 {
            Self {
                amount: seconds / 60,
                unit: DurationUnit::Minutes,
            }
        } else if seconds < 2 * 86_400 {
            Self {
                amount: seconds / 3_600,
                unit: DurationUnit::Hours,
            }
        } else {
            Self {
                amount: seconds / 86_400,
                unit: DurationUnit::Days,
            }
        }
    }
}

/// One source of the edition, in one of the ADR's line forms.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionLine {
    /// `legacy_logs`, `legacy_cache`, `legacy_resource_index` or `enhanced_logs`.
    pub source: String,
    /// The launch mode, for Legacy's resource cache index.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variant: Option<String>,
    /// What it says.
    #[serde(flatten)]
    pub state: LineState,
}

/// A source's line (ADR 0062 section 7, as amended). "Not read" is never folded into "not there" or
/// "no file", and none of them into "before the start".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "line", rename_all = "snake_case")]
pub enum LineState {
    /// Its times, compared.
    Compared {
        /// The latest file creation, for a log folder.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        created: Option<Comparison>,
        /// The latest write.
        written: Comparison,
    },
    /// The folder is not there.
    NotThere,
    /// The folder holds no file.
    NoFile,
    /// The index folder is there and could not be listed (ADR 0062 owner decision 2ก of 2026-10-02).
    NotListed,
    /// The place was not read.
    NotRead {
        /// Why.
        reason: UnmeasuredReason,
    },
}

/// One time compared with the session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Comparison {
    /// How it stands to the session.
    pub relation: Relation,
    /// How far from the start or the end.
    pub duration: Duration,
}

/// How a time stands to the session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Relation {
    /// Earlier than the start by more than the margin.
    BeforeStart,
    /// Any later time; a time within the margin before the start counts as 0.
    AfterStart,
    /// Enhanced's log folder only: earlier than the end by more than the margin.
    BeforeEnd,
    /// Enhanced's log folder when the start is not recorded: within the margin of the end.
    NearEnd,
    /// Enhanced's log folder when the start is not recorded: later than the end by more than the
    /// margin.
    AfterEnd,
}

/// One launch mode's index beside its oldest cache file (ADR 0062 section 4): two dates, never
/// compared.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexBeside {
    /// The launch mode.
    pub variant: String,
    /// The UTC date the index folder was created.
    pub index_created_on: String,
    /// The UTC date the oldest cache file was created; absent when the cache holds no file with a time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oldest_file_created_on: Option<String>,
    /// How many cache files the launch mode's folder holds, so that "holds no cache file" is told apart
    /// from files the listing gave no time for.
    #[serde(default)]
    pub cache_files: u64,
}

/// The ordinary causes printed first, before the general list (ADR 0062 amendment, change 1).
const FIRST_CAUSE: &str = "standing_still";
/// The cause the end comparison carries (ADR 0062 amendment, change 2).
const END_CAUSE: &str = "ended_abruptly";
/// The general list, in section 7's order, less the join cause it opens with: no source compared is
/// written only on joining a server (ADR 0062 owner decision 12 of 2026-10-02).
const GENERAL_CAUSES: [&str; 8] = [
    "removes_logs",
    "other_folder",
    "other_account",
    "opened_closed",
    "launchers",
    "prefetch_off",
    "clock",
    "cleanup",
];

/// The session statements, Legacy's then Enhanced's, each when its edition has one.
pub(super) fn sessions(report: &Report) -> Vec<SessionStatement> {
    EDITIONS
        .iter()
        .filter_map(|edition| session(report, edition))
        .collect()
}

fn text<'o>(observation: &'o Observation, field: &str) -> Option<&'o str> {
    observation
        .fields
        .get(field)
        .and_then(serde_json::Value::as_str)
}

fn timestamp(observation: &Observation, field: &str) -> Option<jiff::Timestamp> {
    time_of(observation, field).and_then(|text| text.parse().ok())
}

/// The anchor name `name` is for `edition`, if it is one (ADR 0062 section 2, "Which names"): the
/// client for both editions, Legacy's game process for Legacy. GTA V's own executables and `FiveM`'s
/// other processes are not anchors.
fn anchor_name(name: &str, edition: &str) -> Option<AnchorName> {
    let name = name.to_ascii_lowercase();
    if name == "fivem.exe" {
        Some(AnchorName::FivemExe)
    } else if edition == "legacy"
        && name.starts_with("fivem_b")
        && name.ends_with("_gtaprocess.exe")
    {
        Some(AnchorName::GtaProcess)
    } else {
        None
    }
}

/// `collector`'s observations of `edition`'s anchor names, with the time in `field`.
fn anchors(
    report: &Report,
    collector: &str,
    edition: &str,
    field: &str,
) -> Vec<(jiff::Timestamp, String, AnchorName)> {
    observations_of(report, collector)
        .into_iter()
        .filter(|observation| text(observation, EDITION_FIELD) == Some(edition))
        .filter_map(|observation| {
            let name = anchor_name(text(observation, "name")?, edition)?;
            let time: jiff::Timestamp = time_of(observation, field)?.parse().ok()?;
            // To the second, as the timeline shows FiveM's selectors (ADR 0051); Prefetch and BAM keep
            // 100-nanosecond fractions the statement does not print.
            let time = jiff::Timestamp::from_second(time.as_second()).ok()?;
            Some((time, time.to_string(), name))
        })
        .collect()
}

/// Whether `collector` was read in a way that lets "no entry" be said: a reason that says the source
/// was looked at and held nothing is a read; any other is not.
fn not_read(reason: Option<UnmeasuredReason>) -> Option<UnmeasuredReason> {
    match reason {
        None
        | Some(
            UnmeasuredReason::SourceEmpty
            | UnmeasuredReason::SourceAbsent
            | UnmeasuredReason::NotOnThisOs,
        ) => None,
        Some(reason) => Some(reason),
    }
}

/// Whether `fivem_dir` found `edition`'s `FiveM.exe`.
fn fivem_exe_present(report: &Report, edition: &str) -> bool {
    let place = match edition {
        "legacy" => "legacy_exe",
        _ => "enhanced_exe",
    };
    observations_of(report, "fivem_dir")
        .iter()
        .any(|observation| {
            text(observation, "location") == Some(place) && observation.fields.contains_key("path")
        })
}

/// A session's start and end as the records give them, with the times compared against.
struct Anchors {
    start: SessionStart,
    start_time: Option<jiff::Timestamp>,
    end: SessionEnd,
    end_time: Option<jiff::Timestamp>,
    running: bool,
}

fn session(report: &Report, edition: &str) -> Option<SessionStatement> {
    let state = match session_anchors(report, edition) {
        Ok(anchors) => known(report, edition, anchors),
        Err(state) => state?,
    };
    Some(SessionStatement {
        edition: edition.to_owned(),
        state,
    })
}

/// The session's anchors (ADR 0062 section 2 and section 5), or — when nothing of the edition runs
/// and no record attributes a run to it — "not known" when neither record was read and the edition's
/// `FiveM.exe` is present, and no statement otherwise: read and holding nothing of it, ADR 0061's
/// statement is the one that speaks.
fn session_anchors(report: &Report, edition: &str) -> Result<Anchors, Option<SessionState>> {
    let prefetch_reason = unmeasured_reason(report, "prefetch", None);
    let bam_reason = unmeasured_reason(report, "bam", None);
    let running = observations_of(report, "process")
        .iter()
        .any(|observation| {
            text(observation, EDITION_FIELD) == Some(edition)
                && text(observation, "name")
                    .is_some_and(|name| anchor_name(name, edition).is_some())
        });
    // Records of a Prefetch that is switched off are not this session's: Windows is not writing them.
    let prefetch = if prefetch_reason == Some(UnmeasuredReason::ServiceDisabled) {
        None
    } else {
        anchors(report, "prefetch", edition, "last_run")
            .into_iter()
            .max_by_key(|(time, _, _)| *time)
    };
    let bam = anchors(report, "bam", edition, "last_run")
        .into_iter()
        .max_by_key(|(time, _, _)| *time);
    let prefetch_unread = match prefetch_reason {
        Some(UnmeasuredReason::ServiceDisabled) => prefetch_reason,
        reason => not_read(reason),
    };
    if !running && prefetch.is_none() && bam.is_none() {
        return Err(match (prefetch_unread, not_read(bam_reason)) {
            (Some(prefetch), Some(bam)) if fivem_exe_present(report, edition) => {
                Some(SessionState::NotKnown { prefetch, bam })
            }
            _ => None,
        });
    }
    let earliest = if running {
        anchors(report, "process", edition, "started_at")
            .into_iter()
            .min_by_key(|(time, _, _)| *time)
    } else {
        None
    };
    // A running process whose creation time could not be read leaves the start to Prefetch, as when
    // nothing runs.
    let (start, start_time) = match (earliest, prefetch) {
        (Some((time, at, name)), _) => (SessionStart::Process { at, name }, Some(time)),
        (None, Some((time, at, name))) => (SessionStart::Prefetch { at, name }, Some(time)),
        (None, None) => match (prefetch_reason, prefetch_unread) {
            (Some(UnmeasuredReason::ServiceDisabled), _) => (SessionStart::SwitchedOff, None),
            (_, Some(reason)) => (SessionStart::NotRead { reason }, None),
            (_, None) => (SessionStart::NotRecorded, None),
        },
    };
    let (end, end_time) = match bam {
        _ if running => (SessionEnd::StillRunning, None),
        Some((time, _, _)) if start_time.is_some_and(|start| time < start) => {
            (SessionEnd::NotRecorded, None)
        }
        Some((time, at, _)) => (SessionEnd::Bam { at }, Some(time)),
        None => match not_read(bam_reason) {
            Some(reason) => (SessionEnd::NotRead { reason }, None),
            None => (SessionEnd::NotRecorded, None),
        },
    };
    Ok(Anchors {
        start,
        start_time,
        end,
        end_time,
        running,
    })
}

/// The statement of a session with anchors: its lines and causes.
fn known(report: &Report, edition: &str, anchors: Anchors) -> SessionState {
    let Anchors {
        start,
        start_time,
        end,
        end_time,
        running,
    } = anchors;
    let before_scan = scan_time(report)
        .zip(end_time.or(if running { None } else { start_time }))
        .map(|(scan, time)| Duration::of_seconds(scan.as_second() - time.as_second()));
    let lines = match edition {
        "legacy" => legacy_lines(report, start_time),
        _ => enhanced_lines(report, start_time, end_time),
    };
    let mut causes = vec![FIRST_CAUSE.to_owned()];
    // The end comparison was made: Enhanced's log folder was compared and the end is BAM's.
    let end_compared = end_time.is_some()
        && lines.iter().any(|line| {
            line.source == ENHANCED_LOGS && matches!(line.state, LineState::Compared { .. })
        });
    if end_compared {
        causes.push(END_CAUSE.to_owned());
    }
    causes.extend(GENERAL_CAUSES.iter().map(|cause| (*cause).to_owned()));
    SessionState::Known {
        start,
        end,
        before_scan,
        lines,
        causes,
    }
}

/// `time` against the start: "before" only beyond the margin, otherwise "after", with a time within
/// the margin before the start counting as 0.
pub(super) fn against_start(time: jiff::Timestamp, start: jiff::Timestamp) -> Comparison {
    let after = time.as_second() - start.as_second();
    if -after > MARGIN_SECONDS {
        Comparison {
            relation: Relation::BeforeStart,
            duration: Duration::of_seconds(-after),
        }
    } else {
        Comparison {
            relation: Relation::AfterStart,
            duration: Duration::of_seconds(after),
        }
    }
}

/// Enhanced's log folder's latest write: against the start like every source, and "before the end"
/// when it is not before the start and is earlier than the end by more than the margin. With no start,
/// against the end alone.
fn against_end(
    time: jiff::Timestamp,
    start: Option<jiff::Timestamp>,
    end: Option<jiff::Timestamp>,
) -> Option<Comparison> {
    let from_start = start.map(|start| against_start(time, start));
    if let Some(comparison) = from_start
        && comparison.relation == Relation::BeforeStart
    {
        return Some(comparison);
    }
    let Some(end) = end else {
        return from_start;
    };
    let before_end = end.as_second() - time.as_second();
    if before_end > MARGIN_SECONDS {
        return Some(Comparison {
            relation: Relation::BeforeEnd,
            duration: Duration::of_seconds(before_end),
        });
    }
    if from_start.is_some() {
        return from_start;
    }
    Some(if -before_end > MARGIN_SECONDS {
        Comparison {
            relation: Relation::AfterEnd,
            duration: Duration::of_seconds(-before_end),
        }
    } else {
        Comparison {
            relation: Relation::NearEnd,
            duration: Duration::of_seconds(before_end),
        }
    })
}

/// Each folder-activity observation of `place`, or the line that says why there is none to compare.
fn place_observations<'r>(
    report: &'r Report,
    place: &str,
) -> Result<Vec<&'r Observation>, LineState> {
    if let Some(reason) = unmeasured_reason(report, "fivem_dir", None)
        .or_else(|| unmeasured_reason(report, "fivem_dir", Some(place)))
    {
        return Err(LineState::NotRead { reason });
    }
    let found: Vec<&Observation> = observations_of(report, "fivem_dir")
        .into_iter()
        .filter(|observation| {
            text(observation, "location") == Some(place)
                && observation.fields.contains_key("folder")
        })
        .collect();
    if found.is_empty() {
        return Err(LineState::NotThere);
    }
    Ok(found)
}

/// One folder's own state when it was not listed: absent, unreadable, or listed.
fn folder_state(observation: &Observation) -> Option<LineState> {
    match text(observation, "folder") {
        Some("absent") => Some(LineState::NotThere),
        Some("unreadable") => Some(LineState::NotRead {
            reason: UnmeasuredReason::ReadFailed,
        }),
        _ => None,
    }
}

fn files(observation: &Observation) -> Option<u64> {
    observation
        .fields
        .get("files")
        .and_then(serde_json::Value::as_u64)
}

/// The line of a folder-activity place compared with the start, by its latest write and, for a log
/// folder, its latest creation.
fn folder_line(
    report: &Report,
    place: &str,
    source: &str,
    with_created: bool,
    start: jiff::Timestamp,
) -> SessionLine {
    let state = match place_observations(report, place) {
        Err(state) => state,
        Ok(found) => {
            let observation = found[0];
            folder_state(observation).unwrap_or_else(|| {
                match timestamp(observation, "latest_modified_at") {
                    Some(written) => LineState::Compared {
                        created: with_created
                            .then(|| timestamp(observation, "latest_created_at"))
                            .flatten()
                            .map(|created| against_start(created, start)),
                        written: against_start(written, start),
                    },
                    None if files(observation) == Some(0) => LineState::NoFile,
                    None => LineState::NotRead {
                        reason: UnmeasuredReason::ReadFailed,
                    },
                }
            })
        }
    };
    SessionLine {
        source: source.to_owned(),
        variant: None,
        state,
    }
}

/// Legacy's lines: its logs, its `data\cache`, and the resource cache index of each launch mode — all
/// launch sources compared with the start (ADR 0062 amendment, changes 1 and 4). With no start there is
/// nothing to compare: Legacy has no end comparison.
fn legacy_lines(report: &Report, start: Option<jiff::Timestamp>) -> Vec<SessionLine> {
    let Some(start) = start else {
        return Vec::new();
    };
    let mut lines = vec![
        folder_line(report, LEGACY_LOGS, LEGACY_LOGS, true, start),
        folder_line(report, LEGACY_CACHE, LEGACY_CACHE, false, start),
    ];
    let index_line = |variant: Option<String>, state| SessionLine {
        source: "legacy_resource_index".to_owned(),
        variant,
        state,
    };
    match place_observations(report, LEGACY_SERVER_CACHE) {
        Err(state) => lines.push(index_line(None, state)),
        Ok(found) => {
            for variant in VARIANTS {
                let Some(observation) = found
                    .iter()
                    .find(|observation| text(observation, "variant") == Some(variant))
                else {
                    continue;
                };
                let state =
                    folder_state(observation).unwrap_or_else(|| index_state(observation, start));
                lines.push(index_line(Some(variant.to_owned()), state));
            }
        }
    }
    lines
}

/// One launch mode's index: not there, not listed (decision 2ก), no file, or its latest write.
fn index_state(observation: &Observation, start: jiff::Timestamp) -> LineState {
    let has = |field: &str| observation.fields.contains_key(field);
    if !has("index_created_at") && !has("index_modified_at") && !has("index_files") {
        return LineState::NotThere;
    }
    match observation
        .fields
        .get("index_files")
        .and_then(serde_json::Value::as_u64)
    {
        None => LineState::NotListed,
        Some(0) => LineState::NoFile,
        Some(_) => match timestamp(observation, "index_latest_modified_at") {
            Some(written) => LineState::Compared {
                created: None,
                written: against_start(written, start),
            },
            None => LineState::NotRead {
                reason: UnmeasuredReason::ReadFailed,
            },
        },
    }
}

/// Enhanced's line: its log folder, a launch source compared with the start, and its latest write with
/// the end too (owner decision 9 of 2026-10-02, in ADR 0062's "As built"). With no start, only the end
/// comparison. Its per-server cache is not compared (owner decision 12): the times read of a server folder
/// change only when an entry is added or removed, not when a join rewrites the files inside it.
fn enhanced_lines(
    report: &Report,
    start: Option<jiff::Timestamp>,
    end: Option<jiff::Timestamp>,
) -> Vec<SessionLine> {
    let mut lines = Vec::new();
    let logs = match place_observations(report, ENHANCED_LOGS) {
        Err(state) => Some(state),
        Ok(found) => {
            let observation = found[0];
            folder_state(observation).or_else(|| {
                match timestamp(observation, "latest_modified_at") {
                    Some(written) => {
                        against_end(written, start, end).map(|written| LineState::Compared {
                            created: start
                                .zip(timestamp(observation, "latest_created_at"))
                                .map(|(start, created)| against_start(created, start)),
                            written,
                        })
                    }
                    None if files(observation) == Some(0) => Some(LineState::NoFile),
                    None => Some(LineState::NotRead {
                        reason: UnmeasuredReason::ReadFailed,
                    }),
                }
            })
        }
    };
    if let Some(state) = logs
        && (start.is_some() || end.is_some())
    {
        lines.push(SessionLine {
            source: ENHANCED_LOGS.to_owned(),
            variant: None,
            state,
        });
    }
    lines
}

/// Each Legacy launch mode's index creation date beside its oldest cache file's (ADR 0062 section 4),
/// for the modes whose index folder has a creation time.
pub(super) fn index_beside(report: &Report) -> Vec<IndexBeside> {
    let found: Vec<&Observation> = observations_of(report, "fivem_dir")
        .into_iter()
        .filter(|observation| {
            text(observation, "location") == Some(LEGACY_SERVER_CACHE)
                && observation.fields.contains_key("folder")
        })
        .collect();
    VARIANTS
        .iter()
        .filter_map(|variant| {
            let observation = found
                .iter()
                .find(|observation| text(observation, "variant") == Some(variant))?;
            Some(IndexBeside {
                variant: (*variant).to_owned(),
                index_created_on: utc_date(timestamp(observation, "index_created_at")?),
                oldest_file_created_on: timestamp(observation, "earliest_created_at").map(utc_date),
                cache_files: files(observation).unwrap_or(0),
            })
        })
        .collect()
}
