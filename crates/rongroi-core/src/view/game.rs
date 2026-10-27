// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! Programs Windows recorded near a `FiveM` session (ADR 0078). A view, never evidence.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::{
    TraceAgeState, observations_of, redact_profile_paths, scan_time, session, time_of, trace_ages,
};
use crate::digest::{path_digest, volume_path_digest};
use crate::loaded_files::PE_EXTENSIONS;
use crate::model::{Mode, Observation, Report};

/// How far before a session's start and after its end a window reaches (ADR 0078 section 3).
pub const WINDOW_SECONDS: i64 = 30 * 60;
/// What one of the four windows of a session says about a candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "fact", rename_all = "snake_case")]
pub enum TimeFact {
    /// One of the candidate's times is inside a window of this kind.
    True,
    /// The source covers the window and holds no such time.
    False,
    /// The window, or the source that would cover it, is not known.
    NotKnown {
        /// Why it is not known.
        reason: NotKnownReason,
    },
}
/// Why a time fact is not known (ADR 0078 sections 4 and 5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum NotKnownReason {
    /// An earlier session has no recorded end, so its during and after windows are not known.
    SessionEndNotRecorded,
    /// The report names no scan time, so the before-the-scan window is not known.
    ScanTimeNotRecorded,
    /// The window is earlier than what the source still covers (ADR 0061's trace ages).
    BeforeTraceAge {
        /// The source whose records do not reach that far back.
        source: String,
    },
}
/// Whether a candidate's file identity fact is true, false, or not known (ADR 0078 section 5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "fact", rename_all = "snake_case")]
pub enum IdentityFact {
    /// The fact holds.
    True,
    /// The fact does not hold within what was read.
    False,
    /// The fact is not known.
    NotKnown {
        /// Why it is not known.
        reason: IdentityNotKnownReason,
    },
}
/// Why a file identity fact is not known (ADR 0079).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum IdentityNotKnownReason {
    /// A standard scan does not run `recorded_files` (ADR 0052, ADR 0079 amendment 7).
    RecordedFilesNotRun,
    /// `recorded_files` ran but holds no observation for the path.
    NoObservationForPath,
    /// The path was not read; `identity_read` says why.
    NotRead,
    /// The signature could not be checked offline (ADR 0035).
    Unverifiable,
    /// The candidate has no program path, so nothing can be joined (ADR 0078 section 4).
    NoPath,
    /// The fields I3 or I4 needs were not read (ADR 0078 section 5).
    Deferred,
    /// No Prefetch record of the program carries `loaded_outside`, or it says
    /// `loaded_outside_unknown` (ADR 0082 section 5).
    NotCounted,
    /// An earlier session's end is never known, so no record can be placed in it (ADR 0082
    /// section 5).
    EarlierSession,
    /// The change journal was not read for the path, so it says nothing about it (ADR 0086
    /// section 5).
    JournalNotRead,
    /// The journal is on another volume than the path's folder (ADR 0086 section 5).
    JournalOtherDrive,
    /// The path's folder is not one the journal can be read for (ADR 0086 section 5).
    JournalFolderUnknown,
    /// A latest session has no recorded end, so its during, after and before-the-scan windows are
    /// not known (ADR 0086 section 5).
    SessionEndNotRecorded,
    /// The report names no scan time, so the before-the-scan window is not known (ADR 0086
    /// section 5).
    ScanTimeNotRecorded,
    /// The journal does not reach back to the window (ADR 0086 section 5), as
    /// `NotKnownReason::BeforeTraceAge` does for the other sources.
    BeforeTraceAge {
        /// The source whose records do not reach that far back.
        source: String,
    },
}
/// How many sessions' windows hold one of a candidate's times, out of the sessions found (R).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NearSessions {
    /// Sessions with a window holding one of the candidate's times.
    pub near: usize,
    /// Sessions the view found.
    pub found: usize,
}
/// One edition's session as the view shows it (ADR 0078 section 2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GameSession {
    /// `legacy` or `enhanced`.
    pub edition: String,
    /// The start ADR 0062 found, or Prefetch's earlier run time.
    pub start: String,
    /// BAM's end, for the latest session only.
    pub end: Option<String>,
    /// Whether this is ADR 0062's latest session of its edition.
    pub latest: bool,
    /// L1: the records that feed this session loaded a file from outside (ADR 0082 section 5).
    #[serde(default = "not_counted")]
    pub l1: IdentityFact,
    /// The files the records feeding this session loaded from outside, summed; `None` when none of
    /// them carries the count. A count only: no name (ADR 0082 section 5).
    #[serde(default)]
    pub loaded_outside: Option<u64>,
}
/// What `recorded_files` read of a candidate's file, or why it read none (ADR 0079 section 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileRead {
    /// The file was read.
    Read,
    /// The file is no longer at its path.
    Missing,
    /// The file is over 64 MiB; only its hash and signature were read.
    TooLarge,
    /// Windows did not allow the file to be read.
    AccessDenied,
    /// The read did not finish, or the observation says nothing about it.
    Failed,
    /// The read refused the file's form, so its fields were not read.
    RefusedForm,
    /// The collector's budget ran out before it reached the file.
    BudgetSpent,
    /// `recorded_files` did not run, as on a standard scan.
    NotRun,
    /// The candidate has no program path, as a Prefetch-only one does, so nothing was joined.
    NoPath,
    /// `recorded_files` ran but holds no observation for the candidate's path.
    NoObservation,
}
/// What `recorded_files` read of a candidate's file, ADR 0079 section 3; evidence only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileDetails {
    /// Whether the file was read, or why it was not.
    pub read: FileRead,
    /// The file's SHA-256, when the read carried it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// The embedded signature's state, as the read named it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    /// The name of the signer, when the signature carried one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<String>,
    /// The SHA-256 of the signer's certificate, when the signature carried one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_cert_sha256: Option<String>,
    /// What the file is, by its content.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_kind: Option<String>,
    /// The version resource's `OriginalFilename`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_filename: Option<String>,
    /// The host the file's `Zone.Identifier` stream names, the website it was downloaded from; SS
    /// mode shows `%DOWNLOAD_HOST%` unless the player agreed (ADR 0064).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub download_host: Option<String>,
    /// Whether bytes follow the end of the file's format, decided for PNG, JPEG, GIF and zip only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trailing_data: Option<bool>,
    /// Whether a PE image sits inside a file that is not itself a PE.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub embedded_pe: Option<bool>,
    /// The `ZoneId` of the file's `Zone.Identifier` stream, when it fits a `u32`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zone_id: Option<u32>,
    /// The change journal's deletion times for the file, newest first, when a whole read matched it
    /// (ADR 0086 section 5).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub journal_deleted: Option<Vec<String>>,
    /// The change journal's rename-from times for the file, newest first (ADR 0086 section 5).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub journal_renamed_from: Option<Vec<String>>,
    /// The change journal's rename-to times for the file, newest first (ADR 0086 section 5).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub journal_renamed_to: Option<Vec<String>>,
    /// Whether the journal holds more times for the file than its lists show (ADR 0086 section 5).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub journal_more: Option<bool>,
}
/// One program Windows recorded with a time in a game window (ADR 0078 section 4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GameCandidate {
    /// The executable name, as the record holds it.
    pub name: String,
    /// The recorded path, when a record carried one.
    pub path: Option<String>,
    /// T1: a time in a before window.
    pub t1: TimeFact,
    /// T2: a time in a during window.
    pub t2: TimeFact,
    /// T3: a time in an after window.
    pub t3: TimeFact,
    /// T4: a time in the before-the-scan window.
    pub t4: TimeFact,
    /// I1: the recorded file is no longer at its path (ADR 0078 section 5).
    pub i1: IdentityFact,
    /// I2: the file's embedded signature is not `valid`, including none (ADR 0035).
    pub i2: IdentityFact,
    /// I3: its name contradicts what the file is or did (ADR 0078 section 5).
    pub i3: IdentityFact,
    /// I4: its path is under Temp or Downloads (ADR 0078 section 5).
    pub i4: IdentityFact,
    /// I5: the change journal holds a deletion or rename of its file in a window of a latest session
    /// (ADR 0086 section 5).
    pub i5: IdentityFact,
    /// L1: it loaded a file with an executable's extension from outside Windows, Program Files and
    /// `FiveM`'s folders (ADR 0082 section 5).
    #[serde(default = "not_counted")]
    pub l1: IdentityFact,
    /// R: how many sessions' windows hold one of its times.
    pub near_sessions: NearSessions,
    /// When the System log recorded an install of this file, as a note: it moves no time fact, no
    /// order and no count (ADR 0081 section 4).
    #[serde(default)]
    pub installed_at: Vec<String>,
    /// Whether the code-integrity log refused this file's image (ADR 0081 section 4).
    #[serde(default)]
    pub refused_by_code_integrity: bool,
    /// The collectors that recorded one of its times, each once, in the order `gather` reads them
    /// (ADR 0078 section 4).
    #[serde(default)]
    pub recorded_by: Vec<String>,
    /// What `recorded_files` read of its path (ADR 0079 section 3). Always set by `game_windows`;
    /// absent only in a view saved before this field existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<FileDetails>,
}
impl GameCandidate {
    /// The candidate as SS mode shows it: its path redacted as evidence rows are (ADR 0049).
    fn redacted(mut self, profiles: Option<&str>) -> Self {
        self.path = self
            .path
            .as_deref()
            .map(|path| redact_profile_paths(path, profiles));
        self
    }
}
/// How many candidates have a time in each window, in both modes (ADR 0078 section 9).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowCounts {
    /// Candidates with a time in a before window.
    pub before: usize,
    /// Candidates with a time in a during window.
    pub during: usize,
    /// Candidates with a time in an after window.
    pub after: usize,
    /// Candidates with a time in the before-the-scan window.
    pub before_scan: usize,
}
/// How many installs with no matching candidate have a time in each window (ADR 0081 section 4).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallCounts {
    /// Installs with a time in a before window.
    pub before: usize,
    /// Installs with a time in a during window.
    pub during: usize,
    /// Installs with a time in an after window.
    pub after: usize,
}
/// One clock change the event logs recorded inside the compared span (ADR 0081 section 3). It says
/// when the change happened and the clock's times either side of it, never why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClockLine {
    /// When the change happened, as the log holds it.
    pub changed_at: String,
    /// The clock's time before the change, when the record held one.
    pub old_time: Option<String>,
    /// The clock's time after the change, when the record held one.
    pub new_time: Option<String>,
}
/// Whether the System log reaches back to the compared span's start, so an absent clock change
/// there would show as absent (ADR 0081 section 3).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClockHistory {
    /// The System log was read, holds no rejected record and its oldest record is at or before the
    /// span's start.
    Known,
    /// The System log was not read, was gapped, or its oldest record falls inside the span.
    #[default]
    NotKnown,
}
/// The clock changes inside the compared span and whether the history before them is known.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClockTrust {
    /// Every clock change inside the span, oldest first; a note that moves no fact, order or count.
    pub changes: Vec<ClockLine>,
    /// Whether the logs reach back far enough to say the span holds every change.
    pub history: ClockHistory,
}
/// The programs Windows recorded near a `FiveM` session (ADR 0078). With no session, every list is
/// empty and every count is zero.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GameWindows {
    /// One latest session per edition, then the earlier sessions Prefetch kept.
    pub sessions: Vec<GameSession>,
    /// Self mode's candidates; in SS mode only those with a true identity fact, their paths redacted.
    pub candidates: Vec<GameCandidate>,
    /// How many candidates each window holds, in both modes.
    pub counts: WindowCounts,
    /// The programs SS mode counts rather than names (ADR 0078 section 9): how many of the
    /// candidates it does not list have a time in each window. Zero in Self mode.
    #[serde(default)]
    pub unnamed: WindowCounts,
    /// Installs with no matching candidate, by the window their time falls in (ADR 0081 section 4).
    #[serde(default)]
    pub unmatched_installs: InstallCounts,
    /// Clock changes inside the compared span, and whether the clock history is known (ADR 0081
    /// section 3). A note: it moves no candidate, order or count.
    #[serde(default)]
    pub clock: ClockTrust,
}

/// The game-windows view for `mode` (ADR 0078): every candidate in Self mode; in SS mode only those
/// with a true identity fact, their paths redacted as rows are (ADR 0078 section 9).
pub fn game_windows(report: &Report, mode: Mode) -> GameWindows {
    let sessions = timed_sessions(report);
    if sessions.is_empty() {
        return GameWindows::default();
    }
    let scan = scan_time(report);
    let candidates = gather(report, &sessions, scan);
    let counts = counts_of(&candidates, &sessions, scan);
    let events = EventRecords::of(report);
    let unmatched_installs = unmatched_installs_of(&candidates, &events, &sessions, scan);
    let found = sessions.len();
    let oldest = oldest_by_source(report);
    let files = RecordedFiles::of(report);
    let mut shown: Vec<(GameCandidate, i64)> = candidates
        .into_iter()
        .map(|candidate| {
            let earliest = candidate
                .times
                .iter()
                .map(|time| time.as_second())
                .min()
                .unwrap_or(i64::MAX);
            let mut facts = with_facts(&candidate, &sessions, scan, &oldest, found, &files);
            facts.installed_at = events.installed_at(&candidate);
            facts.refused_by_code_integrity = events.refuses(&candidate);
            (facts, earliest)
        })
        .collect();
    shown.sort_by(|(left, left_time), (right, right_time)| {
        identity_rank(right)
            .cmp(&identity_rank(left))
            .then_with(|| true_facts(right).cmp(&true_facts(left)))
            .then_with(|| left_time.cmp(right_time))
    });
    let profiles = report.header.profiles_directory.as_deref();
    let mut unnamed = WindowCounts::default();
    let candidates: Vec<GameCandidate> = shown
        .into_iter()
        .filter_map(|(candidate, _)| match mode {
            Mode::SelfCheck => Some(candidate),
            Mode::Ss if has_identity_fact(&candidate) => Some(candidate.redacted(profiles)),
            Mode::Ss => {
                unnamed.before += usize::from(candidate.t1 == TimeFact::True);
                unnamed.during += usize::from(candidate.t2 == TimeFact::True);
                unnamed.after += usize::from(candidate.t3 == TimeFact::True);
                unnamed.before_scan += usize::from(candidate.t4 == TimeFact::True);
                None
            }
        })
        .collect();
    let loads = session_loads(report, &sessions);
    GameWindows {
        sessions: sessions
            .iter()
            .zip(loads)
            .map(|(session, (l1, loaded_outside))| game_session(session, l1, loaded_outside))
            .collect(),
        candidates,
        counts,
        unnamed,
        unmatched_installs,
        clock: clock_of(report, &sessions),
    }
}

/// The clock changes inside the compared span, and whether the history before them is known
/// (ADR 0081 section 3). The span runs from the earliest before-window's start to the latest
/// after-window's end, so a change there is a line even when no candidate sits beside it.
fn clock_of(report: &Report, sessions: &[TimedSession]) -> ClockTrust {
    let Some(span_start) = sessions
        .iter()
        .map(|session| session.start.as_second().saturating_sub(WINDOW_SECONDS))
        .min()
    else {
        return ClockTrust::default();
    };
    let scan = scan_time(report);
    let span_end = sessions
        .iter()
        .map(|session| match session.end.filter(|_| session.latest) {
            Some(end) => end.as_second().saturating_add(WINDOW_SECONDS),
            // A latest session with no recorded end runs to the scan, or else as far as its after
            // window reaches, so a change during it is not dropped (ADR 0081 section 3).
            None if session.latest => match scan {
                Some(scan) => scan.as_second(),
                None => session.start.as_second().saturating_add(WINDOW_SECONDS),
            },
            None => session.start.as_second(),
        })
        .max()
        .unwrap_or(span_start);
    let mut changes: Vec<(jiff::Timestamp, ClockLine)> = Vec::new();
    for observation in observations_of(report, "event_fields") {
        let Some(text) = time_of(observation, "changed_at") else {
            continue;
        };
        let Some(changed_time) = parse_time(text) else {
            continue;
        };
        if changed_time.as_second() < span_start || changed_time.as_second() > span_end {
            continue;
        }
        changes.push((
            changed_time,
            ClockLine {
                changed_at: text.to_owned(),
                old_time: clock_time(observation, "old_time"),
                new_time: clock_time(observation, "new_time"),
            },
        ));
    }
    changes.sort_by_key(|(changed_time, _)| *changed_time);
    // The System and Security logs both record one change, so it is one line for each pair of old and
    // new times; the earliest record of it is kept.
    let mut seen = BTreeSet::new();
    changes.retain(|(_, line)| seen.insert((line.old_time.clone(), line.new_time.clone())));
    ClockTrust {
        changes: changes.into_iter().map(|(_, line)| line).collect(),
        history: clock_history(report, span_start),
    }
}

/// A clock time an `event_fields` record holds, read and shown as `installed_at` is: parsed, then
/// rendered again; `None` when it does not parse (ADR 0081 section 3).
fn clock_time(observation: &Observation, field: &str) -> Option<String> {
    time_of(observation, field)
        .and_then(parse_time)
        .map(|time| time.to_string())
}

/// Whether the System log's history reaches back to `span_start`: the System place was read, not
/// gapped, holds no rejected record, and the System log's oldest record is at or before the span's
/// start (ADR 0081 section 3).
fn clock_history(report: &Report, span_start: i64) -> ClockHistory {
    let system_read = observations_of(report, "event_fields")
        .into_iter()
        .any(|observation| {
            session::text(observation, "log") == Some("system")
                && session::text(observation, "read") == Some("read")
                // A rejected record may hold a clock change the records read do not show.
                && observation
                    .fields
                    .get("rejected")
                    .is_none_or(|rejected| rejected.as_u64() == Some(0))
        });
    // A gap on the whole `event_fields` run, or on its System place, means the place was not read.
    let gapped = report.unmeasured_sources.iter().any(|source| {
        source.collector == "event_fields"
            && matches!(source.place.as_deref(), None | Some("system"))
    });
    let oldest_reaches_span = trace_ages(report, Mode::SelfCheck).rows.iter().any(|row| {
        let oldest = match &row.state {
            TraceAgeState::Measured {
                oldest: Some(text), ..
            } => parse_time(text),
            _ => None,
        };
        row.collector == "evtx"
            && row
                .subject
                .as_deref()
                .is_some_and(|subject| subject.eq_ignore_ascii_case("System.evtx"))
            && oldest.is_some_and(|oldest| oldest.as_second() <= span_start)
    });
    if system_read && !gapped && oldest_reaches_span {
        ClockHistory::Known
    } else {
        ClockHistory::NotKnown
    }
}

/// The `event_fields` records the view joins to candidates: System-log installs and code-integrity
/// refusals (ADR 0081 section 4). Installs never become candidates.
struct EventRecords {
    /// Each System-log install with a time: the path digest it carried, when it carried one, and
    /// the time.
    installs: Vec<(Option<String>, jiff::Timestamp)>,
    /// The volume path digests of the images the code-integrity log refused.
    refused: BTreeSet<String>,
}
impl EventRecords {
    /// Every install and refused image the report's `event_fields` observations hold.
    fn of(report: &Report) -> Self {
        let mut installs = Vec::new();
        let mut refused = BTreeSet::new();
        for observation in observations_of(report, "event_fields") {
            match session::text(observation, "log") {
                Some("system") => {
                    if let Some(time) = time_of(observation, "installed_at").and_then(parse_time) {
                        let digest = session::text(observation, "path_digest").map(str::to_owned);
                        installs.push((digest, time));
                    }
                }
                Some("code_integrity") => {
                    if let Some(digest) = session::text(observation, "volume_path_digest") {
                        refused.insert(digest.to_owned());
                    }
                }
                _ => {}
            }
        }
        Self { installs, refused }
    }
    /// The install times whose path digest is `candidate`'s, as text, in time order.
    fn installed_at(&self, candidate: &Candidate) -> Vec<String> {
        let Some(digest) = candidate.path.as_deref().and_then(path_digest) else {
            return Vec::new();
        };
        let mut times: Vec<jiff::Timestamp> = self
            .installs
            .iter()
            .filter(|(install, _)| install.as_deref() == Some(digest.as_str()))
            .map(|(_, time)| *time)
            .collect();
        times.sort_unstable();
        times.dedup();
        times.into_iter().map(|time| time.to_string()).collect()
    }
    /// Whether the code-integrity log refused `candidate`'s image, by its volume path digest.
    fn refuses(&self, candidate: &Candidate) -> bool {
        candidate
            .path
            .as_deref()
            .and_then(volume_path_digest)
            .is_some_and(|digest| self.refused.contains(&digest))
    }
}

/// How many installs match no candidate's path digest, by the window their time falls in
/// (ADR 0081 section 4). An install without a digest matches nothing.
fn unmatched_installs_of(
    candidates: &[Candidate],
    events: &EventRecords,
    sessions: &[TimedSession],
    scan: Option<jiff::Timestamp>,
) -> InstallCounts {
    let known: BTreeSet<String> = candidates
        .iter()
        .filter_map(|candidate| candidate.path.as_deref().and_then(path_digest))
        .collect();
    let mut counts = InstallCounts::default();
    for (digest, time) in &events.installs {
        if digest.as_ref().is_some_and(|digest| known.contains(digest)) {
            continue;
        }
        let mut hit = Hits::default();
        for session in sessions {
            let hits = hits(session, *time, scan);
            hit.before |= hits.before;
            hit.during |= hits.during;
            hit.after |= hits.after;
        }
        counts.before += usize::from(hit.before);
        counts.during += usize::from(hit.during);
        counts.after += usize::from(hit.after);
    }
    counts
}
/// A session with the times its windows are measured from.
struct TimedSession {
    edition: String,
    start: jiff::Timestamp,
    end: Option<jiff::Timestamp>,
    latest: bool,
}
/// A record's observation before it is joined with the others for the same program.
struct Candidate {
    name: String,
    path: Option<String>,
    times: Vec<jiff::Timestamp>,
    /// The collectors that recorded one of its times.
    sources: BTreeSet<&'static str>,
    /// The L1 fact of each Prefetch record it was made from or joined (ADR 0082 section 5).
    l1: Vec<IdentityFact>,
}
/// Why a candidate has no `recorded_files` observation of its path to join (ADR 0079 section 3).
#[derive(Clone, Copy)]
enum Unjoined {
    /// The candidate has no program path, as a Prefetch-only candidate does.
    NoPath,
    /// `recorded_files` did not run, as on a standard scan.
    NotRun,
    /// `recorded_files` ran and holds no observation for the path.
    NoObservation,
}
/// The `recorded_files` observations by path, ignoring ASCII case (ADR 0079 amendment 7).
struct RecordedFiles<'r> {
    by_path: BTreeMap<String, &'r Observation>,
    /// Whether `recorded_files` ran at all: a standard scan does not run it.
    ran: bool,
}
impl<'r> RecordedFiles<'r> {
    /// Every `recorded_files` observation the report holds, joined by its path.
    fn of(report: &'r Report) -> Self {
        let mut by_path = BTreeMap::new();
        let mut ran = false;
        for observation in observations_of(report, "recorded_files") {
            ran = true;
            if let Some(path) = session::text(observation, "path") {
                by_path
                    .entry(path.to_ascii_lowercase())
                    .or_insert(observation);
            }
        }
        Self { by_path, ran }
    }
    /// The observation of `candidate`'s path, when the collector holds one.
    fn joined(&self, candidate: &Candidate) -> Option<&'r Observation> {
        candidate
            .path
            .as_deref()
            .and_then(|path| self.by_path.get(&path.to_ascii_lowercase()).copied())
    }
    /// I1 to I5 for `candidate`; I5 is measured in `sessions`' latest windows and at `scan`
    /// (ADR 0086 section 5).
    fn facts(
        &self,
        candidate: &Candidate,
        sessions: &[TimedSession],
        scan: Option<jiff::Timestamp>,
    ) -> [IdentityFact; 5] {
        let observation = self.joined(candidate);
        let (i1, i2) = self.time_and_signature_facts(candidate);
        [
            i1,
            i2,
            name_fact(candidate, observation),
            location_fact(candidate),
            self.journal_fact(candidate, sessions, scan),
        ]
    }

    /// Why `candidate` has no observation of its path to join: no path, no run, or no observation.
    fn unjoined(&self, candidate: &Candidate) -> Unjoined {
        if candidate.path.is_none() {
            Unjoined::NoPath
        } else if self.ran {
            Unjoined::NoObservation
        } else {
            Unjoined::NotRun
        }
    }

    /// The reason I1 and I2 give when `candidate` has no observation of its path to join.
    fn unjoined_reason(&self, candidate: &Candidate) -> IdentityNotKnownReason {
        match self.unjoined(candidate) {
            Unjoined::NoPath => IdentityNotKnownReason::NoPath,
            Unjoined::NotRun => IdentityNotKnownReason::RecordedFilesNotRun,
            Unjoined::NoObservation => IdentityNotKnownReason::NoObservationForPath,
        }
    }

    /// I5 for `candidate` (ADR 0086 section 5): true when the journal holds a deletion or a rename
    /// of its file at a time in a window of a latest session. Otherwise it says what the journal
    /// can show of those windows, as `fact` decides them.
    fn journal_fact(
        &self,
        candidate: &Candidate,
        sessions: &[TimedSession],
        scan: Option<jiff::Timestamp>,
    ) -> IdentityFact {
        let Some(observation) = self.joined(candidate) else {
            return not_known(self.unjoined_reason(candidate));
        };
        match session::text(observation, "journal_match") {
            Some("matched") => {}
            Some("other_volume") => {
                return not_known(IdentityNotKnownReason::JournalOtherDrive);
            }
            Some("folder_unknown") => {
                return not_known(IdentityNotKnownReason::JournalFolderUnknown);
            }
            _ => return not_known(IdentityNotKnownReason::JournalNotRead),
        }
        // A read that was not whole has no deletion list, so it cannot say what was deleted.
        let Some(deleted) = times_list(observation, "journal_deleted") else {
            return not_known(IdentityNotKnownReason::JournalNotRead);
        };
        let renamed = ["journal_renamed_from", "journal_renamed_to"]
            .into_iter()
            .filter_map(|field| times_list(observation, field))
            .flatten();
        let times: Vec<jiff::Timestamp> = deleted.into_iter().chain(renamed).collect();
        let latest: Vec<&TimedSession> = sessions.iter().filter(|session| session.latest).collect();
        if latest
            .iter()
            .any(|session| times.iter().any(|time| hits(session, *time, scan).any()))
        {
            return IdentityFact::True;
        }
        // The journal must reach back to the earliest before window; one that starts later cannot
        // show it (ADR 0086 section 5). No latest session leaves no window to reach, so it is not
        // shown as false. This is the first reason after "no time in a window" in the table's order.
        let earliest = latest
            .iter()
            .map(|session| session.start.as_second().saturating_sub(WINDOW_SECONDS))
            .min();
        let reaches_back = earliest
            .zip(journal_reaches_from(observation))
            .is_some_and(|(earliest, from)| from.as_second() <= earliest);
        if !reaches_back {
            return not_known(IdentityNotKnownReason::BeforeTraceAge {
                source: "usn".to_owned(),
            });
        }
        // Without a recorded end the during, after and before-the-scan windows are not known; the
        // before window is, and is judged above.
        if latest.iter().any(|session| session.end.is_none()) {
            return not_known(IdentityNotKnownReason::SessionEndNotRecorded);
        }
        if scan.is_none() {
            return not_known(IdentityNotKnownReason::ScanTimeNotRecorded);
        }
        IdentityFact::False
    }

    /// What `recorded_files` read of `candidate`'s path, from the same join as I1 and I2, or why it
    /// read nothing (ADR 0079 section 3).
    fn details(&self, candidate: &Candidate) -> FileDetails {
        let Some(observation) = self.joined(candidate) else {
            let read = match self.unjoined(candidate) {
                Unjoined::NoPath => FileRead::NoPath,
                Unjoined::NotRun => FileRead::NotRun,
                Unjoined::NoObservation => FileRead::NoObservation,
            };
            return unread(read);
        };
        FileDetails {
            read: file_read_of(observation),
            sha256: text_of(observation, "sha256"),
            signature: text_of(observation, "signature"),
            signer: text_of(observation, "signer"),
            signer_cert_sha256: text_of(observation, "signer_cert_sha256"),
            content_kind: text_of(observation, "content_kind"),
            original_filename: text_of(observation, "original_filename"),
            download_host: text_of(observation, "download_host"),
            trailing_data: flag_of(observation, "trailing_data"),
            embedded_pe: flag_of(observation, "embedded_pe"),
            zone_id: zone_id_of(observation),
            journal_deleted: text_list_of(observation, "journal_deleted"),
            journal_renamed_from: text_list_of(observation, "journal_renamed_from"),
            journal_renamed_to: text_list_of(observation, "journal_renamed_to"),
            journal_more: flag_of(observation, "journal_more"),
        }
    }

    /// I1 and I2 for `candidate`, from the `recorded_files` observation of its path.
    fn time_and_signature_facts(&self, candidate: &Candidate) -> (IdentityFact, IdentityFact) {
        let Some(observation) = self.joined(candidate) else {
            let fact = not_known(self.unjoined_reason(candidate));
            return (fact.clone(), fact);
        };
        match session::text(observation, "identity_read") {
            // A missing file is gone (I1), but the file was not read, so I2 is not known.
            Some("missing") => (
                IdentityFact::True,
                IdentityFact::NotKnown {
                    reason: IdentityNotKnownReason::NotRead,
                },
            ),
            // A file too large to read still exists, and its signature field is what was read.
            Some("read" | "too_large") => (IdentityFact::False, signature_fact(observation)),
            _ => {
                let fact = IdentityFact::NotKnown {
                    reason: IdentityNotKnownReason::NotRead,
                };
                (fact.clone(), fact)
            }
        }
    }
}

/// What `observation`'s `identity_read` says the read of its file was. An absent or unrecognised
/// word is a read that did not finish (ADR 0079 section 3).
fn file_read_of(observation: &Observation) -> FileRead {
    match session::text(observation, "identity_read") {
        Some("read") => FileRead::Read,
        Some("missing") => FileRead::Missing,
        Some("too_large") => FileRead::TooLarge,
        Some("access_denied") => FileRead::AccessDenied,
        Some("refused_form") => FileRead::RefusedForm,
        Some("budget_spent") => FileRead::BudgetSpent,
        _ => FileRead::Failed,
    }
}
/// The details of a file that was not read: the read, and no field.
fn unread(read: FileRead) -> FileDetails {
    FileDetails {
        read,
        sha256: None,
        signature: None,
        signer: None,
        signer_cert_sha256: None,
        content_kind: None,
        original_filename: None,
        download_host: None,
        trailing_data: None,
        embedded_pe: None,
        zone_id: None,
        journal_deleted: None,
        journal_renamed_from: None,
        journal_renamed_to: None,
        journal_more: None,
    }
}
/// `field` of `observation` as text, when it is present and a string.
fn text_of(observation: &Observation, field: &str) -> Option<String> {
    session::text(observation, field).map(str::to_owned)
}
/// The strings `field` of `observation` lists, in the order it holds them, when it is a list.
fn text_list_of(observation: &Observation, field: &str) -> Option<Vec<String>> {
    observation
        .fields
        .get(field)
        .and_then(serde_json::Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::to_owned)
                .collect()
        })
}
/// The times `field` of `observation` lists, in the order it holds them, when it is a list. An
/// entry that is not a time is skipped.
fn times_list(observation: &Observation, field: &str) -> Option<Vec<jiff::Timestamp>> {
    observation
        .fields
        .get(field)
        .and_then(serde_json::Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(serde_json::Value::as_str)
                .filter_map(parse_time)
                .collect()
        })
}
/// `field` of `observation` as a flag, when it is present and a boolean.
fn flag_of(observation: &Observation, field: &str) -> Option<bool> {
    observation
        .fields
        .get(field)
        .and_then(serde_json::Value::as_bool)
}
/// How many times a journal list holds when it was cut: the newest eight per kind, the bound
/// `recorded_files` applies (`JOURNAL_TIMES_CAP` there; ADR 0086 section 3, D5).
const JOURNAL_TIMES_CAP: usize = 8;

/// The time the journal's lists reach back to (ADR 0086 section 5): `journal_from`, or, when
/// `journal_more` says a list was cut, the later of that and the oldest time a cut list kept. A cut
/// list hides every older time, so the journal cannot show before that kept time.
fn journal_reaches_from(observation: &Observation) -> Option<jiff::Timestamp> {
    let from = session::text(observation, "journal_from").and_then(parse_time);
    if flag_of(observation, "journal_more") != Some(true) {
        return from;
    }
    let oldest_kept = ["journal_deleted", "journal_renamed_from", "journal_renamed_to"]
        .into_iter()
        .filter_map(|field| times_list(observation, field))
        .filter(|times| times.len() == JOURNAL_TIMES_CAP)
        .filter_map(|times| times.into_iter().min())
        .max();
    from.map(|from| oldest_kept.map_or(from, |kept| from.max(kept)))
}
/// The zone identifier `observation` holds, when it is a number that fits a `u32`.
fn zone_id_of(observation: &Observation) -> Option<u32> {
    observation
        .fields
        .get("zone_id")
        .and_then(serde_json::Value::as_u64)
        .and_then(|zone| u32::try_from(zone).ok())
}
/// I2: false for a valid signature, true for an invalid or missing one, not known otherwise.
fn signature_fact(observation: &Observation) -> IdentityFact {
    match session::text(observation, "signature") {
        Some("valid") => IdentityFact::False,
        Some("invalid" | "no_embedded_signature") => IdentityFact::True,
        Some("unverifiable_offline") => IdentityFact::NotKnown {
            reason: IdentityNotKnownReason::Unverifiable,
        },
        // An absent or unrecognised field established no signature.
        _ => IdentityFact::NotKnown {
            reason: IdentityNotKnownReason::NotRead,
        },
    }
}

/// A fact whose fields the scan did not read.
fn deferred() -> IdentityFact {
    not_known(IdentityNotKnownReason::Deferred)
}
/// An identity fact that is not known for `reason`.
fn not_known(reason: IdentityNotKnownReason) -> IdentityFact {
    IdentityFact::NotKnown { reason }
}
/// L1 when no record counts the files it loaded from outside (ADR 0082 section 5). It is also what
/// a view saved before L1 existed reads as.
fn not_counted() -> IdentityFact {
    IdentityFact::NotKnown {
        reason: IdentityNotKnownReason::NotCounted,
    }
}
/// The files a Prefetch record loaded from outside, when its count is present and not marked
/// unknown (ADR 0082 section 5).
fn loaded_outside_of(observation: &Observation) -> Option<u64> {
    if observation.fields.contains_key("loaded_outside_unknown") {
        return None;
    }
    observation
        .fields
        .get("loaded_outside")
        .and_then(serde_json::Value::as_u64)
}
/// L1 of one Prefetch record: true when it loaded a file from outside, false when it loaded none,
/// else not counted (ADR 0082 section 5).
fn l1_of(observation: &Observation) -> IdentityFact {
    match loaded_outside_of(observation) {
        Some(0) => IdentityFact::False,
        Some(_) => IdentityFact::True,
        None => not_counted(),
    }
}
/// Combines the L1 facts of the records one candidate or session was made from: true if any is
/// true, false if all are false and there is one, else not counted (ADR 0082 section 5).
fn combined_l1(facts: &[IdentityFact]) -> IdentityFact {
    if facts.contains(&IdentityFact::True) {
        IdentityFact::True
    } else if !facts.is_empty() && facts.iter().all(|fact| *fact == IdentityFact::False) {
        IdentityFact::False
    } else {
        not_counted()
    }
}
/// Document, media and archive extensions a file can wear before a program's, for I3's double
/// extension (ADR 0078 section 5).
const DISGUISE_EXTENSIONS: [&str; 24] = [
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "jpg", "jpeg", "png", "gif",
    "bmp", "webp", "mp3", "mp4", "avi", "mkv", "mov", "wav", "zip", "rar", "7z",
];

/// Extensions of a program recorded running (ADR 0078 section 5).
const PROGRAM_EXTENSIONS: [&str; 4] = ["exe", "com", "scr", "cpl"];

/// Windows file names that belong under `%SystemRoot%` (ADR 0078 section 5).
const SYSTEM_NAMES: [&str; 13] = [
    "svchost",
    "lsass",
    "csrss",
    "winlogon",
    "services",
    "smss",
    "wininit",
    "spoolsv",
    "dllhost",
    "conhost",
    "taskhostw",
    "ctfmon",
    "rundll32",
];
/// I3: the recorded name contradicts what the file is or did (ADR 0078 section 5).
fn name_fact(candidate: &Candidate, observation: Option<&Observation>) -> IdentityFact {
    if name_contradicts(candidate, observation) {
        return IdentityFact::True;
    }
    // The name shapes are all false. Only a read that says what the content is can make I3 false.
    if observation.is_some_and(|observation| session::text(observation, "content_kind").is_some()) {
        IdentityFact::False
    } else {
        deferred()
    }
}

/// Whether any of I3's name, content or version-resource shapes holds (ADR 0078 section 5).
fn name_contradicts(candidate: &Candidate, observation: Option<&Observation>) -> bool {
    let recorded = candidate.name.as_str();
    if has_extension_other_than(recorded, &PROGRAM_EXTENSIONS)
        || has_double_executable_extension(recorded)
        || has_bidi_control(recorded)
        || has_mixed_scripts(recorded)
    {
        return true;
    }
    let Some(observation) = observation else {
        return false;
    };
    let file = candidate.path.as_deref().map_or(recorded, file_name);
    content_contradicts_extension(observation, file)
        || original_filename_contradicts(observation, file)
        || is_system_name_outside_root(recorded, observation)
}

/// Whether the read of `observation` says `file` is a PE image under another kind of name.
fn content_contradicts_extension(observation: &Observation, file: &str) -> bool {
    let Some(kind) = session::text(observation, "content_kind") else {
        return false;
    };
    matches!(kind, "pe_executable" | "pe_dll" | "pe_driver") && !has_extension(file, &PE_EXTENSIONS)
}
/// Whether the version resource's `OriginalFilename` differs from the file's own name, in ASCII case.
fn original_filename_contradicts(observation: &Observation, file: &str) -> bool {
    session::text(observation, "original_filename")
        .is_some_and(|original| !original.eq_ignore_ascii_case(file))
}
/// Whether `name` ends in one of `allowed`, in ASCII case.
fn has_extension(name: &str, allowed: &[&str]) -> bool {
    extension(name).is_some_and(|extension| {
        allowed
            .iter()
            .any(|allowed| extension.eq_ignore_ascii_case(allowed))
    })
}

/// Whether `name` has an extension and it is not one of `allowed`; no extension is not a
/// contradiction by itself (ADR 0078 section 5).
fn has_extension_other_than(name: &str, allowed: &[&str]) -> bool {
    extension(name).is_some_and(|extension| {
        !allowed
            .iter()
            .any(|allowed| extension.eq_ignore_ascii_case(allowed))
    })
}

/// The extension of `name`: what follows its last dot, when it is 1 to 4 ASCII alphanumerics.
fn extension(name: &str) -> Option<&str> {
    name.rsplit_once('.')
        .map(|(_, extension)| extension)
        .filter(|extension| {
            (1..=4).contains(&extension.len())
                && extension
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric())
        })
}

/// Whether `name` has a double extension that ends in a program's (ADR 0078 section 5).
fn has_double_executable_extension(name: &str) -> bool {
    let Some(extension) = extension(name) else {
        return false;
    };
    if !PROGRAM_EXTENSIONS
        .iter()
        .any(|program| extension.eq_ignore_ascii_case(program))
    {
        return false;
    }
    name.rsplit_once('.')
        .and_then(|(stem, _)| stem.rsplit_once('.'))
        .is_some_and(|(_, earlier)| {
            DISGUISE_EXTENSIONS
                .iter()
                .any(|disguise| earlier.eq_ignore_ascii_case(disguise))
        })
}

/// Whether `name` carries a right-to-left override or another bidi control (ADR 0078 section 5).
fn has_bidi_control(name: &str) -> bool {
    name.chars()
        .any(|character| matches!(character, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'))
}
/// Whether `name` has letters from more than one of Latin, Cyrillic and Greek (ADR 0078 section 5).
fn has_mixed_scripts(name: &str) -> bool {
    let mut seen = [false; 3];
    for character in name.chars() {
        if let Some(script) = script_of(character) {
            seen[script as usize] = true;
        }
    }
    seen.into_iter().filter(|seen| *seen).count() > 1
}
/// The script of `character`, for the three scripts a disguised name mixes.
#[derive(Clone, Copy)]
enum Script {
    Latin,
    Cyrillic,
    Greek,
}
/// The script a letter belongs to, or `None` for anything else.
fn script_of(character: char) -> Option<Script> {
    match character {
        '\u{0041}'..='\u{005A}'
        | '\u{0061}'..='\u{007A}'
        | '\u{00C0}'..='\u{024F}'
        | '\u{1E00}'..='\u{1EFF}'
        | '\u{2C60}'..='\u{2C7F}'
        | '\u{A720}'..='\u{A7FF}'
        | '\u{AB30}'..='\u{AB6F}'
        | '\u{FF21}'..='\u{FF3A}'
        | '\u{FF41}'..='\u{FF5A}' => Some(Script::Latin),
        '\u{0400}'..='\u{052F}'
        | '\u{1C80}'..='\u{1C8F}'
        | '\u{2DE0}'..='\u{2DFF}'
        | '\u{A640}'..='\u{A69F}' => Some(Script::Cyrillic),
        '\u{0370}'..='\u{03FF}' | '\u{1F00}'..='\u{1FFF}' => Some(Script::Greek),
        _ => None,
    }
}
/// Whether `name` is a Windows file name kept outside `%SystemRoot%` (ADR 0078 section 5).
fn is_system_name_outside_root(name: &str, observation: &Observation) -> bool {
    let lower = name.to_ascii_lowercase();
    let Some(stem) = lower.strip_suffix(".exe") else {
        return false;
    };
    SYSTEM_NAMES.contains(&stem)
        && observation
            .fields
            .get("under_system_root")
            .and_then(serde_json::Value::as_bool)
            == Some(false)
}
/// I4: the path is under a Temp or Downloads folder; other writable folders arrive with later work
/// (ADR 0078 section 5).
fn location_fact(candidate: &Candidate) -> IdentityFact {
    let Some(path) = candidate.path.as_deref() else {
        return IdentityFact::NotKnown {
            reason: IdentityNotKnownReason::NoPath,
        };
    };
    if path_under_temp_or_downloads(path) {
        return IdentityFact::True;
    }
    deferred()
}

/// Whether a folder of `path`, other than the file itself, is `Temp` or `Downloads`.
fn path_under_temp_or_downloads(path: &str) -> bool {
    let mut folders = path.split(['\\', '/']).peekable();
    while let Some(folder) = folders.next() {
        if folders.peek().is_some()
            && (folder.eq_ignore_ascii_case("temp") || folder.eq_ignore_ascii_case("downloads"))
        {
            return true;
        }
    }
    false
}
/// Whether `candidate` has a true identity fact among I1 to I5 or L1, which SS mode lists it for
/// (ADR 0078 section 9, as amended by ADR 0082 section 5 and ADR 0086 decision 6).
fn has_identity_fact(candidate: &GameCandidate) -> bool {
    [
        &candidate.i1,
        &candidate.i2,
        &candidate.i3,
        &candidate.i4,
        &candidate.i5,
        &candidate.l1,
    ]
    .into_iter()
    .any(|fact| *fact == IdentityFact::True)
}
/// Each session's L1 and loaded-outside count, in `sessions`' order (ADR 0082 section 5). A
/// Prefetch record with a `fivem_edition` feeds the latest session of that edition when one of its
/// run times is in the session's span; an earlier session's end is never known, so no record is
/// placed in it.
fn session_loads(report: &Report, sessions: &[TimedSession]) -> Vec<(IdentityFact, Option<u64>)> {
    let tagged: Vec<&Observation> = observations_of(report, "prefetch")
        .into_iter()
        .filter(|observation| session::text(observation, "fivem_edition").is_some())
        .collect();
    sessions
        .iter()
        .map(|session| {
            if !session.latest {
                let reason = IdentityNotKnownReason::EarlierSession;
                return (IdentityFact::NotKnown { reason }, None);
            }
            let fed: Vec<&Observation> = tagged
                .iter()
                .copied()
                .filter(|observation| {
                    session::text(observation, "fivem_edition") == Some(session.edition.as_str())
                        && run_times(observation)
                            .into_iter()
                            .any(|time| within(session, time))
                })
                .collect();
            let facts: Vec<IdentityFact> = fed.iter().copied().map(l1_of).collect();
            let loaded_outside = fed
                .iter()
                .copied()
                .filter_map(loaded_outside_of)
                .reduce(u64::saturating_add);
            (combined_l1(&facts), loaded_outside)
        })
        .collect()
}
/// Whether `time` is in `session`'s span: from its start, and up to its end when it has one
/// (ADR 0082 section 5).
fn within(session: &TimedSession, time: jiff::Timestamp) -> bool {
    let at = time.as_second();
    at >= session.start.as_second() && session.end.is_none_or(|end| at <= end.as_second())
}
fn game_session(
    session: &TimedSession,
    l1: IdentityFact,
    loaded_outside: Option<u64>,
) -> GameSession {
    GameSession {
        edition: session.edition.clone(),
        start: session.start.to_string(),
        end: session.end.map(|end| end.to_string()),
        latest: session.latest,
        l1,
        loaded_outside,
    }
}
/// ADR 0062's latest session of each edition, then that edition's other Prefetch run times as
/// start-only sessions (ADR 0078 section 2).
fn timed_sessions(report: &Report) -> Vec<TimedSession> {
    let mut sessions = Vec::new();
    for edition in session::EDITIONS {
        let Some((start, end)) = session::session_times(report, edition) else {
            continue;
        };
        sessions.push(TimedSession {
            edition: edition.to_owned(),
            start,
            end,
            latest: true,
        });
        let mut earlier: Vec<jiff::Timestamp> = observations_of(report, "prefetch")
            .into_iter()
            .filter(|observation| is_anchor(observation, edition))
            .flat_map(run_times)
            .filter(|time| start.as_second() - time.as_second() > session::MARGIN_SECONDS)
            .collect();
        earlier.sort_unstable();
        earlier.dedup();
        earlier.reverse();
        // Run times within the margin of one another are one session: Prefetch writes the client's
        // and the game process's run seconds apart (ADR 0078 section 2).
        let mut kept: Vec<jiff::Timestamp> = Vec::new();
        for time in earlier {
            if kept
                .last()
                .is_some_and(|last| last.as_second() - time.as_second() <= session::MARGIN_SECONDS)
            {
                continue;
            }
            kept.push(time);
        }
        for start in kept {
            sessions.push(TimedSession {
                edition: edition.to_owned(),
                start,
                end: None,
                latest: false,
            });
        }
    }
    sessions
}
/// Whether Prefetch's record is one of `edition`'s anchor names.
fn is_anchor(observation: &Observation, edition: &str) -> bool {
    session::text(observation, "fivem_edition") == Some(edition)
        && session::text(observation, "name")
            .is_some_and(|name| session::anchor_name(name, edition).is_some())
}
#[derive(Debug, Clone, Copy, Default)]
#[allow(clippy::struct_excessive_bools)]
struct Hits {
    before: bool,
    during: bool,
    after: bool,
    before_scan: bool,
}
impl Hits {
    /// Whether any window holds the time.
    fn any(self) -> bool {
        self.before || self.during || self.after || self.before_scan
    }
}
/// The windows of `session` that hold `time`.
fn hits(session: &TimedSession, time: jiff::Timestamp, scan: Option<jiff::Timestamp>) -> Hits {
    let at = time.as_second();
    let start = session.start.as_second();
    let mut hits = Hits {
        before: at >= start.saturating_sub(WINDOW_SECONDS) && at < start,
        ..Hits::default()
    };
    if session.latest
        && let Some(end) = session.end
    {
        let end = end.as_second();
        hits.during = at >= start && at <= end;
        hits.after = at > end && at <= end.saturating_add(WINDOW_SECONDS);
        // The before-the-scan window is the latest end up to the scan, so it overlaps the after
        // window: a time in both makes T3 and T4 true (ADR 0078 section 3).
        hits.before_scan = scan.is_some_and(|scan| at > end && at <= scan.as_second());
    }
    hits
}
/// Every window of every session that holds one of `candidate`'s times.
fn hits_of(
    candidate: &Candidate,
    sessions: &[TimedSession],
    scan: Option<jiff::Timestamp>,
) -> Hits {
    let mut total = Hits::default();
    for session in sessions {
        for time in &candidate.times {
            let hit = hits(session, *time, scan);
            total.before |= hit.before;
            total.during |= hit.during;
            total.after |= hit.after;
            total.before_scan |= hit.before_scan;
        }
    }
    total
}
/// The collectors `gather` reads, in the order it reads them. A candidate lists the collectors that
/// recorded one of its times in this order, not alphabetically (ADR 0078 section 4).
const GATHER_ORDER: [&str; 5] = ["prefetch", "bam", "pca", "process", "userassist"];

/// The collectors that recorded one of `candidate`'s times, each once, in `GATHER_ORDER`.
fn recorded_by_of(candidate: &Candidate) -> Vec<String> {
    GATHER_ORDER
        .into_iter()
        .filter(|collector| candidate.sources.contains(collector))
        .map(str::to_owned)
        .collect()
}

/// The candidates of every record with a time in a known window (ADR 0078 section 4). No name keeps a
/// record out: a `FiveM.exe`, `GTA5.exe`, `GTA5_Enhanced.exe`, `PlayGTAV.exe` or
/// `FiveM_b…_GTAProcess.exe` record is a candidate like any other (ADR 0084 decision 3). Sessions are
/// still found from the same records by `session::session_times` (ADR 0062).
fn gather(
    report: &Report,
    sessions: &[TimedSession],
    scan: Option<jiff::Timestamp>,
) -> Vec<Candidate> {
    let mut paths: BTreeMap<String, Candidate> = BTreeMap::new();
    let mut standalone: Vec<Candidate> = Vec::new();
    let mut prefetch: Vec<Candidate> = Vec::new();
    for collector in GATHER_ORDER {
        for observation in observations_of(report, collector) {
            let Some(name) = session::text(observation, "name") else {
                continue;
            };
            let times = times_of(collector, observation);
            if times.is_empty() {
                continue;
            }
            // Prefetch's `path` is the `.pf` file, not the program it recorded: the record is
            // path-less for joining and display (ADR 0078 section 4).
            let path = if collector == "prefetch" {
                None
            } else {
                session::text(observation, "path").map(str::to_owned)
            };
            let candidate = Candidate {
                name: name.to_owned(),
                path,
                times,
                sources: BTreeSet::from([collector]),
                l1: if collector == "prefetch" {
                    vec![l1_of(observation)]
                } else {
                    Vec::new()
                },
            };
            if collector == "prefetch" {
                prefetch.push(candidate);
            } else if let Some(path) = candidate.path.as_deref() {
                let key = path.to_ascii_lowercase();
                merge(&mut paths, key, candidate);
            } else {
                // A record without a program path has nothing to join on, so it is a candidate of
                // its own rather than one merged by name (ADR 0078 section 4).
                standalone.push(candidate);
            }
        }
    }
    for record in prefetch {
        let mut matching = paths
            .iter()
            .filter(|(_, candidate)| {
                candidate
                    .path
                    .as_deref()
                    .is_some_and(|path| file_name(path).eq_ignore_ascii_case(&record.name))
            })
            .map(|(key, _)| key.clone());
        // A Prefetch record joins the one path candidate whose file name is its own; with none or
        // several it stays a candidate of its own, as another Prefetch record of the same name is
        // a different file (ADR 0078 section 4).
        match (matching.next(), matching.next()) {
            (Some(key), None) => {
                if let Some(candidate) = paths.get_mut(&key) {
                    candidate.times.extend(record.times);
                    candidate.sources.extend(record.sources);
                    candidate.l1.extend(record.l1);
                }
            }
            _ => standalone.push(record),
        }
    }
    paths
        .into_values()
        .chain(standalone)
        .filter(|candidate| hits_of(candidate, sessions, scan).any())
        .collect()
}
fn merge(map: &mut BTreeMap<String, Candidate>, key: String, candidate: Candidate) {
    let times = candidate.times.clone();
    let sources = candidate.sources.clone();
    map.entry(key)
        .and_modify(|held| {
            held.times.extend(times);
            held.sources.extend(sources);
        })
        .or_insert(candidate);
}
fn file_name(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}
/// Every time `collector`'s record holds for one program.
fn times_of(collector: &str, observation: &Observation) -> Vec<jiff::Timestamp> {
    if collector == "prefetch" {
        return run_times(observation);
    }
    let field = if collector == "process" {
        "started_at"
    } else {
        "last_run"
    };
    time_of(observation, field)
        .and_then(parse_time)
        .into_iter()
        .collect()
}
/// A Prefetch record's run times, newest first as the report holds them.
fn run_times(observation: &Observation) -> Vec<jiff::Timestamp> {
    observation
        .fields
        .get("run_times")
        .and_then(serde_json::Value::as_array)
        .map_or_else(Vec::new, |times| {
            times
                .iter()
                .filter_map(serde_json::Value::as_str)
                .filter_map(parse_time)
                .collect()
        })
}
fn parse_time(text: &str) -> Option<jiff::Timestamp> {
    let time = text.parse::<jiff::Timestamp>().ok()?;
    jiff::Timestamp::from_second(time.as_second()).ok()
}
/// The four kinds of window a time fact is about (ADR 0078 section 3).
#[derive(Debug, Clone, Copy)]
enum WindowKind {
    Before,
    During,
    After,
    BeforeScan,
}
/// One candidate's T1 to T4, R and I1 to I5, from the windows known and the identity the
/// `recorded_files` observation of its path carries.
fn with_facts(
    candidate: &Candidate,
    sessions: &[TimedSession],
    scan: Option<jiff::Timestamp>,
    oldest: &BTreeMap<&'static str, Option<jiff::Timestamp>>,
    found: usize,
    files: &RecordedFiles<'_>,
) -> GameCandidate {
    let near = sessions
        .iter()
        .filter(|session| {
            candidate
                .times
                .iter()
                .any(|time| hits(session, *time, scan).any())
        })
        .count();
    let [i1, i2, i3, i4, i5] = files.facts(candidate, sessions, scan);
    GameCandidate {
        name: candidate.name.clone(),
        path: candidate.path.clone(),
        t1: fact(WindowKind::Before, candidate, sessions, scan, oldest),
        t2: fact(WindowKind::During, candidate, sessions, scan, oldest),
        t3: fact(WindowKind::After, candidate, sessions, scan, oldest),
        t4: fact(WindowKind::BeforeScan, candidate, sessions, scan, oldest),
        i1,
        i2,
        i3,
        i4,
        i5,
        l1: combined_l1(&candidate.l1),
        near_sessions: NearSessions { near, found },
        installed_at: Vec::new(),
        refused_by_code_integrity: false,
        recorded_by: recorded_by_of(candidate),
        file: Some(files.details(candidate)),
    }
}
/// Whether `kind`'s windows hold one of the candidate's times; else not known when a window or the
/// source covering it is not known; else false (ADR 0078 sections 4 and 5).
fn fact(
    kind: WindowKind,
    candidate: &Candidate,
    sessions: &[TimedSession],
    scan: Option<jiff::Timestamp>,
    oldest: &BTreeMap<&'static str, Option<jiff::Timestamp>>,
) -> TimeFact {
    let mut unknown = None;
    let mut windows: Vec<i64> = Vec::new();
    for session in sessions {
        let start = session.start.as_second();
        match kind {
            WindowKind::Before => {
                let from = start.saturating_sub(WINDOW_SECONDS);
                if candidate
                    .times
                    .iter()
                    .any(|time| time.as_second() >= from && time.as_second() < start)
                {
                    return TimeFact::True;
                }
                windows.push(from);
            }
            WindowKind::During => {
                let Some(end) = session.end.filter(|_| session.latest) else {
                    unknown.get_or_insert(NotKnownReason::SessionEndNotRecorded);
                    continue;
                };
                let end = end.as_second();
                if candidate
                    .times
                    .iter()
                    .any(|time| time.as_second() >= start && time.as_second() <= end)
                {
                    return TimeFact::True;
                }
                windows.push(start);
            }
            WindowKind::After => {
                let Some(end) = session.end.filter(|_| session.latest) else {
                    unknown.get_or_insert(NotKnownReason::SessionEndNotRecorded);
                    continue;
                };
                let end = end.as_second();
                let to = end.saturating_add(WINDOW_SECONDS);
                if candidate
                    .times
                    .iter()
                    .any(|time| time.as_second() > end && time.as_second() <= to)
                {
                    return TimeFact::True;
                }
                windows.push(end);
            }
            WindowKind::BeforeScan => {
                if !session.latest {
                    continue;
                }
                let Some(end) = session.end else {
                    unknown.get_or_insert(NotKnownReason::SessionEndNotRecorded);
                    continue;
                };
                let Some(scan) = scan else {
                    unknown.get_or_insert(NotKnownReason::ScanTimeNotRecorded);
                    continue;
                };
                let (from, to) = (end.as_second(), scan.as_second());
                if candidate
                    .times
                    .iter()
                    .any(|time| time.as_second() > from && time.as_second() <= to)
                {
                    return TimeFact::True;
                }
                windows.push(from);
            }
        }
    }
    if let Some(reason) = unknown {
        return TimeFact::NotKnown { reason };
    }
    for from in windows {
        for source in &candidate.sources {
            if !covered(from, source, oldest) {
                return TimeFact::NotKnown {
                    reason: NotKnownReason::BeforeTraceAge {
                        source: (*source).to_owned(),
                    },
                };
            }
        }
    }
    TimeFact::False
}
/// Whether `source` still reaches back to `from` (ADR 0061's trace ages).
fn covered(
    from: i64,
    source: &'static str,
    oldest: &BTreeMap<&'static str, Option<jiff::Timestamp>>,
) -> bool {
    oldest
        .get(source)
        .copied()
        .flatten()
        .is_some_and(|age| from >= age.as_second())
}
/// Each source's oldest time still held, from the report's trace ages (ADR 0061).
fn oldest_by_source(report: &Report) -> BTreeMap<&'static str, Option<jiff::Timestamp>> {
    let mut oldest = BTreeMap::new();
    for row in trace_ages(report, Mode::SelfCheck).rows {
        let source = match row.collector.as_str() {
            "prefetch" => "prefetch",
            "bam" => "bam",
            "pca" => "pca",
            "userassist" => "userassist",
            _ => continue,
        };
        let time = match row.state {
            TraceAgeState::Measured {
                oldest: Some(text), ..
            } => parse_time(&text),
            _ => None,
        };
        oldest.entry(source).or_insert(time);
    }
    oldest
}
/// How many of R (near at least two sessions), I1 to I5 and L1 are true, for the view's ordering
/// (ADR 0078 section 5, as amended by ADR 0082 section 5 and ADR 0086 decision 6).
fn identity_rank(candidate: &GameCandidate) -> usize {
    usize::from(candidate.near_sessions.near >= 2)
        + [
            &candidate.i1,
            &candidate.i2,
            &candidate.i3,
            &candidate.i4,
            &candidate.i5,
            &candidate.l1,
        ]
        .into_iter()
        .filter(|fact| **fact == IdentityFact::True)
        .count()
}
/// How many of T1 to T4 are true, for the view's ordering (ADR 0078 section 5).
fn true_facts(candidate: &GameCandidate) -> usize {
    [&candidate.t1, &candidate.t2, &candidate.t3, &candidate.t4]
        .into_iter()
        .filter(|fact| **fact == TimeFact::True)
        .count()
}
/// How many candidates have a time in each window.
fn counts_of(
    candidates: &[Candidate],
    sessions: &[TimedSession],
    scan: Option<jiff::Timestamp>,
) -> WindowCounts {
    let mut counts = WindowCounts::default();
    for candidate in candidates {
        let hits = hits_of(candidate, sessions, scan);
        counts.before += usize::from(hits.before);
        counts.during += usize::from(hits.during);
        counts.after += usize::from(hits.after);
        counts.before_scan += usize::from(hits.before_scan);
    }
    counts
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::digest::{path_digest, volume_path_digest};
    use crate::model::{
        AgeCount, AgeFields, AgeRows, Observation, UnmatchedGroup, UnmeasuredReason,
        UnmeasuredSource,
    };

    fn at(text: &str) -> jiff::Timestamp {
        text.parse()
            .unwrap_or_else(|error| panic!("{text}: {error}"))
    }

    /// A BAM record of one program and the time it ran.
    fn bam(name: &str, path: &str, last_run: &str) -> Observation {
        Observation {
            collector: "bam".to_owned(),
            fields: BTreeMap::from([
                ("name".to_owned(), serde_json::Value::from(name)),
                ("path".to_owned(), serde_json::Value::from(path)),
                ("last_run".to_owned(), serde_json::Value::from(last_run)),
            ]),
        }
    }

    /// A `UserAssist` entry: a name and, when Explorer recorded one, a time and a path or the reason
    /// the path is withheld (ADR 0080 owner decisions 1 and 3).
    fn userassist(
        name: &str,
        last_run: Option<&str>,
        path: Option<&str>,
        path_withheld: Option<&str>,
    ) -> Observation {
        let mut fields = BTreeMap::from([("name".to_owned(), serde_json::Value::from(name))]);
        if let Some(last_run) = last_run {
            fields.insert("last_run".to_owned(), serde_json::Value::from(last_run));
        }
        if let Some(path) = path {
            fields.insert("path".to_owned(), serde_json::Value::from(path));
        }
        if let Some(path_withheld) = path_withheld {
            fields.insert(
                "path_withheld".to_owned(),
                serde_json::Value::from(path_withheld),
            );
        }
        Observation {
            collector: "userassist".to_owned(),
            fields,
        }
    }

    /// A report holding only unmatched observations, which is how the view reads every record.
    fn report_of(observations: Vec<Observation>) -> Report {
        serde_json::from_value(serde_json::json!({
            "header": {
                "schema_version": 1,
                "provenance": {
                    "official": false,
                    "version": "0.0.0-test",
                    "commit": null,
                    "exe_sha256": null
                },
                "rules_bundle": {
                    "schema_version": 1,
                    "sha256": "0".repeat(64),
                    "rule_count": 0
                },
                "platform": "windows",
                "os_build": null,
                "elevated": false,
                "generated_at": "2026-01-10T12:00:00Z"
            },
            "evidence": [],
            "unmatched": [UnmatchedGroup {
                collector: "test".to_owned(),
                observations,
            }]
        }))
        .unwrap()
    }

    /// One latest Legacy session from 10:00 to 10:30, so 09:50 is in its before window and 10:15
    /// during it.
    fn session() -> TimedSession {
        TimedSession {
            edition: "legacy".to_owned(),
            start: at("2026-01-10T10:00:00Z"),
            end: Some(at("2026-01-10T10:30:00Z")),
            latest: true,
        }
    }

    fn candidate<'a>(candidates: &'a [Candidate], name: &str) -> &'a Candidate {
        candidates
            .iter()
            .find(|candidate| candidate.name.eq_ignore_ascii_case(name))
            .unwrap_or_else(|| {
                panic!(
                    "no candidate {name}: {}",
                    candidates
                        .iter()
                        .map(|candidate| candidate.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            })
    }

    /// v1: a `UserAssist` entry with a path joins a BAM record of the same path in another case; one
    /// without a path stays a candidate of its own; an entry that carries no `last_run` is not a
    /// candidate at all (ADR 0080 sections 3 and 4).
    #[test]
    fn u4_v1_userassist_joins_by_path_and_an_entry_without_a_time_is_no_candidate() {
        let report = report_of(vec![
            bam("Shared.exe", r"C:\Tools\Shared.exe", "2026-01-10T09:50:00Z"),
            userassist(
                "SHARED.EXE",
                Some("2026-01-10T10:15:00Z"),
                Some(r"c:\tools\shared.exe"),
                None,
            ),
            userassist(
                "Only.exe",
                Some("2026-01-10T10:15:00Z"),
                Some(r"C:\Tools\Only.exe"),
                None,
            ),
            userassist(
                "CitizenFX.FiveM.Client",
                Some("2026-01-10T10:15:00Z"),
                None,
                Some("app_id"),
            ),
            userassist("Never.exe", None, Some(r"C:\Tools\Never.exe"), None),
        ]);

        let candidates = gather(&report, &[session()], None);

        let shared: Vec<&Candidate> = candidates
            .iter()
            .filter(|candidate| candidate.name.eq_ignore_ascii_case("shared.exe"))
            .collect();
        assert_eq!(
            shared.len(),
            1,
            "{}",
            shared
                .iter()
                .map(|candidate| candidate.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
        assert_eq!(shared[0].sources, BTreeSet::from(["bam", "userassist"]));

        let only = candidate(&candidates, "Only.exe");
        assert_eq!(only.path.as_deref(), Some(r"C:\Tools\Only.exe"));
        assert_eq!(only.sources, BTreeSet::from(["userassist"]));

        let app = candidate(&candidates, "CitizenFX.FiveM.Client");
        assert_eq!(app.path, None, "{}", app.name);
        assert_eq!(app.sources, BTreeSet::from(["userassist"]));

        assert!(
            candidates
                .iter()
                .all(|candidate| !candidate.name.eq_ignore_ascii_case("Never.exe")),
            "{}",
            candidates
                .iter()
                .map(|candidate| candidate.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    /// A `FiveM` record of `collector` (Prefetch or BAM) with its time: the anchor name of the Legacy
    /// edition, so the session runs from Prefetch's time to BAM's.
    fn fivem_record(collector: &str, last_run: &str) -> Observation {
        Observation {
            collector: collector.to_owned(),
            fields: BTreeMap::from([
                ("name".to_owned(), serde_json::Value::from("FiveM.exe")),
                (
                    "fivem_edition".to_owned(),
                    serde_json::Value::from("legacy"),
                ),
                ("last_run".to_owned(), serde_json::Value::from(last_run)),
            ]),
        }
    }

    /// The records of one Legacy session from 10:00 to 10:30 and one BAM candidate that ran at 10:15.
    fn base_records() -> Vec<Observation> {
        vec![
            fivem_record("prefetch", "2026-01-10T10:00:00Z"),
            fivem_record("bam", "2026-01-10T10:30:00Z"),
            bam("x.sys", r"C:\Tools\x.sys", "2026-01-10T10:15:00Z"),
        ]
    }

    /// An install the event log recorded: its path digest when the record carried one.
    fn install(log: &str, digest: Option<String>, installed_at: &str) -> Observation {
        let mut fields = BTreeMap::from([
            ("log".to_owned(), serde_json::Value::from(log)),
            (
                "installed_at".to_owned(),
                serde_json::Value::from(installed_at),
            ),
        ]);
        if let Some(digest) = digest {
            fields.insert("path_digest".to_owned(), serde_json::Value::from(digest));
        }
        Observation {
            collector: "event_fields".to_owned(),
            fields,
        }
    }

    /// A refused image the code-integrity log recorded, by its volume path digest.
    fn refused_image(volume_digest: &str) -> Observation {
        Observation {
            collector: "event_fields".to_owned(),
            fields: BTreeMap::from([
                ("log".to_owned(), serde_json::Value::from("code_integrity")),
                (
                    "volume_path_digest".to_owned(),
                    serde_json::Value::from(volume_digest),
                ),
            ]),
        }
    }

    fn digest_of(path: &str) -> String {
        path_digest(path).unwrap_or_else(|| panic!("{path} has no path digest"))
    }

    fn volume_digest_of(path: &str) -> String {
        volume_path_digest(path).unwrap_or_else(|| panic!("{path} has no volume path digest"))
    }

    fn shown<'a>(windows: &'a GameWindows, name: &str) -> &'a GameCandidate {
        windows
            .candidates
            .iter()
            .find(|candidate| candidate.name.eq_ignore_ascii_case(name))
            .unwrap_or_else(|| panic!("no shown candidate {name}"))
    }

    /// h1: an install whose path digest equals a candidate's is shown on that candidate, and moves
    /// neither its times, its facts nor its place in the view (ADR 0081 section 4).
    #[test]
    fn h1_install_with_the_candidates_path_digest_is_shown_on_it_and_moves_no_fact() {
        let without = game_windows(&report_of(base_records()), Mode::SelfCheck);

        let mut records = base_records();
        records.push(install(
            "system",
            Some(digest_of(r"c:\tools\X.SYS")),
            "2026-01-10T09:57:00Z",
        ));
        let with = game_windows(&report_of(records), Mode::SelfCheck);

        let installed: Vec<jiff::Timestamp> = shown(&with, "x.sys")
            .installed_at
            .iter()
            .map(|text| at(text))
            .collect();
        assert_eq!(installed, vec![at("2026-01-10T09:57:00Z")]);
        assert!(shown(&without, "x.sys").installed_at.is_empty());
        assert_eq!(with.unmatched_installs, InstallCounts::default());

        let mut stripped = with.candidates.clone();
        for candidate in &mut stripped {
            candidate.installed_at.clear();
        }
        assert_eq!(stripped, without.candidates);
        assert_eq!(with.counts, without.counts);
    }

    /// h2: an install with no matching candidate is counted in the window it falls in, and the
    /// candidate counts do not change (ADR 0081 section 4).
    #[test]
    fn h2_installs_without_a_matching_candidate_are_counted_per_window() {
        let without = game_windows(&report_of(base_records()), Mode::SelfCheck);
        assert_eq!(
            without.counts.during, 2,
            "the BAM candidate and BAM's FiveM anchor are in the session"
        );

        let mut records = base_records();
        // Another program's digest, three minutes before the session: before window.
        records.push(install(
            "system",
            Some(digest_of(r"C:\Tools\other.sys")),
            "2026-01-10T09:57:00Z",
        ));
        // No path digest, during the session: during window.
        records.push(install("system", None, "2026-01-10T10:10:00Z"));
        let with = game_windows(&report_of(records), Mode::SelfCheck);

        assert_eq!(
            with.unmatched_installs,
            InstallCounts {
                before: 1,
                during: 1,
                after: 0,
            }
        );
        assert_eq!(with.counts, without.counts);
        assert!(shown(&with, "x.sys").installed_at.is_empty());
    }

    /// h3: a refused image sets the flag on the candidate whose volume path digest it carries and on
    /// no other (ADR 0081 section 4).
    #[test]
    fn h3_refused_image_marks_only_the_candidate_with_its_volume_digest() {
        let mut records = base_records();
        records.push(bam("y.sys", r"C:\Tools\y.sys", "2026-01-10T10:20:00Z"));
        records.push(refused_image(&volume_digest_of(
            r"\Device\HarddiskVolume2\Tools\x.sys",
        )));
        let windows = game_windows(&report_of(records), Mode::SelfCheck);

        assert!(shown(&windows, "x.sys").refused_by_code_integrity);
        assert!(!shown(&windows, "y.sys").refused_by_code_integrity);
    }

    /// A clock change the event log recorded, as `event_fields` reads it: the log it came from, when
    /// it happened, and the clock's time before and after.
    fn clock_change(log: &str, changed_at: &str, old_time: &str, new_time: &str) -> Observation {
        Observation {
            collector: "event_fields".to_owned(),
            fields: BTreeMap::from([
                ("log".to_owned(), serde_json::Value::from(log)),
                ("changed_at".to_owned(), serde_json::Value::from(changed_at)),
                ("old_time".to_owned(), serde_json::Value::from(old_time)),
                ("new_time".to_owned(), serde_json::Value::from(new_time)),
            ]),
        }
    }

    /// The `event_fields` run's summary for one log: `read` says whether that log was read.
    fn event_summary(log: &str, read: &str) -> Observation {
        Observation {
            collector: "event_fields".to_owned(),
            fields: BTreeMap::from([
                ("log".to_owned(), serde_json::Value::from(log)),
                ("read".to_owned(), serde_json::Value::from(read)),
            ]),
        }
    }

    /// A log as `evtx` reads it: its file name and the time of its oldest record.
    fn event_log(log: &str, oldest_record_time: &str) -> Observation {
        Observation {
            collector: "evtx".to_owned(),
            fields: BTreeMap::from([
                ("log".to_owned(), serde_json::Value::from(log)),
                ("entries".to_owned(), serde_json::Value::from(40)),
                (
                    "oldest_record_time".to_owned(),
                    serde_json::Value::from(oldest_record_time),
                ),
            ]),
        }
    }

    /// `evtx`'s trace-age declaration as `scan::run` makes it: the oldest record of each log, counted
    /// by its entries, one row per log, and the logs the bundle reads listed first, `System.evtx`
    /// among them (`scan.rs`'s `the_report_declares_ages_and_the_logs_the_bundle_reads`).
    fn evtx_ages() -> BTreeMap<String, AgeFields> {
        BTreeMap::from([(
            "evtx".to_owned(),
            AgeFields {
                oldest: vec!["oldest_record_time".to_owned()],
                count: AgeCount::Field {
                    field: "entries".to_owned(),
                },
                rows: AgeRows::PerValue {
                    field: "log".to_owned(),
                },
                places: Vec::new(),
                extra: Vec::new(),
                first: vec!["System.evtx".to_owned()],
                by_place: Vec::new(),
            },
        )])
    }

    /// The base records with `extra` added, and `evtx` declared for trace ages.
    fn clock_report(extra: Vec<Observation>) -> Report {
        let mut records = base_records();
        records.extend(extra);
        let mut report = report_of(records);
        report.age_fields = evtx_ages();
        report
    }

    /// c1: a one-hour clock change ten minutes before the session is one line that carries its times
    /// and nothing about why (ADR 0081 section 3).
    #[test]
    fn c1_a_clock_change_inside_the_compared_span_is_one_line_with_its_times() {
        let report = clock_report(vec![clock_change(
            "security",
            "2026-01-10T09:50:00Z",
            "2026-01-10T09:50:00Z",
            "2026-01-10T10:50:00Z",
        )]);

        let windows = game_windows(&report, Mode::SelfCheck);

        assert_eq!(
            windows.clock.changes,
            vec![ClockLine {
                changed_at: "2026-01-10T09:50:00Z".to_owned(),
                old_time: Some("2026-01-10T09:50:00Z".to_owned()),
                new_time: Some("2026-01-10T10:50:00Z".to_owned()),
            }]
        );
    }

    /// c1: a clock change a day before the earliest window is no line (ADR 0081 section 3).
    #[test]
    fn c1_a_clock_change_a_day_before_the_span_is_no_line() {
        let report = clock_report(vec![clock_change(
            "system",
            "2026-01-09T10:00:00Z",
            "2026-01-09T10:00:00Z",
            "2026-01-09T11:00:00Z",
        )]);

        let windows = game_windows(&report, Mode::SelfCheck);

        assert!(
            windows.clock.changes.is_empty(),
            "{:?}",
            windows.clock.changes
        );
    }

    /// c1: with no session there is no span, so a clock change is no line (ADR 0081 section 3).
    #[test]
    fn c1_with_no_session_a_clock_change_is_no_line() {
        let report = report_of(vec![clock_change(
            "system",
            "2026-01-10T09:50:00Z",
            "2026-01-10T09:50:00Z",
            "2026-01-10T10:50:00Z",
        )]);

        let windows = game_windows(&report, Mode::SelfCheck);

        assert!(
            windows.clock.changes.is_empty(),
            "{:?}",
            windows.clock.changes
        );
    }

    /// c1: a latest session with no recorded end runs to the scan, so a change at 10:15 in a session
    /// from 10:00, with the scan at 11:00, is one line (ADR 0081 section 3).
    #[test]
    fn c1_a_clock_change_during_a_session_with_no_recorded_end_is_a_line_up_to_the_scan() {
        let mut report = report_of(vec![
            fivem_record("prefetch", "2026-01-10T10:00:00Z"),
            clock_change(
                "system",
                "2026-01-10T10:15:00Z",
                "2026-01-10T10:15:00Z",
                "2026-01-10T10:45:00Z",
            ),
        ]);
        report.header.generated_at = "2026-01-10T11:00:00Z".to_owned();

        let windows = game_windows(&report, Mode::SelfCheck);

        assert_eq!(windows.sessions[0].end, None);
        assert_eq!(
            windows.clock.changes,
            vec![ClockLine {
                changed_at: "2026-01-10T10:15:00Z".to_owned(),
                old_time: Some("2026-01-10T10:15:00Z".to_owned()),
                new_time: Some("2026-01-10T10:45:00Z".to_owned()),
            }]
        );
    }

    /// c1: with no scan time and no recorded end, the span ends where the latest session's after window
    /// does, half an hour after its start: a change at 10:15 is a line, one at 10:45 is not
    /// (ADR 0081 section 3).
    #[test]
    fn c1_without_a_scan_time_a_session_with_no_recorded_end_ends_after_its_window() {
        let mut report = report_of(vec![
            fivem_record("prefetch", "2026-01-10T10:00:00Z"),
            clock_change(
                "system",
                "2026-01-10T10:15:00Z",
                "2026-01-10T10:15:00Z",
                "2026-01-10T10:45:00Z",
            ),
            clock_change(
                "system",
                "2026-01-10T10:45:00Z",
                "2026-01-10T10:45:00Z",
                "2026-01-10T11:15:00Z",
            ),
        ]);
        report.header.generated_at = "not a time".to_owned();

        let windows = game_windows(&report, Mode::SelfCheck);

        assert_eq!(
            windows.clock.changes,
            vec![ClockLine {
                changed_at: "2026-01-10T10:15:00Z".to_owned(),
                old_time: Some("2026-01-10T10:15:00Z".to_owned()),
                new_time: Some("2026-01-10T10:45:00Z".to_owned()),
            }]
        );
    }

    /// c1: the System and Security logs record one change between them, so it is one line; a change
    /// with a different new time is a line of its own (ADR 0081 section 3).
    #[test]
    fn c1_the_same_change_in_the_system_and_security_logs_is_one_line() {
        let report = clock_report(vec![
            clock_change(
                "system",
                "2026-01-10T10:15:00Z",
                "2026-01-10T10:15:00Z",
                "2026-01-10T10:45:00Z",
            ),
            clock_change(
                "security",
                "2026-01-10T10:15:00Z",
                "2026-01-10T10:15:00Z",
                "2026-01-10T10:45:00Z",
            ),
            clock_change(
                "security",
                "2026-01-10T10:20:00Z",
                "2026-01-10T10:20:00Z",
                "2026-01-10T11:00:00Z",
            ),
        ]);

        let windows = game_windows(&report, Mode::SelfCheck);

        assert_eq!(
            windows.clock.changes,
            vec![
                ClockLine {
                    changed_at: "2026-01-10T10:15:00Z".to_owned(),
                    old_time: Some("2026-01-10T10:15:00Z".to_owned()),
                    new_time: Some("2026-01-10T10:45:00Z".to_owned()),
                },
                ClockLine {
                    changed_at: "2026-01-10T10:20:00Z".to_owned(),
                    old_time: Some("2026-01-10T10:20:00Z".to_owned()),
                    new_time: Some("2026-01-10T11:00:00Z".to_owned()),
                },
            ]
        );
    }

    /// c1: a clock time that does not parse is no time, and one that does is shown as the view renders
    /// times, in UTC to the second (ADR 0081 section 3).
    #[test]
    fn c1_a_clock_time_that_does_not_parse_is_no_time_and_one_that_does_is_rendered_again() {
        let report = clock_report(vec![clock_change(
            "system",
            "2026-01-10T10:15:00Z",
            "not a time",
            "2026-01-10T11:45:00+01:00",
        )]);

        let windows = game_windows(&report, Mode::SelfCheck);

        assert_eq!(
            windows.clock.changes,
            vec![ClockLine {
                changed_at: "2026-01-10T10:15:00Z".to_owned(),
                old_time: None,
                new_time: Some("2026-01-10T10:45:00Z".to_owned()),
            }]
        );
    }

    /// c2: with no `event_fields` run at all, the history is not known, even with the System log's
    /// oldest record before the span (ADR 0078 section 5, as amended by ADR 0081 section 3).
    #[test]
    fn c2_no_event_fields_run_makes_the_history_not_known() {
        let report = clock_report(vec![event_log("System.evtx", "2026-01-01T00:00:00Z")]);

        let windows = game_windows(&report, Mode::SelfCheck);

        assert_eq!(windows.clock.history, ClockHistory::NotKnown);
    }

    /// c2: an `event_fields` run whose System place is gapped is not known, even when the run says it
    /// read and the System log's oldest record is before the span.
    #[test]
    fn c2_a_gapped_system_place_makes_the_history_not_known() {
        let mut report = clock_report(vec![
            event_summary("system", "read"),
            event_log("System.evtx", "2026-01-01T00:00:00Z"),
        ]);
        report.unmeasured_sources.push(UnmeasuredSource {
            collector: "event_fields".to_owned(),
            place: Some("system".to_owned()),
            reason: UnmeasuredReason::AccessDenied,
        });

        let windows = game_windows(&report, Mode::SelfCheck);

        assert_eq!(windows.clock.history, ClockHistory::NotKnown);
    }

    /// c2: the System place read and the System log's oldest record before the span is known; the
    /// log is found by the name `evtx` gives it, as the bundle lists it (ADR 0081 section 3).
    #[test]
    fn c2_system_read_and_oldest_record_before_the_span_makes_the_history_known() {
        let report = clock_report(vec![
            event_summary("system", "read"),
            event_log("System.evtx", "2026-01-10T09:00:00Z"),
        ]);

        let windows = game_windows(&report, Mode::SelfCheck);

        assert_eq!(windows.clock.history, ClockHistory::Known);
    }

    /// c2: the System place read and the System log's oldest record at the span's start is known,
    /// since the record is "at or before" that start (ADR 0081 section 3).
    #[test]
    fn c2_system_read_and_oldest_record_at_the_span_start_makes_the_history_known() {
        let report = clock_report(vec![
            event_summary("system", "read"),
            event_log("System.evtx", "2026-01-10T09:30:00Z"),
        ]);

        let windows = game_windows(&report, Mode::SelfCheck);

        assert_eq!(windows.clock.history, ClockHistory::Known);
    }

    /// c2: a rejected record in the System log, a damaged chunk that may hold a clock change, makes the
    /// history not known, even when the log reaches back far enough (ADR 0081 section 3).
    #[test]
    fn c2_a_rejected_record_in_the_system_log_makes_the_history_not_known() {
        let mut summary = event_summary("system", "read");
        summary
            .fields
            .insert("rejected".to_owned(), serde_json::Value::from(1));
        let report = clock_report(vec![
            summary,
            event_log("System.evtx", "2026-01-10T09:00:00Z"),
        ]);

        let windows = game_windows(&report, Mode::SelfCheck);

        assert_eq!(windows.clock.history, ClockHistory::NotKnown);
    }

    /// c2: a System summary that counts no rejected record is as good as one that counts none at all.
    #[test]
    fn c2_a_system_summary_with_no_rejected_record_keeps_the_history_known() {
        let mut summary = event_summary("system", "read");
        summary
            .fields
            .insert("rejected".to_owned(), serde_json::Value::from(0));
        let report = clock_report(vec![
            summary,
            event_log("System.evtx", "2026-01-10T09:00:00Z"),
        ]);

        let windows = game_windows(&report, Mode::SelfCheck);

        assert_eq!(windows.clock.history, ClockHistory::Known);
    }

    /// c2: the System place read but the System log's oldest record inside the span is not known: the
    /// log cannot say whether the clock was changed before its records begin (ADR 0081 section 3).
    #[test]
    fn c2_system_read_and_oldest_record_inside_the_span_makes_the_history_not_known() {
        let report = clock_report(vec![
            event_summary("system", "read"),
            event_log("System.evtx", "2026-01-10T09:45:00Z"),
        ]);

        let windows = game_windows(&report, Mode::SelfCheck);

        assert_eq!(windows.clock.history, ClockHistory::NotKnown);
    }

    /// c3: adding a clock change moves no candidate, changes no order and no count, in either mode;
    /// SS mode shows the same clock lines as Self mode.
    #[test]
    fn c3_a_clock_change_moves_no_candidate_and_no_count_in_either_mode() {
        let log = event_log("System.evtx", "2026-01-01T00:00:00Z");
        let without = game_windows(&clock_report(vec![log.clone()]), Mode::SelfCheck);
        let with = game_windows(
            &clock_report(vec![
                log.clone(),
                clock_change(
                    "system",
                    "2026-01-10T09:50:00Z",
                    "2026-01-10T09:50:00Z",
                    "2026-01-10T10:50:00Z",
                ),
            ]),
            Mode::SelfCheck,
        );
        let ss_without = game_windows(&clock_report(vec![log.clone()]), Mode::Ss);
        let ss_with = game_windows(
            &clock_report(vec![
                log,
                clock_change(
                    "system",
                    "2026-01-10T09:50:00Z",
                    "2026-01-10T09:50:00Z",
                    "2026-01-10T10:50:00Z",
                ),
            ]),
            Mode::Ss,
        );

        assert!(
            !without.candidates.is_empty(),
            "the candidate is in the session"
        );
        assert_eq!(with.clock.changes.len(), 1);
        assert_eq!(with.sessions, without.sessions);
        assert_eq!(with.candidates, without.candidates);
        assert_eq!(with.counts, without.counts);
        assert_eq!(ss_with.candidates, ss_without.candidates);
        assert_eq!(ss_with.counts, ss_without.counts);
        assert_eq!(ss_with.clock, with.clock);
    }

    /// A Prefetch record of `name` with its run times and, when given, the `FiveM` edition it belongs
    /// to (ADR 0082 section 5). Only its run times make it a candidate or feed a session.
    fn prefetch(name: &str, fivem_edition: Option<&str>, run_times: &[&str]) -> Observation {
        let mut fields = BTreeMap::from([
            ("name".to_owned(), serde_json::Value::from(name)),
            (
                "run_times".to_owned(),
                serde_json::Value::Array(
                    run_times
                        .iter()
                        .map(|time| serde_json::Value::from(*time))
                        .collect(),
                ),
            ),
        ]);
        if let Some(edition) = fivem_edition {
            fields.insert("fivem_edition".to_owned(), serde_json::Value::from(edition));
        }
        Observation {
            collector: "prefetch".to_owned(),
            fields,
        }
    }

    /// A `FiveM` anchor record of `collector` for `edition`: the `FiveM.exe` name and the time ADR 0062
    /// reads from it (Prefetch's or BAM's `last_run`).
    fn anchor(collector: &str, edition: &str, last_run: &str) -> Observation {
        Observation {
            collector: collector.to_owned(),
            fields: BTreeMap::from([
                ("name".to_owned(), serde_json::Value::from("FiveM.exe")),
                ("fivem_edition".to_owned(), serde_json::Value::from(edition)),
                ("last_run".to_owned(), serde_json::Value::from(last_run)),
            ]),
        }
    }

    /// `observation` with the count of files it loaded from outside Windows, Program Files and
    /// `FiveM`'s folders (ADR 0082 section 5).
    fn with_loaded_outside(mut observation: Observation, count: u64) -> Observation {
        observation
            .fields
            .insert("loaded_outside".to_owned(), serde_json::Value::from(count));
        observation
    }

    /// `observation` with the count marked as not known, so it carries no `loaded_outside` count.
    fn with_loaded_outside_unknown(mut observation: Observation) -> Observation {
        observation.fields.insert(
            "loaded_outside_unknown".to_owned(),
            serde_json::Value::from(true),
        );
        observation
    }

    /// The session of `edition`, the latest one or an earlier one, that the view shows.
    fn shown_session<'a>(windows: &'a GameWindows, edition: &str, latest: bool) -> &'a GameSession {
        windows
            .sessions
            .iter()
            .find(|session| session.edition == edition && session.latest == latest)
            .unwrap_or_else(|| panic!("no {edition} session, latest {latest}"))
    }

    /// `l1_c1`: a Prefetch `rundll32.exe` record in the Legacy session with `loaded_outside` above zero
    /// has L1 true (ADR 0082 section 5).
    #[test]
    fn l1_c1_a_prefetch_record_with_loaded_outside_above_zero_is_l1_true() {
        let mut records = base_records();
        records.push(with_loaded_outside(
            prefetch("rundll32.exe", None, &["2026-01-10T10:15:00Z"]),
            2,
        ));

        let windows = game_windows(&report_of(records), Mode::SelfCheck);

        assert_eq!(shown(&windows, "rundll32.exe").l1, IdentityFact::True);
    }

    /// `l1_c1`: the same record with `loaded_outside` at zero has L1 false.
    #[test]
    fn l1_c1_a_prefetch_record_with_loaded_outside_zero_is_l1_false() {
        let mut records = base_records();
        records.push(with_loaded_outside(
            prefetch("rundll32.exe", None, &["2026-01-10T10:15:00Z"]),
            0,
        ));

        let windows = game_windows(&report_of(records), Mode::SelfCheck);

        assert_eq!(shown(&windows, "rundll32.exe").l1, IdentityFact::False);
    }

    /// `l1_c1`: a Prefetch record with no `loaded_outside` field is not counted, so its L1 is not
    /// known for that reason.
    #[test]
    fn l1_c1_a_prefetch_record_without_loaded_outside_is_not_counted() {
        let mut records = base_records();
        records.push(prefetch("rundll32.exe", None, &["2026-01-10T10:15:00Z"]));

        let windows = game_windows(&report_of(records), Mode::SelfCheck);

        assert_eq!(
            shown(&windows, "rundll32.exe").l1,
            IdentityFact::NotKnown {
                reason: IdentityNotKnownReason::NotCounted,
            }
        );
    }

    /// `l1_c1`: a Prefetch record that says its `loaded_outside` count is unknown is not counted, even
    /// when it also holds a count.
    #[test]
    fn l1_c1_a_prefetch_record_with_loaded_outside_unknown_is_not_counted() {
        let mut records = base_records();
        records.push(with_loaded_outside_unknown(prefetch(
            "rundll32.exe",
            None,
            &["2026-01-10T10:15:00Z"],
        )));

        let windows = game_windows(&report_of(records), Mode::SelfCheck);

        assert_eq!(
            shown(&windows, "rundll32.exe").l1,
            IdentityFact::NotKnown {
                reason: IdentityNotKnownReason::NotCounted,
            }
        );
    }

    /// `l1_c2`: a candidate with no Prefetch record, here a BAM record alone, has L1 not known because it
    /// is not counted (ADR 0082 section 5).
    #[test]
    fn l1_c2_a_bam_only_candidate_is_l1_not_counted() {
        let windows = game_windows(&report_of(base_records()), Mode::SelfCheck);

        assert_eq!(
            shown(&windows, "x.sys").l1,
            IdentityFact::NotKnown {
                reason: IdentityNotKnownReason::NotCounted,
            }
        );
    }

    /// `l1_c3`: in SS mode a candidate with L1 true is listed by name, though none of its I1 to I4 facts
    /// is true (ADR 0082 section 5, which amends ADR 0078 section 9).
    #[test]
    fn l1_c3_in_ss_mode_an_l1_true_candidate_is_listed_by_name() {
        let mut records = base_records();
        records.push(with_loaded_outside(
            prefetch("rundll32.exe", None, &["2026-01-10T10:15:00Z"]),
            2,
        ));
        let report = report_of(records);

        let self_mode = game_windows(&report, Mode::SelfCheck);
        let shown_self = shown(&self_mode, "rundll32.exe");
        assert_ne!(shown_self.i1, IdentityFact::True);
        assert_ne!(shown_self.i2, IdentityFact::True);
        assert_ne!(shown_self.i3, IdentityFact::True);
        assert_ne!(shown_self.i4, IdentityFact::True);

        let ss = game_windows(&report, Mode::Ss);

        assert_eq!(shown(&ss, "rundll32.exe").l1, IdentityFact::True);
    }

    /// `l1_c3`: the same candidate with `loaded_outside` at zero has L1 false, so SS mode does not list
    /// it, while Self mode still shows it.
    #[test]
    fn l1_c3_in_ss_mode_an_l1_false_candidate_is_not_listed() {
        let mut records = base_records();
        records.push(with_loaded_outside(
            prefetch("rundll32.exe", None, &["2026-01-10T10:15:00Z"]),
            0,
        ));
        let report = report_of(records);

        let self_mode = game_windows(&report, Mode::SelfCheck);
        assert_eq!(shown(&self_mode, "rundll32.exe").l1, IdentityFact::False);

        let ss = game_windows(&report, Mode::Ss);

        assert!(
            ss.candidates
                .iter()
                .all(|candidate| !candidate.name.eq_ignore_ascii_case("rundll32.exe")),
            "{}",
            ss.candidates
                .iter()
                .map(|candidate| candidate.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    /// `l1_c4`: of two candidates equal in T1 to T4 and I1 to I4, the one with L1 true comes first, even
    /// though its time is later. Both records share a name so that their identity facts are the same.
    #[test]
    fn l1_c4_of_equal_candidates_the_one_with_l1_true_comes_first() {
        let mut records = base_records();
        records.push(prefetch("rundll32.exe", None, &["2026-01-10T10:10:00Z"]));
        records.push(with_loaded_outside(
            prefetch("rundll32.exe", None, &["2026-01-10T10:20:00Z"]),
            2,
        ));

        let windows = game_windows(&report_of(records), Mode::SelfCheck);

        let rundll: Vec<&GameCandidate> = windows
            .candidates
            .iter()
            .filter(|candidate| candidate.name.eq_ignore_ascii_case("rundll32.exe"))
            .collect();
        assert_eq!(rundll.len(), 2, "two rundll32.exe candidates");
        let (first, second) = (rundll[0], rundll[1]);
        assert_eq!(first.t1, second.t1);
        assert_eq!(first.t2, second.t2);
        assert_eq!(first.t3, second.t3);
        assert_eq!(first.t4, second.t4);
        assert_eq!(first.i1, second.i1);
        assert_eq!(first.i2, second.i2);
        assert_eq!(first.i3, second.i3);
        assert_eq!(first.i4, second.i4);
        assert_eq!(first.l1, IdentityFact::True);
        assert_eq!(
            second.l1,
            IdentityFact::NotKnown {
                reason: IdentityNotKnownReason::NotCounted,
            }
        );
    }

    /// `l1_c5`: a `FiveM.exe` Prefetch run at the Legacy session's start with `loaded_outside` above zero
    /// makes the latest Legacy session's L1 true, and its count is shown (ADR 0082 section 5).
    #[test]
    fn l1_c5_a_legacy_fivem_exe_run_with_loaded_outside_feeds_the_latest_legacy_session() {
        let mut records = base_records();
        records.push(with_loaded_outside(
            prefetch("FiveM.exe", Some("legacy"), &["2026-01-10T10:00:00Z"]),
            1,
        ));

        let windows = game_windows(&report_of(records), Mode::SelfCheck);

        let legacy = shown_session(&windows, "legacy", true);
        assert_eq!(legacy.l1, IdentityFact::True);
        assert_eq!(legacy.loaded_outside, Some(1));
    }

    /// `l1_c5`: the same run with `loaded_outside` at zero makes the Legacy session's L1 false, with a
    /// count of zero.
    #[test]
    fn l1_c5_a_legacy_fivem_exe_run_with_loaded_outside_zero_makes_the_session_l1_false() {
        let mut records = base_records();
        records.push(with_loaded_outside(
            prefetch("FiveM.exe", Some("legacy"), &["2026-01-10T10:00:00Z"]),
            0,
        ));

        let windows = game_windows(&report_of(records), Mode::SelfCheck);

        let legacy = shown_session(&windows, "legacy", true);
        assert_eq!(legacy.l1, IdentityFact::False);
        assert_eq!(legacy.loaded_outside, Some(0));
    }

    /// `l1_c5`: a `GTA5_Enhanced.exe` run tagged Enhanced, inside both editions' spans, feeds the latest
    /// Enhanced session and never the Legacy one (ADR 0082 section 5).
    #[test]
    fn l1_c5_an_enhanced_run_feeds_the_enhanced_session_and_never_the_legacy_one() {
        let mut records = base_records();
        records.push(anchor("prefetch", "enhanced", "2026-01-10T10:00:00Z"));
        records.push(anchor("bam", "enhanced", "2026-01-10T10:30:00Z"));
        records.push(with_loaded_outside(
            prefetch(
                "GTA5_Enhanced.exe",
                Some("enhanced"),
                &["2026-01-10T10:15:00Z"],
            ),
            3,
        ));

        let windows = game_windows(&report_of(records), Mode::SelfCheck);

        let enhanced = shown_session(&windows, "enhanced", true);
        assert_eq!(enhanced.l1, IdentityFact::True);
        assert_eq!(enhanced.loaded_outside, Some(3));
        let legacy = shown_session(&windows, "legacy", true);
        assert_eq!(
            legacy.l1,
            IdentityFact::NotKnown {
                reason: IdentityNotKnownReason::NotCounted,
            }
        );
        assert_eq!(legacy.loaded_outside, None);
    }

    /// `l1_c5`: a Prefetch record with no `fivem_edition` feeds no session, even with its run time inside
    /// both editions' spans and a count above zero (ADR 0082 section 5).
    #[test]
    fn l1_c5_a_prefetch_record_without_fivem_edition_feeds_no_session() {
        let mut records = base_records();
        records.push(anchor("prefetch", "enhanced", "2026-01-10T10:00:00Z"));
        records.push(anchor("bam", "enhanced", "2026-01-10T10:30:00Z"));
        records.push(with_loaded_outside(
            prefetch("GTA5_Enhanced.exe", None, &["2026-01-10T10:15:00Z"]),
            5,
        ));

        let windows = game_windows(&report_of(records), Mode::SelfCheck);

        for edition in ["legacy", "enhanced"] {
            let session = shown_session(&windows, edition, true);
            assert_eq!(
                session.l1,
                IdentityFact::NotKnown {
                    reason: IdentityNotKnownReason::NotCounted,
                },
                "{edition}"
            );
            assert_eq!(session.loaded_outside, None, "{edition}");
        }
    }

    /// `l1_c6`: a Legacy run after the latest session's recorded end does not feed it, so its L1 is not
    /// counted and its count is absent.
    #[test]
    fn l1_c6_a_record_after_the_latest_session_end_does_not_feed_it() {
        let mut records = base_records();
        records.push(with_loaded_outside(
            prefetch(
                "FiveM_b2802_GTAProcess.exe",
                Some("legacy"),
                &["2026-01-10T10:45:00Z"],
            ),
            1,
        ));

        let windows = game_windows(&report_of(records), Mode::SelfCheck);

        let legacy = shown_session(&windows, "legacy", true);
        assert_eq!(
            legacy.l1,
            IdentityFact::NotKnown {
                reason: IdentityNotKnownReason::NotCounted,
            }
        );
        assert_eq!(legacy.loaded_outside, None);
    }

    /// `l1_c6`: an earlier session's L1 is not known because an earlier session's end is never known, so
    /// no record can be placed in it, even one with a count above zero (ADR 0082 section 5).
    #[test]
    fn l1_c6_an_earlier_session_has_l1_not_known_for_its_earlier_session() {
        let mut records = base_records();
        records.push(with_loaded_outside(
            prefetch("FiveM.exe", Some("legacy"), &["2026-01-10T08:00:00Z"]),
            1,
        ));

        let windows = game_windows(&report_of(records), Mode::SelfCheck);

        let earlier = shown_session(&windows, "legacy", false);
        assert_eq!(
            earlier.l1,
            IdentityFact::NotKnown {
                reason: IdentityNotKnownReason::EarlierSession,
            }
        );
        assert_eq!(earlier.loaded_outside, None);
        let latest = shown_session(&windows, "legacy", true);
        assert_eq!(
            latest.l1,
            IdentityFact::NotKnown {
                reason: IdentityNotKnownReason::NotCounted,
            }
        );
    }

    /// `l1_c7`: a saved candidate and session written before L1 existed, with no `l1` and no
    /// `loaded_outside`, still read, as not counted (ADR 0082 section 5).
    #[test]
    fn l1_c7_a_saved_view_without_l1_reads_as_not_counted() {
        let windows = game_windows(&report_of(base_records()), Mode::SelfCheck);
        let mut saved = serde_json::to_value(&windows).unwrap();
        for session in saved["sessions"].as_array_mut().unwrap() {
            let object = session.as_object_mut().unwrap();
            object.remove("l1");
            object.remove("loaded_outside");
        }
        for candidate in saved["candidates"].as_array_mut().unwrap() {
            candidate.as_object_mut().unwrap().remove("l1");
        }

        let read: GameWindows = serde_json::from_value(saved).unwrap();

        assert!(!read.candidates.is_empty(), "the BAM candidate is saved");
        assert!(!read.sessions.is_empty(), "the Legacy session is saved");
        for candidate in &read.candidates {
            assert_eq!(
                candidate.l1,
                IdentityFact::NotKnown {
                    reason: IdentityNotKnownReason::NotCounted,
                },
                "{}",
                candidate.name
            );
        }
        for session in &read.sessions {
            assert_eq!(
                session.l1,
                IdentityFact::NotKnown {
                    reason: IdentityNotKnownReason::NotCounted,
                },
                "{}",
                session.edition
            );
            assert_eq!(session.loaded_outside, None, "{}", session.edition);
        }
    }

    /// ADR 0084 decision 3: a record named like an anchor is a candidate like any other, whatever
    /// its path; here a BAM record named `FiveM.exe` ran from Downloads.
    #[test]
    fn t_renamed_anchor_name_is_a_candidate() {
        let path = r"C:\Users\x\Downloads\FiveM.exe";
        let mut records = base_records();
        records.push(bam("FiveM.exe", path, "2026-01-10T10:15:00Z"));

        let windows = game_windows(&report_of(records), Mode::SelfCheck);

        let renamed = windows
            .candidates
            .iter()
            .find(|candidate| candidate.path.as_deref() == Some(path))
            .unwrap_or_else(|| panic!("no candidate at {path}"));
        assert_eq!(renamed.name, "FiveM.exe");
        assert_eq!(renamed.t2, TimeFact::True);
    }

    /// ADR 0084 decision 3: the `FiveM.exe` records that anchor a session are candidates too, and
    /// finding the session does not change.
    #[test]
    fn t_anchor_record_is_also_a_candidate() {
        let mut records = base_records();
        // A real Prefetch record carries `run_times` beside `last_run`, and those times are what
        // make it a candidate like any other Prefetch record (ADR 0078 section 6).
        for record in &mut records {
            if record.collector == "prefetch" {
                record.fields.insert(
                    "run_times".to_owned(),
                    serde_json::json!(["2026-01-10T10:00:00Z"]),
                );
            }
        }
        let windows = game_windows(&report_of(records), Mode::SelfCheck);

        let legacy = shown_session(&windows, "legacy", true);
        assert_eq!(legacy.start, "2026-01-10T10:00:00Z");
        assert_eq!(legacy.end.as_deref(), Some("2026-01-10T10:30:00Z"));

        let anchors: Vec<&GameCandidate> = windows
            .candidates
            .iter()
            .filter(|candidate| candidate.name.eq_ignore_ascii_case("FiveM.exe"))
            .collect();
        assert_eq!(
            anchors.len(),
            2,
            "both anchor records are candidates: {}",
            windows
                .candidates
                .iter()
                .map(|candidate| candidate.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
        assert!(
            anchors
                .iter()
                .any(|candidate| candidate.recorded_by == vec!["prefetch".to_owned()])
        );
        assert!(
            anchors
                .iter()
                .any(|candidate| candidate.recorded_by == vec!["bam".to_owned()])
        );
    }

    /// ADR 0084 decision 3: a Prefetch record named `GTA5.exe` inside the window is a candidate like
    /// any other, not only a timeline anchor.
    #[test]
    fn t_gta_process_name_is_a_candidate() {
        let mut records = base_records();
        records.push(prefetch("GTA5.exe", None, &["2026-01-10T10:15:00Z"]));

        let windows = game_windows(&report_of(records), Mode::SelfCheck);

        let gta = shown(&windows, "GTA5.exe");
        assert_eq!(gta.path, None);
        assert_eq!(gta.recorded_by, vec!["prefetch".to_owned()]);
        assert_eq!(gta.t2, TimeFact::True);
    }

    /// ADR 0084 decision 3: SS mode names a `FiveM.exe` candidate only when an identity fact holds.
    /// Without one it is counted with the unnamed candidates, as every other candidate is.
    #[test]
    fn t_ss_mode_names_anchor_only_with_identity_fact() {
        let mut records = base_records();
        records.push(bam(
            "FiveM.exe",
            r"C:\Tools\FiveM.exe",
            "2026-01-10T10:15:00Z",
        ));
        records.push(bam(
            "Other.exe",
            r"C:\Tools\Other.exe",
            "2026-01-10T10:15:00Z",
        ));
        let report = report_of(records);

        let self_mode = game_windows(&report, Mode::SelfCheck);
        let fivem = self_mode
            .candidates
            .iter()
            .find(|candidate| candidate.path.as_deref() == Some(r"C:\Tools\FiveM.exe"))
            .unwrap_or_else(|| panic!("no FiveM.exe candidate at its path"));
        assert!(!has_identity_fact(fivem), "{}", fivem.name);

        let expected = self_mode
            .candidates
            .iter()
            .filter(|candidate| candidate.t2 == TimeFact::True && !has_identity_fact(candidate))
            .count();
        let ss = game_windows(&report, Mode::Ss);

        assert!(
            ss.candidates
                .iter()
                .all(|candidate| !candidate.name.eq_ignore_ascii_case("FiveM.exe")),
            "{}",
            ss.candidates
                .iter()
                .map(|candidate| candidate.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
        assert!(
            ss.candidates
                .iter()
                .all(|candidate| !candidate.name.eq_ignore_ascii_case("Other.exe")),
            "Other.exe is unnamed too"
        );
        assert_eq!(ss.unnamed.during, expected);
    }

    /// A `recorded_files` observation of `path` with the change journal fields `journal` gives it, as
    /// `recorded_files` emits them (ADR 0086 section 5). Only the fields given are present.
    fn journaled(path: &str, journal: Vec<(&'static str, serde_json::Value)>) -> Observation {
        let mut fields = BTreeMap::from([("path".to_owned(), serde_json::Value::from(path))]);
        for (field, value) in journal {
            fields.insert(field.to_owned(), value);
        }
        Observation {
            collector: "recorded_files".to_owned(),
            fields,
        }
    }

    /// A list of times as a journal field holds it, newest first.
    fn times_json(times: &[&str]) -> serde_json::Value {
        serde_json::Value::Array(
            times
                .iter()
                .map(|time| serde_json::Value::from(*time))
                .collect(),
        )
    }

    /// The journal fields of a whole read that matched: its three lists, `journal_more` false, and the
    /// time the journal reaches back to (ADR 0086 section 5).
    fn whole_journal(
        deleted: &[&str],
        renamed_from: &[&str],
        renamed_to: &[&str],
        from: &str,
    ) -> Vec<(&'static str, serde_json::Value)> {
        vec![
            ("journal_match", "matched".into()),
            ("journal_deleted", times_json(deleted)),
            ("journal_renamed_from", times_json(renamed_from)),
            ("journal_renamed_to", times_json(renamed_to)),
            ("journal_more", false.into()),
            ("journal_from", from.into()),
        ]
    }

    /// The I5 of `x.sys`, the BAM candidate of `base_records` at 10:15, when `recorded_files` holds
    /// `journal` for its path.
    fn i5_with(journal: Vec<(&'static str, serde_json::Value)>) -> IdentityFact {
        let mut records = base_records();
        records.push(journaled(r"C:\Tools\x.sys", journal));
        shown(&game_windows(&report_of(records), Mode::SelfCheck), "x.sys")
            .i5
            .clone()
    }

    /// The identity fact that is not known for `reason`.
    fn not_known(reason: IdentityNotKnownReason) -> IdentityFact {
        IdentityFact::NotKnown { reason }
    }

    /// i5: a deletion at a time in each of the four windows makes I5 true, each window on its own. The
    /// scan is at 12:00, so 11:30 is in the before-the-scan window (ADR 0086 section 5).
    #[test]
    fn i5_a_deletion_in_each_window_is_true() {
        let from = "2026-01-10T09:00:00Z";
        assert_eq!(
            i5_with(whole_journal(&["2026-01-10T09:45:00Z"], &[], &[], from)),
            IdentityFact::True,
            "the before window"
        );
        assert_eq!(
            i5_with(whole_journal(&["2026-01-10T10:15:00Z"], &[], &[], from)),
            IdentityFact::True,
            "the during window"
        );
        assert_eq!(
            i5_with(whole_journal(&["2026-01-10T10:45:00Z"], &[], &[], from)),
            IdentityFact::True,
            "the after window"
        );
        assert_eq!(
            i5_with(whole_journal(&["2026-01-10T11:30:00Z"], &[], &[], from)),
            IdentityFact::True,
            "the before-the-scan window"
        );
    }

    /// i5: a rename from or to a time in a window makes I5 true, as a deletion does (ADR 0086
    /// section 5).
    #[test]
    fn i5_a_rename_from_or_to_a_window_is_true() {
        let from = "2026-01-10T09:00:00Z";
        assert_eq!(
            i5_with(whole_journal(&[], &["2026-01-10T10:15:00Z"], &[], from)),
            IdentityFact::True,
            "renamed from"
        );
        assert_eq!(
            i5_with(whole_journal(&[], &[], &["2026-01-10T10:45:00Z"], from)),
            IdentityFact::True,
            "renamed to"
        );
    }

    /// i5: a matched journal with empty lists, reaching back before 09:30, is false: nothing in it
    /// falls in a window and the journal covers them all (ADR 0086 section 5).
    #[test]
    fn i5_a_matched_journal_with_empty_lists_from_before_the_windows_is_false() {
        assert_eq!(
            i5_with(whole_journal(&[], &[], &[], "2026-01-10T09:00:00Z")),
            IdentityFact::False
        );
    }

    /// i5: a deletion at 08:00, outside every window, in a journal that reaches back to 07:00 is
    /// false, not true (ADR 0086 section 5).
    #[test]
    fn i5_a_deletion_outside_every_window_is_not_shown_as_true() {
        assert_eq!(
            i5_with(whole_journal(
                &["2026-01-10T08:00:00Z"],
                &[],
                &[],
                "2026-01-10T07:00:00Z"
            )),
            IdentityFact::False
        );
    }

    /// i5: with no `journal_match` the journal was not read, so I5 is not known for that reason
    /// (ADR 0086 section 5).
    #[test]
    fn i5_without_a_journal_match_is_journal_not_read() {
        assert_eq!(
            i5_with(vec![]),
            not_known(IdentityNotKnownReason::JournalNotRead)
        );
    }

    /// i5: a journal on another volume is `journal_other_drive`, not a read that found nothing
    /// (ADR 0086 section 5).
    #[test]
    fn i5_an_other_volume_is_journal_other_drive() {
        assert_eq!(
            i5_with(vec![("journal_match", "other_volume".into())]),
            not_known(IdentityNotKnownReason::JournalOtherDrive)
        );
    }

    /// i5: a folder the journal cannot be read for is `journal_folder_unknown` (ADR 0086 section 5).
    #[test]
    fn i5_an_unknown_folder_is_journal_folder_unknown() {
        assert_eq!(
            i5_with(vec![("journal_match", "folder_unknown".into())]),
            not_known(IdentityNotKnownReason::JournalFolderUnknown)
        );
    }

    /// i5: a matched journal whose read was not whole has no `journal_deleted`, so it is
    /// `journal_not_read` (ADR 0086 section 5).
    #[test]
    fn i5_a_matched_journal_without_lists_is_journal_not_read() {
        assert_eq!(
            i5_with(vec![("journal_match", "matched".into())]),
            not_known(IdentityNotKnownReason::JournalNotRead)
        );
    }

    /// i5: a journal that starts after the before window's start, here 09:40 against 09:30, cannot
    /// show the window, so I5 is `before_trace_age` from `usn` (ADR 0086 section 5).
    #[test]
    fn i5_a_journal_starting_after_the_before_window_is_before_trace_age() {
        assert_eq!(
            i5_with(whole_journal(&[], &[], &[], "2026-01-10T09:40:00Z")),
            not_known(IdentityNotKnownReason::BeforeTraceAge {
                source: "usn".to_owned(),
            })
        );
    }

    /// i5: a latest session with no recorded end does not know its during or after windows, so I5 is
    /// `session_end_not_recorded` (ADR 0086 section 5). The candidate sits in the before window.
    #[test]
    fn i5_a_latest_session_without_an_end_is_session_end_not_recorded() {
        let records = vec![
            fivem_record("prefetch", "2026-01-10T10:00:00Z"),
            bam("x.sys", r"C:\Tools\x.sys", "2026-01-10T09:45:00Z"),
            journaled(
                r"C:\Tools\x.sys",
                whole_journal(&[], &[], &[], "2026-01-10T09:00:00Z"),
            ),
        ];

        let windows = game_windows(&report_of(records), Mode::SelfCheck);

        assert_eq!(windows.sessions[0].end, None);
        assert_eq!(
            shown(&windows, "x.sys").i5,
            not_known(IdentityNotKnownReason::SessionEndNotRecorded)
        );
    }

    /// i5: a candidate with no path is `no_path` even when `recorded_files` holds a deletion for another
    /// file (ADR 0086 section 5).
    #[test]
    fn i5_a_candidate_with_no_path_is_no_path_even_with_other_data() {
        let mut records = base_records();
        records.push(prefetch("GTA5.exe", None, &["2026-01-10T10:15:00Z"]));
        records.push(journaled(
            r"C:\Tools\x.sys",
            whole_journal(&["2026-01-10T10:15:00Z"], &[], &[], "2026-01-10T09:00:00Z"),
        ));

        let windows = game_windows(&report_of(records), Mode::SelfCheck);

        let gta = shown(&windows, "GTA5.exe");
        assert_eq!(gta.path, None);
        assert_eq!(gta.i5, not_known(IdentityNotKnownReason::NoPath));
    }

    /// i5: on a standard scan, which does not run `recorded_files`, I5 is not known for that reason
    /// (ADR 0086 section 5).
    #[test]
    fn i5_on_a_standard_scan_is_recorded_files_not_run() {
        let windows = game_windows(&report_of(base_records()), Mode::SelfCheck);

        assert_eq!(
            shown(&windows, "x.sys").i5,
            not_known(IdentityNotKnownReason::RecordedFilesNotRun)
        );
    }

    /// i5: of two candidates equal in every other fact, the one with I5 true comes first. Its path sorts
    /// after the other's, so only the rank can put it first (ADR 0086 decision 6).
    #[test]
    fn i5_of_equal_candidates_the_one_with_i5_true_comes_first() {
        let records = vec![
            fivem_record("prefetch", "2026-01-10T10:00:00Z"),
            fivem_record("bam", "2026-01-10T10:30:00Z"),
            bam("x.sys", r"C:\Tools\First\x.sys", "2026-01-10T10:15:00Z"),
            bam("x.sys", r"C:\Tools\Second\x.sys", "2026-01-10T10:15:00Z"),
            journaled(
                r"C:\Tools\First\x.sys",
                whole_journal(&[], &[], &[], "2026-01-10T09:00:00Z"),
            ),
            journaled(
                r"C:\Tools\Second\x.sys",
                whole_journal(&["2026-01-10T10:15:00Z"], &[], &[], "2026-01-10T09:00:00Z"),
            ),
        ];

        let windows = game_windows(&report_of(records), Mode::SelfCheck);

        let same: Vec<&GameCandidate> = windows
            .candidates
            .iter()
            .filter(|candidate| candidate.name.eq_ignore_ascii_case("x.sys"))
            .collect();
        assert_eq!(same.len(), 2, "two x.sys candidates");
        assert_eq!(same[0].path.as_deref(), Some(r"C:\Tools\Second\x.sys"));
        assert_eq!(same[0].i5, IdentityFact::True);
        assert_eq!(same[1].i5, IdentityFact::False);
    }

    /// i5: in SS mode a candidate whose only true identity fact is I5 is named, as I1 to I4 and L1 name
    /// one (ADR 0086 decision 6).
    #[test]
    fn i5_in_ss_mode_a_candidate_whose_only_identity_fact_is_i5_is_named() {
        let mut records = base_records();
        records.push(bam(
            "Helper.exe",
            r"C:\Tools\Helper.exe",
            "2026-01-10T10:15:00Z",
        ));
        records.push(journaled(
            r"C:\Tools\Helper.exe",
            whole_journal(&["2026-01-10T10:15:00Z"], &[], &[], "2026-01-10T09:00:00Z"),
        ));
        let report = report_of(records);

        let self_mode = game_windows(&report, Mode::SelfCheck);
        let helper = shown(&self_mode, "Helper.exe");
        assert_eq!(helper.i5, IdentityFact::True);
        for fact in [&helper.i1, &helper.i2, &helper.i3, &helper.i4, &helper.l1] {
            assert_ne!(*fact, IdentityFact::True, "{fact:?}");
        }
        assert!(has_identity_fact(helper), "{}", helper.name);

        let ss = game_windows(&report, Mode::Ss);

        assert_eq!(shown(&ss, "Helper.exe").i5, IdentityFact::True);
    }

    /// `journal` with `journal_more` set: its lists were cut at the cap (ADR 0086 section 3, D5).
    fn cut(
        mut journal: Vec<(&'static str, serde_json::Value)>,
    ) -> Vec<(&'static str, serde_json::Value)> {
        journal.retain(|(field, _)| *field != "journal_more");
        journal.push(("journal_more", true.into()));
        journal
    }

    /// i5: the window edges are inclusive where ADR 0086 section 5 says: the before window starts at
    /// 09:30 and the during window at 10:00, both in; the scan's window ends at 12:00, in; a time one
    /// second before 09:30 is not.
    #[test]
    fn i5_a_time_at_each_window_edge_is_true() {
        let from = "2026-01-10T09:00:00Z";
        for (time, edge) in [
            ("2026-01-10T09:30:00Z", "the before window's start"),
            ("2026-01-10T10:00:00Z", "the during window's start"),
            ("2026-01-10T10:30:00Z", "the during window's end"),
            ("2026-01-10T11:00:00Z", "the after window's end"),
            ("2026-01-10T12:00:00Z", "the scan"),
        ] {
            assert_eq!(
                i5_with(whole_journal(&[time], &[], &[], from)),
                IdentityFact::True,
                "{edge}"
            );
        }
        assert_eq!(
            i5_with(whole_journal(&["2026-01-10T09:29:59Z"], &[], &[], from)),
            IdentityFact::False,
            "one second before the before window"
        );
    }

    /// i5: a journal that starts exactly at the before window's start, 09:30, with empty lists is
    /// false: it reaches the window (ADR 0086 section 5).
    #[test]
    fn i5_a_journal_from_exactly_the_before_window_start_is_false() {
        assert_eq!(
            i5_with(whole_journal(&[], &[], &[], "2026-01-10T09:30:00Z")),
            IdentityFact::False
        );
    }

    /// i5: a deletion in the before window of an earlier, non-latest session is not a true I5: only the
    /// latest session's windows count (ADR 0086 section 5). The earlier session is at 08:00.
    #[test]
    fn i5_a_deletion_in_an_earlier_sessions_before_window_is_not_true() {
        let mut records = base_records();
        records.push(prefetch("FiveM.exe", Some("legacy"), &["2026-01-10T08:00:00Z"]));
        records.push(journaled(
            r"C:\Tools\x.sys",
            whole_journal(&["2026-01-10T07:45:00Z"], &[], &[], "2026-01-10T07:00:00Z"),
        ));

        let windows = game_windows(&report_of(records), Mode::SelfCheck);

        assert_eq!(windows.sessions.iter().filter(|s| !s.latest).count(), 1);
        assert_eq!(shown(&windows, "x.sys").i5, IdentityFact::False);
    }

    /// i5: a latest session with no recorded end still has its before window, so a deletion at 09:45
    /// in it makes I5 true (ADR 0086 section 5).
    #[test]
    fn i5_a_latest_session_without_an_end_has_its_before_window() {
        let records = vec![
            fivem_record("prefetch", "2026-01-10T10:00:00Z"),
            bam("x.sys", r"C:\Tools\x.sys", "2026-01-10T09:45:00Z"),
            journaled(
                r"C:\Tools\x.sys",
                whole_journal(&["2026-01-10T09:45:00Z"], &[], &[], "2026-01-10T09:00:00Z"),
            ),
        ];

        let windows = game_windows(&report_of(records), Mode::SelfCheck);

        assert_eq!(windows.sessions[0].end, None);
        assert_eq!(shown(&windows, "x.sys").i5, IdentityFact::True);
    }

    /// i5: when the latest session has no end and the journal starts after its before window, the reason
    /// is `before_trace_age`, which comes before `session_end_not_recorded` (ADR 0086 section 5).
    #[test]
    fn i5_a_latest_session_without_an_end_and_a_late_journal_is_before_trace_age() {
        let records = vec![
            fivem_record("prefetch", "2026-01-10T10:00:00Z"),
            bam("x.sys", r"C:\Tools\x.sys", "2026-01-10T09:45:00Z"),
            journaled(
                r"C:\Tools\x.sys",
                whole_journal(&[], &[], &[], "2026-01-10T09:40:00Z"),
            ),
        ];

        let windows = game_windows(&report_of(records), Mode::SelfCheck);

        assert_eq!(
            shown(&windows, "x.sys").i5,
            not_known(IdentityNotKnownReason::BeforeTraceAge {
                source: "usn".to_owned(),
            })
        );
    }

    /// i5: with no scan time, an empty journal that reaches the before window is
    /// `scan_time_not_recorded`, the reason for the before-the-scan window (ADR 0086 section 5).
    #[test]
    fn i5_without_a_scan_time_an_empty_journal_is_scan_time_not_recorded() {
        let mut records = base_records();
        records.push(journaled(
            r"C:\Tools\x.sys",
            whole_journal(&[], &[], &[], "2026-01-10T09:00:00Z"),
        ));
        let mut report = report_of(records);
        report.header.generated_at = "not a time".to_owned();

        let windows = game_windows(&report, Mode::SelfCheck);

        assert_eq!(
            shown(&windows, "x.sys").i5,
            not_known(IdentityNotKnownReason::ScanTimeNotRecorded)
        );
    }

    /// i5: a cut list hides the times older than its oldest kept one. Here the eight kept times are all
    /// after the scan, so the journal's effective start is 12:05, after the before window's 09:30: it
    /// cannot show that window, so the reason is `before_trace_age`, not false (ADR 0086 section 5).
    #[test]
    fn i5_a_cut_journal_whose_kept_times_are_all_late_is_before_trace_age() {
        let kept = [
            "2026-01-10T12:40:00Z",
            "2026-01-10T12:35:00Z",
            "2026-01-10T12:30:00Z",
            "2026-01-10T12:25:00Z",
            "2026-01-10T12:20:00Z",
            "2026-01-10T12:15:00Z",
            "2026-01-10T12:10:00Z",
            "2026-01-10T12:05:00Z",
        ];
        assert_eq!(
            i5_with(cut(whole_journal(&kept, &[], &[], "2026-01-10T09:00:00Z"))),
            not_known(IdentityNotKnownReason::BeforeTraceAge {
                source: "usn".to_owned(),
            })
        );
    }

    /// i5: a cut list whose oldest kept time, 09:00, is before the before window and that holds no time
    /// in a window, with a journal from 08:00, is false (ADR 0086 section 5).
    #[test]
    fn i5_a_cut_journal_whose_oldest_kept_time_is_before_the_window_is_false() {
        let kept = [
            "2026-01-10T09:20:00Z",
            "2026-01-10T09:15:00Z",
            "2026-01-10T09:10:00Z",
            "2026-01-10T09:05:00Z",
            "2026-01-10T09:04:00Z",
            "2026-01-10T09:03:00Z",
            "2026-01-10T09:02:00Z",
            "2026-01-10T09:00:00Z",
        ];
        assert_eq!(
            i5_with(cut(whole_journal(&kept, &[], &[], "2026-01-10T08:00:00Z"))),
            IdentityFact::False
        );
    }

    /// i5: in SS mode a candidate that names no identity fact is not named, so none of its journal times
    /// appears in the serialised view. Its one journal time is outside every window, so I5 is false
    /// (ADR 0086 section 5 and decision 6).
    #[test]
    fn i5_in_ss_mode_a_candidate_not_named_shows_no_journal_time() {
        let time = "2026-01-10T08:17:23Z";
        let mut records = base_records();
        records.push(journaled(
            r"C:\Tools\x.sys",
            whole_journal(&[time], &[], &[], "2026-01-10T07:00:00Z"),
        ));
        let report = report_of(records);

        let self_mode = game_windows(&report, Mode::SelfCheck);
        let self_text = serde_json::to_string(&self_mode)
            .unwrap_or_else(|error| panic!("the Self view serialises: {error}"));
        assert!(self_text.contains(time), "the time shows in Self mode");
        let ss = game_windows(&report, Mode::Ss);

        assert!(
            ss.candidates
                .iter()
                .all(|candidate| !candidate.name.eq_ignore_ascii_case("x.sys"))
        );
        let text = serde_json::to_string(&ss)
            .unwrap_or_else(|error| panic!("the SS view serialises: {error}"));
        assert!(!text.contains(time), "{text}");
    }

    /// i5: `FileDetails` carries the three lists, newest first as the observation holds them, and
    /// `journal_more` (ADR 0086 section 5).
    #[test]
    fn i5_file_details_carry_the_journal_lists_and_more() {
        let mut records = base_records();
        records.push(journaled(
            r"C:\Tools\x.sys",
            vec![
                ("journal_match", "matched".into()),
                (
                    "journal_deleted",
                    times_json(&["2026-01-10T10:15:00Z", "2026-01-10T10:05:00Z"]),
                ),
                (
                    "journal_renamed_from",
                    times_json(&["2026-01-10T09:45:00Z"]),
                ),
                ("journal_renamed_to", times_json(&["2026-01-10T10:45:00Z"])),
                ("journal_more", true.into()),
                ("journal_from", "2026-01-10T09:00:00Z".into()),
            ],
        ));

        let windows = game_windows(&report_of(records), Mode::SelfCheck);

        let file = shown(&windows, "x.sys")
            .file
            .clone()
            .unwrap_or_else(|| panic!("no file details"));
        assert_eq!(
            file.journal_deleted,
            Some(vec![
                "2026-01-10T10:15:00Z".to_owned(),
                "2026-01-10T10:05:00Z".to_owned(),
            ])
        );
        assert_eq!(
            file.journal_renamed_from,
            Some(vec!["2026-01-10T09:45:00Z".to_owned()])
        );
        assert_eq!(
            file.journal_renamed_to,
            Some(vec!["2026-01-10T10:45:00Z".to_owned()])
        );
        assert_eq!(file.journal_more, Some(true));
    }

    /// i5: a `recorded_files` observation with no journal fields leaves the journal details as they
    /// are: none (ADR 0086 section 5).
    #[test]
    fn i5_file_details_without_journal_fields_hold_none() {
        let mut records = base_records();
        records.push(bam(
            "Plain.exe",
            r"C:\Tools\Plain.exe",
            "2026-01-10T10:15:00Z",
        ));
        records.push(journaled(r"C:\Tools\Plain.exe", vec![]));

        let windows = game_windows(&report_of(records), Mode::SelfCheck);

        let file = shown(&windows, "Plain.exe")
            .file
            .clone()
            .unwrap_or_else(|| panic!("no file details"));
        assert_eq!(file.journal_deleted, None);
        assert_eq!(file.journal_renamed_from, None);
        assert_eq!(file.journal_renamed_to, None);
        assert_eq!(file.journal_more, None);
    }

    /// i5: the journal reasons serialise under their `snake_case` names, the source beside
    /// `before_trace_age` (ADR 0086 section 5).
    #[test]
    fn i5_journal_reasons_serialise_under_their_spec_names() {
        assert_eq!(
            serde_json::to_value(IdentityNotKnownReason::BeforeTraceAge {
                source: "usn".to_owned(),
            })
            .unwrap(),
            serde_json::json!({"reason": "before_trace_age", "source": "usn"})
        );
        assert_eq!(
            serde_json::to_value(IdentityNotKnownReason::JournalOtherDrive).unwrap(),
            serde_json::json!({"reason": "journal_other_drive"})
        );
    }
}
