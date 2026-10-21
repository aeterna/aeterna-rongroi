// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! Programs Windows recorded near a `FiveM` session (ADR 0078). A view, never evidence.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::{TraceAgeState, observations_of, scan_time, session, time_of, trace_ages};
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
    /// The candidate has no program path, so nothing can be joined (ADR 0078 section 4).
    NoPath,
    /// I3, I4 and I5 arrive with later work (ADR 0078 section 5, ADR 0079 section 5).
    Deferred,
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
    /// I3: its name contradicts what the file is (deferred to F2).
    pub i3: IdentityFact,
    /// I4: its path is under a folder the account can write (deferred to F2).
    pub i4: IdentityFact,
    /// I5: the change journal holds its rename or deletion (deferred, ADR 0079 section 5).
    pub i5: IdentityFact,
    /// R: how many sessions' windows hold one of its times.
    pub near_sessions: NearSessions,
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
/// The programs Windows recorded near a `FiveM` session (ADR 0078). With no session, every list is
/// empty and every count is zero.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GameWindows {
    /// One latest session per edition, then the earlier sessions Prefetch kept.
    pub sessions: Vec<GameSession>,
    /// Self mode's candidates; empty in SS mode, which shows their counts instead.
    pub candidates: Vec<GameCandidate>,
    /// How many candidates each window holds, in both modes.
    pub counts: WindowCounts,
}

/// The game-windows view for `mode` (ADR 0078): every candidate in Self mode, counts only in SS.
pub fn game_windows(report: &Report, mode: Mode) -> GameWindows {
    let sessions = timed_sessions(report);
    if sessions.is_empty() {
        return GameWindows::default();
    }
    let scan = scan_time(report);
    let candidates = gather(report, &sessions, scan);
    let counts = counts_of(&candidates, &sessions, scan);
    let found = sessions.len();
    let oldest = oldest_by_source(report);
    let files = RecordedFiles::of(report);
    let candidates = match mode {
        Mode::SelfCheck => {
            let mut shown: Vec<(GameCandidate, i64)> = candidates
                .into_iter()
                .map(|candidate| {
                    let earliest = candidate
                        .times
                        .iter()
                        .map(|time| time.as_second())
                        .min()
                        .unwrap_or(i64::MAX);
                    (
                        with_facts(&candidate, &sessions, scan, &oldest, found, &files),
                        earliest,
                    )
                })
                .collect();
            shown.sort_by(|(left, left_time), (right, right_time)| {
                identity_rank(right)
                    .cmp(&identity_rank(left))
                    .then_with(|| true_facts(right).cmp(&true_facts(left)))
                    .then_with(|| left_time.cmp(right_time))
            });
            shown.into_iter().map(|(candidate, _)| candidate).collect()
        }
        Mode::Ss => Vec::new(),
    };
    GameWindows {
        sessions: sessions.iter().map(game_session).collect(),
        candidates,
        counts,
    }
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
    /// I1 to I5 for `candidate`; I3, I4 and I5 wait for later work (ADR 0079 section 5).
    fn facts(&self, candidate: &Candidate) -> [IdentityFact; 5] {
        let deferred = IdentityFact::NotKnown {
            reason: IdentityNotKnownReason::Deferred,
        };
        let (i1, i2) = self.time_and_signature_facts(candidate);
        [i1, i2, deferred.clone(), deferred.clone(), deferred]
    }
    /// I1 and I2 for `candidate`, from the `recorded_files` observation of its path.
    fn time_and_signature_facts(&self, candidate: &Candidate) -> (IdentityFact, IdentityFact) {
        let Some(observation) = self.joined(candidate) else {
            let reason = if candidate.path.is_none() {
                IdentityNotKnownReason::NoPath
            } else if self.ran {
                IdentityNotKnownReason::NoObservationForPath
            } else {
                IdentityNotKnownReason::RecordedFilesNotRun
            };
            let fact = IdentityFact::NotKnown { reason };
            return (fact.clone(), fact);
        };
        match session::text(observation, "identity_read") {
            // A missing file is gone (I1) and has no embedded signature (I2).
            Some("missing") => (IdentityFact::True, IdentityFact::True),
            Some("read") => (IdentityFact::False, signature_fact(observation)),
            _ => {
                let fact = IdentityFact::NotKnown {
                    reason: IdentityNotKnownReason::NotRead,
                };
                (fact.clone(), fact)
            }
        }
    }
}
/// I2: true unless the file's embedded signature verified as `valid` (ADR 0035).
fn signature_fact(observation: &Observation) -> IdentityFact {
    match session::text(observation, "signature") {
        Some("valid") => IdentityFact::False,
        _ => IdentityFact::True,
    }
}
fn game_session(session: &TimedSession) -> GameSession {
    GameSession {
        edition: session.edition.clone(),
        start: session.start.to_string(),
        end: session.end.map(|end| end.to_string()),
        latest: session.latest,
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
/// The candidates of every record with a time in a known window (ADR 0078 section 4).
fn gather(
    report: &Report,
    sessions: &[TimedSession],
    scan: Option<jiff::Timestamp>,
) -> Vec<Candidate> {
    let mut paths: BTreeMap<String, Candidate> = BTreeMap::new();
    let mut standalone: Vec<Candidate> = Vec::new();
    let mut prefetch: Vec<Candidate> = Vec::new();
    for collector in ["prefetch", "bam", "pca", "process"] {
        for observation in observations_of(report, collector) {
            let Some(name) = session::text(observation, "name") else {
                continue;
            };
            if is_timeline_name(name) {
                continue;
            }
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
/// The names the `FiveM` timeline selectors list (ADR 0051 section 4, first row).
fn is_timeline_name(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    ["fivem.exe", "gta5.exe", "gta5_enhanced.exe", "playgtav.exe"].contains(&name.as_str())
        || (name.starts_with("fivem_b") && name.ends_with("_gtaprocess.exe"))
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
    let [i1, i2, i3, i4, i5] = files.facts(candidate);
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
        near_sessions: NearSessions { near, found },
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
/// How many of R (near at least two sessions) and I1 to I4 are true, for the view's ordering
/// (ADR 0078 section 5). I5 waits for its own ADR (ADR 0079 section 5).
fn identity_rank(candidate: &GameCandidate) -> usize {
    usize::from(candidate.near_sessions.near >= 2)
        + [&candidate.i1, &candidate.i2, &candidate.i3, &candidate.i4]
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
