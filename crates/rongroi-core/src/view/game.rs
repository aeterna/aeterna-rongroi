// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! Programs Windows recorded near a `FiveM` session (ADR 0078). A view, never evidence.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::{observations_of, scan_time, session, time_of};
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
    /// The window is earlier than what the source still covers (ADR 0061's trace ages).
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
    let candidates = match mode {
        Mode::SelfCheck => candidates
            .into_iter()
            .map(|candidate| GameCandidate {
                name: candidate.name,
                path: candidate.path,
                t1: NOT_KNOWN,
                t2: NOT_KNOWN,
                t3: NOT_KNOWN,
                t4: NOT_KNOWN,
                near_sessions: NearSessions { near: 0, found },
            })
            .collect(),
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
            .collect();
        earlier.retain(|time| *time != start);
        earlier.sort_unstable();
        earlier.reverse();
        earlier.dedup();
        for start in earlier {
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
        // The rest between the after window and the scan: the four counts do not count the after
        // window's candidates twice.
        let scan_from = end.saturating_add(WINDOW_SECONDS);
        hits.during = at >= start && at <= end;
        hits.after = at > end && at <= scan_from;
        hits.before_scan = scan.is_some_and(|scan| at > scan_from && at <= scan.as_second());
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
    let mut names: BTreeMap<String, Candidate> = BTreeMap::new();
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
            let candidate = Candidate {
                name: name.to_owned(),
                path: session::text(observation, "path").map(str::to_owned),
                times,
            };
            if collector == "prefetch" && candidate.path.is_none() {
                prefetch.push(candidate);
            } else if let Some(path) = candidate.path.as_deref() {
                let key = path.to_ascii_lowercase();
                merge(&mut paths, key, candidate);
            } else {
                let key = candidate.name.to_ascii_lowercase();
                merge(&mut names, key, candidate);
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
        // several it stays a candidate by its name (ADR 0078 section 4).
        match (matching.next(), matching.next()) {
            (Some(key), None) => {
                if let Some(candidate) = paths.get_mut(&key) {
                    candidate.times.extend(record.times);
                }
            }
            _ => merge(&mut names, record.name.to_ascii_lowercase(), record),
        }
    }
    paths
        .into_values()
        .chain(names.into_values())
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
    map.entry(key)
        .and_modify(|held| held.times.extend(times))
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
/// The fact P1 leaves for part 2: no fact is computed yet, and no false is claimed.
const NOT_KNOWN: TimeFact = TimeFact::NotKnown {
    reason: NotKnownReason::SessionEndNotRecorded,
};
