// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! What the Windows Event Log holds, summarised.
//!
//! Windows writes one `.evtx` file per channel under `%SystemRoot%\System32\winevt\Logs`. The
//! collector lists that folder, hands each file's bytes to `rongroi_parsers::evtx`, and decodes
//! nothing itself (ADR 0018). Reading the `Security` channel needs an elevated token, so `not_admin`
//! is an expected outcome of an ordinary scan rather than a defect (ADR 0012, ADR 0024).
//!
//! No rule reads this collector (ADR 0024), so what it sees is listed in Self mode as unmatched
//! observations and counted, never listed, in SS mode (ADR 0014).
//!
//! # One observation per kind of event, never one per record
//!
//! A single log holds tens of thousands of records and a machine has hundreds of logs. One
//! observation per record would put a person's whole event log into a report nobody can read, so
//! records are counted into groups of `(log, channel, provider, event_id, level)` with a first and a
//! last time. Every field a rule could match survives that; the record ids do not, and widening this
//! to keep them is a deliberate decision for the pull request that needs them.
//!
//! # An unread log is evidence, not silence
//!
//! Three things can stop a log being read, and all three are reported as observations rather than
//! only counted in `gaps`: Windows denies it, it is larger than a host reads in one piece
//! (ADR 0019), or this collector's time budget ran out before it was reached. A person who wants the
//! Event Log unexamined does not have to defeat anything — an unreadable or slow log is enough — so
//! the one thing this collector must never do is report nothing and look like it looked.
//!
//! # The parse runs on a thread of its own
//!
//! `rongroi_parsers::evtx` reads a third-party binary-XML decoder, on files the person being checked
//! can write, and one input that made it never return has already been found and fixed
//! (`third_party/evtx/PROVENANCE.md`). "Fixed" is not "proven to terminate", and the desktop app
//! scans **before** it creates its window, so a parse that does not return is not a stalled progress
//! bar — it is an application that never appears. [`PARSE_BUDGET`] bounds the whole collection, on
//! one worker thread, and a log the budget did not reach is named in the report. See ADR 0024.

use std::collections::BTreeMap;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use rongroi_core::model::{CollectorRun, Observation, UnmeasuredReason};
use rongroi_host::{Host, Platform};
use rongroi_parsers::error::ParseError;
use rongroi_parsers::evtx::{self, EvtxFile, EvtxRecord};

use crate::Collector;
use crate::failure::{read_failure, reason_for};

/// Environment variable holding the Windows directory.
///
/// The same variable `prefetch` reads, and for the same reason: `rongroi_parsers::evtx` and ADR 0018
/// both document this artifact's location under `%SystemRoot%`, so the code can be checked against
/// the document that describes it.
pub const SYSTEM_ROOT: &str = "SystemRoot";
/// The Event Log folder, relative to `%SystemRoot%`.
pub const LOGS_RELATIVE_PATH: &str = r"System32\winevt\Logs";
/// Extension of the files Windows writes there, lower-cased for comparison.
const LOG_EXTENSION: &str = ".evtx";

/// How long the whole collection may take before it stops reading logs (ADR 0024).
///
/// A total for the run rather than a limit per file: the cost of the bound is one worker thread for
/// the collector, and a per-file limit would need a new thread for every file that overran, since a
/// parse that does not return cannot be cancelled. A log this collector did not reach inside the
/// budget is reported, by name, as a log that was not examined.
pub const PARSE_BUDGET: Duration = Duration::from_secs(30);

const ID: &str = "evtx";

/// Value of `read` for a log the budget did not reach.
const BUDGET_EXHAUSTED: &str = "budget_exhausted";
/// Value of `read` for a log this program would not parse because it had no worker thread to parse
/// it on. It never parses a log on the thread that has to return.
const PARSE_UNAVAILABLE: &str = "parse_unavailable";

/// The logs Windows writes on every machine, read before anything else.
///
/// A budget that can end a collection early makes the order part of the design rather than something
/// inherited from a directory listing, so it is chosen here and written down. These three exist on
/// every Windows installation, and the tamper signals ADR 0018 was written for — a cleared log — are
/// recorded on `Security` and on the others as ordinary events. Ordering files is not a judgement
/// about what an event *means*, which stays where ADR 0002 put it: in a rule.
const PRIMARY_LOGS: [&str; 3] = ["security.evtx", "system.evtx", "application.evtx"];

/// Every field this collector can emit.
///
/// A folder it could not list gaps all of them, and so does a log it could not read — unlike
/// `prefetch`, where one unreadable `.pf` file gaps nothing. The difference is what one file is: a
/// `.pf` file is one program's record, while an `.evtx` file is the **whole record of a channel**. A
/// rule that read an unread `Security.evtx` as "not found" would be saying the log was never
/// cleared, on evidence that was never read — which is the `pca` case (ADR 0020), not the `fivem_dir`
/// one.
const FIELDS: [&str; 18] = [
    "budget_exhausted",
    "budget_seconds",
    "channel",
    "count",
    "entries",
    "event_id",
    "examined",
    "first_seen",
    "intact",
    "last_seen",
    "level",
    "log",
    "logs",
    "path",
    "provider",
    "read",
    "refused",
    "rejected",
];

/// The `evtx` collector.
#[derive(Debug, Clone, Copy)]
pub struct Evtx {
    /// How long the whole collection may take. [`PARSE_BUDGET`] unless a test says otherwise.
    budget: Duration,
}

impl Default for Evtx {
    fn default() -> Self {
        Self {
            budget: PARSE_BUDGET,
        }
    }
}

impl Collector for Evtx {
    fn id(&self) -> &'static str {
        ID
    }

    fn fields(&self) -> &'static [&'static str] {
        &FIELDS
    }

    /// Lists `%SystemRoot%\System32\winevt\Logs` and reads every `.evtx` file in it, within
    /// [`PARSE_BUDGET`].
    fn collect(&self, host: &dyn Host) -> CollectorRun {
        if host.platform() != Platform::Windows {
            return CollectorRun::Unmeasured {
                collector: ID.to_owned(),
                reason: UnmeasuredReason::NotWindows,
            };
        }
        let Some(dir) = logs_dir(host) else {
            // Without `%SystemRoot%` there is no folder to look in, so nothing was looked at.
            return CollectorRun::Unmeasured {
                collector: ID.to_owned(),
                reason: UnmeasuredReason::ReadFailed,
            };
        };

        let names = match host.list_dir(&dir) {
            // There is no Event Log folder on this machine. Nothing was read, so nothing can be
            // said about what is or is not in a log (ADR 0024).
            Ok(None) => {
                return CollectorRun::Unmeasured {
                    collector: ID.to_owned(),
                    reason: UnmeasuredReason::SourceMissing,
                };
            }
            Ok(Some(entries)) => log_files(entries),
            Err(error) => {
                // The folder is there and Windows would not hand it over. It is emitted as an
                // observation as well as gapped, because with no rule reading this collector a
                // `gaps` entry reaches no screen, and "could not read the artifact" is the part a
                // reviewer needs.
                return CollectorRun::Measured {
                    collector: ID.to_owned(),
                    observations: vec![status(None, read_failure(&error))],
                    gaps: gaps(reason_for(host, &error)),
                };
            }
        };

        let mut collection = Collection::new(self.budget);
        collection.read_all(host, &dir, &names);
        collection.finish()
    }
}

fn gaps(reason: UnmeasuredReason) -> BTreeMap<String, UnmeasuredReason> {
    FIELDS
        .iter()
        .map(|field| ((*field).to_owned(), reason))
        .collect()
}

fn logs_dir(host: &dyn Host) -> Option<String> {
    let root = host.env_var(SYSTEM_ROOT)?;
    let root = root.trim_end_matches(['\\', '/']);
    (!root.is_empty()).then(|| format!(r"{root}\{LOGS_RELATIVE_PATH}"))
}

/// The names of the `.evtx` files directly inside the folder, in the order they are read.
///
/// The three logs of [`PRIMARY_LOGS`] first, in that order, then everything else sorted. A real
/// folder also holds files that are not `.evtx`; they are not this artifact, are not read, and are
/// not reported either, because "there is a file here this collector does not read" is not evidence
/// about anything.
fn log_files(entries: Vec<rongroi_host::DirEntryInfo>) -> Vec<String> {
    let mut names: Vec<String> = entries
        .into_iter()
        .filter(|entry| entry.is_file && entry.name.to_ascii_lowercase().ends_with(LOG_EXTENSION))
        .map(|entry| entry.name)
        .collect();
    names.sort_by_key(|name| {
        let lowered = name.to_ascii_lowercase();
        let rank = PRIMARY_LOGS
            .iter()
            .position(|primary| *primary == lowered)
            .unwrap_or(PRIMARY_LOGS.len());
        (rank, lowered)
    });
    names
}

/// One run over the folder: what was seen, what refused, and whether the budget ran out.
struct Collection {
    observations: Vec<Observation>,
    /// How many `.evtx` files the folder held. Not `examined + refused`: a log that was listed and
    /// was gone by the time it was read counts in neither.
    listed: usize,
    /// Logs that yielded records.
    examined: usize,
    /// Logs that were there and yielded nothing.
    refused: usize,
    /// The first reason a log could not be read, which is what `gaps` reports.
    first_failure: Option<UnmeasuredReason>,
    /// Whether the wall-clock budget ended the collection before every log was read.
    budget_exhausted: bool,
    budget: Duration,
}

impl Collection {
    fn new(budget: Duration) -> Self {
        Self {
            observations: Vec::new(),
            listed: 0,
            examined: 0,
            refused: 0,
            first_failure: None,
            budget_exhausted: false,
            budget,
        }
    }

    /// Reads every log, in order, until the folder or the budget runs out.
    fn read_all(&mut self, host: &dyn Host, dir: &str, names: &[String]) {
        self.listed = names.len();
        let deadline = Instant::now() + self.budget;
        let worker = if names.is_empty() {
            None
        } else {
            ParseWorker::spawn()
        };

        for name in names {
            let path = format!(r"{dir}\{name}");
            let bytes = match host.read_file(&path) {
                // Listed a moment ago and gone now: Windows rolls a log over while a scan runs, so
                // this is ordinary (ADR 0019) and is counted as neither examined nor refused.
                Ok(None) => continue,
                Ok(Some(bytes)) => bytes,
                Err(error) => {
                    // Denied, or larger than a host reads in one piece — which a `Security` log on a
                    // machine whose log size was raised can be. Both are named in the report.
                    self.refuse(name, &path, read_failure(&error), reason_for(host, &error));
                    continue;
                }
            };

            let Some(worker) = worker.as_ref() else {
                self.refuse(name, &path, PARSE_UNAVAILABLE, UnmeasuredReason::ReadFailed);
                continue;
            };
            match worker.parse(bytes, deadline.saturating_duration_since(Instant::now())) {
                Parsed::Done(Ok(file)) => {
                    self.examined += 1;
                    self.observations.push(account(name, &path, &file));
                    self.observations.extend(summaries(name, &file.records));
                }
                // The bytes arrived and are not a readable Event Log file. Each way that happens has
                // a word of its own, because they are different machines to a reviewer.
                Parsed::Done(Err(error)) => {
                    self.refuse(
                        name,
                        &path,
                        parse_failure(&error),
                        UnmeasuredReason::ReadFailed,
                    );
                }
                Parsed::OutOfBudget => {
                    self.budget_exhausted = true;
                    self.refuse(name, &path, BUDGET_EXHAUSTED, UnmeasuredReason::ReadFailed);
                }
                // The worker stopped without answering. `rongroi-parsers` promises it never panics,
                // so this is not expected to happen — and it is reported rather than folded into the
                // budget, because "the parse did not run" and "the parse ran out of time" are not
                // the same thing to a reviewer.
                Parsed::WorkerGone => {
                    self.refuse(name, &path, PARSE_UNAVAILABLE, UnmeasuredReason::ReadFailed);
                }
            }
        }
    }

    /// One log that yielded nothing, named, counted, and gapping the run.
    fn refuse(&mut self, name: &str, path: &str, read: &'static str, reason: UnmeasuredReason) {
        self.refused += 1;
        self.observations.push(log_status(name, path, read));
        self.first_failure = self.first_failure.or(Some(reason));
    }

    fn finish(mut self) -> CollectorRun {
        self.observations.push(folder(
            self.listed,
            self.examined,
            self.refused,
            self.budget_exhausted,
            self.budget,
        ));
        CollectorRun::Measured {
            collector: ID.to_owned(),
            observations: self.observations,
            gaps: self.first_failure.map_or_else(BTreeMap::new, gaps),
        }
    }
}

/// What one call to the parser produced, or why it produced nothing.
enum Parsed {
    /// The parser returned, with a file or with a reason the bytes are not one.
    Done(Result<EvtxFile, ParseError>),
    /// The budget ran out before this file was parsed.
    OutOfBudget,
    /// There is no worker thread to parse on any more.
    WorkerGone,
}

/// The thread every `.evtx` file is parsed on, so that a parse which does not return costs the
/// collection its budget rather than the whole program.
///
/// One thread for the collector, not one per file: the thread cannot be cancelled — a synchronous
/// parse has no cancellation point — so a file that overruns leaves this worker where it is and the
/// collection stops sending. The worker is then dropped without being joined. It is either finished
/// or it is spinning; if it is spinning it costs one core until the process exits, which is a cost
/// this collector cannot avoid and does not hide (ADR 0024).
struct ParseWorker {
    jobs: mpsc::Sender<Vec<u8>>,
    results: mpsc::Receiver<Result<EvtxFile, ParseError>>,
}

impl ParseWorker {
    /// `None` when the operating system would not give this program a thread.
    fn spawn() -> Option<Self> {
        let (jobs, queue) = mpsc::channel::<Vec<u8>>();
        let (answers, results) = mpsc::channel();
        std::thread::Builder::new()
            .name("evtx-parse".to_owned())
            .spawn(move || {
                // Ends when the collector drops `jobs`, which is the ordinary way this thread stops.
                for bytes in queue {
                    if answers.send(evtx::records(&bytes)).is_err() {
                        break;
                    }
                }
            })
            .ok()?;
        Some(Self { jobs, results })
    }

    /// Parses one file, waiting at most `within`.
    fn parse(&self, bytes: Vec<u8>, within: Duration) -> Parsed {
        if within.is_zero() {
            return Parsed::OutOfBudget;
        }
        if self.jobs.send(bytes).is_err() {
            return Parsed::WorkerGone;
        }
        match self.results.recv_timeout(within) {
            Ok(parsed) => Parsed::Done(parsed),
            Err(mpsc::RecvTimeoutError::Timeout) => Parsed::OutOfBudget,
            Err(mpsc::RecvTimeoutError::Disconnected) => Parsed::WorkerGone,
        }
    }
}

/// One kind of event in one log: how many there were, and the first and last time one was written.
///
/// `(channel, provider, event_id, level)` is the whole of what `rongroi_parsers::evtx::EvtxRecord`
/// carries apart from the record id and the time, so nothing a rule could match is lost by counting
/// records into these groups. A field the record did not carry is absent rather than defaulted: a
/// damaged record with no `Channel` element forms a group of its own, which is what happened, and
/// `channel: null` would be a claim the file does not make.
fn summaries(log: &str, records: &[EvtxRecord]) -> Vec<Observation> {
    type Key = (Option<String>, Option<String>, Option<u32>, Option<u8>);

    let mut groups: BTreeMap<Key, Vec<&EvtxRecord>> = BTreeMap::new();
    for record in records {
        let key = (
            record.channel.clone(),
            record.provider.clone(),
            record.event_id,
            record.level,
        );
        groups.entry(key).or_default().push(record);
    }

    groups
        .into_iter()
        .filter_map(|((channel, provider, event_id, level), group)| {
            // A group is the records that landed in it, so it is never empty and both of these are
            // `Some`. `?` is how that is said without an `expect`, which this project denies outside
            // tests.
            let first = group.iter().map(|record| record.written).min()?;
            let last = group.iter().map(|record| record.written).max()?;

            let mut fields = BTreeMap::new();
            fields.insert("log".to_owned(), serde_json::Value::from(log));
            if let Some(channel) = channel {
                fields.insert("channel".to_owned(), serde_json::Value::from(channel));
            }
            if let Some(provider) = provider {
                fields.insert("provider".to_owned(), serde_json::Value::from(provider));
            }
            if let Some(event_id) = event_id {
                fields.insert("event_id".to_owned(), serde_json::Value::from(event_id));
            }
            if let Some(level) = level {
                fields.insert("level".to_owned(), serde_json::Value::from(level));
            }
            fields.insert("count".to_owned(), serde_json::Value::from(group.len()));
            fields.insert(
                "first_seen".to_owned(),
                serde_json::Value::from(first.to_string()),
            );
            fields.insert(
                "last_seen".to_owned(),
                serde_json::Value::from(last.to_string()),
            );
            Some(Observation {
                collector: ID.to_owned(),
                fields,
            })
        })
        .collect()
}

/// What one log held and whether all of it decoded.
///
/// `intact` is `rejected == 0` as a value of its own, the same field and the same meaning `pca` and
/// `prefetch` give it: a rule matches by exact equality and cannot say "more than none". A damaged
/// chunk costs its own records and nothing else (ADR 0018), so a log with one is still read — and a
/// log that is partly unreadable is exactly when what survives matters most.
fn account(log: &str, path: &str, file: &EvtxFile) -> Observation {
    let mut fields = BTreeMap::new();
    fields.insert("log".to_owned(), serde_json::Value::from(log));
    fields.insert("path".to_owned(), serde_json::Value::from(path));
    fields.insert(
        "entries".to_owned(),
        serde_json::Value::from(file.records.len()),
    );
    fields.insert(
        "rejected".to_owned(),
        serde_json::Value::from(file.rejected.len()),
    );
    fields.insert(
        "intact".to_owned(),
        serde_json::Value::from(file.rejected.is_empty()),
    );
    Observation {
        collector: ID.to_owned(),
        fields,
    }
}

/// What the folder held, how much of it was read, and whether the budget ended the run.
///
/// `budget_exhausted` is the fact a rule can ask for: a scan that did not finish reading the Event
/// Log is not a scan that found nothing there. `budget_seconds` is beside it so that a person
/// reading the report does not have to know this program's constants to know what the bound was.
fn folder(
    logs: usize,
    examined: usize,
    refused: usize,
    budget_exhausted: bool,
    budget: Duration,
) -> Observation {
    let mut fields = BTreeMap::new();
    fields.insert("logs".to_owned(), serde_json::Value::from(logs));
    fields.insert("examined".to_owned(), serde_json::Value::from(examined));
    fields.insert("refused".to_owned(), serde_json::Value::from(refused));
    fields.insert(
        "budget_exhausted".to_owned(),
        serde_json::Value::from(budget_exhausted),
    );
    fields.insert(
        "budget_seconds".to_owned(),
        serde_json::Value::from(budget.as_secs()),
    );
    Observation {
        collector: ID.to_owned(),
        fields,
    }
}

/// One log that yielded nothing, with what stopped it.
///
/// It carries no `event_id` and no `entries`, so a rule written for a kind of event never matches one
/// of these and a rule written for this never matches a kind of event.
fn log_status(log: &str, path: &str, read: &'static str) -> Observation {
    let mut fields = BTreeMap::new();
    fields.insert("log".to_owned(), serde_json::Value::from(log));
    fields.insert("path".to_owned(), serde_json::Value::from(path));
    fields.insert("read".to_owned(), serde_json::Value::from(read));
    Observation {
        collector: ID.to_owned(),
        fields,
    }
}

/// The whole folder yielded nothing. There is no file to name, and the collector id already names
/// the folder.
fn status(log: Option<&str>, read: &'static str) -> Observation {
    let mut fields = BTreeMap::new();
    if let Some(log) = log {
        fields.insert("log".to_owned(), serde_json::Value::from(log));
    }
    fields.insert("read".to_owned(), serde_json::Value::from(read));
    Observation {
        collector: ID.to_owned(),
        fields,
    }
}

/// Value of the `read` field for a log whose bytes arrived and are not a readable Event Log file.
///
/// Finer than the one word `gaps` carries: bytes too short to hold the fixed 4 KiB header, bytes
/// whose header does not parse at all, and a header describing a file larger than the bytes supplied
/// are three different files to a reviewer, and only one of them is a truncated log.
fn parse_failure(error: &ParseError) -> &'static str {
    match error {
        ParseError::Truncated { .. } => "truncated",
        ParseError::Malformed { field, .. } => match *field {
            "signature" => "not_event_log",
            "header" => "bad_header",
            // Anything a later version of the parser adds. A word invented here for a failure this
            // collector has not seen would be a guess in evidence.
            _ => "malformed",
        },
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use rongroi_host::{FixtureHost, NonWindowsHost};

    use super::*;

    const LOGS_DIR: &str = r"C:\Windows\System32\winevt\Logs";

    /// The one vendored Event Log sample, as the fixture hosts here reference it.
    const LANGUAGE_PACK: &[u8] =
        include_bytes!("../../../fixtures/evtx/languagepacksetup-operational.evtx");

    /// The fixed header block and one chunk, as `rongroi_parsers::evtx`'s own tests measure them.
    const FILE_HEADER_LEN: usize = 4096;
    const CHUNK_LEN: usize = 65536;

    impl Evtx {
        /// A collector with a budget of a test's choosing.
        ///
        /// Nothing can make the parser hang on demand — the one input that did is fixed and neither
        /// reproducer is in this repository — so the budget is exercised by shrinking it rather than
        /// by slowing the parse down.
        fn with_budget(budget: Duration) -> Self {
            Self { budget }
        }
    }

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
    fn folder_of(observations: &[Observation]) -> &Observation {
        observations
            .iter()
            .find(|observation| observation.fields.contains_key("logs"))
            .expect("every run that listed the folder has a folder account")
    }

    /// The account of one log: the observation carrying how much of it decoded.
    fn account_of<'a>(observations: &'a [Observation], log: &str) -> &'a Observation {
        observations
            .iter()
            .find(|observation| {
                observation.fields.contains_key("entries") && text(observation, "log") == Some(log)
            })
            .unwrap_or_else(|| panic!("no account for {log}"))
    }

    /// The kinds of event one log held: the observations that carry a count.
    fn summaries_of<'a>(observations: &'a [Observation], log: &str) -> Vec<&'a Observation> {
        observations
            .iter()
            .filter(|observation| {
                observation.fields.contains_key("count") && text(observation, "log") == Some(log)
            })
            .collect()
    }

    /// The things that yielded nothing: the observations that carry a `read`.
    fn refusals(observations: &[Observation]) -> Vec<&Observation> {
        observations
            .iter()
            .filter(|observation| observation.fields.contains_key("read"))
            .collect()
    }

    /// A fixture host written into a temporary directory, so that a test can hand the collector
    /// bytes no file in the repository holds.
    ///
    /// `fixtures/evtx/` is the seed corpus `fuzz_evtx` reads and everything in it has to parse, so a
    /// damaged log may not be committed there; a `.evtx` file is binary, so it cannot be written
    /// inline in a `host.yaml` the way `prefetch-corrupt-files` writes its bytes. Building the
    /// directory here is what is left, and `xtask`'s own tests already build fixture trees in the
    /// temporary directory this way.
    struct TempFixture {
        dir: PathBuf,
    }

    impl TempFixture {
        fn new(name: &str, logs: &[(&str, &[u8])]) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "aeterna-rongroi-evtx-{}-{name}",
                std::process::id()
            ));
            std::fs::create_dir_all(&dir).unwrap();

            let mut yaml = String::from(
                "platform: windows\nelevated: true\nenv:\n  SystemRoot: 'C:\\Windows'\nfilesystem:\n  \
                 'C:\\Windows\\System32\\winevt\\Logs':\n",
            );
            for (log, bytes) in logs {
                std::fs::write(dir.join(log), bytes).unwrap();
                yaml.push_str("    - name: ");
                yaml.push_str(log);
                yaml.push_str("\n      from: '");
                yaml.push_str(log);
                yaml.push_str("'\n");
            }
            std::fs::write(dir.join("host.yaml"), yaml).unwrap();
            Self { dir }
        }

        fn host(&self) -> FixtureHost {
            FixtureHost::load(&self.dir).unwrap()
        }
    }

    impl Drop for TempFixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// The same chunk twice behind one header, as `rongroi_parsers::evtx`'s tests build it, with the
    /// second chunk's `ElfChnk\0` signature broken and every other byte left alone.
    fn with_damaged_second_chunk(source: &[u8]) -> Vec<u8> {
        let mut bytes = source[..FILE_HEADER_LEN + CHUNK_LEN].to_vec();
        bytes.extend_from_slice(&source[FILE_HEADER_LEN..FILE_HEADER_LEN + CHUNK_LEN]);
        let second = FILE_HEADER_LEN + CHUNK_LEN;
        bytes[second..second + 8].copy_from_slice(b"XlfChnk\0");
        bytes
    }

    #[test]
    fn the_kinds_of_event_a_log_holds_are_observed() {
        let run = Evtx::default().collect(&fixture("evtx-logs-present"));
        let (observations, gaps) = measured(&run);
        assert!(gaps.is_empty(), "{gaps:?}");

        let kinds = summaries_of(observations, "Application.evtx");
        // 4000 nine times and 4001 eight times, and the damaged trailing record — which has no
        // `Channel` element — is a group of its own rather than being counted with the rest.
        assert_eq!(kinds.len(), 3, "{kinds:?}");

        let of_event = |id: u64| {
            *kinds
                .iter()
                .find(|kind| {
                    field(kind, "event_id") == Some(&id.into())
                        && kind.fields.contains_key("channel")
                })
                .unwrap_or_else(|| panic!("no group for event id {id}"))
        };

        let first = of_event(4000);
        assert_eq!(first.collector, "evtx");
        assert_eq!(
            text(first, "channel"),
            Some("Microsoft-Windows-LanguagePackSetup/Operational")
        );
        assert_eq!(
            text(first, "provider"),
            Some("Microsoft-Windows-LanguagePackSetup")
        );
        assert_eq!(field(first, "level"), Some(&4_u64.into()));
        assert_eq!(field(first, "count"), Some(&8_u64.into()));
        assert_eq!(
            text(first, "first_seen"),
            Some("2018-07-09T20:49:14.0577461Z")
        );
        assert_eq!(
            text(first, "last_seen"),
            Some("2018-07-31T06:42:06.5129262Z")
        );
        assert_eq!(field(of_event(4001), "count"), Some(&8_u64.into()));

        // Every record is counted exactly once, in one group or another.
        let counted: u64 = kinds
            .iter()
            .filter_map(|kind| field(kind, "count").and_then(serde_json::Value::as_u64))
            .sum();
        assert_eq!(counted, 17);
    }

    /// A record the file did not spell completely is not spelled in for it: the damaged trailing
    /// record has no channel, so its group has no `channel` field at all rather than a null one.
    #[test]
    fn a_record_with_no_channel_is_its_own_group_and_claims_no_channel() {
        let run = Evtx::default().collect(&fixture("evtx-logs-present"));
        let (observations, _) = measured(&run);

        let unchannelled: Vec<&Observation> = summaries_of(observations, "Application.evtx")
            .into_iter()
            .filter(|kind| !kind.fields.contains_key("channel"))
            .collect();
        assert_eq!(unchannelled.len(), 1, "{unchannelled:?}");
        assert_eq!(field(unchannelled[0], "count"), Some(&1_u64.into()));
        assert_eq!(field(unchannelled[0], "event_id"), Some(&4000_u64.into()));
    }

    /// The two questions exact equality can ask of a log: how much of it decoded, and whether all of
    /// it did.
    #[test]
    fn each_log_says_how_much_it_held_and_whether_it_was_intact() {
        let run = Evtx::default().collect(&fixture("evtx-logs-present"));
        let (observations, _) = measured(&run);

        let account = account_of(observations, "Security.evtx");
        assert_eq!(
            text(account, "path"),
            Some(format!(r"{LOGS_DIR}\Security.evtx").as_str())
        );
        assert_eq!(field(account, "entries"), Some(&17_u64.into()));
        assert_eq!(field(account, "rejected"), Some(&0_u64.into()));
        assert_eq!(field(account, "intact"), Some(&true.into()));

        let folder = folder_of(observations);
        assert_eq!(field(folder, "logs"), Some(&2_u64.into()));
        assert_eq!(field(folder, "examined"), Some(&2_u64.into()));
        assert_eq!(field(folder, "refused"), Some(&0_u64.into()));
        assert_eq!(field(folder, "budget_exhausted"), Some(&false.into()));
        assert_eq!(field(folder, "budget_seconds"), Some(&30_u64.into()));
    }

    /// A folder holds files that are not `.evtx`. They are not this artifact, so they are not read
    /// and nothing is said about them.
    #[test]
    fn only_evtx_files_are_read() {
        let run = Evtx::default().collect(&fixture("evtx-logs-present"));
        let (observations, _) = measured(&run);
        let json = serde_json::to_string(&observations).unwrap();
        assert!(!json.contains("not-a-log.txt"), "{json}");
        assert_eq!(field(folder_of(observations), "logs"), Some(&2_u64.into()));
    }

    /// **The privacy assertion for this collector.** One Event Log record can carry a user name, a
    /// host name, an address, a SID and a full command line; the parser drops every record's payload
    /// and its `Computer` field for that reason (ADR 0018), and this collector never sees them.
    ///
    /// Unlike the Prefetch fixture — whose account name is a single letter, so asserting its absence
    /// asserts nothing — this file carries a host name, `DESKTOP-1N4R894`, that is 15 characters
    /// long and appears nowhere by accident, so asserting it is absent is a real measurement
    /// (`fixtures/evtx/PROVENANCE.md` counts every string in the file). It is not enough on its own:
    /// a payload leak would show up as element names and payload fragments rather than as that host
    /// name, so the strings this file *does* hold in its records and slack are asserted absent too.
    #[test]
    fn nothing_of_a_record_beyond_its_identity_reaches_an_observation() {
        let run = Evtx::default().collect(&fixture("evtx-logs-present"));
        let (observations, _) = measured(&run);
        let json = serde_json::to_string(&observations).unwrap();

        for leaked in [
            // The machine that wrote this log.
            "DESKTOP-1N4R894",
            // Payload, and the `System` fields this collector does not keep.
            "EventData",
            "ping-response",
            "MS-CV",
            "Context:",
            "PNG 149",
            "Computer",
            "UserID",
            "ProcessID",
            "ThreadID",
            "Correlation",
            "ActivityID",
            "Keywords",
            "Opcode",
            "EventRecordID",
            "xmlns",
            "schemas.microsoft.com",
        ] {
            assert!(
                !json.contains(leaked),
                "{leaked} reached an observation: {json}"
            );
        }
    }

    /// There is no Event Log folder here. Nothing was read, so nothing can be said about what a log
    /// does or does not hold — a rule must not read this as "the log was never cleared".
    #[test]
    fn no_logs_folder_is_unmeasured() {
        assert_eq!(
            Evtx::default().collect(&fixture("evtx-not-present")),
            CollectorRun::Unmeasured {
                collector: "evtx".to_owned(),
                reason: UnmeasuredReason::SourceMissing,
            }
        );
    }

    /// The ordinary outcome of a scan without an elevated token, which ADR 0018 says reading the
    /// `Security` channel needs. It is the signal that makes the restart-as-administrator offer
    /// worth taking (ADR 0012).
    #[test]
    fn access_denied_without_admin_rights_is_a_not_admin_gap_and_is_still_shown() {
        let run = Evtx::default().collect(&fixture("evtx-access-denied"));
        let (observations, gaps) = measured(&run);

        assert_eq!(observations.len(), 1, "{observations:?}");
        assert_eq!(text(&observations[0], "read"), Some("access_denied"));
        assert_eq!(observations[0].fields.get("path"), None);
        for name in FIELDS {
            assert_eq!(gaps.get(name), Some(&UnmeasuredReason::NotAdmin), "{name}");
        }
    }

    /// Denied while the rights were already held is a different fact: restarting would not help, and
    /// the report must not suggest it would.
    #[test]
    fn access_denied_with_admin_rights_is_an_access_denied_gap() {
        let run = Evtx::default().collect(&fixture("evtx-access-denied-elevated"));
        let (observations, gaps) = measured(&run);

        assert_eq!(text(&observations[0], "read"), Some("access_denied"));
        for name in FIELDS {
            assert_eq!(
                gaps.get(name),
                Some(&UnmeasuredReason::AccessDenied),
                "{name}"
            );
        }
    }

    /// One log is listed and has no bytes; the other is readable. The readable one is still reported,
    /// and the run **is** gapped — which is where this collector differs from `prefetch`: an `.evtx`
    /// file is the whole record of a channel, so a rule must not read an unread log as "not found".
    #[test]
    fn one_unreadable_log_is_named_and_gaps_the_run() {
        let run = Evtx::default().collect(&fixture("evtx-log-unreadable"));
        let (observations, gaps) = measured(&run);

        let refused = refusals(observations);
        assert_eq!(refused.len(), 1, "{refused:?}");
        assert_eq!(text(refused[0], "read"), Some("failed"));
        assert_eq!(text(refused[0], "log"), Some("Security.evtx"));
        assert_eq!(
            text(refused[0], "path"),
            Some(format!(r"{LOGS_DIR}\Security.evtx").as_str())
        );
        for name in FIELDS {
            assert_eq!(
                gaps.get(name),
                Some(&UnmeasuredReason::ReadFailed),
                "{name}"
            );
        }

        // The readable log was still read, and the folder says one of the two yielded nothing.
        assert!(!summaries_of(observations, "Application.evtx").is_empty());
        let folder = folder_of(observations);
        assert_eq!(field(folder, "examined"), Some(&1_u64.into()));
        assert_eq!(field(folder, "refused"), Some(&1_u64.into()));
    }

    /// Two ways a file in this folder is not a readable log, each with a word of its own: bytes too
    /// short to hold the fixed 4 KiB header, and bytes long enough whose header is not an Event
    /// Log's. Either way the file is named rather than counted away, and either way the run is
    /// gapped, because a channel's whole record is what was not read.
    #[test]
    fn a_file_that_is_not_a_readable_log_is_reported_with_what_stopped_it() {
        let run = Evtx::default().collect(&fixture("evtx-log-truncated"));
        let (observations, gaps) = measured(&run);
        assert_eq!(text(refusals(observations)[0], "read"), Some("truncated"));
        for name in FIELDS {
            assert_eq!(
                gaps.get(name),
                Some(&UnmeasuredReason::ReadFailed),
                "{name}"
            );
        }

        let mut not_a_log = LANGUAGE_PACK.to_vec();
        not_a_log[..8].copy_from_slice(b"XlfFile0");
        let fixture = TempFixture::new("not-a-log", &[("Application.evtx", &not_a_log)]);
        let run = Evtx::default().collect(&fixture.host());
        let (observations, _) = measured(&run);
        assert_eq!(
            text(refusals(observations)[0], "read"),
            Some("not_event_log")
        );
    }

    /// **Both halves of what the parser hands back.** A damaged chunk costs its own records and
    /// nothing else (ADR 0018), so the log is still read: the records of the intact chunk are
    /// reported, and the account says one chunk was rejected and the file is not intact. A damaged
    /// chunk is not a log that could not be read, so it gaps nothing.
    #[test]
    fn a_damaged_chunk_keeps_the_rest_of_the_log_and_is_accounted_for() {
        let fixture = TempFixture::new(
            "damaged",
            &[(
                "Application.evtx",
                &with_damaged_second_chunk(LANGUAGE_PACK),
            )],
        );
        let run = Evtx::default().collect(&fixture.host());
        let (observations, gaps) = measured(&run);
        assert!(gaps.is_empty(), "{gaps:?}");

        let account = account_of(observations, "Application.evtx");
        assert_eq!(field(account, "entries"), Some(&17_u64.into()));
        assert_eq!(field(account, "rejected"), Some(&1_u64.into()));
        assert_eq!(field(account, "intact"), Some(&false.into()));

        let counted: u64 = summaries_of(observations, "Application.evtx")
            .iter()
            .filter_map(|kind| field(kind, "count").and_then(serde_json::Value::as_u64))
            .sum();
        assert_eq!(counted, 17, "the intact chunk's records survive");
        assert_eq!(
            field(folder_of(observations), "examined"),
            Some(&1_u64.into())
        );
    }

    /// The defence this collector exists to have: a log that is not read inside the budget is named
    /// as one, the folder says the collection did not finish, and every field is a gap — so a rule
    /// reports `unmeasured` rather than "nothing was found in the log".
    ///
    /// A budget of zero stands in for a parse that does not return, because nothing in this
    /// repository can make the parser hang on demand: the one input that did is fixed and neither
    /// reproducer is committed (`third_party/evtx/PROVENANCE.md`). What this proves is the reporting
    /// and the bound's arithmetic, not that a hanging parse is survived — see ADR 0024.
    #[test]
    fn a_log_the_budget_did_not_reach_is_named_and_gaps_the_run() {
        let run = Evtx::with_budget(Duration::ZERO).collect(&fixture("evtx-logs-present"));
        let (observations, gaps) = measured(&run);

        let refused = refusals(observations);
        assert_eq!(refused.len(), 2, "{refused:?}");
        for observation in &refused {
            assert_eq!(text(observation, "read"), Some(BUDGET_EXHAUSTED));
        }
        // Named, so a reviewer reads *which* log went unexamined rather than only that one did.
        assert_eq!(text(refused[0], "log"), Some("Security.evtx"));
        assert_eq!(text(refused[1], "log"), Some("Application.evtx"));

        let folder = folder_of(observations);
        assert_eq!(field(folder, "budget_exhausted"), Some(&true.into()));
        assert_eq!(field(folder, "examined"), Some(&0_u64.into()));
        assert_eq!(field(folder, "refused"), Some(&2_u64.into()));
        assert_eq!(field(folder, "budget_seconds"), Some(&0_u64.into()));

        for name in FIELDS {
            assert_eq!(
                gaps.get(name),
                Some(&UnmeasuredReason::ReadFailed),
                "{name}"
            );
        }
    }

    /// The budget decides which logs go unread, so the order is chosen here rather than taken from a
    /// directory listing.
    #[test]
    fn the_logs_every_machine_has_are_read_first() {
        let entries = |names: &[&str]| {
            names
                .iter()
                .map(|name| rongroi_host::DirEntryInfo {
                    name: (*name).to_owned(),
                    is_file: true,
                })
                .collect()
        };

        assert_eq!(
            log_files(entries(&[
                "Microsoft-Windows-Kernel-Boot%4Operational.evtx",
                "Application.evtx",
                "not-a-log.txt",
                "System.evtx",
                "Security.evtx",
                "AgentHealth.evtx",
            ])),
            [
                "Security.evtx",
                "System.evtx",
                "Application.evtx",
                "AgentHealth.evtx",
                "Microsoft-Windows-Kernel-Boot%4Operational.evtx",
            ]
        );

        // A directory listing has no defined order, and the rest is sorted so that two reads of one
        // folder stay comparable.
        assert_eq!(
            log_files(entries(&["b.evtx", "A.EVTX", "c.evtx"])),
            ["A.EVTX", "b.evtx", "c.evtx"]
        );
    }

    #[test]
    fn non_windows_is_unmeasured() {
        assert_eq!(
            Evtx::default().collect(&NonWindowsHost),
            CollectorRun::Unmeasured {
                collector: "evtx".to_owned(),
                reason: UnmeasuredReason::NotWindows,
            }
        );
    }

    #[test]
    fn systemroot_unset_is_unmeasured() {
        let host = FixtureHost::from_yaml_str("platform: windows\n", "inline").unwrap();
        assert_eq!(
            Evtx::default().collect(&host),
            CollectorRun::Unmeasured {
                collector: "evtx".to_owned(),
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
        assert_eq!(
            logs_dir(&host).as_deref(),
            Some(r"D:\Windows\System32\winevt\Logs")
        );
        // And the fixture hosts describe the folder this builds on an ordinary machine.
        let ordinary = fixture("evtx-logs-present");
        assert_eq!(logs_dir(&ordinary).as_deref(), Some(LOGS_DIR));
    }

    /// Every way an Event Log file's bytes can fail to decode has a word of its own, so that a
    /// reviewer is not told "malformed" about three different files.
    #[test]
    fn every_parse_failure_has_its_own_word() {
        assert_eq!(
            parse_failure(&ParseError::Truncated {
                expected: 4096,
                found: 0
            }),
            "truncated"
        );
        for (field, expected) in [
            ("signature", "not_event_log"),
            ("header", "bad_header"),
            ("record", "malformed"),
            ("chunk", "malformed"),
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
