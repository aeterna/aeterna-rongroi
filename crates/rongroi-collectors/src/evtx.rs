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
//! Four rules read this collector — the Security log's own record that it was cleared, and the System
//! log's record that some log file was (ADR 0031); a log file marked read-only (ADR 0037); and a log
//! file that is not the file its channel is written to (ADR 0042). Everything else it sees is listed
//! in Self mode as unmatched observations and counted, never listed, in SS mode (ADR 0014).
//!
//! # One observation per kind of event, never one per record
//!
//! A single log holds tens of thousands of records and a machine has hundreds of logs. One
//! observation per record would put a person's whole event log into a report nobody can read, so
//! records are counted into groups of `(log, channel, provider, event_id, level)` with a first and a
//! last time. Every field a rule could match survives that; the record ids do not, and widening this
//! to keep them is a deliberate decision for the pull request that needs them.
//!
//! # The state of the log, beside the records in it
//!
//! One record is not enough to say anything about a log. An event that says a log was cleared is
//! ordinary on a machine whose owner ran a PC-optimiser script, and a log that is empty or whose
//! oldest surviving record is recent is equally explained by rotation at the size cap, by the channel
//! never having been enabled, and by clearing. So each log also carries **its own state** — the
//! oldest and newest surviving record, their times and their ids, and how many bytes the file was —
//! and the folder carries how many of its logs hold no records at all.
//!
//! Those are facts, not a conclusion, and one of them points the opposite way to the instinct: a
//! machine where nearly every log is empty is the shape a one-click optimiser leaves, which is
//! evidence **for** the benign explanation and must never be read as corroboration of the others
//! (ADR 0028). The engine matches by exact equality with conjunction only and deliberately gains no
//! join across observations, so the facts a rule would need to reason about a log are computed here
//! and matched flatly there.
//!
//! # What the service is told to write, beside what the folder holds
//!
//! Since ADR 0042 each log whose records name exactly one channel also carries what the Event Log
//! service states about that channel — the file it writes the channel to (`configured_path`), whether
//! that is this file (`at_configured_path`), and the largest it lets the file grow
//! (`max_size_bytes`) — and since ADR 0037 each log carries `read_only`, the one attribute bit a rule
//! reads. A log file named after its channel is the ordinary case; one whose records belong to a
//! channel the service writes somewhere else is a file that was put or left there, and ADR 0042
//! lists the ordinary ways that happens.
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
//!
//! Asking the Event Log service what file and size it sets for a channel (ADR 0042) is a call into
//! another process, and a service that never answers would stall the scan the same way. Those
//! questions run on a second worker thread under a bound of their own, [`CONFIG_BUDGET`], which is not
//! charged to [`PARSE_BUDGET`]: a service that stops answering costs the three configuration fields
//! and nothing a log's own bytes say (ADR 0042, amended 2026-09-14).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use rongroi_core::model::{CollectorRun, Observation, UnmeasuredReason};
use rongroi_host::{ChannelConfig, ChannelConfigReader, Host, Platform};
use rongroi_parsers::error::ParseError;
use rongroi_parsers::evtx::{self, EvtxFile, EvtxRecord};

use crate::failure::{read_failure, reason_for};
use crate::{Collector, Field};

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
///
/// Time spent waiting for the Event Log service is not part of it: that wait has [`CONFIG_BUDGET`].
pub const PARSE_BUDGET: Duration = Duration::from_secs(30);

/// How long one collection may spend, in total, waiting for the Event Log service to describe
/// channels (ADR 0042, amended 2026-09-14).
///
/// Its own bound rather than a share of [`PARSE_BUDGET`], so that a service that stops answering
/// costs the fields that need the service and not the logs read after it. Once it is spent, the
/// service is treated as not answering for the rest of the run: nothing more is asked, and the
/// configuration fields are gapped `budget_spent`. The time waited is added back to the parse
/// deadline, so the worst case for the whole collection is the two bounds together.
///
/// Five seconds against a measurement: on one Windows 11 machine the same two properties of all
/// 1 243 channels took 237 ms in total, the slowest single channel 4.9 ms, and a collection asks
/// about far fewer channels than that — only those a log's records name.
pub const CONFIG_BUDGET: Duration = Duration::from_secs(5);

const ID: &str = "evtx";

/// Value of `read` for the log that was being parsed when the budget ran out.
const BUDGET_EXHAUSTED: &str = "budget_exhausted";
/// Value of `read` for a log that was never opened, because the budget was already spent when its
/// turn came. Separate from [`BUDGET_EXHAUSTED`]: one log used the time and the rest were not looked
/// at, and calling the second a failed read would name a failure that did not happen (ADR 0030).
const NOT_ATTEMPTED: &str = "not_attempted";
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

/// Every reason this collector gives for not having looked (`Collector::unmeasured_reasons`).
///
/// The folder is absent, or present and holding no `.evtx` file; the budget ended the read, or was
/// already spent when a log's turn came; some logs were read and some were not; or listing was
/// denied, denied without administrator rights, or failed — which includes a log larger than a host
/// reads in one piece.
const REASONS: [UnmeasuredReason; 8] = [
    UnmeasuredReason::NotWindows,
    UnmeasuredReason::NotAdmin,
    UnmeasuredReason::NotAttempted,
    UnmeasuredReason::AccessDenied,
    UnmeasuredReason::SourceAbsent,
    UnmeasuredReason::SourceEmpty,
    UnmeasuredReason::BudgetSpent,
    UnmeasuredReason::ReadFailed,
];

/// Every field this collector can emit.
///
/// A folder it could not list gaps all of them, and so does a log it could not read — unlike
/// `prefetch`, where one unreadable `.pf` file gaps nothing. The difference is what one file is: a
/// `.pf` file is one program's record, while an `.evtx` file is the **whole record of a channel**. A
/// rule that read an unread `Security.evtx` as "not found" would be saying the log was never
/// cleared, on evidence that was never read — which is the `pca` case (ADR 0020), not the `fivem_dir`
/// one.
const FIELDS: [Field; 29] = [
    Field::boolean("at_configured_path"),
    Field::boolean("budget_exhausted"),
    Field::number("budget_seconds"),
    Field::text("channel"),
    Field::number("channels"),
    Field::text("configured_path"),
    Field::number("count"),
    Field::number("entries"),
    Field::number("event_id"),
    Field::number("examined"),
    Field::timestamp("first_seen"),
    Field::boolean("intact"),
    Field::timestamp("last_seen"),
    Field::number("level"),
    Field::text("log"),
    Field::number("logs"),
    Field::number("logs_without_records"),
    Field::number("max_size_bytes"),
    Field::number("newest_record_id"),
    Field::timestamp("newest_record_time"),
    Field::number("oldest_record_id"),
    Field::timestamp("oldest_record_time"),
    Field::text("path"),
    Field::text("provider"),
    Field::text("read"),
    Field::boolean("read_only"),
    Field::number("refused"),
    Field::number("rejected"),
    Field::number("size_bytes"),
];

/// The fields that describe what a log held, as opposed to what the folder held.
///
/// The subset `source_empty` gaps: a folder that was listed and holds no `.evtx` file was **read**,
/// so gapping `logs`, `examined`, `refused` or `budget_seconds` — which were measured — would claim
/// it had not (ADR 0030).
const RECORD_FIELDS: [&str; 19] = [
    "at_configured_path",
    "channel",
    "configured_path",
    "count",
    "entries",
    "event_id",
    "first_seen",
    "intact",
    "last_seen",
    "level",
    "max_size_bytes",
    "newest_record_id",
    "newest_record_time",
    "oldest_record_id",
    "oldest_record_time",
    "provider",
    "read_only",
    "rejected",
    "size_bytes",
];

/// The fields that carry what the Event Log service states about a log's channel (ADR 0042).
const CONFIG_FIELDS: [&str; 3] = ["at_configured_path", "configured_path", "max_size_bytes"];

/// The `evtx` collector.
#[derive(Debug, Clone, Copy)]
pub struct Evtx {
    /// How long reading and parsing logs may take. [`PARSE_BUDGET`] unless a test says otherwise.
    budget: Duration,
    /// How long waiting for the Event Log service may take. [`CONFIG_BUDGET`] unless a test says
    /// otherwise.
    config_budget: Duration,
}

impl Default for Evtx {
    fn default() -> Self {
        Self {
            budget: PARSE_BUDGET,
            config_budget: CONFIG_BUDGET,
        }
    }
}

impl Collector for Evtx {
    fn id(&self) -> &'static str {
        ID
    }

    fn fields(&self) -> &'static [Field] {
        &FIELDS
    }

    fn unmeasured_reasons(&self) -> &'static [UnmeasuredReason] {
        &REASONS
    }

    /// Lists `%SystemRoot%\System32\winevt\Logs` and reads every `.evtx` file in it, within
    /// [`PARSE_BUDGET`], asking the Event Log service about channels within [`CONFIG_BUDGET`].
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
                    reason: UnmeasuredReason::SourceAbsent,
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
                    discriminator_gaps: Vec::new(),
                };
            }
        };

        let root = host.env_var(SYSTEM_ROOT).unwrap_or_default();
        let mut collection = Collection::new(self.budget, self.config_budget);
        collection.read_all(host, &dir, &names, &root);
        collection.finish()
    }
}

fn gaps(reason: UnmeasuredReason) -> BTreeMap<String, UnmeasuredReason> {
    FIELDS
        .iter()
        .map(|field| (field.name.to_owned(), reason))
        .collect()
}

/// A gap in what one log would have said, leaving what the folder held measured.
fn record_gaps(reason: UnmeasuredReason) -> BTreeMap<String, UnmeasuredReason> {
    RECORD_FIELDS
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
    /// Of the logs that were read, how many held no record at all.
    ///
    /// Counted only among `examined`: a log that could not be read held nothing that was seen, which
    /// is not the same as holding nothing.
    without_records: usize,
    /// Every channel a surviving record named, across every log that was read.
    ///
    /// The names are kept only so that they can be counted once each; the set itself never reaches an
    /// observation. A log with no records names no channel, which is why `without_records` is beside
    /// the count and not derived from it.
    channels: BTreeSet<String>,
    /// The first reason a log could not be read, which is what `gaps` reports.
    first_failure: Option<UnmeasuredReason>,
    /// The first reason some log's read-only attribute could not be read (ADR 0037).
    attribute_failure: Option<UnmeasuredReason>,
    /// The first reason the Event Log service would not describe some channel (ADR 0042).
    config_failure: Option<UnmeasuredReason>,
    /// What the service said about each channel asked about, so each is asked once. `None` is a
    /// channel the service does not have; a channel whose question failed is not kept.
    configs: BTreeMap<String, Option<ChannelConfig>>,
    /// Who asks the service, once there has been a channel to ask about.
    asker: Asker,
    /// Whether the parse budget ended the collection before every log was read. Never set by the
    /// Event Log service's silence, which has a bound of its own.
    budget_exhausted: bool,
    budget: Duration,
    /// How long questions to the service may be waited for, in total.
    config_budget: Duration,
    /// How long questions to the service have been waited for so far. Added to the parse deadline,
    /// because none of it was spent reading or parsing a log.
    config_waited: Duration,
}

impl Collection {
    fn new(budget: Duration, config_budget: Duration) -> Self {
        Self {
            observations: Vec::new(),
            listed: 0,
            examined: 0,
            refused: 0,
            without_records: 0,
            channels: BTreeSet::new(),
            first_failure: None,
            attribute_failure: None,
            config_failure: None,
            configs: BTreeMap::new(),
            asker: Asker::NotStarted,
            budget_exhausted: false,
            budget,
            config_budget,
            config_waited: Duration::ZERO,
        }
    }

    /// Reads every log, in order, until the folder or the budget runs out.
    fn read_all(&mut self, host: &dyn Host, dir: &str, names: &[String], root: &str) {
        self.listed = names.len();
        let started = Instant::now();
        let worker = if names.is_empty() {
            None
        } else {
            ParseWorker::spawn()
        };

        for name in names {
            let path = format!(r"{dir}\{name}");
            // The budget is already gone, spent by an earlier log. This one is not opened at all,
            // and saying so is not the same statement as "the read of this log ran out of time"
            // (ADR 0030). The earlier log's parse already named the budget as the run's reason.
            if self.budget_exhausted {
                self.refuse(name, &path, NOT_ATTEMPTED, UnmeasuredReason::NotAttempted);
                continue;
            }
            // Asked before the bytes, and answered by the file system without opening the log's
            // contents, so a log that is refused below still says what its attribute is.
            let read_only = match host.is_read_only(&path) {
                Ok(read_only) => read_only,
                Err(error) => {
                    self.attribute_failure =
                        self.attribute_failure.or(Some(reason_for(host, &error)));
                    None
                }
            };
            let bytes = match host.read_file(&path) {
                // Listed a moment ago and gone now: Windows rolls a log over while a scan runs, so
                // this is ordinary (ADR 0019) and is counted as neither examined nor refused.
                Ok(None) => continue,
                Ok(Some(bytes)) => bytes,
                Err(error) => {
                    // Denied, or larger than a host reads in one piece — which a `Security` log on a
                    // machine whose log size was raised can be. Both are named in the report.
                    self.refuse(name, &path, read_failure(&error), reason_for(host, &error));
                    if let Some(read_only) = read_only
                        && let Some(status) = self.observations.last_mut()
                    {
                        status
                            .fields
                            .insert("read_only".to_owned(), serde_json::Value::from(read_only));
                    }
                    continue;
                }
            };

            let Some(worker) = worker.as_ref() else {
                self.refuse(
                    name,
                    &path,
                    PARSE_UNAVAILABLE,
                    UnmeasuredReason::NotAttempted,
                );
                continue;
            };
            // Taken before the bytes are handed to the worker, which takes ownership of them. It is
            // the length of what was read, and ADR 0019 caps that at 64 MiB — a file past the cap is
            // refused rather than truncated, so this is never a short count of a long file.
            let size_bytes = bytes.len();
            // Recomputed for every log: waiting for the service moves it later by exactly the time
            // waited, so that wait is never paid for with a log that was not read.
            let deadline = started + self.budget + self.config_waited;
            match worker.parse(bytes, deadline.saturating_duration_since(Instant::now())) {
                Parsed::Done(Ok(file)) => {
                    self.examined += 1;
                    if file.records.is_empty() {
                        self.without_records += 1;
                    }
                    // Checked before cloning: a real log holds tens of thousands of records and
                    // names one channel, so `extend` over cloned names would allocate a string per
                    // record to throw all but one of them away.
                    let mut channels_of_log: BTreeSet<&str> = BTreeSet::new();
                    for channel in file
                        .records
                        .iter()
                        .filter_map(|record| record.channel.as_deref())
                    {
                        channels_of_log.insert(channel);
                        if !self.channels.contains(channel) {
                            self.channels.insert(channel.to_owned());
                        }
                    }
                    let mut observation = account(name, &path, &file, size_bytes);
                    if let Some(read_only) = read_only {
                        observation
                            .fields
                            .insert("read_only".to_owned(), serde_json::Value::from(read_only));
                    }
                    // Only a log whose records name exactly one channel is compared: a log with no
                    // record names none, and a log naming several is not the file of any one of
                    // them. Neither is reported as anything (ADR 0042).
                    if let [channel] = channels_of_log.into_iter().collect::<Vec<_>>().as_slice()
                        && let Some(config) = self.config_of(host, channel)
                    {
                        configured(&mut observation, &config, &path, root);
                    }
                    self.observations.push(observation);
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
                    self.refuse(name, &path, BUDGET_EXHAUSTED, UnmeasuredReason::BudgetSpent);
                }
                // The worker stopped without answering. `rongroi-parsers` promises it never panics,
                // so this is not expected to happen — and it is reported rather than folded into the
                // budget, because "the parse did not run" and "the parse ran out of time" are not
                // the same thing to a reviewer.
                Parsed::WorkerGone => {
                    self.refuse(
                        name,
                        &path,
                        PARSE_UNAVAILABLE,
                        UnmeasuredReason::NotAttempted,
                    );
                }
            }
        }
    }

    /// What the service states about `channel`, asking it at most once per run and waiting no longer
    /// than what is left of the configuration budget.
    ///
    /// `None` both for a channel the service does not have and for a question that failed; the
    /// second is remembered in `config_failure`, which gaps the fields for the run.
    ///
    /// A question still unanswered when the configuration budget is spent ends the questions, not
    /// the collection: the configuration fields are gapped `budget_spent`, the worker is abandoned
    /// where it waits, no further question is sent to anyone, and every later log is still read and
    /// parsed under the parse budget, which the wait did not use (ADR 0042, amended 2026-09-14).
    fn config_of(&mut self, host: &dyn Host, channel: &str) -> Option<ChannelConfig> {
        if let Some(known) = self.configs.get(channel) {
            return known.clone();
        }
        if matches!(self.asker, Asker::NotStarted) {
            self.asker = match host.channel_config_reader() {
                Ok(reader) => {
                    if let Some(worker) = ConfigWorker::spawn(reader) {
                        Asker::Ready(worker)
                    } else {
                        self.config_failure =
                            self.config_failure.or(Some(UnmeasuredReason::NotAttempted));
                        Asker::Unavailable
                    }
                }
                Err(error) => {
                    self.config_failure = self.config_failure.or(Some(reason_for(host, &error)));
                    Asker::Unavailable
                }
            };
        }
        let asked = match &self.asker {
            Asker::Ready(worker) => {
                let asking = Instant::now();
                let asked = worker.ask(
                    channel,
                    self.config_budget.saturating_sub(self.config_waited),
                );
                self.config_waited += asking.elapsed();
                asked
            }
            // Nothing new to record: whatever made the asker unavailable is in `config_failure`.
            Asker::NotStarted | Asker::Unavailable => return None,
        };
        match asked {
            Asked::Done(Ok(config)) => {
                self.configs.insert(channel.to_owned(), config.clone());
                config
            }
            Asked::Done(Err(error)) => {
                self.config_failure = self.config_failure.or(Some(reason_for(host, &error)));
                None
            }
            // The service is treated as not answering for the rest of the run. Only the fields that
            // need it are gapped; `budget_exhausted` stays about the logs.
            Asked::OutOfBudget => {
                self.config_failure = self.config_failure.or(Some(UnmeasuredReason::BudgetSpent));
                self.asker = Asker::Unavailable;
                None
            }
            // Not expected: a reader that panicked. Reported as a question that was not asked,
            // like a parse worker that stopped, and not as the budget.
            Asked::WorkerGone => {
                self.config_failure = self.config_failure.or(Some(UnmeasuredReason::NotAttempted));
                self.asker = Asker::Unavailable;
                None
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
            self.without_records,
            self.channels.len(),
            self.budget_exhausted,
            self.budget,
        ));
        let mut gaps = match self.first_failure {
            Some(reason) => gaps(reason),
            // The folder is there and holds no `.evtx` file at all. Nothing was refused and nothing
            // was read, so no rule about what a log holds can be answered — but the folder itself
            // was listed, and what it held stays measured (ADR 0030).
            None if self.listed == 0 => record_gaps(UnmeasuredReason::SourceEmpty),
            None => BTreeMap::new(),
        };
        // One log whose attribute, or one channel whose configuration, could not be read makes "no
        // log here is read-only" or "every log is where its channel is written" a claim nobody
        // measured about it, so each gaps its own fields for the run — after the reasons above,
        // which already cover them when the run as a whole was not read.
        if let Some(reason) = self.attribute_failure {
            gaps.entry("read_only".to_owned()).or_insert(reason);
        }
        if let Some(reason) = self.config_failure {
            for field in CONFIG_FIELDS {
                gaps.entry(field.to_owned()).or_insert(reason);
            }
        }
        CollectorRun::Measured {
            collector: ID.to_owned(),
            observations: self.observations,
            gaps,
            discriminator_gaps: Vec::new(),
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

/// Whether the Event Log service can be asked about a channel in this run.
enum Asker {
    /// No log has named a single channel yet, so nobody has tried.
    NotStarted,
    Ready(ConfigWorker),
    /// The host cannot be asked, no thread was given, or the configuration budget was spent waiting.
    /// The reason is in `Collection::config_failure`.
    Unavailable,
}

/// What one question to the service produced, or why it produced nothing.
enum Asked {
    Done(Result<Option<ChannelConfig>, rongroi_host::SourceError>),
    /// The configuration budget ran out before the service answered.
    OutOfBudget,
    /// There is no worker thread to ask on any more.
    WorkerGone,
}

/// The thread every question to the Event Log service is asked on, so that a service which accepts a
/// question and never answers it costs the configuration budget rather than the whole program
/// (ADR 0042).
///
/// The same shape as [`ParseWorker`], and for the same reason: a blocked call into another process
/// has no cancellation point this program can reach. A question that overruns leaves the thread
/// blocked inside the call, and the collection stops sending. Dropping the collection drops `jobs`
/// and `results` without joining the thread. If the service ever answers, the thread finds nobody
/// listening and ends; if it never does, the thread stays blocked, not spinning, until the process
/// exits. The reader it holds opens and closes its own handle for each question, so an abandoned
/// question holds at most the handle it had open.
struct ConfigWorker {
    jobs: mpsc::Sender<String>,
    results: mpsc::Receiver<Result<Option<ChannelConfig>, rongroi_host::SourceError>>,
}

impl ConfigWorker {
    /// `None` when the operating system would not give this program a thread.
    fn spawn(reader: Box<dyn ChannelConfigReader>) -> Option<Self> {
        let (jobs, queue) = mpsc::channel::<String>();
        let (answers, results) = mpsc::channel();
        std::thread::Builder::new()
            .name("evtx-channel-config".to_owned())
            .spawn(move || {
                // Ends when the collector drops `jobs`, or when an answer finds nobody waiting.
                for channel in queue {
                    if answers.send(reader.channel_config(&channel)).is_err() {
                        break;
                    }
                }
            })
            .ok()?;
        Some(Self { jobs, results })
    }

    /// Asks about one channel, waiting at most `within`.
    fn ask(&self, channel: &str, within: Duration) -> Asked {
        if within.is_zero() {
            return Asked::OutOfBudget;
        }
        if self.jobs.send(channel.to_owned()).is_err() {
            return Asked::WorkerGone;
        }
        match self.results.recv_timeout(within) {
            Ok(answer) => Asked::Done(answer),
            Err(mpsc::RecvTimeoutError::Timeout) => Asked::OutOfBudget,
            Err(mpsc::RecvTimeoutError::Disconnected) => Asked::WorkerGone,
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

/// What one log held, whether all of it decoded, and what window of time it covers.
///
/// `intact` is `rejected == 0` as a value of its own, the same field and the same meaning `pca` and
/// `prefetch` give it: a rule matches by exact equality and cannot say "more than none". A damaged
/// chunk costs its own records and nothing else (ADR 0018), so a log with one is still read — and a
/// log that is partly unreadable is exactly when what survives matters most.
///
/// The oldest and newest surviving record are the log's own state, and they are here rather than on
/// a rule because the engine has no join across observations (ADR 0028). **None of the four says
/// anything on its own**: a recent oldest record is what rotation at the size cap, a channel enabled
/// last week, an in-place upgrade and a factory image all look like. A log that holds no record has
/// no oldest and no newest, so the four fields are **absent** there rather than zero or null — the
/// same discipline a record with no `Channel` element gets.
fn account(log: &str, path: &str, file: &EvtxFile, size_bytes: usize) -> Observation {
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
    fields.insert("size_bytes".to_owned(), serde_json::Value::from(size_bytes));
    if let Some(oldest) = extreme(&file.records, Extreme::Oldest) {
        fields.insert(
            "oldest_record_time".to_owned(),
            serde_json::Value::from(oldest.written.to_string()),
        );
        fields.insert(
            "oldest_record_id".to_owned(),
            serde_json::Value::from(oldest.record_id),
        );
    }
    if let Some(newest) = extreme(&file.records, Extreme::Newest) {
        fields.insert(
            "newest_record_time".to_owned(),
            serde_json::Value::from(newest.written.to_string()),
        );
        fields.insert(
            "newest_record_id".to_owned(),
            serde_json::Value::from(newest.record_id),
        );
    }
    Observation {
        collector: ID.to_owned(),
        fields,
    }
}

/// Adds what the service states about the log's one channel to its account (ADR 0042).
///
/// `configured_path` is the service's own spelling, normally beginning `%SystemRoot%`, so that a
/// reader sees what the configuration says rather than this program's rewriting of it.
/// `at_configured_path` compares that path — with `%SystemRoot%` and `%windir%` replaced by the
/// Windows directory this collector listed — to the path of the file that was read, ignoring ASCII
/// case as Windows does. A configured path holding any other variable is not compared, and the field
/// is left out rather than guessed.
fn configured(observation: &mut Observation, config: &ChannelConfig, path: &str, root: &str) {
    observation.fields.insert(
        "configured_path".to_owned(),
        serde_json::Value::from(config.log_file_path.as_str()),
    );
    observation.fields.insert(
        "max_size_bytes".to_owned(),
        serde_json::Value::from(config.max_size_bytes),
    );
    if let Some(expanded) = expand_windows_directory(&config.log_file_path, root) {
        let same = normalise(&expanded) == normalise(path);
        observation.fields.insert(
            "at_configured_path".to_owned(),
            serde_json::Value::from(same),
        );
    }
}

/// `path` with `%SystemRoot%` and `%windir%` replaced by `root`, or `None` when it names any other
/// environment variable, is not drive-rooted once expanded, or when `root` is unknown.
///
/// A `%` is not always a variable here: Windows names a channel's file after the channel with `/`
/// written as `%4`, so `Microsoft-Windows-Kernel-Boot%4Operational.evtx` holds one. A `%` counts as the
/// start of a variable only when a name beginning with a letter or `_`, made of letters, digits and
/// `_`, runs up to the next `%`; every other `%` is kept as it is.
fn expand_windows_directory(path: &str, root: &str) -> Option<String> {
    let root = root.trim_end_matches(['\\', '/']);
    if root.is_empty() {
        return None;
    }
    let mut expanded = String::with_capacity(path.len() + root.len());
    let mut rest = path;
    while let Some(start) = rest.find('%') {
        expanded.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        let name = after.find('%').map(|end| &after[..end]);
        match name {
            Some(name)
                if name.eq_ignore_ascii_case("SystemRoot")
                    || name.eq_ignore_ascii_case("windir") =>
            {
                expanded.push_str(root);
                rest = &after[name.len() + 1..];
            }
            Some(name) if is_variable_name(name) => return None,
            _ => {
                expanded.push('%');
                rest = after;
            }
        }
    }
    expanded.push_str(rest);
    // Only a drive-rooted path is compared: anything else is not a file this collector could have
    // read, and saying it is or is not this one would be a guess.
    let bytes = expanded.as_bytes();
    let rooted = bytes.len() > 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'\\' | b'/');
    rooted.then_some(expanded)
}

/// Whether `name` has the shape of an environment variable's name rather than of a file name's `%4`.
fn is_variable_name(name: &str) -> bool {
    let mut characters = name.chars();
    characters
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || first == '_')
        && characters.all(|character| character.is_ascii_alphanumeric() || character == '_')
}

/// A Windows path in the one form two spellings of it share: ASCII lower case, `\\` separators, no
/// doubled separator.
fn normalise(path: &str) -> String {
    let mut normalised = String::with_capacity(path.len());
    for character in path.chars() {
        let character = if character == '/' { '\\' } else { character };
        if character == '\\' && normalised.ends_with('\\') {
            continue;
        }
        normalised.push(character.to_ascii_lowercase());
    }
    normalised
}

/// Which end of a log's surviving records is wanted.
#[derive(Debug, Clone, Copy)]
enum Extreme {
    /// The record written first.
    Oldest,
    /// The record written last.
    Newest,
}

/// The record at one end of what survives, by the time it was written.
///
/// Chosen by scanning rather than by taking the first or last of the file: records are stored in the
/// order Windows wrote them, but a log recovered around a damaged chunk is missing some of them and
/// an exported log is not the on-disk one, so the order is not relied on. Ties are broken by the
/// record id, so that two records written in the same 100 ns pick the same one every run.
///
/// `None` for a log with no records at all — a log that was cleared, a channel that has never
/// recorded anything, and a file that holds only its header are all this, and the difference between
/// them is not in these bytes.
fn extreme(records: &[EvtxRecord], end: Extreme) -> Option<&EvtxRecord> {
    match end {
        Extreme::Oldest => records
            .iter()
            .min_by_key(|one| (one.written, one.record_id)),
        Extreme::Newest => records
            .iter()
            .max_by_key(|one| (one.written, one.record_id)),
    }
}

/// What the folder held, how much of it was read, and whether the budget ended the run.
///
/// `budget_exhausted` is the fact a rule can ask for: a scan that did not finish reading the Event
/// Log is not a scan that found nothing there. `budget_seconds` is beside it so that a person
/// reading the report does not have to know this program's constants to know what the bound was.
///
/// `logs_without_records` and `channels` are the shape of the folder rather than of one log, and the
/// first of them **points at the benign explanation**: a stock Windows 11 install declares on the
/// order of a thousand channels, most of which have never recorded anything, and a PC-optimiser
/// script clears every one of them in a single click (ADR 0028). A machine where nearly every log is
/// empty is that, far more often than it is anything else, and the pair is reported so that a reader
/// sees it rather than reading one cleared log alone. `channels` counts the distinct channels the
/// surviving records **name**, which is not `examined - logs_without_records`: one file can hold
/// records of several channels, and two files can hold records of one.
fn folder(
    logs: usize,
    examined: usize,
    refused: usize,
    without_records: usize,
    channels: usize,
    budget_exhausted: bool,
    budget: Duration,
) -> Observation {
    let mut fields = BTreeMap::new();
    fields.insert("logs".to_owned(), serde_json::Value::from(logs));
    fields.insert("examined".to_owned(), serde_json::Value::from(examined));
    fields.insert("refused".to_owned(), serde_json::Value::from(refused));
    fields.insert(
        "logs_without_records".to_owned(),
        serde_json::Value::from(without_records),
    );
    fields.insert("channels".to_owned(), serde_json::Value::from(channels));
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

    use rongroi_host::{EventLogConfigSource, FixtureHost, NonWindowsHost};

    use super::*;

    const LOGS_DIR: &str = r"C:\Windows\System32\winevt\Logs";

    /// The one vendored Event Log sample, as the fixture hosts here reference it.
    const LANGUAGE_PACK: &[u8] =
        include_bytes!("../../../fixtures/evtx/languagepacksetup-operational.evtx");

    /// What the Event Log service states about the one channel the vendored sample's records name, as
    /// measured on a Windows 11 machine (ADR 0042), in the fixture-host form.
    const LANGUAGE_PACK_CHANNEL: &str = "event_log_channels:\n  Microsoft-Windows-LanguagePackSetup/Operational:\n    log_file_path: '%SystemRoot%\\System32\\Winevt\\Logs\\Microsoft-Windows-LanguagePackSetup%4Operational.evtx'\n    max_size_bytes: 1052672\n";

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
            Self {
                budget,
                config_budget: CONFIG_BUDGET,
            }
        }

        /// A collector with both bounds of a test's choosing.
        fn with_budgets(budget: Duration, config_budget: Duration) -> Self {
            Self {
                budget,
                config_budget,
            }
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
                yaml.push_str("'\n      read_only: false\n");
            }
            yaml.push_str(LANGUAGE_PACK_CHANNEL);
            std::fs::write(dir.join("host.yaml"), yaml).unwrap();
            Self { dir }
        }

        fn host(&self) -> FixtureHost {
            FixtureHost::load(&self.dir).unwrap()
        }

        /// Rewrites the service's description of the sample's channel into one that accepts the
        /// question and never answers it.
        fn service_never_answers(&self) {
            let yaml = std::fs::read_to_string(self.dir.join("host.yaml"))
                .unwrap()
                .replace(
                    "    log_file_path: '%SystemRoot%\\System32\\Winevt\\Logs\\Microsoft-Windows-LanguagePackSetup%4Operational.evtx'\n    max_size_bytes: 1052672\n",
                    "    never_answers: true\n",
                );
            assert!(yaml.contains("never_answers"), "{yaml}");
            std::fs::write(self.dir.join("host.yaml"), yaml).unwrap();
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

    /// **The log's own state**, which is what a rule about a cleared log has to match on instead of
    /// one record (ADR 0028). The window the surviving records cover, both record ids, and the size
    /// of the file — all four facts about the file rather than about any event in it.
    ///
    /// The oldest record here is the first the file holds and the newest is its damaged trailing
    /// one, which is why the ends are found by scanning the times rather than by taking the first and
    /// last record of the file: those two happen to agree here and would not on a log recovered
    /// around a damaged chunk.
    #[test]
    fn each_log_says_which_record_survives_at_each_end_and_how_large_the_file_was() {
        let run = Evtx::default().collect(&fixture("evtx-logs-present"));
        let (observations, _) = measured(&run);

        let account = account_of(observations, "Security.evtx");
        assert_eq!(
            text(account, "oldest_record_time"),
            Some("2018-07-09T20:49:14.0577461Z")
        );
        assert_eq!(field(account, "oldest_record_id"), Some(&1_u64.into()));
        assert_eq!(
            text(account, "newest_record_time"),
            Some("2018-08-03T06:44:06.4185334Z")
        );
        assert_eq!(field(account, "newest_record_id"), Some(&17_u64.into()));
        // The 4 KiB header and the one chunk behind it.
        assert_eq!(field(account, "size_bytes"), Some(&69632_u64.into()));
    }

    /// **The boundary this collector has to get right.** A log that holds no record has no oldest and
    /// no newest record, so those four fields are absent rather than zero — `oldest_record_id: 0`
    /// would be a record that does not exist, and a rule could match it.
    ///
    /// A cleared channel, a channel that has never recorded anything, and a file holding only its
    /// header are the same bytes. Nothing here decides between them, and the fields that survive say
    /// only what was there: no records, no rejections, and the size of the file.
    #[test]
    fn a_log_with_no_records_has_no_oldest_and_no_newest() {
        let fixture = TempFixture::new(
            "empty-log",
            &[("Application.evtx", &LANGUAGE_PACK[..FILE_HEADER_LEN])],
        );
        let run = Evtx::default().collect(&fixture.host());
        let (observations, gaps) = measured(&run);
        assert!(gaps.is_empty(), "{gaps:?}");

        let account = account_of(observations, "Application.evtx");
        assert_eq!(field(account, "entries"), Some(&0_u64.into()));
        assert_eq!(field(account, "intact"), Some(&true.into()));
        assert_eq!(field(account, "size_bytes"), Some(&4096_u64.into()));
        for absent in [
            "oldest_record_time",
            "oldest_record_id",
            "newest_record_time",
            "newest_record_id",
        ] {
            assert_eq!(field(account, absent), None, "{absent}");
        }

        // It was read, so it counts as examined — and it named no channel, which is the whole
        // reason `channels` is counted apart from the logs.
        let folder = folder_of(observations);
        assert_eq!(field(folder, "examined"), Some(&1_u64.into()));
        assert_eq!(field(folder, "logs_without_records"), Some(&1_u64.into()));
        assert_eq!(field(folder, "channels"), Some(&0_u64.into()));
    }

    /// **The shape a PC-optimiser script leaves**, counted rather than concluded from: a folder full
    /// of logs that hold nothing. One click of a popular gaming "optimiser" clears every channel on
    /// the machine, so this count is evidence for that explanation and never corroboration of
    /// anything else (ADR 0028).
    ///
    /// `channels` is not `examined - logs_without_records`: both readable logs here carry the same
    /// channel, so three logs with records in two of them name one channel between them.
    #[test]
    fn the_folder_counts_the_logs_that_hold_nothing_and_the_channels_that_do() {
        let header_only = &LANGUAGE_PACK[..FILE_HEADER_LEN];
        let fixture = TempFixture::new(
            "mostly-empty",
            &[
                ("Application.evtx", LANGUAGE_PACK),
                ("Security.evtx", LANGUAGE_PACK),
                ("System.evtx", header_only),
                ("Setup.evtx", header_only),
            ],
        );
        let run = Evtx::default().collect(&fixture.host());
        let (observations, _) = measured(&run);

        let folder = folder_of(observations);
        assert_eq!(field(folder, "logs"), Some(&4_u64.into()));
        assert_eq!(field(folder, "examined"), Some(&4_u64.into()));
        assert_eq!(field(folder, "logs_without_records"), Some(&2_u64.into()));
        assert_eq!(field(folder, "channels"), Some(&1_u64.into()));
    }

    /// A log that could not be read held nothing that was **seen**, which is not the same as holding
    /// nothing. Counting it among the logs without records would turn an unread log into evidence
    /// that the machine's logs are empty — the exact inversion ADR 0024 refuses everywhere else.
    #[test]
    fn a_log_that_could_not_be_read_is_not_counted_as_one_without_records() {
        let run = Evtx::default().collect(&fixture("evtx-log-unreadable"));
        let (observations, _) = measured(&run);

        let folder = folder_of(observations);
        assert_eq!(field(folder, "examined"), Some(&1_u64.into()));
        assert_eq!(field(folder, "refused"), Some(&1_u64.into()));
        assert_eq!(field(folder, "logs_without_records"), Some(&0_u64.into()));
        assert_eq!(field(folder, "channels"), Some(&1_u64.into()));
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
                reason: UnmeasuredReason::SourceAbsent,
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
        for field in FIELDS {
            let name = field.name;
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
        for field in FIELDS {
            let name = field.name;
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
        for field in FIELDS {
            let name = field.name;
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
        for field in FIELDS {
            let name = field.name;
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
    /// Two words, not one, and the difference is which of them is this program's fault. The first
    /// log **spent** the budget, which is a limit this program chose and discloses; every log after
    /// it was never opened, and reporting that as a failed read would name a failure that did not
    /// happen (ADR 0030). The run reports the first, because that is the one a reviewer can act on
    /// and because SS mode lists it whatever a rule declared.
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
        // Named, so a reviewer reads *which* log went unexamined rather than only that one did.
        assert_eq!(text(refused[0], "log"), Some("Security.evtx"));
        assert_eq!(text(refused[0], "read"), Some(BUDGET_EXHAUSTED));
        assert_eq!(text(refused[1], "log"), Some("Application.evtx"));
        assert_eq!(text(refused[1], "read"), Some(NOT_ATTEMPTED));

        let folder = folder_of(observations);
        assert_eq!(field(folder, "budget_exhausted"), Some(&true.into()));
        assert_eq!(field(folder, "examined"), Some(&0_u64.into()));
        assert_eq!(field(folder, "refused"), Some(&2_u64.into()));
        assert_eq!(field(folder, "budget_seconds"), Some(&0_u64.into()));

        for field in FIELDS {
            let name = field.name;
            assert_eq!(
                gaps.get(name),
                Some(&UnmeasuredReason::BudgetSpent),
                "{name}"
            );
        }
    }

    /// The folder is there and holds no `.evtx` file: a different statement from the folder not
    /// being there, which used to share one word with it. What the folder held is still measured, so
    /// a rule may still ask for it (ADR 0030).
    #[test]
    fn a_logs_folder_holding_no_log_is_source_empty_and_still_says_what_it_held() {
        let run = Evtx::default().collect(&fixture("evtx-logs-folder-empty"));
        let (observations, gaps) = measured(&run);

        let folder = folder_of(observations);
        assert_eq!(field(folder, "logs"), Some(&0_u64.into()));
        assert_eq!(field(folder, "examined"), Some(&0_u64.into()));
        assert_eq!(field(folder, "refused"), Some(&0_u64.into()));
        for name in RECORD_FIELDS {
            assert_eq!(
                gaps.get(name),
                Some(&UnmeasuredReason::SourceEmpty),
                "{name}"
            );
        }
        assert_eq!(gaps.get("logs"), None);
        assert_eq!(gaps.get("examined"), None);
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

    /// **What the service states about a log's channel, beside the log** (ADR 0042). On this host both
    /// files hold records of the `LanguagePackSetup` channel and neither is named as the service writes
    /// that channel, which is the shape `at_configured_path: false` exists to show.
    #[test]
    fn each_log_says_where_its_channel_is_written_and_whether_this_is_that_file() {
        let run = Evtx::default().collect(&fixture("evtx-logs-present"));
        let (observations, gaps) = measured(&run);
        assert!(gaps.is_empty(), "{gaps:?}");

        let account = account_of(observations, "Security.evtx");
        assert_eq!(
            text(account, "configured_path"),
            Some(
                r"%SystemRoot%\System32\Winevt\Logs\Microsoft-Windows-LanguagePackSetup%4Operational.evtx"
            )
        );
        assert_eq!(
            field(account, "max_size_bytes"),
            Some(&1_052_672_u64.into())
        );
        assert_eq!(field(account, "at_configured_path"), Some(&false.into()));
        assert_eq!(field(account, "read_only"), Some(&false.into()));
    }

    /// The same bytes under the file name the service writes their channel to: the ordinary case.
    /// The service's `%SystemRoot%` and a different capitalisation of `System32` are the same path.
    #[test]
    fn a_log_named_as_its_channel_is_written_is_at_its_configured_path() {
        let fixture = TempFixture::new(
            "at-configured-path",
            &[(
                "Microsoft-Windows-LanguagePackSetup%4Operational.evtx",
                LANGUAGE_PACK,
            )],
        );
        let run = Evtx::default().collect(&fixture.host());
        let (observations, gaps) = measured(&run);
        assert!(gaps.is_empty(), "{gaps:?}");
        let account = account_of(
            observations,
            "Microsoft-Windows-LanguagePackSetup%4Operational.evtx",
        );
        assert_eq!(field(account, "at_configured_path"), Some(&true.into()));
    }

    /// A log with no records names no channel, and a channel the service does not have has no
    /// configuration: neither is compared, neither is reported as anything, and neither is a gap.
    /// A log file can outlive the software that registered its channel.
    #[test]
    fn a_log_with_no_channel_or_an_unregistered_one_carries_no_configuration() {
        let fixture = TempFixture::new(
            "no-configuration",
            &[("Application.evtx", &LANGUAGE_PACK[..FILE_HEADER_LEN])],
        );
        let run = Evtx::default().collect(&fixture.host());
        let (observations, gaps) = measured(&run);
        assert!(gaps.is_empty(), "{gaps:?}");
        for absent in CONFIG_FIELDS {
            assert_eq!(
                field(account_of(observations, "Application.evtx"), absent),
                None
            );
        }

        let other = TempFixture::new("unregistered", &[("Application.evtx", LANGUAGE_PACK)]);
        let yaml = std::fs::read_to_string(other.dir.join("host.yaml"))
            .unwrap()
            .replace(
                "Microsoft-Windows-LanguagePackSetup/Operational",
                "Some-Other/Channel",
            );
        std::fs::write(other.dir.join("host.yaml"), yaml).unwrap();
        let run = Evtx::default().collect(&other.host());
        let (observations, gaps) = measured(&run);
        assert!(gaps.is_empty(), "{gaps:?}");
        let account = account_of(observations, "Application.evtx");
        for absent in CONFIG_FIELDS {
            assert_eq!(field(account, absent), None, "{absent}");
        }
    }

    /// A service that would not describe a channel is not a service with no such channel: the three
    /// fields are gapped with that reason, so a rule on them is unmeasured rather than not found.
    #[test]
    fn a_channel_the_service_would_not_describe_gaps_the_configuration() {
        let fixture = TempFixture::new("config-denied", &[("Application.evtx", LANGUAGE_PACK)]);
        let yaml = std::fs::read_to_string(fixture.dir.join("host.yaml")).unwrap()
            + "access_denied:\n  - 'Microsoft-Windows-LanguagePackSetup/Operational'\n";
        std::fs::write(fixture.dir.join("host.yaml"), yaml).unwrap();
        let run = Evtx::default().collect(&fixture.host());
        let (observations, gaps) = measured(&run);
        for name in CONFIG_FIELDS {
            assert_eq!(
                gaps.get(name),
                Some(&UnmeasuredReason::AccessDenied),
                "{name}"
            );
            assert_eq!(
                field(account_of(observations, "Application.evtx"), name),
                None
            );
        }
        assert_eq!(gaps.get("read_only"), None);
    }

    /// **A service that never answers costs the configuration and nothing else** (ADR 0042, amended
    /// 2026-09-14). The fixture's reader blocks forever on this channel, so the wait is exercised for
    /// real — what is shortened is the bound, not the hang.
    ///
    /// The configuration budget is set **longer** than the parse budget on purpose. If the wait were
    /// still charged to the parse budget, as it was before the amendment, the second log would be
    /// refused unopened; it is read and parsed, which is only possible because the time waited was
    /// added back to the parse deadline. The one small vendored log parses in milliseconds, far
    /// inside the half second the two of them are given.
    ///
    /// The first log's records stay measured, the three configuration fields are gapped
    /// `budget_spent` and nothing else is gapped, the second log naming the same channel does not
    /// wait again, and `budget_exhausted` stays `false` because no log went unread.
    #[test]
    fn a_service_that_never_answers_costs_the_configuration_and_not_the_logs() {
        let fixture = TempFixture::new(
            "config-never-answers",
            &[
                ("System.evtx", LANGUAGE_PACK),
                ("Application.evtx", LANGUAGE_PACK),
            ],
        );
        fixture.service_never_answers();

        let budget = Duration::from_millis(500);
        let config_budget = Duration::from_secs(1);
        let started = Instant::now();
        let run = Evtx::with_budgets(budget, config_budget).collect(&fixture.host());
        let took = started.elapsed();
        assert!(
            took >= config_budget,
            "returned before the configuration budget: {took:?}"
        );
        // One wait, not one per log: a second wait would take at least twice the bound.
        assert!(
            took < config_budget * 2,
            "the service was waited for more than once: {took:?}"
        );

        let (observations, gaps) = measured(&run);
        for log in ["System.evtx", "Application.evtx"] {
            let account = account_of(observations, log);
            assert_eq!(field(account, "entries"), Some(&17_u64.into()), "{log}");
            for name in CONFIG_FIELDS {
                assert_eq!(field(account, name), None, "{log} {name}");
            }
        }
        assert!(refusals(observations).is_empty(), "{observations:?}");

        let expected: BTreeMap<String, UnmeasuredReason> = CONFIG_FIELDS
            .iter()
            .map(|name| ((*name).to_owned(), UnmeasuredReason::BudgetSpent))
            .collect();
        assert_eq!(gaps, &expected);

        let folder = folder_of(observations);
        assert_eq!(field(folder, "budget_exhausted"), Some(&false.into()));
        assert_eq!(field(folder, "examined"), Some(&2_u64.into()));
        assert_eq!(field(folder, "refused"), Some(&0_u64.into()));
    }

    /// The parse budget still ends the collection when parsing is what uses it, whatever the
    /// service did: a zero parse budget refuses both logs exactly as it does on a host whose service
    /// answers, and the configuration is never asked about because no log was parsed.
    #[test]
    fn a_spent_parse_budget_is_still_the_runs_reason_beside_a_service_that_never_answers() {
        let fixture = TempFixture::new(
            "config-never-answers-no-parse-budget",
            &[
                ("System.evtx", LANGUAGE_PACK),
                ("Application.evtx", LANGUAGE_PACK),
            ],
        );
        fixture.service_never_answers();

        let run =
            Evtx::with_budgets(Duration::ZERO, Duration::from_secs(60)).collect(&fixture.host());
        let (observations, gaps) = measured(&run);
        let refused = refusals(observations);
        assert_eq!(text(refused[0], "read"), Some(BUDGET_EXHAUSTED));
        assert_eq!(text(refused[1], "read"), Some(NOT_ATTEMPTED));
        for field in FIELDS {
            let name = field.name;
            assert_eq!(
                gaps.get(name),
                Some(&UnmeasuredReason::BudgetSpent),
                "{name}"
            );
        }
    }

    /// The worker on its own: a question that is never answered returns when its wait does, and a
    /// wait that is already over does not send the question at all.
    #[test]
    fn a_question_to_a_reader_that_never_answers_returns_at_its_deadline() {
        let host = FixtureHost::from_yaml_str(
            "platform: windows\nevent_log_channels:\n  Hung/Channel:\n    never_answers: true\n",
            "inline",
        )
        .unwrap();
        let worker = ConfigWorker::spawn(host.channel_config_reader().unwrap()).unwrap();
        assert!(matches!(
            worker.ask("Hung/Channel", Duration::ZERO),
            Asked::OutOfBudget
        ));
        let within = Duration::from_millis(50);
        let started = Instant::now();
        assert!(matches!(
            worker.ask("Hung/Channel", within),
            Asked::OutOfBudget
        ));
        assert!(started.elapsed() >= within);
    }

    /// A fixture that never described the service, or a file's attribute, has not said "no such
    /// channel" or "not read-only". Both are gaps (ADR 0037, ADR 0042).
    #[test]
    fn a_host_that_does_not_describe_the_service_or_the_attribute_gaps_both() {
        let run = Evtx::default().collect(&fixture("evtx-log-unreadable"));
        let (_, gaps) = measured(&run);
        // This host gaps every field already, for the unreadable log; the point is that nothing
        // here reads as a measurement.
        for name in CONFIG_FIELDS.iter().chain(&["read_only"]) {
            assert!(gaps.contains_key(*name), "{name}");
        }

        let host = FixtureHost::from_yaml_str(
            "platform: windows\nelevated: true\nenv:\n  SystemRoot: 'C:\\Windows'\nfilesystem:\n  'C:\\Windows\\System32\\winevt\\Logs':\n    - name: Setup.evtx\n      read_only: true\n",
            "inline",
        )
        .unwrap();
        let run = Evtx::default().collect(&host);
        let (observations, _) = measured(&run);
        // Refused — it has no bytes — and it still says what its attribute is.
        let refused = refusals(observations);
        assert_eq!(field(refused[0], "read_only"), Some(&true.into()));
    }

    #[test]
    fn only_the_windows_directory_is_expanded_in_a_configured_path() {
        assert_eq!(
            expand_windows_directory(r"%SystemRoot%\System32\Winevt\Logs\A.evtx", r"C:\Windows\")
                .as_deref(),
            Some(r"C:\Windows\System32\Winevt\Logs\A.evtx")
        );
        assert_eq!(
            expand_windows_directory(
                r"%SystemRoot%\Logs\Microsoft-Windows-A%4Operational%4B%4C.evtx",
                r"C:\Windows"
            )
            .as_deref(),
            Some(r"C:\Windows\Logs\Microsoft-Windows-A%4Operational%4B%4C.evtx")
        );
        assert_eq!(
            expand_windows_directory(r"%WINDIR%\x.evtx", r"D:\Win").as_deref(),
            Some(r"D:\Win\x.evtx")
        );
        assert_eq!(
            expand_windows_directory(r"D:\Logs\Security.evtx", r"C:\Windows").as_deref(),
            Some(r"D:\Logs\Security.evtx")
        );
        // Any other variable, an unterminated one, or an unknown Windows directory: not compared.
        assert_eq!(
            expand_windows_directory(r"%ProgramData%\x.evtx", r"C:\Windows"),
            None
        );
        assert_eq!(
            expand_windows_directory(r"%SystemRoot\x.evtx", r"C:\Windows"),
            None
        );
        assert_eq!(expand_windows_directory(r"%SystemRoot%\x.evtx", ""), None);
        assert_eq!(
            normalise(r"C:\Windows\system32\\winevt/Logs\A.EVTX"),
            normalise(r"c:\windows\System32\Winevt\Logs\a.evtx")
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
