// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! The PCI positions Windows started, one start of Windows at a time (ADR 0095 sections 1 and 2).
//!
//! One observation per position the PCI operational log lists as started in at least one start it
//! still holds: how many of those starts list it (`starts_seen`), how many starts the log holds
//! (`starts_total`), whether those two agree (`in_every_start`) and whether the newest start lists it
//! (`in_latest_start`), with the first and last time it was started, and the newest stop or removal
//! line for that position when there is one.
//!
//! The lines are read by `rongroi_parsers::evtx::pci_log_lines` from `Message` of provider
//! `Microsoft-Windows-PCI`, channel `Microsoft-Windows-PCI/Operational` and event id 1. A position is
//! the three numbers the log writes, not a device, a vendor or a serial number; the message text is
//! not kept.
//!
//! A new start begins at a root-start line whose bus was already seen in the current start. Two root
//! buses in one start therefore stay together, and a start is never inferred from a time gap. A
//! device-start line counts at the start it falls inside, wherever in that start it came. Lines
//! before the first root start belong to no start and are ignored.
//!
//! The log is read through the same file path and parse budget as `windows_start` (ADR 0071,
//! ADR 0095): denied without an elevated token is `not_admin`, no file is `source_absent`, and a
//! parse that fails or runs past the budget is `read_failed`. A damaged or unrecognised message keeps
//! the observations and gaps those four start fields, because the starts no longer form a complete
//! account.

use std::collections::{BTreeMap, BTreeSet};

use jiff::Timestamp;
use rongroi_core::model::{CollectorRun, Observation, UnmeasuredReason};
use rongroi_host::{Host, Platform};
use rongroi_parsers::evtx::{PciLineKind, PciLog, PciLogLine, pci_log_lines};
use serde_json::Value;

use crate::failure::reason_for;
use crate::{Collector, Field, evtx};

const ID: &str = "pci_start_history";

/// The PCI operational log's file name in the Event Log folder.
const PCI_LOG: &str = "Microsoft-Windows-PCI%4Operational.evtx";

const FIELDS: [Field; 9] = [
    Field::timestamp("first_started_at"),
    Field::boolean("in_every_start"),
    Field::boolean("in_latest_start"),
    Field::timestamp("last_started_at"),
    Field::text("position"),
    Field::timestamp("removal_recorded_at"),
    Field::number("starts_seen"),
    Field::number("starts_total"),
    Field::timestamp("stop_recorded_at"),
];

const REASONS: [UnmeasuredReason; 6] = [
    UnmeasuredReason::NotWindows,
    UnmeasuredReason::NotAdmin,
    UnmeasuredReason::AccessDenied,
    UnmeasuredReason::SourceAbsent,
    UnmeasuredReason::ReadFailed,
    // A path the host refused to open, off the local drives (ADR 0091).
    UnmeasuredReason::NotAttempted,
];

/// The `pci_start_history` collector.
#[derive(Debug, Default, Clone, Copy)]
pub struct PciStartHistory;

impl Collector for PciStartHistory {
    fn id(&self) -> &'static str {
        ID
    }

    fn fields(&self) -> &'static [Field] {
        &FIELDS
    }

    fn unmeasured_reasons(&self) -> &'static [UnmeasuredReason] {
        &REASONS
    }

    fn collect(&self, host: &dyn Host) -> CollectorRun {
        if host.platform() != Platform::Windows {
            return unmeasured(UnmeasuredReason::NotWindows);
        }
        let Some(root) = host
            .env_var(evtx::SYSTEM_ROOT)
            .map(|r| r.trim_end_matches(['\\', '/']).to_owned())
            .filter(|r| !r.is_empty())
        else {
            return unmeasured(UnmeasuredReason::ReadFailed);
        };
        let path = format!(r"{root}\{}\{PCI_LOG}", evtx::LOGS_RELATIVE_PATH);
        let bytes = match host.read_file(&path) {
            Ok(Some(bytes)) => bytes,
            Ok(None) => return unmeasured(UnmeasuredReason::SourceAbsent),
            Err(error) => return unmeasured(reason_for(host, &error)),
        };
        match parse_within(bytes, evtx::PARSE_BUDGET) {
            Some(Ok(log)) => measured(&log),
            Some(Err(_)) | None => unmeasured(UnmeasuredReason::ReadFailed),
        }
    }
}

/// Parses on a thread of its own and waits at most `within`, so a parse that does not return costs
/// this collector its run rather than the whole scan (ADR 0024), as `windows_start` does.
fn parse_within(
    bytes: Vec<u8>,
    within: std::time::Duration,
) -> Option<Result<PciLog, rongroi_parsers::error::ParseError>> {
    let (answer, result) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("pci-start-history-parse".to_owned())
        .spawn(move || {
            let _ = answer.send(pci_log_lines(&bytes));
        })
        .ok()?;
    result.recv_timeout(within).ok()
}

fn unmeasured(reason: UnmeasuredReason) -> CollectorRun {
    CollectorRun::Unmeasured {
        collector: ID.to_owned(),
        reason,
    }
}

/// One start of Windows the log holds.
#[derive(Debug, Default)]
struct Start {
    /// Every root bus seen since this start began.
    buses: BTreeSet<String>,
    /// The positions already counted at this start.
    started: BTreeSet<String>,
}

/// What the log said about one position across every start.
#[derive(Debug, Default, Clone, Copy)]
struct Position {
    starts_seen: u64,
    latest_start: Option<usize>,
    first: Option<Timestamp>,
    last: Option<Timestamp>,
    stop: Option<Timestamp>,
    removal: Option<Timestamp>,
}

/// Groups the log's lines into starts and emits one observation per position started at least once.
fn measured(log: &PciLog) -> CollectorRun {
    let mut gaps = BTreeMap::new();
    if !log.rejected.is_empty() || log.unrecognised > 0 {
        for field in [
            "starts_seen",
            "starts_total",
            "in_every_start",
            "in_latest_start",
        ] {
            gaps.insert(field.to_owned(), UnmeasuredReason::ReadFailed);
        }
    }
    CollectorRun::Measured {
        collector: ID.to_owned(),
        observations: group(&log.lines),
        gaps,
        discriminator_gaps: Vec::new(),
    }
}

/// The starts and positions the log's lines describe.
fn group(lines: &[PciLogLine]) -> Vec<Observation> {
    let mut starts: Vec<Start> = Vec::new();
    let mut positions: BTreeMap<String, Position> = BTreeMap::new();

    for line in lines {
        match &line.kind {
            PciLineKind::RootStart { bus } => {
                let opens_new = starts.last().is_none_or(|start| start.buses.contains(bus));
                if opens_new {
                    let mut buses = BTreeSet::new();
                    buses.insert(bus.clone());
                    starts.push(Start {
                        buses,
                        started: BTreeSet::new(),
                    });
                } else if let Some(start) = starts.last_mut() {
                    start.buses.insert(bus.clone());
                }
            }
            PciLineKind::DeviceStarted { position } => {
                let Some(index) = starts.len().checked_sub(1) else {
                    continue;
                };
                let Some(start) = starts.get_mut(index) else {
                    continue;
                };
                let state = positions.entry(position.clone()).or_default();
                state.first = Some(
                    state
                        .first
                        .map_or(line.written, |first| first.min(line.written)),
                );
                state.last = Some(
                    state
                        .last
                        .map_or(line.written, |last| last.max(line.written)),
                );
                state.latest_start = Some(index);
                if start.started.insert(position.clone()) {
                    state.starts_seen += 1;
                }
            }
            PciLineKind::DeviceStopped { position } => {
                if starts.is_empty() {
                    continue;
                }
                let state = positions.entry(position.clone()).or_default();
                state.stop = Some(
                    state
                        .stop
                        .map_or(line.written, |stop| stop.max(line.written)),
                );
            }
            PciLineKind::DeviceRemoved { position } => {
                if starts.is_empty() {
                    continue;
                }
                let state = positions.entry(position.clone()).or_default();
                state.removal = Some(
                    state
                        .removal
                        .map_or(line.written, |removal| removal.max(line.written)),
                );
            }
        }
    }

    let starts_total = u64::try_from(starts.len()).unwrap_or(u64::MAX);
    let latest = starts.len().checked_sub(1);
    positions
        .into_iter()
        .filter_map(|(position, state)| observation(position, state, starts_total, latest))
        .collect()
}

/// The one observation a position earns, or `None` when no start lists it as started.
fn observation(
    position: String,
    state: Position,
    starts_total: u64,
    latest: Option<usize>,
) -> Option<Observation> {
    if state.starts_seen == 0 {
        return None;
    }
    let first = state.first?;
    let last = state.last?;
    let mut fields = BTreeMap::new();
    fields.insert("position".to_owned(), Value::from(position));
    fields.insert("starts_seen".to_owned(), Value::from(state.starts_seen));
    fields.insert("starts_total".to_owned(), Value::from(starts_total));
    fields.insert(
        "in_every_start".to_owned(),
        Value::from(state.starts_seen == starts_total),
    );
    fields.insert(
        "in_latest_start".to_owned(),
        Value::from(latest.is_some_and(|latest| state.latest_start == Some(latest))),
    );
    fields.insert(
        "first_started_at".to_owned(),
        Value::from(first.to_string()),
    );
    fields.insert("last_started_at".to_owned(), Value::from(last.to_string()));
    if let Some(stop) = state.stop {
        fields.insert("stop_recorded_at".to_owned(), Value::from(stop.to_string()));
    }
    if let Some(removal) = state.removal {
        fields.insert(
            "removal_recorded_at".to_owned(),
            Value::from(removal.to_string()),
        );
    }
    Some(Observation {
        collector: ID.to_owned(),
        fields,
    })
}

#[cfg(test)]
mod tests {
    use jiff::Timestamp;
    use rongroi_host::{FixtureHost, NonWindowsHost};
    use rongroi_parsers::error::ParseError;
    use rongroi_parsers::evtx::RejectedRecord;

    use super::*;

    fn host(yaml: &str) -> FixtureHost {
        FixtureHost::from_yaml_str(yaml, "inline").unwrap()
    }

    fn at(second: i64) -> Timestamp {
        Timestamp::from_second(second).unwrap()
    }

    fn line(kind: PciLineKind, second: i64) -> PciLogLine {
        PciLogLine {
            written: at(second),
            kind,
        }
    }

    fn root(bus: &str, second: i64) -> PciLogLine {
        line(
            PciLineKind::RootStart {
                bus: bus.to_owned(),
            },
            second,
        )
    }

    fn started(position: &str, second: i64) -> PciLogLine {
        line(
            PciLineKind::DeviceStarted {
                position: position.to_owned(),
            },
            second,
        )
    }

    fn stopped(position: &str, second: i64) -> PciLogLine {
        line(
            PciLineKind::DeviceStopped {
                position: position.to_owned(),
            },
            second,
        )
    }

    fn removed(position: &str, second: i64) -> PciLogLine {
        line(
            PciLineKind::DeviceRemoved {
                position: position.to_owned(),
            },
            second,
        )
    }

    fn by_position(observations: &[Observation]) -> BTreeMap<String, &Observation> {
        observations
            .iter()
            .map(|observation| {
                (
                    observation.fields["position"].as_str().unwrap().to_owned(),
                    observation,
                )
            })
            .collect()
    }

    #[test]
    fn two_root_buses_in_one_start_stay_one_start_and_a_repeated_bus_opens_the_next() {
        let observations = group(&[
            root("0x0", 1),
            root("0x1", 2),
            started("0x0000.0x02.0x00", 3),
            root("0x1", 4),
            started("0x0000.0x03.0x00", 5),
        ]);
        let positions = by_position(&observations);
        assert_eq!(positions.len(), 2);
        assert_eq!(
            positions["0x0000.0x02.0x00"].fields["starts_total"],
            Value::from(2)
        );
        assert_eq!(
            positions["0x0000.0x02.0x00"].fields["starts_seen"],
            Value::from(1)
        );
        assert_eq!(
            positions["0x0000.0x02.0x00"].fields["in_latest_start"],
            Value::from(false)
        );
        assert_eq!(
            positions["0x0000.0x03.0x00"].fields["starts_total"],
            Value::from(2)
        );
        assert_eq!(
            positions["0x0000.0x03.0x00"].fields["in_latest_start"],
            Value::from(true)
        );
    }

    #[test]
    fn a_position_absent_at_the_middle_start_is_seen_at_two_of_three() {
        let observations = group(&[
            root("0x0", 1),
            started("0x0000.0x02.0x00", 2),
            started("0x0000.0x06.0x00", 3),
            root("0x0", 4),
            started("0x0000.0x06.0x00", 5),
            root("0x0", 6),
            started("0x0000.0x02.0x00", 7),
            started("0x0000.0x06.0x00", 8),
        ]);
        let positions = by_position(&observations);
        let absent = &positions["0x0000.0x02.0x00"].fields;
        assert_eq!(absent["starts_seen"], Value::from(2));
        assert_eq!(absent["starts_total"], Value::from(3));
        assert_eq!(absent["in_every_start"], Value::from(false));
        assert_eq!(absent["in_latest_start"], Value::from(true));
        let every = &positions["0x0000.0x06.0x00"].fields;
        assert_eq!(every["starts_seen"], Value::from(3));
        assert_eq!(every["in_every_start"], Value::from(true));
    }

    #[test]
    fn a_position_started_twice_in_one_start_counts_once() {
        let observations = group(&[
            root("0x0", 1),
            started("0x0000.0x02.0x00", 2),
            started("0x0000.0x02.0x00", 3),
        ]);
        assert_eq!(observations.len(), 1);
        let fields = &observations[0].fields;
        assert_eq!(fields["starts_seen"], Value::from(1));
        assert_eq!(fields["starts_total"], Value::from(1));
        assert_eq!(fields["first_started_at"], Value::from(at(2).to_string()));
        assert_eq!(fields["last_started_at"], Value::from(at(3).to_string()));
    }

    #[test]
    fn a_stop_then_a_start_in_one_start_counts_that_start_and_keeps_the_stop_time() {
        let observations = group(&[
            root("0x0", 1),
            stopped("0x0000.0x02.0x00", 2),
            started("0x0000.0x02.0x00", 3),
            removed("0x0000.0x02.0x00", 4),
        ]);
        assert_eq!(observations.len(), 1);
        let fields = &observations[0].fields;
        assert_eq!(fields["starts_seen"], Value::from(1));
        assert_eq!(fields["stop_recorded_at"], Value::from(at(2).to_string()));
        assert_eq!(
            fields["removal_recorded_at"],
            Value::from(at(4).to_string())
        );
    }

    #[test]
    fn lines_before_the_first_root_start_are_ignored() {
        let observations = group(&[
            started("0x0000.0x02.0x00", 1),
            stopped("0x0000.0x02.0x00", 2),
            removed("0x0000.0x02.0x00", 3),
            root("0x0", 4),
            started("0x0000.0x06.0x00", 5),
        ]);
        let positions = by_position(&observations);
        assert_eq!(positions.len(), 1);
        assert!(positions.contains_key("0x0000.0x06.0x00"));
        assert_eq!(
            positions["0x0000.0x06.0x00"].fields["starts_total"],
            Value::from(1)
        );
    }

    #[test]
    fn a_position_with_only_stop_or_removal_lines_is_not_emitted() {
        let observations = group(&[
            root("0x0", 1),
            stopped("0x0000.0x02.0x00", 2),
            removed("0x0000.0x03.0x00", 3),
        ]);
        assert!(observations.is_empty());
    }

    #[test]
    fn rejected_or_unrecognised_input_adds_four_gaps_and_keeps_the_observations() {
        let lines = vec![root("0x0", 1), started("0x0000.0x02.0x00", 2)];
        let rejected = vec![RejectedRecord {
            chunk_number: None,
            record_id: Some(9),
            reason: ParseError::Malformed {
                field: "record",
                detail: "a record did not parse".to_owned(),
            },
        }];
        for log in [
            PciLog {
                lines: lines.clone(),
                unrecognised: 0,
                rejected,
            },
            PciLog {
                lines,
                unrecognised: 1,
                rejected: Vec::new(),
            },
        ] {
            let CollectorRun::Measured {
                observations, gaps, ..
            } = measured(&log)
            else {
                panic!("expected a measured run");
            };
            assert_eq!(observations.len(), 1);
            assert_eq!(
                gaps.keys().map(String::as_str).collect::<Vec<_>>(),
                [
                    "in_every_start",
                    "in_latest_start",
                    "starts_seen",
                    "starts_total"
                ]
            );
            assert!(
                gaps.values()
                    .all(|reason| *reason == UnmeasuredReason::ReadFailed)
            );
        }
    }

    #[test]
    fn a_readable_log_with_no_start_is_measured_with_no_observations() {
        let run = measured(&PciLog::default());
        assert_eq!(
            run,
            CollectorRun::Measured {
                collector: ID.to_owned(),
                observations: Vec::new(),
                gaps: BTreeMap::new(),
                discriminator_gaps: Vec::new(),
            }
        );
    }

    #[test]
    fn a_log_that_is_not_there_or_not_readable_is_unmeasured() {
        let windows = "platform: windows\nenv:\n  SystemRoot: 'C:\\Windows'\n";
        assert_eq!(
            PciStartHistory.collect(&host(windows)),
            unmeasured(UnmeasuredReason::SourceAbsent)
        );
        let denied = format!(
            "{windows}elevated: false\naccess_denied: ['C:\\Windows\\System32\\winevt\\Logs\\{PCI_LOG}']\n"
        );
        assert_eq!(
            PciStartHistory.collect(&host(&denied)),
            unmeasured(UnmeasuredReason::NotAdmin)
        );
        assert_eq!(
            PciStartHistory.collect(&host("platform: windows\n")),
            unmeasured(UnmeasuredReason::ReadFailed)
        );
        assert_eq!(
            PciStartHistory.collect(&NonWindowsHost),
            unmeasured(UnmeasuredReason::NotWindows)
        );
    }
}
