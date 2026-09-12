// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! What is running on the machine at scan time.
//!
//! Each process is reported by name and, when it can be resolved, by the path of its image. Nothing
//! is hashed and no process memory is read (ADR 0010). No rule reads this collector, so the list is
//! shown in Self mode and read by a person.
//!
//! aeterna-rongroi's own process is in this list while it scans. The engine moves that observation
//! into the report's own-traces bucket, so that it stays visible without being presented as evidence
//! about the machine.

use std::collections::BTreeMap;

use rongroi_core::model::{CollectorRun, Observation, UnmeasuredReason};
use rongroi_host::{Host, Platform, ProcessRecord, SourceError};

use crate::Collector;

const ID: &str = "process";

/// Every reason this collector gives for not having looked (`Collector::unmeasured_reasons`).
///
/// The process list was denied or could not be read. `not_admin` is not here: this collector
/// does not split denial by elevation, because the list is readable without it.
const REASONS: [UnmeasuredReason; 3] = [
    UnmeasuredReason::NotWindows,
    UnmeasuredReason::AccessDenied,
    UnmeasuredReason::ReadFailed,
];

/// Every field this collector can emit.
///
/// The list is never a `gaps` key here: a process list that could not be read is the whole reading,
/// so it is an `Unmeasured` run rather than a gap, and an unresolved image path omits `path` on that
/// one process without saying anything about the rest (ADR 0010).
const FIELDS: [&str; 2] = ["name", "path"];

/// The `process` collector.
#[derive(Debug, Default, Clone, Copy)]
pub struct Process;

impl Collector for Process {
    fn id(&self) -> &'static str {
        ID
    }

    fn fields(&self) -> &'static [&'static str] {
        &FIELDS
    }

    fn unmeasured_reasons(&self) -> &'static [UnmeasuredReason] {
        &REASONS
    }

    fn collect(&self, host: &dyn Host) -> CollectorRun {
        if host.platform() != Platform::Windows {
            return CollectorRun::Unmeasured {
                collector: ID.to_owned(),
                reason: UnmeasuredReason::NotWindows,
            };
        }

        match host.running_processes() {
            Ok(processes) => CollectorRun::Measured {
                collector: ID.to_owned(),
                observations: processes.iter().map(observation).collect(),
                gaps: BTreeMap::new(),
            },
            // The list is the whole reading. A `Measured` run with nothing in it would say "the
            // machine was running no processes", which no machine ever is.
            Err(error) => CollectorRun::Unmeasured {
                collector: ID.to_owned(),
                reason: reason_for(&error),
            },
        }
    }
}

/// One process, in the order the host listed it.
///
/// A path that could not be resolved omits that one field. `gaps` describes the whole run, so a
/// single unresolved path must not land there; the process itself is never dropped and a path is
/// never invented (ADR 0010).
fn observation(process: &ProcessRecord) -> Observation {
    let mut fields = BTreeMap::new();
    fields.insert(
        "name".to_owned(),
        serde_json::Value::from(process.name.clone()),
    );
    if let Some(path) = process.path.as_ref().filter(|path| !path.is_empty()) {
        fields.insert("path".to_owned(), serde_json::Value::from(path.clone()));
    }
    Observation {
        collector: ID.to_owned(),
        fields,
    }
}

/// How a failed source read is reported, as `posture` and `fivem_dir` already do it: `Unsupported`,
/// `Failed` and `TooLarge` all mean the list was not read, and nothing about it may be shown as
/// "not found".
fn reason_for(error: &SourceError) -> UnmeasuredReason {
    match error {
        SourceError::AccessDenied => UnmeasuredReason::AccessDenied,
        SourceError::Unsupported(_) | SourceError::Failed(_) | SourceError::TooLarge { .. } => {
            UnmeasuredReason::ReadFailed
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use rongroi_host::{FixtureHost, NonWindowsHost};

    use super::*;

    fn fixture(name: &str) -> FixtureHost {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/hosts")
            .join(name);
        FixtureHost::load(&dir).unwrap()
    }

    fn measured(run: &CollectorRun) -> &[Observation] {
        match run {
            CollectorRun::Measured { observations, .. } => observations,
            CollectorRun::Unmeasured { .. } => panic!("expected a measured run, got {run:?}"),
        }
    }

    fn field<'a>(observation: &'a Observation, name: &str) -> Option<&'a str> {
        observation
            .fields
            .get(name)
            .and_then(serde_json::Value::as_str)
    }

    #[test]
    fn every_process_is_listed_in_host_order() {
        let run = Process.collect(&fixture("process-own-trace"));
        let observations = measured(&run);
        let names: Vec<Option<&str>> = observations
            .iter()
            .map(|observation| field(observation, "name"))
            .collect();
        assert_eq!(
            names,
            [
                Some("System"),
                Some("FiveM.exe"),
                Some("aeterna-rongroi.exe")
            ]
        );
        assert_eq!(observations[0].collector, "process");
        assert_eq!(
            field(&observations[1], "path"),
            Some(r"C:\Users\fixtureuser\AppData\Local\FiveM\FiveM.exe")
        );
    }

    /// A protected process, or one that exits between the snapshot and the query, has no path to
    /// report. Dropping it would understate what is running.
    #[test]
    fn a_process_without_a_path_keeps_its_name_and_is_still_listed() {
        let run = Process.collect(&fixture("process-own-trace"));
        let observations = measured(&run);
        let system = &observations[0];
        assert_eq!(field(system, "name"), Some("System"));
        assert_eq!(system.fields.get("path"), None);
        // One unresolved path is not a gap: `gaps` is about the whole run.
        let CollectorRun::Measured { gaps, .. } = &run else {
            panic!("expected a measured run");
        };
        assert!(gaps.is_empty(), "{gaps:?}");
    }

    #[test]
    fn non_windows_is_unmeasured() {
        assert_eq!(
            Process.collect(&NonWindowsHost),
            CollectorRun::Unmeasured {
                collector: "process".to_owned(),
                reason: UnmeasuredReason::NotWindows,
            }
        );
    }

    /// A host that cannot take the process snapshot measured nothing about what is running. An empty
    /// `Measured` run would be read as "nothing was running".
    #[test]
    fn a_snapshot_that_cannot_be_taken_is_unmeasured_read_failed() {
        let host = FixtureHost::from_yaml_str("platform: windows\n", "inline").unwrap();
        assert_eq!(
            Process.collect(&host),
            CollectorRun::Unmeasured {
                collector: "process".to_owned(),
                reason: UnmeasuredReason::ReadFailed,
            }
        );
    }

    #[test]
    fn a_refused_process_list_keeps_the_reason_windows_gave() {
        assert_eq!(
            reason_for(&SourceError::AccessDenied),
            UnmeasuredReason::AccessDenied
        );
    }
}
