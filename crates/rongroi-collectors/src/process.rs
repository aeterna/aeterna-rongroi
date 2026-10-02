// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! What is running on the machine at scan time.
//!
//! Each process is reported by name and, when each can be read, by the path of its image and the time
//! it was created (ADR 0062). Nothing is hashed and no process memory is read (ADR 0010). No rule reads this collector, so the list is
//! shown in Self mode and read by a person.
//!
//! aeterna-rongroi's own process is in this list while it scans. The engine moves that observation
//! into the report's own-traces bucket, so that it stays visible without being presented as evidence
//! about the machine.

use std::collections::BTreeMap;

use rongroi_core::model::{CollectorRun, Observation, UnmeasuredReason};
use rongroi_host::{Host, Platform, ProcessRecord, SourceError};

use crate::{Collector, Field, fivem_edition};

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
/// one process without saying anything about the rest (ADR 0010). `fivem_edition` is omitted on the
/// same terms, and on every process whose path is below neither of `FiveM`'s program folders (ADR 0062).
/// An unread creation time omits `started_at` the same way (ADR 0062). `started_at` is read for
/// ADR 0062's session statement only and is not a timeline time (owner decision 8, 2026-10-02).
const FIELDS: [Field; 4] = [
    Field::text(fivem_edition::FIELD),
    Field::text("name"),
    Field::text("path"),
    Field::timestamp("started_at").off_timeline(),
];

/// The `process` collector.
#[derive(Debug, Default, Clone, Copy)]
pub struct Process;

impl Collector for Process {
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
                discriminator_gaps: Vec::new(),
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
        // From the path this observation already carries, so it says nothing the path does not.
        if let Some(edition) = fivem_edition::of_path(path) {
            fields.insert(
                fivem_edition::FIELD.to_owned(),
                serde_json::Value::from(edition.as_str()),
            );
        }
    }
    if let Some(at) = process.started_at {
        fields.insert(
            "started_at".to_owned(),
            serde_json::Value::from(at.to_string()),
        );
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

    /// The creation time the host read reaches the observation as RFC 3339 text (ADR 0062).
    #[test]
    fn a_process_carries_the_time_it_was_created() {
        let run = Process.collect(&fixture("process-own-trace"));
        let observations = measured(&run);
        assert_eq!(
            field(&observations[1], "started_at"),
            Some("2026-09-10T18:04:12Z")
        );
    }

    /// A time that could not be read omits that one field, as an unread path does: the process is
    /// still listed with what was read, and the run has no gap (ADR 0010, ADR 0062).
    #[test]
    fn a_process_without_a_start_time_omits_only_that_field() {
        let host = FixtureHost::from_yaml_str(
            "platform: windows\nprocesses:\n  - pid: 1204\n    name: FiveM.exe\n    path: 'C:\\Users\\fixtureuser\\AppData\\Local\\FiveM\\FiveM.exe'\n",
            "inline",
        )
        .unwrap();
        let run = Process.collect(&host);
        let observations = measured(&run);
        assert_eq!(observations.len(), 1);
        assert_eq!(field(&observations[0], "name"), Some("FiveM.exe"));
        assert!(field(&observations[0], "path").is_some());
        assert_eq!(observations[0].fields.get("started_at"), None);
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

    /// The edition comes from the path the observation already carries: each of `FiveM`'s program
    /// folders gives its word, and a path below neither, or no path at all, gives none (ADR 0062).
    #[test]
    fn a_process_below_one_of_fivems_folders_says_which_edition() {
        let host = FixtureHost::from_yaml_str(
            r"
platform: windows
processes:
  - pid: 1
    name: FiveM.exe
    path: 'C:\Users\fixtureuser\AppData\Local\FiveM\FiveM.exe'
  - pid: 2
    name: FiveM_b2802_GTAProcess.exe
    path: 'C:\Users\fixtureuser\AppData\Local\FiveM\FiveM.app\data\cache\subprocess\FiveM_b2802_GTAProcess.exe'
  - pid: 3
    name: FiveM.exe
    path: 'C:\Users\fixtureuser\AppData\Local\FiveM for GTAV Enhanced\FiveM.exe'
  - pid: 4
    name: FiveM.exe
    path: 'C:\Users\fixtureuser\AppData\Local\FiveM2\FiveM.exe'
  - pid: 5
    name: FiveM.exe
",
            "inline",
        )
        .unwrap();
        let run = Process.collect(&host);
        let editions: Vec<Option<&str>> = measured(&run)
            .iter()
            .map(|observation| field(observation, "fivem_edition"))
            .collect();
        assert_eq!(
            editions,
            [Some("legacy"), Some("legacy"), Some("enhanced"), None, None]
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
