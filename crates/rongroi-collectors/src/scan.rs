// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! One full scan: run every collector, evaluate the bundle, freeze the report.
//! The CLI and the desktop app both call [`run`], so they cannot disagree about a result.

use rongroi_core::bundle::Bundle;
use rongroi_core::engine::{self, SelfIdentity};
use rongroi_core::model::{CollectorRun, REPORT_SCHEMA_VERSION, Report, ReportHeader};
use rongroi_core::provenance::Provenance;
use rongroi_host::Host;

/// Inputs that come from outside the scan: build provenance, the clock, and what this program is.
#[derive(Debug, Clone)]
pub struct ScanContext {
    /// Provenance of the running binary.
    pub provenance: Provenance,
    /// Scan time, UTC, RFC 3339.
    pub generated_at: String,
    /// What this program is, so that the engine can tell its own traces from evidence about the
    /// machine (ADR 0010). Computed by the caller's `main`, never read from the running process
    /// here, so that a fixture can exercise the whole path.
    pub self_identity: SelfIdentity,
}

/// Runs every collector against `host` and evaluates `bundle`.
pub fn run(host: &dyn Host, bundle: &Bundle, context: ScanContext) -> Report {
    let runs: Vec<CollectorRun> = crate::all()
        .iter()
        .map(|collector| collector.collect(host))
        .collect();
    let header = ReportHeader {
        schema_version: REPORT_SCHEMA_VERSION,
        provenance: context.provenance,
        rules_bundle: bundle.info().clone(),
        platform: host.platform().as_str().to_owned(),
        os_build: host.os_build(),
        elevated: host.is_elevated(),
        generated_at: context.generated_at,
    };
    engine::evaluate(bundle, &runs, header, &context.self_identity)
}
