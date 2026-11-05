// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! One sidecar session: read Connect's request, scan, and write the saved record back.

use rongroi_collectors::scan::ScanContext;
use rongroi_core::bundle::{Bundle, BundleError};
use rongroi_core::engine::SelfIdentity;
use rongroi_core::model::{Report, ScanTier};
use rongroi_core::provenance::Provenance;
use rongroi_core::view::{self, SavedRecordError, SsOptions};
use thiserror::Error;

use crate::exit::ExitKind;
use crate::request::{self, MAX_LINE_BYTES, RequestError};

/// Why a transport could not carry a line.
#[derive(Debug, Error)]
pub enum TransportError {
    /// The line reached `max` bytes before its newline.
    #[error("the request line is too long")]
    LineTooLong,
    /// The pipe closed before the line's newline.
    #[error("the request line ended before a newline")]
    NoNewline,
    /// The pipe itself failed.
    #[error("the transport failed")]
    Io(#[from] std::io::Error),
}

/// The one pipe between Connect and this sidecar.
pub trait Transport {
    /// Reads one line without its trailing newline, at most `max` bytes.
    ///
    /// # Errors
    ///
    /// [`TransportError`] when the line is too long, ends before a newline, or the pipe fails.
    fn read_line(&mut self, max: usize) -> Result<Vec<u8>, TransportError>;

    /// Writes all of `bytes`.
    ///
    /// # Errors
    ///
    /// [`TransportError`] when the pipe fails.
    fn write_all(&mut self, bytes: &[u8]) -> Result<(), TransportError>;
}

/// Why a session did not finish.
#[derive(Debug, Error)]
pub enum SessionError {
    /// The request line could not be read.
    #[error("the request line could not be read")]
    Read(#[source] TransportError),
    /// The line is not a request Connect may send.
    #[error("the request line was refused: {0}")]
    Request(#[from] RequestError),
    /// The rules bundle this build carries could not be loaded.
    #[error("the rules bundle could not be loaded")]
    Bundle(#[from] BundleError),
    /// The report could not be turned into a saved record.
    #[error("the saved record could not be built")]
    Record(#[from] SavedRecordError),
    /// The record could not be written.
    #[error("the saved record could not be written")]
    Write(#[source] TransportError),
}

/// Runs one sidecar session: read, scan the policy's collectors, write the record.
///
/// `scan` is the scan bound to the host this process reads:
/// [`rongroi_collectors::scan::run_selected`] over a live host in the binary, or a `FixtureHost` in
/// tests. This crate does not depend on a host implementation, so the caller supplies that binding.
///
/// `now` is the caller's clock, read before the scan and again after it, so a test can supply a
/// fixed time. A transport that returns from [`Transport::write_all`] has flushed the bytes and may
/// close the pipe; this function never writes a file.
#[must_use]
pub fn run<F, S>(transport: &mut dyn Transport, scan: S, now: F) -> ExitKind
where
    F: Fn() -> jiff::Timestamp,
    S: Fn(&Bundle, ScanContext, &[&str]) -> Report,
{
    match run_session(transport, scan, now) {
        Ok(()) => ExitKind::Success,
        Err(_) => ExitKind::Failed,
    }
}

fn run_session<F, S>(transport: &mut dyn Transport, scan: S, now: F) -> Result<(), SessionError>
where
    F: Fn() -> jiff::Timestamp,
    S: Fn(&Bundle, ScanContext, &[&str]) -> Report,
{
    let line = transport
        .read_line(MAX_LINE_BYTES)
        .map_err(SessionError::Read)?;
    let request = request::parse_request(&line)?;
    let provenance = Provenance::current();
    let self_identity = SelfIdentity {
        exe_path: std::env::current_exe()
            .ok()
            .map(|path| path.display().to_string()),
        exe_sha256: provenance.exe_sha256.clone(),
    };
    let context = ScanContext {
        provenance,
        generated_at: now().to_string(),
        self_identity,
        tier: ScanTier::Standard,
    };
    let bundle = Bundle::embedded()?;
    let report = {
        let ids: Vec<&str> = request
            .policy
            .required_collectors
            .iter()
            .map(String::as_str)
            .collect();
        scan(&bundle, context, &ids)
    };
    let times = view::SavedTimes {
        scan_finished_at: now().to_string(),
        saved_at: now().to_string(),
    };
    let record = view::saved_record(
        &report,
        SsOptions::default(),
        None,
        request.producer,
        Some(request.binding),
        Some(request.policy),
        times,
    )?;
    let mut bytes = record.to_bytes().map_err(SavedRecordError::from)?;
    bytes.push(b'\n');
    transport.write_all(&bytes).map_err(SessionError::Write)?;
    Ok(())
}

#[cfg(test)]
mod tests;
