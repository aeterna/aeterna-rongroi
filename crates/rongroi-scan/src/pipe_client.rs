// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! The Windows named pipe between Connect and this sidecar.

#![cfg(windows)]

use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Write};
use std::os::windows::fs::OpenOptionsExt;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::{Duration, Instant};

use rongroi_scan::line::{read_line_capped, retry_deadline};
use rongroi_scan::session::{Transport, TransportError};

/// Opens the named pipe `name`, retrying while Connect has not created it yet.
///
/// The retry window is ten seconds from the start of this call, which the sidecar makes before any
/// other work.
///
/// # Errors
///
/// [`TransportError::Io`] when the pipe cannot be opened before the retry window ends or the open
/// fails for a reason other than absence or a busy pipe.
pub fn open(name: &str) -> Result<PipeClient, TransportError> {
    let started = Instant::now();
    loop {
        match open_pipe(name) {
            Ok(file) => return Ok(PipeClient { file }),
            Err(error) if retryable(&error) => {
                let now = Instant::now();
                let Some(deadline) = retry_deadline(started, now, RETRY_BUDGET) else {
                    return Err(TransportError::Io(error));
                };
                let pause = deadline.saturating_duration_since(now).min(RETRY_INTERVAL);
                std::thread::sleep(pause);
            }
            Err(error) => return Err(TransportError::Io(error)),
        }
    }
}

/// The sidecar's end of the named pipe Connect created.
pub struct PipeClient {
    file: File,
}

impl Transport for PipeClient {
    fn read_line(&mut self, max: usize) -> Result<Vec<u8>, TransportError> {
        let mut reader = self.file.try_clone()?;
        let (answer, result) = mpsc::channel();
        // The clone keeps the pipe readable while this call waits; a reader left blocked by the
        // timeout is detached and ends with the process.
        std::thread::Builder::new()
            .name("request-line-read".to_owned())
            .spawn(move || {
                let _ = answer.send(read_line_capped(&mut reader, max));
            })?;
        match result.recv_timeout(READ_TIMEOUT) {
            Ok(line) => line,
            Err(RecvTimeoutError::Timeout) => Err(TransportError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "the request line did not arrive within 10 s",
            ))),
            Err(RecvTimeoutError::Disconnected) => Err(TransportError::Io(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "the request-line reader stopped",
            ))),
        }
    }

    fn write_all(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
        self.file.write_all(bytes)?;
        self.file.flush()?;
        // The session drops this client after the write, which closes the pipe.
        Ok(())
    }
}

/// Opens the pipe without retrying.
fn open_pipe(name: &str) -> std::io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .security_qos_flags(SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION)
        .open(name)
}

/// Whether an open failure is one worth retrying: the pipe is absent or busy.
fn retryable(error: &std::io::Error) -> bool {
    error.kind() == ErrorKind::NotFound || error.raw_os_error() == Some(ERROR_PIPE_BUSY)
}

const SECURITY_SQOS_PRESENT: u32 = 0x0010_0000;
const SECURITY_IDENTIFICATION: u32 = 0x0001_0000;
const ERROR_PIPE_BUSY: i32 = 231;
const RETRY_BUDGET: Duration = Duration::from_secs(10);
const RETRY_INTERVAL: Duration = Duration::from_millis(50);
// D5 leaves the request-line timeout length open; this slice uses ten seconds.
const READ_TIMEOUT: Duration = Duration::from_secs(10);
