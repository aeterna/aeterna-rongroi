// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! Pure helpers shared by the sidecar's pipe transport: one capped line and the open retry
//! deadline.

use std::io::{ErrorKind, Read};
use std::time::{Duration, Instant};

use crate::session::TransportError;

/// Reads one line without its trailing newline, at most `max` bytes.
///
/// A carriage return before the newline is kept: [`crate::request::parse_request`] is what refuses
/// it, not this reader.
///
/// # Errors
///
/// [`TransportError::LineTooLong`] when the line reaches `max` bytes before its newline,
/// [`TransportError::NoNewline`] when the reader ends first, and [`TransportError::Io`] when the
/// reader fails.
pub fn read_line_capped<R: Read>(reader: &mut R, max: usize) -> Result<Vec<u8>, TransportError> {
    let mut line = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        match reader.read(&mut byte) {
            Ok(0) => return Err(TransportError::NoNewline),
            Ok(_) => {
                if byte[0] == b'\n' {
                    return Ok(line);
                }
                if line.len() == max {
                    return Err(TransportError::LineTooLong);
                }
                line.push(byte[0]);
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => return Err(TransportError::Io(error)),
        }
    }
}

/// Returns the instant at which the open retry window ends, or `None` once `now` is at or past it.
///
/// `started` is when the retry window began and `budget` is how long it lasts.
pub fn retry_deadline(started: Instant, now: Instant, budget: Duration) -> Option<Instant> {
    let deadline = started.checked_add(budget)?;
    (now < deadline).then_some(deadline)
}

#[cfg(test)]
mod tests;
