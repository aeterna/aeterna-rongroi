// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! Tests for the pure line reader and the open retry deadline.

use std::io::{self, Cursor, Read};
use std::time::{Duration, Instant};

use super::*;

struct FailingReader;

impl Read for FailingReader {
    fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::from(io::ErrorKind::BrokenPipe))
    }
}

struct InterruptedOnce {
    interrupted: bool,
    input: Cursor<Vec<u8>>,
}

impl Read for InterruptedOnce {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if !self.interrupted {
            self.interrupted = true;
            return Err(io::Error::from(io::ErrorKind::Interrupted));
        }
        self.input.read(buffer)
    }
}

#[test]
fn reads_a_line_without_its_newline() {
    let mut reader = Cursor::new(b"hello\n".to_vec());
    assert_eq!(
        read_line_capped(&mut reader, 16).expect("line reads"),
        b"hello".to_vec()
    );
}

#[test]
fn keeps_a_carriage_return_before_the_newline() {
    let mut reader = Cursor::new(b"hello\r\n".to_vec());
    assert_eq!(
        read_line_capped(&mut reader, 16).expect("line reads"),
        b"hello\r".to_vec()
    );
}

#[test]
fn accepts_a_line_of_exactly_the_cap() {
    let mut input = vec![b'a'; 4];
    input.push(b'\n');
    let mut reader = Cursor::new(input);
    assert_eq!(
        read_line_capped(&mut reader, 4).expect("line reads"),
        b"aaaa".to_vec()
    );
}

#[test]
fn refuses_a_line_one_byte_over_the_cap() {
    let mut input = vec![b'a'; 5];
    input.push(b'\n');
    let mut reader = Cursor::new(input);
    assert!(matches!(
        read_line_capped(&mut reader, 4),
        Err(TransportError::LineTooLong)
    ));
}

#[test]
fn refuses_an_overlong_line_that_never_ends() {
    let mut reader = Cursor::new(vec![b'a'; 5]);
    assert!(matches!(
        read_line_capped(&mut reader, 4),
        Err(TransportError::LineTooLong)
    ));
}

#[test]
fn refuses_a_line_at_the_cap_without_a_newline() {
    let mut reader = Cursor::new(vec![b'a'; 4]);
    assert!(matches!(
        read_line_capped(&mut reader, 4),
        Err(TransportError::NoNewline)
    ));
}

#[test]
fn refuses_a_reader_that_ends_before_the_newline() {
    let mut reader = Cursor::new(b"hello".to_vec());
    assert!(matches!(
        read_line_capped(&mut reader, 16),
        Err(TransportError::NoNewline)
    ));
}

#[test]
fn refuses_an_empty_reader() {
    let mut reader = Cursor::new(Vec::new());
    assert!(matches!(
        read_line_capped(&mut reader, 16),
        Err(TransportError::NoNewline)
    ));
}

#[test]
fn a_zero_cap_accepts_only_an_empty_line() {
    let mut empty = Cursor::new(b"\n".to_vec());
    assert_eq!(
        read_line_capped(&mut empty, 0).expect("empty line reads"),
        Vec::<u8>::new()
    );

    let mut non_empty = Cursor::new(b"a\n".to_vec());
    assert!(matches!(
        read_line_capped(&mut non_empty, 0),
        Err(TransportError::LineTooLong)
    ));
}

#[test]
fn stops_at_the_newline_and_leaves_the_next_line_unread() {
    let mut reader = Cursor::new(b"one\ntwo\n".to_vec());
    assert_eq!(
        read_line_capped(&mut reader, 8).expect("first line reads"),
        b"one".to_vec()
    );
    assert_eq!(
        read_line_capped(&mut reader, 8).expect("second line reads"),
        b"two".to_vec()
    );
    assert!(matches!(
        read_line_capped(&mut reader, 8),
        Err(TransportError::NoNewline)
    ));
}

#[test]
fn retries_an_interrupted_read() {
    let mut reader = InterruptedOnce {
        interrupted: false,
        input: Cursor::new(b"hello\n".to_vec()),
    };
    assert_eq!(
        read_line_capped(&mut reader, 16).expect("line reads"),
        b"hello".to_vec()
    );
}

#[test]
fn reports_a_reader_error() {
    let mut reader = FailingReader;
    let error = read_line_capped(&mut reader, 16).expect_err("read fails");
    let kind = if let TransportError::Io(error) = error {
        error.kind()
    } else {
        io::ErrorKind::Other
    };
    assert_eq!(kind, io::ErrorKind::BrokenPipe);
}

#[test]
fn a_deadline_before_the_budget_expires_is_kept() {
    let started = Instant::now();
    let budget = Duration::from_secs(10);
    let now = started + Duration::from_secs(9);
    assert_eq!(retry_deadline(started, now, budget), Some(started + budget));
}

#[test]
fn the_deadline_itself_is_not_retried() {
    let started = Instant::now();
    let budget = Duration::from_secs(10);
    assert_eq!(retry_deadline(started, started + budget, budget), None);
}

#[test]
fn a_time_after_the_deadline_is_not_retried() {
    let started = Instant::now();
    let budget = Duration::from_secs(10);
    assert_eq!(
        retry_deadline(started, started + budget + Duration::from_secs(1), budget),
        None
    );
}

#[test]
fn a_zero_budget_has_no_deadline() {
    let started = Instant::now();
    assert_eq!(retry_deadline(started, started, Duration::ZERO), None);
}
