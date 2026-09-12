// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! The one error type every parser in this crate returns.

/// Why an artifact could not be parsed.
///
/// Shared by every parser in this crate so that a collector handles one error type however many
/// artifacts it reads. The two variants are the two ways bytes fail: there were not enough of them,
/// or the ones present do not mean what the format says they should.
///
/// This never wraps an [`std::io::Error`]: no I/O happens in this crate, so there is no I/O to fail.
/// Reading the artifact — and deciding that a file which is absent, unreadable or on the wrong
/// Windows version is `Unmeasured` rather than an error — happens in the collector above
/// (AGENTS.md hard rule 4).
///
/// The enum is deliberately *not* `#[non_exhaustive]`. Every caller is inside this workspace, so when
/// a later parser adds a variant the compiler pointing at each `match` that must now handle it is the
/// useful outcome, not friction to be suppressed by a wildcard arm (ADR 0013).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    /// Fewer bytes than the structure needs.
    #[error("truncated: expected at least {expected} bytes, found {found}")]
    Truncated {
        /// Smallest length that could have been decoded.
        expected: usize,
        /// Length actually supplied.
        found: usize,
    },
    /// The bytes are there but do not decode: a timestamp that is not a timestamp, a record with no
    /// delimiter, text in an encoding this artifact never uses.
    #[error("malformed {field}: {detail}")]
    Malformed {
        /// Which part of the artifact — a field name, or `"encoding"` / `"line"` for a whole record.
        /// A fixed set of short identifiers, so a caller may match on it.
        field: &'static str,
        /// What was wrong with it. Never contains a path or any other content read from the machine,
        /// so an error message is always safe to show in either mode.
        detail: String,
    },
}

#[cfg(test)]
mod tests {
    use super::ParseError;

    #[test]
    fn truncated_says_what_was_expected_and_what_was_there() {
        let error = ParseError::Truncated {
            expected: 8,
            found: 7,
        };
        assert_eq!(
            error.to_string(),
            "truncated: expected at least 8 bytes, found 7"
        );
    }

    #[test]
    fn malformed_names_the_part_and_the_problem() {
        let error = ParseError::Malformed {
            field: "timestamp",
            detail: "not a number".to_owned(),
        };
        assert_eq!(error.to_string(), "malformed timestamp: not a number");
    }

    #[test]
    fn errors_can_be_cloned_and_compared_so_a_caller_can_collect_them() {
        let error = ParseError::Truncated {
            expected: 8,
            found: 0,
        };
        assert_eq!(error.clone(), error);
    }
}
