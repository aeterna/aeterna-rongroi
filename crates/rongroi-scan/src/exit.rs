// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! How a sidecar session ended, as the exit code Connect reads.

/// The outcome of one sidecar session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitKind {
    /// The record was written to the pipe.
    Success,
    /// Nothing was written, or the write failed.
    Failed,
}

impl ExitKind {
    /// The process exit code for this outcome.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Success => 0,
            Self::Failed => 1,
        }
    }
}

impl From<ExitKind> for std::process::ExitCode {
    fn from(kind: ExitKind) -> Self {
        Self::from(kind.code())
    }
}
