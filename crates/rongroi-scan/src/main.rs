// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! Sidecar entry point; the real pipe connection arrives in a later slice.

fn main() -> std::process::ExitCode {
    std::process::ExitCode::from(1)
}
