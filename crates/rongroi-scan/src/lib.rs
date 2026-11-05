// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! Input checks and the one session's order of events for the Connect sidecar; no Windows or pipe
//! access lives here.

pub mod exit;
pub mod line;
pub mod pipe_name;
pub mod request;
pub mod session;
