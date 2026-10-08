// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! Reads real PowerShell logs, when pointed at them, and prints **counts only** (ADR 0064). Ignored by
//! default: no log is in this repository, because a PowerShell log is a person's commands. Run on a
//! Windows PC after exporting the two logs to a folder of your own:
//!
//! ```text
//! wevtutil epl Microsoft-Windows-PowerShell/Operational <dir>\operational.evtx
//! wevtutil epl "Windows PowerShell" <dir>\classic.evtx
//! set RONGROI_PS_EVTX_DIR=<dir>
//! <test binary> --ignored --nocapture
//! ```

use rongroi_parsers::evtx::{PowerShellSource, powershell_text, records};

#[test]
#[ignore = "reads real logs from RONGROI_PS_EVTX_DIR; prints counts only"]
fn counts_from_real_powershell_logs() {
    let Some(dir) = std::env::var_os("RONGROI_PS_EVTX_DIR") else {
        return;
    };
    for name in ["operational.evtx", "classic.evtx"] {
        let path = std::path::Path::new(&dir).join(name);
        let Ok(bytes) = std::fs::read(&path) else {
            println!("{name}: not readable");
            continue;
        };
        let started = std::time::Instant::now();
        let parsed = powershell_text(&bytes).expect("an exported log parses");
        let seconds = started.elapsed().as_secs_f64();
        let identity = records(&bytes).expect("an exported log parses");
        let blocks = parsed
            .entries
            .iter()
            .filter(|e| e.source == PowerShellSource::ScriptBlock)
            .count();
        let starts = parsed.entries.len() - blocks;
        let incomplete = parsed.entries.iter().filter(|e| !e.complete).count();
        let with = |f: fn(&rongroi_parsers::powershell_text::Kinds) -> bool| {
            parsed
                .entries
                .iter()
                .filter(|e| f(&e.classification.kinds))
                .count()
        };
        println!(
            "{name}: records={} examined={} rejected={} blocks={blocks} starts={starts} incomplete={incomplete} \
             any={} download_then_execute={} remote_download={} native_interop={} encoded={} decoded={} \
             bypass={} hidden={} defender_tamper={} trace_cleanup={} hosts={} seconds={seconds:.2}",
            identity.records.len(),
            parsed.examined,
            parsed.rejected.len(),
            with(rongroi_parsers::powershell_text::Kinds::any),
            with(|k| k.download_then_execute),
            with(|k| k.remote_download),
            with(|k| k.native_interop),
            with(|k| k.encoded_command),
            with(|k| k.decoded),
            with(|k| k.execution_policy_bypass),
            with(|k| k.hidden_window),
            with(|k| k.defender_tamper),
            with(|k| k.trace_cleanup),
            parsed
                .entries
                .iter()
                .filter(|e| e.classification.download_host.is_some())
                .count(),
        );
    }
}
