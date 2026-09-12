// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! `aeterna-rongroi-cli`: scan this PC and print evidence. Never prints a verdict.

mod output;

use std::io::{BufRead, Write};

use anyhow::Context;
use clap::{Args, Parser, Subcommand, ValueEnum};
use rongroi_collectors::scan::{self, ScanContext};
use rongroi_core::bundle::Bundle;
use rongroi_core::model::Mode;
use rongroi_core::provenance::Provenance;
use rongroi_core::view;
use rongroi_host::Host;

use crate::output::Lang;

#[derive(Parser)]
#[command(
    name = "aeterna-rongroi-cli",
    version,
    about = "Offline PC check for FiveM communities. Shows evidence; never says a PC is clean."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Scan this PC and print the report.
    Scan(ScanArgs),
}

#[derive(Args)]
struct ScanArgs {
    /// `self`: see everything. `ss`: screenshare view — asks for consent, shows only matches.
    #[arg(long, value_enum, default_value_t = ModeArg::SelfCheck)]
    mode: ModeArg,
    /// Print the report as JSON instead of text.
    #[arg(long)]
    json: bool,
    /// Language of the text output.
    #[arg(long, value_enum, default_value_t = Lang::En)]
    lang: Lang,
    /// Skip the SS-mode consent question (the player has already agreed).
    #[arg(long)]
    yes: bool,
    /// Restart with administrator rights before scanning (Windows only). Windows asks you to confirm.
    #[arg(long)]
    elevate: bool,
}

#[derive(Clone, Copy, ValueEnum)]
enum ModeArg {
    #[value(name = "self")]
    SelfCheck,
    Ss,
}

impl From<ModeArg> for Mode {
    fn from(mode: ModeArg) -> Self {
        match mode {
            ModeArg::SelfCheck => Self::SelfCheck,
            ModeArg::Ss => Self::Ss,
        }
    }
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Scan(args) => scan(&args),
    }
}

fn scan(args: &ScanArgs) -> anyhow::Result<()> {
    let bundle = Bundle::embedded().context("the embedded rules bundle is invalid")?;
    let mode = Mode::from(args.mode);
    let host = live_host();

    // Elevation is a property of a process token, so it takes a new process (ADR 0012). Asked before the
    // consent question, so nobody answers that question for a scan that will not happen here.
    if args.elevate && host.is_elevated() != Some(true) {
        return relaunch_elevated(args.lang);
    }

    if mode == Mode::Ss && !args.yes && !ask_consent(args.lang)? {
        println!("{}", output::declined(args.lang));
        return Ok(());
    }

    let context = ScanContext {
        provenance: Provenance::current(),
        generated_at: jiff::Timestamp::now().to_string(),
    };
    let report = scan::run(host.as_ref(), &bundle, context);
    let view = view::for_mode(&report, mode);

    if args.json {
        println!("{}", serde_json::to_string_pretty(&view)?);
    } else {
        print!("{}", output::render(&view, &bundle, args.lang));
    }
    Ok(())
}

fn ask_consent(lang: Lang) -> anyhow::Result<bool> {
    print!("{}", output::consent(lang));
    std::io::stdout().flush()?;
    let mut answer = String::new();
    std::io::stdin().lock().read_line(&mut answer)?;
    Ok(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

/// Starts an elevated copy and returns without scanning; the new process scans from the beginning.
#[cfg(windows)]
fn relaunch_elevated(lang: Lang) -> anyhow::Result<()> {
    use rongroi_host_windows::elevate::{self, ElevateError};

    // `--elevate` is not forwarded, so the new process cannot ask to elevate again: a token that is
    // elevated but restricted reports `is_elevated() == false` and would otherwise relaunch in a loop.
    let forwarded: Vec<String> = std::env::args()
        .skip(1)
        .filter(|arg| arg != "--elevate")
        .collect();

    match elevate::relaunch_elevated(&forwarded) {
        Ok(()) => {
            println!("{}", output::elevate_started(lang));
            Ok(())
        }
        // Declining the prompt is a choice, not a failure (ADR 0012).
        Err(ElevateError::Declined) => {
            println!("{}", output::elevate_declined(lang));
            Ok(())
        }
        Err(error) => Err(anyhow::Error::new(error).context(output::elevate_failed(lang))),
    }
}

// Same signature as the Windows arm, so the caller does not need to know which one it got. There is
// nothing here that can fail: saying so and exiting is the whole behaviour.
#[cfg(not(windows))]
#[allow(clippy::unnecessary_wraps)]
fn relaunch_elevated(lang: Lang) -> anyhow::Result<()> {
    println!("{}", output::elevate_not_windows(lang));
    Ok(())
}

#[cfg(windows)]
fn live_host() -> Box<dyn Host> {
    Box::new(rongroi_host_windows::LiveHost)
}

#[cfg(not(windows))]
fn live_host() -> Box<dyn Host> {
    Box::new(rongroi_host::NonWindowsHost)
}
