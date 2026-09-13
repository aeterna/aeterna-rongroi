// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! `cargo xtask <command>`: scaffolding and project checks. See CONTRIBUTING.md.

mod check_baseline;
mod check_locales;
mod check_rules;
mod check_unicode;
mod new_locale;
mod new_rule;
mod release;
mod release_check;
mod release_notes;
mod release_verify;
mod rules_reference;

use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "xtask", about = "aeterna-rongroi repository tasks")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Validate every rule, its fixtures and rule translations.
    CheckRules,
    /// Run the whole rule set against the baseline hosts; every match needs a `known-fps.csv` row.
    CheckBaseline,
    /// Write the rule reference pages in `docs/` from the rules bundle; `--check` fails if they are stale.
    RulesReference(rules_reference::Args),
    /// Check that every UI locale has the same keys as English.
    CheckLocales,
    /// Fail on zero-width and bidi control characters in any text file.
    CheckUnicode,
    /// Scaffold a new rule: `cargo xtask new-rule posture boot/my-rule`.
    NewRule {
        /// Collector id, in `snake_case`.
        collector: String,
        /// `<category>/<slug>`, in `kebab-case`.
        path: String,
    },
    /// Scaffold a new language: `cargo xtask new-locale vi`.
    NewLocale {
        /// BCP 47 tag, e.g. `vi` or `pt-BR`.
        lang: String,
    },
    /// Check a release tag against the version manifests and `CHANGELOG.md` (release workflow).
    ReleaseCheck(release_check::Args),
    /// Check the built release executables and write `SHA256SUMS` (release workflow).
    ReleaseVerify(release_verify::Args),
    /// Write the release notes for a tag (release workflow).
    ReleaseNotes(release_notes::Args),
}

fn main() -> anyhow::Result<()> {
    let root = repo_root();
    match Cli::parse().command {
        Command::CheckRules => check_rules::run(&root),
        Command::CheckBaseline => check_baseline::run(&root),
        Command::RulesReference(args) => rules_reference::run(&root, &args),
        Command::CheckLocales => check_locales::run(&root),
        Command::CheckUnicode => check_unicode::run(&root),
        Command::NewRule { collector, path } => new_rule::run(&root, &collector, &path),
        Command::NewLocale { lang } => new_locale::run(&root, &lang),
        Command::ReleaseCheck(args) => release_check::run(&root, &args),
        Command::ReleaseVerify(args) => release_verify::run(&args),
        Command::ReleaseNotes(args) => release_notes::run(&root, &args),
    }
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
}

/// Path relative to the repository root, for messages.
fn display(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string()
        .replace('\\', "/")
}
