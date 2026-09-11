// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! `cargo xtask <command>`: scaffolding and project checks. See CONTRIBUTING.md.

mod check_locales;
mod check_rules;
mod check_unicode;
mod new_locale;
mod new_rule;

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
}

fn main() -> anyhow::Result<()> {
    let root = repo_root();
    match Cli::parse().command {
        Command::CheckRules => check_rules::run(&root),
        Command::CheckLocales => check_locales::run(&root),
        Command::CheckUnicode => check_unicode::run(&root),
        Command::NewRule { collector, path } => new_rule::run(&root, &collector, &path),
        Command::NewLocale { lang } => new_locale::run(&root, &lang),
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
