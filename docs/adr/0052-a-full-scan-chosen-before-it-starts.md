# ADR 0052 — A full scan, chosen before it starts

- Status: proposed
- Date: 2026-09-16

## Context

The sources proposed next read more about the player than anything the program reads today:

- FiveM's own logs, which name the servers the game connected to;
- the per-server cache folders FiveM for GTA V Enhanced keeps, whose names identify a server;
- the lists of modules in FiveM's crash dumps, whose paths can name a user folder;
- counts of the Rockstar, Social Club and Steam profiles on the PC.

The owner decided on 2026-09-16 that these are collected only when the player agrees, at the start, to a
fuller scan than the ordinary one.

Today consent does not gate collection. Every collector runs before any question is asked:

- the desktop app scans before its window exists, so that nothing the WebView does can change what was
  measured (`apps/desktop/src-tauri/src/main.rs`, ADR 0001, ADR 0012);
- the CLI asks its question only in SS mode, and only about what is shown, after parsing arguments and
  before scanning (`crates/rongroi-cli/src/main.rs`); Self mode asks nothing.

Consent then decides what SS mode shows (`rongroi_core::view`). For sources whose mere reading is the thing
a player may refuse, that is too late.

## Decision

### 1. Two scan tiers, and each collector belongs to one

`Collector` gains `fn tier(&self) -> ScanTier`, `Standard` by default. `ScanTier` is `standard` or `full`.
Every collector that exists today stays `standard`. A collector is `full` when its own ADR says so, and the
ADR says why.

`scan::run` takes the chosen tier. A `full` collector in a `standard` scan is not called: its run is
`Unmeasured { reason: not_consented }`, so its rules are unmeasured and say why, and no function of it
touches the machine.

The report header gains `scan_tier`. It is additive, as `boot_time` and `profiles_directory` were, and
`REPORT_SCHEMA_VERSION` stays at 1; a report without it was a standard scan.

### 2. `not_consented` is a thirteenth reason, and a scope statement

`UnmeasuredReason::NotConsented`, in words "the player chose the ordinary scan, which does not read this".
Like `not_admin` and `not_attempted` it is one fact about the scan, so `is_scope_statement` is true: it is
never a row, and `ScopeNotes` gains `not_consented`, stated once above the evidence in both modes. ADR 0030's
table gains the row. A rule may not declare it in `unmeasured_when`, because no machine produces it.

### 3. The choice is made before the scan, in the process that scans

**CLI.** `scan --full` asks, on standard error and before any collector runs, a question that lists what a
full scan reads. Only `yes` starts a full scan; anything else starts the standard scan and says so. `--yes`
answers the SS-mode question only, never this one, and no flag answers it. A full scan therefore needs a
person at the keyboard; a script gets the standard scan. `--elevate` forwards `--full`, and the elevated copy
asks again, in its own window, because it is the process that reads.

**Desktop.** The app starts as today and runs the standard scan. The report screen offers "Full scan". It
does not scan in place (ADR 0012's reason stands): it starts a new copy of the program with `--full` and
exits, as the elevation button does. The new copy, **before any collector runs and before any WebView
exists**, shows the same list in a native Windows dialog. Yes starts a full scan; No or closing the dialog
starts the standard scan. The dialog belongs to Windows, not to the WebView, so the property ADR 0001 and
ADR 0012 protect — the report is measured before the WebView exists — holds.

The new copy is meant to keep the token of the copy that started it, so that asking for a full scan neither
gains nor drops administrator rights. The intended call is `CreateProcessW`, expected to give a child of an
elevated copy the same elevated token without another UAC prompt; that expectation is unverified and is
measured before any code (What is unverified). The elevation button forwards `--full` when the current scan
is full.

**The flag alone never reads anything.** A shortcut or a script that passes `--full` gets the question, not a
full scan. The question is asked by the process that will read, every time, so no earlier answer is trusted.

### 4. What SS mode shows from a full scan

- The SS consent question lists, when `scan_tier` is `full`, what the full scan read, and SS mode shows the
  evidence of `full` collectors only after that answer.
- Two kinds of value stay hidden in SS mode even then, each behind its own question the player answers
  separately, default no:
  - a **server identity** — an endpoint from a log, a server cache folder's name;
  - an **account identifier** — should any collector ever emit one (the first ones emit counts only).

  A collector marks such a field in its declaration (`Field::sensitive(kind)`, ADR 0026). `view` replaces
  its value with a placeholder that says which question would show it, as it replaces a user name
  (ADR 0049). The placeholder is in the view, never only in the UI (AGENTS.md hard rule 5).
- Self mode shows everything the full scan read, as it does today.

### 5. What a full scan does not change

Everything in AGENTS.md's hard rules: no network code, read-only collectors, no verdict, no score. A full
scan reads more; it does not read differently. No `full` collector may read a browser's history, a
messenger's storage or any store that holds a credential or a token, whatever the player agrees to
(`crates/rongroi-collectors/AGENTS.md`).

### 6. Initial assignments, for the ADRs that add the sources

| Source (proposed) | Tier | Sensitive field |
|---|---|---|
| Counts and times of FiveM's cache, log and crash folders (ADR 0050's first consumer) | standard | — |
| Number of Enhanced per-server cache folders and their times | standard | — |
| An Enhanced per-server cache folder's name | full | server identity |
| Endpoints and plugin names in FiveM's logs | full | server identity (endpoints) |
| Module lists in FiveM's crash dumps | full | — (paths redacted as today) |
| Counts of Rockstar, Social Club and Steam profiles | full | — |

## Alternatives weighed

| Alternative | Why not |
|---|---|
| Ask in the WebView, then scan in the same process | Undoes the property ADR 0001 and ADR 0012 protect for every full scan. |
| Ask in the WebView, then trust `--full` in the new copy | A flag anyone can put in a shortcut would read the most personal sources without the player seeing the list. |
| Collect everything always, and gate only what is shown | The owner's decision is that these sources are not read without agreement; a report the player saves with `--json` would hold them for whoever opens the file. |
| A per-source checklist at start | More choices than a screenshare can walk through, and each source's reason lives in its ADR; one list with two sensitive switches in SS mode covers the owner's cases. |
| `--yes-full` for scripts | A scripted full scan has no player at the keyboard to agree. |

## What is unverified

- The token a `CreateProcessW` child receives from an elevated parent (section 3).
- Which native dialog API fits: `MessageBoxW` is enough for a yes/no over a text list; `TaskDialogIndirect`
  gives an expandable list. The `windows` crate feature names for either are not checked here and must be
  grepped, not guessed.
- Whether a native dialog shown before a Tauri window exists is brought to the front on every Windows 11
  configuration.

## Owner decisions this ADR needs

1. The native pre-scan dialog in the desktop copy (section 3), rather than trusting the flag.
2. No bypass for scripts (section 3).
3. The two sensitive kinds and their default of hidden in SS mode (section 4).
4. The initial assignments (section 6).

## Consequences

- `rongroi-collectors`: `ScanTier`, `Collector::tier`, `Field::sensitive`; `scan::run` takes a tier;
  the cross-collector tests run both tiers.
- `rongroi-core`: `UnmeasuredReason::NotConsented`, `ScopeNotes.not_consented`, header `scan_tier`, the
  sensitive-value placeholders and the SS options in `view`.
- `rongroi-host-windows`: a same-token relaunch beside `elevate`, and the native dialog.
- CLI: `--full` and its question; `--elevate` forwards it.
- Desktop: the "Full scan" button, the pre-scan dialog, the SS consent screen's extra list and switches.
- `xtask`: `check-baseline` scans at `full`; `check-rules` refuses `not_consented` in `unmeasured_when`.
- `PRIVACY.md`, `docs/architecture.md`, ADR 0030's table, the SS guides and both READMEs describe the two
  tiers in the change that adds the first `full` collector. Until then the tier exists and changes nothing
  a player sees.
- `CONVENTIONS.md`'s glossary gains **scan tier**, **full scan** and **sensitive field**.
