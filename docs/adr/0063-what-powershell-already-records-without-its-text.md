# ADR 0063 — What PowerShell already records, without reading what it says

- Status: accepted — the owner decided the six questions below on 2026-10-08, each as recommended
- Date: 2026-10-08
- Implemented: the selector, the `psreadline` place and its two rules, in the change that adds "As built"

## Context

A cheat sold for FiveM can arrive with no file on disk: the seller hands over one line of PowerShell that
downloads a script and runs it in memory, and the script then opens the game's process. None of this
program's collectors that look for files — `fivem_dir`, `driver_service`, `autostart`, the signature checks —
can see that, because nothing is written where they look.

Windows keeps two records of it that this program already reads or can read without new kinds of access:

- **PowerShell's own operational log.** Windows PowerShell 5 and later write event 4104 for a script block it
  considers suspicious, at level 3 (Warning), even when script block logging is not switched on; with
  script block logging on, every block is written at level 5 (Verbose). The `evtx` collector already reads
  this log on every scan and groups its records by `(log, channel, provider, event_id, level)` with a
  `count`, a `first_seen` and a `last_seen` (ADR 0024). No rule or selector names the log today, so ADR 0061
  folds it with the rest.
- **The NTFS change journal** for the folder PowerShell's line editor (PSReadLine) keeps its command
  history in, `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine`. The `usn` collector already reads the
  journal and counts records for five watched folders (ADR 0047); this folder is not one of them.

Three limits come with these sources and are not changed here:

- **No payload.** ADR 0018 drops `EventData` in the parser, so a selector sees how many suspicious blocks the
  log holds and when the first and last were written, never their text, their script file or who ran them.
  Reading the text is a separate ADR (it is personal data, and it is where an argument such as a token or a
  password is).
- **No file name, no content** in `usn`: a count of records per folder, as for the other watched folders.
- **Each log and the journal is its own retention window**, and both are short (measured below).

This ADR follows the shape of ADR 0059: what Windows records is put on the timeline, and nothing that an
ordinary PC produces every day becomes a row.

## Measured

### What PowerShell's source says

PowerShell 7's `CompiledScriptBlock.cs` (`PowerShell/PowerShell`, master, read 2026-10-08) decides
"suspicious" in `LookupHash` against a fixed list of about 150 words, grouped in the source as Add-Type,
dynamic assembly, type members, InteropServices, obfuscation, Win32 API, crypto, keylogging, internal types and
logging changes. The list includes `Add-Type`, `DllImport`, `OpenProcess`, `VirtualAlloc`,
`WriteProcessMemory`, `ReadProcessMemory`, `GetAsyncKeyState`, `FromBase64String`, `EncodedCommand` and
`Bypass`. It does **not** include `Invoke-Expression`, `iex`, `DownloadString` or `Net.WebClient`. A
suspicious block is written with `LogOperationalWarning`, an ordinary logged block with
`LogOperationalVerbose`. Logging is skipped when `EnableScriptBlockLogging` is explicitly 0 (the four
posture rules of ADR 0038 report that policy) or when the block is product code.

Windows PowerShell 5.1's source is not public; what it does was measured instead.

PSReadLine's `History.cs` at tag `v2.0.0` (the version Windows ships, below) appends with `File.AppendText`
and rewrites with `File.CreateText`; the file is never deleted or renamed by PSReadLine itself.

### A Windows 11 PC (build 26220), 2026-10-08

Windows PowerShell 5.1.26100, elevated, no script block logging policy at either hive. This PC is the
project's development machine and runs PowerShell probes often, so its counts are higher than a player's
PC is likely to show; no other PC was measured (owner decision of 2026-10-08: no VM).

Each case ran in a fresh `powershell.exe -NoProfile -NonInteractive`, carried a nonce, and was counted by that
nonce. The "downloaded" script was a local file read with `WebClient.DownloadString('file:///…')` or
`Get-Content | iex` — no network — holding one `Add-Type -MemberDefinition` with a `[DllImport]` declaration
that calls nothing.

| Case | 4104 written |
|---|---|
| `Get-Date` | none |
| the loader line, both forms | none |
| the script the loader ran | **level 3, once per loader** |
| `Add-Type -AssemblyName System.Windows.Forms` | **level 3** |
| a string containing the word `Bypass` | **level 3** |
| `-EncodedCommand` whose script calls `FromBase64String` | none (one sample) |

| Source | Measured |
|---|---|
| `Microsoft-Windows-PowerShell/Operational` | enabled, 15 of 15 MiB, 1 748 records, oldest **1.29 days** |
| its 4104 level 3 records before the test | **369** over those 1.29 days (67 and 302 by day), 367 with no script path, 2 from a script under the profile |
| its 4104 level 5 records | 0 |
| `Windows PowerShell` (classic) | 15 of 15 MiB, 12 298 records, oldest 5.9 days; provider `PowerShell`, ids 400, 403, 600, 800, all level 4 |
| PowerShell 7 | installed as the MSIX package; provider `PowerShellCore` **not registered**, so `PowerShellCore/Operational` does not exist and PowerShell 7 writes no 4104 on this PC |
| PSReadLine | 2.0.0; `ConsoleHost_history.txt` present |
| change journal | no record of the history file in the span it held (the file was last written 11 days before) |

The 4104 provider reads `Microsoft-Windows-PowerShell`, channel `Microsoft-Windows-PowerShell/Operational`,
level 3 — the three values the selector below pins.

## Decision

### 1. One timeline selector on 4104 level 3, and no rule

`rules/evtx/timeline/powershell-flagged-script-block/`, `role: timeline`, `strength: context`,
`status: experimental`:

```yaml
match:
  provider: Microsoft-Windows-PowerShell
  channel: Microsoft-Windows-PowerShell/Operational
  event_id: 4104
  level: 3
```

It puts the first and last time the log still holds a block PowerShell flagged on the timeline, beside the
session statement (ADR 0062) and the time a server flagged, which the screenshare guide now tells a reviewer
to bring (#145). Its description says what the time cannot say: which script, whose, whether it was a cheat.

Why not a rule: the one PC measured held 369 such records in a day and a half, and ordinary scripts produce
them (a Windows Forms dialog, the word `Bypass`). A rule would be `found` on nearly every PC that uses
PowerShell — the reason ADR 0059 gave Code Integrity and Defender selectors.

What the grouping gives: one group, so **two times** — the oldest flagged block the log still holds and the
newest — and a count in Self mode. The newest is the useful one: it says when PowerShell last flagged
something before the scan. Times in between are not shown (see "Alternatives").

### 2. A sixth watched folder for the change journal, and two rules

Amends ADR 0047. `usn` adds the place `psreadline`: `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine`,
through the base `fivem_dir::ROAMING_APP_DATA` already uses. Two rules, written as the plugin folder's are:

- `rules/usn/psreadline/files-deleted` — `location: psreadline`, `folder: identified`, `deleted|gte: 1`
- `rules/usn/psreadline/files-renamed` — the same with `renamed|gte: 1`

`strength: context`, `status: experimental`, `unmeasured_when: [not_windows, source_absent, other_volume]` —
`source_absent` because the folder exists only on a PC where someone has typed into a PowerShell window.

Why it is worth a rule when the plugin folder's is `context` too: PSReadLine itself appends and rewrites,
and never deletes or renames (section "What PowerShell's source says"), so a deletion here is a person or
another program. `falsepositives` names the ordinary ones: the player clearing their own history, a privacy or
clean-up tool, a profile reset, an editor that saves by writing a new file and renaming it over the old one.
The retention text gives the journal's span, which is beside the row (ADR 0047): **well under an hour** on the
PC measured.

Two limits the `usn` collector already has apply here as they do to `plugins`: only records whose parent is
the folder itself are counted, and a folder deleted and made again gets a new identifier, so a deleted
**folder** — rather than the file in it — leaves this rule with nothing to count. The description says so.

**This is the first watched folder no other collector reads.** ADR 0047 chose its folders as "the folders other
collectors already read", which kept the journal's reach to places the report already describes. This folder
holds one file of personal content; the journal gives only counts and times of changes to it, never its name or
anything inside it, so what SS mode shows is the same kind of fact as for `plugins`. The departure is a decision
for the owner (question 2), not a consequence of ADR 0047.

### 3. Nothing for PowerShell 7 yet

No selector names `PowerShellCore/Operational`. On the one PC measured the log does not exist, because the
MSIX package did not register the provider. How the MSI installer behaves is not measured. The selector's
`falsepositives` says that a script run in PowerShell 7 may be recorded nowhere.

### 4. Nothing for event 400 yet

The classic log's 400 ("engine state changed to Available") reaches back further (5.9 days against 1.29) and
its payload carries the command line PowerShell was started with. Without the payload, a selector would put
the first and last time any PowerShell started on the timeline — Windows' own maintenance starts it too
(37 of the 300 newest classic records were 400s) — and say nothing about which. The payload is the next ADR's
question.

### 5. No new field, reason or collector

The selector reads fields `evtx` declares. `usn` gains one place and no field. No reason is added.

## Alternatives weighed

| Alternative | Why not |
|---|---|
| A `context` rule on 4104 level 3, or `count\|gte: N` | 369 on one PC in 1.3 days; a threshold is a decision about how many flagged scripts are too many |
| Per-hour counts of flagged blocks, so the timeline shows when they cluster | Changes `evtx`'s grouping for every log; worth it only if the two times prove too coarse in use |
| Reading 4104's text, 400's command line or the history file | Personal data and arguments: a separate ADR on ADR 0018 and on PRIVACY.md's "never reads the arguments" |
| A metadata collector for the history file (exists, size, times) | Its value is to the ADR that reads the text; alone it says only that someone once typed into PowerShell |
| Watching the history **file** rather than its folder | `usn` counts per folder (ADR 0047); a file is a new kind of place |

## What is unverified

- **A player's PC.** Every count above is from the development machine. How many flagged blocks an ordinary
  gaming PC writes, and how far back its log reaches, is not measured.
- **Which words Windows PowerShell 5.1 flags.** Measured for six cases; the list is PowerShell 7's.
  `FromBase64String` inside an encoded command was not flagged in the one sample, although it is on
  PowerShell 7's list.
- **Whether an MSI install of PowerShell 7 registers its provider.** Partly answered on 2026-10-08 (ADR 0064,
  runner): a GitHub-hosted runner image, which installs PowerShell 7 with its installer, has
  `PowerShellCore/Operational` with 480 records. A player's MSI install is still not measured.
- **What the change journal records when the history file is cleared or replaced on a PC.** Inferred from
  PSReadLine's source and from what the journal records for any deletion; not observed on that file.
- **Whether a script the loader fetched over the network is flagged as one fetched from a file.** The
  probe used `file:///`. What PowerShell logs is the block's text, which does not depend on where it came
  from — that is reasoning, not a measurement.

## Owner decisions (2026-10-08)

The owner answered "as recommended" to all six:

1. **The 4104 selector instead of a rule** (section 1). Recommended.
2. **The sixth watched folder and its two rules** (section 2), `context`, `experimental` — including that it is
   the first folder `usn` watches which no other collector reads, a departure from ADR 0047's scope.
   Recommended: counts and times only, as for `plugins`, and the departure written into ADR 0047 as an
   amendment in the same change.
3. **No PowerShell 7 selector until a PC with the provider registered is measured** (section 3).
   Recommended.
4. **No event 400 selector without its payload** (section 4). Recommended.
5. **No history-file metadata collector in this change** — moved to the ADR that reads the text. This
   changes the plan's earlier "metadata only" item. Recommended.
6. **Before the change that adds them merges**, one elevated scan of a release build on the Windows 11 PC
   shows the selector's two times and the `psreadline` place `identified`, with the journal's span.
   Recommended.

## Consequences

- `rules/evtx/timeline/powershell-flagged-script-block/` and `rules/usn/psreadline/files-{deleted,renamed}/`,
  each with positive and negative fixtures — the selector's negatives built from the collisions that matter:
  4104 at level 5, 4103 at level 3, and 4104 level 3 from `PowerShellCore` — Thai text in
  `rules/i18n/th.yaml`, `docs/rules-reference*.md` regenerated.
- `usn`'s `PLACES` gains one entry; its module header, the ADR 0047 table and `docs/architecture.md` name it.
- **SS mode shows more.** The selector's two times and the folder's counts: the consent question in
  `crates/rongroi-cli/src/output.rs` (both languages), the desktop's `consent.shows` and `PRIVACY.md` name them
  in the same change, as `rules/AGENTS.md` requires.
- ADR 0061's trace ages put `Microsoft-Windows-PowerShell/Operational` among the first rows by itself, since
  that order is derived from the channels the bundle names.
- `rules/unconfronted.csv`: one row for the selector (no baseline carries a PowerShell operational log) and
  two for the `usn` rules (no baseline describes the PSReadLine folder), each with what would end it.
- No change to the rule format, the engine or either schema version.

## As built (2026-10-08)

- `rules/evtx/timeline/powershell-flagged-script-block/`, `rules/usn/psreadline/files-deleted/` and
  `files-renamed/`, with the fixtures section "Consequences" names; `usn`'s `PLACES` gains `psreadline`
  (`PSREADLINE_LOCATION`, `PSREADLINE_RELATIVE_PATH`); the journal's timeline selector names the folder in its
  text; ADR 0047 carries the amendment.
- `fixtures/hosts/usn-journal-read` gains the folder with three appends and one deletion, so the collector's
  test and the report test assert its counts, its row and its row band in both views.
- **Owner decision 6, met:** one elevated scan with a release-profile build of this change (not an official
  build — the change was not merged yet) on the Windows 11 PC (build 26220), 2026-10-08:

  | What | Read |
  |---|---|
  | the 4104 level 3 group | `Microsoft-Windows-PowerShell`, 373 records, first 2026-10-07T00:23:42Z, last 2026-10-08T07:15:17Z |
  | the selector on the SS timeline | two entries, `first_seen` and `last_seen`, with its title, in English and in Thai |
  | `psreadline` | `identified`, 0 records in the span |
  | the journal's span | 2026-10-08T07:20:46Z to 07:56:40Z, about 36 minutes, 343 462 records |
  | the two `psreadline` rules | `not_found` |
  | trace ages | `Microsoft-Windows-PowerShell%4Operational.evtx` among the first rows |

  The newest flagged block was this project's own probe, run on that PC that morning; the PC is the
  development machine, as section "Measured" says. The folder and the files were removed afterwards.

