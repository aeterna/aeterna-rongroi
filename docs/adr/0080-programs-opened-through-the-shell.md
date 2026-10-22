# ADR 0080 — Programs opened through the shell (UserAssist)

- Status: proposed — five owner questions below; nothing is built
- Date: 2026-10-22
- Related: ADR 0022 (reading registry values), ADR 0034 (Prefetch, BAM and PCA carry no identity), ADR 0038
  (whose `HKCU` a scan reads), ADR 0044 (gaps for one place), ADR 0048 (refused path forms), ADR 0051
  (timeline selectors), ADR 0061 (trace ages), ADR 0064 (the account at the keyboard), ADR 0078 (programs
  recorded near a game session, step P4), ADR 0079 (`recorded_files`)
- Amends: ADR 0034 (a fourth collector that carries no identity), ADR 0078 section 4 (UserAssist as a
  candidate source) and section 7 item 1 (the run count is not emitted), and — if owner question 4 is
  answered yes — ADR 0079 amendment 7 and "As built: P3" item 1 (a fourth source for `recorded_files`)

## Context

ADR 0078 section 7 names UserAssist as the first new source for the game-window view, and its owner
decision D4 puts it before the event payload fields. Windows Explorer keeps, for each account, a record of
the programs and shortcuts the person opened through the shell (Explorer, the Start menu, the taskbar, a
desktop shortcut): `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`. Each
value's name is the program's path or app identity with its letters rotated by 13 (ROT13); its data holds
counters and the last time it was opened. BAM records a program when it ends and Prefetch when it starts,
whoever started it. UserAssist records the person's own act of opening it.

What the code holds today (`dev` at `6d10791`):

- `RegistrySource` reads `HKLM\…` and `HKCU\…` only; `LiveHost` refuses every other root
  (`rongroi-host-windows/src/live.rs`). `HKCU` is the account the scan runs as. `value_names` and
  `read_bytes` (`REG_BINARY` only, 64 KiB cap) are all a collector needs.
- `powershell_text` (ADR 0064) compares the scan's account with the account last signed in at the keyboard
  and reports `same`, `other` or `unknown`, never the SIDs, in a private function (`history_account`).
- No ROT13 decoder exists. The only known-folder lookup is the save dialog's
  `SHGetKnownFolderItem(FOLDERID_Documents)` (`rongroi-host-windows/src/save_dialog.rs`), which is not a
  path resolver. `Host::env_var` exists and `autostart` resolves `%variables%` through it.
- `bam` emits `path` when `paths::is_drive_rooted` holds and `path_withheld: unredactable_form`
  otherwise; it does not call `is_refused_form`. `recorded_files` does.
- `view::game_windows` gathers candidates from `prefetch`, `bam`, `pca` and `process`, reads `last_run`
  from any collector it does not special-case, merges records by path, and maps trace ages in
  `oldest_by_source` for `prefetch`, `bam` and `pca` only (`view/game.rs`).

### Measured (2026-10-22, one Windows 11 PC, build 26220, the PC owner's account)

- Nine GUID subkeys. `{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}` (executables) held 188 values and
  `{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}` (shortcuts) 55; the other seven held 0 or 1.
- Every entry's data was 72 bytes, except one 1,612-byte value per GUID (`UEME_CTLSESSION`).
- Of the 187 executable entries, decoded names were: 65 a drive-letter path, 65 a path starting with a
  known-folder GUID (`{6D809377-…}` 46, `{1AC14E77-…}` 10, `{7C5A40EF-…}` 8, one unidentified), 18 an app
  identity with `!`, 38 an app identity without one (for example `CitizenFX.FiveM.Client`), and 2 `UEME_`
  counters.
- The last-run `FILETIME` at offset 60 was set on 108 entries and zero on 79. The 32-bit value at offset 4,
  which the published layout calls the run count, was zero on 184 of 187, including entries with a recent
  time: on this build it does not count runs.
- `FiveM.exe` under `%LOCALAPPDATA%` had a time. `GTA5_Enhanced.exe` in FiveM's game cache, which FiveM
  starts, was listed with no time. `notepad.exe` started with PowerShell's `Start-Process` left no entry.
  One PC, so these are observations, not a rule of Windows.

## Decision

### 1. A collector, `userassist`

A new collector reads, for the scan's own account, the `Count` key under the executables GUID
`{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}`, with `value_names` and `read_bytes`. No administrator rights are
needed.

- **Names.** A value name is decoded with ROT13 over ASCII letters only. A name starting with `UEME_` is a
  session counter and is skipped.
- **Paths.** A decoded name that is a drive-letter path is the program's path. A name that starts with one
  of five known-folder GUIDs has that prefix replaced from the environment (`Host::env_var`), as
  `autostart` expands `%variables%`, never through an OS call: `{6D809377-6AF0-444B-8957-A3773F02200E}`
  Program Files (`ProgramW6432`, then `ProgramFiles`), `{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}` Program
  Files (x86) (`ProgramFiles(x86)`), `{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}` System32
  (`SystemRoot` + `\System32`), `{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}` SysWOW64 (`SystemRoot` +
  `\SysWOW64`) and `{F38BF404-1D43-42F2-9305-67DE0B28FC23}` Windows (`SystemRoot`). The five GUIDs are
  Microsoft's published `KNOWNFOLDERID` values; three were seen on the measured PC. A resolved or literal
  path is emitted only when `rongroi_host::is_refused_form` does not refuse it and `is_drive_rooted` holds, as
  `recorded_files` requires of its paths; otherwise `path_withheld` says `unresolved_known_folder` (another
  GUID, or a variable the environment lacks) or `unredactable_form`.
- **`name`** is always the last path segment only, ASCII-lower-cased, as `bam`'s. When the path is withheld,
  the rest of the decoded name is dropped, not kept in another field. For an app identity (owner question
  3) `name` is the identity and `path_withheld` is `app_id`.
- **`last_run`** when the `FILETIME` is non-zero and converts (`rongroi_parsers::filetime`); absent
  otherwise, never 1601.
- **Not emitted:** the value at offset 4 (zero on 184 of 187 measured entries with times; amends ADR 0078
  section 7 item 1, which asked for a run count — owner question 5), and the focus fields, whose offsets
  and meaning this ADR did not measure. The parser keeps every byte it does not decode as an unparsed tail,
  as `rongroi_parsers::bam` does.
- **One summary observation:** `entries`, `skipped` (counters), `rejected` (data shorter than 72 bytes or
  a name that does not decode), and `account` — `same`, `other` or `unknown`, by `powershell_text`'s
  comparison, made `pub(crate)` and shared. A scan that ran as another administrator than the person at the
  keyboard therefore says so, and the entries are that administrator's.
- **Gaps.** The key absent is `source_absent`; the reasons come from `failure::reason_for`; a value that
  cannot be read is `partial` for the run (no discriminator, ADR 0044).
- **Parser.** `rongroi_parsers::userassist::{decode_name, parse_entry}`: ROT13, and the 72-byte entry with
  `last_run` at offset 60 (little-endian `FILETIME`), the value at offset 4, and the rest kept unparsed;
  `Truncated` below 72 bytes. A fuzz target for each. Its seed fixtures wait for the delegation wrapper to
  carry binary files (org-standards#72); until then its tests write bytes as `content_hex:`.

### 2. No identity, as ADR 0034 says for Prefetch, BAM and PCA (amends ADR 0034)

A UserAssist name is what a file was called when it was opened; a rename defeats it. `userassist` joins
`NAME_ONLY_COLLECTORS` (`rongroi-core/src/rules.rs`): no **evidence** rule may match its `name` or
`path`; a `role: timeline` selector may, as for the other three (ADR 0051). No rule ships with this
collector.

### 3. A candidate source in the game-window view (amends ADR 0078 section 4)

`userassist` joins `prefetch`, `bam`, `pca` and `process` as a candidate source, through its `last_run`.
An entry with a path merges with other records of that path ignoring ASCII case, as ADR 0078 section 4
says; an app identity has no path and stays a candidate of its own, as a Prefetch-only record does. It
declares a trace age (`rules/ages/userassist.yaml`, the oldest `last_run` it holds), and
`oldest_by_source` in `view/game.rs` maps it, so a T fact outside that span is "not known" (ADR 0061). An
entry with no time is not a candidate.

What UserAssist adds is the act of opening, for entries with a path: a candidate whose path BAM or PCA
and UserAssist both hold was opened by the person through the shell; one that only BAM, PCA or Prefetch
holds near the session was, as far as this account's UserAssist says, started some other way. ADR 0078's
facts are unchanged; the view already lists the sources each candidate came from.

### 4. A fourth source for `recorded_files` (owner question 4)

If owner question 4 is answered yes, `userassist::recorded_paths` joins `bam`, `pca` and `process` in
`recorded_files` with a `by_userassist` flag, so a file the person opened through the shell is read for its
identity in a full scan. That amends ADR 0079 amendment 7 and its "As built: P3" item 1, and, as for the
other three, the key is read a second time by `recorded_files` (ADR 0079 "As built: P3" item 9).

### 5. Privacy

UserAssist lists programs the person opened, as BAM lists programs that ran, and is treated as BAM is
today: paths are redacted in SS mode (`redact_profile_paths`); SS mode counts unmatched observations; the
game-window view names in SS mode only candidates with an identity fact (ADR 0078 D2). A future rule on
entry observations would, like a rule on `bam`'s, show a matched row's `name` and redacted `path` in SS
mode; that is why no rule ships, and a rule added later is reviewed on that question. The consent text
(CLI and desktop, both languages) and `PRIVACY.md` name the read in the change that adds it: "the programs
this account opened through Windows' shell, and when it last opened each; whether the account that ran
the scan is the one signed in at the keyboard".

## Owner questions

1. **Tier.** Recommended: **standard**, as `bam` and `pca`, whose records it sits beside; it reads one key
   of the scan's own account. Alternative: full only, behind the full-scan question.
2. **The shortcuts GUID** `{F4E57C4B-…}`. Recommended: **count only** — a `.lnk` path names a shortcut,
   not the program, and the executables GUID already holds the program it opened. Alternative: list the
   shortcuts too, which also puts shortcut names into the same SS rules as section 5.
3. **App identities** (56 of 187 on the measured PC). Recommended: **emit them** as path-less entries;
   `CitizenFX.FiveM.Client` shows how a game's own launch is written there. They never merge with a BAM or
   PCA record, because those carry paths. Alternative: count them only.
4. **`recorded_files`.** Recommended: **yes**, add UserAssist as a fourth source, at the cost of a second
   read of one registry key in a full scan. Alternative: later, with P6.
5. **The run count** ADR 0078 section 7 item 1 asked for. Recommended: **not emitted**, as measured above.
   Alternative: emit it, with the measurement in `PRIVACY.md` and the field's description.

## Alternatives weighed

| Alternative | Why not |
|---|---|
| Read every account's `NTUSER.DAT` | Opens hives of accounts that did not consent; ADR 0038 and ADR 0060 refused `HKEY_USERS` for the same reason |
| Resolve known-folder GUIDs with `SHGetKnownFolderPath` | An OS call per GUID for five fixed folders the environment already names, and the result is for the scan's account, the same as the environment's |
| Emit the run count | Zero on 184 of 187 measured entries with times; a reader would trust a count that does not count |
| Emit the focus fields | Neither their offsets nor their meaning were measured here |
| Rules naming programs on `userassist` | ADR 0034: a rename defeats them, and every match would put a program's name in SS mode as evidence |
| Read the other seven GUIDs | They held 0 or 1 values on the measured PC; nothing known about their meaning on Windows 11 |

## What is unverified

- Whether UserAssist records a program started by another program on other PCs: one PC showed a child of
  FiveM listed without a time and a `Start-Process` launch not listed at all.
- Whether the value at offset 4 is zero on other Windows 11 builds, and on Windows 10.
- What `{74439963-DECC-4EAC-80D4-6AE69B413749}` names.
- Whether a cleaner that deletes `UserAssist` leaves a trace this program reads (the change journal does
  not cover registry hives).

## Consequences

- `rongroi-parsers`: `userassist` (ROT13, the 72-byte entry), two fuzz targets.
- `rongroi-collectors`: `userassist` collector, registered in `all()`, its ages file; `powershell_text`'s
  account comparison made `pub(crate)`; with owner question 4, `userassist::recorded_paths` and
  `recorded_files`'s `by_userassist`.
- `rongroi-core`: `NAME_ONLY_COLLECTORS` gains `userassist`; `view::game_windows` gathers it and
  `oldest_by_source` maps it; `COLLECTOR_ORDER` places it after `pca`.
- CLI and desktop consent text, `CONSENT_WORDS`, `PRIVACY.md`, the locale name, `docs/architecture.md`.
- No `HKEY_USERS` read, no new host method.
