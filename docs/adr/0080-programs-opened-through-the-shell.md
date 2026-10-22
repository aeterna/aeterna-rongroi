# ADR 0080 — Programs opened through the shell (UserAssist)

- Status: proposed — four owner questions below; nothing is built
- Date: 2026-10-22
- Related: ADR 0022 (reading registry values), ADR 0034 (Prefetch, BAM and PCA carry no identity), ADR 0038
  (whose `HKCU` a scan reads), ADR 0044 (gaps for one place), ADR 0048 (refused path forms), ADR 0061 (trace
  ages), ADR 0064 (the account at the keyboard), ADR 0078 (programs recorded near a game session, step P4),
  ADR 0079 (`recorded_files`)
- Amends: ADR 0034 (a fourth collector that carries no identity), ADR 0078 section 4 (UserAssist as a
  candidate source)

## Context

ADR 0078 section 7 names UserAssist as the first new source for the game-window view, and its owner
decision D4 puts it before the event payload fields. Windows Explorer keeps, for each account, a record of
the programs and shortcuts the person opened through the shell (Explorer, the Start menu, the taskbar, a
desktop shortcut): `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`. Each
value's name is the program's path or app identity with its letters rotated by 13 (ROT13); its data holds
counters and the last time it was opened. BAM records a program when it ends and Prefetch when it starts,
whoever started it. UserAssist records the person's own act of opening it. A loader opened by
double-clicking a file in Downloads leaves a UserAssist entry; the program the loader starts does not.

What the code holds today (`dev` at `6d10791`):

- `RegistrySource` reads `HKLM\…` and `HKCU\…` only; `LiveHost` refuses every other root
  (`rongroi-host-windows/src/live.rs`). `HKCU` is the account the scan runs as. `subkeys`, `value_names`
  and `read_bytes` (`REG_BINARY` only, 64 KiB cap) are all a collector needs.
- `bam` already reads per-user state under `HKLM` without emitting a SID. `powershell_text` (ADR 0064)
  compares the scan's account with the account last signed in at the keyboard and reports `same`, `other`
  or `unknown`, never the SIDs.
- No ROT13 decoder and no known-folder resolver exist. `paths::is_drive_rooted` decides whether a path is
  emitted; any other form is `path_withheld: unredactable_form`.
- `view::game_windows` gathers candidates from `prefetch`, `bam`, `pca` and `process`
  (`view/game.rs`), and reads `last_run` from any collector it does not special-case.

### Measured (2026-10-22, one Windows 11 PC, build 26220, the PC owner's account)

- Nine GUID subkeys. `{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}` (executables) held 188 values and
  `{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}` (shortcuts) 55; the other seven held 0 or 1.
- Every entry's data was 72 bytes, except one 1,612-byte value per GUID (`UEME_CTLSESSION`).
- Of the 187 executable entries, decoded names were: 65 a drive-letter path, 65 a path starting with a
  known-folder GUID (`{6D809377-…}` Program Files 46, `{1AC14E77-…}` System32 10, `{7C5A40EF-…}` Program
  Files (x86) 8, one unidentified), 18 an app identity with `!`, 38 an app identity without one (for
  example `CitizenFX.FiveM.Client`), and 2 `UEME_` counters.
- The last-run `FILETIME` at offset 60 was set on 108 entries and zero on 79. The run count at offset 4
  was zero on 184 of 187, including entries with a recent time: on this build it does not count runs.
- `FiveM.exe` under `%LOCALAPPDATA%` had a time. `GTA5_Enhanced.exe` in FiveM's game cache, which FiveM
  starts, was listed with no time. `notepad.exe` started with PowerShell's `Start-Process` left no entry.
  One PC, so these are observations, not a rule of Windows.

## Decision

### 1. A collector, `userassist`

A new collector reads, for the scan's own account, the `Count` key under the executables GUID
`{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}`. It lists value names with `value_names` and reads each with
`read_bytes`. No administrator rights are needed.

- **Names.** A value name is decoded with ROT13 over ASCII letters only. A name starting with `UEME_` is a
  session counter and is skipped.
- **Paths.** A decoded name that is a drive-letter path is the program's path. A name that starts with one
  of five known-folder GUIDs is resolved through the environment, never through an OS call: Program Files
  (`{6D809377-6AF0-444B-8957-A3773F02200E}`, `%ProgramW6432%` then `%ProgramFiles%`), Program Files (x86)
  (`{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}`, `%ProgramFiles(x86)%`), System32
  (`{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}`, `%SystemRoot%\System32`), SysWOW64
  (`{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}`, `%SystemRoot%\SysWOW64`) and Windows
  (`{F38BF404-1D43-42F2-9305-67DE0B28FC23}`, `%SystemRoot%`). Any other GUID, or a variable the
  environment lacks, keeps the name and withholds the path as `unresolved_known_folder`. A resolved path
  goes through `rongroi_host::is_refused_form` and `is_drive_rooted` as `bam`'s paths do.
- **App identities.** A name that is neither a path nor a known-folder path is an app identity. Owner
  question 3 decides whether it is emitted.
- **Fields of one entry:** `name` (the file name, ASCII-lower-cased, as `bam`'s; for an app identity, the
  identity), `path` or `path_withheld`, `last_run` when the `FILETIME` is non-zero and converts
  (`rongroi_parsers::filetime`), and `focus_count` and `focus_ms` as the data holds them. **The run count
  is not emitted**: it was zero on 184 of 187 entries with times, so a reader would take it as a count it is
  not. A `last_run` of zero is absent, not 1601.
- **One summary observation:** `entries`, `skipped` (counters), `rejected` (data shorter than 72 bytes or
  a name that does not decode), and `account` — `same`, `other` or `unknown`, by the comparison
  `powershell_text` already makes (ADR 0064). A scan that ran as another administrator than the person at
  the keyboard therefore says so, and the entries are that administrator's.
- **Gaps.** The key absent is `source_absent`; access denied is the usual reason; a value that cannot be
  read is `partial` for the run (no discriminator, ADR 0044).
- **Parser.** `rongroi_parsers::userassist::{decode_name, parse_entry}`: ROT13 and the 72-byte layout,
  `Truncated` below 72 bytes, any bytes past 72 kept as an unparsed tail. A fuzz target for each.

### 2. No identity, as ADR 0034 says for Prefetch, BAM and PCA (amends ADR 0034)

A UserAssist name is what a file was called when it was opened; a rename defeats it. `userassist` joins
`NAME_ONLY_COLLECTORS` (`rongroi-core/src/rules.rs`): no rule may match its `name` or `path`. Rules may
read its counts, its account and its times.

### 3. A candidate source in the game-window view (amends ADR 0078 section 4)

`userassist` joins `prefetch`, `bam`, `pca` and `process` as a candidate source, through its `last_run`.
Its path joins other records by path ignoring ASCII case, as ADR 0078 section 4 says. It declares a trace
age (`rules/ages/userassist.yaml`): the oldest `last_run` it holds, so T facts outside that span stay "not
known" (ADR 0061). An entry with no time is not a candidate.

What UserAssist adds to the ladder is the act of opening: a candidate recorded by BAM or Prefetch and by
UserAssist was opened by the person; one recorded only by BAM or Prefetch near the session was started by
something else, as far as this account's record says. ADR 0078's facts are unchanged; the view shows the
sources each candidate came from, as it already does.

### 4. A fourth source for `recorded_files` (owner question 4)

When owner question 4 is answered yes, `userassist::recorded_paths` joins `bam`, `pca` and `process` in
`recorded_files` (ADR 0079 amendment 7), with a `by_userassist` flag, so a file the person opened through
the shell is read for its identity in a full scan.

### 5. Privacy

UserAssist lists programs the person opened, as BAM lists programs that ran. The same rules apply: paths
are redacted in SS mode (`redact_profile_paths`), no rule names a program, SS mode counts unmatched
observations, and the game-window view names in SS mode only candidates with an identity fact (ADR 0078
D2). The consent text (CLI and desktop, both languages) and `PRIVACY.md` name the read in the change that
adds it: "the programs this account opened through Windows' shell, with when it last opened each".

## Owner questions

1. **Tier.** Recommended: **standard**, as `bam` and `pca`, whose records it sits beside; it reads one key
   of the scan's own account. Alternative: full only, behind the full-scan question.
2. **The shortcuts GUID** `{F4E57C4B-…}`. Recommended: **count only** — a `.lnk` path names a shortcut,
   not the program, and the executables GUID already holds the program it opened. Alternative: list the
   shortcuts too.
3. **App identities** (56 of 187 on the measured PC). Recommended: **emit them** as entries with `name` set
   to the identity and `path_withheld: app_id`; they become path-less candidates, as a Prefetch-only record
   does, and `CitizenFX.FiveM.Client` shows how a game's own launch is written there. Alternative: count
   them only.
4. **`recorded_files`.** Recommended: **yes**, add UserAssist as a fourth source in the same change.
   Alternative: later, with P6.

## Alternatives weighed

| Alternative | Why not |
|---|---|
| Read every account's `NTUSER.DAT` | Opens hives of accounts that did not consent; ADR 0038 and ADR 0060 refused `HKEY_USERS` for the same reason |
| Resolve known-folder GUIDs with `SHGetKnownFolderPath` | An OS call per GUID for five fixed folders the environment already names; the environment is what `autostart` already uses |
| Emit the run count | Zero on 184 of 187 measured entries with times; a reader would trust a count that does not count |
| Rules naming programs on `userassist` | ADR 0034: a rename defeats them, and every match would put a program's name in SS mode as evidence |
| Read the other seven GUIDs | They held 0 or 1 values on the measured PC; nothing known about their meaning on Windows 11 |

## What is unverified

- Whether UserAssist records a program started by another program on other PCs: one PC showed a child of
  FiveM listed without a time and a `Start-Process` launch not listed at all.
- Whether the run count is zero on other Windows 11 builds, and on Windows 10.
- What `{74439963-DECC-4EAC-80D4-6AE69B413749}` names.
- Whether a cleaner that deletes `UserAssist` leaves a trace this program reads (the change journal does
  not cover registry hives).
- Whether `focus_count` and `focus_ms` mean anything on this build.

## Consequences

- `rongroi-parsers`: `userassist` (ROT13, the 72-byte entry), two fuzz targets.
- `rongroi-collectors`: `userassist` collector, its ages file, its `recorded_paths` (owner question 4);
  `recorded_files` gains `by_userassist` (question 4).
- `rongroi-core`: `NAME_ONLY_COLLECTORS` gains `userassist`; `view::game_windows` gathers it and maps its
  trace age; `COLLECTOR_ORDER` places it after `pca`.
- CLI and desktop consent text, `PRIVACY.md`, the locale name, `docs/architecture.md`.
- No `HKEY_USERS` read, no new host method.
