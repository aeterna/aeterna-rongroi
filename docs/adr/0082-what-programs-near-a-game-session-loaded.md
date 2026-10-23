# ADR 0082 — What programs near a game session loaded

- Status: proposed — four owner questions below; nothing is built
- Date: 2026-10-23
- Related: ADR 0021 (the Prefetch collector; `loaded_files` and `volumes` are withheld), ADR 0052 (scan
  tiers), ADR 0062 (FiveM sessions and editions), ADR 0078 (programs recorded near a game session, sections
  3, 4, 5 and 9, step P5), ADR 0079 (the file a recorded program ran from)
- Amends: ADR 0021 (one count derived from `loaded_files` inside the collector; nothing of the list is
  emitted), ADR 0078 section 5 (a new fact, L1, which joins the ordering), section 9 (L1 lists a
  candidate's name in SS mode) and step P5 (what is counted, and what is left to a later step)

## Context

ADR 0078 step P5 asks, for `FiveM.exe`, the game process, `rundll32.exe` and `regsvr32.exe` only: how many
files in Prefetch's loaded-file list are outside Windows and Program Files, and how many have a name that
is not a DLL's but content that is a PE; never a path (ADR 0021 stays). A program that is loaded rather
than run leaves its path in that list, not in BAM, PCA or UserAssist.

What the code holds today (`dev` at `38d590c`):

- `rongroi_parsers::prefetch` returns `loaded_files` (the files Prefetch recorded for the program, each as
  `\VOLUME{…}\…`) and `volumes`. The `prefetch` collector (standard tier) emits neither and says so in
  `loaded_files_withheld`.
- One value is already derived from `loaded_files` inside the collector and emitted as a word, never a
  path: `fivem_edition::of_prefetch`, the edition of the executable's own entry.
- `fivem_edition::of_path` knows FiveM's two program folders: `%LOCALAPPDATA%\FiveM\` (Legacy) and
  `%LOCALAPPDATA%\FiveM for GTAV Enhanced\` (Enhanced).
- `view::game` has `PE_EXTENSIONS`, the ten extensions I3 treats as an executable's (`exe`, `dll`, `sys`,
  `scr`, `com`, `cpl`, `ocx`, `drv`, `efi`, `mui`).
- The anchors of a session are `FiveM.exe` and, for Legacy, `FiveM_b…_GTAProcess.exe`
  (`session::anchor_name`). `GTA5.exe`, `GTA5_Enhanced.exe` and `PlayGTAV.exe` are neither anchors nor
  candidates (`game::is_timeline_name`). SS mode lists a candidate by name when one of I1–I4 is true
  (`has_identity_fact`); the ordering counts R and I1–I4 (`identity_rank`).

### Measured (2026-10-23, the Windows 11 PC of ADR 0080 and ADR 0081, build 26220, an elevated token)

A read-only PowerShell probe decompressed the 11 Prefetch files of the programs P5 names (2 `FiveM.exe`, 3
`FiveM_b…_GTAProcess.exe`, `GTA5_Enhanced.exe`, `PlayGTAV.exe`, 4 `rundll32.exe`; no `regsvr32.exe`),
mapped each volume to a drive, and read the first two bytes of each file it could open. Counts only; no
path was kept.

| Record | Entries | Outside¹, all files | Outside¹, an executable's extension | Outside¹, other extension, PE content |
|---|---|---|---|---|
| `FiveM.exe` (Enhanced folder) | 141 | 31 (`.ini`, `.log`, `.db`, …) | 0 | 0 |
| `FiveM.exe` (Legacy folder) | 354 | 6 | 0 | 0 |
| `FiveM_b…_GTAProcess.exe` × 3 | 126–130 | 1 each | 0 | 0 |
| `GTA5_Enhanced.exe` | 61 | 0 | 0 | 0 |
| `PlayGTAV.exe` | 50 | 3 | 1 (its own executable, in a game library) | 0 |
| `rundll32.exe` × 4 | 24–43 | 0 | 0 | 0 |

¹ Not below `\Windows\`, `\Program Files\` or `\Program Files (x86)\` on the system volume, nor below
FiveM's two program folders. NTFS metadata entries (`\$MFT`) are skipped.

Also measured: every one of the 11 lists holds exactly one `\Windows\System32\ntdll.dll` entry, on the
system volume. Inside FiveM's folders the lists are long (189 entries for `FiveM.exe`, 57–59 for the game
process) and hold PEs under other names (18 in FiveM's cache), so the last column cannot be read there.

## Decision

### 1. Which records (amends ADR 0078 step P5)

The Prefetch records whose executable name, compared without ASCII case, is one that
`game::is_timeline_name` accepts (`FiveM.exe`, `GTA5.exe`, `GTA5_Enhanced.exe`, `PlayGTAV.exe`,
`FiveM_b…_GTAProcess.exe`), `rundll32.exe` or `regsvr32.exe`. No other record is counted.

### 2. Expected folders

The **system volume** of a record is the `\VOLUME{…}` prefix of its `\Windows\System32\ntdll.dll` entry
(every Windows process loads that file). An entry is **expected** when it is below `\Windows\`,
`\Program Files\` or `\Program Files (x86)\` on the record's system volume, or below one of FiveM's two
program folders as `fivem_edition::of_path` reads them, on any volume. An entry with no `\VOLUME{…}` prefix,
and NTFS metadata (`\$…` at a volume's root), are skipped. Every other entry is **outside**. Nothing here
calls the host: the record's own list decides.

A record with no `ntdll.dll` entry, or with more than one on different volumes, has no system volume; its
count is not emitted and `loaded_outside` is replaced by `loaded_outside_unknown: "no_system_volume"`.

### 3. The count, standard tier (owner question 1)

On the `prefetch` observation of each record in section 1:

- `loaded_outside`: how many outside entries have an extension in `PE_EXTENSIONS`. That list moves to one
  place both crates use (one list, one name).

Nothing else of `loaded_files` is emitted: no path, file name, extension or volume.

### 4. Not in this step: reading content (owner question 4)

ADR 0078 step P5's second count, a name that is not an executable's on a file whose content is a PE, needs
each outside entry's content: a full-tier read through `content_kind`, a map from Prefetch's volume serial
to a drive letter (`Host::file_id` returns a drive root's serial; its low 32 bits are the ones Prefetch
writes, measured with `fsutil` and `vol`), a budget beside ADR 0079's 90 seconds, and amending ADR 0078
section 8 (a loaded file was not recorded running). On the measured PC it found nothing outside FiveM's
folders. It is left to a later step with its own decisions, after P7 measures more PCs.

The join ADR 0078 section 4 describes (a Prefetch record to a path through its own entry) is also not in
this step; P1's join by file name stays.

### 5. In the view: fact L1 (amends ADR 0078 sections 5 and 9; owner questions 2 and 3)

| Group | Fact | Ordinary causes the text names |
|---|---|---|
| identity | **L1** it loaded a file with an executable's extension from outside Windows, Program Files and FiveM's folders | an add-on, overlay or codec installed in a user folder |

For one record: **true** when `loaded_outside` is above zero; **false** when it is zero; **not known**
when it was not emitted or there is no record. The text for "false" says what was looked at: "of the files
Prefetch recorded for it, none with an executable's extension is outside these folders". Its locale strings
come with the other facts' text in P6.

- **Candidates** (`rundll32.exe`, `regsvr32.exe`): the view keeps `loaded_outside` from the Prefetch
  observation a candidate is made from or joins (P1's name join). When several join, true if any is true,
  false only if every one is false. L1 counts in `identity_rank` and `has_identity_fact` like I1–I4, so SS
  mode lists an L1 candidate by name.
- **Sessions**: a record whose `prefetch` observation carries `fivem_edition` feeds the session of that
  edition that one of its `run_times` falls in: at or after the session's start and, when the session has a
  recorded end, at or before it. A latest session with no recorded end takes every run time after its
  start; an earlier session, whose end is never known, is "not known". The session row shows L1 with the
  rule above over the records that feed it, as a count, no names, in both modes. No record becomes an
  anchor and no session bound changes (ADR 0062). The records that carry `fivem_edition` are `FiveM.exe`,
  Legacy's game process, and the Enhanced game process when FiveM starts it from its game cache (owner
  question 2); a record without it (a GTA V executable in a game library) is counted on its own
  observation and feeds no row.

### 6. `PRIVACY.md`

The Prefetch section adds: for the programs in section 1, one number is now derived from the list of files
Prefetch recorded — how many of them have an executable's extension and are outside Windows, Program Files
and FiveM's folders; the list itself still never leaves the program. No consent text changes: the files
read are the same.

## Owner questions

1. **Count in a standard scan** (section 3). Recommended: **yes** — string checks on a list the collector
   already holds, no host call, 0 on every measured FiveM, game and `rundll32.exe` record. Alternative: a
   full scan only.
2. **The Enhanced game process feeds the Enhanced session's row** (section 5). Recommended: **yes** — FiveM
   starts it from its own game cache, so its `fivem_edition` is Enhanced; it stays out of the anchors, so
   ADR 0062 decision 11 is unchanged. ADR 0062 measured that its Prefetch file was not rewritten during a
   session, so it may fall in no session and add nothing. Alternative: anchors only (`FiveM.exe`, and
   Legacy's game process).
3. **L1 lists a name in SS mode and counts in the ordering** (section 5). Recommended: **yes**, like I1–I4.
   Alternative: a label only, outside `has_identity_fact` and `identity_rank`.
4. **Leave the content read to a later step** (section 4). Recommended: **yes** — it brings a drive map, a
   new full-tier budget and an amendment of ADR 0078 section 8, and found nothing on the measured PC.
   Alternative: build it in this step as a new full-tier collector with 30 seconds of its own (the full
   scan's file reads grow from 90 to 120 seconds, amending ADR 0079 owner decision 1 and amendment 7).

## Alternatives weighed

| Alternative | Why not |
|---|---|
| Count every file outside Windows and Program Files, as ADR 0078 step P5 wrote it | 6–31 per ordinary `FiveM.exe`, and 57–189 more inside FiveM's folders |
| Treat the program's own folder as expected | A folder holding the program says nothing about the other files in it |
| Treat `\Windows\` on any volume as expected | The record's `ntdll.dll` entry names its system volume without a host call |
| A new list of executable extensions | `PE_EXTENSIONS` already says what I3 treats as an executable's; two lists would drift |
| Emit the outside entries' paths, redacted | ADR 0021: the redactor cannot reach `\VOLUME{…}` paths, and a list of loaded files describes what is on the PC |

## What is unverified

- Whether Prefetch records every file a program loaded or only those in its first seconds; the measured
  lists held data files beside DLLs.
- `regsvr32.exe`: the measured PC had no Prefetch file for it. A Windows 10 PC (Prefetch version 30), a
  second PC, and a FiveM folder outside `%LOCALAPPDATA%` were not measured.
- How many outside entries a normal evening gives on other PCs; P7's baseline measures it.

## Consequences

- `rongroi-collectors`: `prefetch` gains `loaded_outside` (or `loaded_outside_unknown`) on section 1's
  records; `PE_EXTENSIONS` moves where both crates read it.
- `rongroi-core`: `view::game_windows` gains L1 on candidates and session rows; `identity_rank` and
  `has_identity_fact` count it.
- `PRIVACY.md`, `docs/architecture.md` (the `prefetch` row). No new collector, no consent change.
- The parser is unchanged: `loaded_files` and `volumes` still leave it only into the collector.
