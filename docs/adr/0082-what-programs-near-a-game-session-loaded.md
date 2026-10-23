# ADR 0082 — What programs near a game session loaded

- Status: proposed — six owner questions below; nothing is built
- Date: 2026-10-23
- Related: ADR 0019 (reading file bytes), ADR 0021 (the Prefetch collector; `loaded_files` and `volumes`
  are withheld), ADR 0052 (scan tiers), ADR 0061 (trace ages), ADR 0062 (FiveM sessions and editions),
  ADR 0078 (programs recorded near a game session, sections 4, 5 and 9, decision D5, step P5), ADR 0079 (the
  file a recorded program ran from), ADR 0080 (UserAssist, `recorded_files`'s fourth source), ADR 0081
  (path digests)
- Amends: ADR 0021 (two counts derived from `loaded_files`, and the volume serials in `volumes` compared
  inside a collector; no path, name or serial is emitted), ADR 0078 section 5 (a new fact, L1, and the
  ordering), section 8 (a file Prefetch recorded as loaded is read, though it was not recorded running),
  section 9 (L1 lists a candidate's name in SS mode) and step P5 (what is counted), ADR 0079 owner
  decision 1 and amendment 7 (the full scan's file reads grow from 90 to 120 seconds)

## Context

ADR 0078 step P5 asks, for `FiveM.exe`, the game process, `rundll32.exe` and `regsvr32.exe` only: how many
files in Prefetch's loaded-file list are outside Windows and Program Files, and how many have a name that
is not a DLL's but content that is a PE; never a path (ADR 0021 stays). A cheat that is loaded rather than
run — a DLL placed beside the game, or passed to `rundll32.exe` under an image's name — leaves its path in
that list.

What the code holds today (`dev` at `38d590c`):

- `rongroi_parsers::prefetch` returns `loaded_files` (the files Prefetch recorded for the program, each as
  `\VOLUME{…}\…`) and `volumes` (each volume's `device_path`, 32-bit `serial` and creation time). The
  `prefetch` collector (standard tier) emits neither and says so in `loaded_files_withheld`.
- One value is already derived from `loaded_files` inside the collector and emitted as a word, never a
  path: `fivem_edition::of_prefetch`, the edition of the executable's own entry. It returns the edition
  only, not the entry.
- `fivem_edition::of_path` knows FiveM's two program folders: `%LOCALAPPDATA%\FiveM\` (Legacy) and
  `%LOCALAPPDATA%\FiveM for GTAV Enhanced\` (Enhanced).
- `Host::file_id(path)` returns, among other things, the volume's 64-bit serial (`FileIdInfo`), and accepts
  a drive root. No host call maps a volume to a drive letter. ADR 0021 said comparing serials "would be a
  new host capability and its own ADR"; `file_id` (ADR 0047) has since made it an existing capability, and
  this is the ADR.
- `recorded_files` (ADR 0079, full tier) reads the content of files that BAM, PCA, `process` and UserAssist
  (ADR 0080) recorded, through `content_kind` (P2), refusing `rongroi_host::is_refused_form` paths (an
  alternate data stream, a `..` segment) before reading. ADR 0079 owner decision 1 allowed 30 seconds per
  collector, up to 90 seconds in a full scan; amendment 7 gave all 90 to `recorded_files`. It does not read
  `loaded_files`.
- In the view, the anchors of a session are `FiveM.exe` and, for Legacy, `FiveM_b…_GTAProcess.exe`
  (`session::anchor_name`). `GTA5.exe`, `GTA5_Enhanced.exe` and `PlayGTAV.exe` are neither anchors nor
  candidates (`game::is_timeline_name`). SS mode lists a candidate by name when one of I1–I4 is true
  (`has_identity_fact`); the ordering counts R and I1–I4 (`identity_rank`).
- ADR 0078 section 4's join of a Prefetch record to a path through its own entry was never built; P1's join
  by file name is still in place.

### Measured (2026-10-23, the Windows 11 PC of ADR 0080 and ADR 0081, build 26220, an elevated token)

A read-only PowerShell probe decompressed the 11 Prefetch files of the programs P5 names (2 `FiveM.exe`, 3
`FiveM_b…_GTAProcess.exe`, `GTA5_Enhanced.exe`, `PlayGTAV.exe`, 4 `rundll32.exe`; no `regsvr32.exe`),
mapped each volume to a drive by its serial, and read the first two bytes of each file it could open.
Counts only; no path was kept.

| Record | Entries | Outside¹, all files | Outside¹, executable extension | Outside¹, other extension but PE content |
|---|---|---|---|---|
| `FiveM.exe` (Enhanced folder) | 141 | 31 (`.ini`, `.log`, `.db`, …) | 0 | 0 |
| `FiveM.exe` (Legacy folder) | 354 | 6 | 0 | 0 |
| `FiveM_b…_GTAProcess.exe` × 3 | 126–130 | 1 each | 0 | 0 |
| `GTA5_Enhanced.exe` | 61 | 0 | 0 | 0 |
| `PlayGTAV.exe` | 50 | 2 | 0² | 0 |
| `rundll32.exe` × 4 | 24–43 | 0 | 0 | 0 |

¹ Not below `\Windows\`, `\Program Files\`, `\Program Files (x86)\` or FiveM's two program folders, and not
the program's own executable. Entries naming NTFS metadata (`\$MFT`) are skipped.
² The launcher's own executable, in a Steam library, is its own entry and is not counted.

Inside FiveM's folders the same counts are large on an ordinary PC: `FiveM.exe` touches 189 files there and
the game process 57–59 (its resources' `.lua` and `.js`), and FiveM keeps 18 PEs under other names in its
cache (14 `.bin`, 2 with no extension, 2 `.exe_<sha1>`). Two more facts were measured: the low 32 bits of
the system drive's 64-bit NTFS serial (`fsutil fsinfo ntfsinfo`) are the serial `vol` shows and Prefetch
writes in `volumes`; and every entry's volume mapped to a drive. (The values are not recorded here: a volume
serial identifies one Windows installation, ADR 0021.)

## Decision

### 1. Which records (amends ADR 0078 step P5)

The Prefetch records whose executable name, compared without ASCII case, is `FiveM.exe`, `GTA5.exe`,
`GTA5_Enhanced.exe`, `PlayGTAV.exe`, `FiveM_b…_GTAProcess.exe` (the names `game::is_timeline_name`
accepts), `rundll32.exe` or `regsvr32.exe`. No other record is counted.

### 2. Expected folders, and the own entry

An entry is **expected** when the part after its `\VOLUME{…}` prefix is below `\Windows\`,
`\Program Files\` or `\Program Files (x86)\`, or below one of FiveM's two program folders as
`fivem_edition::of_path` reads them (any profile). An **own entry** is any entry whose last segment is the
record's executable name, compared without ASCII case, wherever it is and however many there are; a new
`fivem_edition` function returns them, and `of_prefetch`'s edition rule is unchanged. An entry with no
`\VOLUME{…}` prefix, and NTFS metadata (`\$…` at a volume's root), are skipped. Every other entry is
**outside**.

The volume is not considered in this section: the folder names alone decide, so the standard tier makes no
host call.

### 3. Counted by name, standard tier (owner questions 1 and 2)

On the `prefetch` observation of each record in section 1:

- `loaded_outside`: how many outside entries have an executable's extension: `.dll`, `.exe`, `.sys`,
  `.drv`, `.ocx`, `.cpl`, `.mui`, `.ax`, `.efi`, `.scr`, `.node`, `.tlb`. Measured: 0 on all 11.

Nothing else is emitted by `prefetch`: no path, file name, extension or serial. Outside entries with other
extensions (0–31 measured) are counted only through their content (section 4).

### 4. Read by content, full tier: `prefetch_loaded` (owner questions 3 and 4)

A new collector, `prefetch_loaded`, full tier (ADR 0052 section 1; ADR 0078 decision D5), parses the Prefetch files of
section 1's records again and, for each record, considers its outside entries whose extension is **not**
an executable's:

1. **Resolving.** The entry's `\VOLUME{…}` prefix is matched, without ASCII case, against the record's
   `volumes[].device_path`; that volume's `serial` is compared with the low 32 bits of the
   `volume_serial` that `Host::file_id` returns for a drive root. The system drive (`%SystemDrive%`) is
   probed first; another letter, `A:` to `Z:` in order, only while an entry's serial is still unmatched,
   each probe at most once per scan and only while the budget lasts. `Ok(None)` is no drive; an error
   leaves that drive unknown. A serial that matches exactly one drive resolves the entry to that drive plus
   the part after the prefix. No match, more than one match, or a prefix not among `volumes` leaves the
   entry **unread**.
2. **Refusing.** A resolved path that `rongroi_host::is_refused_form` refuses is unread, not read.
3. **Reading.** `Host::read_file`, then `content_kind::parse`. A PE kind is **disguised**. Not found,
   refused by the system, or too large (`TooLarge`, above 64 MiB) is **unread**; any other kind is not
   counted.
4. **Budget.** 30 seconds for the collector, drive probes included, checked between host calls; a call
   already started finishes, so one slow read or probe can overrun it, as ADR 0079 records for
   `recorded_files`. Records are taken in ADR 0079 owner decision 2's order (nearest to the collector's
   newest FiveM or GTA V record first, which here is that record itself), entries in the file's order. When
   the budget ends, every entry not yet read is unread, and each record it cut short or never reached gets
   its observation with `read: "budget_spent"`.
5. **Outcomes.** Not Windows, `%SystemRoot%` unset, the Prefetch folder absent or not listable, and a
   `.pf` file that cannot be read or decoded are classified as `prefetch` classifies them (ADR 0021
   "Failure classification"), so a full scan says why nothing was counted.

Entries inside FiveM's folders are not read: 18 PEs under other names are FiveM's normal cache, so a count
there would never be zero (owner question 4).

One observation per record: `path` (the `.pf` path, joining the `prefetch` observation), `name`,
`loaded_disguised`, `loaded_unread`, and `read`. Nothing else.

**Budget (amends ADR 0079 owner decision 1):** the full scan's file reads grow from 90 seconds
(`recorded_files`) to 120.

### 5. In the view: fact L1 (amends ADR 0078 sections 5 and 9; owner question 5)

| Group | Fact | Ordinary causes the text names |
|---|---|---|
| identity | **L1** it loaded a file with an executable's extension from outside Windows, Program Files and FiveM's folders, or a file whose name is not an executable's but whose content is | an add-on or overlay installed in a user folder, a codec |

For one Prefetch record: **true** when `loaded_outside` or `loaded_disguised` is above zero; **false** when
`loaded_outside` is zero and `prefetch_loaded` read the record with `loaded_disguised` and `loaded_unread`
both zero; **not known** otherwise (a standard scan, unread entries, `budget_spent`, or no record).

- **Candidates** (`rundll32.exe`, `regsvr32.exe`): the Prefetch observation the candidate was made from or
  joined (P1's join by file name, unchanged), and the `prefetch_loaded` observation with the same `.pf`
  `path`. When several join, true if any is true, false only if all are false. L1 counts in `identity_rank`
  and `has_identity_fact` like I1–I4, so SS mode lists an L1 candidate by name.
- **Sessions**: a record whose `prefetch` observation carries `fivem_edition` (its own entry is below that
  edition's FiveM folder: `FiveM.exe`, Legacy's game process, and the Enhanced game process FiveM starts
  from its game cache) feeds the session of the same edition whose "during" window (ADR 0078 section 3)
  holds one of its `run_times`. Only the latest session has a "during" window, so only its row shows L1;
  earlier sessions say "not known". The row shows L1 with the same rule over the records that feed it, as
  counts, no names, in both modes. No record becomes an anchor: ADR 0062's anchors and session bounds are
  unchanged. A record without `fivem_edition` (a GTA V executable in a game library) is counted on its own
  observation and feeds no row in this step.

### 6. Consent and `PRIVACY.md`

Standard: `prefetch` already reads these files; `PRIVACY.md` adds that one count is derived from the
withheld list for the programs in section 1. Full: `prefetch_loaded` reads the content of files Prefetch
recorded as loaded by those programs, and each drive root's identifier; it joins the full-tier consent item
in the CLI (`full_reads`) and the desktop (`FULL_TEXT`), and `PRIVACY.md`.

## Owner questions

1. **Count by name in a standard scan** (section 3). Recommended: **yes** — string checks on a list the
   collector already holds, no host call, 0 on every measured record. Alternative: count only in a full
   scan.
2. **Which extensions are an executable's** (section 3). Recommended: the twelve listed. Alternative:
   `.dll` and `.exe` only, as ADR 0078 step P5 wrote it; then a `.sys` or `.ocx` outside the expected
   folders is seen only by a full scan's content read.
3. **Where content is read** (section 4). Recommended: **a new full-tier collector, `prefetch_loaded`, with
   30 seconds of its own** (full scan reads 90 → 120 s, amends ADR 0079 decision 1) — it emits counts per
   record, while `recorded_files` emits a row per file with a path. Alternative: a fifth source inside
   `recorded_files`' 90 seconds, which shares that budget with the files that ran.
4. **FiveM's own folders** (section 4). Recommended: **not read** — FiveM's cache holds 18 PEs under other
   names on an ordinary PC. Alternative: count them separately, a number that is never zero.
5. **L1 lists a name in SS mode and counts in the ordering** (section 5). Recommended: **yes**, like I1–I4.
   Alternative: a label only, outside `has_identity_fact` and `identity_rank`.
6. **Joining Prefetch by the own entry's path** (ADR 0078 section 4). Recommended: **not in this step**.
   ADR 0078 section 4 placed this join inside the collector, but the paths it joins are other collectors'
   output, which a collector cannot see; the join can only be made in the view, from an emitted value. The
   only value that keeps the path's text out is a
   `path_digest` (ADR 0081's form) on **every** Prefetch record in a standard scan, a stable value that
   links reports and lets anyone who guesses a path (with its profile name) confirm it. The name join stays.
   Alternative: emit that digest now, listed as a further amendment of ADR 0021.

## Alternatives weighed

| Alternative | Why not |
|---|---|
| Count every file outside Windows and Program Files, as ADR 0078 step P5 wrote it | 6–31 per ordinary `FiveM.exe`, and 57–189 more inside FiveM's folders |
| Treat the program's own folder as expected | A folder's name says nothing about the files placed in it; on the measured PC it excused nothing but the executable itself |
| Expect `\Windows\` only on the system volume | Needs the drive map in the standard tier |
| Emit the outside entries' paths, redacted | ADR 0021: the redactor cannot reach `\VOLUME{…}` paths, and a list of loaded files describes what is on the PC |
| Emit the volume serial | ADR 0021: it identifies one Windows installation across reports |
| A new host call for the 32-bit serial | `Host::file_id` already returns the 64-bit serial, whose low 32 bits are the one Prefetch writes (measured with `fsutil` and `vol`) |

## What is unverified

- That `FileIdInfo`'s `VolumeSerialNumber` is the 64-bit serial `fsutil` shows; measured with `fsutil` and
  `vol`, not through `Host::file_id`.
- Whether `Host::file_id` on a FAT32, exFAT or network drive root returns, fails, or blocks; section 4
  probes such a root only while an entry's serial is still unmatched.
- Whether Prefetch records every loaded file or only those touched in the program's first seconds; the
  measured lists held data files beside DLLs.
- `regsvr32.exe`: the measured PC had no Prefetch file for it. A Windows 10 PC (Prefetch version 30), a
  second PC, and a FiveM folder outside `%LOCALAPPDATA%` were not measured.
- How many outside entries a normal evening gives on other PCs; P7's baseline measures it.

## Consequences

- `rongroi-collectors`: `prefetch` gains `loaded_outside`; `fivem_edition` gains the own-entry function; a
  new full-tier collector `prefetch_loaded`, registered in `all()` with everything that list is tied to
  (the ages set, `CONSENT_WORDS`, the locale name, snapshots, `budget_spent` owners, rules-reference, a
  baseline entry or its absence noted).
- `rongroi-core`: `view::game_windows` gains L1 on candidates and session rows; `identity_rank` and
  `has_identity_fact` count it.
- CLI and desktop consent text, `PRIVACY.md`, `docs/architecture.md`.
- The parser is unchanged: `loaded_files` and `volumes` still leave it only into collectors.
