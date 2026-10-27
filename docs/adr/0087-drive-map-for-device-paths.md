# ADR 0087 — A drive map for BAM's and Prefetch's device paths

- Status: proposed — the owner questions in "Owner questions" are open; nothing is built
- Date: 2026-10-27
- Related: ADR 0010 and AGENTS.md hard rule 5 (SS mode redacts paths), ADR 0021 (the Prefetch collector;
  `volumes` withheld as a machine identifier), ADR 0023 (the BAM collector; a path that is not drive-rooted
  is withheld), ADR 0049 (which folders SS mode treats as a profile root), ADR 0078 (programs recorded near
  a game session; "P7 decisions" item 3), ADR 0079 (`recorded_files`), ADR 0081 (`volume_path_digest`),
  ADR 0082 section 4 (the drive map it left for later), ADR 0084 (rule 9 applied), ADR 0086 (I5)
- Amends, if accepted: ADR 0023 "The path is withheld unless it is drive-rooted" (a mapped path is
  drive-rooted and is emitted); ADR 0078 "P7 decisions" item 3 (the drive map is this ADR)

## Context

The game-window view (ADR 0078) lists a program recorded near a session as a candidate and shows its
identity facts I1 to I4 from `recorded_files` (ADR 0079), which reads the file at the program's path. Both
need a drive-rooted path: `recorded_files` keeps drive-rooted paths only, and SS mode's redactor,
`rongroi_core::view::redact_profile_paths`, recognises a profile only after a drive letter (ADR 0049).

The lab replay of P7 (ADR 0078, "As built: P7, lab part") measured on Windows 11 build 26300 that:

- **BAM** names a program as `\Device\HarddiskVolumeN\…`. ADR 0023 had left this unverified; `bam` withholds
  it (`path_withheld: "unredactable_form"`).
- **Prefetch**'s string table names files as `\VOLUME{<creation time>-<serial>}\…`. `prefetch` emits neither
  the list nor the volumes (ADR 0021); the program's own entry gives only its edition (ADR 0062).

So a program known only from BAM or Prefetch has no path, and its I1 to I4 are "not known: no path". That is
the case I1 is for: a program run and then deleted is, by definition, not in the process list, and PCA and
UserAssist record only some programs. In the lab's `downloaded-program-with-its-zone` scenario the same
`tool.exe` was listed twice, once with its path from another source and once from BAM with no path.

Two facts already in the code bound the problem:

- `rongroi_core::digest::volume_path_digest` (ADR 0081) compares two paths without their volume, so Code
  Integrity's `\Device\HarddiskVolumeN\…` can be matched to a candidate's `X:\…`. It answers "the same path
  on some volume", never which volume, and cannot open a file.
- `Host::file_id` returns a drive root's volume serial; ADR 0082 measured that its low 32 bits are the serial
  Prefetch writes in `\VOLUME{…}`.
- **ADR 0081 declined this map once**, for a narrower purpose: joining Code Integrity's events to a
  candidate, where the volume-relative digest is enough and a new host call was "a small gain". I1 to I4 are
  not a join: `recorded_files` has to open the file, which needs a path Windows can open. ADR 0081's other
  reason, that a mount point can give one volume several paths, is why section 1 maps letters only.

## Decision

### 1. The map: drive letters as Windows names them now

A new host call, `Host::drive_map`, lists the drive letters present at scan time. For each letter it gives:

| Field | From | Leaves the collector? |
|---|---|---|
| `letter` | `GetLogicalDrives` | yes, as part of a mapped path |
| `device` (`\Device\HarddiskVolumeN`) | `QueryDosDeviceW("X:")` | **no** |
| `serial` (low 32 bits) | `Host::file_id` of the drive root, the call ADR 0082 measured | **no** |
| `kind` (fixed, removable, other) | `GetDriveTypeW` | no; used by item 3 |

It is read once per scan, needs no administrator rights, and reads no file. A letter whose device is not
`\Device\HarddiskVolume<digits>` (a network drive, a `subst` drive, an optical drive with no disc) is left
out. A volume with no letter (mounted on a folder, or not mounted) has no entry, and a volume that also has a
folder mount point is mapped to its letter only.

`device` and `serial` are machine identifiers (ADR 0021: a serial and a creation time name one volume across
reports). They stay in memory between the host call and the collector, as Prefetch's `volumes` do today, and
never reach a field, a log line, an error text or a snapshot. Two things make that testable rather than
promised: `drive_map`'s errors are fixed messages, like `REFUSED_FORM_MESSAGE`, never a `format!` of a device
name or serial (`SourceError::Unsupported` holds free text); and the map's type writes its own `Debug`, which
prints the letter and kind only. The fixture host gets a `drive_map:` list so tests can say what a machine
has.

### 2. Where the map is used

`crate::paths::map_device_path(map, path) -> Option<String>`, one function beside `is_drive_rooted`:

- `\Device\HarddiskVolumeN\rest` → `X:\rest` when exactly one entry's `device` is `\Device\HarddiskVolumeN`
  (ASCII case ignored, the whole number compared, so `…Volume1` never matches `…Volume12`);
- `\VOLUME{<anything>-<serial>}\rest` → `X:\rest` when exactly one entry's `serial` equals `<serial>`
  (lowercase hex, 8 digits). Two letters with one serial (a cloned disk) give no match; the creation time in
  `\VOLUME{…}` is not compared, because `Host::file_id` does not return one;
- anything else, or no match, or two matches → `None`.

The callers, in order of work:

- **M1, BAM.** `bam` maps before `insert_path`: a mapped path is emitted as `path`, with
  `path_from_device: true`; an unmapped one keeps `path_withheld: "unredactable_form"`.
  `bam::recorded_paths` maps the same way, so `recorded_files` reads the file and the view joins it by path as
  it does a PCA or UserAssist path. The view's code does not change for M1, but what it shows does: a BAM
  record with a path is merged by path with the other sources (ADR 0078 section 4), so a BAM-only program can
  reach I1 and I4, Prefetch's join by file name (`gather`) can now land on it, the path digest joins install
  and Code Integrity events to it (ADR 0081), and a candidate with I1 true is named in SS mode (ADR 0078
  section 9). `recorded_files` reads the newly mapped files' hash, signature and zone stream, inside its
  existing 90 seconds.
- **M1 also reaches one rule.** `bam` computes `disappeared_from_disk` only for a drive-rooted path whose
  location `is_ephemeral_candidate` accepts (a folder such as Temp or Downloads, or a drive other than the
  system drive), and then asks `host.times`. A device path never got there. Mapped, a BAM path under Temp or
  Downloads, or on a fixed non-system letter, can set the field, and
  `rules/bam/ephemeral/executed-program-missing-on-disk` (experimental, `strength: context`) can match it. No
  rule matches `bam`'s `path`: `NAME_ONLY_COLLECTORS` refuses a `path` match on `bam` outside timeline rules.
  M1 also corrects `bam.rs`'s module comment, which still says no rule reads the collector.
- **M2, Prefetch's own entry.** `prefetch` maps the executable's own string-table entry (the one whose last
  segment is the record's executable name, as `fivem_edition::of_prefetch` finds it; when more than one entry
  has that name, none is mapped) and emits it as `program_path`,
  with `path_from_device: true`. The rest of `loaded_files`, and `volumes`, stay withheld (ADR 0021 is
  unchanged for them). The view then joins a Prefetch record by `program_path` instead of by name alone
  (ADR 0078 section 4's join, which ADR 0082 section 4 deferred), and `recorded_files` gains Prefetch as a
  fifth source.

### 3. A device number can name another volume later

`\Device\HarddiskVolumeN` is given when a volume arrives. BAM keeps a value for days; if a USB drive was
removed and another volume arrived since, `N` may now name that other volume, and the mapped path would point
at a file that never was the program. For I1 ("its file is no longer at the recorded path") that is a false
`true`.

- A **Prefetch** path is mapped by serial, which belongs to the volume, not to its arrival order. It is not
  affected.
- A **BAM** path is mapped only to a letter of `kind` fixed. A removable letter's BAM paths stay withheld.
  `GetDriveTypeW` is what Windows says, not what the disk is: a USB disk Windows reports as fixed passes.
  Probe M0 measures whether fixed volumes keep their number across a restart, across a disk added, and
  across a disk removed and returned; if they do not, M1 waits for an amendment.
- `path_from_device: true` stays on the observation so a reader of the report knows Windows wrote a device
  path and the letter is today's.

### 4. Redaction

A mapped path is drive-rooted, so it reaches SS mode by the route a PCA path takes: `redact_profile_paths`
with ADR 0049's profile roots. In SS mode a BAM observation no rule matched is counted, not listed (ADR 0014);
a mapped path is shown when a rule matches it or when the game-window view names its candidate. The shapes
`redact_profile_paths` does not reach (listed in `PRIVACY.md` since 0.4.0: a profile moved for one account
on its own, some 8.3 short names) reach SS mode through this route as they already do through PCA's; the map
adds a route, not a shape. Prefetch writes paths in capitals (`X:\USERS\<ACCOUNT>\…`); the redactor already
matches `Users` in any ASCII case and replaces the name after it, and a test proves it for a mapped Prefetch
path. Nothing about the map itself is shown in SS mode or in a standard report beyond the letter in the path.

### 5. What does not change

- `volume_path_digest` stays for Code Integrity (ADR 0081); it needs no volume.
- No new tier: the map reads no file and no registry key. `recorded_files` stays `full`.
- No new vocabulary for "no letter": `unredactable_form` is still true of a path the map could not turn into a
  drive-rooted one.

## Tests

- `map_device_path`: each accepted shape; `Volume1` against `Volume12`; two entries with one device or one
  serial (→ `None`); a serial of another length; a letter of kind removable for a device path (→ `None`).
- `drive_map`: its error messages are the fixed ones, and its `Debug` output holds no device name or serial.
- `bam`: `disappeared_from_disk` for a mapped path under Temp with the file gone, and the fixtures of
  `executed-program-missing-on-disk` with a mapped path.
- Prefetch M2: two own-entries with the executable's name give no `program_path`.
- `bam` with a fixture `drive_map:`: a mapped path emitted with `path_from_device`; an unmapped one withheld;
  no field, error or `Debug` output of any observation contains `HarddiskVolume`, `\VOLUME{` or a serial
  (a test that walks every field of every observation, as ADR 0021's withholding tests do).
- `recorded_files` reads a mapped BAM path; the view's `renamed-program-run-then-deleted` case moves from
  "I1 not known, no path" to "I1 true".
- SS mode: a mapped path under `C:\Users\<account>\` and a mapped Prefetch path under `C:\USERS\<ACCOUNT>\`
  are both redacted.
- Lab replay: `renamed-program-run-then-deleted` expects I1 true for `helper.exe`; the
  `downloaded-program-with-its-zone` scenario lists `tool.exe` once.

## Order of work

1. **M0, probe** (the lab machine and a Windows 11 PC, read-only): `QueryDosDeviceW` for every letter, before
   and after a restart, after a second virtual disk is added, and after it is removed and added again; whether BAM's `N` for a program on `C:` stays
   the one `C:` maps to. Results go into this ADR as "Measured", with no device numbers or serials (public
   repo).
2. **M1, BAM** (section 2), with its tests, a CHANGELOG line, and the lab replay.
3. **M2, Prefetch's own entry**, after M1 is on `dev`.

Each step is its own PR into `dev`, written by an engineer run (AGENTS.md, delegated delivery).

## Owner questions

1. **Build the map at all** (sections 1–2). Recommended: **yes** — without it the run-then-deleted program,
   the case I1 exists for, never gets I1 to I4. Alternative: leave BAM- and Prefetch-only candidates
   path-less and say so in the view's text.
2. **BAM paths only on fixed letters** (section 3). Recommended: **yes** — a device number can be reused
   after a removable drive leaves, and a wrong path gives a false I1. Alternative: map every letter and accept
   the risk, with `path_from_device` as the only warning.
3. **Emit `path_from_device: true`** (section 3). Recommended: **yes** — the letter is today's, not the one
   Windows saw, and the report should say so. Alternative: emit the path with no marker.
4. **M2, Prefetch's own entry, in this ADR** (section 2). Recommended: **yes, after M1** — it is mapped by
   serial and so is the more reliable of the two, but it changes the view's Prefetch join and adds a source to
   `recorded_files`. Alternative: its own ADR later.
5. **M0 before M1** (order of work). Recommended: **yes** — section 3 rests on fixed volumes keeping their
   number, which is not measured. Alternative: build M1 and measure in the baseline on the owner's PC.

## Alternatives weighed

| Alternative | Why not |
|---|---|
| Widen the SS redactor to `\Device\…` and `\VOLUME{…}` paths | ADR 0021, 0023 and 0049 each declined it; it still leaves `recorded_files` unable to open the file, so I1 to I4 stay not known |
| Compare without the volume (`volume_path_digest`) for I1, as ADR 0081 does for Code Integrity | "Some file at this in-volume path exists on some volume" is not "the program's file is still there"; it cannot read the file for I2 to I4 |
| Emit `device` or `serial` so a reader can map it | A machine identifier in a public report format (ADR 0021) |
| Map at the time BAM wrote the value | Windows keeps no history of device names; nothing to read |

## What is unverified

- Whether a fixed volume keeps its `\Device\HarddiskVolumeN` across a restart, a disk added, and a disk
  removed and returned (probe M0).
- Whether BAM ever writes a drive-rooted path on other Windows builds (ADR 0023's question; M1 handles both).
- How often `executed-program-missing-on-disk` matches once mapped paths reach it (section 2). The lab
  replay in M1 shows it on the lab machine; the change goes in the CHANGELOG.
- Whether Prefetch's `PrefetchVolume`, which derives `Debug` with its serial, is ever printed. Nothing found
  prints it; it is outside this ADR.

## Consequences

- A program run from a fixed drive and then deleted gets I1 from BAM alone; one candidate per program where
  BAM and another source recorded it.
- Standard reports carry more BAM paths. In SS mode they are counted unless a rule or the game-window view
  shows them, and then redacted as every other path is.
- A removable drive's BAM-only program stays path-less, and says so.
- One new host call; the fixture host and every host implementation gain it.
