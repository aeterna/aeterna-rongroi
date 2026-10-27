# ADR 0085 — SRUM: whether it can be read, and what it would add near a game session

- Status: proposed — feasibility only; nothing is measured, built or decided. The owner's questions are
  in "Owner questions"
- Date: 2026-10-27
- Related: ADR 0019 (`read_file` and its 64 MiB limit), ADR 0021 (Prefetch; paths SS mode cannot reach),
  ADR 0023 and ADR 0049 (which paths SS mode redacts), ADR 0038 (one privilege, for one read), ADR 0041
  (Amcache feasibility, the model for this ADR), ADR 0052 (scan tiers), ADR 0054 (no record of network
  traffic is read), ADR 0078 (programs recorded near a game session, section 7 item 3, step P8), ADR 0084
  (rule 9)

## Context

ADR 0078 section 7 lists new sources for the game-window view. Its third item is "**SRUM**: a feasibility
ADR only, on the questions ADR 0041 answered for Amcache (a reader and its licence, a database that was not
shut down cleanly, recovery writes, the privacy seam), not only the file being held open". Its order of work
has step P8, "SRUM feasibility ADR", with no precondition. The owner's decision D4 of 2026-10-21 keeps SRUM
"as feasibility only". This is that ADR. **No collector code is part of it.**

Two earlier ADRs already mention SRUM:

- ADR 0054 (owner, 2026-09-17) decided that no record of where traffic went is read, SRUM among them. Its
  table says "Windows keeps the database open; reading it needs a shadow copy or the raw volume". That
  sentence was written without a measurement in this repository. This ADR treats it as unverified.
- `docs/research/03-pc-check-screenshare-tools.md` lists SRUM as "per-app resource use, including deleted
  binaries", kept "~30 days apps, ~60 days network", "locked database". No source is cited on that row.

Nothing in the code reads SRUM. A search of `crates/`, `docs/`, `PRIVACY.md`, `deny.toml` and
`clippy.toml` for `SRUM`, `SRUDB`, `ESENT`, `VSS`, `SeBackupPrivilege` and `PhysicalDrive` on `dev` at
`508ab46` finds only the documents above and ADR 0078.

Four questions decide whether a collector should exist:

1. Can this program read `SRUDB.dat` without changing anything on the machine?
2. Can the database be parsed safely, to this repository's standard for hostile input, including one that
   was not shut down cleanly?
3. What would it add to the game-window view, and what can it not say?
4. What may leave the parser, and what may SS mode show?

This ADR answers none of them with a measurement. It records what is known, what is not, and what the
owner must decide before anything is measured or built.

### What SRUM is

The System Resource Usage Monitor keeps its data in `%SystemRoot%\System32\sru\SRUDB.dat`, an Extensible
Storage Engine (ESE) database. The source for the layout below is Joachim Metz's knowledge base
([esedb-kb, *System Resource Usage Monitor (SRUM) database*](https://github.com/libyal/esedb-kb/blob/main/documentation/System%20Resource%20Usage%20Monitor%20(SRUM).asciidoc),
GFDL), read on 2026-10-27. It is a reverse-engineered description, not Microsoft's. Microsoft does not
document the file.

| Table | What a row holds (column names from the knowledge base) |
|---|---|
| `SruDbIdMapTable` | `IdType`, `IdIndex`, `IdBlob`. `IdType` 3 is "a user identifier (UserId)" and its blob "contains a Windows NT Security Identifier (SID)". Types 0–2 hold "an UTF-16 encoded string", their meaning marked unknown |
| `{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}`, Application Resource Usage | `TimeStamp`, `AppId`, `UserId`, foreground and background cycle time, `FaceTime`, context switches, bytes and operations read and written, flushes |
| `{5C8CF1C7-7257-4F13-B223-970EF5939312}`, description marked "TODO" | `TimeStamp`, `AppId`, `UserId`, `EndTime`, `DurationMS`, `SpanMS`, and timelines of focus, user input, audio, CPU, disk and network, among 44 columns |
| `{973F5D5C-1D90-4944-BE8E-24B94231A174}`, Network Data Usage | `TimeStamp`, `AppId`, `UserId`, `InterfaceLuid`, `L2ProfileId`, `L2ProfileFlags`, `BytesSent`, `BytesRecvd` |
| `{DD6636C4-8929-4683-974E-22C046A43763}`, Network Connectivity Usage | `TimeStamp`, `AppId`, `UserId`, `InterfaceLuid`, `L2ProfileId`, … |
| `{FEE4E14F-…}` and `{FEE4E14F-…}LT`, Energy Usage; `{D10CA2FE-…FA86}`, Push Notifications; `SruDbCheckpointTable` | not relevant here |

Every per-app row names its program and its account by index into `SruDbIdMapTable`. `TimeStamp` is an
OLE Automation date.

What this ADR does **not** know, from any source it read:

- **How often Windows writes to the file.** DFIR write-ups describe data gathered by a service and written
  to the database about once an hour. No primary source for that was read, and nothing was measured.
- **How long rows are kept.** The research note's "~30 days apps, ~60 days network" has no source.
- **What `TimeStamp` means for a row**: the end of the period it covers, the moment it was written, or
  something else. Not established.
- **Which process holds the file, and with which sharing mode.** Not established.
- **What the `AppId` strings look like**: a drive-rooted path, a `\Device\HarddiskVolumeN\…` path, a
  service name or a packaged app's id. The `sootmark-srum` crate's documentation says "a path, a service
  name or a packaged app's id". Its path shape was not read anywhere.
- **Which other files sit beside it in `sru\`** (checkpoint, transaction logs, reserved logs). ESE in
  general keeps "the checkpoint file and the transaction log files" beside its databases
  ([JetInit](https://learn.microsoft.com/en-us/windows/win32/extensible-storage-engine/jetinit-function)).
  The names in `sru\` were not listed.

## Question 1 — reading the database without changing anything

### What the repository already does

- `LiveHost::read_file` (`crates/rongroi-host-windows/src/filesystem.rs`, `read_file`) opens with
  `std::fs::File::open`: read access, all three sharing flags, no truncation. It reads at most
  `MAX_FILE_BYTES`, 64 MiB (`crates/rongroi-host/src/lib.rs`, ADR 0019), into memory. Nothing is copied to
  disk.
- **No collector reads a file Windows holds against reads.** There is no shadow copy, no raw-volume read and
  no `SeBackupPrivilege` in the code. `FILE_FLAG_BACKUP_SEMANTICS` appears once
  (`crates/rongroi-host-windows/src/usn_journal.rs`, `file_id`), with attribute-only access, because
  `CreateFileW` needs that flag to open a folder (ADR 0037 uses it for the same reason).
- `crates/rongroi-collectors/AGENTS.md` forbids writes "not even temporarily, not even 'to restore it
  afterwards'", and "Do not shell out to other programs".

### The ways in

#### A plain elevated read, into memory — the only path this repository allows

The same read every other collector does, through `FilesystemSource::read_file`. It works only if the
process holding `SRUDB.dat` shares it for reading. ADR 0041 measured the opposite case on a registry hive:
a held file refuses that open with error 32 (`ERROR_SHARING_VIOLATION`), and backup semantics with
`SeBackupPrivilege` enabled did not change that. Whether `SRUDB.dat` behaves like that hive is **not
measured**. ADR 0054's "Windows keeps the database open" is the expectation, not a result.

Two further limits, both **not measured**:

- whether the file fits under 64 MiB on an ordinary PC;
- whether a limited token can open it at all (ADR 0041 found `Amcache.hve` invisible to one).

The read never goes through ESE. The bytes are parsed by Rust code in this process, so nothing this
program does can start ESE recovery on the live file. The one risk to the machine is the open itself, and
a read-only open with every sharing flag does not stop Windows from writing (ADR 0041, the same open).

#### The ESE API (`esent.dll`) — ruled out

Microsoft documents that "Database crash recovery is performed automatically as a part of the
initialization process" and that, unless `JET_paramRecovery` is off, `JetInit` creates "the checkpoint
file and the transaction log files" ([JetInit](https://learn.microsoft.com/en-us/windows/win32/extensible-storage-engine/jetinit-function)).
Initialising an instance over the live database's logs would replay them or create new ones, which is a
write. The same page lists `JET_errDatabaseSharingViolation` among the errors of mismanaged files; whether
an instance with recovery off can attach a database another process holds was not established. It is also
`unsafe` FFI. Not run.

#### `esentutl` — ruled out

Starting another program is forbidden to collectors. Whatever `esentutl` can copy, it does so as another
process, and the copy it makes lands on disk. Its options were not read for this ADR.

#### Volume Shadow Copy — ruled out

For the reasons ADR 0041 gives: creating a snapshot changes the machine and leaves storage behind, and
deleting it is "restore it afterwards". Not run.

#### Reading the raw volume — out of scope here

An NTFS reader over attacker-controlled metadata, with its own ADR, and the flush side effect ADR 0041
quotes. Forensic collectors read locked files this way (the `sootmark-collector` crate describes itself as
reading "NTFS raw (locked files, …)"). Not examined, not run.

### Answer to Question 1

**Not known.** If Windows holds `SRUDB.dat` against reads, the only path this repository allows is closed,
and SRUM is out of reach without a new kind of read. If it does not, the read is the same plain elevated
read Prefetch already does. One read-only probe on one PC settles the first fact (owner question 1).

## Question 2 — parsing the database safely

### The bar

ADR 0041 states it, from ADR 0013, 0015, 0016 and 0018: pure bytes in, structs out; no panic, abort or hang
on any input; allocations bounded by the bytes available; walks over structures the file describes cannot
loop; a fuzz target in `fuzz smoke (ubuntu)` seeded with fixtures; `cargo deny check` passes. An ESE file
has the same hazards a regf hive has: page numbers, tag counts, record offsets, long-value chains and
B-tree child pointers all come from the file. It adds compressed values.

### Candidate crates

Seven crates were found on crates.io on 2026-10-27, at their newest versions. Their packaged source was
**read, not built and not run**. `cargo deny` was **not** run; the licence column was compared by hand with
`deny.toml`'s allow-list. Advisories were not checked. Line references are to the packaged source.

| Crate | Licence | First published | `unsafe` | Input | Dirty database | Logs replayed | What the reading found |
|---|---|---|---|---|---|---|---|
| `sootmark-ese` 0.1.1 (library name `ese`) | MIT OR Apache-2.0, on the allow-list | 2026-10-04 | `unsafe_code = "forbid"` (`Cargo.toml` `[lints.rust]`) | `&[u8]`, borrowed | the header state is parsed; dirty shutdown goes into `problems` (`header.rs`, around line 236) | no: "the transaction logs are not replayed" (`lib.rs:8`) | No dependencies. A visited set per tree walk reports a cycle (`btree.rs:63`). An Xpress value's output capacity comes from a `u16` size (`compression.rs:39`, `xpress.rs:62`). Damage is listed, not fatal, by its own documentation. No fuzz target in the package; `proptest` is a dev-dependency whose tests are not packaged. Three weeks old, two versions |
| `sootmark-srum` 0.1.0 | MIT OR Apache-2.0 | 2026-10-04 | none found | `&[u8]` (`lib.rs:208`) | through `sootmark-ese` | no | Built on `sootmark-ese` and `sootmark-common` 0.3.7 (MIT OR Apache-2.0). Reads every table and resolves `UserId` to a SID string (`id_map.rs`), which this ADR would not want to leave the parser |
| `ese-core` 0.2.2 | Apache-2.0 | 2026-06-13 | one: `unsafe { Mmap::map(&file) }` (`database.rs:132`) | a path, memory-mapped | state constant parsed (`header.rs:8`); no use outside tests found | no | Its own comment: modifying the file "while an `EseDatabase` is live" is "undefined behaviour". A live `SRUDB.dat` is a file Windows may write. It bypasses `read_file` and its limit. Recursion capped at depth 64 with a visited set (`database.rs`, `walk_leaf_pages_inner`) |
| `srum-parser` 0.4.0 | Apache-2.0 | 2026-06-13 | none found | a path (`lib.rs:72`) | through `ese-core` | no | Built on `ese-core` and `forensicnomicon`. No repository listed |
| `ese-parser` 0.1.0 | MIT | 2026-08-13 | none found | a path (`lib.rs:99`) | header log-generation fields only | no ("Recovery from a dirty shutdown" is a non-goal) | Header and raw pages only; B-tree walk and catalog are on its "v0.2 roadmap". Cannot read a table |
| `libesedb` 0.2.7 over `libesedb-sys` 0.2.1 | LGPL-3.0-or-later, not on the allow-list | 2022-06-02 | FFI to bundled C (`libesedb-20230824`) | a path, opened with `LIBESEDB_OPEN_READ` (`db.rs:30`) | in the C library, not read | not read | Out on licence and on `unsafe` outside `rongroi-host-windows`, as `hivex` was in ADR 0041. The most downloaded by far |

What the table says:

- **One crate has the shape this repository asks for**: `sootmark-ese`, bytes in, `forbid`, no
  dependencies, cycles caught, damage reported. It is three weeks old, its fuzzing is not visible in the
  package, and nothing above was run. Taking it means `cargo deny` in this workspace, a fuzz target here,
  and a review of the code at the commit taken, as ADR 0018 did for `evtx`.
- **`ese-core`, and `srum-parser` above it, are out** on the memory map: a mapped live file that Windows
  writes is the undefined behaviour its own comment names, and the path input skips `read_file`.
- **Writing a reader here is the other route.** It would read the catalog, two tables and the id map. Its
  hazards are the same as every ESE reader's. Its size is not estimated.
- **No crate ships a redistributable `SRUDB.dat`.** A fixture would be synthetic, written here from the
  documented layout, never a real person's database.

### A database that was not shut down cleanly

An ESE header carries a state; `sootmark-ese` names `DirtyShutdown` (2) and `CleanShutdown` (3), and says
of a dirty one that "changes still only in the transaction log files are missing". **Whether a live
`SRUDB.dat` read from a running PC is usually dirty is not known.** It is plausible, since the database is
in use, and that is exactly the case this ADR cannot settle without a probe. If it is dirty, the newest
rows, the ones nearest the scan, are the ones a reader of the main file alone may not see.

The options, as ADR 0041 laid them out for a hive:

| Option | Cost |
|---|---|
| Parse the main file and say nothing about its state | A "not recorded" over a dirty file may be false for its newest rows. Not acceptable (`docs/architecture.md`: "not found" about something never read "would be false") |
| **Parse the main file, report a dirty state as `partial`** | Honest. If live files are always dirty, every SRUM read is `partial`, and SS mode lists `partial` whatever a rule declares |
| Read the transaction logs too and replay them in memory | No candidate crate does it. A second parser, over files that may be held as well, read at different moments. Not estimated |

Recovery writes are **not a risk of any option above**: none goes through ESE, and none writes.

### Answer to Question 2

**Feasible as review-and-fuzz work on one young crate, or as writing work, and not with anything as
published.** A dirty database is detectable; making it complete is not on offer from any crate read.

## Question 3 — what SRUM would add to the game-window view, and what it cannot say

What it could add, if it can be read:

- **A record that a program used the CPU, the disk or the screen in a period**, per program and per
  account, from the Application Resource Usage table. ADR 0078's other sources record a start (Prefetch,
  PCA, UserAssist, a process's `started_at`) or an end (BAM). SRUM would record use across a period.
- **A record that does not depend on Prefetch.** Prefetch can be turned off (ADR 0037). Whether SRUM can be
  turned off, and what a PC with it off looks like, is not known.
- **A record that outlives the file**, according to the research note; not verified.

What it cannot say, from the layout alone:

- **When inside the period.** If rows are hourly, a row cannot place a program in ADR 0078's 30-minute
  "before" rather than "during" window. It can say the program was used in a period that overlaps one.
- **Anything about the last period before the scan**, if Windows writes only at intervals. ADR 0078's
  "before the scan" window (T4) is where SRUM would be blindest.
- **How the program started, what its file is, or whether it is signed.** No hash, no signature, no
  content. SRUM adds no identity fact (I1–I5) of its own; at most it adds a path for identity checks to
  look at.
- **Who used it.** `UserId` is an account, not a person.

Whether a period's row can be joined to a candidate depends on the `AppId` path shape. A
`\Device\HarddiskVolumeN\…` path would need the drive map ADR 0082 section 4 left for later, and SS mode
cannot redact that shape (ADR 0021, ADR 0023).

Nothing here vouches for a program (rule 9): a row is a time fact, never a reason to fold or hide a
candidate.

## Question 4 — the privacy seam

SRUM is about a month of everything the PC ran, per account, with network bytes per app and per network
profile. Almost none of it answers ADR 0078's question.

| Part | Proposed handling |
|---|---|
| Network Data Usage and Network Connectivity tables | **Never read.** ADR 0054's owner decision stands: no record of network traffic is read. `L2ProfileId` and `InterfaceLuid` can name networks the PC joined (unverified) |
| Energy, push-notification and checkpoint tables | Never read; nothing in ADR 0078 needs them |
| `SruDbIdMapTable` SIDs (`IdType` 3) | Never leave the parser, hashed or not, as for BAM (`PRIVACY.md`). At most: how many accounts had rows, and whether a row is the scanning account's |
| `AppId` strings | A path only when drive-rooted, the shape SS mode redacts (ADR 0023, ADR 0049); any other shape withheld, and the report says so |
| Per-app numbers (cycles, bytes read, `FaceTime`) | Not emitted. The view needs "used in this period", not how much |
| Rows outside any game window | Should not leave the collector. The collector does not know the windows today: sessions are computed in `rongroi-core` from other collectors' observations. That is a new seam, the same kind ADR 0041 found for hashes (owner question 6) |
| SS mode | ADR 0078 section 9 unchanged: a candidate is named only when an identity fact holds; SRUM adds none, so its rows show as counts per window |

The consent question and `PRIVACY.md` would name SRUM in the change that adds a collector. A month of
program use is the kind of read ADR 0052 put in the full tier.

### Elevation

`SRUDB.dat` sits under `System32`. Whether a limited token can list or open it is not measured. A collector
reports `not_admin` without elevation, as `prefetch` does (`crates/rongroi-collectors/src/failure.rs`), and
needs a reason for a held file. ADR 0041 found that `read_failed` is the nearest existing reason and that
`SourceError::from_io` maps error 32 to `Failed`, so a collector would have to recognise it itself.

## Owner questions

1. **D1, measure first.** A throwaway read-only probe, as ADR 0041 ran, on one Windows 11 PC and one
   GitHub-hosted Windows runner, elevated and limited: whether `SRUDB.dat` opens for reading with every
   sharing flag; its size against 64 MiB; the header's state field; the names in `sru\`; and, counts only,
   how many `AppId` strings are drive-rooted. No content leaves the PC.
   - Options: **A** measure; **B** park SRUM now, as ADR 0041 parked Amcache; **C** design without
     measuring.
   - Recommended: **A**. Every later question turns on whether the file opens.
2. **D2, if the file is held.**
   - Options: **A** park SRUM: no shadow copy, raw volume or ESE API; **B** open an ADR for a raw NTFS
     read, a new parser over attacker-controlled metadata.
   - Recommended: **A**. The raw read is larger than SRUM is worth to one view, and it is a new kind of read
     for the whole program.
3. **D3, the reader, if the file opens.**
   - Options: **A** take `sootmark-ese` after review at a pinned commit, `cargo deny` in this workspace and
     a fuzz target here; **B** write a reader for the catalog, two tables and the id map; **C** `libesedb`,
     which needs an LGPL decision and FFI.
   - Recommended: **A**, falling back to **B** if the review finds what ADR 0041 found in `notatin`.
4. **D4, a dirty database.**
   - Options: **A** detect it and report `partial`; **B** replay the transaction logs in memory.
   - Recommended: **A**. No crate replays; B is a second parser and needs the logs to open too. If D1
     finds live files always dirty, that is a reason to revisit D2, not to drop the state check.
5. **D5, which tables.**
   - Options: **A** Application Resource Usage and the id map only; **B** also `{5C8CF1C7-…}`, whose
     `EndTime` and `DurationMS` may give finer times; **C** every table.
   - Recommended: **A**, and **B** only if D1 shows `{5C8CF1C7-…}` present and its times finer. **C** is
     refused by ADR 0054.
6. **D6, how rows reach the view, and the seam.**
   - Options: **A** the collector is given the session windows and keeps only rows overlapping them (a
     pipeline change: a collector that reads others' results); **B** the collector emits every row of the
     table, off the timeline, and the view filters (Self mode would list a month of programs as unmatched
     observations); **C** the collector keeps rows from a fixed span before the scan, a core constant
     (earlier sessions are lost).
   - Recommended: **decide after D1**. If forced now, **A**: it is the only one where rows outside a window
     never leave the collector. **B** fails "collect only what a rule needs".
7. **D7, what a row means in the view.**
   - Options: **A** its own label, "used in a period that overlaps this window", not one of T1–T4; **B**
     T1–T3 when the whole period lies inside one window.
   - Recommended: **A**. T1–T4 compare a recorded instant with a window; a period is a different fact, and
     merging them would let an hour-wide row look as precise as a Prefetch run time.

## Alternatives weighed

| Alternative | Why not |
|---|---|
| Use the ESE API to open the database | `JetInit` performs crash recovery automatically and creates log files; a write on the scanned machine (Question 1) |
| Copy `SRUDB.dat` with a shadow copy or `esentutl` | A change to the machine, or another program started; both forbidden to collectors (ADR 0041) |
| `ese-core` / `srum-parser` | A memory map of a live file is undefined behaviour by its own comment, and bypasses `read_file` |
| `sootmark-srum` as the parser | Resolves SIDs and every table; the seam in Question 4 wants less to leave the parser |
| Read the network tables "for context" | ADR 0054: the owner decided no record of traffic is read |
| Skip this ADR and add SRUM straight to P1–P7 | ADR 0078 owner decision D4: feasibility only |

## What is unverified

- That Windows holds `SRUDB.dat` against reads (ADR 0054's sentence is unmeasured), which process holds it,
  and with what sharing mode.
- How often Windows writes to it; how long rows are kept (~30 and ~60 days come from an unsourced note);
  what `TimeStamp` marks.
- Whether a live `SRUDB.dat` is usually in a dirty state.
- Its size on an ordinary PC against the 64 MiB limit.
- Whether a limited token can open it.
- The shape of `AppId` strings, and whether types 0–2 are paths, services or package ids.
- That SRUM rows outlive the program's file.
- Whether SRUM can be turned off, and what that looks like.
- That `L2ProfileId` and `InterfaceLuid` identify networks.
- The names of the files in `sru\` beside the database.
- Every crate finding: source read, nothing built, run, fuzzed or put through `cargo deny`; advisories not
  checked; no upstream repository opened.
- The table layout rests on one reverse-engineered knowledge base, not on Microsoft.

## Consequences

- No code, no rule, no fixture, no dependency. `Cargo.lock`, `deny.toml`, `PRIVACY.md` and the report are
  unchanged.
- ADR 0078 step P8 is answered as "proposed, waiting on owner question 1". Steps P1–P7 do not depend on it.
- If the owner chooses D1 A, the probe is not kept in this repository; its results are written into this
  ADR, with no content of the PC's database.
- If D1 shows the file held and D2 is A, this ADR is accepted as "SRUM parked", and ADR 0054's sentence
  gains its measurement.
