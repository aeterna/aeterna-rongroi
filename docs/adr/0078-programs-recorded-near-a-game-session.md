# ADR 0078 — Programs recorded near a game session

- Status: accepted — the owner accepted the six choices in "Owner decisions" on 2026-10-21; nothing is built yet
- Date: 2026-10-21
- Related: ADR 0002 (evidence, not verdict), ADR 0021 (Prefetch), ADR 0028 (facts about more than one
  observation are computed in Rust), ADR 0034 (Prefetch, BAM and PCA carry no identity), ADR 0035
  (signatures), ADR 0051 (timeline), ADR 0061 (trace ages and cross-source statements), ADR 0062 (the
  session), ADR 0076 (lab replay)
- Amends: ADR 0021 (run times), ADR 0034 decision 2 (what SS mode lists), ADR 0061 section 4 (ordering)

## Context

A cheat can be renamed, given an image's extension, appended to a real image, or loaded by a signed
Windows program. Chasing each disguise with its own rule does not end, and ADR 0034 explains why a rule on
a program's name is defeated by the next rename. Three things do not change with the disguise:

1. **It has to run.** A loader, an injector or an executor is a process, or is loaded into one, and Windows
   records runs in more than one place (Prefetch, BAM, PCA, and the sources section 7 adds).
2. **It has to run near the game.** An injector runs after the game starts; a loader runs shortly before; a
   clean-up runs after the game or before a screenshare. Moving a recorded time means changing the clock,
   which leaves a record of its own.
3. **It is a file with content.** Whatever a file is called, its first bytes, its embedded signature and
   its version resource say what it is. A name that contradicts the content is a fact about the file.

The report already holds most of the times: the timeline (ADR 0051), trace ages and the cross-source
statements (ADR 0061), and the session (ADR 0062). Nothing compares the programs Windows recorded with
the game's session, and nothing checks the identity of a program recorded near it. The owner asked on
2026-10-20 for a design that does both, after a FiveM community video showed a cheat delivered as a
`.png` file. The plan was reviewed by a second model and by the owner's security team before this ADR;
their corrections are folded in below.

What the code holds today, measured on `dev` at `67bf1d29`:

- `rongroi_parsers::prefetch` returns up to eight run times (`PrefetchRecord::last_runs`), and the
  `prefetch` collector emits only the newest (`last_run`) and their number (`recorded_runs`).
- `rongroi_collectors::FieldKind` has `Text`, `Number`, `Bool` and `Timestamp`; nothing holds a list.
- `rongroi_parsers::evtx` drops every event payload except where a named purpose reads one field
  (script blocks, ADR 0064; `BootType`, ADR 0071). The reason is privacy, written at the top of the module.
- `FilesystemSource` has `list_dir`, `file_sha256` and `read_file`; nothing reads an alternate data
  stream, and `paths::is_refused_form` refuses a path with a `:` after the drive (ADR 0048, R1).

## Decision

### 1. A view, computed in the core, never evidence

`rongroi_core::view` gains `game_windows(report, mode) -> GameWindows`, beside `cross_source`. Like ADR
0061's statements it has no `found`, `not_found` or `unmeasured` state, no rule id, no strength, and is
never counted in `ListedCounts` or `HiddenCounts`. It joins observations from different collectors, so it
is written in Rust where a fixture can contradict it (ADR 0028). No rule changes, and ADR 0034 decision 1
still holds: no `role: evidence` rule selects a `prefetch`, `bam` or `pca` record by name or path.

### 2. Sessions

**The latest session of each edition is ADR 0062's session**, unchanged: its start from a running
`FiveM.exe` (or Legacy's `FiveM_b…_GTAProcess.exe`) else Prefetch, its end from BAM, never GTA V's
executables, and its ten-minute margin. This ADR adds no second definition.

**Earlier sessions** come from the other run times Prefetch kept for the same names (section 6). They have
a start and no end: BAM keeps only a path's latest end. An earlier session's "during" window is therefore
"not known", and the view never guesses a session's length.

When no session is found, the view prints ADR 0061's statement and nothing else: there is no time to
compare with.

### 3. Four windows per session

| Window | Bounds | Kept for an earlier session |
|---|---|---|
| before | start minus 30 minutes, up to the start | yes |
| during | start to end | no, "not known" |
| after | end, up to end plus 30 minutes | no, "not known" |
| before the scan | the latest session's end, up to the scan's `generated_at` | latest session only |

The 30 minutes are constants in `rongroi-core`, printed in the view's text. Rules and core constants are
compiled into the binary (ADR 0004), so changing them is a release. Lab replay (section 10) measures them
before the view leaves `experimental` wording.

### 4. Candidates

A candidate is a program, other than the names the FiveM timeline selectors list, with a recorded time
inside a window: a Prefetch run time, a BAM end, a PCA launch, a running process's `started_at`, a
UserAssist time (section 7), or a service install (section 7). Records of the same program from different
collectors are one candidate when their paths are equal ignoring ASCII case; a Prefetch record, which has
a name and no emitted path, joins a candidate by the executable's own entry in its loaded-file list, read
inside the collector and never emitted (ADR 0021). A Prefetch record that joins nothing stays a candidate
of its own, named by its executable name.

### 5. Facts, and the ladder they make

Each candidate carries facts. A fact is true, false, or "not known" with the reason. Every fact has its
ordinary causes, fixed strings in the locale files, printed with it.

| Group | Fact | Ordinary causes the text names |
|---|---|---|
| time | **T1** recorded in a "before" window | chat, launchers, recording and GPU tools started before playing |
| time | **T2** recorded in a "during" window | overlays, recording tools, a browser |
| time | **T3** recorded in an "after" window | anything opened after the game |
| time | **T4** recorded in the "before the scan" window | the program a server's staff asked the player to open |
| time | **R** near more than one session: the number of sessions whose windows hold one of its times, out of the sessions found | a program the player opens every time they play |
| identity | **I1** its file is no longer at the recorded path | a self-deleting installer, Storage Sense, a removed USB drive |
| identity | **I2** no embedded signature, one that does not verify, or one that cannot be verified offline (ADR 0035) | open-source tools, mods, catalog-signed Windows files |
| identity | **I3** its name contradicts what it is or did: content kind against extension, `OriginalFilename` against the file name, a recorded run of a name whose extension is not an executable's, a double extension, a right-to-left override or mixed-script name, a Windows system file name outside `%SystemRoot%` | updaters that keep an executable as `.tmp` or `.dat`, renamed portable tools |
| identity | **I4** its path is under Temp, Downloads, a removable drive, or another folder the account can write | anything downloaded and run |
| identity | **I5** the change journal holds a rename or deletion of it inside a window (ADR 0047) | updates, the Recycle Bin, antivirus quarantine |
| around | **C1** a Code Integrity 3033 or 3077, or a Defender 1116, recorded inside a window | the 476 refused DLLs one ordinary PC held (ADR 0059) |
| around | **C2** a log-clearing record (ADR 0031) inside the "before the scan" window | Disk Cleanup and clean-up programs |
| quiet | **O1** a valid signature whose certificate is in `rules/certificate-pins.csv` | (folds the candidate, below) |

I3's name-shape checks are facts about one name in the view, not rules: they make no evidence row, and a
rename that avoids every shape leaves I3 false, which the text says.

**What the reader sees** is the facts as labels on each candidate, never a sum. Candidates with O1 are
folded into one line, "N programs signed by a known publisher", which opens to the list.

**Ordering (amends ADR 0061 section 4).** Candidates are ordered by how many of R and I1 to I5 are true,
then by how many of T1 to T4, then by the earliest recorded time. ADR 0061 section 4 forbade any ranking;
this ADR allows this one ordering in this one view, because a screenshare reviewer otherwise reads dozens
of ordinary programs to reach one with a missing file. It still forbids a number, a colour scale, a verdict
word, and any sentence that calls a candidate suspicious. The heading of the list says that the order
counts facts and is not a judgement.

**Clock trust.** When an event log records a system time change inside the span the view compares
(section 7), every comparison across that point carries the line "the clock was changed at …; times before
and after may not be on the same clock". No candidate is hidden by it. When the logs that would hold such
a record do not reach back that far, or were not read, the line says the clock's history is not known.

**Coverage.** A fact is "false" only inside the span its source still covers (ADR 0061 trace ages); outside
it the fact is "not known". The view never says that something did not run.

### 6. Prefetch's run times (amends ADR 0021)

The `prefetch` collector emits `run_times`, every run time the file holds (at most eight), newest first,
beside `last_run`. `FieldKind` gains `TimestampList`, an array of RFC 3339 UTC strings. `run_times` is
declared `off_timeline` (as `process`'s `started_at` is, ADR 0062): the timeline does not grow by up to
eight entries per Prefetch file, and the field is read by `game_windows` only. No rule may match it; the
bundle loader refuses a `match` on a `TimestampList` field.

This field is the precondition of R and of every earlier session. Without it the view has one session per
edition and R cannot be computed.

### 7. New sources

Each needs its own ADR before code, in this order:

1. **UserAssist**: the values under `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist`,
   ROT13-decoded, with run count and last run time for programs launched through the shell. The account's
   own hive, no administrator rights. A new collector; whether it records launches made by a launcher is
   to be measured first.
2. **Event payload fields (amends ADR 0018 and ADR 0059, as ADR 0064 did).** Three fields, each read by a
   named function with a fixture, and none emitted as text:
   - System 7045, `ImagePath`: resolved as `driver_service` resolves a path (ADR 0048) and compared with
     candidates' paths; emitted as the matched candidate, or as a count of installs with no candidate;
   - Security 4616 and `Microsoft-Windows-Kernel-General` 1, the old and new times: emitted as the two
     times, for clock trust;
   - Code Integrity 3033, the file name: compared with candidates' paths; emitted as whether it matched.
   The consent question and `PRIVACY.md` name these reads in the change that adds them.
3. **SRUM**: a feasibility ADR only, on the questions ADR 0041 answered for Amcache (a reader and its
   licence, a database that was not shut down cleanly, recovery writes, the privacy seam), not only the
   file being held open.

### 8. Identity of a candidate's file

For each candidate whose path is known, in a full scan only (ADR 0052) and within a 30-second budget of its
own, candidates with more true time facts first:

- whether the file exists; when it does not, I1, and the journal's records for its name (I5);
- `sha256` and the embedded signature, as `fivem_dir` checks them (ADR 0035);
- **`content_kind`**: a new parser function, `fn(&[u8])` in `rongroi-parsers`, reading the first and
  last bytes through `read_file` (ADR 0019): `pe_executable`, `pe_dll`, `pe_driver`, `archive`, `image`,
  `script`, `unknown`; and two flags, `trailing_data` (bytes after an image's or archive's end marker) and
  `embedded_pe` (a PE header at a non-zero offset). It has a fuzz target (ADR 0016);
- **`original_filename`**: a new parser function for a PE version resource, with a fuzz target;
- **the `Zone.Identifier` stream**: a new `FilesystemSource` method that names the stream it reads, with
  its own ADR stating why it is not the path form `is_refused_form` refuses. Only its `HostUrl` host is
  kept, declared sensitive as `powershell_text`'s `download_host` is (ADR 0064).

A file is read only because a record points at it. Nothing walks a disk. A file that was never recorded
running is not read, which this ADR accepts: a file that never ran did nothing.

These values are fields added to the collector's observations, so they reach a saved report and its case
code (ADR 0073). `REPORT_SCHEMA_VERSION` stays at 1, as for the other additive fields. `PRIVACY.md` names
them in the change that adds them.

### 9. SS mode (amends ADR 0034 decision 2)

SS mode shows the sessions, the windows, the clock line and, of the candidates, **the names of those with at
least one of I1 to I5 true**, each with its facts and ordinary causes, redacted as rows are (ADR 0049).
Every other candidate is a count per window. ADR 0034 decision 2 kept Prefetch, BAM and PCA records out of
SS mode entirely; this narrows that to records with no identity fact. The consent question and `PRIVACY.md`
say so in the change that ships the view, before any build shows it.

Self mode shows every candidate.

## Order of work

Each step is one pull request against `dev`. Product code comes from engineer runs under the org's
delegated-delivery rules; ADRs and documentation are written by the orchestrator.

| Step | Change | Depends on |
|---|---|---|
| P1 | `run_times` and `TimestampList`; `view::game_windows` with sessions, windows, T1 to T4 and R, from data the report already holds | this ADR |
| P2 | `content_kind` and `original_filename` parser functions, with fuzz targets | this ADR |
| P3 | identity in the collectors (`bam`, `pca`, `process`, `autostart`), I1 to I5; the `Zone.Identifier` ADR and method | P2 |
| P4 | UserAssist ADR and collector; the payload ADR and the three event fields | P1 |
| P5 | Prefetch's loaded-file list, for `FiveM.exe`, the game process, `rundll32.exe` and `regsvr32.exe` only: how many files outside Windows and Program Files, and how many whose name is not a DLL's but whose content is a PE; never a path (ADR 0021 stays) | P2 |
| P6 | the view in the desktop app and the CLI, SS redaction, consent, `PRIVACY.md`, Thai and English text | P3, P4, P5 |
| P7 | lab replay scenarios (ADR 0076): a renamed executable run before the game and deleted after; a DLL appended to an image and loaded by `rundll32.exe`; a stream on a downloaded file; a clock change; and a baseline on an ordinary gaming PC to measure how many candidates a normal evening has | P6 |
| P8 | SRUM feasibility ADR | none |

## Owner decisions (2026-10-21)

1. **D1, how weight is shown:** facts as labels, ordered by the count of identity facts and R, no number
   (section 5). Not a score.
2. **D2, SS mode:** names only for candidates with an identity fact; the rest counted (section 9).
3. **D3, window width:** 30 minutes before and after, as core constants, changed by a release (section 3).
4. **D4, sources:** UserAssist first, then the three event payload fields; SRUM as feasibility only
   (section 7).
5. **D5, file content:** read only at paths a record points to, full scan only, 30-second budget
   (section 8).
6. **D6, Prefetch run times:** emitted for every Prefetch file as `run_times` (section 6).

## Alternatives weighed

| Alternative | Why not |
|---|---|
| A score per candidate | Read as a verdict whatever its caption says (ADR 0002); a threshold would be argued over instead of the facts |
| Rules naming cheat programs or disguise shapes on Prefetch, BAM and PCA | ADR 0034: no identity, and a rename defeats them; they would also put every match in SS mode as evidence |
| A second session definition with its own merge interval | Two meanings of "session" in one report could disagree; ADR 0062's is measured |
| Reading the content of every file in user folders | Slow, reads files no record points at, and adds nothing about what ran |
| SS mode listing every candidate | Shows a player's ordinary programs to a server's staff, which the consent screen never offered |
| `run_times` only for the game's names | Gives earlier sessions, but R needs every candidate's run times |

## What is unverified

- That BAM's time is a process's end everywhere: ADR 0062 measured it on one PC.
- How far back the change journal reaches on a busy PC (39 minutes on the PC ADR 0047 measured).
- Whether UserAssist records programs a launcher starts.
- How many candidates an ordinary evening of play leaves in each window, and whether 30 minutes is right.
- Whether `prefetch-core` reads Windows 11's version 31 files in practice: the parser accepts 30 and 31,
  and the repository's fixtures hold no version 31 file.
- Whether a 3033's file name and a candidate's path are spelled the same way.

## Consequences

- `rongroi-core`: `view::game_windows`, its types, the ordering above, locale strings for each fact and its
  causes; ADR 0061 section 4's text gains a pointer to this ADR.
- `rongroi-collectors`: `FieldKind::TimestampList`; `prefetch` emits `run_times`; identity fields on
  `bam`, `pca`, `process` and `autostart`; new `userassist` collector; `evtx` reads three named fields.
- `rongroi-parsers`: `content_kind`, `pe_version`, the three event field readers, fuzz targets.
- `rongroi-host`: a method for the `Zone.Identifier` stream, in its own ADR.
- `xtask`: `check-rules` refuses a `match` on a `TimestampList` field.
- Consent, `PRIVACY.md`, `docs/architecture.md` and `CONVENTIONS.md`'s glossary (**candidate**, **game
  window**, **fact**) change in the steps that introduce each part.

## As built: P1 (2026-10-21)

P1 shipped in workstream R-05: Prefetch's `run_times` and the data-only `view::game_windows`. There is no
user interface or locale text yet; those come in P6. The build differs from the sections above in four
places. Each is recorded here and is not a change of decision:

1. **Joining a Prefetch record to a path (section 4).** No report holds Prefetch's loaded-file list yet;
   it arrives with P3. Until then, a Prefetch record joins the one path candidate whose file name equals its
   executable name, ignoring ASCII case. When there is no such path candidate, or more than one, the record
   stays a candidate by its name. P3 replaces this with the join section 4 describes.
2. **Where the refusal of `run_times` lives (section 6).** `rongroi_core::rules::validate` refuses a
   `match` or `match_lists` entry that names `run_times`. It uses a list of such fields of its own, because
   the core cannot see the collectors' field kinds. `cargo xtask check-rules` refuses any field the
   collectors declare as `TimestampList`.
3. **One session from close starts (section 2).** `FiveM.exe` and Legacy's game process start seconds
   apart. Prefetch also writes a run seconds after a process started. Run times of one edition within ADR
   0062's ten-minute margin of each other are therefore one session. An earlier session is one that starts
   more than that margin before the latest start.
4. **Facts with no history behind them (section 5).** A running process has no trace age. A fact that
   rests on a `process` time is therefore "true" or "not known", never "false". When a candidate was seen
   by several collectors, its fact is "false" only when every one of them covers the window.

## As built: P2 (2026-10-21)

P2 shipped in workstream R-06: `rongroi_parsers::content_kind::parse` and
`rongroi_parsers::pe_version::original_filename`. Each has a fuzz target. Neither is called by a collector
yet; that is P3. The build differs from section 8 in three places:

1. **The whole file, not its first and last bytes.** `trailing_data` is decided by walking the format to
   its own end: PNG chunks, JPEG segments and then the scan, GIF blocks, and the zip end-of-central-directory
   record. A head and a tail cannot answer that, so the parser takes the whole file. P3 sets the largest
   file a collector reads; a larger file is not read.
2. **Two decisions are deliberately narrow.** `trailing_data` is decided only for PNG, JPEG, GIF and zip,
   and is "not decided" for every other kind. `embedded_pe` is decided only for a file that is not itself a
   PE, because installers legitimately carry other PEs.
3. **No seed fixtures of their own.** The delegation wrapper cannot carry binary files in a patch. The two
   fuzz targets therefore start from the repository's other fixtures, and their tests build their bytes in
   code.
