# ADR 0078 — Programs recorded near a game session

- Status: accepted — the owner accepted the six choices in "Owner decisions" on 2026-10-21; steps P1 to P6
  are built (the "As built" sections here and in ADR 0079 to ADR 0082); P7 and P8 are open
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
compiled into the binary (ADR 0004), so changing them is a release. Lab replay (step P7 in "Order of work")
measures them before the view leaves `experimental` wording.

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
| quiet | ~~**O1** a valid signature whose certificate is in `rules/certificate-pins.csv`~~ (withdrawn 2026-10-24, ADR 0083) | — |

I3's name-shape checks are facts about one name in the view, not rules: they make no evidence row, and a
rename that avoids every shape leaves I3 false, which the text says.

**What the reader sees** is the facts as labels on each candidate, never a sum. No candidate is folded,
hidden or moved because of who published it (O1 withdrawn, amendment of 2026-10-24).

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

## As built: P3 to P5

These steps are recorded in the ADRs that decided their details:

- P3, `recorded_files` and the `Zone.Identifier` stream: ADR 0079, "As built: P3".
- P4, UserAssist: ADR 0080, "As built: P4". The three event fields: ADR 0081, "As built: P4".
- P5, files a program loaded from outside the expected folders: ADR 0082, "As built: P5".

## P6 decisions (2026-10-23, each as recommended)

The owner decided seven questions on the design for step P6, each as recommended, and approved the text
below as drafted.

1. **Scope:** P6 is split. **P6a** shows `game_windows` in the desktop app and the CLI: sessions, windows,
   candidates with their facts and ordinary causes, the clock line, the notes, counts per window, the
   consent text and `PRIVACY.md`. **P6b** adds each candidate's file details that ADR 0079 and ADR 0080 left
   to P6 (hash, signer, content kind, download host, which collectors recorded it).
2. **O1 is not in P6**; no folding line is shown. It follows P6b, which brings the signer.
3. **"Experimental":** a label on the heading and one line saying the 30-minute windows are not yet
   measured on many PCs, until P7's lab replay measures them (section 3).
4. **Placement:** directly after the latest-session statement (ADR 0062) in both front ends.
5. **Consent:** the SS paragraph below is added to the consent screen (CLI and desktop), and the desktop's
   full-scan item gains the CLI's recorded-files item word for word (`rongroi-cli` `full_reads`, third
   item), so the two programs say the same thing. `PRIVACY.md`'s SS table gains a row (section 9).
6. **One Thai suffix:** "(สแกนแบบ Full)" everywhere; `collector.recorded_files`'s "(สแกนเต็ม)" is changed.
7. **The text is approved as drafted.** The keys live under `game.` in
   `apps/desktop/src/locales/{th,en}/report.json`, which the CLI also reads. `{{…}}` is a value filled
   in when shown. When no session is found, the view prints ADR 0061's existing statement and nothing else
   (section 2).

| key (`game.`…) | ไทย | English |
|---|---|---|
| `title` | โปรแกรมที่ถูกบันทึกไว้ใกล้ช่วงเล่นเกม | Programs recorded near a game session |
| `experimental` | ทดลอง | experimental |
| `intro` | Windows บันทึกเวลาที่โปรแกรมทำงานไว้ รายการนี้คือโปรแกรมที่มีเวลาบันทึกอยู่ใน 30 นาทีก่อนเริ่มเล่น ระหว่างเล่น 30 นาทีหลังเลิกเล่น หรือระหว่างเลิกเล่นจนถึงตอนสแกน การอยู่ในรายการไม่ได้บอกอะไรด้วยตัวเอง ส่วนใหญ่เป็นโปรแกรมปกติ | Windows records when programs run. These are the programs with a recorded time in the 30 minutes before a session, during it, in the 30 minutes after it, or between it and this scan. Being listed says nothing on its own: most are ordinary programs. |
| `order` | เรียงตามจำนวนข้อเท็จจริงด้านตัวไฟล์ที่เป็นจริง แล้วตามเวลา การเรียงนี้นับข้อเท็จจริง ไม่ได้ตัดสินโปรแกรมใด | Ordered by how many facts about the file hold, then by time. The order counts facts; it is not a judgement of any program. |
| `windows_unmeasured` | ช่วง 30 นาทียังไม่ได้ทดสอบกับเครื่องเล่นเกมทั่วไปหลายเครื่อง | The 30-minute windows have not yet been measured on many ordinary gaming PCs. |
| `ss_rule` | โหมด SS แสดงชื่อเฉพาะโปรแกรมที่มีข้อเท็จจริงด้านตัวไฟล์เป็นจริง โปรแกรมอื่นแสดงเป็นจำนวนต่อช่วง | SS mode names a program only when a fact about its file holds; other programs are counted per window. |
| `ss_counts` | โปรแกรมอื่นที่ไม่แสดงชื่อ: {{list}} | Other programs, not named: {{list}} |
| `more` | + อีก {{count}} รายการ | + {{count}} more |
| `window.before` | 30 นาทีก่อนเริ่ม | 30 min before |
| `window.during` | ระหว่างเล่น | during |
| `window.after` | 30 นาทีหลังจบ | 30 min after |
| `window.before_scan` | ก่อนสแกน | before this scan |
| `session.latest` | (ล่าสุด) | (latest) |
| `session.earlier` | เซสชันก่อนหน้า เริ่ม {{at}} | earlier session, began {{at}} |
| `fact.t1` | มีบันทึกใน 30 นาทีก่อนเริ่มเล่น | recorded in the 30 minutes before a session |
| `cause.t1` | แชต ตัวเปิดเกม โปรแกรมอัดหน้าจอและโปรแกรมการ์ดจอที่เปิดก่อนเล่น | chat, launchers, recording and GPU tools started before playing |
| `fact.t2` | มีบันทึกระหว่างเล่น | recorded during a session |
| `cause.t2` | overlay โปรแกรมอัดหน้าจอ เบราว์เซอร์ | overlays, recording tools, a browser |
| `fact.t3` | มีบันทึกใน 30 นาทีหลังเลิกเล่น | recorded in the 30 minutes after a session |
| `cause.t3` | อะไรก็ได้ที่เปิดหลังเลิกเล่น | anything opened after the game |
| `fact.t4` | มีบันทึกระหว่างเลิกเล่นจนถึงตอนสแกน | recorded between the session and this scan |
| `cause.t4` | โปรแกรมที่ทีมงานเซิร์ฟเวอร์ขอให้ผู้เล่นเปิด | the program a server's staff asked the player to open |
| `fact.r` | อยู่ใกล้ {{near}} จาก {{found}} เซสชัน | near {{near}} of {{found}} sessions |
| `cause.r` | โปรแกรมที่ผู้เล่นเปิดทุกครั้งที่เล่น | a program the player opens every time they play |
| `fact.i1` | ไม่พบไฟล์ที่ path ที่บันทึกไว้แล้ว | its file is no longer at the recorded path |
| `cause.i1` | ตัวติดตั้งที่ลบตัวเอง Storage Sense ไดรฟ์ USB ที่ถอดออก | a self-deleting installer, Storage Sense, a removed USB drive |
| `fact.i2` | ไม่มีลายเซ็นดิจิทัลที่ตรวจผ่าน | no embedded signature that verifies |
| `cause.i2` | โปรแกรม open-source ม็อด ไฟล์ของ Windows ที่เซ็นแบบ catalog | open-source tools, mods, catalog-signed Windows files |
| `fact.i3` | ชื่อไฟล์ไม่ตรงกับสิ่งที่ไฟล์เป็น | its name does not match what the file is |
| `cause.i3` | ตัวอัปเดตที่เก็บโปรแกรมเป็น .tmp หรือ .dat โปรแกรมพกพาที่ถูกเปลี่ยนชื่อ | updaters that keep an executable as .tmp or .dat, renamed portable tools |
| `fact.i4` | รันจาก Temp หรือ Downloads | it ran from Temp or Downloads |
| `cause.i4` | อะไรก็ได้ที่ดาวน์โหลดแล้วเปิด | anything downloaded and run |
| `fact.l1` | โหลดไฟล์โปรแกรมจากนอกโฟลเดอร์ปกติ | it loaded a program file from outside the usual folders |
| `cause.l1` | add-on, overlay หรือ codec ที่ติดตั้งไว้ในโฟลเดอร์ของผู้ใช้ | an add-on, overlay or codec installed in a user folder |
| `fact.l1_false` | ในไฟล์ที่ Prefetch บันทึกไว้ ไม่มีไฟล์นามสกุลโปรแกรมอยู่นอก Windows, Program Files และโฟลเดอร์ของ FiveM | of the files Prefetch recorded for it, none with a program's extension is outside Windows, Program Files and FiveM's folders |
| `session.l1` | โหลดไฟล์จากนอกโฟลเดอร์ปกติ: {{count}} ไฟล์ | loaded from outside the usual folders: {{count}} files |
| `session.l1_label` | โหลดไฟล์จากนอกโฟลเดอร์ปกติ | Loaded from outside the usual folders |
| `value.false` | ไม่ (ภายในสิ่งที่อ่านได้) | no (within what was read) |
| `nk.session_end_not_recorded` | ไม่รู้: ไม่มีบันทึกว่าเซสชันจบเมื่อไร | not known: the session's end is not recorded |
| `nk.scan_time_not_recorded` | ไม่รู้: ไม่มีบันทึกเวลาสแกน | not known: the scan's time is not recorded |
| `nk.before_trace_age` | ไม่รู้: {{source}} ย้อนไปไม่ถึงช่วงนั้น | not known: {{source}} does not reach back that far |
| `nk.recorded_files_not_run` | ไม่รู้: การสแกนแบบปกติไม่อ่านตัวไฟล์ | not known: a standard scan does not read the file |
| `nk.no_observation_for_path` | ไม่รู้: ไม่ได้อ่านไฟล์ที่ path นี้ | not known: the file at this path was not read |
| `nk.not_read` | ไม่รู้: อ่านไฟล์ไม่ได้ | not known: the file could not be read |
| `nk.unverifiable` | ไม่รู้: ตรวจลายเซ็นแบบออฟไลน์ไม่ได้ | not known: the signature cannot be checked offline |
| `nk.no_path` | ไม่รู้: ไม่มี path ที่บันทึกไว้ | not known: no path was recorded for it |
| `nk.deferred` | ไม่รู้: เวอร์ชันนี้ยังไม่อ่าน | not known: this version does not read it yet |
| `nk.not_counted` | ไม่รู้: ไม่มีบันทึก Prefetch ที่นับไฟล์ที่โหลด | not known: no Prefetch record counted the files it loaded |
| `nk.earlier_session` | ไม่รู้: เซสชันก่อนหน้าไม่มีบันทึกเวลาจบ | not known: an earlier session's end is never recorded |
| `clock.changed` | นาฬิกาเครื่องถูกเปลี่ยนเมื่อ {{at}}{{detail}} เวลาก่อนและหลังจุดนี้อาจไม่ได้อยู่บนนาฬิกาเดียวกัน | The clock was changed at {{at}}{{detail}}; times before and after may not be on the same clock. |
| `clock.detail` |  (จาก {{old}} เป็น {{new}}) |  (from {{old}} to {{new}}) |
| `clock.not_known` | ไม่รู้ว่านาฬิกาถูกเปลี่ยนหรือไม่ เพราะ event log ของ System ย้อนไปไม่ถึงช่วงที่เทียบ หรืออ่านไม่ได้ | Whether the clock was changed is not known: the System event log does not reach back to the compared span, or could not be read. |
| `note.installed` | Windows บันทึกการติดตั้งไฟล์นี้เมื่อ {{at}} | Windows recorded an install of this file at {{at}}. |
| `note.code_integrity` | Code Integrity เคยปฏิเสธไฟล์ที่ path เดียวกันบนไดรฟ์ใดไดรฟ์หนึ่ง | Code Integrity refused a file at the same path on some drive. |
| `note.unmatched_installs` | มีการติดตั้ง service หรือ driver {{count}} รายการในช่วงนี้ ซึ่ง path ไม่ตรงกับโปรแกรมใดในรายการ | {{count}} service or driver installs in this window; their paths are not among the programs listed. |

**Consent, SS paragraph:**

- ไทย: ในโหมด SS โปรแกรมที่ถูกบันทึกใกล้ช่วงที่คุณเล่นเกมครั้งล่าสุดจะแสดงชื่อเฉพาะเมื่อมีข้อเท็จจริงด้านตัวไฟล์เป็นจริง
  ได้แก่ ไฟล์ไม่อยู่ที่เดิมแล้ว ไม่มีลายเซ็นที่ตรวจผ่าน ชื่อไม่ตรงกับสิ่งที่ไฟล์เป็น รันจาก Temp หรือ Downloads
  หรือโหลดไฟล์โปรแกรมจากนอกโฟลเดอร์ปกติ โปรแกรมอื่นแสดงเป็นจำนวนเท่านั้น
- English: In SS mode, programs recorded near your last game session are named only when a fact about the
  file holds: it is no longer where it ran from, it has no signature that verifies, its name does not match
  what it is, it ran from Temp or Downloads, or it loaded a program file from outside the usual folders.
  Other programs are counted, not named.

## As built: P6a (2026-10-23)

P6a shipped in workstream R-13. `ReportView` carries `game_windows` in both modes. It is built in
`rongroi-core::view` for the mode being shown, and it is absent when the report holds no game session. The
desktop app shows the section after the cross-source statements. The CLI prints it after the latest-session
statement. Both use only the keys in the table above. The build fills in four things that the decisions
above leave open:

1. **The unnamed counts are counted in core.** `GameWindows.unnamed` holds, per window, the candidates
   that SS mode does not name. Both front ends print that number and never count it themselves. The
   privacy decision therefore stays in core (hard rule 5). In Self mode the counts are zero, and both
   front ends show the per-window chips instead.
2. **Not-known facts are written out.** A time fact or an identity fact that is not known is shown as
   "fact: not known: reason", using the `nk.*` keys. A fact that does not hold is left out. A false fact
   and an unknown fact therefore never look the same.
3. **An earlier session is shown once.** For a session that is not the latest, the front ends show only
   `session.earlier`, which already carries the session's start. Its end is never recorded.
4. **I5 is not shown.** Core does not compute it yet (ADR 0079 section 5), so it is always "not known:
   this version does not read it yet". It does not decide whether SS mode names a program. The approved
   table has no key for it. It comes to the reader when core computes it.

## P6b decisions (2026-10-23, each as recommended)

The owner decided five questions on step P6b, each as recommended, and approved the text below as drafted.

1. **Placement:** the desktop app folds a candidate's details under its card ("File details", opened by a
   click), as an evidence row folds its technical details. The CLI prints them indented under the
   candidate every time.
2. **Hashes in full:** `sha256` and `signer_cert_sha256` are shown as all 64 hex characters, in the
   monospace face, selectable.
3. **Sources:** every candidate says which collectors recorded it ("Recorded by: …"), in the order the view
   reads them (Prefetch, BAM, PCA, process, UserAssist), named with the collectors' existing names. This
   closes ADR 0080 "As built: P4" item 1.
4. **Consent:** one sentence is added after the SS paragraph of the P6 decisions, in both front ends.
5. **Text:** the keys below, under `game.file.*` in `apps/desktop/src/locales/{en,th}/report.json`, which
   the CLI reads too. `trailing_data` and `embedded_pe` are shown only when true, because each is decided
   for some file kinds only (ADR 0079 "As built: P2" item 2).

What SS mode shows was decided by ADR 0079 section 6 and is unchanged: the details of a candidate SS mode
names, with `download_host` as `%DOWNLOAD_HOST%` unless the player agreed to show download hosts
(ADR 0064). Candidates SS mode does not name are dropped whole, as in P6a.

| Key | ไทย | English |
|---|---|---|
| `title` | รายละเอียดไฟล์ | File details |
| `recorded_by` | บันทึกโดย: {{sources}} | Recorded by: {{sources}} |
| `read.missing` | ไม่มีไฟล์ที่ path นี้แล้ว จึงไม่ได้อ่าน | The file is no longer at this path, so it was not read. |
| `read.too_large` | ไฟล์ใหญ่กว่า 64 MiB จึงอ่านแค่ hash และลายเซ็น | Larger than 64 MiB, so only its hash and signature were read. |
| `read.access_denied` | Windows ไม่ให้อ่านไฟล์นี้ | Windows did not allow this file to be read. |
| `read.failed` | อ่านไฟล์ไม่ได้ | The file could not be read. |
| `read.refused_form` | ไม่ได้อ่าน: โปรแกรมนี้ไม่อ่าน path รูปแบบนี้ | Not read: this program does not read paths of this form. |
| `read.budget_spent` | ไม่ได้อ่าน: เวลาอ่านไฟล์ 90 วินาทีหมดก่อนถึงไฟล์นี้ | Not read: the 90 seconds for reading files ran out before this one. |
| `read.not_run` | การสแกนแบบปกติไม่อ่านตัวไฟล์ | A standard scan does not read the file. |
| `read.no_path` | ไม่มี path ที่บันทึกไว้ จึงไม่มีไฟล์ให้อ่าน | No path was recorded, so there is no file to read. |
| `read.no_observation` | ไม่ได้อ่านไฟล์ที่ path นี้ | The file at this path was not read. |
| `sha256` | SHA-256 | SHA-256 |
| `signature.valid` | ลายเซ็นในไฟล์: ตรวจผ่าน | Embedded signature: verifies |
| `signature.invalid` | ลายเซ็นในไฟล์: ตรวจไม่ผ่าน | Embedded signature: does not verify |
| `signature.no_embedded_signature` | ไม่มีลายเซ็นในไฟล์ | No embedded signature |
| `signature.unverifiable_offline` | ลายเซ็นในไฟล์: ตรวจแบบออฟไลน์ไม่ได้ | Embedded signature: cannot be checked offline |
| `signer` | ผู้เซ็น: {{signer}} | Signer: {{signer}} |
| `signer_cert` | SHA-256 ของใบรับรองผู้เซ็น | Signer certificate SHA-256 |
| `kind.label` | ตัวไฟล์เป็น | What the bytes are |
| `kind.pe_executable` | โปรแกรม (PE) | a program (PE) |
| `kind.pe_dll` | DLL (PE) | a DLL (PE) |
| `kind.pe_driver` | ไดรเวอร์ (PE) | a driver (PE) |
| `kind.archive` | ไฟล์บีบอัด (zip, 7z, rar, gzip, cab) | an archive (zip, 7z, rar, gzip, cab) |
| `kind.image` | รูปภาพ (png, jpeg, gif, bmp, webp, ico) | an image (png, jpeg, gif, bmp, webp, ico) |
| `kind.script` | ข้อความ เช่นสคริปต์ | text, such as a script |
| `kind.unknown` | ไม่ใช่ชนิดที่โปรแกรมนี้รู้จัก | none of the kinds this program knows |
| `trailing_data` | มีข้อมูลต่อท้ายหลังจุดจบของรูปแบบไฟล์ | It has data after the end of its format. |
| `embedded_pe` | มีโปรแกรม (PE) อยู่ข้างใน | It holds a program (PE) inside. |
| `original_filename` | ชื่อในข้อมูลเวอร์ชันของไฟล์: {{name}} | Name in its version information: {{name}} |
| `zone` | โซนที่ Windows บันทึกตอนดาวน์โหลด: {{zone}} | Download zone Windows recorded: {{zone}} |
| `zone_name.0` | เครื่องนี้ (0) | this computer (0) |
| `zone_name.1` | อินทราเน็ต (1) | local intranet (1) |
| `zone_name.2` | เว็บที่เชื่อถือ (2) | trusted sites (2) |
| `zone_name.3` | อินเทอร์เน็ต (3) | the Internet (3) |
| `zone_name.4` | เว็บที่ถูกจำกัด (4) | restricted sites (4) |
| `zone_other` | โซน {{id}} | zone {{id}} |
| `download_host` | ดาวน์โหลดจาก: {{host}} | Downloaded from: {{host}} |

**Consent, sentence added to the SS paragraph:**

- ไทย: สำหรับโปรแกรมที่แสดงชื่อ จะแสดงรายละเอียดของไฟล์ด้วย ได้แก่ hash ลายเซ็นและผู้เซ็น ชนิดของไฟล์ ชื่อในข้อมูลเวอร์ชัน และโซนดาวน์โหลด ส่วนชื่อเว็บที่ดาวน์โหลดแสดงเฉพาะเมื่อคุณยินยอมให้แสดงชื่อเว็บ
- English: For a program it names, it also shows the file's details: its hash, signature and signer, what kind of file it is, the name in its version information, and its download zone. The website it came from is shown only if you agree to show websites.

**The download-host option (owner, 2026-10-23, as drafted).** ADR 0079 owner decision 4 puts a file's
download host under ADR 0064's existing SS option, whose wording named PowerShell only. From P6b it names
both:

- Desktop, `common.json` `download_host`:
  - ไทย: แสดงชื่อเว็บไซต์ที่คำสั่ง PowerShell หรือไฟล์ของโปรแกรมที่ถูกบันทึกไว้ ดาวน์โหลดมาด้วย ถ้าปิดไว้ แต่ละชื่อจะแสดงเป็น %DOWNLOAD_HOST%
  - English: Also show the name of each website a PowerShell command, or a recorded program's file, was downloaded from. Off: each name is shown as %DOWNLOAD_HOST%.
- CLI, `download_host_question`:
  - ไทย: ให้คนที่ดูอยู่เห็นชื่อเว็บไซต์ที่คำสั่ง PowerShell หรือไฟล์ของโปรแกรมที่ถูกบันทึกไว้ ดาวน์โหลดมาหรือไม่ อ่านเฉพาะชื่อ ไม่อ่านส่วนอื่นของที่อยู่หรือตัวคำสั่ง ถ้าไม่ แต่ละชื่อจะแสดงเป็น %DOWNLOAD_HOST% [y/N]
  - English: Show the person watching the name of each website a PowerShell command, or a recorded program's file, was downloaded from? Only the name is read, never the rest of the address or the command. If not, each name is shown as %DOWNLOAD_HOST%. [y/N]

## As built: P6b (2026-10-24)

P6b shipped in workstream R-14. Each `GameCandidate` now carries `recorded_by` and `file`, and both front ends
show them as the P6b decisions above describe. The build fills in four things those decisions leave open:

1. **One join, one reason.** `file.read` comes from the same join as I1 and I2, and the same three-way
   choice applies when nothing joins: no path, a standard scan, or no observation for the path. The
   facts and the details can therefore never disagree. An `identity_read` that is absent or unknown is
   read as `failed`.
2. **Order of the sources.** `recorded_by` follows the order in which the view reads the collectors
   (Prefetch, BAM, PCA, process, UserAssist), not the alphabet. One constant holds that order for both.
3. **The CLI replaces control characters.** The game-window section is the first place the CLI prints
   text from the player's files and from Windows' records as it is: names, paths, the signer, the
   version-information name, the download host, and a signature or content kind it has no words for.
   Every control character in that text is printed as U+FFFD, so a newline cannot forge a line and an
   escape sequence cannot drive the terminal. The desktop app is not affected, because React escapes
   text.
4. **Hash lines read the same.** Both front ends print `SHA-256: <hash>` and
   `Signer certificate SHA-256: <hash>`, with the colon after the label from the table.

## Amendment (2026-10-24): O1 withdrawn

The owner cancelled O1, the fold of candidates signed with a known publisher's certificate (ADR 0083,
"Withdrawn"). Section 5 keeps its row struck through so the history stays readable. No candidate is
folded, hidden or moved because of who published it. The order stays the one section 5 describes: by
how many facts about the file hold. That counts facts and vouches for nothing (`AGENTS.md`, hard rule 9).

## Amendment (2026-10-24): names no longer keep a record out

Section 4 left out of the candidates every record named `FiveM.exe`, `GTA5.exe`, `GTA5_Enhanced.exe`,
`PlayGTAV.exe` or `FiveM_b…_GTAProcess.exe`, whatever its path, so a program renamed to one of them was never
a candidate. Since ADR 0084 decision 3 they are candidates like any other program. Sessions are still found
from the same records (ADR 0062).

## P7 decisions (2026-10-27, each as recommended)

The owner decided three questions on step P7 on 2026-10-27, each as recommended.

1. **The view keeps its `experimental` wording in 0.13.0.** Section 3 ties that wording to measuring the
   30-minute windows, and the approved text says they "have not yet been measured on many ordinary gaming
   PCs". A virtual machine with no real play measures no window width, and one PC's evening is not many.
   P7's results are recorded as the first PC; the wording goes when more than one is measured.
2. **Lab scenarios use a session whose game is still running** (ADR 0076, "Amendment (2026-10-27)"). On the
   lab machine Prefetch wrote no file for `FiveM.exe`, so a session that has ended has no start there; a
   running `FiveM.exe` gives the start, and only the window before the session can be shown. Three
   scenarios: a renamed program run before the session and deleted while it runs (it shows the program as a
   candidate, and that I1 cannot be shown for it, item 3); a downloaded file with its `Zone.Identifier`
   stream; a clock change, made with Windows' own setting, whose event is the trace (nothing is
   back-dated). The fourth, a DLL appended to an image and loaded by
   `rundll32.exe`, needs Prefetch's loaded-file list for fact L1 and is not written.
3. **A program known only from BAM or Prefetch has no path, and the drive map is its own ADR after 0.13.0.**
   Measured on the lab machine (Windows 11 build 26300): BAM names a program as
   `\Device\HarddiskVolumeN\…`, which ADR 0023 had left unverified, and Prefetch's string table uses
   `\VOLUME{…}\…`. Neither is drive-rooted, so `bam` and `prefetch` withhold the path (SS mode cannot redact
   that shape), `recorded_files` never reads such a file, and the candidate's identity facts I1 to I4 are
   "not known: no path". A program run and then deleted, the case I1 is for, gets a path only when PCA,
   UserAssist or the process list also recorded it. Mapping a volume to its drive letter is the drive map
   ADR 0082 section 4 left for later; it needs its own ADR because a mapped path must be redacted as every
   other path is.
