# ADR 0062 — FiveM's own folders, beside its last session

- Status: accepted — the owner decided the nine questions below on 2026-10-01
- Date: 2026-10-01

## Context

The owner described the case on 2026-10-01. A player is in game, an admin asks for a check, and the player
runs this program straight away. On an ordinary PC, what FiveM writes into its own folders fits "was just
playing". When a source FiveM writes is missing, or was last written **before** the session it should belong
to, a reviewer should see that misfit, put beside the session, with its ordinary causes. Two examples the
owner gave:

- the player was in game a minute ago, and FiveM's newest log is from yesterday;
- Legacy's resource cache index was created recently, while the cache files it indexes are 80 days old.

ADR 0002 rules out the obvious answer: no verdict, no score, no "suspicious" label. ADR 0061 already built the
machinery this needs — trace ages, anchors, and one cross-source statement in the view, with line forms whose
"not read" is never folded into "nothing" and whose ordinary causes are always printed. This ADR adds a
second kind of statement beside ADR 0061's, and the reads it needs.

Five things in the report today shape the answer.

1. **The report compares nothing with a session.** ADR 0061's statement compares FiveM's folders with
   Prefetch, BAM and PCA by *how far back* each reaches. Nothing compares FiveM's folders with *when FiveM
   last ran*. The scan's own time is the wrong reference: Enhanced writes its game logs only at launch, so
   after an hour of play they are an hour old, and that is ordinary (measured below).
2. **`process` records no start time.** It lists name and path through a ToolHelp snapshot and opens each
   process with `PROCESS_QUERY_LIMITED_INFORMATION` for its path (ADR 0010). It does not call
   `GetProcessTimes`, which that same access right answers.
3. **No record of a run says which edition ran.** Both editions name their client `FiveM.exe`. `prefetch`
   emits a name, never a path (ADR 0021). `bam` emits a path only when it starts with a drive letter, and
   BAM spells paths as `\Device\HarddiskVolumeN\…`, so in practice it emits `path_withheld` (ADR 0023,
   `bam.rs`). `process` emits a path, which SS mode redacts.
4. **Legacy's resource cache index is not read.** `legacy_server_cache` is folder activity of the top level
   of `server-cache`, `server-cache-priv` and `server-cache-fxdk` (ADR 0053). Its `db` and `unconfirmed`
   subfolders are counted in `folders` and nothing else: neither their own times, which the same listing
   already returns, nor what they hold.
5. **BAM and Prefetch need administrator rights** (ADR 0021, ADR 0023, measured again for ADR 0061). The
   process list does not (ADR 0010).

## Measured on a Windows 11 PC (2026-10-01)

A read-only PowerShell probe, kept out of the repository, ran on a Windows 11 PC (build 26220) with the
owner's permission, elevated, five times: with FiveM closed (baseline), during one Legacy session and right
after it, and during one Enhanced session and right after it. It printed counts, sizes, ages in seconds
before the probe's own time, and file-name shapes with letters and digits masked — no file name, path, user
name or server name. Its output was not committed. One session per edition; the Legacy session joined a
server for about four minutes, the Enhanced session lasted about 28 minutes.

### The records of a run

| Record | Legacy | Enhanced |
|---|---|---|
| Running processes (CIM) | `FiveM.exe` started 2.2 min before the in-game probe; `FiveM_b…_GTAProcess.exe` 1.8 min | two `FiveM.exe` started 24.2 min before; `GTA5_Enhanced.exe` 23.5 min |
| Prefetch, `FiveM.exe` | written 1 s after the process start | written 11 s after the process start |
| Prefetch, game | `FiveM_b…_GTAProcess.exe` at its start | `PlayGTAV.exe` at the start; **`GTA5_Enhanced.exe` not rewritten** — its Prefetch file still held the previous day's run, although the game ran for 23 minutes |
| BAM, during play | `FiveM.exe` 1.5 min, earlier than the probe but later than the start | `FiveM.exe` at the start; `GTA5_Enhanced.exe` 28 s after the game's start |
| BAM, after the game closed | `FiveM.exe` and the game process 9 s before the after-run | `FiveM.exe` 9 s, `GTA5_Enhanced.exe` 12 s |
| Processes after | none of FiveM's | none of FiveM's |

So Prefetch places a run at its **start**, and a BAM entry's time is when a process of that path last
**ended**. During play BAM already held a time inside the session — an earlier process of the same path
that had ended, such as a launcher stage. After the game closed, it held the end, seconds before the probe.
Neither meaning is documented by Microsoft; both rest on this one PC.

The baseline, taken with FiveM closed, read the Enhanced session of the evening before: Prefetch
`FiveM.exe` 18.1 h before the probe, BAM `FiveM.exe` 17.8 h. The same relations held on a session read the
next day.

### FiveM's own folders

Times are against the session's start (Prefetch or the process) and its end (BAM), not against the probe.

| Edition | Source | ADR 0053 place | Written, in the session measured |
|---|---|---|---|
| Legacy | log folder | `legacy_logs` | a log created at launch (within a second of the start); written during play (21 s old in-game); its last write 2 min before BAM's end. FiveM removed one older log at launch: 3 files became 2 |
| Legacy | `data\cache` | `legacy_cache` | written during play (23 s old in-game), including `crashometry` |
| Legacy | `data\cache\servers` | not read | one file added on joining |
| Legacy | resource cache files, `server-cache-priv` | `legacy_server_cache` (`priv`) | 6 files added on joining (5 227 became 5 233) |
| Legacy | resource cache index, `server-cache*\db` | **not read** | its files written about 70 s after the start; the `db` folder's own creation time unchanged |
| Legacy | `%APPDATA%\CitizenFX` | not read | written during play (21 s old in-game) |
| Legacy | crash folder | `legacy_crashes` | not written (no crash) |
| Enhanced | log folder, game and browser logs | `enhanced_logs` | created **at launch only**: 23 minutes into play they were 23 minutes old |
| Enhanced | log folder, launcher log | `enhanced_logs` | written at launch and again at exit, 2 s before BAM's end |
| Enhanced | per-server cache | `enhanced_server_cache` | written while loading the server only (182 files within the hour); 24 minutes old during play; no new server folder |
| Enhanced | a roaming storage folder | not read | written during play and at exit (9 s before the after-run). The probe masked its name, so this ADR cannot name it |
| Enhanced | crash folders | `enhanced_crashes`, `enhanced_launcher_crashes` | not written (no crash) |

Across both sessions:

- **Playing one edition touched none of the other edition's sources.** Every Enhanced place kept its times
  through the Legacy session, and every Legacy place through the Enhanced session.
- **Legacy's resource cache index and its oldest cache file were created in the same minute**, 86 days
  before the probe. The index's files are rewritten each session; its folder's own creation time is not.
- An Enhanced installer log was written between the two sessions, before the Enhanced session began: FiveM
  updated itself. Enhanced's log folder kept the same number of files per family (11) as new ones arrived.

### What the measurement settles, and what it does not

The principle it gives: **compare each source with the session it belongs to** — its start from Prefetch or a
running process, its end from BAM — **never with the scan's time.** A source that was last written before the
start of the session of the edition that ran, or that is not there while Prefetch, BAM or a process says that
edition just ran, does not fit that session; a source written at launch only, being as old as the session
is long, does.

Not measured: a second day; joining a server already fully cached; launching without joining; leaving the
game running for an hour; a PC without the other edition installed; a limited token (Prefetch and BAM need
administrator rights, so such a scan says "not known", section 5).

## Decision

### 1. A session statement per edition, beside ADR 0061's statement

`rongroi_core::view::cross_source` returns, besides ADR 0061's statement, at most **one session statement per
edition**. It is the same kind of thing as ADR 0061's: facts from different collectors printed together, not
evidence — no state, no rule id, no strength, never counted in `ListedCounts` or `HiddenCounts`, computed in
Rust in the core where fixtures can contradict it (ADR 0028, ADR 0034). `CrossSourceStatement` gains a
`kind`: `fivem_and_records` (ADR 0061) or `session`. This amends ADR 0061 section 3's "there is exactly one
statement" to "one of each kind, and one session statement per edition".

It reuses ADR 0061's machinery rather than adding its own:

- a source that was not read takes its reason from the run or from the place's gap (ADR 0044), exactly as
  `view::trace_ages` gives it, and is never folded into "nothing";
- the heading, the line forms and the causes are fixed strings in the locale files, checked by
  `check-locales`; the core fills in only times, durations, counts, the edition and the reason;
- the causes are always printed in full under the statement;
- the edition's places are ADR 0053's, named by `location`.

**Nothing is stored between scans.** The session is read from the PC each time; no file, key or cache of
this program's own remembers an earlier scan.

### 2. Session anchors, per edition

A session has a **start** and an **end**, each from one record, each shown with where it came from.

| Anchor | Gives | From | Rights |
|---|---|---|---|
| A FiveM process running now | the start (its creation time) and "still running" | `process`, which gains `started_at` (section 6) | none (ADR 0010) |
| Prefetch | the start: `last_run` of the edition's client or game process | `prefetch` | Administrators |
| BAM | the end: the latest `last_run` of the edition's entries | `bam` | Administrators |

**Which start.** When one of the edition's FiveM processes is running, the start is the earliest `started_at`
among them and the end is "still running". Otherwise the start is the latest Prefetch `last_run` attributed
to the edition, and the end is the latest BAM `last_run` attributed to it, when that is not earlier than the
start; a BAM time earlier than the start is shown as "the end of this run is not recorded" and only
start comparisons are made.

**Which names.** The client, `FiveM.exe`, for both editions; Legacy's game process `FiveM_b…_GTAProcess.exe`,
which FiveM copies into its own folder. Not GTA V's own executables: `GTA5_Enhanced.exe`'s Prefetch file was
not rewritten in the session measured, `PlayGTAV.exe` and `GTA5.exe` are GTA V's names as much as FiveM's,
and GTA V is played without FiveM.

**Which edition.** From the executable's path, matched against the two program folders ADR 0036 and ADR 0061
already read (`%LOCALAPPDATA%\FiveM\…` and `%LOCALAPPDATA%\FiveM for GTAV Enhanced\…`), as a path below a
profile. The match is made **inside the collector**, which emits one word, `fivem_edition: legacy |
enhanced`, and never a path it does not already emit:

- `process`: from the image path it already reads;
- `bam`: from the value name, which is the path BAM recorded and which the collector reads and withholds today;
- `prefetch`: from the executable's own entry in the `.pf` file's string table, which the parser decodes and
  the collector withholds whole (ADR 0021). That this entry names the program folder for FiveM's `.pf` files
  is **not measured**; until it is, a Prefetch `FiveM.exe` with no edition is an anchor only when one edition's
  `FiveM.exe` is present (`fivem_dir`), and `FiveM_b…_GTAProcess.exe` is Legacy's by name (owner decision 3).

A run whose path is in neither folder has no edition and makes no statement. The word says where a file of
that name ran from, not which program it was (ADR 0034): the causes say so.

**One edition does not anchor the other.** A source of one edition is compared only with that edition's
session, as measured.

### 3. The sources compared with the session

Each of an edition's sources is compared with one end of the session, according to when FiveM was measured
to write it. The fields compared are the ones ADR 0053 already emits, plus the index of section 6.

| Edition | Source | Written | Compared | Field |
|---|---|---|---|---|
| Legacy | the edition's log folder | at launch and during play | with the start | `latest_created_at`, and `latest_modified_at` |
| Legacy | the edition's `data\cache` folder | during play | with the start | `latest_modified_at` |
| Legacy | the resource cache index (`db`), per launch mode | on joining a server | with the start, as a join source | `index_latest_modified_at` (section 6) |
| Legacy | the resource cache files, per launch mode | on joining, only when something new is downloaded | not compared with the session; shown beside its index (section 4) | — |
| Enhanced | the edition's log folder | game logs at launch only; launcher log at launch and at exit | with the start (`latest_created_at`), and with the end (`latest_modified_at`) | both |
| Enhanced | the per-server cache | on joining or loading a server only | with the start, as a join source | the latest server folder's `modified_at`, and the place's `latest_modified_at` |
| both | crash folders | only when the game crashes | **not compared**: no crash is the ordinary case | — |

Places this ADR does **not** add: Legacy's `data\cache\servers` (written on joining, and a file there is a
server's icon), `%APPDATA%\CitizenFX` and Enhanced's roaming storage folder (both written during play). Each
would be a new place under ADR 0053's terms; the storage folder cannot even be named until a probe names it
(owner decision 7).

**The margin.** A source is "before the start" only when its time is earlier than the start by more than
**ten minutes**, and "before the end" only when earlier than the end by more than ten minutes. The longest gap
measured between a record and a write it should match was two minutes (Legacy's last log write against BAM's
end, which is why Legacy's logs are compared with the start only). The margin is shown in the text, not
hidden (owner decision 4).

**A join source.** A source written only on joining a server is compared, but its line always carries the
first two causes in its own words — the game may have been played without joining a server, or joined one
whose resources were all cached — before the general list.

### 4. Within one source: the resource cache's index beside its oldest file

For each Legacy launch mode, the trace ages row of `legacy_server_cache` (ADR 0061) shows, beside the row and
never compared, the index folder's own creation date and the oldest cache file's creation date. On the PC
measured they are the same minute. This is the owner's second example. It needs no session, so it is not in
the session statement: it is a fact about one source, shown wherever that source's age is shown, in both modes,
with its causes under the trace ages section.

### 5. How unmeasured anchors suppress or qualify the statement

| Anchors read | What the statement shows |
|---|---|
| A process of the edition is running | the start from the process; "still running"; start comparisons only. Prefetch and BAM add nothing and are not required, so a scan without administrator rights still makes this statement |
| Prefetch and BAM read, the edition attributed | start, end, both comparisons |
| Prefetch read, BAM not read or no end at or after the start | start comparisons; the end line says why there is none |
| BAM read, Prefetch switched off (`EnablePrefetcher` 0 or 2, `service_disabled`) | "Prefetch is switched off on this PC, so when this run began is not recorded"; end comparisons only |
| BAM read, Prefetch not read | end comparisons; the start line gives Prefetch's reason |
| Neither read, nothing running (`not_admin`, `access_denied`, …) | **no comparison.** One line per edition whose `FiveM.exe` is present: "When FiveM last ran is not known: Prefetch and BAM were not read (reason)." Never "fits", never a comparison with the scan's time |
| Read, and nothing attributed to the edition | no statement for that edition. ADR 0061's statement already speaks to FiveM present with no record of it |

A place that was not read (`unreadable`, its gap) takes its reason in place of its line. A place that is
`absent` while a session anchor of its edition exists gets the line "not there". A place `listed` with no
file gets "holds no file". Neither is folded into the other or into "before the start".

### 6. The reads this needs

- **`process`: `started_at`**, the creation time from
  [GetProcessTimes](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocesstimes)
  on the handle already opened for the path: *"The handle must have the PROCESS_QUERY_INFORMATION or
  PROCESS_QUERY_LIMITED_INFORMATION access right."* `ProcessRecord` gains `started_at: Option<Timestamp>`; a
  process whose time cannot be read omits the field, as one whose path cannot be read does (ADR 0010). The
  `windows` feature `Win32_System_Threading` is already enabled. `FixtureHost`'s `processes:` block gains an
  optional `started_at`.
- **`process`, `bam`, `prefetch`: `fivem_edition`**, derived inside the collector (section 2). `bam` keeps
  withholding the path; `prefetch` keeps withholding the string table.
- **`fivem_dir`: Legacy's resource cache index.** Each `legacy_server_cache` observation gains
  `index_created_at` and `index_modified_at`, the `db` subfolder's own times from the listing it already
  makes, and `index_files`, `index_latest_created_at`, `index_latest_modified_at` from one listing of that
  fixed subfolder — a named place, not recursion (ADR 0009) — with no file name. This amends ADR 0053
  section 1. `unconfirmed` is not read: it held no file in either session measured.

### 7. The text

Both modes show the same statement: no path, no file name, no user name, no server name. Times are shown at
the precision the timeline already shows for FiveM's selectors in SS mode (ADR 0051); a compared source is shown
as a duration from the start or the end, in minutes, hours or days.

English, with invented numbers:

```text
FiveM for GTA V Legacy: its last session, beside its own folders

Session:  began 2026-10-01 11:48 UTC (Prefetch, FiveM.exe); ended 11:52 UTC (BAM);
          8 minutes before this scan
Logs:     last created 1 day before the session began; last written 1 day before it began
Cache:    last written 1 day before the session began
Resource cache index (priv): last written at the start of the session
          (written when a server is joined)

Times more than 10 minutes apart are shown as before or after; closer ones as at the start or the end.
This is not evidence of anything. The same result follows from:
- the game played without joining a server, or joining one whose files were all cached already
- FiveM removing its own older logs, or its own "clear cache"
- FiveM installed in, or moved to, a folder other than the one this program reads, or reinstalled
- FiveM started by another Windows account on this PC: its folders are that account's
- FiveM opened and closed before the game started, or updating itself
- GTA V installed through Steam, Epic or the Rockstar launcher, which start the game in different ways
- Prefetch switched off, as some older SSD and performance guides advise
- a clock that was changed, so that times from different sources are not on the same clock
- disk-cleaning software, or a profile moved or restored from a backup
```

Thai:

```text
FiveM for GTA V Legacy: เซสชันล่าสุด เทียบกับโฟลเดอร์ของ FiveM เอง

เซสชัน:   เริ่ม 2026-10-01 11:48 UTC (Prefetch, FiveM.exe) จบ 11:52 UTC (BAM)
          8 นาทีก่อนสแกน
Log:      สร้างไฟล์ล่าสุด 1 วันก่อนเซสชันเริ่ม เขียนล่าสุด 1 วันก่อนเซสชันเริ่ม
Cache:    เขียนล่าสุด 1 วันก่อนเซสชันเริ่ม
ดัชนีของ resource cache (priv): เขียนล่าสุดตอนเซสชันเริ่ม
          (ถูกเขียนเมื่อเข้าเซิร์ฟเวอร์)

เวลาที่ห่างกันเกิน 10 นาทีแสดงเป็นก่อนหรือหลัง ที่ใกล้กว่านั้นแสดงเป็นตอนเริ่มหรือตอนจบ
ข้อมูลนี้ไม่ใช่หลักฐานของสิ่งใด ผลแบบเดียวกันเกิดได้จาก:
- เล่นเกมโดยไม่ได้เข้าเซิร์ฟเวอร์ หรือเข้าเซิร์ฟเวอร์ที่ไฟล์ถูก cache ไว้ครบแล้ว
- FiveM ลบ log เก่าของตัวเอง หรือใช้ "clear cache" ของ FiveM เอง
- ติดตั้ง FiveM ไว้หรือย้ายไปไว้ในโฟลเดอร์อื่นที่โปรแกรมนี้ไม่ได้อ่าน หรือติดตั้งใหม่
- FiveM ถูกเปิดโดยบัญชี Windows อื่นในเครื่องนี้ ซึ่งโฟลเดอร์ของ FiveM เป็นของบัญชีนั้น
- เปิด FiveM แล้วปิดก่อนเกมเริ่ม หรือ FiveM กำลังอัปเดตตัวเอง
- ติดตั้ง GTA V ผ่าน Steam, Epic หรือ Rockstar launcher ซึ่งเปิดเกมคนละแบบ
- ปิด Prefetch ตามคู่มือ SSD หรือคู่มือเพิ่มความเร็วรุ่นเก่า
- นาฬิกาเครื่องถูกเปลี่ยน ทำให้เวลาจากแต่ละแหล่งไม่ได้อยู่บนนาฬิกาเดียวกัน
- โปรแกรมล้างดิสก์ หรือโปรไฟล์ถูกย้ายหรือกู้คืนจาก backup
```

**The line forms**, each a fixed string with the core filling in the duration or the reason:

| Form | English | Thai |
|---|---|---|
| after the start | last written N after the session began | เขียนล่าสุด N หลังเซสชันเริ่ม |
| at the start | last written at the start of the session | เขียนล่าสุดตอนเซสชันเริ่ม |
| before the start | last written N before the session began | เขียนล่าสุด N ก่อนเซสชันเริ่ม |
| at the end | last written at the end of the session | เขียนล่าสุดตอนเซสชันจบ |
| before the end | last written N before the session ended | เขียนล่าสุด N ก่อนเซสชันจบ |
| join source | (written when a server is joined) | (ถูกเขียนเมื่อเข้าเซิร์ฟเวอร์) |
| not there | the folder is not there | ไม่มีโฟลเดอร์นี้ |
| no file | the folder holds no file | โฟลเดอร์นี้ไม่มีไฟล์ |
| not read | not read: reason | อ่านไม่ได้: เหตุผล |
| still running | still running since T | ยังรันอยู่ตั้งแต่ T |
| end not recorded | the end of this run is not recorded | ไม่มีบันทึกว่ารอบนี้จบเมื่อไร |
| not known | When FiveM last ran is not known: Prefetch and BAM were not read (reason) | ไม่รู้ว่า FiveM รันครั้งล่าสุดเมื่อไร เพราะอ่าน Prefetch และ BAM ไม่ได้ (เหตุผล) |

**The index beside its oldest file** (section 4), under the trace ages row:

```text
Index folder created 2026-07-07; oldest cache file created 2026-07-07
โฟลเดอร์ดัชนีสร้างเมื่อ 2026-07-07 ไฟล์ cache ที่เก่าที่สุดสร้างเมื่อ 2026-07-07
```

with these causes added to the trace ages section's list: FiveM rebuilding or replacing its index (whether and
when it does is not established), FiveM's own "clear cache", cache files copied from another PC or restored
from a backup, and a reinstall that kept the cache.

### 8. What is not done

- **No verdict, no score, no colour, no ranking**, and no word such as "suspicious", "inconsistent" or
  "does not fit" in the output. "Before the session began" is a time relation, and it is printed beside its
  causes.
- **No comparison with the scan's own time.** A source that is old against the scan is ordinary after a long
  session or a session days ago.
- **No rule.** The statement is in the view; no rule reads `started_at`, `fivem_edition` or the index fields,
  and no evidence row depends on a session.
- **No rule or list that names a cleaning program**, for ADR 0061 section 4's reasons.
- **No state between scans**, and no comparison of one report with another.
- **No GTA V executable as an anchor**, for the reasons in section 2.

### 9. What this ADR does not write down

It names the sources compared with the session and when FiveM was measured to write them, because a reviewer
cannot read a line without knowing what it compares. It does not describe how a line could be avoided, and
nothing written under this ADR — code comments, rule text, guides, pull requests — may. That is AGENTS.md's
purpose boundary; a finding of that kind goes to a private report under `SECURITY.md`.

## Alternatives weighed

| Alternative | Why not |
|---|---|
| Compare FiveM's folders with the scan's time | Enhanced's game logs are as old as the session is long; every long session would print a line |
| A rule "FiveM's logs are older than its last run" | A join in the engine (ADR 0028) and a `found` row in SS mode on every PC where FiveM was opened without the game starting |
| Show the statement only when a line is "before" | A statement that appears only on a misfit is read as a finding; shown on every PC with an anchor, the ordinary picture is what a reviewer learns first (owner decision 5) |
| Edition from the executable's name | Both editions name the client `FiveM.exe` |
| Edition in the view from the emitted path | BAM's path is withheld and Prefetch has none; deriving it in the core would need the path in the report |
| GTA V's executables as anchors | `GTA5_Enhanced.exe`'s Prefetch was not rewritten in the session measured; GTA V runs without FiveM |
| Remember the last scan and compare | State kept on the scanned PC, written by a read-only tool, and a second report to trust |
| Exact times instead of durations | Durations from the session are what a reviewer compares; exact times of every folder add matching power without adding a comparison |

## What is unverified

- **One session per edition, on one PC.** A second day, a server already fully cached, launching without
  joining, and an hour-long session are not measured (the plan below).
- **What a BAM time means.** Measured: the end of the session after the game closed, and an earlier ended
  process of the same path during play. Not documented by Microsoft.
- **Why `GTA5_Enhanced.exe`'s Prefetch file was not rewritten** in the Enhanced session, when it was the
  evening before.
- **Whether a `.pf` file's string table names FiveM's program folder** for its executable, which
  `fivem_edition` on `prefetch` needs.
- **When Legacy writes its index**: on joining (about 70 s after launch) or on launch. Launching without
  joining was not measured, so the index is treated as a join source.
- **Whether Legacy's logs are written at exit.** The last write was two minutes before BAM's end.
- **How many logs each edition keeps.** Legacy removed one at launch; Enhanced kept 11 per family.
- **`GetProcessTimes` under a limited token** against FiveM's processes, and against a process of an
  elevated or another account. The probe read creation times through CIM, elevated.
- **Whether Legacy's index folder is ever recreated by FiveM itself** while its cache files stay.
- **The roaming storage folder's name**, which the probe masked.
- **Steam and Epic launches**, and a FiveM installed outside the default folders.

## Before any code: more sessions to measure

This is a precondition of the implementation, kept by the owner with the decisions below. A second read-only
probe of the same kind, on the same PC, elevated, and once with the limited token for the anchors, printing
ages and counts only:

1. **A second day.** One Legacy and one Enhanced session on another day, read during play, right after, and
   the next day before FiveM is opened again — the owner's "newest log is from yesterday" shape on an ordinary
   PC.
2. **A server already fully cached.** Join the same server twice in a row; whether `server-cache-priv`, its
   index and Enhanced's per-server folder are written on the second join.
3. **No join.** Open FiveM, reach the server list, close it; and separately open FiveM and close it while it
   updates. Which places are written, and what Prefetch and BAM hold.
4. **An hour in game** (if the owner agrees). Whether Legacy's logs and cache keep being written, and how old
   Enhanced's game logs and per-server folder are at the end; what BAM holds during play.
5. **The anchors under the limited token.** `started_at` for FiveM's processes through `GetProcessTimes`
   from a limited process, and Prefetch's string table for `FiveM.exe`'s program folder, both editions.
6. **The roaming storage folder's name**, printed as a fixed name only if it is FiveM's own and the same on
   another install.

The results are recorded in this ADR, as an amendment, before the change that builds it is opened. The margin
(section 3) is confirmed or changed from what they show, and any decision they contradict goes back to the owner.

## Owner decisions (2026-10-01)

1. Session statements are a second kind of cross-source statement: `view::cross_source` returns ADR 0061's
   statement and at most one session statement per edition, told apart by `CrossSourceStatement.kind`. ADR
   0061 section 3's "exactly one statement" is amended accordingly in the change that builds this.
2. `process` gains `started_at`, the process's creation time from `GetProcessTimes` on the handle it already
   opens with `PROCESS_QUERY_LIMITED_INFORMATION`; a time that cannot be read omits the field.
3. `fivem_edition` (`legacy` or `enhanced`) is derived inside `process` and `bam` from the path each already
   reads, never emitting a path. `prefetch` gains it only after measurement 5 shows that a `.pf` file's string
   table names FiveM's program folder; until then a Prefetch `FiveM.exe` is an anchor only when one edition's
   `FiveM.exe` is present, and `FiveM_b…_GTAProcess.exe` is Legacy's by name.
4. The margin is ten minutes either side of the session's start and end, shown in the text, and confirmed or
   changed by the measurements before any code.
5. The statement is shown whenever an edition has a session anchor, whether or not any of its lines is
   "before", "not there" or "no file".
6. `fivem_dir`'s `legacy_server_cache` gains `index_created_at`, `index_modified_at`, `index_files`,
   `index_latest_created_at` and `index_latest_modified_at`, from the listing it already makes and one listing
   of the fixed `db` subfolder, with no file name; ADR 0053 section 1 is amended in the change that builds it.
   The trace ages row shows the index's creation date beside the oldest cache file's.
7. No new place in this change: `data\cache\servers`, `%APPDATA%\CitizenFX` and Enhanced's roaming storage
   folder are not read. They are reconsidered after the measurements name the storage folder.
8. Each edition's latest session is used whatever its age, and its age is printed; there is no time limit.
9. The statement is shown in both modes, with the anchors' times at the timeline's precision and every source
   as a duration from the start or the end. The consent question and `PRIVACY.md` name process start times,
   the edition word and the index times in the change that ships them.

With these decisions the owner kept the measurements under "Before any code" as a precondition: they are
recorded here before the implementation is opened.

The points under "What is unverified" stay open until those measurements, or the change that builds this,
say which they settled.

## Consequences

- `rongroi-host`: `ProcessRecord.started_at`; `LiveHost` calls `GetProcessTimes`; `FixtureHost` reads an
  optional `started_at`; `NonWindowsHost` unchanged.
- `rongroi-collectors`: `process` gains `started_at` and `fivem_edition`; `bam` and `prefetch` gain
  `fivem_edition` (decision 3); `fivem_dir`'s `legacy_server_cache` gains the five index fields (decision 6).
  New fields, no new reason; `REPORT_SCHEMA_VERSION` stays at 1.
- `rongroi-core`: `CrossSourceStatement.kind`, a `SessionStatement` shape and its line forms, built by
  `view::cross_source`; the `legacy_server_cache` trace ages row shows the index beside its oldest file.
- CLI and desktop show the statement in both languages; `check-locales` checks its strings.
- Fixtures: synthetic hosts for a session read elevated (each line form), a session read with the limited
  token while FiveM runs, the same with nothing running ("not known"), Prefetch switched off, and an index
  newer than its oldest cache file. No fixture claims to be a measured PC.
- Consent text, `PRIVACY.md`, `docs/architecture.md`, both screenshare guides ("what not to conclude" gains a
  session statement's causes) and the glossary (**session**, **session statement**, `fivem_edition`) change
  with the code.
- ADR 0053 and ADR 0061 are amended in the change that builds this (decisions 1 and 6).
