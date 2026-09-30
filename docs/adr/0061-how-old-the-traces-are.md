# ADR 0061 — How old the traces are, beside how old the machine is

- Status: accepted — the owner decided the eight questions below on 2026-09-30
- Date: 2026-09-30
- Amended: 2026-09-30, with a read-only measurement on a Windows 11 PC ("Measured on a Windows 11 PC
  (2026-09-30)"); the anchor table and the owner decisions follow it
- Implemented: in one change with ADR 0047's `journal_created_on` amendment ("As built")

## Context

The owner asked on 2026-09-16 for this (plan item P7): however carefully the traces on a PC were removed,
a reviewer reading the report should still be able to see that something does not fit, even when nothing
in the report is direct evidence of removal.

ADR 0002 rules out the obvious answer. There is no verdict, no score, and no "abnormal" or "suspicious"
label anywhere in this program, and this repository has no data about ordinary players' PCs to compare a
PC with. What the program can do is **put facts from the same PC side by side**, each with the ordinary
causes of the same result, and leave the judgement to the reviewer. A PC whose Windows folders are years
old, whose FiveM folders were written yesterday and whose records of programs that ran reach back two
days is something a reviewer can read without being told what to think of it.

Four things the report already holds, or does not hold, shape the answer.

1. **Each source's oldest time is there, but scattered.** `evtx` reports each log's
   `oldest_record_time`, its size and, for a log with one channel, the configured `max_size_bytes`
   (ADR 0028, ADR 0042). `prefetch`, `bam` and `pca` carry `last_run` per entry. `usn` carries the journal's
   `first_seen`..`last_seen`. `fivem_dir` carries the earliest and latest file times of FiveM's own
   folders (ADR 0053). The timeline (ADR 0051) lines up the times; it shows spans for `evtx` and `usn` as
   coverage bands, but no count and no oldest time for the other sources, and in SS mode only the times of
   what that mode lists or a timeline selector selects.
2. **Nothing in the report says how old the machine is.** The header has `generated_at` and `boot_time`
   (ADR 0039). `boot_time` is when the running kernel started counting; it says nothing about how long
   Windows has been installed.
3. **The obvious anchor is wrong.** `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\InstallDate` was
   measured on 2026-09-16 on a Windows 11 PC (build 26220): it named a date about six weeks earlier, while a
   Rockstar Games Launcher log on the same PC reached back more than seven years. A feature upgrade rewrites it. The
   `Cryptography` and `ProfileList` keys' last-write times on the same PC were seven hours after that
   `InstallDate`, so they were rewritten by the same upgrade. Neither is the machine's age.
4. **The engine does not join observations** (ADR 0024, ADR 0028), and should not. "FiveM is installed
   but Windows holds no record of it running" is a statement about two collectors at once, so it cannot be
   a rule. ADR 0034 reserved such facts for Rust, where a test can contradict them.

## What was measured before this ADR

All on one Windows 11 PC (build 26220), read-only, with the owner's permission, printing counts and times
only (plan P0, 2026-09-16, and ADR 0047's amendment, 2026-09-30). Nothing was committed from those runs.

| Fact | Value on that PC |
|---|---|
| `InstallDate` | about six weeks before the measurement — after a feature upgrade to an Insider build, not the first installation |
| Oldest Rockstar Games Launcher log line | more than seven years before the measurement |
| `Cryptography` and `ProfileList` key last-write | about seven hours after `InstallDate` |
| USN journal identifier, **if read as a FILETIME** | a date more than seven years back: older than `InstallDate`, and of the same era as the launcher log. One sample; that the identifier is a time at all is not documented |
| Prefetch | 451 files, their times reaching back to the upgrade; unreadable under the limited token |
| USN journal span | 39 minutes, twice, fifteen days apart (32 MiB maximum size, trimmed) |
| `Microsoft-Windows-CodeIntegrity/Operational` | at its 1 MB maximum, reaching back about six weeks |
| Event Log channel sizes (ADR 0042) | 1 166 of 1 243 channels at the 1 MB floor |

## Decision

### 1. A "trace ages" section, a new view beside the timeline

`rongroi_core::view` gains `trace_ages(report, mode) -> TraceAges`, and `ReportView` gains
`trace_ages`. It is additive, as `timeline` was, and `REPORT_SCHEMA_VERSION` stays at 1.

**Why not the timeline.** The timeline is a list of times from observations a mode may show. A trace age
is a fact about a **source** — how far back it still reaches and how much it holds — computed over every
observation of that source, including ones SS mode counts rather than lists. ADR 0051 already made that
distinction for coverage bands: a band is built "in both modes, because a span is a fact about the source
rather than about a program or a file". Trace ages extend the bands; they do not add entries to the
timeline. The section is built from the same report fields the timeline reads (`timestamp_fields`,
`coverage_fields`, `discriminators`, `unmeasured_sources`) plus one new declaration.

**The declaration.** The core does not guess which field is a source's oldest time (ADR 0051 section 2).
`Collector` gains `age() -> Option<Age>`, and `scan::run` copies it into a new additive report field,
`age_fields`:

```text
Age {
  oldest: field,            // the time whose minimum over the source's observations is its oldest
  count: Observations | Field(field),   // how much it holds
  place: Option<value>,     // restrict to observations with this discriminator value (ADR 0044)
  per_place: bool,          // one row per discriminator value instead of one per collector
  extra: [field],           // shown beside the row, never compared: size_bytes, max_size_bytes, trimmed
}
```

| Source | Row | Oldest time | Count | Shown beside it |
|---|---|---|---|---|
| `evtx` | one per log | `oldest_record_time` | `entries` | `size_bytes`, `max_size_bytes` when the Event Log service states one |
| `prefetch` | one | the oldest `last_run` over the `.pf` entries — the oldest of the newest run times each file still holds | entries | `enable_prefetcher` |
| `bam` | one | the oldest `last_run` | entries | — |
| `pca` | one | the oldest `last_run` | launch entries | — |
| `usn` | one, the journal | `first_seen` of `location: journal` | `records` | `last_seen`, `maximum_size`, `trimmed` |
| `fivem_dir` | one per ADR 0053 place | `earliest_created_at` and `earliest_modified_at` | `files`; for `enhanced_server_cache`, server folders | `latest_modified_at` |

Each row states, in this order:

1. **The oldest time still present**, as the report holds it, and how many days before `generated_at`
   that is. Days are the one unit every row uses, so a reviewer compares them without converting.
2. **The count.**
3. **The source's ordinary retention**, in words, with its reference and a mark saying whether Microsoft
   documents it. Where it does not, the text says "not documented by Microsoft" and names what the
   statement rests on. These texts are reviewed data (section 1, "Where the texts live").
4. **Its unmeasured reason**, when the source, or the place, was not read. The row is still shown, with the
   reason in place of the time and the count. `not_admin` reads "not read without administrator rights —
   not known", never "0" or "empty". `source_absent` and `source_empty` keep their ADR 0030 wording.

**Ordinary retention, per source** (checked 2026-09-30):

| Source | What the row says | Documented? |
|---|---|---|
| `evtx` | A log keeps records until it reaches its maximum size; with the default retention, the oldest are then overwritten. The size is set per log, and the documented default for the classic logs is 1 MB. Microsoft, [Eventlog Key](https://learn.microsoft.com/en-us/windows/win32/eventlog/eventlog-key): `MaxSize` *"The default value is 1MB"*; `Retention` *"If this value is 0, the records of events are always overwritten."* The policy CSP gives other defaults for Security ([EventLogService](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-eventlogservice)), and ADR 0042 measured the floor as the ordinary size of most channels | yes |
| `usn` | The journal keeps a size, not a time; past its maximum size the oldest records are truncated. [USN_JOURNAL_DATA_V0](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-usn_journal_data_v0), `MaximumSize`. How long that reaches depends on how busy the volume is: 39 minutes on the one PC measured | yes (the size); the span is measured per scan |
| `prefetch` | Windows removes Prefetch files itself, and keeps none when Prefetch is switched off. A cap of 1 024 files is widely described, **not documented by Microsoft** (ADR 0030) | no — unverified |
| `bam` | Windows removes old entries itself; how old is **not documented by Microsoft**. ADR 0030 reads a seven-day removal at start from `BampScavengeUserSettings`, but the PC measured on 2026-09-30 held entries 47 days old, so the row states neither number as a rule | no — unverified, and the seven days contradicted on one PC |
| `pca` | The files exist on Windows 11 22H2 and later and record launches made from File Explorer (ADR 0020, ADR 0030). How long they keep an entry is **not documented by Microsoft** and not measured | no — unverified |
| `fivem_dir` | FiveM's own folders; how long FiveM keeps logs, crash dumps and caches is **not documented** by FiveM and not measured (ADR 0053) | no — unverified |

**What the section never does.** It does not sort rows by age, colour a row, compute a difference between
two rows, name a row "short" or "recent", or add any number up. It lists sources in `COLLECTOR_ORDER`,
anchors first (section 2). A sentence above it, in both modes, says: *"How far back each source reaches on
this PC, beside when parts of this PC were set up. A source that reaches back only a short way is ordinary
on many PCs; the causes are listed under each row. Nothing here is evidence on its own, and the report cannot
prove a PC is clean."*

**Both modes.** A trace age names no program and no file. In SS mode it adds, for `prefetch`, `bam` and
`pca`, a count and an oldest time that SS mode does not show today (ADR 0034 decision 2). The consent
question and `PRIVACY.md` name that in the change that ships it. `evtx` rows name a log by its file name,
which SS mode already shows in the coverage bands.

**How many `evtx` rows.** A Windows 11 PC has about 400 logs. The section's first rows are the logs this
program's rules and timeline selectors read (System, Security, Windows PowerShell, PowerShell/Operational,
CodeIntegrity/Operational, Windows Defender/Operational), and the rest are folded under one line with how
many logs there are and how many hold records (decision 3).

**Where the texts live.** The retention text, its reference and its documented mark are one file per
source in the rules bundle, `rules/ages/<collector>.yaml`, with translations in `rules/i18n/th.yaml` as a
rule's are. `check-rules` refuses a declared `Age` with no text, a text with no reference, and a
`documented: true` whose reference is not a Microsoft Learn URL. That keeps them where ordinary causes are
already reviewed, and in the bundle hash (decision 2).

### 2. Anchors: facts about when parts of this PC were set up, never one "machine age"

There is no single machine age, and the report does not compute one. It shows **anchors**: dated facts
about the installation, each with what it is and what ordinarily resets it. ADR 0039 put `boot_time` in the
header rather than in an observation so that no rule could read it. The same holds here: a rule on "the PC
is new" would be a verdict about an innocent fact. So anchors go in the header, as
`ReportHeader.anchors: Vec<Anchor>`, each `measured { on, source }` or `unmeasured { reason }`, and the
trace ages section shows them above the sources, in days before the scan.

**Precision: the UTC date, not the time.** An anchor exists to be compared in days and months. A value to
the second, such as a key's last-write time or a journal's creation time, is the same in every report of
one PC and would let two reports be matched, which is why ADR 0047 left the journal identifier out. A date
blurs that without blurring the comparison (decision 4). `boot_time` keeps its ADR 0039 precision.

The candidates:

| Anchor | What it would add | What it is | What ordinarily resets it | Decided (decision 5) |
|---|---|---|---|---|
| `boot_time` | Nothing: already in the header | When the running kernel started counting | Every restart; not a "Shut down" with Fast Startup (ADR 0039) | Shown in this section as it is. It bounds BAM (cleared at start) and nothing else |
| `InstallDate` / `InstallTime` | Nothing: `RegistrySource::read_value` reads them | When this installation was installed **or last upgraded to a new feature version** — measured | A feature upgrade, a reset, a reinstall | Shown, labelled exactly that way, never "installed on" |
| Setup's record of earlier installations (`HKLM\SYSTEM\Setup\Source OS (Updated on …)`) | Nothing: `subkeys` and `read_value` | Each subkey keeps an earlier installation's values, including its `InstallDate`, when a feature upgrade runs. **Not documented by Microsoft** | A reset or a clean reinstall leaves none | **Shown**, as "earliest installation date Windows Setup kept" and how many it kept, marked undocumented; no subkey name is emitted. Measured: eight, the oldest more than seven years old, readable without Administrators |
| Registry key last-write, `Cryptography`, `ProfileList` | `RegistrySource::key_written(key) -> Result<Option<Timestamp>, SourceError>`, through [RegQueryInfoKeyW](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryinfokeyw): *"the last time that the key or any of its value entries is modified"*; the key needs only `KEY_QUERY_VALUE` | The last time anything wrote the key, not when it was made | A feature upgrade (measured: seven hours after `InstallDate`); any program that writes a value there | **Not shipped**: measured twice to follow `InstallDate` (within a day of it on 2026-09-30); `CurrentVersion` and `SYSTEM\Setup` followed the last boot. It adds nothing but a weaker copy of `InstallDate`. `RegistrySource::key_written` is not added |
| Key last-write, BAM `UserSettings`, PCA keys | the same capability | The last time Windows recorded a run | Every program start | **Not shipped**: it is a "last run" time, not an anchor |
| USN journal creation | `usn`'s journal observation gains `journal_created_on`, the date the identifier gives **if it is a FILETIME**, and never the identifier; amends ADR 0047's "Not `UsnJournalID`" | The identifier is documented only as assigned on creation and possibly restamped ([Using the Change Journal Identifier](https://learn.microsoft.com/en-us/windows/win32/fileio/using-the-change-journal-identifier)); that it encodes a time is **not documented** | Deleting and creating the journal again; a restamp when the volume moves between NTFS versions (dual boot, removable media); a new volume | **Shown**, as `journal_created_on`, marked "the identifier read as a time; not documented". Measured: it reads as a date within one day of the oldest installation date Windows Setup kept, more than seven years before the scan. Administrators only, like the rest of `usn` (limited token: error 5, measured) |
| The system drive's own folders | `FilesystemSource::times(path) -> Result<Option<EntryTimes>, SourceError>`: one path's own creation and last-write times, without listing its parent (the parent of a profile folder is a profile root, whose listing holds other people's names) | Creation dates of fixed paths. Measured: the drive root and `$Recycle.Bin` kept dates older than seven years; `Windows`, `System32`, `Program Files`, `ProgramData`, the profiles directory, `Public` and `Default` were all created 75 days before the scan, and the account's profile folder 60 days before — **reset**, not anchors | Formatting or replacing the volume; a disk cloning tool may or may not keep creation times (unverified); for the reset folders, an upgrade or reinstall | **Shown for the drive root and `$Recycle.Bin` only**, as "system drive root created". The other folders are not shown: on the PC measured they were rewritten by something newer than every other anchor |
| FiveM's own install | `fivem_dir`'s two `FiveM.exe` observations gain `program_folder_created_at` and `app_folder_created_at` (`FiveM.app`), through the same `times` capability | When FiveM's program folder was created on this account | Reinstalling FiveM, removing its folder, moving or recreating the profile. **Not** `FiveM.exe`'s own creation time: Enhanced's was measured at 5 days against its folder's 24, so an update replaces the file | **Shown** as the FiveM anchor, beside FiveM's folder activity rows. Measured: Legacy's folder older than `InstallDate` (it survived the upgrade), readable without Administrators |

**Rights.** `GetTickCount64` needs none (ADR 0039). `HKLM\SOFTWARE` values and folder times are expected
to be readable under a limited token; the journal needs Administrators (ADR 0047, measured). The probe
measures each under both tokens, and a read that fails is `unmeasured` with its reason.

### 3. Cross-source statements, in the view

`rongroi_core::view` gains `cross_source(report, mode) -> Vec<CrossSourceStatement>`, and `ReportView` gains
`cross_source`. A statement is **a set of facts from different collectors printed together**. It is not
evidence: it has no `found`, `not_found` or `unmeasured` state, no rule id, no strength, it is never
counted in `ListedCounts` or `HiddenCounts`, and nothing in the engine changes. It is computed in Rust in
the core, where fixtures and tests can contradict it, as ADR 0028 and ADR 0034 require of a fact about more
than one observation.

**There is exactly one statement.** It compares two groups of sources:

- **FiveM's side**, from `fivem_dir`: whether either edition's `FiveM.exe` is present, the latest
  `latest_modified_at` over FiveM's log, crash and cache folders (ADR 0053), and how many Enhanced server
  cache folders there are with the latest `modified_at` among them. The server cache folders come from
  `fivem_dir` (standard tier); a full scan's `fivem_servers` adds only names, which the statement never uses.
  Call the later of the two times **T**.
- **Windows' records of programs that ran**: `prefetch`, `bam` and `pca`, each as the report's
  `timeline_selections` for the FiveM timeline selectors on that collector (ADR 0051 section 4, first row:
  two files per collector), and each source's trace age (section 1).

It is shown when all of these hold:

1. FiveM's side was read and is present: a `FiveM.exe`, or a server cache folder.
2. At least one of `prefetch` and `bam` was read, its FiveM selectors selected nothing, and its oldest held
   time is **earlier than T** — that is, T falls inside what that source still holds. A source that reaches
   back less far than T could not show T at all, and a statement about it would be the "absent means
   removed" reading ADR 0051 section 6 forbids.
3. The bundle holds the FiveM timeline selectors on those collectors.

`pca` alone never makes a statement: it records launches from File Explorer only and does not exist before
Windows 11 22H2 (ADR 0030), so its silence is ordinary for any game started from a launcher.

**How unmeasured sources qualify it.** Every one of the three sources gets its own line, always, in one
of four forms:

| The source | Its line |
|---|---|
| read, FiveM selectors selected something | how many entries, and the latest time |
| read, selected nothing, oldest held time earlier than T | no entry for those names; how many entries it holds, and its oldest |
| read, selected nothing, oldest held time later than T | it holds nothing as old as T, so it could not show it |
| not read (`not_admin`, `access_denied`, `partial`, …) | not read, the reason, and "whether it holds an entry is not known" |
| Prefetch switched off (`EnablePrefetcher` 0 or 2, `service_disabled`, ADR 0030) | Prefetch is switched off on this PC; it keeps no such record |

A source that was not read is never folded into "no entry". When condition 2 is met by one source and the
other is not read, the heading says so ("Prefetch holds no entry …; BAM was not read"), never "none of".
The words "none of these" appear only when all three were read and all three selected nothing.

**Why this pair and no other.** It is the one comparison where both sides are already in the report, where
the absent side has a span that can be checked against T, and where the names compared are a reviewed,
published list rather than anything the core chooses. Other pairs were weighed and are not built:
Event Log spans against the anchors are already side by side in the trace ages section and need no
sentence; the USN journal's 39-minute span makes any comparison with FiveM's folders empty on the PC
measured; crash dumps against Windows Error Reporting would need a read this program does not do.

**SS mode.** The statement is shown in both modes, above the timeline. It contains no path, no file name,
no user name and no server name: FiveM's side is a presence, a count and times; the other side is
counts, times, and the executable names the FiveM timeline selectors list, which the SS consent question
already names (ADR 0051 section 5). Its times are the same values SS mode already shows through the
FiveM selectors and the folder activity selector.

**The text.** English:

```text
FiveM on this PC, beside Windows' records of programs that ran

FiveM:   FiveM.exe is present (Enhanced). FiveM's own folders were last written 2026-05-19 (1 day
         before this scan). 3 server cache folders, the latest written 2026-05-19.
Prefetch: no entry for FiveM.exe, GTA5.exe, GTA5_Enhanced.exe, PlayGTAV.exe or FiveM_b…_GTAProcess.exe.
          It holds 480 entries; the oldest is from 2026-04-02 (48 days before this scan).
BAM:     not read without administrator rights. Whether it holds an entry is not known.
PCA:     no entry for those names. It holds 3 entries; the oldest is from 2026-05-01.

This is not evidence of anything. The same result follows from:
- Windows installed again, reset, or a new PC, with FiveM's folders copied or synced from before
- Windows' own clean-up (Disk Cleanup, Storage Sense), or a clean-up program of any kind
- Prefetch switched off, as some older SSD and performance guides advise
- FiveM reinstalled, or its folders moved from another drive or PC
- FiveM started under a name these records do not list, or in a way Windows does not record here
- Windows removing its own records: Prefetch files are replaced, BAM entries expire, PCA records only
  launches from File Explorer
- a clock that was changed, so that times from different sources are not on the same clock
```

Thai:

```text
FiveM ในเครื่องนี้ เทียบกับบันทึกของ Windows ว่าโปรแกรมใดเคยรัน

FiveM:    พบ FiveM.exe (Enhanced) โฟลเดอร์ของ FiveM ถูกเขียนครั้งล่าสุด 2026-05-19 (1 วันก่อนสแกน)
          มีโฟลเดอร์ cache ของเซิร์ฟเวอร์ 3 โฟลเดอร์ ล่าสุดถูกเขียน 2026-05-19
Prefetch: ไม่มีรายการของ FiveM.exe, GTA5.exe, GTA5_Enhanced.exe, PlayGTAV.exe หรือ FiveM_b…_GTAProcess.exe
          มีรายการทั้งหมด 480 รายการ เก่าสุดคือ 2026-04-02 (48 วันก่อนสแกน)
BAM:      อ่านไม่ได้เพราะไม่มีสิทธิ์ผู้ดูแลระบบ จึงไม่รู้ว่ามีรายการหรือไม่
PCA:      ไม่มีรายการของชื่อเหล่านี้ มีรายการทั้งหมด 3 รายการ เก่าสุดคือ 2026-05-01

ข้อมูลนี้ไม่ใช่หลักฐานของสิ่งใด ผลแบบเดียวกันเกิดได้จาก:
- ติดตั้ง Windows ใหม่, Reset หรือเป็น PC เครื่องใหม่ แล้วคัดลอกหรือ sync โฟลเดอร์ของ FiveM มาจากเดิม
- การล้างของ Windows เอง (Disk Cleanup, Storage Sense) หรือโปรแกรมล้างเครื่องทุกชนิด
- ปิด Prefetch ตามคู่มือ SSD หรือคู่มือเพิ่มความเร็วรุ่นเก่า
- ติดตั้ง FiveM ใหม่ หรือย้ายโฟลเดอร์ของ FiveM มาจากดิสก์หรือเครื่องอื่น
- เปิด FiveM ด้วยชื่อที่ไม่อยู่ในรายการนี้ หรือด้วยวิธีที่ Windows ไม่ได้บันทึกไว้ที่นี่
- Windows ลบบันทึกของตัวเอง: ไฟล์ Prefetch ถูกแทนที่, รายการ BAM หมดอายุ, PCA บันทึกเฉพาะการเปิดจาก File Explorer
- นาฬิกาเครื่องถูกเปลี่ยน ทำให้เวลาจากแต่ละแหล่งไม่ได้อยู่บนนาฬิกาเดียวกัน
```

The numbers above are invented to show the shape; they are not a measurement. The heading, the line forms and the
list of causes are fixed strings in the locale files, checked by `check-locales`; the core fills in only
dates, day counts, counts, the edition and the reason. The causes are always printed in full under the
statement, whatever the lines say, as a timeline selector's are under the timeline.

**The same causes for the trace ages section**, printed once under it: Windows installed again or reset, or
a new PC; Disk Cleanup, Storage Sense and clean-up programs in general; a small Event Log size set by
policy or by a tool; Prefetch switched off by an older SSD guide; FiveM reinstalled; a drive or profile
moved; a clock that was changed.

### 4. What is not done

- **Timestamp forgery detection.** Telling a file time a program wrote from one the file system wrote
  needs NTFS metadata this program does not read: ADR 0041 ruled out reading the raw volume. File times
  stay "what the file system reports" (ADR 0050 section 3), and so do anchors.
- **Rules that name a clean-up program.** Prefetch, BAM and PCA carry a name and no identity (ADR 0034); a
  rule naming a program cannot exclude a legitimate one of the same name, and many clean-up programs are
  ordinary maintenance tools.
- **Hash lists of clean-up programs.** No public, citable list exists, and ADR 0041 notes that a list
  compiled into this program becomes public with it.
- **Any verdict, score, colour or ranking** across rows, anchors or sources, and any sentence that says a
  source is "too short" or "unusually clean". The reviewer compares; the report does not.

**The limit, plainly.** A PC on which Windows was installed again yesterday and a PC bought yesterday
leave the same traces. Nothing this program reads tells them apart, and a statement about either says
so. A reviewer who sees young sources and young anchors is looking at a new installation, and that is
all the report can say about it.

### 5. What this ADR does not write down

It describes what the report shows and what is compared, at the level of "sources whose ages are
compared". It does not describe how a statement could be avoided, and nothing written under this ADR —
code comments, rule text, guides, pull requests — may. That is AGENTS.md's purpose boundary; a finding
of that kind goes to a private report under `SECURITY.md`.

## Alternatives weighed

| Alternative | Why not |
|---|---|
| One "machine age" | Every candidate has an ordinary reset, and they disagree on the one PC measured by seven years. One number would hide which reset happened |
| Trace ages as timeline entries | The timeline lists times of observations a mode may show; an oldest time and a count over hidden observations is a fact about the source, like a band |
| A rule "Prefetch is empty although FiveM is installed" | A join in the engine (ADR 0028) and a `found` row, which is a verdict in SS mode on every freshly installed PC |
| A statement whenever FiveM is present | On a PC whose BAM reaches back three days and whose FiveM last ran a week ago, "BAM holds no FiveM entry" is ordinary and would be printed on most PCs. Condition 2 limits it to the case where the source still reaches T |
| Retention texts compiled into the core | Reviewed less visibly than a bundle file with translations and references (the same argument ADR 0051 made for timeline selectors) |
| Registry key last-write times as anchors | Measured to follow the feature upgrade; they add no fact `InstallDate` does not already give |
| Anchors to the second | Matches two reports of one PC for no gain in a comparison made in days |

## What is unverified

- That the USN journal identifier is a creation time. On one PC it read, twice, as a date of the same era as
  the oldest installation Windows Setup kept (within one day on 2026-09-30); Microsoft documents it only as an
  identifier.
- That `HKLM\SYSTEM\Setup\Source OS (Updated on …)` keeps earlier installation dates on every Windows 10 and
  11 PC. Not documented by Microsoft; one PC kept eight.
- What rewrote `Windows`, `Program Files`, `ProgramData` and the profiles directory 75 days before the scan
  on the PC measured: it matches neither `InstallDate` (60 days) nor any date Windows Setup kept.
- Whether the system drive root's creation date survives a disk cloning tool.
- Prefetch's 1 024-file cap, BAM's retention (seven days by ADR 0030's reading, 47 days held on one PC) and
  PCA's retention: not documented by Microsoft.
- The format of PCA's launch file on build 26220: the probe found one line and could not read a time from it.
- How far back each source reaches on PCs other than the one measured. One PC is not a distribution, and
  this ADR does not claim what is ordinary for players.
- Whether FiveM keeps its program folder's creation time across its own updates. Legacy's did, on one PC;
  the executable's did not.

## The probe

A read-only PowerShell probe, kept out of the repository, measured on a Windows 11 PC (build 26220) on
2026-09-30, once with an elevated token and once with the account's limited token through a scheduled task with the limited run
level (the method of ADR 0060's probe). It prints ages in days before now, counts, error codes and fixed
labels only — no key name below a fixed path, no value name, SID, GUID, journal identifier, file name, path
or user name. It sends only the two USN read control codes.

- **Anchors**: time since boot; `InstallDate` and `InstallTime`; how many `Source OS` subkeys and the
  oldest and newest `InstallDate` among them; `RegQueryInfoKeyW` last-write ages for `Cryptography`,
  `ProfileList` and its subkeys (count, oldest, newest), `CurrentVersion`, `SYSTEM\Setup`, BAM `UserSettings`
  and its subkeys, `AppCompatFlags` and the account's PCA store key, **with the error code under the
  limited token**; the journal identifier read as a FILETIME, as an age or `not_a_plausible_filetime`; the
  creation and last-write ages of the system drive root, `Windows`, `System32`, the `SYSTEM` hive, `Panther`,
  `Program Files` (both), `ProgramData`, the profiles directory, `Public`, `Default`, the account's profile,
  `Windows.old` and `$Recycle.Bin`; how many profile folders there are and their oldest and newest creation;
  FiveM's program folders, `FiveM.app`, `FiveM.exe`, `citizen` and the roaming folders.
- **Oldest record per source**: for eight fixed Windows logs, records, size, maximum size, mode and the
  oldest record's age; for all logs, how many, how many hold records, how many are within 64 KiB of their
  maximum, and the oldest, median and youngest oldest-record ages; Prefetch's `EnablePrefetcher`, `.pf`
  count and oldest and newest file times, and how many carry a FiveM selector name; BAM's user keys, values,
  oldest and newest `last_run`, and FiveM-named values; PCA's launch lines, oldest and newest time, FiveM-named
  lines, and the general databases' line counts; the journal's oldest record in minutes; for each ADR 0053
  place, folders, and the oldest and newest file creation and last-write ages, and for Enhanced's server
  cache the server folders' creation and last-write ages.

Its results are in the next section.

## Measured on a Windows 11 PC (2026-09-30)

The probe above ran on a Windows 11 PC (build 26220) on 2026-09-30, with the owner's permission: once
elevated, once under the same account's limited token through a scheduled task with the limited run
level. It printed ages and counts only; its output was not committed, and the task and its folder were
deleted (the probe's own cleanup line says so). Ages below are days before the scan, rounded; dates that
would identify the PC are given only as "more than seven years".

### Anchors

| Anchor | Age | What it shows |
|---|---|---|
| `boot_time` | 3.5 days | the last start |
| `InstallDate`, `InstallTime` | 60 days, both | the last feature upgrade, not the first installation |
| Windows Setup's earlier installations (`Source OS`) | 8 kept; the oldest **more than seven years**, the newest 214 days | the installations the upgrades replaced |
| USN journal identifier read as a FILETIME | **more than seven years**, within one day of the oldest `Source OS` date | a plausible date: see below |
| System drive root, created | more than seven years (about 137 days older than the oldest `Source OS` date) | the volume, older than every installation on it |
| `$Recycle.Bin`, created / last written | more than seven years / within one day of the oldest `Source OS` date | survived every upgrade |
| `Windows`, `System32`, the `SYSTEM` hive, `Program Files` (both), `ProgramData`, the profiles directory, `Public`, `Default` | all created **75 days** before the scan | reset — by an event that is neither `InstallDate` nor any `Source OS` date; what it was is not established |
| The account's profile folder, the other profile folders | 60 days; 5 folders, 60 to 75 days | reset with the upgrade |
| `Panther` | created 60 days | the upgrade |
| Key last-write: `Cryptography`, `ProfileList` | 60 days, both | followed `InstallDate` again, within a day |
| Key last-write: `CurrentVersion`, `SYSTEM\Setup` | 3.5 days | followed the last start |
| Key last-write: BAM `UserSettings` / its 7 subkeys | 46 days / 0 to 42 days | written as programs run |
| Key last-write: `AppCompatFlags`, the account's PCA store | under a day | written as programs run |
| `ProfileList` subkeys | 4, last written 3.5 to 75 days | written at sign-in |
| FiveM Legacy: program folder, `FiveM.app`, `FiveM.exe`, `citizen`, roaming `CitizenFX` | all created 111 days | older than `InstallDate`: FiveM's folders survived the upgrade |
| FiveM Enhanced: program folder, roaming folder / `FiveM.exe` | 24 days / 5.5 days | the executable is replaced by updates; its folder is not |

**The journal identifier is very likely a FILETIME**, and still undocumented. Read as one, it gives a date
within a day of the oldest installation Windows Setup recorded and of `$Recycle.Bin`'s last write, on a
PC where `InstallDate` is 60 days. Two independent sources agreeing to the day is what a creation time
would produce, and nothing else explains it as well; it is one PC, and Microsoft's page still describes
only an identifier. It also shows why the value must never be emitted as it is: to the 100-nanosecond it
names one journal on one PC.

**What a feature upgrade visibly reset**, on this PC: `InstallDate` and `InstallTime`, the `Cryptography`
and `ProfileList` keys, `Panther`, the account's profile folder, every Event Log's oldest record (the
oldest record over all logs is 60 days, the same day), and Prefetch's oldest file creation (60 days).
Something 75 days back rewrote the Windows and program folders and the profiles directory. What survived:
the drive root, `$Recycle.Bin`, the `Source OS` record, the journal, and FiveM's Legacy folders.

### Oldest record per source

| Source | Elevated | Limited token |
|---|---|---|
| Event Log | 496 logs, 150 holding records, 83 within 64 KiB of their maximum; 493 overwrite when full. Oldest record over all logs 60 days, median 59.5, youngest 0.2 | 458 logs, 131 with records; Security not readable; the rest the same |
| System (20 MiB, full) | 43 820 records, oldest 47 days | same |
| Security (20 MiB, full) | 29 697 records, oldest **2.3 days** | not readable |
| Application (13 of 20 MiB) | 13 777 records, oldest 60 days | same |
| Windows PowerShell (15 MiB, full) | 11 733 records, oldest 4.6 days | same |
| PowerShell/Operational (15 MiB, full) | 768 records, oldest **0.2 days** | same |
| CodeIntegrity/Operational (1 MiB, full) | 1 167 records, oldest 11 days | same |
| Windows Defender/Operational (3 of 16 MiB) | 2 832 records, oldest 60 days | same |
| Prefetch | `EnablePrefetcher` 3; 583 files, newest-run times back to 56 days, created back to 60 days; 6 carry a FiveM selector name | `EnablePrefetcher` readable; the folder is not |
| BAM | 7 user keys, 63 values, oldest `last_run` **47 days**; 2 carry a FiveM selector name | not readable |
| PCA | launch file: 1 line, no time the probe could read; general database 369 lines | same |
| USN journal | oldest record 45 minutes; trimmed | volume not opened (error 5) |
| FiveM Legacy folders | logs 3 files, 17–23 days; crashes 15, 40–53 days; cache 9, 17–25 days; `server-cache-priv` 5 227 files, 24–86 days | same |
| FiveM Enhanced folders | logs 37 files, 0.2–24 days; crashes 10, 15–18 days; launcher crashes 2, 15 days; 3 server folders, created 15–21 days, last written 3–15 days | same |

Three things the numbers change in the design:

- **Full logs reach back days, not weeks.** Security (2.3 days) and PowerShell/Operational (0.2 days) were
  at their 20 MiB and 15 MiB maximum on an ordinary PC in use. A short Event Log age next to a full log is
  ordinary, which is why the row shows the size beside the maximum and the text names "a full log".
- **BAM held entries 47 days old.** ADR 0030's seven-day reading is not what this PC shows; the retention
  text says only that Windows removes old entries and that how old is not documented.
- **The cross-source statement would not appear on this PC.** Prefetch holds 6 and BAM 2 entries with a
  FiveM selector name, and both reach back further than FiveM's latest folder write. That is the ordinary
  case, and the statement is built to stay silent in it.

### What fails under the limited token

- The USN journal (open error 5) and so `journal_created_on`.
- BAM: the values and the key's last-write time (error 5, `SecurityException`).
- The Prefetch folder (`UnauthorizedAccessException`); `EnablePrefetcher` is readable.
- The Security log, and 38 logs the listing does not show.
- The `SYSTEM` hive file's own times.

Everything else read the same as elevated: `InstallDate`, the `Source OS` record, `RegQueryInfoKeyW` on
`Cryptography`, `ProfileList` and its subkeys, `CurrentVersion`, `SYSTEM\Setup`, `AppCompatFlags` and the
account's PCA key, every folder time above including the drive root and `$Recycle.Bin`, PCA, and every
FiveM folder. A scan without Administrators still has four anchors (`boot_time`, `InstallDate`,
`Source OS`, the drive root) and FiveM's; its trace ages show Prefetch, BAM, the journal and Security as
"not read — not known".

## Owner decisions (2026-09-30)

1. Trace ages are a new view section, `view::trace_ages`, built from a new `Collector::age` declaration;
   they are not timeline entries (section 1).
2. Retention texts live in the rules bundle, `rules/ages/<collector>.yaml`, with a reference and a
   documented mark that `check-rules` checks. The BAM text states no number of days: ADR 0030's seven days
   and the 47 days measured disagree.
3. `evtx` rows: the logs the bundle reads come first, each with its size beside its maximum; the rest are
   folded under one line with how many logs there are and how many hold records.
4. Anchors are UTC dates, never times, in `ReportHeader.anchors`, where no rule can read them. The USN
   journal identifier itself is never emitted.
5. The anchors that ship: `boot_time` as now; `InstallDate`, labelled "installed or last feature-upgraded";
   Windows Setup's earliest recorded installation date and how many it kept (`Source OS`), marked
   undocumented; the USN journal's creation date (decision 6); the system drive root's and `$Recycle.Bin`'s
   creation dates, through a new `FilesystemSource::times`; FiveM's program folder and `FiveM.app` creation
   dates, not `FiveM.exe`'s. Registry key last-write times are not shipped, and `RegistrySource::key_written`
   is not added; the `Windows`, `Program Files`, `ProgramData` and profile folders are not anchors.
6. ADR 0047 is amended in the change that builds it: the journal observation gains `journal_created_on`, the
   date the identifier gives when read as a FILETIME, marked "the identifier read as a time; not
   documented". Administrators only.
7. One cross-source statement, FiveM's side against Prefetch, BAM and PCA, shown only when Prefetch or BAM
   was read, its FiveM timeline selectors selected nothing, and its oldest held time is earlier than T;
   every source not read is stated as "not known", and PCA alone never makes a statement (section 3).
8. SS mode shows the trace ages, the anchors and the statement. The consent question and `PRIVACY.md` name
   the per-source counts, the oldest times and the anchor dates in the change that ships them, which also
   changes ADR 0034 decision 2's promise as ADR 0051 did.

The points under "What is unverified" stay open; the changes that build this say which they measured.

## Consequences

- `rongroi-core`: `TraceAges`, `CrossSourceStatement`, `view::trace_ages`, `view::cross_source`,
  `ReportView.trace_ages` and `.cross_source`, `Report.age_fields`, `ReportHeader.anchors`, and the loader
  for `rules/ages/`. All additive; `REPORT_SCHEMA_VERSION` stays at 1.
- `rongroi-collectors`: `Collector::age` on `evtx`, `prefetch`, `bam`, `pca`, `usn` and `fivem_dir`;
  `scan::run` fills `age_fields` and the anchors; `fivem_dir` gains the two folder times.
- `rongroi-host`: `FilesystemSource::times`, answered by `LiveHost`, `FixtureHost` and `NonWindowsHost`.
  `RegistrySource::key_written` only if decision 5 changes.
- ADR 0047 is amended if decision 6 is taken; ADR 0034 decision 2's promise changes with decision 8, as
  ADR 0051 changed it.
- CLI and desktop show the section and the statement in both languages; `xtask check-rules` and
  `check-locales` check the new files; fixtures cover a source read, not read (`not_admin`), empty, and
  switched off, and each of the statement's line forms.
- Consent text, `PRIVACY.md`, `docs/architecture.md`, both screenshare guides ("what not to conclude" gains
  young sources and young anchors, both ways) and the glossary (**trace age**, **anchor** widened from
  ADR 0051's, **cross-source statement**) change with the code.

## As built

The change that builds this ADR took these choices where the text above leaves them open, each the option
the ADR recommends or the one that shows less:

- **The declaration.** `Collector::age` names a list of oldest fields, a count (the observations that carry
  one, or the sum of a number field), whether a row is the collector, one place of it or one value of a field
  (`evtx`'s `log`), the places that get a row, and the fields shown beside it. `fivem_dir`'s Enhanced server
  cache is declared apart (`by_place`): counted in server folders and dated by their creation and last-write
  times, as section 1's table says.
- **Which logs come first.** The logs the bundle's rules and timeline selectors name by `channel`, derived
  from the bundle when the scan runs: today `Security`, `System`, `CodeIntegrity/Operational` and
  `Windows Defender/Operational`. The two PowerShell logs section 1 names are not read by any rule or
  selector today, so they fold with the rest. The folded line also says how many of those logs could not
  be read.
- **Rows with nothing to read.** A declared place with no observation, or whose folder is absent, is
  `source_absent`; a log refused on its own takes the reason its `read` word gives (`access_denied` without
  administrator rights is `not_admin`, as the collectors decide it).
- **Days.** Whole days, rounded down: a source's oldest time against the scan's time; an anchor's date
  against the scan's UTC date; `boot_time` from its own count.
- **Anchors.** `source` is a fixed spelling of what was read, with any environment variable unexpanded, so
  it names no user. `InstallDate` is read and `InstallTime` is not. A `Source OS` subkey whose date could not
  be read makes the anchor unmeasured, since it could hold the earliest date. The journal date is kept only
  from 2000 to 2100, and one after the scan's own date is `read_failed`. FiveM's anchors are Legacy's
  program folder and `FiveM.app`, and Enhanced's program folder; Enhanced's `FiveM.app` is not asked about,
  since the install measured had none. An edition that is not installed is `source_absent`. The observation
  fields keep ADR 0053's precision of a second, as every `fivem_dir` time does; only the anchors are dates.
- **The statement.** It carries no summary sentence, so "none of these" never appears; each record has its
  line. It is not built unless the bundle holds FiveM's selectors on all three records. A record that is
  `source_empty`, `source_absent` or `not_on_this_os` takes the "holds nothing as old as T" form; one that is
  `service_disabled` takes the "switched off" form. The selectors are named by id in the core
  (`view::FIVEM_SELECTORS`), bound to the rules tree by a test, and the report records which selectors the
  bundle held (`Report.timeline_selectors`).
- **Texts.** A reference is a Microsoft Learn page or a document in this repository; `documented: true`
  needs at least one Microsoft Learn reference. A text is shown once per source, under its last row. The
  CLI reads the section's and the statement's fixed words from the desktop's locale files, so each exists
  once.

Not measured by this change: `FilesystemSource::times` on a drive root and `$Recycle.Bin` under a limited
token, `journal_created_on` on a PC, and the whole section on a PC. The points under "What is unverified"
stay open.

## Checked on a Windows 11 PC (2026-10-01)

The CLI built from #123's head (`89c2236`) ran on the same Windows 11 PC (build 26220), `scan --mode ss`, in
English and Thai, once elevated and once with the account's limited token (a scheduled task run with
`/RL LIMITED`). The binary, the task and the output were deleted from the PC afterwards.

- **Elevated.** Every anchor in decision 5 was read. The change journal's creation date and the earliest
  date Windows Setup kept fell one day apart, which agrees with the probe's reading of the journal
  identifier as a time; it is still one PC. The drive root and `$Recycle.Bin` were older than both, and
  `InstallDate` was the last feature upgrade, as measured on 2026-09-30. The four logs the bundle reads came
  first, each with its size against its maximum; the other 412 folded into one line.
- **Limited token.** The journal anchor and the rows of every source that needs administrator rights
  (the four logs, Prefetch, BAM) read "not read without administrator rights — not known", never as
  empty. The anchors that need no rights (Setup's dates, the drive root, `$Recycle.Bin`, FiveM's folders)
  were read as in the elevated run.
- **The cross-source statement did not appear**, in either run: Prefetch and BAM hold entries under
  FiveM's names on this PC, which is the ordinary case decision 7 is built for.
- **Thai** rendered correctly in the console.
- **Open.** The PCA row read "part of this was read and part of it was not" in both runs, the same file the
  probe could not take a time from. Whether that is this build's PCA format or this PC's file is not known.
