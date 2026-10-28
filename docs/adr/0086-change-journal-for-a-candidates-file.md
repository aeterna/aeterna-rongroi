# ADR 0086 — The change journal for a candidate's file

- Status: accepted — the owner decided the seven questions in "Owner decisions" on 2026-10-27, each as
  recommended; the owner passed section 6's text at G1 on 2026-10-28. Built: J1 to J3 and J5 ("As built"
  sections); J4 is measured ("Measured: J4")
- Date: 2026-10-27
- Related: ADR 0021 (no identifier that names one file across two reports), ADR 0044 (gaps), ADR 0047 (the
  change journal, and "The privacy problem"), ADR 0052 (full scan), ADR 0061 (trace ages), ADR 0062 (the
  session), ADR 0073 (a saved report), ADR 0076 (lab replay), ADR 0078 (programs recorded near a game
  session, sections 4, 5, 8 and 9), ADR 0079 (the file a recorded program ran from, section 5 and
  amendment 7), ADR 0080 (UserAssist feeds `recorded_files`), ADR 0084 (rule 9 applied)
- Amends, if accepted: ADR 0047 Question 3 (a name in a record may be compared, inside the parser, with a
  name the caller passes; it is never kept), ADR 0078 sections 5 and 9 (which windows I5 covers), ADR 0079
  section 5 ("I5 is deferred" ends) and amendment 7 (`recorded_files` reads the journal once)

## Context

ADR 0078 section 5 defines identity fact **I5**: "the change journal holds a rename or deletion of it inside
a window (ADR 0047)". ADR 0079 section 5 deferred it: I5 stays "not known" until an ADR decides whether the
`usn` collector may match a file name against a path it was given, without reporting names. This is that
ADR.

What the code holds today, read on `dev` at `508ab46`:

- **The `usn` collector counts and never names.** It reads the system volume's journal to its end, under a
  30-second budget (`usn::BUDGET`), and keeps of each record only its version, its parent folder's
  reference, its time and its reason flags. It reports counts per watched folder, and the journal's own
  oldest and newest record, maximum size and trimmed state. `rongroi_parsers::usn` never reads a file
  name, and no USN, journal identifier or file reference number reaches an observation (ADR 0021). It runs
  in a standard scan and needs administrator rights (ADR 0047, Question 1).
- **The journal names its records' parent folder by reference, not by path.** A version 3 record carries
  the parent's 128-bit identifier and a version 2 record its 64-bit index. `FilesystemSource` already has
  `file_id(path)`, which returns both and the volume serial, so a folder's identifier can be compared with
  a record's without a path ever being read from the journal.
- **`recorded_files` holds the paths I5 is about.** It is the full-tier collector of ADR 0079 amendment 7
  and ADR 0080: one observation per distinct drive-rooted path that BAM, PCA, the process list or
  UserAssist recorded, with `identity_read` and the identity fields. The game-windows view joins its
  observations to candidates by path.
- **The view runs after every collector.** Sessions and windows are computed in `rongroi-core`'s
  `view::game_windows`, from the finished report. No collector knows a window, and ADR 0062 keeps one
  definition of a session.
- **I5 in the view today.** `GameCandidate.i5` is always `IdentityNotKnownReason::Deferred` ("not known:
  this version does not read it yet"). `identity_rank` and `has_identity_fact` leave it out, so it neither
  orders a candidate nor names one in SS mode (ADR 0078, "As built: P6a" item 4).

**How far back the journal reaches.** The journal keeps a size, not a time. On the one PC ADR 0047 measured
(twice, fifteen days apart), it held about 39 minutes of records. ADR 0078's windows are 30 minutes before
a session, the session, 30 minutes after it, and from its end to the scan. On a PC like that one, the
journal would reach the "before the scan" window when the scan follows the session closely, and would
rarely reach the "before" window. This ADR therefore designs I5 to say "not known" whenever the journal
does not reach a window, and never "no". How often I5 can be answered on other PCs is not measured.

## Decision

### 1. The match runs in `recorded_files`, once, in a full scan

`recorded_files` reads the system volume's journal once, through the existing
`UsnJournalSource::read_usn_journal`, and matches its records against the paths it already holds. It is the
only collector that both holds those paths and runs only in a full scan (ADR 0052): a collector cannot tell
a full scan from a standard one (ADR 0079 amendment 7), so the `usn` collector, which runs in every scan,
cannot be the one to do it.

The `usn` collector is unchanged: counts per watched folder, no name, the same fields and rules. A standard
scan reads no name from the journal, as today.

The journal is read before any file's bytes, so this program's own file reads, which move a file's
last-access time on some PCs (ADR 0079, "Measured: the stream read"), are not among the records read.
Whether such a time change writes a journal record at all is not verified; it would not be a rename or a
deletion in any case.

### 2. What is compared, and where

For each path on the system volume, before the read, the collector asks the host for:

- the **parent folder's** `FileId` (`file_id` of the folder holding the file), and
- the **file's own** `FileId` when the file exists (when it does not, I1 already says so).

A path on another volume, or whose folder's volume serial differs from the system volume's root (a
junction, ADR 0047's `other_volume`), is not matched and says so (section 3). A folder that does not exist
or cannot be identified is not matched and says so.

`rongroi_parsers::usn` gains one function that takes a buffer and the set of targets — for each, an index,
the two identifiers, and the file name as UTF-16 — and returns, for each record that matches a target,
only **the target's index, which kind of change, and the record's time**. A record matches a target when:

- its parent is the target's folder **and** its name equals the target's name, ignoring ASCII case as the
  candidate join compares paths (ADR 0078 section 4); or
- its own file reference is the target's own file identifier (a rename of a file that still exists, under
  whatever name it had then).

Only records whose reasons include `USN_REASON_FILE_DELETE`, `USN_REASON_RENAME_OLD_NAME` or
`USN_REASON_RENAME_NEW_NAME` are compared. They are reported as three kinds: **deleted**, **renamed away
from this name** (old name), **renamed to this name** (new name). A record that matches by both rules is
reported once.

**The name in a record is read only to be compared.** The parser borrows the name's bytes from the buffer,
compares them with the targets' names, and returns no type that holds a name, a USN or a file reference.
This amends ADR 0047 Question 3, which said the parser never reads a name. The `usn` collector's own call
(`parse_buffer`) is unchanged and still skips names.

### 3. What `recorded_files` emits for each path

| Field | Kind | Meaning |
|---|---|---|
| `journal_match` | text | `matched` (the path was a target), `other_volume` (not on the system volume, or behind a junction to another), `folder_unknown` (its folder does not exist or could not be identified); absent when the path is not drive-rooted |
| `journal_deleted` | `TimestampList` | times of matching deletion records, newest first, capped (D5) |
| `journal_renamed_from` | `TimestampList` | times of matching old-name rename records, as above |
| `journal_renamed_to` | `TimestampList` | times of matching new-name rename records, as above |
| `journal_more` | bool | a list was cut at the cap |
| `journal_from` | timestamp | the oldest record time of this read, the same on every observation of the run |

The three lists are present, possibly empty, only when `journal_match` is `matched` and the read ended
`Complete`. They are declared `off_timeline`, like Prefetch's `run_times` (ADR 0078 section 6), and the bundle
loader already refuses a `match` on a `TimestampList` field, so no rule can read them.

Nothing else from the journal is emitted: no name, no USN, no file reference, no journal identifier, no
record of a path that is not already one of `recorded_files`' paths.

**Gaps.** When the journal could not be read, the journal fields are a run-wide gap with the reason the
`usn` collector would give (`not_admin`, `access_denied`, `source_absent`, `read_failed`), and `partial` when
the journal changed during the read or a record was damaged, or `budget_spent` when the budget ran out.
These gaps cover the journal fields only; the identity fields and `identity_read` are unaffected, so an
unreadable journal never hides I1 to I4.

### 4. Budget

The journal read has its own budget, `usn::BUDGET` (30 seconds), checked between buffers as the `usn`
collector checks it, beside `recorded_files`' 90 seconds for files. A full scan may therefore take up to
30 seconds longer (D3). ADR 0047 measured about one second for a 32 MiB journal on a runner; a larger journal
on a busy PC was not measured.

### 5. In the view (amends ADR 0078 sections 5 and 9)

I5 is computed for **the latest session's four windows** (before, during, after, before the scan) (D4).
An earlier session's windows are older than the latest session's, and the journal reaching them is less
likely still; the fact's text says "near the latest session".

| I5 | When |
|---|---|
| **true** | a time in `journal_deleted`, `journal_renamed_from` or `journal_renamed_to` falls inside one of those windows |
| **false** | `journal_match` is `matched`, the journal fields carry no gap, no time falls in a window, and `journal_from` is at or before the start of the earliest of those windows that is known |
| **not known** | otherwise, with the first reason that applies, below |

| Reason | Key | New? |
|---|---|---|
| a standard scan | `nk.recorded_files_not_run` | no |
| the candidate has no path | `nk.no_path` | no |
| no `recorded_files` observation for the path | `nk.no_observation_for_path` | no |
| the journal fields carry a gap | `nk.journal_not_read` | yes |
| `journal_match` is `other_volume` | `nk.journal_other_drive` | yes |
| `journal_match` is `folder_unknown` | `nk.journal_folder_unknown` | yes |
| `journal_from` is later than a window's start | `nk.before_trace_age` with the source `usn` ("NTFS change journal") | no |
| the latest session's end is not recorded, so the during and after windows are not known | `nk.session_end_not_recorded` | no |

A time the journal recorded outside every window makes I5 neither true nor anything else: it is not shown,
because a candidate's facts are about the windows.

**Ordering and SS mode (D6).** `identity_rank` counts I5 and `has_identity_fact` includes it, as ADR 0078
sections 5 and 9 always said of I1 to I5. A file that is gone and whose deletion the journal holds inside a
window therefore counts two facts: I1 says it is gone now, I5 says when it went. The heading's words stay:
the order counts facts and is not a judgement (hard rule 9 is not touched: nothing is folded or vouched
for).

**File details.** Under a candidate's file details (ADR 0078, P6b decisions), one line per non-empty kind
lists its times, and `journal_more` adds "+ more". Self mode shows every candidate's; SS mode shows them for
the candidates it names, as every other file detail (ADR 0079 section 6). A saved record holds what the SS
screen showed (ADR 0073).

### 6. Text (drafts for the owner's G1; nothing here is approved)

Keys under `game.` in `apps/desktop/src/locales/{th,en}/report.json`:

| key | ไทย | English |
|---|---|---|
| `fact.i5` | change journal บันทึกว่าไฟล์นี้ถูกลบหรือเปลี่ยนชื่อใกล้ช่วงเล่นครั้งล่าสุด | the change journal recorded it being deleted or renamed near the latest session |
| `cause.i5` | การอัปเดตโปรแกรม ถังขยะ (Recycle Bin) โปรแกรมป้องกันไวรัสกักกันไฟล์ | updates, the Recycle Bin, antivirus quarantine |
| `nk.journal_not_read` | ไม่รู้: อ่าน change journal ไม่ได้ | not known: the change journal could not be read |
| `nk.journal_other_drive` | ไม่รู้: ไฟล์อยู่บนไดรฟ์อื่น ซึ่งโปรแกรมนี้ไม่อ่าน change journal ของไดรฟ์นั้น | not known: the file is on another drive, whose change journal this program does not read |
| `nk.journal_folder_unknown` | ไม่รู้: ระบุโฟลเดอร์ของไฟล์นี้ไม่ได้ | not known: the file's folder could not be identified |
| `file.journal.deleted` | ถูกลบเมื่อ: {{times}} | Deleted at: {{times}} |
| `file.journal.renamed_from` | ถูกเปลี่ยนชื่อจากชื่อนี้เมื่อ: {{times}} | Renamed away from this name at: {{times}} |
| `file.journal.renamed_to` | ถูกเปลี่ยนชื่อเป็นชื่อนี้เมื่อ: {{times}} | Renamed to this name at: {{times}} |

**Consent, full-scan item** (CLI `full_reads` third item and the desktop's full-scan list, word for word,
as P6 decision 5 keeps them), one sentence added:

- ไทย: และอ่าน change journal ของไดรฟ์ Windows เพื่อดูว่าไฟล์เหล่านั้นเคยถูกลบหรือเปลี่ยนชื่อเมื่อไร
  ชื่อไฟล์ใน journal ถูกเทียบบนเครื่องนี้เท่านั้นและไม่ถูกเก็บไว้
- English: It also reads the Windows drive's change journal, to find when any of those files was deleted or
  renamed. File names in the journal are compared on this PC and never kept.

**Consent, SS paragraph** (P6 decisions): the list of facts that name a program gains "or the change journal
recorded it being deleted or renamed near the session" / "หรือ change journal บันทึกว่าถูกลบหรือเปลี่ยนชื่อใกล้ช่วงเล่น".

**`PRIVACY.md`:**

- The change-journal paragraph's "It reads no file name" becomes true of the standard scan only, with a
  pointer to the full-scan list.
- The full-scan list's recorded-files item gains: the Windows drive's change journal is read once more, and
  each record in the folder of one of those files is compared, by name, with that file's name, or by the
  file's own number with that file; for a match, only whether it was a deletion or a rename and when are
  kept. No other name in the journal is kept, and no journal or file number is reported. A file on another
  drive is not looked for.
- The SS table's game-windows row names I5 among the facts that name a program.

## Tests

Each change is tested before it merges, in code, because a delegated patch cannot carry binary fixtures
(ADR 0079 "As built: P3" item 10):

- **Parser:** version 2 and version 3 records built in code; a match by parent and name, by ASCII case only;
  a match by the file's own reference under another name; a record in the right folder with another name
  gives nothing; a record with the right name in another folder gives nothing; a record with neither
  deletion nor rename reasons gives nothing; a record matching both rules is returned once; a damaged record
  keeps the matches before it. The returned type holds an index, a kind and a time only, and a test
  asserts that the match output of a buffer full of names serialises with no name in it. The existing fuzz
  target (`fuzz_usn`) gains the new function.
- **The `usn` collector:** its existing test that no observation holds a name stays, and its output is
  compared field for field with today's for the same fixture.
- **Fixture host:** a `name:` on a `usn_journal` record group, and a file id for a fixture file, so that
  `recorded_files` can be tested end to end.
- **`recorded_files`:** `matched` with each kind; `other_volume` for another drive and for a junction;
  `folder_unknown`; the cap and `journal_more`; every journal gap reason; the journal read stops at its own
  budget without touching the file budget; identity fields unchanged when the journal is unreadable.
- **The view:** I5 true for a time in each of the four windows; false only when `journal_from` reaches the
  earliest known window; each not-known reason of section 5, in its order; a time outside every window
  shows nothing; I5 counts in `identity_rank`; a candidate whose only true fact is I5 is named in SS mode;
  a candidate SS mode does not name carries no journal detail into SS mode or a saved record.
- **Locales:** `cargo xtask check-locales` with the new keys in both languages.
- **Lab replay (ADR 0078 step P7):** the existing scenario "a renamed executable run before the game and
  deleted after" asserts I5 true when the journal reaches the window, and "not known" with the
  trace-age reason when the scenario waits until it does not.

## Order of work

The owner has decided that **0.13.0 ships this ADR only**. No step below starts before 0.13.0 is released.
Each step is one pull request against `dev`. Product code comes from engineer runs under the org's
delegated-delivery rules; ADRs and documentation are written by the orchestrator.

| Step | Change | Depends on |
|---|---|---|
| J0 | this ADR, proposed; then accepted with the owner's decisions | — |
| J1 | the parser's match function, its tests and the fuzz target | J0 accepted, after 0.13.0 |
| J2 | fixture-host names and file ids; `recorded_files` reads the journal, emits section 3's fields and gaps | J1 |
| J3 | the view's I5, ordering and SS naming; locale keys; consent text; `PRIVACY.md`; `docs/architecture.md` | J2, the owner's G1 on section 6's text |
| J4 | a measurement on a Windows 11 PC: an evening's journal span next to the latest session's windows, and a test file renamed and deleted before the scan, read back as I5 | J2; before J3 merges |
| J5 | ADR 0078 step P7's scenario asserts I5 | J3, P7 |

Consent and `PRIVACY.md` change in J3, the same pull request that first shows I5, so no build shows it
before the consent screen says so (ADR 0078 section 9).

## Owner decisions

1. **D1, where the match runs.**
   - (a) In `recorded_files`, one more journal read in a full scan (section 1). **Recommended**: it holds
     the paths and runs only in a full scan; the `usn` collector and the standard scan stay as they are.
   - (b) A new full-tier collector that gathers the same paths again and reads the journal. A fourth read of
     BAM, PCA, the process list and UserAssist, and a second join key for the view.
   - (c) The `usn` collector, given paths. It runs in every scan, so a standard scan would start reading
     names, which the full-scan consent exists to prevent.
2. **D2, how names are handled.**
   - (a) Compared inside the parser with the target's name; only index, kind and time leave it (section 2).
     **Recommended.**
   - (b) Match by the file's own reference only, reading no name. Simpler for privacy, but a file that is
     already gone has no reference to ask for, and that is the case I5 matters most for (I1 true).
   - (c) Emit hashes of the names of every deleted or renamed file, for core to match. Rejected: a hash of a
     name can be reversed by trying common names, and it ships a fingerprint of every changed file.
3. **D3, budget.**
   - (a) Its own 30 seconds, `usn::BUDGET` (section 4). **Recommended**: one unreadable file budget cannot
     starve it, and the bound is the one the `usn` collector already has. A full scan grows by up to 30 s.
   - (b) Inside the 90 seconds. No longer scan, but the journal read takes from the file reads.
4. **D4, which windows.**
   - (a) The latest session's four windows (section 5). **Recommended**: the journal measured on one PC held
     39 minutes, so earlier sessions would almost always be "not known", and an all-sessions "no" would
     almost never be possible.
   - (b) Every session's windows, as the time facts are. Answers more only on a PC whose journal reaches far
     back.
5. **D5, how many times per kind.**
   - (a) The newest eight per kind, with `journal_more`. **Recommended**: the same bound as Prefetch's
     `run_times` (ADR 0078 section 6), so one list shape is reused. This is a choice, not a measurement.
   - (b) Uncapped. A file an updater replaces often could fill the report.
   - (c) No times, booleans only. The collector does not know the windows, so a boolean cannot say "inside
     a window"; this would make I5 a fact about the journal's whole span, which ADR 0078 did not define.
6. **D6, ordering and SS mode.**
   - (a) I5 counts in the ordering and names a candidate in SS mode, like I1 to I4 and L1 (section 5).
     **Recommended**: ADR 0078 decisions D1 and D2 said so of I1 to I5. A deletion both I1 and I5 see counts
     twice.
   - (b) A label only, outside `identity_rank` and `has_identity_fact`. No consent change for SS mode, but
     a clean-up made just before the scan would not, alone, name a program to the reviewer.
7. **D7, text.** Approve section 6 at J3's G1, when the code exists to show it (**recommended**), or now as
   drafted.

**Decided (2026-10-27).** The owner chose every recommended option: D1 (a), D2 (a), D3 (a), D4 (a), D5 (a),
D6 (a) and D7 (approve section 6's text at J3's G1). Step J0 is done; J1 starts after 0.13.0.

## Alternatives weighed

| Alternative | Why not |
|---|---|
| Core hands the candidates to a collector after the view | Collectors run before the view and independently; a second collection phase is a new architecture for one fact |
| The collector computes the windows itself | A second session definition beside ADR 0062's, which ADR 0078 refused |
| Read the journal of every volume a candidate is on | A new consent, new administrator reads, and ADR 0047 decided no second volume's journal is read |
| Emit the matching records' names, redacted | The name is the candidate's own and already in the observation; emitting it again adds nothing, and the rule is that no journal name leaves the parser |
| Share one journal read between `usn` and `recorded_files` | Collectors share no state today (ADR 0079, "Alternatives weighed"); the second read is bounded by its budget |
| Treat a journal that does not reach the window as "no" | ADR 0078 section 5: a fact is false only inside the span its source covers |

## What is unverified

- How far back the journal reaches on PCs other than the one ADR 0047 measured (39 minutes, twice). How often
  I5 can be answered at all depends on it; J4 measures one evening.
- Whether BAM, PCA, the process list and UserAssist spell a file's name as the journal does: case outside
  ASCII, 8.3 short names, and path prefixes. A name spelled differently is not matched, which can make I5
  "no" where the journal holds the change. Not measured.
- Whether moving a file to the Recycle Bin, and antivirus quarantine, appear as old-name rename records in
  the file's own folder. Microsoft documents a move as a rename; it was not measured here.
- Whether a version 2 record's 64-bit parent index matches `file_id`'s `index_64` on a real PC: the `usn`
  collector's module notes that no version 2 record was measured.
- Whether this program's own file reads (last-access times) add journal records, and how many.
- What a second journal read costs on a large journal; ADR 0047 measured about one second for 32 MiB on a
  runner.
- A file with more than one hard link: which name a record carries for it was not checked.

## Consequences

- `rongroi-parsers`: one match function in `usn`, its tests, the fuzz target. `parse_buffer` is unchanged.
- `rongroi-collectors`: `recorded_files` reads the journal under its own budget and emits section 3's
  fields and gaps. `usn` is unchanged.
- `rongroi-host`: the fixture host gains record names and file ids; no new host method.
- `rongroi-core`: I5 computed; three `IdentityNotKnownReason` variants; `identity_rank` and
  `has_identity_fact` include I5; the `Deferred` reason is then used by I3 and I4 only.
- Locale keys, consent text, `PRIVACY.md` and `docs/architecture.md` change in J3.
- ADR 0047's "It reads no file name" holds for the standard scan only; ADR 0079 section 5 is closed.

## As built: J1, J2 (2026-10-28)

**J1** (#243): `rongroi_parsers::usn::match_buffer` walks a buffer as `parse_buffer` does and returns, for each
match, a target index, a kind (`Deleted`, `RenamedFrom`, `RenamedTo`) and the record's time, as section 2 says.
A record with more than one of the three reasons gives one match per kind. Three rules were added at review,
each so that a damaged or hostile buffer cannot make a match:

1. A name whose offset points inside the record's fixed part is damage (`file_name`), so header bytes are never
   compared as a name.
2. An empty name never matches by name.
3. An all-zero file reference on the target is no reference for that record version.

`parse_buffer` is unchanged in what it returns; both share one walk. The fuzz target calls both.

**J2** (fixture #244, collector: this ADR's J2 pull request): `recorded_files` reads the journal once, before
any file's bytes, and emits section 3's six fields. As built, where it differs from or adds to section 3:

1. **`journal_from` is off the timeline too.** Section 3 declared only the three lists so. On the timeline,
   `journal_from` would repeat the oldest record the `usn` collector already puts there, and a full scan with
   no journal would list `recorded_files` among the timeline's unmeasured sources.
2. **`journal_from` is the earliest time of the first buffer that has a timed record**, the oldest record of a
   journal written in time order.
3. **A source gap does not reach the journal fields.** A source BAM, PCA, the process list or UserAssist could
   not read gaps every other field, as before; the six journal fields carry only the journal's own reason.
4. **A damaged record is `partial`**, as section 3 says, not `read_failed` as the `usn` collector gives for
   the same damage: the records before it were compared.
5. **The journal volume is `%SystemRoot%`'s drive**, as the `usn` collector reads it; a path on another letter is
   `other_volume`. A path spelled with `/` is looked up with `\`, and a file at a drive's root is looked for
   under `X:\`.
6. **The journal read's time is given back to the file clock**, so the 30 seconds of the journal and the 90 of
   the files never share time (section 4). The two `file_id` calls per path before the read are counted in
   neither; they read no file.
7. **`budget_spent` has a fifth owner**, `recorded_files`, in the owner list `cargo xtask check-rules` asserts.

A name is compared with ASCII case folding only (section 2), so a recorded 8.3 short name or a name that differs
only in a non-ASCII letter's case is not matched by name; it is matched by the file's own reference when the
file still exists. `matched` then shows empty lists. Not measured how often this happens.

## Measured: J4 (2026-10-28)

One elevated full scan of `dev` at `582c93d` (x64 build), on a Windows 11 PC (build 26220) that is not a gaming PC,
over SSH. Counts only; no path or name is recorded here.

| What | Measured |
|---|---|
| The journal's span at the scan (`journal_from` to the scan time) | 42 minutes 56 seconds |
| `recorded_files` paths | 232 |
| `journal_match: matched` | 172 (155 read, 11 too large, 6 missing); every list empty, `journal_more` false on all |
| `journal_match: folder_unknown` | 55, each recorded by UserAssist alone, its file missing: its folder no longer exists |
| `journal_match: other_volume` | 5, on another drive letter |
| The full scan's time after the consent answer | about 6 seconds, journal read and files together |

What this shows:

1. **The span matches ADR 0047's.** About 40 minutes on both PCs measured. A session that ended more than about
   40 minutes before the scan gives I5 "not known: the NTFS change journal does not reach back that far" for
   every candidate, as section 5 designed; I5 answers for a scan made soon after a session.
2. **`folder_unknown` is common, and it is the folder that is gone, not unreadable**, on this PC: all 55 were old
   UserAssist entries whose files are missing. I1 already says the file is gone; I5 cannot say when.
3. **The test half was not done.** A test program copied, run, renamed and deleted over SSH was recorded by none
   of BAM, PCA, the process list or UserAssist, so it never became a `recorded_files` path and the journal was not
   asked about it. Reading I5 back for a renamed and deleted program needs an interactive run: the lab replay
   (step J5) or the owner's PC. On the lab machine the scenario's program is known only from BAM, whose path is
   withheld until ADR 0087's drive map, so its I5 is "not known: no path" today.

## As built: J3 (2026-10-28; the owner passed G1 the same day, #246)

I5 is computed in `rongroi_core::view::game` for the latest session of each edition, with the windows the time
facts use (before `[start − 30 min, start)`, during `[start, end]`, after `(end, end + 30 min]`, before the scan
`(end, scan]`). Where it differs from or adds to section 5:

1. **The view reads the journal's state from the fields, not from gaps**, because a report carries no per-field
   gaps for the view: no `journal_match` is `journal_not_read`; `matched` with no `journal_deleted` (a read that
   was not whole) is `journal_not_read` too.
2. **A cut list moves the journal's start.** `journal_more` says a list kept its newest eight and dropped older
   times. So when it is set, the start the false check uses is the later of `journal_from` and the oldest time a
   full list kept; a window before that is `before_trace_age`, never false.
3. **False needs every window known.** With a latest session whose end is not recorded, a time in its before window
   still makes I5 true, but I5 is never false: `session_end_not_recorded`. Section 5's "the earliest of those
   windows that is known" is read this way, the stricter reading.
4. **`scan_time_not_recorded`** is a reason section 5 did not list: with no scan time the before-the-scan window is
   not known, as for T4. It comes after `session_end_not_recorded`.
5. **Text.** Section 6's keys, word for word, in both languages, plus `cross_source.source.usn` ("NTFS change
   journal") for the `before_trace_age` source and `game.file.journal.more` ("+ more" / "+ มีอีก"), which section
   6 did not write. The CLI and the desktop show "+ more" after each list that is not empty when `journal_more`
   is set. The consent sentence is word for word in the CLI and the full-scan dialog (present tense); the desktop's
   after-the-scan summary (`consent.full_reads`), which is written in the past tense, says the same in the past
   tense.
6. `PRIVACY.md`'s SS row and full-scan list name the journal's times among a named program's file details.

## As built: J5 (2026-10-28)

Two lab replays (ADR 0076) on the lab machine (Windows 11 build 26300, Arm64) with the x64 build of `dev` at
`d5c4975`:

| Scenario | Expected | Result |
|---|---|---|
| `program-renamed-while-running` (new, full scan) | `renamer.exe`: T1 true; I5 true | 2 ok, 0 failed |
| `renamed-program-run-then-deleted` | `helper.exe`: T1 true; I1 and I5 not known, no path | 3 ok, 0 failed |

What the new replay's report showed, read once by hand beyond what `lab-check` asserts (T1 and I5):

1. **A program renamed while it runs kept its old name and gained its new path.** The process list gave the
   candidate the name it started under, `renamer.exe`, and the path it has now, `…\Downloads\renamed.exe`; the
   file was there, so I1 was false. Why Windows keeps the old name is not established, nor whether other builds
   do the same.
2. **The rename appeared as one time in `journal_renamed_from` and two in `journal_renamed_to`**, all in the window
   before the session. The session's game was still running, so its end is not recorded; I5 was true from the
   before window alone (As built: J3, item 3). Which of section 2's two rules matched each record is not in the
   report: the target's name was the new one, so the new-name records could match by folder and name, and every
   record could match by the file's own number.
3. **BAM recorded the same program as a second `renamer.exe` candidate** with the withheld device path, whose I5
   was "not known: no path", as `helper.exe`'s is. Observed in this one replay; not asserted.

The scenario that was meant to read I5 for a program run and then deleted (section "Tests", lab replay) cannot
until then; it asserts "not known: no path" instead.
