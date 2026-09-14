# ADR 0030 — The words for what was not measured

- Status: accepted
- Date: 2026-09-13

## Context

ADR 0002 fixed three evidence states and ADR 0027 made `unmeasured` carry whether its rule expected
it. What neither settled is the vocabulary of *reasons*, and two holes in it were doing real damage.

### 1. One word made two opposite statements

`source_missing` was documented as "the artifact is not present or not reported on this machine". It
was produced by five different situations across four collectors, and they fall into two groups that
mean opposite things:

- **the place the artifact is kept is not on this PC** — no `%SystemRoot%\Prefetch`, no
  `winevt\Logs`, no BAM key, none of PCA's three files;
- **the place is there and holds nothing** — an emptied Prefetch folder, a BAM key with no record, a
  `winevt\Logs` with no `.evtx` file.

OVAL, whose outcome model this vocabulary has followed since ADR 0002, refuses to call an absence
meaningful until the container is present: its `does not exist` requires that "the underlying
structure is installed on the system". One word for both told a reader the container question had
been asked when it had not.

### 2. Three artifacts read perfectly and lie by omission

This is the larger hole, because **there is no error anywhere**. Each of Prefetch, BAM and PCA has a
state in which the artifact is present, parses cleanly, and is simply not recording:

- **Prefetch** with `EnablePrefetcher` at `0` or `2`. Windows writes no application-launch `.pf`
  file. At `2` — boot only — the folder still holds `NTOSBOOT-B00DFAAD.pf` and layout files, so it is
  not even empty.
- **BAM** beyond seven days, for every machine, always. See "The seven-day scavenge" below.
- **PCA** on any build older than Windows 11 22H2, where the files have never existed; and, even on a
  build that keeps them, PCA records only launches made from File Explorer — which is not how a game
  started by Steam, Epic, Battle.net or a Discord "Play" action is launched.

A rule over any of these got `not_found` — "the collector looked and nothing matched" — displayed
with a retention window that reads as a measurement. It is wrong, and it is wrong in the direction
that costs a player an argument they cannot win.

### 3. A partly-read folder reported as a fully-read one

Verified in the code this change starts from: `prefetch::collect` on a folder where some `.pf` files
were rejected returned `Measured` with `gaps: BTreeMap::new()`. `intact: false` and `rejected` were
on the observation and **no rule-level state carried them**, so the engine produced `NotFound`. The
same held for `pca`'s rejected lines and for `bam`'s rejected values.

### 4. Two reason codes existed with nothing behind them

ADR 0027 established by grep that `not_on_this_os` and `service_disabled` had **no producer anywhere
in the build**, and `check-rules` therefore rejected them in every rule. They were words. Both are
exactly the words the two largest false-positive classes above need.

`os_build` had been in the report header since `scan.rs` was written and no collector read it.

## Decision

### `EvidenceState` still keeps exactly three variants

Nothing here adds a fourth. ADR 0027's reasons stand unchanged: a fourth state breaks the
`types.ts` mirror, every snapshot, the UI switch and `check-rules`' two fixture outcomes, and a
fourth row colour reads as a fourth verdict. Everything below is reasons and wording.

### The twelve reasons, their words, and what ordinarily produces each

The English is R3's recommended wording except where noted; the Thai is beside it in
`crates/rongroi-cli/src/output.rs` and `apps/desktop/src/locales/th/report.json`.

| Reason | English | Thai | Produced by | The ordinary condition, and how common |
|---|---|---|---|---|
| `not_windows` | "not running on Windows" | "ไม่ได้รันบน Windows" | every collector | The scan is not on Windows. Never on a player's PC; universal in this repository's own tests |
| `not_on_this_os` | "this version of Windows does not keep this record" | "Windows รุ่นนี้ไม่ได้เก็บข้อมูลส่วนนี้" | `pca` | The build is older than 22621. **Common** — Windows 10 is still a large share of gaming PCs, and on every one the absence of `appcompat\pca` means nothing |
| `not_admin` | "Windows would not show this without administrator rights" | "ต้องมีสิทธิ์ผู้ดูแลระบบ Windows จึงจะให้อ่าน" | `pca`, `prefetch`, `bam`, `evtx` | An ordinary scan that was not restarted as administrator. **Very common** — which is why it is a scope statement and not a row (ADR 0027) |
| `not_attempted` | "this was not read — the scan stopped before reaching it" | "ไม่ได้อ่านส่วนนี้ เพราะการสแกนหยุดก่อนจะถึง" | `evtx` | A log whose turn came after the 30-second budget was already spent. **Rare** — it needs the budget to run out first |
| `access_denied` | "Windows refused to open this" | "Windows ไม่อนุญาตให้เปิดอ่าน" | `pca`, `prefetch`, `bam`, `evtx`, `posture`, `process`, `fivem_dir` | Denied with the rights already held. Uncommon, and the one denial restarting does not fix |
| `service_disabled` | "the Windows service that writes this record is switched off" | "บริการของ Windows ที่เขียนข้อมูลนี้ถูกปิดอยู่" | `prefetch` | `EnablePrefetcher` is `0` or `2`. **Uncommon** — Windows ships `3`; it takes a performance tweak or an optimiser script to change |
| `source_absent` | "this PC has no such record to read" | "เครื่องนี้ไม่มีข้อมูลส่วนนี้ให้อ่าน" | `pca`, `prefetch`, `bam`, `evtx`, `posture` | The folder or key is not there. For `posture` — a registry value the machine does not report, e.g. Secure Boot on a legacy-BIOS PC — **common**, and all four shipped rules declare it |
| `source_empty` | "the place this is kept is there and holds nothing" | "มีที่เก็บข้อมูลอยู่ แต่ว่างเปล่า" | `pca`, `prefetch`, `bam`, `evtx` | Prefetch: a cleaning tip or optimiser, or eviction at the 1024-file cap — **common on a gaming PC**. BAM: see below. PCA: a clean install that has written nothing — **common**. Event Log: a maintenance script that cleared every log |
| `partial` | "part of this was read and part of it was not" | "อ่านได้บางส่วน ไม่ครบ" | `pca`, `prefetch`, `bam` | A `.pf` from an older Windows, a PCA line with no delimiter, a BAM value too short. **Uncommon but not rare** — an upgraded machine keeps `.pf` files this parser does not decode |
| `budget_spent` | "this program stopped reading before it finished" | "โปรแกรมนี้หยุดอ่านก่อนจะครบ" | `evtx` | The 30-second budget ran out. **Rare**, and it is this program's limit, not the machine's |
| `read_failed` | "this could not be read" | "อ่านข้อมูลนี้ไม่ได้" | every collector that reads a source | I/O failure, a file past the 64 MiB cap (ADR 0019), an unset `%SystemRoot%`. Uncommon |
| `collector_unavailable` | "this build does not read that" | "build นี้ยังไม่ได้อ่านส่วนนี้" | the engine | A rule for a collector this build has none of. Never in a shipped build; it is the ADR 0026 gate |

Three wordings depart from R3:

- **`not_attempted`.** R3's "this was not read — the scan was not given administrator rights" ties
  the reason to elevation, which `not_admin` already says and which no collector produces as
  `not_attempted`. The wording here says what actually happened.
- **`source_empty`.** R3's "the record is there and is empty" contradicts itself — a record that is
  there is not empty. What is there is the *place* the record would be.
- **`service_disabled`, `source_absent`, `partial`, `budget_spent`, `read_failed`,
  `collector_unavailable`, `not_on_this_os`, `not_admin`, `access_denied`** are R3's, and they
  replace the older, terser strings ("needs administrator rights", "not reported on this PC") that
  named the tool's problem rather than the reader's.

Two rules govern all twelve, both borrowed: Microsoft Defender's caveat that an unanswered check "isn't
necessarily flagged because of an issue", and Defender event 3007's register — name the thing that was
not seen, prescribe the remedy where there is one, and never imply anything about the person.

### The seven-day scavenge, and what it means for `source_empty` on `bam`

`BampScavengeUserSettings` deletes every BAM entry older than seven days, at every boot, driven by
`UserSettingsLifetimeMs` (default `0x240C8400` = 604 800 000 ms). This is Microsoft's own code running
on every machine on a schedule, by design.

**The decision: `source_empty` fires on `bam` only when the key holds no record at all, and the
wording is a fact about the place, not about the PC's history.**

The reasoning, and the part that matters for R3's "a state that fires constantly is worse than no
state at all":

- A *nearly* empty BAM key is the normal state of every machine for any question older than a week.
  If this change reported that, the state would fire on the majority of PCs and would be worthless.
  **It does not.** The reason is keyed on `values == 0` — nothing at all under the key — which a
  machine in use does not reach, because the scavenger trims to a seven-day window rather than
  emptying the key.
- A machine that has been off for more than a week reaches `values == 0` on its own at the next boot,
  before anything runs. So it is not rare either, and it is **never** evidence that something was
  removed.
- Because one reason has one wording across four collectors, the wording cannot say "Windows removes
  old entries here". So the wording says only what is true everywhere — "the place this is kept is
  there and holds nothing" — and the BAM-specific half of the story is carried where the rule author
  can say it: in `description`, in `falsepositives`, and by declaring `source_empty` in
  `unmeasured_when`, which is now what keeps it out of an SS reviewer's list.
- `bam` does **not** declare `service_disabled`, deliberately. Nothing this collector reads
  distinguishes "the service is off" from "the scavenger has run", and a reason code that guessed
  between them would put a conclusion in the vocabulary.

The equivalent for Prefetch: absence there is routinely explained by an optimiser the player ran, by a
"delete Prefetch for FPS" tip, or by natural eviction at the 1024-entry cap — which is why
`prefetch-folder-empty` exists as a fixture and why its `PROVENANCE.md` row names those causes.

### What each collector can actually establish, and what it may not

Checked against the collectors rather than taken from the brief:

- **`pca` gets `not_on_this_os`** from `Host::os_build()`, which the report header has carried all
  along. `< 22621` is the whole test. A build the host does not report, or one that is not a number,
  answers `false`: an absent header field is not evidence about the operating system.
- **`prefetch` gets `service_disabled`** from `EnablePrefetcher`, a `REG_DWORD` the existing
  `RegistrySource::read_u32` reads. The answer is the low bit — `0` and `2` both mean no
  application-launch record. A value that is not there or could not be read answers `None` and makes
  no claim.
- **`pca` does not get `service_disabled`, and this is the one the research asked for and could not
  have.** `PcaSvc`'s state is a Service Control Manager read, and `Host` has no service source. Adding
  one is a new host surface with a new live-Windows implementation, which is a decision of its own
  and not this change. So a machine whose owner disabled `PcaSvc` — which privacy.sexy recommends to
  most users — is `source_empty` here, not `service_disabled`. That is true but less informative, and
  it is recorded as unfinished rather than guessed.
- **`bam` does not get `service_disabled` either**, for the reason above.
- **`evtx` gets `budget_spent` and `not_attempted`.** The collector already had a 30-second budget and
  already reported `budget_exhausted` as an observation field; the reason vocabulary now agrees with
  it. The two are split: the log being parsed when the budget ran out **spent** it, and every log
  after it was never opened. Calling the second a failed read names a failure that did not happen.
- **`not_attempted` has a second producer that no fixture can provoke**: a log this program would not
  parse because the operating system gave it no worker thread. It is unreachable from a `FixtureHost`
  and is recorded under "What is unverified".

### A content-level reason gaps only the content fields

`source_empty`, `service_disabled` and `partial` all describe a source the collector **did** read. A
`gaps` entry over every field would say it had not, and would make `files: 0` — the fact the reader
most needs — unanswerable. So each of the four artifact collectors gains a `RECORD_FIELDS` subset:
the fields that describe one recorded program or one log, and not the counts that describe the folder
or the key.

The reasons that describe a source nothing was read from — `not_admin`, `access_denied`,
`read_failed`, `budget_spent` — keep gapping every field, exactly as before.

### SS mode: two exceptions in each direction

ADR 0027's filter stands, with `UnmeasuredReason` answering two questions about itself:

| Evidence | SS | Self |
|---|---|---|
| `found` | listed | listed |
| `not_found`, `posture` strength | listed (ADR 0011) | listed |
| `not_found`, any other strength | counted | listed |
| `unmeasured`, `partial` or `budget_spent` | **listed, declared or not** | listed |
| `unmeasured`, `not_admin` or `not_attempted` | **scope statement** | listed, and the scope statement |
| `unmeasured`, reason in `unmeasured_when` | counted | listed |
| `unmeasured`, reason not in `unmeasured_when` | listed | listed |

`partial` and `budget_spent` are not a rule author's to declare away: both say the artifact was
reachable and that **this program** stopped short of it, which is not something the author could have
anticipated about the machine. `not_attempted` joins `not_admin` as a scope statement for the
symmetric reason — it is one fact about how far the scan got, and N rows saying it would be N
red-looking lines carrying one fact.

`ScopeNotes` therefore gains `not_attempted`. Additive to the view, and `REPORT_SCHEMA_VERSION` stays
at 1 on ADR 0027's argument: `ReportView` is a projection built on demand and never read back.

### `too_large` is not a reason, and stays where it is

R3 asks SS mode to list `too_large` naming this program's limit and never the file's size. That is
already the design one layer down: `SourceError::TooLarge { limit }` carries the limit and cannot
carry the size, because the reader stops one byte past the limit (ADR 0019), and `read_failure` puts
`too_large` on the observation that names the file. It reaches a reader through the `read` field and
its reason is `read_failed`, which SS mode lists unless the rule declared `read_failed`. Adding a
thirteenth reason for it is not in R3's recommended set and is not done here.

### Rejected alternatives

**A `too_large` reason of its own.** It would make the listing rule independent of what a rule
declared. It also duplicates a distinction `read` already carries more finely, and R3's own
recommended set leaves it out.

**Reasons naming the mechanism — `pca_dictionary_frozen`, `prefetch_at_cap`, `bam_pruned_at_boot`,
which R2 §3.1 item 6a suggests.** Each is a conclusion about *why*, and nothing a collector observes
distinguishes it from the innocent causes §3 of the brief enumerates. A reason code is read as a
finding; "the 1024-entry cap evicted it" and "somebody deleted it" produce identical bytes. What the
collector can honestly say is the shape — `files`, `entries`, `rejected`, `intact`,
`logs_without_records` — and those are already fields a rule can match (ADR 0028).

**Keeping `source_missing` as a synonym of `source_absent`.** It would leave the two rule files
untouched. It also leaves the coarsest word in the vocabulary alive in rules and reports, where the
whole point is that it made two opposite statements. The rename is one token in two files and
`check-rules` catches any that is missed.

**A fourth evidence state for "read and empty".** Rejected by ADR 0027 with reasons that have not
changed.

## What is unverified

**No real Windows machine was read.** Every producer here is exercised against a `FixtureHost`. In
particular: that `EnablePrefetcher` is readable without an elevated token on a real machine is
untested — the value is under `HKLM\SYSTEM`, and ADR 0021 already records that whether reading the
Prefetch folder needs elevation "is asserted in prose and never measured". If the registry read is
denied on a real non-elevated scan, `application_launches_recorded` answers `None` and the collector
falls back to the reason it gave before; the failure direction is the safe one, but it is untested.

**`not_attempted`'s second producer is unreachable from any fixture.** The path where the operating
system gives this program no worker thread, or the worker stops without answering, cannot be provoked
by a `FixtureHost`; `std::thread::Builder::spawn` does not fail on demand. It is covered by review and
by the type system, not by a test — the same limit ADR 0027 records for the declared reason lists.

**`PcaSvc` and `SysMain` service states are not read at all**, so `service_disabled` on `pca` and any
SysMain-derived claim on `prefetch` are absent rather than wrong. A collector that wanted them needs a
new source on `Host`.

**The build threshold 22621 is taken from one practitioner's tested observation** (present on
22621.963, absent on 21H2), corroborated by three secondary write-ups, and from no Microsoft page. If
the files actually arrived on some earlier build, `not_on_this_os` would be claimed for a machine that
does keep them — and the report would then say "this version of Windows does not keep this record"
about a machine that does. Nothing in this repository can check it.

**PCA's CP-1252 freeze is not handled and is not claimed to be.** A path with a non-Latin character —
which for a Thai player includes their own `C:\Users\<name>\` — reportedly stops `PcaAppLaunchDic.txt`
gaining new rows while leaving it present, non-empty and parsing cleanly with `intact: true`. That is
the state this whole vocabulary is about and none of the twelve reasons detects it, because the
failure is not a rejected line but a line that was never written. The source is single and
unreplicated; replicating it is the next thing worth doing for a Thai-speaking user base.

**The prevalence column in the table above is judgement from the research, not measurement.** No
distribution of ordinary machines was sampled. The claim that `source_empty` on `bam` does not fire
on most PCs rests on the scavenger trimming rather than emptying, which is reverse-engineering
reported by one source and re-reported by three.

~~The Thai wordings have not been read by a native speaker~~ **(amended 2026-09-14: the project owner
approved the Thai wordings the app shows on screen)**, which ADR 0027 records for the two
strings it added and which is true again for the ten changed here and the two new scope statements.

**Nothing bounds a rule author who declares every reason.** `check-baseline` still fails only on
`Found`; R3 §6.6's proposal to fail it on SS-listed `unmeasured` is not in this change, and neither
are the baseline hosts it would need. A rule that declares `source_absent`, `source_empty` and
`partial` together is invisible to CI, and three of the twelve reasons are now declarable where two
were not.

**`rust (windows)` was not run.** This change is developed on macOS; the Windows job's result for
this commit is not in hand and is not claimed.

## Consequences

- **All 15 report snapshots changed, for two reasons and no others.** Every one gained
  `scope.not_attempted: 0`; the ten carrying posture evidence renamed `source_missing` to
  `source_absent` on the Secure Boot and memory-integrity rows. No evidence appeared or disappeared
  and no hidden count moved — which is the check that the rename of the two rules' `unmeasured_when`
  lines kept `expected: true` where it was.
- `cargo xtask check-rules` prints the same line before and after: `4 rule(s), 8 fixture(s), 2
  language(s) ok`. Two rule files changed one token each, `source_missing` → `source_absent`, because
  `posture` now reports the latter.
- Five fixture hosts are new — `prefetch-folder-empty`, `prefetch-service-disabled`,
  `pca-folder-absent`, `pca-folder-empty`, `evtx-logs-folder-empty` — and `pca-not-present` is now
  described by its build number rather than by a guess about the service. Each has a row in
  `fixtures/hosts/PROVENANCE.md` naming the machine it represents.
- A rule author has three reasons they could not declare before and two more words for what used to
  be one. `check-rules` tells them which collector each belongs to.
- `apps/desktop/src/types.ts`, both locale files and the CLI's reason table carry twelve reasons
  where they carried eight; `check-locales` and the `types.ts` mirror keep the three copies in step.
