# ADR 0028 — Corroborating facts about a log, computed in the collector

- Status: proposed
- Date: 2026-09-13

## Context

ADR 0024 landed the `evtx` collector with no rule, and named the reason: no fixture in this repository
carries event 1102 or 104. There is a second reason, and it is the larger one — **the rule that was
imagined for those events should not be written in the form it was imagined in.**

"Event 1102 is present, therefore the Security log was cleared" is not defensible, and the evidence
against it is not close:

- Ordinary gaming "optimiser" and "debloat" scripts clear **every channel on the machine in one
  click** — `for /f %%G in ('wevtutil.exe el') do wevtutil.exe cl "%%G" /f` walks roughly a thousand
  channels — and several of the same scripts also wipe `C:\Windows\Prefetch` and set
  `EnablePrefetcher`. A player who ran one months ago and has forgotten it presents with a cleared
  Security log, a 1102, a burst of 104s and an empty Prefetch folder: the complete textbook
  anti-forensics composite, produced by no wrongdoing at all.
- All three of SigmaHQ's log-clearing rules sit on **SigmaHQ's own** false-positive suppression list
  for clean Windows baseline images.
- Elastic rates its equivalent rule 21 out of 100. Splunk's known-false-positives note is "It is
  possible that these logs may be legitimately cleared by Administrators."
- A log that is empty, or whose oldest surviving record is recent, is explained equally well by
  rotation at the size cap, by the channel never having been enabled, and by clearing.

The design consequence **inverts the usual detection instinct**: when several tamper-class
observations co-occur in this population, that *raises* the probability of the benign explanation,
because one script click produces all of them at once. The tool must never present the co-occurrence
as mutual corroboration.

So a responsible rule has to be able to match on **the log's own state**, not on one record in it.
`rongroi_core::engine::matches` compares field values for equality and reads `match` as a conjunction;
it has no join across observations, and ADR 0024 and the rule-engine research both conclude it should
not gain one — a join is where the cost stops being linear and where the report stops being auditable
line by line. **The collector computes the facts; the rule matches them flatly.** That is the trade
Hayabusa makes at the rule level, and the opposite of osquery's, which admits arbitrary joins and then
needs a watchdog to survive them.

## Decision

Seven fields, all scalars, all reachable by exact equality or by a comparison operator a later ADR
may add. Nothing here is a structure, a list or a nested object, because a rule cannot reach one.

### On each log's account — the observation that carries `entries`

| Field | Computed from | What it would mean | What innocent condition produces the same value |
|---|---|---|---|
| `oldest_record_time` | the `written` of the surviving record with the earliest time, ties broken by the lower record id | how far back this log still sees | **A recent value is the ordinary case.** Rotation at the size cap (overwrite-as-needed is the default and the Security log's default cap is 20 MB), a channel enabled recently, an in-place Windows upgrade, a restore, an OEM factory image, or the file having been copied. It is also what `wevtutil sl /ms:1048576` leaves — a channel shrunk to its floor self-truncates and writes **no** 1102 and no 104 at all |
| `oldest_record_id` | the `record_id` of that same record | which record number the surviving window starts at | A log exported with `wevtutil epl` or Event Viewer's "Save As" is **renumbered from 1** (Fox-IT), so a low value here is what "the player exported the log to send it to you" looks like. A newly created channel also starts at 1 |
| `newest_record_time` | the `written` of the surviving record with the latest time | when this log last recorded anything | A quiet channel, a channel that was disabled, a machine that has been off, or a log copied from another machine. On the running machine the live log's tail is being written while it is read |
| `newest_record_id` | the `record_id` of that same record | the highest record number that survives | Same as above; the number is Windows' own counter and means nothing on its own |
| `size_bytes` | the length of the bytes the host handed back | how large the file was when it was read | Every log has a size. A small file is a quiet channel, a channel capped small, a channel created recently, or one that has rotated — it is one half of the "at the cap, so rotation explains the short window" reading, and **this tool cannot read the other half**, `maxSize`, from the `.evtx` bytes |

A log that holds no record has no oldest and no newest, so those four fields are **absent** there
rather than zero or null — `oldest_record_id: 0` would be a record that does not exist, and a rule
could match it. That is the same discipline ADR 0024 set for a record with no `Channel` element.

### On the folder's account — the observation that carries `logs`

| Field | Computed from | What it would mean | What innocent condition produces the same value |
|---|---|---|---|
| `logs_without_records` | how many of the logs that were **read** parsed to zero records | how much of this machine's Event Log holds nothing | **This is the field that points at the benign explanation.** A stock Windows 11 install declares on the order of a thousand channels and most have never recorded anything, so a high count is the ordinary state; and a one-click PC optimiser clearing every channel produces exactly the same shape. A high value here is evidence **for** the optimiser explanation, never corroboration of a clearing |
| `channels` | how many distinct channel names the surviving records name, across every log that was read | how many channels actually hold content | A machine with little installed software, a fresh install, a scan that read few logs. It is deliberately **not** `examined - logs_without_records`: one file can hold records of several channels and two files can hold records of one, and the difference between the two numbers is the "a log is not the channel it is named after" signal ADR 0024 already reports per observation |

A log that could not be read is **not** counted in `logs_without_records`. It held nothing that was
seen, which is not the same as holding nothing, and counting it would turn an unread log into evidence
that a machine's logs are empty — the inversion ADR 0024 refuses everywhere else.

### What the fields are not

None of them is a verdict and none is named as one. There is no `suspicious`, no `tampered`, no
`likely_cleared`, no `anomaly`, no score and no boolean that folds several facts into one judgement —
a field name that carries a conclusion is the same violation as a score in a different place
(ADR 0002, AGENTS.md hard rule 3). Each field is a measurement with its innocent explanation written
down beside it in this table, and a field whose innocent explanation could not be named was not added;
the next section is the list of those.

### No record payload, still

Nothing here reaches past `rongroi_parsers::evtx::EvtxRecord`, which carries a record id, a time, an
event id, a channel, a provider and a level. `BackupPath` — the 104 field that says an operator used
"Save and Clear", and one of the few genuinely informative fields in the published research — lives in
the record payload, which the parser drops, and it stays dropped (ADR 0018). The channel names
gathered to count `channels` are kept in a `BTreeSet` inside the collector and never reach an
observation; only the count does.

## Candidates rejected

| Candidate | Why not |
|---|---|
| **Whether record ids are contiguous, or the size of the largest gap** | The research is explicit that this must not ship. A normal export renumbers records from 1 and desynchronises the header ids from the record ids (Fox-IT, 2019), so "a gap in the record ids" cannot be told apart from "the player exported the log to send it to you". Whether a *clear* resets numbering could not be settled from a primary source at all. An indicator whose innocent explanation is indistinguishable from its accusing one is an indicator that will produce a false accusation. The two endpoints are reported; **the derived discontinuity is not**, and a rule must not compute one from them |
| **Whether the records span less time than the log's capacity would suggest** | Not computable from these bytes. The capacity is `maxSize`, which lives in the registry and in `wevtutil gl`, not in the `.evtx` file; this collector reads files. `size_bytes` is the half that is available, and it is reported as a plain length rather than dressed up as a ratio to a cap this program never read |
| **Whether a `1100` precedes a `1102`** | Microsoft, verbatim: 1100 "generates every time Windows Event Log service has shut down. It also generates during normal system shutdown." A gaming PC produces hundreds. "A 1100 precedes the 1102" is therefore true on essentially every machine that has ever been restarted before a log was cleared, so as a field it would read as corroboration while carrying no information. The refined form the research does allow — a 1100 with no following 4608 *while the machine demonstrably kept running* — needs the Security channel, which may be unreadable, and needs "the machine kept running", which is not in these bytes. The raw fact is already in the report either way: 1100 and 1102 each get their own counted group with a first and last time |
| **A `1102_present` or `log_cleared` boolean** | A conclusion with a field name on it. The event is already reported as a group with its channel, provider, event id and count; deciding what that means is a rule's job (ADR 0002) |
| **`empty: true` per log** | `entries: 0` is already an exact-equality match. A second spelling of one idea (CONVENTIONS.md §1) |
| **The list of channel names on the folder observation** | A full list of channels is a rough inventory of the installed software on the PC, which ADR 0024 already declined to add to and ADR 0014 declined for processes. The count answers the question the shape needs |
| **The `Is dirty` / `Is full` file-header flags** | Genuinely informative in principle, and not reachable: the parser returns records and rejections, and the `evtx` crate does not surface the file header's flags through the shape `rongroi_parsers::evtx` exposes. Widening the parser for it is its own pull request. The research also warns that **every** log on a running machine is dirty, so the field would be true nearly always |
| **`Archive-<LogName>-….evtx` files and events 105 / 1105** | The cleanest discriminator in the research for "rotated to archive", and the archive files are `.evtx` files in the same folder, so they are already read and already accounted for by name. Adding a field that classifies a file by its name pattern is a judgement about what a name means, which belongs in a rule matching `log` |
| **The effective audit policy (`auditpol`)** | A different source entirely — not a file in this folder, and this program runs no child processes (AGENTS.md). It belongs to a posture collector if it is ever read at all |

## Alternatives weighed

| Alternative | Why not |
|---|---|
| Give the engine a join across observations, and let a rule say "1102 exists AND the oldest record is later than it" | The feature this research ranks as the most dangerous on the list. It is where matching cost stops being linear and where a report stops being readable line by line. The facts are computed in Rust instead, where a test and a fixture can contradict them |
| Put the corroboration in the rule's `description` and leave the fields out | Prose a reviewer reads is not a fact a rule can match, and the rule would still fire on the one record |
| Emit one observation per record so a rule can see the sequence | ADR 0024 refused this and the reasons have not changed: tens of thousands of observations per log |
| Put the oldest and newest record on each **event group** rather than on the log | They already are, as `first_seen` and `last_seen`. The log-wide window is a different fact and needs a field of its own; reusing those two names on the account would make one rule match two kinds of observation, which is the discipline ADR 0024 set |
| Name the new fields `first_seen` / `last_seen` on the account too | Same objection. Each kind of observation is told apart by a field only it carries, and a rule written for one must not match another |
| Report `oldest_record_time` only when the log holds more than N records | A threshold with no measurement behind it (ADR 0021) |

## What is unverified

**The `.evtx` bytes alone cannot settle what happened to a log, and no field added here changes
that.** This section is the honest limit of the whole pull request.

- **Cleared, rotated, never-enabled and never-happened are not separable from these bytes.** The four
  hypotheses are told apart by `wevtutil gl` (`enabled`, `maxSize`, `retention`, `autoBackup`), by
  `auditpol`, and by the archive files — three sources this collector does not read and one it reads
  only as more `.evtx` files. Every field added here narrows nothing on its own; together they let a
  **person** see the ordinary explanation, which is the whole of the claim being made.
- **Superseded in part by ADR 0042**, which reads each channel's maximum size and file from the Event
  Log service. The paragraph below is left as written: no rule uses the size, and the conclusion that the
  bytes alone cannot separate cleared, rotated and never-enabled still stands.
- **`maxSize` is not read, so the single most informative corroborator in the research is absent.** A
  channel shrunk to its 1 MB floor truncates itself by rotation and leaves no 1102 and no 104 at all —
  and this program cannot see that a channel was shrunk.
- **Whether clearing a channel resets `EventRecordID` could not be established from a primary
  source.** Microsoft's own 1102 sample shows record 1087729 and Eric Zimmerman's shows 494, neither
  of which is 1, while a freshly created backing file would naturally start at 1. The two record-id
  fields are therefore reported as facts and **no inference from them is endorsed**.
- **No number here has been measured on a real machine.** ADR 0024's "What is unverified" applies
  unchanged: how many `.evtx` files a real `winevt\Logs` holds, how many of them are empty, and how
  many channels a real machine's records name are all unknown to this repository. The one vendored
  sample makes `logs_without_records: 0` and `channels: 1` on every fixture that reads it, which
  proves the arithmetic and nothing about the population.
- **The empty-log case is a file holding only its header, not a log Windows cleared.** The test builds
  it from the good sample's first 4096 bytes. A real cleared channel's file is written by Windows and
  may differ in its header; what is proven is that a valid header with no records yields an account
  with no oldest and no newest, which is the branch the code has.
- **The false-positive research is read, not reproduced.** No optimiser script was run and no machine
  in this repository has been through one. The claim that a high `logs_without_records` is the
  optimiser shape rests on the scripts' published source, not on a measurement here.
- **No rule reads any of this yet**, for the reason ADR 0024 gave and this ADR strengthens: the
  fixture that would make a 1102 rule's positive case does not exist, and now the rule it would need
  to be is larger than one match on one record.

## Consequences

- `Collector::fields` for `evtx` grows from 18 names to 25. `cargo xtask check-rules` will accept a
  rule naming any of them, and `rules/AGENTS.md` gains the instruction that co-occurring tamper
  signals are not corroboration.
- `crates/rongroi-collectors/tests/snapshots/report_snapshot__evtx_logs_present_self_view.snap` moves:
  every log account gains five fields and the folder account gains two. The SS-mode snapshot does not
  move, because SS mode counts unmatched observations and lists none of them (ADR 0014).
- `fixtures/hosts/baseline-elevated-win11` emits the new fields — one log account with
  `oldest_record_time` 2018-07-09, `oldest_record_id` 1, `newest_record_id` 17, `size_bytes` 69632,
  and a folder account with `channels: 1` and `logs_without_records: 0`. No rule reads this collector,
  so `cargo xtask check-baseline` is unaffected; the baseline stays quiet.
- No new fixture host and **nothing added to `fixtures/evtx/`**, which is the fuzz seed corpus and
  everything in it must parse (ADR 0021). The empty-log and mostly-empty-folder cases are built in the
  test from the good sample's bytes and written to a fixture host in the temporary directory, as the
  damaged-chunk case already is.
- No dependency, no manifest change, and the 30-second budget and the failure reporting are untouched.
