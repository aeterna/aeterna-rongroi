# ADR 0024 — The Event Log collector

- Status: proposed
- Date: 2026-09-12

## Context

ADR 0018 wrote the Event Log parser and ended by saying that nothing consumes it: "the collector that
reads `%SystemRoot%\System32\winevt\Logs` … and the rules that read the result are later PRs". This is
that collector, and it is the last of the four parsers in `rongroi-parsers` to reach the product.

It is a different shape from the three collectors before it in three ways, and each one is a decision
this ADR has to make rather than inherit.

**The artifact is enormous.** A `.pf` file holds one program's record and a PCA file holds a few
hundred lines. One `.evtx` file holds tens of thousands of records and a machine has hundreds of files.
One observation per record would put a person's entire event log into a report nobody can read.

**The input is attacker-chosen and the parser is not proven to terminate.** `rongroi_parsers::evtx`
reads a vendored third-party binary-XML decoder over offsets taken from the file. Three defects have
been found in it in the time this repository has carried it, one of which was a parse that **did not
return** — located on 2026-09-12 in `StringCache::populate` and fixed in the commit this branch is
stacked on (`third_party/evtx/PROVENANCE.md`, patch 3). One fixed defect is not a proof of
termination, and ADR 0018's own "What is unverified" says so in those words.

**A scan that does not return is an app that never appears.** Verified in
`apps/desktop/src-tauri/src/main.rs`: the scan runs at step 1, `tauri::Builder` is not touched until
step 2, and `webview_hardening::build_main_window` is called in `.setup()` after that. So a collector
that never returns is not a stalled progress bar — there is no window to stall. The CLI is no better
off: `scan::run` is called before anything is printed.

Put together, these are a denial-of-check. Someone who wants the Event Log unexamined does not have to
defeat a detection; it is enough to make the logs unreadable, oversized or slow. That is a thing to
defend against — which the repository's purpose boundary puts squarely in scope — and **the defence is
not to hide it**. An Event Log that could not be read is evidence a reviewer needs.

## Decision

### No rule ships with it

The third time, for the third reason, and it does not weaken with repetition: ADR 0020 (PCA) and
ADR 0021 (Prefetch) both landed a collector with no rule, and here there is an argument of the
artifact's own. `fixtures/evtx/PROVENANCE.md` records that **no fixture in this repository contains
event 1102 or 104** — the cleared-log events ADR 0018 was written for — because the corpora that carry
them are real red-team capture and an unlicensed collection, both ruled out for vendoring by
`docs/research/06`. `docs/rules-authoring.md` requires a positive and a negative fixture for
`status: test`. A rule cannot be written here today without a fixture that does not exist.

The observations land in the unmatched bucket: listed in Self mode, counted and never listed in SS
mode (ADR 0014). Neither the CLI nor the desktop app changes, because both render that bucket by
collector id.

### The observation shape, and the two rules it has to be able to serve

`rongroi_core::engine::matches` compares field values for exact JSON equality and reads a rule's
`match` block as a conjunction — no regex, no substring, no comparison, **no disjunction**. "Event
1102 or 104" is therefore two rules, and each has to be expressible on its own against one
observation. Four kinds of observation:

**One kind of event in one log**, the aggregate:

```json
{
  "collector": "evtx",
  "fields": {
    "log": "Security.evtx",
    "channel": "Security",
    "provider": "Microsoft-Windows-Eventlog",
    "event_id": 1102,
    "level": 4,
    "count": 1,
    "first_seen": "2026-09-11T18:44:02.7130000Z",
    "last_seen": "2026-09-11T18:44:02.7130000Z"
  }
}
```

The 1102 rule matches `{channel: Security, event_id: 1102}`; the 104 rule matches
`{channel: System, event_id: 104}`, or `{event_id: 104}` if it means every channel. Both are
conjunctions of fields this observation carries, and an observation carrying fields a rule does not
name still matches — `matches` iterates the **rule's** fields, not the observation's. The `count`
comes with the match, so the evidence a person reads says how many times it happened.

`(channel, provider, event_id, level)` is the whole of what `EvtxRecord` carries apart from the record
id and the timestamp, so **nothing a rule could match is lost by counting records into groups**.
`log` is added by the collector: it is the file the records came from, which is not the same thing as
the channel they declare, and a log whose records name another channel is a file that was put there.

A field the record did not carry is **absent, not null**. The vendored sample's damaged trailing
record has no `Channel` element, so it forms a group with no `channel` field — `channel: null` would
be a claim the file does not make, and exact equality against `null` is a question no rule should be
invited to ask.

**What one log held**, one per log that parsed:

```json
{ "collector": "evtx", "fields": { "log": "Security.evtx", "path": "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx", "entries": 17, "rejected": 0, "intact": true } }
```

`intact` is `rejected == 0` as a value of its own — the same field and the same meaning `pca` and
`prefetch` give it, and for the same reason: the question a rule wants is `rejected > 0`, which exact
equality cannot express. A damaged chunk costs its own records and nothing else (ADR 0018), so a log
with one is still read and still reported; `rejected` is the only intactness signal the parser gives.

**What the folder held**, one per run that listed it:

```json
{ "collector": "evtx", "fields": { "logs": 214, "examined": 212, "refused": 2, "budget_exhausted": true, "budget_seconds": 30 } }
```

`budget_exhausted` is the matchable form of "this collection did not finish". `budget_seconds` is
beside it so that a person reading the report does not have to know this program's constants to know
what the bound was. `logs >= examined + refused`: a log listed and gone by the time it was read counts
in neither, because Windows rolls a log over while a scan runs and ADR 0019 made that an answer rather
than a failure.

**One log that yielded nothing**, one per log, and one for the folder when the folder itself could not
be listed:

```json
{ "collector": "evtx", "fields": { "log": "Security.evtx", "path": "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx", "read": "too_large" } }
```

`read` is one of `access_denied`, `too_large`, `failed` (from a `SourceError`, through
`crate::failure::read_failure`), `truncated`, `not_event_log`, `bad_header`, `malformed` (from a
`ParseError`), `budget_exhausted` and `parse_unavailable`. They are separated because they are
different machines to a reviewer: a `Security.evtx` Windows would not hand over is an ordinary
non-elevated scan, a `Security.evtx` past the 64 MiB host limit is a machine whose maximum log size
was raised, and a `Security.evtx` the budget did not reach is a machine where something was slow.

Each kind of observation is told apart by a field only it carries — `count`, `entries`, `logs`,
`read` — which is the discipline `pca` set: a rule written for one never matches another.

### Volume: what is aggregated, and what is not capped

Records are counted; logs are not. Every `.evtx` file in the folder is read and each one is accounted
for. The groups are per `(log, channel, provider, event_id, level)`, which on a real machine is
plausibly a few thousand observations rather than the hundreds of thousands one-per-record would be —
**plausibly**, because it has not been measured on a real machine and nothing in this repository can
measure it.

No cap on the number of logs, and no cap on the number of groups. ADR 0021 refused the same thing for
Prefetch in the same words: a number invented here, with no measurement behind it, would silently drop
part of the artifact, and the honest answer is to read the folder and let the report say what was
there. The wall-clock budget below is **not** an exception to that argument — it answers a failure
mode with no upper bound at all, and it reports every log it costs, by name.

The record id is dropped by aggregation. `rongroi_parsers::evtx` notes that the sequence is meaningful
— Windows assigns the ids in order, so a gap is visible — and a rule that needs gaps in it is a
deliberate widening of this shape, which is the review standard ADR 0014 set for this bucket.

### The wall-clock budget: 30 seconds for the whole collection, on one worker thread

**This is the decision the pull request exists to make, so both sides are written down.**

Against a budget: `Collector::collect` is synchronous and returns a `CollectorRun`, so a budget costs
a thread and a channel, and this program has had no thread of its own until now. A budget can also end
a collection on an ordinary machine that is merely slow, which loses evidence that was there to be
read. And the one known non-terminating input is fixed, so the budget defends against a defect nobody
has an example of.

For a budget, and this is what was chosen: the failure it answers has **no upper bound and no error**.
Every other failure this program can have is a wrong answer, a refused file or a crash, all of which
end. A parse that does not return ends nothing: the app never appears, the CLI never prints, and the
person watching a screenshare sees a program that hangs — which is indistinguishable, to them, from a
program that was tampered with. The input is a file on the machine being examined, which is to say a
file the person under suspicion can write. Three defects of this class have been found in this
dependency in one day of carrying it, which is evidence about the rate, not about the remaining count.
The cost is **one thread for the whole collector**, not one per file.

The shape, specifically:

- **One total budget, not a limit per file.** A per-file limit needs a fresh worker for every file
  that overruns, because a synchronous parse has no cancellation point and the thread stuck in it
  cannot be reclaimed. On a folder full of crafted files that is one spinning thread per file — a
  worse outcome than the one being prevented. One budget means one thread, and the worst case is
  bounded by the budget rather than by the number of files.
- **One worker thread, which is dropped and never joined.** Joining it would reintroduce exactly the
  hang the budget exists to bound. A worker that is still spinning when the collection gives up costs
  one core until the process exits; that is stated here rather than hidden, and it is the price of
  bounding an uncancellable parse.
- **The bytes are read on the collector's thread and only the parse is handed to the worker.** A
  `&dyn Host` is not `'static` and cannot be moved into a detachable thread, and the reads are
  already bounded — 64 MiB per file (ADR 0019) — while the parse is the part with no bound. Read time
  is still counted against the budget, so a folder that is slow to read ends the same way.
- **30 seconds.** The whole rest of a scan is milliseconds, so this number is the app's startup time
  in the bad case: 30 s of nothing on screen is already at the edge of what a person waits through,
  and a larger budget buys a worse failure. It is a constant with no configuration, because a switch
  that turns off a bound is a switch that will be turned off.

**The cost of being wrong, in both directions.** Too low, and an ordinary machine with very large logs
has its later logs reported as `budget_exhausted`: evidence is lost, but it is lost *visibly* — each
unread log is named, and every field is gapped, so a rule reports `unmeasured` rather than "nothing
was found in the log". Too high, and a crafted file delays the window by up to the budget. The
asymmetry is why a bound exists at all: the first failure is a report with a hole in it that says
where the hole is, the second is a program that does not start.

**What the budget does not do.** It does not defeat the denial-of-check; it converts it from a hang
into a visible gap. A crafted file placed early in the read order can still consume the whole budget
and starve the logs after it. That is reported — every log after it is named as unexamined — but it is
not prevented, and preventing it is what a per-file limit would cost a thread per hostile file to try.

### The read order is part of the design

Because the budget can end a collection early, **what goes unread is decided by the order**, so the
order is chosen here and written down: `Security.evtx`, `System.evtx`, `Application.evtx`, then every
other `.evtx` file sorted. These three exist on every Windows installation and are where the events
ADR 0018 named are recorded. Ordering files is not a judgement about what an event *means* — that
stays in a rule, where ADR 0002 put it — it is a judgement about which file to open first when there
may not be time for all of them. The remainder is sorted so that two reads of one folder stay
comparable, as `fivem_dir` and `prefetch` already do.

### Failure classification

| What happened | Outcome |
|---|---|
| Not Windows | `Unmeasured { not_windows }` |
| `%SystemRoot%` unset or empty | `Unmeasured { read_failed }` — there was no folder to look in |
| the Event Log folder is not there | `Unmeasured { source_missing }` — since ADR 0030, `source_absent`; a folder holding no `.evtx` file is `source_empty`, and a log the budget did not reach is `budget_spent` or `not_attempted` |
| the folder is there and could not be listed | a `read:` observation **and** every field in `gaps` |
| one log could not be read, decoded, or reached inside the budget | a `read:` observation naming it, **and** every field in `gaps` |
| a log was listed and is gone when read | nothing; counted as neither examined nor refused |
| a log parsed with a damaged chunk | the records that survived, plus `rejected` and `intact: false`; **no gap** |

**One unreadable log gaps the run, which is where this differs from `prefetch`.** ADR 0021 argued
that one unreadable `.pf` file gaps nothing, because a `.pf` file is one program's record and losing
it says nothing about the others. An `.evtx` file is not that: it is the **whole record of a channel**.
A rule reading an unread `Security.evtx` as `NotFound` would be telling a server admin that the log
was never cleared, on evidence that was never read. That is the `pca` case (ADR 0020), and this
collector follows it. The loss stays visible three ways: the log is named with `read`, the folder
account counts it in `refused`, and every field is gapped.

**A damaged chunk is not an unreadable log.** The file was read and most of it decoded; `rejected` and
`intact` carry the loss, and a rule that needs a whole log can add `intact: true` to its matcher. This
is the same line `pca` draws at a malformed line.

**Denial is `not_admin` when this program was not elevated**, through the same
`crate::failure::reason_for` the other two collectors use — attempt first, classify second, so a
machine where the folder happens to be readable is read. ADR 0018 records that the `Security` channel
needs an elevated token. Denial is also **emitted as an observation**, not only counted in `gaps`,
because with no rule reading this collector a `gaps` entry reaches no screen at all.

### What is emitted of a record, and what never reaches this collector

**The payload does not reach the collector at all.** Confirmed by reading `rongroi_parsers::evtx`
rather than assumed: `record()` takes `Event.System`'s `EventRecordID`, `TimeCreated`, `EventID`,
`Channel`, `Level` and `Provider/@Name` out of the rendered record and **stores nothing else**; the
`EventData` block and the `Computer` field pass through that function and are dropped. That is where
an event's user names, host names, source addresses, SIDs and command lines live, and `view` cannot
redact a payload it has no schema for.

What remains is a record id (dropped again by aggregation), a timestamp, an event id, a level, a
channel and a provider. Two of those needed a decision of their own:

- **A channel or a provider name is not a person, but a full list of them describes a machine.**
  Channels are created by installed software, so the list is a rough inventory of what is on the PC —
  which is the same objection ADR 0014 raised to listing every running process. It is settled the same
  way and by the same mechanism: Self mode lists them, **SS mode lists none of them** and says how
  many were withheld. The exposure arrives with a rule, not with the collector, and when it does the
  rule shows one channel and one event id rather than the inventory.
- **Nothing here is path-shaped**, so the `unredactable_form` precedent `pca` set does not apply.
  `path` is emitted for the log file itself and is built by the collector from `%SystemRoot%` and the
  file's own name — `C:\Windows\System32\winevt\Logs\Security.evtx` has no user profile segment in it.
  A channel name is not a path and is not redacted, the same position ADR 0010 takes on a process
  name. If a provider ever spells a path into its name, that is the `pca` `name` case PRIVACY.md
  already discloses.

Every collector before this one ends with a test that serialises the whole observation set and asserts
no identifier is in it. Prefetch's makes a specific point: its fixture's account name is one letter,
so `contains` asserts nothing, and the test asserts *shapes* instead. Here the vendored sample carries
`DESKTOP-1N4R894`, a 15-character host name that `fixtures/evtx/PROVENANCE.md` counted, so asserting
its absence is a real measurement — and it is still not enough on its own, because a payload leak
would show as element names and payload fragments rather than as that host name. Both are asserted.

## Alternatives weighed

| Alternative | Why not |
|---|---|
| One observation per record | Tens of thousands of observations per log. Self mode would render a person's entire event log, and the fields a rule can match are all preserved by counting |
| Aggregate per `(channel, event_id)` only | Loses the provider and the level, which are two of the four fields a rule could scope on, and loses which file the records came from — the signal that a log is not the channel it is named after |
| Aggregate across logs rather than per log | Merges two files into one number, so a log copied in from another machine becomes invisible |
| Keep record ids so gaps in the sequence are visible | A real signal and a real cost: it is one observation per record again. It arrives with the rule that needs it (ADR 0014) |
| No wall-clock budget at all | The failure it answers has no upper bound and no error, on input the person under examination writes, in a program that has no window until the scan returns |
| A budget per file | Needs a fresh thread for every file that overruns, since a stuck parse cannot be reclaimed — one spinning thread per crafted file |
| Bound the parse by bytes instead of time | ADR 0019 already bounds the bytes at 64 MiB. The known defect was a cycle in a 68 KiB file: size is not the thing that was unbounded |
| Join the worker before returning | Reintroduces the hang the budget exists to bound |
| Make the budget configurable | A switch that turns off a bound is a switch that gets turned off, on the machine that most wants it off |
| Skip `Security.evtx` when not elevated | It would make the report quieter on exactly the machine where `not_admin` is the fact worth reporting. Attempt, then classify |
| Read the folder in listing order | The budget makes the order decide what is missing; leaving that to a directory listing is leaving it to chance |
| Cap how many logs are read | A number with no measurement behind it that silently drops part of the artifact (ADR 0021) |
| Report an unreadable log as a per-file loss only, as `prefetch` does | An `.evtx` file is a channel's whole record. A rule would read "not read" as "never happened" |
| Emit the raw `rejected` reasons from the parser | They carry a chunk number and a record id read from the file. `entries`/`rejected`/`intact` carry the signal, as `pca` already decided |

## What is unverified

**No collector in this repository has read an artifact from a real Windows machine, and this one is no
exception.** Every byte it was tested against is the one vendored 2018 sample, bytes built from it in a
test, or bytes written in a fixture. So none of the following is established here: how many `.evtx`
files a real `winevt\Logs` holds, how large they are, how long they take to parse, how many distinct
`(channel, provider, event_id, level)` groups a real machine produces, or whether a real folder holds
files that fail in ways this collector has not seen.

**The 30-second budget has no measurement behind it.** It was chosen from what a person will wait
through with no window on screen, not from a measured distribution of parse times. The first real
machine to run this is the evidence that decides whether it is too small; until then it is a judgement.

**The budget was tested by shrinking it, not by hanging a parse.** Nothing in this repository can make
the parser hang on demand: the defect is fixed and neither reproducing input is committed
(`third_party/evtx/PROVENANCE.md` keeps them outside every repository). The test sets the budget to
zero and asserts the reporting and the gaps. What is proven is that a log the budget does not reach is
named, counted and gapped. What is **not** proven is that a genuinely spinning parse is survived in
the way this ADR describes — that the thread detaches cleanly, that the process still exits, and that
the rest of the report is produced. That path has never been executed.

**The "listed and then gone" branch is not covered by a test.** A `FixtureHost` lists files from the
same map it reads them from, so it cannot describe a log that was in the listing and gone by the time
it was read — which is why `logs` can exceed `examined + refused` in the field documentation and never
does in a test. The same gap exists for `prefetch` (ADR 0021), for the same reason.

**`parse_unavailable` has never been produced.** It covers a thread this program could not spawn and a
worker that stopped without answering. `rongroi-parsers` promises it never panics, so the second
should be unreachable; neither was exercised, because neither can be provoked from a test.

**The Windows CI runner is not a real machine, and here it is closer than usual.** It runs **as
administrator with UAC off**, which is why `docs/testing.md` says Prefetch and PCA are expected
`unmeasured` there. Event Log is different: the folder exists and the token can read it, so the live
smoke on that job is the first time this program parses a real Windows machine's event logs at all.
That makes the job worth watching — and it still cannot answer the question that matters, which is
what this collector does on a machine whose owner is being checked and whose token is not elevated.
Nothing about the `not_admin` branch can be exercised there.

**That reading `%SystemRoot%\System32\winevt\Logs` needs an elevated token for `Security` is prose,
not a measurement.** ADR 0018 states it; nothing here measured it. The collector is correct either
way, because it attempts and classifies.

**The `LiveHost` path was not executed.** `list_dir` and `read_file` against a real Event Log folder
were compiled for `x86_64-pc-windows-msvc` and run by nothing. That Windows answers `PermissionDenied`
— and so `AccessDenied` rather than something else — for a denied log is assumed from `std`'s
documented mapping.

**`TooLarge` is reachable in argument, not in a test.** ADR 0019 caps a read at 64 MiB and a `Security`
log on a machine whose maximum log size was raised can exceed it. `FixtureHost` applies the same limit,
so producing that outcome in a test would mean a 64 MiB fixture; the collector maps the error through
`crate::failure::read_failure`, which is unit-tested for `TooLarge` in `failure.rs`, and the collector's
own branch is the same one `access_denied` takes. **Whether a real `Security.evtx` ever exceeds 64 MiB
in practice is not established here** — the default maximum is far below it, and the case is a machine
that was configured differently.

**`rongroi_parsers::evtx` on real-machine input is unmeasured.** One vendored sample, its mutations and
a 30-second fuzz smoke per target is the whole of the evidence, and this pull request is what first
sends a real machine's logs through it.

## Consequences

- `all()` gains `evtx::Evtx`. `docs/architecture.md` gains its row, `PRIVACY.md` says what is read of
  an event log and what is not, and `fixtures/hosts/PROVENANCE.md` gains six rows.
- **This program now creates a thread.** One, for the lifetime of one collector, named `evtx-parse`.
  It may outlive the collection; see the budget decision.
- No dependency enters `Cargo.lock` and no manifest changes: `rongroi-collectors` has depended on
  `rongroi-parsers` since ADR 0020, and the budget uses `std::sync::mpsc` and `std::thread`.
- **No existing snapshot moves.** No fixture host that predates this change sets `%SystemRoot%` *and*
  describes a `winevt\Logs` folder, so the collector is `Unmeasured` on every one of them and
  contributes no observation. `cargo xtask check-baseline` is untouched for the same reason — both
  baselines have no `SystemRoot` — and the rule set has nothing to say about this collector anyway.
- Two new L3 snapshots, read by name, so `pnpm -C apps/desktop test` is unaffected.
- Six new fixture hosts, four of which point at `fixtures/evtx/` with `from:` and copy nothing.
  **Nothing is added to `fixtures/evtx/`**: it is the seed corpus `fuzz_evtx` reads and everything in
  it must parse. The two cases that need bytes no repository file holds — a damaged chunk, and a
  header that is not an Event Log's — are built in the test and written to a fixture host in the
  temporary directory, which is what `xtask`'s own tests already do.
- **The `evtx` parser is reachable from a real scan for the first time.** Until this pull request it
  was called only by its own crate's tests and by `fuzz_evtx`; from here it is called on whatever
  sits in a player's `winevt\Logs`.
