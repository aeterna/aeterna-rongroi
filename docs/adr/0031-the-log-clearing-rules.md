# ADR 0031 — The two log-clearing rules, and the one that is not written

- Status: proposed
- Date: 2026-09-13

## Context

Every rule this repository has shipped so far describes the machine. `secure_boot: disabled` says
something about a PC; nobody reads it as a sentence about a person, and its own `description` says so.

These two are different in kind. A log-clearing rule that fires puts a line in front of a community's
staff, during a screenshare, about the person sitting at the keyboard, and they will act on it. ADR
0028 put the evidence for that change of register on the record and it has not moved:

- A popular gaming "optimiser" clears on the order of a thousand channels in one click and wipes
  Prefetch in the same run. A player who ran one months ago presents the complete textbook
  anti-forensics composite having done nothing wrong.
- **All three** of SigmaHQ's log-clearing rules sit on SigmaHQ's own false-positive suppression list
  for clean Windows baseline images, one of them with the catch-all pattern `.*`. Elastic rates its
  equivalent 21 out of 100. Splunk's known-false-positives note is "It is possible that these logs may
  be legitimately cleared by Administrators."
- Microsoft's own instruction for event 1102 is *investigate*, not *conclude*, and it is written for a
  SIEM with an analyst behind it. This program has no analyst step. It has a screenshare.

So the question this ADR answers is not "can a 1102 rule be written" — it is three equalities and it
could have been written months ago. It is **which rules are defensible, in what words, and which are
not written at all.**

## Decision

### Two rules, because one cannot say what two say

The engine gained a value list meaning **or** in ADR 0029, so `event_id: [1102, 104]` is now
expressible. It is also wrong here. 1102 lives on the `Security` channel and 104 on `System`, and
`match` is a conjunction of independent entries with no grouping: one rule carrying
`event_id: [1102, 104]` and `channel: [Security, System]` asks for the **cross product**, so it also
matches a 1102 on `System` and a 104 on `Security`. Neither combination is a thing Windows writes, so
the widened rule would not be wrong in practice — it would be a rule whose `title` claims one thing and
whose `match` says another, which `rules/AGENTS.md` names as the failure this repository cares most
about. Two rules, one predicate each.

They are also two different findings for a reader. One names the Security log, which needs an elevated
token to read and is the log a reviewer came for. The other cannot name its log at all (below), so
saying "the Security log was cleared" and "some log was cleared" in one row would be the vaguer of the
two claims wearing the sharper one's title.

| | `security-audit-log-cleared` | `event-log-file-cleared` |
|---|---|---|
| id | `ff967b28-984b-4de0-b361-58367ae0c2d5` | `f4c99b57-02c8-4e53-82d0-dba8bdc13dda` |
| `match` | `provider: Microsoft-Windows-Eventlog`, `channel: Security`, `event_id: 1102` | `provider: Microsoft-Windows-Eventlog`, `channel: System`, `event_id: 104` |
| `strength` | `tamper` | `tamper` |
| `status` | `experimental` | `experimental` |

Each declares the other in `related` as `similar`, and **each says in its own `description` that the
two rows can be one action**: clearing the Security log can be recorded both in Security as a 1102 and
in System as a 104. The engine has no negation, so the de-duplication SigmaHQ does with a `filter`
block is not available here, and the honest substitute is to tell the reader — in the text shown beside
every row, whatever the state (ADR 0027) — rather than to let two rows read as two events.

### Three equalities, never the event id alone

An event id is unique only **per provider**. 1102 is also an Exchange antimalware engine update in the
`Application` log and an RDP client event on `Microsoft-Windows-TerminalServices-RDPClient/Operational`;
104 is also "client timezone bias from UTC" on the Remote Desktop Services channel. A rule on the number
alone names those people. Both rules therefore pin `provider` and `channel` as well, which is what
SigmaHQ does and what Elastic's originally proposed query did not. Each rule carries a negative fixture
built from exactly those collisions, so the gate fails if the pins are ever dropped.

The field names are the collector's own — `provider`, `channel`, `event_id`, on the per-kind summary
observation `evtx` emits (ADR 0024). `check-rules` enforces them against `Collector::fields`.

**No operator is used.** ADR 0029 added four, and none of them earns its place here: the predicate is
three exact equalities. In particular `count|gte: N` is not written. A high count is the optimiser's
shape, not a worse finding, and a rule that fired only above a threshold would be a rule that has
decided how many clearings are too many.

### `strength: tamper`, argued rather than picked

`tamper` is "traces were removed or altered". That is what the record says happened, and it is the one
thing about it that is not in doubt: the records really are gone. It is a description of the **class of
evidence**, not a severity — this program has none (ADR 0002) — and it makes no claim about who or why.

Two levels were weighed against it.

- **`context`** — "background information for the reviewer". It would be a euphemism. It would file a
  record that says a log was destroyed in the same drawer as "this machine has no TPM", and a reader
  who later learned what the row meant would be right to distrust the labelling.
- **`posture`** — rejected, and for a reason that is behaviour and not taste. `view::ss_lists` lists a
  `posture` rule's `not_found` in SS mode, because the machine's posture is what an SS reviewer came
  for. A `not_found` here means almost nothing: the Security log holds a limited window, and a later
  clearing removes the record of an earlier one, so "no 1102 today" is compatible with any number of
  clearings. Under `posture` that near-empty negative becomes a row a reviewer reads as "we looked and
  it is clean" — the closest thing to a verdict this program can accidentally emit. Under `tamper` it is
  counted, not listed, which is the honest weight. The snapshots show exactly that: `not_found: 2` in
  the SS hidden counts, no row.

### `status: experimental`, and no fixture manufactured to leave it

`test` means "believed correct", and it needs a positive and a negative fixture — both of which these
rules have, more than one each. The fixtures are not what holds the status down. This is:

> **There is no Security-channel `.evtx` file in this repository, and one cannot be added.** Every
> candidate carried somebody's real data, which is why exactly one modern sample is vendored — a
> LanguagePackSetup log — and why the last one that looked clean was removed on finding a real machine
> SID in its chunk string table (`fixtures/evtx/PROVENANCE.md`).

So the strings these rules match — `Microsoft-Windows-Eventlog`, `Security`, `System` — have never been
produced by this code from any bytes. They are read from Microsoft's published manifest and sample XML
and from Eric Zimmerman's EvtxECmd maps, and typed into a rule. That is a different kind of confidence
from `secure_boot: disabled`, where the matched string is written by our own collector and the fixture
compares a rule against the same line of Rust that emits it.

A fixture is a claim about an ordinary machine (`fixtures/hosts/PROVENANCE.md`). Writing a synthetic
Security log to reach `test` would be manufacturing that claim to satisfy a gate, which is the failure
mode a gate is supposed to prevent. `experimental` is what this evidence supports. The condition that
would raise it is stated rather than left to memory: **a Security-channel sample that carries nobody's
data, or a run of this code against a real machine's `winevt\Logs` with a 1102 in it.**

### `unmeasured_when`: three declared, two deliberately not

Both rules declare `[not_windows, not_admin, access_denied]` and leave out `source_missing` and
`read_failed`, of the five the `evtx` collector can report.

- `not_admin` — the Security log needs an elevated token, so this is the ordinary outcome of an
  ordinary scan, for **both** rules: the collector's `gaps` are folder-wide, so one unreadable log gaps
  every field and leaves a System-channel rule unmeasured too.
- `access_denied` — the same thing when Windows refuses an elevated read as well, which the Event Log
  service holding the live file open can produce.
- `not_windows` — a scan that is not on Windows. Declared by every rule in the bundle.
- `source_missing` — **not** declared. Every Windows machine has `%SystemRoot%\System32\winevt\Logs`.
  Its absence is not ordinary and a reviewer should see the line.
- `read_failed` — **not** declared, and this is the one that cost something. It covers a log larger
  than a host reads in one piece, a log that would not parse, and the collector's 30-second budget
  running out before a log was reached; any one of them gaps the whole run. It may well turn out to be
  common on a real machine with two hundred logs — nobody here has measured that. But "the Event Log
  could not be read" is precisely the result a reviewer of a log-clearing rule most needs to see, and
  declaring it would turn that into a number they move past (ADR 0027). Declaring a reason you have not
  thought about hides a result a reviewer should have seen, so the reason that has not been measured is
  the one left undeclared.

The visible cost is in the snapshots: on the fixture hosts that set no `%SystemRoot%` — `pca`,
`prefetch`, `bam`, `fivem_dir` — the SS view now lists two `unmeasured / read_failed / not expected`
rows. That is an artifact of those hosts rather than a machine state, and it is the right direction to
err in: two rows saying "this was not measured" is not a sea of red flags, and it is true.

### `retention`, which has to say more than how far back the source sees

The usual sentence is "how far back the source can see". These rules need a second clause, because **the
evidence erases itself**: a later clearing of the Security log removes the 1102 that recorded an earlier
one. So both `retention` strings end with the consequence, in words, rather than leaving the reader to
derive it — *nothing found here does not mean no log was ever cleared.*

### `falsepositives`, which is the most important text in this change

It is rendered beside every `found` row in the reader's language (ADR 0027), so it is written for a
community admin reading it aloud mid-screenshare, not for an examiner. Five entries on the 1102 rule and
five on the 104, in the order a reader should meet them:

1. **The gaming optimiser, first.** It is the dominant cause in this population and it is absent from
   every enterprise rule's list, because enterprises do not run them. Named in plain words — "clear
   every log on the PC in one click" — with the part that matters to a reader on the spot: the owner
   usually ran it months ago and has forgotten.
2. **Factory imaging.** Vendor-documented: Sysprep `/generalize` "deletes event logs". Every retail
   prebuilt gaming PC has been through it, so the person who cleared the log is the manufacturer.
3. **Software that resets the log as part of setup.** SigmaHQ's own first-listed false positive.
4. **The Event Viewer "Clear Log" button.** Standard troubleshooting advice, and the dialog offers to
   keep a backup, so doing it is not even careless.
5. **Feature updates, in-place reinstalls, maintenance scripts and scheduled tasks.**

The 104 rule's first entry adds why its count reaches the hundreds, because the number is the thing a
reader will react to and it is the benign explanation's own signature.

**Disk Cleanup and Storage Sense are deliberately absent.** It is the most commonly repeated cause in
the folklore and the research found no evidence for it; a false reassurance is as much a defect here as
a false accusation.

### The rule that is not written: "the Security log is empty"

`entries: 0` on `Security.evtx` is one equality, the collector emits the field, and it would have been
the third rule in this change. It is not written, and it should not be written from these bytes.

**Cleared, rotated at the size cap, never enabled, and a channel this machine has never used are not
separable from an `.evtx` file.** What would separate them is `maxSize` and the channel's `enabled`
flag, which live in the registry and in `wevtutil gl` — a different source and a child process, neither
of which this program has (ADR 0028 records the same gap from the collector's side). The Security log
defaults to 20 MB and to overwrite-as-needed, and practitioners report that window covering hours to
days on a busy machine, so a short or empty log is the **expected** state and a rule keyed on it would
fire on ordinary machines while presenting itself as a finding about a person.

The same reasoning rules out anything built on `logs_without_records`: a high count is the optimiser's
shape and therefore evidence **for** the benign explanation, and a rule that showed it as a finding
would be doing exactly the inversion `rules/AGENTS.md` forbids.

It is worth saying plainly what that leaves: **the two rules that ship can only see a clearing that
Windows wrote a surviving record about.** A clearing whose record has itself been cleared, a log
truncated by shrinking its size cap, and a channel that was switched off are all invisible to them, and
the `retention` text says so to the reader rather than only here.

## Alternatives weighed

| Alternative | Why not |
|---|---|
| One rule, `event_id: [1102, 104]` with a channel list | Asks for the cross product; the `title` would claim more than the `match` says. Two findings, two rules |
| A narrow 104 rule restricted to the six channels SigmaHQ calls important | The cleared channel is in the record's payload, which the parser drops (ADR 0018). It cannot be written at all, and a rule that pretended to be narrow would be worse than one that admits it is broad |
| Ship the 1102 rule only, and drop the 104 | Tempting, because the 104 cannot name its log. But the 104's count is what makes the optimiser visible; without it the 1102 stands alone and reads worse than the evidence is. Shipping both, each saying they can be one action, shows the reader more and claims less |
| `status: test` on the strength of the synthetic fixtures | The fixtures test the engine, not the strings. See above |
| `count\|gte` on the 104 rule, to fire only on a burst | A threshold is a decision about how many clearings are too many, and the burst is the benign shape anyway |
| Add a Security-channel log to `baseline-elevated-win11` so `check-baseline` can measure these rules | A baseline is a claim that a machine like it is unremarkable. Inventing one to exercise a rule is what `fixtures/hosts/PROVENANCE.md` forbids, and the invented log would be describing a machine nobody has seen |

## What is unverified

**The evidence base is weak, and the rules must never be read as saying more than this.** A `found` row
from either of them means: *Windows recorded that a log was cleared, at this time, and this program can
see nothing of what the log held before that.* It does not mean the person cleared it, that they knew
it happened, that anything was hidden, or that there was anything to hide. Two rows are not two events.
A high count is not a worse finding. And a `not_found` row is close to meaningless in both directions.

Specifically unverified:

- **No Security or System `.evtx` record has ever been read by this code.** `Microsoft-Windows-Eventlog`,
  `Security` and `System` are typed from published documentation. If the collector emits any of them in
  a different shape, both rules are `not_found` on every machine — which this program shows a player as
  evidence that something was looked for and was not there. `check-rules` cannot catch that, because it
  checks field *names* and not the values a real machine puts in them.
- **`check-baseline` cannot measure these rules, and its green says nothing about them.** On
  `baseline-elevated-win11` both are `not_found`; on the other two baselines both are `unmeasured`.
  The gate fails only on `found`, so it would stay green whatever these rules said. This is the false
  green ADR 0026 was written to close, reappearing for this rule set because the one vendored sample is
  a LanguagePackSetup log. It is recorded here, in `docs/testing.md` beside the gate it defeats, and in
  `rules/AGENTS.md`. It is **not** closed.
- **Whether a clearing of the Security channel always writes a 104 in the System log** is unresolved in
  the research, on every Windows build. The rules' text says the two rows *can* be one action, never
  that they are.
- **The false-positive research is read, not reproduced.** No optimiser script was run, no machine was
  imaged, nothing in `falsepositives` was observed here. Each entry is sourced in the rule's
  `references` or in ADR 0028; none is measured.
- **How often `read_failed` really happens** on a machine with two hundred logs and a 30-second budget.
  The decision not to declare it rests on an argument, not on a number.
- **`rust (windows)` was not run for this change.** It adds no Rust behaviour — two YAML files, their
  fixtures, a translation, and a test helper that looks a rule up by path instead of by index — but
  that is an argument and not a run.

## Consequences

- The `evtx` collector is read by a rule for the first time. Its module header and the report-snapshot
  test doc comments said "no rule reads this collector"; both are corrected rather than left to rot.
- Every report snapshot gains two evidence rows. On hosts where the Event Log is readable they are
  `not_found`; where `%SystemRoot%` is unset they are `unmeasured / read_failed`, and SS mode lists
  those two rows because `read_failed` is undeclared. In the `evtx` SS snapshot the two `not_found`
  results are counted and not listed, which is the `tamper`-not-`posture` decision showing up as
  behaviour.
- `crates/rongroi-cli/src/output.rs`'s test helper took `bundle.rules()[0]` and assumed it was the
  secure-boot rule. `rules/evtx/` sorts before `rules/posture/`, so adding a rule broke four tests that
  are about rendering and not about ordering. The helper now finds its rule by path.
- `rules/known-fps.csv` still has no rows.
- No change to the rule format, the report schema, the engine, or any collector's behaviour.
  `RULES_SCHEMA_VERSION` and `REPORT_SCHEMA_VERSION` are untouched.
