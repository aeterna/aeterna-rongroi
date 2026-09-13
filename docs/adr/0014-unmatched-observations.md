# ADR 0014 — Unmatched observations

- Status: accepted
- Date: 2026-09-12

## Context

A collector reads the machine whether or not a rule asks about what it finds. Two of the three
collectors that ship today read it and then threw the result away.

`Report` held `{ header, evidence, own_traces }`. `evidence` is built by mapping over the rules in the
bundle, and an `Observation` reaches that structure only inside `EvidenceState::Found`. The CLI walks
`view.evidence` and `view.own_traces`, and the desktop app renders the same two lists. So an
observation that matched no rule reached no screen: not because a mode hid it, but because nothing
carried it.

`fivem_dir` and `process` are both in that state, each deliberately shipping without a rule (ADR 0009,
ADR 0010). Every scan listed FiveM's plugin folder and enumerated the running processes, and every
scan discarded both.

ADR 0009 said otherwise. Of `fivem_dir` it stated: *"The observations are still visible in Self mode,
where a person reads them."* That sentence was false when it was written, and `fivem_dir.rs` and
`process.rs` repeat the claim in their module documentation. ADR 0010 had already noticed the gap and
recorded it as a consequence rather than fixing it.

A tool whose stated purpose is to show a reviewer what is on a PC, and which then silently drops most
of what it read, is not doing the thing it claims.

## Decision

### Keep them, and give the idea one name

An observation that **no active rule matched at all** is an **unmatched observation**. `Report` and
`ReportView` gain `unmatched: Vec<UnmatchedGroup>`, where an `UnmatchedGroup` is one collector's id
and the observations of its run that no rule matched. The term goes in the `CONVENTIONS.md` glossary
and is the only word used for the idea in code, UI keys and docs (AGENTS.md hard rule 8). `context` is
already a `Strength` value and is not reused here.

The alternative was to delete the sentence from ADR 0009 and accept that a collector without a rule
reads the machine for nothing. That would keep the code honest at the cost of the feature: the plugin
folder and the process list are exactly the things a reviewer wants to look at before any rule exists
that can name what is worth calling out. Showing them costs a bucket; dropping the claim costs the
reading.

### Unmatched is the complement of "matched", not the union of "did not match"

An observation is unmatched when **no** non-deprecated rule matched it. "Matched" means what
`engine::matches` already means, including the `allow` check: an observation a rule excluded by hash
or signer was not matched by that rule.

The implementation collects the observations that matched **at least one** rule and takes the
complement within the run. The obvious wrong implementation — treating each rule's non-match as
unmatched — would list almost every observation, most of them several times over, because a rule
matching one thing does not match any of the others. An observation that matched rule A is evidence
under rule A; that rule B did not match it says nothing worth showing.

An observation excluded by a rule's `allow` list is unmatched rather than dropped. The allow list says
"this rule does not call this software out", not "this file was never there", and the difference
belongs to the person reading the report.

### Own traces are partitioned out first, and are never also unmatched

`evaluate` already moves every observation describing this program out of the runs before any rule is
evaluated (ADR 0010). That order is kept, and unmatched observations are computed from the runs that
partitioning returned. aeterna-rongroi's own process matches no rule either, so without that order it
would appear in both buckets and the report would show the tool to the reader twice, once as
transparency and once as something seen on the machine.

### Self lists them; SS counts them. The asymmetry is the point

Self mode passes `unmatched` through whole. SS mode leaves it empty and adds the number of
observations to `HiddenCounts`, which gains a third field.

This is deliberate, and it is not the same treatment own traces get. SS mode's promise to the person
being screenshared is "only what matches a rule, paths redacted" — the consent screen says so before
anything is read. An unmatched listing is the opposite of that promise: it is every file name in
FiveM's plugin folder and the name of every process running on the machine, which is to say the
person's editor, their chat client, whatever else they happen to have open, shown to a server's staff
because they agreed to a cheat check.

Redaction does not rescue it. Path redaction replaces the `X:\Users\<name>\` shape; it does not make a
list of everything a person is running less of a disclosure, and the same gap ADR 0010 recorded — a
process **name** is not a path and is not redacted — applies to every entry. A redaction pass over a
raw listing would look like a guarantee while changing almost nothing about what the listing reveals.

Own traces are listed in SS mode because they are one known program, this one, and hiding "this was us"
from the person watching would tell them less. Unmatched observations are unbounded and are about the
person. The two buckets are shown differently because they are different things, not because one of
them was overlooked.

Counting rather than omitting silently keeps SS mode honest: the viewer is told that the tool saw
things it is not showing them, and the player can read the full list in Self mode first and know
exactly what SS mode will and will not reveal.

### Additive, with no schema bump

`unmatched` carries `#[serde(default)]` and `REPORT_SCHEMA_VERSION` stays at 1, exactly as `own_traces`
did: a report written before the field existed reads back with none, which is what it meant.

## Consequences

- ADR 0009's "No rule reads this collector yet" paragraph is corrected in place rather than edited to
  remove the false sentence: the record should show what was claimed, that it was wrong, and what
  fixed it. ADR 0010's consequence bullet noting that a collector without a rule was *not* shown in
  Self mode described the state at that time and is superseded by this ADR.
- `Report` and `ReportView` both gained a field, and every existing report snapshot gained
  `"unmatched"` and a third `hidden` count. Two of those snapshots gained content rather than an empty
  list: the `fivem_dir` Self view now contains the fixture's plugin paths, and the `process` Self view
  the two processes that are not this program.
- The `fivem_dir` SS snapshot can now assert something it could not before. It checked that the
  fixture user name never appears, which held trivially while no observation of that collector reached
  any view. It now holds because SS mode excludes the listing on purpose, and the test also asserts
  that the file names are absent.
- A posture observation that matches no posture rule is an unmatched observation too. On a machine
  where every setting is as the rules would like, Self mode now shows what was read — Secure Boot on,
  memory integrity on, a TPM present — instead of showing four `not_found` lines and nothing else.
  This is the same statement the rules make, from the other direction, and it is what the collector
  actually saw.
- A collector whose observations all matched a rule contributes no group at all, rather than an empty
  one, and neither does a run that could not look: it saw nothing to leave unmatched.
- The cost is one pass over each run per rule. The engine stays pure — no I/O, no clock.
