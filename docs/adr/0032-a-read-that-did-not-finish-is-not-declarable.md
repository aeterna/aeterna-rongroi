# ADR 0032 — A read that did not finish is not a rule author's to declare away

- Status: accepted
- Date: 2026-09-13

## Context

ADR 0027 gave `unmeasured_when` its meaning: a reason a rule declares is counted in SS mode, a reason
it did not declare is listed as a row. ADR 0030 carved out two reasons that are listed **whatever the
rule said** — `partial` and `budget_spent` — with this argument:

> A rule author cannot declare either away, because neither is a fact about the machine for them to
> have anticipated.

`read_failed` meets that description word for word and was not carved out. Its own row in ADR 0030's
vocabulary table reads "I/O failure, a file past the 64 MiB cap, an unset `%SystemRoot%`. Uncommon".
None of those is a kind of machine. An ordinary Windows 11 PC has a readable
`HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State`; a rule that says it expects that key to be
unreadable is not describing a population, it is describing a fault.

ADR 0027 recorded the consequence as an open question rather than as a defect, and named the four
rules it applies to:

> **all four shipped rules already declare `read_failed`** … in lines written when nothing read the
> field. From this change on those lines have teeth, so a registry read that genuinely failed is
> counted rather than listed in SS mode.

So the four lines predate the mechanism they now drive. They were not a decision about `read_failed`;
they were a list written while the field decided nothing. The question this ADR answers is not "were
those four authors right" — none of them was choosing — but "is this a choice a rule author has".

## Decision

**`read_failed` joins `partial` and `budget_spent` as a reason no rule may declare.** Two mechanisms,
because they cover different bundles:

1. `UnmeasuredReason::is_always_listed` returns true for it, so a view lists the row even when the
   evidence carries `expected: true`. This binds any bundle the program loads, including one built
   before this change and one this repository's gates never saw.
2. `check-rules` refuses a rule whose `unmeasured_when` names any reason `is_always_listed` answers
   true for. This binds the rules in this repository, at build time, with a message that says why.

The four `read_failed` lines are deleted from `rules/posture/*`. With (2) in place they could not be
restored by a later rule without the gate saying so, which is the half that makes the deletion stick.

### Why both, and not either alone

(1) alone leaves the declaration in the file, readable as a decision an author made, driving nothing.
That is the shape this project has repeatedly found to be worse than an absence: a line that looks
load-bearing and is not. (2) alone leaves the guarantee outside the program — a third-party bundle,
or a rule set from a future version of this repository read by an older binary, would still silence
a failed read.

### What was rejected

**Leaving it to rule authors with guidance in `rules/AGENTS.md`.** The four existing lines are the
argument against: they were written by an author following the format, not misreading guidance.

**Carving out nothing and deleting the four lines only.** The next rule written gets the same list
copied from a neighbour. Nothing in the repository would object.

**Treating `access_denied` the same way.** Three of the four rules declare it too, and that one *is*
a fact about the machine: a non-elevated scan on a machine whose owner did not take the elevation
offer is an ordinary population, not a fault. It stays declarable. The line between the two sets is
whether the artifact was reached: `access_denied` and `source_absent` say the program never got to
it and why, in terms of how the machine is set up; `partial`, `budget_spent` and `read_failed` say it
got there and the read did not finish.

## What this does not fix

- **It does not bound the other direction.** ADR 0027's open question was two-sided; this settles one
  reason. A rule that declares `not_windows`, `source_absent` and `access_denied` — as
  `secure-boot-disabled` now does — still silences three of the four things that can stop it, and
  `check-baseline` still fails only on `Found`. ADR 0033 takes up the part of that which is
  measurable.
- **It changes no `access_denied` declaration**, so the second half of ADR 0027's paragraph — three
  rules declaring `access_denied` in lines written before the field was read — is still unexamined.
  It is left as it stands rather than swept along with this one: the argument above says it is a
  legitimate declaration, not that it is the one each author meant.
- **Nothing was measured about how often `read_failed` actually occurs.** The vocabulary table calls
  it "uncommon" and no scan of a real population backs that. If it turns out to be common, this
  change makes reports longer in exactly the situation where the extra rows say least.

## Consequences

- Four `rules/posture/*/rule.yaml` files lose a `read_failed` entry. No rule's matching changes;
  `RULES_SCHEMA_VERSION` and `REPORT_SCHEMA_VERSION` are untouched.
- **Twelve report snapshots change, and the change is the point.** On the six fixture hosts whose
  registry this program cannot read, `test-signing-enabled` and `tpm-absent` came out
  `unmeasured / read_failed` and both declared it: SS mode counted them and showed nothing. They are
  now two rows a reviewer can see, and `hidden.unmeasured_expected` drops from 4 to 2 on each of
  those views. The other two posture rules are unaffected because they reach those hosts through
  `source_absent`, which they declare and still may.

  The four `expected: true → false` pairs in each Self view are the same fact seen from the other
  mode, where nothing was hidden to begin with.
- The two log-clearing rules' comments said `read_failed` was "left out deliberately". That is no
  longer a choice made there, and the comments now say so rather than claiming credit for a
  prohibition.
- A rule that names `partial` or `budget_spent` is refused with the same message, which was true in
  substance before this change and enforced nowhere.
