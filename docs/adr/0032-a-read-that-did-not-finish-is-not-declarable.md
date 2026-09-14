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

## Amendment (2026-09-14) — every `access_denied` declaration, reviewed

### The question

"What this does not fix" above left the `access_denied` declarations unexamined: legitimate in principle,
never checked against what each rule's collector actually does. Eleven of the eighteen rules declared it.
This amendment checks each one against the question the declaration answers — **on an ordinary machine,
is this collector's read of the fields this rule matches refused, and does the refusal come out as
`access_denied`?** A declared reason is counted in SS mode and an undeclared one is listed, so a
declaration that describes no ordinary machine hides the row a reviewer should see.

### What `access_denied` means per collector — read in the code, not assumed

| Collector | When a refusal becomes `access_denied` |
|---|---|
| `evtx`, `prefetch` | `crate::failure::reason_for`: a refusal while `Host::is_elevated()` is `Some(false)` is `not_admin`; `access_denied` is a refusal **with** the Administrators group enabled in the token, or on a host that cannot say. `LiveHost::is_elevated` answers `None` only if `CreateWellKnownSid` or `CheckTokenMembership` fails |
| `posture`, registry settings (`secure_boot`, `hvci`, `script_block_logging`) | `posture`'s own `reason_for`: any `SourceError::AccessDenied`, elevated or not |
| `posture`, `test_signing` and `tpm` | never: `LiveHost::code_integrity_options` and `LiveHost::tpm_info` return `SourceError::Failed` for every failure (`system_integrity.rs`, `tpm.rs`), which is `read_failed`. Only a `FixtureHost` produces a refusal here |
| `posture`, `secure_boot_firmware` | `crate::failure::reason_for`: `not_admin` without elevation; `access_denied` only when an elevated token does not hold `SeSystemEnvironmentPrivilege` (`firmware.rs`) |

### What was measured

Read-only, on 2026-09-14, on the Windows 11 machine (build 26220) the earlier ADRs measured, with
`Get-Acl`; only well-known principals are recorded:

| Object | Access |
|---|---|
| `HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State` | `BUILTIN\Users`: ReadKey · `ALL APPLICATION PACKAGES`: ReadKey |
| `HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity` | `BUILTIN\Users`: ReadKey · `ALL APPLICATION PACKAGES`: ReadKey |
| `HKLM\SOFTWARE\Policies\Microsoft\Windows` (the `ScriptBlockLogging` key under it was absent) | `Authenticated Users`: ReadKey |
| `%SystemRoot%\Prefetch` | `BUILTIN\Administrators`: FullControl, and nothing for other accounts |
| `%SystemRoot%\System32\winevt\Logs` | `Administrators`, `SYSTEM`, `NT SERVICE\EventLog`: FullControl · `Authenticated Users`: Read |
| `Security.evtx`, `System.evtx`, `Application.evtx` in it | `Administrators`, `SYSTEM`, `NT SERVICE\EventLog`: FullControl |

With the scans already recorded: elevated, that machine read 413 log files and 243 `.pf` files with no
refusal (ADR 0037) and the Event Log service described all 148 channels asked (ADR 0042); the GitHub
`windows-latest` runner, elevated, read 221 log files with no refusal (ADR 0037). Under a limited token
the `posture` registry readings were read (ADR 0033, ADR 0038) and the firmware reading was `not_admin`;
the privilege the firmware read needs was held by all three elevated tokens it was checked on — the SSH
session, a scheduled task at the highest run level, and the CI runner (ADR 0038).

ADR 0031 had given the log-clearing rules' declaration a reason: an elevated read refused "which the
Event Log service holding the live file open can produce". Neither elevated scan above met it, on any
log; the live `Security.evtx` was read on both.

### The review

| Rule | Declared before | After | Reason |
|---|---|---|---|
| `event-log-file-cleared` `f4c99b57` | `not_windows, not_admin, access_denied` | `not_windows, not_admin` | `access_denied` is a refusal with administrator rights; two elevated scans read every log, including the live files ADR 0031 expected to be refused. An unreadable log is the result this rule's reviewer most needs to see (ADR 0031's own argument for `read_failed`) |
| `security-audit-log-cleared` `ff967b28` | `not_windows, not_admin, access_denied` | `not_windows, not_admin` | As above |
| `event-log-file-read-only` `9b318bfa` | `not_windows, not_admin, access_denied` | `not_windows, not_admin` | As above; the attribute is read before the bytes, and neither elevated scan was refused either |
| `event-log-not-at-configured-path` `87a53c8f` | `not_windows, not_admin, access_denied` | `not_windows, not_admin` | As above, and the service described every channel asked, elevated |
| `prefetch-file-read-only` `7d493537` | `not_windows, not_admin, access_denied, source_absent, service_disabled` | `not_windows, not_admin, source_absent, service_disabled` | Administrators hold full control of the folder, and an elevated scan listed it on both machines; a non-elevated refusal is `not_admin`, which stays |
| `secure-boot-disabled` `7c1f3a52` | `not_windows, source_absent, access_denied` | `not_windows, source_absent` | The key grants `Users` read and a limited-token scan read it. `posture` reports any refusal as `access_denied`, so a refused read here is a machine whose key permissions were changed |
| `secure-boot-firmware-disagrees` `5ec56c3d` | `not_windows, not_admin, source_absent, access_denied` | `not_windows, not_admin, source_absent` | `secure_boot` as above; `secure_boot_firmware` without elevation is `not_admin`, which stays, and elevated it is refused only for a token without a privilege every elevated token checked held |
| `test-signing-enabled` `75162c70` | `not_windows, access_denied` | `not_windows` | The live query never reports a refusal; the declaration described no real machine — a line that looks load-bearing and is not, which is the shape this ADR removed for `read_failed` |
| `script-block-logging-disabled-by-policy` `88eb2aca` | `not_windows, access_denied` | `not_windows` | `Policies\Microsoft\Windows` grants `Authenticated Users` read and a limited-token scan was not refused. ADR 0038 wrote the line in the same pull request that measured this |
| `hvci-disabled` `8458638a` | `not_windows, source_absent, access_denied` | `not_windows, source_absent` | As `secure-boot-disabled` |
| `tpm-absent` `66d513b5` | `not_windows, access_denied` | `not_windows` | As `test-signing-enabled` |
| the seven `fivem_dir` rules (ADR 0036) | `not_windows` | unchanged | Never declared it: the folders are in the player's own profile. Each already says so in a comment, except `asi-file-with-valid-signature` and `signature-not-checked`, whose line was left alone |

**No declaration was kept.** That is the outcome of eleven separate checks, not a rule: `access_denied`
stays declarable, and a rule whose collector is refused on an ordinary machine *with* the reason
`access_denied` should declare it. None of the eighteen has such a collector today. Each changed line
carries a `#` comment with its reason.

### What this does not change, and what it does not establish

- **`posture` does not split a registry refusal by elevation**, as the artifact collectors do. A future
  `posture` reading of a key that only administrators may read would report an ordinary non-elevated scan
  as `access_denied`; that rule would have a real reason to declare it, or `posture` would move to
  `crate::failure::reason_for`. Neither is decided here.
- **Access lists from one machine and refusals from two.** Security software that refuses an elevated
  read of these files or keys, or a Group Policy that removes a right from Administrators, was not
  measured. On such a machine these rows are now listed in SS mode with the reason Windows gave, which is
  the cost if this review is wrong — a longer report on that machine, never a hidden result.
- **No report snapshot moves.** No snapshotted fixture host produces `access_denied` for these rules. The
  new test `a_refusal_no_rule_expects_is_listed_in_ss_mode` runs the three hosts that do —
  `evtx-access-denied-elevated`, `prefetch-access-denied-elevated`, `registry-access-denied` — and
  requires each refused rule to be `expected: false` and listed in SS mode; with the rules as they were,
  it fails.
- The rules bundle's SHA-256 changes, and `docs/rules-reference*.md` lose eleven lines. No rule text a
  reader sees changed, so `rules/i18n/th.yaml` is untouched.
