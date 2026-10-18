# ADR 0076 — Lab replay: showing a rule fires on a real Windows

- Status: proposed — drafted 2026-10-18 at the owner's request, as the validation ("red") half of the
  detection-validation programme of ADR 0074 and ADR 0075; the owner's questions are at the end. Nothing
  here is built yet.
- Date: 2026-10-18
- Related: ADR 0074 (the ledger and the `stable` requirements), ADR 0069 (the virtual machine lab),
  ADR 0017 and ADR 0033 (baseline), `fixtures/hosts/PROVENANCE.md`, `SECURITY.md`, `AGENTS.md` (purpose
  boundary)

## Context

ADR 0074 §5 makes `stable` require a rule to have been seen `found` on a lab machine. The ledger, read
2026-10-18, shows how far that is:

- 60 evidence rules (77 less 17 timeline selectors);
- 10 rules seen `found` anywhere outside a fixture — 4 on `lab-vm-arm64`, the rest on the owner's PC or a
  GitHub runner;
- fixtures are fed to the engine directly, not through a collector (`xtask/src/check_rules.rs`), so a green
  `check-rules` does not show that a collector on a real Windows emits what the fixture claims.

The ADR 0069 lab already does the hard part. `.claude/probes/vm-lab/lab.sh boot <step>` boots a Windows 11
Arm virtual machine, runs a script from a USB share before the scan (`PRE_CMD`), runs `rongroi.exe scan
--json`, shuts the machine down and copies the result out. Steps T7–T9 are named as positive cases
(`T7-positive-invariants`, `T8-positive-de`, `T9-positive-de-cmd`); what each set up is in a maintainer's
untracked notes, not here. What is missing is a repeatable form: each step writes to the
one system disk, so a trace set up for one step is still there for the next, and the steps live in a
maintainer's untracked notes.

## Decision

### 1. A scenario is one trace, set up on a throwaway disk

A **scenario** names one rule (or a few that read the same trace) and has three parts:

- `setup.ps1` — puts the trace in place on the virtual machine, using only what §2 allows;
- `expect.yaml` — the rule ids that must read `found`, and the neighbouring rules that must stay
  `not_found` (so a scenario also catches a rule that fires too widely);
- `README.md` — what the trace stands for in the real world, and what the scenario does not show.

Each run boots from a fresh copy-on-write overlay of the installed system disk (`qemu-img create -b
win.qcow2`), and the overlay is deleted after the scan. Nothing a scenario does survives it; there is no
teardown to get wrong. `lab.sh` gains a `replay <scenario>` command that does this, checks the scan against
`expect.yaml`, and prints one line per rule.

### 2. What a scenario may put on the machine

A scenario reproduces the **trace**, never the thing that leaves it:

- Windows' own settings changed the way an administrator would change them;
- files and folders created with the names, places and shapes a rule looks for, containing inert content
  (an empty or harmless test program built from this repository);
- Windows' own log and history entries produced by running ordinary commands.

A scenario never contains or downloads a cheat, a loader, malware, a vulnerable driver, or anything from a
cheat seller, and the virtual machine has no network during a run. A rule that can only be shown by
installing such a thing is not replayed; §5 says what happens to it.

### 3. What a scenario never does

Within the purpose boundary in `AGENTS.md`, a scenario only shows that a trace **is found**. It never
tests whether a trace can be removed, hidden, forged or made to read as clean. When a scenario fails — the
rule reads `not_found` where `expect.yaml` says `found` — that is a false negative and gets an issue
describing the rule and the Windows build, not how the trace was avoided. If a failure shows a way a real
cheat could avoid a rule, it goes through `SECURITY.md`'s private reporting instead, as every bypass does.

### 4. The result goes into the ledger

A passing scenario adds ledger rows (ADR 0074 §1) — `lab-vm-arm64`, the build, `found` for each expected
rule, `not_found` for each neighbour — with `evidence` set to the scenario path and the run date. The raw
scan stays with the maintainer; the virtual machine belongs to no person, but the report holds paths and
times that the ledger does not need.

### 5. Rules that cannot be replayed

A rule whose trace needs a forbidden thing (§2) — for example the vulnerable-driver hash list, whose match
is a driver file's hash — is listed in `rules/not-replayable.csv` with the reason, one row per rule, added
only with the owner's yes. For such a rule ADR 0074 §5's "seen found on a lab machine" is replaced by the
row and by the provenance of its list.

### 6. Order of work

1. `lab.sh replay` with overlays, and the scenario format — no scenario yet.
2. A first batch of five scenarios, one per collector, from the collectors whose trace is a Windows setting
   or a file shape: `defender_exclusion`, `net_config`, `autostart`, `evtx` (a log-clearing event on the
   machine's own log), `fivem_dir`.
3. Further batches by the coverage table's gap list, oldest gap first.

Scenarios and their results feed the next step later: a fixture host generated from a real collector run
(`fixtures/hosts/PROVENANCE.md`, "generated from a real Windows install") closes the gap between fixtures
and collectors. That is its own decision and is not made here.

## What this does not do

- It does not test any machine but the lab's own virtual machine.
- It does not measure x64, Windows 10 or a GitHub runner; the lab is Windows 11 on Arm (ADR 0069). A
  rule whose source differs on x64 still needs `owner-pc` or a runner for its client-build column.
- It does not change any rule, collector or report.

## Alternatives weighed

- **Replay on GitHub's Windows runners.** Not now: they are x64 and throwaway, which helps, but they are
  Windows Server and their logs are public in this repository; a scenario's output would need the same care
  as a fixture. Revisit after the first batch.
- **Replay on the owner's own PC.** Rejected: a scenario changes system settings, and the owner's PC is not
  throwaway.
- **Write more fixtures instead.** Rejected as a substitute: a fixture states what a collector emits; a
  replay shows it.

## What is unverified

- How long one replay takes. A step waits 60 seconds after logon before its setup (`lab.sh`) and is cut off
  at 30 minutes; the time from boot to power-off was not recorded for the ADR 0069 steps.
- Whether a fresh overlay boots as fast as the base disk, and whether Windows' first-boot work on an
  overlay changes what a scan sees (expected not, since the base is already installed).
- Whether every collector in the first batch reads the same on Arm as on x64.

## Questions for the owner

1. Scenarios live in this public repository (`lab/scenarios/`), or stay in the maintainer's untracked
   notes like the lab today?
2. `rules/not-replayable.csv` (§5): accept it as the way hash-list rules reach `stable`?
3. The first batch of five in §6.2: these five, or others?
4. GitHub runners as a second replay target after the first batch (Alternatives): yes or not yet?
