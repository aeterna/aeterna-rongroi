# ADR 0076 — Lab replay: showing a rule fires on a real Windows

- Status: accepted — drafted 2026-10-18 at the owner's request, as the validation ("red") half of the
  detection-validation programme of ADR 0074 and ADR 0075; the owner answered its four questions the same
  day (Owner decisions, at the end). Nothing here is built yet.
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

The four rules seen `found` on `lab-vm-arm64` came from the ADR 0070 and ADR 0072 lab steps, which emulated
a device. Three of them — `pci_device/absent/not-present`, `pci_device/no-driver/problem-28`,
`hid_device/absent/not-present` — already show all three conditions of ADR 0074 §5 in `docs/coverage.md`
(confronted, seen found on the lab machine, measured on a client build); the fourth is a timeline selector.
Promoting them is its own change and does not wait for this ADR.

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
teardown to get wrong. A `replay <scenario>` command does this, checks the scan against `expect.yaml`, and
prints one line per rule.

**A control scan.** The lab machine is not an ordinary PC: a virtual machine on Arm may already read
`found` for some rules with no scenario at all (no IOMMU table, memory integrity off). Each batch therefore
starts with one scan of a fresh overlay with no `setup.ps1`. A scenario passes only if every rule it
expects `found` reads `not_found` in that control scan; otherwise the `found` belongs to the machine, not to
the scenario, and the scenario is rewritten or the rule is left out of it.

**One restart.** A setting that Windows reads only at boot (for example test signing) cannot be shown by a
scan in the same session as its setup. `expect.yaml` may ask for one restart between `setup.ps1` and the
scan; nothing else changes.

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

1. The `replay` command with overlays, the control scan, and the scenario format — no scenario yet. One
   replay of an empty scenario is timed before the first batch (What is unverified).
2. A first batch of five scenarios, one per collector, whose trace is a Windows setting or a file shape:
   `defender_exclusion`, `autostart`, `evtx` (a log file set read-only, and a log-clearing event on the
   machine's own log), `net_config`, `posture` (the two script block logging policies). Owner decision 3
   moved `fivem_dir` to the second batch and added `posture`.
3. Further batches by the coverage table's gap list, oldest gap first; `fivem_dir` first.

Not every rule in the first batch can reach `stable` after it. Read from `docs/coverage.md` on 2026-10-18:
the `posture` logging rules and `evtx/log-file/event-log-file-read-only` are `confronted`, so a pass gives
them all three conditions. `defender_exclusion/fivem/fivem-folder-excluded` and
`autostart/outside-windows/no-valid-embedded-signature` read `known fp`, and
`net_config/hosts/fivem-or-rockstar-name-in-hosts` and the log-clearing rules are `unconfronted`; a pass
adds their ledger rows but leaves the first condition open.

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

- Whether Windows' first-boot work on an overlay changes what a scan sees (expected not, since the base is
  already installed). Two control scans agreed with each other (as built, below); neither was compared
  with a scan of the base disk itself.
- Whether every collector in the first batch reads the same on Arm as on x64.

## As built (2026-10-18)

`lab/replay.sh` and `cargo xtask lab-check` (§1, §4). Two control replays on the lab machine, with the
rongroi build of 2026-10-17 (rules bundle `944035a4…`, 77 rules):

- **Time.** 110 and 111 seconds from boot to power-off, the 60-second wait after logon included. A batch
  of five scenarios plus its control is about ten minutes, not the hours the 30-minute limit allowed for.
- **The control scan earns its place.** With no scenario, three rules already read `found`:
  `hid_device/absent/not-present` and `pci_device/absent/not-present`, because the installed disk
  remembers the devices the ADR 0070 and ADR 0072 steps emulated, and `posture/tpm/tpm-absent`, because
  the machine has no TPM (`tpm-tis-device` fails under the Mac's hypervisor). A scenario can never be
  credited with these; 35 rules read `not_found` and 22 `unmeasured`.
- **Encoding.** Windows PowerShell 5.1 rewrites a redirected program's output as UTF-16LE. The first control
  scan came back that way; `run.ps1` now lets `cmd` do the redirect, so `scan.json` holds the bytes the
  program wrote, and the second came back as UTF-8.

**First batch (2026-10-18).** Seven scenarios, one trace each, all passing against one control replay with a
build of `dev` at `2d0c11d` (rules bundle `42ed5dca…`): the two machine policies that turn script block logging
off, a Defender exclusion of FiveM's folder, an unsigned program in the profile's Run key, an event log file set
read-only, the Application log cleared (with one restart), and a FiveM name in the hosts file. Their 15 ledger
rows raised the rules seen `found` outside a fixture from 10 to 16, and three of them then met §5 of ADR 0074 and
became `stable`. One lesson: an unchanged copy of the running program is the tool's own trace (ADR 0010) and
never reaches a rule, so a scenario that needs an inert program changes the copy's bytes.

The build the virtual machine runs is the maintainer's `cli.exe`. Ledger rows from a replay are only as
current as that build's rules bundle, whose hash every scan carries in `header.rules_bundle`.

## Owner decisions (2026-10-18)

1. **Scenarios are public**, in `lab/scenarios/`, and so is the `replay` command, which takes the virtual
   machine's location from the environment rather than a path on one maintainer's machine. What builds the
   virtual machine (the answer file, with its throwaway local account, and the ISO) stays with the
   maintainer. A scenario is reviewed against §2 and §3 the way a fixture is.
2. **`rules/not-replayable.csv` is accepted** (§5): one row per rule, each added with the owner's yes and
   naming where the rule's list comes from.
3. **The first batch** is `defender_exclusion`, `autostart`, `evtx`, `net_config` and `posture` (§6.2);
   `fivem_dir`, most of whose rules are `unconfronted`, moves to the second batch.
4. **GitHub runners: not yet.** Revisit after the first batch (Alternatives).

## Amendment (2026-10-27): scenarios for the game-window view (ADR 0078 step P7)

ADR 0078 step P7 asks lab replay to show the game-window view's facts on a real Windows. That view is not a
rule: it has no id and no `found`. This amendment extends the scenario format for it. The owner decided the
shape on 2026-10-27 (ADR 0078, "P7 decisions").

**What four probes on the lab machine showed** (2026-10-27, build of `dev` at `508ab46`, not kept in this
repository):

- Prefetch wrote no file for a program named `FiveM.exe` under `%LOCALAPPDATA%\FiveM\`, whether it was an
  Arm64 copy of a Windows program or the x64 build of this repository under emulation, run at once after
  sign-in or four minutes later. Prefetch was on (`EnablePrefetcher` 3) and wrote files for other programs in
  the same minutes. Why it skipped this one was not established.
- BAM recorded both copies. A session's start comes from Prefetch or from a running process (ADR 0062), so a
  session that has ended has no start on this machine, and the view is not computed.
- With the inert `FiveM.exe` still running when the scan reads, the session has a start (the process) and
  no end ("still running"), and the view is computed: 55 candidates, all in the window before the session.
  Only that window can be shown here; the windows during and after a session, and before the scan, need an
  end, which this machine does not leave.

**1. Where game-window scenarios live.** `lab/scenarios/game_windows/<name>/`. `game_windows` names the view,
not a collector; it is the one folder under `lab/scenarios/` that is not a collector's.

**2. How a scenario makes a session.** `setup.ps1` copies Windows' own `ping.exe` to
`%LOCALAPPDATA%\FiveM\FiveM.exe` and starts it so that it is still running when the scan reads, as a player's
game is during a screenshare. It is inert: it pings this machine, which has no network. A scenario puts its
own trace in place before that start, so the trace falls in the window before the session.

**3. Three new fields in `expect.yaml`**, each optional:

```yaml
full: true                 # the scan is a full scan; replay answers the consent question with `yes`
game_windows:              # the view must exist, and hold each candidate below
  - name: helper.exe       # a candidate's file name, compared without ASCII case
    facts:                 # only the facts listed are checked
      t1: true             # true | false | not_known | not_known:<reason>
      i1: not_known:no_path
clock_changed: true        # the view's clock line lists at least one change
```

- `found` may be empty when `game_windows` or `clock_changed` is given; a scenario still expects something.
- A fact key is one of `t1`–`t4`, `i1`–`i5` and `l1`, as the view names them. `not_known:<reason>` is the
  view's reason word (`no_path`, `recorded_files_not_run`, …). An unknown key, value or reason is refused, as
  an unknown field is.
- Candidate checks run on the scenario's scan only. The control scan has no running `FiveM.exe`, so it has no
  view to compare with; a candidate the control would also hold is the machine's, and a scenario names only
  a candidate its own `setup.ps1` made.

**4. The ledger.** `rules/measured.csv` is one row per rule (ADR 0074 §1), and a view result is not a rule.
`lab-check` prints ledger rows for `found` and `not_found` rules only. A game-window result is recorded in
ADR 0078 "As built: P7", with the replay run and the build's bundle hash.

**5. What `replay.sh` changes.** With `full: true` it runs `rongroi.exe scan --full --json` and answers the
consent question with `yes` on standard input; without it, nothing changes. The question still runs, as it
must for any full scan (ADR 0052); only the answer is given by the script, on a machine that belongs to no
person.

**6. What these scenarios do not show.** The windows after a session and before the scan; anything that
needs Prefetch to record the game or another program, such as fact L1 (Prefetch's loaded-file list), so the
scenario of a DLL appended to an image and loaded by `rundll32.exe` is not written (ADR 0078, "P7
decisions", item 2; it is not a rule, so `rules/not-replayable.csv` has no row for it); and identity facts
for a program known only from BAM or Prefetch, whose paths are not drive-rooted (ADR 0078, "P7 decisions",
item 3).
