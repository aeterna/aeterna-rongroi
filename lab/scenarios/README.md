# Scenarios

One folder per scenario, under the collector it is about: `lab/scenarios/<collector>/<name>/`. A scenario
puts **one trace** on the lab virtual machine and says which rules must read it
([ADR 0076](../../docs/adr/0076-lab-replay.md) §1). Scenarios for the game-window view, which is not a rule,
live under `lab/scenarios/game_windows/<name>/` (ADR 0076, "Amendment (2026-10-27)").

| File | What it holds |
|---|---|
| `setup.ps1` | puts the trace in place; runs elevated as the lab's local account, 60 seconds after logon |
| `expect.yaml` | which rules must read `found`, which neighbours must stay `not_found`, whether a restart is needed |
| `README.md` | what the trace stands for in the real world, and what the scenario does not show |

## `expect.yaml`

```yaml
found:                 # at least one rule id; each must read `found`
  - 00000000-0000-4000-8000-000000000000
not_found:             # optional; neighbouring rules that must stay `not_found`
  - 00000000-0000-4000-8000-000000000001
restart: false         # optional; true restarts Windows once between setup.ps1 and the scan
full: false            # optional; true makes the scan a full scan, and replay answers its question with yes
game_windows:          # optional; the game-window view must exist and hold each candidate listed
  - name: helper.exe   # a candidate's file name, without ASCII case
    facts:             # only the facts listed are checked: t1-t4, i1-i5, l1
      t1: true         # true | false | not_known | not_known:<reason>
clock_changed: false   # optional; true means the view's clock line lists at least one change
```

`found` may be empty when `game_windows` or `clock_changed` is given. A game-window scenario makes its session
with an inert `FiveM.exe` (a copy of Windows' `ping.exe` in `%LOCALAPPDATA%\FiveM\`) that is still running when
the scan reads, because the lab machine's Prefetch does not record it; only the window before the session can
be shown. `lab-check` writes ledger rows for rules only; a game-window result goes into ADR 0078 "As built: P7".

Rule ids are the `id` in each `rule.yaml`. `cargo xtask lab-check` refuses an unknown field, an empty
`found` with neither `game_windows` nor `clock_changed`, an id listed twice, and an id that is not in the rules bundle. Set `restart: true` only for a
setting Windows reads at boot, such as test signing.

## What `setup.ps1` may do (ADR 0076 §2)

- change Windows' own settings the way an administrator would;
- create files and folders with the names, places and shapes a rule looks for, with inert content;
- run ordinary Windows commands so that Windows writes its own log and history entries.

It never contains or downloads a cheat, a loader, malware, a vulnerable driver or anything from a cheat
seller, and the machine has no network. It never removes, hides or forges a trace, and never tests whether
that can be done (ADR 0076 §3). A rule that cannot be shown without a forbidden thing goes in
`rules/not-replayable.csv` with the owner's yes (§5), not here.

There is no teardown: the disk is a throwaway overlay.

## Before a pull request

1. Run `lab/replay.sh control` for the batch and keep its `scan.json`.
2. Run the scenario with `RONGROI_LAB_CONTROL` set; every line must be `ok`.
3. Add the ledger rows `lab-check --evidence … --date …` prints to `rules/measured.csv`, then run
   `cargo xtask coverage`.
4. Review `setup.ps1` against the list above as you would a fixture.
