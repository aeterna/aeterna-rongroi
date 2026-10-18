# Scenarios

One folder per scenario, under the collector it is about: `lab/scenarios/<collector>/<name>/`. A scenario
puts **one trace** on the lab virtual machine and says which rules must read it
([ADR 0076](../../docs/adr/0076-lab-replay.md) §1).

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
```

Rule ids are the `id` in each `rule.yaml`. `cargo xtask lab-check` refuses an unknown field, an empty
`found`, an id listed twice, and an id that is not in the rules bundle. Set `restart: true` only for a
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
