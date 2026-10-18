# Lab replay

Shows that a rule reads a trace that is really on a Windows machine, not only in a fixture
([ADR 0076](../docs/adr/0076-lab-replay.md)). A passing replay adds rows to the measurement ledger
`rules/measured.csv` ([ADR 0074](../docs/adr/0074-a-coverage-table-for-the-rules.md)), which is what
`stable` needs.

A replay never runs on anyone's PC. It runs on the maintainer's Windows 11 Arm virtual machine
([ADR 0069](../docs/adr/0069-device-inventory-source.md)), booted from a throwaway copy of its
disk with no network, and the copy is deleted after the scan.

## What is here

| Path | What it is |
|---|---|
| `replay.sh` | boots the virtual machine from an overlay, runs one scenario, scans, checks the scan |
| `scenarios/` | one folder per scenario; the format is in [`scenarios/README.md`](scenarios/README.md) |

What builds the virtual machine (the Windows answer file with its throwaway local account, the ISO, the
logon task that runs `run.ps1` from the share disk) stays with the maintainer and is not in this
repository (ADR 0076, owner decision 1). `replay.sh` takes the machine's folder from `RONGROI_LAB`.

## Running

```bash
export RONGROI_LAB=/Volumes/WD1TB/aeterna-vm.noindex/rongroi-dma-lab   # the maintainer's folder
lab/replay.sh control                                                    # once per batch
export RONGROI_LAB_CONTROL="$RONGROI_LAB/replay/<control run>/results/scan.json"
lab/replay.sh lab/scenarios/<collector>/<name>
```

`replay.sh` prints `VM off after <n>s` and then one line per rule from `cargo xtask lab-check`. The raw
scan stays in `$RONGROI_LAB/replay/<run>/results/`, outside the repository: the virtual machine belongs to
no person, but a report holds paths and times the ledger does not need (ADR 0076 §4).

When every line is `ok`, the ledger rows come from the same command with `--evidence` and `--date`:

```bash
cargo xtask lab-check --expect lab/scenarios/<collector>/<name>/expect.yaml \
  --scan "$RONGROI_LAB/replay/<run>/results/scan.json" --control "$RONGROI_LAB_CONTROL" \
  --evidence "lab/scenarios/<collector>/<name> (run <run>)" --date 2026-10-18
```

Append them to `rules/measured.csv`, run `cargo xtask coverage`, and open a pull request.

## When a scenario fails

- A rule reads `not_found` where `expect.yaml` says `found`: a false negative. Open an issue naming the
  rule and the Windows build, not how the trace was avoided (ADR 0076 §3).
- A neighbour reads `found`: the rule fires too widely. Open an issue.
- The control scan already reads `found`: the trace belongs to the machine, not the scenario. Rewrite the
  scenario or leave that rule out of it.
- Anything that shows a way a real cheat could avoid a rule goes to [`SECURITY.md`](../SECURITY.md)'s
  private reporting, never into an issue, a pull request or this folder.
