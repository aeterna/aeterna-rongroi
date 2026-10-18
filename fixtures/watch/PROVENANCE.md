<!-- SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# fixtures/watch — the committed shape of each Windows runner label

`.github/workflows/windows-watch.yml` (ADR 0075 §1) compares each week's scan of a GitHub Windows runner
with `<label>.json` here. A file holds the shape of one report: `os_build`, every rule's state (and its
reason when unmeasured), and every collector's state with the sorted names of the fields its observations
carried. It holds no field value, no path and no count. A runner image is a machine set up by GitHub and
used by no person (ADR 0048).

A file changes only in a pull request that says what changed and why — a new build, a collector change,
or a real regression — and names the run whose artifact it was copied from.

## Where each file came from

| File | Run | Commit | Image (`ImageOS` `ImageVersion`) | `os_build` |
|---|---|---|---|---|
| `windows-latest.json` | [39107233878](https://github.com/aeterna/aeterna-rongroi/actions/runs/39107233878), artifact `windows-watch-windows-latest` | `a15bd10` | win25-vs2026 20261007.264.1 | 26100 |
| `windows-2022.json` | 39107233878, artifact `windows-watch-windows-2022` | `a15bd10` | win22 20261012.333.1 | 20348 |
| `windows-11-arm.json` | 39107233878, artifact `windows-watch-windows-11-arm` | `a15bd10` | win11-vs2026-arm64 20261013.183.4 | 26200 |
| `windows-11-vs2026-arm.json` | 39107233878, artifact `windows-watch-windows-11-vs2026-arm` | `a15bd10` | win11-vs2026-arm64 20261013.183.4 | 26200 |

Run 39107233878 was started by a temporary `push` trigger on branch `ci/windows-watch`, removed before
merge: `workflow_dispatch` cannot start a workflow that is not yet on the default branch. The files are the
artifacts byte for byte.

Until two or three scheduled runs have compared against these files (report-only phase,
`WATCH_FAIL_ON_DIFFERENCE: "false"`), a difference is printed and does not fail the job; a field set that
comes and goes between runs on one image is to be left out of the shape before failure is turned on.
