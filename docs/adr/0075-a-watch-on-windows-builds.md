# ADR 0075 — A watch on Windows builds

- Status: proposed — drafted 2026-10-18 at the owner's request, as the second half of a detection-validation
  programme beside ADR 0074; the owner's questions are at the end. Nothing here is built yet.
  Owner decided 2026-10-18: weekly (§1); no Windows 10 lab machine for now (§2); the monthly read is a
  delegated read-only run, checked by a maintainer (§3).
- Date: 2026-10-18
- Related: ADR 0074 (the ledger this writes into), ADR 0003 (offline), ADR 0048 (a runner image's data
  belongs to no person), `.github/workflows/certificate-pins.yml` (the scheduled-check pattern this follows)

## Context

Every collector reads something Windows can change in an update, and several already depend on the
version:

- `pca` reads files that exist only from Windows 11 22H2 (build 22621) and says `not_on_this_os` before it
  (ADR 0020, ADR 0030).
- `bam`'s value layout is documented for Windows 10 builds only (ADR 0023).
- From 24H2, `EnumDeviceDrivers` needs `SeDebugPrivilege` (ADR 0046).
- `ProductName` says "Windows 10 Home" on a Windows 11 25H2 PC (ADR 0056).
- Fast Startup changes what `pci_device` and `windows_start` report (ADR 0069, ADR 0071).

Today a real Windows machine runs this program in three situations, and none of them is triggered by
Windows changing:

| Where | When it runs | Build today |
|---|---|---|
| `windows.yml` job `windows-live` on `windows-latest` | a pull request that changes code; skipped on pushes to `dev` and `main`, on `dev`→`main` pull requests and on pull requests that change only docs (`windows.yml`, step "scope") | Windows Server 2025, 26100 |
| the owner's own PC | the GUI check of each release (GOVERNANCE "How to release", step 5) and one-off probes | Windows 11 25H2, 26220 |
| the ADR 0069 virtual machine | one-off measurements | Windows 11 Arm, 26300 |

So when GitHub moves `windows-latest` to a new image, or a Windows feature update changes a source, the
first sign is a red pull request about something else, or a report from a reviewer. The live smoke step
prints every rule's state (`windows.yml`, "Live smoke — the CLI reads this machine") but asserts none,
and nothing compares one run's states to the last.

## Decision

### 1. A scheduled workflow on GitHub's Windows images: `windows-watch.yml`

- Runs weekly (owner's choice: GitHub updates its images more often than monthly, and a month of
  changes in one comparison cannot be told apart) and on `workflow_dispatch`, never on `pull_request` or `push`, and is never a required
  check — the reason `certificate-pins.yml` gives: a calendar must not turn someone's pull request red.
- A matrix over the Windows images GitHub offers by label (`windows-latest` is today image
  `windows-2025-vs2026`, ADR 0060; the other labels on offer are to be read from GitHub's runner-images
  list when this is built). The list is edited in the workflow when GitHub adds or retires one.
- Each job builds the CLI, runs `scan --json` elevated, and reduces the report to a **shape**:
  `os_build`, then for every rule its state and reason, and for every collector its state and the set of
  field names its observations carried. No field value, no path, no count of observations — a count
  changes from run to run on the same image and would make every week a diff.
- The shape is compared with a committed file, `fixtures/watch/<image>.json`. The same shape passes. A
  different shape fails the job and prints the difference; the maintainer then commits the new shape in a
  pull request that says what changed and why (a new build, a collector change, a real regression).
- A passing run on a new `os_build` adds the collector rows of ADR 0074's ledger for that build, in the
  same kind of pull request. The workflow itself only reads; it has `contents: read` and opens nothing.

A runner image is a machine set up by GitHub and used by no person, so its shape can be committed, as
ADR 0048 already does for its drivers.

### 2. Client Windows, on the machines the owner already uses

GitHub's images are Windows Server. A player runs Home or Pro. Two existing steps cover client builds
without new infrastructure:

- The release GUI check on the owner's PC already runs the official build there. It also writes the
  ledger rows for that build: `os_build`, `token`, and the state of each collector. When the owner's PC
  takes a feature update, the next release check is the first measurement on it.
- The ADR 0069 virtual machine is used when a question needs a fresh install, a Fast Startup case or a
  different build, as it is now.

Neither is scheduled.

No Windows 10 lab machine is set up now (owner decision): this Mac runs Windows 10 x64 only slowly, and an
Arm build of Windows 10 is hard to obtain. ADR 0074's table lists "never measured on Windows 10" as a gap
for every collector, so the cost is visible — chiefly the rules whose source differs by version (`bam`,
`pca`). A Windows 10 measurement becomes its own piece of work when a reviewer reports from Windows 10, or
when it is shown that players on Windows 10 are many.

### 3. A monthly read of what Microsoft changed

Once a month, a read-only delegated run (`aeterna-delegate`, read mode, organisation standard §10) reads Windows release notes for changes to what the collectors read: event
log channels, Defender and Code Integrity events, the PCA and Prefetch folders, BAM, the vulnerable driver
blocklist, device enumeration, Secure Boot and firmware. Its output is unverified until a maintainer has
checked each claim against the source it cites (§10.4); only then is it recorded. The result is one line in `docs/research/` per
month: "nothing that touches a collector", or a link to the issue or ADR amendment it led to.

No program in this repository fetches those notes. ADR 0003 is about this program's code; keeping the
read outside it keeps that claim simple to check.

## What this does not do

- It does not measure a player's machine, and it does not add any data to a report.
- It does not decide whether a changed shape is a bug. A person reads the difference.
- It does not follow Windows Insider builds. They change weekly and players are rarely on them.

## Alternatives weighed

- **Run the watch on every push to `dev`.** Rejected: the organisation standard §11.2 removed exactly
  these repeat runs, and a push is not when Windows changes.
- **Assert rule outcomes in the existing live smoke.** Rejected for the pull-request job: a runner image
  change would then fail unrelated pull requests. The weekly job is where that comparison belongs.
- **Fetch Microsoft's release-health pages in CI and diff them.** Rejected: the pages are HTML with no
  stable format, and a page change is not a collector change. A monthly human read is cheaper than
  maintaining a scraper.
- **A self-hosted runner on a client Windows PC.** Rejected for now: the organisation's self-hosted runners
  are WSL on the owner's PC and are not offered to this repository, and a public repository should not
  run pull-request code on a personal machine.

## What is unverified

- The cost. GitHub's documentation says standard runners are free for public repositories; that was not
  checked for this repository's plan. One `windows-live` job takes about 30 minutes today (`rust (windows)`
  on pull request 184), so two images weekly is roughly an hour of Windows time a week, not measured.
- Whether the shape is stable from week to week on one image. If an Event Log channel or a driver appears
  and disappears between runs, the shape needs to leave that collector's field set out; to be measured
  with the first two or three runs, during which the job reports a difference without failing.
- GitHub may delay or drop a scheduled run, and disables schedules in a public repository after 60 days
  without activity (as `certificate-pins.yml` notes).

## Questions for the owner

Decided 2026-10-18: weekly; no Windows 10 lab machine for now; the monthly read is delegated and checked.

1. May the release GUI check on your PC write ledger rows (build and collector states, no values) into
   the public repository?
