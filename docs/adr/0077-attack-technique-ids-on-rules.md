# ADR 0077 — ATT&CK technique ids on rules

- Status: accepted — the owner accepted the three choices in "Owner decisions" on 2026-10-18, from the
  detection-validation plan that followed `docs/research/07-red-team-and-detection-validation.md`; nothing
  is built yet
- Date: 2026-10-18
- Related: ADR 0074 (the coverage table), ADR 0076 (lab replay), ADR 0027 (what the reader is shown),
  `docs/research/07-red-team-and-detection-validation.md` ("The gap this makes obvious")

## Context

MITRE ATT&CK is the common language of detection work: a rule, an emulation test and a threat report
cross-walk through the same technique id. Research note 07 found that no rule here carries one, so the
coverage table cannot be read against the standard matrix, and a scenario (ADR 0076) cannot point to the
Atomic Red Team test for the same technique.

Three things, read on attack.mitre.org on 2026-10-18, shape the decision:

- **The ids move.** ATT&CK v20.0 was released 2026-10-13 (the versions page). Since v19 there is a
  *Defense Impairment* tactic (TA0112, created 2026-04-14), and techniques this project would name have new
  ids there: *Clear Windows Event Logs* is `T1685.005`, *Disable or Modify Windows Event Log* is
  `T1685.001`, *Windows Host Firewall* is `T1686.003`. *Indicator Removal* (`T1070`, tactic *Stealth*,
  TA0005) no longer lists `T1070.001`. An id copied from an older article can therefore be wrong today. That
  older ids were moved rather than removed is inferred from these pages; the v19 changelog was not read.
- **ATT&CK describes intrusions, not game cheating.** Many collectors read a trace with a close technique
  (log clearing, defence tools turned off, autostart, DMA hardware). Others have none: a file in the FiveM
  folder, a server list, the marker a modified Windows build leaves.
- **Terms of use.** MITRE grants use of ATT&CK, commercial use included, provided copies keep its
  copyright notice ("© 2026 The MITRE Corporation. This work is reproduced and distributed with the
  permission of The MITRE Corporation.").

## Decision

### 1. A field `attack`, separate from `tags`

`rule.yaml` gains an optional field `attack`: a list of technique or sub-technique ids (`T1685.005`,
`T1200`). It is not a tag. `tags` stay the project's own group names (`[posture, logging]`), and an export
to Sigma later turns each id into Sigma's `attack.t1685.005` form.

The id is metadata for maintainers and for the coverage table. It changes no match, and it is not shown in
a report. Showing it to a reader would be its own decision under ADR 0027.

### 2. An empty list is allowed and explained

A rule with no technique that fits writes `attack: []` and `attack_note`, one sentence saying why. A rule
without the field is not yet mapped. `check-rules` refuses `attack: []` without `attack_note`, and an
`attack_note` beside a non-empty list. A close-enough id is worse than none: the coverage table would then
claim a technique the rule does not read.

### 3. One pinned version, kept in the repository

`rules/attack/techniques.csv` holds the id and name of every Enterprise technique and sub-technique of
one ATT&CK version, with that version and MITRE's notice in `rules/attack/PROVENANCE.md` and a `REUSE.toml`
annotation. `check-rules` refuses an id that is not in the file. Nothing is fetched at build or scan time
(ADR 0003).

When MITRE releases a new version (twice a year so far), one pull request replaces the file. Any rule whose
id is gone then fails `check-rules`, and that pull request maps it again. The first file is v20.0.

### 4. The coverage table counts techniques

`cargo xtask coverage` adds a column `attack` to each rule row and a section listing each technique with
its rules and, from the ledger, whether any of them was seen `found`. As in ADR 0074 §3, it shows counts
and lists, never a percentage of the matrix: most of the matrix (cloud, mail, identity) has nothing to do
with a PC check, so a percentage would mislead.

An ATT&CK Navigator layer file is not generated now (owner decision 3).

## Order of work

1. The field, the CSV with its provenance and licence annotation, the `check-rules` checks, the coverage
   column and section, and `docs/rules-authoring.md` — no rule mapped yet.
2. The mapping, one pull request per collector. A maintainer checks every id against its page at the
   pinned version before it is merged.

A first reading of the mapping, to be judged rule by rule in step 2, not decided here. Names were read
on attack.mitre.org or in Atomic Red Team's Windows index on 2026-10-18; "fit" is this ADR's reading.

| Collector or rules | Technique at v20.0 | Fit |
|---|---|---|
| `evtx` log clearing | `T1685.005` Clear Windows Event Logs | close |
| `posture` script block logging off by policy | `T1685.001` Disable or Modify Windows Event Log | close |
| `evtx` log file read-only or moved | `T1685.001` | to judge |
| `defender_exclusion`, `evtx` Defender real-time protection off | `T1685` Disable or Modify Tools | close |
| `net_config` firewall | `T1686.003` Windows Host Firewall | close |
| `net_config` hosts file | none found | `[]` |
| `posture` test signing | `T1553.006` Code Signing Policy Modification | close |
| `posture` Secure Boot, memory integrity, mitigations | to judge | to judge |
| `autostart` | `T1547.001`, `T1053.005`, `T1543.003` | close |
| `driver_service` vulnerable driver list | `T1068` Exploitation for Privilege Escalation, or `T1687` Exploitation for Defense Impairment | to judge |
| `pci_device`, `hid_device` | `T1200` Hardware Additions (its text names DMA) | close |
| `usn` journal deleted | `T1070` Indicator Removal; no sub-technique fits | to judge |
| `powershell_text` | `T1059.001` PowerShell | close |
| `prefetch`, `bam`, `pca` | none: they show a program ran, which ATT&CK treats as a data source | `[]` |
| `fivem_dir`, `fivem_servers`, `install_marker`, `os_image`, `windows_start` | none: specific to the game or context only | `[]` |

## What this does not do

- It does not change any match, status or report.
- It does not run Atomic Red Team tests. A scenario may name the Atomic test for its technique as a
  reference. It never runs one, because some tests download a payload, which ADR 0076 §2 forbids.
- It does not claim coverage of ATT&CK. A technique with a rule means only that a trace of it is read.

## Alternatives weighed

- **Ids in `tags`, Sigma style.** Rejected (owner decision 1): `tags` are free group names, and mixing
  the two makes both harder to check and count.
- **An id on every rule.** Rejected (owner decision 2): it forces a wrong id on the rules ATT&CK does not
  describe.
- **Fetch the matrix in CI.** Rejected: a build would then depend on the network and on a page that
  changes, and a new version would fail unrelated pull requests. The pinned file changes only when a pull
  request changes it.

## What is unverified

- The exact old-to-new id pairs of the v19 restructuring. The v19.2 to v20.0 changelog was read in part.
  The v19 changelog was not read.
- Whether MITRE's notice must appear in the CSV itself, or whether `PROVENANCE.md` beside it is enough.
  Step 1 reads the terms of use again for this.
- The fit of every row marked "to judge" above.

## Owner decisions (2026-10-18)

1. A separate field `attack`, not ids inside `tags` (§1).
2. `attack: []` is allowed, with `attack_note` saying why (§2).
3. Pin the ATT&CK version now, and leave the Navigator layer for later (§3, §4).
