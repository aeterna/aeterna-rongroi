# ADR 0048 — The `driver_service` collector and the vulnerable-driver rule

- Status: accepted
- Date: 2026-09-15

## Context

ADR 0046 decided what a vulnerable-driver check reads and compares: registered driver services in the
registry, the SHA-256 of each driver's file, LOLDrivers' `vulnerable driver` category, strength `posture`,
every driver service emitted, the rule naming a data file that the bundle build expands. It left five
things to the collector's own ADR, and measured what they rest on, on a GitHub-hosted runner and on a
Windows 11 PC ("Measured on a runner", "Measured on a PC", "The data file, counted"):

1. how an `ImagePath` becomes a file;
2. the budget;
3. whether an unverified LOLDrivers entry is in the data file;
4. how the matched LOLDrivers entry reaches the reader;
5. what an observation carries.

The owner decided 1, 3, 4 and 5 on 2026-09-15, each as recommended here. The rest follows from ADR 0046
and from the collectors already in this repository.

Nothing here reads a loaded module, an Authenticode hash or Microsoft's blocklist switch. ADR 0046 gave
each of those its own ADR.

## Decision

### The collector

Id `driver_service`: one observation is one driver service, the way one `process` observation is one
process. It is not `drivers`, because it does not see which drivers are loaded (ADR 0046, Question 2), and
the name should not say it does.

It lists the keys directly under `HKLM\SYSTEM\CurrentControlSet\Services` with `RegistrySource::subkeys`,
reads `Type` in each, and keeps the services whose `Type` is `1` (`SERVICE_KERNEL_DRIVER`) or `2`
(`SERVICE_FILE_SYSTEM_DRIVER`). For each it reads `ImagePath` and `Start` with `RegistrySource::read_value`,
resolves the file and hashes it with `FilesystemSource::file_sha256`. No new Windows API, no new `windows`
feature and no new crate (ADR 0046).

It needs no administrator rights: on both machines measured, a token without Administrators read every
key and hashed every file. It never reports `not_admin`.

### The observation

| Field | Kind | Value |
|---|---|---|
| `service` | text | The service's key name |
| `path` | text | The resolved file, in drive-letter form. Absent when the `ImagePath` form is not one below |
| `sha256` | text | Lowercase hex of the file. Absent when the file was not hashed |
| `start` | number | `Start` as stored: 0 boot, 1 system, 2 automatic, 3 on demand, 4 disabled. Absent when there is none |

`start` is there for the reader, not the rule. A `found` row on a driver whose `Start` is `4` is a driver
Windows will not load, and a reader who can see that does not have to ask. The rule matches on `sha256`
alone, so `start` changes no result. The owner chose it over the three fields ADR 0046 named.

`Type` is not a field: every observation already has `Type` 1 or 2, and which of the two says nothing a
reader or the rule uses.

### The resolver

Decided by the owner: **every relative `ImagePath` is read as relative to `%SystemRoot%`.**

| `ImagePath` | File |
|---|---|
| absent or empty | `%SystemRoot%\System32\drivers\<service>.sys` |
| `\SystemRoot\<rest>` | `%SystemRoot%\<rest>` |
| `\??\<drive letter>:\<rest>` | `<drive letter>:\<rest>` |
| `<drive letter>:\<rest>` | as written |
| relative: no leading `\`, no drive letter, no `%` | `%SystemRoot%\<ImagePath>` |
| anything else: `%…%`, a quoted path, `\??\` without a drive letter, a UNC path | none |

`%SystemRoot%` is the environment variable, read with `EnvironmentSource::env_var`. An `ImagePath` is
`REG_EXPAND_SZ` on both machines measured, and this program does not expand it: `\SystemRoot\` is the only
variable-like prefix measured, and it is matched literally.

What it rests on:

- The absent case: on both machines every driver service without an `ImagePath` had that file, and on the
  runner 9 of the 14 were loaded under that name. That is evidence, not a documented rule (ADR 0046).
- The relative case: two forms occurred, `System32\` (218 and 206 services) and `SysWOW64\` (1, on the PC
  only), and every one resolved under `%SystemRoot%` to a file that existed. No primary source read says
  Windows resolves every relative `ImagePath` that way. Naming only the two folders measured would make the
  next unmeasured folder a gap. Reading every relative path this way risks hashing the wrong file if
  Windows resolves one elsewhere. A wrong file has a different hash, so the cost of being wrong is a
  `not_found` for a driver that is there, never a `found` for one that is not.
- `\??\` with a drive letter: 2 on the runner, 12 on the PC, all resolved to existing files.
- A bare drive letter: not measured. It is the form the other rows resolve to, so it needs no guess.

A form in the last row produces an observation with `service` and `start` and no `path` or `sha256`, and a
`read_failed` gap on `sha256`: the value exists and this program did not understand it.

Every `/` in the path the table above builds is read as `\`. A resolved path is then an unknown form (last
row), rather than the file its segments appear to name, when any segment after the drive: is `.` or `..`;
is empty, from a repeated or trailing separator; ends in `.` or a space; contains a `:` past the drive
(reaching an alternate data stream); or, for the segment right after the drive, is `Documents and Settings`
(a junction to `Users` on current Windows) case-insensitively. No such `ImagePath` was measured on either
machine. Each is a spelling this program does not read as the file it appears to name. When this ADR was
accepted, each could also have carried a user name past SS-mode redaction, which then recognised a profile
path only as a drive letter, one separator, the folder `Users` and the name after it. Which folders SS mode
treats as a profile root is decided for every collector that reports a path in ADR 0049, not in this
resolver: since then redaction reaches these spellings as well, and the refusals stay because the resolver
still does not read them. ADR 0049 also states what redaction does not reach.

### What is a gap and what is not

The engine reads a gap on `sha256` as "not every driver was hashed": a rule that matched nothing is then
`unmeasured` with that reason instead of `not_found`, and a rule that matched is still `found`
(`engine::evaluate_rule`). So:

| Event | Observation | Gap on `sha256` |
|---|---|---|
| The `Services` key is refused, absent or cannot be read, or `%SystemRoot%` is unset | none | the whole run is `Unmeasured`: `access_denied` if refused, otherwise `read_failed` |
| `Type`, `ImagePath` or `Start` refused in one key | none for that key | `access_denied` |
| `Type`, `ImagePath` or `Start` unreadable in one key for another reason | none for that key | `read_failed` |
| Unknown `ImagePath` form | without `path`, `sha256` | `read_failed` |
| Resolved file does not exist | without `sha256` | none |
| File refused | without `sha256` | `access_denied` |
| File could not be read for another reason | without `sha256` | `read_failed` |
| Budget spent before this file | without `sha256` | `budget_spent` |

A missing file is not a gap. A driver service whose file is gone is a key an uninstaller left behind, and
there is no file there to be vulnerable. `FilesystemSource::file_sha256` answers a missing file and an
unreadable one with the same error, so after a failure the collector lists the file's folder with
`FilesystemSource::list_dir`: a file the folder does not hold is missing, and any other answer keeps the
failure. No host method is added. The cost: a resolver mistake that points at a path with no file
reads as that ordinary case. The PC and the runner had none.

When several gaps occur, the one reported is the first in this order: `budget_spent`, `access_denied`,
`read_failed`. A gap holds one reason per field, so one has to win: `budget_spent` first because it says
the rest was never tried, then the reason a person can act on before the one nobody can.

### The budget

30 seconds of wall clock for the whole collector, checked before each file is hashed, as `usn` does. The
runner's first pass took 15.5 seconds for 140 MiB; the PC's took 8.7 seconds for 286 MiB, with no control
over the cache. Services are visited in the order `subkeys` returns them; after the budget, each remaining
driver service is still emitted without `sha256`, so the reader sees every one that was registered.

`budget_spent` gains a third producer. The owner table in `rules/AGENTS.md`, ADR 0030 and
`xtask`'s `the_revived_reasons_belong_to_one_collector_each` name it.

### The data file

`rules/driver_service/vulnerable-driver/loldrivers-listed/loldrivers-vulnerable-drivers.csv`, beside the rule
(a rule lives at `<collector>/<category>/<slug>/rule.yaml`):

```
sha256,loldrivers_id,file_name
```

- One row per distinct `SHA256`, lowercase, sorted by `sha256`. `loldrivers_id` is the entry's `Id`;
  `file_name` is the sample's `Filename`, or its `OriginalFilename` when `Filename` is empty. When one hash
  is in several entries, the row carries the entry whose `Id` sorts first.
- **Decided by the owner: only entries whose `Verified` is true**, case-insensitively. At commit `1c60ea1`
  that is 1,847 hashes; the 18 more from unverified entries are left out.
- Only `Category: vulnerable driver` (ADR 0046). A sample without a 64-hex-digit `SHA256` is left out; 97
  such samples at `1c60ea1` (ADR 0046).
- Annotated in `REUSE.toml` as Apache-2.0, "LOLDrivers contributors", `precedence = "override"`, like
  `fixtures/evtx/*.evtx`. The rule text beside it stays CC-BY-SA-4.0.
- A `PROVENANCE.md` beside it names the upstream repository, the commit, the date taken, the filter above,
  the licence, and the script that reproduces the file from a sparse checkout of `yaml/` at that commit.
  The script is `cargo xtask loldrivers`, so the next update runs the same filter; it reads only `yaml/`
  of a checkout someone already made, and never fetches anything itself.
- It is updated by a pull request that changes the commit, the file and `PROVENANCE.md` together. The
  program never fetches it (ADR 0003).

### The rule format

A rule gains `match_lists`, a map from a `match` field to a data file beside `rule.yaml`:

```yaml
collector: driver_service
strength: posture
match_lists:
  sha256: loldrivers-vulnerable-drivers.csv
```

- The bundle carries each named file beside its rule's text, so the rules bundle SHA-256 shown on About &
  code covers the data.
- `Bundle::from_bundle_json` expands it before validation: the file's first column becomes a list under
  `match.sha256`, and every other rule rule applies to the result as if it had been written there
  (ADR 0029: a list means any of them). The engine and `Evidence` are unchanged.
- A field may be in `match` or `match_lists`, not both. The file must exist beside the rule, start with a
  header line whose first column is the field's name, and have at least one row after it, with no empty
  and no duplicate first column; for `sha256`, every first column is a lowercase 64-hex-digit value. Only
  the first column is read, as the text before the first comma. `rules::validate` refuses anything else,
  so `cargo xtask check-rules` and the embedded bundle refuse the same files.
- `cargo xtask rules-reference` renders the condition as the file's name and its row count, never the
  hashes.
- `Rule` is `deny_unknown_fields`, so a rule using `match_lists` does not parse in a build that predates
  it. `RULES_SCHEMA_VERSION` becomes 3, as ADR 0035 raised it to 2.

### How the reader finds which entry matched

Decided by the owner: **the row shows the matched file's `sha256`, and the rule's text says where the list
is.** Its `description` names LOLDrivers and the data file's path in the repository, which About & code
already shows how to reach (ADR 0045). A reader searches that file for the hash and finds the LOLDrivers id
and file name on the same line, and can look the id up on LOLDrivers' site from any other device.

Carrying the id onto the row itself was weighed and not chosen for this collector: it needs the view or
the report to join an observation to a data file, a change to `Evidence`, both UIs and the report schema,
for a line the reader can find with one search.

### The rule

`rules/driver_service/vulnerable-driver/loldrivers-listed/rule.yaml`:

- `strength: posture`, `status: test`, `match_lists: { sha256: … }`, nothing in `match`.
- `retention`: the driver services registered when the scan ran. A driver that was registered, loaded and
  removed before the scan is not seen (ADR 0046).
- `falsepositives`: hardware utilities ship such drivers: overclocking, fan and RGB control, hardware
  monitoring. LOLDrivers' own RTCore64.sys entry is the MSI Afterburner driver (ADR 0046, Question 3). A
  `found` row says a driver with a known weakness is registered, not that anything used it.
- `unmeasured_when: [not_windows]`, as the other `posture` rules declare it. Every other reason this
  collector reports is either always listed (`read_failed`, `budget_spent`) or one an ordinary PC does not
  produce (`access_denied`, measured on both machines).
- A positive fixture: a host with one driver service whose fixture `sha256` is a hash in the data file. The
  fixture carries the hash as text; no driver binary is committed (`rules/AGENTS.md`). A negative fixture:
  the same service with a hash that is not in the file.

### Baseline

`fixtures/hosts/baseline-*` hosts that read `driver_service` are rebuilt from a run of the collector on a
GitHub-hosted Windows runner, printed by `windows.yml`'s live smoke step: its driver services, paths, starts
and hashes belong to a published image and to no person (ADR 0046). `fixtures/hosts/PROVENANCE.md` cites the
run and says what it does not show: the rule quiet on an image with Microsoft's drivers, not on a gaming PC.
No baseline is built from anyone's own PC.

### Privacy

Every driver service is emitted, as `process` emits every process (ADR 0046). In Self mode the player sees
their own driver list among unmatched observations; in SS mode only a match is listed, and every driver the
rule did not match is counted (ADR 0014). A path under a profile root is redacted in SS mode like any
other (ADR 0023, ADR 0049); every form the resolver produces is drive-letter form.

`PRIVACY.md`, the CLI consent text and the desktop consent text name driver services — their names, file
paths and file hashes — in the pull request that registers the collector.

## Alternatives weighed

| Alternative | Why not |
|---|---|
| Resolve only `System32\` and `SysWOW64\` | The next unmeasured relative folder becomes a gap on every PC that has one; the wrong-file risk of the chosen reading costs a `not_found`, not a false `found` |
| Include unverified LOLDrivers entries | 18 more hashes, each a `found` row resting on an entry its own catalogue has not verified |
| The LOLDrivers id on the row | A change to `Evidence`, the view, both UIs and the report schema for a line one search finds |
| Only `service`, `path`, `sha256` | A `found` row on a disabled driver would not say so |
| A missing file as a gap | Leftover service keys are ordinary; every PC with one would read `unmeasured` |
| A new operator such as `sha256\|in_file` | A change to ADR 0029's operator vocabulary and to the engine; ADR 0046 chose expansion |
| No budget | 15.5 s cold on a runner with no third-party drivers; a PC with more has no bound |

## What is unverified

- A primary source for how Windows resolves a relative `ImagePath`, and for the default when it is absent.
- Rights for a standard account that is not an administrator on a PC (the PC below was scanned with an
  administrator's limited token, not a standard account), and for a driver file whose ACL refuses its
  users.
- A cold hash time on a PC.
- How often an ordinary gaming PC reads `found`. One PC with a hardware utility did (below); a baseline
  from a runner cannot show the rate, and no person's driver list is published to show it.
- The budget is checked between files, not while one is hashing: one very large file, a slow removable
  volume, or a drive letter mapped to a network share can hold the scan past 30 s on that file alone, and a
  file's size is not bounded before it is hashed. A path on a mapped network drive is read through the
  network like any other. Genuine drivers are small — the runner's 424 took 15.5 seconds cold — so this was
  not measured on either machine.

## The rule on a PC

On 2026-09-15 the CLI built from `dev` at `28efbee` scanned a Windows 11 PC (build 26220) that has ASUS
GPU Tweak III 1.9.5.8 installed, once elevated and once with a limited token from a scheduled task. The two
reports agree:

- 464 driver services, every one hashed, in a scan of 24 seconds.
- The rule is `found`, with two rows: `AsIO` (`C:\WINDOWS\SysWow64\drivers\AsIO.sys`) and `Asusgio2`
  (`C:\WINDOWS\system32\drivers\AsIO2.sys`, running). Both hashes belong to LOLDrivers entry
  `2651f5c4-d9e1-4b06-92be-e9e7313f87c4`, and both files are signed by ASUSTeK Computer Inc.
- `VulnerableDriverBlocklistEnable` under `HKLM\SYSTEM\CurrentControlSet\Control\CI\Config` is 1 on this
  PC, and `Asusgio2` runs. The blocklist this program does not read did not stop this driver; what that
  value controls has no Microsoft-documented source (ADR 0046).

This is the rule's first `falsepositives` case seen on a real PC: a hardware utility's drivers. Which
installer placed them was not established.

## Consequences

- A new collector `driver_service`, a new rule under `rules/driver_service/`, a vendored Apache-2.0 data
  file with its `PROVENANCE.md` and reproduction script, `match_lists` in the rule format and
  `RULES_SCHEMA_VERSION` 3.
- `budget_spent` has three producers: `evtx`, `usn`, `driver_service`.
- `PRIVACY.md`, both consent texts, `docs/architecture.md`, ADR 0030's reason table, `rules/AGENTS.md`,
  README (both languages) and CHANGELOG change in the pull requests that ship it.
- No network code, no new dependency, no new `windows` feature.
- Implemented as `crates/rongroi-collectors/src/driver_service.rs`; the baseline's driver services come
  from `windows.yml` run 34955915842. The rule and its data file follow in their own pull request.
- The rule is `rules/driver_service/vulnerable-driver/loldrivers-listed/rule.yaml`, with 1,847 rows at
  LOLDrivers `1c60ea1`.
- Accepted by the owner on 2026-09-15, as written.
