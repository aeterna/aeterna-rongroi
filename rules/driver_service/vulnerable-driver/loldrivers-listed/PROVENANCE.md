# `loldrivers-vulnerable-drivers.csv`

The SHA-256 of every driver sample LOLDrivers catalogues as a verified vulnerable driver, with the
LOLDrivers entry id and file name for each, so a reader who finds a hash on a `found` row can find the
entry. It is data taken from another project, under that project's licence, and this rule reads its first
column (ADR 0046, ADR 0048). **No driver file is in this repository.**

| Field | Value |
|---|---|
| Source | https://github.com/magicsword-io/LOLDrivers |
| Licence | Apache-2.0 (`LICENSES/Apache-2.0.txt`) |
| Copyright | LOLDrivers contributors |
| Commit | `1c60ea1c8909396fe294c76aaafae4923b6dbea1`, pushed 2026-09-08 |
| Taken | 2026-09-15 |
| Read | `yaml/*.yaml` only, 687 files, from a sparse checkout that fetched nothing under `drivers/` |
| Rows | 1,847 |

## The filter

- `Category` is `vulnerable driver`; `malicious` entries are left out.
- `Verified` is true (`TRUE`, `true` or `True`, quoted or not). 18 hashes from unverified entries are left
  out.
- Each sample under `KnownVulnerableSamples` whose `SHA256` is 64 hex digits, lower-cased. 97 vulnerable
  samples carry none and are not here; 78 of them carry an Authenticode hash, which this program does not
  compute (ADR 0046).
- One row per distinct hash. When a hash is in several entries, the row names the entry whose `Id` sorts
  first. `file_name` is the sample's `Filename`, or its `OriginalFilename` when `Filename` is empty, and is
  empty when both are.

## Rebuilding it

```bash
git clone -q --filter=blob:none --no-checkout https://github.com/magicsword-io/LOLDrivers.git loldrivers
git -C loldrivers sparse-checkout set --no-cone '/yaml/'
git -C loldrivers checkout -q <commit>
cargo xtask loldrivers --checkout loldrivers          # writes this file
cargo xtask loldrivers --checkout loldrivers --check  # confirms it
```

An update is one pull request that changes the commit and date above, this file and the row count
together. The program never fetches the list.
