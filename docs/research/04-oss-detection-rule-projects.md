# 04 — Open-source detection-rule projects (2026-09-11)

How large detection and forensics projects structure rules and collectors.

## Projects studied

| Project | License | What we looked at |
|---|---|---|
| [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) (11k★) | rules DRL 1.1 | rule schema, folder taxonomy, regression tests, deprecation |
| [Yamato-Security/hayabusa](https://github.com/Yamato-Security/hayabusa) + [hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules) | AGPL-3.0 / DRL 1.1 | Rust engine with a separate rules repo, bundled rules, EN/JP docs |
| [WithSecureLabs/chainsaw](https://github.com/WithSecureLabs/chainsaw) | GPL-3.0 | Rust, Sigma on event logs, mapping files, golden CLI tests |
| [Velocidex/velociraptor](https://github.com/Velocidex/velociraptor) | AGPL-3.0 | YAML artifact definitions with preconditions, golden tests |
| [osquery](https://github.com/osquery/osquery), [signature-base](https://github.com/Neo23x0/signature-base) | Apache-2.0/GPL-2.0, DRL 1.1 | table specs, IOC formats |
| [VirusTotal/yara-x](https://github.com/VirusTotal/yara-x) | BSD-3-Clause | Rust workspace, rule test macros, golden files |
| [magicsword-io/LOLDrivers](https://github.com/magicsword-io/LOLDrivers) | Apache-2.0 | per-driver YAML, schema validation, generated hash lists |
| [ForensicRS](https://github.com/ForensicRS) | MIT | Rust traits for live vs offline registry and filesystems |

## Patterns worth copying

1. **Sigma-style fields**: UUIDv4 `id`, `title`, `status` lifecycle, `description`, `author`, `date`/`modified`,
   `references`, `tags`, non-empty `falsepositives`, and `related` links
   ([spec](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-rules-specification.md)).
2. **Declared collector plus precondition**: Velociraptor sources carry a `precondition`; a failed one skips the
   source ([example](https://github.com/Velocidex/velociraptor/blob/master/artifacts/definitions/Windows/Forensics/Bam.yaml)).
   → our `unmeasured` with a reason.
3. **Unique IDs checked in CI** ([hayabusa check](https://github.com/Yamato-Security/hayabusa-rules/blob/main/.github/workflows/duplicate-id-check.yaml)).
4. **Positive fixtures with expected match counts** for rules past experimental
   ([Sigma regression data](https://github.com/SigmaHQ/sigma/blob/master/regression_data/README.md)).
5. **Clean-machine baseline**: run all rules over clean systems; CI fails on new hits unless listed with a reason
   ([goodlog tests](https://github.com/SigmaHQ/sigma/blob/master/.github/workflows/goodlog-tests.yml)).
6. **Collectors behind traits** so golden tests run anywhere
   ([ForensicRS README](https://github.com/ForensicRS/forensic-rs/blob/main/README.md)).
7. **Deprecation** by status and a moved file, never reuse of an ID.
8. **PR changelog prefixes** feeding release notes ([template](https://github.com/SigmaHQ/sigma/blob/master/.github/PULL_REQUEST_TEMPLATE.md)).
9. **One bundled rules file** rather than thousands of loose YAML files: Hayabusa found loose rules triggered
   antivirus and writing many files can overwrite USN evidence
   ([encoded rules](https://github.com/Yamato-Security/hayabusa-encoded-rules)).

## Patterns to avoid

- Score-summing IOC files with no IDs or false-positive notes — they add up to a verdict.
- String booleans and loose enums (`Verified: 'TRUE'`).
- Rules shipped with the engine but no test step in CI.
- Published rule packs nobody maintains.
- Test data with no license.
- Fetching rules over the network (impossible for an offline tool).
- Mixing licenses in one folder.

## What this meant for aeterna-rongroi

- Rule format v1 follows Sigma's fields, adds `strength`, `retention` and `unmeasured_when`, and forbids
  name-based allow entries.
- One folder per rule with its fixtures; translations in `rules/i18n/`.
- Validation in Rust shared by the build and `cargo xtask check-rules`.
- Rules embedded in the executable as one bundle (ADR 0004).
