# Changelog

All notable changes are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- `posture` collector: Windows test signing, memory integrity (HVCI) and whether a TPM is present, beside
  the Secure Boot state it already read. Memory integrity is read from the configured policy in the
  registry, which says what Windows was told to enforce and not that the hypervisor is enforcing it; a
  machine with no TPM is reported as a fact rather than as something that could not be measured (ADR 0011).
- Three rules, all `experimental`: test signing is on, memory integrity is configured off, and no TPM is
  present. The last is the first `context`-strength rule, so SS mode lists it only when it matches.
- `fivem_dir` collector: the files directly inside `%LOCALAPPDATA%\FiveM\FiveM.app\plugins`, each with its path and, when it can be read, its SHA-256. No rule reads it yet, so the files are shown in Self mode for a person to judge (ADR 0009).
- File-system and environment host sources, with `FixtureHost` describing directories and environment variables in YAML (ADR 0009).
- Restart with administrator rights on request: `aeterna-rongroi-cli scan --elevate` and a "Scan as
  administrator" button in the desktop app, so checks that need an elevated token can be measured instead of
  being reported as `Unmeasured`. The program starts again and scans from the beginning; declining the
  Windows prompt is a normal outcome, not an error (ADR 0012).

### Fixed
- Desktop app: the report header shows the program version, which the release notes ask people to check.

## [0.1.0] - 2026-09-11

### Added
- Repository foundation: licenses, NOTICE with GPL section 7 terms, AGENTS.md, CONVENTIONS.md, policies.
- Rule format v1, rules bundle embedded in the executable, evidence engine with Found / NotFound / Unmeasured.
- Secure Boot posture collector with Live and Fixture hosts.
- CLI with Self and SS modes, and an unofficial-build banner.
- Desktop app shell (Tauri 2) with consent screen and English / Thai.
- Release workflow: official Windows executables with `SHA256SUMS`, SBOMs and build attestations in a draft GitHub release (ADR 0008).
