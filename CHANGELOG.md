# Changelog

All notable changes are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- `fivem_dir` collector: the files directly inside `%LOCALAPPDATA%\FiveM\FiveM.app\plugins`, each with its path and, when it can be read, its SHA-256. No rule reads it yet, so the files are shown in Self mode for a person to judge (ADR 0009).
- File-system and environment host sources, with `FixtureHost` describing directories and environment variables in YAML (ADR 0009).

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
