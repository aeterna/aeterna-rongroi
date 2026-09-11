# 06 — Testing Windows forensic code (2026-09-11)

## Test corpora and whether a GPL-3.0 repository may vendor them

| Corpus | License | Contents | Vendor? |
|---|---|---|---|
| [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) | GPL-3.0 | 278 `.evtx`, including log-cleared events 104 and 1102 | yes |
| [hayabusa-sample-evtx](https://github.com/Yamato-Security/hayabusa-sample-evtx) | **none** | 599 `.evtx` | **no** — check out in CI only |
| [omerbenamram/evtx samples](https://github.com/omerbenamram/evtx) | Apache-2.0 | ~30 files incl. corrupt ones | yes |
| [EricZimmerman/Prefetch test files](https://github.com/EricZimmerman/Prefetch) | MIT | every Prefetch version incl. Win10 compressed, plus a bad file | yes |
| [EricZimmerman/Registry test hives](https://github.com/EricZimmerman/Registry) | MIT | SAM/SECURITY/SYSTEM/SOFTWARE plus deliberately broken hives | yes (large) |
| [plaso test_data](https://github.com/log2timeline/plaso/tree/main/test_data) | Apache-2.0 | ~745 MB mixed artifacts | cherry-pick only |
| [frnsc-prefetch artifacts](https://github.com/ForensicRS/frnsc-prefetch) | MIT | Prefetch per version under a fake `C:\` | yes |
| [nt-hive testhive](https://github.com/ColinFinck/nt-hive) | GPL-2.0-or-later | tiny synthetic hive built with the Offline Registry Library | yes |
| [LOLDrivers](https://github.com/magicsword-io/LOLDrivers) | Apache-2.0 | ~215 MB | hash list only |

## Testing Windows code off Windows

- ForensicRS defines `VirtualFileSystem` and `RegistryReader` traits with live and offline implementations;
  a chroot filesystem turns a folder into a fake `C:\`
  ([vfs.rs](https://github.com/ForensicRS/forensic-rs/blob/main/src/traits/vfs.rs)).
- dfvfs / dfwinreg (Python) use the same idea with fake filesystems and registries.
- Gate live code with `#[cfg(windows)]`; mark live smoke tests `#[cfg_attr(not(windows), ignore)]`.

## Snapshots and fuzzing

- The evtx crate snapshots decoded records with insta
  ([test file](https://github.com/omerbenamram/evtx/blob/master/tests/test_record_samples.rs)).
- yara-x has one cargo-fuzz target per file-format parser
  ([fuzz targets](https://github.com/VirusTotal/yara-x/tree/main/lib/fuzz/fuzz_targets)).
- Velociraptor keeps `.in.yaml` / `.out.yaml` golden pairs for artifacts.

## Rule testing

- Sigma requires regression data for rules with status `test` or `stable`, with an expected match count, and runs
  all rules over clean baselines with an allow-list of known false positives.
- Hayabusa's rules repository only checks parsing and duplicate IDs; its engine repository runs integration
  tests on Linux and Windows.

## Real Windows

- GitHub Windows runners run as administrator with UAC disabled
  ([docs](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)).
- The runner image disables `SysMain` and (on most images) `PcaSvc`
  ([Configure-System.ps1](https://github.com/actions/runner-images/blob/main/images/windows/scripts/build/Configure-System.ps1)),
  so Prefetch and PCA are not produced there.
- Velociraptor's Windows job creates real artifacts first, then runs golden tests
  ([windows.yml](https://github.com/Velocidex/velociraptor/blob/master/.github/workflows/windows.yml)).
- Windows Sandbox can run fixture generators with networking disabled and a read-only mapped folder; its
  default account name is generic ([.wsb docs](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-configure-using-wsb-file)).

## Tauri UI testing

- `@tauri-apps/api/mocks` provides `mockIPC` for Vitest ([docs](https://v2.tauri.app/develop/tests/mocking/)).
- `tauri-driver` WebDriver tests run on Windows and Linux only, not macOS
  ([docs](https://v2.tauri.app/develop/tests/webdriver/)).

## Anti-cheat projects

Grim uses a dedicated false-positive issue form with required reproduction details and labels
([form](https://github.com/GrimAnticheat/Grim/blob/2.0/.github/ISSUE_TEMPLATE/false-positive.yml)).

## What this meant for aeterna-rongroi

- Layers L0–L5 in `docs/testing.md`, with fixture hosts as fake machines.
- Rule tests use observation-level fixtures, so hash-based rules can be tested without cheat binaries.
- Prefetch and PCA are verified on a real Windows 11 machine, not on CI runners.
- Every gate is broken on purpose once to prove it can fail.
