# Changelog

All notable changes are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Listed counts: every report view carries how many of the evidence it lists are found, not found and
  not measured, and the text report prints them on one line above the evidence. Three numbers, never
  one (ADR 0045).
- The code link: the text report prints, above its closing footer line, where to read this binary's
  code — the commit of an official build, or the repository with a note that the code of an unofficial
  build is not known. Rule text now carries each rule's status and where its rule, fixtures and
  collector are in the repository, checked to exist by a test (ADR 0045).
- The desktop report reads in layers (ADR 0045). Three counts of what the view lists — found, not found,
  not measured — each a filter, sit above the rows with the sentence that no report proves a PC clean.
  Rows are grouped by collector under plain names; a match starts open with its ordinary causes, other
  rows start closed with the description cut to two lines, and the not-found rows of a group fold into
  one line. Each row opens technical details: the observation as a table, the rule id, status,
  collector, strength and reason code, and where the rule, its fixtures and its collector are in the
  repository. A new About & code screen shows the repository and this build's commit as copyable text and
  QR codes drawn in Rust, how to check a downloaded file, and why no button opens a web page. No plugin,
  no JavaScript dependency and no network code were added.
- The `usn` collector: the Windows drive's NTFS change journal, read on a volume handle that cannot write
  and through the two read control codes only, counted per folder other collectors read — records, and
  how many created, deleted, renamed or changed a file, with the first and last time. No file name,
  journal identifier or file number reaches the report. No rule reads it yet. `DeviceIoControl` and
  `CreateFileW` are each banned in `clippy.toml` outside one read-only wrapper, and `fuzz_usn` joins the
  fuzz smoke run (ADR 0047).
- `match_lists` in the rule format: a rule can keep a long list of values for one field in a CSV file
  beside `rule.yaml`, carried in the rules bundle and expanded into `match` when it loads. The reference
  pages name the file and its row count. Rule format version 3 (ADR 0048).
- The `driver_service` collector: every driver service registered with Windows, with its start setting,
  the path its `ImagePath` resolves to and the SHA-256 of that file. Every relative `ImagePath` is read
  under `%SystemRoot%`; a refused, unreadable or unresolved file leaves the hash a gap, and hashing stops
  after 30 seconds. No administrator rights are needed (ADR 0048).
- A vulnerable-driver rule (`posture`, status `test`): a driver service registered on the PC whose file's
  SHA-256 is one of 1,847 verified vulnerable-driver hashes from LOLDrivers at commit `1c60ea1`, vendored
  under Apache-2.0 beside the rule with how to rebuild it (`cargo xtask loldrivers`). A `found` row shows
  the hash; the data file gives the LOLDrivers entry. Hardware utilities install such drivers, and the rule
  says so (ADR 0046, ADR 0048).

### Changed
- SS-mode redaction knows more profile folders (ADR 0049). Besides `X:\Users\<name>`, it replaces
  `Documents and Settings\<name>` and its 8.3 short name, the same folders reached through a drive's
  administrative share, and the machine's own `ProfilesDirectory` when it has been moved. It reads `\` and
  `/` in any mix and run, applies `.` and `..`, and finds a second path
  written straight after a name. The scan reads `ProfilesDirectory` into the report header
  (`profiles_directory`, additive, schema stays at 1); an SS view and the header the app reads outside a view
  drop it. `redact_user_paths` is now `redact_profile_paths`. What is still not reached — a profile moved for
  one account on its own, paths without a drive letter, some 8.3 short names — is listed in `PRIVACY.md`.
- The desktop report header no longer shows the executable's SHA-256. It is on About & code, with the
  commit, the rules bundle SHA-256 and how to check a downloaded file (ADR 0045).
- The vulnerable-driver list is designed (ADR 0046, accepted): LOLDrivers' vulnerable drivers by SHA-256,
  matched against registered driver services as `posture`, vendored as a data file under its own licence.
  No collector code until its rights, `ImagePath` forms and cost are measured. Loaded modules, the
  Authenticode hash and Microsoft's blocklist switch are not read.
- The USN change journal is designed (ADR 0047, accepted): counts of records per folder other collectors
  already read, with file names dropped in the parser and no journal identifier in the report. The
  measurement on a GitHub-hosted runner found the journal readable on a handle without write access, and
  the collector is under Added.
- ADR 0046 and ADR 0047 carry measurements from a GitHub-hosted Windows Server 2025 runner under an
  elevated token, a restricted token and a standard account. Driver services and their files were readable
  without Administrators there, and hashing them took 15.5 seconds cold. The USN journal read on a volume
  handle opened without write access, returned only version 3 records, and matched folders by their 128-bit
  identifier; without Administrators the volume could not be opened.
- ADR 0046 carries measurements from a Windows 11 PC and the LOLDrivers count. Under the limited token all
  464 driver services were read and all 463 driver files hashed, including those in `DriverStore` and
  `Program Files`, and a relative `SysWOW64\` `ImagePath` the runner did not have was found. LOLDrivers at
  commit `1c60ea1` holds 1,865 distinct SHA-256 values for vulnerable drivers; 97 samples carry no file
  SHA-256.
- The `driver_service` collector is designed (ADR 0048, accepted): registered driver services with each file's
  SHA-256 and `Start`, a resolver that reads relative `ImagePath` values under `%SystemRoot%`, a 30-second
  budget, and a vulnerable-driver rule whose `match_lists` names a vendored file of 1,847 verified LOLDrivers
  hashes. Rule format version 3.
- A directory listing returns each entry's size and its creation and last-write times, read from the
  listing without opening the entry and kept in whole seconds, as a basis for showing when FiveM's cache,
  log and crash folders changed. The last-access time stays unread. Fixture hosts can describe the three
  values, and refuse a directory with a size or a time with a fraction of a second. No collector emits the
  values yet, so reports are unchanged (ADR 0050, accepted).
- The timeline (ADR 0051, accepted): both front ends list the times a report holds, oldest first, with
  when the scan ran and when Windows started as anchors, the span each event log and the change journal
  could see, and the sources whose times could not be read — including the change journal's `not_admin`,
  which reached no output before. Self mode's timeline holds every time the scan read. SS mode's holds the
  times of the evidence it lists and what **timeline selectors** select: rule files with `role: timeline`
  (rule format version 4) that make no evidence and no count. Nine ship: FiveM and GTA V executables by
  name in Prefetch, BAM and PCA (`experimental`), each watched folder's journal times, each event log's
  oldest and newest record, and FiveM's folder activity. The consent question and PRIVACY.md name what the
  SS timeline shows, program by program. The desktop groups rows in an order the core now decides. A rule
  on Prefetch, BAM or PCA that matches `name` or `path` is now refused when the bundle loads (ADR 0034).
- Two scan tiers (ADR 0052). A **full scan** reads more than the standard one, and only when the player
  says yes before it starts, in the process that reads: `scan --full` asks on standard error and only
  `yes` starts it; the desktop app's "Full scan" button starts a new copy with the same token, which asks
  in a Windows dialog before any collector runs and before any WebView exists. No flag answers for the
  player. In a standard scan a `full` collector is not called: its rules are unmeasured with the new
  reason `not_consented`, a scope statement said once above the evidence. The header carries `scan_tier`.
  A field a `full` collector declares sensitive is shown in SS mode as `%SERVER_IDENTITY%` or
  `%ACCOUNT_IDENTIFIER%` unless the player agreed to show that kind, a separate question, default no.
- The first `full` collector, `fivem_servers`: the name of each server cache folder FiveM for GTA V
  Enhanced keeps, with its creation and last-write times, and one `context` rule that lists them
  (ADR 0055). What the name is made from is not known.
- ADR 0052 records a Windows 11 measurement: under UAC's default settings, a process started with
  `CreateProcessW` from an elevated copy is elevated, and from a standard copy is standard, with no consent
  prompt in between. A desktop copy started for a full scan neither gains nor loses administrator rights.
- `fivem_dir` reports FiveM's log, crash and cache folders in both editions as folder activity — how many
  files and subfolders, their total size, the earliest and latest file times, and the folder's own times —
  and each Enhanced server cache folder's creation and last-change times and entry count, with no file or
  folder name. No rule reads them: Self mode lists them and SS mode counts them. The consent question and
  PRIVACY.md say so (ADR 0053, accepted).
- The `net_config` collector: the settings that decide where network traffic goes, never a record of
  where it went (ADR 0054). Of the hosts file, found through `DataBasePath`, it counts the lines in effect
  and reports only the lines that give a name under `cfx.re`, `fivem.net` or `rockstargames.com` an
  address, with the address and its kind; of the current user's proxy, whether it is on and whether a
  server or a setup script is set, never their addresses; of the Windows Firewall rules, how many there
  are and, for each rule for a program in a FiveM folder, its action, state, direction, protocol,
  profiles and program path, never its name or description. SS mode never shows a hosts line's address,
  only its kind (`view::SS_WITHHELD_FIELDS`). One `posture` rule, `experimental`: the hosts file gives a
  FiveM or Rockstar name an address. The consent question, PRIVACY.md and both screenshare guides say what
  is read. The owner decided that no record of where traffic went is read: not SRUM, the DNS cache, the
  live TCP table, the firewall log or a packet capture.
- ADR 0054 records a second Windows 11 measurement: the hosts file's folder (`DataBasePath`), the proxy
  values and the firewall rules key all read the same with and without administrator rights; FiveM's four
  firewall rules include two for GTA V Enhanced's executable inside FiveM's folder, so the collector finds
  FiveM's rules by folder rather than by file name.

### Fixed
- A `SYSTEMTIME` value in an Event Log record whose milliseconds were above 4294 overflowed a `u32` in the
  vendored `evtx` crate: a panic in a test or fuzz build, and in a release build a silently wrapped value.
  It is now refused like every other value above 999, the record is rejected and the rest of the chunk is
  read. Found by `fuzz_evtx` in CI; the fourth patch in `third_party/evtx` (PROVENANCE.md).

## [0.3.0] - 2026-09-14

### Added
- Two negative fixtures for the log-clearing rules, each the shape an ordinary log holds from the Event Log
  service without anyone clearing it: `1100` and `1101` on Security, and `30` plus the classic `EventLog`
  provider's start and stop records on System, both measured on ordinary Windows 11 machines. Widening either
  rule to one of those event ids now fails `cargo xtask check-rules`. The owner decided not to build a machine
  to capture a publishable log for a baseline; `rules/unconfronted.csv` records that.
- The pinned `FiveM.exe` signing certificate can no longer go stale silently (ADR 0036, amendment of
  2026-09-14). `rules/certificate-pins.csv` records each certificate an `allow` names with its subject,
  validity and measurement date; `cargo xtask check-rules` requires a row for every such entry and none
  for a certificate no rule allows, without reading a clock. A new monthly workflow, `certificate pins`,
  runs `cargo xtask check-pin-expiry`, which fails 90 days before a rule's newest pinned certificate
  expires — for the certificate pinned today, from 2027-06-07. It is not a required check and does not
  run on pull requests. It watches the last date the certificate can sign, not the day the publisher
  actually switches, which nothing here can see.
- Two `posture` readings and two rules (ADR 0038). `secure_boot_firmware` is Secure Boot as the firmware's
  own UEFI `SecureBoot` variable reports it, beside the registry's `secure_boot`; reading it enables
  `SeSystemEnvironmentPrivilege` in this program's own token for the read and puts it back, and without
  administrator rights it is `unmeasured / not_admin` — measured on one Windows 11 machine, elevated and
  under a limited token. The rule `secure-boot-firmware-disagrees` (`experimental`) is the registry saying
  on while the firmware says off. `script_block_logging` is the Windows PowerShell machine policy as
  `enabled`, `disabled` or `not_configured`, which are three different statements; the rule
  `script-block-logging-disabled-by-policy` (`experimental`) matches only a policy written to off. Kernel
  DMA Protection was considered and is **not** read: Microsoft documents no programmatic interface for
  its state, and the ADR declines to ship a guessed structure. The Windows CI job checks that the firmware
  read leaves the privilege as it found it and agrees with `Get-SecureBootUEFI`.
- **Script block logging policy, per engine and per hive** (ADR 0038, amended 2026-09-14). `posture` now
  also reports `script_block_logging_user` (Windows PowerShell's per-user policy), `script_block_logging_pwsh`
  and `script_block_logging_pwsh_user` (PowerShell 7's, following its `UseWindowsPowerShellPolicySetting`),
  and three `experimental` rules match each set to off. A per-user field is `machine_takes_precedence` when
  that PowerShell takes its policy from the machine hive and never reads the user's. The per-user reads are of
  the Windows account the scan runs as — after a restart with another administrator's password, that
  administrator's — so a live host now opens `HKCU` besides `HKLM`, and nothing else; the consent question,
  `PRIVACY.md` and the screenshare guide say so. Every mapping follows what Windows PowerShell 5.1 and
  PowerShell 7.6 were measured to do on the Windows CI runner, where a new step writes each case, runs both
  engines and counts event 4104, and the CLI's reading is printed beside it.
- The Windows CI job records Microsoft Defender's state and what its Operational log recorded while this
  program enabled `SeSystemEnvironmentPrivilege` for the firmware read (ADR 0038). With real-time protection,
  behaviour monitoring and download scanning switched on, 38 such processes in 15 minutes left no detection
  and no event naming them. One Defender configuration on one runner; nothing about other security products.
- The report header says when Windows last started counting, so the times on other rows can be read
  against it (ADR 0039): `boot_time`, the scan's clock minus `GetTickCount64`, or `unmeasured` with a
  reason — never a guessed time. It is context, not evidence, and no rule can read it. It is shown in both
  modes and named in the consent question. The CLI and the app print it as one line with its caveat on
  the same line: a "Shut down" with Fast Startup (the Windows default), sleep and hibernation do not
  reset it, so a start days before the scan is ordinary. On a real Windows 11 machine it agreed to the
  second with `Win32_OperatingSystem.LastBootUpTime`, with and without administrator rights, while the
  System log's own start record was 7 hours away because the clock had been changed since; the
  screenshare guide now says both.
- **The first rules on `fivem_dir`** (ADR 0036), all `experimental`. For Legacy's plugins folder and,
  separately, Enhanced's `asi` folder: a file with no embedded signature that verifies here, and a file
  with a valid one, each naming what Windows said. A file whose signature could not be checked at all is
  its own row, so a failed check is shown rather than falling to "not found" under the others. Every rule
  says in `falsepositives` that these folders ordinarily hold ReShade, ENB, overlays and their text files;
  the Enhanced rules say that the folder is not known to be loaded. No `allow` entry for any plugin: none
  was measured from a published file. In SS mode the files in these folders are now shown, redacted,
  where they were only counted.
- **`fivem_dir` reads `FiveM.exe`** in each edition's program folder under `%LOCALAPPDATA%`, with the same
  hash and signature check, and two rules pin it: `FiveM.exe` with no embedded signature that verifies,
  and `FiveM.exe` validly signed with a certificate other than the one both editions carried when
  measured on 2026-09-13 ("Rockstar Games, Inc.", valid 2026-07-21 to 2027-09-05). That certificate will
  be renewed, and the rule's text tells a reviewer what the row then means and what to do. Measured on
  one real Windows 11 machine, elevated and under a limited token, and every rule was made to fire there
  on copies of real files in a scratch folder. The consumer and elevated baselines describe `FiveM.exe`
  as measured; the two unsigned-plugin rules are recorded in `rules/unconfronted.csv`.
- Signature checking, without the network (ADR 0035). `fivem_dir` reports, for each file in FiveM's plugin
  folders, what Windows says about the Authenticode signature embedded in it: `valid` with the signer's
  name and the SHA-256 of the signing certificate, `no_embedded_signature`, `invalid`, or
  `unverifiable_offline`. `WinVerifyTrust` runs with no revocation checking and URL retrieval from the
  local cache only. Checking a signature is the one read in this program that Windows could take to the
  network by itself, where `cargo deny` and every lint are blind, so the Windows CI job switches the
  CAPI2 log on and fails if the offline tests leave a network retrieval (event 53) behind — beside a
  positive twin that must leave one. On a real Windows 11 machine the check agreed with PowerShell on
  the signing certificate of an embedded-signed executable, called a copy with one changed byte
  `invalid`, and found nothing embedded in a catalog-only Windows file. It also showed that PowerShell's
  `Catalog` does not mean "nothing embedded": `explorer.exe` has both.
- `fivem_dir` reads FiveM for GTA V **Enhanced**, which installs separately and keeps its user data under
  `%APPDATA%` rather than `%LOCALAPPDATA%`. On a machine with only Enhanced, the collector used to report
  that Legacy's plugin folder was absent and nothing about the one it never looked in. It now reads
  Enhanced's `gta5enhanced\asi` folder under `location: enhanced_asi`, and reports each folder of both
  editions — listed, absent or unreadable — by name. That the Enhanced client loads from that folder is
  **not established**; the ADR says what was and was not found. `gta5enhanced\mods` is not read.
- A screenshare guide, in English and Thai (`docs/screenshare-guide.md`, `docs/screenshare-guide.th.md`),
  for staff checking a PC over a screenshare and for the player being checked. It covers getting and
  verifying the real file, administrator rights, running SS mode, reading each row, what each of the six
  rules' ordinary causes are, what SS mode withholds and why, and what a report does not mean. It is the
  M3 item README listed as planned, and the one `CONVENTIONS.md` §8 once said existed when it did not.
  Two things the guide found are written into it rather than papered over: the CLI writes its SS-mode
  consent question to the same output as `--json`, so `--json > report.json` hides the question from
  the player; and `--elevate` scans in a new console window this project has not checked stays open.
- A rule reference, in English and Thai (`docs/rules-reference.md`, `docs/rules-reference.th.md`), so
  that a reviewer or a player can read what every rule looks at without opening its YAML: title, id,
  collector, strength, status, each `match` condition in words with its operator and whether case
  matters, `retention`, `unmeasured_when`, `falsepositives`, `allow` and references, grouped by
  collector and category. The pages are generated by `cargo xtask rules-reference` from the bundle the
  program embeds, loaded by the same code, with the Thai text from `rules/i18n/th.yaml` and the words for
  a strength or a reason from the desktop app's `report.json`. The `rust (ubuntu)` job runs
  `cargo xtask rules-reference --check`, so a pull request that changes a rule without regenerating the
  pages fails, with an error naming the command to run.
- ADR 0040: reports are not signed. A key inside an executable anyone can build is readable by the
  person whose report it signs, a verifier that is the same executable checks itself, and a Windows
  modified to lie would have a real key sign the lie. The official-build marker (ADR 0007) and the
  release attestation (ADR 0008) say where a binary came from, not whether a report reflects the
  machine; watching the scan run is the control. Both screenshare guides gain §11, "What a report does
  not prove about itself", PRIVACY.md says a report file is not signed, and the ADR lists what would make
  the question worth asking again without promising it.
- Three rules about the state of a Prefetch or event log **file** rather than a record in it, all
  `experimental` and `tamper` (ADR 0037, ADR 0042): a `.pf` file marked read-only, an `.evtx` file marked
  read-only, and a log file whose records belong to a channel that the Windows Event Log service writes
  to a different file. Reading them needed two new reads, both disclosed in the consent question:
  **one attribute bit** of each `.pf` and `.evtx` file, amending ADR 0009's "no attributes", and **what
  the Event Log service states about a channel** — its file and its maximum size — through
  `EvtOpenChannelConfig`, a new host source. That question is asked on a thread of its own and charged
  to the `evtx` 30-second budget, so an Event Log service that never answers ends the collection with
  the configuration `unmeasured / budget_spent` instead of stalling the scan. The registry was measured first and rejected: on one Windows
  11 machine no `WINEVT\Channels` key named a file, and the registry's `MaxSize` disagreed with the size
  Windows uses on 18 of the 94 keys carrying one. On that machine, elevated, all three rules were
  `not_found`: 243 `.pf` and 413 `.evtx` files none read-only, and 148 of 148 logs with records at the
  path their channel is written to. `max_size_bytes` is reported and **no rule reads it**: Windows'
  documented minimum, 1 MiB, is the size 1 166 of that machine's 1 243 channels had, so there is no
  "unusually small" to write down.
- `prefetch` reports its own configuration as an observation — whether the folder is `listed`, `absent`
  or `unreadable`, and the `EnablePrefetcher` value, left out when the registry holds none (ADR 0037).
  Both used to reach the report only as the reason a rule could not be answered. No rule reads either:
  a Windows 11 PC had the value at 3 and GitHub's Windows CI image has no value at all.

- The Windows CI job suspends the Event Log service and runs a scan, which must finish and report the
  configured-path rule as `unmeasured / budget_spent` (ADR 0042 §5). The bound on the channel-configuration
  reads had been shown only against a fixture reader that never answers.
- Amcache is decided against for now (ADR 0041, accepted): no collector and no hash rules until a hive
  reader meets this repository's parser bar, and then only hashes already published elsewhere, each
  with its source.
- `clippy.toml` bans the four calls that write UEFI firmware variables. Reading the Secure Boot variable
  enables `SeSystemEnvironmentPrivilege` in this program's own token, and that privilege permits writes too
  (ADR 0038, now accepted). `AGENTS.md` hard rule 2 names the token as the one thing a collector may change.

### Changed
- `script_block_logging` follows what Windows PowerShell 5.1 was measured to do with the value rather than
  its type alone (ADR 0038, amended 2026-09-14): a `REG_SZ` holding 1 or 0 is `enabled` or `disabled`, as a
  `REG_DWORD` or `REG_QWORD` is, where it was a `read_failed` gap before; a value holding any other number or
  string, or of another type, is `not_configured`, where it was `read_failed`. The rule's text now says what
  was measured: with the policy off, 5.1 also stops recording the script blocks it otherwise logs by itself.
- No rule declares `access_denied` any more (ADR 0032, amended). Eleven rules did, in lines never checked
  against their collectors. Each was: on `evtx` and `prefetch` the reason means a refusal **with**
  administrator rights, which two elevated scans never met; the `posture` registry keys grant every
  account read access and a limited-token scan read them; and the test-signing and TPM queries never
  report a refusal at all. A refusal on any of these rules is now a row SS mode lists instead of a number
  it counts. A scan without administrator rights still reads as `not_admin`, which stays declared where it
  was. No rule's matching or text changed.
- `cargo xtask check-baseline` no longer counts a rule as confronted by an observation that differs from it
  only in the collector's discriminator, `fivem_dir`'s `location` (ADR 0033, amended; ADR 0044). The two
  valid-signature plugin rules were "confronted" only by the baselines' `FiveM.exe`, which is about
  another place: with `location: plugni` written into the Legacy rule and its fixtures every gate still
  passed. Both rules now carry an honest `rules/unconfronted.csv` row, which ends when a baseline holds a
  plugin file measured from a published release. **The gate measures two fewer rules than it said it
  did**; no fixture was invented to change that.
- **A signature whose chain ends at a root this PC does not trust is `unverifiable_offline`, no longer
  `invalid`** (ADR 0035, amendment of 2026-09-14). Measured on the Windows CI runner with a root deleted
  from every certificate store it was in: a genuine signature that does not carry its root answers
  `CERT_E_CHAINING`, and one that carries it answers `CERT_E_UNTRUSTEDROOT` — the same code a self-signed
  signature gives — with no network retrieval in either case. Offline the two cannot be told apart, so a
  genuine `FiveM.exe` on a PC that has not fetched its publisher's root no longer reads as a signature
  that does not verify. No rule outcome changes: every rule that reads `signature` matches both values;
  a self-signed signature is now shown as `unverifiable_offline`. The CI step and its live test assert the
  measured codes; the three "no embedded signature that verifies" rules say what that value covers.
- **Rule format 2.** `allow.signer`, a certificate subject's name, is replaced by
  `allow.signer_cert_sha256`, the SHA-256 of the signing certificate (ADR 0035). Code-signing certificates
  stolen from NVIDIA in 2022 signed malware under NVIDIA's own name, so a name-based exclusion would have
  exempted it. No rule used the old field; one that did would no longer parse, which is why
  `RULES_SCHEMA_VERSION` is now 2.
- M2 is complete as scoped, and no Prefetch, BAM or PCA rule is planned (ADR 0034). The three
  collector ADRs each deferred that rule as "a separate decision" and nobody made it. What those
  collectors emit names a program only by file name or path, `allow` compares only `sha256` and
  `signer`, so such a rule cannot exclude a legitimate program of the same name and a rename defeats
  it. **No gate refuses it**: a throwaway `prefetch` rule naming one executable passed both
  `check-rules` and `check-baseline`, while a `pca` rule on `\Downloads\` failed `check-baseline` as
  the baseline intends. `CONVENTIONS.md` §6 records the rule as enforced by review. README's milestone
  table now lists M1 and M2 as released in 0.2.0 instead of "merged, not released" and "0.1.0 is the
  only release so far".
- A PC with no Prefetch folder is now a `prefetch` run that was **measured**, with every field about a
  record gapped by the reason it used to be `Unmeasured` for (`source_absent`, or `service_disabled`),
  instead of an `Unmeasured` run with nothing in it (ADR 0037). A rule on a Prefetch record comes out
  exactly as before; the difference is the new configuration observation, listed in Self mode.

### Fixed
- Every ordinary PC reported BAM `intact: false`, with two `read: failed` rows per account in Self mode.
  Each account key under `bam\State\UserSettings` holds, beside its program records, two `REG_DWORD`
  values named `Version` and `SequenceNumber` that Microsoft does not document, and `bam` counted them as
  records it could not read. They are now counted in a new account field, `metadata_values`, and no
  longer in `values` or `rejected`; a value with one of those names that is not a number is still
  refused and shown. Measured on every account key of one Windows 11 machine (build 26220), and the same
  two refusals per account were in a 0.2.0 report from another (build 26200) (ADR 0023, amended). No
  rule reads BAM, so no evidence changed.
- One FiveM folder that could not be listed made **every** `fivem_dir` rule `unmeasured`, including the
  rules about folders that were read (ADR 0036 recorded it). A gap can now be confined to one place a
  collector reads, keyed by the field that says which place — `fivem_dir`'s `location` (ADR 0044). The
  rules that could match in the unreadable place stay `unmeasured`, the rule for a file whose signature
  could not be checked among them; the others answer from the places that were read. On the fixture
  where Legacy's program folder is denied, four of the seven rules that SS mode used to list as "could not
  check" are now `not_found` about folders that were checked. When no place at all could be read, every
  rule is `unmeasured` as before. No other collector declares such a field, and no report snapshot
  changed.
- The SS-mode consent question named the wrong scan. In the CLI and in the window app it said the
  check reads "machine security settings"; since 0.2.0 it also reads the programs running, FiveM's
  plugins folder, what Prefetch, BAM and the Program Compatibility Assistant recorded about programs
  that ran, and how many events of each kind the event logs hold. A player agreed to a narrower check
  than the one that ran. Both now list every kind of source, in the words `PRIVACY.md` uses. The window
  app's version says the reading already happened, which is true: it scans before its window opens. A
  test keyed by collector id fails when a collector is added without the question saying so.
- The CLI asked its SS-mode consent question on standard output, the stream `--json` writes the report
  to. `scan --mode ss --json > report.json` put the question into the file and left the program waiting
  for an answer to a question the player could not see. The question, the refusal line and the
  `--elevate` status lines now go to standard error, and a test runs the binary and parses standard
  output as JSON.
- `scan --elevate` in the CLI lost its report. The copy it starts runs in a console window of its own,
  and on a real Windows 11 machine that window closed less than a second after the scan finished. The
  copy now waits for Enter before it exits, and prints an error before waiting rather than after. The
  same measurement showed the window open with the report in it 5 seconds after the prompt appeared,
  and closed after Enter (ADR 0012, amended). The path through the UAC prompt itself was not run,
  because a program cannot answer the prompt.
- `PRIVACY.md` told the reader that nothing is stored "unless you click **Export**". No export or save
  button exists in the window version; the only file is one a person redirects CLI output into.
- An Event Log service that did not answer took the other `evtx` rules down with it. With the service
  suspended on the Windows CI runner, the question about a channel's configuration waited out the whole
  30-second `evtx` budget, and `event-log-file-cleared` and `event-log-file-read-only` — which read only
  the logs — came out `unmeasured / budget_spent` beside the configured-path rule. The questions now have a
  5-second bound of their own that is not taken from the 30 seconds; once it is spent the service is not
  asked again, only `configured_path`, `at_configured_path` and `max_size_bytes` are gapped
  `budget_spent`, and every log is still read (ADR 0042, amended). The bound was set against a
  measurement: on one Windows 11 machine the same two properties of all 1 243 channels took 237 ms in
  total. The CI step now also requires the other `evtx` rules not to be `budget_spent`.

## [0.2.0] - 2026-09-13

### Changed
- Every CI job has a `timeout-minutes`, and `cargo nextest` fails a test that stops making progress
  instead of running out the job's clock. Only the fuzz job was bounded. The vendored `evtx` parser's
  cycle-guard regression test says in its own doc comment that a regression there is a **hung** test
  rather than a red one, and removing the guard confirmed it — the test was still running after 100
  seconds. Without a bound the answer to that regression was the runner's six-hour default, on a job
  that then reports only that it timed out.
- The Windows live smoke prints the `rule_id` and collector of every evidence row, not the state of the
  posture rows alone. Four lines reading "found / found / unmeasured / found" said a machine had been
  measured and not which rule saw what.
- Documentation caught up with what the gates and one real Windows machine now say. "Needs admin" in
  `docs/architecture.md` is a measurement for PCA, BAM and Prefetch instead of "unverified" or "not
  measured"; the README milestone table no longer says no collector reads the four parsers; and
  `docs/rules-authoring.md`, `CONVENTIONS.md` and `AGENTS.md` describe the baseline gate's second
  question — was this rule ever put one — rather than only its first.

### Fixed
- `cargo xtask check-baseline` was green for two rules it had never compared to anything (ADR 0033).
  The gate fails only on a rule that *matches* a baseline, which a rule that was never put a question
  to satisfies for free: the only Event Log sample in this repository is a LanguagePackSetup log, so
  the two log-clearing rules — which name the `Security` and `System` channels — agreed with none of
  their three conditions on every baseline and would have passed however they were written.
  A transposed letter in that `channel:` value passes every gate too, as long as the rule's own fixtures carry the same transposition — which is what happens when one person writes both. Each rule must now also be **confronted**: some baseline
  observation has to carry the fields the rule's `match` names and come within one unsatisfied
  condition of firing it. A rule nothing confronts fails unless `rules/unconfronted.csv` carries a row
  giving a reason and what would end it, and the row itself fails once a baseline does confront the
  rule — so the fixture that closes a hole also deletes the note that recorded it. The two
  log-clearing rules have rows today: the hole is not closed, it is now reported on every run instead
  of only in an ADR.
- A failed read was counted instead of shown, if a rule happened to declare it (ADR 0032). All four
  rules that ship today named `read_failed` in `unmeasured_when`, in lines written before anything
  read that field; once ADR 0027 gave those lines teeth, a registry value this program genuinely
  could not read became a number in SS mode rather than a row. `read_failed` now joins `partial` and
  `budget_spent` as a reason a view lists whatever the rule said — all three say the artifact was
  reachable and the read of it did not finish, which is a fault rather than a kind of machine — and
  `cargo xtask check-rules` refuses a rule that names any of them, so the line cannot come back. On a
  fixture host whose registry cannot be read, an SS view that showed nothing now shows the two rules
  that could not be measured. `access_denied` stays declarable: a scan without administrator rights
  is an ordinary machine, not a fault.
- Twelve words for what could not be measured, where there were eight (ADR 0030). `source_missing` made
  two opposite statements and is now `source_absent` ("this PC has no such record to read") and
  `source_empty` ("the place this is kept is there and holds nothing"); `partial`, `not_attempted` and
  `budget_spent` are new; `not_on_this_os` and `service_disabled` existed as words with no producer and
  now have one each — PCA on a Windows older than 22H2, and Prefetch with `EnablePrefetcher` switched
  off. A Prefetch folder that was half read reported `not_found` — "looked for and not there" — and now
  reports `partial`. Every reason has a one-line wording a non-expert reads, in English and Thai, and
  none of `source_empty`, `service_disabled` or `not_on_this_os` is a finding: Windows empties BAM of
  entries older than seven days at every boot, and a Prefetch folder is routinely emptied by an
  optimiser the player ran. SS mode always lists `partial` and `budget_spent`, whatever a rule
  declared, and states `not_attempted` once above the evidence as it already did `not_admin`.
- Two gates that could not fail (ADR 0026). `cargo xtask check-rules` now rejects a rule whose
  `collector` is not a collector in this build, or whose `match` names a field that collector cannot
  emit — a misspelling used to ship as a rule that is `not_found` on every machine, which this program
  shows a player as evidence that something was looked for and was not there. The vocabulary comes from
  a new required `Collector::fields`, bound to what each collector really emits by a test over every
  fixture host. And `cargo xtask check-baseline` gains `fixtures/hosts/baseline-elevated-win11`, the
  first baseline on which `pca`, `prefetch`, `bam` and `evtx` are `Measured` rather than `Unmeasured`:
  until now a rule for any of those four passed that gate whatever it said. The four rules that ship
  today pass both unchanged.
- A rule's `match` compared strings byte for byte, so a rule naming `C:\Windows\Temp\x.exe` did not match
  an observation carrying `C:\WINDOWS\Temp\x.exe` and reported `not_found` — a silent miss shown as a
  thing looked for and not there. Strings now compare without regard to ASCII case; a rule names in
  `cased` any field it wants compared exactly, and a rule that says nothing gets the safe comparison.
  Numbers, booleans and null are unchanged and are still never coerced. No shipped rule's behaviour
  changes (ADR 0025).
- Vendored `evtx`: a `u16` multiplication in `binxml/name.rs` that overflows on a name length above
  32767. Under overflow checks it panics; in an ordinary release build it wraps silently, leaving
  `data_size` short and the cursor in the wrong place with nothing reporting it. The patch widens
  before multiplying, so an implausible length becomes an out-of-range seek and the chunk is refused
  like any other damaged chunk. `fuzz_evtx` found it on `dev` minutes after the pull request that
  introduced the parser had merged with that same job green — the fuzzer takes a random seed, so the
  regression test added for it is deterministic rather than a saved crash input.
- Vendored `evtx`: a crafted `.evtx` input made the Event Log parser **not return** — past 300 s under
  the sanitizer, past 600 s without. A chunk's string table is a set of linked chains, and the walk of
  them guarded only against an entry pointing at itself, so a chain closed into a cycle of two or more
  was walked forever, overwriting the same cache keys each time round — which is why memory never grew
  and no allocator alarm fired. The walk now stops at a position it has already cached, and that loses
  no string. This defect was recorded here as open with its location not found; both saved reproducing
  inputs now parse, and `docs/testing.md` records the exception as closed rather than open. One fixed
  defect is not a proof that this parser cannot hang, and neither document claims it is.

### Removed
- The `application-no-crc32.evtx` Event Log fixture, on finding that it carried a real machine SID
  (`S-1-5-21-…-1000`, the first user account of a real computer) in its chunk string table. It had been
  vendored and committed on the strength of a byte scan that missed it, under a provenance document
  asserting no such SID was present — an assertion that was wrong in both directions, since the
  well-known `S-1-5-18` it did claim was not there either. `fixtures/evtx/PROVENANCE.md` records the
  correction rather than quietly dropping the file. The `EventID`-as-object case it covered is now a
  unit test over `scalar`/`number`, and two tests that asserted the absence of strings only that file
  contained were trimmed, since such an assertion passes whether or not the parser works.

### Added
- The first two rules that read the Event Log, both `strength: tamper` and both `status: experimental`
  (ADR 0031): the Security log's own record that it was cleared (event 1102), and the System log's record
  that some log file was (event 104). Each pins `provider` and `channel` beside the id, because an event
  id is unique only per provider and 1102 is also an Exchange engine update and an RDP client event; each
  says in its own text that the two rows can be one action, since clearing the Security log can be
  recorded in both logs and the engine has no way to de-duplicate them. `falsepositives` leads with the
  gaming "optimiser" that clears every log on the PC in one click, which is the dominant innocent cause in
  this population, and `retention` says that a later clearing removes the record of an earlier one, so
  finding nothing means very little. A third rule — "the Security log is empty" — is **deliberately not
  written**: cleared, rotated at the size cap and never enabled are not separable from an `.evtx` file.
  `cargo xtask check-baseline` cannot measure either rule, because the one Event Log sample in this
  repository is a LanguagePackSetup log; `docs/testing.md` records that as an open false green.
- Four operators for a rule's `match`, written `field|operator` (ADR 0029): a value list meaning **or**,
  `gt`/`gte`/`lt`/`lte` on numbers and on timestamps, `startswith`/`endswith`/`contains` on text, and
  `exists`, which tells a field that was withheld from one that is absent from one nobody could read.
  Text operators fold ASCII case and `cased` still turns that off per field; timestamps are parsed rather
  than compared as text, because the collectors emit two shapes and the text order puts the later instant
  first. **A field in the run's `gaps` makes the rule `unmeasured` under every operator** — `exists: false`
  checks it before matching, since a field nobody could read is also a field that is not there.
  `check-rules` rejects an operator that is not one of these, an empty value list, a `cased` entry `match`
  compares no text of, and an operator the field's declared kind cannot take; `Collector::fields` now
  declares that kind. The four shipped rules are unaffected.
- Reports now show what the rules already said (ADR 0027). Every row carries the rule's `description`,
  and a `found` row the `falsepositives` list of what legitimately produces the same evidence — both
  were mandatory in every rule, translated into Thai, rejected by CI when empty, and rendered nowhere.
  `unmeasured_when` now does something: a reason the rule named is counted in SS mode, one it did not
  name is listed, `hidden.unmeasured` splits into expected and unexpected, and missing administrator
  rights is one scope statement above the evidence instead of a row per rule. `check-rules` rejects an
  `unmeasured_when` reason the collector cannot report. The report format gains fields and no schema
  bump, as `own_traces` and `unmatched` did; the evidence states are still exactly three.
- The `evtx` collector now reports each log's **own state** beside the events in it — the time and record
  id of the oldest and newest surviving record and the size of the file — and, per folder, how many logs
  read held no record and how many channels have any. A rule about a cleared log has to match the log,
  not one event: a gaming "optimiser" script clears every channel in one click, so a folder of empty logs
  is evidence **for** that benign explanation and never corroboration. Each field's innocent explanation,
  and the candidates rejected for having none, are in ADR 0028.
- The `evtx` collector, the last of the four parsers to reach the product: it reads every `.evtx` file
  in `%SystemRoot%\System32\winevt\Logs` and reports, per log, **how many events of each kind** it
  holds — channel, provider, event id, level, a count and the first and last time one was written —
  plus how much of the log decoded. Records are counted, never listed: a real log holds tens of
  thousands. No event's payload reaches the collector, because the parser drops it and with it the user
  names, host names, addresses, SIDs and command lines an event carries. A log that was denied, is
  larger than a host reads in one piece, or was not reached inside the collector's 30-second budget is
  **named in the report as one that was not read** and gaps the run, so a rule reports `unmeasured`
  rather than "nothing was found in the log" — an Event Log nobody could read is what someone who
  wants it unexamined would arrange. The parse runs on a worker thread so that a log that does not
  parse costs the collection its budget rather than the whole program, which until now had no window
  on screen while it scanned. No rule reads it yet (ADR 0024).
- The `bam` collector: it enumerates the Background Activity Moderator's per-account keys under
  `HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings` and reports, per registry value,
  the program's name, when BAM last saw it run, the parser's moderation state and how many bytes the
  value held — that last one because whether a value is still the documented 24 is the first sign of a
  layout this repository has never confirmed on Windows 11. **No part of the account's SID goes out**,
  hashed or otherwise: it identifies one account and one Windows installation, and the report says how
  many accounts had records instead. A path is emitted only when it begins with a drive letter, the one
  shape SS-mode redaction can reach. An absent BAM key is `source_absent`; a key that is there and
  holds nothing is `source_empty` with `values: 0`. No rule reads it yet (ADR 0023).
- Hosts can enumerate the registry and read a value's bytes: `RegistrySource` gains `subkeys`,
  `value_names` and `read_bytes`, which is what BAM needs and what no other artifact does — its value
  *names* are executable paths and its value *data* is the artifact. A key or value that is not there
  is an answer rather than a failure, as it already is for a file. Each value is bounded at 64 KiB and
  a larger one is refused whole rather than truncated; the count of subkeys and of values is
  deliberately not bounded, because a partial enumeration would read as "there was nothing else". A
  fixture writes a binary value as a map with `content:` or `from:`, the pair a file entry already uses
  (ADR 0022).
- The `prefetch` collector: it lists `%SystemRoot%\Prefetch` and reports, per `.pf` file, the
  program's name, how many times Windows recorded it running, how many run times the file still held
  and the newest of them, plus one account of how many files the folder held and how many decoded —
  an emptied Prefetch folder is `files: 0`. **The files each program loaded and the volumes it touched
  are read and never reported**: Prefetch writes loaded-file paths as `\VOLUME{…}\USERS\<account>\…`,
  which SS-mode redaction cannot reach, a raw listing of them is what SS mode promises not to show
  whether or not a name is replaced in it, and a volume serial number identifies one machine across
  two reports with no rule able to ask anything of it. Reading the folder needs an elevated token, so
  a scan without one reports `not_admin` and says in the report that it could not read the artifact.
  No rule reads it yet (ADR 0021).
- The `pca` collector, the first thing in the product to call `rongroi-parsers`: it reads the three
  Program Compatibility Assistant files under `%WinDir%\appcompat\pca` and reports, per launch record,
  the program's name, when PCA saw it run, and its path — the last of these only when the path begins
  with a drive letter, which is the one shape SS-mode redaction can reach, so that a UNC or device path
  carrying an account name is withheld rather than shown unredacted. The general databases contribute
  only how many records they held and whether every line parsed, because no position in them has an
  established meaning and one of them is a user path. A file that is there and could not be read says so
  in the report rather than being counted away. No rule reads it yet, so what it sees is listed in Self
  mode and counted in SS mode (ADR 0020).
- Hosts can read a file's bytes: `FilesystemSource::read_file` returns the contents of a file a
  collector names, which is what the four parsers in `rongroi-parsers` have been waiting for — their
  whole API is bytes in, structs out, and until now nothing on a `Host` returned bytes. A file that is
  not there is an answer rather than a failure, as it already is for a directory. The read is bounded
  at 64 MiB and a larger file is refused whole rather than truncated: the file's size is chosen by
  whoever put it on the machine being examined, and a truncated artifact would be reported as a damaged
  one. A fixture describes a file's bytes inline with `content:` or points at a file under `fixtures/`
  with `from:`. Nothing consumes it yet; the collectors are the next pull requests (ADR 0019).
- Event Log parser: Windows `.evtx` files decode to a plain struct per record — the record id, the time
  it was written, the event id, the channel, the provider and the level — and a damaged chunk costs its
  own records and nothing else, the rest of the log being returned alongside an account of what failed.
  No event is interpreted: which id means a log was cleared is a rule's judgement, not a parser's. A
  record's payload is deliberately not kept, because that is where user names, host names, addresses and
  command lines live. The binary XML decoder is the `evtx` crate, whose error type stops inside the
  parser module; it brings the unmaintained `encoding` crate with it, and `deny.toml` now carries an
  ignore for RUSTSEC-2021-0153 that states the exposure rather than waving it away (ADR 0018).
- The `evtx` crate is **vendored under `third_party/evtx/` with one patch**, rather than taken from the
  registry. Its binary-XML reader sized a `Vec` from a record's substitution count without bounding it
  against the bytes remaining, so a **crafted** 68 KiB Event Log reached a 7.7 GB allocation — measured,
  not estimated. Crafted matters: the input came out of `fuzz_evtx`, mutated from a well-formed sample,
  and an unmodified Event Log does not do this. macOS survives it, since the reservation is lazy. Windows was not tested: there the
  commit is charged up front and a failed Rust allocation aborts uncatchably, so a machine without that
  much commit available would lose the process. Either way the size is chosen by the file and not by the
  program, which is what this crate's "never panics, never aborts" contract rules out. The patch bounds the reservation by the bytes the input could actually
  contain. Both fixes are now offered upstream as
  [omerbenamram/evtx#294](https://github.com/omerbenamram/evtx/pull/294), which credits the April 2026
  reports (#291, #292, #293) rather than claiming the finding, and discloses that it was written and
  opened by an AI assistant on the account owner's instruction. The directory goes away when an
  upstream release carries the fix. Everything else
  in it is byte-identical to the published crate and `third_party/evtx/PROVENANCE.md` says how to check
  that (ADR 0018).
- `fuzz_evtx`, the fuzz layer's sixth target, seeded from the same `fixtures/evtx/` file the parser tests
  read. It covers more third-party code than any other target, and the RUSTSEC ignore above names it as
  one of the things that bounds the risk of taking that dependency. It earned that billing immediately:
  it found the unbounded allocation above before the parser was ever pushed, and with the patch reverted
  it rediscovers it from the committed fixture alone in under 90 seconds.
- `cargo xtask check-baseline`: the whole rule set is run against fixture hosts described as ordinary
  machines, through the same `scan::run` pipeline the CLI uses, and any `Found` evidence that is not
  recorded in `rules/known-fps.csv` with a written reason fails the gate — as does a row whose rule no
  longer matches, because an unused exception is a claim about the rule set that is no longer true.
  Two baseline profiles ship, and both are silent today (ADR 0017).
- Prefetch parser: Windows `.pf` files — MAM-compressed or not — decode to a plain struct with the
  executable, run count, the last eight run times, the volumes and the loaded files, with every raw
  `FILETIME` kept beside its converted timestamp. SCCA versions 30 and 31 (Windows 10 and 11) are read;
  an older or unrecognised version is a typed error rather than a wrong parse. The decompressor is the
  `prefetch-core` crate, whose error type stops inside the parser module and never reaches the rest of
  the codebase (ADR 0015).
- The fuzz layer `docs/testing.md` has promised since M2: one cargo-fuzz target per parser entry point,
  seeded from the same fixtures the parser tests read, and a CI job that builds them and runs each for 30
  seconds as a smoke gate. `fuzz/` is its own workspace because cargo-fuzz needs nightly, so the pinned
  1.98.1 toolchain builds, lints and tests everything else exactly as before (ADR 0016).
- `fuzz_prefetch`, the fuzz layer's fifth target, seeded from the same `fixtures/prefetch/` files the parser
  tests read. Prefetch is the only parser that hands bytes read from the machine to a third-party
  decompressor, and a target pointed at it is half of why ADR 0015 accepted that dependency's immaturity.
- Unmatched observations: what a collector saw that no rule matched is kept, grouped by collector, and
  listed in Self mode — the files in FiveM's plugin folder and the running processes, which no rule reads.
  SS mode counts them and lists none, because a raw listing of every file and program name is what that
  mode promises not to show. `unmatched` is a new, additive field of the report format (ADR 0014).
- `process` collector: the processes running at scan time, each with its image name and, when Windows
  will name it, the path of its image. Nothing is hashed and no process memory is read; a process whose
  path cannot be resolved is still listed, without that field. No rule reads it yet (ADR 0010).
- Own traces: aeterna-rongroi is itself running while it scans, so the report now separates the
  observations that describe the tool from evidence about the machine, and shows them in an "own traces"
  section of its own — in both Self and SS mode, because hiding "this was us" from the person watching a
  screenshare would tell them less. The section is new in the CLI output and in the desktop report, and
  `own_traces` is a new, additive field of the report format (ADR 0010).
- `rongroi-parsers`: a new crate that turns Windows artifact bytes into plain Rust structs, with its
  first two parsers — BAM registry values and the PCA text files. Parsers are pure (no OS calls, no
  `Host`, no clock, no panic on any input), so they are tested on macOS and Linux as well as Windows.
  A PCA file with a malformed line returns the lines that parsed alongside an account of the ones that
  did not, and bytes whose meaning no public source establishes are kept rather than named or dropped
  (ADR 0013).
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
- ADR 0009 claimed the `fivem_dir` collector's observations were "still visible in Self mode". They were
  not: nothing carried an observation that no rule matched, so both collectors that ship without a rule
  read the machine on every scan and the result was discarded (ADR 0014).
- Desktop app: the report header shows the program version, which the release notes ask people to check.
- Documentation that had drifted from the code. `CONVENTIONS.md` §4 named `cargo xtask scrub-check` as
  what keeps a real user name, host name or SID out of a fixture; that command has never existed, review by
  hand is all there is, and the section now says so and records the gap. ADR 0008 and ADRs 0010–0018 were
  still `proposed` for decisions that are built and merged, and ADR 0008's Context still said no release
  workflow existed. `CONTRIBUTING.md` told a contributor to run `cargo xtask new-collector`, which does not
  exist either. README's Status table called M0 "in progress" and everything after it "planned", and put
  the release pipeline in M3 although it shipped with 0.1.0; it now says which milestones are released,
  which are merged but unreleased, and that nothing reads the M2 parsers yet. `GOVERNANCE.md` still framed
  the pre-first-release steps as outstanding, ADR 0013 placed USN and Amcache in M2 against README's M3,
  and `CONVENTIONS.md` §8 said a screenshare guide exists in Thai when it exists in no language.

## [0.1.0] - 2026-09-11

### Added
- Repository foundation: licenses, NOTICE with GPL section 7 terms, AGENTS.md, CONVENTIONS.md, policies.
- Rule format v1, rules bundle embedded in the executable, evidence engine with Found / NotFound / Unmeasured.
- Secure Boot posture collector with Live and Fixture hosts.
- CLI with Self and SS modes, and an unofficial-build banner.
- Desktop app shell (Tauri 2) with consent screen and English / Thai.
- Release workflow: official Windows executables with `SHA256SUMS`, SBOMs and build attestations in a draft GitHub release (ADR 0008).
