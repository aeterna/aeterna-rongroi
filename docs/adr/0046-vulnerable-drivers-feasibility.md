# ADR 0046 — Vulnerable drivers: what can be read, and what a list would cost

- Status: accepted — the recommendation below. The measurements under "Before any code" exist, except the
  baseline, which is made from a run of the collector itself
- Date: 2026-09-14
- Amended: 2026-09-14, with measurements on a GitHub-hosted runner ("Measured on a runner")
- Amended: 2026-09-15, with measurements on a Windows 11 PC ("Measured on a PC") and the LOLDrivers count
  ("The data file, counted")

## Context

README's milestone table lists a "vulnerable-driver list" under M3 as planned. Nothing reads drivers
today. No collector, rule, fixture or dependency mentions them.

### What a vulnerable driver is

Microsoft describes the class in its own blocklist page
([Microsoft recommended driver block rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules),
read 2026-09-14): "malicious actors are turning to exploit vulnerabilities in legitimate and signed kernel
drivers to run malware in kernel". The drivers it blocks have "Known security vulnerabilities that an
attacker could exploit to elevate privileges in the Windows kernel", or are malware, or have "Behaviors
that aren't malicious but circumvent the Windows Security Model".

Such a driver is signed, so Windows loads it. What it lets a program do once loaded is the driver's own
property, not the program's. This project reads a PC for "machine posture that makes cheating easier"
(AGENTS.md) as well as for traces. A driver like that on the machine is posture of that kind. It is not a
trace of anyone using it, and the same driver ships inside ordinary hardware utilities (Question 3).

### The idea this ADR examines

Compare the drivers installed on the PC with a published list of vulnerable drivers, by file hash. The
list would be reviewed in a pull request and embedded in the binary like every rule (ADR 0004), never
fetched at runtime (ADR 0003).

Four questions decide whether that should be built, and how:

1. Which list, under what licence, and in what form does it enter this repository?
2. How does this program see which drivers are on the PC without changing anything, and with what rights?
3. What does a match mean, and what does it cost the reader and the player?
4. Can this program read whether Microsoft's own blocklist is switched on?

This ADR answers from sources and from this repository's code. **Nothing was measured on a Windows
machine for it**, and the measurements a collector would need first are listed under "Before any code".
No collector code, rule, fixture or dependency is part of it.

## Question 1 — the list

### LOLDrivers

[`magicsword-io/LOLDrivers`](https://github.com/magicsword-io/LOLDrivers) is a community-maintained
catalogue. Read on 2026-09-14:

- **Licence.** The repository's `LICENSE` is the Apache License 2.0. Its top level holds no `NOTICE` file
  (GitHub contents API).
- **Size.** 2,390 drivers, by the repository's own badge. Each entry can list several samples, so the
  number of hashes is larger. It was not counted.
- **Form.** One YAML file per driver under `yaml/`. An entry has a `Category` — `vulnerable driver` or a
  malicious category — and a `Verified` flag. Each sample under `KnownVulnerableSamples` carries `MD5`,
  `SHA1`, `SHA256`, and a separate `Authentihash` with its own MD5, SHA-1 and SHA-256.
- **The repository also holds driver binaries** under `drivers/`. This project must never copy them. A
  signed, exploitable kernel driver is the same hazard class as the cheat binaries and loaders
  that `rules/AGENTS.md` says never to commit. Only hashes and the entry's id and file name would be taken.
- **Update cadence.** The README says it is continuously updated. No schedule was found.

One entry, read on its page ([RTCore64.sys](https://www.loldrivers.io/drivers/e32bc3da-4db1-4858-a62c-6fbe4db6afbd/)),
shows why the Authentihash is recorded separately. It lists three `RTCore64.sys` samples, each with a
different file SHA-256 and a different Authentihash SHA-256.

#### How the list would enter this repository

`rules/` is CC-BY-SA-4.0 (`rules/AGENTS.md`, `REUSE.toml`). A hash table taken from LOLDrivers is
Apache-2.0 material. **Whether Apache-2.0 material can be relicensed under CC-BY-SA-4.0 was not
established, and this design does not need it to be.** This repository already keeps third-party material
under its own licence in its own files, annotated in `REUSE.toml`:

- `fixtures/evtx/*.evtx` — Apache-2.0, "2019 Omer Ben-Amram", with `fixtures/evtx/PROVENANCE.md`;
- `third_party/evtx/**` — MIT OR Apache-2.0, with `third_party/evtx/PROVENANCE.md`.

The list would follow that pattern: one data file holding only the fields a rule needs, annotated
Apache-2.0 with LOLDrivers' copyright, beside a `PROVENANCE.md` naming the upstream commit, the date it was
taken, the filter applied and how to reproduce the file from that commit. The rule that uses it stays
CC-BY-SA-4.0 text. Apache-2.0 is on `deny.toml`'s allow-list, which lists licences "compatible with
distributing the whole program under GPL-3.0-or-later".

Taking the data means downloading it from GitHub at a pinned commit. That is done once per update, by a
person, in the pull request that updates the file. The program never does it.

#### Which entries

| Choice | What it would say |
|---|---|
| **Only `Category: vulnerable driver`** | "A signed driver with a known weakness is installed." Posture, as above |
| Also the malicious categories | "A driver catalogued as malware is installed." That is a malware finding. This program does not claim to detect malware, and a `found` row with that meaning would need its own rule text and its own review |

### Microsoft's blocklist

Microsoft publishes its list as an App Control policy, downloaded from `aka.ms/VulnerableDriverBlockList`,
applied as a signed `SiPolicy.p7b`. The page says "The blocklist is updated quarterly", and that the
downloadable list "usually contains a more complete set of known vulnerable drivers than the version in
the OS and delivered by Windows Update".

It is not proposed as this program's list:

- Reading it means a parser for a signed PKCS#7 file wrapping an App Control policy. That is a new parser
  over a binary format, with the bar ADR 0013 and ADR 0018 set, where LOLDrivers needs no parser in the
  program at all: the data file is built before compile time.
- The terms of the download were not read.
- On a PC where the blocklist is enforced, Windows already refuses to load what it lists (Question 4).
  A report that repeats Microsoft's list adds least exactly where Windows already acts on it.

## Question 2 — seeing which drivers are on the PC

### Registered driver services — the registry

Microsoft documents where a driver service lives. `CreateServiceW` "creates a key with the same name as the
service under the following registry key: **HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Services**",
and stores values there including `Type` ("Service type specified by *dwServiceType*") and `ImagePath`
("Name of binary file")
([CreateServiceW](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew),
read 2026-09-14). The same page gives the two driver types: `SERVICE_KERNEL_DRIVER` `0x00000001`, "Driver
service", and `SERVICE_FILE_SYSTEM_DRIVER` `0x00000002`, "File system driver service".

What this repository already has for it:

- `RegistrySource::subkeys` lists the keys under `Services` without recursing (ADR 0022).
- `RegistrySource::read_value` returns `Type` as `RegistryData::Dword` and `ImagePath` as
  `RegistryData::Text`, "as stored: environment variables in an expandable string are not expanded"
  (`crates/rongroi-host/src/lib.rs`).
- `FilesystemSource` already hashes a file for `fivem_dir` (`sha256`).

So this path needs **no new Windows API, no new `windows` feature and no new crate**. `windows-registry`,
which the live registry reader uses, is pinned apart from the `windows` features.

What it needs that does not exist:

- **A resolver from `ImagePath` to a file.** Driver services write paths in more than one form. No code in
  `crates/` resolves `\SystemRoot\` or `\??\` prefixes today (`git grep`, 2026-09-14). The forms that occur
  and what Windows does when `ImagePath` is absent are not established from a primary source here. A
  resolver must turn every path it reports into the drive-letter form, because that is the one shape
  SS-mode redaction reaches (ADR 0023).
- **Rights, not measured.** Whether a limited token can list every subkey of `Services`, read `Type` and
  `ImagePath` in each, and open each driver file to hash it, is not known. This project states rights only
  after measuring them (ADR 0033), so the collector's row in `docs/architecture.md` could not be written
  yet.

What it sees and does not see:

- It sees drivers **registered** at the moment of the scan, loaded or not.
- It does not see a driver that was registered, loaded and removed before the scan. What a scan reads is
  the machine as it is when the scan runs. The rule's `retention` has to say so.

### Loaded modules — not proposed

Two ways exist to ask which drivers are loaded now. Neither is proposed:

| Candidate | Why not |
|---|---|
| `NtQuerySystemInformation` with `SystemModuleInformation` | Not among the classes Microsoft documents on [NtQuerySystemInformation](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation), and not defined anywhere in the `windows` 0.62.2 sources (searched 2026-09-14). The layout would come from reverse-engineered headers, the reason ADR 0038 dropped a DMA reading. The page also says the function and its structures "are internal to the operating system and subject to change from one release of Windows to another" |
| `EnumDeviceDrivers` with `GetDeviceDriverFileNameW` | Documented, feature `Win32_System_ProcessStatus` in 0.62.2 (not enabled here). But "Starting in Windows 11 Version 24H2, **EnumDeviceDrivers** will require **SeDebugPrivilege** to return valid *ImageBase* values … the returned *lpImageBase* array will contain addresses that are all NULL" ([EnumDeviceDrivers](https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-enumdevicedrivers)). The file name is looked up by that address, so on current Windows this path needs `SeDebugPrivilege`. That privilege opens any process on the machine. ADR 0038 allows enabling a privilege only for one named read, and a privilege of that reach would need its own ADR |

"Loaded now" would be a stronger statement than "registered". It reopens in its own ADR if a documented
interface gives driver file names without `SeDebugPrivilege`.

### Which hash

| Hash | Cost | What it misses |
|---|---|---|
| **`sha256` of the file** | None new. The field exists, `allow` compares it, and it is the glossary's "only file hash" (`CONVENTIONS.md`) | The same driver with its signature replaced or stripped has a different file SHA-256 |
| Authenticode hash (`Authentihash`) | `CryptCATAdminCalcHashFromFileHandle2` is in `src/Windows/Win32/Security/Cryptography/Catalog/mod.rs` of `windows` 0.62.2, under `Win32_Security_Cryptography_Catalog`, which this repository already enables for `WinVerifyTrust` (ADR 0035). No new feature, but new `unsafe` code in `rongroi-host-windows`, and a second file hash under its own glossary row — `allow` could not compare it | Nothing the file-hash column catches |

The first collector would use `sha256` only. The Authenticode hash is a separate decision, the way ADR 0035
gave signature checking its own ADR before `fivem_dir` grew rules from it.

## Question 3 — what a match means, and what it costs

### What it can show

A match shows that a file whose content LOLDrivers lists as a vulnerable driver is registered as a driver
service on this PC, at the moment of the scan. It does not show that the driver is loaded, that anything
used it, or why it is installed.

### Who else has it

The RTCore64.sys entry above is the MSI Afterburner driver. LOLDrivers lists its samples as published by
Micro-Star. MSI Afterburner is a GPU overclocking and monitoring utility of the kind this project's
audience runs. **On gaming PCs a `found` row from this rule will often be a hardware utility.** The rule's
`falsepositives` has to name that category plainly: overclocking, fan and RGB control, and hardware
monitoring tools. Search results name more drivers of that kind. They were not opened on LOLDrivers for
this ADR, so none is named here.

### Strength

| Strength | In SS mode (ADR 0014, ADR 0027) | Fits |
|---|---|---|
| **`posture`** | `found` and `not_found` are both listed: staff see that the check ran | What the evidence is: a property of how the machine is set up. It sits beside memory integrity, which the report already shows, and Microsoft's page ties the two together: the blocklist "is also enforced when either memory integrity … Smart App Control, or S mode is active" |
| `presence` | `not_found` is counted, not listed | The same strength ADR 0041 gave an Amcache hash. It reads as a trace of something having been put there, which is more than the evidence says |

### What the report would show of the player's drivers

A driver service list names the player's hardware and some of their software: a GPU vendor, a VPN, a
virtualisation product, peripherals. Every observation no rule matches becomes an unmatched observation,
listed in Self mode and counted in SS mode (ADR 0014).

| Way | Cost |
|---|---|
| **Emit every driver service**: its service name, its resolved path and its `sha256` | Self mode lists the player's own drivers to the player. SS mode lists none of them, only matches. This is what `process` already does with running programs, and `PRIVACY.md` already describes that. The consent question and `PRIVACY.md` would name drivers in the same pull request |
| Emit only services whose hash a rule names | Nothing else leaves the collector. It needs a seam from the rules bundle into a collector, which ADR 0041 found `docs/architecture.md`'s pipeline does not have |
| Emit only non-Microsoft drivers | Needs a signature check per driver to decide, and "signed by Microsoft" is not what the rule asks |

### A rule that names thousands of hashes

A `match` list already means "any of them" (ADR 0029), so `sha256: [...]` works in the engine today. Three
things stand against writing the hashes into `rule.yaml`:

- `rule.yaml` is CC-BY-SA-4.0, and the hashes are Apache-2.0 material.
- `cargo xtask rules-reference` would render every hash into `docs/rules-reference*.md`.
- A reviewer of an update would read a diff of rule text that is really a data refresh.

| Form | Cost |
|---|---|
| **The rule names the data file; the bundle build expands it into the rule's `match`** | The engine and `Evidence` are unchanged. A rule-format change: `check-rules` validates the file, and `rules-reference` shows the file and its row count instead of the hashes |
| A new operator, e.g. `sha256\|in_file:` | A change to the operator vocabulary of ADR 0029, and to the engine |
| Hashes inline in `rule.yaml` | The three problems above |

Which LOLDrivers entry matched should be visible to the reader, so that "why is this listed" has an answer
they can check. The data file carries each hash's LOLDrivers id and file name. How that reaches the row
without a network link is a detail for the collector's own ADR.

### Baselines

A new collector needs a `baseline-*` host that reads it (`crates/rongroi-collectors/AGENTS.md`), and a
baseline "asserts that a machine like this is unremarkable" (`fixtures/hosts/PROVENANCE.md`). It must be
measured, not invented.

A driver service list from anyone's own PC is not publishable: it describes that person's hardware and
software. A GitHub-hosted Windows runner is a machine whose driver list belongs to a published image and to no person.
A baseline measured there would show the rule quiet on that image. It would not show the rule quiet on a
gaming PC, and its `PROVENANCE.md` row would have to say so.

A rule matching `sha256` alone has one condition, so any baseline driver observation carrying a `sha256`
confronts it (ADR 0033).

## Question 4 — whether Microsoft's blocklist is on

Microsoft's page: "Since the Windows 11 2022 update, the vulnerable driver blocklist is enabled by default
for all devices, and can be turned on or off via the Windows Security app. Except on Windows Server 2016,
the vulnerable driver blocklist is also enforced when either memory integrity, also known as
hypervisor-protected code integrity (HVCI), Smart App Control, or S mode is active."

**No Microsoft page read for this ADR names a registry value or an API for that switch.** The blocklist
page names none. [KB5020779](https://support.microsoft.com/en-us/topic/kb5020779-the-vulnerable-driver-blocklist-after-the-october-2022-preview-release-3fcbe13a-6013-4118-b584-fcfbc6a09936)
sends the reader to the Windows Security app. A value named `VulnerableDriverBlocklistEnable` appears in
answers on Microsoft's Q&A forum, some under `HKLM\SYSTEM\CurrentControlSet\Control\CI\Config` and some
under `…\CI\Policy`. Forum answers disagreeing about the key is not a documented source.
`SystemCodeIntegrityInformation`, which `posture` already reads, documents no blocklist bit.

So the switch is not read, for the reason ADR 0038 gave for Kernel DMA Protection. It reopens when
Microsoft documents a programmatic interface for it. Memory integrity, which the report already shows,
is the documented condition under which the blocklist is enforced whatever the switch says.

## Recommendation

1. **List:** LOLDrivers, `Category: vulnerable driver` only, `SHA256` only. Vendored as a trimmed data
   file under Apache-2.0 with a `PROVENANCE.md`, updated by pull request. Never its binaries. Never
   fetched by the program.
2. **Source:** registered driver services in the registry, with `sha256` of the resolved file. Loaded
   modules and the Authenticode hash each wait for their own ADR.
3. **Strength:** `posture`.
4. **Privacy:** emit every driver service, as `process` emits every process. `PRIVACY.md` and the consent
   question name drivers in the same pull request.
5. **Rule form:** the rule names the data file, and the bundle build expands it.
6. **Microsoft's switch:** not read.
7. **Order:** nothing is written until the measurements below exist.

## Before any code

Each of these is a measurement or a decision, written into the collector's own ADR:

1. **Rights, on a real Windows 11 PC, with a limited token and an elevated one:** listing
   `HKLM\SYSTEM\CurrentControlSet\Services`, reading `Type` and `ImagePath` in each driver service, and
   opening each resolved file to hash it. Only counts and error codes are recorded, never a service name
   or path. On a person's own PC, a limited-token run is not arranged by changing that machine, so it is
   that person's to run or to decline.
2. **The `ImagePath` forms** that occur, from the same run on a GitHub-hosted runner, where the names
   belong to a published image. From that: the resolver's cases, and what an absent `ImagePath` means,
   with a primary source or a measurement for each.
3. **Cost:** how many driver services, how many bytes hashed, how long, on the same runner. Whether the
   collector needs a budget follows from that.
4. **The data file:** how many LOLDrivers samples in the chosen category carry a `SHA256`, counted at the
   pinned commit when the file is made.
5. **A baseline** from the runner, with its limitation written in `fixtures/hosts/PROVENANCE.md`.

## Measured on a runner

**Where and how.** One GitHub-hosted runner, image `windows-2025-vs2026`, Windows Server 2025 Datacenter
build 26100, on 2026-09-14: workflow run [`34868203532`](https://github.com/aeterna/aeterna-rongroi/actions/runs/34868203532), commit `077a7e0` on a throwaway branch that was deleted afterwards. The
probe was a PowerShell script compiling C# at run time. It printed counts, forms and error codes and
nothing else, and it is not kept in this repository. It ran under three tokens:

- **elevated:** the runner's own token. GitHub's runners run as administrator with UAC off
  (`.github/workflows/windows.yml`);
- **restricted:** a token made from that one with `CreateRestrictedToken`, Administrators and
  `S-1-5-114` deny-only and privileges removed with `DISABLE_MAX_PRIVILEGE`, used by impersonation. It keeps the
  elevated token's integrity level, so it is not a UAC limited token;
- **standard user:** a local account created for the run, not a member of Administrators, running the
  probe through a scheduled task. That is the closest the runner comes to an ordinary account.

The runner and the account were discarded with it.

| | Elevated | Restricted | Standard user |
|---|---|---|---|
| Keys directly under `HKLM\SYSTEM\CurrentControlSet\Services` | 764 | 764 | 764 |
| Of those, opened for reading | 764 | 764 | 764 |
| Driver services: `Type` 1 or 2 | 422 | 422 | 422 |
| Driver files resolved, opened and hashed with SHA-256 | 422 | 422 | 422 |
| Bytes hashed | 147 217 632 | 147 217 632 | 147 217 632 |
| Time for all of the above | 15.5 s | 0.23 s | 0.28 s |
| `EnumDeviceDrivers`: entries / with a non-null base | 257 / 257 | 257 / 0 | 257 / 0 |

The first pass read the files cold. The later passes read files the system had just cached, so their
times say nothing about a scan.

**`ImagePath` forms**, of the 422 driver services:

| Form | Services |
|---|---|
| `System32\…`, relative | 218 |
| `\SystemRoot\…` | 188 |
| absent | 14 |
| `\??\…` | 2 |
| a drive letter, `%…%`, quoted, or anything else | 0 |

Every `ImagePath` present was `REG_EXPAND_SZ` (408).

**An absent `ImagePath`.** For all 14, `%SystemRoot%\System32\drivers\<service name>.sys` existed and was
hashed, and 9 of the 14 were loaded under that file name (`EnumDeviceDrivers`, elevated). That fits Windows
using that path when the value is absent. It is one image's evidence, not a documented rule.

### What that settles, and what it does not

1. **Rights, on this image:** a token without Administrators lists every driver service, reads `Type`
   and `ImagePath`, and hashes every driver file. Measurement 1 asked this of a real Windows 11 PC. A
   runner has only Microsoft's drivers under `%SystemRoot%`; a gaming PC keeps third-party drivers in other
   folders with other ACLs, and those were not reached. Measurement 1 stays open for a PC.
2. **Resolver cases:** the four forms above. Forms that did not occur here, a drive letter from a
   third-party installer among them, are not handled by guessing: a form the resolver does not know leaves
   that file's `sha256` a gap.
3. **Cost:** 422 files and about 140 MiB, 15.5 seconds cold. That is half of `evtx`'s whole 30-second budget
   (ADR 0024) on a machine with no third-party drivers, so the collector needs a budget of its own, and
   hashing is where it goes.
4. **`EnumDeviceDrivers` without Administrators returns no base addresses on build 26100**, as
   Microsoft's page says of 24H2. Question 2's reason for not proposing it now rests on a measurement too.
5. **The data file** (measurement 4) was not counted: that needs the LOLDrivers data downloaded, which is
   done in the pull request that makes the file.
6. **A baseline** (measurement 5): this run shows the runner has 422 driver services to describe. The
   baseline fixture is made from a run of the collector itself, so that its observations have the
   collector's shape, not from this probe's counts.

## Measured on a PC

**Where and how.** One Windows 11 PC, version 25H2, build 26220, on 2026-09-15, at its owner's request. A
PowerShell script read the registry through .NET and hashed each file on a stream opened for reading with
every share mode, the access `std::fs::File::open` asks for. It printed counts, forms and error codes and
nothing else: no service name and no path. It ran twice:

- **elevated:** an administrator's token;
- **limited:** the same account's filtered token, through a scheduled task created with the limited run
  level for this run and deleted afterwards. A standard account that is not an administrator was not run
  on this PC; the runner's standard account covers that case on its image.

The script and the task were deleted from the PC afterwards. Nothing else on it was changed.

| | Elevated | Limited |
|---|---|---|
| Keys directly under `HKLM\SYSTEM\CurrentControlSet\Services` | 870 | 870 |
| Of those, opened for reading | 870 | 870 |
| Driver services: `Type` 1 / `Type` 2 | 425 / 39 | 425 / 39 |
| Driver files resolved | 463 | 463 |
| Distinct files among them (services sharing one file) | 456 | 456 |
| Driver files opened and hashed with SHA-256 | 463 | 463 |
| Errors opening a key or a file | 0 | 0 |
| Bytes hashed | 299 977 544 | 299 977 544 |
| Time for all of the above | 8.72 s, the first pass | 1.38 s |

Whether the files were already in the system's cache on the first pass was not controlled: the PC was in
use, and a loaded driver's file may be. The time bounds nothing.

**Where the files are**, of the 463:

| Folder | Files | Hashed without Administrators |
|---|---|---|
| `%SystemRoot%\System32\drivers` | 419 | 419 |
| `%SystemRoot%\System32\DriverStore` | 36 | 36 |
| elsewhere under `%SystemRoot%` | 4 | 4 |
| `Program Files`, outside `%SystemRoot%` | 4 | 4 |

**`ImagePath` forms**, of the 464 driver services:

| Form | Services |
|---|---|
| `\SystemRoot\…` | 233 |
| `System32\…`, relative | 206 |
| `\??\` and a drive letter | 12 |
| absent | 12 |
| `SysWOW64\drivers\…`, relative | 1 |
| a bare drive letter, `%…%`, quoted, `\??\` without a drive letter, or anything else | 0 |

Every `ImagePath` present was `REG_EXPAND_SZ` (452). For all 12 absent, `%SystemRoot%\System32\drivers\<service
name>.sys` existed. The `SysWOW64\` service resolved under `%SystemRoot%` to a file that existed. It did not
occur on the runner, and the script only found it because it counted what matched no known form.

### What the PC settles, and what it does not

1. **Rights (measurement 1):** on this PC, the limited token lists every driver service, reads `Type` and
   `ImagePath`, and hashes every driver file, including the 40 in `DriverStore` and `Program Files`. It is
   one PC. A driver installed with an ACL that refuses its users was not met, and the collector reads a
   refused file as a gap, as it does any other.
2. **Resolver cases:** five forms now, from two machines. Two are relative paths, under `System32\` and
   `SysWOW64\`, and both resolved under `%SystemRoot%`. No primary source read here says Windows resolves
   every relative `ImagePath` against `%SystemRoot%`. The collector's own ADR chooses between naming the two
   folders measured and treating any relative path that way, and says which evidence it rests on.
3. **Cost:** twice the runner's bytes on a PC with third-party drivers. Hashing stays where the time goes,
   and the budget of its own that the runner's numbers called for stands.

## The data file, counted

Counted on 2026-09-15 at LOLDrivers commit
[`1c60ea1`](https://github.com/magicsword-io/LOLDrivers/tree/1c60ea1c8909396fe294c76aaafae4923b6dbea1),
from `yaml/` only, downloaded with a sparse checkout that fetched no file under `drivers/`. Every one of
the 687 files parsed as YAML.

| | `vulnerable driver` | `malicious` |
|---|---|---|
| Entries | 565 | 122 |
| Entries with `Verified` true | 493 | 118 |
| Samples under `KnownVulnerableSamples` | 2 045 | 345 |
| Samples with a 64-hex-digit `SHA256` | 1 948 | 337 |
| Distinct `SHA256` values | 1 865 | 316 |
| Distinct `SHA256` values from verified entries only | 1 847 | — |
| Samples with no file `SHA256` | 97 | 8 |
| Of those, samples with an `Authentihash` `SHA256` | 78 | — |

No `SHA256` appears in both categories. The README badge's "Drivers 2390", quoted under Question 1, is
still 2,390 at this commit. It equals the number of samples across both categories (2,045 + 345), not the
687 entries.

What that means for the recommendation:

- **Size:** 1,865 distinct hashes. A `match` list of that length is data the bundle build expands, as
  Question 3 recommends, not text a reviewer reads.
- **What a file hash misses in the list itself:** 97 samples have no file `SHA256`; an Authenticode hash
  would reach 78 of them. That is a count for the Authenticode hash's own ADR, not a change to this one.
- **Verified:** taking only verified entries drops 18 hashes. The collector's own ADR decides whether an
  unverified entry is in the file.
- **Also recorded, not a decision:** each sample carries `LoadsDespiteHVCI`. Among the vulnerable drivers'
  distinct hashes, 324 say `TRUE`, 1,315 say `FALSE` and 226 carry no value. The report already shows
  memory integrity (`posture`); whether a match should be read beside it is for the rule's own text.

## What is not established

- Rights for a standard account that is not an administrator on a PC, and for a driver file whose ACL
  refuses its users.
- A primary source for how Windows resolves a relative `ImagePath`, and for the default when it is absent.
- Whether any Microsoft document names the blocklist switch. The pages read here do not.
- The download terms of Microsoft's blocklist.
- Which other hardware-utility drivers LOLDrivers lists. Only RTCore64.sys was opened.

## Consequences

- No code, no rule, no fixture, no dependency. `Cargo.lock`, `deny.toml` and the report are unchanged.
- Accepted by the owner on 2026-09-14, with all seven points of the recommendation as written.
- README's M3 row links here: the vulnerable-driver list is designed, and waits on the measurements under
  "Before any code".
- Amended on 2026-09-15: the rights, forms, cost and data-file measurements exist. The collector's own ADR
  comes next, with the resolver's cases, the budget, whether unverified entries are in the data file, and
  how the matched LOLDrivers entry reaches the row. Still no code, rule, fixture or dependency here.
