# ADR 0056 — What Windows says this installation is

- Status: accepted — the owner asked on 2026-09-20 for the traces that popular "gaming" Windows
  modifications leave, after research into `kernelos.org` and the builds around it
- Date: 2026-09-20

## Context

A large part of the FiveM player population does not run the Windows Microsoft shipped. Two kinds of
modification are common:

- **A playbook applied over a clean install.** Atlas (`Atlas-OS/Atlas`) and ReviOS
  (`meetrevision/playbook`) are archives run by AME Wizard on an ordinary Windows installation. Both are
  open source, so what they write can be read rather than guessed.
- **A pre-modified ISO.** KernelOS (`kernelos.org`, v1.6.0 for Windows 11 23H2–26H2), Ghost Spectre,
  and images built with `tiny11builder` are installed instead of Microsoft's image. Their contents are
  not published, so nothing in this repository can name a marker they write.

The two kinds need different evidence, and neither is evidence of cheating:

1. **A playbook names itself in the registry.** Both projects write their own name where `winver` and
   Settings show it. That is a fact a reviewer can read off the screen, and it is the cheapest, least
   ambiguous reading there is.
2. **A pre-modified ISO is known by what is missing.** Its selling point is that components are gone.
   The nearest thing to a measurable fact is whether the services Windows ships with are still
   registered, and how they are set to start. A stripped image has no Defender service key at all; an
   ordinary machine with a third-party antivirus has the key and a disabled service. Those two are
   different rows, and this ADR keeps them different rules rather than one "Defender is off".

Both readings are **posture, not a trace**: a person may install any operating system on their own PC.
The rules say so in their own text (ADR 0002).

## Measured

On one Windows 11 PC (build 26220, `DisplayVersion` 25H2), 2026-09-20, with the owner's permission,
read-only, with an **elevated** token:

| Key | Value | Data |
|---|---|---|
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion` | `ProductName` | `Windows 10 Home` |
| | `EditionID` | `Core` |
| | `CompositionEditionID` | `Core` |
| | `DisplayVersion` | `25H2` |
| | `CurrentBuild` | `26220` |
| | `UBR` | `0x2514` |
| | `BuildLabEx` | `26100.6.amd64fre.ge_release_flt.260716-1700` |
| | `InstallationType` | `Client` |
| | `RegisteredOrganization` | present, empty |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation` | `Manufacturer` | `Msi` |
| | `Model` | `MS-7A36` |
| | `SupportURL` | `http://www.msi.com/` |
| `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Start` | `WinDefend`, `EventLog`, `SysMain`, `DPS`, `WSearch`, `DiagTrack` | `2` (automatic) |
| | `wuauserv`, `WerSvc` | `3` (manual) |

Two of those measurements decide rules that were considered and **not** written:

- `ProductName` reads `Windows 10 Home` on a genuine Windows 11 25H2 machine. Microsoft never updated
  the string. No rule may treat a `ProductName` that disagrees with the build as a modification.
- An ordinary retail PC carries OEM information — a board vendor's name, model and support URL. No rule
  may treat the presence of OEM information as a modification; only the specific strings the two
  playbooks write are matched.

A limited-token measurement was **not** made, so `access_denied` stays declarable for this collector
rather than being ruled out the way ADR 0054 ruled it out for `net_config`.

### What the two playbooks write, read from their own source

Both were read from a clone of the published repository, not from memory:

| Project | Source (commit) | Written |
|---|---|---|
| Atlas | `Atlas-OS/Atlas` `1ed9630616b29f0c7974e8bd76a94fc06f60388c`, `src/playbook/Configuration/tweaks/misc/config-oem-information.yml` | `RegisteredOrganization` = `Atlas Playbook <version>`; `OEMInformation\Model` = the same; `OEMInformation\Manufacturer` = `Atlas Team`; `OEMInformation\SupportURL` = `https://discord.atlasos.net` |
| ReviOS | `meetrevision/playbook` `ee5990aae435bc03d7c4d65a9e25fe95a08d31f5`, `src/Configuration/Tasks/final.yml` | `RegisteredOrganization` = `ReviOS 10 <version>` or `ReviOS 11 <version>`; `OEMInformation\Model` = the same |

Atlas also creates `HKLM\SOFTWARE\AtlasOS` and `%windir%\AtlasModules`, and ReviOS installs
`%ProgramFiles%\Revision Tool`. Those are folders and keys rather than values, no baseline in this
repository carries one, and a rule for them would be unconfronted (ADR 0033). They are left for a later
change; the four values above are what this one reads.

## Decision

A new standard-tier collector, **`os_image`**, reads one observation holding what Windows says this
installation is, in the shape `posture` uses (ADR 0011): every value that could be read is a field, and
every value that could not is a `gaps` entry under the field's own name, so a rule that needs it is
`unmeasured` rather than `not_found`.

- **Identity**, from `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`: `product_name`, `edition_id`,
  `composition_edition_id`, `display_version`, `current_build`, `ubr`, `build_lab_ex`,
  `installation_type`, `registered_organization`.
- **OEM information**, from `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation`:
  `oem_manufacturer`, `oem_model`, `oem_support_url`.
- **Services Windows ships with**, from `HKLM\SYSTEM\CurrentControlSet\Services\<name>`: one text field
  per service — `service_windefend`, `service_wuauserv`, `service_wersvc`, `service_eventlog`,
  `service_sysmain`, `service_dps`, `service_wsearch`, `service_diagtrack` — holding `boot`, `system`,
  `automatic`, `manual`, `disabled`, or `absent` when the service key is not there at all. The key's
  absence is a **statement about the machine**, not a gap: it is the whole point of the reading.

**`RegisteredOwner` is not read.** It holds the name of the person who set the PC up — on the measured
machine, a first name. It would add nothing to either reading and it is exactly the kind of value
`AGENTS.md` tells collectors not to collect.

Seven rules ship with it, all `experimental`, all `strength: posture`, in two groups: three that match
the strings the two playbooks write, and four about services Windows ships with. Each names in its
`falsepositives` the ordinary machine that produces the same row — a third-party antivirus for the
Defender rules, a corporate policy for Windows Update, and for every rule, the plain fact that a person
may run whatever operating system they like on their own PC.

## Consequences

- A pre-modified ISO that names itself nowhere is not identified as that ISO. What the report shows is
  which components are gone, which is what a reviewer can act on anyway.
- The version numbers in `Atlas Playbook <version>` and `ReviOS 11 <version>` are matched with
  `startswith`, so a new release of either does not need a change here.
- A player who removes the value, or renames it, defeats the first group. The second group does not
  depend on any string a modification chooses.
- Three baseline hosts gain the measured identity, OEM and service values above, so every one of the
  seven rules is confronted (ADR 0033) and none needs a `rules/unconfronted.csv` row.
