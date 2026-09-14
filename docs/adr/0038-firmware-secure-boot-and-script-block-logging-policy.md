# ADR 0038 — Secure Boot as the firmware reports it, the script block logging policy, and no Kernel DMA Protection

- Status: accepted
- Date: 2026-09-13

## Context

Three more machine settings were proposed for the `posture` collector:

1. whether a machine policy turns **PowerShell script block logging** off;
2. a second, independent reading of **Secure Boot** — the firmware's own — beside the registry value
   `UEFISecureBootEnabled` that `secure_boot` has read since M0, and a rule for the two disagreeing;
3. the state of **Kernel DMA Protection**, as posture.

The first is one more registry value. The second is a new kind of source: this program has never read a
firmware variable, and the read needs a privilege this program has never enabled. The third turned out to
have no documented source at all. A new kind of source is an ADR (CONVENTIONS.md §8), and so is a
decision not to read something for a reason a later contributor would otherwise have to rediscover.

Every Windows API, feature gate, constant and registry path below was read in the `windows` 0.62.2 sources
or on Microsoft Learn on 2026-09-13 rather than recalled, and each quotation carries its link.

## Decision

### 1. `script_block_logging`: three values, one rule on the explicit one

**Where the policy is.** Microsoft's Windows PowerShell 5.1 documentation enables script block logging by
writing `EnableScriptBlockLogging` under `HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging`
([about_Logging](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging?view=powershell-5.1)).
The collector reads exactly that value, as a DWORD, through the existing `RegistrySource::read_u32`.

**Not configured is not off.** The same Group Policy lives under Computer Configuration and User
Configuration, and Microsoft states which wins:

> "Group policy settings in the Computer Configuration path take precedence over Group Policy settings in
> the User Configuration path."
> — [about_Group_Policy_Settings](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings?view=powershell-5.1)

So the field has three values and none of them is a gap:

| Value | Registry | What it says |
|---|---|---|
| `enabled` | DWORD 1 | a machine policy turns it on |
| `disabled` | DWORD 0 | a machine policy turns it off, and no per-user policy overrides a machine one |
| `not_configured` | key or value absent | no machine policy. A per-user policy this program does not read may apply |

A value of another number, or of another type, is a `read_failed` gap: it is there and names nothing this
program can name. *(Superseded 2026-09-14: Windows PowerShell 5.1 was measured, and the mapping now follows
it — see "Amendment of 2026-09-14" below.)* That is not hypothetical — Microsoft's own snippet writes the value with
`Set-ItemProperty … -Value "1"`, which is a string. How Windows PowerShell 5.1 treats a string is not
established here; PowerShell 7, whose source is public, only honours an integer 0 or 1 for this setting
and reads the machine key before the user key
([`Utils.cs`](https://github.com/PowerShell/PowerShell/blob/master/src/System.Management.Automation/engine/Utils.cs),
`TrySetPolicySettingsFromRegistryKey` and `GetPolicySettingFromGPO`). A gap is the answer that cannot be
wrong about either.

**Why an explicit 0 differs from nothing, and is worth a rule.** In PowerShell 7's source, a script block
whose content matches PowerShell's built-in list of suspicious patterns is logged even when script block
logging is not turned on — *unless* the setting is explicitly `false`, in which case it is skipped
([`CompiledScriptBlock.cs`](https://github.com/PowerShell/PowerShell/blob/master/src/System.Management.Automation/engine/runtime/CompiledScriptBlock.cs),
`LogScriptBlockCreation`). So on that engine "not configured" still leaves a record of some scripts and
"disabled" leaves none. **That Windows PowerShell 5.1 behaves the same way is not established**: it is
closed source, and the claim is made in third-party write-ups this project did not verify. The rule text
therefore says only what is documented — with the policy off, PowerShell writes fewer records of the
scripts it runs — and not how many fewer.

The rule is `script-block-logging-disabled-by-policy`, `strength: posture`, `status: experimental`. It
matches `disabled` alone. `not_configured` is what Windows ships and what the one machine measured holds,
and a rule on it would fire on nearly every PC.

**What it is not.** Its `falsepositives` name organisation-managed PCs (Microsoft's own page warns that
script block logging can write passwords used by a script into the event log, which is a reason an
organisation turns it off), security and privacy baselines, debloat guides and optimiser tools, policies
left from earlier management, and administrators reducing log size. None of them is "no normal reason".

**Not read** *(until the amendment of 2026-09-14, which reads both)*: the per-user policy under `HKCU` — `LiveHost` refuses every hive but `HKLM` (ADR 0022), and
the user an elevated scan runs as need not be the player — and PowerShell 7's own policy under
`…\Policies\Microsoft\PowerShellCore`, including its fallback to the Windows PowerShell key. Both are named
in the rule's description so a reader knows the edges.

### 2. `secure_boot_firmware`: the UEFI variable, read through a new `FirmwareSource`

**The source.** `GetFirmwareEnvironmentVariableExW` for the variable `SecureBoot` in the EFI global-variable
namespace `{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}` — the GUID Microsoft's own Secure Boot scripts pass as
`$efi_guid` ([UEFI Validation Option ROM Guidance](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/uefi-validation-option-rom-validation-guidance)).
What the variable's value means is stated in two Microsoft documents: the Secure Boot key guidance
describes `Confirm-SecureBootUEFI` as `SetupMode == 0 && SecureBoot == 1`
([Windows Secure Boot Key Creation and Management Guidance](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/windows-secure-boot-key-creation-and-management-guidance)),
and Azure Attestation's policy treats Secure Boot as enabled when that variable's data is `AQ` — base64 of
the single byte `0x01` ([Azure Attestation policy version 1.2](https://learn.microsoft.com/en-us/azure/attestation/policy-version-1-2)).
One byte holding 1 is `enabled`, one byte holding 0 is `disabled`, and anything else is a failure: never
read as either. `SetupMode` is not read; the rule compares the one variable both documents name.

Feature gates, read in the crate: `GetFirmwareEnvironmentVariableExW` is in
`Win32_System_WindowsProgramming`; `GetFirmwareType` in `Win32_System_SystemInformation`, which ADR 0039
added for `GetTickCount64`; `AdjustTokenPrivileges`, `LookupPrivilegeValueW`, `SE_SYSTEM_ENVIRONMENT_NAME` and
`GetTokenInformation` in `Win32_Security`; `OpenProcessToken` in `Win32_System_Threading` behind
`Win32_Security`. The `windows` crate declares no `NtQuerySystemInformation` class for Secure Boot, and
Microsoft's page for that function documents none
([NtQuerySystemInformation](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation)),
so that route was not taken.

**A new trait, not a registry method.** `Host` gains `FirmwareSource` with `firmware_secure_boot()`. It
touches a different source from every existing trait — the firmware, through the kernel — which is the axis
ADR 0009, 0011 and 0019 split traits on. It answers four ways (`Enabled`, `Disabled`, `VariableAbsent`,
`NotUefi`), or `AccessDenied`, or a failure.

**Legacy BIOS is `source_absent`, and is decided before any privilege is asked for.** Microsoft:

> "Firmware variables are not supported on a legacy BIOS-based system. The GetFirmwareEnvironmentVariableEx
> function will always fail on a legacy BIOS-based system, or if Windows was installed using legacy BIOS on
> a system that supports both legacy BIOS and UEFI."
> — [GetFirmwareEnvironmentVariableExW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getfirmwareenvironmentvariableexw)

`GetFirmwareType` answers first. On BIOS the answer is `NotUefi` and no privilege is touched, so a scan
without administrator rights on such a PC reports `source_absent`, which is true, rather than `not_admin`,
which would promise that elevating would answer. A UEFI firmware with no `SecureBoot` variable
(`ERROR_ENVVAR_NOT_FOUND`) is `source_absent` too: in both cases the place the setting is kept is not there.
`ERROR_INVALID_FUNCTION` from the read itself is also `NotUefi`, which is the documented legacy answer.

**Without administrator rights it is `not_admin`, never a guess.** Microsoft:

> "To read a UEFI firmware environment variable, the user account that the app is running under must have
> the SE_SYSTEM_ENVIRONMENT_NAME privilege."

A token without the privilege makes `AdjustTokenPrivileges` succeed with `ERROR_NOT_ALL_ASSIGNED`, which the
host reports as `AccessDenied`; `ERROR_PRIVILEGE_NOT_HELD` from the read is the same. The collector splits a
denial by elevation through `failure::reason_for`, as the artifact collectors do, so `posture` now reports
`not_admin` — for this one field. Every other `posture` setting is still read with no elevation. SS mode
states `not_admin` once, in the scope line (ADR 0027, ADR 0030), and the restart-as-administrator offer is
what answers it.

**Enabling a privilege in this program's own token is consistent with read-only — as a stated new
capability.** Hard rule 2 says a collector never writes, deletes, moves or locks files, keys or logs on the
scanned machine. This writes nothing to the machine and nothing to the firmware. What it changes is one
attribute of a privilege this process's token already holds, for the duration of one read, after which it
is put back from the `PreviousState` the enabling call returned and the handle is closed; the token ends
with the process. It is still a capability this program did not have — a privilege whose name says it can
modify firmware values — so it is written down here rather than slipped in, the enabling code asks only for
`TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY`, and the only firmware call made while it is enabled is the read.
The alternatives weighed:

| Alternative | Why not |
|---|---|
| Impersonate a duplicated token on the reading thread instead | Leaves the process token untouched, at the cost of `DuplicateTokenEx`, `SetThreadToken` and a revert that must never be skipped. The process token's change is already bounded and undone; the gain is not worth three more `unsafe` calls |
| Leave the privilege enabled | Nothing needs it afterwards, and a token left changed is a change this program made |
| Do not read the firmware | Then a registry value is the only reading of Secure Boot, and nothing can say whether it describes the firmware |

**The rule is the one-way disagreement.** `secure-boot-firmware-disagrees` matches `secure_boot: enabled`
with `secure_boot_firmware: disabled`: the value Windows keeps says Secure Boot is on, and the firmware,
which is what enforces it, says it is off. `strength: posture`, not `tamper` — `tamper` says traces were
removed or altered, and this program cannot tell why the two differ or which changed last; what it can say
is that Secure Boot is off in the place that decides, while the existing `secure-boot-disabled` rule, which
reads the registry, is quiet. Its `falsepositives` are virtual firmware, firmware that reports
inconsistently after an update or a key reset, and a disk moved to other hardware or a firmware setting
changed before Windows recorded the new state. **When Windows rewrites `UEFISecureBootEnabled` is not
established here**, which is why the last of those is stated as a condition rather than as a fact.

**The reverse is not a rule.** Registry off with firmware on makes the machine look *less* protected than
it is, and `secure-boot-disabled` already fires on the registry reading and carries its own
`falsepositives`. A Microsoft community thread records that direction on a PC whose firmware was in setup
mode and whose registry value followed once the keys were restored; that is one report, not verified here,
and it is why the negative fixture `registry-off-firmware-on` exists — to keep a later edit from quietly
widening the rule.

**Virtual machines.** How a hypervisor's virtual firmware answers is not established — a guest started
through a virtual BIOS would take the `NotUefi` path by `GetFirmwareType`, but no such guest was measured —
and it is the first `falsepositives` entry. The
GitHub `windows-latest` runner, a virtual machine whose registry reports Secure Boot off (ADR 0033), is
compared on every CI run with PowerShell's own `Get-SecureBootUEFI` reading of the same variable — which
shows the two readers agree there, not what an ordinary PC reports.

### 3. Kernel DMA Protection: not read

Microsoft documents two ways to see the state of Kernel DMA Protection, and both are programs for a person
to look at:

> "Launch MSINFO32.exe. Check "Kernel DMA Protection" field in the "System Summary" page." … "Launch Windows
> Security application … "Memory Access Protection" will be listed as an available Security Feature, if
> enabled."
> — [Kernel DMA Protection (Memory Access Protection) for OEMs](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-kernel-dma-protection)

The user-facing page says the same and names no API
([Kernel DMA Protection](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)).
The candidates considered:

| Candidate | Why not |
|---|---|
| An `NtQuerySystemInformation` class for the DMA guard policy | Not in Microsoft's documented list of classes, not declared by the `windows` crate, and its layout would come from reverse-engineered headers. A guessed layout is not shipped: a wrong one is a posture value this program invented |
| `Win32_DeviceGuard.AvailableSecurityProperties` value 3 | Documented, but it says "DMA protection is available" for virtualisation-based security — the IOMMU — and not that the Kernel DMA Protection policy is on. It is also WMI, which ADR 0011 declined as a far larger surface than one value is worth |
| `DmaGuard` policy CSP / `Kernel DMA Protection` Group Policy | A policy for devices incompatible with DMA remapping, not the state. An absent policy is the default on every PC |

So item 3 is dropped. It reopens when Microsoft documents a programmatic interface for the state.

Whatever is read in future, a posture value about DMA protection describes how this machine treats
DMA-capable peripherals. **It would not detect a DMA device, and neither does anything in this program**:
a cheat on a second PC reaches memory through hardware and leaves nothing on the checked PC, as README and
`docs/architecture.md` say. The firmware Secure Boot rule added here says nothing about that either, and
the screenshare guide says so beside it.

## Measured on a real Windows machine

On 2026-09-13, one Windows 11 machine, build 26220, with a cross-built CLI and a cross-built test binary,
read-only throughout. Nothing on the machine was changed.

| Run | `secure_boot` | `secure_boot_firmware` | `script_block_logging` | Rule `5ec56c3d` | Rule `88eb2aca` |
|---|---|---|---|---|---|
| Elevated | `enabled` | `enabled` | `not_configured` | `not_found` | `not_found` |
| Limited token (`schtasks /RL LIMITED`) | `enabled` | gap `not_admin` | `not_configured` | `unmeasured / not_admin` | `not_found` |

- PowerShell on the same machine agreed: `Get-SecureBootUEFI -Name SecureBoot` returned the single byte
  `01`, `SetupMode` `00`, and `Confirm-SecureBootUEFI` `True`. No `ScriptBlockLogging` key existed under
  `HKLM` or under the SSH account's `HKCU`, nor PowerShell 7's under `HKLM`.
- The ignored test `live_firmware_read_leaves_the_privilege_as_it_found_it` read the privilege's attributes
  in the token before and after the read, three ways: from the SSH session the privilege was already
  enabled (attributes 3) and stayed so; from a scheduled task at the highest run level it was held and
  disabled (0), was enabled for the read, and was 0 again afterwards — the restoring path, exercised; under
  a limited token it was not held at all and the answer was `AccessDenied`.
- The policy key was readable without elevation.

**The GitHub `windows-latest` runner, on this pull request's first CI run** (run 34753088364): the
privilege test found the privilege held and disabled (0), read `Ok(Disabled)`, and left it at 0 — the
restoring path, on a second machine; the CLI reported `secure_boot: disabled`, `secure_boot_firmware:
disabled`, `test_signing: enabled`, `tpm: absent` and `script_block_logging: not_configured`, and
`Get-SecureBootUEFI -Name SecureBoot` agreed with the firmware reading. A runner is a virtual machine
imaged for CI, not an ordinary PC.

**One machine is one machine.** Nothing here says how other firmware, other builds, or virtual machines
answer, or how often the rule would fire on a population.

## Baselines

- All three baselines carry no `ScriptBlockLogging` key, so `script_block_logging` is `not_configured`
  there. Microsoft's own enabling snippet creates the key when `Test-Path` says it is not there, which is
  the documented shape of a machine nobody configured, and the machine above holds no such key. The rule is confronted: the field is present and one condition away.
- `baseline-elevated-win11` declares `firmware: { secure_boot: enabled }`, measured elevated above, beside
  the registry's `UEFISecureBootEnabled: 1`. The disagreement rule is confronted there.
- `baseline-hardened-win11` and `baseline-consumer-win11` are `elevated: false`, and a limited token cannot
  read the variable, so they declare `access_denied` — measured under a limited token above, not chosen to
  quiet anything. Neither confronts the firmware rule, and neither needs to: one baseline does.
- `fixtures/hosts/PROVENANCE.md` records each value and its source.

## What is unverified

- ~~**Windows PowerShell 5.1's handling of the policy** — whether an explicit 0 also suppresses the logging
  of suspicious script blocks, and how it treats a `REG_SZ` value.~~ Measured on 2026-09-14 on one CI
  runner; see the amendment below.
- **When Windows writes `UEFISecureBootEnabled`**, and therefore how long a registry value can outlive a
  firmware change. This is the condition the third `falsepositives` entry depends on.
- **How other hypervisors' virtual firmware and other vendors' firmware report the variable.** CI adds one
  virtual machine, the GitHub runner, and compares this reader with PowerShell's there.
- **The variable's size.** One byte is what Azure Attestation's `AQ` implies and what the machine above
  returned. The UEFI specification that defines it was not reachable from this session (the page answered
  403), so any other length is refused rather than interpreted.
- **Whether every UEFI firmware without Secure Boot support answers `ERROR_ENVVAR_NOT_FOUND`** rather than
  some other code. Another code is a `read_failed` gap, which SS mode lists.

## Accepted by the owner

On 2026-09-13 the project owner accepted this ADR's reading of hard rule 2: enabling a privilege the
process token already holds, for one named read, and restoring it, is not a change to the scanned
machine. Two things were made part of that acceptance, in the same change:

- **The write calls are banned.** `clippy.toml` lists `SetFirmwareEnvironmentVariableA`, `…W`, `…ExA`
  and `…ExW` under `disallowed-methods`. The ban was checked by adding a call to one of them in
  `rongroi-host-windows` and running clippy for `x86_64-pc-windows-msvc`: it failed with "use of a
  disallowed method". The call was then removed.
- **The exception is written where the rule is.** `AGENTS.md` hard rule 2 and
  `crates/rongroi-collectors/AGENTS.md` say that the one change a collector may make is to this
  program's own token, for a read an ADR names, and that any further privilege needs its own ADR.

Not established, and the condition for revisiting: whether security software flags a process that
enables `SeSystemEnvironmentPrivilege`. *(One Defender configuration on one runner was measured on
2026-09-14 — see the amendment below. That is not an answer for other security products.)* If players report that it does, reading the firmware only when
the person running the scan asks for it is the fallback to weigh.

## Consequences

- `rongroi-host` gains `FirmwareSource` and `FirmwareSecureBoot`; `Host` gains the supertrait. `LiveHost`,
  `NonWindowsHost` (`Unsupported`) and `FixtureHost` implement it. A fixture's `firmware:` block takes
  `secure_boot: enabled | disabled | variable_absent | not_uefi | access_denied | read_failed`; a fixture
  without the block is `Unsupported`, never a default (ADR 0011).
- The named non-baseline fixtures that are `elevated: false` now declare `access_denied`, and
  `secure-boot-unreported`, a legacy-BIOS Windows 10, declares `not_uefi`.
- `posture` emits two more fields and reports `not_admin`. `check-rules`' test that used `not_admin` as a
  reason `posture` cannot report now uses `source_empty`.
- Every report snapshot gains the two rules, and a fixture host that describes no registry at all now
  carries a `posture` observation holding `script_block_logging: not_configured` — the answer ADR 0022 gave
  a fixture without a key, now visible because this field treats absence as an answer.
- No `windows` feature is added — `Win32_System_SystemInformation` arrived with ADR 0039 — no crate is
  added, and `Cargo.lock` does not move.
- The consent text in the CLI and the desktop app names the firmware reading and the PowerShell logging
  policy; `PRIVACY.md`, `docs/architecture.md` and the screenshare guide say what is read.
- The Windows CI job runs the privilege test and compares the firmware reading with `Get-SecureBootUEFI`.

## Amendment of 2026-09-14 — what each PowerShell does with the policy, the scopes read, and Defender

Three questions this ADR left open are answered here, each by a measurement on the GitHub `windows-latest`
runner rather than by one engine's source: how Windows PowerShell 5.1 treats the policy value; which of the
policy's other scopes a rule needs and what reading them means; and what Microsoft Defender recorded while
this program enabled `SeSystemEnvironmentPrivilege`. A runner is an imaged virtual machine (Windows build
26100, `powershell.exe` 10.0.26100.33158, PowerShell 7.6.5), not a player's PC, and **one runner is one
machine**. Nothing below was measured on a player's PC or on the owner's.

### How it was measured

A CI step (`What PowerShell does with a script block logging policy`, `.github/workflows/windows.yml`)
writes one case at a time to the policy keys, clears `Microsoft-Windows-PowerShell/Operational` and
`PowerShellCore/Operational`, and starts each engine twice in a fresh process with one line to run:

- an **inert** line, which only a policy that turns logging on should record; and
- an inert line holding one word from PowerShell's public list of suspicious content, which PowerShell
  records on its own when no policy says otherwise.

Each line carries a nonce, and the step counts event 4104 carrying it, with its level. It then runs the CLI
and prints every `script_block_logging*` field and the four rules' states, so the collector's reading sits
beside what the engines did in the same case. Every key is exported first and put back afterwards, and the
step fails if a key that was absent is present at the end. Both engines' logs recorded the inert line when
their machine policy was 1, so their zeros are measurements and not a log that records nothing.

The automatic record is documented by Microsoft outside Learn. The PowerShell team's 2015 post says
PowerShell "automatically logs script blocks when they have content often used by malicious scripts", and
that setting `EnableScriptBlockLogging` to 0 disables it
([PowerShell ♥ the Blue Team](https://devblogs.microsoft.com/powershell/powershell-the-blue-team/)). None of
the Learn pages this ADR cites — `about_Logging` (5.1), `about_Logging_Windows` (7.5), *PowerShell security
features*, the WindowsPowerShell Policy CSP — mentions it; they were searched on 2026-09-14.

Run 34804676954 measured the first 27 cases; run 34806733664 repeated them and added nine chosen from
PowerShell 7's source and from the first run's 5.1 results. The engines' counts in the two runs agree on all 27
cases they share; the first run's CLI columns are the collector before this change.

### What was measured

"Inert" and "listed" are the two lines; a count is events 4104 carrying the nonce, `L5` verbose and `L3`
warning. "5.1" is Windows PowerShell's result and "7" PowerShell 7's; the four columns on the right are what
the CLI reported in the same case.

| Case (keys written) | 5.1 inert / listed | 7 inert / listed | `script_block_logging` | `…_user` | `…_pwsh` | `…_pwsh_user` |
|---|---|---|---|---|---|---|
| no policy | 0 / 1 L3 | 0 / 1 L3 | `not_configured` | `not_configured` | `not_configured` | `not_configured` |
| machine `REG_DWORD` 1 | 1 L5 / 1 L3 | 0 / 1 | `enabled` | `machine_takes_precedence` | `not_configured` | `not_configured` |
| machine `REG_DWORD` 0 | **0 / 0** | 0 / 1 | `disabled` | `machine_takes_precedence` | `not_configured` | `not_configured` |
| machine `REG_DWORD` 2 | 0 / 1 | 0 / 1 | `not_configured` | `machine_takes_precedence` | `not_configured` | `not_configured` |
| machine `REG_SZ` "1" | 1 / 1 | 0 / 1 | `enabled` | `machine_takes_precedence` | `not_configured` | `not_configured` |
| machine `REG_SZ` "0" | **0 / 0** | 0 / 1 | `disabled` | `machine_takes_precedence` | `not_configured` | `not_configured` |
| machine `REG_SZ` "01" | 0 / 1 | 0 / 1 | `not_configured` | `machine_takes_precedence` | `not_configured` | `not_configured` |
| machine `REG_EXPAND_SZ` "0" | **0 / 0** | 0 / 1 | `disabled` | `machine_takes_precedence` | `not_configured` | `not_configured` |
| machine `REG_MULTI_SZ` "0" | 0 / 1 | 0 / 1 | `not_configured` | `machine_takes_precedence` | `not_configured` | `not_configured` |
| machine `REG_QWORD` 1 | 1 / 1 | 0 / 1 | `enabled` | `machine_takes_precedence` | `not_configured` | `not_configured` |
| machine `REG_QWORD` 0 | **0 / 0** | 0 / 1 | `disabled` | `machine_takes_precedence` | `not_configured` | `not_configured` |
| machine key with no value | 0 / 1 | 0 / 1 | `not_configured` | `machine_takes_precedence` | `not_configured` | `not_configured` |
| user `REG_DWORD` 1 | 1 / 1 | 0 / 1 | `not_configured` | `enabled` | `not_configured` | `not_configured` |
| user `REG_DWORD` 0 | **0 / 0** | 0 / 1 | `not_configured` | `disabled` | `not_configured` | `not_configured` |
| user `REG_SZ` "0" | **0 / 0** | 0 / 1 | `not_configured` | `disabled` | `not_configured` | `not_configured` |
| machine 1, user 0 | 1 / 1 | 0 / 1 | `enabled` | `machine_takes_precedence` | `not_configured` | `not_configured` |
| machine 0, user 1 | **0 / 0** | 0 / 1 | `disabled` | `machine_takes_precedence` | `not_configured` | `not_configured` |
| machine key with no value, user 0 | 0 / 1 | 0 / 1 | `not_configured` | `machine_takes_precedence` | `not_configured` | `not_configured` |
| machine 2, user 0 | 0 / 1 | 0 / 1 | `not_configured` | `machine_takes_precedence` | `not_configured` | `not_configured` |
| PowerShell 7 machine `REG_DWORD` 1 | 0 / 1 | 1 L5 / 1 L3 | `not_configured` | `not_configured` | `enabled` | `machine_takes_precedence` |
| PowerShell 7 machine `REG_DWORD` 0 | 0 / 1 | **0 / 0** | `not_configured` | `not_configured` | `disabled` | `machine_takes_precedence` |
| PowerShell 7 machine `REG_SZ` "0" | 0 / 1 | 0 / 1 | `not_configured` | `not_configured` | `not_configured` | `not_configured` |
| PowerShell 7 machine `REG_QWORD` 0 | 0 / 1 | 0 / 1 | `not_configured` | `not_configured` | `not_configured` | `not_configured` |
| PowerShell 7 machine `UseWindowsPowerShellPolicySetting` 1, machine 0 | **0 / 0** | **0 / 0** | `disabled` | `machine_takes_precedence` | `disabled` | `machine_takes_precedence` |
| PowerShell 7 machine fallback 1, machine 1 | 1 / 1 | 1 / 1 | `enabled` | `machine_takes_precedence` | `enabled` | `machine_takes_precedence` |
| PowerShell 7 machine fallback 1, no Windows PowerShell key | 0 / 1 | 0 / 1 | `not_configured` | `not_configured` | `not_configured` | `not_configured` |
| PowerShell 7 machine fallback 1 and its own 0, machine 1 | 1 / 1 | 1 / 1 | `enabled` | `machine_takes_precedence` | `enabled` | `machine_takes_precedence` |
| PowerShell 7 machine fallback 1, machine `REG_SZ` "0" | **0 / 0** | 0 / 1 | `disabled` | `machine_takes_precedence` | `not_configured` | `not_configured` |
| PowerShell 7 machine fallback `REG_SZ` "1", machine 0 | **0 / 0** | 0 / 0 — **`pwsh` exited `0xE0434352`** | `disabled` | `machine_takes_precedence` | gap `read_failed` | gap `read_failed` |
| PowerShell 7 user 0 | 0 / 1 | **0 / 0** | `not_configured` | `not_configured` | `not_configured` | `disabled` |
| PowerShell 7 machine 1, PowerShell 7 user 0 | 0 / 1 | 1 / 1 | `not_configured` | `not_configured` | `enabled` | `machine_takes_precedence` |
| PowerShell 7 machine `REG_SZ` "0", PowerShell 7 user 0 | 0 / 1 | **0 / 0** | `not_configured` | `not_configured` | `not_configured` | `disabled` |
| PowerShell 7 machine 2, PowerShell 7 user 0 | 0 / 1 | **0 / 0** | `not_configured` | `not_configured` | `not_configured` | `disabled` |
| PowerShell 7 machine `EnableScriptBlockInvocationLogging` 1 only, PowerShell 7 user 0 | 0 / 1 | 0 / 1 | `not_configured` | `not_configured` | `not_configured` | `machine_takes_precedence` |
| PowerShell 7 machine fallback 1 (no Windows PowerShell machine key), PowerShell 7 user 0 | 0 / 1 | **0 / 0** | `not_configured` | `not_configured` | `not_configured` | `disabled` |
| PowerShell 7 user fallback 1, user 0 | **0 / 0** | **0 / 0** | `not_configured` | `disabled` | `not_configured` | `disabled` |

Every row's four fields are the collector's unit test `script_block_logging_follows_what_each_powershell_was_measured_to_do`,
except the malformed-fallback row, which is `a_pwsh_fallback_switch_that_is_not_a_dword_is_a_gap`.

### What the measurement settles

- **With the policy explicitly off, Windows PowerShell 5.1 also stops its automatic record** — the listed
  line was logged as a warning with no policy, and not at all with 0. That was the first "not established"
  item above. The same holds for PowerShell 7, as its source said.
- **5.1 compares the value as text.** A `REG_DWORD`, `REG_QWORD`, `REG_SZ` or `REG_EXPAND_SZ` holding 1 or
  0 all counted; `"01"`, a `REG_MULTI_SZ` and `REG_DWORD` 2 did nothing. That matches the comparison in
  the oldest published ancestor of that code, PowerShell 6.0.0-alpha.9 (`String.Equals("0",
  logScriptBlockExecution.ToString(), …)` in `CompiledScriptBlock.cs`), which is supporting evidence only:
  5.1 is closed. Microsoft's own enabling snippet writes a `REG_SZ`, so this is the ordinary shape, and it
  was a `read_failed` gap before this amendment.
- **In 5.1, the machine key decides as soon as it exists.** A key with no value, or with 2, left logging at
  its default and a per-user 0 was not applied. Only without a machine key did a per-user value count. Microsoft
  documents only that "The Computer Configuration policy setting takes precedence over the User
  Configuration policy setting"
  ([WindowsPowerShell Policy CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-windowspowershell)),
  which does not say what an empty key or an unrecognised value does.
- **PowerShell 7 counts only a `REG_DWORD`**, as its source reads (`rawRegistryValue is int` in
  `Utils.TrySetPolicySettingsFromRegistryKey`, PowerShell `master` at `5e35e5a`). It does not read Windows
  PowerShell's key unless its own key holds `UseWindowsPowerShellPolicySetting` — and then only that key,
  and still only a `REG_DWORD`. Its machine hive decides only when the key it ends up reading sets
  `EnableScriptBlockLogging` or `EnableScriptBlockInvocationLogging` to a `REG_DWORD` 1 or 0; otherwise it
  reads the account's key. Microsoft documents the field as "enables using the value from a similar Windows
  PowerShell Group Policy setting"
  ([about_Group_Policy_Settings](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings?view=powershell-7.5)),
  which does not say what happens when that setting is absent; the source and the runner agree that
  PowerShell 7 then goes on to the next hive.
- **A `REG_SZ` `UseWindowsPowerShellPolicySetting` stops PowerShell 7 from starting.** Both `pwsh`
  processes exited with `0xE0434352`, the code of an unhandled .NET exception, and ran nothing. The source
  casts the value with `(int)`. The collector reports both PowerShell 7 fields as `read_failed` there: there
  is no policy state to name for an engine that does not run. This is the one row where the answer is a
  gap by design.

### The mapping, and a registry read that keeps the type

`script_block_logging` keeps its meaning — Windows PowerShell's machine policy — and now follows the 5.1
rows: 1 or 0 as text is `enabled` or `disabled`, and any other value, type, or no value is
`not_configured`. `script_block_logging_user`, `script_block_logging_pwsh` and
`script_block_logging_pwsh_user` are new, each as its engine applies it. A per-user field is
`machine_takes_precedence` when its engine takes the policy from `HKLM` and never reads the account's key —
a statement about precedence, not about what the account's key holds, which is then not read.

`RegistrySource::read_u32` cannot carry this: a live host's `windows-registry` reader accepts a `REG_QWORD`
there as well (`Key::get_u32` calls `get_u64`, which "Accepts `REG_DWORD` … and `REG_QWORD`", 0.100.0), and a
string is an error. `RegistrySource` gains `read_value`, which hands back `RegistryData::{Dword, Qword, Text,
OtherType}` — `REG_SZ` and `REG_EXPAND_SZ` are `Text`, unexpanded, and any other type's data is not read — with
a string bounded by the same 64 KiB as a binary value (ADR 0022). A fixture writes a `REG_QWORD` as
`{ qword: 0 }`. Whether a key exists is read with `value_names`, whose names are discarded.

`REG_EXPAND_SZ` is read unexpanded, and 5.1 is .NET, which expands it on read; a value whose `%variable%`
expands to 0 or 1 would be `not_configured` here and honoured by 5.1. That case was not measured.

### Which scopes, and what `HKCU` means

The rule is about a policy turning logging **off**. From the rows above, four places can do that, for two
engines: Windows PowerShell's key in `HKLM`, the same key in `HKCU` when `HKLM` has none, PowerShell 7's key
in `HKLM` (or Windows PowerShell's through its fallback), and PowerShell 7's in `HKCU` when `HKLM` decides
nothing. PowerShell 7 also reads its `powershell.config.json` after both hives; that is a file in its install
folder and in the user's documents, not a policy, and is not read. Each place gets a field and a rule —
`script-block-logging-disabled-by-user-policy`, `pwsh-script-block-logging-disabled-by-policy` and
`pwsh-script-block-logging-disabled-by-user-policy`, all `posture` and `experimental` — because a rule has
no `or` between fields and a reader should see which engine and which hive.

**`HKCU` is the account this program runs as.** A scan without elevation, or one elevated by the same
account through the consent prompt, reads the player's own per-user policy. A scan restarted with a
**different** administrator's password (ADR 0012) reads that administrator's, and the player's is not read —
and the report cannot tell those apart. Both per-user rules say so in `description` and `falsepositives`,
and the consent question and `PRIVACY.md` name the account.

On the runner, `HKCU\Software\Policies` granted the account itself `ReadKey` only and `Administrators` and
`SYSTEM` `FullControl`, so on that machine an account without administrator rights could not write its own
per-user policy. Whether that ACL is the same on a player's Windows 11 was not measured.

| Alternative | Why not |
|---|---|
| Read `HKLM` only, as before | Leaves the per-user policy, which the CSP documents as a Group Policy of its own and which 5.1 was measured to apply, as a `not_found` a reader takes for "looked, not there" |
| Read the interactive user's hive through `HKEY_USERS\<SID>` | Needs the SID of the person at the keyboard, which the elevated process does not have without asking Windows for the session's user — a new read of an identity this program deliberately never reports (ADR 0023) |
| Skip `HKCU` when elevated | The recommended scan is elevated, so the per-user rules would almost never answer; and a same-account elevation, the common case, reads the right hive |
| One field per engine with the precedence resolved and no per-hive detail | Hides which hive said off, and the two per-user cases carry a false positive the machine cases do not |
| Per-hive raw values, with the precedence in the rules | `match` has no negation, and 5.1's "the machine key exists" is not a value any field could hold without becoming this design |

`LiveHost` now opens `HKCU` as well as `HKLM`, for reading, and refuses every other root (ADR 0022 is
amended to say so).

### Microsoft Defender while the privilege was enabled

The runner's Defender was measured, in the window from just before the firmware test to after the CLI's
last scan in the PowerShell step. **One Defender configuration on one runner is what this says. It is not
a statement about any other endpoint security product, or about Defender with other settings or
signatures.**

**Run 34806733664.** Before the window the image had Defender's service running
(`AMRunningMode` Normal, product 4.18.26080.3, tamper protection off) with real-time protection, behaviour
monitoring and download scanning all **off**. The step switched real-time protection on; behaviour
monitoring and download scanning stayed off. The window, 14.8 minutes, held the firmware test — which found
the privilege held and disabled, enabled it for the read and left it disabled — the live smoke's CLI scan
and the PowerShell step's 36 CLI scans, each of which enables the privilege for the firmware read. Defender's
Operational log recorded 4 events in it, ids 2000 ×2 and 5007 ×2; **no detection event** (1006–1008, 1015,
1116–1119: 0), **no event naming** the test binary or the CLI, and `Get-MpThreatDetection` listed nothing
since the window opened. The events' messages were not printed in that run.

That run had behaviour monitoring off. Microsoft describes behaviour monitoring as the capability that
"observes process, file, and service activity in real time", and says it "is enabled by default"
([Behavior monitoring in Microsoft Defender Antivirus](https://learn.microsoft.com/en-us/defender-endpoint/behavior-monitor)),
so that run neither had the part of Defender that watches a running process nor matched Defender's default
configuration. The step now switches behaviour monitoring and download scanning on as well, and prints each
event's first line.

**Run 34808373469** (this pull request's three-commit head, `99b8cf8`). The image was as before; the step
switched real-time protection, behaviour monitoring and download scanning on, and `Get-MpComputerStatus`
reported all three `True` for the whole window, at its start and at its end. The window, 15.2 minutes,
held the same privileged reads: the firmware test (privilege held and disabled, restored to disabled), the
live smoke's scan and 36 CLI scans. Defender's Operational log recorded 5 events:

| Id | Count | First line of the message |
|---|---|---|
| 5000 | 1 | Real-time Protection scanning … was enabled — the step's own change, five seconds into the window |
| 5007 | 2 | Configuration has changed — at 1 and 4 minutes into the window, after the step's last change; what changed was not read |
| 2000 | 2 | security intelligence version updated |

**No detection event** (1006–1008, 1015, 1116–1119: 0), **no event naming** the test binary or the CLI, and
`Get-MpThreatDetection` listed nothing since the window opened. Each setting was put back afterwards.

What this is: on one runner, Defender platform 4.18.26080.3 with real-time protection, behaviour monitoring
and download scanning on, cloud-delivered protection and tamper protection as the image had them (tamper
protection off; cloud protection not read), recorded nothing about 38 processes that enabled
`SeSystemEnvironmentPrivilege` for a firmware read. What it is not: evidence about other endpoint security
products, about Defender with cloud protection or attack surface reduction rules configured differently,
about later signatures, or about a player's PC. The fallback named in "Accepted by the owner" — reading the
firmware only when the person running the scan asks — is not needed on this evidence, and is still the one
to weigh if a report says otherwise.

### Still not established

- How a player's Windows 11, rather than a runner, answers any row above; the rows are one build of each
  engine.
- `REG_EXPAND_SZ` whose `%variable%` expands to 0 or 1.
- Whether other PowerShell 7 releases, or Windows PowerShell on other Windows builds, treat the value the
  same way.
- Whether `HKCU\Software\Policies` refuses writes by a standard account on a player's PC.
- Whether any security product other than the one Defender configuration above flags a process that
  enables `SeSystemEnvironmentPrivilege`.

### Consequences of the amendment

- `rongroi-host`: `RegistryData`, `RegistrySource::read_value`, `bound_registry_data`; the fixture host
  reads `{ qword: }`. `rongroi-host-windows`: `HKCU` is opened. No dependency or `windows` feature is
  added.
- `posture` emits ten fields; three rules are added; the existing rule's title and description now name
  Windows PowerShell and say what was measured. Every report snapshot gains the three rules and, where a
  `posture` observation exists, the three fields, each `not_configured`. All three baselines hold none of
  the four keys, measured on the runner and consistent with the machine measured above (`PROVENANCE.md`);
  each new rule is confronted there.
- The consent question in the CLI and the app, `PRIVACY.md`, `docs/architecture.md`, both screenshare guides
  and `CHANGELOG.md` say what is read. The Windows CI job keeps the PowerShell step and the two Defender
  steps.
