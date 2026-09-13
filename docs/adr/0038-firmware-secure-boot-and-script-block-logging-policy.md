# ADR 0038 — Secure Boot as the firmware reports it, the script block logging policy, and no Kernel DMA Protection

- Status: proposed
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
program can name. That is not hypothetical — Microsoft's own snippet writes the value with
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

**Not read:** the per-user policy under `HKCU` — `LiveHost` refuses every hive but `HKLM` (ADR 0022), and
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

- **Windows PowerShell 5.1's handling of the policy** — whether an explicit 0 also suppresses the logging
  of suspicious script blocks, and how it treats a `REG_SZ` value. PowerShell 7's source is the evidence
  cited; 5.1 is closed.
- **When Windows writes `UEFISecureBootEnabled`**, and therefore how long a registry value can outlive a
  firmware change. This is the condition the third `falsepositives` entry depends on.
- **How other hypervisors' virtual firmware and other vendors' firmware report the variable.** CI adds one
  virtual machine, the GitHub runner, and compares this reader with PowerShell's there.
- **The variable's size.** One byte is what Azure Attestation's `AQ` implies and what the machine above
  returned. The UEFI specification that defines it was not reachable from this session (the page answered
  403), so any other length is refused rather than interpreted.
- **Whether every UEFI firmware without Secure Boot support answers `ERROR_ENVVAR_NOT_FOUND`** rather than
  some other code. Another code is a `read_failed` gap, which SS mode lists.

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
