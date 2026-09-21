# ADR 0057 — Named places a modification installs, and the mitigation switches it flips

- Status: accepted — the owner asked on 2026-09-21 for the rest of the "gaming Windows" work in one
  change, after ADR 0056 shipped
- Date: 2026-09-21

## Context

ADR 0056 reads what Windows *says* this installation is. Two things it deliberately left out are the
ones a reviewer can check on a screenshare in a second:

1. **The places a modification installs.** Atlas creates a module folder, a desktop folder of
   configuration scripts and its own registry key; ReviOS installs its own tool and a wallpaper folder.
   ADR 0056 left these out because a rule for them would be **unconfronted** (ADR 0033): a collector
   that emits an observation only when it finds something gives a baseline nothing to answer with.
2. **What those playbooks switch off.** Atlas' "Disable All Mitigations" script writes four settings.
   Three of them are plain `REG_DWORD` switches that any tweak script or pre-modified image may write,
   whoever wrote them, and they are machine posture of exactly the kind `posture` already reports.

## Measured

**Limited-token measurement, 2026-09-21**, on the same Windows 11 PC as ADR 0056 (build 26220), with
the owner's permission: a scheduled task at run level `LIMITED` on the signed-in desktop, which ran as
the account's **limited** token — `whoami /groups` in it reported Medium Mandatory Level and
`BUILTIN\Administrators` as "Group used for deny only". The probe wrote its output to a file under
`%TEMP%`; the script, the task and the file were deleted in the same run.

Read successfully with that token:

| Read | Result |
|---|---|
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion` → `ProductName`, `RegisteredOrganization` | read |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation` → `Model` | read |
| `HKLM\SYSTEM\CurrentControlSet\Services\WinDefend` → `Start` | read |
| `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager` and its `kernel` subkey | read |
| Listing `%ProgramData%\Microsoft\Windows Defender\Platform` | read — two version folders |
| `%SystemRoot%\AtlasModules`, `%ProgramFiles%\Revision Tool` | not there |

**So every read in ADR 0056 and in this ADR works without administrator rights**, on the one PC that
was measured. That is the same evidence ADR 0054 acted on for `net_config`, and this ADR acts on it the
same way: `access_denied` stops being a reason the `os_image` rules declare, so a machine that does
refuse one of these reads produces a row a reviewer is shown rather than a number in the scope line.

**Elevated measurement, 2026-09-21**, same PC, for the three switches:

| Value | Data |
|---|---|
| `Session Manager\Memory Management` → `FeatureSettingsOverride`, `FeatureSettingsOverrideMask` | neither value exists |
| `Session Manager\kernel` → `DisableExceptionChainValidation` | does not exist |
| `Session Manager\kernel` → `MitigationOptions` | does not exist |
| `Session Manager` → `ProtectionMode` | `1` |

### What the playbook writes, read from its own source

`Atlas-OS/Atlas` `1ed9630616b29f0c7974e8bd76a94fc06f60388c`,
`src/playbook/Executables/AtlasDesktop/7. Security/Mitigations/Disable All Mitigations.cmd`:
`FeatureSettingsOverride` and `FeatureSettingsOverrideMask` both to `3`,
`DisableExceptionChainValidation` to `1`, `ProtectionMode` to `0`, and `MitigationOptions` /
`MitigationAuditOptions` to a mask with every nibble set to 2.

## Decision

### A new collector, `install_marker`

It reads whether each of six named places is there, and **emits one observation for every one of them,
whatever the answer** — `present: true` or `present: false`. That is what makes a rule for them
confrontable, and it is the whole reason this is a collector of its own rather than more fields on
`os_image`.

- The discriminator is `marker`: the place's canonical spelling with its environment variable left
  unexpanded (`%SystemRoot%\AtlasModules`). A rule matches on that, so it does not change with the
  drive letter, the locale or the case Windows used. `path` carries where this PC actually put it.
- A place whose environment variable is not set, or whose read was refused, is a `DiscriminatorGaps`
  for that place alone and leaves the other five answered (ADR 0044).
- **Nothing inside a folder is reported.** The listing is used for one bit — is it there — and dropped.
  A test asserts that no entry name reaches an observation.
- Five places come from the two playbooks' own source. The sixth is Microsoft's own,
  `%ProgramData%\Microsoft\Windows Defender\Platform`, read for its **absence**: an image that removed
  Defender has no platform folder, while switching Defender off leaves it in place. It is read beside
  `os_image`'s `service_windefend`, which says which of the two happened.

### Three more settings on `posture`

`speculative_execution_mitigations`, `exception_chain_validation` and `object_namespace_protection`,
each `enabled`, `disabled`, `not_configured` or `configured_other`. They are machine posture, not a
signature of any one product: any script, image or owner may write them.

- The speculative-execution reading is `disabled` **only on the pair** — override and mask both `3` —
  because that pair is what turns the mitigations off, and either alone is a different statement.
- `DisableExceptionChainValidation` names what is *off*, so `1` is `disabled` and `0` is `enabled`.
- `not_configured` is kept apart from `enabled`: "nobody wrote this" is not the same statement as
  "somebody wrote it to on", exactly as for the PowerShell policies in ADR 0038.

### What is deliberately not read

- **`MitigationOptions` and `MitigationAuditOptions`.** Their meaning is per-nibble, their default
  varies by Windows version and by processor, and the measured PC has neither value. A rule on them
  would say more than this program can honestly measure today.
- **The boot entry description.** Atlas writes its name there with `bcdedit`. Reading the BCD store
  needs either a privilege or another program, and this program starts no other program.
- **Power scheme names.** Atlas renames the active scheme and KernelOS ships a named one, but the
  KernelOS name comes from its own marketing page and nothing in this repository has measured it. It
  stays out until somebody measures it (see below).

## Consequences

- Six rules ship: three on `install_marker` (Atlas places, ReviOS places, the absent Defender platform
  folder) and three on `posture`. All are `experimental` and `posture` strength, and each names in
  `falsepositives` the ordinary machine that produces the same row.
- The `os_image` rules from ADR 0056 no longer declare `access_denied`, on the measurement above.
- A pre-modified ISO that installs nothing under a name we know — KernelOS, Ghost Spectre, a
  `tiny11builder` image — is still identified only by what is missing. The owner decided on 2026-09-21
  not to install one in a VM to measure it, and to collect `os_image` output from players who run one
  instead. A named-build rule for those waits for that measurement.
