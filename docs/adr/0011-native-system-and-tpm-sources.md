# ADR 0011 — Native system and TPM sources

- Status: proposed
- Date: 2026-09-12

## Context

Until now every `posture` reading was a registry value. Three more machine settings are worth showing a
reviewer: whether the kernel accepts drivers no trusted publisher signed (test signing), whether memory
integrity (HVCI) is enforced, and whether the machine has a TPM. Only one of those is a registry value.
Test signing is reported by the running kernel, and the TPM is reported by TPM Base Services, so both
need a kind of source the `Host` trait did not have. A new kind of source is an ADR (CONVENTIONS.md §8).

Read in the vendored `windows` 0.62.2 source on 2026-09-12, rather than assumed: `NtQuerySystemInformation`
is generated under the `Wdk_System_SystemInformation` feature, `Tbsi_GetDeviceInfo` under
`Win32_System_TpmBaseServices`, and `SYSTEM_CODEINTEGRITY_INFORMATION` — the structure the first one fills
— under `Win32_System_WindowsProgramming`. Both calls therefore have crate-provided bindings, and neither
needs a hand-written `extern "system"` declaration.

## Decision

### Two traits, not one

`Host` now also requires `SystemIntegritySource` (`code_integrity_options`) and `TpmSource` (`tpm_info`).
They are separate for the reason ADR 0009 gave for splitting the file system from the environment: a
collector that only wants to know about the TPM should not be handed the kernel's code-integrity state,
and `FixtureHost` can then describe either one alone.

### HVCI is read from the registry, deliberately

Two different things could be called HVCI: the **configured policy** under
`HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity`, and the
**running state** in the `Win32_DeviceGuard` CIM class. This reads the registry key. It needs no new
source trait and no WMI dependency, and WMI would be a far larger surface than one value is worth.

The cost is that the key states what Windows was configured to enforce and not that the hypervisor is
enforcing anything: a machine whose hardware lacks the necessary virtualisation support can carry the
setting and enforce nothing. The rule text says so plainly, in the same way the existing
`secure-boot-disabled` rule carries a caveat about its own key. If the running state is ever needed, it
is a new source and a new ADR, not a quiet change of meaning behind the same field name.

### A missing TPM is an answer, not an error

`Tbsi_GetDeviceInfo` answering `TBS_E_TPM_NOT_FOUND` is the platform telling us something true about the
machine, so it becomes `Ok(TpmInfo { present: false, .. })` and the collector reports `tpm: absent`. Any
other failing result code is an error and becomes a gap, so a rule that needs the field reads
`Unmeasured` rather than `NotFound`. Treating "no TPM" as a failure would have hidden a fact behind a
reason code; treating a genuine failure as "absent" would have invented one.

### A fixture's silence is `Unsupported`, not a default

When a fixture host has no `code_integrity:` or `tpm:` block, the accessor returns `Unsupported`. A
fixture written before this feature existed never modelled these settings, and must not be read as
claiming one of them. The alternative — defaulting to "enabled"/"present" — would have let a fixture
silently assert a security setting nobody wrote down, which is the same class of mistake as reporting
`NotFound` for something that was never read.

The consequence is that the four hosts that existed before this change state these settings explicitly.
The `fivem-dir-*` hosts deliberately do not, and their reports show the new rules as `Unmeasured` — an
honest description of a fixture that does not model them.

### `context` strength and SS mode

`tpm-absent` is this repository's first `context` rule. SS mode lists all `posture` evidence whatever its
state, but a `context` rule that is `NotFound` or `Unmeasured` is only counted in `hidden`
(`rongroi_core::view::for_mode`). That is existing behaviour rather than a bug, and it is the intended
reading here: that a machine *has* a TPM is not something a reviewer watching a screenshare needs to see
listed, while the absence of one is shown because it is `Found`.

## Consequences

- `windows` gains three features: `Wdk_System_SystemInformation`, `Win32_System_TpmBaseServices` and
  `Win32_System_WindowsProgramming`. Each name was read from that crate's own manifest.
- Bit decoding and TBS result classification are pure functions in `system_integrity.rs` and `tpm.rs`,
  outside the `unsafe` blocks, so they are compiled and tested on macOS and Linux as well as Windows —
  the same split ADR 0012 made for argument quoting. The two `unsafe` calls themselves can only be
  exercised on Windows.
- The code-integrity bits are read by masking, not by comparing the whole word: the kernel sets a dozen
  other flags in it, and an unrelated one must not change the answer.
- `CodeIntegrityOptions` also carries `enabled`, which no rule reads yet. It comes back in the same word
  as the test-signing bit, and dropping it would mean a second system call to recover it later.
- `posture` still produces exactly one observation per run, now with up to five fields, so a future rule
  can match on more than one setting at once.
- The live implementations cannot be exercised on a build machine. They are type-checked for
  `x86_64-pc-windows-msvc` from any operating system and run by the Windows CI job and its live smoke test.
