# ADR 0095 — The PCI positions Windows started, one start at a time

- Status: accepted — the owner decided the questions below on 2026-11-18, each as recommended. Sections 3 and 4 are built ("As built"); section 1 waits for a physical PC and other Windows builds
- Date: 2026-11-18
- Amends: ADR 0018 (two more kinds of event whose payload is read), ADR 0069 (a device's position is read, from a log
  and not from the device list), ADR 0070 (`pci_device` gains fields), ADR 0071 (`windows_start` gains a second kind of
  observation)

## Context

`pci_device` says which PCI devices Windows remembers now (ADR 0070). It cannot say that a device was started at some
earlier start and not at others unless Windows still lists it as absent. A reviewer looking at a PC after a game session
wants that history: which bus positions held a device Windows started, at which starts.

Windows has a log that may answer this. `Microsoft-Windows-PCI/Operational` records state changes of the PCI root bus,
its bridges and its devices. Each record's `EventData` has a `Message` field, for example
`[PDO] (0x0000.0x06.0x00): Begin state transition from UNINITIALIZED to STARTED`. A message names a position, not a
vendor, a model, a serial number or a person.

This ADR decides what is read from that log, the facts added to `pci_device`, and one kind of bug check. It does not
decide USB, display or Bluetooth devices. Those are separate ADRs.

## Measured before code

All probes printed counts, field names or lab values. No device id, serial number, account or address from a real PC was
kept.

### On the development PC (2026-11-18, Windows build 26320, elevated)

| Question | Result |
|---|---|
| Is the channel present and enabled? | Yes: circular, 1 MB |
| How much does it hold? | 1,902 records over 25 days |
| What kinds of message? | 19 root starts, 190 bridge starts and 742 device starts, each with a begin and a finish line |
| Do root starts match Windows starts? | Yes: all 19 match `Kernel-Boot` event 27, 15 at the same second. The other 4 are the second of two starts 90–102 s apart |
| Which positions appear? | 39 distinct device positions, each at every start. One device start is left over (39 × 19 = 741) and is not explained |
| Can `DEVPKEY_PciDevice_*` be read? | Base class on 24 of 40 present PCI devices, link speed and width on 12, with no driver of our own |

### In the lab virtual machine (2026-11-18, Windows 11 Arm 26300, QEMU)

Each row is one full start on a throwaway overlay of the lab disk. "Device" is a QEMU NVMe controller, which Windows has a
driver for. "No driver" is QEMU's `edu`, which it does not.

| Change before the start | Latest start's positions compared with the first row |
|---|---|
| Nothing | 5 positions |
| Device at a root-complex slot | adds `0x0000.0x06.0x00` |
| That device removed | back to the 5 |
| Device behind root port 1 | adds `0x0001.0x00.0x00` |
| The same again | the same position |
| Removed | back to the 5 |
| Device behind root port 2 | adds `0x0002.0x00.0x00` |
| Removed | back to the 5 |
| Device with no driver, behind root port 1 or 2 | **no change** |

After a Fast Startup shutdown (`shutdown /s /hybrid`), the next `Kernel-Boot` event 27 had `BootType=1` and **no new root
start** was logged. A device taken out during that shutdown had a line `[PDO] (position): … to REMOVED` at the resume, both
for the NVMe device and for the device with no driver. The following full start listed the positions without it.

With a Medium-integrity token in the same machine:

| Read | Result |
|---|---|
| PCI device list and `DEVPKEY_PciDevice_*` | allowed |
| `DEVPKEY_Device_Children` | allowed |
| The channel through `Get-WinEvent` | allowed |
| `Microsoft-Windows-PCI%4Operational.evtx` and `System.evtx` as files | denied |

### The bug check record

`Microsoft-Windows-WER-SystemErrorReporting` event 1001 in `System` holds `param1`, `param2` and `param3`. On the one
record measured, `param1` has the shape `0x… (0x…, 0x…, 0x…, 0x…)`, `param2` is a dump path and `param3` an identifier.
Microsoft documents bug check `0xE6` as `DRIVER_VERIFIER_DMA_VIOLATION`, and first parameter `0x26` as "IOMMU detected DMA
violation". No record with this code has been seen.

## Decision

### 1. A collector: `pci_start_history`

Standard tier. It reads `Microsoft-Windows-PCI%4Operational.evtx` through the same file path and parse budget as
`windows_start` (ADR 0071). A denied read without an elevated token is `not_admin`; a PC without the file is
`source_absent`.

The parser keeps only: the record time, whether the message is a root start, a device start or a device removal, and the
position written in the fixed form above. **Every other part of the payload is dropped**, including any message it does
not recognise, which is counted as a gap.

A new start begins at a root-start line whose root bus number was already seen in the current start. That keeps two root
buses in one start together and does not depend on the time between starts.

One observation per position:

| Field | Kind | Holds |
|---|---|---|
| `position` | text | the three numbers as the log writes them |
| `starts_seen` | number | how many starts in the log list it as started |
| `starts_total` | number | how many starts the log holds |
| `in_every_start` | boolean | `starts_seen == starts_total` |
| `in_latest_start` | boolean | listed at the newest start |
| `first_started_at`, `last_started_at` | timestamp | first and last time it was listed as started |
| `removal_recorded_at` | timestamp | newest removal line for that position, when there is one |

The rule engine reads one observation at a time, so the comparison across starts is made here.

### 2. One context rule

`pci_start_history/partial/not-every-start`: `in_every_start: false`, `strength: context`, `status: experimental`.

The row says Windows started a device at this position at N of the M starts the log holds. It does not say what the
device was, why it was there or how it left. False positives to name: a part added, replaced or moved; a firmware setting
that changes what the board shows; an external PCIe or Thunderbolt device; a position change caused by another device; a
log that begins in the middle of a change.

No timeline selector. A position present at every start would add one line per position with nothing to ask about, and a
selector would show them in SS mode.

### 3. More facts on `pci_device`

`pci_device` gains `bus_class`, `bus_subclass`, `link_speed`, `link_width`, `max_link_speed`, `max_link_width` and
`child_count`. A value Windows does not give is absent. `child_count` counts `DEVPKEY_Device_Children`; the children's ids
are not kept.

`DEVPKEY_PciDevice_*` is declared by `pciprop.h` and is not in the `windows` 0.62.2 bindings, so `device.rs` defines those
keys and cites the header. No Microsoft Learn page was found. ADR 0069 §4 is the precedent: a declared key, read as what
was measured.

**No rule uses these fields.** On the measured PC a link below its maximum is ordinary, and a network controller has no
child device. An expected-result table would also be a list of what counts as normal, which hard rule 9 does not allow. A person
reads the facts beside the device.

`pci_device` does not gain a position. The history collector says whether a position was at the newest start, so the
device list need not be joined to the log.

### 4. Bug check `0xE6` on `windows_start`

`windows_start` gains a discriminator, `record`: `start` for what it reports today and `bug_check` for this. The second
kind is emitted only when `param1` names code `0xE6`, with `bug_check_code`, `bug_check_parameter_1` and the record time.
The parse is the one the collector already makes. `param2`, `param3`, the other parameters and every other bug check are
dropped.

`windows_start/dma/bug-check-e6`: `strength: context`, `status: experimental`. False positives to name: Driver Verifier
turned on, a faulty driver, faulty hardware.

### 5. What the reader is told

The change that ships section 1 also changes `PRIVACY.md`, which today says the program never reads "a device's position
on the board", and both consent texts and both screenshare guides. They say: positions come from a Windows log, name no
device, and let two reports of one PC be matched, as first-install times already do (ADR 0069 §7).

SS mode lists the rows the rule matched and counts the rest. `pci_start_history` is not added to the saved record's
`DEVICE_COLLECTORS` until an upload consent text names it. The same change confirms that Connect's collector list keeps it
out until a Connect decision says otherwise.

## What this does not do

- It does not say what a device was, what it did, or whether it read memory.
- It does not list a device Windows did not start. A present device with no driver remains the concern of
  `pci_device/no-driver/problem-28`.
- It cannot speak for starts the circular log no longer holds. The report states how far back it reaches.
- It does not read the log through the Event Log API, so it is unmeasured without elevation (below).

## Alternatives weighed

- **`EvtQuery` for standard users.** The Medium-integrity probe could read the channel this way. It would add a second
  evtx path and rendering surface, while the existing parser already reads the file when elevated. It can be added later
  if unelevated scans need this row.
- **Join positions to `pci_device`.** It would put a position on every present device for no finding this ADR makes.
- **A time gap to tell starts apart.** Tried on the development PC and wrong: starts 90–102 s apart were merged.
- **`Kernel-PnP`, `DeviceSetupManager`, `UserPnp` or `Kernel-WHEA` payloads.** They carry instance ids, names or raw data, and
  are not needed for this question.
- **`Win32_DeviceGuard`.** ADR 0038 already declined it.

## What is unverified

- A physical PC with a card added, removed or moved. The virtual machine runs Windows on Arm.
- Whether the channel exists and is enabled on older supported Windows builds.
- How often positions change on ordinary PCs. One PC was measured, with none.
- Why the development PC has one device start beyond 39 per start.
- A real `0xE6` record.

## Decisions for the owner

Decided on 2026-11-18: all as recommended.

| # | Question | Decided |
|---|---|---|
| 1 | Read this log in the standard scan if the virtual machine and a real PC show it works? | Yes |
| 2 | Allow PCI positions, and tell the reader that reports can be matched through them? | Yes |
| 3 | Read payload from this log and the `0xE6` bug check only? | Yes |
| 4 | Keep Connect out until Offline has shipped? | Yes |

## As built (2026-11-18)

- Section 3: `pci_device` carries the seven fields; they are read for present devices only, and no rule uses them.
- Section 4: `windows_start` declares `record`; `windows_start/dma/bug-check-e6` is in `rules/unconfronted.csv`, because no baseline host carries a System log.
- Sections 1 and 2 are not built.

## Consequences

- One collector, two context rules, seven `pci_device` fields and one new discriminator on `windows_start`.
- `COLLECTOR_ORDER`, fixtures, baselines, snapshots, ages, translations, the rules reference, the coverage table,
  `measured.csv`, the consent texts, `PRIVACY.md`, the guides and `docs/architecture.md` change with the code.
- The rules stay `experimental` until at least three real PCs have been measured.
