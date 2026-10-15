# ADR 0070 — The PCI devices Windows knows: a collector and two rules

- Status: accepted — the owner decided the four questions below on 2026-10-15, each as recommended
- Date: 2026-10-15

## Context

ADR 0069 decided the source: a read-only `DeviceSource` over CfgMgr32 that lists the PCI and HID devices Windows
remembers, present or not, as model ids with a class code, a driver service, a problem code and three times. It left
the collectors and rules to later ADRs. This is the first: PCI only.

What a reviewer needs from it, in the order the measurements support it:

1. **A PCI device Windows has no driver for.** A card whose firmware does not imitate a real device, as a cheap one
   with its default firmware may, is enumerated by Windows and left without a driver. In the virtual machine of
   ADR 0069 ("Measured in a virtual machine") a driverless PCI device showed problem
   code 28 and no service. On the development PC, 0 of 40 present PCI devices had problem code 28, while 17 had no
   driver service at all — 16 host bridges and one SMBus controller — so "no service" alone is ordinary and problem
   code 28 is not.
2. **A PCI device that is not in the PC any more.** The virtual machine showed what one leaves behind: it is
   listed as not present; `LastArrivalDate` is the last start at which it was there; and `LastRemovalDate` exists
   only when it left while Windows was running or during a Fast Startup shutdown, where it is the moment Windows
   resumed.

This ADR does **not** cover HID devices (ADR 0069's other enumerator), IOMMU tables (an amendment of ADR 0038), the
kind of the last start (an amendment of the `evtx` collector's ADR), or the case code and the button that saves a
report (their own ADR). Each is decided apart, so this one can ship alone.

### Why HID waits

Every rule the plan sketched for HID devices fell: the development PC shows three present devices of the Mouse
class with one mouse connected, so "more than one mouse" is true of an ordinary PC; and the other two needed the
`USB` enumerator or `BusReportedDeviceDesc`, which ADR 0069 decided not to read. A HID collector with no rule would
add a consent line and a row type for context only. It waits until a case shows it is needed.

## Decision (proposed)

### 1. The collector: `pci_device`

One observation per device `DeviceSource::devices` returns with `bus = Pci`, present or not. Standard tier: no
administrator rights are needed (ADR 0069, measurement 1) and no field names a person, a file or a server.

| Field | Kind | Holds |
|---|---|---|
| `name` | text | the model id ADR 0069 §3 keeps, e.g. `PCI\VEN_1234&DEV_11E8&SUBSYS_11001AF4&REV_10` |
| `vendor_id`, `device_id` | text | the four hex digits after `VEN_` and `DEV_`, upper case |
| `subsystem_id` | text | the eight hex digits after `SUBSYS_`, when the id has them |
| `class_code` | text | the four hex digits of `PCI\CC_xxxx` in the compatible ids (`0600` host bridge, `0108` NVMe, `0300` display) |
| `service` | text | the driver service bound to the device; absent when none is |
| `problem_code` | number | Windows' problem code, present devices only; absent for a device that is not present |
| `present` | yes/no | listed with `CM_GETIDLIST_FILTER_PRESENT` |
| `first_install_at`, `last_arrival_at`, `last_removal_at` | time | ADR 0069's three times, whole seconds; absent when Windows gave none |

No discriminator: the collector reads one place. A device whose properties could not be read keeps `name`,
`present` and a gap for each field it could not read, so a rule that needs one of them is `unmeasured` for that
device rather than `not_found`. A failure of the device list itself is `unmeasured` for the whole run with the
reason `read_failed`; on anything but Windows, `not_windows`.

Every PCI device is emitted, as ADR 0069 §6 decided. ADR 0014 then shows the devices no rule matched as a list in
Self mode and a count in SS mode.

### 2. Rule: a PCI device with no driver installed

`pci_device/no-driver/problem-28`: `present: true`, `problem_code: 28`, `strength: presence`, `status:
experimental`, `unmeasured_when: [not_windows]`.

- **Title:** "A PCI device has no driver installed"
- **Description** says Windows found the device and installed no driver for it, and that this program cannot say
  what the device is beyond the ids Windows recorded. It does not say a card was used to cheat, or that a card
  imitating another device would appear here — one with a driver would not.
- **False positives:** Windows installed again, before the chipset or device drivers were added; a capture, sound,
  serial or expansion card whose driver was never installed; hardware too new or too old for the drivers Windows
  carries; a virtual machine, whose virtual devices often have no driver (in the measured virtual machine its
  network device did not).

Problem code 28 only. Other codes (10, failed to start; 22, disabled; 43, stopped after a failure) are left out: a
device with a driver that fails is a different question, and none was measured.

### 3. Rule: a PCI device that is not in the PC now

`pci_device/absent/not-present`: `present: false`, `strength: context`, `status: experimental`.

- **Title:** "A PCI device Windows set up earlier is not present now"
- **Description**, in the words the measurements allow:
  - "Windows set this device up first on `first_install_at`, and it was present at the start of Windows on
    `last_arrival_at`. It is not present now."
  - Only when `last_removal_at` exists: "Windows recorded its removal at `last_removal_at`." The row never says how
    the device left. A device taken out while the PC was fully shut down has no removal time at all; one taken out
    during a Fast Startup shutdown has the time Windows resumed (ADR 0069, measured in a virtual machine).
- **False positives:** a graphics card, SSD or network card replaced or moved to another slot; a BIOS update or a
  BIOS setting that changes which devices the board shows (an onboard controller switched off, a slot's mode
  changed); a Thunderbolt or external PCIe device that was unplugged; Windows moved to another PC.
- Strength `context`, not `presence`: an absent device is common on any PC that has had a part changed. The
  development PC had none, which is one PC.

### 4. Timeline

One timeline selector, `pci_device/timeline/absent-device-times`, `role: timeline`, `match: {present: false}`:
puts each absent device's three times on the timeline, so a reviewer sees "present at the start of …" and any
removal time beside the FiveM session and the other records ADR 0051 gathers.

**No selector for present devices.** Their `last_arrival_at` is the start of Windows for every one (40 identical
entries on the development PC), and their `first_install_at` is mostly the day Windows was installed.

**No "new device" rule.** The plan's R-A4 ("first set up in the last N days") needs a comparison with the scan time
that a rule's `match` cannot express today. The absent-device selector and the device list in Self mode show
`first_install_at` already; a rule waits for a reason to add that operator.

### 5. What a reviewer reads alongside

- The SS guide (th/en) gets rows in "It can show" — a PCI device with no driver; a PCI device that was present at
  an earlier start and is not now, with a removal time only in the cases above — and keeps "It cannot show" a DMA
  card whose firmware imitates a real device, and a mouse box (no HID collector).
- PRIVACY.md and the consent text name the new read before it ships: "the PCI devices Windows has recorded,
  present or not — the maker and model numbers Windows uses, the driver, and when Windows set each up, last saw it
  at start-up and recorded it removed; never a serial number."
- `docs/architecture.md` gains the collector's row.

### 6. Fixtures and baseline

- The three `baseline-*` hosts gain synthetic device lists shaped like the development PC: host bridges (`0600`)
  and an SMBus controller (`0C05`) with no service and problem code 0, an NVMe controller with `stornvme`, a display
  controller with a driver — all present. Both rules must be quiet on all three (`cargo xtask check-baseline`).
- Positive fixtures: `pci-no-driver` (one present device, problem code 28) and `pci-absent` (one absent device with
  a removal time, one without). Negative: the baselines, and a present device with no service and problem code 0.
- No id from a real PC goes into a fixture. The vendor ids used are QEMU's (`1B36`, `1AF4`, `1234`) and the
  well-known chipset and display vendors, with made-up device ids.

### 7. Checked in the virtual machine before release

The release that carries this collector runs its CLI in the lab virtual machine through the seven steps ADR 0069
measured, and the result is written into this ADR: step 1 shows the no-driver row; step 2 and step 6 show the absent
row, without and with a removal time; steps 3 and 7 show no absent row for the device that came back.

## What this does not do

- It does not detect a DMA card that imitates a real device, and nothing written from it may claim to.
- It does not read HID devices, IOMMU tables, the kind of the last start, or a device's registers.
- It does not say how or why a device left the PC.

## Alternatives weighed

- **Rule on "no driver service".** Fires on 17 of 40 devices of an ordinary PC.
- **Rule on every non-zero problem code.** Mixes "no driver" with "driver failed"; none of the others was measured.
- **`presence` strength for an absent device.** Any PC whose graphics card was replaced would show a presence row.
- **A HID collector in the same release.** No rule survives for it (Context).

## What is unverified

- Problem code 28 for a real card on a physical x64 PC (the virtual machine runs Windows on Arm).
- A PCI device removed while Windows runs (the virtual machine's guest never completed it).
- How often an absent PCI device appears on ordinary players' PCs: one PC measured, with none.

## Decisions for the owner

Decided on 2026-10-15: all four as recommended.

| # | Question | Recommended |
|---|---|---|
| 1 | Standard tier (every scan), not the full scan's consent? | **Yes**: no administrator rights, no personal names; the consent text and PRIVACY.md name the read |
| 2 | The no-driver rule matches problem code 28 only, as `presence`? | **Yes** |
| 3 | The absent-device rule is `context`, and says "removed at" only beside a recorded removal time? | **Yes** |
| 4 | No HID collector, no "new device" rule and no selector for present devices in this release? | **Yes** |

## Consequences

- One collector, two rules, one timeline selector, fixtures for three baselines and two positives.
- Two PRs: the `DeviceSource` trait with `LiveHost` and `FixtureHost` (ADR 0069's scope), then this collector, its
  rules, the guide, PRIVACY.md and the consent text.
- The report gains `pci_device` observations; `REPORT_SCHEMA_VERSION` stays 1 (ADR 0069 §8).

## As built (2026-10-15)

- `crates/rongroi-collectors/src/pci_device.rs`; rules `pci_device/no-driver/problem-28`,
  `pci_device/absent/not-present` and the selector `pci_device/timeline/absent-device-times`, each with a positive
  and a negative fixture; the three baselines describe synthetic devices and every rule is quiet and confronted
  there (`check-baseline`).
- Every timestamp field is a timeline time, as ADR 0051 makes every time value in Self mode: on an ordinary PC that
  is one `last_arrival_at` per device at the start of Windows. SS mode shows only the selector's absent devices.
- The consent question (CLI and desktop, both languages), PRIVACY.md, both screenshare guides and
  `docs/architecture.md` name the read. `COLLECTOR_ORDER` puts `pci_device` after `driver_service`.
- A fixture host that describes no devices makes the run `read_failed`, so every older report snapshot gained that
  one unmeasured run and nothing else.
- Section 7, the run in the lab virtual machine, is recorded below ("Section 7, as run").

## Section 7, as run (2026-10-15)

The CLI built from `feat/pci-device` at `6facdd0` (`x86_64-pc-windows-gnu`, run under x64 emulation) ran
`rongroi scan --json` elevated in the ADR 0069 lab virtual machine (Windows 11 Arm 26300, QEMU's `edu` device as the
card) at five steps. The steps are those of ADR 0069, run again with the CLI in place of the probe:

| Step | What was done before it | `no-driver` | `absent` | What the absent row held |
|---|---|---|---|---|
| T1 | `edu` added, full start | found: `edu` and the VM's network card (no virtio driver on this image), both 28 | not found | — |
| T2 | `edu` removed while off after a full shutdown | found: the network card | found: `edu` | `last_arrival_at` = T1's start, no `last_removal_at` |
| T3 | `edu` back, full start | found: both | not found | — |
| T4 | Fast Startup shutdown with `edu` in | found: both | not found | — |
| T5 | `edu` removed while off after T4's Fast Startup shutdown | found: the network card | found: `edu` | `last_arrival_at` = T4's start, `last_removal_at` = the resume, 2 minutes later; the report's boot time did not move from T4's |

Every row is what this section asked for. On the timeline the absent device's times were attributed to the
`absent` rule's evidence, not repeated by the selector. Step 4 of ADR 0069 (a removal while running) is not
repeated: there the guest never completed the PCI hot-unplug, so that case stays not measured. The reports are kept with the lab
(`.claude/probes/vm-lab/results/T*-scan.json`, not in this repository: they are a whole report of a lab machine).
