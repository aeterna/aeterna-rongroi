# ADR 0072 — The HID devices Windows knows, on the timeline only

- Status: accepted — the owner chose to show HID times now rather than wait for a case, and decided the four
  questions below, on 2026-10-16
- Date: 2026-10-16
- Amends: ADR 0070 decision 4 ("no HID collector in this release"), for the next release

## Context

ADR 0069 built a source that lists the `HID` enumerator as well as `PCI`, and ADR 0070 used only the `PCI` half. ADR 0070
left HID out because no rule survived (0070, "Why HID waits"): an ordinary PC already has more than one mouse-class
device (three on the development PC with one mouse connected), and the other sketched rules needed the `USB`
enumerator or `BusReportedDeviceDesc`, which ADR 0069 does not read. Matching a box by its vendor and product numbers
would put a product's numbers in this public repository, which this project does not do.

What HID does have is **times**. ADR 0069 measured them in the lab virtual machine with a second USB mouse (0069, steps
1–7):

- a mouse added while the PC was off has a `FirstInstallDate` at the next start;
- a mouse removed while Windows was running has a `LastRemovalDate` to the minute (step 4) — unlike PCI, whose
  hot-unplug the guest never completed;
- a mouse removed during a Fast Startup shutdown has a `LastRemovalDate` at the resume; after a full shutdown it has
  none, and `windows_start` (ADR 0071) now says which kind of shutdown it was.

A box that sits between a mouse and the PC is plugged in where the mouse was. When that happens the PC sees a mouse
leave and a mouse arrive. The times say **when** that happened, not what was plugged in, and an ordinary mouse swap
looks the same. That is context, and it is what the owner chose to show.

Measured on the development PC on 2026-10-16 (read-only, counts only): 25 HID devices, all present — 3 with the
`mouhid` service (class Mouse), 8 `kbdhid` (Keyboard), 14 with no service (HIDClass collections). In the virtual
machine a QEMU USB mouse was `mouhid` and its keyboard collection `kbdhid`.

## Decision

### 1. The collector: `hid_device`, standard tier

One observation per device the `HID` enumerator lists, present or not, in the shape of `pci_device` (ADR 0070 §1):

| Field | Kind | From |
|---|---|---|
| `name` | text | the model id: `HID\VID_xxxx&PID_xxxx` plus `REV_`, `MI_` and `COL` when present — never the instance part (ADR 0069) |
| `vendor_id`, `product_id` | text | `VID_` and `PID_` of the model id |
| `service` | text | the driver service: `mouhid` is a mouse, `kbdhid` a keyboard |
| `present` | boolean | |
| `first_install_at`, `last_arrival_at`, `last_removal_at` | timestamp | as `pci_device` |

No `problem_code` and no class code: no selector reads them. An unreadable property is a gap on its field, as in
`pci_device`. No administrator rights are needed (ADR 0069, measured).

### 2. One context rule and one timeline selector

- `hid_device/absent/not-present` — `present: false`, `context`, `experimental`: an HID device Windows set up earlier
  that is not present now, with its times, in the shape of `pci_device`'s absent rule (ADR 0070 §3). A mouse or
  keyboard that was used once and put away matches on every PC, and the rule says so in its `falsepositives`.
- `hid_device/timeline/device-times` — every HID device, present or not: when Windows first set each up, last saw it
  at a start and recorded it removed. The owner asked for every device rather than mice only (question 2): on the
  development PC that is 25 devices and up to 75 lines, 14 of them collections of a device that is listed again with
  its driver.

SS mode lists what the rule matched and puts every HID device's times on the timeline; it lists no present device as
a finding.

### 3. Consent, privacy, the guides

The consent text and PRIVACY.md name the read: "the mice, keyboards and other input devices Windows remembers, present
or not: the maker and model numbers and the driver, and when Windows set each up, last saw it at a start and recorded
it removed — never a serial number or a name". The guides' "cannot show" row for a box between the mouse and the PC
changes to: the program shows when mice were plugged in and taken out, and cannot tell a box from a mouse.

### 4. Fixtures

QEMU's USB mouse and keyboard ids (`VID_0627&PID_0001`) and made-up ids only; no id from a real PC, as ADR 0069 says.
Baselines: the consumer PC has a mouse and a keyboard with the collections Windows lists beside them (a driver
service on the mouse and keyboard entries only, as measured); the hardened PC a mouse and a keyboard; the elevated
baseline, which describes the CI runner, none, since its HID devices were not measured.

## What this does not do

- It does not say a box is there. A box that copies the mouse's numbers looks like that mouse; one that does not looks
  like a new mouse.
- It does not read `USB`, `BusReportedDeviceDesc`, friendly names or location paths (ADR 0069 decision 4).
- It does not compare a time with the scan's session. The reviewer reads the times beside the session on the timeline.

## Alternatives weighed

- **Wait for a case** (ADR 0070 decision 4). The owner chose to show the times now.
- **No rule** (recommended, not chosen): a device that is gone is the same kind of context ADR 0070 already reports for PCI.
- **A rule on more than one mouse.** Ordinary on the development PC (three `mouhid` devices with one mouse).
- **A rule on a mouse first set up recently.** "Recently" needs a time compared with the scan, which no rule does; and a
  new mouse is ordinary.

## What is unverified

- A real box: not measured, no box is owned (ADR 0069).
- Whether a box presents itself as `mouhid`: expected, not measured.
- HID times on x64 hardware: measured on the development PC for present devices only; removal times only in the VM.

## Decisions for the owner

Decided on 2026-10-16.

| # | Question | Recommended | Decided |
|---|---|---|---|
| 1 | Standard tier, no administrator rights, with the consent text and PRIVACY.md naming the read? | **Yes** | Yes |
| 2 | The present-device selector picks mice only (`mouhid`), not keyboards (`kbdhid`)? | Mice only: 3 rows on the development PC instead of 11 | **Every HID device, present or not** |
| 3 | No rule, only timeline selectors? | Yes | **A `context` rule for an HID device that is not present now, and one selector** |
| 4 | Checked in the lab virtual machine before release, as ADR 0070 §7 was? | **Yes**: add, remove while running, remove while off | Yes |

## Consequences

- One collector, one rule and one selector, baselines and fixtures; consent, PRIVACY.md, the guides, architecture and changelog.
- The report gains `hid_device` observations. Every HID device's times are on the timeline in both modes.

## As built (2026-10-16)

- `crates/rongroi-collectors/src/hid_device.rs`, the shape of `pci_device` without class code or problem code;
  `COLLECTOR_ORDER` puts it after `pci_device`.
- `rules/hid_device/absent/not-present` and the selector `rules/hid_device/timeline/device-times`
  (`present: [true, false]`), each with a positive and a negative fixture; Thai text in `rules/i18n/th.yaml`.
- The consent text (CLI and app, both languages), PRIVACY.md, both screenshare guides, `docs/architecture.md` and the
  changelog name the read. ADR 0070 carries the amendment.
- The reading was mapped first through `aeterna-delegate` (read mode, verified) and every fact used was checked
  in the files.
