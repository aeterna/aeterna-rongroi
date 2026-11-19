# ADR 0096 — USB, display and Bluetooth devices Windows remembers, and device facts before the scan

- Status: proposed — five questions for the owner below
- Date: 2026-11-19
- Amends: ADR 0069 (three more enumerators; `USB` is read after all), ADR 0070 and ADR 0072 (device times are counted
  in the "before the scan" window), ADR 0078 (that window gains device counts), ADR 0062 (whose "never the scan's
  time" ADR 0078 §3 already narrowed)

## Context

R1 (ADR 0095, release 0.16.0) covered the PCI bus. The DMA traces plan's second release, R2, covers the other devices
a PC is connected to or remembers: USB devices, displays and Bluetooth devices, and what happened to them between the
latest game session and the scan.

The owner decided on 2026-11-18, as plan question 1, that R2 reads these devices **in the full scan only** and keeps
**models, types and times**: no EDID for displays, and Bluetooth through the Bluetooth API. ADR 0069 §2 had decided
not to read `USB`, because that enumerator adds storage, phones and cameras whose names can carry a person's name.
PRIVACY.md still says the program never reads "any USB device, phone, camera or drive".

Plan scrutiny on 2026-11-18 added three limits: no port or parent device, no timeline selector for these devices
(a selector puts every row's times on the SS timeline), and no undocumented registry layout (ADR 0038).

## Measured before deciding

On the development PC (2026-11-19, Windows build 26320, elevated). The probe printed counts and id shapes only, with
every hex run masked, and no instance id, serial number, address or name (`.claude/probes/r2-devices-2026-11-19/`,
kept outside git).

| Enumerator | Remembered | Present | With first install / arrival / removal | Hardware id shapes |
|---|---|---|---|---|
| `USB` | 23 | 21 | 23 / 23 / 2 | `USB\VID_h&PID_h&REV_h&MI_h` (13), `USB\VID_h&PID_h&REV_h` (8), root hubs (2) |
| `USBSTOR` | 1 | 0 | 1 / 1 / 1 | `USBSTOR\Disk<vendor>_<product>_<rev>`, maker and product as text |
| `DISPLAY` | 2 | 2 | 2 / 2 / 0 | `MONITOR\AAAhhhh` (3 letters and 4 hex digits) |
| `BTH` | 4 | 4 | 4 / 4 / 0 | the PC's own Bluetooth services (`BTH\MS_…`) |
| `BTHENUM` | 12 | 12 | 12 / 12 / 0 | `BTHENUM\{service}_VID&h_PID&h` (9), `BTHENUM\Dev_` and 12 hex digits (2), `BTHENUM\{service}_LOCALMFG&h` (1) |
| `BTHLE`, `BTHLEDEVICE` | 0 | 0 | — | — |

- USB classes from `USB\Class_xx` in the compatible ids: 01 audio (2), 03 HID (10), 08 storage (2), 0E video (1),
  E0 wireless controller (1), FF vendor-specific (1).
- The third part of a USB instance id looked like a serial number on 5 devices and like an address on 1. ADR 0069 §3
  already keeps it inside the host; this ADR keeps that rule.
- Field widths, counted without printing the digits: USB `VID_`, `PID_` and `REV_` 4 hex digits on all 21 model ids, `MI_` 2
  on 13; 17 USB devices have `USB\Class_xx&SubClass_xx&Prot_xx` with 2 digits each; displays 3 letters and 4 digits;
  Bluetooth `VID&` 8 and `PID&` 4 on 9 ids, and a braced GUID on 10.
- `BTHENUM\Dev_` followed by 12 hex digits is the shape of a Bluetooth device address. Two of the 12 hardware ids
  have it, so the hardware id itself can carry an address, not only the instance part.
- The Bluetooth API without an inquiry returned 2 devices where `BTHENUM` lists 12 entries for the same devices'
  services. The probe's decoding of the API's flags and dates was not reliable, so those values are not used here.
- All of it is read through CfgMgr32 without administrator rights (ADR 0069 measurement 1; the `USB` and `DISPLAY`
  keys grant Users read).

## Decision

### 1. `DeviceSource` reads three more buses

`DeviceBus` gains `Usb`, `Display` and `Bluetooth`. The enumerators are `USB`, `DISPLAY` and `BTHENUM`, read the way ADR 0069 §2 reads `PCI` and `HID`: every device Windows remembers, then which are present,
each opened as a phantom when absent.

The model id keeps only fields of the first hardware id that match one fixed shape each, as ADR 0069 §3 does. A
field of any other shape is dropped whole, not shortened:

| Bus | Kept, each in exactly this shape | Dropped whole |
|---|---|---|
| USB | `VID_` and `PID_` with 4 hex digits, `REV_` with 4, `MI_` with 2, and `ROOT_HUB` alone | every other part |
| Display | `MONITOR\` with 3 letters and 4 hex digits | any other id, such as a default-monitor name |
| Bluetooth | the service id as a braced GUID, and `VID&` with 8 hex digits and `PID&` with 4 after it | `Dev_` with an address, `LOCALMFG&…`, and every other shape |

A Bluetooth id with no braced GUID keeps nothing and has no `name`. USB also reads the class, subclass and protocol from
the first `USB\Class_xx&SubClass_xx&Prot_xx` of the **compatible ids**, each 2 hex digits. A composite USB device is
listed once per interface (`MI_`), as Windows lists it; rows are not merged.

Not read: `USBSTOR`
(its id holds maker and product as free text), `SWD`, `BTH` (the PC's own radio), friendly names, bus-reported
descriptions, location paths, parent devices, EDID, Bluetooth addresses, and `BTHLEDEVICE` until a Bluetooth LE device
has been measured.

### 2. Three collectors, full scan

`usb_device`, `display_device` and `bluetooth_device`, each in the shape of `hid_device` (ADR 0072 §1): `name`,
`vendor_id` and `product_id` where the id has them, `service`, `present`, and the three times. `usb_device` adds
`usb_class`, `usb_subclass` and `usb_protocol`; `bluetooth_device` adds `bluetooth_service`. Full tier, as decided.
An unreadable property is a gap on its field.

### 3. Rules

- `usb_device/absent/not-present` and `display_device/absent/not-present`: `present: false`, `context`,
  `experimental`, in the words of `pci_device`'s absent rule (ADR 0070 §3). False positives: a drive, phone, headset
  or game controller used once and put away; a dock, KVM switch or capture device; a monitor or TV replaced.
- No Bluetooth rule. No rule can tell a paired device's ordinary causes apart from others; the rows are listed in
  Self mode and counted in SS mode.
- No timeline selector for the three collectors. Self mode lists every row; SS mode lists matched rows and counts
  the rest (ADR 0014).

### 4. Device facts before the scan (ADR 0078 amended)

ADR 0078 §3 already defines the "before the scan" window: from the latest session's end to the scan's
`generated_at`. It is built in `rongroi_core::view::game` (`GameWindows`), which already carries counts per window
(ADR 0081 §4). That view gains two counts for the window, from fields reports already carry. The session statement
(`view::session`) does not change and still compares nothing with the scan's time.

- devices whose `last_removal_at` falls in it, per collector (`pci_device`, `hid_device`, `usb_device`,
  `display_device`, `bluetooth_device`);
- Windows starts (`windows_start`, `record: start`) in it.

Each count says what was recorded, never why. There is no window, and the counts are "not known", when no session
was found, when the latest session has no recorded end (one still running included), or when the scan time is not
known, as ADR 0078 already words those cases. No new timeline entries. The saved record does not carry this view, so
it does not change.

### 5. What the reader is told

PRIVACY.md, both consent texts and both screenshare guides name the three reads in the full scan: model numbers,
type, driver and times, never a serial number, name, address or EDID. They also say that the type shows which kinds
of device were plugged in, such as a drive or a phone, and that the first-set-up times of these devices, like the PCI
ones, can match two reports of one PC. The SS consent names the counts of section 4, which SS mode shows. ADR 0069 §2's "`USB` is not read" is replaced
by this ADR. The three collectors stay out of the saved record's `DEVICE_COLLECTORS`, and out of Connect, until an
upload consent text names them.

## What this does not do

- It does not say what a device was used for, and it does not tell a cheat device from an ordinary one with the same
  numbers.
- It does not read a storage device's contents, a monitor's EDID, or which port a device used.
- It does not see a device Windows never set up, or one whose entry was removed from the device store.
- It does not run in the standard scan.

## Alternatives weighed

- **The Bluetooth API, as plan question 1 said.** It returns addresses and names that would have to be dropped, its
  last-used and last-seen times were not decoded reliably in the probe, and it needs a second code path. The device
  store gives models, presence and times through the code `pci_device` and `hid_device` already use. Question 1 below
  asks the owner to change that part of the earlier decision.
- **`USBSTOR` for storage.** The maker and product are free text; `USB` already shows a storage device's numbers and
  class 08.
- **A timeline selector for absent USB devices.** It would put every past drive's times on the SS timeline.
- **A new window for "before the scan".** ADR 0078 already has it; adding counts there keeps one definition.
- **Section 4 as a separate ADR.** It would let the collectors ship without touching the window. It is small and uses
  the same devices, so it stays here; question 3 lets the owner take it out.

## What is unverified

- Bluetooth LE devices: the measured PC has none, so `BTHLEDEVICE` is not read until one is measured.
- Older supported Windows builds.
- How many absent USB devices an ordinary PC remembers. One PC was measured, with 2.
- Whether a removal time is written for USB and display devices taken out while the PC is off. ADR 0069 measured
  this for PCI only.

## Decisions for the owner

| # | Question | Recommended |
|---|---|---|
| 1 | Read Bluetooth devices from the device store (`BTHENUM`) instead of the Bluetooth API, changing that part of plan question 1? | **Yes**: the address shape is dropped whole, and the same code and times as PCI and HID |
| 2 | A `context` rule for an absent USB device and for an absent display, and no Bluetooth rule? | **Yes** |
| 3 | Add the two counts to the "before the scan" window instead of building a new timeline line? | **Yes** |
| 4 | Keep the three collectors out of the saved record and Connect until an upload consent names them? | **Yes** |
| 5 | Check in the lab virtual machine before release: a USB device and a display added, removed while running, removed while off? | **Yes** |

## Consequences

- Three collectors, two context rules, one amended session statement, and three more `DeviceBus` values.
- `COLLECTOR_ORDER`, fixtures, baselines, snapshots, translations, the rules reference, the coverage table, the consent
  texts, PRIVACY.md, the guides and `docs/architecture.md` change with the code.
- The rules stay `experimental` until three real PCs have been measured, as ADR 0095's do.
