# ADR 0069 — Which devices Windows knows, and when they came and went

- Status: accepted — the owner decided the five questions below on 2026-10-15, each as recommended. The
  collectors and rules that would read this source are later ADRs
- Date: 2026-10-14
- Number: 0066–0068 are held by another plan that is still in review; this one keeps 0069

## Context

Some cheats run on a second PC and read or write the game's memory through a PCIe card in the player's PC (direct
memory access, DMA), and move the mouse through a small box between the real mouse and the PC. Nothing of the cheat
runs on the player's PC. ADR 0038 says this project "would not detect a DMA device", and the screenshare guide
lists "Cheats running on a second PC" among what it cannot show. **Both stay true.** A card whose firmware presents
itself as an ordinary device looks like that device to every documented API this project may call.

What the PC does keep is Windows' own record of the devices it has enumerated — including devices that are no
longer present — with times Windows stores beside each one. A person checking a PC wants to ask: which PCI devices
are in this PC, does any have no driver, and did a device leave the PC shortly before the check? That is evidence
and context of the same kind `driver_service` gives (ADR 0002), never a verdict.

This ADR decides only the **source**: a host trait, what it reads, what it refuses to read, and which `windows`
features it needs. The collectors (`pci_device`, `hid_device`) and their rules come after, each with its own ADR,
fixtures and baseline (crates/rongroi-collectors/AGENTS.md).

### What already exists

- No source reads devices. `FirmwareSource` reads one UEFI variable (ADR 0038); `BootTimeSource` reads how long the
  kernel has been running (ADR 0039).
- `BootTimeSource`'s documentation already says what a "start" is: a restart, or a shutdown with Fast Startup off.
  A default "Shut down" hibernates the kernel and does not reset the count.
- ADR 0014: an observation no rule matches is still kept. Self mode lists it; SS mode shows only a count.
- `REPORT_SCHEMA_VERSION` is 1 (`crates/rongroi-core/src/model.rs:16`) and every addition since has been additive.
- ADR 0011 rejected WMI for one registry value: "a far larger surface than one value is worth".

## Measured before code

On 2026-10-14, on the development PC (Windows 11, build 26220), with a counts-only PowerShell probe that calls the
same CfgMgr32 functions this ADR proposes, through P/Invoke. The probe printed counts and coarse time buckets only:
no instance id, hardware id, name or serial left the PC. It ran twice, at High integrity and at Medium integrity
(a scheduled task with `/rl LIMITED` in the owner's session). Its scripts are kept outside the repository.

| # | Question | Result |
|---|---|---|
| 1 | Do the reads need administrator rights? | **No.** Every line of the two runs is identical apart from the integrity level: the device lists, every property, `setupapi.dev.log` and the `Kernel-PnP/Configuration` log |
| 2 | How many devices, and how many not present? | 235 device ids without the "present" filter, 229 with it. PCI 40 (all present) · USB 22 (21 present) · HID 25 (all present). No Thunderbolt or USB4 enumerator exists on this PC, so the name of that enumerator is **not measured** |
| 3 | Which time properties have a value? | `FirstInstallDate`, `InstallDate` and `LastArrivalDate` on every PCI, USB and HID entry. `LastRemovalDate` on **none** of the 86 present entries and on the one absent USB entry |
| 4 | What does `LastArrivalDate` mean for a PCI device? | All 40 fall within 15 minutes after the kernel started (uptime 134.5 h). On this PC it is re-written at each start: it says "present at the last start", not "plugged in at that time". For HID it does move: 6 of 25 HID devices arrived 1–30 days after the start, while the PC was running (a receiver or a mouse plugged in again) |
| 5 | Is `LastRemovalDate` written at shutdown? | **No** for present devices (none has one). The absent USB device has one, 1–30 days old |
| 6 | Does a PCI card taken out while the PC is off get a `LastRemovalDate`? | **Not measured.** This PC has no absent PCI device. Needs a test card (PLAN-DMA §6 H1) |
| 7 | How many present PCI devices have no driver service? | 17 of 40: 16 host bridges (class `0600`) and one SMBus controller (`0C05`), all with problem code 0. **"No service" alone is ordinary.** One PC only; the plan asks for three |
| 8 | `setupapi.dev.log` | 1.8 MB, 9 days. Windows rotates it at about 4 MB into `setupapi.dev.<timestamp>.log`; with three such files the history reaches back 74 days. "Hardware initiated" device installs: none in the current file, three in the oldest (one PCI, through a Windows Update driver). Most sections are driver-package operations whose headers carry file paths |
| 9 | `Microsoft-Windows-Kernel-PnP/Configuration` | Enabled, circular, 1 MB, 2008 records, 63 days. The provider's own message texts: 400 "was configured", 410 "was started", 411 "had a problem starting", 420 "was deleted", 430 "requires further installation". 400 and 410 carry `DeviceInstanceId`. **No PCI event in 63 days**: they are written when a device is first set up, not at each start |

## Decision (proposed)

### 1. A source trait, `DeviceSource`

```text
pub enum DeviceBus { Pci, Hid }

pub struct DeviceRecord {
    bus: DeviceBus,
    hardware_id: String,          // the device's model, never its instance (section 3)
    class_code: Option<String>,   // PCI: the four hex digits of `PCI\CC_xxxx` in CompatibleIds
    service: Option<String>,      // DEVPKEY_Device_Service; None = no driver service bound
    problem_code: Option<u32>,    // DEVPKEY_Device_ProblemCode, present devices only
    present: bool,                // listed with CM_GETIDLIST_FILTER_PRESENT
    first_install: Option<Timestamp>,
    last_arrival: Option<Timestamp>,
    last_removal: Option<Timestamp>,
}

pub trait DeviceSource {
    fn devices(&self) -> Result<Vec<DeviceRecord>, SourceError>;
}
```

Times are whole seconds through `rongroi_host::listed_time`, as ADR 0050 keeps them. `None` is a value Windows did
not give, never a zero.

`NonWindowsHost` returns `Unsupported`. `Host` gains `DeviceSource`.

### 2. Two enumerators, and nothing else

`CM_Get_Device_ID_List_SizeW` / `CM_Get_Device_ID_ListW` with `CM_GETIDLIST_FILTER_ENUMERATOR` for `PCI` and for
`HID`, once without `CM_GETIDLIST_FILTER_PRESENT` (every device Windows remembers) and once with it (which of them
are present). Each id is opened with `CM_Locate_DevNodeW(…, CM_LOCATE_DEVNODE_PHANTOM)` so absent devices can be
read, and read with `CM_Get_DevNode_PropertyW`.

**`USB` is not read.** An HID device's own hardware id already names its vendor and product
(`HID\VID_xxxx&PID_xxxx…`), which is all a mouse or keyboard row needs. The `USB` enumerator would add storage,
phones, cameras and hubs, and a device's name there can carry its owner's name. This drops the "USB-serial chip"
row the plan sketched (R-B2); the plan already judged it of almost no use against a two-PC cheat.

Not read: `STORAGE`, `SCSI`, `SWD`, `BTHENUM`, `DISPLAY` or any other enumerator; `FriendlyName`;
`BusReportedDeviceDesc`; `LocationPaths`; driver files; a device's configuration space or registers (that would need
a driver of our own, which this project does not have).

### 3. A model, never an instance

A device instance id has three parts, `<enumerator>\<device id>\<instance>`. The third part of a USB-backed device
is often its **serial number**; of a PCI device it is a location on the board. The host keeps only the first entry of
`DEVPKEY_Device_HardwareIds`, cut to the fields that name a model:

- PCI: `VEN_`, `DEV_`, `SUBSYS_`, `REV_`.
- HID: `VID_`, `PID_`, `REV_` (and `MI_`/`COL` when present, which name an interface of the same model).

The instance part never leaves `rongroi-host-windows`. It is used inside the host only to open the device node,
the way ADR 0047 keeps a journal's identifier inside the host.

### 4. Two time properties without their own documentation page

`DEVPKEY_Device_FirstInstallDate` has a Microsoft Learn page. `DEVPKEY_Device_LastArrivalDate` and
`DEVPKEY_Device_LastRemovalDate` are declared in the `windows` 0.62.2 bindings, which are generated from the
Windows SDK's metadata, and every value measured came back as `DEVPROP_TYPE_FILETIME` — but neither has a page.
This is not a layout the project would guess (ADR 0038, 0046): the key and its type are declared, and only the
prose is missing.

Proposed: read them, and every place that shows one says **what was measured** rather than what the name suggests —
"Windows recorded this time under *last arrival*; on a measured PC it is re-written at each start" and
"Windows recorded this time under *last removal*; on a measured PC it was not written at shutdown". Measurement 6 is
the open half: until a test card shows what a card taken out while the PC is off leaves behind, no rule may say a
card was removed.

### 5. One Windows feature set, recorded where it is used

`rongroi-host-windows` gains `Win32_Devices_DeviceAndDriverInstallation` (the `CM_*` functions) and
`Win32_Devices_Properties` (`CM_Get_DevNode_PropertyW` is gated on it, and the `DEVPKEY_Device_*` constants live
there; `DEVPROPKEY` itself is in `Win32_Foundation`, already listed). Both names were read from the `windows`
0.62.2 manifest and sources, and go into the `Cargo.toml` comment as ADR 0011 and 0035 did.

`unsafe` stays in one new module, `device.rs`. Every `CONFIGRET` other than `CR_SUCCESS` becomes a
`SourceError`; a property with no value (`CR_NO_SUCH_VALUE`) is `None`, not an error. One device that fails to
read keeps its bus and `present` and is still returned — one device is never a reason to fail the list.

### 6. The inventory, not only what a rule needs

`crates/rongroi-collectors/AGENTS.md` says "collect only what a rule needs". A device row is useful to a person
mainly beside the others: what else is in the PC, which device left, which is the only one of its kind. Proposed: the
collectors emit every PCI and HID device as an observation, and the report keeps all of them. The collectors'
AGENTS.md gets a second named exception, as it has for `powershell_text`.

What a screen shows follows ADR 0014, with one consequence spelled out. Self mode lists every device. SS mode shows
in full every device row a rule matched — a device with no driver, a device first set up recently, a device that is
no longer present — and only a count of the rest. A person watching a screenshare therefore sees the rows that
need a question, and the rest of the inventory is not shown to the audience of a stream. The report file holds the
whole inventory either way, because a comparison with an earlier report of the same PC (which device is new, which
left) needs it; whoever receives that file is the one who must say why they keep it.

### 7. What it reveals

- The set of first-install times of 40 PCI devices is close to unique to one Windows installation. Two reports from
  the same PC can be linked through it, as ADR 0050 §4 says of listing times. This tool sends nothing; a server that
  receives uploaded reports can make that link, and PRIVACY.md and the consent text must say so before the first
  collector ships.
- Hardware ids name models, which can identify unusual hardware. No serial, location, owner name or friendly name.

### 8. The report

Additive: device rows are observations with fields, as every collector's are, and `REPORT_SCHEMA_VERSION` stays 1.
The collector ADRs confirm this against the code before they merge.

## What this does not do

- It does not detect a DMA card whose firmware presents it as an ordinary device, and nothing written from it may
  claim to.
- It does not read memory, a device's registers, the network, other PCs on the network, or anything over USB.
- It does not read `setupapi.dev.log` or the Kernel-PnP log. Measurements 8 and 9 show both mostly repeat what
  `FirstInstallDate` holds (a device's first setup), with less history for this purpose (9 and 63 days) and more
  unrelated text (file paths). The plan's ADR for the SetupAPI log should wait until a test card shows it adds
  something.

## Alternatives weighed

- **WMI `Win32_PnPEntity`.** The same devices through a far larger surface, rejected for the reason ADR 0011 gave.
- **SetupAPI `SetupDiGetClassDevsW` / `SetupDiGetDevicePropertyW`.** Same properties through a wider API; CfgMgr32 is
  the smaller documented layer and needs no device-information set kept open.
- **The registry under `HKLM\SYSTEM\CurrentControlSet\Enum`.** Holds the ids, but reading the time properties there
  means reading Windows' own property-store layout, which ADR 0038 rules out.
- **Only the devices a rule matches.** Smaller, but a device that left the PC cannot be shown beside what stayed,
  and the server-side comparison the plan relies on has nothing to compare (section 6).

## What is unverified

- Measurement 6: what a PCI card taken out while the PC is off leaves behind (`present`, `last_arrival`,
  `last_removal`). The source is useful without it (which devices exist, which have no driver, when each was first
  set up), but the "left before the check" row depends on it.
- Fast Startup: whether Windows re-writes `LastArrivalDate` when it resumes from a default "Shut down"
  (`BootTimeSource` already says the kernel does not restart then). A card can only be taken out with the power off,
  so the "a start after the player left the game" reading of the plan needs this measured too.
- The Thunderbolt / USB4 enumerator name and class code (no such controller on the measured PC).
- One PC only. The plan asks for three for the "no driver" baseline (measurement 7).
- Whether `CM_Get_DevNode_PropertyW` returns `ProblemCode` for an absent device (not needed: it is read for
  present devices only).

## Decisions for the owner

Decided on 2026-10-15: all five as recommended. The owner also chose to measure question 6 of "Measured before code"
and the Fast Startup case in a virtual machine before any test card is bought.

| # | Question | Recommended |
|---|---|---|
| 1 | Read `LastArrivalDate` / `LastRemovalDate`, which have no documentation page (section 4)? | **Yes**, labelled with what was measured, and no rule says "removed" until measurement 6 exists |
| 2 | Read `HID` only and not `USB` (section 2)? | **Yes**. Drops the USB-serial row |
| 3 | Emit the whole PCI + HID inventory: the report file keeps all of it, SS mode shows rule-matched device rows in full and counts the rest (section 6)? | **Yes**, and amend the collectors' AGENTS.md |
| 4 | Leave `LocationPaths`, `BusReportedDeviceDesc` and friendly names unread (section 2)? | **Yes**. A later rule that needs one asks for it in its own ADR |
| 5 | Park the SetupAPI-log ADR until a test card shows it adds something ("What this does not do")? | **Yes** |

## Consequences

- One trait, one host module, two `windows` features; no collector yet, so no rule, report or UI change.
- `FixtureHost` gains a device list; the three `baseline-*` hosts get synthetic devices shaped like measurement 7
  (host bridges without a service are ordinary), so `check-baseline` can confront the later rules. No id from a real
  PC goes into a fixture.
- PRIVACY.md and the consent question name devices before the first collector reads them.
