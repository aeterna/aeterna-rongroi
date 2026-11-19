// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! The Bluetooth devices Windows remembers, present or not (ADR 0096 section 2).
//!
//! One observation per device or service the `BTHENUM` enumerator lists: its model id —
//! `BTHENUM\{service}_VID&…_PID&…` with the service GUID, never an address or local manufacturing data
//! (ADR 0096) — whether it is present, the driver service bound to it, and the three times Windows stores
//! beside it. Full tier (ADR 0096).
//!
//! As in `hid_device`, a property the host could not read for one device is a gap on that field for the run.

use std::collections::BTreeMap;

use rongroi_core::model::{CollectorRun, Observation, ScanTier, UnmeasuredReason};
use rongroi_host::{DeviceBus, DeviceProperty, DeviceRecord, Host, Platform, SourceError};

use crate::{Collector, Field};

const ID: &str = "bluetooth_device";

/// Every reason this collector gives for not having looked (`Collector::unmeasured_reasons`).
///
/// No `not_admin`: ADR 0069 and ADR 0096 measured the list and every property read the same without
/// administrator rights. A refused list is `access_denied`; any other failure, and a property that
/// could not be read, is `read_failed`.
const REASONS: [UnmeasuredReason; 3] = [
    UnmeasuredReason::NotWindows,
    UnmeasuredReason::AccessDenied,
    UnmeasuredReason::ReadFailed,
];

/// Every field this collector can emit, sorted by name.
const FIELDS: [Field; 9] = [
    Field::text("bluetooth_service"),
    Field::timestamp("first_install_at"),
    Field::timestamp("last_arrival_at"),
    Field::timestamp("last_removal_at"),
    Field::text("name"),
    Field::boolean("present"),
    Field::text("product_id"),
    Field::text("service"),
    Field::text("vendor_id"),
];

/// The `bluetooth_device` collector.
#[derive(Debug, Default, Clone, Copy)]
pub struct BluetoothDevice;

impl Collector for BluetoothDevice {
    fn id(&self) -> &'static str {
        ID
    }

    fn fields(&self) -> &'static [Field] {
        &FIELDS
    }

    fn unmeasured_reasons(&self) -> &'static [UnmeasuredReason] {
        &REASONS
    }

    fn tier(&self) -> ScanTier {
        ScanTier::Full
    }

    fn collect(&self, host: &dyn Host) -> CollectorRun {
        if host.platform() != Platform::Windows {
            return unmeasured(UnmeasuredReason::NotWindows);
        }
        let devices = match host.devices(DeviceBus::Bluetooth) {
            Ok(devices) => devices,
            Err(error) => return unmeasured(reason_for(&error)),
        };
        let mut gaps = BTreeMap::new();
        for device in &devices {
            for property in &device.unreadable {
                for field in fields_of(*property) {
                    gaps.insert((*field).to_owned(), UnmeasuredReason::ReadFailed);
                }
            }
        }
        CollectorRun::Measured {
            collector: ID.to_owned(),
            observations: devices.iter().map(observation).collect(),
            gaps,
            discriminator_gaps: Vec::new(),
        }
    }
}

fn unmeasured(reason: UnmeasuredReason) -> CollectorRun {
    CollectorRun::Unmeasured {
        collector: ID.to_owned(),
        reason,
    }
}

fn reason_for(error: &SourceError) -> UnmeasuredReason {
    match error {
        SourceError::AccessDenied => UnmeasuredReason::AccessDenied,
        SourceError::NotLocal(_) => UnmeasuredReason::NotAttempted,
        SourceError::Unsupported(_) | SourceError::Failed(_) | SourceError::TooLarge { .. } => {
            UnmeasuredReason::ReadFailed
        }
    }
}

/// The fields a property that could not be read leaves unknown.
fn fields_of(property: DeviceProperty) -> &'static [&'static str] {
    match property {
        DeviceProperty::CompatibleIds
        | DeviceProperty::ProblemCode
        | DeviceProperty::BusClass
        | DeviceProperty::BusSubclass
        | DeviceProperty::LinkSpeed
        | DeviceProperty::LinkWidth
        | DeviceProperty::MaxLinkSpeed
        | DeviceProperty::MaxLinkWidth
        | DeviceProperty::ChildCount => &[],
        DeviceProperty::Service => &["service"],
        DeviceProperty::FirstInstall => &["first_install_at"],
        DeviceProperty::LastArrival => &["last_arrival_at"],
        DeviceProperty::LastRemoval => &["last_removal_at"],
    }
}

fn is_braced_guid(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.len() != 38 || bytes[0] != b'{' || bytes[37] != b'}' {
        return false;
    }
    if bytes[9] != b'-' || bytes[14] != b'-' || bytes[19] != b'-' || bytes[24] != b'-' {
        return false;
    }
    let hex_ranges = [1..9, 10..14, 15..19, 20..24, 25..37];
    hex_ranges
        .iter()
        .all(|range| bytes[range.clone()].iter().all(u8::is_ascii_hexdigit))
}

fn observation(device: &DeviceRecord) -> Observation {
    let mut fields = BTreeMap::new();
    let mut text = |name: &str, value: &str| {
        fields.insert(name.to_owned(), serde_json::Value::from(value));
    };
    let rest = device
        .model_id
        .split_once('\\')
        .map(|(_, r)| r)
        .unwrap_or("");
    if !rest.is_empty() {
        text("name", &device.model_id);
        let mut tokens = rest.split('_');
        if let Some(first) = tokens.next().filter(|s| is_braced_guid(s)) {
            text("bluetooth_service", first);
        }
        for token in tokens {
            if let Some(vid) = token.strip_prefix("VID&") {
                if vid.len() == 8 && vid.bytes().all(|b| b.is_ascii_hexdigit()) {
                    text("vendor_id", vid);
                }
            } else if let Some(pid) = token.strip_prefix("PID&") {
                if pid.len() == 4 && pid.bytes().all(|b| b.is_ascii_hexdigit()) {
                    text("product_id", pid);
                }
            }
        }
    }
    if let Some(service) = device.service.as_deref().filter(|s| !s.is_empty()) {
        text("service", service);
    }
    fields.insert(
        "present".to_owned(),
        serde_json::Value::from(device.present),
    );
    for (name, time) in [
        ("first_install_at", device.first_install),
        ("last_arrival_at", device.last_arrival),
        ("last_removal_at", device.last_removal),
    ] {
        if let Some(time) = time {
            fields.insert(name.to_owned(), serde_json::Value::from(time.to_string()));
        }
    }
    Observation {
        collector: ID.to_owned(),
        fields,
    }
}

#[cfg(test)]
mod tests {
    use rongroi_host::{FixtureHost, NonWindowsHost};

    use super::*;

    fn host(yaml: &str) -> FixtureHost {
        FixtureHost::from_yaml_str(yaml, "inline").unwrap()
    }

    fn measured(run: &CollectorRun) -> (&[Observation], &BTreeMap<String, UnmeasuredReason>) {
        match run {
            CollectorRun::Measured {
                observations, gaps, ..
            } => (observations, gaps),
            CollectorRun::Unmeasured { .. } => panic!("expected a measured run, got {run:?}"),
        }
    }

    #[test]
    fn bluetooth_device_carries_its_service_numbers_driver_and_times() {
        let run = BluetoothDevice.collect(&host(
            r"platform: windows
devices:
  - id: 'BTHENUM\{0000110e-0000-1000-8000-00805f9b34fb}_VID&000205ac_PID&0257\7&111e2646&0&0000'
    present: true
    service: BthAvrcpTarget
    first_install: '2026-10-15T11:32:36Z'
    last_arrival: '2026-10-15T11:32:36Z'
",
        ));
        let (observations, gaps) = measured(&run);
        assert!(gaps.is_empty(), "{gaps:?}");
        assert_eq!(observations.len(), 1);
        let fields = &observations[0].fields;
        let text = |name: &str| fields.get(name).and_then(serde_json::Value::as_str);
        assert_eq!(
            text("name"),
            Some(r"BTHENUM\{0000110E-0000-1000-8000-00805F9B34FB}_VID&000205AC_PID&0257")
        );
        assert_eq!(
            text("bluetooth_service"),
            Some("{0000110E-0000-1000-8000-00805F9B34FB}")
        );
        assert_eq!(text("vendor_id"), Some("000205AC"));
        assert_eq!(text("product_id"), Some("0257"));
        assert_eq!(text("service"), Some("BthAvrcpTarget"));
        assert_eq!(fields.get("present"), Some(&serde_json::Value::from(true)));
        assert_eq!(text("first_install_at"), Some("2026-10-15T11:32:36Z"));
        assert_eq!(text("last_arrival_at"), Some("2026-10-15T11:32:36Z"));
    }

    #[test]
    fn bluetooth_address_shape_drops_everything_after_enumerator() {
        let run = BluetoothDevice.collect(&host(
            r"platform: windows
devices:
  - id: 'BTHENUM\Dev_001122334455\1&2'
    present: false
",
        ));
        let (observations, gaps) = measured(&run);
        assert!(gaps.is_empty(), "{gaps:?}");
        assert_eq!(observations.len(), 1);
        let fields = &observations[0].fields;
        assert!(!fields.contains_key("name"));
        assert!(!fields.contains_key("bluetooth_service"));
        assert!(!fields.contains_key("vendor_id"));
        assert!(!fields.contains_key("product_id"));
        assert_eq!(fields.get("present"), Some(&serde_json::Value::from(false)));
    }

    #[test]
    fn unreadable_properties_produce_gaps() {
        let run = BluetoothDevice.collect(&host(
            r"platform: windows
devices:
  - id: 'BTHENUM\{0000110e-0000-1000-8000-00805f9b34fb}_VID&000205ac_PID&0257\7&111e2646&0&0000'
    present: true
    unreadable: [service, last_arrival]
",
        ));
        let (_, gaps) = measured(&run);
        assert_eq!(gaps.get("service"), Some(&UnmeasuredReason::ReadFailed));
        assert_eq!(
            gaps.get("last_arrival_at"),
            Some(&UnmeasuredReason::ReadFailed)
        );
    }

    #[test]
    fn a_list_that_cannot_be_read_is_unmeasured_and_non_windows_is_not_windows() {
        assert_eq!(
            BluetoothDevice.collect(&host("platform: windows\n")),
            unmeasured(UnmeasuredReason::ReadFailed)
        );
        assert_eq!(
            BluetoothDevice.collect(&NonWindowsHost),
            unmeasured(UnmeasuredReason::NotWindows)
        );
        assert_eq!(
            reason_for(&SourceError::AccessDenied),
            UnmeasuredReason::AccessDenied
        );
    }

    #[test]
    fn tier_is_full() {
        assert_eq!(BluetoothDevice.tier(), ScanTier::Full);
    }
}
