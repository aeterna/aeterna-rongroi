// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! The HID devices Windows remembers, present or not (ADR 0069, ADR 0072).
//!
//! One observation per device the `HID` enumerator lists: its model id — `HID\VID_…&PID_…` with `REV_`, `MI_` and
//! `COL` when there, never the instance part, which for some devices is a serial number — its vendor and product
//! numbers, the driver service bound to it (`mouhid` for a mouse, `kbdhid` for a keyboard), whether it is present,
//! and the three times Windows stores beside it. No administrator rights are needed (ADR 0069, measured).
//!
//! It exists for the times (ADR 0072): when a mouse or keyboard left and another arrived. Nothing here says what a
//! device is beyond its numbers and its driver, and a box between a mouse and the PC looks like a mouse.
//!
//! As in `pci_device`, a property the host could not read for one device is a gap on that field for the run.

use std::collections::BTreeMap;

use rongroi_core::model::{CollectorRun, Observation, UnmeasuredReason};
use rongroi_host::{DeviceBus, DeviceProperty, DeviceRecord, Host, Platform, SourceError};

use crate::{Collector, Field};

const ID: &str = "hid_device";

/// Every reason this collector gives for not having looked (`Collector::unmeasured_reasons`).
///
/// No `not_admin`: ADR 0069 measured the list and every property read the same without
/// administrator rights. A refused list is `access_denied`; any other failure, and a property that
/// could not be read, is `read_failed`.
const REASONS: [UnmeasuredReason; 3] = [
    UnmeasuredReason::NotWindows,
    UnmeasuredReason::AccessDenied,
    UnmeasuredReason::ReadFailed,
];

/// Every field this collector can emit, sorted by name.
const FIELDS: [Field; 8] = [
    Field::timestamp("first_install_at"),
    Field::timestamp("last_arrival_at"),
    Field::timestamp("last_removal_at"),
    Field::text("name"),
    Field::boolean("present"),
    Field::text("product_id"),
    Field::text("service"),
    Field::text("vendor_id"),
];

/// The `hid_device` collector.
#[derive(Debug, Default, Clone, Copy)]
pub struct HidDevice;

impl Collector for HidDevice {
    fn id(&self) -> &'static str {
        ID
    }

    fn fields(&self) -> &'static [Field] {
        &FIELDS
    }

    fn unmeasured_reasons(&self) -> &'static [UnmeasuredReason] {
        &REASONS
    }

    fn collect(&self, host: &dyn Host) -> CollectorRun {
        if host.platform() != Platform::Windows {
            return unmeasured(UnmeasuredReason::NotWindows);
        }
        let devices = match host.devices(DeviceBus::Hid) {
            Ok(devices) => devices,
            // The list is the whole reading: an empty `Measured` run would say this PC has no input
            // device, which is not something a failed read can claim.
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

/// How a failed list is reported, as `process` reports one.
fn reason_for(error: &SourceError) -> UnmeasuredReason {
    match error {
        SourceError::AccessDenied => UnmeasuredReason::AccessDenied,
        SourceError::Unsupported(_) | SourceError::Failed(_) | SourceError::TooLarge { .. } => {
            UnmeasuredReason::ReadFailed
        }
    }
}

/// The fields a property that could not be read leaves unknown. The class code and problem code are not
/// reported for HID devices (ADR 0072), so their properties leave nothing unknown.
fn fields_of(property: DeviceProperty) -> &'static [&'static str] {
    match property {
        DeviceProperty::CompatibleIds | DeviceProperty::ProblemCode => &[],
        DeviceProperty::Service => &["service"],
        DeviceProperty::FirstInstall => &["first_install_at"],
        DeviceProperty::LastArrival => &["last_arrival_at"],
        DeviceProperty::LastRemoval => &["last_removal_at"],
    }
}

/// The hex digits after `prefix` in a model id's fields, when they are there.
fn model_field<'a>(model_id: &'a str, prefix: &str) -> Option<&'a str> {
    let (_, device) = model_id.split_once('\\')?;
    device
        .split('&')
        .find_map(|field| field.strip_prefix(prefix))
        .filter(|value| !value.is_empty())
}

fn observation(device: &DeviceRecord) -> Observation {
    let mut fields = BTreeMap::new();
    let mut text = |name: &str, value: &str| {
        fields.insert(name.to_owned(), serde_json::Value::from(value));
    };
    text("name", &device.model_id);
    for (name, prefix) in [("vendor_id", "VID_"), ("product_id", "PID_")] {
        if let Some(value) = model_field(&device.model_id, prefix) {
            text(name, value);
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

    /// QEMU's USB mouse, as the lab virtual machine listed it (ADR 0069).
    #[test]
    fn a_mouse_carries_its_numbers_driver_and_times_and_no_pci_fields() {
        let run = HidDevice.collect(&host(
            r"platform: windows
devices:
  - id: 'HID\VID_0627&PID_0001\7&111e2646&0&0000'
    present: true
    service: mouhid
    problem_code: 0
    first_install: '2026-10-15T11:32:36Z'
    last_arrival: '2026-10-15T11:32:36Z'
  - id: 'PCI\VEN_1234&DEV_11E8\3&0'
    present: true
",
        ));
        let (observations, gaps) = measured(&run);
        assert!(gaps.is_empty(), "{gaps:?}");
        assert_eq!(observations.len(), 1, "PCI devices are another collector's");
        let fields = &observations[0].fields;
        let text = |name: &str| fields.get(name).and_then(serde_json::Value::as_str);
        assert_eq!(text("name"), Some(r"HID\VID_0627&PID_0001"));
        assert_eq!(text("vendor_id"), Some("0627"));
        assert_eq!(text("product_id"), Some("0001"));
        assert_eq!(text("service"), Some("mouhid"));
        assert_eq!(fields.get("present"), Some(&serde_json::Value::from(true)));
        assert_eq!(text("first_install_at"), Some("2026-10-15T11:32:36Z"));
        assert!(!fields.contains_key("problem_code"));
        assert!(!fields.contains_key("class_code"));
    }

    #[test]
    fn a_mouse_removed_while_running_keeps_its_removal_time() {
        let run = HidDevice.collect(&host(
            r"platform: windows
devices:
  - id: 'HID\VID_0627&PID_0001\7&2&0&0000'
    present: false
    last_arrival: '2026-10-15T11:37:35Z'
    last_removal: '2026-10-15T11:41:02Z'
",
        ));
        let (observations, _) = measured(&run);
        let fields = &observations[0].fields;
        assert_eq!(fields.get("present"), Some(&serde_json::Value::from(false)));
        assert_eq!(
            fields.get("last_removal_at"),
            Some(&serde_json::Value::from("2026-10-15T11:41:02Z"))
        );
    }

    /// An unread service or time is a gap on its field; an unread problem code leaves nothing unknown here.
    #[test]
    fn only_properties_this_collector_reports_become_gaps() {
        let run = HidDevice.collect(&host(
            r"platform: windows
devices:
  - id: 'HID\VID_0627&PID_0001\7&3&0&0000'
    present: true
    unreadable: [service, problem_code, last_removal]
",
        ));
        let (_, gaps) = measured(&run);
        assert_eq!(
            gaps.keys().map(String::as_str).collect::<Vec<_>>(),
            ["last_removal_at", "service"]
        );
    }

    #[test]
    fn a_list_that_cannot_be_read_is_unmeasured_and_non_windows_is_not_windows() {
        assert_eq!(
            HidDevice.collect(&host("platform: windows\n")),
            unmeasured(UnmeasuredReason::ReadFailed)
        );
        assert_eq!(
            HidDevice.collect(&NonWindowsHost),
            unmeasured(UnmeasuredReason::NotWindows)
        );
    }
}
