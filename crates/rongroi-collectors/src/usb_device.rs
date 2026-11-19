// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! The USB devices Windows remembers, present or not (ADR 0096 section 2).
//!
//! One observation per device the `USB` enumerator lists: its model id — `USB\VID_…&PID_…` with `REV_`, `MI_`
//! and root hubs, never the instance part, which for some devices is a serial number — its vendor and product
//! numbers, the driver service bound to it, whether it is present, the USB class, subclass and protocol from
//! compatible ids, and the three times Windows stores beside it. Full tier (ADR 0096).
//!
//! As in `pci_device` and `hid_device`, a property the host could not read for one device is a gap on that
//! field for the run. An unreadable `CompatibleIds` is a `read_failed` gap on `usb_class`, `usb_protocol`
//! and `usb_subclass`.

use std::collections::BTreeMap;

use rongroi_core::model::{CollectorRun, Observation, ScanTier, UnmeasuredReason};
use rongroi_host::{DeviceBus, DeviceProperty, DeviceRecord, Host, Platform, SourceError};

use crate::{Collector, Field};

const ID: &str = "usb_device";

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
const FIELDS: [Field; 11] = [
    Field::timestamp("first_install_at"),
    Field::timestamp("last_arrival_at"),
    Field::timestamp("last_removal_at"),
    Field::text("name"),
    Field::boolean("present"),
    Field::text("product_id"),
    Field::text("service"),
    Field::text("usb_class"),
    Field::text("usb_protocol"),
    Field::text("usb_subclass"),
    Field::text("vendor_id"),
];

/// The `usb_device` collector.
#[derive(Debug, Default, Clone, Copy)]
pub struct UsbDevice;

impl Collector for UsbDevice {
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
        let devices = match host.devices(DeviceBus::Usb) {
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
        DeviceProperty::CompatibleIds => &["usb_class", "usb_protocol", "usb_subclass"],
        DeviceProperty::ProblemCode
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
    let rest = device
        .model_id
        .split_once('\\')
        .map(|(_, r)| r)
        .unwrap_or("");
    if !rest.is_empty() {
        text("name", &device.model_id);
        for (name, prefix) in [("vendor_id", "VID_"), ("product_id", "PID_")] {
            if let Some(value) = model_field(&device.model_id, prefix) {
                text(name, value);
            }
        }
    }
    if let Some(service) = device.service.as_deref().filter(|s| !s.is_empty()) {
        text("service", service);
    }
    if let Some(ref class) = device.usb_class {
        text("usb_class", class);
    }
    if let Some(ref protocol) = device.usb_protocol {
        text("usb_protocol", protocol);
    }
    if let Some(ref subclass) = device.usb_subclass {
        text("usb_subclass", subclass);
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
    fn usb_device_carries_its_numbers_driver_usb_classes_and_times() {
        let run = UsbDevice.collect(&host(
            r"platform: windows
devices:
  - id: 'USB\VID_046D&PID_C52B&REV_2401&MI_00\7&111e2646&0&0000'
    present: true
    service: usbccgp
    compatible_ids: ['USB\Class_03&SubClass_01&Prot_01']
    first_install: '2026-10-15T11:32:36Z'
    last_arrival: '2026-10-15T11:32:36Z'
",
        ));
        let (observations, gaps) = measured(&run);
        assert!(gaps.is_empty(), "{gaps:?}");
        assert_eq!(observations.len(), 1);
        let fields = &observations[0].fields;
        let text = |name: &str| fields.get(name).and_then(serde_json::Value::as_str);
        assert_eq!(text("name"), Some(r"USB\VID_046D&PID_C52B&REV_2401&MI_00"));
        assert_eq!(text("vendor_id"), Some("046D"));
        assert_eq!(text("product_id"), Some("C52B"));
        assert_eq!(text("service"), Some("usbccgp"));
        assert_eq!(text("usb_class"), Some("03"));
        assert_eq!(text("usb_subclass"), Some("01"));
        assert_eq!(text("usb_protocol"), Some("01"));
        assert_eq!(fields.get("present"), Some(&serde_json::Value::from(true)));
        assert_eq!(text("first_install_at"), Some("2026-10-15T11:32:36Z"));
        assert_eq!(text("last_arrival_at"), Some("2026-10-15T11:32:36Z"));
        assert!(!fields.contains_key("last_removal_at"));
    }

    #[test]
    fn root_hub_has_no_vendor_or_product_id() {
        let run = UsbDevice.collect(&host(
            r"platform: windows
devices:
  - id: 'USB\ROOT_HUB30\4&1f2e3d4c&0'
    present: true
    service: USBHUB3
",
        ));
        let (observations, gaps) = measured(&run);
        assert!(gaps.is_empty(), "{gaps:?}");
        assert_eq!(observations.len(), 1);
        let fields = &observations[0].fields;
        let text = |name: &str| fields.get(name).and_then(serde_json::Value::as_str);
        assert_eq!(text("name"), Some(r"USB\ROOT_HUB30"));
        assert_eq!(text("vendor_id"), None);
        assert_eq!(text("product_id"), None);
        assert_eq!(text("service"), Some("USBHUB3"));
        assert_eq!(fields.get("present"), Some(&serde_json::Value::from(true)));
    }

    #[test]
    fn empty_rest_after_usb_omits_name_and_ids() {
        let run = UsbDevice.collect(&host(
            r"platform: windows
devices:
  - id: 'USB\UNKNOWN_DEVICE\1&2'
    present: false
",
        ));
        let (observations, gaps) = measured(&run);
        assert!(gaps.is_empty(), "{gaps:?}");
        assert_eq!(observations.len(), 1);
        let fields = &observations[0].fields;
        assert!(!fields.contains_key("name"));
        assert!(!fields.contains_key("vendor_id"));
        assert!(!fields.contains_key("product_id"));
        assert_eq!(fields.get("present"), Some(&serde_json::Value::from(false)));
    }

    #[test]
    fn unreadable_compatible_ids_is_a_gap_on_usb_classes() {
        let run = UsbDevice.collect(&host(
            r"platform: windows
devices:
  - id: 'USB\VID_046D&PID_C52B\1&2'
    present: true
    unreadable: [compatible_ids]
",
        ));
        let (_, gaps) = measured(&run);
        assert_eq!(gaps.get("usb_class"), Some(&UnmeasuredReason::ReadFailed));
        assert_eq!(
            gaps.get("usb_protocol"),
            Some(&UnmeasuredReason::ReadFailed)
        );
        assert_eq!(
            gaps.get("usb_subclass"),
            Some(&UnmeasuredReason::ReadFailed)
        );
    }

    #[test]
    fn a_usb_device_with_no_class_compatible_id_has_no_usb_class_subclass_or_protocol() {
        let run = UsbDevice.collect(&host(
            r"platform: windows
devices:
  - id: 'USB\VID_046D&PID_C52B\1&2'
    present: true
",
        ));
        let (observations, gaps) = measured(&run);
        assert!(gaps.is_empty(), "{gaps:?}");
        assert_eq!(observations.len(), 1);
        let fields = &observations[0].fields;
        assert!(!fields.contains_key("usb_class"));
        assert!(!fields.contains_key("usb_subclass"));
        assert!(!fields.contains_key("usb_protocol"));
    }

    #[test]
    fn a_list_that_cannot_be_read_is_unmeasured_and_non_windows_is_not_windows() {
        assert_eq!(
            UsbDevice.collect(&host("platform: windows\n")),
            unmeasured(UnmeasuredReason::ReadFailed)
        );
        assert_eq!(
            UsbDevice.collect(&NonWindowsHost),
            unmeasured(UnmeasuredReason::NotWindows)
        );
        assert_eq!(
            reason_for(&SourceError::AccessDenied),
            UnmeasuredReason::AccessDenied
        );
    }

    #[test]
    fn tier_is_full() {
        assert_eq!(UsbDevice.tier(), ScanTier::Full);
    }
}
