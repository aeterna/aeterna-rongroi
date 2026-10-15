// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! The PCI devices Windows remembers, present or not (ADR 0069, ADR 0070).
//!
//! One observation per device the `PCI` enumerator lists: its model id — never its instance, which
//! for some devices is a serial number — its vendor, device and subsystem ids and class code, the
//! driver service bound to it, its problem code when it is present, whether it is present, and the
//! three times Windows stores beside it. No administrator rights are needed (ADR 0069, measured).
//!
//! Every device is emitted, as `process` emits every process (ADR 0069 section 6). A property the host
//! could not read for one device is a gap on that field for the run, so a rule that needs it is
//! `unmeasured` rather than `not_found`. A property Windows holds no value for is left out of that one
//! observation and is not a gap.
//!
//! What the times mean was measured, on one PC and in a virtual machine (ADR 0069): `last_arrival_at` is
//! re-written at each start of Windows, but not at a resume from a Fast Startup shutdown;
//! `last_removal_at` is written when a device leaves a running Windows or during a Fast Startup
//! shutdown, and not at a full shutdown. Nothing here says how or why a device left.

use std::collections::BTreeMap;

use rongroi_core::model::{CollectorRun, Observation, UnmeasuredReason};
use rongroi_host::{DeviceBus, DeviceProperty, DeviceRecord, Host, Platform, SourceError};

use crate::{Collector, Field};

const ID: &str = "pci_device";

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
const FIELDS: [Field; 11] = [
    Field::text("class_code"),
    Field::text("device_id"),
    Field::timestamp("first_install_at"),
    Field::timestamp("last_arrival_at"),
    Field::timestamp("last_removal_at"),
    Field::text("name"),
    Field::boolean("present"),
    Field::number("problem_code"),
    Field::text("service"),
    Field::text("subsystem_id"),
    Field::text("vendor_id"),
];

/// The `pci_device` collector.
#[derive(Debug, Default, Clone, Copy)]
pub struct PciDevice;

impl Collector for PciDevice {
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
        let devices = match host.devices(DeviceBus::Pci) {
            Ok(devices) => devices,
            // The list is the whole reading: an empty `Measured` run would say this PC has no PCI
            // device, which no PC is.
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

/// The fields a property that could not be read leaves unknown.
fn fields_of(property: DeviceProperty) -> &'static [&'static str] {
    match property {
        DeviceProperty::CompatibleIds => &["class_code"],
        DeviceProperty::Service => &["service"],
        DeviceProperty::ProblemCode => &["problem_code"],
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
    for (name, prefix) in [
        ("vendor_id", "VEN_"),
        ("device_id", "DEV_"),
        ("subsystem_id", "SUBSYS_"),
    ] {
        if let Some(value) = model_field(&device.model_id, prefix) {
            text(name, value);
        }
    }
    if let Some(class_code) = &device.class_code {
        text("class_code", class_code);
    }
    if let Some(service) = device.service.as_deref().filter(|s| !s.is_empty()) {
        text("service", service);
    }
    fields.insert(
        "present".to_owned(),
        serde_json::Value::from(device.present),
    );
    if let Some(code) = device.problem_code {
        fields.insert("problem_code".to_owned(), serde_json::Value::from(code));
    }
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
    fn a_present_device_carries_its_ids_class_problem_code_and_times() {
        let run = PciDevice.collect(&host(
            r"platform: windows
devices:
  - id: 'PCI\VEN_1234&DEV_11E8&SUBSYS_11001AF4&REV_10\4&c580b9d&0&0020'
    present: true
    compatible_ids: ['PCI\CC_00FF00', 'PCI\CC_00FF']
    problem_code: 28
    first_install: '2026-10-15T11:32:36Z'
    last_arrival: '2026-10-15T11:32:36Z'
",
        ));
        let (observations, gaps) = measured(&run);
        assert!(gaps.is_empty(), "{gaps:?}");
        let fields = &observations[0].fields;
        let text = |name: &str| fields.get(name).and_then(serde_json::Value::as_str);
        assert_eq!(
            text("name"),
            Some(r"PCI\VEN_1234&DEV_11E8&SUBSYS_11001AF4&REV_10")
        );
        assert_eq!(text("vendor_id"), Some("1234"));
        assert_eq!(text("device_id"), Some("11E8"));
        assert_eq!(text("subsystem_id"), Some("11001AF4"));
        assert_eq!(text("class_code"), Some("00FF"));
        assert_eq!(text("service"), None);
        assert_eq!(fields.get("present"), Some(&serde_json::Value::from(true)));
        assert_eq!(
            fields.get("problem_code"),
            Some(&serde_json::Value::from(28))
        );
        assert_eq!(text("first_install_at"), Some("2026-10-15T11:32:36Z"));
        assert_eq!(text("last_removal_at"), None);
    }

    #[test]
    fn an_absent_device_has_no_problem_code_and_keeps_its_removal_time() {
        let run = PciDevice.collect(&host(
            r"platform: windows
devices:
  - id: 'PCI\VEN_1234&DEV_11E8&SUBSYS_11001AF4&REV_10\4&c580b9d&0&0020'
    present: false
    last_arrival: '2026-10-15T11:51:35Z'
    last_removal: '2026-10-15T11:53:25Z'
",
        ));
        let (observations, _) = measured(&run);
        let fields = &observations[0].fields;
        assert_eq!(fields.get("present"), Some(&serde_json::Value::from(false)));
        assert_eq!(fields.get("problem_code"), None);
        assert_eq!(
            fields.get("last_removal_at"),
            Some(&serde_json::Value::from("2026-10-15T11:53:25Z"))
        );
    }

    /// One device's unread property is a gap on that field for the run, so a rule that needs it is
    /// `unmeasured`; the device itself is still listed.
    #[test]
    fn an_unreadable_property_is_a_gap_on_its_field_and_the_device_is_kept() {
        let run = PciDevice.collect(&host(
            r"platform: windows
devices:
  - id: 'PCI\VEN_8086&DEV_1234\3&0'
    present: true
    unreadable: [problem_code, last_removal]
  - id: 'PCI\VEN_8086&DEV_5678\3&1'
    present: true
    problem_code: 0
",
        ));
        let (observations, gaps) = measured(&run);
        assert_eq!(observations.len(), 2);
        assert_eq!(
            gaps.keys().map(String::as_str).collect::<Vec<_>>(),
            ["last_removal_at", "problem_code"]
        );
        assert!(gaps.values().all(|r| *r == UnmeasuredReason::ReadFailed));
    }

    /// HID devices are another collector's (none yet): this one never lists them.
    #[test]
    fn hid_devices_are_not_listed() {
        let run = PciDevice.collect(&host(
            r"platform: windows
devices:
  - id: 'HID\VID_0627&PID_0001\6&43b7243&0&0000'
    present: true
",
        ));
        assert!(measured(&run).0.is_empty());
    }

    #[test]
    fn a_list_that_cannot_be_read_is_unmeasured_and_non_windows_is_not_windows() {
        assert_eq!(
            PciDevice.collect(&host("platform: windows\n")),
            unmeasured(UnmeasuredReason::ReadFailed)
        );
        assert_eq!(
            PciDevice.collect(&NonWindowsHost),
            unmeasured(UnmeasuredReason::NotWindows)
        );
        assert_eq!(
            reason_for(&SourceError::AccessDenied),
            UnmeasuredReason::AccessDenied
        );
    }

    #[test]
    fn model_fields_are_read_from_the_model_id_only() {
        assert_eq!(
            model_field(r"PCI\VEN_10DE&DEV_2684&SUBSYS_88D21043&REV_A1", "SUBSYS_"),
            Some("88D21043")
        );
        assert_eq!(model_field(r"PCI\VEN_10DE", "DEV_"), None);
        assert_eq!(model_field("PCI", "VEN_"), None);
    }
}
