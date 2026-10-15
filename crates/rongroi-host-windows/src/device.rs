// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! The devices Windows remembers, through `CfgMgr32` (ADR 0069).
//!
//! Two lists per enumerator: every device id (`CM_GETIDLIST_FILTER_ENUMERATOR`), and the present ones
//! (`… | CM_GETIDLIST_FILTER_PRESENT`). Each id is opened with `CM_LOCATE_DEVNODE_PHANTOM`, so a device
//! that is not present can be read too, and six properties are read with `CM_Get_DevNode_PropertyW`.
//! Nothing is installed, started, stopped or changed; no driver of a device is opened. ADR 0069 measured
//! every one of these reads giving the same answer without administrator rights.
//!
//! The instance part of an id never leaves this module: [`rongroi_host::device_model_id`] keeps the model.

/// The strings of a `REG_MULTI_SZ`-style buffer of UTF-16 units: strings ended by a NUL, the list
/// ended by an empty one. A buffer cut short still gives the strings it holds.
pub fn multi_sz(buffer: &[u16]) -> Vec<String> {
    buffer
        .split(|unit| *unit == 0)
        .take_while(|part| !part.is_empty())
        .map(String::from_utf16_lossy)
        .collect()
}

#[cfg(windows)]
mod live {
    use rongroi_host::{
        DeviceBus, DeviceProperty, DeviceRecord, SourceError, device_model_id, device_time,
        pci_class_code,
    };
    use windows::Win32::Devices::DeviceAndDriverInstallation::{
        CM_GETIDLIST_FILTER_ENUMERATOR, CM_GETIDLIST_FILTER_PRESENT, CM_Get_DevNode_PropertyW,
        CM_Get_Device_ID_List_SizeW, CM_Get_Device_ID_ListW, CM_LOCATE_DEVNODE_PHANTOM,
        CM_Locate_DevNodeW, CONFIGRET, CR_BUFFER_SMALL, CR_NO_SUCH_VALUE, CR_SUCCESS,
    };
    use windows::Win32::Devices::Properties::{
        DEVPKEY_Device_CompatibleIds, DEVPKEY_Device_FirstInstallDate,
        DEVPKEY_Device_LastArrivalDate, DEVPKEY_Device_LastRemovalDate, DEVPKEY_Device_ProblemCode,
        DEVPKEY_Device_Service, DEVPROP_TYPE_FILETIME, DEVPROP_TYPE_STRING,
        DEVPROP_TYPE_STRING_LIST, DEVPROP_TYPE_UINT32, DEVPROPTYPE,
    };
    use windows::Win32::Foundation::DEVPROPKEY;
    use windows::core::PCWSTR;

    /// Most UTF-16 units a device id list may take: far above the few hundred devices of a PC
    /// (235 ids, about 20 000 units, on the PC ADR 0069 measured), and a bound on what one answer can
    /// make this program allocate.
    const MAX_LIST_UNITS: u32 = 4 * 1024 * 1024;
    /// Most bytes one property may take. The six read here are a few hundred bytes at most.
    const MAX_PROPERTY_BYTES: u32 = 64 * 1024;

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn failed(call: &str, code: CONFIGRET) -> SourceError {
        SourceError::Failed(format!("{call} returned CONFIGRET {}", code.0))
    }

    /// Every device id `enumerator` lists, with `flags` added to `CM_GETIDLIST_FILTER_ENUMERATOR`.
    #[allow(unsafe_code)]
    fn device_ids(enumerator: &str, flags: u32) -> Result<Vec<String>, SourceError> {
        let filter = wide(enumerator);
        let flags = CM_GETIDLIST_FILTER_ENUMERATOR | flags;
        // The list can grow between asking its size and reading it; one retry with a fresh size.
        for _ in 0..2 {
            let mut units = 0u32;
            // SAFETY: `units` is a valid `u32` to write to, and `filter` is a NUL-ended UTF-16 string
            // that outlives the call. The call only reads Windows' device tree.
            let code = unsafe {
                CM_Get_Device_ID_List_SizeW(&raw mut units, PCWSTR(filter.as_ptr()), flags)
            };
            if code != CR_SUCCESS {
                return Err(failed("CM_Get_Device_ID_List_SizeW", code));
            }
            if units > MAX_LIST_UNITS {
                return Err(SourceError::Failed(format!(
                    "the device id list is {units} UTF-16 units, above this host's limit of {MAX_LIST_UNITS}"
                )));
            }
            let mut buffer = vec![0u16; units as usize];
            // SAFETY: `buffer` is as long as the size Windows stated and is written by this call
            // only; `filter` is as above.
            let code =
                unsafe { CM_Get_Device_ID_ListW(PCWSTR(filter.as_ptr()), &mut buffer, flags) };
            if code == CR_BUFFER_SMALL {
                continue;
            }
            if code != CR_SUCCESS {
                return Err(failed("CM_Get_Device_ID_ListW", code));
            }
            return Ok(super::multi_sz(&buffer));
        }
        Err(SourceError::Failed(
            "the device id list kept growing while it was read".to_owned(),
        ))
    }

    /// One property's raw bytes and type; `Ok(None)` when Windows holds no value for it.
    #[allow(unsafe_code)]
    fn property(devinst: u32, key: &DEVPROPKEY) -> Result<Option<(DEVPROPTYPE, Vec<u8>)>, ()> {
        let mut kind = DEVPROPTYPE(0);
        let mut size = 0u32;
        // SAFETY: a null buffer with a size of 0 asks for the size only; `key`, `kind` and `size`
        // are valid for the call. The call only reads.
        let code = unsafe {
            CM_Get_DevNode_PropertyW(devinst, key, &raw mut kind, None, &raw mut size, 0)
        };
        if code == CR_NO_SUCH_VALUE {
            return Ok(None);
        }
        if code != CR_BUFFER_SMALL || size > MAX_PROPERTY_BYTES {
            return Err(());
        }
        let mut buffer = vec![0u8; size as usize];
        // SAFETY: `buffer` holds `size` bytes, the size Windows stated for this property.
        let code = unsafe {
            CM_Get_DevNode_PropertyW(
                devinst,
                key,
                &raw mut kind,
                Some(buffer.as_mut_ptr()),
                &raw mut size,
                0,
            )
        };
        if code != CR_SUCCESS {
            return Err(());
        }
        buffer.truncate(size as usize);
        Ok(Some((kind, buffer)))
    }

    fn units(bytes: &[u8]) -> Vec<u16> {
        bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_le_bytes(*pair))
            .collect()
    }

    /// Reads one property of the kind `expected`, turning it with `convert`. A value of another type
    /// is unreadable rather than guessed at.
    fn read<T>(
        devinst: u32,
        key: &DEVPROPKEY,
        expected: DEVPROPTYPE,
        convert: impl FnOnce(&[u8]) -> Option<T>,
    ) -> Result<Option<T>, ()> {
        match property(devinst, key)? {
            None => Ok(None),
            Some((kind, bytes)) if kind == expected => convert(&bytes).map(Some).ok_or(()),
            Some(_) => Err(()),
        }
    }

    fn filetime(bytes: &[u8]) -> Option<u64> {
        let raw: [u8; 8] = bytes.get(..8)?.try_into().ok()?;
        Some(u64::from_le_bytes(raw))
    }

    #[allow(unsafe_code)]
    fn record(bus: DeviceBus, id: &str, present: bool) -> Option<DeviceRecord> {
        let model_id = device_model_id(bus, id)?;
        let mut record = DeviceRecord {
            bus,
            model_id,
            class_code: None,
            service: None,
            problem_code: None,
            present,
            first_install: None,
            last_arrival: None,
            last_removal: None,
            unreadable: Vec::new(),
        };
        let mut devinst = 0u32;
        let wide_id = wide(id);
        // SAFETY: `devinst` is a valid `u32` to write to and `wide_id` a NUL-ended UTF-16 string that
        // outlives the call. `PHANTOM` lets a device that is not present be located; nothing changes.
        let code = unsafe {
            CM_Locate_DevNodeW(
                &raw mut devinst,
                PCWSTR(wide_id.as_ptr()),
                CM_LOCATE_DEVNODE_PHANTOM,
            )
        };
        if code != CR_SUCCESS {
            record.unreadable = vec![
                DeviceProperty::CompatibleIds,
                DeviceProperty::Service,
                DeviceProperty::ProblemCode,
                DeviceProperty::FirstInstall,
                DeviceProperty::LastArrival,
                DeviceProperty::LastRemoval,
            ];
            return Some(record);
        }
        let mut missing = Vec::new();
        if bus == DeviceBus::Pci {
            match read(
                devinst,
                &DEVPKEY_Device_CompatibleIds,
                DEVPROP_TYPE_STRING_LIST,
                |b| Some(super::multi_sz(&units(b))),
            ) {
                Ok(ids) => record.class_code = ids.and_then(|ids| pci_class_code(&ids)),
                Err(()) => missing.push(DeviceProperty::CompatibleIds),
            }
        }
        match read(devinst, &DEVPKEY_Device_Service, DEVPROP_TYPE_STRING, |b| {
            super::multi_sz(&units(b)).into_iter().next()
        }) {
            Ok(service) => record.service = service,
            Err(()) => missing.push(DeviceProperty::Service),
        }
        if present {
            match read(
                devinst,
                &DEVPKEY_Device_ProblemCode,
                DEVPROP_TYPE_UINT32,
                |b| Some(u32::from_le_bytes(b.get(..4)?.try_into().ok()?)),
            ) {
                Ok(code) => record.problem_code = code,
                Err(()) => missing.push(DeviceProperty::ProblemCode),
            }
        }
        for (key, property) in [
            (
                &DEVPKEY_Device_FirstInstallDate,
                DeviceProperty::FirstInstall,
            ),
            (&DEVPKEY_Device_LastArrivalDate, DeviceProperty::LastArrival),
            (&DEVPKEY_Device_LastRemovalDate, DeviceProperty::LastRemoval),
        ] {
            match read(devinst, key, DEVPROP_TYPE_FILETIME, filetime) {
                Ok(time) => {
                    let time = time.and_then(device_time);
                    match property {
                        DeviceProperty::FirstInstall => record.first_install = time,
                        DeviceProperty::LastArrival => record.last_arrival = time,
                        _ => record.last_removal = time,
                    }
                }
                Err(()) => missing.push(property),
            }
        }
        record.unreadable = missing;
        Some(record)
    }

    impl rongroi_host::DeviceSource for crate::LiveHost {
        fn devices(&self, bus: DeviceBus) -> Result<Vec<DeviceRecord>, SourceError> {
            let all = device_ids(bus.enumerator(), 0)?;
            let present: std::collections::BTreeSet<String> =
                device_ids(bus.enumerator(), CM_GETIDLIST_FILTER_PRESENT)?
                    .into_iter()
                    .map(|id| id.to_ascii_uppercase())
                    .collect();
            Ok(all
                .iter()
                .filter_map(|id| record(bus, id, present.contains(&id.to_ascii_uppercase())))
                .collect())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn units(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    /// Run by the Windows CI job (ADR 0069). Asserts the shape a live list must have, never what the
    /// runner's devices are, and prints only counts.
    #[cfg(windows)]
    #[test]
    #[ignore = "reads this machine's device list; run by the Windows CI job"]
    fn live_devices_pci_and_hid_are_models_with_no_instance_part() {
        use rongroi_host::{DeviceBus, DeviceSource as _};

        let host = crate::LiveHost;
        for bus in [DeviceBus::Pci, DeviceBus::Hid] {
            let devices = host.devices(bus).unwrap();
            let present = devices.iter().filter(|device| device.present).count();
            let unreadable = devices.iter().filter(|d| !d.unreadable.is_empty()).count();
            println!(
                "{}: {} devices, {present} present, {unreadable} with an unreadable property",
                bus.enumerator(),
                devices.len()
            );
            for device in &devices {
                let prefix = format!("{}\\", bus.enumerator());
                assert!(device.model_id.starts_with(&prefix), "{}", device.model_id);
                // Two parts only: the instance part never leaves the host.
                assert_eq!(
                    device.model_id.matches('\\').count(),
                    1,
                    "{}",
                    device.model_id
                );
                assert!(device.present || device.problem_code.is_none());
                if bus == DeviceBus::Hid {
                    assert_eq!(device.class_code, None);
                }
            }
        }
    }

    #[test]
    fn a_list_ends_at_the_empty_string() {
        assert_eq!(
            multi_sz(&units("PCI\\A\0PCI\\B\0\0ignored\0")),
            vec!["PCI\\A".to_owned(), "PCI\\B".to_owned()]
        );
    }

    #[test]
    fn a_list_cut_short_keeps_what_it_holds_and_an_empty_one_holds_nothing() {
        assert_eq!(multi_sz(&units("PCI\\A\0PCI\\B")), vec!["PCI\\A", "PCI\\B"]);
        assert!(multi_sz(&units("\0")).is_empty());
        assert!(multi_sz(&[]).is_empty());
    }
}
