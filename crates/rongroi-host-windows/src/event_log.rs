// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! What the Windows Event Log service states about a channel's log file (ADR 0042).
//!
//! Two properties of a channel's configuration are read — the path of the file the service writes it
//! to and the largest that file may grow — through `EvtOpenChannelConfig` and
//! `EvtGetChannelConfigProperty`: the service's own statement of the channel's configuration, which
//! on the machine ADR 0042 measured disagreed with the registry's `MaxSize` for 18 of the 94 keys that
//! carry one. `EvtSetChannelConfigProperty` and `EvtSaveChannelConfig`, which would change a channel,
//! are never called, and the handle is closed on every path.

/// `ERROR_ACCESS_DENIED`.
///
/// These codes are written out rather than imported from `windows` so that the classification below
/// compiles and is tested on every operating system. The values are those `windows` 0.62.2 declares in
/// `Win32::Foundation`.
pub const ERROR_ACCESS_DENIED: u32 = 5;

/// `ERROR_EVT_CHANNEL_NOT_FOUND`: the service has no channel of that name.
pub const ERROR_EVT_CHANNEL_NOT_FOUND: u32 = 15007;

/// What a failed Event Log call's Win32 error code says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenOutcome {
    /// The service has no such channel. An answer, not a failure to look.
    NoSuchChannel,
    /// The service refused this caller.
    AccessDenied,
    /// Anything else, including a service that is not running.
    Failed,
}

/// Classifies the Win32 error code of a failed `EvtOpenChannelConfig` or
/// `EvtGetChannelConfigProperty`.
pub fn classify(win32_error: u32) -> OpenOutcome {
    match win32_error {
        ERROR_EVT_CHANNEL_NOT_FOUND => OpenOutcome::NoSuchChannel,
        ERROR_ACCESS_DENIED => OpenOutcome::AccessDenied,
        _ => OpenOutcome::Failed,
    }
}

/// The Win32 error code inside an `HRESULT` built by `HRESULT_FROM_WIN32`, or `None` for an `HRESULT`
/// of any other facility.
pub fn win32_code(hresult: u32) -> Option<u32> {
    // FACILITY_WIN32 is 7, with the severity bit set: 0x8007xxxx.
    (hresult & 0xFFFF_0000 == 0x8007_0000).then_some(hresult & 0xFFFF)
}

#[cfg(windows)]
impl rongroi_host::EventLogConfigSource for crate::LiveHost {
    fn channel_config_reader(
        &self,
    ) -> Result<Box<dyn rongroi_host::ChannelConfigReader>, rongroi_host::SourceError> {
        Ok(Box::new(LiveChannelConfigReader))
    }
}

/// Asks the local Event Log service. It holds nothing, so it can move to any thread; each question
/// opens and closes its own handle on the thread that asks it.
#[cfg(windows)]
#[derive(Debug, Clone, Copy)]
struct LiveChannelConfigReader;

#[cfg(windows)]
impl rongroi_host::ChannelConfigReader for LiveChannelConfigReader {
    fn channel_config(
        &self,
        channel: &str,
    ) -> Result<Option<rongroi_host::ChannelConfig>, rongroi_host::SourceError> {
        live::channel_config(channel)
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
mod live {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    use rongroi_host::{ChannelConfig, SourceError};
    use windows::Win32::System::EventLog::{
        EVT_CHANNEL_CONFIG_PROPERTY_ID, EVT_HANDLE, EVT_VARIANT,
        EvtChannelLoggingConfigLogFilePath, EvtChannelLoggingConfigMaxSize, EvtClose,
        EvtGetChannelConfigProperty, EvtOpenChannelConfig, EvtVarTypeString, EvtVarTypeUInt64,
    };
    use windows::core::PCWSTR;

    use super::{OpenOutcome, classify, win32_code};

    /// Closes a channel configuration handle when it goes out of scope, whichever path left.
    struct Handle(EVT_HANDLE);

    impl Drop for Handle {
        fn drop(&mut self) {
            // SAFETY: `self.0` is a handle `EvtOpenChannelConfig` returned and nothing has closed it.
            // The result says nothing about the channel and is not read.
            let _ = unsafe { EvtClose(self.0) };
        }
    }

    fn failure(error: &windows::core::Error, call: &str) -> SourceError {
        let code = error.code().0.cast_unsigned();
        match win32_code(code).map(classify) {
            Some(OpenOutcome::AccessDenied) => SourceError::AccessDenied,
            _ => SourceError::Failed(format!("{call} returned {code:#010x}")),
        }
    }

    pub(super) fn channel_config(channel: &str) -> Result<Option<ChannelConfig>, SourceError> {
        let wide: Vec<u16> = OsStr::new(channel)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        // SAFETY: `wide` is a NUL-terminated UTF-16 string that outlives the call. `None` is the
        // local machine, and flags must be zero. The handle only reads unless a set-and-save pair
        // is called on it, and neither is anywhere in this program.
        let opened = unsafe { EvtOpenChannelConfig(None, PCWSTR(wide.as_ptr()), 0) };
        let handle = match opened {
            Ok(handle) => Handle(handle),
            Err(error) => {
                let code = error.code().0.cast_unsigned();
                return match win32_code(code).map(classify) {
                    Some(OpenOutcome::NoSuchChannel) => Ok(None),
                    _ => Err(failure(&error, "EvtOpenChannelConfig")),
                };
            }
        };

        let path = property(
            &handle,
            EvtChannelLoggingConfigLogFilePath,
            |variant, buffer| {
                if variant.Type != EvtVarTypeString.0.cast_unsigned() {
                    return None;
                }
                // SAFETY: the service said the variant holds a string, so `StringVal` is the member it
                // wrote.
                let pointer = unsafe { variant.Anonymous.StringVal };
                wide_string_within(pointer, buffer)
            },
        )?;
        let max_size_bytes = property(&handle, EvtChannelLoggingConfigMaxSize, |variant, _| {
            if variant.Type != EvtVarTypeUInt64.0.cast_unsigned() {
                return None;
            }
            // SAFETY: the service said the variant holds an unsigned 64-bit number, so `UInt64Val`
            // is the member it wrote.
            Some(unsafe { variant.Anonymous.UInt64Val })
        })?;
        Ok(Some(ChannelConfig {
            log_file_path: path,
            max_size_bytes,
        }))
    }

    /// Reads one property into a buffer the service sizes, and decodes it with `decode`.
    ///
    /// The buffer is a vector of `u64` rather than of bytes because the service writes an
    /// `EVT_VARIANT` at its start, which has the alignment of a pointer; `u64` has that alignment on
    /// the one target this crate builds for.
    fn property<T>(
        handle: &Handle,
        id: EVT_CHANNEL_CONFIG_PROPERTY_ID,
        decode: impl Fn(&EVT_VARIANT, &[u64]) -> Option<T>,
    ) -> Result<T, SourceError> {
        let mut used = 0_u32;
        // SAFETY: a size of zero with no buffer is the documented way to learn the size needed;
        // `used` is a valid out-pointer.
        let sized = unsafe { EvtGetChannelConfigProperty(handle.0, id, 0, 0, None, &raw mut used) };
        if let Err(error) = sized {
            // ERROR_INSUFFICIENT_BUFFER (122) is the answer the first call is expected to give.
            if win32_code(error.code().0.cast_unsigned()) != Some(122) {
                return Err(failure(&error, "EvtGetChannelConfigProperty"));
            }
        }
        let bytes = usize::try_from(used)
            .unwrap_or(usize::MAX)
            .max(size_of::<EVT_VARIANT>());
        let mut buffer = vec![0_u64; bytes.div_ceil(size_of::<u64>())];
        let Ok(capacity) = u32::try_from(buffer.len() * size_of::<u64>()) else {
            return Err(SourceError::Failed(
                "a channel property does not fit in a u32-sized buffer".to_owned(),
            ));
        };
        // SAFETY: `buffer` is `capacity` writable, pointer-aligned bytes that outlive the call, at
        // least the size of an `EVT_VARIANT`, and the size the previous call asked for.
        unsafe {
            EvtGetChannelConfigProperty(
                handle.0,
                id,
                0,
                capacity,
                Some(buffer.as_mut_ptr().cast::<EVT_VARIANT>()),
                &raw mut used,
            )
        }
        .map_err(|error| failure(&error, "EvtGetChannelConfigProperty"))?;
        // SAFETY: the call succeeded, so the buffer starts with an initialised `EVT_VARIANT`, and it
        // is aligned and at least that large (above).
        let variant = unsafe { &*buffer.as_ptr().cast::<EVT_VARIANT>() };
        decode(variant, &buffer).ok_or_else(|| {
            SourceError::Failed(format!(
                "channel property {} arrived as variant type {}",
                id.0, variant.Type
            ))
        })
    }

    /// The NUL-terminated UTF-16 string at `pointer`, read only if it lies inside `buffer`.
    ///
    /// The service writes the string's characters into the same buffer as the variant pointing at
    /// them; a pointer anywhere else, or a string with no terminator before the buffer ends, is
    /// refused rather than followed.
    fn wide_string_within(pointer: PCWSTR, buffer: &[u64]) -> Option<String> {
        let start = buffer.as_ptr().cast::<u16>() as usize;
        let units = buffer.len() * (size_of::<u64>() / size_of::<u16>());
        let at = pointer.0 as usize;
        if at < start || at >= start + units * size_of::<u16>() || !(at - start).is_multiple_of(2) {
            return None;
        }
        let offset = (at - start) / size_of::<u16>();
        // SAFETY: `buffer` is `units` initialised `u16`s wide at that alignment (a `u64` is two of
        // them and has the stricter alignment), and it outlives the slice.
        let wide = unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<u16>(), units) };
        let rest = &wide[offset..];
        let end = rest.iter().position(|unit| *unit == 0)?;
        String::from_utf16(&rest[..end]).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_channel_the_service_does_not_have_is_an_answer() {
        assert_eq!(
            classify(ERROR_EVT_CHANNEL_NOT_FOUND),
            OpenOutcome::NoSuchChannel
        );
    }

    #[test]
    fn a_refusal_is_access_denied_and_anything_else_failed() {
        assert_eq!(classify(ERROR_ACCESS_DENIED), OpenOutcome::AccessDenied);
        // RPC_S_SERVER_UNAVAILABLE (the service is not running), ERROR_INVALID_PARAMETER.
        for code in [1722_u32, 87] {
            assert_eq!(classify(code), OpenOutcome::Failed, "{code}");
        }
    }

    #[test]
    fn only_a_win32_hresult_carries_a_win32_code() {
        assert_eq!(win32_code(0x8007_3A9F), Some(ERROR_EVT_CHANNEL_NOT_FOUND));
        assert_eq!(win32_code(0x8007_0005), Some(ERROR_ACCESS_DENIED));
        assert_eq!(win32_code(0x8028_400F), None);
        assert_eq!(win32_code(0), None);
    }

    /// On a real Windows machine the three classic channels are always registered, and the service
    /// names a file for each. A channel nobody registered is `None`, not an error.
    #[cfg(windows)]
    #[test]
    fn the_service_states_a_file_for_the_application_channel() {
        use rongroi_host::EventLogConfigSource;

        let reader = crate::LiveHost.channel_config_reader().unwrap();
        let config = reader
            .channel_config("Application")
            .unwrap()
            .expect("every Windows installation registers the Application channel");
        assert!(
            config
                .log_file_path
                .to_ascii_lowercase()
                .ends_with(r"\application.evtx"),
            "{config:?}"
        );
        assert!(config.max_size_bytes > 0, "{config:?}");
        assert_eq!(
            reader.channel_config("Rongroi-No-Such-Channel/Operational"),
            Ok(None)
        );
    }
}
