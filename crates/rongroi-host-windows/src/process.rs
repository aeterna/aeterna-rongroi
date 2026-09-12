// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! What is running on this machine, read through the ToolHelp process snapshot (ADR 0010).
//!
//! Name and path only: no image is hashed, no process memory is read, and every handle is closed as
//! soon as the one query that needs it has answered.

/// Largest image path this reads, in UTF-16 code units, including the terminating NUL. Windows' own
/// limit for an extended-length path is 32 767 characters.
#[cfg(windows)]
const MAX_IMAGE_PATH_UNITS: usize = 32_768;

/// Reads a UTF-16 string Windows wrote into a fixed buffer, stopping at the first NUL.
///
/// It sits outside the `unsafe` blocks so that it compiles and is tested on every operating system —
/// the same split ADR 0011 made for the TBS result codes. Invalid UTF-16 becomes the replacement
/// character instead of an error: a name the reviewer can read is worth more than a dropped process.
pub fn wide_to_string(buffer: &[u16]) -> String {
    let end = buffer
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(buffer.len());
    String::from_utf16_lossy(&buffer[..end])
}

#[cfg(windows)]
impl rongroi_host::ProcessSource for crate::LiveHost {
    #[allow(unsafe_code)]
    fn running_processes(
        &self,
    ) -> Result<Vec<rongroi_host::ProcessRecord>, rongroi_host::SourceError> {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, TH32CS_SNAPPROCESS,
        };

        // SAFETY: `TH32CS_SNAPPROCESS` with process id 0 asks for a snapshot of the whole machine's
        // process list. The call only reads; it changes nothing on this machine. The handle it
        // returns is closed below, on every path out of this function.
        let snapshot =
            unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }.map_err(|error| {
                rongroi_host::SourceError::Failed(format!(
                    "CreateToolhelp32Snapshot failed: {error}"
                ))
            })?;

        let walked = walk_snapshot(snapshot);

        // SAFETY: `snapshot` came from the successful `CreateToolhelp32Snapshot` above and is not
        // used again after this call.
        let _ = unsafe { CloseHandle(snapshot) };

        walked
    }
}

/// Walks every entry of an open process snapshot.
///
/// The whole walk fails together: a partial list that looked complete would be read as "nothing else
/// was running", which is the same mistake as reporting `NotFound` for something never read.
#[cfg(windows)]
#[allow(unsafe_code)]
fn walk_snapshot(
    snapshot: windows::Win32::Foundation::HANDLE,
) -> Result<Vec<rongroi_host::ProcessRecord>, rongroi_host::SourceError> {
    use windows::Win32::System::Diagnostics::ToolHelp::{
        PROCESSENTRY32W, Process32FirstW, Process32NextW,
    };

    let Ok(size) = u32::try_from(size_of::<PROCESSENTRY32W>()) else {
        return Err(rongroi_host::SourceError::Failed(
            "PROCESSENTRY32W does not fit in a u32".to_owned(),
        ));
    };
    // The caller states the size of its own structure in `dwSize`; Windows fills in the rest.
    let mut entry = PROCESSENTRY32W {
        dwSize: size,
        ..Default::default()
    };

    // SAFETY: `entry` is a fully initialised `PROCESSENTRY32W` whose `dwSize` holds its own size in
    // bytes, as the API requires, and it outlives the call. `snapshot` is an open process snapshot.
    unsafe { Process32FirstW(snapshot, &raw mut entry) }.map_err(|error| {
        rongroi_host::SourceError::Failed(format!("Process32FirstW failed: {error}"))
    })?;

    let mut processes = Vec::new();
    loop {
        processes.push(rongroi_host::ProcessRecord {
            pid: entry.th32ProcessID,
            name: wide_to_string(&entry.szExeFile),
            path: image_path(entry.th32ProcessID),
        });
        // SAFETY: as for `Process32FirstW` above. Windows reports the end of the list as an error,
        // which is an ordinary end of the walk and not a failure to look.
        if unsafe { Process32NextW(snapshot, &raw mut entry) }.is_err() {
            return Ok(processes);
        }
    }
}

/// The full path of one process's image, or `None` when Windows will not name it.
///
/// A protected process and a process that exited between the snapshot and this call answer the same
/// way: nothing is known about its path. The caller still lists the process, without the field
/// (ADR 0010).
#[cfg(windows)]
#[allow(unsafe_code)]
fn image_path(pid: u32) -> Option<String> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
        QueryFullProcessImageNameW,
    };
    use windows::core::PWSTR;

    let mut buffer = vec![0_u16; MAX_IMAGE_PATH_UNITS];
    let mut length = u32::try_from(buffer.len()).ok()?;

    // SAFETY: `PROCESS_QUERY_LIMITED_INFORMATION` is the smallest access right that lets a process
    // be asked for its own identity — no memory of it is read and nothing about it is changed —
    // `false` does not inherit the handle, and the handle is closed before this function returns.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;

    // SAFETY: `buffer` holds `length` writable UTF-16 units and outlives the call, `length` is a
    // valid in/out pointer holding that count, and `handle` is the process opened just above. The
    // call only reads the image path Windows already keeps for that process.
    let queried = unsafe {
        QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_WIN32,
            PWSTR(buffer.as_mut_ptr()),
            &raw mut length,
        )
    };

    // SAFETY: `handle` came from the successful `OpenProcess` above and is not used again.
    let _ = unsafe { CloseHandle(handle) };

    queried.ok()?;
    // On success Windows sets `length` to the number of units it wrote, not counting the NUL.
    let written = usize::try_from(length).ok()?.min(buffer.len());
    let path = wide_to_string(&buffer[..written]);
    (!path.is_empty()).then_some(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_ends_at_the_first_nul_and_not_at_the_end_of_the_buffer() {
        let mut buffer = [0_u16; 16];
        for (slot, unit) in buffer.iter_mut().zip("FiveM.exe".encode_utf16()) {
            *slot = unit;
        }
        assert_eq!(wide_to_string(&buffer), "FiveM.exe");
    }

    #[test]
    fn a_buffer_without_a_nul_is_read_to_its_end() {
        let buffer: Vec<u16> = "explorer.exe".encode_utf16().collect();
        assert_eq!(wide_to_string(&buffer), "explorer.exe");
    }

    #[test]
    fn an_empty_buffer_is_an_empty_name() {
        assert_eq!(wide_to_string(&[]), "");
        assert_eq!(wide_to_string(&[0, 0, 0]), "");
    }

    #[test]
    fn a_name_outside_ascii_survives() {
        let buffer: Vec<u16> = "โปรแกรม.exe".encode_utf16().chain([0]).collect();
        assert_eq!(wide_to_string(&buffer), "โปรแกรม.exe");
    }

    /// A file name is whatever bytes the file system holds, so it need not be valid UTF-16. The
    /// process is still listed, with a name the reviewer can see.
    #[test]
    fn invalid_utf16_does_not_panic_and_does_not_drop_the_name() {
        // 0xD800 is a lone high surrogate: no valid UTF-16 sequence ends there.
        let buffer = [u16::from(b'a'), 0xD800, u16::from(b'b'), 0];
        assert_eq!(wide_to_string(&buffer), "a\u{fffd}b");
    }
}
