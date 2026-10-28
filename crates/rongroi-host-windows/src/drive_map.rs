// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! The drive map: the letters Windows has now, with what a device path is mapped through (ADR 0087
//! section 1). Nothing is read from a file and no administrator right is needed.

#[cfg(windows)]
pub(crate) use live::read;

#[cfg(windows)]
mod live {
    use rongroi_host::{DriveKind, DriveMap, DriveMapEntry, SourceError, UsnJournalSource};

    use windows::Win32::Storage::FileSystem::{GetDriveTypeW, GetLogicalDrives, QueryDosDeviceW};
    use windows::Win32::System::Diagnostics::Debug::{
        SEM_FAILCRITICALERRORS, SEM_NOOPENFILEERRORBOX, SetThreadErrorMode, THREAD_ERROR_MODE,
    };
    use windows::Win32::System::WindowsProgramming::{DRIVE_FIXED, DRIVE_REMOVABLE};
    use windows::core::PCWSTR;

    use crate::LiveHost;

    /// The prefix of the only device name a letter is mapped through. Anything else — a network drive,
    /// a `subst` drive, an optical drive with no disc — leaves the letter out (ADR 0087 section 1).
    const HARD_DISK_VOLUME: &str = r"\Device\HarddiskVolume";

    /// Most UTF-16 units `QueryDosDeviceW` may write. A device path is far shorter.
    const MAX_DEVICE_UNITS: usize = 1024;

    /// The fixed reason the whole map cannot be read. It names no device and no serial.
    const LIST_FAILED_MESSAGE: &str = "cannot list the drive letters";

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Whether `device` is exactly `\Device\HarddiskVolume<digits>`.
    fn is_hard_disk_volume(device: &str) -> bool {
        let Some(prefix) = device.get(..HARD_DISK_VOLUME.len()) else {
            return false;
        };
        if !prefix.eq_ignore_ascii_case(HARD_DISK_VOLUME) {
            return false;
        }
        device.get(HARD_DISK_VOLUME.len()..).is_some_and(|digits| {
            !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
        })
    }

    fn drive_kind(code: u32) -> DriveKind {
        if code == DRIVE_FIXED {
            DriveKind::Fixed
        } else if code == DRIVE_REMOVABLE {
            DriveKind::Removable
        } else {
            DriveKind::Other
        }
    }

    /// The device `QueryDosDeviceW("X:")` names, or `None` when it fails or is not a hard disk volume.
    #[allow(unsafe_code)]
    fn device_of(letter: char) -> Option<String> {
        let name = wide(&format!("{letter}:"));
        let mut buffer = [0u16; MAX_DEVICE_UNITS];
        // SAFETY: `name` is a NUL-terminated UTF-16 string that outlives the call, and `buffer` is a
        // live slice whose length is passed by the wrapper. The call only reads Windows' device map.
        let length = unsafe { QueryDosDeviceW(PCWSTR(name.as_ptr()), Some(&mut buffer[..])) };
        let length = usize::try_from(length).ok()?.min(buffer.len());
        let target = buffer.get(..length)?;
        // A device can have several targets separated by NUL; the first is the volume's own name.
        let target = target.split(|unit| *unit == 0).next().unwrap_or(&[]);
        let device = String::from_utf16_lossy(target);
        is_hard_disk_volume(&device).then_some(device)
    }

    /// One letter's entry. A letter whose device is not a hard disk volume, or whose volume serial
    /// cannot be read, is left out: without a serial it cannot map a Prefetch path, and a partial
    /// entry would need a value nobody read.
    #[allow(unsafe_code)]
    fn entry(letter: char) -> Option<DriveMapEntry> {
        let device = device_of(letter)?;
        let root = format!("{letter}:\\");
        let serial =
            u32::try_from(LiveHost.file_id(&root).ok()??.volume_serial & u64::from(u32::MAX))
                .ok()?;
        let wide_root = wide(&root);
        // SAFETY: `wide_root` is a NUL-terminated UTF-16 string that outlives the call. The call only
        // reads what kind of drive Windows reports; it opens nothing.
        let kind = drive_kind(unsafe { GetDriveTypeW(PCWSTR(wide_root.as_ptr())) });
        Some(DriveMapEntry {
            letter,
            device,
            serial,
            kind,
        })
    }

    /// Puts the calling thread in `SEM_FAILCRITICALERRORS | SEM_NOOPENFILEERRORBOX` for as long as it
    /// lives, so that reading a removable or card-reader letter with no media raises no "There is no
    /// disk in the drive" dialog and does not block (ADR 0087 section 1). Only this process's own
    /// thread is changed: the scanned machine's drives, files and registry are untouched (AGENTS.md
    /// hard rule 2). `Drop` restores the thread's previous mode on every return path.
    struct ErrorModeGuard {
        old: THREAD_ERROR_MODE,
    }

    impl ErrorModeGuard {
        /// Sets the mode, or gives `None` when Windows refuses it: the letters are then read without
        /// the guard, as before, and no new error is reported.
        #[allow(unsafe_code)]
        fn set() -> Option<Self> {
            let mut old = THREAD_ERROR_MODE::default();
            // SAFETY: `old` is a live, writable `THREAD_ERROR_MODE` for the call to fill, and the flags
            // change the error mode of this thread only.
            unsafe {
                SetThreadErrorMode(
                    SEM_FAILCRITICALERRORS | SEM_NOOPENFILEERRORBOX,
                    Some(&raw mut old),
                )
            }
            .ok()?;
            Some(Self { old })
        }
    }

    impl Drop for ErrorModeGuard {
        #[allow(unsafe_code)]
        fn drop(&mut self) {
            // SAFETY: `self.old` is the value the successful `SetThreadErrorMode` in `set` wrote, and
            // `None` asks for no old value, so the call touches no memory of ours.
            let _ = unsafe { SetThreadErrorMode(self.old, None) };
        }
    }

    /// Every letter `GetLogicalDrives` reports, read once (ADR 0087 section 1).
    #[allow(unsafe_code)]
    pub(crate) fn read() -> Result<DriveMap, SourceError> {
        // SAFETY: `GetLogicalDrives` takes no arguments, touches no memory of ours and only reads a
        // bitmask Windows keeps; it changes nothing on this machine.
        let drives = unsafe { GetLogicalDrives() };
        if drives == 0 {
            return Err(SourceError::Failed(LIST_FAILED_MESSAGE.to_owned()));
        }
        // Set before the first letter is read: a card reader with no media still has a letter here.
        let _error_mode = ErrorModeGuard::set();
        let mut entries = Vec::new();
        for index in 0..26u8 {
            if drives & (1u32 << index) == 0 {
                continue;
            }
            if let Some(entry) = entry(char::from(b'A' + index)) {
                entries.push(entry);
            }
        }
        Ok(DriveMap { entries })
    }
}
