// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! How long Windows has been counting since it started, for the report header (ADR 0039).

#[cfg(windows)]
impl rongroi_host::BootTimeSource for crate::LiveHost {
    /// `GetTickCount64`: "the number of milliseconds that have elapsed since the system was
    /// started", and the count Microsoft names for elapsed time "that accounts for sleep or
    /// hibernation". `QueryUnbiasedInterruptTime` leaves those out and would put the start later than
    /// it was; `NtQuerySystemInformation(SystemTimeOfDayInformation)` documents its structure as
    /// opaque. The function has no failure to report.
    #[allow(unsafe_code)]
    fn since_boot(&self) -> Result<std::time::Duration, rongroi_host::SourceError> {
        use windows::Win32::System::SystemInformation::GetTickCount64;

        // SAFETY: `GetTickCount64` takes no arguments, touches no memory of ours and only reads a
        // counter the kernel keeps; it changes nothing on this machine.
        let milliseconds = unsafe { GetTickCount64() };
        Ok(std::time::Duration::from_millis(milliseconds))
    }
}
