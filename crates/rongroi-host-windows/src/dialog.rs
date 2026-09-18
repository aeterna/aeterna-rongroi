// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! A yes-or-no question in a window that belongs to Windows, not to a `WebView` (ADR 0052).
//!
//! The desktop app asks for a full scan here, before any collector runs and before any `WebView` exists,
//! so that what the scan reads is decided by a person and measured before a window of this program can
//! do anything (ADR 0001, ADR 0012).

/// Shows `text` under `title` with Yes and No, No the default, and returns whether Yes was chosen.
/// Closing the window is No. On anything but Windows there is no dialog and the answer is No.
#[cfg(windows)]
#[allow(unsafe_code)]
pub fn ask_yes_no(title: &str, text: &str) -> bool {
    use windows::Win32::UI::WindowsAndMessaging::{
        IDYES, MB_DEFBUTTON2, MB_ICONQUESTION, MB_SETFOREGROUND, MB_TOPMOST, MB_YESNO, MessageBoxW,
    };
    use windows::core::HSTRING;

    let title = HSTRING::from(title);
    let text = HSTRING::from(text);
    // SAFETY: both strings are NUL-terminated `HSTRING`s owned by this function and outlive the call,
    // which returns only after the window closes; there is no owner window.
    let answer = unsafe {
        MessageBoxW(
            None,
            &text,
            &title,
            MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2 | MB_SETFOREGROUND | MB_TOPMOST,
        )
    };
    answer == IDYES
}

/// Anything but Windows: no dialog, and so no agreement.
#[cfg(not(windows))]
pub fn ask_yes_no(_title: &str, _text: &str) -> bool {
    false
}
