// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! Windows' own Save dialog, for the one file this program writes when a person asks it to: a saved report
//! (ADR 0073). Nothing here writes; it returns the path the person chose, or that they cancelled.
//!
//! The dialog runs on a thread of its own with COM initialised for that thread, so it never meets the COM
//! state the `WebView` keeps on the window's thread.

use std::path::PathBuf;

/// Shows the Save dialog with `title`, `default_name` in the name box and the Documents folder open, owned by
/// the window `owner` when given (an `HWND` as an integer). `Ok(None)` when the person cancelled; Windows asks
/// before replacing a file.
///
/// # Errors
///
/// A sentence saying which call failed, or that there is no such dialog on this platform.
pub fn ask_save_path(
    title: &str,
    default_name: &str,
    owner: Option<isize>,
) -> Result<Option<PathBuf>, String> {
    let title = title.to_owned();
    let default_name = default_name.to_owned();
    std::thread::Builder::new()
        .name("save-dialog".to_owned())
        .spawn(move || live::ask(&title, &default_name, owner))
        .map_err(|error| format!("no thread for the Save dialog: {error}"))?
        .join()
        .map_err(|_| "the Save dialog's thread stopped".to_owned())?
}

#[cfg(windows)]
#[allow(unsafe_code)]
mod live {
    use std::path::PathBuf;

    use windows::Win32::Foundation::{ERROR_CANCELLED, HWND};
    use windows::Win32::System::Com::{
        CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE, CoCreateInstance,
        CoInitializeEx, CoTaskMemFree, CoUninitialize,
    };
    use windows::Win32::UI::Shell::Common::COMDLG_FILTERSPEC;
    use windows::Win32::UI::Shell::{
        FOLDERID_Documents, FOS_FORCEFILESYSTEM, FOS_NOREADONLYRETURN, FOS_OVERWRITEPROMPT,
        FileSaveDialog, IFileSaveDialog, IShellItem, KF_FLAG_DEFAULT, SHGetKnownFolderItem,
        SIGDN_FILESYSPATH,
    };
    use windows::core::{HRESULT, HSTRING, w};

    pub(super) fn ask(
        title: &str,
        default_name: &str,
        owner: Option<isize>,
    ) -> Result<Option<PathBuf>, String> {
        // SAFETY: called once on this thread, which nothing else uses; balanced by `CoUninitialize` below
        // when it succeeded.
        let init =
            unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) };
        if init.is_err() {
            return Err(format!("COM could not start for the Save dialog: {init:?}"));
        }
        let result = show(title, default_name, owner);
        // SAFETY: this thread's `CoInitializeEx` succeeded above; every COM object made here is dropped by
        // now, inside `show`.
        unsafe { CoUninitialize() };
        result
    }

    fn show(
        title: &str,
        default_name: &str,
        owner: Option<isize>,
    ) -> Result<Option<PathBuf>, String> {
        let fail = |what: &str, error: windows::core::Error| format!("{what} failed: {error}");
        // SAFETY: COM is initialised on this thread; the CLSID and interface are Windows' own.
        let dialog: IFileSaveDialog =
            unsafe { CoCreateInstance(&FileSaveDialog, None, CLSCTX_INPROC_SERVER) }
                .map_err(|e| fail("creating the Save dialog", e))?;
        let types = [COMDLG_FILTERSPEC {
            pszName: w!("JSON"),
            pszSpec: w!("*.json"),
        }];
        // SAFETY: each string is an `HSTRING` or a static wide string that outlives the call; `types` lives
        // until the dialog is dropped at the end of this function.
        unsafe {
            dialog
                .SetTitle(&HSTRING::from(title))
                .map_err(|e| fail("SetTitle", e))?;
            dialog
                .SetFileName(&HSTRING::from(default_name))
                .map_err(|e| fail("SetFileName", e))?;
            dialog
                .SetFileTypes(&types)
                .map_err(|e| fail("SetFileTypes", e))?;
            dialog
                .SetDefaultExtension(w!("json"))
                .map_err(|e| fail("SetDefaultExtension", e))?;
            let options = dialog.GetOptions().map_err(|e| fail("GetOptions", e))?;
            dialog
                .SetOptions(
                    options | FOS_OVERWRITEPROMPT | FOS_FORCEFILESYSTEM | FOS_NOREADONLYRETURN,
                )
                .map_err(|e| fail("SetOptions", e))?;
            // The Documents folder when Windows can name it; otherwise the dialog's own choice.
            if let Ok(documents) =
                SHGetKnownFolderItem::<IShellItem>(&FOLDERID_Documents, KF_FLAG_DEFAULT, None)
            {
                let _ = dialog.SetFolder(&documents);
            }
        }
        let owner = owner.map(|handle| HWND(handle as *mut core::ffi::c_void));
        // SAFETY: `owner`, when given, is the window handle the caller holds; the call returns when the
        // dialog closes.
        match unsafe { dialog.Show(owner) } {
            Ok(()) => {}
            Err(error) if error.code() == HRESULT::from_win32(ERROR_CANCELLED.0) => {
                return Ok(None);
            }
            Err(error) => return Err(fail("showing the Save dialog", error)),
        }
        // SAFETY: `Show` succeeded, so the dialog has a result; the path string is Windows' allocation,
        // copied and then freed with `CoTaskMemFree` as the documentation asks.
        unsafe {
            let item = dialog.GetResult().map_err(|e| fail("GetResult", e))?;
            let path = item
                .GetDisplayName(SIGDN_FILESYSPATH)
                .map_err(|e| fail("GetDisplayName", e))?;
            let text = path.to_string();
            CoTaskMemFree(Some(path.0.cast_const().cast()));
            text.map(|text| Some(PathBuf::from(text)))
                .map_err(|_| "the chosen path is not valid Unicode".to_owned())
        }
    }
}

/// Anything but Windows: there is no Save dialog.
#[cfg(not(windows))]
mod live {
    use std::path::PathBuf;

    pub(super) fn ask(
        _title: &str,
        _default_name: &str,
        _owner: Option<isize>,
    ) -> Result<Option<PathBuf>, String> {
        Err("there is no Save dialog on this platform".to_owned())
    }
}

#[cfg(test)]
mod tests {
    #[cfg(not(windows))]
    #[test]
    fn there_is_no_save_dialog_off_windows() {
        assert!(super::ask_save_path("t", "n.json", None).is_err());
    }
}
