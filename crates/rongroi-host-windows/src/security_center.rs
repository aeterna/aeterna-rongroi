// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! The antivirus products Windows Security Center lists, read through the WSC API (ADR 0090).
//!
//! Only the list is read: the program never registers with Security Center, changes a default
//! product or asks for notifications.

use rongroi_host::SourceError;

/// `E_ACCESSDENIED`: Windows refused the call.
const E_ACCESSDENIED: i32 = 0x8007_0005_u32.cast_signed();

/// Classifies a failed WSC API call from the HRESULT it returned.
///
/// `E_ACCESSDENIED` is the one answer a caller can act on; every other code, a failed
/// `RemediationPath` read included, is a failure that names the call and the HRESULT (ADR 0090
/// section 4).
pub fn classify_error(call: &str, code: i32) -> SourceError {
    if code == E_ACCESSDENIED {
        SourceError::AccessDenied
    } else {
        SourceError::Failed(format!("{call} returned {:#010x}", code.cast_unsigned()))
    }
}

/// Every antivirus product Security Center lists, in the order it lists them (ADR 0090 section 1).
///
/// The COM objects live on a thread of their own, initialised there and dropped there, so this
/// program's main thread never meets the COM state the desktop app keeps. A panic on that thread is
/// a failure, never a panic in the caller.
#[cfg(windows)]
pub fn products() -> Result<Vec<rongroi_host::AntivirusProductRecord>, SourceError> {
    std::thread::Builder::new()
        .name("security-center".to_owned())
        .spawn(live::read)
        .map_err(|error| {
            SourceError::Failed(format!("no thread for Security Center: {error}"))
        })?
        .join()
        .map_err(|_| SourceError::Failed("the Security Center read stopped".to_owned()))?
}

#[cfg(windows)]
#[allow(unsafe_code)]
mod live {
    use rongroi_host::{AntivirusProductRecord, SourceError};
    use windows::Win32::System::Com::{
        CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx,
        CoUninitialize,
    };
    use windows::Win32::System::SecurityCenter::{
        IWSCProductList, WSCProductList, WSC_SECURITY_PROVIDER_ANTIVIRUS,
    };
    use windows::core::Error;

    use super::classify_error;

    /// A mapper that names `call` and carries its HRESULT into [`classify_error`].
    fn call_error(call: &'static str) -> impl FnOnce(Error) -> SourceError {
        move |error| classify_error(call, error.code().0)
    }

    pub(super) fn read() -> Result<Vec<AntivirusProductRecord>, SourceError> {
        // SAFETY: called once on this thread, which nothing else uses; balanced by `CoUninitialize`
        // below when it succeeded. `COINIT_MULTITHREADED` because nothing here needs a message loop.
        let init = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
        if init.is_err() {
            return Err(classify_error("CoInitializeEx", init.0));
        }
        let result = read_list();
        // SAFETY: this thread's `CoInitializeEx` succeeded above, and every COM object made here is
        // dropped by now, inside `read_list`.
        unsafe { CoUninitialize() };
        result
    }

    fn read_list() -> Result<Vec<AntivirusProductRecord>, SourceError> {
        // SAFETY: COM is initialised on this thread, and the class and interface are Windows' own.
        let created = unsafe { CoCreateInstance(&WSCProductList, None, CLSCTX_INPROC_SERVER) };
        let list: IWSCProductList =
            created.map_err(call_error("CoCreateInstance(WSCProductList)"))?;
        // SAFETY: `list` is a live WSC product list; `Initialize` only selects which provider type to
        // enumerate and changes nothing on the machine.
        let initialized = unsafe { list.Initialize(WSC_SECURITY_PROVIDER_ANTIVIRUS) };
        initialized.map_err(call_error("IWSCProductList::Initialize"))?;
        // SAFETY: `list` is initialised for the antivirus provider and is live for this call.
        let counted = unsafe { list.Count() };
        let count = counted.map_err(call_error("IWSCProductList::Count"))?;
        let mut products = Vec::new();
        for index in 0..count {
            // SAFETY: `index` is below the count just read, and `list` is live.
            let item = unsafe { list.get_Item(index) };
            let product = item.map_err(call_error("IWSCProductList::get_Item"))?;
            // SAFETY: `product` is a live item of the list.
            let named = unsafe { product.ProductName() };
            let display_name = named.map_err(call_error("ProductName"))?.to_string();
            // SAFETY: `product` is a live item of the list; the value is copied, not decoded.
            let stated = unsafe { product.ProductState() };
            let state = stated.map_err(call_error("ProductState"))?.0;
            // SAFETY: `product` is a live item of the list. A failure here fails the whole list, as
            // an incomplete answer must (ADR 0090 section 4).
            let remediated = unsafe { product.RemediationPath() };
            let remediation_path = remediated.map_err(call_error("RemediationPath"))?.to_string();
            products.push(AntivirusProductRecord {
                display_name,
                state,
                remediation_path,
            });
        }
        Ok(products)
    }
}

#[cfg(test)]
mod tests {
    use rongroi_host::SourceError;

    use super::classify_error;

    /// A refused read is its own answer, which a collector reports as `access_denied`, not a failure.
    #[test]
    fn access_denied_is_its_own_answer() {
        assert_eq!(
            classify_error("CoCreateInstance", 0x8007_0005_u32.cast_signed()),
            SourceError::AccessDenied
        );
    }

    /// Every other failure names the call and carries the HRESULT as an unsigned hex value.
    #[test]
    fn every_other_failure_names_the_call_and_the_hresult_in_hex() {
        assert_eq!(
            classify_error("RemediationPath", 0x8000_4005_u32.cast_signed()),
            SourceError::Failed("RemediationPath returned 0x80004005".to_owned())
        );
    }
}
