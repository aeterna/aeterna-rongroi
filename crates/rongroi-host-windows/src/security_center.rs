// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! The antivirus products Windows Security Center lists, read through the WSC API (ADR 0090).
//!
//! Only the list is read: the program never registers with Security Center, changes a default
//! product or asks for notifications.

#[cfg(windows)]
use std::sync::mpsc;
#[cfg(windows)]
use std::time::Duration;

#[cfg(windows)]
use rongroi_host::AntivirusList;
use rongroi_host::SourceError;

/// How long the Security Center read may take before this program stops waiting. A0 measured 23 ms
/// at most; blocking was not measured.
#[cfg(windows)]
const TIMEOUT: Duration = Duration::from_secs(15);

/// `E_ACCESSDENIED`: Windows refused the call.
const E_ACCESSDENIED: i32 = 0x8007_0005_u32.cast_signed();

/// `ERROR_SERVICE_NOT_ACTIVE` as an HRESULT: the service that answers is not running.
const ERROR_SERVICE_NOT_ACTIVE: i32 = 0x8007_0426_u32.cast_signed();

/// Classifies a failed WSC API call from the HRESULT it returned.
///
/// `E_ACCESSDENIED` is the one answer a caller can act on; every other code, a failed
/// `RemediationPath` read included, is a failure that names the call and the HRESULT (ADR 0090
/// section 4). The service not running is not among them: it is an answer, from the three calls
/// that ask the service whether it is there (see [`is_service_not_running`]).
pub fn classify_error(call: &str, code: i32) -> SourceError {
    if code == E_ACCESSDENIED {
        SourceError::AccessDenied
    } else {
        SourceError::Failed(format!("{call} returned {:#010x}", code.cast_unsigned()))
    }
}

/// Whether a failed WSC API call means the Security Center service is not running.
///
/// Measured on the lab machine 75 s after boot: the service was `Stopped` with start type
/// `Automatic`, and `IWSCProductList::Initialize` returned `0x80070426`
/// (`ERROR_SERVICE_NOT_ACTIVE`); after it started, the same call listed the product (ADR 0090).
/// The program never starts or changes the service, so this answer may change on its own.
pub fn is_service_not_running(code: i32) -> bool {
    code == ERROR_SERVICE_NOT_ACTIVE
}

/// Every antivirus product Security Center lists, in the order it lists them (ADR 0090 section 1).
///
/// The COM objects live on a thread of their own, initialised there and dropped there, so this
/// program's main thread never meets the COM state the desktop app keeps. A panic on that thread is
/// a failure, never a panic in the caller. A call that does not answer in time leaves the thread
/// detached rather than hanging the scan.
#[cfg(windows)]
pub fn products() -> Result<AntivirusList, SourceError> {
    let (sender, receiver) = mpsc::channel();
    std::thread::Builder::new()
        .name("security-center".to_owned())
        .spawn(move || {
            // A timed-out caller has dropped the receiver, so a failed send is expected and ignored.
            let _ = sender.send(live::read());
        })
        .map_err(|error| SourceError::Failed(format!("no thread for Security Center: {error}")))?;
    match receiver.recv_timeout(TIMEOUT) {
        Ok(answer) => answer,
        Err(mpsc::RecvTimeoutError::Timeout) => Err(SourceError::Failed(
            "the Security Center read did not answer in 15 s".to_owned(),
        )),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(SourceError::Failed(
            "the Security Center read stopped".to_owned(),
        )),
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
mod live {
    use rongroi_host::{AntivirusList, AntivirusProductRecord, SourceError};
    use windows::Win32::System::Com::{
        CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx,
        CoUninitialize,
    };
    use windows::Win32::System::SecurityCenter::{
        IWSCProductList, WSC_SECURITY_PROVIDER_ANTIVIRUS, WSCProductList,
    };
    use windows::core::Error;

    use super::{classify_error, is_service_not_running};

    /// A mapper that names `call` and carries its HRESULT into [`classify_error`].
    fn call_error(call: &'static str) -> impl FnOnce(Error) -> SourceError {
        move |error| classify_error(call, error.code().0)
    }

    pub(super) fn read() -> Result<AntivirusList, SourceError> {
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

    fn read_list() -> Result<AntivirusList, SourceError> {
        // SAFETY: COM is initialised on this thread, and the class and interface are Windows' own.
        let created = unsafe { CoCreateInstance(&WSCProductList, None, CLSCTX_INPROC_SERVER) };
        let list: IWSCProductList = match created {
            Ok(list) => list,
            Err(error) if is_service_not_running(error.code().0) => {
                return Ok(AntivirusList::ServiceNotRunning);
            }
            Err(error) => {
                return Err(classify_error(
                    "CoCreateInstance(WSCProductList)",
                    error.code().0,
                ));
            }
        };
        // SAFETY: `list` is a live WSC product list; `Initialize` only selects which provider type to
        // enumerate and changes nothing on the machine.
        let initialized = unsafe { list.Initialize(WSC_SECURITY_PROVIDER_ANTIVIRUS) };
        if let Err(error) = initialized {
            if is_service_not_running(error.code().0) {
                return Ok(AntivirusList::ServiceNotRunning);
            }
            return Err(classify_error(
                "IWSCProductList::Initialize",
                error.code().0,
            ));
        }
        // SAFETY: `list` is initialised for the antivirus provider and is live for this call.
        let counted = unsafe { list.Count() };
        let count = match counted {
            Ok(count) => count,
            Err(error) if is_service_not_running(error.code().0) => {
                return Ok(AntivirusList::ServiceNotRunning);
            }
            Err(error) => return Err(classify_error("IWSCProductList::Count", error.code().0)),
        };
        let count = u32::try_from(count)
            .map_err(|_| SourceError::Failed(format!("IWSCProductList::Count returned {count}")))?;
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
            let remediation_path = remediated
                .map_err(call_error("RemediationPath"))?
                .to_string();
            products.push(AntivirusProductRecord {
                display_name,
                state,
                remediation_path,
            });
        }
        Ok(AntivirusList::Products(products))
    }
}

#[cfg(test)]
mod tests {
    use rongroi_host::SourceError;

    use super::{classify_error, is_service_not_running};

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

    /// `ERROR_SERVICE_NOT_ACTIVE` is not a failure to report as `read_failed`: it is the service
    /// that answers not running, which may change by itself (ADR 0090).
    #[test]
    fn service_not_active_is_its_own_answer_not_a_failure() {
        assert!(is_service_not_running(0x8007_0426_u32.cast_signed()));
        assert!(!is_service_not_running(0x8007_0005_u32.cast_signed()));
    }
}
