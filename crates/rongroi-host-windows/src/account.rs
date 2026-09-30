// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! The account this program runs as, as a SID, so a collector can tell whether a scheduled task runs
//! as the same account (ADR 0060). It is compared and never reported.

/// Writes a SID's parts in the `S-R-I-S…` form `ConvertSidToStringSidW` documents: the identifier
/// authority in decimal when it fits in 32 bits, and as `0x` followed by twelve hex digits otherwise.
pub fn sid_text(revision: u8, authority: [u8; 6], sub_authorities: &[u32]) -> String {
    use std::fmt::Write as _;

    let mut text = if authority[..2] == [0, 0] {
        let low = [authority[2], authority[3], authority[4], authority[5]];
        format!("S-{revision}-{}", u32::from_be_bytes(low))
    } else {
        let mut hex = format!("S-{revision}-0x");
        for byte in authority {
            let _ = write!(hex, "{byte:02X}");
        }
        hex
    };
    for sub_authority in sub_authorities {
        let _ = write!(text, "-{sub_authority}");
    }
    text
}

#[cfg(windows)]
impl rongroi_host::AccountSource for crate::LiveHost {
    /// `GetTokenInformation(TokenUser)` on this process's token, opened with `TOKEN_QUERY` only. The
    /// SID is read field by field with `GetSidIdentifierAuthority`, `GetSidSubAuthorityCount` and
    /// `GetSidSubAuthority` rather than `ConvertSidToStringSidW`, which would need a feature of the
    /// `windows` crate this program does not otherwise use and a `LocalFree` of its result.
    #[allow(unsafe_code)]
    fn account_sid(&self) -> Result<String, rongroi_host::SourceError> {
        use rongroi_host::SourceError;
        use windows::Win32::Foundation::{CloseHandle, HANDLE};
        use windows::Win32::Security::{
            GetSidIdentifierAuthority, GetSidSubAuthority, GetSidSubAuthorityCount,
            GetTokenInformation, IsValidSid, TOKEN_QUERY, TOKEN_USER, TokenUser,
        };
        use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

        let mut token = HANDLE::default();
        // SAFETY: `GetCurrentProcess` returns a pseudo-handle for this process, and `token` is a valid
        // out-pointer. Query access only: nothing about the token can be changed through it.
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) }
            .map_err(|error| SourceError::Failed(format!("OpenProcessToken failed: {error}")))?;
        // u64 words keep the pointer in TOKEN_USER aligned. A TOKEN_USER and the largest SID
        // (68 bytes) fit in far less than 1 KiB.
        let mut buffer = vec![0_u64; 128];
        let mut needed = 0_u32;
        let bytes = u32::try_from(buffer.len() * 8).unwrap_or(0);
        // SAFETY: `token` is open with TOKEN_QUERY, and `buffer` is `bytes` writable bytes that
        // outlive the call; `needed` is a valid out-pointer.
        let result = unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                Some(buffer.as_mut_ptr().cast()),
                bytes,
                &raw mut needed,
            )
        };
        // SAFETY: `token` was opened above and is closed once.
        let _ = unsafe { CloseHandle(token) };
        result.map_err(|error| {
            SourceError::Failed(format!("GetTokenInformation(TokenUser) failed: {error}"))
        })?;
        // SAFETY: `GetTokenInformation` succeeded, so the buffer begins with a TOKEN_USER whose SID
        // pointer points into the same buffer, which lives until the end of this function.
        let sid = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() }.User.Sid;
        // SAFETY: `sid` points into `buffer`, as above.
        if !unsafe { IsValidSid(sid) }.as_bool() {
            return Err(SourceError::Failed(
                "the token's user SID is not valid".to_owned(),
            ));
        }
        // SAFETY: `sid` is valid, so these return pointers into it, read at once.
        let authority = unsafe { *GetSidIdentifierAuthority(sid) }.Value;
        // SAFETY: as above.
        let count = unsafe { *GetSidSubAuthorityCount(sid) };
        let sub_authorities: Vec<u32> = (0..u32::from(count))
            // SAFETY: `index` is below the count the SID itself states.
            .map(|index| unsafe { *GetSidSubAuthority(sid, index) })
            .collect();
        // The revision is the SID's first byte; every SID Windows issues is revision 1.
        // SAFETY: a valid SID is at least eight bytes long.
        let revision = unsafe { *sid.0.cast::<u8>() };
        Ok(sid_text(revision, authority, &sub_authorities))
    }
}

#[cfg(test)]
mod tests {
    use super::sid_text;

    /// Run by the Windows CI job: the account a runner's job runs as has a SID of the `S-1-5-`
    /// family, and the read needs no right the job lacks.
    #[cfg(windows)]
    #[test]
    fn the_live_account_sid_is_read() {
        use rongroi_host::AccountSource as _;

        let sid = crate::LiveHost.account_sid().unwrap();
        assert!(sid.starts_with("S-1-5-"), "{sid}");
    }

    #[test]
    fn a_sid_is_written_as_windows_writes_it() {
        assert_eq!(sid_text(1, [0, 0, 0, 0, 0, 5], &[18]), "S-1-5-18");
        assert_eq!(
            sid_text(1, [0, 0, 0, 0, 0, 5], &[21, 1, 2, 3, 1001]),
            "S-1-5-21-1-2-3-1001"
        );
        assert_eq!(
            sid_text(1, [0, 0, 0x12, 0x34, 0x56, 0x78], &[]),
            "S-1-305419896"
        );
        assert_eq!(
            sid_text(1, [1, 2, 3, 4, 5, 6], &[7]),
            "S-1-0x010203040506-7"
        );
    }
}
