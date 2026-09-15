// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! The NTFS change journal of one volume, read through the two read-only control codes and nothing
//! else (ADR 0047).
//!
//! The volume is opened with `GENERIC_READ` alone. Microsoft's own example asks for write access too;
//! ADR 0047 measured on a GitHub-hosted runner that both reads succeed without it, and a handle that
//! cannot write is the collector's promise kept by the operating system as well as by this code.
//! `DeviceIoControl` carries the codes that create and delete a journal as well as the two that read
//! one, so `clippy.toml` bans it everywhere and this module calls it in one function that accepts only
//! the two read codes. `CreateFileW` is banned the same way and called in one function that accepts
//! only `GENERIC_READ` or `FILE_READ_ATTRIBUTES`.

use rongroi_host::UsnJournalState;

/// `ERROR_ACCESS_DENIED`.
pub const ERROR_ACCESS_DENIED: u32 = 5;
/// `ERROR_FILE_NOT_FOUND`.
pub const ERROR_FILE_NOT_FOUND: u32 = 2;
/// `ERROR_PATH_NOT_FOUND`.
pub const ERROR_PATH_NOT_FOUND: u32 = 3;
/// `ERROR_JOURNAL_DELETE_IN_PROGRESS`: a journal is being deleted and cannot be read.
pub const ERROR_JOURNAL_DELETE_IN_PROGRESS: u32 = 1178;
/// `ERROR_JOURNAL_NOT_ACTIVE`: the volume has no journal. Measured on a runner's `D:` (ADR 0047).
pub const ERROR_JOURNAL_NOT_ACTIVE: u32 = 1179;
/// `ERROR_JOURNAL_ENTRY_DELETED`: the records asked for were trimmed away.
pub const ERROR_JOURNAL_ENTRY_DELETED: u32 = 1181;

/// Bytes `FSCTL_QUERY_USN_JOURNAL` is given to write into: `USN_JOURNAL_DATA_V2`'s size.
pub const QUERY_OUTPUT_LEN: usize = 80;
/// `USN_JOURNAL_DATA_V0`'s size: the fields this module reads all lie inside it.
pub const QUERY_V0_LEN: usize = 56;
/// `READ_USN_JOURNAL_DATA_V1`'s size, 48 bytes with its trailing padding; accepted on the runner
/// (ADR 0047).
pub const READ_INPUT_LEN: usize = 48;
/// Bytes one `FSCTL_READ_USN_JOURNAL` call may return: 1 MiB, as measured.
pub const READ_OUTPUT_LEN: usize = 1 << 20;

/// What a failed call means to a reader of the journal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    /// The volume has no journal.
    NotActive,
    /// The call was refused.
    AccessDenied,
    /// The journal was trimmed past the read, or is being deleted.
    JournalChanged,
    /// Anything else.
    Failed,
}

/// Classifies a Win32 error code from a journal call.
pub fn classify(win32_error: u32) -> Failure {
    match win32_error {
        ERROR_JOURNAL_NOT_ACTIVE => Failure::NotActive,
        ERROR_ACCESS_DENIED => Failure::AccessDenied,
        ERROR_JOURNAL_ENTRY_DELETED | ERROR_JOURNAL_DELETE_IN_PROGRESS => Failure::JournalChanged,
        _ => Failure::Failed,
    }
}

/// The journal identifier and state from the bytes `FSCTL_QUERY_USN_JOURNAL` returned, or `None` when
/// it returned fewer than `USN_JOURNAL_DATA_V0` holds. Offsets from Microsoft's structure:
/// `UsnJournalID` 0, `FirstUsn` 8, `NextUsn` 16, `LowestValidUsn` 24, `MaxUsn` 32, `MaximumSize` 40.
pub fn journal_state(bytes: &[u8]) -> Option<(u64, UsnJournalState)> {
    let bytes = bytes.get(..QUERY_V0_LEN)?;
    let u64_at = |at: usize| {
        bytes
            .get(at..at + 8)
            .and_then(|b| <[u8; 8]>::try_from(b).ok())
            .map(u64::from_le_bytes)
    };
    let i64_at = |at: usize| {
        bytes
            .get(at..at + 8)
            .and_then(|b| <[u8; 8]>::try_from(b).ok())
            .map(i64::from_le_bytes)
    };
    Some((
        u64_at(0)?,
        UsnJournalState {
            first_usn: i64_at(8)?,
            next_usn: i64_at(16)?,
            lowest_valid_usn: i64_at(24)?,
            maximum_size: u64_at(40)?,
        },
    ))
}

/// The input for one `FSCTL_READ_USN_JOURNAL` call: `READ_USN_JOURNAL_DATA_V1` with `StartUsn`, every
/// reason, no waiting (`ReturnOnlyOnClose`, `Timeout` and `BytesToWaitFor` all zero), the journal
/// identifier, and major versions 2 to 3 — version 4 records are written only with range tracking on
/// and carry no time.
pub fn read_input(start_usn: i64, journal_id: u64) -> [u8; READ_INPUT_LEN] {
    let mut input = [0u8; READ_INPUT_LEN];
    input[0..8].copy_from_slice(&start_usn.to_le_bytes());
    input[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
    input[32..40].copy_from_slice(&journal_id.to_le_bytes());
    input[40..42].copy_from_slice(&2u16.to_le_bytes());
    input[42..44].copy_from_slice(&3u16.to_le_bytes());
    input
}

#[cfg(windows)]
mod live {
    use std::ops::ControlFlow;

    use rongroi_host::{FileId, SourceError, UsnJournalRead, UsnReadEnd};
    use windows::Win32::Foundation::{CloseHandle, E_INVALIDARG, GENERIC_READ, HANDLE};
    use windows::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, CreateFileW, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAGS_AND_ATTRIBUTES, FILE_ID_INFO, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
        FILE_SHARE_MODE, FILE_SHARE_READ, FILE_SHARE_WRITE, FileIdInfo, GetFileInformationByHandle,
        GetFileInformationByHandleEx, OPEN_EXISTING,
    };
    use windows::Win32::System::IO::DeviceIoControl;
    use windows::Win32::System::Ioctl::{FSCTL_QUERY_USN_JOURNAL, FSCTL_READ_USN_JOURNAL};
    use windows::core::PCWSTR;

    use super::{
        ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, Failure, QUERY_OUTPUT_LEN,
        READ_OUTPUT_LEN, classify, journal_state, read_input,
    };

    /// A handle this module opened, closed when dropped.
    struct OwnedHandle(HANDLE);

    impl Drop for OwnedHandle {
        #[allow(unsafe_code)]
        fn drop(&mut self) {
            // SAFETY: the handle came from a successful `CreateFileW` in this module and is closed
            // exactly once, here. Closing a handle changes nothing on the volume.
            unsafe { CloseHandle(self.0) }.ok();
        }
    }

    /// The only control codes this program sends to a volume. Both read (ADR 0047).
    #[derive(Debug, Clone, Copy)]
    enum ReadOnlyControl {
        QueryUsnJournal,
        ReadUsnJournal,
    }

    impl ReadOnlyControl {
        fn code(self) -> u32 {
            match self {
                Self::QueryUsnJournal => FSCTL_QUERY_USN_JOURNAL,
                Self::ReadUsnJournal => FSCTL_READ_USN_JOURNAL,
            }
        }
    }

    /// Every `DeviceIoControl` call in this program. `clippy.toml` bans the function everywhere else,
    /// because the same function creates and deletes change journals; this one can only send the two
    /// codes [`ReadOnlyControl`] names (ADR 0047).
    #[allow(unsafe_code, clippy::disallowed_methods)]
    fn control(
        handle: &OwnedHandle,
        control: ReadOnlyControl,
        input: &[u8],
        output: &mut [u8],
    ) -> windows::core::Result<usize> {
        let (Ok(input_len), Ok(output_len)) =
            (u32::try_from(input.len()), u32::try_from(output.len()))
        else {
            return Err(windows::core::Error::from_hresult(E_INVALIDARG));
        };
        let mut returned = 0u32;
        // SAFETY: `handle` is open. `input` and `output` are live slices and their exact lengths are
        // passed, so the call reads and writes only inside them. `returned` outlives the call. There is
        // no OVERLAPPED, so the call completes before it returns. `control` is one of the two read codes.
        unsafe {
            DeviceIoControl(
                handle.0,
                control.code(),
                (!input.is_empty()).then_some(input.as_ptr().cast()),
                input_len,
                Some(output.as_mut_ptr().cast()),
                output_len,
                Some(&raw mut returned),
                None,
            )
        }?;
        Ok(usize::try_from(returned).unwrap_or(0))
    }

    /// The only access this program asks `CreateFileW` for. Neither can write (ADR 0047).
    #[derive(Debug, Clone, Copy)]
    enum ReadOnlyAccess {
        /// `GENERIC_READ`, for the volume handle the two control codes are sent to.
        VolumeRead,
        /// `FILE_READ_ATTRIBUTES`, for a folder whose identifiers are read.
        AttributesOnly,
    }

    impl ReadOnlyAccess {
        fn mask(self) -> u32 {
            match self {
                Self::VolumeRead => GENERIC_READ.0,
                Self::AttributesOnly => FILE_READ_ATTRIBUTES.0,
            }
        }
    }

    /// Every `CreateFileW` call in this program. `clippy.toml` bans the function everywhere else,
    /// because the same function opens for writing and creates files; this one opens an existing path
    /// with one of the two masks [`ReadOnlyAccess`] names (ADR 0047).
    #[allow(unsafe_code, clippy::disallowed_methods)]
    fn open(
        path: &str,
        access: ReadOnlyAccess,
        share: FILE_SHARE_MODE,
        flags: FILE_FLAGS_AND_ATTRIBUTES,
    ) -> windows::core::Result<OwnedHandle> {
        let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
        // SAFETY: `wide` is NUL-terminated UTF-16 that outlives the call. No security attributes and no
        // template. `OPEN_EXISTING` never creates, and `access` is `GENERIC_READ` or
        // `FILE_READ_ATTRIBUTES`, neither of which can write.
        let handle = unsafe {
            CreateFileW(
                PCWSTR(wide.as_ptr()),
                access.mask(),
                share,
                None,
                OPEN_EXISTING,
                flags,
                None,
            )
        }?;
        Ok(OwnedHandle(handle))
    }

    fn win32(error: &windows::core::Error) -> Option<u32> {
        crate::event_log::win32_code(error.code().0.cast_unsigned())
    }

    fn failed(error: &windows::core::Error, call: &str) -> SourceError {
        SourceError::Failed(format!(
            "{call} returned {:#010x}",
            error.code().0.cast_unsigned()
        ))
    }

    impl rongroi_host::UsnJournalSource for crate::LiveHost {
        fn read_usn_journal(
            &self,
            volume: char,
            visit: &mut dyn FnMut(&[u8]) -> ControlFlow<()>,
        ) -> Result<Option<UsnJournalRead>, SourceError> {
            if !volume.is_ascii_alphabetic() {
                return Err(SourceError::Unsupported(format!(
                    "`{volume}` is not a drive letter"
                )));
            }
            let handle = open(
                &format!(r"\\.\{volume}:"),
                ReadOnlyAccess::VolumeRead,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                FILE_FLAGS_AND_ATTRIBUTES(0),
            )
            .map_err(|error| match win32(&error) {
                Some(ERROR_ACCESS_DENIED) => SourceError::AccessDenied,
                _ => failed(&error, "CreateFileW on the volume"),
            })?;

            let mut query = [0u8; QUERY_OUTPUT_LEN];
            let returned = match control(&handle, ReadOnlyControl::QueryUsnJournal, &[], &mut query)
            {
                Ok(returned) => returned,
                Err(error) => {
                    return match win32(&error).map(classify) {
                        Some(Failure::NotActive) => Ok(None),
                        Some(Failure::AccessDenied) => Err(SourceError::AccessDenied),
                        _ => Err(failed(&error, "FSCTL_QUERY_USN_JOURNAL")),
                    };
                }
            };
            let Some((journal_id, state)) =
                journal_state(query.get(..returned).unwrap_or_default())
            else {
                return Err(SourceError::Failed(
                    "FSCTL_QUERY_USN_JOURNAL returned fewer bytes than USN_JOURNAL_DATA_V0"
                        .to_owned(),
                ));
            };

            let mut output = vec![0u8; READ_OUTPUT_LEN];
            let mut start = state.first_usn;
            while start < state.next_usn {
                let input = read_input(start, journal_id);
                let returned = match control(
                    &handle,
                    ReadOnlyControl::ReadUsnJournal,
                    &input,
                    &mut output,
                ) {
                    Ok(returned) => returned,
                    Err(error) => {
                        return match win32(&error).map(classify) {
                            Some(Failure::JournalChanged | Failure::NotActive) => {
                                Ok(Some(UsnJournalRead {
                                    state,
                                    end: UsnReadEnd::JournalChanged,
                                }))
                            }
                            Some(Failure::AccessDenied) => Err(SourceError::AccessDenied),
                            _ => Err(failed(&error, "FSCTL_READ_USN_JOURNAL")),
                        };
                    }
                };
                let bytes = output.get(..returned).unwrap_or_default();
                let Some(next) = bytes
                    .first_chunk::<8>()
                    .map(|next| i64::from_le_bytes(*next))
                else {
                    return Err(SourceError::Failed(
                        "FSCTL_READ_USN_JOURNAL returned fewer than eight bytes".to_owned(),
                    ));
                };
                if bytes.len() > 8 && visit(bytes).is_break() {
                    return Ok(Some(UsnJournalRead {
                        state,
                        end: UsnReadEnd::Stopped,
                    }));
                }
                // A read that does not move the start forward is a failure, not `Complete`: `Complete`
                // means every buffer up to `next_usn` was handed to the visitor, and a call that makes
                // no progress leaves the rest of that promise unread. Returning here, rather than
                // looping again on the same `start`, is also what keeps this loop finite.
                if next <= start {
                    return Err(SourceError::Failed(
                        "FSCTL_READ_USN_JOURNAL did not move past the USN it was asked to start from"
                            .to_owned(),
                    ));
                }
                start = next;
            }
            Ok(Some(UsnJournalRead {
                state,
                end: UsnReadEnd::Complete,
            }))
        }

        #[allow(unsafe_code)]
        fn file_id(&self, path: &str) -> Result<Option<FileId>, SourceError> {
            let handle = match open(
                path,
                ReadOnlyAccess::AttributesOnly,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                FILE_FLAG_BACKUP_SEMANTICS,
            ) {
                Ok(handle) => handle,
                Err(error) => {
                    return match win32(&error) {
                        Some(ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND) => Ok(None),
                        Some(ERROR_ACCESS_DENIED) => Err(SourceError::AccessDenied),
                        _ => Err(failed(&error, "CreateFileW on a folder")),
                    };
                }
            };
            let mut info = BY_HANDLE_FILE_INFORMATION::default();
            // SAFETY: `handle` is open and `info` is a live `BY_HANDLE_FILE_INFORMATION` the call fills.
            unsafe { GetFileInformationByHandle(handle.0, &raw mut info) }
                .map_err(|error| failed(&error, "GetFileInformationByHandle"))?;
            let mut id = FILE_ID_INFO::default();
            let size = u32::try_from(std::mem::size_of::<FILE_ID_INFO>()).unwrap_or(0);
            // SAFETY: `id` is a live `FILE_ID_INFO` and `size` is exactly its size, which is what
            // `FileIdInfo` fills.
            unsafe {
                GetFileInformationByHandleEx(handle.0, FileIdInfo, (&raw mut id).cast(), size)
            }
            .map_err(|error| failed(&error, "GetFileInformationByHandleEx(FileIdInfo)"))?;
            Ok(Some(FileId {
                id_128: id.FileId.Identifier,
                index_64: (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
                volume_serial: id.VolumeSerialNumber,
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_journal_errors_mean_what_the_collector_reports() {
        assert_eq!(classify(ERROR_JOURNAL_NOT_ACTIVE), Failure::NotActive);
        assert_eq!(classify(ERROR_ACCESS_DENIED), Failure::AccessDenied);
        assert_eq!(
            classify(ERROR_JOURNAL_ENTRY_DELETED),
            Failure::JournalChanged
        );
        assert_eq!(
            classify(ERROR_JOURNAL_DELETE_IN_PROGRESS),
            Failure::JournalChanged
        );
        assert_eq!(classify(87), Failure::Failed);
    }

    #[test]
    fn a_query_result_is_read_at_the_documented_offsets() {
        // Every field a distinct non-zero value, so a read one offset off answers with a neighbour's.
        const JOURNAL_ID: u64 = 0xDEAD;
        const FIRST_USN: i64 = 4096;
        const NEXT_USN: i64 = 9000;
        const LOWEST_VALID_USN: i64 = 1024;
        const MAX_USN: i64 = 0x7FFF_FFFF_FFFF_0000;
        const MAXIMUM_SIZE: u64 = 33_554_432;
        const ALLOCATION_DELTA: u64 = 8_388_608;
        let mut bytes = [0u8; 80];
        bytes[0..8].copy_from_slice(&JOURNAL_ID.to_le_bytes());
        bytes[8..16].copy_from_slice(&FIRST_USN.to_le_bytes());
        bytes[16..24].copy_from_slice(&NEXT_USN.to_le_bytes());
        bytes[24..32].copy_from_slice(&LOWEST_VALID_USN.to_le_bytes());
        bytes[32..40].copy_from_slice(&MAX_USN.to_le_bytes());
        bytes[40..48].copy_from_slice(&MAXIMUM_SIZE.to_le_bytes());
        bytes[48..56].copy_from_slice(&ALLOCATION_DELTA.to_le_bytes());

        let (journal_id, state) = journal_state(&bytes).unwrap();
        assert_eq!(journal_id, JOURNAL_ID);
        assert_eq!(state.first_usn, FIRST_USN);
        assert_eq!(state.next_usn, NEXT_USN);
        assert_eq!(state.lowest_valid_usn, LOWEST_VALID_USN);
        assert_eq!(state.maximum_size, MAXIMUM_SIZE);
        // `MaxUsn` at 32 is not kept: no field may answer with it.
        assert!(
            [state.first_usn, state.next_usn, state.lowest_valid_usn]
                .iter()
                .all(|usn| *usn != MAX_USN)
        );
        assert_ne!(state.maximum_size, MAX_USN.cast_unsigned());
        assert_eq!(journal_state(&bytes[..55]), None);
    }

    #[test]
    fn a_read_asks_for_every_reason_from_the_start_in_versions_2_to_3() {
        let input = read_input(4096, 0xDEAD);
        assert_eq!(&input[0..8], &4096i64.to_le_bytes());
        assert_eq!(&input[8..12], &[0xFF; 4]);
        assert_eq!(&input[12..32], &[0; 20]);
        assert_eq!(&input[32..40], &0xDEAD_u64.to_le_bytes());
        assert_eq!(&input[40..44], &[2, 0, 3, 0]);
        assert_eq!(&input[44..48], &[0; 4]);
    }

    /// Run by the Windows CI job (ADR 0047): the runner is elevated and its `C:` has a journal. What is
    /// asserted is the measured shape, and nothing is printed of what the journal holds.
    #[cfg(windows)]
    #[test]
    #[ignore = "reads this machine's change journal; run by the Windows CI job"]
    fn live_usn_the_system_volume_journal_reads_and_a_folder_identifier_matches_its_records() {
        use rongroi_host::{UsnJournalSource as _, UsnReadEnd};

        let host = crate::LiveHost;
        let system_root = std::env::var("SystemRoot").unwrap();
        let volume = system_root.chars().next().unwrap();
        let logs = host
            .file_id(&format!(r"{system_root}\System32\winevt\Logs"))
            .unwrap()
            .unwrap();
        // The drive root answers with the same volume the Logs folder is on: both are read from the
        // system volume, so a caller comparing `FileId`s never mistakes one volume for another.
        let root = host.file_id(&format!(r"{volume}:\")).unwrap().unwrap();
        assert_eq!(root.volume_serial, logs.volume_serial);

        let mut buffers = 0usize;
        let mut matched = 0usize;
        let read = host
            .read_usn_journal(volume, &mut |bytes| {
                buffers += 1;
                let parsed = rongroi_parsers::usn::parse_buffer(bytes).unwrap();
                assert_eq!(parsed.damage, None);
                matched += parsed
                    .records
                    .iter()
                    .filter(|record| match record.parent {
                        rongroi_parsers::usn::ParentReference::Id128(id) => id == logs.id_128,
                        rongroi_parsers::usn::ParentReference::Index64(index) => {
                            index == logs.index_64
                        }
                    })
                    .count();
                std::ops::ControlFlow::Continue(())
            })
            .unwrap()
            .unwrap();
        println!(
            "usn: end {:?} · buffers {buffers} · records under winevt\\Logs {matched}",
            read.end
        );
        assert_eq!(read.end, UsnReadEnd::Complete);
        assert!(buffers > 0);
        assert!(
            matched > 0,
            "the Event Log service writes to its folder continuously"
        );
    }
}
