// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! Reads directories, file hashes and environment variables from the real machine.
//!
//! Everything here opens for reading only: nothing is written, renamed, deleted or locked, and no
//! timestamp is changed (AGENTS.md hard rule 2). No `unsafe` is needed — `std::fs` is enough.

use rongroi_host::{DirEntryInfo, EnvironmentSource, FilesystemSource, SourceError};

use crate::LiveHost;

impl FilesystemSource for LiveHost {
    fn list_dir(&self, dir: &str) -> Result<Option<Vec<DirEntryInfo>>, SourceError> {
        let entries = match std::fs::read_dir(dir) {
            Ok(entries) => entries,
            // The folder is not there. That is a fact about this machine, not a failure to look, so
            // the collector can report "measured, nothing in it" rather than "unmeasured".
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(SourceError::from_io(&error)),
        };

        let mut listed = Vec::new();
        for entry in entries {
            // One unreadable entry fails the whole listing on purpose: a partial list that looked
            // complete would be read as "nothing else was there".
            let entry = entry.map_err(|error| SourceError::from_io(&error))?;
            listed.push(DirEntryInfo {
                // `file_type` does not follow reparse points, so a link to a directory is not a file.
                // An entry whose type cannot be read is reported as not-a-file: the collector only
                // observes what it could confirm is a file.
                is_file: entry.file_type().is_ok_and(|kind| kind.is_file()),
                // A name that is not valid Unicode is kept in lossy form. It is still shown to the
                // reviewer; hashing it will fail and the observation then carries only the path.
                name: entry.file_name().to_string_lossy().into_owned(),
            });
        }
        Ok(Some(listed))
    }

    fn file_sha256(&self, path: &str) -> Result<String, SourceError> {
        rongroi_host::sha256_file(std::path::Path::new(path))
            .map_err(|error| SourceError::from_io(&error))
    }
}

impl EnvironmentSource for LiveHost {
    fn env_var(&self, name: &str) -> Option<String> {
        std::env::var(name).ok()
    }
}
