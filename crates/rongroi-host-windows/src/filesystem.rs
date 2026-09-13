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

    fn read_file(&self, path: &str) -> Result<Option<Vec<u8>>, SourceError> {
        // Opened for reading only, like every other read here: no truncation flag, no write share
        // request, no timestamp changed (AGENTS.md hard rule 2).
        let file = match std::fs::File::open(path) {
            Ok(file) => file,
            // The file is not there — the same fact `list_dir` reports for a folder. A Prefetch entry
            // that Windows replaced between the listing and the read lands here.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(SourceError::from_io(&error)),
        };
        // The limit lives in `rongroi-host`, so this host refuses exactly what the fixture host does.
        rongroi_host::read_bounded(std::io::BufReader::new(file), rongroi_host::MAX_FILE_BYTES)
            .map(Some)
    }

    /// `symlink_metadata`, not `metadata`: the attribute of the directory entry the collector listed,
    /// never of whatever a link points at. On Windows the standard library opens the entry with no
    /// read or write access and every share mode, and falls back to the directory listing when even
    /// that is refused, so asking neither reads the file's contents nor stands in the way of the
    /// service writing it (ADR 0037).
    fn is_read_only(&self, path: &str) -> Result<Option<bool>, SourceError> {
        match std::fs::symlink_metadata(path) {
            Ok(metadata) => Ok(Some(metadata.permissions().readonly())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(SourceError::from_io(&error)),
        }
    }
}

impl EnvironmentSource for LiveHost {
    fn env_var(&self, name: &str) -> Option<String> {
        std::env::var(name).ok()
    }
}

#[cfg(test)]
mod tests {
    use rongroi_host::FilesystemSource;

    use crate::LiveHost;

    /// Both answers on a real file system, and a file that is not there. The test sets the attribute
    /// on a file it created in its own temporary folder, never on anything a scan reads.
    #[test]
    fn the_read_only_attribute_is_read_from_the_file_system() {
        let dir = std::env::temp_dir().join(format!("rongroi-read-only-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let clear = dir.join("clear.txt");
        let set = dir.join("set.txt");
        std::fs::write(&clear, b"x").unwrap();
        std::fs::write(&set, b"x").unwrap();
        let mut permissions = std::fs::metadata(&set).unwrap().permissions();
        permissions.set_readonly(true);
        std::fs::set_permissions(&set, permissions).unwrap();

        let answer = |path: &std::path::Path| LiveHost.is_read_only(path.to_str().unwrap());
        assert_eq!(answer(&clear), Ok(Some(false)));
        assert_eq!(answer(&set), Ok(Some(true)));
        assert_eq!(answer(&dir.join("absent.txt")), Ok(None));

        let mut permissions = std::fs::metadata(&set).unwrap().permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        permissions.set_readonly(false);
        std::fs::set_permissions(&set, permissions).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
