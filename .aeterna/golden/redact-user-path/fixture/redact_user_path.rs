// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later

/// Replace the user name in a Windows user-profile path with `<user>`.
///
/// Only a path that starts with a drive letter, `:\`, `Users`, `\` and a non-empty name is changed.
/// The name runs to the next `\` or to the end of the path. Every other path is returned unchanged.
pub fn redact_user_path(path: &str) -> String {
    todo!()
}
