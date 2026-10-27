// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later

/// Read the program name and the hash out of a Prefetch file name such as `APP.EXE-0BADF00D.pf`.
///
/// Returns `None` unless `file` is a bare file name (no `\` or `/`) ending in `.pf` (any ASCII case).
/// The stem is split at its last `-`; the part after it must be exactly 8 ASCII hex digits and the
/// part before it must be non-empty. The name is returned as written.
pub fn parse_prefetch_name(file: &str) -> Option<(String, u32)> {
    todo!()
}
