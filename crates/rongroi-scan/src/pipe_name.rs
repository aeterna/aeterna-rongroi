// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! Validation of the named-pipe name that Connect creates for the sidecar.

use thiserror::Error;

/// The fixed prefix Connect puts before the random token in its pipe name.
pub const PIPE_PREFIX: &str = r"\\.\pipe\rongroi-";

/// Number of lowercase hexadecimal characters the token after the prefix must have.
const TOKEN_LEN: usize = 32;

/// Why a name cannot be a pipe name created by Connect.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PipeNameError {
    /// The name does not begin with [`PIPE_PREFIX`] in exactly that case.
    #[error("pipe name does not have the expected prefix")]
    Prefix,
    /// The part after the prefix is not exactly 32 characters long.
    #[error("pipe name token is not 32 characters long")]
    Length,
    /// The part after the prefix contains a character outside 0-9 and a-f.
    #[error("pipe name token is not lowercase hexadecimal ASCII")]
    NotLowerHex,
}

/// Checks that `name` is [`PIPE_PREFIX`] followed by exactly 32 lowercase hexadecimal ASCII
/// characters and nothing else.
///
/// # Errors
///
/// Returns [`PipeNameError::Prefix`] when the prefix is missing or differs in case,
/// [`PipeNameError::Length`] when the token has the wrong number of characters, and
/// [`PipeNameError::NotLowerHex`] when a token character is not `0`-`9` or `a`-`f`.
pub fn validate(name: &str) -> Result<(), PipeNameError> {
    let token = name.strip_prefix(PIPE_PREFIX).ok_or(PipeNameError::Prefix)?;
    if token.chars().count() != TOKEN_LEN {
        return Err(PipeNameError::Length);
    }
    if !token
        .bytes()
        .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(PipeNameError::NotLowerHex);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_token(token: &str) -> String {
        let mut name = String::from(PIPE_PREFIX);
        name.push_str(token);
        name
    }

    #[test]
    fn accepts_prefix_and_32_lower_hex() {
        let token = "0123456789abcdef0123456789abcdef";
        assert_eq!(validate(&with_token(token)), Ok(()));
    }

    #[test]
    fn rejects_uppercase_hex() {
        let token = "0123456789ABCDEF0123456789ABCDEF";
        assert_eq!(
            validate(&with_token(token)),
            Err(PipeNameError::NotLowerHex)
        );
    }

    #[test]
    fn rejects_31_hex_characters() {
        assert_eq!(
            validate(&with_token(&"0".repeat(31))),
            Err(PipeNameError::Length)
        );
    }

    #[test]
    fn rejects_33_hex_characters() {
        assert_eq!(
            validate(&with_token(&"0".repeat(33))),
            Err(PipeNameError::Length)
        );
    }

    #[test]
    fn rejects_unc_server_prefix() {
        let prefix = r"\\server\pipe\rongroi-";
        assert_eq!(
            validate(&format!("{prefix}{}", "0".repeat(32))),
            Err(PipeNameError::Prefix)
        );
    }

    #[test]
    fn rejects_forward_slash_path() {
        let prefix = "//./pipe/rongroi-";
        assert_eq!(
            validate(&format!("{prefix}{}", "0".repeat(32))),
            Err(PipeNameError::Prefix)
        );
    }

    #[test]
    fn rejects_uppercase_prefix() {
        let prefix = r"\\.\PIPE\rongroi-";
        assert_eq!(
            validate(&format!("{prefix}{}", "0".repeat(32))),
            Err(PipeNameError::Prefix)
        );
    }

    #[test]
    fn rejects_trailing_backslash_x() {
        let token = "0123456789abcdef0123456789abcdef\\x";
        assert_eq!(validate(&with_token(token)), Err(PipeNameError::Length));
    }

    #[test]
    fn rejects_trailing_newline() {
        let token = "0123456789abcdef0123456789abcdef\n";
        assert_eq!(validate(&with_token(token)), Err(PipeNameError::Length));
    }

    #[test]
    fn rejects_nul_in_token() {
        let token = "0123456789abcdef\u{0}123456789abcdef";
        assert_eq!(
            validate(&with_token(token)),
            Err(PipeNameError::NotLowerHex)
        );
    }

    #[test]
    fn rejects_thai_digits() {
        assert_eq!(
            validate(&with_token(&"\u{0E50}".repeat(32))),
            Err(PipeNameError::NotLowerHex)
        );
    }

    #[test]
    fn rejects_empty_name() {
        assert_eq!(validate(""), Err(PipeNameError::Prefix));
    }
}
