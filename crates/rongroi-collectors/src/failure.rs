// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! How a collector reports a source it could not read.
//!
//! Two vocabularies, both of which every collector that reads a file has to use the same way:
//! [`reason_for`] picks the `UnmeasuredReason` a failure puts in `gaps`, and [`read_failure`] picks
//! the value of the `read` field on the observation that says so in the report.
//!
//! They live here rather than in one collector because two collectors saying the same thing in two
//! wordings is two things a rule author has to learn. `pca` wrote both first (ADR 0020) and
//! `prefetch` uses them unchanged (ADR 0021).

use rongroi_core::model::UnmeasuredReason;
use rongroi_host::{Host, SourceError};

/// How a failed source read is reported in `gaps`.
///
/// Denial is split by whether this program could have used administrator rights, which is what makes
/// the CLI's and the app's restart-as-administrator offer worth taking (ADR 0012). A collector calls
/// this *after* attempting the read, never instead of attempting it, so a machine where the artifact
/// happens to be readable without those rights is read.
pub fn reason_for(host: &dyn Host, error: &SourceError) -> UnmeasuredReason {
    match error {
        SourceError::AccessDenied if host.is_elevated() == Some(false) => {
            UnmeasuredReason::NotAdmin
        }
        SourceError::AccessDenied => UnmeasuredReason::AccessDenied,
        SourceError::Unsupported(_) | SourceError::Failed(_) | SourceError::TooLarge { .. } => {
            UnmeasuredReason::ReadFailed
        }
    }
}

/// Value of the `read` field for a source whose bytes never arrived.
///
/// Deliberately finer than the [`UnmeasuredReason`] the same failure puts in `gaps`: "Windows would
/// not let me read it", "it is larger than this program reads" and "the read failed" are different
/// things to a reviewer, and an artifact this program could not read is what an evader would arrange.
pub fn read_failure(error: &SourceError) -> &'static str {
    match error {
        SourceError::AccessDenied => "access_denied",
        SourceError::TooLarge { .. } => "too_large",
        SourceError::Unsupported(_) | SourceError::Failed(_) => "failed",
    }
}

#[cfg(test)]
mod tests {
    use rongroi_host::FixtureHost;

    use super::*;

    fn host(elevated: &str) -> FixtureHost {
        FixtureHost::from_yaml_str(
            &format!("platform: windows\nelevated: {elevated}\n"),
            "inline",
        )
        .unwrap()
    }

    /// The pair that makes the restart-as-administrator offer worth taking: denied, and this program
    /// did not have the rights it could have asked for.
    #[test]
    fn denial_without_admin_rights_is_not_admin() {
        assert_eq!(
            reason_for(&host("false"), &SourceError::AccessDenied),
            UnmeasuredReason::NotAdmin
        );
    }

    /// Denied with the rights already held is a different fact, and restarting would not help.
    #[test]
    fn denial_with_admin_rights_is_access_denied() {
        assert_eq!(
            reason_for(&host("true"), &SourceError::AccessDenied),
            UnmeasuredReason::AccessDenied
        );
    }

    /// A host that cannot say whether it is elevated has not said it is not, so the honest answer is
    /// the one that does not blame a missing token.
    #[test]
    fn denial_on_a_host_that_cannot_say_is_access_denied() {
        let host = FixtureHost::from_yaml_str("platform: windows\n", "inline").unwrap();
        assert_eq!(
            reason_for(&host, &SourceError::AccessDenied),
            UnmeasuredReason::AccessDenied
        );
    }

    #[test]
    fn everything_else_is_read_failed() {
        for error in [
            SourceError::Failed("disk".to_owned()),
            SourceError::Unsupported("no file system".to_owned()),
            SourceError::TooLarge { limit: 1 },
        ] {
            assert_eq!(
                reason_for(&host("false"), &error),
                UnmeasuredReason::ReadFailed,
                "{error:?}"
            );
        }
    }

    #[test]
    fn the_read_field_names_the_three_ways_bytes_do_not_arrive() {
        assert_eq!(read_failure(&SourceError::AccessDenied), "access_denied");
        assert_eq!(
            read_failure(&SourceError::TooLarge { limit: 1 }),
            "too_large"
        );
        assert_eq!(
            read_failure(&SourceError::Failed("io".to_owned())),
            "failed"
        );
        assert_eq!(
            read_failure(&SourceError::Unsupported("none".to_owned())),
            "failed"
        );
    }
}
