// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! Windows `FILETIME` to UTC timestamp, in one place.
//!
//! A `FILETIME` counts 100-nanosecond intervals since 1601-01-01T00:00:00Z. Several artifacts in M2
//! store one — BAM stores it directly, and Prefetch and Amcache carry it too — so the epoch offset
//! and the 100-nanosecond unit are written down once, here, and tested once, rather than being
//! rediscovered by each parser and each caller (ADR 0013).
//!
//! Nothing in this module reads the clock or a time zone: it is arithmetic on a number.

use jiff::Timestamp;

/// 100-nanosecond intervals from the `FILETIME` epoch (1601-01-01T00:00:00Z) to the Unix epoch
/// (1970-01-01T00:00:00Z): 11 644 473 600 seconds, in units of 100 ns.
const UNIX_EPOCH_AS_FILETIME: i128 = 116_444_736_000_000_000;

/// Converts a Windows `FILETIME` to a UTC timestamp.
///
/// `None` means the value does not name an instant this program can represent — a `FILETIME` runs to
/// the year 60056, far past the year 9999 where [`jiff::Timestamp`] stops. That happens with a
/// corrupt or hostile value rather than with a real one, and it is reported as "no timestamp" rather
/// than as a wrong instant. `None` never means "the artifact had no value here": a value of zero is
/// the 1601 epoch and converts like any other.
///
/// Keep the raw `u64` beside the result wherever one is stored, so that a value this cannot
/// represent is still visible to whoever reads the artifact next.
pub fn to_timestamp(filetime: u64) -> Option<Timestamp> {
    // i128 throughout: a u64 FILETIME multiplied by 100 exceeds u64 and i64, and this must not
    // overflow on any input, including a deliberately absurd one.
    let ticks_since_unix_epoch = i128::from(filetime) - UNIX_EPOCH_AS_FILETIME;
    let nanoseconds = ticks_since_unix_epoch.checked_mul(100)?;
    // The range is checked here rather than left to `Timestamp::from_nanosecond`. That function
    // returns a `Result`, but on a value past its range it panics in a debug build before it can
    // return one: a `FILETIME` of u64::MAX trips `assertion failed:
    // UnixEpochSeconds::checkc(secs).is_ok()` inside jiff-core (observed, jiff 0.2.35 — the test
    // below is what found it). This crate promises never to panic on any input, so nothing out of
    // range is handed over. The bounds come from jiff's own constants, so a jiff upgrade that moves
    // them moves this with it.
    let earliest = Timestamp::MIN.as_nanosecond();
    let latest = Timestamp::MAX.as_nanosecond();
    if nanoseconds < earliest || nanoseconds > latest {
        return None;
    }
    Timestamp::from_nanosecond(nanoseconds).ok()
}

#[cfg(test)]
mod tests {
    use super::to_timestamp;

    /// The value Windows writes when it means 1601-01-01, and the value it writes when a field was
    /// never filled in, are the same bytes. Converting it must produce that instant rather than
    /// `None`: deciding what a zero means is the collector's judgement, and it cannot make it if the
    /// parser has already thrown the value away.
    #[test]
    fn zero_is_the_filetime_epoch_not_a_missing_value() {
        assert_eq!(
            to_timestamp(0).map(|time| time.to_string()),
            Some("1601-01-01T00:00:00Z".to_owned())
        );
    }

    #[test]
    fn the_unix_epoch_offset_is_right() {
        assert_eq!(
            to_timestamp(116_444_736_000_000_000).map(|time| time.to_string()),
            Some("1970-01-01T00:00:00Z".to_owned())
        );
    }

    #[test]
    fn a_known_instant_round_trips() {
        // 2020-01-01T00:00:00Z = unix 1_577_836_800 s; + 11_644_473_600 s of epoch offset, in 100 ns.
        assert_eq!(
            to_timestamp(132_223_104_000_000_000).map(|time| time.to_string()),
            Some("2020-01-01T00:00:00Z".to_owned())
        );
    }

    #[test]
    fn the_hundred_nanosecond_unit_is_not_rounded_away() {
        assert_eq!(
            to_timestamp(116_444_736_000_000_001).map(jiff::Timestamp::as_nanosecond),
            Some(100)
        );
    }

    #[test]
    fn a_value_beyond_the_representable_range_is_none_rather_than_a_wrong_instant() {
        assert_eq!(to_timestamp(u64::MAX), None);
    }

    /// Garbage in a registry value is a normal input here. Nothing may abort on it.
    #[test]
    fn extreme_values_return_an_answer_instead_of_panicking() {
        for filetime in [
            0,
            1,
            u64::MAX,
            u64::MAX - 1,
            u64::MAX / 2,
            i64::MAX as u64,
            1 << 63,
        ] {
            let _ = to_timestamp(filetime);
        }
    }
}
