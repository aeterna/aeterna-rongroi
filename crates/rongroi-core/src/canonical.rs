// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! RFC 8785 (JSON Canonicalization Scheme) and the record hashes ADR 0089 builds on it: the
//! `visual_hash` staff compare on screen and the `policy_hash` a pairing code carries.

use std::cmp::Ordering;
use std::fmt::Write as _;

use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Why a value could not be canonicalised.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CanonicalError {
    /// A number had no exact integer form: it held a fraction, or did not fit `i64`/`u64`.
    #[error("a record number must be an integer that fits i64 or u64")]
    NonInteger,
}

/// The RFC 8785 serialization of `value`.
///
/// Object keys are ordered by UTF-16 code units, not by their UTF-8 bytes: an astral character's
/// first surrogate (`U+D83D`) sorts before a BMP character such as `U+E000`, though its code point
/// and UTF-8 bytes sort after. Strings escape only `"`, `\` and `U+0000`–`U+001F`; every other
/// character, ASCII or not, is written as UTF-8. Numbers must be integers: the record model holds
/// none of the floats RFC 8785's number rule would cover (ADR 0089 §2).
///
/// # Errors
///
/// [`CanonicalError::NonInteger`] when a number is not an integer, or does not fit `i64`/`u64`.
pub fn canonical_json(value: &Value) -> Result<String, CanonicalError> {
    let mut out = String::new();
    write_value(value, &mut out)?;
    Ok(out)
}

fn write_value(value: &Value, out: &mut String) -> Result<(), CanonicalError> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(number) => write_number(number, out)?,
        Value::String(text) => write_string(text, out),
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_value(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => write_object(map, out)?,
    }
    Ok(())
}

fn write_object(map: &Map<String, Value>, out: &mut String) -> Result<(), CanonicalError> {
    let mut entries: Vec<_> = map.iter().collect();
    entries.sort_unstable_by(|&(left, _), &(right, _)| utf16_order(left, right));
    out.push('{');
    for (index, (key, value)) in entries.into_iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        write_string(key, out);
        out.push(':');
        write_value(value, out)?;
    }
    out.push('}');
    Ok(())
}

fn utf16_order(left: &str, right: &str) -> Ordering {
    left.encode_utf16().cmp(right.encode_utf16())
}

fn write_string(text: &str, out: &mut String) {
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{0c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn write_number(number: &Number, out: &mut String) -> Result<(), CanonicalError> {
    if number.is_i64() || number.is_u64() {
        out.push_str(&number.to_string());
        return Ok(());
    }
    if let Some(float) = number.as_f64() {
        return write_integral_float(float, out);
    }
    Err(CanonicalError::NonInteger)
}

// The range check before each cast is what makes it exact: neither cast can truncate or change sign.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::float_cmp
)]
fn write_integral_float(float: f64, out: &mut String) -> Result<(), CanonicalError> {
    let two_63 = 2f64.powi(63);
    let two_64 = 2f64.powi(64);
    if float.fract() != 0.0 {
        return Err(CanonicalError::NonInteger);
    }
    if (0.0..two_64).contains(&float) {
        let _ = write!(out, "{}", float as u64);
    } else if (-two_63..0.0).contains(&float) {
        let _ = write!(out, "{}", float as i64);
    } else {
        return Err(CanonicalError::NonInteger);
    }
    Ok(())
}

/// The first 8 bytes of `SHA-256(canonical_json(record without its top-level visual_hash))`, as 16
/// lowercase hex characters (ADR 0089 §2).
///
/// # Errors
///
/// [`CanonicalError::NonInteger`] as [`canonical_json`].
pub fn visual_hash(record: &Value) -> Result<String, CanonicalError> {
    hash_without(record, "visual_hash")
}

/// The first 8 bytes of `SHA-256(canonical_json(policy without its top-level policy_hash))`, as 16
/// lowercase hex characters (ADR 0089 §5).
///
/// # Errors
///
/// [`CanonicalError::NonInteger`] as [`canonical_json`].
pub fn policy_hash(policy: &Value) -> Result<String, CanonicalError> {
    hash_without(policy, "policy_hash")
}

fn hash_without(value: &Value, member: &str) -> Result<String, CanonicalError> {
    let mut copy = value.clone();
    if let Value::Object(map) = &mut copy {
        let _ = map.remove(member);
    }
    let canonical = canonical_json(&copy)?;
    Ok(first_eight_hex(&canonical))
}

fn first_eight_hex(text: &str) -> String {
    let digest = Sha256::digest(text.as_bytes());
    let mut out = String::with_capacity(16);
    for byte in digest.iter().take(8) {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The canonical form of `tests/data/visual-hash-v1.json` without its `visual_hash` member.
    const FIXTURE_CANONICAL: &str = r#"{"binding":{"expires_at":"2026-10-31T14:35:00Z","issued_at":"2026-10-31T14:30:00Z","nonce":"c4b82e91024a","server_origin":"http://203.0.113.10:30130","ticket":"9f82c4e1b07a412891d604e38a291bf0"},"case_code":"7K9M-2X4P","kind":"rongroi-saved-report","official_build":true,"policy":{"policy_hash":"a1b2c3d4e5f60718","profile":"posture","require_elevation":true,"required_collectors":["posture","os_image","install_marker","defender_exclusion","net_config","driver_service"],"server_name":"Example City"},"producer":{"mode":"single-shot","name":"rongroi-connect","version":"0.1.0"},"rongroi_version":"0.14.0","schema":2,"view":{"generated_at":"2026-10-31T14:30:00Z","schema_version":2}}"#;

    /// The `policy_hash` the fixture carries, as the literals this vector is checked against.
    const FIXTURE_POLICY_HASH: &str = "a1b2c3d4e5f60718";

    /// The `visual_hash` the fixture carries, as the literals this vector is checked against.
    const FIXTURE_VISUAL_HASH: &str = "4f8a91bc023e5d71";

    fn first_eight_hex_by_hand(text: &str) -> String {
        use sha2::{Digest, Sha256};
        use std::fmt::Write as _;
        let digest = Sha256::digest(text.as_bytes());
        let mut out = String::with_capacity(16);
        for byte in digest.iter().take(8) {
            let _ = write!(out, "{byte:02x}");
        }
        out
    }

    #[test]
    fn object_keys_sort_by_utf16_code_units() {
        let mut object = serde_json::Map::new();
        let _ = object.insert("\u{e000}".to_owned(), json!("bmp"));
        let _ = object.insert("\u{1f600}".to_owned(), json!("astral"));
        let _ = object.insert("a".to_owned(), json!("ascii"));
        let value = Value::Object(object);
        assert_eq!(
            canonical_json(&value).unwrap(),
            "{\"a\":\"ascii\",\"\u{1f600}\":\"astral\",\"\u{e000}\":\"bmp\"}"
        );
    }

    #[test]
    fn strings_escape_only_what_jcs_escapes() {
        let text =
            "\"\\\u{0000}\u{0001}\u{0008}\u{0009}\u{000a}\u{000c}\u{000d}\u{001f}\u{007f}\u{e000}";
        let expected = "\"\\\"\\\\\\u0000\\u0001\\b\\t\\n\\f\\r\\u001f\u{007f}\u{e000}\"";
        assert_eq!(
            canonical_json(&Value::String(text.to_owned())).unwrap(),
            expected
        );
    }

    #[test]
    fn arrays_and_objects_nest_without_whitespace() {
        let value = json!({"z": [1, {"b": true, "a": null}], "a": {"list": [false, "x"]}});
        assert_eq!(
            canonical_json(&value).unwrap(),
            r#"{"a":{"list":[false,"x"]},"z":[1,{"a":null,"b":true}]}"#
        );
    }

    #[test]
    fn integer_edges_are_emitted_exactly() {
        let value = Value::Array(vec![
            Value::from(0i64),
            Value::from(-1i64),
            Value::from(i64::MIN),
            Value::from(i64::MAX),
            Value::from(u64::MAX),
        ]);
        assert_eq!(
            canonical_json(&value).unwrap(),
            "[0,-1,-9223372036854775808,9223372036854775807,18446744073709551615]"
        );
    }

    #[test]
    fn a_fractional_number_is_refused() {
        assert_eq!(canonical_json(&json!(1.5)), Err(CanonicalError::NonInteger));
        assert_eq!(
            canonical_json(&json!(1e300)),
            Err(CanonicalError::NonInteger)
        );
        assert_eq!(canonical_json(&json!(1.0)).unwrap(), "1");
    }

    #[test]
    fn visual_hash_ignores_the_member_it_lives_in() {
        let record = json!({"kind": "rongroi-saved-report", "schema": 2});
        let mut with = record.clone();
        let map = with.as_object_mut().unwrap();
        let _ = map.insert("visual_hash".to_owned(), json!("ffffffffffffffff"));
        assert_eq!(visual_hash(&record).unwrap(), visual_hash(&with).unwrap());
        let hash = visual_hash(&record).unwrap();
        assert_eq!(hash.len(), 16);
        assert!(
            hash.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
    }

    #[test]
    fn a_changed_field_changes_the_visual_hash() {
        let original = json!({"kind": "rongroi-saved-report", "schema": 2});
        let mut changed = original.clone();
        changed["schema"] = json!(3);
        assert_ne!(
            visual_hash(&original).unwrap(),
            visual_hash(&changed).unwrap()
        );
    }

    #[test]
    fn policy_hash_ignores_the_member_it_lives_in() {
        let policy = json!({"profile": "posture", "policy_hash": "a1b2c3d4e5f60718"});
        let mut without = policy.clone();
        let _ = without.as_object_mut().unwrap().remove("policy_hash");
        assert_eq!(
            policy_hash(&policy).unwrap(),
            policy_hash(&without).unwrap()
        );
    }

    #[test]
    fn the_fixed_record_pins_its_canonical_form_and_exact_hash() {
        let fixture = include_str!("../tests/data/visual-hash-v1.json");
        let record: Value = serde_json::from_str(fixture).unwrap();
        // The literals the cross-language vector carries, checked before anything recomputes them.
        assert_eq!(
            record["policy"]["policy_hash"].as_str(),
            Some(FIXTURE_POLICY_HASH)
        );
        assert_eq!(record["visual_hash"].as_str(), Some(FIXTURE_VISUAL_HASH));
        let mut without = record.clone();
        let _ = without.as_object_mut().unwrap().remove("visual_hash");
        assert_eq!(canonical_json(&without).unwrap(), FIXTURE_CANONICAL);
        assert_eq!(
            first_eight_hex_by_hand(FIXTURE_CANONICAL),
            visual_hash(&record).unwrap()
        );
    }
}
