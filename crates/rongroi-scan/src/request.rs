// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! Validation of the one JSON line Connect writes to the sidecar.

use std::collections::BTreeSet;

use rongroi_collectors::ScanTier;
use rongroi_core::view::{Binding, Policy, Producer, ProducerMode, ProducerName, Profile};
use serde::Deserialize;
use serde_json::{Map, Value};
use thiserror::Error;

/// The largest line, in bytes, that [`parse_request`] accepts.
pub const MAX_LINE_BYTES: usize = 16 * 1024;

/// A request from Connect, validated for the sidecar.
#[derive(Debug)]
pub struct Request {
    /// How the record is tied to the case the Server Kit opened.
    pub binding: Binding,
    /// The policy the scan runs under.
    pub policy: Policy,
    /// Which program produced the request and how it ran.
    pub producer: Producer,
}

/// Why a line cannot be accepted as a request from Connect.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RequestError {
    /// The line is longer than [`MAX_LINE_BYTES`].
    #[error("request line is too long")]
    LineTooLong,
    /// The line contains a carriage return or a line feed.
    #[error("request line contains a line break")]
    LineBreak,
    /// The line is not UTF-8 text.
    #[error("request line is not valid UTF-8")]
    NotUtf8,
    /// The line is not valid JSON.
    #[error("request line is not valid JSON")]
    InvalidJson,
    /// The top-level JSON value is not an object.
    #[error("request JSON is not an object")]
    NotJsonObject,
    /// The top-level object does not have exactly `binding`, `policy` and `producer`.
    #[error("request must have exactly binding, policy and producer")]
    TopLevelMembers,
    /// The binding object does not have the required members and only the allowed ones.
    #[error("binding does not have the required members")]
    BindingMembers,
    /// The policy object does not have exactly the required members.
    #[error("policy does not have exactly the required members")]
    PolicyMembers,
    /// The producer object does not have exactly the required members.
    #[error("producer does not have exactly the required members")]
    ProducerMembers,
    /// A member has a JSON type the request does not allow.
    #[error("request member has a wrong JSON type")]
    MemberShape,
    /// The ticket is not 32 lowercase hexadecimal characters.
    #[error("ticket is not 32 lowercase hexadecimal characters")]
    Ticket,
    /// The nonce is not 1 to 128 printable ASCII characters.
    #[error("nonce is not 1 to 128 printable ASCII characters")]
    Nonce,
    /// An `issued_at` or `expires_at` value is not a timestamp of at most 40 characters.
    #[error("binding timestamp is not a valid timestamp")]
    Timestamp,
    /// The server origin is not an allowed HTTP(S) origin.
    #[error("server origin is not an allowed HTTP(S) origin")]
    ServerOrigin,
    /// The policy profile is not `posture`, `standard` or `custom`.
    #[error("policy profile is not posture, standard or custom")]
    Profile,
    /// The policy server name is empty, too long or contains a control character.
    #[error("policy server name is empty, too long or has a control character")]
    ServerName,
    /// The policy hash is not 16 lowercase hexadecimal characters matching the policy.
    #[error("policy hash is not 16 lowercase hexadecimal characters matching the policy")]
    PolicyHash,
    /// The received policy could not be hashed.
    #[error("policy could not be hashed")]
    PolicyHashCalculation,
    /// The required collector list is empty, too long, unknown or repeated.
    #[error("required collectors are empty, too long, unknown or repeated")]
    RequiredCollectors,
    /// A required collector is only read in a full scan, and the sidecar only runs standard scans.
    #[error("required collector is only read in a full scan")]
    FullTierCollector,
    /// The producer name is not `rongroi-connect`.
    #[error("producer name is not rongroi-connect")]
    ProducerName,
    /// The producer version is not 1 to 32 allowed characters.
    #[error("producer version is not 1 to 32 allowed characters")]
    ProducerVersion,
    /// The producer mode is not `single-shot`.
    #[error("producer mode is not single-shot")]
    ProducerMode,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    binding: InputBinding,
    policy: InputPolicy,
    producer: InputProducer,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InputBinding {
    ticket: String,
    nonce: String,
    server_origin: Option<String>,
    issued_at: Option<String>,
    expires_at: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InputPolicy {
    profile: String,
    required_collectors: Vec<String>,
    require_elevation: bool,
    server_name: String,
    policy_hash: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InputProducer {
    name: String,
    version: String,
    mode: String,
}

/// Parses and validates the one JSON line Connect sends.
///
/// The line is one line without its trailing newline.
///
/// # Errors
///
/// Returns a [`RequestError`] naming the rule that refused the line.
pub fn parse_request(line: &[u8]) -> Result<Request, RequestError> {
    if line.len() > MAX_LINE_BYTES {
        return Err(RequestError::LineTooLong);
    }
    if line.iter().any(|byte| matches!(byte, b'\n' | b'\r')) {
        return Err(RequestError::LineBreak);
    }
    let text = std::str::from_utf8(line).map_err(|_| RequestError::NotUtf8)?;
    let value: Value = serde_json::from_str(text).map_err(|_| RequestError::InvalidJson)?;
    let object = value.as_object().ok_or(RequestError::NotJsonObject)?;

    if !has_exact_members(object, &["binding", "policy", "producer"]) {
        return Err(RequestError::TopLevelMembers);
    }
    let binding = object
        .get("binding")
        .and_then(Value::as_object)
        .ok_or(RequestError::BindingMembers)?;
    if !has_allowed_members(
        binding,
        &[
            "ticket",
            "nonce",
            "server_origin",
            "issued_at",
            "expires_at",
        ],
        &["ticket", "nonce"],
    ) {
        return Err(RequestError::BindingMembers);
    }
    let policy_value = object
        .get("policy")
        .cloned()
        .ok_or(RequestError::PolicyMembers)?;
    let policy = policy_value
        .as_object()
        .ok_or(RequestError::PolicyMembers)?;
    if !has_exact_members(
        policy,
        &[
            "profile",
            "required_collectors",
            "require_elevation",
            "server_name",
            "policy_hash",
        ],
    ) {
        return Err(RequestError::PolicyMembers);
    }
    let producer = object
        .get("producer")
        .and_then(Value::as_object)
        .ok_or(RequestError::ProducerMembers)?;
    if !has_exact_members(producer, &["name", "version", "mode"]) {
        return Err(RequestError::ProducerMembers);
    }

    let input: Input = serde_json::from_value(value).map_err(|_| RequestError::MemberShape)?;
    let binding = validate_binding(input.binding)?;
    let policy = validate_policy(input.policy, &policy_value)?;
    let producer = validate_producer(input.producer)?;
    Ok(Request {
        binding,
        policy,
        producer,
    })
}

/// Every collector id in this build, sorted.
pub fn known_collector_ids() -> Vec<&'static str> {
    let mut ids: Vec<&'static str> = rongroi_collectors::all()
        .iter()
        .map(|collector| collector.id())
        .collect();
    ids.sort_unstable();
    ids
}

fn has_exact_members(map: &Map<String, Value>, names: &[&str]) -> bool {
    map.len() == names.len() && names.iter().all(|name| map.contains_key(*name))
}

fn has_allowed_members(map: &Map<String, Value>, allowed: &[&str], required: &[&str]) -> bool {
    map.keys().all(|key| allowed.contains(&key.as_str()))
        && required.iter().all(|key| map.contains_key(*key))
}

fn validate_binding(input: InputBinding) -> Result<Binding, RequestError> {
    if !is_lower_hex(&input.ticket, 32) {
        return Err(RequestError::Ticket);
    }
    if !is_nonce(&input.nonce) {
        return Err(RequestError::Nonce);
    }
    validate_timestamp(input.issued_at.as_deref())?;
    validate_timestamp(input.expires_at.as_deref())?;
    if input
        .server_origin
        .as_deref()
        .is_some_and(|origin| !is_server_origin(origin))
    {
        return Err(RequestError::ServerOrigin);
    }
    Ok(Binding {
        server_origin: input.server_origin,
        ticket: input.ticket,
        nonce: input.nonce,
        issued_at: input.issued_at,
        expires_at: input.expires_at,
    })
}

fn validate_policy(input: InputPolicy, policy_value: &Value) -> Result<Policy, RequestError> {
    let profile = match input.profile.as_str() {
        "posture" => Profile::Posture,
        "standard" => Profile::Standard,
        "custom" => Profile::Custom,
        _ => return Err(RequestError::Profile),
    };
    if !is_server_name(&input.server_name) {
        return Err(RequestError::ServerName);
    }
    if !is_lower_hex(&input.policy_hash, 16) {
        return Err(RequestError::PolicyHash);
    }
    let expected = rongroi_core::canonical::policy_hash(policy_value)
        .map_err(|_| RequestError::PolicyHashCalculation)?;
    if input.policy_hash != expected {
        return Err(RequestError::PolicyHash);
    }
    validate_collectors(&input.required_collectors)?;
    Ok(Policy {
        profile,
        required_collectors: input.required_collectors,
        require_elevation: input.require_elevation,
        server_name: input.server_name,
        policy_hash: input.policy_hash,
    })
}

fn validate_producer(input: InputProducer) -> Result<Producer, RequestError> {
    if input.name != "rongroi-connect" {
        return Err(RequestError::ProducerName);
    }
    if !is_producer_version(&input.version) {
        return Err(RequestError::ProducerVersion);
    }
    let mode = match input.mode.as_str() {
        "single-shot" => ProducerMode::SingleShot,
        _ => return Err(RequestError::ProducerMode),
    };
    Ok(Producer {
        name: ProducerName::RongroiConnect,
        version: input.version,
        mode,
    })
}

/// Whether `text` is exactly `len` lowercase hexadecimal characters.
fn is_lower_hex(text: &str, len: usize) -> bool {
    text.chars().count() == len
        && text
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// Whether `text` is 1 to 128 bytes from the printable ASCII range.
fn is_nonce(text: &str) -> bool {
    (1..=128).contains(&text.chars().count())
        && text.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
}

/// Whether `value` is an absent timestamp or one of at most 40 characters that parses.
fn validate_timestamp(value: Option<&str>) -> Result<(), RequestError> {
    match value {
        Some(text) if text.chars().count() > 40 || text.parse::<jiff::Timestamp>().is_err() => {
            Err(RequestError::Timestamp)
        }
        _ => Ok(()),
    }
}

/// Whether `origin` is an HTTP(S) origin with no path, query, fragment or user information.
fn is_server_origin(origin: &str) -> bool {
    let Some(rest) = origin
        .strip_prefix("http://")
        .or_else(|| origin.strip_prefix("https://"))
    else {
        return false;
    };
    (1..=255).contains(&origin.chars().count())
        && !rest.is_empty()
        && !rest.chars().any(|character| {
            matches!(character, '/' | '?' | '#' | '@' | '\\')
                || character.is_whitespace()
                || character.is_control()
        })
}

/// Whether `name` is 1 to 128 characters with no control character.
fn is_server_name(name: &str) -> bool {
    (1..=128).contains(&name.chars().count()) && !name.chars().any(char::is_control)
}

/// Whether `ids` is 1 to 64 known collector ids with no repetition.
fn validate_collectors(ids: &[String]) -> Result<(), RequestError> {
    if !(1..=64).contains(&ids.len()) {
        return Err(RequestError::RequiredCollectors);
    }
    let known = known_collector_ids();
    let mut seen = BTreeSet::new();
    for id in ids {
        if !known.contains(&id.as_str()) || !seen.insert(id.as_str()) {
            return Err(RequestError::RequiredCollectors);
        }
    }
    let full: BTreeSet<&str> = rongroi_collectors::all()
        .iter()
        .filter(|collector| collector.tier() == ScanTier::Full)
        .map(|collector| collector.id())
        .collect();
    if ids.iter().any(|id| full.contains(id.as_str())) {
        return Err(RequestError::FullTierCollector);
    }
    Ok(())
}

/// Whether `version` is 1 to 32 characters from the producer version alphabet.
fn is_producer_version(version: &str) -> bool {
    (1..=32).contains(&version.chars().count())
        && version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'+' | b'-'))
}

#[cfg(test)]
mod tests;
