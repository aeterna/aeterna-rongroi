// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! One scheduled task's file under `%SystemRoot%\System32\Tasks`: the XML the Task Scheduler writes
//! (ADR 0060).
//!
//! Of the document this module keeps five things: whether `Settings/Enabled` says the task is on, the
//! kind of each trigger under `Triggers`, each `Exec` action's `Command`, how many `ComHandler`
//! actions there are, and the user id of the principal the actions run as. **`Arguments`,
//! `WorkingDirectory`, `Author`, `Description` and every other element are never read into a
//! value**: arguments are where a token, a password or an address passed to a program at start lives
//! (ADR 0060, section 4), and the parser is where that is enforced — nothing it returns can carry them.
//! The principal's user id is returned so a collector can tell whether the task runs as the account
//! scanning, and the collector never reports it.
//!
//! The encoding is taken from a byte-order mark — UTF-16 little- or big-endian, or UTF-8 — or, without
//! one, from whether the first two bytes are `<` and a zero byte in either order; anything else is
//! read as UTF-8. The encoding the Task Scheduler writes was not recorded by ADR 0060's probe, so
//! every one of those is accepted and any other bytes are a `Malformed` error rather than a guess.
//! The XML itself is read with `quick-xml`, which never fetches an external entity or a DTD.

use quick_xml::events::{BytesStart, Event};
use quick_xml::{Reader, XmlVersion};

use crate::error::ParseError;

/// The deepest element nesting accepted. A task file nests five levels at most; the bound keeps a
/// hostile file from growing the element stack without limit.
const MAX_DEPTH: usize = 64;

/// What one kind of trigger is called in a report. The names are the Task Scheduler schema's trigger
/// elements (`BootTrigger`, `LogonTrigger`, …), written the way this program writes a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TriggerKind {
    /// `BootTrigger`: when the system starts.
    Boot,
    /// `CalendarTrigger`: on a daily, weekly or monthly schedule.
    Calendar,
    /// `EventTrigger`: when an event is logged.
    Event,
    /// `IdleTrigger`: when the computer is idle.
    Idle,
    /// `LogonTrigger`: when a user signs in.
    Logon,
    /// `RegistrationTrigger`: when the task is registered or changed.
    Registration,
    /// `SessionStateChangeTrigger`: on a session connecting, disconnecting, locking or unlocking.
    SessionChange,
    /// `TimeTrigger`: at one time.
    Time,
    /// `WnfStateChangeTrigger`: on a Windows Notification Facility state change.
    Wnf,
    /// Any other element under `Triggers`.
    Other,
}

impl TriggerKind {
    /// The value a report carries for this kind.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Boot => "boot",
            Self::Calendar => "calendar",
            Self::Event => "event",
            Self::Idle => "idle",
            Self::Logon => "logon",
            Self::Registration => "registration",
            Self::SessionChange => "session_change",
            Self::Time => "time",
            Self::Wnf => "wnf",
            Self::Other => "other",
        }
    }

    fn from_element(name: &str) -> Self {
        match name {
            "BootTrigger" => Self::Boot,
            "CalendarTrigger" => Self::Calendar,
            "EventTrigger" => Self::Event,
            "IdleTrigger" => Self::Idle,
            "LogonTrigger" => Self::Logon,
            "RegistrationTrigger" => Self::Registration,
            "SessionStateChangeTrigger" => Self::SessionChange,
            "TimeTrigger" => Self::Time,
            "WnfStateChangeTrigger" => Self::Wnf,
            _ => Self::Other,
        }
    }
}

/// What one task file says, of what ADR 0060 reads.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Task {
    /// `Settings/Enabled`, or `None` when the element is absent — which the Task Scheduler schema
    /// reads as `true`; deciding that is the collector's.
    pub enabled: Option<bool>,
    /// The kind of each element under `Triggers`, in document order, repeats included.
    pub triggers: Vec<TriggerKind>,
    /// Each `Exec` action's `Command`, in document order, exactly as written once XML escapes are
    /// resolved. `None` for an `Exec` with no `Command`.
    pub exec_commands: Vec<Option<String>>,
    /// How many `ComHandler` actions the task has. A handler names a COM class, not a file.
    pub com_handlers: usize,
    /// `UserId` of the principal the actions run as: the one whose `id` the `Actions` element's
    /// `Context` names, or the first principal when there is no `Context` or nothing matches it.
    /// Returned for comparison only; never report it.
    pub principal_user_id: Option<String>,
}

/// Where the reader is, as far as this parser cares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Capture {
    Enabled,
    Command,
    UserId,
}

/// Parses one task file.
pub fn parse_task(bytes: &[u8]) -> Result<Task, ParseError> {
    let text = decode(bytes)?;
    parse_text(&text)
}

/// The file's text, from the encoding its first bytes name.
fn decode(bytes: &[u8]) -> Result<String, ParseError> {
    match bytes {
        [0xFF, 0xFE, rest @ ..] => utf16(rest, u16::from_le_bytes),
        [0xFE, 0xFF, rest @ ..] => utf16(rest, u16::from_be_bytes),
        [0xEF, 0xBB, 0xBF, rest @ ..] => utf8(rest),
        [b'<', 0, ..] => utf16(bytes, u16::from_le_bytes),
        [0, b'<', ..] => utf16(bytes, u16::from_be_bytes),
        _ => utf8(bytes),
    }
}

fn utf8(bytes: &[u8]) -> Result<String, ParseError> {
    String::from_utf8(bytes.to_vec()).map_err(|_| ParseError::Malformed {
        field: "encoding",
        detail: "not valid UTF-8".to_owned(),
    })
}

fn utf16(bytes: &[u8], unit: fn([u8; 2]) -> u16) -> Result<String, ParseError> {
    let (pairs, rest) = bytes.as_chunks::<2>();
    if !rest.is_empty() {
        return Err(ParseError::Malformed {
            field: "encoding",
            detail: "UTF-16 with an odd number of bytes".to_owned(),
        });
    }
    char::decode_utf16(pairs.iter().map(|pair| unit(*pair)))
        .collect::<Result<String, _>>()
        .map_err(|_| ParseError::Malformed {
            field: "encoding",
            detail: "UTF-16 with an unpaired surrogate".to_owned(),
        })
}

fn malformed(detail: impl Into<String>) -> ParseError {
    ParseError::Malformed {
        field: "xml",
        detail: detail.into(),
    }
}

/// Reads the elements this module keeps, by their local names (the Task Scheduler's namespace is not
/// checked: every element it names is under one), and nothing else.
fn parse_text(text: &str) -> Result<Task, ParseError> {
    let mut reader = Reader::from_str(text);
    let mut stack: Vec<String> = Vec::new();
    let mut task = Task::default();
    let mut capture: Option<(Capture, String)> = None;
    let mut actions_context: Option<String> = None;
    let mut principals: Vec<(Option<String>, Option<String>)> = Vec::new();
    let mut root_seen = false;

    loop {
        let event = reader
            .read_event()
            .map_err(|error| malformed(format!("not well-formed XML: {error}")))?;
        match event {
            Event::Start(start) => {
                let name = start.local_name().as_ref().to_owned();
                open(
                    &mut task,
                    &stack,
                    &name,
                    &start,
                    &mut actions_context,
                    &mut principals,
                    &mut root_seen,
                )?;
                capture = capture_for(&stack, &name).map(|what| (what, String::new()));
                stack.push(name);
                if stack.len() > MAX_DEPTH {
                    return Err(malformed("elements nested too deeply"));
                }
            }
            Event::Empty(start) => {
                let name = start.local_name().as_ref().to_owned();
                open(
                    &mut task,
                    &stack,
                    &name,
                    &start,
                    &mut actions_context,
                    &mut principals,
                    &mut root_seen,
                )?;
                // An empty element holds no text: an empty `Command` is an empty command.
                if let Some(what) = capture_for(&stack, &name) {
                    store(&mut task, &mut principals, what, String::new())?;
                }
            }
            Event::End(_) => {
                if let Some((what, value)) = capture.take() {
                    store(&mut task, &mut principals, what, value)?;
                }
                stack.pop();
            }
            Event::Text(content) => {
                if let Some((_, value)) = capture.as_mut() {
                    value.push_str(&content.xml10_content());
                }
            }
            Event::CData(content) => {
                if let Some((_, value)) = capture.as_mut() {
                    value.push_str(&content.into_inner());
                }
            }
            Event::GeneralRef(reference) => {
                if let Some((_, value)) = capture.as_mut() {
                    value.push(resolve_reference(&reference)?);
                }
            }
            Event::Eof => break,
            Event::Comment(_) | Event::Decl(_) | Event::PI(_) | Event::DocType(_) => {}
        }
        // Text is only captured directly inside the element being read; a child element ends it.
        if let Some((_, _)) = &capture
            && !matches!(
                stack.last().map(String::as_str),
                Some("Enabled" | "Command" | "UserId")
            )
        {
            capture = None;
        }
    }
    if !stack.is_empty() {
        return Err(malformed("the document ends inside an element"));
    }
    if !root_seen {
        return Err(malformed("no Task element at the root"));
    }
    task.principal_user_id = chosen_principal(principals, actions_context.as_deref());
    Ok(task)
}

/// Which captured value the element `name`, opened inside `stack`, holds.
fn capture_for(stack: &[String], name: &str) -> Option<Capture> {
    let path: Vec<&str> = stack.iter().map(String::as_str).collect();
    match (path.as_slice(), name) {
        (["Task", "Settings"], "Enabled") => Some(Capture::Enabled),
        (["Task", "Actions", "Exec"], "Command") => Some(Capture::Command),
        (["Task", "Principals", "Principal"], "UserId") => Some(Capture::UserId),
        _ => None,
    }
}

/// Records what opening `name` inside `stack` says.
fn open(
    task: &mut Task,
    stack: &[String],
    name: &str,
    start: &BytesStart<'_>,
    actions_context: &mut Option<String>,
    principals: &mut Vec<(Option<String>, Option<String>)>,
    root_seen: &mut bool,
) -> Result<(), ParseError> {
    let path: Vec<&str> = stack.iter().map(String::as_str).collect();
    match (path.as_slice(), name) {
        ([], "Task") => *root_seen = true,
        ([], _) => return Err(malformed("the root element is not Task")),
        (["Task", "Triggers"], trigger) => task.triggers.push(TriggerKind::from_element(trigger)),
        (["Task"], "Actions") => *actions_context = attribute(start, "Context")?,
        (["Task", "Actions"], "Exec") => task.exec_commands.push(None),
        (["Task", "Actions"], "ComHandler") => task.com_handlers += 1,
        (["Task", "Principals"], "Principal") => {
            principals.push((attribute(start, "id")?, None));
        }
        _ => {}
    }
    Ok(())
}

/// Stores one captured element's text.
fn store(
    task: &mut Task,
    principals: &mut [(Option<String>, Option<String>)],
    what: Capture,
    value: String,
) -> Result<(), ParseError> {
    match what {
        Capture::Enabled => task.enabled = Some(boolean(&value)?),
        Capture::Command => {
            if let Some(last) = task.exec_commands.last_mut() {
                *last = Some(value);
            }
        }
        Capture::UserId => {
            if let Some(last) = principals.last_mut() {
                last.1 = Some(value);
            }
        }
    }
    Ok(())
}

/// An `xs:boolean`: `true`, `false`, `1` or `0`, with surrounding whitespace.
fn boolean(value: &str) -> Result<bool, ParseError> {
    match value.trim() {
        "true" | "1" => Ok(true),
        "false" | "0" => Ok(false),
        _ => Err(ParseError::Malformed {
            field: "enabled",
            detail: "not an xs:boolean".to_owned(),
        }),
    }
}

/// One attribute's value with its escapes resolved, or `None` when the element does not carry it.
fn attribute(start: &BytesStart<'_>, name: &str) -> Result<Option<String>, ParseError> {
    for attribute in start.attributes() {
        let attribute = attribute.map_err(|error| malformed(format!("attribute: {error}")))?;
        if attribute.key.local_name().as_ref() == name {
            let value = attribute
                .normalized_value(XmlVersion::Implicit1_0)
                .map_err(|error| malformed(format!("attribute value: {error}")))?;
            return Ok(Some(value.into_owned()));
        }
    }
    Ok(None)
}

/// A character reference, or one of XML's five predefined entities. Any other entity is an error: a
/// task file declares none, and this parser does not read a DTD.
fn resolve_reference(reference: &quick_xml::events::BytesRef<'_>) -> Result<char, ParseError> {
    if let Some(character) = reference
        .resolve_char_ref()
        .map_err(|error| malformed(format!("character reference: {error}")))?
    {
        return Ok(character);
    }
    match &**reference {
        "lt" => Ok('<'),
        "gt" => Ok('>'),
        "amp" => Ok('&'),
        "quot" => Ok('"'),
        "apos" => Ok('\''),
        _ => Err(malformed("an entity that is not one of XML's five")),
    }
}

/// The user id of the principal the actions run as.
fn chosen_principal(
    principals: Vec<(Option<String>, Option<String>)>,
    context: Option<&str>,
) -> Option<String> {
    if let Some(context) = context
        && let Some((_, user)) = principals
            .iter()
            .find(|(id, _)| id.as_deref() == Some(context))
    {
        return user.clone();
    }
    principals.into_iter().next().and_then(|(_, user)| user)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TASK: &str = r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Author>Contoso</Author>
    <Description>Keeps the Contoso updater current</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger><Enabled>true</Enabled></LogonTrigger>
    <TimeTrigger><StartBoundary>2026-01-01T00:00:00</StartBoundary></TimeTrigger>
    <BootTrigger />
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-21-1-2-3-1001</UserId>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <Enabled>false</Enabled>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>"%LOCALAPPDATA%\Contoso\updater.exe"</Command>
      <Arguments>--token=secret-value</Arguments>
      <WorkingDirectory>C:\Users\alex</WorkingDirectory>
    </Exec>
    <ComHandler><ClassId>{00000000-0000-0000-0000-000000000000}</ClassId></ComHandler>
  </Actions>
</Task>
"#;

    fn utf16le(text: &str) -> Vec<u8> {
        let mut bytes = vec![0xFF, 0xFE];
        for unit in text.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        bytes
    }

    #[test]
    fn a_task_file_gives_its_state_triggers_commands_and_principal() {
        let task = parse_task(&utf16le(TASK)).unwrap();
        assert_eq!(task.enabled, Some(false));
        assert_eq!(
            task.triggers,
            vec![TriggerKind::Logon, TriggerKind::Time, TriggerKind::Boot]
        );
        assert_eq!(
            task.exec_commands,
            vec![Some(r#""%LOCALAPPDATA%\Contoso\updater.exe""#.to_owned())]
        );
        assert_eq!(task.com_handlers, 1);
        assert_eq!(
            task.principal_user_id.as_deref(),
            Some("S-1-5-21-1-2-3-1001")
        );
    }

    /// ADR 0060, section 4: nothing the parser returns carries an argument, a working folder, an
    /// author or a description, whatever the document holds.
    #[test]
    fn arguments_and_other_elements_never_reach_the_result() {
        let task = parse_task(TASK.as_bytes()).unwrap();
        let debug = format!("{task:?}");
        for never in [
            "secret-value",
            "Arguments",
            r"C:\Users\alex",
            "Contoso</",
            "Keeps",
        ] {
            assert!(!debug.contains(never), "{never} in {debug}");
        }
    }

    #[test]
    fn every_encoding_the_file_may_be_in_is_read_the_same() {
        let expected = parse_task(TASK.as_bytes()).unwrap();
        let mut bom_utf8 = vec![0xEF, 0xBB, 0xBF];
        bom_utf8.extend_from_slice(TASK.as_bytes());
        let mut utf16be = vec![0xFE, 0xFF];
        for unit in TASK.encode_utf16() {
            utf16be.extend_from_slice(&unit.to_be_bytes());
        }
        let no_bom_le: Vec<u8> = utf16le(TASK)[2..].to_vec();
        for bytes in [utf16le(TASK), bom_utf8, utf16be, no_bom_le] {
            assert_eq!(parse_task(&bytes).unwrap(), expected);
        }
    }

    #[test]
    fn an_absent_enabled_is_left_to_the_caller_and_a_task_may_have_no_trigger() {
        let task = parse_task(
            br"<Task><Actions><Exec><Command>C:\a.exe</Command></Exec></Actions></Task>",
        )
        .unwrap();
        assert_eq!(task.enabled, None);
        assert!(task.triggers.is_empty());
        assert_eq!(task.exec_commands, vec![Some(r"C:\a.exe".to_owned())]);
        assert_eq!(task.principal_user_id, None);
    }

    #[test]
    fn escapes_are_resolved_and_unknown_triggers_are_other() {
        let task = parse_task(
            br"<Task><Triggers><WnfStateChangeTrigger/><SessionStateChangeTrigger/><FutureTrigger/></Triggers><Settings><Enabled> 1 </Enabled></Settings><Actions><Exec><Command>C:\a&amp;b\&#x61;.exe</Command></Exec><Exec/><Exec><Command/></Exec></Actions></Task>",
        )
        .unwrap();
        assert_eq!(task.enabled, Some(true));
        assert_eq!(
            task.triggers,
            vec![
                TriggerKind::Wnf,
                TriggerKind::SessionChange,
                TriggerKind::Other
            ]
        );
        assert_eq!(
            task.exec_commands,
            vec![Some(r"C:\a&b\a.exe".to_owned()), None, Some(String::new())]
        );
    }

    #[test]
    fn the_principal_named_by_the_actions_context_is_chosen() {
        let task = parse_task(
            br#"<Task><Principals><Principal id="A"><UserId>first</UserId></Principal><Principal id="B"><UserId>second</UserId></Principal></Principals><Actions Context="B"><Exec><Command>x</Command></Exec></Actions></Task>"#,
        )
        .unwrap();
        assert_eq!(task.principal_user_id.as_deref(), Some("second"));
        let no_context = parse_task(
            br#"<Task><Principals><Principal id="A"><GroupId>S-1-5-32-545</GroupId></Principal></Principals><Actions><Exec><Command>x</Command></Exec></Actions></Task>"#,
        )
        .unwrap();
        assert_eq!(no_context.principal_user_id, None);
    }

    #[test]
    fn a_document_that_is_not_a_task_is_an_error_not_an_empty_task() {
        for bytes in [
            &b""[..],
            b"<NotATask/>",
            b"<Task><Settings><Enabled>maybe</Enabled></Settings></Task>",
            b"<Task><Settings>",
            b"<Task></Wrong>",
            b"<Task><Actions><Exec><Command>&custom;</Command></Exec></Actions></Task>",
            &[0xFF, 0xFE, 0x3C],
            &[0xFF, 0xFE, 0x00, 0xD8, 0x3C, 0x00],
            &[0xC3, 0x28],
        ] {
            assert!(parse_task(bytes).is_err(), "{bytes:?}");
        }
    }

    #[test]
    fn nesting_is_bounded() {
        let mut deep = String::from("<Task>");
        for _ in 0..MAX_DEPTH {
            deep.push_str("<a>");
        }
        assert!(parse_task(deep.as_bytes()).is_err());
    }
}
