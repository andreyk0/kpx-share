//! The KeePass XML document as keepassxc-cli exports it, read into wire structs.
//!
//! Only what kpx-share uses is kept; every other element is skipped whole. Of `<History>`, only
//! each old version's last-modification time is read, so old versions never become entries or
//! fields. Values are byte-exact: text is copied verbatim and only entity and character
//! references are decoded.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use quick_xml::Reader;
use quick_xml::events::{BytesRef, BytesStart, Event};

use super::ExportError;
use crate::model::Uuid;
use crate::secret::SecretBytes;

/// Groups nested deeper than this are refused rather than recursed into: hand-built databases
/// nest a handful of levels, and each level is a stack frame.
pub(super) const MAX_GROUP_DEPTH: usize = 64;

#[derive(Debug)]
pub(super) struct WireDocument {
    pub(super) meta: WireMeta,
    pub(super) root: WireGroup,
}

#[derive(Debug, Default)]
pub(super) struct WireMeta {
    /// `None` when Meta has no `<Binaries>`, as in every export of a KDBX 4 database.
    pub(super) binaries: Option<Vec<WireBinary>>,
    pub(super) recycle_bin_enabled: Option<bool>,
    pub(super) recycle_bin: Option<Uuid>,
}

#[derive(Debug)]
pub(super) struct WireBinary {
    pub(super) id: String,
    pub(super) compression: Compression,
    pub(super) base64: SecretBytes,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Compression {
    Gzip,
    None,
}

#[derive(Debug)]
pub(super) struct WireGroup {
    pub(super) uuid: Uuid,
    pub(super) name: String,
    pub(super) entries: Vec<WireEntry>,
    pub(super) groups: Vec<WireGroup>,
}

#[derive(Debug)]
pub(super) struct WireEntry {
    pub(super) uuid: Uuid,
    pub(super) tags: Option<String>,
    pub(super) strings: Vec<(String, SecretBytes)>,
    pub(super) binaries: Vec<WireBinaryRef>,
    pub(super) history: Vec<WireHistoryItem>,
}

/// One `<Entry>` inside `<History>`: only its `<Times><LastModificationTime>`.
#[derive(Debug)]
pub(super) struct WireHistoryItem {
    pub(super) last_modified: Option<String>,
}

#[derive(Debug)]
pub(super) struct WireBinaryRef {
    pub(super) name: String,
    pub(super) id: String,
}

pub(super) fn parse_document(xml: &[u8]) -> Result<WireDocument, ExportError> {
    let mut cursor = Cursor::new(xml);
    cursor.open_root("KeePassFile")?;
    let mut meta = None;
    let mut root = None;
    cursor.children("KeePassFile", |cursor, child| match child.name().as_ref() {
        "Meta" => set_once(
            &mut meta,
            parse_meta(cursor)?,
            cursor,
            "KeePassFile",
            "Meta",
        ),
        "Root" => set_once(
            &mut root,
            parse_root(cursor)?,
            cursor,
            "KeePassFile",
            "Root",
        ),
        _ => cursor.skip(&child),
    })?;
    cursor.close_root()?;
    Ok(WireDocument {
        meta: meta.unwrap_or_default(),
        root: required(root, &cursor, "KeePassFile", "Root")?,
    })
}

fn parse_meta(cursor: &mut Cursor<'_>) -> Result<WireMeta, ExportError> {
    let mut binaries = None;
    let mut recycle_bin_enabled = None;
    let mut recycle_bin = None;
    cursor.children("Meta", |cursor, child| match child.name().as_ref() {
        "Binaries" => {
            let parsed = parse_binaries(cursor)?;
            set_once(&mut binaries, parsed, cursor, "Meta", "Binaries")
        }
        "RecycleBinEnabled" => {
            let enabled = cursor.boolean("RecycleBinEnabled")?;
            set_once(
                &mut recycle_bin_enabled,
                enabled,
                cursor,
                "Meta",
                "RecycleBinEnabled",
            )
        }
        "RecycleBinUUID" => {
            let uuid = cursor.uuid("RecycleBinUUID")?;
            set_once(&mut recycle_bin, uuid, cursor, "Meta", "RecycleBinUUID")
        }
        _ => cursor.skip(&child),
    })?;
    Ok(WireMeta {
        binaries,
        recycle_bin_enabled,
        recycle_bin,
    })
}

fn parse_binaries(cursor: &mut Cursor<'_>) -> Result<Vec<WireBinary>, ExportError> {
    let mut binaries = Vec::new();
    cursor.children("Binaries", |cursor, child| match child.name().as_ref() {
        "Binary" => {
            let id = cursor
                .attribute(&child, "Binary", "ID")?
                .ok_or_else(|| cursor.invalid_attribute("Binary", "ID"))?;
            let compression = match cursor.attribute(&child, "Binary", "Compressed")? {
                None => Compression::None,
                Some(flag) => match parse_boolean(&flag) {
                    Some(true) => Compression::Gzip,
                    Some(false) => Compression::None,
                    None => return Err(cursor.invalid_attribute("Binary", "Compressed")),
                },
            };
            let mut base64 = SecretBytes::new();
            cursor.text("Binary", &mut base64)?;
            binaries.push(WireBinary {
                id,
                compression,
                base64,
            });
            Ok(())
        }
        _ => cursor.skip(&child),
    })?;
    Ok(binaries)
}

fn parse_root(cursor: &mut Cursor<'_>) -> Result<WireGroup, ExportError> {
    let mut group = None;
    cursor.children("Root", |cursor, child| match child.name().as_ref() {
        "Group" => set_once(&mut group, parse_group(cursor, 0)?, cursor, "Root", "Group"),
        _ => cursor.skip(&child),
    })?;
    required(group, cursor, "Root", "Group")
}

fn parse_group(cursor: &mut Cursor<'_>, depth: usize) -> Result<WireGroup, ExportError> {
    if depth > MAX_GROUP_DEPTH {
        return Err(ExportError::NestingTooDeep {
            position: cursor.position(),
        });
    }
    let mut uuid = None;
    let mut name = None;
    let mut entries = Vec::new();
    let mut groups = Vec::new();
    cursor.children("Group", |cursor, child| match child.name().as_ref() {
        "UUID" => {
            let parsed = cursor.uuid("UUID")?;
            set_once(&mut uuid, parsed, cursor, "Group", "UUID")
        }
        "Name" => {
            let parsed = cursor.plain_text("Name")?;
            set_once(&mut name, parsed, cursor, "Group", "Name")
        }
        "Entry" => {
            entries.push(parse_entry(cursor)?);
            Ok(())
        }
        "Group" => {
            groups.push(parse_group(cursor, depth + 1)?);
            Ok(())
        }
        _ => cursor.skip(&child),
    })?;
    Ok(WireGroup {
        uuid: required(uuid, cursor, "Group", "UUID")?,
        name: required(name, cursor, "Group", "Name")?,
        entries,
        groups,
    })
}

fn parse_entry(cursor: &mut Cursor<'_>) -> Result<WireEntry, ExportError> {
    let mut uuid = None;
    let mut tags = None;
    let mut strings = Vec::new();
    let mut binaries = Vec::new();
    let mut history = None;
    cursor.children("Entry", |cursor, child| match child.name().as_ref() {
        "UUID" => {
            let parsed = cursor.uuid("UUID")?;
            set_once(&mut uuid, parsed, cursor, "Entry", "UUID")
        }
        "Tags" => {
            let parsed = cursor.plain_text("Tags")?;
            set_once(&mut tags, parsed, cursor, "Entry", "Tags")
        }
        "String" => {
            strings.push(parse_string(cursor)?);
            Ok(())
        }
        "Binary" => {
            binaries.push(parse_binary_ref(cursor)?);
            Ok(())
        }
        "History" => {
            let parsed = parse_history(cursor)?;
            set_once(&mut history, parsed, cursor, "Entry", "History")
        }
        _ => cursor.skip(&child),
    })?;
    Ok(WireEntry {
        uuid: required(uuid, cursor, "Entry", "UUID")?,
        tags,
        strings,
        binaries,
        history: history.unwrap_or_default(),
    })
}

/// Old versions of an entry: never entries, never fields, only when each was last modified.
fn parse_history(cursor: &mut Cursor<'_>) -> Result<Vec<WireHistoryItem>, ExportError> {
    let mut items = Vec::new();
    cursor.children("History", |cursor, child| match child.name().as_ref() {
        "Entry" => {
            let mut last_modified = None;
            cursor.children("Entry", |cursor, child| match child.name().as_ref() {
                "Times" => cursor.children("Times", |cursor, child| match child.name().as_ref() {
                    "LastModificationTime" => {
                        let parsed = cursor.plain_text("LastModificationTime")?;
                        set_once(
                            &mut last_modified,
                            parsed,
                            cursor,
                            "Times",
                            "LastModificationTime",
                        )
                    }
                    _ => cursor.skip(&child),
                }),
                _ => cursor.skip(&child),
            })?;
            items.push(WireHistoryItem { last_modified });
            Ok(())
        }
        _ => cursor.skip(&child),
    })?;
    Ok(items)
}

fn parse_string(cursor: &mut Cursor<'_>) -> Result<(String, SecretBytes), ExportError> {
    let mut key = None;
    let mut value = None;
    cursor.children("String", |cursor, child| match child.name().as_ref() {
        "Key" => {
            let parsed = cursor.plain_text("Key")?;
            set_once(&mut key, parsed, cursor, "String", "Key")
        }
        "Value" => {
            let mut parsed = SecretBytes::new();
            cursor.text("Value", &mut parsed)?;
            set_once(&mut value, parsed, cursor, "String", "Value")
        }
        _ => cursor.skip(&child),
    })?;
    Ok((
        required(key, cursor, "String", "Key")?,
        required(value, cursor, "String", "Value")?,
    ))
}

fn parse_binary_ref(cursor: &mut Cursor<'_>) -> Result<WireBinaryRef, ExportError> {
    let mut name = None;
    let mut id = None;
    cursor.children("Binary", |cursor, child| match child.name().as_ref() {
        "Key" => {
            let parsed = cursor.plain_text("Key")?;
            set_once(&mut name, parsed, cursor, "Binary", "Key")
        }
        "Value" => {
            let reference = cursor
                .attribute(&child, "Value", "Ref")?
                .ok_or_else(|| cursor.invalid_attribute("Value", "Ref"))?;
            cursor.skip(&child)?;
            set_once(&mut id, reference, cursor, "Binary", "Value")
        }
        _ => cursor.skip(&child),
    })?;
    Ok(WireBinaryRef {
        name: required(name, cursor, "Binary", "Key")?,
        id: required(id, cursor, "Binary", "Value")?,
    })
}

fn set_once<T>(
    slot: &mut Option<T>,
    value: T,
    cursor: &Cursor<'_>,
    parent: &'static str,
    element: &'static str,
) -> Result<(), ExportError> {
    match slot.replace(value) {
        None => Ok(()),
        Some(_) => Err(ExportError::RepeatedElement {
            parent,
            element,
            position: cursor.position(),
        }),
    }
}

fn required<T>(
    slot: Option<T>,
    cursor: &Cursor<'_>,
    parent: &'static str,
    element: &'static str,
) -> Result<T, ExportError> {
    slot.ok_or(ExportError::MissingElement {
        parent,
        element,
        position: cursor.position(),
    })
}

fn parse_boolean(text: &str) -> Option<bool> {
    match text {
        "True" => Some(true),
        "False" => Some(false),
        _ => None,
    }
}

/// Where decoded text goes: a `String` for names, [`SecretBytes`] for values.
trait TextSink {
    fn push_str(&mut self, text: &str);
}

impl TextSink for String {
    fn push_str(&mut self, text: &str) {
        String::push_str(self, text);
    }
}

impl TextSink for SecretBytes {
    fn push_str(&mut self, text: &str) {
        self.extend_from_slice(text.as_bytes());
    }
}

/// A pull reader over the borrowed XML, with one method per shape of element content.
struct Cursor<'x> {
    reader: Reader<&'x [u8]>,
}

impl<'x> Cursor<'x> {
    fn new(xml: &'x [u8]) -> Self {
        let mut reader = Reader::from_reader(xml);
        let config = reader.config_mut();
        // `<Value/>` and `<Value></Value>` both arrive as Start then End.
        config.expand_empty_elements = true;
        config.trim_text(false);
        config.check_end_names = true;
        Self { reader }
    }

    fn position(&self) -> u64 {
        self.reader.buffer_position()
    }

    /// The next event that carries document content; comments, PIs and the declaration are
    /// dropped, and a DOCTYPE (which could declare entities) is refused.
    fn next(&mut self) -> Result<Event<'x>, ExportError> {
        loop {
            match self.reader.read_event() {
                Ok(Event::Comment(_) | Event::Decl(_) | Event::PI(_)) => {}
                Ok(Event::DocType(_)) => {
                    return Err(ExportError::DocType {
                        position: self.position(),
                    });
                }
                Ok(event) => return Ok(event),
                Err(error) => {
                    return Err(ExportError::Xml {
                        position: self.reader.error_position(),
                        message: error.to_string(),
                    });
                }
            }
        }
    }

    fn open_root(&mut self, name: &'static str) -> Result<(), ExportError> {
        loop {
            match self.next()? {
                Event::Start(start) if start.name().as_ref() == name => return Ok(()),
                Event::Text(text) if is_xml_whitespace(&text) => {}
                Event::Eof => return Err(ExportError::UnexpectedEof { inside: "document" }),
                _ => return Err(self.unexpected("document")),
            }
        }
    }

    fn close_root(&mut self) -> Result<(), ExportError> {
        loop {
            match self.next()? {
                Event::Eof => return Ok(()),
                Event::Text(text) if is_xml_whitespace(&text) => {}
                _ => return Err(self.unexpected("document")),
            }
        }
    }

    /// Visits each child element of the element just opened, through its end tag. Whitespace
    /// between children is formatting; any other text there is refused.
    fn children(
        &mut self,
        parent: &'static str,
        mut visit: impl FnMut(&mut Self, BytesStart<'x>) -> Result<(), ExportError>,
    ) -> Result<(), ExportError> {
        loop {
            match self.next()? {
                Event::Start(child) => visit(self, child)?,
                Event::End(_) => return Ok(()),
                Event::Text(text) if is_xml_whitespace(&text) => {}
                Event::Eof => return Err(ExportError::UnexpectedEof { inside: parent }),
                _ => return Err(self.unexpected(parent)),
            }
        }
    }

    /// Reads the text content of the element just opened, through its end tag, decoding
    /// references and copying everything else verbatim.
    fn text(&mut self, element: &'static str, sink: &mut impl TextSink) -> Result<(), ExportError> {
        loop {
            match self.next()? {
                Event::Text(text) => sink.push_str(&text),
                Event::CData(data) => sink.push_str(&data),
                Event::GeneralRef(reference) => {
                    let decoded = self.reference(&reference)?;
                    sink.push_str(decoded.encode_utf8(&mut [0u8; 4]));
                }
                Event::End(_) => return Ok(()),
                Event::Eof => return Err(ExportError::UnexpectedEof { inside: element }),
                _ => return Err(self.unexpected(element)),
            }
        }
    }

    fn plain_text(&mut self, element: &'static str) -> Result<String, ExportError> {
        let mut text = String::new();
        self.text(element, &mut text)?;
        Ok(text)
    }

    fn boolean(&mut self, element: &'static str) -> Result<bool, ExportError> {
        let text = self.plain_text(element)?;
        parse_boolean(&text).ok_or(ExportError::InvalidBoolean {
            element,
            position: self.position(),
        })
    }

    fn uuid(&mut self, element: &'static str) -> Result<Uuid, ExportError> {
        let text = self.plain_text(element)?;
        let invalid = || ExportError::InvalidUuid {
            position: self.position(),
        };
        let bytes = STANDARD.decode(text).map_err(|_| invalid())?;
        let bytes: [u8; 16] = bytes.try_into().map_err(|_| invalid())?;
        Ok(Uuid::from_bytes(bytes))
    }

    fn reference(&self, reference: &BytesRef<'_>) -> Result<char, ExportError> {
        let position = self.position();
        match reference.resolve_char_ref() {
            Ok(Some(character)) => Ok(character),
            Err(_) => Err(ExportError::InvalidCharacterReference { position }),
            Ok(None) => match &**reference {
                "lt" => Ok('<'),
                "gt" => Ok('>'),
                "amp" => Ok('&'),
                "quot" => Ok('"'),
                "apos" => Ok('\''),
                _ => Err(ExportError::UnknownEntity { position }),
            },
        }
    }

    /// The attribute's raw value; KeePass attributes (`ID`, `Ref`, `Compressed`) never need
    /// unescaping.
    fn attribute(
        &self,
        start: &BytesStart<'_>,
        element: &'static str,
        attribute: &'static str,
    ) -> Result<Option<String>, ExportError> {
        match start.try_get_attribute(attribute) {
            Ok(found) => Ok(found.map(|found| found.value.into_owned())),
            Err(_) => Err(self.invalid_attribute(element, attribute)),
        }
    }

    fn invalid_attribute(&self, element: &'static str, attribute: &'static str) -> ExportError {
        ExportError::InvalidAttribute {
            element,
            attribute,
            position: self.position(),
        }
    }

    /// Consumes the element just opened, whatever it contains.
    fn skip(&mut self, start: &BytesStart<'_>) -> Result<(), ExportError> {
        self.reader
            .read_to_end(start.name())
            .map(|_| ())
            .map_err(|error| ExportError::Xml {
                position: self.reader.error_position(),
                message: error.to_string(),
            })
    }

    fn unexpected(&self, inside: &'static str) -> ExportError {
        ExportError::UnexpectedContent {
            inside,
            position: self.position(),
        }
    }
}

/// XML's whitespace: space, tab, CR, LF.
fn is_xml_whitespace(text: &str) -> bool {
    text.bytes()
        .all(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
}
