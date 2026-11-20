//! Import: keepassxc-cli's XML export (`keepassxc-cli export -f xml`) into a [`Database`].
//!
//! Two stages: [`xml`] reads the document into wire structs that mirror the XML, then this module
//! builds the domain model from them — decoding attachments, sorting each entry's strings into
//! standard fields, custom attributes and TOTP, and computing group paths.

mod xml;

use std::collections::HashMap;
use std::collections::btree_map;
use std::io;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use flate2::read::GzDecoder;

use crate::model::{
    Attachment, CustomAttributes, Database, Entry, FieldName, GroupPath, Location, StandardFields,
    Tags, Uuid,
};
use crate::otp;
use crate::secret::SecretBytes;
use xml::{Compression, WireBinary, WireDocument, WireEntry, WireGroup};

/// Why an export could not be imported. Messages name elements, keys and byte offsets, never a
/// field's or attachment's value.
#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    #[error("malformed XML at byte {position}: {message}")]
    Xml { position: u64, message: String },
    #[error("the export has a DOCTYPE (at byte {position}); keepassxc-cli never writes one")]
    DocType { position: u64 },
    #[error("unexpected content inside <{inside}> at byte {position}")]
    UnexpectedContent { inside: &'static str, position: u64 },
    #[error("the export ends inside <{inside}>")]
    UnexpectedEof { inside: &'static str },
    #[error("<{parent}> has no <{element}> (element ends at byte {position})")]
    MissingElement {
        parent: &'static str,
        element: &'static str,
        position: u64,
    },
    #[error("<{parent}> has more than one <{element}> (at byte {position})")]
    RepeatedElement {
        parent: &'static str,
        element: &'static str,
        position: u64,
    },
    #[error("unknown entity reference at byte {position}")]
    UnknownEntity { position: u64 },
    #[error("invalid character reference at byte {position}")]
    InvalidCharacterReference { position: u64 },
    #[error("<{element}> is neither True nor False (at byte {position})")]
    InvalidBoolean {
        element: &'static str,
        position: u64,
    },
    #[error("invalid UUID at byte {position}")]
    InvalidUuid { position: u64 },
    #[error("<{element}> attribute {attribute} is missing or invalid (at byte {position})")]
    InvalidAttribute {
        element: &'static str,
        attribute: &'static str,
        position: u64,
    },
    #[error(
        "groups nest more than {} deep (at byte {position})",
        xml::MAX_GROUP_DEPTH
    )]
    NestingTooDeep { position: u64 },
    #[error("two entries share UUID {0}")]
    DuplicateUuid(Uuid),
    #[error("entry {entry} has field {key:?} twice")]
    DuplicateField { entry: Uuid, key: String },
    #[error("entry {entry} has attachment {name:?} twice")]
    DuplicateAttachment { entry: Uuid, name: String },
    #[error("entry {entry} attachment {name:?} refers to binary {id:?}, which Meta has not got")]
    UnknownBinary {
        entry: Uuid,
        name: String,
        id: String,
    },
    #[error("Meta lists binary {id:?} twice")]
    DuplicateBinary { id: String },
    #[error("binary {id:?} is not valid base64")]
    BinaryBase64 { id: String },
    #[error("binary {id:?} is marked compressed but does not gunzip")]
    BinaryGzip {
        id: String,
        #[source]
        source: io::Error,
    },
}

/// Parses an export into the database model, consuming the XML.
///
/// `xml` is dropped — and so wiped — as soon as it has been read, before the model is built.
///
/// # Errors
/// Any [`ImportError`]: the document is malformed, or not shaped like a KeePass export.
pub fn import(xml: SecretBytes) -> Result<Database, ImportError> {
    let document = xml::parse_document(xml.expose());
    drop(xml);
    build_database(document?)
}

fn build_database(document: WireDocument) -> Result<Database, ImportError> {
    let binaries = decode_binaries(document.meta.binaries)?;
    let recycle_bin = match document.meta.recycle_bin_enabled {
        Some(true) => document.meta.recycle_bin.filter(|uuid| !uuid.is_nil()),
        Some(false) | None => None,
    };
    let context = BuildContext {
        binaries: &binaries,
        recycle_bin,
    };
    let mut entries = Vec::new();
    let root_location = context.location(document.root.uuid, Location::Live);
    // The root group's own name is not part of any path: see `GroupPath`.
    context.collect(
        document.root,
        &GroupPath::default(),
        root_location,
        &mut entries,
    )?;
    Database::new(entries).map_err(ImportError::DuplicateUuid)
}

fn decode_binaries(binaries: Vec<WireBinary>) -> Result<HashMap<String, SecretBytes>, ImportError> {
    let mut decoded = HashMap::with_capacity(binaries.len());
    for binary in binaries {
        let content = decode_binary(&binary)?;
        if decoded.insert(binary.id.clone(), content).is_some() {
            return Err(ImportError::DuplicateBinary { id: binary.id });
        }
    }
    Ok(decoded)
}

fn decode_binary(binary: &WireBinary) -> Result<SecretBytes, ImportError> {
    let stored = STANDARD
        .decode(binary.base64.expose())
        .map(SecretBytes::from_vec)
        .map_err(|_| ImportError::BinaryBase64 {
            id: binary.id.clone(),
        })?;
    match binary.compression {
        Compression::None => Ok(stored),
        Compression::Gzip => {
            SecretBytes::read_to_end(GzDecoder::new(stored.expose())).map_err(|source| {
                ImportError::BinaryGzip {
                    id: binary.id.clone(),
                    source,
                }
            })
        }
    }
}

struct BuildContext<'a> {
    binaries: &'a HashMap<String, SecretBytes>,
    recycle_bin: Option<Uuid>,
}

impl BuildContext<'_> {
    /// A group is in the recycle bin when it is the bin or any group below it.
    fn location(&self, group: Uuid, parent: Location) -> Location {
        match parent {
            Location::RecycleBin => Location::RecycleBin,
            Location::Live if self.recycle_bin == Some(group) => Location::RecycleBin,
            Location::Live => Location::Live,
        }
    }

    fn collect(
        &self,
        group: WireGroup,
        path: &GroupPath,
        location: Location,
        out: &mut Vec<Entry>,
    ) -> Result<(), ImportError> {
        for entry in group.entries {
            out.push(self.build_entry(entry, path.clone(), location)?);
        }
        for child in group.groups {
            let child_location = self.location(child.uuid, location);
            let child_path = path.child(child.name.clone());
            self.collect(child, &child_path, child_location, out)?;
        }
        Ok(())
    }

    fn build_entry(
        &self,
        wire: WireEntry,
        groups: GroupPath,
        location: Location,
    ) -> Result<Entry, ImportError> {
        let uuid = wire.uuid;
        let (fields, mut custom) = sort_strings(uuid, wire.strings)?;
        let otp = otp::extract(&mut custom);
        let attachments = self.attachments(uuid, wire.binaries)?;
        Ok(Entry {
            uuid,
            groups,
            tags: wire.tags.as_deref().map(Tags::parse).unwrap_or_default(),
            location,
            fields,
            custom,
            otp,
            attachments,
        })
    }

    fn attachments(
        &self,
        entry: Uuid,
        references: Vec<xml::WireBinaryRef>,
    ) -> Result<Vec<Attachment>, ImportError> {
        let mut attachments: Vec<Attachment> = Vec::with_capacity(references.len());
        for reference in references {
            if attachments.iter().any(|a| a.name() == reference.name) {
                return Err(ImportError::DuplicateAttachment {
                    entry,
                    name: reference.name,
                });
            }
            let Some(content) = self.binaries.get(&reference.id) else {
                return Err(ImportError::UnknownBinary {
                    entry,
                    name: reference.name,
                    id: reference.id,
                });
            };
            attachments.push(Attachment::new(reference.name, content.clone()));
        }
        Ok(attachments)
    }
}

/// Splits an entry's `<String>`s into the standard fields and the rest.
fn sort_strings(
    entry: Uuid,
    strings: Vec<(String, SecretBytes)>,
) -> Result<(StandardFields, CustomAttributes), ImportError> {
    let mut fields = StandardFields::default();
    let mut custom = CustomAttributes::new();
    for (key, value) in strings {
        match FieldName::parse(key) {
            FieldName::Standard(field) => {
                if fields.set(field, value).is_some() {
                    return Err(ImportError::DuplicateField {
                        entry,
                        key: field.key().to_owned(),
                    });
                }
            }
            FieldName::Custom(name) => match custom.entry(name) {
                btree_map::Entry::Vacant(slot) => {
                    slot.insert(value);
                }
                btree_map::Entry::Occupied(slot) => {
                    return Err(ImportError::DuplicateField {
                        entry,
                        key: slot.key().as_str().to_owned(),
                    });
                }
            },
        }
    }
    Ok((fields, custom))
}
