//! `meta.json`: what an entry directory records about itself, for `ls`, `rm` and replacement.
//!
//! The file is not secret and holds no secret: names, paths, tags, times and which fields are
//! incomplete, never a value. [`EntryMeta`] is the type the code works with; the stored shape is
//! a private `MetaFile` (see [`crate::schema`]), and [`read`] parses it back, rejecting an
//! unknown schema version, unknown keys and times that run backwards.

use std::collections::BTreeMap;
use std::io;
use std::path::PathBuf;

use jiff::Timestamp;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::layout::{BoundedReadError, EntryDir, read_bounded};
use crate::model::{FieldName, Uuid};
use crate::otp::{Otp, OtpFormat, OtpIssue, OtpProblem, OtpUri};
use crate::schema::SchemaVersion;
use crate::select::{Eligibility, ResolvedEntry};

pub(crate) const META_FILE: &str = "meta.json";

/// A `meta.json` holds a few names per field; 1 MiB is room for thousands of custom attributes.
const META_BYTES_MAX: u64 = 1024 * 1024;

// --- Validity ---------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("an entry must expire after it is exported ({exported_at} .. {expires_at})")]
pub struct ValidityError {
    exported_at: Timestamp,
    expires_at: Timestamp,
}

/// When an entry was written and when it stops being valid, `exported_at < expires_at`.
///
/// The writer only records the expiry; deleting at that time is the watcher's job. The expiry
/// recorded is the session's at the time of writing: a later add with a shorter TTL moves the
/// session's earlier, and the session record (see [`crate::session::SessionRecord`]) is what
/// governs deletion, so an entry's `expires_at` in `meta.json` can be later than the time its
/// directory goes. `ls` shows the session's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Validity {
    exported_at: Timestamp,
    expires_at: Timestamp,
}

impl Validity {
    /// # Errors
    /// `expires_at` is not after `exported_at`.
    pub fn new(exported_at: Timestamp, expires_at: Timestamp) -> Result<Self, ValidityError> {
        if exported_at < expires_at {
            Ok(Self {
                exported_at,
                expires_at,
            })
        } else {
            Err(ValidityError {
                exported_at,
                expires_at,
            })
        }
    }

    #[must_use]
    pub fn exported_at(&self) -> Timestamp {
        self.exported_at
    }

    #[must_use]
    pub fn expires_at(&self) -> Timestamp {
        self.expires_at
    }
}

// --- The stored record ------------------------------------------------------------------------

/// The `meta.json` schema version.
const META_VERSION: u32 = 1;

/// The rule the entry was shared under.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "rule", rename_all = "snake_case", deny_unknown_fields)]
pub enum EligibilityRecord {
    /// `tagged:<tag>` in the CLI's words.
    Tagged {
        tag: String,
    },
    Any,
}

impl From<&Eligibility> for EligibilityRecord {
    fn from(eligibility: &Eligibility) -> Self {
        match eligibility {
            Eligibility::Tagged(tag) => Self::Tagged {
                tag: tag.name().to_owned(),
            },
            Eligibility::Any => Self::Any,
        }
    }
}

/// What became of the entry's TOTP.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum OtpRecord {
    Absent,
    /// Written as an `otpauth://` URI to `file`.
    Present {
        file: String,
    },
    /// The entry has TOTP attributes this tool could not read; no `otp` file was written.
    Unrecognised {
        format: OtpFormatRecord,
        problem: OtpProblemRecord,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OtpFormatRecord {
    OtpauthUri,
    #[serde(rename = "keepassxc_legacy")]
    KeePassXcLegacy,
    #[serde(rename = "keepass2")]
    KeePass2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OtpProblemRecord {
    NotAnOtpauthUri,
    EmptySecret,
    InvalidSettings,
    InvalidPeriod,
    InvalidDigits,
    UnknownAlgorithm,
}

impl From<OtpFormat> for OtpFormatRecord {
    fn from(format: OtpFormat) -> Self {
        match format {
            OtpFormat::OtpauthUri => Self::OtpauthUri,
            OtpFormat::KeePassXcLegacy => Self::KeePassXcLegacy,
            OtpFormat::KeePass2 => Self::KeePass2,
        }
    }
}

impl From<OtpProblem> for OtpProblemRecord {
    fn from(problem: OtpProblem) -> Self {
        match problem {
            OtpProblem::NotAnOtpauthUri => Self::NotAnOtpauthUri,
            OtpProblem::EmptySecret => Self::EmptySecret,
            OtpProblem::InvalidSettings => Self::InvalidSettings,
            OtpProblem::InvalidPeriod => Self::InvalidPeriod,
            OtpProblem::InvalidDigits => Self::InvalidDigits,
            OtpProblem::UnknownAlgorithm => Self::UnknownAlgorithm,
        }
    }
}

impl OtpRecord {
    fn of(otp: &Otp<OtpUri>, file: &str) -> Self {
        match otp {
            Otp::Absent => Self::Absent,
            Otp::Present(_) => Self::Present {
                file: file.to_owned(),
            },
            Otp::Unrecognised(OtpIssue { format, problem }) => Self::Unrecognised {
                format: (*format).into(),
                problem: (*problem).into(),
            },
        }
    }
}

/// Everything `meta.json` says.
///
/// `fields` and `attachments` map the name a value has in the database (`UserName`, a custom
/// attribute's key, an attachment's file name) to its file's path relative to the entry
/// directory; the file name is a sanitised form of the key, so the map is how to find it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntryMeta {
    pub uuid: Uuid,
    /// `Group/Sub/Title` as stored in the database, placeholders unresolved; an entry without a
    /// title ends in `(no title)`.
    pub path: String,
    pub tags: Vec<String>,
    pub eligibility: EligibilityRecord,
    /// The session's expiry when the entry was written. The session record governs deletion and
    /// can be earlier ([`Validity`]).
    pub validity: Validity,
    pub fields: BTreeMap<String, String>,
    pub attachments: BTreeMap<String, String>,
    pub otp: OtpRecord,
    /// The fields whose value still holds a placeholder that could not be resolved, `{REF:…}`
    /// or any other kind.
    pub unresolved: Vec<String>,
}

impl EntryMeta {
    /// `fields` and `attachments` are the writer's name-to-file maps; `otp_file` is where the
    /// TOTP URI goes when there is one.
    pub(crate) fn new(
        entry: &ResolvedEntry,
        validity: &Validity,
        fields: BTreeMap<String, String>,
        attachments: BTreeMap<String, String>,
        otp_file: &str,
    ) -> Self {
        Self {
            uuid: entry.uuid(),
            path: entry.label().path(),
            tags: entry
                .tags()
                .as_slice()
                .iter()
                .map(|tag| tag.name().to_owned())
                .collect(),
            eligibility: entry.eligibility().into(),
            validity: *validity,
            fields,
            attachments,
            otp: OtpRecord::of(entry.otp(), otp_file),
            unresolved: entry
                .unresolved()
                .iter()
                .map(|name: &FieldName| name.key().to_owned())
                .collect(),
        }
    }

    /// The bytes of `meta.json`.
    ///
    /// # Errors
    /// The serialiser refuses, which it does not for these types.
    pub(crate) fn to_json(&self) -> Result<Vec<u8>, serde_json::Error> {
        let mut json = serde_json::to_vec_pretty(&MetaFile::from(self))?;
        json.push(b'\n');
        Ok(json)
    }
}

/// The stored shape of `meta.json`; [`EntryMeta`] is what it is parsed into. The record enums
/// ([`EligibilityRecord`], [`OtpRecord`]) are plain sums of what is stored, so they are shared
/// by both.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MetaFile {
    version: SchemaVersion<META_VERSION>,
    #[serde(with = "uuid_hex")]
    uuid: Uuid,
    path: String,
    tags: Vec<String>,
    eligibility: EligibilityRecord,
    exported_at: Timestamp,
    expires_at: Timestamp,
    fields: BTreeMap<String, String>,
    attachments: BTreeMap<String, String>,
    otp: OtpRecord,
    unresolved: Vec<String>,
}

impl From<&EntryMeta> for MetaFile {
    fn from(meta: &EntryMeta) -> Self {
        Self {
            version: SchemaVersion,
            uuid: meta.uuid,
            path: meta.path.clone(),
            tags: meta.tags.clone(),
            eligibility: meta.eligibility.clone(),
            exported_at: meta.validity.exported_at(),
            expires_at: meta.validity.expires_at(),
            fields: meta.fields.clone(),
            attachments: meta.attachments.clone(),
            otp: meta.otp.clone(),
            unresolved: meta.unresolved.clone(),
        }
    }
}

impl TryFrom<MetaFile> for EntryMeta {
    type Error = ValidityError;

    fn try_from(file: MetaFile) -> Result<Self, ValidityError> {
        Ok(Self {
            uuid: file.uuid,
            path: file.path,
            tags: file.tags,
            eligibility: file.eligibility,
            validity: Validity::new(file.exported_at, file.expires_at)?,
            fields: file.fields,
            attachments: file.attachments,
            otp: file.otp,
            unresolved: file.unresolved,
        })
    }
}

mod uuid_hex {
    use super::{Deserialize, Deserializer, Serializer, Uuid};

    pub(super) fn serialize<S: Serializer>(uuid: &Uuid, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(uuid)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Uuid, D::Error> {
        let text = String::deserialize(deserializer)?;
        Uuid::parse_hex(&text)
            .ok_or_else(|| serde::de::Error::custom("uuid must be 32 hexadecimal digits"))
    }
}

// --- Reading back -----------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum MetaError {
    #[error("{}: {source}", .path.display())]
    Io { path: PathBuf, source: io::Error },
    #[error("{} is larger than {META_BYTES_MAX} bytes", .path.display())]
    TooLarge { path: PathBuf },
    #[error("{}: {source}", .path.display())]
    Parse {
        path: PathBuf,
        source: serde_json::Error,
    },
    #[error("{}: {source}", .path.display())]
    Validity {
        path: PathBuf,
        source: ValidityError,
    },
}

/// Parses `<entry>/meta.json`. A symlink in its place is refused.
///
/// # Errors
/// The file is missing, unreadable, over 1 MiB, not valid `meta.json` of the current schema, or
/// has an expiry that is not after its export time.
pub fn read(dir: &EntryDir) -> Result<EntryMeta, MetaError> {
    let path = dir.path().join(META_FILE);
    let io_error = |source| MetaError::Io {
        path: path.clone(),
        source,
    };
    let text = read_bounded(&path, META_BYTES_MAX).map_err(|error| match error {
        BoundedReadError::Io(source) => io_error(source),
        BoundedReadError::TooLarge { .. } => MetaError::TooLarge { path: path.clone() },
    })?;
    let file: MetaFile = serde_json::from_slice(&text).map_err(|source| MetaError::Parse {
        path: path.clone(),
        source,
    })?;
    EntryMeta::try_from(file).map_err(|source| MetaError::Validity { path, source })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> EntryMeta {
        EntryMeta {
            uuid: Uuid::parse_hex("00112233445566778899aabbccddeeff").unwrap(),
            path: "Work/Sub/Title".into(),
            tags: vec!["agent".into()],
            eligibility: EligibilityRecord::Tagged {
                tag: "agent".into(),
            },
            validity: Validity::new(
                "2026-01-02T03:04:05Z".parse().unwrap(),
                "2026-01-02T04:04:05Z".parse().unwrap(),
            )
            .unwrap(),
            fields: BTreeMap::from([("Title".into(), "title".into())]),
            attachments: BTreeMap::new(),
            otp: OtpRecord::Unrecognised {
                format: OtpFormatRecord::KeePass2,
                problem: OtpProblemRecord::InvalidPeriod,
            },
            unresolved: vec!["Notes".into()],
        }
    }

    #[test]
    fn the_stored_shape_is_pinned() {
        // A contract: `ls` and later versions read this. Written by hand from the schema.
        let expected = r#"{
  "version": 1,
  "uuid": "00112233445566778899aabbccddeeff",
  "path": "Work/Sub/Title",
  "tags": ["agent"],
  "eligibility": {"rule": "tagged", "tag": "agent"},
  "exported_at": "2026-01-02T03:04:05Z",
  "expires_at": "2026-01-02T04:04:05Z",
  "fields": {"Title": "title"},
  "attachments": {},
  "otp": {"state": "unrecognised", "format": "keepass2", "problem": "invalid_period"},
  "unresolved": ["Notes"]
}"#;
        let stored: serde_json::Value =
            serde_json::from_slice(&sample().to_json().unwrap()).unwrap();
        assert_eq!(
            stored,
            serde_json::from_str::<serde_json::Value>(expected).unwrap()
        );
        let back = EntryMeta::try_from(serde_json::from_value::<MetaFile>(stored).unwrap());
        assert_eq!(back.unwrap(), sample());
    }

    #[test]
    fn a_different_version_an_unknown_key_or_backwards_times_are_refused() {
        let stored = serde_json::to_value(MetaFile::from(&sample())).unwrap();
        assert!(serde_json::from_value::<MetaFile>(stored.clone()).is_ok());
        let mut other_version = stored.clone();
        other_version["version"] = 2.into();
        assert!(serde_json::from_value::<MetaFile>(other_version).is_err());
        let mut unknown_key = stored.clone();
        unknown_key["password"] = "x".into();
        assert!(serde_json::from_value::<MetaFile>(unknown_key).is_err());
        let mut backwards = stored;
        backwards["expires_at"] = backwards["exported_at"].clone();
        let file = serde_json::from_value::<MetaFile>(backwards).unwrap();
        assert!(EntryMeta::try_from(file).is_err());
    }

    #[test]
    fn validity_orders_its_times() {
        let early: Timestamp = "2026-01-01T00:00:00Z".parse().unwrap();
        let late: Timestamp = "2026-01-01T00:00:01Z".parse().unwrap();
        assert!(Validity::new(early, late).is_ok());
        assert!(Validity::new(late, early).is_err());
        assert!(Validity::new(early, early).is_err());
    }
}
