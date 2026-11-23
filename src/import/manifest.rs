//! `manifest.json`, the agent's description of what it staged, parsed into a [`Manifest`].
//!
//! The wire shape is two JSON objects told apart by `kind`:
//!
//! ```json
//! {"kind": "new", "entry": "Group/Title", "username": "u", "url": "https://…",
//!  "password": "password-file", "attachments": {"name in KeePassXC": "file"}}
//! {"kind": "existing", "entry": "Group/Title", "attachments": {"name in KeePassXC": "file"}}
//! ```
//!
//! Every value is checked here, before anything is read or decrypted: the entry path, the
//! attachment names and the plain fields by their own types, and the file names as
//! [`SafeName`]s, each named once; the result is a [`Plan`] naming the files. The manifest holds
//! names, never secrets, but a careless agent may still write a secret where a file name or an
//! unknown key belongs, so no error repeats the password's file name or anything of the JSON
//! but the names of keys this schema defines.

use std::fmt;

use serde::Deserialize;
use serde::de::{Deserializer, MapAccess, Visitor};

use super::plan::{Attachment, Contents, Kind, NonEmpty, Password, Plan, PlanError, Role};
use crate::layout::SafeName;
use crate::select::CliEntryPath;

/// The manifest's name in the staging directory.
pub const MANIFEST_FILE: &str = "manifest.json";

/// Bound on `manifest.json`: names and a few short fields, never content.
pub(super) const MANIFEST_BYTES_MAX: u64 = 64 * 1024;

/// Bound on an entry path; any real group path and title fit many times over.
const ENTRY_PATH_BYTES_MAX: usize = 4096;

/// KeePassXC keeps attachment names as entered; 255 bytes is a file name's limit on Linux, where
/// the attachment may one day be saved.
pub const ATTACHMENT_NAME_BYTES_MAX: usize = 255;

/// Bound on a user name or URL.
pub const FIELD_TEXT_BYTES_MAX: usize = 1024;

// --- Values -----------------------------------------------------------------------------------

/// Why a name or field value from the manifest is refused. Never carries the value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TextError {
    #[error("is empty; leave it out instead")]
    Empty,
    #[error("is {found} bytes, more than the {max} allowed")]
    TooLong { found: usize, max: usize },
    #[error("holds a control character")]
    ControlCharacter,
    #[error("has an empty group or title between its '/'s")]
    EmptySegment,
    #[error(
        "holds a user name or password before '@' in its host part; keepassxc-cli gets the URL as a program argument, which other users can read"
    )]
    UserInfo,
}

/// `text` is 1 to `max` bytes without control characters.
fn check_text(text: &str, max: usize) -> Result<(), TextError> {
    if text.is_empty() {
        return Err(TextError::Empty);
    }
    if text.len() > max {
        return Err(TextError::TooLong {
            found: text.len(),
            max,
        });
    }
    if text.chars().any(char::is_control) {
        return Err(TextError::ControlCharacter);
    }
    Ok(())
}

/// Where the entry is: `Group/…/Title`, each part non-empty and free of control characters. A
/// `/` always separates, so a group or title holding one cannot be named. Displayed as written.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntryPath {
    groups: Vec<String>,
    title: String,
}

impl EntryPath {
    /// # Errors
    /// `text` is empty, too long, holds a control character or has an empty part.
    pub fn parse(text: &str) -> Result<Self, TextError> {
        check_text(text, ENTRY_PATH_BYTES_MAX)?;
        let mut parts: Vec<String> = text.split('/').map(str::to_owned).collect();
        if parts.iter().any(String::is_empty) {
            return Err(TextError::EmptySegment);
        }
        let title = parts.pop().ok_or(TextError::Empty)?;
        Ok(Self {
            groups: parts,
            title,
        })
    }

    #[must_use]
    pub fn groups(&self) -> &[String] {
        &self.groups
    }

    #[must_use]
    pub fn title(&self) -> &str {
        &self.title
    }

    /// The string keepassxc-cli finds this entry by, and the path [`crate::Database::entries_at`]
    /// compares.
    #[must_use]
    pub fn cli_path(&self) -> CliEntryPath {
        CliEntryPath::new(&self.groups, &self.title)
    }
}

impl fmt::Display for EntryPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for group in &self.groups {
            write!(f, "{group}/")?;
        }
        f.write_str(&self.title)
    }
}

/// An attachment's name in KeePassXC: 1 to [`ATTACHMENT_NAME_BYTES_MAX`] bytes of UTF-8, no
/// control characters, so it can be shown on one line.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct AttachmentName(String);

impl AttachmentName {
    /// # Errors
    /// `name` is empty, too long or holds a control character.
    pub fn parse(name: &str) -> Result<Self, TextError> {
        check_text(name, ATTACHMENT_NAME_BYTES_MAX)?;
        Ok(Self(name.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AttachmentName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A user name: 1 to [`FIELD_TEXT_BYTES_MAX`] bytes, no control characters; absent is empty.
/// Not secret: the confirmation shows it, and keepassxc-cli gets it as a program argument.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldText(String);

impl FieldText {
    /// # Errors
    /// `text` is empty, too long or holds a control character.
    pub fn parse(text: &str) -> Result<Self, TextError> {
        check_text(text, FIELD_TEXT_BYTES_MAX)?;
        Ok(Self(text.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A URL, as a [`FieldText`] whose host part (after `scheme://`, up to the first `/`, `?` or `#`)
/// holds no `@`: credentials there (`https://user:pass@host/`) would reach keepassxc-cli's
/// argument list, which every user on the machine can read. Text without `://` is not checked
/// further; KeePass URLs need not be URLs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntryUrl(FieldText);

impl EntryUrl {
    /// # Errors
    /// As [`FieldText::parse`], or [`TextError::UserInfo`].
    pub fn parse(text: &str) -> Result<Self, TextError> {
        let text = FieldText::parse(text)?;
        if let Some((_scheme, rest)) = text.as_str().split_once("://") {
            let host = rest.split(['/', '?', '#']).next().unwrap_or_default();
            if host.contains('@') {
                return Err(TextError::UserInfo);
            }
        }
        Ok(Self(text))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

// --- The manifest -----------------------------------------------------------------------------

/// What is to be imported, naming the files that hold the secrets: the password's file and each
/// attachment's, none of them read yet.
pub type Manifest = Plan<(), ()>;

#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    #[error("{MANIFEST_FILE}: {0}")]
    Json(JsonProblem),
    #[error("{MANIFEST_FILE}: the entry path {0}")]
    Entry(TextError),
    #[error("{MANIFEST_FILE}: the username {0}")]
    Username(TextError),
    #[error("{MANIFEST_FILE}: the url {0}")]
    Url(TextError),
    #[error("{MANIFEST_FILE}: the name of attachment number {position} {source}")]
    AttachmentName { position: usize, source: TextError },
    #[error("{MANIFEST_FILE}: {0}")]
    Plan(#[from] PlanError),
    #[error(
        "{MANIFEST_FILE}: the file of {0} is not a plain file name (letters, digits, '.', '-', '_', not starting with '.')"
    )]
    FileName(Role),
    #[error("{MANIFEST_FILE}: the file of {0} is the manifest itself")]
    FileIsManifest(Role),
    #[error("{MANIFEST_FILE}: a new entry needs a password, an attachment or both")]
    NothingForNewEntry,
    #[error("{MANIFEST_FILE}: an existing entry needs at least one attachment")]
    NoAttachments,
}

/// Where in `manifest.json` serde found a problem, when it knows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Position {
    pub line: usize,
    pub column: usize,
}

impl fmt::Display for Position {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, " at line {} column {}", self.line, self.column)
    }
}

/// [`Position`] or nothing: serde reports line 0 when it has no position.
struct At(Option<Position>);

impl fmt::Display for At {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(position) => position.fmt(f),
            None => Ok(()),
        }
    }
}

/// What was wrong with the JSON, in fixed words: serde's own messages can quote a value or an
/// unknown key, and only one naming a key of this schema is kept.
#[derive(Debug, thiserror::Error)]
pub enum JsonProblem {
    #[error("not valid JSON{}", At(*.0))]
    Syntax(Option<Position>),
    #[error("a key this manifest does not have{}; the keys are kind, entry, username, url, password and attachments, and an existing entry takes only kind, entry and attachments", At(*.0))]
    UnknownKey(Option<Position>),
    #[error("\"kind\" is neither \"new\" nor \"existing\"{}", At(*.0))]
    UnknownKind(Option<Position>),
    #[error("the key {key:?} {problem}{}", At(*.position))]
    SchemaKey {
        key: &'static str,
        problem: KeyProblem,
        position: Option<Position>,
    },
    #[error("not a manifest's shape{}; see `kpx-share import --help`", At(*.0))]
    Shape(Option<Position>),
}

/// What is wrong with a key this schema defines.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum KeyProblem {
    #[error("is missing")]
    Missing,
    #[error("is given twice")]
    Twice,
}

impl KeyProblem {
    /// How serde's message for this problem starts, the key following in backquotes.
    fn serde_prefix(self) -> &'static str {
        match self {
            Self::Missing => "missing field `",
            Self::Twice => "duplicate field `",
        }
    }
}

impl JsonProblem {
    fn of(error: &serde_json::Error) -> Self {
        /// The keys this schema defines, the only names a message may hold.
        const KEYS: [&str; 6] = [
            "kind",
            "entry",
            "username",
            "url",
            "password",
            "attachments",
        ];
        let position = (error.line() > 0).then(|| Position {
            line: error.line(),
            column: error.column(),
        });
        match error.classify() {
            serde_json::error::Category::Data => {
                let message = error.to_string();
                let schema_key = [KeyProblem::Missing, KeyProblem::Twice]
                    .into_iter()
                    .find_map(|problem| {
                        let rest = message.strip_prefix(problem.serde_prefix())?;
                        let named = rest.split('`').next()?;
                        let key = KEYS.into_iter().find(|key| *key == named)?;
                        Some((key, problem))
                    });
                if message.starts_with("unknown field") {
                    Self::UnknownKey(position)
                } else if message.starts_with("unknown variant") {
                    Self::UnknownKind(position)
                } else if let Some((key, problem)) = schema_key {
                    Self::SchemaKey {
                        key,
                        problem,
                        position,
                    }
                } else {
                    Self::Shape(position)
                }
            }
            serde_json::error::Category::Syntax
            | serde_json::error::Category::Eof
            | serde_json::error::Category::Io => Self::Syntax(position),
        }
    }
}

/// Parses and checks the bytes of `manifest.json`.
///
/// # Errors
/// See [`ManifestError`].
pub fn parse(json: &[u8]) -> Result<Manifest, ManifestError> {
    let wire: WireManifest = serde_json::from_slice(json)
        .map_err(|error| ManifestError::Json(JsonProblem::of(&error)))?;
    let manifest = match wire {
        WireManifest::New {
            entry,
            username,
            url,
            password,
            attachments,
        } => {
            let entry = EntryPath::parse(&entry).map_err(ManifestError::Entry)?;
            let username = username
                .as_deref()
                .map(FieldText::parse)
                .transpose()
                .map_err(ManifestError::Username)?;
            let url = url
                .as_deref()
                .map(EntryUrl::parse)
                .transpose()
                .map_err(ManifestError::Url)?;
            let password = password
                .as_deref()
                .map(|file| file_name(file, Role::Password))
                .transpose()?;
            let attachments = attachment_files(attachments)?;
            let contents = match password {
                Some(file) => Contents::WithPassword {
                    password: Password::new(file, ()),
                    attachments,
                },
                None => Contents::AttachmentsOnly(
                    NonEmpty::new(attachments).ok_or(ManifestError::NothingForNewEntry)?,
                ),
            };
            Plan::new(
                entry,
                Kind::New {
                    username,
                    url,
                    contents,
                },
            )?
        }
        WireManifest::Existing { entry, attachments } => {
            let entry = EntryPath::parse(&entry).map_err(ManifestError::Entry)?;
            let attachments = NonEmpty::new(attachment_files(attachments)?)
                .ok_or(ManifestError::NoAttachments)?;
            Plan::new(entry, Kind::Existing(attachments))?
        }
    };
    Ok(manifest)
}

fn file_name(file: &str, role: Role) -> Result<SafeName, ManifestError> {
    let Some(name) = SafeName::parse(file) else {
        return Err(ManifestError::FileName(role));
    };
    if name.as_str() == MANIFEST_FILE {
        return Err(ManifestError::FileIsManifest(role));
    }
    Ok(name)
}

/// The attachments in the manifest's order; [`Plan::new`] refuses a name or a file twice.
fn attachment_files(wire: WireAttachments) -> Result<Vec<Attachment<()>>, ManifestError> {
    wire.0
        .into_iter()
        .enumerate()
        .map(|(index, (name, file))| {
            let name =
                AttachmentName::parse(&name).map_err(|source| ManifestError::AttachmentName {
                    position: index + 1,
                    source,
                })?;
            let file = file_name(&file, Role::Attachment(name.clone()))?;
            Ok(Attachment::new(name, file, ()))
        })
        .collect()
}

// --- Wire shape -------------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
enum WireManifest {
    New {
        entry: String,
        username: Option<String>,
        url: Option<String>,
        password: Option<String>,
        #[serde(default)]
        attachments: WireAttachments,
    },
    Existing {
        entry: String,
        attachments: WireAttachments,
    },
}

/// The `attachments` object as its pairs, in order and with any repeated key kept, so a repeat
/// is refused rather than silently won by the last.
#[derive(Default)]
struct WireAttachments(Vec<(String, String)>);

impl<'de> Deserialize<'de> for WireAttachments {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Pairs;
        impl<'de> Visitor<'de> for Pairs {
            type Value = WireAttachments;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an object of attachment names to file names")
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
                let mut pairs = Vec::new();
                while let Some(pair) = map.next_entry::<String, String>()? {
                    pairs.push(pair);
                }
                Ok(WireAttachments(pairs))
            }
        }
        deserializer.deserialize_map(Pairs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refused(json: &str) -> ManifestError {
        parse(json.as_bytes()).unwrap_err()
    }

    /// Both kinds parse into exactly what they say, attachments in order. Red when `kind` is not
    /// what tells the two apart, or the attachment pairs are reordered.
    #[test]
    fn both_kinds_parse_with_their_fields() {
        let new = parse(
            br#"{"entry":"Ops/Certs/hvac","kind":"new","username":"u","url":"https://x",
                "password":"pw","attachments":{"b.pem":"b","a.pem":"a"}}"#,
        )
        .unwrap();
        assert_eq!(new.entry().groups(), ["Ops", "Certs"]);
        assert_eq!(new.entry().title(), "hvac");
        assert_eq!(new.entry().to_string(), "Ops/Certs/hvac");
        assert_eq!(new.entry().cli_path().as_str(), "/Ops/Certs/hvac");
        match new.kind() {
            Kind::New { username, url, .. } => {
                assert_eq!(username.as_ref().map(FieldText::as_str), Some("u"));
                assert_eq!(url.as_ref().map(EntryUrl::as_str), Some("https://x"));
            }
            Kind::Existing(_) => panic!("new parsed as existing"),
        }
        assert_eq!(
            new.password().map(|password| password.file().as_str()),
            Some("pw")
        );
        let names: Vec<_> = new
            .attachments()
            .iter()
            .map(|a| (a.name().as_str(), a.file().as_str()))
            .collect();
        assert_eq!(names, [("b.pem", "b"), ("a.pem", "a")]);

        let existing =
            parse(br#"{"kind":"existing","entry":"hvac","attachments":{"x y":"f"}}"#).unwrap();
        assert!(matches!(existing.kind(), Kind::Existing(_)));
        assert_eq!(existing.entry().groups(), [] as [String; 0]);
        let attachments_only =
            parse(br#"{"kind":"new","entry":"G/T","attachments":{"a":"f"}}"#).unwrap();
        assert!(attachments_only.password().is_none());
    }

    /// An existing entry cannot be given fields, unknown keys are refused, and a new entry needs
    /// something to hold. Red when `deny_unknown_fields` is dropped, or when either "needs" rule
    /// is.
    #[test]
    fn unknown_keys_and_empty_imports_are_refused() {
        for json in [
            r#"{"kind":"existing","entry":"G/T","attachments":{"a":"f"},"password":"pw"}"#,
            r#"{"kind":"new","entry":"G/T","password":"pw","notes":"n"}"#,
            r#"{"kind":"new","entry":"G/T","password":"pw","tags":"agent"}"#,
        ] {
            assert!(
                matches!(
                    refused(json),
                    ManifestError::Json(JsonProblem::UnknownKey(_))
                ),
                "{json}"
            );
        }
        assert!(matches!(
            refused(r#"{"kind":"new","entry":"G/T"}"#),
            ManifestError::NothingForNewEntry
        ));
        assert!(matches!(
            refused(r#"{"kind":"new","entry":"G/T","attachments":{}}"#),
            ManifestError::NothingForNewEntry
        ));
        assert!(matches!(
            refused(r#"{"kind":"existing","entry":"G/T","attachments":{}}"#),
            ManifestError::NoAttachments
        ));
        assert!(matches!(
            refused(r#"{"kind":"replace","entry":"G/T"}"#),
            ManifestError::Json(JsonProblem::UnknownKind(_))
        ));
        let missing = refused(r#"{"kind":"new","password":"pw"}"#).to_string();
        assert!(
            missing.contains("the key \"entry\" is missing"),
            "{missing}"
        );
    }

    /// Each value rule, refused by name of the rule. Red when any one check is dropped.
    #[test]
    fn every_value_rule_refuses() {
        type Expected = fn(&ManifestError) -> bool;
        let new = |extra: &str| format!(r#"{{"kind":"new","entry":"G/T","password":"pw"{extra}}}"#);
        let cases: [(String, Expected); 17] = [
            (new(r#","username":"a\tb""#), |e| {
                matches!(e, ManifestError::Username(TextError::ControlCharacter))
            }),
            (new(r#","username":"""#), |e| {
                matches!(e, ManifestError::Username(TextError::Empty))
            }),
            (new(r#","url":"""#), |e| {
                matches!(e, ManifestError::Url(TextError::Empty))
            }),
            (new(&format!(r#","url":"{}""#, "u".repeat(1025))), |e| {
                matches!(
                    e,
                    ManifestError::Url(TextError::TooLong { found: 1025, .. })
                )
            }),
            (new(r#","url":"https://bob:pw@h/x""#), |e| {
                matches!(e, ManifestError::Url(TextError::UserInfo))
            }),
            (new(r#","url":"ssh://token@h""#), |e| {
                matches!(e, ManifestError::Url(TextError::UserInfo))
            }),
            (
                r#"{"kind":"new","entry":"G//T","password":"pw"}"#.into(),
                |e| matches!(e, ManifestError::Entry(TextError::EmptySegment)),
            ),
            (
                r#"{"kind":"new","entry":"G/T/","password":"pw"}"#.into(),
                |e| matches!(e, ManifestError::Entry(TextError::EmptySegment)),
            ),
            (r#"{"kind":"new","entry":"","password":"pw"}"#.into(), |e| {
                matches!(e, ManifestError::Entry(TextError::Empty))
            }),
            (
                r#"{"kind":"new","entry":"G/T\u0007","password":"pw"}"#.into(),
                |e| matches!(e, ManifestError::Entry(TextError::ControlCharacter)),
            ),
            (
                r#"{"kind":"new","entry":"G/T","password":"../pw"}"#.into(),
                |e| matches!(e, ManifestError::FileName(Role::Password)),
            ),
            (
                r#"{"kind":"new","entry":"G/T","password":"manifest.json"}"#.into(),
                |e| matches!(e, ManifestError::FileIsManifest(Role::Password)),
            ),
            (new(r#","attachments":{"":"f"}"#), |e| {
                matches!(
                    e,
                    ManifestError::AttachmentName {
                        position: 1,
                        source: TextError::Empty
                    }
                )
            }),
            (
                new(&format!(r#","attachments":{{"{}":"f"}}"#, "n".repeat(256))),
                |e| {
                    matches!(
                        e,
                        ManifestError::AttachmentName {
                            source: TextError::TooLong { found: 256, .. },
                            ..
                        }
                    )
                },
            ),
            (
                new(r#","attachments":{"a":"f","a":"g"}"#),
                |e| matches!(e, ManifestError::Plan(PlanError::AttachmentNamedTwice(name)) if name.as_str() == "a"),
            ),
            (new(r#","attachments":{"a":"pw"}"#), |e| {
                matches!(
                    e,
                    ManifestError::Plan(PlanError::FileNamedTwice(Role::Attachment(_)))
                )
            }),
            (new(r#","attachments":{"a":".hidden"}"#), |e| {
                matches!(e, ManifestError::FileName(Role::Attachment(_)))
            }),
        ];
        for (json, expected) in cases {
            let error = refused(&json);
            assert!(expected(&error), "{json} gave {error:?}");
        }
        for url in [
            "https://h/x@y",
            "https://h?u=a@b",
            "mailto:a@b",
            &"u".repeat(1024),
        ] {
            let json = new(&format!(r#","url":"{url}""#));
            assert!(parse(json.as_bytes()).is_ok(), "{url}");
        }
        let longest = "n".repeat(ATTACHMENT_NAME_BYTES_MAX);
        assert!(parse(new(&format!(r#","attachments":{{"{longest}":"f"}}"#)).as_bytes()).is_ok());
    }

    /// A value the agent put where a file name or a key belongs could be the secret itself: no
    /// message repeats the password's file name, a JSON value or an unknown key. Red when an
    /// error prints the field, or serde's message ("invalid type: string …", "unknown field
    /// `…`", "unknown variant `…`") is passed through.
    #[test]
    fn no_error_repeats_a_value_or_an_unknown_key() {
        for json in [
            r#"{"kind":"new","entry":"G/T","password":"hunter2 secret"}"#,
            r#"{"kind":"new","entry":"G/T","password":"hunter2","attachments":{"a":"hunter2"}}"#,
            r#"{"kind":"new","entry":"G/T","password":["hunter2"]}"#,
            r#"{"kind":"new","entry":"G/T","username":"hunter2","password":7}"#,
            r#"{"kind":"new","entry":"G/T","attachments":{"a":"hunter2 x"}}"#,
            r#"{"kind":"new","entry":"G/T","attachments":"hunter2"}"#,
            r#"{"kind":"new","entry":"G/T","attachments":{"a":["hunter2"]}}"#,
            r#"{"kind":"new","entry":"G/T","password":"hunter2"#,
            r#"{"kind":"new","entry":"G/T","password":"pw","hunter2":"x"}"#,
            r#"{"kind":"hunter2","entry":"G/T"}"#,
            r#"{"kind":"new","entry":"G/T","url":"https://u:hunter2@h"}"#,
        ] {
            let shown = refused(json).to_string();
            assert!(!shown.contains("hunter2"), "{json} gave {shown}");
        }
    }

    /// A position serde knows is shown as it is; one it does not is left out, never "line 0".
    /// Red when the position is always or never shown.
    #[test]
    fn a_json_error_shows_its_position_only_when_known() {
        let syntax = refused("{\n  \"kind\": \"new\",\n  oops\n}").to_string();
        assert!(
            syntax.contains("not valid JSON at line 3 column 3"),
            "{syntax}"
        );
        for json in [
            r#"{"kind":"replace","entry":"G/T"}"#,
            r#"{"kind":"new","entry":"G/T","password":"pw","x":1}"#,
        ] {
            let shown = refused(json).to_string();
            assert!(!shown.contains("line 0"), "{shown}");
        }
    }
}
