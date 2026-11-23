//! The database as exported: entries with their identity, fields, TOTP, attachments and history.
//!
//! Every value here is built by [`crate::export`]; constructors are crate-private, so holding an
//! [`Entry`] means its fields went through the boundary parse.

use std::borrow::Borrow;
use std::collections::{BTreeMap, HashMap};
use std::fmt;

use crate::otp::{Otp, TotpSource};
use crate::secret::SecretBytes;
use crate::text::hex_digit;

/// An entry's or group's UUID: 16 bytes, stored base64 in the XML and written as 32 hex digits in
/// `{REF:…@I:…}` placeholders.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Uuid([u8; 16]);

impl Uuid {
    pub(crate) fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Parses the 32-hex-digit form, either case.
    #[must_use]
    pub fn parse_hex(text: &str) -> Option<Self> {
        let digits = text.as_bytes();
        if digits.len() != 32 {
            return None;
        }
        let mut bytes = [0u8; 16];
        for (byte, pair) in bytes.iter_mut().zip(digits.chunks_exact(2)) {
            let [high, low] = pair else { return None };
            *byte = (hex_digit(*high)? << 4) | hex_digit(*low)?;
        }
        Some(Self(bytes))
    }

    #[must_use]
    pub fn is_nil(&self) -> bool {
        self.0 == [0u8; 16]
    }
}

/// Lower-case, 32 hex digits, no dashes.
impl fmt::Display for Uuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|byte| write!(f, "{byte:02x}"))
    }
}

impl fmt::Debug for Uuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Uuid({self})")
    }
}

/// The names of the groups holding an entry, outermost first, without the root group.
///
/// The root group is left out because it is the database itself — KeePassXC names it after the
/// database, and `keepassxc-cli ls`/`show` paths start below it — so `Work/Sub` is the same path
/// whatever the database is called. An entry directly in the root has an empty path.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GroupPath(Vec<String>);

impl GroupPath {
    pub(crate) fn child(&self, name: String) -> Self {
        let mut names = self.0.clone();
        names.push(name);
        Self(names)
    }

    #[must_use]
    pub fn names(&self) -> &[String] {
        &self.0
    }
}

/// What separates tags in `<Tags>`: `,` is what keepassxc-cli exports, `;` what KeePassXC also
/// accepts.
const TAG_SEPARATORS: [char; 2] = [',', ';'];

/// One tag as the database spells it, with its case-folded form for matching: non-empty, trimmed,
/// free of separators.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tag {
    name: String,
    folded: String,
}

impl Tag {
    /// Trims `name`; `None` when nothing is left or it holds a separator. Tags are labels, not
    /// secrets, so they need not stay byte-exact.
    pub(crate) fn parse(name: &str) -> Option<Self> {
        let name = name.trim();
        if name.is_empty() || name.contains(TAG_SEPARATORS) {
            return None;
        }
        Some(Self {
            name: name.to_owned(),
            folded: name.to_lowercase(),
        })
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Whether the two are the same tag, ignoring case.
    pub(crate) fn matches(&self, other: &Tag) -> bool {
        self.folded == other.folded
    }
}

/// An entry's tags, in the order the database lists them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Tags(Vec<Tag>);

impl Tags {
    /// Splits on either separator and drops the pieces that are empty after trimming.
    pub(crate) fn parse(text: &str) -> Self {
        Self(text.split(TAG_SEPARATORS).filter_map(Tag::parse).collect())
    }

    #[must_use]
    pub fn as_slice(&self) -> &[Tag] {
        &self.0
    }
}

/// The five fields every KeePass entry has a slot for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StandardField {
    Title,
    UserName,
    Password,
    Url,
    Notes,
}

impl StandardField {
    pub const ALL: [Self; 5] = [
        Self::Title,
        Self::UserName,
        Self::Password,
        Self::Url,
        Self::Notes,
    ];

    /// The `<Key>` this field has in the XML.
    #[must_use]
    pub fn key(self) -> &'static str {
        match self {
            Self::Title => "Title",
            Self::UserName => "UserName",
            Self::Password => "Password",
            Self::Url => "URL",
            Self::Notes => "Notes",
        }
    }

    pub(crate) fn from_key(key: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|field| field.key() == key)
    }
}

/// The name of a custom attribute: a `<String>` key that is not a [`StandardField`]'s. Built only
/// by [`FieldName::parse`].
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AttributeName(String);

impl AttributeName {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Lets a [`CustomAttributes`] map be looked up by `&str`; consistent with the derived `Ord`,
/// which compares the inner `String`.
impl Borrow<str> for AttributeName {
    fn borrow(&self) -> &str {
        &self.0
    }
}

/// Names any value-carrying field of an entry, e.g. to record which still hold placeholders.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FieldName {
    Standard(StandardField),
    Custom(AttributeName),
}

impl FieldName {
    /// Classifies a `<String>` key; keys are case-sensitive, as in KeePass.
    pub(crate) fn parse(key: String) -> Self {
        match StandardField::from_key(&key) {
            Some(field) => Self::Standard(field),
            None => Self::Custom(AttributeName(key)),
        }
    }

    /// The `<Key>` this field has in the XML.
    #[must_use]
    pub fn key(&self) -> &str {
        match self {
            Self::Standard(field) => field.key(),
            Self::Custom(name) => name.as_str(),
        }
    }
}

/// The standard fields an entry carries; `None` means the XML had no `<String>` for it, which is
/// different from one with an empty value.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StandardFields {
    title: Option<SecretBytes>,
    user_name: Option<SecretBytes>,
    password: Option<SecretBytes>,
    url: Option<SecretBytes>,
    notes: Option<SecretBytes>,
}

impl StandardFields {
    #[must_use]
    pub fn get(&self, field: StandardField) -> Option<&SecretBytes> {
        match field {
            StandardField::Title => self.title.as_ref(),
            StandardField::UserName => self.user_name.as_ref(),
            StandardField::Password => self.password.as_ref(),
            StandardField::Url => self.url.as_ref(),
            StandardField::Notes => self.notes.as_ref(),
        }
    }

    /// Returns the value the field held before, if any.
    pub(crate) fn set(&mut self, field: StandardField, value: SecretBytes) -> Option<SecretBytes> {
        self.slot_mut(field).replace(value)
    }

    fn slot_mut(&mut self, field: StandardField) -> &mut Option<SecretBytes> {
        match field {
            StandardField::Title => &mut self.title,
            StandardField::UserName => &mut self.user_name,
            StandardField::Password => &mut self.password,
            StandardField::Url => &mut self.url,
            StandardField::Notes => &mut self.notes,
        }
    }
}

/// Custom attributes by name; the map makes a duplicate name unrepresentable.
pub type CustomAttributes = BTreeMap<AttributeName, SecretBytes>;

/// An entry's attachments as the export carries them, which depends on the database's format:
/// for KDBX 3.1 `keepassxc-cli export -f xml` includes every attachment's bytes; for KDBX 4 it
/// names the attachments but includes none of their bytes (keepassxc-cli 2.8), and
/// `keepassxc-cli attachment-export` reads them one at a time.
#[derive(Clone, Debug)]
pub enum Attachments {
    Exported(Vec<Attachment>),
    NamedOnly(Vec<String>),
}

impl Attachments {
    /// The attachments' names, in the order the export lists them, whichever form it took.
    #[must_use]
    pub fn names(&self) -> Vec<&str> {
        match self {
            Self::Exported(attachments) => attachments.iter().map(Attachment::name).collect(),
            Self::NamedOnly(names) => names.iter().map(String::as_str).collect(),
        }
    }
}

/// An entry's older versions as the export lists them, oldest first: only when each was last
/// modified, never their fields. KeePassXC appends a version each time it changes an entry, and
/// drops the oldest ones beyond the database's history limits; `import` reads this to tell that
/// nothing was dropped.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct History(Vec<HistoryItem>);

impl History {
    pub(crate) fn new(items: Vec<HistoryItem>) -> Self {
        Self(items)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Whether every version in `older` is still here, in the same place: what is left when
    /// versions were only appended.
    #[must_use]
    pub fn extends(&self, older: &Self) -> bool {
        self.0.starts_with(&older.0)
    }
}

/// One older version of an entry, known by its `<Times><LastModificationTime>` exactly as the
/// export writes it (compared, never interpreted); `None` when the export has none, which
/// keepassxc-cli never writes but a hand-written document may.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoryItem {
    last_modified: Option<String>,
}

impl HistoryItem {
    pub(crate) fn new(last_modified: Option<String>) -> Self {
        Self { last_modified }
    }
}

/// A file attached to an entry, decoded and decompressed.
#[derive(Clone, Debug)]
pub struct Attachment {
    name: String,
    content: SecretBytes,
}

impl Attachment {
    pub(crate) fn new(name: String, content: SecretBytes) -> Self {
        Self { name, content }
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn content(&self) -> &SecretBytes {
        &self.content
    }
}

/// Whether an entry sits in the database's recycle bin (or a group below it).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Location {
    Live,
    RecycleBin,
}

/// An entry as stored: field values are raw, placeholders not yet resolved.
#[derive(Debug)]
pub struct Entry {
    pub(crate) uuid: Uuid,
    pub(crate) groups: GroupPath,
    pub(crate) tags: Tags,
    pub(crate) location: Location,
    pub(crate) fields: StandardFields,
    pub(crate) custom: CustomAttributes,
    pub(crate) otp: Otp<TotpSource>,
    pub(crate) attachments: Attachments,
    pub(crate) history: History,
}

impl Entry {
    #[must_use]
    pub fn uuid(&self) -> Uuid {
        self.uuid
    }

    #[must_use]
    pub fn groups(&self) -> &GroupPath {
        &self.groups
    }

    #[must_use]
    pub fn tags(&self) -> &Tags {
        &self.tags
    }

    #[must_use]
    pub fn location(&self) -> Location {
        self.location
    }

    #[must_use]
    pub fn fields(&self) -> &StandardFields {
        &self.fields
    }

    #[must_use]
    pub fn custom(&self) -> &CustomAttributes {
        &self.custom
    }

    #[must_use]
    pub fn otp(&self) -> &Otp<TotpSource> {
        &self.otp
    }

    #[must_use]
    pub fn attachments(&self) -> &Attachments {
        &self.attachments
    }

    #[must_use]
    pub fn history(&self) -> &History {
        &self.history
    }
}

/// Every current entry of a database, in document order; history versions are not entries.
/// And every group, the root (an empty path) included, with or without entries.
#[derive(Debug)]
pub struct Database {
    entries: Vec<Entry>,
    by_uuid: HashMap<Uuid, usize>,
    groups: Vec<(GroupPath, Location)>,
}

impl Database {
    /// `Err` carries the first UUID that two entries share.
    pub(crate) fn new(
        entries: Vec<Entry>,
        groups: Vec<(GroupPath, Location)>,
    ) -> Result<Self, Uuid> {
        let mut by_uuid = HashMap::with_capacity(entries.len());
        for (index, entry) in entries.iter().enumerate() {
            if by_uuid.insert(entry.uuid, index).is_some() {
                return Err(entry.uuid);
            }
        }
        Ok(Self {
            entries,
            by_uuid,
            groups,
        })
    }

    /// Whether a group outside the recycle bin has the path `names`, outermost first, compared
    /// exactly, as `keepassxc-cli add` finds the group of a new entry. The root, `[]`, always
    /// has.
    #[must_use]
    pub fn has_live_group(&self, names: &[String]) -> bool {
        self.groups
            .iter()
            .any(|(path, location)| *location == Location::Live && path.names() == names)
    }

    #[must_use]
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    #[must_use]
    pub fn entry(&self, uuid: Uuid) -> Option<&Entry> {
        self.by_uuid
            .get(&uuid)
            .and_then(|&index| self.entries.get(index))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid_hex_round_trip_either_case() {
        let uuid = Uuid::parse_hex("00112233445566778899AABBCCDDEEFF").unwrap();
        assert_eq!(uuid.to_string(), "00112233445566778899aabbccddeeff");
        assert_eq!(
            Uuid::parse_hex("00112233445566778899aabbccddeeff"),
            Some(uuid)
        );
    }

    #[test]
    fn uuid_hex_rejects_wrong_length_and_non_hex() {
        assert_eq!(Uuid::parse_hex("0011"), None);
        assert_eq!(Uuid::parse_hex("g0112233445566778899aabbccddeeff"), None);
        assert_eq!(Uuid::parse_hex("+0112233445566778899aabbccddeeff"), None);
    }

    #[test]
    fn tags_split_on_both_separators_and_drop_empties() {
        let tags = Tags::parse("ops; agent,,Work ;");
        let names: Vec<&str> = tags.as_slice().iter().map(Tag::name).collect();
        assert_eq!(names, ["ops", "agent", "Work"]);
    }
}
