//! Which entries may be shared, the picker's list of them, and resolving the one picked.
//!
//! The only way to a [`ResolvedEntry`] is [`Eligible::resolve`], and the only ways to an
//! [`Eligible`] are [`Database::eligible`] and [`Database::pick`], which both apply the
//! [`Eligibility`] rule. So holding a `ResolvedEntry` proves its entry passed that rule, and the
//! rule it passed is recorded on it.

use std::collections::BTreeSet;

use crate::model::{
    Attachment, Attachments, CustomAttributes, Database, Entry, FieldName, Location, StandardField,
    StandardFields, Tag, Tags, Uuid,
};
use crate::otp::{Otp, OtpUri};
use crate::placeholder::{Completeness, Resolver};
use crate::secret::SecretBytes;

/// The tag that makes an entry shareable, matched case-insensitively.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequiredTag(Tag);

impl RequiredTag {
    pub const DEFAULT: &'static str = "agent";

    /// # Errors
    /// The name is empty after trimming, or contains a tag separator (`,` or `;`), so it could
    /// never match a tag.
    pub fn parse(name: &str) -> Result<Self, InvalidTag> {
        Tag::parse(name).map(Self).ok_or(InvalidTag)
    }

    /// The `agent` tag.
    #[must_use]
    pub fn agent() -> Self {
        Self::parse(Self::DEFAULT)
            .unwrap_or_else(|InvalidTag| unreachable!("{:?} is a valid tag", Self::DEFAULT))
    }

    #[must_use]
    pub fn name(&self) -> &str {
        self.0.name()
    }

    fn is_on(&self, tags: &Tags) -> bool {
        tags.as_slice().iter().any(|tag| tag.matches(&self.0))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("a tag must be non-empty and contain neither ',' nor ';'")]
pub struct InvalidTag;

/// The rule an entry must pass to be shared: carry the tag, or the user passed `--any`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Eligibility {
    Tagged(RequiredTag),
    /// `--any`: every live entry, tagged or not.
    Any,
}

/// Why an entry may not be shared under the rule asked for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ineligibility {
    MissingTag,
    /// Entries in the recycle bin are never shared, not even with `--any`.
    InRecycleBin,
}

impl Eligibility {
    fn check(&self, entry: &Entry) -> Result<(), Ineligibility> {
        match (entry.location(), self) {
            (Location::RecycleBin, _) => Err(Ineligibility::InRecycleBin),
            (Location::Live, Self::Any) => Ok(()),
            (Location::Live, Self::Tagged(tag)) if tag.is_on(entry.tags()) => Ok(()),
            (Location::Live, Self::Tagged(_)) => Err(Ineligibility::MissingTag),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PickError {
    #[error("no entry has UUID {0}")]
    NotFound(Uuid),
    #[error("entry {uuid} may not be shared: {reason:?}")]
    Ineligible { uuid: Uuid, reason: Ineligibility },
}

/// Witness that `entry` passed `eligibility`.
#[derive(Debug)]
pub struct Eligible<'db> {
    database: &'db Database,
    entry: &'db Entry,
    eligibility: Eligibility,
}

impl Database {
    /// The entries that pass `eligibility`, in database order.
    pub fn eligible<'db>(
        &'db self,
        eligibility: &'db Eligibility,
    ) -> impl Iterator<Item = Eligible<'db>> + 'db {
        self.entries()
            .iter()
            .filter(|entry| eligibility.check(entry).is_ok())
            .map(move |entry| Eligible {
                database: self,
                entry,
                eligibility: eligibility.clone(),
            })
    }

    /// The picker's list: one line per eligible entry. No secret is in it.
    #[must_use]
    pub fn picker_items(&self, eligibility: &Eligibility) -> Vec<PickerItem> {
        self.eligible(eligibility)
            .map(|eligible| PickerItem::of(eligible.entry))
            .collect()
    }

    /// The entries keepassxc-cli could find at `path`, in database order: it takes the first, so
    /// `path` names an entry only when this holds exactly one.
    #[must_use]
    pub fn entries_at(&self, path: &CliEntryPath) -> Vec<&Entry> {
        self.entries()
            .iter()
            .filter(|entry| EntryLabel::of(entry).cli_path() == *path)
            .collect()
    }

    /// Maps a picked [`PickerItem::id`] back to its entry, checking `eligibility` again.
    ///
    /// # Errors
    /// No entry has `uuid`, or it fails `eligibility`.
    pub fn pick(&self, uuid: Uuid, eligibility: Eligibility) -> Result<Eligible<'_>, PickError> {
        let entry = self.entry(uuid).ok_or(PickError::NotFound(uuid))?;
        eligibility
            .check(entry)
            .map_err(|reason| PickError::Ineligible { uuid, reason })?;
        Ok(Eligible {
            database: self,
            entry,
            eligibility,
        })
    }
}

/// What the picker shows for one entry. These values are displayed, so they are plain strings:
/// the group path, title, username and URL are what a human uses to recognise an entry.
/// Placeholders in them are shown raw.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PickerItem {
    /// Stable across exports of the same database; pass it to [`Database::pick`].
    pub id: Uuid,
    pub label: EntryLabel,
    pub user_name: Option<String>,
    pub url: Option<String>,
}

impl PickerItem {
    fn of(entry: &Entry) -> Self {
        let shown = |field| entry.fields().get(field).map(displayed);
        Self {
            id: entry.uuid(),
            label: EntryLabel::of(entry),
            user_name: shown(StandardField::UserName),
            url: shown(StandardField::Url),
        }
    }
}

/// How an entry is named to humans and on disk: its group path and its title as stored in the
/// database, placeholders unresolved.
///
/// The picker shows these raw values, so they are not secret by design. A resolved title can be
/// (`{REF:P@I:<uuid>}` resolves to another entry's password), which is why the directory name and
/// `meta.json` take their names from here and never from the resolved title.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntryLabel {
    groups: Vec<String>,
    title: Option<String>,
}

impl EntryLabel {
    #[must_use]
    pub fn new(groups: Vec<String>, title: Option<String>) -> Self {
        Self { groups, title }
    }

    pub(crate) fn of(entry: &Entry) -> Self {
        Self::new(
            entry.groups().names().to_vec(),
            entry.fields().get(StandardField::Title).map(displayed),
        )
    }

    /// The title as stored; `None` for an entry without one.
    #[must_use]
    pub fn title(&self) -> Option<&str> {
        self.title.as_deref()
    }

    fn cli_path(&self) -> CliEntryPath {
        CliEntryPath::new(&self.groups, self.title().unwrap_or_default())
    }

    /// `Group/Sub/Title`; an entry with no title shows as `Group/Sub/(no title)`.
    #[must_use]
    pub fn path(&self) -> String {
        let mut path = self.groups.join("/");
        if !path.is_empty() {
            path.push('/');
        }
        path.push_str(self.title().unwrap_or("(no title)"));
        path
    }
}

/// Field values are UTF-8 by construction (decoded from XML text), so this never substitutes.
fn displayed(value: &SecretBytes) -> String {
    String::from_utf8_lossy(value.expose()).into_owned()
}

impl Eligible<'_> {
    #[must_use]
    pub fn eligibility(&self) -> &Eligibility {
        &self.eligibility
    }

    /// The entry with its placeholders resolved against the whole database, its TOTP rendered
    /// as one `otpauth://` URI, and the bytes of every attachment: from the export, or, when the
    /// export has none ([`Attachments::NamedOnly`]), from `export_attachment`, called once per
    /// attachment with the path keepassxc-cli finds this entry by.
    ///
    /// # Errors
    /// Attachments must be exported and another entry has the same [`CliEntryPath`], so
    /// keepassxc-cli could read the other entry's; or `export_attachment` failed.
    pub fn resolve<E>(
        self,
        export_attachment: impl FnMut(&CliEntryPath, &str) -> Result<SecretBytes, E>,
    ) -> Result<ResolvedEntry, ResolveError<E>> {
        let attachments = self.attachments(export_attachment)?;
        let entry = self.entry;
        let mut resolver = Resolver::new(self.database);
        let mut unresolved = BTreeSet::new();
        let mut note = |name: FieldName, completeness| match completeness {
            Completeness::Complete => {}
            Completeness::Unresolved => {
                unresolved.insert(name);
            }
        };

        let mut fields = StandardFields::default();
        for field in StandardField::ALL {
            if let Some(resolution) = resolver.standard_field(entry, field) {
                note(FieldName::Standard(field), resolution.completeness);
                fields.set(field, resolution.value);
            }
        }
        let custom: CustomAttributes = entry
            .custom()
            .iter()
            .map(|(name, raw)| {
                let resolution = resolver.value(entry, raw.expose());
                note(FieldName::Custom(name.clone()), resolution.completeness);
                (name.clone(), resolution.value)
            })
            .collect();
        let otp = entry.otp().map_present(|source| {
            source.render(
                fields.get(StandardField::Title),
                fields.get(StandardField::UserName),
            )
        });

        Ok(ResolvedEntry {
            uuid: entry.uuid(),
            label: EntryLabel::of(entry),
            tags: entry.tags().clone(),
            eligibility: self.eligibility,
            fields,
            custom,
            otp,
            attachments,
            unresolved,
        })
    }

    fn attachments<E>(
        &self,
        mut export_attachment: impl FnMut(&CliEntryPath, &str) -> Result<SecretBytes, E>,
    ) -> Result<Vec<Attachment>, ResolveError<E>> {
        let names = match self.entry.attachments() {
            Attachments::Exported(attachments) => return Ok(attachments.clone()),
            Attachments::NamedOnly(names) if names.is_empty() => return Ok(Vec::new()),
            Attachments::NamedOnly(names) => names,
        };
        let path = EntryLabel::of(self.entry).cli_path();
        let sharing = self.database.entries_at(&path).len();
        if sharing > 1 {
            return Err(ResolveError::AmbiguousPath {
                path: path.0,
                entries: sharing,
            });
        }
        names
            .iter()
            .map(|name| match export_attachment(&path, name) {
                Ok(content) => Ok(Attachment::new(name.clone(), content)),
                Err(source) => Err(ResolveError::Attachment {
                    name: name.clone(),
                    source,
                }),
            })
            .collect()
    }
}

/// Why [`Eligible::resolve`] could not complete the entry. `E` is the attachment exporter's error.
#[derive(Debug, thiserror::Error)]
pub enum ResolveError<E> {
    #[error(
        "{entries} entries have the path {path:?}, by which keepassxc-cli finds the entry to export its attachments; rename or move all but one"
    )]
    AmbiguousPath { path: String, entries: usize },
    #[error("cannot export attachment {name:?}: {source}")]
    Attachment {
        name: String,
        #[source]
        source: E,
    },
}

/// How keepassxc-cli addresses an entry: `/`, then each group's name followed by `/`, then the
/// title as stored. keepassxc-cli compares it with each entry's in turn and uses the first that
/// matches, so it names one entry only when no other entry has the same string; a `/` inside a
/// group name or title is what can make two different entries share one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CliEntryPath(String);

impl CliEntryPath {
    /// The path of an entry titled `title` in the groups `groups`, outermost first.
    pub(crate) fn new(groups: &[impl AsRef<str>], title: &str) -> Self {
        let mut path = String::from("/");
        for group in groups {
            path.push_str(group.as_ref());
            path.push('/');
        }
        path.push_str(title);
        Self(path)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// `Group/Title`, as a human writes it: without the leading `/`.
    #[must_use]
    pub fn as_written(&self) -> &str {
        self.0.strip_prefix('/').unwrap_or(&self.0)
    }

    #[cfg(test)]
    pub(crate) fn for_tests(path: &str) -> Self {
        Self(path.to_owned())
    }
}

/// One entry, ready to be written out: placeholders resolved, TOTP normalised. Obtainable only
/// through [`Eligible::resolve`].
#[derive(Debug)]
pub struct ResolvedEntry {
    uuid: Uuid,
    label: EntryLabel,
    tags: Tags,
    eligibility: Eligibility,
    fields: StandardFields,
    custom: CustomAttributes,
    otp: Otp<OtpUri>,
    attachments: Vec<Attachment>,
    unresolved: BTreeSet<FieldName>,
}

impl ResolvedEntry {
    #[must_use]
    pub fn uuid(&self) -> Uuid {
        self.uuid
    }

    /// The unresolved name: what the directory and `meta.json` are named by.
    #[must_use]
    pub fn label(&self) -> &EntryLabel {
        &self.label
    }

    #[must_use]
    pub fn tags(&self) -> &Tags {
        &self.tags
    }

    /// The rule this entry was shared under; [`Eligibility::Any`] means `--any` was used.
    #[must_use]
    pub fn eligibility(&self) -> &Eligibility {
        &self.eligibility
    }

    /// Absent fields stay absent; the writer decides what an absent field becomes on disk.
    #[must_use]
    pub fn fields(&self) -> &StandardFields {
        &self.fields
    }

    /// Custom attributes, without the attributes consumed as TOTP.
    #[must_use]
    pub fn custom(&self) -> &CustomAttributes {
        &self.custom
    }

    #[must_use]
    pub fn otp(&self) -> &Otp<OtpUri> {
        &self.otp
    }

    #[must_use]
    pub fn attachments(&self) -> &[Attachment] {
        &self.attachments
    }

    /// The fields whose value still holds a placeholder left verbatim.
    #[must_use]
    pub fn unresolved(&self) -> &BTreeSet<FieldName> {
        &self.unresolved
    }
}
