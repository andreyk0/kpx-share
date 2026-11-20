//! Writing one resolved entry into a session directory.
//!
//! ```text
//! <session>/<slug>/
//!   username  password  url  notes  title     always there; an empty file is an empty or absent field
//!   otp                                       the otpauth:// URI, only when the entry has readable TOTP
//!   attributes/<name>                         custom fields
//!   attachments/<name>                        raw bytes
//!   meta.json                                 see [`crate::meta`]
//! ```
//!
//! Every directory is 0700 and every file 0600 whatever the umask, values are written byte for
//! byte (no newline added, nothing trimmed), and nothing secret is written outside the session
//! directory.
//!
//! An entry appears whole or not at all: everything is written under `<session>/.partial-<random>`
//! and then renamed to `<session>/<slug>`. The partial directory is removed on any failure.
//!
//! The same entry (same UUID) added again replaces the earlier one with `RENAME_EXCHANGE`, so the
//! path is never missing and never half old, half new. If its title changed in between, the new
//! slug is a new directory, and the earlier directory of that UUID is removed once the new one is
//! in place: one entry has one directory in a session. A different entry whose title gives the
//! same slug is refused; nothing is ever overwritten.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use rustix::fs::{CWD, RenameFlags, renameat_with};
use rustix::io::Errno;

use crate::layout::{
    EntryDir, ListError, RemoveEntryError, SafeName, SessionDir, create_private_dir,
    random_partial_name, write_private_file,
};
use crate::meta::{self, EntryMeta, META_FILE, MetaError, Validity};
use crate::model::{StandardField, Uuid};
use crate::otp::Otp;
use crate::secret::SecretBytes;
use crate::select::ResolvedEntry;

const OTP_FILE: &str = "otp";

/// Retries when the entry's name changes between looking at it and renaming onto it; only a
/// concurrent `rm` or add of the very same slug, in a directory one human drives, can cause that.
const PUBLISH_ATTEMPTS_MAX: usize = 3;

/// What kind of named value a [`WriteError`] is about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NameKind {
    Attribute,
    Attachment,
}

impl NameKind {
    fn dir(self) -> &'static str {
        match self {
            Self::Attribute => "attributes",
            Self::Attachment => "attachments",
        }
    }
}

impl std::fmt::Display for NameKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Attribute => "attribute",
            Self::Attachment => "attachment",
        })
    }
}

/// No variant carries a field or attachment value; names, paths and I/O errors only.
#[derive(Debug, thiserror::Error)]
pub enum WriteError {
    #[error("the {kind} name {name:?} has no letter or digit to name a file by")]
    UnusableName { kind: NameKind, name: String },
    #[error("the {kind}s {first:?} and {second:?} would both be the file {file}")]
    NameCollision {
        kind: NameKind,
        first: String,
        second: String,
        file: String,
    },
    #[error("{} already holds a different entry ({existing})", .path.display())]
    SlugTaken { path: PathBuf, existing: Uuid },
    #[error("{} exists and is not an entry directory of this tool", .path.display())]
    NotAnEntry { path: PathBuf },
    #[error("{} exists and its metadata is unreadable: {source}", .path.display())]
    ExistingUnreadable { path: PathBuf, source: MetaError },
    #[error("{} kept changing while it was replaced", .path.display())]
    Contended { path: PathBuf },
    #[error("{}: {source}", .path.display())]
    Io { path: PathBuf, source: io::Error },
    #[error("the new entry is in place but the old one at {} could not be removed: {source}", .path.display())]
    OldEntryRemains { path: PathBuf, source: io::Error },
    #[error(
        "the new entry is in place but the session could not be scanned for an older copy of it: {0}"
    )]
    ScanForCopies(ListError),
    #[error("meta.json could not be serialised: {0}")]
    Serialise(serde_json::Error),
}

impl WriteError {
    fn io(path: &Path, source: io::Error) -> Self {
        Self::Io {
            path: path.to_owned(),
            source,
        }
    }
}

/// Writes `entry` into `session` and returns where it is. See the module documentation.
///
/// The slug is the sanitised title, or the UUID's 32 hex digits when there is no usable title. An
/// entry already at that slug is the *same entry* when its `meta.json` holds the same UUID; one
/// whose `meta.json` is missing or unreadable is never replaced.
///
/// # Errors
/// A name collision or unusable name (checked before anything is written), a different entry at
/// the slug, or an I/O failure; on any of them no new entry and no partial directory is left.
/// The two exceptions come after the new entry is in place and say so: an older copy that cannot
/// be removed ([`WriteError::OldEntryRemains`]) and a session that cannot be scanned for one
/// ([`WriteError::ScanForCopies`]).
pub fn write_entry(
    session: &SessionDir,
    entry: &ResolvedEntry,
    validity: &Validity,
) -> Result<EntryDir, WriteError> {
    let plan = Plan::of(entry, validity)?;
    let partial = Partial::create(session)?;
    plan.write_into(partial.path())?;
    let published = publish(session, partial, plan.slug, plan.meta.uuid)?;
    remove_other_copies(session, &published, plan.meta.uuid)?;
    Ok(published)
}

// --- The plan: what goes where, decided before any byte is written ----------------------------

struct PlannedFile<'a> {
    /// Relative to the entry directory, `/`-separated.
    path: String,
    /// `None` is an absent standard field, which becomes an empty file here and nowhere earlier.
    content: Option<&'a SecretBytes>,
}

struct Plan<'a> {
    slug: SafeName,
    files: Vec<PlannedFile<'a>>,
    meta: EntryMeta,
}

fn standard_file(field: StandardField) -> &'static str {
    match field {
        StandardField::Title => "title",
        StandardField::UserName => "username",
        StandardField::Password => "password",
        StandardField::Url => "url",
        StandardField::Notes => "notes",
    }
}

/// A custom attribute or attachment given its file.
struct NamedFile<'a> {
    name: &'a str,
    path: String,
    content: &'a SecretBytes,
}

/// Gives each of `items` a file name under the kind's directory; two names that sanitise alike,
/// or one that sanitises to nothing, are an error.
fn named_files<'a>(
    kind: NameKind,
    items: impl Iterator<Item = (&'a str, &'a SecretBytes)>,
) -> Result<Vec<NamedFile<'a>>, WriteError> {
    let mut taken: BTreeMap<SafeName, &str> = BTreeMap::new();
    let mut files = Vec::new();
    for (name, content) in items {
        let safe = SafeName::sanitise(name).ok_or_else(|| WriteError::UnusableName {
            kind,
            name: name.to_owned(),
        })?;
        if let Some(first) = taken.insert(safe.clone(), name) {
            return Err(WriteError::NameCollision {
                kind,
                first: first.to_owned(),
                second: name.to_owned(),
                file: format!("{}/{safe}", kind.dir()),
            });
        }
        files.push(NamedFile {
            name,
            path: format!("{}/{safe}", kind.dir()),
            content,
        });
    }
    Ok(files)
}

/// Adds each of `named` to the files to write and to `meta`'s name-to-path map.
fn place<'a>(
    files: &mut Vec<PlannedFile<'a>>,
    paths: &mut BTreeMap<String, String>,
    named: Vec<NamedFile<'a>>,
) {
    for file in named {
        paths.insert(file.name.to_owned(), file.path.clone());
        files.push(PlannedFile {
            path: file.path,
            content: Some(file.content),
        });
    }
}

/// Named by the unresolved title: the resolved one may be another entry's password.
fn slug_of(entry: &ResolvedEntry) -> SafeName {
    entry
        .label()
        .title()
        .and_then(SafeName::sanitise)
        .unwrap_or_else(|| SafeName::from_uuid(entry.uuid()))
}

impl<'a> Plan<'a> {
    fn of(entry: &'a ResolvedEntry, validity: &Validity) -> Result<Self, WriteError> {
        let mut files = Vec::new();
        let mut fields = BTreeMap::new();

        for field in StandardField::ALL {
            let path = standard_file(field);
            fields.insert(field.key().to_owned(), path.to_owned());
            files.push(PlannedFile {
                path: path.to_owned(),
                content: entry.fields().get(field),
            });
        }
        if let Otp::Present(uri) = entry.otp() {
            files.push(PlannedFile {
                path: OTP_FILE.to_owned(),
                content: Some(uri.as_secret()),
            });
        }

        let attributes = named_files(
            NameKind::Attribute,
            entry
                .custom()
                .iter()
                .map(|(name, value)| (name.as_str(), value)),
        )?;
        let attachments = named_files(
            NameKind::Attachment,
            entry
                .attachments()
                .iter()
                .map(|attachment| (attachment.name(), attachment.content())),
        )?;
        let mut attachment_paths = BTreeMap::new();
        place(&mut files, &mut fields, attributes);
        place(&mut files, &mut attachment_paths, attachments);

        Ok(Self {
            slug: slug_of(entry),
            files,
            meta: EntryMeta::new(entry, validity, fields, attachment_paths, OTP_FILE),
        })
    }

    /// Writes the whole entry under `root`, an empty directory made by [`Partial::create`].
    fn write_into(&self, root: &Path) -> Result<(), WriteError> {
        for kind in [NameKind::Attribute, NameKind::Attachment] {
            let dir = root.join(kind.dir());
            create_private_dir(&dir).map_err(|source| WriteError::io(&dir, source))?;
        }
        for file in &self.files {
            let path = root.join(&file.path);
            let bytes = file.content.map_or(&[][..], SecretBytes::expose);
            write_private_file(&path, bytes).map_err(|source| WriteError::io(&path, source))?;
        }
        let json = self.meta.to_json().map_err(WriteError::Serialise)?;
        let path = root.join(META_FILE);
        write_private_file(&path, &json).map_err(|source| WriteError::io(&path, source))
    }
}

// --- The partial directory --------------------------------------------------------------------

/// A directory being written, removed on drop unless it was renamed into place.
struct Partial {
    path: PathBuf,
    armed: bool,
}

impl Partial {
    fn create(session: &SessionDir) -> Result<Self, WriteError> {
        let path = session
            .path()
            .join(random_partial_name().map_err(|source| WriteError::io(session.path(), source))?);
        create_private_dir(&path).map_err(|source| WriteError::io(&path, source))?;
        Ok(Self { path, armed: true })
    }

    fn path(&self) -> &Path {
        &self.path
    }

    /// The directory has been renamed to its final name; there is nothing left to remove.
    fn keep(mut self) {
        self.armed = false;
    }

    /// Removes the directory and reports a failure, for the case where leaving it behind matters.
    fn remove(mut self) -> io::Result<()> {
        self.armed = false;
        fs::remove_dir_all(&self.path)
    }
}

impl Drop for Partial {
    fn drop(&mut self) {
        if self.armed {
            // Already failing: the caller gets the error that caused this. A directory that
            // survives is inside the session directory, which the watcher deletes.
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

// --- Publishing -------------------------------------------------------------------------------

/// Removes the directories of `uuid` other than `published`: the same entry added again under
/// another title (the slug follows the title) is one entry, so the old directory goes once the
/// new one is in place. An entry whose `meta.json` cannot be read is not known to be this one
/// and stays, and so does anything in the session that is not an entry directory.
fn remove_other_copies(
    session: &SessionDir,
    published: &EntryDir,
    uuid: Uuid,
) -> Result<(), WriteError> {
    let listed = session
        .entries_among_strangers()
        .map_err(WriteError::ScanForCopies)?;
    let others = listed.into_iter().filter(|other| {
        other.dir.slug() != published.slug() && other.meta.as_ref().is_ok_and(|m| m.uuid == uuid)
    });
    for other in others {
        match session.remove_entry(other.dir.slug()) {
            // Removed by someone else meanwhile: the goal is met.
            Ok(()) | Err(RemoveEntryError::NotFound(_)) => {}
            Err(RemoveEntryError::Io { path, source }) => {
                return Err(WriteError::OldEntryRemains { path, source });
            }
        }
    }
    Ok(())
}

fn rename(from: &Path, to: &Path, flags: RenameFlags) -> Result<(), Errno> {
    renameat_with(CWD, from, CWD, to, flags)
}

/// What is at an entry's slug.
fn occupant(path: &Path, slug: &SafeName) -> Result<Option<Uuid>, WriteError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(WriteError::io(path, source)),
        Ok(found) if !found.is_dir() => Err(WriteError::NotAnEntry {
            path: path.to_owned(),
        }),
        Ok(_) => meta::read(&EntryDir::new(path.to_owned(), slug.clone()))
            .map(|meta| Some(meta.uuid))
            .map_err(|source| WriteError::ExistingUnreadable {
                path: path.to_owned(),
                source,
            }),
    }
}

/// Moves the finished `partial` to `<session>/<slug>`: a plain rename onto a free slug, an
/// exchange when the slug holds the same entry (`uuid`), an error otherwise.
fn publish(
    session: &SessionDir,
    partial: Partial,
    slug: SafeName,
    uuid: Uuid,
) -> Result<EntryDir, WriteError> {
    let target = session.path().join(slug.as_str());
    for _ in 0..PUBLISH_ATTEMPTS_MAX {
        match rename(partial.path(), &target, RenameFlags::NOREPLACE) {
            Ok(()) => {
                partial.keep();
                return Ok(EntryDir::new(target, slug));
            }
            Err(Errno::EXIST) => {}
            Err(errno) => return Err(WriteError::io(&target, errno.into())),
        }
        match occupant(&target, &slug)? {
            None => {}
            Some(existing) if existing != uuid => {
                return Err(WriteError::SlugTaken {
                    path: target,
                    existing,
                });
            }
            Some(_) => match rename(partial.path(), &target, RenameFlags::EXCHANGE) {
                Ok(()) => {
                    // The partial's name now holds the entry that was replaced.
                    let old = partial.path().to_owned();
                    return partial
                        .remove()
                        .map(|()| EntryDir::new(target, slug))
                        .map_err(|source| WriteError::OldEntryRemains { path: old, source });
                }
                Err(Errno::NOENT) => {}
                Err(errno) => return Err(WriteError::io(&target, errno.into())),
            },
        }
    }
    Err(WriteError::Contended { path: target })
}
