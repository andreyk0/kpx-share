//! Where shared entries live: `$XDG_RUNTIME_DIR/kpx-share/<session>/<entry>/…`.
//!
//! The first two levels are witnesses, each built by constructors that check the directory exists,
//! is a real directory (not a symlink), belongs to this user and is mode 0700:
//!
//! - [`ShareRoot`] additionally proves the directory is on tmpfs, and needs no secret to do so, so
//!   the CLI builds it before it unlocks anything: nothing secret may be written to a disk.
//! - [`SessionDir`] is one session's directory below a root, named by a [`SessionName`].
//! - [`EntryDir`] only pairs an entry's path below a session with its [`SafeName`]. It checks
//!   nothing: the writer makes the directory (0700, whatever the umask) and
//!   [`SessionDir::entries`] finds it, and each has just done so when it builds the value.
//!
//! An existing directory with the wrong owner or mode is refused, never repaired: someone else's
//! directory, or one another process loosened on purpose, is not ours to chmod.

use std::ffi::OsString;
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::meta::{self, EntryMeta, MetaError};
use crate::mountinfo::{self, Filesystem, MountInfoError};

pub(crate) const PRIVATE_DIR_MODE: u32 = 0o700;
pub(crate) const PRIVATE_FILE_MODE: u32 = 0o600;

/// Below `$XDG_RUNTIME_DIR`.
const ROOT_DIR_NAME: &str = "kpx-share";

const MOUNTINFO_PATH: &str = "/proc/self/mountinfo";

/// What an in-progress write is called inside a session directory, followed by random hex. A
/// [`SafeName`] never starts with `.`, so no entry can be mistaken for one of these, nor the
/// reverse.
pub(crate) const PARTIAL_PREFIX: &str = ".partial-";

/// The non-secret record of what a session is bound to and when it ends, see [`crate::session`].
/// Hidden for the same reason as [`PARTIAL_PREFIX`]: no entry can have this name.
pub(crate) const SESSION_RECORD_FILE: &str = ".session.json";

// --- Directories ------------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum DirError {
    #[error("{} is a symlink, not a directory", .path.display())]
    Symlink { path: PathBuf },
    #[error("{} is not a directory", .path.display())]
    NotDirectory { path: PathBuf },
    #[error("{} is owned by uid {found}, not by uid {expected}", .path.display())]
    WrongOwner {
        path: PathBuf,
        found: u32,
        expected: u32,
    },
    #[error("{} has mode {mode:04o}, it must be exactly 0700", .path.display())]
    WrongMode { path: PathBuf, mode: u32 },
    #[error("{}: {source}", .path.display())]
    Io { path: PathBuf, source: io::Error },
}

impl DirError {
    fn io(path: &Path, source: io::Error) -> Self {
        Self::Io {
            path: path.to_owned(),
            source,
        }
    }
}

/// Creates `path` (its parent must exist) with mode 0700 if it is missing, then checks that what
/// is there is a private directory of ours.
fn ensure_private_dir(path: &Path) -> Result<(), DirError> {
    match create_private_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(source) => return Err(DirError::io(path, source)),
    }
    verify_private_dir(path)
}

/// `lstat`s `path`, so a symlink is refused rather than followed.
fn verify_private_dir(path: &Path) -> Result<(), DirError> {
    const PERMISSION_BITS: u32 = 0o7777;
    let meta = fs::symlink_metadata(path).map_err(|source| DirError::io(path, source))?;
    let file_type = meta.file_type();
    if file_type.is_symlink() {
        return Err(DirError::Symlink {
            path: path.to_owned(),
        });
    }
    if !file_type.is_dir() {
        return Err(DirError::NotDirectory {
            path: path.to_owned(),
        });
    }
    let expected = rustix::process::geteuid().as_raw();
    if meta.uid() != expected {
        return Err(DirError::WrongOwner {
            path: path.to_owned(),
            found: meta.uid(),
            expected,
        });
    }
    let mode = meta.mode() & PERMISSION_BITS;
    if mode != PRIVATE_DIR_MODE {
        return Err(DirError::WrongMode {
            path: path.to_owned(),
            mode,
        });
    }
    Ok(())
}

// --- ShareRoot --------------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum RootError {
    #[error("XDG_RUNTIME_DIR is not set, so there is no tmpfs to share into")]
    NoRuntimeDir,
    #[error("{} is not an absolute path with a final component", .0.display())]
    NotAbsolute(PathBuf),
    #[error(transparent)]
    Dir(#[from] DirError),
    #[error("{} is on {filesystem}, not tmpfs: a secret written there could reach a disk", .path.display())]
    NotTmpfs {
        path: PathBuf,
        filesystem: Filesystem,
    },
    #[error("cannot read {MOUNTINFO_PATH}: {0}")]
    ReadMountInfo(io::Error),
    #[error("cannot tell the filesystem of {}: {source}", .path.display())]
    MountInfo {
        path: PathBuf,
        source: MountInfoError,
    },
}

/// Witness that `path` is a real directory on tmpfs, owned by this user, mode 0700.
///
/// Both what the filesystem is and what the directory looks like are checked, once, here; the
/// check happens at construction and the type promises nothing about later changes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShareRoot {
    path: PathBuf,
}

impl ShareRoot {
    /// `<runtime_dir>/kpx-share`, `runtime_dir` being what `XDG_RUNTIME_DIR` holds.
    ///
    /// # Errors
    /// `runtime_dir` is absent or empty, or [`ShareRoot::at`] refuses the directory.
    pub fn in_runtime_dir(runtime_dir: Option<&std::ffi::OsStr>) -> Result<Self, RootError> {
        let runtime_dir = runtime_dir
            .filter(|dir| !dir.is_empty())
            .ok_or(RootError::NoRuntimeDir)?;
        Self::at(&Path::new(runtime_dir).join(ROOT_DIR_NAME))
    }

    /// The share root at `path`, created with mode 0700 when missing (its parent must exist).
    ///
    /// The filesystem is checked before anything is created, so a refusal leaves nothing behind.
    ///
    /// # Errors
    /// `path` is relative, is not on tmpfs, or exists as something other than a real directory of
    /// ours with mode exactly 0700 (including any group or other permission bit).
    pub fn at(path: &Path) -> Result<Self, RootError> {
        let not_absolute = || RootError::NotAbsolute(path.to_owned());
        if !path.is_absolute() {
            return Err(not_absolute());
        }
        let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
            return Err(not_absolute());
        };
        let canonical = fs::canonicalize(parent)
            .map_err(|source| DirError::io(parent, source))?
            .join(name);
        require_tmpfs(&canonical)?;
        ensure_private_dir(&canonical)?;
        Ok(Self { path: canonical })
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// What is directly below the root: session directories, and anything else that is in the way.
    ///
    /// # Errors
    /// The root cannot be read.
    pub fn session_slots(&self) -> io::Result<Vec<SessionSlot>> {
        let mut slots = Vec::new();
        for item in fs::read_dir(&self.path)? {
            let item = item?;
            let name = item
                .file_name()
                .to_str()
                .and_then(|name| SessionName::parse(name).ok());
            // `DirEntry::file_type` does not follow symlinks, so a link is never a session.
            slots.push(match (name, item.file_type()?.is_dir()) {
                (Some(name), true) => SessionSlot::Session(name),
                _ => SessionSlot::Foreign(item.path()),
            });
        }
        slots.sort_by(|a, b| a.sort_key().cmp(b.sort_key()));
        Ok(slots)
    }
}

/// One thing directly below a [`ShareRoot`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionSlot {
    Session(SessionName),
    /// Not a directory named like a session; never touched.
    Foreign(PathBuf),
}

impl SessionSlot {
    fn sort_key(&self) -> &Path {
        match self {
            Self::Session(name) => Path::new(name.as_str()),
            Self::Foreign(path) => path,
        }
    }
}

fn require_tmpfs(canonical: &Path) -> Result<(), RootError> {
    let mountinfo = fs::read_to_string(MOUNTINFO_PATH).map_err(RootError::ReadMountInfo)?;
    match mountinfo::filesystem_of(&mountinfo, canonical) {
        Ok(Filesystem::Tmpfs) => Ok(()),
        Ok(filesystem) => Err(RootError::NotTmpfs {
            path: canonical.to_owned(),
            filesystem,
        }),
        Err(source) => Err(RootError::MountInfo {
            path: canonical.to_owned(),
            source,
        }),
    }
}

// --- Names ------------------------------------------------------------------------------------

/// Longest [`SessionName`]: a hyphenated UUID is 36 bytes, which leaves room for a fallback.
pub const SESSION_NAME_BYTES_MAX: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SessionNameError {
    #[error("a session name must not be empty")]
    Empty,
    #[error("a session name is at most {SESSION_NAME_BYTES_MAX} bytes, this one has {0}")]
    TooLong(usize),
    #[error("a session name holds only letters, digits, '-' and '_', not {0:?}")]
    BadCharacter(char),
}

/// A single path component naming a session directory: 1 to [`SESSION_NAME_BYTES_MAX`] characters
/// from `[A-Za-z0-9_-]`. Anything else, `.`, `..` and `/` included, cannot be built.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionName(String);

impl SessionName {
    /// # Errors
    /// `name` is empty, too long, or holds a character outside `[A-Za-z0-9_-]`.
    pub fn parse(name: &str) -> Result<Self, SessionNameError> {
        if name.is_empty() {
            return Err(SessionNameError::Empty);
        }
        if name.len() > SESSION_NAME_BYTES_MAX {
            return Err(SessionNameError::TooLong(name.len()));
        }
        match name
            .chars()
            .find(|c| !(c.is_ascii_alphanumeric() || *c == '-' || *c == '_'))
        {
            Some(bad) => Err(SessionNameError::BadCharacter(bad)),
            None => Ok(Self(name.to_owned())),
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Longest [`SafeName`]. A file name is at most 255 bytes on Linux; this leaves room for anything
/// a later tool appends (`.tmp`, `.bak`) without hitting that limit.
pub const SAFE_NAME_BYTES_MAX: usize = 200;

/// A single path component this tool writes: an entry's directory or one of its files.
///
/// It holds only letters and digits (Unicode included) and `.`, `-`, `_`; it never starts with
/// `.`, so it is neither `.`/`..` nor hidden, nor a `.partial-*`; it is at most
/// [`SAFE_NAME_BYTES_MAX`] bytes and has at least one letter or digit. Built by
/// [`sanitise`](Self::sanitise), which is lossy: two raw names may give one `SafeName`, and the
/// writer treats that as a collision.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SafeName(String);

impl SafeName {
    fn is_allowed(c: char) -> bool {
        c.is_alphanumeric() || matches!(c, '.' | '-' | '_')
    }

    /// Replaces each run of other characters (spaces, `/`, NUL, control characters, …) with one
    /// `_`, drops leading dots and cuts to [`SAFE_NAME_BYTES_MAX`]. `None` when no letter or digit
    /// is left, so there is nothing to name it by.
    #[must_use]
    pub fn sanitise(raw: &str) -> Option<Self> {
        let mut name = String::with_capacity(raw.len().min(SAFE_NAME_BYTES_MAX));
        for c in raw.chars() {
            if Self::is_allowed(c) {
                name.push(c);
            } else if !name.ends_with('_') {
                name.push('_');
            }
        }
        let mut name = name.trim_start_matches('.').to_owned();
        while name.len() > SAFE_NAME_BYTES_MAX {
            name.pop();
        }
        name.chars()
            .any(char::is_alphanumeric)
            .then_some(Self(name))
    }

    /// `name` if it is already exactly what [`sanitise`](Self::sanitise) would make of it: how a
    /// directory name read back from disk is checked.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::sanitise(name).filter(|safe| safe.0 == name)
    }

    /// The 32 hex digits of `uuid`, the name of an entry with no usable title.
    #[must_use]
    pub fn from_uuid(uuid: crate::model::Uuid) -> Self {
        Self(uuid.to_string())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for SafeName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

// --- SessionDir and EntryDir ------------------------------------------------------------------

/// Witness that `<root>/<name>` is a real directory of ours, mode 0700.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionDir {
    name: SessionName,
    path: PathBuf,
}

impl SessionDir {
    /// Creates the session directory if it is missing.
    ///
    /// # Errors
    /// It exists as something other than a real directory of ours with mode exactly 0700, or
    /// cannot be created.
    pub fn open(root: &ShareRoot, name: &SessionName) -> Result<Self, DirError> {
        let path = root.path().join(name.as_str());
        ensure_private_dir(&path)?;
        Ok(Self {
            name: name.clone(),
            path,
        })
    }

    /// The session directory if it exists; it is never created.
    ///
    /// # Errors
    /// It exists as something other than a real directory of ours with mode exactly 0700.
    pub fn find(root: &ShareRoot, name: &SessionName) -> Result<Option<Self>, DirError> {
        let path = root.path().join(name.as_str());
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(source) => Err(DirError::io(&path, source)),
            Ok(_) => {
                verify_private_dir(&path)?;
                Ok(Some(Self {
                    name: name.clone(),
                    path,
                }))
            }
        }
    }

    #[must_use]
    pub fn name(&self) -> &SessionName {
        &self.name
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Deletes the directory and everything in it. A directory that is already gone is success:
    /// the postcondition holds.
    ///
    /// # Errors
    /// Something in it cannot be removed.
    pub fn remove(self) -> io::Result<()> {
        match fs::remove_dir_all(&self.path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            other => other,
        }
    }

    /// Deletes one entry directory, which must be one [`entries`](Self::entries) would list.
    ///
    /// # Errors
    /// There is no such entry, or it cannot be removed.
    pub fn remove_entry(&self, slug: &SafeName) -> Result<(), RemoveEntryError> {
        let path = self.path.join(slug.as_str());
        match fs::symlink_metadata(&path) {
            Ok(found) if found.is_dir() => {}
            Ok(_) => return Err(RemoveEntryError::NotFound(slug.clone())),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(RemoveEntryError::NotFound(slug.clone()));
            }
            Err(source) => return Err(RemoveEntryError::Io { path, source }),
        }
        fs::remove_dir_all(&path).map_err(|source| RemoveEntryError::Io { path, source })
    }

    /// Every entry directory in the session, by name. In-progress writes (`.partial-*`) and the
    /// session record are not entries and are skipped; each entry's `meta.json` is parsed, and a
    /// failure to is reported beside that entry rather than hiding the others.
    ///
    /// # Errors
    /// The directory cannot be read, or holds something that is neither an entry, the session
    /// record nor an in-progress write.
    pub fn entries(&self) -> Result<Vec<ListedEntry>, ListError> {
        let Scan { entries, strangers } = self.scan()?;
        match strangers.into_iter().next() {
            Some(stranger) => Err(ListError::Foreign(stranger)),
            None => Ok(entries),
        }
    }

    /// The entry directories of the session, passing over anything that is not one: a stray file
    /// of the agent's or the human's does not stop a caller that only looks for its own entries.
    ///
    /// # Errors
    /// The directory cannot be read.
    pub fn entries_among_strangers(&self) -> Result<Vec<ListedEntry>, ListError> {
        self.scan().map(|scan| scan.entries)
    }

    fn scan(&self) -> Result<Scan, ListError> {
        let io_error = |source| ListError::Io {
            path: self.path.clone(),
            source,
        };
        let mut entries = Vec::new();
        let mut strangers = Vec::new();
        for item in fs::read_dir(&self.path).map_err(io_error)? {
            let item = item.map_err(io_error)?;
            let file_name = item.file_name();
            if file_name
                .as_encoded_bytes()
                .starts_with(PARTIAL_PREFIX.as_bytes())
                || file_name == SESSION_RECORD_FILE
            {
                continue;
            }
            let is_dir = item.file_type().map_err(io_error)?.is_dir();
            let slug = file_name.to_str().and_then(SafeName::parse);
            match (is_dir, slug) {
                (true, Some(slug)) => {
                    let dir = EntryDir::new(self.path.join(slug.as_str()), slug);
                    let meta = meta::read(&dir);
                    entries.push(ListedEntry { dir, meta });
                }
                _ => strangers.push(item.path()),
            }
        }
        entries.sort_by(|a, b| a.dir.slug.cmp(&b.dir.slug));
        Ok(Scan { entries, strangers })
    }
}

/// What a session directory holds besides its record and in-progress writes.
struct Scan {
    entries: Vec<ListedEntry>,
    /// Everything that is not a directory named like an entry, in directory order.
    strangers: Vec<PathBuf>,
}

#[derive(Debug, thiserror::Error)]
pub enum RemoveEntryError {
    #[error("no entry named {0} in this session")]
    NotFound(SafeName),
    #[error("{}: {source}", .path.display())]
    Io { path: PathBuf, source: io::Error },
}

#[derive(Debug, thiserror::Error)]
pub enum ListError {
    #[error("{}: {source}", .path.display())]
    Io { path: PathBuf, source: io::Error },
    #[error("{} is not an entry directory", .0.display())]
    Foreign(PathBuf),
}

/// An entry directory found in a session, with its metadata parsed.
#[derive(Debug)]
pub struct ListedEntry {
    pub dir: EntryDir,
    pub meta: Result<EntryMeta, MetaError>,
}

/// An entry's directory inside a [`SessionDir`]: the path the CLI prints.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntryDir {
    path: PathBuf,
    slug: SafeName,
}

impl EntryDir {
    pub(crate) fn new(path: PathBuf, slug: SafeName) -> Self {
        Self { path, slug }
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[must_use]
    pub fn slug(&self) -> &SafeName {
        &self.slug
    }
}

/// A random name for a directory being written, `.partial-` plus 16 hex digits.
pub(crate) fn random_partial_name() -> io::Result<OsString> {
    const RANDOM_BYTES: usize = 8;
    let mut bytes = [0u8; RANDOM_BYTES];
    let got = rustix::rand::getrandom(&mut bytes, rustix::rand::GetRandomFlags::empty())?;
    if got != RANDOM_BYTES {
        return Err(io::Error::other(
            "getrandom returned fewer bytes than asked",
        ));
    }
    let random = u64::from_le_bytes(bytes);
    Ok(OsString::from(format!("{PARTIAL_PREFIX}{random:016x}")))
}

/// `O_NOFOLLOW`, for `OpenOptions::custom_flags`.
pub(crate) fn no_follow_flag() -> i32 {
    rustix::fs::OFlags::NOFOLLOW.bits().cast_signed()
}

/// Creates a directory with mode exactly 0700, whatever the umask. Fails if it exists.
pub(crate) fn create_private_dir(path: &Path) -> io::Result<()> {
    fs::DirBuilder::new().mode(PRIVATE_DIR_MODE).create(path)?;
    // `mkdir` applies the umask; a fresh directory is ours to set exactly.
    fs::set_permissions(path, fs::Permissions::from_mode(PRIVATE_DIR_MODE))
}

/// Creates `path` (it must not exist; a symlink there is not followed) with mode exactly 0600
/// and writes `bytes` to it.
pub(crate) fn write_private_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(PRIVATE_FILE_MODE)
        .custom_flags(no_follow_flag())
        .open(path)?;
    // `open` applies the umask to the mode; the file is ours to set exactly.
    file.set_permissions(fs::Permissions::from_mode(PRIVATE_FILE_MODE))?;
    file.write_all(bytes)
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum BoundedReadError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("larger than {max} bytes")]
    TooLarge { max: u64 },
}

/// The whole of the file at `path`, which must be at most `max` bytes. A symlink in its place is
/// refused; a file that is missing is [`BoundedReadError::Io`] with kind `NotFound`.
pub(crate) fn read_bounded(path: &Path, max: u64) -> Result<Vec<u8>, BoundedReadError> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(no_follow_flag())
        .open(path)?;
    let mut bytes = Vec::new();
    file.take(max.saturating_add(1)).read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).map_or(true, |len| len > max) {
        return Err(BoundedReadError::TooLarge { max });
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_name_accepts_a_uuid_and_nothing_path_like() {
        assert!(SessionName::parse("0b1c2d3e-4f50-6172-8394-a5b6c7d8e9f0").is_ok());
        assert!(SessionName::parse("fallback_pid-1234").is_ok());
        assert_eq!(SessionName::parse(""), Err(SessionNameError::Empty));
        for bad in ["..", ".", "a/b", "a b", "a\0b", "é", "a.b"] {
            assert!(
                matches!(
                    SessionName::parse(bad),
                    Err(SessionNameError::BadCharacter(_))
                ),
                "{bad:?}"
            );
        }
        assert!(SessionName::parse(&"a".repeat(SESSION_NAME_BYTES_MAX)).is_ok());
        assert_eq!(
            SessionName::parse(&"a".repeat(SESSION_NAME_BYTES_MAX + 1)),
            Err(SessionNameError::TooLong(SESSION_NAME_BYTES_MAX + 1))
        );
    }

    #[test]
    fn a_bounded_read_takes_exactly_max_bytes_and_refuses_more_a_symlink_or_nothing() {
        let scratch = tempfile::TempDir::new().unwrap();
        let file = scratch.path().join("f");
        fs::write(&file, b"12345").unwrap();
        assert_eq!(read_bounded(&file, 5).unwrap(), b"12345");
        assert!(matches!(
            read_bounded(&file, 4),
            Err(BoundedReadError::TooLarge { max: 4 })
        ));
        let link = scratch.path().join("link");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        assert!(matches!(
            read_bounded(&link, 5),
            Err(BoundedReadError::Io(_))
        ));
        let missing = read_bounded(&scratch.path().join("absent"), 5).unwrap_err();
        assert!(
            matches!(&missing, BoundedReadError::Io(error) if error.kind() == io::ErrorKind::NotFound),
            "{missing:?}"
        );
    }

    fn sanitised(raw: &str) -> Option<String> {
        SafeName::sanitise(raw).map(|name| name.0)
    }

    #[test]
    fn sanitise_replaces_runs_of_unsafe_characters() {
        assert_eq!(sanitised("GitHub token"), Some("GitHub_token".into()));
        assert_eq!(sanitised("a / b\0c"), Some("a_b_c".into()));
        assert_eq!(sanitised("prod-db_v1.2"), Some("prod-db_v1.2".into()));
        assert_eq!(sanitised("пароль"), Some("пароль".into()));
    }

    #[test]
    fn sanitise_never_yields_dot_names_or_hidden_ones() {
        assert_eq!(sanitised("."), None);
        assert_eq!(sanitised(".."), None);
        assert_eq!(sanitised("../../etc/passwd"), Some("_.._etc_passwd".into()));
        assert_eq!(sanitised(".partial-abc"), Some("partial-abc".into()));
        assert_eq!(sanitised("...x"), Some("x".into()));
    }

    #[test]
    fn sanitise_refuses_names_with_nothing_to_name_them_by() {
        for raw in ["", " ", "/", "---", "_", "._."] {
            assert_eq!(sanitised(raw), None, "{raw:?}");
        }
    }

    #[test]
    fn sanitise_bounds_the_length_on_a_character_boundary() {
        let long = "é".repeat(SAFE_NAME_BYTES_MAX);
        let name = sanitised(&long).unwrap();
        assert!(name.len() <= SAFE_NAME_BYTES_MAX);
        assert!(name.chars().all(|c| c == 'é'));
    }

    #[test]
    fn sanitise_is_idempotent_and_parse_accepts_only_its_fixed_points() {
        for raw in ["GitHub token", "a/b", ".x", "a_ b", "x.y-z", "é é"] {
            let once = SafeName::sanitise(raw).unwrap();
            assert_eq!(SafeName::sanitise(once.as_str()), Some(once.clone()));
            assert_eq!(SafeName::parse(once.as_str()), Some(once));
        }
        assert_eq!(SafeName::parse("GitHub token"), None);
        assert_eq!(SafeName::parse(".partial-abc"), None);
    }
}
