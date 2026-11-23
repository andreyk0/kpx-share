//! The staging area: `$XDG_RUNTIME_DIR/kpx-import/<name>/`, what an agent leaves for `import`.
//!
//! [`ImportRoot`] is a [`PrivateTmpfsDir`] the agent creates and kpx-share only verifies;
//! [`ImportLock`] holds it locked for one import, and is what every step below the root takes.
//! [`Opened::open`] checks `<name>`; [`Opened::claim`] renames it to `.claimed.<random>.<name>` in
//! the root, so the agent's paths stop reaching what is being imported (a write there fails
//! instead of landing in a file kpx-share will delete), and checks the renamed directory is the
//! one opened. [`Claimed::read`] reads the manifest and every file it names exactly once into
//! memory and checks them, so what is confirmed, written and compared later are those bytes
//! (invariant S6). Once the database holds them, [`Claimed::finish`] deletes each file that still
//! holds exactly the bytes read (S4), and the directory; anything else, it puts back under
//! `<name>` and reports. Every other ending puts the directory back whole ([`Claimed::restore`]).
//!
//! A claimed directory names where it came from, so one an import left when it was killed is put
//! back under its name by the next import ([`ImportLock::restore_stale_claims`]); holding the lock
//! proves no running import owns it. Nothing claimed is ever deleted unread.
//!
//! In the root, only the names kpx-share uses mean anything: staging directories (a
//! [`SafeName`]), `.work-*` and claimed directories. Anything else there is left alone.

use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs::File;
use std::io::{self, Read as _};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags, RenameFlags};
use rustix::io::Errno;

use super::manifest::{self, MANIFEST_BYTES_MAX, MANIFEST_FILE, ManifestError};
use super::plan::{Attachment, Plan, Role};
use crate::layout::{
    DirError, NotOurs, PrivateTmpfsDir, RootError, SafeName, WhenMissing, random_name,
    require_ours, require_ours_and_private, split_random_name,
};
use crate::secret::SecretBytes;

/// Below `$XDG_RUNTIME_DIR`.
pub const IMPORT_ROOT_DIR: &str = "kpx-import";

/// How a claimed staging directory's name starts; then 16 random hex digits, `.` and the staging
/// directory's own name. That name is a [`SafeName`], which never starts with `.`, so a claimed
/// directory is never taken for a staging one.
const CLAIMED_PREFIX: &str = ".claimed.";

/// Bound on one attachment: a key, a certificate, a QR code image is kilobytes; this leaves room
/// for a larger document without letting a wrong file fill memory.
pub const ATTACHMENT_BYTES_MAX: u64 = 16 * 1024 * 1024;

/// Bound on an entry's password: a longer one is not credible as a password.
pub const PASSWORD_BYTES_MAX: u64 = 4096;

#[derive(Debug, thiserror::Error)]
pub enum StagingError {
    #[error("XDG_RUNTIME_DIR is not set, so there is no staging area to import from")]
    NoRuntimeDir,
    #[error("nothing is staged: {} does not exist", .0.display())]
    NothingStaged(PathBuf),
    #[error(transparent)]
    Root(RootError),
    #[error(
        "another import is running (it holds {}); wait for it to finish, then import again",
        .0.display()
    )]
    Busy(PathBuf),
    #[error("cannot lock {}: {source}", .path.display())]
    Lock { path: PathBuf, source: io::Error },
    #[error(transparent)]
    Dir(#[from] DirError),
    #[error("cannot claim {}: {source}", .path.display())]
    Claim { path: PathBuf, source: io::Error },
    #[error("{} changed while it was claimed; nothing was read, and {restored}", .path.display())]
    ChangedWhileClaimed { path: PathBuf, restored: Restored },
    #[error("{}: {source}", .path.display())]
    List { path: PathBuf, source: io::Error },
    #[error(
        "{} is not something the manifest names; the staging directory must hold only {MANIFEST_FILE} and its files",
        .0
    )]
    Unexpected(String),
    #[error(transparent)]
    Manifest(#[from] ManifestError),
    #[error("the file of {0} is not in the staging directory")]
    Missing(Role),
    #[error("the file of {0} is a symlink")]
    Symlink(Role),
    #[error("the file of {0} is not a regular file")]
    NotRegular(Role),
    #[error("the file of {role} is {source}")]
    WrongOwner { role: Role, source: NotOurs },
    #[error("cannot read the file of {role}: {source}")]
    Read { role: Role, source: io::Error },
    #[error("the file of {role} is larger than {max} bytes")]
    TooLarge { role: Role, max: u64 },
    #[error("the file of {0} is empty")]
    Empty(Role),
    #[error("the password's file {0}")]
    Password(PasswordProblem),
}

/// Why a staged password cannot be the entry's: keepassxc-cli reads it as one line of text, so
/// it strips a CR, replaces invalid UTF-8, and cannot take a line feed or NUL.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PasswordProblem {
    #[error("is not valid UTF-8")]
    NotUtf8,
    #[error("holds a NUL, CR or LF byte (keepassxc-cli reads the password as one line)")]
    LineBreakOrNul,
}

// --- The root and its lock --------------------------------------------------------------------

/// Witness that `$XDG_RUNTIME_DIR/kpx-import` is a private directory on tmpfs. The agent creates
/// it; kpx-share never does, so its absence means nothing was staged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportRoot {
    dir: PrivateTmpfsDir,
}

impl ImportRoot {
    /// # Errors
    /// `runtime_dir` is absent or empty, the root does not exist, or [`PrivateTmpfsDir::at`]
    /// refuses it.
    pub fn in_runtime_dir(runtime_dir: Option<&OsStr>) -> Result<Self, StagingError> {
        let runtime_dir = runtime_dir
            .filter(|dir| !dir.is_empty())
            .ok_or(StagingError::NoRuntimeDir)?;
        let path = Path::new(runtime_dir).join(IMPORT_ROOT_DIR);
        match PrivateTmpfsDir::at(&path, WhenMissing::Refuse) {
            Ok(dir) => Ok(Self { dir }),
            Err(RootError::Dir(DirError::Io { source, .. }))
                if source.kind() == io::ErrorKind::NotFound =>
            {
                Err(StagingError::NothingStaged(path))
            }
            Err(error) => Err(StagingError::Root(error)),
        }
    }

    /// Takes the one import's lock: an exclusive `flock` on the root directory itself, so no
    /// lock file is left and none can be planted, released when the [`ImportLock`] is dropped
    /// (or the process dies). The descriptor is close-on-exec, so no child holds it.
    ///
    /// # Errors
    /// [`StagingError::Busy`] when another import holds it; never waits.
    pub fn lock(self) -> Result<ImportLock, StagingError> {
        let path = self.dir.path().to_owned();
        let fd = open_private_dir(rustix::fs::CWD, &path, &path)?;
        match rustix::fs::flock(&fd, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => Ok(ImportLock { root: self, fd }),
            Err(Errno::WOULDBLOCK) => Err(StagingError::Busy(path)),
            Err(errno) => Err(StagingError::Lock {
                path,
                source: errno.into(),
            }),
        }
    }
}

/// Witness that this process is the only import on the root, held open and locked: every step
/// that touches the root (the claim, the work directory, the commit, the cleanup) takes it, so
/// none can run without the lock.
#[derive(Debug)]
pub struct ImportLock {
    root: ImportRoot,
    fd: OwnedFd,
}

impl ImportLock {
    #[must_use]
    pub fn path(&self) -> &Path {
        self.root.dir.path()
    }

    fn fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    /// Puts back the staging directories earlier imports claimed and never returned (killed,
    /// interrupted): each claimed directory is renamed to the name it records, unless something
    /// has that name now. Under the lock, no running import owns one, so each is stale.
    ///
    /// # Errors
    /// The root cannot be listed.
    pub fn restore_stale_claims(&self) -> Result<Vec<StaleClaim>, StagingError> {
        let mut stale = Vec::new();
        for raw in list_raw(self.fd(), self.path())? {
            let Some(claimed) = ClaimedName::parse(&raw) else {
                continue;
            };
            let is_dir = rustix::fs::statat(self.fd(), raw.as_os_str(), AtFlags::SYMLINK_NOFOLLOW)
                .is_ok_and(|stat| FileType::from_raw_mode(stat.st_mode) == FileType::Directory);
            if !is_dir {
                continue;
            }
            let from = self.path().join(&raw);
            let to = self.path().join(claimed.origin.as_str());
            stale.push(
                match rename_no_replace(
                    self.fd(),
                    raw.as_os_str(),
                    OsStr::new(claimed.origin.as_str()),
                ) {
                    Ok(()) => StaleClaim::Restored { from, to },
                    Err(Errno::EXIST | Errno::NOTEMPTY) => StaleClaim::NameTaken { from, to },
                    Err(errno) => StaleClaim::Failed {
                        from,
                        source: errno.into(),
                    },
                },
            );
        }
        Ok(stale)
    }
}

/// What became of a claimed directory an earlier import left.
#[derive(Debug)]
pub enum StaleClaim {
    Restored {
        from: PathBuf,
        to: PathBuf,
    },
    /// Left where it is: `to` exists, and neither is deleted.
    NameTaken {
        from: PathBuf,
        to: PathBuf,
    },
    Failed {
        from: PathBuf,
        source: io::Error,
    },
}

impl fmt::Display for StaleClaim {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Restored { from, to } => write!(
                f,
                "put {} back as {}: an earlier import was interrupted after claiming it",
                from.display(),
                to.display()
            ),
            Self::NameTaken { from, to } => write!(
                f,
                "{} holds files an interrupted import claimed, which may be in no database, and {} exists again: look into both, then import one, or delete what you do not need",
                from.display(),
                to.display()
            ),
            Self::Failed { from, source } => write!(
                f,
                "cannot put back {}, which an interrupted import claimed: {source}",
                from.display()
            ),
        }
    }
}

/// `.claimed.<16 hex>.<origin>`: a claimed staging directory, and the name it came from.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ClaimedName {
    random: String,
    origin: SafeName,
}

impl ClaimedName {
    fn new(origin: &SafeName) -> io::Result<Self> {
        let random = random_name("")?
            .into_string()
            .map_err(|_| io::Error::other("random hex is not UTF-8"))?;
        Ok(Self {
            random,
            origin: origin.clone(),
        })
    }

    /// The name parsed, or `None` for any other name: an exact prefix, exactly 16 lower-case
    /// hex digits, `.`, and a [`SafeName`].
    fn parse(name: &OsStr) -> Option<Self> {
        let (random, rest) = split_random_name(name, OsStr::new(CLAIMED_PREFIX))?;
        let origin = std::str::from_utf8(rest.strip_prefix(b".")?).ok()?;
        Some(Self {
            random: random.to_owned(),
            origin: SafeName::parse(origin)?,
        })
    }

    fn file_name(&self) -> OsString {
        OsString::from(format!(
            "{CLAIMED_PREFIX}{}.{}",
            self.random,
            self.origin.as_str()
        ))
    }
}

fn rename_no_replace(dir: BorrowedFd<'_>, from: &OsStr, to: &OsStr) -> Result<(), Errno> {
    rustix::fs::renameat_with(dir, from, dir, to, RenameFlags::NOREPLACE)
}

/// Every name directly in the directory `fd` (called `path` in errors), `.` and `..` excepted,
/// whatever its bytes: for the root, where unknown names are passed over.
fn list_raw(fd: BorrowedFd<'_>, path: &Path) -> Result<Vec<OsString>, StagingError> {
    let list_error = |source: Errno| StagingError::List {
        path: path.to_owned(),
        source: source.into(),
    };
    let mut names = Vec::new();
    let mut dir = Dir::read_from(fd).map_err(list_error)?;
    while let Some(item) = dir.read() {
        let item = item.map_err(list_error)?;
        let raw = item.file_name().to_bytes();
        if raw != b"." && raw != b".." {
            names.push(OsStr::from_bytes(raw).to_owned());
        }
    }
    Ok(names)
}

/// The names directly in a staging directory, which may hold only names kpx-share could have
/// been told about: one that is not UTF-8 is refused here.
fn list(fd: BorrowedFd<'_>, path: &Path) -> Result<BTreeSet<String>, StagingError> {
    list_raw(fd, path)?
        .into_iter()
        .map(|raw| {
            raw.into_string().map_err(|raw| {
                StagingError::Unexpected(path.join(raw).to_string_lossy().into_owned())
            })
        })
        .collect()
}

// --- The claimed directory --------------------------------------------------------------------

/// Witness that `<root>/<name>` is a real directory of ours, mode 0700, held open: not yet out of
/// the agent's reach.
#[derive(Debug)]
pub struct Opened<'l> {
    lock: &'l ImportLock,
    fd: OwnedFd,
    name: SafeName,
}

impl<'l> Opened<'l> {
    /// # Errors
    /// It does not exist, is a symlink or not a directory, is not ours, or has another mode.
    pub fn open(lock: &'l ImportLock, name: &SafeName) -> Result<Self, StagingError> {
        let path = lock.path().join(name.as_str());
        match open_private_dir(lock.fd(), Path::new(name.as_str()), &path) {
            Ok(fd) => Ok(Self {
                lock,
                fd,
                name: name.clone(),
            }),
            Err(DirError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
                Err(StagingError::NothingStaged(path))
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Renames the directory out of the agent's reach and checks what was renamed is what was
    /// opened.
    ///
    /// # Errors
    /// See [`Opened::rename`] and [`Renamed::verify`].
    pub fn claim(self) -> Result<Claimed<'l>, StagingError> {
        self.rename()?.verify()
    }

    /// Renames `<name>` to `.claimed.<random>.<name>`, not over anything.
    ///
    /// # Errors
    /// The rename fails.
    pub fn rename(self) -> Result<Renamed<'l>, StagingError> {
        let path = self.lock.path().join(self.name.as_str());
        let claim_error = |source: io::Error| StagingError::Claim {
            path: path.clone(),
            source,
        };
        let renamed = ClaimedName::new(&self.name).map_err(claim_error)?;
        rename_no_replace(
            self.lock.fd(),
            OsStr::new(self.name.as_str()),
            renamed.file_name().as_os_str(),
        )
        .map_err(|errno| claim_error(errno.into()))?;
        Ok(Renamed(Claimed {
            lock: self.lock,
            fd: self.fd,
            name: self.name,
            renamed,
        }))
    }
}

/// A staging directory renamed, not yet checked to be the one opened.
#[derive(Debug)]
pub struct Renamed<'l>(Claimed<'l>);

impl<'l> Renamed<'l> {
    /// The claimed directory, when the directory now at the claimed name is the one opened;
    /// otherwise it is put back and the change reported, with where it went.
    ///
    /// # Errors
    /// [`StagingError::ChangedWhileClaimed`].
    pub fn verify(self) -> Result<Claimed<'l>, StagingError> {
        let claimed = self.0;
        let at_name = rustix::fs::statat(
            claimed.lock.fd(),
            claimed.renamed.file_name().as_os_str(),
            AtFlags::SYMLINK_NOFOLLOW,
        );
        let opened = rustix::fs::fstat(&claimed.fd);
        match (at_name, opened) {
            (Ok(at_name), Ok(opened))
                if (at_name.st_dev, at_name.st_ino) == (opened.st_dev, opened.st_ino) =>
            {
                Ok(claimed)
            }
            _ => {
                let path = claimed.staging_path();
                Err(StagingError::ChangedWhileClaimed {
                    path,
                    restored: claimed.restore(),
                })
            }
        }
    }
}

/// Witness that the staging directory `<name>` was renamed, under the lock, to `renamed` in the
/// root, checked to be the directory held open: a real directory of ours, mode 0700.
#[derive(Debug)]
pub struct Claimed<'l> {
    lock: &'l ImportLock,
    fd: OwnedFd,
    name: SafeName,
    renamed: ClaimedName,
}

impl Claimed<'_> {
    /// Where the claimed directory is now.
    #[must_use]
    pub fn path(&self) -> PathBuf {
        self.lock.path().join(self.renamed.file_name())
    }

    /// Where it is put back.
    fn staging_path(&self) -> PathBuf {
        self.lock.path().join(self.name.as_str())
    }

    /// Reads `manifest.json`, checks that the directory holds exactly it and the files it names,
    /// and reads each of those once.
    ///
    /// # Errors
    /// See [`StagingError`]; all of them before anything is decrypted.
    pub fn read(&self) -> Result<Staged, StagingError> {
        let json = self.read_file(&manifest_file(), &Role::Manifest, MANIFEST_BYTES_MAX)?;
        let manifest = manifest::parse(json.expose())?;
        self.check_listing(&manifest)?;
        let plan = manifest.try_map(
            |file, ()| {
                EntryPassword::parse(self.read_file(file, &Role::Password, PASSWORD_BYTES_MAX)?)
            },
            |name, file, ()| {
                let role = Role::Attachment(name.clone());
                let bytes = self.read_file(file, &role, ATTACHMENT_BYTES_MAX)?;
                AttachmentContent::parse(role, bytes)
            },
        )?;
        Ok(Staged {
            plan,
            manifest: json,
        })
    }

    /// The directory holds `manifest.json`, the files the manifest names, and nothing else.
    fn check_listing(&self, manifest: &manifest::Manifest) -> Result<(), StagingError> {
        let mut listed = list(self.fd.as_fd(), &self.path())?;
        listed.remove(MANIFEST_FILE);
        for (role, file) in manifest.files() {
            if !listed.remove(file.as_str()) {
                return Err(StagingError::Missing(role));
            }
        }
        match listed.into_iter().next() {
            Some(stranger) => Err(StagingError::Unexpected(
                self.staging_path().join(stranger).display().to_string(),
            )),
            None => Ok(()),
        }
    }

    /// The whole of `<claimed>/<file>`, at most `max` bytes, which must be a regular file of
    /// ours. Opened without following a link and without blocking on a FIFO.
    fn read_file(
        &self,
        file: &SafeName,
        role: &Role,
        max: u64,
    ) -> Result<SecretBytes, StagingError> {
        let read_error = |source: io::Error| StagingError::Read {
            role: role.clone(),
            source,
        };
        let fd = self.open_file(file).map_err(|errno| match errno {
            Errno::NOENT => StagingError::Missing(role.clone()),
            Errno::LOOP => StagingError::Symlink(role.clone()),
            errno => read_error(errno.into()),
        })?;
        let stat = rustix::fs::fstat(&fd).map_err(|errno| read_error(errno.into()))?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
            return Err(StagingError::NotRegular(role.clone()));
        }
        require_ours(stat.st_uid).map_err(|source| StagingError::WrongOwner {
            role: role.clone(),
            source,
        })?;
        let bytes = SecretBytes::read_to_end(File::from(fd).take(max.saturating_add(1)))
            .map_err(read_error)?;
        if u64::try_from(bytes.len()).map_or(true, |len| len > max) {
            return Err(StagingError::TooLarge {
                role: role.clone(),
                max,
            });
        }
        Ok(bytes)
    }

    fn open_file(&self, file: &SafeName) -> Result<OwnedFd, Errno> {
        rustix::fs::openat(
            &self.fd,
            file.as_str(),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NOCTTY | OFlags::NONBLOCK,
            Mode::empty(),
        )
    }

    /// Whether `<claimed>/<file>` still holds exactly `bytes`: read up to one byte more.
    fn still_holds(&self, file: &SafeName, bytes: &[u8]) -> io::Result<bool> {
        let fd = self.open_file(file)?;
        let limit = u64::try_from(bytes.len()).map_or(u64::MAX, |len| len.saturating_add(1));
        let now = SecretBytes::read_to_end(File::from(fd).take(limit))?;
        Ok(now.expose() == bytes)
    }

    /// After the database is proven to hold `staged`, or found to hold it already: deletes each
    /// file read that still holds the bytes read, then the directory. A file that changed
    /// meanwhile, or one that appeared, is not the import's to delete: it is kept, the directory
    /// put back under its name, and both reported. Nothing here undoes the import.
    #[must_use]
    pub fn finish(self, staged: &Staged) -> Vec<CleanupProblem> {
        let mut problems = Vec::new();
        for (role, file, read) in staged.files() {
            match self.still_holds(&file, read) {
                Ok(true) => {
                    if let Err(source) =
                        rustix::fs::unlinkat(&self.fd, file.as_str(), AtFlags::empty())
                    {
                        problems.push(CleanupProblem::Unlink {
                            role,
                            source: source.into(),
                        });
                    }
                }
                Ok(false) => problems.push(CleanupProblem::Changed(role)),
                // Gone already: nothing of it is left to delete.
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(source) => problems.push(CleanupProblem::Unlink { role, source }),
            }
        }
        let removed = rustix::fs::unlinkat(
            self.lock.fd(),
            self.renamed.file_name().as_os_str(),
            AtFlags::REMOVEDIR,
        );
        if removed.is_ok() {
            return problems;
        }
        let left = list_raw(self.fd.as_fd(), &self.path());
        let at = match self.restore() {
            Restored::Back(path) => path,
            Restored::Kept(kept) => {
                let at = kept.claimed.clone();
                problems.push(CleanupProblem::Kept(kept));
                at
            }
        };
        match left {
            Ok(left) => problems.extend(
                left.into_iter()
                    .map(|name| CleanupProblem::Left(at.join(name))),
            ),
            Err(error) => problems.push(CleanupProblem::Unlisted { at, error }),
        }
        problems
    }

    /// Puts the directory back under its name, unless something took the name meanwhile.
    #[must_use]
    pub fn restore(self) -> Restored {
        let renamed = self.renamed.file_name();
        match rename_no_replace(
            self.lock.fd(),
            renamed.as_os_str(),
            OsStr::new(self.name.as_str()),
        ) {
            Ok(()) => Restored::Back(self.staging_path()),
            Err(errno) => Restored::Kept(KeptAt {
                claimed: self.path(),
                reason: match errno {
                    Errno::EXIST | Errno::NOTEMPTY => KeptBecause::NameTaken(self.staging_path()),
                    errno => KeptBecause::Io(errno.into()),
                },
            }),
        }
    }
}

fn manifest_file() -> SafeName {
    SafeName::parse(MANIFEST_FILE)
        .unwrap_or_else(|| unreachable!("{MANIFEST_FILE:?} is a safe name"))
}

/// Where [`Claimed::restore`] left the staging directory.
#[derive(Debug)]
pub enum Restored {
    /// Back under its name.
    Back(PathBuf),
    Kept(KeptAt),
}

impl fmt::Display for Restored {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Back(path) => write!(f, "it is back in {}", path.display()),
            Self::Kept(kept) => kept.fmt(f),
        }
    }
}

/// A claimed directory that could not be put back under its name.
#[derive(Debug)]
pub struct KeptAt {
    pub claimed: PathBuf,
    pub reason: KeptBecause,
}

#[derive(Debug)]
pub enum KeptBecause {
    /// Something new is at the staging directory's name.
    NameTaken(PathBuf),
    Io(io::Error),
}

impl fmt::Display for KeptAt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let claimed = self.claimed.display();
        match &self.reason {
            KeptBecause::NameTaken(name) => write!(
                f,
                "the staged files are kept in {claimed}: {} exists again, so they were not moved back",
                name.display()
            ),
            KeptBecause::Io(error) => write!(
                f,
                "the staged files are kept in {claimed}: cannot move them back: {error}"
            ),
        }
    }
}

/// What finishing the staging directory left behind. None of it undoes the import.
#[derive(Debug)]
pub enum CleanupProblem {
    /// A file that was imported could not be deleted.
    Unlink { role: Role, source: io::Error },
    /// The file of `role` no longer holds what was imported: kept.
    Changed(Role),
    /// Something the manifest does not name, added during the import: not ours to delete.
    Left(PathBuf),
    /// What is left in `at` could not be listed, so is not named here.
    Unlisted { at: PathBuf, error: StagingError },
    /// The directory, holding what was kept, could not be put back under its name.
    Kept(KeptAt),
}

impl fmt::Display for CleanupProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unlink { role, source } => {
                write!(f, "cannot delete the imported file of {role}: {source}")
            }
            Self::Changed(role) => write!(
                f,
                "kept the file of {role}: it changed during the import, and what is in it now was not imported"
            ),
            Self::Left(path) => write!(
                f,
                "left {}: it appeared during the import and is not in the manifest",
                path.display()
            ),
            Self::Unlisted { at, error } => write!(
                f,
                "{} holds something besides what was imported, which cannot be listed: {error}",
                at.display()
            ),
            Self::Kept(kept) => kept.fmt(f),
        }
    }
}

/// Opens `name` below `at` without following a link, and checks it is a directory of ours with
/// mode 0700. `path` is what errors call it.
///
/// Not opened `O_DIRECTORY`: with it a symlink fails as "not a directory", and the descriptor's
/// own type tells the two apart. `O_NONBLOCK` and `O_NOCTTY` keep a FIFO or a terminal in its
/// place from blocking or being adopted; `O_CLOEXEC` keeps it from every child.
fn open_private_dir(at: impl AsFd, name: &Path, path: &Path) -> Result<OwnedFd, DirError> {
    let fd = rustix::fs::openat(
        at,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK | OFlags::NOCTTY,
        Mode::empty(),
    )
    .map_err(|errno| match errno {
        Errno::LOOP => DirError::Symlink {
            path: path.to_owned(),
        },
        errno => DirError::Io {
            path: path.to_owned(),
            source: errno.into(),
        },
    })?;
    let stat = rustix::fs::fstat(&fd).map_err(|errno| DirError::Io {
        path: path.to_owned(),
        source: errno.into(),
    })?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory {
        return Err(DirError::NotDirectory {
            path: path.to_owned(),
        });
    }
    require_ours_and_private(path, stat.st_uid, stat.st_mode)?;
    Ok(fd)
}

// --- What was staged --------------------------------------------------------------------------

/// A new entry's password as staged: 1 to [`PASSWORD_BYTES_MAX`] bytes of UTF-8 without NUL, CR
/// or LF, so keepassxc-cli stores exactly these bytes.
#[derive(Debug)]
pub struct EntryPassword(SecretBytes);

impl EntryPassword {
    fn parse(bytes: SecretBytes) -> Result<Self, StagingError> {
        if bytes.is_empty() {
            return Err(StagingError::Empty(Role::Password));
        }
        if u64::try_from(bytes.len()).map_or(true, |len| len > PASSWORD_BYTES_MAX) {
            return Err(StagingError::TooLarge {
                role: Role::Password,
                max: PASSWORD_BYTES_MAX,
            });
        }
        if std::str::from_utf8(bytes.expose()).is_err() {
            return Err(StagingError::Password(PasswordProblem::NotUtf8));
        }
        if bytes
            .expose()
            .iter()
            .any(|byte| matches!(byte, b'\0' | b'\r' | b'\n'))
        {
            return Err(StagingError::Password(PasswordProblem::LineBreakOrNul));
        }
        Ok(Self(bytes))
    }

    #[must_use]
    pub fn secret(&self) -> &SecretBytes {
        &self.0
    }

    #[cfg(test)]
    pub(crate) fn for_tests(bytes: &[u8]) -> Self {
        Self(SecretBytes::copy_from(bytes))
    }
}

/// An attachment's bytes as staged: 1 to [`ATTACHMENT_BYTES_MAX`] bytes, any bytes.
#[derive(Debug)]
pub struct AttachmentContent(SecretBytes);

impl AttachmentContent {
    fn parse(role: Role, bytes: SecretBytes) -> Result<Self, StagingError> {
        if bytes.is_empty() {
            return Err(StagingError::Empty(role));
        }
        if u64::try_from(bytes.len()).map_or(true, |len| len > ATTACHMENT_BYTES_MAX) {
            return Err(StagingError::TooLarge {
                role,
                max: ATTACHMENT_BYTES_MAX,
            });
        }
        Ok(Self(bytes))
    }

    #[must_use]
    pub fn secret(&self) -> &SecretBytes {
        &self.0
    }

    #[cfg(test)]
    pub(crate) fn for_tests(bytes: &[u8]) -> Self {
        Self(SecretBytes::copy_from(bytes))
    }
}

/// A staged attachment: its name, its file and its bytes.
pub type StagedAttachment = Attachment<AttachmentContent>;

/// An import with every secret read: what is confirmed, written and compared.
pub type StagedPlan = Plan<EntryPassword, AttachmentContent>;

/// Everything staged, read once and checked. Built only by [`Claimed::read`].
#[derive(Debug)]
pub struct Staged {
    plan: StagedPlan,
    /// The manifest's bytes as read, to see at the cleanup that it still holds them.
    manifest: SecretBytes,
}

impl Staged {
    #[must_use]
    pub fn plan(&self) -> &StagedPlan {
        &self.plan
    }

    /// Every file read, with what it is for and the bytes read from it, the manifest first:
    /// what [`Claimed::finish`] may delete.
    fn files(&self) -> Vec<(Role, SafeName, &[u8])> {
        let password = self.plan.password().map(|password| {
            (
                Role::Password,
                password.file().clone(),
                password.content().secret().expose(),
            )
        });
        let attachments = self.plan.attachments().iter().map(|attachment| {
            (
                Role::Attachment(attachment.name().clone()),
                attachment.file().clone(),
                attachment.content().secret().expose(),
            )
        });
        std::iter::once((Role::Manifest, manifest_file(), self.manifest.expose()))
            .chain(password)
            .chain(attachments)
            .collect()
    }

    /// A staged import that was never read from disk, so nothing can be deleted for it.
    #[cfg(test)]
    pub(crate) fn for_tests(plan: StagedPlan) -> Self {
        Self {
            plan,
            manifest: SecretBytes::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    /// A root on tmpfs, locked, with a staging directory `hvac` (0700) holding one file.
    fn locked_root() -> (tempfile::TempDir, ImportLock) {
        let runtime = std::env::var_os("XDG_RUNTIME_DIR").expect("XDG_RUNTIME_DIR is tmpfs");
        let scratch = tempfile::TempDir::new_in(runtime).unwrap();
        let root = scratch.path().join(IMPORT_ROOT_DIR);
        private_dir(&root);
        private_dir(&root.join("hvac"));
        std::fs::write(root.join("hvac/manifest.json"), b"{}").unwrap();
        let lock = ImportRoot::in_runtime_dir(Some(scratch.path().as_os_str()))
            .unwrap()
            .lock()
            .unwrap();
        (scratch, lock)
    }

    fn private_dir(path: &Path) {
        std::fs::create_dir(path).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    fn hvac() -> SafeName {
        SafeName::parse("hvac").unwrap()
    }

    /// A claimed name records where it came from, and only exactly that shape is one. Red when
    /// the parse takes a near miss for a claimed directory.
    #[test]
    fn a_claimed_name_is_its_prefix_16_hex_digits_and_a_safe_name() {
        let parsed = ClaimedName::parse(OsStr::new(".claimed.0123456789abcdef.hvac")).unwrap();
        assert_eq!(parsed.origin, hvac());
        assert_eq!(
            parsed.file_name(),
            OsString::from(".claimed.0123456789abcdef.hvac")
        );
        for near_miss in [
            ".claimed.0123456789abcde.hvac",
            ".claimed.0123456789abcdefa.hvac",
            ".claimed.0123456789ABCDEF.hvac",
            ".claimed.0123456789abcdef-hvac",
            ".claimed.0123456789abcdef.",
            ".claimed.0123456789abcdef..hidden",
            ".claimed-0123456789abcdef.hvac",
            "hvac",
        ] {
            assert_eq!(
                ClaimedName::parse(OsStr::new(near_miss)),
                None,
                "{near_miss}"
            );
        }
        let made = ClaimedName::new(&hvac()).unwrap();
        assert_eq!(ClaimedName::parse(&made.file_name()), Some(made));
    }

    /// `<name>` swapped for another directory between the open and the rename: the claim is
    /// refused, what was renamed is put back, and the opened directory is left where the swap
    /// put it. Red without the inode check.
    #[test]
    fn a_directory_swapped_between_open_and_rename_is_refused_and_put_back() {
        let (scratch, lock) = locked_root();
        let root = scratch.path().join(IMPORT_ROOT_DIR);
        let opened = Opened::open(&lock, &hvac()).unwrap();
        std::fs::rename(root.join("hvac"), root.join("elsewhere")).unwrap();
        private_dir(&root.join("hvac"));

        let error = opened.claim().unwrap_err();

        assert!(
            matches!(
                &error,
                StagingError::ChangedWhileClaimed {
                    restored: Restored::Back(_),
                    ..
                }
            ),
            "{error:?}"
        );
        assert!(error.to_string().contains("it is back in"), "{error}");
        assert!(root.join("hvac").is_dir());
        assert!(root.join("elsewhere/manifest.json").exists());
        assert_eq!(lock.restore_stale_claims().unwrap().len(), 0);
    }

    /// When the swapped directory cannot be put back either (the name is taken again), the
    /// refusal says where it is, and nothing is deleted. Red when that is not reported.
    #[test]
    fn a_failed_put_back_after_a_swap_is_reported() {
        let (scratch, lock) = locked_root();
        let root = scratch.path().join(IMPORT_ROOT_DIR);
        let opened = Opened::open(&lock, &hvac()).unwrap();
        std::fs::rename(root.join("hvac"), root.join("elsewhere")).unwrap();
        private_dir(&root.join("hvac"));
        let renamed = opened.rename().unwrap();
        private_dir(&root.join("hvac"));
        std::fs::write(root.join("hvac/new"), b"x").unwrap();

        let error = renamed.verify().unwrap_err();

        let shown = error.to_string();
        assert!(
            matches!(
                &error,
                StagingError::ChangedWhileClaimed {
                    restored: Restored::Kept(KeptAt {
                        reason: KeptBecause::NameTaken(_),
                        ..
                    }),
                    ..
                }
            ),
            "{error:?}"
        );
        assert!(shown.contains("the staged files are kept in"), "{shown}");
        assert!(shown.contains(".claimed."), "{shown}");
        assert!(root.join("hvac/new").exists());
        assert!(root.join("elsewhere/manifest.json").exists());
    }
}
