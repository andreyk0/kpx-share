//! The database file `import` replaces, the copy it works on, and the one write to the file.
//!
//! [`LiveDatabase`] resolves the configured path once, to the file a rename can replace:
//! symlinks followed (the link stays a link), and refused unless it is a regular file of ours
//! with one link, since a rename would leave a second hard link holding the old version. Its
//! bytes are read once ([`DatabaseFiles`]) and copied into a [`WorkDir`] on the staging root's
//! tmpfs; everything until [`commit`] runs on the copy. The work directory holds only ciphertext
//! and is removed when dropped, on every exit path.
//!
//! [`commit`] is the only write to the database (invariant S2): the proven copy is written and
//! synced beside it first, then the file is read again and must still hold the bytes first read,
//! and only then is the copy renamed onto it, after which the file is read back and must be
//! byte-identical to the proven copy (S3). The same ciphertext under the same key is the same
//! plaintext, so what was proven of the copy holds of the file.
//!
//! Every step here takes the [`ImportLock`]: none of them can run outside one import's lock.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs;
use std::io::{self, Write as _};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use super::staging::ImportLock;
use crate::layout::{
    BoundedReadError, NotOurs, PERMISSION_BITS, create_private_dir, no_follow_flag, random_name,
    read_bounded, require_ours, split_random_name, write_private_file,
};

/// Bound on the database file. A personal database with attachments is megabytes; this is far
/// above any, and refuses a wrong file before it is copied into memory and onto tmpfs.
pub const DATABASE_BYTES_MAX: u64 = 1 << 30;

/// How the work directory below the staging root is named: then 16 random hex digits. A
/// staging directory is a [`crate::layout::SafeName`], which never starts with `.`.
const WORK_DIR_PREFIX: &str = ".work-";
const COPY_FILE: &str = "db.kdbx";
/// What a temporary copy beside the database is named after `.<file name>`, then 16 random hex
/// digits.
const TEMPORARY_INFIX: &str = ".kpx-import-";

#[derive(Debug, thiserror::Error)]
pub enum DatabaseError {
    #[error("cannot resolve the database {}: {source}", .path.display())]
    Resolve { path: PathBuf, source: io::Error },
    #[error("the database {} is not a regular file", .0.display())]
    NotRegular(PathBuf),
    #[error("the database {} is {source}", .path.display())]
    WrongOwner { path: PathBuf, source: NotOurs },
    #[error(
        "the database {} has {links} hard links; replacing it would leave the others on the old version",
        .path.display()
    )]
    HardLinked { path: PathBuf, links: u64 },
}

/// Witness that `dir/file` is the canonical path of a regular file of ours with one link: what
/// `import` reads, and the one path it renames onto; `mode` is what its replacement gets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiveDatabase {
    dir: PathBuf,
    file: OsString,
    mode: u32,
}

impl LiveDatabase {
    /// # Errors
    /// See [`DatabaseError`].
    pub fn resolve(configured: &Path) -> Result<Self, DatabaseError> {
        let resolve_error = |path: &Path, source| DatabaseError::Resolve {
            path: path.to_owned(),
            source,
        };
        let path =
            fs::canonicalize(configured).map_err(|source| resolve_error(configured, source))?;
        // A canonical path of a file has both; `/` alone is a directory, refused below.
        let (Some(dir), Some(file)) = (path.parent(), path.file_name()) else {
            return Err(DatabaseError::NotRegular(path));
        };
        let meta = fs::symlink_metadata(&path).map_err(|source| resolve_error(&path, source))?;
        if !meta.file_type().is_file() {
            return Err(DatabaseError::NotRegular(path));
        }
        if let Err(source) = require_ours(meta.uid()) {
            return Err(DatabaseError::WrongOwner { path, source });
        }
        if meta.nlink() != 1 {
            return Err(DatabaseError::HardLinked {
                path,
                links: meta.nlink(),
            });
        }
        Ok(Self {
            dir: dir.to_owned(),
            file: file.to_owned(),
            mode: meta.mode() & PERMISSION_BITS,
        })
    }

    #[must_use]
    pub fn path(&self) -> PathBuf {
        self.dir.join(&self.file)
    }

    /// `.<file>.kpx-import-`: how every temporary copy beside the database starts.
    fn temporary_prefix(&self) -> OsString {
        let mut prefix = OsString::from(".");
        prefix.push(&self.file);
        prefix.push(TEMPORARY_INFIX);
        prefix
    }
}

/// Everything [`commit`] does to the live database's files, in its order: the first read, the
/// copy written beside it and synced, the read before the rename, the rename, the directory's
/// sync and the read back. Production is [`Disk`]; tests hand in one that records, changes the
/// file or fails, to see the order kept and each failure handled.
pub trait DatabaseFiles: fmt::Debug {
    /// # Errors
    /// The file cannot be read, or is larger than [`DATABASE_BYTES_MAX`].
    fn read(&self, path: &Path) -> io::Result<Vec<u8>>;

    /// Writes all of `bytes` to `file`, just created beside the database.
    ///
    /// # Errors
    /// The write fails.
    fn write(&self, file: &mut fs::File, bytes: &[u8]) -> io::Result<()>;

    /// Syncs `file`'s data to the disk.
    ///
    /// # Errors
    /// The sync fails.
    fn sync(&self, file: &fs::File) -> io::Result<()>;

    /// # Errors
    /// The rename fails.
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()>;

    /// Syncs the directory `dir`, so a rename in it is on the disk.
    ///
    /// # Errors
    /// It cannot be opened or synced.
    fn sync_dir(&self, dir: &Path) -> io::Result<()>;
}

/// The files themselves.
#[derive(Debug)]
pub struct Disk;

impl DatabaseFiles for Disk {
    fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        read_bounded(path, DATABASE_BYTES_MAX).map_err(|error| match error {
            BoundedReadError::Io(error) => error,
            BoundedReadError::TooLarge { max } => {
                io::Error::other(format!("larger than {max} bytes"))
            }
        })
    }

    fn write(&self, file: &mut fs::File, bytes: &[u8]) -> io::Result<()> {
        file.write_all(bytes)
    }

    fn sync(&self, file: &fs::File) -> io::Result<()> {
        file.sync_all()
    }

    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        fs::rename(from, to)
    }

    fn sync_dir(&self, dir: &Path) -> io::Result<()> {
        fs::File::open(dir).and_then(|dir| dir.sync_all())
    }
}

/// `<staging root>/.work-<random>/`, holding the copy of the database `import` works on. Removed
/// with everything in it when dropped.
#[derive(Debug)]
pub struct WorkDir {
    path: PathBuf,
}

impl WorkDir {
    /// Creates the directory (0700) and writes `database` into it as the copy (0600).
    ///
    /// # Errors
    /// Either cannot be created.
    pub fn with_copy(lock: &ImportLock, database: &[u8]) -> io::Result<Self> {
        let path = lock.path().join(random_name(WORK_DIR_PREFIX)?);
        create_private_dir(&path)?;
        let work = Self { path };
        write_private_file(&work.copy(), database)?;
        Ok(work)
    }

    /// The copy of the database.
    #[must_use]
    pub fn copy(&self) -> PathBuf {
        self.path.join(COPY_FILE)
    }
}

impl Drop for WorkDir {
    fn drop(&mut self) {
        // Ciphertext only, on tmpfs; a directory left behind is removed by the next import.
        let _left_for_the_next_import = fs::remove_dir_all(&self.path);
    }
}

/// Removes what earlier imports left (a crash, a kill), all of it ciphertext: work directories
/// of ours (`.work-*`) directly below the root, and temporary copies of ours
/// (`.<file>.kpx-import-*`) beside the database. Returns what could not be removed.
#[must_use]
pub fn remove_leftovers(lock: &ImportLock, database: &LiveDatabase) -> Vec<(PathBuf, io::Error)> {
    let mut failures = remove_ours(lock.path(), OsStr::new(WORK_DIR_PREFIX), Leftover::Dir);
    failures.extend(remove_ours(
        &database.dir,
        &database.temporary_prefix(),
        Leftover::File,
    ));
    failures
}

/// What kind of thing a leftover is; anything else under its name is not ours and is left.
#[derive(Clone, Copy)]
enum Leftover {
    Dir,
    File,
}

/// Whether `name` is `prefix` and exactly the 16 lower-case hex digits [`random_name`] adds:
/// the only names kpx-share gives, so a file like `.db.kdbx.lock` beside the database is not one.
fn is_named_ours(name: &OsStr, prefix: &OsStr) -> bool {
    split_random_name(name, prefix).is_some_and(|(_, rest)| rest.is_empty())
}

fn remove_ours(dir: &Path, prefix: &OsStr, kind: Leftover) -> Vec<(PathBuf, io::Error)> {
    let mut failures = Vec::new();
    let items = match fs::read_dir(dir) {
        Ok(items) => items,
        Err(error) => return vec![(dir.to_owned(), error)],
    };
    for item in items {
        let item = match item {
            Ok(item) => item,
            Err(error) => {
                failures.push((dir.to_owned(), error));
                continue;
            }
        };
        if !is_named_ours(&item.file_name(), prefix) {
            continue;
        }
        // `DirEntry::metadata` does not follow a symlink.
        let meta = match item.metadata() {
            Ok(meta) => meta,
            Err(error) => {
                failures.push((item.path(), error));
                continue;
            }
        };
        if require_ours(meta.uid()).is_err() {
            continue;
        }
        let removed = match kind {
            Leftover::Dir if meta.is_dir() => fs::remove_dir_all(item.path()),
            Leftover::File if meta.is_file() => fs::remove_file(item.path()),
            Leftover::Dir | Leftover::File => continue,
        };
        if let Err(error) = removed {
            failures.push((item.path(), error));
        }
    }
    failures
}

/// Why the database was not replaced: it holds exactly what it held before.
#[derive(Debug, thiserror::Error)]
pub enum CommitRefusal {
    #[error(
        "{} changed during the import (saved by KeePassXC meanwhile?); nothing was written, import again with KeePassXC not saving",
        .0.display()
    )]
    Changed(PathBuf),
    #[error("cannot read {} again: {source}", .path.display())]
    Reread { path: PathBuf, source: io::Error },
    #[error("cannot write {}: {source}", .path.display())]
    Write { path: PathBuf, source: io::Error },
    #[error("cannot rename {} onto {}: {source}", .from.display(), .to.display())]
    Rename {
        from: PathBuf,
        to: PathBuf,
        source: io::Error,
    },
}

/// The database was replaced, but is not proven to hold the proven copy.
#[derive(Debug, thiserror::Error)]
pub enum Unverified {
    #[error("cannot sync the directory {}: {source}", .path.display())]
    SyncDir { path: PathBuf, source: io::Error },
    #[error("cannot read it back: {0}")]
    ReadBack(io::Error),
    #[error("reading it back gave other bytes than were written")]
    Differs,
}

/// How [`commit`] failed, by what it left: the file untouched, or replaced and unproven.
#[derive(Debug)]
pub enum CommitError {
    Refused(CommitRefusal),
    Unverified(Unverified),
}

/// Replaces the database with `proven` when it still holds `original`, then reads it back.
///
/// # Errors
/// See [`CommitError`]. A refusal leaves no temporary file behind.
pub fn commit(
    _lock: &ImportLock,
    database: &LiveDatabase,
    original: &[u8],
    proven: &[u8],
    files: &dyn DatabaseFiles,
) -> Result<(), CommitError> {
    let path = database.path();
    let temporary = write_beside(database, proven, files).map_err(CommitError::Refused)?;
    let unchanged = still_original(&path, original, files);
    let renamed = unchanged.and_then(|()| {
        files
            .rename(&temporary, &path)
            .map_err(|source| CommitRefusal::Rename {
                from: temporary.clone(),
                to: path.clone(),
                source,
            })
    });
    if let Err(refusal) = renamed {
        let _already_gone = fs::remove_file(&temporary);
        return Err(CommitError::Refused(refusal));
    }
    files.sync_dir(&database.dir).map_err(|source| {
        CommitError::Unverified(Unverified::SyncDir {
            path: database.dir.clone(),
            source,
        })
    })?;
    let read_back = files
        .read(&path)
        .map_err(|error| CommitError::Unverified(Unverified::ReadBack(error)))?;
    if read_back == proven {
        Ok(())
    } else {
        Err(CommitError::Unverified(Unverified::Differs))
    }
}

/// The file at `path` still holds `original`: read right before the rename, after the slow
/// write of the copy, so a save landing meanwhile is seen.
fn still_original(
    path: &Path,
    original: &[u8],
    files: &dyn DatabaseFiles,
) -> Result<(), CommitRefusal> {
    let now = files.read(path).map_err(|source| CommitRefusal::Reread {
        path: path.to_owned(),
        source,
    })?;
    if now == original {
        Ok(())
    } else {
        Err(CommitRefusal::Changed(path.to_owned()))
    }
}

/// Writes `bytes` to `.<file>.kpx-import-<random>` beside the database, with its mode, synced:
/// a temporary name a rename moves onto the database atomically. Removed again on failure.
fn write_beside(
    database: &LiveDatabase,
    bytes: &[u8],
    files: &dyn DatabaseFiles,
) -> Result<PathBuf, CommitRefusal> {
    let write_error = |at: &Path, source| CommitRefusal::Write {
        path: at.to_owned(),
        source,
    };
    let name = random_name(database.temporary_prefix())
        .map_err(|source| write_error(&database.path(), source))?;
    let temporary = database.dir.join(name);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(database.mode)
        .custom_flags(no_follow_flag())
        .open(&temporary)
        .map_err(|source| write_error(&temporary, source))?;
    let written = file
        // `open` applies the umask; the copy gets exactly the database's mode.
        .set_permissions(fs::Permissions::from_mode(database.mode))
        .and_then(|()| files.write(&mut file, bytes))
        .and_then(|()| files.sync(&file));
    match written {
        Ok(()) => Ok(temporary),
        Err(source) => {
            let _already_gone = fs::remove_file(&temporary);
            Err(write_error(&temporary, source))
        }
    }
}
