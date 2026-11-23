//! `import`: write what an agent staged on tmpfs into the database, after the human confirms,
//! and prove the database holds every staged byte before deleting the staged copy.
//!
//! The order is the point, and each step's result is the next one's input:
//!
//! 1. [`ImportRoot::lock`] makes this the only import running, until the end: every later step
//!    takes the [`ImportLock`]. Staging directories an interrupted import claimed are put back
//!    ([`ImportLock::restore_stale_claims`]). [`Opened::claim`] renames this one out of the
//!    agent's reach, and [`Claimed::read`] reads it once into memory and checks every rule;
//!    [`LiveDatabase::resolve`] finds the file to replace. Nothing is decrypted yet.
//! 2. [`confirm`](confirm::confirm) asks the human, showing names and sizes only. Nothing is
//!    decrypted, and no password asked for, before the go (invariant S7).
//! 3. The database's bytes are read once and copied into a [`WorkDir`] on the same tmpfs; it is
//!    unlocked, exported and [`preflight`]ed, written ([`ImportKey`]) and exported again, and
//!    [`prove`]n against the first export: only the staged things were added (S1).
//! 4. [`commit`] replaces the database with the proven copy, by one rename, only while the file
//!    still holds the bytes first read (S2), and reads it back (S3).
//! 5. Once the database holds what was staged (proven in 4, or found already there by the
//!    preflight in 3), exactly the files read, still holding what was read, are deleted (S4).
//!    Every other ending puts the staging directory back.
//!
//! Secrets (S5, S6) live in [`SecretBytes`](crate::SecretBytes) read once from the staging files,
//! and reach keepassxc-cli only on its stdin or a pipe; what is printed is names and sizes. A
//! dialog the human closes is [`Outcome::Declined`], carried as a value to the end.

/// Unwraps an [`Outcome::Done`], or returns `Ok(Outcome::Declined)` from the function.
macro_rules! done {
    ($outcome:expr) => {
        match $outcome {
            $crate::unlock::Outcome::Done(value) => value,
            $crate::unlock::Outcome::Declined => {
                return Ok($crate::unlock::Outcome::Declined);
            }
        }
    };
}

pub mod check;
pub mod confirm;
pub mod database;
pub mod manifest;
pub mod plan;
pub mod staging;

use std::ffi::OsStr;
use std::fmt;
use std::io::{self, Write};
use std::path::PathBuf;

use crate::export::{self, ExportError};
use crate::layout::SafeName;
use crate::mode::Mode;
use crate::model::Database;
use crate::unlock::{
    ImportKey, NewEntryFields, Outcome, UnlockError, UnlockRequest, UnlockTools, Unlocked,
    check_pipeable, unlock_for_import,
};
use check::{CheckError, Preflight, preflight, prove};
use confirm::{ConfirmError, Decision};
use database::{
    CommitError, CommitRefusal, DatabaseError, DatabaseFiles, LiveDatabase, Unverified, WorkDir,
    commit, remove_leftovers,
};
use manifest::{AttachmentName, EntryPath};
use plan::Kind;
use staging::{
    Claimed, CleanupProblem, ImportLock, ImportRoot, Opened, Restored, Staged, StagedPlan,
    StagingError,
};

/// The programs and files `import` uses. Production is [`ImportTools::production`]; tests hand
/// in fakes.
#[derive(Debug)]
pub struct ImportTools<'a> {
    pub unlock: UnlockTools,
    /// Where the answer is read from in a terminal.
    pub tty: PathBuf,
    pub files: &'a dyn DatabaseFiles,
}

impl<'a> ImportTools<'a> {
    /// The real programs, by absolute path, chosen for how the human is reached.
    #[must_use]
    pub fn production(mode: Mode, files: &'a dyn DatabaseFiles) -> Self {
        Self {
            unlock: UnlockTools::production(mode),
            tty: PathBuf::from("/dev/tty"),
            files,
        }
    }
}

/// What the human asked `import` to do.
#[derive(Clone, Debug)]
pub struct ImportRequest {
    pub database: UnlockRequest,
    pub name: SafeName,
}

/// One thing imported, or found already there.
#[derive(Debug)]
pub enum Item {
    Entry {
        entry: EntryPath,
        /// Its length; `None` when no password was staged, so the entry's is empty.
        password_bytes: Option<usize>,
    },
    Attachment {
        entry: EntryPath,
        name: AttachmentName,
        bytes: usize,
    },
}

impl fmt::Display for Item {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Entry {
                entry,
                password_bytes: Some(bytes),
            } => write!(f, "entry {entry} (password {bytes} bytes)"),
            Self::Entry {
                entry,
                password_bytes: None,
            } => write!(f, "entry {entry} (no password)"),
            Self::Attachment { entry, name, bytes } => {
                write!(f, "attachment {name} ({bytes} bytes) to {entry}")
            }
        }
    }
}

/// What an import that succeeded did.
#[derive(Debug)]
pub struct Report {
    pub database: PathBuf,
    pub entry: EntryPath,
    pub items: Vec<Item>,
    /// What deleting the staging directory left; the import stands regardless.
    pub cleanup: Vec<CleanupProblem>,
}

/// How an `import` that did not fail ended.
#[derive(Debug)]
pub enum Imported {
    /// The database holds what was staged, proven; the staged files are deleted.
    Added(Report),
    /// The database already held all of it, unchanged; the staged files are deleted.
    AlreadyThere(Report),
    /// The human said no, or closed a dialog. Nothing changed; the staging directory is back.
    Declined,
}

/// What a failed import left of the database.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DatabaseState {
    Unchanged,
    /// Replaced, but not proven to hold the copy: the staged files are kept.
    ReplacedUnverified,
}

#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    #[error(transparent)]
    Staging(#[from] StagingError),
    #[error(transparent)]
    Database(#[from] DatabaseError),
    #[error(transparent)]
    Unlock(#[from] UnlockError),
    #[error(transparent)]
    Confirm(#[from] ConfirmError),
    #[error("cannot read the database {}: {source}", .path.display())]
    Read { path: PathBuf, source: io::Error },
    #[error("cannot copy the database into the staging root: {0}")]
    Copy(io::Error),
    #[error("cannot read the written copy of the database: {0}")]
    ReadCopy(io::Error),
    #[error("the database export could not be read: {0}")]
    Export(#[from] ExportError),
    #[error(transparent)]
    Check(#[from] CheckError<UnlockError>),
    #[error("the copy changed while it was checked; nothing was written")]
    CopyChanged,
    #[error(transparent)]
    Refused(#[from] CommitRefusal),
    #[error(
        "{} was replaced, but {reason}; the staged files are kept: open it in KeePassXC and check entry {entry}",
        .path.display()
    )]
    Unverified {
        path: PathBuf,
        entry: EntryPath,
        reason: Unverified,
    },
}

impl ImportError {
    #[must_use]
    pub fn database_state(&self) -> DatabaseState {
        match self {
            Self::Unverified { .. } => DatabaseState::ReplacedUnverified,
            Self::Staging(_)
            | Self::Database(_)
            | Self::Unlock(_)
            | Self::Confirm(_)
            | Self::Read { .. }
            | Self::Copy(_)
            | Self::ReadCopy(_)
            | Self::Export(_)
            | Self::Check(_)
            | Self::CopyChanged
            | Self::Refused(_) => DatabaseState::Unchanged,
        }
    }
}

/// What the database got, when nothing failed or was declined.
#[derive(Clone, Copy, Debug)]
enum Applied {
    Added,
    AlreadyThere,
}

/// Imports what is staged under `request.name` into the database.
///
/// `err` is where notices go, and on a terminal the confirmation summary.
///
/// # Errors
/// See [`ImportError`]; [`ImportError::database_state`] says what it left. On every error the
/// staging directory is put back (or, when that is impossible, where it is is reported).
pub fn import(
    runtime_dir: Option<&OsStr>,
    tools: &ImportTools<'_>,
    request: &ImportRequest,
    err: &mut dyn Write,
) -> Result<Imported, ImportError> {
    let lock = ImportRoot::in_runtime_dir(runtime_dir)?.lock()?;
    for stale in lock.restore_stale_claims()? {
        notice(err, format_args!("{stale}"));
    }
    let claimed = Opened::open(&lock, &request.name)?.claim()?;
    let staged = match claimed.read() {
        Ok(staged) => staged,
        Err(error) => {
            put_back(claimed, err);
            return Err(error.into());
        }
    };
    match proceed(&lock, &staged, tools, request, err) {
        Ok(Outcome::Done((applied, database))) => {
            let items = items(staged.plan());
            let report = Report {
                database,
                entry: staged.plan().entry().clone(),
                items,
                cleanup: claimed.finish(&staged),
            };
            Ok(match applied {
                Applied::Added => Imported::Added(report),
                Applied::AlreadyThere => Imported::AlreadyThere(report),
            })
        }
        Ok(Outcome::Declined) => {
            put_back(claimed, err);
            Ok(Imported::Declined)
        }
        Err(error) => {
            put_back(claimed, err);
            Err(error)
        }
    }
}

/// Puts the staging directory back, saying where it is when that cannot be done.
fn put_back(claimed: Claimed<'_>, err: &mut dyn Write) {
    match claimed.restore() {
        Restored::Back(_) => {}
        Restored::Kept(kept) => notice(err, format_args!("{kept}")),
    }
}

/// Everything after the staging directory is read: the go, the copy, the writes, the proof and
/// the commit. Returns the database's resolved path with what it got.
fn proceed(
    lock: &ImportLock,
    staged: &Staged,
    tools: &ImportTools<'_>,
    request: &ImportRequest,
    err: &mut dyn Write,
) -> Result<Outcome<(Applied, PathBuf)>, ImportError> {
    let plan = staged.plan();
    let live = LiveDatabase::resolve(&request.database.database)?;
    check_pipeable(&request.database, &tools.unlock.prompter)?;

    let summary = confirm::summary(&live.path(), staged);
    match confirm::confirm(&tools.unlock.prompter, &tools.tty, &summary, err)? {
        Decision::Import => {}
        Decision::Declined => return Ok(Outcome::Declined),
    }

    for (path, error) in remove_leftovers(lock, &live) {
        notice(
            err,
            format_args!("cannot remove {}: {error}", path.display()),
        );
    }
    let original = tools
        .files
        .read(&live.path())
        .map_err(|source| ImportError::Read {
            path: live.path(),
            source,
        })?;
    let work = WorkDir::with_copy(lock, &original).map_err(ImportError::Copy)?;
    // The dialogs name the database as the summary did, by its resolved path; keepassxc-cli runs
    // on the copy.
    let shown = UnlockRequest {
        database: live.path(),
        ..request.database.clone()
    };
    let entry = plan.entry().cli_path();
    let Unlocked { xml, key } = done!(unlock_for_import(
        &tools.unlock,
        &shown,
        &work.copy(),
        &entry
    )?);
    let before = export::parse(xml)?;
    match done!(preflight(&before, plan, |name| key.export_attachment(name))?) {
        Preflight::AlreadyDone => return Ok(Outcome::Done((Applied::AlreadyThere, live.path()))),
        Preflight::ToDo => {}
    }

    let proven = done!(write_and_prove(key, &before, plan, &work)?);
    match commit(lock, &live, &original, &proven, tools.files) {
        Ok(()) => Ok(Outcome::Done((Applied::Added, live.path()))),
        Err(CommitError::Refused(refusal)) => Err(refusal.into()),
        Err(CommitError::Unverified(reason)) => Err(ImportError::Unverified {
            path: live.path(),
            entry: plan.entry().clone(),
            reason,
        }),
    }
}

/// Writes `plan` to the copy, proves the result against `before`, and returns the copy's bytes:
/// read before the proof and again after it, so they are the bytes that were proven.
fn write_and_prove(
    key: ImportKey,
    before: &Database,
    plan: &StagedPlan,
    work: &WorkDir,
) -> Result<Outcome<Vec<u8>>, ImportError> {
    done!(apply(&key, plan)?);
    let candidate = read_copy(work)?;
    let after = export::parse(done!(key.export_again()?))?;
    done!(prove(before, &after, plan, |name| key.export_attachment(name))?);
    drop(key);
    if read_copy(work)? == candidate {
        Ok(Outcome::Done(candidate))
    } else {
        Err(ImportError::CopyChanged)
    }
}

/// Writes `plan` to the copy: the entry when it is new, then each attachment.
fn apply(key: &ImportKey, plan: &StagedPlan) -> Result<Outcome<()>, UnlockError> {
    if let Kind::New { username, url, .. } = plan.kind() {
        done!(key.add_entry(&NewEntryFields {
            username: username.as_ref().map(manifest::FieldText::as_str),
            url: url.as_ref().map(manifest::EntryUrl::as_str),
            password: plan.password().map(|password| password.content().secret()),
        })?);
    }
    for attachment in plan.attachments() {
        done!(key.import_attachment(attachment.name().as_str(), attachment.content().secret())?);
    }
    Ok(Outcome::Done(()))
}

/// The copy's bytes: ciphertext, so not a [`SecretBytes`](crate::SecretBytes).
fn read_copy(work: &WorkDir) -> Result<Vec<u8>, ImportError> {
    std::fs::read(work.copy()).map_err(ImportError::ReadCopy)
}

fn items(plan: &StagedPlan) -> Vec<Item> {
    let entry = match plan.kind() {
        Kind::New { .. } => Some(Item::Entry {
            entry: plan.entry().clone(),
            password_bytes: plan.password().map(|pw| pw.content().secret().len()),
        }),
        Kind::Existing(_) => None,
    };
    entry
        .into_iter()
        .chain(
            plan.attachments()
                .iter()
                .map(|attachment| Item::Attachment {
                    entry: plan.entry().clone(),
                    name: attachment.name().clone(),
                    bytes: attachment.content().secret().len(),
                }),
        )
        .collect()
}

fn notice(err: &mut dyn Write, message: fmt::Arguments<'_>) {
    // Failing to write a notice leaves nowhere to report it.
    let _unreportable = writeln!(err, "kpx-share: {message}");
}
