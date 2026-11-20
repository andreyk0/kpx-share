//! `ls`, `rm` and `gc`: looking at and cleaning up what has been shared.
//!
//! None of it reads a secret: listing reads `meta.json` (names, never values) and cleaning reads
//! `.session.json`.

use std::fmt;
use std::io;
use std::path::PathBuf;
use std::time::Duration;

use jiff::Timestamp;

use crate::layout::{
    DirError, ListError, RemoveEntryError, SafeName, SessionDir, SessionName, SessionSlot,
    ShareRoot,
};
use crate::process::ProcessError;
use crate::session::{self, RecordError, SessionEnd, UNRECORDED_GRACE};
use crate::text::one_line;

// --- ls ---------------------------------------------------------------------------------------

/// When a session's directory goes, which is every entry's expiry in it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionExpiry {
    At(Timestamp),
    /// The directory has no record yet (an add died before writing it), so nothing is scheduled.
    Unrecorded,
}

impl fmt::Display for SessionExpiry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::At(at) => write!(f, "{at}"),
            Self::Unrecorded => f.write_str("-"),
        }
    }
}

/// One entry shared into a session, as `ls` shows it.
#[derive(Debug)]
pub enum ListedLine {
    Shared {
        slug: SafeName,
        /// `Group/Sub/Title`.
        path: String,
        /// The session's, not the one in the entry's `meta.json`: a later add with a shorter TTL
        /// moves the session's expiry, and the directory goes then.
        expires_at: SessionExpiry,
    },
    /// The entry directory is there but its `meta.json` is not usable.
    Unreadable { slug: SafeName, problem: String },
}

impl fmt::Display for ListedLine {
    /// `slug<TAB>path<TAB>expiry`. The path is a database value, so it is made one line: one
    /// entry is always one line.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Shared {
                slug,
                path,
                expires_at,
            } => {
                write!(f, "{slug}\t{}\t{expires_at}", one_line(path))
            }
            Self::Unreadable { slug, problem } => write!(f, "{slug}\t(unreadable: {problem})\t-"),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ListSessionError {
    #[error(transparent)]
    List(#[from] ListError),
    #[error(transparent)]
    Record(#[from] RecordError),
}

/// The entries in `session`, by slug, each with the session's expiry.
///
/// # Errors
/// The directory cannot be listed or its session record cannot be read.
pub fn list(session: &SessionDir) -> Result<Vec<ListedLine>, ListSessionError> {
    let expires_at = match session::read_record(session)? {
        Some(record) => SessionExpiry::At(record.expires_at()),
        None => SessionExpiry::Unrecorded,
    };
    Ok(session
        .entries()?
        .into_iter()
        .map(|listed| {
            let slug = listed.dir.slug().clone();
            match listed.meta {
                Ok(meta) => ListedLine::Shared {
                    slug,
                    path: meta.path,
                    expires_at,
                },
                Err(error) => ListedLine::Unreadable {
                    slug,
                    problem: error.to_string(),
                },
            }
        })
        .collect())
}

// --- rm ---------------------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum RemoveError {
    #[error(transparent)]
    Dir(#[from] DirError),
    #[error(transparent)]
    Entry(#[from] RemoveEntryError),
    #[error("cannot remove the session directory {}: {source}", .path.display())]
    Session { path: PathBuf, source: io::Error },
}

/// What `rm` did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Removed {
    Entry,
    /// The whole session directory. The watcher keeps waiting until the session it remembers
    /// ends (its process exits or its expiry passes), so a later add into the same session is
    /// still watched.
    Session,
    /// There was no session directory: nothing had been shared, which is what was asked for.
    NothingShared,
}

/// Removes one entry of session `name`.
///
/// # Errors
/// There is no such session or entry, or it cannot be removed.
pub fn remove_entry(
    root: &ShareRoot,
    name: &SessionName,
    slug: &SafeName,
) -> Result<Removed, RemoveError> {
    let Some(session) = SessionDir::find(root, name)? else {
        return Err(RemoveEntryError::NotFound(slug.clone()).into());
    };
    session.remove_entry(slug)?;
    Ok(Removed::Entry)
}

/// Removes session `name` and everything in it.
///
/// # Errors
/// The directory is not ours, or something in it cannot be removed.
pub fn remove_session(root: &ShareRoot, name: &SessionName) -> Result<Removed, RemoveError> {
    match SessionDir::find(root, name)? {
        None => Ok(Removed::NothingShared),
        Some(session) => {
            let path = session.path().to_owned();
            session
                .remove()
                .map_err(|source| RemoveError::Session { path, source })?;
            Ok(Removed::Session)
        }
    }
}

// --- gc ---------------------------------------------------------------------------------------

/// Why `gc` removed a session directory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RemovedBecause {
    Ended(SessionEnd),
    /// It has no usable record and has not been touched for longer than [`UNRECORDED_GRACE`]:
    /// abandoned by an add that died.
    Unrecorded {
        idle: Duration,
    },
}

/// What `gc` did with one thing under the share root.
#[derive(Debug)]
pub enum GcOutcome {
    Removed(RemovedBecause),
    /// Its session is still going.
    Live,
    /// Removed between listing and looking, by its watcher or by `rm`: the goal is met.
    AlreadyGone,
    /// No usable record, but touched within [`UNRECORDED_GRACE`]: it may be a session being
    /// created, so it stays.
    KeptRecent {
        problem: String,
    },
    /// Not a session directory (wrong name, not a directory); never touched.
    Foreign,
    Failed(String),
}

#[derive(Debug)]
pub struct GcEntry {
    pub path: PathBuf,
    pub outcome: GcOutcome,
}

/// What a `gc` report adds up to: how many directories it removed, how many it left alone
/// (everything that was neither removed nor failed) and how many it could not judge or remove.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GcSummary {
    pub removed: usize,
    pub kept: usize,
    pub failed: usize,
}

impl GcSummary {
    #[must_use]
    pub fn of(report: &[GcEntry]) -> Self {
        let count = |wanted: fn(&GcOutcome) -> bool| {
            report.iter().filter(|entry| wanted(&entry.outcome)).count()
        };
        let removed = count(|outcome| matches!(outcome, GcOutcome::Removed(_)));
        let failed = count(|outcome| matches!(outcome, GcOutcome::Failed(_)));
        Self {
            removed,
            kept: report.len() - removed - failed,
            failed,
        }
    }
}

impl fmt::Display for GcSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} removed, {} kept, {} failed",
            self.removed, self.kept, self.failed
        )
    }
}

impl fmt::Display for GcEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let path = self.path.display();
        match &self.outcome {
            GcOutcome::Removed(RemovedBecause::Ended(end)) => write!(f, "removed {path}: {end}"),
            GcOutcome::Removed(RemovedBecause::Unrecorded { idle }) => write!(
                f,
                "removed {path}: no session record, untouched for {} minutes",
                idle.as_secs() / 60
            ),
            GcOutcome::Live => write!(f, "kept {path}: its session is live"),
            GcOutcome::AlreadyGone => write!(f, "{path} was already gone"),
            GcOutcome::KeptRecent { problem } => {
                write!(f, "kept {path}: {problem}, but it was touched recently")
            }
            GcOutcome::Foreign => write!(f, "kept {path}: not a session directory"),
            GcOutcome::Failed(problem) => write!(f, "failed {path}: {problem}"),
        }
    }
}

/// Removes every session directory under `root` whose session has ended at `now`: its process is
/// gone or its expiry passed. This is what cleans up after a watcher that died.
///
/// A directory with no usable record is removed only when it has not been modified for longer
/// than [`UNRECORDED_GRACE`]; a younger one may be a session being created.
///
/// # Errors
/// The root cannot be read; a problem with one directory is its [`GcOutcome::Failed`].
pub fn gc(root: &ShareRoot, now: Timestamp) -> io::Result<Vec<GcEntry>> {
    Ok(root
        .session_slots()?
        .into_iter()
        .map(|slot| match slot {
            SessionSlot::Foreign(path) => GcEntry {
                path,
                outcome: GcOutcome::Foreign,
            },
            SessionSlot::Session(name) => GcEntry {
                path: root.path().join(name.as_str()),
                outcome: judge(root, &name, now),
            },
        })
        .collect())
}

#[derive(Debug, thiserror::Error)]
enum JudgeError {
    #[error(transparent)]
    Dir(#[from] DirError),
    #[error(transparent)]
    Process(#[from] ProcessError),
    #[error("cannot remove it: {0}")]
    Remove(io::Error),
    #[error("cannot tell how long it has been idle: {0}")]
    Idle(io::Error),
}

fn judge(root: &ShareRoot, name: &SessionName, now: Timestamp) -> GcOutcome {
    judge_session(root, name, now).unwrap_or_else(|error| GcOutcome::Failed(error.to_string()))
}

fn judge_session(
    root: &ShareRoot,
    name: &SessionName,
    now: Timestamp,
) -> Result<GcOutcome, JudgeError> {
    let Some(dir) = SessionDir::find(root, name)? else {
        return Ok(GcOutcome::AlreadyGone);
    };
    match session::read_record(&dir) {
        Ok(Some(record)) => match record.ended(now)? {
            Some(end) => {
                dir.remove().map_err(JudgeError::Remove)?;
                Ok(GcOutcome::Removed(RemovedBecause::Ended(end)))
            }
            None => Ok(GcOutcome::Live),
        },
        Ok(None) => unrecorded(dir, now, "it has no session record".to_owned()),
        Err(error) => unrecorded(dir, now, format!("unusable session record: {error}")),
    }
}

fn unrecorded(dir: SessionDir, now: Timestamp, problem: String) -> Result<GcOutcome, JudgeError> {
    let modified = std::fs::metadata(dir.path())
        .and_then(|meta| meta.modified())
        .map_err(JudgeError::Idle)?;
    let modified =
        Timestamp::try_from(modified).map_err(|error| JudgeError::Idle(io::Error::other(error)))?;
    let idle = Duration::try_from(now.duration_since(modified)).unwrap_or(Duration::ZERO);
    if idle > UNRECORDED_GRACE {
        dir.remove().map_err(JudgeError::Remove)?;
        Ok(GcOutcome::Removed(RemovedBecause::Unrecorded { idle }))
    } else {
        Ok(GcOutcome::KeptRecent { problem })
    }
}
