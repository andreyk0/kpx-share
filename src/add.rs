//! `add`: unlock the database, let the human pick one entry, write it into the session.
//!
//! The order is the point of this module, and the types hold it:
//!
//! 1. [`ShareRoot`] (tmpfs checked) and then [`Session`] (directory and record) exist before
//!    anything secret does: [`unlock_into`] takes the [`Session`] it does not otherwise need, so
//!    the database cannot be unlocked, and a password cannot be asked for, until there is a
//!    tmpfs session to write into (invariant I1).
//! 2. The watcher is running before the first secret is written, so a session directory with
//!    secrets in it is never unwatched (I3); a watcher that cannot be started fails the add
//!    with nothing written.
//! 3. Only the one picked entry is resolved and written (I2). When the export carries no
//!    attachment bytes (a KDBX 4 database), the picked entry's attachments are exported one by
//!    one with the key that unlocked the database, which is dropped once they are read.
//! 4. The watcher is asked for again once the entry is written, before its path is returned. A
//!    watcher that had seen the session end and was exiting still reads as running to the first
//!    request, which can then precede the whole unlock and pick; the second request narrows
//!    that window to the time the write takes. A session whose watcher cannot be started then
//!    loses the entry just written; on a re-add under the same slug that is the only copy, since
//!    the write already replaced the older one.

use std::ffi::OsStr;

use jiff::Timestamp;

use crate::export::{self, ExportError};
use crate::launch::{Launch, WatcherLauncher, WatcherSpec};
use crate::layout::{EntryDir, RemoveEntryError, RootError, SessionDir, ShareRoot};
use crate::mode::Mode;
use crate::pick::{ChooseError, Picker, Query, choose};
use crate::select::{Eligibility, PickError, ResolveError};
use crate::session::{Binding, Session, SessionError, Ttl};
use crate::subprocess::ToolError;
use crate::unlock::{
    ShareKey, UnlockError, UnlockRequest, UnlockTools, Unlocked, unlock_for_share,
};
use crate::writer::{WriteError, write_entry};

/// The programs `add` runs. Production is [`AddTools::production`]; tests hand in fakes.
#[derive(Debug)]
pub struct AddTools<'a> {
    pub unlock: UnlockTools,
    pub picker: Picker,
    pub launcher: &'a dyn WatcherLauncher,
}

impl<'a> AddTools<'a> {
    /// The real programs, by absolute path, chosen for how the human is reached.
    #[must_use]
    pub fn production(mode: Mode, launcher: &'a dyn WatcherLauncher) -> Self {
        Self {
            unlock: UnlockTools::production(mode),
            picker: Picker::for_mode(mode),
            launcher,
        }
    }
}

/// What the human asked `add` to do.
#[derive(Clone, Debug)]
pub struct AddRequest {
    pub database: UnlockRequest,
    pub query: Option<Query>,
    pub eligibility: Eligibility,
    pub ttl: Ttl,
}

/// Where `add` runs: the value of `XDG_RUNTIME_DIR` and the session this process is in.
#[derive(Clone, Copy, Debug)]
pub struct Where<'a> {
    pub runtime_dir: Option<&'a OsStr>,
    pub binding: &'a Binding,
}

#[derive(Debug, thiserror::Error)]
pub enum AddError {
    #[error(transparent)]
    Root(#[from] RootError),
    #[error(transparent)]
    Session(#[from] SessionError),
    #[error("cannot start the watcher that deletes the session: {0}")]
    Watcher(#[from] ToolError),
    #[error(transparent)]
    Unlock(#[from] UnlockError),
    #[error("the database export could not be read: {0}")]
    Export(#[from] ExportError),
    #[error(transparent)]
    Choose(#[from] ChooseError),
    #[error(transparent)]
    Pick(#[from] PickError),
    #[error(transparent)]
    Resolve(#[from] ResolveError<UnlockError>),
    #[error(transparent)]
    Write(#[from] WriteError),
    #[error(
        "cannot start the watcher that deletes the session, and the entry written without it could not be removed: {watcher}; {removal}"
    )]
    EntryUnwatched {
        watcher: ToolError,
        removal: RemoveEntryError,
    },
}

/// How an `add` that did not fail ended.
#[derive(Debug)]
pub enum Added {
    /// The entry is written; this is its directory.
    Shared(EntryDir),
    /// The human closed the password dialog or the picker. Nothing was written.
    Declined,
}

/// Shares one entry of the database into the session and returns its directory.
///
/// # Errors
/// See [`AddError`]. Until the watcher is running nothing secret has been read or written. A
/// failure inside [`write_entry`] leaves no new entry directory (see there for the two
/// exceptions, which leave the entry in place). When the watcher cannot be started after the
/// write, the entry just written is removed again, and the add fails.
pub fn add(at: Where<'_>, tools: &AddTools<'_>, request: &AddRequest) -> Result<Added, AddError> {
    let root = ShareRoot::in_runtime_dir(at.runtime_dir)?;
    let session = Session::open(&root, at.binding, request.ttl, Timestamp::now())?;
    let watcher = WatcherSpec {
        root: &root,
        session: session.dir().name(),
    };
    tools.launcher.ensure_running(&watcher)?;

    let Unlocked { xml, key } = match unlock_into(&session, tools, &request.database) {
        Ok(unlocked) => unlocked,
        Err(UnlockError::Cancelled) => return Ok(Added::Declined),
        Err(error) => return Err(error.into()),
    };
    let database = export::parse(xml)?;
    let items = database.picker_items(&request.eligibility);
    let uuid = match choose(&items, request.query.as_ref(), &tools.picker) {
        Ok(uuid) => uuid,
        Err(ChooseError::Cancelled) => return Ok(Added::Declined),
        Err(error) => return Err(error.into()),
    };
    let picked = database.pick(uuid, request.eligibility.clone())?;
    let entry = match picked.resolve(|entry, name| key.export_attachment(entry, name)) {
        Ok(entry) => entry,
        Err(ResolveError::Attachment {
            source: UnlockError::Cancelled,
            ..
        }) => return Ok(Added::Declined),
        Err(error) => return Err(error.into()),
    };
    drop(key);

    let written = write_entry(session.dir(), &entry, &session.validity())?;
    match tools.launcher.ensure_running(&watcher) {
        Ok(Launch::Started | Launch::AlreadyRunning) => Ok(Added::Shared(written)),
        Err(watcher_error) => Err(unshare(session.dir(), &written, watcher_error)),
    }
}

/// The error for an entry that cannot be watched: removes it, so no secret is left in a session
/// nothing will delete.
fn unshare(session: &SessionDir, written: &EntryDir, watcher: ToolError) -> AddError {
    match session.remove_entry(written.slug()) {
        // Already gone is the goal.
        Ok(()) | Err(RemoveEntryError::NotFound(_)) => AddError::Watcher(watcher),
        Err(removal) => AddError::EntryUnwatched { watcher, removal },
    }
}

/// Unlocks the database for `session`, which the password dialog names. Asking for the session is
/// also what makes "a tmpfs session exists" a precondition of reading the database.
fn unlock_into(
    session: &Session,
    tools: &AddTools<'_>,
    request: &UnlockRequest,
) -> Result<Unlocked<ShareKey>, UnlockError> {
    unlock_for_share(&tools.unlock, request, session.dir().name())
}
