//! The watcher: deletes a session directory when its session ends (invariant I3).
//!
//! It follows the session record, not a copy of it: each time it wakes it reads
//! `.session.json` again, and a record on disk replaces the one it remembers. It sleeps in `poll`
//! on a pidfd of the watched process, with the time left until `expires_at` as the timeout, and
//! at most [`WatchPace::recheck`] so that a record that was rewritten or a clock that jumped is
//! noticed.
//!
//! A vanished directory or record does not end the watch while the remembered session is live:
//! `add` asks systemd whether a watcher runs and, finding one, relies on it, so a watcher that
//! left early (an `rm --all` racing an add, an expired session recreated while the old watcher
//! wakes) would leave the new entry unwatched. The watcher exits once the session it last knew
//! has ended, deleting the directory if there is one, or when it never learned of a session.

use std::io;
use std::thread;
use std::time::{Duration, Instant};

use jiff::Timestamp;
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::io::Errno;
use rustix::process::{PidfdFlags, pidfd_open};

use crate::layout::{DirError, SessionDir, SessionName, ShareRoot};
use crate::process::{Liveness, ProcessError};
use crate::session::{self, RecordError, SessionEnd, SessionRecord, UNRECORDED_GRACE};

/// How often the watcher looks at the directory again, and for how long it waits for a record
/// that has not appeared.
#[derive(Clone, Copy, Debug)]
pub struct WatchPace {
    /// The longest the watcher sleeps without reading the record again: how long a rewritten
    /// record (a shortened expiry, a recreated session) takes to be noticed.
    pub recheck: Duration,
    /// How long, from the start, it waits for a first record before giving up. A session
    /// directory is made with its record right after, so waiting this long is waiting for
    /// something that only a dead `add` leaves missing; see [`UNRECORDED_GRACE`].
    pub unrecorded_grace: Duration,
}

impl WatchPace {
    pub const PRODUCTION: Self = Self {
        recheck: Duration::from_secs(30),
        unrecorded_grace: UNRECORDED_GRACE,
    };
}

/// How long to wait before looking again when the pidfd says the process exited but the process
/// table has not caught up. A moment, not a loop.
const EXIT_SETTLE: Duration = Duration::from_millis(50);

#[derive(Debug, thiserror::Error)]
pub enum WatchError {
    #[error(transparent)]
    Dir(#[from] DirError),
    #[error(transparent)]
    Record(#[from] RecordError),
    #[error(transparent)]
    Process(#[from] ProcessError),
    #[error("cannot open a pidfd for the watched process: {0}")]
    Pidfd(Errno),
    #[error("waiting for the watched process failed: {0}")]
    Poll(Errno),
    #[error("cannot remove the session directory {}: {source}", .path.display())]
    Remove {
        path: std::path::PathBuf,
        source: io::Error,
    },
}

/// How a watch finished.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WatchOutcome {
    /// The session ended and its directory was deleted.
    Removed(SessionEnd),
    /// The session ended and its directory was already gone.
    EndedWithoutDirectory(SessionEnd),
    /// No record appeared within [`WatchPace::unrecorded_grace`]: there was no session to
    /// follow. Whatever directory exists is left for `gc`.
    NeverRecorded,
}

/// Watches session `name` under `root` until the session ends, at the production pace.
///
/// # Errors
/// See [`WatchError`]; every one of them leaves the directory for `gc`.
pub fn watch(root: &ShareRoot, name: &SessionName) -> Result<WatchOutcome, WatchError> {
    watch_paced(root, name, WatchPace::PRODUCTION)
}

/// [`watch`] at the given pace.
///
/// Each round reads the directory and its record afresh: a record on disk replaces the one
/// remembered, and with none on disk the remembered one decides. Until a first record has been
/// read the watcher waits, for at most [`WatchPace::unrecorded_grace`] from its start.
///
/// # Errors
/// See [`WatchError`]; every one of them leaves the directory for `gc`.
pub fn watch_paced(
    root: &ShareRoot,
    name: &SessionName,
    pace: WatchPace,
) -> Result<WatchOutcome, WatchError> {
    let started = Instant::now();
    let mut remembered: Option<SessionRecord> = None;
    loop {
        let dir = SessionDir::find(root, name)?;
        let on_disk = match &dir {
            Some(dir) => session::read_record(dir)?,
            None => None,
        };
        remembered = on_disk.or(remembered);
        let Some(record) = remembered else {
            let grace_left = pace.unrecorded_grace.saturating_sub(started.elapsed());
            if grace_left.is_zero() {
                return Ok(WatchOutcome::NeverRecorded);
            }
            thread::sleep(pace.recheck.min(grace_left));
            continue;
        };
        if let Some(end) = record.ended(Timestamp::now())? {
            return match dir {
                Some(dir) => {
                    let path = dir.path().to_owned();
                    dir.remove()
                        .map_err(|source| WatchError::Remove { path, source })?;
                    Ok(WatchOutcome::Removed(end))
                }
                None => Ok(WatchOutcome::EndedWithoutDirectory(end)),
            };
        }
        wait(&record, pace.recheck)?;
    }
}

/// Sleeps until the watched process exits, the session expires or `recheck` passes. It does not
/// decide which: the caller asks the record again.
fn wait(record: &SessionRecord, recheck: Duration) -> Result<(), WatchError> {
    let slice = record
        .remaining(Timestamp::now())
        .map_or(Duration::ZERO, |left| left.min(recheck));
    let watched = record.watched();
    let pidfd = match pidfd_open(watched.pid(), PidfdFlags::empty()) {
        Ok(pidfd) => pidfd,
        // No such process: the caller finds it gone.
        Err(Errno::SRCH) => return Ok(()),
        Err(errno) => return Err(WatchError::Pidfd(errno)),
    };
    // Only now does the pidfd name a process that cannot change: if it started when the record
    // says it did, it is the watched one, and a recycled pid is `Gone`.
    match watched.liveness()? {
        Liveness::Gone => return Ok(()),
        Liveness::Alive => {}
    }
    let timeout = Timespec {
        tv_sec: i64::try_from(slice.as_secs()).unwrap_or(i64::MAX),
        tv_nsec: slice.subsec_nanos().into(),
    };
    let mut fds = [PollFd::new(&pidfd, PollFlags::IN)];
    match poll(&mut fds, Some(&timeout)) {
        Ok(_) | Err(Errno::INTR) => {}
        Err(errno) => return Err(WatchError::Poll(errno)),
    }
    if fds.iter().any(|fd| !fd.revents().is_empty()) {
        thread::sleep(EXIT_SETTLE);
    }
    Ok(())
}
