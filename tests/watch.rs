//! The watcher (invariant I3): the session directory is deleted when the watched process exits
//! or the TTL passes, and not before.
//!
//! Method: a real `sleep` child is the watched process and a scratch share root on tmpfs holds
//! the session; `watch()` runs on a thread and reports its outcome over a channel, so a watcher
//! that never reacts fails the test by timeout instead of hanging it. Each test's doc comment
//! names the mutation that turns it red. The watcher as its own process, and under systemd, is in
//! `tests/add.rs`.

mod common;

use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use common::process::Sleeper;
use common::share::{resolve_any, scratch_on_tmpfs, validity};
use common::{entry, string};
use jiff::Timestamp;
use kpx_share::layout::{SessionDir, SessionName, ShareRoot};
use kpx_share::process::{ProcessIdentity, StartTime};
use kpx_share::session::{
    Binding, ClaudeEnv, ClaudeSessionId, Session, SessionEnd, SessionRecord, Ttl,
};
use kpx_share::watch::{WatchError, WatchOutcome, WatchPace, watch, watch_paced};
use kpx_share::writer::write_entry;
use tempfile::TempDir;

/// The watcher reacts within this of the event; it is generous for a loaded machine, and far
/// below the 30 s re-check interval, so reaching it proves the pidfd or the expiry woke it.
const REACTION: Duration = Duration::from_secs(2);

/// How long a watcher that must keep running is given to prove it did.
const LONG_ENOUGH_TO_HAVE_LEFT: Duration = Duration::from_millis(400);

/// A pace at which the watcher looks at the directory many times within a test, so that a wake
/// with the directory or record missing is certain to happen.
const QUICK: WatchPace = WatchPace {
    recheck: Duration::from_millis(50),
    unrecorded_grace: Duration::from_secs(30),
};

struct Watched {
    _scratch: TempDir,
    root: ShareRoot,
    session: Session,
    name: SessionName,
}

fn claude_binding(sleeper: &Sleeper) -> Binding {
    Binding::resolve(ClaudeEnv::Present {
        session: ClaudeSessionId::parse("0b1c2d3e-4f50-6172-8394-a5b6c7d8e9f0").unwrap(),
        pid: sleeper.pid(),
    })
    .unwrap()
}

/// Opens the session of `sleeper` under `root` and shares one entry into it.
fn open_session(root: &ShareRoot, sleeper: &Sleeper, ttl: &str) -> Session {
    let session = Session::open(
        root,
        &claude_binding(sleeper),
        Ttl::parse(ttl).unwrap(),
        Timestamp::now(),
    )
    .unwrap();
    let body = entry(1, &string("Title", "Thing"));
    write_entry(session.dir(), &resolve_any("", &body, 1), &validity()).unwrap();
    session
}

fn session_for(sleeper: &Sleeper, ttl: &str) -> Watched {
    let scratch = scratch_on_tmpfs();
    let root = ShareRoot::at(&scratch.path().join("kpx-share")).unwrap();
    let session = open_session(&root, sleeper, ttl);
    Watched {
        _scratch: scratch,
        name: claude_binding(sleeper).name(),
        root,
        session,
    }
}

type Outcome = Result<WatchOutcome, String>;

fn spawn_watcher(watched: &Watched) -> mpsc::Receiver<Outcome> {
    spawn_with(watched, watch)
}

fn spawn_watcher_paced(watched: &Watched, pace: WatchPace) -> mpsc::Receiver<Outcome> {
    spawn_with(watched, move |root, name| watch_paced(root, name, pace))
}

fn spawn_with(
    watched: &Watched,
    run: impl FnOnce(&ShareRoot, &SessionName) -> Result<WatchOutcome, WatchError> + Send + 'static,
) -> mpsc::Receiver<Outcome> {
    let (send, receive) = mpsc::channel();
    let (root, name) = (watched.root.clone(), watched.name.clone());
    thread::spawn(move || {
        let outcome = run(&root, &name).map_err(|error| error.to_string());
        let _receiver_may_be_gone = send.send(outcome);
    });
    receive
}

/// Fails when the watcher has returned, whatever it returned.
fn assert_still_running(outcome: &mpsc::Receiver<Outcome>, why: &str) {
    match outcome.recv_timeout(LONG_ENOUGH_TO_HAVE_LEFT) {
        Err(mpsc::RecvTimeoutError::Timeout) => {}
        other => panic!("the watcher left: {why}: {other:?}"),
    }
}

fn gone(watched: &Watched) -> bool {
    SessionDir::find(&watched.root, &watched.name)
        .unwrap()
        .is_none()
}

/// Red when the watcher does not notice the process exit: with the pidfd wait removed it sleeps
/// until the 30 s re-check and this times out; with the exit check removed it never deletes.
#[test]
fn killing_the_watched_process_deletes_the_session_directory() {
    let mut sleeper = Sleeper::spawn();
    let watched = session_for(&sleeper, "8h");
    let outcome = spawn_watcher(&watched);
    thread::sleep(Duration::from_millis(200));
    assert!(!gone(&watched), "deleted while the process was alive");

    sleeper.kill();

    assert_eq!(
        outcome.recv_timeout(REACTION).unwrap(),
        Ok(WatchOutcome::Removed(SessionEnd::ProcessGone))
    );
    assert!(gone(&watched));
}

/// A process that has exited but is not yet reaped still has its pid and start time.
#[test]
fn an_exited_but_unreaped_process_counts_as_gone() {
    let mut sleeper = Sleeper::spawn();
    let watched = session_for(&sleeper, "8h");
    let outcome = spawn_watcher(&watched);
    thread::sleep(Duration::from_millis(200));

    sleeper.kill_leaving_zombie();

    assert_eq!(
        outcome.recv_timeout(REACTION).unwrap(),
        Ok(WatchOutcome::Removed(SessionEnd::ProcessGone))
    );
    assert!(gone(&watched));
}

/// Red when the TTL is not enforced (the process stays alive throughout), or is enforced early.
#[test]
fn the_ttl_deletes_the_session_directory_while_the_process_lives() {
    let sleeper = Sleeper::spawn();
    let started = Instant::now();
    let watched = session_for(&sleeper, "1s");
    let outcome = spawn_watcher(&watched);

    let result = outcome
        .recv_timeout(Duration::from_secs(1) + REACTION)
        .unwrap();

    assert_eq!(result, Ok(WatchOutcome::Removed(SessionEnd::Expired)));
    assert!(started.elapsed() >= Duration::from_secs(1), "deleted early");
    assert!(gone(&watched));
}

/// A recycled pid: the record names the pid of a live process but another start time. Red when
/// only the pid is compared (the watcher would keep the secrets for as long as the stranger lives).
#[test]
fn a_recycled_pid_counts_as_gone() {
    let sleeper = Sleeper::spawn();
    let watched = session_for(&sleeper, "8h");
    let real = sleeper.identity();
    let recycled =
        ProcessIdentity::new(real.pid(), StartTime::from_ticks(real.start().ticks() + 1));
    let record = SessionRecord::new(recycled, watched.session.record().expires_at());
    kpx_share::session::write_record(watched.session.dir(), &record).unwrap();

    let outcome = spawn_watcher(&watched);

    assert_eq!(
        outcome.recv_timeout(REACTION).unwrap(),
        Ok(WatchOutcome::Removed(SessionEnd::ProcessGone))
    );
    assert!(gone(&watched));
}

// --- A vanished directory or record while the session is live (D1) ---------------------------
//
// These run at the QUICK pace, so the watcher wakes many times while the directory or record is
// missing. The watcher keeps waiting on what it last read for as long as that session is live,
// so the mutation for each is a watcher that returns when it finds the directory or the record
// missing.

/// `rm --all` followed by a new add: the directory goes, then comes back with a record for a
/// different process, while the watcher runs. The watcher stays through the gap, follows the new
/// record and deletes the new directory when the new process exits. Red when the watcher returns
/// on finding the directory missing: `add` would have been told a watcher was running.
#[test]
fn a_directory_removed_and_recreated_while_watching_is_followed() {
    let (mut first, mut second) = (Sleeper::spawn(), Sleeper::spawn());
    let watched = session_for(&first, "8h");
    let outcome = spawn_watcher_paced(&watched, QUICK);
    thread::sleep(Duration::from_millis(200));
    std::fs::remove_dir_all(watched.session.dir().path()).unwrap();
    assert_still_running(
        &outcome,
        "the directory was missing and its session was live",
    );

    let reopened = open_session(&watched.root, &second, "8h");
    first.kill();

    assert_still_running(
        &outcome,
        "the first process exited but the new session was live",
    );
    assert!(!gone(&watched), "the new session's directory was deleted");
    assert_eq!(reopened.dir().path(), watched.session.dir().path());
    second.kill();
    assert_eq!(
        outcome.recv_timeout(REACTION).unwrap(),
        Ok(WatchOutcome::Removed(SessionEnd::ProcessGone))
    );
    assert!(gone(&watched));
}

/// The record is deleted while the directory and the process live: the watcher keeps what it
/// knew and still deletes the directory when the process exits. Red when the watcher returns on
/// finding the record missing.
#[test]
fn a_record_deleted_while_watching_does_not_end_the_watch() {
    let mut sleeper = Sleeper::spawn();
    let watched = session_for(&sleeper, "8h");
    let outcome = spawn_watcher_paced(&watched, QUICK);
    thread::sleep(Duration::from_millis(200));
    std::fs::remove_file(watched.session.dir().path().join(".session.json")).unwrap();
    assert_still_running(&outcome, "the record was missing and its session was live");
    assert!(!gone(&watched));

    sleeper.kill();

    assert_eq!(
        outcome.recv_timeout(REACTION).unwrap(),
        Ok(WatchOutcome::Removed(SessionEnd::ProcessGone))
    );
    assert!(gone(&watched));
}

/// The remembered session ends while its directory is gone: nothing to delete, and the watcher
/// says so instead of waiting for a record that will not come. Red when the watcher waits on, or
/// reports a removal that did not happen.
#[test]
fn a_session_that_ends_after_its_directory_went_is_reported_as_such() {
    let mut sleeper = Sleeper::spawn();
    let watched = session_for(&sleeper, "8h");
    let outcome = spawn_watcher_paced(&watched, QUICK);
    thread::sleep(Duration::from_millis(200));
    std::fs::remove_dir_all(watched.session.dir().path()).unwrap();

    sleeper.kill();

    assert_eq!(
        outcome.recv_timeout(REACTION).unwrap(),
        Ok(WatchOutcome::EndedWithoutDirectory(SessionEnd::ProcessGone))
    );
}

/// No record yet: the watcher waits, follows the session once it is created, and deletes it when
/// its process exits. Red when the watcher returns on finding no directory at its start.
#[test]
fn a_session_created_after_the_watcher_started_is_followed() {
    let (first, mut second) = (Sleeper::spawn(), Sleeper::spawn());
    let watched = session_for(&first, "8h");
    std::fs::remove_dir_all(watched.session.dir().path()).unwrap();
    let outcome = spawn_watcher_paced(&watched, QUICK);
    assert_still_running(&outcome, "no session had been created yet");

    open_session(&watched.root, &second, "8h");
    assert_still_running(&outcome, "the session was live");
    second.kill();

    assert_eq!(
        outcome.recv_timeout(REACTION).unwrap(),
        Ok(WatchOutcome::Removed(SessionEnd::ProcessGone))
    );
    assert!(gone(&watched));
}

/// A directory that never gets a record is not the watcher's to delete: after the grace it gives
/// up and leaves it to `gc`. Red when the grace is not applied (it never returns) or when it
/// deletes the directory.
#[test]
fn a_watcher_that_never_finds_a_record_gives_up_and_leaves_the_directory() {
    let sleeper = Sleeper::spawn();
    let watched = session_for(&sleeper, "8h");
    std::fs::remove_file(watched.session.dir().path().join(".session.json")).unwrap();
    let pace = WatchPace {
        unrecorded_grace: Duration::from_millis(300),
        ..QUICK
    };

    let outcome = spawn_watcher_paced(&watched, pace);

    assert_eq!(
        outcome.recv_timeout(REACTION).unwrap(),
        Ok(WatchOutcome::NeverRecorded)
    );
    assert!(!gone(&watched));
}

/// A later add with a shorter TTL rewrites the record; the watcher reads it again when it wakes
/// and deletes the session at the new expiry, with its process still alive. Red when the watcher
/// keeps the expiry it first read.
#[test]
fn a_shortened_expiry_is_followed() {
    let sleeper = Sleeper::spawn();
    let watched = session_for(&sleeper, "8h");
    let outcome = spawn_watcher_paced(&watched, QUICK);
    thread::sleep(Duration::from_millis(200));
    assert_still_running(&outcome, "the session had hours left");

    open_session(&watched.root, &sleeper, "1s");

    assert_eq!(
        outcome
            .recv_timeout(Duration::from_secs(1) + REACTION)
            .unwrap(),
        Ok(WatchOutcome::Removed(SessionEnd::Expired))
    );
    assert!(gone(&watched));
}
