//! `ls`, `rm` and `gc` against session directories on tmpfs.
//!
//! Method: sessions are made with `Session::open` around real `sleep` children (a session per
//! child: `ParentShell` bindings are named by pid and start time), and `gc` is given explicit
//! clock readings so expiry and idleness need no sleeping. Each test's doc comment names the
//! mutation that turns it red.

mod common;

use std::fs;

use common::process::Sleeper;
use common::share::{resolve_any, root_in, scratch_on_tmpfs, validity};
use common::{entry, string};
use jiff::Timestamp;
use kpx_share::layout::{RemoveEntryError, SafeName, SessionDir, SessionName, ShareRoot};
use kpx_share::manage::{
    GcEntry, GcOutcome, GcSummary, RemoveError, Removed, RemovedBecause, gc, list, remove_entry,
    remove_session,
};
use kpx_share::process::{ProcessIdentity, StartTime};
use kpx_share::session::{Binding, Session, SessionEnd, SessionRecord, Ttl, write_record};
use kpx_share::writer::write_entry;

fn open(root: &ShareRoot, sleeper: &Sleeper, ttl: &str, now: Timestamp) -> Session {
    let binding = Binding::ParentShell {
        watched: sleeper.identity(),
    };
    Session::open(root, &binding, Ttl::parse(ttl).unwrap(), now).unwrap()
}

fn share(session: &Session, uuid_byte: u8, title: &str) {
    let body = entry(uuid_byte, &string("Title", title));
    write_entry(
        session.dir(),
        &resolve_any("", &body, uuid_byte),
        &validity(),
    )
    .unwrap();
}

fn outcome_of<'a>(report: &'a [GcEntry], session: &Session) -> &'a GcOutcome {
    &report
        .iter()
        .find(|entry| entry.path == session.dir().path())
        .unwrap()
        .outcome
}

fn exists(session: &Session) -> bool {
    session.dir().path().exists()
}

/// Red when failures are counted as kept, or kept ones as removed or failed.
#[test]
fn the_gc_summary_counts_removed_failed_and_everything_else_as_kept() {
    let entry = |outcome| GcEntry {
        path: "/x".into(),
        outcome,
    };
    let report = [
        entry(GcOutcome::Removed(RemovedBecause::Ended(
            SessionEnd::Expired,
        ))),
        entry(GcOutcome::Failed("no".into())),
        entry(GcOutcome::Live),
        entry(GcOutcome::Foreign),
        entry(GcOutcome::AlreadyGone),
    ];

    let summary = GcSummary::of(&report);

    assert_eq!(
        summary,
        GcSummary {
            removed: 1,
            kept: 3,
            failed: 1
        }
    );
}

/// Red when `gc` removes live sessions, keeps ones whose process is gone, or keeps expired ones.
#[test]
fn gc_removes_sessions_whose_process_is_gone_or_whose_expiry_passed_and_keeps_live_ones() {
    let scratch = scratch_on_tmpfs();
    let root = root_in(&scratch);
    let now = Timestamp::now();
    let live = Sleeper::spawn();
    let mut dead = Sleeper::spawn();
    let expiring = Sleeper::spawn();
    let live_session = open(&root, &live, "8h", now);
    let dead_session = open(&root, &dead, "8h", now);
    let expired_session = open(&root, &expiring, "1h", now);
    for session in [&live_session, &dead_session, &expired_session] {
        share(session, 1, "Thing");
    }
    dead.kill();

    let report = gc(&root, now + std::time::Duration::from_secs(2 * 3600)).unwrap();

    assert!(matches!(
        outcome_of(&report, &live_session),
        GcOutcome::Live
    ));
    assert!(matches!(
        outcome_of(&report, &dead_session),
        GcOutcome::Removed(RemovedBecause::Ended(SessionEnd::ProcessGone))
    ));
    assert!(matches!(
        outcome_of(&report, &expired_session),
        GcOutcome::Removed(RemovedBecause::Ended(SessionEnd::Expired))
    ));
    assert!(exists(&live_session));
    assert!(!exists(&dead_session));
    assert!(!exists(&expired_session));
    // Red when removed and kept are counted the wrong way round.
    assert_eq!(
        GcSummary::of(&report),
        GcSummary {
            removed: 2,
            kept: 1,
            failed: 0
        }
    );
    assert_eq!(
        GcSummary::of(&report).to_string(),
        "2 removed, 1 kept, 0 failed"
    );
}

/// Red when only the pid is compared.
#[test]
fn gc_treats_a_recycled_pid_as_gone() {
    let scratch = scratch_on_tmpfs();
    let root = root_in(&scratch);
    let now = Timestamp::now();
    let sleeper = Sleeper::spawn();
    let session = open(&root, &sleeper, "8h", now);
    let real = sleeper.identity();
    let recycled =
        ProcessIdentity::new(real.pid(), StartTime::from_ticks(real.start().ticks() + 1));
    write_record(
        session.dir(),
        &SessionRecord::new(recycled, session.record().expires_at()),
    )
    .unwrap();

    let report = gc(&root, now).unwrap();

    assert!(matches!(
        outcome_of(&report, &session),
        GcOutcome::Removed(RemovedBecause::Ended(SessionEnd::ProcessGone))
    ));
    assert!(!exists(&session));
}

/// A directory with no usable record is removed only once it has been idle longer than the
/// default TTL. Red when it is removed at once (a session being created would lose its
/// directory), or never.
#[test]
fn gc_removes_a_directory_without_a_usable_record_only_when_it_is_old() {
    let scratch = scratch_on_tmpfs();
    let root = root_in(&scratch);
    let now = Timestamp::now();
    let (bare, broken) = (Sleeper::spawn(), Sleeper::spawn());
    let bare = open(&root, &bare, "8h", now);
    let broken = open(&root, &broken, "8h", now);
    fs::remove_file(bare.dir().path().join(".session.json")).unwrap();
    fs::write(broken.dir().path().join(".session.json"), "not json").unwrap();

    let young = gc(&root, now).unwrap();
    assert!(matches!(
        outcome_of(&young, &bare),
        GcOutcome::KeptRecent { .. }
    ));
    assert!(matches!(
        outcome_of(&young, &broken),
        GcOutcome::KeptRecent { .. }
    ));
    assert!(exists(&bare) && exists(&broken));

    let old = gc(&root, now + std::time::Duration::from_secs(9 * 3600)).unwrap();
    assert!(matches!(
        outcome_of(&old, &bare),
        GcOutcome::Removed(RemovedBecause::Unrecorded { .. })
    ));
    assert!(matches!(
        outcome_of(&old, &broken),
        GcOutcome::Removed(RemovedBecause::Unrecorded { .. })
    ));
    assert!(!exists(&bare) && !exists(&broken));
}

/// Anything below the root that is not a session directory is reported and never touched.
#[test]
fn gc_leaves_what_is_not_a_session_directory_alone() {
    let scratch = scratch_on_tmpfs();
    let root = root_in(&scratch);
    fs::write(root.path().join("notes.txt"), "mine").unwrap();
    fs::create_dir(root.path().join("not a session")).unwrap();
    fs::write(root.path().join("a-file-named-like-a-session"), "mine").unwrap();

    let report = gc(
        &root,
        Timestamp::now() + std::time::Duration::from_secs(99 * 3600),
    )
    .unwrap();

    assert_eq!(report.len(), 3);
    assert!(
        report
            .iter()
            .all(|entry| matches!(entry.outcome, GcOutcome::Foreign))
    );
    assert!(root.path().join("notes.txt").exists());
    assert!(root.path().join("not a session").exists());
    assert!(root.path().join("a-file-named-like-a-session").exists());
}

/// Red when `ls` shows a value, drops an entry, or lets a title break the one-line format.
#[test]
fn ls_shows_slug_path_and_expiry_one_line_per_entry() {
    let scratch = scratch_on_tmpfs();
    let root = root_in(&scratch);
    let sleeper = Sleeper::spawn();
    let session = open(&root, &sleeper, "8h", Timestamp::now());
    let expiry = session.record().expires_at();
    let body = [
        entry(
            1,
            &[string("Title", "GitHub"), string("Password", "SECRET-1")].concat(),
        ),
        entry(2, &string("Title", "two&#10;lines")),
    ]
    .concat();
    for byte in [1, 2] {
        write_entry(session.dir(), &resolve_any("", &body, byte), &validity()).unwrap();
    }

    let lines: Vec<String> = list(session.dir())
        .unwrap()
        .iter()
        .map(ToString::to_string)
        .collect();

    assert_eq!(
        lines,
        [
            format!("GitHub\tGitHub\t{expiry}"),
            format!("two_lines\ttwo lines\t{expiry}"),
        ]
    );
    assert!(!lines.concat().contains("SECRET-1"));
}

/// The expiry `ls` shows is the session record's, whatever the entry's `meta.json` was written
/// with (`validity()` is a fixed instant that is not the session's): red when `ls` shows the
/// entry's. A directory with no record has no expiry to show: red when a made-up one is shown.
#[test]
fn ls_shows_the_session_expiry_not_the_one_written_into_the_entry() {
    let scratch = scratch_on_tmpfs();
    let root = root_in(&scratch);
    let sleeper = Sleeper::spawn();
    let session = open(&root, &sleeper, "8h", Timestamp::now());
    share(&session, 1, "Thing");
    let shown = |session: &Session| {
        list(session.dir())
            .unwrap()
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
    };

    assert_eq!(
        shown(&session),
        [format!("Thing\tThing\t{}", session.record().expires_at())]
    );
    assert_ne!(validity().expires_at(), session.record().expires_at());

    fs::remove_file(session.dir().path().join(".session.json")).unwrap();
    assert_eq!(shown(&session), ["Thing\tThing\t-"]);
}

/// An entry whose `meta.json` cannot be read is still listed, so it can be seen and removed.
#[test]
fn ls_lists_an_entry_with_unreadable_metadata_as_such() {
    let scratch = scratch_on_tmpfs();
    let root = root_in(&scratch);
    let sleeper = Sleeper::spawn();
    let session = open(&root, &sleeper, "8h", Timestamp::now());
    share(&session, 1, "Thing");
    fs::write(session.dir().path().join("Thing/meta.json"), "{").unwrap();

    let lines: Vec<String> = list(session.dir())
        .unwrap()
        .iter()
        .map(ToString::to_string)
        .collect();

    assert_eq!(lines.len(), 1);
    assert!(lines[0].starts_with("Thing\t(unreadable: "), "{lines:?}");
}

/// Red when `rm <slug>` removes more than the one entry, or `rm --all` leaves the directory.
#[test]
fn rm_removes_one_entry_or_the_whole_session() {
    let scratch = scratch_on_tmpfs();
    let root = root_in(&scratch);
    let sleeper = Sleeper::spawn();
    let session = open(&root, &sleeper, "8h", Timestamp::now());
    share(&session, 1, "One");
    share(&session, 2, "Two");
    let name = session.dir().name().clone();

    let removed = remove_entry(&root, &name, &SafeName::parse("One").unwrap()).unwrap();
    assert_eq!(removed, Removed::Entry);
    assert!(!session.dir().path().join("One").exists());
    assert!(session.dir().path().join("Two").exists());
    assert!(session.dir().path().join(".session.json").exists());

    assert_eq!(remove_session(&root, &name).unwrap(), Removed::Session);
    assert!(!exists(&session));
    assert_eq!(
        remove_session(&root, &name).unwrap(),
        Removed::NothingShared
    );
}

#[test]
fn rm_of_an_unknown_entry_or_session_is_an_error_and_removes_nothing() {
    let scratch = scratch_on_tmpfs();
    let root = root_in(&scratch);
    let sleeper = Sleeper::spawn();
    let session = open(&root, &sleeper, "8h", Timestamp::now());
    share(&session, 1, "One");
    let missing = SafeName::parse("Nope").unwrap();

    let error = remove_entry(&root, session.dir().name(), &missing).unwrap_err();
    assert!(
        matches!(error, RemoveError::Entry(RemoveEntryError::NotFound(_))),
        "{error:?}"
    );
    let other = SessionName::parse("no-such-session").unwrap();
    assert!(remove_entry(&root, &other, &missing).is_err());
    assert!(SessionDir::find(&root, &other).unwrap().is_none());
    assert!(session.dir().path().join("One").exists());
}
