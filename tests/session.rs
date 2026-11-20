//! `Session::open`: the session directory and its record, on tmpfs.
//!
//! Method: open sessions under a scratch share root with explicit clock readings (`now` is a
//! parameter, so nothing sleeps) and watched processes that are real (`sleep` children), and read
//! the record and the directory back. Each test's doc comment names the mutation that turns it
//! red.

mod common;

use std::fs;
use std::time::Duration;

use common::process::{Sleeper, this_process};
use common::share::{resolve_any, root_in, scratch_on_tmpfs, validity};
use common::{entry, string};
use jiff::Timestamp;
use kpx_share::layout::{SessionDir, SessionName};
use kpx_share::session::{
    Binding, ClaudeEnv, ClaudeSessionId, RecordError, Session, SessionError, SessionRecord, Ttl,
    read_record, write_record,
};
use kpx_share::writer::write_entry;

const CLAUDE_ID: &str = "0b1c2d3e-4f50-6172-8394-a5b6c7d8e9f0";

fn t(text: &str) -> Timestamp {
    text.parse().unwrap()
}

fn shell_binding() -> Binding {
    Binding::ParentShell {
        watched: this_process(),
    }
}

fn claude_binding(sleeper: &Sleeper) -> Binding {
    Binding::resolve(ClaudeEnv::Present {
        session: ClaudeSessionId::parse(CLAUDE_ID).unwrap(),
        pid: sleeper.pid(),
    })
    .unwrap()
}

fn ttl(text: &str) -> Ttl {
    Ttl::parse(text).unwrap()
}

fn share_one_entry(session: &Session) {
    let body = entry(1, &string("Title", "Thing"));
    let resolved = resolve_any("", &body, 1);
    write_entry(session.dir(), &resolved, &validity()).unwrap();
}

fn entry_names(session: &Session) -> Vec<String> {
    session
        .dir()
        .entries()
        .unwrap()
        .iter()
        .map(|listed| listed.dir.slug().to_string())
        .collect()
}

/// Red when the expiry is not `now + ttl`, or the record is not written on creation.
#[test]
fn a_new_session_records_its_process_and_an_expiry_of_now_plus_ttl() {
    let scratch = scratch_on_tmpfs();
    let root = root_in(&scratch);
    let binding = shell_binding();

    let session = Session::open(&root, &binding, ttl("30m"), t("2026-01-01T00:00:00Z")).unwrap();

    let expected = SessionRecord::new(binding.watched(), t("2026-01-01T00:30:00Z"));
    assert_eq!(session.record(), &expected);
    assert_eq!(read_record(session.dir()).unwrap(), Some(expected));
    assert_eq!(session.dir().name(), &binding.name());
}

/// Red when a later add moves the expiry (it would let a session outlive its TTL by adding again).
#[test]
fn a_later_add_shares_the_first_adds_expiry_and_keeps_its_entries() {
    let scratch = scratch_on_tmpfs();
    let root = root_in(&scratch);
    let binding = shell_binding();
    let first = Session::open(&root, &binding, ttl("30m"), t("2026-01-01T00:00:00Z")).unwrap();
    share_one_entry(&first);

    let second = Session::open(&root, &binding, ttl("8h"), t("2026-01-01T00:10:00Z")).unwrap();

    assert_eq!(second.record().expires_at(), t("2026-01-01T00:30:00Z"));
    assert_eq!(entry_names(&second), ["Thing"]);
}

/// A later add with a shorter TTL brings the expiry forward, in the record on disk (which is
/// what the watcher reads), and a still later add with a long one does not move it back. Red when
/// the existing record is kept as it is, or the shortened one is not written.
#[test]
fn a_later_add_with_a_shorter_ttl_shrinks_the_expiry_and_never_grows_it_back() {
    let scratch = scratch_on_tmpfs();
    let root = root_in(&scratch);
    let binding = shell_binding();
    Session::open(&root, &binding, ttl("8h"), t("2026-01-01T00:00:00Z")).unwrap();

    let shorter = Session::open(&root, &binding, ttl("30m"), t("2026-01-01T00:10:00Z")).unwrap();
    assert_eq!(shorter.record().expires_at(), t("2026-01-01T00:40:00Z"));
    assert_eq!(shorter.validity().expires_at(), t("2026-01-01T00:40:00Z"));
    let on_disk = read_record(shorter.dir()).unwrap().unwrap();
    assert_eq!(
        on_disk,
        SessionRecord::new(binding.watched(), t("2026-01-01T00:40:00Z"))
    );

    let longer = Session::open(&root, &binding, ttl("8h"), t("2026-01-01T00:20:00Z")).unwrap();
    assert_eq!(longer.record().expires_at(), t("2026-01-01T00:40:00Z"));
    assert_eq!(read_record(longer.dir()).unwrap(), Some(on_disk));
}

/// Red when an expired session is reused instead of replaced.
#[test]
fn once_expired_the_next_add_starts_a_fresh_session_without_the_old_entries() {
    let scratch = scratch_on_tmpfs();
    let root = root_in(&scratch);
    let binding = shell_binding();
    let first = Session::open(&root, &binding, ttl("30m"), t("2026-01-01T00:00:00Z")).unwrap();
    share_one_entry(&first);

    let second = Session::open(&root, &binding, ttl("1h"), t("2026-01-01T00:30:00Z")).unwrap();

    assert_eq!(second.record().expires_at(), t("2026-01-01T01:30:00Z"));
    assert_eq!(entry_names(&second), Vec::<String>::new());
}

/// The same Claude session id under a new `claude` process (a resume) is a new session: red when
/// the record's process is not compared.
#[test]
fn the_same_claude_session_under_another_process_starts_afresh() {
    let scratch = scratch_on_tmpfs();
    let root = root_in(&scratch);
    let (old, new) = (Sleeper::spawn(), Sleeper::spawn());
    let first = Session::open(
        &root,
        &claude_binding(&old),
        ttl("8h"),
        t("2026-01-01T00:00:00Z"),
    )
    .unwrap();
    share_one_entry(&first);

    let second = Session::open(
        &root,
        &claude_binding(&new),
        ttl("8h"),
        t("2026-01-01T00:01:00Z"),
    )
    .unwrap();

    assert_eq!(second.dir().name().as_str(), format!("claude-{CLAUDE_ID}"));
    assert_eq!(second.record().watched(), new.identity());
    assert_eq!(entry_names(&second), Vec::<String>::new());
}

/// An add that died between creating the directory and writing the record leaves a bare
/// directory: the next add completes it. Red when a missing record is an error.
#[test]
fn a_directory_without_a_record_gets_one() {
    let scratch = scratch_on_tmpfs();
    let root = root_in(&scratch);
    let binding = shell_binding();
    SessionDir::open(&root, &binding.name()).unwrap();

    let session = Session::open(&root, &binding, ttl("1h"), t("2026-01-01T00:00:00Z")).unwrap();

    assert_eq!(session.record().expires_at(), t("2026-01-01T01:00:00Z"));
}

/// A record that cannot be read is not silently replaced: it may belong to something else.
/// Red when the invalid record is overwritten.
#[test]
fn an_unreadable_record_is_an_error_and_is_left_alone() {
    let scratch = scratch_on_tmpfs();
    let root = root_in(&scratch);
    let binding = shell_binding();
    let dir = SessionDir::open(&root, &binding.name()).unwrap();
    let record_path = dir.path().join(".session.json");
    fs::write(&record_path, "{\"version\": 9}").unwrap();

    let error = Session::open(&root, &binding, ttl("1h"), t("2026-01-01T00:00:00Z")).unwrap_err();

    assert!(
        matches!(error, SessionError::Record(RecordError::Invalid { .. })),
        "{error:?}"
    );
    assert_eq!(
        fs::read_to_string(&record_path).unwrap(),
        "{\"version\": 9}"
    );
}

/// Red when the record is written in place (a reader could see half of it) or leaves its
/// temporary file behind.
#[test]
fn writing_a_record_replaces_it_whole_and_leaves_nothing_behind() {
    let scratch = scratch_on_tmpfs();
    let root = root_in(&scratch);
    let dir = SessionDir::open(&root, &SessionName::parse("s1").unwrap()).unwrap();
    let first = SessionRecord::new(this_process(), t("2026-01-01T00:00:00Z"));
    let second = SessionRecord::new(this_process(), t("2030-01-01T00:00:00Z"));

    write_record(&dir, &first).unwrap();
    write_record(&dir, &second).unwrap();

    assert_eq!(read_record(&dir).unwrap(), Some(second));
    let names: Vec<_> = fs::read_dir(dir.path())
        .unwrap()
        .map(|item| item.unwrap().file_name())
        .collect();
    assert_eq!(names, [".session.json"]);
    let mode = common::share::mode(&dir.path().join(".session.json"));
    assert_eq!(mode, 0o600);
}

/// `remaining` is how the watcher and `add` judge expiry; a record in the past has none.
#[test]
fn a_record_has_no_time_remaining_at_its_expiry() {
    let record = SessionRecord::new(this_process(), t("2026-01-01T00:00:10Z"));
    assert_eq!(
        record.remaining(t("2026-01-01T00:00:00Z")),
        Some(Duration::from_secs(10))
    );
    assert_eq!(record.remaining(t("2026-01-01T00:00:10Z")), None);
}
