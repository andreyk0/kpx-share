//! What a session is: a name, the process it lives and dies with, and when it ends regardless.
//!
//! - [`Binding`] says where the session comes from: a Claude Code session (its environment names
//!   the session and the `claude` process), or, without one, the parent shell.
//! - [`Ttl`] and the record's `expires_at` bound the session in time.
//! - [`SessionRecord`] is the non-secret `.session.json` in the session directory, which the
//!   watcher and `gc` read to decide when the directory has to go.
//! - [`Session`] is a session directory with its record: what `add` writes into.
//!
//! The session ends when the watched process is gone or `expires_at` has passed, whichever is
//! first. `expires_at` is set when the session directory is first created and a later add can
//! only bring it forward (a shorter `--ttl`), never push it back: a TTL is a bound on how long
//! secrets sit on tmpfs, and no add can loosen it.

use std::ffi::OsStr;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::time::Duration;

use jiff::{SignedDuration, Timestamp};
use rustix::process::Pid;
use serde::{Deserialize, Serialize};

use crate::layout::{
    BoundedReadError, DirError, SESSION_RECORD_FILE, SessionDir, SessionName, ShareRoot,
    random_partial_name, read_bounded, write_private_file,
};
use crate::meta::{Validity, ValidityError};
use crate::process::{Liveness, ProcessError, ProcessIdentity, StartTime, pid_from_raw};
use crate::schema::SchemaVersion;

// --- Claude Code's environment ----------------------------------------------------------------

const CLAUDE_SESSION_VAR: &str = "CLAUDE_CODE_SESSION_ID";
const CLAUDE_PID_VAR: &str = "CLAUDE_PID";

/// A Claude Code session id: a UUID in its hyphenated form, held in lower case so one session
/// has one name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaudeSessionId(String);

impl ClaudeSessionId {
    /// # Errors
    /// `text` is not `8-4-4-4-12` hexadecimal digits.
    pub fn parse(text: &str) -> Result<Self, BindingError> {
        const HYPHENS_AT: [usize; 4] = [8, 13, 18, 23];
        const UUID_BYTES: usize = 36;
        let well_formed = text.len() == UUID_BYTES
            && text.bytes().enumerate().all(|(index, byte)| {
                if HYPHENS_AT.contains(&index) {
                    byte == b'-'
                } else {
                    byte.is_ascii_hexdigit()
                }
            });
        if well_formed {
            Ok(Self(text.to_ascii_lowercase()))
        } else {
            Err(BindingError::BadSessionId)
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// What Claude Code's environment says: both variables, or neither.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClaudeEnv {
    Absent,
    Present { session: ClaudeSessionId, pid: Pid },
}

impl ClaudeEnv {
    /// Reads `CLAUDE_CODE_SESSION_ID` and `CLAUDE_PID` from the process environment.
    ///
    /// # Errors
    /// See [`ClaudeEnv::parse`].
    pub fn from_env() -> Result<Self, BindingError> {
        Self::parse(
            std::env::var_os(CLAUDE_SESSION_VAR).as_deref(),
            std::env::var_os(CLAUDE_PID_VAR).as_deref(),
        )
    }

    /// # Errors
    /// Exactly one of the two is set (which one is the session cannot be guessed), or a value is
    /// not a UUID or a pid.
    pub fn parse(session: Option<&OsStr>, pid: Option<&OsStr>) -> Result<Self, BindingError> {
        match (session, pid) {
            (None, None) => Ok(Self::Absent),
            (Some(_), None) => Err(BindingError::Half {
                set: CLAUDE_SESSION_VAR,
                missing: CLAUDE_PID_VAR,
            }),
            (None, Some(_)) => Err(BindingError::Half {
                set: CLAUDE_PID_VAR,
                missing: CLAUDE_SESSION_VAR,
            }),
            (Some(session), Some(pid)) => Ok(Self::Present {
                session: ClaudeSessionId::parse(
                    session.to_str().ok_or(BindingError::BadSessionId)?,
                )?,
                pid: parse_pid(pid.to_str().ok_or(BindingError::BadPid)?)?,
            }),
        }
    }
}

fn parse_pid(text: &str) -> Result<Pid, BindingError> {
    text.parse::<i32>()
        .ok()
        .and_then(pid_from_raw)
        .ok_or(BindingError::BadPid)
}

// --- Binding ----------------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum BindingError {
    #[error("{set} is set but {missing} is not; refusing to guess which session this is")]
    Half {
        set: &'static str,
        missing: &'static str,
    },
    #[error("{CLAUDE_SESSION_VAR} is not a UUID")]
    BadSessionId,
    #[error("{CLAUDE_PID_VAR} is not a process id")]
    BadPid,
    #[error("{CLAUDE_PID_VAR} names a process that cannot be inspected: {0}")]
    Claude(#[source] ProcessError),
    #[error("the parent shell has no process id this process can see")]
    NoParent,
    #[error("the parent shell cannot be inspected: {0}")]
    ParentShell(#[source] ProcessError),
}

/// Where a session comes from, and so what it is named by and what its end is tied to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Binding {
    /// Under Claude Code: named by its session, ends with the `claude` process.
    Claude {
        session: ClaudeSessionId,
        watched: ProcessIdentity,
    },
    /// Anywhere else: named by the parent shell (pid and start time, so a recycled pid is
    /// another session), ends with it.
    ParentShell { watched: ProcessIdentity },
}

impl Binding {
    /// The binding for the environment this process runs in.
    ///
    /// # Errors
    /// See [`ClaudeEnv::from_env`] and [`Binding::resolve`].
    pub fn from_env() -> Result<Self, BindingError> {
        Self::resolve(ClaudeEnv::from_env()?)
    }

    /// # Errors
    /// The process the session would be tied to is not running or cannot be inspected.
    pub fn resolve(env: ClaudeEnv) -> Result<Self, BindingError> {
        match env {
            ClaudeEnv::Present { session, pid } => Ok(Self::Claude {
                session,
                watched: ProcessIdentity::of_running(pid).map_err(BindingError::Claude)?,
            }),
            ClaudeEnv::Absent => {
                let parent = rustix::process::getppid().ok_or(BindingError::NoParent)?;
                Ok(Self::ParentShell {
                    watched: ProcessIdentity::of_running(parent)
                        .map_err(BindingError::ParentShell)?,
                })
            }
        }
    }

    #[must_use]
    pub fn watched(&self) -> ProcessIdentity {
        match self {
            Self::Claude { watched, .. } | Self::ParentShell { watched } => *watched,
        }
    }

    /// `claude-<uuid>`, or `shell-<pid>-<start ticks>`: at most 43 bytes, all `[a-z0-9-]`.
    #[must_use]
    pub fn name(&self) -> SessionName {
        let name = match self {
            Self::Claude { session, .. } => format!("claude-{}", session.as_str()),
            Self::ParentShell { watched } => format!(
                "shell-{}-{}",
                watched.pid().as_raw_nonzero(),
                watched.start().ticks()
            ),
        };
        SessionName::parse(&name)
            .unwrap_or_else(|error| unreachable!("{name:?} is built to be a session name: {error}"))
    }
}

// --- Ttl --------------------------------------------------------------------------------------

#[derive(Clone, Debug, thiserror::Error)]
pub enum TtlError {
    #[error("not a duration like 30m or 8h: {0}")]
    Unparsable(jiff::Error),
    #[error("a TTL must be between {} and {}", Ttl::MIN, Ttl::MAX)]
    OutOfRange,
}

/// How long a session lasts at most, from 1 second to 7 days.
///
/// The ceiling is there because a TTL is a bound on how long a secret may sit on tmpfs: a week
/// is already past any working session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ttl(SignedDuration);

impl Ttl {
    pub const MIN: Self = Self(SignedDuration::from_secs(1));
    pub const MAX: Self = Self(SignedDuration::from_hours(7 * 24));
    pub const DEFAULT: Self = Self(SignedDuration::from_hours(8));

    /// Parses jiff's friendly duration format: `30m`, `8h`, `1h 30m`, `90 seconds`.
    ///
    /// # Errors
    /// The text is not a duration, or it is outside [`Ttl::MIN`] to [`Ttl::MAX`].
    pub fn parse(text: &str) -> Result<Self, TtlError> {
        let duration: SignedDuration = text.parse().map_err(TtlError::Unparsable)?;
        if (Self::MIN.0..=Self::MAX.0).contains(&duration) {
            Ok(Self(duration))
        } else {
            Err(TtlError::OutOfRange)
        }
    }

    #[must_use]
    pub fn as_duration(self) -> Duration {
        // A `Ttl` is always positive, so the conversion cannot fail.
        Duration::try_from(self.0).unwrap_or(Duration::ZERO)
    }

    /// When a session started at `start` ends.
    #[must_use]
    pub fn expiry(self, start: Timestamp) -> Timestamp {
        // Cannot overflow: `start` is a real clock reading and the TTL is at most a week.
        start.saturating_add(self.0).unwrap_or(start)
    }
}

/// The friendly form [`Ttl::parse`] reads: `8h`, `1h 30m`, `168h`.
impl std::fmt::Display for Ttl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#}", self.0)
    }
}

impl std::str::FromStr for Ttl {
    type Err = TtlError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::parse(text)
    }
}

// --- The record -------------------------------------------------------------------------------

/// Why a session is over.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionEnd {
    Expired,
    ProcessGone,
}

impl std::fmt::Display for SessionEnd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Expired => "expired",
            Self::ProcessGone => "its process is gone",
        })
    }
}

/// What the watcher and `gc` need to know about a session: the process it is tied to and when it
/// expires. Not secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionRecord {
    watched: ProcessIdentity,
    expires_at: Timestamp,
}

impl SessionRecord {
    #[must_use]
    pub fn new(watched: ProcessIdentity, expires_at: Timestamp) -> Self {
        Self {
            watched,
            expires_at,
        }
    }

    #[must_use]
    pub fn watched(&self) -> ProcessIdentity {
        self.watched
    }

    #[must_use]
    pub fn expires_at(&self) -> Timestamp {
        self.expires_at
    }

    /// Why the session is over at `now`, or `None` while it is not. Expiry is judged first, so an
    /// expired session is never reported as anything that needs the process table.
    ///
    /// # Errors
    /// The watched process's status cannot be read.
    pub fn ended(&self, now: Timestamp) -> Result<Option<SessionEnd>, ProcessError> {
        if self.expires_at <= now {
            return Ok(Some(SessionEnd::Expired));
        }
        Ok(match self.watched.liveness()? {
            Liveness::Alive => None,
            Liveness::Gone => Some(SessionEnd::ProcessGone),
        })
    }

    /// Time left, `None` once there is none.
    #[must_use]
    pub fn remaining(&self, now: Timestamp) -> Option<Duration> {
        Duration::try_from(self.expires_at.duration_since(now))
            .ok()
            .filter(|left| !left.is_zero())
    }
}

/// The stored shape of `.session.json`; [`SessionRecord`] is what it is parsed into.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordFile {
    version: SchemaVersion<RECORD_VERSION>,
    watched: WatchedFile,
    expires_at: Timestamp,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WatchedFile {
    pid: i32,
    start_ticks: u64,
}

const RECORD_VERSION: u32 = 1;

/// A session record is a few dozen bytes.
const RECORD_BYTES_MAX: u64 = 4096;

/// How long a session directory may sit without a record before it counts as abandoned. `add`
/// writes the record right after it creates the directory, so a directory that still has none
/// after this long was left by an add that died between the two. The wait is orders of magnitude
/// longer than that moment on purpose: a clock step or a stalled add must never get a directory
/// deleted while it is being created, and the only cost of waiting is an empty directory.
pub const UNRECORDED_GRACE: Duration = Duration::from_secs(8 * 60 * 60);

impl From<&SessionRecord> for RecordFile {
    fn from(record: &SessionRecord) -> Self {
        Self {
            version: SchemaVersion,
            watched: WatchedFile {
                pid: record.watched.pid().as_raw_nonzero().get(),
                start_ticks: record.watched.start().ticks(),
            },
            expires_at: record.expires_at,
        }
    }
}

impl TryFrom<RecordFile> for SessionRecord {
    type Error = RecordProblem;

    fn try_from(file: RecordFile) -> Result<Self, RecordProblem> {
        let pid = pid_from_raw(file.watched.pid).ok_or(RecordProblem::BadPid)?;
        Ok(Self::new(
            ProcessIdentity::new(pid, StartTime::from_ticks(file.watched.start_ticks)),
            file.expires_at,
        ))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RecordProblem {
    #[error("the pid is not a process id")]
    BadPid,
    #[error("larger than {RECORD_BYTES_MAX} bytes")]
    TooLarge,
    #[error("{0}")]
    Json(serde_json::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum RecordError {
    #[error("{}: {source}", .path.display())]
    Io { path: PathBuf, source: io::Error },
    #[error("{} is not a valid session record: {problem}", .path.display())]
    Invalid {
        path: PathBuf,
        problem: RecordProblem,
    },
}

fn record_path(dir: &SessionDir) -> PathBuf {
    dir.path().join(SESSION_RECORD_FILE)
}

/// The record in `dir`; `None` when there is none yet. A symlink in its place is refused.
///
/// # Errors
/// The file is unreadable or is not a record of the current version.
pub fn read_record(dir: &SessionDir) -> Result<Option<SessionRecord>, RecordError> {
    let path = record_path(dir);
    let io_error = |source| RecordError::Io {
        path: path.clone(),
        source,
    };
    let invalid = |problem| RecordError::Invalid {
        path: path.clone(),
        problem,
    };
    let text = match read_bounded(&path, RECORD_BYTES_MAX) {
        Ok(text) => text,
        Err(BoundedReadError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(None);
        }
        Err(BoundedReadError::Io(error)) => return Err(io_error(error)),
        Err(BoundedReadError::TooLarge { .. }) => return Err(invalid(RecordProblem::TooLarge)),
    };
    serde_json::from_slice::<RecordFile>(&text)
        .map_err(|error| invalid(RecordProblem::Json(error)))
        .and_then(|file| SessionRecord::try_from(file).map_err(invalid))
        .map(Some)
}

/// Writes `record` into `dir` atomically: written whole under a `.partial-*` name, then renamed
/// over `.session.json`, so a reader sees the old record or the new one and never half of one.
///
/// # Errors
/// The file cannot be written.
pub fn write_record(dir: &SessionDir, record: &SessionRecord) -> Result<(), RecordError> {
    let target = record_path(dir);
    let io_error = |source| RecordError::Io {
        path: target.clone(),
        source,
    };
    let temporary = dir.path().join(random_partial_name().map_err(io_error)?);
    let mut json = serde_json::to_vec_pretty(&RecordFile::from(record))
        .map_err(|error| io_error(io::Error::other(error)))?;
    json.push(b'\n');
    let written =
        write_private_file(&temporary, &json).and_then(|()| fs::rename(&temporary, &target));
    if written.is_err() {
        // The write already failed; its error is the one to report.
        let _ = fs::remove_file(&temporary);
    }
    written.map_err(io_error)
}

// --- Session ----------------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error(transparent)]
    Dir(#[from] DirError),
    #[error(transparent)]
    Record(#[from] RecordError),
    #[error("cannot remove the ended session {}: {source}", .path.display())]
    RemoveEnded { path: PathBuf, source: io::Error },
    #[error("cannot tell whether the session has ended: {0}")]
    Process(#[from] ProcessError),
    /// The session would end before it started; [`Session::open`] makes sure it does not.
    #[error(transparent)]
    Validity(#[from] ValidityError),
}

/// A session directory together with its record: the witness that a watcher has a record to
/// follow, so what is written here ends when the session does.
#[derive(Debug)]
pub struct Session {
    dir: SessionDir,
    record: SessionRecord,
    validity: Validity,
}

impl Session {
    /// The directory for `binding` under `root`, with a record.
    ///
    /// The existing session is kept when its record names the same watched process and has not
    /// expired; its `expires_at` becomes `now` + `ttl` if that is earlier, and is never moved
    /// later (the record is rewritten whole, see [`write_record`]). Otherwise what is there
    /// belongs to a session that is over (or to an earlier process with the same Claude session
    /// id, after `--resume`): it is removed and a fresh session starts, with `expires_at` =
    /// `now` + `ttl`. A directory without a record (made by an add that died before writing it)
    /// gets one.
    ///
    /// # Errors
    /// See [`SessionError`]; a record that exists but cannot be parsed is not overwritten.
    pub fn open(
        root: &ShareRoot,
        binding: &Binding,
        ttl: Ttl,
        now: Timestamp,
    ) -> Result<Self, SessionError> {
        let name = binding.name();
        let mut dir = SessionDir::open(root, &name)?;
        let fresh = SessionRecord::new(binding.watched(), ttl.expiry(now));
        let record = match read_record(&dir)? {
            Some(existing)
                if existing.watched() == binding.watched() && existing.remaining(now).is_some() =>
            {
                if fresh.expires_at() < existing.expires_at() {
                    // A shorter TTL is a tighter bound the human asked for; the watcher reads
                    // the record again when it wakes and follows it.
                    write_record(&dir, &fresh)?;
                    fresh
                } else {
                    existing
                }
            }
            Some(_) => {
                let path = dir.path().to_owned();
                dir.remove()
                    .map_err(|source| SessionError::RemoveEnded { path, source })?;
                dir = SessionDir::open(root, &name)?;
                write_record(&dir, &fresh)?;
                fresh
            }
            None => {
                write_record(&dir, &fresh)?;
                fresh
            }
        };
        // Holds for both records: a kept one has time remaining, and a fresh one expires a TTL
        // (at least a second) after `now`.
        let validity = Validity::new(now, record.expires_at())?;
        Ok(Self {
            dir,
            record,
            validity,
        })
    }

    #[must_use]
    pub fn dir(&self) -> &SessionDir {
        &self.dir
    }

    #[must_use]
    pub fn record(&self) -> &SessionRecord {
        &self.record
    }

    /// What an entry written into this session now is valid for: from when the session was
    /// opened to when it ends.
    #[must_use]
    pub fn validity(&self) -> Validity {
        self.validity
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStrExt;

    const UUID: &str = "0B1C2D3E-4F50-6172-8394-A5B6C7D8E9F0";

    fn os(text: &str) -> &OsStr {
        OsStr::new(text)
    }

    #[test]
    fn both_variables_make_a_claude_binding_input_with_a_lower_case_session() {
        let me = rustix::process::getpid();
        let env =
            ClaudeEnv::parse(Some(os(UUID)), Some(os(&me.as_raw_nonzero().to_string()))).unwrap();
        let ClaudeEnv::Present { session, pid } = env else {
            panic!("{env:?}");
        };
        assert_eq!(session.as_str(), "0b1c2d3e-4f50-6172-8394-a5b6c7d8e9f0");
        assert_eq!(pid, me);
        let binding = Binding::resolve(ClaudeEnv::Present { session, pid }).unwrap();
        assert_eq!(
            binding.name().as_str(),
            "claude-0b1c2d3e-4f50-6172-8394-a5b6c7d8e9f0"
        );
    }

    #[test]
    fn neither_variable_is_absent_and_exactly_one_is_an_error() {
        assert_eq!(ClaudeEnv::parse(None, None).unwrap(), ClaudeEnv::Absent);
        assert!(matches!(
            ClaudeEnv::parse(Some(os(UUID)), None),
            Err(BindingError::Half {
                set: CLAUDE_SESSION_VAR,
                missing: CLAUDE_PID_VAR
            })
        ));
        assert!(matches!(
            ClaudeEnv::parse(None, Some(os("123"))),
            Err(BindingError::Half {
                set: CLAUDE_PID_VAR,
                missing: CLAUDE_SESSION_VAR
            })
        ));
    }

    #[test]
    fn malformed_values_are_errors() {
        for bad in [
            "",
            "not-a-uuid",
            "0b1c2d3e4f5061728394a5b6c7d8e9f0",
            &format!("{UUID}0"),
            "0b1c2d3e-4f50-6172-8394-a5b6c7d8e9fg",
            "../../../../../../../../../../etc",
        ] {
            assert!(
                matches!(ClaudeSessionId::parse(bad), Err(BindingError::BadSessionId)),
                "{bad}"
            );
        }
        for bad in ["", "0", "-5", "abc", "99999999999", " 12"] {
            assert!(
                matches!(
                    ClaudeEnv::parse(Some(os(UUID)), Some(os(bad))),
                    Err(BindingError::BadPid)
                ),
                "{bad}"
            );
        }
        let not_unicode = OsStr::from_bytes(b"\xff");
        assert!(matches!(
            ClaudeEnv::parse(Some(not_unicode), Some(os("1"))),
            Err(BindingError::BadSessionId)
        ));
    }

    #[test]
    fn the_parent_shell_is_named_by_pid_and_start_time() {
        let watched =
            ProcessIdentity::new(Pid::from_raw(4242).unwrap(), StartTime::from_ticks(777));
        let binding = Binding::ParentShell { watched };
        assert_eq!(binding.name().as_str(), "shell-4242-777");
        let recycled =
            ProcessIdentity::new(Pid::from_raw(4242).unwrap(), StartTime::from_ticks(778));
        assert_ne!(
            binding.name(),
            Binding::ParentShell { watched: recycled }.name()
        );
    }

    #[test]
    fn a_ttl_is_a_friendly_duration_within_bounds() {
        assert_eq!(Ttl::parse("8h").unwrap(), Ttl::DEFAULT);
        assert_eq!(Ttl::parse("1s").unwrap(), Ttl::MIN);
        assert_eq!(Ttl::parse("168h").unwrap(), Ttl::MAX);
        // What the CLI shows is what it reads back.
        for ttl in [Ttl::MIN, Ttl::DEFAULT, Ttl::MAX] {
            assert_eq!(Ttl::parse(&ttl.to_string()).unwrap(), ttl);
        }
        assert_eq!(
            [Ttl::MIN, Ttl::DEFAULT, Ttl::MAX].map(|ttl| ttl.to_string()),
            ["1s", "8h", "168h"]
        );
        assert_eq!(Ttl::parse("30m").unwrap().0, SignedDuration::from_mins(30));
        assert_eq!(
            Ttl::parse("1h 30m").unwrap().0,
            SignedDuration::from_mins(90)
        );
        assert_eq!(Ttl::parse("2s").unwrap().0, SignedDuration::from_secs(2));
        for out_of_range in ["0s", "500ms", "169h", "-1h"] {
            assert!(
                matches!(Ttl::parse(out_of_range), Err(TtlError::OutOfRange)),
                "{out_of_range}"
            );
        }
        for nonsense in ["", "soon", "8", "h8", "8d"] {
            assert!(
                matches!(Ttl::parse(nonsense), Err(TtlError::Unparsable(_))),
                "{nonsense}"
            );
        }
        let start: Timestamp = "2026-01-01T00:00:00Z".parse().unwrap();
        assert_eq!(
            Ttl::parse("90m").unwrap().expiry(start),
            "2026-01-01T01:30:00Z".parse::<Timestamp>().unwrap()
        );
    }

    #[test]
    fn the_record_file_is_pinned_and_round_trips() {
        // A contract: the watcher of an older build reads what a newer `add` wrote.
        let record = SessionRecord::new(
            ProcessIdentity::new(Pid::from_raw(4242).unwrap(), StartTime::from_ticks(777)),
            "2026-01-02T03:04:05Z".parse().unwrap(),
        );
        let stored = serde_json::to_value(RecordFile::from(&record)).unwrap();
        let expected: serde_json::Value = serde_json::from_str(
            r#"{"version": 1, "watched": {"pid": 4242, "start_ticks": 777},
                "expires_at": "2026-01-02T03:04:05Z"}"#,
        )
        .unwrap();
        assert_eq!(stored, expected);
        let back = SessionRecord::try_from(serde_json::from_value::<RecordFile>(stored).unwrap());
        assert_eq!(back.unwrap(), record);
    }

    #[test]
    fn a_record_of_another_version_or_with_a_bad_pid_is_refused() {
        let parse = |json: &str| {
            serde_json::from_str::<RecordFile>(json)
                .map_err(|_| ())
                .and_then(|file| SessionRecord::try_from(file).map_err(|_| ()))
        };
        let good = r#"{"version": 1, "watched": {"pid": 1, "start_ticks": 2}, "expires_at": "2026-01-02T03:04:05Z"}"#;
        assert!(parse(good).is_ok());
        assert!(parse(&good.replace("\"version\": 1", "\"version\": 2")).is_err());
        assert!(parse(&good.replace("\"pid\": 1", "\"pid\": 0")).is_err());
        assert!(parse(&good.replace("\"pid\": 1", "\"pid\": -3")).is_err());
        assert!(parse(&good.replace("\"pid\": 1,", "\"pid\": 1, \"extra\": 1,")).is_err());
    }

    #[test]
    fn expiry_is_judged_before_the_process_and_the_process_is_not_asked_when_expired() {
        let me = ProcessIdentity::of_running(rustix::process::getpid()).unwrap();
        let t0: Timestamp = "2026-01-01T00:00:00Z".parse().unwrap();
        let t1: Timestamp = "2026-01-01T00:00:10Z".parse().unwrap();
        let live = SessionRecord::new(me, t1);
        assert_eq!(live.ended(t0).unwrap(), None);
        assert_eq!(live.ended(t1).unwrap(), Some(SessionEnd::Expired));
        let recycled = SessionRecord::new(
            ProcessIdentity::new(me.pid(), StartTime::from_ticks(me.start().ticks() + 1)),
            t1,
        );
        assert_eq!(recycled.ended(t0).unwrap(), Some(SessionEnd::ProcessGone));
        assert_eq!(live.remaining(t0), Some(Duration::from_secs(10)));
        assert_eq!(live.remaining(t1), None);
    }
}
