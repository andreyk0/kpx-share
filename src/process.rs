//! Processes, identified by pid and start time.
//!
//! A pid alone can be recycled: the watched process exits, another gets its number, and a
//! watcher that only asked "is pid N alive?" keeps the secrets for as long as the stranger runs.
//! A [`ProcessIdentity`] adds the process's start time (field 22 of `/proc/<pid>/stat`, in clock
//! ticks since boot), which a recycled pid cannot share.

use std::fs;
use std::io;
use std::path::PathBuf;

use rustix::process::Pid;

/// Field 22 of `/proc/<pid>/stat`: when the process started, in clock ticks since boot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StartTime(u64);

impl StartTime {
    #[must_use]
    pub fn from_ticks(ticks: u64) -> Self {
        Self(ticks)
    }

    #[must_use]
    pub fn ticks(self) -> u64 {
        self.0
    }
}

/// `raw` as a pid: positive (`Pid::from_raw` panics on a negative number and returns `None` for 0).
#[must_use]
pub fn pid_from_raw(raw: i32) -> Option<Pid> {
    if raw > 0 { Pid::from_raw(raw) } else { None }
}

/// One process, for as long as its pid is not recycled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessIdentity {
    pid: Pid,
    start: StartTime,
}

/// Whether a [`ProcessIdentity`] still names a running process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Liveness {
    Alive,
    /// No such pid, a different process now has it, or it has exited and is only waiting to be
    /// reaped.
    Gone,
}

#[derive(Debug, thiserror::Error)]
pub enum ProcessError {
    #[error("no process has pid {}", .0.as_raw_nonzero())]
    NoSuchProcess(Pid),
    #[error("cannot read {}: {source}", .path.display())]
    Read { path: PathBuf, source: io::Error },
    #[error("{} is not a process status line: {reason}", .path.display())]
    Malformed { path: PathBuf, reason: StatProblem },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum StatProblem {
    #[error("no closing parenthesis after the command name")]
    NoCommandEnd,
    #[error("fewer than 22 fields")]
    TooShort,
    #[error("the start time is not a number")]
    StartNotANumber,
}

impl ProcessIdentity {
    #[must_use]
    pub fn new(pid: Pid, start: StartTime) -> Self {
        Self { pid, start }
    }

    #[must_use]
    pub fn pid(self) -> Pid {
        self.pid
    }

    #[must_use]
    pub fn start(self) -> StartTime {
        self.start
    }

    /// The identity of the process that has `pid` now.
    ///
    /// # Errors
    /// There is no such process, or its status cannot be read or parsed.
    pub fn of_running(pid: Pid) -> Result<Self, ProcessError> {
        match read_stat(pid)? {
            Some(stat) if stat.state.is_alive() => Ok(Self::new(pid, stat.start)),
            Some(_) | None => Err(ProcessError::NoSuchProcess(pid)),
        }
    }

    /// # Errors
    /// The process's status cannot be read or parsed (its absence is [`Liveness::Gone`]).
    pub fn liveness(self) -> Result<Liveness, ProcessError> {
        Ok(match read_stat(self.pid)? {
            Some(stat) if stat.start == self.start && stat.state.is_alive() => Liveness::Alive,
            Some(_) | None => Liveness::Gone,
        })
    }
}

/// `None` when the process does not exist.
fn read_stat(pid: Pid) -> Result<Option<Stat>, ProcessError> {
    let path = PathBuf::from(format!("/proc/{}/stat", pid.as_raw_nonzero()));
    match fs::read_to_string(&path) {
        Ok(text) => parse_stat(&text)
            .map(Some)
            .map_err(|reason| ProcessError::Malformed { path, reason }),
        // ESRCH shows up as ENOENT when the /proc entry vanishes between open and read.
        Err(error) if matches!(error.kind(), io::ErrorKind::NotFound) => Ok(None),
        Err(error) if error.raw_os_error() == Some(rustix::io::Errno::SRCH.raw_os_error()) => {
            Ok(None)
        }
        Err(source) => Err(ProcessError::Read { path, source }),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Running,
    /// `Z` (zombie) or `X` (dead): the process has exited.
    Exited,
}

impl State {
    fn is_alive(self) -> bool {
        match self {
            Self::Running => true,
            Self::Exited => false,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Stat {
    state: State,
    start: StartTime,
}

/// `<pid> (<comm>) <state> <ppid> …`. The command name may hold spaces and parentheses, so the
/// fields are counted from the *last* `)`, which only the kernel's closing one can be after it.
fn parse_stat(text: &str) -> Result<Stat, StatProblem> {
    /// `state` is field 3; `starttime` is field 22.
    const START_FIELD_AFTER_STATE: usize = 22 - 3;
    let after_command = text
        .rfind(')')
        .and_then(|end| text.get(end + 1..))
        .ok_or(StatProblem::NoCommandEnd)?;
    let mut fields = after_command.split_ascii_whitespace();
    let state = match fields.next().ok_or(StatProblem::TooShort)? {
        "Z" | "X" => State::Exited,
        _ => State::Running,
    };
    let start = fields
        .nth(START_FIELD_AFTER_STATE - 1)
        .ok_or(StatProblem::TooShort)?
        .parse()
        .map_err(|_| StatProblem::StartNotANumber)?;
    Ok(Stat {
        state,
        start: StartTime(start),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fields 4..=21 are filler; field 22 is `start`; two more follow.
    fn stat_line(comm: &str, state: &str, start: &str) -> String {
        let filler = vec!["0"; 18].join(" ");
        format!("4242 ({comm}) {state} {filler} {start} 1000 2000\n")
    }

    #[test]
    fn the_start_time_is_field_22() {
        let stat = parse_stat(&stat_line("sleep", "S", "98765")).unwrap();
        assert_eq!(stat.start, StartTime(98765));
        assert_eq!(stat.state, State::Running);
    }

    #[test]
    fn a_command_name_with_spaces_and_parentheses_does_not_shift_the_fields() {
        let stat = parse_stat(&stat_line("a b) (c 1 2 3", "R", "555")).unwrap();
        assert_eq!(stat.start, StartTime(555));
    }

    #[test]
    fn zombie_and_dead_are_exited() {
        for state in ["Z", "X"] {
            let stat = parse_stat(&stat_line("x", state, "1")).unwrap();
            assert_eq!(stat.state, State::Exited, "{state}");
        }
    }

    #[test]
    fn malformed_lines_are_errors_not_guesses() {
        assert_eq!(parse_stat("4242 no parens"), Err(StatProblem::NoCommandEnd));
        assert_eq!(parse_stat("4242 (x) S 1 2 3"), Err(StatProblem::TooShort));
        assert_eq!(
            parse_stat(&stat_line("x", "S", "soon")),
            Err(StatProblem::StartNotANumber)
        );
        assert_eq!(
            parse_stat(&stat_line("x", "S", "-5")),
            Err(StatProblem::StartNotANumber)
        );
    }

    #[test]
    fn this_process_is_alive_and_a_wrong_start_time_is_gone() {
        let me = rustix::process::getpid();
        let identity = ProcessIdentity::of_running(me).unwrap();
        assert_eq!(identity.liveness().unwrap(), Liveness::Alive);
        let recycled = ProcessIdentity::new(me, StartTime(identity.start().ticks() + 1));
        assert_eq!(recycled.liveness().unwrap(), Liveness::Gone);
    }
}
