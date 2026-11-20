//! The command line: argument types, and one function per command that does what it says and
//! returns how the process should exit.
//!
//! The commands take everything they depend on as arguments (the runtime directory, the session
//! binding, the tools, where output goes), so tests drive them with fakes and a scratch
//! directory. [`main`] is the only place that reads the environment and chooses the real programs;
//! nothing on the command line or in the environment can substitute a tool.
//!
//! Output (invariant I7): the only thing `add` writes to stdout is the entry directory's path.
//! Everything else, notices and errors alike, goes to stderr as `kpx-share: <message>`, and no
//! message holds a field value.

use std::error::Error;
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};
use jiff::Timestamp;

use crate::add::{AddRequest, AddTools, Added, Where, add};
use crate::harden::harden;
use crate::launch::SystemdRun;
use crate::layout::{DirError, RootError, SafeName, SessionDir, SessionName, ShareRoot};
use crate::manage::{self, GcOutcome, GcSummary, Removed};
use crate::mode::Mode;
use crate::pick::Query;
use crate::select::{Eligibility, InvalidTag, RequiredTag};
use crate::session::{Binding, BindingError, Ttl};
use crate::text::one_line;
use crate::unlock::{MasterKey, UnlockRequest, YubiKeySlot};
use crate::watch::{WatchOutcome, watch};

// --- Arguments --------------------------------------------------------------------------------

#[derive(Debug, Parser)]
#[command(
    name = "kpx-share",
    version,
    about = "Share one KeePassXC entry into an AI agent session as files on tmpfs",
    long_about = "Unlocks your KeePassXC database, lets you pick one entry, and writes it as \
                  files under $XDG_RUNTIME_DIR/kpx-share/<session>/<entry>/ (tmpfs). A watcher \
                  deletes the session directory when the session's process exits or its TTL \
                  passes."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Pick one entry and share it into this session; prints the entry's directory
    Add(AddArgs),
    /// List the entries shared into this session
    Ls,
    /// Remove one shared entry, or all of them
    Rm(RmArgs),
    /// Remove the directories of sessions that have ended
    Gc,
    /// Delete a session directory when its session ends (started by `add`)
    #[command(hide = true)]
    Watch(WatchArgs),
}

#[derive(Debug, Args)]
pub struct AddArgs {
    /// Share any entry, tagged or not
    #[arg(long, conflicts_with = "tag")]
    any: bool,
    /// The tag an entry must carry to be shared (case-insensitive)
    #[arg(long, default_value = RequiredTag::DEFAULT, value_name = "TAG")]
    tag: String,
    /// The database file (.kdbx)
    #[arg(long, env = "KPX_SHARE_DB", value_name = "PATH")]
    db: Option<PathBuf>,
    /// The database's key file
    #[arg(long, env = "KPX_SHARE_KEY_FILE", value_name = "PATH")]
    key_file: Option<PathBuf>,
    /// The database has a key file and no password: ask for none (needs a key file)
    #[arg(long, requires = "key_file")]
    no_password: bool,
    /// The slot of the hardware key that answers the database's challenge
    #[arg(long, env = "KPX_SHARE_YUBIKEY", value_name = "1|2", value_parser = parse_slot)]
    yubikey: Option<YubiKeySlot>,
    #[arg(long, default_value_t = Ttl::DEFAULT, value_name = "DURATION", help = ttl_help())]
    ttl: Ttl,
    /// Words that narrow the choice: each must occur in an entry's path, user name or URL
    query: Vec<String>,
}

fn ttl_help() -> String {
    format!(
        "How long the session lasts at most, if its process does not end first ({} to {}); \
         a later add can shorten it, never extend it",
        Ttl::MIN,
        Ttl::MAX
    )
}

fn parse_slot(text: &str) -> Result<YubiKeySlot, String> {
    match text {
        "1" => Ok(YubiKeySlot::One),
        "2" => Ok(YubiKeySlot::Two),
        other => Err(format!("{other:?} is not a slot, use 1 or 2")),
    }
}

#[derive(Debug, Args)]
pub struct RmArgs {
    /// The entry to remove, as `ls` shows it
    #[arg(required_unless_present = "all", conflicts_with = "all")]
    slug: Option<String>,
    /// Remove every entry of this session
    #[arg(long)]
    all: bool,
}

#[derive(Debug, Args)]
pub struct WatchArgs {
    #[arg(long)]
    session: String,
    #[arg(long)]
    root: PathBuf,
}

#[derive(Debug, thiserror::Error)]
pub enum ArgsError {
    #[error("no database configured: pass --db or set KPX_SHARE_DB")]
    NoDatabase,
    #[error("--no-password needs --key-file: without a password a database needs a key file")]
    NoPasswordNeedsKeyFile,
    #[error("--tag {0:?}: {InvalidTag}")]
    BadTag(String),
    #[error("{0:?} is not an entry name; `kpx-share ls` shows them")]
    BadSlug(String),
    #[error("{0:?} is not a session name")]
    BadSession(String),
}

impl AddArgs {
    /// # Errors
    /// No database was given, or the tag cannot be a tag.
    pub fn into_request(self) -> Result<AddRequest, ArgsError> {
        let database = self.db.ok_or(ArgsError::NoDatabase)?;
        let eligibility = if self.any {
            Eligibility::Any
        } else {
            Eligibility::Tagged(
                RequiredTag::parse(&self.tag).map_err(|InvalidTag| ArgsError::BadTag(self.tag))?,
            )
        };
        let master_key = match (self.no_password, self.key_file) {
            (false, key_file) => MasterKey::Password { key_file },
            (true, Some(key_file)) => MasterKey::KeyFileOnly { key_file },
            // The command line refuses this (`requires`); a caller building AddArgs otherwise
            // gets the same refusal.
            (true, None) => return Err(ArgsError::NoPasswordNeedsKeyFile),
        };
        Ok(AddRequest {
            database: UnlockRequest {
                database,
                master_key,
                yubikey: self.yubikey,
            },
            query: Query::parse(&self.query.join(" ")),
            eligibility,
            ttl: self.ttl,
        })
    }
}

/// What `rm` was asked to remove.
enum RmTarget {
    Entry(SafeName),
    Everything,
}

impl RmArgs {
    fn target(self) -> Result<RmTarget, ArgsError> {
        match self.slug {
            None => Ok(RmTarget::Everything),
            Some(slug) => SafeName::parse(&slug)
                .map(RmTarget::Entry)
                .ok_or(ArgsError::BadSlug(slug)),
        }
    }
}

// --- Output and exit --------------------------------------------------------------------------

/// How a command ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Exit {
    Success,
    Failure,
    /// The human closed the password dialog or the picker.
    Cancelled,
}

impl Exit {
    /// 130 is what a shell reports for a process ended by Ctrl-C, and what fzf exits with on Esc.
    pub const CANCELLED_CODE: u8 = 130;
}

impl From<Exit> for ExitCode {
    fn from(exit: Exit) -> Self {
        match exit {
            Exit::Success => Self::SUCCESS,
            Exit::Failure => Self::FAILURE,
            Exit::Cancelled => Self::from(Exit::CANCELLED_CODE),
        }
    }
}

/// Where a command's output goes.
pub struct Io<'a> {
    pub out: &'a mut dyn Write,
    pub err: &'a mut dyn Write,
}

impl std::fmt::Debug for Io<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Io").finish_non_exhaustive()
    }
}

impl Io<'_> {
    /// One line on stderr. Failing to write a diagnostic leaves nowhere to report it.
    fn say(&mut self, message: impl std::fmt::Display) {
        let _unreportable = writeln!(self.err, "kpx-share: {message}");
    }

    fn fail(&mut self, error: &dyn Error) -> Exit {
        self.say(error_line(error));
        Exit::Failure
    }
}

/// `error` and its causes on one line. A cause whose text the message already includes (the
/// errors here print their `source` themselves) is not repeated.
#[must_use]
pub fn error_line(error: &dyn Error) -> String {
    let mut line = error.to_string();
    let mut cause = error.source();
    while let Some(next) = cause {
        let text = next.to_string();
        if !line.contains(&text) {
            line.push_str(": ");
            line.push_str(&text);
        }
        cause = next.source();
    }
    one_line(&line)
}

// --- Commands ---------------------------------------------------------------------------------

/// `add`: prints the entry directory's path, and only that, on stdout.
pub fn add_command(args: AddArgs, at: Where<'_>, tools: &AddTools<'_>, io: &mut Io<'_>) -> Exit {
    let request = match args.into_request() {
        Ok(request) => request,
        Err(error) => return io.fail(&error),
    };
    if request.eligibility == Eligibility::Any {
        io.say("sharing from all entries (--any), not only those tagged");
    }
    match add(at, tools, &request) {
        Ok(Added::Shared(entry)) => match writeln!(io.out, "{}", entry.path().display()) {
            Ok(()) => Exit::Success,
            Err(error) => io.fail(&error),
        },
        Ok(Added::Declined) => {
            io.say("cancelled");
            Exit::Cancelled
        }
        Err(error) => io.fail(&error),
    }
}

#[derive(Debug, thiserror::Error)]
enum SessionLookupError {
    #[error(transparent)]
    Root(#[from] RootError),
    #[error(transparent)]
    Dir(#[from] DirError),
}

fn find_session(at: Where<'_>) -> Result<Option<SessionDir>, SessionLookupError> {
    let root = ShareRoot::in_runtime_dir(at.runtime_dir)?;
    Ok(SessionDir::find(&root, &at.binding.name())?)
}

/// `ls`: one line per entry on stdout.
pub fn ls_command(at: Where<'_>, io: &mut Io<'_>) -> Exit {
    let dir = match find_session(at) {
        Ok(Some(dir)) => dir,
        Ok(None) => {
            io.say("nothing is shared into this session");
            return Exit::Success;
        }
        Err(error) => return io.fail(&error),
    };
    match manage::list(&dir) {
        Ok(lines) => {
            for line in lines {
                if let Err(error) = writeln!(io.out, "{line}") {
                    return io.fail(&error);
                }
            }
            Exit::Success
        }
        Err(error) => io.fail(&error),
    }
}

/// `rm <slug>` and `rm --all`.
pub fn rm_command(args: RmArgs, at: Where<'_>, io: &mut Io<'_>) -> Exit {
    let target = match args.target() {
        Ok(target) => target,
        Err(error) => return io.fail(&error),
    };
    let root = match ShareRoot::in_runtime_dir(at.runtime_dir) {
        Ok(root) => root,
        Err(error) => return io.fail(&error),
    };
    let name = at.binding.name();
    let removed = match &target {
        RmTarget::Entry(slug) => manage::remove_entry(&root, &name, slug),
        RmTarget::Everything => manage::remove_session(&root, &name),
    };
    match removed {
        Ok(Removed::Entry) => io.say("removed the entry"),
        Ok(Removed::Session) => io.say("removed this session's directory"),
        Ok(Removed::NothingShared) => io.say("nothing is shared into this session"),
        Err(error) => return io.fail(&error),
    }
    Exit::Success
}

/// `gc`: reports on stderr what it removed, kept and could not remove.
pub fn gc_command(runtime_dir: Option<&std::ffi::OsStr>, io: &mut Io<'_>) -> Exit {
    let root = match ShareRoot::in_runtime_dir(runtime_dir) {
        Ok(root) => root,
        Err(error) => return io.fail(&error),
    };
    let report = match manage::gc(&root, Timestamp::now()) {
        Ok(report) => report,
        Err(error) => return io.fail(&error),
    };
    for entry in &report {
        match &entry.outcome {
            GcOutcome::Live | GcOutcome::AlreadyGone => {}
            GcOutcome::Removed(_)
            | GcOutcome::Failed(_)
            | GcOutcome::KeptRecent { .. }
            | GcOutcome::Foreign => io.say(format_args!("gc: {entry}")),
        }
    }
    let summary = GcSummary::of(&report);
    io.say(format_args!("gc: {summary}"));
    if summary.failed == 0 {
        Exit::Success
    } else {
        Exit::Failure
    }
}

/// The hidden `watch`: runs until the session ends, and says how on stderr (the journal).
pub fn watch_command(args: WatchArgs, io: &mut Io<'_>) -> Exit {
    let Ok(name) = SessionName::parse(&args.session) else {
        return io.fail(&ArgsError::BadSession(args.session));
    };
    let root = match ShareRoot::at(&args.root) {
        Ok(root) => root,
        Err(error) => return io.fail(&error),
    };
    match watch(&root, &name) {
        Ok(WatchOutcome::Removed(end)) => io.say(format_args!("watch: removed {name:?}: {end}")),
        Ok(WatchOutcome::EndedWithoutDirectory(end)) => {
            io.say(format_args!(
                "watch: {name:?} {end}, its directory was already gone"
            ));
        }
        Ok(WatchOutcome::NeverRecorded) => {
            io.say(format_args!(
                "watch: {name:?} never had a session record, left for gc"
            ));
        }
        Err(error) => return io.fail(&error),
    }
    Exit::Success
}

// --- The process ------------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
enum SetupError {
    #[error(transparent)]
    Binding(#[from] BindingError),
    #[error("cannot find this program's own path to start the watcher: {0}")]
    CurrentExe(std::io::Error),
}

/// The program: hardens the process, reads the command line and the environment, and runs the
/// command with the real tools.
pub fn main() -> ExitCode {
    let mut stdout = std::io::stdout().lock();
    let mut stderr = std::io::stderr().lock();
    let mut io = Io {
        out: &mut stdout,
        err: &mut stderr,
    };
    // First, before the command line, the environment or any file is looked at (I6).
    if let Err(error) = harden() {
        return io.fail(&error).into();
    }
    let cli = Cli::parse();
    run(cli.command, &mut io).into()
}

fn run(command: Command, io: &mut Io<'_>) -> Exit {
    let runtime_dir = std::env::var_os("XDG_RUNTIME_DIR");
    let runtime_dir = runtime_dir.as_deref();
    match command {
        Command::Gc => gc_command(runtime_dir, io),
        Command::Watch(args) => watch_command(args, io),
        Command::Add(args) => {
            let (binding, launcher) = match session_setup() {
                Ok(setup) => setup,
                Err(error) => return io.fail(&error),
            };
            let tools = AddTools::production(Mode::detect(), &launcher);
            let at = Where {
                runtime_dir,
                binding: &binding,
            };
            add_command(args, at, &tools, io)
        }
        Command::Ls | Command::Rm(_) => {
            let binding = match Binding::from_env() {
                Ok(binding) => binding,
                Err(error) => return io.fail(&error),
            };
            let at = Where {
                runtime_dir,
                binding: &binding,
            };
            match command {
                Command::Rm(args) => rm_command(args, at, io),
                _ => ls_command(at, io),
            }
        }
    }
}

fn session_setup() -> Result<(Binding, SystemdRun), SetupError> {
    Ok((
        Binding::from_env()?,
        SystemdRun::for_current_exe().map_err(SetupError::CurrentExe)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, thiserror::Error)]
    #[error("outer: {source}")]
    struct Outer {
        source: Inner,
    }

    #[derive(Debug, thiserror::Error)]
    #[error("inner")]
    struct Inner(#[source] std::io::Error);

    #[test]
    fn the_error_chain_is_one_line_without_repeating_what_the_message_already_says() {
        let error = Outer {
            source: Inner(std::io::Error::other("disk\nfull")),
        };
        assert_eq!(error_line(&error), "outer: inner: disk full");
    }

    #[test]
    fn the_clap_definition_is_consistent() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }
}
