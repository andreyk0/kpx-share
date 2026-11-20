//! Unlocking the database: run `keepassxc-cli export -f xml` and keep its stdout in memory.
//!
//! keepassxc-cli reads the master password from its stdin. In a terminal it is left to prompt
//! there ([`PasswordSource::Terminal`]); without one, the password comes from pinentry over
//! Assuan and is written to keepassxc-cli's stdin ([`PasswordSource::Pinentry`]). A database
//! with a key file and no password ([`MasterKey::KeyFileOnly`]) is exported with
//! `--no-password`, and nothing is asked for; when it also needs a `YubiKey` touch and there is
//! no terminal, a pinentry notice says so first.
//!
//! Secrecy (invariants I6 and I7): the decrypted XML is read straight into [`SecretBytes`] and
//! goes nowhere else; the password lives in a [`SecretBytes`] and is written to the pipe in place,
//! without an intermediate copy. keepassxc-cli's stderr is not secret (it prints prompts and
//! error messages, never database content), so it is captured, bounded, and carried in the error.
//! Nothing read from pinentry is ever included in an error.

use std::ffi::OsString;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, ExitStatus, Stdio};
use std::thread;

use crate::assuan::{self, AssuanError, Dialog};
use crate::layout::SessionName;
use crate::mode::Mode;
use crate::secret::SecretBytes;
use crate::subprocess::{ToolError, capture_stderr, ignore_broken_pipe, take_pipe};
use crate::tools;

/// What the database's master key is made of, besides a hardware key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MasterKey {
    /// A password, asked for on the terminal or through pinentry, and optionally a key file.
    Password { key_file: Option<PathBuf> },
    /// A key file and no password at all: nothing is asked for, and keepassxc-cli is told so
    /// (`--no-password`; any password piped to it is "invalid credentials" for such a database).
    KeyFileOnly { key_file: PathBuf },
}

impl MasterKey {
    fn key_file(&self) -> Option<&Path> {
        match self {
            Self::Password { key_file } => key_file.as_deref(),
            Self::KeyFileOnly { key_file } => Some(key_file),
        }
    }
}

/// Where the database is and what unlocks it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnlockRequest {
    pub database: PathBuf,
    pub master_key: MasterKey,
    pub yubikey: Option<YubiKeySlot>,
}

/// A `YubiKey` challenge-response slot. A serial number (`slot:serial`) is not supported.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum YubiKeySlot {
    One,
    Two,
}

impl YubiKeySlot {
    fn argument(self) -> &'static str {
        match self {
            Self::One => "1",
            Self::Two => "2",
        }
    }
}

/// Where the master password comes from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PasswordSource {
    /// keepassxc-cli prompts on the terminal it inherits.
    Terminal,
    /// Ask the program (pinentry) through a dialog, then hand the answer to keepassxc-cli.
    Pinentry { program: PathBuf },
}

impl PasswordSource {
    #[must_use]
    pub fn for_mode(mode: Mode) -> Self {
        match mode {
            Mode::Terminal => Self::Terminal,
            Mode::NoTerminal => Self::Pinentry {
                program: tools::path(tools::PINENTRY_GNOME3).to_owned(),
            },
        }
    }
}

/// Where keepassxc-cli's stderr went.
enum Stderr {
    /// To the terminal, where the human has already seen it.
    OnTerminal,
    /// Captured, bounded and on one line.
    Captured(String),
}

/// Why the database could not be unlocked. No variant holds the password or database content.
#[derive(Debug, thiserror::Error)]
pub enum UnlockError {
    /// keepassxc-cli or pinentry could not be run, talked to, or failed with its stderr captured.
    #[error(transparent)]
    Tool(#[from] ToolError),
    /// The human closed the password dialog, or the `YubiKey` notice.
    #[error("the pinentry dialog was cancelled")]
    Cancelled,
    #[error("the pinentry dialog ({}) failed: {source}", tool.display())]
    Pinentry { tool: PathBuf, source: AssuanError },
    #[error("the password contains a line break, which keepassxc-cli cannot read from a pipe")]
    PasswordHasLineBreak,
    /// keepassxc-cli rejected the password, key file or `YubiKey` response. Only recognised when
    /// its stderr was captured, by its message; anything unrecognised is a [`ToolError::Failed`].
    #[error("keepassxc-cli reported invalid credentials")]
    InvalidCredentials,
    /// keepassxc-cli failed having written its complaint to the terminal.
    #[error("{} exited with {status}; see its output above", tool.display())]
    FailedOnTerminal { tool: PathBuf, status: ExitStatus },
}

/// Runs `keepassxc-cli export -f xml` for `request` and returns the XML. `session` is the
/// session the entry is for; the password dialog names it.
///
/// # Errors
/// See [`UnlockError`].
pub fn unlock(
    request: &UnlockRequest,
    source: &PasswordSource,
    session: &SessionName,
) -> Result<SecretBytes, UnlockError> {
    unlock_with(tools::path(tools::KEEPASSXC_CLI), request, source, session)
}

/// [`unlock`] with the keepassxc-cli at `keepassxc_cli`, for callers that are handed the tools.
///
/// # Errors
/// See [`UnlockError`].
pub fn unlock_with(
    keepassxc_cli: &Path,
    request: &UnlockRequest,
    source: &PasswordSource,
    session: &SessionName,
) -> Result<SecretBytes, UnlockError> {
    match (&request.master_key, source) {
        (_, PasswordSource::Terminal) => export(keepassxc_cli, request, &Credentials::OnTerminal),
        (MasterKey::KeyFileOnly { .. }, PasswordSource::Pinentry { program }) => {
            // Without a terminal keepassxc-cli's touch prompt is captured, and with no password
            // dialog nothing else tells the human the key is about to be asked for.
            if let Some(slot) = request.yubikey {
                show_touch_notice(program, request, slot, session)?;
            }
            export(keepassxc_cli, request, &Credentials::NothingToAsk)
        }
        (MasterKey::Password { .. }, PasswordSource::Pinentry { program }) => {
            let password = ask_pinentry(program, request, session)?;
            export(keepassxc_cli, request, &Credentials::Password(&password))
        }
    }
}

/// How keepassxc-cli is given what it asks for.
enum Credentials<'a> {
    /// It prompts on the terminal it inherits.
    OnTerminal,
    /// Written to its stdin as one line.
    Password(&'a SecretBytes),
    /// There is no terminal and no password: its stdin is closed and its stderr captured.
    NothingToAsk,
}

fn export_args(request: &UnlockRequest) -> Vec<OsString> {
    let mut args: Vec<OsString> = ["export", "-f", "xml"].map(Into::into).into();
    if matches!(request.master_key, MasterKey::KeyFileOnly { .. }) {
        args.push("--no-password".into());
    }
    if let Some(key_file) = request.master_key.key_file() {
        args.extend(["-k".into(), key_file.into()]);
    }
    if let Some(slot) = request.yubikey {
        args.extend(["-y".into(), slot.argument().into()]);
    }
    // After `--`, so a database path that starts with `-` is not read as an option.
    args.extend(["--".into(), request.database.clone().into()]);
    args
}

fn export(
    program: &Path,
    request: &UnlockRequest,
    credentials: &Credentials<'_>,
) -> Result<SecretBytes, UnlockError> {
    let io_error = |source| ToolError::Io {
        tool: program.to_owned(),
        source,
    };
    let mut command = Command::new(program);
    command.args(export_args(request)).stdout(Stdio::piped());
    match credentials {
        Credentials::OnTerminal => command.stdin(Stdio::inherit()).stderr(Stdio::inherit()),
        Credentials::Password(password) => {
            if password.expose().iter().any(|b| matches!(b, b'\n' | b'\r')) {
                return Err(UnlockError::PasswordHasLineBreak);
            }
            command.stdin(Stdio::piped()).stderr(Stdio::piped())
        }
        Credentials::NothingToAsk => command.stdin(Stdio::null()).stderr(Stdio::piped()),
    };
    let mut child = command.spawn().map_err(|source| ToolError::Spawn {
        tool: program.to_owned(),
        source,
    })?;

    let outcome = run_to_completion(&mut child, credentials);
    // Reaped on every path; a failed read leaves the exit status moot.
    let status = child.wait();
    let (xml, stderr) = outcome.map_err(io_error)?;
    let status = status.map_err(io_error)?;
    if status.success() {
        return Ok(xml);
    }
    Err(match stderr {
        Stderr::Captured(text) if text.contains(INVALID_CREDENTIALS_MESSAGE) => {
            UnlockError::InvalidCredentials
        }
        Stderr::Captured(stderr) => UnlockError::Tool(ToolError::Failed {
            tool: program.to_owned(),
            status,
            stderr,
        }),
        Stderr::OnTerminal => UnlockError::FailedOnTerminal {
            tool: program.to_owned(),
            status,
        },
    })
}

/// keepassxc-cli's message for a wrong password, key file or `YubiKey` response (2.8).
const INVALID_CREDENTIALS_MESSAGE: &str = "Invalid credentials were provided";

/// Feeds the password, then collects stdout (secret) and stderr (diagnostics) concurrently.
fn run_to_completion(
    child: &mut Child,
    credentials: &Credentials<'_>,
) -> io::Result<(SecretBytes, Stderr)> {
    if let Credentials::Password(password) = credentials {
        let mut stdin = take_pipe(child.stdin.take())?;
        // keepassxc-cli may exit without reading it; its exit status says why.
        ignore_broken_pipe(
            stdin
                .write_all(password.expose())
                .and_then(|()| stdin.write_all(b"\n")),
        )?;
    }
    let stdout = take_pipe(child.stdout.take())?;
    let stderr = child.stderr.take();
    thread::scope(|scope| {
        let captured = scope.spawn(|| stderr.map(capture_stderr));
        let xml = SecretBytes::read_to_end(stdout);
        let stderr = match captured.join() {
            Ok(Some(text)) => Stderr::Captured(text),
            // No pipe was asked for: stderr was the terminal's.
            Ok(None) => Stderr::OnTerminal,
            Err(_panicked) => Stderr::Captured(String::new()),
        };
        xml.map(|xml| (xml, stderr))
    })
}

/// The first line of every dialog: which database, which session it is for, so that an
/// unexpected prompt is recognisable.
fn unlock_line(request: &UnlockRequest, session: &SessionName) -> String {
    format!(
        "kpx-share: unlock {} to share one entry into session {}",
        request.database.display(),
        session.as_str()
    )
}

/// What the password dialog says: [`unlock_line`] and, when a `YubiKey` slot is configured, that
/// the key must be touched after the password, because without a terminal keepassxc-cli's
/// "please touch your `YubiKey`" is captured and the human never sees it.
#[must_use]
pub fn pinentry_description(request: &UnlockRequest, session: &SessionName) -> String {
    let touch = request
        .yubikey
        .map(|slot| {
            format!(
                "\nAfter the password, touch the YubiKey (slot {}) when it flashes.",
                slot.argument()
            )
        })
        .unwrap_or_default();
    format!("{}{touch}", unlock_line(request, session))
}

/// What the notice says when there is no password to ask for and so no dialog to carry the
/// instruction to touch the key `slot`.
#[must_use]
pub fn touch_notice(request: &UnlockRequest, slot: YubiKeySlot, session: &SessionName) -> String {
    format!(
        "{}\nAfter you press OK, touch the YubiKey (slot {}) when it flashes.",
        unlock_line(request, session),
        slot.argument()
    )
}

/// Tells the human, in a window, to touch the key `slot`, and returns once they have pressed OK.
fn show_touch_notice(
    program: &Path,
    request: &UnlockRequest,
    slot: YubiKeySlot,
    session: &SessionName,
) -> Result<(), UnlockError> {
    let description = touch_notice(request, slot, session);
    with_pinentry(program, |server, client| {
        assuan::message(server, client, "kpx-share", &description)
    })
}

fn ask_pinentry(
    program: &Path,
    request: &UnlockRequest,
    session: &SessionName,
) -> Result<SecretBytes, UnlockError> {
    let description = pinentry_description(request, session);
    let dialog = Dialog {
        title: "kpx-share",
        description: &description,
        prompt: "Password:",
    };
    with_pinentry(program, |server, client| {
        assuan::get_pin(server, client, &dialog)
    })
}

/// Runs pinentry, lets `talk` hold the Assuan conversation, and ends it: politely when it
/// succeeded, by killing it when not. A dismissed dialog is [`UnlockError::Cancelled`].
fn with_pinentry<T>(
    program: &Path,
    talk: impl FnOnce(&mut ChildStdout, &mut ChildStdin) -> Result<T, AssuanError>,
) -> Result<T, UnlockError> {
    let io_error = |source| ToolError::Io {
        tool: program.to_owned(),
        source,
    };
    let mut child = Command::new(program)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|source| ToolError::Spawn {
            tool: program.to_owned(),
            source,
        })?;
    let (mut stdin, mut stdout) = match (
        take_pipe(child.stdin.take()),
        take_pipe(child.stdout.take()),
    ) {
        (Ok(stdin), Ok(stdout)) => (stdin, stdout),
        (Err(source), _) | (_, Err(source)) => {
            kill_and_reap(&mut child);
            return Err(io_error(source).into());
        }
    };
    let answer = talk(&mut stdout, &mut stdin);
    if answer.is_ok() {
        assuan::bye(&mut stdin);
        drop(stdin);
        // The conversation is complete; how pinentry exits is not our concern.
        let _exit = child.wait();
    } else {
        drop(stdin);
        kill_and_reap(&mut child);
    }
    answer.map_err(|source| match source {
        AssuanError::Cancelled => UnlockError::Cancelled,
        source => UnlockError::Pinentry {
            tool: program.to_owned(),
            source,
        },
    })
}

fn kill_and_reap(child: &mut Child) {
    // It may already have exited, which is the outcome wanted.
    let _killed = child.kill();
    let _exit = child.wait();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(key_file: Option<&str>, yubikey: Option<YubiKeySlot>) -> UnlockRequest {
        UnlockRequest {
            database: "db dir/-my.kdbx".into(),
            master_key: MasterKey::Password {
                key_file: key_file.map(Into::into),
            },
            yubikey,
        }
    }

    fn session() -> SessionName {
        SessionName::parse("claude-0b1c").unwrap()
    }

    fn args(request: &UnlockRequest) -> Vec<String> {
        export_args(request)
            .into_iter()
            .map(|arg| arg.into_string().unwrap())
            .collect()
    }

    #[test]
    fn args_are_the_database_alone_by_default() {
        assert_eq!(
            args(&request(None, None)),
            ["export", "-f", "xml", "--", "db dir/-my.kdbx"]
        );
    }

    #[test]
    fn key_file_and_yubikey_slot_precede_the_database() {
        assert_eq!(
            args(&request(Some("/k/key"), Some(YubiKeySlot::Two))),
            [
                "export",
                "-f",
                "xml",
                "-k",
                "/k/key",
                "-y",
                "2",
                "--",
                "db dir/-my.kdbx"
            ]
        );
        assert_eq!(
            args(&request(None, Some(YubiKeySlot::One))),
            ["export", "-f", "xml", "-y", "1", "--", "db dir/-my.kdbx"]
        );
    }

    /// `--no-password` is what makes keepassxc-cli accept a database that has only a key file.
    /// Red when it is missing there, or present when a password is asked for.
    #[test]
    fn a_key_file_only_database_is_exported_with_no_password() {
        let request = UnlockRequest {
            database: "db.kdbx".into(),
            master_key: MasterKey::KeyFileOnly {
                key_file: "/k/key".into(),
            },
            yubikey: Some(YubiKeySlot::Two),
        };
        assert_eq!(
            args(&request),
            [
                "export",
                "-f",
                "xml",
                "--no-password",
                "-k",
                "/k/key",
                "-y",
                "2",
                "--",
                "db.kdbx"
            ]
        );
        assert!(!args(&self::request(Some("/k/key"), None)).contains(&"--no-password".to_owned()));
    }

    /// The text the human sees when a dialog appears from nowhere: the database, the session it
    /// is for and, only with a `YubiKey` slot configured, the instruction to touch the key.
    #[test]
    fn the_password_dialog_names_the_database_the_session_and_a_yubikey_touch() {
        assert_eq!(
            pinentry_description(&request(None, None), &session()),
            "kpx-share: unlock db dir/-my.kdbx to share one entry into session claude-0b1c"
        );
        assert_eq!(
            pinentry_description(&request(Some("/k"), Some(YubiKeySlot::Two)), &session()),
            "kpx-share: unlock db dir/-my.kdbx to share one entry into session claude-0b1c\n\
             After the password, touch the YubiKey (slot 2) when it flashes."
        );
    }

    /// With no password to ask for, the notice is the only place the touch is announced.
    #[test]
    fn the_touch_notice_names_the_database_the_session_and_the_slot() {
        assert_eq!(
            touch_notice(&request(None, None), YubiKeySlot::One, &session()),
            "kpx-share: unlock db dir/-my.kdbx to share one entry into session claude-0b1c\n\
             After you press OK, touch the YubiKey (slot 1) when it flashes."
        );
    }

    #[test]
    fn a_missing_keepassxc_cli_is_a_spawn_error_naming_it() {
        let missing = Path::new("/nonexistent/keepassxc-cli");
        let error = unlock_with(
            missing,
            &request(None, None),
            &PasswordSource::Terminal,
            &session(),
        )
        .unwrap_err();
        assert!(
            matches!(&error, UnlockError::Tool(ToolError::Spawn { tool, .. }) if tool == missing),
            "{error:?}"
        );
        assert!(error.to_string().contains("/nonexistent/keepassxc-cli"));
    }

    #[test]
    fn mode_chooses_the_password_source() {
        assert_eq!(
            PasswordSource::for_mode(Mode::Terminal),
            PasswordSource::Terminal
        );
        assert_eq!(
            PasswordSource::for_mode(Mode::NoTerminal),
            PasswordSource::Pinentry {
                program: "/usr/bin/pinentry-gnome3".into()
            }
        );
    }
}
