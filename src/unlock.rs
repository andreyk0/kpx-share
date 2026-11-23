//! Unlocking the database: run `keepassxc-cli export -f xml` and keep its stdout in memory; then,
//! with the same key ([`ShareKey`]), `keepassxc-cli attachment-export` for each attachment the
//! export does not carry (see [`crate::model::Attachments`]). `import` unlocks a copy of the
//! database the same way and holds an [`ImportKey`], which also adds an entry
//! (`keepassxc-cli add`) and attachments (`keepassxc-cli attachment-import`) to that copy.
//!
//! keepassxc-cli reads the master password from its stdin. A typed password
//! ([`MasterKey::TypedPassword`]) is, in a terminal, left to keepassxc-cli to prompt for there
//! ([`Prompter::Terminal`]); without one, it comes from pinentry over Assuan and is written to
//! keepassxc-cli's stdin ([`Prompter::Pinentry`]). An encrypted password
//! ([`MasterKey::EncryptedPassword`]) is decrypted by gpg, which asks for whatever the `OpenPGP`
//! key needs (a card's PIN through gpg-agent, a touch), and is written to keepassxc-cli's stdin
//! in either mode. A database with a key file and no password ([`MasterKey::KeyFileOnly`]) is
//! exported with `--no-password`, and nothing is asked for. Whenever no password dialog is shown
//! and the database needs a `YubiKey` touch, a pinentry notice says so first. `import` pipes
//! the entry's password to keepassxc-cli's stdin after the master password, so for it the master
//! password is never left to the terminal ([`UnlockError::TypedPasswordOnTerminal`]), and a
//! dialog the human closes is an [`Outcome::Declined`], not an error.
//!
//! Secrecy (invariants I6 and I7): the decrypted XML and attachments are read straight into
//! [`SecretBytes`] and go nowhere else; the password lives in a [`SecretBytes`], held until the
//! last attachment is exported, and is written to the pipe in place,
//! without an intermediate copy. An attachment being imported reaches keepassxc-cli through a
//! pipe it opens as `/dev/fd/<n>`, never a file (invariant S5). keepassxc-cli's and gpg's stderr
//! is not secret (prompts and error messages, never database content or plaintext), so it is
//! captured, bounded, and carried in the error. Nothing read from pinentry is ever included in
//! an error.

use std::ffi::OsString;
use std::io::{self, PipeReader, PipeWriter, Write};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, ExitStatus, Stdio};
use std::thread;

use crate::assuan::{self, AssuanError, Dialog};
use crate::layout::SessionName;
use crate::mode::Mode;
use crate::secret::SecretBytes;
use crate::select::CliEntryPath;
use crate::subprocess::{ToolError, capture_stderr, ignore_broken_pipe, take_pipe};
use crate::tools;

/// What the database's master key is made of, besides a hardware key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MasterKey {
    /// A password the human types, on the terminal or into pinentry, and optionally a key file.
    TypedPassword { key_file: Option<PathBuf> },
    /// A password kept OpenPGP-encrypted in `file` and decrypted by gpg, and optionally a key
    /// file. The decrypted text is the password; one trailing line feed is not part of it.
    EncryptedPassword {
        file: PathBuf,
        key_file: Option<PathBuf>,
    },
    /// A key file and no password at all: nothing is asked for, and keepassxc-cli is told so
    /// (`--no-password`; any password piped to it is "invalid credentials" for such a database).
    KeyFileOnly { key_file: PathBuf },
}

impl MasterKey {
    fn key_file(&self) -> Option<&Path> {
        match self {
            Self::TypedPassword { key_file } | Self::EncryptedPassword { key_file, .. } => {
                key_file.as_deref()
            }
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

/// How the human is asked for a typed password and told to touch a `YubiKey`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Prompter {
    /// On the terminal: keepassxc-cli prompts on the terminal it inherits, and the programs run
    /// write to it.
    Terminal,
    /// In a window: the program (pinentry) shows the password dialog and the touch notices.
    Pinentry { program: PathBuf },
}

impl Prompter {
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

/// The programs unlocking runs. Production is [`UnlockTools::production`]; tests hand in fakes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnlockTools {
    pub keepassxc_cli: PathBuf,
    pub gpg: PathBuf,
    pub prompter: Prompter,
}

impl UnlockTools {
    /// The real programs, by absolute path, with the prompter for `mode`.
    #[must_use]
    pub fn production(mode: Mode) -> Self {
        Self {
            keepassxc_cli: tools::path(tools::KEEPASSXC_CLI).to_owned(),
            gpg: tools::path(tools::GPG).to_owned(),
            prompter: Prompter::for_mode(mode),
        }
    }
}

/// How a step the human takes part in ended, when it did not fail: done, or declined by closing
/// a dialog (the password dialog, a `YubiKey` notice).
#[derive(Debug, PartialEq, Eq)]
#[must_use]
pub enum Outcome<T> {
    Done(T),
    Declined,
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
    /// The human closed the password dialog, or the `YubiKey` notice, while sharing; `import`
    /// reports it as [`Outcome::Declined`] instead.
    #[error("the pinentry dialog was cancelled")]
    Cancelled,
    #[error("the pinentry dialog ({}) failed: {source}", tool.display())]
    Pinentry { tool: PathBuf, source: AssuanError },
    #[error("the password contains a line break, which keepassxc-cli cannot read from a pipe")]
    PasswordHasLineBreak,
    #[error(
        "{} decrypts to more than {ENCRYPTED_PASSWORD_BYTES_MAX} bytes, too long to be a password",
        file.display()
    )]
    EncryptedPasswordTooLong { file: PathBuf },
    /// keepassxc-cli rejected the password, key file or `YubiKey` response. Only recognised when
    /// its stderr was captured, by its message; anything unrecognised is a [`ToolError::Failed`].
    #[error("keepassxc-cli reported invalid credentials")]
    InvalidCredentials,
    /// keepassxc-cli failed having written its complaint to the terminal.
    #[error("{} exited with {status}; see its output above", tool.display())]
    FailedOnTerminal { tool: PathBuf, status: ExitStatus },
    /// `import` writes the entry's password to keepassxc-cli's stdin, so the master password
    /// must be piped there too, and a typed one can only come from pinentry.
    #[error(
        "import cannot ask for the database password on a terminal: keepassxc-cli would read it from the same stdin as the entry's password; use --password-gpg, or run it without a terminal (`! kpx-share import …` in Claude Code), where pinentry asks"
    )]
    TypedPasswordOnTerminal,
    /// keepassxc-cli succeeded but closed the attachment's pipe before reading all of it.
    #[error(
        "{} reported success but did not read the whole attachment",
        tool.display()
    )]
    AttachmentNotRead { tool: PathBuf },
}

/// The database, unlocked once: its XML export, and the key `K` to run keepassxc-cli on it again.
#[derive(Debug)]
pub struct Unlocked<K> {
    pub xml: SecretBytes,
    pub key: K,
}

/// Runs `keepassxc-cli export -f xml` for `request` with the real programs and returns the XML
/// with the key that unlocked it. `session` is the session the entry is for; the password
/// dialog names it.
///
/// # Errors
/// See [`UnlockError`].
pub fn unlock(
    request: &UnlockRequest,
    prompter: &Prompter,
    session: &SessionName,
) -> Result<Unlocked<ShareKey>, UnlockError> {
    let tools = UnlockTools {
        prompter: prompter.clone(),
        ..UnlockTools::production(Mode::Terminal)
    };
    unlock_for_share(&tools, request, session)
}

/// [`unlock`] with the programs in `tools`, for callers that are handed them.
///
/// # Errors
/// See [`UnlockError`].
pub fn unlock_for_share(
    tools: &UnlockTools,
    request: &UnlockRequest,
    session: &SessionName,
) -> Result<Unlocked<ShareKey>, UnlockError> {
    let export = Operation::Share {
        session,
        step: ShareStep::Export,
    };
    let credentials = match (&request.master_key, &tools.prompter) {
        (MasterKey::TypedPassword { .. } | MasterKey::KeyFileOnly { .. }, Prompter::Terminal) => {
            Credentials::OnTerminal
        }
        _ => match acquire(
            tools,
            request,
            &export,
            plan_piped(request, &tools.prompter)?,
        )? {
            Outcome::Done(piped) => Credentials::Piped(piped),
            Outcome::Declined => return Err(UnlockError::Cancelled),
        },
    };
    let held = Held {
        tools: tools.clone(),
        request: request.clone(),
        target: request.database.clone(),
    };
    let xml = held.run(export, credentials.input())?;
    Ok(Unlocked {
        xml,
        key: ShareKey {
            held,
            session: session.clone(),
            credentials,
        },
    })
}

/// Fails the way [`unlock_for_import`] would before asking for anything, when the master key
/// cannot be piped to keepassxc-cli: so `import` can refuse before its confirmation dialog.
///
/// # Errors
/// [`UnlockError::TypedPasswordOnTerminal`].
pub fn check_pipeable(request: &UnlockRequest, prompter: &Prompter) -> Result<(), UnlockError> {
    plan_piped(request, prompter).map(|_source| ())
}

/// Exports `copy`, a copy of `request.database`, for `import` into the entry at `entry`. The
/// dialogs name `request.database`, the database the human knows; every keepassxc-cli run is on
/// `copy`.
///
/// # Errors
/// See [`UnlockError`]; a dialog closed is [`Outcome::Declined`].
pub fn unlock_for_import(
    tools: &UnlockTools,
    request: &UnlockRequest,
    copy: &Path,
    entry: &CliEntryPath,
) -> Result<Outcome<Unlocked<ImportKey>>, UnlockError> {
    let source = plan_piped(request, &tools.prompter)?;
    let export = || Operation::Import {
        entry,
        step: ImportStep::Export,
    };
    let Outcome::Done(credentials) = acquire(tools, request, &export(), source)? else {
        return Ok(Outcome::Declined);
    };
    let held = Held {
        tools: tools.clone(),
        request: request.clone(),
        target: copy.to_owned(),
    };
    let xml = held.run(export(), Input::Piped(&credentials))?;
    Ok(Outcome::Done(Unlocked {
        xml,
        key: ImportKey {
            held,
            entry: entry.clone(),
            credentials,
        },
    }))
}

/// Where a master password that is piped to keepassxc-cli comes from, decided before anything
/// is asked for.
#[derive(Clone, Copy)]
enum PipedSource<'a> {
    /// gpg decrypts this file.
    Decrypt(&'a Path),
    /// This pinentry asks for it.
    Ask(&'a Path),
    /// A key file alone: there is no password.
    Nothing,
}

/// Where the master password comes from when it must be piped. A typed password on a terminal
/// cannot be: only keepassxc-cli itself can prompt there, on the stdin it reads.
fn plan_piped<'a>(
    request: &'a UnlockRequest,
    prompter: &'a Prompter,
) -> Result<PipedSource<'a>, UnlockError> {
    match (&request.master_key, prompter) {
        (MasterKey::EncryptedPassword { file, .. }, _) => Ok(PipedSource::Decrypt(file)),
        (MasterKey::TypedPassword { .. }, Prompter::Pinentry { program }) => {
            Ok(PipedSource::Ask(program))
        }
        (MasterKey::KeyFileOnly { .. }, _) => Ok(PipedSource::Nothing),
        (MasterKey::TypedPassword { .. }, Prompter::Terminal) => {
            Err(UnlockError::TypedPasswordOnTerminal)
        }
    }
}

/// Gets the password `source` names, asking or decrypting once, and announces the `YubiKey`
/// touch the export will need when no password dialog says so.
fn acquire(
    tools: &UnlockTools,
    request: &UnlockRequest,
    export: &Operation<'_>,
    source: PipedSource<'_>,
) -> Result<Outcome<Piped>, UnlockError> {
    let piped = match source {
        PipedSource::Decrypt(file) => {
            let password = decrypt_password(&tools.gpg, file, &tools.prompter)?;
            announce_touch(tools, request, export)?.map(|()| Piped::Password(password))
        }
        PipedSource::Ask(program) => ask_pinentry(program, request, export)?.map(Piped::Password),
        PipedSource::Nothing => {
            announce_touch(tools, request, export)?.map(|()| Piped::NothingToAsk)
        }
    };
    Ok(piped)
}

impl<T> Outcome<T> {
    /// The value done, through `done`; a decline stays one.
    pub fn map<U>(self, done: impl FnOnce(T) -> U) -> Outcome<U> {
        match self {
            Self::Done(value) => Outcome::Done(done(value)),
            Self::Declined => Outcome::Declined,
        }
    }
}

/// For a keepassxc-cli run whose password is piped and whose stderr is captured, says that a
/// `YubiKey` touch is about to be asked for, since keepassxc-cli's own prompt is never seen: on
/// the terminal a line, otherwise a pinentry notice. A typed password's dialog carries the
/// instruction itself (see [`pinentry_description`]) and is not announced again.
fn announce_touch(
    tools: &UnlockTools,
    request: &UnlockRequest,
    operation: &Operation<'_>,
) -> Result<Outcome<()>, UnlockError> {
    match (&tools.prompter, request.yubikey) {
        (Prompter::Pinentry { program }, Some(slot)) => {
            show_touch_notice(program, request, slot, operation)
        }
        (Prompter::Terminal, Some(slot)) => {
            eprintln!("{}", touch_line(request, slot, operation));
            Ok(Outcome::Done(()))
        }
        (_, None) => Ok(Outcome::Done(())),
    }
}

/// What both keys run keepassxc-cli with: the programs, the request (which the dialogs name) and
/// the database file the runs are on.
#[derive(Debug)]
struct Held {
    tools: UnlockTools,
    request: UnlockRequest,
    target: PathBuf,
}

impl Held {
    fn run(&self, operation: Operation<'_>, input: Input<'_>) -> Result<SecretBytes, UnlockError> {
        run(&self.tools, &self.request, &self.target, operation, input)
    }
}

/// What unlocked the database for `add`, kept to run keepassxc-cli on it again: a password asked
/// for or decrypted once is not asked for or decrypted again. Each run still unlocks the
/// database (key derivation, and a `YubiKey` touch when one is configured).
#[derive(Debug)]
pub struct ShareKey {
    held: Held,
    session: SessionName,
    credentials: Credentials,
}

impl ShareKey {
    /// The bytes of attachment `name` of the entry keepassxc-cli finds at `entry`, exactly.
    ///
    /// # Errors
    /// See [`UnlockError`]. A `YubiKey` notice dismissed is [`UnlockError::Cancelled`].
    pub fn export_attachment(
        &self,
        entry: &CliEntryPath,
        name: &str,
    ) -> Result<SecretBytes, UnlockError> {
        let operation = Operation::Share {
            session: &self.session,
            step: ShareStep::AttachmentExport { entry, name },
        };
        match &self.held.tools.prompter {
            // keepassxc-cli runs quiet here (see [`ShareStep::AttachmentExport`]) and so prompts
            // for nothing: this line is the prompt.
            Prompter::Terminal => eprintln!("{}", terminal_prompt(&self.held.request, name)),
            Prompter::Pinentry { .. } => {
                match announce_touch(&self.held.tools, &self.held.request, &operation)? {
                    Outcome::Done(()) => {}
                    Outcome::Declined => return Err(UnlockError::Cancelled),
                }
            }
        }
        self.held.run(operation, self.credentials.input())
    }
}

/// The key `import` holds: every run is on the copy, with the password piped, about the one
/// entry being imported, and each announces the `YubiKey` touch it needs, since keepassxc-cli's
/// own prompt is captured.
#[derive(Debug)]
pub struct ImportKey {
    held: Held,
    entry: CliEntryPath,
    credentials: Piped,
}

/// What a new entry is created with besides its title; absent ones are left empty. Plain values,
/// passed to keepassxc-cli as arguments, and the password, on its stdin.
#[derive(Clone, Copy, Debug)]
pub struct NewEntryFields<'a> {
    pub username: Option<&'a str>,
    pub url: Option<&'a str>,
    pub password: Option<&'a SecretBytes>,
}

impl ImportKey {
    /// The copy's XML export again, to check what was written.
    ///
    /// # Errors
    /// See [`UnlockError`].
    pub fn export_again(&self) -> Result<Outcome<SecretBytes>, UnlockError> {
        self.run(ImportStep::ExportAgain)
    }

    /// The bytes of the entry's attachment `name`, exactly.
    ///
    /// # Errors
    /// See [`UnlockError`].
    pub fn export_attachment(&self, name: &str) -> Result<Outcome<SecretBytes>, UnlockError> {
        self.run(ImportStep::CompareAttachment { name })
    }

    /// Adds the entry to the copy with `fields`; keepassxc-cli refuses when one is at its path.
    ///
    /// # Errors
    /// See [`UnlockError`].
    pub fn add_entry(&self, fields: &NewEntryFields<'_>) -> Result<Outcome<()>, UnlockError> {
        Ok(self.run(ImportStep::AddEntry(fields))?.map(drop))
    }

    /// Adds `content` to the entry as attachment `name`; keepassxc-cli refuses when one of that
    /// name is there.
    ///
    /// # Errors
    /// See [`UnlockError`].
    pub fn import_attachment(
        &self,
        name: &str,
        content: &SecretBytes,
    ) -> Result<Outcome<()>, UnlockError> {
        let feed = AttachmentFeed::open(content).map_err(|source| ToolError::Io {
            tool: self.held.tools.keepassxc_cli.clone(),
            source,
        })?;
        Ok(self
            .run(ImportStep::AttachmentImport { name, feed })?
            .map(drop))
    }

    fn run(&self, step: ImportStep<'_>) -> Result<Outcome<SecretBytes>, UnlockError> {
        let operation = Operation::Import {
            entry: &self.entry,
            step,
        };
        match announce_touch(&self.held.tools, &self.held.request, &operation)? {
            Outcome::Done(()) => {}
            Outcome::Declined => return Ok(Outcome::Declined),
        }
        self.held
            .run(operation, Input::Piped(&self.credentials))
            .map(Outcome::Done)
    }
}

/// How keepassxc-cli is given what it asks for.
#[derive(Debug)]
enum Credentials {
    /// It reads the terminal it inherits, and prompts there unless run with `-q`.
    OnTerminal,
    Piped(Piped),
}

impl Credentials {
    fn input(&self) -> Input<'_> {
        match self {
            Self::OnTerminal => Input::Terminal,
            Self::Piped(piped) => Input::Piped(piped),
        }
    }
}

/// Credentials keepassxc-cli is given on a pipe, its stderr captured.
#[derive(Debug)]
enum Piped {
    /// Written to its stdin as one line.
    Password(SecretBytes),
    /// There is no password: nothing of the master key is written to its stdin.
    NothingToAsk,
}

/// What one keepassxc-cli run reads on its stdin.
#[derive(Clone, Copy)]
enum Input<'a> {
    Terminal,
    Piped(&'a Piped),
}

/// One keepassxc-cli run, with what it is for: a step of `add` sharing into a session, or of
/// `import` into one entry. The reads write their result to keepassxc-cli's stdout; the writes
/// print only chatter there, which is dropped.
enum Operation<'a> {
    Share {
        session: &'a SessionName,
        step: ShareStep<'a>,
    },
    Import {
        entry: &'a CliEntryPath,
        step: ImportStep<'a>,
    },
}

enum ShareStep<'a> {
    /// The whole database as KeePass XML.
    Export,
    /// One attachment's bytes, written to the file `/dev/stdout`. `attachment-export --stdout`
    /// writes through a text stream instead, which does not keep binary bytes as they are. It
    /// runs with `-q`, as otherwise keepassxc-cli also writes "Successfully exported…" to
    /// stdout; that silences its password and `YubiKey` prompts too.
    AttachmentExport {
        entry: &'a CliEntryPath,
        name: &'a str,
    },
}

enum ImportStep<'a> {
    /// The copy as KeePass XML, before anything is written.
    Export,
    /// The copy again, after the writes.
    ExportAgain,
    /// One attachment of the entry, as [`ShareStep::AttachmentExport`] exports it.
    CompareAttachment { name: &'a str },
    /// The new entry, its password (if any) read from stdin after the master password.
    AddEntry(&'a NewEntryFields<'a>),
    /// One attachment, read from the pipe `feed`.
    AttachmentImport {
        name: &'a str,
        feed: AttachmentFeed<'a>,
    },
}

/// What a keepassxc-cli subcommand does, as far as its arguments and stdin go.
enum CliCommand<'a> {
    Export,
    AttachmentExport {
        entry: &'a str,
        name: &'a str,
    },
    Add {
        entry: &'a str,
        fields: &'a NewEntryFields<'a>,
    },
    AttachmentImport {
        entry: &'a str,
        name: &'a str,
        file: String,
    },
}

impl<'a> Operation<'a> {
    /// The subcommand, borrowing only what the operation borrows, so the operation itself can
    /// still give up its attachment pipe.
    fn command(&self) -> CliCommand<'a> {
        match self {
            Self::Share { step, .. } => match step {
                ShareStep::Export => CliCommand::Export,
                ShareStep::AttachmentExport { entry, name } => {
                    let entry: &'a CliEntryPath = entry;
                    CliCommand::AttachmentExport {
                        entry: entry.as_str(),
                        name,
                    }
                }
            },
            Self::Import { entry, step } => {
                let entry: &'a str = entry.as_str();
                match step {
                    ImportStep::Export | ImportStep::ExportAgain => CliCommand::Export,
                    ImportStep::CompareAttachment { name } => {
                        CliCommand::AttachmentExport { entry, name }
                    }
                    ImportStep::AddEntry(fields) => CliCommand::Add { entry, fields },
                    ImportStep::AttachmentImport { name, feed } => CliCommand::AttachmentImport {
                        entry,
                        name,
                        file: feed.path(),
                    },
                }
            }
        }
    }

    /// The attachment's pipe, taken out of the operation once its arguments are built.
    fn into_feed(self) -> Option<AttachmentFeed<'a>> {
        match self {
            Self::Import {
                step: ImportStep::AttachmentImport { feed, .. },
                ..
            } => Some(feed),
            Self::Share { .. }
            | Self::Import {
                step:
                    ImportStep::Export
                    | ImportStep::ExportAgain
                    | ImportStep::CompareAttachment { .. }
                    | ImportStep::AddEntry(_),
                ..
            } => None,
        }
    }
}

/// keepassxc-cli's arguments to do `command` to `target`: the configured database for `add`,
/// the copy for `import`.
fn args(request: &UnlockRequest, target: &Path, command: &CliCommand<'_>) -> Vec<OsString> {
    let mut args: Vec<OsString> = match command {
        CliCommand::Export => ["export", "-f", "xml"].map(Into::into).into(),
        CliCommand::AttachmentExport { .. } => vec!["attachment-export".into(), "-q".into()],
        CliCommand::Add { .. } => vec!["add".into()],
        CliCommand::AttachmentImport { .. } => vec!["attachment-import".into()],
    };
    if matches!(request.master_key, MasterKey::KeyFileOnly { .. }) {
        args.push("--no-password".into());
    }
    if let Some(key_file) = request.master_key.key_file() {
        args.extend(["-k".into(), key_file.into()]);
    }
    if let Some(slot) = request.yubikey {
        args.extend(["-y".into(), slot.argument().into()]);
    }
    if let CliCommand::Add { fields, .. } = command {
        // `--name=value`, so a value starting with `-` is not read as an option.
        let field = |name: &str, value: &str| format!("--{name}={value}").into();
        args.extend(fields.username.map(|value| field("username", value)));
        args.extend(fields.url.map(|value| field("url", value)));
        if fields.password.is_some() {
            args.push("--password-prompt".into());
        }
    }
    // After `--`, so a database path, entry path or attachment name that starts with `-` is not
    // read as an option.
    args.extend(["--".into(), target.into()]);
    match command {
        CliCommand::Export => {}
        CliCommand::AttachmentExport { entry, name } => {
            args.extend([*entry, name, "/dev/stdout"].map(Into::into));
        }
        CliCommand::Add { entry, .. } => args.push((*entry).into()),
        CliCommand::AttachmentImport { entry, name, file } => {
            args.extend([(*entry).into(), (*name).into(), file.into()]);
        }
    }
    args
}

/// What keepassxc-cli reads on its stdin, line by line: the master password, then the new
/// entry's password when one is added.
fn stdin_lines<'a>(input: Input<'a>, command: &CliCommand<'a>) -> Vec<&'a SecretBytes> {
    let master = match input {
        Input::Piped(Piped::Password(password)) => Some(password),
        Input::Piped(Piped::NothingToAsk) | Input::Terminal => None,
    };
    let entry = match command {
        CliCommand::Add { fields, .. } => fields.password,
        CliCommand::Export
        | CliCommand::AttachmentExport { .. }
        | CliCommand::AttachmentImport { .. } => None,
    };
    master.into_iter().chain(entry).collect()
}

fn run(
    tools: &UnlockTools,
    request: &UnlockRequest,
    target: &Path,
    operation: Operation<'_>,
    input: Input<'_>,
) -> Result<SecretBytes, UnlockError> {
    let program = &tools.keepassxc_cli;
    let io_error = |source| ToolError::Io {
        tool: program.clone(),
        source,
    };
    if let Input::Piped(Piped::Password(password)) = input {
        if password.expose().iter().any(|b| matches!(b, b'\n' | b'\r')) {
            return Err(UnlockError::PasswordHasLineBreak);
        }
    }
    let command = operation.command();
    let lines = stdin_lines(input, &command);
    let mut child_command = Command::new(program);
    child_command
        .args(args(request, target, &command))
        .stdout(Stdio::piped());
    match (input, lines.is_empty()) {
        (Input::Terminal, _) => child_command
            .stdin(Stdio::inherit())
            .stderr(Stdio::inherit()),
        (Input::Piped(_), false) => child_command.stdin(Stdio::piped()).stderr(Stdio::piped()),
        (Input::Piped(_), true) => child_command.stdin(Stdio::null()).stderr(Stdio::piped()),
    };
    let attachment_pipe = operation.into_feed();
    if let Some(pipe) = &attachment_pipe {
        pipe.inherit().map_err(io_error)?;
    }
    let spawned = child_command.spawn();
    // The child has its copy of the pipe's read end, or failed to start; either way this
    // process's copy goes now, so the writer sees the pipe close when keepassxc-cli exits.
    let writer = attachment_pipe.map(AttachmentFeed::into_writer);
    let mut child = spawned.map_err(|source| ToolError::Spawn {
        tool: program.clone(),
        source,
    })?;

    let outcome = thread::scope(|scope| {
        let writing = writer.map(|writer| scope.spawn(move || writer.write()));
        let outcome = feed_stdin(&mut child, &lines)
            .and_then(|()| collect_output(&mut child, SecretBytes::read_to_end));
        let written = match writing.map(thread::ScopedJoinHandle::join) {
            None => Ok(Fed::All),
            Some(Ok(written)) => written,
            Some(Err(_panicked)) => Err(io::Error::other("the attachment writer panicked")),
        };
        outcome.and_then(|output| written.map(|taken| (output, taken)))
    });
    // Reaped on every path; a failed read leaves the exit status moot.
    let status = child.wait();
    let ((stdout, stderr), taken) = outcome.map_err(io_error)?;
    let status = status.map_err(io_error)?;
    match (status.success(), taken) {
        (true, Fed::All) => return Ok(stdout),
        (true, Fed::Cut) => {
            return Err(UnlockError::AttachmentNotRead {
                tool: program.clone(),
            });
        }
        // Its exit status and stderr say why.
        (false, Fed::All | Fed::Cut) => {}
    }
    Err(match stderr {
        Stderr::Captured(text) if text.contains(INVALID_CREDENTIALS_MESSAGE) => {
            UnlockError::InvalidCredentials
        }
        stderr => failure(program, status, stderr),
    })
}

/// An attachment on its way to `keepassxc-cli attachment-import`, which reads it from
/// `/dev/fd/<n>`: the read end of a pipe it inherits, fed from memory by a thread, so no
/// plaintext file is ever written.
///
/// Both ends are close-on-exec, as std opens them, except the read end from
/// [`AttachmentFeed::inherit`], just before keepassxc-cli is spawned, until the parent drops it
/// just after: the one descriptor kpx-share lets a child inherit. A process another thread
/// starts in that window inherits it too; kpx-share starts no other process concurrently, so
/// only a test harness running tests in parallel can see it.
struct AttachmentFeed<'a> {
    reader: PipeReader,
    writer: PipeWriter,
    content: &'a SecretBytes,
}

impl<'a> AttachmentFeed<'a> {
    fn open(content: &'a SecretBytes) -> io::Result<Self> {
        let (reader, writer) = io::pipe()?;
        Ok(Self {
            reader,
            writer,
            content,
        })
    }

    /// Lets the next child spawned inherit the read end, at the number [`Self::path`] names.
    fn inherit(&self) -> io::Result<()> {
        rustix::io::fcntl_setfd(&self.reader, rustix::io::FdFlags::empty())?;
        Ok(())
    }

    fn path(&self) -> String {
        format!("/dev/fd/{}", self.reader.as_raw_fd())
    }

    fn into_writer(self) -> FeedWriter<'a> {
        drop(self.reader);
        FeedWriter {
            writer: self.writer,
            content: self.content,
        }
    }
}

/// The write end of an [`AttachmentFeed`], after the spawn.
struct FeedWriter<'a> {
    writer: PipeWriter,
    content: &'a SecretBytes,
}

impl FeedWriter<'_> {
    /// Writes the whole attachment, then closes the pipe so keepassxc-cli reads its end.
    fn write(mut self) -> io::Result<Fed> {
        match self.writer.write_all(self.content.expose()) {
            Ok(()) => Ok(Fed::All),
            Err(error) if error.kind() == io::ErrorKind::BrokenPipe => Ok(Fed::Cut),
            Err(error) => Err(error),
        }
    }
}

/// Whether keepassxc-cli took the whole attachment: it closed the pipe before the last byte
/// ([`Fed::Cut`]) when it failed, which its exit status says, or when it stopped reading early,
/// which nothing else would say.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fed {
    All,
    Cut,
}

/// keepassxc-cli's message for a wrong password, key file or `YubiKey` response (2.8).
const INVALID_CREDENTIALS_MESSAGE: &str = "Invalid credentials were provided";

/// The error for `tool` exiting with `status`, carrying its stderr when that was captured.
fn failure(tool: &Path, status: ExitStatus, stderr: Stderr) -> UnlockError {
    match stderr {
        Stderr::Captured(stderr) => UnlockError::Tool(ToolError::Failed {
            tool: tool.to_owned(),
            status,
            stderr,
        }),
        Stderr::OnTerminal => UnlockError::FailedOnTerminal {
            tool: tool.to_owned(),
            status,
        },
    }
}

/// Writes `lines` to keepassxc-cli's stdin, each followed by a line feed, when there are any.
fn feed_stdin(child: &mut Child, lines: &[&SecretBytes]) -> io::Result<()> {
    if lines.is_empty() {
        return Ok(());
    }
    let mut stdin = take_pipe(child.stdin.take())?;
    // keepassxc-cli may exit without reading them; its exit status says why.
    ignore_broken_pipe(lines.iter().try_for_each(|line| {
        stdin
            .write_all(line.expose())
            .and_then(|()| stdin.write_all(b"\n"))
    }))
}

/// Reads stdout (secret) with `read_stdout` while stderr (diagnostics), when it was piped, is
/// captured concurrently, so neither pipe can fill and stall the child.
fn collect_output(
    child: &mut Child,
    read_stdout: impl FnOnce(ChildStdout) -> io::Result<SecretBytes>,
) -> io::Result<(SecretBytes, Stderr)> {
    let stdout = take_pipe(child.stdout.take())?;
    let stderr = child.stderr.take();
    thread::scope(|scope| {
        let captured = scope.spawn(|| stderr.map(capture_stderr));
        let read = read_stdout(stdout);
        let stderr = match captured.join() {
            Ok(Some(text)) => Stderr::Captured(text),
            // No pipe was asked for: stderr was the terminal's.
            Ok(None) => Stderr::OnTerminal,
            Err(_panicked) => Stderr::Captured(String::new()),
        };
        read.map(|read| (read, stderr))
    })
}

/// The first line of every dialog: which database, and why, so that an unexpected prompt is
/// recognisable: the session an entry is shared into, or the entry `import` adds to.
///
/// With [`Values::Cut`], every value in it is cut to its share of an Assuan line
/// ([`assuan::shortened`]); values within their share are shown whole.
fn unlock_line(request: &UnlockRequest, operation: &Operation<'_>, values: Values) -> String {
    /// Shares, in escaped bytes; with the fixed words, the `YubiKey` instruction and a name's
    /// quoting (which at most doubles it) the line stays far below
    /// [`assuan::SENT_LINE_BYTES_MAX`].
    const DATABASE_SHOWN_MAX: usize = 160;
    const ENTRY_SHOWN_MAX: usize = 160;
    const NAME_SHOWN_MAX: usize = 60;
    let shown = |text: &str, max: usize, keep: assuan::Keep| match values {
        Values::Whole => text.to_owned(),
        Values::Cut => assuan::shortened(text, max, keep),
    };
    let database = shown(
        &request.database.display().to_string(),
        DATABASE_SHOWN_MAX,
        assuan::Keep::End,
    );
    let shown_name = |name: &str| shown(name, NAME_SHOWN_MAX, assuan::Keep::Start);
    match operation {
        Operation::Share { session, step } => {
            let session = session.as_str();
            match step {
                ShareStep::Export => format!(
                    "kpx-share: unlock {database} to share one entry into session {session}"
                ),
                ShareStep::AttachmentExport { name, .. } => format!(
                    "kpx-share: unlock {database} again to export attachment {:?} into session {session}",
                    shown_name(name)
                ),
            }
        }
        Operation::Import { entry, step } => {
            let entry = shown(entry.as_written(), ENTRY_SHOWN_MAX, assuan::Keep::Start);
            match step {
                ImportStep::Export => {
                    format!("kpx-share: unlock {database} to import into entry {entry}")
                }
                ImportStep::ExportAgain => {
                    format!("kpx-share: unlock {database} again to check entry {entry}")
                }
                ImportStep::CompareAttachment { name: attachment } => format!(
                    "kpx-share: unlock {database} again to compare attachment {:?} of entry {entry}",
                    shown_name(attachment)
                ),
                ImportStep::AddEntry(_) => {
                    format!("kpx-share: unlock {database} again to add entry {entry}")
                }
                ImportStep::AttachmentImport {
                    name: attachment, ..
                } => format!(
                    "kpx-share: unlock {database} again to add attachment {:?} to entry {entry}",
                    shown_name(attachment)
                ),
            }
        }
    }
}

/// What the password dialog says: [`unlock_line`] for the export it is asked for, and, when a
/// `YubiKey` slot is configured, that the key must be touched after the password, because
/// without a terminal keepassxc-cli's "please touch your `YubiKey`" is captured and the human
/// never sees it.
fn pinentry_description(request: &UnlockRequest, export: &Operation<'_>) -> String {
    let touch = request
        .yubikey
        .map(|slot| {
            format!(
                "\nAfter the password, touch the YubiKey (slot {}) when it flashes.",
                slot.argument()
            )
        })
        .unwrap_or_default();
    fitted(|values| format!("{}{touch}", unlock_line(request, export, values)))
}

/// How [`unlock_line`] shows the database, the entry and an attachment name.
#[derive(Clone, Copy)]
enum Values {
    Whole,
    /// Each cut to its share of an Assuan line.
    Cut,
}

/// A pinentry text: `build`'s with every value whole, as it always was, unless that would not
/// fit one Assuan line; only then with them cut.
fn fitted(build: impl Fn(Values) -> String) -> String {
    let whole = build(Values::Whole);
    if assuan::description_fits(&whole) {
        whole
    } else {
        build(Values::Cut)
    }
}

/// What is printed on the terminal before an attachment is exported, in place of keepassxc-cli's
/// prompts, which `-q` silences: what to type or touch, if anything.
fn terminal_prompt(request: &UnlockRequest, attachment: &str) -> String {
    let database = request.database.display();
    let password = match request.master_key {
        MasterKey::TypedPassword { .. } => Some("type the password and press Enter".to_owned()),
        // Decrypted once already, and held.
        MasterKey::EncryptedPassword { .. } | MasterKey::KeyFileOnly { .. } => None,
    };
    let touch = request.yubikey.map(|slot| {
        format!(
            "touch the YubiKey (slot {}) when it flashes",
            slot.argument()
        )
    });
    let steps: Vec<String> = password.into_iter().chain(touch).collect();
    let mut prompt =
        format!("kpx-share: unlocking {database} again to export attachment {attachment:?}");
    if !steps.is_empty() {
        prompt.push_str(": ");
        prompt.push_str(&steps.join(", then "));
    }
    prompt
}

/// What the notice says when there is no password dialog to carry the instruction to touch the
/// key `slot` (see [`announce_touch`]).
fn touch_notice(request: &UnlockRequest, slot: YubiKeySlot, operation: &Operation<'_>) -> String {
    fitted(|values| {
        format!(
            "{}\nAfter you press OK, touch the YubiKey (slot {}) when it flashes.",
            unlock_line(request, operation, values),
            slot.argument()
        )
    })
}

/// [`touch_notice`] for the terminal, where there is nothing to press first and no line limit:
/// every value is shown whole.
fn touch_line(request: &UnlockRequest, slot: YubiKeySlot, operation: &Operation<'_>) -> String {
    format!(
        "{}: touch the YubiKey (slot {}) when it flashes",
        unlock_line(request, operation, Values::Whole),
        slot.argument()
    )
}

/// Bound on a decrypted password: anything longer is the wrong file, not a master password.
const ENCRYPTED_PASSWORD_BYTES_MAX: usize = 4096;

/// gpg's arguments to decrypt `file` to stdout: no prompts of its own on the terminal
/// (`--batch`; gpg-agent's pinentry still asks for a card PIN), and no chatter on stderr.
fn gpg_args(file: &Path) -> Vec<OsString> {
    ["--batch", "--quiet", "--decrypt", "--"]
        .map(OsString::from)
        .into_iter()
        .chain([file.into()])
        .collect()
}

/// The password `file` decrypts to, without one trailing line feed, so a file made from
/// `echo pw` holds `pw`. gpg's stderr goes to the terminal under [`Prompter::Terminal`], where
/// it may say what it waits for, and is captured otherwise.
fn decrypt_password(
    gpg: &Path,
    file: &Path,
    prompter: &Prompter,
) -> Result<SecretBytes, UnlockError> {
    let io_error = |source| ToolError::Io {
        tool: gpg.to_owned(),
        source,
    };
    let mut command = Command::new(gpg);
    command
        .args(gpg_args(file))
        .stdin(Stdio::null())
        .stdout(Stdio::piped());
    match prompter {
        Prompter::Terminal => command.stderr(Stdio::inherit()),
        Prompter::Pinentry { .. } => command.stderr(Stdio::piped()),
    };
    let mut child = command.spawn().map_err(|source| ToolError::Spawn {
        tool: gpg.to_owned(),
        source,
    })?;
    let outcome = collect_output(&mut child, read_bounded);
    // Reaped on every path; a failed read leaves the exit status moot.
    let status = child.wait();
    let (mut password, stderr) = outcome.map_err(io_error)?;
    let status = status.map_err(io_error)?;
    if !status.success() {
        return Err(failure(gpg, status, stderr));
    }
    if password.len() > ENCRYPTED_PASSWORD_BYTES_MAX {
        return Err(UnlockError::EncryptedPasswordTooLong {
            file: file.to_owned(),
        });
    }
    if password.expose().ends_with(b"\n") {
        password.truncate(password.len() - 1);
    }
    Ok(password)
}

/// gpg's stdout, up to one byte past [`ENCRYPTED_PASSWORD_BYTES_MAX`], so a longer one is
/// recognised without being kept whole. The rest is drained unread, so gpg never blocks on a
/// full pipe.
fn read_bounded(mut stdout: ChildStdout) -> io::Result<SecretBytes> {
    let limit = u64::try_from(ENCRYPTED_PASSWORD_BYTES_MAX + 1).unwrap_or(u64::MAX);
    let read = SecretBytes::read_to_end(io::Read::take(&mut stdout, limit))?;
    io::copy(&mut stdout, &mut io::sink())?;
    Ok(read)
}

/// Tells the human, in a window, to touch the key `slot`, and returns once they have pressed OK.
fn show_touch_notice(
    program: &Path,
    request: &UnlockRequest,
    slot: YubiKeySlot,
    operation: &Operation<'_>,
) -> Result<Outcome<()>, UnlockError> {
    let description = touch_notice(request, slot, operation);
    with_pinentry(program, |server, client| {
        assuan::message(server, client, "kpx-share", &description)
    })
}

fn ask_pinentry(
    program: &Path,
    request: &UnlockRequest,
    export: &Operation<'_>,
) -> Result<Outcome<SecretBytes>, UnlockError> {
    let description = pinentry_description(request, export);
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
/// succeeded, by killing it when not. A dismissed dialog is [`Outcome::Declined`].
pub(crate) fn with_pinentry<T>(
    program: &Path,
    talk: impl FnOnce(&mut ChildStdout, &mut ChildStdin) -> Result<T, AssuanError>,
) -> Result<Outcome<T>, UnlockError> {
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
    match answer {
        Ok(value) => Ok(Outcome::Done(value)),
        Err(AssuanError::Cancelled) => Ok(Outcome::Declined),
        Err(source) => Err(UnlockError::Pinentry {
            tool: program.to_owned(),
            source,
        }),
    }
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
            master_key: MasterKey::TypedPassword {
                key_file: key_file.map(Into::into),
            },
            yubikey,
        }
    }

    fn session_name() -> SessionName {
        SessionName::parse("claude-0b1c").unwrap()
    }

    fn share<'a>(session: &'a SessionName, step: ShareStep<'a>) -> Operation<'a> {
        Operation::Share { session, step }
    }

    fn export_args(request: &UnlockRequest) -> Vec<String> {
        let session = session_name();
        let operation = share(&session, ShareStep::Export);
        strings(args(request, &request.database, &operation.command()))
    }

    fn strings(args: Vec<OsString>) -> Vec<String> {
        args.into_iter()
            .map(|arg| arg.into_string().unwrap())
            .collect()
    }

    #[test]
    fn args_are_the_database_alone_by_default() {
        assert_eq!(
            export_args(&request(None, None)),
            ["export", "-f", "xml", "--", "db dir/-my.kdbx"]
        );
    }

    #[test]
    fn key_file_and_yubikey_slot_precede_the_database() {
        assert_eq!(
            export_args(&request(Some("/k/key"), Some(YubiKeySlot::Two))),
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
            export_args(&request(None, Some(YubiKeySlot::One))),
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
            export_args(&request),
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
        assert!(
            !export_args(&self::request(Some("/k/key"), None))
                .contains(&"--no-password".to_owned())
        );
    }

    /// The text the human sees when a dialog appears from nowhere: the database, the session it
    /// is for and, only with a `YubiKey` slot configured, the instruction to touch the key.
    #[test]
    fn the_password_dialog_names_the_database_the_session_and_a_yubikey_touch() {
        let session = session_name();
        let export = share(&session, ShareStep::Export);
        assert_eq!(
            pinentry_description(&request(None, None), &export),
            "kpx-share: unlock db dir/-my.kdbx to share one entry into session claude-0b1c"
        );
        assert_eq!(
            pinentry_description(&request(Some("/k"), Some(YubiKeySlot::Two)), &export),
            "kpx-share: unlock db dir/-my.kdbx to share one entry into session claude-0b1c\n\
             After the password, touch the YubiKey (slot 2) when it flashes."
        );
    }

    /// With no password to ask for, the notice is the only place the touch is announced.
    #[test]
    fn the_touch_notice_names_the_database_the_session_and_the_slot() {
        let session = session_name();
        assert_eq!(
            touch_notice(
                &request(None, None),
                YubiKeySlot::One,
                &share(&session, ShareStep::Export)
            ),
            "kpx-share: unlock db dir/-my.kdbx to share one entry into session claude-0b1c\n\
             After you press OK, touch the YubiKey (slot 1) when it flashes."
        );
    }

    /// Each attachment export unlocks the database again, so with a `YubiKey` each needs a touch,
    /// and the notice says which attachment it is for.
    #[test]
    fn an_attachment_export_has_its_own_touch_notice_naming_the_attachment() {
        let entry = CliEntryPath::for_tests("/G/Title");
        let session = session_name();
        assert_eq!(
            touch_notice(
                &request(None, None),
                YubiKeySlot::Two,
                &share(
                    &session,
                    ShareStep::AttachmentExport {
                        entry: &entry,
                        name: "cert.der"
                    }
                )
            ),
            "kpx-share: unlock db dir/-my.kdbx again to export attachment \"cert.der\" into session claude-0b1c\n\
             After you press OK, touch the YubiKey (slot 2) when it flashes."
        );
    }

    /// The attachment's entry path, name and target follow `--`, so a name starting with `-` is
    /// not an option; the target is the file `/dev/stdout`, never `--stdout` (which is not
    /// byte-exact for binary data).
    #[test]
    fn attachment_args_put_the_entry_name_and_target_after_the_database() {
        let entry = CliEntryPath::for_tests("/G x/Title");
        let request = request(Some("/k/key"), None);
        let session = session_name();
        let operation = share(
            &session,
            ShareStep::AttachmentExport {
                entry: &entry,
                name: "-cert.der",
            },
        );
        let args = strings(args(&request, &request.database, &operation.command()));
        assert_eq!(
            args,
            [
                "attachment-export",
                "-q",
                "-k",
                "/k/key",
                "--",
                "db dir/-my.kdbx",
                "/G x/Title",
                "-cert.der",
                "/dev/stdout"
            ]
        );
    }

    #[test]
    fn a_missing_keepassxc_cli_is_a_spawn_error_naming_it() {
        let missing = Path::new("/nonexistent/keepassxc-cli");
        let tools = UnlockTools {
            keepassxc_cli: missing.to_owned(),
            ..UnlockTools::production(Mode::Terminal)
        };
        let error = unlock_for_share(&tools, &request(None, None), &session_name()).unwrap_err();
        assert!(
            matches!(&error, UnlockError::Tool(ToolError::Spawn { tool, .. }) if tool == missing),
            "{error:?}"
        );
        assert!(error.to_string().contains("/nonexistent/keepassxc-cli"));
    }

    #[test]
    fn a_missing_gpg_is_a_spawn_error_naming_it_and_keepassxc_cli_never_runs() {
        let missing = Path::new("/nonexistent/gpg");
        let tools = UnlockTools {
            keepassxc_cli: "/nonexistent/keepassxc-cli".into(),
            gpg: missing.to_owned(),
            prompter: Prompter::Terminal,
        };
        let encrypted = UnlockRequest {
            master_key: MasterKey::EncryptedPassword {
                file: "pw.gpg".into(),
                key_file: None,
            },
            ..request(None, None)
        };
        let error = unlock_for_share(&tools, &encrypted, &session_name()).unwrap_err();
        assert!(
            matches!(&error, UnlockError::Tool(ToolError::Spawn { tool, .. }) if tool == missing),
            "{error:?}"
        );
    }

    #[test]
    fn gpg_decrypts_the_file_after_the_options_without_prompting_itself() {
        let args: Vec<String> = gpg_args(Path::new("-pw.gpg"))
            .into_iter()
            .map(|arg| arg.into_string().unwrap())
            .collect();
        assert_eq!(args, ["--batch", "--quiet", "--decrypt", "--", "-pw.gpg"]);
    }

    #[test]
    fn the_terminal_touch_line_names_the_database_the_session_and_the_slot() {
        let session = session_name();
        let line = touch_line(
            &request(None, Some(YubiKeySlot::Two)),
            YubiKeySlot::Two,
            &share(&session, ShareStep::Export),
        );
        assert_eq!(
            line,
            "kpx-share: unlock db dir/-my.kdbx to share one entry into session claude-0b1c: \
             touch the YubiKey (slot 2) when it flashes"
        );
    }

    #[test]
    fn mode_chooses_the_prompter_and_production_tools_are_absolute() {
        assert_eq!(Prompter::for_mode(Mode::Terminal), Prompter::Terminal);
        assert_eq!(
            UnlockTools::production(Mode::NoTerminal),
            UnlockTools {
                keepassxc_cli: "/usr/bin/keepassxc-cli".into(),
                gpg: "/usr/bin/gpg".into(),
                prompter: Prompter::Pinentry {
                    program: "/usr/bin/pinentry-gnome3".into()
                },
            }
        );
    }

    // --- import ---------------------------------------------------------------------------------

    fn import_entry() -> CliEntryPath {
        CliEntryPath::for_tests("/Ops/-hvac")
    }

    /// Every dialog of an import names the entry, and each run says what it does to it, so a
    /// touch notice for a write is told apart from one for a read. Expected texts written out by
    /// hand. Red when an import's text falls back to add's ("share one entry into session"), or
    /// a step's text names another.
    #[test]
    fn import_dialogs_name_the_entry_and_what_each_run_does() {
        let request = request(None, None);
        let entry = import_entry();
        let fields = NewEntryFields {
            username: None,
            url: None,
            password: None,
        };
        let content = SecretBytes::copy_from(b"x");
        let line = |step| {
            unlock_line(
                &request,
                &Operation::Import {
                    entry: &entry,
                    step,
                },
                Values::Whole,
            )
        };
        let texts = [
            line(ImportStep::Export),
            line(ImportStep::CompareAttachment { name: "a.pem" }),
            line(ImportStep::ExportAgain),
            line(ImportStep::AddEntry(&fields)),
            line(ImportStep::AttachmentImport {
                name: "b.pem",
                feed: AttachmentFeed::open(&content).unwrap(),
            }),
        ];
        assert_eq!(
            texts,
            [
                "kpx-share: unlock db dir/-my.kdbx to import into entry Ops/-hvac",
                "kpx-share: unlock db dir/-my.kdbx again to compare attachment \"a.pem\" of entry Ops/-hvac",
                "kpx-share: unlock db dir/-my.kdbx again to check entry Ops/-hvac",
                "kpx-share: unlock db dir/-my.kdbx again to add entry Ops/-hvac",
                "kpx-share: unlock db dir/-my.kdbx again to add attachment \"b.pem\" to entry Ops/-hvac",
            ]
        );
    }

    /// A new entry's fields are `--name=value` options before `--`, and the password is asked
    /// for (`--password-prompt`) only when one is staged; the entry path follows the copy's
    /// path; an attachment import names the pipe it reads. Red when a value is passed as a
    /// separate argument (a `-` value would be an option), `--password-prompt` is always or
    /// never passed, or the attachment's file is not the pipe.
    #[test]
    fn write_args_pass_fields_as_options_and_the_attachment_as_its_pipe() {
        let entry = import_entry();
        let request = request(None, Some(YubiKeySlot::One));
        let fields = NewEntryFields {
            username: Some("-u x"),
            url: Some("https://h/"),
            password: None,
        };
        let add = Operation::Import {
            entry: &entry,
            step: ImportStep::AddEntry(&fields),
        };
        assert_eq!(
            strings(args(&request, Path::new("/w/db.kdbx"), &add.command())),
            [
                "add",
                "-y",
                "1",
                "--username=-u x",
                "--url=https://h/",
                "--",
                "/w/db.kdbx",
                "/Ops/-hvac"
            ]
        );
        let content = SecretBytes::copy_from(b"x");
        let feed = AttachmentFeed::open(&content).unwrap();
        let pipe = feed.path();
        let import = Operation::Import {
            entry: &entry,
            step: ImportStep::AttachmentImport { name: "-a", feed },
        };
        assert_eq!(
            strings(args(&request, Path::new("/w/db.kdbx"), &import.command())),
            [
                "attachment-import",
                "-y",
                "1",
                "--",
                "/w/db.kdbx",
                "/Ops/-hvac",
                "-a",
                pipe.as_str()
            ]
        );
        assert!(pipe.starts_with("/dev/fd/"), "{pipe}");
    }

    /// keepassxc-cli reads the master password first and the entry's second; with neither
    /// there is nothing on stdin. Red when the order is swapped or a line is dropped.
    #[test]
    fn stdin_carries_the_master_password_then_the_entry_password() {
        let master = Piped::Password(SecretBytes::copy_from(b"master"));
        let entry_password = SecretBytes::copy_from(b"entry");
        let fields = NewEntryFields {
            username: None,
            url: None,
            password: Some(&entry_password),
        };
        let add = CliCommand::Add {
            entry: "/G/T",
            fields: &fields,
        };
        let shown = |lines: Vec<&SecretBytes>| -> Vec<Vec<u8>> {
            lines
                .into_iter()
                .map(|line| line.expose().to_vec())
                .collect()
        };
        assert_eq!(
            shown(stdin_lines(Input::Piped(&master), &add)),
            [b"master".to_vec(), b"entry".to_vec()]
        );
        assert_eq!(
            shown(stdin_lines(Input::Piped(&Piped::NothingToAsk), &add)),
            [b"entry".to_vec()]
        );
        assert_eq!(
            shown(stdin_lines(
                Input::Piped(&Piped::NothingToAsk),
                &CliCommand::Export
            )),
            [] as [Vec<u8>; 0]
        );
    }

    /// `add`'s texts are main's (467e785), byte for byte, whenever they fit one Assuan line: a
    /// 200-byte database path and a 100-byte attachment name are shown whole in the password
    /// dialog, the touch notice and the terminal touch line. The expected texts are main's format
    /// strings, filled in. Red when a value is cut that fits.
    #[test]
    fn add_texts_are_mains_while_they_fit() {
        let database = format!("/{}.kdbx", "d".repeat(194));
        assert_eq!(database.len(), 200);
        let request = UnlockRequest {
            database: PathBuf::from(&database),
            ..request(None, Some(YubiKeySlot::Two))
        };
        let name = "n".repeat(100);
        let entry = CliEntryPath::for_tests("/G/T");
        let session = session_name();
        let export = share(&session, ShareStep::Export);
        let attachment = share(
            &session,
            ShareStep::AttachmentExport {
                entry: &entry,
                name: &name,
            },
        );
        let export_line =
            format!("kpx-share: unlock {database} to share one entry into session claude-0b1c");
        let attachment_line = format!(
            "kpx-share: unlock {database} again to export attachment {name:?} into session claude-0b1c"
        );
        assert_eq!(
            pinentry_description(&request, &export),
            format!(
                "{export_line}\nAfter the password, touch the YubiKey (slot 2) when it flashes."
            )
        );
        for (operation, line) in [(&export, &export_line), (&attachment, &attachment_line)] {
            assert_eq!(
                touch_notice(&request, YubiKeySlot::Two, operation),
                format!("{line}\nAfter you press OK, touch the YubiKey (slot 2) when it flashes.")
            );
            assert_eq!(
                touch_line(&request, YubiKeySlot::Two, operation),
                format!("{line}: touch the YubiKey (slot 2) when it flashes")
            );
        }
    }

    /// The terminal touch line has no line limit and is never cut. Red when it is.
    #[test]
    fn the_terminal_touch_line_shows_every_value_whole() {
        let database = format!("/{}", "d".repeat(4000));
        let request = UnlockRequest {
            database: PathBuf::from(&database),
            ..request(None, Some(YubiKeySlot::Two))
        };
        let session = session_name();
        let line = touch_line(
            &request,
            YubiKeySlot::Two,
            &share(&session, ShareStep::Export),
        );
        assert!(line.contains(&database), "{line}");
    }

    /// Long values (a 4000-byte database path and entry path, a 1000-byte attachment name, as a
    /// database may hold for `add`) still give touch notices and the password dialog within one
    /// Assuan line, for every step; all are `%`, which escapes to three bytes, and a name of
    /// quotes, which `{:?}` doubles, is shown too. Red when a value is shown uncut.
    #[test]
    fn every_dialog_fits_one_assuan_line_whatever_it_names() {
        let escaped_len = |text: &str| -> usize {
            text.chars()
                .map(|ch| match ch {
                    '%' | '\r' | '\n' => 3,
                    ch => ch.len_utf8(),
                })
                .sum()
        };
        let request = UnlockRequest {
            database: PathBuf::from("/").join("%".repeat(4000)),
            ..request(None, Some(YubiKeySlot::Two))
        };
        let entry = CliEntryPath::for_tests(&format!("/G/{}", "%".repeat(4000)));
        let name = format!("{}{}", "\"".repeat(100), "%".repeat(1000));
        let content = SecretBytes::copy_from(b"x");
        let fields = NewEntryFields {
            username: None,
            url: None,
            password: None,
        };
        let session = session_name();
        let operations = [
            share(
                &session,
                ShareStep::AttachmentExport {
                    entry: &entry,
                    name: &name,
                },
            ),
            Operation::Import {
                entry: &entry,
                step: ImportStep::Export,
            },
            Operation::Import {
                entry: &entry,
                step: ImportStep::CompareAttachment { name: &name },
            },
            Operation::Import {
                entry: &entry,
                step: ImportStep::AddEntry(&fields),
            },
            Operation::Import {
                entry: &entry,
                step: ImportStep::AttachmentImport {
                    name: &name,
                    feed: AttachmentFeed::open(&content).unwrap(),
                },
            },
        ];
        for operation in &operations {
            for text in [
                touch_notice(&request, YubiKeySlot::Two, operation),
                pinentry_description(&request, operation),
            ] {
                let line = escaped_len(&format!("SETDESC {text}\n"));
                assert!(line <= assuan::SENT_LINE_BYTES_MAX, "{line}: {text}");
            }
        }
    }

    /// The attachment pipe's read end is close-on-exec until just before keepassxc-cli is
    /// spawned, so a pinentry notice shown first does not inherit it. Red when `open` clears the
    /// flag itself.
    #[test]
    fn the_attachment_pipe_is_inheritable_only_once_asked() {
        let content = SecretBytes::copy_from(b"x");
        let feed = AttachmentFeed::open(&content).unwrap();
        let flags = || rustix::io::fcntl_getfd(&feed.reader).unwrap();
        assert!(flags().contains(rustix::io::FdFlags::CLOEXEC));
        feed.inherit().unwrap();
        assert!(!flags().contains(rustix::io::FdFlags::CLOEXEC));
        assert!(
            rustix::io::fcntl_getfd(&feed.writer)
                .unwrap()
                .contains(rustix::io::FdFlags::CLOEXEC)
        );
    }

    /// Only a typed password on a terminal cannot be piped; everything else can, in either mode.
    /// Red when `check_pipeable` accepts it, or refuses another combination.
    #[test]
    fn only_a_typed_password_on_a_terminal_cannot_be_piped() {
        let pinentry = Prompter::Pinentry {
            program: "/p".into(),
        };
        let typed = request(None, None);
        let encrypted = UnlockRequest {
            master_key: MasterKey::EncryptedPassword {
                file: "pw.gpg".into(),
                key_file: None,
            },
            ..request(None, None)
        };
        let key_only = UnlockRequest {
            master_key: MasterKey::KeyFileOnly {
                key_file: "/k".into(),
            },
            ..request(None, None)
        };
        assert!(matches!(
            check_pipeable(&typed, &Prompter::Terminal),
            Err(UnlockError::TypedPasswordOnTerminal)
        ));
        for (request, prompter) in [
            (&typed, &pinentry),
            (&encrypted, &Prompter::Terminal),
            (&encrypted, &pinentry),
            (&key_only, &Prompter::Terminal),
            (&key_only, &pinentry),
        ] {
            assert!(check_pipeable(request, prompter).is_ok(), "{request:?}");
        }
    }
}
