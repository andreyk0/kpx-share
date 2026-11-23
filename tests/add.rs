//! `add` end to end: the real `keepassxc-cli` on a throwaway KDBX, fake pinentry and picker
//! programs (bash scripts), a scratch share root on tmpfs, and the command functions of
//! `kpx_share::cli` driven with in-memory output.
//!
//! The real pinentry, fzf and fuzzel are never run. The watcher is either a recording fake, the
//! real `kpx-share watch` run as a child process, or (once) the real `systemd-run --user`.
//! Each test's doc comment names the mutation that turns it red. Needs `keepassxc-cli`, bash and
//! `sleep`; without them these tests fail, never skip.
//!
//! All scripts and the database are created once, before any test spawns a process (`ETXTBSY`).

mod common;

use std::cell::RefCell;
use std::collections::VecDeque;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;
use std::thread;
use std::time::{Duration, Instant};

use clap::{CommandFactory, FromArgMatches};
use common::fakes::{fuzzel_choosing, pinentry, runs, was_invoked, write_script};
use common::process::{Sleeper, this_process};
use common::share::scratch_on_tmpfs;
use common::{document, entry, string, uuid_hex};
use kpx_share::add::{AddTools, Where};
use kpx_share::cli::{Cli, Command as Subcommand, Exit, Io, add_command, ls_command, rm_command};
use kpx_share::launch::{Launch, SystemdRun, WatcherLauncher, WatcherSpec};
use kpx_share::layout::{SessionDir, ShareRoot};
use kpx_share::mode::Mode;
use kpx_share::pick::Picker;
use kpx_share::session::{Binding, Session, Ttl, read_record};
use kpx_share::subprocess::ToolError;
use kpx_share::tools;
use kpx_share::unlock::{Prompter, UnlockTools};
use tempfile::TempDir;

/// In every secret field of the database, so one search finds a leak anywhere.
const MARKER: &str = "kpxmark-9f3c1a";
const PASSWORD: &str = "pw";
/// The password the leaky pinentry answers, which no database takes.
const LEAKY_PASSWORD: &str = "leaky-pass-5d1e";
const KPX_SHARE: &str = env!("CARGO_BIN_EXE_kpx-share");

// --- Fixtures ---------------------------------------------------------------------------------

struct Fixtures {
    db: PathBuf,
    /// Answers `pw`. One copy per test that asks whether it ran, as tests run in parallel.
    pinentry_shared: PathBuf,
    pinentry_before_tmpfs: PathBuf,
    pinentry_launch_fails: PathBuf,
    pinentry_cancelled: PathBuf,
    pinentry_leaky: PathBuf,
    /// A database protected by `key_file` alone, and the key file.
    key_file_only_db: PathBuf,
    key_file: PathBuf,
    /// Never to run: the database it is offered for has no password.
    pinentry_not_wanted: PathBuf,
    /// A keepassxc-cli that prints the start of a document holding `MARKER` and fails.
    keepassxc_failing: PathBuf,
    /// Chooses the first of the entries it is offered.
    fuzzel_shared: PathBuf,
    fuzzel_asked: PathBuf,
    /// A KDBX 4 database (password `pw`) with one tagged entry, `Certs/mqtt broker`, carrying
    /// [`KDBX4_ATTACHMENTS`]; and a pinentry for it alone, so its dialogs can be counted.
    kdbx4_db: PathBuf,
    pinentry_kdbx4: PathBuf,
    /// A gpg home of its own, whose wrapper counts its runs; `pw` encrypted to its key; and a
    /// pinentry that must never run when the password is decrypted instead.
    gpg: common::gpg::ThrowawayGpg,
    gpg_pw: PathBuf,
    pinentry_gpg_unused: PathBuf,
}

/// Binary bytes that a text stream would not carry unchanged, an empty file, and a name that
/// starts with `-`.
fn kdbx4_attachments() -> [(&'static str, Vec<u8>); 3] {
    [
        ("cert.der", (0..=255).cycle().take(768).collect()),
        ("empty.txt", Vec::new()),
        (
            "-client.key",
            b"-----BEGIN KEY-----\r\nno newline at the end".to_vec(),
        ),
    ]
}

/// Writes the KDBX 4 fixture. An entry's `CustomData` is what makes keepassxc-cli save KDBX 4
/// rather than 3.1; the header's version is checked, as the tests mean nothing on 3.1.
fn create_kdbx4_db(dir: &Path) -> PathBuf {
    use base64::Engine;
    let encode = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);
    let attachments = kdbx4_attachments();
    let (binaries, references): (Vec<String>, Vec<String>) = attachments
        .iter()
        .enumerate()
        .map(|(id, (name, bytes))| {
            (
                format!(r#"<Binary ID="{id}">{}</Binary>"#, encode(bytes)),
                format!(r#"<Binary><Key>{name}</Key><Value Ref="{id}"/></Binary>"#),
            )
        })
        .unzip();
    let (binaries, references) = (binaries.concat(), references.concat());
    let custom_data =
        "<CustomData><Item><Key>kpx-share-test</Key><Value>KDBX 4</Value></Item></CustomData>";
    let body = format!(
        "<Group><UUID>BwcHBwcHBwcHBwcHBwcHBw==</UUID><Name>Certs</Name>{}</Group>",
        entry(
            0x21,
            &[
                string("Title", "mqtt broker"),
                string("Password", &format!("{MARKER}-mqtt")),
                "<Tags>agent</Tags>".to_owned(),
                custom_data.to_owned(),
                references,
            ]
            .concat()
        )
    );
    let xml = dir.join("kdbx4.xml");
    fs::write(
        &xml,
        document(&format!("<Binaries>{binaries}</Binaries>"), &body),
    )
    .unwrap();
    let db = dir.join("kdbx4.kdbx");
    common::create_kdbx_from_xml(&xml, &db, PASSWORD, None);
    let header = fs::read(&db).unwrap();
    assert_eq!(&header[8..12], [0, 0, 4, 0], "the fixture must be KDBX 4.0");
    db
}

fn fixtures() -> &'static Fixtures {
    static FIXTURES: OnceLock<Fixtures> = OnceLock::new();
    FIXTURES.get_or_init(|| {
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("add-fixtures");
        let _absent_is_fine = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let tagged = "<Tags>agent</Tags>";
        let entries = [
            entry(
                1,
                &[
                    string("Title", "Alpha login"),
                    string("UserName", &format!("{MARKER}-user")),
                    string("Password", &format!("{MARKER}-pw")),
                    string("URL", &format!("https://{MARKER}.example")),
                    string("Notes", &format!("{MARKER}-notes")),
                    string("API key", &format!("{MARKER}-api")),
                    tagged.to_owned(),
                ]
                .concat(),
            ),
            entry(
                2,
                &[
                    string("Title", "Beta untagged"),
                    string("Password", &format!("{MARKER}-untagged")),
                ]
                .concat(),
            ),
            entry(
                3,
                &[
                    string("Title", "Gamma target"),
                    string("Password", &format!("{MARKER}-ref-target")),
                    tagged.to_owned(),
                ]
                .concat(),
            ),
            entry(
                4,
                &[
                    string("Title", &format!("{{REF:P@I:{}}}", uuid_hex(3))),
                    tagged.to_owned(),
                ]
                .concat(),
            ),
        ]
        .concat();
        let xml = dir.join("db.xml");
        fs::write(&xml, document("", &entries)).unwrap();
        let db = dir.join("db.kdbx");
        common::create_kdbx_from_xml(&xml, &db, PASSWORD, None);
        let key_file = dir.join("db.key");
        fs::write(&key_file, "not a real key, throwaway\n").unwrap();
        let key_file_only_db = dir.join("keyed-only.kdbx");
        common::create_key_file_only_kdbx(&xml, &key_file_only_db, &key_file);
        let gpg = common::gpg::ThrowawayGpg::create(&dir);

        Fixtures {
            db,
            pinentry_shared: pinentry(&dir, "pinentry-shared", &["D pw", "OK"]),
            pinentry_before_tmpfs: pinentry(&dir, "pinentry-before-tmpfs", &["D pw", "OK"]),
            pinentry_launch_fails: pinentry(&dir, "pinentry-launch-fails", &["D pw", "OK"]),
            pinentry_cancelled: pinentry(
                &dir,
                "pinentry-cancelled",
                &["ERR 83886179 Operation cancelled <Pinentry>"],
            ),
            key_file_only_db,
            key_file,
            pinentry_not_wanted: pinentry(&dir, "pinentry-not-wanted", &["D pw", "OK"]),
            pinentry_leaky: pinentry(
                &dir,
                "pinentry-leaky",
                &[&format!("D {LEAKY_PASSWORD}"), "OK"],
            ),
            keepassxc_failing: write_script(
                &dir,
                "keepassxc-failing",
                &format!(
                    "cat >/dev/null\n\
                     printf '<KeePassFile><Entry><String><Key>Password</Key><Value>{MARKER}-pw</Value>'\n\
                     echo 'simulated failure' >&2\n\
                     exit 3\n"
                ),
            ),
            fuzzel_shared: fuzzel_choosing(&dir, "fuzzel-shared", 0),
            fuzzel_asked: fuzzel_choosing(&dir, "fuzzel-asked", 0),
            kdbx4_db: create_kdbx4_db(&dir),
            pinentry_kdbx4: pinentry(&dir, "pinentry-kdbx4", &["D pw", "OK"]),
            gpg_pw: {
                let file = dir.join("pw.gpg");
                gpg.encrypt(b"pw\n", &file);
                file
            },
            gpg,
            pinentry_gpg_unused: pinentry(&dir, "pinentry-gpg-unused", &["D x", "OK"]),
        }
    })
}

// --- Launchers --------------------------------------------------------------------------------

/// What the session directory looked like when the watcher was asked for.
#[derive(Debug)]
struct Launched {
    session_existed: bool,
    entries_then: usize,
}

/// What a [`Recording`] launcher answers a request with.
#[derive(Clone, Copy, Debug)]
enum Answer {
    Launched(Launch),
    CannotStart,
}

fn cannot_start() -> ToolError {
    ToolError::Spawn {
        tool: PathBuf::from("/usr/bin/systemd-run"),
        source: io::Error::other("no user manager"),
    }
}

/// Records each request, then answers the next of `answers` (`Started` once they run out).
#[derive(Debug, Default)]
struct Recording {
    requests: RefCell<Vec<Launched>>,
    answers: RefCell<VecDeque<Answer>>,
}

impl Recording {
    fn answering(answers: &[Answer]) -> Self {
        Self {
            requests: RefCell::default(),
            answers: RefCell::new(answers.iter().copied().collect()),
        }
    }
}

impl WatcherLauncher for Recording {
    fn ensure_running(&self, spec: &WatcherSpec<'_>) -> Result<Launch, ToolError> {
        let dir = SessionDir::find(spec.root, spec.session).unwrap();
        self.requests.borrow_mut().push(Launched {
            session_existed: dir.is_some(),
            entries_then: dir.map_or(0, |dir| dir.entries_among_strangers().unwrap().len()),
        });
        match self.answers.borrow_mut().pop_front() {
            None | Some(Answer::Launched(Launch::Started)) => Ok(Launch::Started),
            Some(Answer::Launched(Launch::AlreadyRunning)) => Ok(Launch::AlreadyRunning),
            Some(Answer::CannotStart) => Err(cannot_start()),
        }
    }
}

#[derive(Debug)]
struct Failing;

impl WatcherLauncher for Failing {
    fn ensure_running(&self, _spec: &WatcherSpec<'_>) -> Result<Launch, ToolError> {
        Err(cannot_start())
    }
}

/// Runs the real `kpx-share watch` as a child process, without systemd; one per launcher, as
/// systemd runs one unit per session.
#[derive(Debug, Default)]
struct DirectChild(RefCell<Vec<Child>>);

impl WatcherLauncher for DirectChild {
    fn ensure_running(&self, spec: &WatcherSpec<'_>) -> Result<Launch, ToolError> {
        if !self.0.borrow().is_empty() {
            return Ok(Launch::AlreadyRunning);
        }
        let child = Command::new(KPX_SHARE)
            .args(spec.args())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|source| ToolError::Spawn {
                tool: KPX_SHARE.into(),
                source,
            })?;
        self.0.borrow_mut().push(child);
        Ok(Launch::Started)
    }
}

impl Drop for DirectChild {
    fn drop(&mut self) {
        for child in self.0.get_mut() {
            let _already_gone = child.kill();
            let _reaped = child.wait();
        }
    }
}

// --- Driving the commands ---------------------------------------------------------------------

/// A scratch `XDG_RUNTIME_DIR` on tmpfs and the session this test is in.
struct Setting {
    runtime: TempDir,
    binding: Binding,
}

impl Setting {
    fn new() -> Self {
        Self::bound_to(Binding::ParentShell {
            watched: this_process(),
        })
    }

    fn bound_to(binding: Binding) -> Self {
        Self {
            runtime: scratch_on_tmpfs(),
            binding,
        }
    }

    fn at(&self) -> Where<'_> {
        Where {
            runtime_dir: Some(self.runtime.path().as_os_str()),
            binding: &self.binding,
        }
    }

    fn session_path(&self) -> PathBuf {
        self.runtime
            .path()
            .join("kpx-share")
            .join(self.binding.name().as_str())
    }
}

struct Run {
    exit: Exit,
    stdout: String,
    stderr: String,
}

fn tools_with<'a>(
    pinentry: &Path,
    fuzzel: &Path,
    launcher: &'a dyn WatcherLauncher,
) -> AddTools<'a> {
    AddTools {
        unlock: UnlockTools {
            prompter: Prompter::Pinentry {
                program: pinentry.to_owned(),
            },
            ..UnlockTools::production(Mode::NoTerminal)
        },
        picker: Picker::Fuzzel {
            program: fuzzel.to_owned(),
        },
        launcher,
    }
}

fn capture(command: impl FnOnce(&mut Io<'_>) -> Exit) -> Run {
    let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
    let exit = command(&mut Io {
        out: &mut stdout,
        err: &mut stderr,
    });
    Run {
        exit,
        stdout: String::from_utf8(stdout).unwrap(),
        stderr: String::from_utf8(stderr).unwrap(),
    }
}

/// Parses `argv` as the binary does, minus every argument's environment variable, so a developer's
/// own `KPX_SHARE_DB` or `KPX_SHARE_KEY_FILE` cannot change what a test runs. clap reads the
/// environment while parsing, and removing the variables from this process would race the tests
/// running beside it.
fn parse(argv: &[&str]) -> Cli {
    fn without_env(command: clap::Command) -> clap::Command {
        let args: Vec<_> = command
            .get_arguments()
            .map(|arg| arg.get_id().clone())
            .collect();
        let command = args.into_iter().fold(command, |command, id| {
            command.mut_arg(id, |arg| arg.env(None))
        });
        let subcommands: Vec<_> = command
            .get_subcommands()
            .map(|subcommand| subcommand.get_name().to_owned())
            .collect();
        subcommands.into_iter().fold(command, |command, name| {
            command.mut_subcommand(name, without_env)
        })
    }
    let matches = without_env(Cli::command())
        .try_get_matches_from(argv)
        .unwrap();
    Cli::from_arg_matches(&matches).unwrap()
}

fn add_args(db: &Path, rest: &[&str]) -> kpx_share::cli::AddArgs {
    let mut argv = vec!["kpx-share", "add", "--db", db.to_str().unwrap()];
    argv.extend_from_slice(rest);
    match parse(&argv).command {
        Subcommand::Add(parsed) => parsed,
        other => panic!("{other:?}"),
    }
}

fn run_add(setting: &Setting, tools: &AddTools<'_>, rest: &[&str]) -> Run {
    run_add_db(setting, tools, &fixtures().db, rest)
}

fn run_add_db(setting: &Setting, tools: &AddTools<'_>, db: &Path, rest: &[&str]) -> Run {
    let args = add_args(db, rest);
    capture(|io| add_command(args, setting.at(), tools, io))
}

fn run_ls(setting: &Setting) -> Run {
    capture(|io| ls_command(setting.at(), io))
}

/// Every path below `dir`, and what every file in it holds, as one string.
fn everything_in(dir: &Path) -> String {
    fn walk(dir: &Path, out: &mut String) {
        for item in fs::read_dir(dir).unwrap() {
            let path = item.unwrap().path();
            out.push_str(&path.display().to_string());
            out.push('\n');
            if path.is_dir() {
                walk(&path, out);
            } else {
                out.push_str(&String::from_utf8_lossy(&fs::read(&path).unwrap()));
                out.push('\n');
            }
        }
    }
    let mut out = String::new();
    walk(dir, &mut out);
    out
}

fn wait_until(limit: Duration, mut done: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        if done() {
            return true;
        }
        thread::sleep(Duration::from_millis(50));
    }
    done()
}

// --- Output (I7) and what is written (I2) -----------------------------------------------------

/// A KDBX 4 export names attachments without their bytes, so they are exported one at a time,
/// with the password asked for once, and written byte for byte. Red when they are exported with
/// `--stdout` (the binary file changes), when an attachment is looked up by anything but the
/// entry's path, when `--` is missing (the `-` name is read as an option), or when the password
/// dialog is shown again for each attachment.
#[test]
fn a_kdbx4_entrys_attachments_are_exported_byte_for_byte_with_one_password_dialog() {
    let fixtures = fixtures();
    let setting = Setting::new();
    let launcher = Recording::default();
    let tools = tools_with(&fixtures.pinentry_kdbx4, &fixtures.fuzzel_shared, &launcher);

    let run = run_add_db(&setting, &tools, &fixtures.kdbx4_db, &["mqtt"]);

    assert_eq!(run.exit, Exit::Success, "{}", run.stderr);
    let entry_dir = PathBuf::from(run.stdout.trim_end());
    let meta: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(entry_dir.join("meta.json")).unwrap()).unwrap();
    for (name, bytes) in kdbx4_attachments() {
        let file = meta["attachments"][name].as_str().unwrap();
        assert_eq!(fs::read(entry_dir.join(file)).unwrap(), bytes, "{name}");
    }
    assert_eq!(runs(&fixtures.pinentry_kdbx4), 1);
}

/// `--password-gpg`: the password is decrypted once and held for the export and every
/// attachment after it, so a `YubiKey` that must be touched to decrypt is touched once per add;
/// no password dialog is shown. Red when the flag is not passed on (the dialog runs), or when
/// the password is decrypted again for each attachment (gpg runs four times).
#[test]
fn an_encrypted_password_is_decrypted_once_for_the_export_and_every_attachment() {
    let fixtures = fixtures();
    let setting = Setting::new();
    let launcher = Recording::default();
    let mut tools = tools_with(
        &fixtures.pinentry_gpg_unused,
        &fixtures.fuzzel_shared,
        &launcher,
    );
    tools.unlock.gpg = fixtures.gpg.wrapper.clone();
    let password_gpg = fixtures.gpg_pw.to_str().unwrap();

    let run = run_add_db(
        &setting,
        &tools,
        &fixtures.kdbx4_db,
        &["--password-gpg", password_gpg, "mqtt"],
    );

    assert_eq!(run.exit, Exit::Success, "{}", run.stderr);
    let entry_dir = PathBuf::from(run.stdout.trim_end());
    let meta: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(entry_dir.join("meta.json")).unwrap()).unwrap();
    assert_eq!(
        meta["attachments"].as_object().unwrap().len(),
        kdbx4_attachments().len()
    );
    assert_eq!(runs(&fixtures.gpg.wrapper), 1);
    assert_eq!(runs(&fixtures.pinentry_gpg_unused), 0);
}

/// Red when anything but the entry path reaches stdout (the `--any` notice or a field value
/// printed there), or when a field value reaches stderr.
#[test]
fn the_only_stdout_is_the_entry_path_and_no_secret_is_printed() {
    let fixtures = fixtures();
    let setting = Setting::new();
    let launcher = Recording::default();
    let tools = tools_with(
        &fixtures.pinentry_shared,
        &fixtures.fuzzel_shared,
        &launcher,
    );

    let run = run_add(&setting, &tools, &["--any", "alpha"]);

    assert_eq!(run.exit, Exit::Success, "{}", run.stderr);
    let entry_dir = setting.session_path().join("Alpha_login");
    assert_eq!(run.stdout, format!("{}\n", entry_dir.display()));
    assert!(
        run.stderr.contains("--any"),
        "the notice goes to stderr: {}",
        run.stderr
    );
    // The scratch directory's name is random and may spell the two-letter password.
    let runtime = setting.runtime.path().to_str().unwrap();
    for shown in [&run.stdout, &run.stderr] {
        assert!(!shown.contains(MARKER), "{shown}");
        assert!(!shown.replace(runtime, "").contains(PASSWORD), "{shown}");
    }
    assert_eq!(
        fs::read_to_string(entry_dir.join("password")).unwrap(),
        format!("{MARKER}-pw")
    );
}

/// `--no-password --key-file`: a database with a key file and no password is added from with no
/// password dialog at all. Red when the dialog is shown, or `--no-password` is not passed on.
#[test]
fn a_key_file_only_database_is_added_from_without_a_password_dialog() {
    let fixtures = fixtures();
    let setting = Setting::new();
    let launcher = Recording::default();
    let tools = tools_with(
        &fixtures.pinentry_not_wanted,
        &fixtures.fuzzel_shared,
        &launcher,
    );
    let key_file = fixtures.key_file.to_str().unwrap();

    let run = run_add_db(
        &setting,
        &tools,
        &fixtures.key_file_only_db,
        &["--key-file", key_file, "--no-password", "alpha"],
    );

    assert_eq!(run.exit, Exit::Success, "{}", run.stderr);
    assert!(!was_invoked(&fixtures.pinentry_not_wanted));
    assert_eq!(
        fs::read_to_string(setting.session_path().join("Alpha_login/password")).unwrap(),
        format!("{MARKER}-pw")
    );
}

/// I7 through the command, on the path where keepassxc-cli fails in a way it does not recognise
/// after printing part of the decrypted document: its complaint reaches stderr, and neither the
/// password it was given nor the document reaches stdout or stderr. Red when the password or its
/// stdout is added to the failure's text.
#[test]
fn a_keepassxc_cli_that_fails_after_partial_output_leaks_nothing_to_stdout_or_stderr() {
    let fixtures = fixtures();
    let setting = Setting::new();
    let launcher = Recording::default();
    let mut tools = tools_with(&fixtures.pinentry_leaky, &fixtures.fuzzel_shared, &launcher);
    tools.unlock.keepassxc_cli = fixtures.keepassxc_failing.clone();

    let run = run_add(&setting, &tools, &["alpha"]);

    assert_eq!(run.exit, Exit::Failure);
    assert_eq!(run.stdout, "");
    assert!(run.stderr.contains("simulated failure"), "{}", run.stderr);
    for shown in [&run.stdout, &run.stderr] {
        assert!(!shown.contains(LEAKY_PASSWORD), "{shown}");
        assert!(!shown.contains(MARKER), "{shown}");
    }
    assert!(!everything_in(&setting.session_path()).contains(MARKER));
}

/// Red when the tag rule is not applied: with `Eligibility::Any` in its place the untagged entry
/// is found and written.
#[test]
fn an_untagged_entry_is_not_shared_without_any() {
    let fixtures = fixtures();
    let setting = Setting::new();
    let launcher = Recording::default();
    let tools = tools_with(
        &fixtures.pinentry_shared,
        &fixtures.fuzzel_shared,
        &launcher,
    );

    let run = run_add(&setting, &tools, &["beta"]);

    assert_eq!(run.exit, Exit::Failure);
    assert_eq!(run.stdout, "");
    assert!(
        run.stderr.starts_with("kpx-share: no entry matches"),
        "{}",
        run.stderr
    );
    let on_disk = everything_in(&setting.session_path());
    assert!(!on_disk.contains(MARKER), "{on_disk}");
    assert!(!on_disk.contains("Beta"), "{on_disk}");
    assert_eq!(
        SessionDir::find(
            &ShareRoot::in_runtime_dir(setting.at().runtime_dir).unwrap(),
            &setting.binding.name()
        )
        .unwrap()
        .unwrap()
        .entries()
        .unwrap()
        .len(),
        0
    );
}

#[test]
fn any_shares_an_untagged_entry_and_a_custom_tag_changes_the_rule() {
    let fixtures = fixtures();
    let launcher = Recording::default();
    let tools = tools_with(
        &fixtures.pinentry_shared,
        &fixtures.fuzzel_shared,
        &launcher,
    );

    let with_any = Setting::new();
    let run = run_add(&with_any, &tools, &["--any", "beta"]);
    assert_eq!(run.exit, Exit::Success, "{}", run.stderr);
    assert!(with_any.session_path().join("Beta_untagged").exists());

    let wrong_tag = Setting::new();
    let run = run_add(&wrong_tag, &tools, &["--tag", "ops", "alpha"]);
    assert_eq!(run.exit, Exit::Failure, "{}", run.stderr);
    assert!(!wrong_tag.session_path().join("Alpha_login").exists());
}

/// A title that resolves to another entry's password names nothing: not the directory, not
/// `ls`, not `meta.json`; only the `title` file holds the resolved value. Red when the slug or
/// the meta path is derived from the resolved title.
#[test]
fn a_title_that_is_a_reference_to_a_password_leaks_into_no_name() {
    let fixtures = fixtures();
    let setting = Setting::new();
    let launcher = Recording::default();
    let tools = tools_with(
        &fixtures.pinentry_shared,
        &fixtures.fuzzel_shared,
        &launcher,
    );

    let run = run_add(&setting, &tools, &["ref"]);
    assert_eq!(run.exit, Exit::Success, "{}", run.stderr);
    let listing = run_ls(&setting);

    let session = setting.session_path();
    let names: Vec<String> = fs::read_dir(&session)
        .unwrap()
        .map(|item| item.unwrap().file_name().into_string().unwrap())
        .collect();
    let entry_dir = names
        .iter()
        .find(|name| !name.starts_with('.'))
        .expect("an entry directory");
    assert_eq!(
        fs::read_to_string(session.join(entry_dir).join("title")).unwrap(),
        format!("{MARKER}-ref-target")
    );
    for shown in [
        &names.join("\n"),
        &run.stdout,
        &run.stderr,
        &listing.stdout,
        &listing.stderr,
        &fs::read_to_string(session.join(entry_dir).join("meta.json")).unwrap(),
    ] {
        assert!(!shown.contains(MARKER), "{shown}");
    }
    assert!(listing.stdout.contains("REF"), "{}", listing.stdout);
}

/// With several candidates the picker decides, and `ls` and `rm` see what `add` wrote.
#[test]
fn the_picker_chooses_among_several_and_ls_and_rm_follow() {
    let fixtures = fixtures();
    let setting = Setting::new();
    let launcher = Recording::default();
    let tools = tools_with(&fixtures.pinentry_shared, &fixtures.fuzzel_asked, &launcher);

    let run = run_add(&setting, &tools, &[]);
    assert_eq!(run.exit, Exit::Success, "{}", run.stderr);
    assert!(was_invoked(&fixtures.fuzzel_asked));
    assert!(run.stdout.ends_with("/Alpha_login\n"), "{}", run.stdout);

    let second = run_add(&setting, &tools, &["gamma"]);
    assert_eq!(second.exit, Exit::Success, "{}", second.stderr);
    let listing = run_ls(&setting);
    let lines: Vec<&str> = listing.stdout.lines().collect();
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert!(
        lines[0].starts_with("Alpha_login\tAlpha login\t"),
        "{lines:?}"
    );
    assert!(
        lines[1].starts_with("Gamma_target\tGamma target\t"),
        "{lines:?}"
    );
    assert!(!listing.stdout.contains(MARKER));
    // The same expiry for both: the session's, fixed by the first add.
    let expiry = |line: &str| line.rsplit('\t').next().unwrap().to_owned();
    assert_eq!(expiry(lines[0]), expiry(lines[1]));

    let args = match parse(&["kpx-share", "rm", "Alpha_login"]).command {
        Subcommand::Rm(args) => args,
        other => panic!("{other:?}"),
    };
    let removed = capture(|io| rm_command(args, setting.at(), io));
    assert_eq!(removed.exit, Exit::Success, "{}", removed.stderr);
    assert_eq!(run_ls(&setting).stdout.lines().count(), 1);
}

#[test]
fn cancelling_the_password_dialog_is_a_cancellation_that_writes_nothing() {
    let fixtures = fixtures();
    let setting = Setting::new();
    let launcher = Recording::default();
    let tools = tools_with(
        &fixtures.pinentry_cancelled,
        &fixtures.fuzzel_shared,
        &launcher,
    );

    let run = run_add(&setting, &tools, &["alpha"]);

    assert_eq!(run.exit, Exit::Cancelled);
    assert_eq!(run.stdout, "");
    assert_eq!(run.stderr, "kpx-share: cancelled\n");
    assert!(!everything_in(&setting.session_path()).contains(MARKER));
    assert_eq!(Exit::CANCELLED_CODE, 130);
}

// --- Ordering (I1, I3) ------------------------------------------------------------------------

/// A share root that is not on tmpfs is refused before the database is unlocked: the fake
/// pinentry never runs, no watcher is started, nothing is created. Red when the database is
/// unlocked (or the password asked for) before the root is checked.
#[test]
fn a_share_root_on_disk_is_refused_before_any_password_is_asked_for() {
    let fixtures = fixtures();
    let on_disk = common::share::scratch_on_disk();
    let setting = Setting {
        runtime: on_disk,
        binding: Binding::ParentShell {
            watched: this_process(),
        },
    };
    let launcher = Recording::default();
    let tools = tools_with(
        &fixtures.pinentry_before_tmpfs,
        &fixtures.fuzzel_shared,
        &launcher,
    );

    let run = run_add(&setting, &tools, &["alpha"]);

    assert_eq!(run.exit, Exit::Failure);
    assert!(run.stderr.contains("not tmpfs"), "{}", run.stderr);
    assert_eq!(run.stdout, "");
    assert!(
        !was_invoked(&fixtures.pinentry_before_tmpfs),
        "the password was asked for before the tmpfs check"
    );
    assert!(launcher.requests.borrow().is_empty());
    assert!(!setting.runtime.path().join("kpx-share").exists());
}

/// The watcher is requested after the session directory and its record exist and before any
/// entry is written, so a session with secrets in it is never unwatched; and once more after the
/// entry is written, when the first answer (`AlreadyRunning`) may be a watcher that was exiting.
/// Red when the first request comes after the write, or when the second is dropped.
#[test]
fn the_watcher_is_requested_before_the_entry_is_written_and_again_after() {
    let fixtures = fixtures();
    let setting = Setting::new();
    let launcher = Recording::answering(&[Answer::Launched(Launch::AlreadyRunning)]);
    let tools = tools_with(
        &fixtures.pinentry_shared,
        &fixtures.fuzzel_shared,
        &launcher,
    );

    let run = run_add(&setting, &tools, &["alpha"]);

    assert_eq!(run.exit, Exit::Success, "{}", run.stderr);
    let requests = launcher.requests.borrow();
    assert_eq!(requests.len(), 2, "{requests:?}");
    assert!(requests[0].session_existed);
    assert_eq!(requests[0].entries_then, 0);
    assert_eq!(requests[1].entries_then, 1);
}

/// A later add with a shorter TTL moves the session's expiry earlier, and `ls` shows that expiry
/// for the earlier entry too, though its `meta.json` still holds the later one. Red when `ls`
/// shows the entry's own `expires_at`.
#[test]
fn ls_shows_the_shortened_expiry_for_an_entry_written_under_a_longer_one() {
    let fixtures = fixtures();
    let setting = Setting::new();
    let launcher = Recording::default();
    let tools = tools_with(
        &fixtures.pinentry_shared,
        &fixtures.fuzzel_shared,
        &launcher,
    );
    assert_eq!(
        run_add(&setting, &tools, &["--ttl", "8h", "alpha"]).exit,
        Exit::Success
    );
    let shorter = run_add(&setting, &tools, &["--ttl", "1h", "gamma"]);
    assert_eq!(shorter.exit, Exit::Success, "{}", shorter.stderr);

    let root = ShareRoot::in_runtime_dir(setting.at().runtime_dir).unwrap();
    let dir = SessionDir::find(&root, &setting.binding.name())
        .unwrap()
        .unwrap();
    let session_expiry = read_record(&dir).unwrap().unwrap().expires_at().to_string();
    let meta = fs::read_to_string(setting.session_path().join("Alpha_login/meta.json")).unwrap();
    assert!(!meta.contains(&session_expiry), "{meta}");
    let listing = run_ls(&setting);

    let lines: Vec<&str> = listing.stdout.lines().collect();
    assert_eq!(lines.len(), 2, "{lines:?}");
    for line in lines {
        assert_eq!(line.rsplit('\t').next().unwrap(), session_expiry, "{line}");
    }
}

/// A file the agent left in the session directory is not an entry and does not fail an add that
/// has already published: the same entry added again succeeds and the file is untouched. Red when
/// the scan for older copies refuses a stranger.
#[test]
fn a_stray_file_in_the_session_does_not_fail_an_add() {
    let fixtures = fixtures();
    let setting = Setting::new();
    let launcher = Recording::default();
    let tools = tools_with(
        &fixtures.pinentry_shared,
        &fixtures.fuzzel_shared,
        &launcher,
    );
    let first = run_add(&setting, &tools, &["alpha"]);
    assert_eq!(first.exit, Exit::Success, "{}", first.stderr);
    let stray = setting.session_path().join("agent-notes.txt");
    fs::write(&stray, "not an entry").unwrap();

    let again = run_add(&setting, &tools, &["alpha"]);

    assert_eq!(again.exit, Exit::Success, "{}", again.stderr);
    assert_eq!(fs::read_to_string(&stray).unwrap(), "not an entry");
    assert!(setting.session_path().join("Alpha_login/password").exists());
}

/// A watcher that cannot be started once the entry is written fails the add and takes the entry
/// back: nothing secret stays in a session nothing will delete. The entry from an earlier add is
/// untouched. Red when the second request is dropped (the add succeeds), or its failure is
/// ignored, or the entry is left.
#[test]
fn an_add_whose_watcher_is_gone_by_the_write_fails_and_leaves_no_new_entry() {
    let fixtures = fixtures();
    let setting = Setting::new();
    let launcher = Recording::answering(&[
        Answer::Launched(Launch::AlreadyRunning),
        Answer::Launched(Launch::AlreadyRunning),
        Answer::Launched(Launch::AlreadyRunning),
        Answer::CannotStart,
    ]);
    let tools = tools_with(
        &fixtures.pinentry_shared,
        &fixtures.fuzzel_shared,
        &launcher,
    );
    let first = run_add(&setting, &tools, &["alpha"]);
    assert_eq!(first.exit, Exit::Success, "{}", first.stderr);

    let run = run_add(&setting, &tools, &["gamma"]);

    assert_eq!(run.exit, Exit::Failure);
    assert_eq!(run.stdout, "");
    assert!(
        run.stderr
            .starts_with("kpx-share: cannot start the watcher"),
        "{}",
        run.stderr
    );
    assert!(setting.session_path().join("Alpha_login").exists());
    assert!(!setting.session_path().join("Gamma_target").exists());
    assert_eq!(launcher.requests.borrow().len(), 4);
}

/// A watcher that cannot be started fails the add with nothing secret read or written: the
/// password is never asked for. Red when the add goes on without a watcher.
#[test]
fn an_add_whose_watcher_cannot_start_fails_before_asking_for_the_password() {
    let fixtures = fixtures();
    let setting = Setting::new();
    let tools = tools_with(
        &fixtures.pinentry_launch_fails,
        &fixtures.fuzzel_shared,
        &Failing,
    );

    let run = run_add(&setting, &tools, &["alpha"]);

    assert_eq!(run.exit, Exit::Failure);
    assert_eq!(run.stdout, "");
    assert!(
        run.stderr
            .starts_with("kpx-share: cannot start the watcher"),
        "{}",
        run.stderr
    );
    assert!(!was_invoked(&fixtures.pinentry_launch_fails));
    assert!(!everything_in(&setting.session_path()).contains(MARKER));
}

// --- The watcher as a process (I3, I6) --------------------------------------------------------

fn session_gone(setting: &Setting) -> bool {
    !setting.session_path().exists()
}

/// `add`, then the real watcher process: killing the watched process deletes the session
/// directory within 2 s. Red when the watcher ignores the process exiting.
#[test]
fn the_watcher_process_deletes_the_session_when_the_watched_process_dies() {
    let fixtures = fixtures();
    let mut sleeper = Sleeper::spawn();
    let setting = Setting::bound_to(Binding::ParentShell {
        watched: sleeper.identity(),
    });
    let launcher = DirectChild::default();
    let tools = tools_with(
        &fixtures.pinentry_shared,
        &fixtures.fuzzel_shared,
        &launcher,
    );
    let run = run_add(&setting, &tools, &["alpha"]);
    assert_eq!(run.exit, Exit::Success, "{}", run.stderr);
    thread::sleep(Duration::from_millis(300));
    assert!(setting.session_path().join("Alpha_login").exists());

    sleeper.kill();

    assert!(
        wait_until(Duration::from_secs(2), || session_gone(&setting)),
        "the session directory outlived its process"
    );
}

/// The same with the process alive and `--ttl 2s`. Red when the TTL is not enforced.
#[test]
fn the_watcher_process_deletes_the_session_when_the_ttl_passes() {
    let fixtures = fixtures();
    let sleeper = Sleeper::spawn();
    let setting = Setting::bound_to(Binding::ParentShell {
        watched: sleeper.identity(),
    });
    let launcher = DirectChild::default();
    let tools = tools_with(
        &fixtures.pinentry_shared,
        &fixtures.fuzzel_shared,
        &launcher,
    );
    let started = Instant::now();
    let run = run_add(&setting, &tools, &["--ttl", "2s", "alpha"]);
    assert_eq!(run.exit, Exit::Success, "{}", run.stderr);
    assert!(setting.session_path().join("Alpha_login").exists());

    assert!(
        wait_until(Duration::from_secs(5), || session_gone(&setting)),
        "the session directory outlived its TTL"
    );
    assert!(started.elapsed() >= Duration::from_secs(2), "deleted early");
}

/// The process hardens itself whichever command runs (I6): a watcher started with a core limit
/// of 1000 blocks has it set to 0. Red when `main` does not call `harden`. It cannot show that
/// hardening comes before argument parsing, only that it happens for this command.
#[test]
fn the_process_is_hardened_whichever_command_it_runs() {
    let sleeper = Sleeper::spawn();
    let setting = Setting::bound_to(Binding::ParentShell {
        watched: sleeper.identity(),
    });
    let root = ShareRoot::in_runtime_dir(setting.at().runtime_dir).unwrap();
    let session = Session::open(
        &root,
        &setting.binding,
        Ttl::parse("1h").unwrap(),
        jiff::Timestamp::now(),
    )
    .unwrap();
    let mut child = Command::new("bash")
        .arg("-c")
        .arg("ulimit -c 1000; exec \"$0\" watch --session \"$1\" --root \"$2\"")
        .arg(KPX_SHARE)
        .arg(session.dir().name().as_str())
        .arg(root.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let limits = format!("/proc/{}/limits", child.id());
    let core_limit_is_zero = || {
        fs::read_to_string(&limits).is_ok_and(|text| {
            text.lines()
                .find(|line| line.starts_with("Max core file size"))
                .is_some_and(|line| {
                    let fields: Vec<&str> = line.split_whitespace().collect();
                    fields.get(4..6) == Some(&["0", "0"][..])
                })
        })
    };

    let hardened = wait_until(Duration::from_secs(2), core_limit_is_zero);

    child.kill().unwrap();
    child.wait().unwrap();
    assert!(hardened, "the core file size limit was never set to 0");
}

// --- The real systemd -------------------------------------------------------------------------

/// Stops the unit and removes the directory, whatever the test did.
struct Cleanup {
    unit: String,
    session: PathBuf,
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _best_effort = Command::new(tools::SYSTEMCTL)
            .args(["--user", "stop"])
            .arg(format!("{}.service", self.unit))
            .output();
        let _best_effort = Command::new(tools::SYSTEMCTL)
            .args(["--user", "reset-failed"])
            .arg(format!("{}.service", self.unit))
            .output();
        let _best_effort = fs::remove_dir_all(&self.session);
    }
}

fn unit_is_active(unit: &str) -> bool {
    Command::new(tools::SYSTEMCTL)
        .args(["--user", "is-active", "--quiet"])
        .arg(format!("{unit}.service"))
        .status()
        .unwrap()
        .success()
}

/// `add` with the real `systemd-run --user`: the watcher runs as the unit `kpx-share-<session>`,
/// a second request finds it running, and the TTL deletes the directory and ends the unit. The
/// unit is stopped and the directory removed even if an assertion fails. Returns without testing
/// when no systemd user manager is reachable (a container, a CI runner).
#[test]
fn systemd_runs_the_watcher_as_a_user_unit_that_cleans_up_after_the_ttl() {
    let reachable = Command::new(tools::SYSTEMCTL)
        .args(["--user", "show-environment"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success());
    if !reachable {
        eprintln!("no systemd user manager is reachable: the systemd-run path is not tested");
        return;
    }
    let fixtures = fixtures();
    let sleeper = Sleeper::spawn();
    let setting = Setting::bound_to(Binding::ParentShell {
        watched: sleeper.identity(),
    });
    let unit = SystemdRun::unit_name(&setting.binding.name());
    let _cleanup = Cleanup {
        unit: unit.clone(),
        session: setting.session_path(),
    };
    let launcher = SystemdRun::new(PathBuf::from(KPX_SHARE));
    let tools = tools_with(
        &fixtures.pinentry_shared,
        &fixtures.fuzzel_shared,
        &launcher,
    );

    let run = run_add(&setting, &tools, &["--ttl", "4s", "alpha"]);

    assert_eq!(run.exit, Exit::Success, "{}", run.stderr);
    assert!(unit_is_active(&unit), "the unit {unit} is not running");
    let root = ShareRoot::in_runtime_dir(setting.at().runtime_dir).unwrap();
    let again = launcher.ensure_running(&WatcherSpec {
        root: &root,
        session: &setting.binding.name(),
    });
    assert!(matches!(again, Ok(Launch::AlreadyRunning)), "{again:?}");
    assert!(
        wait_until(Duration::from_secs(8), || session_gone(&setting)),
        "the session directory outlived its TTL"
    );
    assert!(
        wait_until(Duration::from_secs(3), || !unit_is_active(&unit)),
        "the unit {unit} outlived the session"
    );
}
