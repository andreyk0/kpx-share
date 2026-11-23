//! `import` end to end: the real `keepassxc-cli` on throwaway KDBX databases (4.0 and 3.1),
//! behind a wrapper script that records what it was run with; fake pinentry programs and
//! throwaway gpg homes; a scratch `XDG_RUNTIME_DIR` on tmpfs where each test stages what an agent
//! would; and `kpx_share::cli::import_command` driven with in-memory output.
//!
//! The wrapper (see [`WRAPPER`]) appends, for every keepassxc-cli run: every argument to
//! `logs/argv`; where each of its open descriptors points to `logs/fds`; the live database's
//! inode and modification time to `logs/live`; whether the import root is locked to
//! `logs/lock`; and every file below the runtime directory, outside the staging and claimed
//! directories, that holds a sentinel to `logs/leaks`. Then, when the test asked for it in
//! `hooks/env`, it changes something mid-run (the live database, a claimed file, the copy, a file
//! where the agent wrote it), and runs the real keepassxc-cli. What the result says is checked
//! with keepassxc-cli itself (`show`, `attachment-export`), never with the code under test. Each
//! test's doc comment names the mutation that turns it red. Needs `keepassxc-cli`, bash, gpg and
//! util-linux `flock`; without them these tests fail, never skip.
//!
//! All scripts and databases are created once, before any test spawns a process (`ETXTBSY`).

mod common;

use std::cell::{Cell, RefCell};
use std::fs;
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;

use clap::{CommandFactory, FromArgMatches};
use common::fakes::{runs, write_script};
use common::gpg::ThrowawayGpg;
use common::share::scratch_on_tmpfs;
use kpx_share::cli::{Cli, Command as Subcommand, Exit, Io, import_command};
use kpx_share::import::ImportTools;
use kpx_share::import::database::{DatabaseFiles, Disk};
use kpx_share::unlock::{Prompter, UnlockTools};
use tempfile::TempDir;

/// In every staged password, so one search finds it anywhere.
const PASSWORD_MARKER: &str = "kpximp-pw-7c2e91";
/// In every staged attachment.
const ATTACHMENT_MARKER: &str = "kpximp-att-4b8d03";
/// The throwaway databases' master password: a sentinel too, as it must never be printed either.
const MASTER: &str = "kpximp-master-3f7a";
const KEEPASSXC_CLI: &str = "/usr/bin/keepassxc-cli";
const NAME: &str = "hvac";

// --- Fixtures ---------------------------------------------------------------------------------

/// The keepassxc-cli wrapper. The runtime directory is found from the copy's path (the argument
/// after `--` is `<runtime>/kpx-import/.work-*/db.kdbx`); `hooks/env` there says what to record
/// and what to change.
const WRAPPER: &str = r#"copy=""
after_dashes=0
for arg in "$@"; do
  if [[ $after_dashes == 1 ]]; then copy=$arg; break; fi
  if [[ $arg == -- ]]; then after_dashes=1; fi
done
runtime=${copy%/kpx-import/*}
hooks="$runtime/hooks"
if [[ -n "$copy" && -f "$hooks/env" ]]; then
  # shellcheck disable=SC1091 # written by the test
  source "$hooks/env"
  logs="$runtime/logs"
  mkdir -p "$logs"
  # The listing's own descriptor is closed by the time it is read: `|| true`.
  for fd in "/proc/$$/fd"/*; do
    printf '%s\n' "$(readlink -- "$fd" || true)"
  done >>"$logs/fds"
  printf '%s\0' "$@" >>"$logs/argv"
  stat -c '%i %Y.%y' -- "$LIVE" >>"$logs/live"
  if flock -n "$runtime/kpx-import" true; then echo free; else echo busy; fi >>"$logs/lock"
  for marker in "${MARKERS[@]}"; do
    rc=0
    grep -rlaF --exclude-dir="$NAME" --exclude-dir='.claimed.*' --exclude-dir=logs \
      --exclude-dir=hooks -e "$marker" -- "$runtime" >>"$logs/leaks" || rc=$?
    if [[ $rc -gt 1 ]]; then exit 99; fi
  done
  claimed=""
  for dir in "$runtime"/kpx-import/.claimed.*; do
    if [[ -d $dir ]]; then claimed=$dir; fi
  done
  if [[ -n "${CONCURRENT:-}" && ! -e "$hooks/concurrent.done" ]] &&
    [[ $1 == add || $1 == attachment-import ]]; then
    cp -- "$CONCURRENT" "$LIVE"
    : >"$hooks/concurrent.done"
  fi
  if [[ -n "${LATE:-}" && ! -e "$hooks/late.done" ]]; then
    printf 'late' >"$claimed/$LATE"
    : >"$hooks/late.done"
  fi
  if [[ -n "${REWRITE:-}" && ! -e "$hooks/rewrite.done" ]]; then
    printf 'rewritten in place after it was read' >"$claimed/$REWRITE"
    : >"$hooks/rewrite.done"
  fi
  if [[ -n "${REPLACE:-}" && ! -e "$hooks/replace.done" ]]; then
    printf 'replaced after it was read' >"$claimed/$REPLACE.new"
    mv -- "$claimed/$REPLACE.new" "$claimed/$REPLACE"
    : >"$hooks/replace.done"
  fi
  if [[ -n "${AGENT_WRITE:-}" && ! -e "$hooks/agent-write.done" ]]; then
    if { printf 'what the agent wrote' >"$STAGING/$AGENT_WRITE"; } 2>/dev/null; then
      echo wrote
    else
      echo failed
    fi >>"$logs/agent-write"
    : >"$hooks/agent-write.done"
  fi
  if [[ -n "${RECREATE:-}" ]]; then
    mkdir -p -- "$STAGING"
  fi
  if [[ -n "${APPEND:-}" && ! -e "$hooks/append.done" ]]; then
    : >"$hooks/append-now"
    for _ in $(seq 200); do
      if [[ -e "$hooks/appended" ]]; then break; fi
      sleep 0.05
    done
    : >"$hooks/append.done"
  fi
  if [[ -n "${PARTIAL_READ:-}" && $1 == attachment-import ]]; then
    head -c 10 -- "${@: -1}" >/dev/null
    exit 0
  fi
  if [[ ${TOUCH_COPY:-} == "$1" ]]; then
    rc=0
    /usr/bin/keepassxc-cli "$@" || rc=$?
    printf 'x' >>"$copy"
    exit "$rc"
  fi
fi
exec /usr/bin/keepassxc-cli "$@"
"#;

/// A keepassxc-cli that drops `-y <slot>` and runs [`WRAPPER`]: the import is asked for with a
/// `YubiKey` slot, so its notices are shown, and runs on a database that needs none.
fn without_yubikey(wrapper: &Path) -> String {
    format!(
        "args=()\nskip=0\nfor arg in \"$@\"; do\n\
         \x20 if [[ $skip == 1 ]]; then skip=0; continue; fi\n\
         \x20 if [[ $arg == -y ]]; then skip=1; continue; fi\n\
         \x20 args+=(\"$arg\")\n\
         done\n\
         exec '{}' \"${{args[@]}}\"\n",
        wrapper.display()
    )
}

struct Fixtures {
    keepassxc: PathBuf,
    keepassxc_without_yubikey: PathBuf,
    /// The base database (KDBX 4): `Ops/hvac-control-tls` with attachment `old.pem`, one history
    /// version and tag `agent`; and `Ops/other` with a custom attribute.
    db: PathBuf,
    /// The same as a KDBX 3.1 database, whose export carries the attachments' bytes.
    kdbx31_db: PathBuf,
    /// A database whose history limit is 2 items, and `Ops/full` with 2 history versions.
    history_db: PathBuf,
    /// Another database, the bytes a concurrent save writes.
    concurrent_db: PathBuf,
    /// The base database protected by `key_file` alone.
    key_file_only_db: PathBuf,
    key_file: PathBuf,
    /// For the input-rule test: never to run, since every case is refused before the go.
    pinentry_rules: PathBuf,
    gpg_rules: ThrowawayGpg,
    gpg_rules_pw: PathBuf,
    /// For the cancel test: declines at CONFIRM.
    pinentry_declines: PathBuf,
    /// Answers CONFIRM with "not confirmed", what pinentry may send for its Cancel button.
    pinentry_not_confirmed: PathBuf,
    /// Confirms, then cancels the password dialog.
    pinentry_getpin_cancelled: PathBuf,
    gpg_cancel: ThrowawayGpg,
    gpg_cancel_pw: PathBuf,
    /// For the import through `--password-gpg`.
    gpg_success: ThrowawayGpg,
    gpg_success_pw: PathBuf,
    /// Answers OK and the master password; one per test that counts or reads its runs.
    pinentry: Vec<PathBuf>,
    /// Answers OK and a password no database takes.
    pinentry_wrong: PathBuf,
    /// Number `n - 1` cancels its `n`th `YubiKey` notice.
    pinentry_cancelling_notice: Vec<PathBuf>,
    /// Cancels its first notice, for the rerun's preflight.
    pinentry_cancelling_preflight: PathBuf,
    pinentry_hanging: PathBuf,
}

/// Longest line a pinentry accepts, line feed included (Assuan's `ASSUAN_LINELENGTH`).
const ASSUAN_LINE_BYTES_MAX: usize = 1000;

/// A pinentry that answers `OK` to everything but `CONFIRM`, which gets `confirm`, and `GETPIN`,
/// which gets `getpin` (lines); a line longer than Assuan allows gets an error, as pinentry
/// gives. Every line it is sent, in every run, is appended to `<script>.log`; each run appends a
/// line to `<script>.runs`.
fn pinentry(dir: &Path, name: &str, confirm: &str, getpin: &[&str]) -> PathBuf {
    pinentry_with(
        dir,
        name,
        &format!("printf '%s\\n' '{confirm}'"),
        getpin,
        "",
    )
}

/// [`pinentry`] that cancels its `n`th `MESSAGE` (a `YubiKey` notice), counted over all its
/// runs, and answers the others `OK`.
fn pinentry_cancelling_notice(dir: &Path, name: &str, n: usize) -> PathBuf {
    let master = answers_master();
    pinentry_with(
        dir,
        name,
        "echo OK",
        &[master[0].as_str(), master[1].as_str()],
        &format!(
            "\x20   MESSAGE) seen=$(( $(cat \"$0.notices\" 2>/dev/null || echo 0) + 1 ))\n\
             \x20     echo \"$seen\" > \"$0.notices\"\n\
             \x20     if (( seen == {n} )); then echo '{CANCELLED}'; else echo OK; fi ;;\n"
        ),
    )
}

/// [`pinentry`] that, asked to confirm, writes its pid to `$KPXIMP_WAITING` and waits there
/// until it is killed: an import blocked at its confirmation.
fn pinentry_hanging_at_confirm(dir: &Path, name: &str) -> PathBuf {
    pinentry_with(
        dir,
        name,
        "printf '%s' \"$$\" > \"$KPXIMP_WAITING\"; exec sleep 600",
        &["OK"],
        "",
    )
}

/// The fake pinentry: `confirm` is the shell command answering `CONFIRM`, `getpin` the lines
/// answering `GETPIN`, and `first_cases` more `case` arms, tried before the others.
fn pinentry_with(
    dir: &Path,
    name: &str,
    confirm: &str,
    getpin: &[&str],
    first_cases: &str,
) -> PathBuf {
    let getpin = getpin
        .iter()
        .map(|line| format!(" '{line}'"))
        .collect::<Vec<_>>()
        .concat();
    write_script(
        dir,
        name,
        &format!(
            "export LC_ALL=C\n\
             echo run >> \"$0.runs\"\n\
             echo 'OK Pleased to meet you'\n\
             while IFS= read -r line; do\n\
             \x20 printf '%s\\n' \"$line\" >> \"$0.log\"\n\
             \x20 if (( ${{#line}} + 1 > {ASSUAN_LINE_BYTES_MAX} )); then\n\
             \x20   echo 'ERR 536870918 Line too long <Pinentry>'; continue\n\
             \x20 fi\n\
             \x20 case \"$line\" in\n\
             {first_cases}\
             \x20   CONFIRM) {confirm} ;;\n\
             \x20   GETPIN) printf '%s\\n'{getpin} ;;\n\
             \x20   BYE) echo 'OK closing connection'; exit 0 ;;\n\
             \x20   *) echo OK ;;\n\
             \x20 esac\n\
             done\n"
        ),
    )
}

fn answers_master() -> [String; 2] {
    [format!("D {MASTER}"), "OK".to_owned()]
}

/// The lines `program` was sent, every run, in order.
fn pinentry_lines(program: &Path) -> Vec<String> {
    let mut log = program.as_os_str().to_owned();
    log.push(".log");
    fs::read_to_string(Path::new(&log))
        .unwrap_or_default()
        .lines()
        .map(str::to_owned)
        .collect()
}

/// The commands `program` was sent, every run, in order.
fn pinentry_log(program: &Path) -> Vec<String> {
    pinentry_lines(program)
        .into_iter()
        .map(|line| line.split(' ').next().unwrap_or_default().to_owned())
        .collect()
}

const CANCELLED: &str = "ERR 83886179 Operation cancelled <Pinentry>";

/// The database format the fixture is written in: an entry's `CustomData` is what makes
/// keepassxc-cli save KDBX 4.
#[derive(Clone, Copy)]
enum Format {
    Kdbx4,
    Kdbx31,
}

fn base_xml(format: Format) -> String {
    let marker = match format {
        Format::Kdbx4 => {
            "<CustomData><Item><Key>kpx-share-test</Key><Value>KDBX 4</Value></Item></CustomData>"
        }
        Format::Kdbx31 => "",
    };
    common::document(
        "<HistoryMaxItems>10</HistoryMaxItems><Binaries>\
         <Binary ID=\"0\">b2xkIHBlbQ==</Binary></Binaries>",
        &format!(
            "<Group><UUID>BwcHBwcHBwcHBwcHBwcHBw==</UUID><Name>Ops</Name>{}{}\
             <Group><UUID>CAgICAgICAgICAgICAgICA==</UUID><Name>Empty</Name></Group></Group>",
            common::entry(
                0x11,
                &[
                    common::string("Title", "hvac-control-tls"),
                    common::string("UserName", "hvac"),
                    common::string("Password", "tls-pw"),
                    "<Tags>agent</Tags>".to_owned(),
                    marker.to_owned(),
                    r#"<Binary><Key>old.pem</Key><Value Ref="0"/></Binary>"#.to_owned(),
                    format!(
                        "<History>{}</History>",
                        common::entry(
                            0x11,
                            &[
                                "<Times><LastModificationTime>2020-01-01T00:00:00Z</LastModificationTime></Times>".to_owned(),
                                common::string("Title", "hvac-control-tls"),
                            ]
                            .concat()
                        )
                    ),
                ]
                .concat()
            ),
            common::entry(
                0x22,
                &[
                    common::string("Title", "other"),
                    common::string("Password", "other-pw"),
                    common::string("API key", "k-123"),
                ]
                .concat()
            ),
        ),
    )
}

fn history_xml() -> String {
    let version = |day: u8| {
        common::entry(
            0x33,
            &[
                format!(
                    "<Times><LastModificationTime>2020-01-0{day}T00:00:00Z</LastModificationTime></Times>"
                ),
                common::string("Title", "full"),
            ]
            .concat(),
        )
    };
    common::document(
        "<HistoryMaxItems>2</HistoryMaxItems>",
        &format!(
            "<Group><UUID>BwcHBwcHBwcHBwcHBwcHBw==</UUID><Name>Ops</Name>{}</Group>",
            common::entry(
                0x33,
                &[
                    common::string("Title", "full"),
                    "<CustomData><Item><Key>k</Key><Value>v</Value></Item></CustomData>".to_owned(),
                    format!("<History>{}{}</History>", version(1), version(2)),
                ]
                .concat()
            )
        ),
    )
}

/// The KDBX header's version, bytes 8 to 12: 4.0, or 3.1.
const KDBX4_VERSION: [u8; 4] = [0, 0, 4, 0];
const KDBX31_VERSION: [u8; 4] = [1, 0, 3, 0];

fn kdbx(dir: &Path, name: &str, xml: &str, version: [u8; 4]) -> PathBuf {
    let source = dir.join(format!("{name}.xml"));
    fs::write(&source, xml).unwrap();
    let db = dir.join(format!("{name}.kdbx"));
    common::create_kdbx_from_xml(&source, &db, MASTER, None);
    assert_eq!(&fs::read(&db).unwrap()[8..12], version, "{name}'s format");
    db
}

fn fixtures() -> &'static Fixtures {
    static FIXTURES: OnceLock<Fixtures> = OnceLock::new();
    FIXTURES.get_or_init(|| {
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("import-fixtures");
        let _absent_is_fine = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let key_file = dir.join("db.key");
        fs::write(&key_file, "not a real key, throwaway\n").unwrap();
        let key_file_only_db = dir.join("keyed-only.kdbx");
        let base = dir.join("keyed.xml");
        fs::write(&base, base_xml(Format::Kdbx4)).unwrap();
        common::create_key_file_only_kdbx(&base, &key_file_only_db, &key_file);
        let gpg = |name: &str| {
            let sub = dir.join(name);
            fs::create_dir_all(&sub).unwrap();
            let gpg = ThrowawayGpg::create(&sub);
            let pw = dir.join(format!("{name}-pw.gpg"));
            gpg.encrypt(format!("{MASTER}\n").as_bytes(), &pw);
            (gpg, pw)
        };
        let (gpg_rules, gpg_rules_pw) = gpg("gpg-rules");
        let (gpg_cancel, gpg_cancel_pw) = gpg("gpg-cancel");
        let (gpg_success, gpg_success_pw) = gpg("gpg-success");
        let keepassxc = write_script(&dir, "keepassxc-wrapper", WRAPPER);
        let master = answers_master();
        let master = [master[0].as_str(), master[1].as_str()];
        Fixtures {
            keepassxc_without_yubikey: write_script(
                &dir,
                "keepassxc-without-yubikey",
                &without_yubikey(&keepassxc),
            ),
            keepassxc,
            db: kdbx(&dir, "base", &base_xml(Format::Kdbx4), KDBX4_VERSION),
            kdbx31_db: kdbx(&dir, "kdbx31", &base_xml(Format::Kdbx31), KDBX31_VERSION),
            history_db: kdbx(&dir, "history", &history_xml(), KDBX4_VERSION),
            concurrent_db: kdbx(&dir, "concurrent", &history_xml(), KDBX4_VERSION),
            key_file_only_db,
            key_file,
            pinentry_rules: pinentry(&dir, "pinentry-rules", "OK", &master),
            gpg_rules,
            gpg_rules_pw,
            pinentry_declines: pinentry(&dir, "pinentry-declines", CANCELLED, &master),
            pinentry_not_confirmed: pinentry(
                &dir,
                "pinentry-not-confirmed",
                "ERR 83886194 Not confirmed <Pinentry>",
                &master,
            ),
            pinentry_getpin_cancelled: pinentry(
                &dir,
                "pinentry-getpin-cancelled",
                "OK",
                &[CANCELLED],
            ),
            gpg_cancel,
            gpg_cancel_pw,
            gpg_success,
            gpg_success_pw,
            pinentry: (0..48)
                .map(|i| pinentry(&dir, &format!("pinentry-{i}"), "OK", &master))
                .collect(),
            pinentry_wrong: pinentry(&dir, "pinentry-wrong", "OK", &["D wrong-master-5e1d", "OK"]),
            pinentry_cancelling_notice: (1..=4)
                .map(|n| pinentry_cancelling_notice(&dir, &format!("pinentry-notice-{n}"), n))
                .collect(),
            pinentry_cancelling_preflight: pinentry_cancelling_notice(
                &dir,
                "pinentry-notice-preflight",
                1,
            ),
            pinentry_hanging: pinentry_hanging_at_confirm(&dir, "pinentry-hanging"),
        }
    })
}

/// Pinentry number `index`, for a test of its own.
fn own_pinentry(index: usize) -> &'static Path {
    &fixtures().pinentry[index]
}

// --- A test's world ---------------------------------------------------------------------------

/// A scratch `XDG_RUNTIME_DIR` on tmpfs holding `kpx-import/` (made as an agent makes it), the
/// database at `db/db.kdbx`, and the wrapper's `hooks/` and `logs/`.
struct Setting {
    runtime: TempDir,
    db: PathBuf,
}

impl Setting {
    fn new(fixture_db: &Path) -> Self {
        let runtime = scratch_on_tmpfs();
        let db_dir = runtime.path().join("db");
        fs::create_dir(&db_dir).unwrap();
        let db = db_dir.join("db.kdbx");
        fs::copy(fixture_db, &db).unwrap();
        fs::set_permissions(&db, fs::Permissions::from_mode(0o600)).unwrap();
        let root = runtime.path().join("kpx-import");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(runtime.path().join("hooks")).unwrap();
        let setting = Self { runtime, db };
        setting.hooks("");
        setting
    }

    fn root(&self) -> PathBuf {
        self.runtime.path().join("kpx-import")
    }

    fn staging(&self) -> PathBuf {
        self.root().join(NAME)
    }

    /// Writes the wrapper's `hooks/env`: what to watch, plus `extra` assignments.
    fn hooks(&self, extra: &str) {
        fs::write(
            self.runtime.path().join("hooks/env"),
            format!(
                "LIVE='{}'\nSTAGING='{}'\nNAME='{NAME}'\n\
                 MARKERS=('{PASSWORD_MARKER}' '{ATTACHMENT_MARKER}' '{MASTER}')\n{extra}",
                self.db.display(),
                self.staging().display()
            ),
        )
        .unwrap();
    }

    /// Stages `files` and a manifest, as an agent would: the directory 0700, files 0600.
    fn stage(&self, manifest: &str, files: &[(&str, &[u8])]) {
        let staging = self.staging();
        fs::create_dir(&staging).unwrap();
        fs::set_permissions(&staging, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(staging.join("manifest.json"), manifest).unwrap();
        for (name, bytes) in files {
            fs::write(staging.join(name), bytes).unwrap();
        }
    }

    fn log(&self, name: &str) -> Vec<u8> {
        fs::read(self.runtime.path().join("logs").join(name)).unwrap_or_default()
    }

    fn log_lines(&self, name: &str) -> Vec<String> {
        String::from_utf8(self.log(name))
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    fn db_bytes(&self) -> Vec<u8> {
        fs::read(&self.db).unwrap()
    }
}

struct Run {
    exit: Exit,
    stdout: String,
    stderr: String,
}

/// Parses `argv` as the binary does, minus every argument's environment variable, so a
/// developer's own `KPX_SHARE_*` cannot change what a test runs.
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

fn tools<'a>(prompter: Prompter, gpg: &Path, files: &'a dyn DatabaseFiles) -> ImportTools<'a> {
    ImportTools {
        unlock: UnlockTools {
            keepassxc_cli: fixtures().keepassxc.clone(),
            gpg: gpg.to_owned(),
            prompter,
        },
        tty: PathBuf::from("/nonexistent/tty"),
        files,
    }
}

fn pinentry_tools(program: &Path) -> ImportTools<'static> {
    tools(
        Prompter::Pinentry {
            program: program.to_owned(),
        },
        Path::new("/nonexistent/gpg"),
        &Disk,
    )
}

fn run_import(setting: &Setting, tools: &ImportTools<'_>, extra: &[&str]) -> Run {
    run_import_from(setting, &setting.db, tools, extra)
}

/// `kpx-share import --db <db> <extra…> hvac` in `setting`.
fn run_import_from(setting: &Setting, db: &Path, tools: &ImportTools<'_>, extra: &[&str]) -> Run {
    let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
    let exit = import_into(setting, db, tools, extra, &mut stdout, &mut stderr);
    Run {
        exit,
        stdout: String::from_utf8(stdout).unwrap(),
        stderr: String::from_utf8(stderr).unwrap(),
    }
}

fn import_into(
    setting: &Setting,
    db: &Path,
    tools: &ImportTools<'_>,
    extra: &[&str],
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Exit {
    let db = db.to_str().unwrap().to_owned();
    let mut command_line = vec!["kpx-share", "import", "--db", &db];
    command_line.extend_from_slice(extra);
    command_line.push(NAME);
    let Subcommand::Import(import_args) = parse(&command_line).command else {
        panic!("not an import")
    };
    import_command(
        import_args,
        Some(setting.runtime.path().as_os_str()),
        tools,
        &mut Io { out, err },
    )
}

/// Whether keepassxc-cli is expected to have run, so an empty log proves something.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Keepassxc {
    Ran,
    NeverRan,
}

/// S5: no sentinel on stdout or stderr, in any argument keepassxc-cli got, or in any file below
/// the runtime directory outside the staging directory while it ran; no keepassxc-cli run held a
/// descriptor on anything below the import root; and nothing kpx-share made is left behind: no
/// work directory with the copy, no claimed directory, no temporary file beside the database.
fn assert_no_leak(setting: &Setting, run: &Run, keepassxc: Keepassxc, extra_secrets: &[&str]) {
    let left: Vec<String> = listing(&setting.root())
        .into_iter()
        .chain(listing(&setting.runtime.path().join("db")))
        .filter(|name| {
            name.starts_with(".work-")
                || name.starts_with(".claimed.")
                || name.contains(".kpx-import-")
        })
        .collect();
    assert_eq!(left, [] as [String; 0]);
    let argv = setting.log("argv");
    match keepassxc {
        Keepassxc::Ran => assert!(!argv.is_empty(), "the wrapper never ran"),
        Keepassxc::NeverRan => assert_eq!(String::from_utf8_lossy(&argv), ""),
    }
    let argv = String::from_utf8_lossy(&argv);
    for secret in [PASSWORD_MARKER, ATTACHMENT_MARKER, MASTER]
        .iter()
        .chain(extra_secrets)
    {
        assert!(!run.stdout.contains(secret), "stdout: {}", run.stdout);
        assert!(!run.stderr.contains(secret), "stderr: {}", run.stderr);
        assert!(!argv.contains(secret), "argv: {argv}");
    }
    assert_eq!(String::from_utf8_lossy(&setting.log("leaks")), "");
    let root = setting.root();
    let held: Vec<String> = setting
        .log_lines("fds")
        .into_iter()
        .filter(|target| Path::new(target).starts_with(&root))
        .collect();
    assert_eq!(
        held,
        [] as [String; 0],
        "a child held a descriptor below the root"
    );
}

/// How the test itself opens a database with keepassxc-cli.
#[derive(Clone, Copy)]
enum Opens<'a> {
    Master,
    KeyFile(&'a Path),
}

/// `keepassxc-cli show` of `entry` in `db`, protected values and attachments included.
fn show(db: &Path, entry: &str) -> String {
    show_with(db, entry, Opens::Master)
}

fn show_with(db: &Path, entry: &str, opens: Opens<'_>) -> String {
    keepassxc(
        &["show", "-q", "-s", "--all", "--show-attachments"],
        db,
        &[entry],
        opens,
    )
    .map(|out| String::from_utf8(out).unwrap())
    .unwrap()
}

fn attachment(db: &Path, entry: &str, name: &str) -> Vec<u8> {
    keepassxc(
        &["attachment-export", "-q"],
        db,
        &[entry, name, "/dev/stdout"],
        Opens::Master,
    )
    .unwrap()
}

fn keepassxc(args: &[&str], db: &Path, rest: &[&str], opens: Opens<'_>) -> io::Result<Vec<u8>> {
    let mut command = Command::new(KEEPASSXC_CLI);
    command.args(args);
    if let Opens::KeyFile(key_file) = opens {
        command.args(["--no-password", "-k"]).arg(key_file);
    }
    let mut child = command
        .arg("--")
        .arg(db)
        .args(rest)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stdin = child.stdin.take().unwrap();
    if let Opens::Master = opens {
        stdin.write_all(format!("{MASTER}\n").as_bytes())?;
    }
    drop(stdin);
    let output = child.wait_with_output()?;
    if output.status.success() {
        Ok(output.stdout)
    } else {
        Err(io::Error::other(
            String::from_utf8_lossy(&output.stderr).into_owned(),
        ))
    }
}

/// A staged password: [`PASSWORD_MARKER`] and more.
const STAGED_PASSWORD: &[u8] = b"kpximp-pw-7c2e91-Secret_1";

fn password_file() -> Vec<u8> {
    assert!(STAGED_PASSWORD.starts_with(PASSWORD_MARKER.as_bytes()));
    STAGED_PASSWORD.to_vec()
}

/// Bytes a text stream would not carry: NUL, CR, LF, invalid UTF-8, and the sentinel.
fn binary_attachment() -> Vec<u8> {
    let mut bytes = b"\0\r\n\xff\xfe-BEGIN\r\n".to_vec();
    bytes.extend_from_slice(ATTACHMENT_MARKER.as_bytes());
    bytes.extend((0..=255u8).cycle().take(1000));
    bytes
}

const NEW_MANIFEST: &str = r#"{"kind":"new","entry":"Ops/mqtt","username":"broker","url":"mqtts://h:8883",
    "password":"pw.txt","attachments":{"ca.der":"ca"}}"#;

fn stage_new(setting: &Setting) {
    setting.stage(
        NEW_MANIFEST,
        &[("pw.txt", &password_file()), ("ca", &binary_attachment())],
    );
}

const EXISTING_MANIFEST: &str =
    r#"{"kind":"existing","entry":"Ops/hvac-control-tls","attachments":{"hvac22.pem":"pem"}}"#;

fn pem() -> Vec<u8> {
    format!("-----BEGIN PRIVATE KEY-----\n{ATTACHMENT_MARKER}\n-----END PRIVATE KEY-----\n")
        .into_bytes()
}

fn stage_existing(setting: &Setting) {
    setting.stage(EXISTING_MANIFEST, &[("pem", &pem())]);
}

/// The names in `dir`, sorted; none when it is missing or not a directory.
fn listing(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .map(|items| {
            items
                .map(|item| item.unwrap().file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names
}

fn assert_staging_intact(setting: &Setting, files: &[&str]) {
    let mut expected: Vec<String> = files.iter().map(|name| (*name).to_owned()).collect();
    expected.sort();
    assert_eq!(listing(&setting.staging()), expected);
}

// --- What an import adds ----------------------------------------------------------------------

/// A new entry with fields, a password and a binary attachment: imported byte for byte, one
/// line per item on stdout, the staging directory gone, nothing secret anywhere, and what an
/// earlier run left (a work directory, a temporary copy beside the database) removed. Red when
/// the password or attachment is passed any other way than stdin and the pipe (argv, a file),
/// when the attachment goes through a text stream, when the staging directory is kept, or a
/// leftover is not removed.
#[test]
fn a_new_entry_is_imported_byte_for_byte_and_the_staging_directory_removed() {
    let setting = Setting::new(&fixtures().db);
    stage_new(&setting);
    let stale = setting.root().join(".work-00000000000000ff");
    fs::create_dir(&stale).unwrap();
    fs::write(stale.join("db.kdbx"), b"ciphertext").unwrap();
    let stale_copy = setting
        .runtime
        .path()
        .join("db/.db.kdbx.kpx-import-0000000000000001");
    fs::write(&stale_copy, b"ciphertext").unwrap();

    let run = run_import(&setting, &pinentry_tools(own_pinentry(0)), &[]);

    assert_no_leak(&setting, &run, Keepassxc::Ran, &[]);
    assert_eq!(run.exit, Exit::Success, "{}", run.stderr);
    assert_eq!(
        run.stdout,
        format!(
            "added entry Ops/mqtt (password {} bytes)\nadded attachment ca.der ({} bytes) to Ops/mqtt\n",
            password_file().len(),
            binary_attachment().len()
        )
    );
    assert!(run.stderr.contains("tag it \"agent\""), "{}", run.stderr);
    assert!(run.stderr.contains("commit "), "{}", run.stderr);
    let shown = show(&setting.db, "Ops/mqtt");
    assert!(shown.contains("UserName: broker\n"), "{shown}");
    assert!(shown.contains("URL: mqtts://h:8883\n"), "{shown}");
    assert!(
        shown.contains(&format!(
            "Password: {}\n",
            String::from_utf8(password_file()).unwrap()
        )),
        "the password is stored exactly"
    );
    assert_eq!(
        attachment(&setting.db, "Ops/mqtt", "ca.der"),
        binary_attachment()
    );
    assert!(!setting.staging().exists());
}

/// An attachment added to an existing entry, beside the one it had; every field, tag and
/// attachment of it and of the other entry as before (S1, checked with `show`), in a KDBX 4
/// database and a KDBX 3.1 one, whose export carries the attachments' bytes. Red when the
/// import replaces (`attachment-import -f`) or drops the old attachment, or changes a field.
#[test]
fn an_attachment_is_added_to_an_existing_entry_and_nothing_else_changes() {
    for (db, program) in [(&fixtures().db, 1), (&fixtures().kdbx31_db, 16)] {
        let setting = Setting::new(db);
        let target_before = show(&setting.db, "Ops/hvac-control-tls");
        let other_before = show(&setting.db, "Ops/other");
        stage_existing(&setting);

        let run = run_import(&setting, &pinentry_tools(own_pinentry(program)), &[]);

        assert_eq!(run.exit, Exit::Success, "{}", run.stderr);
        assert_eq!(
            run.stdout,
            format!(
                "added attachment hvac22.pem ({} bytes) to Ops/hvac-control-tls\n",
                pem().len()
            )
        );
        assert_eq!(show(&setting.db, "Ops/other"), other_before);
        let target_after = show(&setting.db, "Ops/hvac-control-tls");
        let expected = target_before.replace(
            "  old.pem (7 B)\n",
            &format!("  hvac22.pem ({} B)\n  old.pem (7 B)\n", pem().len()),
        );
        assert_ne!(expected, target_before, "the fixture lists old.pem");
        assert_eq!(sorted_lines(&target_after), sorted_lines(&expected));
        assert_eq!(
            attachment(&setting.db, "Ops/hvac-control-tls", "hvac22.pem"),
            pem()
        );
        assert_eq!(
            attachment(&setting.db, "Ops/hvac-control-tls", "old.pem"),
            b"old pem"
        );
        assert_eq!(&setting.db_bytes()[8..12], &fs::read(db).unwrap()[8..12]);
        assert_no_leak(&setting, &run, Keepassxc::Ran, &[]);
    }
}

/// A new entry in a KDBX 3.1 database. Red when the 3.1 export, which carries attachment bytes,
/// is read differently from a KDBX 4 one by the proof.
#[test]
fn a_new_entry_is_imported_into_a_kdbx_3_1_database() {
    let setting = Setting::new(&fixtures().kdbx31_db);
    stage_new(&setting);

    let run = run_import(&setting, &pinentry_tools(own_pinentry(17)), &[]);

    assert_eq!(run.exit, Exit::Success, "{}", run.stderr);
    assert_eq!(
        attachment(&setting.db, "Ops/mqtt", "ca.der"),
        binary_attachment()
    );
    assert_eq!(&setting.db_bytes()[8..12], KDBX31_VERSION);
    assert_no_leak(&setting, &run, Keepassxc::Ran, &[]);
}

fn sorted_lines(text: &str) -> Vec<&str> {
    let mut lines: Vec<&str> = text.lines().collect();
    lines.sort_unstable();
    lines
}

/// The largest attachment allowed, 16 MiB, round-trips exactly through the pipe; one byte
/// more is refused before anything runs. Red when the bound moves, or when the pipe is read
/// before its writer finished (a truncated attachment).
#[test]
fn a_16_mib_attachment_round_trips_and_one_byte_more_is_refused() {
    let largest: Vec<u8> = (0..16 * 1024 * 1024u32)
        .map(|i| u8::try_from(i % 251).unwrap())
        .collect();
    let manifest = r#"{"kind":"new","entry":"Ops/big","attachments":{"big.bin":"big"}}"#;

    let setting = Setting::new(&fixtures().db);
    setting.stage(manifest, &[("big", &largest)]);
    let run = run_import(&setting, &pinentry_tools(own_pinentry(2)), &[]);
    assert_eq!(run.exit, Exit::Success, "{}", run.stderr);
    assert!(attachment(&setting.db, "Ops/big", "big.bin") == largest);

    let too_large = Setting::new(&fixtures().db);
    let mut bytes = largest;
    bytes.push(0);
    too_large.stage(manifest, &[("big", &bytes)]);
    let run = run_import(&too_large, &pinentry_tools(own_pinentry(3)), &[]);
    assert_eq!(run.exit, Exit::Failure);
    assert!(
        run.stderr.contains("larger than 16777216 bytes"),
        "{}",
        run.stderr
    );
    assert_eq!(runs(own_pinentry(3)), 0);
}

/// Through `--password-gpg`: the master password is decrypted once, after the confirmation,
/// and every keepassxc-cli run gets it on stdin. Red when gpg runs before the confirmation, more
/// than once, or the decrypted password reaches anything printed.
#[test]
fn an_import_through_an_encrypted_password_decrypts_it_once_after_the_go() {
    let fixtures = fixtures();
    let setting = Setting::new(&fixtures.db);
    stage_new(&setting);
    let program = own_pinentry(18);
    let tools = tools(
        Prompter::Pinentry {
            program: program.to_owned(),
        },
        &fixtures.gpg_success.wrapper,
        &Disk,
    );

    let run = run_import(
        &setting,
        &tools,
        &["--password-gpg", fixtures.gpg_success_pw.to_str().unwrap()],
    );

    assert_eq!(run.exit, Exit::Success, "{}", run.stderr);
    assert_eq!(runs(&fixtures.gpg_success.wrapper), 1);
    assert_eq!(
        pinentry_log(program),
        ["SETTITLE", "SETDESC", "CONFIRM", "BYE"]
    );
    assert_eq!(
        attachment(&setting.db, "Ops/mqtt", "ca.der"),
        binary_attachment()
    );
    assert_no_leak(&setting, &run, Keepassxc::Ran, &[]);
}

/// A key-file-only database and a new entry with a password: keepassxc-cli's stdin carries the
/// entry's password alone, which is stored exactly. Red when a master password line is written
/// for a database that has none (keepassxc-cli would take it as the entry's password).
#[test]
fn a_key_file_only_database_gets_a_new_entry_with_its_password() {
    let fixtures = fixtures();
    let setting = Setting::new(&fixtures.key_file_only_db);
    stage_new(&setting);
    let program = own_pinentry(19);

    let run = run_import(
        &setting,
        &pinentry_tools(program),
        &[
            "--key-file",
            fixtures.key_file.to_str().unwrap(),
            "--no-password",
        ],
    );

    assert_eq!(run.exit, Exit::Success, "{}", run.stderr);
    assert!(!pinentry_log(program).contains(&"GETPIN".to_owned()));
    let shown = show_with(&setting.db, "Ops/mqtt", Opens::KeyFile(&fixtures.key_file));
    assert!(
        shown.contains(&format!(
            "Password: {}\n",
            String::from_utf8(password_file()).unwrap()
        )),
        "{shown}"
    );
    assert_no_leak(&setting, &run, Keepassxc::Ran, &[]);
}

/// The database's mode is kept by the replacement, whatever the umask. Red when the copy beside
/// it is created with a fixed mode.
#[test]
fn the_database_keeps_its_mode() {
    let setting = Setting::new(&fixtures().db);
    fs::set_permissions(&setting.db, fs::Permissions::from_mode(0o640)).unwrap();
    stage_existing(&setting);

    let run = run_import(&setting, &pinentry_tools(own_pinentry(20)), &[]);

    assert_eq!(run.exit, Exit::Success, "{}", run.stderr);
    assert_eq!(
        fs::metadata(&setting.db).unwrap().permissions().mode() & 0o7777,
        0o640
    );
}

/// With a `YubiKey` slot every run after the password dialog announces its touch, saying what
/// it does: comparing, adding the attachment, checking the entry. Red when a run is not
/// announced, or announced with another run's words.
#[test]
fn with_a_yubikey_every_run_is_announced_by_what_it_does() {
    let fixtures = fixtures();
    let setting = Setting::new(&fixtures.db);
    stage_existing(&setting);
    let program = own_pinentry(21);
    let mut tools = pinentry_tools(program);
    tools.unlock.keepassxc_cli = fixtures.keepassxc_without_yubikey.clone();

    let run = run_import(&setting, &tools, &["--yubikey", "2"]);

    assert_eq!(run.exit, Exit::Success, "{}", run.stderr);
    let db = fs::canonicalize(&setting.db).unwrap();
    let db = db.display();
    let touch = "%0AAfter you press OK, touch the YubiKey (slot 2) when it flashes.";
    let descriptions: Vec<String> = pinentry_lines(program)
        .into_iter()
        .filter(|line| line.starts_with("SETDESC kpx-share: unlock"))
        .collect();
    assert_eq!(
        descriptions,
        [
            format!(
                "SETDESC kpx-share: unlock {db} to import into entry Ops/hvac-control-tls%0AAfter the password, touch the YubiKey (slot 2) when it flashes."
            ),
            format!(
                "SETDESC kpx-share: unlock {db} again to add attachment \"hvac22.pem\" to entry Ops/hvac-control-tls{touch}"
            ),
            format!(
                "SETDESC kpx-share: unlock {db} again to check entry Ops/hvac-control-tls{touch}"
            ),
            format!(
                "SETDESC kpx-share: unlock {db} again to compare attachment \"hvac22.pem\" of entry Ops/hvac-control-tls{touch}"
            ),
        ]
    );
    let argv = String::from_utf8(setting.log("argv")).unwrap();
    assert!(
        !argv.contains("-y\0"),
        "the wrapper dropped the slot: {argv:?}"
    );
}

/// A confirmation with many attachments and a 1 KiB URL still fits one Assuan line, which the
/// fake pinentry, like pinentry, refuses beyond 1000 bytes. Red when the summary lists every
/// attachment, or shows a value uncut.
#[test]
fn a_large_import_still_fits_the_confirmation_line() {
    let setting = Setting::new(&fixtures().db);
    let names: Vec<String> = (0..40).map(|i| format!("certificate-{i:02}.pem")).collect();
    let attachments: Vec<String> = names
        .iter()
        .enumerate()
        .map(|(i, name)| format!(r#""{name}":"a{i}""#))
        .collect();
    let url = format!("https://h/{}", "p".repeat(1014));
    assert_eq!(url.len(), 1024);
    let manifest = format!(
        r#"{{"kind":"new","entry":"Ops/many","url":"{url}","attachments":{{{}}}}}"#,
        attachments.join(",")
    );
    let files: Vec<(String, Vec<u8>)> = (0..40)
        .map(|i| {
            (
                format!("a{i}"),
                format!("{ATTACHMENT_MARKER} {i}").into_bytes(),
            )
        })
        .collect();
    let files: Vec<(&str, &[u8])> = files
        .iter()
        .map(|(name, bytes)| (name.as_str(), bytes.as_slice()))
        .collect();
    setting.stage(&manifest, &files);
    let program = own_pinentry(22);

    let run = run_import(&setting, &pinentry_tools(program), &[]);

    assert_eq!(run.exit, Exit::Success, "{}", run.stderr);
    let lines = pinentry_lines(program);
    let longest = lines.iter().map(String::len).max().unwrap();
    assert!(longest < ASSUAN_LINE_BYTES_MAX, "{longest}");
    assert!(
        lines
            .iter()
            .any(|line| line.contains("and 37 more attachments")),
        "{lines:?}"
    );
    assert_no_leak(&setting, &run, Keepassxc::Ran, &[]);
}

// --- Refused before the go (S7) ---------------------------------------------------------------

/// How a case of [`every_input_rule_is_refused_before_anything_runs`] stages its mistake.
type Arrange = Box<dyn Fn(&Setting)>;

/// One input rule: what the agent got wrong, how it is staged, and what the refusal says.
type Case = (&'static str, Arrange, &'static str);

/// A manifest naming one password file, `pw.txt`.
const PLAIN: &str = r#"{"kind":"new","entry":"Ops/x","password":"pw.txt"}"#;

/// What the staging directory holds besides what the manifest names.
fn file_cases() -> Vec<Case> {
    vec![
        (
            "no manifest",
            Box::new(|s: &Setting| {
                s.stage(PLAIN, &[("pw.txt", STAGED_PASSWORD)]);
                fs::remove_file(s.staging().join("manifest.json")).unwrap();
            }),
            "manifest.json is not in the staging directory",
        ),
        (
            "a stray file",
            Box::new(|s: &Setting| {
                s.stage(PLAIN, &[("pw.txt", STAGED_PASSWORD), ("notes", b"n")]);
            }),
            "is not something the manifest names",
        ),
        (
            "a subdirectory",
            Box::new(|s: &Setting| {
                s.stage(PLAIN, &[("pw.txt", STAGED_PASSWORD)]);
                fs::create_dir(s.staging().join("sub")).unwrap();
            }),
            "is not something the manifest names",
        ),
        (
            "a symlinked file",
            Box::new(|s: &Setting| {
                s.stage(PLAIN, &[]);
                fs::write(s.runtime.path().join("elsewhere"), STAGED_PASSWORD).unwrap();
                std::os::unix::fs::symlink(
                    s.runtime.path().join("elsewhere"),
                    s.staging().join("pw.txt"),
                )
                .unwrap();
            }),
            "the file of the password is a symlink",
        ),
        (
            "a FIFO",
            Box::new(|s: &Setting| {
                s.stage(PLAIN, &[]);
                let fifo = s.staging().join("pw.txt");
                let made = Command::new("mkfifo").arg(&fifo).status().unwrap();
                assert!(made.success());
            }),
            "the file of the password is not a regular file",
        ),
        (
            "a missing file",
            Box::new(|s: &Setting| s.stage(PLAIN, &[])),
            "the file of the password is not in the staging directory",
        ),
    ]
}

/// What a staged value holds.
fn value_cases() -> Vec<Case> {
    vec![
        (
            "a CR in the password",
            Box::new(|s: &Setting| s.stage(PLAIN, &[("pw.txt", b"kpximp-pw-7c2e91\r")])),
            "holds a NUL, CR or LF byte",
        ),
        (
            "a NUL in the password",
            Box::new(|s: &Setting| s.stage(PLAIN, &[("pw.txt", b"kpximp-pw-7c2e91\0x")])),
            "holds a NUL, CR or LF byte",
        ),
        (
            "a password that is not UTF-8",
            Box::new(|s: &Setting| s.stage(PLAIN, &[("pw.txt", b"kpximp-pw-7c2e91\xff")])),
            "is not valid UTF-8",
        ),
        (
            "an empty password",
            Box::new(|s: &Setting| s.stage(PLAIN, &[("pw.txt", b"")])),
            "the file of the password is empty",
        ),
        (
            "a password over 4096 bytes",
            Box::new(|s: &Setting| s.stage(PLAIN, &[("pw.txt", &[b'a'; 4097])])),
            "larger than 4096 bytes",
        ),
        (
            "an empty attachment",
            Box::new(|s: &Setting| {
                s.stage(
                    r#"{"kind":"new","entry":"Ops/x","attachments":{"a":"a"}}"#,
                    &[("a", b"")],
                );
            }),
            "the file of attachment \"a\" is empty",
        ),
        (
            "an unknown manifest key",
            Box::new(|s: &Setting| {
                s.stage(
                    r#"{"kind":"new","entry":"Ops/x","password":"pw.txt","notes":"n"}"#,
                    &[("pw.txt", STAGED_PASSWORD)],
                );
            }),
            "a key this manifest does not have",
        ),
        (
            "a URL with a password in it",
            Box::new(|s: &Setting| {
                s.stage(
                    r#"{"kind":"new","entry":"Ops/x","url":"https://bob:pw@h/","password":"pw.txt"}"#,
                    &[("pw.txt", STAGED_PASSWORD)],
                );
            }),
            "holds a user name or password before '@'",
        ),
    ]
}

/// The directories and the database.
fn place_cases() -> Vec<Case> {
    vec![
        (
            "a staging directory open to the group",
            Box::new(|s: &Setting| {
                s.stage(PLAIN, &[("pw.txt", STAGED_PASSWORD)]);
                fs::set_permissions(s.staging(), fs::Permissions::from_mode(0o750)).unwrap();
            }),
            "it must be exactly 0700",
        ),
        (
            "a root open to the group",
            Box::new(|s: &Setting| {
                s.stage(PLAIN, &[("pw.txt", STAGED_PASSWORD)]);
                fs::set_permissions(s.root(), fs::Permissions::from_mode(0o755)).unwrap();
            }),
            "it must be exactly 0700",
        ),
        (
            "a symlinked staging directory",
            Box::new(|s: &Setting| {
                let real = s.root().join("real");
                fs::create_dir(&real).unwrap();
                fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).unwrap();
                fs::write(real.join("manifest.json"), PLAIN).unwrap();
                fs::write(real.join("pw.txt"), STAGED_PASSWORD).unwrap();
                std::os::unix::fs::symlink(&real, s.staging()).unwrap();
            }),
            "is a symlink, not a directory",
        ),
        (
            "a staging name that is a file",
            Box::new(|s: &Setting| fs::write(s.staging(), PLAIN).unwrap()),
            "is not a directory",
        ),
        (
            "nothing staged",
            Box::new(|_: &Setting| {}),
            "nothing is staged",
        ),
        (
            "a hard-linked database",
            Box::new(|s: &Setting| {
                s.stage(PLAIN, &[("pw.txt", STAGED_PASSWORD)]);
                fs::hard_link(&s.db, s.runtime.path().join("db/second.kdbx")).unwrap();
            }),
            "has 2 hard links",
        ),
    ]
}

/// Every input rule refuses with nothing run: no pinentry (so no confirmation and no password
/// dialog), no gpg, no keepassxc-cli; the database and the staging directory as they were (put
/// back after the claim). Red when any one check is dropped (that case then reaches the
/// confirmation), moved after it, or the claimed directory is not put back.
#[test]
fn every_input_rule_is_refused_before_anything_runs() {
    let fixtures = fixtures();
    let gpg_args = ["--password-gpg", fixtures.gpg_rules_pw.to_str().unwrap()];
    let cases = [file_cases(), value_cases(), place_cases()]
        .into_iter()
        .flatten();
    for (what, arrange, message) in cases {
        let setting = Setting::new(&fixtures.db);
        arrange(&setting);
        let db_before = setting.db_bytes();
        let staged_before = listing(&setting.staging());
        let tools = tools(
            Prompter::Pinentry {
                program: fixtures.pinentry_rules.clone(),
            },
            &fixtures.gpg_rules.wrapper,
            &Disk,
        );

        let run = run_import(&setting, &tools, &gpg_args);

        assert_eq!(run.exit, Exit::Failure, "{what}: {}", run.stderr);
        assert!(run.stderr.contains(message), "{what}: {}", run.stderr);
        assert!(
            run.stderr
                .ends_with("kpx-share: the database is unchanged\n"),
            "{what}: {}",
            run.stderr
        );
        assert_eq!(run.stdout, "", "{what}");
        assert_eq!(setting.db_bytes(), db_before, "{what}");
        assert_eq!(listing(&setting.staging()), staged_before, "{what}");
        assert_no_leak(&setting, &run, Keepassxc::NeverRan, &[]);
    }
    assert_eq!(runs(&fixtures.pinentry_rules), 0);
    assert_eq!(runs(&fixtures.gpg_rules.wrapper), 0);
}

/// Declining the confirmation ends the import there: exit 130, gpg never run, no password
/// asked for, the database and the staging directory untouched (put back under its name). Red
/// when the password is decrypted (or keepassxc-cli run) before the confirmation, a declined one
/// is taken as yes, or the staging directory is left claimed.
#[test]
fn declining_the_confirmation_decrypts_nothing_and_changes_nothing() {
    let fixtures = fixtures();
    let setting = Setting::new(&fixtures.db);
    stage_new(&setting);
    let db_before = setting.db_bytes();
    let tools = tools(
        Prompter::Pinentry {
            program: fixtures.pinentry_declines.clone(),
        },
        &fixtures.gpg_cancel.wrapper,
        &Disk,
    );

    let run = run_import(
        &setting,
        &tools,
        &["--password-gpg", fixtures.gpg_cancel_pw.to_str().unwrap()],
    );

    assert_eq!(run.exit, Exit::Cancelled, "{}", run.stderr);
    assert_eq!(runs(&fixtures.gpg_cancel.wrapper), 0);
    assert_eq!(runs(&fixtures.pinentry_declines), 1);
    let sent = pinentry_log(&fixtures.pinentry_declines);
    assert!(sent.contains(&"CONFIRM".to_owned()), "{sent:?}");
    assert!(!sent.contains(&"GETPIN".to_owned()), "{sent:?}");
    assert_eq!(setting.db_bytes(), db_before);
    assert_staging_intact(&setting, &["manifest.json", "pw.txt", "ca"]);
    assert_no_leak(&setting, &run, Keepassxc::NeverRan, &[]);
}

/// pinentry's "not confirmed" (`ERR 83886194`) is a no, as a cancel is: exit 130, no password
/// asked for, nothing changed. Red when it is taken as a failure (exit 1) or a yes.
#[test]
fn not_confirmed_is_a_decline() {
    let fixtures = fixtures();
    let setting = Setting::new(&fixtures.db);
    stage_existing(&setting);
    let db_before = setting.db_bytes();

    let run = run_import(
        &setting,
        &pinentry_tools(&fixtures.pinentry_not_confirmed),
        &[],
    );

    assert_eq!(run.exit, Exit::Cancelled, "{}", run.stderr);
    assert_eq!(runs(&fixtures.pinentry_not_confirmed), 1);
    let sent = pinentry_log(&fixtures.pinentry_not_confirmed);
    assert!(sent.contains(&"CONFIRM".to_owned()), "{sent:?}");
    assert!(!sent.contains(&"GETPIN".to_owned()), "{sent:?}");
    assert_eq!(setting.db_bytes(), db_before);
    assert_staging_intact(&setting, &["manifest.json", "pem"]);
    assert_no_leak(&setting, &run, Keepassxc::NeverRan, &[]);
}

/// Cancelling the password dialog after confirming is a decline too: exit 130, keepassxc-cli
/// never run, nothing changed, the staging directory back. Red when the cancel is taken as a
/// failure, or the claimed directory is not put back.
#[test]
fn cancelling_the_password_dialog_is_a_decline() {
    let fixtures = fixtures();
    let setting = Setting::new(&fixtures.db);
    stage_existing(&setting);
    let db_before = setting.db_bytes();

    let run = run_import(
        &setting,
        &pinentry_tools(&fixtures.pinentry_getpin_cancelled),
        &[],
    );

    assert_eq!(run.exit, Exit::Cancelled, "{}", run.stderr);
    assert!(pinentry_log(&fixtures.pinentry_getpin_cancelled).contains(&"GETPIN".to_owned()));
    assert_eq!(setting.db_bytes(), db_before);
    assert_staging_intact(&setting, &["manifest.json", "pem"]);
    assert_no_leak(&setting, &run, Keepassxc::NeverRan, &[]);
}

/// Holds `dir`'s lock in a child `flock` process, as a concurrent import in another process would;
/// released when the child's stdin closes.
struct HeldLock(Child);

impl HeldLock {
    fn take(dir: &Path) -> Self {
        let mut child = Command::new("flock")
            .args(["-n", "-o"])
            .arg(dir)
            .args(["sh", "-c", "echo held; exec cat"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("util-linux flock must be installed for these tests");
        let mut line = String::new();
        BufReader::new(child.stdout.as_mut().unwrap())
            .read_line(&mut line)
            .unwrap();
        assert_eq!(line, "held\n", "flock could not take the lock");
        Self(child)
    }

    fn release(mut self) {
        drop(self.0.stdin.take());
        assert!(self.0.wait().unwrap().success());
    }
}

/// While another import holds the root's lock, an import refuses at once (exit 1) and touches
/// nothing: no confirmation, no keepassxc-cli, the database, the staging directory and the
/// other import's work directory as they were. Red when the lock is not taken, or taken after
/// the stale work directories are removed.
#[test]
fn an_import_refuses_while_another_holds_the_lock() {
    let setting = Setting::new(&fixtures().db);
    stage_existing(&setting);
    let others = setting.root().join(".work-00000000000000aa");
    fs::create_dir(&others).unwrap();
    fs::write(others.join("db.kdbx"), b"the other import's copy").unwrap();
    let db_before = setting.db_bytes();
    let held = HeldLock::take(&setting.root());
    let program = own_pinentry(15);

    let run = run_import(&setting, &pinentry_tools(program), &[]);

    assert_eq!(run.exit, Exit::Failure, "{}", run.stderr);
    assert!(
        run.stderr.contains("another import is running"),
        "{}",
        run.stderr
    );
    assert_eq!(runs(program), 0);
    assert_eq!(String::from_utf8_lossy(&setting.log("argv")), "");
    assert_eq!(setting.db_bytes(), db_before);
    assert_staging_intact(&setting, &["manifest.json", "pem"]);
    assert_eq!(
        fs::read(others.join("db.kdbx")).unwrap(),
        b"the other import's copy"
    );

    held.release();
    let run = run_import(&setting, &pinentry_tools(program), &[]);
    assert_eq!(run.exit, Exit::Success, "{}", run.stderr);
    assert!(
        !others.exists(),
        "a stale work directory is removed once the lock is free"
    );
}

/// The lock is held through every keepassxc-cli run, and no run inherits a descriptor on the
/// root, the claimed directory or the work directory. Red when the lock is dropped early, or its
/// descriptor (or any other kpx-share opens) is not close-on-exec.
#[test]
fn the_lock_is_held_for_the_whole_run_and_no_child_inherits_it() {
    let setting = Setting::new(&fixtures().db);
    stage_new(&setting);

    let run = run_import(&setting, &pinentry_tools(own_pinentry(23)), &[]);

    assert_eq!(run.exit, Exit::Success, "{}", run.stderr);
    let lock = setting.log_lines("lock");
    assert!(lock.len() >= 4, "{lock:?}");
    assert!(lock.iter().all(|state| state == "busy"), "{lock:?}");
    assert_ne!(
        setting.log_lines("fds"),
        [] as [String; 0],
        "the descriptors were logged"
    );
    assert_no_leak(&setting, &run, Keepassxc::Ran, &[]);
}

/// The confirmation names the database, the entry, its fields and that they are program
/// arguments, and each item's size, and comes before the password dialog. Red when the dialogs
/// are swapped, the summary shows a value, or the argument notice is gone.
#[test]
fn the_confirmation_comes_first_and_shows_names_and_sizes_only() {
    let setting = Setting::new(&fixtures().db);
    stage_new(&setting);
    let program = own_pinentry(4);

    let run = run_import(&setting, &pinentry_tools(program), &[]);

    assert_eq!(run.exit, Exit::Success, "{}", run.stderr);
    let sent = pinentry_log(program);
    let confirm = sent.iter().position(|line| line == "CONFIRM");
    let getpin = sent.iter().position(|line| line == "GETPIN");
    assert!(confirm.is_some() && confirm < getpin, "{sent:?}");
    let description = pinentry_lines(program)
        .into_iter()
        .find(|line| line.starts_with("SETDESC kpx-share: import into"))
        .unwrap();
    let canonical = fs::canonicalize(&setting.db).unwrap();
    assert_eq!(
        description,
        format!(
            "SETDESC kpx-share: import into {}%0Anew entry Ops/mqtt%0Ausername: broker%0AURL: mqtts://h:8883%0Apassword: {} bytes%0A(the username and URL reach keepassxc-cli as program arguments)%0Aattachment ca.der: {} bytes%0A%0AImport this into the database?",
            canonical.display(),
            password_file().len(),
            binary_attachment().len()
        )
    );
    assert_no_leak(&setting, &run, Keepassxc::Ran, &[]);
}

/// On a terminal a typed master password cannot be piped beside the entry's: refused before the
/// confirmation, with the way out. Red when it gets as far as asking.
#[test]
fn a_typed_password_on_a_terminal_is_refused_before_the_confirmation() {
    let setting = Setting::new(&fixtures().db);
    stage_new(&setting);
    let tty = setting.runtime.path().join("tty");
    fs::write(&tty, "y\n").unwrap();
    let mut tools = tools(Prompter::Terminal, Path::new("/nonexistent/gpg"), &Disk);
    tools.tty = tty;

    let run = run_import(&setting, &tools, &[]);

    assert_eq!(run.exit, Exit::Failure);
    assert!(run.stderr.contains("--password-gpg"), "{}", run.stderr);
    assert!(!run.stderr.contains("Import this"), "{}", run.stderr);
    assert_staging_intact(&setting, &["manifest.json", "pw.txt", "ca"]);
    assert_no_leak(&setting, &run, Keepassxc::NeverRan, &[]);
}

/// On a terminal the summary goes to stderr and the answer is read from the terminal: `y`
/// imports, anything else declines with 130. Red when the answer is not read, or read wrongly.
#[test]
fn on_a_terminal_the_answer_is_read_from_the_tty() {
    let fixtures = fixtures();
    for (answer, exit) in [
        ("y\n", Exit::Success),
        ("no\n", Exit::Cancelled),
        ("", Exit::Cancelled),
    ] {
        let setting = Setting::new(&fixtures.key_file_only_db);
        stage_existing(&setting);
        let tty = setting.runtime.path().join("tty");
        fs::write(&tty, answer).unwrap();
        let mut tools = tools(Prompter::Terminal, Path::new("/nonexistent/gpg"), &Disk);
        tools.tty = tty;

        let run = run_import(
            &setting,
            &tools,
            &[
                "--key-file",
                fixtures.key_file.to_str().unwrap(),
                "--no-password",
            ],
        );

        assert_eq!(run.exit, exit, "{answer:?}: {}", run.stderr);
        assert!(
            run.stderr.contains("existing entry Ops/hvac-control-tls\n"),
            "{}",
            run.stderr
        );
        assert!(
            run.stderr.contains("Import this into the database? [y/N] "),
            "{}",
            run.stderr
        );
        let ran = if exit == Exit::Success {
            Keepassxc::Ran
        } else {
            Keepassxc::NeverRan
        };
        assert_no_leak(&setting, &run, ran, &[]);
    }
}

// --- Refused after the go: nothing changed ----------------------------------------------------

/// A wrong master password: exit 1, nothing changed, and the wrong password itself printed
/// nowhere. Red when keepassxc-cli's stdin, or the password, reaches an error message.
#[test]
fn a_wrong_master_password_changes_nothing_and_leaks_nothing() {
    let setting = Setting::new(&fixtures().db);
    stage_new(&setting);
    let db_before = setting.db_bytes();

    let run = run_import(&setting, &pinentry_tools(&fixtures().pinentry_wrong), &[]);

    assert_eq!(run.exit, Exit::Failure);
    assert!(run.stderr.contains("invalid credentials"), "{}", run.stderr);
    assert_eq!(setting.db_bytes(), db_before);
    assert_staging_intact(&setting, &["manifest.json", "pw.txt", "ca"]);
    assert_no_leak(&setting, &run, Keepassxc::Ran, &["wrong-master-5e1d"]);
}

/// A new entry where one already is, holding other values: refused by the preflight, nothing
/// written, the staging directory back. Red when the preflight lets it through (keepassxc-cli
/// would then refuse, with another message), or treats it as already done (the staging
/// directory would be deleted).
#[test]
fn a_new_entry_at_a_taken_path_is_refused_and_nothing_changes() {
    let setting = Setting::new(&fixtures().db);
    setting.stage(
        r#"{"kind":"new","entry":"Ops/other","password":"pw.txt"}"#,
        &[("pw.txt", &password_file())],
    );
    let db_before = setting.db_bytes();

    let run = run_import(&setting, &pinentry_tools(own_pinentry(5)), &[]);

    assert_eq!(run.exit, Exit::Failure);
    assert!(
        run.stderr.contains("entry Ops/other already exists"),
        "{}",
        run.stderr
    );
    assert_eq!(setting.db_bytes(), db_before);
    assert_staging_intact(&setting, &["manifest.json", "pw.txt"]);
    assert_no_leak(&setting, &run, Keepassxc::Ran, &[]);
}

/// An entry whose history is at the database's limit: the attachment would push its oldest
/// version out, so the import is refused, naming the setting, and the file is byte-unchanged.
/// Red without the history check of the proof.
#[test]
fn an_entry_at_its_history_limit_is_refused_and_the_file_is_unchanged() {
    let setting = Setting::new(&fixtures().history_db);
    setting.stage(
        r#"{"kind":"existing","entry":"Ops/full","attachments":{"a.pem":"a"}}"#,
        &[("a", &pem())],
    );
    let db_before = setting.db_bytes();

    let run = run_import(&setting, &pinentry_tools(own_pinentry(6)), &[]);

    assert_eq!(run.exit, Exit::Failure);
    assert!(
        run.stderr
            .contains("dropped old history versions of entry Ops/full"),
        "{}",
        run.stderr
    );
    assert!(run.stderr.contains("Database Settings"), "{}", run.stderr);
    assert_eq!(setting.db_bytes(), db_before);
    assert_staging_intact(&setting, &["manifest.json", "a"]);
    assert_no_leak(&setting, &run, Keepassxc::Ran, &[]);
}

/// The copy changing after it was read for the proof (here: a byte appended after the last
/// attachment comparison) is refused: what would be committed is not what was proven. Red
/// without the second read of the copy.
#[test]
fn a_copy_that_changes_during_the_proof_is_not_committed() {
    let setting = Setting::new(&fixtures().db);
    setting.hooks("TOUCH_COPY='attachment-export'\n");
    stage_existing(&setting);
    let db_before = setting.db_bytes();

    let run = run_import(&setting, &pinentry_tools(own_pinentry(24)), &[]);

    assert_eq!(run.exit, Exit::Failure, "{}", run.stderr);
    assert!(
        run.stderr.contains("the copy changed while it was checked"),
        "{}",
        run.stderr
    );
    assert_eq!(setting.db_bytes(), db_before);
    assert_staging_intact(&setting, &["manifest.json", "pem"]);
    assert_no_leak(&setting, &run, Keepassxc::Ran, &[]);
}

/// The live file saved by someone else between the copy and the commit (S2): refused, and the
/// file keeps what the other save wrote. Red when the commit does not compare the file with the
/// bytes first read.
#[test]
fn a_database_saved_during_the_import_is_kept_as_saved() {
    let setting = Setting::new(&fixtures().db);
    setting.hooks(&format!(
        "CONCURRENT='{}'\n",
        fixtures().concurrent_db.display()
    ));
    stage_existing(&setting);

    let run = run_import(&setting, &pinentry_tools(own_pinentry(7)), &[]);

    assert_eq!(run.exit, Exit::Failure, "{}", run.stderr);
    assert!(
        run.stderr.contains("changed during the import"),
        "{}",
        run.stderr
    );
    assert_eq!(
        setting.db_bytes(),
        fs::read(&fixtures().concurrent_db).unwrap()
    );
    assert_staging_intact(&setting, &["manifest.json", "pem"]);
    assert_no_leak(&setting, &run, Keepassxc::Ran, &[]);
}

/// The live database's files, truthful but for one thing a test asks: what happens at the read
/// numbered `at` (1 the first read, 2 the read right before the rename, 3 the read back), or
/// whether writing the copy beside the database fails.
#[derive(Debug, Default)]
struct Meddling {
    reads: Cell<usize>,
    /// Whether the copy beside the database existed at the second read.
    copy_seen_at_second_read: Cell<bool>,
    at_second_read: RefCell<Option<SecondRead>>,
    lie_at_read_back: bool,
    fail_write: bool,
}

#[derive(Debug)]
enum SecondRead {
    /// Another save lands: the file gets these bytes just before it is read.
    Save(Vec<u8>),
    /// The file is replaced by a directory after it is read, so the rename fails.
    BecomeDirectory,
}

impl DatabaseFiles for Meddling {
    fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        self.reads.set(self.reads.get() + 1);
        if self.reads.get() == 2 {
            let dir = path.parent().unwrap();
            self.copy_seen_at_second_read.set(
                listing(dir)
                    .iter()
                    .any(|name| name.contains(".kpx-import-")),
            );
            match self.at_second_read.borrow_mut().take() {
                Some(SecondRead::Save(bytes)) => fs::write(path, bytes)?,
                Some(SecondRead::BecomeDirectory) => {
                    let bytes = Disk.read(path)?;
                    fs::remove_file(path)?;
                    fs::create_dir(path)?;
                    fs::write(path.join("inside"), b"x")?;
                    return Ok(bytes);
                }
                None => {}
            }
        }
        let mut bytes = Disk.read(path)?;
        if self.lie_at_read_back && self.reads.get() == 3 {
            if let Some(last) = bytes.last_mut() {
                *last ^= 1;
            }
        }
        Ok(bytes)
    }

    fn write(&self, file: &mut fs::File, bytes: &[u8]) -> io::Result<()> {
        if self.fail_write {
            file.write_all(bytes.get(..10).unwrap_or(bytes))?;
            return Err(io::Error::other("the disk is full (simulated)"));
        }
        Disk.write(file, bytes)
    }

    fn sync(&self, file: &fs::File) -> io::Result<()> {
        Disk.sync(file)
    }

    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        Disk.rename(from, to)
    }

    fn sync_dir(&self, dir: &Path) -> io::Result<()> {
        Disk.sync_dir(dir)
    }
}

/// The live database's files as they are, with each call recorded by name, in order.
#[derive(Debug, Default)]
struct Recording(RefCell<Vec<&'static str>>);

impl DatabaseFiles for Recording {
    fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        self.0.borrow_mut().push("read");
        Disk.read(path)
    }

    fn write(&self, file: &mut fs::File, bytes: &[u8]) -> io::Result<()> {
        self.0.borrow_mut().push("write");
        Disk.write(file, bytes)
    }

    fn sync(&self, file: &fs::File) -> io::Result<()> {
        self.0.borrow_mut().push("sync");
        Disk.sync(file)
    }

    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        self.0.borrow_mut().push("rename");
        Disk.rename(from, to)
    }

    fn sync_dir(&self, dir: &Path) -> io::Result<()> {
        self.0.borrow_mut().push("sync dir");
        Disk.sync_dir(dir)
    }
}

/// The commit's steps in their order: the first read, the copy written beside the database and
/// synced, the read that compares, the rename, the directory synced, the read back. Red when a
/// sync is skipped, or a step moves.
#[test]
fn the_commit_writes_syncs_compares_renames_and_syncs_the_directory_in_that_order() {
    let setting = Setting::new(&fixtures().db);
    stage_existing(&setting);
    let files = Recording::default();
    let tools = tools(
        Prompter::Pinentry {
            program: own_pinentry(34).to_owned(),
        },
        Path::new("/nonexistent/gpg"),
        &files,
    );

    let run = run_import(&setting, &tools, &[]);

    assert_eq!(run.exit, Exit::Success, "{}", run.stderr);
    assert_eq!(
        *files.0.borrow(),
        [
            "read", "write", "sync", "read", "rename", "sync dir", "read"
        ]
    );
}

/// Files of the database's own beside it, even dotfiles that start like a copy of ours, outlive
/// the sweep of stale copies, which removes only exactly the prefix and 16 lower-case hex
/// digits. Red when the sweep matches by prefix alone, by another digit count, or ignores what
/// follows the digits.
#[test]
fn files_beside_the_database_that_are_not_stale_copies_are_kept() {
    let setting = Setting::new(&fixtures().db);
    let db_dir = setting.runtime.path().join("db");
    let keep = [
        ".gitignore",
        ".db.kdbx.lock",
        ".db.kdbx.kpx-import-notours",
        ".db.kdbx.kpx-import-0123456789ABCDEF",
        ".db.kdbx.kpx-import-0123456789abcde",
        ".db.kdbx.kpx-import-0123456789abcdef.bak",
    ];
    let stale = ".db.kdbx.kpx-import-0123456789abcdef";
    for name in keep.iter().chain([&stale]) {
        fs::write(db_dir.join(name), b"x").unwrap();
    }
    stage_existing(&setting);

    let run = run_import(&setting, &pinentry_tools(own_pinentry(35)), &[]);

    assert_eq!(run.exit, Exit::Success, "{}", run.stderr);
    for name in keep {
        assert!(db_dir.join(name).exists(), "{name}");
    }
    assert!(!db_dir.join(stale).exists(), "{stale}");
}

fn meddling_tools(files: &Meddling, program: usize) -> ImportTools<'_> {
    tools(
        Prompter::Pinentry {
            program: own_pinentry(program).to_owned(),
        },
        Path::new("/nonexistent/gpg"),
        files,
    )
}

/// A save landing after the copy is written beside the database but before the rename (S2):
/// the file is read only then, so the save is seen, kept, and the copy removed. Red when the
/// file is compared before the copy is written (the window is then the whole write), or the
/// copy is left behind.
#[test]
fn a_save_after_the_copy_is_written_is_seen_and_kept() {
    let setting = Setting::new(&fixtures().db);
    stage_existing(&setting);
    let saved = fs::read(&fixtures().concurrent_db).unwrap();
    let files = Meddling {
        at_second_read: RefCell::new(Some(SecondRead::Save(saved.clone()))),
        ..Meddling::default()
    };

    let run = run_import(&setting, &meddling_tools(&files, 25), &[]);

    assert_eq!(run.exit, Exit::Failure, "{}", run.stderr);
    assert!(
        files.copy_seen_at_second_read.get(),
        "the copy is written first"
    );
    assert!(
        run.stderr.contains("changed during the import"),
        "{}",
        run.stderr
    );
    assert_eq!(setting.db_bytes(), saved);
    assert_staging_intact(&setting, &["manifest.json", "pem"]);
    assert_no_leak(&setting, &run, Keepassxc::Ran, &[]);
}

/// The copy beside the database is removed when writing it fails, and when renaming it onto the
/// database fails; the database is left as it was. Red when either path leaves the copy.
#[test]
fn a_failed_write_or_rename_removes_the_copy_beside_the_database() {
    let setting = Setting::new(&fixtures().db);
    stage_existing(&setting);
    let db_before = setting.db_bytes();
    let failing_write = Meddling {
        fail_write: true,
        ..Meddling::default()
    };
    let run = run_import(&setting, &meddling_tools(&failing_write, 26), &[]);
    assert_eq!(run.exit, Exit::Failure, "{}", run.stderr);
    assert!(run.stderr.contains("disk is full"), "{}", run.stderr);
    assert_eq!(setting.db_bytes(), db_before);
    assert_no_leak(&setting, &run, Keepassxc::Ran, &[]);

    let setting = Setting::new(&fixtures().db);
    stage_existing(&setting);
    let failing_rename = Meddling {
        at_second_read: RefCell::new(Some(SecondRead::BecomeDirectory)),
        ..Meddling::default()
    };
    let run = run_import(&setting, &meddling_tools(&failing_rename, 27), &[]);
    assert_eq!(run.exit, Exit::Failure, "{}", run.stderr);
    assert!(run.stderr.contains("cannot rename"), "{}", run.stderr);
    assert!(setting.db.is_dir(), "what the rename met is left as it was");
    assert_no_leak(&setting, &run, Keepassxc::Ran, &[]);
}

/// A read-back that differs from what was written (S3): exit 3, said so, and the staged files
/// kept, back under their name, since the database is not proven to hold them. Red when the
/// read-back is skipped or not compared, or the staging directory is removed anyway.
#[test]
fn a_read_back_that_differs_exits_3_and_keeps_the_staged_files() {
    let setting = Setting::new(&fixtures().db);
    stage_existing(&setting);
    let files = Meddling {
        lie_at_read_back: true,
        ..Meddling::default()
    };

    let run = run_import(&setting, &meddling_tools(&files, 8), &[]);

    assert_eq!(run.exit, Exit::ReplacedUnverified, "{}", run.stderr);
    assert_eq!(files.reads.get(), 3);
    assert!(
        run.stderr
            .contains("was replaced, but reading it back gave other bytes"),
        "{}",
        run.stderr
    );
    assert_eq!(run.stdout, "");
    assert_staging_intact(&setting, &["manifest.json", "pem"]);
    assert_no_leak(&setting, &run, Keepassxc::Ran, &[]);
}

/// stdout that cannot be written after the import is done: the import still succeeded, so the
/// exit is 0 and stderr says what happened, never "the database is unchanged". Red when the
/// write failure is turned into a failed import.
#[test]
fn an_unwritable_stdout_after_the_import_still_exits_0() {
    struct Broken;
    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let setting = Setting::new(&fixtures().db);
    stage_existing(&setting);
    let mut stderr = Vec::new();

    let exit = import_into(
        &setting,
        &setting.db,
        &pinentry_tools(own_pinentry(28)),
        &[],
        &mut Broken,
        &mut stderr,
    );

    let stderr = String::from_utf8(stderr).unwrap();
    assert_eq!(exit, Exit::Success, "{stderr}");
    assert!(
        stderr.contains("cannot write what was imported to stdout"),
        "{stderr}"
    );
    assert!(!stderr.contains("unchanged"), "{stderr}");
    assert_eq!(
        attachment(&setting.db, "Ops/hvac-control-tls", "hvac22.pem"),
        pem()
    );
}

// --- How the database is written (S2) ---------------------------------------------------------

/// The live file is never touched until the commit, which replaces it by a rename: same inode
/// and modification time at every keepassxc-cli run, a new inode after. Red when keepassxc-cli
/// runs on the live file instead of the copy, or the file is written in place.
#[test]
fn the_database_is_untouched_until_one_rename_replaces_it() {
    let setting = Setting::new(&fixtures().db);
    let inode_before = fs::metadata(&setting.db).unwrap().ino();
    stage_existing(&setting);

    let run = run_import(&setting, &pinentry_tools(own_pinentry(9)), &[]);

    assert_eq!(run.exit, Exit::Success, "{}", run.stderr);
    let states = setting.log_lines("live");
    assert!(states.len() >= 4, "{states:?}");
    assert!(states.iter().all(|state| *state == states[0]), "{states:?}");
    assert!(
        states[0].starts_with(&format!("{inode_before} ")),
        "{states:?}"
    );
    assert_ne!(fs::metadata(&setting.db).unwrap().ino(), inode_before);
    let argv = String::from_utf8(setting.log("argv")).unwrap();
    assert!(
        !argv.split('\0').any(|arg| Path::new(arg) == setting.db),
        "keepassxc-cli opened the live file: {argv:?}"
    );
}

/// A database reached through a symlink: the link's target is replaced, the link stays a link.
/// Red when the rename goes onto the configured path (the link) instead of the resolved one.
#[test]
fn a_symlinked_database_is_replaced_at_its_target_and_the_link_kept() {
    let setting = Setting::new(&fixtures().db);
    let link = setting.runtime.path().join("db/link.kdbx");
    std::os::unix::fs::symlink(&setting.db, &link).unwrap();
    stage_existing(&setting);

    let run = run_import_from(&setting, &link, &pinentry_tools(own_pinentry(10)), &[]);

    assert_eq!(run.exit, Exit::Success, "{}", run.stderr);
    assert!(fs::symlink_metadata(&link).unwrap().is_symlink());
    assert_eq!(fs::read_link(&link).unwrap(), setting.db);
    assert_eq!(
        attachment(&setting.db, "Ops/hvac-control-tls", "hvac22.pem"),
        pem()
    );
}

// --- The staged files (S4, S6) ----------------------------------------------------------------

/// Run again after the database already holds everything (as after a crash between the rename
/// and the cleanup): nothing written, said so, and the staging directory deleted. Red when the
/// preflight does not recognise it (the rerun would fail on the existing attachment).
#[test]
fn a_rerun_finds_everything_already_there_and_only_cleans_up() {
    let setting = Setting::new(&fixtures().db);
    stage_new(&setting);
    let first = run_import(&setting, &pinentry_tools(own_pinentry(11)), &[]);
    assert_eq!(first.exit, Exit::Success, "{}", first.stderr);
    let db_after_first = setting.db_bytes();
    stage_new(&setting);

    let run = run_import(&setting, &pinentry_tools(own_pinentry(12)), &[]);

    assert_eq!(run.exit, Exit::Success, "{}", run.stderr);
    assert_eq!(
        run.stdout,
        format!(
            "already in the database: entry Ops/mqtt (password {} bytes)\n\
             already in the database: attachment ca.der ({} bytes) to Ops/mqtt\n",
            password_file().len(),
            binary_attachment().len()
        )
    );
    assert_eq!(setting.db_bytes(), db_after_first);
    assert!(!setting.staging().exists());
    assert_no_leak(&setting, &run, Keepassxc::Ran, &[]);
}

/// A file that appears in the claimed directory while the import runs is not the import's:
/// left, the directory put back under its name, and reported, while the files read are deleted
/// and the exit is still 0. Red when the staging directory is removed whole.
#[test]
fn a_file_added_during_the_import_is_left_and_reported() {
    let setting = Setting::new(&fixtures().db);
    setting.hooks("LATE='late.txt'\n");
    stage_existing(&setting);

    let run = run_import(&setting, &pinentry_tools(own_pinentry(13)), &[]);

    assert_eq!(run.exit, Exit::Success, "{}", run.stderr);
    assert_staging_intact(&setting, &["late.txt"]);
    assert!(
        run.stderr.contains(&format!(
            "left {}: it appeared during the import",
            setting.staging().join("late.txt").display()
        )),
        "{}",
        run.stderr
    );
    assert_no_leak(&setting, &run, Keepassxc::Ran, &[]);
}

/// A staged file rewritten after it was read, in place or by a rename over it, changes nothing
/// that was imported (S6), and is not deleted, since its new bytes are in no database (S4): it
/// is kept, back under the staging directory's name, and reported. Red when a staged file is
/// read again after the confirmation, or deleted without comparing it with what was read.
#[test]
fn a_staged_file_rewritten_during_the_import_is_kept_not_deleted() {
    for (hook, now, program) in [
        ("REWRITE", &b"rewritten in place after it was read"[..], 14),
        ("REPLACE", &b"replaced after it was read"[..], 29),
    ] {
        let setting = Setting::new(&fixtures().db);
        setting.hooks(&format!("{hook}='pem'\n"));
        stage_existing(&setting);

        let run = run_import(&setting, &pinentry_tools(own_pinentry(program)), &[]);

        assert_eq!(run.exit, Exit::Success, "{hook}: {}", run.stderr);
        assert_eq!(
            attachment(&setting.db, "Ops/hvac-control-tls", "hvac22.pem"),
            pem(),
            "{hook}"
        );
        assert_staging_intact(&setting, &["pem"]);
        assert_eq!(
            fs::read(setting.staging().join("pem")).unwrap(),
            now,
            "{hook}"
        );
        assert!(
            run.stderr.contains(
                "kept the file of attachment \"hvac22.pem\": it changed during the import"
            ),
            "{hook}: {}",
            run.stderr
        );
        assert_no_leak(&setting, &run, Keepassxc::Ran, &[]);
    }
}

/// Once claimed, the staging directory is out of the agent's reach: a write to a staged file's
/// path fails instead of landing in a file the cleanup would delete. Red when the directory is
/// read where it is rather than claimed first.
#[test]
fn the_agents_path_stops_reaching_the_claimed_files() {
    let setting = Setting::new(&fixtures().db);
    setting.hooks("AGENT_WRITE='pem'\n");
    stage_existing(&setting);

    let run = run_import(&setting, &pinentry_tools(own_pinentry(30)), &[]);

    assert_eq!(run.exit, Exit::Success, "{}", run.stderr);
    assert_eq!(setting.log_lines("agent-write"), ["failed"]);
    assert!(!setting.staging().exists());
    assert_no_leak(&setting, &run, Keepassxc::Ran, &[]);
}

/// When the import fails and the agent has made a new directory under the staging name
/// meanwhile, the claimed one is not moved over it: it is kept where it is, and its path
/// reported, so the staged secrets are neither lost nor mixed in. Red when that is not reported.
#[test]
fn a_claimed_directory_that_cannot_go_back_is_kept_and_reported() {
    let setting = Setting::new(&fixtures().db);
    setting.hooks("RECREATE=1\n");
    stage_existing(&setting);

    let run = run_import(&setting, &pinentry_tools(&fixtures().pinentry_wrong), &[]);

    assert_eq!(run.exit, Exit::Failure, "{}", run.stderr);
    let claimed: Vec<String> = listing(&setting.root())
        .into_iter()
        .filter(|name| name.starts_with(".claimed."))
        .collect();
    let [claimed] = claimed.as_slice() else {
        panic!("one claimed directory is kept: {claimed:?}")
    };
    let claimed = setting.root().join(claimed);
    assert_eq!(listing(&claimed), ["manifest.json", "pem"]);
    assert_eq!(listing(&setting.staging()), [] as [String; 0]);
    assert!(
        run.stderr.contains(&format!(
            "the staged files are kept in {}: {} exists again",
            claimed.display(),
            setting.staging().display()
        )),
        "{}",
        run.stderr
    );
}

/// The environment of [`child_import_waits_at_the_confirmation`], run as its own process.
const CHILD_RUNTIME: &str = "KPXIMP_CHILD_RUNTIME";
const CHILD_DB: &str = "KPXIMP_CHILD_DB";
const CHILD_PINENTRY: &str = "KPXIMP_CHILD_PINENTRY";

/// Not a test of its own: the process [`a_killed_import_is_put_back_by_the_next_one`] kills.
/// Without its environment it does nothing. It never touches the shared fixtures.
#[test]
fn child_import_waits_at_the_confirmation() {
    let (Some(runtime), Some(db), Some(pinentry)) = (
        std::env::var_os(CHILD_RUNTIME),
        std::env::var_os(CHILD_DB),
        std::env::var_os(CHILD_PINENTRY),
    ) else {
        return;
    };
    let db = db.to_str().unwrap().to_owned();
    let Subcommand::Import(args) = parse(&["kpx-share", "import", "--db", &db, NAME]).command
    else {
        panic!("not an import")
    };
    let tools = ImportTools {
        unlock: UnlockTools {
            keepassxc_cli: PathBuf::from("/nonexistent/keepassxc-cli"),
            gpg: PathBuf::from("/nonexistent/gpg"),
            prompter: Prompter::Pinentry {
                program: PathBuf::from(pinentry),
            },
        },
        tty: PathBuf::from("/nonexistent/tty"),
        files: &Disk,
    };
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let _killed_before_it_returns = import_command(
        args,
        Some(&runtime),
        &tools,
        &mut Io {
            out: &mut out,
            err: &mut err,
        },
    );
}

/// An import killed (SIGKILL, no chance to clean up) while its confirmation is shown leaves the
/// staging directory claimed; the next import puts it back under its name, says so, and imports
/// it. Red when stale claims are not restored at the start (the rerun then finds nothing
/// staged), or not reported.
#[test]
fn a_killed_import_is_put_back_by_the_next_one() {
    let fixtures = fixtures();
    let setting = Setting::new(&fixtures.db);
    stage_existing(&setting);
    let waiting = setting.runtime.path().join("pinentry-waiting");
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "child_import_waits_at_the_confirmation",
            "--nocapture",
        ])
        .env(CHILD_RUNTIME, setting.runtime.path())
        .env(CHILD_DB, &setting.db)
        .env(CHILD_PINENTRY, &fixtures.pinentry_hanging)
        .env("KPXIMP_WAITING", &waiting)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    for _ in 0..400 {
        if waiting.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    let pinentry_pid = fs::read_to_string(&waiting).expect("the import reached its confirmation");
    child.kill().unwrap();
    child.wait().unwrap();
    let _gone = Command::new("kill").arg(pinentry_pid.trim()).status();
    let claimed: Vec<String> = listing(&setting.root())
        .into_iter()
        .filter(|name| name.starts_with(".claimed."))
        .collect();
    assert_eq!(
        claimed.len(),
        1,
        "the killed import left its claim: {claimed:?}"
    );
    assert!(!setting.staging().exists());

    let run = run_import(&setting, &pinentry_tools(own_pinentry(31)), &[]);

    assert_eq!(run.exit, Exit::Success, "{}", run.stderr);
    assert!(
        run.stderr.contains(&format!(
            "put {} back as {}",
            setting.root().join(&claimed[0]).display(),
            setting.staging().display()
        )),
        "{}",
        run.stderr
    );
    assert_eq!(
        attachment(&setting.db, "Ops/hvac-control-tls", "hvac22.pem"),
        pem()
    );
    assert_no_leak(&setting, &run, Keepassxc::Ran, &[]);
}

/// A stale claim whose name is taken again is left where it is and reported with both paths;
/// nothing is deleted, and the staged directory at the name is imported. Red when the claim is
/// moved over the name, deleted, or not reported.
#[test]
fn a_stale_claim_whose_name_is_taken_is_reported_and_kept() {
    let setting = Setting::new(&fixtures().db);
    let stale = setting.root().join(".claimed.00000000000000cc.hvac");
    fs::create_dir(&stale).unwrap();
    fs::set_permissions(&stale, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(stale.join("pem"), b"from the interrupted import").unwrap();
    stage_existing(&setting);

    let run = run_import(&setting, &pinentry_tools(own_pinentry(32)), &[]);

    assert_eq!(run.exit, Exit::Success, "{}", run.stderr);
    assert!(
        run.stderr.contains(&format!(
            "{} holds files an interrupted import claimed, which may be in no database, and {} exists again",
            stale.display(),
            setting.staging().display()
        )),
        "{}",
        run.stderr
    );
    assert_eq!(
        fs::read(stale.join("pem")).unwrap(),
        b"from the interrupted import"
    );
}

/// The name taken by an EMPTY directory, which a plain rename would silently replace, still
/// counts as taken: reported, the empty directory left as it is, the claim kept. Red when the
/// put-back renames over what is there.
#[test]
fn a_stale_claim_is_not_moved_over_an_empty_directory_at_its_name() {
    let setting = Setting::new(&fixtures().db);
    let stale = setting.root().join(".claimed.00000000000000cd.hvac");
    fs::create_dir(&stale).unwrap();
    fs::set_permissions(&stale, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(stale.join("pem"), b"from the interrupted import").unwrap();
    fs::create_dir(setting.staging()).unwrap();
    fs::set_permissions(setting.staging(), fs::Permissions::from_mode(0o700)).unwrap();

    let run = run_import(&setting, &pinentry_tools(own_pinentry(40)), &[]);

    assert!(
        run.stderr.contains(&format!(
            "{} holds files an interrupted import claimed, which may be in no database, and {} exists again",
            stale.display(),
            setting.staging().display()
        )),
        "{}",
        run.stderr
    );
    assert_eq!(listing(&setting.staging()), [] as [String; 0]);
    assert_eq!(
        fs::read(stale.join("pem")).unwrap(),
        b"from the interrupted import"
    );
}

/// Names in the root that are neither a staging directory, a work directory nor a claimed one
/// (one not even UTF-8) are passed over: they block no import and are blamed on no staging
/// directory. Red when the root is listed strictly.
#[test]
fn an_unknown_name_in_the_root_does_not_block_an_import() {
    use std::os::unix::ffi::OsStrExt;
    let setting = Setting::new(&fixtures().db);
    let junk = setting
        .root()
        .join(std::ffi::OsStr::from_bytes(b"junk\xff"));
    fs::write(&junk, b"x").unwrap();
    fs::write(setting.root().join(".claimed.not-hex.hvac"), b"x").unwrap();
    stage_existing(&setting);

    let run = run_import(&setting, &pinentry_tools(own_pinentry(33)), &[]);

    assert_eq!(run.exit, Exit::Success, "{}", run.stderr);
    assert!(junk.exists());
    assert!(setting.root().join(".claimed.not-hex.hvac").exists());
}

// --- Declined mid-run -------------------------------------------------------------------------

/// A `YubiKey` notice closed at any run after the go (adding the entry, adding the attachment,
/// checking the entry, comparing the attachment) ends the import there as declined: exit 130,
/// the database byte for byte as it was, the staging directory back. Red when a declined notice
/// at any of the four runs is taken as a failure, or the import goes on.
#[test]
fn a_notice_closed_at_any_run_declines_the_import() {
    let fixtures = fixtures();
    for (n, program) in fixtures.pinentry_cancelling_notice.iter().enumerate() {
        let setting = Setting::new(&fixtures.db);
        stage_new(&setting);
        let db_before = setting.db_bytes();
        let mut tools = pinentry_tools(program);
        tools.unlock.keepassxc_cli = fixtures.keepassxc_without_yubikey.clone();

        let run = run_import(&setting, &tools, &["--yubikey", "2"]);

        assert_eq!(
            run.exit,
            Exit::Cancelled,
            "notice {}: {}",
            n + 1,
            run.stderr
        );
        assert_eq!(setting.db_bytes(), db_before, "notice {}", n + 1);
        assert_staging_intact(&setting, &["manifest.json", "pw.txt", "ca"]);
        assert_no_leak(&setting, &run, Keepassxc::Ran, &[]);
    }
}

/// A notice closed while the rerun's preflight compares an attachment of an existing new entry
/// is a decline too, not a refusal. Red when the preflight's new-entry arm turns a decline into
/// "already exists".
#[test]
fn a_notice_closed_in_the_preflight_declines_the_import() {
    let fixtures = fixtures();
    let setting = Setting::new(&fixtures.db);
    stage_new(&setting);
    let first = run_import(&setting, &pinentry_tools(own_pinentry(36)), &[]);
    assert_eq!(first.exit, Exit::Success, "{}", first.stderr);
    stage_new(&setting);
    let mut tools = pinentry_tools(&fixtures.pinentry_cancelling_preflight);
    tools.unlock.keepassxc_cli = fixtures.keepassxc_without_yubikey.clone();

    let run = run_import(&setting, &tools, &["--yubikey", "2"]);

    assert_eq!(run.exit, Exit::Cancelled, "{}", run.stderr);
    assert_staging_intact(&setting, &["manifest.json", "pw.txt", "ca"]);
}

/// An agent that held a staged file open, and writes to it after it was read, is not deleted
/// from under: the file is kept with what it now holds, back under the staging name, and
/// reported. Red when the cleanup deletes without comparing.
#[test]
fn a_staged_file_appended_through_an_open_descriptor_is_kept() {
    let setting = Setting::new(&fixtures().db);
    setting.hooks("APPEND=1\n");
    stage_existing(&setting);
    let hooks = setting.runtime.path().join("hooks");
    let opened = hooks.join("agent-opened");
    let mut agent = Command::new("bash")
        .args([
            "-c",
            "exec 3>>\"$1\"; : >\"$2\"; while [[ ! -e $3 ]]; do sleep 0.02; done; \
             printf ' and more' >&3; : >\"$4\"",
            "agent",
        ])
        .arg(setting.staging().join("pem"))
        .arg(&opened)
        .arg(hooks.join("append-now"))
        .arg(hooks.join("appended"))
        .spawn()
        .unwrap();
    for _ in 0..400 {
        if opened.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(opened.exists(), "the agent opened the file");

    let run = run_import(&setting, &pinentry_tools(own_pinentry(37)), &[]);

    assert!(agent.wait().unwrap().success());
    assert_eq!(run.exit, Exit::Success, "{}", run.stderr);
    let mut now = pem();
    now.extend_from_slice(b" and more");
    assert_eq!(fs::read(setting.staging().join("pem")).unwrap(), now);
    assert!(
        run.stderr
            .contains("kept the file of attachment \"hvac22.pem\""),
        "{}",
        run.stderr
    );
    assert_eq!(
        attachment(&setting.db, "Ops/hvac-control-tls", "hvac22.pem"),
        pem()
    );
}

/// keepassxc-cli succeeding without reading the whole attachment from its pipe is an error said
/// as such, before the proof would find the attachment cut. Red when a pipe closed early is
/// taken as written.
#[test]
fn an_attachment_keepassxc_did_not_read_whole_is_an_error() {
    let setting = Setting::new(&fixtures().db);
    setting.hooks("PARTIAL_READ=1\n");
    let big: Vec<u8> = (0..1024 * 1024u32)
        .map(|i| u8::try_from(i % 241).unwrap())
        .collect();
    setting.stage(EXISTING_MANIFEST, &[("pem", &big)]);
    let db_before = setting.db_bytes();

    let run = run_import(&setting, &pinentry_tools(own_pinentry(38)), &[]);

    assert_eq!(run.exit, Exit::Failure, "{}", run.stderr);
    assert!(
        run.stderr
            .contains("reported success but did not read the whole attachment"),
        "{}",
        run.stderr
    );
    assert_eq!(setting.db_bytes(), db_before);
    assert_staging_intact(&setting, &["manifest.json", "pem"]);
}

/// An entry path of 4000 bytes still leaves the password dialog within one Assuan line, which
/// the fake pinentry, like pinentry, refuses beyond 1000 bytes. Red when the dialog shows the
/// path uncut.
#[test]
fn a_long_entry_path_still_fits_the_password_dialog() {
    let setting = Setting::new(&fixtures().db);
    let title = "t".repeat(3996);
    setting.stage(
        &format!(r#"{{"kind":"new","entry":"Ops/{title}","password":"pw.txt"}}"#),
        &[("pw.txt", STAGED_PASSWORD)],
    );
    let program = own_pinentry(39);

    let run = run_import(&setting, &pinentry_tools(program), &[]);

    assert_eq!(run.exit, Exit::Success, "{}", run.stderr);
    let description = pinentry_lines(program)
        .into_iter()
        .find(|line| line.starts_with("SETDESC kpx-share: unlock"))
        .unwrap();
    assert!(
        description.len() < ASSUAN_LINE_BYTES_MAX,
        "{}",
        description.len()
    );
    assert!(description.contains("…"), "{description}");
}

// --- The new entry's group ----------------------------------------------------------------------

/// Whether any keepassxc-cli run had `word` as an argument: a subcommand, when no entry path or
/// value is that word.
fn ran_with(setting: &Setting, word: &str) -> bool {
    String::from_utf8(setting.log("argv"))
        .unwrap()
        .split('\0')
        .any(|arg| arg == word)
}

/// A new entry whose group does not exist (at the top, or one level down) is refused in the
/// preflight, before keepassxc-cli `add` runs, naming the group: exit 1, the database byte for
/// byte as it was, the staging directory back. Red when the group is not checked (keepassxc-cli
/// then fails with its own "could not create entry"), or a missing inner group is taken for its
/// existing parent.
#[test]
fn a_new_entry_in_a_missing_group_is_refused_before_anything_is_written() {
    // keepassxc-cli matches group names exactly: `ops` is not `Ops`.
    for (program, entry, group) in [
        (41, "MQTT/x", "MQTT"),
        (42, "Ops/Nope/x", "Ops/Nope"),
        (45, "ops/x", "ops"),
    ] {
        let setting = Setting::new(&fixtures().db);
        setting.stage(
            &format!(r#"{{"kind":"new","entry":"{entry}","password":"pw.txt"}}"#),
            &[("pw.txt", STAGED_PASSWORD)],
        );
        let db_before = setting.db_bytes();

        let run = run_import(&setting, &pinentry_tools(own_pinentry(program)), &[]);

        assert_eq!(run.exit, Exit::Failure, "{}", run.stderr);
        assert!(
            run.stderr.contains(&format!(
                "there is no group {group} for new entry {entry}; create the group in KeePassXC, or name an existing one"
            )),
            "{}",
            run.stderr
        );
        assert!(ran_with(&setting, "export"), "{entry}");
        assert!(!ran_with(&setting, "add"), "{entry}");
        assert_eq!(setting.db_bytes(), db_before, "{entry}");
        assert_staging_intact(&setting, &["manifest.json", "pw.txt"]);
    }
}

/// A new entry goes into an existing nested group that holds no entry yet, and into the root.
/// Red when groups are known only by the entries in them, or the root is not a group.
#[test]
fn a_new_entry_goes_into_an_empty_nested_group_or_the_root() {
    for (index, entry) in ["Ops/Empty/x", "x"].into_iter().enumerate() {
        let setting = Setting::new(&fixtures().db);
        setting.stage(
            &format!(r#"{{"kind":"new","entry":"{entry}","password":"pw.txt"}}"#),
            &[("pw.txt", STAGED_PASSWORD)],
        );

        let run = run_import(&setting, &pinentry_tools(own_pinentry(43 + index)), &[]);

        assert_eq!(run.exit, Exit::Success, "{entry}: {}", run.stderr);
        assert!(
            show(&setting.db, entry).contains(&format!(
                "Password: {}",
                std::str::from_utf8(STAGED_PASSWORD).unwrap()
            )),
            "{entry}"
        );
    }
}
