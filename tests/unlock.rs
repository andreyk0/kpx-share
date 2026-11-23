//! `unlock()` end to end against the real `keepassxc-cli` and a throwaway KDBX (password `pw`).
//!
//! The password-source path that production runs under `!` is exercised whole: a fake pinentry
//! (a bash script speaking Assuan on stdin/stdout, standing in for pinentry-gnome3) is spawned,
//! the password is read from it, and keepassxc-cli is run with that password on its stdin. The
//! terminal path is run on a real pty through `script`, with the test acting as the human.
//! Needs `keepassxc-cli`, bash and `script`; without them these tests fail, never skip.
//!
//! All scripts and databases are created once, before any test spawns a process, so no fork can
//! hold a script's write handle open while another test executes it (`ETXTBSY`).

mod common;

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;

use kpx_share::layout::SessionName;
use kpx_share::mode::Mode;
use kpx_share::subprocess::ToolError;
use kpx_share::unlock::{
    MasterKey, Prompter, UnlockError, UnlockRequest, UnlockTools, YubiKeySlot, unlock_for_share,
};
use kpx_share::{SecretBytes, unlock};

/// The session the dialog is for.
fn session() -> SessionName {
    SessionName::parse("claude-0b1c2d3e-4f50-6172-8394-a5b6c7d8e9f0").unwrap()
}

/// `unlock::unlock` for the test session: the export.
fn unlock(request: &UnlockRequest, source: &Prompter) -> Result<SecretBytes, UnlockError> {
    unlock::unlock(request, source, &session()).map(|unlocked| unlocked.xml)
}

const PASSWORD: &str = "pw";
const WRONG_PASSWORD: &str = "wrong-pass-7";
/// What the pinentry answers when keepassxc-cli is a fake that fails: no real database takes it.
const LEAKY_PASSWORD: &str = "leaky-pass-5d1e";
const CHILD_ENV: &str = "KPX_TEST_CHILD_DB";

/// Substrings of the fixture's secret fields (passwords, TOTP seeds, history); none may reach an
/// error message.
const FIXTURE_MARKERS: [&str; 5] = ["pw-11", "pw-22", "JBSWY3DP", "STEAMSEED", "OLD-HISTORY"];

struct Fixtures {
    plain_db: PathBuf,
    key_file_db: PathBuf,
    key_file: PathBuf,
    /// Protected by `key_file` alone, no password.
    key_file_only_db: PathBuf,
    /// Records that it ran, and answers with a password no database takes.
    pinentry_unused: PathBuf,
    /// Answers `GETPIN` with `pw`, the first letter escaped (`%70`), as pinentry may.
    pinentry_pw: PathBuf,
    pinentry_wrong: PathBuf,
    pinentry_leaky: PathBuf,
    /// Writes the start of an XML document holding a fixture secret to stdout, a complaint to
    /// stderr, and exits 3.
    keepassxc_failing: PathBuf,
    pinentry_cancel: PathBuf,
    pinentry_garbage: PathBuf,
    pinentry_line_break: PathBuf,
    /// Dismisses a `MESSAGE` with OK, and records what it is sent.
    pinentry_notice: PathBuf,
    /// Closes a `MESSAGE` window.
    pinentry_notice_closed: PathBuf,
    /// Succeeds with an empty document only if `pinentry_notice` has been sent its `MESSAGE`
    /// already, so it shows the order the two ran in; exits 9 otherwise.
    keepassxc_after_notice: PathBuf,
    /// A gpg home of its own, and files encrypted to its key.
    gpg: common::gpg::ThrowawayGpg,
    /// `pw` and a line feed, as `echo pw | gpg -e` writes it.
    gpg_pw_line: PathBuf,
    /// `pw` exactly.
    gpg_pw: PathBuf,
    gpg_wrong: PathBuf,
    /// One byte longer than a decrypted password may be.
    gpg_too_long: PathBuf,
    /// `pw`, not encrypted at all.
    gpg_plaintext: PathBuf,
    /// Records that it ran; a decrypted password must not show a dialog.
    pinentry_gpg_unused: PathBuf,
    /// [`Fixtures::pinentry_notice`] and [`Fixtures::keepassxc_after_notice`], for the
    /// encrypted-password test alone, so the two notice tests cannot see each other's runs.
    pinentry_gpg_notice: PathBuf,
    keepassxc_after_gpg_notice: PathBuf,
}

/// One byte more than kpx-share takes from gpg as a password.
const ENCRYPTED_PASSWORD_TOO_LONG_BYTES: usize = 4097;

fn fixtures() -> &'static Fixtures {
    static FIXTURES: OnceLock<Fixtures> = OnceLock::new();
    FIXTURES.get_or_init(|| {
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("unlock-fixtures");
        let _absent_is_fine = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let key_file = dir.join("db.key");
        fs::write(&key_file, "not a real key, throwaway\n").unwrap();
        let plain_db = dir.join("plain.kdbx");
        common::create_throwaway_kdbx(&plain_db, PASSWORD, None);
        let key_file_db = dir.join("keyed.kdbx");
        common::create_throwaway_kdbx(&key_file_db, PASSWORD, Some(&key_file));
        let key_file_only_db = dir.join("keyed-only.kdbx");
        common::create_key_file_only_kdbx(
            &common::fixture_xml_path(),
            &key_file_only_db,
            &key_file,
        );

        let pinentry =
            |name: &str, getpin_reply: &[&str]| common::fakes::pinentry(&dir, name, getpin_reply);
        let notice_pair = |pinentry_name: &str, keepassxc_name: &str| {
            let pinentry = common::fakes::pinentry_showing_message(&dir, pinentry_name, &["OK"]);
            let keepassxc = common::fakes::write_script(
                &dir,
                keepassxc_name,
                &format!(
                    "cat >/dev/null\n\
                     grep -qx MESSAGE '{}.received' || exit 9\n\
                     echo '<KeePassFile/>'\n",
                    pinentry.display()
                ),
            );
            (pinentry, keepassxc)
        };
        let (pinentry_notice, keepassxc_after_notice) =
            notice_pair("pinentry-notice", "keepassxc-after-notice");
        let (pinentry_gpg_notice, keepassxc_after_gpg_notice) =
            notice_pair("pinentry-gpg-notice", "keepassxc-after-gpg-notice");

        let gpg = common::gpg::ThrowawayGpg::create(&dir);
        let encrypted = |name: &str, plaintext: &[u8]| {
            let file = dir.join(name);
            gpg.encrypt(plaintext, &file);
            file
        };
        let gpg_pw_line = encrypted("pw-line.gpg", b"pw\n");
        let gpg_pw = encrypted("pw.gpg", PASSWORD.as_bytes());
        let gpg_wrong = encrypted("wrong.gpg", WRONG_PASSWORD.as_bytes());
        let gpg_too_long = encrypted("too-long.gpg", &[b'a'; ENCRYPTED_PASSWORD_TOO_LONG_BYTES]);
        let gpg_plaintext = dir.join("plaintext.gpg");
        fs::write(&gpg_plaintext, PASSWORD).unwrap();

        Fixtures {
            gpg,
            gpg_pw_line,
            gpg_pw,
            gpg_wrong,
            gpg_too_long,
            gpg_plaintext,
            pinentry_gpg_unused: pinentry("pinentry-gpg-unused", &["D x", "OK"]),
            pinentry_gpg_notice,
            keepassxc_after_gpg_notice,
            pinentry_notice,
            keepassxc_after_notice,
            pinentry_notice_closed: common::fakes::pinentry_showing_message(
                &dir,
                "pinentry-notice-closed",
                &["ERR 83886179 Operation cancelled <Pinentry>"],
            ),
            plain_db,
            key_file_db,
            key_file,
            key_file_only_db,
            pinentry_unused: pinentry("pinentry-unused", &["D x", "OK"]),
            pinentry_pw: pinentry("pinentry-pw", &["D %70w", "OK"]),
            pinentry_wrong: pinentry("pinentry-wrong", &[&format!("D {WRONG_PASSWORD}"), "OK"]),
            pinentry_leaky: pinentry("pinentry-leaky", &[&format!("D {LEAKY_PASSWORD}"), "OK"]),
            keepassxc_failing: common::fakes::write_script(
                &dir,
                "keepassxc-failing",
                "cat >/dev/null\n\
                 printf '<KeePassFile><Entry><String><Key>Password</Key><Value>pw-11</Value>'\n\
                 echo 'simulated failure' >&2\n\
                 exit 3\n",
            ),
            pinentry_cancel: pinentry(
                "pinentry-cancel",
                &["ERR 83886179 Operation cancelled <Pinentry>"],
            ),
            pinentry_garbage: pinentry("pinentry-garbage", &["WAT"]),
            pinentry_line_break: pinentry("pinentry-line-break", &["D a%0Ab", "OK"]),
        }
    })
}

fn request(database: &Path) -> UnlockRequest {
    UnlockRequest {
        database: database.to_owned(),
        master_key: MasterKey::TypedPassword { key_file: None },
        yubikey: None,
    }
}

fn pinentry(program: &Path) -> Prompter {
    Prompter::Pinentry {
        program: program.to_owned(),
    }
}

/// The real programs, except keepassxc-cli at `keepassxc_cli`, asking through `prompter`.
fn tools(keepassxc_cli: &Path, prompter: Prompter) -> UnlockTools {
    UnlockTools {
        keepassxc_cli: keepassxc_cli.to_owned(),
        prompter,
        ..UnlockTools::production(Mode::Terminal)
    }
}

fn assert_exported_fixture(xml: &SecretBytes) {
    let database = kpx_share::export::parse(xml.clone()).unwrap();
    assert_eq!(database.entries().len(), 8);
}

#[test]
fn pinentry_password_unlocks_the_database() {
    let fixtures = fixtures();
    let xml = unlock(
        &request(&fixtures.plain_db),
        &pinentry(&fixtures.pinentry_pw),
    )
    .unwrap();
    assert_exported_fixture(&xml);
}

#[test]
fn key_file_is_passed_to_keepassxc_cli() {
    let fixtures = fixtures();
    let mut with_key = request(&fixtures.key_file_db);
    with_key.master_key = MasterKey::TypedPassword {
        key_file: Some(fixtures.key_file.clone()),
    };
    assert_exported_fixture(&unlock(&with_key, &pinentry(&fixtures.pinentry_pw)).unwrap());

    let without_key = request(&fixtures.key_file_db);
    let error = unlock(&without_key, &pinentry(&fixtures.pinentry_pw)).unwrap_err();
    assert!(
        matches!(error, UnlockError::InvalidCredentials),
        "{error:?}"
    );
}

/// A database protected by a key file alone, measured with keepassxc-cli 2.8.0: any password
/// piped to it is "invalid credentials", and `--no-password -k key` works with no stdin. So with
/// `KeyFileOnly` it unlocks, no pinentry dialog is shown, and without it (`Password`) the same
/// database is refused. Red when `--no-password` is not passed, or when pinentry is run anyway.
#[test]
fn a_key_file_only_database_unlocks_without_a_dialog() {
    let fixtures = fixtures();
    let key_file_only = UnlockRequest {
        database: fixtures.key_file_only_db.clone(),
        master_key: MasterKey::KeyFileOnly {
            key_file: fixtures.key_file.clone(),
        },
        yubikey: None,
    };

    let xml = unlock(&key_file_only, &pinentry(&fixtures.pinentry_unused)).unwrap();

    assert_exported_fixture(&xml);
    assert!(
        !common::fakes::was_invoked(&fixtures.pinentry_unused),
        "the password dialog was shown for a database with no password"
    );
    let as_password = UnlockRequest {
        master_key: MasterKey::TypedPassword {
            key_file: Some(fixtures.key_file.clone()),
        },
        ..key_file_only
    };
    let error = unlock(&as_password, &pinentry(&fixtures.pinentry_pw)).unwrap_err();
    assert!(
        matches!(error, UnlockError::InvalidCredentials),
        "{error:?}"
    );
}

/// A key-file-only database with a `YubiKey` slot and no terminal: no password dialog, but a
/// notice about the touch is shown, and keepassxc-cli is run only after it was dismissed (the
/// fake keepassxc-cli fails unless pinentry has been sent `MESSAGE`). Red when the notice is
/// not shown, is shown after keepassxc-cli ran, or a password is asked for as well.
#[test]
fn a_key_file_only_database_with_a_yubikey_shows_a_touch_notice_and_no_password_dialog() {
    let fixtures = fixtures();
    let request = UnlockRequest {
        database: fixtures.key_file_only_db.clone(),
        master_key: MasterKey::KeyFileOnly {
            key_file: fixtures.key_file.clone(),
        },
        yubikey: Some(YubiKeySlot::Two),
    };

    let xml = unlock_for_share(
        &tools(
            &fixtures.keepassxc_after_notice,
            pinentry(&fixtures.pinentry_notice),
        ),
        &request,
        &session(),
    )
    .unwrap()
    .xml;

    assert_eq!(xml.expose(), b"<KeePassFile/>\n");
    let sent = common::fakes::received(&fixtures.pinentry_notice);
    assert_eq!(sent.len(), 4, "{sent:?}");
    assert!(sent[0].starts_with("SETTITLE "), "{sent:?}");
    assert!(
        sent[1].starts_with("SETDESC ") && sent[1].contains("slot 2"),
        "{sent:?}"
    );
    assert_eq!(sent[2], "MESSAGE");
    assert_eq!(sent[3], "BYE");
}

/// Closing the notice is a cancellation and keepassxc-cli is not run. Red when the closed window
/// is ignored: the unlock then proceeds instead of returning `Cancelled`.
#[test]
fn closing_the_touch_notice_cancels_before_keepassxc_cli_runs() {
    let fixtures = fixtures();
    let request = UnlockRequest {
        database: fixtures.key_file_only_db.clone(),
        master_key: MasterKey::KeyFileOnly {
            key_file: fixtures.key_file.clone(),
        },
        yubikey: Some(YubiKeySlot::One),
    };

    let error = unlock_for_share(
        &tools(
            &fixtures.keepassxc_after_notice,
            pinentry(&fixtures.pinentry_notice_closed),
        ),
        &request,
        &session(),
    )
    .unwrap_err();

    assert!(matches!(error, UnlockError::Cancelled), "{error:?}");
}

#[test]
fn a_wrong_password_is_invalid_credentials_and_the_error_leaks_nothing() {
    let fixtures = fixtures();
    let error = unlock(
        &request(&fixtures.plain_db),
        &pinentry(&fixtures.pinentry_wrong),
    )
    .unwrap_err();
    assert!(
        matches!(error, UnlockError::InvalidCredentials),
        "{error:?}"
    );
    assert_leaks_nothing(&error);
}

fn assert_leaks_nothing(error: &UnlockError) {
    for shown in [
        error.to_string(),
        format!("{error:?}"),
        format!("{error:#?}"),
    ] {
        for secret in FIXTURE_MARKERS
            .into_iter()
            .chain([WRONG_PASSWORD, LEAKY_PASSWORD])
        {
            assert!(!shown.contains(secret), "{secret} in {shown}");
        }
        assert!(!shown.contains("<?xml"), "{shown}");
    }
}

#[test]
fn an_unrecognised_failure_carries_keepassxc_clis_stderr() {
    let fixtures = fixtures();
    let missing = fixtures.plain_db.with_file_name("no-such.kdbx");
    let error = unlock(&request(&missing), &pinentry(&fixtures.pinentry_pw)).unwrap_err();
    match &error {
        UnlockError::Tool(ToolError::Failed { tool, stderr, .. }) => {
            assert_eq!(tool, Path::new("/usr/bin/keepassxc-cli"));
            assert!(stderr.contains("Failed to open database file"), "{stderr}");
        }
        other => panic!("{other:?}"),
    }
    assert_leaks_nothing(&error);
}

/// I7 on the `Failed` path, which the real keepassxc-cli reaches only for failures other than
/// bad credentials: the program prints part of the decrypted XML and fails unrecognisably. What
/// it said on stderr is carried (so the path was taken); neither the password it was given nor
/// the XML it printed is in the error in any form. Red when the password or stdout is added to
/// `ToolError::Failed`.
#[test]
fn an_unrecognised_failure_after_partial_output_leaks_neither_password_nor_xml() {
    let fixtures = fixtures();

    let error = unlock_for_share(
        &tools(
            &fixtures.keepassxc_failing,
            pinentry(&fixtures.pinentry_leaky),
        ),
        &request(&fixtures.plain_db),
        &session(),
    )
    .unwrap_err();

    match &error {
        UnlockError::Tool(ToolError::Failed { stderr, .. }) => {
            assert!(stderr.contains("simulated failure"), "{stderr}");
        }
        other => panic!("{other:?}"),
    }
    assert_leaks_nothing(&error);
}

#[test]
fn cancelling_the_prompt_is_cancelled() {
    let fixtures = fixtures();
    let error = unlock(
        &request(&fixtures.plain_db),
        &pinentry(&fixtures.pinentry_cancel),
    )
    .unwrap_err();
    assert!(matches!(error, UnlockError::Cancelled), "{error:?}");
}

#[test]
fn a_garbled_pinentry_is_an_error_naming_it() {
    let fixtures = fixtures();
    let error = unlock(
        &request(&fixtures.plain_db),
        &pinentry(&fixtures.pinentry_garbage),
    )
    .unwrap_err();
    assert!(
        matches!(&error, UnlockError::Pinentry { tool, .. } if *tool == fixtures.pinentry_garbage),
        "{error:?}"
    );
}

#[test]
fn a_password_with_a_line_break_is_refused_before_keepassxc_cli_runs() {
    let fixtures = fixtures();
    let error = unlock(
        &request(&fixtures.plain_db),
        &pinentry(&fixtures.pinentry_line_break),
    )
    .unwrap_err();
    assert!(
        matches!(error, UnlockError::PasswordHasLineBreak),
        "{error:?}"
    );
}

#[test]
fn a_missing_pinentry_is_a_spawn_error_naming_it() {
    let fixtures = fixtures();
    let missing = Path::new("/nonexistent/pinentry");
    let error = unlock(&request(&fixtures.plain_db), &pinentry(missing)).unwrap_err();
    assert!(
        matches!(&error, UnlockError::Tool(ToolError::Spawn { tool, .. }) if tool == missing),
        "{error:?}"
    );
}

#[test]
fn yubikey_slot_reaches_keepassxc_cli() {
    // No YubiKey is attached, so unlock must fail, and fail inside keepassxc-cli rather than at
    // argument parsing; that it ran with `-y 1` is pinned by the unit test on the arguments.
    let fixtures = fixtures();
    let mut with_slot = request(&fixtures.plain_db);
    with_slot.yubikey = Some(YubiKeySlot::One);
    let error = unlock(&with_slot, &pinentry(&fixtures.pinentry_pw)).unwrap_err();
    assert!(
        matches!(
            error,
            UnlockError::Tool(ToolError::Failed { .. }) | UnlockError::InvalidCredentials
        ),
        "{error:?}"
    );
}

/// Child body: unlock on the terminal this process was started on.
#[test]
fn child_unlock_on_terminal() {
    let Some(database) = std::env::var_os(CHILD_ENV) else {
        return;
    };
    let xml = unlock(&request(Path::new(&database)), &Prompter::Terminal).unwrap();
    println!("unlocked entries={}", {
        kpx_share::export::parse(xml).unwrap().entries().len()
    });
}

/// keepassxc-cli prompts on the terminal itself and reads the answer from its stdin, which is
/// the pty. The test waits for the prompt before typing, as the human would.
#[test]
fn terminal_source_lets_keepassxc_cli_prompt_on_the_terminal() {
    let fixtures = fixtures();
    let mut script = Command::new("/usr/bin/script")
        .args(["--quiet", "--return", "--command"])
        .arg(format!(
            "{} child_unlock_on_terminal --exact --nocapture --test-threads=1",
            std::env::current_exe().unwrap().display()
        ))
        .arg("/dev/null")
        .env(CHILD_ENV, &fixtures.plain_db)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = script.stdin.take().unwrap();
    let mut stdout = script.stdout.take().unwrap();
    let mut seen = Vec::new();
    let mut chunk = [0u8; 1024];
    while !String::from_utf8_lossy(&seen).contains("Enter password to unlock") {
        let count = stdout.read(&mut chunk).unwrap();
        assert_ne!(count, 0, "script ended before the prompt: {seen:?}");
        seen.extend_from_slice(&chunk[..count]);
    }
    stdin.write_all(format!("{PASSWORD}\n").as_bytes()).unwrap();
    stdout.read_to_end(&mut seen).unwrap();
    assert!(script.wait().unwrap().success());
    let seen = String::from_utf8_lossy(&seen);
    assert!(seen.contains("unlocked entries=8"), "{seen}");
}

// --- An encrypted password, decrypted by gpg ------------------------------------------------

fn encrypted_request(database: &Path, file: &Path) -> UnlockRequest {
    UnlockRequest {
        database: database.to_owned(),
        master_key: MasterKey::EncryptedPassword {
            file: file.to_owned(),
            key_file: None,
        },
        yubikey: None,
    }
}

/// The real keepassxc-cli and the throwaway gpg, asking through `prompter`.
fn gpg_tools(prompter: Prompter) -> UnlockTools {
    UnlockTools {
        gpg: fixtures().gpg.wrapper.clone(),
        ..tools(Path::new("/usr/bin/keepassxc-cli"), prompter)
    }
}

fn unlock_encrypted(file: &Path, prompter: Prompter) -> Result<SecretBytes, UnlockError> {
    let request = encrypted_request(&fixtures().plain_db, file);
    unlock_for_share(&gpg_tools(prompter), &request, &session()).map(|unlocked| unlocked.xml)
}

/// The password gpg decrypts unlocks the database, and no dialog is shown, though there is no
/// terminal and pinentry is configured. Red when the encrypted password falls through to the
/// pinentry dialog (it answers a password no database takes, and its run is counted).
#[test]
fn an_encrypted_password_unlocks_the_database_with_no_dialog() {
    let fixtures = fixtures();
    let xml = unlock_encrypted(&fixtures.gpg_pw, pinentry(&fixtures.pinentry_gpg_unused)).unwrap();
    assert_exported_fixture(&xml);
    assert_eq!(common::fakes::runs(&fixtures.pinentry_gpg_unused), 0);
}

/// `echo pw | gpg -e` encrypts `pw` and a line feed, and that file unlocks a database whose
/// password is `pw`. Red when the line feed is kept: the password then holds a line break.
#[test]
fn one_trailing_line_feed_is_not_part_of_the_encrypted_password() {
    let fixtures = fixtures();
    let xml = unlock_encrypted(&fixtures.gpg_pw_line, Prompter::Terminal).unwrap();
    assert_exported_fixture(&xml);
}

#[test]
fn a_wrong_encrypted_password_is_invalid_credentials_and_the_error_leaks_nothing() {
    let fixtures = fixtures();
    let error = unlock_encrypted(&fixtures.gpg_wrong, Prompter::Terminal).unwrap_err();
    assert!(
        matches!(error, UnlockError::InvalidCredentials),
        "{error:?}"
    );
    assert_leaks_nothing(&error);
}

/// A file gpg cannot decrypt fails naming gpg, with what gpg said, and keepassxc-cli is not run
/// (its failure would name keepassxc-cli instead).
#[test]
fn a_file_gpg_cannot_decrypt_fails_naming_gpg_and_carrying_its_stderr() {
    let fixtures = fixtures();
    let error = unlock_encrypted(
        &fixtures.gpg_plaintext,
        pinentry(&fixtures.pinentry_gpg_unused),
    )
    .unwrap_err();
    match &error {
        UnlockError::Tool(ToolError::Failed { tool, stderr, .. }) => {
            assert_eq!(tool, &fixtures.gpg.wrapper);
            assert!(!stderr.is_empty(), "gpg said nothing");
        }
        other => panic!("{other:?}"),
    }
    assert!(!error.to_string().contains(PASSWORD), "{error}");
}

/// A file that decrypts to more than a password can be is refused, before keepassxc-cli runs.
/// Red when the bound is dropped: keepassxc-cli is then given 4097 bytes and reports invalid
/// credentials.
#[test]
fn a_file_decrypting_to_more_than_a_password_is_refused() {
    let fixtures = fixtures();
    let error = unlock_encrypted(&fixtures.gpg_too_long, Prompter::Terminal).unwrap_err();
    assert!(
        matches!(&error, UnlockError::EncryptedPasswordTooLong { file } if *file == fixtures.gpg_too_long),
        "{error:?}"
    );
}

/// With an encrypted password there is no password dialog to say a `YubiKey` touch follows, so
/// the touch notice is shown, before keepassxc-cli runs. Red when the notice is skipped for an
/// encrypted password: the fake keepassxc-cli then exits 9.
#[test]
fn an_encrypted_password_with_a_yubikey_shows_the_touch_notice_before_keepassxc_cli() {
    let fixtures = fixtures();
    let request = UnlockRequest {
        yubikey: Some(YubiKeySlot::Two),
        ..encrypted_request(&fixtures.plain_db, &fixtures.gpg_pw)
    };
    let tools = UnlockTools {
        keepassxc_cli: fixtures.keepassxc_after_gpg_notice.clone(),
        ..gpg_tools(pinentry(&fixtures.pinentry_gpg_notice))
    };

    let xml = unlock_for_share(&tools, &request, &session()).unwrap().xml;

    assert_eq!(xml.expose(), b"<KeePassFile/>\n");
    let sent = common::fakes::received(&fixtures.pinentry_gpg_notice);
    assert_eq!(sent[2], "MESSAGE", "{sent:?}");
}
