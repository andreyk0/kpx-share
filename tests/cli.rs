//! The `kpx-share` binary as a user meets it: help text, argument errors and exit codes.
//!
//! Method: run the real binary with `CLAUDE_*`, `KPX_SHARE_*` removed from its environment (so
//! the developer's own settings cannot change the outcome) and check stdout, stderr and the
//! exit status. Nothing here reaches a database or a share root.

use std::process::{Command, Output};

fn kpx_share(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_kpx-share"))
        .args(args)
        .env_remove("CLAUDE_PID")
        .env_remove("CLAUDE_CODE_SESSION_ID")
        .env_remove("KPX_SHARE_DB")
        .env_remove("KPX_SHARE_KEY_FILE")
        .env_remove("KPX_SHARE_YUBIKEY")
        .output()
        .unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).unwrap()
}

#[test]
fn help_lists_the_commands_and_the_add_options_but_not_the_watcher() {
    let help = kpx_share(&["--help"]);
    assert_eq!(help.status.code(), Some(0));
    let help = text(&help.stdout);
    for command in ["add", "ls", "rm", "gc"] {
        assert!(help.contains(&format!("\n  {command} ")), "{help}");
    }
    assert!(!help.contains("\n  watch"), "{help}");

    let add_help = text(&kpx_share(&["add", "--help"]).stdout);
    for option in [
        "--any",
        "--tag",
        "--db",
        "--key-file",
        "--yubikey",
        "--ttl",
        "KPX_SHARE_DB",
        "KPX_SHARE_KEY_FILE",
        "KPX_SHARE_YUBIKEY",
        "--no-password",
    ] {
        assert!(add_help.contains(option), "{option} in {add_help}");
    }
    // A flag that drops the password prompt is given on the command line, never inherited.
    assert!(!add_help.contains("KPX_SHARE_NO_PASSWORD"), "{add_help}");
}

/// The bounds and default shown are the ones `--ttl` enforces, written out here from the spec:
/// 8 hours by default, from a second to a week.
#[test]
fn the_ttl_help_shows_the_default_and_the_bounds() {
    let add_help = text(&kpx_share(&["add", "--help"]).stdout);
    assert!(add_help.contains("(1s to 168h)"), "{add_help}");
    assert!(add_help.contains("[default: 8h]"), "{add_help}");
}

/// `--no-password` is valid only with a key file, from the command line or `KPX_SHARE_KEY_FILE`:
/// it is refused as a usage error (exit 2) without one, and accepted with one (the run then goes
/// on and stops at the share root, which is pointed at a directory that does not exist, so
/// nothing real is touched). It is a flag only: a `KPX_SHARE_NO_PASSWORD` in the environment, set
/// to anything, neither asks for it nor trips the key file requirement. Red when `requires` is
/// dropped or does not see the environment's key file, or when the variable is read again.
#[test]
fn no_password_needs_a_key_file_and_is_given_on_the_command_line_only() {
    let run = |args: &[&str], env: &[(&str, &str)]| {
        Command::new(env!("CARGO_BIN_EXE_kpx-share"))
            .args(args)
            .env_remove("CLAUDE_PID")
            .env_remove("CLAUDE_CODE_SESSION_ID")
            .env_remove("KPX_SHARE_DB")
            .env_remove("KPX_SHARE_KEY_FILE")
            .env_remove("KPX_SHARE_YUBIKEY")
            .env("XDG_RUNTIME_DIR", "/nonexistent-kpx-share-test")
            .envs(env.iter().copied())
            .output()
            .unwrap()
    };
    let without = run(&["add", "--db", "/x.kdbx", "--no-password"], &[]);
    assert_eq!(without.status.code(), Some(2), "{}", text(&without.stderr));

    for with in [
        run(
            &[
                "add",
                "--db",
                "/x.kdbx",
                "--no-password",
                "--key-file",
                "/k",
            ],
            &[],
        ),
        run(
            &["add", "--db", "/x.kdbx", "--no-password"],
            &[("KPX_SHARE_KEY_FILE", "/k")],
        ),
        // The variable is not an option: set to false or to true, it changes nothing.
        run(
            &["add", "--db", "/x.kdbx"],
            &[("KPX_SHARE_NO_PASSWORD", "0")],
        ),
        run(
            &["add", "--db", "/x.kdbx"],
            &[("KPX_SHARE_NO_PASSWORD", "1")],
        ),
    ] {
        assert_eq!(with.status.code(), Some(1), "{}", text(&with.stderr));
        assert!(
            text(&with.stderr).starts_with("kpx-share: "),
            "{}",
            text(&with.stderr)
        );
    }
}

/// No tool can be substituted from the command line: there is no option for one.
#[test]
fn no_option_names_a_tool_program() {
    let add_help = text(&kpx_share(&["add", "--help"]).stdout);
    for tool in ["pinentry", "fzf", "fuzzel", "keepassxc-cli", "launcher"] {
        assert!(!add_help.contains(tool), "{tool} in {add_help}");
    }
}

#[test]
fn add_without_a_database_is_one_line_on_stderr_and_exit_1() {
    let run = kpx_share(&["add"]);
    assert_eq!(run.status.code(), Some(1));
    assert_eq!(text(&run.stdout), "");
    assert_eq!(
        text(&run.stderr),
        "kpx-share: no database configured: pass --db or set KPX_SHARE_DB\n"
    );
}

#[test]
fn a_bad_tag_ttl_or_slot_is_refused_before_anything_runs() {
    let bad_tag = kpx_share(&["add", "--db", "/nonexistent.kdbx", "--tag", "a,b"]);
    assert_eq!(bad_tag.status.code(), Some(1));
    assert!(text(&bad_tag.stderr).starts_with("kpx-share: --tag \"a,b\""));

    for args in [
        &["add", "--ttl", "soon"][..],
        &["add", "--ttl", "0s"],
        &["add", "--yubikey", "3"],
        &["add", "--any", "--tag", "x"],
        &["rm"],
        &["rm", "x", "--all"],
    ] {
        let run = kpx_share(args);
        assert_eq!(run.status.code(), Some(2), "{args:?}");
        assert_eq!(text(&run.stdout), "");
    }
}

#[test]
fn a_session_environment_with_only_one_variable_is_an_error_not_a_guess() {
    let run = Command::new(env!("CARGO_BIN_EXE_kpx-share"))
        .args(["ls"])
        .env("CLAUDE_PID", "1")
        .env_remove("CLAUDE_CODE_SESSION_ID")
        .output()
        .unwrap();
    assert_eq!(run.status.code(), Some(1));
    assert_eq!(
        text(&run.stderr),
        "kpx-share: CLAUDE_PID is set but CLAUDE_CODE_SESSION_ID is not; refusing to guess which session this is\n"
    );
}
