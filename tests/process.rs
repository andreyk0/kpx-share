//! Process-wide state, observed from a child process.
//!
//! `harden()` and `Mode::detect()` act on the whole process, so they are tested in a child that
//! is this test binary re-executed on one of the `child_*` tests below with `KPX_TEST_CHILD`
//! set (without it they do nothing). The parent runs the child with a chosen stdin and reads
//! what it reports on stdout. Expected values are written out by hand.

use std::fs;
use std::process::{Command, Stdio};

use kpx_share::harden::harden;
use kpx_share::mode::Mode;
use rustix::process::{DumpableBehavior, dumpable_behavior};

const CHILD_ENV: &str = "KPX_TEST_CHILD";

fn in_child() -> bool {
    std::env::var_os(CHILD_ENV).is_some()
}

fn core_limits() -> String {
    let limits = fs::read_to_string("/proc/self/limits").unwrap();
    let line = limits
        .lines()
        .find(|line| line.starts_with("Max core file size"))
        .unwrap();
    line.split_whitespace()
        .skip(4)
        .collect::<Vec<_>>()
        .join(" ")
}

/// Child body: report dumpability and the core limits, before or after `harden()`.
#[test]
fn child_harden() {
    if !in_child() {
        return;
    }
    if std::env::var(CHILD_ENV).unwrap() == "harden" {
        harden().unwrap();
    }
    let dumpable = dumpable_behavior().unwrap() == DumpableBehavior::Dumpable;
    println!("dumpable={dumpable} core_limits={}", core_limits());
}

/// Child body: report the detected mode.
#[test]
fn child_mode() {
    if !in_child() {
        return;
    }
    println!("mode={:?}", Mode::detect());
}

fn run_child(test: &str, how: &str, stdin: Stdio) -> String {
    let output = Command::new(std::env::current_exe().unwrap())
        .args([test, "--exact", "--nocapture", "--test-threads=1"])
        .env(CHILD_ENV, how)
        .stdin(stdin)
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    String::from_utf8(output.stdout).unwrap()
}

#[test]
fn harden_makes_the_process_non_dumpable_with_no_core_files() {
    let before = run_child("child_harden", "plain", Stdio::null());
    assert!(
        before.contains("dumpable=true core_limits=unlimited unlimited"),
        "control run, so the assertion below can fail: {before}"
    );
    let after = run_child("child_harden", "harden", Stdio::null());
    assert!(after.contains("dumpable=false core_limits=0 0"), "{after}");
}

#[test]
fn no_terminal_mode_when_stdin_is_not_a_terminal() {
    let out = run_child("child_mode", "detect", Stdio::null());
    assert!(out.contains("mode=NoTerminal"), "{out}");
}

/// A real terminal: `script` runs the child on a fresh pty as its controlling terminal.
#[test]
fn terminal_mode_on_a_pty() {
    let output = Command::new("/usr/bin/script")
        .args(["--quiet", "--return", "--command"])
        .arg(format!(
            "{} child_mode --exact --nocapture --test-threads=1",
            std::env::current_exe().unwrap().display()
        ))
        .arg("/dev/null")
        .env(CHILD_ENV, "detect")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let out = String::from_utf8_lossy(&output.stdout);
    assert!(out.contains("mode=Terminal"), "{output:?}");
}
