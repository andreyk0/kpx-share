//! Fake external programs: bash scripts standing in for pinentry and the pickers.
//!
//! Every script is written before any test spawns a process, so no fork can hold a script's write
//! handle open while another test executes it (`ETXTBSY`): call these from a `OnceLock`
//! initialiser, not from inside a test.

#![allow(dead_code, unreachable_pub)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// Writes an executable `<dir>/<name>` that runs `body` under `bash -euo pipefail`.
pub fn write_script(dir: &Path, name: &str, body: &str) -> PathBuf {
    let path = dir.join(name);
    fs::write(
        &path,
        format!("#!/usr/bin/env bash\nset -euo pipefail\n{body}"),
    )
    .unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    path
}

/// A pinentry speaking Assuan: every command is answered `OK`, except `GETPIN`, which gets the
/// lines of `getpin_reply`. Running it creates `<script>.invoked`.
pub fn pinentry(dir: &Path, name: &str, getpin_reply: &[&str]) -> PathBuf {
    pinentry_answering(dir, name, "GETPIN", getpin_reply)
}

/// A pinentry like [`pinentry`] whose `MESSAGE` gets the lines of `message_reply` and whose
/// `GETPIN` gets `D pw` and `OK`.
pub fn pinentry_showing_message(dir: &Path, name: &str, message_reply: &[&str]) -> PathBuf {
    pinentry_answering(dir, name, "MESSAGE", message_reply)
}

/// What the pinentry `program` was sent since it was written, one command per line, and so
/// whether and in which order it was spoken to (see [`pinentry`]).
pub fn received(program: &Path) -> Vec<String> {
    let mut log = program.as_os_str().to_owned();
    log.push(".received");
    fs::read_to_string(Path::new(&log))
        .unwrap_or_default()
        .lines()
        .map(str::to_owned)
        .collect()
}

/// A pinentry answering `OK` to everything except `command`, which gets the lines of `reply`
/// (`GETPIN` gets `D pw` and `OK` when it is not the command). Each line it is sent is appended
/// to `<script>.received`.
fn pinentry_answering(dir: &Path, name: &str, command: &str, reply: &[&str]) -> PathBuf {
    let replies = |command: &str, lines: &[&str]| {
        format!(
            "\x20   {command})\n{}\x20     ;;\n",
            lines
                .iter()
                .map(|line| format!("      printf '%s\\n' '{line}'\n"))
                .collect::<Vec<_>>()
                .concat()
        )
    };
    let cases = if command == "GETPIN" {
        replies("GETPIN", reply)
    } else {
        format!(
            "{}{}",
            replies(command, reply),
            replies("GETPIN", &["D pw", "OK"])
        )
    };
    write_script(
        dir,
        name,
        &format!(
            ": > \"$0.invoked\"\n\
             : > \"$0.received\"\n\
             echo 'OK Pleased to meet you'\n\
             while IFS= read -r line; do\n\
             printf '%s\\n' \"$line\" >> \"$0.received\"\n\
             \x20 case \"$line\" in\n\
             {cases}\
             \x20   BYE) echo 'OK closing connection'; exit 0 ;;\n\
             \x20   *) echo OK ;;\n\
             \x20 esac\n\
             done\n"
        ),
    )
}

/// A fuzzel stand-in that answers with the 0-based index `choice` and creates
/// `<script>.invoked`.
pub fn fuzzel_choosing(dir: &Path, name: &str, choice: usize) -> PathBuf {
    write_script(
        dir,
        name,
        &format!("cat >/dev/null\n: > \"$0.invoked\"\necho {choice}\n"),
    )
}

/// Whether `program` has been run since it was written (see [`pinentry`]).
pub fn was_invoked(program: &Path) -> bool {
    let mut marker = program.as_os_str().to_owned();
    marker.push(".invoked");
    Path::new(&marker).exists()
}
