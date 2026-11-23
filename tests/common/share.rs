//! Helpers for the tests that write entries to disk.

#![allow(dead_code, unreachable_pub)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use kpx_share::ResolvedEntry;
use kpx_share::layout::{SessionDir, SessionName, ShareRoot};
use kpx_share::meta::Validity;
use tempfile::TempDir;

use super::{document, parse_str, resolve};

/// Imports `body` under the root group and resolves entry `uuid_byte` with `--any`.
pub fn resolve_any(meta: &str, body: &str, uuid_byte: u8) -> ResolvedEntry {
    resolve(&parse_str(&document(meta, body)), uuid_byte)
}

/// `<scratch>/kpx-share` as a share root, built the way the CLI builds it.
pub fn root_in(scratch: &TempDir) -> ShareRoot {
    ShareRoot::at(&scratch.path().join("kpx-share")).unwrap()
}

/// A scratch directory on tmpfs: below `$XDG_RUNTIME_DIR`.
pub fn scratch_on_tmpfs() -> TempDir {
    let runtime = std::env::var_os("XDG_RUNTIME_DIR")
        .expect("these tests need XDG_RUNTIME_DIR, a tmpfs, to write into");
    TempDir::new_in(runtime).unwrap()
}

/// A scratch directory below the build directory, which is a disk (these tests are not meant to
/// run with `target/` on tmpfs; `refuses_a_directory_on_disk` fails if it is).
pub fn scratch_on_disk() -> TempDir {
    TempDir::new_in(env!("CARGO_TARGET_TMPDIR")).unwrap()
}

/// `<scratch>/kpx-share/s1`, built the way the CLI builds it.
pub fn session_in(scratch: &Path) -> SessionDir {
    let root = ShareRoot::at(&scratch.join("kpx-share")).unwrap();
    SessionDir::open(&root, &SessionName::parse("s1").unwrap()).unwrap()
}

pub fn validity() -> Validity {
    Validity::new(
        "2026-03-04T05:06:07Z".parse().unwrap(),
        "2026-03-04T13:06:07Z".parse().unwrap(),
    )
    .unwrap()
}

pub fn mode(path: &Path) -> u32 {
    fs::symlink_metadata(path).unwrap().permissions().mode() & 0o7777
}

/// Every path below `dir`, directories included, relative to `dir`, sorted.
pub fn tree(dir: &Path) -> Vec<PathBuf> {
    fn walk(base: &Path, dir: &Path, out: &mut Vec<PathBuf>) {
        for item in fs::read_dir(dir).unwrap() {
            let path = item.unwrap().path();
            out.push(path.strip_prefix(base).unwrap().to_owned());
            if fs::symlink_metadata(&path).unwrap().is_dir() {
                walk(base, &path, out);
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, dir, &mut out);
    out.sort();
    out
}

pub fn is_dir(path: &Path) -> bool {
    fs::symlink_metadata(path).unwrap().is_dir()
}

/// The names of `.partial-*` leftovers in a session directory.
pub fn partials(session: &SessionDir) -> Vec<String> {
    fs::read_dir(session.path())
        .unwrap()
        .map(|item| item.unwrap().file_name().into_string().unwrap())
        .filter(|name| name.starts_with(".partial-"))
        .collect()
}
