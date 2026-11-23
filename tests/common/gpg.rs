//! A throwaway gpg home with one software key, and a `gpg` wrapper that uses it.
//!
//! The developer's own keyring and card are never touched: every gpg run here, and the wrapper
//! kpx-share is handed in place of `/usr/bin/gpg`, passes `--homedir` explicitly, so no process's
//! environment is changed. The key has no passphrase, so decrypting needs no pinentry and no
//! touch. Like the other fakes, call these from a `OnceLock` initialiser, not from inside a test.

#![allow(dead_code, unreachable_pub)]

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use super::fakes::write_script;

const GPG: &str = "/usr/bin/gpg";
const USER_ID: &str = "kpx-share test <kpx-share-test@example.invalid>";

/// A gpg home holding one key, and an executable that runs the real gpg with it.
pub struct ThrowawayGpg {
    pub home: PathBuf,
    /// Runs `/usr/bin/gpg --homedir <home>` with its arguments; each run appends a line to
    /// `<wrapper>.runs` (see [`super::fakes::runs`]).
    pub wrapper: PathBuf,
}

impl ThrowawayGpg {
    /// Creates `<dir>/gnupg` with a new passphrase-less key, and `<dir>/gpg` to use it.
    pub fn create(dir: &Path) -> Self {
        let home = dir.join("gnupg");
        fs::create_dir_all(&home).unwrap();
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
        let generated = Command::new(GPG)
            .arg("--homedir")
            .arg(&home)
            .args([
                "--batch",
                "--quiet",
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                "",
            ])
            .args([
                "--quick-generate-key",
                USER_ID,
                "default",
                "default",
                "never",
            ])
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(
            generated.status.success(),
            "gpg --quick-generate-key: {}",
            String::from_utf8_lossy(&generated.stderr)
        );
        let wrapper = write_script(
            dir,
            "gpg",
            &format!(
                "echo run >> \"$0.runs\"\nexec {GPG} --homedir '{}' \"$@\"\n",
                home.display()
            ),
        );
        Self { home, wrapper }
    }

    /// Writes `plaintext`, encrypted to the throwaway key, to `file`.
    pub fn encrypt(&self, plaintext: &[u8], file: &Path) {
        let mut child = Command::new(GPG)
            .arg("--homedir")
            .arg(&self.home)
            .args(["--batch", "--quiet", "--yes", "--trust-model", "always"])
            .args(["--recipient", USER_ID, "--encrypt", "--output"])
            .arg(file)
            .stdin(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(plaintext).unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "gpg --encrypt: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
