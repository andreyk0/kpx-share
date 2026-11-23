//! The external programs kpx-share runs, by absolute path.
//!
//! Absolute, so a `PATH` entry an agent controls cannot substitute one of them: these are the
//! programs that see the master password and the decrypted database.

use std::path::Path;

pub const KEEPASSXC_CLI: &str = "/usr/bin/keepassxc-cli";
pub const FZF: &str = "/usr/bin/fzf";
pub const FUZZEL: &str = "/usr/bin/fuzzel";
pub const PINENTRY_GNOME3: &str = "/usr/bin/pinentry-gnome3";
pub const GPG: &str = "/usr/bin/gpg";
pub const SYSTEMD_RUN: &str = "/usr/bin/systemd-run";
pub const SYSTEMCTL: &str = "/usr/bin/systemctl";

/// A tool's absolute path as a [`Path`].
#[must_use]
pub fn path(tool: &'static str) -> &'static Path {
    Path::new(tool)
}
