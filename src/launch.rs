//! Starting the watcher so that it outlives the `!` command that started it.
//!
//! Production runs it as a transient user unit of systemd, `kpx-share-<session>`, which no
//! process group or terminal hang-up of the caller reaches. [`WatcherLauncher`] is the seam
//! between `add` and that mechanism.

use std::ffi::OsString;
use std::io;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use crate::layout::{SessionName, ShareRoot};
use crate::subprocess::{ToolError, capture_stderr};
use crate::tools;

/// What the watcher is to watch.
#[derive(Clone, Copy, Debug)]
pub struct WatcherSpec<'a> {
    pub root: &'a ShareRoot,
    pub session: &'a SessionName,
}

impl WatcherSpec<'_> {
    /// The arguments of the hidden `watch` subcommand that does the watching.
    #[must_use]
    pub fn args(&self) -> Vec<OsString> {
        vec![
            "watch".into(),
            "--session".into(),
            self.session.as_str().into(),
            "--root".into(),
            self.root.path().into(),
        ]
    }
}

/// What [`WatcherLauncher::ensure_running`] found or did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Launch {
    Started,
    /// A watcher for this session was already running; it follows the session record, so it
    /// covers this add too.
    AlreadyRunning,
}

/// Makes sure one watcher runs for a session.
pub trait WatcherLauncher: std::fmt::Debug {
    /// # Errors
    /// The watcher could not be started and was not already running.
    fn ensure_running(&self, spec: &WatcherSpec<'_>) -> Result<Launch, ToolError>;
}

/// `systemd-run --user`, with the unit named after the session.
#[derive(Clone, Debug)]
pub struct SystemdRun {
    /// This program, as an absolute path: what the unit runs.
    executable: PathBuf,
}

impl SystemdRun {
    /// # Errors
    /// The path of the running executable cannot be determined.
    pub fn for_current_exe() -> io::Result<Self> {
        std::env::current_exe().map(|executable| Self { executable })
    }

    #[must_use]
    pub fn new(executable: PathBuf) -> Self {
        Self { executable }
    }

    /// `kpx-share-<session>`; systemd adds `.service`.
    #[must_use]
    pub fn unit_name(session: &SessionName) -> String {
        format!("kpx-share-{}", session.as_str())
    }

    /// Whether the unit is active. Anything but a clean "active" counts as not running: if
    /// systemd cannot be reached at all, `systemd-run` fails next and says so.
    fn is_active(unit: &str) -> bool {
        Command::new(tools::path(tools::SYSTEMCTL))
            .args(["--user", "is-active", "--quiet"])
            .arg(format!("{unit}.service"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    }
}

impl WatcherLauncher for SystemdRun {
    fn ensure_running(&self, spec: &WatcherSpec<'_>) -> Result<Launch, ToolError> {
        let unit = Self::unit_name(spec.session);
        if Self::is_active(&unit) {
            return Ok(Launch::AlreadyRunning);
        }
        let tool = tools::path(tools::SYSTEMD_RUN);
        let mut child = Command::new(tool)
            .args(["--user", "--collect", "--quiet"])
            .arg(format!("--unit={unit}"))
            .arg("--")
            .arg(&self.executable)
            .args(spec.args())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|source| ToolError::Spawn {
                tool: tool.to_owned(),
                source,
            })?;
        let stderr = child.stderr.take().map(capture_stderr).unwrap_or_default();
        let status = child.wait().map_err(|source| ToolError::Io {
            tool: tool.to_owned(),
            source,
        })?;
        if status.success() {
            Ok(Launch::Started)
        } else {
            Err(ToolError::Failed {
                tool: tool.to_owned(),
                status,
                stderr,
            })
        }
    }
}
