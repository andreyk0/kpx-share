//! Process hardening: the decrypted database must never reach disk (invariant I6).
//!
//! A core dump of a process holding the XML would write it out, and a dumpable process can be
//! inspected through `/proc/<pid>/mem` by anything running as the same user. [`harden`] closes
//! both for this process, and the first for the children it spawns, before the first secret is
//! read.

use rustix::io::Errno;
use rustix::process::{DumpableBehavior, Resource, Rlimit, set_dumpable_behavior, setrlimit};

#[derive(Debug, thiserror::Error)]
pub enum HardenError {
    #[error("could not mark the process non-dumpable: {0}")]
    NotDumpable(#[source] Errno),
    #[error("could not set the core file size limit to 0: {0}")]
    CoreLimit(#[source] Errno),
}

/// Makes the process non-dumpable and forbids core files (`RLIMIT_CORE` soft and hard = 0).
///
/// Call it first thing in `main`. Only the core limit reaches the children kpx-share spawns:
/// `execve` resets `PR_SET_DUMPABLE`, so each child is dumpable unless it hardens itself.
/// keepassxc-cli 2.8.0 makes itself non-dumpable (measured); pinentry-gnome3 is covered by the
/// inherited limit alone, which systemd-coredump honours.
///
/// # Errors
/// Either syscall fails; the process must not go on to read secrets.
pub fn harden() -> Result<(), HardenError> {
    set_dumpable_behavior(DumpableBehavior::NotDumpable).map_err(HardenError::NotDumpable)?;
    setrlimit(
        Resource::Core,
        Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )
    .map_err(HardenError::CoreLimit)
}
