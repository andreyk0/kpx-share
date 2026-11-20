//! Small helpers for the modules that run external programs.

use std::io::{self, Read};
use std::path::PathBuf;
use std::process::ExitStatus;

use crate::text::one_line;

/// How running an external program went wrong, whichever program it is. No variant holds what
/// was written to the program's stdin or read from its stdout.
#[derive(Debug, thiserror::Error)]
pub enum ToolError {
    #[error("could not run {}: {source}", tool.display())]
    Spawn { tool: PathBuf, source: io::Error },
    #[error("I/O with {} failed: {source}", tool.display())]
    Io { tool: PathBuf, source: io::Error },
    /// It ran and exited unsuccessfully; `stderr` is what it said, bounded and on one line (see
    /// [`capture_stderr`]), possibly empty.
    #[error("{} exited with {status}{}", tool.display(), stderr_suffix(stderr))]
    Failed {
        tool: PathBuf,
        status: ExitStatus,
        stderr: String,
    },
}

fn stderr_suffix(stderr: &str) -> String {
    if stderr.is_empty() {
        String::new()
    } else {
        format!(": {stderr}")
    }
}

/// A pipe that was requested with `Stdio::piped()` and so is always there.
pub(crate) fn take_pipe<T>(pipe: Option<T>) -> io::Result<T> {
    pipe.ok_or_else(|| io::Error::other("a requested pipe is missing"))
}

/// A child that exited before reading its stdin is not an I/O failure: its exit status says why.
pub(crate) fn ignore_broken_pipe(written: io::Result<()>) -> io::Result<()> {
    match written {
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => Ok(()),
        other => other,
    }
}

/// Bound on the stderr kept; the rest is read and dropped so the child never blocks on a full pipe.
const STDERR_BYTES_MAX: u64 = 2048;

/// A child's stderr as one trimmed line, bounded, so it cannot drive the terminal it is printed
/// on.
pub(crate) fn capture_stderr(mut stderr: impl Read) -> String {
    let mut text = Vec::new();
    // A read error ends the capture with what arrived: this is best-effort context for a failure.
    let _read = (&mut stderr).take(STDERR_BYTES_MAX).read_to_end(&mut text);
    let _drained = io::copy(&mut stderr, &mut io::sink());
    one_line(&String::from_utf8_lossy(&text)).trim().to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn captured_stderr_is_bounded_and_one_line() {
        let noisy = [&b"ok \x1b[31mred\x07\n"[..], &[b'x'; 5000]].concat();
        let text = capture_stderr(&noisy[..]);
        assert!(text.starts_with("ok  [31mred  xxx"), "{text:?}");
        assert_eq!(text.len(), 2048);
    }

    #[test]
    fn a_broken_pipe_is_not_an_error_but_other_errors_are() {
        assert!(ignore_broken_pipe(Err(io::ErrorKind::BrokenPipe.into())).is_ok());
        assert!(ignore_broken_pipe(Err(io::ErrorKind::PermissionDenied.into())).is_err());
    }
}
