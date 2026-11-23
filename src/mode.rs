//! Whether a human is at a terminal, decided once at startup.
//!
//! keepassxc-cli reads the master password from its **stdin** (measured: with a controlling
//! terminal present but stdin a pipe, it consumed the pipe and ignored the terminal), and fzf
//! draws on `/dev/tty`. So the terminal workflow needs both: stdin is a terminal, and
//! `/dev/tty` opens. Under Claude Code's `!` there is neither (stdin is not a tty), so the
//! password comes from pinentry and the picker is a GUI.
//!
//! Requiring both, rather than `/dev/tty` alone, errs towards the GUI: a piped stdin in a real
//! shell gets pinentry instead of a keepassxc-cli that would read the pipe as the password.

use std::fs::OpenOptions;
use std::io::{self, IsTerminal};

/// How the human is reached.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// A real shell: keepassxc-cli prompts on the terminal, the picker is fzf.
    Terminal,
    /// No terminal (a `!` command): the password comes from pinentry, the picker is fuzzel.
    NoTerminal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stdin {
    Terminal,
    NotTerminal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControllingTerminal {
    Opens,
    Absent,
}

impl Mode {
    /// Probes the process's real stdin and `/dev/tty`.
    #[must_use]
    pub fn detect() -> Self {
        let stdin = if io::stdin().is_terminal() {
            Stdin::Terminal
        } else {
            Stdin::NotTerminal
        };
        let controlling = match OpenOptions::new().read(true).write(true).open("/dev/tty") {
            Ok(_) => ControllingTerminal::Opens,
            Err(_) => ControllingTerminal::Absent,
        };
        Self::from_probes(stdin, controlling)
    }

    /// The decision, separated from the probes so every combination is testable.
    #[must_use]
    pub fn from_probes(stdin: Stdin, controlling: ControllingTerminal) -> Self {
        match (stdin, controlling) {
            (Stdin::Terminal, ControllingTerminal::Opens) => Self::Terminal,
            (Stdin::Terminal, ControllingTerminal::Absent)
            | (Stdin::NotTerminal, ControllingTerminal::Opens | ControllingTerminal::Absent) => {
                Self::NoTerminal
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_terminal_stdin_with_a_controlling_terminal_is_terminal_mode() {
        use ControllingTerminal::{Absent, Opens};
        use Stdin::{NotTerminal, Terminal};
        assert_eq!(Mode::from_probes(Terminal, Opens), Mode::Terminal);
        assert_eq!(Mode::from_probes(Terminal, Absent), Mode::NoTerminal);
        assert_eq!(Mode::from_probes(NotTerminal, Opens), Mode::NoTerminal);
        assert_eq!(Mode::from_probes(NotTerminal, Absent), Mode::NoTerminal);
    }
}
