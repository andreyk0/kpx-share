//! Throwaway child processes to be the "watched process" of a session.

#![allow(dead_code, unreachable_pub)]

use std::process::{Child, Command, Stdio};

use kpx_share::process::ProcessIdentity;
use rustix::process::Pid;

/// A `sleep` that is killed when this goes out of scope.
pub struct Sleeper(Child);

impl Sleeper {
    pub fn spawn() -> Self {
        Self(
            Command::new("sleep")
                .arg("600")
                .stdin(Stdio::null())
                .spawn()
                .expect("sleep must be installed for these tests"),
        )
    }

    pub fn pid(&self) -> Pid {
        Pid::from_raw(i32::try_from(self.0.id()).unwrap()).unwrap()
    }

    pub fn identity(&self) -> ProcessIdentity {
        ProcessIdentity::of_running(self.pid()).unwrap()
    }

    /// Kills it but leaves it unreaped: a zombie, which still has its pid and start time.
    pub fn kill_leaving_zombie(&mut self) {
        self.0.kill().unwrap();
    }

    /// Kills it and reaps it, so its pid is free to be recycled.
    pub fn kill(&mut self) {
        let _already_dead = self.0.kill();
        self.0.wait().unwrap();
    }
}

impl Drop for Sleeper {
    fn drop(&mut self) {
        let _already_dead = self.0.kill();
        let _reaped = self.0.wait();
    }
}

/// This test process itself: alive for as long as the test runs.
pub fn this_process() -> ProcessIdentity {
    ProcessIdentity::of_running(rustix::process::getpid()).unwrap()
}
