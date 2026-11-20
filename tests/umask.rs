//! Directories are 0700 and files 0600 whatever the umask.
//!
//! The umask is process-wide, so this is its own test binary with one `#[test]`. It runs the whole
//! write under two umasks: 0, which would leave a file created without an explicit mode at 0666,
//! and 0o277, which would strip the owner's write bit from a file whose mode was never set
//! explicitly afterwards.

mod common;

use std::fs;

use common::share::{mode, resolve_any, scratch_on_tmpfs, session_in, tree, validity};
use common::{entry, string};
use rustix::fs::Mode;
use rustix::process::umask;

const BINARIES: &str = r#"<Binaries><Binary ID="0">cGxhaW4AYnl0ZXP/</Binary></Binaries>"#;

#[test]
fn modes_are_exact_under_a_hostile_umask() {
    for (round, hostile) in [0o000, 0o277].into_iter().enumerate() {
        let scratch = scratch_on_tmpfs();
        let previous = umask(Mode::from_bits_truncate(hostile));

        let body = entry(
            0x01,
            &[
                string("Title", "Modes"),
                string("Password", "p"),
                string("Extra", "e"),
                r#"<Binary><Key>blob</Key><Value Ref="0"/></Binary>"#.to_owned(),
            ]
            .concat(),
        );
        let session = session_in(scratch.path());
        let written = kpx_share::writer::write_entry(
            &session,
            &resolve_any(BINARIES, &body, 0x01),
            &validity(),
        );
        // Restore before any assertion can unwind with the hostile umask still set.
        umask(previous);
        let written = written.unwrap();

        let root = scratch.path().join("kpx-share");
        assert_eq!(mode(&root), 0o700, "round {round}: share root");
        assert_eq!(mode(session.path()), 0o700, "round {round}: session");
        assert_eq!(mode(written.path()), 0o700, "round {round}: entry");
        let below = tree(written.path());
        assert!(below.len() >= 10, "{below:?}");
        for relative in below {
            let path = written.path().join(&relative);
            let expected = if fs::symlink_metadata(&path).unwrap().is_dir() {
                0o700
            } else {
                0o600
            };
            assert_eq!(
                mode(&path),
                expected,
                "round {round}, umask {hostile:03o}: {}",
                relative.display()
            );
        }
    }
}
