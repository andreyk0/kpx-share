//! Writing one entry into a session directory, and listing it back.
//!
//! Method: build `ResolvedEntry` values the real way (hand-written XML, `import`, `pick`,
//! `resolve`), write them to a session on tmpfs, and compare the bytes on disk with values
//! written out here from the layout in `kpx_share::writer`. Each test's doc comment names the
//! mutation that turns it red. Permissions under a hostile umask are in `tests/umask.rs`, which
//! needs its own process.

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

use common::share::{is_dir, partials, resolve_any, scratch_on_tmpfs, session_in, tree, validity};
use common::{entry, string};
use kpx_share::layout::{ListError, SafeName};
use kpx_share::meta::{EligibilityRecord, OtpFormatRecord, OtpProblemRecord, OtpRecord};
use kpx_share::writer::{NameKind, WriteError, write_entry};

const NO_META: &str = "";
const NONE: [&str; 0] = [];

fn read(dir: &Path, relative: &str) -> Vec<u8> {
    fs::read(dir.join(relative)).unwrap()
}

fn paths(dir: &Path) -> Vec<String> {
    tree(dir)
        .iter()
        .map(|path| path.to_str().unwrap().to_owned())
        .collect()
}

/// A custom attribute `name` → `value`, an attachment and a TOTP, all in one entry.
const BINARIES: &str = r#"<Binaries><Binary ID="0">cGxhaW4AYnl0ZXP/</Binary></Binaries>"#;

fn full_entry(uuid_byte: u8) -> kpx_share::ResolvedEntry {
    let body = entry(
        uuid_byte,
        &[
            string("Title", "GitHub login"),
            string("UserName", "octocat"),
            string("Password", "hunter2"),
            string("URL", "https://github.com"),
            string("Notes", "note"),
            string("API key", "k-123"),
            string("otp", "otpauth://totp/GH:octocat?secret=JBSWY3DPEHPK3PXP"),
            "<Tags>agent;ops</Tags>".to_owned(),
            r#"<Binary><Key>cert.pem</Key><Value Ref="0"/></Binary>"#.to_owned(),
        ]
        .concat(),
    );
    resolve_any(BINARIES, &body, uuid_byte)
}

/// Red when a file of the documented layout is not written, is misnamed, or holds other bytes.
#[test]
fn writes_the_documented_layout() {
    let scratch = scratch_on_tmpfs();
    let session = session_in(scratch.path());

    let written = write_entry(&session, &full_entry(0x01), &validity()).unwrap();

    assert_eq!(written.path(), session.path().join("GitHub_login"));
    assert_eq!(written.slug().as_str(), "GitHub_login");
    assert_eq!(
        paths(written.path()),
        [
            "attachments",
            "attachments/cert.pem",
            "attributes",
            "attributes/API_key",
            "meta.json",
            "notes",
            "otp",
            "password",
            "title",
            "url",
            "username",
        ]
    );
    let dir = written.path();
    assert_eq!(read(dir, "username"), b"octocat");
    assert_eq!(read(dir, "password"), b"hunter2");
    assert_eq!(read(dir, "url"), b"https://github.com");
    assert_eq!(read(dir, "notes"), b"note");
    assert_eq!(read(dir, "title"), b"GitHub login");
    assert_eq!(read(dir, "attributes/API_key"), b"k-123");
    assert_eq!(
        read(dir, "otp"),
        b"otpauth://totp/GH:octocat?secret=JBSWY3DPEHPK3PXP"
    );
    assert_eq!(read(dir, "attachments/cert.pem"), b"plain\0bytes\xff");
    assert_eq!(partials(&session), NONE);
}

/// I5. Red when the writer appends a newline, trims, or normalises line endings.
#[test]
fn values_are_written_byte_exact() {
    let scratch = scratch_on_tmpfs();
    let session = session_in(scratch.path());
    let body = entry(
        0x02,
        &[
            string("Title", "bytes"),
            string("Password", "  spaced\ttab  "),
            string("Notes", "first\n  second  \n\n\nlast\n"),
            string("UserName", ""),
        ]
        .concat(),
    );
    let resolved = resolve_any(NO_META, &body, 0x02);

    let dir = write_entry(&session, &resolved, &validity()).unwrap();

    assert_eq!(read(dir.path(), "password"), b"  spaced\ttab  ");
    assert_eq!(read(dir.path(), "notes"), b"first\n  second  \n\n\nlast\n");
    assert_eq!(read(dir.path(), "username"), b"");
}

/// Red when an absent standard field is skipped instead of written empty, or an `otp` file is
/// written for an entry without readable TOTP.
#[test]
fn absent_and_empty_fields_are_empty_files_and_otp_exists_only_with_totp() {
    let scratch = scratch_on_tmpfs();
    let session = session_in(scratch.path());
    let body = entry(0x03, &[string("Title", "bare"), string("URL", "")].concat());

    let dir = write_entry(&session, &resolve_any(NO_META, &body, 0x03), &validity()).unwrap();

    for file in ["username", "password", "url", "notes"] {
        assert_eq!(read(dir.path(), file), b"", "{file}");
    }
    assert!(!dir.path().join("otp").exists());
    let meta = kpx_share::meta::read(&dir).unwrap();
    assert_eq!(meta.otp, OtpRecord::Absent);
}

/// Red when a value is copied into `meta.json`: the marker is in every value-carrying place.
#[test]
fn meta_json_holds_no_secret_and_reads_back_typed() {
    const MARKER: &str = "SECRET-MARKER-9d41c7";
    let scratch = scratch_on_tmpfs();
    let session = session_in(scratch.path());
    let body = entry(
        0x04,
        &[
            string("Title", "Marked"),
            string("UserName", &format!("user-{MARKER}")),
            string("Password", &format!("pw-{MARKER}")),
            string("URL", &format!("https://x/{MARKER}")),
            string("Notes", &format!("notes {MARKER}")),
            string("Custom", &format!("custom-{MARKER}")),
            string("otp", &format!("otpauth://totp/A:b?secret={MARKER}")),
            "<Tags>agent</Tags>".to_owned(),
            r#"<Binary><Key>blob</Key><Value Ref="0"/></Binary>"#.to_owned(),
        ]
        .concat(),
    );
    let binaries = format!(r#"<Binaries><Binary ID="0">{}</Binary></Binaries>"#, {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(MARKER)
    });
    let resolved = resolve_any(&binaries, &body, 0x04);

    let dir = write_entry(&session, &resolved, &validity()).unwrap();

    let meta_text = String::from_utf8(read(dir.path(), "meta.json")).unwrap();
    assert!(!meta_text.contains(MARKER), "{meta_text}");
    // The marker really is in the entry: it reached the value files.
    for file in [
        "username",
        "password",
        "url",
        "notes",
        "attributes/Custom",
        "otp",
        "attachments/blob",
    ] {
        let content = String::from_utf8(read(dir.path(), file)).unwrap();
        assert!(content.contains(MARKER), "{file}");
    }

    let listed = session.entries().unwrap();
    assert_eq!(listed.len(), 1);
    let meta = listed[0].meta.as_ref().unwrap();
    assert_eq!(meta.uuid.to_string(), "04".repeat(16));
    assert_eq!(meta.path, "Marked");
    assert_eq!(meta.tags, ["agent"]);
    assert_eq!(meta.eligibility, EligibilityRecord::Any);
    assert_eq!(meta.validity, validity());
    assert_eq!(meta.fields["UserName"], "username");
    assert_eq!(meta.fields["Custom"], "attributes/Custom");
    assert_eq!(meta.attachments["blob"], "attachments/blob");
    assert_eq!(meta.otp, OtpRecord::Present { file: "otp".into() });
    assert_eq!(meta.unresolved, NONE);
}

/// Red when `unresolved`, the group path, the eligibility rule or the OTP issue is not recorded.
#[test]
fn meta_json_records_unresolved_fields_group_path_and_otp_trouble() {
    let scratch = scratch_on_tmpfs();
    let session = session_in(scratch.path());
    let inner = entry(
        0x05,
        &[
            string("Title", "Deep"),
            string("Notes", "{REF:P@I:ffffffffffffffffffffffffffffffff}"),
            string("TOTP Seed", "SEED"),
            string("TOTP Settings", "not-settings"),
            "<Tags>Agent</Tags>".to_owned(),
        ]
        .concat(),
    );
    let body = format!(
        "<Group><UUID>qqqqqqqqqqqqqqqqqqqqqg==</UUID><Name>Work</Name><Group><UUID>qqqqqqqqqqqqqqqqqqqqqg==</UUID><Name>Sub</Name>{inner}</Group></Group>"
    );
    let database = common::import_str(&common::document(NO_META, &body));
    let resolved = database
        .pick(
            common::uuid(0x05),
            kpx_share::Eligibility::Tagged(kpx_share::RequiredTag::agent()),
        )
        .unwrap()
        .resolve();

    let dir = write_entry(&session, &resolved, &validity()).unwrap();

    let meta = kpx_share::meta::read(&dir).unwrap();
    assert_eq!(meta.path, "Work/Sub/Deep");
    assert_eq!(meta.unresolved, ["Notes"]);
    assert_eq!(
        meta.eligibility,
        EligibilityRecord::Tagged {
            tag: "agent".into()
        }
    );
    assert_eq!(
        meta.otp,
        OtpRecord::Unrecognised {
            format: OtpFormatRecord::KeePassXcLegacy,
            problem: OtpProblemRecord::InvalidSettings,
        }
    );
    assert!(!dir.path().join("otp").exists());
    assert_eq!(read(dir.path(), "attributes/TOTP_Seed"), b"SEED");
}

/// I4. Red when the partial directory is not removed after the rename is refused, when the
/// refused entry overwrites the first, or when the error is not `SlugTaken`.
#[test]
fn a_different_entry_with_the_same_slug_is_refused_and_leaves_no_partial() {
    let scratch = scratch_on_tmpfs();
    let session = session_in(scratch.path());
    let first = resolve_any(
        NO_META,
        &entry(
            0x06,
            &(string("Title", "Same") + &string("Password", "first")),
        ),
        0x06,
    );
    let second = resolve_any(
        NO_META,
        &entry(
            0x07,
            &(string("Title", "Same") + &string("Password", "second")),
        ),
        0x07,
    );
    let written = write_entry(&session, &first, &validity()).unwrap();

    let error = write_entry(&session, &second, &validity()).unwrap_err();

    match error {
        WriteError::SlugTaken { path, existing } => {
            assert_eq!(path, written.path());
            assert_eq!(existing.to_string(), "06".repeat(16));
        }
        other => panic!("expected SlugTaken, got {other:?}"),
    }
    assert_eq!(partials(&session), Vec::<String>::new());
    assert_eq!(read(written.path(), "password"), b"first");
    assert_eq!(session.entries().unwrap().len(), 1);
}

/// I4. An existing directory that is not one of ours is never replaced, even by "the same" title.
/// Red when a missing or unparsable `meta.json` is treated as "same entry".
#[test]
fn a_directory_without_readable_meta_is_never_replaced() {
    let scratch = scratch_on_tmpfs();
    let session = session_in(scratch.path());
    let squatter = session.path().join("Title");
    fs::create_dir(&squatter).unwrap();
    fs::write(squatter.join("mine"), b"precious").unwrap();
    let resolved = resolve_any(NO_META, &entry(0x08, &string("Title", "Title")), 0x08);

    let error = write_entry(&session, &resolved, &validity()).unwrap_err();

    assert!(
        matches!(error, WriteError::ExistingUnreadable { .. }),
        "{error:?}"
    );
    assert_eq!(read(&squatter, "mine"), b"precious");
    assert_eq!(partials(&session), NONE);
}

struct StopOnDrop<'a>(&'a AtomicBool);

impl Drop for StopOnDrop<'_> {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

/// A re-add of the same entry is matched by UUID, not by slug: after its title changed there is
/// one directory, the new one. Another entry, and a directory whose `meta.json` cannot be read,
/// are not this entry and stay. Red when the old directory is left (two directories hold one
/// UUID), when the removal is by anything but the UUID (the bystander goes), or when an
/// unreadable directory is taken for a copy.
#[test]
fn the_same_entry_under_a_new_title_leaves_one_directory_and_no_other_is_touched() {
    let scratch = scratch_on_tmpfs();
    let session = session_in(scratch.path());
    let titled = |uuid_byte: u8, title: &str, password: &str| {
        resolve_any(
            NO_META,
            &entry(
                uuid_byte,
                &(string("Title", title) + &string("Password", password)),
            ),
            uuid_byte,
        )
    };
    write_entry(&session, &titled(0x0a, "Bystander", "other"), &validity()).unwrap();
    fs::create_dir(session.path().join("Unreadable")).unwrap();
    let before = write_entry(&session, &titled(0x09, "Before", "v1"), &validity()).unwrap();

    let after = write_entry(&session, &titled(0x09, "After", "v2"), &validity()).unwrap();

    assert_eq!(after.slug().as_str(), "After");
    assert!(
        !before.path().exists(),
        "the earlier directory is still there"
    );
    assert_eq!(read(after.path(), "password"), b"v2");
    let mut names: Vec<String> = fs::read_dir(session.path())
        .unwrap()
        .map(|item| item.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    assert_eq!(names, ["After", "Bystander", "Unreadable"]);
}

/// I4. Red when a replacement leaves old files behind (merge), when the old entry is not
/// removed, or when a reader polling the path sees it missing: the poller runs through many
/// replacements, so a remove-then-rename implementation is caught with high probability, not
/// with certainty.
#[test]
fn the_same_entry_replaces_the_old_one_without_the_path_ever_disappearing() {
    const REPLACEMENTS: usize = 300;
    let scratch = scratch_on_tmpfs();
    let session = session_in(scratch.path());
    let old = resolve_any(
        NO_META,
        &entry(
            0x09,
            &[
                string("Title", "Rotating"),
                string("Password", "v1"),
                string("OnlyInV1", "old"),
            ]
            .concat(),
        ),
        0x09,
    );
    let written = write_entry(&session, &old, &validity()).unwrap();
    let entry_path: PathBuf = written.path().to_owned();

    let done = AtomicBool::new(false);
    let missing = thread::scope(|scope| {
        let poller = scope.spawn(|| {
            let mut missing = 0usize;
            while !done.load(Ordering::Acquire) {
                if fs::read(entry_path.join("password")).is_err() {
                    missing += 1;
                }
            }
            missing
        });
        // Stops the poller when this scope ends, panic included; else a failed assertion below
        // would leave `thread::scope` waiting for it forever.
        let _stop = StopOnDrop(&done);
        for round in 0..REPLACEMENTS {
            let version = format!("v{}", round + 2);
            let new = resolve_any(
                NO_META,
                &entry(
                    0x09,
                    &(string("Title", "Rotating") + &string("Password", &version)),
                ),
                0x09,
            );
            let again = write_entry(&session, &new, &validity()).unwrap();
            assert_eq!(again.path(), entry_path);
        }
        done.store(true, Ordering::Release);
        poller.join().unwrap()
    });

    assert_eq!(
        missing, 0,
        "the entry was missing or unreadable mid-replace"
    );
    assert_eq!(
        read(&entry_path, "password"),
        format!("v{}", REPLACEMENTS + 1).as_bytes()
    );
    assert!(!entry_path.join("attributes/OnlyInV1").exists());
    assert_eq!(partials(&session), NONE);
    assert_eq!(session.entries().unwrap().len(), 1);
}

/// Red when `.partial-*` is listed as an entry (or makes the listing fail).
#[test]
fn listing_ignores_in_progress_writes_and_reports_strangers() {
    let scratch = scratch_on_tmpfs();
    let session = session_in(scratch.path());
    write_entry(&session, &full_entry(0x0a), &validity()).unwrap();
    let in_progress = session.path().join(".partial-0123456789abcdef");
    fs::create_dir(&in_progress).unwrap();
    fs::write(in_progress.join("meta.json"), b"{}").unwrap();

    let listed = session.entries().unwrap();

    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].dir.slug().as_str(), "GitHub_login");

    fs::write(session.path().join("stray.txt"), b"").unwrap();
    assert!(matches!(
        session.entries(),
        Err(ListError::Foreign(path)) if path.ends_with("stray.txt")
    ));
}

/// Red when one unreadable `meta.json` hides the other entries, or is reported as fine.
#[test]
fn a_corrupt_meta_is_reported_beside_its_entry() {
    let scratch = scratch_on_tmpfs();
    let session = session_in(scratch.path());
    let good = write_entry(&session, &full_entry(0x0b), &validity()).unwrap();
    let bad = write_entry(
        &session,
        &resolve_any(NO_META, &entry(0x0c, &string("Title", "Bad")), 0x0c),
        &validity(),
    )
    .unwrap();
    fs::write(bad.path().join("meta.json"), b"{\"version\": 7}").unwrap();

    let listed = session.entries().unwrap();

    let by_slug = |slug: &str| {
        listed
            .iter()
            .find(|listed| listed.dir.slug().as_str() == slug)
            .unwrap()
    };
    assert!(by_slug(good.slug().as_str()).meta.is_ok());
    assert!(by_slug("Bad").meta.is_err());
}

/// Red when two names that sanitise alike overwrite one another instead of failing, or when the
/// failure happens after some bytes were written.
#[test]
fn attribute_names_that_sanitise_alike_are_an_error_and_write_nothing() {
    let scratch = scratch_on_tmpfs();
    let session = session_in(scratch.path());
    let body = entry(
        0x0d,
        &[
            string("Title", "Clash"),
            string("a b", "one"),
            string("a/b", "two"),
        ]
        .concat(),
    );

    let error = write_entry(&session, &resolve_any(NO_META, &body, 0x0d), &validity()).unwrap_err();

    match error {
        WriteError::NameCollision { kind, file, .. } => {
            assert_eq!(kind, NameKind::Attribute);
            assert_eq!(file, "attributes/a_b");
        }
        other => panic!("expected NameCollision, got {other:?}"),
    }
    assert!(
        tree(session.path()).is_empty(),
        "{:?}",
        tree(session.path())
    );
}

/// Red when an attribute and an attachment of one name collide (they have separate directories),
/// or when a name with nothing to name a file by is written.
#[test]
fn attribute_and_attachment_may_share_a_name_and_an_unusable_name_is_an_error() {
    let scratch = scratch_on_tmpfs();
    let session = session_in(scratch.path());
    let both = entry(
        0x0e,
        &[
            string("Title", "Both"),
            string("same", "attribute"),
            r#"<Binary><Key>same</Key><Value Ref="0"/></Binary>"#.to_owned(),
        ]
        .concat(),
    );
    let dir = write_entry(&session, &resolve_any(BINARIES, &both, 0x0e), &validity()).unwrap();
    assert_eq!(read(dir.path(), "attributes/same"), b"attribute");
    assert_eq!(read(dir.path(), "attachments/same"), b"plain\0bytes\xff");

    let unusable = entry(0x0f, &(string("Title", "Unusable") + &string("..", "x")));
    let error = write_entry(
        &session,
        &resolve_any(NO_META, &unusable, 0x0f),
        &validity(),
    )
    .unwrap_err();
    assert!(
        matches!(
            error,
            WriteError::UnusableName {
                kind: NameKind::Attribute,
                ..
            }
        ),
        "{error:?}"
    );
    assert!(!session.path().join("Unusable").exists());
}

/// Red when a hostile attribute name writes outside `attributes/`, or when titles are not
/// sanitised into one path component.
#[test]
fn hostile_names_stay_inside_the_entry() {
    let scratch = scratch_on_tmpfs();
    let session = session_in(scratch.path());
    let body = entry(
        0x10,
        &[
            string("Title", "../../escape"),
            string("../../../../pwned", "x"),
        ]
        .concat(),
    );

    let dir = write_entry(&session, &resolve_any(NO_META, &body, 0x10), &validity()).unwrap();

    assert_eq!(dir.path().parent().unwrap(), session.path());
    assert_eq!(dir.slug().as_str(), "_.._escape");
    assert_eq!(
        paths(dir.path())
            .iter()
            .filter(|p| p.starts_with("attributes/"))
            .count(),
        1
    );
    assert_eq!(
        paths(scratch.path())
            .iter()
            .filter(|path| !path.starts_with("kpx-share"))
            .count(),
        0,
        "nothing was written outside the share root"
    );
}

/// Red when an entry without a usable title is not named by its UUID.
#[test]
fn an_entry_without_a_usable_title_is_named_by_its_uuid() {
    let scratch = scratch_on_tmpfs();
    let session = session_in(scratch.path());
    for (byte, title) in [(0x11u8, None), (0x12, Some("")), (0x13, Some("///"))] {
        let children = title.map_or_else(String::new, |title| string("Title", title));
        let resolved = resolve_any(NO_META, &entry(byte, &children), byte);

        let dir = write_entry(&session, &resolved, &validity()).unwrap();

        assert_eq!(dir.slug().as_str(), format!("{byte:02x}").repeat(16));
        assert_eq!(
            SafeName::parse(dir.slug().as_str()).as_ref(),
            Some(dir.slug())
        );
    }
}

/// Everything lives below the share root: after a write the scratch directory holds `kpx-share`
/// and nothing else. Red when a temporary file is created beside it.
#[test]
fn nothing_is_written_outside_the_share_root() {
    let scratch = scratch_on_tmpfs();
    let session = session_in(scratch.path());

    write_entry(&session, &full_entry(0x14), &validity()).unwrap();

    let top: Vec<_> = fs::read_dir(scratch.path())
        .unwrap()
        .map(|item| item.unwrap().file_name())
        .collect();
    assert_eq!(top, ["kpx-share"]);
    assert!(is_dir(&scratch.path().join("kpx-share/s1")));
}

/// A title that resolves to another entry's password must not name the directory or appear in
/// `meta.json`; only the `title` file holds the resolved value. Red when the slug or `meta.path`
/// is derived from the resolved title instead of the stored one.
#[test]
fn a_title_that_resolves_to_a_password_names_nothing() {
    const MARKER: &str = "MARKER-pw-7f3a91";
    let reference = format!("{{REF:P@I:{}}}", common::uuid_hex(0x02));
    let body = [
        entry(0x01, &string("Title", &reference)),
        entry(
            0x02,
            &[string("Title", "Target"), string("Password", MARKER)].concat(),
        ),
    ]
    .concat();
    let scratch = scratch_on_tmpfs();
    let session = session_in(scratch.path());

    let written = write_entry(&session, &resolve_any(NO_META, &body, 0x01), &validity()).unwrap();

    assert_eq!(read(written.path(), "title"), MARKER.as_bytes());
    assert_eq!(
        written.slug().as_str(),
        "_REF_P_I_02020202020202020202020202020202_"
    );
    let meta = String::from_utf8(read(written.path(), "meta.json")).unwrap();
    assert!(!meta.contains(MARKER), "{meta}");
    assert!(meta.contains(&reference), "{meta}");
    for name in paths(session.path()) {
        assert!(!name.contains(MARKER), "{name}");
    }
}
