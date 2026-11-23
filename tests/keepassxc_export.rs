//! Parsing real keepassxc-cli output.
//!
//! `tests/fixtures/agent-db.xml` is imported into a throwaway KDBX in a temp dir and exported
//! again with `keepassxc-cli export -f xml`, exactly as kpx-share will run it, so these tests read
//! what keepassxc-cli actually writes (re-compressed attachments, sorted tags, empty standard
//! fields filled in). Needs `keepassxc-cli` on `PATH`; without it these tests fail, never skip.
//! Expected values are written out by hand from the fixture.

mod common;

use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::OnceLock;

use common::{field, otp_uri, resolve, resolved, text, uuid, uuid_hex};
use kpx_share::model::{AttributeName, FieldName, StandardField, Tag};
use kpx_share::{Database, Eligibility, PickerItem, RequiredTag, SecretBytes};

const PASSWORD: &str = "pw";

fn keepassxc_cli(args: &[&str], stdin: &str) -> Vec<u8> {
    let mut child = Command::new("keepassxc-cli")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("keepassxc-cli must be installed for these tests");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "keepassxc-cli {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

/// The fixture as keepassxc-cli 2.8 exports it; built once per test binary.
fn exported_xml() -> &'static [u8] {
    static EXPORT: OnceLock<Vec<u8>> = OnceLock::new();
    EXPORT.get_or_init(|| {
        let dir = tempfile::tempdir().unwrap();
        let kdbx = dir.path().join("fixture.kdbx");
        common::create_throwaway_kdbx(&kdbx, PASSWORD, None);
        keepassxc_cli(
            &["export", "-q", "-f", "xml", kdbx.to_str().unwrap()],
            &format!("{PASSWORD}\n"),
        )
    })
}

fn database() -> Database {
    kpx_share::export::parse(SecretBytes::copy_from(exported_xml())).unwrap()
}

fn labels(items: &[PickerItem]) -> Vec<String> {
    items.iter().map(|item| item.label.path()).collect()
}

#[test]
fn history_versions_are_neither_entries_nor_fields() {
    let database = database();
    assert_eq!(database.entries().len(), 8);
    let server = database.entry(uuid(0x11)).unwrap();
    assert_eq!(field(server, StandardField::Title), Some("Server"));
    let names: Vec<&str> = server.custom().keys().map(AttributeName::as_str).collect();
    assert_eq!(names, ["API Key"]);
    for entry in database.entries() {
        for which in StandardField::ALL {
            let value = entry
                .fields()
                .get(which)
                .map_or(&b""[..], SecretBytes::expose);
            assert!(
                !value.windows(12).any(|w| w == b"OLD-HISTORY-"),
                "{entry:?}"
            );
        }
    }
}

#[test]
fn picker_lists_agent_tagged_live_entries() {
    let database = database();
    assert_eq!(
        labels(&database.picker_items(&Eligibility::Tagged(RequiredTag::agent()))),
        [
            "Server",
            "Work/Ref User",
            "Work/Sub/Steam",
            "Work/Sub/KeePass2",
            "Work/Sub/Cycle A",
        ]
    );
    assert_eq!(
        labels(&database.picker_items(&Eligibility::Any)),
        [
            "Server",
            "Untagged",
            "Work/Ref User",
            "Work/Sub/Steam",
            "Work/Sub/KeePass2",
            "Work/Sub/Cycle A",
            "Work/Sub/Cycle B",
        ]
    );
}

#[test]
fn values_survive_byte_exact() {
    let server = resolve(&database(), 0x11);
    assert_eq!(
        resolved(&server, StandardField::Notes),
        Some("line one\nline two with trailing spaces   \n\ttab-indented\n\n")
    );
    assert_eq!(
        resolved(&server, StandardField::Password),
        Some("pw-11 <current> & \"quoted\"")
    );
    assert_eq!(
        text(server.custom().get("API Key").unwrap()),
        "  spaced key  "
    );
    let tags: Vec<&str> = server.tags().as_slice().iter().map(Tag::name).collect();
    assert_eq!(tags, ["agent", "ops"]);
}

#[test]
fn attachments_are_decoded() {
    let server = resolve(&database(), 0x11);
    let attachments: Vec<(&str, &[u8])> = server
        .attachments()
        .iter()
        .map(|a| (a.name(), a.content().expose()))
        .collect();
    assert_eq!(
        attachments,
        [
            ("gz.txt", &b"gz-attach\n"[..]),
            ("plain.bin", b"plain-attach")
        ]
    );
}

#[test]
fn placeholders_resolve_against_the_database() {
    let database = database();
    let user = resolve(&database, 0x33);
    assert_eq!(
        resolved(&user, StandardField::UserName),
        Some("Ref User-user")
    );
    assert_eq!(
        resolved(&user, StandardField::Password),
        Some("pw-11 <current> & \"quoted\"")
    );
    assert_eq!(
        resolved(&user, StandardField::Url),
        Some("https://srv.example/login")
    );
    assert_eq!(
        resolved(&user, StandardField::Notes),
        Some("{UNKNOWN} and pw-11 <current> & \"quoted\"")
    );
    let unresolved: Vec<_> = user.unresolved().iter().cloned().collect();
    assert_eq!(unresolved, [FieldName::Standard(StandardField::Notes)]);

    let cycle = resolve(&database, 0x66);
    let expected = format!("{{REF:P@I:{}}}", uuid_hex(0x66));
    assert_eq!(resolved(&cycle, StandardField::Password), Some(&*expected));
    assert!(
        cycle
            .unresolved()
            .contains(&FieldName::Standard(StandardField::Password))
    );
}

#[test]
fn every_totp_layout_becomes_one_uri() {
    let database = database();
    assert_eq!(
        otp_uri(&resolve(&database, 0x11)),
        "otpauth://totp/Server:admin?secret=JBSWY3DPEHPK3PXP&issuer=Server"
    );
    let legacy = resolve(&database, 0x33);
    assert_eq!(
        otp_uri(&legacy),
        "otpauth://totp/Ref%20User:Ref%20User-user?secret=GEZDGNBVGY3TQOJQ&period=30&digits=8\
         &issuer=Ref%20User&algorithm=SHA1"
    );
    assert!(legacy.custom().is_empty());
    assert_eq!(
        otp_uri(&resolve(&database, 0x44)),
        "otpauth://totp/Steam:gamer?secret=STEAMSEEDBASE32&period=30&digits=5&issuer=Steam\
         &algorithm=SHA1&encoder=steam"
    );
    let keepass2 = resolve(&database, 0x55);
    assert_eq!(
        otp_uri(&keepass2),
        "otpauth://totp/KeePass2:kp2?secret=MFRGGZDFMZTWQ2LK&period=60&digits=8\
         &issuer=KeePass2&algorithm=SHA256"
    );
    assert!(keepass2.custom().is_empty());
}
