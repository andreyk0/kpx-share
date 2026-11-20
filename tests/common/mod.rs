//! Helpers shared by the integration tests.

#![allow(dead_code, unreachable_pub)]

pub mod fakes;
pub mod process;
pub mod share;

use kpx_share::model::{Database, Entry, StandardField, Uuid};
use kpx_share::otp::Otp;
use kpx_share::{Eligibility, ResolvedEntry, SecretBytes, import};

/// The hand-written fixture, as the file `tests/fixtures/agent-db.xml`.
pub fn fixture_xml_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/agent-db.xml")
}

/// Imports the fixture into a new KDBX at `kdbx`, protected by `password` and, if given,
/// `key_file`. Throwaway data only: never a real database.
pub fn create_throwaway_kdbx(
    kdbx: &std::path::Path,
    password: &str,
    key_file: Option<&std::path::Path>,
) {
    create_kdbx_from_xml(&fixture_xml_path(), kdbx, password, key_file);
}

/// Imports the KeePass XML file `xml` into a new KDBX at `kdbx`. Throwaway data only.
pub fn create_kdbx_from_xml(
    xml: &std::path::Path,
    kdbx: &std::path::Path,
    password: &str,
    key_file: Option<&std::path::Path>,
) {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let mut command = Command::new("keepassxc-cli");
    command.arg("import").arg("-p");
    if let Some(key_file) = key_file {
        command.arg("--set-key-file").arg(key_file);
    }
    // Without -p, import aborts with "No key is set" when there is no TTY.
    let mut child = command
        .arg(xml)
        .arg(kdbx)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("keepassxc-cli must be installed for these tests");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(format!("{password}\n{password}\n").as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "keepassxc-cli import failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Imports the KeePass XML file `xml` into a new KDBX at `kdbx` protected by `key_file` alone, no
/// password (what `--no-password` unlocks). Throwaway data only.
pub fn create_key_file_only_kdbx(
    xml: &std::path::Path,
    kdbx: &std::path::Path,
    key_file: &std::path::Path,
) {
    use std::process::{Command, Stdio};

    let output = Command::new("keepassxc-cli")
        .args(["import", "--set-key-file"])
        .arg(key_file)
        .arg(xml)
        .arg(kdbx)
        .stdin(Stdio::null())
        .output()
        .expect("keepassxc-cli must be installed for these tests");
    assert!(
        output.status.success(),
        "keepassxc-cli import failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// A KeePass XML document whose root group holds `body` (entries and groups).
pub fn document(meta: &str, body: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<KeePassFile>
	<Meta>{meta}</Meta>
	<Root>
		<Group>
			<UUID>qqqqqqqqqqqqqqqqqqqqqg==</UUID>
			<Name>Root</Name>
			{body}
		</Group>
		<DeletedObjects/>
	</Root>
</KeePassFile>
"#
    )
}

/// One `<Entry>` with UUID `uuid_byte` repeated 16 times and the given extra children.
pub fn entry(uuid_byte: u8, children: &str) -> String {
    format!(
        "<Entry><UUID>{}</UUID>{children}</Entry>",
        uuid_base64(uuid_byte)
    )
}

pub fn string(key: &str, value: &str) -> String {
    format!("<String><Key>{key}</Key><Value>{value}</Value></String>")
}

/// The 32-hex-digit form of `uuid_byte` repeated, as `{REF:…@I:…}` writes it.
pub fn uuid_hex(uuid_byte: u8) -> String {
    format!("{uuid_byte:02x}").repeat(16)
}

pub fn uuid(uuid_byte: u8) -> Uuid {
    Uuid::parse_hex(&uuid_hex(uuid_byte)).unwrap()
}

fn uuid_base64(uuid_byte: u8) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode([uuid_byte; 16])
}

pub fn import_str(xml: &str) -> Database {
    import(SecretBytes::copy_from(xml.as_bytes())).unwrap()
}

/// Entry `uuid_byte` of `database`, picked with `--any` and resolved.
pub fn resolve(database: &Database, uuid_byte: u8) -> ResolvedEntry {
    database
        .pick(uuid(uuid_byte), Eligibility::Any)
        .unwrap()
        .resolve()
}

pub fn text(value: &SecretBytes) -> &str {
    std::str::from_utf8(value.expose()).unwrap()
}

pub fn field(entry: &Entry, field: StandardField) -> Option<&str> {
    entry.fields().get(field).map(text)
}

pub fn resolved(entry: &ResolvedEntry, field: StandardField) -> Option<&str> {
    entry.fields().get(field).map(text)
}

pub fn otp_uri(entry: &ResolvedEntry) -> &str {
    match entry.otp() {
        Otp::Present(uri) => text(uri.as_secret()),
        other => panic!("expected a TOTP URI, got {other:?}"),
    }
}
