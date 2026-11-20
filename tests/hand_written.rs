//! Import, selection and resolution on small hand-written KeePass XML documents.
//!
//! Each test builds the smallest document that exercises one rule and checks the public API's
//! result against values written out by hand from the KeePass format and the rule itself.

mod common;

use common::share::resolve_any;
use common::{document, entry, field, import_str, otp_uri, resolved, string, text, uuid, uuid_hex};
use kpx_share::import::ImportError;
use kpx_share::model::{AttributeName, FieldName, Location, StandardField};
use kpx_share::otp::{Otp, OtpFormat, OtpIssue, OtpProblem};
use kpx_share::select::{Ineligibility, PickError};
use kpx_share::{Eligibility, RequiredTag, ResolvedEntry, SecretBytes, import};

fn agent() -> Eligibility {
    Eligibility::Tagged(RequiredTag::agent())
}

const NO_NAMES: [&str; 0] = [];

fn custom_names(entry: &ResolvedEntry) -> Vec<&str> {
    entry.custom().keys().map(AttributeName::as_str).collect()
}

// --- History ---------------------------------------------------------------------------------

#[test]
fn history_versions_are_neither_entries_nor_fields() {
    let history = format!(
        "<History>{}{}</History>",
        entry(
            0x11,
            &(string("Password", "OLD-PASSWORD") + &string("HistoryOnly", "leak"))
        ),
        entry(0x99, &string("Title", "only in history")),
    );
    let body = entry(
        0x11,
        &format!(
            "<Tags>agent</Tags>{}{history}",
            string("Password", "current")
        ),
    );
    let database = import_str(&document("", &body));

    assert_eq!(database.entries().len(), 1);
    assert!(database.entry(uuid(0x99)).is_none());
    let only = &database.entries()[0];
    assert_eq!(field(only, StandardField::Password), Some("current"));
    assert!(only.custom().is_empty(), "{:?}", only.custom().keys());
}

// --- Tags and eligibility ---------------------------------------------------------------------

#[test]
fn agent_tag_matches_case_insensitively_with_either_separator() {
    let body = [
        entry(
            0x01,
            &(string("Title", "semicolon") + "<Tags>ops;Agent</Tags>"),
        ),
        entry(0x02, &(string("Title", "comma") + "<Tags>AGENT,ops</Tags>")),
        entry(
            0x03,
            &(string("Title", "spaced") + "<Tags>ops ; agent </Tags>"),
        ),
        entry(
            0x04,
            &(string("Title", "superstring") + "<Tags>agents,ops</Tags>"),
        ),
        entry(
            0x05,
            &(string("Title", "joined") + "<Tags>ops agent</Tags>"),
        ),
        entry(0x06, &string("Title", "untagged")),
    ]
    .concat();
    let database = import_str(&document("", &body));

    let tagged: Vec<String> = database
        .picker_items(&agent())
        .iter()
        .map(|item| item.label.path())
        .collect();
    assert_eq!(tagged, ["semicolon", "comma", "spaced"]);

    let any = database.picker_items(&Eligibility::Any);
    assert_eq!(any.len(), 6);
}

#[test]
fn a_custom_required_tag_replaces_the_default() {
    let body = [
        entry(0x01, "<Tags>agent</Tags>"),
        entry(0x02, "<Tags>CI</Tags>"),
    ]
    .concat();
    let database = import_str(&document("", &body));
    let ci = Eligibility::Tagged(RequiredTag::parse("ci").unwrap());
    let ids: Vec<_> = database.picker_items(&ci).iter().map(|i| i.id).collect();
    assert_eq!(ids, [uuid(0x02)]);
    assert!(RequiredTag::parse(" ").is_err());
    assert!(RequiredTag::parse("a,b").is_err());
}

#[test]
fn pick_rechecks_eligibility_and_records_the_rule() {
    let body = [
        entry(0x01, "<Tags>agent</Tags>"),
        entry(0x02, "<Tags>other</Tags>"),
    ]
    .concat();
    let database = import_str(&document("", &body));

    assert_eq!(
        database.pick(uuid(0x02), agent()).unwrap_err(),
        PickError::Ineligible {
            uuid: uuid(0x02),
            reason: Ineligibility::MissingTag
        }
    );
    assert_eq!(
        database.pick(uuid(0x03), Eligibility::Any).unwrap_err(),
        PickError::NotFound(uuid(0x03))
    );
    let by_tag = database.pick(uuid(0x01), agent()).unwrap().resolve();
    assert_eq!(by_tag.eligibility(), &agent());
    let by_any = database
        .pick(uuid(0x02), Eligibility::Any)
        .unwrap()
        .resolve();
    assert_eq!(by_any.eligibility(), &Eligibility::Any);
}

#[test]
fn recycle_bin_entries_are_never_eligible() {
    let meta = "<RecycleBinEnabled>True</RecycleBinEnabled>\
                <RecycleBinUUID>zMzMzMzMzMzMzMzMzMzMzA==</RecycleBinUUID>";
    let body = format!(
        "{}<Group><UUID>zMzMzMzMzMzMzMzMzMzMzA==</UUID><Name>Recycle Bin</Name>{}\
         <Group><UUID>3d3d3d3d3d3d3d3d3d3d3Q==</UUID><Name>Below</Name>{}</Group></Group>",
        entry(0x01, "<Tags>agent</Tags>"),
        entry(0x02, "<Tags>agent</Tags>"),
        entry(0x03, "<Tags>agent</Tags>"),
    );
    let database = import_str(&document(meta, &body));

    assert_eq!(database.entries().len(), 3, "recycled entries are imported");
    assert_eq!(
        database.entry(uuid(0x03)).unwrap().location(),
        Location::RecycleBin
    );
    let any: Vec<_> = database
        .picker_items(&Eligibility::Any)
        .iter()
        .map(|i| i.id)
        .collect();
    assert_eq!(any, [uuid(0x01)]);
    assert_eq!(
        database.pick(uuid(0x02), Eligibility::Any).unwrap_err(),
        PickError::Ineligible {
            uuid: uuid(0x02),
            reason: Ineligibility::InRecycleBin
        }
    );
}

#[test]
fn a_disabled_recycle_bin_is_an_ordinary_group() {
    let meta = "<RecycleBinEnabled>False</RecycleBinEnabled>\
                <RecycleBinUUID>zMzMzMzMzMzMzMzMzMzMzA==</RecycleBinUUID>";
    let body = format!(
        "<Group><UUID>zMzMzMzMzMzMzMzMzMzMzA==</UUID><Name>Bin</Name>{}</Group>",
        entry(0x01, "")
    );
    let database = import_str(&document(meta, &body));
    assert_eq!(database.entries()[0].location(), Location::Live);
}

// --- Identity --------------------------------------------------------------------------------

#[test]
fn group_path_excludes_the_root_group() {
    let body = format!(
        "{}<Group><UUID>u7u7u7u7u7u7u7u7u7u7uw==</UUID><Name>Work</Name>\
         <Group><UUID>3d3d3d3d3d3d3d3d3d3d3Q==</UUID><Name>Sub</Name>{}</Group></Group>",
        entry(0x01, &string("Title", "At root")),
        entry(0x02, &(string("Title", "Deep") + &string("UserName", "me"))),
    );
    let database = import_str(&document("", &body));
    let items = database.picker_items(&Eligibility::Any);
    let labels: Vec<String> = items.iter().map(|item| item.label.path()).collect();
    assert_eq!(labels, ["At root", "Work/Sub/Deep"]);
    assert_eq!(items[1].user_name.as_deref(), Some("me"));
    assert_eq!(items[1].url, None);
}

// --- Byte-exact values -----------------------------------------------------------------------

#[test]
fn values_are_byte_exact_apart_from_reference_decoding() {
    let notes = "  leading\n\ttab\r\ncrlf as is\ntrailing   \n\n";
    let body = entry(
        0x01,
        &[
            string("Notes", notes),
            string("Password", "a&lt;b&gt;c&amp;d&quot;e&apos;f&#13;&#x263A;"),
            string("cdata", "<![CDATA[<raw & kept>]]>"),
        ]
        .concat(),
    );
    let database = import_str(&document("", &body));
    let only = &database.entries()[0];
    assert_eq!(
        only.fields().get(StandardField::Notes).unwrap().expose(),
        notes.as_bytes()
    );
    assert_eq!(
        field(only, StandardField::Password),
        Some("a<b>c&d\"e'f\r\u{263A}")
    );
    let cdata = only.custom().get("cdata").unwrap();
    assert_eq!(text(cdata), "<raw & kept>");
}

#[test]
fn absent_and_empty_fields_stay_distinct() {
    let body = entry(
        0x01,
        &(string("Title", "") + "<String><Key>URL</Key><Value/></String>"),
    );
    let entry = resolve_any("", &body, 0x01);
    assert_eq!(resolved(&entry, StandardField::Title), Some(""));
    assert_eq!(resolved(&entry, StandardField::Url), Some(""));
    assert_eq!(resolved(&entry, StandardField::Password), None);
    assert_eq!(resolved(&entry, StandardField::UserName), None);
}

// --- Attachments -----------------------------------------------------------------------------

#[test]
fn attachments_decode_gzip_and_plain() {
    // Contents hand-encoded: gzip of b"gzipped\nattachment\x00\xff", and base64 of
    // b"plain\x00bytes\xff".
    let meta = r#"<Binaries>
        <Binary ID="0" Compressed="True">H4sIAAAAAAAC/0uvyiwoSE3hSiwpSUzOyE3NK2H4DwCrGPNRFAAAAA==</Binary>
        <Binary ID="1" Compressed="False">cGxhaW4AYnl0ZXP/</Binary>
        <Binary ID="2">cGxhaW4AYnl0ZXP/</Binary>
    </Binaries>"#;
    let body = entry(
        0x01,
        r#"<Binary><Key>a.gz.txt</Key><Value Ref="0"/></Binary>
           <Binary><Key>b.bin</Key><Value Ref="1"/></Binary>
           <Binary><Key>c.bin</Key><Value Ref="2"></Value></Binary>"#,
    );
    let entry = resolve_with_meta(meta, &body, 0x01);
    let attachments: Vec<(&str, &[u8])> = entry
        .attachments()
        .iter()
        .map(|a| (a.name(), a.content().expose()))
        .collect();
    assert_eq!(
        attachments,
        [
            ("a.gz.txt", &b"gzipped\nattachment\x00\xff"[..]),
            ("b.bin", &b"plain\x00bytes\xff"[..]),
            ("c.bin", &b"plain\x00bytes\xff"[..]),
        ]
    );
}

fn resolve_with_meta(meta: &str, body: &str, uuid_byte: u8) -> ResolvedEntry {
    import_str(&document(meta, body))
        .pick(uuid(uuid_byte), Eligibility::Any)
        .unwrap()
        .resolve()
}

#[test]
fn a_reference_to_a_missing_binary_is_an_error() {
    let body = entry(0x01, r#"<Binary><Key>gone</Key><Value Ref="7"/></Binary>"#);
    let error = import(SecretBytes::copy_from(document("", &body).as_bytes())).unwrap_err();
    assert!(
        matches!(&error, ImportError::UnknownBinary { id, .. } if id == "7"),
        "{error:?}"
    );
}

#[test]
fn a_compressed_binary_that_does_not_gunzip_is_an_error() {
    let meta = r#"<Binaries><Binary ID="0" Compressed="True">cGxhaW4AYnl0ZXP/</Binary></Binaries>"#;
    let body = entry(0x01, r#"<Binary><Key>x</Key><Value Ref="0"/></Binary>"#);
    let error = import(SecretBytes::copy_from(document(meta, &body).as_bytes())).unwrap_err();
    assert!(matches!(error, ImportError::BinaryGzip { .. }), "{error:?}");
}

// --- Placeholders ----------------------------------------------------------------------------

#[test]
fn references_resolve_across_the_database() {
    let body = [
        entry(
            0x01,
            &[
                string("Title", "Target"),
                string("UserName", "target-user"),
                string("Password", "target-pw"),
                string("URL", "https://t.example"),
                string("Notes", "target notes"),
            ]
            .concat(),
        ),
        entry(
            0x02,
            &[
                string("Password", &format!("{{REF:P@I:{}}}", uuid_hex(0x01))),
                string(
                    "Notes",
                    &format!(
                        "{{ref:t@i:{0}}}|{{REF:U@I:{0}}}|{{REF:A@I:{0}}}|{{REF:N@I:{1}}}",
                        uuid_hex(0x01),
                        uuid_hex(0x01).to_uppercase()
                    ),
                ),
                string("Custom", &format!("key={{REF:P@I:{}}}", uuid_hex(0x01))),
            ]
            .concat(),
        ),
    ]
    .concat();
    let entry = resolve_any("", &body, 0x02);
    assert_eq!(resolved(&entry, StandardField::Password), Some("target-pw"));
    assert_eq!(
        resolved(&entry, StandardField::Notes),
        Some("Target|target-user|https://t.example|target notes")
    );
    assert_eq!(text(entry.custom().get("Custom").unwrap()), "key=target-pw");
    assert!(entry.unresolved().is_empty(), "{:?}", entry.unresolved());
}

#[test]
fn own_field_placeholders_resolve_in_any_case() {
    let body = entry(
        0x01,
        &[
            string("Title", "T"),
            string("UserName", "u-{title}"),
            string("Password", "p"),
            string("Notes", "{USERNAME}/{Password}/{url}/{NOTES}"),
        ]
        .concat(),
    );
    let entry = resolve_any("", &body, 0x01);
    assert_eq!(resolved(&entry, StandardField::UserName), Some("u-T"));
    // {url}: absent URL substitutes as empty. {NOTES} inside Notes is a cycle, kept verbatim.
    assert_eq!(
        resolved(&entry, StandardField::Notes),
        Some("u-T/p//{NOTES}")
    );
    let unresolved: Vec<_> = entry.unresolved().iter().cloned().collect();
    assert_eq!(unresolved, [FieldName::Standard(StandardField::Notes)]);
}

#[test]
fn unknown_placeholders_and_dangling_references_stay_verbatim_and_are_recorded() {
    let dangling = format!("{{REF:P@I:{}}}", uuid_hex(0x77));
    let body = entry(
        0x01,
        &[
            string("Title", "T"),
            string("Password", &dangling),
            string("Notes", "{S:Other} {DT_SIMPLE} {} {TITLE"),
            string("Mixed", "{TITLE}+{CLEARFIELD}"),
            string("Plain", "{TITLE}"),
        ]
        .concat(),
    );
    let entry = resolve_any("", &body, 0x01);
    assert_eq!(resolved(&entry, StandardField::Password), Some(&*dangling));
    assert_eq!(
        resolved(&entry, StandardField::Notes),
        Some("{S:Other} {DT_SIMPLE} {} {TITLE")
    );
    assert_eq!(text(entry.custom().get("Mixed").unwrap()), "T+{CLEARFIELD}");
    assert_eq!(text(entry.custom().get("Plain").unwrap()), "T");
    let unresolved: Vec<String> = entry
        .unresolved()
        .iter()
        .map(|name| name.key().to_owned())
        .collect();
    assert_eq!(unresolved, ["Password", "Notes", "Mixed"]);
}

#[test]
fn reference_cycles_stop_and_are_recorded() {
    let body = [
        entry(
            0x01,
            &string("Password", &format!("a{{REF:P@I:{}}}", uuid_hex(0x02))),
        ),
        entry(
            0x02,
            &string("Password", &format!("b{{REF:P@I:{}}}", uuid_hex(0x01))),
        ),
    ]
    .concat();
    let entry = resolve_any("", &body, 0x01);
    // 0x01 → "a" + 0x02's password → "b" + 0x01's password, which is being resolved: verbatim.
    let expected = format!("ab{{REF:P@I:{}}}", uuid_hex(0x01));
    assert_eq!(resolved(&entry, StandardField::Password), Some(&*expected));
    assert!(
        entry
            .unresolved()
            .contains(&FieldName::Standard(StandardField::Password))
    );
}

#[test]
fn reference_chains_stop_at_the_depth_bound() {
    // Entry n's password references entry n+1's; the last holds "end". Twelve hops exceed the
    // bound of ten, so resolution stops partway and keeps that reference verbatim.
    let hops: u8 = 12;
    let body: String = (1..=hops)
        .map(|n| {
            let value = if n == hops {
                "end".to_owned()
            } else {
                format!("{n}>{{REF:P@I:{}}}", uuid_hex(n + 1))
            };
            entry(n, &string("Password", &value))
        })
        .collect();
    let entry = resolve_any("", &body, 1);
    let expected = format!("1>2>3>4>5>6>7>8>9>10>{{REF:P@I:{}}}", uuid_hex(11));
    assert_eq!(resolved(&entry, StandardField::Password), Some(&*expected));
    assert!(!entry.unresolved().is_empty());

    let short = resolve_any("", &body, 4);
    assert_eq!(
        resolved(&short, StandardField::Password),
        Some("4>5>6>7>8>9>10>11>end")
    );
    assert!(short.unresolved().is_empty());
}

// --- TOTP ------------------------------------------------------------------------------------

#[test]
fn otpauth_attribute_is_kept_verbatim_and_consumed() {
    let uri = "otpauth://totp/Ex:me?secret=JBSWY3DPEHPK3PXP&amp;issuer=Ex";
    let body = entry(0x01, &[string("Title", "T"), string("otp", uri)].concat());
    let entry = resolve_any("", &body, 0x01);
    assert_eq!(
        otp_uri(&entry),
        "otpauth://totp/Ex:me?secret=JBSWY3DPEHPK3PXP&issuer=Ex"
    );
    assert_eq!(custom_names(&entry), NO_NAMES);
}

#[test]
fn keepassxc_legacy_settings_normalise_to_a_uri() {
    let body = [
        entry(
            0x01,
            &[
                string("Title", "My Site"),
                string("UserName", "me@x"),
                string("TOTP Seed", "GEZDGNBVGY3TQOJQ"),
                string("TOTP Settings", "45;7"),
            ]
            .concat(),
        ),
        entry(
            0x02,
            &[
                string("Title", "Steam"),
                string("UserName", "gamer"),
                string("TOTP Seed", "STEAMSEED"),
                string("TOTP Settings", "30;S"),
            ]
            .concat(),
        ),
        entry(0x03, &string("TOTP Seed", "DEFAULTS")),
    ]
    .concat();
    let standard = resolve_any("", &body, 0x01);
    assert_eq!(
        otp_uri(&standard),
        "otpauth://totp/My%20Site:me%40x?secret=GEZDGNBVGY3TQOJQ&period=45&digits=7\
         &issuer=My%20Site&algorithm=SHA1"
    );
    assert_eq!(custom_names(&standard), NO_NAMES);
    assert_eq!(
        otp_uri(&resolve_any("", &body, 0x02)),
        "otpauth://totp/Steam:gamer?secret=STEAMSEED&period=30&digits=5&issuer=Steam\
         &algorithm=SHA1&encoder=steam"
    );
    assert_eq!(
        otp_uri(&resolve_any("", &body, 0x03)),
        "otpauth://totp/:?secret=DEFAULTS&period=30&digits=6&issuer=&algorithm=SHA1"
    );
}

#[test]
fn keepass2_timeotp_attributes_normalise_to_a_uri() {
    let body = [
        entry(
            0x01,
            &[
                string("Title", "KP2"),
                string("UserName", "u"),
                string("TimeOtp-Secret-Base32", "MFRGGZDFMZTWQ2LK"),
                string("TimeOtp-Period", "60"),
                string("TimeOtp-Length", "8"),
                string("TimeOtp-Algorithm", "HMAC-SHA-512"),
            ]
            .concat(),
        ),
        entry(0x02, &string("TimeOtp-Secret-Base32", "MFRGGZDF")),
    ]
    .concat();
    let full = resolve_any("", &body, 0x01);
    assert_eq!(
        otp_uri(&full),
        "otpauth://totp/KP2:u?secret=MFRGGZDFMZTWQ2LK&period=60&digits=8&issuer=KP2\
         &algorithm=SHA512"
    );
    assert_eq!(custom_names(&full), NO_NAMES);
    assert_eq!(
        otp_uri(&resolve_any("", &body, 0x02)),
        "otpauth://totp/:?secret=MFRGGZDF&period=30&digits=6&issuer=&algorithm=SHA1"
    );
}

#[test]
fn the_otp_uri_wins_and_other_layouts_stay_custom_attributes() {
    let body = entry(
        0x01,
        &[
            string("otp", "otpauth://totp/a?secret=AAAA"),
            string("TOTP Seed", "BBBB"),
            string("TOTP Settings", "30;6"),
        ]
        .concat(),
    );
    let entry = resolve_any("", &body, 0x01);
    assert_eq!(otp_uri(&entry), "otpauth://totp/a?secret=AAAA");
    assert_eq!(custom_names(&entry), ["TOTP Seed", "TOTP Settings"]);
}

#[test]
fn unreadable_totp_is_reported_and_its_attributes_kept() {
    let cases = [
        (
            string("otp", "not a uri"),
            OtpFormat::OtpauthUri,
            OtpProblem::NotAnOtpauthUri,
        ),
        (
            string("TOTP Seed", "AAAA") + &string("TOTP Settings", "30"),
            OtpFormat::KeePassXcLegacy,
            OtpProblem::InvalidSettings,
        ),
        (
            string("TOTP Seed", "AAAA") + &string("TOTP Settings", "30;9"),
            OtpFormat::KeePassXcLegacy,
            OtpProblem::InvalidDigits,
        ),
        (
            string("TOTP Seed", ""),
            OtpFormat::KeePassXcLegacy,
            OtpProblem::EmptySecret,
        ),
        (
            string("TimeOtp-Secret-Base32", "AAAA") + &string("TimeOtp-Period", "0"),
            OtpFormat::KeePass2,
            OtpProblem::InvalidPeriod,
        ),
        (
            string("TimeOtp-Secret-Base32", "AAAA") + &string("TimeOtp-Algorithm", "MD5"),
            OtpFormat::KeePass2,
            OtpProblem::UnknownAlgorithm,
        ),
    ];
    for (attributes, format, problem) in cases {
        let entry = resolve_any("", &entry(0x01, &attributes), 0x01);
        match entry.otp() {
            Otp::Unrecognised(issue) => assert_eq!(*issue, OtpIssue { format, problem }),
            other => panic!("{attributes}: expected Unrecognised, got {other:?}"),
        }
        assert!(
            !entry.custom().is_empty(),
            "{attributes}: attributes dropped"
        );
    }
}

// --- Malformed input -------------------------------------------------------------------------

fn import_error(xml: &str) -> ImportError {
    import(SecretBytes::copy_from(xml.as_bytes())).unwrap_err()
}

#[test]
fn structural_errors_are_reported_without_values() {
    let duplicate_field = document(
        "",
        &entry(
            0x01,
            &(string("Password", "SECRET-ONE") + &string("Password", "SECRET-TWO")),
        ),
    );
    let error = import_error(&duplicate_field);
    assert!(
        matches!(error, ImportError::DuplicateField { .. }),
        "{error:?}"
    );
    assert!(!error.to_string().contains("SECRET"), "{error}");

    let duplicate_uuid = document("", &[entry(0x01, ""), entry(0x01, "")].concat());
    assert!(matches!(
        import_error(&duplicate_uuid),
        ImportError::DuplicateUuid(_)
    ));

    let doctype = document("", "").replacen(
        "?>\n",
        "?>\n<!DOCTYPE KeePassFile [<!ENTITY e \"v\">]>\n",
        1,
    );
    let error = import_error(&doctype);
    assert!(matches!(error, ImportError::DocType { .. }), "{error:?}");

    let unknown_entity = document("", &entry(0x01, &string("Password", "a&secret;b")));
    let error = import_error(&unknown_entity);
    assert!(
        matches!(error, ImportError::UnknownEntity { .. }),
        "{error:?}"
    );
    assert!(!error.to_string().contains("secret"), "{error}");

    let truncated = document("", &entry(0x01, ""));
    let truncated = &truncated[..truncated.len() / 2];
    assert!(import(SecretBytes::copy_from(truncated.as_bytes())).is_err());

    let no_uuid = document(
        "",
        "<Entry><String><Key>Title</Key><Value>x</Value></String></Entry>",
    );
    assert!(matches!(
        import_error(&no_uuid),
        ImportError::MissingElement {
            element: "UUID",
            ..
        }
    ));
}
