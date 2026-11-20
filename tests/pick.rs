//! `choose()` driving fake picker programs (bash scripts speaking fzf's or fuzzel's protocol).
//!
//! The real fzf and fuzzel are never run (fuzzel opens a window). Each fake records the arguments
//! and stdin it got in `<script>.args` and `<script>.stdin`, and answers the way the real picker
//! does per its documentation: fzf prints the selected line and exits 130 on Esc and 1 on no
//! match; fuzzel `--index` prints a 0-based index. Everything here is therefore evidence about
//! kpx-share's side of the protocol, not about the real programs.
//!
//! The scripts are all written once, up front, so no fork can hold a script's write handle open
//! while another test executes it (`ETXTBSY`).

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use kpx_share::model::Uuid;
use kpx_share::pick::{ChooseError, Picker, Query, choose};
use kpx_share::select::{EntryLabel, PickerItem};
use kpx_share::subprocess::ToolError;

struct Scripts {
    dir: PathBuf,
}

impl Scripts {
    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    fn fzf(&self, name: &str) -> Picker {
        Picker::Fzf {
            program: self.path(name),
        }
    }

    fn fuzzel(&self, name: &str) -> Picker {
        Picker::Fuzzel {
            program: self.path(name),
        }
    }

    fn log(&self, name: &str, stream: &str) -> String {
        fs::read_to_string(self.path(&format!("{name}.{stream}"))).unwrap()
    }
}

const LOGGING: &str = "cat > \"$0.stdin\"\nprintf '%s\\n' \"$@\" > \"$0.args\"\n";

fn scripts() -> &'static Scripts {
    static SCRIPTS: OnceLock<Scripts> = OnceLock::new();
    SCRIPTS.get_or_init(|| {
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("pick-fixtures");
        let _absent_is_fine = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let scripts = [
            // Selects the second line it was given, as fzf prints it.
            // One copy per test that reads its logs, as tests run in parallel.
            (
                "fzf-second-all",
                format!("{LOGGING}sed -n 2p \"$0.stdin\"\n"),
            ),
            (
                "fzf-second-filtered",
                format!("{LOGGING}sed -n 2p \"$0.stdin\"\n"),
            ),
            ("fzf-cancel", "cat >/dev/null\nexit 130\n".to_owned()),
            ("fzf-no-match", "cat >/dev/null\nexit 1\n".to_owned()),
            (
                "fzf-error",
                "cat >/dev/null\necho 'fzf: boom' >&2\nexit 2\n".to_owned(),
            ),
            ("fzf-garbage", "cat >/dev/null\necho hello\n".to_owned()),
            (
                "fzf-out-of-range",
                "cat >/dev/null\nprintf '99\\tx\\n'\n".to_owned(),
            ),
            ("fuzzel-second", format!("{LOGGING}echo 1\n")),
            ("fuzzel-cancel", "cat >/dev/null\nexit 1\n".to_owned()),
            (
                "fuzzel-error",
                "cat >/dev/null\necho 'failed to connect to the compositor' >&2\nexit 1\n"
                    .to_owned(),
            ),
            (
                "fuzzel-garbage",
                "cat >/dev/null\necho 'a label'\n".to_owned(),
            ),
        ];
        for (name, body) in scripts {
            common::fakes::write_script(&dir, name, &body);
        }
        Scripts { dir }
    })
}

fn uuid(byte: u8) -> Uuid {
    Uuid::parse_hex(&format!("{byte:02x}").repeat(16)).unwrap()
}

fn item(byte: u8, title: &str, user: Option<&str>) -> PickerItem {
    PickerItem {
        id: uuid(byte),
        label: EntryLabel::new(vec![], Some(title.to_owned())),
        user_name: user.map(str::to_owned),
        url: None,
    }
}

/// Two entries with the same label, then one whose title has a tab and a newline.
fn items() -> Vec<PickerItem> {
    vec![
        item(1, "Dup", Some("u1")),
        item(2, "Dup", Some("u2")),
        item(3, "tab\there\nnewline", None),
    ]
}

fn query(text: &str) -> Query {
    Query::parse(text).unwrap()
}

#[test]
fn fzf_gets_index_prefixed_lines_and_the_choice_maps_back_by_index() {
    let scripts = scripts();
    let chosen = choose(&items(), None, &scripts.fzf("fzf-second-all")).unwrap();
    // Entries 1 and 2 have identical labels; only the index tells them apart.
    assert_eq!(chosen, uuid(2));
    assert_eq!(
        scripts.log("fzf-second-all", "stdin"),
        "0\tDup  u1\n1\tDup  u2\n2\ttab here newline\n"
    );
    assert_eq!(
        scripts.log("fzf-second-all", "args"),
        "--delimiter=\t\n--with-nth=2..\n--no-multi\n--prompt=kpx-share> \n"
    );
}

#[test]
fn the_index_counts_matching_entries_not_all_entries() {
    let scripts = scripts();
    let items = [
        item(9, "Other", None),
        item(1, "Dup", Some("u1")),
        item(2, "Dup", Some("u2")),
    ];
    // Candidates are the two Dup entries; the picker's index 1 is the second of them.
    let picker = scripts.fzf("fzf-second-filtered");
    let chosen = choose(&items, Some(&query("dup")), &picker).unwrap();
    assert_eq!(chosen, uuid(2));
    assert_eq!(
        scripts.log("fzf-second-filtered", "stdin"),
        "0\tDup  u1\n1\tDup  u2\n"
    );
    assert!(
        scripts
            .log("fzf-second-filtered", "args")
            .ends_with("--query=dup\n")
    );
}

#[test]
fn fuzzel_gets_plain_lines_and_its_index_maps_back() {
    let scripts = scripts();
    let chosen = choose(
        &items(),
        Some(&query("DUP")),
        &scripts.fuzzel("fuzzel-second"),
    )
    .unwrap();
    assert_eq!(chosen, uuid(2));
    assert_eq!(scripts.log("fuzzel-second", "stdin"), "Dup  u1\nDup  u2\n");
    assert_eq!(
        scripts.log("fuzzel-second", "args"),
        "--dmenu\n--index\n--only-match\n--prompt=kpx-share> \n--log-level=error\n--log-no-syslog\n--search=dup\n"
    );
}

#[test]
fn a_query_matching_one_entry_skips_the_picker() {
    let scripts = scripts();
    // fzf-error would fail the call if it ran.
    let chosen = choose(&items(), Some(&query("newline")), &scripts.fzf("fzf-error")).unwrap();
    assert_eq!(chosen, uuid(3));
}

#[test]
fn declining_is_cancelled() {
    let scripts = scripts();
    for picker in [
        scripts.fzf("fzf-cancel"),
        scripts.fzf("fzf-no-match"),
        scripts.fuzzel("fuzzel-cancel"),
    ] {
        let error = choose(&items(), None, &picker).unwrap_err();
        assert!(
            matches!(error, ChooseError::Cancelled),
            "{picker:?}: {error:?}"
        );
    }
}

#[test]
fn a_failing_picker_is_not_a_cancel_and_carries_its_stderr() {
    let scripts = scripts();
    for (picker, said) in [
        (scripts.fzf("fzf-error"), "fzf: boom"),
        (
            scripts.fuzzel("fuzzel-error"),
            "failed to connect to the compositor",
        ),
    ] {
        let error = choose(&items(), None, &picker).unwrap_err();
        assert!(
            matches!(
                &error,
                ChooseError::Tool(ToolError::Failed { stderr, .. }) if stderr == said
            ),
            "{error:?}"
        );
    }
}

#[test]
fn output_that_is_not_a_choice_is_an_error() {
    let scripts = scripts();
    for picker in [
        scripts.fzf("fzf-garbage"),
        scripts.fzf("fzf-out-of-range"),
        scripts.fuzzel("fuzzel-garbage"),
    ] {
        let error = choose(&items(), None, &picker).unwrap_err();
        assert!(
            matches!(error, ChooseError::UnexpectedChoice { .. }),
            "{picker:?}: {error:?}"
        );
    }
}
