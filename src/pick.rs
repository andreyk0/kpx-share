//! Choosing one entry: filter by a query, then ask the human if more than one is left.
//!
//! The picker shows only [`PickerItem`] text (label, user name, URL): nothing secret. The human's
//! choice comes back as an **index** into the list that was sent, never as text to be matched
//! again, because labels may contain anything, including tabs and newlines.
//!
//! - fzf (terminal): each input line is `<index>\t<display>`, with `--with-nth 2..` hiding the
//!   index; fzf prints the whole selected line, and the index is read off its front.
//! - fuzzel (no terminal): `--dmenu --index` prints the selected line's index.
//!
//! The query is applied here, in Rust, once ([`Query::matches`]), so both pickers see the same
//! candidates; it is passed on to the picker only as the text to start typing with.

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::thread;

use crate::mode::Mode;
use crate::model::Uuid;
use crate::select::PickerItem;
use crate::subprocess::{ToolError, capture_stderr, ignore_broken_pipe, take_pipe};
use crate::text::one_line;
use crate::tools;

/// What the human typed after `add`: non-empty, with at least one word.
///
/// An entry matches when every whitespace-separated word occurs, ignoring case, somewhere in its
/// label, user name or URL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Query {
    /// Lowercased words separated by single spaces; never empty.
    text: String,
}

impl Query {
    /// `None` when `text` has no words, so "no query" has one representation: `Option::None`.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let words: Vec<String> = text.split_whitespace().map(str::to_lowercase).collect();
        (!words.is_empty()).then(|| Self {
            text: words.join(" "),
        })
    }

    /// The normalised query (lowercase, single spaces), as the picker starts with it.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    #[must_use]
    pub fn matches(&self, item: &PickerItem) -> bool {
        let haystack = [
            Some(item.label.path()),
            item.user_name.clone(),
            item.url.clone(),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase();
        self.text.split(' ').all(|word| haystack.contains(word))
    }
}

/// The picker program to run, with the protocol it speaks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Picker {
    Fzf { program: PathBuf },
    Fuzzel { program: PathBuf },
}

impl Picker {
    #[must_use]
    pub fn for_mode(mode: Mode) -> Self {
        match mode {
            Mode::Terminal => Self::Fzf {
                program: tools::path(tools::FZF).to_owned(),
            },
            Mode::NoTerminal => Self::Fuzzel {
                program: tools::path(tools::FUZZEL).to_owned(),
            },
        }
    }

    fn program(&self) -> &Path {
        match self {
            Self::Fzf { program } | Self::Fuzzel { program } => program,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ChooseError {
    #[error("there are no entries to choose from")]
    NoEntries,
    #[error("no entry matches {query:?}")]
    NoMatch { query: String },
    #[error("nothing was chosen")]
    Cancelled,
    #[error(transparent)]
    Tool(#[from] ToolError),
    /// The picker succeeded but printed something that is not a choice among the lines it was
    /// given. The output is not shown: it is whatever the program printed.
    #[error("{} printed a choice that is not one of the entries offered", tool.display())]
    UnexpectedChoice { tool: PathBuf },
}

/// The id of the entry to share: the only match, or the one the human picks among the matches.
///
/// The picker runs only when more than one entry matches `query` (or any entry, with no query).
///
/// # Errors
/// See [`ChooseError`]; [`ChooseError::Cancelled`] is the human declining.
pub fn choose(
    items: &[PickerItem],
    query: Option<&Query>,
    picker: &Picker,
) -> Result<Uuid, ChooseError> {
    let candidates = candidates(items, query);
    match candidates.as_slice() {
        [] => Err(match query {
            Some(query) => ChooseError::NoMatch {
                query: query.text().to_owned(),
            },
            None => ChooseError::NoEntries,
        }),
        [only] => Ok(only.id),
        several => {
            let lines: Vec<String> = several.iter().map(|item| display_line(item)).collect();
            let index = run_picker(picker, query, &lines)?;
            several
                .get(index)
                .map(|item| item.id)
                .ok_or_else(|| ChooseError::UnexpectedChoice {
                    tool: picker.program().to_owned(),
                })
        }
    }
}

fn candidates<'a>(items: &'a [PickerItem], query: Option<&Query>) -> Vec<&'a PickerItem> {
    items
        .iter()
        .filter(|item| query.is_none_or(|query| query.matches(item)))
        .collect()
}

/// `Group/Title  user  url`, on one line, with an absent or empty user name or URL left out.
fn display_line(item: &PickerItem) -> String {
    let fields = [
        Some(item.label.path()),
        item.user_name.clone().filter(|name| !name.is_empty()),
        item.url.clone().filter(|url| !url.is_empty()),
    ];
    one_line(&fields.into_iter().flatten().collect::<Vec<_>>().join("  "))
}

/// Runs the picker over `lines` and returns the index of the line chosen.
fn run_picker(
    picker: &Picker,
    query: Option<&Query>,
    lines: &[String],
) -> Result<usize, ChooseError> {
    let (args, input) = match picker {
        Picker::Fzf { .. } => (fzf_args(query), fzf_input(lines)),
        Picker::Fuzzel { .. } => (fuzzel_args(query), fuzzel_input(lines)),
    };
    let tool = picker.program();
    let output = run(tool, &args, &input)?;
    let declined = match picker {
        // 1: nothing matched what was typed; 130: Esc or Ctrl-C.
        Picker::Fzf { .. } => matches!(output.status.code(), Some(1 | 130)),
        // fuzzel has no distinct exit status for Esc: it exits 1 having printed nothing at all.
        // Anything on stderr means it failed instead.
        Picker::Fuzzel { .. } => {
            !output.status.success() && output.stdout.is_empty() && output.stderr.is_empty()
        }
    };
    if declined {
        return Err(ChooseError::Cancelled);
    }
    if !output.status.success() {
        return Err(ToolError::Failed {
            tool: tool.to_owned(),
            status: output.status,
            stderr: output.stderr,
        }
        .into());
    }
    let index = match picker {
        Picker::Fzf { .. } => parse_fzf_output(&output.stdout),
        Picker::Fuzzel { .. } => parse_index(&output.stdout),
    };
    index.ok_or_else(|| ChooseError::UnexpectedChoice {
        tool: tool.to_owned(),
    })
}

fn fzf_args(query: Option<&Query>) -> Vec<String> {
    let mut args: Vec<String> = [
        "--delimiter=\t",
        "--with-nth=2..",
        "--no-multi",
        "--prompt=kpx-share> ",
    ]
    .map(Into::into)
    .into();
    if let Some(query) = query {
        args.push(format!("--query={}", query.text()));
    }
    args
}

fn fuzzel_args(query: Option<&Query>) -> Vec<String> {
    let mut args: Vec<String> = [
        "--dmenu",
        "--index",
        "--only-match",
        "--prompt=kpx-share> ",
        "--log-level=error",
        "--log-no-syslog",
    ]
    .map(Into::into)
    .into();
    if let Some(query) = query {
        args.push(format!("--search={}", query.text()));
    }
    args
}

fn fzf_input(lines: &[String]) -> Vec<u8> {
    lines
        .iter()
        .enumerate()
        .flat_map(|(index, line)| format!("{index}\t{line}\n").into_bytes())
        .collect()
}

fn fuzzel_input(lines: &[String]) -> Vec<u8> {
    lines
        .iter()
        .flat_map(|line| format!("{line}\n").into_bytes())
        .collect()
}

/// fzf prints the selected line, `<index>\t<display>`.
fn parse_fzf_output(stdout: &[u8]) -> Option<usize> {
    let line = stdout.split(|byte| *byte == b'\n').next()?;
    parse_index(line.split(|byte| *byte == b'\t').next()?)
}

/// A decimal index, optionally followed by a newline.
fn parse_index(stdout: &[u8]) -> Option<usize> {
    std::str::from_utf8(stdout).ok()?.trim_end().parse().ok()
}

struct PickerOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: String,
}

/// Feeds `input` and collects the output. stdin is written from its own thread so a picker that
/// answers before reading everything cannot deadlock the caller.
fn run(tool: &Path, args: &[String], input: &[u8]) -> Result<PickerOutput, ToolError> {
    let io_error = |source| ToolError::Io {
        tool: tool.to_owned(),
        source,
    };
    let mut child = Command::new(tool)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|source| ToolError::Spawn {
            tool: tool.to_owned(),
            source,
        })?;
    let mut stdin = take_pipe(child.stdin.take()).map_err(io_error)?;
    let stdout = take_pipe(child.stdout.take()).map_err(io_error)?;
    let stderr = take_pipe(child.stderr.take()).map_err(io_error)?;
    let collected = thread::scope(|scope| {
        let writer = scope.spawn(move || {
            let written = stdin.write_all(input).and_then(|()| stdin.flush());
            ignore_broken_pipe(written)
        });
        let captured = scope.spawn(|| capture_stderr(stderr));
        let stdout = read_all(stdout);
        let written = writer.join();
        let stderr = captured.join().unwrap_or_default();
        (stdout, written, stderr)
    });
    let status = child.wait();
    let (stdout, written, stderr) = collected;
    let stdout = stdout.map_err(io_error)?;
    written
        .unwrap_or_else(|_panicked| Err(io::Error::other("writer thread panicked")))
        .map_err(io_error)?;
    Ok(PickerOutput {
        status: status.map_err(io_error)?,
        stdout,
        stderr,
    })
}

fn read_all(mut source: impl io::Read) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    source.read_to_end(&mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::select::EntryLabel;

    fn item(id_byte: u8, groups: &[&str], title: &str, user: &str, url: &str) -> PickerItem {
        let some = |text: &str| (!text.is_empty()).then(|| text.to_owned());
        PickerItem {
            id: Uuid::parse_hex(&format!("{id_byte:02x}").repeat(16)).unwrap(),
            label: EntryLabel::new(
                groups.iter().map(|group| (*group).to_owned()).collect(),
                some(title),
            ),
            user_name: some(user),
            url: some(url),
        }
    }

    fn query(text: &str) -> Query {
        Query::parse(text).unwrap()
    }

    #[test]
    fn a_query_needs_a_word() {
        assert_eq!(Query::parse(""), None);
        assert_eq!(Query::parse(" \t\n "), None);
        assert_eq!(query("  Git   HUB ").text(), "git hub");
    }

    #[test]
    fn every_word_must_occur_ignoring_case_in_label_user_or_url() {
        let github = item(
            1,
            &["Work", "Dev"],
            "GitHub",
            "Alice",
            "https://github.com/login",
        );
        let matching = [
            "github",
            "GITHUB",
            "work dev",
            "alice",
            "dev  alice",
            "login",
            "work/dev/github",
        ];
        for text in matching {
            assert!(query(text).matches(&github), "{text}");
        }
        for text in ["gitlab", "github bob", "alice zzz", "Dev/Work"] {
            assert!(!query(text).matches(&github), "{text}");
        }
    }

    #[test]
    fn an_entry_without_user_or_url_matches_on_its_label() {
        let bare = item(2, &[], "Server", "", "");
        assert!(query("serv").matches(&bare));
        assert!(!query("none").matches(&bare));
        assert!(query("(no title)").matches(&item(3, &["G"], "", "", "")));
    }

    #[test]
    fn display_lines_join_label_user_and_url_on_one_line() {
        let full = item(1, &["Work"], "GitHub", "alice", "https://github.com");
        assert_eq!(
            display_line(&full),
            "Work/GitHub  alice  https://github.com"
        );
        assert_eq!(display_line(&item(2, &[], "Server", "", "")), "Server");
        let nasty = item(3, &[], "a\tb\nc", "d\re", "");
        assert_eq!(display_line(&nasty), "a b c  d e");
    }

    #[test]
    fn candidates_keep_the_item_order_and_the_query_filters() {
        let items = [
            item(1, &[], "Alpha", "", ""),
            item(2, &[], "Beta", "", ""),
            item(3, &[], "Alphabet", "", ""),
        ];
        let ids = |query: Option<&Query>| -> Vec<Uuid> {
            candidates(&items, query)
                .iter()
                .map(|item| item.id)
                .collect()
        };
        assert_eq!(ids(None), [items[0].id, items[1].id, items[2].id]);
        assert_eq!(ids(Some(&query("alpha"))), [items[0].id, items[2].id]);
    }

    fn unrunnable() -> Picker {
        Picker::Fzf {
            program: "/nonexistent/picker".into(),
        }
    }

    #[test]
    fn no_items_and_no_matches_are_distinct_errors_and_run_no_picker() {
        let items = [item(1, &[], "Alpha", "", "")];
        let none = choose(&[], None, &unrunnable()).unwrap_err();
        assert!(matches!(none, ChooseError::NoEntries), "{none:?}");
        let unmatched = choose(&items, Some(&query("zzz")), &unrunnable()).unwrap_err();
        assert!(
            matches!(&unmatched, ChooseError::NoMatch { query } if query == "zzz"),
            "{unmatched:?}"
        );
    }

    #[test]
    fn a_single_candidate_is_chosen_without_running_a_picker() {
        let items = [item(1, &[], "Alpha", "", ""), item(2, &[], "Beta", "", "")];
        assert_eq!(
            choose(&items, Some(&query("beta")), &unrunnable()).unwrap(),
            items[1].id
        );
        assert_eq!(
            choose(&items[..1], None, &unrunnable()).unwrap(),
            items[0].id
        );
    }

    #[test]
    fn several_candidates_run_the_picker() {
        let items = [
            item(1, &[], "Alpha", "", ""),
            item(2, &[], "Alpine", "", ""),
        ];
        let error = choose(&items, Some(&query("alp")), &unrunnable()).unwrap_err();
        assert!(
            matches!(error, ChooseError::Tool(ToolError::Spawn { .. })),
            "{error:?}"
        );
    }

    #[test]
    fn fzf_input_prefixes_each_line_with_its_index_and_args_hide_it() {
        let lines = ["a b".to_owned(), "c".to_owned()];
        assert_eq!(fzf_input(&lines), b"0\ta b\n1\tc\n");
        assert_eq!(
            fzf_args(Some(&query("Foo  bar"))),
            [
                "--delimiter=\t",
                "--with-nth=2..",
                "--no-multi",
                "--prompt=kpx-share> ",
                "--query=foo bar"
            ]
        );
        assert_eq!(fzf_args(None).len(), 4);
    }

    #[test]
    fn fuzzel_prints_indexes_of_plain_lines() {
        assert_eq!(
            fuzzel_input(&["a b".to_owned(), "c".to_owned()]),
            b"a b\nc\n"
        );
        let args = fuzzel_args(Some(&query("x")));
        assert!(args.contains(&"--dmenu".to_owned()));
        assert!(args.contains(&"--index".to_owned()));
        assert_eq!(args.last().unwrap(), "--search=x");
        assert!(
            !fuzzel_args(None)
                .iter()
                .any(|arg| arg.starts_with("--search"))
        );
    }

    #[test]
    fn the_index_is_read_from_the_front_of_the_line_whatever_follows() {
        assert_eq!(parse_fzf_output(b"7\tWork/1\t2\n"), Some(7));
        assert_eq!(parse_fzf_output(b"12\t\n"), Some(12));
        assert_eq!(parse_fzf_output(b"0"), Some(0));
        for bad in [&b""[..], b"\n", b"x\t1\n", b"-1\t\n", b" 3\t", b"\t3\n"] {
            assert_eq!(parse_fzf_output(bad), None, "{bad:?}");
        }
        assert_eq!(parse_index(b"3\n"), Some(3));
        assert_eq!(parse_index(b""), None);
        assert_eq!(parse_index(b"3 4\n"), None);
    }
}
