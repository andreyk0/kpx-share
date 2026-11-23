//! The human's go, asked before anything is decrypted (invariant S7): a summary of what is staged
//! and where it goes, in a pinentry window without a terminal, on stderr with a `y/N` question
//! read from the terminal otherwise. Nothing in the summary is secret: names, plain fields and
//! sizes only.
//!
//! pinentry takes the summary as one Assuan line, at most [`assuan::SENT_LINE_BYTES_MAX`] bytes
//! once escaped, so the summary is bounded by construction: each shown value is cut to its share
//! ([`assuan::shortened`]), and only the first attachments are listed, the rest counted.

use std::fmt::Write as _;
use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use super::plan::Kind;
use super::staging::Staged;
use crate::assuan::{self, Keep, shortened};
use crate::unlock::{Outcome, Prompter, UnlockError, with_pinentry};

/// The human's answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Import,
    Declined,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfirmError {
    #[error("cannot ask for confirmation: {0}")]
    Pinentry(UnlockError),
    #[error("cannot ask for confirmation on {}: {source}", .path.display())]
    Terminal { path: PathBuf, source: io::Error },
}

/// What each shown value may take of the line, in escaped bytes, `…` included. With the fixed
/// words around them they add up to well under [`assuan::SENT_LINE_BYTES_MAX`]; the test
/// `the_summary_fits_one_assuan_line_whatever_is_staged` holds the sum to it.
const DATABASE_SHOWN_MAX: usize = 120;
const ENTRY_SHOWN_MAX: usize = 120;
const USERNAME_SHOWN_MAX: usize = 80;
const URL_SHOWN_MAX: usize = 120;
const ATTACHMENT_NAME_SHOWN_MAX: usize = 40;
/// Attachments listed one per line; the others are counted on one more.
const ATTACHMENTS_LISTED_MAX: usize = 3;

/// The question after the summary.
const QUESTION: &str = "Import this into the database?";

/// What the confirmation shows: the database, the entry and whether it is new, its plain fields
/// and that they are program arguments, and the size of each secret.
#[must_use]
pub fn summary(database: &Path, staged: &Staged) -> String {
    let plan = staged.plan();
    let mut text = format!(
        "kpx-share: import into {}\n",
        shortened(
            &database.display().to_string(),
            DATABASE_SHOWN_MAX,
            Keep::End
        )
    );
    let entry = shortened(&plan.entry().to_string(), ENTRY_SHOWN_MAX, Keep::Start);
    // Writing to a String cannot fail.
    let _infallible = match plan.kind() {
        Kind::New { username, url, .. } => writeln!(
            text,
            "new entry {entry}\nusername: {}\nURL: {}\npassword: {}\n\
             (the username and URL reach keepassxc-cli as program arguments)",
            username.as_ref().map_or_else(
                || "(empty)".to_owned(),
                |username| shortened(username.as_str(), USERNAME_SHOWN_MAX, Keep::Start)
            ),
            url.as_ref().map_or_else(
                || "(empty)".to_owned(),
                |url| shortened(url.as_str(), URL_SHOWN_MAX, Keep::Start)
            ),
            plan.password().map_or_else(
                || "(empty)".to_owned(),
                |pw| bytes(pw.content().secret().len())
            ),
        ),
        Kind::Existing(_) => writeln!(text, "existing entry {entry}"),
    };
    let attachments = plan.attachments();
    for attachment in attachments.iter().take(ATTACHMENTS_LISTED_MAX) {
        let _infallible = writeln!(
            text,
            "attachment {}: {}",
            shortened(
                attachment.name().as_str(),
                ATTACHMENT_NAME_SHOWN_MAX,
                Keep::Start
            ),
            bytes(attachment.content().secret().len())
        );
    }
    if let Some(more) = attachments
        .get(ATTACHMENTS_LISTED_MAX..)
        .filter(|more| !more.is_empty())
    {
        let total: usize = more.iter().map(|a| a.content().secret().len()).sum();
        let _infallible = writeln!(
            text,
            "and {} more attachments, {} in all",
            more.len(),
            bytes(total)
        );
    }
    text
}

fn bytes(count: usize) -> String {
    match count {
        1 => "1 byte".to_owned(),
        count => format!("{count} bytes"),
    }
}

/// What pinentry is shown: the summary and the question.
fn description(summary: &str) -> String {
    format!("{summary}\n{QUESTION}")
}

/// Asks whether to import what `summary` describes: through pinentry's `CONFIRM`, or on the
/// terminal, with the summary written to `err` and the answer read from `tty`.
///
/// # Errors
/// The question could not be asked or answered; that is no answer, so nothing is imported.
pub fn confirm(
    prompter: &Prompter,
    tty: &Path,
    summary: &str,
    err: &mut dyn Write,
) -> Result<Decision, ConfirmError> {
    match prompter {
        Prompter::Pinentry { program } => {
            let description = description(summary);
            match with_pinentry(program, |server, client| {
                assuan::confirm(server, client, "kpx-share import", &description)
            }) {
                Ok(Outcome::Done(())) => Ok(Decision::Import),
                Ok(Outcome::Declined) => Ok(Decision::Declined),
                Err(error) => Err(ConfirmError::Pinentry(error)),
            }
        }
        Prompter::Terminal => ask_on_terminal(tty, summary, err),
    }
}

/// Bound on the answer read: `yes` and a line feed, with room for stray spaces.
const ANSWER_BYTES_MAX: usize = 16;

fn ask_on_terminal(
    tty: &Path,
    summary: &str,
    err: &mut dyn Write,
) -> Result<Decision, ConfirmError> {
    let terminal_error = |source| ConfirmError::Terminal {
        path: tty.to_owned(),
        source,
    };
    write!(err, "{summary}{QUESTION} [y/N] ")
        .and_then(|()| err.flush())
        .map_err(terminal_error)?;
    let mut terminal = OpenOptions::new()
        .read(true)
        .open(tty)
        .map_err(terminal_error)?;
    let mut answer = Vec::new();
    let mut byte = [0u8; 1];
    while answer.len() < ANSWER_BYTES_MAX {
        match terminal.read(&mut byte) {
            Ok(0) => break,
            Ok(_) if byte == *b"\n" => break,
            Ok(_) => answer.push(byte[0]),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(terminal_error(error)),
        }
    }
    let answer = String::from_utf8_lossy(&answer);
    if matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
        Ok(Decision::Import)
    } else {
        Ok(Decision::Declined)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::import::staging::{AttachmentContent, EntryPassword};

    fn staged_from(json: &str, content: &[u8]) -> Staged {
        let manifest = crate::import::manifest::parse(json.as_bytes()).unwrap();
        Staged::for_tests(
            manifest
                .try_map(
                    |_, ()| Ok::<_, ()>(EntryPassword::for_tests(&[b'a'; 32])),
                    |_, _, ()| Ok(AttachmentContent::for_tests(content)),
                )
                .unwrap(),
        )
    }

    /// The whole summary for five attachments, written out by hand: three listed, two counted
    /// with their total. Red when a line changes, the count or the total is off, or a sixth
    /// line appears.
    #[test]
    fn the_summary_lists_three_attachments_and_counts_the_rest() {
        let staged = staged_from(
            r#"{"kind":"existing","entry":"Ops/hvac","attachments":
                {"a.pem":"a","b.pem":"b","c.pem":"c","d.pem":"d","e.pem":"e"}}"#,
            b"0123456789",
        );
        assert_eq!(
            summary(Path::new("/db/my.kdbx"), &staged),
            "kpx-share: import into /db/my.kdbx\n\
             existing entry Ops/hvac\n\
             attachment a.pem: 10 bytes\n\
             attachment b.pem: 10 bytes\n\
             attachment c.pem: 10 bytes\n\
             and 2 more attachments, 20 bytes in all\n"
        );
    }

    /// The worst a manifest can stage (every value at its bound, made of `%`, which escapes to
    /// three bytes, and many attachments) still fits one Assuan line. Red when a value is shown
    /// uncut, or every attachment is listed.
    #[test]
    fn the_summary_fits_one_assuan_line_whatever_is_staged() {
        let percents = |count: usize| "%".repeat(count);
        let attachments: Vec<String> = (0..400)
            .map(|i| format!(r#""{}{i}":"f{i}""#, percents(250)))
            .collect();
        let json = format!(
            r#"{{"kind":"new","entry":"{}","username":"{}","url":"{}","password":"pw","attachments":{{{}}}}}"#,
            percents(4096),
            percents(1024),
            percents(1024),
            attachments.join(",")
        );
        let staged = staged_from(&json, b"16 MiB stands in");
        let database = Path::new("/").join(percents(4000));
        let line = format!(
            "SETDESC {}\n",
            description(&summary(&database, &staged))
                .chars()
                .map(|ch| match ch {
                    '%' => "%25".to_owned(),
                    '\n' => "%0A".to_owned(),
                    ch => ch.to_string(),
                })
                .collect::<String>()
        );
        // The attachments here are a few bytes; real ones of 16 MiB print up to 5 more digits
        // on each of the 3 listed lines and 6 on the count line.
        let size_digits_margin = 3 * 5 + 6;
        assert!(
            line.len() + size_digits_margin <= assuan::SENT_LINE_BYTES_MAX,
            "{} bytes: {line}",
            line.len()
        );
        assert!(line.contains("and 397 more attachments"), "{line}");
    }
}
