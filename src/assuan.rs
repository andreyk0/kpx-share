//! The client side of a pinentry session: the Assuan protocol, just enough to ask for a password.
//!
//! The client sends `SETTITLE`, `SETDESC`, `SETPROMPT` and `GETPIN`, each answered by `OK`; the
//! password arrives as percent-escaped `D` lines before the final `OK` of `GETPIN`. A notice
//! is `SETTITLE`, `SETDESC` and `MESSAGE`, answered by `OK` once the human has dismissed it. A
//! refused prompt is an `ERR` line whose code is a gpg-error value.
//!
//! The functions are generic over [`Read`] and [`Write`] so a scripted fake can stand in for
//! pinentry. The reader is deliberately unbuffered: a `BufReader` would keep the password in an
//! internal buffer this code could not wipe, so lines are read a byte at a time into
//! [`SecretBytes`]. Error values never carry a line from the server, since any line may be the
//! password.

use std::io::{self, Read, Write};

use zeroize::Zeroize;

use crate::secret::SecretBytes;
use crate::text::hex_digit;

/// Assuan lines are at most 1000 bytes; this is the slack kpx-share tolerates.
const LINE_BYTES_MAX: usize = 4096;
/// A longer master password is not credible; bounds what concatenated `D` lines may add up to.
const PIN_BYTES_MAX: usize = 4096;
/// gpg-error `GPG_ERR_CANCELED`, the low 16 bits of the code pinentry reports on cancel (the high
/// bits name the error's source).
const GPG_ERR_CANCELED: u32 = 99;
const GPG_ERR_CODE_MASK: u32 = 0xFFFF;

/// The texts of the prompt window; none is secret.
#[derive(Clone, Copy, Debug)]
pub struct Dialog<'a> {
    pub title: &'a str,
    pub description: &'a str,
    pub prompt: &'a str,
}

#[derive(Debug, thiserror::Error)]
pub enum AssuanError {
    #[error("pinentry I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("pinentry closed the connection")]
    Closed,
    #[error("pinentry sent a line or password longer than the supported maximum")]
    TooLong,
    #[error("pinentry sent a line that is not valid Assuan")]
    Malformed,
    #[error("pinentry asked for a client inquiry, which kpx-share does not support")]
    Inquire,
    #[error("the pinentry dialog was cancelled")]
    Cancelled,
    #[error("pinentry refused with error code {code}")]
    Refused { code: u32 },
}

/// One line from the server, parsed.
#[derive(Debug)]
enum Response {
    Ok,
    /// Unescaped payload of a `D` line.
    Data(SecretBytes),
    Err {
        code: u32,
    },
    /// A `#` comment or `S` status line.
    Ignored,
}

/// Runs the dialog and returns the password the human typed.
///
/// # Errors
/// [`AssuanError::Cancelled`] when the human dismissed the prompt; otherwise the protocol or
/// I/O failure.
pub fn get_pin(
    server: &mut impl Read,
    client: &mut impl Write,
    dialog: &Dialog<'_>,
) -> Result<SecretBytes, AssuanError> {
    set_up(
        server,
        client,
        &[
            ("SETTITLE", dialog.title),
            ("SETDESC", dialog.description),
            ("SETPROMPT", dialog.prompt),
        ],
    )?;
    send(client, "GETPIN")?;
    let mut pin = SecretBytes::new();
    loop {
        match next_response(server)? {
            Response::Ok => return Ok(pin),
            Response::Data(chunk) => {
                if pin.len() + chunk.len() > PIN_BYTES_MAX {
                    return Err(AssuanError::TooLong);
                }
                pin.extend_from_slice(chunk.expose());
            }
            Response::Ignored => {}
            Response::Err { code } => return Err(refusal(code)),
        }
    }
}

/// Shows `title` and `description` in a window with an OK button and returns once the human has
/// dismissed it.
///
/// # Errors
/// [`AssuanError::Cancelled`] when the human closed the window instead of pressing OK; otherwise
/// the protocol or I/O failure.
pub fn message(
    server: &mut impl Read,
    client: &mut impl Write,
    title: &str,
    description: &str,
) -> Result<(), AssuanError> {
    set_up(
        server,
        client,
        &[("SETTITLE", title), ("SETDESC", description)],
    )?;
    send(client, "MESSAGE")?;
    expect_ok(server)
}

/// Reads the greeting, then sends each `(command, text)` and waits for its `OK`.
fn set_up(
    server: &mut impl Read,
    client: &mut impl Write,
    commands: &[(&str, &str)],
) -> Result<(), AssuanError> {
    expect_ok(server)?; // the greeting
    for (keyword, text) in commands {
        send(client, &format!("{keyword} {}", escape(text)))?;
        expect_ok(server)?;
    }
    Ok(())
}

/// Ends the session politely. The password is already in hand, so a failure here is not one.
pub fn bye(client: &mut impl Write) {
    let _ignored = send(client, "BYE");
}

fn send(client: &mut impl Write, line: &str) -> Result<(), AssuanError> {
    client.write_all(line.as_bytes())?;
    client.write_all(b"\n")?;
    client.flush()?;
    Ok(())
}

/// Percent-escapes what Assuan lines cannot carry raw: `%`, CR and LF.
fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '%' => out.push_str("%25"),
            '\r' => out.push_str("%0D"),
            '\n' => out.push_str("%0A"),
            other => out.push(other),
        }
    }
    out
}

fn refusal(code: u32) -> AssuanError {
    if code & GPG_ERR_CODE_MASK == GPG_ERR_CANCELED {
        AssuanError::Cancelled
    } else {
        AssuanError::Refused { code }
    }
}

/// Reads responses until the `OK` that answers the last command.
fn expect_ok(server: &mut impl Read) -> Result<(), AssuanError> {
    loop {
        match next_response(server)? {
            Response::Ok => return Ok(()),
            Response::Ignored => {}
            Response::Data(_) => return Err(AssuanError::Malformed),
            Response::Err { code } => return Err(refusal(code)),
        }
    }
}

fn next_response(server: &mut impl Read) -> Result<Response, AssuanError> {
    parse_response(&read_line(server)?)
}

/// One line without its `\n`, read a byte at a time into a wiped-on-drop buffer.
fn read_line(server: &mut impl Read) -> Result<SecretBytes, AssuanError> {
    let mut line = SecretBytes::new();
    let mut byte = [0u8; 1];
    let outcome = loop {
        match server.read(&mut byte) {
            Ok(0) => break Err(AssuanError::Closed),
            Ok(_) if byte == *b"\n" => break Ok(()),
            Ok(_) if line.len() >= LINE_BYTES_MAX => break Err(AssuanError::TooLong),
            Ok(_) => line.extend_from_slice(&byte),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => break Err(AssuanError::Io(error)),
        }
    };
    byte.zeroize();
    outcome.map(|()| line)
}

fn parse_response(line: &SecretBytes) -> Result<Response, AssuanError> {
    let mut parts = line.expose().splitn(2, |byte| *byte == b' ');
    let keyword = parts.next().unwrap_or_default();
    let rest = parts.next().unwrap_or_default();
    match keyword {
        b"OK" => Ok(Response::Ok),
        b"D" => unescape(rest).map(Response::Data),
        b"ERR" => error_code(rest).map(|code| Response::Err { code }),
        b"#" | b"S" => Ok(Response::Ignored),
        b"INQUIRE" => Err(AssuanError::Inquire),
        _ => Err(AssuanError::Malformed),
    }
}

/// The leading decimal code of an `ERR <code> <description>` line.
fn error_code(rest: &[u8]) -> Result<u32, AssuanError> {
    let token = rest.split(|byte| *byte == b' ').next().unwrap_or_default();
    std::str::from_utf8(token)
        .ok()
        .and_then(|digits| digits.parse().ok())
        .ok_or(AssuanError::Malformed)
}

fn unescape(data: &[u8]) -> Result<SecretBytes, AssuanError> {
    let mut out = SecretBytes::new();
    let mut bytes = data.iter().copied();
    while let Some(byte) = bytes.next() {
        let decoded = if byte == b'%' {
            let high = bytes.next().and_then(hex_digit);
            let low = bytes.next().and_then(hex_digit);
            match (high, low) {
                (Some(high), Some(low)) => (high << 4) | low,
                _ => return Err(AssuanError::Malformed),
            }
        } else {
            byte
        };
        out.extend_from_slice(&[decoded]);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    const DIALOG: Dialog<'_> = Dialog {
        title: "kpx-share",
        description: "Unlock 100%\nnow",
        prompt: "Password:",
    };

    /// What a conforming client must send for `DIALOG`, written out from the protocol.
    const DIALOG_SENT: &str =
        "SETTITLE kpx-share\nSETDESC Unlock 100%25%0Anow\nSETPROMPT Password:\nGETPIN\n";

    fn session(server_script: &str) -> (Result<SecretBytes, AssuanError>, String) {
        let mut sent = Vec::new();
        let result = get_pin(
            &mut Cursor::new(server_script.as_bytes().to_vec()),
            &mut sent,
            &DIALOG,
        );
        (result, String::from_utf8(sent).unwrap())
    }

    fn pin(server_script: &str) -> Vec<u8> {
        let (result, sent) = session(server_script);
        assert_eq!(sent, DIALOG_SENT);
        result.unwrap().expose().to_vec()
    }

    /// A pinentry that has exited: every write fails.
    struct Broken;

    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    const ACCEPTS_SETUP: &str = "OK Pleased to meet you\nOK\nOK\nOK\n";

    #[test]
    fn password_is_unescaped_from_a_data_line() {
        let script = format!("{ACCEPTS_SETUP}D pw%25x%0Ay%0D z\nOK\n");
        assert_eq!(pin(&script), b"pw%x\ny\r z");
    }

    #[test]
    fn data_lines_concatenate_and_comments_and_status_are_skipped() {
        let script = format!("{ACCEPTS_SETUP}# thinking\nS PINENTRY_LAUNCHED 1\nD ab\nD cd\nOK\n");
        assert_eq!(pin(&script), b"abcd");
    }

    #[test]
    fn no_data_line_is_an_empty_password() {
        assert_eq!(pin(&format!("{ACCEPTS_SETUP}OK\n")), b"");
    }

    #[test]
    fn cancel_is_cancelled_whatever_the_error_source() {
        for code in ["83886179", "99"] {
            let script = format!("{ACCEPTS_SETUP}ERR {code} Operation cancelled <Pinentry>\n");
            let (result, sent) = session(&script);
            assert!(matches!(result, Err(AssuanError::Cancelled)), "{result:?}");
            assert_eq!(sent, DIALOG_SENT);
        }
    }

    #[test]
    fn other_errors_are_refusals_carrying_the_code() {
        let (result, _) = session(&format!("{ACCEPTS_SETUP}ERR 83886194 Not confirmed\n"));
        assert!(matches!(
            result,
            Err(AssuanError::Refused { code: 83_886_194 })
        ));
    }

    #[test]
    fn an_error_answering_a_setup_command_stops_the_session() {
        let (result, sent) = session("OK hi\nERR 83886081 Invalid value\n");
        assert!(
            matches!(result, Err(AssuanError::Refused { .. })),
            "{result:?}"
        );
        assert_eq!(sent, "SETTITLE kpx-share\n");
    }

    #[test]
    fn malformed_lines_are_errors_not_passwords() {
        let malformed = [
            "WAT\n",
            "D %zz\n",
            "D abc%4\n",
            "D %\n",
            "ERR notanumber x\n",
            "ERR\n",
        ];
        for line in malformed {
            let (result, _) = session(&format!("{ACCEPTS_SETUP}{line}OK\n"));
            assert!(
                matches!(result, Err(AssuanError::Malformed)),
                "{line:?} gave {result:?}"
            );
        }
        let (result, _) = session("D data before the greeting\n");
        assert!(matches!(result, Err(AssuanError::Malformed)));
    }

    #[test]
    fn inquire_is_unsupported() {
        let (result, _) = session(&format!("{ACCEPTS_SETUP}INQUIRE PASSPHRASE\n"));
        assert!(matches!(result, Err(AssuanError::Inquire)));
    }

    #[test]
    fn a_closed_connection_is_an_error_even_after_data() {
        for script in [
            "",
            "OK hi\n",
            "OK hi\nOK",
            &format!("{ACCEPTS_SETUP}D pw\n"),
        ] {
            let (result, _) = session(script);
            assert!(matches!(result, Err(AssuanError::Closed)), "{script:?}");
        }
    }

    #[test]
    fn oversized_lines_and_passwords_are_refused() {
        let line = format!("{ACCEPTS_SETUP}D {}\nOK\n", "a".repeat(LINE_BYTES_MAX + 1));
        assert!(matches!(session(&line).0, Err(AssuanError::TooLong)));
        let chunk = format!("D {}\n", "a".repeat(PIN_BYTES_MAX / 2 + 1));
        let sum = format!("{ACCEPTS_SETUP}{chunk}{chunk}OK\n");
        assert!(matches!(session(&sum).0, Err(AssuanError::TooLong)));
    }

    #[test]
    fn errors_never_print_the_server_line() {
        let (result, _) = session(&format!("{ACCEPTS_SETUP}D hunter2 %zz\n"));
        let shown = format!("{result:?}");
        assert!(!shown.contains("hunter2"), "{shown}");
    }

    fn notice(server_script: &str) -> (Result<(), AssuanError>, String) {
        let mut sent = Vec::new();
        let result = message(
            &mut Cursor::new(server_script.as_bytes().to_vec()),
            &mut sent,
            "kpx-share",
            "Touch 100%\nnow",
        );
        (result, String::from_utf8(sent).unwrap())
    }

    /// What a conforming client must send for the notice above, written out from the protocol.
    const NOTICE_SENT: &str = "SETTITLE kpx-share\nSETDESC Touch 100%25%0Anow\nMESSAGE\n";

    #[test]
    fn a_notice_is_shown_by_message_and_ends_with_the_oks_answer() {
        let (result, sent) = notice("OK hi\nOK\nOK\n# shown\nOK\n");
        result.unwrap();
        assert_eq!(sent, NOTICE_SENT);
    }

    #[test]
    fn closing_a_notice_is_cancelled_and_other_failures_are_not() {
        let (result, sent) = notice("OK hi\nOK\nOK\nERR 83886179 Operation cancelled <Pinentry>\n");
        assert!(matches!(result, Err(AssuanError::Cancelled)), "{result:?}");
        assert_eq!(sent, NOTICE_SENT);

        let (result, _) = notice("OK hi\nOK\nOK\nERR 83886194 Not confirmed\n");
        assert!(matches!(
            result,
            Err(AssuanError::Refused { code: 83_886_194 })
        ));
        let (result, sent) = notice("OK hi\nERR 83886081 Invalid value\n");
        assert!(matches!(result, Err(AssuanError::Refused { .. })));
        assert_eq!(sent, "SETTITLE kpx-share\n");
        let (result, _) = notice("OK hi\nOK\nOK\n");
        assert!(matches!(result, Err(AssuanError::Closed)));
    }

    #[test]
    fn bye_sends_one_line_and_swallows_a_broken_pipe() {
        let mut sent = Vec::new();
        bye(&mut sent);
        assert_eq!(sent, b"BYE\n");
        bye(&mut Broken);
    }
}
