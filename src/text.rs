//! Small text helpers shared by the modules that parse or print text they do not control.

/// The value of one hexadecimal digit, either case.
pub(crate) fn hex_digit(digit: u8) -> Option<u8> {
    char::from(digit)
        .to_digit(16)
        .and_then(|value| u8::try_from(value).ok())
}

/// `text` with every control character, newline and tab included, replaced by a space: what is
/// printed on one line cannot start another, move the cursor or drive the terminal. The text is
/// untrusted wherever it comes from a database value or a program's output.
pub(crate) fn one_line(text: &str) -> String {
    text.chars()
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_hex_digit_is_its_value_in_either_case_and_nothing_else_is_one() {
        let values: Vec<_> = b"09afAF".iter().map(|&digit| hex_digit(digit)).collect();
        assert_eq!(
            values,
            [Some(0), Some(9), Some(10), Some(15), Some(10), Some(15)]
        );
        for not_hex in [b'g', b' ', b'/', b':', 0xff] {
            assert_eq!(hex_digit(not_hex), None, "{not_hex}");
        }
    }

    #[test]
    fn control_characters_become_spaces_and_the_rest_is_kept() {
        assert_eq!(one_line("a\tb\nc\r\x1b[31md\x07é"), "a b c  [31md é");
    }
}
