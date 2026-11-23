//! KeePass placeholders in field values: which ones are resolved, and how.
//!
//! Resolved:
//! - `{TITLE}`, `{USERNAME}`, `{PASSWORD}`, `{URL}`, `{NOTES}` (any case): the same entry's field;
//! - `{REF:<F>@I:<uuid>}`: field `<F>` (`T`itle, `U`sername, `P`assword, url `A`, `N`otes) of the
//!   entry whose UUID is the 32 hex digits `<uuid>`, searched across the whole database.
//!
//! A substituted value is itself resolved first, in its own entry's context. Every other
//! placeholder, a reference to a missing entry, a reference cycle, and a chain deeper than
//! [`MAX_DEPTH`] are left in the text verbatim and reported as [`Completeness::Unresolved`].

use crate::model::{Database, Entry, StandardField, Uuid};
use crate::secret::SecretBytes;

/// How many references deep a substitution may go. Real references are one or two deep; the
/// bound keeps a long chain from exhausting the stack.
pub(crate) const MAX_DEPTH: usize = 10;

/// Whether a resolved value still holds a placeholder that was left verbatim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Completeness {
    Complete,
    Unresolved,
}

impl Completeness {
    fn and(self, other: Self) -> Self {
        match (self, other) {
            (Self::Complete, Self::Complete) => Self::Complete,
            (Self::Unresolved, _) | (_, Self::Unresolved) => Self::Unresolved,
        }
    }
}

#[derive(Debug)]
pub(crate) struct Resolution {
    pub(crate) value: SecretBytes,
    pub(crate) completeness: Completeness,
}

#[derive(Debug, PartialEq, Eq)]
enum Placeholder {
    OwnField(StandardField),
    Reference { field: StandardField, target: Uuid },
    Other,
}

/// Resolves values against one database, tracking the fields being resolved to break cycles.
pub(crate) struct Resolver<'db> {
    database: &'db Database,
    /// The (entry, field) pairs whose values are being resolved, outermost first.
    in_progress: Vec<(Uuid, StandardField)>,
}

impl<'db> Resolver<'db> {
    pub(crate) fn new(database: &'db Database) -> Self {
        Self {
            database,
            in_progress: Vec::new(),
        }
    }

    /// `entry`'s standard field resolved; `None` when the entry has no such field.
    pub(crate) fn standard_field(
        &mut self,
        entry: &Entry,
        field: StandardField,
    ) -> Option<Resolution> {
        let raw = entry.fields().get(field)?;
        self.in_progress.push((entry.uuid(), field));
        let resolution = self.value(entry, raw.expose());
        self.in_progress.pop();
        Some(resolution)
    }

    /// `raw` resolved in the context of `entry`, whose own fields `{TITLE}` etc. refer to.
    pub(crate) fn value(&mut self, entry: &Entry, raw: &[u8]) -> Resolution {
        let mut value = SecretBytes::new();
        let mut completeness = Completeness::Complete;
        let mut rest = raw;
        while let Some(found) = next_placeholder(rest) {
            value.extend_from_slice(found.before);
            if let Some(expansion) = self.expand(entry, found.body) {
                value.extend_from_slice(expansion.value.expose());
                completeness = completeness.and(expansion.completeness);
            } else {
                value.extend_from_slice(found.verbatim);
                completeness = Completeness::Unresolved;
            }
            rest = found.after;
        }
        value.extend_from_slice(rest);
        Resolution {
            value,
            completeness,
        }
    }

    /// The text a placeholder stands for; `None` keeps it verbatim.
    fn expand(&mut self, entry: &Entry, body: &[u8]) -> Option<Resolution> {
        match classify(body) {
            Placeholder::OwnField(field) => self.substitute(entry, field),
            Placeholder::Reference { field, target } => {
                // The whole database, untagged and recycle-bin entries included, whatever
                // eligibility rule picked the entry being resolved: the human wrote this
                // reference into an entry they chose to share, and KeePassXC shows the same
                // value for it. Eligibility gates what is shared, not what a reference follows.
                let target = self.database.entry(target)?;
                self.substitute(target, field)
            }
            Placeholder::Other => None,
        }
    }

    fn substitute(&mut self, target: &Entry, field: StandardField) -> Option<Resolution> {
        let already_resolving = self.in_progress.contains(&(target.uuid(), field));
        if already_resolving || self.in_progress.len() >= MAX_DEPTH {
            return None;
        }
        // Substituting into text is where an absent field finally becomes empty text, as in
        // KeePassXC.
        Some(
            self.standard_field(target, field)
                .unwrap_or_else(|| Resolution {
                    value: SecretBytes::new(),
                    completeness: Completeness::Complete,
                }),
        )
    }
}

struct Found<'t> {
    before: &'t [u8],
    /// Between the braces, non-empty, without `{` or `}`.
    body: &'t [u8],
    /// The placeholder with its braces, as written.
    verbatim: &'t [u8],
    after: &'t [u8],
}

/// The first `{…}` in `text` with a non-empty body and no brace inside it.
fn next_placeholder(text: &[u8]) -> Option<Found<'_>> {
    let mut search_from = 0;
    loop {
        let open = search_from + text.get(search_from..)?.iter().position(|&b| b == b'{')?;
        let body_start = open + 1;
        let body_len = text
            .get(body_start..)?
            .iter()
            .position(|&b| b == b'{' || b == b'}')?;
        let close = body_start + body_len;
        match text.get(close) {
            Some(b'}') if body_len > 0 => {
                let (before, from_open) = text.split_at(open);
                let (verbatim, after) = from_open.split_at(body_len + 2);
                let body = verbatim.get(1..=body_len)?;
                return Some(Found {
                    before,
                    body,
                    verbatim,
                    after,
                });
            }
            // `{}` is literal text; `{` inside a body starts the candidate over from there.
            Some(b'}') => search_from = close + 1,
            _ => search_from = close,
        }
    }
}

fn classify(body: &[u8]) -> Placeholder {
    let Ok(body) = std::str::from_utf8(body) else {
        return Placeholder::Other;
    };
    if let Some(field) = own_field(body) {
        return Placeholder::OwnField(field);
    }
    reference(body).unwrap_or(Placeholder::Other)
}

fn own_field(body: &str) -> Option<StandardField> {
    [
        ("TITLE", StandardField::Title),
        ("USERNAME", StandardField::UserName),
        ("PASSWORD", StandardField::Password),
        ("URL", StandardField::Url),
        ("NOTES", StandardField::Notes),
    ]
    .into_iter()
    .find_map(|(name, field)| body.eq_ignore_ascii_case(name).then_some(field))
}

/// `REF:<F>@I:<32 hex>`, case-insensitive apart from the hex, which is either case anyway.
fn reference(body: &str) -> Option<Placeholder> {
    let (prefix, rest) = body.split_at_checked(4)?;
    if !prefix.eq_ignore_ascii_case("REF:") {
        return None;
    }
    let (letter, rest) = rest.split_at_checked(1)?;
    let (search, target) = rest.split_at_checked(3)?;
    if !search.eq_ignore_ascii_case("@I:") {
        return None;
    }
    let field = match letter.to_ascii_uppercase().as_str() {
        "T" => StandardField::Title,
        "U" => StandardField::UserName,
        "P" => StandardField::Password,
        "A" => StandardField::Url,
        "N" => StandardField::Notes,
        _ => return None,
    };
    let target = Uuid::parse_hex(target)?;
    Some(Placeholder::Reference { field, target })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn found(text: &str) -> Option<(String, String, String)> {
        next_placeholder(text.as_bytes()).map(|f| {
            let s = |b: &[u8]| String::from_utf8(b.to_vec()).unwrap();
            assert_eq!(s(f.verbatim), format!("{{{}}}", s(f.body)));
            (s(f.before), s(f.body), s(f.after))
        })
    }

    #[test]
    fn finds_first_braced_body() {
        assert_eq!(
            found("a{X}b{Y}"),
            Some(("a".into(), "X".into(), "b{Y}".into()))
        );
    }

    #[test]
    fn empty_braces_and_unclosed_brace_are_text() {
        assert_eq!(found("{}"), None);
        assert_eq!(found("a{b"), None);
        assert_eq!(
            found("{}{X}"),
            Some(("{}".into(), "X".into(), String::new()))
        );
    }

    #[test]
    fn nested_open_brace_restarts_the_candidate() {
        assert_eq!(
            found("{{TITLE}}"),
            Some(("{".into(), "TITLE".into(), "}".into()))
        );
    }

    #[test]
    fn classifies_own_fields_in_any_case() {
        assert_eq!(
            classify(b"password"),
            Placeholder::OwnField(StandardField::Password)
        );
        assert_eq!(
            classify(b"UserName"),
            Placeholder::OwnField(StandardField::UserName)
        );
        assert_eq!(classify(b"S:custom"), Placeholder::Other);
    }

    #[test]
    fn classifies_references_by_uuid_only() {
        let target = Uuid::parse_hex("0123456789abcdef0123456789abcdef").unwrap();
        assert_eq!(
            classify(b"ref:a@i:0123456789ABCDEF0123456789ABCDEF"),
            Placeholder::Reference {
                field: StandardField::Url,
                target
            }
        );
        assert_eq!(
            classify(b"REF:P@T:Some Title"),
            Placeholder::Other,
            "search by title is not supported"
        );
        assert_eq!(
            classify(b"REF:X@I:0123456789abcdef0123456789abcdef"),
            Placeholder::Other
        );
        assert_eq!(classify(b"REF:P@I:0123"), Placeholder::Other);
    }
}
