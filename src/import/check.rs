//! What the database holds, before and after the import is applied to the copy.
//!
//! [`preflight`] classifies the copy before anything is written: the import is still to do, was
//! already done (a rerun after the database was replaced but before the staging directory was
//! deleted), or is refused because something staged collides with what is there. [`prove`]
//! compares the copy after the writes with the copy before (invariant S1): the target holds
//! exactly what was staged, byte for byte, and nothing else in the database changed. Entries are
//! compared by UUID and by their parsed content; the XML itself is never compared, as its
//! binary references are renumbered on every save.
//!
//! Neither reads attachment bytes itself: each takes the exporter it is handed, which exports an
//! attachment of the staged entry by name, and may come back [`Outcome::Declined`] (the human
//! closed a `YubiKey` notice); that ends the check as declined.

use std::collections::BTreeSet;

use super::manifest::{AttachmentName, EntryPath, EntryUrl, FieldText};
use super::plan::Kind;
use super::staging::{StagedAttachment, StagedPlan};
use crate::model::{Database, Entry, Location, StandardField, Uuid};
use crate::otp::Otp;
use crate::secret::SecretBytes;
use crate::select::EntryLabel;
use crate::unlock::Outcome;

/// What the copy says about the import, before anything is written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Preflight {
    /// Nothing staged is there yet.
    ToDo,
    /// Everything staged is there, byte for byte: nothing to write.
    AlreadyDone,
}

/// Why the database cannot take what is staged. It is unchanged.
#[derive(Debug, thiserror::Error)]
pub enum Refusal {
    #[error(
        "entry {0} already exists and does not hold what is staged; import only adds, so stage it as \"existing\" with attachments, or choose another path"
    )]
    EntryExists(EntryPath),
    #[error("there is no entry {0} to add attachments to")]
    NoEntry(EntryPath),
    #[error(
        "there is no group {} for new entry {entry}; create the group in KeePassXC, or name an existing one",
        entry.groups().join("/")
    )]
    NoGroup { entry: EntryPath },
    #[error(
        "{count} entries have the path {entry}, and keepassxc-cli would take the first; rename or move all but one"
    )]
    Ambiguous { entry: EntryPath, count: usize },
    #[error("entry {0} is in the recycle bin")]
    InRecycleBin(EntryPath),
    #[error(
        "entry {entry} already has an attachment {:?} with other content; import only adds, never replaces",
        name.as_str()
    )]
    AttachmentDiffers {
        entry: EntryPath,
        name: AttachmentName,
    },
    #[error(
        "entry {entry} already has attachment {:?} but not every staged one; import all of them anew under other names, or remove it in KeePassXC",
        name.as_str()
    )]
    PartlyThere {
        entry: EntryPath,
        name: AttachmentName,
    },
}

/// What of an entry changed, never how: no value is named.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Aspect {
    Fields,
    Attributes,
    Totp,
    Tags,
    Attachments,
    Group,
    Location,
    History,
}

impl std::fmt::Display for Aspect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Fields => "standard fields",
            Self::Attributes => "custom attributes",
            Self::Totp => "TOTP",
            Self::Tags => "tags",
            Self::Attachments => "attachment names",
            Self::Group => "group",
            Self::Location => "place in or out of the recycle bin",
            Self::History => "history",
        })
    }
}

/// What staged item the copy does not hold exactly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StagedItem {
    Title,
    Username,
    Url,
    Password,
    Notes,
    Attachment(AttachmentName),
}

impl std::fmt::Display for StagedItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Title => f.write_str("its title"),
            Self::Username => f.write_str("its username"),
            Self::Url => f.write_str("its URL"),
            Self::Password => f.write_str("its password"),
            Self::Notes => f.write_str("its notes"),
            Self::Attachment(name) => write!(f, "attachment {:?}", name.as_str()),
        }
    }
}

/// Why the written copy is not what was asked for. The database is unchanged; this is a
/// keepassxc-cli or kpx-share bug, or a KeePassXC behaviour kpx-share does not expect, except
/// [`ProofError::HistoryPruned`].
#[derive(Debug, thiserror::Error)]
pub enum ProofError {
    #[error(
        "KeePassXC dropped old history versions of entry {0} to stay within the database's history limits; raise them (Database Settings, History: maximum items and maximum size per entry) or delete old history, and import again"
    )]
    HistoryPruned(EntryPath),
    #[error("entry {label} ({uuid}) is missing after the import")]
    EntryGone { uuid: Uuid, label: String },
    #[error("the {aspect} of entry {label} ({uuid}) changed")]
    EntryChanged {
        uuid: Uuid,
        label: String,
        aspect: Aspect,
    },
    #[error("the import made {0} new entries, not the one asked for")]
    NewEntries(usize),
    #[error("after the import, {count} entries have the path {entry}, not exactly the target")]
    TargetNotAlone { entry: EntryPath, count: usize },
    #[error("entry {entry} does not hold {item} as staged")]
    Differs { entry: EntryPath, item: StagedItem },
}

/// How [`preflight`] and [`prove`] fail: by a verdict, or by the exporter, whose error is `E`.
#[derive(Debug, thiserror::Error)]
pub enum CheckError<E> {
    #[error(transparent)]
    Refused(Refusal),
    #[error("the written copy is not what was staged, so nothing was imported: {0}")]
    Proof(ProofError),
    #[error("cannot export attachment {:?} to compare it: {source}", name.as_str())]
    Export {
        name: AttachmentName,
        #[source]
        source: E,
    },
}

/// Classifies `database` for `staged`.
///
/// # Errors
/// A [`Refusal`], or the exporter's error.
pub fn preflight<E>(
    database: &Database,
    staged: &StagedPlan,
    mut export_attachment: impl FnMut(&str) -> Result<Outcome<SecretBytes>, E>,
) -> Result<Outcome<Preflight>, CheckError<E>> {
    let entry = staged.entry();
    let refused = |refusal| Err(CheckError::Refused(refusal));
    match (
        staged.kind(),
        database.entries_at(&entry.cli_path()).as_slice(),
    ) {
        // keepassxc-cli add makes no group: its "could not create entry" says nothing of why.
        (Kind::New { .. }, []) if !database.has_live_group(entry.groups()) => {
            refused(Refusal::NoGroup {
                entry: entry.clone(),
            })
        }
        (Kind::New { .. }, []) => Ok(Outcome::Done(Preflight::ToDo)),
        (Kind::Existing(_), []) => refused(Refusal::NoEntry(entry.clone())),
        (_, found @ [_, _, ..]) => refused(Refusal::Ambiguous {
            entry: entry.clone(),
            count: found.len(),
        }),
        (Kind::Existing(_), [target]) => {
            if target.location() == Location::RecycleBin {
                return refused(Refusal::InRecycleBin(entry.clone()));
            }
            Ok(Outcome::Done(
                match done!(attachments_present(target, staged, &mut export_attachment)?) {
                    Presence::None => Preflight::ToDo,
                    Presence::All => Preflight::AlreadyDone,
                },
            ))
        }
        (Kind::New { username, url, .. }, [target]) => {
            if holds_new_entry(target, staged, username.as_ref(), url.as_ref()).is_err() {
                return refused(Refusal::EntryExists(entry.clone()));
            }
            if staged.attachments().is_empty() {
                return Ok(Outcome::Done(Preflight::AlreadyDone));
            }
            match attachments_present(target, staged, &mut export_attachment) {
                Ok(Outcome::Done(Presence::All)) => Ok(Outcome::Done(Preflight::AlreadyDone)),
                Ok(Outcome::Done(Presence::None)) | Err(CheckError::Refused(_)) => {
                    refused(Refusal::EntryExists(entry.clone()))
                }
                Ok(Outcome::Declined) => Ok(Outcome::Declined),
                Err(error) => Err(error),
            }
        }
    }
}

/// Which of the staged attachments `target` already has.
enum Presence {
    None,
    /// Every one, byte for byte.
    All,
}

fn attachments_present<E>(
    target: &Entry,
    staged: &StagedPlan,
    export_attachment: &mut impl FnMut(&str) -> Result<Outcome<SecretBytes>, E>,
) -> Result<Outcome<Presence>, CheckError<E>> {
    let names = target.attachments().names();
    let present: Vec<&StagedAttachment> = staged
        .attachments()
        .iter()
        .filter(|attachment| names.contains(&attachment.name().as_str()))
        .collect();
    let Some(first) = present.first() else {
        return Ok(Outcome::Done(Presence::None));
    };
    if present.len() < staged.attachments().len() {
        return Err(CheckError::Refused(Refusal::PartlyThere {
            entry: staged.entry().clone(),
            name: first.name().clone(),
        }));
    }
    for attachment in present {
        if !done!(same_attachment(attachment, export_attachment)?) {
            return Err(CheckError::Refused(Refusal::AttachmentDiffers {
                entry: staged.entry().clone(),
                name: attachment.name().clone(),
            }));
        }
    }
    Ok(Outcome::Done(Presence::All))
}

fn same_attachment<E>(
    attachment: &StagedAttachment,
    export_attachment: &mut impl FnMut(&str) -> Result<Outcome<SecretBytes>, E>,
) -> Result<Outcome<bool>, CheckError<E>> {
    let held =
        export_attachment(attachment.name().as_str()).map_err(|source| CheckError::Export {
            name: attachment.name().clone(),
            source,
        })?;
    Ok(held.map(|held| held == *attachment.content().secret()))
}

/// `target` holds the fields a new entry made from `staged` has, or names the first it does not.
/// An absent username, URL or password is an empty one, as keepassxc-cli creates it.
fn holds_new_entry(
    target: &Entry,
    staged: &StagedPlan,
    username: Option<&FieldText>,
    url: Option<&EntryUrl>,
) -> Result<(), StagedItem> {
    let value = |field| {
        target
            .fields()
            .get(field)
            .map_or(&b""[..], SecretBytes::expose)
    };
    let expected = [
        (
            StandardField::Title,
            Some(staged.entry().title().as_bytes()),
            StagedItem::Title,
        ),
        (
            StandardField::UserName,
            username.map(|text| text.as_str().as_bytes()),
            StagedItem::Username,
        ),
        (
            StandardField::Url,
            url.map(|text| text.as_str().as_bytes()),
            StagedItem::Url,
        ),
        (
            StandardField::Password,
            staged.password().map(|pw| pw.content().secret().expose()),
            StagedItem::Password,
        ),
        (StandardField::Notes, None, StagedItem::Notes),
    ];
    match expected
        .into_iter()
        .find(|(field, staged, _)| value(*field) != staged.unwrap_or_default())
    {
        Some((_, _, item)) => Err(item),
        None => Ok(()),
    }
}

/// Proves that `after` is `before` with `staged` added and nothing else changed.
///
/// # Errors
/// A [`ProofError`], or the exporter's error.
pub fn prove<E>(
    before: &Database,
    after: &Database,
    staged: &StagedPlan,
    mut export_attachment: impl FnMut(&str) -> Result<Outcome<SecretBytes>, E>,
) -> Result<Outcome<()>, CheckError<E>> {
    let failed = |error| Err(CheckError::Proof(error));
    let entry = staged.entry();
    let path = entry.cli_path();
    let added: Vec<Uuid> = after
        .entries()
        .iter()
        .map(Entry::uuid)
        .filter(|uuid| before.entry(*uuid).is_none())
        .collect();
    let target_uuid = match (
        staged.kind(),
        added.as_slice(),
        before.entries_at(&path).as_slice(),
    ) {
        (Kind::New { .. }, [new], _) => *new,
        (Kind::Existing(_), [], [existing]) => existing.uuid(),
        (Kind::New { .. } | Kind::Existing(_), _, _) => {
            return failed(ProofError::NewEntries(added.len()));
        }
    };
    for old in before.entries() {
        let Some(new) = after.entry(old.uuid()) else {
            return failed(ProofError::EntryGone {
                uuid: old.uuid(),
                label: EntryLabel::of(old).path(),
            });
        };
        if old.uuid() == target_uuid {
            match only_added_to(old, new, staged) {
                Ok(()) => {}
                Err(Aspect::History) => return failed(ProofError::HistoryPruned(entry.clone())),
                Err(aspect) => return failed(changed(old, aspect)),
            }
        } else if let Err(aspect) = untouched(old, new) {
            return failed(changed(old, aspect));
        }
    }
    let target = match after.entries_at(&path).as_slice() {
        [found] if found.uuid() == target_uuid => *found,
        others => {
            return failed(ProofError::TargetNotAlone {
                entry: entry.clone(),
                count: others.len(),
            });
        }
    };
    if let Kind::New { username, url, .. } = staged.kind() {
        if let Err(item) = holds_new_entry(target, staged, username.as_ref(), url.as_ref()) {
            return failed(ProofError::Differs {
                entry: entry.clone(),
                item,
            });
        }
        if let Err(aspect) = bare(target, staged) {
            return failed(changed(target, aspect));
        }
    }
    for attachment in staged.attachments() {
        if !done!(same_attachment(attachment, &mut export_attachment)?) {
            return failed(ProofError::Differs {
                entry: entry.clone(),
                item: StagedItem::Attachment(attachment.name().clone()),
            });
        }
    }
    Ok(Outcome::Done(()))
}

fn changed(entry: &Entry, aspect: Aspect) -> ProofError {
    ProofError::EntryChanged {
        uuid: entry.uuid(),
        label: EntryLabel::of(entry).path(),
        aspect,
    }
}

// Each check below holds, or names the first aspect in which it does not.

/// `new` is `old`, for an entry the import must not touch.
fn untouched(old: &Entry, new: &Entry) -> Result<(), Aspect> {
    same_but_attachments_and_history(old, new)?;
    if old.attachments().names() != new.attachments().names() {
        return Err(Aspect::Attachments);
    }
    if old.history() != new.history() {
        return Err(Aspect::History);
    }
    Ok(())
}

/// `new` is the existing target `old` with only the staged attachments added, and the history
/// versions KeePassXC appends for each. (A new target has no old version: its UUID is one
/// `before` lacks.)
fn only_added_to(old: &Entry, new: &Entry, staged: &StagedPlan) -> Result<(), Aspect> {
    same_but_attachments_and_history(old, new)?;
    // The export refuses an entry with two attachments of one name, so sets compare them all.
    let mut expected: BTreeSet<&str> = old.attachments().names().into_iter().collect();
    expected.extend(staged.attachments().iter().map(|a| a.name().as_str()));
    let held: BTreeSet<&str> = new.attachments().names().into_iter().collect();
    if held != expected {
        return Err(Aspect::Attachments);
    }
    if !new.history().extends(old.history()) {
        return Err(Aspect::History);
    }
    Ok(())
}

fn same_but_attachments_and_history(old: &Entry, new: &Entry) -> Result<(), Aspect> {
    if old.fields() != new.fields() {
        return Err(Aspect::Fields);
    }
    if old.custom() != new.custom() {
        return Err(Aspect::Attributes);
    }
    if old.otp() != new.otp() {
        return Err(Aspect::Totp);
    }
    if old.tags() != new.tags() {
        return Err(Aspect::Tags);
    }
    if old.groups() != new.groups() {
        return Err(Aspect::Group);
    }
    if old.location() != new.location() {
        return Err(Aspect::Location);
    }
    Ok(())
}

/// A new target holds nothing but what was staged: no attributes, TOTP or tags, the staged
/// group, out of the recycle bin, the staged attachment names.
fn bare(target: &Entry, staged: &StagedPlan) -> Result<(), Aspect> {
    let wanted: BTreeSet<&str> = staged
        .attachments()
        .iter()
        .map(|a| a.name().as_str())
        .collect();
    let held: BTreeSet<&str> = target.attachments().names().into_iter().collect();
    if !target.custom().is_empty() {
        Err(Aspect::Attributes)
    } else if !matches!(target.otp(), Otp::Absent) {
        Err(Aspect::Totp)
    } else if !target.tags().as_slice().is_empty() {
        Err(Aspect::Tags)
    } else if target.groups().names() != staged.entry().groups() {
        Err(Aspect::Group)
    } else if target.location() != Location::Live {
        Err(Aspect::Location)
    } else if held != wanted {
        Err(Aspect::Attachments)
    } else {
        Ok(())
    }
}

/// Hand-written exports before and after, built from the KeePass XML format; the exporter is a
/// map from (entry path, name) to bytes. Each test changes one thing the proof must notice
/// (invariant S1), and names the check whose removal turns it red.
#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::convert::Infallible;

    use super::*;
    use crate::import::plan::{Attachment, Contents, NonEmpty, Password, Plan};
    use crate::import::staging::{AttachmentContent, EntryPassword};
    use crate::layout::SafeName;

    const GROUP: &str = "qqqqqqqqqqqqqqqqqqqqqg==";
    /// Entry UUIDs: 16 times the byte 0x11, 0x22, 0x33.
    const TARGET: &str = "EREREREREREREREREREREQ==";
    const OTHER: &str = "IiIiIiIiIiIiIiIiIiIiIg==";
    const NEW: &str = "MzMzMzMzMzMzMzMzMzMzMw==";

    fn string(key: &str, value: &str) -> String {
        format!("<String><Key>{key}</Key><Value>{value}</Value></String>")
    }

    fn history(stamps: &[&str]) -> String {
        let items: Vec<String> = stamps
            .iter()
            .map(|stamp| {
                format!(
                    "<Entry><UUID>{TARGET}</UUID><Times><LastModificationTime>{stamp}</LastModificationTime></Times></Entry>"
                )
            })
            .collect();
        format!("<History>{}</History>", items.concat())
    }

    fn attachments(names: &[&str]) -> String {
        names
            .iter()
            .map(|name| format!(r#"<Binary><Key>{name}</Key><Value Ref="0"/></Binary>"#))
            .collect::<Vec<_>>()
            .concat()
    }

    fn entry(uuid: &str, children: &[String]) -> String {
        format!("<Entry><UUID>{uuid}</UUID>{}</Entry>", children.concat())
    }

    /// A KDBX 4-style export (attachments named, no bytes) with these entries in group `Ops`.
    fn database(entries: &[String]) -> Database {
        let xml = format!(
            "<KeePassFile><Meta/><Root><Group><UUID>{GROUP}</UUID><Name>Root</Name>\
             <Group><UUID>u7u7u7u7u7u7u7u7u7u7uw==</UUID><Name>Ops</Name>{}</Group>\
             </Group></Root></KeePassFile>",
            entries.concat()
        );
        crate::export::parse(SecretBytes::copy_from(xml.as_bytes())).unwrap()
    }

    fn target(extra: &[String]) -> String {
        let mut children = vec![string("Title", "hvac"), string("Password", "p")];
        children.extend_from_slice(extra);
        entry(TARGET, &children)
    }

    fn other(extra: &[String]) -> String {
        let mut children = vec![
            string("Title", "other"),
            string("UserName", "u"),
            "<Tags>agent</Tags>".to_owned(),
        ];
        children.extend_from_slice(extra);
        entry(OTHER, &children)
    }

    /// Each attachment staged in a file named after it.
    fn staged_attachments(attachments: &[(&str, &[u8])]) -> Vec<StagedAttachment> {
        attachments
            .iter()
            .map(|(name, content)| {
                Attachment::new(
                    AttachmentName::parse(name).unwrap(),
                    SafeName::sanitise(name).unwrap(),
                    AttachmentContent::for_tests(content),
                )
            })
            .collect()
    }

    fn password(bytes: &[u8]) -> Password<EntryPassword> {
        Password::new(
            SafeName::parse("password").unwrap(),
            EntryPassword::for_tests(bytes),
        )
    }

    fn existing(attachments: &[(&str, &[u8])]) -> StagedPlan {
        existing_at("Ops/hvac", attachments)
    }

    fn existing_at(entry: &str, attachments: &[(&str, &[u8])]) -> StagedPlan {
        Plan::new(
            EntryPath::parse(entry).unwrap(),
            Kind::Existing(NonEmpty::new(staged_attachments(attachments)).unwrap()),
        )
        .unwrap()
    }

    fn new_entry(password_bytes: Option<&[u8]>, attachments: &[(&str, &[u8])]) -> StagedPlan {
        let attachments = staged_attachments(attachments);
        Plan::new(
            EntryPath::parse("Ops/new").unwrap(),
            Kind::New {
                username: Some(FieldText::parse("bob").unwrap()),
                url: None,
                contents: match password_bytes {
                    Some(bytes) => Contents::WithPassword {
                        password: password(bytes),
                        attachments,
                    },
                    None => Contents::AttachmentsOnly(NonEmpty::new(attachments).unwrap()),
                },
            },
        )
        .unwrap()
    }

    /// An exporter answering, by attachment name, from `held`, as keepassxc-cli would for the
    /// staged entry of the copy.
    fn exporter(
        held: &[(&str, &[u8])],
    ) -> impl FnMut(&str) -> Result<Outcome<SecretBytes>, Infallible> {
        let held: HashMap<String, Vec<u8>> = held
            .iter()
            .map(|(name, bytes)| ((*name).to_owned(), bytes.to_vec()))
            .collect();
        move |name| {
            Ok(Outcome::Done(SecretBytes::copy_from(
                held.get(name)
                    .unwrap_or_else(|| panic!("no attachment {name:?}")),
            )))
        }
    }

    fn proof(before: &Database, after: &Database, staged: &StagedPlan) -> Result<(), ProofError> {
        let held = [
            ("hvac22.pem", &b"PEM\0\r\n"[..]),
            ("qr.png", &b"\x89PNG"[..]),
        ];
        match prove(before, after, staged, exporter(&held)) {
            Ok(Outcome::Done(())) => Ok(()),
            Ok(Outcome::Declined) => panic!("nothing declined"),
            Err(CheckError::Proof(error)) => Err(error),
            Err(other) => panic!("not a proof failure: {other:?}"),
        }
    }

    fn pem() -> StagedPlan {
        existing(&[("hvac22.pem", b"PEM\0\r\n")])
    }

    fn before_existing() -> Database {
        database(&[
            target(&[attachments(&["old.pem"]), history(&["t1", "t2"])]),
            other(&[]),
        ])
    }

    /// What KeePassXC does for one attachment: adds it, and appends one history version.
    /// Red when the proof is stricter than that (rejects the appended version or the old
    /// attachment kept beside the new one).
    #[test]
    fn an_added_attachment_with_its_history_version_is_proven() {
        let after = database(&[
            target(&[
                attachments(&["old.pem", "hvac22.pem"]),
                history(&["t1", "t2", "t3"]),
            ]),
            other(&[]),
        ]);
        proof(&before_existing(), &after, &pem()).unwrap();
    }

    /// Red without `unchanged` for entries other than the target.
    #[test]
    fn any_change_to_another_entry_is_refused() {
        let target_after = target(&[
            attachments(&["old.pem", "hvac22.pem"]),
            history(&["t1", "t2", "t3"]),
        ]);
        let changes = [
            (string("Password", "p2"), Aspect::Fields),
            (string("Extra", "x"), Aspect::Attributes),
            (attachments(&["x.bin"]), Aspect::Attachments),
            (history(&["t9"]), Aspect::History),
        ];
        for (change, aspect) in changes {
            let after = database(&[target_after.clone(), other(&[change])]);
            let error = proof(&before_existing(), &after, &pem()).unwrap_err();
            assert!(
                matches!(error, ProofError::EntryChanged { aspect: found, .. } if found == aspect),
                "{aspect:?}: {error:?}"
            );
        }
        let retagged = database(&[
            target_after.clone(),
            entry(
                OTHER,
                &[
                    string("Title", "other"),
                    string("UserName", "u"),
                    "<Tags>ops</Tags>".to_owned(),
                ],
            ),
        ]);
        assert!(matches!(
            proof(&before_existing(), &retagged, &pem()),
            Err(ProofError::EntryChanged {
                aspect: Aspect::Tags,
                ..
            })
        ));
        let gone = database(&[target_after]);
        assert!(matches!(
            proof(&before_existing(), &gone, &pem()),
            Err(ProofError::EntryGone { .. })
        ));
    }

    /// The target may gain the staged attachments and history, nothing else. Red without the
    /// target's field comparison, its attachment-name comparison, or the history check.
    #[test]
    fn the_target_changes_only_by_the_staged_attachments_and_appended_history() {
        let cases = [
            (
                target(&[
                    string("Notes", "n"),
                    attachments(&["old.pem", "hvac22.pem"]),
                    history(&["t1", "t2", "t3"]),
                ]),
                "a field",
            ),
            (
                target(&[
                    attachments(&["old.pem", "hvac22.pem", "more"]),
                    history(&["t1", "t2", "t3"]),
                ]),
                "an extra attachment",
            ),
            (
                target(&[attachments(&["hvac22.pem"]), history(&["t1", "t2", "t3"])]),
                "an old attachment gone",
            ),
        ];
        for (after_target, what) in cases {
            let after = database(&[after_target, other(&[])]);
            let error = proof(&before_existing(), &after, &pem()).unwrap_err();
            assert!(
                matches!(error, ProofError::EntryChanged { .. }),
                "{what}: {error:?}"
            );
        }
    }

    /// KeePassXC drops the oldest history version beyond the database's limit. Red without the
    /// `extends` check, or when a dropped version is reported as something else.
    #[test]
    fn a_pruned_history_is_refused_by_name() {
        let pruned = database(&[
            target(&[
                attachments(&["old.pem", "hvac22.pem"]),
                history(&["t2", "t3"]),
            ]),
            other(&[]),
        ]);
        let error = proof(&before_existing(), &pruned, &pem()).unwrap_err();
        assert!(matches!(error, ProofError::HistoryPruned(_)), "{error:?}");
        assert!(error.to_string().contains("history"), "{error}");
    }

    /// Red when the attachment bytes are not compared with what was staged.
    #[test]
    fn a_staged_attachment_held_with_other_bytes_is_refused() {
        let after = database(&[
            target(&[
                attachments(&["old.pem", "hvac22.pem"]),
                history(&["t1", "t2", "t3"]),
            ]),
            other(&[]),
        ]);
        let staged = existing(&[("hvac22.pem", b"PEM\0\n")]);
        assert!(matches!(
            proof(&before_existing(), &after, &staged),
            Err(ProofError::Differs {
                item: StagedItem::Attachment(_),
                ..
            })
        ));
    }

    fn new_after(children: &[String]) -> String {
        let mut all = vec![
            string("Title", "new"),
            string("UserName", "bob"),
            string("Password", "secret"),
            string("URL", ""),
            string("Notes", ""),
        ];
        all.extend_from_slice(children);
        entry(NEW, &all)
    }

    /// A new entry is proven when it alone was added, holds the staged fields (an absent URL
    /// as empty), and nothing more. Red when any of those checks is dropped.
    #[test]
    fn a_new_entry_is_proven_only_as_staged() {
        let before = database(&[target(&[]), other(&[])]);
        let staged = new_entry(Some(b"secret"), &[("qr.png", b"\x89PNG")]);
        let after = |new: String| database(&[target(&[]), other(&[]), new]);
        proof(
            &before,
            &after(new_after(&[attachments(&["qr.png"])])),
            &staged,
        )
        .unwrap();

        let wrong_password = entry(
            NEW,
            &[
                string("Title", "new"),
                string("UserName", "bob"),
                string("Password", "secreT"),
                attachments(&["qr.png"]),
            ],
        );
        assert!(matches!(
            proof(&before, &after(wrong_password), &staged),
            Err(ProofError::Differs {
                item: StagedItem::Password,
                ..
            })
        ));
        let tagged = new_after(&["<Tags>agent</Tags>".to_owned(), attachments(&["qr.png"])]);
        assert!(matches!(
            proof(&before, &after(tagged), &staged),
            Err(ProofError::EntryChanged {
                aspect: Aspect::Tags,
                ..
            })
        ));
        let extra = new_after(&[attachments(&["qr.png", "x"])]);
        assert!(matches!(
            proof(&before, &after(extra), &staged),
            Err(ProofError::EntryChanged {
                aspect: Aspect::Attachments,
                ..
            })
        ));
        let two = database(&[
            target(&[]),
            other(&[]),
            new_after(&[attachments(&["qr.png"])]),
            entry("RERERERERERERERERERERA==", &[string("Title", "stray")]),
        ]);
        assert!(matches!(
            proof(&before, &two, &staged),
            Err(ProofError::NewEntries(2))
        ));
    }

    fn classify(database: &Database, staged: &StagedPlan) -> Result<Preflight, Refusal> {
        let held = [("hvac22.pem", &b"PEM\0\r\n"[..])];
        match preflight(database, staged, exporter(&held)) {
            Ok(Outcome::Done(outcome)) => Ok(outcome),
            Ok(Outcome::Declined) => panic!("nothing declined"),
            Err(CheckError::Refused(refusal)) => Err(refusal),
            Err(other) => panic!("not a refusal: {other:?}"),
        }
    }

    /// Each case of the preflight table. Red when a case is classified as another: a present
    /// attachment with other bytes as done, one of two present as to-do, a differing entry as
    /// done.
    #[test]
    fn preflight_tells_to_do_done_and_collisions_apart() {
        let plain = database(&[target(&[]), other(&[])]);
        assert_eq!(classify(&plain, &pem()).unwrap(), Preflight::ToDo);
        let with_pem = database(&[target(&[attachments(&["hvac22.pem"])]), other(&[])]);
        assert_eq!(classify(&with_pem, &pem()).unwrap(), Preflight::AlreadyDone);
        let other_bytes = existing(&[("hvac22.pem", b"PEM")]);
        assert!(matches!(
            classify(&with_pem, &other_bytes),
            Err(Refusal::AttachmentDiffers { .. })
        ));
        let two = existing(&[("hvac22.pem", b"PEM\0\r\n"), ("b.pem", b"B")]);
        assert!(matches!(
            classify(&with_pem, &two),
            Err(Refusal::PartlyThere { .. })
        ));
        let missing = existing_at("Ops/nope", &[("a", b"a")]);
        assert!(matches!(
            classify(&plain, &missing),
            Err(Refusal::NoEntry(_))
        ));
        let twice = database(&[target(&[]), entry(OTHER, &[string("Title", "hvac")])]);
        assert!(matches!(
            classify(&twice, &pem()),
            Err(Refusal::Ambiguous { count: 2, .. })
        ));

        let staged_new = new_entry(Some(b"secret"), &[]);
        assert_eq!(classify(&plain, &staged_new).unwrap(), Preflight::ToDo);
        let done = database(&[target(&[]), new_after(&[])]);
        assert_eq!(
            classify(&done, &staged_new).unwrap(),
            Preflight::AlreadyDone
        );
        let other_password = new_entry(Some(b"secreT"), &[]);
        assert!(matches!(
            classify(&done, &other_password),
            Err(Refusal::EntryExists(_))
        ));
    }

    /// Red when the recycle bin is not checked for an existing target.
    #[test]
    fn an_existing_target_in_the_recycle_bin_is_refused() {
        let xml = format!(
            "<KeePassFile><Meta><RecycleBinEnabled>True</RecycleBinEnabled>\
             <RecycleBinUUID>u7u7u7u7u7u7u7u7u7u7uw==</RecycleBinUUID></Meta>\
             <Root><Group><UUID>{GROUP}</UUID><Name>Root</Name>\
             <Group><UUID>u7u7u7u7u7u7u7u7u7u7uw==</UUID><Name>Ops</Name>{}</Group>\
             </Group></Root></KeePassFile>",
            target(&[])
        );
        let binned = crate::export::parse(SecretBytes::copy_from(xml.as_bytes())).unwrap();
        assert!(matches!(
            classify(&binned, &pem()),
            Err(Refusal::InRecycleBin(_))
        ));
    }

    /// A new entry's group must be live: the same path in the recycle bin (its own name there)
    /// is not the group. Red when the location is not checked.
    #[test]
    fn a_new_entry_whose_group_is_only_in_the_recycle_bin_is_refused() {
        let xml = format!(
            "<KeePassFile><Meta><RecycleBinEnabled>True</RecycleBinEnabled>\
             <RecycleBinUUID>u7u7u7u7u7u7u7u7u7u7uw==</RecycleBinUUID></Meta>\
             <Root><Group><UUID>{GROUP}</UUID><Name>Root</Name>\
             <Group><UUID>u7u7u7u7u7u7u7u7u7u7uw==</UUID><Name>Ops</Name></Group>\
             </Group></Root></KeePassFile>"
        );
        let binned = crate::export::parse(SecretBytes::copy_from(xml.as_bytes())).unwrap();
        assert!(matches!(
            classify(&binned, &new_entry(Some(b"secret"), &[])),
            Err(Refusal::NoGroup { .. })
        ));
    }

    /// `meta` and the groups, each `(uuid, name, entries)` below the root.
    fn database_in(meta: &str, groups: &[(&str, &str, &[String])]) -> Database {
        let groups: Vec<String> = groups
            .iter()
            .map(|(uuid, name, entries)| {
                format!(
                    "<Group><UUID>{uuid}</UUID><Name>{name}</Name>{}</Group>",
                    entries.concat()
                )
            })
            .collect();
        let xml = format!(
            "<KeePassFile><Meta>{meta}</Meta><Root><Group><UUID>{GROUP}</UUID><Name>Root</Name>\
             {}</Group></Root></KeePassFile>",
            groups.concat()
        );
        crate::export::parse(SecretBytes::copy_from(xml.as_bytes())).unwrap()
    }

    /// A new entry keepassxc-cli finds at the staged path but in another group (one whose name
    /// holds the `/`), or put into the recycle bin, is not what was asked for. Red without the
    /// group arm or the location arm of `not_bare`.
    #[test]
    fn a_new_entry_in_another_group_or_the_recycle_bin_is_refused() {
        const OPS: &str = "u7u7u7u7u7u7u7u7u7u7uw==";
        let staged = Plan::new(
            EntryPath::parse("Ops/sub/new").unwrap(),
            Kind::New {
                username: Some(FieldText::parse("bob").unwrap()),
                url: None,
                contents: Contents::WithPassword {
                    password: password(b"secret"),
                    attachments: Vec::new(),
                },
            },
        )
        .unwrap();
        let before = database_in("", &[("RERERERERERERERERERERA==", "Ops/sub", &[])]);
        let after = database_in(
            "",
            &[("RERERERERERERERERERERA==", "Ops/sub", &[new_after(&[])])],
        );
        assert!(
            matches!(
                proof(&before, &after, &staged),
                Err(ProofError::EntryChanged {
                    aspect: Aspect::Group,
                    ..
                })
            ),
            "{:?}",
            proof(&before, &after, &staged)
        );

        let bin = format!(
            "<RecycleBinEnabled>True</RecycleBinEnabled><RecycleBinUUID>{OPS}</RecycleBinUUID>"
        );
        let staged = new_entry(Some(b"secret"), &[]);
        let before = database_in(&bin, &[(OPS, "Ops", &[])]);
        let after = database_in(&bin, &[(OPS, "Ops", &[new_after(&[])])]);
        assert!(matches!(
            proof(&before, &after, &staged),
            Err(ProofError::EntryChanged {
                aspect: Aspect::Location,
                ..
            })
        ));
    }

    /// A `YubiKey` notice closed while an attachment is compared ends the check as declined,
    /// neither passed nor failed. Red when a declined export is taken as a mismatch or a match.
    #[test]
    fn a_declined_export_ends_the_check_as_declined() {
        let declined = |_: &str| Ok::<_, Infallible>(Outcome::Declined);
        let with_pem = database(&[target(&[attachments(&["hvac22.pem"])]), other(&[])]);
        assert!(matches!(
            preflight(&with_pem, &pem(), declined),
            Ok(Outcome::Declined)
        ));
        let after = database(&[
            target(&[
                attachments(&["old.pem", "hvac22.pem"]),
                history(&["t1", "t2", "t3"]),
            ]),
            other(&[]),
        ]);
        assert!(matches!(
            prove(&before_existing(), &after, &pem(), declined),
            Ok(Outcome::Declined)
        ));
    }
}
