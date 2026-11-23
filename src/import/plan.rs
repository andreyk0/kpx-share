//! The shape of an import, the same before its files are read and after: which entry, whether it
//! is new, and what it gets, each secret by the staged file it is in. `P` is what a password
//! holds and `A` what an attachment holds: nothing yet in the manifest, their bytes once read.
//!
//! What a valid import is lives in these types rather than in a check: a new entry gets a
//! password and any attachments, or no password and at least one attachment; an existing entry
//! gets at least one attachment, and nothing else. [`Plan::new`], the one constructor, refuses an
//! attachment name or a file named twice; [`Plan::try_map`] changes only what the leaves hold,
//! never their names or files, so every plan keeps that.

use std::collections::BTreeSet;
use std::fmt;

use super::manifest::{AttachmentName, EntryPath, EntryUrl, FieldText, MANIFEST_FILE};
use crate::layout::SafeName;

/// A list with at least one item; built only by [`NonEmpty::new`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NonEmpty<T>(Vec<T>);

impl<T> NonEmpty<T> {
    /// `None` when `items` is empty.
    #[must_use]
    pub fn new(items: Vec<T>) -> Option<Self> {
        (!items.is_empty()).then_some(Self(items))
    }

    #[must_use]
    pub fn as_slice(&self) -> &[T] {
        &self.0
    }

    /// Each item through `map`, in order; as many items come out as went in.
    fn try_map<U, E>(self, map: impl FnMut(T) -> Result<U, E>) -> Result<NonEmpty<U>, E> {
        self.0
            .into_iter()
            .map(map)
            .collect::<Result<_, _>>()
            .map(NonEmpty)
    }
}

/// A new entry's password, staged in `file`.
#[derive(Debug)]
pub struct Password<P> {
    file: SafeName,
    content: P,
}

impl<P> Password<P> {
    #[must_use]
    pub fn new(file: SafeName, content: P) -> Self {
        Self { file, content }
    }

    #[must_use]
    pub fn file(&self) -> &SafeName {
        &self.file
    }

    #[must_use]
    pub fn content(&self) -> &P {
        &self.content
    }
}

/// An attachment called `name` in KeePassXC, staged in `file`.
#[derive(Debug)]
pub struct Attachment<A> {
    name: AttachmentName,
    file: SafeName,
    content: A,
}

impl<A> Attachment<A> {
    #[must_use]
    pub fn new(name: AttachmentName, file: SafeName, content: A) -> Self {
        Self {
            name,
            file,
            content,
        }
    }

    #[must_use]
    pub fn name(&self) -> &AttachmentName {
        &self.name
    }

    #[must_use]
    pub fn file(&self) -> &SafeName {
        &self.file
    }

    #[must_use]
    pub fn content(&self) -> &A {
        &self.content
    }
}

/// What a new entry holds.
#[derive(Debug)]
pub enum Contents<P, A> {
    WithPassword {
        password: Password<P>,
        attachments: Vec<Attachment<A>>,
    },
    /// Its password is empty.
    AttachmentsOnly(NonEmpty<Attachment<A>>),
}

#[derive(Debug)]
pub enum Kind<P, A> {
    New {
        username: Option<FieldText>,
        url: Option<EntryUrl>,
        contents: Contents<P, A>,
    },
    Existing(NonEmpty<Attachment<A>>),
}

/// What a staged file is for: how errors name it, since the password's file name is never shown.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Role {
    Manifest,
    Password,
    Attachment(AttachmentName),
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Manifest => f.write_str(MANIFEST_FILE),
            Self::Password => f.write_str("the password"),
            Self::Attachment(name) => write!(f, "attachment {:?}", name.as_str()),
        }
    }
}

/// Why the parts given to [`Plan::new`] are not one import.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum PlanError {
    #[error("attachment {:?} is named twice", .0.as_str())]
    AttachmentNamedTwice(AttachmentName),
    #[error("the file of {0} is named for something else too")]
    FileNamedTwice(Role),
}

/// One import into `entry`: no attachment name, and no file, twice.
#[derive(Debug)]
pub struct Plan<P, A> {
    entry: EntryPath,
    kind: Kind<P, A>,
}

impl<P, A> Plan<P, A> {
    /// # Errors
    /// Two attachments have one name, or two leaves one file.
    pub fn new(entry: EntryPath, kind: Kind<P, A>) -> Result<Self, PlanError> {
        let plan = Self { entry, kind };
        let mut names = BTreeSet::new();
        for attachment in plan.attachments() {
            if !names.insert(attachment.name()) {
                return Err(PlanError::AttachmentNamedTwice(attachment.name().clone()));
            }
        }
        let mut files = BTreeSet::new();
        for (role, file) in plan.files() {
            if !files.insert(file) {
                return Err(PlanError::FileNamedTwice(role));
            }
        }
        Ok(plan)
    }

    #[must_use]
    pub fn entry(&self) -> &EntryPath {
        &self.entry
    }

    #[must_use]
    pub fn kind(&self) -> &Kind<P, A> {
        &self.kind
    }

    /// The new entry's password; none for an existing entry, or a new one without.
    #[must_use]
    pub fn password(&self) -> Option<&Password<P>> {
        match &self.kind {
            Kind::New {
                contents: Contents::WithPassword { password, .. },
                ..
            } => Some(password),
            Kind::New {
                contents: Contents::AttachmentsOnly(_),
                ..
            }
            | Kind::Existing(_) => None,
        }
    }

    /// Every attachment, in the manifest's order.
    #[must_use]
    pub fn attachments(&self) -> &[Attachment<A>] {
        match &self.kind {
            Kind::New {
                contents: Contents::WithPassword { attachments, .. },
                ..
            } => attachments,
            Kind::New {
                contents: Contents::AttachmentsOnly(attachments),
                ..
            }
            | Kind::Existing(attachments) => attachments.as_slice(),
        }
    }

    /// Every file the plan names and what it is for, the password's first.
    #[must_use]
    pub fn files(&self) -> Vec<(Role, &SafeName)> {
        self.password()
            .map(|password| (Role::Password, password.file()))
            .into_iter()
            .chain(self.attachments().iter().map(|attachment| {
                (
                    Role::Attachment(attachment.name().clone()),
                    attachment.file(),
                )
            }))
            .collect()
    }

    /// The same import with each leaf's content mapped, the password first, then the attachments
    /// in order; names, files and shape stay.
    ///
    /// # Errors
    /// The first error either map returns.
    pub fn try_map<P2, A2, E>(
        self,
        password: impl FnOnce(&SafeName, P) -> Result<P2, E>,
        mut attachment: impl FnMut(&AttachmentName, &SafeName, A) -> Result<A2, E>,
    ) -> Result<Plan<P2, A2>, E> {
        let mut map_attachment = |leaf: Attachment<A>| {
            let content = attachment(&leaf.name, &leaf.file, leaf.content)?;
            Ok(Attachment {
                name: leaf.name,
                file: leaf.file,
                content,
            })
        };
        let kind = match self.kind {
            Kind::New {
                username,
                url,
                contents,
            } => Kind::New {
                username,
                url,
                contents: match contents {
                    Contents::WithPassword {
                        password: leaf,
                        attachments,
                    } => {
                        let content = password(&leaf.file, leaf.content)?;
                        Contents::WithPassword {
                            password: Password {
                                file: leaf.file,
                                content,
                            },
                            attachments: attachments
                                .into_iter()
                                .map(&mut map_attachment)
                                .collect::<Result<_, _>>()?,
                        }
                    }
                    Contents::AttachmentsOnly(attachments) => {
                        Contents::AttachmentsOnly(attachments.try_map(&mut map_attachment)?)
                    }
                },
            },
            Kind::Existing(attachments) => Kind::Existing(attachments.try_map(map_attachment)?),
        };
        Ok(Plan {
            entry: self.entry,
            kind,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(text: &str) -> AttachmentName {
        AttachmentName::parse(text).unwrap()
    }

    fn file(text: &str) -> SafeName {
        SafeName::parse(text).unwrap()
    }

    fn existing(attachments: Vec<Attachment<()>>) -> Result<Plan<(), ()>, PlanError> {
        Plan::new(
            EntryPath::parse("G/T").unwrap(),
            Kind::Existing(NonEmpty::new(attachments).unwrap()),
        )
    }

    /// The constructor is the uniqueness witness: a name or a file twice is refused, and the
    /// password's file counts. Red when either check is dropped.
    #[test]
    fn a_plan_names_no_attachment_and_no_file_twice() {
        assert_eq!(
            existing(vec![
                Attachment::new(name("a"), file("f"), ()),
                Attachment::new(name("a"), file("g"), ()),
            ])
            .unwrap_err(),
            PlanError::AttachmentNamedTwice(name("a"))
        );
        assert_eq!(
            existing(vec![
                Attachment::new(name("a"), file("f"), ()),
                Attachment::new(name("b"), file("f"), ()),
            ])
            .unwrap_err(),
            PlanError::FileNamedTwice(Role::Attachment(name("b")))
        );
        let with_password = Plan::new(
            EntryPath::parse("G/T").unwrap(),
            Kind::New {
                username: None,
                url: None,
                contents: Contents::WithPassword {
                    password: Password::new(file("f"), ()),
                    attachments: vec![Attachment::new(name("a"), file("f"), ())],
                },
            },
        );
        assert_eq!(
            with_password.unwrap_err(),
            PlanError::FileNamedTwice(Role::Attachment(name("a")))
        );
    }

    /// A map changes what the leaves hold and nothing else. Red when it drops or reorders one.
    #[test]
    fn try_map_keeps_names_files_and_order() {
        let plan = existing(vec![
            Attachment::new(name("b"), file("g"), ()),
            Attachment::new(name("a"), file("f"), ()),
        ])
        .unwrap();
        let mapped = plan
            .try_map(
                |_, ()| Ok::<_, ()>(0),
                |name, file, ()| Ok(format!("{name}:{file}")),
            )
            .unwrap();
        let leaves: Vec<_> = mapped
            .attachments()
            .iter()
            .map(|a| (a.name().as_str(), a.file().as_str(), a.content().as_str()))
            .collect();
        assert_eq!(leaves, [("b", "g", "b:g"), ("a", "f", "a:f")]);
    }
}
