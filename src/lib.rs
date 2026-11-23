//! kpx-share: put one KeePassXC entry into an AI agent's session as plain files on tmpfs, and
//! write what an agent staged into the database.
//!
//! The library holds everything the binary does, so integration tests can drive it.
//!
//! The pipeline: [`export::parse`] the decrypted XML into a [`Database`], list
//! [`Database::picker_items`], [`Database::pick`] one under an [`Eligibility`] rule, and
//! [`Eligible::resolve`] it into the [`ResolvedEntry`] that gets written out.
//!
//! Around it: [`session`] says which session the entry goes into and when that ends, [`add`]
//! runs the whole flow in the order that keeps secrets off disk, [`watch`] deletes the session
//! when it ends, [`manage`] lists, removes and cleans up, and [`cli`] is the command line.
//! [`import`] is the one command that writes the database: it adds what an agent staged on tmpfs,
//! and proves the result before it replaces the file.

pub mod add;
pub mod assuan;
pub mod cli;
pub mod export;
pub mod harden;
pub mod import;
pub mod launch;
pub mod layout;
pub mod manage;
pub mod meta;
pub mod mode;
pub mod model;
pub mod mountinfo;
pub mod otp;
pub mod pick;
mod placeholder;
pub mod process;
mod schema;
pub mod secret;
pub mod select;
pub mod session;
pub mod subprocess;
mod text;
pub mod tools;
pub mod unlock;
pub mod watch;
pub mod writer;

pub use export::ExportError;
pub use model::{Database, Entry};
pub use secret::SecretBytes;
pub use select::{Eligibility, Eligible, EntryLabel, PickerItem, RequiredTag, ResolvedEntry};
