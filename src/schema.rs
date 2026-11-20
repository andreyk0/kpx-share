//! The version marker of a stored file, shared by `meta.json` and `.session.json`.
//!
//! Both follow one convention. The stored shape is a private `*File` struct that derives serde
//! and carries a [`SchemaVersion`]; the domain type is a different struct, built from the file by
//! `TryFrom` where the file is loaded and turned back into one by `From` where it is saved. A file
//! of another version, with an unknown key or with values the domain type refuses is a parse
//! failure at the load, never something the rest of the code meets.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// The schema version `CURRENT` of a stored file: a unit type that serialises as the number and
/// deserialises only from it, so a file from a different schema is a parse failure rather than a
/// misreading.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SchemaVersion<const CURRENT: u32>;

impl<const CURRENT: u32> Serialize for SchemaVersion<CURRENT> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u32(CURRENT)
    }
}

impl<'de, const CURRENT: u32> Deserialize<'de> for SchemaVersion<CURRENT> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let found = u32::deserialize(deserializer)?;
        if found == CURRENT {
            Ok(Self)
        } else {
            Err(serde::de::Error::custom(format!(
                "unsupported version {found}, this build reads {CURRENT}"
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_current_version_is_read_and_it_is_written_as_a_number() {
        assert_eq!(serde_json::to_string(&SchemaVersion::<3>).unwrap(), "3");
        assert_eq!(
            serde_json::from_str::<SchemaVersion<3>>("3").unwrap(),
            SchemaVersion
        );
        for other in ["2", "4", "0", "\"3\""] {
            assert!(
                serde_json::from_str::<SchemaVersion<3>>(other).is_err(),
                "{other}"
            );
        }
    }
}
