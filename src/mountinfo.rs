//! Which filesystem a path lives on, read from `/proc/self/mountinfo`.
//!
//! The format is `proc(5)`: each line is
//! `id parent major:minor root mount-point options [optional…] - fstype source super-options`,
//! with space, tab, newline and backslash in the mount point written as `\040`, `\011`, `\012`
//! and `\134`.

use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};

/// The filesystem type that matters here: only tmpfs keeps a secret off disk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Filesystem {
    Tmpfs,
    Other(String),
}

impl Filesystem {
    fn parse(fstype: &str) -> Self {
        match fstype {
            "tmpfs" => Self::Tmpfs,
            other => Self::Other(other.to_owned()),
        }
    }
}

impl std::fmt::Display for Filesystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tmpfs => f.write_str("tmpfs"),
            Self::Other(fstype) => f.write_str(fstype),
        }
    }
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum MountInfoError {
    #[error("mountinfo line {line} is malformed: {reason}")]
    Malformed { line: usize, reason: &'static str },
    #[error("no mount in mountinfo contains {}", .0.display())]
    NoMount(PathBuf),
}

struct Mount {
    point: PathBuf,
    filesystem: Filesystem,
}

/// The filesystem of the mount whose mount point is the longest prefix of `path`; when two mounts
/// share that mount point the later line wins, since it is mounted over the earlier one.
///
/// `path` must be canonical: a symlink on the way would make the prefix test name the wrong mount.
///
/// # Errors
/// A line of `mountinfo` does not parse (refusing beats guessing which filesystem it names), or no
/// mount contains `path`.
pub fn filesystem_of(mountinfo: &str, path: &Path) -> Result<Filesystem, MountInfoError> {
    let mut best: Option<Mount> = None;
    for (index, line) in mountinfo.lines().enumerate() {
        let mount = parse_line(line).map_err(|reason| MountInfoError::Malformed {
            line: index + 1,
            reason,
        })?;
        let deeper_or_equal = best.as_ref().is_none_or(|current| {
            mount.point.components().count() >= current.point.components().count()
        });
        if path.starts_with(&mount.point) && deeper_or_equal {
            best = Some(mount);
        }
    }
    best.map(|mount| mount.filesystem)
        .ok_or_else(|| MountInfoError::NoMount(path.to_owned()))
}

fn parse_line(line: &str) -> Result<Mount, &'static str> {
    const MOUNT_POINT_FIELD: usize = 4;
    const FIRST_OPTIONAL_FIELD: usize = 6;
    let fields: Vec<&str> = line.split(' ').collect();
    let point = fields
        .get(MOUNT_POINT_FIELD)
        .ok_or("fewer than five fields")?;
    let separator = fields
        .iter()
        .skip(FIRST_OPTIONAL_FIELD)
        .position(|field| *field == "-")
        .map(|offset| offset + FIRST_OPTIONAL_FIELD)
        .ok_or("no ` - ` separator")?;
    let fstype = fields
        .get(separator + 1)
        .filter(|fstype| !fstype.is_empty())
        .ok_or("no filesystem type after the separator")?;
    Ok(Mount {
        point: PathBuf::from(OsString::from_vec(unescape(point)?)),
        filesystem: Filesystem::parse(fstype),
    })
}

/// Decodes `\NNN` (three octal digits) escapes; any other backslash is malformed.
fn unescape(field: &str) -> Result<Vec<u8>, &'static str> {
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut rest = bytes;
    while let Some((&byte, tail)) = rest.split_first() {
        if byte != b'\\' {
            out.push(byte);
            rest = tail;
            continue;
        }
        let digits = tail.get(..3).ok_or("truncated octal escape")?;
        let value = digits.iter().try_fold(0u32, |acc, digit| match digit {
            b'0'..=b'7' => Ok(acc * 8 + u32::from(digit - b'0')),
            _ => Err("non-octal digit in escape"),
        })?;
        out.push(u8::try_from(value).map_err(|_| "octal escape above 255")?);
        rest = tail.get(3..).ok_or("truncated octal escape")?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MOUNTINFO: &str = "\
25 1 0:22 / / rw,relatime shared:1 - btrfs /dev/nvme0n1p2 rw,subvolid=5
30 25 0:25 / /run rw,nosuid shared:2 - tmpfs tmpfs rw,mode=755
31 30 0:40 / /run/user/1000 rw,nosuid shared:3 - tmpfs tmpfs rw,size=1638400k
32 25 0:50 / /mnt/with\\040space rw - tmpfs tmpfs rw
33 25 0:51 / /mnt/back\\134slash rw - ext4 /dev/sda1 rw
34 31 0:52 / /run/user/1000/doc rw,relatime - fuse.portal portal rw
";

    fn fs(path: &str) -> Result<Filesystem, MountInfoError> {
        filesystem_of(MOUNTINFO, Path::new(path))
    }

    #[test]
    fn longest_mount_point_wins() {
        assert_eq!(fs("/run/user/1000/kpx-share"), Ok(Filesystem::Tmpfs));
        assert_eq!(
            fs("/home/a/kpx-share"),
            Ok(Filesystem::Other("btrfs".into()))
        );
        assert_eq!(
            fs("/run/user/1000/doc/x"),
            Ok(Filesystem::Other("fuse.portal".into()))
        );
    }

    #[test]
    fn a_mount_point_is_a_component_prefix_not_a_string_prefix() {
        // `/mnt/with space2` is not below the mount at `/mnt/with space`.
        assert_eq!(
            fs("/mnt/with space/x"),
            Ok(Filesystem::Tmpfs),
            "escape decoded"
        );
        assert_eq!(
            fs("/mnt/with space2/x"),
            Ok(Filesystem::Other("btrfs".into()))
        );
    }

    #[test]
    fn escapes_decode_to_bytes() {
        assert_eq!(fs("/mnt/back\\slash"), Ok(Filesystem::Other("ext4".into())));
        assert_eq!(unescape("a\\040b\\011\\012"), Ok(b"a b\t\n".to_vec()));
    }

    #[test]
    fn malformed_input_is_an_error_not_a_guess() {
        assert_eq!(
            unescape("a\\04"),
            Err("truncated octal escape"),
            "short escape"
        );
        assert_eq!(unescape("a\\089"), Err("non-octal digit in escape"));
        assert_eq!(unescape("\\777"), Err("octal escape above 255"));
        let broken = "1 2 3:4 / /x rw no-separator tmpfs tmpfs rw\n";
        assert_eq!(
            filesystem_of(broken, Path::new("/x")),
            Err(MountInfoError::Malformed {
                line: 1,
                reason: "no ` - ` separator"
            })
        );
        assert_eq!(
            filesystem_of("", Path::new("/x")),
            Err(MountInfoError::NoMount("/x".into()))
        );
    }

    #[test]
    fn a_later_mount_over_the_same_point_wins() {
        let stacked = "1 0 0:1 / /srv rw - ext4 a rw\n2 1 0:2 / /srv rw - tmpfs b rw\n";
        assert_eq!(
            filesystem_of(stacked, Path::new("/srv/x")),
            Ok(Filesystem::Tmpfs)
        );
    }
}
