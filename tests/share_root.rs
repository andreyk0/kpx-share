//! I1: nothing secret is written outside a tmpfs, decided before unlocking.
//!
//! Method: build `ShareRoot` on real directories, one on tmpfs (`$XDG_RUNTIME_DIR`) and one on the
//! build directory's disk, and on the shapes a careless setup produces (symlink, loose mode,
//! someone else's file). Each refusal is checked by its error variant, and by the disk being left
//! as it was.

mod common;

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};

use common::share::{mode, scratch_on_disk, scratch_on_tmpfs};
use kpx_share::layout::{DirError, RootError, ShareRoot};
use kpx_share::mountinfo::Filesystem;

#[test]
fn accepts_and_creates_a_private_directory_on_tmpfs() {
    let scratch = scratch_on_tmpfs();
    let path = scratch.path().join("kpx-share");

    let root = ShareRoot::at(&path).unwrap();

    assert_eq!(root.path(), fs::canonicalize(&path).unwrap());
    assert_eq!(mode(&path), 0o700);
    // An existing 0700 directory is accepted as it is.
    assert!(ShareRoot::at(&path).is_ok());
}

/// Red when `require_tmpfs` accepts every filesystem.
#[test]
fn refuses_a_directory_on_disk_and_creates_nothing() {
    let scratch = scratch_on_disk();
    let path = scratch.path().join("kpx-share");

    let error = ShareRoot::at(&path).unwrap_err();

    match &error {
        RootError::NotTmpfs { filesystem, .. } => {
            assert_ne!(*filesystem, Filesystem::Tmpfs);
            let message = error.to_string();
            assert!(message.contains(&filesystem.to_string()), "{message}");
            assert!(message.contains("kpx-share"), "{message}");
        }
        other => panic!("expected NotTmpfs, got {other:?}"),
    }
    assert!(!path.exists(), "a refused root must not be created");
}

/// An existing directory on disk is refused too, not only a missing one.
#[test]
fn refuses_an_existing_private_directory_on_disk() {
    let scratch = scratch_on_disk();
    let path = scratch.path().join("kpx-share");
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();

    assert!(matches!(
        ShareRoot::at(&path),
        Err(RootError::NotTmpfs { .. })
    ));
}

#[test]
fn refuses_a_symlink_even_to_a_good_directory() {
    let scratch = scratch_on_tmpfs();
    let real = scratch.path().join("real");
    fs::create_dir(&real).unwrap();
    fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).unwrap();
    let link = scratch.path().join("kpx-share");
    symlink(&real, &link).unwrap();

    assert!(matches!(
        ShareRoot::at(&link),
        Err(RootError::Dir(DirError::Symlink { .. }))
    ));
}

#[test]
fn refuses_group_or_other_bits_and_does_not_chmod() {
    let scratch = scratch_on_tmpfs();
    let path = scratch.path().join("kpx-share");
    fs::create_dir(&path).unwrap();
    for loose in [0o755, 0o710, 0o701, 0o770, 0o2700, 0o1700] {
        fs::set_permissions(&path, fs::Permissions::from_mode(loose)).unwrap();
        assert!(
            matches!(
                ShareRoot::at(&path),
                Err(RootError::Dir(DirError::WrongMode { .. }))
            ),
            "{loose:o}"
        );
        assert_eq!(mode(&path), loose, "the directory is left alone");
    }
}

#[test]
fn refuses_a_regular_file_and_a_relative_path() {
    let scratch = scratch_on_tmpfs();
    let file = scratch.path().join("kpx-share");
    fs::write(&file, b"").unwrap();

    assert!(matches!(
        ShareRoot::at(&file),
        Err(RootError::Dir(DirError::NotDirectory { .. }))
    ));
    assert!(matches!(
        ShareRoot::at("kpx-share".as_ref()),
        Err(RootError::NotAbsolute(_))
    ));
}
