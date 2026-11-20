//! Observes that no secret is left in freed memory.
//!
//! A global allocator scans every block as it is freed for a marker string planted in the XML
//! input. The marker sits in a password, in a value another entry references (so resolution
//! copies it), and in a TOTP seed (so the URI renderer copies it). If the input buffer, or any
//! intermediate copy made while importing, resolving and dropping, is freed without being wiped,
//! the scan finds the marker. A positive control proves the scan sees an unwiped buffer.
//!
//! One `#[test]` only: the allocator is process-wide, and other tests' allocations would race.

#![allow(unsafe_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use kpx_share::{Eligibility, SecretBytes, import};

const MARKER: &[u8] = b"ZEROIZE-MARKER-7f3a9c";

static ARMED: AtomicBool = AtomicBool::new(false);
static MARKED_FREES: AtomicUsize = AtomicUsize::new(0);

struct ScanOnFree;

// SAFETY: every call forwards to `System` with the caller's arguments; `dealloc` only reads the
// block it is about to free, which is still allocated and `layout.size()` bytes long.
unsafe impl GlobalAlloc for ScanOnFree {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ARMED.load(Ordering::SeqCst) {
            let block = unsafe { std::slice::from_raw_parts(ptr, layout.size()) };
            if block.windows(MARKER.len()).any(|window| window == MARKER) {
                MARKED_FREES.fetch_add(1, Ordering::SeqCst);
            }
        }
        unsafe { System.dealloc(ptr, layout) }
    }
    // `realloc` is the trait default: alloc, copy, then `dealloc` above, so the old block of a
    // growing buffer is scanned too.
}

#[global_allocator]
static ALLOCATOR: ScanOnFree = ScanOnFree;

fn xml() -> Vec<u8> {
    let marker = std::str::from_utf8(MARKER).unwrap();
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<KeePassFile><Meta/><Root><Group><UUID>qqqqqqqqqqqqqqqqqqqqqg==</UUID><Name>Root</Name>
<Entry><UUID>EREREREREREREREREREREQ==</UUID><Tags>agent</Tags>
<String><Key>Title</Key><Value>Target</Value></String>
<String><Key>Password</Key><Value>a &amp; {marker} &lt; b</Value></String>
</Entry>
<Entry><UUID>IiIiIiIiIiIiIiIiIiIiIg==</UUID><Tags>agent</Tags>
<String><Key>Title</Key><Value>Referrer</Value></String>
<String><Key>Password</Key><Value>{{REF:P@I:11111111111111111111111111111111}}</Value></String>
<String><Key>TOTP Seed</Key><Value>{marker}</Value></String>
</Entry>
</Group></Root></KeePassFile>"#
    )
    .into_bytes()
}

#[test]
fn no_secret_reaches_freed_memory() {
    // Positive control: an unwiped buffer holding the marker is seen when freed.
    ARMED.store(true, Ordering::SeqCst);
    drop(std::hint::black_box(MARKER.to_vec()));
    ARMED.store(false, Ordering::SeqCst);
    assert_eq!(
        MARKED_FREES.swap(0, Ordering::SeqCst),
        1,
        "the scan sees frees"
    );

    let input = SecretBytes::from_vec(xml());
    ARMED.store(true, Ordering::SeqCst);
    {
        let database = import(input).unwrap();
        let resolved = database
            .pick(
                kpx_share::model::Uuid::parse_hex("22222222222222222222222222222222").unwrap(),
                Eligibility::Any,
            )
            .unwrap()
            .resolve();
        // The marker really was copied through resolution and TOTP rendering.
        let password = resolved
            .fields()
            .get(kpx_share::model::StandardField::Password)
            .unwrap();
        assert!(password.expose().windows(MARKER.len()).any(|w| w == MARKER));
        assert!(matches!(resolved.otp(), kpx_share::otp::Otp::Present(_)));
    }
    ARMED.store(false, Ordering::SeqCst);
    assert_eq!(MARKED_FREES.load(Ordering::SeqCst), 0);
}
