//! Integration test for the typed `HermesError` variants surfaced at
//! `HbcFile::parse`. Locks the variant shape a downstream
//! `droidsaw/src/error.rs :: classify()` downcast pattern-matches on —
//! tests here guard the typed API contract, not the parser itself.
//!
//! Synthesized inputs only; no fixture dependency. `HbcFile` itself
//! doesn't implement Debug, so each test unwraps Ok/Err manually rather
//! than using `Result::expect_err`.

use droidsaw_hermes::error::HermesError;
use droidsaw_hermes::parser::HbcFile;

fn err_from_parse(buf: &[u8]) -> HermesError {
    match HbcFile::parse(buf, None) {
        Ok(_) => panic!("parser accepted an input that should have errored"),
        Err(e) => e,
    }
}

#[test]
fn empty_buffer_surfaces_header_too_small() {
    let err = err_from_parse(&[]);
    assert!(
        matches!(err, HermesError::HeaderTooSmall { got: 0 }),
        "expected HeaderTooSmall {{ got: 0 }}, got {err:?}"
    );
}

#[test]
fn sub_header_buffer_surfaces_header_too_small_with_length() {
    let buf = vec![0u8; 64]; // less than the 128-byte header
    let err = err_from_parse(&buf);
    assert!(
        matches!(err, HermesError::HeaderTooSmall { got: 64 }),
        "expected HeaderTooSmall {{ got: 64 }}, got {err:?}"
    );
}

#[test]
fn bad_magic_surfaces_invalid_magic_with_bytes() {
    // Fill to the 128-byte header so we pass the HeaderTooSmall gate and
    // land on the magic check. First 8 bytes = the bad magic.
    let mut buf = vec![0u8; 128];
    buf[..8].copy_from_slice(b"NOTHERMS");
    let err = err_from_parse(&buf);
    match err {
        HermesError::InvalidMagic { found } => {
            assert_eq!(
                &found, b"NOTHERMS",
                "variant must carry the bad bytes for triage"
            );
        }
        other => panic!("expected InvalidMagic {{ found: \"NOTHERMS\" }}, got {other:?}"),
    }
}

#[test]
fn bad_magic_surfaces_invalid_magic_with_bytes_insta() {
    // Risk: LOW — test-only proof-of-concept; no production-code change.
    let mut buf = vec![0u8; 128];
    buf[..8].copy_from_slice(b"NOTHERMS");
    let err = err_from_parse(&buf);
    insta::assert_debug_snapshot!(err);
}

// ── overflow_string_count > string_count cross-validation ──────────────────
//
// HBC format invariant: overflow string entries are a sub-pool of the main
// string pool, so overflow_string_count <= string_count must hold.
// A typed-Err gate fires at the point where both counts are projected
// from the header, before any section/bound_count work.
//
// Synthesized v96 header layout (128 bytes):
//   offset  0-7  : HBC magic (0x1F1903C103BC1FC6, LE)
//   offset  8-11 : version = 96 (0x60)
//   offset 32-35 : file_length = 128 (matches buf.len() → no Finding noise)
//   offset 52-55 : string_count = 0
//   offset 56-59 : overflow_string_count = 1   ← impossible
//
// All other fields remain zero. Version 96 → V87to96Header layout.

fn valid_v96_header_with_overflow_exceeds_string() -> Vec<u8> {
    // Start with a zeroed 128-byte buffer.
    let mut buf = vec![0u8; 128];

    // Magic: 0x1F1903C103BC1FC6 in little-endian
    buf[..8].copy_from_slice(&[0xc6, 0x1f, 0xbc, 0x03, 0xc1, 0x03, 0x19, 0x1f]);

    // Version = 96 at offset 8
    buf[8..12].copy_from_slice(&96u32.to_le_bytes());

    // file_length = 128 at offset 32 (avoids FileLengthDisagreement Finding noise)
    buf[32..36].copy_from_slice(&128u32.to_le_bytes());

    // string_count = 0 at offset 52 (already zero, explicit for clarity)
    buf[52..56].copy_from_slice(&0u32.to_le_bytes());

    // overflow_string_count = 1 at offset 56 — the impossible case
    buf[56..60].copy_from_slice(&1u32.to_le_bytes());

    buf
}

#[test]
fn overflow_string_count_exceeds_string_count_surfaces_typed_error() {
    let buf = valid_v96_header_with_overflow_exceeds_string();
    let err = err_from_parse(&buf);
    match err {
        HermesError::OverflowStringCountExceedsStringCount {
            overflow: 1,
            total: 0,
        } => {}
        other => panic!(
            "expected OverflowStringCountExceedsStringCount {{ overflow: 1, total: 0 }}, \
             got {other:?}"
        ),
    }
}

#[test]
fn overflow_string_count_equal_to_string_count_is_accepted() {
    // Boundary: overflow_string_count == string_count is valid (all strings overflow).
    let mut buf = valid_v96_header_with_overflow_exceeds_string();
    // Set string_count = 1 at offset 52 → now overflow(1) == total(1), must accept.
    buf[52..56].copy_from_slice(&1u32.to_le_bytes());
    // Parser will reject on SectionExceedsBounds or similar for the zero-length
    // file — we only need to confirm it does NOT reject with
    // OverflowStringCountExceedsStringCount.
    if let Err(HermesError::OverflowStringCountExceedsStringCount { .. }) = HbcFile::parse(&buf, None) {
        panic!(
            "overflow_string_count == string_count must be accepted by the \
             cross-validation gate"
        );
    }
}
