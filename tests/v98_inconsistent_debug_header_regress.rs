//! Regression: v98 `parse → emit_hbc_v98 → parse` round-trip on an
//! adversarial input whose `debug_info_offset` points INTO the file
//! header (overlap with [0, HEADER_SIZE)). Without the structural
//! guard, the second parse returns `InconsistentDebugHeader {
//! lexical_data_offset: 349, debug_data_size: 0 }` because the
//! parser's 20-byte DebugInfoHeader reads `file_length` (which emit
//! recomputes) as `lexical_data_offset`. With it, the parser treats
//! overlap with the file header as the existing "structurally bad
//! → no debug_info" case, so both parses agree on
//! `debug_info_v96 = None` and the round-trip closes.
//!
//! Fuzz target that surfaced this:
//! `fuzz/fuzz_targets/fuzz_emit_roundtrip_hbc.rs` (artifact preserved
//! under `tests/fixtures/adversarial/inconsistent_debug_header/`).

use std::fs;

use droidsaw_hermes::emit::emit_hbc_v98;
use droidsaw_hermes::parser::{HbcFile, HbcFileEquiv, V98};

const FIXTURE_PATH: &str =
    "tests/fixtures/adversarial/inconsistent_debug_header/v98_debug_header_overlaps_file_header.hbc";

#[test]
fn v98_debug_header_overlap_does_not_crash_first_parse() {
    let bytes = fs::read(FIXTURE_PATH).expect("fixture must be checked in");
    let hbc = HbcFile::parse(&bytes, None).expect("first parse must succeed");
    assert_eq!(hbc.version, 98);
    // The overlap-with-header case collapses to "no debug_info" by the
    // structural guard added in `debug_info_v96_parse` /
    // `parse_inner`'s filename-table read path.
    assert!(
        hbc.debug_info_v96().is_none(),
        "overlap with file header must collapse to debug_info_v96 = None"
    );
}

#[test]
fn v98_debug_header_overlap_roundtrips_via_emit() {
    let bytes = fs::read(FIXTURE_PATH).expect("fixture must be checked in");

    let hbc1 = HbcFile::parse(&bytes, None).expect("first parse must succeed");
    let equiv1 = HbcFileEquiv::<V98>::new(&hbc1)
        .expect("fixture's first parse must be HbcFileEquiv<V98>");

    let emitted = emit_hbc_v98(&hbc1).expect("emit_hbc_v98 must succeed");

    let hbc2 = HbcFile::parse(&emitted, None)
        .expect("second parse must succeed (no InconsistentDebugHeader)");
    let equiv2 = HbcFileEquiv::<V98>::new(&hbc2)
        .expect("second parse must produce v98 output");

    assert!(
        equiv1 == equiv2,
        "HbcFileEquiv<V98> must hold across emit on overlap-with-header input"
    );
}
