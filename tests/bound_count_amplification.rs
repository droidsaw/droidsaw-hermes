//! Acceptance tests for the extended four-counts → ten-counts
//! amplification gate.
//!
//! Without the extended gate, 4 of 10 amplifiable header counts had
//! an early `bound_count` gate at `parser::parse_inner` (function /
//! string / overflow_string / reg_exp); the other 6 (string_kind /
//! identifier / obj_shape_table / big_int / cjs_module /
//! function_source) relied solely on the downstream `section!` /
//! `section_opt!` `cursor + size <= buf.len()` check — not a
//! memory-safety hole, but a hardening uniformity gap.
//!
//! Each fixture is a deterministic 128-byte HBC v96 header with
//! exactly one ungated count inflated to `u32::MAX`; the
//! new gate must reject with `HermesError::BoundCountExceeded`
//! (`CountExceeded`-shaped) before any `section!` work.
//!
//! `identifier_count` and `big_int_count` are the strongest candidates
//! (large stride × meaningful per-entry payload); this test file covers
//! both.

use std::fs;

use droidsaw_hermes::HermesError;
use droidsaw_hermes::parser::HbcFile;

const FIXTURE_DIR: &str = "tests/fixtures/adversarial/bound_count_amplification";

/// Build a 128-byte v96 HBC header with `field_offset` set to
/// `u32::MAX`. Magic + version are populated; `file_length = 128` so
/// the file-length cross-validation Finding does not fire spuriously.
fn build_header_with_inflated_count(field_offset: usize) -> Vec<u8> {
    let mut buf = vec![0u8; 128];
    buf[0..8].copy_from_slice(&0x1F1903C103BC1FC6u64.to_le_bytes());
    buf[8..12].copy_from_slice(&96u32.to_le_bytes());
    buf[32..36].copy_from_slice(&128u32.to_le_bytes());
    buf[field_offset..field_offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    buf
}

fn assert_bound_count_rejected(bytes: &[u8], expected_item: &str) {
    let err = HbcFile::parse(bytes, None)
        .map(|_| ())
        .expect_err("inflated header count must reject at parse-time bound_count");
    match err {
        HermesError::BoundCountExceeded(ref ce) => {
            assert_eq!(
                ce.got,
                u64::from(u32::MAX),
                "expected got=u32::MAX, item={expected_item}, err={err:?}",
            );
            assert_eq!(
                ce.item, expected_item,
                "expected item={expected_item}, err={err:?}",
            );
        }
        other => panic!("expected BoundCountExceeded for {expected_item}, got {other:?}"),
    }
}

// v87..=v96 header offsets per `header::parse_v87_to_96` (which is
// the in-range routing for our v96 fixtures).

const STRING_KIND_COUNT_OFFSET: usize = 44;
const IDENTIFIER_COUNT_OFFSET: usize = 48;
const BIG_INT_COUNT_OFFSET: usize = 64;

#[test]
fn identifier_count_exceeds_input_returns_bound_count_exceeded() {
    let bytes = build_header_with_inflated_count(IDENTIFIER_COUNT_OFFSET);
    assert_bound_count_rejected(&bytes, "identifier_hashes");
}

#[test]
fn big_int_count_exceeds_input_returns_bound_count_exceeded() {
    let bytes = build_header_with_inflated_count(BIG_INT_COUNT_OFFSET);
    assert_bound_count_rejected(&bytes, "big_int_table");
}

#[test]
fn string_kind_count_exceeds_input_returns_bound_count_exceeded() {
    let bytes = build_header_with_inflated_count(STRING_KIND_COUNT_OFFSET);
    assert_bound_count_rejected(&bytes, "string_kinds");
}

#[test]
fn fixture_identifier_bytes_match_disk() {
    let on_disk = fs::read(format!("{FIXTURE_DIR}/identifier_count_exceeds_input.hbc"))
        .expect("fixture must be checked in");
    assert_eq!(
        on_disk,
        build_header_with_inflated_count(IDENTIFIER_COUNT_OFFSET)
    );
}

#[test]
fn fixture_big_int_bytes_match_disk() {
    let on_disk = fs::read(format!("{FIXTURE_DIR}/big_int_count_exceeds_input.hbc"))
        .expect("fixture must be checked in");
    assert_eq!(
        on_disk,
        build_header_with_inflated_count(BIG_INT_COUNT_OFFSET)
    );
}

#[test]
fn fixture_identifier_on_disk_rejects() {
    let bytes = fs::read(format!("{FIXTURE_DIR}/identifier_count_exceeds_input.hbc"))
        .expect("fixture must be checked in");
    assert_bound_count_rejected(&bytes, "identifier_hashes");
}

#[test]
fn fixture_big_int_on_disk_rejects() {
    let bytes = fs::read(format!("{FIXTURE_DIR}/big_int_count_exceeds_input.hbc"))
        .expect("fixture must be checked in");
    assert_bound_count_rejected(&bytes, "big_int_table");
}

/// Regenerate the on-disk fixtures. `#[ignore]` in CI; run manually
/// with `cargo test --test bound_count_amplification regen_ --
/// --ignored --nocapture`.
#[test]
#[ignore = "regen helper — run manually with --ignored after layout changes"]
fn regen_bound_count_amplification_fixtures() {
    fs::create_dir_all(FIXTURE_DIR).unwrap();
    for (name, field_offset) in [
        ("identifier_count_exceeds_input.hbc", IDENTIFIER_COUNT_OFFSET),
        ("big_int_count_exceeds_input.hbc", BIG_INT_COUNT_OFFSET),
    ] {
        let path = format!("{FIXTURE_DIR}/{name}");
        let bytes = build_header_with_inflated_count(field_offset);
        fs::write(&path, &bytes).unwrap();
        println!("wrote {} bytes to {path}", bytes.len());
    }
}
