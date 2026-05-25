//! Acceptance test for the overflow-string-table OOR typed-Finding shape.
//!
//! Builds (and re-checks-in) a 132-byte deterministic HBC v96 fixture
//! whose single SmallStringTable entry carries the overflow sentinel
//! `str_length == 255` paired with `str_offset = 0x42` while the
//! header declares `overflow_string_count = 0`. That combination is
//! the exact corruption-mask shape — the
//! lookup falls through to the silent-empty branch, and the parser
//! must emit a typed [`HermesFinding::OverflowIndexOutOfRange`] so
//! the failure mode is observable.
//!
//! The fixture lives at
//! `tests/fixtures/adversarial/overflow_string_oor/oor_idx_str0.hbc`
//! and seeds `fuzz_parser`'s corpus
//! (`fuzz/seeds/fuzz_parser/03_overflow_string_oor`).
//!
//! `regen_overflow_string_oor_fixture` is `#[ignore]`d in CI; run
//! manually with `cargo test --test overflow_string_oor regen_ -- \
//! --ignored --nocapture` to rewrite the bytes after a structural
//! change to the layout. The acceptance test re-derives the bytes in
//! memory so a missing or stale fixture file still surfaces a clear
//! failure rather than silently passing.

use std::fs;

use droidsaw_hermes::finding::{HermesFinding, drain_findings_for_test};
use droidsaw_hermes::parser::HbcFile;

const FIXTURE_PATH: &str =
    "tests/fixtures/adversarial/overflow_string_oor/oor_idx_str0.hbc";

const SEED_PATH: &str = "fuzz/seeds/fuzz_parser/03_overflow_string_oor";

/// Build a minimal v96 HBC blob whose SmallStringTable[0] carries the
/// overflow sentinel `str_length=255` with `str_offset=0x42` while
/// `overflow_string_count = 0`. The single 4-byte entry encodes:
///
/// ```text
/// bit 0     : is_utf16        = 0
/// bits 1-23 : str_offset      = 0x42  (≥ overflow_string_count → OOR)
/// bits 24-31: str_length      = 255   (overflow indirection sentinel)
/// ```
fn build_oor_hbc() -> Vec<u8> {
    let mut buf = vec![0u8; 132];

    // Magic: 0x1F1903C103BC1FC6 little-endian.
    buf[0..8].copy_from_slice(&0x1F1903C103BC1FC6u64.to_le_bytes());
    // Version 96.
    buf[8..12].copy_from_slice(&96u32.to_le_bytes());
    // sourceHash (20 bytes) zeroed at 12..32.
    // file_length @32 — informational; parser does not validate.
    buf[32..36].copy_from_slice(&132u32.to_le_bytes());
    // global_code_index @36 — zeroed.
    // function_count @40 — zeroed.
    // string_kind_count @44 — zeroed.
    // identifier_count @48 — zeroed.
    // string_count @52 — 1.
    buf[52..56].copy_from_slice(&1u32.to_le_bytes());
    // overflow_string_count @56 — 0 (so any str_offset ≥ 0 trips OOR).
    // string_storage_size @60 — zeroed.
    // Remaining v87..=v96 header fields zeroed; section! produces
    // zero-sized FunctionHeaders / StringKinds / IdentifierHashes /
    // OverflowStringTable / StringStorage / etc.

    // SmallStringTable[0] @128: little-endian u32 with bits 24..31 =
    // 0xFF and bits 1..24 = 0x42.
    let entry: u32 = (0xFFu32 << 24) | (0x42u32 << 1);
    buf[128..132].copy_from_slice(&entry.to_le_bytes());
    buf
}

#[test]
fn fixture_bytes_match_disk() {
    let on_disk = fs::read(FIXTURE_PATH)
        .expect("adversarial fixture must be checked in — run `regen_overflow_string_oor_fixture`");
    let in_memory = build_oor_hbc();
    assert_eq!(
        on_disk, in_memory,
        "fixture drift; rerun regen_overflow_string_oor_fixture"
    );
}

#[test]
fn parse_succeeds_emits_typed_finding_observable_empty_string() {
    // Drain stale state from prior tests on this thread.
    let _ = drain_findings_for_test();

    let bytes = build_oor_hbc();
    let hbc = HbcFile::parse(&bytes, None).expect("minimal v96 header parses cleanly");
    assert_eq!(hbc.string_count, 1);
    assert_eq!(hbc.overflow_string_count, 0);

    // String[0] returns `Err(HermesError::OverflowIndexOutOfRange)`.
    // The Finding side-channel still fires for backwards-compat /
    // aggregator parity.
    let res = hbc.string_get(0);
    match res {
        Err(droidsaw_hermes::HermesError::OverflowIndexOutOfRange { index, count }) => {
            assert_eq!(index, 0);
            assert_eq!(count, 0);
        }
        other => panic!("expected OverflowIndexOutOfRange Err, got {other:?}"),
    }

    // The OOR fired exactly once (dedup keys on (variant, index, count)).
    let findings = drain_findings_for_test();
    assert_eq!(
        findings,
        vec![HermesFinding::OverflowIndexOutOfRange {
            index: 0,
            count: 0,
        }],
        "expected single typed Finding for OOR shape, got {findings:?}"
    );

    // Re-asking on the same idx after drain re-fires (drain resets dedup).
    let _ = hbc.string_get(0);
    let findings_2 = drain_findings_for_test();
    assert_eq!(findings_2.len(), 1, "post-drain re-fire");
}

#[test]
fn many_lookups_dedup_to_one_finding() {
    let _ = drain_findings_for_test();
    let bytes = build_oor_hbc();
    let hbc = HbcFile::parse(&bytes, None).expect("parse");
    for _ in 0..50 {
        // Each lookup returns the same typed Err; Finding dedup is
        // per-thread on the (variant, index, count) tuple.
        let res = hbc.string_get(0);
        assert!(
            matches!(
                res,
                Err(droidsaw_hermes::HermesError::OverflowIndexOutOfRange { .. })
            ),
            "expected OOR Err on every lookup"
        );
    }
    let findings = drain_findings_for_test();
    assert_eq!(findings.len(), 1, "{findings:?}");
}

/// Regenerate the on-disk fixture + fuzz seed. `#[ignore]` in CI; run
/// manually after a structural layout change. WHY: fixtures are
/// checked-in bytes; structural changes need to refresh both the
/// `tests/fixtures/...` integration-test fixture and the
/// `fuzz/seeds/...` libFuzzer seed so they stay in sync.
#[test]
#[ignore = "regen helper — run manually with --ignored after layout changes"]
fn regen_overflow_string_oor_fixture() {
    let bytes = build_oor_hbc();

    let fixture_dir = std::path::Path::new(FIXTURE_PATH).parent().unwrap();
    fs::create_dir_all(fixture_dir).unwrap();
    fs::write(FIXTURE_PATH, &bytes).unwrap();

    let seed_dir = std::path::Path::new(SEED_PATH).parent().unwrap();
    fs::create_dir_all(seed_dir).unwrap();
    fs::write(SEED_PATH, &bytes).unwrap();

    println!("wrote {} bytes to {FIXTURE_PATH}", bytes.len());
    println!("wrote {} bytes to {SEED_PATH}", bytes.len());
}
