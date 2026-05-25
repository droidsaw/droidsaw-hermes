//! Acceptance test for `HermesFinding::FileLengthDisagreement`.
//!
//! Two corruption-mask shapes covered:
//! - **Trailing-data smuggling** — `file_length` declared shorter
//!   than `buf.len()`. The TARmageddon-class generalization
//!   (single-archive cross-source disagreement). Without this
//!   Finding, the parser walks sections to `cursor = file_length`,
//!   never re-enters the smuggled bytes, and emits no signal — caller
//!   can't distinguish "well-formed" from "smuggled trailing data".
//! - **Truncated** — `file_length` declared longer than `buf.len()`.
//!   The parser's section! `cursor + size <= buf.len()` checks
//!   already produced a typed `SectionExceedsBounds` *iff* a
//!   section's size pushed past `buf.len()`. With our smaller
//!   minimal-header fixture, sum-of-section-sizes is 0 and the
//!   declared-longer file_length is unobservable in parse output —
//!   exactly the case where the cross-validation surfaces a signal
//!   that would otherwise be lost.

use std::fs;

use droidsaw_hermes::finding::{HermesFinding, drain_findings_for_test};
use droidsaw_hermes::parser::HbcFile;

const FIXTURE_DIR: &str = "tests/fixtures/adversarial/file_length_disagree";

/// 128 + `trailing_bytes` total. Header carries `file_length = 128`
/// (matches the 128-byte well-formed header range); buf.len() is
/// 128 + trailing. The cross-validation must observe both and
/// emit a Finding. All counts in the header are 0 so the
/// section! walk produces zero-sized sections (cursor stays at 128).
fn build_trailing_data_hbc(trailing_bytes: usize) -> Vec<u8> {
    let total = 128 + trailing_bytes;
    let mut buf = vec![0u8; total];
    buf[0..8].copy_from_slice(&0x1F1903C103BC1FC6u64.to_le_bytes());
    // version 96 — in-range per the parse-entry version gate.
    buf[8..12].copy_from_slice(&96u32.to_le_bytes());
    // file_length declared at the header-only boundary, IGNORING
    // the trailing bytes — the smuggling shape.
    buf[32..36].copy_from_slice(&128u32.to_le_bytes());
    // All other header fields zero → zero-sized sections.
    // Trailing bytes default to zero; could be anything (the
    // parser must not read them as bytecode).
    buf
}

/// 128-byte minimal header with `file_length` declared LARGER than
/// the actual buffer. Per Phase 0 audit, the section! macros bound
/// every section by `buf.len()`, so even though file_length is
/// declared larger, no section reads past the buffer — the only
/// signal would be the cross-validation Finding.
fn build_truncated_hbc() -> Vec<u8> {
    let mut buf = vec![0u8; 128];
    buf[0..8].copy_from_slice(&0x1F1903C103BC1FC6u64.to_le_bytes());
    buf[8..12].copy_from_slice(&96u32.to_le_bytes());
    // Declare 1024 bytes when only 128 are present.
    buf[32..36].copy_from_slice(&1024u32.to_le_bytes());
    buf
}

fn assert_disagreement(bytes: &[u8], expected_declared: u32, expected_observed: u64) {
    // Drain any stale findings from earlier tests on this thread.
    let _ = drain_findings_for_test();

    let _hbc = HbcFile::parse(bytes, None).expect("tolerant-parse continues on disagreement");
    let findings = drain_findings_for_test();
    let mut saw = false;
    for f in &findings {
        if let HermesFinding::FileLengthDisagreement { declared, observed } = *f {
            assert_eq!(declared, expected_declared);
            assert_eq!(observed, expected_observed);
            saw = true;
        }
    }
    assert!(
        saw,
        "expected FileLengthDisagreement {{ declared: {expected_declared}, observed: {expected_observed} }} \
         in {findings:?}"
    );
}

#[test]
fn trailing_data_emits_disagreement() {
    let bytes = build_trailing_data_hbc(64);
    assert_disagreement(&bytes, 128, 128 + 64);
}

#[test]
fn trailing_data_parse_succeeds() {
    let bytes = build_trailing_data_hbc(64);
    let _ = drain_findings_for_test();
    let hbc = HbcFile::parse(&bytes, None).expect("Ok");
    assert_eq!(hbc.version, 96);
    assert_eq!(hbc.function_count, 0);
    assert_eq!(hbc.string_count, 0);
    let _ = drain_findings_for_test();
}

#[test]
fn truncated_emits_disagreement() {
    let bytes = build_truncated_hbc();
    assert_disagreement(&bytes, 1024, 128);
}

#[test]
fn well_formed_emits_no_disagreement() {
    // Header-only 128-byte HBC; file_length = 128, buf.len() = 128.
    let _ = drain_findings_for_test();
    let mut buf = vec![0u8; 128];
    buf[0..8].copy_from_slice(&0x1F1903C103BC1FC6u64.to_le_bytes());
    buf[8..12].copy_from_slice(&96u32.to_le_bytes());
    buf[32..36].copy_from_slice(&128u32.to_le_bytes());
    let _ = HbcFile::parse(&buf, None).expect("Ok");
    let findings = drain_findings_for_test();
    for f in &findings {
        assert!(
            !matches!(f, HermesFinding::FileLengthDisagreement { .. }),
            "well-formed file emitted spurious FileLengthDisagreement: {f:?}"
        );
    }
}

#[test]
fn dedup_holds_across_parses() {
    // Two parses of the SAME shape on the same thread should
    // produce one Finding (full-value dedup in `finding::emit_finding`).
    let _ = drain_findings_for_test();
    let bytes = build_trailing_data_hbc(64);
    let _ = HbcFile::parse(&bytes, None).expect("Ok");
    let _ = HbcFile::parse(&bytes, None).expect("Ok");
    let findings = drain_findings_for_test();
    let count = findings
        .iter()
        .filter(|f| matches!(f, HermesFinding::FileLengthDisagreement { .. }))
        .count();
    assert_eq!(count, 1, "{findings:?}");
}

#[test]
fn fixture_trailing_loads_and_emits_disagreement() {
    let bytes = fs::read(format!("{FIXTURE_DIR}/trailing_data.hbc"))
        .expect("fixture must be checked in");
    let observed = bytes.len() as u64;
    assert_disagreement(&bytes, 128, observed);
}

#[test]
fn fixture_truncated_loads_and_emits_disagreement() {
    let bytes = fs::read(format!("{FIXTURE_DIR}/truncated.hbc"))
        .expect("fixture must be checked in");
    assert_disagreement(&bytes, 1024, 128);
}

#[test]
fn fixture_trailing_bytes_match_disk() {
    let on_disk = fs::read(format!("{FIXTURE_DIR}/trailing_data.hbc"))
        .expect("fixture must be checked in");
    assert_eq!(on_disk, build_trailing_data_hbc(64));
}

#[test]
fn fixture_truncated_bytes_match_disk() {
    let on_disk = fs::read(format!("{FIXTURE_DIR}/truncated.hbc"))
        .expect("fixture must be checked in");
    assert_eq!(on_disk, build_truncated_hbc());
}

/// Regenerate the on-disk file-length disagreement fixtures.
/// `#[ignore]` in CI; run manually with `cargo test --test
/// file_length_disagree regen_ -- --ignored --nocapture` after a
/// structural change.
#[test]
#[ignore = "regen helper — run manually with --ignored after layout changes"]
fn regen_file_length_disagree_fixtures() {
    fs::create_dir_all(FIXTURE_DIR).unwrap();
    let trailing = build_trailing_data_hbc(64);
    let truncated = build_truncated_hbc();
    fs::write(format!("{FIXTURE_DIR}/trailing_data.hbc"), &trailing).unwrap();
    fs::write(format!("{FIXTURE_DIR}/truncated.hbc"), &truncated).unwrap();
    println!("wrote {} bytes to {FIXTURE_DIR}/trailing_data.hbc", trailing.len());
    println!("wrote {} bytes to {FIXTURE_DIR}/truncated.hbc", truncated.len());
}
