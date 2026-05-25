//! Acceptance test for the `MAX_BIGINT_BYTES` cap.
//!
//! Underlying amplification: `parser::bigint_le_twos_to_decimal`
//! performs a BCD-style base-256 → base-10 conversion that runs in
//! O(N²) in the BigInt storage-entry byte length. The per-entry length
//! is bounded only by the table-wide `big_int_storage_size: u32`; an
//! attacker-shipped HBC with a single 4 MiB BigInt entry would run
//! ~10 trillion mul-adds per `bigint_as_str` call — multi-minute CPU
//! hang per HBC decompile.
//!
//! Cap: `parser::HbcFile::bigint_as_str` gates on
//! `bytes.len() > MAX_BIGINT_BYTES` (default 4096) before any
//! conversion work, emits a typed `HermesFinding::BigIntTooLarge`,
//! and returns `None`. The emit-site arm renders
//! `/* missing bigint #N */` so the decompile run continues (lenient
//! policy).
//!
//! The fixture below carries one BigInt storage entry whose byte
//! length is 1 MiB (= 262× the cap). The wall-clock guard locks the
//! short-circuit: without the cap the loop is ~10 hours of work;
//! with it the cap fires in microseconds. The on-disk fixture is
//! regenerated via the `regen_*_fixture` helper marked `#[ignore]`.

#![allow(
    clippy::cast_possible_truncation,
    reason = "PROOF: HBC parser/decompiler. IDs (string-id, builtin-id, function-id, regex-id) are widened from parser-validated u32 header counts and narrowed via explicit width-bounded ops. Slot/level-id narrows carry explicit `& 0xFFFF` / `& 0xFF` masks at the cast site. See module-level Cast hygiene doc-comment."
)]

use std::fs;
use std::time::Instant;

use droidsaw_hermes::parser::HbcFile;

const FIXTURE_PATH: &str =
    "tests/fixtures/adversarial/bigint_decimal_quadratic_bomb/single_1mib_v87.hbc";

/// 1 MiB BigInt storage entry — well above the 4 KiB cap.
const BOMB_BIGINT_BYTES: u32 = 1 << 20;

/// Build a v87 HBC carrying one BigInt entry whose storage byte length
/// is `BOMB_BIGINT_BYTES`. Layout per `header::parse_v87_to_96`
/// + `parser::parse_inner`'s `section!` walk:
///   Header(128) + BigIntTable(8) + BigIntStorage(BOMB_BIGINT_BYTES)
///   = 128 + 8 + (1 << 20) bytes total.
fn build_bigint_bomb_v87() -> Vec<u8> {
    let total: usize = 128 + 8 + BOMB_BIGINT_BYTES as usize;
    let mut buf = vec![0u8; total];

    // Magic + version 87 (V87to96 branch).
    buf[0..8].copy_from_slice(&0x1F1903C103BC1FC6u64.to_le_bytes());
    buf[8..12].copy_from_slice(&87u32.to_le_bytes());

    // file_length @32 matches buf.len() — keeps the file-length
    // cross-validation Finding silent.
    buf[32..36].copy_from_slice(&(total as u32).to_le_bytes());

    // big_int_count @64 = 1 entry.
    buf[64..68].copy_from_slice(&1u32.to_le_bytes());
    // big_int_storage_size @68 = BOMB bytes.
    buf[68..72].copy_from_slice(&BOMB_BIGINT_BYTES.to_le_bytes());

    // BigIntTable @128: one 8-byte entry — (storage_offset=0, length=BOMB).
    buf[128..132].copy_from_slice(&0u32.to_le_bytes());
    buf[132..136].copy_from_slice(&BOMB_BIGINT_BYTES.to_le_bytes());

    // BigIntStorage @136: BOMB_BIGINT_BYTES of 0xFF — pre-cap, this
    // is a worst-case input for the BCD accumulator (every byte
    // carries maximum into the digit vector). Post-cap, the bytes
    // are never touched.
    for slot in &mut buf[136..total] {
        *slot = 0xFF;
    }

    buf
}

#[test]
fn fixture_bytes_match_disk() {
    let on_disk = fs::read(FIXTURE_PATH)
        .expect("fixture must be checked in — run regen_bigint_decimal_quadratic_bomb_fixture");
    assert_eq!(on_disk, build_bigint_bomb_v87());
}

#[test]
fn parse_and_bigint_accessor_short_circuit_under_1s() {
    let bytes = build_bigint_bomb_v87();

    // Acceptance gate: parse + every `bigint_as_str` call together
    // complete in well under 1 s. The fixture carries one BigInt
    // entry whose byte length is 262× the cap; without the cap this
    // would be ~10 hours of O(N²) work (≈ 10¹² mul-adds).
    let started = Instant::now();
    let hbc = HbcFile::parse(&bytes, None).expect("v87 header parses cleanly");
    let _ = droidsaw_hermes::finding::drain_findings_for_test();
    let got = hbc.bigint_as_str(0);
    let elapsed = started.elapsed();

    assert_eq!(hbc.version, 87);
    assert_eq!(hbc.bigint_count(), 1);
    assert_eq!(got, None, "over-cap accessor must return None");
    assert!(
        elapsed.as_millis() < 1_000,
        "parse + bigint_as_str took {elapsed:?}, expected < 1 s (cap short-circuits the O(N²) path)"
    );

    let findings = droidsaw_hermes::finding::drain_findings_for_test();
    let saw_cap = findings.iter().any(|f| {
        matches!(
            f,
            droidsaw_hermes::finding::HermesFinding::BigIntTooLarge {
                index: 0,
                observed: BOMB_BIGINT_BYTES,
                limit: droidsaw_hermes::finding::MAX_BIGINT_BYTES,
            }
        )
    });
    assert!(
        saw_cap,
        "expected HermesFinding::BigIntTooLarge with observed={BOMB_BIGINT_BYTES}, got {findings:?}"
    );
}

#[test]
fn fixture_loads_and_short_circuits_under_1s() {
    let bytes = fs::read(FIXTURE_PATH).expect("fixture must be checked in");
    let started = Instant::now();
    let hbc = HbcFile::parse(&bytes, None).expect("v87 header parses cleanly");
    let _ = droidsaw_hermes::finding::drain_findings_for_test();
    let got = hbc.bigint_as_str(0);
    let elapsed = started.elapsed();

    assert_eq!(got, None);
    assert!(
        elapsed.as_millis() < 1_000,
        "on-disk fixture parse + bigint_as_str took {elapsed:?}"
    );
}

/// Regenerate the on-disk fixture. `#[ignore]` in CI; run manually
/// with `cargo test --test bigint_decimal_quadratic_bomb regen_ --
/// --ignored --nocapture`.
#[test]
#[ignore = "regen helper — run manually with --ignored after layout changes"]
fn regen_bigint_decimal_quadratic_bomb_fixture() {
    let bytes = build_bigint_bomb_v87();
    let path = std::path::Path::new(FIXTURE_PATH);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create fixture parent");
    }
    fs::write(path, &bytes).expect("write fixture");
    println!("wrote {} bytes to {FIXTURE_PATH}", bytes.len());
}
