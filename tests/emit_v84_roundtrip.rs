// SPDX-License-Identifier: BSD-3-Clause

//! Deterministic unit coverage for `emit_hbc_v84` and
//! `HbcFileEquiv::<V84>::eq`.
//!
//! The fuzz roundtrip target (`fuzz_emit_roundtrip_hbc`) and the
//! env-gated corpus test (`hbc_corpus_roundtrip`) both exercise v84
//! but produce zero LCOV credit (fuzz) or run only when a corpus is
//! staged (env-gate). This file provides always-on coverage via a
//! minimal v84 seed that exercises every branch in the emit + equiv
//! path reachable from a header-only (function_count=0) file.
//!
//! ## Minimal v84 seed layout
//!
//! ```text
//! [0..8]   magic = HBC_MAGIC
//! [8..12]  version = 84
//! [32..36] file_length = 128
//! rest     0x00 (all counts/sizes zero)
//! ```
//!
//! Version 84 uses the `V84to86Header` layout (`header.rs:parse_v84_to_86`);
//! `HbcFileEquiv::<V84>::new` gates on `file.version == V84::VERSION == 84`.

use droidsaw_hermes::emit::emit_hbc_v84;
use droidsaw_hermes::parser::{HbcFile, HbcFileEquiv, V84};

fn minimal_v84_seed() -> Vec<u8> {
    let mut buf = vec![0u8; 128];
    buf[0..8].copy_from_slice(&0x1F19_03C1_03BC_1FC6u64.to_le_bytes());
    buf[8..12].copy_from_slice(&84u32.to_le_bytes());
    buf[32..36].copy_from_slice(&128u32.to_le_bytes());
    buf
}

/// Exercises `emit_hbc_v84` and `HbcFileEquiv::<V84>::PartialEq` on
/// the canonical minimal v84 seed. Provides LCOV coverage for both
/// functions that the fuzz/corpus gates cover at runtime but not in
/// `cargo llvm-cov`.
#[test]
fn emit_hbc_v84_minimal_roundtrips_and_equiv_holds() {
    let seed = minimal_v84_seed();

    let hbc1 = HbcFile::parse(&seed, None)
        .expect("minimal v84 seed must parse cleanly");
    let equiv1 = HbcFileEquiv::<V84>::new(&hbc1)
        .expect("version=84 file must produce Some(HbcFileEquiv<V84>)");

    let emitted = emit_hbc_v84(&hbc1)
        .expect("emit_hbc_v84 on minimal v84 seed must succeed");

    let hbc2 = HbcFile::parse(&emitted, None)
        .expect("parse-emit-parse: second parse of v84 output must succeed");
    let equiv2 = HbcFileEquiv::<V84>::new(&hbc2)
        .expect("emit_hbc_v84 output must remain version=84");

    assert!(
        equiv1 == equiv2,
        "HbcFileEquiv<V84> violated round-trip on minimal seed: \
         src_len={} emit_len={}",
        seed.len(),
        emitted.len(),
    );

    // Byte-identity is a theorem of correct emit on clean inputs
    // (no garbage in parser-ignored fields).
    assert_eq!(
        seed,
        emitted,
        "minimal v84 seed must round-trip byte-identically: \
         first diff at byte {:?}",
        seed.iter()
            .zip(emitted.iter())
            .enumerate()
            .find(|(_, (a, b))| a != b)
            .map(|(i, _)| i),
    );
}

/// Exercises the `HbcFileEquiv::<V84>::new` `None` arm: a non-v84
/// file must not match the V84 equivalence class.
#[test]
fn hbc_file_equiv_v84_new_returns_none_for_non_v84() {
    let mut buf = minimal_v84_seed();
    // Change version to 96
    buf[8..12].copy_from_slice(&96u32.to_le_bytes());
    let hbc = HbcFile::parse(&buf, None).expect("version-96 seed parses");
    assert!(
        HbcFileEquiv::<V84>::new(&hbc).is_none(),
        "HbcFileEquiv::<V84>::new must return None for version=96 file"
    );
}
