//! Shared proptest scaffolding for HBC round-trip + quotient-laws
//! tests.
//!
//! Hosts `hbc_bytes_strategy` (byte-mutation generator over the
//! minimal v96 seed) so `roundtrip_hbc_proptest.rs` and
//! `quotient_laws_proptest.rs` share a single source. Both files
//! `mod common;` this module; Cargo's `tests/<dir>/mod.rs` convention
//! means it's compiled into each consumer test binary instead of
//! becoming its own test target.

use proptest::prelude::*;
use std::sync::OnceLock;

/// Smallest possible valid v96 HBC: a 128-byte header with magic,
/// version=96, file_length=128, and all counts/sizes zero. Parses
/// cleanly (7 sections, all size 0). See `roundtrip_hbc_proptest.rs`
/// docs for why this synthesized seed beats the prior fuzz-fixture
/// seed (parser-ignored garbage canonicalizes on emit).
pub fn minimal_v96_seed() -> &'static Vec<u8> {
    static SEED: OnceLock<Vec<u8>> = OnceLock::new();
    SEED.get_or_init(|| {
        let mut h = vec![0u8; 128];
        h[0..8].copy_from_slice(&0x1F19_03C1_03BC_1FC6u64.to_le_bytes());
        h[8..12].copy_from_slice(&96u32.to_le_bytes());
        h[32..36].copy_from_slice(&128u32.to_le_bytes());
        h
    })
}

/// Byte-mutation strategy: identity / bit-flip / byte-substitution /
/// truncation. Same shape as the dex side; reused across the v96
/// roundtrip proptest and the quotient-laws proptest.
pub fn hbc_bytes_strategy() -> impl Strategy<Value = Vec<u8>> {
    let seed = minimal_v96_seed();
    let seed_len = seed.len();

    let identity = Just(seed.clone()).boxed();

    let bit_flip = (0..seed_len, 0u8..8)
        .prop_map(|(pos, bit)| {
            let mut out = minimal_v96_seed().clone();
            out[pos] ^= 1 << bit;
            out
        })
        .boxed();

    let byte_subst = (0..seed_len, any::<u8>())
        .prop_map(|(pos, val)| {
            let mut out = minimal_v96_seed().clone();
            out[pos] = val;
            out
        })
        .boxed();

    let truncate = (32..seed_len)
        .prop_map(|len| minimal_v96_seed()[..len].to_vec())
        .boxed();

    prop_oneof![
        1 => identity,
        3 => bit_flip,
        2 => byte_subst,
        1 => truncate,
    ]
}
