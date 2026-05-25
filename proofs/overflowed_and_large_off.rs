// SPDX-License-Identifier: BSD-3-Clause

//! Kani Tier-1 proof — `SmallFuncHeaderV98Raw::overflowed_and_large_off`
//! at `droidsaw_hermes::parser::SmallFuncHeaderV98Raw`.
//!
//! Proves the bit-discriminant correctness of the v98 small-header
//! overflow predicate + large-offset composition:
//!
//! 1. **`overflowed` extraction**: production uses `(flags_byte >> 5) &
//!    1 != 0`. The proof oracle uses the equivalent byte-bit-test
//!    `flags_byte & 0x20 != 0` — different primitive (mask vs shift)
//!    but mathematically identical. A regression flipping the bit
//!    index (e.g. `& 0x10` for bit 4) diverges from the oracle.
//!
//! 2. **`large_off` shift-discriminant**: production composes
//!    `(func_name << SHIFT) | offset` with `SHIFT = 16` for EarlyV98
//!    and `SHIFT = 24` for LateV98. The proof asserts that for each
//!    variant, the production result's high bits (above SHIFT) carry
//!    func_name verbatim and the low SHIFT bits carry offset's low
//!    SHIFT bits — closing the "wrong-region shift" attack primitive
//!    where attacker-controlled `large_off` would route to the wrong
//!    bit window.
//!
//! Two variants × two claims = the four sub-proofs below.
//!
//! **What this proof verifies (production-code gauge):**
//! - Target: production `overflowed_and_large_off` method. Called
//!   directly via a constructed enum value; if production has a bug,
//!   the proof fails.
//! - Oracle for `overflowed`: byte-bit-test `& 0x20`. For `large_off`:
//!   independent bit-window extraction from the production result.
//!
//! **Dominator proven**: the lint+types floor cannot detect a
//! `>> 5` → `>> 4` typo (both compile, both produce u8 → bool). The
//! independent bit-test surfaces it.

#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::indexing_slicing)]
#![allow(clippy::unwrap_used)]

use crate::parser::SmallFuncHeaderV98Raw;

// BOUNDS: unwind-depth = 2; reason = the method is straight-line —
// match arm + 2 arithmetic ops. No loops.

// Helpers — construct the enum variants with symbolic fields the
// production method actually reads, plus arbitrary kani::any() for
// the ones it doesn't (raw_param_count, raw_byte_size, etc. are not
// touched by overflowed_and_large_off).

fn arb_early_v98(raw_offset: u32, raw_func_name: u32, raw_flags_byte: u8) -> SmallFuncHeaderV98Raw {
    SmallFuncHeaderV98Raw::EarlyV98 {
        raw_offset,
        raw_param_count: kani::any(),
        raw_byte_size: kani::any(),
        raw_func_name,
        raw_uncharacterized_mid: kani::any(),
        raw_flags_byte,
    }
}

fn arb_late_v98(raw_offset: u32, raw_func_name: u32, raw_flags_byte: u8) -> SmallFuncHeaderV98Raw {
    SmallFuncHeaderV98Raw::LateV98 {
        raw_offset,
        raw_param_count: kani::any(),
        raw_loop_depth: kani::any(),
        raw_byte_size: kani::any(),
        raw_func_name,
        raw_uncharacterized_mid_lo: kani::any(),
        raw_uncharacterized_mid_hi: kani::any(),
        raw_flags_byte,
    }
}

#[kani::proof]
#[kani::unwind(2)]
fn early_v98_overflowed_matches_bit5_test() {
    let raw_offset: u32 = kani::any();
    let raw_func_name: u32 = kani::any();
    let raw_flags_byte: u8 = kani::any();

    let hdr = arb_early_v98(raw_offset, raw_func_name, raw_flags_byte);
    let (overflowed, _) = hdr.overflowed_and_large_off();

    // Independent oracle: byte-bit-test on bit 5.
    let oracle = raw_flags_byte & 0x20 != 0;
    kani::assert(
        overflowed == oracle,
        "EarlyV98 overflowed matches bit-5 mask oracle",
    );
}

#[kani::proof]
#[kani::unwind(2)]
fn late_v98_overflowed_matches_bit5_test() {
    let raw_offset: u32 = kani::any();
    let raw_func_name: u32 = kani::any();
    let raw_flags_byte: u8 = kani::any();

    let hdr = arb_late_v98(raw_offset, raw_func_name, raw_flags_byte);
    let (overflowed, _) = hdr.overflowed_and_large_off();

    let oracle = raw_flags_byte & 0x20 != 0;
    kani::assert(
        overflowed == oracle,
        "LateV98 overflowed matches bit-5 mask oracle",
    );
}

#[kani::proof]
#[kani::unwind(2)]
fn early_v98_large_off_shift_is_16() {
    // Constrain offset's high half so the OR is unambiguous: with
    // offset's bits 16..32 zero, the high half of large_off is
    // purely func_name (the early-v98 layout window).
    let raw_offset: u32 = kani::any();
    let raw_func_name: u32 = kani::any();
    let raw_flags_byte: u8 = kani::any();
    kani::assume(raw_offset < (1u32 << 16));

    let hdr = arb_early_v98(raw_offset, raw_func_name, raw_flags_byte);
    let (_, large_off) = hdr.overflowed_and_large_off();

    // Independent extraction: low 16 bits = offset; high (48 bits) >>
    // 16 viewed as u32 = func_name.
    #[allow(clippy::as_conversions, clippy::cast_possible_truncation)]
    let low_16 = (large_off & 0xFFFF) as u32;
    #[allow(clippy::as_conversions, clippy::cast_possible_truncation)]
    let high_shifted = (large_off >> 16) as u32;
    kani::assert(low_16 == raw_offset, "EarlyV98: low 16 bits = raw_offset");
    kani::assert(
        high_shifted == raw_func_name,
        "EarlyV98: result >> 16 = raw_func_name (shift discriminant proven)",
    );
}

#[kani::proof]
#[kani::unwind(2)]
fn late_v98_large_off_shift_is_24() {
    let raw_offset: u32 = kani::any();
    let raw_func_name: u32 = kani::any();
    let raw_flags_byte: u8 = kani::any();
    kani::assume(raw_offset < (1u32 << 24));

    let hdr = arb_late_v98(raw_offset, raw_func_name, raw_flags_byte);
    let (_, large_off) = hdr.overflowed_and_large_off();

    #[allow(clippy::as_conversions, clippy::cast_possible_truncation)]
    let low_24 = (large_off & ((1u64 << 24) - 1)) as u32;
    #[allow(clippy::as_conversions, clippy::cast_possible_truncation)]
    let high_shifted = (large_off >> 24) as u32;
    kani::assert(low_24 == raw_offset, "LateV98: low 24 bits = raw_offset");
    kani::assert(
        high_shifted == raw_func_name,
        "LateV98: result >> 24 = raw_func_name (shift discriminant proven)",
    );
}
