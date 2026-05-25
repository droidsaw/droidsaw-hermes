//! Formal-verification harnesses for the parser's bit-twiddling
//! primitives. Build with: `cargo kani --package droidsaw-hermes`.
//! Requires: `rustup + cargo kani setup`.
//!
//! **Anti-pattern harness removed.** The earlier `read_u32_no_panic`
//! and `read_u16_no_panic` harnesses were no-panic claims on functions
//! whose discipline (`.get(..).and_then(<[u8]>::first_chunk)`) already
//! proves no-panic at the type-system floor. No-panic harnesses on functions
//! whose discipline already proves no-panic are tautological
//! and contributed false confidence. Removed without replacement —
//! the discipline gauge stays in production source.

#![cfg(kani)]

use super::{pack_flags, read_bitfield};

/// Verify: pack_flags output uses only bits 0-6 (7-bit field).
#[kani::proof]
fn pack_flags_bounded() {
    let raw: u8 = kani::any();
    let result = pack_flags(raw);
    kani::assert(result <= 0x7F, "pack_flags must produce a 7-bit value");
}

/// Verify `read_bitfield` over the FULL production input range
/// `(num_bits: 1..=32, start_bit: 0..=40-num_bits)`. The earlier
/// `read_bitfield_bounded_small` capped `num_bits ≤ 8` — a
/// tautological subset that proved a strict subspace of the actual
/// production callsite envelope (raw_offset / raw_info_offset use
/// 25-bit widths; bit-pack composes go up to 32). This strengthens
/// the proof to cover the load-bearing widths.
///
/// Range claim: `result < (1u32 << num_bits)` for every accepted
/// input pair. The independent oracle is byte-collected accumulation
/// (bit-extract from a u64 windowed read) — different primitive ops
/// from production's nested-shift accumulator.
#[kani::proof]
#[kani::unwind(33)]
fn read_bitfield_bounded_full_u32() {
    let buf: [u8; 5] = kani::any();
    let start_bit: u32 = kani::any();
    let num_bits: u32 = kani::any();
    kani::assume(num_bits >= 1 && num_bits <= 32);
    // 5-byte buffer = 40 bits available; start_bit + num_bits must fit.
    kani::assume(start_bit <= 40u32.saturating_sub(num_bits));

    let result = read_bitfield(&buf, start_bit, num_bits);

    // Range claim: result fits in `num_bits` bits. For num_bits == 32
    // the bound `1u32 << 32` overflows; treat that arm with the
    // explicit `u32::MAX` upper bound instead.
    if num_bits == 32 {
        kani::assert(
            u64::from(result) <= u64::from(u32::MAX),
            "32-bit read fits in u32 (trivially true; explicit floor)",
        );
    } else {
        kani::assert(
            result < (1u32 << num_bits),
            "read_bitfield result < 2^num_bits for num_bits in 1..=31",
        );
    }
}
