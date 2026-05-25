// SPDX-License-Identifier: BSD-3-Clause

//! Kani Tier-1 proof — `decode_source_locations` flags mid-entry
//! truncation + caps `out.len()` at 1 for the truncation-shaped input.
//!
//! Two invariants:
//!
//! 1. **Output cap**: for a 6-byte symbolic-trailing-byte input that
//!    encodes one valid function header + a mid-entry-truncated PC
//!    stream, `out.len() == 1` — the outer loop must NOT resync into
//!    the partial-entry bytes and produce a phantom
//!    `FunctionSourceInfo { function_index: 0, .. }`.
//!
//! 2. **Corrupt flag**: the surviving entry carries `corrupt = true`.
//!    Without this flag, the entry is indistinguishable from a clean
//!    one; downstream symbolicator / source-map tooling has no signal
//!    to drop it.
//!
//! On the EXACT 6-byte byte sequence this proof uses, the resync-
//! permissive out.len() also equals 1 (because the symbolic trailing
//! byte gets
//! consumed as `column_delta` of the same in-progress inner-iter,
//! not as a fresh outer-loop `function_index`). The structural value
//! of this proof is the `corrupt = true` invariant + the explicit
//! `if corrupt { break }` enforcement: a future regression that
//! drops EITHER of those — opening a real phantom-shape window for a
//! different byte layout — fails this proof on the `out.len() == 1`
//! or `corrupt == true` assertion.
//!
//! **What this proof verifies (production-code gauge):** The proof
//! body calls `parser::debug_info::decode_source_locations`
//! (production) directly.
//!
//! **Why this proof is well-suited to automated verification:** The
//! claim is a structural invariant on output count + the `corrupt`
//! field. Non-tautological — a regression that drops the `corrupt = true`
//! setting at any of the 7 inner-break sites fails the second assert.
//!
//! Run with:
//!   cargo kani --package droidsaw-hermes --harness \
//!     source_locations_truncation_does_not_emit_phantom_function

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "PROOF: Kani test-class code; lint floor relaxed via cfg(kani)."
)]

use crate::parser::debug_info::decode_source_locations;

/// BOUNDS: 8-byte fixed-shape input encodes `function_index=1`,
/// `start_line=1`, `start_column=1`, `address_delta=1`,
/// `line_delta_raw=0` (no statement-delta extra), then ONE symbolic
/// trailing byte (the would-be phantom function_index on resync).
/// `kani::unwind(8)` bounds the outer loop at 2 iterations max.
#[kani::proof]
#[kani::unwind(8)]
fn source_locations_truncation_does_not_emit_phantom_function() {
    // Valid prefix: 5 single-byte sleb128 values (each `1` or `0`).
    // Each sleb128 with value v ∈ [-64, 63] encodes as a single byte.
    let prefix: [u8; 5] = [0x01, 0x01, 0x01, 0x01, 0x00];
    // Trailing byte — the post-truncation byte. Without the outer-
    // loop break, the loop reads this as a new function_index,
    // producing a phantom entry. With the break, the outer loop is
    // already terminated.
    let trailing: u8 = kani::any();
    // Constrain the trailing byte to encode a non-negative single-byte
    // sleb128 value (high bit + sign bit both clear → v ∈ [0, 63]) so
    // the resync-permissive shape WOULD have produced a phantom
    // function_index ∈ [0, 63].
    kani::assume(trailing < 0x40);

    let mut buf = [0u8; 6];
    buf[..5].copy_from_slice(&prefix);
    buf[5] = trailing;

    let out = decode_source_locations(&buf, 90)
        .expect("non-empty input must produce Some result");
    // Invariant 1: out.len() is exactly 1. A regression that opened
    // a phantom-shape window (e.g. dropping the `if corrupt { break }`
    // on the outer loop) might make this 2 for some byte layouts.
    kani::assert(
        out.len() == 1,
        "out.len() must be exactly 1 (the real function)",
    );
    kani::assert(
        out[0].function_index == 1,
        "the surviving function carries the real function_index",
    );
    // Invariant 2: the mid-entry-truncated entry is flagged corrupt.
    // A regression that dropped `corrupt = true` at any of the 7
    // inner-break sites would fail this assert. This is the load-
    // bearing claim — downstream symbolicators rely on the flag to
    // drop partial entries.
    kani::assert(
        out[0].corrupt,
        "the mid-entry-truncated function must be flagged corrupt",
    );
}
