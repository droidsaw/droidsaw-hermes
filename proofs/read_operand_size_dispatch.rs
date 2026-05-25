// SPDX-License-Identifier: BSD-3-Clause

//! Kani Tier-1 proof — `read_operand` size dispatch at
//! `droidsaw_hermes::scanner::read_operand`.
//!
//! Proves: for an 8-byte symbolic code buffer + symbolic `pos` and
//! `size`, `read_operand` returns `Some(v)` iff `size ∈ {1, 2, 4}` AND
//! `pos.checked_add(size as usize)` ≤ `code.len()`. On `Some`, `v`
//! matches a u64-accumulator independent oracle that assembles the
//! little-endian bytes via shift-and-OR — computationally distinct
//! from production's `u16/u32::from_le_bytes` LLVM intrinsics.
//!
//! **What this proof verifies (production-code gauge):**
//! - Target: production `read_operand`. Called directly; if production
//!   has a bug, the proof fails.
//! - Oracle: per-byte u64 accumulator. A regression accepting an
//!   illegal `size` (e.g. `size = 3` returning `Some(0)` instead of
//!   `None`) would surface as the dispatch returning `Some` where the
//!   oracle says `None`.
//!
//! **Dominator proven**: the `match size { 1 | 2 | 4 => ..., _ =>
//! None }` dispatch. A typo widening the accepted set (e.g. adding
//! `3` to the match arm) would silently OOB-read downstream
//! consumers expecting the canonical sizes.
//!
//! **Bounds check**: `pos + size <= code.len()` via `pos.checked_add`.
//! Asserted via the oracle: on `None`, either size is not in {1,2,4}
//! or the bounds-check failed.

#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::indexing_slicing)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::as_conversions)]

use crate::scanner::read_operand;

// BOUNDS: unwind-depth = 5; reason = read_operand has no loops; the
// match-then-from-le-bytes is straight-line. Oracle accumulator
// iterates at most 4 bytes.

#[kani::proof]
#[kani::unwind(5)]
fn read_operand_size_dispatch_and_le_assembly() {
    let code: [u8; 8] = kani::any();
    let pos: usize = kani::any();
    let size: u8 = kani::any();
    kani::assume(pos <= 8);

    let production = read_operand(&code, pos, size);

    // Oracle: production returns Some iff size ∈ {1, 2, 4} AND the
    // window [pos, pos+size) fits in code.
    let valid_size = size == 1 || size == 2 || size == 4;
    let in_bounds = (pos as u64).saturating_add(size as u64) <= code.len() as u64;
    let expected_some = valid_size && in_bounds;

    match (production, expected_some) {
        (None, false) => {
            // Both reject — agreement on the rejection arm.
        }
        (Some(v), true) => {
            // Per-byte u64-accumulator oracle: assemble LE bytes via
            // shift-and-OR. Computationally distinct from production's
            // u16/u32::from_le_bytes.
            let mut acc: u64 = 0;
            for i in 0..(size as usize) {
                acc |= (code[pos + i] as u64) << (8 * i);
            }
            kani::assert(
                u64::from(v) == acc,
                "read_operand result agrees with per-byte LE u64 accumulator",
            );
        }
        (Some(_), false) => kani::assert(
            false,
            "read_operand returned Some on an out-of-spec input (size ∉ {1,2,4} or OOB)",
        ),
        (None, true) => kani::assert(
            false,
            "read_operand returned None on a valid in-bounds canonical-size input",
        ),
    }
}
