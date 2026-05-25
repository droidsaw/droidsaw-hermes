// SPDX-License-Identifier: BSD-3-Clause

//! Kani Tier-1 proof — `exception_count_is_capped` is sound +
//! exhaustive over the full `u32` state-space.
//!
//! `HbcFile::function_exception_count` (silent path, returns 0 +
//! emits a Finding on cap) and `HbcFile::function_exception_count_checked`
//! (strict path, returns Err on cap) both gate on the same predicate
//! `exception_count_is_capped(declared)`. This proof verifies two
//! structural invariants on the predicate:
//!
//! 1. **Soundness**: `exception_count_is_capped(declared) == true`
//!    iff `declared > MAX_EXCEPTION_HANDLERS`. A regression that
//!    swapped `>` for `>=`, `<`, or any wrong constant would fail.
//!
//! 2. **Boundary exact**: at `declared == MAX_EXCEPTION_HANDLERS`,
//!    the predicate returns `false` (the cap is "exceeds", not "≥").
//!    At `declared == MAX_EXCEPTION_HANDLERS + 1`, it returns `true`.
//!
//! **Why this proof is well-suited to automated verification:**
//! `exception_count_is_capped` is a `const fn` taking a single `u32`
//! input. Automated verification enumerates the full `u32` state-space
//! symbolically in a single step. The proof is non-tautological: a
//! regression flipping the operator, dropping the const, or off-by-one
//! in the cap constant fails.
//!
//! The Kani harness deliberately does NOT exercise
//! `function_exception_count` directly — constructing a synthetic
//! `HbcFile` in Kani would push the proof into Tier-3 cost (parser
//! graph + heap-modeling explosion, same root cause as the
//! documented `decode_mutf8` intractability). Instead the predicate
//! captures the structural invariant both accessors gate on; the
//! accessors' integration tests in `tests/` exercise the
//! `predicate-trip → Finding-emit` and `predicate-trip → typed-Err`
//! couplings.
//!
//! Run with:
//!   cargo kani --package droidsaw-hermes --harness \
//!     exception_count_is_capped_predicate_is_sound

#![allow(
    clippy::expect_used,
    reason = "PROOF: Kani test-class code; lint floor relaxed via cfg(kani)."
)]

use crate::finding::MAX_EXCEPTION_HANDLERS;
use crate::parser::HbcFile;

/// BOUNDS: no unwind attribute — the predicate is loop-free
/// (`declared > MAX_EXCEPTION_HANDLERS`). Kani evaluates it
/// symbolically in one step.
#[kani::proof]
fn exception_count_is_capped_predicate_is_sound() {
    let declared: u32 = kani::any();
    let capped = HbcFile::exception_count_is_capped(declared);
    kani::assert(
        capped == (declared > MAX_EXCEPTION_HANDLERS),
        "exception_count_is_capped(declared) must equal `declared > MAX_EXCEPTION_HANDLERS`",
    );
}

/// Boundary check: at the cap exactly, predicate returns false.
#[kani::proof]
fn exception_count_at_cap_is_not_capped() {
    let capped = HbcFile::exception_count_is_capped(MAX_EXCEPTION_HANDLERS);
    kani::assert(
        !capped,
        "declared == MAX_EXCEPTION_HANDLERS must NOT be capped (cap is `>`, not `>=`)",
    );
}

/// Boundary check: one above the cap, predicate returns true.
#[kani::proof]
fn exception_count_one_above_cap_is_capped() {
    let capped = HbcFile::exception_count_is_capped(MAX_EXCEPTION_HANDLERS + 1);
    kani::assert(
        capped,
        "declared == MAX_EXCEPTION_HANDLERS + 1 must be capped",
    );
}
