// SPDX-License-Identifier: BSD-3-Clause

//! Kani Tier-1 proof — `overflow_header_is_oob` is sound + total over
//! the full `(u64, usize)` state-space, including the u64-overflow path.
//!
//! `HbcFile::function_get` (silent path, returns small-header
//! FunctionData + emits a Finding on OOB) and
//! `HbcFile::function_get_checked` (strict path, returns Err on OOB)
//! both gate on the same predicate
//! `overflow_header_is_oob(large_off, buf_len)`. This proof verifies
//! the predicate is structurally sound:
//!
//! 1. **OOB iff sum exceeds buf_len**: for any
//!    `(large_off, buf_len)` where
//!    `large_off + LARGE_FUNCTION_HEADER_SIZE` fits in `u64`,
//!    `overflow_header_is_oob == ((large_off + 40) > buf_len)`.
//!
//! 2. **u64-overflow always OOB**: if `large_off > u64::MAX - 40`,
//!    the predicate returns `true` regardless of `buf_len`. The brief
//!    explicitly called out this attacker-reachable shape (an
//!    `overflowed` claim with a near-`u64::MAX` composed offset).
//!
//! 3. **Boundary exact**: at `large_off + 40 == buf_len` (exact fit),
//!    the predicate returns `false` (NOT OOB). At
//!    `large_off + 40 == buf_len + 1`, it returns `true`.
//!
//! **Why this proof is well-suited to automated verification:**
//! `overflow_header_is_oob` is a `const fn` taking `(u64, usize)`.
//! Automated verification enumerates the cross-product state-space
//! symbolically. The main soundness harness uses a **u128 independent
//! oracle** rather than re-deriving production's `checked_add`-on-u64
//! verbatim — u128 cannot overflow at this scale (`u64 + 40 << u128::MAX`),
//! so the oracle's arithmetic primitive is structurally different from
//! production's. A regression that drops production's `checked_add`
//! (silently wrapping u64) would diverge from the u128 oracle and
//! fail the proof; a coordinated regression in both sides cannot
//! occur because the oracle uses a fundamentally different arithmetic
//! type. The three boundary harnesses (exact-fit, one-past-fit,
//! u64-overflow) pin specific points structurally without invoking
//! any arithmetic primitive at all.
//!
//! Run with:
//!   cargo kani --package droidsaw-hermes --harness \
//!     overflow_header_is_oob_predicate_is_sound

#![allow(
    clippy::expect_used,
    reason = "PROOF: Kani test-class code; lint floor relaxed via cfg(kani)."
)]

use crate::parser::{HbcFile, LARGE_FUNCTION_HEADER_SIZE};

/// BOUNDS: no unwind attribute — the predicate is a single
/// `checked_add` + comparison. Kani evaluates it in one step.
///
/// Independent oracle: u128 arithmetic. `u64 + 40` cannot overflow
/// in u128 (the u128 ceiling is `2^128`, vastly above `2^64 + 40`),
/// so the oracle's primitive is structurally different from
/// production's `checked_add`-on-u64 path. Production and oracle
/// converge on the same boolean for every `(u64, usize)` input only
/// when production correctly handles the u64-overflow case.
#[kani::proof]
fn overflow_header_is_oob_predicate_is_sound() {
    let large_off: u64 = kani::any();
    let buf_len: usize = kani::any();
    let oob = HbcFile::overflow_header_is_oob(large_off, buf_len);

    // Independent oracle: lift both operands to u128 (no overflow at
    // this scale) and compute the OOB condition directly. The oracle
    // never invokes `checked_add` — a regression that drops
    // `checked_add` in production silently wraps u64, the oracle
    // doesn't wrap, and the proof fails.
    let expected: bool = {
        let end_u128 = (large_off as u128) + (LARGE_FUNCTION_HEADER_SIZE as u128);
        end_u128 > (buf_len as u128)
    };

    kani::assert(
        oob == expected,
        "overflow_header_is_oob must agree with the u128 independent oracle for every (u64, usize) input",
    );
}

/// Boundary check: exact-fit (`large_off + 40 == buf_len`) is NOT OOB.
#[kani::proof]
fn overflow_header_exact_fit_is_not_oob() {
    let buf_len: usize = kani::any();
    kani::assume(buf_len >= LARGE_FUNCTION_HEADER_SIZE);
    let large_off = (buf_len - LARGE_FUNCTION_HEADER_SIZE) as u64;
    let oob = HbcFile::overflow_header_is_oob(large_off, buf_len);
    kani::assert(
        !oob,
        "large_off + LARGE_FUNCTION_HEADER_SIZE == buf_len must NOT be OOB",
    );
}

/// Boundary check: one byte past fit (`large_off + 40 == buf_len + 1`)
/// IS OOB.
#[kani::proof]
fn overflow_header_one_past_fit_is_oob() {
    let buf_len: usize = kani::any();
    // Need buf_len + 1 - LARGE_FUNCTION_HEADER_SIZE to be a valid u64
    // representable; constrain accordingly.
    kani::assume(buf_len < usize::MAX);
    let large_off = match (buf_len + 1).checked_sub(LARGE_FUNCTION_HEADER_SIZE) {
        Some(v) => v as u64,
        None => return, // buf_len + 1 < 40; nothing to assert (the
                        // predicate is trivially OOB in this region;
                        // the previous harness covers it).
    };
    let oob = HbcFile::overflow_header_is_oob(large_off, buf_len);
    kani::assert(
        oob,
        "large_off + LARGE_FUNCTION_HEADER_SIZE == buf_len + 1 MUST be OOB",
    );
}

/// u64-overflow case: `large_off > u64::MAX - 40` MUST be OOB
/// regardless of `buf_len`.
#[kani::proof]
fn overflow_header_u64_overflow_is_oob() {
    let large_off: u64 = kani::any();
    let buf_len: usize = kani::any();
    kani::assume(large_off > u64::MAX - LARGE_FUNCTION_HEADER_SIZE as u64);
    let oob = HbcFile::overflow_header_is_oob(large_off, buf_len);
    kani::assert(
        oob,
        "u64-overflow on large_off + LARGE_FUNCTION_HEADER_SIZE MUST be OOB",
    );
}
