// SPDX-License-Identifier: BSD-3-Clause

//! Kani Tier-1 proof — V98 disambiguator HEADER_END plausibility floor at
//! `droidsaw_hermes::header::disambiguate_both_options_valid`.
//!
//! Proves the invariant introduced to close the BytecodeOptions
//! overlap discovered during kani audit (via findings doc):
//!
//! For an Early-v98 file with stripped debug
//! (`debug_info_offset[104..108] == 0`) whose `BytecodeOptions` byte at
//! offset 108 is any low-bits-only value (the canonical
//! `BYTECODE_OPTIONS_VALID_MASK & v == 0` shape, i.e. v in 0..=0x07
//! covering all reserved-bit-clean flag combinations), the
//! disambiguator MUST return `Err(HermesError::AmbiguousV98Form)` when
//! `function_count > 0` and `buf.len() > 128`. Without the guard, the loose
//! `debug_with > 0` plausibility check let CBMC enumerate values
//! 1..=7 routing through `Ok(true)` (Late-v98 mis-pick); with the guard the
//! `HEADER_END = 128` floor rejects them as structurally impossible
//! debug offsets and the C-1 escalation fires.
//!
//! **What this proof verifies (production-code gauge):**
//! - Target: production `disambiguate_both_options_valid`. Called
//!   directly with a constructed buffer; if production drops or
//!   relaxes the HEADER_END floor, the proof's typed-Err assertion
//!   fails.
//! - Oracle: boundary structural assertion on the typed-Err return —
//!   no re-derivation of the disambiguation logic in the proof body.
//!
//! **Bounded-domain harness shape.** Rather than driving the function
//! with a 144-byte fully-symbolic buffer (which previously pushed CBMC
//! into a 16 GB / unbounded SAT search), this harness constructs
//! the OVERLAP CLASS DIRECTLY: a hand-built 256-byte buffer with all
//! positions concrete except the BytecodeOptions byte at 108, which is
//! symbolic over the constrained `0..=0x07` low-bits-only range.
//! That's 8 enumerated cases × the function's straight-line path =
//! tight CBMC envelope.

#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::indexing_slicing)]
#![allow(clippy::unwrap_used)]

use crate::HermesError;
use crate::header::disambiguate_both_options_valid;

// BOUNDS: unwind-depth = 4; reason = the function dispatches over a
// constant-size header window + 4 small field projections + an
// optional Finding emit. No loops in the verified path. The Finding
// emit goes through a global drain (telemetry channel) — that's a
// side effect outside the proof's claim and the unwind doesn't reach
// it on the Err arm.

#[kani::proof]
#[kani::unwind(4)]
fn stripped_early_v98_with_strict_mode_set_escalates_to_ambiguous() {
    // 256-byte buffer comfortably above the 128-byte HEADER_END floor
    // and the function_count > 0 + buf.len() > 128 escalation gate.
    let mut buf = [0u8; 256];

    // Symbolic option byte at offset 108 (BYTECODE_OPTIONS_EARLY).
    // Constrained to the low-bits-only range that the upstream
    // detect_late_v98_form mask gate admits as "valid options" —
    // exactly the values that would route the call into the
    // disambiguator AND that without the guard would overflow the `> 0` predicate
    // as a phantom debug offset.
    let option_byte: u8 = kani::any();
    kani::assume(option_byte > 0 && option_byte <= 0x07);
    buf[108] = option_byte;

    // BYTECODE_OPTIONS_LATE at 112: also any low-bits-only value so
    // both options pass the upstream mask gate. Concrete 0x01 picks
    // one valid value; symbolic over 1..=7 here would explode the
    // state space without strengthening the claim (the bug is
    // EARLY-side; we just need LATE to be admissible).
    buf[112] = 0x01;

    // debug_info_offset at 104..108 = 0 (stripped Early-v98).
    // Already zero from buf initialization; explicit for clarity.
    buf[104..108].copy_from_slice(&0u32.to_le_bytes());

    // function_count at offset 40 > 0 triggers the C-1 escalation
    // arm of disambiguate_both_options_valid.
    buf[40..44].copy_from_slice(&1u32.to_le_bytes());

    let result = disambiguate_both_options_valid(&buf);

    // With the guard MUST escalate to AmbiguousV98Form — the HEADER_END = 128
    // plausibility floor rejects the BytecodeOptions byte (value
    // 1..=7) as a candidate debug_info_offset, both projections
    // become not-plausible, and function_count > 0 + buf.len() > 128
    // fires the C-1 fail-closed escalation.
    //
    // Without the guard: `debug_with > 0` would be true (debug_with = u32 from byte
    // 108 padded with zeros = option_byte's low bits), early would be
    // false (stripped), branch would return Ok(true) → silent Late-v98
    // misclassification → wrong layout shifts.
    match result {
        Err(HermesError::AmbiguousV98Form { early, late }) => {
            kani::assert(
                early == option_byte,
                "AmbiguousV98Form carries the early-options byte verbatim",
            );
            kani::assert(
                late == 0x01,
                "AmbiguousV98Form carries the late-options byte verbatim",
            );
        }
        _ => kani::assert(
            false,
            "stripped Early-v98 + low-bits-set BytecodeOptions MUST escalate \
             to AmbiguousV98Form (HEADER_END=128 floor + C-1 escalation)",
        ),
    }
}
