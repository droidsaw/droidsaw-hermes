// SPDX-License-Identifier: BSD-3-Clause

//! Kani Tier-1 proof — `decode_function` typed-Err on malformed input.
//!
//! Two structural claims, one per failure shape:
//!
//! 1. **Unknown opcode** (`opcode_id >= num_opcodes`) must yield
//!    `HermesError::UnknownOpcode`. Without this typed Err, the
//!    decoder silently `break`s on this condition and returns
//!    `Ok(partial_vec)`.
//!
//! 2. **Truncated instruction** (declared instruction size or operand
//!    width extends past the available bytes) must yield
//!    `HermesError::TruncatedInstructionStream`. Without this typed
//!    Err, the decoder `break`s mid-operand-loop, leaving a partial
//!    `DecodedInst` with `operands.len() < op_types.len()` for any
//!    downstream consumer to OOB-index.
//!
//! **What this proof verifies (production-code gauge):** The proof
//! body calls `droidsaw_hermes::decompile::decode::decode_function`
//! (production) directly. `num_opcodes` is looked up via the production
//! `opcodes::get_version_tables` — Kani resolves the version dispatch at
//! proof time. A regression that drops either typed-Err return — e.g.
//! reverting to `break`, or returning a different variant — fails the
//! proof.
//!
//! **Why this proof is well-suited to automated verification:** The
//! claims are structural invariants the type system cannot enforce.
//! `decode_function`'s body is bounded by `while pos < code.len()`;
//! with `code: [u8; 1]` (one symbolic byte) the loop runs at most once.
//! Both proofs use minimal symbolic input (one or two bytes) to keep
//! the search space tractable.
//!
//! Run with:
//!   cargo kani --package droidsaw-hermes --harness \
//!     decode_function_unknown_opcode_returns_typed_err
//!   cargo kani --package droidsaw-hermes --harness \
//!     decode_function_truncated_inst_returns_typed_err

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "PROOF: Kani test-class code; lint floor relaxed via cfg(kani)."
)]

use crate::decompile::decode::decode_function;
use crate::error::HermesError;
use crate::opcodes::get_version_tables;

/// BOUNDS: code is [u8; 1] (a single symbolic byte). `while pos < code.len()`
/// runs at most once before the cap check decides.
#[kani::proof]
#[kani::unwind(3)]
fn decode_function_unknown_opcode_returns_typed_err() {
    // v40 is the lowest supported Hermes bytecode version; its opcode
    // table has fewer than 256 entries, so the "opcode_byte >= num_opcodes"
    // branch is reachable from a symbolic u8.
    let version: u32 = 40;
    let (sizes, _, _) = get_version_tables(version).expect("v40 is supported");
    let num_opcodes = sizes.len();
    // Structurally proves the path is reachable from a u8 symbolic input:
    // if num_opcodes ever grows to >= 256 in a future revision, the proof
    // fails here (alerting the maintainer that the unknown-opcode path
    // needs a different exercise route).
    kani::assert(num_opcodes < 256, "v40 num_opcodes must be < 256 for u8-reach");

    let opcode_byte: u8 = kani::any();
    kani::assume(usize::from(opcode_byte) >= num_opcodes);

    let code = [opcode_byte];
    let result = decode_function(&code, version);
    match result {
        Err(HermesError::UnknownOpcode {
            offset,
            opcode_id,
            num_opcodes: nopc,
        }) => {
            kani::assert(offset == 0, "byte at offset 0");
            kani::assert(opcode_id == opcode_byte, "variant carries the byte");
            kani::assert(nopc == num_opcodes, "variant carries num_opcodes");
        }
        _ => kani::assert(
            false,
            "opcode_id >= num_opcodes must yield UnknownOpcode",
        ),
    }
}

/// BOUNDS: code is [u8; 1] (a single symbolic byte). The proof picks a
/// multi-byte opcode and provides no operand bytes; the cap fires on the
/// first inst_end > code.len() check.
#[kani::proof]
#[kani::unwind(3)]
fn decode_function_truncated_inst_returns_typed_err() {
    let version: u32 = 96;
    let (sizes, _, _) = get_version_tables(version).expect("v96 is supported");
    let num_opcodes = sizes.len();

    let opcode_byte: u8 = kani::any();
    let opcode_idx = usize::from(opcode_byte);
    kani::assume(opcode_idx < num_opcodes);
    // Pick out the multi-byte subset by assumption (Kani enumerates u8
    // values whose declared size > 1).
    let inst_size = sizes[opcode_idx];
    kani::assume(inst_size > 1);

    // Provide only the opcode byte — no operand bytes. inst_end = 1 +
    // (inst_size - 1) > code.len() = 1 so the truncated-instruction
    // path fires.
    let code = [opcode_byte];
    let result = decode_function(&code, version);
    match result {
        Err(HermesError::TruncatedInstructionStream { offset, opcode_id }) => {
            kani::assert(offset == 0, "truncated inst starts at offset 0");
            kani::assert(opcode_id == opcode_byte, "variant carries the byte");
        }
        _ => kani::assert(
            false,
            "declared inst_size > remaining bytes must yield TruncatedInstructionStream",
        ),
    }
}
