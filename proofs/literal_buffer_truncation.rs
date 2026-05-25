// SPDX-License-Identifier: BSD-3-Clause

//! Kani Tier-1 proof — `parse_literal_buffer` typed-Err on truncated payload.
//!
//! Four structural claims, one per truncatable type-tag in
//! `parse_literal_buffer`:
//!
//! - Tag 0x30 (Number) expects 8 payload bytes.
//! - Tag 0x40 (LongString) expects 4 payload bytes.
//! - Tag 0x50 (ShortString) expects 2 payload bytes.
//! - Tag 0x70 (Integer) expects 4 payload bytes.
//!
//! For each, when the buffer holds the tag byte plus a payload of fewer
//! than the expected bytes, the function must return
//! `HermesError::TruncatedLiteralBuffer { tag, expected_payload, remaining }`.
//! Without this typed Err, the function would push a phantom-default
//! `LiteralValue` (Number 0.0 / Integer 0 / etc.) AND not advance the
//! buffer pointer, so the outer loop would re-read the partial payload
//! as a new tag — silent resync corruption that catastrophically
//! breaks roundtrip-byte-equality.
//!
//! **What this proof verifies (production-code gauge):** The proof body
//! calls `parser::round_trip::parse_literal_buffer` (production)
//! directly. A regression that drops any of the four typed-Err returns
//! — or swaps `Err` for `Ok` with a phantom value — fails the proof.
//!
//! **Why this proof is well-suited to automated verification:** The
//! claim is a structural invariant the type system cannot enforce. With
//! `buf: [u8; N]` for small `N` (1+payload_size-1), automated verification
//! can enumerate every byte combination and exercise both the tag-decode
//! and truncation-check paths in a single symbolic step. The function's
//! outer loop runs at most once on a single-item buffer.
//!
//! Run with:
//!   cargo kani --package droidsaw-hermes --harness \
//!     literal_buffer_number_truncation_returns_typed_err
//!   (and the three sibling harnesses for tags 0x40 / 0x50 / 0x70)

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "PROOF: Kani test-class code; lint floor relaxed via cfg(kani)."
)]

use crate::error::HermesError;
use crate::parser::round_trip::parse_literal_buffer;

/// Tag 0x30 (Number, 8-byte payload) with only 7 payload bytes available.
/// BOUNDS: buf is [u8; 8] (tag + 7 payload bytes). Outer while loop runs
/// once; the Number arm's `if p + 8 > buf.len()` fires (`p = 1`,
/// `buf.len() = 8`, `1 + 8 = 9 > 8`).
#[kani::proof]
#[kani::unwind(3)]
fn literal_buffer_number_truncation_returns_typed_err() {
    let payload_byte: u8 = kani::any();
    // tag_byte = 0x31 = (0x30 type-mask) | (seq_len 1). Force tag_byte's
    // high bit clear so the short-form path is taken; force the low 4
    // bits to 1 (seq_len). The high 3 bits of type_tag are 0x3.
    let buf: [u8; 8] = [0x31, payload_byte, 0, 0, 0, 0, 0, 0];
    let result = parse_literal_buffer(&buf, 0, 1);
    match result {
        Err(HermesError::TruncatedLiteralBuffer {
            tag,
            expected_payload,
            remaining,
        }) => {
            kani::assert(tag == 0x30, "variant carries the type-tag");
            kani::assert(expected_payload == 8, "Number declares 8-byte payload");
            kani::assert(remaining == 7, "7 bytes left after the tag byte");
        }
        _ => kani::assert(
            false,
            "Number with 7-byte payload must trip TruncatedLiteralBuffer",
        ),
    }
}

/// Tag 0x40 (LongString, 4-byte payload) with only 3 payload bytes.
#[kani::proof]
#[kani::unwind(3)]
fn literal_buffer_long_string_truncation_returns_typed_err() {
    let payload_byte: u8 = kani::any();
    let buf: [u8; 4] = [0x41, payload_byte, 0, 0];
    let result = parse_literal_buffer(&buf, 0, 1);
    match result {
        Err(HermesError::TruncatedLiteralBuffer {
            tag,
            expected_payload,
            remaining,
        }) => {
            kani::assert(tag == 0x40, "variant carries the type-tag");
            kani::assert(expected_payload == 4, "LongString declares 4-byte payload");
            kani::assert(remaining == 3, "3 bytes left after the tag byte");
        }
        _ => kani::assert(
            false,
            "LongString with 3-byte payload must trip TruncatedLiteralBuffer",
        ),
    }
}

/// Tag 0x50 (ShortString, 2-byte payload) with only 1 payload byte.
#[kani::proof]
#[kani::unwind(3)]
fn literal_buffer_short_string_truncation_returns_typed_err() {
    let payload_byte: u8 = kani::any();
    let buf: [u8; 2] = [0x51, payload_byte];
    let result = parse_literal_buffer(&buf, 0, 1);
    match result {
        Err(HermesError::TruncatedLiteralBuffer {
            tag,
            expected_payload,
            remaining,
        }) => {
            kani::assert(tag == 0x50, "variant carries the type-tag");
            kani::assert(expected_payload == 2, "ShortString declares 2-byte payload");
            kani::assert(remaining == 1, "1 byte left after the tag byte");
        }
        _ => kani::assert(
            false,
            "ShortString with 1-byte payload must trip TruncatedLiteralBuffer",
        ),
    }
}

/// Tag 0x70 (Integer, 4-byte payload) with only 3 payload bytes.
#[kani::proof]
#[kani::unwind(3)]
fn literal_buffer_integer_truncation_returns_typed_err() {
    let payload_byte: u8 = kani::any();
    let buf: [u8; 4] = [0x71, payload_byte, 0, 0];
    let result = parse_literal_buffer(&buf, 0, 1);
    match result {
        Err(HermesError::TruncatedLiteralBuffer {
            tag,
            expected_payload,
            remaining,
        }) => {
            kani::assert(tag == 0x70, "variant carries the type-tag");
            kani::assert(expected_payload == 4, "Integer declares 4-byte payload");
            kani::assert(remaining == 3, "3 bytes left after the tag byte");
        }
        _ => kani::assert(
            false,
            "Integer with 3-byte payload must trip TruncatedLiteralBuffer",
        ),
    }
}
