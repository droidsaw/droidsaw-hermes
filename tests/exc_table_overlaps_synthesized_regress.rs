//! Regression: `parse → emit → parse` round-trip on an adversarial v84
//! bundle whose **non-overflowed** function carries the
//! `has_exception_handler` flag and an exception-handler table whose
//! resolved offset points **inside the 128-byte file header**.
//!
//! Mechanism (byte-traced on a fuzzer-found 619-byte crash). Function
//! 11 is not overflowed; its small-header `info_offset` resolves the
//! exception-table offset (`get_exc_table_offset`) to **32**, so the
//! handler-count word is read at `read_u32(buf, 32)` — aliasing the
//! header `file_length` field at bytes [32..36). On the first parse the
//! input bytes there are `00 00 00 00` → count 0 → no handlers. Emit
//! faithfully recomputes `file_length` (= 619 = `0x0000026b`) into bytes
//! 32..36, so the second parse reads count = 619, decodes a bogus
//! handler, and without the guard fails
//! `ExceptionHandlerOutOfFunctionRange`.
//!
//! This is the same region-aliasing class as the overflow large-header
//! overlap (see `overflow_large_header_overlaps_synthesized_regress.rs`)
//! but reached through a function's **exception-handler table** rather
//! than its large function header, and on a **non-overflowed** function
//! — a path the large-header overlap predicate does not cover.
//!
//! The fix records the function as **Unrecognized** at the FIRST parse
//! (a true terminal — its body is never decoded and its aliased table is
//! never range-checked) and `reject_if_unrecognized` then refuses emit
//! with `UnrepresentableIR`, so the round-trip violation cannot manifest.
//! Adversarial-only: a well-formed Hermes bundle never lays an exception
//! table inside the file header.
//!
//! The crash bytes are a checked-in fixture (read via `CARGO_MANIFEST_DIR`,
//! no `/tmp` dependency) so the gate is durable on any checkout / CI.

use droidsaw_hermes::emit::{emit_hbc_v84, HermesEmitError};
use droidsaw_hermes::parser::{HbcFile, HbcFileEquiv, UnrecognizedReason, V84};
use std::path::PathBuf;

/// The 619-byte v84 crash input found by `fuzz_emit_roundtrip_hbc`.
fn crash_bytes() -> Vec<u8> {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests/fixtures/adversarial/exc_table_overlaps_synthesized/v84_exc_table_aliases_file_length.bin");
    std::fs::read(&p)
        .unwrap_or_else(|e| panic!("read fixture {}: {e}", p.display()))
}

#[test]
fn first_parse_records_exc_table_overlap_function_as_unrecognized() {
    let bytes = crash_bytes();
    let hbc = HbcFile::parse(&bytes, None).expect("first parse of the crash bytes");

    // It must match the v84 emit pipeline (otherwise the round-trip
    // wouldn't have hit emit_hbc_v84 in the fuzz target).
    assert!(
        HbcFileEquiv::<V84>::new(&hbc).is_some(),
        "crash input must be a v84 bundle"
    );

    // Exactly the exception-table-overlap function is marked.
    let unrec = hbc.unrecognized_functions();
    assert_eq!(
        unrec.len(),
        1,
        "exactly one function (the exc-table-overlap one) is recover-and-marked"
    );
    let u = unrec[0];
    assert!(
        matches!(
            u.reason,
            UnrecognizedReason::ExceptionTableOverlapsSynthesizedRegion { .. }
        ),
        "reason must be the exception-table-overlap class, got {:?}",
        u.reason
    );
    // The marked function is a true terminal.
    assert!(
        hbc.is_function_unrecognized(u.func_idx),
        "the recover-and-marked function reports as unrecognized"
    );
}

#[test]
fn emit_refuses_round_trip_for_exc_table_overlap() {
    let bytes = crash_bytes();
    let hbc = HbcFile::parse(&bytes, None).expect("first parse of the crash bytes");

    // Emit must refuse with the typed `UnrepresentableIR` (the fuzz
    // target's skip sentinel), NOT produce bytes that crash the second
    // parse. Before the fix, emit_hbc_v84 succeeded and the second parse
    // panicked with ExceptionHandlerOutOfFunctionRange.
    match emit_hbc_v84(&hbc) {
        Err(HermesEmitError::UnrepresentableIR { .. }) => { /* honest refusal */ }
        Ok(emitted) => {
            // If emit ever succeeds again, the round-trip MUST hold.
            let reparsed = HbcFile::parse(&emitted, None);
            panic!(
                "emit_hbc_v84 unexpectedly succeeded ({} bytes); second parse ok={} \
                 — the round-trip-fidelity guard regressed",
                emitted.len(),
                reparsed.is_ok()
            );
        }
        Err(other) => panic!("expected UnrepresentableIR, got {other:?}"),
    }
}
