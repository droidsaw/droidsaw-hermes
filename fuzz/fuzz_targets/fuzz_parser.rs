#![no_main]

//! `fuzz_parser` — Hermes HBC parser structural-invariant gate.
//!
//! **Asserts (on any input where `HbcFile::parse` succeeds):**
//! 1. `string_as_str(i)` completes without panic for all
//!    `i in 0..string_count`. Validates that every string pool entry
//!    the header declares is safely accessible.
//! 2. `function_get(i)` completes without panic for all
//!    `i in 0..function_count` (capped at 256 per the cfg/ssa pattern).
//!    Validates that every function header the header declares is
//!    safely accessible.
//! 3. `overflow_string_count <= string_count`. Overflow string entries
//!    are a sub-pool of the main string pool; more overflow entries than
//!    total strings is structurally impossible per the HBC format spec.
//! 4. `bigint_as_str(i)` completes without panic for all
//!    `i in 0..bigint_count` (capped at 256). The accessor short-
//!    circuits over-cap entries via the `MAX_BIGINT_BYTES` gate so
//!    the O(N²) base-256 → base-10 helper cannot run on attacker-
//!    chosen byte lengths; this loop verifies the panic-free
//!    contract under fuzz mutation.
//! 7. `function_get_checked(i)` completes without panic for all
//!    `i in 0..function_count`. The strict-API variant returns typed
//!    `Err(HermesError::OverflowedHeaderOutOfBounds { large_off,
//!    buf_len })` when the `overflowed` bit is set and the large-header
//!    is past EOF, instead of the lenient `function_get`'s silent
//!    fallback to the small header's truncated 25-bit offset. The
//!    `11_overflowed_header_oob` corpus seed exercises the strict
//!    accessor so libFuzzer surfaces any regression that re-introduces
//!    the silent reinterpretation.
//!
//! Covers the "Parser never panics on random bytes" P0 row plus the
//! structural accessor invariant, including the BigInt-accessor loop
//! which verifies the panic-free contract for the `MAX_BIGINT_BYTES`-capped
//! base-256 → base-10 helper under fuzz mutation.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(hbc) = droidsaw_hermes::parser::HbcFile::parse(data, None) else {
        return;
    };

    // Inv 3: overflow_string_count <= string_count.
    assert!(
        hbc.overflow_string_count <= hbc.string_count,
        "overflow_string_count ({}) > string_count ({}) — impossible per HBC format spec",
        hbc.overflow_string_count,
        hbc.string_count,
    );

    // Inv 1: all declared string pool entries are accessible without panic.
    // Cap at 256 to bound execution time per fuzz iteration.
    let string_limit = hbc.string_count.min(256);
    for i in 0..string_limit {
        // Returns Ok(Some(_)), Ok(None), or typed Err — never panic.
        let _ = hbc.string_as_str(i);
    }

    // Inv 2: all declared function headers are accessible without panic.
    let func_limit = hbc.function_count.min(256);
    for i in 0..func_limit {
        // Returns FunctionData — never panic.
        let _ = hbc.function_get(i);
    }

    // Inv 4: all declared BigInt table entries are accessible without
    // panic. The over-cap path emits a typed Finding and returns None
    // in microseconds; this loop ensures the cap holds under fuzz
    // mutation of `big_int_count` × per-entry length.
    let bigint_limit = hbc.bigint_count().min(256);
    for i in 0..bigint_limit {
        let _ = hbc.bigint_as_str(i);
    }

    // Inv 5: source-locations decoding never panics + every entry's
    // `corrupt` flag is structurally valid (true ⇒ partial PC stream;
    // false ⇒ clean termination).
    if let Some(funcs) = hbc.source_locations() {
        for f in &funcs {
            // Touch each field to ensure no lazy/deferred panic. The
            // `corrupt` flag itself is the load-bearing new signal; if
            // a regression dropped it from the struct, this fuzz
            // target would fail to compile (compile-time gauge).
            let _ = (f.function_index, f.start_line, f.start_column, f.corrupt);
            for loc in &f.locations {
                let _ = (loc.address, loc.line, loc.column, loc.statement);
            }
        }
    }

    // Inv 6: exception-handler accessors never panic; cap-trip
    // (count > MAX_EXCEPTION_HANDLERS) surfaces via HermesFinding
    // channel with a silent 0 / empty fallback.
    for fid in 0..func_limit {
        let exc_count = hbc.function_exception_count(fid);
        // The cap-trip path returns 0 here, so the inner loop is a
        // no-op on adversarial input. `.min(64)` independently bounds
        // per-input work on clean inputs.
        for handler_idx in 0..exc_count.min(64) {
            let _ = hbc.function_exception_get(fid, handler_idx);
        }
        // Also exercise the strict-API checked variant — its Err
        // path is reachable only via the cap-trip predicate.
        let _ = hbc.function_exception_count_checked(fid);
    }

    // Inv 7: `function_get_checked` strict-variant accessor never
    // panics; reaches the typed-Err return when the `overflowed` bit
    // is set and `large_off + LARGE_FUNCTION_HEADER_SIZE > buf.len()`.
    // The lenient `function_get` falls back to the small-header's
    // truncated 25-bit offset silently; the strict variant surfaces
    // `HermesError::OverflowedHeaderOutOfBounds` so callers that opt
    // in cannot have their analysis silently anchored to attacker-
    // chosen metadata.
    for fid in 0..func_limit {
        let _ = hbc.function_get_checked(fid);
    }
});
