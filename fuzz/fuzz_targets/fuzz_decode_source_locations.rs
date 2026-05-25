#![no_main]

//! Fuzz target for
//! `droidsaw_hermes::parser::debug_info::decode_source_locations`.
//!
//! Outer shape: `(version: u8, data: &[u8])` packed into the libFuzzer
//! `&[u8]` slot. The first byte selects an HBC version (84..=99 modulo
//! the version range the decoder accepts); the remaining bytes are the
//! debug-info varint stream.
//!
//! Invariants on every iteration:
//!
//!   1. No panic on any input.
//!   2. The returned `Vec<FunctionSourceInfo>` is bounded by
//!      `SOURCE_LOCATIONS_MAX_FUNCTIONS` (1 << 22). The function
//!      enforces this internally; we assert it as a guard against
//!      regression.
//!   3. Each function's `locations.len()` is bounded by
//!      `SOURCE_LOCATIONS_MAX_PC_ENTRIES` (1 << 20).
//!   4. Determinism: a second call on the same input produces an
//!      equal `Vec`.
//!   5. Returns `None` only on empty input or first-varint-read
//!      failure (we don't assert this exhaustively; just confirm no
//!      panic on the `None` path).

use droidsaw_hermes::parser::debug_info::decode_source_locations;
use libfuzzer_sys::fuzz_target;

// Mirrored from debug_info.rs (kept here as a local cap-floor; if
// the production caps loosen, this fuzz assertion needs to track).
const SOURCE_LOCATIONS_MAX_FUNCTIONS: usize = 1 << 22;
const SOURCE_LOCATIONS_MAX_PC_ENTRIES: usize = 1 << 20;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let version = u32::from(data[0]).saturating_add(80); // map first byte to 80..=335
    let payload = &data[1..];

    let result = decode_source_locations(payload, version);

    if let Some(ref functions) = result {
        // (2) Function count bound.
        assert!(
            functions.len() <= SOURCE_LOCATIONS_MAX_FUNCTIONS,
            "function count {} exceeds cap {}",
            functions.len(),
            SOURCE_LOCATIONS_MAX_FUNCTIONS
        );

        // (3) Per-function location count bound.
        for (i, f) in functions.iter().enumerate() {
            assert!(
                f.locations.len() <= SOURCE_LOCATIONS_MAX_PC_ENTRIES,
                "function {i} (idx={}) has {} locations, exceeds cap {}",
                f.function_index,
                f.locations.len(),
                SOURCE_LOCATIONS_MAX_PC_ENTRIES
            );
        }
    }

    // (4) Determinism.
    let result2 = decode_source_locations(payload, version);
    assert_eq!(
        result, result2,
        "decode_source_locations nondeterministic on version={version} payload.len={}",
        payload.len()
    );
});
