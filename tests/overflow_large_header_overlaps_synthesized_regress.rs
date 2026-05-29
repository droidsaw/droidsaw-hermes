//! Regression: `parse → emit → parse` round-trip on adversarial inputs
//! whose overflowed function carries a tiny `large_off`, so its 40-byte
//! SecondaryFuncHeader physically overlaps a region emit recomputes from
//! IR. Emit's faithful recompute of that region overwrites bytes the
//! overlapping large header re-reads on the next parse, mutating that
//! function's `offset`/`size`/`flags` and breaking the round-trip.
//!
//! Three overlap classes are exercised, each built deterministically
//! in-test (no `/tmp` reads, no checked-in `.bin`) so the gate is durable
//! on any checkout / CI / machine:
//!
//!   - `v96`: overflowed function's large header overlaps the 128-byte
//!     **file header**; the aliased byte lands in the large-header
//!     `offset` field → body region grows past the bytecode region → the
//!     second parse fails `FunctionBodyOutOfBytecodeRegion` without the
//!     guard. (Replica of the fuzzer-found repro shape.)
//!   - `v98`: overflowed function's large header overlaps the **file
//!     header**; the aliased byte is the large-header `flags` byte →
//!     `has_exception` flips on → an exception table is read from header
//!     bytes → the second parse fails `ExceptionHandlerOutOfFunctionRange`
//!     without the guard. (Replica of the fuzzer-found repro shape.)
//!   - `v97 ObjShapeTable`: overflowed function's large header overlaps
//!     the **ObjShapeTable** — a SYNTHESIZE region the v97/v98/v99 emit
//!     path recomputes (`emit_obj_shape_table_v98`). If this region is
//!     missing from the overlap predicate's source-of-truth span set the
//!     overlap is not caught and the round-trip silently corrupts the
//!     shape table.
//!
//! The guard records the overlapping function as **Unrecognized** at the
//! FIRST parse (a true terminal — its body is never decoded at the
//! aliased offset) and `reject_if_unrecognized` then refuses emit with
//! `UnrepresentableIR`, so the round-trip violation cannot manifest.
//! Region-aliasing is adversarial-only: a well-formed Hermes bundle never
//! lays a large header inside a synthesized region.

use droidsaw_hermes::emit::{emit_hbc, emit_hbc_v98, emit_hbc_v99, HermesEmitError};
use droidsaw_hermes::parser::{HbcFile, UnrecognizedReason};

const HBC_MAGIC: u64 = 0x1F19_03C1_03BC_1FC6;

/// Build a v96 HBC whose single overflowed function lays its large
/// header **inside the 128-byte file header**. The small header's
/// `info_offset = 0` and `offset = 32` compose to `large_off =
/// (0 << 16) | 32 = 32`, so the 40-byte large header spans [32..72) —
/// overlapping `file_length` at [32..36). This is the v96 `/tmp` repro
/// shape (single body-region symptom), built deterministically.
fn build_v96_header_overlap() -> Vec<u8> {
    // 128B header + 1×16B FunctionHeaders entry = 144B. The large header
    // span [32..72) is in-bounds (< 144) so it is the OVERLAP path, not
    // the OOB path.
    let mut buf = vec![0u8; 144];
    buf[0..8].copy_from_slice(&HBC_MAGIC.to_le_bytes());
    buf[8..12].copy_from_slice(&96u32.to_le_bytes());
    buf[32..36].copy_from_slice(&144u32.to_le_bytes()); // file_length
    buf[40..44].copy_from_slice(&1u32.to_le_bytes()); // function_count = 1

    // f0 SmallFuncHeader @128 (v96 16-byte stride):
    //   offset (bits 0..25)        = 32  → composes large_off low 16 bits
    //   info_offset (bits 64..89)  = 0   → composes large_off high bits
    //   flags @entry[15] bit 5 set       = overflowed
    // large_off = (info_offset << 16) | offset = 32.
    buf[128..132].copy_from_slice(&32u32.to_le_bytes()); // offset = 32
    // word 2 (bytes 8..12 of the entry) carries info_offset low 25 bits = 0.
    buf[143] = 0x20; // entry[15] = absolute 128+15 = 143; bit 5 = overflow
    buf
}

/// Build a v98 (late/v99 layout) HBC whose single overflowed function
/// lays its large header **inside the file header**, with the aliased
/// byte falling on the large-header `flags` byte (the `has_exception`
/// path — the v98 `/tmp` repro symptom). `large_off = 1` places the
/// 40-byte large header at [1..41); the large-header flags byte sits at
/// `large_off + 31 = 32`, the same byte as `file_length`.
fn build_v98_header_overlap() -> Vec<u8> {
    // 128B header + 1×12B FunctionHeaders entry = 140B. large header span
    // [1..41) is in-bounds (< 140) → OVERLAP path.
    let mut buf = vec![0u8; 140];
    buf[0..8].copy_from_slice(&HBC_MAGIC.to_le_bytes());
    buf[8..12].copy_from_slice(&98u32.to_le_bytes());
    buf[32..36].copy_from_slice(&140u32.to_le_bytes()); // file_length
    buf[40..44].copy_from_slice(&1u32.to_le_bytes()); // function_count = 1
    // Disambiguate v98 form: the early-form BytecodeOptions byte (108) is
    // set non-MBZ-valid (a reserved bit set) so early_valid=false, while
    // the late-form byte (112) stays zero so late_valid=true → unambiguous
    // LATE form (large_off = (func_name << 24) | offset).
    buf[108] = 0x80;

    // f0 SmallFuncHeader @128 (v98 12-byte stride, late/v99 layout):
    //   offset (bits 0..25)  = 1
    //   func_name (bits 46..54) = 0
    //   flags @entry[11] bit 5 set = overflowed
    // late-v98/v99 large_off = (func_name << 24) | offset = 1.
    buf[128..132].copy_from_slice(&1u32.to_le_bytes()); // offset = 1
    buf[128 + 11] = 0x20; // entry[11] bit 5 = overflow
    buf
}

/// Build a v99 HBC carrying one ObjShapeTable entry, with a single
/// overflowed function whose large header overlaps the **ObjShapeTable**.
/// v99 is used (not v97) because emit supports v84/v96/v98/v99 — v97 has
/// no emit pipeline, so the round-trip closure (`reject_if_unrecognized`)
/// can only be exercised on an emit-supported version. v99 shares the
/// v98-late layout + `emit_hbc_v98_or_v99` ObjShapeTable synthesize path.
///
/// Layout (v99, 12-byte FunctionHeaders): Header[0..128) +
/// FunctionHeaders[128..140) (1 entry) + zero-sized middle sections +
/// ObjShapeTable[140..148) (1 entry, 8 bytes). The overflowed function's
/// `offset = 140`, `func_name = 0` → `large_off = (0 << 24) | 140 = 140`,
/// so its 40-byte large header spans [140..180), overlapping the
/// ObjShapeTable at [140..148). The buffer is 180 bytes so the large
/// header is in-bounds (OVERLAP path, not OOB).
fn build_v99_obj_shape_table_overlap() -> Vec<u8> {
    let mut buf = vec![0u8; 180];
    buf[0..8].copy_from_slice(&HBC_MAGIC.to_le_bytes());
    buf[8..12].copy_from_slice(&99u32.to_le_bytes());
    buf[32..36].copy_from_slice(&180u32.to_le_bytes()); // file_length
    buf[40..44].copy_from_slice(&1u32.to_le_bytes()); // function_count = 1
    buf[88..92].copy_from_slice(&1u32.to_le_bytes()); // obj_shape_table_count = 1

    // f0 SmallFuncHeader @128 (v99 12-byte stride, V98LateToV99 layout):
    //   offset (bits 0..25)   = 140
    //   func_name (bits 46..54) = 0
    //   flags @entry[11] bit 5 set = overflowed
    // V98LateToV99 large_off = (func_name << 24) | offset = 140.
    buf[128..132].copy_from_slice(&140u32.to_le_bytes()); // offset = 140
    buf[128 + 11] = 0x20; // entry[11] bit 5 = overflow

    // ObjShapeTable @140: one 8-byte entry (key_buffer_offset, num_props).
    // Contents are immaterial — the test asserts the overlap is caught,
    // not the entry values.
    buf[140..144].copy_from_slice(&0u32.to_le_bytes());
    buf[144..148].copy_from_slice(&0u32.to_le_bytes());
    buf
}

/// Assert at least one function is marked Unrecognized with the overlap
/// reason, and that every such index reports `is_function_unrecognized
/// == true` (the terminal-decode gate downstream consumers honor).
fn assert_overlap_unrecognized(hbc: &HbcFile<'_>) {
    let overlaps: Vec<u32> = hbc
        .unrecognized_functions()
        .iter()
        .filter(|u| {
            matches!(
                u.reason,
                UnrecognizedReason::OverflowedHeaderOverlapsSynthesizedRegion { .. }
            )
        })
        .map(|u| u.func_idx)
        .collect();
    assert!(
        !overlaps.is_empty(),
        "expected at least one overlap-class Unrecognized function"
    );
    for idx in overlaps {
        assert!(
            hbc.is_function_unrecognized(idx),
            "overlap function {idx} must report is_function_unrecognized() == true (terminal)"
        );
    }
}

#[test]
fn v96_header_overlap_function_is_unrecognized_terminal() {
    let bytes = build_v96_header_overlap();
    let hbc = HbcFile::parse(&bytes, None).expect("first parse must succeed");
    assert_eq!(hbc.version, 96);
    assert_overlap_unrecognized(&hbc);
}

#[test]
fn v98_header_overlap_function_is_unrecognized_terminal() {
    let bytes = build_v98_header_overlap();
    let hbc = HbcFile::parse(&bytes, None).expect("first parse must succeed");
    assert_eq!(hbc.version, 98);
    assert_overlap_unrecognized(&hbc);
}

/// The FIX's primary regression: an overflowed function whose large
/// header overlaps the ObjShapeTable (a v97/v98/v99 SYNTHESIZE region)
/// is recover-marked Unrecognized. Before adding `obj_shape_table` to the
/// predicate's source-of-truth span set, this function parsed clean with
/// an attacker-aliased offset and emit silently corrupted the shape table
/// on round-trip.
#[test]
fn v99_obj_shape_table_overlap_function_is_unrecognized_terminal() {
    let bytes = build_v99_obj_shape_table_overlap();
    let hbc = HbcFile::parse(&bytes, None).expect("first parse must succeed");
    assert_eq!(hbc.version, 99);
    assert_eq!(hbc.shape_table_count(), 1, "ObjShapeTable must be present");
    assert_overlap_unrecognized(&hbc);
}

#[test]
fn v96_emit_refused_so_roundtrip_holds() {
    let bytes = build_v96_header_overlap();
    let hbc = HbcFile::parse(&bytes, None).expect("first parse must succeed");
    // Emit must now refuse (overlap function is Unrecognized →
    // reject_if_unrecognized) rather than producing bytes that fail the
    // second parse with FunctionBodyOutOfBytecodeRegion.
    match emit_hbc(&hbc) {
        Err(HermesEmitError::UnrepresentableIR { .. }) => {}
        Ok(emitted) => {
            // If emit ever DID produce bytes, the second parse must not
            // regress — but with the fix it should not reach here.
            let _ = HbcFile::parse(&emitted, None)
                .expect("second parse must not fail (no FunctionBodyOutOfBytecodeRegion)");
            panic!("emit unexpectedly succeeded on an Unrecognized-bearing file");
        }
        Err(other) => panic!("expected UnrepresentableIR, got {other}"),
    }
}

#[test]
fn v98_emit_refused_so_roundtrip_holds() {
    let bytes = build_v98_header_overlap();
    let hbc = HbcFile::parse(&bytes, None).expect("first parse must succeed");
    // Emit must now refuse rather than producing bytes that fail the
    // second parse with ExceptionHandlerOutOfFunctionRange.
    match emit_hbc_v98(&hbc) {
        Err(HermesEmitError::UnrepresentableIR { .. }) => {}
        Ok(emitted) => {
            let _ = HbcFile::parse(&emitted, None)
                .expect("second parse must not fail (no ExceptionHandlerOutOfFunctionRange)");
            panic!("emit unexpectedly succeeded on an Unrecognized-bearing file");
        }
        Err(other) => panic!("expected UnrepresentableIR, got {other}"),
    }
}

/// The ObjShapeTable overlap must also block emit (round-trip closure for
/// the newly-covered region). `emit_hbc_v98` handles v98/v99 via the
/// shared `emit_hbc_v98_or_v99` path.
#[test]
fn v99_obj_shape_table_overlap_emit_refused() {
    let bytes = build_v99_obj_shape_table_overlap();
    let hbc = HbcFile::parse(&bytes, None).expect("first parse must succeed");
    match emit_hbc_v99(&hbc) {
        Err(HermesEmitError::UnrepresentableIR { .. }) => {}
        Ok(emitted) => {
            let _ = HbcFile::parse(&emitted, None)
                .expect("second parse must not fail");
            panic!("emit unexpectedly succeeded on an Unrecognized-bearing file");
        }
        Err(other) => panic!("expected UnrepresentableIR, got {other}"),
    }
}
