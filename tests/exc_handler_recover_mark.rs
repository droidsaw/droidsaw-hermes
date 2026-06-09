//! Per-function containment of out-of-range exception-handler triples.
//!
//! A handler `(start, end, target)` that violates `start < end &&
//! end <= fn_size && target < fn_size` used to hard-fail the whole
//! bundle at region validation
//! (`HermesError::ExceptionHandlerOutOfFunctionRange` from
//! `HbcFile::parse`). The damage is confined to one function's handler
//! metadata — the body span was already proven in-region and
//! non-overlapping — so the parse now recover-marks the offending
//! function `UnrecognizedReason::ExceptionHandlerOutOfFunctionRange`
//! (terminal: never decoded; the typed error surfaces from decompile
//! on the marked index) and every other function stays honestly
//! parseable.
//!
//! Also pinned here: the sorted-merge invariant of the unrecognized
//! side-set. Pass-3 marks (bad handler triples) can carry LOWER
//! function indices than Pass-1 marks (broken overflow claims);
//! naively appending them would break the ascending order that
//! `is_function_unrecognized`'s binary search relies on.
//!
//! All fixtures are synthetic, built deterministically in-test on the
//! v99 wire layout (unambiguous 36-byte large headers, so layout
//! selection plays no part in what these tests prove).

use droidsaw_hermes::finding::{HermesFinding, drain_findings_for_test};
use droidsaw_hermes::parser::{HbcFile, UnrecognizedReason};

const HBC_MAGIC: u64 = 0x1F19_03C1_03BC_1FC6;

/// Geometry: Header[0..128) + FunctionHeaders[128..140) (1 × 12-byte
/// entry) → region starts 140. Body [144..208) (offset 144, size 64),
/// 36-byte large header at 208, exception table @ align4(208+36) =
/// 244. File is 260 bytes so the conservative large-header OOB bound
/// (`large_off + 40 <= len`) holds.
const LARGE_OFF: usize = 208;
const BODY_OFF: u32 = 144;
const BODY_SIZE: u32 = 64;

/// v99 bundle with one overflowed function whose exception table
/// carries the given `(start, end, target)` triple.
fn build_v99_with_triple(start: u32, end: u32, target: u32) -> Vec<u8> {
    let mut buf = vec![0u8; 260];
    buf[0..8].copy_from_slice(&HBC_MAGIC.to_le_bytes());
    buf[8..12].copy_from_slice(&99u32.to_le_bytes());
    buf[32..36].copy_from_slice(&260u32.to_le_bytes()); // file_length
    buf[40..44].copy_from_slice(&1u32.to_le_bytes()); // function_count = 1

    // f0 SmallFuncHeader @128: offset bitfield = LARGE_OFF (low bits
    // of large_off), func_name = 0, flags bit 5 = overflowed.
    buf[128..132].copy_from_slice(&(LARGE_OFF as u32).to_le_bytes());
    buf[128 + 11] = 0x20;

    // 36-byte large header @208.
    buf[LARGE_OFF..LARGE_OFF + 4].copy_from_slice(&BODY_OFF.to_le_bytes());
    buf[LARGE_OFF + 4..LARGE_OFF + 8].copy_from_slice(&1u32.to_le_bytes()); // paramCount
    buf[LARGE_OFF + 12..LARGE_OFF + 16].copy_from_slice(&BODY_SIZE.to_le_bytes());
    buf[LARGE_OFF + 35] = 0x0c; // flags: strict + hasExceptionHandler

    // Exception table @244: count 1 + the caller's triple.
    let t = LARGE_OFF + 36;
    buf[t..t + 4].copy_from_slice(&1u32.to_le_bytes());
    buf[t + 4..t + 8].copy_from_slice(&start.to_le_bytes());
    buf[t + 8..t + 12].copy_from_slice(&end.to_le_bytes());
    buf[t + 12..t + 16].copy_from_slice(&target.to_le_bytes());
    buf
}

/// Two-function v99 bundle forcing marks from BOTH validation passes
/// with inverted index order: f0 trips Pass 3 (bad handler triple),
/// f1 trips Pass 1 (overflow claim past EOF). The merged side-set
/// must come out ascending `[0, 1]` — an append would yield `[1, 0]`
/// and silently break the binary-search membership checks.
///
/// Geometry: FunctionHeaders[128..152) (2 entries) → region starts
/// 152. f0 body [160..224) (offset 160, size 64), f0 large header at
/// 224 [224..260), table @ align4(224+36) = 260. File is 280 bytes.
fn build_pass1_and_pass3_marks() -> Vec<u8> {
    let lo = 224usize;
    let mut buf = vec![0u8; 280];
    buf[0..8].copy_from_slice(&HBC_MAGIC.to_le_bytes());
    buf[8..12].copy_from_slice(&99u32.to_le_bytes());
    buf[32..36].copy_from_slice(&280u32.to_le_bytes());
    buf[40..44].copy_from_slice(&2u32.to_le_bytes()); // function_count = 2

    // f0 @128: overflowed, large_off = 224, bad triple below.
    buf[128..132].copy_from_slice(&(lo as u32).to_le_bytes());
    buf[128 + 11] = 0x20;
    // f1 @140: overflowed with large_off far past EOF — Pass 1's
    // OverflowedHeaderOutOfBounds recover-mark. offset bitfield =
    // 0x100000 with func_name bits 46..54 = 1 composes
    // large_off = (1 << 24) | 0x100000, way beyond 280 bytes.
    buf[140..144].copy_from_slice(&0x0010_0000u32.to_le_bytes());
    // func_name bitfield bits 46..54: set bit 46+0 → byte 5 bit 6.
    buf[144 + 1] |= 0x40;
    buf[140 + 11] = 0x20;

    // f0 large header @224: body [160..224), bad triple (50, 10, 0).
    buf[lo..lo + 4].copy_from_slice(&160u32.to_le_bytes());
    buf[lo + 12..lo + 16].copy_from_slice(&64u32.to_le_bytes());
    buf[lo + 35] = 0x0c; // strict + hasExceptionHandler
    let t = lo + 36; // 260
    buf[t..t + 4].copy_from_slice(&1u32.to_le_bytes());
    buf[t + 4..t + 8].copy_from_slice(&50u32.to_le_bytes()); // start
    buf[t + 8..t + 12].copy_from_slice(&10u32.to_le_bytes()); // end < start
    buf[t + 12..t + 16].copy_from_slice(&0u32.to_le_bytes()); // target
    buf
}

#[test]
fn bad_triple_recover_marks_function_parse_continues() {
    let _ = drain_findings_for_test();
    // start > end: violates the well-formed-range invariant.
    let bytes = build_v99_with_triple(50, 10, 0);
    let hbc = HbcFile::parse(&bytes, None)
        .expect("one bad handler triple must not abort the bundle");

    assert!(hbc.is_function_unrecognized(0));
    assert_eq!(hbc.unrecognized_functions().len(), 1);
    assert!(matches!(
        hbc.unrecognized_functions()[0].reason,
        UnrecognizedReason::ExceptionHandlerOutOfFunctionRange {
            handler_idx: 0,
            start: 50,
            end: 10,
            target: 0,
            fn_size: 64,
        }
    ));

    // The violation is observable on the finding channel.
    let findings = drain_findings_for_test();
    assert!(
        findings.iter().any(|f| matches!(
            f,
            HermesFinding::ExceptionHandlerOutOfFunctionRange {
                func_idx: 0,
                handler_idx: 0,
                start: 50,
                end: 10,
                target: 0,
                fn_size: 64,
            }
        )),
        "{findings:?}"
    );

    // Terminal: decompile refuses the marked index with the attached
    // typed error instead of decoding the body.
    let err = droidsaw_hermes::decompile::decompile_function(&hbc, &bytes, 0, false)
        .expect_err("unrecognized function must not decompile");
    assert!(matches!(
        err,
        droidsaw_hermes::HermesError::ExceptionHandlerOutOfFunctionRange {
            func_idx: 0,
            handler_idx: 0,
            start: 50,
            end: 10,
            target: 0,
            fn_size: 64,
        }
    ));
}

#[test]
fn target_past_function_size_recover_marks() {
    let _ = drain_findings_for_test();
    // start < end <= size, but target lands past the body.
    let bytes = build_v99_with_triple(0, 32, 200);
    let hbc = HbcFile::parse(&bytes, None)
        .expect("one bad handler target must not abort the bundle");
    assert!(hbc.is_function_unrecognized(0));
    assert!(matches!(
        hbc.unrecognized_functions()[0].reason,
        UnrecognizedReason::ExceptionHandlerOutOfFunctionRange {
            handler_idx: 0,
            start: 0,
            end: 32,
            target: 200,
            fn_size: 64,
        }
    ));
}

#[test]
fn valid_triple_stays_recognized() {
    // Control: the same geometry with an in-range triple parses with
    // nothing marked — the containment path does not over-trigger.
    let bytes = build_v99_with_triple(0, 32, 40);
    let hbc = HbcFile::parse(&bytes, None).expect("valid bundle must parse");
    assert!(hbc.unrecognized_functions().is_empty());
    assert_eq!(hbc.function_exception_count(0), 1);
    let eh = hbc.function_exception_get(0, 0);
    assert_eq!((eh.start, eh.end, eh.target), (0, 32, 40));
}

#[test]
fn pass3_and_pass1_marks_merge_sorted() {
    let bytes = build_pass1_and_pass3_marks();
    let hbc = HbcFile::parse(&bytes, None)
        .expect("both contained violation classes must keep the bundle parseable");

    let marks = hbc.unrecognized_functions();
    assert_eq!(marks.len(), 2, "{marks:?}");
    // Ascending order despite f0 being marked AFTER f1 in pass order
    // (Pass 1 marks f1, Pass 3 marks f0).
    assert_eq!(marks[0].func_idx, 0);
    assert_eq!(marks[1].func_idx, 1);
    assert!(matches!(
        marks[0].reason,
        UnrecognizedReason::ExceptionHandlerOutOfFunctionRange { .. }
    ));
    assert!(matches!(
        marks[1].reason,
        UnrecognizedReason::OverflowedHeaderOutOfBounds { .. }
    ));
    // Binary-search membership works for both (the invariant an
    // append-order side-set would break).
    assert!(hbc.is_function_unrecognized(0));
    assert!(hbc.is_function_unrecognized(1));
}
