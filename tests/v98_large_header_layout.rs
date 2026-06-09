//! HBC v98-late large-FunctionHeader layout disambiguation.
//!
//! The wire version cannot distinguish the two large-header shapes
//! shipped by version-98 `static_h` toolchains: the 36-byte v99-era
//! shape (flags @ +35, exception table @ align4(+36)) and the 40-byte
//! CacheNewObject-era shape (extra `numCacheNewObject` byte at +35,
//! flags @ +36, table @ align4(+40)). Decoding a 40-byte bundle with
//! the 36-byte model reads the last cache byte as flags — a cache
//! value with bit 3 set becomes a phantom `hasExceptionHandler`, the
//! real flags byte + pad become the handler count, and the following
//! words become garbage `(start, end, target)` triples that abort the
//! whole-bundle parse at region validation.
//!
//! The parser selects ONE shape per bundle by whole-population
//! coherence (`HbcFile::large_header_layout`): decode every overflowed
//! header under both candidates, pick the shape with zero violations.
//! Ties with byte-identical decodes keep the 36-byte default; ties
//! with material disagreement and no-coherent-shape populations mark
//! every overflowed function unrecognized (fail honest — never a
//! per-function guess).
//!
//! All fixtures are synthetic, built deterministically in-test. The
//! 40-byte valid-table fixture doubles as the libFuzzer layout-straddle
//! seed (`fuzz/seeds/fuzz_parser/12_v98_late_40b_large_header`);
//! `regen_v98_late_40b_seed` is `#[ignore]`d in CI — run manually with
//! `cargo test --test v98_large_header_layout regen_ -- --ignored`
//! after a structural change.

use std::fs;

use droidsaw_hermes::finding::{HermesFinding, drain_findings_for_test};
use droidsaw_hermes::parser::{HbcFile, LargeHeaderLayout, UnrecognizedReason};

const HBC_MAGIC: u64 = 0x1F19_03C1_03BC_1FC6;

const SEED_PATH: &str = "fuzz/seeds/fuzz_parser/12_v98_late_40b_large_header";

/// Same bytes for the emit-roundtrip target (it takes raw HBC input
/// like `fuzz_parser`), so the `parse → emit → parse` surface reaches
/// the Shape40 layout straddle by seed rather than mutation luck.
const ROUNDTRIP_SEED_PATH: &str =
    "fuzz/seeds/fuzz_emit_roundtrip_hbc/v98_late_40b_large_header.hbc";

/// Geometry shared by the single-function builders:
/// Header[0..128) + FunctionHeaders[128..140) (1 × 12-byte entry) →
/// bytecode region starts at 140. Function body [144..208) (offset
/// 144, size 64), large header at 208.
const LARGE_OFF: usize = 208;
const BODY_OFF: u32 = 144;
const BODY_SIZE: u32 = 64;

/// Size of the trailing all-zero debug-info region every v98 builder
/// appends. `debug_info_offset` points at it, which (a) gives the
/// form detector an honest late-form signal (the late-layout
/// `debug_info_offset` u32 sits at header offset 108 — the early
/// layout's BytecodeOptions position) and (b) bounds the bytecode
/// region at `content_len` instead of EOF, like a real bundle.
const DEBUG_TAIL: usize = 20;

/// Write the 128-byte v98 late-form header + one overflowed 12-byte
/// SmallFuncHeader whose composed `large_off` points at
/// [`LARGE_OFF`]. The file is `content_len` bytes of content plus a
/// [`DEBUG_TAIL`]-byte zeroed debug region at `debug_info_offset =
/// content_len`.
fn v98_late_skeleton(content_len: usize) -> Vec<u8> {
    let total_len = content_len + DEBUG_TAIL;
    let mut buf = vec![0u8; total_len];
    buf[0..8].copy_from_slice(&HBC_MAGIC.to_le_bytes());
    buf[8..12].copy_from_slice(&98u32.to_le_bytes());
    buf[32..36].copy_from_slice(&(total_len as u32).to_le_bytes()); // file_length
    buf[40..44].copy_from_slice(&1u32.to_le_bytes()); // function_count = 1
    // Late-layout debug_info_offset @108. Doubles as the form signal:
    // either its low byte fails the early-position MBZ check outright,
    // or the both-valid path sees a plausible late projection
    // (128 <= content_len < total_len) against an implausible early
    // one (offset 104 stays 0) — both routes pick LATE.
    buf[108..112].copy_from_slice(&(content_len as u32).to_le_bytes());

    // f0 SmallFuncHeader @128 (12-byte stride, late/v99 bitfields):
    //   offset (bits 0..25)     = LARGE_OFF (low bits of large_off)
    //   func_name (bits 46..54) = 0         (high bits of large_off)
    //   flags @entry[11] bit 5  = overflowed
    buf[128..132].copy_from_slice(&(LARGE_OFF as u32).to_le_bytes());
    buf[128 + 11] = 0x20;
    buf
}

/// Write the shared 40-byte large-header scalar prefix at
/// [`LARGE_OFF`]: offset/paramCount/loopDepth/bytecodeSize/
/// functionName/numberRegCount/nonPtrRegCount/frameSize. Bytes +32..
/// (cache bytes, flags, table) are the per-fixture discriminators and
/// are left to the caller.
fn write_large_header_prefix(buf: &mut [u8]) {
    let lo = LARGE_OFF;
    buf[lo..lo + 4].copy_from_slice(&BODY_OFF.to_le_bytes()); // offset
    buf[lo + 4..lo + 8].copy_from_slice(&1u32.to_le_bytes()); // paramCount
    buf[lo + 8..lo + 12].copy_from_slice(&0u32.to_le_bytes()); // loopDepth
    buf[lo + 12..lo + 16].copy_from_slice(&BODY_SIZE.to_le_bytes()); // bytecodeSize
    buf[lo + 16..lo + 20].copy_from_slice(&0u32.to_le_bytes()); // functionName
    buf[lo + 20..lo + 24].copy_from_slice(&0u32.to_le_bytes()); // numberRegCount
    buf[lo + 24..lo + 28].copy_from_slice(&0u32.to_le_bytes()); // nonPtrRegCount
    buf[lo + 28..lo + 32].copy_from_slice(&10u32.to_le_bytes()); // frameSize
}

/// 40-byte-shape bundle with a VALID exception table.
///
/// Large header [208..248): cache bytes +32..+36 = `00 00 00 03`
/// (`numCacheNewObject = 3` — under the wrong 36-byte read this byte
/// is flags with `prohibitInvoke == 3`, an impossible encoding, so
/// the 36-byte shape scores a violation), flags @ +36 = 0x0c
/// (strictMode + hasExceptionHandler). Exception table @
/// align4(208 + 40) = 248: count 1, triple (0, 32, 40) — in-range for
/// the 64-byte body.
fn build_shape40_valid_exc_table() -> Vec<u8> {
    let mut buf = v98_late_skeleton(264);
    write_large_header_prefix(&mut buf);
    buf[LARGE_OFF + 35] = 0x03; // numCacheNewObject
    buf[LARGE_OFF + 36] = 0x0c; // flags: strict + hasExceptionHandler
    let t = LARGE_OFF + 40; // 248
    buf[t..t + 4].copy_from_slice(&1u32.to_le_bytes()); // count
    buf[t + 4..t + 8].copy_from_slice(&0u32.to_le_bytes()); // start
    buf[t + 8..t + 12].copy_from_slice(&32u32.to_le_bytes()); // end
    buf[t + 12..t + 16].copy_from_slice(&40u32.to_le_bytes()); // target
    buf
}

/// The phantom-flags shape from the real-world misread: 40-byte
/// header whose `numCacheNewObject` byte is 0x0b (bit 3 set), real
/// flags @ +36 = 0x04 (strictMode only, NO exception handler). Under
/// the wrong 36-byte read, 0x0b becomes flags → phantom
/// `hasExceptionHandler`; the phantom table base align4(208+36) = 244
/// lands on the real flags byte + pad (`04 00 00 00` → count 4) and
/// the words after the header decode as garbage triples — the first
/// is (2538120, 1, 0) against a 64-byte body, the exact whole-bundle
/// abort shape this fixture regresses.
fn build_shape40_phantom_flags() -> Vec<u8> {
    let mut buf = v98_late_skeleton(296);
    write_large_header_prefix(&mut buf);
    buf[LARGE_OFF + 35] = 0x0b; // numCacheNewObject; bit 3 set
    buf[LARGE_OFF + 36] = 0x04; // real flags: strict only, hasExc = 0
    // Garbage words after the header — the phantom 36-byte read's
    // "triples" (count 4 comes from the flags+pad bytes at 244).
    buf[248..252].copy_from_slice(&2_538_120u32.to_le_bytes());
    buf[252..256].copy_from_slice(&1u32.to_le_bytes());
    // remaining phantom-triple words stay zero
    buf
}

/// Tie with byte-identical decodes: bytes +35 and +36 are both 0x04
/// (strictMode, no exception handler), so both shapes are coherent
/// and decode identically — selection keeps the deterministic
/// `Shape36` default and nothing is marked.
fn build_tie_identical_decode() -> Vec<u8> {
    let mut buf = v98_late_skeleton(248);
    write_large_header_prefix(&mut buf);
    buf[LARGE_OFF + 35] = 0x04;
    buf[LARGE_OFF + 36] = 0x04;
    buf
}

/// No coherent shape: bytes +35 and +36 are both 0x0b
/// (`prohibitInvoke == 3` under either read). Two functions — f0
/// overflowed (must be recover-marked), f1 plain small-header (must
/// parse normally).
///
/// Geometry differs from the single-function builders:
/// FunctionHeaders[128..152) (2 entries) → region starts 152;
/// f0 body (declared in the untrusted large header) [160..192);
/// f1 body [192..200); f0 large header @ 216 [216..256).
fn build_no_coherent_shape() -> Vec<u8> {
    let content = 256usize;
    let total = content + DEBUG_TAIL;
    let lo = 216usize;
    let mut buf = vec![0u8; total];
    buf[0..8].copy_from_slice(&HBC_MAGIC.to_le_bytes());
    buf[8..12].copy_from_slice(&98u32.to_le_bytes());
    buf[32..36].copy_from_slice(&(total as u32).to_le_bytes());
    buf[40..44].copy_from_slice(&2u32.to_le_bytes()); // function_count = 2
    // Late-layout debug_info_offset @108 (form signal + region bound,
    // same shape as `v98_late_skeleton`).
    buf[108..112].copy_from_slice(&(content as u32).to_le_bytes());

    // f0 @128: overflowed, large_off = 216.
    buf[128..132].copy_from_slice(&(lo as u32).to_le_bytes());
    buf[128 + 11] = 0x20;
    // f1 @140: non-overflowed; offset = 192 (word 0), bytecodeSize = 8
    // (word 1 bits 0..14), flags = 0x04 (strict).
    buf[140..144].copy_from_slice(&192u32.to_le_bytes());
    buf[144..148].copy_from_slice(&8u32.to_le_bytes());
    buf[140 + 11] = 0x04;

    // f0 large header @216: scalar prefix + poisoned tail bytes.
    buf[lo..lo + 4].copy_from_slice(&160u32.to_le_bytes()); // offset
    buf[lo + 12..lo + 16].copy_from_slice(&32u32.to_le_bytes()); // bytecodeSize
    buf[lo + 35] = 0x0b; // prohibitInvoke == 3 under the 36-byte read
    buf[lo + 36] = 0x0b; // prohibitInvoke == 3 under the 40-byte read
    buf
}

/// Selection-budget exhaustion: 8 overflowed functions whose
/// large headers sit at 12-byte stride (`large_off_i = 224 + 12*i`)
/// over one shared run of valid exception-table words, so each
/// function's Shape40 candidate table is a fresh offset into the same
/// bytes — the aliasing shape the per-table memo cannot collapse.
///
/// The run is a uniform 3-word period starting at byte 264:
/// `[count=200, start=0, end=1288]` repeating. At each stride the
/// period lines up so that, for function `i`:
/// - Shape36 flags (byte `large_off + 35`) = byte 3 of a `start`
///   word = 0x00 → no handler, no violation, no walk;
/// - Shape40 flags (byte `large_off + 36`) = byte 0 of an `end` word
///   (1288 = 0x508 → 0x08) → hasExceptionHandler, prohibitInvoke 0,
///   overflowed bit clear;
/// - the Shape40 table at `large_off + 40` reads count 200 and 200
///   valid triples `(0, 1288, 200)` — a 200-unit budget walk;
/// - `bytecodeSizeInBytes` (word at `large_off + 12`) = 1288, so the
///   table validates (required = max(end, target+1) = 1288).
///
/// File is 2,772 bytes → budget = 2772/12*4 = 924 triples; walks cost
/// 200 each at distinct offsets, so the budget dies inside the fifth
/// walk — selection must fail honest (ambiguous), never pick a shape
/// from the partial score.
fn build_budget_exhaustion_aliased_tables() -> Vec<u8> {
    const FUNC_COUNT: usize = 8;
    const COUNT: u32 = 200;
    const END: u32 = 1288; // 0x508: low byte 0x08 doubles as Shape40 flags
    let lo0 = 128 + 12 * FUNC_COUNT; // 224: large-header zone after entries
    let w_base = lo0 + 40; // 264: shared table-word run
    let last_table = lo0 + 12 * (FUNC_COUNT - 1) + 40; // 348
    let content = last_table + 4 + 12 * COUNT as usize; // 2752
    let total = content + DEBUG_TAIL;
    let mut buf = vec![0u8; total];
    buf[0..8].copy_from_slice(&HBC_MAGIC.to_le_bytes());
    buf[8..12].copy_from_slice(&98u32.to_le_bytes());
    buf[32..36].copy_from_slice(&(total as u32).to_le_bytes());
    buf[40..44].copy_from_slice(&(FUNC_COUNT as u32).to_le_bytes());
    // Late-layout debug_info_offset @108 (form signal + region bound).
    buf[108..112].copy_from_slice(&(content as u32).to_le_bytes());

    // Overflowed small headers @128 + 12i composing large_off_i.
    for i in 0..FUNC_COUNT {
        let e = 128 + 12 * i;
        let lo = (lo0 + 12 * i) as u32;
        buf[e..e + 4].copy_from_slice(&lo.to_le_bytes());
        buf[e + 11] = 0x20;
    }

    // Shared word run: [COUNT, 0, END] repeating from w_base to the
    // end of the last table's span.
    let mut w = w_base;
    let mut j = 0usize;
    while w + 4 <= content {
        let word = match j % 3 {
            0 => COUNT,
            1 => 0,
            _ => END,
        };
        buf[w..w + 4].copy_from_slice(&word.to_le_bytes());
        w += 4;
        j += 1;
    }

    // Function 0's scored bytes precede the run: bytecodeSize words
    // for functions 0..2 land in [224..264), as do f0's flag bytes.
    buf[236..240].copy_from_slice(&END.to_le_bytes()); // fn_size_0
    buf[248..252].copy_from_slice(&END.to_le_bytes()); // fn_size_1
    // byte 259 (Shape36 flags of f0) stays 0x00: no handler claimed.
    buf[260] = 0x08; // Shape40 flags of f0: hasExceptionHandler
    buf[261] = 0x05; // fn_size_2 word @260 = [08 05 00 00] = 1288
    buf
}

/// v99 regression: the 36-byte shape still decodes (no selection runs
/// for version != 98). Large header [208..244): flags @ +35 = 0x0c
/// (strict + hasExceptionHandler), exception table @ align4(208+36) =
/// 244: count 1, triple (0, 32, 40). File is 260 bytes so the shared
/// conservative OOB bound (`large_off + 40 <= len`) holds.
fn build_v99_shape36_valid_exc_table() -> Vec<u8> {
    // Reuse the skeleton (the V98LateToV99 wire layout is shared);
    // only the version differs — v99 needs no form disambiguation,
    // and the debug tail keeps the same region geometry.
    let mut buf = v98_late_skeleton(260);
    buf[8..12].copy_from_slice(&99u32.to_le_bytes()); // version 99
    write_large_header_prefix(&mut buf);
    buf[LARGE_OFF + 35] = 0x0c; // flags: strict + hasExceptionHandler
    let t = LARGE_OFF + 36; // 244
    buf[t..t + 4].copy_from_slice(&1u32.to_le_bytes()); // count
    buf[t + 4..t + 8].copy_from_slice(&0u32.to_le_bytes()); // start
    buf[t + 8..t + 12].copy_from_slice(&32u32.to_le_bytes()); // end
    buf[t + 12..t + 16].copy_from_slice(&40u32.to_le_bytes()); // target
    buf
}

#[test]
fn shape40_valid_exc_table_selected_and_decoded() {
    let bytes = build_shape40_valid_exc_table();
    let hbc = HbcFile::parse(&bytes, None).expect("40-byte-shape bundle must parse");
    assert_eq!(hbc.version, 98);
    assert_eq!(hbc.large_header_layout(), Some(LargeHeaderLayout::Shape40));
    assert!(hbc.unrecognized_functions().is_empty());

    let f = hbc.function_get(0);
    assert_eq!(f.offset, BODY_OFF);
    assert_eq!(f.size, BODY_SIZE);
    assert_eq!(f.param_count, 1);
    assert_eq!(f.frame_size, 10);
    assert_eq!(f.flags, 0x0c, "flags read at +36, not the cache byte at +35");
    assert_eq!((f.flags >> 3) & 1, 1, "hasExceptionHandler");

    assert_eq!(hbc.function_exception_count(0), 1);
    let eh = hbc.function_exception_get(0, 0);
    assert_eq!((eh.start, eh.end, eh.target), (0, 32, 40));
}

#[test]
fn phantom_flags_shape_no_longer_aborts_parse() {
    let bytes = build_shape40_phantom_flags();
    // A 36-byte model reads numCacheNewObject (0x0b) as
    // flags → phantom hasExceptionHandler → count 4 from the real
    // flags+pad bytes → garbage triple (2538120, 1, 0) vs a 64-byte
    // body → ExceptionHandlerOutOfFunctionRange whole-bundle abort.
    let hbc = HbcFile::parse(&bytes, None)
        .expect("phantom-flags shape must parse under the selected 40-byte shape");
    assert_eq!(hbc.large_header_layout(), Some(LargeHeaderLayout::Shape40));
    assert!(hbc.unrecognized_functions().is_empty());

    let f = hbc.function_get(0);
    assert_eq!(f.flags, 0x04, "real flags byte at +36 (strict only)");
    assert_eq!((f.flags >> 3) & 1, 0, "no phantom hasExceptionHandler");
    assert_eq!(hbc.function_exception_count(0), 0);
}

#[test]
fn tie_with_identical_decode_keeps_shape36_default() {
    let bytes = build_tie_identical_decode();
    let hbc = HbcFile::parse(&bytes, None).expect("tie bundle must parse");
    assert_eq!(
        hbc.large_header_layout(),
        Some(LargeHeaderLayout::Shape36),
        "byte-identical tie keeps the deterministic Shape36 default"
    );
    assert!(hbc.unrecognized_functions().is_empty());
    assert_eq!(hbc.function_get(0).flags, 0x04);
}

#[test]
fn no_coherent_shape_marks_overflowed_unrecognized_parse_continues() {
    let _ = drain_findings_for_test();
    let bytes = build_no_coherent_shape();
    let hbc = HbcFile::parse(&bytes, None)
        .expect("ambiguous-layout bundle must still parse (fail honest, not hard)");
    assert_eq!(hbc.large_header_layout(), None);

    // f0 (overflowed): recover-marked, inert decode.
    assert!(hbc.is_function_unrecognized(0));
    assert_eq!(hbc.unrecognized_functions().len(), 1);
    assert!(matches!(
        hbc.unrecognized_functions()[0].reason,
        UnrecognizedReason::LargeHeaderLayoutAmbiguous { large_off: 216 }
    ));
    let f0 = hbc.function_get(0);
    assert_eq!(
        (f0.offset, f0.size, f0.flags),
        (0, 0, 0),
        "no decode under a guessed layout"
    );
    assert_eq!(hbc.function_exception_count(0), 0);

    // f1 (plain small header): unaffected.
    assert!(!hbc.is_function_unrecognized(1));
    let f1 = hbc.function_get(1);
    assert_eq!((f1.offset, f1.size, f1.flags), (192, 8, 0x04));

    // Exactly one bundle-level finding carries the population counts.
    let findings = drain_findings_for_test();
    let ambiguous: Vec<_> = findings
        .iter()
        .filter(|f| matches!(f, HermesFinding::V98LargeHeaderLayoutAmbiguous { .. }))
        .collect();
    assert_eq!(ambiguous.len(), 1, "{findings:?}");
    assert!(matches!(
        ambiguous[0],
        HermesFinding::V98LargeHeaderLayoutAmbiguous {
            overflowed_scored: 1,
            violations_shape36: 1,
            violations_shape40: 1,
            decode_disagreements: 0,
            selection_budget_exhausted: false,
        }
    ));
}

#[test]
fn budget_exhaustion_fails_honest_marks_all_overflowed() {
    let _ = drain_findings_for_test();
    let bytes = build_budget_exhaustion_aliased_tables();
    let hbc = HbcFile::parse(&bytes, None)
        .expect("budget-exhausted bundle must still parse (fail honest, not hard)");
    assert_eq!(
        hbc.large_header_layout(),
        None,
        "an exhausted selection pass must never pick a shape from a partial score"
    );

    // Every overflowed function is recover-marked, including the ones
    // the pass never reached before the budget died.
    assert_eq!(hbc.unrecognized_functions().len(), 8);
    for idx in 0..8 {
        assert!(hbc.is_function_unrecognized(idx));
        let f = hbc.function_get(idx);
        assert_eq!((f.offset, f.size, f.flags), (0, 0, 0), "fn {idx} must decode inert");
    }
    assert!(matches!(
        hbc.unrecognized_functions()[0].reason,
        UnrecognizedReason::LargeHeaderLayoutAmbiguous { large_off: 224 }
    ));

    // The bundle-level finding records the exhaustion.
    let findings = drain_findings_for_test();
    let ambiguous: Vec<_> = findings
        .iter()
        .filter(|f| matches!(f, HermesFinding::V98LargeHeaderLayoutAmbiguous { .. }))
        .collect();
    assert_eq!(ambiguous.len(), 1, "{findings:?}");
    assert!(matches!(
        ambiguous[0],
        HermesFinding::V98LargeHeaderLayoutAmbiguous {
            selection_budget_exhausted: true,
            violations_shape36: 0,
            violations_shape40: 0,
            ..
        }
    ));
}

#[test]
fn v99_shape36_path_still_decodes() {
    let bytes = build_v99_shape36_valid_exc_table();
    let hbc = HbcFile::parse(&bytes, None).expect("v99 bundle must parse");
    assert_eq!(hbc.version, 99);
    assert_eq!(
        hbc.large_header_layout(),
        Some(LargeHeaderLayout::Shape36),
        "v99 stays pinned; selection only runs for version 98"
    );
    assert!(hbc.unrecognized_functions().is_empty());

    let f = hbc.function_get(0);
    assert_eq!(f.offset, BODY_OFF);
    assert_eq!(f.size, BODY_SIZE);
    assert_eq!(f.flags, 0x0c, "flags read at +35 on the v99 shape");
    assert_eq!(hbc.function_exception_count(0), 1);
    let eh = hbc.function_exception_get(0, 0);
    assert_eq!((eh.start, eh.end, eh.target), (0, 32, 40));
}

/// The committed libFuzzer layout-straddle seeds must stay in sync
/// with the in-memory builder (test-as-generator: the test proves the
/// bytes, the seed files are its artifact). Both targets take raw HBC
/// bytes, so the parser seed and the emit-roundtrip seed are the same
/// builder output.
#[test]
fn seed_file_matches_builder() {
    let in_memory = build_shape40_valid_exc_table();
    for path in [SEED_PATH, ROUNDTRIP_SEED_PATH] {
        let on_disk = fs::read(path).unwrap_or_else(|e| {
            panic!("layout-straddle seed {path} must be checked in ({e}); run `regen_v98_late_40b_seed`")
        });
        assert_eq!(on_disk, in_memory, "seed drift at {path}; rerun regen_v98_late_40b_seed");
    }
}

/// Regenerate the on-disk fuzz seeds. `#[ignore]` in CI; run manually
/// after a structural layout change.
#[test]
#[ignore = "regen helper — run manually with --ignored after layout changes"]
fn regen_v98_late_40b_seed() {
    let bytes = build_shape40_valid_exc_table();
    for path in [SEED_PATH, ROUNDTRIP_SEED_PATH] {
        let seed_dir = std::path::Path::new(path).parent().unwrap();
        fs::create_dir_all(seed_dir).unwrap();
        fs::write(path, &bytes).unwrap();
        println!("wrote {} bytes to {path}", bytes.len());
    }
}
