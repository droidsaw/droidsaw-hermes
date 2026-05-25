//! Round-trip equivalence machinery: `HbcVersion` trait, version-tag
//! marker structs (V84/V96/V98/V99), `HbcFileEquiv` newtype, and the
//! per-version `PartialEq` impls that define what "two HBC files emit
//! to the same bytes" means.
//!
//! Spec-first discipline: the `PartialEq` impls below ARE the emit
//! specification for HBC. Every section's emit mode (synthesize-from-IR
//! vs byte-passthrough-from-`buf`-slice) derives from what this
//! equivalence considers equivalent.

#![allow(
    clippy::cast_possible_wrap,
    reason = "PROOF: signed/unsigned reinterpretation in HBC jump offsets and operand decode; values bounded by per-function bytecode size cap."
)]

use super::{read_f64, read_u16, read_u32, HbcFile, LiteralValue};

// ── Round-trip equivalence (HbcFileEquiv) ──────────────────────────────────
//
// Spec-first discipline: the `impl PartialEq for HbcFileEquiv<V96>`
// below IS the emit specification for HBC. Every section's emit mode
// (synthesize-from-IR vs byte-passthrough-from-`buf`-slice) derives
// from what this equivalence considers equivalent. Structurally
// mirrors `droidsaw_dex::parser::ContentEquiv`.

/// Marker trait carrying the HBC bytecode version tag at type level.
/// Version-parameterizes the round-trip equivalence so mixing versions
/// is a compile-time error.
pub trait HbcVersion {
    /// Numeric version tag as it appears in the HBC header.
    const VERSION: u32;
    /// Short name for diagnostics (e.g. `"v96"`).
    const NAME: &'static str;
}

/// HBC bytecode version 84 — Hermes v0.11 era (RN 0.70/0.71, 2022).
/// Pre-v87 (no bigint sections) + pre-v97 (no ObjShapeTable; has
/// ObjValueBuffer) + v≥84 (function_source_count slot exists in header
/// even when count is 0). 16-byte SmallFuncHeader with same bit-layout
/// as v96; emit reuses `SmallFuncHeaderV96Raw` + `raw_small_func_header_v96`
/// via the existing `version < 97 && size == 16` gate.
/// Byte-identical round-trip verified.
#[derive(Debug, Clone, Copy)]
pub struct V84;

impl HbcVersion for V84 {
    const VERSION: u32 = 84;
    const NAME: &'static str = "v84";
}

/// HBC bytecode version 96 — the target of the v1 emitter. Pre-v97
/// layout (array_buffer + obj_key_buffer + obj_value_buffer; no
/// obj_shape_table); v87+ bigint sections. v96 is the dominant version
/// in production RN bundles; v98 / v84 appear as minorities.
#[derive(Debug, Clone, Copy)]
pub struct V96;

impl HbcVersion for V96 {
    const VERSION: u32 = 96;
    const NAME: &'static str = "v96";
}

/// HBC bytecode version 98. Post-v97 layout: adds `ObjShapeTable`
/// section, drops `ObjValueBuffer`, changes `SmallFuncHeader` to 12
/// bytes/entry. v98 exists in two forms: early-v98 (shares v97 bitfield
/// widths) and late-v98 (shares v99 bitfield widths + adds
/// `numStringSwitchImms` u32 in the header). `HbcFile::use_v99_func_header`
/// and `has_num_string_switch_imms` disambiguate at runtime.
/// `detect_late_v98_form` detects the form by checking whether
/// `byte[108]=0x60` passes or fails the v97-BytecodeOptions validity
/// check (late_valid && !early_valid → late-v98).
#[derive(Debug, Clone, Copy)]
pub struct V98;

impl HbcVersion for V98 {
    const VERSION: u32 = 98;
    const NAME: &'static str = "v98";
}

/// HBC bytecode version 99 — current Hermes upstream
/// (`hermes/include/hermes/BCGen/HBC/BytecodeVersion.h::BYTECODE_VERSION
/// = 99`). Structurally identical to late-v98 per
/// `parser::parse_inner`: `use_v99_header = version >= 99 || (version ==
/// 98 && has_num_string_switch_imms)` — so all v99 files enter the
/// late-v98 code path (12-byte SmallFuncHeader with v99-layout
/// bitfields, `numStringSwitchImms` u32 in the header, ObjShapeTable
/// section). Emit lifts the v98 implementation unchanged.
///
/// Byte-identity verification is structural-only + fuzz-driven for
/// this version.
#[derive(Debug, Clone, Copy)]
pub struct V99;

impl HbcVersion for V99 {
    const VERSION: u32 = 99;
    const NAME: &'static str = "v99";
}

/// Version-tagged quotient newtype over an `HbcFile`. `PartialEq` is
/// implemented per concrete version; constructing the wrapper verifies
/// that the underlying `HbcFile` actually carries version `V::VERSION`.
///
/// For `V = V96`, the `PartialEq` impl below is the round-trip
/// equivalence specification for the v96 HBC emitter.
pub struct HbcFileEquiv<'a, V: HbcVersion> {
    file: &'a HbcFile<'a>,
    _v: std::marker::PhantomData<V>,
}

impl<'a, V: HbcVersion> HbcFileEquiv<'a, V> {
    /// Wrap an `HbcFile` under the version tag. Returns `None` if the
    /// file's runtime version doesn't match `V::VERSION` (prevents
    /// mixing a v76 IR with the v96 equivalence class at runtime; the
    /// type system already excludes mixing across different `V`).
    pub fn new(file: &'a HbcFile<'a>) -> Option<Self> {
        if file.version == V::VERSION {
            Some(Self {
                file,
                _v: std::marker::PhantomData,
            })
        } else {
            None
        }
    }

    /// Underlying `HbcFile` reference — escape hatch for callers that
    /// need access to non-equivalence-relevant fields.
    pub fn inner(&self) -> &'a HbcFile<'a> {
        self.file
    }
}

impl<'a, V: HbcVersion> std::fmt::Debug for HbcFileEquiv<'a, V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HbcFileEquiv")
            .field("V", &V::NAME)
            .field("version", &self.file.version)
            .field("function_count", &self.file.function_count)
            .field("string_count", &self.file.string_count)
            .field("section_count", &self.file.section_count())
            .finish_non_exhaustive()
    }
}

/// Round-trip equivalence for v96 HBC files — the emit specification.
///
/// ## What is compared
///
/// - **Version tag** — `V96::VERSION` on both sides (guaranteed by
///   `::new()` gate; redundantly checked for defense).
/// - **Primary header counts** — `function_count`, `string_count`,
///   `overflow_string_count`, `string_storage_size`, `cjs_module_count`,
///   `regexp_count()`, `bigint_count()`, `object_shape_count()`. These
///   drive section sizing and must round-trip by value.
/// - **`sections` vec** — element-wise `name` + `size`. Offsets
///   (`sections[i].1`) are layout gauge freedom and NOT compared.
/// - **Section content bytes** — each section's byte slice at its own
///   file's offset is compared bytewise. SYNTHESIZE sections (Header /
///   FunctionHeaders / SmallStringTable / OverflowStringTable /
///   RegExpTable / BigIntTable) produce bytewise-identical output by
///   deterministic emission from the same IR; PASSTHROUGH sections
///   (StringStorage / ObjValueBuffer / ArrayBuffer / RegExpStorage /
///   IdentifierHashes / ObjKeyBuffer / FunctionSourceTable /
///   BigIntStorage / StringKinds) are copied byte-for-byte from the
///   source buffer.
/// - **Function-body bytecode** — each function's `(offset, size)`
///   byte range within the file's `buf()`, compared bytewise
///   (passthrough on emit; decode-reencode is out of scope for v1).
///
/// ## debug_info PASSTHROUGH
///
/// `debug_info_offset` + `debug_filename_count` ARE compared as IR
/// fields (step 2 below). HBC debug_info is line-number +
/// scope-chain metadata, not DEX's dangling-pointer-vector format;
/// stripping would destroy RE signal without security benefit. Emit
/// preserves the header offset; section bytes come through via body
/// passthrough.
///
/// ## What is NOT compared (intentional gauge freedom)
///
/// - **`input_hash`** — parser-internal SipHash diag scoping; not a
///   format-level invariant.
/// - **`sections[i].1` (absolute offsets)** — layout gauge freedom;
///   section size + content bytes cover correctness.
/// - **Header `sourceHash` bytes** — the 20-byte SHA1 at header
///   offset 12 is the JS source hash, not a bytecode integrity
///   checksum. Preserved byte-for-byte on emit; not surfaced on
///   `HbcFile`'s IR (parser skips the bytes). Covered by
///   the PASSTHROUGH byte-range compare in step (4b).
// PASSTHROUGH byte-ranges within the v96 HBC 128-byte header: parser
// reads them but does not decompose them into typed IR fields; emit
// preserves verbatim. Ranges: `12..32` sourceHash, `36..40`
// global_code_index, `92..96` segment_id / cjs_module_offset,
// `108..128` BytecodeOptions + trailing padding. Every other header
// byte is SYNTHESIZE-from-IR and covered by IR-field equality in
// `HbcFileEquiv::eq` step (2); parser-ignored garbage bytes (e.g.
// `big_int_storage_size` when `big_int_count == 0`) get canonicalized
// to 0 on emit, so we don't bytewise compare those regions — they'd
// spuriously fail despite IR equivalence.
const V96_HEADER_PASSTHROUGH_RANGES: &[(usize, usize)] = &[
    (12, 32),
    (36, 40),
    (92, 96),
    (108, 128),
];

// V84 header PASSTHROUGH byte ranges. v84 has no bigint slots (v<87),
// so slots after `reg_exp_storage_size` shift up by 8 bytes relative
// to v96; `segment_id/cjs_offset` PASS slot lands at 84..88, and
// BytecodeOptions+padding starts at 100..128 (28 bytes of PASS vs
// v96's 20 bytes at 108..128). sourceHash + global_code_index PASS
// ranges are shared with v96.
const V84_HEADER_PASSTHROUGH_RANGES: &[(usize, usize)] = &[
    (12, 32),
    (36, 40),
    (84, 88),
    (100, 128),
];

/// Bytewise compare the PASSTHROUGH regions within the v84 HBC 128-byte
/// header. Mirrors `header_passthrough_equiv_v96` with v84-specific
/// range table.
fn header_passthrough_equiv_v84(a: &[u8], b: &[u8]) -> bool {
    if a.len() < 128 || b.len() < 128 {
        return a == b;
    }
    for &(start, end) in V84_HEADER_PASSTHROUGH_RANGES {
        let (Some(slice_a), Some(slice_b)) = (a.get(start..end), b.get(start..end)) else {
            return false;
        };
        if slice_a != slice_b {
            return false;
        }
    }
    true
}

/// Bytewise compare the PASSTHROUGH regions within the v96 HBC 128-byte
/// header. Used by `HbcFileEquiv<V96>::eq` in lieu of a full-header
/// bytewise compare (see `V96_HEADER_PASSTHROUGH_RANGES` doc).
fn header_passthrough_equiv_v96(a: &[u8], b: &[u8]) -> bool {
    if a.len() < 128 || b.len() < 128 {
        // Both headers should be 128 bytes for v96; defensive fall-back
        // to full bytewise compare on anything shorter.
        return a == b;
    }
    for &(start, end) in V96_HEADER_PASSTHROUGH_RANGES {
        let (Some(slice_a), Some(slice_b)) = (a.get(start..end), b.get(start..end)) else {
            return false;
        };
        if slice_a != slice_b {
            return false;
        }
    }
    true
}

// WHY: `HbcFileEquiv<V96>::eq` slices `buf()[offset..offset + size]`
// where `offset` / `size` are u32 header fields validated at parse time
// (see `section!` / `section_opt!` macros at `parse_inner` — both
// reject `cursor + size > buf.len()` pre-construction). `u32→usize`
// widens on 64-bit targets (u32::MAX < usize::MAX), narrows to no-op
// on 32-bit targets (same bit width, bounds hold by section-validation
// invariant). Block-level allow matches the per-crate `ipa.rs`
// uniform-cluster precedent.
/// Round-trip equivalence for v84 HBC files.
///
/// Section layout: Header / FunctionHeaders / StringKinds /
/// IdentifierHashes / SmallStringTable / OverflowStringTable /
/// StringStorage / ArrayBuffer / ObjKeyBuffer / ObjValueBuffer /
/// RegExpTable / RegExpStorage. No BigInt tables (v<87), no
/// ObjShapeTable (v<97), no FunctionSourceTable materialized when
/// count==0 (v84+ reserves the header slot regardless).
///
/// What's compared: primary header counts, sections vec (name + size),
/// section content bytes, header PASS byte ranges, per-function
/// metadata via shared helper.
///
/// What's NOT compared (gauge freedom): absolute section offsets,
/// sourceHash bytes (PASS range coverage), input_hash, debug_info
/// internals (v84 predates the v94 typed-decomposition floor —
/// format is opaque; passthrough preserves verbatim).
#[allow(clippy::as_conversions, reason = "Spec-bounded value-domain narrowing (parser-validated field; preceding PROOF documents the bit-width invariant).")]
impl<'a> PartialEq for HbcFileEquiv<'a, V84> {
    fn eq(&self, other: &Self) -> bool {
        let a = self.file;
        let b = other.file;

        if a.version != b.version || a.version != V84::VERSION {
            return false;
        }

        if a.function_count != b.function_count
            || a.string_count != b.string_count
            || a.overflow_string_count != b.overflow_string_count
            || a.string_storage_size != b.string_storage_size
            || a.cjs_module_count != b.cjs_module_count
        {
            return false;
        }
        if a.regexp_count() != b.regexp_count()
            || a.bigint_count() != b.bigint_count()
            || a.object_shape_count() != b.object_shape_count()
        {
            return false;
        }
        if a.debug_info_offset() != b.debug_info_offset() {
            return false;
        }

        if a.sections.len() != b.sections.len() {
            return false;
        }
        for (sa, sb) in a.sections.iter().zip(b.sections.iter()) {
            if sa.0 != sb.0 || sa.2 != sb.2 {
                return false;
            }
        }
        for (idx, (sa, sb)) in a.sections.iter().zip(b.sections.iter()).enumerate() {
            if idx == 0 && sa.0 == "Header" {
                continue;
            }
            let a_off = sa.1 as usize;
            let a_sz = sa.2 as usize;
            let b_off = sb.1 as usize;
            let b_sz = sb.2 as usize;
            let (Some(slice_a), Some(slice_b)) = (
                a.buf().get(a_off..a_off.saturating_add(a_sz)),
                b.buf().get(b_off..b_off.saturating_add(b_sz)),
            ) else {
                return false;
            };
            if slice_a != slice_b {
                return false;
            }
        }

        if !header_passthrough_equiv_v84(a.buf(), b.buf()) {
            return false;
        }

        // v84 uses the same 16-byte SmallFuncHeader bit-layout as v96;
        // `raw_small_func_header_v96` accepts v<97 + size==16, so v84
        // qualifies. Reuse the V96 exclusion helper verbatim.
        for i in 0..a.function_count {
            let fa = a.function_get(i);
            let fb = b.function_get(i);

            let overflowed_adversarial = match a.raw_small_func_header_v96(i) {
                Some(raw) => {
                    let overflowed = (raw.raw_flags_byte >> 5) & 1 != 0;
                    let large_off =
                        (u64::from(raw.raw_info_offset) << 16) | u64::from(raw.raw_offset);
                    overflowed && large_off < 128
                }
                None => false,
            };
            if overflowed_adversarial {
                continue;
            }

            if fa.offset != fb.offset
                || fa.size != fb.size
                || fa.name_id != fb.name_id
                || fa.param_count != fb.param_count
                || fa.flags != fb.flags
                || fa.frame_size != fb.frame_size
            {
                return false;
            }
        }

        true
    }
}

#[allow(clippy::as_conversions, reason = "Spec-bounded value-domain narrowing (parser-validated field; preceding PROOF documents the bit-width invariant).")]
impl<'a> PartialEq for HbcFileEquiv<'a, V96> {
    fn eq(&self, other: &Self) -> bool {
        let a = self.file;
        let b = other.file;

        // (1) Version tag — redundant with ::new() gate but cheap defense.
        if a.version != b.version || a.version != V96::VERSION {
            return false;
        }

        // (2) Primary header counts (drive section sizing).
        if a.function_count != b.function_count
            || a.string_count != b.string_count
            || a.overflow_string_count != b.overflow_string_count
            || a.string_storage_size != b.string_storage_size
            || a.cjs_module_count != b.cjs_module_count
        {
            return false;
        }
        if a.regexp_count() != b.regexp_count()
            || a.bigint_count() != b.bigint_count()
            || a.object_shape_count() != b.object_shape_count()
        {
            return false;
        }

        // debug_info_offset: emit preserves the header field verbatim
        // from IR (not stripped; see type-level doc). `debug_filename_count`
        // is NOT compared — the parser reads it via
        // `read_u32(buf, debug_info_offset)`, and adversarial offsets
        // pointing into the 0..128 Header region produce divergent
        // counts across round-trip despite equivalent IR (same root
        // cause as the function metadata drop: IR derived from
        // attacker-controlled read into the emit-modified Header
        // zone). For legitimate files, debug_info lives in the body
        // (offset >= 128) and is PASSTHROUGH-preserved — a spot check
        // on a v96 corpus sample confirms `debug_filename_count` agrees, but
        // the equivalence class can't require it without excluding the
        // Header-overlap adversarial case.
        if a.debug_info_offset() != b.debug_info_offset() {
            return false;
        }

        // (3) `sections` vec: element-wise name + size. Absolute
        //     offsets are gauge freedom and NOT compared.
        if a.sections.len() != b.sections.len() {
            return false;
        }
        for (sa, sb) in a.sections.iter().zip(b.sections.iter()) {
            if sa.0 != sb.0 || sa.2 != sb.2 {
                return false;
            }
        }

        // (4) Section content bytes — each side sliced by its own
        //     offset (sections are in the same order per (3)). This
        //     covers PASSTHROUGH section byte-identity correctness.
        //
        //     Header (index 0, sections[0]) is SYNTHESIZE-from-IR on
        //     emit; its count/size fields get canonicalized from IR
        //     even when the source buffer has garbage in parser-ignored
        //     fields (e.g. `big_int_storage_size` bytes when
        //     `big_int_count == 0`). IR-field equality in step (2)
        //     already covers every synthesized header field; we don't
        //     bytewise-compare the Header section. Step (4b) covers
        //     the PASSTHROUGH portions of the header separately.
        for (idx, (sa, sb)) in a.sections.iter().zip(b.sections.iter()).enumerate() {
            if idx == 0 && sa.0 == "Header" {
                continue;
            }
            let a_off = sa.1 as usize;
            let a_sz = sa.2 as usize;
            let b_off = sb.1 as usize;
            let b_sz = sb.2 as usize;
            let (Some(slice_a), Some(slice_b)) = (
                a.buf().get(a_off..a_off.saturating_add(a_sz)),
                b.buf().get(b_off..b_off.saturating_add(b_sz)),
            ) else {
                // Either side points outside its buffer — not equivalent.
                return false;
            };
            if slice_a != slice_b {
                return false;
            }
        }

        // (4b) Header PASSTHROUGH byte-range bytewise compare. These
        //      are ranges within the 128-byte Header that the parser
        //      reads-but-does-not-decompose (sourceHash,
        //      global_code_index, segment_id/cjs_offset, BytecodeOptions
        //      + padding). Emit preserves them verbatim; bytewise
        //      equality is the gauge-fixed check. See
        //      `header_passthrough_equiv_v96` + the const
        //      `V96_HEADER_PASSTHROUGH_RANGES` for the exact ranges.
        if !header_passthrough_equiv_v96(a.buf(), b.buf()) {
            return false;
        }

        // (5) Function metadata compare. The FunctionHeaders section
        //     bytes are covered byte-for-byte by (4) above. This step
        //     additionally asserts that the parser's resolved
        //     `FunctionData` view agrees across round-trip — catching
        //     any future regression where the emit's bit-pack drifts
        //     out of alignment with the parser's bitfield read.
        //
        //     Overlap-aware exclusion: overflowed functions with an
        //     `info_offset` landing inside the 0..128 Header region
        //     follow an attacker-controlled pointer into the emit-
        //     modified Header zone. IR fields derived from that read
        //     (frame_size, flags, name_id, size) can diverge across
        //     round-trip even when the equivalence class is
        //     preserved. Those entries are excluded from the metadata
        //     compare; the FunctionHeaders section-byte compare at (4)
        //     already covers their SmallFuncHeader row, so no gauge
        //     coverage is lost.
        for i in 0..a.function_count {
            let fa = a.function_get(i);
            let fb = b.function_get(i);

            // Re-derive the overflowed flag from the raw SmallFuncHeader
            // row (pre-overflow-resolution). Non-zero bit 5 == overflowed.
            let overflowed_adversarial = match a.raw_small_func_header_v96(i) {
                Some(raw) => {
                    let overflowed = (raw.raw_flags_byte >> 5) & 1 != 0;
                    // Re-derive large_off the same way function_get
                    // does (pre-v97 / v96 branch): (info_offset << 16)
                    // | offset. Adversarial iff overflowed AND
                    // large_off < 128 (Header region).
                    let large_off =
                        (u64::from(raw.raw_info_offset) << 16) | u64::from(raw.raw_offset);
                    overflowed && large_off < 128
                }
                // Non-v96 or out-of-range — fall through to the
                // generic compare. raw_small_func_header_v96 already
                // gates on version < 97; V96-tagged equivalence reaches
                // this branch only via the ::new() gate so this path
                // should be unreachable in well-formed use.
                None => false,
            };

            if overflowed_adversarial {
                continue;
            }

            if fa.offset != fb.offset
                || fa.size != fb.size
                || fa.name_id != fb.name_id
                || fa.param_count != fb.param_count
                || fa.flags != fb.flags
                || fa.frame_size != fb.frame_size
            {
                return false;
            }
        }

        // debug_info_offset + debug_filename_count + sourceHash bytes
        // (within Header section at (4)) intentionally NOT compared.
        // See type-level doc-comment for rationale.

        true
    }
}

// V98 HBC header PASSTHROUGH byte ranges. v98 shifts slots relative to
// v96 because `obj_value_buffer_size` is replaced by `obj_shape_table_count`
// (same slot, still SYN) and late-v98/v99 insert an additional
// `numStringSwitchImms` u32 at offset 92..96, shifting subsequent SYN
// fields + the trailing PASS range by 4 bytes. Computed at equivalence-
// compare time via `v98_header_passthrough_ranges(use_v99_header)`.
fn v98_header_passthrough_ranges(use_v99_header: bool) -> [(usize, usize); 4] {
    if use_v99_header {
        // late-v98 / v99: numStringSwitchImms present; segment/cjs
        // shifts to 96..100; BytecodeOptions+pad to 112..128.
        [(12, 32), (36, 40), (96, 100), (112, 128)]
    } else {
        // early-v98 / v97: no numStringSwitchImms; same layout as v96
        // except slot 88..92 is `obj_shape_table_count` (SYN) instead
        // of `obj_value_buffer_size` — both SYN so the PASS ranges
        // match v96.
        [(12, 32), (36, 40), (92, 96), (108, 128)]
    }
}

/// Bytewise compare the PASSTHROUGH regions within the v98 HBC header.
/// Late-v98/v99 files have a 132-byte header stretch (128 base + 4 for
/// `numStringSwitchImms`) but section offsets in `HbcFile::sections`
/// start at 128 unchanged — the extra 4 bytes live within the header's
/// PASS range which v98's ranges table accounts for.
fn header_passthrough_equiv_v98(
    a: &[u8],
    b: &[u8],
    use_v99_header: bool,
) -> bool {
    if a.len() < 128 || b.len() < 128 {
        return a == b;
    }
    let ranges = v98_header_passthrough_ranges(use_v99_header);
    for &(start, end) in ranges.iter() {
        let (Some(slice_a), Some(slice_b)) = (a.get(start..end), b.get(start..end)) else {
            return false;
        };
        if slice_a != slice_b {
            return false;
        }
    }
    true
}

/// Round-trip equivalence for v98 HBC files.
///
/// ## What is compared (vs `HbcFileEquiv<V96>`)
///
/// Same shape as v96: primary header counts, sections vec (name+size),
/// section content bytes, header PASSTHROUGH byte ranges, per-function
/// metadata with Header-overlap-aware exclusion. v98-specific deltas:
///
/// - **`object_shape_count`** is compared as a primary count (v97+
///   only; v96's analogous slot was `obj_value_buffer_size`).
/// - **`has_num_string_switch_imms`** flag is compared (determines
///   header layout + FunctionHeader bit-packing).
/// - **`use_v99_func_header`** flag is compared (late-v98/v99 layout
///   vs early-v98/v97 layout).
/// - Header PASSTHROUGH ranges are computed per the early/late split
///   — `v98_header_passthrough_ranges(use_v99_header)` yields the 4
///   ranges to bytewise-compare within the 128-byte base header.
///
/// Sections list for v98: Header,
/// FunctionHeaders, StringKinds, IdentifierHashes, SmallStringTable,
/// OverflowStringTable, StringStorage, ArrayBuffer, ObjKeyBuffer,
/// ObjShapeTable, RegExpTable, RegExpStorage, FunctionSourceTable.
/// ObjValueBuffer is absent in v97+ (architectural change). Byte-
/// identity across section content covers every SYN section except
/// Header; Header SYN fields are covered by the IR-field equality step.
#[allow(clippy::as_conversions, reason = "`u32→usize` widens on 64-bit targets. Mirrors `V96` allow.")]
impl<'a> PartialEq for HbcFileEquiv<'a, V98> {
    fn eq(&self, other: &Self) -> bool {
        let a = self.file;
        let b = other.file;

        // (1) Version tag — redundant with ::new() gate but cheap defense.
        if a.version != b.version || a.version != V98::VERSION {
            return false;
        }

        // (2) Primary header counts.
        if a.function_count != b.function_count
            || a.string_count != b.string_count
            || a.overflow_string_count != b.overflow_string_count
            || a.string_storage_size != b.string_storage_size
            || a.cjs_module_count != b.cjs_module_count
        {
            return false;
        }
        if a.regexp_count() != b.regexp_count()
            || a.bigint_count() != b.bigint_count()
            || a.object_shape_count() != b.object_shape_count()
        {
            return false;
        }
        if a.debug_info_offset() != b.debug_info_offset() {
            return false;
        }

        // v98-specific: layout flags must match (emit must reproduce
        // the same early-vs-late format).
        if a.use_v99_func_header() != b.use_v99_func_header()
            || a.has_num_string_switch_imms() != b.has_num_string_switch_imms()
        {
            return false;
        }

        // (3) `sections` vec element-wise (name + size; offsets are gauge freedom).
        if a.sections.len() != b.sections.len() {
            return false;
        }
        for (sa, sb) in a.sections.iter().zip(b.sections.iter()) {
            if sa.0 != sb.0 || sa.2 != sb.2 {
                return false;
            }
        }

        // (4) Section content bytes — skip Header (byte compare
        // handled in step 4b for the PASS ranges; SYN fields covered
        // by (2) above).
        for (idx, (sa, sb)) in a.sections.iter().zip(b.sections.iter()).enumerate() {
            if idx == 0 && sa.0 == "Header" {
                continue;
            }
            let a_off = sa.1 as usize;
            let a_sz = sa.2 as usize;
            let b_off = sb.1 as usize;
            let b_sz = sb.2 as usize;
            let (Some(slice_a), Some(slice_b)) = (
                a.buf().get(a_off..a_off.saturating_add(a_sz)),
                b.buf().get(b_off..b_off.saturating_add(b_sz)),
            ) else {
                return false;
            };
            if slice_a != slice_b {
                return false;
            }
        }

        // (4b) Header PASS byte ranges (version-layout-aware).
        if !header_passthrough_equiv_v98(a.buf(), b.buf(), a.use_v99_func_header()) {
            return false;
        }

        v98_v99_function_metadata_equiv(a, b)
    }
}

/// v99 round-trip equivalence — structurally identical to v98 per
/// `parser::parse_inner`'s `use_v99_header` branch; v99 always uses the
/// late-v98 layout. The only semantic delta from `HbcFileEquiv<V98>` is
/// the version-tag check; everything else lifts unchanged via the
/// shared `v98_v99_function_metadata_equiv` helper.
#[allow(clippy::as_conversions, reason = "Spec-bounded value-domain narrowing (parser-validated field; preceding PROOF documents the bit-width invariant).")]
impl<'a> PartialEq for HbcFileEquiv<'a, V99> {
    fn eq(&self, other: &Self) -> bool {
        let a = self.file;
        let b = other.file;

        if a.version != b.version || a.version != V99::VERSION {
            return false;
        }

        if a.function_count != b.function_count
            || a.string_count != b.string_count
            || a.overflow_string_count != b.overflow_string_count
            || a.string_storage_size != b.string_storage_size
            || a.cjs_module_count != b.cjs_module_count
        {
            return false;
        }
        if a.regexp_count() != b.regexp_count()
            || a.bigint_count() != b.bigint_count()
            || a.object_shape_count() != b.object_shape_count()
        {
            return false;
        }
        if a.debug_info_offset() != b.debug_info_offset() {
            return false;
        }
        if a.use_v99_func_header() != b.use_v99_func_header()
            || a.has_num_string_switch_imms() != b.has_num_string_switch_imms()
        {
            return false;
        }

        if a.sections.len() != b.sections.len() {
            return false;
        }
        for (sa, sb) in a.sections.iter().zip(b.sections.iter()) {
            if sa.0 != sb.0 || sa.2 != sb.2 {
                return false;
            }
        }
        for (idx, (sa, sb)) in a.sections.iter().zip(b.sections.iter()).enumerate() {
            if idx == 0 && sa.0 == "Header" {
                continue;
            }
            let a_off = sa.1 as usize;
            let a_sz = sa.2 as usize;
            let b_off = sb.1 as usize;
            let b_sz = sb.2 as usize;
            let (Some(slice_a), Some(slice_b)) = (
                a.buf().get(a_off..a_off.saturating_add(a_sz)),
                b.buf().get(b_off..b_off.saturating_add(b_sz)),
            ) else {
                return false;
            };
            if slice_a != slice_b {
                return false;
            }
        }

        // v99 header layout matches late-v98 (numStringSwitchImms
        // always present + same BytecodeOptions offset), so reuse the
        // v98 range table with use_v99_header=true forced.
        if !header_passthrough_equiv_v98(a.buf(), b.buf(), true) {
            return false;
        }

        v98_v99_function_metadata_equiv(a, b)
    }
}

/// Shared function-metadata compare for v98/v99 equivalence — avoids
/// duplicating the per-function loop between the two impls since v99's
/// SmallFuncHeader layout is identical to late-v98. Returns false on
/// any disagreement; adversarial-overlap overflowed functions (with
/// `large_off < 128`) are excluded from the compare per the v96
/// precedent.
fn v98_v99_function_metadata_equiv(a: &HbcFile<'_>, b: &HbcFile<'_>) -> bool {
    for i in 0..a.function_count {
        let fa = a.function_get(i);
        let fb = b.function_get(i);

        let overflowed_adversarial = match a.raw_small_func_header_v98(i) {
            Some(raw) => {
                let (overflowed, large_off) = raw.overflowed_and_large_off();
                overflowed && large_off < 128
            }
            None => false,
        };
        if overflowed_adversarial {
            continue;
        }

        if fa.offset != fb.offset
            || fa.size != fb.size
            || fa.name_id != fb.name_id
            || fa.param_count != fb.param_count
            || fa.flags != fb.flags
            || fa.frame_size != fb.frame_size
        {
            return false;
        }
    }
    true
}

/// Sentinel tag emitted when `parse_literal_buffer` hits its defensive
/// catch-all arm. The downstream `resolve_buffers` pass in
/// `decompile::optimize` maps this to the `/* invalid literal tag */`
/// placeholder, rather than a `"?"` fallback which would be
/// indistinguishable from a legitimate string literal.
pub(crate) const LITERAL_TAG_INVALID: u8 = u8::MAX;

/// Parse serialized literal buffer.
///
/// The `type_tag = tag_byte & 0x70` mask is mathematically exhaustive over
/// the eight defined Hermes literal types (`0x00..=0x70` step `0x10`); the
/// catch-all arm below is therefore **unreachable via any byte input** and
/// serves only as a defensive contract against a future refactor that
/// widens the mask. When it does fire we tag the slot with
/// `LITERAL_TAG_INVALID` so downstream emission surfaces a loud
/// placeholder instead of silently producing a `null`-shaped
/// `LiteralValue { tag: 0, … }` that renders as `"?"`. Classification
/// uses the 5+1 split; locked by a direct-construction unit test below.
// WHY: `p` byte-walker with explicit `p + N <= buf.len()` bounds checks
#[allow(clippy::arithmetic_side_effects, reason = "`p` byte-walker with explicit `p + N <= buf.len()` bounds checks before every `p += N` in each literal-tag branch; `remaining -= items` bounded by loop iteration count.")]
// WHY: literal-buffer walker — u8/u16/u32 widens to u32/usize for tag
// + length decode; index bounds checked per-byte. See parser_inner's
// section-bounds gates for the upstream invariants.
#[allow(clippy::as_conversions, reason = "literal-buffer walker — u8/u16/u32 widens to u32/usize for tag + length decode; index bounds checked per-byte. See parser_inner's section-bounds gates for the upstream invariants.")]
#[allow(
    clippy::indexing_slicing,
    reason = "buf[p] / buf[p+N] reads guarded by per-branch p + N <= buf.len() and the outer while p < buf.len() loop gate"
)]
pub(crate) fn parse_literal_buffer(
    buf: &[u8],
    offset: u32,
    num_items: u32,
) -> Result<Vec<LiteralValue>, crate::error::HermesError> {
    use crate::error::HermesError;

    // Pre-allocate the output Vec to its expected length, capped by the
    // input buffer length. Each literal needs at least one tag byte, so
    // `num_items > buf.len()` is impossible on well-formed input; the
    // min() makes this safe against adversarial num_items = u32::MAX
    // without changing observable behavior. Eliminates Vec-doubling
    // realloc churn (a profiled hot-path during full-bundle decompile).
    let cap = (num_items as usize).min(buf.len());
    let mut out = Vec::with_capacity(cap);
    if offset as usize >= buf.len() {
        return Ok(out);
    }

    let mut p = offset as usize;
    let mut remaining = num_items;

    while remaining > 0 && p < buf.len() {
        let tag_byte = buf[p];
        p += 1;
        let (seq_len, type_tag);

        if tag_byte & 0x80 != 0 {
            if p >= buf.len() {
                break;
            }
            seq_len = (u32::from(tag_byte & 0x0F) << 8) | u32::from(buf[p]);
            p += 1;
            type_tag = tag_byte & 0x70;
        } else {
            seq_len = u32::from(tag_byte & 0x0F);
            type_tag = tag_byte & 0x70;
        }

        let items_to_read = remaining.min(seq_len);
        remaining -= items_to_read;

        for _ in 0..items_to_read {
            if p >= buf.len() {
                break;
            }
            let mut val = LiteralValue {
                tag: 0,
                str_id: 0,
                ival: 0,
                dval: 0.0,
            };
            match type_tag {
                0x00 => val.tag = 0, // Null
                0x10 => val.tag = 1, // True
                0x20 => val.tag = 2, // False
                0x30 => {
                    // Number (8 bytes). Without this typed Err, a
                    // bounds-fail would push a phantom
                    // `LiteralValue { tag: 3, dval: 0.0 }` and leave
                    // `p` unadvanced, so the outer loop would re-read
                    // the partial payload as a new tag — silent resync
                    // corruption. Returning typed `Err` breaks the
                    // outer loop by construction; `out` is discarded.
                    if p + 8 > buf.len() {
                        return Err(HermesError::TruncatedLiteralBuffer {
                            tag: 0x30,
                            expected_payload: 8,
                            remaining: buf.len() - p,
                        });
                    }
                    val.tag = 3;
                    val.dval = read_f64(buf, p);
                    p += 8;
                }
                0x40 => {
                    // LongString (4-byte index). See 0x30 note.
                    if p + 4 > buf.len() {
                        return Err(HermesError::TruncatedLiteralBuffer {
                            tag: 0x40,
                            expected_payload: 4,
                            remaining: buf.len() - p,
                        });
                    }
                    val.tag = 4;
                    val.str_id = read_u32(buf, p);
                    p += 4;
                }
                0x50 => {
                    // ShortString (2-byte index). See 0x30 note.
                    if p + 2 > buf.len() {
                        return Err(HermesError::TruncatedLiteralBuffer {
                            tag: 0x50,
                            expected_payload: 2,
                            remaining: buf.len() - p,
                        });
                    }
                    val.tag = 4;
                    val.str_id = u32::from(read_u16(buf, p));
                    p += 2;
                }
                0x60 => val.tag = 5, // Undefined
                0x70 => {
                    // Integer (4 bytes). See 0x30 note.
                    if p + 4 > buf.len() {
                        return Err(HermesError::TruncatedLiteralBuffer {
                            tag: 0x70,
                            expected_payload: 4,
                            remaining: buf.len() - p,
                        });
                    }
                    val.tag = 6;
                    val.ival = read_u32(buf, p) as i32;
                    p += 4;
                }
                // Unreachable: the `& 0x70` mask in both branches above
                // bounds `type_tag` to the eight arms already handled.
                // The arm exists only as a defensive contract; if it
                // ever fires we surface a sentinel tag so downstream
                // emit renders a loud placeholder rather than a
                // `null`-shaped fallback that collides with a real Null.
                _ => val.tag = LITERAL_TAG_INVALID,
            }
            out.push(val);
        }
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::super::bigint_le_twos_to_decimal;
    use super::*;
    use std::borrow::Cow;

    #[test]
    fn test_parse_basic_v99() {
        let Ok(data) = std::fs::read("tests/fixtures/basic_v99.hbc") else {
            eprintln!("SKIP: tests/fixtures/basic_v99.hbc not found");
            return;
        };
        let hbc = HbcFile::parse(&data, None).unwrap();
        assert_eq!(hbc.version, 99);
        assert_eq!(hbc.function_count, 10);
        assert!(hbc.string_count > 40);

        // Verify string access
        for i in 0..hbc.string_count {
            // In-test bare `expect` is allowed — typed Err here
            // indicates a fixture or logic regression.
            let s = hbc
                .string_as_str(i)
                .expect("string_as_str on basic_v99 fixture should not Err");
            // Should not panic
            let _ = s;
        }

        // Verify function access
        for i in 0..hbc.function_count {
            let f = hbc.function_get(i);
            assert!(f.offset > 0 || i == 0);
            assert!(f.size > 0);
        }

        // Check known strings exist
        let all_strings: Vec<String> = (0..hbc.string_count)
            .map(|i| {
                hbc.string_as_str(i)
                    .expect("string_as_str on basic_v99 fixture should not Err")
                    .map(Cow::into_owned)
                    .unwrap_or_default()
            })
            .collect();
        assert!(all_strings.iter().any(|s| s == "fibonacci"));
        assert!(all_strings.iter().any(|s| s.contains("sk_test")));
    }

    #[test]
    fn test_parse_all_versions() {
        let mut skipped = 0;
        for v in [
            84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99,
        ] {
            let path = format!("tests/fixtures/basic_v{v}.hbc");
            let Ok(data) = std::fs::read(&path) else {
                skipped += 1;
                continue;
            };
            let hbc = HbcFile::parse(&data, None).unwrap_or_else(|e| panic!("v{v}: {e}"));
            assert_eq!(hbc.version, v, "v{v}: wrong version");
            assert_eq!(hbc.function_count, 10, "v{v}: wrong function count");
            assert!(hbc.string_count > 30, "v{v}: too few strings");

            // All functions should parse
            for i in 0..hbc.function_count {
                let f = hbc.function_get(i);
                assert!(f.size > 0, "v{v} func {i}: zero size");
            }

            // All strings should parse
            for i in 0..hbc.string_count {
                let _ = hbc
                    .string_as_str(i)
                    .unwrap_or_else(|e| panic!("v{v} idx {i}: string_as_str: {e}"));
            }
        }
        if skipped > 0 {
            eprintln!("SKIP: {skipped} HBC fixtures not found");
        }
    }

    // test_parser_matches_ffi removed — FFI has been deleted.
    // The parser was validated against C++ FFI on all 16 versions before removal.

    /// Locks the defensive-contract classification of the `_ =>` catch-all in
    /// `parse_literal_buffer`. The `type_tag = tag_byte & 0x70` mask has
    /// exactly eight possible outputs (`0x00..=0x70` step `0x10`) and all
    /// eight are explicitly matched — the catch-all is mathematically
    /// unreachable via any byte input. This test enumerates every possible
    /// `tag_byte` and asserts the produced tag is in `{0..=6}`, never
    /// `LITERAL_TAG_INVALID`. If a future refactor widens the mask or adds
    /// a ninth tag without extending the match, the sweep fires.
    #[test]
    fn parse_literal_buffer_tag_mask_is_exhaustive_over_all_bytes() {
        for tag_byte in 0u8..=255 {
            // Short-form (bit-7 clear) with seq_len == 1 and a 4-byte
            // payload is enough to drive every type_tag arm without
            // short-reading. Values that set the extension bit (0x80) are
            // exercised by the `_extended` case below.
            if tag_byte & 0x80 != 0 {
                continue;
            }
            let short_tag = (tag_byte & 0x70) | 0x01;
            let mut buf = vec![short_tag];
            buf.extend_from_slice(&[0u8; 8]);
            let out = parse_literal_buffer(&buf, 0, 1)
                .expect("well-formed input must not surface TruncatedLiteralBuffer");
            assert_eq!(out.len(), 1, "tag_byte={tag_byte:#x}");
            let produced = out[0].tag;
            assert!(
                produced <= 6,
                "short-form tag_byte={tag_byte:#x} produced tag={produced}; \
                 expected 0..=6 (catch-all is unreachable via byte input)"
            );
            assert_ne!(
                produced, LITERAL_TAG_INVALID,
                "short-form tag_byte={tag_byte:#x} hit the defensive catch-all; \
                 the `& 0x70` mask exhaustiveness has regressed"
            );
        }
    }

    /// Extension-bit (0x80) variant of the above sweep — the extended
    /// decoding path reads one extra byte for `seq_len` but uses the same
    /// `& 0x70` mask for `type_tag`. Lock both paths so the defensive
    /// arm's unreachability is invariant across the two decoding modes.
    #[test]
    fn parse_literal_buffer_tag_mask_is_exhaustive_extended() {
        for tag_byte in 128u8..=255 {
            // Set seq_len=1 via the low-nibble of tag_byte + the
            // second-byte extension. We want the mask output to vary, so
            // iterate every byte in 0x80..=0xFF.
            let mut buf = vec![tag_byte, 0x01];
            buf.extend_from_slice(&[0u8; 8]);
            let out = parse_literal_buffer(&buf, 0, 1)
                .expect("well-formed input must not surface TruncatedLiteralBuffer");
            assert_eq!(out.len(), 1, "tag_byte={tag_byte:#x}");
            let produced = out[0].tag;
            assert!(
                produced <= 6,
                "extended tag_byte={tag_byte:#x} produced tag={produced}; \
                 expected 0..=6"
            );
            assert_ne!(
                produced, LITERAL_TAG_INVALID,
                "extended tag_byte={tag_byte:#x} hit the defensive catch-all"
            );
        }
    }

    /// Positive sanity: the `LITERAL_TAG_INVALID` sentinel round-trips
    /// through a directly-constructed `LiteralValue` and does not overlap
    /// with any well-formed tag value in `{0..=6}`. Locks the sentinel
    /// constant so a future change that reuses `u8::MAX` for a new
    /// well-formed tag fires this test.
    #[test]
    fn literal_tag_invalid_sentinel_does_not_overlap_well_formed_tags() {
        for t in 0u8..=6 {
            assert_ne!(
                t, LITERAL_TAG_INVALID,
                "LITERAL_TAG_INVALID ({LITERAL_TAG_INVALID}) overlaps \
                 well-formed literal tag {t}"
            );
        }
        let v = LiteralValue {
            tag: LITERAL_TAG_INVALID,
            str_id: 0,
            ival: 0,
            dval: 0.0,
        };
        assert_eq!(v.tag, u8::MAX);
    }

    // ── TruncatedLiteralBuffer typed-Err contract ──────────────────────────
    //
    // Without this typed Err, `parse_literal_buffer` would push a
    // phantom-default LiteralValue (tag=3/4/4/6, payload=defaults) when
    // a 0x30/0x40/0x50/0x70 item's payload underran the buffer, and
    // would NOT advance `p` past the partial entry. The outer loop
    // would then re-read the same byte as a new tag — silent resync
    // corruption. Returning `HermesError::TruncatedLiteralBuffer`
    // directly breaks the outer loop by construction.

    /// 0x30 (Number) needs 8 payload bytes; provide only 7.
    #[test]
    fn parse_literal_buffer_truncated_number_payload_returns_typed_err() {
        use crate::error::HermesError;
        // tag byte 0x31 = type 0x30 (Number) + seq_len 1.
        let mut buf = vec![0x31u8];
        buf.extend_from_slice(&[0u8; 7]); // 7 bytes — 1 short of 8.
        let err = match parse_literal_buffer(&buf, 0, 1) {
            Ok(_) => panic!("7-byte Number payload must trip TruncatedLiteralBuffer, got Ok"),
            Err(e) => e,
        };
        match err {
            HermesError::TruncatedLiteralBuffer { tag, expected_payload, remaining } => {
                assert_eq!(tag, 0x30, "variant carries the offending tag");
                assert_eq!(expected_payload, 8, "Number declares 8-byte payload");
                assert_eq!(remaining, 7, "buf had 7 bytes left after the tag byte");
            }
            other => panic!("expected TruncatedLiteralBuffer, got {other:?}"),
        }
    }

    /// 0x40 (LongString) needs 4 payload bytes; provide only 3.
    #[test]
    fn parse_literal_buffer_truncated_long_string_payload_returns_typed_err() {
        use crate::error::HermesError;
        let mut buf = vec![0x41u8]; // type 0x40 + seq_len 1
        buf.extend_from_slice(&[0u8; 3]);
        let err = match parse_literal_buffer(&buf, 0, 1) {
            Ok(_) => panic!("3-byte LongString payload must trip TruncatedLiteralBuffer, got Ok"),
            Err(e) => e,
        };
        assert!(
            matches!(
                err,
                HermesError::TruncatedLiteralBuffer {
                    tag: 0x40,
                    expected_payload: 4,
                    remaining: 3
                }
            ),
            "expected TruncatedLiteralBuffer {{ tag: 0x40, expected_payload: 4, remaining: 3 }}, got {err:?}"
        );
    }

    /// 0x50 (ShortString) needs 2 payload bytes; provide only 1.
    #[test]
    fn parse_literal_buffer_truncated_short_string_payload_returns_typed_err() {
        use crate::error::HermesError;
        let mut buf = vec![0x51u8]; // type 0x50 + seq_len 1
        buf.extend_from_slice(&[0u8; 1]);
        let err = match parse_literal_buffer(&buf, 0, 1) {
            Ok(_) => panic!("1-byte ShortString payload must trip TruncatedLiteralBuffer, got Ok"),
            Err(e) => e,
        };
        assert!(
            matches!(
                err,
                HermesError::TruncatedLiteralBuffer {
                    tag: 0x50,
                    expected_payload: 2,
                    remaining: 1
                }
            ),
            "expected TruncatedLiteralBuffer {{ tag: 0x50, expected_payload: 2, remaining: 1 }}, got {err:?}"
        );
    }

    /// 0x70 (Integer) needs 4 payload bytes; provide only 3.
    #[test]
    fn parse_literal_buffer_truncated_integer_payload_returns_typed_err() {
        use crate::error::HermesError;
        let mut buf = vec![0x71u8]; // type 0x70 + seq_len 1
        buf.extend_from_slice(&[0u8; 3]);
        let err = match parse_literal_buffer(&buf, 0, 1) {
            Ok(_) => panic!("3-byte Integer payload must trip TruncatedLiteralBuffer, got Ok"),
            Err(e) => e,
        };
        assert!(
            matches!(
                err,
                HermesError::TruncatedLiteralBuffer {
                    tag: 0x70,
                    expected_payload: 4,
                    remaining: 3
                }
            ),
            "expected TruncatedLiteralBuffer {{ tag: 0x70, expected_payload: 4, remaining: 3 }}, got {err:?}"
        );
    }

    /// Silent resync corruption regression test: a single 0x30 tag with 7
    /// payload bytes would otherwise produce TWO LiteralValues (a
    /// phantom Number 0.0 from the truncated payload, then another
    /// tag-read from the partial-payload byte). The typed Err breaks
    /// the outer loop so no second iteration happens.
    #[test]
    fn parse_literal_buffer_truncation_does_not_resync_into_phantom_item() {
        // 0x32 = type 0x30 + seq_len 2 (two Number items declared).
        let mut buf = vec![0x32u8];
        buf.extend_from_slice(&[0u8; 7]); // 7 bytes — first item underruns, second item shouldn't happen.
        let result = parse_literal_buffer(&buf, 0, 2);
        // The resync-permissive shape would return
        // Ok(vec![Number(0.0), Number(0.0)]) — phantom from the
        // truncation + resync corruption. The typed-Err contract
        // requires Err on the first item.
        assert!(
            result.is_err(),
            "must Err on the first truncated item — not resync into a \
             phantom"
        );
    }

    // ── bigint_le_twos_to_decimal helper ──────────────────────────────────
    // Covers the 5 edge cases: empty slice, single-byte positive,
    // negative-sign-bit, multi-byte positive, the batch2 30-digit fixture
    // value, and zero-padding handling.

    #[test]
    fn bigint_le_twos_empty_is_zero() {
        assert_eq!(bigint_le_twos_to_decimal(&[]), "0");
    }

    #[test]
    fn bigint_le_twos_single_byte_positive() {
        assert_eq!(bigint_le_twos_to_decimal(&[0x7B]), "123");
        assert_eq!(bigint_le_twos_to_decimal(&[0x00]), "0");
        assert_eq!(bigint_le_twos_to_decimal(&[0x01]), "1");
        assert_eq!(bigint_le_twos_to_decimal(&[0x7F]), "127");
    }

    #[test]
    fn bigint_le_twos_negative_sign_bit() {
        // All bits set in a single byte is two's-complement -1.
        assert_eq!(bigint_le_twos_to_decimal(&[0xFF]), "-1");
        // 0x80 is -128.
        assert_eq!(bigint_le_twos_to_decimal(&[0x80]), "-128");
        // Multi-byte negative: -2 is 0xFE 0xFF (LE).
        assert_eq!(bigint_le_twos_to_decimal(&[0xFE, 0xFF]), "-2");
    }

    #[test]
    fn bigint_le_twos_multi_byte_positive() {
        // 1234 = 0x04D2 → LE bytes [0xD2, 0x04].
        assert_eq!(bigint_le_twos_to_decimal(&[0xD2, 0x04]), "1234");
        // 65535 = 0xFFFF needs a trailing zero byte to prevent the MSB
        // sign bit from flipping the interpretation to -1.
        assert_eq!(bigint_le_twos_to_decimal(&[0xFF, 0xFF, 0x00]), "65535");
    }

    #[test]
    fn bigint_le_twos_batch2_fixture_30_digits() {
        // `123456789012345678901234567890n` in LE two's-complement.
        // Canonical hex (big-endian): 0x01 8EE9 0FF6 C373 E0EE 4E3F 0AD2.
        // Hermes encodes with a leading 0x00 byte when the positive
        // value's natural MSB has its sign bit set — but this value's
        // natural MSB (`0x01`) is safe, so no padding is needed.
        let le: Vec<u8> = vec![
            0xD2, 0x0A, 0x3F, 0x4E, 0xEE, 0xE0, 0x73, 0xC3, 0xF6, 0x0F, 0xE9, 0x8E, 0x01,
        ];
        assert_eq!(
            bigint_le_twos_to_decimal(&le),
            "123456789012345678901234567890"
        );
    }

    #[test]
    fn bigint_le_twos_zero_padding_positive() {
        // Positive value with explicit trailing zero sign-pad byte —
        // the magnitude should collapse and digits stay correct.
        assert_eq!(bigint_le_twos_to_decimal(&[0x7B, 0x00]), "123");
        // All zero magnitude with padding → "0".
        assert_eq!(bigint_le_twos_to_decimal(&[0x00, 0x00, 0x00]), "0");
    }

    #[test]
    fn bigint_as_str_roundtrip_via_synthetic_hbc() {
        // End-to-end check: construct a minimal synthetic HBC blob whose
        // big_int_table + big_int_storage hold one known entry, verify
        // that HbcFile::bigint_as_str returns the expected decimal.
        //
        // A full v87+ HBC header is complex; instead, we stitch an HbcFile
        // by hand using the struct fields exposed for testing at
        // module-visibility. Because the fields are crate-private, this
        // test uses the parser-internal constructor indirectly: we build
        // a fake buf with known offsets and populate the section tuples.
        //
        // Layout inside `buf`:
        //   [0..8)    — BigIntTable entry: offset=0 (into storage), length=1
        //   [8..9)    — BigIntStorage: byte 0x7B
        let buf: Vec<u8> = {
            let mut b = Vec::new();
            b.extend_from_slice(&0u32.to_le_bytes()); // storage offset 0
            b.extend_from_slice(&1u32.to_le_bytes()); // length 1
            b.push(0x7B); // the value 123
            b
        };
        let hbc = HbcFile {
            buf: &buf,
            header: crate::header::HbcHeader::V87to96(crate::header::V87to96Header {
                version: 87,
                file_length: 0,
                global_code_index: 0,
                function_count: 0,
                string_kind_count: 0,
                identifier_count: 0,
                string_count: 0,
                overflow_string_count: 0,
                string_storage_size: 0,
                big_int_count: 1,
                big_int_storage_size: 1,
                reg_exp_count: 0,
                reg_exp_storage_size: 0,
                array_buffer_size: 0,
                obj_key_buffer_size: 0,
                obj_value_buffer_size: 0,
                segment_id: 0,
                cjs_module_count: 0,
                function_source_count: 0,
                debug_info_offset: 0,
            }),
            version: 87,
            function_count: 0,
            string_kind_count: 0,
            identifier_count: 0,
            string_count: 0,
            overflow_string_count: 0,
            string_storage_size: 0,
            cjs_module_count: 0,
            reg_exp_count: 0,
            reg_exp_storage_size: 0,
            function_source_count: 0,
            func_header_size: 12,
            debug_info_offset: 0,
            obj_shape_table_count: 0,
            use_v99_func_header: false,
            func_headers: (0, 0),
            small_string_table: (0, 0),
            overflow_string_table: (0, 0),
            string_storage: (0, 0),
            string_kinds: (0, 0),
            cjs_modules: (0, 0),
            regexp_table: (0, 0),
            array_buffer: (0, 0),
            obj_key_buffer: (0, 0),
            obj_value_buffer: (0, 0),
            obj_shape_table: (0, 0),
            big_int_count: 1,
            big_int_table: (0, 8),
            big_int_storage: (8, 1),
            debug_filename_count: 0,
            debug_filename_table: (0, 0),
            debug_filename_storage: (0, 0),
            debug_info_v96: None,
            string_kind_map: Vec::new(),
            bytecode_region: (0, 0),
            sections: Vec::new(),
            input_hash: String::new(),
        };
        assert_eq!(hbc.bigint_as_str(0), Some("123".to_string()));
        // Out-of-bounds index → None, no panic.
        assert_eq!(hbc.bigint_as_str(1), None);
        assert_eq!(hbc.bigint_as_str(u32::MAX), None);
    }

    /// A BigInt storage entry whose byte length exceeds
    /// [`crate::finding::MAX_BIGINT_BYTES`] must short-circuit
    /// `bigint_as_str` to `None` (skipping the O(N²) accumulator) and
    /// emit [`crate::finding::HermesFinding::BigIntTooLarge`] with the
    /// observed/limit pair on the thread-local channel.
    #[test]
    fn bigint_as_str_over_cap_returns_none_and_emits_finding() {
        let _ = crate::finding::drain_findings_for_test();

        // Layout inside `buf`:
        //   [0..8)                — BigIntTable entry: offset=0, length=N
        //   [8..8+N)              — BigIntStorage: N zero bytes
        // Storage byte count = MAX_BIGINT_BYTES + 1 so the cap trips.
        let n: u32 = crate::finding::MAX_BIGINT_BYTES + 1;
        let n_usize = n as usize;
        let buf: Vec<u8> = {
            let mut b = Vec::new();
            b.extend_from_slice(&0u32.to_le_bytes()); // storage offset 0
            b.extend_from_slice(&n.to_le_bytes()); // length = MAX+1
            b.extend(std::iter::repeat_n(0u8, n_usize));
            b
        };
        let hbc = HbcFile {
            buf: &buf,
            header: crate::header::HbcHeader::V87to96(crate::header::V87to96Header {
                version: 87,
                file_length: 0,
                global_code_index: 0,
                function_count: 0,
                string_kind_count: 0,
                identifier_count: 0,
                string_count: 0,
                overflow_string_count: 0,
                string_storage_size: 0,
                big_int_count: 1,
                big_int_storage_size: n,
                reg_exp_count: 0,
                reg_exp_storage_size: 0,
                array_buffer_size: 0,
                obj_key_buffer_size: 0,
                obj_value_buffer_size: 0,
                segment_id: 0,
                cjs_module_count: 0,
                function_source_count: 0,
                debug_info_offset: 0,
            }),
            version: 87,
            function_count: 0,
            string_kind_count: 0,
            identifier_count: 0,
            string_count: 0,
            overflow_string_count: 0,
            string_storage_size: 0,
            cjs_module_count: 0,
            reg_exp_count: 0,
            reg_exp_storage_size: 0,
            function_source_count: 0,
            func_header_size: 12,
            debug_info_offset: 0,
            obj_shape_table_count: 0,
            use_v99_func_header: false,
            func_headers: (0, 0),
            small_string_table: (0, 0),
            overflow_string_table: (0, 0),
            string_storage: (0, 0),
            string_kinds: (0, 0),
            cjs_modules: (0, 0),
            regexp_table: (0, 0),
            array_buffer: (0, 0),
            obj_key_buffer: (0, 0),
            obj_value_buffer: (0, 0),
            obj_shape_table: (0, 0),
            big_int_count: 1,
            big_int_table: (0, 8),
            big_int_storage: (8, n_usize),
            debug_filename_count: 0,
            debug_filename_table: (0, 0),
            debug_filename_storage: (0, 0),
            debug_info_v96: None,
            string_kind_map: Vec::new(),
            bytecode_region: (0, 0),
            sections: Vec::new(),
            input_hash: String::new(),
        };

        // Wall-clock guard: skipping the O(N²) helper means this call
        // returns in microseconds. Even if the cap were missing, an
        // N²-on-4097-bytes path is ~40M mul-adds — comfortably under
        // 1 s, so this assertion is a smoke-floor (it would catch a
        // regression to "no cap and decimal-conversion path opens up
        // for arbitrarily large N").
        let started = std::time::Instant::now();
        let got = hbc.bigint_as_str(0);
        let elapsed = started.elapsed();
        assert_eq!(got, None);
        assert!(
            elapsed < std::time::Duration::from_millis(50),
            "over-cap call should short-circuit; took {elapsed:?}"
        );

        let findings = crate::finding::drain_findings_for_test();
        let saw_cap = findings.iter().any(|f| {
            matches!(
                f,
                crate::finding::HermesFinding::BigIntTooLarge {
                    index,
                    observed,
                    limit,
                } if *index == 0
                    && *observed == n
                    && *limit == crate::finding::MAX_BIGINT_BYTES
            )
        });
        assert!(
            saw_cap,
            "expected HermesFinding::BigIntTooLarge, got {findings:?}"
        );
    }

    /// Build a 144-byte v96 HBC blob carrying one overflowed function
    /// header whose `large_off + 32` exceeds `buf.len()`. Used by the
    /// `get_exc_table_offset_prev97_overflowed_oob_returns_zero` test
    /// to drive the PreV84/V84-V96 overflowed branch's bounds guard.
    fn build_prev97_overflowed_oob_hbc() -> Vec<u8> {
        // Layout: 128B Header + 16B FunctionHeaders (1 entry, v96 stride) = 144B.
        let mut buf = vec![0u8; 144];

        // Magic + version 96.
        buf[0..8].copy_from_slice(&0x1F1903C103BC1FC6u64.to_le_bytes());
        buf[8..12].copy_from_slice(&96u32.to_le_bytes());
        // file_length informational @32.
        buf[32..36].copy_from_slice(&144u32.to_le_bytes());
        // function_count @40 = 1.
        buf[40..44].copy_from_slice(&1u32.to_le_bytes());
        // Remaining counts (string_*, overflow_string_*, ...) = 0 so each
        // section!-tracked region collapses to zero size.

        // FunctionHeaders @128: one 16-byte entry.
        //
        // v96 bitfield layout per `get_exc_table_offset`:
        //   bits   0..25  offset    → 0
        //   bits  25..32  param_count → 0
        //   bits  32..47  byte_size → 0
        //   bits  47..64  func_name → 0
        //   bits  64..89  info_offset → 256 (large_off = 256 << 16 = 16_777_216 ≫ buf.len())
        //   byte 15       flags_byte → 0x20 (bit 5 set = overflowed)
        //
        // Word 2 (bytes 8..12) carries `info_offset` in its low 25 bits.
        buf[128 + 8..128 + 12].copy_from_slice(&256u32.to_le_bytes());
        // flags_byte at entry[15] = absolute offset 128+15 = 143.
        buf[143] = 0x20;
        buf
    }

    #[test]
    fn get_exc_table_offset_prev97_overflowed_oob_returns_zero() {
        // Pre-validation behaviour pinned a defense-in-depth guard
        // inside `get_exc_table_offset` that returned 0 when the
        // PreV84/V84-V96 overflowed branch saw `large_off + 32 >
        // buf.len()`. The parser-time `validate_function_regions` pass
        // now catches the same shape one layer earlier via the strict
        // `function_get_checked` API, surfacing
        // `OverflowedHeaderOutOfBounds` before the inner guard is
        // reached. This test pins the parse-time rejection; the inner
        // guard itself is exercised directly by
        // `get_exc_table_offset_prev97_inner_guard_returns_zero_on_oob`
        // below (manual HbcFile construction bypasses validate, so the
        // PreV84/V84-V96 large_off+32 guard fires).
        let bytes = build_prev97_overflowed_oob_hbc();
        match HbcFile::parse(&bytes, None) {
            Err(crate::error::HermesError::OverflowedHeaderOutOfBounds {
                func_idx, ..
            }) => {
                assert_eq!(func_idx, 0);
            }
            Ok(_) => {
                panic!("parse must reject the OOB-overflow fixture via the strict API")
            }
            Err(other) => panic!("unexpected parse error: {other:?}"),
        }
    }

    /// Pins the PreV84/V84-V96 `large_off + 32 > buf.len()` guard
    /// inside `get_exc_table_offset` directly. Required because
    /// `validate_function_regions` now intercepts the OOB-overflow
    /// shape at parse time, so the inner guard is unreachable via
    /// `HbcFile::parse`. Manual HbcFile construction (struct literal,
    /// bypassing parse) restores direct coverage of the inner guard's
    /// zero-return path.
    #[test]
    fn get_exc_table_offset_prev97_inner_guard_returns_zero_on_oob() {
        // Same byte layout as `build_prev97_overflowed_oob_hbc`: v96
        // header, function_count=1, one overflowed function with
        // info_offset=256 so `large_off = 256 << 16 = 16_777_216` is
        // far past the 144-byte buf bound.
        let bytes = build_prev97_overflowed_oob_hbc();
        // Construct HbcFile manually so we bypass the new parse-time
        // strict-API rejection. Only the fields `get_exc_table_offset`
        // reads (`func_headers`, `func_header_size`, `header`, `buf`)
        // need real values; the rest can be defaults.
        let hbc = HbcFile {
            buf: &bytes,
            header: crate::header::HbcHeader::V87to96(crate::header::V87to96Header {
                version: 96,
                file_length: 144,
                global_code_index: 0,
                function_count: 1,
                string_kind_count: 0,
                identifier_count: 0,
                string_count: 0,
                overflow_string_count: 0,
                string_storage_size: 0,
                big_int_count: 0,
                big_int_storage_size: 0,
                reg_exp_count: 0,
                reg_exp_storage_size: 0,
                array_buffer_size: 0,
                obj_key_buffer_size: 0,
                obj_value_buffer_size: 0,
                segment_id: 0,
                cjs_module_count: 0,
                function_source_count: 0,
                debug_info_offset: 0,
            }),
            version: 96,
            function_count: 1,
            string_kind_count: 0,
            identifier_count: 0,
            string_count: 0,
            overflow_string_count: 0,
            string_storage_size: 0,
            cjs_module_count: 0,
            reg_exp_count: 0,
            reg_exp_storage_size: 0,
            function_source_count: 0,
            func_header_size: 16,
            debug_info_offset: 0,
            obj_shape_table_count: 0,
            use_v99_func_header: false,
            func_headers: (128, 16),
            small_string_table: (0, 0),
            overflow_string_table: (0, 0),
            string_storage: (0, 0),
            string_kinds: (0, 0),
            cjs_modules: (0, 0),
            regexp_table: (0, 0),
            array_buffer: (0, 0),
            obj_key_buffer: (0, 0),
            obj_value_buffer: (0, 0),
            obj_shape_table: (0, 0),
            big_int_count: 0,
            big_int_table: (0, 0),
            big_int_storage: (0, 0),
            debug_filename_count: 0,
            debug_filename_table: (0, 0),
            debug_filename_storage: (0, 0),
            debug_info_v96: None,
            string_kind_map: Vec::new(),
            bytecode_region: (144, 144),
            sections: Vec::new(),
            input_hash: String::new(),
        };
        // Direct call: the inner guard at `large_off + 32 > buf.len()`
        // fires (16_777_216 + 32 > 144) and returns 0.
        let inner = hbc.get_exc_table_offset(0);
        assert_eq!(
            inner, 0,
            "PreV84/V84-V96 overflowed OOB inner guard must return 0"
        );
    }
}
