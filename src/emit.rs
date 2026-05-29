//! HBC bytecode emitter — `parse ∘ emit ∘ parse == parse` round-trip.
//!
//! Scope v1: HBC version 96 only. v96 is the dominant version in
//! production RN HBC bundles. Non-v96 (v98 / v84) versions are
//! out-of-scope for v1 emit. Round-trip equivalence is defined by
//! `parser::HbcFileEquiv<V96>` — the `impl PartialEq` there IS the emit
//! specification (spec-first discipline: the equivalence class is
//! authored before any emit code; emit derives from it).
//!
//! ## Per-section mode contract
//!
//! **SYNTHESIZE** (6 sections): Header, FunctionHeaders,
//! SmallStringTable, OverflowStringTable, RegExpTable, BigIntTable.
//! Emit reconstructs these from IR fields + `NonDecreasing<T>`
//! invariants.
//!
//! **PASSTHROUGH** (10 sections + function bodies): StringStorage,
//! ObjValueBuffer, ArrayBuffer, RegExpStorage, IdentifierHashes,
//! ObjKeyBuffer, FunctionSourceTable, BigIntStorage, StringKinds +
//! per-function bytecode bodies. Emit slices bytes from `HbcFile::buf()`.
//!
//! **FIRM-SKIP** (1 section): CJSModules (section only written when
//! `cjs_module_count > 0`).
//!
//! **PASSTHROUGH for debug_info**: HBC debug_info is a line-number /
//! scope-chain table (not DEX's dangling-pointer-vector format).
//! Stripping would destroy reverse-engineering signal without security
//! benefit. Emit preserves `debug_info_offset` from IR + section bytes
//! via body passthrough.
//!
//! **N/A**: ObjShapeTable (pre-v97 layout doesn't have it).
//!
//! ## SHA1 reframe
//!
//! The 20-byte field at HBC header offset 12 is `sourceHash` (SHA1 of
//! the **original JavaScript source** per Hermes upstream
//! `BCFileHeader::sourceHash`), **not** a bytecode integrity checksum.
//! Parse-side validation is impossible (no source access); emit-side
//! recompute is meaningless. Emit preserves the 20 bytes verbatim from
//! `&buf[12..32]`. No cryptographic operation in this module.
//!
//! ## Landing progress
//!
//! - Phase 1: Header synthesize + passthrough baseline for sections body.
//!   Proves header IR fields agree with bytes.
//! - Phases 2-5: progressively replace passthrough with section-by-section
//!   synthesize.
#![allow(missing_docs, reason = "internal")]

use crate::parser::{
    HbcFile, HbcVersion, ObjShapeTableEntryV98Raw, SmallFuncHeaderV96Raw,
    SmallFuncHeaderV98Raw, SmallStringTableEntryV96Raw, V84, V96, V98, V99,
};
use thiserror::Error;

/// Hermes HBC magic constant (first 8 bytes of every HBC file).
const HBC_MAGIC: u64 = 0x1F19_03C1_03BC_1FC6;

/// v96 HBC file header size in bytes (fixed layout; spec-defined).
const HEADER_SIZE: usize = 128;

/// v96 SmallFuncHeader entry byte-size (fixed). Pre-v97 layout; v97+
/// uses 12.
const SMALL_FUNC_HEADER_V96_SIZE: usize = 16;

/// v97+ SmallFuncHeader entry byte-size. v98 uses this (both early +
/// late variants pack into 12 bytes; they differ only in bit
/// partitioning, not byte count).
const SMALL_FUNC_HEADER_V98_SIZE: usize = 12;

/// Shared format gate: the SmallStringTable / OverflowStringTable /
/// RegExpTable / BigIntTable encoding is bit-identical across every
/// emit-supported version (v84 / v96 / v98 / v99), so their emit
/// helpers accept any of them. Narrower gates (`require_v84_or_v96`
/// for the 16-byte SmallFuncHeader path; `require_v98_or_v99` for
/// the 12-byte SmallFuncHeader path) apply to version-specific
/// helpers.
fn require_shared_table_format(file: &HbcFile<'_>) -> Result<(), HermesEmitError> {
    if file.version == V84::VERSION
        || file.version == V96::VERSION
        || file.version == V98::VERSION
        || file.version == V99::VERSION
    {
        Ok(())
    } else {
        Err(HermesEmitError::VersionMismatch {
            expected: V96::VERSION,
            got: file.version,
        })
    }
}

/// v84-or-v96 gate for the 16-byte pre-v97 SmallFuncHeader path. Both
/// versions share the same bit-layout (offset 25b + param_count 7b +
/// byte_size 15b + func_name 17b + info_offset 25b + uncharacterized
/// 31b + flags_byte at byte[15]), so `emit_function_headers_v96` +
/// `SmallFuncHeaderV96Raw` are reused for v84 via this widened gate.
fn require_v84_or_v96(file: &HbcFile<'_>) -> Result<(), HermesEmitError> {
    if file.version == V84::VERSION || file.version == V96::VERSION {
        Ok(())
    } else {
        Err(HermesEmitError::VersionMismatch {
            expected: V96::VERSION,
            got: file.version,
        })
    }
}

/// v98-or-v99 gate used by the shared late-v98/v99 synthesize path.
/// Both versions produce bytewise-identical output for the
/// FunctionHeaders + ObjShapeTable synthesize regions because v99 is
/// defined to share the late-v98 layout (per
/// `parser::parse_inner::use_v99_header`).
fn require_v98_or_v99(file: &HbcFile<'_>) -> Result<(), HermesEmitError> {
    if file.version == V98::VERSION || file.version == V99::VERSION {
        Ok(())
    } else {
        Err(HermesEmitError::VersionMismatch {
            expected: V98::VERSION,
            got: file.version,
        })
    }
}

/// Type-level witness that emit produces function IDs in non-decreasing
/// order. v1 use-case is trivially satisfied (linear `0..function_count`
/// iteration), but the newtype future-proofs the emit path against IR
/// mutations that attempt to reorder functions: the constructor is
/// `pub(crate)` + the only advance path is `.next()` which requires the
/// previous witness, so a mis-sequenced reordering (via `unsafe` or a
/// downstream IR-mutation pass) is a compile-time error at the callsite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct NonDecreasing<T: PartialOrd + Copy>(T);

impl<T: PartialOrd + Copy> NonDecreasing<T> {
    /// Start a fresh non-decreasing sequence at `initial`.
    pub(crate) fn start(initial: T) -> Self {
        Self(initial)
    }

    /// Advance to `next` if it preserves the non-decreasing invariant.
    /// Returns `None` on misorder — caller can `?`-propagate to reject
    /// the emit.
    pub(crate) fn advance(self, next: T) -> Option<Self> {
        if next >= self.0 {
            Some(Self(next))
        } else {
            None
        }
    }
}

/// FunctionId — emit-side 0-based function index. Wrapper over `u32` so
/// the `NonDecreasing<FunctionId>` type-level witness is distinct from
/// e.g. `NonDecreasing<u32>` on unrelated counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct FunctionId(u32);

/// OR-write the low `num_bits` of `value` into `out` starting at
/// `start_bit`. Inverse of `parser::read_bitfield`. Silently truncates
/// writes past the end of `out` — callers ensure
/// `out.len() * 8 >= start_bit + num_bits`.
///
/// Output must be zero-initialized for the bit-range being written (the
/// OR-semantics preserve any non-zero bits outside the write range, but
/// OR'ing into already-set bits would produce the union of old+new
/// values — wrong). The v96 synthesize callers all write into a fresh
/// 16-byte zero'd buffer per entry, so this constraint is satisfied by
/// construction.
#[allow(clippy::arithmetic_side_effects, reason = "Parser-bounded arithmetic; surrounding loop guards ensure offsets remain within the slice (see preceding PROOF in this function or block).")]
fn bit_pack_u32(out: &mut [u8], start_bit: u32, num_bits: u32, value: u32) {
    debug_assert!(num_bits <= 32, "bit_pack_u32 caps at 32 bits");
    debug_assert!(
        num_bits == 32 || value < (1u32 << num_bits),
        "value 0x{value:x} exceeds {num_bits}-bit field"
    );

    let mut bit_idx = start_bit;
    let mut written: u32 = 0;
    while written < num_bits {
        #[allow(clippy::as_conversions, reason = "bit_idx / 8 + 1 <= out.len() is ensured by callers (emit_function_headers_v96 passes a 16-byte buffer with start_bit + num_bits ≤ 128); defense-in-depth bounds check mirrors read_bitfield's early break on out-of-bounds.")]
        let byte_idx = (bit_idx / 8) as usize;
        let bits_in_byte = 8 - (bit_idx % 8);
        let bits_to_write = bits_in_byte.min(num_bits - written);
        let mask = if bits_to_write == 32 {
            u32::MAX
        } else {
            (1u32 << bits_to_write) - 1
        };
        let shift = bit_idx % 8;
        #[allow(clippy::as_conversions, clippy::cast_possible_truncation, reason = "u32→u8 narrows; `mask` is at most 8 bits wide (`bits_in_byte` ≤ 8), so the masked value fits in u8 by construction — truncation cannot fire.")]
        let value_chunk = ((value >> written) & mask) as u8;
        let Some(slot) = out.get_mut(byte_idx) else { break };
        *slot |= value_chunk << shift;
        written += bits_to_write;
        bit_idx += bits_to_write;
    }
}

/// Emit-side typed error surface. `ChecksumRecomputeFailed` is absent
/// because HBC `sourceHash` is a hash of the original JavaScript source,
/// not a recomputed bytecode-integrity field.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum HermesEmitError {
    /// A section's byte-size width-narrows on attacker-controlled IR
    /// values (e.g. `file_length` u32 narrowing on a ≥4 GiB emit; a
    /// section's `count × stride` exceeding u32).
    #[error("emit size overflow: {section} got {got}, cap {cap}")]
    SizeOverflow {
        section: &'static str,
        got: u64,
        cap: u64,
    },

    /// A section offset or back-patch computation overflows u32 during
    /// emit layout.
    #[error("emit offset overflow in {context}")]
    OffsetOverflow { context: &'static str },

    /// IR shape cannot be round-trip emitted — caller handed an IR
    /// that violates a canonical-ordering invariant (e.g. a misordered
    /// `NonDecreasing<T>` slipped in via `unsafe`), or the input is
    /// in an unsupported shape for v1 (e.g. not-yet-implemented
    /// section emission).
    #[error("unrepresentable IR: {reason}")]
    UnrepresentableIR { reason: &'static str },

    /// The input `HbcFile`'s runtime version doesn't match the target
    /// emit version (V96 for v1).
    #[error("version mismatch: expected {expected}, got {got}")]
    VersionMismatch { expected: u32, got: u32 },

    /// Input `HbcFile`'s backing buffer is shorter than the 128-byte
    /// header. Should be impossible for a successfully-parsed file
    /// (parser gate checks `buf.len() >= 128` upfront) — defense
    /// against IR constructed without going through parse.
    #[error("input buffer shorter than 128-byte header: got {got}")]
    InputTooShort { got: usize },
}

/// Refuse to emit a file that carries Unrecognized functions.
///
/// A file with Unrecognized functions parsed only because the
/// recover-and-mark path tolerated an out-of-bounds overflow header.
/// Emit re-synthesizes the file header from IR (file_length, and other
/// header fields), which normalizes any adversarial inconsistency the
/// tolerant parse accepted; re-parsing the normalized bytes can then
/// interpret a *different* function's metadata (e.g. an exception
/// table) differently, breaking the parse→emit→parse round-trip. Since
/// the IR of such a file cannot be faithfully round-tripped, emit
/// reports it as unrepresentable rather than producing bytes that
/// silently diverge on re-parse.
fn reject_if_unrecognized(file: &HbcFile<'_>) -> Result<(), HermesEmitError> {
    if !file.unrecognized_functions().is_empty() {
        return Err(HermesEmitError::UnrepresentableIR {
            reason: "file contains functions whose headers could not be honestly resolved \
                     (recover-and-mark); a faithful round-trip is not guaranteed",
        });
    }
    Ok(())
}

/// Emit an HBC file from a parsed `HbcFile`.
///
/// Target: `parser::HbcFile::parse(&emit_hbc(&f)?)?` produces an
/// `HbcFile` that is `HbcFileEquiv<V96>`-equal to `f`. See module docs
/// for the per-section mode contract and the equivalence spec site.
///
/// Pipeline: SYNTHESIZE the 128-byte header from IR fields;
/// PASSTHROUGH the body (`&buf[128..]`) as baseline. Subsequent
/// refactors replace passthrough regions with synthesize-from-IR on a
/// per-section basis.
pub fn emit_hbc(file: &HbcFile<'_>) -> Result<Vec<u8>, HermesEmitError> {
    if file.version != V96::VERSION {
        return Err(HermesEmitError::VersionMismatch {
            expected: V96::VERSION,
            got: file.version,
        });
    }
    reject_if_unrecognized(file)?;

    let src = file.buf();
    if src.len() < HEADER_SIZE {
        return Err(HermesEmitError::InputTooShort { got: src.len() });
    }

    // file_length fits u32 or we can't synthesize the header field.
    // HBC format itself caps at u32::MAX since `file_length` is a u32
    // header field; emitting anything larger is meaningless for v96.
    let total_len = src.len();
    #[allow(
        clippy::map_err_ignore,
        reason = "TryFromIntError is unit-shaped; the relevant context (got/limit) is captured in the typed error"
    )]
    let file_length_u32 = u32::try_from(total_len).map_err(|_| {
        // WHY: u64::try_from(usize) only fails on 128-bit targets
        // (usize::BITS == 128 > 64); unsupported by us + the workspace.
        // u64::MAX >= usize::MAX on 64-bit and 32-bit, so the cast is
        // infallible here. Explicit comment since clippy::as_conversions
        #[allow(clippy::as_conversions, reason = "u64::try_from(usize) only fails on 128-bit targets (usize::BITS == 128 > 64); unsupported by us + the workspace. u64::MAX >= usize::MAX on 64-bit and 32-bit, so the cast is infallible here. Explicit comment since clippy::as_conversions is crate-root-deny'd.")]
        HermesEmitError::SizeOverflow {
            section: "file_length",
            got: total_len as u64,
            cap: u64::from(u32::MAX),
        }
    })?;

    let mut out = Vec::with_capacity(total_len);

    emit_header_v96(file, src, file_length_u32, &mut out)?;

    // SYNTHESIZE three section regions (FunctionHeaders,
    // SmallStringTable, OverflowStringTable) from raw-bitfield IR and
    // stitch the body back together around them.
    // Remaining body regions (StringKinds, IdentifierHashes,
    // StringStorage, ObjValueBuffer, ArrayBuffer, RegExpStorage,
    // ObjKeyBuffer, FunctionSourceTable, BigIntStorage, RegExp/BigInt
    // tables, per-function bytecode bodies, debug_info) are still
    // body-passthrough.
    //
    // Layout on disk (v96; observed pre-v97 section order):
    //   HEADER               [  0             ..  HEADER_SIZE        )  synthesized
    //   (gap)                [  HEADER_SIZE   ..  fh_start           )  passthrough
    //   FunctionHeaders      [  fh_start      ..  fh_end             )  synthesized
    //   StringKinds          [                                       )  passthrough
    //   IdentifierHashes     [                                       )  passthrough
    //   SmallStringTable     [  sst_start     ..  sst_end            )  synthesized
    //   OverflowStringTable  [  ost_start     ..  ost_end            )  synthesized
    //   body-rest            [  ost_end       ..  file_length        )  passthrough
    //
    // Emit order is position-preserving — each synthesized region
    // reproduces the same byte range that was at those offsets in
    // `src`, so output length + every downstream offset (debug_info,
    // function bytecode, etc.) round-trips unchanged.
    let fh_start = file.func_headers_start();
    let fh_size_bytes = section_bytes_usize(
        "FunctionHeaders",
        file.function_count,
        file.func_header_size(),
    )?;
    let fh_end = fh_start
        .checked_add(fh_size_bytes)
        .ok_or(HermesEmitError::OffsetOverflow {
            context: "FunctionHeaders end",
        })?;

    let sst_start = file.small_string_table_start();
    let sst_size_bytes = section_bytes_usize("SmallStringTable", file.string_count, 4)?;
    let sst_end = sst_start
        .checked_add(sst_size_bytes)
        .ok_or(HermesEmitError::OffsetOverflow {
            context: "SmallStringTable end",
        })?;

    let ost_start = file.overflow_string_table_start();
    // overflow_string_table_start == 0 when the section is empty
    // (`section_opt!`-analogous — parser's `section!` still records
    // (0, 0) for zero-sized sections because `section!` doesn't
    // advance `cursor` on size==0 strictly, but `ost_start` could be
    // either the last-cursor value or the legitimate post-small-table
    // position; we just skip the synthesize when the count is zero
    // and let body-passthrough continue from sst_end).
    let has_overflow_table = file.overflow_string_count > 0;
    let ost_size_bytes = if has_overflow_table {
        section_bytes_usize(
            "OverflowStringTable",
            file.overflow_string_count,
            8,
        )?
    } else {
        0
    };
    let ost_end = if has_overflow_table {
        ost_start
            .checked_add(ost_size_bytes)
            .ok_or(HermesEmitError::OffsetOverflow {
                context: "OverflowStringTable end",
            })?
    } else {
        sst_end
    };

    // Layout-consistency gates. The section offsets came from the
    // parser's `section!` macro at parse time, so they're bounded by
    // `buf.len()`; the gates here catch post-parse IR mutation that
    // violates the expected ordering.
    if fh_start < HEADER_SIZE
        || fh_end > src.len()
        || sst_start < fh_end
        || sst_end > src.len()
        || (has_overflow_table && (ost_start < sst_end || ost_end > src.len()))
    {
        return Err(HermesEmitError::UnrepresentableIR {
            reason: "section layout inconsistent with buffer",
        });
    }

    // Gap between HEADER and FunctionHeaders (0 bytes in the observed
    // v96 corpus; preserved here for layout-agnostic correctness).
    let pre_fh_gap = src
        .get(HEADER_SIZE..fh_start)
        .ok_or(HermesEmitError::InputTooShort { got: src.len() })?;
    out.extend_from_slice(pre_fh_gap);

    emit_function_headers_v96(file, &mut out)?;

    // Gap between FunctionHeaders and SmallStringTable covers the
    // StringKinds + IdentifierHashes sections, which stay passthrough.
    let pre_sst_gap = src
        .get(fh_end..sst_start)
        .ok_or(HermesEmitError::InputTooShort { got: src.len() })?;
    out.extend_from_slice(pre_sst_gap);

    emit_small_string_table_v96(file, &mut out)?;

    // OverflowStringTable typically sits immediately after
    // SmallStringTable in v96 with no gap. Preserve any alignment
    // bytes defensively.
    if has_overflow_table {
        let pre_ost_gap = src
            .get(sst_end..ost_start)
            .ok_or(HermesEmitError::InputTooShort { got: src.len() })?;
        out.extend_from_slice(pre_ost_gap);
        emit_overflow_string_table_v96(file, &mut out)?;
    }

    let body_rest = src
        .get(ost_end..)
        .ok_or(HermesEmitError::InputTooShort { got: src.len() })?;
    out.extend_from_slice(body_rest);

    debug_assert_eq!(
        out.len(),
        total_len,
        "emit length must match input length after section synthesize + body passthrough"
    );

    Ok(out)
}

/// Shared helper: compute `count × stride` as a `usize` with overflow
/// checks at every narrowing point. Used by `emit_hbc` to size each
/// synthesized section region before slicing the source buffer.
fn section_bytes_usize(
    section: &'static str,
    count: u32,
    stride: u32,
) -> Result<usize, HermesEmitError> {
    let bytes_u64 =
        u64::from(count)
            .checked_mul(u64::from(stride))
            .ok_or(HermesEmitError::SizeOverflow {
                section,
                got: u64::from(count),
                cap: u64::from(u32::MAX),
            })?;
    #[allow(
        clippy::map_err_ignore,
        reason = "TryFromIntError is unit-shaped; the relevant context (got/section) is captured in the typed error"
    )]
    let bytes_usize = usize::try_from(bytes_u64).map_err(|_| HermesEmitError::SizeOverflow {
        section,
        got: bytes_u64,
        cap: u64::from(u32::MAX),
    })?;
    Ok(bytes_usize)
}

/// Synthesize the 128-byte v96 HBC header from IR fields.
///
/// ## Byte layout (v96, pre-v97 object layout)
///
/// ```text
/// off  size field                   mode
/// ---- ---- ---------------------- -------------------------------
///  0     8  magic                  SYNTHESIZE (HBC_MAGIC constant)
///  8     4  version                SYNTHESIZE (V96::VERSION == 96)
/// 12    20  sourceHash             PASSTHROUGH (&src[12..32])
/// 32     4  file_length            SYNTHESIZE (out buf length)
/// 36     4  global_code_index      PASSTHROUGH (&src[36..40])
/// 40     4  function_count         SYNTHESIZE
/// 44     4  string_kind_count      SYNTHESIZE
/// 48     4  identifier_count       SYNTHESIZE
/// 52     4  string_count           SYNTHESIZE
/// 56     4  overflow_string_count  SYNTHESIZE
/// 60     4  string_storage_size    SYNTHESIZE
/// 64     4  big_int_count (v87+)   SYNTHESIZE
/// 68     4  big_int_storage_size   SYNTHESIZE
/// 72     4  reg_exp_count          SYNTHESIZE
/// 76     4  reg_exp_storage_size   SYNTHESIZE
/// 80     4  array_buffer_size      SYNTHESIZE (v<97 layout)
/// 84     4  obj_key_buffer_size    SYNTHESIZE (v<97 layout)
/// 88     4  obj_value_buffer_size  SYNTHESIZE (v<97 layout)
/// 92     4  segment_id/cjs_offset  PASSTHROUGH (&src[92..96])
/// 96     4  cjs_module_count       SYNTHESIZE
/// 100    4  function_source_count  SYNTHESIZE (v84+)
/// 104    4  debug_info_offset      SYNTHESIZE (firm-strip: always 0)
/// 108   20  BytecodeOptions+pad    PASSTHROUGH (&src[108..128])
/// ```
///
/// Reference: Hermes `include/hermes/BCGen/HBC/BytecodeFileFormat.h`
/// (`BCFileHeader` struct layout for v96; pinned to upstream SHA
/// where the v96 header layout was frozen).
fn emit_header_v96(
    file: &HbcFile<'_>,
    src: &[u8],
    file_length: u32,
    out: &mut Vec<u8>,
) -> Result<(), HermesEmitError> {
    // Magic (bytes 0..8).
    out.extend_from_slice(&HBC_MAGIC.to_le_bytes());

    // Version (bytes 8..12).
    out.extend_from_slice(&V96::VERSION.to_le_bytes());

    // sourceHash (bytes 12..32) — PASSTHROUGH; we cannot recompute SHA1.
    let source_hash = src
        .get(12..32)
        .ok_or(HermesEmitError::InputTooShort { got: src.len() })?;
    out.extend_from_slice(source_hash);

    // file_length (bytes 32..36) — recomputed.
    out.extend_from_slice(&file_length.to_le_bytes());

    // global_code_index (bytes 36..40) — PASSTHROUGH (parser skips it;
    // emit preserves to round-trip).
    let global_code_index = src
        .get(36..40)
        .ok_or(HermesEmitError::InputTooShort { got: src.len() })?;
    out.extend_from_slice(global_code_index);

    // Header counts (bytes 40..92) — all SYNTHESIZE from IR.
    out.extend_from_slice(&file.function_count.to_le_bytes());
    out.extend_from_slice(&file.string_kind_count().to_le_bytes());
    out.extend_from_slice(&file.identifier_count().to_le_bytes());
    out.extend_from_slice(&file.string_count.to_le_bytes());
    out.extend_from_slice(&file.overflow_string_count.to_le_bytes());
    out.extend_from_slice(&file.string_storage_size.to_le_bytes());
    out.extend_from_slice(&file.bigint_count().to_le_bytes());
    out.extend_from_slice(&file.big_int_storage_size().to_le_bytes());
    out.extend_from_slice(&file.regexp_count().to_le_bytes());
    out.extend_from_slice(&file.reg_exp_storage_size().to_le_bytes());
    // Pre-v97 layout (v96 hits this branch):
    out.extend_from_slice(&file.array_buffer_size().to_le_bytes());
    out.extend_from_slice(&file.obj_key_buffer_size().to_le_bytes());
    out.extend_from_slice(&file.obj_value_buffer_size().to_le_bytes());

    // segment_id / cjs_module_offset (bytes 92..96) — PASSTHROUGH
    // (parser skips it via `off += 4`).
    let segment_cjs = src
        .get(92..96)
        .ok_or(HermesEmitError::InputTooShort { got: src.len() })?;
    out.extend_from_slice(segment_cjs);

    // cjs_module_count (bytes 96..100) — SYNTHESIZE.
    out.extend_from_slice(&file.cjs_module_count.to_le_bytes());

    // function_source_count (bytes 100..104) — SYNTHESIZE (v84+, v96
    // is >= 84 so always present).
    out.extend_from_slice(&file.function_source_count().to_le_bytes());

    // debug_info_offset (bytes 104..108) — PASSTHROUGH from IR.
    // HBC debug_info is a line-number + scope-chain table with no
    // pointer surface analogous to DEX debug_info_item. Stripping it
    // would destroy reverse-engineering signal (source maps, scope
    // reconstruction) without security benefit for droidsaw's RE-tool
    // use case. debug_info section bytes come through unchanged via
    // body passthrough; preserving the header offset makes them
    // reachable to the second parse.
    out.extend_from_slice(&file.debug_info_offset().to_le_bytes());

    // BytecodeOptions byte + trailing padding (bytes 108..128) —
    // PASSTHROUGH. The parser reads buf[108] once for late-v98
    // detection but does not store BytecodeOptions or padding bytes
    // in the IR. For round-trip, preserve bytes 108..128 verbatim.
    let options_and_padding = src
        .get(108..128)
        .ok_or(HermesEmitError::InputTooShort { got: src.len() })?;
    out.extend_from_slice(options_and_padding);

    debug_assert_eq!(
        out.len(),
        HEADER_SIZE,
        "header emit must produce exactly {HEADER_SIZE} bytes"
    );

    Ok(())
}

/// Synthesize the v96 FunctionHeaders section — `function_count × 16`
/// bytes, one SmallFuncHeader entry per function. Bit-packed from the
/// raw bitfields returned by `HbcFile::raw_small_func_header_v96`
/// (pre-overflow-resolution values); byte-identical to the source
/// FunctionHeaders region for any v96 HBC file that parses cleanly.
///
/// Each 16-byte entry is bit-packed per the upstream
/// `BytecodeFileFormat.h` v96 SmallFuncHeader layout (see
/// `SmallFuncHeaderV96Raw` docs for the bit-partition). Bits 89..120
/// are `raw_uncharacterized_mid` — currently opaque to the IR but
/// preserved verbatim through the raw-accessor round-trip. Byte 15 is
/// the raw `flags_byte` (bit 5 = overflowed); emit writes this directly
/// rather than going through `pack_flags`, since `pack_flags` is lossy
/// on bits 5+7.
///
/// For overflowed functions (flags_byte bit 5 set), the 40-byte
/// SecondaryFuncHeader at `large_off = (info_offset << 16) | offset`
/// stays as **body-passthrough** in v1: it lives in the bytecode-body
/// region between function entries and gets copied through unchanged
/// by `emit_hbc`'s body-rest passthrough. Synthesize-from-IR for the
/// SecondaryFuncHeader requires a separate IR expansion and is
/// deferred.
///
/// Wiring: `emit_hbc` calls this after `emit_header_v96` to synthesize
/// the FunctionHeaders region in-place. Callable standalone for unit /
/// corpus-gated testing.
pub fn emit_function_headers_v96(
    file: &HbcFile<'_>,
    out: &mut Vec<u8>,
) -> Result<(), HermesEmitError> {
    require_v84_or_v96(file)?;

    // Both v84 and v96 use the 16-byte pre-v97 SmallFuncHeader layout.
    // A non-16 func_header_size on either version would indicate
    // parser-IR drift.
    #[allow(clippy::as_conversions, reason = "Spec-bounded value-domain narrowing (parser-validated field; preceding PROOF documents the bit-width invariant).")]
    {
        if file.func_header_size() as usize != SMALL_FUNC_HEADER_V96_SIZE {
            return Err(HermesEmitError::UnrepresentableIR {
                reason: "pre-v97 SmallFuncHeader size != 16",
            });
        }
    }

    let mut seq: Option<NonDecreasing<FunctionId>> = None;
    for i in 0..file.function_count {
        // Type-level non-decreasing gauge: advance the witness with
        // each function. Misorder (e.g. an IR mutation that hands out
        // decreasing FunctionIds via `unsafe`) hits the `None` branch
        // and rejects the emit.
        let fid = FunctionId(i);
        seq = Some(match seq {
            None => NonDecreasing::start(fid),
            Some(prev) => prev.advance(fid).ok_or(
                HermesEmitError::UnrepresentableIR {
                    reason: "FunctionId sequence not non-decreasing",
                },
            )?,
        });

        let raw = file
            .raw_small_func_header_v96(i)
            .ok_or(HermesEmitError::UnrepresentableIR {
                reason: "missing raw SmallFuncHeader for in-range function index",
            })?;

        emit_one_small_func_header_v96(out, &raw);
    }

    // Silence the NonDecreasing witness unused-binding warning on
    // `function_count == 0`. The witness is a type-level gauge, not a
    // runtime value — dropping it at end-of-loop is correct.
    let _ = seq;

    Ok(())
}

/// Emit a single 16-byte v96 SmallFuncHeader entry via bit-pack from
/// raw-bitfield IR. Helper extracted to keep `emit_function_headers_v96`
/// legible + enable unit testing of individual entry encoding.
#[allow(clippy::arithmetic_side_effects, reason = "Parser-bounded arithmetic; surrounding loop guards ensure offsets remain within the slice (see preceding PROOF in this function or block).")]
fn emit_one_small_func_header_v96(
    out: &mut Vec<u8>,
    raw: &SmallFuncHeaderV96Raw,
) {
    let mut entry = [0u8; SMALL_FUNC_HEADER_V96_SIZE];
    bit_pack_u32(&mut entry, 0, 25, raw.raw_offset);
    bit_pack_u32(&mut entry, 25, 7, raw.raw_param_count);
    bit_pack_u32(&mut entry, 32, 15, raw.raw_byte_size);
    bit_pack_u32(&mut entry, 47, 17, raw.raw_func_name);
    bit_pack_u32(&mut entry, 64, 25, raw.raw_info_offset);
    bit_pack_u32(&mut entry, 89, 31, raw.raw_uncharacterized_mid);
    entry[15] = raw.raw_flags_byte;
    out.extend_from_slice(&entry);
}

/// Synthesize the v96 SmallStringTable section — `string_count × 4`
/// bytes, one SmallStringTable entry per string. Each 4-byte entry
/// bit-packs `(is_utf16: 1b, str_offset: 23b, str_length: 8b)` from
/// the raw IR returned by `HbcFile::raw_small_string_table_entry`
/// (pre-overflow-resolution values); byte-identical to the source
/// SmallStringTable region for any v96 HBC file that parses cleanly.
///
/// The `str_length == 255` sentinel continues to signal overflow-
/// routing on parse — the companion `emit_overflow_string_table_v96`
/// emits the 8-byte `(offset, length)` entry that the sentinel
/// points to.
///
/// Called standalone or wired into `emit_hbc` alongside
/// `emit_overflow_string_table_v96` to replace the body-passthrough
/// for the two string-table sections.
pub fn emit_small_string_table_v96(
    file: &HbcFile<'_>,
    out: &mut Vec<u8>,
) -> Result<(), HermesEmitError> {
    require_shared_table_format(file)?;
    for i in 0..file.string_count {
        let raw = file
            .raw_small_string_table_entry(i)
            .ok_or(HermesEmitError::UnrepresentableIR {
                reason: "missing raw SmallStringTable entry for in-range index",
            })?;
        emit_one_small_string_table_entry_v96(out, &raw);
    }
    Ok(())
}

/// Emit a single 4-byte v96 SmallStringTable entry via bit-pack from
/// raw-bitfield IR. Helper extracted to mirror
/// `emit_one_small_func_header_v96` + enable unit testing of the
/// entry encoding independently of the iteration.
fn emit_one_small_string_table_entry_v96(
    out: &mut Vec<u8>,
    raw: &SmallStringTableEntryV96Raw,
) {
    let mut entry = [0u8; 4];
    bit_pack_u32(&mut entry, 0, 1, u32::from(raw.is_utf16));
    bit_pack_u32(&mut entry, 1, 23, raw.str_offset);
    bit_pack_u32(&mut entry, 24, 8, raw.str_length);
    out.extend_from_slice(&entry);
}

/// Synthesize the v96 OverflowStringTable section —
/// `overflow_string_count × 8` bytes of `(offset, length)` u32 pairs,
/// one entry per overflow-routed string. Empty when the string table
/// has no length ≥ 255 entries. Byte-exact inverse of the parse-side
/// overflow-branch read in `string_get`.
///
pub fn emit_overflow_string_table_v96(
    file: &HbcFile<'_>,
    out: &mut Vec<u8>,
) -> Result<(), HermesEmitError> {
    require_shared_table_format(file)?;
    for i in 0..file.overflow_string_count {
        let (offset, length) = file.raw_overflow_string_table_entry_v96(i).ok_or(
            HermesEmitError::UnrepresentableIR {
                reason: "missing raw OverflowStringTable entry for in-range index",
            },
        )?;
        out.extend_from_slice(&offset.to_le_bytes());
        out.extend_from_slice(&length.to_le_bytes());
    }
    Ok(())
}

/// Synthesize the v96 RegExpTable section — `reg_exp_count × 8` bytes
/// of `(offset, length)` u32 pairs, one entry per regex. Byte-exact
/// inverse of the parse-side table read (parser's `regexp_get` reads
/// the same two u32s; this emits them).
///
/// Used standalone or as a future hook for a section-walker-aware
/// emit_hbc refactor. Current emit_hbc continues to body-passthrough
/// the whole body; this helper's output matches what passthrough
/// emits for the RegExpTable region (verified by test).
pub fn emit_regexp_table_v96(
    file: &HbcFile<'_>,
    out: &mut Vec<u8>,
) -> Result<(), HermesEmitError> {
    require_shared_table_format(file)?;
    for i in 0..file.regexp_count() {
        let (offset, length) = file.regexp_table_entry_raw(i).ok_or(
            HermesEmitError::OffsetOverflow {
                context: "regexp_table entry",
            },
        )?;
        out.extend_from_slice(&offset.to_le_bytes());
        out.extend_from_slice(&length.to_le_bytes());
    }
    Ok(())
}

/// Synthesize the v96 BigIntTable section — `big_int_count × 8` bytes
/// of `(rel_offset, length)` u32 pairs, one entry per bigint. Empty
/// when `big_int_count == 0` (majority of corpus samples).
///
/// Byte-exact inverse of the parse-side table read.
pub fn emit_bigint_table_v96(
    file: &HbcFile<'_>,
    out: &mut Vec<u8>,
) -> Result<(), HermesEmitError> {
    require_shared_table_format(file)?;
    for i in 0..file.bigint_count() {
        let (offset, length) = file.bigint_table_entry_raw(i).ok_or(
            HermesEmitError::OffsetOverflow {
                context: "bigint_table entry",
            },
        )?;
        out.extend_from_slice(&offset.to_le_bytes());
        out.extend_from_slice(&length.to_le_bytes());
    }
    Ok(())
}

// ── v98 synthesize ────────────────────────────────────────────────────────
//
// v98 adds the ObjShapeTable section (v97+) and changes SmallFuncHeader to
// 12 bytes/entry with two bit-layout variants (early-v98/v97 and
// late-v98/v99). StringStorage + ArrayBuffer + ObjKeyBuffer + RegExp /
// BigInt content + per-function bytecode bodies stay body-passthrough
// exactly like v96. Section ordering:
//   Header → FunctionHeaders → StringKinds → IdentifierHashes →
//   SmallStringTable → OverflowStringTable → StringStorage →
//   ArrayBuffer → ObjKeyBuffer → ObjShapeTable → RegExpTable →
//   RegExpStorage → FunctionSourceTable.
// (Missing vs v96: ObjValueBuffer; added vs v96: ObjShapeTable.)
//
// v98 layout notes: LATE-v98 is detected via byte[108] invalid
// BytecodeOptions (use_v99_func_header = true). Both early and late
// forms use 12-byte SmallFuncHeader entries.

/// Synthesize the v98 FunctionHeaders section — `function_count × 12`
/// bytes, one SmallFuncHeader per function. Dispatches on
/// `file.use_v99_func_header()` to choose between the EarlyV98 and
/// LateV98 bit-layouts (both 12 bytes, different field widths). Each
/// entry is bit-packed from the raw IR returned by
/// `HbcFile::raw_small_func_header_v98`; byte-identical to the source
/// FunctionHeaders region for any v98 HBC file that parses cleanly.
///
/// SecondaryFuncHeader content (40-byte blocks at `large_off` for
/// overflowed functions) stays body-passthrough in v1 — same discipline
/// as the v96 arc's directive 4(a).
pub fn emit_function_headers_v98(
    file: &HbcFile<'_>,
    out: &mut Vec<u8>,
) -> Result<(), HermesEmitError> {
    require_v98_or_v99(file)?;
    #[allow(clippy::as_conversions, reason = "Spec-bounded value-domain narrowing (parser-validated field; preceding PROOF documents the bit-width invariant).")]
    {
        if file.func_header_size() as usize != SMALL_FUNC_HEADER_V98_SIZE {
            return Err(HermesEmitError::UnrepresentableIR {
                reason: "v98 SmallFuncHeader size != 12",
            });
        }
    }

    let mut seq: Option<NonDecreasing<FunctionId>> = None;
    for i in 0..file.function_count {
        let fid = FunctionId(i);
        seq = Some(match seq {
            None => NonDecreasing::start(fid),
            Some(prev) => prev.advance(fid).ok_or(
                HermesEmitError::UnrepresentableIR {
                    reason: "FunctionId sequence not non-decreasing",
                },
            )?,
        });

        let raw = file
            .raw_small_func_header_v98(i)
            .ok_or(HermesEmitError::UnrepresentableIR {
                reason: "missing raw SmallFuncHeader for in-range v98 index",
            })?;
        emit_one_small_func_header_v98(out, &raw);
    }
    let _ = seq;
    Ok(())
}

/// Emit one 12-byte v98 SmallFuncHeader entry. Dispatches on the
/// raw-IR variant to pack the appropriate bit-layout:
///
/// - **EarlyV98** (v97 / early-v98): bits 0..25 offset; 25..32
///   param_count(7b); 32..47 byte_size(15b); 47..64 func_name(17b);
///   64..88 uncharacterized(24b); byte 11 flags_byte.
/// - **LateV98** (late-v98 / v99): bits 0..25 offset; 25..30
///   param_count(5b); 30..32 loop_depth(2b); 32..46 byte_size(14b);
///   46..54 func_name(8b); 54..88 uncharacterized(34b); byte 11
///   flags_byte.
#[allow(clippy::arithmetic_side_effects, reason = "Parser-bounded arithmetic; surrounding loop guards ensure offsets remain within the slice (see preceding PROOF in this function or block).")]
fn emit_one_small_func_header_v98(out: &mut Vec<u8>, raw: &SmallFuncHeaderV98Raw) {
    let mut entry = [0u8; SMALL_FUNC_HEADER_V98_SIZE];
    match *raw {
        SmallFuncHeaderV98Raw::EarlyV98 {
            raw_offset,
            raw_param_count,
            raw_byte_size,
            raw_func_name,
            raw_uncharacterized_mid,
            raw_flags_byte,
        } => {
            bit_pack_u32(&mut entry, 0, 25, raw_offset);
            bit_pack_u32(&mut entry, 25, 7, raw_param_count);
            bit_pack_u32(&mut entry, 32, 15, raw_byte_size);
            bit_pack_u32(&mut entry, 47, 17, raw_func_name);
            bit_pack_u32(&mut entry, 64, 24, raw_uncharacterized_mid);
            entry[11] = raw_flags_byte;
        }
        SmallFuncHeaderV98Raw::LateV98 {
            raw_offset,
            raw_param_count,
            raw_loop_depth,
            raw_byte_size,
            raw_func_name,
            raw_uncharacterized_mid_lo,
            raw_uncharacterized_mid_hi,
            raw_flags_byte,
        } => {
            bit_pack_u32(&mut entry, 0, 25, raw_offset);
            bit_pack_u32(&mut entry, 25, 5, raw_param_count);
            bit_pack_u32(&mut entry, 30, 2, raw_loop_depth);
            bit_pack_u32(&mut entry, 32, 14, raw_byte_size);
            bit_pack_u32(&mut entry, 46, 8, raw_func_name);
            // 34-bit uncharacterized window split into two u32s at
            // parse time (bits 54..86 + 86..88) so each pack fits.
            bit_pack_u32(&mut entry, 54, 32, raw_uncharacterized_mid_lo);
            bit_pack_u32(&mut entry, 86, 2, raw_uncharacterized_mid_hi);
            entry[11] = raw_flags_byte;
        }
    }
    out.extend_from_slice(&entry);
}

/// Synthesize the v98 ObjShapeTable section — `object_shape_count × 8`
/// bytes of `(key_buffer_offset, num_props)` u32 pairs. Empty when
/// the table is unused (0 entries). Byte-exact inverse of the
/// parser-side `object_shape_get` read.
pub fn emit_obj_shape_table_v98(
    file: &HbcFile<'_>,
    out: &mut Vec<u8>,
) -> Result<(), HermesEmitError> {
    require_v98_or_v99(file)?;
    for i in 0..file.object_shape_count() {
        let raw = file
            .raw_obj_shape_table_entry_v98(i)
            .ok_or(HermesEmitError::UnrepresentableIR {
                reason: "missing raw ObjShapeTable entry for in-range v98 index",
            })?;
        emit_one_obj_shape_table_entry_v98(out, &raw);
    }
    Ok(())
}

fn emit_one_obj_shape_table_entry_v98(out: &mut Vec<u8>, raw: &ObjShapeTableEntryV98Raw) {
    out.extend_from_slice(&raw.key_buffer_offset.to_le_bytes());
    out.extend_from_slice(&raw.num_props.to_le_bytes());
}

/// Synthesize the 128-byte v98 HBC header from IR fields. Mirrors the
/// v96 layout except:
///   - slot 88..92 holds `obj_shape_table_count` (v97+) instead of
///     `obj_value_buffer_size` (v96).
///   - late-v98/v99 insert 4 bytes at 92..96 for `numStringSwitchImms`,
///     shifting the segment_id/cjs/cjs_count/func_source/debug_info
///     slots up by 4. BytecodeOptions+padding start at 112 (vs 108).
///
/// Header byte budget stays 128 (the inserted field fits within the
/// fixed 128-byte window because v96's slot 88..92 is repurposed).
fn emit_header_v98(
    file: &HbcFile<'_>,
    src: &[u8],
    file_length: u32,
    out: &mut Vec<u8>,
) -> Result<(), HermesEmitError> {
    out.extend_from_slice(&HBC_MAGIC.to_le_bytes());
    // Version field is preserved verbatim from the input file — v98
    // and v99 inputs round-trip as themselves; the magic + structural
    // layout are identical so emit is version-agnostic past this point.
    out.extend_from_slice(&file.version.to_le_bytes());

    // sourceHash (12..32) — passthrough.
    let source_hash = src
        .get(12..32)
        .ok_or(HermesEmitError::InputTooShort { got: src.len() })?;
    out.extend_from_slice(source_hash);

    // file_length (32..36) — recompute.
    out.extend_from_slice(&file_length.to_le_bytes());

    // global_code_index (36..40) — passthrough.
    let global_code_index = src
        .get(36..40)
        .ok_or(HermesEmitError::InputTooShort { got: src.len() })?;
    out.extend_from_slice(global_code_index);

    // Counts 40..92 — SYN (same 13 u32 fields as v96 through
    // obj_shape_table_count; v96's slot 88..92 was obj_value_buffer_size
    // which doesn't exist in v97+ — replaced by obj_shape_table_count).
    out.extend_from_slice(&file.function_count.to_le_bytes());
    out.extend_from_slice(&file.string_kind_count().to_le_bytes());
    out.extend_from_slice(&file.identifier_count().to_le_bytes());
    out.extend_from_slice(&file.string_count.to_le_bytes());
    out.extend_from_slice(&file.overflow_string_count.to_le_bytes());
    out.extend_from_slice(&file.string_storage_size.to_le_bytes());
    out.extend_from_slice(&file.bigint_count().to_le_bytes());
    out.extend_from_slice(&file.big_int_storage_size().to_le_bytes());
    out.extend_from_slice(&file.regexp_count().to_le_bytes());
    out.extend_from_slice(&file.reg_exp_storage_size().to_le_bytes());
    out.extend_from_slice(&file.array_buffer_size().to_le_bytes());
    out.extend_from_slice(&file.obj_key_buffer_size().to_le_bytes());
    out.extend_from_slice(&file.object_shape_count().to_le_bytes());

    // Optional numStringSwitchImms (late-v98/v99 only). The source
    // bytes at 92..96 are either a passthrough u32 (late-v98) or the
    // start of segment_id/cjs_offset (early-v98). Synthesize when the
    // layout says it's present; the value is not exposed on HbcFile
    // today so passthrough from src bytes 92..96 is the spec-correct
    // emit: byte-identity + IR is not lossy since no IR field mirrors
    // this value.
    let ssi_present = file.has_num_string_switch_imms();
    let mut cursor: usize = 92;
    if ssi_present {
        let ssi_bytes = src
            .get(92..96)
            .ok_or(HermesEmitError::InputTooShort { got: src.len() })?;
        out.extend_from_slice(ssi_bytes);
        cursor = 96;
    }

    // segment_id/cjs_module_offset — passthrough at cursor..cursor+4.
    let segment_cjs = src
        .get(cursor..cursor.saturating_add(4))
        .ok_or(HermesEmitError::InputTooShort { got: src.len() })?;
    out.extend_from_slice(segment_cjs);

    // cjs_module_count / function_source_count / debug_info_offset — SYN.
    out.extend_from_slice(&file.cjs_module_count.to_le_bytes());
    out.extend_from_slice(&file.function_source_count().to_le_bytes());
    out.extend_from_slice(&file.debug_info_offset().to_le_bytes());

    // BytecodeOptions + trailing padding — passthrough. Starts at 112
    // for late-v98/v99, 108 for early-v98.
    let opts_start = if ssi_present { 112 } else { 108 };
    let options_and_padding = src
        .get(opts_start..128)
        .ok_or(HermesEmitError::InputTooShort { got: src.len() })?;
    out.extend_from_slice(options_and_padding);

    debug_assert_eq!(
        out.len(),
        HEADER_SIZE,
        "v98 header emit must produce exactly {HEADER_SIZE} bytes"
    );
    Ok(())
}

/// Top-level v98 HBC emit entry point — `parse ∘ emit_hbc_v98 ∘ parse
/// == parse` round-trip for v98 inputs. Mirrors `emit_hbc` (v96)
/// using v98 section ordering. Four synthesize regions are injected in
/// position-preserving order: FunctionHeaders, SmallStringTable,
/// OverflowStringTable, ObjShapeTable. Every other region is body-
/// passthrough (StringKinds / IdentifierHashes / StringStorage /
/// ArrayBuffer / ObjKeyBuffer / RegExp* / BigInt* / FunctionSourceTable
/// / debug_info / per-function bytecode bodies).
///
/// Round-trip equivalence is defined by `HbcFileEquiv<V98>` — the
/// `PartialEq` there IS the emit specification.
pub fn emit_hbc_v98(file: &HbcFile<'_>) -> Result<Vec<u8>, HermesEmitError> {
    if file.version != V98::VERSION {
        return Err(HermesEmitError::VersionMismatch {
            expected: V98::VERSION,
            got: file.version,
        });
    }
    emit_hbc_v98_or_v99(file)
}

/// Top-level v99 HBC emit entry point. v99 shares the late-v98 layout
/// byte-for-byte per `parser::parse_inner`'s `use_v99_header` branch.
/// v99 always uses v99-layout FunctionHeaders, carries
/// `numStringSwitchImms`, and includes the ObjShapeTable section.
/// Implementation forwards to the same internal body that
/// `emit_hbc_v98` uses for late-v98 inputs.
pub fn emit_hbc_v99(file: &HbcFile<'_>) -> Result<Vec<u8>, HermesEmitError> {
    if file.version != V99::VERSION {
        return Err(HermesEmitError::VersionMismatch {
            expected: V99::VERSION,
            got: file.version,
        });
    }
    emit_hbc_v98_or_v99(file)
}

/// Shared v98/v99 emit body. Gates on v98 || v99; delegates per-
/// section synthesize to the v98 helpers which accept both versions
/// via `require_v98_or_v99`. Caller must pre-gate on the specific
/// version (via `emit_hbc_v98` or `emit_hbc_v99`) for the correct
/// typed error message on mismatched inputs.
fn emit_hbc_v98_or_v99(file: &HbcFile<'_>) -> Result<Vec<u8>, HermesEmitError> {
    require_v98_or_v99(file)?;
    reject_if_unrecognized(file)?;

    let src = file.buf();
    if src.len() < HEADER_SIZE {
        return Err(HermesEmitError::InputTooShort { got: src.len() });
    }

    let total_len = src.len();
    #[allow(
        clippy::map_err_ignore,
        reason = "TryFromIntError is unit-shaped; the relevant context (got/section) is captured in the typed error"
    )]
    let file_length_u32 = u32::try_from(total_len).map_err(|_| {
        #[allow(clippy::as_conversions, reason = "Spec-bounded value-domain narrowing (parser-validated field; preceding PROOF documents the bit-width invariant).")]
        HermesEmitError::SizeOverflow {
            section: "file_length",
            got: total_len as u64,
            cap: u64::from(u32::MAX),
        }
    })?;

    let mut out = Vec::with_capacity(total_len);

    emit_header_v98(file, src, file_length_u32, &mut out)?;

    // Region layout (position-preserving synthesize + passthrough):
    //   [  0   ..  HEADER_SIZE  ) synthesized (emit_header_v98)
    //   [HEADER_SIZE .. fh_start)  passthrough (gap)
    //   [fh_start .. fh_end    )   synthesized (FunctionHeaders)
    //   [fh_end   .. sst_start )   passthrough (StringKinds + IdentifierHashes)
    //   [sst_start .. sst_end  )   synthesized (SmallStringTable)
    //   [sst_end  .. ost_start )   passthrough (gap; 0 on observed corpus)
    //   [ost_start .. ost_end  )   synthesized (OverflowStringTable)
    //   [ost_end  .. shape_start) passthrough (StringStorage + ArrayBuffer + ObjKeyBuffer)
    //   [shape_start .. shape_end) synthesized (ObjShapeTable)
    //   [shape_end .. file_length) passthrough (RegExp* + FunctionSourceTable + debug_info)
    let fh_start = file.func_headers_start();
    let fh_size_bytes = section_bytes_usize(
        "FunctionHeaders",
        file.function_count,
        file.func_header_size(),
    )?;
    let fh_end = fh_start
        .checked_add(fh_size_bytes)
        .ok_or(HermesEmitError::OffsetOverflow {
            context: "FunctionHeaders end",
        })?;

    let sst_start = file.small_string_table_start();
    let sst_size_bytes = section_bytes_usize("SmallStringTable", file.string_count, 4)?;
    let sst_end = sst_start
        .checked_add(sst_size_bytes)
        .ok_or(HermesEmitError::OffsetOverflow {
            context: "SmallStringTable end",
        })?;

    let ost_start = file.overflow_string_table_start();
    let has_overflow_table = file.overflow_string_count > 0;
    let ost_size_bytes = if has_overflow_table {
        section_bytes_usize(
            "OverflowStringTable",
            file.overflow_string_count,
            8,
        )?
    } else {
        0
    };
    let ost_end = if has_overflow_table {
        ost_start
            .checked_add(ost_size_bytes)
            .ok_or(HermesEmitError::OffsetOverflow {
                context: "OverflowStringTable end",
            })?
    } else {
        sst_end
    };

    let shape_start = file.obj_shape_table_start();
    let has_shape_table = file.object_shape_count() > 0;
    let shape_size_bytes = if has_shape_table {
        section_bytes_usize("ObjShapeTable", file.object_shape_count(), 8)?
    } else {
        0
    };
    let shape_end = if has_shape_table {
        shape_start
            .checked_add(shape_size_bytes)
            .ok_or(HermesEmitError::OffsetOverflow {
                context: "ObjShapeTable end",
            })?
    } else {
        ost_end
    };

    // Layout-consistency gate.
    if fh_start < HEADER_SIZE
        || fh_end > src.len()
        || sst_start < fh_end
        || sst_end > src.len()
        || (has_overflow_table && (ost_start < sst_end || ost_end > src.len()))
        || (has_shape_table && (shape_start < ost_end || shape_end > src.len()))
    {
        return Err(HermesEmitError::UnrepresentableIR {
            reason: "v98 section layout inconsistent with buffer",
        });
    }

    // Gap: HEADER → FunctionHeaders (0 bytes on observed corpus).
    let pre_fh_gap = src
        .get(HEADER_SIZE..fh_start)
        .ok_or(HermesEmitError::InputTooShort { got: src.len() })?;
    out.extend_from_slice(pre_fh_gap);

    emit_function_headers_v98(file, &mut out)?;

    // Passthrough StringKinds + IdentifierHashes.
    let pre_sst_gap = src
        .get(fh_end..sst_start)
        .ok_or(HermesEmitError::InputTooShort { got: src.len() })?;
    out.extend_from_slice(pre_sst_gap);

    emit_small_string_table_v96(file, &mut out)?;

    if has_overflow_table {
        let pre_ost_gap = src
            .get(sst_end..ost_start)
            .ok_or(HermesEmitError::InputTooShort { got: src.len() })?;
        out.extend_from_slice(pre_ost_gap);
        emit_overflow_string_table_v96(file, &mut out)?;
    }

    // Passthrough StringStorage + ArrayBuffer + ObjKeyBuffer (cursor
    // starts at ost_end, runs to shape_start).
    if has_shape_table {
        let pre_shape_gap = src
            .get(ost_end..shape_start)
            .ok_or(HermesEmitError::InputTooShort { got: src.len() })?;
        out.extend_from_slice(pre_shape_gap);
        emit_obj_shape_table_v98(file, &mut out)?;
    }

    // Body-rest: RegExpTable + RegExpStorage + FunctionSourceTable +
    // debug_info + per-function bytecode bodies — all body-passthrough.
    let body_rest = src
        .get(shape_end..)
        .ok_or(HermesEmitError::InputTooShort { got: src.len() })?;
    out.extend_from_slice(body_rest);

    debug_assert_eq!(
        out.len(),
        total_len,
        "v98 emit length must match input length"
    );
    Ok(out)
}

// ── v84 synthesize ────────────────────────────────────────────────────────
//
// v84 predates bigint (v<87) and ObjShapeTable (v<97); section set is:
//   Header → FunctionHeaders → StringKinds → IdentifierHashes →
//   SmallStringTable → OverflowStringTable → StringStorage →
//   ArrayBuffer → ObjKeyBuffer → ObjValueBuffer → RegExpTable →
//   RegExpStorage.
// No BigIntTable, no BigIntStorage, no ObjShapeTable. ObjValueBuffer is
// present (v<97 layout). FunctionSourceTable exists as a header slot
// (v≥84) but the section materializes only when `function_source_count
// > 0` — the section materializes only when the count is non-zero.
//
// Header slot map:
//    0..8     magic                SYN
//    8..12    version              SYN (value from file.version)
//   12..32    sourceHash           PASS
//   32..36    file_length          SYN
//   36..40    global_code_index    PASS
//   40..44    function_count       SYN
//   44..48    string_kind_count    SYN
//   48..52    identifier_count     SYN
//   52..56    string_count         SYN
//   56..60    overflow_string_cnt  SYN
//   60..64    string_storage_size  SYN
//   64..68    reg_exp_count        SYN   (v<87 — no bigint above this)
//   68..72    reg_exp_storage_size SYN
//   72..76    array_buffer_size    SYN   (v<97 layout)
//   76..80    obj_key_buffer_size  SYN
//   80..84    obj_value_buffer_size SYN
//   84..88    segment_id/cjs_off   PASS
//   88..92    cjs_module_count     SYN
//   92..96    function_source_cnt  SYN   (v≥84)
//   96..100   debug_info_offset    SYN
//  100..128   BytecodeOptions+pad  PASS   (28 bytes — v84 has no
//                                          bigint fields so the PASS
//                                          range starts 8 bytes earlier
//                                          than v96's 108..128)

/// Synthesize the 128-byte v84 HBC header from IR fields. Mirrors
/// `emit_header_v96` with the v<87 slot layout (no bigint fields;
/// BytecodeOptions at 100..128).
fn emit_header_v84(
    file: &HbcFile<'_>,
    src: &[u8],
    file_length: u32,
    out: &mut Vec<u8>,
) -> Result<(), HermesEmitError> {
    out.extend_from_slice(&HBC_MAGIC.to_le_bytes());
    // Version preserved from the input file (allows accurate error
    // reporting if callers ever pass a mis-tagged v84 file).
    out.extend_from_slice(&file.version.to_le_bytes());

    let source_hash = src
        .get(12..32)
        .ok_or(HermesEmitError::InputTooShort { got: src.len() })?;
    out.extend_from_slice(source_hash);

    out.extend_from_slice(&file_length.to_le_bytes());

    let global_code_index = src
        .get(36..40)
        .ok_or(HermesEmitError::InputTooShort { got: src.len() })?;
    out.extend_from_slice(global_code_index);

    // Counts 40..64 — SYN (no bigint in v<87).
    out.extend_from_slice(&file.function_count.to_le_bytes());
    out.extend_from_slice(&file.string_kind_count().to_le_bytes());
    out.extend_from_slice(&file.identifier_count().to_le_bytes());
    out.extend_from_slice(&file.string_count.to_le_bytes());
    out.extend_from_slice(&file.overflow_string_count.to_le_bytes());
    out.extend_from_slice(&file.string_storage_size.to_le_bytes());

    // RegExp slots start at 64..72 (no bigint above).
    out.extend_from_slice(&file.regexp_count().to_le_bytes());
    out.extend_from_slice(&file.reg_exp_storage_size().to_le_bytes());

    // v<97 layout: ArrayBuffer + ObjKeyBuffer + ObjValueBuffer.
    out.extend_from_slice(&file.array_buffer_size().to_le_bytes());
    out.extend_from_slice(&file.obj_key_buffer_size().to_le_bytes());
    out.extend_from_slice(&file.obj_value_buffer_size().to_le_bytes());

    // segment_id / cjs_module_offset (84..88) — passthrough.
    let segment_cjs = src
        .get(84..88)
        .ok_or(HermesEmitError::InputTooShort { got: src.len() })?;
    out.extend_from_slice(segment_cjs);

    out.extend_from_slice(&file.cjs_module_count.to_le_bytes());
    out.extend_from_slice(&file.function_source_count().to_le_bytes());
    out.extend_from_slice(&file.debug_info_offset().to_le_bytes());

    // BytecodeOptions + padding (100..128) — 28-byte PASS range.
    let options_and_padding = src
        .get(100..128)
        .ok_or(HermesEmitError::InputTooShort { got: src.len() })?;
    out.extend_from_slice(options_and_padding);

    debug_assert_eq!(
        out.len(),
        HEADER_SIZE,
        "v84 header emit must produce exactly {HEADER_SIZE} bytes"
    );
    Ok(())
}

/// Top-level v84 HBC emit entry point — mirrors `emit_hbc` (v96) with
/// v84 section ordering. Injects FunctionHeaders, SmallStringTable,
/// OverflowStringTable, RegExpTable as synthesize regions in position-
/// preserving order; everything else is body-passthrough (StringKinds,
/// IdentifierHashes, StringStorage, ArrayBuffer, ObjKeyBuffer,
/// ObjValueBuffer, RegExpStorage, FunctionSourceTable, debug_info, and
/// per-function bytecode bodies).
pub fn emit_hbc_v84(file: &HbcFile<'_>) -> Result<Vec<u8>, HermesEmitError> {
    if file.version != V84::VERSION {
        return Err(HermesEmitError::VersionMismatch {
            expected: V84::VERSION,
            got: file.version,
        });
    }
    reject_if_unrecognized(file)?;

    let src = file.buf();
    if src.len() < HEADER_SIZE {
        return Err(HermesEmitError::InputTooShort { got: src.len() });
    }

    let total_len = src.len();
    #[allow(
        clippy::map_err_ignore,
        reason = "TryFromIntError is unit-shaped; the relevant context (got/section) is captured in the typed error"
    )]
    let file_length_u32 = u32::try_from(total_len).map_err(|_| {
        #[allow(clippy::as_conversions, reason = "Spec-bounded value-domain narrowing (parser-validated field; preceding PROOF documents the bit-width invariant).")]
        HermesEmitError::SizeOverflow {
            section: "file_length",
            got: total_len as u64,
            cap: u64::from(u32::MAX),
        }
    })?;

    let mut out = Vec::with_capacity(total_len);

    emit_header_v84(file, src, file_length_u32, &mut out)?;

    // Section-region layout (position-preserving):
    //   [  0         .. HEADER_SIZE    ) synthesized (emit_header_v84)
    //   [HEADER_SIZE .. fh_start       ) passthrough (gap; 0 observed)
    //   [fh_start    .. fh_end         ) synthesized (FunctionHeaders, v96 helper)
    //   [fh_end      .. sst_start      ) passthrough (StringKinds + IdentifierHashes)
    //   [sst_start   .. sst_end        ) synthesized (SmallStringTable)
    //   [sst_end     .. ost_start      ) passthrough (gap; 0 observed)
    //   [ost_start   .. ost_end        ) synthesized (OverflowStringTable)
    //   [ost_end     .. regexp_start   ) passthrough (StringStorage + ArrayBuffer
    //                                                 + ObjKeyBuffer + ObjValueBuffer)
    //   [regexp_start .. regexp_end    ) synthesized (RegExpTable)
    //   [regexp_end  .. file_length    ) passthrough (RegExpStorage + FunctionSourceTable
    //                                                 + debug_info + bytecode bodies)
    let fh_start = file.func_headers_start();
    let fh_size_bytes = section_bytes_usize(
        "FunctionHeaders",
        file.function_count,
        file.func_header_size(),
    )?;
    let fh_end = fh_start
        .checked_add(fh_size_bytes)
        .ok_or(HermesEmitError::OffsetOverflow {
            context: "FunctionHeaders end",
        })?;

    let sst_start = file.small_string_table_start();
    let sst_size_bytes = section_bytes_usize("SmallStringTable", file.string_count, 4)?;
    let sst_end = sst_start
        .checked_add(sst_size_bytes)
        .ok_or(HermesEmitError::OffsetOverflow {
            context: "SmallStringTable end",
        })?;

    let ost_start = file.overflow_string_table_start();
    let has_overflow_table = file.overflow_string_count > 0;
    let ost_size_bytes = if has_overflow_table {
        section_bytes_usize(
            "OverflowStringTable",
            file.overflow_string_count,
            8,
        )?
    } else {
        0
    };
    let ost_end = if has_overflow_table {
        ost_start
            .checked_add(ost_size_bytes)
            .ok_or(HermesEmitError::OffsetOverflow {
                context: "OverflowStringTable end",
            })?
    } else {
        sst_end
    };

    let regexp_start = file.regexp_table_start();
    let has_regexp_table = file.regexp_count() > 0;
    let regexp_size_bytes = if has_regexp_table {
        section_bytes_usize("RegExpTable", file.regexp_count(), 8)?
    } else {
        0
    };
    let regexp_end = if has_regexp_table {
        regexp_start
            .checked_add(regexp_size_bytes)
            .ok_or(HermesEmitError::OffsetOverflow {
                context: "RegExpTable end",
            })?
    } else {
        ost_end
    };

    if fh_start < HEADER_SIZE
        || fh_end > src.len()
        || sst_start < fh_end
        || sst_end > src.len()
        || (has_overflow_table && (ost_start < sst_end || ost_end > src.len()))
        || (has_regexp_table && (regexp_start < ost_end || regexp_end > src.len()))
    {
        return Err(HermesEmitError::UnrepresentableIR {
            reason: "v84 section layout inconsistent with buffer",
        });
    }

    // Gap: HEADER → FunctionHeaders.
    let pre_fh_gap = src
        .get(HEADER_SIZE..fh_start)
        .ok_or(HermesEmitError::InputTooShort { got: src.len() })?;
    out.extend_from_slice(pre_fh_gap);

    emit_function_headers_v96(file, &mut out)?;

    // Gap: FunctionHeaders → SmallStringTable (StringKinds + IdentifierHashes passthrough).
    let pre_sst_gap = src
        .get(fh_end..sst_start)
        .ok_or(HermesEmitError::InputTooShort { got: src.len() })?;
    out.extend_from_slice(pre_sst_gap);

    emit_small_string_table_v96(file, &mut out)?;

    if has_overflow_table {
        let pre_ost_gap = src
            .get(sst_end..ost_start)
            .ok_or(HermesEmitError::InputTooShort { got: src.len() })?;
        out.extend_from_slice(pre_ost_gap);
        emit_overflow_string_table_v96(file, &mut out)?;
    }

    // Gap: OverflowStringTable → RegExpTable (StringStorage + ArrayBuffer
    // + ObjKeyBuffer + ObjValueBuffer passthrough).
    if has_regexp_table {
        let pre_regexp_gap = src
            .get(ost_end..regexp_start)
            .ok_or(HermesEmitError::InputTooShort { got: src.len() })?;
        out.extend_from_slice(pre_regexp_gap);
        emit_regexp_table_v96(file, &mut out)?;
    }

    // Body-rest: RegExpStorage + FunctionSourceTable + debug_info
    // + per-function bytecode bodies — body-passthrough.
    let body_rest = src
        .get(regexp_end..)
        .ok_or(HermesEmitError::InputTooShort { got: src.len() })?;
    out.extend_from_slice(body_rest);

    debug_assert_eq!(
        out.len(),
        total_len,
        "v84 emit length must match input length"
    );
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{HbcFile, HbcFileEquiv};

    /// Smallest possible valid v96 HBC: 128-byte header + all counts zero.
    /// Shared discipline with `tests/roundtrip_hbc_proptest.rs`. Fuzz
    /// fixtures have garbage bytes in unused-count header fields that
    /// emit canonicalizes from IR; a clean synthesized seed avoids that
    /// noise (see proptest file header for the detailed rationale).
    fn minimal_v96_seed() -> Vec<u8> {
        let mut h = vec![0u8; 128];
        h[0..8].copy_from_slice(&HBC_MAGIC.to_le_bytes());
        h[8..12].copy_from_slice(&V96::VERSION.to_le_bytes());
        h[32..36].copy_from_slice(&128u32.to_le_bytes());
        h
    }

    #[test]
    fn emit_hbc_roundtrips_minimal_v96() {
        let seed = minimal_v96_seed();
        let hbc1 = HbcFile::parse(&seed, None).expect("minimal v96 must parse");
        let emitted = emit_hbc(&hbc1).expect("minimal v96 must emit");
        let hbc2 = HbcFile::parse(&emitted, None).expect("emit output must parse");

        let equiv1 = HbcFileEquiv::<V96>::new(&hbc1).expect("hbc1 must be v96");
        let equiv2 = HbcFileEquiv::<V96>::new(&hbc2).expect("hbc2 must be v96");
        assert!(
            equiv1 == equiv2,
            "HbcFileEquiv<V96> must hold across parse → emit → parse: {equiv1:?} vs {equiv2:?}"
        );
    }

    #[test]
    fn emit_hbc_byte_identical_on_clean_minimal() {
        // The minimal seed has file_length==128 already + debug_info_offset==0
        // already, so emit produces a byte-identical output. This asserts
        // the theorem: byte-identity is a corollary
        // of correct emit on a well-formed input.
        let seed = minimal_v96_seed();
        let hbc = HbcFile::parse(&seed, None).expect("minimal v96 must parse");
        let emitted = emit_hbc(&hbc).expect("minimal v96 must emit");
        assert_eq!(emitted, seed, "clean v96 emit must be byte-identical");
    }

    #[test]
    fn emit_hbc_preserves_source_hash() {
        // Seed with a distinctive sourceHash to confirm it's preserved.
        let mut seed = minimal_v96_seed();
        let distinctive_hash: [u8; 20] = [
            0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,
        ];
        seed[12..32].copy_from_slice(&distinctive_hash);

        let hbc = HbcFile::parse(&seed, None).expect("seed must parse");
        let emitted = emit_hbc(&hbc).expect("seed must emit");

        // sourceHash bytes 12..32 must be byte-passthrough per SHA1 reframe.
        assert_eq!(
            &emitted[12..32],
            &distinctive_hash,
            "sourceHash must be byte-passthrough; SHA1 cannot be recomputed"
        );
    }

    #[test]
    fn emit_hbc_preserves_debug_info_offset() {
        // debug_info is PASSTHROUGH on emit (reversed from initial
        // strip posture — HBC debug_info is line-number metadata, not
        // DEX's dangling-pointer-vector format). Emit reads
        // debug_info_offset from IR + writes it verbatim to the header;
        // section bytes flow through via body passthrough.
        //
        // The minimal seed has debug_info_offset=0, which is correctly
        // preserved as 0. Setting a non-zero value and round-tripping
        // through the header synthesis exercises the passthrough from
        // IR (parser re-reads 0 via the `debug_info_offset == 0 || +16
        // > buf.len()` gate; actually testing non-zero requires a
        // fixture with valid debug_info bytes at the target offset —
        // out of scope for this unit test; covered by the env-gated
        // corpus round-trip test on user-staged samples that ship a
        // real debug_info section).
        let seed = minimal_v96_seed();
        let hbc = HbcFile::parse(&seed, None).expect("seed must parse");
        let emitted = emit_hbc(&hbc).expect("seed must emit");

        let debug_info_offset =
            u32::from_le_bytes(emitted[104..108].try_into().expect("slice is 4 bytes"));
        assert_eq!(
            debug_info_offset, 0,
            "minimal seed has debug_info_offset=0; emit preserves as 0"
        );
    }

    #[test]
    fn emit_hbc_recomputes_file_length() {
        // Seed with a wrong file_length to confirm emit recomputes.
        let mut seed = minimal_v96_seed();
        seed[32..36].copy_from_slice(&0xDEADu32.to_le_bytes());

        let hbc = HbcFile::parse(&seed, None).expect("seed must parse");
        let emitted = emit_hbc(&hbc).expect("seed must emit");

        let file_length =
            u32::from_le_bytes(emitted[32..36].try_into().expect("slice is 4 bytes"));
        assert_eq!(
            usize::try_from(file_length).expect("u32 → usize on 64-bit target"),
            emitted.len(),
            "file_length header field must match emitted buffer length"
        );
    }

    #[test]
    fn bit_pack_u32_round_trips_read_bitfield() {
        // Pack a mix of bit-widths into a zeroed buffer and verify
        // `read_bitfield` reads back the same values. Locks in the
        // write-vs-read invariant: the two functions are byte-exact
        // inverses over [0, 32] bits.
        //
        // `read_bitfield` is the reference here — it's the parser-side
        // function callers (including `function_get`) go through.
        use crate::parser::read_bitfield_for_test as read_bitfield;

        let cases: &[(u32, u32, u32)] = &[
            (0, 25, 0x01FF_FFFF),         // max 25-bit value at bit 0
            (25, 7, 0x7F),                // max 7-bit value at bit 25
            (32, 15, 0x7FFF),             // max 15-bit value at bit 32
            (47, 17, 0x1_FFFF),           // max 17-bit value at bit 47
            (64, 25, 0x01FF_FFFF),        // max 25-bit value at bit 64
            (89, 31, 0x7FFF_FFFF),        // max 31-bit value at bit 89
            (0, 32, 0xDEAD_BEEF),         // full u32 at bit 0
            (5, 3, 0b101),                // odd offsets, small widths
            (7, 9, 0x1A5),                // crossing byte boundaries
        ];

        for &(start_bit, num_bits, value) in cases {
            let mut buf = [0u8; 24]; // > 128 bits for the 31-bit-at-89 case
            bit_pack_u32(&mut buf, start_bit, num_bits, value);
            let got = read_bitfield(&buf, start_bit, num_bits);
            assert_eq!(
                got, value,
                "round-trip failure: start_bit={start_bit} num_bits={num_bits} \
                 value=0x{value:x} got=0x{got:x}"
            );
        }
    }

    #[test]
    fn emit_one_small_func_header_v96_round_trips_read_bitfield() {
        // Build a SmallFuncHeaderV96Raw with distinctive per-field
        // values, emit, then re-read via read_bitfield to confirm
        // every field lands at the right bit offset. This is the
        // unit-level gauge that catches bit-layout bugs without
        // needing a corpus sample.
        use crate::parser::read_bitfield_for_test as read_bitfield;

        let raw = SmallFuncHeaderV96Raw {
            raw_offset: 0x0123_4567 & 0x01FF_FFFF,        // 25 bits
            raw_param_count: 0x55 & 0x7F,                 // 7 bits
            raw_byte_size: 0x6A5A & 0x7FFF,               // 15 bits
            raw_func_name: 0x1_5A5A & 0x1_FFFF,           // 17 bits
            raw_info_offset: 0x00FE_DCBA & 0x01FF_FFFF,   // 25 bits
            raw_uncharacterized_mid: 0x5A5A_A5A5 & 0x7FFF_FFFF, // 31 bits
            raw_flags_byte: 0xA5,                         // 8 bits
        };

        let mut out: Vec<u8> = Vec::new();
        emit_one_small_func_header_v96(&mut out, &raw);
        assert_eq!(out.len(), 16);

        assert_eq!(read_bitfield(&out, 0, 25), raw.raw_offset);
        assert_eq!(read_bitfield(&out, 25, 7), raw.raw_param_count);
        assert_eq!(read_bitfield(&out, 32, 15), raw.raw_byte_size);
        assert_eq!(read_bitfield(&out, 47, 17), raw.raw_func_name);
        assert_eq!(read_bitfield(&out, 64, 25), raw.raw_info_offset);
        assert_eq!(read_bitfield(&out, 89, 31), raw.raw_uncharacterized_mid);
        assert_eq!(out[15], raw.raw_flags_byte);
    }

    #[test]
    fn emit_function_headers_v96_on_minimal_seed() {
        // Minimal v96 seed has function_count=0, so the synthesize
        // helper produces an empty output — the degenerate case the
        // main loop must handle cleanly.
        let seed = minimal_v96_seed();
        let hbc = HbcFile::parse(&seed, None).expect("minimal v96 must parse");
        let mut out: Vec<u8> = Vec::new();
        emit_function_headers_v96(&hbc, &mut out)
            .expect("minimal v96 fh emit must succeed");
        assert_eq!(out.len(), 0, "zero functions → zero bytes");
    }

    #[test]
    fn non_decreasing_rejects_misorder() {
        // The NonDecreasing witness is a type-level gauge — verify
        // the runtime check rejects a misordered advance while
        // accepting equal-or-greater advances.
        let seq = NonDecreasing::start(FunctionId(5));
        assert!(
            seq.advance(FunctionId(5)).is_some(),
            "equal advance must succeed"
        );
        assert!(
            seq.advance(FunctionId(6)).is_some(),
            "strictly-greater advance must succeed"
        );
        assert!(
            seq.advance(FunctionId(4)).is_none(),
            "strictly-less advance must be rejected"
        );
    }

    #[test]
    fn emit_one_small_string_table_entry_v96_round_trips_read_bitfield() {
        // SmallStringTable entry bit-layout: bit 0 = is_utf16,
        // bits 1..24 = str_offset (23b), bits 24..32 = str_length (8b).
        // Verify pack ↔ read_bitfield for each field independently.
        use crate::parser::read_bitfield_for_test as read_bitfield;

        let raw = SmallStringTableEntryV96Raw {
            is_utf16: true,
            str_offset: 0x0055_5555 & 0x007F_FFFF, // 23 bits
            str_length: 0xA5,                       // 8 bits (255 sentinel is legit)
        };

        let mut out: Vec<u8> = Vec::new();
        emit_one_small_string_table_entry_v96(&mut out, &raw);
        assert_eq!(out.len(), 4);

        assert_eq!(read_bitfield(&out, 0, 1), u32::from(raw.is_utf16));
        assert_eq!(read_bitfield(&out, 1, 23), raw.str_offset);
        assert_eq!(read_bitfield(&out, 24, 8), raw.str_length);
    }

    #[test]
    fn emit_small_string_table_v96_on_minimal_seed() {
        // Minimal v96 seed has string_count=0, so synthesize emits
        // zero bytes. Ensures the helper handles the degenerate case.
        let seed = minimal_v96_seed();
        let hbc = HbcFile::parse(&seed, None).expect("minimal v96 must parse");
        let mut out: Vec<u8> = Vec::new();
        emit_small_string_table_v96(&hbc, &mut out)
            .expect("minimal v96 sst emit must succeed");
        assert_eq!(out.len(), 0);
    }

    #[test]
    fn emit_overflow_string_table_v96_on_minimal_seed() {
        // Same degenerate-case coverage for OverflowStringTable.
        let seed = minimal_v96_seed();
        let hbc = HbcFile::parse(&seed, None).expect("minimal v96 must parse");
        let mut out: Vec<u8> = Vec::new();
        emit_overflow_string_table_v96(&hbc, &mut out)
            .expect("minimal v96 ost emit must succeed");
        assert_eq!(out.len(), 0);
    }

    #[test]
    fn emit_hbc_rejects_non_v96() {
        // Parse one of the non-v96 adversarial fixtures, confirm emit
        // rejects with VersionMismatch. The fixture is adversarial — it
        // can also trip the parser's function-region validation
        // (`FunctionBodyOutOfBytecodeRegion`, a hard-reject region
        // violation distinct from the recover-and-mark overflow-OOB
        // class), in which case parse fails before emit sees it. Either
        // rejection point preserves the "non-v96 input cannot reach v96
        // emit" invariant.
        let v93_fixture: &[u8] =
            include_bytes!("../tests/fixtures/adversarial/oom/fuzz_ssa/47d147c4c0f9.hbc");
        match HbcFile::parse(v93_fixture, None) {
            Ok(v93) => {
                assert_eq!(v93.version, 93);
                match emit_hbc(&v93) {
                    Err(HermesEmitError::VersionMismatch { expected, got }) => {
                        assert_eq!(expected, 96);
                        assert_eq!(got, 93);
                    }
                    other => panic!("expected VersionMismatch, got {other:?}"),
                }
            }
            Err(crate::HermesError::FunctionBodyOutOfBytecodeRegion { .. }) => {
                // Parse-time rejection: function-region validation caught
                // the adversarial fixture before reaching emit.
            }
            Err(other) => panic!("unexpected parse error: {other:?}"),
        }
    }
}
