//! Hermes decompiler error type.
//!
//! Covers both the **parser** surface (`HbcFile::parse`) and the **decode /
//! decompile** surface downstream of a parsed file. Parse-time variants
//! (`HeaderTooSmall`, `InvalidMagic`, `Section*`) replace the prior
//! `Result<_, String>` return type at the public entry point so top-binary
//! `classify()` can downcast instead of substring-match on messages.
#![allow(missing_docs, reason = "internal")]

use droidsaw_common::budget::BudgetExhausted;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum HermesError {
    /// Input buffer shorter than the 128-byte Hermes file header; parser
    /// cannot read the version / counts / section sizes. Carries the
    /// observed buffer length for triage. Surfaces in two places in
    /// `parse_inner`: the initial `buf.len() < 128` guard and the
    /// `first_chunk::<8>()` magic read (which is only reachable if the
    /// first guard passes, so triggering it would indicate a torn read).
    #[error("file too small for Hermes bytecode header: got {got} bytes")]
    HeaderTooSmall { got: usize },

    /// First 8 bytes of the buffer don't match the Hermes magic constant
    /// `0x1F1903C103BC1FC6`. `found` carries the bytes as-read for triage.
    #[error("invalid Hermes bytecode magic: {found:02x?}")]
    InvalidMagic { found: [u8; 8] },

    /// HBC bytecode version is outside the supported range, or is a value
    /// for which no per-version opcode / schema table exists. `observed`
    /// is the version as read from the file header; `supported_min` /
    /// `supported_max` enclose the inclusive user-facing range
    /// (`MIN_SUPPORTED_VERSION..=MAX_SUPPORTED_VERSION` per
    /// `crate::header`). Fail-closed at the parser entry — parse rejects
    /// any out-of-range version before any layout-dependent parsing
    /// begins, so a downstream late-failure inside
    /// `get_version_opcodes` / `get_version_schemas` is unreachable
    /// from `HbcFile::parse`'s entry point.
    #[error(
        "unsupported Hermes bytecode version: observed {observed}, supported {supported_min}..={supported_max}"
    )]
    UnsupportedVersion {
        observed: u32,
        supported_min: u32,
        supported_max: u32,
    },

    /// A `section!`-tracked section's size is larger than `u32::MAX` when
    /// multiplied out from the section's count × stride. File can't hold
    /// such a section regardless of length; this fires before any bounds
    /// check against `buf.len()` would.
    #[error("section {name} too large: {size} bytes exceeds u32::MAX")]
    SectionSizeOverflow { name: &'static str, size: u64 },

    /// A `section!`-tracked section's `cursor + size` extends past the
    /// buffer's length. Adversarial inputs crafting a count that survives
    /// `SectionSizeOverflow` but exceeds `buf.len()` land here.
    #[error(
        "section {name} exceeds file bounds: cursor {cursor} + size {size} > buf.len() {file_len}"
    )]
    SectionExceedsBounds {
        name: &'static str,
        cursor: u64,
        size: u64,
        file_len: usize,
    },

    /// `cursor + size` (or the 4-byte alignment of it) would overflow
    /// `u32::MAX` — only reachable on ≥4 GiB inputs, but silent truncation
    /// there would mis-point every subsequent section read, so surface as
    /// a typed error instead.
    #[error("section {name} cursor overflows u32")]
    SectionCursorOverflow { name: &'static str },

    #[error("SSA construction failed: {0}")]
    Ssa(droidsaw_common::ssa::SsaError),

    /// Exception-handler target is reachable from entry via normal control flow
    /// such that it would be placed earlier in RPO than one of its try-region
    /// blocks. Structurer requires catch blocks to follow their try-region in
    /// the block order; adversarial HBC can construct layouts that violate this
    /// and would otherwise produce incorrect try-catch emission.
    #[error(
        "invalid exception layout: catch block 0x{catch:04x} precedes try-region block \
         0x{try_region:04x} in RPO"
    )]
    InvalidExceptionLayout { catch: u32, try_region: u32 },

    /// A count read from input exceeds what the input size can credibly
    /// back, i.e. the count would drive an allocation or loop body larger
    /// than the input could possibly have encoded. Defense against
    /// adversarial inputs that inflate a u32 count field to amplify a
    /// small file into gigabytes of RSS.
    ///
    /// This variant is the per-function / per-decompile-stage shape used
    /// by `decompile/ssa.rs` (variadic Call argc, instruction-count
    /// bounds). Parser-header amplification bounds use the canonical
    /// [`droidsaw_common::guard::CountExceeded`] shape via
    /// [`HermesError::BoundCountExceeded`].
    #[error("count {got} exceeds input-derived max {max} for {item}")]
    CountExceedsInput {
        got: u32,
        max: usize,
        item: &'static str,
    },

    /// Parser-header amplification defense surfaced through the canonical
    /// [`droidsaw_common::guard::bound_count`] helper. Mirrors
    /// `DexError::BoundCountExceeded` so both bundle crates funnel through
    /// the same `CountExceeded` typed-Err shape. Covers the four primary
    /// HBC header counts (function/string/overflow_string/reg_exp).
    #[error(transparent)]
    BoundCountExceeded(#[from] droidsaw_common::guard::CountExceeded),

    /// Arithmetic overflow on an attacker-controlled value during HBC parse
    /// or bytecode decode. Routes through typed-Err instead of silently
    /// wrapping. `context` names the HBC field for triage.
    #[error("arithmetic overflow in {context}")]
    ArithmeticOverflow { context: &'static str },

    /// Parse or decompile resource budget exhausted. Surfaces when
    /// attacker-controlled input size exceeds the configured memory cap
    /// or when the SSA phi-sealing iteration limit fires (mapped from
    /// `SsaError::IterationLimit` at the error-conversion boundary).
    #[error(transparent)]
    Budget(#[from] BudgetExhausted),

    /// String-table lookup hit `str_length == 255` overflow sentinel
    /// but the routed `str_offset` was `>= overflow_string_count` —
    /// the indirection target is out-of-range. Mirrors
    /// `crate::finding::HermesFinding::OverflowIndexOutOfRange`
    /// payload as the in-band typed signal for the same failure
    /// mode the side-channel Finding surfaces.
    #[error(
        "string-table overflow lookup out of range: index={index}, overflow_count={count}"
    )]
    OverflowIndexOutOfRange { index: u32, count: u32 },

    /// String-storage end exceeds the storage region's extent —
    /// `abs_offset + byte_len > string_storage.0 + string_storage.1`
    /// (or analogous overflow guard). Surfaces from `string_get` /
    /// `string_as_str` as the typed face of the bounds check
    /// (`end > self.buf.len()`).
    #[error(
        "string storage end exceeds bound: index={index}, abs_offset={abs_offset}, byte_len={byte_len}, bound={bound}"
    )]
    StringStorageEndExceedsBuffer {
        /// String-table index whose decode tripped the bound.
        index: u32,
        /// Absolute byte offset within `buf` for the string start.
        abs_offset: usize,
        /// Decoded length-in-bytes (post UTF-16 doubling).
        byte_len: usize,
        /// Validated upper bound (`string_storage.0 +
        /// string_storage.1` or `buf.len()`).
        bound: usize,
    },

    /// String entry's `len == 0` after the overflow rebase produced a
    /// non-zero `str_length` (corruption signal: the in-table entry
    /// said "use overflow" but the rebased value reads as empty).
    /// **Note**: a string entry that is *legitimately* empty surfaces
    /// as `Ok(Some(StringData{ len: 0, ... }))` — this Err is reserved
    /// for the corruption-mask shape where the lookup chain itself is
    /// broken.
    #[error("string entry zero length after overflow rebase: index={index}")]
    ZeroLengthAfterOverflow { index: u32 },

    /// String entry's `offset == 0` after non-overflow validation
    /// passed but downstream UTF decode preconditions detected the
    /// offset is corrupt. Surfaces only when the `str_length > 0`
    /// invariant held but `abs_offset` is sentinel-zero —
    /// distinguishable from a legitimately-empty string by the
    /// non-zero len.
    #[error("string entry zero offset with non-zero length: index={index}, len={len}")]
    ZeroOffsetWithLength { index: u32, len: u32 },

    /// `overflow_string_count` exceeds `string_count` in the HBC header.
    /// Overflow string entries are a sub-pool of the main string pool;
    /// having more overflow entries than total strings is structurally
    /// impossible per the HBC format spec.
    #[error(
        "overflow_string_count ({overflow}) exceeds string_count ({total}) — \
         impossible per HBC format spec"
    )]
    OverflowStringCountExceedsStringCount { overflow: u32, total: u32 },

    /// Decompile request for a `func_id` beyond the bundle's
    /// `function_count`. Surfaces from `decompile_one` /
    /// `decompile_function` when callers pass an out-of-range id
    /// (e.g. external indexing bugs, fuzzer-generated ids).
    #[error("decompile: function_id {id} >= function_count {function_count}")]
    FunctionIdOutOfRange { id: u32, function_count: u32 },

    /// A function header's declared `(offset, size)` extends past the
    /// HBC buffer. Surfaces from `decompile_one` when the parser-
    /// preserved offsets don't bound-check against the actual
    /// in-memory buffer length (truncated read, mis-parsed header).
    #[error("decompile: function body offset={offset} size={size} exceeds buffer length {buf_len}")]
    FunctionBodyExceedsBuffer { offset: u32, size: u32, buf_len: usize },

    /// `decode_function` encountered a byte that names no opcode for the
    /// current bytecode version (i.e. `opcode_id >= num_opcodes`). The
    /// decoder returns this typed Err so callers observe the failure
    /// directly, rather than receiving a silently truncated instruction
    /// stream that would flow into the CFG/SSA pipeline as if complete.
    #[error("decode: unknown opcode {opcode_id} at offset {offset} (num_opcodes = {num_opcodes})")]
    UnknownOpcode {
        /// Byte offset within the function's bytecode where the unknown
        /// opcode was read.
        offset: usize,
        /// The opcode byte value.
        opcode_id: u8,
        /// Number of valid opcodes for this bytecode version (so callers
        /// can confirm the index is genuinely out of range, not a
        /// version-mismatch).
        num_opcodes: usize,
    },

    /// `decode_function` ran out of bytecode mid-instruction — either
    /// the declared `inst_size` extends past `code.len()`, the operand
    /// schema's declared width overruns the instruction's own length,
    /// `inst_size == 0` (which would loop forever), or one of the
    /// internal `pos`/`op_pos` advances overflowed `usize`. The decoder
    /// returns this typed Err rather than a silently partial `DecodedInst`
    /// (which could have `operands.len() < op_types.len()`, causing OOB
    /// access in consumers iterating via `op_types.len()`).
    #[error("decode: truncated instruction stream at offset {offset} (opcode {opcode_id})")]
    TruncatedInstructionStream {
        /// Byte offset within the function's bytecode where the
        /// truncation was detected.
        offset: usize,
        /// The opcode byte at `offset` (so the caller can tell *which*
        /// instruction underran the buffer).
        opcode_id: u8,
    },

    /// `parse_literal_buffer` ran out of bytes mid-payload for an
    /// ArrayBuffer or ObjValueBuffer item with tag 0x30/0x40/0x50/0x70
    /// (Number / LongString / ShortString / Integer). The parser returns
    /// this typed Err so the caller observes the truncation directly,
    /// rather than a phantom-default `LiteralValue` with the buffer
    /// pointer not advanced — which would cause the outer loop to re-read
    /// partial payload bytes as a new tag, breaking roundtrip-byte-equality.
    #[error(
        "literal buffer: truncated payload for tag {tag:#x} \
         (expected {expected_payload} bytes, {remaining} remaining)"
    )]
    TruncatedLiteralBuffer {
        /// The 0x30/0x40/0x50/0x70 type-tag whose payload underran.
        tag: u8,
        /// Bytes the tag's payload schema expects (8 / 4 / 2 / 4).
        expected_payload: usize,
        /// Bytes actually remaining in the buffer at the point of
        /// truncation.
        remaining: usize,
    },

    /// `debug_info_v96_parse` read a header where
    /// `lexical_data_offset > debug_data_size`, violating the upstream
    /// `BytecodeFileFormat.h` invariant
    /// `lexical_data_offset <= debug_data_size` (the lexical-data region
    /// is a suffix of the post-filename-storage data blob). The parser
    /// surfaces this typed Err rather than silently saturating
    /// `lexical_data_size` to 0, which would mask the spec violation
    /// by treating the malformed header as "no lexical data".
    #[error(
        "inconsistent debug info header: lexical_data_offset {lexical_data_offset} \
         exceeds debug_data_size {debug_data_size}"
    )]
    InconsistentDebugHeader {
        /// The `lexical_data_offset` field as read from the v96
        /// DebugInfoHeader (offset 12, u32 LE).
        lexical_data_offset: u32,
        /// The `debug_data_size` field as read from the v96
        /// DebugInfoHeader (offset 16, u32 LE).
        debug_data_size: u32,
    },

    /// A function's declared exception-handler count exceeded
    /// [`crate::finding::MAX_EXCEPTION_HANDLERS`]. Surfaces from
    /// `HbcFile::function_exception_count_checked` — the strict-API
    /// alternative to the silent-0 `function_exception_count`. The
    /// strict API surfaces this typed error; the side-channel
    /// [`crate::finding::HermesFinding::ExceptionCountCap`] surfaces
    /// it through the lenient API, closing the observability gap.
    #[error(
        "function {func_idx}: exception count {declared} exceeds cap {cap}"
    )]
    ExceptionCountCap {
        /// The function index whose declared count tripped the cap.
        func_idx: u32,
        /// The declared exception-handler count (verbatim from the
        /// HBC byte stream).
        declared: u32,
        /// The cap that was exceeded (snapshot of
        /// `MAX_EXCEPTION_HANDLERS` at the call).
        cap: u32,
    },

    /// A function header had the `overflowed` flag set but the
    /// declared large-header offset extends past the HBC buffer
    /// (`large_off + LARGE_FUNCTION_HEADER_SIZE > buf.len()`).
    /// Surfaces from `HbcFile::function_get_checked` — the strict-API
    /// alternative to the silent-truncated-25-bit fallback in
    /// `function_get`. The non-strict path returns a `FunctionData`
    /// whose `offset` comes from the small header's bitfield,
    /// indistinguishable from a real non-overflowed function —
    /// letting an attacker re-route body decode to a wrong offset via
    /// crafted metadata. Side-channel
    /// [`crate::finding::HermesFinding::OverflowedHeaderOutOfBounds`]
    /// is emitted from the silent path so existing callers observe
    /// the violation; the strict API surfaces this typed Err for
    /// consumers that need to distinguish "valid small-header
    /// function" from "broken overflow claim".
    #[error(
        "function {func_idx}: overflow large-header at {large_off:#x} extends past buf.len() = {buf_len}"
    )]
    OverflowedHeaderOutOfBounds {
        /// The function index whose overflow claim tripped the OOB check.
        func_idx: u32,
        /// The declared large-header offset (verbatim from the
        /// composed small-header bitfields).
        large_off: u64,
        /// The HBC buffer length at the time of the OOB check.
        buf_len: usize,
    },

    /// A function header had the `overflowed` flag set with an
    /// in-bounds large-header offset, but the large-header byte span
    /// `[large_off, large_off + LARGE_FUNCTION_HEADER_SIZE)`
    /// physically intersects a region that emit recomputes from IR
    /// (the 128-byte file header, the FunctionHeaders small-header
    /// table, or the string tables). Because those bytes are
    /// double-claimed — once by the synthesized region, once by this
    /// function's large header — emit's faithful recompute of the
    /// synthesized region silently mutates this function's
    /// `offset`/`size`/`flags`, breaking `parse → emit → parse`. A
    /// well-formed Hermes bundle never lays a large header inside a
    /// synthesized region (the serializer places SecondaryFuncHeaders
    /// in the function-info region after every table), so this shape
    /// is adversarial-only. The non-strict `function_get` path returns
    /// the aliased `offset`, indistinguishable from a real function,
    /// letting body decode route to a wrong offset; the strict API
    /// surfaces this typed Err so the caller can recover-and-mark the
    /// function as unrecognized (terminal — never decoded).
    #[error(
        "function {func_idx}: overflow large-header at {large_off:#x} overlaps a synthesized region"
    )]
    OverflowedHeaderOverlapsSynthesizedRegion {
        /// The function index whose overflow claim overlaps a
        /// synthesized region.
        func_idx: u32,
        /// The declared large-header offset (verbatim from the
        /// composed small-header bitfields).
        large_off: u64,
    },

    /// HBC v98 form-disambiguation failed because both
    /// `BytecodeOptions`-byte positions (offset 108 for v98-early,
    /// 112 for v98-late) had reserved bits set (`& 0xF8 != 0`). With
    /// neither position passing the MBZ check, there is no honest
    /// signal for which layout the writer intended; downstream
    /// `SmallFuncHeader` bitfield widths differ (16 vs 12 bytes) and
    /// the `large_off = (raw_func_name << shift) | raw_offset`
    /// composition uses shift=16 for early and shift=24 for late, so
    /// guessing wrong silently routes function bodies to attacker-
    /// chosen regions. Fail-closed per the adversarial-review §H-1
    /// gauge.
    ///
    /// `early` and `late` carry the observed BytecodeOptions bytes at
    /// offsets 108 / 112 for audit-trail attribution.
    #[error(
        "ambiguous v98 form: both BytecodeOptions positions have reserved bits set \
         (early=0x{early:02x}, late=0x{late:02x}); no honest disambiguation signal"
    )]
    AmbiguousV98Form { early: u8, late: u8 },

    /// `function_get_checked`'s entry-OOB guard fired:
    /// `entry_off + func_header_size > buf.len()` for an in-range
    /// function index. Structurally unreachable for any `HbcFile`
    /// constructed via `HbcFile::parse` (the section-walk macro
    /// validates that the function-header table fits within `buf`
    /// at parse time). Surfaces only if `HbcFile` state is mutated
    /// outside `parse` — e.g., a test helper that builds the struct
    /// fields manually with inconsistent section offsets, counts,
    /// and buffer lengths. Strict-API contract: the
    /// `function_get_checked` callsite returns this typed Err
    /// rather than silently delegating to the lenient `function_get`
    /// all-zero default.
    #[error(
        "function header entry out of bounds: func_idx={func_idx}, entry_off={entry_off}, \
         fh_size={fh_size}, buf_len={buf_len}"
    )]
    FunctionHeaderEntryOutOfBounds {
        /// The function index whose entry exceeds buf bounds.
        func_idx: u32,
        /// The computed entry offset (`func_headers.0 + idx*fh_size`).
        entry_off: usize,
        /// The SmallFuncHeader stride at the time of the check.
        fh_size: u32,
        /// The HBC buffer length at the time of the check.
        buf_len: usize,
    },

    /// A function's declared `(offset, size)` falls outside the file's
    /// bytecode-body region. The bytecode region is the contiguous
    /// span between the end of all `section!`-tracked metadata
    /// (FunctionHeaders, StringKinds, IdentifierHashes, SmallString /
    /// OverflowString tables, StringStorage, ArrayBuffer, Obj buffers,
    /// BigInt sections, RegExp sections, CJSModules, FunctionSource
    /// table) and the start of debug info (or end of buffer when
    /// `debug_info_offset == 0`).
    ///
    /// Out-of-region offsets let an attacker re-route function-body
    /// decode to file-header bytes (offset=0), parsed metadata sections
    /// (string storage, BigInt storage, etc.), or post-debug-info
    /// trailing bytes (e.g., the SHA-1 footer). Each of those produces
    /// a phantom IR that disagrees with what the Hermes VM would
    /// execute on the same bytes.
    #[error(
        "function {func_idx}: body (offset={offset}, size={size}) outside bytecode region \
         [{region_start}..{region_end})"
    )]
    FunctionBodyOutOfBytecodeRegion {
        /// The function index whose body fell outside the region.
        func_idx: u32,
        /// File-absolute offset of the declared function body.
        offset: u32,
        /// Declared bytecode size of the function body.
        size: u32,
        /// Lower bound of the bytecode region (inclusive).
        region_start: u32,
        /// Upper bound of the bytecode region (exclusive).
        region_end: u32,
    },

    /// Two function bodies' `(offset, size)` ranges overlap. After
    /// sorting functions by `offset`, an adjacent pair satisfies
    /// `prev.offset + prev.size > cur.offset` — the previous function's
    /// end extends past the next function's start. Overlapping bodies
    /// mean the same bytes get disassembled as two distinct functions
    /// with different call-graph entries, and detection rules that
    /// hash "function bytecode body" hash the same bytes twice under
    /// different function IDs.
    ///
    /// `a_idx` and `b_idx` are the offset-sorted pair (`a` is the
    /// earlier-starting function; declaration-index order is preserved
    /// in the payload for triage).
    #[error(
        "function bodies overlap: function {a_idx} (offset={a_offset}, size={a_size}) \
         overlaps function {b_idx} (offset={b_offset}, size={b_size})"
    )]
    FunctionBodyOverlap {
        /// Index of the earlier-starting function in the overlap.
        a_idx: u32,
        /// File-absolute offset of the earlier-starting function body.
        a_offset: u32,
        /// Declared size of the earlier-starting function body.
        a_size: u32,
        /// Index of the later-starting function in the overlap.
        b_idx: u32,
        /// File-absolute offset of the later-starting function body.
        b_offset: u32,
        /// Declared size of the later-starting function body.
        b_size: u32,
    },

    /// The function table contained more exact-duplicate function-info
    /// entries than the dedup tolerance allows. Two function-info
    /// entries pointing at the SAME `(offset, size)` are accepted as a
    /// production-Hermes nop-stub deduplication pattern (observed on
    /// 14% of an F-Droid corpus sample, signature `function N + M
    /// both at offset=O, size=9`). Many such dedups in one bundle is a
    /// corruption signal — the table is no longer a function index
    /// space, it's a many-to-one alias.
    #[error(
        "function-body dedup overflow: {dedup_count} exact-duplicate function-info pairs \
         exceed threshold {threshold}; first duplicate pair at offset={first_offset} \
         size={first_size} (functions {first_a_idx} + {first_b_idx})"
    )]
    FunctionBodyDedupOverflow {
        /// Total count of exact-duplicate function-info pairs observed.
        dedup_count: u32,
        /// Tolerance threshold above which the dedup pattern is rejected.
        threshold: u32,
        /// First duplicate pair's shared offset (debug aid).
        first_offset: u32,
        /// First duplicate pair's shared size (debug aid).
        first_size: u32,
        /// Lower function index of the first observed dedup pair.
        first_a_idx: u32,
        /// Higher function index of the first observed dedup pair.
        first_b_idx: u32,
    },

    /// CFG construction observed an exception-handler `target` that
    /// does not match the start offset of any basic block. Block
    /// leaders come from instruction starts at branch / fallthrough /
    /// post-terminator positions; a handler whose `target` lands in
    /// the middle of an instruction's operand bytes — or past the
    /// last instruction — synthesizes no block, and the legacy silent-
    /// skip path would absorb the bogus handler into the CFG (the
    /// Hermes VM rejects mis-aimed handlers at install time, but the
    /// structurer would otherwise emit a try/catch the runtime never
    /// installs).
    ///
    /// The parser-side `ExceptionHandlerOutOfFunctionRange` check
    /// fires earlier on the `target >= fn.size` shape; this variant
    /// catches the remaining case `target < fn.size && target is not
    /// a block leader`.
    #[error(
        "exception handler target 0x{target:04x} does not map to a basic block leader"
    )]
    InvalidExceptionHandlerTarget {
        /// The handler's catch target (function-relative bytecode offset)
        /// that failed to match any block ID.
        target: u32,
    },

    /// An exception handler `(start, end, target)` triple — read from
    /// the per-function handler table at `infoOffset` — falls outside
    /// the parent function's bytecode range. The handler offsets are
    /// function-relative bytecode-stream offsets (0-based within the
    /// function's `(offset, size)` body), so the validation checks
    /// `start < end`, `end <= fn.size`, and `target < fn.size`.
    ///
    /// Out-of-range handlers let an attacker construct try/catch
    /// regions whose `target` lies in another function's body or in
    /// mid-instruction bytes that synthesize a phantom catch block —
    /// the Hermes VM rejects the bogus handler at install time, but
    /// droidsaw's structurer would otherwise emit a try/catch that
    /// the runtime never installs (false-positive on "uses exception
    /// handling" detection rules).
    #[error(
        "function {func_idx} handler {handler_idx}: (start={start}, end={end}, target={target}) \
         outside function bytecode range (size={fn_size})"
    )]
    ExceptionHandlerOutOfFunctionRange {
        /// The function index whose handler tripped the bounds check.
        func_idx: u32,
        /// The handler index within the function's exception-handler
        /// table (0-based; `0..count`).
        handler_idx: u32,
        /// Function-relative start of the try-region (verbatim from
        /// the handler entry's first u32).
        start: u32,
        /// Function-relative end of the try-region (verbatim from the
        /// handler entry's second u32). Validation requires
        /// `start < end && end <= fn_size`.
        end: u32,
        /// Function-relative catch target (verbatim from the handler
        /// entry's third u32). Validation requires `target < fn_size`;
        /// the further "target lands on an instruction boundary" check
        /// surfaces at CFG-construction time.
        target: u32,
        /// The parent function's bytecode size (the upper bound the
        /// handler triple violated).
        fn_size: u32,
    },
}

impl From<droidsaw_common::ssa::SsaError> for HermesError {
    fn from(e: droidsaw_common::ssa::SsaError) -> Self {
        use droidsaw_common::ssa::SsaError;
        match e {
            SsaError::IterationLimit { .. } => HermesError::Budget(BudgetExhausted {
                kind: droidsaw_common::budget::BudgetKind::Steps,
                context: "ssa-seal-phis",
            }),
            other => HermesError::Ssa(other),
        }
    }
}

pub type Result<T> = std::result::Result<T, HermesError>;

/// Clamp a parse-time count against the physical size of the input.
///
/// Thin wrapper over [`droidsaw_common::guard::bound_count`] that
/// preserves the hermes-side u32 input shape (HBC header `*_count`
/// fields are u32 on disk; the cast to `u64` is purely
/// downcast-avoidance and free). The `CountExceeded` error variant
/// from common converts into [`HermesError::BoundCountExceeded`] via
/// `#[from]` on the `?` boundary. Mirrors `droidsaw-dex/src/error.rs`'s
/// `bound_count` wrapper exactly so both bundle crates present the
/// identical call-site idiom.
#[inline]
pub fn bound_count(
    got: u32,
    stride: usize,
    data_len: usize,
    item: &'static str,
) -> Result<usize> {
    droidsaw_common::guard::bound_count(u64::from(got), stride, data_len, item)
        .map_err(HermesError::from)
}
