//! v96 debug_info decomposition. Typed IR + parser for the
//! `DebugInfoHeader` + `DebugFileRegion` table + source-locations varint
//! stream layout that's stable across HBC v94..v99. Extracted from
//! `parser/mod.rs` to keep this single-purpose: types + parse + decode
//! in one file, the `HbcFile` impl that calls them stays in mod.rs.

#![allow(
    clippy::cast_possible_truncation,
    reason = "PROOF: v96 debug_info section parsing. All 20 cast sites are u32/u64↔usize widens on validated debug-info section offsets; bounded by the `cursor + sz > buf.len()` check inside the `section!` macro that frames every read, so any read past the section ceiling fails before the cast executes."
)]

use super::read_u32;
use crate::error::HermesError;
use crate::header::HEADER_SIZE;

// ── Debug info v96 decomposition ─────────────────────────────────────────
//
// Decomposes the HBC v96 debug_info section into typed IR beyond just
// filename counts.
//
// Upstream reference: facebook/hermes@v0.12.0 (HBC v96 era)
//   - `include/hermes/BCGen/HBC/BytecodeFileFormat.h` :: `DebugInfoHeader`
//     (5 u32s, 20 bytes total: filenameCount, filenameStorageSize,
//     fileRegionCount, lexicalDataOffset, debugDataSize)
//   - `include/hermes/BCGen/HBC/BytecodeFileFormat.h` :: `DebugFileRegion`
//     (3 u32s, 12 bytes each: fromAddress, filenameId, sourceMappingUrlId)
//   - `include/hermes/BCGen/HBC/DebugInfo.h` — source-location data layout
//     ("[sourceLocations][lexicalData]" concatenation with lexicalDataOffset
//     marking the boundary within the post-filename-storage data region)
//
// Source-location varint walk format (v94..v97 range; v96 hits this
// branch): per-function entries encoded as
//     function_index: sleb128
//     start_line: sleb128
//     start_column: sleb128
//     [ address_delta: sleb128   (-1 terminates the per-function run)
//       line_delta: sleb128
//       column_delta: sleb128
//       scope_address: sleb128
//       env_register: sleb128
//       (if line_delta & 1) statement_delta: sleb128
//       (line_delta >>= 1)
//     ]*
// Outer loop terminates when no more bytes to read.

/// v96 `DebugInfoHeader` — 20 bytes at the start of the debug_info section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DebugInfoHeaderV96 {
    pub filename_count: u32,
    pub filename_storage_size: u32,
    pub file_region_count: u32,
    pub lexical_data_offset: u32,
    pub debug_data_size: u32,
}

/// v96 `DebugFileRegion` — 12 bytes per entry in the debug file region
/// table. Maps a bytecode address range to a filename + source-mapping URL
/// (both as string-id references into the main HBC string table).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DebugFileRegion {
    pub from_address: u32,
    pub filename_id: u32,
    pub source_mapping_url_id: u32,
}

/// Source location entry — a decoded (address, line, column, statement)
/// tuple within a function's source-location table. Accumulated from the
/// per-PC delta-encoded varint stream in debug_info.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceLocation {
    /// PC-relative bytecode address within the owning function.
    pub address: u32,
    /// 1-based source line number.
    pub line: u32,
    /// 1-based source column number.
    pub column: u32,
    /// Source-statement counter (bumped per statement; 0 when no
    /// statement boundary at this location).
    pub statement: u32,
}

/// Per-function source-info header + location table. Decoded lazily
/// from the varint stream via `HbcFile::source_locations`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionSourceInfo {
    /// Function index (matches `HbcFile::function_get` indexing when
    /// non-negative; attacker-crafted inputs may encode out-of-range
    /// indices — caller discriminates).
    pub function_index: u32,
    /// Start line for the function.
    pub start_line: u32,
    /// Start column for the function.
    pub start_column: u32,
    /// Decoded PC → (line, column, statement) mappings for the
    /// function, in order of increasing address.
    pub locations: Vec<SourceLocation>,
    /// Set to `true` when the per-PC varint stream ended mid-entry for
    /// THIS function. When set, the inner break also stops the outer
    /// loop (so no phantom `FunctionSourceInfo { function_index: 0, .. }`
    /// is appended) AND the in-progress entry is tagged `corrupt = true`
    /// so downstream symbolicator / source-map consumers can drop it
    /// rather than report fabricated source locations.
    pub corrupt: bool,
}

/// Binary classification of debug_info presence on an `HbcFile`. See
/// `HbcFile::debug_info_classification`. Production RN bundles
/// overwhelmingly strip source info; those that retain it leave a
/// significant forensic surface including CI-path disclosures in
/// filename storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DebugInfoClassification {
    /// `debug_info_offset == 0`; the file encodes no debug_info at all.
    Absent,
    /// DebugInfoHeader is present but its payload is empty (`debug_data_size == 0`,
    /// `file_region_count == 0`, `filename_storage_size == 0`). Production-RN
    /// default — saves bundle size by stripping source mapping while
    /// preserving the header slot for format consistency.
    HeaderOnly,
    /// DebugInfoHeader is present with a non-empty payload (source_locations
    /// and/or lexical_data). The builder retained source-mapping data —
    /// unusual in production RN. Filename storage in this mode routinely
    /// discloses builder's CI path structure.
    Full,
}

/// Container for v96 debug_info decomposition data. Present on
/// `HbcFile` when `debug_info_offset > 0` AND the file's version falls
/// in the v94..v99 range (the DebugInfoHeader layout is stable across
/// that range). Source locations are decoded on-demand via
/// `HbcFile::source_locations` rather than eagerly at parse time.
#[derive(Debug, Clone)]
pub struct DebugInfoV96 {
    /// Decoded 20-byte header.
    pub header: DebugInfoHeaderV96,
    /// Byte-range (offset, size) of the 12-byte-per-entry file region
    /// table within the HBC buffer. Empty when `file_region_count == 0`.
    pub file_region_table: (usize, usize),
    /// Byte-range (offset, size) of the raw filename storage within the
    /// HBC buffer. Content format is a packed UTF-8 byte stream; entry
    /// boundaries are encoded via `DebugFileRegion`'s `filename_id`
    /// referencing the main HBC string table, so this field is less
    /// load-bearing than the file_region_table itself.
    pub filename_storage: (usize, usize),
    /// Byte-range of the varint-encoded source-locations data. Starts
    /// after filename storage; ends at
    /// `source_locations_start + lexical_data_offset` (the
    /// `lexical_data_offset` field of the header is an offset WITHIN
    /// the post-filename-storage data blob, NOT an absolute file
    /// offset).
    pub source_locations_data: (usize, usize),
    /// Byte-range of the lexical data (scope chains, variable names).
    /// Not decomposed in v1 — exposed as a raw byte-range for future
    /// decomposition.
    pub lexical_data: (usize, usize),
}

// Version range where the 20-byte DebugInfoHeader + 12-byte
// DebugFileRegion layout applies. Layout is stable in the Hermes
// v0.12-era source (tag `v0.12.0`). Earlier versions may have used a
// narrower header; later versions (v99+) added scope-descriptor
// indexing but kept the first 5 u32s identical. Gate used by
// `debug_info_v96_parse` below.
pub(super) const DEBUG_INFO_V96_MIN: u32 = 94;
pub(super) const DEBUG_INFO_V96_MAX: u32 = 99;

/// Defensive cap on per-function location entries accumulated during
/// `decode_source_locations`. Adversarial inputs could encode
/// arbitrary-length address-delta streams; capping prevents OOM while
/// staying well above the largest observed real-function PC count on
/// the largest observed real-world functions (≈ 15k PCs).
pub(super) const SOURCE_LOCATIONS_MAX_PC_ENTRIES: usize = 1 << 20;

/// Defensive cap on functions enumerated during source-location walk.
/// Bounded by the largest observed `function_count` in real corpora
/// (≈ 300k) with a safety margin. Adversarial inputs beyond this cap
/// truncate rather than OOM.
pub(super) const SOURCE_LOCATIONS_MAX_FUNCTIONS: usize = 1 << 22;

/// Decode a v94..v99 source-locations varint stream into
/// `FunctionSourceInfo` entries. Returns `None` if the first varint
/// read fails (empty stream or malformed); returns truncated results on
/// mid-walk corruption (adversarial path).
///
/// Format per upstream `lib/BCGen/HBC/DebugInfo.cpp` + the vendored
/// `hermes-dec/parsers/debug_info_parser.py`:
///
/// ```text
/// [{
///     function_index: sleb128,
///     start_line: sleb128,
///     start_column: sleb128,
///     [{  address_delta: sleb128  (-1 terminates)
///         line_delta: sleb128
///         column_delta: sleb128
///         (v94..v96)  scope_address: sleb128
///         (v94..v96)  env_register: sleb128
///         (v99+)      env_idx: sleb128
///         (if line_delta & 1) statement_delta: sleb128
///         (then line_delta >>= 1)
///     }]*
/// }]*
/// ```
///
/// All arithmetic is `saturating_*` to bound adversarial deltas; line
/// and column are u32 but the source deltas are signed i32 — saturate
/// to 0 on negative results.
#[allow(clippy::arithmetic_side_effects, reason = "Parser-bounded arithmetic; surrounding loop guards ensure offsets remain within the slice (see preceding PROOF in this function or block).")]
#[doc(hidden)] // Exposed for libFuzzer (fuzz_decode_source_locations); not part of public API.
pub fn decode_source_locations(data: &[u8], version: u32) -> Option<Vec<FunctionSourceInfo>> {
    use droidsaw_common::encoding::read_sleb128;

    if data.is_empty() {
        return None;
    }
    let has_scope_env = (94..97).contains(&version);
    let has_env_idx = version >= 99;

    let mut functions: Vec<FunctionSourceInfo> =
        Vec::with_capacity(data.len().min(4096) / 8);
    let mut pos = 0usize;

    while pos < data.len() && functions.len() < SOURCE_LOCATIONS_MAX_FUNCTIONS {
        // Outer: function_index. If read fails (OOB / invalid), stop.
        let (function_index_i32, consumed) = match read_sleb128(data, pos) {
            Ok(v) => v,
            Err(_) => break,
        };
        // Negative function_index terminates per upstream convention
        // (also defensive against malformed streams — upstream encodes
        // valid function indices as non-negative u32).
        if function_index_i32 < 0 {
            break;
        }
        pos = pos.saturating_add(consumed);

        let (start_line_i32, consumed) = match read_sleb128(data, pos) {
            Ok(v) => v,
            Err(_) => break,
        };
        pos = pos.saturating_add(consumed);
        let (start_column_i32, consumed) = match read_sleb128(data, pos) {
            Ok(v) => v,
            Err(_) => break,
        };
        pos = pos.saturating_add(consumed);

        // PROOF: line 235 above `break`s when `function_index_i32 < 0`,
        // so the i32→u32 cast cannot fail here. We still use the fallible
        // `try_from` (no `expect`/`unwrap` — those would trip the crate's
        // `unwrap_used`/`expect_used` deny floor and the runtime `panic =
        // abort` profile). If a future refactor flips line 235, the
        // `else break` below is the defense-in-depth fallback rather than
        // a silent `unwrap_or(0)` that would mint a phantom function_index.
        let function_index = match u32::try_from(function_index_i32) {
            Ok(v) => v,
            Err(_) => break,
        };
        let mut current_line = i32::max(start_line_i32, 0);
        let mut current_column = i32::max(start_column_i32, 0);
        let mut current_address: i64 = 0;
        let mut current_statement: i64 = 0;
        let mut locations: Vec<SourceLocation> = Vec::new();

        // `corrupt` is set when the per-PC varint stream ends mid-entry
        // (any `Err` from `read_sleb128`). The negative-address-delta
        // terminator is a SPEC convention — it does NOT set `corrupt`,
        // and the outer loop continues to the next function. When
        // `corrupt` IS set, `pos` is not aligned with a per-entry
        // boundary, so the outer loop must stop — otherwise it would
        // theoretically resync into the partial-entry bytes and produce
        // a phantom `FunctionSourceInfo { function_index: 0, .. }`.
        // The flag is surfaced to downstream consumers so they can drop
        // the partial entry rather than report fabricated source
        // locations.
        let mut corrupt = false;

        loop {
            if locations.len() >= SOURCE_LOCATIONS_MAX_PC_ENTRIES {
                break;
            }
            let (address_delta, consumed) = match read_sleb128(data, pos) {
                Ok(v) => v,
                Err(_) => {
                    corrupt = true;
                    break;
                }
            };
            pos = pos.saturating_add(consumed);
            if address_delta < 0 {
                // Spec convention: negative address_delta terminates
                // this function's PC stream. Not a corruption — the
                // outer loop should continue to the next function.
                break;
            }
            let (line_delta_raw, consumed) = match read_sleb128(data, pos) {
                Ok(v) => v,
                Err(_) => {
                    corrupt = true;
                    break;
                }
            };
            pos = pos.saturating_add(consumed);
            let (column_delta, consumed) = match read_sleb128(data, pos) {
                Ok(v) => v,
                Err(_) => {
                    corrupt = true;
                    break;
                }
            };
            pos = pos.saturating_add(consumed);

            if has_scope_env {
                // scope_address + env_register — decoded for bytes
                // consumed, value otherwise unused in v1.
                if let Ok((_, c)) = read_sleb128(data, pos) {
                    pos = pos.saturating_add(c);
                } else {
                    corrupt = true;
                    break;
                }
                if let Ok((_, c)) = read_sleb128(data, pos) {
                    pos = pos.saturating_add(c);
                } else {
                    corrupt = true;
                    break;
                }
            } else if has_env_idx {
                if let Ok((_, c)) = read_sleb128(data, pos) {
                    pos = pos.saturating_add(c);
                } else {
                    corrupt = true;
                    break;
                }
            }

            let mut statement_delta: i32 = 0;
            let line_delta = if line_delta_raw & 1 != 0 {
                let (sd, consumed) = match read_sleb128(data, pos) {
                    Ok(v) => v,
                    Err(_) => {
                        corrupt = true;
                        break;
                    }
                };
                pos = pos.saturating_add(consumed);
                statement_delta = sd;
                line_delta_raw >> 1
            } else {
                line_delta_raw >> 1
            };

            current_address = current_address.saturating_add(i64::from(address_delta));
            current_line = current_line.saturating_add(line_delta);
            current_column = current_column.saturating_add(column_delta);
            current_statement = current_statement.saturating_add(i64::from(statement_delta));

            locations.push(SourceLocation {
                address: u32::try_from(current_address.clamp(0, i64::from(u32::MAX)))
                    .unwrap_or(0),
                line: u32::try_from(i32::max(current_line, 0)).unwrap_or(0),
                column: u32::try_from(i32::max(current_column, 0)).unwrap_or(0),
                statement: u32::try_from(current_statement.clamp(0, i64::from(u32::MAX)))
                    .unwrap_or(0),
            });
        }

        functions.push(FunctionSourceInfo {
            function_index,
            start_line: u32::try_from(i32::max(start_line_i32, 0)).unwrap_or(0),
            start_column: u32::try_from(i32::max(start_column_i32, 0)).unwrap_or(0),
            locations,
            corrupt,
        });

        // If the per-PC stream ended mid-entry, `pos` is past a partial
        // varint sequence; resuming the outer loop would re-read those
        // bytes as a new `function_index` and produce a phantom entry.
        // Stop here — the partial entry is preserved on the result
        // with `corrupt = true` so callers can decide whether to keep
        // it or drop it.
        if corrupt {
            break;
        }
    }

    if functions.is_empty() {
        None
    } else {
        Some(functions)
    }
}

/// Parse the 20-byte `DebugInfoHeader` + derive byte-ranges for the
/// 12-byte `DebugFileRegion` table, filename storage, source-locations
/// data, and lexical data.
///
/// Return-shape contract:
/// - `Ok(None)` — `debug_info_offset == 0`, version out of v94..v99
///   range, `debug_data_size == 0` (no section data; v99 hermesc emits a
///   non-zero `lexical_data_offset` in this case), or any bounds check
///   fails (OOB header / OOB file-region table / OOB storage / OOB data
///   regions, including any overflow in the cumulative `checked_*`
///   arithmetic). The "absent or structurally-bad" cases collapse to a
///   single `None` so callers that have no debug-info section behave
///   identically to callers whose header just OOBs.
/// - `Err(HermesError::InconsistentDebugHeader { .. })` — the header
///   parsed without OOB, `debug_data_size > 0`, but violates the upstream
///   `BytecodeFileFormat.h` invariant `lexical_data_offset <=
///   debug_data_size`. The typed Err surfaces this rather than silently
///   saturating `lexical_data_size` to 0 (which would be
///   indistinguishable from a benign zero-lexical-data header).
/// - `Ok(Some(_))` — fully-validated decomposition.
///
/// Adversarial inputs that encode out-of-bounds field values produce
/// `Ok(None)` rather than panicking or returning partial data. All u32
/// arithmetic uses `checked_add` on the cumulative offset; cast to
/// `usize` is guarded by `debug_info_offset as u64 + 20 <= buf.len() as
/// u64` which cannot overflow.
pub(super) fn debug_info_v96_parse(
    buf: &[u8],
    debug_info_offset: u32,
    version: u32,
) -> Result<Option<DebugInfoV96>, HermesError> {
    if debug_info_offset == 0 {
        return Ok(None);
    }
    if !(DEBUG_INFO_V96_MIN..=DEBUG_INFO_V96_MAX).contains(&version) {
        return Ok(None);
    }
    // STRUCTURAL INVARIANT: the debug_info section must not overlap the
    // file header. A `debug_info_offset` that lands inside [0, HEADER_SIZE)
    // would make the 20-byte DebugInfoHeader read u32s out of the file
    // header itself — e.g., `lexical_data_offset` reads from byte
    // `debug_info_offset + 12`, which is the `file_length` u32 at offset
    // 32 when `debug_info_offset == 20`. That value is recomputed by the
    // emit path (synthesize, not passthrough), so a first parse that
    // accepts the overlap can drift across emit (file_length changes from
    // the raw input value to the actual buffer length), causing the
    // second parse to see a different lexical_data_offset and raise
    // `InconsistentDebugHeader`. Treating overlap-with-header as the
    // existing "structurally bad → Ok(None)" case keeps the
    // parse∘emit∘parse fuzz roundtrip closed without inventing new error
    // variants.
    #[allow(
        clippy::as_conversions,
        reason = "HEADER_SIZE is a 128-byte compile-time constant that fits in u32; widen for comparison with the u32-typed `debug_info_offset`."
    )]
    if debug_info_offset < HEADER_SIZE as u32 {
        return Ok(None);
    }
    #[allow(clippy::as_conversions, reason = "u32 → usize widen on 64-bit targets; bounded by `as u64 + 20 <= buf.len() as u64` check below before any in-buf slicing.")]
    let dbg_off = debug_info_offset as usize;
    // Header bounds: need 20 bytes.
    let Some(header_end) = u64::from(debug_info_offset).checked_add(20) else {
        return Ok(None);
    };
    // WHY: buf.len() as u64 widens on 64-bit targets (usize <= u64).
    #[allow(clippy::as_conversions, reason = "buf.len() as u64 widens on 64-bit targets (usize <= u64).")]
    if header_end > buf.len() as u64 {
        return Ok(None);
    }

    let header = DebugInfoHeaderV96 {
        filename_count: read_u32(buf, dbg_off),
        #[allow(clippy::arithmetic_side_effects, reason = "Parser-bounded arithmetic; surrounding loop guards ensure offsets remain within the slice (see preceding PROOF in this function or block).")]
        filename_storage_size: read_u32(buf, dbg_off + 4),
        #[allow(clippy::arithmetic_side_effects, reason = "Parser-bounded arithmetic; surrounding loop guards ensure offsets remain within the slice (see preceding PROOF in this function or block).")]
        file_region_count: read_u32(buf, dbg_off + 8),
        #[allow(clippy::arithmetic_side_effects, reason = "Parser-bounded arithmetic; surrounding loop guards ensure offsets remain within the slice (see preceding PROOF in this function or block).")]
        lexical_data_offset: read_u32(buf, dbg_off + 12),
        #[allow(clippy::arithmetic_side_effects, reason = "Parser-bounded arithmetic; surrounding loop guards ensure offsets remain within the slice (see preceding PROOF in this function or block).")]
        debug_data_size: read_u32(buf, dbg_off + 16),
    };
    // Note the arithmetic_side_effects allows on the dbg_off+N reads
    // above: header_end <= buf.len() proves dbg_off + {0..20} are
    // all in-bounds usize-addable without wrap.

    // v99 hermesc sets lexical_data_offset to the debug header size (31)
    // even when debug_data_size = 0; a zero-length data section has no
    // valid sub-ranges regardless of the offset field.
    if header.debug_data_size == 0 {
        return Ok(None);
    }

    // SPEC INVARIANT (upstream `BytecodeFileFormat.h`): the
    // lexical-data region is a suffix of the post-filename-storage
    // data blob, so `lexical_data_offset <= debug_data_size`. Detect
    // the inconsistent-header shape BEFORE any downstream arithmetic
    // — a saturated subtraction would silently mask the violation as
    // a "zero-byte lexical data" range. Surface the typed Err so
    // downstream consumers + fuzz harnesses can assert on the precise
    // failure mode.
    if header.lexical_data_offset > header.debug_data_size {
        return Err(HermesError::InconsistentDebugHeader {
            lexical_data_offset: header.lexical_data_offset,
            debug_data_size: header.debug_data_size,
        });
    }

    // File region table: file_region_count × 12 bytes, immediately
    // after the 20-byte header.
    let file_region_entry_size: u64 = 12;
    let Some(file_region_table_size) =
        u64::from(header.file_region_count).checked_mul(file_region_entry_size)
    else {
        return Ok(None);
    };
    let file_region_table_start = header_end; // dbg_off + 20
    let Some(file_region_table_end) = file_region_table_start.checked_add(file_region_table_size)
    else {
        return Ok(None);
    };
    #[allow(clippy::as_conversions, reason = "Spec-bounded value-domain narrowing (parser-validated field; preceding PROOF documents the bit-width invariant).")]
    if file_region_table_end > buf.len() as u64 {
        return Ok(None);
    }

    // Filename storage: immediately after the file region table, with
    // a 4-byte u32 length prefix preceding the UTF-8 content.
    // Bytes at file_region_table_end encode `u32 = filename_storage_size`
    // verbatim before the UTF-8 filename bytes begin (standard
    // length-prefixed-array convention). Per-entry semantics for
    // filename_count > 1 are unverified. Treat the 4-byte prefix as
    // part of the
    // on-disk filename_storage region and point the UTF-8 content start
    // 4 bytes past file_region_table_end.
    let filename_storage_prefix: u64 = 4;
    let Some(filename_storage_start) = file_region_table_end.checked_add(filename_storage_prefix)
    else {
        return Ok(None);
    };
    let Some(filename_storage_end) =
        filename_storage_start.checked_add(u64::from(header.filename_storage_size))
    else {
        return Ok(None);
    };
    #[allow(clippy::as_conversions, reason = "Spec-bounded value-domain narrowing (parser-validated field; preceding PROOF documents the bit-width invariant).")]
    if filename_storage_end > buf.len() as u64 {
        return Ok(None);
    }

    // Source-locations data: starts at filename_storage_end; ends at
    // filename_storage_end + lexical_data_offset. The
    // lexical_data_offset is a relative offset WITHIN the
    // post-filename-storage data blob per the upstream DebugInfo.h
    // "[sourceLocations][lexicalData]" comment.
    let data_start = filename_storage_end;
    let Some(source_locations_end) = data_start.checked_add(u64::from(header.lexical_data_offset))
    else {
        return Ok(None);
    };
    #[allow(clippy::as_conversions, reason = "Spec-bounded value-domain narrowing (parser-validated field; preceding PROOF documents the bit-width invariant).")]
    if source_locations_end > buf.len() as u64 {
        return Ok(None);
    }

    // Lexical data: from source_locations_end to
    // data_start + debug_data_size (the total data blob size per
    // header). Clamp to buf.len() defensively if the header's
    // debug_data_size claims more than the buffer holds.
    let Some(data_total_end) = data_start.checked_add(u64::from(header.debug_data_size)) else {
        return Ok(None);
    };
    #[allow(clippy::as_conversions, reason = "Spec-bounded value-domain narrowing (parser-validated field; preceding PROOF documents the bit-width invariant).")]
    let lexical_data_end = data_total_end.min(buf.len() as u64);
    // PROOF: at this point `header.lexical_data_offset <=
    // header.debug_data_size` (early-rejected above), so
    // `source_locations_end = data_start + lexical_data_offset` and
    // `data_total_end = data_start + debug_data_size` give
    // `source_locations_end <= data_total_end`. Together with
    // `lexical_data_end = min(data_total_end, buf.len())`, either
    // `source_locations_end <= buf.len()` (checked above) or
    // `source_locations_end <= data_total_end`, so this `saturating_sub`
    // never actually saturates in-spec; saturation would only fire on
    // a `lexical_data_end < source_locations_end` shape that the
    // early-reject prevents. Kept as `saturating_sub` for defense in
    // depth.
    let lexical_data_size = lexical_data_end.saturating_sub(source_locations_end);

    // All ranges confirmed in-bounds; safe to cast back to usize.
    #[allow(clippy::as_conversions, reason = "Spec-bounded value-domain narrowing (parser-validated field; preceding PROOF documents the bit-width invariant).")]
    let out = DebugInfoV96 {
        header,
        file_region_table: (
            file_region_table_start as usize,
            file_region_table_size as usize,
        ),
        filename_storage: (
            filename_storage_start as usize,
            u64::from(header.filename_storage_size) as usize,
        ),
        source_locations_data: (
            data_start as usize,
            u64::from(header.lexical_data_offset) as usize,
        ),
        lexical_data: (source_locations_end as usize, lexical_data_size as usize),
    };
    Ok(Some(out))
}

#[cfg(test)]
mod source_locations_resync_tests {
    use super::*;

    /// Encode `v: i32` as sleb128 and append to `out`. Mirrors the
    /// canonical algorithm; safe for the test-input shapes we use
    /// (small magnitudes that fit in ≤5 bytes).
    fn write_sleb128_to(out: &mut Vec<u8>, mut v: i64) {
        loop {
            let byte = (v as u8) & 0x7f;
            let high_bit = byte & 0x40;
            v >>= 7;
            let done = (v == 0 && high_bit == 0) || (v == -1 && high_bit != 0);
            if done {
                out.push(byte);
                return;
            }
            out.push(byte | 0x80);
        }
    }

    /// Build a source-locations stream with a single function whose
    /// per-PC entry ends mid-`column_delta` (the third varint of an
    /// entry). Without the outer-loop break, the loop resyncs into the
    /// partial `column_delta` byte and produces a phantom
    /// `FunctionSourceInfo { function_index: 0, .. }`. With it, the
    /// outer loop stops; the single in-progress entry is preserved
    /// with `corrupt = true`.
    #[test]
    fn truncated_per_pc_entry_does_not_produce_phantom_function() {
        // function_index = 1; start_line = 1; start_column = 1.
        // Inner per-PC: address_delta = 1, line_delta_raw = 0, then
        // truncate before column_delta. The negative-address
        // terminator is OMITTED — the stream ends mid-entry.
        let mut buf = Vec::new();
        write_sleb128_to(&mut buf, 1); // function_index
        write_sleb128_to(&mut buf, 1); // start_line
        write_sleb128_to(&mut buf, 1); // start_column
        write_sleb128_to(&mut buf, 1); // address_delta
        write_sleb128_to(&mut buf, 0); // line_delta_raw — then EOF.

        let out = decode_source_locations(&buf, 90).expect("non-empty input");
        assert_eq!(out.len(), 1, "exactly the in-progress function is recorded");
        assert!(
            out[0].corrupt,
            "mid-entry EOF must flag the in-progress function as corrupt"
        );
        assert_eq!(
            out[0].function_index, 1,
            "function_index from the well-formed header is preserved"
        );
    }

    /// Build a stream where the inner break is followed by bytes that
    /// WOULD parse as a new function_index — the resync-corruption
    /// shape under test. The trailing junk byte after the truncated
    /// entry is a positive sleb128 that would resync to
    /// function_index=0 on the outer loop's next iteration.
    /// Belt-and-suspenders: a buffer where the truncation point is
    /// followed by extra bytes that could (in principle) be parsed as
    /// a new function header. With this concrete byte shape, the
    /// trailing 0x00 byte happens to be consumed as `column_delta` of
    /// the same partial entry — so no phantom is produced. The test
    /// still has value: it pins the `corrupt = true` flag on the
    /// in-progress entry AND verifies the structural `if corrupt
    /// { break }` is
    /// reached (otherwise a future refactor that introduces a real
    /// phantom-shape vulnerability would not regress this test). The
    /// `outer loop must NOT resync` invariant is enforced
    /// structurally by the outer-loop break, not by this test's exact
    /// byte sequence.
    #[test]
    fn truncated_entry_with_trailing_byte_flags_corrupt() {
        let mut buf = Vec::new();
        write_sleb128_to(&mut buf, 5); // function_index
        write_sleb128_to(&mut buf, 1); // start_line
        write_sleb128_to(&mut buf, 1); // start_column
        write_sleb128_to(&mut buf, 1); // address_delta
        write_sleb128_to(&mut buf, 0); // line_delta_raw
        // The trailing 0x00 is single-byte sleb128 for 0. It is
        // consumed by the column_delta read of the same inner
        // iteration (not by a fresh outer-loop function_index read), so
        // this shape does NOT produce a 2-entry result. The next inner
        // iter then hits EOF on the second address_delta; the inner-
        // break sets `corrupt = true` and the outer loop terminates
        // without attempting any further read.
        buf.push(0x00);

        let out = decode_source_locations(&buf, 90).expect("non-empty input");
        assert_eq!(
            out.len(),
            1,
            "exactly the in-progress function is recorded; out.len() = {}",
            out.len()
        );
        assert_eq!(out[0].function_index, 5, "real function preserved");
        assert!(out[0].corrupt, "in-progress entry flagged corrupt");
    }

    /// Negative `address_delta` is a SPEC convention that terminates
    /// the PC stream without indicating corruption. The outer loop
    /// MUST continue to the next function in this case; `corrupt`
    /// stays false.
    #[test]
    fn negative_address_delta_is_normal_terminator_not_corruption() {
        let mut buf = Vec::new();
        // First function: index 7, one PC entry, then negative-address
        // terminator.
        write_sleb128_to(&mut buf, 7);
        write_sleb128_to(&mut buf, 1);
        write_sleb128_to(&mut buf, 1);
        write_sleb128_to(&mut buf, 1);
        write_sleb128_to(&mut buf, 0);
        write_sleb128_to(&mut buf, 0);
        write_sleb128_to(&mut buf, -1); // terminator
        // Second function: index 9, terminated immediately.
        write_sleb128_to(&mut buf, 9);
        write_sleb128_to(&mut buf, 2);
        write_sleb128_to(&mut buf, 3);
        write_sleb128_to(&mut buf, -1);

        let out = decode_source_locations(&buf, 90).expect("non-empty input");
        assert_eq!(out.len(), 2, "both functions decoded — terminator is not corruption");
        assert_eq!(out[0].function_index, 7);
        assert!(!out[0].corrupt, "clean termination must NOT set corrupt");
        assert_eq!(out[1].function_index, 9);
        assert!(!out[1].corrupt);
    }
}

#[cfg(test)]
mod debug_info_v96_parse_tests {
    //! Tests pinning the debug-info parse invariants.
    //!
    //! Invariant A: `decode_source_locations` must not mint a
    //!   `function_index = 0` phantom from a negative i32. Verified
    //!   via a negative-function-index input: the outer loop breaks
    //!   immediately, producing an empty result.
    //!
    //! Invariant B: `debug_info_v96_parse` must return
    //!   `Err(InconsistentDebugHeader { .. })` when the header's
    //!   `lexical_data_offset > debug_data_size` rather than silently
    //!   saturating `lexical_data_size` to 0.
    use super::*;
    use crate::error::HermesError;

    fn write_u32_le(out: &mut Vec<u8>, v: u32) {
        out.extend_from_slice(&v.to_le_bytes());
    }

    /// Build a buffer with a single 20-byte v96 DebugInfoHeader at
    /// offset `DBG_HDR_OFFSET = HEADER_SIZE` (the first valid offset
    /// past the file header — the parser's overlap-with-header guard
    /// rejects `debug_info_offset < HEADER_SIZE` as structurally bad).
    /// Pad preceding bytes with 0xCC so a stray prefix-read surfaces
    /// visibly. All header fields (filename_count,
    /// filename_storage_size, file_region_count) are zero — so the
    /// table/storage ranges collapse to empty and the only header
    /// fields driving the lexical-data layout are the two values
    /// under test. Returns (buf, dbg_off).
    fn synth_header(
        lexical_data_offset: u32,
        debug_data_size: u32,
        trailing_pad: usize,
    ) -> (Vec<u8>, u32) {
        #[allow(
            clippy::as_conversions,
            reason = "HEADER_SIZE is a 128-byte compile-time constant that fits in u32."
        )]
        const DBG_HDR_OFFSET: u32 = HEADER_SIZE as u32;
        let mut buf = Vec::with_capacity(DBG_HDR_OFFSET as usize + 20 + trailing_pad);
        // Leading pad so the header sits at a non-zero offset past the
        // file header (the `debug_info_offset == 0` short-circuit
        // returns Ok(None); offsets in [1, HEADER_SIZE) hit the
        // overlap-with-header guard).
        buf.extend(std::iter::repeat_n(0xCCu8, DBG_HDR_OFFSET as usize));
        write_u32_le(&mut buf, 0); // filename_count
        write_u32_le(&mut buf, 0); // filename_storage_size
        write_u32_le(&mut buf, 0); // file_region_count
        write_u32_le(&mut buf, lexical_data_offset); // dbg_off + 12
        write_u32_le(&mut buf, debug_data_size); // dbg_off + 16
        buf.extend(std::iter::repeat_n(0u8, trailing_pad));
        (buf, DBG_HDR_OFFSET)
    }

    /// Invariant B happy path: `lexical_data_offset <= debug_data_size`
    /// produces `Ok(Some(_))` with a sane lexical_data range.
    #[test]
    fn debug_info_v96_parse_consistent_header_returns_ok_some() {
        // lexical_data_offset = 16, debug_data_size = 32 (within spec).
        // 64 trailing bytes ensure the post-header data region fits
        // (need 4-byte filename_storage prefix + 32 bytes of debug data).
        let (buf, dbg_off) = synth_header(16, 32, 64);
        let out = debug_info_v96_parse(&buf, dbg_off, 96)
            .expect("consistent header parses without error")
            .expect("consistent header is not absent-or-OOB");
        assert_eq!(out.header.lexical_data_offset, 16);
        assert_eq!(out.header.debug_data_size, 32);
        assert_eq!(out.lexical_data.1, 16, "lexical_data_size = 32 - 16 = 16");
    }

    /// Invariant B: `lexical_data_offset > debug_data_size` triggers
    /// the typed-Err rejection. The variant surfaces so downstream
    /// consumers / fuzz harnesses can assert on the precise failure
    /// rather than seeing a silent zero-size lexical region.
    #[test]
    fn debug_info_v96_parse_inconsistent_header_returns_typed_err() {
        // lexical_data_offset = 64 > debug_data_size = 32: spec
        // violation. 256 trailing bytes so OOB does not fire first.
        let (buf, dbg_off) = synth_header(64, 32, 256);
        let err = debug_info_v96_parse(&buf, dbg_off, 96)
            .expect_err("inconsistent header must return typed Err");
        match err {
            HermesError::InconsistentDebugHeader {
                lexical_data_offset,
                debug_data_size,
            } => {
                assert_eq!(lexical_data_offset, 64);
                assert_eq!(debug_data_size, 32);
            }
            other => panic!("expected InconsistentDebugHeader, got {other:?}"),
        }
    }

    /// Invariant B edge case: `lexical_data_offset == debug_data_size`
    /// stays within spec (lexical-data region is empty, but the header
    /// is consistent). Must NOT trigger the Err.
    #[test]
    fn debug_info_v96_parse_equal_offset_and_size_is_consistent() {
        let (buf, dbg_off) = synth_header(16, 16, 64);
        let out = debug_info_v96_parse(&buf, dbg_off, 96)
            .expect("equal offset/size is in spec")
            .expect("not OOB");
        assert_eq!(out.lexical_data.1, 0, "lexical_data_size = 16 - 16 = 0");
    }

    /// v99 hermesc emits lexical_data_offset = 31 with debug_data_size = 0
    /// (no actual debug data). Must return Ok(None), not InconsistentDebugHeader.
    #[test]
    fn debug_info_v96_parse_zero_data_size_nonzero_offset_returns_ok_none() {
        // Matches the exact field values from v99 hermesc without -g:
        // lexical_data_offset = 31, debug_data_size = 0.
        let (buf, dbg_off) = synth_header(31, 0, 64);
        assert!(
            matches!(debug_info_v96_parse(&buf, dbg_off, 99), Ok(None)),
            "debug_data_size = 0 must return Ok(None) regardless of lexical_data_offset"
        );
    }

    /// Invariant B absent-case: `debug_info_offset == 0` returns
    /// `Ok(None)` (no debug info section), not Err.
    #[test]
    fn debug_info_v96_parse_zero_offset_returns_ok_none() {
        let buf = vec![0u8; 128];
        assert!(matches!(debug_info_v96_parse(&buf, 0, 96), Ok(None)));
    }

    /// Overlap-with-header guard: `debug_info_offset` in
    /// `[1, HEADER_SIZE)` collapses to `Ok(None)` rather than reading
    /// the 20-byte DebugInfoHeader out of the file header's bytes.
    /// See `STRUCTURAL INVARIANT` comment in `debug_info_v96_parse`.
    #[test]
    fn debug_info_v96_parse_overlap_with_header_returns_ok_none() {
        // 256-byte buffer so any offset in [1, 128) would be in-bounds
        // for the 20-byte header read if the structural guard were not
        // present. Filling with 0xCC ensures the bytes a stray read
        // would sample are clearly noise (not zeros that could
        // coincidentally look "consistent").
        let buf = vec![0xCCu8; 256];
        for off in [1u32, 20, 32, 92, 108, 127] {
            assert!(
                matches!(debug_info_v96_parse(&buf, off, 96), Ok(None)),
                "debug_info_offset={off} (overlap with file header) must return Ok(None)"
            );
        }
    }

    /// Invariant A: `decode_source_locations` with a leading negative
    /// `function_index` (sleb128 = -1) must produce an empty result.
    /// The pattern is `if let Ok(v) = u32::try_from(...) { v } else
    /// { break }` — invariant is local to the call site and cannot
    /// mint a phantom function_index = 0.
    #[test]
    fn decode_source_locations_negative_function_index_yields_none() {
        // Single byte sleb128 = -1 (0x7f). function_index_i32 < 0
        // immediately, outer loop must break before producing any
        // function entry.
        let buf = vec![0x7f];
        let out = decode_source_locations(&buf, 90);
        // The function returns `None` if `functions.is_empty()` per
        // the final check at function end.
        assert!(out.is_none(), "negative function_index produces no output");
    }
}
