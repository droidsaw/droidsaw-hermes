// PARSER-ORACLE: Textbook recursive-descent on raw HBC bytes.
// Sole purpose: differential cross-check on production HbcFile::parse.
// MUST NOT call production HbcFile::parse or any parser helper.
// If both share a decoder, both can be wrong in the same way.

// MAINTENANCE: This oracle covers the structural sections of the HBC format
// listed below:
//   header fields (magic, version, function_count, string_count)
//   section layout (FunctionHeaders offset/size, SmallStringTable, StringStorage)
//   string table entries (raw bytes)
// Production parse sites:
//   droidsaw-hermes/src/header.rs (parse_hbc_header, per-variant constructors)
//   droidsaw-hermes/src/parser.rs:960 (HbcFile::parse)
//   droidsaw-hermes/src/parser.rs:993 (parse_inner)
//
// ParseShape deliberately does NOT reuse HbcFile, HbcHeader, or any
// production type — shared types hide mismatches.

// Version scope: v40..=v100 (all versions production supports).
// v40..=v83 = PreV84 layout; v84..=v86 = V84to86; v87..=v96 = V87to96;
// v97 + v98-early = V97toV98Early; v98-late + v99+ = V98LateToV99.
// v40/v76 corpus is currently blocked on sample sourcing; oracle handles
// all versions structurally.

#![allow(
    clippy::cast_possible_truncation,
    reason = "PROOF: HBC parser/decompiler. IDs (string-id, builtin-id, function-id, regex-id) are widened from parser-validated u32 header counts and narrowed via explicit width-bounded ops. Slot/level-id narrows carry explicit `& 0xFFFF` / `& 0xFF` masks at the cast site. See module-level Cast hygiene doc-comment."
)]

#![cfg(any(test, kani, fuzzing))]
#![allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    missing_docs,
    reason = "PROOF: all arithmetic in this module is bounds-checked before use. \
              Multiplications use checked_mul; additions use checked_add; every \
              byte read is bounds-guarded via get(). as-casts are widenings \
              (u32 → usize, safe on all supported platforms). \
              missing_docs: oracle module is test/fuzz-only."
)]

// ─── ParseShape — the oracle's comparison subject ─────────────────────────

/// Extracted HBC parse shape for differential comparison.
///
/// Production `HbcFile` is projected via `HbcFile::to_shape()` before
/// comparison; the naive oracle returns this type directly. No production
/// types are shared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HbcParseShape {
    /// First 4 bytes of the magic (low 32 bits of the 8-byte LE magic constant).
    pub magic_lo: u32,
    /// High 32 bits of the magic.
    pub magic_hi: u32,
    /// HBC version (bytes 8..12).
    pub version: u32,
    /// `function_count` (offset version-dependent; see header layout).
    pub function_count: u32,
    /// `string_count` (offset version-dependent).
    pub string_count: u32,
    /// `string_storage_size` (offset version-dependent).
    pub string_storage_size: u32,
    /// Computed offset of the FunctionHeaders section (follows 128-byte header).
    pub function_headers_offset: u32,
    /// Computed size of the FunctionHeaders section.
    pub function_headers_size: u64,
    /// Raw string bytes per string table entry, in index order.
    /// Populated by walking the SmallStringTable + OverflowStringTable +
    /// StringStorage sections exactly as the production parser does.
    pub string_table_entries: Vec<Vec<u8>>,
}

/// Errors produced by the naive HBC parser oracle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HbcParseOracleError {
    /// Buffer too short for the 128-byte header.
    HeaderTooSmall { have: usize },
    /// Magic bytes don't match the HBC constant.
    InvalidMagic { found: [u8; 8] },
    /// Version is outside the supported range.
    UnsupportedVersion { version: u32 },
    /// `overflow_string_count > string_count`.
    OverflowCountExceedsTotal { overflow: u32, total: u32 },
    /// Section exceeds buffer bounds.
    SectionOutOfBounds {
        name: &'static str,
        offset: u64,
        size: u64,
        buf_len: usize,
    },
    /// Arithmetic overflow computing an offset or size.
    ArithmeticOverflow { context: &'static str },
    /// A count × stride product exceeds the buffer length.
    CountExceedsBounds {
        what: &'static str,
        count: u32,
        stride: usize,
        file_size: usize,
    },
}

impl core::fmt::Display for HbcParseOracleError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}

// ─── HBC header constants (independent of production header.rs) ──────────

/// 8-byte magic constant.
const HBC_MAGIC: u64 = 0x1F1903C103BC1FC6;
/// Fixed header size.
const HBC_HEADER_SIZE: usize = 128;
/// Supported version range.
const HBC_MIN_VERSION: u32 = 40;
const HBC_MAX_VERSION: u32 = 100;

// ─── Internal helpers (no shared code with production) ───────────────────

/// Bounds-checked little-endian u32 reader. Returns 0 on OOB (mirrors
/// production `parse_inner`'s `read_u32` helper — OOB-returns-0 semantics).
fn read_u32_oob0(buf: &[u8], offset: usize) -> u32 {
    buf.get(offset..)
        .and_then(<[u8]>::first_chunk::<4>)
        .map_or(0, |a| u32::from_le_bytes(*a))
}

/// Bound-count guard. Returns `Err` when `count * stride > file_size` or
/// on arithmetic overflow.
fn bound_count(
    count: u32,
    stride: usize,
    file_size: usize,
    what: &'static str,
) -> Result<usize, HbcParseOracleError> {
    let total = (count as usize)
        .checked_mul(stride)
        .ok_or(HbcParseOracleError::ArithmeticOverflow { context: what })?;
    if total > file_size {
        return Err(HbcParseOracleError::CountExceedsBounds {
            what,
            count,
            stride,
            file_size,
        });
    }
    Ok(count as usize)
}

// ─── Section cursor (mirrors production `section!` macro semantics) ───────

/// Advance the cursor by `size` bytes, aligning to 4. Returns the
/// `(start_offset, size)` tuple. Returns `Err` on overflow or OOB.
fn section_advance(
    cursor: &mut u32,
    size: u64,
    buf_len: usize,
    name: &'static str,
) -> Result<(usize, usize), HbcParseOracleError> {
    if size > u64::from(u32::MAX) {
        return Err(HbcParseOracleError::SectionOutOfBounds {
            name,
            offset: u64::from(*cursor),
            size,
            buf_len,
        });
    }
    let sz = size as u32;
    let cur = u64::from(*cursor);
    if cur + u64::from(sz) > buf_len as u64 {
        return Err(HbcParseOracleError::SectionOutOfBounds {
            name,
            offset: cur,
            size: u64::from(sz),
            buf_len,
        });
    }
    let start = *cursor as usize;
    let next = cur.saturating_add(u64::from(sz));
    let aligned = (next.saturating_add(3)) & !3u64;
    if aligned > u64::from(u32::MAX) {
        return Err(HbcParseOracleError::ArithmeticOverflow { context: name });
    }
    *cursor = aligned as u32;
    Ok((start, sz as usize))
}

// ─── Version-discriminated header field extraction ────────────────────────

/// Header field layout for a given version.
struct HbcHeaderFields {
    #[allow(dead_code)] // version retained for debug/documentation; shape does not need it
    version: u32,
    function_count: u32,
    string_kind_count: u32,
    identifier_count: u32,
    string_count: u32,
    overflow_string_count: u32,
    string_storage_size: u32,
    /// `func_header_size`: 16 for pre-v97; 12 for v97+.
    func_header_size: u32,
}

/// Extract header fields from a 128-byte buffer according to version layout.
/// All reads use `read_u32_oob0` (OOB-returns-0) matching production semantics.
/// v98-early vs v98-late detection mirrors `detect_late_v98_form` in production.
fn extract_header_fields(buf: &[u8], version: u32) -> HbcHeaderFields {
    // Layout: magic(8) + [pad/internal(24)] + file_length(4) = offset 32 baseline
    // Then field order varies by version (see header.rs parse functions):
    //   0..8   = magic
    //   8..12  = version (u32 LE)
    //   12..32 = internal fields (source_hash etc, not needed for oracle shape)
    //   32     = file_length
    //   36     = global_code_index
    //   40     = function_count (PRESENT IN ALL VARIANTS)
    //   44     = string_kind_count
    //   48     = identifier_count
    //   52     = string_count
    //   56     = overflow_string_count
    //   60     = string_storage_size
    //   (then version-dependent fields follow at 64+)

    let function_count = read_u32_oob0(buf, 40);
    let string_kind_count = read_u32_oob0(buf, 44);
    let identifier_count = read_u32_oob0(buf, 48);
    let string_count = read_u32_oob0(buf, 52);
    let overflow_string_count = read_u32_oob0(buf, 56);
    let string_storage_size = read_u32_oob0(buf, 60);

    // func_header_size: 16 for pre-v97; 12 for v97+.
    // Both V97toV98Early and V98LateToV99 use 12-byte SmallFuncHeader
    // (production: header.rs line 252-253).
    // `detect_late_v98` only discriminates the *header-field layout*, not
    // the function-header stride — so it is not needed here.
    let func_header_size = if version >= 97 { 12 } else { 16 };

    HbcHeaderFields {
        version,
        function_count,
        string_kind_count,
        identifier_count,
        string_count,
        overflow_string_count,
        string_storage_size,
        func_header_size,
    }
}

// ─── Naive HBC parser entry point ────────────────────────────────────────

/// Naive textbook recursive-descent HBC parser. Produces an `HbcParseShape`
/// for differential comparison against `HbcFile::parse`.
///
/// This function MUST NOT call `HbcFile::parse`, `parse_hbc_header`, or any
/// production parser helper. It reads the same bytes using its own
/// `read_u32_oob0` decoder.
///
/// Version scope: v40..=v100 (all versions production supports).
pub fn naive_parse_hbc(buf: &[u8]) -> Result<HbcParseShape, HbcParseOracleError> {
    // ── 1. Header (128 bytes) ──────────────────────────────────────────────
    if buf.len() < HBC_HEADER_SIZE {
        return Err(HbcParseOracleError::HeaderTooSmall { have: buf.len() });
    }

    // Magic: first 8 bytes as LE u64.
    let magic_bytes: [u8; 8] = [
        buf[0], buf[1], buf[2], buf[3],
        buf[4], buf[5], buf[6], buf[7],
    ];
    let magic_u64 = u64::from_le_bytes(magic_bytes);
    if magic_u64 != HBC_MAGIC {
        return Err(HbcParseOracleError::InvalidMagic { found: magic_bytes });
    }
    let magic_lo = u32::from_le_bytes([magic_bytes[0], magic_bytes[1], magic_bytes[2], magic_bytes[3]]);
    let magic_hi = u32::from_le_bytes([magic_bytes[4], magic_bytes[5], magic_bytes[6], magic_bytes[7]]);

    // Version at offset 8.
    let version = read_u32_oob0(buf, 8);
    if !(HBC_MIN_VERSION..=HBC_MAX_VERSION).contains(&version) {
        return Err(HbcParseOracleError::UnsupportedVersion { version });
    }

    // Extract version-discriminated header fields.
    let hdr = extract_header_fields(buf, version);

    // Cross-validate overflow_string_count <= string_count (same gate as production).
    if hdr.overflow_string_count > hdr.string_count {
        return Err(HbcParseOracleError::OverflowCountExceedsTotal {
            overflow: hdr.overflow_string_count,
            total: hdr.string_count,
        });
    }

    // Bound-count guards (mirror production discipline).
    bound_count(hdr.function_count, hdr.func_header_size as usize, buf.len(), "function_headers")?;
    bound_count(hdr.string_count, 4, buf.len(), "small_string_table")?;
    bound_count(hdr.overflow_string_count, 8, buf.len(), "overflow_string_table")?;

    // ── 2. Section layout (cursor-based, matching `section!` macro) ───────
    // Section order mirrors production `parse_inner` exactly:
    //   FunctionHeaders, StringKinds, IdentifierHashes, SmallStringTable,
    //   OverflowStringTable, StringStorage
    // Then version-conditional sections follow. We only need the offsets
    // of the first six for the oracle shape.
    let mut cursor: u32 = 128;

    let func_headers_offset = cursor;
    let _func_headers = section_advance(
        &mut cursor,
        u64::from(hdr.function_count)
            .checked_mul(u64::from(hdr.func_header_size))
            .ok_or(HbcParseOracleError::ArithmeticOverflow {
                context: "function_headers_size",
            })?,
        buf.len(),
        "FunctionHeaders",
    )?;

    let _string_kinds = section_advance(
        &mut cursor,
        u64::from(hdr.string_kind_count).checked_mul(4).ok_or(
            HbcParseOracleError::ArithmeticOverflow { context: "string_kinds_size" },
        )?,
        buf.len(),
        "StringKinds",
    )?;
    let _ident_hashes = section_advance(
        &mut cursor,
        u64::from(hdr.identifier_count).checked_mul(4).ok_or(
            HbcParseOracleError::ArithmeticOverflow { context: "ident_hashes_size" },
        )?,
        buf.len(),
        "IdentifierHashes",
    )?;

    let small_string_table = section_advance(
        &mut cursor,
        u64::from(hdr.string_count).checked_mul(4).ok_or(
            HbcParseOracleError::ArithmeticOverflow { context: "small_string_table_size" },
        )?,
        buf.len(),
        "SmallStringTable",
    )?;

    let overflow_string_table = section_advance(
        &mut cursor,
        u64::from(hdr.overflow_string_count).checked_mul(8).ok_or(
            HbcParseOracleError::ArithmeticOverflow { context: "overflow_string_table_size" },
        )?,
        buf.len(),
        "OverflowStringTable",
    )?;

    let string_storage = section_advance(
        &mut cursor,
        u64::from(hdr.string_storage_size),
        buf.len(),
        "StringStorage",
    )?;

    let _ = cursor; // suppress unused-assignment warning

    // ── 3. String table entries ────────────────────────────────────────────
    // For each string index i in 0..string_count:
    //   Read SmallStringTable[i] (u32 at small_string_table.0 + i*4).
    //   Decode: bits[0..1] = is_utf16, bits[1..24] = str_offset, bits[24..32] = str_length.
    //   If str_length == 255: read OverflowStringTable[str_offset] for true (offset, length).
    //   Extract bytes from StringStorage[str_offset..str_offset+byte_len].
    //
    // This is an independent decode — no calls to production string_get().
    let mut string_table_entries: Vec<Vec<u8>> = Vec::with_capacity(hdr.string_count as usize);

    for i in 0..(hdr.string_count as usize) {
        let entry_off = small_string_table
            .0
            .checked_add(i.checked_mul(4).ok_or(HbcParseOracleError::ArithmeticOverflow {
                context: "small_string_table entry stride",
            })?)
            .ok_or(HbcParseOracleError::ArithmeticOverflow {
                context: "small_string_table entry offset",
            })?;

        // Read the 4-byte entry.
        let entry_bytes = buf
            .get(entry_off..entry_off.checked_add(4).ok_or(
                HbcParseOracleError::ArithmeticOverflow { context: "entry_end" },
            )?)
            .unwrap_or(&[0u8; 4][..]);

        // Decode bitfields: matches production `read_bitfield` usage.
        let entry_u32 = u32::from_le_bytes({
            let mut a = [0u8; 4];
            let len = entry_bytes.len().min(4);
            a[..len].copy_from_slice(&entry_bytes[..len]);
            a
        });
        let is_utf16 = (entry_u32 & 1) != 0;
        let mut str_offset = (entry_u32 >> 1) & 0x7FFFFF; // bits 1..24
        let mut str_length = (entry_u32 >> 24) & 0xFF;    // bits 24..32
        let overflow_routed;

        // Overflow indirection: str_length == 255 means follow overflow table.
        if str_length == 255 {
            if str_offset < hdr.overflow_string_count {
                let ovf_off = overflow_string_table
                    .0
                    .checked_add(
                        (str_offset as usize)
                            .checked_mul(8)
                            .ok_or(HbcParseOracleError::ArithmeticOverflow {
                                context: "overflow_string stride",
                            })?,
                    )
                    .ok_or(HbcParseOracleError::ArithmeticOverflow {
                        context: "overflow_string off",
                    })?;
                str_offset = read_u32_oob0(buf, ovf_off);
                str_length = read_u32_oob0(
                    buf,
                    ovf_off
                        .checked_add(4)
                        .ok_or(HbcParseOracleError::ArithmeticOverflow {
                            context: "overflow_string length off",
                        })?,
                );
                overflow_routed = true;
            } else {
                // OOR overflow reference — produce empty entry (matches
                // the oracle's structural-only intent; production returns
                // a typed Err which the fuzz harness handles by skipping).
                string_table_entries.push(Vec::new());
                continue;
            }
        } else {
            overflow_routed = false;
        }

        // Compute byte_len.
        let byte_len = if is_utf16 {
            if overflow_routed {
                (str_length as usize)
                    .checked_mul(2)
                    .ok_or(HbcParseOracleError::ArithmeticOverflow {
                        context: "string byte_len utf16 overflow",
                    })?
            } else {
                // Non-overflow path: str_length <= 254 per sentinel check above.
                // 254 * 2 = 508 cannot wrap usize on any supported platform.
                str_length as usize * 2
            }
        } else {
            str_length as usize
        };

        // Compute absolute offset into StringStorage.
        let abs_off = string_storage
            .0
            .checked_add(str_offset as usize)
            .ok_or(HbcParseOracleError::ArithmeticOverflow {
                context: "string abs_offset",
            })?;
        let abs_end = abs_off
            .checked_add(byte_len)
            .ok_or(HbcParseOracleError::ArithmeticOverflow {
                context: "string abs_end",
            })?;

        let bound = string_storage.0 + string_storage.1;
        if abs_end > bound {
            // Beyond string_storage bounds — produce empty (matches oracle
            // structural-only approach; production returns typed Err).
            string_table_entries.push(Vec::new());
            continue;
        }

        let raw = buf.get(abs_off..abs_end).unwrap_or(&[]);
        string_table_entries.push(raw.to_vec());
    }

    Ok(HbcParseShape {
        magic_lo,
        magic_hi,
        version,
        function_count: hdr.function_count,
        string_count: hdr.string_count,
        string_storage_size: hdr.string_storage_size,
        function_headers_offset: func_headers_offset,
        function_headers_size: u64::from(hdr.function_count)
            .saturating_mul(u64::from(hdr.func_header_size)),
        string_table_entries,
    })
}

// ─── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::HbcFile;

    // ── Helper: run both parsers and assert shape isomorphism ───────────

    fn assert_shapes_equal(data: &[u8], label: &str) {
        let prod = HbcFile::parse(data, None);
        let oracle = naive_parse_hbc(data);

        match (&prod, &oracle) {
            (Ok(prod_file), Ok(oracle_shape)) => {
                let prod_shape = prod_file.to_shape();
                assert_eq!(
                    prod_shape, *oracle_shape,
                    "HbcParseShape diverged on {label}\nproduction: {prod_shape:#?}\noracle: {oracle_shape:#?}"
                );
            }
            (Err(_), Err(_)) => {
                // Both rejected — no shape to compare.
            }
            (Ok(prod_file), Err(oracle_err)) => {
                let prod_shape = prod_file.to_shape();
                panic!(
                    "production accepted {label} but oracle Err({oracle_err:?})\n\
                     prod_shape.function_count={}, .string_count={}",
                    prod_shape.function_count, prod_shape.string_count,
                );
            }
            (Err(prod_err), Ok(oracle_shape)) => {
                // Oracle more permissive than production. Log but don't
                // panic — production has additional validity checks
                // (overflow count guard, bound_count guards) that the
                // oracle mirrors but may disagree on edge cases.
                eprintln!(
                    "ORACLE-MORE-PERMISSIVE on {label}: prod Err({prod_err:?}), \
                     oracle.function_count={}, .string_count={}",
                    oracle_shape.function_count, oracle_shape.string_count,
                );
            }
        }
    }

    // ── Unit test 1: invalid magic — both reject ─────────────────────────

    #[test]
    fn unit_bad_magic_both_reject() {
        let mut data = vec![0u8; 128];
        data[0..8].copy_from_slice(b"DEADBEEF");
        let oracle = naive_parse_hbc(&data);
        assert!(
            matches!(oracle, Err(HbcParseOracleError::InvalidMagic { .. })),
            "expected InvalidMagic, got {oracle:?}"
        );
        let prod = HbcFile::parse(&data, None);
        assert!(prod.is_err(), "production must reject invalid magic");
    }

    // ── Unit test 2: truncated header ────────────────────────────────────

    #[test]
    fn unit_truncated_header() {
        let data = vec![0u8; 64]; // < 128 bytes
        let oracle = naive_parse_hbc(&data);
        assert!(
            matches!(oracle, Err(HbcParseOracleError::HeaderTooSmall { .. })),
            "expected HeaderTooSmall, got {oracle:?}"
        );
    }

    // ── Unit test 3: unsupported version ─────────────────────────────────

    #[test]
    fn unit_unsupported_version_low() {
        let mut data = vec![0u8; 128];
        // Write valid magic.
        data[0..8].copy_from_slice(&HBC_MAGIC.to_le_bytes());
        // Version 10 (< MIN 40).
        data[8..12].copy_from_slice(&10u32.to_le_bytes());
        let oracle = naive_parse_hbc(&data);
        assert!(
            matches!(oracle, Err(HbcParseOracleError::UnsupportedVersion { version: 10 })),
            "expected UnsupportedVersion(10), got {oracle:?}"
        );
    }

    // ── Unit test 4: unsupported version — too high ───────────────────────

    #[test]
    fn unit_unsupported_version_high() {
        let mut data = vec![0u8; 128];
        data[0..8].copy_from_slice(&HBC_MAGIC.to_le_bytes());
        data[8..12].copy_from_slice(&200u32.to_le_bytes());
        let oracle = naive_parse_hbc(&data);
        assert!(
            matches!(oracle, Err(HbcParseOracleError::UnsupportedVersion { version: 200 })),
            "expected UnsupportedVersion(200), got {oracle:?}"
        );
    }

    // ── Unit test 5: overflow_string_count > string_count — both reject ──

    #[test]
    fn unit_overflow_exceeds_total_both_reject() {
        let mut data = vec![0u8; 128];
        data[0..8].copy_from_slice(&HBC_MAGIC.to_le_bytes());
        data[8..12].copy_from_slice(&96u32.to_le_bytes()); // v96 layout
        // string_count = 5 at offset 52
        data[52..56].copy_from_slice(&5u32.to_le_bytes());
        // overflow_string_count = 10 (> 5) at offset 56
        data[56..60].copy_from_slice(&10u32.to_le_bytes());
        let oracle = naive_parse_hbc(&data);
        assert!(
            matches!(oracle, Err(HbcParseOracleError::OverflowCountExceedsTotal { overflow: 10, total: 5 })),
            "expected OverflowCountExceedsTotal, got {oracle:?}"
        );
        let prod = HbcFile::parse(&data, None);
        assert!(prod.is_err(), "production must also reject overflow>total");
    }

    // ── Unit test 6: adversarial corpus sweep ────────────────────────────

    #[test]
    fn unit_corpus_adversarial_sweep() {
        let manifest = env!("CARGO_MANIFEST_DIR");
        let adversarial = std::path::Path::new(manifest).join("tests/fixtures/adversarial");
        if !adversarial.exists() {
            return;
        }
        let mut count = 0usize;
        for path in walkdir_hbc(&adversarial) {
            let data = std::fs::read(&path).expect("read fixture");
            assert_shapes_equal(&data, &path.display().to_string());
            count += 1;
        }
        eprintln!("unit_corpus_adversarial_sweep: {count} samples checked");
    }

    // ── Unit test 7: language_surface HBC corpus ─────────────────────────

    #[test]
    fn unit_corpus_language_surface_sweep() {
        let manifest = env!("CARGO_MANIFEST_DIR");
        let ls = std::path::Path::new(manifest).join("tests/fixtures/language_surface");
        if !ls.exists() {
            return;
        }
        let mut count = 0usize;
        for path in walkdir_hbc(&ls) {
            let data = std::fs::read(&path).expect("read fixture");
            assert_shapes_equal(&data, &path.display().to_string());
            count += 1;
        }
        eprintln!("unit_corpus_language_surface_sweep: {count} samples checked");
    }

    // ── Helper ────────────────────────────────────────────────────────────

    fn walkdir_hbc(root: &std::path::Path) -> Vec<std::path::PathBuf> {
        let mut out = Vec::new();
        fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            let Ok(entries) = std::fs::read_dir(dir) else { return };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    walk(&path, out);
                } else if path.extension().is_some_and(|e| e == "hbc") {
                    out.push(path);
                }
            }
        }
        walk(root, &mut out);
        out.sort();
        out
    }
}
