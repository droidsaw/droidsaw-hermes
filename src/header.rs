//! HBC header version-typed dispatch.
//!
//! The HBC binary header at offsets 0..128 is a version-conditional
//! state machine: which fields are present depends on the parsed
//! version. Rather than scattering `if version >= N { ... }` branches
//! through downstream consumers, this module reads the version first
//! and dispatches to a typed variant whose field set exactly matches
//! the wire format for that version.
//!
//! Layout-equivalence classes (5 variants for HBC versions 40..=99+):
//! - [`HbcHeader::PreV84`] (v40..=v83): pre-bigint, pre-`function_source_count`,
//!   `obj_value_buffer` layout, 16-byte `SmallFuncHeader`.
//! - [`HbcHeader::V84to86`] (v84..=v86): adds `function_source_count`.
//! - [`HbcHeader::V87to96`] (v87..=v96): adds `big_int_count` +
//!   `big_int_storage_size` header pair.
//! - [`HbcHeader::V97toV98Early`] (v97 + v98 early-form): swaps
//!   `obj_value_buffer_size` for `obj_shape_table_count`; switches
//!   `SmallFuncHeader` to 12 bytes.
//! - [`HbcHeader::V98LateToV99`] (v98 late-form + v99..=): adds
//!   `num_string_switch_imms` u32; `SmallFuncHeader` bitfield split
//!   widens `param_count` from 7 to 5 bits.
//!
//! v98-early vs v98-late is detected via the `BytecodeOptions` byte-peek
//! at offsets 108 and 112, with `debug_info_offset` disambiguation.
//! The `version` u32 is preserved within each variant so non-layout
//! discriminators (`has_env_idx` v99-only in source-location decoding,
//! string_kind RLE 31/1 vs 30/2 split at v72, `has_scope_env` v94..=96
//! in source-location decoding) remain expressible without re-parsing.
//!
//! Wire-format reads use the same bounds-checked, OOB-returns-0 helper
//! as `parser::read_u32` to preserve byte-identical behavior on
//! truncated and adversarial inputs.

use crate::error::HermesError;

/// HBC magic constant — 8-byte little-endian preamble identifying the file.
pub const HBC_MAGIC: u64 = 0x1F1903C103BC1FC6;

/// Total fixed-size HBC header (the first 128 bytes of every HBC file).
pub const HEADER_SIZE: usize = 128;

/// Smallest HBC bytecode version this build will accept at parse time.
/// Versions below this are rejected fail-closed by [`parse_hbc_header`]
/// with [`HermesError::UnsupportedVersion`] before any layout-dependent
/// parsing begins. Set to **40** — the earliest version for which the
/// crate carries opcode + schema + string-id + func-id tables
/// (`opcodes.rs` / `decompile/schemas.rs`).
pub const MIN_SUPPORTED_VERSION: u32 = 40;

/// Largest HBC bytecode version this build will accept at parse time.
/// Versions above this are rejected fail-closed by [`parse_hbc_header`]
/// with [`HermesError::UnsupportedVersion`] before any layout-dependent
/// parsing begins. Set to **100** — the latest version for which the
/// crate carries opcode + schema + string-id + func-id tables
/// (`opcodes.rs` / `decompile/schemas.rs`). The synthetic internal
/// value `V98_LATE = 9801` is a parser-internal discriminator (not a
/// real on-disk header version) and is therefore excluded from the
/// user-facing range exposed via the error variant.
pub const MAX_SUPPORTED_VERSION: u32 = 100;

/// `BytecodeOptions` byte position when v98 is in early-form layout.
const BYTECODE_OPTIONS_EARLY: usize = 108;

/// `BytecodeOptions` byte position when v98 is in late-form layout.
const BYTECODE_OPTIONS_LATE: usize = 112;

/// Mask of bits that must be zero for a `BytecodeOptions` byte to be
/// considered valid (upstream Hermes encodes only the low 3 bits).
const BYTECODE_OPTIONS_VALID_MASK: u8 = 0xF8;

/// Bounds-checked little-endian u32 reader; returns 0 on OOB. Matches
/// the semantics of `parser::read_u32` exactly so the new typed parse
/// path produces byte-identical output to the existing imperative one.
fn read_u32_le(buf: &[u8], offset: usize) -> u32 {
    buf.get(offset..)
        .and_then(<[u8]>::first_chunk::<4>)
        .map_or(0, |a| u32::from_le_bytes(*a))
}

/// HBC v40..=v83 header layout. No bigint pair, no
/// `function_source_count`, `obj_value_buffer_size` (not
/// `obj_shape_table_count`), 16-byte `SmallFuncHeader`.
#[derive(Debug, Clone)]
#[allow(missing_docs, reason = "wire-format field roles documented at module + variant level")]
pub struct PreV84Header {
    pub version: u32,
    pub file_length: u32,
    pub global_code_index: u32,
    pub function_count: u32,
    pub string_kind_count: u32,
    pub identifier_count: u32,
    pub string_count: u32,
    pub overflow_string_count: u32,
    pub string_storage_size: u32,
    pub reg_exp_count: u32,
    pub reg_exp_storage_size: u32,
    pub array_buffer_size: u32,
    pub obj_key_buffer_size: u32,
    pub obj_value_buffer_size: u32,
    pub segment_id: u32,
    pub cjs_module_count: u32,
    pub debug_info_offset: u32,
}

/// HBC v84..=v86 header layout. Adds `function_source_count` after
/// `cjs_module_count`; otherwise identical to [`PreV84Header`].
#[derive(Debug, Clone)]
#[allow(missing_docs, reason = "wire-format field roles documented at module + variant level")]
pub struct V84to86Header {
    pub version: u32,
    pub file_length: u32,
    pub global_code_index: u32,
    pub function_count: u32,
    pub string_kind_count: u32,
    pub identifier_count: u32,
    pub string_count: u32,
    pub overflow_string_count: u32,
    pub string_storage_size: u32,
    pub reg_exp_count: u32,
    pub reg_exp_storage_size: u32,
    pub array_buffer_size: u32,
    pub obj_key_buffer_size: u32,
    pub obj_value_buffer_size: u32,
    pub segment_id: u32,
    pub cjs_module_count: u32,
    pub function_source_count: u32,
    pub debug_info_offset: u32,
}

/// HBC v87..=v96 header layout. Adds `big_int_count` +
/// `big_int_storage_size` after `string_storage_size`.
#[derive(Debug, Clone)]
#[allow(missing_docs, reason = "wire-format field roles documented at module + variant level")]
pub struct V87to96Header {
    pub version: u32,
    pub file_length: u32,
    pub global_code_index: u32,
    pub function_count: u32,
    pub string_kind_count: u32,
    pub identifier_count: u32,
    pub string_count: u32,
    pub overflow_string_count: u32,
    pub string_storage_size: u32,
    pub big_int_count: u32,
    pub big_int_storage_size: u32,
    pub reg_exp_count: u32,
    pub reg_exp_storage_size: u32,
    pub array_buffer_size: u32,
    pub obj_key_buffer_size: u32,
    pub obj_value_buffer_size: u32,
    pub segment_id: u32,
    pub cjs_module_count: u32,
    pub function_source_count: u32,
    pub debug_info_offset: u32,
}

/// HBC v97 + v98 early-form header layout. Replaces
/// `obj_value_buffer_size` with `obj_shape_table_count`; switches
/// `SmallFuncHeader` from 16 to 12 bytes (consumed downstream via
/// [`HbcHeader::func_header_size`]).
#[derive(Debug, Clone)]
#[allow(missing_docs, reason = "wire-format field roles documented at module + variant level")]
pub struct V97toV98EarlyHeader {
    pub version: u32,
    pub file_length: u32,
    pub global_code_index: u32,
    pub function_count: u32,
    pub string_kind_count: u32,
    pub identifier_count: u32,
    pub string_count: u32,
    pub overflow_string_count: u32,
    pub string_storage_size: u32,
    pub big_int_count: u32,
    pub big_int_storage_size: u32,
    pub reg_exp_count: u32,
    pub reg_exp_storage_size: u32,
    pub array_buffer_size: u32,
    pub obj_key_buffer_size: u32,
    pub obj_shape_table_count: u32,
    pub segment_id: u32,
    pub cjs_module_count: u32,
    pub function_source_count: u32,
    pub debug_info_offset: u32,
}

/// HBC v98 late-form + v99+ header layout. Adds
/// `num_string_switch_imms` u32 after `obj_shape_table_count`;
/// `SmallFuncHeader` bitfield split widens `param_count` from 7 to 5
/// bits, narrows `bytecode_size_in_bytes` to 14 bits, and narrows
/// `function_name` to 8 bits (consumed downstream via
/// [`HbcHeader::use_v99_func_header`]).
#[derive(Debug, Clone)]
#[allow(missing_docs, reason = "wire-format field roles documented at module + variant level")]
pub struct V98LateToV99Header {
    pub version: u32,
    pub file_length: u32,
    pub global_code_index: u32,
    pub function_count: u32,
    pub string_kind_count: u32,
    pub identifier_count: u32,
    pub string_count: u32,
    pub overflow_string_count: u32,
    pub string_storage_size: u32,
    pub big_int_count: u32,
    pub big_int_storage_size: u32,
    pub reg_exp_count: u32,
    pub reg_exp_storage_size: u32,
    pub array_buffer_size: u32,
    pub obj_key_buffer_size: u32,
    pub obj_shape_table_count: u32,
    pub num_string_switch_imms: u32,
    pub segment_id: u32,
    pub cjs_module_count: u32,
    pub function_source_count: u32,
    pub debug_info_offset: u32,
}

/// HBC header parsed into a typed variant whose field set matches the
/// wire format for the file's version. See module docs for variant
/// boundaries.
#[derive(Debug, Clone)]
pub enum HbcHeader {
    /// HBC v40..=v83.
    PreV84(PreV84Header),
    /// HBC v84..=v86.
    V84to86(V84to86Header),
    /// HBC v87..=v96.
    V87to96(V87to96Header),
    /// HBC v97 + v98 early-form.
    V97toV98Early(V97toV98EarlyHeader),
    /// HBC v98 late-form + v99+.
    V98LateToV99(V98LateToV99Header),
}

impl HbcHeader {
    /// Wire-format version tag (8..12 in every variant).
    pub fn version(&self) -> u32 {
        match self {
            HbcHeader::PreV84(h) => h.version,
            HbcHeader::V84to86(h) => h.version,
            HbcHeader::V87to96(h) => h.version,
            HbcHeader::V97toV98Early(h) => h.version,
            HbcHeader::V98LateToV99(h) => h.version,
        }
    }

    /// FunctionHeaders entry stride in bytes: 16 for pre-v97 layouts,
    /// 12 for v97+. This is layout-discriminated by the variant tag and
    /// requires no `if version >= N` branching at consumer sites.
    pub fn func_header_size(&self) -> u32 {
        match self {
            HbcHeader::PreV84(_) | HbcHeader::V84to86(_) | HbcHeader::V87to96(_) => 16,
            HbcHeader::V97toV98Early(_) | HbcHeader::V98LateToV99(_) => 12,
        }
    }

    /// True when this file uses the v99-shape `SmallFuncHeader`
    /// bitfield split (5-bit `param_count`, 8-bit `function_name`,
    /// 14-bit `bytecode_size_in_bytes`). Equivalent to "late v98 or
    /// v99+"; replaces the cached `use_v99_func_header` boolean.
    pub fn use_v99_func_header(&self) -> bool {
        matches!(self, HbcHeader::V98LateToV99(_))
    }

    /// True when this file's header carries the `num_string_switch_imms`
    /// u32 field. Same discriminant as [`Self::use_v99_func_header`]
    /// for v98+.
    pub fn has_num_string_switch_imms(&self) -> bool {
        matches!(self, HbcHeader::V98LateToV99(_))
    }

    /// `file_length` projection (declared file length, header offset
    /// 32..36; present in every variant).
    ///
    /// This is the producer's declared truth about file length; it is
    /// **not** the same as the buffer length actually handed to
    /// [`crate::parser::HbcFile::parse`]. Section bounds checks use
    /// `buf.len()`, never this field — but a mismatch between the two
    /// indicates either a truncated file or a smuggled-trailing-data
    /// shape (TARmageddon-class single-archive cross-source
    /// disagreement). The parser cross-validates the two at parse
    /// entry and emits [`crate::finding::HermesFinding::FileLengthDisagreement`]
    /// on mismatch.
    pub fn file_length(&self) -> u32 {
        match self {
            HbcHeader::PreV84(h) => h.file_length,
            HbcHeader::V84to86(h) => h.file_length,
            HbcHeader::V87to96(h) => h.file_length,
            HbcHeader::V97toV98Early(h) => h.file_length,
            HbcHeader::V98LateToV99(h) => h.file_length,
        }
    }

    /// `function_count` projection (present in every variant).
    pub fn function_count(&self) -> u32 {
        match self {
            HbcHeader::PreV84(h) => h.function_count,
            HbcHeader::V84to86(h) => h.function_count,
            HbcHeader::V87to96(h) => h.function_count,
            HbcHeader::V97toV98Early(h) => h.function_count,
            HbcHeader::V98LateToV99(h) => h.function_count,
        }
    }

    /// `string_kind_count` projection.
    pub fn string_kind_count(&self) -> u32 {
        match self {
            HbcHeader::PreV84(h) => h.string_kind_count,
            HbcHeader::V84to86(h) => h.string_kind_count,
            HbcHeader::V87to96(h) => h.string_kind_count,
            HbcHeader::V97toV98Early(h) => h.string_kind_count,
            HbcHeader::V98LateToV99(h) => h.string_kind_count,
        }
    }

    /// `identifier_count` projection.
    pub fn identifier_count(&self) -> u32 {
        match self {
            HbcHeader::PreV84(h) => h.identifier_count,
            HbcHeader::V84to86(h) => h.identifier_count,
            HbcHeader::V87to96(h) => h.identifier_count,
            HbcHeader::V97toV98Early(h) => h.identifier_count,
            HbcHeader::V98LateToV99(h) => h.identifier_count,
        }
    }

    /// `string_count` projection.
    pub fn string_count(&self) -> u32 {
        match self {
            HbcHeader::PreV84(h) => h.string_count,
            HbcHeader::V84to86(h) => h.string_count,
            HbcHeader::V87to96(h) => h.string_count,
            HbcHeader::V97toV98Early(h) => h.string_count,
            HbcHeader::V98LateToV99(h) => h.string_count,
        }
    }

    /// `overflow_string_count` projection.
    pub fn overflow_string_count(&self) -> u32 {
        match self {
            HbcHeader::PreV84(h) => h.overflow_string_count,
            HbcHeader::V84to86(h) => h.overflow_string_count,
            HbcHeader::V87to96(h) => h.overflow_string_count,
            HbcHeader::V97toV98Early(h) => h.overflow_string_count,
            HbcHeader::V98LateToV99(h) => h.overflow_string_count,
        }
    }

    /// `string_storage_size` projection.
    pub fn string_storage_size(&self) -> u32 {
        match self {
            HbcHeader::PreV84(h) => h.string_storage_size,
            HbcHeader::V84to86(h) => h.string_storage_size,
            HbcHeader::V87to96(h) => h.string_storage_size,
            HbcHeader::V97toV98Early(h) => h.string_storage_size,
            HbcHeader::V98LateToV99(h) => h.string_storage_size,
        }
    }

    /// `reg_exp_count` projection.
    pub fn reg_exp_count(&self) -> u32 {
        match self {
            HbcHeader::PreV84(h) => h.reg_exp_count,
            HbcHeader::V84to86(h) => h.reg_exp_count,
            HbcHeader::V87to96(h) => h.reg_exp_count,
            HbcHeader::V97toV98Early(h) => h.reg_exp_count,
            HbcHeader::V98LateToV99(h) => h.reg_exp_count,
        }
    }

    /// `reg_exp_storage_size` projection.
    pub fn reg_exp_storage_size(&self) -> u32 {
        match self {
            HbcHeader::PreV84(h) => h.reg_exp_storage_size,
            HbcHeader::V84to86(h) => h.reg_exp_storage_size,
            HbcHeader::V87to96(h) => h.reg_exp_storage_size,
            HbcHeader::V97toV98Early(h) => h.reg_exp_storage_size,
            HbcHeader::V98LateToV99(h) => h.reg_exp_storage_size,
        }
    }

    /// `array_buffer_size` projection.
    pub fn array_buffer_size(&self) -> u32 {
        match self {
            HbcHeader::PreV84(h) => h.array_buffer_size,
            HbcHeader::V84to86(h) => h.array_buffer_size,
            HbcHeader::V87to96(h) => h.array_buffer_size,
            HbcHeader::V97toV98Early(h) => h.array_buffer_size,
            HbcHeader::V98LateToV99(h) => h.array_buffer_size,
        }
    }

    /// `obj_key_buffer_size` projection.
    pub fn obj_key_buffer_size(&self) -> u32 {
        match self {
            HbcHeader::PreV84(h) => h.obj_key_buffer_size,
            HbcHeader::V84to86(h) => h.obj_key_buffer_size,
            HbcHeader::V87to96(h) => h.obj_key_buffer_size,
            HbcHeader::V97toV98Early(h) => h.obj_key_buffer_size,
            HbcHeader::V98LateToV99(h) => h.obj_key_buffer_size,
        }
    }

    /// `cjs_module_count` projection.
    pub fn cjs_module_count(&self) -> u32 {
        match self {
            HbcHeader::PreV84(h) => h.cjs_module_count,
            HbcHeader::V84to86(h) => h.cjs_module_count,
            HbcHeader::V87to96(h) => h.cjs_module_count,
            HbcHeader::V97toV98Early(h) => h.cjs_module_count,
            HbcHeader::V98LateToV99(h) => h.cjs_module_count,
        }
    }

    /// `debug_info_offset` projection.
    pub fn debug_info_offset(&self) -> u32 {
        match self {
            HbcHeader::PreV84(h) => h.debug_info_offset,
            HbcHeader::V84to86(h) => h.debug_info_offset,
            HbcHeader::V87to96(h) => h.debug_info_offset,
            HbcHeader::V97toV98Early(h) => h.debug_info_offset,
            HbcHeader::V98LateToV99(h) => h.debug_info_offset,
        }
    }

    /// `function_source_count`: zero for `PreV84`, the parsed value for
    /// every variant from `V84to86` onward.
    pub fn function_source_count(&self) -> u32 {
        match self {
            HbcHeader::PreV84(_) => 0,
            HbcHeader::V84to86(h) => h.function_source_count,
            HbcHeader::V87to96(h) => h.function_source_count,
            HbcHeader::V97toV98Early(h) => h.function_source_count,
            HbcHeader::V98LateToV99(h) => h.function_source_count,
        }
    }

    /// `big_int_count`: zero for variants that pre-date the bigint
    /// header pair (`PreV84`, `V84to86`); the parsed value otherwise.
    pub fn big_int_count(&self) -> u32 {
        match self {
            HbcHeader::PreV84(_) | HbcHeader::V84to86(_) => 0,
            HbcHeader::V87to96(h) => h.big_int_count,
            HbcHeader::V97toV98Early(h) => h.big_int_count,
            HbcHeader::V98LateToV99(h) => h.big_int_count,
        }
    }

    /// `big_int_storage_size`: zero pre-v87, the parsed value otherwise.
    pub fn big_int_storage_size(&self) -> u32 {
        match self {
            HbcHeader::PreV84(_) | HbcHeader::V84to86(_) => 0,
            HbcHeader::V87to96(h) => h.big_int_storage_size,
            HbcHeader::V97toV98Early(h) => h.big_int_storage_size,
            HbcHeader::V98LateToV99(h) => h.big_int_storage_size,
        }
    }

    /// `obj_value_buffer_size`: parsed for pre-v97 variants; zero for
    /// v97+ where the slot is replaced by `obj_shape_table_count`.
    pub fn obj_value_buffer_size(&self) -> u32 {
        match self {
            HbcHeader::PreV84(h) => h.obj_value_buffer_size,
            HbcHeader::V84to86(h) => h.obj_value_buffer_size,
            HbcHeader::V87to96(h) => h.obj_value_buffer_size,
            HbcHeader::V97toV98Early(_) | HbcHeader::V98LateToV99(_) => 0,
        }
    }

    /// `obj_shape_table_count`: zero for pre-v97; the parsed value for
    /// v97+ where the slot replaces `obj_value_buffer_size`.
    pub fn obj_shape_table_count(&self) -> u32 {
        match self {
            HbcHeader::PreV84(_) | HbcHeader::V84to86(_) | HbcHeader::V87to96(_) => 0,
            HbcHeader::V97toV98Early(h) => h.obj_shape_table_count,
            HbcHeader::V98LateToV99(h) => h.obj_shape_table_count,
        }
    }
}

/// Parse the 128-byte HBC header into a typed variant. Reads the
/// version field first, then dispatches to the variant constructor.
/// v98 is split into early-form and late-form via byte-peek of the
/// `BytecodeOptions` byte at offsets 108 and 112, with
/// `debug_info_offset` disambiguation when both positions look valid.
pub fn parse_hbc_header(buf: &[u8]) -> Result<HbcHeader, HermesError> {
    if buf.len() < HEADER_SIZE {
        return Err(HermesError::HeaderTooSmall { got: buf.len() });
    }
    let Some(magic_bytes) = buf.first_chunk::<8>() else {
        return Err(HermesError::HeaderTooSmall { got: buf.len() });
    };
    let magic = u64::from_le_bytes(*magic_bytes);
    if magic != HBC_MAGIC {
        return Err(HermesError::InvalidMagic {
            found: *magic_bytes,
        });
    }

    let version = read_u32_le(buf, 8);

    // Fail-closed parse-time version dispatch: reject any version outside
    // `MIN_SUPPORTED_VERSION..=MAX_SUPPORTED_VERSION` *before* any
    // layout-dependent parsing begins. Accepting an unsupported version
    // into a layout variant and deferring failure to `get_version_opcodes`
    // / `get_version_schemas` is a "parse succeeds; downstream fails late"
    // anti-pattern that violates "validate before commit".
    //
    // The two rejection arms (low + high) AND the in-range layout-
    // dispatch arms together exhaust `u32`. Folding the rejection into
    // the same match keeps the supported-set the single source of
    // truth: changing `MIN_SUPPORTED_VERSION` or `MAX_SUPPORTED_VERSION`
    // automatically widens / narrows both the accept and reject arms.
    match version {
        // Below the supported floor (default `0..=39` when
        // `MIN_SUPPORTED_VERSION == 40`).
        0..MIN_SUPPORTED_VERSION => Err(HermesError::UnsupportedVersion {
            observed: version,
            supported_min: MIN_SUPPORTED_VERSION,
            supported_max: MAX_SUPPORTED_VERSION,
        }),
        MIN_SUPPORTED_VERSION..=83 => Ok(HbcHeader::PreV84(parse_pre_v84(buf, version))),
        84..=86 => Ok(HbcHeader::V84to86(parse_v84_to_86(buf, version))),
        87..=96 => Ok(HbcHeader::V87to96(parse_v87_to_96(buf, version))),
        97 => Ok(HbcHeader::V97toV98Early(parse_v97_to_v98_early(buf, 97))),
        98 => {
            // `detect_late_v98_form` returns Err when both
            // BytecodeOptions positions fail MBZ (no honest signal);
            // propagate the typed Err. On Ok, dispatch to the
            // chosen layout.
            if detect_late_v98_form(buf)? {
                Ok(HbcHeader::V98LateToV99(parse_v98_late_to_v99(buf, 98)))
            } else {
                Ok(HbcHeader::V97toV98Early(parse_v97_to_v98_early(buf, 98)))
            }
        }
        99..=MAX_SUPPORTED_VERSION => {
            Ok(HbcHeader::V98LateToV99(parse_v98_late_to_v99(buf, version)))
        }
        // Above the supported ceiling (`(MAX_SUPPORTED_VERSION + 1)..=u32::MAX`
        // — default `101..=u32::MAX` when `MAX_SUPPORTED_VERSION == 100`).
        _ => Err(HermesError::UnsupportedVersion {
            observed: version,
            supported_min: MIN_SUPPORTED_VERSION,
            supported_max: MAX_SUPPORTED_VERSION,
        }),
    }
}

/// Detect v98 late-form layout. Returns `Ok(true)` for late-form,
/// `Ok(false)` for early-form, or `Err(AmbiguousV98Form)` when both
/// `BytecodeOptions`-byte positions fail the MBZ check (no honest
/// disambiguation signal).
///
/// **Fail-closed contract.** Under adversarial input, an attacker who
/// flips reserved bits in BOTH `BYTECODE_OPTIONS_EARLY` (108) and
/// `BYTECODE_OPTIONS_LATE` (112) defeats the heuristic; downstream
/// `SmallFuncHeader` bitfield widths differ (16 vs 12 bytes) and the
/// composed `large_off = (raw_func_name << shift) | raw_offset` uses
/// shift=16 for early and shift=24 for late. Guessing wrong silently
/// routes function bodies to attacker-chosen regions. The previous
/// implementation defaulted to early-form on that shape — the
/// adversarial-review §H-1 gauge requires fail-closed instead.
///
/// **Cross-validation.** When both positions PASS MBZ AND both
/// layouts' `debug_info_offset` projections are zero (legitimate
/// stripped-RN-bundle shape, indistinguishable from a crafted
/// pretending-to-be-stripped attack on the byte-peek heuristic
/// alone): attempt function-table footprint cross-validation.
/// Function-table base = HEADER_SIZE (128); per-entry stride is 16
/// bytes for early-form, 12 bytes for late-form. If exactly one
/// layout's footprint fits in `buf.len()`, pick that one + emit a
/// `V98FormAmbiguous` Finding for audit visibility. If both or
/// neither fit, default to early-form (preserves standard behavior on
/// the dominant stripped-bundle shape) + emit the Finding.
fn detect_late_v98_form(buf: &[u8]) -> Result<bool, HermesError> {
    let Some(opt_early) = buf.get(BYTECODE_OPTIONS_EARLY).copied() else {
        return Ok(false);
    };
    let Some(opt_late) = buf.get(BYTECODE_OPTIONS_LATE).copied() else {
        return Ok(false);
    };
    let early_valid = opt_early & BYTECODE_OPTIONS_VALID_MASK == 0;
    let late_valid = opt_late & BYTECODE_OPTIONS_VALID_MASK == 0;
    match (early_valid, late_valid) {
        (false, false) => Err(HermesError::AmbiguousV98Form {
            early: opt_early,
            late: opt_late,
        }),
        (true, false) => Ok(false),
        (false, true) => Ok(true),
        (true, true) => disambiguate_both_options_valid(buf),
    }
}

/// Both `BytecodeOptions`-byte positions passed the MBZ check.
/// Disambiguate via `debug_info_offset` projection (the
/// standard heuristic). When both projections are simultaneously
/// plausible the function returns `Ok(false)` (early) or `Ok(true)`
/// (late) per the projection that's in-bounds.
///
/// **Fail-closed escalation for the both-zero shape.** When both
/// projections are zero/OOB AND the buffer is large enough to carry
/// function bodies (`function_count > 0 && buf.len() > 128`), this
/// returns `Err(AmbiguousV98Form)` rather than defaulting to early.
/// Rationale: an attacker who zeros both `debug_info_offset` byte
/// positions defeats the byte-peek heuristic exactly as the both-MBZ-
/// invalid 0x80/0x80 entry did before C-1's parent fix — different
/// 8-byte pattern, same downstream wrong-layout primitive
/// (`large_off = (raw_func_name << shift) | raw_offset` uses
/// shift=16 vs 24). Wave 1 re-review C-1 identified this still-
/// reachable entry; this gate fails closed on the attacker shape
/// while preserving the legitimate stripped-RN fixture case
/// (`function_count == 0` OR `buf.len() <= 128`).
///
/// **No table-size cross-validation.** v97-to-v98-early and
/// v98-late-to-v99 share the same 12-byte `SmallFuncHeader` stride
/// per [`HbcHeader::func_header_size`] (`header.rs:250`); a
/// footprint check `128 + function_count * stride <= buf.len()`
/// produces identical answers for both layouts and cannot
/// disambiguate. A meaningful cross-validation would require
/// decoding a candidate function header under each layout and
/// verifying its bitfield-derived offsets are in-bounds — that
/// requires per-function bounds checks not implemented here.
pub(crate) fn disambiguate_both_options_valid(buf: &[u8]) -> Result<bool, HermesError> {
    // debug_info_offset positions: late-form at offset 108, early-form
    // at offset 104 (base 92 + 16 vs base 92 + 12).
    let base = 92usize;
    let debug_with = read_u32_le(buf, base.saturating_add(16));
    let debug_without = read_u32_le(buf, base.saturating_add(12));
    let buf_len_u32 = u32::try_from(buf.len()).unwrap_or(u32::MAX);

    // Plausibility floor: a legitimate debug_info_offset must live
    // PAST the 128-byte header. Any offset in `1..128` is structurally
    // impossible (the header itself occupies bytes 0..128) and must
    // not satisfy the "plausible" predicate.
    //
    // Without this floor, the byte at offset 108 (which in Early-v98
    // layout is the `BytecodeOptions` packed-flags byte, NOT part of
    // debug_info_offset) can satisfy `debug_with > 0` when an
    // Early-v98 file's options have any low bit set (e.g.
    // `strictMode = 1`). Combined with stripped-debug Early-v98
    // (`debug_info_offset[104..108] == 0` → `early_debug_plausible
    // = false`), the loose `> 0` check would route through the
    // `late_debug_plausible && !early_debug_plausible → Ok(true)`
    // arm, silently mis-detecting the file as Late-v98 and triggering
    // the wrong layout shifts downstream (12-byte function headers +
    // 24-bit shift instead of 16-byte + 16-bit).
    const HEADER_END: u32 = 128;
    let late_debug_plausible = debug_with >= HEADER_END && debug_with < buf_len_u32;
    let early_debug_plausible = debug_without >= HEADER_END && debug_without < buf_len_u32;
    if late_debug_plausible && !early_debug_plausible {
        return Ok(true);
    }
    if !late_debug_plausible && early_debug_plausible {
        return Ok(false);
    }

    // Both projections plausible OR both zero/OOB — no honest signal
    // to disambiguate at the byte-peek layer.
    let function_count = read_u32_le(buf, 40);
    let early_options = buf.get(BYTECODE_OPTIONS_EARLY).copied().unwrap_or(0);
    let late_options = buf.get(BYTECODE_OPTIONS_LATE).copied().unwrap_or(0);

    // C-1 escalation: an attacker who zeroed (or saturated) both debug
    // projections to defeat the heuristic gains the same wrong-layout
    // primitive as the original §H-1 attack. Fail closed on this shape.
    // The legitimate stripped-RN-bundle case is preserved by the
    // function_count == 0 guard. (buf.len() >= HEADER_SIZE is already
    // enforced by parse_hbc_header before reaching this function.)
    if function_count > 0 {
        return Err(HermesError::AmbiguousV98Form {
            early: early_options,
            late: late_options,
        });
    }

    // Genuinely-stripped / header-only / function_count == 0 case:
    // emit the Finding for audit visibility and default to early-form
    // (preserves standard behavior on stripped-RN bundles).
    crate::finding::emit_finding(crate::finding::HermesFinding::V98FormAmbiguous {
        early_options,
        late_options,
        function_count,
        debug_with,
        debug_without,
        picked_late: false,
    });
    Ok(false)
}

fn parse_pre_v84(buf: &[u8], version: u32) -> PreV84Header {
    PreV84Header {
        version,
        file_length: read_u32_le(buf, 32),
        global_code_index: read_u32_le(buf, 36),
        function_count: read_u32_le(buf, 40),
        string_kind_count: read_u32_le(buf, 44),
        identifier_count: read_u32_le(buf, 48),
        string_count: read_u32_le(buf, 52),
        overflow_string_count: read_u32_le(buf, 56),
        string_storage_size: read_u32_le(buf, 60),
        reg_exp_count: read_u32_le(buf, 64),
        reg_exp_storage_size: read_u32_le(buf, 68),
        array_buffer_size: read_u32_le(buf, 72),
        obj_key_buffer_size: read_u32_le(buf, 76),
        obj_value_buffer_size: read_u32_le(buf, 80),
        segment_id: read_u32_le(buf, 84),
        cjs_module_count: read_u32_le(buf, 88),
        debug_info_offset: read_u32_le(buf, 92),
    }
}

fn parse_v84_to_86(buf: &[u8], version: u32) -> V84to86Header {
    V84to86Header {
        version,
        file_length: read_u32_le(buf, 32),
        global_code_index: read_u32_le(buf, 36),
        function_count: read_u32_le(buf, 40),
        string_kind_count: read_u32_le(buf, 44),
        identifier_count: read_u32_le(buf, 48),
        string_count: read_u32_le(buf, 52),
        overflow_string_count: read_u32_le(buf, 56),
        string_storage_size: read_u32_le(buf, 60),
        reg_exp_count: read_u32_le(buf, 64),
        reg_exp_storage_size: read_u32_le(buf, 68),
        array_buffer_size: read_u32_le(buf, 72),
        obj_key_buffer_size: read_u32_le(buf, 76),
        obj_value_buffer_size: read_u32_le(buf, 80),
        segment_id: read_u32_le(buf, 84),
        cjs_module_count: read_u32_le(buf, 88),
        function_source_count: read_u32_le(buf, 92),
        debug_info_offset: read_u32_le(buf, 96),
    }
}

fn parse_v87_to_96(buf: &[u8], version: u32) -> V87to96Header {
    V87to96Header {
        version,
        file_length: read_u32_le(buf, 32),
        global_code_index: read_u32_le(buf, 36),
        function_count: read_u32_le(buf, 40),
        string_kind_count: read_u32_le(buf, 44),
        identifier_count: read_u32_le(buf, 48),
        string_count: read_u32_le(buf, 52),
        overflow_string_count: read_u32_le(buf, 56),
        string_storage_size: read_u32_le(buf, 60),
        big_int_count: read_u32_le(buf, 64),
        big_int_storage_size: read_u32_le(buf, 68),
        reg_exp_count: read_u32_le(buf, 72),
        reg_exp_storage_size: read_u32_le(buf, 76),
        array_buffer_size: read_u32_le(buf, 80),
        obj_key_buffer_size: read_u32_le(buf, 84),
        obj_value_buffer_size: read_u32_le(buf, 88),
        segment_id: read_u32_le(buf, 92),
        cjs_module_count: read_u32_le(buf, 96),
        function_source_count: read_u32_le(buf, 100),
        debug_info_offset: read_u32_le(buf, 104),
    }
}

fn parse_v97_to_v98_early(buf: &[u8], version: u32) -> V97toV98EarlyHeader {
    V97toV98EarlyHeader {
        version,
        file_length: read_u32_le(buf, 32),
        global_code_index: read_u32_le(buf, 36),
        function_count: read_u32_le(buf, 40),
        string_kind_count: read_u32_le(buf, 44),
        identifier_count: read_u32_le(buf, 48),
        string_count: read_u32_le(buf, 52),
        overflow_string_count: read_u32_le(buf, 56),
        string_storage_size: read_u32_le(buf, 60),
        big_int_count: read_u32_le(buf, 64),
        big_int_storage_size: read_u32_le(buf, 68),
        reg_exp_count: read_u32_le(buf, 72),
        reg_exp_storage_size: read_u32_le(buf, 76),
        array_buffer_size: read_u32_le(buf, 80),
        obj_key_buffer_size: read_u32_le(buf, 84),
        obj_shape_table_count: read_u32_le(buf, 88),
        segment_id: read_u32_le(buf, 92),
        cjs_module_count: read_u32_le(buf, 96),
        function_source_count: read_u32_le(buf, 100),
        debug_info_offset: read_u32_le(buf, 104),
    }
}

fn parse_v98_late_to_v99(buf: &[u8], version: u32) -> V98LateToV99Header {
    V98LateToV99Header {
        version,
        file_length: read_u32_le(buf, 32),
        global_code_index: read_u32_le(buf, 36),
        function_count: read_u32_le(buf, 40),
        string_kind_count: read_u32_le(buf, 44),
        identifier_count: read_u32_le(buf, 48),
        string_count: read_u32_le(buf, 52),
        overflow_string_count: read_u32_le(buf, 56),
        string_storage_size: read_u32_le(buf, 60),
        big_int_count: read_u32_le(buf, 64),
        big_int_storage_size: read_u32_le(buf, 68),
        reg_exp_count: read_u32_le(buf, 72),
        reg_exp_storage_size: read_u32_le(buf, 76),
        array_buffer_size: read_u32_le(buf, 80),
        obj_key_buffer_size: read_u32_le(buf, 84),
        obj_shape_table_count: read_u32_le(buf, 88),
        num_string_switch_imms: read_u32_le(buf, 92),
        segment_id: read_u32_le(buf, 96),
        cjs_module_count: read_u32_le(buf, 100),
        function_source_count: read_u32_le(buf, 104),
        debug_info_offset: read_u32_le(buf, 108),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_minimal_header(version: u32) -> Vec<u8> {
        let mut buf = vec![0u8; HEADER_SIZE];
        buf[0..8].copy_from_slice(&HBC_MAGIC.to_le_bytes());
        buf[8..12].copy_from_slice(&version.to_le_bytes());
        buf
    }

    #[test]
    fn rejects_truncated_header() {
        let buf = vec![0u8; 64];
        match parse_hbc_header(&buf) {
            Err(HermesError::HeaderTooSmall { got: 64 }) => {}
            other => panic!("expected HeaderTooSmall, got {other:?}"),
        }
    }

    #[test]
    fn rejects_bad_magic() {
        let mut buf = vec![0u8; HEADER_SIZE];
        buf[0..8].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE]);
        match parse_hbc_header(&buf) {
            Err(HermesError::InvalidMagic { .. }) => {}
            other => panic!("expected InvalidMagic, got {other:?}"),
        }
    }

    #[test]
    fn dispatches_pre_v84_for_v40() {
        let buf = make_minimal_header(40);
        match parse_hbc_header(&buf).unwrap() {
            HbcHeader::PreV84(h) => assert_eq!(h.version, 40),
            other => panic!("expected PreV84, got {other:?}"),
        }
    }

    #[test]
    fn dispatches_v84_to_86_for_v85() {
        let buf = make_minimal_header(85);
        match parse_hbc_header(&buf).unwrap() {
            HbcHeader::V84to86(h) => assert_eq!(h.version, 85),
            other => panic!("expected V84to86, got {other:?}"),
        }
    }

    #[test]
    fn dispatches_v87_to_96_for_v96() {
        let buf = make_minimal_header(96);
        match parse_hbc_header(&buf).unwrap() {
            HbcHeader::V87to96(h) => assert_eq!(h.version, 96),
            other => panic!("expected V87to96, got {other:?}"),
        }
    }

    #[test]
    fn dispatches_v97_to_v98_early_for_v97() {
        let buf = make_minimal_header(97);
        match parse_hbc_header(&buf).unwrap() {
            HbcHeader::V97toV98Early(h) => assert_eq!(h.version, 97),
            other => panic!("expected V97toV98Early, got {other:?}"),
        }
    }

    #[test]
    fn dispatches_v98_early_when_all_options_zero() {
        // All-zero options bytes + all-zero debug projections + zero
        // function_count: cross-validation path fires, both layouts'
        // footprints trivially fit (128 + 0 * stride ≤ buf.len()), so
        // both_fits → default to early-form per tolerant-parse
        // discipline. A `V98FormAmbiguous` Finding is also emitted to
        // surface the ambiguity in the audit channel.
        let buf = make_minimal_header(98);
        match parse_hbc_header(&buf).unwrap() {
            HbcHeader::V97toV98Early(h) => assert_eq!(h.version, 98),
            other => panic!("expected V97toV98Early (early v98), got {other:?}"),
        }
    }

    #[test]
    fn dispatches_v98_late_when_late_options_valid_only() {
        let mut buf = make_minimal_header(98);
        // Make early position invalid (high bits set) and late position valid.
        buf[BYTECODE_OPTIONS_EARLY] = 0xF8;
        buf[BYTECODE_OPTIONS_LATE] = 0x00;
        match parse_hbc_header(&buf).unwrap() {
            HbcHeader::V98LateToV99(h) => assert_eq!(h.version, 98),
            other => panic!("expected V98LateToV99 (late v98), got {other:?}"),
        }
    }

    #[test]
    fn dispatches_v98_early_when_early_options_valid_only() {
        // Early position passes MBZ, late position fails: standard
        // behavior picks early-form; with the guard it still does
        // (it has the only honest signal). The explicit `Ok(false)`
        // is returned rather than the implicit fallthrough.
        let mut buf = make_minimal_header(98);
        buf[BYTECODE_OPTIONS_EARLY] = 0x00;
        buf[BYTECODE_OPTIONS_LATE] = 0xF8;
        match parse_hbc_header(&buf).unwrap() {
            HbcHeader::V97toV98Early(h) => assert_eq!(h.version, 98),
            other => panic!("expected V97toV98Early (early v98), got {other:?}"),
        }
    }

    #[test]
    fn rejects_v98_when_both_options_invalid() {
        // Both BytecodeOptions positions have reserved bits set: without the guard
        // the heuristic would silently fall through to early-form, letting an attacker
        // who authored late-form route function bodies to attacker-chosen
        // regions via the 24-vs-16-bit `large_off` shift difference.
        // With the guard, MUST return `Err(AmbiguousV98Form)` — no honest
        // signal to disambiguate, fail closed.
        let mut buf = make_minimal_header(98);
        buf[BYTECODE_OPTIONS_EARLY] = 0x80;
        buf[BYTECODE_OPTIONS_LATE] = 0x80;
        match parse_hbc_header(&buf) {
            Err(HermesError::AmbiguousV98Form { early: 0x80, late: 0x80 }) => {}
            other => panic!(
                "expected AmbiguousV98Form on both-invalid v98 header, got {other:?}"
            ),
        }
    }

    #[test]
    fn rejects_v98_when_both_options_high_bits_max() {
        // Tighten the §H-1 gauge: every shape where both options carry
        // reserved bits must Err. Use 0xF8 (all reserved bits set) on
        // both positions.
        let mut buf = make_minimal_header(98);
        buf[BYTECODE_OPTIONS_EARLY] = 0xF8;
        buf[BYTECODE_OPTIONS_LATE] = 0xF8;
        match parse_hbc_header(&buf) {
            Err(HermesError::AmbiguousV98Form { early: 0xF8, late: 0xF8 }) => {}
            other => panic!(
                "expected AmbiguousV98Form with 0xF8/0xF8, got {other:?}"
            ),
        }
    }

    #[test]
    fn rejects_v98_when_both_options_valid_and_both_debug_zero_with_function_bodies() {
        // Companion attack: The canonical §H-1 fix (both reserved bits set)
        // closes one entry, but the equivalent semantic primitive lives on the
        // both-valid + both-debug-zero entry: attacker zeros both
        // debug_info_offset projections (8 bytes at offsets 104 + 108)
        // while leaving both options bytes clean (0x00). Without the guard: the
        // disambiguator's debug-projection heuristic returns "neither
        // plausible" → falls through to early-form. Attacker reaches the
        // same downstream wrong-layout primitive (24-vs-16-bit `large_off`
        // shift) with a different byte pattern.
        //
        // With the guard: when function_count > 0 AND buf.len() > 128
        // (attacker controls function bodies; not a header-only stripped
        // fixture), the disambiguator must Err rather than defaulting
        // to early.
        let mut buf = make_minimal_header(98);
        // Extend buffer past HEADER_SIZE so buf.len() > 128.
        buf.extend(std::iter::repeat_n(0u8, 64));
        // function_count at offset 40: set to 1.
        buf[40..44].copy_from_slice(&1u32.to_le_bytes());
        // Both options bytes valid (clean 0x00 — no reserved bits set).
        buf[BYTECODE_OPTIONS_EARLY] = 0x00;
        buf[BYTECODE_OPTIONS_LATE] = 0x00;
        // Both debug_info_offset projections zero (default-zero from
        // make_minimal_header). Explicit for clarity.
        buf[104..108].copy_from_slice(&0u32.to_le_bytes()); // early position
        buf[108..112].copy_from_slice(&0u32.to_le_bytes()); // late position
        match parse_hbc_header(&buf) {
            Err(HermesError::AmbiguousV98Form { early: 0x00, late: 0x00 }) => {}
            other => panic!(
                "expected AmbiguousV98Form on both-valid + both-debug-zero + function_count>0 + buf>128, got {other:?}"
            ),
        }
    }

    #[test]
    fn admits_v98_when_both_options_valid_and_both_debug_zero_but_no_function_bodies() {
        // Companion to the C-1 PoC: when function_count == 0, the
        // disambiguator must NOT Err — that case is the legitimate
        // stripped-RN-bundle shape and the standard tolerant-parse
        // behavior (default to early + emit Finding) is preserved.
        //
        // Threat-model rationale: an attacker who zeros function_count
        // can't carry function bodies through the parse; the layout-
        // selection asymmetry only matters when function bodies exist.
        let mut buf = make_minimal_header(98);
        // function_count = 0 (default in make_minimal_header).
        buf[BYTECODE_OPTIONS_EARLY] = 0x00;
        buf[BYTECODE_OPTIONS_LATE] = 0x00;
        match parse_hbc_header(&buf).expect("parse must succeed on stripped-RN shape") {
            HbcHeader::V97toV98Early(h) => assert_eq!(h.version, 98),
            other => panic!("expected V97toV98Early on stripped-RN shape, got {other:?}"),
        }
        // Confirm the Finding fires for audit visibility.
        let findings = crate::finding::drain_findings_for_test();
        assert!(
            findings
                .iter()
                .any(|f| matches!(f, crate::finding::HermesFinding::V98FormAmbiguous { picked_late: false, .. })),
            "stripped-RN shape must emit V98FormAmbiguous Finding for audit visibility; got {findings:?}"
        );
    }

    // No table-size cross-validation test: per `HbcHeader::func_header_size`
    // both V97toV98Early and V98LateToV99 use a 12-byte SmallFuncHeader
    // stride, so footprint-based cross-validation cannot disambiguate
    // them. Per-function bitfield-bounds validation would be needed for
    // a real cross-validation signal, but is not implemented here.

    #[test]
    fn v98_all_zero_options_emits_ambiguous_finding() {
        // Both BytecodeOptions positions pass MBZ (0x00 / 0x00); both
        // `debug_info_offset` projections are zero (header-only buffer).
        // This is the byte-peek-ambiguous shape; the disambiguator must
        // emit `V98FormAmbiguous` for audit-channel visibility AND
        // default to early-form for tolerant-parse continuity.
        let _ = crate::finding::drain_findings_for_test();
        let buf = make_minimal_header(98);
        let header = parse_hbc_header(&buf).expect("parse");
        assert!(matches!(header, HbcHeader::V97toV98Early(_)));
        let findings = crate::finding::drain_findings_for_test();
        assert!(
            findings.iter().any(|f| matches!(
                f,
                crate::finding::HermesFinding::V98FormAmbiguous { picked_late: false, .. }
            )),
            "expected V98FormAmbiguous(picked_late=false) Finding, drain returned: {:?}",
            findings
        );
    }

    #[test]
    fn dispatches_v98_late_to_v99_for_v99() {
        let buf = make_minimal_header(99);
        match parse_hbc_header(&buf).unwrap() {
            HbcHeader::V98LateToV99(h) => assert_eq!(h.version, 99),
            other => panic!("expected V98LateToV99, got {other:?}"),
        }
    }

    #[test]
    fn dispatches_v98_late_to_v99_for_v100() {
        // Forward-compat: any v >= 99 uses late layout.
        let buf = make_minimal_header(100);
        match parse_hbc_header(&buf).unwrap() {
            HbcHeader::V98LateToV99(h) => assert_eq!(h.version, 100),
            other => panic!("expected V98LateToV99, got {other:?}"),
        }
    }

    #[test]
    fn func_header_size_is_16_pre_v97_else_12() {
        for v in [40u32, 76, 84, 87, 94, 96] {
            let h = parse_hbc_header(&make_minimal_header(v)).unwrap();
            assert_eq!(h.func_header_size(), 16, "v{v}");
        }
        for v in [97u32, 98, 99, 100] {
            let h = parse_hbc_header(&make_minimal_header(v)).unwrap();
            assert_eq!(h.func_header_size(), 12, "v{v}");
        }
    }

    #[test]
    fn use_v99_func_header_only_for_late_v98_or_v99() {
        for v in [40u32, 76, 84, 87, 96, 97] {
            let h = parse_hbc_header(&make_minimal_header(v)).unwrap();
            assert!(!h.use_v99_func_header(), "v{v}");
        }
        // v98 with all-zero options → early form → false.
        let h = parse_hbc_header(&make_minimal_header(98)).unwrap();
        assert!(!h.use_v99_func_header());
        // v99 → late form → true.
        let h = parse_hbc_header(&make_minimal_header(99)).unwrap();
        assert!(h.use_v99_func_header());
    }

    // ── V98-disambiguator BytecodeOptions-overlap regression suite ────────
    //
    // Filed as `findings-hermes-v98-disambiguator-bytecodeoptions-overlap-
    // Without the guard, `disambiguate_both_options_valid`'s
    // plausibility check (`debug_with > 0`) would admit ANY non-zero u32 read
    // from offset 108 as a "plausible debug offset" — including values
    // that are just the Early-v98 BytecodeOptions byte's low bits (e.g.
    // `strictMode = 1` → debug_with = 1). This silently misclassifies
    // Early-v98 files as Late-v98. With the guard, the floor is HEADER_END = 128.

    #[test]
    fn rejects_v98_when_stripped_early_with_strict_mode_set() {
        // Adversarial shape:
        // - Early-v98 file with stripped debug (debug_info_offset[104..108] = 0)
        // - BytecodeOptions byte at 108 = 0x04 (strictMode bit set)
        // - Both raw option positions are individually "valid" (low bits)
        //   so the cross-validation path falls into disambiguate_both_options_valid
        // Without the guard: returns Ok(true) (Late-v98 mis-pick) via the loose
        // `debug_with > 0` predicate. With the guard: HEADER_END = 128 floor
        // rejects the strictMode byte as a plausible offset, both
        // projections become not-plausible, function_count > 0 fires
        // the AmbiguousV98Form escalation.
        let mut buf = make_minimal_header(98);
        // function_count > 0 triggers the C-1 escalation arm.
        buf[40..44].copy_from_slice(&1u32.to_le_bytes());
        // Both option positions valid (low bits only).
        buf[BYTECODE_OPTIONS_EARLY] = 0x04;  // strictMode bit
        buf[BYTECODE_OPTIONS_LATE] = 0x04;
        // debug_info_offset at 104..108 = 0 (stripped Early-v98).
        // debug_with at 108..112 = BytecodeOptions byte + 0 padding = 4.
        match parse_hbc_header(&buf) {
            Err(HermesError::AmbiguousV98Form { .. }) => {}
            other => panic!(
                "expected AmbiguousV98Form on stripped-Early-v98 with options-byte \
                 falsely plausible (HEADER_END=128 floor), got {other:?}"
            ),
        }
    }

    #[test]
    fn legitimate_early_with_real_debug_offset_still_dispatches_early() {
        // Regression check: a real debug offset (well past the header)
        // must still pick Early-v98. Without this, the HEADER_END = 128
        // floor could over-restrict.
        let mut buf = make_minimal_header(98);
        // Real debug offset at the early position (104), well past 128.
        buf[104..108].copy_from_slice(&512u32.to_le_bytes());
        // Late position (108) has the BytecodeOptions byte (low bits OK).
        buf[BYTECODE_OPTIONS_EARLY] = 0x00;
        buf[BYTECODE_OPTIONS_LATE] = 0x00;
        match parse_hbc_header(&buf).unwrap() {
            HbcHeader::V97toV98Early(h) => assert_eq!(h.version, 98),
            other => panic!("expected V97toV98Early with real debug offset, got {other:?}"),
        }
    }

    #[test]
    fn legitimate_late_with_real_debug_offset_still_dispatches_late() {
        // Regression check: a real debug offset at the late position
        // (108) must pick Late-v98.
        let mut buf = make_minimal_header(98);
        buf.resize(600, 0); // extend so that offset 512 is in-bounds for plausibility check
        // Real debug offset at the late position.
        buf[108..112].copy_from_slice(&512u32.to_le_bytes());
        buf[BYTECODE_OPTIONS_EARLY] = 0x00;
        buf[BYTECODE_OPTIONS_LATE] = 0x00;
        match parse_hbc_header(&buf).unwrap() {
            HbcHeader::V98LateToV99(h) => assert_eq!(h.version, 98),
            other => panic!("expected V98LateToV99 with real debug offset, got {other:?}"),
        }
    }
}
