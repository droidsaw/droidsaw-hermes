//! Hermes parser-side typed Findings.
//!
//! When the parser (or its lookup methods like
//! [`crate::parser::HbcFile::string_get`]) detects a corruption-mask
//! shape that would otherwise collapse silently into an empty
//! [`crate::parser::StringData`] return, it emits a typed
//! [`HermesFinding`] onto a thread-local channel. Triage tooling +
//! tests drain the channel via [`drain_findings_for_test`].
//!
//! This shape mirrors [`droidsaw_common::diag::emit_warning`] (in
//! particular, the [`droidsaw_common::diag::Warning::RegionDepthExceeded`]
//! pattern) but lives in `droidsaw-hermes` so the variants stay close
//! to their emitter.
//!
//! # Why a typed finding rather than just an empty fallback?
//!
//! The pre-existing fallback at `parser::HbcFile::string_get` returned
//! `StringData{ offset: 0, len: 0 }` on overflow-out-of-range. A silent
//! empty return cannot distinguish "string is legitimately empty" from
//! "overflow lookup landed out-of-range" — the typed finding is the
//! side-channel that surfaces the difference. The in-band signal is
//! widened by `string_get`'s `Result<StringData, HermesError>` return,
//! making the Finding channel a secondary observability path.

use std::cell::RefCell;
use std::collections::HashSet;

/// A typed parser-side finding.
///
/// Variants are added as new corruption-mask shapes are migrated off
/// silent-empty fallbacks. `#[non_exhaustive]` so consumer code must
/// match with `_ =>` — new variants are non-breaking.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum HermesFinding {
    /// Hermes string-table lookup hit the overflow sentinel
    /// (`str_length == 255`) but the routed `str_offset` was
    /// `>= overflow_string_count` — the indirection target is
    /// out-of-range. `string_get` falls back to an empty `StringData`
    /// (preserving its pre-existing shape) and emits this finding so
    /// the corruption-mask is observable.
    OverflowIndexOutOfRange {
        /// The string-table index whose lookup hit OOR.
        index: u32,
        /// Snapshot of `overflow_string_count` at the time of the
        /// fault — bound the routed `str_offset` was checked against.
        count: u32,
    },
    /// HBC header's declared `file_length` field disagrees with the
    /// buffer length actually handed to `HbcFile::parse`. The parser
    /// continues using `min(file_length as u64, buf.len() as u64)` as
    /// the effective bound (already structural via the `section!`
    /// macro — every section is `cursor + size <= buf.len()`-checked
    /// and well-formed HBCs have `sum(section_sizes) = file_length`,
    /// so a trailing-data shape walks to `cursor = file_length` and
    /// stops without re-entering the smuggled bytes). The Finding
    /// surfaces the disagreement as a typed signal — caller can
    /// distinguish "file is well-formed" from "file_length declared
    /// shorter than observed" (trailing-data smuggling shape) or
    /// "file_length declared longer than observed" (truncated shape).
    FileLengthDisagreement {
        /// Declared file length from the HBC header (`u32` per the
        /// wire format).
        declared: u32,
        /// Observed buffer length as handed to `HbcFile::parse`
        /// (`u64` — buffers may exceed `u32::MAX` on >4 GB inputs).
        observed: u64,
    },
    /// An ObjectShapeTable entry's `num_props` exceeded
    /// [`MAX_OBJECT_SHAPE_NUM_PROPS`]. Hermes's shape table carries
    /// attacker-controlled `num_props: u32`; downstream decompile
    /// passes (`optimize::resolve_buffers`) use it to size
    /// `Vec::with_capacity(num_props as usize)` and drive
    /// `for i in 0..num_props` loops, which at `num_props = 1 << 28`
    /// would allocate multi-GB and iterate ~268M times — DoS via
    /// amplification. The per-shape consumer-side cap surfaces the
    /// violation as a typed Finding; the offending shape is treated as
    /// "unresolved" and the rest of the decompile run continues
    /// (lenient policy).
    ObjectShapeNumPropsExceeded {
        /// The shape entry's declared `num_props`.
        observed: u32,
        /// The cap that was exceeded (the snapshot of
        /// [`MAX_OBJECT_SHAPE_NUM_PROPS`] at emission time).
        limit: u32,
    },
    /// A BigInt storage entry's byte length exceeded
    /// [`MAX_BIGINT_BYTES`]. The base-256 → base-10 conversion in
    /// `parser::bigint_le_twos_to_decimal` is O(N²) in the entry byte
    /// length, and the per-entry length is bounded only by
    /// `big_int_storage_size: u32` at parse-time. An attacker-shipped
    /// HBC with a single ~4 MiB BigInt entry would run ~10 trillion
    /// mul-adds (multi-minute CPU hang) per `bigint_as_str` call. The
    /// cap surfaces the violation as a typed Finding; the caller
    /// returns `None` (mirroring the out-of-bounds path), and the
    /// emit-site arm renders `/* missing bigint #N */` so the
    /// decompile run continues (lenient policy).
    BigIntTooLarge {
        /// The BigInt table index whose storage entry exceeded the cap.
        index: u32,
        /// The observed byte length of the BigInt storage entry.
        observed: u32,
        /// The cap that was exceeded (the snapshot of
        /// [`MAX_BIGINT_BYTES`] at emission time).
        limit: u32,
    },

    /// A function's declared exception-handler count
    /// (`function_exception_count`) exceeded the
    /// [`MAX_EXCEPTION_HANDLERS`] cap. When this fires, the lenient
    /// accessor returns `0`, which is indistinguishable from "this
    /// function has no handlers" — CFG construction proceeds without
    /// try/catch edges, letting an attacker hide handlers behind an
    /// oversized count. The accessor preserves its u32-returning API
    /// across all callers, but this Finding makes the cap observable.
    /// The strict-API alternative is
    /// `HbcFile::function_exception_count_checked()` which returns
    /// `Result<u32, HermesError>` and surfaces
    /// [`crate::error::HermesError::ExceptionCountCap`].
    ExceptionCountCap {
        /// The function index whose declared exception count
        /// exceeded the cap.
        func_idx: u32,
        /// The declared exception-handler count (verbatim from the
        /// HBC byte stream).
        declared: u32,
        /// The cap that was exceeded (snapshot of
        /// [`MAX_EXCEPTION_HANDLERS`] at emission time).
        cap: u32,
    },

    /// A function header had the `overflowed` flag set but the
    /// declared large-header offset (`large_off`) was such that
    /// `large_off + LARGE_FUNCTION_HEADER_SIZE > buf.len()`. The
    /// non-strict path (`function_get`) silently falls back to the
    /// small header's truncated 25-bit offset bitfield, indistinguishable
    /// from a real non-overflowed function — letting an attacker
    /// re-route body decode to a wrong offset via crafted metadata.
    /// `function_get` still returns the small-header `FunctionData`
    /// to preserve its `FunctionData`-returning API across 30
    /// production callers, but this Finding makes the OOB observable.
    /// The strict-API alternative is `HbcFile::function_get_checked()`
    /// which returns `Result<FunctionData, HermesError>` and surfaces
    /// [`crate::error::HermesError::OverflowedHeaderOutOfBounds`].
    OverflowedHeaderOutOfBounds {
        /// The function index whose overflow claim tripped the OOB
        /// check.
        func_idx: u32,
        /// The declared large-header offset (verbatim from the
        /// composed small-header bitfields).
        large_off: u64,
        /// The HBC buffer length at the time of the OOB check.
        buf_len: usize,
    },

    /// A function's overflow large-header is in-bounds but its byte
    /// span intersects a region emit recomputes from IR (file header /
    /// FunctionHeaders table / string tables). The bytes are
    /// double-claimed, so emit's faithful recompute would silently
    /// mutate this function's metadata — a `parse → emit → parse`
    /// fidelity break. Adversarial-only (a well-formed Hermes bundle
    /// never overlaps a large header with a synthesized region). The
    /// function is recorded unrecognized (terminal — never decoded)
    /// and emit refuses the file as unrepresentable. Strict-API
    /// counterpart:
    /// [`crate::error::HermesError::OverflowedHeaderOverlapsSynthesizedRegion`].
    OverflowedHeaderOverlapsSynthesizedRegion {
        /// The function index whose overflow claim overlaps a
        /// synthesized region.
        func_idx: u32,
        /// The declared large-header offset (verbatim from the
        /// composed small-header bitfields).
        large_off: u64,
    },

    /// A function has its `has_exception_handler` flag set and the
    /// exception-handler table it points at intersects a region emit
    /// recomputes from IR (file header / a SYNTHESIZE-mode table
    /// section). The table's count word / handler entries are
    /// double-claimed, so emit's faithful recompute would silently
    /// mutate the bytes the next parse re-reads as this function's
    /// handlers — a `parse → emit → parse` fidelity break.
    /// Adversarial-only (a well-formed Hermes bundle never lays an
    /// exception table inside a synthesized region). The function is
    /// recorded unrecognized (terminal — never decoded) and emit
    /// refuses the file as unrepresentable. Strict-API counterpart:
    /// [`crate::error::HermesError::ExceptionTableOverlapsSynthesizedRegion`].
    ExceptionTableOverlapsSynthesizedRegion {
        /// The function index whose exception table overlaps a
        /// synthesized region.
        func_idx: u32,
        /// The resolved exception-table offset (`get_exc_table_offset`).
        exc_offset: u32,
    },

    /// HBC v98 form-disambiguation could not pick a layout from the
    /// `BytecodeOptions`-byte heuristic alone (both `BYTECODE_OPTIONS_EARLY`
    /// at offset 108 and `BYTECODE_OPTIONS_LATE` at offset 112 passed the
    /// MBZ check, AND both layouts' `debug_info_offset` projections were
    /// either simultaneously zero/OOB or simultaneously plausible). The
    /// legitimate stripped-RN-bundle shape looks identical to a crafted
    /// late-form-pretending-to-be-early attack at the byte-peek layer.
    ///
    /// **No table-size cross-validation.** v97-to-v98-early and v98-late-to-v99
    /// share the same 12-byte `SmallFuncHeader` stride (see
    /// `HbcHeader::func_header_size`), so a footprint check produces
    /// identical answers for both layouts and cannot disambiguate.
    /// A meaningful cross-validation would require decoding a candidate
    /// function header under each layout and verifying its bitfield-derived
    /// offsets are in-bounds — that requires decoding function headers
    /// under each layout and verifying bitfield-derived offsets.
    ///
    /// `picked_late` records the chosen layout (always `false` →
    /// early-form per tolerant-parse discipline; this preserves standard
    /// behavior on the dominant stripped-bundle shape).
    V98FormAmbiguous {
        /// The observed BytecodeOptions byte at offset 108.
        early_options: u8,
        /// The observed BytecodeOptions byte at offset 112.
        late_options: u8,
        /// Function count from header offset 40 (same offset in both
        /// candidate layouts; carried for audit-trail attribution).
        function_count: u32,
        /// `debug_info_offset` projection at offset 108 (late-form position).
        debug_with: u32,
        /// `debug_info_offset` projection at offset 104 (early-form position).
        debug_without: u32,
        /// Final pick (`true` → late-form, `false` → early-form).
        picked_late: bool,
    },
}

/// Maximum acceptable `function_exception_count` on a single function
/// header. Set to **10000**: well above the largest counts observed in
/// production HBC (single-digit per function); an attacker-controlled
/// count above this bound is a CFG-without-try-edges silent-default
/// signal. Used by `HbcFile::function_exception_count` and
/// `function_exception_get` to gate the read; see
/// [`HermesFinding::ExceptionCountCap`].
pub const MAX_EXCEPTION_HANDLERS: u32 = 10_000;

/// Maximum acceptable `num_props` on a single ObjectShape table entry.
///
/// Set to **65536**: JS objects with > 64K properties don't exist in
/// the wild; an attacker-controlled `num_props` above this bound is a
/// DoS amplification signal (see
/// [`HermesFinding::ObjectShapeNumPropsExceeded`]). Used by
/// `decompile::optimize::resolve_buffers` to gate
/// `Vec::with_capacity(num_props as usize)` and `for i in 0..num_props`
/// loops at the two consumer sites.
pub const MAX_OBJECT_SHAPE_NUM_PROPS: u32 = 65_536;

/// Maximum acceptable byte length for a single BigInt storage entry.
///
/// Set to **4096**: `parser::bigint_le_twos_to_decimal` is O(N²) in
/// the entry byte length (per-byte multiply-by-256 + add over a digit
/// vector that grows to ~2.4·N decimal digits). At N=4096 the total
/// work is ~40M mul-adds (well under 1 s on commodity hardware); at
/// the unbounded ceiling (`big_int_storage_size: u32 = u32::MAX`),
/// a single attacker-controlled entry would run ~10 trillion mul-adds
/// per `bigint_as_str` call — multi-minute CPU hang per HBC decompile.
///
/// Empirical headroom: real-world RN BigInt literals are tiny
/// (Hermes's own 30-digit fixture is 13 bytes). 4096 gives ample
/// margin while keeping the O(N²) work bounded.
///
/// Used by `parser::HbcFile::bigint_as_str` to gate the conversion
/// before any work is done; entries above the cap return `None` and
/// emit [`HermesFinding::BigIntTooLarge`].
pub const MAX_BIGINT_BYTES: u32 = 4096;

thread_local! {
    /// Findings emitted on this thread's parser paths.
    static FINDINGS: RefCell<Vec<HermesFinding>> = const { RefCell::new(Vec::new()) };
    /// One-shot dedup keyed by the full Finding value so a single
    /// fault shape doesn't spam when the caller does many lookups in
    /// a tight loop. Real-world cardinality is bounded by
    /// (#variants × distinct argument tuples observed this thread).
    static SEEN: RefCell<HashSet<HermesFinding>> = RefCell::new(HashSet::new());
}

/// Push a [`HermesFinding`] onto the current thread's parser channel.
///
/// Deduplicated by the full `HermesFinding` value per thread — the
/// first emission for a given value records, later calls are no-ops.
/// On reentrant `RefCell` borrow the call is a silent no-op (mirrors
/// the `common::diag::emit_warning` reentrancy-tolerance shape so
/// this function cannot itself panic from inside a nested context).
pub fn emit_finding(f: HermesFinding) {
    let fire = SEEN.with(|s| {
        s.try_borrow_mut()
            .ok()
            .map(|mut set| set.insert(f.clone()))
            .unwrap_or(false)
    });
    if !fire {
        return;
    }
    FINDINGS.with(|w| {
        if let Ok(mut v) = w.try_borrow_mut() {
            v.push(f);
        }
    });
}

/// Drain the current thread's parser finding channel.
///
/// Test-only thin wrapper around [`drain_findings`] kept for the
/// existing test-suite call sites. Both functions share the same
/// implementation; new code should prefer [`drain_findings`].
#[doc(hidden)]
pub fn drain_findings_for_test() -> Vec<HermesFinding> {
    drain_findings()
}

/// Drain the current thread's parser finding channel.
///
/// Every `HbcFile::parse` emits Findings onto a thread-local channel
/// (`emit_finding`). Without an operator-facing drain, those signals
/// never reach stdout / JSON / audit envelopes — the channel is
/// not accessible. This is the production drain that top-binary
/// command paths call after every `HbcFile::parse` to surface the
/// per-bundle Findings.
///
/// Returns an empty `Vec` on reentrant borrow. Idempotent — a second
/// call from the same thread returns empty until the next
/// `emit_finding` repopulates the channel.
pub fn drain_findings() -> Vec<HermesFinding> {
    let out = FINDINGS.with(|w| {
        w.try_borrow_mut()
            .ok()
            .map(|mut v| std::mem::take(&mut *v))
            .unwrap_or_default()
    });
    SEEN.with(|s| {
        if let Ok(mut set) = s.try_borrow_mut() {
            set.clear();
        }
    });
    out
}

/// Discard pending findings on this thread without returning them.
///
/// Use at trust boundaries — at the entry of a per-bundle parse call,
/// before any `emit_finding` can fire — to defend against cross-tenant
/// residual leakage. If the calling thread previously hosted a parse
/// that emitted findings then returned `Err` via `?` (so the caller
/// never reached its own [`drain_findings`]), those findings would
/// otherwise persist in the channel and be attributed to the next
/// bundle parsed on the same thread (tokio `spawn_blocking` reuses
/// blocking-pool workers across tasks).
///
/// Like [`drain_findings`], this clears both `FINDINGS` and `SEEN`.
/// Reentrant-safe: a try_borrow failure is a no-op rather than a panic.
pub fn discard_findings() {
    FINDINGS.with(|w| {
        if let Ok(mut v) = w.try_borrow_mut() {
            v.clear();
        }
    });
    SEEN.with(|s| {
        if let Ok(mut set) = s.try_borrow_mut() {
            set.clear();
        }
    });
}

/// Translate per-thread [`HermesFinding`] records into workspace-shared
/// [`droidsaw_common::finding::Finding`] payloads. Variants fan out to
/// one Finding each; the resulting `Vec` joins the per-dex / per-apk
/// Finding stream in the top binary's audit envelope.
///
/// Severity defaults are conservative because the underlying signal
/// is "tolerantly-parsed corruption observed" — the parse already
/// chose a fallback shape. Higher-severity routing (`HermesError`)
/// goes through the typed-Err path, not this channel.
#[must_use]
pub fn findings_as_common(
    findings: Vec<HermesFinding>,
) -> Vec<droidsaw_common::finding::Finding> {
    use droidsaw_common::finding::{Confidence, Finding, Layer, Severity};
    findings
        .into_iter()
        .map(|f| {
            // Per-variant Confidence assignment. Variants reporting a
            // bytes-prove-violation (count overflow / index OOR /
            // header OOB / hard-spec cap exceeded) are Verified
            // (producer attests semantics are precise). Variants
            // reporting a parser disambiguation pick (V98FormAmbiguous)
            // OR a soft cap (FileLengthDisagreement,
            // ObjectShapeNumPropsExceeded — operator-tunable defaults,
            // not bytes-prove-malformed) stay at the Unverified default
            // — the parser is signaling "this looked suspicious"
            // rather than "this is provably malformed".
            let (id, severity, confidence, detail) = match &f {
                HermesFinding::OverflowIndexOutOfRange { index, count } => (
                    "HERMES_OVERFLOW_INDEX_OOR",
                    Severity::Medium,
                    Confidence::Verified,
                    format!(
                        "overflow string-table index {index} >= overflow_string_count {count}"
                    ),
                ),
                HermesFinding::FileLengthDisagreement { declared, observed } => (
                    "HERMES_FILE_LENGTH_DISAGREEMENT",
                    Severity::Medium,
                    Confidence::Unverified,
                    format!("declared {declared} vs observed {observed}"),
                ),
                HermesFinding::ObjectShapeNumPropsExceeded { observed, limit } => (
                    "HERMES_OBJECT_SHAPE_NUM_PROPS_EXCEEDED",
                    Severity::Medium,
                    Confidence::Unverified,
                    format!("num_props {observed} exceeds cap {limit}"),
                ),
                HermesFinding::BigIntTooLarge {
                    index,
                    observed,
                    limit,
                } => (
                    "HERMES_BIGINT_TOO_LARGE",
                    Severity::Medium,
                    Confidence::Verified,
                    format!("bigint #{index} length {observed} exceeds cap {limit}"),
                ),
                HermesFinding::ExceptionCountCap {
                    func_idx,
                    declared,
                    cap,
                } => (
                    "HERMES_EXCEPTION_COUNT_CAP",
                    Severity::Medium,
                    Confidence::Verified,
                    format!(
                        "function {func_idx} declared {declared} exception handlers; cap {cap}"
                    ),
                ),
                HermesFinding::OverflowedHeaderOutOfBounds {
                    func_idx,
                    large_off,
                    buf_len,
                } => (
                    "HERMES_OVERFLOWED_HEADER_OOB",
                    Severity::High,
                    Confidence::Verified,
                    format!(
                        "function {func_idx} large-header offset {large_off:#x} exceeds buf.len() {buf_len}"
                    ),
                ),
                HermesFinding::OverflowedHeaderOverlapsSynthesizedRegion {
                    func_idx,
                    large_off,
                } => (
                    "HERMES_OVERFLOWED_HEADER_OVERLAPS_SYNTHESIZED_REGION",
                    Severity::High,
                    Confidence::Verified,
                    format!(
                        "function {func_idx} large-header at {large_off:#x} overlaps a synthesized region"
                    ),
                ),
                HermesFinding::ExceptionTableOverlapsSynthesizedRegion {
                    func_idx,
                    exc_offset,
                } => (
                    "HERMES_EXCEPTION_TABLE_OVERLAPS_SYNTHESIZED_REGION",
                    Severity::High,
                    Confidence::Verified,
                    format!(
                        "function {func_idx} exception table at {exc_offset:#x} overlaps a synthesized region"
                    ),
                ),
                HermesFinding::V98FormAmbiguous {
                    early_options,
                    late_options,
                    function_count,
                    debug_with,
                    debug_without,
                    picked_late,
                } => (
                    "HERMES_V98_FORM_AMBIGUOUS",
                    Severity::Low,
                    Confidence::Unverified,
                    format!(
                        "v98 form disambiguation byte-peek-ambiguous \
                         (early_options=0x{early_options:02x}, late_options=0x{late_options:02x}, \
                         function_count={function_count}, debug_with={debug_with}, \
                         debug_without={debug_without}, picked_late={picked_late})"
                    ),
                ),
            };
            let mut out = Finding::new(id, Layer::Hbc, severity, detail);
            out.confidence = confidence;
            out
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emit_then_drain() {
        let _ = drain_findings_for_test();
        emit_finding(HermesFinding::OverflowIndexOutOfRange {
            index: 7,
            count: 3,
        });
        let v = drain_findings_for_test();
        assert_eq!(
            v,
            vec![HermesFinding::OverflowIndexOutOfRange {
                index: 7,
                count: 3,
            }]
        );
    }

    #[test]
    fn dedup_per_key() {
        let _ = drain_findings_for_test();
        for _ in 0..5 {
            emit_finding(HermesFinding::OverflowIndexOutOfRange {
                index: 1,
                count: 0,
            });
        }
        emit_finding(HermesFinding::OverflowIndexOutOfRange {
            index: 2,
            count: 0,
        });
        let v = drain_findings_for_test();
        assert_eq!(v.len(), 2, "{v:?}");
    }

    #[test]
    fn drain_resets_dedup() {
        let _ = drain_findings_for_test();
        emit_finding(HermesFinding::OverflowIndexOutOfRange {
            index: 9,
            count: 0,
        });
        let _ = drain_findings_for_test();
        // After drain, same key fires again.
        emit_finding(HermesFinding::OverflowIndexOutOfRange {
            index: 9,
            count: 0,
        });
        let v = drain_findings_for_test();
        assert_eq!(v.len(), 1, "{v:?}");
    }

    #[test]
    fn discard_clears_channel_without_returning() {
        let _ = drain_findings_for_test();
        emit_finding(HermesFinding::OverflowIndexOutOfRange {
            index: 4,
            count: 0,
        });
        discard_findings();
        let v = drain_findings_for_test();
        assert!(
            v.is_empty(),
            "discard_findings must clear the channel; got {v:?}"
        );
    }

    #[test]
    fn discard_clears_dedup_set() {
        let _ = drain_findings_for_test();
        emit_finding(HermesFinding::OverflowIndexOutOfRange {
            index: 11,
            count: 0,
        });
        discard_findings();
        // After discard, the same key fires again — proving SEEN was cleared.
        emit_finding(HermesFinding::OverflowIndexOutOfRange {
            index: 11,
            count: 0,
        });
        let v = drain_findings_for_test();
        assert_eq!(v.len(), 1, "{v:?}");
    }
}
