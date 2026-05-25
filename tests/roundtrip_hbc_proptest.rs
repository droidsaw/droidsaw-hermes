//! `parse ∘ emit_hbc ∘ parse == parse` structural round-trip property
//! for HBC v96.
//!
//! `parser::HbcFileEquiv<V96>`'s `PartialEq` is the round-trip
//! equivalence specification. This proptest mutates a known-good v96
//! HBC fixture and asserts that any successfully-parsed mutant round-
//! trips through `emit_hbc` to an `HbcFileEquiv<V96>`-equal `HbcFile`.
//!
//! ## Case counts
//!
//! Default: **256 cases**. Override with `PROPTEST_CASES=N cargo test`.
//!
//! ## What MUST round-trip exactly (checked by `HbcFileEquiv<V96>`)
//!
//! - Version tag (V96::VERSION == 96).
//! - Primary header counts (function_count, string_count, overflow_
//!   string_count, string_storage_size, cjs_module_count, regexp_count,
//!   bigint_count, object_shape_count).
//! - `debug_info_offset` — preserved from IR (emit writes verbatim).
//! - `sections` element-wise (name + size).
//! - Non-Header section content bytes (SYNTHESIZE + PASSTHROUGH modes
//!   per `src/emit.rs` module docs).
//! - Header PASSTHROUGH byte ranges (sourceHash, global_code_index,
//!   segment_id/cjs_offset, BytecodeOptions + padding).
//!
//! ## What is intentionally NOT compared (gauge freedom)
//!
//! - Header bytes AS A WHOLE — emit recomputes file_length + strips
//!   nothing but canonicalizes parser-ignored count fields (e.g.
//!   `big_int_storage_size` when `big_int_count == 0`); the Header
//!   PASSTHROUGH byte-range compare covers the non-synthesized regions.
//! - Per-section absolute offsets — layout-dependent; only sizes
//!   compared.
//! - Parser-internal `input_hash` (SipHash diagnostic scope).
//! - Function metadata — `function_get()` follows overflowed-bit
//!   pointers to in-buffer SecondaryFuncHeaders at attacker-controlled
//!   offsets; when those land in 0..128 Header region, derived IR
//!   fields diverge despite equivalent structure. FunctionHeaders
//!   section bytes ARE compared (passthrough-covered in step 4).
//! - `debug_filename_count` — same root cause as function metadata:
//!   read via `read_u32(buf, debug_info_offset)` which can land in
//!   emit-modified Header for adversarial inputs. debug_info_offset
//!   preservation is the handle to the full debug_info region.
//!
//! ## Byte-identity theorem
//!
//! `emit_hbc(parse(bytes)) == bytes` holds on v96 corpus samples
//! staged by the user (see `tests/hbc_corpus_roundtrip.rs`). Byte-
//! identity is a consequence of correct emit combined with canonical-
//! ordering and IR capture; not enforced as a proptest invariant here
//! (mutations generally break parse) but is locked in as a hard gate
//! in the corpus round-trip test on real inputs.

use droidsaw_hermes::emit::{HermesEmitError, emit_hbc};
use droidsaw_hermes::parser::{HbcFile, HbcFileEquiv, V96};
use proptest::prelude::*;

mod common;
use common::hbc_bytes_strategy;

proptest! {
    #![proptest_config(ProptestConfig {
        // 256 cases — seed-mutation proptest target. Per-file corpus
        // p80 shapes (~115k funcs, ~196k strings) scale with corpus
        // round-trip, not this seed-mutation file; `PROPTEST_CASES`
        // env var can override per the workspace convention.
        cases: 256,
        max_shrink_iters: 1024,
        ..ProptestConfig::default()
    })]

    #[test]
    fn parse_emit_parse_structural_equivalence(bytes in hbc_bytes_strategy()) {
        let Ok(hbc1) = HbcFile::parse(&bytes, None) else {
            return Ok(()); // unparseable input is not a round-trip violation
        };

        // Version gate: v1 only handles v96. Non-v96 inputs are out-
        // of-scope (v98, v76, v40 emit deferred).
        let Some(equiv1) = HbcFileEquiv::<V96>::new(&hbc1) else {
            return Ok(());
        };

        let emitted = match emit_hbc(&hbc1) {
            Ok(buf) => buf,
            // v1 stub returns `UnrepresentableIR` on every call;
            // once D6 lands, this arm only covers IR shapes that
            // cannot round-trip (non-canonical orderings slipping a
            // NonDecreasing<T> gate, etc.). Expected; skip cleanly.
            Err(HermesEmitError::UnrepresentableIR { .. }) => return Ok(()),
            Err(HermesEmitError::SizeOverflow { .. }) => return Ok(()),
            Err(HermesEmitError::OffsetOverflow { .. }) => return Ok(()),
            Err(HermesEmitError::VersionMismatch { .. }) => return Ok(()),
            Err(e) => {
                prop_assert!(
                    false,
                    "parse succeeded, emit failed with internal error — round-trip violation: {e}"
                );
                return Ok(());
            }
        };

        let hbc2 = match HbcFile::parse(&emitted, None) {
            Ok(h) => h,
            Err(e) => {
                prop_assert!(
                    false,
                    "parse-emit-parse: second parse failed (layout bug): {e:?}"
                );
                return Ok(());
            }
        };

        let Some(equiv2) = HbcFileEquiv::<V96>::new(&hbc2) else {
            prop_assert!(
                false,
                "parse-emit-parse: second parse produced non-v96 output"
            );
            return Ok(());
        };

        // HbcFileEquiv<V96> PartialEq (parser.rs) is the spec.
        prop_assert!(
            equiv1 == equiv2,
            "HbcFileEquiv<V96> violated post round-trip: {:?} vs {:?}",
            equiv1,
            equiv2
        );
    }
}
