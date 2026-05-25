#![no_main]

//! `parse → emit_hbc → parse == parse` structural round-trip fuzz
//! for HBC v84 / v96 / v98 / v99. Targets the per-version emit
//! surfaces + both parse surfaces + each `HbcFileEquiv<_>` invariant.
//!
//! ## Typed-error discipline
//!
//! The emit surfaces return `HermesEmitError::UnrepresentableIR` for
//! adversarial inputs whose section layout the parser accepts but
//! emit can't reproduce byte-identically (e.g. sections in non-
//! canonical order or with invalid cursor positions crafted by a
//! fuzzer). This is a **typed rejection**, not a round-trip bug —
//! the emit spec explicitly scopes out layouts the format definition
//! considers unrepresentable. The fuzz target treats
//! `UnrepresentableIR` as skip and only panics on other emit-side
//! errors (which would be genuine bugs).
//!
//! All other `.expect()` calls (second-parse, HbcFileEquiv::new on
//! second parse, equiv assertion) remain hard gates — a panic on
//! any of them IS a round-trip violation.

use droidsaw_hermes::emit::{
    emit_hbc, emit_hbc_v84, emit_hbc_v98, emit_hbc_v99, HermesEmitError,
};
use droidsaw_hermes::parser::{HbcFile, HbcFileEquiv, V84, V96, V98, V99};
use libfuzzer_sys::fuzz_target;

/// Try-emit wrapper that skips on `UnrepresentableIR` (typed rejection
/// for adversarial layouts) while preserving panic behavior on any
/// other emit error. Returns `None` when the fuzz iteration should
/// exit without further checks.
fn try_emit(
    result: Result<Vec<u8>, HermesEmitError>,
    version_label: &str,
) -> Option<Vec<u8>> {
    match result {
        Ok(bytes) => Some(bytes),
        Err(HermesEmitError::UnrepresentableIR { .. }) => None,
        Err(e) => panic!("parse succeeded + {version_label}, emit failed with non-skip error: {e}"),
    }
}

fuzz_target!(|data: &[u8]| {
    // First parse: random-bytes path. Most inputs fail parse; OK — we
    // only exercise emit on successfully-parsed inputs.
    let Ok(hbc1) = HbcFile::parse(data, None) else {
        return;
    };

    // Version gates: v84, v96, v98, v99 have emit paths. Other
    // versions skip (v40 / v76 / v97 stay sibling-stream scope).
    if HbcFileEquiv::<V84>::new(&hbc1).is_some() {
        let equiv1 = HbcFileEquiv::<V84>::new(&hbc1).unwrap();

        let Some(emitted) = try_emit(emit_hbc_v84(&hbc1), "v84") else {
            return;
        };

        let hbc2 = HbcFile::parse(&emitted, None)
            .expect("parse-emit-parse: second parse failed (v84 emit layout bug)");

        let equiv2 = HbcFileEquiv::<V84>::new(&hbc2)
            .expect("parse-emit-parse: second parse produced non-v84 output");

        assert!(
            equiv1 == equiv2,
            "HbcFileEquiv<V84> violated round-trip: structural drift across emit"
        );
    } else if HbcFileEquiv::<V96>::new(&hbc1).is_some() {
        let equiv1 = HbcFileEquiv::<V96>::new(&hbc1).unwrap();

        let Some(emitted) = try_emit(emit_hbc(&hbc1), "v96") else {
            return;
        };

        let hbc2 = HbcFile::parse(&emitted, None)
            .expect("parse-emit-parse: second parse failed (v96 emit layout bug)");

        let equiv2 = HbcFileEquiv::<V96>::new(&hbc2)
            .expect("parse-emit-parse: second parse produced non-v96 output");

        assert!(
            equiv1 == equiv2,
            "HbcFileEquiv<V96> violated round-trip: structural drift across emit"
        );
    } else if HbcFileEquiv::<V98>::new(&hbc1).is_some() {
        let equiv1 = HbcFileEquiv::<V98>::new(&hbc1).unwrap();

        let Some(emitted) = try_emit(emit_hbc_v98(&hbc1), "v98") else {
            return;
        };

        let hbc2 = HbcFile::parse(&emitted, None)
            .expect("parse-emit-parse: second parse failed (v98 emit layout bug)");

        let equiv2 = HbcFileEquiv::<V98>::new(&hbc2)
            .expect("parse-emit-parse: second parse produced non-v98 output");

        assert!(
            equiv1 == equiv2,
            "HbcFileEquiv<V98> violated round-trip: structural drift across emit"
        );
    } else if HbcFileEquiv::<V99>::new(&hbc1).is_some() {
        let equiv1 = HbcFileEquiv::<V99>::new(&hbc1).unwrap();

        let Some(emitted) = try_emit(emit_hbc_v99(&hbc1), "v99") else {
            return;
        };

        let hbc2 = HbcFile::parse(&emitted, None)
            .expect("parse-emit-parse: second parse failed (v99 emit layout bug)");

        let equiv2 = HbcFileEquiv::<V99>::new(&hbc2)
            .expect("parse-emit-parse: second parse produced non-v99 output");

        assert!(
            equiv1 == equiv2,
            "HbcFileEquiv<V99> violated round-trip: structural drift across emit"
        );
    }
});
