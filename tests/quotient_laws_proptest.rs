//! Quotient-newtype equivalence laws for `HbcFileEquiv<V96>`.
//!
//! `HbcFileEquiv<V>` (parser.rs) is the round-trip equivalence
//! specification for `emit_hbc` on v96 HBC files. Its `PartialEq`
//! impl IS the spec for "what counts as round-trip equivalent."
//! `parse_emit_parse_structural_equivalence` (in
//! `roundtrip_hbc_proptest.rs`) checks PRESERVATION of the class by
//! parse-emit-parse; this file checks that the projection IS a
//! well-formed equivalence relation in the first place.
//!
//! ## Three laws
//!
//! - **Reflexivity** — `equiv(&hbc) == equiv(&hbc)` for every parse-
//!   success v96 `hbc`.
//! - **Symmetry** — `(a ~ b) == (b ~ a)`. Required by `PartialEq`.
//! - **Transitivity** — `(a ~ b) ∧ (b ~ c) ⇒ a ~ c`. Required by
//!   `PartialEq`. Empty-on-coverage risk addressed by deterministic
//!   coverage-counter (see manual `TestRunner` block).
//!
//! ## Version scope
//!
//! Only `V96` is tested. The impl is shared across V84/V98/V99 (same
//! shape, version-tagged via `PhantomData`); per-version laws-tests
//! are overkill unless the impl diverges. If a future version-
//! specific impl ships, add a parallel test here.
//!
//! ## What this does NOT cover
//!
//! - `Eq` axioms — `HbcFileEquiv` only impls `PartialEq`.
//! - Structural `arb_hbc_file_v96()` — out of scope.

#![allow(
    clippy::cast_precision_loss,
    reason = "PROOF: HBC parser/decompiler stats (LineMap deltas, function-size histograms); f32/f64 mantissa loss is below per-bytecode measurement noise."
)]

use droidsaw_hermes::parser::{HbcFile, HbcFileEquiv, V96};
use proptest::prelude::*;
use proptest::test_runner::{Config, TestRunner};
use std::cell::Cell;

mod common;
use common::hbc_bytes_strategy;

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        max_shrink_iters: 1024,
        ..ProptestConfig::default()
    })]

    /// `HbcFileEquiv::<V96>::new(&hbc) == HbcFileEquiv::<V96>::new(&hbc)`
    /// for every parse-success v96 file.
    #[test]
    fn hbc_file_equiv_reflexive(bytes in hbc_bytes_strategy()) {
        let Ok(hbc) = HbcFile::parse(&bytes, None) else { return Ok(()); };
        let Some(e1) = HbcFileEquiv::<V96>::new(&hbc) else { return Ok(()); };
        let Some(e2) = HbcFileEquiv::<V96>::new(&hbc) else { return Ok(()); };
        prop_assert!(e1 == e2, "reflexivity violated: x !~ x");
    }

    /// `(a ~ b) iff (b ~ a)` for parse-success v96 pairs.
    #[test]
    fn hbc_file_equiv_symmetric(
        a in hbc_bytes_strategy(),
        b in hbc_bytes_strategy(),
    ) {
        let Ok(ha) = HbcFile::parse(&a, None) else { return Ok(()); };
        let Ok(hb) = HbcFile::parse(&b, None) else { return Ok(()); };
        let Some(ea) = HbcFileEquiv::<V96>::new(&ha) else { return Ok(()); };
        let Some(eb) = HbcFileEquiv::<V96>::new(&hb) else { return Ok(()); };
        let ab = ea == eb;
        let ba = eb == ea;
        prop_assert_eq!(ab, ba, "symmetry violated: ab={}, ba={}", ab, ba);
    }
}

/// Transitivity with deterministic coverage report. Manual
/// `TestRunner` so we own the loop counters; same shape as the dex
/// quotient-laws transitivity test.
#[test]
fn hbc_file_equiv_transitive() {
    let config = Config {
        cases: 256,
        max_shrink_iters: 1024,
        ..Config::default()
    };
    let mut runner = TestRunner::new(config);
    let total: Cell<u64> = Cell::new(0);
    let fired: Cell<u64> = Cell::new(0);
    let result = runner.run(
        &(hbc_bytes_strategy(), hbc_bytes_strategy(), hbc_bytes_strategy()),
        |(a, b, c)| {
            total.set(total.get() + 1);
            let Ok(ha) = HbcFile::parse(&a, None) else { return Ok(()); };
            let Ok(hb) = HbcFile::parse(&b, None) else { return Ok(()); };
            let Ok(hc) = HbcFile::parse(&c, None) else { return Ok(()); };
            let Some(ea) = HbcFileEquiv::<V96>::new(&ha) else { return Ok(()); };
            let Some(eb) = HbcFileEquiv::<V96>::new(&hb) else { return Ok(()); };
            let Some(ec) = HbcFileEquiv::<V96>::new(&hc) else { return Ok(()); };
            if !(ea == eb && eb == ec) {
                return Ok(());
            }
            fired.set(fired.get() + 1);
            prop_assert!(
                ea == ec,
                "transitivity violated: (a ~ b) ∧ (b ~ c) ∧ ¬(a ~ c)"
            );
            Ok(())
        },
    );
    let total = total.get();
    let fired = fired.get();
    let pct = if total == 0 { 0.0 } else { (fired as f64 / total as f64) * 100.0 };
    eprintln!(
        "[quotient-laws/hermes] transitivity precondition fired {fired}/{total} cases ({pct:.2}%)"
    );
    if let Err(e) = result {
        panic!("transitivity proptest failed: {e}");
    }
}
