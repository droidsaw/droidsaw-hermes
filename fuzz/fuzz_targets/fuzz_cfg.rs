#![no_main]

//! `fuzz_cfg` — Hermes CFG construction structural-invariant gate.
//!
//! **Asserts:**
//! 1. `Cfg::build` completes without panic for every function body the
//!    HBC parser accepts. (Panic-freedom invariant.)
//! 2. **CFG pred/succ symmetry:** for every edge A → B in the resulting
//!    graph, B appears in A's successors **and** A appears in B's
//!    predecessors. This directly tests the postcondition documented in
//!    `Cfg::build`'s doc-comment. A one-way edge is a CFG-builder bug
//!    that downstream SSA and structuring phases silently miscompile.
//!
//! Verifies the core CFG invariant: predecessor-successor symmetry. The fuzzer
//! exercises the property directly as documented in `Cfg::build`'s contract.

use std::collections::BTreeMap;

use droidsaw_hermes::decompile::cfg::{Cfg, ExcHandler};
use droidsaw_hermes::decompile::decode::decode_function;
use droidsaw_hermes::parser::HbcFile;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let hbc = match HbcFile::parse(data, None) {
        Ok(h) => h,
        Err(_) => return,
    };

    // Cap function-iteration so a pathological function_count in the header
    // can't turn a single fuzz execution into a timeout. 256 is generous for
    // any realistic seed and still hits every branch in Cfg::build.
    let limit = hbc.function_count.min(256);
    let version = hbc.opcode_version();

    for i in 0..limit {
        let f = hbc.function_get(i);
        let start = f.offset as usize;
        let end = match start.checked_add(f.size as usize) {
            Some(v) => v,
            None => continue,
        };
        if end > data.len() {
            continue;
        }
        let code = &data[start..end];
        let Ok(instructions) = decode_function(code, version) else {
            continue;
        };

        // Gather exception handlers for this function.
        let exc_count = hbc.function_exception_count(i).min(64);
        let mut exc_handlers: Vec<ExcHandler> = Vec::with_capacity(exc_count as usize);
        for j in 0..exc_count {
            let eh = hbc.function_exception_get(i, j);
            exc_handlers.push(ExcHandler {
                start: eh.start,
                end: eh.end,
                target: eh.target,
            });
        }

        let cfg = match Cfg::build(&instructions, &exc_handlers, code) {
            Ok(c) => c,
            Err(_) => continue,
        };

        // Structural invariant: pred/succ symmetry.
        // For every edge A → B: B ∈ A.successors AND A ∈ B.predecessors.
        // Build a fast-lookup predecessor set per block.
        let pred_sets: BTreeMap<u32, std::collections::BTreeSet<u32>> = cfg
            .blocks
            .iter()
            .map(|(&bid, b)| {
                (
                    bid,
                    b.predecessors.iter().copied().collect(),
                )
            })
            .collect();

        for (&bid_a, block_a) in &cfg.blocks {
            for &bid_b in &block_a.successors {
                let preds_b = pred_sets.get(&bid_b).cloned().unwrap_or_default();
                assert!(
                    preds_b.contains(&bid_a),
                    "CFG pred/succ symmetry violated: block {} has successor {} \
                     but {} does not list {} as a predecessor. \
                     Block {} predecessors: {:?}",
                    bid_a,
                    bid_b,
                    bid_b,
                    bid_a,
                    bid_b,
                    preds_b,
                );
            }
        }
    }
});
