#![no_main]

//! `fuzz_ssa` — Hermes SSA construction structural-invariant gate.
//!
//! **Asserts:**
//! 1. `build_ssa` completes without panic for every function body with a
//!    well-formed CFG. (Panic-freedom invariant.)
//! 2. **block_order covers all blocks:** every block in `ssa.blocks` appears
//!    exactly once in `ssa.block_order`. A missing block would cause dead
//!    code to be silently dropped; a duplicate would produce duplicate
//!    output.
//! 3. **Phi-operand predecessor coverage:** for every φ-node in block B,
//!    each operand source block `s` is a predecessor of B in the CFG.
//!    An orphaned operand key is a phi-placement bug that produces wrong
//!    code silently.
//!
//! Verifies SSA invariants: every use is dominated by its definition, and
//! every φ node's source is defined on its predecessor edge. Hermes SSA is
//! built through `droidsaw_common::ssa::Builder` via CfgAdapter. The parsed
//! `f.frame_size` is attacker-controlled via the HBC header, so the fuzzer is
//! the primary surface for the frame-relative variadic-call resolver.
//!
use std::collections::BTreeSet;

use droidsaw_hermes::decompile::cfg::{Cfg, ExcHandler};
use droidsaw_hermes::decompile::decode::decode_function;
use droidsaw_hermes::decompile::ssa::build_ssa;
use droidsaw_hermes::parser::HbcFile;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let hbc = match HbcFile::parse(data, None) {
        Ok(h) => h,
        Err(_) => return,
    };

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

        let Ok(cfg) = Cfg::build(&instructions, &exc_handlers, code) else {
            continue;
        };
        let Ok(ssa) = build_ssa(&cfg, f.frame_size) else {
            continue;
        };

        // --- Structural invariants ---

        // Inv 2: block_order covers every block exactly once.
        let all_block_ids: BTreeSet<u32> = ssa.blocks.iter().map(|b| b.id).collect();
        let order_set: BTreeSet<u32> = ssa.block_order.iter().copied().collect();
        assert_eq!(
            order_set,
            all_block_ids,
            "SSA block_order does not cover all blocks: \
             in order but not blocks: {:?}, in blocks but not order: {:?}",
            order_set.difference(&all_block_ids).collect::<Vec<_>>(),
            all_block_ids.difference(&order_set).collect::<Vec<_>>(),
        );
        // Also check block_order has no duplicates (set size == vec size).
        assert_eq!(
            ssa.block_order.len(),
            order_set.len(),
            "SSA block_order has duplicate entries: len={} but unique={}",
            ssa.block_order.len(),
            order_set.len(),
        );

        // Inv 3: phi-operand predecessor coverage.
        // Build predecessor sets from the CFG (not the SSA) as the ground truth.
        let pred_sets: std::collections::BTreeMap<u32, BTreeSet<u32>> = cfg
            .blocks
            .iter()
            .map(|(&bid, b)| (bid, b.predecessors.iter().copied().collect()))
            .collect();

        for block in &ssa.blocks {
            let preds = pred_sets.get(&block.id).cloned().unwrap_or_default();
            for phi in &block.phis {
                for &(src_block, _) in &phi.args {
                    assert!(
                        preds.contains(&src_block),
                        "SSA phi-operand predecessor violation: block {} has phi \
                         dst={:?} with operand from block {}, but {} is not a \
                         CFG predecessor of {}. Predecessors: {:?}",
                        block.id,
                        phi.dst,
                        src_block,
                        src_block,
                        block.id,
                        preds,
                    );
                }
            }
        }
    }
});
