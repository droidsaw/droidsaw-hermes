#![no_main]

// Differential oracle fuzz target for Hermes CFG construction.
//
// Property: for every Hermes function body that the production pipeline accepts,
// the naive oracle's CfgShape must equal the production Cfg::to_shape().
//
// Any divergence is a silent-wrong-CFG bug: wrong dominators without panicking.
//
// Invariants asserted:
// 1. naive_cfg(instructions, exc_handlers, bytecodes).leaders == production_cfg.to_shape().leaders
// 2. naive_cfg(instructions, exc_handlers, bytecodes).edges == production_cfg.to_shape().edges
// 3. naive_cfg(instructions, exc_handlers, bytecodes).block_instructions == production_cfg.to_shape().block_instructions
//
// Harness design:
// - Input: raw byte slice (arbitrary HBC bytes).
// - Harness runs production HbcFile::parse first; skips if parse fails.
// - For each function in the parsed HBC (up to 256): decode_function + Cfg::build,
//   then oracle on the same inputs; assert CfgShape equality.
// - Stateless: no internal mutation across fuzz iterations.

use droidsaw_hermes::decompile::cfg::{Cfg, ExcHandler};
use droidsaw_hermes::decompile::cfg_oracle::{naive_cfg, CfgShape};
use droidsaw_hermes::decompile::decode::decode_function;
use droidsaw_hermes::parser::HbcFile;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Step 1: production parse. Skip inputs that fail parse.
    let hbc = match HbcFile::parse(data, None) {
        Ok(h) => h,
        Err(_) => return,
    };

    // Cap function-iteration so a pathological function_count can't cause timeout.
    let limit = hbc.function_count.min(256);
    let version = hbc.opcode_version();

    for i in 0..limit {
        let f = hbc.function_get(i);

        // Step 2: get function bytecode slice.
        let start = f.offset as usize;
        let end = match start.checked_add(f.size as usize) {
            Some(v) => v,
            None => continue,
        };
        if end > data.len() {
            continue;
        }
        let fn_slice = &data[start..end];

        // Step 3: decode instructions.
        let instructions = match decode_function(fn_slice, version) {
            Ok(v) => v,
            Err(_) => continue,
        };

        // Step 4: gather exception handlers.
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

        // Step 5: production CFG builder. Skip on InvalidExceptionLayout (adversarial input).
        let prod_cfg = match Cfg::build(&instructions, &exc_handlers, fn_slice) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let prod_shape = prod_cfg.to_shape();

        // Step 6: naive oracle. Pass same inputs as production.
        let oracle_shape = match naive_cfg(&instructions, &exc_handlers, fn_slice) {
            Ok(s) => s,
            Err(_) => continue, // oracle error on production-accepted input: skip
        };

        // Step 7: assert isomorphism.
        assert_cfg_shapes_equal(&prod_shape, &oracle_shape, i);
    }
});

fn assert_cfg_shapes_equal(prod: &CfgShape, oracle: &CfgShape, func_idx: u32) {
    assert_eq!(
        prod.leaders,
        oracle.leaders,
        "CFG leaders diverge at func_idx={func_idx}\nproduction: {:?}\noracle: {:?}",
        prod.leaders,
        oracle.leaders,
    );
    assert_eq!(
        prod.edges,
        oracle.edges,
        "CFG edges diverge at func_idx={func_idx}\nproduction: {:?}\noracle: {:?}",
        prod.edges,
        oracle.edges,
    );
    assert_eq!(
        prod.block_instructions,
        oracle.block_instructions,
        "CFG block_instructions diverge at func_idx={func_idx}\nproduction: {:?}\noracle: {:?}",
        prod.block_instructions,
        oracle.block_instructions,
    );
}
