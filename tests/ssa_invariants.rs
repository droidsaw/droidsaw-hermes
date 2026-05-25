// SPDX-License-Identifier: BSD-3-Clause

//! Deterministic unit coverage for `build_ssa` on a minimal v96 HBC.
//!
//! The fuzz target (`fuzz_ssa`) exercises `build_ssa` on adversarial input
//! but produces zero LCOV credit. This file provides always-on coverage via
//! a minimal v96 seed containing a single `Ret r0` function body that
//! reaches the core SSA construction path (linear single-block function).
//!
//! ## Minimal v96 seed layout (146 bytes)
//!
//! ```text
//! [0..8]     magic = HBC_MAGIC
//! [8..12]    version = 96
//! [12..32]   sha1 = 0x00 × 20 (not validated at parse time)
//! [32..36]   file_length = 146
//! [36..40]   global_code_index = 0
//! [40..44]   function_count = 1
//! [44..128]  remaining header fields = 0 (all counts/sizes zero)
//! [128..144] FunctionHeaders[0]: raw_offset=144, raw_byte_size=2, rest=0
//! [144..146] function body: [0x5C, 0x00]  (Ret r0)
//! ```
//!
//! V96 uses `V87to96Header` layout; `SmallFuncHeaderV96` is 16 bytes.
//! Opcode 0x5C is `Ret`, size=2 (opcode + register operand).
//! The function has no exception handlers (flags byte = 0x00).
//! `frame_size` is 0 for all pre-v97 headers.

use std::collections::BTreeSet;

use droidsaw_hermes::decompile::cfg::{Cfg, ExcHandler};
use droidsaw_hermes::decompile::decode::decode_function;
use droidsaw_hermes::decompile::ssa::build_ssa;
use droidsaw_hermes::parser::HbcFile;

fn minimal_v96_ret_seed() -> Vec<u8> {
    let mut buf = vec![0u8; 146];
    // magic (8 bytes) + version=96 (4 bytes)
    buf[0..8].copy_from_slice(&0x1F19_03C1_03BC_1FC6u64.to_le_bytes());
    buf[8..12].copy_from_slice(&96u32.to_le_bytes());
    // file_length=146 at offset 32; function_count=1 at offset 40
    buf[32..36].copy_from_slice(&146u32.to_le_bytes());
    buf[40..44].copy_from_slice(&1u32.to_le_bytes());
    // FunctionHeaders[0] at [128..144] (16-byte SmallFuncHeaderV96 bitfield):
    //   raw_offset=144 → bits 0..25; 144=0x90 fits in low byte
    //   raw_byte_size=2 → bits 32..47; 2 fits in byte[4]
    buf[128] = 0x90;
    buf[132] = 0x02;
    // Function body at [144..146]: Ret r0 (opcode 0x5C + register 0x00)
    buf[144] = 0x5C;
    buf[145] = 0x00;
    buf
}

/// Exercises `build_ssa` on a minimal v96 HBC containing a single `Ret r0`
/// function. Verifies three structural invariants:
///
/// 1. `block_order` covers all blocks (no block is silently dropped).
/// 2. `block_order` has no duplicate entries.
/// 3. Single-block function has no phi nodes (no merge points).
#[test]
fn build_ssa_single_ret_satisfies_structural_invariants() {
    let data = minimal_v96_ret_seed();

    let hbc = HbcFile::parse(&data, None)
        .expect("minimal v96 seed must parse cleanly");

    assert_eq!(hbc.function_count, 1, "seed must have exactly 1 function");

    let version = hbc.opcode_version();
    let f = hbc.function_get(0);

    let start = f.offset as usize;
    let end = start
        .checked_add(f.size as usize)
        .expect("f.offset + f.size must not overflow usize");
    assert!(
        end <= data.len(),
        "function body [{}..{}] must be within file bounds ({})",
        start,
        end,
        data.len()
    );

    let code = &data[start..end];
    let instructions = decode_function(code, version)
        .expect("Ret r0 body [0x5C, 0x00] must decode cleanly");

    let exc_handlers: Vec<ExcHandler> = (0..hbc.function_exception_count(0))
        .map(|j| {
            let eh = hbc.function_exception_get(0, j);
            ExcHandler { start: eh.start, end: eh.end, target: eh.target }
        })
        .collect();

    let cfg = Cfg::build(&instructions, &exc_handlers, code)
        .expect("CFG build must succeed for single Ret r0");

    let ssa = build_ssa(&cfg, f.frame_size)
        .expect("build_ssa must succeed on a single-Ret CFG");

    // Inv 1 + 2: block_order covers all blocks exactly once.
    let all_ids: BTreeSet<u32> = ssa.blocks.iter().map(|b| b.id).collect();
    let order_ids: BTreeSet<u32> = ssa.block_order.iter().copied().collect();
    assert_eq!(
        order_ids,
        all_ids,
        "block_order must cover all blocks: missing={:?} extra={:?}",
        all_ids.difference(&order_ids).collect::<Vec<_>>(),
        order_ids.difference(&all_ids).collect::<Vec<_>>(),
    );
    assert_eq!(
        ssa.block_order.len(),
        order_ids.len(),
        "block_order must have no duplicate entries",
    );

    // Inv 3: single-block function has no phi nodes at any block.
    for block in &ssa.blocks {
        assert!(
            block.phis.is_empty(),
            "single-block Ret function must have no phi nodes in block {}",
            block.id,
        );
    }
}
