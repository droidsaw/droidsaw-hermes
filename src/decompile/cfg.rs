//! Control flow graph construction from decoded instructions.
#![allow(missing_docs, reason = "internal")]
#![cfg_attr(
    not(test),
    allow(
        clippy::indexing_slicing,
        clippy::string_slice,
        reason = "PROOF: CFG build iterates over decoded instructions where each operand offset is bounded by the instruction-stream length (validated at decode-time). BlockIdx values are minted by the leader-detection pass and used only as indices into the just-constructed `blocks: Vec<BasicBlock>`. Successor/predecessor edge lists carry only minted indices. Same uniformity as dex/cfg.rs which has been refined to per-impl/per-fn allows. v1.x refinement candidate (~26 sites)."
    )
)]

use std::collections::{BTreeMap, BTreeSet};

use super::decode::{DecodedInst, Operand};
use crate::HermesError;

pub type BlockId = u32;

/// Offset of the instruction immediately following `inst`.
/// `None` when `inst.offset + inst.size` would wrap u32 — only reachable via
/// an adversarially synthesized `DecodedInst` (legitimate HBC bytecode is
/// < 4 GiB and the parser rejects out-of-range offsets).
fn inst_next_offset(inst: &DecodedInst) -> Option<u32> {
    inst.offset.checked_add(u32::from(inst.size))
}

/// Signed-relative branch target (`base + rel`). Returns `None` on wrap.
/// Call sites either skip the target (switch-table walkers — bogus targets
/// can't match any block anyway) or surface typed-Err at the boundary.
fn signed_target(base: u32, rel: i32) -> Option<u32> {
    base.checked_add_signed(rel)
}

/// Exception handler range.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ExcHandler {
    pub start: u32,
    pub end: u32,
    pub target: u32,
}

/// A basic block in the control flow graph.
#[derive(Debug, serde::Serialize)]
pub struct BasicBlock {
    pub id: BlockId,
    pub start: u32, // first instruction offset
    pub end: u32,   // offset after last instruction
    pub instructions: Vec<DecodedInst>,
    pub successors: Vec<BlockId>,
    pub predecessors: Vec<BlockId>,
    pub exc_handler: Option<BlockId>, // catch block if inside try
    /// For StringSwitchImm: string IDs for each case (parallel to successors[1..]).
    pub switch_string_ids: Vec<u32>,
}

/// The complete control flow graph for a function.
#[derive(Debug, serde::Serialize)]
pub struct Cfg {
    pub blocks: BTreeMap<BlockId, BasicBlock>,
    pub entry: BlockId,
    pub block_order: Vec<BlockId>, // topological/RPO order
    /// Reverse exception map: catch block → try-region blocks that flow to it on throw.
    /// Used by SSA as implicit predecessors for phi insertion (not added to
    /// successors/predecessors to avoid breaking structurer merge-point detection).
    pub exc_predecessors: BTreeMap<BlockId, Vec<BlockId>>,
}

#[allow(clippy::as_conversions, clippy::cast_possible_truncation, clippy::cast_sign_loss, reason = "CFG construction `as`-cast cluster — all sites are bounded by construction. `inst.offset` + `inst.size` are u32 parser fields (≤4 GiB file bound); `str_table_off` / `jt_offset` are u32 operand fields; `j as usize` iterates a clamped `num_entries` (clamp(0, 65536)); `min_case as i64` / `max_case as i64` / `rel as i64` are i32 widens (all via `From` would also work; kept as `as` because they're wrapped in the saturating-arith chain that the codebase's posture keeps). `clamp(0, 65536) as u32` truncation/sign-loss are statically eliminated by the clamp range. The block-level allow matches the `ipa.rs` precedent for uniform clusters.")]
impl Cfg {
    /// Build a CFG from decoded instructions and exception handlers.
    /// `bytecodes` is the raw function bytecode for reading SwitchImm jump tables.
    ///
    /// Postconditions: for every edge (A->B), B appears in A's successors and A
    /// appears in B's predecessors. Every instruction belongs to exactly one block.
    ///
    /// Returns `HermesError::InvalidExceptionLayout` when the exception-handler
    /// layout would place a catch target ahead of its try-region blocks in RPO
    /// (see Invariant 7 below). Parser-accepted HBC from well-formed bundles
    /// does not hit this; adversarial input can.
    pub fn build(
        instructions: &[DecodedInst],
        exc_handlers: &[ExcHandler],
        bytecodes: &[u8],
    ) -> std::result::Result<Self, HermesError> {
        if instructions.is_empty() {
            let mut blocks = BTreeMap::new();
            blocks.insert(
                0,
                BasicBlock {
                    id: 0,
                    start: 0,
                    end: 0,
                    instructions: vec![],
                    successors: vec![],
                    predecessors: vec![],
                    exc_handler: None,
                    switch_string_ids: vec![],
                },
            );
            let cfg = Cfg {
                blocks,
                entry: 0,
                block_order: vec![0],
                exc_predecessors: BTreeMap::new(),
            };
            droidsaw_common::diag::stage_dump("cfg", &cfg);
            return Ok(cfg);
        }

        // Step 1: Find block boundaries (addresses where new blocks start)
        let mut boundaries = BTreeSet::new();
        boundaries.insert(0u32); // entry

        for inst in instructions {
            let Some(next) = inst_next_offset(inst) else {
                return Err(HermesError::ArithmeticOverflow {
                    context: "instruction next-offset",
                });
            };

            if inst.is_terminator() {
                boundaries.insert(next);
            }

            // Jump targets start new blocks
            if let Some(target) = inst.branch_target() {
                boundaries.insert(target);
            }

            // StringSwitchImm: (Reg, UInt(hashCount), UInt(strTableOffset), Addr(default), UInt(numCases))
            // Table entries: (stringID: u32be, jumpOffset: i32be) — 8 bytes each, big-endian
            if inst.name == "StringSwitchImm" {
                if let Some(Operand::Addr(default_rel)) = inst.operands.get(3)
                    && let Some(default_target) = signed_target(inst.offset, *default_rel)
                {
                    boundaries.insert(default_target);
                }
                if let (Some(Operand::UInt(str_table_off)), Some(Operand::UInt(num_cases))) =
                    (inst.operands.get(2), inst.operands.get(4))
                {
                    let num = (*num_cases).min(65536);
                    let Some(table_start) =
                        (inst.offset as usize).checked_add(*str_table_off as usize)
                    else {
                        continue; // overflow — skip malformed table
                    };
                    for j in 0..num {
                        let Some(entry_off) =
                            (j as usize).checked_mul(8).and_then(|o| table_start.checked_add(o))
                        else {
                            break; // overflow — rest of table unreachable
                        };
                        let Some(entry_end) = entry_off.checked_add(8) else {
                            break;
                        };
                        if entry_end <= bytecodes.len() {
                            let rel = i32::from_be_bytes([
                                bytecodes[entry_off.wrapping_add(4)],
                                bytecodes[entry_off.wrapping_add(5)],
                                bytecodes[entry_off.wrapping_add(6)],
                                bytecodes[entry_off.wrapping_add(7)],
                            ]);
                            if let Some(target_addr) = signed_target(inst.offset, rel) {
                                boundaries.insert(target_addr);
                            }
                        }
                    }
                }
            }
            // SwitchImm/UIntSwitchImm: all case targets
            // operands: Reg8, UInt32(jump_table_offset), Addr32(default), UInt32(min), UInt32(max)
            else if inst.name.contains("SwitchImm") {
                if let Some(Operand::Addr(default_rel)) = inst.operands.get(2)
                    && let Some(default_target) = signed_target(inst.offset, *default_rel)
                {
                    boundaries.insert(default_target);
                }
                if let (
                    Some(Operand::UInt(jt_offset)),
                    Some(Operand::UInt(min_case)),
                    Some(Operand::UInt(max_case)),
                ) = (
                    inst.operands.get(1),
                    inst.operands.get(3),
                    inst.operands.get(4),
                ) {
                    // `num_entries` uses saturating i64 because the cases are i64-span
                    // differences; clamp(0, 65536) means the cast back to u32 can
                    // never overflow u32::MAX.
                    let num_entries = i64::from(*max_case)
                        .saturating_sub(i64::from(*min_case))
                        .saturating_add(1)
                        .clamp(0, 65536) as u32;
                    let Some(jt_start) = (inst.offset as usize).checked_add(*jt_offset as usize)
                    else {
                        continue; // overflow — skip malformed table
                    };
                    for j in 0..num_entries {
                        let Some(entry_off) =
                            (j as usize).checked_mul(4).and_then(|o| jt_start.checked_add(o))
                        else {
                            break;
                        };
                        let Some(entry_end) = entry_off.checked_add(4) else {
                            break;
                        };
                        if entry_end <= bytecodes.len() {
                            let rel = i32::from_le_bytes([
                                bytecodes[entry_off],
                                // WHY: `entry_end = entry_off + 4` validated above; +1/+2/+3 in-bounds.
                                bytecodes[entry_off.wrapping_add(1)],
                                bytecodes[entry_off.wrapping_add(2)],
                                bytecodes[entry_off.wrapping_add(3)],
                            ]);
                            if let Some(target_addr) = signed_target(inst.offset, rel) {
                                boundaries.insert(target_addr);
                            }
                        }
                    }
                }
            }
        }

        // Exception handler boundaries
        for eh in exc_handlers {
            boundaries.insert(eh.start);
            boundaries.insert(eh.end);
            boundaries.insert(eh.target);
        }

        // Step 2: Create blocks by splitting instructions at boundaries
        let boundary_vec: Vec<u32> = boundaries.iter().copied().collect();
        let mut offset_to_block: BTreeMap<u32, BlockId> = BTreeMap::new();

        // Map instruction offsets to the block they belong to
        for inst in instructions {
            // Find which block this instruction belongs to
            let block_start = match boundary_vec.binary_search(&inst.offset) {
                Ok(i) => boundary_vec[i],
                // WHY: guard `i > 0` proves `i - 1` never wraps.
                #[allow(clippy::arithmetic_side_effects, reason = "guard `i > 0` proves `i - 1` never wraps.")]
                Err(i) if i > 0 => boundary_vec[i - 1],
                _ => 0,
            };
            offset_to_block.entry(block_start).or_insert(block_start);
        }

        // Assign block IDs and collect instructions per block
        let mut blocks = BTreeMap::new();
        let mut current_block_insts: Vec<DecodedInst> = Vec::new();
        let mut current_start: u32 = 0;

        for inst in instructions {
            if boundaries.contains(&inst.offset) && !current_block_insts.is_empty() {
                // Finish previous block
                let id = current_start;
                let end = inst.offset;
                blocks.insert(
                    id,
                    BasicBlock {
                        id,
                        start: current_start,
                        end,
                        instructions: std::mem::take(&mut current_block_insts),
                        successors: vec![],
                        predecessors: vec![],
                        exc_handler: None,
                        switch_string_ids: vec![],
                    },
                );
                current_start = inst.offset;
            }
            if current_block_insts.is_empty() {
                current_start = inst.offset;
            }
            current_block_insts.push(inst.clone());
        }

        // Finish last block
        if let Some(last) = current_block_insts.last() {
            let id = current_start;
            let end = inst_next_offset(last).ok_or(HermesError::ArithmeticOverflow {
                context: "final block end offset",
            })?;
            blocks.insert(
                id,
                BasicBlock {
                    id,
                    start: current_start,
                    end,
                    instructions: current_block_insts,
                    successors: vec![],
                    predecessors: vec![],
                    exc_handler: None,
                    switch_string_ids: vec![],
                },
            );
        }

        // Step 3: Add edges
        let block_ids: Vec<BlockId> = blocks.keys().copied().collect();

        for i in 0..block_ids.len() {
            let bid = block_ids[i];
            let block = &blocks[&bid];
            let last = match block.instructions.last() {
                Some(inst) => inst,
                None => continue,
            };

            let mut succs = Vec::new();

            if last.is_unconditional_jump() {
                if let Some(target) = last.branch_target()
                    && blocks.contains_key(&target)
                {
                    succs.push(target);
                }
            } else if last.is_conditional_branch() {
                // Conditional: two successors — target and fallthrough
                if let Some(target) = last.branch_target()
                    && blocks.contains_key(&target)
                {
                    succs.push(target);
                }
                // Fallthrough
                if let Some(next) = inst_next_offset(last)
                    && blocks.contains_key(&next)
                {
                    succs.push(next);
                }
            } else if last.name == "StringSwitchImm" {
                // StringSwitchImm: (Reg, UInt(hashCount), UInt(strTableOffset), Addr(default), UInt(numCases))
                // String table entries: (stringID: u32be, jumpOffset: i32be) — 8 bytes each, big-endian
                if let Some(Operand::Addr(default_rel)) = last.operands.get(3)
                    && let Some(default_target) = signed_target(last.offset, *default_rel)
                    && blocks.contains_key(&default_target)
                {
                    succs.push(default_target);
                }
                let mut string_ids = Vec::new();
                if let (Some(Operand::UInt(str_table_off)), Some(Operand::UInt(num_cases))) =
                    (last.operands.get(2), last.operands.get(4))
                {
                    let num = (*num_cases).min(65536);
                    // overflow → 0; bounds check in the inner loop will skip
                    let table_start = (last.offset as usize)
                        .checked_add(*str_table_off as usize)
                        .unwrap_or_default();
                    for j in 0..num {
                        let Some(entry_off) =
                            (j as usize).checked_mul(8).and_then(|o| table_start.checked_add(o))
                        else {
                            break;
                        };
                        let Some(entry_end) = entry_off.checked_add(8) else {
                            break;
                        };
                        if entry_end <= bytecodes.len() {
                            let str_id = u32::from_be_bytes([
                                bytecodes[entry_off],
                                bytecodes[entry_off.wrapping_add(1)],
                                bytecodes[entry_off.wrapping_add(2)],
                                bytecodes[entry_off.wrapping_add(3)],
                            ]);
                            let rel = i32::from_be_bytes([
                                bytecodes[entry_off.wrapping_add(4)],
                                bytecodes[entry_off.wrapping_add(5)],
                                bytecodes[entry_off.wrapping_add(6)],
                                bytecodes[entry_off.wrapping_add(7)],
                            ]);
                            string_ids.push(str_id);
                            if let Some(target) = signed_target(last.offset, rel)
                                && blocks.contains_key(&target)
                                && !succs.contains(&target)
                            {
                                succs.push(target);
                            }
                        }
                    }
                }
                if let Some(b) = blocks.get_mut(&bid) {
                    b.switch_string_ids = string_ids;
                }
            } else if last.name.contains("SwitchImm") {
                // SwitchImm/UIntSwitchImm: default target + all case targets
                // (Reg, UInt(jtOffset), Addr(default), UInt(min), UInt(max))
                if let Some(Operand::Addr(default_rel)) = last.operands.get(2)
                    && let Some(default_target) = signed_target(last.offset, *default_rel)
                    && blocks.contains_key(&default_target)
                {
                    succs.push(default_target);
                }
                if let (
                    Some(Operand::UInt(jt_offset)),
                    Some(Operand::UInt(min_case)),
                    Some(Operand::UInt(max_case)),
                ) = (
                    last.operands.get(1),
                    last.operands.get(3),
                    last.operands.get(4),
                ) {
                    let num_entries = i64::from(*max_case)
                        .saturating_sub(i64::from(*min_case))
                        .saturating_add(1)
                        .clamp(0, 65536) as u32;
                    // overflow → 0; bounds check in the inner loop will skip
                    let jt_start = (last.offset as usize)
                        .checked_add(*jt_offset as usize)
                        .unwrap_or_default();
                    for j in 0..num_entries {
                        let Some(entry_off) =
                            (j as usize).checked_mul(4).and_then(|o| jt_start.checked_add(o))
                        else {
                            break;
                        };
                        let Some(entry_end) = entry_off.checked_add(4) else {
                            break;
                        };
                        if entry_end <= bytecodes.len() {
                            let rel = i32::from_le_bytes([
                                bytecodes[entry_off],
                                bytecodes[entry_off.wrapping_add(1)],
                                bytecodes[entry_off.wrapping_add(2)],
                                bytecodes[entry_off.wrapping_add(3)],
                            ]);
                            if let Some(target) = signed_target(last.offset, rel)
                                && blocks.contains_key(&target)
                                && !succs.contains(&target)
                            {
                                succs.push(target);
                            }
                        }
                    }
                }
            } else if last.is_return() || last.is_throw() || last.name == "Unreachable" {
                // No successors
            } else {
                // Fallthrough to next block
                // WHY: `i < block_ids.len()` is the loop bound; `i + 1` can only overflow
                // when `len == usize::MAX`, which is unreachable for any realized Vec.
                #[allow(clippy::arithmetic_side_effects, reason = "`i < block_ids.len()` is the loop bound; `i + 1` can only overflow when `len == usize::MAX`, which is unreachable for any realized Vec.")]
                if i + 1 < block_ids.len() {
                    #[allow(clippy::arithmetic_side_effects, reason = "Parser-bounded arithmetic; surrounding loop guards ensure offsets remain within the slice (see preceding PROOF in this function or block).")]
                    succs.push(block_ids[i + 1]);
                }
            }

            if let Some(b) = blocks.get_mut(&bid) {
                b.successors = succs;
            }
        }

        // Build predecessor lists
        let edges: Vec<(BlockId, BlockId)> = blocks
            .values()
            .flat_map(|b| b.successors.iter().map(move |&s| (b.id, s)))
            .collect();
        for (from, to) in edges {
            if let Some(block) = blocks.get_mut(&to) {
                block.predecessors.push(from);
            }
        }

        // Step 4: Map exception handlers to blocks. Each handler's
        // `target` must match the start offset of some block exactly
        // (block IDs are derived from leader-detected instruction
        // starts). A non-matching target points into mid-instruction
        // operand bytes or past the last instruction — fail closed
        // rather than silent-skip.
        // Parser-side `ExceptionHandlerOutOfFunctionRange` already
        // filtered out-of-range targets; this catches the remaining
        // in-range-but-not-a-leader case.
        let valid_targets: BTreeSet<BlockId> = blocks.keys().copied().collect();
        for eh in exc_handlers {
            if !valid_targets.contains(&eh.target) {
                return Err(HermesError::InvalidExceptionHandlerTarget { target: eh.target });
            }
            let affected: Vec<BlockId> = blocks
                .values()
                .filter(|b| b.start >= eh.start && b.end <= eh.end)
                .map(|b| b.id)
                .collect();
            for bid in affected {
                if let Some(block) = blocks.get_mut(&bid) {
                    block.exc_handler = Some(eh.target);
                }
            }
        }

        // Step 5: Compute reverse post-order via iterative DFS.
        // `blocks` is guaranteed non-empty here: the `instructions.is_empty()`
        // branch above returns early, and otherwise step 2 inserts at least
        // one block (boundary `0` is always present in `boundaries`).
        let block_order = {
            let Some(&entry) = blocks.keys().next() else {
                let cfg = Cfg {
                    blocks,
                    entry: 0,
                    block_order: Vec::new(),
                    exc_predecessors: BTreeMap::new(),
                };
                droidsaw_common::diag::stage_dump("cfg", &cfg);
                return Ok(cfg);
            };
            let mut visited = BTreeSet::new();
            let mut post_order = Vec::with_capacity(blocks.len());
            let mut stack: Vec<(BlockId, bool)> = vec![(entry, false)];
            while let Some((bid, expanded)) = stack.pop() {
                if expanded {
                    post_order.push(bid);
                    continue;
                }
                if !visited.insert(bid) {
                    continue;
                }
                stack.push((bid, true)); // revisit for post-order
                if let Some(block) = blocks.get(&bid) {
                    for &s in block.successors.iter().rev() {
                        if !visited.contains(&s) {
                            stack.push((s, false));
                        }
                    }
                }
            }
            post_order.reverse();
            // Append unreachable blocks (catch handlers) at the end of RPO,
            // sorted by block ID for deterministic ordering. They must come
            // AFTER the main body so the structurer emits them inside
            // try-catch recovery, not before the function body.
            let mut unreachable: Vec<BlockId> = blocks
                .keys()
                .filter(|bid| !visited.contains(bid))
                .copied()
                .collect();
            unreachable.sort();
            post_order.extend(unreachable);
            post_order
        };

        // Invariant 7: every catch target must appear after all blocks that list
        // it as an `exc_handler`. The append-unreachable pass above enforces this
        // for catch blocks that normal control flow cannot reach. Adversarial HBC
        // can place an exception-handler target at an offset already reachable
        // from entry (via branch/fallthrough), in which case DFS visits it at its
        // natural RPO position and the structurer's try-catch emission ordering
        // precondition is violated. Report as typed `Err` rather than silently
        // producing a mis-ordered block_order.
        {
            let rpo_pos: BTreeMap<BlockId, usize> = block_order
                .iter()
                .enumerate()
                .map(|(i, b)| (*b, i))
                .collect();
            for b in blocks.values() {
                let Some(catch) = b.exc_handler else { continue };
                // PROOF: step 4 (above) only sets `exc_handler` to a target that
                // passes `valid_targets.contains(&eh.target)` — i.e., a key already
                // present in `blocks`. Step 5 builds `block_order` from every key in
                // `blocks` (DFS-reachable set ∪ unreachable-appended set), so
                // `rpo_pos` is keyed by exactly `blocks.keys()`. Therefore
                // `rpo_pos.contains_key(&catch)` is guaranteed; unwrap_or(usize::MAX)
                // is dead. Same invariant holds for `b.id` (b is from blocks.values()).
                debug_assert!(
                    rpo_pos.contains_key(&catch),
                    "exc_handler target {catch} not in rpo_pos — step-4 validation invariant violated"
                );
                debug_assert!(
                    rpo_pos.contains_key(&b.id),
                    "block id {} not in rpo_pos — block_order construction invariant violated",
                    b.id
                );
                let handler_pos = rpo_pos.get(&catch).copied().unwrap_or(usize::MAX);
                let try_pos = rpo_pos.get(&b.id).copied().unwrap_or(0);
                if try_pos >= handler_pos {
                    return Err(HermesError::InvalidExceptionLayout {
                        catch,
                        try_region: b.id,
                    });
                }
            }
        }

        // Build reverse exception map: catch_block → [try_region_blocks]
        let mut exc_predecessors: BTreeMap<BlockId, Vec<BlockId>> = BTreeMap::new();
        for block in blocks.values() {
            if let Some(catch_target) = block.exc_handler {
                exc_predecessors
                    .entry(catch_target)
                    .or_default()
                    .push(block.id);
            }
        }

        // PROOF: `block_order` is non-empty here: `blocks.keys().next() == None` already
        // returned early above (entry = 0, empty block_order). Reaching this point
        // guarantees `block_order.first()` is Some; `unwrap_or(0)` is dead.
        debug_assert!(!block_order.is_empty(), "block_order empty after non-empty blocks — unreachable");
        let cfg = Cfg {
            entry: block_order.first().copied().unwrap_or(0),
            blocks,
            block_order,
            exc_predecessors,
        };
        droidsaw_common::diag::stage_dump("cfg", &cfg);
        Ok(cfg)
    }

    /// Print the CFG for debugging.
    pub fn dump(&self) {
        for &bid in &self.block_order {
            let block = &self.blocks[&bid];
            let preds: Vec<String> = block
                .predecessors
                .iter()
                .map(|p| format!("0x{p:04x}"))
                .collect();
            let succs: Vec<String> = block
                .successors
                .iter()
                .map(|s| format!("0x{s:04x}"))
                .collect();
            // SEMANTICS-DEFAULT-EMPTY: `exc_handler` is None for blocks that are not
            // covered by any exception handler; absent → no catch annotation in dump.
            let exc = block
                .exc_handler
                .map(|e| format!(" catch→0x{e:04x}"))
                .unwrap_or_default();
            println!(
                "BB 0x{:04x} (preds: [{}], succs: [{}]{})",
                bid,
                preds.join(", "),
                succs.join(", "),
                exc,
            );
            for inst in &block.instructions {
                let ops: Vec<String> = inst
                    .operands
                    .iter()
                    .map(|op| match op {
                        super::decode::Operand::Reg(r) => format!("r{r}"),
                        super::decode::Operand::Reg32(r) => format!("r{r}"),
                        super::decode::Operand::UInt(v) => format!("{v}"),
                        super::decode::Operand::Int(v) => format!("{v}"),
                        super::decode::Operand::Double(v) => format!("{v}"),
                        super::decode::Operand::Addr(rel) => {
                            // Display-only dump; saturating math keeps the print readable
                            // even if the operand is out-of-range (adversarial input).
                            let t = i64::from(inst.offset).saturating_add(i64::from(*rel));
                            format!("→0x{t:04x}")
                        }
                    })
                    .collect();
                println!(
                    "    0x{:04x}: {} {}",
                    inst.offset,
                    inst.name,
                    ops.join(", ")
                );
            }
        }
    }
}
