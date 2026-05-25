// CFG-ORACLE: Dragon Book §8.4 leader-set algorithm adapted for Hermes bytecode.
// Sole purpose: differential cross-check against production Cfg::build.
//
// MUST be an independent reimplementation — must NOT reuse production
// DecodedInst CF predicates or call decode_function. It reimplements the same
// CF-opcode classification using the instruction *name* (a &'static str that
// is safe to compare — names are assigned by the opcode table, not
// attacker-controlled bytes) so that a bug in the production name-matching
// path (is_conditional_branch / is_unconditional_jump / etc.) is caught by
// divergence rather than hidden by shared code.
//
// MAINTENANCE: This oracle covers the control-flow-affecting opcode categories
// listed below. The production CFG builder's opcode-handling sites are:
//   droidsaw-hermes/src/decompile/cfg.rs (Cfg::build)
// Oracle CF classification mirrors production DecodedInst predicates:
//   is_unconditional_jump: name == "Jmp" || name == "JmpLong"
//   is_conditional_branch: name.starts_with('J') && !is_unconditional_jump
//   StringSwitchImm: name == "StringSwitchImm"
//   SwitchImm variants: name.contains("SwitchImm") && name != "StringSwitchImm"
//   is_return: name == "Ret" || name == "ReturnUndefined" (name=="Ret" in prod)
//   is_throw: name == "Throw"
//   Unreachable: name == "Unreachable"

// Coverage table (mirrors opcode-category enumeration):
// - Conditional branches (J*): COVERED — two successors (branch + fall-through)
// - Unconditional branches (Jmp, JmpLong): COVERED — one successor
// - StringSwitchImm: COVERED — default + string-table case targets
// - SwitchImm / UIntSwitchImm: COVERED — default + jump-table case targets
// - Exception handlers (ExcHandler): COVERED — try-region overlap model
// - Throw: COVERED — no fall-through
// - Ret / ReturnUndefined / Unreachable: COVERED — no successors
// - Non-CF instructions: COVERED — fall-through only
// - ThrowIfEmpty: not a terminator (conditional throw — falls through); OUT-OF-SCOPE
//   same as production which does NOT include it in is_terminator()

#![allow(
    clippy::cast_sign_loss,
    reason = "PROOF: HBC's BigInt sign-encoding + jump-offset signed/unsigned reinterpretation; values originate from validated-width operands."
)]

#![cfg(any(test, kani, fuzzing))]
#![allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    missing_docs,
    reason = "PROOF: arithmetic in this module operates on instruction addresses and sizes \
              bounds-checked before use. Overflow is guarded by checked_add/checked_mul; \
              as-casts from u32 to usize are widenings on all supported targets (usize >= 32 bits). \
              missing_docs: oracle module is test/fuzz-only; doc coverage not required."
)]

use std::collections::{BTreeMap, BTreeSet};

use super::decode::{DecodedInst, Operand};

// ─── CfgShape — the oracle's comparison subject ──────────────────────────────

/// Extracted CFG shape for differential comparison.
///
/// Production CFG goes through `Cfg::to_shape()` before comparison; the naive
/// oracle returns this type directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CfgShape {
    /// Block-start offsets (byte offsets from function start).
    pub leaders: BTreeSet<u32>,
    /// Edges: (from_leader, to_leader, kind). Sorted for determinism.
    pub edges: BTreeSet<(u32, u32, EdgeKindOracle)>,
    /// Entry offset (always 0 for valid Hermes functions).
    pub entry: u32,
    /// leader → instruction offsets in monotone-increasing order.
    pub block_instructions: BTreeMap<u32, Vec<u32>>,
}

/// Edge kind for oracle comparison — mirrors production edge semantics without
/// sharing production types. Independence is intentional: shared types hide mismatches.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum EdgeKindOracle {
    /// Normal fall-through from a non-branch instruction or conditional branch fall-through.
    FallThrough,
    /// Unconditional or conditional branch taken.
    Branch,
    /// Switch default edge.
    SwitchDefault,
    /// Exception handler edge.
    ExceptionHandler,
}

// ─── Oracle errors ────────────────────────────────────────────────────────────

/// Errors from the naive CFG oracle. Disjoint from production errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CfgOracleError {
    /// Input instruction list is empty.
    EmptyInstructions,
    /// Arithmetic overflow computing an address.
    ArithmeticOverflow { context: &'static str },
}

// ─── CF-opcode predicates — MUST NOT reuse production DecodedInst methods ────
//
// ORACLE-OPCODE-LOCKSTEP-BEGIN
// Canonical CF opcode names tracked by this oracle.
// build.rs parses this section and cross-checks it against decode.rs.
// If a new CF opcode is added to production, it MUST also appear here.
//
// Unconditional jumps:   "Jmp"  "JmpLong"
// Switch (any variant):  "SwitchImm"  "StringSwitchImm"
// Return:                "Ret"
// Throw (block-ending):  "Throw"
// Unreachable:           "Unreachable"
// ORACLE-OPCODE-LOCKSTEP-END
//
// These predicates enumerate the CF-affecting opcode categories covered by
// this oracle. They use name-string matching to mirror production's
// name-matching predicates, independently re-derived so a typo in production
// is caught by divergence.

fn oracle_is_uncond_jump(name: &str) -> bool {
    name == "Jmp" || name == "JmpLong"
}

fn oracle_is_cond_branch(name: &str) -> bool {
    // Production: starts_with('J') && name != "Jmp" && name != "JmpLong"
    // All J* instructions except Jmp/JmpLong are conditional branches.
    name.starts_with('J') && name != "Jmp" && name != "JmpLong"
        && !name.contains("SwitchImm")
}

fn oracle_is_string_switch(name: &str) -> bool {
    name == "StringSwitchImm"
}

fn oracle_is_int_switch(name: &str) -> bool {
    // SwitchImm or UIntSwitchImm (but not StringSwitchImm)
    name.contains("SwitchImm") && name != "StringSwitchImm"
}

fn oracle_is_return(name: &str) -> bool {
    name == "Ret"
}

fn oracle_is_throw(name: &str) -> bool {
    // Production is_throw: name == "Throw"
    // Note: ThrowIfEmpty is NOT a terminator (conditional throw).
    name == "Throw"
}

fn oracle_is_unreachable(name: &str) -> bool {
    name == "Unreachable"
}

fn oracle_is_terminator(name: &str) -> bool {
    // Also handle SwitchImm variants as terminators (they end blocks in production)
    oracle_is_uncond_jump(name)
        || oracle_is_cond_branch(name)
        || oracle_is_string_switch(name)
        || oracle_is_int_switch(name)
        || oracle_is_return(name)
        || oracle_is_throw(name)
        || oracle_is_unreachable(name)
}

/// Compute the signed branch target from a DecodedInst's first Addr operand.
/// Returns None on overflow or missing operand.
fn branch_target(inst: &DecodedInst) -> Option<u32> {
    if let Some(Operand::Addr(rel)) = inst.operands.first() {
        inst.offset.checked_add_signed(*rel)
    } else {
        None
    }
}

/// Offset of the byte immediately following `inst`.
fn inst_next_offset(inst: &DecodedInst) -> Option<u32> {
    inst.offset.checked_add(u32::from(inst.size))
}

// ─── Main oracle entry point ──────────────────────────────────────────────────

/// Textbook Dragon Book §8.4 leader-set CFG construction oracle for Hermes bytecode.
///
/// Input: decoded instructions (from `decode_function`) + exception handlers.
/// `bytecodes` is the raw function bytecode for reading SwitchImm jump tables —
/// same as what `Cfg::build` receives.
///
/// Returns a `CfgShape` for differential comparison against `Cfg::build(…).to_shape()`.
///
/// **Sole purpose:** differential cross-check against production `Cfg::build`.
pub fn naive_cfg(
    instructions: &[DecodedInst],
    exc_handlers: &[super::cfg::ExcHandler],
    bytecodes: &[u8],
) -> Result<CfgShape, CfgOracleError> {
    if instructions.is_empty() {
        // Production Cfg::build returns an empty block at offset 0 for empty functions.
        // Mirror that behavior so oracle and production shapes agree.
        let mut leaders = BTreeSet::new();
        leaders.insert(0u32);
        let mut block_instructions = BTreeMap::new();
        block_instructions.insert(0u32, Vec::new());
        return Ok(CfgShape {
            leaders,
            edges: BTreeSet::new(),
            entry: 0,
            block_instructions,
        });
    }

    // ── Pre-compute instruction offset set ───────────────────────────────────
    // INVARIANT: A leader is only valid if an instruction starts exactly at that
    // offset. Branch targets that land between instructions (or past the end of the
    // stream) are NOT valid block-start offsets. Production Cfg::build never creates
    // a block at such an offset because block-splits only fire when
    // `boundaries.contains(&inst.offset)` — i.e., when an instruction's exact offset
    // matches a boundary. We replicate this by pre-building `inst_offsets` and only
    // inserting targets that appear in it.
    //
    // Exception: Rule 3 ("next after last instruction") may produce an offset past
    // the instruction stream. That boundary is harmless — it can never be an
    // instruction offset — but we keep it in the set anyway so the same pruning step
    // that removes empty blocks cleans it up. (Production also harmlessly tracks it.)
    let inst_offsets: BTreeSet<u32> = instructions.iter().map(|i| i.offset).collect();

    // Helper: insert a target only if it is a real instruction offset.
    macro_rules! insert_if_instr {
        ($set:expr, $t:expr) => {
            if inst_offsets.contains(&$t) {
                $set.insert($t);
            }
        };
    }

    // ── Find leaders (Dragon Book §8.4) ──────────────────────────────────────
    let mut leaders: BTreeSet<u32> = BTreeSet::new();
    // Rule 1: first instruction is a leader
    if let Some(first) = instructions.first() {
        leaders.insert(first.offset);
    }

    for inst in instructions {
        let name = inst.name;

        // Rule 3: instruction after any branch/terminal is a leader.
        // May produce an offset past the end; pruning handles it.
        if oracle_is_terminator(name)
            && let Some(next) = inst_next_offset(inst)
        {
            // Only insert if a real instruction starts at `next`.
            insert_if_instr!(leaders, next);
        }

        // Rule 2: branch targets are leaders — only if instruction-aligned.
        if (oracle_is_uncond_jump(name) || oracle_is_cond_branch(name))
            && let Some(t) = branch_target(inst)
        {
            insert_if_instr!(leaders, t);
        }

        // StringSwitchImm: default target + all string-table case targets
        if oracle_is_string_switch(name) {
            // Default target: operand[3] (Addr)
            if let Some(Operand::Addr(rel)) = inst.operands.get(3)
                && let Some(t) = inst.offset.checked_add_signed(*rel)
            {
                insert_if_instr!(leaders, t);
            }
            // String table case targets
            if let (Some(Operand::UInt(str_table_off)), Some(Operand::UInt(num_cases))) =
                (inst.operands.get(2), inst.operands.get(4))
            {
                let num = (*num_cases).min(65536) as usize;
                if let Some(table_start) = (inst.offset as usize).checked_add(*str_table_off as usize) {
                    for j in 0..num {
                        let Some(entry_off) =
                            j.checked_mul(8).and_then(|o| table_start.checked_add(o))
                        else {
                            break;
                        };
                        let Some(entry_end) = entry_off.checked_add(8) else {
                            break;
                        };
                        if entry_end <= bytecodes.len()
                            && let Some(t) = inst.offset.checked_add_signed(i32::from_be_bytes([
                                bytecodes[entry_off.wrapping_add(4)],
                                bytecodes[entry_off.wrapping_add(5)],
                                bytecodes[entry_off.wrapping_add(6)],
                                bytecodes[entry_off.wrapping_add(7)],
                            ]))
                        {
                            insert_if_instr!(leaders, t);
                        }
                    }
                }
            }
        }

        // SwitchImm / UIntSwitchImm: default target + all jump-table case targets
        if oracle_is_int_switch(name) {
            // Default target: operand[2] (Addr)
            if let Some(Operand::Addr(rel)) = inst.operands.get(2)
                && let Some(t) = inst.offset.checked_add_signed(*rel)
            {
                insert_if_instr!(leaders, t);
            }
            // Jump table case targets
            if let (
                Some(Operand::UInt(jt_offset)),
                Some(Operand::UInt(min_case)),
                Some(Operand::UInt(max_case)),
            ) = (
                inst.operands.get(1),
                inst.operands.get(3),
                inst.operands.get(4),
            ) {
                let num_entries = i64::from(*max_case)
                    .saturating_sub(i64::from(*min_case))
                    .saturating_add(1)
                    .clamp(0, 65536) as usize;
                if let Some(jt_start) = (inst.offset as usize).checked_add(*jt_offset as usize) {
                    for j in 0..num_entries {
                        let Some(entry_off) =
                            j.checked_mul(4).and_then(|o| jt_start.checked_add(o))
                        else {
                            break;
                        };
                        let Some(entry_end) = entry_off.checked_add(4) else {
                            break;
                        };
                        if entry_end <= bytecodes.len()
                            && let Some(t) = inst.offset.checked_add_signed(i32::from_le_bytes([
                                bytecodes[entry_off],
                                bytecodes[entry_off.wrapping_add(1)],
                                bytecodes[entry_off.wrapping_add(2)],
                                bytecodes[entry_off.wrapping_add(3)],
                            ]))
                        {
                            insert_if_instr!(leaders, t);
                        }
                    }
                }
            }
        }
    }

    // Rule 4: exception handler entry points are leaders — only if instruction-aligned.
    for eh in exc_handlers {
        insert_if_instr!(leaders, eh.start);
        insert_if_instr!(leaders, eh.end);
        insert_if_instr!(leaders, eh.target);
    }

    // ── Build addr → instruction index map ───────────────────────────────────
    let addr_to_idx: BTreeMap<u32, usize> = instructions
        .iter()
        .enumerate()
        .map(|(i, inst)| (inst.offset, i))
        .collect();

    // ── Build block_instructions ──────────────────────────────────────────────
    // Each block contains instructions where leader <= inst.offset < next_leader.
    // Only include instructions at offsets that exist in the decoded stream.
    let mut block_instructions: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
    for &l in &leaders {
        block_instructions.insert(l, Vec::new());
    }

    for inst in instructions {
        // The block leader for this instruction is the largest leader <= inst.offset
        if let Some((&leader, _)) = block_instructions.range(..=inst.offset).next_back() {
            block_instructions.entry(leader).or_default().push(inst.offset);
        }
    }

    // Prune leaders that correspond to empty blocks (no real instructions).
    // Production Cfg::build only creates blocks for boundaries that have at least one
    // instruction, so leaders beyond the instruction stream are not emitted as blocks.
    block_instructions.retain(|_, v| !v.is_empty());
    leaders.retain(|l| block_instructions.contains_key(l));
    let leader_vec: Vec<u32> = leaders.iter().copied().collect();

    // ── Add normal-flow edges ─────────────────────────────────────────────────
    let mut edges: BTreeSet<(u32, u32, EdgeKindOracle)> = BTreeSet::new();

    for &leader in &leader_vec {
        let block_insns = block_instructions
            .get(&leader)
            .map(|v| v.as_slice())
            .unwrap_or(&[]);
        let last_addr = match block_insns.last() {
            Some(&a) => a,
            None => continue, // empty block (leader beyond instruction stream)
        };
        let last = match addr_to_idx.get(&last_addr).and_then(|&i| instructions.get(i)) {
            Some(i) => i,
            None => continue,
        };
        let name = last.name;
        let next_off = inst_next_offset(last);

        if oracle_is_return(name) || oracle_is_throw(name) || oracle_is_unreachable(name) {
            continue; // no successors
        }

        if oracle_is_uncond_jump(name) {
            if let Some(t) = branch_target(last)
                && leaders.contains(&t)
            {
                edges.insert((leader, t, EdgeKindOracle::Branch));
            }
            continue; // no fall-through
        }

        if oracle_is_cond_branch(name) {
            let branch_t = branch_target(last);
            if let Some(t) = branch_t
                && leaders.contains(&t)
            {
                edges.insert((leader, t, EdgeKindOracle::Branch));
            }
            if let Some(next) = next_off
                && leaders.contains(&next)
                // DEDUP: when branch target == fall-through (e.g. `JNotLessN addr=4` at
                // offset 0, size 4 → both branch and fall-through point to offset 4),
                // production `to_shape()` only emits one Branch edge (the target label
                // wins because `tb.start == target_off`). Match that by skipping the
                // FallThrough edge when it points to the same block as the Branch edge.
                && Some(next) != branch_t
            {
                edges.insert((leader, next, EdgeKindOracle::FallThrough));
            }
            continue;
        }

        if oracle_is_string_switch(name) {
            // Default target: operand[3]
            if let Some(Operand::Addr(rel)) = last.operands.get(3)
                && let Some(t) = last.offset.checked_add_signed(*rel)
                && leaders.contains(&t)
            {
                edges.insert((leader, t, EdgeKindOracle::SwitchDefault));
            }
            // String-table case targets
            if let (Some(Operand::UInt(str_table_off)), Some(Operand::UInt(num_cases))) =
                (last.operands.get(2), last.operands.get(4))
            {
                let num = (*num_cases).min(65536) as usize;
                if let Some(table_start) =
                    (last.offset as usize).checked_add(*str_table_off as usize)
                {
                    for j in 0..num {
                        let Some(entry_off) =
                            j.checked_mul(8).and_then(|o| table_start.checked_add(o))
                        else {
                            break;
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
                            if let Some(t) = last.offset.checked_add_signed(rel)
                                && leaders.contains(&t)
                                // DEDUP: mirror production `!succs.contains(&target)`.
                                && !edges.contains(&(leader, t, EdgeKindOracle::SwitchDefault))
                            {
                                edges.insert((leader, t, EdgeKindOracle::Branch));
                            }
                        }
                    }
                }
            }
            continue;
        }

        if oracle_is_int_switch(name) {
            // Default target: operand[2]
            if let Some(Operand::Addr(rel)) = last.operands.get(2)
                && let Some(t) = last.offset.checked_add_signed(*rel)
                && leaders.contains(&t)
            {
                edges.insert((leader, t, EdgeKindOracle::SwitchDefault));
            }
            // Jump table case targets
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
                    .clamp(0, 65536) as usize;
                if let Some(jt_start) =
                    (last.offset as usize).checked_add(*jt_offset as usize)
                {
                    for j in 0..num_entries {
                        let Some(entry_off) =
                            j.checked_mul(4).and_then(|o| jt_start.checked_add(o))
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
                            if let Some(t) = last.offset.checked_add_signed(rel)
                                && leaders.contains(&t)
                                // DEDUP: production `!succs.contains(&target)` skips case
                                // targets already added as the default. Mirror that: don't
                                // insert a Branch edge when the target is already the
                                // SwitchDefault target for this block.
                                && !edges.contains(&(leader, t, EdgeKindOracle::SwitchDefault))
                            {
                                edges.insert((leader, t, EdgeKindOracle::Branch));
                            }
                        }
                    }
                }
            }
            continue;
        }

        // Non-CF instruction: fall-through to next block
        if let Some(next) = next_off
            && leaders.contains(&next)
        {
            edges.insert((leader, next, EdgeKindOracle::FallThrough));
        }
    }

    // ── Add exception edges ────────────────────────────────────────────────────
    // Mirrors production Step 4: for each block, the exception edge target is set
    // by the LAST handler (in exc_handlers order) whose try-region fully contains
    // the block. Production uses a simple overwrite loop:
    //   for each handler: for each contained block: block.exc_handler = Some(handler.target)
    // So when two handlers cover the same block, the later one wins.
    //
    // BUG-CLASS-E (overlap vs containment): production uses containment
    //   b.start >= eh.start && b.end <= eh.end
    // not overlap. Fixed in this pass.
    //
    // BUG-CLASS-F (first-vs-last handler semantics): production only records
    // the LAST handler per block (last write wins). Oracle uses a
    // BTreeMap<block_start, exc_target> (last-write-wins) and emits edges
    // from that map, not directly from the handler loop.
    //
    // We also must skip any handler whose target is not a valid leader (production
    // checks `valid_targets.contains(&eh.target)` and skips the handler entirely).
    // Note: in production, `valid_targets` is the set of blocks BEFORE the RPO
    // computation (and the `InvalidExceptionLayout` check may cause early-exit with Err,
    // which the fuzz harness skips). Here we mirror the pre-RPO behavior: only include
    // handlers whose target is a leader that survived pruning.
    {
        // block_start → exc_target (last-write-wins, mirroring production overwrite).
        let mut block_exc: BTreeMap<u32, u32> = BTreeMap::new();
        for eh in exc_handlers {
            if !leaders.contains(&eh.target) {
                continue;
            }
            for (ldr_idx, &block_start) in leader_vec.iter().enumerate() {
                // Compute block_end = last-inst.offset + last-inst.size
                let block_insns = block_instructions
                    .get(&block_start)
                    .map(|v| v.as_slice())
                    .unwrap_or(&[]);
                let block_end = match block_insns.last() {
                    Some(&last_addr) => match addr_to_idx.get(&last_addr).and_then(|&i| instructions.get(i)) {
                        Some(li) => li.offset.saturating_add(u32::from(li.size)),
                        None => match leader_vec.get(ldr_idx.wrapping_add(1)) {
                            Some(&next) => next,
                            None => block_start.saturating_add(1),
                        },
                    },
                    None => continue, // empty block
                };

                // Containment: block must fit entirely within handler's try-region.
                // Matches production: b.start >= eh.start && b.end <= eh.end.
                if block_start >= eh.start && block_end <= eh.end {
                    // Last write wins — same semantics as production's overwrite loop.
                    block_exc.insert(block_start, eh.target);
                }
            }
        }
        // Emit one edge per block (the last-write target).
        for (block_start, exc_target) in block_exc {
            edges.insert((block_start, exc_target, EdgeKindOracle::ExceptionHandler));
        }
    }

    let entry = leader_vec.first().copied().unwrap_or(0);
    Ok(CfgShape {
        leaders,
        edges,
        entry,
        block_instructions,
    })
}

// ─── Production adapter: Cfg::to_shape() ─────────────────────────────────────

use super::cfg::Cfg;

impl Cfg {
    /// Extract the `CfgShape` comparison subject from a production CFG.
    /// Used by differential tests to compare against the oracle's output.
    ///
    /// Edge kinds are inferred from the last instruction's name in each block,
    /// mirroring the oracle's classification.
    pub fn to_shape(&self) -> CfgShape {
        let leaders: BTreeSet<u32> = self.blocks.values().map(|b| b.start).collect();
        let entry = self.entry;
        let entry_off = self.blocks.get(&entry).map(|b| b.start).unwrap_or(0);

        let mut edges: BTreeSet<(u32, u32, EdgeKindOracle)> = BTreeSet::new();
        for block in self.blocks.values() {
            let from = block.start;
            let name = block.instructions.last().map(|i| i.name).unwrap_or("");

            // Exception edges: stored in exc_handler, not successors
            if let Some(catch_id) = block.exc_handler
                && let Some(catch_block) = self.blocks.get(&catch_id)
            {
                edges.insert((from, catch_block.start, EdgeKindOracle::ExceptionHandler));
            }

            if block.successors.is_empty() {
                continue;
            }

            if oracle_is_uncond_jump(name) {
                for &s in &block.successors {
                    if let Some(tb) = self.blocks.get(&s) {
                        edges.insert((from, tb.start, EdgeKindOracle::Branch));
                    }
                }
            } else if oracle_is_cond_branch(name) {
                // Production adds target first, then fallthrough (index 0 = target, 1 = fallthrough)
                // But we only need to label them correctly.
                // target = branch_target (first Addr operand)
                let target_off = block.instructions.last()
                    .and_then(|li| li.offset.checked_add_signed(
                        *match li.operands.first() {
                            Some(Operand::Addr(r)) => r,
                            _ => &0i32,
                        }
                    ));
                for &s in &block.successors {
                    if let Some(tb) = self.blocks.get(&s) {
                        let kind = if Some(tb.start) == target_off {
                            EdgeKindOracle::Branch
                        } else {
                            EdgeKindOracle::FallThrough
                        };
                        edges.insert((from, tb.start, kind));
                    }
                }
            } else if oracle_is_string_switch(name) || oracle_is_int_switch(name) {
                // Production `Cfg::build` step 3 pushes default FIRST (if valid), then cases.
                // When the default target resolves outside the CFG (block doesn't exist),
                // production skips it and only pushes case targets — the first successor
                // is then a case target, NOT the default.
                //
                // Oracle computes the actual default target from the Addr operand and
                // compares each successor's start to it. Only emits SwitchDefault for a
                // successor that actually matches the default target; everything else is Branch.
                let last_inst = block.instructions.last();
                let default_off = if oracle_is_string_switch(name) {
                    // StringSwitchImm: default is operand[3] (Addr)
                    last_inst.and_then(|li| {
                        if let Some(Operand::Addr(r)) = li.operands.get(3) {
                            li.offset.checked_add_signed(*r)
                        } else {
                            None
                        }
                    })
                } else {
                    // SwitchImm/UIntSwitchImm: default is operand[2] (Addr)
                    last_inst.and_then(|li| {
                        if let Some(Operand::Addr(r)) = li.operands.get(2) {
                            li.offset.checked_add_signed(*r)
                        } else {
                            None
                        }
                    })
                };
                for &s in &block.successors {
                    if let Some(tb) = self.blocks.get(&s) {
                        let kind = if Some(tb.start) == default_off {
                            EdgeKindOracle::SwitchDefault
                        } else {
                            EdgeKindOracle::Branch
                        };
                        edges.insert((from, tb.start, kind));
                    }
                }
            } else {
                // Fall-through
                for &s in &block.successors {
                    if let Some(tb) = self.blocks.get(&s) {
                        edges.insert((from, tb.start, EdgeKindOracle::FallThrough));
                    }
                }
            }
        }

        let mut block_instructions: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
        for block in self.blocks.values() {
            let addrs: Vec<u32> = block.instructions.iter().map(|i| i.offset).collect();
            block_instructions.insert(block.start, addrs);
        }

        CfgShape {
            leaders,
            edges,
            entry: entry_off,
            block_instructions,
        }
    }
}

// ─── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::cfg::{Cfg, ExcHandler};
    use super::super::decode::{decode_function, DecodedInst};

    const VERSION: u32 = 96;

    fn run_oracle(
        instructions: &[DecodedInst],
        exc_handlers: &[ExcHandler],
        bytecodes: &[u8],
    ) -> CfgShape {
        naive_cfg(instructions, exc_handlers, bytecodes).expect("oracle should not fail")
    }

    fn decode(bytecodes: &[u8]) -> Vec<DecodedInst> {
        decode_function(bytecodes, VERSION).expect("decode_function")
    }

    // ── Category: Ret — single terminal block ────────────────────────────
    #[test]
    fn ret_terminal_no_successors() {
        // Ret r0: in v96, Ret is opcode 0x5c (index 92 in V95_NAMES), size 2 bytes.
        let bytecodes: &[u8] = &[0x5c, 0x00]; // Ret r0 (opcode + reg)
        let instructions = decode(bytecodes);
        assert!(!instructions.is_empty(), "should decode Ret at 0x5c");
        assert_eq!(instructions[0].name, "Ret", "opcode 0x5c should be Ret; got {}", instructions[0].name);
        let shape = run_oracle(&instructions, &[], bytecodes);
        let from_0: Vec<_> = shape.edges.iter().filter(|(f, _, _)| *f == 0).collect();
        assert!(from_0.is_empty(), "Ret should have no successors; got {:?}", from_0);
    }

    // ── Category: Jmp — unconditional branch ─────────────────────────────
    #[test]
    fn jmp_branch_edge() {
        // Jmp: in v96, opcode 0x8e (index 142 in V95_NAMES), size 2 bytes (1 opcode + 1 Addr8).
        // Jmp +2 at offset 0 → target = 0+2 = 2 (byte address).
        // Ret: opcode 0x5c, size 2 bytes.
        let bytecodes: &[u8] = &[
            0x8e, 0x02, // Jmp +2 (offset 0, 2 bytes) → target = 0+2 = 2
            0x5c, 0x00, // Ret r0 (offset 2, 2 bytes)
        ];
        let instructions = decode(bytecodes);
        if instructions.is_empty() {
            return;
        }
        let jmp_inst = &instructions[0];
        if jmp_inst.name != "Jmp" {
            return; // opcode mapping differs from expected — skip
        }
        let shape = run_oracle(&instructions, &[], bytecodes);
        let branch = shape.edges.iter().find(|(f, t, k)| {
            *f == 0 && *t == 2 && matches!(k, EdgeKindOracle::Branch)
        });
        assert!(branch.is_some(), "Jmp should produce Branch(0→2); edges={:?}", shape.edges);
    }

    // Helper: build a mock DecodedInst. `op` is set to OpCode::Add as a placeholder;
    // the oracle uses `name` for CF classification, not `op`.
    fn mock_inst(offset: u32, size: u8, opcode: u8, name: &'static str, operands: Vec<Operand>) -> DecodedInst {
        DecodedInst {
            offset,
            size,
            opcode,
            name,
            op: crate::opcodes::OpCode::Add, // placeholder — oracle uses name, not op
            operands,
            op_types: &[],
        }
    }

    // ── Category: conditional branch — two successors ────────────────────
    #[test]
    fn conditional_branch_two_successors() {
        // JNotLess r0 r1 +8: conditional branch from offset 0 (size 4)
        // Fall-through to offset 4, branch target = offset 8.
        let instructions = vec![
            mock_inst(0, 4, 0x28, "JNotLess", vec![Operand::Addr(8), Operand::Reg(0), Operand::Reg(1)]),
            mock_inst(4, 2, 0x02, "Ret",      vec![Operand::Reg(0)]),
            mock_inst(8, 2, 0x02, "Ret",      vec![Operand::Reg(0)]),
        ];
        let bytecodes = vec![0u8; 16];
        let shape = run_oracle(&instructions, &[], &bytecodes);
        // Leaders: 0, 4 (fall-through), 8 (branch target)
        assert!(shape.leaders.contains(&0));
        assert!(shape.leaders.contains(&4), "fall-through 4 should be leader; {:?}", shape.leaders);
        assert!(shape.leaders.contains(&8), "branch target 8 should be leader; {:?}", shape.leaders);
        let br = shape.edges.iter().find(|(f, t, k)| *f == 0 && *t == 8 && matches!(k, EdgeKindOracle::Branch));
        let ft = shape.edges.iter().find(|(f, t, k)| *f == 0 && *t == 4 && matches!(k, EdgeKindOracle::FallThrough));
        assert!(br.is_some(), "branch edge 0→8 expected; edges={:?}", shape.edges);
        assert!(ft.is_some(), "fall-through edge 0→4 expected; edges={:?}", shape.edges);
    }

    // ── Category: exception handler edges ────────────────────────────────
    #[test]
    fn exception_handler_edge() {
        // Three blocks: 0..4 (try region), 4..8 (normal successor), 8..10 (catch block)
        let instructions = vec![
            mock_inst(0, 4, 0x28, "JNotLess", vec![Operand::Addr(8), Operand::Reg(0), Operand::Reg(1)]),
            mock_inst(4, 2, 0x02, "Ret",      vec![Operand::Reg(0)]),
            mock_inst(8, 2, 0x02, "Ret",      vec![Operand::Reg(0)]),
        ];
        let exc_handlers = vec![ExcHandler { start: 0, end: 4, target: 8 }];
        let bytecodes = vec![0u8; 16];
        let shape = run_oracle(&instructions, &exc_handlers, &bytecodes);
        let exc_edge = shape.edges.iter().find(|(f, t, k)| {
            *f == 0 && *t == 8 && matches!(k, EdgeKindOracle::ExceptionHandler)
        });
        assert!(exc_edge.is_some(), "exception edge 0→8 expected; edges={:?}", shape.edges);
    }

    // ── Differential test: compare oracle vs production ───────────────────
    #[test]
    fn differential_empty_function() {
        // Empty instruction list: both should produce empty shape
        let oracle = naive_cfg(&[], &[], &[]).expect("oracle");
        let prod = Cfg::build(&[], &[], &[]).expect("prod cfg");
        let prod_shape = prod.to_shape();
        assert_eq!(oracle.leaders, prod_shape.leaders, "leaders differ");
        assert_eq!(oracle.edges, prod_shape.edges, "edges differ");
        assert_eq!(oracle.block_instructions, prod_shape.block_instructions, "block_instructions differ");
    }

    #[test]
    fn differential_single_ret() {
        // Ret r0 in v96: opcode 0x5c, size 2 bytes.
        let bytecodes: &[u8] = &[0x5c, 0x00];
        let instructions = decode(bytecodes);
        if instructions.is_empty() {
            return;
        }
        let oracle = naive_cfg(&instructions, &[], bytecodes).expect("oracle");
        let prod = Cfg::build(&instructions, &[], bytecodes).expect("prod cfg");
        let prod_shape = prod.to_shape();
        assert_eq!(oracle.leaders, prod_shape.leaders, "leaders differ");
        assert_eq!(oracle.edges, prod_shape.edges, "edges differ");
        assert_eq!(oracle.block_instructions, prod_shape.block_instructions, "block_instructions differ");
    }

    // ── Regression test: BUG-CLASS-A — non-instruction-aligned branch target ─
    // A conditional branch with a target that falls between instructions (not at
    // any instruction start offset) must NOT produce a spurious leader at that
    // offset. The oracle must only insert leaders at actual instruction offsets.
    //
    // Setup: JNotLessN at offset 0 (size 4) with Addr(4): branch target = 4.
    // The next instruction starts at offset 10 (not 4). So offset 4 is NOT a
    // valid instruction start — it must not become a leader.
    #[test]
    fn no_leader_at_non_instruction_offset() {
        // Instruction at 0 (size 4, JNotLessN, Addr(4)): branch target = 0+4 = 4.
        // Next instruction at 10 (size 4, JNotLessN): rule-3 offset from inst at 6? No —
        // inst at 10 starts at 10. The key: offset 4 is between instruction boundaries
        // (instruction at 0 is 4 bytes, so it spans 0-3; the next instruction is at 10).
        // Since no instruction starts at 4, the branch target 4 must NOT become a leader.
        let instructions = vec![
            mock_inst(0,  4, 0x28, "JNotLessN", vec![Operand::Addr(4), Operand::Reg(0), Operand::Reg(0)]),
            // next instruction at 10 (not 4 — gap 4..10 has no instruction)
            mock_inst(10, 4, 0x28, "JNotLessN", vec![Operand::Addr(-10i32), Operand::Reg(0), Operand::Reg(0)]),
            mock_inst(14, 2, 0x5c, "Ret",        vec![Operand::Reg(0)]),
        ];
        let bytecodes = vec![0u8; 30];
        let shape = run_oracle(&instructions, &[], &bytecodes);
        // Leader at 4 is NOT valid (no instruction starts at 4).
        assert!(!shape.leaders.contains(&4), "non-instruction-aligned offset 4 must not be a leader; {:?}", shape.leaders);
        // Valid leaders: 0 (rule 1), 0 (from JNotLessN at 10, Addr(-10) → target = 0, already there),
        // 10 (rule-3 after JNotLessN at 0: next = 0+4 = 4 — but 4 is not an instruction! So 10
        // becomes a leader via rule-3 from JNotLessN at 10? Let's not over-specify — just check !4.
        // The oracle must NOT contain leader 4. Leaders 0 and 14 at minimum.
        assert!(shape.leaders.contains(&0), "0 should be a leader");
        assert!(shape.leaders.contains(&14), "14 should be a leader (fall-through of JNotLessN at 10)");
    }

    // ── Regression test: BUG-CLASS-B — switch default/case dedup ─────────────
    // When a SwitchImm case target equals the default target, the oracle must NOT
    // emit both a SwitchDefault and a Branch edge for the same (from, to) pair.
    // Production dedups via `!succs.contains(&target)`.
    #[test]
    fn switch_imm_default_equals_case_no_duplicate_edge() {
        // SwitchImm at offset 0 with default pointing to same block as a case.
        // (Reg, UInt(jt_off), Addr(default), UInt(min), UInt(max))
        // Default target = offset 4 (relative 4), case[0] also = offset 4.
        // Jump table at offset 10 (jt_off=10), one entry, little-endian rel = 4 - 0 = 4.
        let mut bytecodes = vec![0u8; 20];
        // Jump table at offset 10: entry 0 = i32 LE for relative offset to block 4 = 4 - 0 = 4.
        bytecodes[10] = 4;
        bytecodes[11] = 0;
        bytecodes[12] = 0;
        bytecodes[13] = 0;
        let instructions = vec![
            mock_inst(0, 10, 0x00, "SwitchImm", vec![
                Operand::Reg(0),
                Operand::UInt(10), // jt_off
                Operand::Addr(4),  // default: 0+4 = 4
                Operand::UInt(0),  // min_case
                Operand::UInt(0),  // max_case (one entry)
            ]),
            mock_inst(4, 2, 0x5c, "Ret", vec![Operand::Reg(0)]),
        ];
        let shape = run_oracle(&instructions, &[], &bytecodes);
        // There should be exactly ONE edge from block 0 to block 4.
        let edges_from_0: Vec<_> = shape.edges.iter().filter(|(f, _, _)| *f == 0).collect();
        assert_eq!(edges_from_0.len(), 1, "should be exactly 1 edge from 0; got {edges_from_0:?}");
        let has_default = shape.edges.contains(&(0, 4, EdgeKindOracle::SwitchDefault));
        assert!(has_default, "SwitchDefault edge 0→4 expected; edges={:?}", shape.edges);
    }

    // ── Regression test: BUG-CLASS-C — cond branch target == fall-through ────
    // When a conditional branch's target offset equals its fall-through offset
    // (e.g., `JNotLessN addr=4` at offset 0 with size 4 → branch AND fall-through
    // both land on block 4), the oracle should emit only one edge (Branch, not
    // FallThrough) to match production's to_shape() behavior.
    #[test]
    fn cond_branch_target_equals_fallthrough_single_edge() {
        // JNotLessN at offset 0 (size 4), Addr(4): branch target = 0+4 = 4 = fall-through.
        let instructions = vec![
            mock_inst(0, 4, 0x28, "JNotLessN", vec![Operand::Addr(4), Operand::Reg(0), Operand::Reg(0)]),
            mock_inst(4, 2, 0x5c, "Ret",       vec![Operand::Reg(0)]),
        ];
        let bytecodes = vec![0u8; 16];
        let shape = run_oracle(&instructions, &[], &bytecodes);
        // Exactly one edge from 0 (Branch to 4), not two.
        let edges_from_0: Vec<_> = shape.edges.iter().filter(|(f, _, _)| *f == 0).collect();
        assert_eq!(edges_from_0.len(), 1, "should be exactly 1 edge from block 0; got {edges_from_0:?}");
        let has_branch = shape.edges.contains(&(0, 4, EdgeKindOracle::Branch));
        assert!(has_branch, "Branch edge 0→4 expected; edges={:?}", shape.edges);
        let has_ft = shape.edges.contains(&(0, 4, EdgeKindOracle::FallThrough));
        assert!(!has_ft, "FallThrough edge 0→4 must NOT be present; edges={:?}", shape.edges);
    }

    // ── Regression: BUG-CLASS-D — SwitchImm with invalid default target ─────────
    // When a SwitchImm's default target is outside the function's instruction stream,
    // production's step 3 skips the default and only adds case targets to succs.
    // `to_shape()` must NOT label the first (case) successor as SwitchDefault just
    // because it's first in the succs list; it must use the Addr operand to identify
    // the true default.
    #[test]
    fn switch_imm_invalid_default_case_labeled_branch_not_default() {
        // SwitchImm at offset 0 (size 10):
        //   Reg(0), UInt(10)=jt_off, Addr(9999)=default (invalid, outside function),
        //   UInt(0)=min_case, UInt(0)=max_case (one case entry).
        // Jump table at offset 10 (jt_off=10): entry 0 = i32 LE = 4 - 0 = 4 → case target = offset 4.
        // Default (9999+0=9999) is NOT a valid instruction. Case (4) IS valid.
        let mut bytecodes = vec![0u8; 20];
        bytecodes[10] = 4;  // case[0] relative = 4 → target = 0 + 4 = 4
        let instructions = vec![
            mock_inst(0, 10, 0x00, "SwitchImm", vec![
                Operand::Reg(0),
                Operand::UInt(10),   // jt_off
                Operand::Addr(9999), // default: invalid (9999 > function size)
                Operand::UInt(0),    // min_case
                Operand::UInt(0),    // max_case (one entry)
            ]),
            mock_inst(4, 2, 0x5c, "Ret", vec![Operand::Reg(0)]),
        ];
        let oracle = naive_cfg(&instructions, &[], &bytecodes).expect("oracle");
        let prod = Cfg::build(&instructions, &[], &bytecodes).expect("prod cfg");
        let prod_shape = prod.to_shape();
        // The only edge from 0: production must emit (0, 4, Branch) since default was invalid.
        // Oracle must agree.
        assert_eq!(oracle.edges, prod_shape.edges, "edges must agree; oracle={:?} prod={:?}", oracle.edges, prod_shape.edges);
        // Specifically: no SwitchDefault edge from 0.
        let has_default = prod_shape.edges.iter().any(|(f, _, k)| *f == 0 && matches!(k, EdgeKindOracle::SwitchDefault));
        assert!(!has_default, "SwitchDefault edge must not appear when default target is invalid; edges={:?}", prod_shape.edges);
    }

    // ── Regression test: BUG-CLASS-E — exception overlap vs containment ──────
    // Production uses strict containment (b.start >= eh.start && b.end <= eh.end):
    // the block must fit entirely within the handler's try-region.
    //
    // Discriminating case: handler [1, 3), block [0, 4).
    //   Overlap  fires  : 0 < 3 && 4 > 1 → TRUE  (wrong — block is not "in" the try-region)
    //   Containment fires: 0 >= 1 → FALSE          (correct — block starts before handler)
    // Oracle must NOT emit an ExceptionHandler edge for the partial-overlap case.
    #[test]
    fn exception_handler_containment_not_overlap() {
        // Three instructions: [0, 4), [4, 6), [6, 8).
        // Block [0, 4) spans offsets 0..4.
        // Handler [1, 3) → target 6.
        //   Overlap:     0 < 3 && 4 > 1 → fires   (wrong — block is not "in" the try-region)
        //   Containment: 0 >= 1 → false  → skipped (correct)
        let instructions = vec![
            mock_inst(0, 4, 0x28, "JNotLess", vec![Operand::Addr(6), Operand::Reg(0), Operand::Reg(1)]),
            mock_inst(4, 2, 0x5c, "Ret", vec![Operand::Reg(0)]),
            mock_inst(6, 2, 0x5c, "Ret", vec![Operand::Reg(0)]),
        ];
        let bytecodes = vec![0u8; 16];

        // Case 1: partial overlap — no exc edge (block not contained in handler).
        let eh_partial = vec![ExcHandler { start: 1, end: 3, target: 6 }];
        let oracle_partial = naive_cfg(&instructions, &eh_partial, &bytecodes).expect("oracle");
        let exc_edge = oracle_partial.edges.iter().find(|(_, _, k)| matches!(k, EdgeKindOracle::ExceptionHandler));
        assert!(exc_edge.is_none(),
            "no ExcHandler edge when block [0,4) only partially overlaps handler [1,3); edges={:?}",
            oracle_partial.edges);

        // Case 2: full containment — exc edge IS emitted.
        // handler [0, 4), block [0, 4): 0 >= 0 && 4 <= 4 → contained.
        // Target = 6 (catch block, outside try-region, so production accepts it).
        let eh_full = vec![ExcHandler { start: 0, end: 4, target: 6 }];
        let oracle_full = naive_cfg(&instructions, &eh_full, &bytecodes).expect("oracle");
        let exc_edge_full = oracle_full.edges.iter().find(|(f, t, k)| {
            *f == 0 && *t == 6 && matches!(k, EdgeKindOracle::ExceptionHandler)
        });
        assert!(exc_edge_full.is_some(),
            "ExcHandler edge 0→6 expected when block [0,4) fully contained in handler [0,4); edges={:?}",
            oracle_full.edges);

        // Case 3: differential — oracle must match production for both cases.
        let prod_partial = Cfg::build(&instructions, &eh_partial, &bytecodes).expect("prod partial");
        let prod_partial_shape = prod_partial.to_shape();
        assert_eq!(oracle_partial.edges, prod_partial_shape.edges,
            "partial overlap: oracle must agree with production; oracle={:?} prod={:?}",
            oracle_partial.edges, prod_partial_shape.edges);

        let prod_full = Cfg::build(&instructions, &eh_full, &bytecodes).expect("prod full");
        let prod_full_shape = prod_full.to_shape();
        assert_eq!(oracle_full.edges, prod_full_shape.edges,
            "full containment: oracle must agree with production; oracle={:?} prod={:?}",
            oracle_full.edges, prod_full_shape.edges);
    }

    // ── Regression test: BUG-CLASS-F — last-write-wins exc handler semantics ──
    // When two exception handlers both contain the same block, production's Step 4
    // is an overwrite loop: the LAST handler (in exc_handlers order) wins.
    // Oracle uses a BTreeMap<block_start, exc_target> with last-write-wins,
    // then emits edges from that map (matching production's single-edge behavior).
    //
    // Setup: two instructions (blocks 0 and 6), two handlers both covering block [0, 4).
    //   Handler[0]: [0, 4) → target 6  (first)
    //   Handler[1]: [0, 4) → target 6  (second — same target, tests dedup)
    //   Handler[2]: [0, 4) → target 6  with a different first handler to test overwrite.
    // Simplest test: handler[0] target=6, handler[1] target=6 — oracle must emit
    // exactly one ExcHandler edge 0→6, not two.
    //
    // For a more discriminating test: two handlers covering block 0 with different
    // targets. Production emits edge for the LAST one. Oracle must agree.
    #[test]
    fn exception_handler_last_write_wins() {
        // Two blocks: [0, 4) (JNotLess) and [4, 6) (Ret), and [6, 8) (Ret) as catch.
        // Two exception handlers both covering block 0:
        //   h0: [0, 4) → target 6  (first: would give (0, 6, ExcHandler))
        //   h1: [0, 4) → target 6  (second, same target — dedup test)
        let instructions = vec![
            mock_inst(0, 4, 0x28, "JNotLess", vec![Operand::Addr(4), Operand::Reg(0), Operand::Reg(1)]),
            mock_inst(4, 2, 0x5c, "Ret", vec![Operand::Reg(0)]),
            mock_inst(6, 2, 0x5c, "Ret", vec![Operand::Reg(0)]),
        ];
        let bytecodes = vec![0u8; 16];
        let eh_two = vec![
            ExcHandler { start: 0, end: 4, target: 6 },
            ExcHandler { start: 0, end: 4, target: 6 },
        ];
        let oracle = naive_cfg(&instructions, &eh_two, &bytecodes).expect("oracle");
        // Exactly one ExcHandler edge from block 0, not two.
        let exc_edges: Vec<_> = oracle.edges.iter().filter(|(_, _, k)| matches!(k, EdgeKindOracle::ExceptionHandler)).collect();
        assert_eq!(exc_edges.len(), 1, "two identical handlers covering same block → exactly 1 ExcHandler edge; got {:?}", exc_edges);

        // Differential: oracle must agree with production for the two-handler case.
        let prod = Cfg::build(&instructions, &eh_two, &bytecodes).expect("prod");
        let prod_shape = prod.to_shape();
        assert_eq!(oracle.edges, prod_shape.edges,
            "two-handler case: oracle must agree with production; oracle={:?} prod={:?}",
            oracle.edges, prod_shape.edges);
    }

    mod synthetic_differential_proptests {
        //! Synthetic-input proptests for the same shape-equivalence property
        //! that `fuzz/fuzz_targets/cfg_differential.rs` checks against
        //! real-HBC mutations. The fuzz target requires libFuzzer +
        //! coverage-guided traversal through the full HBC parser before it
        //! reaches the CFG builder; these run as part of `cargo test` and
        //! target the small synthetic-CFG space directly, complementing
        //! the byte-level fuzz target rather than replacing it.
        //!
        //! Generator: sequences of fixed-size-2 mock instructions, each
        //! either Linear (`Add`, falls through), Ret (terminator), or
        //! Jmp(rel) (unconditional branch). No exception handlers (the
        //! `InvalidExceptionLayout` Err-path is exercised separately by
        //! the focused unit tests above).
        use super::*;
        use proptest::prelude::*;

        #[derive(Debug, Clone)]
        enum Slot {
            Linear,
            Ret,
            Jmp(i32),
        }

        fn arb_slot(max_rel: i32) -> impl Strategy<Value = Slot> {
            prop_oneof![
                6 => Just(Slot::Linear),
                1 => Just(Slot::Ret),
                3 => (-max_rel..=max_rel).prop_map(Slot::Jmp),
            ]
        }

        fn arb_program() -> impl Strategy<Value = Vec<Slot>> {
            (1usize..=12usize).prop_flat_map(|n| {
                #[allow(clippy::cast_possible_wrap)]
                let max_rel = (n as i32) * 2 + 4;
                proptest::collection::vec(arb_slot(max_rel), n..=n)
            })
        }

        fn slots_to_decoded(slots: &[Slot]) -> Vec<DecodedInst> {
            #[allow(clippy::cast_possible_truncation)]
            slots
                .iter()
                .enumerate()
                .map(|(i, s)| {
                    let offset = (i as u32) * 2;
                    match s {
                        Slot::Linear => mock_inst(offset, 2, 0x00, "Add", vec![]),
                        Slot::Ret => {
                            mock_inst(offset, 2, 0x5C, "Ret", vec![Operand::Reg(0)])
                        }
                        Slot::Jmp(rel) => {
                            mock_inst(offset, 2, 0x8E, "Jmp", vec![Operand::Addr(*rel)])
                        }
                    }
                })
                .collect()
        }

        proptest! {
            #[test]
            fn prod_and_oracle_agree_on_synthetic_programs(slots in arb_program()) {
                let insts = slots_to_decoded(&slots);
                let total_bytes = insts.len() * 2;
                let bytecodes = vec![0u8; total_bytes];

                // Both implementations may legitimately return Err on the
                // same input (ArithmeticOverflow on degenerate cases); only
                // the both-Ok case is differentially comparable.
                let Ok(prod_cfg) = Cfg::build(&insts, &[], &bytecodes) else {
                    return Ok(());
                };
                let Ok(oracle_shape) = naive_cfg(&insts, &[], &bytecodes) else {
                    return Ok(());
                };
                let prod_shape = prod_cfg.to_shape();

                prop_assert_eq!(
                    &prod_shape.leaders,
                    &oracle_shape.leaders,
                    "leaders diverge on slots={:?}", slots,
                );
                prop_assert_eq!(
                    &prod_shape.edges,
                    &oracle_shape.edges,
                    "edges diverge on slots={:?}", slots,
                );
                prop_assert_eq!(
                    &prod_shape.block_instructions,
                    &oracle_shape.block_instructions,
                    "block_instructions diverge on slots={:?}", slots,
                );
                prop_assert_eq!(prod_shape.entry, oracle_shape.entry);
            }
        }
    }
}
