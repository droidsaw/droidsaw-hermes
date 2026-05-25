//! Region IR — thin adapter over [`droidsaw_common::region`].
//!
//! The full region IR + structurer + lowerer machinery lives in
//! `droidsaw-common::region` after the `common-region-promotion` hoist.
//! This file provides [`HermesStmtBackend`], an impl of
//! `StmtBackend` that wires hermes's concrete types
//! ([`BlockId`] / [`Condition`] / [`Stmt`] / [`SsaFunction`]) to the
//! common-hosted algorithm.
//! The two public entry points — [`build_region_tree`] and
//! [`lower_region`] — preserve the pre-hoist signatures so the
//! `structure::structure_function_with_exc_choice` call site at
//! `structure.rs:605-606` is unchanged. Each constructs a
//! [`HermesStmtBackend`] and delegates to the common fns of the same
//! name.
#![allow(
    clippy::cast_possible_wrap,
    reason = "PROOF: signed/unsigned reinterpretation in HBC jump offsets and operand decode; values bounded by per-function bytecode size cap."
)]

#![allow(missing_docs, reason = "internal")]

use std::collections::BTreeMap;

use droidsaw_common::region::{
    self as common_region, CaseLabel, CondBranch, StmtBackend, TerminatorKind,
};

pub use droidsaw_common::region::reachable_in;

use super::cfg::BlockId;
use super::ssa::{Resolved, SsaBlock, SsaFunction, SsaOperand, VarId};
use super::structure::{
    Condition, Stmt, emit_block_ops, emit_dispatcher, extract_condition, min_case_from_switch,
};
use super::sugar;

/// Hermes-flavored region tree. Common's [`droidsaw_common::region::RegionNode`]
/// parameterized over hermes's [`BlockId`] + [`Condition`].
pub type RegionNode = common_region::RegionNode<BlockId, Condition>;

/// Adapter between hermes's SSA / Stmt ADTs and the common
/// [`StmtBackend`] trait. Pre-computes phi-copy materialization +
/// block topology once per decompile so per-method lookups in the
/// lowerer are O(log n) rather than O(n).
pub struct HermesStmtBackend<'a> {
    /// Pre-computed def-use copies keyed by predecessor block: for each
    /// phi at successor S with arg (pred_P, var), stores
    /// `phi_copies[pred_P].push((dst, src))`. Emitted as `Stmt::PhiAssign`
    /// at the tail of each predecessor's ops by `emit_block_ops`.
    phi_copies: super::structure::PhiCopies,
    /// Fast block-id → block-ref lookup for `emit_dispatcher` + per-block
    /// ops inspection.
    block_map: BTreeMap<BlockId, &'a SsaBlock>,
    /// Successor map; `emit_dispatcher` needs this plus `block_order`.
    all_succs: BTreeMap<BlockId, Vec<BlockId>>,
}

impl<'a> HermesStmtBackend<'a> {
    pub fn new(ssa: &'a SsaFunction<Resolved>) -> Self {
        let mut phi_copies: super::structure::PhiCopies = BTreeMap::new();
        for block in &ssa.blocks {
            for phi in &block.phis {
                for (pred_id, var) in &phi.args {
                    phi_copies
                        .entry(*pred_id)
                        .or_default()
                        .push((
                            std::rc::Rc::from(format!("{}", phi.dst)),
                            std::rc::Rc::from(format!("{var}")),
                        ));
                }
            }
        }
        let block_map: BTreeMap<BlockId, &'a SsaBlock> =
            ssa.blocks.iter().map(|b| (b.id, b)).collect();
        let all_succs: BTreeMap<BlockId, Vec<BlockId>> = ssa
            .blocks
            .iter()
            .map(|b| (b.id, b.successors.clone()))
            .collect();
        Self {
            phi_copies,
            block_map,
            all_succs,
        }
    }
}

impl StmtBackend for HermesStmtBackend<'_> {
    type BlockId = BlockId;
    type Condition = Condition;
    type Stmt = Stmt;
    type Ssa = SsaFunction<Resolved>;

    fn successors(&self, _ssa: &SsaFunction<Resolved>, block: BlockId) -> Vec<BlockId> {
        // PROOF: `all_succs` is built from `ssa.blocks.iter().map(|b|(b.id,..))` in
        // `HermesStmtBackend::new`. The region structurer only queries blocks from
        // `ssa.block_order`, which is a subset of `ssa.blocks` keys. Therefore
        // `all_succs.contains_key(&block)` holds for any `block` passed by the
        // region engine; `unwrap_or_default()` is dead.
        debug_assert!(self.all_succs.contains_key(&block), "block {block} missing from all_succs — ssa.blocks invariant violated");
        self.all_succs.get(&block).cloned().unwrap_or_default()
    }
    fn predecessors(&self, _ssa: &SsaFunction<Resolved>, block: BlockId) -> Vec<BlockId> {
        // PROOF: `block_map` is built from `ssa.blocks.iter().map(|b|(b.id,..))`.
        // Same invariant: region engine only queries `ssa.block_order` blocks, which
        // are keys in `ssa.blocks` → keys in `block_map`. `unwrap_or_default()` is dead.
        debug_assert!(self.block_map.contains_key(&block), "block {block} missing from block_map — ssa.blocks invariant violated");
        self.block_map
            .get(&block)
            .map(|b| b.predecessors.clone())
            .unwrap_or_default()
    }
    fn block_order<'b>(&self, ssa: &'b SsaFunction<Resolved>) -> &'b [BlockId] {
        &ssa.block_order
    }

    fn extract_condition(&self, _ssa: &SsaFunction<Resolved>, block: BlockId) -> Option<Condition> {
        // Raw jump-fires-when-true form — no negation. The common
        // structurer uses this for `Loop.cond` directly so `while (cond)`
        // matches hermes's pre-regionalized polarity (e.g. `JNotLess`
        // yields `Compare { op: ">=", ... }` and renders `while (>=)`).
        self.block_map.get(&block).and_then(|b| extract_condition(b))
    }

    fn emit_block_ops(&self, _ssa: &SsaFunction<Resolved>, block: BlockId, out: &mut Vec<Stmt>) {
        if let Some(b) = self.block_map.get(&block) {
            let stmts = emit_block_ops(b, &self.phi_copies);
            out.extend(stmts);
        }
    }

    fn emit_dispatcher(&self, ssa: &SsaFunction<Resolved>, scc_blocks: &[BlockId], out: &mut Vec<Stmt>) {
        let order_set: std::collections::BTreeSet<BlockId> = scc_blocks.iter().copied().collect();
        let stmts = emit_dispatcher(
            &ssa.block_order,
            &self.block_map,
            &self.phi_copies,
            &self.all_succs,
            &order_set,
            0,
        );
        out.extend(stmts);
    }

    fn build_if(&self, cond: Condition, then_body: Vec<Stmt>, else_body: Vec<Stmt>) -> Stmt {
        Stmt::If {
            cond,
            then_body,
            else_body,
        }
    }

    fn build_while(
        &self,
        cond: Option<Condition>,
        body: Vec<Stmt>,
        label: Option<String>,
    ) -> Stmt {
        let while_stmt = Stmt::While { cond, body };
        match label {
            Some(l) => Stmt::Labeled {
                label: l,
                body: vec![while_stmt],
            },
            None => while_stmt,
        }
    }

    fn build_try_catch(
        &self,
        try_body: Vec<Stmt>,
        catch_handler: BlockId,
        catch_body: Vec<Stmt>,
    ) -> Stmt {
        // Pull catch_var from the first op of the catch handler block if
        // it's a `Catch` instruction (mirrors legacy structure.rs:940-948).
        let mut catch_var = "err".to_string();
        if let Some(cb) = self.block_map.get(&catch_handler)
            && let Some(first) = cb.ops.first()
            && first.name == "Catch"
            && let Some(dst) = &first.dst
        {
            catch_var = format!("{dst}");
        }
        Stmt::TryCatch {
            try_body,
            catch_var,
            catch_body,
        }
    }

    fn build_return(&self, _ssa: &SsaFunction<Resolved>, block: BlockId) -> Option<Stmt> {
        let b = self.block_map.get(&block)?;
        let last = b.ops.last()?;
        let v = match last.operands.first() {
            Some(SsaOperand::Var(v)) => Some(*v),
            _ => None,
        };
        Some(Stmt::Return(v))
    }

    fn build_throw(&self, _ssa: &SsaFunction<Resolved>, block: BlockId) -> Option<Stmt> {
        let b = self.block_map.get(&block)?;
        let last = b.ops.last()?;
        let SsaOperand::Var(v) = last.operands.first()? else {
            return None;
        };
        Some(Stmt::Throw(*v))
    }

    fn build_break(&self, label: Option<String>) -> Stmt {
        Stmt::Break(label)
    }

    fn build_continue(&self, label: Option<String>) -> Stmt {
        Stmt::Continue(label)
    }

    fn build_labeled(&self, label: String, body: Vec<Stmt>) -> Stmt {
        Stmt::Labeled { label, body }
    }

    fn classify_terminator(&self, _ssa: &SsaFunction<Resolved>, block: BlockId) -> TerminatorKind {
        let Some(b) = self.block_map.get(&block) else {
            return TerminatorKind::Fallthrough;
        };
        let Some(last) = b.ops.last() else {
            return TerminatorKind::Fallthrough;
        };
        if last.name == "Ret" {
            return TerminatorKind::Return;
        }
        if last.name == "Throw" {
            return TerminatorKind::Throw;
        }
        if last.original.is_conditional_branch() && b.successors.len() == 2 {
            return TerminatorKind::Conditional;
        }
        if last.original.name.contains("SwitchImm") && !b.successors.is_empty() {
            return TerminatorKind::Switch;
        }
        TerminatorKind::Fallthrough
    }

    fn conditional_branch(
        &self,
        _ssa: &SsaFunction<Resolved>,
        block: BlockId,
    ) -> CondBranch<BlockId, Condition> {
        let empty = CondBranch {
            then_target: None,
            else_target: None,
            cond: None,
        };
        let Some(b) = self.block_map.get(&block) else {
            return empty;
        };
        let Some(last) = b.ops.last() else {
            return empty;
        };
        let target_offset = last.original.branch_target();
        let succs = &b.successors;

        // Branch-polarity swap matches legacy structure.rs:1235.
        let is_negated = last.name.contains("False") || last.name.contains("Not");
        let (then_target, else_target) = if is_negated {
            (
                succs.iter().find(|&&s| Some(s) != target_offset).copied(),
                target_offset,
            )
        } else {
            (
                target_offset,
                succs.iter().find(|&&s| Some(s) != target_offset).copied(),
            )
        };

        let cond = extract_condition(b).map(|c| {
            if is_negated {
                sugar::negate_condition(c)
            } else {
                c
            }
        });

        CondBranch {
            then_target,
            else_target,
            cond,
        }
    }

    fn switch_cases(&self, _ssa: &SsaFunction<Resolved>, block: BlockId) -> Vec<CaseLabel> {
        let Some(b) = self.block_map.get(&block) else {
            return Vec::new();
        };
        let Some(last) = b.ops.last() else {
            return Vec::new();
        };
        let is_string_switch = last.original.name == "StringSwitchImm";
        let min_case = if is_string_switch {
            0
        } else {
            min_case_from_switch(last)
        };
        let n_cases = b.successors.len().saturating_sub(1); // succ[0] is default
        (0..n_cases)
            .map(|i| {
                if is_string_switch {
                    // SEMANTICS-DEFAULT-EMPTY: `switch_string_ids` may have fewer entries
                    // than `successors.len()-1` in malformed HBC where the string-table
                    // offset list is truncated. Defaulting to string-id 0 produces a
                    // best-effort case label ("") rather than discarding the entire switch.
                    CaseLabel::String(b.switch_string_ids.get(i).copied().unwrap_or(0))
                } else {
                    #[allow(clippy::as_conversions, reason = "usize→i64 widens on every project-supported target; `i` is bounded by `n_cases = successors.len() - 1`.")]
                    CaseLabel::Const(min_case.saturating_add(i as i64).to_string())
                }
            })
            .collect()
    }

    fn build_switch(
        &self,
        _ssa: &SsaFunction<Resolved>,
        head: BlockId,
        cases: Vec<(CaseLabel, Vec<Stmt>)>,
        default: Vec<Stmt>,
    ) -> Option<Stmt> {
        let b = self.block_map.get(&head)?;
        let last = b.ops.last()?;
        let discriminant = match last.operands.first() {
            Some(SsaOperand::Var(v)) => *v,
            _ => VarId(u32::MAX, u32::MAX),
        };
        let lowered_cases: Vec<(String, Vec<Stmt>)> = cases
            .into_iter()
            .map(|(label, body)| {
                let key = match label {
                    CaseLabel::Const(s) => s,
                    CaseLabel::String(id) => format!("__str_case_{id}"),
                };
                (key, body)
            })
            .collect();
        Some(Stmt::Switch {
            discriminant,
            cases: lowered_cases,
            default,
        })
    }
}

/// Build the region tree for an SSA function. Thin wrapper over
/// [`droidsaw_common::region::build_region_tree`] that constructs a
/// [`HermesStmtBackend`] for this function.
pub fn build_region_tree(
    ssa: &SsaFunction<Resolved>,
    exc_handlers: &BTreeMap<BlockId, BlockId>,
) -> RegionNode {
    let backend = HermesStmtBackend::new(ssa);
    common_region::build_region_tree(&backend, ssa, exc_handlers)
}

/// Lower a region tree to a `Vec<Stmt>`. Thin wrapper over
/// [`droidsaw_common::region::lower_region`] that constructs a
/// [`HermesStmtBackend`] for this function.
pub fn lower_region(region: &RegionNode, ssa: &SsaFunction<Resolved>) -> Vec<Stmt> {
    let backend = HermesStmtBackend::new(ssa);
    common_region::lower_region(region, &backend, ssa)
}
