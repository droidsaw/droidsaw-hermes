//! SSA construction using Braun et al. (CC 2013) algorithm.
//!
//! Converts register-based instructions into SSA form where each register
//! assignment creates a new variable version, and phi functions are inserted
//! at merge points.
//!
//! The Braun name-resolution state machine lives in
//! `droidsaw_common::ssa`; this module adapts the hermes `Cfg` for that
//! generic builder, classifies each hermes instruction's register reads /
//! writes, and wraps the result in the hermes-flavored `SsaFunction`
//! container used by the rest of the decompiler pipeline.
#![allow(missing_docs, reason = "internal")]

use std::collections::BTreeMap;
use std::marker::PhantomData;

use droidsaw_common::graph::Graph;
use droidsaw_common::ssa::{Builder as CommonBuilder, SsaCfg};

use super::cfg::{BlockId, Cfg};
use super::decode::{DecodedInst, Operand};

pub use phase::{Phase, Raw, Resolved};

/// Phase markers for SSA function transformations.
///
/// A later pass parameterises `SsaFunction` over `P: Phase` so the
/// post-`optimize::resolve_strings` precondition (every property-name
/// operand is `SsaOperand::ResolvedString(_)`, never `Const(sid)`)
/// becomes machine-checked at the type level. Visitors that depend on
/// resolved strings — including the cross-layer-taint two-hop
/// property-chain back-walk — take `&SsaFunction<Resolved>`; the
/// `Const(sid)` runtime arm disappears at the type-system floor.
///
/// Sealed: [`Raw`] and [`Resolved`] are the only implementors of
/// [`Phase`]. Adding a third phase is an explicit decision; ad-hoc
/// downstream `impl Phase for MyPhase` is rejected at compile time.
pub mod phase {
    mod sealed {
        pub trait Sealed {}
    }

    /// Sealed marker trait identifying an SSA transformation phase.
    pub trait Phase: sealed::Sealed + Copy + Clone + std::fmt::Debug + 'static {}

    /// Pre-`optimize::resolve_strings`. Property-name operands may
    /// still be encoded as `SsaOperand::Const(sid)` references into
    /// the Hermes string table awaiting decode.
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    pub struct Raw;
    impl sealed::Sealed for Raw {}
    impl Phase for Raw {}

    /// Post-`optimize::resolve_strings`. Every property-name operand
    /// is canonical `SsaOperand::ResolvedString(_)`.
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    pub struct Resolved;
    impl sealed::Sealed for Resolved {}
    impl Phase for Resolved {}

    #[cfg(test)]
    mod tests {
        use super::*;

        // Trait-bound smoke tests: if either marker stops satisfying
        // `Phase`, these stop compiling. The bound list also pins the
        // foundation requirements `SsaFunction<P>` will inherit.
        fn assert_phase<P: Phase>() {}

        #[test]
        fn raw_is_phase() {
            assert_phase::<Raw>();
        }

        #[test]
        fn resolved_is_phase() {
            assert_phase::<Resolved>();
        }
    }
}

/// SSA variable identifier: (register, version).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize)]
pub struct VarId(pub u32, pub u32);

impl std::fmt::Display for VarId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "r{}_{}", self.0, self.1)
    }
}

impl VarId {
    /// Parse the `Display` form (`"r{reg}_{ver}"`) back to a `VarId`.
    /// Returns `None` for any string that isn't strict-shape, including
    /// renamed display forms (`"this"`, `"a0"`, IPA-derived names),
    /// literal constants ("`42`", `"true"`), and member-access chains
    /// (`"a0.value"`). Inverse of `Display` on the canonical form.
    ///
    /// Used by `count_var_uses` and `resolve_var` to recover the
    /// canonical VarId at lookup sites where the upstream code carries
    /// the formatted string in a `Stmt` field; non-VarId strings yield
    /// `None`, which the callers handle as "not in the map" (which is
    /// what they were doing before — the String-keyed map didn't hold
    /// non-canonical names either, since they were never inserted).
    pub fn from_display_str(s: &str) -> Option<Self> {
        let rest = s.strip_prefix('r')?;
        let (reg, ver) = rest.split_once('_')?;
        let reg: u32 = reg.parse().ok()?;
        let ver: u32 = ver.parse().ok()?;
        Some(VarId(reg, ver))
    }
}

impl From<droidsaw_common::ssa::Var<u32>> for VarId {
    fn from(v: droidsaw_common::ssa::Var<u32>) -> Self {
        VarId(v.reg, v.ver)
    }
}

/// A phi function at a block entry.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Phi {
    pub dst: VarId,
    pub args: Vec<(BlockId, VarId)>,
}

/// An SSA operation derived from a bytecode instruction.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SsaOp {
    pub name: &'static str,
    pub op: crate::opcodes::OpCode,
    pub dst: Option<VarId>,
    pub operands: Vec<SsaOperand>,
    pub original: DecodedInst,
}

/// An operand in SSA form.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub enum SsaOperand {
    Var(VarId),
    /// Destination placeholder — marks operand position 0 as the instruction's
    /// output register. Not a variable reference. Must never be counted as a use.
    DstPlaceholder,
    Const(i64),
    ConstDouble(f64),
    StringId(u32),
    FuncId(u32),
    BlockTarget(BlockId),
    ResolvedString(String),
    /// BigInt literal value (signed-decimal) resolved from the HBC bigint
    /// constant table at `optimize::resolve_bigints` time. Mirrors
    /// `ResolvedString`: the emit-side pattern-matches this directly instead
    /// of carrying the raw table index through to rendering — which is what
    /// the `LoadConstBigInt` / `LoadConstBigIntLongIndex` operand is.
    ResolvedBigInt(String),
}

/// SSA-form basic block.
#[derive(Debug, serde::Serialize)]
pub struct SsaBlock {
    pub id: BlockId,
    pub phis: Vec<Phi>,
    pub ops: Vec<SsaOp>,
    pub successors: Vec<BlockId>,
    pub predecessors: Vec<BlockId>,
    /// For StringSwitchImm: string IDs for each case (from CFG).
    pub switch_string_ids: Vec<u32>,
}

/// Complete SSA representation of a function.
///
/// Parameterized by [`Phase`]: `SsaFunction<Raw>` is the post-`build_ssa`
/// shape (property-name operands may still be `SsaOperand::Const(sid)`
/// references into the Hermes string table); `SsaFunction<Resolved>` is
/// the post-`optimize::optimize` shape (every property-name operand is
/// canonical `SsaOperand::ResolvedString(_)`). The only transition
/// between the two phases is `optimize::optimize`'s consume-and-return
/// signature plus the [`SsaFunction::into_resolved`] reinterpret it uses
/// internally.
#[derive(Debug, serde::Serialize)]
#[serde(bound = "")]
pub struct SsaFunction<P: Phase> {
    pub blocks: Vec<SsaBlock>,
    pub block_order: Vec<BlockId>,
    /// Human-readable names for SSA variables, populated by optimize::name_variables.
    pub var_names: std::collections::BTreeMap<VarId, String>,
    pub param_names: std::collections::BTreeMap<u32, String>,
    /// VarIds for each parameter in index order, mirroring `SsaBody::param_vars` in the
    /// DEX SSA. Populated during construction from `LoadParam`/`LoadParamLong` dst VarIds
    /// so that taint analysis can seed parameters without scanning instructions.
    pub param_vars: Vec<VarId>,
    /// Phase witness. Zero-sized at runtime; the gauge is the
    /// `P: Phase` parameter, threaded through every consumer signature.
    #[serde(skip)]
    pub(in crate::decompile) _phase: PhantomData<P>,
}

/// Adapter that exposes the hermes [`Cfg`] as a [`SsaCfg`] view for the
/// generic Braun builder in `droidsaw_common::ssa`.
struct CfgAdapter<'a>(&'a Cfg);

impl<'a> Graph for CfgAdapter<'a> {
    type Node = BlockId;

    fn entry(&self) -> BlockId {
        self.0.entry
    }

    fn nodes(&self) -> Vec<BlockId> {
        self.0.blocks.keys().copied().collect()
    }

    fn successors(&self, n: BlockId) -> Vec<BlockId> {
        // PROOF: callers iterate `nodes()` which returns `self.0.blocks.keys()`.
        // Any `n` passed by the graph algorithms is a key in `blocks`; the `.get()`
        // cannot return None on this call path. `unwrap_or_default()` is dead.
        debug_assert!(self.0.blocks.contains_key(&n), "block {n} missing from Cfg.blocks — nodes() invariant violated");
        self.0
            .blocks
            .get(&n)
            .map(|b| b.successors.clone())
            .unwrap_or_default()
    }

    fn predecessors(&self, n: BlockId) -> Vec<BlockId> {
        // PROOF: same invariant as successors() — `n` is always from `nodes()` which
        // yields exactly `self.0.blocks.keys()`.
        debug_assert!(self.0.blocks.contains_key(&n), "block {n} missing from Cfg.blocks — nodes() invariant violated");
        self.0
            .blocks
            .get(&n)
            .map(|b| b.predecessors.clone())
            .unwrap_or_default()
    }
}

impl<'a> SsaCfg for CfgAdapter<'a> {
    fn exc_predecessors(&self, n: BlockId) -> Vec<BlockId> {
        if n == self.0.entry {
            return Vec::new();
        }
        // SEMANTICS-DEFAULT-EMPTY: `exc_predecessors` is populated only for catch-
        // target blocks; a block with no exception predecessors has no entry in the
        // map. Absent key → empty Vec is the correct semantic (no exception edges).
        self.0
            .exc_predecessors
            .get(&n)
            .cloned()
            .unwrap_or_default()
    }
}

/// Classify which registers an instruction reads and writes.
fn classify_inst(inst: &DecodedInst) -> (Option<u32>, Vec<u32>) {
    let ops = &inst.operands;
    let types = inst.op_types;
    let name = inst.name;

    // Most instructions: first operand is dst (Reg8), rest are sources
    // Exceptions: stores, jumps, returns, throws
    match name {
        // No destination
        "Ret" | "Throw" | "Debugger" | "AsyncBreakCheck" | "ProfilePoint" | "Unreachable"
        | "Nop" => {
            let reads: Vec<u32> = ops.iter().filter_map(|o| o.as_reg()).collect();
            (None, reads)
        }

        // Stores: destination is a property/environment, not a register
        n if n.starts_with("PutById")
            || n.starts_with("TryPutById")
            || n.starts_with("PutByVal")
            || n.starts_with("StoreToEnvironment")
            || n.starts_with("StoreNPToEnvironment")
            || n.starts_with("DefineOwn")
            || n.starts_with("PutNewOwn")
            || n.starts_with("PutOwn")
            || n == "FastArrayStore"
            || n == "FastArrayPush"
            || n == "FastArrayAppend"
            || n == "AddOwnPrivateBySym" =>
        {
            let reads: Vec<u32> = ops.iter().filter_map(|o| o.as_reg()).collect();
            (None, reads)
        }

        // Jumps: no destination register
        n if n.starts_with('J') => {
            let reads: Vec<u32> = ops.iter().skip(1).filter_map(|o| o.as_reg()).collect();
            (None, reads)
        }

        // Switch (SwitchImm, UIntSwitchImm, StringSwitchImm)
        n if n.contains("SwitchImm") => {
            let reads: Vec<u32> = ops.iter().filter_map(|o| o.as_reg()).collect();
            (None, reads)
        }

        // DeclareGlobalVar: no registers
        "DeclareGlobalVar" => (None, vec![]),

        // Default: first Reg8 is dst, rest are reads — validated against schema
        _ => {
            let first_is_reg = matches!(
                types.first(),
                Some(crate::decompile::decode::OpType::R | crate::decompile::decode::OpType::R4)
            );
            if first_is_reg {
                if let Some((Operand::Reg(dst), rest)) = ops.split_first() {
                    let reads: Vec<u32> = rest.iter().filter_map(|o| o.as_reg()).collect();
                    (Some(u32::from(*dst)), reads)
                } else if let Some((Operand::Reg32(dst), rest)) = ops.split_first() {
                    let reads: Vec<u32> = rest.iter().filter_map(|o| o.as_reg()).collect();
                    (Some(*dst), reads)
                } else {
                    let reads: Vec<u32> = ops.iter().filter_map(|o| o.as_reg()).collect();
                    (None, reads)
                }
            } else {
                // Schema says first operand is not a register — treat all as reads
                let reads: Vec<u32> = ops.iter().filter_map(|o| o.as_reg()).collect();
                (None, reads)
            }
        }
    }
}

/// Build SSA from a CFG.
///
/// `frame_size` is the function's total register frame size (from the HBC
/// function header). The variadic-call resolver places each arg at register
/// `frame_size - 9 - i` per the Hermes stack-frame ABI. A `frame_size` of 0
/// means "unavailable" (pre-v97 small headers, or synthetic empty returns):
/// variadic arg resolution is skipped and callsites render without resolved
/// args.
///
/// Postconditions: every variable use has a reaching definition. Phi argument
/// count equals predecessor count for each phi node.
///
/// Returns `Err(HermesError::Ssa)` if the underlying Braun builder exhausts
/// its `u32` version counter or if `seal_phis` fails to reach a fixed point.
pub fn build_ssa(cfg: &Cfg, frame_size: u32) -> crate::Result<SsaFunction<Raw>> {
    let adapter = CfgAdapter(cfg);
    let mut builder: CommonBuilder<CfgAdapter<'_>, u32> = CommonBuilder::new();
    let mut ssa_blocks: Vec<SsaBlock> = Vec::new();
    // Collect (param_index, VarId) from LoadParam/LoadParamLong as we build.
    let mut param_var_map: BTreeMap<u32, VarId> = BTreeMap::new();

    // Credible upper bound on variadic Call/CallLong/CallDirect/CallDirectLongIndex
    // argc. Each implicit arg register must have been set by a prior register-writing
    // instruction, so a well-formed argc cannot exceed the function's total instruction
    // count. Adversarial HBC fabricating a u32 argc up to 2^32 drives an unbounded
    // `for i in 0..argc { ssa_operands.push(..) }` below and amplifies an ~300-B input
    // into multi-GB RSS — the cap below converts the amplification into a typed Err.
    let total_insns: usize = cfg
        .blocks
        .values()
        .map(|b| b.instructions.len())
        .sum();

    // Pass 1: walk blocks + instructions. Reads/writes drive the builder;
    // merge points get empty-args phis, which are sealed in pass 2.
    for &bid in &cfg.block_order {
        let block = match cfg.blocks.get(&bid) {
            Some(b) => b,
            None => continue,
        };

        let mut ops = Vec::new();

        for inst in &block.instructions {
            let (dst_reg, _read_regs) = classify_inst(inst);

            // Read operands in SSA form
            let ssa_operands: Vec<SsaOperand> = inst
                .operands
                .iter()
                .enumerate()
                .map(|(i, op)| -> crate::Result<SsaOperand> {
                    Ok(match op {
                        Operand::Reg(r) => {
                            let r32 = u32::from(*r);
                            if i == 0 && dst_reg == Some(r32) {
                                // This is the destination — will be written after
                                SsaOperand::DstPlaceholder
                            } else {
                                let var: VarId =
                                    builder.read_variable(bid, r32, &adapter)?.into();
                                SsaOperand::Var(var)
                            }
                        }
                        Operand::Reg32(r) => {
                            if i == 0 && dst_reg == Some(*r) {
                                SsaOperand::DstPlaceholder
                            } else {
                                let var: VarId =
                                    builder.read_variable(bid, *r, &adapter)?.into();
                                SsaOperand::Var(var)
                            }
                        }
                        Operand::UInt(v) => {
                            let _ot = inst.op_types.get(i);
                            if inst.name.contains("LoadConstString") && i == 1 {
                                SsaOperand::StringId(*v)
                            } else if (inst.name.contains("CreateClosure")
                                || inst.name.contains("CreateGenerator"))
                                && i >= 1
                            {
                                SsaOperand::FuncId(*v)
                            } else {
                                SsaOperand::Const(i64::from(*v))
                            }
                        }
                        Operand::Int(v) => SsaOperand::Const(i64::from(*v)),
                        Operand::Double(v) => SsaOperand::ConstDouble(*v),
                        Operand::Addr(rel) => {
                            #[allow(clippy::as_conversions, clippy::cast_possible_truncation, clippy::cast_sign_loss, reason = "branch-target reduction — `inst.offset` is a u32 byte offset; `i64::from(u32)` widens safely; `i32::from(rel)` widens safely; `saturating_add` clamps to i64 range. On well-formed HBC the result fits u32 by construction. On adversarial bytecode the final `as u32` can wrap or sign-flip — the runtime consequence is observable but semantically benign (the downstream BlockTarget lookup misses and falls through), mirroring the `expr::const_id_to_u32` discipline.")]
                            let target = (i64::from(inst.offset))
                                .saturating_add(i64::from(*rel))
                                as u32;
                            SsaOperand::BlockTarget(target)
                        }
                    })
                })
                .collect::<crate::Result<Vec<_>>>()?;

            // For variadic Call/CallLong/CallDirect/CallBuiltin: resolve the
            // implicit argument registers. Per Hermes's stack-frame ABI (see
            // `sh_stack_frame_layout.h`), the caller places outgoing call
            // slots at the TOP of its own register frame, so regardless of
            // the Call opcode's dst register, arg0 lives at
            // `frame_size - 9` (one slot below thisArg at `frame_size - 8`)
            // and arg[i] at `frame_size - 9 - i`. The bytecode `argc`
            // operand includes the thisArg slot, so the number of explicit
            // args is `argc - 1`. For Call the resolver pushes `thisArg`
            // first (so downstream emit can route it as the call receiver);
            // CallBuiltin's thisArg is implicit-undefined in the interpreter
            // and is not pushed.
            //
            // `frame_size == 0` means the header didn't expose it (pre-v97
            // layouts, or synthetic empty returns); fall back to pushing no
            // resolved args, which preserves the prior "args collapsed to
            // argc" display. This keeps adversarial non-v97 inputs from
            // silently emitting garbage.
            let mut ssa_operands = ssa_operands;
            let frame_top_arg0 = frame_size.checked_sub(9);
            let (argc_for_resolve, item_label, include_this) = match inst.name {
                "Call" | "CallLong" => match inst.operands.get(2) {
                    Some(Operand::UInt(n)) => (Some(*n), "variadic Call argc", true),
                    _ => (None, "", true),
                },
                "CallDirect" | "CallDirectLongIndex" => match inst.operands.get(1) {
                    Some(Operand::UInt(n)) => (Some(*n), "variadic CallDirect argc", true),
                    _ => (None, "", true),
                },
                "CallBuiltin" | "CallBuiltinLong" => match inst.operands.get(2) {
                    Some(Operand::UInt(n)) => {
                        // CallBuiltin's interpreter handler sets thisArg to
                        // implicit undefined (see `implCallBuiltin`), so the
                        // caller does not load it and we do not push it.
                        (Some(*n), "variadic CallBuiltin argc", false)
                    }
                    _ => (None, "", false),
                },
                _ => (None, "", false),
            };
            if let Some(argc) = argc_for_resolve {
                // WHY: u32→usize is a widen on every project-supported target
                // (32-bit-or-wider).
                #[allow(clippy::as_conversions, reason = "u32→usize is a widen on every project-supported target (32-bit-or-wider).")]
                let argc_usize = argc as usize;
                if argc_usize > total_insns {
                    return Err(crate::HermesError::CountExceedsInput {
                        got: argc,
                        max: total_insns,
                        item: item_label,
                    });
                }
                if let Some(arg0_reg) = frame_top_arg0 {
                    let explicit = argc.saturating_sub(1);
                    if include_this {
                        // thisArg at frame_size - 8 = arg0_reg + 1. The frame
                        // top is at `frame_size - 1`, so arg0_reg + 1 cannot
                        // overflow when frame_size fits in u32 and `arg0_reg
                        // = frame_size - 9` — this is a static invariant of
                        // the layout, not an attacker-controllable condition.
                        let this_reg = arg0_reg.saturating_add(1);
                        let var: VarId =
                            builder.read_variable(bid, this_reg, &adapter)?.into();
                        ssa_operands.push(SsaOperand::Var(var));
                    }
                    // arg[i] at arg0_reg - i (decreasing register order).
                    // Adversarial HBC can fabricate (frame_size, argc) pairs
                    // that place arg[explicit-1] below register 0 — surface
                    // as a typed error rather than letting saturating_sub
                    // collapse out-of-range indices to register 0, which
                    // would silently push the same VarId repeatedly and
                    // reproduce the shape of the latent-bug this fix removes.
                    for i in 0..explicit {
                        let Some(arg_reg) = arg0_reg.checked_sub(i) else {
                            // WHY: u32→usize widens on 32+-bit targets.
                            #[allow(clippy::as_conversions, reason = "u32→usize widens on 32+-bit targets.")]
                            let max_usize = arg0_reg.saturating_add(1) as usize;
                            return Err(crate::HermesError::CountExceedsInput {
                                got: explicit,
                                max: max_usize,
                                item: item_label,
                            });
                        };
                        let var: VarId =
                            builder.read_variable(bid, arg_reg, &adapter)?.into();
                        ssa_operands.push(SsaOperand::Var(var));
                    }
                }
            }

            // Write destination register
            let dst = if let Some(reg) = dst_reg {
                let var = builder.new_var(reg)?;
                builder.write_variable(bid, reg, var);
                Some(VarId::from(var))
            } else {
                None
            };

            // Capture parameter VarIds for the convenience param_vars field.
            if matches!(inst.name, "LoadParam" | "LoadParamLong")
                && let (Some(var), Some(SsaOperand::Const(idx))) =
                    (dst, ssa_operands.get(1))
            {
                // WHY: i64→u32 narrows; idx is the LoadParam parameter index
                // (bounded by the function-header `paramCount` field, which
                // fits in u8/u16 in HBC headers); wrap is unreachable here.
                #[allow(clippy::as_conversions, clippy::cast_possible_truncation, clippy::cast_sign_loss, reason = "i64→u32 narrows; idx is the LoadParam parameter index (bounded by the function-header `paramCount` field, which fits in u8/u16 in HBC headers); truncation/sign-loss unreachable here.")]
                let idx_u32 = *idx as u32;
                param_var_map.insert(idx_u32, var);
            }

            ops.push(SsaOp {
                name: inst.name,
                op: inst.op,
                dst,
                operands: ssa_operands,
                original: inst.clone(),
            });
        }

        ssa_blocks.push(SsaBlock {
            id: bid,
            phis: Vec::new(),
            ops,
            successors: block.successors.clone(),
            predecessors: block.predecessors.clone(),
            switch_string_ids: block.switch_string_ids.clone(),
        });
    }

    // Pass 2: fill phi operand lists (may create additional phis on
    // back-edges; seal_phis iterates until stable).
    builder.seal_phis(&adapter)?;

    // Pass 3: drain phis into the hermes-flavored SsaBlock.phis.
    for ssa_block in &mut ssa_blocks {
        let common_phis = builder.take_phis(ssa_block.id);
        ssa_block.phis = common_phis
            .into_iter()
            .map(|p| Phi {
                dst: VarId::from(p.dst),
                args: p
                    .args
                    .into_iter()
                    .map(|(b, v)| (b, VarId::from(v)))
                    .collect(),
            })
            .collect();
    }

    // Post-pass: find variables used but never defined (created by Braun algorithm
    // at entry block for registers never written in the function). Inject synthetic
    // LoadConstUndefined definitions at the start of the entry block.
    let mut defined: std::collections::BTreeSet<VarId> = std::collections::BTreeSet::new();
    let mut used: Vec<VarId> = Vec::new();
    for block in &ssa_blocks {
        for phi in &block.phis {
            defined.insert(phi.dst);
        }
        for op in &block.ops {
            if let Some(dst) = &op.dst {
                defined.insert(*dst);
            }
            for operand in &op.operands {
                if let SsaOperand::Var(v) = operand
                    && !defined.contains(v)
                {
                    used.push(*v);
                }
            }
        }
    }
    // Inject definitions for undefined variables
    let undefined_vars: Vec<VarId> = used
        .into_iter()
        .filter(|v| !defined.contains(v))
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    if !undefined_vars.is_empty()
        && let Some(entry_block) = ssa_blocks.first_mut()
    {
        let mut synthetic_ops = Vec::new();
        for var in undefined_vars {
            synthetic_ops.push(SsaOp {
                name: "LoadConstUndefined",
                op: crate::opcodes::OpCode::LoadConstUndefined,
                dst: Some(var),
                operands: vec![SsaOperand::DstPlaceholder],
                original: super::decode::DecodedInst {
                    offset: 0,
                    size: 0,
                    opcode: 0,
                    name: "LoadConstUndefined",
                    op: crate::opcodes::OpCode::LoadConstUndefined,
                    operands: vec![],
                    op_types: &[],
                },
            });
        }
        synthetic_ops.append(&mut entry_block.ops);
        entry_block.ops = synthetic_ops;
    }

    let ssa_fn = SsaFunction::<Raw> {
        block_order: cfg.block_order.clone(),
        blocks: ssa_blocks,
        var_names: std::collections::BTreeMap::new(),
        param_names: std::collections::BTreeMap::new(),
        param_vars: param_var_map.into_values().collect(),
        _phase: PhantomData,
    };
    droidsaw_common::diag::stage_dump("ssa", &ssa_fn);
    Ok(ssa_fn)
}

impl SsaFunction<Raw> {
    /// Reinterpret a freshly-optimized Raw SSA as Resolved. The transition
    /// is meaningful only at the end of `optimize::optimize`'s body, which
    /// is where this method is intended to be called from. Phase is purely
    /// a phantom witness; no runtime data is touched.
    pub fn into_resolved(self) -> SsaFunction<Resolved> {
        SsaFunction::<Resolved> {
            blocks: self.blocks,
            block_order: self.block_order,
            var_names: self.var_names,
            param_names: self.param_names,
            param_vars: self.param_vars,
            _phase: PhantomData,
        }
    }
}

impl<P: Phase> SsaFunction<P> {
    /// Dump SSA IR for debugging. Phase-agnostic — both `Raw` and
    /// `Resolved` shapes render identically.
    pub fn dump(&self, get_str: &dyn Fn(u32) -> String) {
        for block in &self.blocks {
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
            println!(
                "BB_0x{:04x}: (preds: [{}], succs: [{}])",
                block.id,
                preds.join(","),
                succs.join(",")
            );

            for phi in &block.phis {
                let args: Vec<String> = phi
                    .args
                    .iter()
                    .map(|(b, v)| format!("0x{b:04x}:{v}"))
                    .collect();
                println!("    {} = phi({})", phi.dst, args.join(", "));
            }

            for op in &block.ops {
                let dst_str = match &op.dst {
                    Some(v) => format!("{v} = "),
                    None => String::new(),
                };
                let operands: Vec<String> = op
                    .operands
                    .iter()
                    .enumerate()
                    .map(|(i, o)| {
                        if i == 0 && op.dst.is_some() {
                            return String::new(); // skip dst in operand list
                        }
                        match o {
                            SsaOperand::Var(v) => format!("{v}"),
                            SsaOperand::Const(c) => format!("{c}"),
                            SsaOperand::ConstDouble(d) => format!("{d}"),
                            SsaOperand::StringId(s) => {
                                let val = get_str(*s);
                                if val.len() > 30 {
                                    format!("str[{s}]")
                                } else {
                                    format!("\"{val}\"")
                                }
                            }
                            SsaOperand::FuncId(f) => format!("func[{f}]"),
                            SsaOperand::DstPlaceholder => String::new(),
                            SsaOperand::BlockTarget(t) => format!("→0x{t:04x}"),
                            SsaOperand::ResolvedString(s) => format!("\"{s}\""),
                            SsaOperand::ResolvedBigInt(s) => format!("{s}n"),
                        }
                    })
                    .filter(|s| !s.is_empty())
                    .collect();

                println!("    {dst_str}{} {}", op.name, operands.join(", "));
            }
        }
    }
}

// SSA-construction regression tests (corpus-sample HBC fid 77091 single-pred
// cycle termination, three-block cycle, acyclic chain walk) have been
// promoted to the generic `droidsaw_common::ssa` module's test suite
// alongside the algorithm itself. Hermes-specific behaviour (opcode
// classification, LoadParam param_vars tracking, LoadConstUndefined
// post-pass) is covered by the HBC corpus tests in `droidsaw-bench`.

#[cfg(test)]
mod varid_display_roundtrip_tests {
    //! Round-trip gauge for `VarId::from_display_str ⟂ Display`. The
    //! parser is the inverse of the existing `Display` impl
    //! (`"r{reg}_{ver}"`), used by `count_var_uses` and `resolve_var`
    //! to recover the canonical VarId at lookup sites where upstream
    //! code carries the formatted string in a Stmt field. Locks the
    //! inverse contract + the rejection set against future drift.
    use super::VarId;
    use proptest::prelude::*;

    proptest! {
        /// For every VarId in the full (u32, u32) domain, the parser
        /// returns Some(v) on the Display output.
        #[test]
        fn display_str_round_trips_for_every_varid(reg: u32, ver: u32) {
            let v = VarId(reg, ver);
            let s = format!("{v}");
            prop_assert_eq!(VarId::from_display_str(&s), Some(v));
        }
    }

    /// Rejection set: every non-canonical input the production code
    /// might ever feed in must return `None`, not silently parse to a
    /// wrong VarId. These shapes are dropped at the boundary rather
    /// than silently parsed.
    #[test]
    fn rejects_non_canonical_inputs() {
        // Empty / missing prefix / no underscore.
        assert_eq!(VarId::from_display_str(""), None);
        assert_eq!(VarId::from_display_str("r"), None);
        assert_eq!(VarId::from_display_str("r_"), None);
        assert_eq!(VarId::from_display_str("r1_"), None);
        assert_eq!(VarId::from_display_str("_0"), None);
        assert_eq!(VarId::from_display_str("0_0"), None);
        // Non-digit components.
        assert_eq!(VarId::from_display_str("r1_a"), None);
        assert_eq!(VarId::from_display_str("rfoo_0"), None);
        // Wrong-case prefix.
        assert_eq!(VarId::from_display_str("R0_0"), None);
        // Extra structure (member-access chain, multi-underscore).
        assert_eq!(VarId::from_display_str("r0_0_0"), None);
        assert_eq!(VarId::from_display_str("r0_0.field"), None);
        // u32 overflow on the reg half (one past u32::MAX).
        assert_eq!(VarId::from_display_str("4294967296_0"), None);
        assert_eq!(VarId::from_display_str("r4294967296_0"), None);
        // Renamed display forms that production may pass through.
        assert_eq!(VarId::from_display_str("this"), None);
        assert_eq!(VarId::from_display_str("a0"), None);
        assert_eq!(VarId::from_display_str("globalThis"), None);
        assert_eq!(VarId::from_display_str("undefined"), None);
        // JS literal constants that might appear as switch-case labels.
        assert_eq!(VarId::from_display_str("42"), None);
        assert_eq!(VarId::from_display_str("\"foo\""), None);
    }

    /// Boundary values explicitly: zero, max, max-1, mixed.
    #[test]
    fn boundary_values_round_trip() {
        for &(reg, ver) in &[
            (0u32, 0u32),
            (0, 1),
            (1, 0),
            (u32::MAX, u32::MAX),
            (u32::MAX, 0),
            (0, u32::MAX),
            (u32::MAX - 1, u32::MAX - 1),
        ] {
            let v = VarId(reg, ver);
            assert_eq!(
                VarId::from_display_str(&format!("{v}")),
                Some(v),
                "round-trip failed for VarId({reg}, {ver})"
            );
        }
    }
}
