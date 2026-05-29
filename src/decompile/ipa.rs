//! Inter-procedural analysis: propagate argument names from call sites to callees.
//!
//! When function A calls `B(user, config)`, propagate "user" and "config" as
//! parameter names for function B. Uses plurality voting when multiple call
//! sites provide different names for the same parameter.
#![allow(
    clippy::cast_possible_truncation,
    reason = "PROOF: HBC parser/decompiler. IDs (string-id, builtin-id, function-id, regex-id) narrow from i64 to u32 only after parser bounds them against the validated HBC header u32 counts. Per-site #[allow] attributes at the deepest call sites carry the per-cast PROOF; this file-level allow is the umbrella for the remaining sites in the same family."
)]

#![allow(missing_docs, reason = "internal")]

use std::collections::BTreeMap;

use super::{cfg, decode, optimize, ssa};
use crate::parser;

/// Result of IPA: maps function_id → param_index → inferred name.
pub type IpaNames = BTreeMap<u32, BTreeMap<u32, String>>;

/// Run IPA across all functions in a bundle.
///
/// For each function:
/// 1. Build SSA and run optimizer (to get variable names)
/// 2. Scan for call instructions where the callee is a known function
/// 3. Collect argument names from the caller's variable naming
///
/// Returns a map of function_id → param_index → best name (plurality vote).
pub fn collect_param_names(
    hbc: &parser::HbcFile,
    data: &[u8],
    get_str: &dyn Fn(u32) -> String,
    get_func_name: &dyn Fn(u32) -> String,
) -> IpaNames {
    // Candidate names: func_id → param_index → name → count
    let mut candidates: BTreeMap<u32, BTreeMap<u32, BTreeMap<String, u32>>> = BTreeMap::new();

    let get_literal =
        |buf_type: u8, offset: u32, num_items: u32, index: u32| -> (u8, u32, i32, f64) {
            let val = hbc.literal_get(buf_type, offset, num_items, index);
            (val.tag, val.str_id, val.ival, val.dval)
        };
    // Lenient policy: corrupted / missing shape entry renders as
    // `(0, 0)`. See decompile/mod.rs `get_shape` for the rationale
    // (amplification-cap + the lenient-default contract for the
    // ipa-extraction walk).
    let get_shape = |index: u32| -> (u32, u32) {
        match hbc.object_shape_get(index) {
            Some(shape) => (shape.key_buffer_offset, shape.num_props),
            None => (0, 0),
        }
    };
    let get_bigint = |idx: u32| -> Option<String> { hbc.bigint_as_str(idx) };

    #[allow(clippy::as_conversions, reason = "this loop's `as` casts are u32→usize / usize→u64 widens on every project-supported target (32+-bit). Slice indexing below is bounds- gated by the `end > data.len() as u64` check and `body_end <= data.len()` by construction. Block-level allow keeps the per-cast annotations out of the loop body's hot reading path.")]
    for fid in 0..hbc.function_count {
        // Skip unrecognized functions: their lenient `function_get`
        // offset is the untrusted small-header fallback, so decoding
        // their body would route at an attacker-controllable position.
        if hbc.is_function_unrecognized(fid) {
            continue;
        }
        let f = hbc.function_get(fid);
        let end = u64::from(f.offset).saturating_add(u64::from(f.size));
        if end > data.len() as u64 || f.size == 0 {
            continue;
        }

        let code_end = (end as usize).saturating_add(256).min(data.len());
        let code = data
            .get(f.offset as usize..code_end)
            .unwrap_or(&[]);
        let body_end = u64::from(f.offset).saturating_add(u64::from(f.size)) as usize;
        let Some(body) = data.get(f.offset as usize..body_end) else {
            continue;
        };
        let Ok(instructions) = decode::decode_function(body, hbc.opcode_version()) else {
            continue;
        };

        let exc_count = hbc.function_exception_count(fid);
        let mut exc_handlers = Vec::new();
        for i in 0..exc_count {
            let eh = hbc.function_exception_get(fid, i);
            exc_handlers.push(cfg::ExcHandler {
                start: eh.start,
                end: eh.end,
                target: eh.target,
            });
        }

        let Ok(cfg) = cfg::Cfg::build(&instructions, &exc_handlers, code) else {
            continue;
        };
        let Ok(ssa_func) = ssa::build_ssa(&cfg, f.frame_size) else {
            continue;
        };
        let ssa_func = optimize::optimize(
            ssa_func,
            get_str,
            &get_literal,
            &get_shape,
            get_func_name,
            &get_bigint,
        );

        // Build closure map: VarId → target function ID
        let mut closure_targets: BTreeMap<ssa::VarId, u32> = BTreeMap::new();
        for block in &ssa_func.blocks {
            for op in &block.ops {
                if (op.name.starts_with("CreateClosure")
                    || op.name.starts_with("CreateAsyncClosure")
                    || op.name.starts_with("CreateGeneratorClosure"))
                    && let Some(dst) = &op.dst
                {
                    // Last operand is the function ID
                    if let Some(&ssa::SsaOperand::Const(func_id)) = op.operands.last() {
                        // WHY: i64→u32 narrows; func_id is the bytecode-format
                        // function index (bounded by `function_count` u32 in
                        // the HBC header); wrap is unreachable.
                        #[allow(clippy::as_conversions, clippy::cast_possible_truncation, clippy::cast_sign_loss, reason = "i64→u32 narrows + sign-loss; func_id is the bytecode-format function index (bounded by `function_count` u32 in the HBC header, non-negative by construction); truncation/sign-loss unreachable.")]
                        closure_targets.insert(*dst, func_id as u32);
                    }
                }
            }
        }

        // Scan call instructions for argument names
        for block in &ssa_func.blocks {
            for op in &block.ops {
                let (target_fid, arg_start) = match op.name {
                    // CallDirect: last original operand is func_id
                    "CallDirect" | "CallDirectLongIndex" => {
                        let func_id = op.original.operands.last().and_then(|o| {
                            if let decode::Operand::UInt(v) = o {
                                Some(*v)
                            } else {
                                None
                            }
                        });
                        (func_id, 0)
                    }
                    // Call1-4: first implicit arg is the callee, resolve via closure_targets
                    n if n.starts_with("Call") && !n.contains("Builtin") => {
                        let callee_var = op.operands.iter().find_map(|o| {
                            if let ssa::SsaOperand::Var(v) = o {
                                Some(*v)
                            } else {
                                None
                            }
                        });
                        let target = callee_var.and_then(|v| closure_targets.get(&v).copied());
                        // Args: index 0 is callee, index 1 is this, real args start at 2
                        (target, 2)
                    }
                    _ => (None, 0),
                };

                if let Some(target_fid) = target_fid {
                    // Extract argument variable names
                    let implicit_args: Vec<&ssa::SsaOperand> = op
                        .operands
                        .iter()
                        .filter(|o| matches!(o, ssa::SsaOperand::Var(_)))
                        .collect();

                    for (i, arg) in implicit_args.iter().enumerate().skip(arg_start) {
                        if let ssa::SsaOperand::Var(var_id) = arg {
                            // Look up the variable name from the optimizer's naming pass
                            if let Some(name) = ssa_func.var_names.get(var_id) {
                                // Skip generic register names (r0.1) and param names (a0)
                                if !name.starts_with('r')
                                    && !name.starts_with('a')
                                    && !name.is_empty()
                                    && super::expr::is_valid_js_ident(name)
                                {
                                    // WHY: usize→u32 narrows; param indices
                                    // are bounded by frame-size operand
                                    // (≤ u8 in HBC headers).
                                    #[allow(clippy::as_conversions, clippy::cast_possible_truncation, reason = "usize→u32 narrows; param indices are bounded by frame-size operand (≤ u8 in HBC headers), so truncation cannot fire.")]
                                    let param_idx = i.saturating_sub(arg_start) as u32;
                                    let counter = candidates
                                        .entry(target_fid)
                                        .or_default()
                                        .entry(param_idx)
                                        .or_default()
                                        .entry(name.clone())
                                        .or_insert(0);
                                    *counter = counter.saturating_add(1);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Plurality vote: pick the most common name for each (func_id, param_index)
    let mut result: IpaNames = BTreeMap::new();
    for (func_id, params) in &candidates {
        for (param_idx, names) in params {
            if let Some((best_name, _count)) = names.iter().max_by_key(|(_, count)| *count) {
                result
                    .entry(*func_id)
                    .or_default()
                    .insert(*param_idx, best_name.clone());
            }
        }
    }

    result
}
