//! SSA optimization passes: copy propagation, expression propagation, dead code elimination.
#![cfg_attr(
    not(test),
    allow(
        clippy::indexing_slicing,
        clippy::string_slice,
        reason = "PROOF: optimizer operates on validated SSA built by ssa::Builder. Every VarId, BlockIdx, def-site, use-site, and phi index is minted at SSA construction time. Worklist iteration consumes minted indices; rewrite passes preserve the indexing invariants of the input SSA. v1.x refinement candidate (~33 sites; uniform invariant)."
    )
)]
//!
//! **Cast hygiene**: ~50 `as`-cast sites in this module fall into three
//! buckets:
//!
//! 1. Constant-folding arithmetic reinterprets (`i64 → i32`/`f64`/`u32` for
//!    JS semantic ops: Add, Sub, BitAnd, LShift, etc.) — semantic by
//!    definition; no bound to cite beyond "JS bitwise ops coerce to i32 per
//!    spec; arithmetic ops use f64". Wrapped in a block-level allow on the
//!    fold_constants function.
//! 2. HBC-ID narrows (`i64 → u32` for string-id, builtin-id, function-id,
//!    regex-id) — bounded by HBC header `*_count` u32 fields at parse time;
//!    narrow is unreachable on well-formed HBC. Routed through
//!    `const_id_to_u32` helper with a single function-level WHY.
//! 3. Slot-id / level-id narrows with explicit `& 0xFFFF` masks — bounded
//!    by construction; annotated per-site.
#![allow(missing_docs, reason = "internal")]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    clippy::cast_possible_wrap,
    reason = "PROOF: all casts fall into the three buckets named in the module-level Cast hygiene doc-comment above. Bucket 1 (constant-fold arithmetic) is JS-spec-defined semantic reinterpretation; Bucket 2 (HBC-ID narrows) is bounded by parser-validated u32 header counts; Bucket 3 (slot/level-id) is bounded by explicit `& 0xFFFF` masks. The cast_* lint family fires on the same `as` sites the existing per-fn clippy::as_conversions allows already document."
)]

use std::collections::{BTreeMap, BTreeSet};

use rustc_hash::{FxHashMap, FxHashSet};

// DETERMINISM: FxHashMap/FxHashSet usage in this module is internal-only.
// All swaps below replace BTreeMap<VarId, _> / BTreeSet<VarId> — keyed by
// VarId for O(1) lookup during SSA optimize passes. None iterate the
// resulting map for emit-order output; emit uses block / instruction
// order from `SsaFunction.blocks` / `block.ops` (Vec, insertion-ordered).
// count_uses is a profiled hot-path; FxHashMap reduces alloc pressure
// relative to BTreeMap on the per-function-sized maps here.


use super::ssa::{Raw, Resolved, SsaBlock, SsaFunction, SsaOp, SsaOperand, VarId};

/// Format an f64 as a valid JS numeric literal.
/// Uses scientific notation for extreme values to avoid 300-digit decimals
/// that OXC rejects. Handles NaN, Infinity, and subnormals.
fn fmt_js_double(v: f64) -> String {
    if v.is_nan() {
        return "NaN".to_string();
    }
    if v.is_infinite() {
        return if v > 0.0 {
            "Infinity".to_string()
        } else {
            "-Infinity".to_string()
        };
    }
    if v == 0.0 {
        return "0".to_string();
    }
    let abs = v.abs();
    // Use default formatting for "normal" values; scientific for extreme
    if (1e-6..1e20).contains(&abs) {
        format!("{v}")
    } else {
        format!("{v:e}")
    }
}

/// Escape a string for safe embedding in a JS double-quoted string literal.
fn escape_js_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\0' => out.push_str("\\0"),
            c if c.is_control() => {
                out.push_str(&format!("\\u{:04x}", u32::from(c)));
            }
            c => out.push(c),
        }
    }
    out
}

/// Check if a string is a valid JS identifier and not a reserved word.
fn is_valid_js_ident(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let mut chars = s.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_alphabetic() && first != '_' && first != '$' {
        return false;
    }
    if !chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$') {
        return false;
    }
    !is_js_reserved(s)
}

fn is_js_reserved(s: &str) -> bool {
    matches!(
        s,
        "break"
            | "case"
            | "catch"
            | "continue"
            | "debugger"
            | "default"
            | "delete"
            | "do"
            | "else"
            | "finally"
            | "for"
            | "function"
            | "if"
            | "in"
            | "instanceof"
            | "new"
            | "return"
            | "switch"
            | "this"
            | "throw"
            | "try"
            | "typeof"
            | "var"
            | "void"
            | "while"
            | "with"
            | "class"
            | "const"
            | "enum"
            | "export"
            | "extends"
            | "import"
            | "super"
            | "implements"
            | "interface"
            | "let"
            | "package"
            | "private"
            | "protected"
            | "public"
            | "static"
            | "yield"
            | "await"
            | "null"
            | "true"
            | "false"
    )
}

/// Sugar: rewrite tagged-template call shapes into the synthetic
/// `HermesTaggedTemplate` SSA op.
///
/// Hermes compiles `` tag`chunk0${sub0}chunk1...` `` as:
///   - A `CallBuiltin HermesBuiltin.getTemplateObject` whose args are
///     `(templateObjId, dupFlag, raw0, raw1, ..., rawN-1, cooked0, ..., cookedN-1)`
///     — raws first, then cookeds (confirmed via `hermesc -dump-bytecode`
///     against reference fixtures, and consistent with
///     `UnrollGetTemplateObject` in Hermes's compiler).
///   - A `Call*` whose first arg is the getTemplateObject result and whose
///     remaining args are the `sub0..subM` substitution values.
///
/// After this pass, the Call* op is renamed to `HermesTaggedTemplate` with
/// operand layout
///   `[DstPlaceholder, tag, Const(chunk_count), ResolvedString(cooked0),
///     ResolvedString(raw0), ..., ResolvedString(cookedN-1),
///     ResolvedString(rawN-1), <subs…>]`
/// which `expr.rs::build_expr` lowers to `Expr::TaggedTemplate`. The
/// getTemplateObject CallBuiltin itself is left in place; dead-code
/// elimination removes it when the result var is no longer referenced.
///
/// The rewrite is skipped when cooked/raw chunks aren't both resolvable as
/// `ResolvedString`, which preserves the raw `HermesBuiltin.getTemplateObject(...)`
/// emit as a truthful fallback.
#[allow(clippy::as_conversions, clippy::cast_possible_truncation, clippy::cast_sign_loss, clippy::cast_possible_wrap, reason = "i64→u32 narrows on HBC builtin-id (bounded by parser-validated builtin-id u8/u16 operand width — truncation/sign-loss unreachable); usize→i64 on chunk_count bounded by operands.len() (≤ HBC op-count cap, wrap unreachable). See module doc bucket 2.")]
fn rewrite_tagged_templates(func: &mut SsaFunction<Raw>) {
    // Pass 1: find every CallBuiltin-getTemplateObject and extract its chunks.
    //
    // Operand layout after `build_ssa` + string propagation:
    //   operands[0] = DstPlaceholder
    //   operands[1] = Const(builtin_id)
    //   operands[2] = Const(argc_bytecode)   — includes implicit thisArg slot
    //   operands[3] = Const(templateObjId)   — first explicit ABI arg
    //   operands[4] = Const(dupFlag)
    //   operands[5..5+N] = ResolvedString(raw_i)      for i in 0..N
    //   operands[5+N..5+2N] = ResolvedString(cooked_i) for i in 0..N
    //
    // `template_def_sites` tracks (block_idx, op_idx) for each template-object
    // producer so pass 3 can delete the producer once all consumers are
    // rewritten into TaggedTemplate (the CallBuiltin getTemplateObject is
    // side-effect-free for this purpose: frozen-object construction with no
    // observable mutation, caching is transparent, and its sole consumer is
    // the now-rewritten Call).
    let mut templates: FxHashMap<VarId, (Vec<String>, Vec<String>)> = FxHashMap::default();
    let mut template_def_sites: FxHashMap<VarId, (usize, usize)> = FxHashMap::default();
    for (bi, block) in func.blocks.iter().enumerate() {
        for (oi, op) in block.ops.iter().enumerate() {
            if op.name != "CallBuiltin" && op.name != "CallBuiltinLong" {
                continue;
            }
            let Some(SsaOperand::Const(builtin_id)) = op.operands.get(1) else {
                continue;
            };
            if super::expr::is_get_template_object(*builtin_id as u32).is_none() {
                continue;
            }
            if op.operands.len() < 7 {
                continue;
            }
            let chunk_count = op.operands.len().saturating_sub(5) / 2;
            if chunk_count == 0
                || 5usize.saturating_add(chunk_count.saturating_mul(2)) != op.operands.len()
            {
                continue;
            }
            let raws_start: usize = 5;
            let cookeds_start = raws_start.saturating_add(chunk_count);
            let mut raw = Vec::with_capacity(chunk_count);
            let mut cooked = Vec::with_capacity(chunk_count);
            let mut ok = true;
            for i in 0..chunk_count {
                match (
                    op.operands.get(raws_start.saturating_add(i)),
                    op.operands.get(cookeds_start.saturating_add(i)),
                ) {
                    (
                        Some(SsaOperand::ResolvedString(r)),
                        Some(SsaOperand::ResolvedString(c)),
                    ) => {
                        raw.push(r.clone());
                        cooked.push(c.clone());
                    }
                    _ => {
                        ok = false;
                        break;
                    }
                }
            }
            if !ok {
                continue;
            }
            if let Some(dst) = op.dst {
                templates.insert(dst, (cooked, raw));
                template_def_sites.insert(dst, (bi, oi));
            }
        }
    }
    if templates.is_empty() {
        return;
    }

    // Pass 2: rewrite matching Call* ops. Track which template vars got
    // consumed so pass 3 can delete their producers.
    let mut consumed: FxHashSet<VarId> = FxHashSet::default();
    for block in &mut func.blocks {
        for op in &mut block.ops {
            // arg0 index after SSA's variadic resolver. Call*N fixed-arity
            // ops place arg0 at index 3 (dst, callee, thisArg, arg0...).
            // Variadic Call / CallDirect place arg0 at index 4 (dst, callee,
            // argc, thisArg, arg0... or dst, argc, funcId, thisArg, arg0...).
            let arg0_idx = match op.name {
                "Call1" | "Call2" | "Call3" | "Call4" => 3,
                "Call" | "CallLong" | "CallDirect" | "CallDirectLongIndex" => 4,
                _ => continue,
            };
            let Some(SsaOperand::Var(arg0_var)) = op.operands.get(arg0_idx) else {
                continue;
            };
            let arg0_var = *arg0_var;
            let Some((cooked, raw)) = templates.get(&arg0_var) else {
                continue;
            };
            let callee = op
                .operands
                .get(1)
                .cloned()
                .unwrap_or(SsaOperand::DstPlaceholder);
            // Substitution values: everything after arg0.
            let subs: Vec<SsaOperand> = op
                .operands
                .iter()
                .skip(arg0_idx.saturating_add(1))
                .cloned()
                .collect();

            let chunk_count = cooked.len();
            let mut new_ops: Vec<SsaOperand> = Vec::with_capacity(
                3usize
                    .saturating_add(chunk_count.saturating_mul(2))
                    .saturating_add(subs.len()),
            );
            new_ops.push(SsaOperand::DstPlaceholder);
            new_ops.push(callee);
            new_ops.push(SsaOperand::Const(chunk_count as i64));
            for i in 0..chunk_count {
                new_ops.push(SsaOperand::ResolvedString(cooked[i].clone()));
                new_ops.push(SsaOperand::ResolvedString(raw[i].clone()));
            }
            new_ops.extend(subs);

            op.name = "HermesTaggedTemplate";
            op.operands = new_ops;
            consumed.insert(arg0_var);
        }
    }

    // Pass 3: delete the getTemplateObject producers whose result got folded
    // into a TaggedTemplate — *only when* the template-object var has no
    // remaining readers. Recount uses over the post-rewrite function so the
    // check reflects the TaggedTemplate operand layout (which strips the
    // original arg0 var reference) rather than the pre-rewrite shape. If any
    // unrelated op still reads the producer's dst (e.g. a user-authored
    // alias like `const tpl = String.raw\`...\`; use(tpl);`), leaving the
    // producer in place preserves the reader's reference; the main DCE pass
    // will elide it later if subsequent optimization drops those readers.
    let post_uses = count_uses(func);
    let mut by_block: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for var in consumed {
        // SEMANTICS-DEFAULT-EMPTY: `count_uses` only inserts a key when a var is
        // referenced at least once; absent key → 0 uses, which is the correct sentinel
        // for "this var has no remaining readers after rewrite".
        // SEMANTICS-DEFAULT-EMPTY: var absent from use-counts ⇒ 0 uses; dead-code/phi-elim correctly removes the entry.
        if post_uses.get(&var).copied().unwrap_or(0) > 0 {
            continue;
        }
        if let Some((bi, oi)) = template_def_sites.get(&var) {
            by_block.entry(*bi).or_default().push(*oi);
        }
    }
    for (bi, mut indices) in by_block {
        indices.sort_unstable();
        indices.dedup();
        if let Some(block) = func.blocks.get_mut(bi) {
            for oi in indices.into_iter().rev() {
                if oi < block.ops.len() {
                    block.ops.remove(oi);
                }
            }
        }
    }
}

/// Elide `HermesBuiltin.initRegexNamedGroups(regex, groups_map)` calls
/// whose result is unused. See the caller WHY comment in `pattern_rewrite`
/// for the source-vs-compiler-artifact rationale. Implementation walks
/// the function once to count VarId reads (including phi args), then
/// drops matching ops when `uses[dst] == 0`. Safe across blocks because
/// the count is global.
// WHY: i64→u32 narrow on HBC builtin-id. See module doc bucket 2.
#[allow(clippy::as_conversions, clippy::cast_possible_truncation, clippy::cast_sign_loss, reason = "i64→u32 narrow on HBC builtin-id; bounded by parser-validated builtin-id operand width (u8/u16), truncation/sign-loss unreachable. See module doc bucket 2.")]
fn elide_init_regex_named_groups(func: &mut SsaFunction<Raw>) {
    // Pre-count uses over the current IR so cross-block readers keep the
    // call alive (defensive: hermesc-emitted code never uses the result,
    // but adversarial HBC could, and we'd rather leave the call visible
    // than drop a result a downstream op depends on).
    let uses = count_uses(func);
    for block in &mut func.blocks {
        block.ops.retain(|op| {
            if op.name != "CallBuiltin" && op.name != "CallBuiltinLong" {
                return true;
            }
            let Some(SsaOperand::Const(id)) = op.operands.get(1) else {
                return true;
            };
            if super::expr::is_init_regex_named_groups(*id as u32).is_none() {
                return true;
            }
            let Some(dst) = op.dst else {
                return true;
            };
            // SEMANTICS-DEFAULT-EMPTY: absent key in `count_uses` map means 0 uses.
            // SEMANTICS-DEFAULT-EMPTY: var absent from use-counts ⇒ 0 uses; dead-code/phi-elim correctly removes the entry.
            uses.get(&dst).copied().unwrap_or(0) > 0
        });
    }
}

/// Fold `NewArrayWithBuffer + CallBuiltin arraySpread + DefineOwnByVal`
/// into a synthetic `HermesArraySpreadLit` op carrying the structured
/// prefix / spread-src / trailing-value triple. See
/// `rewrite_tagged_templates` for the synthetic-op precedent.
///
/// Operand layout of the synthetic op (consumed by `expr.rs`):
///   [DstPlaceholder, ResolvedString(prefix_literal_or_empty),
///    Var(spread_src), <TrailingExpr>]
/// where `prefix_literal_or_empty` is the raw ResolvedString inherited
/// from the original NewArrayWithBuffer (`"[5]"`, `"[1, 2, 3]"`, etc.)
/// without modification — the emit arm parses out its bracketed elements.
/// `<TrailingExpr>` is the `DefineOwnByVal`'s value operand (already
/// resolved by earlier passes: Const / ResolvedString / Var).
///
/// Conditions for folding (strict, bail on any miss):
///   - The cluster is entirely within a single block (no cross-block
///     data flow; keeps use-count reasoning local).
///   - `NewArrayWithBuffer`'s dst is read by both the arraySpread's
///     target-operand AND the DefineOwnByVal's object-operand (same-
///     target invariant — the DefineOwnByVal writes into the array
///     that was just spread into).
///   - The arraySpread's dst is used exactly once, by the matching
///     DefineOwnByVal's key-operand (the returned next-free-idx).
///   - Order: NewArrayWithBuffer precedes arraySpread precedes
///     DefineOwnByVal in the block.
///
/// On match, the NewArrayWithBuffer op is rewritten in place to
/// `HermesArraySpreadLit`; arraySpread + DefineOwnByVal are removed.
/// Only the simple `[prefix, ...src, trailing]` shape is handled;
/// multi-spread or multi-trailing shapes (rare in hermesc output)
/// fall through to the legacy three-statement emit.
// WHY: i64→u32 narrow on HBC builtin-id. See module doc bucket 2.
#[allow(clippy::as_conversions, clippy::cast_possible_truncation, clippy::cast_sign_loss, reason = "i64→u32 narrow on HBC builtin-id; bounded by parser-validated builtin-id operand width (u8/u16), truncation/sign-loss unreachable. See module doc bucket 2.")]
fn rewrite_array_spread_sugar(func: &mut SsaFunction<Raw>) {
    let uses = count_uses(func);
    // Block-scoped rewrite — indices only meaningful within one block.
    for block in &mut func.blocks {
        // Scan for the arraySpread call; from it, locate the matching
        // NewArrayWithBuffer (prior) and DefineOwnByVal (subsequent).
        let mut clusters: Vec<(usize, usize, usize)> = Vec::new();
        for (i, op) in block.ops.iter().enumerate() {
            if op.name != "CallBuiltin" && op.name != "CallBuiltinLong" {
                continue;
            }
            let Some(SsaOperand::Const(builtin_id)) = op.operands.get(1) else {
                continue;
            };
            if super::expr::is_array_spread(*builtin_id as u32).is_none() {
                continue;
            }
            // arraySpread resolved operand layout after frame-relative
            // variadic fix: [dst, Const(id), Const(argc), arg0=target,
            // arg1=src, arg2=startIdx]. argc should be 4 (thisArg + 3
            // explicit args); bail if different.
            let Some(SsaOperand::Const(argc)) = op.operands.get(2) else {
                continue;
            };
            if *argc != 4 {
                continue;
            }
            let Some(SsaOperand::Var(target_var)) = op.operands.get(3) else {
                continue;
            };
            let Some(arr_spread_dst) = op.dst else {
                continue;
            };
            // arraySpread.dst must be used exactly once (by the
            // matching DefineOwnByVal). More than one use means the
            // returned index escaped into other computation — bail.
            // SEMANTICS-DEFAULT-EMPTY: absent key in `count_uses` map means 0 uses.
            // SEMANTICS-DEFAULT-EMPTY: var absent from use-counts ⇒ 0 uses; dead-code/phi-elim correctly removes the entry.
            if uses.get(&arr_spread_dst).copied().unwrap_or(0) != 1 {
                continue;
            }
            // Locate NewArrayWithBuffer preceding in the block with
            // dst == target_var AND a resolved ResolvedString operand[1]
            // (post-`resolve_buffers` form). If target is produced by a
            // different op (plain `NewArray`, or cross-block def),
            // bail — current scope only handles the with-buffer case.
            let mut prefix_idx: Option<usize> = None;
            for (pi, prev_op) in block.ops.iter().enumerate().take(i) {
                if prev_op.dst == Some(*target_var)
                    && (prev_op.name == "NewArrayWithBuffer"
                        || prev_op.name == "NewArrayWithBufferLong")
                    && matches!(prev_op.operands.get(1), Some(SsaOperand::ResolvedString(_)))
                {
                    prefix_idx = Some(pi);
                }
            }
            let Some(prefix_idx) = prefix_idx else { continue };
            // Locate DefineOwnByVal subsequent in the block with
            // operand layout [obj=target_var, value, key=arr_spread_dst, flag].
            let mut define_idx: Option<usize> = None;
            for (di, subsequent_op) in block.ops.iter().enumerate().skip(i.saturating_add(1)) {
                if subsequent_op.name != "DefineOwnByVal"
                    && subsequent_op.name != "DefineOwnInDenseArray"
                    && subsequent_op.name != "DefineOwnInDenseArrayL"
                {
                    continue;
                }
                let obj_matches = matches!(
                    subsequent_op.operands.first(),
                    Some(SsaOperand::Var(v)) if *v == *target_var
                );
                let key_matches = matches!(
                    subsequent_op.operands.get(2),
                    Some(SsaOperand::Var(v)) if *v == arr_spread_dst
                );
                if obj_matches && key_matches {
                    define_idx = Some(di);
                    break;
                }
                // Any op that writes to target_var invalidates the
                // cluster (another path could mutate the target before
                // the trailing write).
                if subsequent_op.dst == Some(*target_var) {
                    break;
                }
            }
            let Some(define_idx) = define_idx else { continue };
            clusters.push((prefix_idx, i, define_idx));
        }
        if clusters.is_empty() {
            continue;
        }
        // Apply rewrites in reverse index order so earlier indices stay
        // valid as we remove tail ops.
        clusters.sort_by_key(|&(p, _, _)| p);
        // Build a flat removal set (arraySpread + DefineOwnByVal indices
        // from each cluster) and a prefix-index → (src_var, trailing_op)
        // rewrite map.
        let mut prefix_rewrites: BTreeMap<usize, (SsaOperand, SsaOperand)> = BTreeMap::new();
        let mut to_remove: BTreeSet<usize> = BTreeSet::new();
        for &(prefix_idx, arr_spread_idx, define_idx) in &clusters {
            // Fetch src_var (operand[4] of arraySpread) + trailing value
            // (operand[1] of DefineOwnByVal) before mutating the block.
            let Some(arr_spread_op) = block.ops.get(arr_spread_idx) else {
                continue;
            };
            let Some(src_operand) = arr_spread_op.operands.get(4).cloned() else {
                continue;
            };
            let Some(define_op) = block.ops.get(define_idx) else {
                continue;
            };
            let Some(trailing_operand) = define_op.operands.get(1).cloned() else {
                continue;
            };
            prefix_rewrites.insert(prefix_idx, (src_operand, trailing_operand));
            to_remove.insert(arr_spread_idx);
            to_remove.insert(define_idx);
        }
        // Rewrite the NewArrayWithBuffer ops to the synthetic name + new
        // operand layout, preserving dst.
        for (&pi, (src_operand, trailing_operand)) in &prefix_rewrites {
            if let Some(op) = block.ops.get_mut(pi) {
                let Some(prefix_str) = op.operands.get(1).cloned() else {
                    continue;
                };
                op.name = "HermesArraySpreadLit";
                op.operands = vec![
                    SsaOperand::DstPlaceholder,
                    prefix_str,
                    src_operand.clone(),
                    trailing_operand.clone(),
                ];
            }
        }
        // Remove the arraySpread + DefineOwnByVal ops (reverse order).
        let mut remove_sorted: Vec<usize> = to_remove.into_iter().collect();
        remove_sorted.sort_unstable();
        for idx in remove_sorted.into_iter().rev() {
            if idx < block.ops.len() {
                block.ops.remove(idx);
            }
        }
    }
}

/// Fold `NewObject + CallBuiltin copyDataProperties(...)` clusters
/// into a synthetic `HermesObjectSpreadLit` op that renders as an
/// `Expr::ObjectLit` with `Spread` entries — the inverse of hermesc's
/// lowering of `{...source}` / `{a: 1, ...src, c: 3}`.
///
/// Operand layout of the synthetic op (consumed by `expr.rs`):
///   [DstPlaceholder, ResolvedString("K:keyname" | "S"), operand, ...]
/// where each `(tag, operand)` pair encodes one entry:
///   - `"K:<name>"` + value operand → `ObjectEntry::KeyVal(name, value)`
///   - `"S"` + source operand       → `ObjectEntry::Spread(source)`
///
/// Conditions for folding:
///   - Cluster is within a single block (keeps use-counting local).
///   - Leading op creates the target: either `NewObject(dst)` (empty
///     base) or `NewObjectWithBuffer(dst, "{k: v, ...}")` (pre-seeded
///     KeyVal prefix — after `resolve_buffers` runs, the literal is a
///     `ResolvedString`).
///   - Followed by ≥1 `CallBuiltin copyDataProperties` whose target-
///     operand is the cluster dst.
///   - Optionally followed by `PutOwnByIndex` / `PutOwnByIndexL` /
///     `PutOwnById` / `PutOwnByIdLong` / `PutOwnByIdShort` that write
///     literal keys to the cluster dst (trailing explicit props).
///   - The cluster dst must be used downstream (at least once after
///     the cluster ends) — otherwise the fold produces dead code.
///
/// On match, the leading `NewObject`/`NewObjectWithBuffer` is rewritten
/// in place to `HermesObjectSpreadLit` with the entry-encoded operand
/// layout; the `copyDataProperties` + `PutOwn*` ops are removed. The
/// prefix entries (for `NewObjectWithBuffer`) are hoisted into the
/// synthesized entry list so the final literal reads naturally.
///
/// Only block-local clusters with sane operand shapes are folded;
/// anything else falls through to the legacy unfolded emit.
// WHY: i64→u32 narrow on HBC builtin-id; matches `rewrite_array_spread_sugar`.
#[allow(clippy::as_conversions, clippy::cast_possible_truncation, clippy::cast_sign_loss, reason = "i64→u32 narrow on HBC builtin-id; bounded by parser-validated builtin-id operand width (u8/u16), truncation/sign-loss unreachable. Matches `rewrite_array_spread_sugar`.")]
fn rewrite_object_spread_sugar(func: &mut SsaFunction<Raw>) {
    let uses = count_uses(func);
    for block in &mut func.blocks {
        // First pass: scan for the earliest copyDataProperties call in
        // each cluster, pair it with a preceding NewObject/Buffer, then
        // extend the cluster with additional copyDataProperties calls
        // + trailing PutOwn* writes on the same dst.
        let mut clusters: Vec<ObjectSpreadCluster> = Vec::new();
        let mut consumed: BTreeSet<usize> = BTreeSet::new();

        for (i, op) in block.ops.iter().enumerate() {
            if consumed.contains(&i) {
                continue;
            }
            if op.name != "CallBuiltin" && op.name != "CallBuiltinLong" {
                continue;
            }
            let Some(SsaOperand::Const(builtin_id)) = op.operands.get(1) else {
                continue;
            };
            if super::expr::is_copy_data_properties(*builtin_id as u32).is_none() {
                continue;
            }
            // copyDataProperties operand layout:
            //   [dst, Const(id), Const(argc), arg0=target, arg1=source,
            //    arg2?=excluded_set]
            // We require argc ≥ 4 (thisArg + target + source, maybe
            // excluded). Target must be a Var.
            let Some(SsaOperand::Var(target_var)) = op.operands.get(3) else {
                continue;
            };
            let Some(SsaOperand::Var(source_var)) = op.operands.get(4) else {
                continue;
            };
            // Locate the preceding allocator with dst == target_var.
            // `NewObject` → empty base; `NewObjectWithBuffer[Long]` →
            // prefix (literal entries already resolved into operand[1]
            // as a `ResolvedString`).
            let mut alloc_idx: Option<usize> = None;
            for (pi, prev_op) in block.ops.iter().enumerate().take(i) {
                if prev_op.dst != Some(*target_var) {
                    continue;
                }
                if prev_op.name == "NewObject" || prev_op.name == "CacheNewObject" {
                    alloc_idx = Some(pi);
                    break;
                }
                if (prev_op.name == "NewObjectWithBuffer"
                    || prev_op.name == "NewObjectWithBufferLong"
                    || prev_op.name == "NewObjectWithBufferAndParent")
                    && matches!(
                        prev_op.operands.get(1),
                        Some(SsaOperand::ResolvedString(_))
                    )
                {
                    alloc_idx = Some(pi);
                    break;
                }
                // Any other op producing target_var means the
                // allocator isn't where we expect — bail.
                alloc_idx = None;
                break;
            }
            let Some(alloc_idx) = alloc_idx else {
                continue;
            };

            // Extend the cluster: walk forward from `i` collecting
            // additional copyDataProperties + PutOwn* ops on the same
            // target until we hit an op that isn't part of the cluster
            // (e.g. the downstream consumer read).
            let mut entries: Vec<ObjectSpreadEntry> = Vec::new();
            // Spread entry from the current copyDataProperties.
            entries.push(ObjectSpreadEntry::Spread(SsaOperand::Var(*source_var)));
            let mut removals: Vec<usize> = vec![i];

            for (ni, next_op) in block.ops.iter().enumerate().skip(i.saturating_add(1)) {
                if consumed.contains(&ni) {
                    break;
                }
                // Another copyDataProperties on the same target → spread
                if (next_op.name == "CallBuiltin" || next_op.name == "CallBuiltinLong")
                    && matches!(
                        next_op.operands.get(1),
                        Some(SsaOperand::Const(id))
                            if super::expr::is_copy_data_properties(*id as u32).is_some()
                    )
                    && matches!(
                        next_op.operands.get(3),
                        Some(SsaOperand::Var(v)) if *v == *target_var
                    )
                {
                    let Some(src_operand) = next_op.operands.get(4).cloned() else {
                        break;
                    };
                    entries.push(ObjectSpreadEntry::Spread(src_operand));
                    removals.push(ni);
                    continue;
                }
                // PutOwnByIndex / PutOwnByIndexL: operand layout
                //   [obj=target, value, Const(index)]. We treat the
                //   numeric index as the key string (e.g. `"0"`, `"1"`).
                if (next_op.name == "PutOwnByIndex" || next_op.name == "PutOwnByIndexL")
                    && matches!(
                        next_op.operands.first(),
                        Some(SsaOperand::Var(v)) if *v == *target_var
                    )
                {
                    let Some(value_operand) = next_op.operands.get(1).cloned() else {
                        break;
                    };
                    let Some(SsaOperand::Const(idx)) = next_op.operands.get(2) else {
                        break;
                    };
                    entries.push(ObjectSpreadEntry::KeyVal(idx.to_string(), value_operand));
                    removals.push(ni);
                    continue;
                }
                // DefineOwnById / DefineOwnByIdLong / PutOwnById / etc:
                //   [obj=target, value, Const(_slot), ResolvedString(key)]
                // after resolve_buffers. Hermes v96 emits the trailing
                // `c: 3` in `{...a, c: 3}` as `DefineOwnById`; later
                // versions / other shapes use `PutOwnById*`. We accept
                // both and require the ResolvedString key form; bail
                // on any other operand shape.
                if (next_op.name == "DefineOwnById"
                    || next_op.name == "DefineOwnByIdLong"
                    || next_op.name == "PutOwnById"
                    || next_op.name == "PutOwnByIdLong"
                    || next_op.name == "PutOwnByIdShort")
                    && matches!(
                        next_op.operands.first(),
                        Some(SsaOperand::Var(v)) if *v == *target_var
                    )
                {
                    let Some(value_operand) = next_op.operands.get(1).cloned() else {
                        break;
                    };
                    let Some(SsaOperand::ResolvedString(key)) = next_op.operands.get(3) else {
                        break;
                    };
                    entries.push(ObjectSpreadEntry::KeyVal(key.clone(), value_operand));
                    removals.push(ni);
                    continue;
                }
                // Any other op that writes to target_var invalidates
                // the cluster (the dst has been mutated outside the
                // fold's recognition set).
                if next_op.dst == Some(*target_var) {
                    break;
                }
                // Any op that reads target_var ends the cluster
                // (downstream consumer seen — fold stops here).
                let reads_target = next_op
                    .operands
                    .iter()
                    .any(|o| matches!(o, SsaOperand::Var(v) if *v == *target_var));
                if reads_target {
                    break;
                }
            }

            // Require the cluster dst to have downstream uses; a dst
            // that's never read means the cluster is dead and the fold
            // would produce an unused ObjectLit.
            // SEMANTICS-DEFAULT-EMPTY: absent key in `count_uses` map means 0 uses.
            // SEMANTICS-DEFAULT-EMPTY: var absent from use-counts ⇒ 0 uses; dead-code/phi-elim correctly removes the entry.
            if uses.get(target_var).copied().unwrap_or(0) == 0 {
                continue;
            }

            consumed.extend(&removals);
            clusters.push(ObjectSpreadCluster {
                alloc_idx,
                entries,
                removals,
            });
        }

        if clusters.is_empty() {
            continue;
        }
        // Apply rewrites — sort by alloc_idx for deterministic order.
        clusters.sort_by_key(|c| c.alloc_idx);
        let mut all_removals: BTreeSet<usize> = BTreeSet::new();
        for cluster in &clusters {
            // Fetch the allocator's prefix entries if it was a
            // NewObjectWithBuffer — parse `{ a: 1, b: 2 }` → KeyVal
            // entries. The raw ResolvedString came from resolve_buffers.
            let prefix_entries = block
                .ops
                .get(cluster.alloc_idx)
                .and_then(object_buffer_prefix_entries);

            // Rewrite the allocator op in place to the synthetic op.
            if let Some(op) = block.ops.get_mut(cluster.alloc_idx) {
                let mut operands: Vec<SsaOperand> = vec![SsaOperand::DstPlaceholder];
                if let Some(prefix) = prefix_entries {
                    for entry in prefix {
                        push_object_spread_entry(&mut operands, entry);
                    }
                }
                for entry in &cluster.entries {
                    push_object_spread_entry(&mut operands, entry.clone());
                }
                op.name = "HermesObjectSpreadLit";
                op.operands = operands;
            }
            all_removals.extend(&cluster.removals);
        }
        let mut remove_sorted: Vec<usize> = all_removals.into_iter().collect();
        remove_sorted.sort_unstable();
        for idx in remove_sorted.into_iter().rev() {
            if idx < block.ops.len() {
                block.ops.remove(idx);
            }
        }
    }
}

/// A single entry in a recognized object-spread cluster — either a
/// literal `key: value` write (from `PutOwnByIndex`/`PutOwnById`) or a
/// `...source` write (from `copyDataProperties`).
#[derive(Debug, Clone)]
enum ObjectSpreadEntry {
    KeyVal(String, SsaOperand),
    Spread(SsaOperand),
}

/// A matched cluster ready for rewrite: the allocator's index (the op
/// to rename to `HermesObjectSpreadLit`), the entry list collected in
/// source order, and the indices of ops to remove after the rewrite.
struct ObjectSpreadCluster {
    alloc_idx: usize,
    entries: Vec<ObjectSpreadEntry>,
    removals: Vec<usize>,
}

/// Serialize one entry into the synthetic op's operand-stream. Each
/// entry contributes 2 operands — a `ResolvedString` tag then the
/// value (or spread source) operand.
fn push_object_spread_entry(out: &mut Vec<SsaOperand>, entry: ObjectSpreadEntry) {
    match entry {
        ObjectSpreadEntry::KeyVal(k, v) => {
            out.push(SsaOperand::ResolvedString(format!("K:{k}")));
            out.push(v);
        }
        ObjectSpreadEntry::Spread(v) => {
            out.push(SsaOperand::ResolvedString("S".to_string()));
            out.push(v);
        }
    }
}

/// Parse a `ResolvedString` operand from a `NewObjectWithBuffer*` op
/// back into a list of `KeyVal` entries for hoisting into a
/// `HermesObjectSpreadLit` prefix. Returns `None` for an op that
/// isn't a `NewObjectWithBuffer*` or whose resolved literal doesn't
/// parse as `{ k: v, ... }` shape.
///
/// The input shape produced by `resolve_buffers` is `{ key: val, ... }`
/// where values are raw JS tokens (numbers, strings, `true`, etc.)
/// from the literal-value buffer. We split on top-level `, ` which is
/// sound for this shape because the literal tokens don't contain
/// commas-followed-by-space (numeric / bool / null / simple-string).
/// On any parse surprise, return `None` and the cluster emits without
/// a prefix (the original KeyVal entries remain as PutOwnBy* writes
/// outside the cluster and fall back to unfolded emit).
fn object_buffer_prefix_entries(op: &SsaOp) -> Option<Vec<ObjectSpreadEntry>> {
    if op.name != "NewObjectWithBuffer"
        && op.name != "NewObjectWithBufferLong"
        && op.name != "NewObjectWithBufferAndParent"
    {
        return None;
    }
    let SsaOperand::ResolvedString(lit) = op.operands.get(1)? else {
        return None;
    };
    let trimmed = lit.trim();
    let inner = trimmed
        .strip_prefix('{')
        .and_then(|s| s.strip_suffix('}'))
        .map(str::trim)?;
    if inner.is_empty() {
        return Some(Vec::new());
    }
    let mut entries = Vec::new();
    for pair in inner.split(", ") {
        let (k, v) = pair.split_once(": ")?;
        entries.push(ObjectSpreadEntry::KeyVal(
            k.trim().to_string(),
            SsaOperand::ResolvedString(v.trim().to_string()),
        ));
    }
    Some(entries)
}

/// Count how many times each VarId is used (read) across all blocks.
/// DstPlaceholder operands are not Var, so they're never counted.
fn count_uses(func: &SsaFunction<Raw>) -> FxHashMap<VarId, usize> {
    let mut uses: FxHashMap<VarId, usize> = FxHashMap::default();

    for block in &func.blocks {
        for phi in &block.phis {
            for (_, var) in &phi.args {
                let entry = uses.entry(*var).or_insert(0);
                *entry = entry.saturating_add(1);
            }
        }
        for op in &block.ops {
            for operand in &op.operands {
                if let SsaOperand::Var(v) = operand {
                    let entry = uses.entry(*v).or_insert(0);
                    *entry = entry.saturating_add(1);
                }
            }
        }
    }

    uses
}

/// Copy propagation: replace uses of `x = Mov y` with `y`.
pub fn copy_propagation(func: &mut SsaFunction<Raw>) {
    // Build copy map: dst → src for all Mov instructions
    let mut copies: FxHashMap<VarId, VarId> = FxHashMap::default();

    for block in &func.blocks {
        for op in &block.ops {
            if (op.name == "Mov" || op.name == "MovLong")
                && let (Some(dst), Some(SsaOperand::Var(src))) = (&op.dst, op.operands.get(1))
            {
                copies.insert(*dst, *src);
            }
        }
    }

    // Transitively resolve copies: if a → b → c, resolve a → c
    let mut resolved: FxHashMap<VarId, VarId> = FxHashMap::default();
    for &start in copies.keys() {
        let mut current = start;
        let mut visited = BTreeSet::new();
        while let Some(&next) = copies.get(&current) {
            if !visited.insert(current) {
                break; // cycle
            }
            current = next;
        }
        if current != start {
            resolved.insert(start, current);
        }
    }

    if resolved.is_empty() {
        return;
    }

    // Replace all uses
    for block in &mut func.blocks {
        for phi in &mut block.phis {
            for (_, var) in &mut phi.args {
                if let Some(&replacement) = resolved.get(var) {
                    *var = replacement;
                }
            }
        }
        for op in &mut block.ops {
            for operand in &mut op.operands {
                if let SsaOperand::Var(v) = operand
                    && let Some(&replacement) = resolved.get(v)
                {
                    *v = replacement;
                }
            }
        }
    }
}

/// Constant folding: fold binary ops on two constants into a single constant.
/// Only folds in blocks with no phis (to avoid loop variable issues).
// WHY: constant-folding arithmetic uses `as` for JS-spec reinterprets
// (i32 for bitwise, f64 for arithmetic). See module doc, bucket 1.
#[allow(clippy::as_conversions, reason = "constant-folding arithmetic uses `as` for JS-spec reinterprets (i32 for bitwise, f64 for arithmetic). See module doc, bucket 1.")]
pub fn constant_folding(func: &mut SsaFunction<Raw>) {
    // Collect vars involved in phis — don't fold these
    let mut phi_vars: FxHashSet<VarId> = FxHashSet::default();
    for block in &func.blocks {
        for phi in &block.phis {
            phi_vars.insert(phi.dst);
            for (_, v) in &phi.args {
                phi_vars.insert(*v);
            }
        }
    }

    // Build map of VarId → constant value (only for non-phi vars)
    let mut const_vals: FxHashMap<VarId, i64> = FxHashMap::default();
    let mut const_doubles: FxHashMap<VarId, f64> = FxHashMap::default();

    for block in &func.blocks {
        for op in &block.ops {
            if let Some(dst) = &op.dst {
                if phi_vars.contains(dst) {
                    continue;
                }
                match op.name {
                    "LoadConstZero" => {
                        const_vals.insert(*dst, 0);
                    }
                    "LoadConstUInt8" | "LoadConstInt" => {
                        if let Some(SsaOperand::Const(v)) = op.operands.get(1) {
                            const_vals.insert(*dst, *v);
                        }
                    }
                    "LoadConstDouble" => {
                        if let Some(SsaOperand::ConstDouble(v)) = op.operands.get(1) {
                            const_doubles.insert(*dst, *v);
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    // Fold binary ops
    for block in &mut func.blocks {
        for op in &mut block.ops {
            let Some(dst) = &op.dst else { continue };
            let dst = *dst;
            let (lhs_var, rhs_var) = match (op.operands.get(1), op.operands.get(2)) {
                (Some(SsaOperand::Var(l)), Some(SsaOperand::Var(r))) => (*l, *r),
                _ => continue,
            };

            // Try integer folding — use f64 for JS semantics, only fold numeric ops
            // Skip plain "Add" (polymorphic — could be string concat)
            if let (Some(&lv), Some(&rv)) = (const_vals.get(&lhs_var), const_vals.get(&rhs_var)) {
                let result: Option<f64> = match op.name {
                    // AddN is numeric-only; plain Add might be string concat — skip
                    "AddN" => Some(lv as f64 + rv as f64),
                    "Sub" | "SubN" => Some(lv as f64 - rv as f64),
                    "Mul" | "MulN" => Some(lv as f64 * rv as f64),
                    "Div" | "DivN" if rv != 0 => Some(lv as f64 / rv as f64),
                    "Mod" if rv != 0 => Some(lv as f64 % rv as f64),
                    _ => None,
                };
                // Bitwise ops: JS coerces to signed i32 first
                let bitwise_result: Option<i64> = match op.name {
                    "BitAnd" => Some(i64::from(lv as i32 & rv as i32)),
                    "BitOr" => Some(i64::from(lv as i32 | rv as i32)),
                    "BitXor" => Some(i64::from(lv as i32 ^ rv as i32)),
                    "LShift" => Some(i64::from((lv as i32).wrapping_shl((rv & 31) as u32))),
                    "RShift" => Some(i64::from((lv as i32).wrapping_shr((rv & 31) as u32))),
                    "URshift" => Some(i64::from((lv as u32).wrapping_shr((rv & 31) as u32))),
                    _ => None,
                };
                if let Some(val) = bitwise_result {
                    // URshift produces unsigned u32 — if result > i32::MAX, emit as double
                    if val > i64::from(i32::MAX) || val < i64::from(i32::MIN) {
                        op.name = "LoadConstDouble";
                        op.op = crate::opcodes::OpCode::LoadConstDouble;
                        op.operands =
                            vec![op.operands[0].clone(), SsaOperand::ConstDouble(val as f64)];
                        const_doubles.insert(dst, val as f64);
                    } else {
                        op.name = "LoadConstInt";
                        op.op = crate::opcodes::OpCode::LoadConstInt;
                        op.operands = vec![op.operands[0].clone(), SsaOperand::Const(val)];
                        const_vals.insert(dst, val);
                    }
                } else if let Some(val) = result {
                    // Check if result is an integer
                    if val.fract() == 0.0 && val.abs() <= f64::from(i32::MAX) {
                        op.name = "LoadConstInt";
                        op.op = crate::opcodes::OpCode::LoadConstInt;
                        op.operands = vec![op.operands[0].clone(), SsaOperand::Const(val as i64)];
                        const_vals.insert(dst, val as i64);
                    } else {
                        op.name = "LoadConstDouble";
                        op.op = crate::opcodes::OpCode::LoadConstDouble;
                        op.operands = vec![op.operands[0].clone(), SsaOperand::ConstDouble(val)];
                        const_doubles.insert(dst, val);
                    }
                }
            }

            // Try float folding
            if let (Some(&lv), Some(&rv)) =
                (const_doubles.get(&lhs_var), const_doubles.get(&rhs_var))
            {
                let result = match op.name {
                    "Add" | "AddN" => Some(lv + rv),
                    "Sub" | "SubN" => Some(lv - rv),
                    "Mul" | "MulN" => Some(lv * rv),
                    "Div" | "DivN" => Some(lv / rv),
                    _ => None,
                };
                if let Some(val) = result {
                    op.name = "LoadConstDouble";
                    op.op = crate::opcodes::OpCode::LoadConstDouble;
                    op.operands = vec![op.operands[0].clone(), SsaOperand::ConstDouble(val)];
                    const_doubles.insert(dst, val);
                }
            }
        }
    }
}

/// Dead code elimination: remove ops whose results are never used.
pub fn dead_code_elimination(func: &mut SsaFunction<Raw>) {
    let uses = count_uses(func);

    for block in &mut func.blocks {
        block.ops.retain(|op| {
            // Keep ops with no destination (side effects)
            let Some(dst) = &op.dst else {
                return true;
            };

            // Keep ops with side effects even if result unused
            if has_side_effects(op.name) {
                return true;
            }

            // Remove if destination is never used
            // SEMANTICS-DEFAULT-EMPTY: absent key in `count_uses` map means 0 uses.
            // SEMANTICS-DEFAULT-EMPTY: var absent from use-counts ⇒ 0 uses; dead-code/phi-elim correctly removes the entry.
            uses.get(dst).copied().unwrap_or(0) > 0
        });

        // Remove phis whose dst has zero uses. Trivial phis (singleton /
        // all-args-equal) are NOT removed here — `name_variables` needs
        // them visible to propagate the upstream var's name to the phi
        // dst; otherwise the dangling phi.dst references downstream emit
        // verbatim as `rN_M` instead of the semantically-equivalent name
        // (e.g. `globalThis`, `undefined`, a named parameter). Once
        // name propagation completes, rewriting the references would
        // also be correct but exposes a latent
        // `coalesce_phi_names + build_inline_map` name-collision in
        // cross-block phi groups — that stays out-of-scope; the name-only
        // propagation here is the minimum fix.
        // SEMANTICS-DEFAULT-EMPTY: absent key in `count_uses` map means 0 uses.
        // SEMANTICS-DEFAULT-EMPTY: var absent from use-counts ⇒ 0 uses; dead-code/phi-elim correctly removes the entry.
        block.phis.retain(|phi| uses.get(&phi.dst).copied().unwrap_or(0) > 0);
    }
}

/// Does this instruction have side effects (shouldn't be eliminated)?
fn has_side_effects(name: &str) -> bool {
    super::expr::has_side_effects(name)
}

/// Closure/environment variable naming.
/// Tracks StoreToEnvironment to infer slot contents, then names LoadFromEnvironment
/// with descriptive names like `_closure0_callback` instead of `_closure0_slot5`.
// WHY: `as u32` on HBC IDs (level, slot) — bounded by HBC format u32
// count fields; see module doc bucket 2. Explicit `& 0xFFFF` masks on
#[allow(clippy::as_conversions, reason = "`as u32` on HBC IDs (level, slot) — bounded by HBC format u32 count fields; see module doc bucket 2. Explicit `& 0xFFFF` masks on slot ops ensure the narrow doesn't lose information.")]
pub fn name_closure_vars(
    func: &mut SsaFunction<Raw>,
    get_str: &dyn Fn(u32) -> String,
    get_func_name: &dyn Fn(u32) -> String,
) {
    // Track which registers hold environments
    let mut env_registers: FxHashMap<VarId, u32> = FxHashMap::default(); // var → nesting level

    // Build definition map: VarId → defining SsaOp index (block, op)
    let mut def_map: FxHashMap<VarId, (usize, usize)> = FxHashMap::default();
    for (bi, block) in func.blocks.iter().enumerate() {
        for (oi, op) in block.ops.iter().enumerate() {
            if let Some(dst) = &op.dst {
                def_map.insert(*dst, (bi, oi));
            }
        }
    }

    // Track what gets stored into each (level, slot) pair
    // Key: (level, slot), Value: name inferred from the stored value
    let mut slot_names: BTreeMap<(u32, u32), String> = BTreeMap::new();

    // First pass: collect environment info and slot names from stores
    for block in &func.blocks {
        for op in &block.ops {
            if op.name == "GetEnvironment"
                && let (Some(dst), Some(SsaOperand::Const(level))) = (&op.dst, op.operands.get(1))
            {
                env_registers.insert(*dst, *level as u32);
            }
            if (op.name == "CreateEnvironment" || op.name == "CreateFunctionEnvironment")
                && let Some(dst) = &op.dst
            {
                env_registers.insert(*dst, 0);
            }
            // Track StoreToEnvironment: opcode, env_reg, slot, value
            // Operand layout: [DstPlaceholder, Var(env), Const(slot), Var(value)]
            if (op.name.starts_with("StoreToEnvironment")
                || op.name.starts_with("StoreNPToEnvironment"))
                && let Some(SsaOperand::Var(env_var)) = op.operands.get(1)
            {
                // SEMANTICS-DEFAULT-EMPTY: `env_registers` tracks GetEnvironment/
                // CreateEnvironment dsts. If `env_var` is not from those opcodes
                // (e.g. a pass-through register in obfuscated/unusual HBC), level 0
                // is the best-effort fallback for name-inference; incorrect level
                // only affects var rename quality, not correctness of emitted code.
                // SEMANTICS-DEFAULT-EMPTY: env_var absent from env_registers ⇒ level 0 (initial env nesting depth).
                let level = env_registers.get(env_var).copied().unwrap_or(0);
                if let Some(SsaOperand::Const(slot)) = op.operands.get(2) {
                    let key = (level, *slot as u32 & 0xFFFF);
                    if let Some(SsaOperand::Var(val_var)) = op.operands.get(3) {
                        let name = infer_var_name(
                            *val_var,
                            &def_map,
                            &func.blocks,
                            get_str,
                            get_func_name,
                        );
                        if let Some(name) = name {
                            slot_names.entry(key).or_insert(name);
                        }
                    }
                }
            }
        }
    }

    // Second pass: rename LoadFromEnvironment operands
    // Also rename StoreToEnvironment targets for cleaner emit
    for block in &mut func.blocks {
        for op in &mut block.ops {
            if (op.name == "LoadFromEnvironment" || op.name == "LoadFromEnvironmentL")
                && let Some(SsaOperand::Var(env_var)) = op.operands.get(1)
            {
                // SEMANTICS-DEFAULT-EMPTY: same fallback as the store pass above;
                // unrecognized env register → level 0 for name-inference quality only.
                // SEMANTICS-DEFAULT-EMPTY: env_var absent from env_registers ⇒ level 0 (initial env nesting depth).
                let level = env_registers.get(env_var).copied().unwrap_or(0);
                if let Some(SsaOperand::Const(slot)) = op.operands.get(2) {
                    let slot_val = *slot as u32 & 0xFFFF;
                    let sentinel = 0xF000_0000 | (level << 16) | slot_val;
                    op.operands[1] = SsaOperand::Const(i64::from(sentinel));
                    if let Some(name) = slot_names.get(&(level, slot_val)) {
                        op.operands[2] = SsaOperand::ResolvedString(name.clone());
                    }
                }
            }
        }
    }
}

/// Trace a variable back to its definition to infer a human-readable name.
/// Follows Mov chains and recognizes common definition patterns.
// WHY: i64→u32 narrows on HBC IDs (string-id, function-id). See module
// doc bucket 2.
#[allow(clippy::as_conversions, reason = "i64→u32 narrows on HBC IDs (string-id, function-id). See module doc bucket 2.")]
fn infer_var_name(
    var: VarId,
    def_map: &FxHashMap<VarId, (usize, usize)>,
    blocks: &[SsaBlock],
    get_str: &dyn Fn(u32) -> String,
    get_func_name: &dyn Fn(u32) -> String,
) -> Option<String> {
    let mut current = var;
    // Follow Mov chains (max 8 hops to avoid cycles)
    for _ in 0..8 {
        let (bi, oi) = def_map.get(&current)?;
        let def_op = &blocks[*bi].ops[*oi];
        match def_op.name {
            // Mov: follow the chain
            "Mov" | "MovLong" => {
                if let Some(SsaOperand::Var(src)) = def_op.operands.get(1) {
                    current = *src;
                    continue;
                }
                return None;
            }
            // Parameter: use param name
            "LoadParam" | "LoadParamLong" => {
                return match def_op.operands.get(1) {
                    Some(&SsaOperand::Const(0)) => Some("this".into()),
                    Some(&SsaOperand::Const(idx)) => {
                        Some(format!("a{}", idx.saturating_sub(1)))
                    }
                    _ => None,
                };
            }
            // Closure: use the target function's actual name
            n if n.starts_with("CreateClosure")
                || n.starts_with("CreateAsyncClosure")
                || n.starts_with("CreateGeneratorClosure") =>
            {
                if let Some(&SsaOperand::Const(fid)) = def_op.operands.last() {
                    let name = get_func_name(fid as u32);
                    if !name.is_empty() {
                        return Some(name);
                    }
                }
                return None;
            }
            // Property read: use the property name
            n if n.starts_with("GetById") || n.starts_with("TryGetById") => {
                // String ID is in the last UInt operand
                for operand in def_op.operands.iter().rev() {
                    if let &SsaOperand::Const(str_id) = operand
                        && str_id >= 0
                    {
                        let name = get_str(str_id as u32);
                        if !name.is_empty() && super::expr::is_valid_js_ident(&name) {
                            return Some(name);
                        }
                    }
                }
                return None;
            }
            // String constant: use the string value if it's a short identifier
            "LoadConstString" | "LoadConstStringLongIndex" => {
                if let Some(&SsaOperand::Const(str_id)) = def_op.operands.get(1) {
                    let s = get_str(str_id as u32);
                    if s.len() <= 30 && super::expr::is_valid_js_ident(&s) {
                        return Some(s);
                    }
                }
                return None;
            }
            _ => return None,
        }
    }
    None
}

/// Assign human-readable names to SSA variables based on how they're defined.
// WHY: i64→u32 narrows on HBC IDs (string-id, function-id). See module
// doc bucket 2.
#[allow(clippy::as_conversions, reason = "i64→u32 narrows on HBC IDs (string-id, function-id). See module doc bucket 2.")]
pub fn name_variables(
    func: &mut SsaFunction<Raw>,
    get_str: &dyn Fn(u32) -> String,
    get_func_name: &dyn Fn(u32) -> String,
) {
    let mut names: BTreeMap<VarId, String> = BTreeMap::new();

    for block in &func.blocks {
        for op in &block.ops {
            let Some(dst) = &op.dst else { continue };

            match op.name {
                // Parameters: a0 = this, a1 = first arg, etc.
                "LoadParam" | "LoadParamLong" => {
                    if let Some(SsaOperand::Const(idx)) = op.operands.get(1) {
                        let name = if *idx == 0 {
                            "this".to_string()
                        } else {
                            format!("a{}", idx.saturating_sub(1))
                        };
                        names.insert(*dst, name);
                    }
                }
                // Property access: chain from object name + property string
                n if n.starts_with("GetById") || n.starts_with("TryGetById") => {
                    let prop = match op.operands.last() {
                        Some(SsaOperand::Const(sid)) => {
                            let s = get_str(*sid as u32);
                            if !s.is_empty() && s.len() < 30 {
                                Some(s)
                            } else {
                                None
                            }
                        }
                        Some(SsaOperand::ResolvedString(s)) => {
                            if !s.is_empty() && s.len() < 30 {
                                Some(s.clone())
                            } else {
                                None
                            }
                        }
                        _ => None,
                    };
                    if let Some(prop) = prop {
                        if !is_valid_js_ident(&prop) {
                            // Skip naming for non-identifier properties (e.g. "content-disposition")
                            // These would produce invalid JS if used as variable names
                        } else {
                            let obj_name =
                                if let Some(SsaOperand::Var(obj_var)) = op.operands.get(1) {
                                    names.get(obj_var).cloned()
                                } else {
                                    None
                                };
                            let full_name = match obj_name {
                                Some(ref obj) if obj != "global" && !obj.contains('.') => {
                                    format!("{obj}.{prop}")
                                }
                                _ => prop,
                            };
                            names.insert(*dst, full_name);
                        }
                    }
                }
                // Global object
                "GetGlobalObject" => {
                    names.insert(*dst, "globalThis".to_string());
                }
                // Constants
                "LoadConstNull" => {
                    // Don't name the variable "null" — it's a reserved word.
                    // The value is used via inline_map, not the variable name.
                }
                // Name these for readability in expressions (e.g., print(undefined)),
                // but the emit path must not emit `var undefined = ...` or `false = x`.
                "LoadConstUndefined" => {
                    names.insert(*dst, "undefined".to_string());
                }
                "LoadConstTrue" => {
                    names.insert(*dst, "true".to_string());
                }
                "LoadConstFalse" => {
                    names.insert(*dst, "false".to_string());
                }
                // Catch
                "Catch" => {
                    names.insert(*dst, "err".to_string());
                }
                // New object/array
                "NewObject" => {
                    names.insert(*dst, "obj".to_string());
                }
                "NewArray" => {
                    names.insert(*dst, "arr".to_string());
                }
                // Closures: name from function table
                n if n.starts_with("CreateClosure")
                    || n.starts_with("CreateAsyncClosure")
                    || n.starts_with("CreateGeneratorClosure") =>
                {
                    if let Some(SsaOperand::FuncId(fid)) = op
                        .operands
                        .iter()
                        .find(|o| matches!(o, SsaOperand::FuncId(_)))
                    {
                        let fname = get_func_name(*fid);
                        if !fname.is_empty() && is_valid_js_ident(&fname) {
                            names.insert(*dst, fname);
                        }
                    }
                }
                _ => {}
            }
        }
    }

    // Signature-based type inference: collect property accesses per source variable,
    // then match against known signatures to infer meaningful names.
    let mut property_accesses: BTreeMap<VarId, Vec<String>> = BTreeMap::new();
    for block in &func.blocks {
        for op in &block.ops {
            if (op.name.starts_with("GetById") || op.name.starts_with("TryGetById"))
                && let Some(SsaOperand::Var(obj_var)) = op.operands.get(1)
            {
                let prop = match op.operands.last() {
                    Some(SsaOperand::Const(sid)) => {
                        let s = get_str(*sid as u32);
                        if !s.is_empty() { Some(s) } else { None }
                    }
                    Some(SsaOperand::ResolvedString(s)) if !s.is_empty() => Some(s.clone()),
                    _ => None,
                };
                if let Some(prop) = prop {
                    property_accesses.entry(*obj_var).or_default().push(prop);
                }
            }
        }
    }

    // Signature table: property sets → inferred name
    let signatures: &[(&[&str], u32, &str)] = &[
        // (properties, min_match, inferred_name)
        (&["latitude", "longitude"], 2, "location"),
        (&["email", "username", "password", "name"], 2, "user"),
        (
            &["status", "headers", "statusCode", "data", "body"],
            2,
            "response",
        ),
        (&["method", "url", "headers", "body"], 2, "request"),
        (&["message", "stack", "name", "code"], 2, "error"),
        (
            &["host", "port", "protocol", "pathname", "search", "href"],
            2,
            "url",
        ),
        (&["width", "height", "x", "y"], 2, "rect"),
        (&["style", "children", "onPress", "onLayout"], 2, "props"),
        (
            &["navigate", "goBack", "push", "replace", "reset"],
            2,
            "navigation",
        ),
        (&["dispatch", "getState", "subscribe"], 2, "store"),
        (&["get", "set", "delete", "has", "clear"], 2, "map"),
        (&["add", "delete", "has", "clear", "size"], 2, "set"),
        (&["then", "catch", "finally"], 2, "promise"),
        (&["next", "done", "value", "return"], 2, "iterator"),
        (
            &[
                "length", "push", "pop", "shift", "splice", "map", "filter", "forEach",
            ],
            3,
            "arr",
        ),
        (&["setItem", "getItem", "removeItem", "clear"], 2, "storage"),
        (
            &["accessToken", "refreshToken", "expiresIn", "tokenType"],
            2,
            "auth",
        ),
        (&["dsn", "release", "environment"], 2, "config"),
    ];

    for (var, props) in &property_accesses {
        // Skip variables that already have a meaningful name (not rN pattern)
        if let Some(existing) = names.get(var)
            && (!existing.starts_with('r') || existing.contains('.'))
        {
            continue;
        }
        // Match against signatures
        for &(sig_props, min_match, inferred_name) in signatures {
            let matches = sig_props
                .iter()
                .filter(|&&p| props.iter().any(|a| a == p))
                .count();
            if matches >= min_match as usize {
                names.insert(*var, inferred_name.to_string());
                break;
            }
        }
    }

    // Parameter renaming: trace property accesses through copy chains (Mov, phi)
    // to find which parameters are used as objects.
    // Build copy chain: dst → src for Mov instructions
    let mut copy_sources: BTreeMap<VarId, VarId> = BTreeMap::new();
    for block in &func.blocks {
        for op in &block.ops {
            if (op.name == "Mov" || op.name == "MovLong")
                && let (Some(dst), Some(SsaOperand::Var(src))) = (&op.dst, op.operands.get(1))
            {
                copy_sources.insert(*dst, *src);
            }
        }
    }
    // Trace a variable back to its parameter origin
    let trace_to_param = |mut var: VarId| -> Option<VarId> {
        for i in 0..10 {
            // limit chain depth
            if names
                .get(&var)
                .is_some_and(|n| n.starts_with('a') && n[1..].chars().all(|c| c.is_ascii_digit()))
            {
                return Some(var);
            }
            {
                let src = copy_sources.get(&var)?;
                var = *src
            }
            debug_assert!(
                i < 9,
                "Parameter copy chain exceeds heuristic limit of 10. Potential cycle or pathological code."
            );
        }
        None
    };

    // Collect property accesses attributed to parameters (through copies)
    let mut param_props: BTreeMap<VarId, Vec<String>> = BTreeMap::new();
    for (var, props) in &property_accesses {
        // Direct parameter access
        if names
            .get(var)
            .is_some_and(|n| n.starts_with('a') && n.len() <= 3)
        {
            param_props
                .entry(*var)
                .or_default()
                .extend(props.iter().cloned());
        }
        // Traced through copy chain
        if let Some(param_var) = trace_to_param(*var) {
            param_props
                .entry(param_var)
                .or_default()
                .extend(props.iter().cloned());
        }
    }

    let mut param_renames: BTreeMap<VarId, String> = BTreeMap::new();
    for (param_var, props) in &param_props {
        if props.len() >= 2 {
            let has_ui_props = props.iter().any(|p| {
                matches!(
                    p.as_str(),
                    "style"
                        | "children"
                        | "onPress"
                        | "onLayout"
                        | "onTouchEnd"
                        | "testID"
                        | "accessible"
                        | "key"
                        | "ref"
                        | "disabled"
                        | "value"
                        | "onChange"
                        | "onChangeText"
                        | "placeholder"
                        | "source"
                        | "title"
                        | "data"
                        | "renderItem"
                        | "opacity"
                        | "width"
                        | "height"
                        | "flex"
                        | "backgroundColor"
                )
            });
            if has_ui_props {
                param_renames.insert(*param_var, "props".into());
            }
        }
        if !param_renames.contains_key(param_var) && props.len() >= 3 {
            param_renames.insert(*param_var, "opts".into());
        }
    }
    // Store param renames in dedicated map (param_index → name).
    // Also collect (old_canonical → new_name) so we can rewrite cached
    // GetById display chains (e.g. `a0.value` → `props.value`) that were
    // built from the pre-rename canonical name in the first loop above.
    let mut canonical_renames: BTreeMap<String, String> = BTreeMap::new();
    for block in &func.blocks {
        for op in &block.ops {
            if (op.name == "LoadParam" || op.name == "LoadParamLong")
                && let Some(dst) = &op.dst
                && let Some(SsaOperand::Const(idx)) = op.operands.get(1)
                && *idx > 0
                && let Some(new_name) = param_renames.get(dst)
            {
                func.param_names
                    .insert(idx.saturating_sub(1) as u32, new_name.clone());
                let old_canonical = format!("a{}", idx.saturating_sub(1));
                canonical_renames.insert(old_canonical, new_name.clone());
                names.insert(*dst, new_name.clone());
            }
        }
    }
    if !canonical_renames.is_empty() {
        for display in names.values_mut() {
            for (old, new) in &canonical_renames {
                let prefix = format!("{old}.");
                if display.starts_with(&prefix) {
                    *display = format!("{new}.{}", &display[prefix.len()..]);
                    break;
                }
            }
        }
    }

    // Propagate names across trivial-phi equivalence classes. A phi whose
    // args all reference the same VarId V carries the same semantic value
    // as V, so phi.dst should display as V does. Trivial phis persist in
    // SSA under this pass's sibling change to `dead_code_elimination`
    // (which now only removes zero-use phis, not trivial ones); at emit
    // time the structurer lowers every surviving phi to a `PhiAssign
    // dst = src` copy at each predecessor's end, and the emit path at
    // `structure.rs`'s `resolve_var(dst) == resolve_var(src)` filter
    // collapses the copy into a no-op. For that filter to fire, both
    // sides must resolve to the same display name — which is what this
    // loop ensures by copying `first`'s name into `var_names[phi.dst]`.
    // Without the propagation, `phi.dst` would resolve to its verbatim
    // `rN_M` VarId form while `first` resolves to (e.g.) `globalThis` or
    // `undefined`, the names differ, the copy survives, and the emit
    // shows both the garbled `rN_M` name and the spurious `rN_M = src`
    // move line.
    //
    // Iterate to fixed point so the name propagates through chained
    // trivial phis (phi1.dst → phi2.arg → named-var).
    //
    // Why not rewrite SSA references instead (Braun-paper-style
    // `removeTrivialPhis`)? Doing so exposes a latent
    // `coalesce_phi_names` + `build_inline_map` name-collision bug where
    // differently-sourced vars sharing a physical register collapse under
    // one name and inline each other's expressions into wrong use sites.
    // The name-only propagation here is scope-bounded to the finding and
    // avoids that interaction; the coalesce/inline collision is a separate
    // stream to draft if it ever becomes visible after this fix lands.
    loop {
        let mut progress = false;
        for block in &func.blocks {
            for phi in &block.phis {
                if phi.args.is_empty() {
                    continue;
                }
                let first = phi.args[0].1;
                let all_equal = phi.args.iter().all(|(_, v)| *v == first);
                if !all_equal || phi.dst == first {
                    continue;
                }
                if names.contains_key(&phi.dst) {
                    continue;
                }
                if let Some(src_name) = names.get(&first).cloned() {
                    names.insert(phi.dst, src_name);
                    progress = true;
                }
            }
        }
        if !progress {
            break;
        }
    }

    func.var_names = names;
}

/// Pattern rewrite: multi-instruction patterns → single high-level ops.
/// Runs as a forward scan per block using a DefMap for O(n) lookups.
// WHY: i64→u32 narrows on HBC IDs (string-id). See module doc bucket 2.
#[allow(clippy::as_conversions, reason = "i64→u32 narrows on HBC IDs (string-id). See module doc bucket 2.")]
pub fn pattern_rewrite(func: &mut SsaFunction<Raw>, get_str: &dyn Fn(u32) -> String) {
    // Build def map: VarId → (block index, op index within block)
    let mut def_map: BTreeMap<VarId, (usize, usize)> = BTreeMap::new();
    for (bi, block) in func.blocks.iter().enumerate() {
        for (oi, op) in block.ops.iter().enumerate() {
            if let Some(dst) = &op.dst {
                def_map.insert(*dst, (bi, oi));
            }
        }
    }

    // Pattern B: LoadConstString propagation — replace Var refs to string loads
    // with ResolvedString at use sites.
    let mut string_vars: BTreeMap<VarId, String> = BTreeMap::new();
    for block in func.blocks.iter() {
        for op in &block.ops {
            if (op.name == "LoadConstString" || op.name == "LoadConstStringLongIndex")
                && let Some(dst) = &op.dst
                && let Some(SsaOperand::StringId(sid)) = op.operands.get(1)
            {
                string_vars.insert(*dst, get_str(*sid));
            }
        }
    }

    if !string_vars.is_empty() {
        for block in &mut func.blocks {
            for op in &mut block.ops {
                // Skip string propagation for jump/branch instructions —
                // the structurer's extract_condition needs Var operands
                if op.original.is_jump() {
                    continue;
                }
                for operand in &mut op.operands {
                    if let SsaOperand::Var(v) = operand
                        && let Some(s) = string_vars.get(v)
                    {
                        *operand = SsaOperand::ResolvedString(s.clone());
                    }
                }
            }
        }
    }

    // Resolve property name string IDs in GetById/PutById to ResolvedString.
    // The last operand (Const) is a string table index for the property name.
    // DefineOwnById* also uses a trailing stringId (for class-body static field
    // names); CreatePrivateName has its stringId at operand index 1 (for
    // `#name` lookup during class-body sugar recovery).
    for block in &mut func.blocks {
        for op in &mut block.ops {
            if (op.name.starts_with("GetById")
                || op.name.starts_with("TryGetById")
                || op.name.starts_with("PutById")
                || op.name.starts_with("TryPutById")
                || op.name.starts_with("DefineOwnById"))
                && let Some(last) = op.operands.last_mut()
                && let SsaOperand::Const(sid) = last
            {
                let resolved = get_str(*sid as u32);
                if !resolved.is_empty() {
                    *last = SsaOperand::ResolvedString(resolved);
                }
            }
            if op.name == "CreatePrivateName"
                && let Some(operand) = op.operands.get_mut(1)
                && let SsaOperand::Const(sid) = operand
            {
                let resolved = get_str(*sid as u32);
                if !resolved.is_empty() {
                    *operand = SsaOperand::ResolvedString(resolved);
                }
            }
        }
    }

    // Tagged-template sugar: rewrite `Call(tag, getTemplateObject(...), ...subs)`
    // to the synthetic `HermesTaggedTemplate` op with structured operands.
    // Runs AFTER string propagation (so the getTemplateObject args are
    // ResolvedString) and BEFORE the MethodCall rewrite (so we match the raw
    // Call* shape). Must run before the CreateThis+Construct pattern below
    // because it rewrites Call* opnames, and the name is the match key.
    rewrite_tagged_templates(func);

    // Builtin-desugaring: elide `HermesBuiltin.initRegexNamedGroups(regex,
    // {name: idx, ...})` calls whose result is unused. Hermes emits this
    // call after every regex literal with named capture groups to install
    // the runtime `.groups.<name>` metadata on the regex — it's compiler-
    // internal setup, not source. Source-level JS just writes
    // `/(?<name>...)/` and the regex engine handles named-group lookup.
    // Suppressing the call restores source shape; roundtrip is preserved
    // because hermesc re-inserts the call during its own codegen over the
    // regex literal.
    elide_init_regex_named_groups(func);

    // Pattern A: CreateThisForNew + Construct → ConstructNew (adjacency match)
    // Pattern C: GetById + Call1/2/3/4 → MethodCall (same-block def lookup)
    let uses = count_uses(func);

    // Collect cross-block variable rewrites from SelectObject elimination
    let mut cross_block_rewrites: Vec<(VarId, VarId)> = Vec::new();
    // Collect pending SelectObject removals for cross-block cases
    // (createThis_dst, construct_dst) — find SelectObject referencing createThis_dst
    // in other blocks, remove it, rewrite its dst to construct_dst
    let mut pending_select_removals: Vec<(VarId, VarId)> = Vec::new();

    // Build per-block def map: VarId → op index (only within same block)
    for (bi, block) in func.blocks.iter_mut().enumerate() {
        let mut block_defs: BTreeMap<VarId, usize> = BTreeMap::new();
        for (oi, op) in block.ops.iter().enumerate() {
            if let Some(dst) = &op.dst {
                block_defs.insert(*dst, oi);
            }
        }

        let ops_snapshot: Vec<super::ssa::SsaOp> = block.ops.clone();
        let mut remove_indices: BTreeSet<usize> = BTreeSet::new();

        // Pattern A: CreateThis[ForNew] + Construct → ConstructNew
        // Search backwards from each Construct to find its CreateThis (may have
        // Mov or other ops in between due to copy propagation).
        for i in 0..ops_snapshot.len() {
            if !(ops_snapshot[i].name == "Construct" || ops_snapshot[i].name == "ConstructLong") {
                continue;
            }
            let construct_callee = ops_snapshot[i].operands.get(1);
            // Search backwards for CreateThis/CreateThisForNew with same callee
            let mut create_idx = None;
            for j in (0..i).rev() {
                let create_name = ops_snapshot[j].name;
                // CreateThisForNew: operands = [dst, callee, cacheIdx]
                // CreateThis: operands = [dst, prototype, callee] — callee at index 2
                let callee_match = match create_name {
                    "CreateThisForNew" | "CreateThisForSuper" => {
                        ops_snapshot[j].operands.get(1) == construct_callee
                    }
                    "CreateThis" => ops_snapshot[j].operands.get(2) == construct_callee,
                    _ => false,
                };
                if callee_match {
                    create_idx = Some(j);
                    break;
                }
            }
            let Some(ci) = create_idx else { continue };
            block.ops[i].name = "ConstructNew";
            remove_indices.insert(ci);
            // Also remove SelectObject that references this CreateThis result.
            // SelectObject picks between construct result and createThis result.
            // May not be immediately after Construct — can be in the same block
            // or in a successor block (if CFG splits between Construct and SelectObject).
            let create_this_dst = ops_snapshot[ci].dst;
            let construct_dst_var = ops_snapshot[i].dst;
            if let (Some(ct_dst), Some(con_dst)) = (create_this_dst, construct_dst_var) {
                // Search current block first
                let mut found = false;
                for (k, op_k) in ops_snapshot.iter().enumerate().skip(i.saturating_add(1)) {
                    if op_k.name == "SelectObject" {
                        let refs_create_this = op_k
                            .operands
                            .iter()
                            .any(|o| matches!(o, SsaOperand::Var(v) if *v == ct_dst));
                        if refs_create_this {
                            if let Some(select_dst) = op_k.dst {
                                for op in block.ops.iter_mut() {
                                    for operand in &mut op.operands {
                                        if let SsaOperand::Var(v) = operand
                                            && *v == select_dst
                                        {
                                            *v = con_dst;
                                        }
                                    }
                                }
                                cross_block_rewrites.push((select_dst, con_dst));
                                remove_indices.insert(k);
                            }
                            found = true;
                            break;
                        }
                    }
                }
                // If not found in current block, defer cross-block SelectObject removal
                if !found {
                    pending_select_removals.push((ct_dst, con_dst));
                }
            }
        }

        // Pattern C: GetById + Call1/2/3/4 → MethodCall (same-block only)
        for op in block.ops.iter_mut() {
            if !matches!(op.name, "Call1" | "Call2" | "Call3" | "Call4") || op.operands.len() < 2 {
                continue;
            }
            let Some(SsaOperand::Var(callee_var)) = op.operands.get(1) else {
                continue;
            };
            let callee_var = *callee_var;
            let Some(&get_idx) = block_defs.get(&callee_var) else {
                continue;
            };
            let get_op = &ops_snapshot[get_idx];
            if !(get_op.name.starts_with("GetById") || get_op.name.starts_with("TryGetById")) {
                continue;
            }
            // SEMANTICS-DEFAULT-EMPTY: absent key in `count_uses` map means 0 uses.
            // SEMANTICS-DEFAULT-EMPTY: var absent from use-counts ⇒ 0 uses; dead-code/phi-elim correctly removes the entry.
            if uses.get(&callee_var).copied().unwrap_or(0) != 1 {
                continue;
            }
            let Some(obj) = get_op.operands.get(1).cloned() else {
                continue;
            };
            let Some(SsaOperand::Const(sid)) = get_op.operands.last() else {
                continue;
            };
            let prop_name = get_str(*sid as u32);
            let mut new_operands = vec![
                op.operands[0].clone(), // dst placeholder
                obj,
                SsaOperand::ResolvedString(prop_name),
            ];
            // Skip dst, callee, thisArg — remaining are real args
            for arg in op.operands.iter().skip(3) {
                new_operands.push(arg.clone());
            }
            op.name = "MethodCall";
            op.op = crate::opcodes::OpCode::MethodCall;
            op.operands = new_operands;
            remove_indices.insert(get_idx);
        }

        // Pattern D: Babel async-to-generator unwrapping
        // Detect: Call1/Call where callee resolves to _asyncToGenerator,
        //   argument is a CreateGeneratorClosure → mark closure as async
        // Collect rewrites first, then apply (avoids borrow conflicts).
        let mut async_rewrites: Vec<(usize, VarId, VarId)> = Vec::new(); // (closure_idx, from, to)
        for (oi, op) in ops_snapshot.iter().enumerate() {
            if !matches!(op.name, "Call1" | "Call" | "CallLong") {
                continue;
            }
            let callee_is_async_wrapper =
                if let Some(SsaOperand::Var(callee_var)) = op.operands.get(1) {
                    block_defs.get(callee_var).is_some_and(|&idx| {
                        let callee_op = &ops_snapshot[idx];
                        (callee_op.name.starts_with("GetById")
                            || callee_op.name.starts_with("TryGetById"))
                            && callee_op.operands.last().is_some_and(|o| match o {
                                SsaOperand::ResolvedString(s) => s.contains("asyncToGenerator"),
                                SsaOperand::Const(sid) => {
                                    get_str(*sid as u32).contains("asyncToGenerator")
                                }
                                _ => false,
                            })
                    })
                } else {
                    false
                };

            if !callee_is_async_wrapper {
                continue;
            }

            let closure_arg = if op.name == "Call1" {
                op.operands.get(2)
            } else {
                op.operands.get(4).or(op.operands.get(3))
            };

            if let Some(SsaOperand::Var(closure_var)) = closure_arg
                && let Some(&closure_idx) = block_defs.get(closure_var)
                && ops_snapshot[closure_idx]
                    .name
                    .starts_with("CreateGeneratorClosure")
                && let Some(wrapper_dst) = &op.dst
            {
                async_rewrites.push((closure_idx, *wrapper_dst, *closure_var));
                remove_indices.insert(oi);
            }
        }
        for (closure_idx, from, to) in async_rewrites {
            block.ops[closure_idx].name = "CreateAsyncClosure";
            for op in block.ops.iter_mut() {
                for operand in &mut op.operands {
                    if let SsaOperand::Var(v) = operand
                        && *v == from
                    {
                        *v = to;
                    }
                }
            }
        }

        // Remove ops marked for deletion
        if !remove_indices.is_empty() {
            let mut idx = 0usize;
            block.ops.retain(|_| {
                let keep = !remove_indices.contains(&idx);
                idx = idx.saturating_add(1);
                keep
            });
        }

        let _ = bi; // used for future cross-block patterns
    }

    // Apply deferred cross-block SelectObject removals.
    // These are SelectObjects in successor blocks that weren't found in the same block.
    for (ct_dst, con_dst) in &pending_select_removals {
        for blk in func.blocks.iter_mut() {
            let mut found_idx = None;
            for (i, op) in blk.ops.iter().enumerate() {
                if op.name == "SelectObject" {
                    let refs_ct = op
                        .operands
                        .iter()
                        .any(|o| matches!(o, SsaOperand::Var(v) if v == ct_dst));
                    if refs_ct {
                        found_idx = Some((i, op.dst));
                        break;
                    }
                }
            }
            if let Some((idx, Some(select_dst))) = found_idx {
                // Remove the SelectObject
                blk.ops.remove(idx);
                // Rewrite all references from select_dst to construct_dst
                for op in blk.ops.iter_mut() {
                    for operand in &mut op.operands {
                        if let SsaOperand::Var(v) = operand
                            && *v == select_dst {
                                *v = *con_dst;
                            }
                    }
                }
                cross_block_rewrites.push((select_dst, *con_dst));
            }
        }
    }

    // Apply deferred cross-block rewrites from SelectObject elimination.
    // These rewrites replace SelectObject's dst with Construct's dst across all blocks.
    for (from, to) in &cross_block_rewrites {
        for blk in func.blocks.iter_mut() {
            for op in blk.ops.iter_mut() {
                for operand in &mut op.operands {
                    if let SsaOperand::Var(v) = operand
                        && v == from {
                            *v = *to;
                        }
                }
            }
            for phi in &mut blk.phis {
                if phi.dst == *from {
                    phi.dst = *to;
                }
                for arg in &mut phi.args {
                    if arg.1 == *from {
                        arg.1 = *to;
                    }
                }
            }
        }
    }
}

/// Loud placeholder emitted when an array/object buffer literal carries a
/// tag outside the seven well-formed values (`0..=6`). `parse_literal_buffer`
/// in `parser.rs` uses a `& 0x70` mask that is exhaustive over the eight
/// defined Hermes literal types, so this placeholder is only reachable via
/// the sentinel (`u8::MAX`) that the parser's defensive catch-all emits if
/// a future refactor ever widens the mask. A `"?"` fallback was rejected
/// because it would collide with a legitimate one-character string
/// literal in the emitted JS.
pub(crate) const INVALID_LITERAL_PLACEHOLDER: &str = "/* invalid literal tag */";

/// Loud placeholder installed when a `NewArrayWithBuffer` /
/// `NewObjectWithBuffer` immediate operand arrives in a shape the resolver
/// cannot decode (expected `SsaOperand::Const`, got anything else). Without
/// this signal these sites would `continue` silently, leaving the op
/// un-rewritten so the emitter fell back to `Expr::ArrayLit(vec![])` /
/// `Expr::ObjectLit(vec![])` — i.e. a literal `[]` or `{}` in decompiled JS
/// that is visually indistinguishable from a genuinely-empty literal. This
/// comment-placeholder is syntactically valid inside a JS array/object
/// literal and loud enough in review to flag the defensive arm firing.
///
/// Classification: all 7 arms are **class (a) defensive contracts, not
/// (b) typed errors**. `NewArrayWithBuffer` and `NewObjectWithBuffer`
/// carry exclusively
/// `OpType::U2`/`U4` immediates (see `decompile/schemas.rs`), which the SSA
/// converter lowers to `Operand::UInt` → `SsaOperand::Const(_)` unconditionally
/// for instructions whose names don't match the `CreateClosure` /
/// `CreateGenerator` / `LoadConstString` guards in `ssa.rs:281-292`. None of
/// `copy_propagation`, `constant_folding`, or `pattern_rewrite` rewrite these
/// operand slots either. The `_ =>` arms are therefore unreachable via
/// well-formed HBC; they remain as defensive contracts against a future
/// SSA/optimizer refactor. Direct-`SsaOp`-construction unit tests in
/// `mod unresolved_buffer_tests` lock the placeholder.
pub(crate) const UNRESOLVED_BUFFER_PLACEHOLDER: &str = "/* unresolved buffer operand */";

/// Install the loud unresolved-buffer placeholder on a `NewArrayWithBuffer`
/// / `NewObjectWithBuffer` op whose immediate operands don't match the
/// decoder's expected `SsaOperand::Const` shape. Emits `[<placeholder>]` or
/// `{ <placeholder> }` depending on `is_array`; the emitter then renders the
/// op as `Expr::Raw(<that string>)` rather than its empty-literal fallback.
fn install_unresolved_buffer_placeholder(op: &mut SsaOp, is_array: bool) {
    let content = if is_array {
        format!("[{UNRESOLVED_BUFFER_PLACEHOLDER}]")
    } else {
        format!("{{ {UNRESOLVED_BUFFER_PLACEHOLDER} }}")
    };
    let dst = op.operands.first().cloned().unwrap_or(SsaOperand::DstPlaceholder);
    op.operands = vec![dst, SsaOperand::ResolvedString(content)];
}

/// Resolve literal buffer contents for NewArrayWithBuffer/NewObjectWithBuffer.
/// Replaces the op with a ResolvedString operand containing the decoded literal.
// WHY: i64→u32 narrows on HBC buffer offsets/counts; usize→u32 on pre-
// sized Vec::with_capacity. All bounded by HBC header counts. See module
// doc bucket 2.
#[allow(clippy::as_conversions, reason = "i64→u32 narrows on HBC buffer offsets/counts; usize→u32 on pre- sized Vec::with_capacity. All bounded by HBC header counts. See module doc bucket 2.")]
pub fn resolve_buffers(
    func: &mut SsaFunction<Raw>,
    get_str: &dyn Fn(u32) -> String,
    get_literal: &dyn Fn(u8, u32, u32, u32) -> (u8, u32, i32, f64),
    get_shape: &dyn Fn(u32) -> (u32, u32),
) {
    // Records keys per NewObjectWithBuffer dst so the `PutOwnBySlotIdx`
    // post-pass can map slot indices back to property names. Keys are
    // captured as already-formatted JS identifiers (via the same
    // is_valid_js_ident / escaped-string logic used to build the
    // ResolvedString literal), so we stash the raw key too when the
    // formatted form is a quoted string — property-access-by-string
    // requires bracket notation + the raw name.
    let mut shape_keys: BTreeMap<VarId, Vec<(String, bool)>> = BTreeMap::new();
    // Parallel side-table: initial rendered value per slot (e.g. "null",
    // "false", "42", "\"hello\""). Read by the cluster-fold post-pass below
    // to distinguish placeholder `null` slots (fold candidates) from
    // source-written literal slots that must survive the fold.
    let mut shape_values: BTreeMap<VarId, Vec<String>> = BTreeMap::new();
    for block in &mut func.blocks {
        for op in &mut block.ops {
            match op.name {
                "NewArrayWithBuffer" | "NewArrayWithBufferLong" => {
                    // Operands: [dst, numElements, numLiterals, bufferOffset].
                    // The `_ =>` arms below are defensive: SSA lowers all
                    // UInt immediates for these op names to `Const(_)`, so
                    // only a future refactor can trip them. Install a loud
                    // placeholder instead of `continue` so the emitter sees
                    // a `ResolvedString` and renders it rather than
                    // falling through to `Expr::ArrayLit(vec![])` (an
                    // empty `[]` that collides with a real empty array
                    // literal). See `UNRESOLVED_BUFFER_PLACEHOLDER` doc.
                    let num_literals = match op.operands.get(2) {
                        Some(SsaOperand::Const(n)) => *n as u32,
                        _ => {
                            install_unresolved_buffer_placeholder(op, true);
                            continue;
                        }
                    };
                    let buf_offset = match op.operands.get(3) {
                        Some(SsaOperand::Const(o)) => *o as u32,
                        _ => {
                            install_unresolved_buffer_placeholder(op, true);
                            continue;
                        }
                    };
                    let mut items = Vec::new();
                    for i in 0..num_literals {
                        let (tag, str_id, ival, dval) = get_literal(0, buf_offset, num_literals, i);
                        let s = match tag {
                            0 => "null".to_string(),
                            1 => "true".to_string(),
                            2 => "false".to_string(),
                            3 => fmt_js_double(dval),
                            4 => {
                                let v = get_str(str_id);
                                format!("\"{}\"", escape_js_string(&v))
                            }
                            5 => "undefined".to_string(),
                            6 => format!("{ival}"),
                            // Defensive contract: `parse_literal_buffer`'s
                            // `& 0x70` mask is exhaustive, so only the
                            // sentinel produced by its catch-all (tag
                            // `u8::MAX`) — or a future well-formed tag
                            // not yet handled here — can land in this
                            // arm. The prior `"?"` fallback was
                            // indistinguishable from a legitimate
                            // single-character string literal in emitted
                            // output; render a loud JS comment
                            // placeholder instead.
                            _ => INVALID_LITERAL_PLACEHOLDER.to_string(),
                        };
                        items.push(s);
                    }
                    // Replace the operands with a single ResolvedString
                    let content = format!("[{}]", items.join(", "));
                    op.operands = vec![op.operands[0].clone(), SsaOperand::ResolvedString(content)];
                }
                "NewObjectWithBuffer" | "NewObjectWithBufferLong" => {
                    // v84-v96: [dst, numLiterals, numKeys, keyBufOff, valBufOff]
                    // v97+:    [dst, shapeTableIdx, valBufOff]
                    // Try to decode value buffer if we have enough operands.
                    // The `_ =>` arms below are defensive: SSA lowers all
                    // UInt immediates for these op names to `Const(_)`,
                    // so only a future refactor can trip them. Install a
                    // loud placeholder instead of `continue` so the
                    // emitter sees a `ResolvedString` and renders it
                    // rather than falling through to `Expr::ObjectLit(vec![])`
                    // (an empty `{}` that collides with a real empty
                    // object literal). See `UNRESOLVED_BUFFER_PLACEHOLDER`.
                    let (num_props, val_offset) = if op.operands.len() >= 5 {
                        // v84-v96 format
                        let n = match op.operands.get(1) {
                            Some(SsaOperand::Const(n)) => *n as u32,
                            _ => {
                                install_unresolved_buffer_placeholder(op, false);
                                continue;
                            }
                        };
                        let vo = match op.operands.get(4) {
                            Some(SsaOperand::Const(o)) => *o as u32,
                            _ => {
                                install_unresolved_buffer_placeholder(op, false);
                                continue;
                            }
                        };
                        (n, vo)
                    } else if op.operands.len() >= 3 {
                        // v97+ format: [dst, shapeTableIdx, valBufOff]
                        let shape_idx = match op.operands.get(1) {
                            Some(SsaOperand::Const(n)) => *n as u32,
                            _ => {
                                install_unresolved_buffer_placeholder(op, false);
                                continue;
                            }
                        };
                        let vo = match op.operands.get(2) {
                            Some(SsaOperand::Const(o)) => *o as u32,
                            _ => {
                                install_unresolved_buffer_placeholder(op, false);
                                continue;
                            }
                        };
                        let (key_off, n) = get_shape(shape_idx);
                        if n == 0 {
                            continue;
                        }
                        // Amplification cap: an attacker-controlled
                        // `num_props = 1 << 28` would request multi-GB
                        // `Vec::with_capacity` on the two lines below
                        // and drive a ~268M-iteration loop. The cap
                        // surfaces the violation as a typed Finding and
                        // installs an unresolved placeholder (lenient
                        // policy — parse continues).
                        if n > crate::finding::MAX_OBJECT_SHAPE_NUM_PROPS {
                            crate::finding::emit_finding(
                                crate::finding::HermesFinding::ObjectShapeNumPropsExceeded {
                                    observed: n,
                                    limit: crate::finding::MAX_OBJECT_SHAPE_NUM_PROPS,
                                },
                            );
                            install_unresolved_buffer_placeholder(op, false);
                            continue;
                        }
                        // For v97+, values are in the literal value buffer (type 0)
                        // not the obj value buffer (type 2)
                        let mut props = Vec::new();
                        let mut keys_raw: Vec<(String, bool)> = Vec::with_capacity(n as usize);
                        let mut values_raw: Vec<String> = Vec::with_capacity(n as usize);
                        for i in 0..n {
                            let (ktag, kstr, _, _) = get_literal(1, key_off, n, i);
                            let (key, key_raw, key_is_ident) = if ktag == 4 {
                                let k = get_str(kstr);
                                if k.is_empty() || k.starts_with('<') {
                                    let synth = format!("_{i}");
                                    (synth.clone(), synth, true)
                                } else if is_valid_js_ident(&k) {
                                    (k.clone(), k, true)
                                } else {
                                    let quoted = format!(
                                        "\"{}\"",
                                        k.replace('\\', "\\\\").replace('"', "\\\"")
                                    );
                                    (quoted, k, false)
                                }
                            } else {
                                let synth = format!("key{i}");
                                (synth.clone(), synth, true)
                            };
                            keys_raw.push((key_raw, key_is_ident));
                            let (vtag, vstr, vival, vdval) = get_literal(0, vo, n, i);
                            let val = match vtag {
                                0 => "null".to_string(),
                                1 => "true".to_string(),
                                2 => "false".to_string(),
                                3 => fmt_js_double(vdval),
                                4 => {
                                    let v = get_str(vstr);
                                    format!("\"{}\"", escape_js_string(&v))
                                }
                                5 => "undefined".to_string(),
                                6 => format!("{vival}"),
                                // See the NewArrayWithBuffer arm above
                                // for the defensive-contract rationale.
                                _ => INVALID_LITERAL_PLACEHOLDER.to_string(),
                            };
                            values_raw.push(val.clone());
                            props.push(format!("{key}: {val}"));
                        }
                        if !props.is_empty() {
                            let content = format!("{{ {} }}", props.join(", "));
                            op.operands =
                                vec![op.operands[0].clone(), SsaOperand::ResolvedString(content)];
                            if let Some(dst) = op.dst {
                                shape_keys.insert(dst, keys_raw);
                                shape_values.insert(dst, values_raw);
                            }
                        }
                        continue;
                    } else {
                        continue;
                    };

                    // Read key buffer to get property names. Defensive
                    // `_ =>` arm — see the UNRESOLVED_BUFFER_PLACEHOLDER
                    // doc for the class-(a) rationale.
                    let key_offset = match op.operands.get(3) {
                        Some(SsaOperand::Const(o)) => *o as u32,
                        _ => {
                            install_unresolved_buffer_placeholder(op, false);
                            continue;
                        }
                    };
                    // v84-v96 amplification cap (paired with the v97+
                    // arm's gate above): the `for i in 0..num_props`
                    // loop below is O(num_props); even without
                    // `Vec::with_capacity` an attacker-controlled
                    // `num_props = 1 << 28` is a multi-second DoS.
                    if num_props > crate::finding::MAX_OBJECT_SHAPE_NUM_PROPS {
                        crate::finding::emit_finding(
                            crate::finding::HermesFinding::ObjectShapeNumPropsExceeded {
                                observed: num_props,
                                limit: crate::finding::MAX_OBJECT_SHAPE_NUM_PROPS,
                            },
                        );
                        install_unresolved_buffer_placeholder(op, false);
                        continue;
                    }
                    let mut props = Vec::new();
                    for i in 0..num_props {
                        let (ktag, kstr, _, _) = get_literal(1, key_offset, num_props, i);
                        let key = if ktag == 4 {
                            let k = get_str(kstr);
                            if k.is_empty() || k.starts_with('<') {
                                format!("_{i}")
                            } else if is_valid_js_ident(&k) {
                                k
                            } else {
                                format!("\"{}\"", k.replace('\\', "\\\\").replace('"', "\\\""))
                            }
                        } else {
                            format!("key{i}")
                        };
                        let (vtag, vstr, vival, vdval) = get_literal(2, val_offset, num_props, i);
                        let val = match vtag {
                            0 => "null".to_string(),
                            1 => "true".to_string(),
                            2 => "false".to_string(),
                            3 => fmt_js_double(vdval),
                            4 => {
                                let v = get_str(vstr);
                                format!("\"{}\"", escape_js_string(&v))
                            }
                            5 => "undefined".to_string(),
                            6 => format!("{vival}"),
                            // See the NewArrayWithBuffer arm above
                            // for the defensive-contract rationale.
                            _ => INVALID_LITERAL_PLACEHOLDER.to_string(),
                        };
                        props.push(format!("{key}: {val}"));
                    }
                    if !props.is_empty() {
                        let content = format!("{{ {} }}", props.join(", "));
                        op.operands =
                            vec![op.operands[0].clone(), SsaOperand::ResolvedString(content)];
                    }
                }
                _ => {}
            }
        }
    }

    // Post-pass: rewrite `PutOwnBySlotIdx obj, val, slot_idx` to carry the
    // shape's property name instead of the raw slot index. Hermes's
    // `NewObjectWithBuffer` allocates an object with a shape table
    // determining property order; `PutOwnBySlotIdx` writes to slot N,
    // which semantically means `obj.<shape.keys[N]> = val`, NOT
    // `obj[N] = val` (array-index write). Pre-pass, the emit renders
    // `r3[0] = {inner: 7}` — syntactically a numeric-keyed property write,
    // which after parsing mutates the JS property named `"0"` rather than
    // the intended `outer`. Post-pass, operand[2]'s `Const(slot)` is
    // replaced by `ResolvedString(key_name)` when the defining
    // NewObjectWithBuffer's shape is known; the emit arm in `expr.rs`
    // uses this to render `obj.key_name = val` (or `obj["key"] = val` for
    // non-identifier keys). Unresolved cases (obj from a different block,
    // buffer format not recorded) fall through to the legacy
    // `obj[slot] = val` emit — preserves behavior on edge cases we don't
    // yet track.
    if !shape_keys.is_empty() {
        for block in &mut func.blocks {
            for op in &mut block.ops {
                if op.name != "PutOwnBySlotIdx" && op.name != "PutOwnBySlotIdxLong" {
                    continue;
                }
                let Some(SsaOperand::Var(obj_var)) = op.operands.first() else {
                    continue;
                };
                let Some(SsaOperand::Const(slot)) = op.operands.get(2) else {
                    continue;
                };
                let Some(keys) = shape_keys.get(obj_var) else {
                    continue;
                };
                let slot_idx = *slot as usize;
                if slot_idx >= keys.len() {
                    continue;
                }
                let (raw_key, _is_ident) = &keys[slot_idx];
                // Store the raw key; the `PutOwnBySlotIdx` emit arm in
                // `expr.rs` picks member-access (`.name`) vs indexed
                // (`["name"]`) via `is_valid_js_ident` on the resolved
                // string. Single-source-of-truth for the ident check.
                op.operands[2] = SsaOperand::ResolvedString(raw_key.clone());
            }
        }
    }

    // Cluster-fold pass: `NewObjectWithBuffer(r_N, shape) + PutOwnBySlotIdx(r_N, val, key)`
    // where shape's buffer had `null` at the slot matching `key` folds into a
    // single synthetic `HermesObjectLit` op that renders as `{key: val, ...}`.
    //
    // Motivation: hermesc emits `null` placeholders in the shape-table value
    // buffer for slots whose values are non-literal (sub-objects, computed
    // expressions, closure refs). A subsequent `PutOwnBySlotIdx` writes the
    // real value. Current emit renders the cluster as two statements —
    // `var r_N = { key: null };` then `r_N.key = <val>;` — surfacing a `null`
    // that was never in source. Post-fold: `{ key: <val> }` single literal.
    //
    // Fold rule: only slots whose initial shape-buffer value is exactly
    // `"null"` AND are written by a subsequent PutOwnBySlotIdx are folded.
    // Slots with source-literals (`false`, `42`, `"s"`) survive verbatim;
    // source-written `null` without a subsequent Put also survives.
    // Cluster invalidated by any intervening write to the buffer dst.
    //
    // Applies to v97+ NewObjectWithBuffer only (where shape_keys is
    // populated). Pre-v97 falls through unchanged.
    if !shape_keys.is_empty() {
        // (buffer_op_idx, Vec<put_op_idx>, Vec<(slot_idx, val_operand)>, keys, values)
        // Pre-capturing keys/values in the tuple avoids a second shape_keys /
        // shape_values lookup during the rewrite loop — avoids redundant re-lookup.
        type ClusterFold = (
            usize,
            Vec<usize>,
            Vec<(usize, SsaOperand)>,
            Vec<(String, bool)>,
            Vec<String>,
        );
        for block in &mut func.blocks {
            // Pre-index ops in this block by defining dst → op_idx. Used
            // below to reject use-before-def folds: a Put's val operand
            // must not reference a VarId defined in this block at an op
            // index >= the buffer op's index. (This indexing doubles as
            // the O(N log N) lookup for the put-by-obj_var step.)
            let mut var_def_idx: BTreeMap<VarId, usize> = BTreeMap::new();
            // Pre-index Put ops by their obj_var target. Lowers the
            // worst-case from O(M×N) to O(N log N) on blocks with many
            // NewObjectWithBuffer ops.
            let mut puts_by_obj: BTreeMap<VarId, Vec<usize>> = BTreeMap::new();
            for (k, prep_op) in block.ops.iter().enumerate() {
                if let Some(dst) = prep_op.dst {
                    var_def_idx.entry(dst).or_insert(k);
                }
                if (prep_op.name == "PutOwnBySlotIdx" || prep_op.name == "PutOwnBySlotIdxLong")
                    && let Some(SsaOperand::Var(obj)) = prep_op.operands.first()
                {
                    puts_by_obj.entry(*obj).or_default().push(k);
                }
            }
            let mut cluster_folds: Vec<ClusterFold> = Vec::new();
            for (i, op) in block.ops.iter().enumerate() {
                if op.name != "NewObjectWithBuffer" && op.name != "NewObjectWithBufferLong" {
                    continue;
                }
                let Some(buffer_dst) = op.dst else { continue };
                let Some(keys) = shape_keys.get(&buffer_dst) else { continue };
                let Some(values) = shape_values.get(&buffer_dst) else { continue };
                // Block-wide sanity: reject the cluster if any non-Put op
                // between this buffer op and end-of-block writes buffer_dst
                // BEFORE all its matching Puts are collected (signals the
                // object escaped into other mutation paths before fold
                // completion). Cheap check via var_def_idx.
                let mut slot_overrides: BTreeMap<usize, SsaOperand> = BTreeMap::new();
                let mut put_indices: Vec<usize> = Vec::new();
                // SEMANTICS-DEFAULT-EMPTY: `puts_by_obj` is populated only for
                // NewObjectWithBuffer dsts that have at least one PutOwnBySlotIdx
                // sibling. Absent key means zero Put ops for this object — an empty
                // cluster is valid and will be rejected downstream by a length check.
                // SEMANTICS-DEFAULT-EMPTY: buffer_dst absent from puts_by_obj ⇒ no PutByVal ops; optimization correctly skips.
                let candidate_puts = puts_by_obj.get(&buffer_dst).cloned().unwrap_or_default();
                // Invalidation fence: the first non-Put op after `i` whose
                // dst == buffer_dst blocks folds of Puts >= that fence.
                let fence_idx = block
                    .ops
                    .iter()
                    .enumerate()
                    .skip(i.saturating_add(1))
                    .find(|(_, later_op)| {
                        later_op.name != "PutOwnBySlotIdx"
                            && later_op.name != "PutOwnBySlotIdxLong"
                            && later_op.dst == Some(buffer_dst)
                    })
                    .map(|(fi, _)| fi)
                    .unwrap_or(usize::MAX);
                for j in candidate_puts {
                    if j <= i || j >= fence_idx {
                        continue;
                    }
                    let later_op = match block.ops.get(j) {
                        Some(op) => op,
                        None => continue,
                    };
                    let Some(val_operand) = later_op.operands.get(1) else { continue };
                    let Some(SsaOperand::ResolvedString(key_name)) = later_op.operands.get(2)
                    else {
                        continue;
                    };
                    let Some(slot_idx) = keys.iter().position(|(k, _)| k == key_name) else {
                        continue;
                    };
                    // Fold only placeholder-null slots. Source-literal slots
                    // (including intentional `null`) survive untouched.
                    if values.get(slot_idx).map(String::as_str) != Some("null") {
                        continue;
                    }
                    // Use-before-def check: the Put's val operand may
                    // reference a Var defined in
                    // this block at an op index >= `i`. Folding would
                    // move the read upward past its def, silently
                    // changing program semantics (under `var` hoisting
                    // a pre-init read is `undefined`, not the post-init
                    // value). Only accept val operands whose VarId either
                    // (a) has no defining op in this block (param /
                    // cross-block flow / implicit), (b) is defined
                    // strictly before the buffer op, or (c) is defined
                    // by a pure op whose value will resolve through
                    // `build_inline_map`'s substitute pipeline — pure-op
                    // Vars emit as their Expr tree (e.g. a nested
                    // `{inner: 7}` literal) which is execution-position
                    // independent. The `is_pure` check mirrors the gate
                    // `build_inline_map` uses to decide inlining.
                    if let SsaOperand::Var(val_var) = val_operand
                        && let Some(&def_idx) = var_def_idx.get(val_var)
                        && def_idx >= i
                    {
                        let def_op_name = block.ops.get(def_idx).map(|o| o.name).unwrap_or("");
                        if !super::expr::is_pure(def_op_name) {
                            continue;
                        }
                    }
                    // Last-Put-wins on multi-Put-same-slot (unusual shape).
                    slot_overrides.insert(slot_idx, val_operand.clone());
                    put_indices.push(j);
                }
                if !slot_overrides.is_empty() {
                    let overrides_vec: Vec<(usize, SsaOperand)> =
                        slot_overrides.into_iter().collect();
                    cluster_folds.push((i, put_indices, overrides_vec, keys.clone(), values.clone()));
                }
            }
            if cluster_folds.is_empty() {
                continue;
            }
            // Collect per-cluster rewrites before mutating the block.
            let mut rewrites: BTreeMap<usize, Vec<SsaOperand>> = BTreeMap::new();
            let mut to_remove: BTreeSet<usize> = BTreeSet::new();
            for (buffer_idx, put_indices, slot_overrides, keys, values) in cluster_folds {
                let Some(buffer_dst) = block.ops.get(buffer_idx).and_then(|o| o.dst) else {
                    continue;
                };
                let override_map: BTreeMap<usize, SsaOperand> =
                    slot_overrides.into_iter().collect();
                let mut new_operands: Vec<SsaOperand> =
                    Vec::with_capacity(1usize.saturating_add(keys.len().saturating_mul(2)));
                new_operands.push(SsaOperand::Var(buffer_dst));
                for (idx, (key_entry, value_entry)) in keys.iter().zip(values.iter()).enumerate() {
                    new_operands.push(SsaOperand::ResolvedString(key_entry.0.clone()));
                    match override_map.get(&idx) {
                        Some(v) => new_operands.push(v.clone()),
                        None => new_operands.push(SsaOperand::ResolvedString(value_entry.clone())),
                    }
                }
                rewrites.insert(buffer_idx, new_operands);
                for pi in put_indices {
                    to_remove.insert(pi);
                }
            }
            // Rename + rewrite buffer ops.
            for (idx, operands) in rewrites {
                if let Some(op) = block.ops.get_mut(idx) {
                    op.name = "HermesObjectLit";
                    op.operands = operands;
                }
            }
            // Remove PutOwnBySlotIdx ops in reverse index order so earlier
            // indices stay valid.
            let mut remove_sorted: Vec<usize> = to_remove.into_iter().collect();
            remove_sorted.sort_unstable_by(|a, b| b.cmp(a));
            for idx in remove_sorted {
                if idx < block.ops.len() {
                    block.ops.remove(idx);
                }
            }
        }
    }
}

/// Run all optimization passes.
///
/// Postconditions: DCE only removes ops where `is_pure` returns true.
/// Variable names don't collide with JS reserved words.
/// Resolve BigInt literal indices to their signed-decimal string form.
///
/// `LoadConstBigInt` / `LoadConstBigIntLongIndex` encode their literal payload
/// as an index into the HBC bigint-constant-table. Without this pass the raw
/// index flows through as `SsaOperand::Const(idx)` and the emit path renders
/// it as `{idx}n` — visually valid JS but semantically wrong (e.g. `123n`
/// compiles to index `0`, decompiled as `0n`). This pass rewrites operand[1]
/// to a `ResolvedBigInt(String)` carrying the real value, mirroring the
/// `ResolvedString` precedent installed by `resolve_buffers`.
///
/// Out-of-bounds indices (accessor returns `None`) leave the operand as-is
/// so the emit-site arm can surface a `/* missing bigint #N */` placeholder,
/// matching sibling `missing-builtin-id` / `missing-regex-operand` behavior.
// WHY: i64→u32 narrow on HBC bigint-id. See module doc bucket 2.
#[allow(clippy::as_conversions, reason = "i64→u32 narrow on HBC bigint-id. See module doc bucket 2.")]
fn resolve_bigints(func: &mut SsaFunction<Raw>, get_bigint: &dyn Fn(u32) -> Option<String>) {
    for block in &mut func.blocks {
        for op in &mut block.ops {
            if matches!(op.name, "LoadConstBigInt" | "LoadConstBigIntLongIndex")
                && let Some(SsaOperand::Const(idx)) = op.operands.get(1)
                && *idx >= 0
                && let Some(val) = get_bigint(*idx as u32)
            {
                op.operands[1] = SsaOperand::ResolvedBigInt(val);
            }
        }
    }
}

/// Drive the full optimize pipeline.
///
/// **Phase transition (`Raw` → `Resolved`).** This is the only sanctioned
/// `SsaFunction<Raw> → SsaFunction<Resolved>` transition in the crate.
/// Internally every pass runs against `&mut SsaFunction<Raw>`; the
/// consumed value is reinterpreted via [`SsaFunction::into_resolved`]
/// once `name_variables` + `coalesce_phi_names` complete and every
/// property-name operand is canonical `SsaOperand::ResolvedString(_)`.
/// Downstream consumers (`structure_function_with_exc`, `lower_region`,
/// `find_back_edges`, the cross-layer-taint visitor) require
/// `&SsaFunction<Resolved>` and cannot accept the raw value.
pub fn optimize(
    func: SsaFunction<Raw>,
    get_str: &dyn Fn(u32) -> String,
    get_literal: &dyn Fn(u8, u32, u32, u32) -> (u8, u32, i32, f64),
    get_shape: &dyn Fn(u32) -> (u32, u32),
    get_func_name: &dyn Fn(u32) -> String,
    get_bigint: &dyn Fn(u32) -> Option<String>,
) -> SsaFunction<Resolved> {
    let mut func = func;
    copy_propagation(&mut func);
    constant_folding(&mut func);
    pattern_rewrite(&mut func, get_str);
    // Expression inlining is handled at emit time by the structurer's
    // build_inline_map(), not at the IR level.
    dead_code_elimination(&mut func);
    name_closure_vars(&mut func, get_str, get_func_name);
    resolve_buffers(&mut func, get_str, get_literal, get_shape);
    // Array-spread cluster fold: runs AFTER `resolve_buffers` so the
    // leading NewArrayWithBuffer has a `ResolvedString` operand[1] that
    // the fold's detector can pattern-match. See
    // `rewrite_array_spread_sugar` for details. Placed here (not inside
    // pattern_rewrite) because the buffer resolution is a prerequisite
    // for pattern detection.
    rewrite_array_spread_sugar(&mut func);
    rewrite_object_spread_sugar(&mut func);
    resolve_bigints(&mut func, get_bigint);
    name_variables(&mut func, get_str, get_func_name);
    // Run DCE to fixed point: naming may resolve variables to constants,
    // and unused phi removal may expose more dead code.
    for _ in 0..4 {
        let before: usize = func
            .blocks
            .iter()
            .map(|b| b.ops.len().saturating_add(b.phis.len()))
            .sum();
        dead_code_elimination(&mut func);
        let after: usize = func
            .blocks
            .iter()
            .map(|b| b.ops.len().saturating_add(b.phis.len()))
            .sum();
        if after == before {
            break;
        }
    }

    // Phi coalescing: rename phi-related variable versions to a single name.
    // For same-register phis (rN.X = phi(rN.Y, rN.Z)), all versions get name "rN".
    // This dramatically reduces the number of "var rN_M" lines in output.
    coalesce_phi_names(&mut func);

    func.into_resolved()
}

/// Coalesce phi-related variables into shared names.
///
/// For each phi node, if all arguments come from the same register as the
/// destination, map all versions to a single name. Also transitively coalesces
/// through phi chains (phi A uses phi B's dst, both same register).
fn coalesce_phi_names(func: &mut SsaFunction<Raw>) {
    // Build coalescing sets: groups of VarIds that should share a name.
    // Key: register number. Value: set of VarIds from that register involved in phis.
    let mut coalesce_groups: BTreeMap<u32, BTreeSet<VarId>> = BTreeMap::new();

    for block in &func.blocks {
        for phi in &block.phis {
            let dst_reg = phi.dst.0;
            // Check if all args are from the same register
            let all_same_reg = phi.args.iter().all(|(_, v)| v.0 == dst_reg);
            if all_same_reg {
                let group = coalesce_groups.entry(dst_reg).or_default();
                group.insert(phi.dst);
                for (_, v) in &phi.args {
                    group.insert(*v);
                }
            }
        }
    }

    // Also coalesce Mov instructions: if rN.X = Mov rN.Y (same register),
    // they should share the same name.
    for block in &func.blocks {
        for op in &block.ops {
            if (op.name == "Mov" || op.name == "MovLong")
                && let (Some(dst), Some(SsaOperand::Var(src))) = (&op.dst, op.operands.get(1))
                && dst.0 == src.0
            {
                let group = coalesce_groups.entry(dst.0).or_default();
                group.insert(*dst);
                group.insert(*src);
            }
        }
    }

    // Apply: map all coalesced VarIds to a single name.
    // Use the var_names entry if one exists, otherwise use "rN".
    for (reg, vars) in &coalesce_groups {
        // Check if any var in the group already has a name
        let existing_name = vars.iter().find_map(|v| func.var_names.get(v).cloned());
        let name = existing_name.unwrap_or_else(|| format!("r{reg}"));

        for v in vars {
            func.var_names.insert(*v, name.clone());
        }
    }
}

#[cfg(test)]
mod invalid_literal_tag_tests {
    //! Lock the defensive-contract placeholder for the three `_ =>` arms
    //! in `resolve_buffers` that emit a comment placeholder on an unknown
    //! literal tag. The `parse_literal_buffer` mask (`& 0x70`) is
    //! exhaustive over the eight
    //! defined Hermes literal types, so a non-0..=6 tag can only reach
    //! here via the sentinel `u8::MAX` emitted by the parser's own
    //! defensive catch-all — itself unreachable via byte input. The
    //! placeholder is therefore a defensive contract against future
    //! SSA/parser refactors, not a runtime-input hazard. Unit tests at
    //! the direct-`SsaOp` construction layer are the correct lock
    //! (precedent: the analogous builtin-id and regex-operand defensive arms).

    use super::*;
    use crate::decompile::decode::{DecodedInst, Operand};
    use std::marker::PhantomData;
    use crate::decompile::ssa::{SsaBlock, SsaFunction, SsaOp, SsaOperand, VarId};
    use crate::opcodes::OpCode;

    fn make_fn_with_op(op_name: &'static str, op: OpCode, operands: Vec<SsaOperand>) -> SsaFunction<Raw> {
        let original = DecodedInst {
            offset: 0,
            size: 0,
            opcode: 0,
            name: op_name,
            op,
            operands: Vec::<Operand>::new(),
            op_types: &[],
        };
        let ssa_op = SsaOp {
            name: op_name,
            op,
            dst: Some(VarId(0, 0)),
            operands,
            original,
        };
        SsaFunction::<Raw> {
            blocks: vec![SsaBlock {
                id: 0u32,
                phis: Vec::new(),
                ops: vec![ssa_op],
                successors: Vec::new(),
                predecessors: Vec::new(),
                switch_string_ids: Vec::new(),
            }],
            block_order: vec![0u32],
            var_names: Default::default(),
            param_names: Default::default(),
            param_vars: Vec::new(),
            _phase: PhantomData,
        }
    }

    fn resolved_string(func: &SsaFunction<Raw>) -> Option<String> {
        let op = func.blocks.first()?.ops.first()?;
        match op.operands.last()? {
            SsaOperand::ResolvedString(s) => Some(s.clone()),
            _ => None,
        }
    }

    /// `NewArrayWithBuffer` — the site flagged at `optimize.rs:1234` in
    /// the audit. A `get_literal` stub that returns the parser's
    /// sentinel tag (`u8::MAX`) for one element must render the loud
    /// placeholder in the emitted array, not `"?"`.
    #[test]
    fn new_array_with_buffer_unknown_tag_emits_placeholder() {
        // Operands: [dst, numElements, numLiterals, bufferOffset]
        let operands = vec![
            SsaOperand::DstPlaceholder,
            SsaOperand::Const(1),
            SsaOperand::Const(1),
            SsaOperand::Const(0),
        ];
        let mut func = make_fn_with_op(
            "NewArrayWithBuffer",
            OpCode::NewArrayWithBuffer,
            operands,
        );

        let get_str = |_id: u32| -> String { String::new() };
        // Return the parser's defensive sentinel — this is the single
        // path by which the `_ =>` arm can be reached today.
        let get_literal = |_t: u8, _off: u32, _n: u32, _i: u32| -> (u8, u32, i32, f64) {
            (crate::parser::LITERAL_TAG_INVALID, 0, 0, 0.0)
        };
        let get_shape = |_i: u32| -> (u32, u32) { (0, 0) };

        resolve_buffers(&mut func, &get_str, &get_literal, &get_shape);

        let rendered = resolved_string(&func).expect("expected ResolvedString");
        assert_eq!(rendered, format!("[{INVALID_LITERAL_PLACEHOLDER}]"));
        assert!(
            !rendered.contains('?'),
            "placeholder must not regress to the old `?` rendering: {rendered}"
        );
    }

    /// Positive sanity: a well-formed tag value (4 = string, empty) must
    /// NOT emit the placeholder. Guards against a future refactor that
    /// accidentally collapses a well-formed tag onto the `_ =>` arm.
    #[test]
    fn new_array_with_buffer_well_formed_tag_does_not_emit_placeholder() {
        let operands = vec![
            SsaOperand::DstPlaceholder,
            SsaOperand::Const(1),
            SsaOperand::Const(1),
            SsaOperand::Const(0),
        ];
        let mut func = make_fn_with_op(
            "NewArrayWithBuffer",
            OpCode::NewArrayWithBuffer,
            operands,
        );

        let get_str = |_id: u32| -> String { String::new() };
        let get_literal = |_t: u8, _off: u32, _n: u32, _i: u32| -> (u8, u32, i32, f64) {
            // tag 0 = null
            (0, 0, 0, 0.0)
        };
        let get_shape = |_i: u32| -> (u32, u32) { (0, 0) };

        resolve_buffers(&mut func, &get_str, &get_literal, &get_shape);

        let rendered = resolved_string(&func).expect("expected ResolvedString");
        assert_eq!(rendered, "[null]");
        assert!(
            !rendered.contains(INVALID_LITERAL_PLACEHOLDER),
            "well-formed tag=0 must not trigger the defensive placeholder"
        );
    }

    /// The placeholder string itself is stable — a refactor that changes
    /// the wording would ratchet-diff on every downstream consumer; lock
    /// it here.
    #[test]
    fn invalid_literal_placeholder_has_stable_shape() {
        assert_eq!(INVALID_LITERAL_PLACEHOLDER, "/* invalid literal tag */");
        // Must be distinguishable from a single-character string literal
        // (the old `"?"` rendering collided with a legitimate `"?"`).
        assert!(INVALID_LITERAL_PLACEHOLDER.contains("/*"));
        assert!(INVALID_LITERAL_PLACEHOLDER.contains("*/"));
    }
}

#[cfg(test)]
mod unresolved_buffer_tests {
    //! Lock the defensive-contract placeholder for the seven `_ => continue`
    //! arms in `resolve_buffers` for `NewArrayWithBuffer` /
    //! `NewObjectWithBuffer` ops whose immediate operands are not
    //! `SsaOperand::Const`. Un-rewritten ops
    //! fall through in `decompile/expr.rs` to `Expr::ArrayLit(vec![])` /
    //! `Expr::ObjectLit(vec![])` — i.e. an empty `[]` / `{}` in decompiled
    //! JS indistinguishable from a real empty literal. That is a
    //! **content-loss** pattern, worse than sibling sentinel sites (which
    //! at least render something visibly wrong).
    //!
    //! Classification: **all 7 arms are class (a) defensive contract,
    //! not class (b) typed error.**
    //!
    //! Proof. `NewArrayWithBuffer` / `NewArrayWithBufferLong` /
    //! `NewObjectWithBuffer` / `NewObjectWithBufferLong` schemas
    //! (`decompile/schemas.rs`) define all immediate operands as
    //! `OpType::U2` or `OpType::U4`, which the decoder
    //! (`decompile/decode.rs:171-187`) lowers to `Operand::UInt`. The SSA
    //! converter (`decompile/ssa.rs:281-292`) maps `Operand::UInt` to
    //! `SsaOperand::Const(*v as i64)` unconditionally for any instruction
    //! name not matching the `CreateClosure` / `CreateGenerator` /
    //! `LoadConstString` guards — none of these four names match. The
    //! subsequent optimizer passes (`copy_propagation`, `constant_folding`,
    //! `pattern_rewrite`, `name_closure_vars`) only rewrite `Var` operand
    //! slots or binary-op operand shapes, never these immediates. The
    //! `_ =>` arms are therefore unreachable via well-formed HBC; they
    //! stand as defensive contracts against a future refactor that widens
    //! the SSA lowering rule or re-orders the optimizer pipeline to
    //! introduce a new operand-shape source before `resolve_buffers`.
    //!
    //! Since the arms are unreachable via adversarial HBC byte input, the
    //! correct lock is a direct-`SsaOp`-construction unit test rather than
    //! an adversarial fixture. The fixture would have to construct an
    //! impossible-to-byte-emit SSA state to exercise the arm.
    use super::*;
    use crate::decompile::decode::{DecodedInst, Operand};
    use std::marker::PhantomData;
    use crate::decompile::ssa::{SsaBlock, SsaFunction, SsaOp, SsaOperand, VarId};
    use crate::opcodes::OpCode;

    fn make_fn_with_op(
        op_name: &'static str,
        op: OpCode,
        operands: Vec<SsaOperand>,
    ) -> SsaFunction<Raw> {
        let original = DecodedInst {
            offset: 0,
            size: 0,
            opcode: 0,
            name: op_name,
            op,
            operands: Vec::<Operand>::new(),
            op_types: &[],
        };
        let ssa_op = SsaOp {
            name: op_name,
            op,
            dst: Some(VarId(0, 0)),
            operands,
            original,
        };
        SsaFunction::<Raw> {
            blocks: vec![SsaBlock {
                id: 0u32,
                phis: Vec::new(),
                ops: vec![ssa_op],
                successors: Vec::new(),
                predecessors: Vec::new(),
                switch_string_ids: Vec::new(),
            }],
            block_order: vec![0u32],
            var_names: Default::default(),
            param_names: Default::default(),
            param_vars: Vec::new(),
            _phase: PhantomData,
        }
    }

    fn resolved_string(func: &SsaFunction<Raw>) -> Option<String> {
        let op = func.blocks.first()?.ops.first()?;
        match op.operands.last()? {
            SsaOperand::ResolvedString(s) => Some(s.clone()),
            _ => None,
        }
    }

    /// Shared stubs for the defensive-arm tests. The resolver never
    /// reaches the `get_*` closures when the immediate-operand match
    /// hits `_ =>`, so returning neutral zeros is fine.
    fn run_resolve_with_empty_stubs(func: &mut SsaFunction<Raw>) {
        let get_str = |_: u32| String::new();
        let get_literal =
            |_: u8, _: u32, _: u32, _: u32| -> (u8, u32, i32, f64) { (0, 0, 0, 0.0) };
        let get_shape = |_: u32| -> (u32, u32) { (0, 0) };
        resolve_buffers(func, &get_str, &get_literal, &get_shape);
    }

    /// Site 1 — `NewArrayWithBuffer` numLiterals (operand 2) arrives as
    /// `Var` instead of `Const`. Previously `continue`d silently, leaving
    /// the op un-rewritten and the emitter rendering `[]`. Must now
    /// install the loud array placeholder.
    #[test]
    fn array_num_literals_non_const_installs_placeholder() {
        let operands = vec![
            SsaOperand::DstPlaceholder,
            SsaOperand::Const(1),
            SsaOperand::Var(VarId(1, 0)), // bad shape
            SsaOperand::Const(0),
        ];
        let mut func = make_fn_with_op(
            "NewArrayWithBuffer",
            OpCode::NewArrayWithBuffer,
            operands,
        );
        run_resolve_with_empty_stubs(&mut func);
        let rendered = resolved_string(&func).expect("expected ResolvedString placeholder");
        assert_eq!(rendered, format!("[{UNRESOLVED_BUFFER_PLACEHOLDER}]"));
    }

    /// Site 2 — `NewArrayWithBuffer` bufferOffset (operand 3) non-Const.
    #[test]
    fn array_buf_offset_non_const_installs_placeholder() {
        let operands = vec![
            SsaOperand::DstPlaceholder,
            SsaOperand::Const(1),
            SsaOperand::Const(1),
            SsaOperand::Var(VarId(1, 0)), // bad shape
        ];
        let mut func = make_fn_with_op(
            "NewArrayWithBufferLong",
            OpCode::NewArrayWithBufferLong,
            operands,
        );
        run_resolve_with_empty_stubs(&mut func);
        let rendered = resolved_string(&func).expect("expected ResolvedString placeholder");
        assert_eq!(rendered, format!("[{UNRESOLVED_BUFFER_PLACEHOLDER}]"));
    }

    /// Site 3 — v84-v96 `NewObjectWithBuffer` numLiterals (operand 1)
    /// non-Const.
    #[test]
    fn object_v84_num_literals_non_const_installs_placeholder() {
        // 5 operands to take the v84-v96 branch
        let operands = vec![
            SsaOperand::DstPlaceholder,
            SsaOperand::Var(VarId(1, 0)), // bad shape at operand 1
            SsaOperand::Const(1),
            SsaOperand::Const(0),
            SsaOperand::Const(0),
        ];
        let mut func = make_fn_with_op(
            "NewObjectWithBuffer",
            OpCode::NewObjectWithBuffer,
            operands,
        );
        run_resolve_with_empty_stubs(&mut func);
        let rendered = resolved_string(&func).expect("expected ResolvedString placeholder");
        assert_eq!(
            rendered,
            format!("{{ {UNRESOLVED_BUFFER_PLACEHOLDER} }}")
        );
    }

    /// Site 4 — v84-v96 `NewObjectWithBuffer` valBufOff (operand 4)
    /// non-Const.
    #[test]
    fn object_v84_val_offset_non_const_installs_placeholder() {
        let operands = vec![
            SsaOperand::DstPlaceholder,
            SsaOperand::Const(1),
            SsaOperand::Const(1),
            SsaOperand::Const(0),
            SsaOperand::Var(VarId(1, 0)), // bad shape at operand 4
        ];
        let mut func = make_fn_with_op(
            "NewObjectWithBufferLong",
            OpCode::NewObjectWithBufferLong,
            operands,
        );
        run_resolve_with_empty_stubs(&mut func);
        let rendered = resolved_string(&func).expect("expected ResolvedString placeholder");
        assert_eq!(
            rendered,
            format!("{{ {UNRESOLVED_BUFFER_PLACEHOLDER} }}")
        );
    }

    /// Site 5 — v97+ `NewObjectWithBuffer` shapeTableIdx (operand 1)
    /// non-Const.
    #[test]
    fn object_v97_shape_idx_non_const_installs_placeholder() {
        // 3 operands to take the v97+ branch
        let operands = vec![
            SsaOperand::DstPlaceholder,
            SsaOperand::Var(VarId(1, 0)), // bad shape at operand 1
            SsaOperand::Const(0),
        ];
        let mut func = make_fn_with_op(
            "NewObjectWithBuffer",
            OpCode::NewObjectWithBuffer,
            operands,
        );
        run_resolve_with_empty_stubs(&mut func);
        let rendered = resolved_string(&func).expect("expected ResolvedString placeholder");
        assert_eq!(
            rendered,
            format!("{{ {UNRESOLVED_BUFFER_PLACEHOLDER} }}")
        );
    }

    /// Site 6 — v97+ `NewObjectWithBuffer` valBufOff (operand 2) non-Const.
    #[test]
    fn object_v97_val_offset_non_const_installs_placeholder() {
        let operands = vec![
            SsaOperand::DstPlaceholder,
            SsaOperand::Const(0),
            SsaOperand::Var(VarId(1, 0)), // bad shape at operand 2
        ];
        let mut func = make_fn_with_op(
            "NewObjectWithBufferLong",
            OpCode::NewObjectWithBufferLong,
            operands,
        );
        run_resolve_with_empty_stubs(&mut func);
        let rendered = resolved_string(&func).expect("expected ResolvedString placeholder");
        assert_eq!(
            rendered,
            format!("{{ {UNRESOLVED_BUFFER_PLACEHOLDER} }}")
        );
    }

    /// Site 7 — v84-v96 `NewObjectWithBuffer` keyBufOff (operand 3)
    /// non-Const. This site is past the early numLiterals/valBufOff
    /// checks; the key_offset read itself is the first non-Const slot.
    #[test]
    fn object_v84_key_offset_non_const_installs_placeholder() {
        let operands = vec![
            SsaOperand::DstPlaceholder,
            SsaOperand::Const(1),
            SsaOperand::Const(1),
            SsaOperand::Var(VarId(1, 0)), // bad shape at operand 3
            SsaOperand::Const(0),
        ];
        let mut func = make_fn_with_op(
            "NewObjectWithBuffer",
            OpCode::NewObjectWithBuffer,
            operands,
        );
        run_resolve_with_empty_stubs(&mut func);
        let rendered = resolved_string(&func).expect("expected ResolvedString placeholder");
        assert_eq!(
            rendered,
            format!("{{ {UNRESOLVED_BUFFER_PLACEHOLDER} }}")
        );
    }

    /// Positive sanity: a well-formed `NewArrayWithBuffer` with all-Const
    /// immediates and a non-empty literal buffer must NOT install the
    /// placeholder — it must render the decoded array contents. Guards
    /// against a refactor that accidentally routes well-formed inputs
    /// through the defensive arm.
    #[test]
    fn array_well_formed_const_operands_do_not_install_placeholder() {
        let operands = vec![
            SsaOperand::DstPlaceholder,
            SsaOperand::Const(1),
            SsaOperand::Const(1),
            SsaOperand::Const(0),
        ];
        let mut func = make_fn_with_op(
            "NewArrayWithBuffer",
            OpCode::NewArrayWithBuffer,
            operands,
        );
        let get_str = |_: u32| String::new();
        // tag 0 = null — well-formed
        let get_literal = |_: u8, _: u32, _: u32, _: u32| (0u8, 0u32, 0i32, 0f64);
        let get_shape = |_: u32| (0u32, 0u32);
        resolve_buffers(&mut func, &get_str, &get_literal, &get_shape);
        let rendered = resolved_string(&func).expect("expected ResolvedString");
        assert_eq!(rendered, "[null]");
        assert!(
            !rendered.contains(UNRESOLVED_BUFFER_PLACEHOLDER),
            "well-formed operands must not trigger the defensive placeholder: {rendered}"
        );
    }

    /// Positive sanity: a well-formed v97+ `NewObjectWithBuffer` with
    /// all-Const immediates and a 1-key shape must NOT install the
    /// placeholder.
    #[test]
    fn object_v97_well_formed_const_operands_do_not_install_placeholder() {
        let operands = vec![
            SsaOperand::DstPlaceholder,
            SsaOperand::Const(0), // shape_idx
            SsaOperand::Const(0), // val_offset
        ];
        let mut func = make_fn_with_op(
            "NewObjectWithBuffer",
            OpCode::NewObjectWithBuffer,
            operands,
        );
        let get_str = |id: u32| if id == 7 { "k".to_string() } else { String::new() };
        // Return tag 4 (string) for keys, tag 0 (null) for values.
        // First call per iteration is key (buffer_type=1), second is value (buffer_type=0).
        let get_literal = |t: u8, _: u32, _: u32, _: u32| -> (u8, u32, i32, f64) {
            if t == 1 {
                (4, 7, 0, 0.0) // string key "k"
            } else {
                (0, 0, 0, 0.0) // null value
            }
        };
        // 1 key in the shape.
        let get_shape = |_: u32| (0u32, 1u32);
        resolve_buffers(&mut func, &get_str, &get_literal, &get_shape);
        let rendered = resolved_string(&func).expect("expected ResolvedString");
        assert_eq!(rendered, "{ k: null }");
        assert!(
            !rendered.contains(UNRESOLVED_BUFFER_PLACEHOLDER),
            "well-formed v97+ operands must not trigger the defensive placeholder: {rendered}"
        );
    }

    /// Lock the placeholder wording + shape so a future refactor doesn't
    /// diff every downstream consumer.
    #[test]
    fn unresolved_buffer_placeholder_has_stable_shape() {
        assert_eq!(
            UNRESOLVED_BUFFER_PLACEHOLDER,
            "/* unresolved buffer operand */"
        );
        // Must be a syntactically valid JS comment so the final
        // `[<placeholder>]` / `{ <placeholder> }` render parses.
        assert!(UNRESOLVED_BUFFER_PLACEHOLDER.starts_with("/*"));
        assert!(UNRESOLVED_BUFFER_PLACEHOLDER.ends_with("*/"));
        // Must be distinguishable from the sibling
        // `INVALID_LITERAL_PLACEHOLDER` — they mark different failure
        // modes (operand-shape vs. tag-byte) and ought not collide in
        // downstream grep / ratchet diagnostics.
        assert_ne!(UNRESOLVED_BUFFER_PLACEHOLDER, INVALID_LITERAL_PLACEHOLDER);
    }

    /// `num_props` on a `NewObjectWithBuffer` op exceeds the per-shape
    /// amplification cap. Both consumer arms (v84-v96 `Const`-operand
    /// and v97+ `get_shape`-derived) must (a) install the unresolved
    /// placeholder and (b) emit `HermesFinding::ObjectShapeNumPropsExceeded`.
    #[test]
    fn new_object_with_buffer_v84_v96_num_props_cap_fires() {
        let _ = crate::finding::drain_findings_for_test();
        // v84-v96 format: [dst, numLiterals=BIG, numKeys=0, keyBufOff=0, valBufOff=0]
        let huge = crate::finding::MAX_OBJECT_SHAPE_NUM_PROPS.saturating_add(1);
        let operands = vec![
            SsaOperand::DstPlaceholder,
            SsaOperand::Const(i64::from(huge)),
            SsaOperand::Const(0),
            SsaOperand::Const(0),
            SsaOperand::Const(0),
        ];
        let mut func = make_fn_with_op(
            "NewObjectWithBuffer",
            OpCode::NewObjectWithBuffer,
            operands,
        );

        let get_str = |_id: u32| -> String { String::new() };
        let get_literal = |_t: u8, _off: u32, _n: u32, _i: u32| -> (u8, u32, i32, f64) {
            (0, 0, 0, 0.0)
        };
        let get_shape = |_i: u32| -> (u32, u32) { (0, 0) };

        resolve_buffers(&mut func, &get_str, &get_literal, &get_shape);

        let findings = crate::finding::drain_findings_for_test();
        let saw_cap = findings.iter().any(|f| {
            matches!(
                f,
                crate::finding::HermesFinding::ObjectShapeNumPropsExceeded {
                    observed,
                    limit
                } if *observed == huge && *limit == crate::finding::MAX_OBJECT_SHAPE_NUM_PROPS
            )
        });
        assert!(saw_cap, "expected ObjectShapeNumPropsExceeded, got {findings:?}");
        // Lenient policy installs the unresolved placeholder.
        let rendered = resolved_string(&func).expect("expected ResolvedString placeholder");
        assert!(
            rendered.contains(UNRESOLVED_BUFFER_PLACEHOLDER),
            "expected unresolved placeholder, got {rendered}"
        );
    }

    #[test]
    fn new_object_with_buffer_v97_num_props_cap_fires() {
        let _ = crate::finding::drain_findings_for_test();
        // v97+ format: [dst, shapeTableIdx=0, valBufOff=0]
        let huge = crate::finding::MAX_OBJECT_SHAPE_NUM_PROPS.saturating_add(1);
        let operands = vec![
            SsaOperand::DstPlaceholder,
            SsaOperand::Const(0),
            SsaOperand::Const(0),
        ];
        let mut func = make_fn_with_op(
            "NewObjectWithBuffer",
            OpCode::NewObjectWithBuffer,
            operands,
        );

        let get_str = |_id: u32| -> String { String::new() };
        let get_literal = |_t: u8, _off: u32, _n: u32, _i: u32| -> (u8, u32, i32, f64) {
            (0, 0, 0, 0.0)
        };
        // get_shape returns `(key_off, num_props)` — huge num_props
        // drives the cap.
        let get_shape = |_i: u32| -> (u32, u32) { (0, huge) };

        resolve_buffers(&mut func, &get_str, &get_literal, &get_shape);

        let findings = crate::finding::drain_findings_for_test();
        let saw_cap = findings.iter().any(|f| {
            matches!(
                f,
                crate::finding::HermesFinding::ObjectShapeNumPropsExceeded {
                    observed,
                    limit
                } if *observed == huge && *limit == crate::finding::MAX_OBJECT_SHAPE_NUM_PROPS
            )
        });
        assert!(saw_cap, "expected ObjectShapeNumPropsExceeded, got {findings:?}");
        let rendered = resolved_string(&func).expect("expected ResolvedString placeholder");
        assert!(
            rendered.contains(UNRESOLVED_BUFFER_PLACEHOLDER),
            "expected unresolved placeholder, got {rendered}"
        );
    }

    #[test]
    fn new_object_with_buffer_at_cap_does_not_fire() {
        let _ = crate::finding::drain_findings_for_test();
        let at_cap = crate::finding::MAX_OBJECT_SHAPE_NUM_PROPS;
        // v84-v96 format with num_props EXACTLY at the cap → must
        // NOT fire (cap is `>` not `>=`).
        let operands = vec![
            SsaOperand::DstPlaceholder,
            SsaOperand::Const(i64::from(at_cap)),
            SsaOperand::Const(0),
            SsaOperand::Const(0),
            SsaOperand::Const(0),
        ];
        let mut func = make_fn_with_op(
            "NewObjectWithBuffer",
            OpCode::NewObjectWithBuffer,
            operands,
        );

        let get_str = |_id: u32| -> String { String::new() };
        let get_literal = |_t: u8, _off: u32, _n: u32, _i: u32| -> (u8, u32, i32, f64) {
            (0, 0, 0, 0.0)
        };
        let get_shape = |_i: u32| -> (u32, u32) { (0, 0) };

        resolve_buffers(&mut func, &get_str, &get_literal, &get_shape);

        let findings = crate::finding::drain_findings_for_test();
        for f in &findings {
            assert!(
                !matches!(
                    f,
                    crate::finding::HermesFinding::ObjectShapeNumPropsExceeded { .. }
                ),
                "cap must NOT fire at the inclusive boundary: {f:?}"
            );
        }
    }
}

#[cfg(test)]
mod object_buffer_fold_tests {
    //! Lock the synthetic `HermesObjectLit` op's operand-shape invariant
    //! produced by `resolve_buffers`' cluster-fold post-pass. The emit arm
    //! in `expr.rs` walks operands as `[dst, key1, val1, key2, val2, ...]`
    //! pairs; a shape regression (odd pair count, non-ResolvedString key)
    //! would render `{malformed HermesObjectLit ...}` at emit time.
    use super::*;
    use std::marker::PhantomData;
    use crate::decompile::decode::{DecodedInst, Operand};
    use crate::decompile::ssa::{SsaBlock, SsaOp};
    use crate::opcodes::OpCode;

    fn make_fn(ops: Vec<SsaOp>) -> SsaFunction<Raw> {
        SsaFunction::<Raw> {
            blocks: vec![SsaBlock {
                id: 0u32,
                phis: Vec::new(),
                ops,
                successors: Vec::new(),
                predecessors: Vec::new(),
                switch_string_ids: Vec::new(),
            }],
            block_order: vec![0u32],
            var_names: Default::default(),
            param_names: Default::default(),
            param_vars: Vec::new(),
            _phase: PhantomData,
        }
    }

    fn make_op(name: &'static str, op: OpCode, dst: Option<VarId>, operands: Vec<SsaOperand>) -> SsaOp {
        SsaOp {
            name,
            op,
            dst,
            original: DecodedInst {
                offset: 0,
                size: 0,
                opcode: 0,
                name,
                op,
                operands: Vec::<Operand>::new(),
                op_types: &[],
            },
            operands,
        }
    }

    /// Invariant: after the fold, `HermesObjectLit.operands.len()` is
    /// `1 + 2·#keys`. Verified on a two-slot cluster where one slot
    /// folds (placeholder `null` + Put) and the other survives
    /// (source-literal `false`).
    #[test]
    fn hermes_object_lit_operand_shape_invariant() {
        let buffer_dst = VarId(0, 0);
        let val_var = VarId(1, 0);
        let buffer_op = make_op(
            "NewObjectWithBuffer",
            OpCode::NewObjectWithBuffer,
            Some(buffer_dst),
            vec![SsaOperand::Var(buffer_dst), SsaOperand::Const(0), SsaOperand::Const(0)],
        );
        // Synthetic put to force the fold to fire. val_var must be
        // defined BEFORE the buffer op for the use-before-def check to
        // pass; simulate a param-like def (no block-local def).
        let put_op = make_op(
            "PutOwnBySlotIdx",
            OpCode::PutOwnBySlotIdx,
            None,
            vec![
                SsaOperand::Var(buffer_dst),
                SsaOperand::Var(val_var),
                SsaOperand::Const(0),
            ],
        );
        let mut func = make_fn(vec![buffer_op, put_op]);
        // Stub get_shape to return a 2-key shape: ("value", "done").
        let keys_storage: Vec<&str> = vec!["value", "done"];
        let get_str = move |i: u32| keys_storage.get(i as usize).unwrap_or(&"").to_string();
        let get_literal = |kind: u8, _off: u32, _n: u32, i: u32| -> (u8, u32, i32, f64) {
            if kind == 1 {
                // Key buffer: return str-tag (4) with str_id = i.
                (4, i, 0, 0.0)
            } else {
                // Value buffer: slot 0 = null (tag 0, fold candidate),
                // slot 1 = false (tag 2, source-literal survives).
                if i == 0 {
                    (0, 0, 0, 0.0)
                } else {
                    (2, 0, 0, 0.0)
                }
            }
        };
        let get_shape = |_: u32| -> (u32, u32) { (0, 2) };
        resolve_buffers(&mut func, &get_str, &get_literal, &get_shape);

        let op = func.blocks.first().and_then(|b| b.ops.first()).expect("expected buffer op");
        assert_eq!(op.name, "HermesObjectLit", "buffer op must be renamed post-fold");
        // 1 (dst) + 2*2 (keys) = 5 operands.
        assert_eq!(op.operands.len(), 5, "operand count must be 1 + 2·keys");
        // Odd-indexed operands (keys) must be ResolvedString.
        for k_idx in [1usize, 3] {
            assert!(
                matches!(op.operands.get(k_idx), Some(SsaOperand::ResolvedString(_))),
                "operand {k_idx} (key) must be ResolvedString"
            );
        }
        // Folded slot 0 → Var(val_var); source-literal slot 1 → ResolvedString("false").
        assert!(
            matches!(op.operands.get(2), Some(SsaOperand::Var(v)) if *v == val_var),
            "operand 2 (slot 0 value) must be the folded Var"
        );
        assert!(
            matches!(op.operands.get(4), Some(SsaOperand::ResolvedString(s)) if s == "false"),
            "operand 4 (slot 1 value) must be the source-literal token"
        );
        // Put op removed.
        assert_eq!(func.blocks[0].ops.len(), 1, "PutOwnBySlotIdx must be removed post-fold");
    }
}
