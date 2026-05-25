//! Sugar recovery passes: pattern-match heuristics that transform structured
//! statements into higher-level JS constructs (switch, for-in, class, etc.).
//! Separated from core structuring to isolate heuristic logic from CFG analysis.
#![allow(
    clippy::cast_possible_truncation,
    reason = "PROOF: HBC parser/decompiler. IDs (string-id, builtin-id, function-id, regex-id) narrow from i64 to u32 only after parser bounds them against the validated HBC header u32 counts. Per-site #[allow] attributes at the deepest call sites carry the per-cast PROOF; this file-level allow is the umbrella for the remaining sites in the same family."
)]

#![allow(missing_docs, reason = "internal")]
#![allow(clippy::only_used_in_recursion, reason = "Recursive sugar helpers; the lint flags an over-conservative refactor opportunity, not a bug.")]
#![cfg_attr(
    not(test),
    allow(
        clippy::indexing_slicing,
        clippy::string_slice,
        reason = "PROOF: sugar passes consume Region / StructuredFunction / SsaBody trees produced post-parse / post-CFG / post-SSA / post-structuring. Every Region::Block reference, BlockIdx, VarId, and Expr/Stmt node is constructed by upstream passes that validate against parser-accepted pools. UTF-8 boundary safety is preserved because string slicing operates on identifier-name buffers (sanitize_id outputs) or on emit-internal `String` constructions. Per-fn refinement deferred (~54 sites; uniform invariant)."
    )
)]

use std::collections::{BTreeMap, BTreeSet};

use super::cfg::BlockId;
use super::ssa::{SsaOperand, VarId};
use super::structure::{Condition, DestructureKey, DestructurePath, StaticField, Stmt};

/// Apply a rewrite function to a Vec<Stmt> and all nested child bodies.
/// **Post-order**: children are rewritten before their containing body,
/// so any new container statements `rewrite` introduces are NOT revisited.
/// This is load-bearing for rewrites that wrap statements in containers
/// (e.g. `recover_try_catch` wrapping in `TryCatch`) — visiting the new
/// children would re-fire the wrap and loop indefinitely. The previous
/// pre-order version masked this with stack overflow at ~24 frames; the
/// fix is the contract change, not the recursion shape.
///
/// AST depth in real Hermes bundles is bounded by program nesting (tens,
/// not thousands), so the recursive descent here doesn't approach the
/// 8 MiB main-thread stack budget once the infinite-wrap is gone.
pub(super) fn apply_deep(stmts: Vec<Stmt>, rewrite: &dyn Fn(Vec<Stmt>) -> Vec<Stmt>) -> Vec<Stmt> {
    let processed: Vec<Stmt> = stmts
        .into_iter()
        .map(|s| descend_stmt(s, rewrite))
        .collect();
    rewrite(processed)
}

/// Descend into a single statement's child bodies, applying `apply_deep`
/// to each. Pure container dispatch — leaves are returned unchanged.
fn descend_stmt(stmt: Stmt, rewrite: &dyn Fn(Vec<Stmt>) -> Vec<Stmt>) -> Stmt {
    match stmt {
        Stmt::If {
            cond,
            then_body,
            else_body,
        } => Stmt::If {
            cond,
            then_body: apply_deep(then_body, rewrite),
            else_body: apply_deep(else_body, rewrite),
        },
        Stmt::While { cond, body } => Stmt::While {
            // `cond` is `Option<Condition>`; unconditional loops pass through unchanged.
            cond,
            body: apply_deep(body, rewrite),
        },
        Stmt::ForIn { key, obj, body } => Stmt::ForIn {
            key,
            obj,
            body: apply_deep(body, rewrite),
        },
        Stmt::Switch {
            discriminant,
            cases,
            default,
        } => {
            let cases = cases
                .into_iter()
                .map(|(c, body)| (c, apply_deep(body, rewrite)))
                .collect();
            let default = apply_deep(default, rewrite);
            Stmt::Switch {
                discriminant,
                cases,
                default,
            }
        }
        Stmt::TryCatch {
            try_body,
            catch_var,
            catch_body,
        } => Stmt::TryCatch {
            try_body: apply_deep(try_body, rewrite),
            catch_var,
            catch_body: apply_deep(catch_body, rewrite),
        },
        Stmt::Labeled { label, body } => Stmt::Labeled {
            label,
            body: apply_deep(body, rewrite),
        },
        other => other,
    }
}

/// Flatten early returns: transform `if (c) { body } else { return }` → `if (!c) return; body`
/// Uses depth-limited recursion — the flattening moves statements between tree levels,
/// so iterative breadth-first processing doesn't work.
pub(super) fn flatten_early_returns(stmts: Vec<Stmt>) -> Vec<Stmt> {
    flatten_early_returns_inner(stmts, 0)
}

fn flatten_early_returns_inner(stmts: Vec<Stmt>, depth: usize) -> Vec<Stmt> {
    debug_assert!(
        depth <= 500,
        "flatten_early_returns recursion depth {} exceeds limit 500. Tree likely too deep or cyclic.",
        depth
    );
    if depth > 500 {
        return stmts;
    }
    let mut result = Vec::with_capacity(stmts.len());

    for stmt in stmts {
        match stmt {
            Stmt::If {
                cond,
                then_body,
                else_body,
            } => {
                // Pattern: else is just a return → flip to early return guard
                if else_body.len() == 1
                    && matches!(else_body[0], Stmt::Return(_) | Stmt::Throw(_))
                    && !then_body.is_empty()
                    && !matches!(then_body.last(), Some(Stmt::Return(_) | Stmt::Throw(_)))
                {
                    let negated = negate_condition(cond);
                    result.push(Stmt::If {
                        cond: negated,
                        then_body: else_body,
                        else_body: vec![],
                    });
                    result.extend(flatten_early_returns_inner(
                        then_body,
                        depth.saturating_add(1),
                    ));
                }
                // Pattern: then is just a return → keep as early return guard
                else if then_body.len() == 1
                    && matches!(then_body[0], Stmt::Return(_) | Stmt::Throw(_))
                    && !else_body.is_empty()
                {
                    result.push(Stmt::If {
                        cond,
                        then_body,
                        else_body: vec![],
                    });
                    result.extend(flatten_early_returns_inner(
                        else_body,
                        depth.saturating_add(1),
                    ));
                } else {
                    result.push(Stmt::If {
                        cond,
                        then_body: flatten_early_returns_inner(then_body, depth.saturating_add(1)),
                        else_body: flatten_early_returns_inner(else_body, depth.saturating_add(1)),
                    });
                }
            }
            Stmt::While { cond, body } => {
                result.push(Stmt::While {
                    cond,
                    body: flatten_early_returns_inner(body, depth.saturating_add(1)),
                });
            }
            Stmt::ForIn { key, obj, body } => {
                result.push(Stmt::ForIn {
                    key,
                    obj,
                    body: flatten_early_returns_inner(body, depth.saturating_add(1)),
                });
            }
            Stmt::Switch {
                discriminant,
                cases,
                default,
            } => {
                result.push(Stmt::Switch {
                    discriminant,
                    cases: cases
                        .into_iter()
                        .map(|(v, b)| (v, flatten_early_returns_inner(b, depth.saturating_add(1))))
                        .collect(),
                    default: flatten_early_returns_inner(default, depth.saturating_add(1)),
                });
            }
            Stmt::TryCatch {
                try_body,
                catch_var,
                catch_body,
            } => {
                result.push(Stmt::TryCatch {
                    try_body: flatten_early_returns_inner(try_body, depth.saturating_add(1)),
                    catch_var,
                    catch_body: flatten_early_returns_inner(catch_body, depth.saturating_add(1)),
                });
            }
            other => result.push(other),
        }
    }

    result
}

/// Negate a condition for early-return flattening.
pub(super) fn negate_condition(cond: Condition) -> Condition {
    match cond {
        Condition::Truthy(v) => Condition::Falsy(v),
        Condition::Falsy(v) => Condition::Truthy(v),
        Condition::Compare { op, left, right } => {
            let negated_op = match op {
                "===" => "!==",
                "!==" => "===",
                "==" => "!=",
                "!=" => "==",
                "<" => ">=",
                ">=" => "<",
                ">" => "<=",
                "<=" => ">",
                other => other,
            };
            Condition::Compare {
                op: negated_op,
                left,
                right,
            }
        }
        Condition::IsUndefined(v) => Condition::NotUndefined(v),
        Condition::NotUndefined(v) => Condition::IsUndefined(v),
    }
}

/// Structure the SSA function.
/// Recover switch statements from chains of if (const === discriminant) { ... }.
/// Handles both nested if-else chains AND sequential if statements (post early-return flattening).
pub(super) fn recover_switch(stmts: Vec<Stmt>) -> Vec<Stmt> {
    apply_deep(stmts, &recover_switch_one_level)
}

/// Single-level switch recovery (no recursion — apply_deep handles children).
fn recover_switch_one_level(stmts: Vec<Stmt>) -> Vec<Stmt> {
    let mut result = Vec::with_capacity(stmts.len());
    let mut i = 0;

    while i < stmts.len() {
        if let Stmt::If {
            cond: Condition::Compare { op, .. },
            ..
        } = &stmts[i]
            && *op == "==="
            && let Some((pre_stmts, switch_stmt, consumed)) =
                try_extract_switch_sequential(&stmts[i..], true)
        {
            result.extend(pre_stmts);
            result.push(switch_stmt);
            i = i.saturating_add(consumed);
            continue;
        }

        result.push(stmts[i].clone());
        i = i.saturating_add(1);
    }

    result
}

/// Detect sequential if (const === disc) { return ... } statements with the same discriminant.
/// Returns (pre_stmts, switch_stmt, consumed_count)
fn try_extract_switch_sequential(stmts: &[Stmt], _debug: bool) -> Option<(Vec<Stmt>, Stmt, usize)> {
    // Extract discriminant from first statement
    let Stmt::If {
        cond:
            Condition::Compare {
                op: "===",
                right: discriminant,
                left: first_left,
            },
        then_body: first_body,
        else_body: first_else,
    } = &stmts[0]
    else {
        return None;
    };

    let disc = *discriminant;
    let mut cases: Vec<(String, Vec<Stmt>)> = Vec::new();

    // First: try nested else chain (original if-else-if pattern)
    if !first_else.is_empty() {
        cases.push((format!("{first_left}"), first_body.clone()));
        let mut remaining = first_else.as_slice();
        loop {
            if remaining.len() == 1
                && let Stmt::If {
                    cond:
                        Condition::Compare {
                            op: "===",
                            left,
                            right,
                        },
                    then_body,
                    else_body,
                } = &remaining[0]
                && *right == disc
            {
                cases.push((format!("{left}"), then_body.clone()));
                remaining = else_body.as_slice();
                continue;
            }
            break;
        }
        if cases.len() >= 3 {
            return Some((
                vec![],
                Stmt::Switch {
                    discriminant: disc,
                    cases,
                    default: remaining.to_vec(),
                },
                1,
            ));
        }
    }

    // Second: try sequential if statements (post early-return flattening)
    // Allow LoadConst assigns between If statements (they define case values).
    // We count them as consumed but they'll also be emitted before the switch
    // so the inline_map can resolve case label VarIds to their string values.
    cases.clear();
    let mut consumed = 0;
    let mut pre_switch: Vec<Stmt> = Vec::new();
    for stmt in stmts {
        match stmt {
            Stmt::If {
                cond: Condition::Compare { op, left, right },
                then_body,
                else_body,
            } if *op == "===" && *right == disc && else_body.is_empty() => {
                // Verify the case value comes from a constant load (not an arbitrary variable)
                // Check both pre_switch (between-case assigns) and the stmts before the chain
                let left_str = format!("{left}");
                let is_const = pre_switch.iter().any(|s| {
                    if let Stmt::Assign { dst, op, .. } = s {
                        dst.as_ref() == left_str.as_str() && op.name.starts_with("LoadConst")
                    } else {
                        false
                    }
                }) || stmts[..consumed].iter().any(|s| {
                    if let Stmt::Assign { dst, op, .. } = s {
                        dst.as_ref() == left_str.as_str() && op.name.starts_with("LoadConst")
                    } else {
                        false
                    }
                });
                if !is_const && !cases.is_empty() {
                    // Non-constant case after initial cases — stop the chain
                    break;
                }
                let label = left_str;
                cases.push((label, then_body.clone()));
                consumed = consumed.saturating_add(1);
                continue;
            }
            Stmt::Assign { op, .. } if op.name.starts_with("LoadConst") => {
                pre_switch.push(stmt.clone());
                consumed = consumed.saturating_add(1);
                continue;
            }
            _ => break,
        }
    }

    if cases.len() < 3 {
        return None;
    }

    // Check if the statement after the chain is a default (return/assignment)
    let mut default = Vec::new();
    if consumed < stmts.len()
        && let Stmt::Return(_) = &stmts[consumed]
    {
        default.push(stmts[consumed].clone());
        consumed = consumed.saturating_add(1);
    }

    Some((
        pre_switch,
        Stmt::Switch {
            discriminant: disc,
            cases,
            default,
        },
        consumed,
    ))
}

/// Recover for-in loops from GetPNameList + GetNextPName + JmpUndefined pattern.
/// Pattern: a while loop whose first op is GetNextPName on a GetPNameList result.
/// Recover for-in loops from the sequential pattern:
///   Assign { GetPNameList }
///   If IsUndefined { return/break }   (guard)
///   Assign { GetNextPName }           (from loop header)
///   While { body }
pub(super) fn recover_for_in(stmts: Vec<Stmt>) -> Vec<Stmt> {
    recover_for_in_inner(stmts, 0)
}

fn recover_for_in_inner(stmts: Vec<Stmt>, depth: usize) -> Vec<Stmt> {
    debug_assert!(
        depth <= 500,
        "recover_for_in recursion depth {} exceeds limit 500. Tree likely too deep or cyclic.",
        depth
    );
    if depth > 500 {
        return stmts;
    }
    let mut result = Vec::with_capacity(stmts.len());
    let mut i = 0;

    while i < stmts.len() {
        // Sequential pattern: GetPNameList → IsUndefined guard → GetNextPName → While
        if i.saturating_add(3) < stmts.len() {
            let is_pname_list =
                matches!(&stmts[i], Stmt::Assign { op, .. } if op.name == "GetPNameList");
            let is_guard = matches!(
                &stmts[i.saturating_add(1)],
                Stmt::If {
                    cond: Condition::IsUndefined(_),
                    ..
                } | Stmt::If {
                    cond: Condition::NotUndefined(_),
                    ..
                }
            );
            let get_next_info = if let Stmt::Assign { op, .. } = &stmts[i.saturating_add(2)] {
                if op.name == "GetNextPName" {
                    let key = op.dst.unwrap_or(VarId(u32::MAX, u32::MAX));
                    Some(key)
                } else {
                    None
                }
            } else {
                None
            };
            let is_while = matches!(&stmts[i.saturating_add(3)], Stmt::While { .. });

            if is_pname_list
                && is_guard
                && is_while
                && let Some(key_var) = get_next_info
            {
                let obj_var = if let Stmt::Assign { op, .. } = &stmts[i] {
                    match op.operands.get(1) {
                        Some(SsaOperand::Var(v)) => *v,
                        _ => VarId(u32::MAX, u32::MAX),
                    }
                } else {
                    VarId(u32::MAX, u32::MAX)
                };
                let body = if let Stmt::While { body, .. } = &stmts[i.saturating_add(3)] {
                    body.clone()
                } else {
                    vec![]
                };
                let post = if let Stmt::If { then_body, .. } = &stmts[i.saturating_add(1)] {
                    then_body.clone()
                } else {
                    vec![]
                };

                result.push(Stmt::ForIn {
                    key: key_var,
                    obj: obj_var,
                    body: recover_for_in_inner(body, depth.saturating_add(1)),
                });
                result.extend(recover_for_in_inner(post, depth.saturating_add(1)));
                i = i.saturating_add(4);
                continue;
            }
        }

        // Recurse into children
        match stmts[i].clone() {
            Stmt::If {
                cond,
                then_body,
                else_body,
            } => result.push(Stmt::If {
                cond,
                then_body: recover_for_in_inner(then_body, depth.saturating_add(1)),
                else_body: recover_for_in_inner(else_body, depth.saturating_add(1)),
            }),
            Stmt::While { cond, body } => result.push(Stmt::While {
                cond,
                body: recover_for_in_inner(body, depth.saturating_add(1)),
            }),
            other => result.push(other),
        }
        i = i.saturating_add(1);
    }

    result
}

/// Recover destructuring: consecutive GetById on the same object → var { a, b } = obj
fn recover_destructuring_one_level(stmts: Vec<Stmt>) -> Vec<Stmt> {
    let mut result = Vec::with_capacity(stmts.len());
    let mut i = 0;

    while i < stmts.len() {
        // Check if this is a GetById assign
        if let Stmt::Assign { op, dst, .. } = &stmts[i]
            && (op.name.starts_with("GetById") || op.name.starts_with("TryGetById"))
        {
            let obj_var = op.operands.get(1).and_then(|o| {
                if let SsaOperand::Var(v) = o {
                    Some(*v)
                } else {
                    None
                }
            });
            let prop = op.operands.last().and_then(|o| match o {
                SsaOperand::ResolvedString(s) => Some(s.clone()),
                _ => None,
            });

            if let (Some(obj), Some(prop_name)) = (obj_var, prop) {
                let mut bindings = vec![(prop_name, dst.to_string())];
                let mut j = i.saturating_add(1);
                while j < stmts.len() {
                    if let Stmt::Assign {
                        op: next_op,
                        dst: next_dst,
                        ..
                    } = &stmts[j]
                        && (next_op.name.starts_with("GetById")
                            || next_op.name.starts_with("TryGetById"))
                        && next_op.operands.get(1) == Some(&SsaOperand::Var(obj))
                        && let Some(SsaOperand::ResolvedString(s)) = next_op.operands.last()
                    {
                        bindings.push((s.clone(), next_dst.to_string()));
                        j = j.saturating_add(1);
                        continue;
                    }
                    break;
                }

                if bindings.len() >= 3 {
                    result.push(Stmt::Destructure {
                        object: format!("{obj}"),
                        bindings,
                    });
                    i = j;
                    continue;
                }
            }
        }

        result.push(stmts[i].clone());
        i = i.saturating_add(1);
    }

    result
}

/// Recover class syntax from CreateBaseClass/CreateDerivedClass + PutNewOwnById patterns.
fn recover_class_one_level(stmts: Vec<Stmt>) -> Vec<Stmt> {
    // Pre-scan: collect private-name bindings so `AddOwnPrivateBySym` can be
    // folded into the class body with the correct `#name`. Also track which
    // SSA vars hold closures so `DefineOwnById` with a closure value is still
    // treated as a method (not a static field). Record LoadConst* literal
    // values for any SSA var we may need to inline directly into a
    // `static x = VALUE` emit — the defining `Stmt::Assign` is consumed by
    // the class-recovery scan below, which strips it from `build_inline_map`'s
    // view, so we have to resolve the literal here instead.
    let mut private_names: BTreeMap<String, String> = BTreeMap::new();
    let mut closure_vars: BTreeSet<String> = BTreeSet::new();
    let mut literal_vars: BTreeMap<String, String> = BTreeMap::new();
    for s in &stmts {
        if let Stmt::Assign { dst, op, .. } = s {
            if op.name == "CreatePrivateName"
                && let Some(SsaOperand::ResolvedString(name)) = op.operands.get(1)
            {
                private_names.insert(dst.to_string(), name.clone());
            }
            if op.name.starts_with("CreateClosure")
                || op.name.starts_with("CreateAsyncClosure")
                || op.name.starts_with("CreateGeneratorClosure")
            {
                closure_vars.insert(dst.to_string());
            }
            if let Some(lit) = load_const_literal(op.name, &op.operands) {
                literal_vars.insert(dst.to_string(), lit);
            }
        }
    }

    let mut result = Vec::with_capacity(stmts.len());
    let mut i = 0;

    while i < stmts.len() {
        // Detect CreateBaseClass/CreateDerivedClass assignment
        if let Stmt::Assign { dst, op, .. } = &stmts[i]
            && (op.name == "CreateBaseClass"
                || op.name == "CreateBaseClassLongIndex"
                || op.name == "CreateDerivedClass"
                || op.name == "CreateDerivedClassLongIndex")
        {
            let class_var = dst.to_string();
            let extends = if op.name.contains("Derived") {
                // DerivedClass has parent as operand
                op.operands.get(1).map(|o| match o {
                    SsaOperand::Var(v) => format!("{v}"),
                    _ => "?".into(),
                })
            } else {
                None
            };

            // Scan ahead for method definitions + static-field initializers on
            // the class or its prototype.
            //   v99: DefineOwnByVal(prototype, closure, "name", ...) — method
            //   v99: DefineOwnById(class, value, cache, "name") — static public field
            //   v99: AddOwnPrivateBySym(class, value, sym) — static private field
            //   v96: PutNewOwnById(class, closure, stringId) — method
            // Interleaved LoadConst*/GetGlobalObject/CreatePrivateName/CreateClosure
            // assignments produce values consumed by the above; we skip them
            // without emitting so they don't leak outside the class.
            let mut methods: Vec<(String, String)> = Vec::new();
            let mut static_fields: Vec<StaticField> = Vec::new();
            let mut j = i.saturating_add(1);
            while j < stmts.len() {
                match &stmts[j] {
                    // Static public field: DefineOwnById on the class, value
                    // is NOT a closure. Checked before the method arm so
                    // field-shaped DefineOwnById doesn't land in `methods`.
                    // Only consume the stmt when both name and value can be
                    // extracted — on failure, break so the op keeps its
                    // pre-patch post-class emit rather than being silently
                    // dropped.
                    Stmt::Op(op)
                        if op.name.starts_with("DefineOwnById")
                            && first_var(&op.operands).as_deref() == Some(class_var.as_str())
                            && !is_closure_value(&op.operands, &closure_vars) =>
                    {
                        match (
                            op.operands.iter().find_map(resolved_string),
                            op.operands.get(1).and_then(var_name),
                        ) {
                            (Some(name), Some(value)) => {
                                let value = literal_vars.get(&value).cloned().unwrap_or(value);
                                static_fields.push(StaticField {
                                    name,
                                    value,
                                    is_private: false,
                                });
                                j = j.saturating_add(1);
                                continue;
                            }
                            _ => break,
                        }
                    }
                    // Static private field: AddOwnPrivateBySym(class, value, sym).
                    // Operand order per Hermes VM (lib/VM/Interpreter.cpp)
                    // emitAddOwnPrivateBySym(objReg, valueReg, symReg). Same
                    // consume-on-success-only guard as the public arm above.
                    Stmt::Op(op)
                        if op.name == "AddOwnPrivateBySym"
                            && first_var(&op.operands).as_deref() == Some(class_var.as_str()) =>
                    {
                        let sym_var = op.operands.get(2).and_then(var_name);
                        let name = sym_var.and_then(|v| private_names.get(&v).cloned());
                        let value = op.operands.get(1).and_then(var_name);
                        match (name, value) {
                            (Some(name), Some(value)) => {
                                let value = literal_vars.get(&value).cloned().unwrap_or(value);
                                static_fields.push(StaticField {
                                    name,
                                    value,
                                    is_private: true,
                                });
                                j = j.saturating_add(1);
                                continue;
                            }
                            _ => break,
                        }
                    }
                    Stmt::Op(op)
                        if op.name.starts_with("PutNewOwnById")
                            || op.name.starts_with("PutNewOwnNEById")
                            || op.name.starts_with("DefineOwnByVal")
                            || op.name.starts_with("DefineOwnById") =>
                    {
                        let prop = op.operands.iter().find_map(resolved_string);
                        let value = match op.operands.get(1) {
                            Some(SsaOperand::Var(v)) => format!("{v}"),
                            _ => "?".into(),
                        };
                        if let Some(prop_name) = prop {
                            methods.push((prop_name, value));
                        }
                        j = j.saturating_add(1);
                        continue;
                    }
                    // Skip CreateClosure + value-producing loads (LoadConst*,
                    // GetGlobalObject, CreatePrivateName) — their outputs feed
                    // later class-body stores.
                    Stmt::Assign { op, .. }
                        if op.name.starts_with("CreateClosure")
                            || op.name.starts_with("CreateAsyncClosure")
                            || op.name.starts_with("CreateGeneratorClosure")
                            || op.name.starts_with("LoadConst")
                            || op.name == "CreatePrivateName"
                            || op.name == "GetGlobalObject" =>
                    {
                        j = j.saturating_add(1);
                        continue;
                    }
                    // Skip StoreToEnvironment (class stored to env)
                    Stmt::Op(op)
                        if op.name.starts_with("StoreToEnvironment")
                            || op.name.starts_with("StoreNPToEnvironment") =>
                    {
                        j = j.saturating_add(1);
                        continue;
                    }
                    _ => break,
                }
            }

            if !methods.is_empty() || !static_fields.is_empty() {
                result.push(Stmt::Class {
                    name: class_var,
                    extends,
                    methods,
                    static_fields,
                });
                i = j;
                continue;
            }
        }

        result.push(stmts[i].clone());
        i = i.saturating_add(1);
    }

    result
}

fn first_var(ops: &[SsaOperand]) -> Option<String> {
    match ops.first()? {
        SsaOperand::Var(v) => Some(format!("{v}")),
        _ => None,
    }
}

fn var_name(op: &SsaOperand) -> Option<String> {
    match op {
        SsaOperand::Var(v) => Some(format!("{v}")),
        _ => None,
    }
}

fn resolved_string(op: &SsaOperand) -> Option<String> {
    match op {
        SsaOperand::ResolvedString(s) => Some(s.clone()),
        _ => None,
    }
}

fn is_closure_value(ops: &[SsaOperand], closure_vars: &BTreeSet<String>) -> bool {
    match ops.get(1) {
        Some(SsaOperand::Var(v)) => closure_vars.contains(&format!("{v}")),
        _ => false,
    }
}

/// Resolve a `LoadConst*` Assign to a display string. Covers the subset
/// that shows up as static-field initializers; anything unrecognized
/// returns `None` and the caller falls back to the SSA-var reference.
fn load_const_literal(name: &str, ops: &[SsaOperand]) -> Option<String> {
    match name {
        "LoadConstZero" => Some("0".into()),
        "LoadConstUndefined" => Some("undefined".into()),
        "LoadConstNull" => Some("null".into()),
        "LoadConstTrue" => Some("true".into()),
        "LoadConstFalse" => Some("false".into()),
        "LoadConstEmpty" => Some("undefined".into()),
        "LoadConstInt" | "LoadConstUInt8" => match ops.get(1) {
            Some(SsaOperand::Const(v)) => Some(v.to_string()),
            _ => None,
        },
        "LoadConstDouble" => match ops.get(1) {
            Some(SsaOperand::ConstDouble(d)) => Some(format!("{d}")),
            _ => None,
        },
        // `LoadConstString` is intentionally unhandled: the defining op keeps
        // operand index 1 as `StringId` (optimize's string-propagation rewrites
        // use sites only, not defs), and sugar has no `get_str` resolver. A
        // string-initialized static field falls back to the SSA-var name
        // until `get_str` is threaded through `recover_class`.
        _ => None,
    }
}

pub(super) fn recover_class(stmts: Vec<Stmt>) -> Vec<Stmt> {
    apply_deep(stmts, &recover_class_one_level)
}

/// Recover ESM syntax from CJS patterns.
/// - var x = require(id) → import x from "module"
/// - exports.name = value → export const name = value
/// - module.exports = value → export default value
pub(super) fn recover_esm_one_level(
    stmts: Vec<Stmt>,
    get_str: &dyn Fn(u32) -> String,
    get_module_name: &dyn Fn(i64) -> Option<String>,
) -> Vec<Stmt> {
    let mut result = Vec::with_capacity(stmts.len());

    for stmt in stmts {
        match &stmt {
            // Pattern: var x = require(moduleId) → import x from "module"
            Stmt::Assign { dst, op, .. } if op.name == "CallRequire" => {
                let module_id = op.operands.get(2).and_then(|o| match o {
                    SsaOperand::Const(id) => Some(*id),
                    _ => None,
                });
                if let Some(id) = module_id
                    && let Some(module_path) = get_module_name(id)
                {
                    result.push(Stmt::Import {
                        name: dst.to_string(),
                        source: module_path,
                    });
                    continue;
                }
                result.push(stmt);
            }
            // Pattern: exports.name = value or module.exports = value
            Stmt::Op(op)
                if (op.name.starts_with("PutById") || op.name.starts_with("TryPutById")) =>
            {
                // Check if the object is "exports" or "module"
                let obj_name = op.operands.first().and_then(|o| match o {
                    SsaOperand::Var(v) => Some(format!("{v}")),
                    _ => None,
                });
                let prop = op.operands.last().and_then(|o| match o {
                    SsaOperand::ResolvedString(s) => Some(s.clone()),
                    SsaOperand::Const(sid) => {
                        #[allow(clippy::as_conversions, clippy::cast_possible_truncation, clippy::cast_sign_loss, reason = "i64→u32 narrows; sid is the bytecode-format string-id (bounded by the string_count u32 in the HBC header); truncation/sign-loss unreachable.")]
                        let sid_u32 = *sid as u32;
                        let s = get_str(sid_u32);
                        if s.is_empty() { None } else { Some(s) }
                    }
                    _ => None,
                });
                let value = op.operands.get(1).map(|o| match o {
                    SsaOperand::Var(v) => format!("{v}"),
                    SsaOperand::Const(c) => format!("{c}"),
                    SsaOperand::ResolvedString(s) => format!("\"{s}\""),
                    _ => "undefined".to_string(),
                });

                // Heuristic: check if we're writing to a variable named "exports" or "module"
                // This is fragile but works for Metro CJS wrappers where arg 2 is exports
                if let (Some(_obj), Some(prop_name), Some(val)) = (&obj_name, &prop, &value)
                    && prop_name == "exports"
                {
                    // module.exports = value → export default
                    result.push(Stmt::ExportDefault { value: val.clone() });
                    continue;
                }
                result.push(stmt);
            }
            _ => result.push(stmt),
        }
    }

    result
}

/// Clean up generator/async function bodies.
/// - Remove `void 0 /* generator start */` and `void 0 /* resume */` noise
/// - Remove ResumeGenerator's `if (isReturn) { return; }` guard
/// - Merge `yield; return VALUE;` into `yield VALUE;`
pub(super) fn recover_generator_one_level(stmts: Vec<Stmt>) -> Vec<Stmt> {
    let mut result = Vec::with_capacity(stmts.len());
    let mut i = 0;

    while i < stmts.len() {
        match &stmts[i] {
            // Remove generator noise ops
            Stmt::Op(op) if op.name == "StartGenerator" => {
                i = i.saturating_add(1);
                continue;
            }
            Stmt::Assign { op, .. } if op.name == "ResumeGenerator" => {
                // ResumeGenerator is often followed by `if (isReturn) { return; }`
                // Skip both the assign and the guard if present
                if i.saturating_add(1) < stmts.len()
                    && let Stmt::If {
                        then_body,
                        else_body,
                        ..
                    } = &stmts[i.saturating_add(1)]
                {
                    // Guard pattern: if(isReturn) { return/CompleteGenerator; return; }
                    let is_return_guard = (then_body.len() <= 2
                        && then_body.iter().any(|s| {
                            matches!(s, Stmt::Return(_))
                                || matches!(s, Stmt::Op(op) if op.name == "CompleteGenerator")
                        }))
                        || (else_body.len() <= 2
                            && else_body.iter().any(|s| {
                                matches!(s, Stmt::Return(_))
                                    || matches!(s, Stmt::Op(op) if op.name == "CompleteGenerator")
                            }));
                    if is_return_guard {
                        i = i.saturating_add(2); // skip both ResumeGenerator assign and guard if
                        continue;
                    }
                }
                i = i.saturating_add(1);
                continue;
            }
            // Remove standalone CompleteGenerator
            Stmt::Op(op) if op.name == "CompleteGenerator" => {
                i = i.saturating_add(1);
                continue;
            }
            // `yield;` followed by `return VALUE;` → skip the return
            // The yield already carries the semantics; the return is the runtime mechanism.
            Stmt::Op(op) if op.name == "SaveGenerator" || op.name == "SaveGeneratorLong" => {
                result.push(stmts[i].clone());
                // Skip the return that follows SaveGenerator (it's the yield mechanism)
                if i.saturating_add(1) < stmts.len()
                    && matches!(&stmts[i.saturating_add(1)], Stmt::Return(_))
                {
                    i = i.saturating_add(2);
                } else {
                    i = i.saturating_add(1);
                }
            }
            // Detect {value: X, done: true/false} + optional PutOwnBySlotIdx + return
            // These are generator yield/return protocol objects.
            //
            // Matches both the pre-fold shape (`NewObjectWithBuffer` with
            // `ResolvedString({value: X, done: Y})` + subsequent PutOwnBySlotIdx
            // writing `value`) and the post-fold shape (`HermesObjectLit`
            // with operands `[dst, "value", <value_operand>, "done", <done_token>]`
            // produced by `optimize::resolve_buffers`' cluster-fold pass).
            // The `value_var` extraction below also covers both shapes —
            // HermesObjectLit stores the already-folded value in operand[2]
            // (when keys are `value`-first).
            Stmt::Assign { op, .. }
                if (op.name == "NewObjectWithBuffer"
                    || op.name == "NewObjectWithBufferLong"
                    || op.name == "HermesObjectLit")
                    && i.saturating_add(1) < stmts.len() =>
            {
                // For `HermesObjectLit` the done-literal is a separate operand
                // (`ResolvedString("true")` / `ResolvedString("false")` /
                // `ResolvedString("null")`); for `NewObjectWithBuffer` it's
                // embedded in the single `ResolvedString({...})` operand.
                // Treat both via string-level contains after flattening the
                // operand list to its rendered-token form.
                let (is_done_true, is_done_false) = if op.name == "HermesObjectLit" {
                    // Walk pair operands: [dst, key1, val1, key2, val2, ...].
                    let mut done_tok: Option<&str> = None;
                    let mut k_idx: usize = 1;
                    while k_idx.saturating_add(1) < op.operands.len() {
                        if let (
                            Some(SsaOperand::ResolvedString(k)),
                            Some(SsaOperand::ResolvedString(v)),
                        ) = (
                            op.operands.get(k_idx),
                            op.operands.get(k_idx.saturating_add(1)),
                        ) && k == "done"
                        {
                            done_tok = Some(v.as_str());
                            break;
                        }
                        k_idx = k_idx.saturating_add(2);
                    }
                    match done_tok {
                        Some("true") => (true, false),
                        Some("false") | Some("null") => (false, true),
                        _ => (false, false),
                    }
                } else {
                    let resolved = op
                        .operands
                        .iter()
                        .find_map(|o| {
                            if let SsaOperand::ResolvedString(s) = o {
                                Some(s.as_str())
                            } else {
                                None
                            }
                        })
                        .unwrap_or("");
                    (
                        resolved.contains("done: true"),
                        resolved.contains("done: null") || resolved.contains("done: false"),
                    )
                };

                if is_done_true || is_done_false {
                    // Look ahead: skip any assignment-like stmts (PutOwnBySlotIdx rendered
                    // as index assigns), find the Return that completes the yield/return protocol.
                    let mut j = i.saturating_add(1);
                    // For HermesObjectLit, value is already folded into the op's
                    // operand list — extract it from the pair whose key is `value`.
                    // PutOwnBySlotIdx ops for the value slot were removed by the
                    // fold pass, so the subsequent scan won't find a `value`-writing
                    // Put. Pre-seeding `value_var` from the folded operands covers this.
                    let mut value_var: Option<VarId> = if op.name == "HermesObjectLit" {
                        let mut extracted: Option<VarId> = None;
                        let mut k_idx: usize = 1;
                        while k_idx.saturating_add(1) < op.operands.len() {
                            if let (Some(SsaOperand::ResolvedString(k)), Some(SsaOperand::Var(v))) = (
                                op.operands.get(k_idx),
                                op.operands.get(k_idx.saturating_add(1)),
                            ) && k == "value"
                            {
                                extracted = Some(*v);
                                break;
                            }
                            k_idx = k_idx.saturating_add(2);
                        }
                        extracted
                    } else {
                        None
                    };
                    while j < stmts.len() {
                        match &stmts[j] {
                            // PutOwnBySlotIdx as Stmt::Op
                            Stmt::Op(p)
                                if p.name.starts_with("PutOwnBySlotIdx")
                                    || p.name.starts_with("PutOwnByVal") =>
                            {
                                if let Some(SsaOperand::Var(v)) = p.operands.get(1) {
                                    value_var = Some(*v);
                                }
                                j = j.saturating_add(1);
                            }
                            // Store to environment (state variable update) — skip
                            Stmt::Op(p)
                                if p.name.starts_with("StoreNPToEnvironment")
                                    || p.name.starts_with("StoreToEnvironment") =>
                            {
                                j = j.saturating_add(1);
                            }
                            Stmt::Return(_) => {
                                if is_done_false {
                                    result.push(Stmt::Comment(if let Some(val) = value_var {
                                        format!("await {val}")
                                    } else {
                                        "await".into()
                                    }));
                                } else {
                                    result.push(Stmt::Return(value_var));
                                }
                                j = j.saturating_add(1);
                                break;
                            }
                            _ => break,
                        }
                    }
                    if j > i.saturating_add(1) {
                        i = j;
                        continue;
                    }
                }
                result.push(stmts[i].clone());
                i = i.saturating_add(1);
            }
            _ => {
                result.push(stmts[i].clone());
                i = i.saturating_add(1);
            }
        }
    }

    result
}

/// Linearize async state machines into sequential await calls.
///
/// Hermes compiles `async function f() { let x = await p; ... }` into a generator
/// state machine where a state variable (environment slot) dispatches to different
/// continuation points. This pass detects the state machine pattern and flattens
/// it into sequential code with `await` expressions.
///
/// Pattern detected:
/// ```text
/// try { } catch (e) {
///   stateSlot = errorState;
///   throw e;
///   stateVar = closure_slot_N;
///   if (stateVar === 2) { throwTypeError; }           // completed guard
///   else if (stateVar === 3) { throw/return based on a0; }  // done handler
///   else { ... actual work ... // await ... }          // active states
/// }
/// ```
pub(super) fn linearize_async(stmts: Vec<Stmt>) -> Vec<Stmt> {
    // Pattern 1: try-catch wrapper with state machine in catch body (pre-structural try-catch)
    let tc_idx = stmts.iter().position(|s| {
        if let Stmt::TryCatch {
            try_body,
            catch_body,
            ..
        } = s
        {
            catch_body.len() >= 4
                && try_body.iter().all(|t| match t {
                    Stmt::Comment(_) => true,
                    Stmt::Op(op) => op.name.starts_with("Store"),
                    _ => false,
                })
        } else {
            false
        }
    });

    if let Some(tc_idx) = tc_idx {
        let catch_body = match &stmts[tc_idx] {
            Stmt::TryCatch { catch_body, .. } => catch_body,
            _ => return stmts,
        };
        let if_stmt = catch_body.iter().find(|s| matches!(s, Stmt::If { .. }));
        if let Some(if_stmt) = if_stmt {
            let active_else = skip_state_guards(if_stmt);
            if !active_else.is_empty() {
                let mut linear = Vec::new();
                collect_active_work(&active_else, &mut linear);
                if !linear.is_empty() {
                    return linear;
                }
            }
        }
    }

    // Pattern 2: flat state dispatch at end of function (structural try-catch)
    // Shape: [try-catch blocks..., setup stmts, if (state===2) { throwTypeError }
    //         else { if (state===3) { done } else { active work } }]
    // Only trigger when the first guard contains throwTypeError (async-specific).
    let if_stmt = stmts.iter().rev().find(|s| matches!(s, Stmt::If { .. }));
    if let Some(if_stmt) = if_stmt {
        // Verify this is an async state machine: first if-branch must have throwTypeError
        let has_type_error_guard = if let Stmt::If { then_body, .. } = if_stmt {
            then_body.iter().any(|s| {
                if let Stmt::Assign { op, .. } | Stmt::Op(op) = s {
                    op.name == "CallBuiltin" || op.name == "CallBuiltinLong"
                } else {
                    false
                }
            })
        } else {
            false
        };
        if has_type_error_guard {
            let active_else = skip_state_guards(if_stmt);
            if !active_else.is_empty() {
                let mut linear = Vec::new();
                collect_active_work(&active_else, &mut linear);
                if !linear.is_empty() {
                    return linear;
                }
            }
        }
    }

    stmts
}

/// Walk nested if (state===N) chains, skipping guard branches (throwTypeError, done handler).
/// Returns the statements from the innermost "else" that contains the active work.
fn skip_state_guards(stmt: &Stmt) -> Vec<Stmt> {
    if let Stmt::If {
        then_body,
        else_body,
        ..
    } = stmt
    {
        // Check if then_body is a guard
        if is_state_guard(then_body) {
            // Skip this guard, recurse into else
            // The else might contain another guard or the active states
            if let Some(inner_if) = else_body.iter().find(|s| matches!(s, Stmt::If { .. })) {
                return skip_state_guards(inner_if);
            }
            // else_body IS the active states (no more guards)
            return else_body.clone();
        }
    }
    vec![]
}

/// Check if a block is a state machine guard (not real work).
fn is_state_guard(stmts: &[Stmt]) -> bool {
    // Guard: contains CallBuiltin (throwTypeError) — the "already completed" state
    let has_call_builtin = stmts.iter().any(|s| {
        if let Stmt::Assign { op, .. } | Stmt::Op(op) = s {
            op.name == "CallBuiltin" || op.name == "CallBuiltinLong"
        } else {
            false
        }
    });
    if has_call_builtin {
        return true;
    }

    // Guard: if(a0===1) throw; if(a0===2) return — the done handler
    let has_throw = stmts.iter().any(|s| {
        if let Stmt::If { then_body, .. } = s {
            then_body.iter().any(|t| matches!(t, Stmt::Throw(_)))
        } else {
            matches!(s, Stmt::Throw(_))
        }
    });
    let has_return = stmts.iter().any(|s| {
        if let Stmt::If { then_body, .. } = s {
            then_body.iter().any(|t| matches!(t, Stmt::Return(_)))
        } else {
            matches!(s, Stmt::Return(_))
        }
    });
    let has_no_await = !stmts
        .iter()
        .any(|s| matches!(s, Stmt::Comment(c) if c.starts_with("await")));

    has_throw && has_return && has_no_await
}

/// Recursively collect the actual work statements from active state bodies.
/// Strips state variable updates, resume checks, and if-else dispatch on sub-states.
fn collect_active_work(stmts: &[Stmt], output: &mut Vec<Stmt>) {
    for s in stmts {
        match s {
            // Skip state variable updates
            Stmt::Op(op)
                if op.name.starts_with("StoreNPToEnvironment")
                    || op.name.starts_with("StoreToEnvironment") =>
            {
                continue;
            }
            // Await comments stay
            Stmt::Comment(c) if c.starts_with("await") => {
                output.push(s.clone());
            }
            // If-else: check if it's a resume check or a sub-state dispatch
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                if is_state_guard(then_body) {
                    // Resume check — the work is in the else branch
                    collect_active_work(else_body, output);
                } else if is_state_guard(else_body) {
                    collect_active_work(then_body, output);
                } else {
                    // Sub-state dispatch or real conditional — collect from both
                    // Prioritize: both branches may have real work
                    let mut then_work = Vec::new();
                    let mut else_work = Vec::new();
                    collect_active_work(then_body, &mut then_work);
                    collect_active_work(else_body, &mut else_work);
                    // If both have work, emit sequentially (state 0 then state 1)
                    output.extend(then_work);
                    output.extend(else_work);
                }
            }
            // Keep everything else (assignments, calls, returns)
            _ => {
                output.push(s.clone());
            }
        }
    }
}

pub(super) fn recover_destructuring(stmts: Vec<Stmt>) -> Vec<Stmt> {
    apply_deep(stmts, &recover_destructuring_one_level)
}

/// Recover defaulted single-entry destructuring:
///   `var { [key]: target = default } = object;`  (computed key)
///   `var { key: target = default } = object;`     (static key)
///
/// Marker: a 3-stmt cluster
///   `[i]   Stmt::Assign { dst: X, op: GetBy*(object, key) }`
///   `[i+1] Stmt::If { cond: undef-marker(X), then_body: [Assign(X, LoadConst*(default))], else_body: [] }`
///   `[i+2] Stmt::Op(PutBy*(target_obj, X, target_prop_const))`
///
/// where the **undef-marker** is either `Condition::IsUndefined(X)` (from
/// `JmpUndefined`) or `Condition::Compare("===", X, U)` where `U` is bound
/// to a `LoadConstUndefined` Assign earlier in the block (from the more
/// common `JStrictNotEqual L, X, undef` lowering, after structurer branch
/// negation flips the polarity).
///
/// The marker shape is unfakeable from any source-level JS surface other
/// than a defaulted destructure (no human writes
/// `let x = obj.k; if (x === undefined) x = 99; globalThis.y = x;`), so
/// reconstruction is lossless on this gate. Absent the marker, the cluster
/// is left untouched and emit falls through to the existing sequential form.
///
/// SSA versioning across the 3 stmts: `X` appears as 3 distinct VarIds —
/// the GetBy* dst (`X.0`), the LoadConst dst inside the THEN branch (`X.1`),
/// and the PutBy* value operand (`X.2`, the merge point). All three share
/// the same register number (`VarId.0`); we match by register, not version,
/// so the structural identity survives Hermes-level register reuse.
pub(super) fn recover_destructuring_with_default(stmts: Vec<Stmt>) -> Vec<Stmt> {
    apply_deep(stmts, &recover_destructuring_with_default_one_level)
}

fn recover_destructuring_with_default_one_level(stmts: Vec<Stmt>) -> Vec<Stmt> {
    let undef_regs = collect_undef_regs(&stmts);

    // Scan for If-stmts matching the undef-marker shape. For each hit, walk
    // backward to find the final `GetBy*` Assign (the cluster's source-read)
    // and forward to the `PutBy*` Op (the cluster's binding-store); fold the
    // three into a single `DestructureWithDefault`.
    //
    // Non-adjacency is load-bearing: Hermes emits `PhiAssign` + a shared
    // `LoadConstUndefined` Assign between the final-get and the If, so the
    // three target stmts are not index-contiguous. Walking past phis /
    // `LoadConstUndefined` Assigns (both harmless to skip) reaches the
    // correct anchors.
    let mut replace: BTreeMap<usize, Stmt> = BTreeMap::new();
    let mut drop_idxs: BTreeSet<usize> = BTreeSet::new();
    for (if_idx, s) in stmts.iter().enumerate() {
        let Stmt::If {
            cond,
            then_body,
            else_body,
        } = s
        else {
            continue;
        };
        if !else_body.is_empty() {
            continue;
        }
        let Some(x_reg) = cond_undef_marker_reg(cond, &undef_regs) else {
            continue;
        };
        let Some(default_str) = then_body_default(then_body, x_reg) else {
            continue;
        };
        let Some((get_idx, object, path, chain_idxs)) = walk_back_chain(&stmts, if_idx, x_reg)
        else {
            continue;
        };
        let Some((put_idx, target_prop, target_receiver)) = find_put_target(&stmts, if_idx, x_reg)
        else {
            continue;
        };
        // Clusters can't overlap — each If has at most one match, and Get/Put
        // indices are distinct per If. Overlapping-dst edge-cases (e.g. the
        // same reg driving two Ifs) are filtered by the single-if scan.
        if drop_idxs.contains(&get_idx)
            || drop_idxs.contains(&put_idx)
            || chain_idxs.iter().any(|i| drop_idxs.contains(i))
        {
            continue;
        }
        drop_idxs.insert(get_idx);
        drop_idxs.insert(put_idx);
        // Intermediate chain steps absorbed into the path become orphan
        // Assigns post-fold (their only use-site was the next chain-step,
        // which is itself now in drop_idxs or absorbed). Dropping them
        // keeps emit tidy and prevents `var r3_N = globalThis.data.outer;`
        // stragglers ahead of the folded `var { outer: { ... } } = ...;`.
        for idx in chain_idxs {
            drop_idxs.insert(idx);
        }
        replace.insert(
            if_idx,
            Stmt::DestructureWithDefault {
                object,
                target_receiver,
                target: target_prop,
                default: default_str,
                path,
            },
        );
    }

    if replace.is_empty() {
        return stmts;
    }
    let mut result: Vec<Stmt> = Vec::with_capacity(stmts.len());
    for (i, s) in stmts.into_iter().enumerate() {
        if let Some(new_s) = replace.remove(&i) {
            result.push(new_s);
        } else if !drop_idxs.contains(&i) {
            result.push(s);
        }
    }
    result
}

/// Collect SSA register numbers that hold the value `undefined` at the
/// current scope: directly defined by `LoadConstUndefined`, or transitively
/// propagated by `PhiAssign` from one.
///
/// The register number is what `Condition::Compare.right` surfaces — the
/// structurer carries `VarId` there, and two SSA versions of the same
/// register share `VarId.0`. Propagation through `PhiAssign` is needed
/// because Hermes re-phis the undef-constant across each defaulting cluster
/// (see `r1_6 → r1_12 → r1_23 → r1_35` in the sample fixture).
fn collect_undef_regs(stmts: &[Stmt]) -> BTreeSet<u32> {
    let mut undef_names: BTreeSet<String> = BTreeSet::new();
    for s in stmts {
        if let Stmt::Assign { op, dst, .. } = s
            && op.name == "LoadConstUndefined"
        {
            undef_names.insert(dst.to_string());
        }
    }
    // Multi-pass through PhiAssigns until fixpoint; bound by stmts.len().
    for _ in 0..stmts.len() {
        let mut added = false;
        for s in stmts {
            if let Stmt::PhiAssign { dst, src } = s
                && undef_names.contains(src.as_ref())
                && undef_names.insert(dst.to_string())
            {
                added = true;
            }
        }
        if !added {
            break;
        }
    }
    let mut regs: BTreeSet<u32> = BTreeSet::new();
    for name in &undef_names {
        if let Some(reg) = parse_varid_reg(name) {
            regs.insert(reg);
        }
    }
    regs
}

/// Parse a `VarId`-display string of the form `"rN_M"` into its register
/// number `N`. Returns `None` for any other shape — coalesce-renamed keys
/// (e.g. `"inner"`) don't carry a register, which is the correct signal that
/// they aren't candidates for the undef-propagation pass.
fn parse_varid_reg(s: &str) -> Option<u32> {
    let rest = s.strip_prefix('r')?;
    let (r_str, _) = rest.split_once('_')?;
    r_str.parse().ok()
}

/// If `cond` matches the `X === undefined` undef-marker (in either direct
/// `IsUndefined` or `Compare("===", X, U)` form where `U` is known-undef),
/// return the register of `X`.
fn cond_undef_marker_reg(cond: &Condition, undef_regs: &BTreeSet<u32>) -> Option<u32> {
    match cond {
        Condition::IsUndefined(v) => Some(v.0),
        Condition::Compare {
            op: "===",
            left,
            right,
        } => {
            if undef_regs.contains(&right.0) {
                Some(left.0)
            } else if undef_regs.contains(&left.0) {
                Some(right.0)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Inspect a defaulting `If`'s then-body; return the `LoadConst*` literal
/// that writes the default value to `x_reg`, if one exists. Allows trailing
/// `PhiAssign` stmts after the LoadConst (which Hermes emits to phi the
/// value forward past the merge point) but rejects any other trailing stmt
/// — the fold deletes the If, so silently discarding side-effecting stmts
/// inside the then-branch would be a semantic regression.
fn then_body_default(then_body: &[Stmt], x_reg: u32) -> Option<String> {
    let first = then_body.first()?;
    let Stmt::Assign { op, .. } = first else {
        return None;
    };
    if op.dst?.0 != x_reg {
        return None;
    }
    // Tail must be phi-copies only. Any non-phi stmt post-LoadConst signals
    // a then-body shape the detector wasn't designed for; bail rather than
    // silently drop the tail during fold.
    if !then_body[1..]
        .iter()
        .all(|s| matches!(s, Stmt::PhiAssign { .. }))
    {
        return None;
    }
    load_const_literal(op.name, &op.operands)
}

/// Maximum destructure-pattern nesting depth accepted by the chain-walker —
/// the TOTAL `DestructurePath` depth, counting the leaf level. Walker
/// iterations cap at `DEPTH - 1` so at most `DEPTH-1` `Nested` wrappers
/// sit above the terminal `Leaf`.
///
/// Source-level JS past 5-6 levels of `{ a: { b: { c: ... } } }` is
/// practically unreadable; 8 is the practical ceiling. The cap defends
/// against obfuscated bytecode synthesizing pathologically deep chains
/// that would otherwise drive the walker + emit into unbounded work.
const MAX_DESTRUCTURE_CHAIN_DEPTH: usize = 8;

/// Walk backward from `if_idx` to find the defaulting cluster's final-get
/// (`Assign { op: GetBy*, dst_reg == x_reg }`), then walk the `GetBy*`
/// ancestor chain to assemble the source object + destructure-pattern path.
///
/// Returns `(final_get_idx, source_varid_string, path)` on success, or
/// `None` if the walk halts before locating a GetBy* final-get.
///
/// `PhiAssign` and `LoadConstUndefined` stmts between the `If` and the
/// final-get are skipped (harmless non-cluster content). Anything else
/// interrupts the walk — the cluster isn't the expected marker shape.
///
/// Chain-walk termination rule: given a candidate chain-step whose obj
/// operand is defined by ANOTHER `GetBy*`, we ask whether that definer is
/// itself a chain-step (its obj is ALSO `GetBy*`-defined) or a source-fetch
/// (its obj is NOT `GetBy*`-defined — typically a `GetGlobalObject` Assign
/// or a PhiAssign from one). We absorb chain-steps; we stop at source-
/// fetches WITHOUT absorbing them, leaving the source-fetch's dst as the
/// destructure's source object (source = the GetByVal's obj operand, not
/// globalThis).
fn walk_back_chain(
    stmts: &[Stmt],
    if_idx: usize,
    x_reg: u32,
) -> Option<(usize, String, DestructurePath, Vec<usize>)> {
    let mut j = if_idx;
    while j > 0 {
        j = j.saturating_sub(1);
        let s = stmts.get(j)?;
        if matches!(s, Stmt::PhiAssign { .. }) {
            continue;
        }
        if let Stmt::Assign { op, .. } = s
            && op.name == "LoadConstUndefined"
        {
            continue;
        }
        if let Stmt::Assign { op, .. } = s
            && op.dst.map(|d| d.0) == Some(x_reg)
            && is_getby_op(op.name)
        {
            return walk_chain_from(stmts, j, op);
        }
        return None;
    }
    None
}

/// Build the destructure-pattern path from a final-get Assign, walking
/// back through the `GetBy*` ancestor chain. Depth-bounded by
/// `MAX_DESTRUCTURE_CHAIN_DEPTH` (walker returns the partial path at
/// the cap rather than failing — an 8-deep destructure still folds
/// correctly; a 9-deep one leaves the outermost level un-absorbed, which
/// falls back to the sequential emit for that step). This bounded-bypass
/// behavior is the defense against pathologically deep obfuscated chains.
fn walk_chain_from(
    stmts: &[Stmt],
    final_get_idx: usize,
    final_get_op: &super::ssa::SsaOp,
) -> Option<(usize, String, DestructurePath, Vec<usize>)> {
    let (obj_var, key) = extract_get_step(final_get_op)?;
    let mut source_var = obj_var;
    let mut path = DestructurePath::Leaf { key };
    // Intermediate chain steps absorbed into the path. Each was an Assign
    // whose dst, post-absorb, has a single consumer — the next chain-step
    // that we also absorbed. Verified before each absorb by the
    // `is_safe_to_drop` scan below; adversarial bytecode with a non-cluster
    // consumer of a chain-step dst halts the walk at that level rather
    // than leaving a dangling SSA reference.
    //
    // The source-fetch step (whose dst becomes the DestructureWithDefault's
    // `object` field) is NOT added here — it still has a real use (from
    // the new stmt) and must survive the fold.
    let mut absorbed_chain_idxs: Vec<usize> = Vec::new();

    // Cap at DEPTH - 1 Nested wraps so total path depth (Leaf + wraps) ≤
    // MAX_DESTRUCTURE_CHAIN_DEPTH.
    for _ in 0..MAX_DESTRUCTURE_CHAIN_DEPTH.saturating_sub(1) {
        let Some((parent_idx, parent_op)) = find_prior_getby(stmts, final_get_idx, source_var)
        else {
            break;
        };
        // Cycle defense: if the walker somehow re-encounters an already-
        // absorbed index (adversarial shape: two GetBy* Assigns with
        // reciprocally-pointing obj operands), halt rather than loop.
        // `drop_idxs` BTreeSet in the caller dedups, but early exit keeps
        // path depth honest.
        if absorbed_chain_idxs.contains(&parent_idx) {
            break;
        }
        // Malformed GetBy* operand layout halts the chain without losing
        // the accumulated path (vs `?` which would discard everything).
        let Some((parent_obj, parent_key)) = extract_get_step(parent_op) else {
            break;
        };
        // Chain-step vs source-fetch discriminator: if parent's obj is
        // ALSO defined by a `GetBy*`, parent is a chain-step candidate;
        // otherwise parent is a source-fetch (stop without absorbing, so
        // the current `source_var` stays as the destructure's source).
        if find_prior_getby(stmts, final_get_idx, parent_obj).is_none() {
            break;
        }
        // Safety gate for the drop: the chain-step's dst (which equals
        // the loop's current `source_var`) must have NO uses outside the
        // fold cluster. Expected-single-use is the SSA-well-formed case
        // (one consumer = the next chain-step we already absorbed, or
        // the final-get); adversarial shapes with another consumer halt
        // the walk here so the absorbed index stays live.
        if !is_safe_to_drop_chain_step(stmts, source_var, final_get_idx, &absorbed_chain_idxs) {
            break;
        }
        path = DestructurePath::Nested {
            key: parent_key,
            inner: Box::new(path),
        };
        source_var = parent_obj;
        absorbed_chain_idxs.push(parent_idx);
    }

    Some((
        final_get_idx,
        format!("{source_var}"),
        path,
        absorbed_chain_idxs,
    ))
}

/// Scan `stmts` for uses of `target` (SSA var) that would be invalidated
/// if the Assign defining it were dropped. Returns `true` iff every use
/// is either (a) inside the already-fold-committed region — the final-get
/// Assign at `final_get_idx`, the absorbed chain-step Assigns at
/// `absorbed`, or a `PhiAssign` (harmless self-copy post-coalesce) —
/// or (b) the chain-step Assign at `target`'s own definer (which is what
/// we're about to absorb).
///
/// If any other Stmt references `target` as an operand var or phi src,
/// the chain-step is unsafe to drop — `walk_chain_from` halts without
/// absorbing that level. This defends the fold against adversarial HBC
/// that stashes multiple consumers on an intermediate chain dst.
fn is_safe_to_drop_chain_step(
    stmts: &[Stmt],
    target: VarId,
    final_get_idx: usize,
    absorbed: &[usize],
) -> bool {
    let target_str = format!("{target}");
    for (idx, s) in stmts.iter().enumerate() {
        if idx == final_get_idx || absorbed.contains(&idx) {
            continue;
        }
        // The Assign that defines `target` is itself the chain-step
        // candidate — skip, it's about to be absorbed.
        if let Stmt::Assign { op, .. } = s
            && op.dst == Some(target)
        {
            continue;
        }
        // Scan operand Vars across Assign/Op operands, PhiAssign srcs,
        // Return/Throw vars, and If conditions. Any hit disqualifies the
        // drop.
        let hit = match s {
            Stmt::Assign { op, .. } | Stmt::Op(op) => op
                .operands
                .iter()
                .any(|o| matches!(o, SsaOperand::Var(v) if *v == target)),
            Stmt::PhiAssign { src, .. } => src.as_ref() == target_str.as_str(),
            Stmt::Return(Some(v)) | Stmt::Throw(v) => *v == target,
            Stmt::If { cond, .. } => cond_references_var(cond, target),
            _ => false,
        };
        if hit {
            return false;
        }
    }
    true
}

fn cond_references_var(cond: &Condition, target: VarId) -> bool {
    match cond {
        Condition::Truthy(v)
        | Condition::Falsy(v)
        | Condition::IsUndefined(v)
        | Condition::NotUndefined(v) => *v == target,
        Condition::Compare { left, right, .. } => *left == target || *right == target,
    }
}

/// Accepted `GetBy*` opcodes for destructure-pattern chain walks. Matches
/// the static-key (`GetById*`, `TryGetById*`) and computed-key (`GetByVal`)
/// forms produced by Hermes for property-access lowering.
fn is_getby_op(name: &str) -> bool {
    matches!(
        name,
        "GetByVal"
            | "GetByIdShort"
            | "GetById"
            | "GetByIdLong"
            | "TryGetByIdShort"
            | "TryGetById"
            | "TryGetByIdLong"
    )
}

/// Extract `(obj_var, key)` from a `GetBy*` op. Operand layout for
/// dst-bearing ops is `[DstPlaceholder, obj, ...]`; computed keys have
/// `operands[2] = Var(key)`, static keys have `operands.last() =
/// ResolvedString(prop)`.
fn extract_get_step(op: &super::ssa::SsaOp) -> Option<(VarId, DestructureKey)> {
    let SsaOperand::Var(obj) = op.operands.get(1)? else {
        return None;
    };
    if op.name == "GetByVal" {
        let SsaOperand::Var(key) = op.operands.get(2)? else {
            return None;
        };
        return Some((*obj, DestructureKey::Computed(format!("{key}"))));
    }
    if is_getby_op(op.name) {
        let SsaOperand::ResolvedString(name) = op.operands.last()? else {
            return None;
        };
        return Some((*obj, DestructureKey::Static(name.clone())));
    }
    None
}

/// Find the most recent `Stmt::Assign` before `upto_idx` whose `op.dst`
/// matches `target_var` exactly (full `VarId` match — reg + version) and
/// whose op is a `GetBy*`. Returns `(stmt_index, op)` or `None` if no such
/// Assign exists. Scanning in reverse; first hit wins.
fn find_prior_getby(
    stmts: &[Stmt],
    upto_idx: usize,
    target_var: VarId,
) -> Option<(usize, &super::ssa::SsaOp)> {
    let end = upto_idx.min(stmts.len());
    for i in (0..end).rev() {
        if let Stmt::Assign { op, .. } = &stmts[i]
            && op.dst == Some(target_var)
            && is_getby_op(op.name)
        {
            return Some((i, op));
        }
    }
    None
}

/// Walk forward from `if_idx` to find the `Op(PutBy*)` whose value operand
/// register matches `x_reg`; return `(put_idx, target_prop, receiver_varid)`.
///
/// Intervening `PhiAssign` stmts are skipped (the merge-point forwarders).
/// The receiver is the `PutBy*`'s operand 0 — typically a `globalThis`-var
/// at top-level scope. It's carried through to `DestructureWithDefault` so
/// the verifier use-tracker and inline-map counter don't undercount it
/// once the PutBy* itself is dropped on fold.
fn find_put_target(
    stmts: &[Stmt],
    if_idx: usize,
    x_reg: u32,
) -> Option<(usize, String, String)> {
    let mut j = if_idx.saturating_add(1);
    while j < stmts.len() {
        let s = stmts.get(j)?;
        match s {
            Stmt::PhiAssign { .. } => {
                j = j.saturating_add(1);
                continue;
            }
            Stmt::Op(op)
                if (op.name.starts_with("PutById") || op.name.starts_with("TryPutById"))
                    && matches!(op.operands.get(1), Some(SsaOperand::Var(v)) if v.0 == x_reg) =>
            {
                // PutBy* operand layout: [receiver, value, cache_idx, prop].
                let SsaOperand::Var(receiver_var) = op.operands.first()? else {
                    return None;
                };
                let prop = match op.operands.last()? {
                    SsaOperand::ResolvedString(s) => s.clone(),
                    _ => return None,
                };
                return Some((j, prop, format!("{receiver_var}")));
            }
            _ => return None,
        }
    }
    None
}

/// Recover try-catch blocks using structural info from the CFG exception handler table.
/// If exc_handlers is available, uses block_id on each Stmt to determine which
/// statements are inside try regions. Falls back to positional splitting at Catch ops.
pub(super) fn recover_try_catch(
    stmts: Vec<Stmt>,
    exc_handlers: &BTreeMap<BlockId, BlockId>,
) -> Vec<Stmt> {
    let mut excluded: std::collections::BTreeSet<BlockId> = std::collections::BTreeSet::new();
    recover_try_catch_inner(stmts, exc_handlers, &mut excluded)
}

/// Test-only probe: counts entries into `recover_try_catch_inner` so tests
/// can assert the handler-dense recursion path is exercised and bounded.
/// Linear in the number of try-region wraps produced; unbounded if the
/// `excluded`-set guard is broken. Not used on production paths.
#[cfg(test)]
pub(super) static RECOVER_TC_INNER_CALLS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// Inner worker. `excluded` holds catch_target ids that the current
/// recursion path has already wrapped — they shadow the corresponding
/// entries in `exc_handlers` so nested try regions don't re-fire on the
/// outer handler. Carrying the set by `&mut` (insert before recurse,
/// remove after) collapses what was a per-level full-`exc_handlers`
/// clone (O(K²) total work for K handlers) to O(log K) per level.
fn recover_try_catch_inner(
    stmts: Vec<Stmt>,
    exc_handlers: &BTreeMap<BlockId, BlockId>,
    excluded: &mut std::collections::BTreeSet<BlockId>,
) -> Vec<Stmt> {
    #[cfg(test)]
    RECOVER_TC_INNER_CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut result = Vec::with_capacity(stmts.len());

    // Find indices of Catch assignments
    let mut catch_indices = Vec::new();
    for (i, stmt) in stmts.iter().enumerate() {
        if let Stmt::Assign { op, .. } = stmt
            && op.name == "Catch"
        {
            catch_indices.push(i);
        }
    }

    if catch_indices.is_empty() {
        // No catches at this level — nothing to do (apply_deep handles children)
        return stmts;
    }

    // Structural recovery: use block_id + exc_handlers to identify try regions
    if !exc_handlers.is_empty() {
        // Pre-scan: find Catch statements that appear BEFORE their try region.
        // Only collect catch blocks whose handler target is referenced by
        // try-protected statements appearing AFTER the catch in the statement list.
        let catch_targets: std::collections::BTreeSet<BlockId> =
            exc_handlers.values().copied().collect();
        let mut catch_map: BTreeMap<BlockId, (String, Vec<Stmt>)> = BTreeMap::new();
        {
            let mut j = 0;
            while j < stmts.len() {
                if let Stmt::Assign {
                    op,
                    dst,
                    block_id: Some(bid),
                    ..
                } = &stmts[j]
                    && op.name == "Catch"
                    && catch_targets.contains(bid)
                {
                    // Check if any later statement has this block as its handler target
                    let has_try_after = stmts[j.saturating_add(1)..]
                        .iter()
                        .any(|s| get_stmt_handler(s, exc_handlers, excluded) == Some(*bid));
                    if !has_try_after {
                        // No try region follows — this catch block IS the main body
                        j = j.saturating_add(1);
                        continue;
                    }

                    let catch_var = dst.to_string();
                    let catch_block = *bid;
                    j = j.saturating_add(1);
                    let catch_start = j;
                    while j < stmts.len() {
                        let h = get_stmt_handler(&stmts[j], exc_handlers, excluded);
                        if h.is_some() && h != Some(catch_block) {
                            break;
                        }
                        if let Stmt::Assign { op, .. } = &stmts[j]
                            && op.name == "Catch"
                        {
                            break;
                        }
                        j = j.saturating_add(1);
                    }
                    catch_map.insert(catch_block, (catch_var, stmts[catch_start..j].to_vec()));
                } else {
                    j = j.saturating_add(1);
                }
            }
        }

        // Build set of statement indices that belong to pre-scanned catch blocks
        let mut catch_stmt_indices: std::collections::BTreeSet<usize> =
            std::collections::BTreeSet::new();
        if !catch_map.is_empty() {
            let mut j = 0;
            while j < stmts.len() {
                if let Stmt::Assign {
                    op,
                    block_id: Some(bid),
                    ..
                } = &stmts[j]
                    && op.name == "Catch"
                    && catch_map.contains_key(bid)
                {
                    catch_stmt_indices.insert(j);
                    j = j.saturating_add(1);
                    while j < stmts.len() {
                        let h = get_stmt_handler(&stmts[j], exc_handlers, excluded);
                        if h.is_some() && h != Some(*bid) {
                            break;
                        }
                        if let Stmt::Assign { op, .. } = &stmts[j]
                            && op.name == "Catch"
                        {
                            break;
                        }
                        catch_stmt_indices.insert(j);
                        j = j.saturating_add(1);
                    }
                } else {
                    j = j.saturating_add(1);
                }
            }
        }

        let mut i = 0;
        while i < stmts.len() {
            // Skip statements already collected in catch_map
            if catch_stmt_indices.contains(&i) {
                i = i.saturating_add(1);
                continue;
            }

            // Check if this statement's block has an exception handler
            let handler = get_stmt_handler(&stmts[i], exc_handlers, excluded);
            if let Some(catch_target) = handler {
                // Collect consecutive statements protected by the same handler
                let try_start = i;
                while i < stmts.len()
                    && get_stmt_handler(&stmts[i], exc_handlers, excluded) == Some(catch_target)
                {
                    i = i.saturating_add(1);
                }
                let try_body: Vec<Stmt> = stmts[try_start..i].to_vec();

                // Look up catch body from pre-scanned map, or from what follows
                let (catch_var, catch_body) =
                    if let Some((var, body)) = catch_map.remove(&catch_target) {
                        (var, body)
                    } else if i < stmts.len()
                        && let Stmt::Assign { op, dst, .. } = &stmts[i]
                        && op.name == "Catch"
                    {
                        let var = dst.to_string();
                        i = i.saturating_add(1);
                        let catch_start = i;
                        while i < stmts.len() {
                            let h = get_stmt_handler(&stmts[i], exc_handlers, excluded);
                            if h.is_some() && h != Some(catch_target) {
                                break;
                            }
                            if let Stmt::Assign { op, .. } = &stmts[i]
                                && op.name == "Catch"
                            {
                                break;
                            }
                            i = i.saturating_add(1);
                        }
                        (var, stmts[catch_start..i].to_vec())
                    } else {
                        ("err".to_string(), vec![])
                    };

                let was_inserted = excluded.insert(catch_target);
                let try_recursed = recover_try_catch_inner(try_body, exc_handlers, excluded);
                let catch_recursed = recover_try_catch_inner(catch_body, exc_handlers, excluded);
                if was_inserted {
                    excluded.remove(&catch_target);
                }
                result.push(Stmt::TryCatch {
                    try_body: try_recursed,
                    catch_var,
                    catch_body: catch_recursed,
                });
                continue;
            }

            // Not in a try region — emit as-is
            result.push(stmts[i].clone());
            i = i.saturating_add(1);
        }
        return result;
    }

    // Fallback: positional splitting at Catch ops (when no exc_handlers available)
    let mut i = 0;
    for &catch_idx in &catch_indices {
        let try_body: Vec<Stmt> = stmts[i..catch_idx].to_vec();

        let catch_var = if let Stmt::Assign { dst, .. } = &stmts[catch_idx] {
            dst.to_string()
        } else {
            "err".to_string()
        };

        let catch_end = catch_indices
            .iter()
            .find(|&&idx| idx > catch_idx)
            .copied()
            .unwrap_or(stmts.len());
        let catch_body: Vec<Stmt> = stmts[catch_idx.saturating_add(1)..catch_end].to_vec();

        if !try_body.is_empty() || !catch_body.is_empty() {
            result.push(Stmt::TryCatch {
                try_body,
                catch_var,
                catch_body,
            });
        }

        i = catch_end;
    }

    // Remaining statements after the last catch
    for stmt in stmts[i..].iter().cloned() {
        result.push(stmt);
    }

    result
}

/// Get the exception handler for a statement's source block, if any.
fn get_stmt_handler(
    stmt: &Stmt,
    exc_handlers: &BTreeMap<BlockId, BlockId>,
    excluded: &std::collections::BTreeSet<BlockId>,
) -> Option<BlockId> {
    match stmt {
        Stmt::Assign {
            block_id: Some(bid),
            ..
        } => {
            let target = exc_handlers.get(bid).copied()?;
            // Targets the current recursion path has already wrapped are
            // filtered out so nested try regions don't re-fire on outer
            // handlers. Equivalent to the old `inner_handlers.retain(|_, t|
            // *t != catch_target)` scheme but without the per-level clone.
            if excluded.contains(&target) {
                None
            } else {
                Some(target)
            }
        }
        _ => None,
    }
}

/// Strip Hermes runtime TDZ / const-reassignment traps.
///
/// `hermesc` emits `CallBuiltin throwTypeError N` (builtin id 44) and
/// `CallBuiltin throwReferenceError N` (id 45) as runtime sentinels for
/// strict-mode TDZ violations and `const` reassignment. They surface as
/// either:
///   1. A bare `Stmt::Op(CallBuiltin throwTypeError, …)` at statement
///      position, or
///   2. The else-branch of an `if (binding) {} else { throwTypeError }`
///      generated by class / closure-slot initialization checks.
///
/// Both shapes are runtime artifacts of bytecode-level checks the source
/// program never wrote. Drop them. After dropping, an `If` whose then *and*
/// else are both empty collapses to nothing as well.
pub(super) fn strip_tdz_traps(stmts: Vec<Stmt>) -> Vec<Stmt> {
    // Two passes: first drops the bare CallBuiltin stmts, second collapses
    // any `If` whose then *and* else are now both empty. apply_deep is
    // top-down, so the parent If's empty-check happens before its children
    // get drained — running twice closes the gap without restructuring.
    let once = apply_deep(stmts, &strip_tdz_one_level);
    apply_deep(once, &strip_tdz_one_level)
}

fn is_tdz_trap_op(op_name: &str, ops: &[SsaOperand]) -> bool {
    if op_name != "CallBuiltin" && op_name != "CallBuiltinLong" {
        return false;
    }
    matches!(ops.get(1), Some(SsaOperand::Const(44 | 45)))
}

fn strip_tdz_one_level(stmts: Vec<Stmt>) -> Vec<Stmt> {
    let mut out: Vec<Stmt> = Vec::with_capacity(stmts.len());
    for stmt in stmts {
        match stmt {
            Stmt::Assign { ref op, .. } if is_tdz_trap_op(op.name, &op.operands) => {
                continue;
            }
            Stmt::Op(ref op) if is_tdz_trap_op(op.name, &op.operands) => {
                continue;
            }
            Stmt::If {
                cond,
                then_body,
                else_body,
            } => {
                if then_body.is_empty() && else_body.is_empty() {
                    continue;
                }
                out.push(Stmt::If {
                    cond,
                    then_body,
                    else_body,
                });
            }
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod regression_tests {
    //! Regression fixtures for sugar-pass bugs.
    //!
    //! Each test constructs the minimal AST shape that triggers the
    //! bug and asserts termination + bounded work. Real-world
    //! decompile coverage across actual HBC files lives in
    //! `droidsaw-bench`.
    use super::*;
    use crate::decompile::ssa::VarId;
    use crate::decompile::structure::{Condition, Stmt};
    use std::cell::Cell;

    fn vid() -> VarId {
        VarId(0, 0)
    }

    /// Trivial leaf Stmt that doesn't pull in SsaOp construction
    /// machinery. Sufficient for exercising apply_deep / recover_try_catch
    /// AST traversal — these passes don't inspect Comment payload.
    fn leaf() -> Stmt {
        Stmt::Comment("test".into())
    }

    /// Bug #2: pre-order `apply_deep`
    /// re-descended into newly-created child bodies. With a rewrite
    /// that wraps in `TryCatch` (e.g. `recover_try_catch` reacting to
    /// remaining handlers), each visit produced a deeper TryCatch that
    /// got revisited — infinite wrapping. The original recursive
    /// `rewrite_children` masked this with stack overflow at ~24
    /// frames; the iterative replacement removed the bound and made
    /// the explosion observable.
    ///
    /// Fix: post-order — children are rewritten before the parent body
    /// is rewritten, so newly-created sub-bodies in the parent rewrite
    /// are NOT revisited.
    #[test]
    fn apply_deep_does_not_revisit_newly_created_bodies() {
        // Rewrite that always wraps non-empty bodies in another TryCatch.
        // If apply_deep re-visited the newly-created try_body, this
        // would wrap forever and the test would hang or OOM.
        let call_count = Cell::new(0usize);
        let rewrite = |stmts: Vec<Stmt>| -> Vec<Stmt> {
            call_count.set(call_count.get() + 1);
            if stmts.is_empty() {
                stmts
            } else {
                vec![Stmt::TryCatch {
                    try_body: stmts,
                    catch_var: "e".into(),
                    catch_body: vec![],
                }]
            }
        };

        // Input: 3 leaf stmts at root (no child bodies). apply_deep
        // visits exactly 1 body (the root).
        let input: Vec<Stmt> = (0..3).map(|_| leaf()).collect();

        let _result = apply_deep(input, &rewrite);

        // Hard upper bound: post-order visits exactly 1 body in this
        // input (the root has no container children). Pre-order would
        // visit unbounded times. Allow a small slack for safety.
        assert!(
            call_count.get() <= 4,
            "apply_deep called rewrite {} times — newly-created TryCatch bodies are being revisited",
            call_count.get()
        );
    }

    /// Defence-in-depth: a tree with a real container (If) calls
    /// rewrite once per body in the input, not per body in the output.
    #[test]
    fn apply_deep_calls_rewrite_per_input_body_only() {
        let call_count = Cell::new(0usize);
        let rewrite = |stmts: Vec<Stmt>| -> Vec<Stmt> {
            call_count.set(call_count.get() + 1);
            stmts
        };

        // Input: If with two child bodies (then + else), each empty.
        // 3 bodies total: root, then_body, else_body.
        let input = vec![Stmt::If {
            cond: Condition::Truthy(vid()),
            then_body: vec![],
            else_body: vec![],
        }];

        let _ = apply_deep(input, &rewrite);

        assert_eq!(
            call_count.get(),
            3,
            "apply_deep should rewrite each of {{root, then_body, else_body}} exactly once"
        );
    }

    /// Bug #2b (hang in `recover_try_catch` from quadratic clone work):
    /// `recover_try_catch` cloned the full `exc_handlers` BTreeMap on
    /// every recursion level (`let mut inner_handlers = exc_handlers.clone();
    /// inner_handlers.retain(...)`). For a function with K handlers,
    /// total clone work was O(K²); combined with apply_deep visiting
    /// each TryCatch's children, the call tree exploded to ~8.8M
    /// invocations on a 23-stmt body.
    ///
    /// Fix: `excluded: &mut BTreeSet<BlockId>` passed by mutable ref;
    /// insert before recursion, remove after. O(log K) per level.
    /// `get_stmt_handler` filters out excluded targets on the inner
    /// recursion so nested try regions don't re-fire on outer handlers.
    ///
    /// Test shape: 50 stmts all tagged with a block_id that maps to
    /// the same catch target, plus one Catch stmt in the middle. The
    /// outer wrap collects all 50 into one try_body and recurses. With
    /// the `excluded` guard, the recursion sees every stmt as
    /// already-wrapped (handler filtered to None) and returns after
    /// one extra level. Without the guard, the recursion re-sees the
    /// same handler on the same stmts and wraps again, unbounded —
    /// the mutation-test (see commit message) confirms a stack
    /// overflow on that path.
    #[test]
    fn recover_try_catch_terminates_on_handler_dense_input() {
        use crate::decompile::cfg::BlockId;
        use crate::decompile::decode::DecodedInst;
        use crate::decompile::ssa::SsaOp;
        use crate::opcodes::OpCode;
        use std::sync::atomic::Ordering;

        fn stub_inst(name: &'static str, op: OpCode) -> DecodedInst {
            DecodedInst {
                offset: 0,
                size: 0,
                opcode: 0,
                name,
                op,
                operands: Vec::new(),
                op_types: &[],
            }
        }

        fn assign(block: BlockId, op_name: &'static str, op: OpCode) -> Stmt {
            Stmt::Assign {
                dst: "t".into(),
                op: SsaOp {
                    name: op_name,
                    op,
                    dst: None,
                    operands: Vec::new(),
                    original: stub_inst(op_name, op),
                },
                block_id: Some(block),
            }
        }

        // 50 protected blocks all share one catch target. This
        // concentrates the dense-handler work in a single try region
        // so the outer wrap's try_body contains every stmt, forcing
        // the recursion to either (a) see the handler as `excluded`
        // and terminate, or (b) re-wrap ad infinitum under a broken
        // guard.
        const K: u32 = 50;
        const CATCH_TARGET: BlockId = 100;
        let mut handlers: BTreeMap<BlockId, BlockId> = BTreeMap::new();
        for i in 0..K {
            handlers.insert(i, CATCH_TARGET);
        }

        // 50 Assign stmts carrying a block_id that IS a key in
        // `handlers`, so `get_stmt_handler` returns Some(100) and
        // drives the handler-consultation branch. One Catch stmt is
        // placed mid-list so the recursion's `catch_indices` is
        // non-empty — without this, the recursion returns early at
        // line ~1090 and the bug (re-wrapping) would be masked.
        let mut stmts: Vec<Stmt> = Vec::new();
        for i in 0..K {
            if i == K / 2 {
                stmts.push(assign(i, "Catch", OpCode::Catch));
            } else {
                stmts.push(assign(i, "Add", OpCode::Add));
            }
        }

        RECOVER_TC_INNER_CALLS.store(0, Ordering::Relaxed);
        let result = recover_try_catch(stmts, &handlers);
        let call_count = RECOVER_TC_INNER_CALLS.load(Ordering::Relaxed);

        // The handler-consultation branch was taken: output is a
        // single TryCatch wrapping all the protected stmts (plus the
        // Catch stmt inside try_body). The original test had zero
        // TryCatch in the output because `Comment` leaves skipped the
        // whole branch.
        let try_catch_count = result
            .iter()
            .filter(|s| matches!(s, Stmt::TryCatch { .. }))
            .count();
        assert!(
            try_catch_count >= 1,
            "expected at least one TryCatch in output (handler branch taken); got 0 — \
             handler-dense recursion path was not exercised"
        );

        // The `excluded` guard bounds the recursion: outer call wraps
        // once, inner call sees excluded and returns. Total calls
        // should be small (≤ 4 covers outer + try recursion + catch
        // recursion + slack). An unbounded recursion would either
        // stack-overflow (test aborts) or blow past this bound.
        assert!(
            call_count <= 8,
            "recover_try_catch_inner called {call_count} times — expected O(1) for \
             this shape; unbounded recursion on broken `excluded` guard"
        );
    }

    // ----- Defaulted-destructuring recovery tests -----
    //
    // These cover the `recover_destructuring_with_default` sugar pass
    // (fixture: destructuring_default_computed/object_pattern). The marker
    // is `GetByVal + LoadConstUndefined + If(IsUndefined) + Assign(LoadConst*
    // default) + PutBy*` in a 6-stmt cluster. The pass folds the cluster
    // into a single `Stmt::DestructureWithDefault`.
    //
    // Positive test (`recover_destructure_with_default_folds_marker_cluster`):
    // the cluster reconstructs as expected. Negative test
    // (`recover_destructure_with_default_leaves_unmarked_gets_alone`): adjacent
    // `GetBy*` Assigns without the undef-marker If are left unchanged — this
    // is the load-bearing false-positive gate.

    use crate::decompile::decode::DecodedInst;
    use crate::decompile::ssa::SsaOp;
    use crate::opcodes::OpCode;

    fn stub_inst_for_dst(name: &'static str, op: OpCode) -> DecodedInst {
        DecodedInst {
            offset: 0,
            size: 0,
            opcode: 0,
            name,
            op,
            operands: Vec::new(),
            op_types: &[],
        }
    }

    fn ssa_assign(
        dst: VarId,
        name: &'static str,
        op: OpCode,
        operands: Vec<SsaOperand>,
    ) -> Stmt {
        Stmt::Assign {
            dst: std::rc::Rc::from(format!("{dst}")),
            op: SsaOp {
                name,
                op,
                dst: Some(dst),
                operands,
                original: stub_inst_for_dst(name, op),
            },
            block_id: None,
        }
    }

    fn ssa_op(name: &'static str, op: OpCode, operands: Vec<SsaOperand>) -> Stmt {
        Stmt::Op(SsaOp {
            name,
            op,
            dst: None,
            operands,
            original: stub_inst_for_dst(name, op),
        })
    }

    #[test]
    fn recover_destructure_with_default_folds_marker_cluster() {
        // Stmt sequence mirrors the destructuring_default_computed fixture's
        // case-1 shape (see find_final_get doc-comment):
        //   r4_3 = GetByIdShort(globalThis, "obj")       ← obj read (unmatched)
        //   r3_4 = GetByIdShort(globalThis, "key")       ← key read (unmatched)
        //   r3_5 = GetByVal(r4_3, r3_4)                  ← final-get (matched)
        //   r1_6 = LoadConstUndefined                     ← undef source
        //   if (r3_5 === r1_6) { r3_7 = LoadConstUInt8(99) }
        //   PutByIdLoose(globalThis, r3_5-or-phi, "val")
        //
        // Simplified: single var IDs; omit the intermediate "globalThis.obj"
        // read (the detector doesn't consult it, only the GetByVal anchor).
        let globalthis = VarId(2, 0);
        let obj_v = VarId(4, 3);
        let key_v = VarId(3, 4);
        let x_v = VarId(3, 5); // GetByVal dst
        let u_v = VarId(1, 6); // LoadConstUndefined dst
        let default_v = VarId(3, 7);

        let stmts = vec![
            ssa_assign(
                x_v,
                "GetByVal",
                OpCode::GetByVal,
                vec![
                    SsaOperand::DstPlaceholder,
                    SsaOperand::Var(obj_v),
                    SsaOperand::Var(key_v),
                ],
            ),
            ssa_assign(
                u_v,
                "LoadConstUndefined",
                OpCode::LoadConstUndefined,
                vec![SsaOperand::DstPlaceholder],
            ),
            Stmt::If {
                cond: Condition::Compare {
                    op: "===",
                    left: x_v,
                    right: u_v,
                },
                then_body: vec![ssa_assign(
                    default_v,
                    "LoadConstUInt8",
                    OpCode::LoadConstUInt8,
                    vec![SsaOperand::DstPlaceholder, SsaOperand::Const(99)],
                )],
                else_body: vec![],
            },
            ssa_op(
                "PutByIdLoose",
                OpCode::PutByIdLoose,
                vec![
                    SsaOperand::Var(globalthis),
                    SsaOperand::Var(x_v),
                    SsaOperand::Const(0),
                    SsaOperand::ResolvedString("val".into()),
                ],
            ),
        ];

        let folded = recover_destructuring_with_default_one_level(stmts);
        assert_eq!(
            folded.len(),
            2,
            "expected marker cluster to fold to 1 DestructureWithDefault + retain \
             the LoadConstUndefined Assign; got {folded:?}"
        );
        let (target, default, target_receiver, path) = folded
            .iter()
            .find_map(|s| match s {
                Stmt::DestructureWithDefault {
                    target,
                    default,
                    target_receiver,
                    path,
                    ..
                } => Some((
                    target.clone(),
                    default.clone(),
                    target_receiver.clone(),
                    path.clone(),
                )),
                _ => None,
            })
            .expect("DestructureWithDefault missing from output");
        assert_eq!(target, "val");
        assert_eq!(default, "99");
        assert_eq!(
            target_receiver, "r2_0",
            "receiver must carry the consumed PutBy*'s operand-0 var \
             (format {{VarId}})"
        );
        // Flat computed-key case shapes as `Leaf(Computed(<key-varid>))`.
        match path {
            DestructurePath::Leaf {
                key: DestructureKey::Computed(v),
            } => assert_eq!(v, "r3_4", "computed-key leaf carries the key's VarId string"),
            other => panic!("expected Leaf(Computed(...)), got {other:?}"),
        }
    }

    #[test]
    fn recover_destructure_with_default_leaves_unmarked_gets_alone() {
        // Two adjacent GetByVal Assigns with no intervening If — false-positive
        // gate. The detector must NOT fold these into a DestructureWithDefault.
        let obj = VarId(4, 0);
        let key1 = VarId(3, 0);
        let key2 = VarId(3, 1);
        let dst1 = VarId(5, 0);
        let dst2 = VarId(5, 1);

        let stmts = vec![
            ssa_assign(
                dst1,
                "GetByVal",
                OpCode::GetByVal,
                vec![
                    SsaOperand::DstPlaceholder,
                    SsaOperand::Var(obj),
                    SsaOperand::Var(key1),
                ],
            ),
            ssa_assign(
                dst2,
                "GetByVal",
                OpCode::GetByVal,
                vec![
                    SsaOperand::DstPlaceholder,
                    SsaOperand::Var(obj),
                    SsaOperand::Var(key2),
                ],
            ),
            ssa_op(
                "PutByIdLoose",
                OpCode::PutByIdLoose,
                vec![
                    SsaOperand::Var(obj),
                    SsaOperand::Var(dst2),
                    SsaOperand::Const(0),
                    SsaOperand::ResolvedString("out".into()),
                ],
            ),
        ];

        let out = recover_destructuring_with_default_one_level(stmts.clone());
        assert_eq!(
            out.len(),
            stmts.len(),
            "marker-absent input must be returned unchanged"
        );
        assert!(
            !out.iter().any(|s| matches!(s, Stmt::DestructureWithDefault { .. })),
            "no DestructureWithDefault may appear without the If undef-marker; got {out:?}"
        );
    }

    /// Build a nested static-chain cluster. `chain_keys` is outermost-
    /// first (same order as source-level), e.g. `["outer", "inner"]` for
    /// `{ outer: { inner: target = default } } = source`. Registers are
    /// deterministic: `src_reg = 2`, each chain step uses reg=3 with a
    /// distinct version (source-fetch at version 0; step i at version i+1;
    /// final-get dst also reg=3).
    #[allow(clippy::arithmetic_side_effects)] // test helper; inputs are small ints
    fn build_nested_chain_cluster(chain_keys: &[&str]) -> (Vec<Stmt>, u32) {
        assert!(
            !chain_keys.is_empty(),
            "chain must have at least one key (outermost == final)"
        );
        let globalthis = VarId(2, 0);
        // Root: `r3_0 = globalThis.<chain_keys[0]>` — the source-fetch.
        // Then each subsequent key walks r3_i = r3_{i-1}.<key_i>.
        let mut stmts: Vec<Stmt> = Vec::new();
        let mut prev = globalthis;
        for (i, key) in chain_keys.iter().enumerate() {
            let dst = VarId(3, i as u32);
            stmts.push(ssa_assign(
                dst,
                "GetByIdShort",
                OpCode::GetByIdShort,
                vec![
                    SsaOperand::DstPlaceholder,
                    SsaOperand::Var(prev),
                    SsaOperand::Const(0),
                    SsaOperand::ResolvedString((*key).into()),
                ],
            ));
            prev = dst;
        }
        let final_get_reg = 3u32;
        let final_dst = prev;
        let u_v = VarId(1, 0);
        stmts.push(ssa_assign(
            u_v,
            "LoadConstUndefined",
            OpCode::LoadConstUndefined,
            vec![SsaOperand::DstPlaceholder],
        ));
        let default_dst = VarId(3, chain_keys.len() as u32);
        stmts.push(Stmt::If {
            cond: Condition::Compare {
                op: "===",
                left: final_dst,
                right: u_v,
            },
            then_body: vec![ssa_assign(
                default_dst,
                "LoadConstZero",
                OpCode::LoadConstZero,
                vec![SsaOperand::DstPlaceholder],
            )],
            else_body: vec![],
        });
        stmts.push(ssa_op(
            "PutByIdLoose",
            OpCode::PutByIdLoose,
            vec![
                SsaOperand::Var(globalthis),
                SsaOperand::Var(final_dst),
                SsaOperand::Const(0),
                SsaOperand::ResolvedString("renamed".into()),
            ],
        ));
        (stmts, final_get_reg)
    }

    #[test]
    fn recover_destructure_with_default_folds_two_level_static_chain() {
        // Mirrors fixture case 3: `var { outer: { inner: renamed = 0 } } = data;`.
        // Chain steps (outermost first): `data`, `outer`, `inner`. The
        // source-fetch is the `data` step; pattern-path covers `outer` +
        // `inner`. Expected path after fold: Nested(Static("outer"),
        // Leaf(Static("inner"))); source_var resolves to the data-fetch's
        // dst (r3_0 per build_nested_chain_cluster's numbering).
        let (stmts, _) = build_nested_chain_cluster(&["data", "outer", "inner"]);
        let folded = recover_destructuring_with_default_one_level(stmts);

        let (source, target, default, path) = folded
            .iter()
            .find_map(|s| match s {
                Stmt::DestructureWithDefault {
                    object,
                    target,
                    default,
                    path,
                    ..
                } => Some((object.clone(), target.clone(), default.clone(), path.clone())),
                _ => None,
            })
            .expect("DestructureWithDefault missing from nested-chain fold");
        assert_eq!(target, "renamed");
        assert_eq!(default, "0");
        // Source is the dst of the source-fetch step (the `data` lookup),
        // which is `r3_0` under the helper's register numbering.
        assert_eq!(source, "r3_0");
        // Path must reconstruct outer→inner nesting.
        match path {
            DestructurePath::Nested {
                key: DestructureKey::Static(outer_name),
                inner,
            } => {
                assert_eq!(outer_name, "outer");
                match *inner {
                    DestructurePath::Leaf {
                        key: DestructureKey::Static(inner_name),
                    } => assert_eq!(inner_name, "inner"),
                    other => panic!("expected Leaf(Static('inner')), got {other:?}"),
                }
            }
            other => panic!("expected Nested(Static('outer'), Leaf(Static('inner'))), got {other:?}"),
        }
    }

    #[test]
    fn recover_destructure_with_default_halts_absorb_on_extra_consumer() {
        // Adversarial shape: an intermediate chain-step's dst is
        // consumed by a non-cluster
        // stmt. The walker must NOT absorb that step (dropping it would
        // leave the extra consumer with a dangling SSA reference); the
        // fold should degrade to a shallower path or bail entirely, but
        // NOT silently corrupt the stmt list.
        //
        // Shape built below: `{ outer: { inner: renamed = 0 } } = data`
        // chain PLUS an extra `r3_8 = r3_28.other` stmt between the
        // outer step and the inner final-get — r3_28 (the outer step's
        // dst) now has 2 consumers: the final-get AND the r3_8 side-
        // branch.
        let globalthis = VarId(2, 0);
        let data_dst = VarId(3, 27);
        let outer_dst = VarId(3, 28);
        let inner_dst = VarId(3, 29);
        let side_dst = VarId(3, 99);
        let u_v = VarId(1, 0);
        let default_dst = VarId(3, 50);

        let stmts = vec![
            ssa_assign(
                data_dst,
                "GetByIdShort",
                OpCode::GetByIdShort,
                vec![
                    SsaOperand::DstPlaceholder,
                    SsaOperand::Var(globalthis),
                    SsaOperand::Const(0),
                    SsaOperand::ResolvedString("data".into()),
                ],
            ),
            ssa_assign(
                outer_dst,
                "GetByIdShort",
                OpCode::GetByIdShort,
                vec![
                    SsaOperand::DstPlaceholder,
                    SsaOperand::Var(data_dst),
                    SsaOperand::Const(0),
                    SsaOperand::ResolvedString("outer".into()),
                ],
            ),
            // Extra consumer of outer_dst — NOT part of the cluster.
            ssa_assign(
                side_dst,
                "GetByIdShort",
                OpCode::GetByIdShort,
                vec![
                    SsaOperand::DstPlaceholder,
                    SsaOperand::Var(outer_dst),
                    SsaOperand::Const(0),
                    SsaOperand::ResolvedString("other".into()),
                ],
            ),
            ssa_assign(
                inner_dst,
                "GetByIdShort",
                OpCode::GetByIdShort,
                vec![
                    SsaOperand::DstPlaceholder,
                    SsaOperand::Var(outer_dst),
                    SsaOperand::Const(0),
                    SsaOperand::ResolvedString("inner".into()),
                ],
            ),
            ssa_assign(
                u_v,
                "LoadConstUndefined",
                OpCode::LoadConstUndefined,
                vec![SsaOperand::DstPlaceholder],
            ),
            Stmt::If {
                cond: Condition::Compare {
                    op: "===",
                    left: inner_dst,
                    right: u_v,
                },
                then_body: vec![ssa_assign(
                    default_dst,
                    "LoadConstZero",
                    OpCode::LoadConstZero,
                    vec![SsaOperand::DstPlaceholder],
                )],
                else_body: vec![],
            },
            ssa_op(
                "PutByIdLoose",
                OpCode::PutByIdLoose,
                vec![
                    SsaOperand::Var(globalthis),
                    SsaOperand::Var(inner_dst),
                    SsaOperand::Const(0),
                    SsaOperand::ResolvedString("renamed".into()),
                ],
            ),
        ];

        let folded = recover_destructuring_with_default_one_level(stmts);

        // outer_dst's defining Assign (index 1 pre-fold) MUST survive the
        // fold so the side_dst = outer_dst.other consumer keeps a valid
        // src. The inner final-get + If + PutBy* still fold, but the path
        // degrades to `Leaf(Static("inner"))` with source = outer_dst
        // (not a Nested path reaching data_dst).
        let outer_dst_still_defined = folded.iter().any(|s| matches!(
            s,
            Stmt::Assign { op, .. } if op.dst == Some(outer_dst)
        ));
        assert!(
            outer_dst_still_defined,
            "adversarial consumer of outer_dst must prevent its absorption; \
             got folded stmts that dropped it:\n{folded:?}"
        );

        let path = folded
            .iter()
            .find_map(|s| match s {
                Stmt::DestructureWithDefault { path, .. } => Some(path.clone()),
                _ => None,
            })
            .expect("inner-only fold should still produce a DestructureWithDefault");
        // Degradation check: the path is a bare Leaf (no Nested wrappers)
        // because the walker halted at the outer-step absorb.
        assert!(
            matches!(path, DestructurePath::Leaf { .. }),
            "walker should degrade to Leaf when a chain-step has extra \
             consumers; got {path:?}"
        );
    }

    #[test]
    fn recover_destructure_with_default_bounds_chain_walk_at_depth_eight() {
        // Pathological-depth test: a chain of 10 static-key steps (9 pattern
        // levels + 1 source-fetch). The walker's MAX_DESTRUCTURE_CHAIN_DEPTH
        // = 8 cap means at most 8 levels absorb into the path; the outermost
        // pattern level (step 1 in outer-first order) is left as a
        // sequential GetBy* rather than a Nested wrapper. The fold still
        // succeeds — the cap guarantees bounded work, not all-or-nothing.
        //
        // This test's purpose: prove the cap is enforced. If the walker
        // went unbounded on deep chains, adversarial HBC could drive it
        // into pathological work.
        let keys = [
            "lvl0", "lvl1", "lvl2", "lvl3", "lvl4", "lvl5", "lvl6", "lvl7", "lvl8", "lvl9",
        ];
        let (stmts, _) = build_nested_chain_cluster(&keys);
        let folded = recover_destructuring_with_default_one_level(stmts);
        let path = folded
            .iter()
            .find_map(|s| match s {
                Stmt::DestructureWithDefault { path, .. } => Some(path.clone()),
                _ => None,
            })
            .expect("DestructureWithDefault present even at cap depth");
        // Count Nested wrappers in the path; cap allows ≤ MAX-1 Nested +
        // 1 Leaf = up to 8 levels.
        fn depth(p: &DestructurePath) -> usize {
            match p {
                DestructurePath::Leaf { .. } => 1,
                DestructurePath::Nested { inner, .. } => 1usize.saturating_add(depth(inner)),
            }
        }
        let d = depth(&path);
        assert!(
            d <= MAX_DESTRUCTURE_CHAIN_DEPTH,
            "chain-walk absorbed {d} levels; cap is {MAX_DESTRUCTURE_CHAIN_DEPTH}"
        );
    }
}
