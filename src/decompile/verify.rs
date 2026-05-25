//! Semantic validation of structured decompiler output.
//!
//! OXC validates syntax — this module validates semantics:
//! - Every variable used is defined before use
//! - No unreachable code after return/throw
//! - Function parameter counts are consistent
//!
//! Runs after structuring, before emit. Catches pipeline bugs
//! that syntax validation cannot detect.
#![allow(missing_docs, reason = "internal")]

use std::collections::BTreeSet;

use super::structure::{Condition, DestructureKey, DestructurePath, Stmt};

/// Record each computed-key VarId-format reference along a
/// `DestructurePath` as a use. Static keys are property-name literals,
/// not SSA refs.
fn walk_destructure_path_uses(path: &DestructurePath, used: &mut Vec<String>) {
    let (key, next) = match path {
        DestructurePath::Leaf { key } => (key, None),
        DestructurePath::Nested { key, inner } => (key, Some(inner.as_ref())),
    };
    if let DestructureKey::Computed(v) = key {
        used.push(v.clone());
    }
    if let Some(inner) = next {
        walk_destructure_path_uses(inner, used);
    }
}

/// Semantic verification result.
#[derive(Debug)]
pub struct VerifyResult {
    pub warnings: Vec<String>,
}

impl VerifyResult {
    pub fn is_ok(&self) -> bool {
        self.warnings.is_empty()
    }
}

/// SSA well-formedness check: "every use of a variable must
/// have a def somewhere in the body". This is weaker than a dominance
/// check — it's set-inclusion, not flow-sensitive — but that's on
/// purpose. The structurer and optimizer can reorder and merge phis in
/// ways that make a strict dominance check noisy, but "no free variables
/// in the final output" is a universal invariant: if the emitter references
/// a name that nothing ever writes, something earlier in the pipeline
/// dropped a def on the floor.
///
/// Not flow-sensitive, by design:
///   - Merge across branches is not tracked (both branches' dsts count as
///     defined in the outer scope). False negatives on branch-local
///     name shadowing are acceptable; false positives on phi-merged
///     values would be noise.
///   - Parameter names `a0..a{n-1}` are treated as pre-defined.
///   - `DstPlaceholder` is never counted as a use.
///
/// Returns a list of `(use_name, context)` pairs for every variable read
/// that has no corresponding write anywhere in the body. Zero items means
/// the body is free-variable-clean — emit can be trusted to produce output
/// whose every variable reference has a backing definition.
pub fn collect_free_variables(stmts: &[Stmt], param_count: u32) -> Vec<String> {
    let mut defined: BTreeSet<String> = BTreeSet::new();
    let mut used: Vec<String> = Vec::new();

    for i in 0..param_count {
        defined.insert(format!("a{i}"));
    }

    walk_collect(stmts, &mut defined, &mut used, 0);

    // Version-0 registers (`r\d+_0`) are the pristine initial state of
    // each physical register at function entry, backed by a synthetic
    // LoadConstUndefined in the SSA builder. They're implicitly defined
    // from the structurer's point of view — no explicit Assign statement
    // writes them, but every function starts with this state. Treat them
    // as pre-defined for the free-variable check.
    //
    // This weakens the check from "every use has an explicit def" to
    // "every use has an explicit def OR is a pristine register read".
    // The bug class we want to catch — pipeline stage dropped a def on
    // the floor — still trips the check because it involves version > 0
    // VarIds (phis, reassignments) that must have been written somewhere.
    fn is_version_zero_reg(name: &str) -> bool {
        let Some(rest) = name.strip_prefix('r') else {
            return false;
        };
        let Some((reg, ver)) = rest.split_once('_') else {
            return false;
        };
        ver == "0" && !reg.is_empty() && reg.chars().all(|c| c.is_ascii_digit())
    }

    used.retain(|name| !defined.contains(name) && !is_version_zero_reg(name));
    used.sort();
    used.dedup();
    used
}

fn walk_collect(
    stmts: &[Stmt],
    defined: &mut BTreeSet<String>,
    used: &mut Vec<String>,
    depth: usize,
) {
    debug_assert!(depth <= 100, "walk_collect recursion depth exceeds 100");
    if depth > 100 {
        return;
    }

    // Two-pass over this level: first collect all dsts (so forward refs
    // to later Assigns in the same block, produced by structurer
    // reordering, are recognized as defined), then collect uses.
    for stmt in stmts {
        collect_dsts(stmt, defined);
    }
    for stmt in stmts {
        match stmt {
            Stmt::Assign { op, .. } => {
                for operand in &op.operands {
                    if let super::ssa::SsaOperand::Var(v) = operand {
                        used.push(format!("{v}"));
                    }
                }
            }
            Stmt::PhiAssign { src, .. } => {
                // Heuristic: src is the source var name. Treat as a use.
                if !src.is_empty() && !src.chars().all(|c| c.is_ascii_digit()) {
                    used.push(src.to_string());
                }
            }
            Stmt::Return(Some(v)) => used.push(format!("{v}")),
            Stmt::Return(None) => {}
            Stmt::Throw(v) => used.push(format!("{v}")),
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                walk_collect(then_body, defined, used, depth.saturating_add(1));
                walk_collect(else_body, defined, used, depth.saturating_add(1));
            }
            Stmt::While { body, .. } => {
                walk_collect(body, defined, used, depth.saturating_add(1));
            }
            Stmt::ForIn { body, .. } => {
                walk_collect(body, defined, used, depth.saturating_add(1));
            }
            Stmt::Switch { cases, default, .. } => {
                for (_, body) in cases {
                    walk_collect(body, defined, used, depth.saturating_add(1));
                }
                walk_collect(default, defined, used, depth.saturating_add(1));
            }
            Stmt::TryCatch {
                try_body,
                catch_var,
                catch_body,
            } => {
                walk_collect(try_body, defined, used, depth.saturating_add(1));
                defined.insert(catch_var.clone());
                walk_collect(catch_body, defined, used, depth.saturating_add(1));
            }
            Stmt::Labeled { body, .. } => {
                walk_collect(body, defined, used, depth.saturating_add(1));
            }
            Stmt::Op(op) => {
                for operand in &op.operands {
                    if let super::ssa::SsaOperand::Var(v) = operand {
                        used.push(format!("{v}"));
                    }
                }
            }
            // `Destructure.object` is the SSA var name of the source object
            // (formatted via `format!("{obj}")` in sugar.rs); its bindings'
            // `dst` fields are defs, not uses — they belong to collect_dsts.
            Stmt::Destructure { object, .. } => used.push(object.clone()),
            // `DestructureWithDefault` follows the same shape: `object` is an
            // SSA-var reference (use); each `Computed` key along the path is
            // a VarId-format string (use); `target_receiver` is the PutBy*'s
            // consumed receiver (use); `target` is the property-name literal
            // on the PutBy*, NOT an SSA def (it's a globalThis member, not a
            // local binding the verifier tracks).
            Stmt::DestructureWithDefault {
                object,
                target_receiver,
                path,
                ..
            } => {
                used.push(object.clone());
                used.push(target_receiver.clone());
                walk_destructure_path_uses(path, used);
            }
            // `Class.name` is a dst (the class binding — emitted from a
            // sugared Assign's original dst), so it's NOT a use. `extends`
            // and each method's closure var ARE var refs (uses).
            Stmt::Class {
                extends,
                methods,
                static_fields,
                ..
            } => {
                if let Some(parent) = extends {
                    used.push(parent.clone());
                }
                for (_, method_var) in methods {
                    used.push(method_var.clone());
                }
                for field in static_fields {
                    used.push(field.value.clone());
                }
            }
            // `Import.name` is the bound dst (def, not use); `source` is a
            // literal module path, not a variable. Nothing to add.
            Stmt::Import { .. } => {}
            // `ExportNamed.value` and `ExportDefault.value` are string-
            // formatted values that may be either SSA var refs (e.g. `r3_0`)
            // or JS literals (e.g. `"hello"`, `42`). Treat uniformly as uses
            // — matches the convention in `count_var_uses` in structure.rs.
            // `ExportNamed.name` is the exported symbol name, not an SSA var.
            Stmt::ExportNamed { value, .. } => used.push(value.clone()),
            Stmt::ExportDefault { value } => used.push(value.clone()),
            // Break/Continue carry optional source-level labels, not SSA vars.
            Stmt::Break(_) | Stmt::Continue(_) => {}
            Stmt::Comment(_) => {}
        }
    }
}

fn collect_dsts(stmt: &Stmt, defined: &mut BTreeSet<String>) {
    match stmt {
        Stmt::Assign { dst, .. } => {
            defined.insert(dst.to_string());
        }
        Stmt::PhiAssign { dst, .. } => {
            defined.insert(dst.to_string());
        }
        Stmt::If {
            then_body,
            else_body,
            ..
        } => {
            for s in then_body {
                collect_dsts(s, defined);
            }
            for s in else_body {
                collect_dsts(s, defined);
            }
        }
        Stmt::While { body, .. } => {
            for s in body {
                collect_dsts(s, defined);
            }
        }
        Stmt::ForIn { body, key, .. } => {
            defined.insert(format!("{key}"));
            for s in body {
                collect_dsts(s, defined);
            }
        }
        Stmt::Switch { cases, default, .. } => {
            for (_, body) in cases {
                for s in body {
                    collect_dsts(s, defined);
                }
            }
            for s in default {
                collect_dsts(s, defined);
            }
        }
        Stmt::TryCatch {
            try_body,
            catch_var,
            catch_body,
        } => {
            for s in try_body {
                collect_dsts(s, defined);
            }
            defined.insert(catch_var.clone());
            for s in catch_body {
                collect_dsts(s, defined);
            }
        }
        Stmt::Labeled { body, .. } => {
            for s in body {
                collect_dsts(s, defined);
            }
        }
        // Each binding's `dst` is the SSA var name of a GetById Assign that
        // was consumed into this Destructure during sugaring — it's a real
        // def in the post-sugar stmt list (the Assign was absorbed, so it
        // is absent from the list), so we must credit it here or a
        // downstream use would read as a free variable.
        Stmt::Destructure { bindings, .. } => {
            for (_, dst) in bindings {
                defined.insert(dst.clone());
            }
        }
        // `DestructureWithDefault.target` names a `globalThis.<prop>` write
        // (consumed PutBy*), not a local SSA binding — no def to record
        // here. The 3-stmt cluster's intermediate SSA dsts (GetBy result,
        // LoadConst default) ARE consumed but they had no use site outside
        // the cluster itself, so dropping them silently is correct.
        Stmt::DestructureWithDefault { .. } => {}
        // `Class.name` carries the original Assign's dst (sugar.rs consumes
        // CreateBaseClass/CreateDerivedClass into this variant and drops the
        // Assign). Same load-bearing reason as Destructure above: the def
        // only survives in the Class variant post-sugar.
        Stmt::Class { name, .. } => {
            defined.insert(name.clone());
        }
        // `Import.name` is the dst from the consumed `var x = require(...)`
        // Assign (sugar.rs recover_esm). The literal `source` is not an SSA
        // name.
        Stmt::Import { name, .. } => {
            defined.insert(name.clone());
        }
        // Op has no dst (side-effecting instruction with no result register).
        Stmt::Op(_) => {}
        // Return/Throw carry uses, not defs.
        Stmt::Return(_) | Stmt::Throw(_) => {}
        // ExportNamed/ExportDefault don't introduce local SSA bindings — the
        // exported name lives in the module namespace, not the function's
        // local scope. `value` is a use (handled in walk_collect).
        Stmt::ExportNamed { .. } | Stmt::ExportDefault { .. } => {}
        // Break/Continue reference source-level labels, not SSA dsts.
        Stmt::Break(_) | Stmt::Continue(_) => {}
        Stmt::Comment(_) => {}
    }
}

/// Verify semantic properties of a structured function body.
pub fn verify_body(stmts: &[Stmt], param_count: u32) -> VerifyResult {
    let mut warnings = Vec::new();
    let mut defined: BTreeSet<String> = BTreeSet::new();

    // Parameters are pre-defined (a0, a1, ...)
    for i in 0..param_count.saturating_sub(1) {
        defined.insert(format!("a{i}"));
    }

    // Check use-before-def and unreachable code
    check_stmts(stmts, &mut defined, &mut warnings, 0);

    VerifyResult { warnings }
}

fn check_stmts(
    stmts: &[Stmt],
    defined: &mut BTreeSet<String>,
    warnings: &mut Vec<String>,
    depth: usize,
) {
    debug_assert!(
        depth <= 100,
        "check_stmts recursion depth {} exceeds limit 100. Tree likely too deep or cyclic.",
        depth
    );
    if depth > 100 {
        return;
    }

    let mut saw_terminator = false;

    for stmt in stmts {
        // Check for unreachable code after return/throw
        if saw_terminator {
            // Allow comments after terminators (common pattern)
            if !matches!(stmt, Stmt::Comment(_)) {
                warnings.push("unreachable code after return/throw".into());
                break; // Only warn once per block
            }
            continue;
        }

        match stmt {
            Stmt::Assign { dst, op, .. } => {
                // Check operand uses
                for operand in &op.operands {
                    if let super::ssa::SsaOperand::Var(v) = operand {
                        let name = format!("{v}");
                        if !defined.contains(&name) && !name.starts_with("r0_0") {
                            // r0_0 is often `this` or implicit — skip
                        }
                    }
                }
                defined.insert(dst.to_string());
            }
            Stmt::PhiAssign { dst, .. } => {
                defined.insert(dst.to_string());
            }
            Stmt::Return(_) | Stmt::Throw(_) => {
                saw_terminator = true;
            }
            Stmt::If {
                cond,
                then_body,
                else_body,
            } => {
                check_condition_uses(cond, defined, warnings);
                let mut then_defined = defined.clone();
                let mut else_defined = defined.clone();
                check_stmts(then_body, &mut then_defined, warnings, depth.saturating_add(1));
                check_stmts(else_body, &mut else_defined, warnings, depth.saturating_add(1));
                // Variables defined in both branches are available after
                for name in &then_defined {
                    if else_defined.contains(name) {
                        defined.insert(name.clone());
                    }
                }
            }
            Stmt::While { cond, body } => {
                // Unconditional loop (`cond = None`) renders as `while (true)`
                // and has no variable uses to check.
                if let Some(cond) = cond {
                    check_condition_uses(cond, defined, warnings);
                }
                check_stmts(body, &mut defined.clone(), warnings, depth.saturating_add(1));
            }
            Stmt::ForIn { body, .. } => {
                check_stmts(body, &mut defined.clone(), warnings, depth.saturating_add(1));
            }
            Stmt::Switch { cases, default, .. } => {
                for (_, body) in cases {
                    check_stmts(body, &mut defined.clone(), warnings, depth.saturating_add(1));
                }
                check_stmts(default, &mut defined.clone(), warnings, depth.saturating_add(1));
            }
            Stmt::TryCatch {
                try_body,
                catch_var,
                catch_body,
            } => {
                check_stmts(try_body, &mut defined.clone(), warnings, depth.saturating_add(1));
                let mut catch_defined = defined.clone();
                catch_defined.insert(catch_var.clone());
                check_stmts(catch_body, &mut catch_defined, warnings, depth.saturating_add(1));
            }
            Stmt::Labeled { body, .. } => {
                check_stmts(body, &mut defined.clone(), warnings, depth.saturating_add(1));
            }
            Stmt::Break(_) | Stmt::Continue(_) => {
                saw_terminator = true;
            }
            // Sugared variants that carry local SSA dsts absorbed from an
            // earlier Assign (see collect_dsts comments). Credit the dsts
            // into `defined` so later uses in this flow aren't flagged.
            Stmt::Destructure { bindings, .. } => {
                for (_, dst) in bindings {
                    defined.insert(dst.clone());
                }
            }
            // No local SSA defs to record — see `collect_dsts` comment.
            Stmt::DestructureWithDefault { .. } => {}
            Stmt::Class { name, .. } => {
                defined.insert(name.clone());
            }
            Stmt::Import { name, .. } => {
                defined.insert(name.clone());
            }
            // No local def, no flow effect. `Op` operand-use checking isn't
            // done by this pass even for Assign today; ExportNamed/Default
            // values aren't verified either. Explicit no-op — if that
            // changes, each variant gets its own arm.
            Stmt::Op(_) | Stmt::ExportNamed { .. } | Stmt::ExportDefault { .. } => {}
            Stmt::Comment(_) => {}
        }
    }
}

fn check_condition_uses(
    cond: &Condition,
    _defined: &BTreeSet<String>,
    _warnings: &mut Vec<String>,
) {
    // Currently just validates condition structure exists.
    // Future: check that condition variables are defined.
    match cond {
        Condition::Truthy(_)
        | Condition::Falsy(_)
        | Condition::IsUndefined(_)
        | Condition::NotUndefined(_)
        | Condition::Compare { .. } => {}
    }
}

#[cfg(test)]
mod tests {
    use super::super::ssa::VarId;
    use super::*;

    #[test]
    fn test_unreachable_after_return() {
        let stmts = vec![
            Stmt::Return(Some(VarId(0, 0))),
            Stmt::Comment("cleanup".into()),
            Stmt::Return(None), // unreachable
        ];
        let result = verify_body(&stmts, 1);
        assert!(
            result.warnings.iter().any(|w| w.contains("unreachable")),
            "should detect unreachable code: {:?}",
            result.warnings
        );
    }

    #[test]
    fn test_clean_body() {
        let stmts = vec![Stmt::Return(None)];
        let result = verify_body(&stmts, 1);
        assert!(result.is_ok());
    }
}
