//! Control flow structuring: recover if/else/while/for/switch from CFG.
//!
//! Computes dominator and post-dominator trees, then uses them to identify
//! if-then-else regions, loops, and try/catch blocks.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    reason = "PROOF: HBC parser/decompiler. IDs (string-id, builtin-id, function-id, regex-id) are widened from parser-validated u32 header counts and narrowed via explicit width-bounded ops. Slot/level-id narrows carry explicit `& 0xFFFF` / `& 0xFF` masks at the cast site. See module-level Cast hygiene doc-comment. PROOF: signed/unsigned reinterpretation in HBC jump offsets and operand decode; values bounded by per-function bytecode size cap. PROOF: HBC's BigInt sign-encoding + jump-offset signed/unsigned reinterpretation; values originate from validated-width operands."
)]

#![allow(missing_docs, reason = "internal")]
#![allow(dead_code, clippy::if_same_then_else, clippy::only_used_in_recursion, reason = "structure.rs is mid-rewrite (DSAW_LEGACY_STRUCTURER escape hatch active); some helpers + branches are intentionally kept for the legacy path until v1 deprecation.")]
#![cfg_attr(
    not(test),
    allow(
        clippy::indexing_slicing,
        clippy::string_slice,
        reason = "PROOF: structuring operates on a validated CFG (BlockIdx values minted by cfg::build) with dominator/post-dominator trees built by `droidsaw_common::graph::dominators`. Region trees, predecessor/successor lists, and SSA references are constructed by upstream passes; this module reads them. String slicing operates on identifier names (sanitize_id outputs) or on emit-internal `String` buffers. v1.x refinement candidate (~6 sites)."
    )
)]

use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use super::cfg::BlockId;
use super::ssa::{Resolved, SsaBlock, SsaFunction, SsaOp, SsaOperand, VarId};

/// Serialize `Rc<str>` as a plain string. Sidesteps the serde `rc` feature
/// flag — opting that in workspace-wide pulls in `Rc<T>` Serialize for every
/// crate. Per-field `#[serde(serialize_with = ...)]` keeps the change local
/// and emits the same wire shape as the previous `String` representation.
mod rc_str_serde {
    use std::rc::Rc;

    pub(super) fn serialize<S: serde::Serializer>(s: &Rc<str>, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(s)
    }
}

/// Per-predecessor phi-copy carriers: `(dst, src)` VarId-format names that
/// will be lowered to `Stmt::PhiAssign` at the tail of each predecessor block.
/// Shares `Stmt::Assign.dst`'s `Rc<str>` discipline so copies through
/// `apply_deep` are pointer-bumps rather than allocations.
pub(super) type PhiCopies = BTreeMap<BlockId, Vec<(Rc<str>, Rc<str>)>>;

/// Narrow an SSA `Const` operand (i64 by SsaOperand layout) to a `u32`
/// HBC-format ID — string-id, regex-id, builtin-id, etc. All such IDs
/// are bounded by the corresponding `*_count` u32 header field at parse
/// time, so the narrow is unreachable on well-formed HBC. Adversarial
/// wrap is observable but semantically benign (lookup miss → fallback).
#[allow(clippy::as_conversions, reason = "Spec-bounded value-domain narrowing (parser-validated field; preceding PROOF documents the bit-width invariant).")]
fn const_id_to_u32(v: i64) -> u32 {
    v as u32
}

/// Check if a string is a valid JS identifier (safe for dot notation and unquoted object keys).
/// Returns false for strings with hyphens, dots, spaces, or starting with digits.
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

fn is_valid_js_identifier(s: &str) -> bool {
    if s.is_empty() || is_js_reserved(s) {
        return false;
    }
    let mut chars = s.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_alphabetic() && first != '_' && first != '$' {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
}

/// Format property access: `obj.prop` if valid identifier, `obj["prop"]` otherwise.
fn escape_prop(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

fn fmt_prop_access(obj: &str, prop: &str) -> String {
    if is_valid_js_identifier(prop) {
        format!("{obj}.{prop}")
    } else {
        format!("{obj}[\"{}\"]", escape_prop(prop))
    }
}

/// Format property key for object literals: `prop` if valid identifier, `"prop"` otherwise.
fn fmt_prop_key(prop: &str) -> String {
    if is_valid_js_identifier(prop) {
        prop.to_string()
    } else {
        format!("\"{}\"", escape_prop(prop))
    }
}

/// Render a single `DestructureKey` in source-level pattern position —
/// `[computed]` for `Computed(v)` (resolved via inline_map) or bare
/// property-key for `Static(name)`.
fn render_destructure_key(
    key: &DestructureKey,
    inline_map: &BTreeMap<VarId, super::expr::Expr>,
) -> String {
    match key {
        DestructureKey::Computed(v) => format!("[{}]", resolve_var(v, inline_map)),
        DestructureKey::Static(name) => fmt_prop_key(name),
    }
}

/// Render a `DestructurePath` as a destructure-pattern entry, outermost
/// wrapper last. The leaf carries the `target` binding + `default` literal;
/// nested levels wrap the inner entry in `{ key: <inner> }` form.
///
/// Shorthand: static-key leaf where `key == target` collapses to
/// `target = default` (omitting the redundant `key:` prefix). Applies only
/// at the leaf; nested levels always spell out `key: { ... }`.
fn render_destructure_path(
    path: &DestructurePath,
    target: &str,
    default: &str,
    inline_map: &BTreeMap<VarId, super::expr::Expr>,
) -> String {
    match path {
        DestructurePath::Leaf { key } => match key {
            DestructureKey::Static(name) if name == target => {
                format!("{target} = {default}")
            }
            _ => {
                let key_render = render_destructure_key(key, inline_map);
                format!("{key_render}: {target} = {default}")
            }
        },
        DestructurePath::Nested { key, inner } => {
            let key_render = render_destructure_key(key, inline_map);
            let inner_rendered = render_destructure_path(inner, target, default, inline_map);
            format!("{key_render}: {{ {inner_rendered} }}")
        }
    }
}

/// Structured statement in the output.
#[derive(Debug, Clone, serde::Serialize)]
pub enum Stmt {
    /// Variable assignment: var name = expr
    Assign {
        /// VarId-format identifier name (`"r{reg}_{ver}"`, occasionally a
        /// renamed display form after `coalesce_phi_names`/IPA). Stored as
        /// `Rc<str>` so `apply_deep` sugar passes clone Stmt nodes via
        /// pointer-bump rather than per-clone heap allocation — the field
        /// is cloned at every sugar-pass walk over the Stmt tree, so its
        /// clone cost dominates the per-decompile allocation profile.
        #[serde(serialize_with = "rc_str_serde::serialize")]
        dst: Rc<str>,
        op: SsaOp,
        /// Source CFG block ID (for structural try-catch recovery)
        block_id: Option<BlockId>,
    },
    /// Side-effecting operation (no result)
    Op(SsaOp),
    /// Return
    Return(Option<VarId>),
    /// Throw
    Throw(VarId),
    /// If-then-else
    If {
        cond: Condition,
        then_body: Vec<Stmt>,
        else_body: Vec<Stmt>,
    },
    /// While loop. `cond = None` represents an unconditional loop — the JS
    /// surface syntax `while (true)`, `for (;;)`, or `do { ... } while (true)`.
    /// Modeled as `Option` rather than a sentinel `Condition::Truthy(VarId::MAX)`
    /// to avoid rendering a spurious `r4294967295_4294967295` identifier.
    While {
        cond: Option<Condition>,
        body: Vec<Stmt>,
    },
    /// For-in loop
    ForIn {
        key: VarId,
        obj: VarId,
        body: Vec<Stmt>,
    },
    /// Switch statement
    Switch {
        discriminant: VarId,
        cases: Vec<(String, Vec<Stmt>)>, // (case value string, body)
        default: Vec<Stmt>,
    },
    /// Try-catch
    TryCatch {
        try_body: Vec<Stmt>,
        catch_var: String,
        catch_body: Vec<Stmt>,
    },
    /// Destructuring: var { prop: dst, ... } = obj
    Destructure {
        object: String,
        bindings: Vec<(String, String)>, // (property_name, dest_var)
    },
    /// Single-leaf defaulted destructuring with an optional nesting chain:
    ///   `var { [key]: target = default } = object;`              (flat computed key)
    ///   `var { key: target = default } = object;`                (flat static key; shorthand when key == target)
    ///   `var { outer: { inner: target = default } } = object;`   (nested static chain)
    ///   `var { [key]: { inner: target = default } } = object;`   (mixed: computed at root + static inner)
    /// Reconstructed by sugar from the marker cluster
    /// `Assign(GetBy*-chain) + If(IsUndefined|Compare-with-undef) + Op(PutBy*)`.
    /// The undef-marker is unfakeable from any JS surface other than a
    /// defaulted destructure, so reconstruction is lossless.
    DestructureWithDefault {
        /// VarId-format source-object reference (resolved via inline_map).
        object: String,
        /// VarId-format receiver of the consumed PutBy* (typically
        /// `globalThis` at top level). Not emitted — tracked so the
        /// verifier / use-counter don't under-count this var.
        target_receiver: String,
        /// Final binding name (the property on the consumed PutBy*).
        target: String,
        /// Pre-rendered default-value literal from the `LoadConst*` op.
        default: String,
        /// Destructure-pattern path from the outermost level to the leaf.
        /// `Leaf { key }` covers the flat case; `Nested { key, inner }`
        /// wraps an intermediate static-key level.
        path: DestructurePath,
    },
    /// Class declaration
    Class {
        name: String,
        extends: Option<String>,
        methods: Vec<(String, String)>, // (method_name, closure_var)
        /// Static fields (`static x = 1`, `static #x = 1`). Reconstructed by
        /// sugar from `DefineOwnById` (public) + `AddOwnPrivateBySym` (private)
        /// emitted after the class-creation sequence. Each entry carries the
        /// field name, the SSA-var holding the initializer value, and a
        /// private-flag (renders as `#name`).
        static_fields: Vec<StaticField>,
    },
    /// ESM import: import name from "source"
    Import { name: String, source: String },
    /// ESM named export: export const name = value
    ExportNamed { name: String, value: String },
    /// ESM default export: export default value
    ExportDefault { value: String },
    /// Phi copy assignment: dst = src (emitted at end of predecessor blocks).
    /// Both fields are VarId-format identifier names; stored as `Rc<str>` to
    /// share the cheap-clone discipline of `Stmt::Assign.dst`.
    PhiAssign {
        #[serde(serialize_with = "rc_str_serde::serialize")]
        dst: Rc<str>,
        #[serde(serialize_with = "rc_str_serde::serialize")]
        src: Rc<str>,
    },
    /// Labeled block: `label: { body }` — target for break/continue
    Labeled { label: String, body: Vec<Stmt> },
    /// Break with optional label
    Break(Option<String>),
    /// Continue with optional label
    Continue(Option<String>),
    /// Comment
    Comment(String),
}

/// Static-field member of a class body (`static name = value` or
/// `static #name = value`). The `value` string is an SSA-var reference
/// resolved through the emitter's `inline_map`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct StaticField {
    pub name: String,
    pub value: String,
    pub is_private: bool,
}

/// Step in a destructure pattern's property-key chain. Matches the
/// source-level `{ foo: ... }` (static) vs `{ [var]: ... }` (computed)
/// distinction.
#[derive(Debug, Clone, serde::Serialize)]
pub enum DestructureKey {
    /// Static key: the property-name literal (e.g. `"x"` → `x`).
    Static(String),
    /// Computed key: a VarId-format SSA reference resolved via inline_map
    /// at emit (e.g. `"r3_4"` → `globalThis.key`).
    Computed(String),
}

/// Destructure-pattern shape, outermost to innermost. `Leaf` is the
/// terminal level — the default + target binding live on the enclosing
/// `Stmt::DestructureWithDefault`, not here. `Nested` carries the outer
/// level's key + a boxed child path.
///
/// Depth is bounded by the sugar-pass chain-walker cap (≤8); JavaScript
/// source-level nesting past that is practically unreadable and the cap
/// defends against obfuscated bytecode synthesizing arbitrarily deep
/// chains. Emit traverses the path recursively; verify-walk visits any
/// computed-key `VarId` refs along the path.
#[derive(Debug, Clone, serde::Serialize)]
pub enum DestructurePath {
    Leaf {
        key: DestructureKey,
    },
    Nested {
        key: DestructureKey,
        inner: Box<DestructurePath>,
    },
}

/// A branch condition.
#[derive(Debug, Clone, serde::Serialize)]
pub enum Condition {
    Truthy(VarId),
    Falsy(VarId),
    Compare {
        op: &'static str,
        left: VarId,
        right: VarId,
    },
    IsUndefined(VarId),
    NotUndefined(VarId),
}

/// A structured function body.
#[derive(Debug, serde::Serialize)]
pub struct StructuredFunction {
    pub name: String,
    pub params: u32,
    pub body: Vec<Stmt>,
    pub is_strict: bool,
    pub is_async: bool,
    pub is_generator: bool,
    pub is_arrow: bool,
    /// Human-readable variable names from the optimizer.
    pub var_names: BTreeMap<VarId, String>,
    /// Renamed parameter names (index → name). Empty = use default a0, a1, ...
    pub param_names: BTreeMap<u32, String>,
}

// --- Dominator computation (Cooper, Harvey, Kennedy algorithm) ---

/// Compute immediate dominators via common's Cooper-Harvey-Kennedy.
///
/// hbc's structurer has its own RPO (`block_order`) so we use the
/// `dominators_with_rpo` variant that takes a pre-computed order and a
/// predecessor closure — no need to build a Graph trait impl.
///
/// One historical quirk preserved: the returned map includes `entry → entry`
/// (self-loop sentinel) because downstream code in structure.rs may look up
/// the entry's idom and expect a value. Common's version omits the entry by
/// convention, so we add it back here.
fn compute_dominators(
    entry: BlockId,
    block_order: &[BlockId],
    preds: &BTreeMap<BlockId, Vec<BlockId>>,
) -> BTreeMap<BlockId, BlockId> {
    // PROOF: callers pass `all_preds` built from `ssa.blocks.iter().map(|b|(b.id, ..))`.
    // `dominators_with_rpo` iterates `block_order` which is `ssa.block_order` — every
    // element is a key in `ssa.blocks` and therefore a key in `preds`.
    // `unwrap_or_default()` is dead on this call path.
    let mut idom = droidsaw_common::graph::dominators_with_rpo(entry, block_order, |b| {
        debug_assert!(preds.contains_key(&b), "block {b} missing from preds — ssa.blocks invariant violated");
        preds.get(&b).cloned().unwrap_or_default()
    });
    idom.insert(entry, entry);
    idom
}

/// Compute immediate post-dominators via common's `post_dominators_with_virtual_exit`.
///
/// Returns `PostDom::Exit` for nodes with no real merge point (all paths
/// diverge to different exits). No sentinel value required or exposed.
fn compute_post_dominators(
    block_order: &[BlockId],
    all_succs: &BTreeMap<BlockId, Vec<BlockId>>,
) -> BTreeMap<BlockId, droidsaw_common::PostDom<BlockId>> {
    // PROOF: callers pass `all_succs` built from `ssa.blocks.iter().map(|b|(b.id, ..))`.
    // `post_dominators_with_virtual_exit` iterates `block_order` which is `ssa.block_order`
    // — every element is a key in `ssa.blocks` and therefore a key in `all_succs`.
    // `unwrap_or_default()` is dead on this call path.
    droidsaw_common::graph::post_dominators_with_virtual_exit(block_order, |b| {
        debug_assert!(all_succs.contains_key(&b), "block {b} missing from all_succs — ssa.blocks invariant violated");
        all_succs.get(&b).cloned().unwrap_or_default()
    })
}

/// Find the merge point (immediate post-dominator) for a conditional branch.
fn find_merge_point(
    block_id: BlockId,
    succs: &[BlockId],
    ipdom: &BTreeMap<BlockId, droidsaw_common::PostDom<BlockId>>,
) -> Option<BlockId> {
    if succs.len() != 2 {
        return None;
    }
    match ipdom.get(&block_id)? {
        droidsaw_common::PostDom::Node(m) if *m != block_id => Some(*m),
        _ => None,
    }
}

/// Extract condition from the last op of a block.
pub(super) fn extract_condition(block: &SsaBlock) -> Option<Condition> {
    let last = block.ops.last()?;
    match last.name {
        "JmpTrue" | "JmpTrueLong" => last.operands.get(1).and_then(|o| {
            if let SsaOperand::Var(v) = o {
                Some(Condition::Truthy(*v))
            } else {
                None
            }
        }),
        "JmpFalse" | "JmpFalseLong" => last.operands.get(1).and_then(|o| {
            if let SsaOperand::Var(v) = o {
                Some(Condition::Falsy(*v))
            } else {
                None
            }
        }),
        "JmpUndefined" | "JmpUndefinedLong" => last.operands.get(1).and_then(|o| {
            if let SsaOperand::Var(v) = o {
                Some(Condition::IsUndefined(*v))
            } else {
                None
            }
        }),
        "JmpTypeOfIs" => {
            // JmpTypeOfIs: jump if typeof(reg) matches type bitfield
            // Treat as Truthy — the structurer's branch swap + negate handles polarity
            last.operands.get(1).and_then(|o| {
                if let SsaOperand::Var(v) = o {
                    Some(Condition::Truthy(*v))
                } else {
                    None
                }
            })
        }
        n if n.starts_with('J') && n != "Jmp" && n != "JmpLong" => {
            // Condition-polarity maps the conditional-branch opcode to its
            // "jump-fires-when-true" comparator. The chain is MOST-SPECIFIC
            // FIRST because `str::contains` does substring matching, so a
            // bare `contains("Equal")` would swallow every opcode whose
            // name has "Equal" as a substring — `JNotEqual`, `JGreaterEqual`,
            // `JLessEqual`, `JNotGreaterEqual`, `JNotLessEqual`, and their
            // `Long` / `N` / `NLong` variants. Keep this ordering invariant
            // or the loop-exit polarity silently flips (see the test module
            // below, which pins every opcode name that reaches this arm).
            let op = if n.contains("StrictEqual") {
                "==="
            } else if n.contains("StrictNotEqual") {
                "!=="
            } else if n.contains("NotGreaterEqual") {
                "<"
            } else if n.contains("NotLessEqual") {
                ">"
            } else if n.contains("GreaterEqual") {
                ">="
            } else if n.contains("LessEqual") {
                "<="
            } else if n.contains("NotGreater") {
                "<="
            } else if n.contains("NotLess") {
                ">="
            } else if n.contains("Greater") {
                ">"
            } else if n.contains("Less") {
                "<"
            } else if n.contains("NotEqual") {
                "!="
            } else if n.contains("Equal") {
                "=="
            } else {
                "??"
            };
            if let (Some(SsaOperand::Var(l)), Some(SsaOperand::Var(r))) =
                (last.operands.get(1), last.operands.get(2))
            {
                Some(Condition::Compare {
                    op,
                    left: *l,
                    right: *r,
                })
            } else {
                None
            }
        }
        _ => None,
    }
}

use super::sugar::{
    apply_deep, flatten_early_returns, linearize_async, negate_condition, recover_class,
    recover_destructuring, recover_destructuring_with_default, recover_esm_one_level,
    recover_for_in, recover_generator_one_level, recover_switch, recover_try_catch,
    strip_tdz_traps,
};

/// Compute the natural loop body: all blocks on paths from header back through the latch.
/// Uses reverse BFS from each latch block, stopping at the header.
fn compute_natural_loop(
    header: BlockId,
    latch_blocks: &[BlockId],
    _all_succs: &BTreeMap<BlockId, Vec<BlockId>>,
    all_preds: &BTreeMap<BlockId, Vec<BlockId>>,
) -> BTreeSet<BlockId> {
    // PROOF: callers pass `all_preds` built from `ssa.blocks.iter().map(|b|(b.id, ..))`.
    // `collect_loop_body_multi` walks backwards from latch_blocks (which are elements of
    // `ssa.block_order`) via predecessors. Every BlockId reachable from `header` through
    // back-edges is a key in `ssa.blocks` and therefore a key in `all_preds`.
    // `unwrap_or_default()` is dead on this call path.
    droidsaw_common::graph::collect_loop_body_multi(
        |b| {
            debug_assert!(all_preds.contains_key(&b), "block {b} missing from all_preds — ssa.blocks invariant violated");
            all_preds.get(&b).cloned().unwrap_or_default()
        },
        header,
        latch_blocks,
    )
}

/// Structure an SSA function into a high-level JS-like representation.
///
/// Postconditions: `params` equals the header's `param_count`. All
/// non-terminator SSA ops appear in the output.
pub fn structure_function(
    ssa: &SsaFunction<Resolved>,
    name: String,
    params: u32,
    flags: u8,
) -> StructuredFunction {
    structure_function_with_exc(ssa, name, params, flags, &BTreeMap::new())
}

pub fn structure_function_with_exc(
    ssa: &SsaFunction<Resolved>,
    name: String,
    params: u32,
    flags: u8,
    exc_handlers: &BTreeMap<BlockId, BlockId>,
) -> StructuredFunction {
    // Region path is the default. `DSAW_LEGACY_STRUCTURER=1` is the
    // escape hatch while the legacy code stays in-tree.
    // The region path fixes several bug classes where legacy
    // misattributes blocks via its RPO-ordering partition heuristic.
    let use_region = std::env::var("DSAW_LEGACY_STRUCTURER").is_err();
    structure_function_with_exc_choice(ssa, name, params, flags, exc_handlers, use_region)
}

/// Like `structure_function_with_exc` but the front-end choice is explicit,
/// not read from `DSAW_REGION_STRUCTURER`. Used by the differential test so
/// parallel test threads don't race on process-global env state.
pub fn structure_function_with_exc_choice(
    ssa: &SsaFunction<Resolved>,
    name: String,
    params: u32,
    flags: u8,
    exc_handlers: &BTreeMap<BlockId, BlockId>,
    use_region: bool,
) -> StructuredFunction {
    let prohibit_invoke = flags & 0x03;
    // Arrow functions have ProhibitConstruct (2) and are always anonymous in Hermes.
    // Named functions with this flag are a v84-v90 flags layout mismatch.
    let is_arrow = prohibit_invoke == 2 && name.is_empty();
    let is_strict = (flags >> 2) & 1 != 0;
    let is_async = ((flags >> 5) & 3) == 2;
    let mut is_generator = ((flags >> 5) & 3) == 1;

    // Detect generator body: inner function containing StartGenerator
    if !is_generator {
        for block in &ssa.blocks {
            for op in &block.ops {
                if op.name == "StartGenerator" {
                    is_generator = true;
                    break;
                }
            }
            if is_generator {
                break;
            }
        }
    }

    let block_map: BTreeMap<BlockId, &SsaBlock> = ssa.blocks.iter().map(|b| (b.id, b)).collect();
    let all_succs: BTreeMap<BlockId, Vec<BlockId>> = ssa
        .blocks
        .iter()
        .map(|b| (b.id, b.successors.clone()))
        .collect();
    let all_preds: BTreeMap<BlockId, Vec<BlockId>> = ssa
        .blocks
        .iter()
        .map(|b| (b.id, b.predecessors.clone()))
        .collect();

    // Find back edges (loops)
    let back_edges = find_back_edges(ssa);
    let loop_headers: BTreeSet<BlockId> = back_edges.iter().map(|(_, t)| *t).collect();

    // Compute post-dominators for merge-point detection
    let ipdom = compute_post_dominators(&ssa.block_order, &all_succs);

    // Build phi copy map: for each predecessor block, collect the phi assignments
    // it needs to emit at its end (dst = src for each successor's phi that references it).
    // Stored as `Rc<str>` so the downstream `Stmt::PhiAssign.dst/src` clones in
    // `emit_block_ops` are pointer-bumps rather than per-clone allocations.
    let mut phi_copies: PhiCopies = BTreeMap::new();
    for block in &ssa.blocks {
        for phi in &block.phis {
            for (pred_id, var) in &phi.args {
                phi_copies
                    .entry(*pred_id)
                    .or_default()
                    .push((Rc::from(format!("{}", phi.dst)), Rc::from(format!("{var}"))));
            }
        }
    }

    // Opt-in regionalized structurer. Sugar pass chain below is path-agnostic
    // — it runs on whichever Vec<Stmt> the chosen front-end produces.
    let body = if use_region {
        let region = super::region::build_region_tree(ssa, exc_handlers);
        super::region::lower_region(&region, ssa)
    } else {
        structure_blocks(
            &ssa.block_order,
            &block_map,
            &all_succs,
            &all_preds,
            &loop_headers,
            &back_edges,
            &ipdom,
            &phi_copies,
            exc_handlers,
        )
    };

    let body = flatten_early_returns(body);
    let body = recover_switch(body);
    let body = recover_for_in(body);
    // Try-catch is now handled during structuring — post-pass only for edge cases
    let body = apply_deep(body, &|stmts| recover_try_catch(stmts, exc_handlers));
    let body = recover_destructuring_with_default(body);
    let body = recover_destructuring(body);
    let body = recover_class(body);
    // Generator cleanup: runs on all functions to catch both flagged generators
    // and unflagged generator bodies (v99 splits generator into wrapper + body).
    let body = apply_deep(body, &recover_generator_one_level);
    // Async linearization: flatten state machine into sequential await calls.
    // Only apply to async inner functions (?anon_0_* or async-flagged) to avoid
    // destroying sync generator loop structure.
    let body = if is_async || name.contains("anon_0_") {
        linearize_async(body)
    } else {
        body
    };
    // Strip Hermes runtime TDZ / const-reassignment traps. Runs after all
    // pattern recovery so the matcher sees fully-shaped Stmts (e.g. an
    // `if (slot) {} else { throwTypeError }` whose then was already drained
    // by recover_class).
    let body = strip_tdz_traps(body);

    let structured = StructuredFunction {
        name,
        params,
        body,
        is_strict,
        is_async,
        is_generator,
        is_arrow,
        var_names: ssa.var_names.clone(),
        param_names: ssa.param_names.clone(),
    };
    droidsaw_common::diag::stage_dump("structure", &structured);
    structured
}

pub(super) fn find_back_edges(ssa: &SsaFunction<Resolved>) -> Vec<(BlockId, BlockId)> {
    let mut visited = BTreeSet::new();
    let mut in_stack = BTreeSet::new();
    let mut back_edges = Vec::new();

    let block_map: BTreeMap<BlockId, &SsaBlock> = ssa.blocks.iter().map(|b| (b.id, b)).collect();

    // Iterative DFS to avoid stack overflow on deep CFGs
    let Some(&entry) = ssa.block_order.first() else {
        return back_edges;
    };

    // Stack holds (block_id, successor_index, is_entering)
    let mut stack: Vec<(BlockId, usize)> = vec![(entry, 0)];
    visited.insert(entry);
    in_stack.insert(entry);

    while let Some((bid, si)) = stack.last_mut() {
        // SEMANTICS-DEFAULT-EMPTY: `block_map` contains all `ssa.blocks` ids; a
        // missing `bid` would indicate a successor reference to an id outside
        // `ssa.blocks`, which cannot happen by ssa-builder construction but is treated
        // as no-successors to terminate the DFS branch rather than panic.
        let succs = block_map.get(bid).map(|b| &b.successors[..]).unwrap_or(&[]);
        if *si < succs.len() {
            let succ = succs[*si];
            *si = si.saturating_add(1);
            if in_stack.contains(&succ) {
                back_edges.push((*bid, succ));
            } else if !visited.contains(&succ) {
                visited.insert(succ);
                in_stack.insert(succ);
                stack.push((succ, 0));
            }
        } else {
            in_stack.remove(bid);
            stack.pop();
        }
    }

    back_edges
}

/// Emit statements for a block's non-terminator instructions.
/// Phi declarations are emitted at the top (merge point).
/// Phi copy assignments are appended at the end (predecessor outgoing copies).
pub(super) fn emit_block_ops(
    block: &SsaBlock,
    phi_copies: &PhiCopies,
) -> Vec<Stmt> {
    let mut stmts = Vec::new();

    // Phi declarations at the merge point are intentionally not emitted as
    // marker comments here. The real writes happen via PhiAssign in each
    // predecessor block (see the phi_copies loop below). An earlier shape
    // pushed a Stmt::Comment("var rN = ... /* phi(...) */") as a
    // human-readable marker, but with the inline_map / skip_set split in
    // StructuredFunction::emit the predecessor PhiAssigns emit correctly
    // and the marker was misread as a decompiler bug.

    for op in &block.ops {
        if op.original.is_terminator() {
            continue;
        }
        if let Some(dst) = &op.dst {
            stmts.push(Stmt::Assign {
                dst: Rc::from(format!("{dst}")),
                op: op.clone(),
                block_id: Some(block.id),
            });
        } else {
            stmts.push(Stmt::Op(op.clone()));
        }
    }

    // Emit phi copy assignments for successor blocks' phis
    if let Some(copies) = phi_copies.get(&block.id) {
        for (dst, src) in copies {
            stmts.push(Stmt::PhiAssign {
                dst: dst.clone(),
                src: src.clone(),
            });
        }
    }

    stmts
}

/// Emit a dispatcher loop for blocks that cannot be structured by recursive descent.
/// Produces: `__dispatch: while (true) { switch (__state) { case 0: ...; case 1: ...; } }`
/// Each block becomes a case. Edges between blocks set __state and continue.
/// Exits (returns/throws, or jumps outside the block set) break out.
#[allow(clippy::too_many_arguments, reason = "Many-arg signature reflects the parser/structurer threading multiple bytecode-version contexts; bundling into a context struct would relocate field listing rather than eliminate it.")]
pub(super) fn emit_dispatcher(
    block_order: &[BlockId],
    block_map: &BTreeMap<BlockId, &SsaBlock>,
    phi_copies: &PhiCopies,
    all_succs: &BTreeMap<BlockId, Vec<BlockId>>,
    order_set: &BTreeSet<BlockId>,
    depth: usize,
) -> Vec<Stmt> {
    if block_order.is_empty() {
        return vec![];
    }

    let label = format!("__dispatch_{depth}");
    let state_var = format!("__state_{depth}");

    // Map each block to a case index
    let block_to_case: BTreeMap<BlockId, usize> = block_order
        .iter()
        .enumerate()
        .map(|(i, &bid)| (bid, i))
        .collect();

    let mut cases: Vec<(String, Vec<Stmt>)> = Vec::new();

    for (case_idx, &bid) in block_order.iter().enumerate() {
        let mut case_body: Vec<Stmt> = Vec::new();

        if let Some(block) = block_map.get(&bid) {
            // Emit block ops (excluding terminator)
            case_body.extend(emit_block_ops(block, phi_copies));

            // Handle terminator: route to next case or exit
            if let Some(last) = block.ops.last() {
                if last.name == "Ret" {
                    if let Some(SsaOperand::Var(v)) = last.operands.first() {
                        case_body.push(Stmt::Return(Some(*v)));
                    } else {
                        case_body.push(Stmt::Return(None));
                    }
                } else if last.name == "Throw" {
                    if let Some(SsaOperand::Var(v)) = last.operands.first() {
                        case_body.push(Stmt::Throw(*v));
                    }
                } else {
                    // Route to successors
                    // SEMANTICS-DEFAULT-EMPTY: `all_succs` contains all `ssa.blocks` ids;
                    // a missing `bid` here would be a dispatcher iteration over a block id
                    // that is not in the SSA — structurally impossible but treated as
                    // no-successors (empty case body continues the loop without routing).
                    let succs: Vec<BlockId> = all_succs
                        .get(&bid)
                        .cloned()
                        .unwrap_or_default()
                        .into_iter()
                        .filter(|s| order_set.contains(s))
                        .collect();

                    if succs.len() == 1 {
                        if let Some(&target_case) = block_to_case.get(&succs[0]) {
                            // Set state and continue the dispatcher loop
                            case_body.push(Stmt::Comment(format!("{state_var} = {target_case}")));
                            case_body.push(Stmt::Continue(Some(label.clone())));
                        }
                    } else if succs.len() >= 2 && last.original.is_conditional_branch() {
                        // Conditional: emit if/else with state transitions
                        let cond = extract_condition(block);
                        let target = last.original.branch_target();
                        let is_negated = last.name.contains("False") || last.name.contains("Not");

                        let (then_target, else_target) = if is_negated {
                            (succs.iter().find(|&&s| Some(s) != target).copied(), target)
                        } else {
                            (target, succs.iter().find(|&&s| Some(s) != target).copied())
                        };

                        if let Some(cond) = cond {
                            let cond = if is_negated {
                                negate_condition(cond)
                            } else {
                                cond
                            };

                            let then_body = if let Some(tt) = then_target {
                                if let Some(&tc) = block_to_case.get(&tt) {
                                    vec![
                                        Stmt::Comment(format!("{state_var} = {tc}")),
                                        Stmt::Continue(Some(label.clone())),
                                    ]
                                } else {
                                    vec![Stmt::Break(Some(label.clone()))]
                                }
                            } else {
                                vec![Stmt::Break(Some(label.clone()))]
                            };

                            let else_body = if let Some(et) = else_target {
                                if let Some(&ec) = block_to_case.get(&et) {
                                    vec![
                                        Stmt::Comment(format!("{state_var} = {ec}")),
                                        Stmt::Continue(Some(label.clone())),
                                    ]
                                } else {
                                    vec![Stmt::Break(Some(label.clone()))]
                                }
                            } else {
                                vec![Stmt::Break(Some(label.clone()))]
                            };

                            case_body.push(Stmt::If {
                                cond,
                                then_body,
                                else_body,
                            });
                        }
                    }
                    // For jumps to blocks outside our set, the case just falls through
                    // to break (added below)
                }
            }
        }

        cases.push((format!("{case_idx}"), case_body));
    }

    // Initial state assignment + labeled while(true) { switch(__state) { ... } }
    let switch_stmt = Stmt::Switch {
        discriminant: VarId(u32::MAX, u32::MAX), // sentinel — resolved via inline_map
        cases,
        default: vec![Stmt::Break(Some(label.clone()))],
    };

    let while_body = vec![switch_stmt];

    vec![
        Stmt::Comment(format!("var {state_var} = 0")),
        Stmt::Labeled {
            label: label.clone(),
            body: vec![Stmt::While {
                // Unconditional dispatcher loop: `while (true) { switch (state) … }`.
                cond: None,
                body: while_body,
            }],
        },
    ]
}

/// Recursively structure a region of blocks.
///
/// Legacy structurer signature — carries the full analysis context
/// explicitly rather than through a struct. Region structurer is
/// the default now (see `region.rs`); this path is the
/// `DSAW_LEGACY_STRUCTURER=1` escape hatch for one release cycle.
/// Not worth refactoring the arg list of code scheduled for deletion.
#[allow(clippy::too_many_arguments, reason = "Many-arg signature reflects the parser/structurer threading multiple bytecode-version contexts; bundling into a context struct would relocate field listing rather than eliminate it.")]
fn structure_blocks(
    block_order: &[BlockId],
    block_map: &BTreeMap<BlockId, &SsaBlock>,
    all_succs: &BTreeMap<BlockId, Vec<BlockId>>,
    all_preds: &BTreeMap<BlockId, Vec<BlockId>>,
    loop_headers: &BTreeSet<BlockId>,
    back_edges: &[(BlockId, BlockId)],
    ipdom: &BTreeMap<BlockId, droidsaw_common::PostDom<BlockId>>,
    phi_copies: &PhiCopies,
    exc_handlers: &BTreeMap<BlockId, BlockId>,
) -> Vec<Stmt> {
    structure_blocks_inner(
        block_order,
        block_map,
        all_succs,
        all_preds,
        loop_headers,
        back_edges,
        ipdom,
        phi_copies,
        exc_handlers,
        0,
    )
}

#[allow(clippy::too_many_arguments, reason = "Many-arg signature reflects the parser/structurer threading multiple bytecode-version contexts; bundling into a context struct would relocate field listing rather than eliminate it.")]
fn structure_blocks_inner(
    block_order: &[BlockId],
    block_map: &BTreeMap<BlockId, &SsaBlock>,
    all_succs: &BTreeMap<BlockId, Vec<BlockId>>,
    all_preds: &BTreeMap<BlockId, Vec<BlockId>>,
    loop_headers: &BTreeSet<BlockId>,
    back_edges: &[(BlockId, BlockId)],
    ipdom: &BTreeMap<BlockId, droidsaw_common::PostDom<BlockId>>,
    phi_copies: &PhiCopies,
    exc_handlers: &BTreeMap<BlockId, BlockId>,
    depth: usize,
) -> Vec<Stmt> {
    // Guard against infinite recursion from pathological CFGs.
    // When depth exceeds the limit, emit remaining blocks as a flat
    // dispatcher loop rather than silently truncating.
    if depth > block_map.len().saturating_add(4) {
        return emit_dispatcher(
            block_order,
            block_map,
            phi_copies,
            all_succs,
            &block_order.iter().copied().collect(),
            depth,
        );
    }

    let mut stmts = Vec::new();
    let mut processed: BTreeSet<BlockId> = BTreeSet::new();
    let order_set: BTreeSet<BlockId> = block_order.iter().copied().collect();

    // Pre-step: partition blocks by exception region. Find try regions (blocks
    // with the same exc_handler) and their catch targets. Emit TryCatch directly
    // so catch blocks are never emitted out of order.
    if !exc_handlers.is_empty() {
        // Collect catch targets that appear in our block set
        let catch_targets: BTreeSet<BlockId> = exc_handlers
            .values()
            .filter(|target| order_set.contains(target))
            .copied()
            .collect();

        // Find try regions: groups of blocks sharing the same handler
        let mut try_regions: Vec<(BlockId, Vec<BlockId>)> = Vec::new(); // (catch_target, try_blocks)
        let mut current_handler: Option<BlockId> = None;
        let mut current_try_blocks: Vec<BlockId> = Vec::new();

        for &bid in block_order {
            let handler = exc_handlers.get(&bid).copied();
            if handler != current_handler {
                if let Some(target) = current_handler
                    && !current_try_blocks.is_empty()
                {
                    try_regions.push((target, std::mem::take(&mut current_try_blocks)));
                }
                current_handler = handler;
            }
            if handler.is_some() {
                current_try_blocks.push(bid);
            }
        }
        if let Some(target) = current_handler
            && !current_try_blocks.is_empty()
        {
            try_regions.push((target, current_try_blocks));
        }

        // For each try region, structure both the try body and catch body,
        // emit TryCatch, and mark all blocks as processed.
        if !try_regions.is_empty() {
            // Re-iterate blocks in order, emitting try-catch when we hit a try region
            let mut try_region_map: BTreeMap<BlockId, (BlockId, Vec<BlockId>)> = BTreeMap::new();
            for (catch_target, try_blocks) in &try_regions {
                if let Some(&first) = try_blocks.first() {
                    try_region_map.insert(first, (*catch_target, try_blocks.clone()));
                }
            }
            // Mark all try region blocks and catch targets
            let mut try_block_set: BTreeSet<BlockId> = BTreeSet::new();
            for (_, blocks) in &try_regions {
                for &b in blocks {
                    try_block_set.insert(b);
                }
            }

            for &bid in block_order {
                if processed.contains(&bid) {
                    continue;
                }

                // Check if this block starts a try region
                if let Some((catch_target, try_blocks)) = try_region_map.get(&bid) {
                    // Mark try blocks as processed
                    for &tb in try_blocks {
                        processed.insert(tb);
                    }

                    // Structure the try body (with inner exc_handlers minus this region)
                    let mut inner_handlers = exc_handlers.clone();
                    inner_handlers.retain(|_, target| target != catch_target);
                    let try_body = structure_blocks_inner(
                        try_blocks,
                        block_map,
                        all_succs,
                        all_preds,
                        loop_headers,
                        back_edges,
                        ipdom,
                        phi_copies,
                        &inner_handlers,
                        depth.saturating_add(1),
                    );

                    // Find and structure the catch block
                    let mut catch_var = "err".to_string();
                    let mut catch_body_blocks: Vec<BlockId> = Vec::new();
                    if let Some(catch_block) = block_map.get(catch_target) {
                        processed.insert(*catch_target);
                        // Extract catch variable from Catch instruction
                        if let Some(catch_op) = catch_block.ops.first()
                            && catch_op.name == "Catch"
                            && let Some(dst) = &catch_op.dst
                        {
                            catch_var = format!("{dst}");
                        }
                        // Collect catch body: the catch target + blocks reachable from it
                        // that haven't been processed and aren't in try regions
                        catch_body_blocks.push(*catch_target);
                        for &succ in &catch_block.successors {
                            if !processed.contains(&succ)
                                && order_set.contains(&succ)
                                && !try_block_set.contains(&succ)
                            {
                                catch_body_blocks.push(succ);
                                processed.insert(succ);
                            }
                        }
                    }

                    let catch_body = if catch_body_blocks.is_empty() {
                        vec![]
                    } else {
                        structure_blocks_inner(
                            &catch_body_blocks,
                            block_map,
                            all_succs,
                            all_preds,
                            loop_headers,
                            back_edges,
                            ipdom,
                            phi_copies,
                            &inner_handlers,
                            depth.saturating_add(1),
                        )
                    };

                    stmts.push(Stmt::TryCatch {
                        try_body,
                        catch_var,
                        catch_body,
                    });
                    continue;
                }

                // Skip blocks that are catch targets (handled above)
                if catch_targets.contains(&bid) {
                    processed.insert(bid);
                    continue;
                }

                // Not a try region or catch target — emit normally
                // (will be handled by the main loop below)
            }

            // If we consumed all blocks via try regions, return early
            if block_order.iter().all(|b| processed.contains(b)) {
                return stmts;
            }
        }
    }

    for &bid in block_order {
        if processed.contains(&bid) {
            continue;
        }

        processed.insert(bid);

        let Some(block) = block_map.get(&bid) else {
            continue;
        };

        // Check if this block is a loop header — wrap body in While
        if loop_headers.contains(&bid) {
            let latch_blocks: Vec<BlockId> = back_edges
                .iter()
                .filter(|(_, target)| *target == bid)
                .map(|(latch, _)| *latch)
                .collect();

            if !latch_blocks.is_empty() {
                // PROOF: `latch_blocks` is non-empty (checked above), so `max()` returns
                // Some; `unwrap_or(bid)` is dead.
                debug_assert!(!latch_blocks.is_empty());
                let max_latch = latch_blocks.iter().copied().max().unwrap_or(bid);

                // Emit the header block's non-terminator ops BEFORE the while
                stmts.extend(emit_block_ops(block, phi_copies));

                // Extract loop condition from the header's conditional branch
                let loop_cond = if let Some(last) = block.ops.last() {
                    if last.original.is_conditional_branch() {
                        extract_condition(block)
                    } else {
                        None
                    }
                } else {
                    None
                };

                // Loop body: blocks reachable from header that can reach the latch,
                // determined by membership in the natural loop (all blocks on paths
                // from header to latch). This is correct even if blocks are reordered.
                let is_self_loop = latch_blocks.contains(&bid);
                let loop_body_set = compute_natural_loop(bid, &latch_blocks, all_succs, all_preds);
                let body_ids: Vec<BlockId> = block_order
                    .iter()
                    .copied()
                    .filter(|&b| b != bid && loop_body_set.contains(&b) && !processed.contains(&b))
                    .collect();

                // Mark header + body as processed
                for &b in &body_ids {
                    processed.insert(b);
                }

                // Determine which successor is the loop body entry vs exit
                // For conditional: the branch that stays in the loop is the body
                // Pass nested loop info so break/continue work inside
                let inner_loop_headers: BTreeSet<BlockId> = loop_headers
                    .iter()
                    .filter(|&&h| h > bid && h <= max_latch)
                    .copied()
                    .collect();
                let inner_back_edges: Vec<(BlockId, BlockId)> = back_edges
                    .iter()
                    .filter(|(latch, target)| {
                        *latch > bid && *latch <= max_latch && inner_loop_headers.contains(target)
                    })
                    .cloned()
                    .collect();

                let mut body = structure_blocks_inner(
                    &body_ids,
                    block_map,
                    all_succs,
                    all_preds,
                    &inner_loop_headers,
                    &inner_back_edges,
                    ipdom,
                    phi_copies,
                    exc_handlers,
                    depth.saturating_add(1),
                );

                // Self-loop: the header IS the loop body. Re-emit its ops
                // as the loop body since they were already emitted above as
                // the loop "setup" but are actually the iterated computation.
                if is_self_loop && body.is_empty() {
                    body = emit_block_ops(block, phi_copies);
                }

                // `None` renders as `while (true)` — legitimate infinite loop
                // from `while(true)` / `for(;;)` / `do-while(true)` source.
                stmts.push(Stmt::While {
                    cond: loop_cond,
                    body,
                });
                continue;
            }
        }

        // Emit this block's operations
        stmts.extend(emit_block_ops(block, phi_copies));

        // Handle terminator
        let Some(last) = block.ops.last() else {
            continue;
        };

        if last.name == "Ret" {
            if let Some(SsaOperand::Var(v)) = last.operands.first() {
                stmts.push(Stmt::Return(Some(*v)));
            } else {
                stmts.push(Stmt::Return(None));
            }
        } else if last.name == "Throw" {
            if let Some(SsaOperand::Var(v)) = last.operands.first() {
                stmts.push(Stmt::Throw(*v));
            }
        } else if last.original.name.contains("SwitchImm") {
            // Multi-way branch: emit as switch statement
            let discriminant = match last.operands.first() {
                Some(SsaOperand::Var(v)) => *v,
                _ => VarId(u32::MAX, u32::MAX),
            };
            let is_string_switch = last.original.name == "StringSwitchImm";
            let min_case = if is_string_switch {
                0 // StringSwitchImm cases are indexed by string ID, not min/max
            } else {
                min_case_from_switch(last)
            };

            let succs = &block.successors;
            if succs.is_empty() {
                continue;
            }
            // First successor is the default target, rest are case targets
            let default_target = succs.first().copied();
            let case_targets = &succs[1..];

            let mut cases = Vec::new();
            for (i, &target) in case_targets.iter().enumerate() {
                if processed.contains(&target) {
                    continue;
                }
                processed.insert(target);
                let case_val = if is_string_switch {
                    // Encode string ID for resolution at emit time
                    if let Some(&str_id) = block.switch_string_ids.get(i) {
                        format!("__str_case_{str_id}")
                    } else {
                        format!("{i}")
                    }
                } else {
                    #[allow(clippy::as_conversions, reason = "usize→i64 widens on every project-supported target; `i` is a switch-table index bounded by `n_cases`.")]
                    let i_i64 = i as i64;
                    format!("{}", min_case.saturating_add(i_i64))
                };
                let case_body = if let Some(case_block) = block_map.get(&target) {
                    let mut body = emit_block_ops(case_block, phi_copies);
                    // Check if case block ends with Ret
                    if let Some(case_last) = case_block.ops.last()
                        && case_last.name == "Ret"
                    {
                        if let Some(SsaOperand::Var(v)) = case_last.operands.first() {
                            body.push(Stmt::Return(Some(*v)));
                        } else {
                            body.push(Stmt::Return(None));
                        }
                    }
                    body
                } else {
                    vec![]
                };
                cases.push((case_val, case_body));
            }

            // Default case
            let default_body = if let Some(dt) = default_target {
                if !processed.contains(&dt) {
                    processed.insert(dt);
                    if let Some(def_block) = block_map.get(&dt) {
                        let mut body = emit_block_ops(def_block, phi_copies);
                        if let Some(def_last) = def_block.ops.last()
                            && def_last.name == "Ret"
                        {
                            if let Some(SsaOperand::Var(v)) = def_last.operands.first() {
                                body.push(Stmt::Return(Some(*v)));
                            } else {
                                body.push(Stmt::Return(None));
                            }
                        }
                        body
                    } else {
                        vec![]
                    }
                } else {
                    vec![]
                }
            } else {
                vec![]
            };

            if !cases.is_empty() {
                stmts.push(Stmt::Switch {
                    discriminant,
                    cases,
                    default: default_body,
                });
            }
        } else if last.original.is_unconditional_jump() {
            if let Some(target) = last.original.branch_target() {
                if loop_headers.contains(&target) && processed.contains(&target) {
                    stmts.push(Stmt::Continue(None));
                } else if !order_set.contains(&target) && !processed.contains(&target) {
                    // Jump to outside the current region — emitted as comment because
                    // we may not be inside a loop/switch context. Phase 2 (dispatcher
                    // emission) will use real Stmt::Break with labels.
                    stmts.push(Stmt::Comment("break".to_string()));
                }
            }
        } else if last.original.is_conditional_branch() {
            let cond = extract_condition(block);
            let target = last.original.branch_target();

            let succs = &block.successors;
            if succs.len() == 2 {
                let merge = find_merge_point(bid, succs, ipdom);

                // Determine then/else targets
                // For JmpFalse/JNotX: target is "else" (skip), fallthrough is "then"
                // For JmpTrue/JX: target is "then" (take), fallthrough is "else"
                let is_negated = last.name.contains("False") || last.name.contains("Not");
                let (then_target, else_target) = if is_negated {
                    (succs.iter().find(|&&s| Some(s) != target).copied(), target)
                } else {
                    (target, succs.iter().find(|&&s| Some(s) != target).copied())
                };

                // Collect blocks in the then-branch (between then_target and merge)
                let then_blocks: Vec<BlockId> = if let (Some(tt), Some(merge_id)) =
                    (then_target, merge)
                {
                    block_order
                        .iter()
                        .copied()
                        .filter(|&b| {
                            b >= tt
                                && b < merge_id
                                && !processed.contains(&b)
                                && order_set.contains(&b)
                        })
                        .collect()
                } else if let Some(tt) = then_target {
                    // No merge point — claim all blocks from then_target onwards
                    block_order
                        .iter()
                        .copied()
                        .filter(|&b| b >= tt && !processed.contains(&b) && order_set.contains(&b))
                        .collect()
                } else {
                    vec![]
                };

                let else_blocks: Vec<BlockId> =
                    if let (Some(et), Some(merge_id)) = (else_target, merge) {
                        block_order
                            .iter()
                            .copied()
                            .filter(|&b| {
                                b >= et
                                    && b < merge_id
                                    && !processed.contains(&b)
                                    && !then_blocks.contains(&b)
                                    && order_set.contains(&b)
                            })
                            .collect()
                    } else if let Some(et) = else_target {
                        block_order
                            .iter()
                            .copied()
                            .filter(|&b| {
                                b >= et
                                    && !processed.contains(&b)
                                    && !then_blocks.contains(&b)
                                    && order_set.contains(&b)
                            })
                            .collect()
                    } else {
                        vec![]
                    };

                // Mark blocks as processed
                for &b in &then_blocks {
                    processed.insert(b);
                }
                for &b in &else_blocks {
                    processed.insert(b);
                }

                // If both branches end with return/throw, the merge point
                // will never be reached via these branches — don't mark it.
                // Otherwise, the merge point continues after the if/else.

                // Recursively structure the then and else regions
                let then_body = structure_blocks_inner(
                    &then_blocks,
                    block_map,
                    all_succs,
                    all_preds,
                    loop_headers,
                    back_edges,
                    ipdom,
                    phi_copies,
                    exc_handlers,
                    depth.saturating_add(1),
                );
                let else_body = structure_blocks_inner(
                    &else_blocks,
                    block_map,
                    all_succs,
                    all_preds,
                    loop_headers,
                    back_edges,
                    ipdom,
                    phi_copies,
                    exc_handlers,
                    depth.saturating_add(1),
                );

                if let Some(cond) = cond {
                    // When is_negated (JmpFalse/JNotX), branches are already swapped
                    // (then=fallthrough, else=target). Negate the condition to cancel
                    // the double-negation: Falsy(v) renders as !v, but the branch swap
                    // already accounts for it, so flip to Truthy(v) → v.
                    let cond = if is_negated {
                        negate_condition(cond)
                    } else {
                        cond
                    };
                    stmts.push(Stmt::If {
                        cond,
                        then_body,
                        else_body,
                    });
                }
            }
        }
    }

    stmts
}

// --- Emitter ---

/// SSA variable names are now valid JS identifiers (r0_1 format).
/// This function exists for backward compatibility but is a no-op.
fn sanitize(s: &str) -> String {
    s.to_string()
}

/// Count how many times each `VarId` appears as an operand across all
/// statements. Non-VarId identifier strings (renamed display forms,
/// literal constants, member-access chains, etc.) are silently dropped —
/// they couldn't be looked up by `VarId` downstream anyway, and the
/// previous `BTreeMap<String, _>` shape never inserted them as keys
/// downstream consumers searched for.
fn count_var_uses(stmts: &[Stmt]) -> BTreeMap<VarId, usize> {
    let mut uses: BTreeMap<VarId, usize> = BTreeMap::new();

    fn bump(uses: &mut BTreeMap<VarId, usize>, key: VarId) {
        uses.entry(key)
            .and_modify(|n| *n = n.saturating_add(1))
            .or_insert(1);
    }

    /// Parse a VarId-format identifier string (from a Stmt field like
    /// `Destructure.object`) and bump if it parses; drop otherwise.
    fn bump_str(uses: &mut BTreeMap<VarId, usize>, s: &str) {
        if let Some(v) = VarId::from_display_str(s) {
            bump(uses, v);
        }
    }

    fn walk(stmts: &[Stmt], uses: &mut BTreeMap<VarId, usize>) {
        for stmt in stmts {
            match stmt {
                Stmt::Assign { op, .. } | Stmt::Op(op) => {
                    for operand in &op.operands {
                        if let SsaOperand::Var(v) = operand {
                            bump(uses, *v);
                        }
                    }
                }
                Stmt::Return(Some(v)) | Stmt::Throw(v) => {
                    bump(uses, *v);
                }
                Stmt::If {
                    cond,
                    then_body,
                    else_body,
                } => {
                    match cond {
                        Condition::Truthy(v)
                        | Condition::Falsy(v)
                        | Condition::IsUndefined(v)
                        | Condition::NotUndefined(v) => {
                            bump(uses, *v);
                        }
                        Condition::Compare { left, right, .. } => {
                            bump(uses, *left);
                            bump(uses, *right);
                        }
                    }
                    walk(then_body, uses);
                    walk(else_body, uses);
                }
                Stmt::While { cond, body } => {
                    // Unconditional loop (`cond = None`) has no operand uses.
                    if let Some(cond) = cond {
                        match cond {
                            Condition::Truthy(v)
                            | Condition::Falsy(v)
                            | Condition::IsUndefined(v)
                            | Condition::NotUndefined(v) => {
                                bump(uses, *v);
                            }
                            Condition::Compare { left, right, .. } => {
                                bump(uses, *left);
                                bump(uses, *right);
                            }
                        }
                    }
                    walk(body, uses);
                }
                Stmt::ForIn { key, obj, body } => {
                    bump(uses, *key);
                    bump(uses, *obj);
                    walk(body, uses);
                }
                Stmt::Switch {
                    discriminant,
                    cases,
                    default,
                } => {
                    bump(uses, *discriminant);
                    for (label, body) in cases {
                        // Case labels are case-value strings (e.g.
                        // `"42"`, `"\"foo\""`, occasionally a VarId-
                        // format `"r3_0"` reference). Parse-and-bump
                        // on the VarId-format minority; literals drop.
                        bump_str(uses, label);
                        walk(body, uses);
                    }
                    walk(default, uses);
                }
                Stmt::TryCatch {
                    try_body,
                    catch_body,
                    ..
                } => {
                    walk(try_body, uses);
                    walk(catch_body, uses);
                }
                Stmt::Destructure { object, bindings } => {
                    bump_str(uses, object);
                    for (_, dst) in bindings {
                        bump_str(uses, dst);
                    }
                }
                Stmt::DestructureWithDefault {
                    object,
                    target_receiver,
                    path,
                    ..
                } => {
                    bump_str(uses, object);
                    // Preserve the consumed PutBy*'s receiver as a use so
                    // inline-eligibility decisions elsewhere in the function
                    // don't see a spurious count drop.
                    bump_str(uses, target_receiver);
                    // Walk the path, bumping each computed-key VarId ref.
                    // Static keys are literal property names, not SSA refs.
                    fn visit(p: &DestructurePath, uses: &mut BTreeMap<VarId, usize>) {
                        let (key, next) = match p {
                            DestructurePath::Leaf { key } => (key, None),
                            DestructurePath::Nested { key, inner } => (key, Some(inner.as_ref())),
                        };
                        if let DestructureKey::Computed(v) = key {
                            bump_str(uses, v);
                        }
                        if let Some(inner) = next {
                            visit(inner, uses);
                        }
                    }
                    visit(path, uses);
                }
                Stmt::Import { name, .. } => {
                    bump_str(uses, name);
                }
                Stmt::ExportDefault { value } => {
                    bump_str(uses, value);
                }
                Stmt::ExportNamed { value, .. } => {
                    bump_str(uses, value);
                }
                Stmt::PhiAssign { src, .. } => {
                    bump_str(uses, src);
                }
                Stmt::Labeled { body, .. } => {
                    walk(body, uses);
                }
                Stmt::Class {
                    extends,
                    methods,
                    static_fields,
                    ..
                } => {
                    if let Some(parent) = extends {
                        bump_str(uses, parent);
                    }
                    for (_, method_var) in methods {
                        bump_str(uses, method_var);
                    }
                    for field in static_fields {
                        bump_str(uses, &field.value);
                    }
                }
                _ => {}
            }
        }
    }

    walk(stmts, &mut uses);
    uses
}

/// Check if an op has side effects (calls, stores, throws).
fn op_has_side_effects(name: &str) -> bool {
    super::expr::has_side_effects(name)
}

/// Return the set of closure-op dst names that `optimize::name_variables`
/// renamed to a JS-valid identifier — the module-hoist triad anchors that
/// `strip_module_hoist_preamble` (emit.rs) matches by text shape.
/// Result of rest-parameter sugar detection. `start_idx` is the user-
/// visible param index where the rest-param begins (0 means the function
/// has NO declared non-rest params — signature is `(...rest)`). `call_dst_key`
/// is the VarId identifying the copyRestArgs call's dst so the emit path
/// can skip its Stmt::Assign and rewrite use sites.
/// `rest_name` is the rest-param identifier (from IPA / var_names if
/// available, else `rest`).
struct RestParamSugar {
    start_idx: u32,
    call_dst_key: VarId,
    rest_name: String,
}

/// Detect the `var rest = HermesBuiltin.copyRestArgs(startIdx)` pattern
/// at the head of a function body. Returns `Some(RestParamSugar)` when
/// the first non-synthetic Stmt::Assign matches; `None` otherwise.
/// Tolerates leading `PhiAssign`s (which hermesc-emitted rest-param
/// functions don't produce but adversarial HBC might).
fn detect_rest_param_sugar(
    body: &[Stmt],
    var_names: &BTreeMap<super::ssa::VarId, String>,
    declared_params: &[String],
) -> Option<RestParamSugar> {
    for (stmt_idx, stmt) in body.iter().enumerate() {
        let Stmt::Assign { op, .. } = stmt else {
            // PhiAssign / Op / Return / etc. — skip through PhiAssigns
            // but bail on the first non-Assign/non-PhiAssign to avoid
            // hoisting across control-flow boundaries.
            match stmt {
                Stmt::PhiAssign { .. } => continue,
                _ => return None,
            }
        };
        // Skip leading LoadConst* ops that set up the startIdx arg
        // register for the CallBuiltin below. Hermes emits
        // `LoadConstZero` / `LoadConstUInt8` immediately before
        // `CallBuiltin copyRestArgs, 2` to load the startIdx constant.
        // Any other op kind before the CallBuiltin breaks the pattern
        // (e.g. a regular property access means the function has real
        // body ops first — not rest-params sugar).
        if op.name.starts_with("LoadConst") {
            continue;
        }
        if op.name != "CallBuiltin" && op.name != "CallBuiltinLong" {
            return None;
        }
        let Some(super::ssa::SsaOperand::Const(id)) = op.operands.get(1) else {
            return None;
        };
        super::expr::is_copy_rest_args(const_id_to_u32(*id))?;
        // Operand[3] is arg0 after the frame-relative variadic resolver:
        // `startIdx` (the count of non-rest declared params). Usually a
        // `Var` referencing an earlier `LoadConstZero` / `LoadConstUInt8`
        // since constant propagation doesn't dissolve Var→LoadConst
        // edges. Chase the Var backward to its defining Stmt and
        // extract the immediate; bail if the chase fails. Already-
        // folded `Const(n)` is accepted directly as an adversarial-
        // shape tolerance.
        let start_idx = match op.operands.get(3) {
            Some(super::ssa::SsaOperand::Const(n)) if *n >= 0 => const_id_to_u32(*n),
            Some(super::ssa::SsaOperand::Var(target)) => {
                let mut found = None;
                for earlier in body.iter().take(stmt_idx) {
                    if let Stmt::Assign { op: earlier_op, .. } = earlier
                        && earlier_op.dst == Some(*target)
                    {
                        match earlier_op.name {
                            "LoadConstZero" => {
                                found = Some(0u32);
                            }
                            "LoadConstUInt8" | "LoadConstInt" => {
                                if let Some(super::ssa::SsaOperand::Const(n)) =
                                    earlier_op.operands.get(1)
                                    && *n >= 0
                                {
                                    found = Some(const_id_to_u32(*n));
                                }
                            }
                            _ => {}
                        }
                    }
                }
                found?
            }
            // Missing / non-Const / non-Var (e.g. ResolvedString): bail.
            _ => return None,
        };
        // `startIdx` must not exceed the declared param count (a
        // well-formed hermesc rest-param points at the slot immediately
        // after all declared non-rest params). Exceeding that is a
        // corrupt input; leave the call visible.
        // WHY: u32→usize widens on every project-supported target.
        #[allow(clippy::as_conversions, reason = "u32→usize widens on every project-supported target.")]
        let start_idx_usize = start_idx as usize;
        if start_idx_usize > declared_params.len() {
            return None;
        }
        let call_dst = op.dst?;
        let rest_name = var_names
            .get(&call_dst)
            .cloned()
            .filter(|s| super::expr::is_valid_js_ident(s))
            .unwrap_or_else(|| "rest".to_string());
        return Some(RestParamSugar {
            start_idx,
            call_dst_key: call_dst,
            rest_name,
        });
    }
    None
}

fn collect_named_closure_dsts(
    stmts: &[Stmt],
    var_names: &BTreeMap<VarId, String>,
) -> BTreeSet<VarId> {
    let mut out = BTreeSet::new();
    fn walk(stmts: &[Stmt], var_names: &BTreeMap<VarId, String>, out: &mut BTreeSet<VarId>) {
        for stmt in stmts {
            match stmt {
                Stmt::Assign { op, .. } => {
                    if is_create_closure_op(op.name)
                        && let Some(var_id) = op.dst
                        && let Some(renamed) = var_names.get(&var_id)
                        && renamed != &format!("{var_id}")
                        && super::expr::is_valid_js_ident(renamed)
                    {
                        out.insert(var_id);
                    }
                }
                Stmt::If {
                    then_body,
                    else_body,
                    ..
                } => {
                    walk(then_body, var_names, out);
                    walk(else_body, var_names, out);
                }
                Stmt::While { body, .. } | Stmt::ForIn { body, .. } => {
                    walk(body, var_names, out);
                }
                Stmt::Switch { cases, default, .. } => {
                    for (_, body) in cases {
                        walk(body, var_names, out);
                    }
                    walk(default, var_names, out);
                }
                Stmt::TryCatch {
                    try_body,
                    catch_body,
                    ..
                } => {
                    walk(try_body, var_names, out);
                    walk(catch_body, var_names, out);
                }
                Stmt::Labeled { body, .. } => {
                    walk(body, var_names, out);
                }
                _ => {}
            }
        }
    }
    walk(stmts, var_names, &mut out);
    out
}

/// True for the eight closure-allocating opcodes. Flagged side-effecting in
/// `is_pure_op` (to preserve the hoist-triad anchor for emit.rs), but
/// inline-eligible when anonymous — see `build_inline_map`.
fn is_create_closure_op(name: &str) -> bool {
    matches!(
        name,
        "CreateClosure"
            | "CreateClosureLongIndex"
            | "CreateAsyncClosure"
            | "CreateAsyncClosureLongIndex"
            | "CreateGenerator"
            | "CreateGeneratorClosure"
            | "CreateGeneratorClosureLongIndex"
            | "CreateGeneratorLongIndex"
    )
}

/// Build a map of variable name → inlined expression tree for single-use,
/// non-side-effect assignments. Uses `Expr` trees for correct substitution.
///
/// `named_closure_dsts` names the closure dsts that must stay standalone
/// (the hoist-triad anchors); anonymous closures inline through the normal
/// `use_count == 1` gate plus a closure-specific bypass of the purity test.
pub fn build_inline_map(
    stmts: &[Stmt],
    get_str: &dyn Fn(u32) -> String,
    named_closure_dsts: &BTreeSet<VarId>,
) -> BTreeMap<VarId, super::expr::Expr> {
    let uses = count_var_uses(stmts);
    let mut inline_map: BTreeMap<VarId, super::expr::Expr> = BTreeMap::new();

    fn collect(
        stmts: &[Stmt],
        uses: &BTreeMap<VarId, usize>,
        inline_map: &mut BTreeMap<VarId, super::expr::Expr>,
        get_str: &dyn Fn(u32) -> String,
        named_closure_dsts: &BTreeSet<VarId>,
        depth: usize,
    ) {
        for stmt in stmts {
            match stmt {
                Stmt::Assign { op, .. } => {
                    // The canonical lookup key is `op.dst` (Option<VarId>);
                    // the renamed `dst: Rc<str>` is the display form, not
                    // the map key. SsaOp::dst is None for void-result ops
                    // (Call*-no-result, Store*, etc.) which we don't inline.
                    let Some(var_id) = op.dst else {
                        continue;
                    };
                    // SEMANTICS-DEFAULT-EMPTY: `count_var_uses` only
                    // inserts a VarId when it appears as a read operand;
                    // absent key means 0 uses.
                    let use_count = uses.get(&var_id).copied().unwrap_or(0);
                    // `depth == 0` prevents cross-branch moves (use-before-def).
                    // Anonymous `CreateClosure*` is the hermesc-emitted shape
                    // for inline callable args (`.then(fn(){...})`); fold it
                    // into the use site. Named closures stay standalone for
                    // the emit.rs preamble stripper.
                    let pure = !op_has_side_effects(op.name);
                    let closure_arg_inlineable =
                        is_create_closure_op(op.name) && !named_closure_dsts.contains(&var_id);
                    if use_count == 1 && (pure || closure_arg_inlineable) && depth == 0 {
                        let expr = super::expr::build_expr(op, get_str);
                        inline_map.insert(var_id, expr);
                    }
                }
                Stmt::If {
                    then_body,
                    else_body,
                    ..
                } => {
                    collect(
                        then_body,
                        uses,
                        inline_map,
                        get_str,
                        named_closure_dsts,
                        depth.saturating_add(1),
                    );
                    collect(
                        else_body,
                        uses,
                        inline_map,
                        get_str,
                        named_closure_dsts,
                        depth.saturating_add(1),
                    );
                }
                Stmt::While { body, .. } | Stmt::ForIn { body, .. } => {
                    collect(
                        body,
                        uses,
                        inline_map,
                        get_str,
                        named_closure_dsts,
                        depth.saturating_add(1),
                    );
                }
                Stmt::Switch { cases, default, .. } => {
                    for (_, body) in cases {
                        collect(
                            body,
                            uses,
                            inline_map,
                            get_str,
                            named_closure_dsts,
                            depth.saturating_add(1),
                        );
                    }
                    collect(
                        default,
                        uses,
                        inline_map,
                        get_str,
                        named_closure_dsts,
                        depth.saturating_add(1),
                    );
                }
                Stmt::TryCatch {
                    try_body,
                    catch_body,
                    ..
                } => {
                    collect(
                        try_body,
                        uses,
                        inline_map,
                        get_str,
                        named_closure_dsts,
                        depth.saturating_add(1),
                    );
                    collect(
                        catch_body,
                        uses,
                        inline_map,
                        get_str,
                        named_closure_dsts,
                        depth.saturating_add(1),
                    );
                }
                Stmt::Labeled { body, .. } => {
                    collect(
                        body,
                        uses,
                        inline_map,
                        get_str,
                        named_closure_dsts,
                        depth.saturating_add(1),
                    );
                }
                _ => {}
            }
        }
    }

    collect(
        stmts,
        &uses,
        &mut inline_map,
        get_str,
        named_closure_dsts,
        0,
    );
    inline_map
}

/// Resolve a variable name through the inline map using tree-based substitution.
/// Sanitizes Hermes internal characters (? in names) to valid JS identifiers.
///
/// `name` is the textual identifier from a Stmt field; if it parses as a
/// canonical `VarId` (`"r{reg}_{ver}"`), the lookup goes through the
/// VarId-keyed `inline_map`. Non-canonical names (literal constants,
/// renamed display forms, member-access chains) round-trip unchanged —
/// they were never inserted into the map by `build_inline_map`.
fn resolve_var(name: &str, inline_map: &BTreeMap<VarId, super::expr::Expr>) -> String {
    let raw = match VarId::from_display_str(name).and_then(|v| inline_map.get(&v)) {
        Some(expr) => {
            let resolved = expr.clone().substitute(inline_map);
            format!("{resolved}")
        }
        None => name.to_string(),
    };
    // Sanitize Hermes internal names: ?anon_0_foo → _anon_0_foo
    if raw.contains('?') {
        raw.replace('?', "_")
    } else {
        raw
    }
}

impl StructuredFunction {
    /// Apply ESM recovery: require() → import, exports.x → export
    pub fn apply_esm(
        &mut self,
        get_str: &dyn Fn(u32) -> String,
        get_module_name: &dyn Fn(i64) -> Option<String>,
    ) {
        self.body = apply_deep(std::mem::take(&mut self.body), &|stmts| {
            recover_esm_one_level(stmts, get_str, get_module_name)
        });
    }

    /// Emit with sanitized variable names (valid-ish JS identifiers).
    pub fn emit_js(&self, get_str: &dyn Fn(u32) -> String) -> String {
        let raw = self.emit(get_str);
        sanitize(&raw)
    }

    pub fn emit(&self, get_str: &dyn Fn(u32) -> String) -> String {
        let mut out = String::new();
        let mut modifiers = String::new();
        if self.is_async {
            modifiers.push_str("async ");
        }
        let star = if self.is_generator { "*" } else { "" };
        // param_count includes `this` (param 0) — user-visible params start at 1
        let user_params = self.params.saturating_sub(1);
        let mut params: Vec<String> = (0..user_params)
            .map(|i| {
                self.param_names
                    .get(&i)
                    .cloned()
                    .unwrap_or_else(|| format!("a{i}"))
            })
            .collect();

        // Rest-parameter sugar: scan the leading ops of the body for the
        // `var rest = HermesBuiltin.copyRestArgs(startIdx)` pattern that
        // hermesc emits for `function f(...rest) { ... }`. If detected,
        // hoist into the signature + rewrite use sites.
        //
        // Shape check: first non-`PhiAssign` stmt is `Stmt::Assign` whose
        // op is `CallBuiltin copyRestArgs` with argc=2 and operand[3]
        // (first explicit arg, resolved by the frame-relative variadic
        // pass) is a `Const(startIdx)` — or a `Var` referencing a
        // LoadConst we can chase. `startIdx` equals the number of non-rest
        // user params; the rest-param appears at `params[startIdx]`.
        //
        // Elision contract: the `var rest = copyRestArgs(..)` Stmt::Assign
        // must be added to `skip_set` so emit doesn't re-print the now-
        // obsolete `var r1_1 = ...` line, AND the dst VarId must resolve
        // to the rest-param name at use sites (via `inline_map` Raw
        // injection, the same mechanism var_names uses for display
        // rename). Both are applied inside the sibling `inline_map`
        // setup block below.
        let rest_param_sugar = detect_rest_param_sugar(&self.body, &self.var_names, &params);
        let mut rest_skip_keys: BTreeSet<VarId> = BTreeSet::new();
        if let Some(sugar) = &rest_param_sugar {
            // WHY: u32→usize widens on every project-supported target.
            #[allow(clippy::as_conversions, reason = "u32→usize widens on every project-supported target.")]
            let start = sugar.start_idx as usize;
            if start <= params.len() {
                params.truncate(start);
            }
            params.push(format!("...{}", sugar.rest_name));
            rest_skip_keys.insert(sugar.call_dst_key);
        }
        // Sanitize Hermes internal names:
        // - ?anon_0_counter → _anon_0_counter (generators)
        // - "get PropertyName" → get_PropertyName (getter/setter)
        // - names with non-identifier chars → replace with _
        let sanitized_name;
        let name = if self.name.is_empty() {
            "anonymous"
        } else if is_valid_js_identifier(&self.name) {
            &self.name
        } else {
            // Sanitize: replace non-identifier chars with _, prefix if starts with digit or is reserved
            let mut s: String = self
                .name
                .chars()
                .map(|c| {
                    if c.is_ascii_alphanumeric() || c == '_' || c == '$' {
                        c
                    } else {
                        '_'
                    }
                })
                .collect();
            if s.starts_with(|c: char| c.is_ascii_digit()) || is_js_reserved(&s) {
                s.insert(0, '_');
            }
            sanitized_name = s;
            &sanitized_name
        };

        // Build inline map for single-use variables.
        //
        // IMPORTANT: `inline_map` is used for *substitution* (resolve_var,
        // format_op_inline, format_cond_inline) at use sites. The defining
        // Stmt::Assign for a key in `inline_map` is skipped at emit time
        // because the expression is inlined into its single use.
        //
        // `var_names` (from name_variables / coalesce_phi_names) is a
        // *rename* map — it changes how a dst is *displayed*, but the
        // defining statement must still emit. Merging var_names into the
        // skip-source caused side-effecting Calls / CreateClosures to be
        // dropped (bug taxonomy P0, classes #1–#4).
        //
        // Fix: keep build_inline_map's output as the canonical skip set
        // (`skip_set`); merge var_names into the substitution view
        // (`inline_map`) so use sites still pick up the rename.
        // Hoist-triad anchors must stay standalone — see `build_inline_map`
        // and `strip_module_hoist_preamble` (emit.rs) for the pairing.
        let named_closure_dsts = collect_named_closure_dsts(&self.body, &self.var_names);
        let inline_exprs = build_inline_map(&self.body, get_str, &named_closure_dsts);
        let mut skip_set: BTreeSet<VarId> = inline_exprs.keys().copied().collect();
        let mut inline_map = inline_exprs;
        // Rest-param sugar: skip the `copyRestArgs` defining stmt + map
        // its dst to the rest-param name. Emit path's Raw substitution
        // replaces `r_dst.length` → `rest.length` etc.
        if let Some(sugar) = &rest_param_sugar {
            skip_set.extend(rest_skip_keys.iter().copied());
            inline_map.insert(
                sugar.call_dst_key,
                super::expr::Expr::Raw(sugar.rest_name.clone()),
            );
        }

        for (var_id, var_name) in &self.var_names {
            // If the existing inline entry is just a `Expr::Param { index }`
            // (which formats as the canonical `aN` regardless of IPA rename)
            // and `var_names` has a different display name, prefer the rename.
            // Otherwise keep the structured Expr (constants, computed chains).
            match inline_map.get(var_id) {
                Some(super::expr::Expr::Param { index }) => {
                    let canonical = if *index == 0 {
                        "this".to_string()
                    } else {
                        format!("a{}", index.saturating_sub(1))
                    };
                    if *var_name != canonical {
                        inline_map.insert(*var_id, super::expr::Expr::Raw(var_name.clone()));
                    }
                }
                Some(_) => {}
                None => {
                    inline_map.insert(*var_id, super::expr::Expr::Raw(var_name.clone()));
                }
            }
        }

        if self.is_arrow {
            // Arrow function: (params) => { body }
            out.push_str(&format!("{}({}) => {{\n", modifiers, params.join(", ")));
        } else {
            out.push_str(&format!(
                "{}function{star} {name}({}) {{\n",
                modifiers,
                params.join(", ")
            ));
        }

        let mut declared = BTreeSet::new();
        for stmt in &self.body {
            emit_stmt(
                &mut out,
                stmt,
                1,
                get_str,
                &inline_map,
                &skip_set,
                &params,
                &mut declared,
            );
        }

        out.push_str("}\n");
        out
    }
}

// Legacy emitter shared between the legacy and region paths — the
// parameter list carries the full emit context (get_str resolver,
// inline map, skip set, params, declared set). Refactoring into a
// struct would churn every call site for minimal benefit; the
// warning is a style hint, not a bug.
#[allow(clippy::too_many_arguments, reason = "Many-arg signature reflects the parser/structurer threading multiple bytecode-version contexts; bundling into a context struct would relocate field listing rather than eliminate it.")]
fn emit_stmt(
    out: &mut String,
    stmt: &Stmt,
    indent: usize,
    get_str: &dyn Fn(u32) -> String,
    inline_map: &BTreeMap<VarId, super::expr::Expr>,
    skip_set: &BTreeSet<VarId>,
    params: &[String],
    declared: &mut BTreeSet<String>,
) {
    let pad = "  ".repeat(indent);
    match stmt {
        Stmt::Assign { dst, op, .. } => {
            // Skip assignments that were inlined at their use site.
            // Only skip if the dst was a true single-use inlining target —
            // not just a rename. See StructuredFunction::emit for the split.
            // `op.dst` is the canonical VarId; `Stmt::Assign` always has
            // it (the dst-less SSA ops surface as `Stmt::Op` instead).
            if let Some(var_id) = op.dst
                && skip_set.contains(&var_id)
            {
                return;
            }
            // Resolve the dst name through var_names (might be "false", "true", etc.)
            let resolved_dst = resolve_var(dst.as_ref(), inline_map);
            // LoadParam: synthetic op for "this is parameter N." If the dst's
            // resolved name still matches the parameter name as it appears in
            // the function signature (`this`, the IPA-named slot, or the
            // canonical `aN`), the parameter is already declared and
            // emitting `var a0 = a0;` is a no-op self-write.
            // BUT if coalesce_phi_names has merged the LoadParam dst into a
            // phi group with a *different* shared name, the LoadParam now
            // means "copy the param into the shared slot" — that's a real
            // assignment and must emit.
            if matches!(op.name, "LoadParam" | "LoadParamLong")
                && let Some(SsaOperand::Const(idx)) = op.operands.get(1)
            {
                let canonical = if *idx == 0 {
                    "this".to_string()
                } else {
                    format!("a{}", idx.saturating_sub(1))
                };
                let signature_name = if *idx == 0 {
                    None
                } else {
                    // WHY: u32→usize widens on every project-supported target.
                    #[allow(clippy::as_conversions, reason = "u32→usize widens on every project-supported target.")]
                    let idx_usize = *idx as usize;
                    params.get(idx_usize.saturating_sub(1)).cloned()
                };
                if resolved_dst == canonical
                    || signature_name.as_deref() == Some(resolved_dst.as_str())
                {
                    return;
                }
            }
            // Comment out assignments to reserved literals (false = x is invalid JS)
            if is_js_reserved(&resolved_dst) {
                out.push_str(&format!(
                    "{pad}// {resolved_dst} = {};\n",
                    format_op_inline(op, get_str, inline_map)
                ));
                return;
            }
            let dst_display: &str = if *resolved_dst != **dst {
                &resolved_dst
            } else {
                dst.as_ref()
            };
            let dst_is_member = dst_display.contains('.') || dst_display.contains('[');
            let dst_is_invalid_lhs = dst_is_member || !is_valid_js_identifier(dst_display);
            // If the dst was *renamed* (by name_variables / IPA / coalesce_phi_names)
            // to a display form that isn't a valid binding LHS — typically a
            // member-access chain like `a0.value` — then this Stmt::Assign is a
            // *def whose value is meant to be re-read at use sites via the rename*,
            // not a real store. Emitting `a0.value = props.value;` is a no-op
            // self-write. The correct behaviour:
            //   - pure op: drop the statement; use sites resolve through inline_map
            //   - impure op (Call, etc.): keep the side effect, emit as a bare
            //     statement so the call still runs but the bogus binding is gone
            if dst_is_invalid_lhs && *resolved_dst != **dst {
                if !op_has_side_effects(op.name) {
                    return;
                }
                let rendered = format_op_inline(op, get_str, inline_map);
                out.push_str(&format!("{pad}{rendered};\n"));
                return;
            }
            // Don't emit `var` for member access names (e.g., "a1.startTime").
            // Key the `declared` set on the *display name* so coalesced SSA
            // versions sharing a single user-visible name get one `var` +
            // re-assigns. Also suppress `var` if the display name is already
            // a parameter (`this`, `aN`, or an IPA-renamed slot).
            let is_param = dst_display == "this"
                || params.iter().any(|p| p == dst_display)
                || (dst_display.starts_with('a')
                    && dst_display[1..].chars().all(|c| c.is_ascii_digit())
                    && !dst_display[1..].is_empty());
            let rendered = format_op_inline(op, get_str, inline_map);
            // Drop tautological self-assigns. Defs of LoadConstUndefined,
            // GetGlobalObject, etc. were named after their value by
            // `name_variables` (`undefined`, `globalThis`), so the def
            // collapses to `undefined = undefined;` after substitution.
            if *dst_display == rendered && !op_has_side_effects(op.name) {
                return;
            }
            let decl = if dst_is_invalid_lhs {
                ""
            } else if is_param {
                ""
            } else if declared.insert(dst_display.to_string()) {
                "var "
            } else {
                ""
            };
            out.push_str(&format!("{pad}{decl}{dst_display} = {rendered};\n"));
        }
        Stmt::Op(op) => {
            let rendered = format_op_inline(op, get_str, inline_map);
            // Wrap in parens if statement starts with { (ambiguous with block)
            let rendered = if rendered.starts_with('{') {
                format!("({rendered})")
            } else {
                rendered
            };
            // Skip statements that assign to reserved literals (e.g., "false = x")
            // PROOF: `str::split` always yields at least one item (the whole string for
            // an empty delimiter or empty input); `next()` is always Some here.
            let first_word = rendered
                .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                .next()
                .unwrap_or("");
            if is_js_reserved(first_word) && (rendered.contains(" = ") || rendered.contains('.')) {
                out.push_str(&format!("{pad}// {rendered};\n"));
            } else {
                out.push_str(&format!("{pad}{rendered};\n"));
            }
        }
        Stmt::Return(Some(v)) => {
            let val = resolve_var(&format!("{v}"), inline_map);
            out.push_str(&format!("{pad}return {val};\n"));
        }
        Stmt::Return(None) => out.push_str(&format!("{pad}return;\n")),
        Stmt::Throw(v) => {
            let val = resolve_var(&format!("{v}"), inline_map);
            out.push_str(&format!("{pad}throw {val};\n"));
        }
        Stmt::If {
            cond,
            then_body,
            else_body,
        } => {
            out.push_str(&format!(
                "{pad}if ({}) {{\n",
                format_cond_inline(cond, inline_map)
            ));
            for s in then_body {
                emit_stmt(
                    out,
                    s,
                    indent.saturating_add(1),
                    get_str,
                    inline_map,
                    skip_set,
                    params,
                    declared,
                );
            }
            if !else_body.is_empty() {
                out.push_str(&format!("{pad}}} else {{\n"));
                for s in else_body {
                    emit_stmt(
                        out,
                        s,
                        indent.saturating_add(1),
                        get_str,
                        inline_map,
                        skip_set,
                        params,
                        declared,
                    );
                }
            }
            out.push_str(&format!("{pad}}}\n"));
        }
        Stmt::While { cond, body } => {
            // `cond = None` renders as `while (true)` — literal infinite loop
            // from source-level `while(true)` / `for(;;)` / `do-while(true)`.
            let rendered = match cond {
                Some(c) => format_cond_inline(c, inline_map),
                None => "true".to_string(),
            };
            out.push_str(&format!("{pad}while ({rendered}) {{\n"));
            for s in body {
                emit_stmt(
                    out,
                    s,
                    indent.saturating_add(1),
                    get_str,
                    inline_map,
                    skip_set,
                    params,
                    declared,
                );
            }
            out.push_str(&format!("{pad}}}\n"));
        }
        Stmt::TryCatch {
            try_body,
            catch_var,
            catch_body,
        } => {
            out.push_str(&format!("{pad}try {{\n"));
            for s in try_body {
                emit_stmt(
                    out,
                    s,
                    indent.saturating_add(1),
                    get_str,
                    inline_map,
                    skip_set,
                    params,
                    declared,
                );
            }
            let catch_name = resolve_var(catch_var, inline_map);
            out.push_str(&format!("{pad}}} catch ({catch_name}) {{\n"));
            for s in catch_body {
                emit_stmt(
                    out,
                    s,
                    indent.saturating_add(1),
                    get_str,
                    inline_map,
                    skip_set,
                    params,
                    declared,
                );
            }
            out.push_str(&format!("{pad}}}\n"));
        }
        Stmt::ForIn { key, obj, body } => {
            let key_s = resolve_var(&format!("{key}"), inline_map);
            let obj_s = resolve_var(&format!("{obj}"), inline_map);
            out.push_str(&format!("{pad}for (var {key_s} in {obj_s}) {{\n"));
            for s in body {
                emit_stmt(
                    out,
                    s,
                    indent.saturating_add(1),
                    get_str,
                    inline_map,
                    skip_set,
                    params,
                    declared,
                );
            }
            out.push_str(&format!("{pad}}}\n"));
        }
        Stmt::Switch {
            discriminant,
            cases,
            default,
        } => {
            // Defensive contract: both upstream switch builders
            // (`structure.rs:1205` and `region.rs:1199`) fall
            // back to `VarId(u32::MAX, u32::MAX)` if the SwitchImm terminator's
            // discriminant slot is not `SsaOperand::Var`. That arm is
            // unreachable via well-formed HBC (slot 0 is `R`, always resolves
            // to `Var` post-SSA), but without the guard below the sentinel
            // would render as the identifier `r4294967295_4294967295` — a
            // syntactically-valid but semantically-nonexistent reference.
            // Rewrite the sentinel at the emit layer to an explicit
            // placeholder so a defensive path
            // triggered by a future refactor is loud, not silent.
            let disc_s = if *discriminant == VarId(u32::MAX, u32::MAX) {
                "/* missing switch discriminant */ undefined".to_string()
            } else {
                resolve_var(&format!("{discriminant}"), inline_map)
            };
            out.push_str(&format!("{pad}switch ({disc_s}) {{\n"));
            for (val, body) in cases {
                let val_resolved = if let Some(str_id_str) = val.strip_prefix("__str_case_") {
                    if let Ok(str_id) = str_id_str.parse::<u32>() {
                        format!("\"{}\"", get_str(str_id))
                    } else {
                        resolve_var(val, inline_map)
                    }
                } else {
                    resolve_var(val, inline_map)
                };
                out.push_str(&format!("{pad}  case {val_resolved}:\n"));
                for s in body {
                    emit_stmt(
                        out,
                        s,
                        indent.saturating_add(2),
                        get_str,
                        inline_map,
                        skip_set,
                        params,
                        declared,
                    );
                }
                // Add break if case doesn't end with return/throw
                let needs_break = !body
                    .iter()
                    .any(|s| matches!(s, Stmt::Return(_) | Stmt::Throw(_)));
                if needs_break {
                    let inner_pad = "  ".repeat(indent.saturating_add(2));
                    out.push_str(&format!("{inner_pad}break;\n"));
                }
            }
            if !default.is_empty() {
                out.push_str(&format!("{pad}  default:\n"));
                for s in default {
                    emit_stmt(
                        out,
                        s,
                        indent.saturating_add(2),
                        get_str,
                        inline_map,
                        skip_set,
                        params,
                        declared,
                    );
                }
            }
            out.push_str(&format!("{pad}}}\n"));
        }
        Stmt::Destructure { object, bindings } => {
            let obj_resolved = resolve_var(object, inline_map);
            // Check if any binding target contains `.` (member expression) —
            // can't use var { } destructuring with member targets, emit individual assigns
            let has_member_target = bindings.iter().any(|(_, dst)| {
                let r = resolve_var(dst, inline_map);
                r.contains('.')
            });
            if has_member_target {
                for (prop, dst) in bindings {
                    let dst_resolved = resolve_var(dst, inline_map);
                    let rhs = fmt_prop_access(&obj_resolved, prop);
                    // Skip tautological self-assigns. After IPA renaming,
                    // a destructure binding `r3_0 = opts.name` collapses to
                    // `opts.name = opts.name` because the GetById dst was
                    // already renamed to its display chain.
                    if dst_resolved == rhs {
                        continue;
                    }
                    out.push_str(&format!("{pad}{dst_resolved} = {rhs};\n"));
                }
                return;
            }
            let props: Vec<String> = bindings
                .iter()
                .map(|(prop, dst)| {
                    let dst_resolved = resolve_var(dst, inline_map);
                    if *prop == dst_resolved {
                        fmt_prop_key(prop)
                    } else {
                        format!("{}: {dst_resolved}", fmt_prop_key(prop))
                    }
                })
                .collect();
            out.push_str(&format!(
                "{pad}var {{ {} }} = {obj_resolved};\n",
                props.join(", ")
            ));
        }
        Stmt::DestructureWithDefault {
            object,
            target,
            default,
            path,
            ..
        } => {
            let obj_resolved = resolve_var(object, inline_map);
            let inner = render_destructure_path(path, target, default, inline_map);
            out.push_str(&format!("{pad}var {{ {inner} }} = {obj_resolved};\n"));
        }
        Stmt::Class {
            name,
            extends,
            methods,
            static_fields,
        } => {
            let name_resolved = resolve_var(name, inline_map);
            let ext = match extends {
                Some(parent) => format!(" extends {}", resolve_var(parent, inline_map)),
                None => String::new(),
            };
            out.push_str(&format!("{pad}class {name_resolved}{ext} {{\n"));
            for field in static_fields {
                let val = resolve_var(&field.value, inline_map);
                // `CreatePrivateName`'s stored string already carries the
                // leading `#` (Hermes stringifies private names as `#foo`);
                // don't double-prefix.
                let name_out = if field.is_private && !field.name.starts_with('#') {
                    format!("#{}", field.name)
                } else {
                    field.name.clone()
                };
                out.push_str(&format!("{pad}  static {name_out} = {val};\n"));
            }
            for (method_name, method_var) in methods {
                let val = resolve_var(method_var, inline_map);
                out.push_str(&format!("{pad}  {method_name}() {{ /* {val} */ }}\n"));
            }
            out.push_str(&format!("{pad}}}\n"));
        }
        Stmt::Import { name, source } => {
            out.push_str(&format!("{pad}import {name} from \"{source}\";\n"));
        }
        Stmt::ExportNamed { name, value } => {
            out.push_str(&format!("{pad}export const {name} = {value};\n"));
        }
        Stmt::ExportDefault { value } => {
            out.push_str(&format!("{pad}export default {value};\n"));
        }
        Stmt::PhiAssign { dst, src } => {
            let dst_resolved = resolve_var(dst.as_ref(), inline_map);
            let src_resolved = resolve_var(src.as_ref(), inline_map);
            // Skip trivial copies (same value) and copies to JS literals/keywords
            if dst_resolved == src_resolved
                || matches!(
                    dst_resolved.as_str(),
                    "null" | "undefined" | "true" | "false" | "this" | "NaN" | "Infinity"
                )
            {
                return;
            }
            let decl = if dst_resolved.contains('.')
                || dst_resolved.contains('[')
                || !is_valid_js_identifier(&dst_resolved)
            {
                ""
            } else if declared.insert(dst.to_string()) {
                "var "
            } else {
                ""
            };
            out.push_str(&format!("{pad}{decl}{dst_resolved} = {src_resolved};\n"));
        }
        Stmt::Labeled { label, body } => {
            // When the body is a single loop statement, emit as a labeled-loop
            // (`L: while (...) { ... }`) rather than labeled-block form
            // (`L: { while (...) { ... } }`). A labeled block does NOT accept
            // `continue L` in JS; only a labeled loop does. The region
            // structurer wraps loops that need labels for cross-loop break /
            // continue — unwrap here so the emitted JS reflects loop-label
            // semantics.
            let is_single_loop = body.len() == 1
                && matches!(body.first(), Some(Stmt::While { .. } | Stmt::ForIn { .. }));
            if is_single_loop {
                out.push_str(&format!("{pad}{label}: "));
                let mut child_buf = String::new();
                emit_stmt(
                    &mut child_buf,
                    &body[0],
                    indent,
                    get_str,
                    inline_map,
                    skip_set,
                    params,
                    declared,
                );
                // `emit_stmt` for a loop prefixes indentation itself; strip
                // the leading pad we already wrote to avoid doubling.
                out.push_str(child_buf.trim_start_matches(pad.as_str()));
            } else {
                out.push_str(&format!("{pad}{label}: {{\n"));
                for s in body {
                    emit_stmt(
                        out,
                        s,
                        indent.saturating_add(1),
                        get_str,
                        inline_map,
                        skip_set,
                        params,
                        declared,
                    );
                }
                out.push_str(&format!("{pad}}}\n"));
            }
        }
        Stmt::Break(None) => out.push_str(&format!("{pad}break;\n")),
        Stmt::Break(Some(label)) => out.push_str(&format!("{pad}break {label};\n")),
        Stmt::Continue(None) => out.push_str(&format!("{pad}continue;\n")),
        Stmt::Continue(Some(label)) => out.push_str(&format!("{pad}continue {label};\n")),
        Stmt::Comment(text) => out.push_str(&format!("{pad}// {text}\n")),
    }
}

fn format_cond(cond: &Condition) -> String {
    format_cond_inline(cond, &BTreeMap::new())
}

fn format_cond_inline(
    cond: &Condition,
    inline_map: &BTreeMap<VarId, super::expr::Expr>,
) -> String {
    match cond {
        Condition::Truthy(v) => resolve_var(&format!("{v}"), inline_map),
        Condition::Falsy(v) => {
            let resolved = resolve_var(&format!("{v}"), inline_map);
            // Parenthesize compound expressions to prevent !a + 1 → (!a) + 1
            if resolved.contains(' ') && !resolved.starts_with('(') {
                format!("!({resolved})")
            } else {
                format!("!{resolved}")
            }
        }
        Condition::Compare { op, left, right } => {
            let l = resolve_var(&format!("{left}"), inline_map);
            let r = resolve_var(&format!("{right}"), inline_map);
            format!("{l} {op} {r}")
        }
        Condition::IsUndefined(v) => {
            format!("{} === undefined", resolve_var(&format!("{v}"), inline_map))
        }
        Condition::NotUndefined(v) => {
            format!("{} !== undefined", resolve_var(&format!("{v}"), inline_map))
        }
    }
}

/// Format an op with inlined single-use variables resolved.
fn format_op_inline(
    op: &SsaOp,
    get_str: &dyn Fn(u32) -> String,
    inline_map: &BTreeMap<VarId, super::expr::Expr>,
) -> String {
    let expr = super::expr::build_expr(op, get_str);
    let resolved = expr.substitute(inline_map);
    format!("{resolved}")
}

/// Decode the `min_case` (slot 3) of a `SwitchImm` terminator.
///
/// Defensive contract: slot 3 is a `U4` immediate per `schemas.rs` and
/// always decodes to `Operand::UInt`, so the
/// fallback arm is unreachable via well-formed HBC. We keep it as a defense
/// against future refactors, but unlike the other sentinel sites a `0`
/// min_case is numerically valid — no rendered-JS marker distinguishes a
/// genuine 0 from a fallback. Instead, record a one-shot thread-local
/// warning on the defensive path so tests and future diagnostic tooling can
/// observe that the arm fired.
pub(super) fn min_case_from_switch(last: &SsaOp) -> i64 {
    match last.original.operands.get(3) {
        Some(super::decode::Operand::UInt(v)) => i64::from(*v),
        _ => {
            super::sentinel_diag::warn_once(
                "structure::switch_min_case_fallback",
                format!(
                    "non-UInt operand at slot 3 of {} — min_case falling to 0",
                    last.original.name,
                ),
            );
            0
        }
    }
}

pub fn format_op(op: &SsaOp, get_str: &dyn Fn(u32) -> String) -> String {
    let ops = &op.operands;
    match op.name {
        "Add" | "AddN" => fbin(ops, "+"),
        "Sub" | "SubN" => fbin(ops, "-"),
        "Mul" | "MulN" => fbin(ops, "*"),
        "Div" | "DivN" => fbin(ops, "/"),
        "Mod" => fbin(ops, "%"),
        "BitAnd" => fbin(ops, "&"),
        "BitOr" => fbin(ops, "|"),
        "BitXor" => fbin(ops, "^"),
        "LShift" => fbin(ops, "<<"),
        "RShift" => fbin(ops, ">>"),
        "URshift" => fbin(ops, ">>>"),
        "Eq" => fbin(ops, "=="),
        "Neq" => fbin(ops, "!="),
        "StrictEq" => fbin(ops, "==="),
        "StrictNeq" => fbin(ops, "!=="),
        "Less" => fbin(ops, "<"),
        "LessEq" => fbin(ops, "<="),
        "Greater" => fbin(ops, ">"),
        "GreaterEq" => fbin(ops, ">="),
        "InstanceOf" => fbin(ops, "instanceof"),
        "IsIn" => fbin(ops, "in"),
        "Negate" => format!("-{}", vr(ops, 1)),
        "Not" => format!("!{}", vr(ops, 1)),
        "BitNot" => format!("~{}", vr(ops, 1)),
        "TypeOf" => format!("typeof {}", vr(ops, 1)),
        "Inc" => format!("{} + 1", vr(ops, 1)),
        "Dec" => format!("{} - 1", vr(ops, 1)),

        "LoadConstString" | "LoadConstStringLongIndex" => {
            if let Some(SsaOperand::StringId(s)) = ops.get(1) {
                let v = get_str(*s);
                let escaped = v
                    .replace('\\', "\\\\")
                    .replace('"', "\\\"")
                    .replace('\n', "\\n")
                    .replace('\r', "\\r")
                    .replace('\0', "\\0");
                format!("\"{escaped}\"")
            } else {
                "\"\"".into()
            }
        }
        "LoadConstInt" | "LoadConstUInt8" => cr(ops, 1),
        "LoadConstDouble" => match ops.get(1) {
            Some(SsaOperand::ConstDouble(d)) => {
                if d.is_nan() {
                    "NaN".into()
                } else if d.is_infinite() {
                    if *d > 0.0 {
                        "Infinity".into()
                    } else {
                        "-Infinity".into()
                    }
                } else {
                    format!("{d}")
                }
            }
            // Defensive contract: slot 1 is a `D` immediate per
            // schemas.rs and always decodes to `Operand::Double` →
            // `SsaOperand::ConstDouble`. Well-formed HBC can never reach this arm
            // through the decode+SSA pipeline. If a future SSA refactor ever
            // produces a non-`ConstDouble` binding for this slot, emit a distinct
            // placeholder instead of silently rendering the literal `0.0` —
            // which would otherwise be indistinguishable from a genuine zero.
            _ => "/* missing LoadConstDouble operand */ undefined".into(),
        },
        "LoadConstNull" => "null".into(),
        "LoadConstUndefined" => "undefined".into(),
        "LoadConstTrue" => "true".into(),
        "LoadConstFalse" => "false".into(),
        "LoadConstZero" => "0".into(),
        "LoadConstEmpty" => "undefined".into(),
        "LoadParam" => match ops.get(1) {
            Some(SsaOperand::Const(0)) => "this".into(),
            Some(SsaOperand::Const(n)) => format!("a{}", n.saturating_sub(1)),
            // Defensive contract: slot 1 is a `U1` immediate per
            // schemas.rs and always decodes to `Operand::UInt` →
            // `SsaOperand::Const`. Well-formed HBC can never reach this arm.
            // Previous fallback `"arguments[?]"` rendered as a literal identifier
            // access (a real JS reference), silently corrupting the decompiled
            // body. Emit a distinct placeholder that cannot be mistaken for a
            // valid expression.
            _ => "/* missing LoadParam index */ undefined".into(),
        },

        n if n.starts_with("GetById") || n.starts_with("TryGetById") => {
            let obj = vr(ops, 1);
            if let Some(SsaOperand::Const(sid)) = ops.last() {
                let prop = get_str(const_id_to_u32(*sid));
                fmt_prop_access(&obj, &prop)
            } else {
                format!("{obj}[?]")
            }
        }
        "GetByVal" => format!("{}[{}]", vr(ops, 1), vr(ops, 2)),
        "GetGlobalObject" => "globalThis".into(),
        // Call1: (dst, callee, thisArg) — zero user args, thisArg is implicit
        "Call1" => format!("{}()", vr(ops, 1)),
        "Call2" => format!("{}.call({}, {})", vr(ops, 1), vr(ops, 2), vr(ops, 3)),
        "Call3" => format!(
            "{}.call({}, {}, {})",
            vr(ops, 1),
            vr(ops, 2),
            vr(ops, 3),
            vr(ops, 4)
        ),
        "Call4" => format!(
            "{}.call({}, {}, {}, {})",
            vr(ops, 1),
            vr(ops, 2),
            vr(ops, 3),
            vr(ops, 4),
            vr(ops, 5)
        ),
        "Construct" | "ConstructLong" => format!("new {}()", vr(ops, 1)),
        "ConstructNew" => {
            // ConstructNew: dst, callee, thisArg, ...args
            let callee = vr(ops, 1);
            let args: Vec<String> = ops
                .iter()
                .skip(3)
                .filter_map(|o| match o {
                    SsaOperand::Var(v) => Some(format!("{v}")),
                    SsaOperand::Const(c) => Some(format!("{c}")),
                    SsaOperand::ResolvedString(s) => Some(format!("\"{s}\"")),
                    _ => None,
                })
                .collect();
            format!("new {callee}({})", args.join(", "))
        }
        "MethodCall" => {
            // MethodCall: dst, obj, "method", ...args
            let obj = vr(ops, 1);
            let method = match ops.get(2) {
                Some(SsaOperand::ResolvedString(s)) => s.clone(),
                _ => "?".into(),
            };
            let args: Vec<String> = ops
                .iter()
                .skip(3)
                .filter_map(|o| match o {
                    SsaOperand::Var(v) => Some(format!("{v}")),
                    SsaOperand::Const(c) => Some(format!("{c}")),
                    SsaOperand::ResolvedString(s) => Some(format!("\"{s}\"")),
                    _ => None,
                })
                .collect();
            format!("{obj}.{method}({})", args.join(", "))
        }
        "GetEnvironment" => format!("env[{}]", cr(ops, 1)),
        "LoadFromEnvironment" | "LoadFromEnvironmentL" => {
            // Check for closure name sentinel from optimize::name_closure_vars
            if let Some(SsaOperand::Const(sentinel)) = ops.get(1) {
                let s = const_id_to_u32(*sentinel);
                if s & 0xF000_0000 == 0xF000_0000 {
                    let level = (s >> 16) & 0xFFF;
                    let slot = s & 0xFFFF;
                    return format!("_closure{level}_slot{slot}");
                }
            }
            format!("{}.slot[{}]", vr(ops, 1), cr(ops, 2))
        }
        "CreateThis" => format!("Object.create({}.prototype)", vr(ops, 1)),
        "SelectObject" => format!(
            "{} instanceof Object ? {} : {}",
            vr(ops, 2),
            vr(ops, 2),
            vr(ops, 1)
        ),
        "Mov" | "MovLong" => vr(ops, 1),
        "NewObject" => "({})".into(),
        "NewObjectWithParent" => format!("Object.create({})", vr(ops, 1)),
        "NewArray" => format!("new Array({})", cr(ops, 1)),
        "Catch" => "void 0 /* caught exception */".into(),

        // For-in / for-of
        "GetPNameList" => format!("Object.keys({})", vr(ops, 1)),
        "GetNextPName" => format!("{}.next()", vr(ops, 1)),
        "IteratorBegin" => format!("{}[Symbol.iterator]()", vr(ops, 1)),
        "IteratorNext" => format!("{}.next()", vr(ops, 1)),
        "IteratorClose" => format!("{}.return()", vr(ops, 1)),

        // Generator
        "StartGenerator" => "void 0 /* generator start */".into(),
        "ResumeGenerator" => "void 0 /* resume */".into(),
        "SaveGenerator" | "SaveGeneratorLong" => "yield".into(),
        "CompleteGenerator" => "return".into(),
        "CreateGenerator" | "CreateGeneratorLongIndex" => {
            let fid = ops.iter().find_map(|o| {
                if let SsaOperand::FuncId(f) = o {
                    Some(f)
                } else {
                    None
                }
            });
            if let Some(fid) = fid {
                format!("void 0 /* generator #{fid} */")
            } else {
                "void 0 /* generator */".into()
            }
        }

        // Class
        "CreateClosure" | "CreateClosureLongIndex" => {
            // FuncId is the last operand (after dst placeholder and env register)
            let fid = ops.iter().find_map(|o| {
                if let SsaOperand::FuncId(f) = o {
                    Some(f)
                } else {
                    None
                }
            });
            if let Some(fid) = fid {
                format!("void 0 /* closure #{fid} */")
            } else {
                "void 0 /* closure */".into()
            }
        }
        "CreateAsyncClosure" | "CreateAsyncClosureLongIndex" => {
            let fid = ops.iter().find_map(|o| {
                if let SsaOperand::FuncId(f) = o {
                    Some(f)
                } else {
                    None
                }
            });
            if let Some(fid) = fid {
                format!("void 0 /* async closure #{fid} */")
            } else {
                "void 0 /* async closure */".into()
            }
        }
        "CreateGeneratorClosure" | "CreateGeneratorClosureLongIndex" => {
            let fid = ops.iter().find_map(|o| {
                if let SsaOperand::FuncId(f) = o {
                    Some(f)
                } else {
                    None
                }
            });
            if let Some(fid) = fid {
                format!("void 0 /* generator #{fid} */")
            } else {
                "void 0 /* generator */".into()
            }
        }

        // Type checks
        "AddEmptyString" | "AddS" => format!("\"\" + {}", vr(ops, 1)),
        "ToNumber" | "ToNumeric" => format!("+{}", vr(ops, 1)),
        "ToInt32" => format!("{} | 0", vr(ops, 1)),
        "ToUint32" => format!("{} >>> 0", vr(ops, 1)),

        // Arguments
        "GetArgumentsLength" => "arguments.length".into(),
        "GetArgumentsPropByVal" | "GetArgumentsPropByValLoose" | "GetArgumentsPropByValStrict" => {
            format!("arguments[{}]", vr(ops, 1))
        }
        "ReifyArguments" | "ReifyArgumentsLoose" | "ReifyArgumentsStrict" => {
            "Array.from(arguments)".into()
        }

        // CreateThis variants
        "CreateThisForNew" | "CreateThisForSuper" => {
            format!("Object.create({}.prototype)", vr(ops, 1))
        }

        // Misc
        "GetNewTarget" => "new.target".into(),
        "NewObjectWithBuffer" | "NewObjectWithBufferLong" | "NewObjectWithBufferAndParent" => {
            // Check if buffer was resolved by optimize::resolve_buffers
            if let Some(SsaOperand::ResolvedString(s)) = ops.get(1) {
                s.clone()
            } else {
                "{ /* buffer */ }".into()
            }
        }
        "NewArrayWithBuffer" | "NewArrayWithBufferLong" => {
            if let Some(SsaOperand::ResolvedString(s)) = ops.get(1) {
                s.clone()
            } else {
                "[ /* buffer */ ]".into()
            }
        }

        // Store operations (side effects — emitted as statements)
        n if n.starts_with("PutById") || n.starts_with("TryPutById") => {
            let obj = vr(ops, 0);
            if let Some(SsaOperand::Const(sid)) = ops.last() {
                let prop = get_str(const_id_to_u32(*sid));
                let val = vr(ops, 1);
                format!("{} = {val}", fmt_prop_access(&obj, &prop))
            } else {
                format!("{obj}[?] = {}", vr(ops, 1))
            }
        }
        n if n.starts_with("PutNewOwnById")
            || n.starts_with("PutNewOwnNEById")
            || n.starts_with("DefineOwnById") =>
        {
            let obj = vr(ops, 0);
            let val = vr(ops, 1);
            if let Some(SsaOperand::Const(sid)) = ops.last() {
                let prop = get_str(const_id_to_u32(*sid));
                format!("{} = {val}", fmt_prop_access(&obj, &prop))
            } else {
                format!("{obj}[?] = {val}")
            }
        }
        "PutByVal" | "PutByValLoose" | "PutByValStrict" => {
            format!("{}[{}] = {}", vr(ops, 0), vr(ops, 1), vr(ops, 2))
        }
        "PutOwnByIndex" | "PutOwnByIndexL" => {
            format!("{}[{}] = {}", vr(ops, 0), cr(ops, 2), vr(ops, 1))
        }
        "PutOwnByVal" => {
            format!("{}[{}] = {}", vr(ops, 0), vr(ops, 2), vr(ops, 1))
        }
        n if n.starts_with("StoreToEnvironment") || n.starts_with("StoreNPToEnvironment") => {
            format!("{}.slot[{}] = {}", vr(ops, 0), cr(ops, 1), vr(ops, 2))
        }
        "DelById" | "DelByIdLong" => {
            if let Some(SsaOperand::Const(sid)) = ops.last() {
                let prop = get_str(const_id_to_u32(*sid));
                format!("delete {}", fmt_prop_access(&vr(ops, 0), &prop))
            } else {
                format!("delete {}[?]", vr(ops, 0))
            }
        }
        "DelByVal" => format!("delete {}[{}]", vr(ops, 0), vr(ops, 1)),
        "DeclareGlobalVar" => {
            if let Some(SsaOperand::Const(sid)) = ops.first() {
                let name = get_str(const_id_to_u32(*sid));
                format!("/* global */ var {name}")
            } else {
                "/* global */ var ?".into()
            }
        }
        "Throw" => format!("throw {}", vr(ops, 0)),
        "ThrowIfEmpty" | "ThrowIfUndefined" => {
            format!("{} /* {} */", vr(ops, 0), op.name)
        }
        "Debugger" => "debugger".into(),
        "DirectEval" => format!("eval({})", vr(ops, 1)),
        "PutOwnGetterSetterByVal" | "DefineOwnGetterSetterByVal" => {
            format!(
                "Object.defineProperty({}, {}, {{get: {}, set: {}}})",
                vr(ops, 0),
                vr(ops, 1),
                vr(ops, 2),
                vr(ops, 3)
            )
        }

        // Environment operations
        "CreateEnvironment" | "CreateFunctionEnvironment" | "CreateTopLevelEnvironment" => {
            format!("void 0 /* new env({}) */", cr(ops, 1))
        }
        "GetParentEnvironment" => format!("void 0 /* parent env({}) */", cr(ops, 1)),

        // Object/array slot initialization
        "PutOwnBySlotIdx" => {
            format!("{}[{}] = {}", vr(ops, 0), cr(ops, 2), vr(ops, 1))
        }
        "DefineOwnInDenseArray" => {
            format!("{}[{}] = {}", vr(ops, 0), cr(ops, 2), vr(ops, 1))
        }
        "DefineOwnByVal" => {
            format!("{}[{}] = {}", vr(ops, 0), vr(ops, 1), vr(ops, 2))
        }
        "GetByIndex" => format!("{}[{}]", vr(ops, 1), cr(ops, 2)),

        // Regex
        "CreateRegExp" => {
            if let (Some(SsaOperand::Const(pat)), Some(SsaOperand::Const(flags))) =
                (ops.get(1), ops.get(2))
            {
                let pattern = get_str(const_id_to_u32(*pat));
                let flag_str = get_str(const_id_to_u32(*flags));
                // Escape unescaped forward slashes for regex literal delimiter,
                // but preserve existing escape sequences (e.g., \/ stays \/)
                let mut safe = String::with_capacity(pattern.len());
                let mut chars = pattern.chars().peekable();
                while let Some(c) = chars.next() {
                    match c {
                        '\\' => {
                            safe.push('\\');
                            if let Some(n) = chars.next() {
                                safe.push(n);
                            }
                        }
                        '/' => {
                            safe.push('\\');
                            safe.push('/');
                        }
                        _ => safe.push(c),
                    }
                }
                format!("/{safe}/{flag_str}")
            } else {
                "void 0 /* regexp */".into()
            }
        }

        // Builtins
        "CallBuiltin" | "CallBuiltinLong" => {
            let args: Vec<String> = ops
                .iter()
                .skip(1)
                .filter_map(|o| match o {
                    SsaOperand::Var(v) => Some(format!("{v}")),
                    SsaOperand::Const(c) => Some(format!("{c}")),
                    _ => None,
                })
                .collect();
            format!("void 0 /* builtin ({}) */", args.join(", "))
        }
        "GetBuiltinClosure" => format!("void 0 /* builtin[{}] */", cr(ops, 1)),

        // Class operations (v99)
        "CreateBaseClass" | "CreateBaseClassLongIndex" => {
            format!("void 0 /* class ({}) */", vr(ops, 1))
        }
        "CreateDerivedClass" | "CreateDerivedClassLongIndex" => {
            format!("void 0 /* class extends {} ({}) */", vr(ops, 3), vr(ops, 1))
        }
        "CreatePrivateName" => match ops.get(1) {
            Some(SsaOperand::Const(sid)) => {
                let name = get_str(const_id_to_u32(*sid));
                format!("void 0 /* #private({name}) */")
            }
            Some(SsaOperand::ResolvedString(name)) => {
                format!("void 0 /* #private({name}) */")
            }
            _ => "void 0 /* #private */".into(),
        },
        "LoadParentNoTraps" => format!("void 0 /* super ({}) */", vr(ops, 1)),

        // Private field operations
        "PrivateIsIn" => format!("{} in {}", vr(ops, 1), vr(ops, 2)),
        "AddOwnPrivateBySym" => {
            // Has dst: [DstPlaceholder, object, sym]
            format!("{}._private = {}", vr(ops, 1), vr(ops, 2))
        }
        "PutOwnPrivateBySym" => {
            // No dst: [object, value, ...]
            format!("{}._private = {}", vr(ops, 0), vr(ops, 1))
        }
        "GetOwnPrivateBySym" => format!("{}._private", vr(ops, 1)),

        // BigInt — `optimize::resolve_bigints` rewrites the table-index operand
        // to `ResolvedBigInt(decimal)`. A surviving `Const(idx)` means
        // out-of-bounds: surface a loud placeholder rather than `{idx}n`.
        "LoadConstBigInt" | "LoadConstBigIntLongIndex" => match ops.get(1) {
            Some(SsaOperand::ResolvedBigInt(s)) => format!("{s}n"),
            Some(SsaOperand::Const(v)) => format!("/* missing bigint #{v} */"),
            _ => "/* missing bigint */".into(),
        },

        // CallWithNewTarget (v97+, used for super() calls)
        // Emit as Reflect.construct for syntactic validity outside class constructors
        "CallWithNewTarget" | "CallWithNewTargetLong" => {
            format!("Reflect.construct({}, [])", vr(ops, 1))
        }

        _ => {
            let args: Vec<String> = ops
                .iter()
                .skip(1)
                .filter_map(|o| match o {
                    SsaOperand::Var(v) => Some(format!("{v}")),
                    SsaOperand::Const(c) => Some(format!("{c}")),
                    SsaOperand::ConstDouble(d) => Some(format!("{d}")),
                    SsaOperand::StringId(s) => Some(format!("\"{}\"", get_str(*s))),
                    SsaOperand::FuncId(f) => Some(format!("func[{f}]")),
                    _ => None,
                })
                .collect();
            format!("void 0 /* {} ({}) */", op.name, args.join(", "))
        }
    }
}

fn fbin(ops: &[SsaOperand], op: &str) -> String {
    format!("{} {op} {}", vr(ops, 1), vr(ops, 2))
}

fn vr(ops: &[SsaOperand], i: usize) -> String {
    match ops.get(i) {
        Some(SsaOperand::Var(v)) => format!("{v}"),
        Some(SsaOperand::Const(c)) => format!("{c}"),
        Some(SsaOperand::ConstDouble(d)) => {
            if d.is_nan() {
                "NaN".into()
            } else if d.is_infinite() {
                if *d > 0.0 {
                    "Infinity".into()
                } else {
                    "-Infinity".into()
                }
            } else {
                format!("{d}")
            }
        }
        Some(SsaOperand::StringId(s)) => format!("str[{s}]"),
        Some(SsaOperand::ResolvedString(s)) => {
            let escaped = s
                .replace('\\', "\\\\")
                .replace('"', "\\\"")
                .replace('\n', "\\n");
            format!("\"{escaped}\"")
        }
        Some(SsaOperand::DstPlaceholder) => String::new(),
        _ => "?".into(),
    }
}

fn cr(ops: &[SsaOperand], i: usize) -> String {
    match ops.get(i) {
        Some(SsaOperand::Const(c)) => format!("{c}"),
        Some(SsaOperand::Var(v)) => format!("{v}"),
        _ => "?".into(),
    }
}

#[cfg(test)]
mod structure_sentinel_tests {
    //! Regression tests ensuring that the five structurally-unreachable
    //! defensive-contract fallbacks in `structure.rs` / `region.rs`
    //! surface a distinct placeholder (or recorded diagnostic, for
    //! `min_case`) rather than silently emitting syntactically-valid-but-
    //! semantically-wrong JS.
    //!
    //! These five fallback arms cannot be reached via well-formed HBC — the
    //! operand schemas in `schemas.rs` guarantee slot shapes (R → Var, U4 →
    //! UInt, D → Double) post-SSA. The placeholders lock defensive contracts
    //! against future SSA refactors that might introduce non-resolvable
    //! bindings. The correct lock is a unit test at the direct-`SsaOp` /
    //! direct-`Stmt`-construction layer — no adversarial HBC fixture can
    //! reach these branches.
    //!
    //! Sibling precedent: `mod builtin_id_tests` / `mod regex_operand_tests`
    //! in `expr.rs`.
    use super::*;
    use crate::decompile::decode::{DecodedInst, Operand};
    use crate::decompile::ssa::{SsaOp, SsaOperand, VarId};
    use crate::opcodes::OpCode;

    fn stub_inst(name: &'static str, op: OpCode, operands: Vec<Operand>) -> DecodedInst {
        DecodedInst {
            offset: 0,
            size: 0,
            opcode: 0,
            name,
            op,
            operands,
            op_types: &[],
        }
    }

    fn no_str(_: u32) -> String {
        String::new()
    }

    // --- LoadConstDouble (structure.rs:2304) ---

    #[test]
    fn load_const_double_with_non_const_double_emits_missing_placeholder() {
        // Operand slot 1 is bound to a register (Var) instead of the expected
        // immediate ConstDouble. Without the placeholder, we'd silently emit
        // the literal 0.0.
        let ssa_op = SsaOp {
            name: "LoadConstDouble",
            op: OpCode::LoadConstDouble,
            dst: None,
            operands: vec![SsaOperand::DstPlaceholder, SsaOperand::Var(VarId(0, 0))],
            original: stub_inst("LoadConstDouble", OpCode::LoadConstDouble, Vec::new()),
        };
        let out = format_op(&ssa_op, &no_str);
        assert!(
            out.contains("/* missing LoadConstDouble operand */"),
            "expected missing-operand placeholder, got {out:?}"
        );
        assert!(
            !out.contains("0.0"),
            "placeholder must not fall through to literal 0.0, got {out:?}"
        );
    }

    #[test]
    fn load_const_double_with_valid_const_still_renders_literal() {
        // Sanity check: the ConstDouble path is untouched by the fix.
        let ssa_op = SsaOp {
            name: "LoadConstDouble",
            op: OpCode::LoadConstDouble,
            dst: None,
            operands: vec![SsaOperand::DstPlaceholder, SsaOperand::ConstDouble(2.5)],
            original: stub_inst("LoadConstDouble", OpCode::LoadConstDouble, Vec::new()),
        };
        let out = format_op(&ssa_op, &no_str);
        assert!(
            out.contains("2.5"),
            "ConstDouble path must render the literal, got {out:?}"
        );
        assert!(
            !out.contains("missing"),
            "positive path must not emit a placeholder, got {out:?}"
        );
    }

    // --- LoadParam (structure.rs:2315) ---

    #[test]
    fn load_param_with_non_const_index_emits_missing_placeholder() {
        // Operand slot 1 is bound to a register (Var) instead of the expected
        // immediate Const. Without the placeholder, we'd emit the literal
        // `arguments[?]` — a valid JS reference that silently corrupts the
        // body.
        let ssa_op = SsaOp {
            name: "LoadParam",
            op: OpCode::LoadParam,
            dst: None,
            operands: vec![SsaOperand::DstPlaceholder, SsaOperand::Var(VarId(0, 0))],
            original: stub_inst("LoadParam", OpCode::LoadParam, Vec::new()),
        };
        let out = format_op(&ssa_op, &no_str);
        assert!(
            out.contains("/* missing LoadParam index */"),
            "expected missing-index placeholder, got {out:?}"
        );
        assert!(
            !out.contains("arguments[?]"),
            "placeholder must not fall through to arguments[?], got {out:?}"
        );
    }

    #[test]
    fn load_param_with_valid_const_zero_still_renders_this() {
        let ssa_op = SsaOp {
            name: "LoadParam",
            op: OpCode::LoadParam,
            dst: None,
            operands: vec![SsaOperand::DstPlaceholder, SsaOperand::Const(0)],
            original: stub_inst("LoadParam", OpCode::LoadParam, Vec::new()),
        };
        let out = format_op(&ssa_op, &no_str);
        assert_eq!(out, "this", "Const(0) must render as `this`, got {out:?}");
    }

    #[test]
    fn load_param_with_valid_const_n_still_renders_a_n_minus_one() {
        let ssa_op = SsaOp {
            name: "LoadParam",
            op: OpCode::LoadParam,
            dst: None,
            operands: vec![SsaOperand::DstPlaceholder, SsaOperand::Const(3)],
            original: stub_inst("LoadParam", OpCode::LoadParam, Vec::new()),
        };
        let out = format_op(&ssa_op, &no_str);
        assert_eq!(out, "a2", "Const(3) must render as `a2`, got {out:?}");
    }

    // --- Switch discriminant (structure.rs:1205, region.rs:1199) ---

    fn empty_structured_function_with_switch(disc: VarId) -> StructuredFunction {
        StructuredFunction {
            name: "probe".into(),
            params: 1,
            body: vec![Stmt::Switch {
                discriminant: disc,
                cases: vec![("0".to_string(), vec![Stmt::Return(Some(VarId(1, 0)))])],
                default: Vec::new(),
            }],
            is_strict: false,
            is_async: false,
            is_generator: false,
            is_arrow: false,
            var_names: BTreeMap::new(),
            param_names: BTreeMap::new(),
        }
    }

    #[test]
    fn switch_with_sentinel_discriminant_emits_missing_placeholder() {
        // Both structure.rs:1205 and region.rs:1199 fall back to
        // VarId(u32::MAX, u32::MAX) when the switch terminator's discriminant
        // slot is not a Var. Without the emit-layer rewrite, the sentinel
        // renders as `r4294967295_4294967295` — a valid-looking identifier
        // that references nothing. The emit layer rewrites it to a distinct
        // placeholder.
        let sf = empty_structured_function_with_switch(VarId(u32::MAX, u32::MAX));
        let out = sf.emit(&no_str);
        assert!(
            out.contains("/* missing switch discriminant */"),
            "expected missing-discriminant placeholder, got {out:?}"
        );
        assert!(
            !out.contains("r4294967295_4294967295"),
            "sentinel must not render as an identifier, got {out:?}"
        );
    }

    #[test]
    fn switch_with_valid_discriminant_renders_identifier() {
        // Sanity check: the non-sentinel path is untouched.
        let sf = empty_structured_function_with_switch(VarId(5, 0));
        let out = sf.emit(&no_str);
        assert!(
            out.contains("switch (r5_0)"),
            "non-sentinel discriminant must render as its VarId identifier, got {out:?}"
        );
        assert!(
            !out.contains("missing switch discriminant"),
            "positive path must not emit the placeholder, got {out:?}"
        );
    }

    // --- min_case fallback (structure.rs:1213) ---

    #[test]
    fn min_case_with_non_uint_operand_records_warning_and_falls_to_zero() {
        // The min_case slot is `U4` per schemas.rs; the defensive arm records
        // a one-shot thread-local warning instead of silently emitting
        // numerically-valid 0 (which is indistinguishable from a genuine 0).
        let _ = super::super::sentinel_diag::drain_warnings(); // clear prior state

        let ssa_op = SsaOp {
            name: "SwitchImm",
            op: OpCode::SwitchImm,
            dst: None,
            operands: Vec::new(),
            original: stub_inst(
                "SwitchImm",
                OpCode::SwitchImm,
                // Slots 0-2 are placeholders (Reg, UInt, Addr); slot 3 is the
                // min_case. Here slot 3 is a Reg (non-UInt) — the defensive
                // arm fires.
                vec![
                    Operand::Reg(0),
                    Operand::UInt(0),
                    Operand::Addr(0),
                    Operand::Reg(1),
                ],
            ),
        };
        let v = min_case_from_switch(&ssa_op);
        assert_eq!(v, 0, "fallback must be 0 (the only sane neutral default)");
        let warnings = super::super::sentinel_diag::drain_warnings();
        assert_eq!(
            warnings.len(),
            1,
            "expected one warning to have been recorded, got {warnings:?}"
        );
        assert!(
            warnings[0].contains("structure::switch_min_case_fallback"),
            "warning must identify the site, got {warnings:?}"
        );
    }

    #[test]
    fn min_case_with_valid_uint_operand_does_not_warn() {
        let _ = super::super::sentinel_diag::drain_warnings();
        let ssa_op = SsaOp {
            name: "SwitchImm",
            op: OpCode::SwitchImm,
            dst: None,
            operands: Vec::new(),
            original: stub_inst(
                "SwitchImm",
                OpCode::SwitchImm,
                vec![
                    Operand::Reg(0),
                    Operand::UInt(0),
                    Operand::Addr(0),
                    Operand::UInt(42),
                ],
            ),
        };
        let v = min_case_from_switch(&ssa_op);
        assert_eq!(v, 42, "valid UInt(42) must decode as min_case=42");
        let warnings = super::super::sentinel_diag::drain_warnings();
        assert!(
            warnings.is_empty(),
            "positive path must not warn, got {warnings:?}"
        );
    }

    #[test]
    fn min_case_warn_is_one_shot_per_site() {
        let _ = super::super::sentinel_diag::drain_warnings();
        let ssa_op = SsaOp {
            name: "SwitchImm",
            op: OpCode::SwitchImm,
            dst: None,
            operands: Vec::new(),
            original: stub_inst(
                "SwitchImm",
                OpCode::SwitchImm,
                vec![
                    Operand::Reg(0),
                    Operand::UInt(0),
                    Operand::Addr(0),
                    Operand::Reg(1),
                ],
            ),
        };
        for _ in 0..5 {
            let _ = min_case_from_switch(&ssa_op);
        }
        let warnings = super::super::sentinel_diag::drain_warnings();
        assert_eq!(
            warnings.len(),
            1,
            "warning should be one-shot (deduped by site), got {warnings:?}"
        );
    }
}

#[cfg(test)]
mod infinite_loop_repr_tests {
    //! Regression tests ensuring that
    //! `Stmt::While { cond: None, .. }` — the data-model representation of an
    //! unconditional loop (`while(true)`, `for(;;)`, `do-while(true)` in
    //! source) — renders as the JS literal `while (true) { ... }` rather than
    //! the prior sentinel `Condition::Truthy(VarId::MAX)` which emitted the
    //! spurious identifier `while (r4294967295_4294967295) { ... }`.
    //!
    //! Fixture-level coverage (`tests/fixtures/language_surface/whileloop/*`,
    //! `forloop/infinite`) drives the same path end-to-end through
    //! `hermesc → HbcFile::parse → decompile_bundle`. These direct-emit tests
    //! lock the rendering behaviour on machines where `hermesc` isn't
    //! installed.
    use super::*;
    use std::collections::BTreeSet;

    fn emit_top_level(stmt: &Stmt) -> String {
        let mut out = String::new();
        let inline_map = BTreeMap::new();
        let skip_set = BTreeSet::new();
        let mut declared = BTreeSet::new();
        emit_stmt(
            &mut out,
            stmt,
            0,
            &|_| String::new(),
            &inline_map,
            &skip_set,
            &[],
            &mut declared,
        );
        out
    }

    #[test]
    fn while_with_cond_none_renders_as_while_true() {
        let stmt = Stmt::While {
            cond: None,
            body: vec![Stmt::Comment("loop body".into())],
        };
        let out = emit_top_level(&stmt);
        assert!(
            out.starts_with("while (true) {"),
            "expected `while (true) {{`, got {out:?}"
        );
        assert!(
            !out.contains("r4294967295"),
            "`cond = None` must not surface any u32::MAX sentinel identifier, got {out:?}"
        );
    }

    #[test]
    fn while_with_some_cond_still_renders_the_condition() {
        // Sanity: the conditional-loop path is untouched by the data-model change.
        let stmt = Stmt::While {
            cond: Some(Condition::Truthy(VarId(0, 0))),
            body: vec![],
        };
        let out = emit_top_level(&stmt);
        assert!(
            out.starts_with("while (r0) {") || out.starts_with("while (r0_0) {"),
            "conditional loop should render its condition variable, got {out:?}"
        );
        assert!(
            !out.contains("true"),
            "`cond = Some(_)` must not collapse to `true`, got {out:?}"
        );
    }
}

#[cfg(test)]
mod extract_condition_polarity_tests {
    //! Regression tests pinning `extract_condition`'s mapping from each
    //! conditional-branch opcode name to its "jump-fires-when-true"
    //! comparator.
    //!
    //! Without ordering most-specific first, the third arm
    //! (`contains("Equal")`) greedily swallows every opcode name containing
    //! "Equal" as a substring — 8 distinct
    //! opcodes plus their `Long` / `N` / `NLong` variants. That collapsed
    //! `JGreaterEqual` / `JLessEqual` / `JNotGreaterEqual` / `JNotLessEqual`
    //! / `JNotEqual` and their N-variants to `==`, silently flipping loop-exit
    //! polarity in `forloop/infinite`, `forloop/sum`, and
    //! `whileloop/do_while_infinite`. These tests pin the correct per-opcode
    //! mapping so future reorderings of the else-if chain can't regress.
    use super::*;
    use crate::decompile::decode::{DecodedInst, Operand};
    use crate::decompile::ssa::{SsaOp, SsaOperand, VarId};
    use crate::opcodes::OpCode;

    fn block_with_branch(name: &'static str) -> SsaBlock {
        let inst = DecodedInst {
            offset: 0,
            size: 0,
            opcode: 0,
            name,
            // OpCode value here is unused by `extract_condition` (which reads
            // `name` and `operands`); any variant is fine. Pick `JEqual` as a
            // stand-in for all — the test uses the name string for dispatch.
            op: OpCode::JEqual,
            operands: vec![Operand::Addr(0), Operand::Reg(1), Operand::Reg(2)],
            op_types: &[],
        };
        let ssa_op = SsaOp {
            name,
            op: OpCode::JEqual,
            dst: None,
            operands: vec![
                SsaOperand::BlockTarget(0),
                SsaOperand::Var(VarId(1, 0)),
                SsaOperand::Var(VarId(2, 0)),
            ],
            original: inst,
        };
        SsaBlock {
            id: 0,
            phis: Vec::new(),
            ops: vec![ssa_op],
            successors: Vec::new(),
            predecessors: Vec::new(),
            switch_string_ids: Vec::new(),
        }
    }

    fn op_for(name: &'static str) -> &'static str {
        let block = block_with_branch(name);
        match extract_condition(&block) {
            Some(Condition::Compare { op, .. }) => op,
            other => panic!("expected Compare for {name}, got {other:?}"),
        }
    }

    #[test]
    fn equality_opcodes_map_to_equality_comparators() {
        assert_eq!(op_for("JEqual"), "==");
        assert_eq!(op_for("JEqualLong"), "==");
        assert_eq!(op_for("JNotEqual"), "!=");
        assert_eq!(op_for("JNotEqualLong"), "!=");
        assert_eq!(op_for("JStrictEqual"), "===");
        assert_eq!(op_for("JStrictEqualLong"), "===");
        assert_eq!(op_for("JStrictNotEqual"), "!==");
        assert_eq!(op_for("JStrictNotEqualLong"), "!==");
    }

    #[test]
    fn ordering_opcodes_map_to_ordering_comparators() {
        // Plain ordering: fires when the ordering relation holds.
        assert_eq!(op_for("JLess"), "<");
        assert_eq!(op_for("JLessLong"), "<");
        assert_eq!(op_for("JLessN"), "<");
        assert_eq!(op_for("JLessNLong"), "<");
        assert_eq!(op_for("JGreater"), ">");
        assert_eq!(op_for("JGreaterLong"), ">");
        assert_eq!(op_for("JGreaterN"), ">");
        assert_eq!(op_for("JGreaterNLong"), ">");
        assert_eq!(op_for("JLessEqual"), "<=");
        assert_eq!(op_for("JLessEqualLong"), "<=");
        assert_eq!(op_for("JLessEqualN"), "<=");
        assert_eq!(op_for("JLessEqualNLong"), "<=");
        assert_eq!(op_for("JGreaterEqual"), ">=");
        assert_eq!(op_for("JGreaterEqualLong"), ">=");
        assert_eq!(op_for("JGreaterEqualN"), ">=");
        assert_eq!(op_for("JGreaterEqualNLong"), ">=");
    }

    #[test]
    fn not_prefixed_ordering_opcodes_map_to_negated_comparators() {
        // `JNotX(a, b)` fires when `!(a X b)` — the opposite relation.
        assert_eq!(op_for("JNotLess"), ">=");
        assert_eq!(op_for("JNotLessLong"), ">=");
        assert_eq!(op_for("JNotLessN"), ">=");
        assert_eq!(op_for("JNotLessNLong"), ">=");
        assert_eq!(op_for("JNotGreater"), "<=");
        assert_eq!(op_for("JNotGreaterLong"), "<=");
        assert_eq!(op_for("JNotGreaterN"), "<=");
        assert_eq!(op_for("JNotGreaterNLong"), "<=");
        // These four are the ones the `Equal`-greedy chain incorrectly
        // emitted as `==` — the loop-exit polarity invariant.
        assert_eq!(op_for("JNotLessEqual"), ">");
        assert_eq!(op_for("JNotLessEqualLong"), ">");
        assert_eq!(op_for("JNotLessEqualN"), ">");
        assert_eq!(op_for("JNotLessEqualNLong"), ">");
        assert_eq!(op_for("JNotGreaterEqual"), "<");
        assert_eq!(op_for("JNotGreaterEqualLong"), "<");
        assert_eq!(op_for("JNotGreaterEqualN"), "<");
        assert_eq!(op_for("JNotGreaterEqualNLong"), "<");
    }
}

#[cfg(test)]
mod inline_callable_args_tests {
    //! Regression tests locking the invariants that drive the inline-
    //! callable-args fix across `symbol_iterator`, `array_methods_es6`,
    //! and `promise_chain` fixtures.
    //!
    //! - Anonymous `CreateClosure` (no `var_names` rename) with `use_count == 1`
    //!   inlines into its single use (the callable-arg site).
    //! - Named `CreateClosure` (dst renamed to a JS ident by
    //!   `optimize::name_variables`) stays standalone so the emit.rs
    //!   module-hoist-preamble stripper can pair it with the matching
    //!   `globalThis.NAME = NAME;` self-reassign.
    use super::*;
    use crate::decompile::decode::DecodedInst;
    use crate::decompile::ssa::{SsaOp, SsaOperand, VarId};
    use crate::opcodes::OpCode;

    fn stub_create_closure(dst: VarId, func_id: u32) -> SsaOp {
        SsaOp {
            name: "CreateClosure",
            op: OpCode::CreateClosure,
            dst: Some(dst),
            operands: vec![
                SsaOperand::DstPlaceholder,
                SsaOperand::Var(VarId(0, 0)),
                SsaOperand::FuncId(func_id),
            ],
            original: DecodedInst {
                offset: 0,
                size: 0,
                opcode: 0,
                name: "CreateClosure",
                op: OpCode::CreateClosure,
                operands: Vec::new(),
                op_types: &[],
            },
        }
    }

    fn no_str(_: u32) -> String {
        String::new()
    }

    #[test]
    fn anonymous_one_use_closure_is_inlined() {
        // r5_6 = CreateClosure(fid=1); r5_7 = Call(r5_6).
        // r5_6 has no var_names entry → it's anonymous → should inline.
        let cc = stub_create_closure(VarId(5, 6), 1);
        let stmts = vec![
            Stmt::Assign {
                dst: Rc::from("r5_6"),
                op: cc,
                block_id: None,
            },
            Stmt::Assign {
                dst: Rc::from("r5_7"),
                op: SsaOp {
                    name: "Call1",
                    op: OpCode::Call1,
                    dst: Some(VarId(5, 7)),
                    operands: vec![
                        SsaOperand::DstPlaceholder,
                        SsaOperand::Var(VarId(5, 6)),
                        SsaOperand::Var(VarId(0, 0)),
                    ],
                    original: DecodedInst {
                        offset: 0,
                        size: 0,
                        opcode: 0,
                        name: "Call1",
                        op: OpCode::Call1,
                        operands: Vec::new(),
                        op_types: &[],
                    },
                },
                block_id: None,
            },
        ];
        let var_names: BTreeMap<VarId, String> = BTreeMap::new();
        let named = collect_named_closure_dsts(&stmts, &var_names);
        assert!(
            named.is_empty(),
            "anonymous closure should not be named: {named:?}"
        );
        let inline_map = build_inline_map(&stmts, &no_str, &named);
        assert!(
            inline_map.contains_key(&VarId(5, 6)),
            "anonymous one-use closure should inline: {inline_map:?}"
        );
    }

    #[test]
    fn named_closure_is_not_inlined_even_when_one_use() {
        // `var foo = CreateClosure(fid=1);` — optimize::name_variables
        // renamed the dst to "foo". The hoist-triad anchor must stay
        // standalone for the emit.rs preamble stripper.
        let cc = stub_create_closure(VarId(1, 0), 1);
        let stmts = vec![Stmt::Assign {
            dst: Rc::from("r1_0"),
            op: cc,
            block_id: None,
        }];
        let mut var_names: BTreeMap<VarId, String> = BTreeMap::new();
        var_names.insert(VarId(1, 0), "foo".to_string());
        let named = collect_named_closure_dsts(&stmts, &var_names);
        assert!(
            named.contains(&VarId(1, 0)),
            "named closure dst should appear in named_closure_dsts: {named:?}"
        );
        let inline_map = build_inline_map(&stmts, &no_str, &named);
        assert!(
            !inline_map.contains_key(&VarId(1, 0)),
            "named closure must not inline: {inline_map:?}"
        );
    }

    #[test]
    fn synthetic_rename_matching_display_is_treated_as_anonymous() {
        // If name_variables happens to insert the canonical `rN_M` form as
        // the rename (equal to the VarId Display), that's not a real rename;
        // the closure is still effectively anonymous.
        let cc = stub_create_closure(VarId(3, 7), 1);
        let stmts = vec![Stmt::Assign {
            dst: Rc::from("r3_7"),
            op: cc,
            block_id: None,
        }];
        let mut var_names: BTreeMap<VarId, String> = BTreeMap::new();
        var_names.insert(VarId(3, 7), "r3_7".to_string());
        let named = collect_named_closure_dsts(&stmts, &var_names);
        assert!(
            named.is_empty(),
            "synthetic-shape rename should not mark dst as named: {named:?}"
        );
    }
}
