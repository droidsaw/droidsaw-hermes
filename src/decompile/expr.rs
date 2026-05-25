//! Structured expression IR — replaces format_op's String output.
//!
//! Every variant maps 1:1 to a valid JS expression. The `Raw` variant
//! is an escape hatch for JS built-in identifiers and the catch-all fallback.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "PROOF: HBC decompiler ID narrows. String-id, builtin-id, function-id, regex-id are widened from parser-validated u32 header counts and narrowed via explicit width-bounded ops at use sites. `i64 → u16/usize` sign-loss sites encode HBC constant-pool indices that the parser validates non-negative before they enter the SsaOperand::Const path."
)]

#![allow(missing_docs, reason = "internal")]
#![allow(dead_code, reason = "Expr/UnaryOp variants exist for completeness, not all constructed yet")]
#![cfg_attr(
    not(test),
    allow(
        clippy::indexing_slicing,
        clippy::string_slice,
        reason = "PROOF: Expr IR transformations consume Expr trees built upstream from validated SSA. Indexing into Expr operands (e.g. Call args, MemberAccess components) is bounded by `Vec::len()` of the just-constructed children; siblings of the structuring/sugar passes. String slicing is on identifier names or emit-internal buffers. v1.x refinement candidate (~11 sites)."
    )
)]

use super::ssa::VarId;

use crate::opcodes::OpCode;

/// Narrow an SSA `Const` operand (i64 by SsaOperand layout) to a `u32`
/// HBC-format ID — string-id, function-id, builtin-id, regex-id, or
/// param-index. All such IDs are bounded by the corresponding `*_count`
/// header field (u32) at parse time, so the narrow is unreachable on
/// well-formed HBC; on adversarial input the wrap is observable but
/// semantically benign (lookup miss → fallback / placeholder render).
#[allow(clippy::as_conversions, reason = "Spec-bounded value-domain narrowing (parser-validated field; preceding PROOF documents the bit-width invariant).")]
fn const_id_to_u32(v: i64) -> u32 {
    v as u32
}

/// Narrow an SSA `Const` operand to a `u16` opcode-tag identifier (e.g.
/// `JmpTypeOfIs`'s typeof bitfield). Tags are bounded by the schemas
/// table size (well under u16::MAX); wrap is unreachable.
#[allow(clippy::as_conversions, reason = "Spec-bounded value-domain narrowing (parser-validated field; preceding PROOF documents the bit-width invariant).")]
fn const_tag_to_u16(v: i64) -> u16 {
    v as u16
}

/// Single source of truth: does this instruction have side effects?
/// Used by both the optimizer (DCE) and the structurer (inline_map).
/// An instruction with side effects must not be removed by DCE and
/// must not be inlined (its execution order matters).
///
/// Design: lists PURE opcodes and defaults to "has side effects" for
/// anything not listed. This way, a new opcode added to schemas.rs
/// defaults to safe (kept by DCE) rather than silently removed.
pub fn has_side_effects(name: &str) -> bool {
    !is_pure(name)
}

/// Typed purity check using OpCode enum.
pub fn is_pure_op(op: OpCode) -> bool {
    matches!(
        op,
        // Loads — read-only access to registers, params, constants
        OpCode::LoadConstUndefined | OpCode::LoadConstNull | OpCode::LoadConstTrue | OpCode::LoadConstFalse
            | OpCode::LoadConstZero | OpCode::LoadConstUInt8 | OpCode::LoadConstInt
            | OpCode::LoadConstDouble | OpCode::LoadConstString | OpCode::LoadConstStringLongIndex
            | OpCode::LoadConstEmpty | OpCode::LoadConstBigInt | OpCode::LoadConstBigIntLongIndex
            | OpCode::LoadParam | OpCode::LoadParamLong
            | OpCode::LoadFromEnvironment
            // Arithmetic / bitwise — pure computation
            | OpCode::Add | OpCode::AddN | OpCode::Sub | OpCode::SubN | OpCode::Mul | OpCode::MulN
            | OpCode::Div | OpCode::DivN | OpCode::Mod
            | OpCode::BitAnd | OpCode::BitOr | OpCode::BitXor | OpCode::BitNot
            | OpCode::LShift | OpCode::RShift | OpCode::URshift
            | OpCode::Negate | OpCode::Inc | OpCode::Dec
            | OpCode::Add32 | OpCode::Sub32 | OpCode::Mul32 | OpCode::Divi32 | OpCode::Divu32
            // Comparison — pure, no mutation
            | OpCode::Less | OpCode::Greater
            | OpCode::Eq | OpCode::Neq | OpCode::StrictEq | OpCode::StrictNeq
            | OpCode::InstanceOf | OpCode::IsIn
            // Type operations — pure queries
            | OpCode::TypeOf | OpCode::TypeOfIs | OpCode::ToNumber | OpCode::ToNumeric | OpCode::ToInt32
            | OpCode::AddEmptyString
            | OpCode::CoerceThisNS | OpCode::LoadThisNS
            // Property reads — observable via getters, but treated as pure for decompilation
            | OpCode::GetById | OpCode::GetByIdShort | OpCode::GetByIdLong
            | OpCode::TryGetById | OpCode::TryGetByIdLong
            | OpCode::GetByVal
            | OpCode::GetByIndex
            // Object/array construction — pure allocation
            | OpCode::NewObject | OpCode::NewObjectWithBuffer | OpCode::NewObjectWithBufferLong
            | OpCode::NewArray | OpCode::NewArrayWithBuffer | OpCode::NewArrayWithBufferLong
            | OpCode::NewFastArray
            | OpCode::CreateRegExp
            | OpCode::CreateThis | OpCode::CreateThisForNew
            | OpCode::NewTypedObjectWithBuffer
            // Closure environment reads
            | OpCode::GetClosureEnvironment | OpCode::GetParentEnvironment | OpCode::GetEnvironment
            | OpCode::GetGlobalObject
            // Control flow
            | OpCode::Mov | OpCode::MovLong
            | OpCode::Phi
            | OpCode::Not
            // Iterator protocol
            | OpCode::IteratorNext | OpCode::IteratorClose
            | OpCode::GetPNameList | OpCode::GetNextPName
            | OpCode::GetBuiltinClosure
            // Misc pure ops
            | OpCode::GetNewTarget
            | OpCode::GetArgumentsLength | OpCode::GetArgumentsPropByVal
            | OpCode::ReifyArguments | OpCode::ReifyArgumentsStrict
            | OpCode::SelectObject
            | OpCode::Unreachable
            | OpCode::ProfilePoint
            | OpCode::Debugger
            | OpCode::AsyncBreakCheck
    )
}

/// String-based purity check (backward compat — delegates to typed version).
pub(crate) fn is_pure(name: &str) -> bool {
    // Fast path: use the string name to look up by first char
    // This is called from has_side_effects which is used by DCE and inlining.
    // Once all callers migrate to is_pure_op, this can be removed.
    matches!(
        name,
        "LoadConstUndefined"
            | "LoadConstNull"
            | "LoadConstTrue"
            | "LoadConstFalse"
            | "LoadConstZero"
            | "LoadConstUInt8"
            | "LoadConstInt"
            | "LoadConstDouble"
            | "LoadConstString"
            | "LoadConstStringLongIndex"
            | "LoadConstEmpty"
            | "LoadConstBigInt"
            | "LoadConstBigIntLongIndex"
            | "LoadParam"
            | "LoadParamLong"
            | "LoadFromEnvironment"
            | "LoadFromEnvironmentLong"
            | "Add"
            | "AddN"
            | "Sub"
            | "SubN"
            | "Mul"
            | "MulN"
            | "Div"
            | "DivN"
            | "Mod"
            | "ModN"
            | "Exp"
            | "BitAnd"
            | "BitOr"
            | "BitXor"
            | "BitNot"
            | "LShift"
            | "RShift"
            | "URshift"
            | "Negate"
            | "Inc"
            | "Dec"
            | "Add32"
            | "Sub32"
            | "Mul32"
            | "Divi32"
            | "Divu32"
            | "Less"
            | "LessN"
            | "LessEqual"
            | "LessEqualN"
            | "Greater"
            | "GreaterN"
            | "GreaterEqual"
            | "GreaterEqualN"
            | "Eq"
            | "Neq"
            | "StrictEq"
            | "StrictNeq"
            | "InstanceOf"
            | "IsIn"
            | "TypeOf"
            | "TypeOfIs"
            | "ToNumber"
            | "ToNumeric"
            | "ToInt32"
            | "ToString"
            | "AddEmptyString"
            | "CoerceThisNS"
            | "LoadThisNS"
            | "GetById"
            | "GetByIdShort"
            | "GetByIdLong"
            | "TryGetById"
            | "TryGetByIdLong"
            | "GetByVal"
            | "GetByIndex"
            | "NewObject"
            | "NewObjectWithBuffer"
            | "NewObjectWithBufferLong"
            // Synthetic op from `optimize::resolve_buffers` cluster-fold:
            // folds `NewObjectWithBuffer + PutOwnBySlotIdx` into a single
            // object literal. Pure because it replaces pure primitives.
            | "HermesObjectLit"
            // Synthetic op from `optimize::rewrite_object_spread_sugar`:
            // folds `NewObject + copyDataProperties + PutOwn*` into one
            // object literal with spread entries. Pure for the same
            // reason as HermesObjectLit — replaces an allocator + pure
            // property writes with a single literal expression.
            | "HermesObjectSpreadLit"
            | "NewArray"
            | "NewArrayWithBuffer"
            | "NewArrayWithBufferLong"
            | "NewFastArray"
            | "CreateRegExp"
            | "CreateThis"
            | "CreateThisForNew"
            | "NewTypedObjectWithBuffer"
            | "GetClosureEnvironment"
            | "GetParentEnvironment"
            | "GetEnvironment"
            | "GetGlobalObject"
            | "Mov"
            | "MovLong"
            | "Phi"
            | "Not"
            | "IteratorNext"
            | "IteratorClose"
            | "GetPNameList"
            | "GetNextPName"
            | "GetBuiltinClosure"
            | "GetNewTarget"
            | "GetArgumentsLength"
            | "GetArgumentsPropByVal"
            | "ReifyArguments"
            | "ReifyArgumentsStrict"
            | "SelectObject"
            | "Unreachable"
            | "ProfilePoint"
            | "Debugger"
            | "AsyncBreakCheck"
    )
}

/// A single entry in an object literal — either a `key: value` pair or
/// a `...source` spread. Lets `Expr::ObjectLit` represent ES2018
/// object-spread syntax. Display renders `KeyVal` as `key: value`
/// (or `"key": value` for non-identifier keys) and `Spread` as
/// `...source`.
#[derive(Debug, Clone, serde::Serialize)]
pub enum ObjectEntry {
    KeyVal(String, Expr),
    Spread(Expr),
}

impl ObjectEntry {
    /// Construct a key-value entry. Shorthand for construction sites
    /// that push `(String, Expr)` pairs.
    pub fn kv(key: impl Into<String>, value: Expr) -> Self {
        Self::KeyVal(key.into(), value)
    }

    /// Construct a spread entry — `...source` in the rendered output.
    pub fn spread(value: Expr) -> Self {
        Self::Spread(value)
    }
}

impl std::fmt::Display for ObjectEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ObjectEntry::KeyVal(key, value) => {
                if is_valid_js_ident(key) {
                    write!(f, "{key}: {value}")
                } else {
                    // Quote keys that aren't valid JS identifiers
                    // (strings with special chars, numeric-looking
                    // tokens, etc.). Escape `\\`, `"`, and newlines so
                    // the emitted text is parseable back.
                    let escaped = key
                        .replace('\\', "\\\\")
                        .replace('"', "\\\"")
                        .replace('\n', "\\n");
                    write!(f, "\"{escaped}\": {value}")
                }
            }
            ObjectEntry::Spread(value) => write!(f, "...{value}"),
        }
    }
}

/// A structured JS expression.
#[derive(Debug, Clone, serde::Serialize)]
#[non_exhaustive]
pub enum Expr {
    // Atoms
    Literal(Literal),
    Var(VarId),
    Global,
    This,
    Param {
        index: u32,
    },

    // Operators
    Binary {
        op: BinOp,
        left: Box<Expr>,
        right: Box<Expr>,
    },
    Unary {
        op: UnaryOp,
        operand: Box<Expr>,
    },

    // Access
    Member {
        object: Box<Expr>,
        property: String,
    },
    Index {
        object: Box<Expr>,
        index: Box<Expr>,
    },

    // Calls
    Call {
        callee: Box<Expr>,
        this_arg: Option<Box<Expr>>,
        args: Vec<Expr>,
    },
    MethodCall {
        object: Box<Expr>,
        method: String,
        args: Vec<Expr>,
    },
    New {
        callee: Box<Expr>,
        args: Vec<Expr>,
    },

    // Allocation
    ArrayLit(Vec<Expr>),
    ObjectLit(Vec<ObjectEntry>),
    RegExp {
        pattern: String,
        flags: String,
    },
    // Special
    Typeof(Box<Expr>),
    Delete(Box<Expr>),
    Assign {
        target: Box<Expr>,
        value: Box<Expr>,
    },
    Void(String),

    // JS keywords and well-known identifiers
    Arguments,
    NewTarget,
    Debugger,
    Yield(Option<Box<Expr>>),
    Await(Box<Expr>),
    Spread(Box<Expr>),

    /// A well-known global identifier (Array, Object, Reflect, eval, require).
    /// Distinguished from Var to enable pattern-matching without string comparison.
    GlobalIdent(String),

    /// Decompiler metadata — not visible in JS, internal to Hermes bytecode.
    /// Consolidates all decompiler-specific concepts that have no JS equivalent.
    /// Distinguished from JS expression variants to make the boundary explicit.
    Meta(DecompileMeta),

    /// JSX element: `<tag props>children</tag>` or `<tag props />`
    /// Reconstructed from `createElement(tag, props, ...children)` calls.
    Jsx {
        tag: Box<Expr>,
        props: Box<Expr>,
        children: Vec<Expr>,
    },

    /// Tagged template literal: `` tag`chunk0${sub0}chunk1${sub1}...chunkN` ``.
    /// Reconstructed from `Call(tag, getTemplateObject(...), ...subs)` where
    /// the `getTemplateObject` call's args resolve to the cooked/raw chunk
    /// pairs. `cooked` and `raw` always have length `subs.len() + 1`; the
    /// emit pipeline escapes cooked vs. raw form per ES spec (cooked in the
    /// template literal body, raw preserved for `.raw` access at runtime).
    TaggedTemplate {
        tag: Box<Expr>,
        cooked: Vec<String>,
        raw: Vec<String>,
        subs: Vec<Expr>,
    },

    /// Hermes DeclareGlobalVar: hoisted global variable declaration.
    /// Emitted as `/* global */ var name`.
    DeclareGlobal(String),

    /// Hermes CompleteGenerator: signals generator function completion.
    /// Usually elided by sugar pass; emitted as `return` if it survives to emit.
    CompleteGenerator,

    /// Escape hatch: raw JS expression string.
    /// Used for buffer-decoded literals and unimplemented opcode fallbacks.
    Raw(String),
}

/// Decompiler-specific metadata variants (no JS equivalent).
/// Rendered as pseudo-JS comments/identifiers during emit.
#[derive(Debug, Clone, serde::Serialize)]
pub enum DecompileMeta {
    /// Closure environment reference
    Env(EnvKind),
    /// Closure/generator function reference
    Closure {
        func_id: u32,
        kind: ClosureKind,
        /// Resolved function name (empty if unknown)
        name: String,
    },
}

#[derive(Debug, Clone, serde::Serialize)]
pub enum Literal {
    Int(i64),
    Double(f64),
    String(String),
    Bool(bool),
    Null,
    Undefined,
    /// BigInt literal rendered as its signed-decimal string (e.g. `"123"`,
    /// `"-1"`, `"123456789012345678901234567890"`). The `Display` impl
    /// emits `{s}n` to round-trip the JS BigInt literal syntax. The
    /// `String` representation (widened from `i64`) holds arbitrary-
    /// precision values that would not fit in a machine integer.
    BigInt(String),
}

#[derive(Debug, Clone, Copy, serde::Serialize)]
pub enum EnvKind {
    Current,
    Parent,
    Closure,
}

#[derive(Debug, Clone, Copy, serde::Serialize)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    /// `a ** b` (ES2016 exponentiation). Right-associative; precedence
    /// higher than `* / %`, lower than unary. Desugared from
    /// `HermesBuiltin.exponentiationOperator(a, b)` by
    /// `rewrite_exponentiation_operator` in optimize.rs.
    Exp,
    BitAnd,
    BitOr,
    BitXor,
    LShift,
    RShift,
    URShift,
    Eq,
    Neq,
    StrictEq,
    StrictNeq,
    Less,
    LessEq,
    Greater,
    GreaterEq,
    InstanceOf,
    In,
}

#[derive(Debug, Clone, Copy, serde::Serialize)]
pub enum UnaryOp {
    Neg,
    Not,
    BitNot,
    Typeof,
    Void,
    ToNumber,
    ToInt32,
    ToUint32,
}

#[derive(Debug, Clone, Copy, serde::Serialize)]
pub enum ClosureKind {
    Sync,
    Async,
    Generator,
}

/// Try to convert a Call or MethodCall expression into an Expr::Jsx.
/// Returns the original expression unchanged if it's not a createElement call
/// or the tag doesn't look like a valid component.
fn try_convert_jsx(expr: Expr) -> Expr {
    let (tag_expr, props_expr, children) = match &expr {
        Expr::Call { callee, args, .. } if !args.is_empty() => {
            let is_create_element = matches!(callee.as_ref(),
                Expr::Member { property, .. } if property == "createElement");
            if !is_create_element {
                return expr;
            }
            let tag = args[0].clone();
            let props = if args.len() > 1 {
                args[1].clone()
            } else {
                Expr::Literal(Literal::Null)
            };
            let children: Vec<Expr> = args.iter().skip(2).cloned().collect();
            (tag, props, children)
        }
        Expr::MethodCall { method, args, .. } if method == "createElement" && !args.is_empty() => {
            let tag = args[0].clone();
            let props = if args.len() > 1 {
                args[1].clone()
            } else {
                Expr::Literal(Literal::Null)
            };
            let children: Vec<Expr> = args.iter().skip(2).cloned().collect();
            (tag, props, children)
        }
        _ => return expr,
    };

    // Validate tag looks like a component (not a number, object, etc.)
    let tag_str = format!("{tag_expr}");
    let tag_name = tag_str.rsplit('.').next().unwrap_or(&tag_str);
    if tag_name.is_empty()
        || tag_name.contains('[')
        || tag_name.contains(']')
        || tag_name.contains('(')
        || tag_name.contains(')')
        || tag_name.starts_with(|c: char| c.is_ascii_digit() || c == '{')
    {
        return expr; // Not a recognizable component
    }

    Expr::Jsx {
        tag: Box::new(tag_expr),
        props: Box::new(props_expr),
        children,
    }
}

/// Format JSX props for Display. Converts Expr props to JSX attribute syntax.
fn format_jsx_props(props: &Expr) -> String {
    match props {
        Expr::Literal(Literal::Null) => String::new(),
        Expr::ObjectLit(entries) if entries.is_empty() => String::new(),
        Expr::ObjectLit(entries) => {
            let mut jsx_props = String::new();
            for entry in entries {
                // JSX doesn't support spread-in-props at this pass (it's
                // a different attribute form: `<X {...rest}/>`); if one
                // shows up, rendering it as-text via Display preserves
                // round-trip signal without pretending JSX supports it.
                let (key, val) = match entry {
                    ObjectEntry::KeyVal(k, v) => (k, v),
                    ObjectEntry::Spread(_) => {
                        if !jsx_props.is_empty() {
                            jsx_props.push(' ');
                        }
                        jsx_props.push_str(&format!("{{{entry}}}"));
                        continue;
                    }
                };
                if !jsx_props.is_empty() {
                    jsx_props.push(' ');
                }
                let val_str = format!("{val}");
                if val_str == "true" {
                    jsx_props.push_str(key);
                } else {
                    jsx_props.push_str(&format!("{key}={{{val_str}}}"));
                }
            }
            if jsx_props.is_empty() {
                String::new()
            } else {
                format!(" {jsx_props}")
            }
        }
        other => {
            let p = format!("{other}");
            if p == "null" || p == "undefined" || p == "{  }" {
                String::new()
            } else if p.starts_with("{ ") && p.ends_with(" }") {
                // Inline object from Raw/buffer: { key: val, ... } → key={val} ...
                let inner = &p[2..p.len().saturating_sub(2)];
                let mut jsx_props = String::new();
                for prop in inner.split(", ") {
                    if let Some((key, val)) = prop.split_once(": ") {
                        if !jsx_props.is_empty() {
                            jsx_props.push(' ');
                        }
                        if val == "true" {
                            jsx_props.push_str(key);
                        } else {
                            jsx_props.push_str(&format!("{key}={{{val}}}"));
                        }
                    }
                }
                if jsx_props.is_empty() {
                    String::new()
                } else {
                    format!(" {jsx_props}")
                }
            } else {
                format!(" {{...{p}}}")
            }
        }
    }
}

/// JS-spec intrinsic global names that hermesc routes through `globalThis`
/// property access even when the source wrote the bare identifier. Keeping
/// the list hermes-local (not in `droidsaw-common`) because these are JS
/// language-spec names, not Dalvik / shared-algorithm concerns. Additions must be
/// unambiguously non-shadowable by typical user code: constructors / module
/// objects only, never DOM hosts (`window`, `document`).
pub(super) fn is_intrinsic_global(name: &str) -> bool {
    matches!(
        name,
        "Symbol"
            | "Array"
            | "Object"
            | "Promise"
            | "Map"
            | "Set"
            | "WeakMap"
            | "WeakSet"
            | "Proxy"
            | "Reflect"
            | "JSON"
            | "Math"
            | "Error"
            | "String"
            | "Number"
            | "Boolean"
            | "BigInt"
            | "Date"
            | "RegExp"
    )
}

impl std::fmt::Display for Expr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Expr::Literal(lit) => write!(f, "{lit}"),
            // Use VarId's Display (r0_1) — already valid JS identifiers
            Expr::Var(v) => write!(f, "{v}"),
            Expr::Global => write!(f, "globalThis"),
            Expr::This => write!(f, "this"),
            Expr::Param { index } => {
                if *index == 0 {
                    write!(f, "this")
                } else {
                    write!(f, "a{}", index.saturating_sub(1))
                }
            }
            Expr::Binary { op, left, right } => {
                // Parenthesize nested binary expressions with lower precedence
                let left_str = if let Expr::Binary { op: inner_op, .. } = left.as_ref() {
                    if inner_op.precedence() < op.precedence() {
                        format!("({left})")
                    } else {
                        format!("{left}")
                    }
                } else {
                    format!("{left}")
                };
                let right_str = if let Expr::Binary { op: inner_op, .. } = right.as_ref() {
                    if inner_op.precedence() <= op.precedence() {
                        format!("({right})")
                    } else {
                        format!("{right}")
                    }
                } else {
                    format!("{right}")
                };
                write!(f, "{left_str} {op} {right_str}")
            }
            Expr::Unary { op, operand } => match op {
                UnaryOp::Neg => write!(f, "-{operand}"),
                UnaryOp::Not => write!(f, "!{operand}"),
                UnaryOp::BitNot => write!(f, "~{operand}"),
                UnaryOp::Typeof => write!(f, "typeof {operand}"),
                UnaryOp::Void => write!(f, "void {operand}"),
                UnaryOp::ToNumber => write!(f, "+{operand}"),
                UnaryOp::ToInt32 => write!(f, "{operand} | 0"),
                UnaryOp::ToUint32 => write!(f, "{operand} >>> 0"),
            },
            Expr::Member { object, property } => {
                // Intrinsic-global unwrap: `globalThis.Symbol` → `Symbol`,
                // `globalThis.Math` → `Math`, etc. Source-level bare references
                // to JS-spec intrinsics compile through hermesc as
                // `TryGetById globalThis, "<name>"` → `Member { Global, name }`.
                // Stripping the `globalThis.` qualifier at emit restores the
                // source shape (`Math.sqrt(...)` rather than
                // `globalThis.Math.sqrt(...)`). Non-intrinsic property calls
                // (`user.doStuff()`, `globalThis.print(...)`) stay untouched.
                // Scope cousin handled below in `Expr::GlobalIdent` for the
                // `CallBuiltin` path where `builtin_name(id)` returns
                // `"globalThis.Symbol"` / `"globalThis.eval"` as literals.
                // `Expr::Raw("globalThis")` arises when the GetGlobalObject
                // result is named `"globalThis"` by `optimize::name_variables`
                // and then inserted into the inline_map as a Raw rename (the
                // canonical path; `structure.rs:1760`). `Expr::Global` is the
                // defensive match for the rare case where no var-name rename
                // intervenes between `build_expr` and Display.
                let obj_is_global = match object.as_ref() {
                    Expr::Global => true,
                    Expr::Raw(s) => s == "globalThis",
                    _ => false,
                };
                if obj_is_global && is_intrinsic_global(property) {
                    return write!(f, "{property}");
                }
                // Wrap numeric literals in parens to prevent 1.prop → (1).prop
                let obj_str = format!("{object}");
                let needs_parens = obj_str
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_digit() || c == '-');
                let obj_fmt = if needs_parens {
                    format!("({obj_str})")
                } else {
                    obj_str
                };
                // Use bracket notation for non-identifier properties (e.g., "content-disposition")
                if property.is_empty()
                    || (!property
                        .chars()
                        .next()
                        .is_some_and(|c| c.is_ascii_alphabetic())
                        && !property.starts_with('_')
                        && !property.starts_with('$'))
                    || !property
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
                {
                    write!(
                        f,
                        "{obj_fmt}[\"{}\"]",
                        property
                            .replace('\\', "\\\\")
                            .replace('"', "\\\"")
                            .replace('\n', "\\n")
                            .replace('\r', "\\r")
                    )
                } else {
                    write!(f, "{obj_fmt}.{property}")
                }
            }
            Expr::Index { object, index } => write!(f, "{object}[{index}]"),
            Expr::Call {
                callee,
                this_arg,
                args,
            } => {
                if let Some(this_expr) = this_arg {
                    let this_str = format!("{this_expr}");
                    // Skip thisArg if it's undefined (may have been a Var at build time
                    // that resolved to undefined after substitution)
                    if this_str == "undefined" {
                        let args_str: Vec<String> = args.iter().map(|a| format!("{a}")).collect();
                        return write!(f, "{callee}({})", args_str.join(", "));
                    }
                    // If callee is obj.method and thisArg is obj, it's a normal method call
                    let is_method_call = matches!(callee.as_ref(), Expr::Member { object, .. }
                        if format!("{object}") == this_str);
                    if is_method_call {
                        let args_str: Vec<String> = args.iter().map(|a| format!("{a}")).collect();
                        write!(f, "{callee}({})", args_str.join(", "))
                    } else {
                        // Genuine .call() — preserve explicit this binding
                        let mut all_args = vec![this_str];
                        all_args.extend(args.iter().map(|a| format!("{a}")));
                        write!(f, "{callee}.call({})", all_args.join(", "))
                    }
                } else {
                    let args_str: Vec<String> = args.iter().map(|a| format!("{a}")).collect();
                    write!(f, "{callee}({})", args_str.join(", "))
                }
            }
            Expr::MethodCall {
                object,
                method,
                args,
            } => {
                let args_str: Vec<String> = args.iter().map(|a| format!("{a}")).collect();
                if method.starts_with('[') {
                    write!(f, "{object}{method}({})", args_str.join(", "))
                } else {
                    write!(f, "{object}.{method}({})", args_str.join(", "))
                }
            }
            Expr::New { callee, args } => {
                let args_str: Vec<String> = args.iter().map(|a| format!("{a}")).collect();
                write!(f, "new {callee}({})", args_str.join(", "))
            }
            Expr::ArrayLit(items) => {
                let items_str: Vec<String> = items.iter().map(|i| format!("{i}")).collect();
                write!(f, "[{}]", items_str.join(", "))
            }
            Expr::ObjectLit(entries) => {
                let entries_str: Vec<String> = entries.iter().map(|e| format!("{e}")).collect();
                write!(f, "{{ {} }}", entries_str.join(", "))
            }
            Expr::RegExp { pattern, flags } => {
                // Sanitize: strip line terminators, escape unescaped forward slashes.
                // The pattern from the Hermes string table is already in regex-internal
                // format — forward slashes that were escaped in source (`\/`) are stored
                // as `\/`. We must NOT double-escape them.
                let mut safe_pattern = String::with_capacity(pattern.len());
                let mut chars = pattern.chars().peekable();
                while let Some(c) = chars.next() {
                    match c {
                        '\\' => {
                            // Backslash: emit it and the next char verbatim (it's an escape sequence)
                            safe_pattern.push('\\');
                            if let Some(esc) = chars.next() {
                                safe_pattern.push(esc);
                            }
                        }
                        '/' => {
                            // Unescaped forward slash: must escape for regex literal delimiter
                            safe_pattern.push('\\');
                            safe_pattern.push('/');
                        }
                        '\n' | '\r' | '\u{2028}' | '\u{2029}' => {
                            safe_pattern.push('\\');
                            safe_pattern.push('n');
                        }
                        _ => safe_pattern.push(c),
                    }
                }
                // Only allow valid regex flags
                let safe_flags: String = flags.chars().filter(|c| "dgimsuy".contains(*c)).collect();
                write!(f, "/{safe_pattern}/{safe_flags}")
            }
            Expr::Meta(DecompileMeta::Closure {
                func_id,
                kind,
                name,
            }) => {
                let prefix = match kind {
                    ClosureKind::Sync => "closure",
                    ClosureKind::Async => "async",
                    ClosureKind::Generator => "generator",
                };
                if name.is_empty() {
                    write!(f, "null /* {prefix} #{func_id} */")
                } else {
                    write!(f, "null /* {prefix} {name} #{func_id} */")
                }
            }
            Expr::Typeof(operand) => write!(f, "typeof {operand}"),
            Expr::Delete(operand) => write!(f, "delete {operand}"),
            Expr::Assign { target, value } => {
                let t = format!("{target}");
                // Comment out assignments to reserved literals (false = x is invalid JS)
                if matches!(
                    t.as_str(),
                    "false"
                        | "true"
                        | "undefined"
                        | "null"
                        | "this"
                        | "return"
                        | "throw"
                        | "delete"
                        | "class"
                        | "function"
                        | "catch"
                        | "finally"
                ) {
                    write!(f, "/* {t} = {value} */")
                } else {
                    write!(f, "{t} = {value}")
                }
            }
            Expr::Void(comment) => write!(f, "void 0 /* {comment} */"),
            Expr::Arguments => write!(f, "arguments"),
            Expr::NewTarget => write!(f, "new.target"),
            Expr::Debugger => write!(f, "debugger"),
            Expr::Yield(Some(value)) => write!(f, "yield {value}"),
            Expr::Yield(None) => write!(f, "yield"),
            Expr::Await(value) => write!(f, "await {value}"),
            Expr::Spread(operand) => write!(f, "...{operand}"),
            Expr::GlobalIdent(name) => {
                // Sanitize Hermes internal names (? prefix)
                let safe = if name.contains('?') {
                    name.replace('?', "_")
                } else {
                    name.clone()
                };
                // Intrinsic-global unwrap for the CallBuiltin path: names like
                // `"globalThis.Symbol"` / `"globalThis.eval"` come from
                // `builtin_name(id)` as literals (not Member + Global). Strip
                // the `globalThis.` qualifier when the suffix is a known
                // intrinsic so the call renders as `Symbol(...)` rather than
                // `globalThis.Symbol(...)`. Keeps non-intrinsic GlobalIdent
                // names untouched.
                if let Some(suffix) = safe.strip_prefix("globalThis.")
                    && is_intrinsic_global(suffix)
                {
                    return write!(f, "{suffix}");
                }
                write!(f, "{safe}")
            }
            Expr::Jsx {
                tag,
                props,
                children,
            } => {
                let tag_str = format!("{tag}");
                // Strip quotes from string literal tags: "div" → div
                let tag_name =
                    if tag_str.starts_with('"') && tag_str.ends_with('"') && tag_str.len() > 2 {
                        &tag_str[1..tag_str.len().saturating_sub(1)]
                    } else {
                        // Use the last component for qualified names: r3.View → View
                        tag_str.rsplit('.').next().unwrap_or(&tag_str)
                    };
                let props_str = format_jsx_props(props);
                if children.is_empty() {
                    write!(f, "<{tag_name}{props_str} />")
                } else {
                    let children_str: Vec<String> =
                        children.iter().map(|c| format!("{c}")).collect();
                    write!(
                        f,
                        "<{tag_name}{props_str}>{}</{tag_name}>",
                        children_str.join(", ")
                    )
                }
            }
            Expr::TaggedTemplate {
                tag,
                cooked: _,
                raw,
                subs,
            } => {
                // Emit `` tag`raw0${sub0}raw1${sub1}...rawN` `` using the RAW
                // chunks as the template-literal body. Hermes stores both
                // cooked and raw forms; the cooked form is what `.valueOf()`
                // would produce from the literal, the raw form preserves the
                // escape sequences (\n as 2 chars rather than newline). Round-
                // tripping through hermesc requires the raw form in the
                // literal body so the recompiled cooked/raw pair reproduces
                // the original bytecode chunks. If the lengths don't line up
                // (malformed rewrite), fall back to a call-shaped fallback.
                if raw.len() != subs.len().saturating_add(1) {
                    let args_str: Vec<String> =
                        subs.iter().map(|s| format!("{s}")).collect();
                    return write!(f, "{tag}(/* tagged-template malformed */ {})", args_str.join(", "));
                }
                let tag_str = format!("{tag}");
                // Wrap the tag expression in parens when it's not a simple
                // identifier/member expression — e.g. binary, assignment, or
                // call results — so `(a||b)`tpl`` parses correctly.
                let tag_needs_parens = matches!(
                    tag.as_ref(),
                    Expr::Binary { .. }
                        | Expr::Unary { .. }
                        | Expr::Assign { .. }
                        | Expr::New { .. }
                );
                if tag_needs_parens {
                    write!(f, "({tag_str})`")?;
                } else {
                    write!(f, "{tag_str}`")?;
                }
                // raw[0] chunk0 ${sub0} raw[1] chunk1 ... raw[N].
                //
                // Hermes's raw chunks are the source-level bytes between
                // `` ` `` delimiters verbatim — they should already contain
                // `\\\``, `\\${`, etc. for any source-level escapes. But for
                // adversarial HBC (attacker-crafted or bit-flipped string
                // tables that stash a literal backtick / unescaped `${` /
                // trailing `\` into a raw chunk) we escape defensively so
                // the re-parseable JS invariant holds end-to-end. See
                // `tagged_template_raw_escape_hazards` fixture for the
                // coverage entry.
                for (i, chunk) in raw.iter().enumerate() {
                    f.write_str(&escape_template_raw_chunk(chunk))?;
                    if i < subs.len() {
                        write!(f, "${{{}}}", subs[i])?;
                    }
                }
                write!(f, "`")
            }
            Expr::Meta(DecompileMeta::Env(EnvKind::Current)) => write!(f, "_env"),
            Expr::Meta(DecompileMeta::Env(EnvKind::Parent)) => write!(f, "_parentEnv"),
            Expr::Meta(DecompileMeta::Env(EnvKind::Closure)) => write!(f, "_env"),
            Expr::DeclareGlobal(name) => {
                let safe = name.replace('?', "_");
                write!(f, "/* global */ var {safe}")
            }
            Expr::CompleteGenerator => write!(f, "return"),
            Expr::Raw(s) => {
                // Sanitize: strip line terminators that could inject code
                let safe: String = s
                    .chars()
                    .map(|c| match c {
                        '\n' | '\r' | '\u{2028}' | '\u{2029}' => ' ',
                        '`' => '\'',
                        '?' => '_',
                        _ => c,
                    })
                    .collect();
                // Intrinsic-global unwrap for the `var_names` rename path:
                // `optimize::name_variables` builds chains like `"globalThis.Symbol"`
                // for multi-use intrinsic-read vars, which `structure.rs:1760`
                // inserts into the inline_map as `Expr::Raw`. Strip the
                // `globalThis.` qualifier when the full remainder is a known
                // intrinsic identifier so the emit renders as the bare name.
                // Limited to the exact two-segment `globalThis.<intrinsic>`
                // shape — longer Raw strings (`"globalThis.Math.PI"` would be
                // three-segment) fall through unchanged and continue to be
                // printed verbatim; the outer Member wraps handle deeper
                // chains via the structured path.
                if let Some(suffix) = safe.strip_prefix("globalThis.")
                    && is_intrinsic_global(suffix)
                {
                    return write!(f, "{suffix}");
                }
                write!(f, "{safe}")
            }
        }
    }
}

/// Check if a string is a valid JS identifier (safe to use unquoted as an object key).
/// Convert TypeOfIs bitfield to type name string.
/// Bitfield: bit 0=undefined, 1=object, 2=string, 3=symbol, 4=boolean, 5=number, 6=bigint, 7=function, 8=null
fn typeof_bitfield_name(bits: u16) -> &'static str {
    match bits {
        1 => "undefined",  // bit 0
        2 => "object",     // bit 1
        4 => "string",     // bit 2
        8 => "symbol",     // bit 3
        16 => "boolean",   // bit 4
        32 => "number",    // bit 5
        64 => "bigint",    // bit 6
        128 => "function", // bit 7
        256 => "null",     // bit 8 (typeof null === "object" but this is the null bit)
        _ => "unknown",    // multiple bits set or zero
    }
}

/// Defensive escape for a `TaggedTemplate` raw chunk. Well-formed Hermes-
/// emitted raw chunks already contain the source-level escape sequences
/// (`\\\``, `\\${`, etc.), so this is a no-op for any chunk whose bytes
/// originated from `hermesc`'s `getTemplateObject` lowering. The escape
/// exists to neutralize three hazards an adversarial HBC string table
/// could introduce:
///   - An unescaped `` ` `` — would close the template literal early and
///     leave residual bytes as stray JS syntax.
///   - An unescaped `${` — would open a substitution whose contents are
///     the following raw bytes, re-parseable only by accident.
///   - A trailing lone `\` — would escape the literal-closing `` ` ``
///     that immediately follows, yielding a truncated-emit parse error.
///
/// Each hazard becomes an escaped form that hermesc parses back to a raw
/// chunk containing the same bytes, preserving the round-trip property.
fn escape_template_raw_chunk(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            // Treat `\X` as a two-char source-level escape group: emit both
            // verbatim so well-formed hermesc-emitted raws round-trip
            // unchanged (the raw form already contains `\``, `\${`, etc.).
            // A trailing lone `\` gets doubled so it doesn't escape the
            // closing `` ` `` of the emitted template literal.
            '\\' => {
                out.push('\\');
                match chars.next() {
                    Some(next) => out.push(next),
                    None => out.push('\\'),
                }
            }
            // Bare unescaped backtick / `${` only reach here on adversarial
            // input (hermesc would never emit them). Escape defensively so
            // the emitted JS still re-parses as the same raw chunk.
            '`' => out.push_str("\\`"),
            '$' if chars.peek() == Some(&'{') => {
                out.push_str("\\${");
                chars.next();
            }
            other => out.push(other),
        }
    }
    out
}

pub fn is_valid_js_ident(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    // Check reserved words
    if matches!(
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
    ) {
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

impl std::fmt::Display for Literal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Literal::Int(n) => write!(f, "{n}"),
            Literal::Double(d) => {
                if d.is_nan() {
                    write!(f, "NaN")
                } else if d.is_infinite() {
                    if *d > 0.0 {
                        write!(f, "Infinity")
                    } else {
                        write!(f, "-Infinity")
                    }
                } else {
                    write!(f, "{d}")
                }
            }
            Literal::String(s) => {
                let escaped = s
                    .replace('\\', "\\\\")
                    .replace('"', "\\\"")
                    .replace('\n', "\\n")
                    .replace('\r', "\\r")
                    .replace('\0', "\\0")
                    .replace('\u{2028}', "\\u2028")
                    .replace('\u{2029}', "\\u2029");
                write!(f, "\"{escaped}\"")
            }
            Literal::Bool(b) => write!(f, "{b}"),
            Literal::Null => write!(f, "null"),
            Literal::Undefined => write!(f, "undefined"),
            Literal::BigInt(s) => write!(f, "{s}n"),
        }
    }
}

impl Expr {
    /// Recursively substitute `Expr::Var(v)` nodes with values from the map.
    /// This is the tree-based replacement for string-level `word_boundary_replace`.
    pub fn substitute(self, map: &std::collections::BTreeMap<VarId, Expr>) -> Expr {
        try_convert_jsx(self.substitute_depth(map, 0))
    }

    fn substitute_depth(
        self,
        map: &std::collections::BTreeMap<VarId, Expr>,
        depth: usize,
    ) -> Expr {
        // Guard against cycles in the inline map
        debug_assert!(
            depth <= 32,
            "Expr substitution depth {} exceeds 32. Likely cycle in inline map.",
            depth
        );
        if depth > 32 {
            return self;
        }
        match self {
            Expr::Var(v) => {
                match map.get(&v) {
                    Some(replacement) => replacement.clone().substitute_depth(map, depth.saturating_add(1)),
                    None => Expr::Var(v),
                }
            }
            Expr::Binary { op, left, right } => Expr::Binary {
                op,
                left: Box::new(left.substitute_depth(map, depth.saturating_add(1))),
                right: Box::new(right.substitute_depth(map, depth.saturating_add(1))),
            },
            Expr::Unary { op, operand } => Expr::Unary {
                op,
                operand: Box::new(operand.substitute_depth(map, depth.saturating_add(1))),
            },
            Expr::Member { object, property } => Expr::Member {
                object: Box::new(object.substitute_depth(map, depth.saturating_add(1))),
                property,
            },
            Expr::Index { object, index } => Expr::Index {
                object: Box::new(object.substitute_depth(map, depth.saturating_add(1))),
                index: Box::new(index.substitute_depth(map, depth.saturating_add(1))),
            },
            Expr::Call {
                callee,
                this_arg,
                args,
            } => Expr::Call {
                callee: Box::new(callee.substitute_depth(map, depth.saturating_add(1))),
                this_arg: this_arg.map(|t| Box::new(t.substitute_depth(map, depth.saturating_add(1)))),
                args: args
                    .into_iter()
                    .map(|a| a.substitute_depth(map, depth.saturating_add(1)))
                    .collect(),
            },
            Expr::MethodCall {
                object,
                method,
                args,
            } => Expr::MethodCall {
                object: Box::new(object.substitute_depth(map, depth.saturating_add(1))),
                method,
                args: args
                    .into_iter()
                    .map(|a| a.substitute_depth(map, depth.saturating_add(1)))
                    .collect(),
            },
            Expr::Jsx {
                tag,
                props,
                children,
            } => Expr::Jsx {
                tag: Box::new(tag.substitute_depth(map, depth.saturating_add(1))),
                props: Box::new(props.substitute_depth(map, depth.saturating_add(1))),
                children: children
                    .into_iter()
                    .map(|c| c.substitute_depth(map, depth.saturating_add(1)))
                    .collect(),
            },
            Expr::TaggedTemplate {
                tag,
                cooked,
                raw,
                subs,
            } => Expr::TaggedTemplate {
                tag: Box::new(tag.substitute_depth(map, depth.saturating_add(1))),
                cooked,
                raw,
                subs: subs
                    .into_iter()
                    .map(|s| s.substitute_depth(map, depth.saturating_add(1)))
                    .collect(),
            },
            Expr::New { callee, args } => Expr::New {
                callee: Box::new(callee.substitute_depth(map, depth.saturating_add(1))),
                args: args
                    .into_iter()
                    .map(|a| a.substitute_depth(map, depth.saturating_add(1)))
                    .collect(),
            },
            Expr::ArrayLit(items) => Expr::ArrayLit(
                items
                    .into_iter()
                    .map(|i| i.substitute_depth(map, depth.saturating_add(1)))
                    .collect(),
            ),
            Expr::ObjectLit(entries) => Expr::ObjectLit(
                entries
                    .into_iter()
                    .map(|e| match e {
                        ObjectEntry::KeyVal(k, v) => ObjectEntry::KeyVal(
                            k,
                            v.substitute_depth(map, depth.saturating_add(1)),
                        ),
                        ObjectEntry::Spread(v) => {
                            ObjectEntry::Spread(v.substitute_depth(map, depth.saturating_add(1)))
                        }
                    })
                    .collect(),
            ),
            Expr::Typeof(operand) => {
                Expr::Typeof(Box::new(operand.substitute_depth(map, depth.saturating_add(1))))
            }
            Expr::Delete(operand) => {
                Expr::Delete(Box::new(operand.substitute_depth(map, depth.saturating_add(1))))
            }
            Expr::Assign { target, value } => Expr::Assign {
                target: Box::new(target.substitute_depth(map, depth.saturating_add(1))),
                value: Box::new(value.substitute_depth(map, depth.saturating_add(1))),
            },
            Expr::Yield(Some(v)) => Expr::Yield(Some(Box::new(v.substitute_depth(map, depth.saturating_add(1))))),
            Expr::Await(v) => Expr::Await(Box::new(v.substitute_depth(map, depth.saturating_add(1)))),
            Expr::Spread(v) => Expr::Spread(Box::new(v.substitute_depth(map, depth.saturating_add(1)))),
            // Atoms — no substitution possible
            other @ (Expr::Literal(_)
            | Expr::Global
            | Expr::This
            | Expr::Param { .. }
            | Expr::RegExp { .. }
            | Expr::Meta(DecompileMeta::Closure { .. })
            | Expr::Void(_)
            | Expr::Arguments
            | Expr::NewTarget
            | Expr::Debugger
            | Expr::Yield(None)
            | Expr::GlobalIdent(_)
            | Expr::Meta(DecompileMeta::Env(_))
            | Expr::DeclareGlobal(_)
            | Expr::CompleteGenerator
            | Expr::Raw(_)) => other,
        }
    }
}

impl BinOp {
    /// JS operator precedence (higher = binds tighter). Per MDN / ES spec:
    /// exponentiation at 14 (right-assoc, higher than `* / %`), followed by
    /// multiplicative at 13, additive at 12, etc.
    fn precedence(self) -> u8 {
        match self {
            BinOp::Exp => 14,
            BinOp::Mul | BinOp::Div | BinOp::Mod => 13,
            BinOp::Add | BinOp::Sub => 12,
            BinOp::LShift | BinOp::RShift | BinOp::URShift => 11,
            BinOp::Less
            | BinOp::LessEq
            | BinOp::Greater
            | BinOp::GreaterEq
            | BinOp::InstanceOf
            | BinOp::In => 10,
            BinOp::Eq | BinOp::Neq | BinOp::StrictEq | BinOp::StrictNeq => 9,
            BinOp::BitAnd => 8,
            BinOp::BitXor => 7,
            BinOp::BitOr => 6,
        }
    }
}

impl std::fmt::Display for BinOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            BinOp::Add => "+",
            BinOp::Sub => "-",
            BinOp::Mul => "*",
            BinOp::Div => "/",
            BinOp::Mod => "%",
            BinOp::Exp => "**",
            BinOp::BitAnd => "&",
            BinOp::BitOr => "|",
            BinOp::BitXor => "^",
            BinOp::LShift => "<<",
            BinOp::RShift => ">>",
            BinOp::URShift => ">>>",
            BinOp::Eq => "==",
            BinOp::Neq => "!=",
            BinOp::StrictEq => "===",
            BinOp::StrictNeq => "!==",
            BinOp::Less => "<",
            BinOp::LessEq => "<=",
            BinOp::Greater => ">",
            BinOp::GreaterEq => ">=",
            BinOp::InstanceOf => "instanceof",
            BinOp::In => "in",
        };
        write!(f, "{s}")
    }
}

use super::ssa::{SsaOp, SsaOperand};

/// Convert a VarId operand to an Expr
fn var_expr(ops: &[SsaOperand], i: usize) -> Expr {
    match ops.get(i) {
        Some(SsaOperand::Var(v)) => Expr::Var(*v),
        Some(SsaOperand::Const(c)) => Expr::Literal(Literal::Int(*c)),
        Some(SsaOperand::ConstDouble(d)) => Expr::Literal(Literal::Double(*d)),
        Some(SsaOperand::StringId(s)) => Expr::Literal(Literal::String(format!("str[{s}]"))),
        Some(SsaOperand::ResolvedString(s)) => Expr::Literal(Literal::String(s.clone())),
        Some(SsaOperand::ResolvedBigInt(s)) => Expr::Literal(Literal::BigInt(s.clone())),
        Some(SsaOperand::FuncId(f)) => Expr::Meta(DecompileMeta::Closure {
            func_id: *f,
            kind: ClosureKind::Sync,
            name: String::new(),
        }),
        Some(SsaOperand::DstPlaceholder) => Expr::Void("dst".into()),
        Some(SsaOperand::BlockTarget(_)) => Expr::Void("target".into()),
        None => Expr::Literal(Literal::Undefined),
    }
}

/// Extract thisArg for Call1-4: returns Some(expr) only for genuine .call() patterns.
/// Most non-undefined thisArgs are method calls (obj.method(args)) where Pattern C
/// should have rewritten to MethodCall. We only emit .call() when the callee is NOT
/// a member expression — if callee is `obj.prop`, thisArg=obj is the normal method
/// call convention and should be elided.
fn call_this_arg(ops: &[SsaOperand], callee_idx: usize, this_idx: usize) -> Option<Box<Expr>> {
    let this_expr = var_expr(ops, this_idx);
    match &this_expr {
        Expr::Literal(Literal::Undefined) => None,
        _ => {
            // If callee operand points to a Var (will be inlined to Member at emit time),
            // we can't check its shape here. Only suppress for obvious cases:
            // if callee and thisArg are the same var, it's self-reference (not .call).
            // Otherwise, emit .call() to preserve the explicit this binding.
            let callee_op = ops.get(callee_idx);
            let this_op = ops.get(this_idx);
            // If both are the same var, this is an unusual pattern — skip thisArg
            if let (Some(SsaOperand::Var(cv)), Some(SsaOperand::Var(tv))) = (callee_op, this_op)
                && cv == tv
            {
                return None;
            }
            Some(Box::new(this_expr))
        }
    }
}

/// Build a structured Expr from an SsaOp.
/// Falls back to Raw(format_op) for unimplemented arms.
pub fn build_expr(op: &SsaOp, get_str: &dyn Fn(u32) -> String) -> Expr {
    let ops = &op.operands;
    let expr = match op.name {
        // Binary arithmetic
        "Add" | "AddN" => binary(BinOp::Add, ops),
        "Sub" | "SubN" => binary(BinOp::Sub, ops),
        "Mul" | "MulN" => binary(BinOp::Mul, ops),
        "Div" | "DivN" => binary(BinOp::Div, ops),
        "Mod" => binary(BinOp::Mod, ops),

        // Binary bitwise
        "BitAnd" => binary(BinOp::BitAnd, ops),
        "BitOr" => binary(BinOp::BitOr, ops),
        "BitXor" => binary(BinOp::BitXor, ops),
        "LShift" => binary(BinOp::LShift, ops),
        "RShift" => binary(BinOp::RShift, ops),
        "URshift" => binary(BinOp::URShift, ops),

        // Binary comparison
        "Eq" => binary(BinOp::Eq, ops),
        "Neq" => binary(BinOp::Neq, ops),
        "StrictEq" => binary(BinOp::StrictEq, ops),
        "StrictNeq" => binary(BinOp::StrictNeq, ops),
        "Less" => binary(BinOp::Less, ops),
        "LessEq" => binary(BinOp::LessEq, ops),
        "Greater" => binary(BinOp::Greater, ops),
        "GreaterEq" => binary(BinOp::GreaterEq, ops),
        "InstanceOf" => binary(BinOp::InstanceOf, ops),
        "IsIn" => binary(BinOp::In, ops),

        // Unary
        "Negate" => Expr::Unary {
            op: UnaryOp::Neg,
            operand: Box::new(var_expr(ops, 1)),
        },
        "Not" => Expr::Unary {
            op: UnaryOp::Not,
            operand: Box::new(var_expr(ops, 1)),
        },
        "BitNot" => Expr::Unary {
            op: UnaryOp::BitNot,
            operand: Box::new(var_expr(ops, 1)),
        },
        "TypeOf" => Expr::Typeof(Box::new(var_expr(ops, 1))),
        "ToNumber" | "ToNumeric" => Expr::Unary {
            op: UnaryOp::ToNumber,
            operand: Box::new(var_expr(ops, 1)),
        },
        "ToInt32" => Expr::Unary {
            op: UnaryOp::ToInt32,
            operand: Box::new(var_expr(ops, 1)),
        },
        "ToUint32" => Expr::Unary {
            op: UnaryOp::ToUint32,
            operand: Box::new(var_expr(ops, 1)),
        },
        "Inc" => Expr::Binary {
            op: BinOp::Add,
            left: Box::new(var_expr(ops, 1)),
            right: Box::new(Expr::Literal(Literal::Int(1))),
        },
        "Dec" => Expr::Binary {
            op: BinOp::Sub,
            left: Box::new(var_expr(ops, 1)),
            right: Box::new(Expr::Literal(Literal::Int(1))),
        },

        // Constants
        "LoadConstNull" => Expr::Literal(Literal::Null),
        "LoadConstUndefined" => Expr::Literal(Literal::Undefined),
        "LoadConstTrue" => Expr::Literal(Literal::Bool(true)),
        "LoadConstFalse" => Expr::Literal(Literal::Bool(false)),
        "LoadConstZero" => Expr::Literal(Literal::Int(0)),
        "LoadConstEmpty" => Expr::Literal(Literal::Undefined),
        "LoadConstInt" | "LoadConstUInt8" => {
            if let Some(SsaOperand::Const(v)) = ops.get(1) {
                Expr::Literal(Literal::Int(*v))
            } else {
                Expr::Literal(Literal::Int(0))
            }
        }
        "LoadConstDouble" => {
            if let Some(SsaOperand::ConstDouble(v)) = ops.get(1) {
                Expr::Literal(Literal::Double(*v))
            } else {
                Expr::Literal(Literal::Double(0.0))
            }
        }
        "LoadConstBigInt" | "LoadConstBigIntLongIndex" => {
            // `optimize::resolve_bigints` rewrites operand[1] from
            // `Const(table-index)` to `ResolvedBigInt(decimal-string)` when
            // the index is in range. A surviving `Const(v)` means the pass
            // couldn't resolve — surface a loud placeholder rather than
            // silently rendering the index as the value, matching sibling
            // `missing-builtin-id` / `missing-regex-operand` behavior.
            match ops.get(1) {
                Some(SsaOperand::ResolvedBigInt(s)) => Expr::Literal(Literal::BigInt(s.clone())),
                Some(SsaOperand::Const(v)) => {
                    Expr::Raw(format!("/* missing bigint #{v} */"))
                }
                _ => Expr::Raw("/* missing bigint */".into()),
            }
        }
        "LoadConstString" | "LoadConstStringLongIndex" => {
            if let Some(SsaOperand::StringId(s)) = ops.get(1) {
                Expr::Literal(Literal::String(get_str(*s)))
            } else {
                Expr::Literal(Literal::String(String::new()))
            }
        }

        // Parameters
        "LoadParam" | "LoadParamLong" => {
            if let Some(SsaOperand::Const(idx)) = ops.get(1) {
                Expr::Param { index: const_id_to_u32(*idx) }
            } else {
                Expr::Param { index: 0 }
            }
        }

        // Global
        "GetGlobalObject" => Expr::Global,

        // Member access
        n if n.starts_with("GetById") || n.starts_with("TryGetById") => {
            let obj = var_expr(ops, 1);
            let prop = match ops.last() {
                Some(SsaOperand::Const(sid)) => Some(get_str(const_id_to_u32(*sid))),
                Some(SsaOperand::ResolvedString(s)) => Some(s.clone()),
                _ => None,
            };
            if let Some(prop) = prop {
                Expr::Member {
                    object: Box::new(obj),
                    property: prop,
                }
            } else {
                Expr::Raw(super::structure::format_op(op, get_str))
            }
        }
        "GetByVal" => Expr::Index {
            object: Box::new(var_expr(ops, 1)),
            index: Box::new(var_expr(ops, 2)),
        },

        // Object/array
        "NewObject" => Expr::ObjectLit(vec![]),
        "NewArray" => {
            if let Some(SsaOperand::Const(n)) = ops.get(1) {
                Expr::Call {
                    callee: Box::new(Expr::GlobalIdent("Array".into())),
                    this_arg: None,
                    args: vec![Expr::Literal(Literal::Int(*n))],
                }
            } else {
                Expr::ArrayLit(vec![])
            }
        }
        "NewFastArray" => Expr::ArrayLit(vec![]),
        "CacheNewObject" => Expr::ObjectLit(vec![]),
        "Mov" | "MovLong" => var_expr(ops, 1),

        // --- Phase 2: Calls ---

        // Call1: (dst, callee, thisArg) — zero user args
        "Call1" => {
            let this_arg = call_this_arg(ops, 1, 2);
            Expr::Call {
                callee: Box::new(var_expr(ops, 1)),
                this_arg,
                args: vec![],
            }
        }
        // Call2-4: (dst, callee, thisArg, arg1, ...)
        "Call2" => {
            let this_arg = call_this_arg(ops, 1, 2);
            Expr::Call {
                callee: Box::new(var_expr(ops, 1)),
                this_arg,
                args: vec![var_expr(ops, 3)],
            }
        }
        "Call3" => {
            let this_arg = call_this_arg(ops, 1, 2);
            Expr::Call {
                callee: Box::new(var_expr(ops, 1)),
                this_arg,
                args: vec![var_expr(ops, 3), var_expr(ops, 4)],
            }
        }
        "Call4" => {
            let this_arg = call_this_arg(ops, 1, 2);
            Expr::Call {
                callee: Box::new(var_expr(ops, 1)),
                this_arg,
                args: vec![var_expr(ops, 3), var_expr(ops, 4), var_expr(ops, 5)],
            }
        }

        // MethodCall: (dst, obj, "method", args...)
        "MethodCall" => {
            let obj = var_expr(ops, 1);
            let method = match ops.get(2) {
                Some(SsaOperand::ResolvedString(s)) => s.clone(),
                _ => "?".into(),
            };
            let args: Vec<Expr> = ops.iter().skip(3).map(operand_to_expr).collect();
            Expr::MethodCall {
                object: Box::new(obj),
                method,
                args,
            }
        }

        // Construct
        "Construct" | "ConstructLong" => Expr::New {
            callee: Box::new(var_expr(ops, 1)),
            args: vec![],
        },
        "ConstructNew" => {
            let callee = var_expr(ops, 1);
            let args: Vec<Expr> = ops.iter().skip(3).map(operand_to_expr).collect();
            Expr::New {
                callee: Box::new(callee),
                args,
            }
        }

        // --- Phase 2: Stores (return Assign expressions) ---
        n if n.starts_with("PutById") || n.starts_with("TryPutById") => {
            let obj = var_expr(ops, 0);
            let prop = match ops.last() {
                Some(SsaOperand::Const(sid)) => Some(get_str(const_id_to_u32(*sid))),
                Some(SsaOperand::ResolvedString(s)) => Some(s.clone()),
                _ => None,
            };
            if let Some(prop) = prop {
                Expr::Assign {
                    target: Box::new(Expr::Member {
                        object: Box::new(obj),
                        property: prop,
                    }),
                    value: Box::new(var_expr(ops, 1)),
                }
            } else {
                Expr::Raw(super::structure::format_op(op, get_str))
            }
        }
        n if n.starts_with("PutNewOwnById")
            || n.starts_with("PutNewOwnNEById")
            || n.starts_with("DefineOwnById") =>
        {
            let obj = var_expr(ops, 0);
            let val = var_expr(ops, 1);
            if let Some(SsaOperand::Const(sid)) = ops.last() {
                let prop = get_str(const_id_to_u32(*sid));
                Expr::Assign {
                    target: Box::new(Expr::Member {
                        object: Box::new(obj),
                        property: prop,
                    }),
                    value: Box::new(val),
                }
            } else {
                Expr::Raw(super::structure::format_op(op, get_str))
            }
        }
        "PutByVal" | "PutByValLoose" | "PutByValStrict" => Expr::Assign {
            target: Box::new(Expr::Index {
                object: Box::new(var_expr(ops, 0)),
                index: Box::new(var_expr(ops, 1)),
            }),
            value: Box::new(var_expr(ops, 2)),
        },
        "PutOwnByIndex" | "PutOwnByIndexL" => Expr::Assign {
            target: Box::new(Expr::Index {
                object: Box::new(var_expr(ops, 0)),
                index: Box::new(var_expr(ops, 2)),
            }),
            value: Box::new(var_expr(ops, 1)),
        },
        "PutOwnByVal" => Expr::Assign {
            target: Box::new(Expr::Index {
                object: Box::new(var_expr(ops, 0)),
                index: Box::new(var_expr(ops, 2)),
            }),
            value: Box::new(var_expr(ops, 1)),
        },
        // Semantically: obj.shape.keys[slot_idx] = val. `optimize::resolve_buffers`
        // rewrites operand[2] from `Const(slot_idx)` to `ResolvedString(key_name)`
        // when the defining `NewObjectWithBuffer`'s shape is known — that's the
        // common case for hermesc output. Unresolved cases (obj from a cross-
        // block def, or pre-v97 buffer format we don't track) fall back to the
        // legacy indexed emit, which syntactically mutates the JS property named
        // `"{slot}"` — incorrect but preserves observable shape.
        "PutOwnBySlotIdx" | "PutOwnBySlotIdxLong" => {
            let target = match ops.get(2) {
                Some(SsaOperand::ResolvedString(key)) if is_valid_js_ident(key) => Expr::Member {
                    object: Box::new(var_expr(ops, 0)),
                    property: key.clone(),
                },
                Some(SsaOperand::ResolvedString(key)) => Expr::Index {
                    object: Box::new(var_expr(ops, 0)),
                    index: Box::new(Expr::Literal(Literal::String(key.clone()))),
                },
                _ => Expr::Index {
                    object: Box::new(var_expr(ops, 0)),
                    index: Box::new(var_expr(ops, 2)),
                },
            };
            Expr::Assign {
                target: Box::new(target),
                value: Box::new(var_expr(ops, 1)),
            }
        }
        "GetOwnBySlotIdx" | "GetOwnBySlotIdxLong" => Expr::Index {
            object: Box::new(var_expr(ops, 1)),
            index: Box::new(var_expr(ops, 2)),
        },

        // FastArray operations (v97+)
        "FastArrayStore" => Expr::Assign {
            target: Box::new(Expr::Index {
                object: Box::new(var_expr(ops, 0)),
                index: Box::new(var_expr(ops, 1)),
            }),
            value: Box::new(var_expr(ops, 2)),
        },
        "FastArrayLoad" => Expr::Index {
            object: Box::new(var_expr(ops, 1)),
            index: Box::new(var_expr(ops, 2)),
        },
        "FastArrayLength" => Expr::Member {
            object: Box::new(var_expr(ops, 1)),
            property: "length".into(),
        },
        "FastArrayPush" => Expr::MethodCall {
            object: Box::new(var_expr(ops, 0)),
            method: "push".into(),
            args: vec![var_expr(ops, 1)],
        },
        "FastArrayAppend" => Expr::MethodCall {
            object: Box::new(var_expr(ops, 0)),
            method: "push".into(),
            args: vec![Expr::Spread(Box::new(var_expr(ops, 1)))],
        },

        // --- Phase 2: Closures ---
        "CreateClosure" | "CreateClosureLongIndex" => {
            closure_expr_or_placeholder(ops, ClosureKind::Sync)
        }
        "CreateAsyncClosure" | "CreateAsyncClosureLongIndex" => {
            closure_expr_or_placeholder(ops, ClosureKind::Async)
        }
        "CreateGeneratorClosure"
        | "CreateGeneratorClosureLongIndex"
        | "CreateGenerator"
        | "CreateGeneratorLongIndex" => closure_expr_or_placeholder(ops, ClosureKind::Generator),

        // --- Phase 2: Environment ---
        "CreateEnvironment" | "CreateFunctionEnvironment" | "CreateTopLevelEnvironment" => {
            Expr::Meta(DecompileMeta::Env(EnvKind::Current))
        }
        "GetEnvironment" => Expr::Meta(DecompileMeta::Env(EnvKind::Current)),
        "GetParentEnvironment" => Expr::Meta(DecompileMeta::Env(EnvKind::Parent)),
        n if n.starts_with("LoadFromEnvironment") => {
            // Check for closure name sentinel
            if let Some(SsaOperand::Const(sentinel)) = ops.get(1) {
                let s = const_id_to_u32(*sentinel);
                if s & 0xF000_0000 == 0xF000_0000 {
                    let level = (s >> 16) & 0xFFF;
                    let slot = s & 0xFFFF;
                    // Use resolved name if available
                    if let Some(SsaOperand::ResolvedString(name)) = ops.get(2) {
                        return Expr::Raw(format!("_closure{level}_{name}"));
                    }
                    return Expr::Raw(format!("_closure{level}_slot{slot}"));
                }
            }
            Expr::Member {
                object: Box::new(var_expr(ops, 1)),
                property: format!(
                    "slot[{}]",
                    match ops.get(2) {
                        Some(SsaOperand::Const(c)) => format!("{c}"),
                        _ => "?".into(),
                    }
                ),
            }
        }
        n if n.starts_with("StoreToEnvironment") || n.starts_with("StoreNPToEnvironment") => {
            Expr::Assign {
                target: Box::new(Expr::Member {
                    object: Box::new(var_expr(ops, 0)),
                    property: format!(
                        "slot[{}]",
                        match ops.get(1) {
                            Some(SsaOperand::Const(c)) => format!("{c}"),
                            _ => "?".into(),
                        }
                    ),
                }),
                value: Box::new(var_expr(ops, 2)),
            }
        }

        // --- Phase 2: Misc ---
        "Catch" => Expr::Void("caught exception".into()),
        "Debugger" => Expr::Debugger,
        // No-ops: profiling and async break checks don't affect program semantics
        "ProfilePoint" | "AsyncBreakCheck" => Expr::Void("".into()),
        // This coercion: load `this` for non-strict mode
        "CoerceThisNS" | "LoadThisNS" => Expr::This,
        // Closure environment access
        "GetClosureEnvironment" => Expr::Meta(DecompileMeta::Env(EnvKind::Closure)),
        // TypeOfIs / JmpTypeOfIs: typeof x matches type bitfield
        // Bitfield: 0=Undefined, 1=Object, 2=String, 3=Symbol, 4=Boolean, 5=Number, 6=Bigint, 7=Function, 8=Null
        "TypeOfIs" | "JmpTypeOfIs" => {
            let type_name = match ops.get(2) {
                Some(SsaOperand::Const(tag)) => typeof_bitfield_name(const_tag_to_u16(*tag)),
                _ => "unknown",
            };
            Expr::Binary {
                op: BinOp::StrictEq,
                left: Box::new(Expr::Unary {
                    op: UnaryOp::Typeof,
                    operand: Box::new(var_expr(ops, 1)),
                }),
                right: Box::new(Expr::Literal(Literal::String(type_name.into()))),
            }
        }
        "DirectEval" => Expr::Call {
            callee: Box::new(Expr::GlobalIdent("eval".into())),
            this_arg: None,
            args: vec![var_expr(ops, 1)],
        },
        "Throw" => Expr::Raw(format!("throw {}", var_expr(ops, 0))),
        // Runtime assertion: throws if this was already initialized in derived constructor.
        // No JS equivalent — elide from output.
        "ThrowIfThisInitialized" => Expr::Void("".into()),
        "DeclareGlobalVar" => {
            if let Some(SsaOperand::Const(sid)) = ops.first() {
                Expr::DeclareGlobal(get_str(const_id_to_u32(*sid)))
            } else {
                Expr::DeclareGlobal("?".into())
            }
        }
        "AddEmptyString" | "AddS" => Expr::Binary {
            op: BinOp::Add,
            left: Box::new(Expr::Literal(Literal::String(String::new()))),
            right: Box::new(var_expr(ops, 1)),
        },

        // Delete
        "DelById" | "DelByIdLong" => {
            if let Some(SsaOperand::Const(sid)) = ops.last() {
                let prop = get_str(const_id_to_u32(*sid));
                Expr::Delete(Box::new(Expr::Member {
                    object: Box::new(var_expr(ops, 1)),
                    property: prop,
                }))
            } else {
                Expr::Raw(super::structure::format_op(op, get_str))
            }
        }
        // DelByVal: [R:dst, R:obj, R:key]
        "DelByVal" => Expr::Delete(Box::new(Expr::Index {
            object: Box::new(var_expr(ops, 1)),
            index: Box::new(var_expr(ops, 2)),
        })),

        // Buffer-decoded objects/arrays
        "NewObjectWithBuffer" | "NewObjectWithBufferLong" | "NewObjectWithBufferAndParent" => {
            if let Some(SsaOperand::ResolvedString(s)) = ops.get(1) {
                Expr::Raw(s.clone())
            } else {
                Expr::ObjectLit(vec![])
            }
        }
        "NewArrayWithBuffer" | "NewArrayWithBufferLong" => {
            if let Some(SsaOperand::ResolvedString(s)) = ops.get(1) {
                Expr::Raw(s.clone())
            } else {
                Expr::ArrayLit(vec![])
            }
        }
        "NewObjectWithParent" => Expr::Call {
            callee: Box::new(Expr::Member {
                object: Box::new(Expr::GlobalIdent("Object".into())),
                property: "create".into(),
            }),
            this_arg: None,
            args: vec![var_expr(ops, 1)],
        },

        // For-in
        "GetPNameList" => Expr::Call {
            callee: Box::new(Expr::Member {
                object: Box::new(Expr::GlobalIdent("Object".into())),
                property: "keys".into(),
            }),
            this_arg: None,
            args: vec![var_expr(ops, 1)],
        },
        "GetNextPName" => Expr::MethodCall {
            object: Box::new(var_expr(ops, 1)),
            method: "next".into(),
            args: vec![],
        },
        "IteratorBegin" => Expr::MethodCall {
            object: Box::new(var_expr(ops, 1)),
            method: "[Symbol.iterator]".into(),
            args: vec![],
        },
        "IteratorNext" | "IteratorClose" => Expr::MethodCall {
            object: Box::new(var_expr(ops, 1)),
            method: if op.name == "IteratorNext" {
                "next"
            } else {
                "return"
            }
            .into(),
            args: vec![],
        },

        // Generator
        "StartGenerator" => Expr::Void("generator start".into()),
        "ResumeGenerator" => Expr::Void("resume".into()),
        "SaveGenerator" | "SaveGeneratorLong" => Expr::Yield(None),
        "CompleteGenerator" => Expr::CompleteGenerator,

        // Arguments
        "GetArgumentsLength" => Expr::Member {
            object: Box::new(Expr::Arguments),
            property: "length".into(),
        },
        n if n.starts_with("GetArgumentsPropByVal") => Expr::Index {
            object: Box::new(Expr::Arguments),
            index: Box::new(var_expr(ops, 1)),
        },
        n if n.starts_with("ReifyArguments") => Expr::Call {
            callee: Box::new(Expr::Member {
                object: Box::new(Expr::GlobalIdent("Array".into())),
                property: "from".into(),
            }),
            this_arg: None,
            args: vec![Expr::Arguments],
        },

        // CreateThis
        "CreateThisForNew" | "CreateThisForSuper" | "CreateThis" => Expr::Call {
            callee: Box::new(Expr::Member {
                object: Box::new(Expr::GlobalIdent("Object".into())),
                property: "create".into(),
            }),
            this_arg: None,
            args: vec![Expr::Member {
                object: Box::new(var_expr(ops, 1)),
                property: "prototype".into(),
            }],
        },
        // SelectObject picks constructor return: typeof ret === "object" ? ret : this
        "SelectObject" => var_expr(ops, 0),
        "GetNewTarget" => Expr::NewTarget,

        // Regex
        "CreateRegExp" => {
            // Missing/malformed pattern or flags operand: surface as a
            // degenerate placeholder instead of falling to an empty string
            // (which would silently emit `new RegExp("", "")` — indistinguishable
            // from a genuine empty regex literal in source).
            let pattern = match ops.get(1) {
                Some(SsaOperand::Const(id)) => Some(get_str(const_id_to_u32(*id))),
                Some(SsaOperand::ResolvedString(s)) => Some(s.clone()),
                Some(SsaOperand::StringId(id)) => Some(get_str(*id)),
                _ => None,
            };
            let flags = match ops.get(2) {
                Some(SsaOperand::Const(id)) => Some(get_str(const_id_to_u32(*id))),
                Some(SsaOperand::ResolvedString(s)) => Some(s.clone()),
                Some(SsaOperand::StringId(id)) => Some(get_str(*id)),
                _ => None,
            };
            match (pattern, flags) {
                (Some(pattern), Some(flags)) => Expr::RegExp { pattern, flags },
                _ => Expr::Raw("/* missing regex operand */".into()),
            }
        }

        // Builtins — ops = [DstPlaceholder, builtin_id, argcount, arg0, arg1, ...]
        // (no thisArg slot: the interpreter's `implCallBuiltin` sets thisArg
        // to implicit undefined, so SSA's variadic resolver does not push one).
        "CallBuiltin" | "CallBuiltinLong" => {
            // Desugar known source-level operator-to-builtin lowerings at
            // emit time. Hermes has no dedicated bytecode for ES2016 `**`,
            // so the compiler emits `HermesBuiltin.exponentiationOperator(a, b)`;
            // unwind it back to the binary form. Roundtrip is preserved —
            // hermesc re-emits the call during its own codegen. Guard on
            // exact arg count (2) so malformed input falls through to the
            // generic Call-emit rather than producing a broken Binary.
            if let Some(SsaOperand::Const(id)) = ops.get(1)
                && is_exponentiation_operator(const_id_to_u32(*id)).is_some()
                && ops.len() == 5
            {
                return Expr::Binary {
                    op: BinOp::Exp,
                    left: Box::new(operand_to_expr(&ops[3])),
                    right: Box::new(operand_to_expr(&ops[4])),
                };
            }
            let callee = match ops.get(1) {
                Some(SsaOperand::Const(id)) => {
                    Expr::GlobalIdent(builtin_name(const_id_to_u32(*id)).into())
                }
                // Missing/malformed builtin-id operand: surface as a degenerate
                // placeholder instead of falling to id=0 (which would silently
                // render as `globalThis.Symbol(args)`).
                _ => Expr::Raw("/* missing builtin_id */".into()),
            };
            // Skip [dst, builtin_id, argcount]; args are the resolved
            // variadic operands pushed by `ssa::build_ssa`. If `frame_size`
            // was unavailable (pre-v97 headers), this yields an empty arg
            // list — preferred over silently treating argcount as an arg.
            let args: Vec<Expr> = ops.iter().skip(3).map(operand_to_expr).collect();
            Expr::Call {
                callee: Box::new(callee),
                this_arg: None,
                args,
            }
        }
        "GetBuiltinClosure" => match ops.get(1) {
            Some(SsaOperand::Const(id)) => Expr::GlobalIdent(builtin_name(const_id_to_u32(*id)).into()),
            // Missing/malformed builtin-id operand: surface as a degenerate
            // placeholder instead of falling to id=0.
            _ => Expr::Raw("/* missing builtin_id */".into()),
        },

        // Synthetic op produced by `optimize::rewrite_tagged_templates`.
        // Operand layout:
        //   [DstPlaceholder, tag, Const(N), cooked0, raw0, ..., cookedN-1, rawN-1, subs…]
        // N >= 1, subs.len() == N - 1. Malformed shapes fall through to a
        // Raw placeholder; the rewriter is the only producer and guarantees
        // well-formedness, so this is defense-in-depth.
        "HermesTaggedTemplate" => {
            let tag_expr = var_expr(ops, 1);
            let chunk_count = match ops.get(2) {
                #[allow(clippy::as_conversions, reason = "i64→usize narrows; `n` is the call's variadic-arg count (bounded by the callsite's frame_size operand, ≤ u8 in HBC headers); guarded by `*n >= 1` ahead of cast.")]
                Some(SsaOperand::Const(n)) if *n >= 1 => *n as usize,
                _ => return Expr::Raw("/* malformed tagged-template */".into()),
            };
            let needed = 3usize.saturating_add(chunk_count.saturating_mul(2));
            if ops.len() < needed {
                return Expr::Raw("/* malformed tagged-template */".into());
            }
            let mut cooked = Vec::with_capacity(chunk_count);
            let mut raw = Vec::with_capacity(chunk_count);
            for i in 0..chunk_count {
                let key_idx = 3usize.saturating_add(i.saturating_mul(2));
                match (ops.get(key_idx), ops.get(key_idx.saturating_add(1))) {
                    (
                        Some(SsaOperand::ResolvedString(c)),
                        Some(SsaOperand::ResolvedString(r)),
                    ) => {
                        cooked.push(c.clone());
                        raw.push(r.clone());
                    }
                    _ => return Expr::Raw("/* malformed tagged-template */".into()),
                }
            }
            let subs: Vec<Expr> = ops.iter().skip(needed).map(operand_to_expr).collect();
            Expr::TaggedTemplate {
                tag: Box::new(tag_expr),
                cooked,
                raw,
                subs,
            }
        }

        // Synthetic op produced by `optimize::rewrite_array_spread_sugar`.
        // Operand layout:
        //   [DstPlaceholder, ResolvedString(prefix_literal), Var(spread_src), <trailing_expr>]
        // where `prefix_literal` is the original NewArrayWithBuffer-
        // emitted array like `[5]` or `[1, 2, 3]` or `[]`. Parse out the
        // inner elements, then emit `[<prefix...>, ...spread_src,
        // <trailing>]` as a structured ArrayLit.
        "HermesArraySpreadLit" => {
            let Some(SsaOperand::ResolvedString(prefix_str)) = ops.get(1) else {
                return Expr::Raw("/* malformed array-spread */".into());
            };
            // Parse `[a, b, c]` → individual element exprs. The prefix
            // comes from resolve_buffers's literal-value emission, so
            // elements are always scalar JS literals (numbers, strings,
            // booleans, null, undefined). Split on top-level `, ` —
            // safe for these shapes since no element contains `, ` in
            // its emitted form. Empty `[]` yields an empty prefix.
            let trimmed = prefix_str.trim();
            let inner = trimmed
                .strip_prefix('[')
                .and_then(|s| s.strip_suffix(']'))
                .map(str::trim)
                .unwrap_or("");
            let prefix_elements: Vec<Expr> = if inner.is_empty() {
                Vec::new()
            } else {
                inner
                    .split(", ")
                    .map(|s| Expr::Raw(s.to_string()))
                    .collect()
            };
            let spread_src = operand_to_expr(&ops[2]);
            let trailing = operand_to_expr(&ops[3]);
            let mut items = prefix_elements;
            items.push(Expr::Spread(Box::new(spread_src)));
            items.push(trailing);
            Expr::ArrayLit(items)
        }

        // Synthetic op produced by `optimize::resolve_buffers`'s cluster-fold
        // post-pass. Operand layout: [dst, key1_str, val1_operand, key2_str,
        // val2_operand, ...] where each valN is either `ResolvedString(token)`
        // for source-literals (rendered as-is — `null`, `false`, `42`,
        // `"hello"`) or `Var(v)` for folded slots (resolved through the
        // normal substitute pipeline). Renders as
        // `Expr::ObjectLit(Vec<(key, val_expr)>)`; `Display for Expr::ObjectLit`
        // handles ident-vs-quoted key rendering via `is_valid_js_ident`.
        "HermesObjectLit" => {
            let mut pairs: Vec<(String, Expr)> = Vec::new();
            let mut i: usize = 1;
            while i.saturating_add(1) < ops.len() {
                let key = match ops.get(i) {
                    Some(SsaOperand::ResolvedString(k)) => k.clone(),
                    _ => return Expr::Raw("/* malformed HermesObjectLit key */".into()),
                };
                let value_expr = match ops.get(i.saturating_add(1)) {
                    Some(SsaOperand::ResolvedString(token)) => Expr::Raw(token.clone()),
                    Some(other) => operand_to_expr(other),
                    None => return Expr::Raw("/* malformed HermesObjectLit value */".into()),
                };
                pairs.push((key, value_expr));
                i = i.saturating_add(2);
            }
            Expr::ObjectLit(
                pairs
                    .into_iter()
                    .map(|(k, v)| ObjectEntry::KeyVal(k, v))
                    .collect(),
            )
        }

        // Synthetic op produced by `optimize::rewrite_object_spread_sugar`.
        // Operand layout: [Dst, tag1, operand1, tag2, operand2, ...]
        // where each tag is a ResolvedString — `"K:<keyname>"` for a
        // KeyVal entry (value operand follows) or `"S"` for a spread
        // entry (source operand follows). Renders as
        // `Expr::ObjectLit(Vec<ObjectEntry>)` with `KeyVal` / `Spread`
        // entries in source order; `Display for Expr::ObjectLit` +
        // `Display for ObjectEntry` handle the final token output
        // (`{a: 1, ...src, c: 3}`).
        "HermesObjectSpreadLit" => {
            let mut entries: Vec<ObjectEntry> = Vec::new();
            let mut i: usize = 1;
            while i.saturating_add(1) < ops.len() {
                let tag = match ops.get(i) {
                    Some(SsaOperand::ResolvedString(t)) => t.clone(),
                    _ => return Expr::Raw("/* malformed object-spread */".into()),
                };
                let value_operand = ops.get(i.saturating_add(1));
                let Some(value_operand) = value_operand else {
                    return Expr::Raw("/* malformed object-spread */".into());
                };
                // Mirror HermesObjectLit's value-resolution rule: a
                // `ResolvedString` operand is a raw JS token (a literal
                // value from the source buffer) and must render as
                // `Expr::Raw`; anything else flows through
                // `operand_to_expr`.
                let value_expr = match value_operand {
                    SsaOperand::ResolvedString(token) => Expr::Raw(token.clone()),
                    other => operand_to_expr(other),
                };
                if let Some(rest) = tag.strip_prefix("K:") {
                    entries.push(ObjectEntry::KeyVal(rest.to_string(), value_expr));
                } else if tag == "S" {
                    entries.push(ObjectEntry::Spread(value_expr));
                } else {
                    return Expr::Raw("/* malformed object-spread tag */".into());
                }
                i = i.saturating_add(2);
            }
            Expr::ObjectLit(entries)
        }

        "CallWithNewTarget" | "CallWithNewTargetLong" => Expr::Call {
            callee: Box::new(Expr::Member {
                object: Box::new(Expr::GlobalIdent("Reflect".into())),
                property: "construct".into(),
            }),
            this_arg: None,
            args: vec![var_expr(ops, 1), Expr::ArrayLit(vec![])],
        },

        // Class (v99)
        "CreateBaseClass" | "CreateBaseClassLongIndex" => Expr::Void("class".into()),
        "CreateDerivedClass" | "CreateDerivedClassLongIndex" => Expr::Void("class extends".into()),
        "CreatePrivateName" => Expr::Void("private".into()),
        // LoadParentNoTraps: loads the parent class of a constructor.
        // `super` is only valid inside class methods, so emit as
        // Object.getPrototypeOf(class) for general context safety.
        "LoadParentNoTraps" => Expr::Call {
            callee: Box::new(Expr::Member {
                object: Box::new(Expr::GlobalIdent("Object".into())),
                property: "getPrototypeOf".into(),
            }),
            this_arg: None,
            args: vec![var_expr(ops, 1)],
        },
        "PrivateIsIn" => Expr::Binary {
            op: BinOp::In,
            left: Box::new(var_expr(ops, 1)),
            right: Box::new(var_expr(ops, 2)),
        },
        "AddOwnPrivateBySym" => Expr::Assign {
            target: Box::new(Expr::Member {
                object: Box::new(var_expr(ops, 1)),
                property: "_private".into(),
            }),
            value: Box::new(var_expr(ops, 2)),
        },
        "PutOwnPrivateBySym" => Expr::Assign {
            target: Box::new(Expr::Member {
                object: Box::new(var_expr(ops, 0)),
                property: "_private".into(),
            }),
            value: Box::new(var_expr(ops, 1)),
        },
        "GetOwnPrivateBySym" => Expr::Member {
            object: Box::new(var_expr(ops, 1)),
            property: "_private".into(),
        },

        // Remaining misc
        "DefineOwnInDenseArray" | "DefineOwnInDenseArrayL" | "DefineOwnByVal" => Expr::Assign {
            target: Box::new(Expr::Index {
                object: Box::new(var_expr(ops, 0)),
                index: Box::new(var_expr(ops, 2)),
            }),
            value: Box::new(var_expr(ops, 1)),
        },
        "GetByIndex" => Expr::Index {
            object: Box::new(var_expr(ops, 1)),
            index: Box::new(var_expr(ops, 2)),
        },
        "ThrowIfEmpty" | "ThrowIfUndefined" => var_expr(ops, 0),

        // Variadic Call: ops = [DstPlaceholder, callee, argcount, thisArg, arg1, arg2, ...]
        "Call" | "CallLong" => {
            let callee = var_expr(ops, 1);
            let this_arg = call_this_arg(ops, 1, 3);
            let args: Vec<Expr> = ops.iter().skip(4).map(operand_to_expr).collect();
            Expr::Call {
                callee: Box::new(callee),
                this_arg,
                args,
            }
        }
        // CallDirect: ops = [DstPlaceholder, argcount, func_id, thisArg, arg1, arg2, ...]
        "CallDirect" | "CallDirectLongIndex" => {
            // Surface a missing/malformed func_id operand as a placeholder rather
            // than falling through to `#0` (which would silently reference
            // function 0 — typically the global script entry — making the call
            // look legitimate). The U2/U4 immediate slot always decodes to
            // `SsaOperand::Const` in well-formed HBC, so the placeholder arm
            // is defensive against future SSA refactors.
            let callee = match ops.get(2) {
                Some(SsaOperand::Const(id)) => {
                    Expr::Raw(format!("/* direct #{} */", const_id_to_u32(*id)))
                }
                Some(SsaOperand::FuncId(id)) => Expr::Raw(format!("/* direct #{id} */")),
                _ => Expr::Raw("/* missing func_id */".into()),
            };
            let this_arg = call_this_arg(ops, 2, 3);
            let args: Vec<Expr> = ops.iter().skip(4).map(operand_to_expr).collect();
            Expr::Call {
                callee: Box::new(callee),
                this_arg,
                args,
            }
        }
        // CallRequire: [R:dst, R:callee, U4:module_id] — no implicit args
        "CallRequire" => {
            // Missing/malformed module_id operand: surface as a placeholder
            // argument instead of falling to `require(0)` (which silently
            // references module 0). Slot 2 is a U4 immediate per schemas.rs
            // and always decodes to `SsaOperand::Const` in well-formed HBC;
            // placeholder arm is defensive against future SSA refactors.
            let id_arg = match ops.get(2) {
                Some(SsaOperand::Const(id)) => Expr::Literal(Literal::Int(*id)),
                _ => Expr::Raw("/* missing module_id */".into()),
            };
            Expr::Call {
                callee: Box::new(Expr::GlobalIdent("require".into())),
                this_arg: None,
                args: vec![id_arg],
            }
        }

        // Everything else: Raw fallback
        _ => Expr::Raw(super::structure::format_op(op, get_str)),
    };
    // Convert createElement calls to Jsx at build time
    try_convert_jsx(expr)
}

fn binary(op: BinOp, ops: &[SsaOperand]) -> Expr {
    Expr::Binary {
        op,
        left: Box::new(var_expr(ops, 1)),
        right: Box::new(var_expr(ops, 2)),
    }
}

/// Convert a single SsaOperand to an Expr
/// Hermes builtin ID → name mapping.
/// From include/hermes/FrontEndDefs/Builtins.def
/// IDs are from BUILTIN_METHOD + PRIVATE_BUILTIN + JS_BUILTIN (BUILTIN_OBJECT is skipped).
fn builtin_name(id: u32) -> &'static str {
    // Builtin operand IDs verified against `hermesc -dump-bytecode` output.
    // Includes NORMAL_METHOD entries (globalThis.Symbol/eval) which take enum
    // slots and are counted in bytecode operand IDs.
    const NAMES: &[&str] = &[
        "globalThis.Symbol",
        "globalThis.eval", // 0-1
        "Array.isArray",   // 2
        "Date.UTC",
        "Date.parse", // 3-4
        "JSON.parse",
        "JSON.stringify", // 5-6
        "Math.abs",
        "Math.acos",
        "Math.asin",
        "Math.atan",
        "Math.atan2", // 7-11
        "Math.ceil",
        "Math.cos",
        "Math.exp",
        "Math.floor",
        "Math.hypot", // 12-16
        "Math.imul",
        "Math.log",
        "Math.max",
        "Math.min",
        "Math.pow", // 17-21
        "Math.round",
        "Math.sin",
        "Math.sqrt",
        "Math.tan",
        "Math.trunc", // 22-26
        "Object.create",
        "Object.defineProperties",
        "Object.defineProperty", // 27-29
        "Object.freeze",
        "Object.getOwnPropertyDescriptor", // 30-31
        "Object.getOwnPropertyNames",
        "Object.getPrototypeOf", // 32-33
        "Object.isExtensible",
        "Object.isFrozen",
        "Object.keys",
        "Object.seal",         // 34-37
        "String.fromCharCode", // 38
        "HermesBuiltin.silentSetPrototypeOf",
        "HermesBuiltin.requireFast", // 39-40
        "HermesBuiltin.getTemplateObject",
        "HermesBuiltin.ensureObject", // 41-42
        "HermesBuiltin.getMethod",
        "HermesBuiltin.throwTypeError", // 43-44
        "HermesBuiltin.throwReferenceError",
        "HermesBuiltin.copyDataProperties", // 45-46
        "HermesBuiltin.copyRestArgs",
        "HermesBuiltin.arraySpread", // 47-48
        "HermesBuiltin.apply",
        "HermesBuiltin.applyArguments", // 49-50
        "HermesBuiltin.applyWithNewTarget",
        "HermesBuiltin.exportAll", // 51-52
        "HermesBuiltin.exponentiationOperator",
        "HermesBuiltin.initRegexNamedGroups", // 53-54
        "HermesBuiltin.functionPrototypeApply",
        "HermesBuiltin.functionPrototypeCall",  // 55-56
        "HermesBuiltin.functionPrototypeCall2", // 57 (duplicate slot from MARK_FIRST_JS_BUILTIN)
        "HermesBuiltin.spawnAsync",
        "HermesBuiltin.makeAsyncIterator",   // 58-59
        "HermesBuiltin.awaitAsyncGenerator", // 60
    ];
    // WHY: u32→usize widens on every project-supported target; out-of-table
    // ids fall through `unwrap_or("builtin")`.
    #[allow(clippy::as_conversions, reason = "u32→usize widens on every project-supported target; out-of-table ids fall through `unwrap_or(\"builtin\")`.")]
    let idx = id as usize;
    NAMES.get(idx).copied().unwrap_or("builtin")
}

/// Test whether a builtin id names `HermesBuiltin.getTemplateObject`. Returns
/// `Some(())` on match, `None` otherwise. Uses the canonical `builtin_name`
/// table so the check stays in sync if the id shifts across Hermes versions.
pub(super) fn is_get_template_object(id: u32) -> Option<()> {
    (builtin_name(id) == "HermesBuiltin.getTemplateObject").then_some(())
}

/// Test whether a builtin id names `HermesBuiltin.initRegexNamedGroups`.
/// Hermes emits a call to this builtin after every regex-literal that
/// declares named capture groups, to install the `{name: group_idx}`
/// mapping on the regex object. The call is compiler-internal setup —
/// source-level JS just writes `/(?<name>...)/` — so the
/// `rewrite_regex_named_groups` sugar pass elides unused occurrences.
/// Uses the canonical `builtin_name` table so the check stays in sync if
/// the id shifts across Hermes versions.
pub(super) fn is_init_regex_named_groups(id: u32) -> Option<()> {
    (builtin_name(id) == "HermesBuiltin.initRegexNamedGroups").then_some(())
}

/// Test whether a builtin id names `HermesBuiltin.exponentiationOperator`.
/// Hermes lowers the ES2016 `a ** b` operator to this builtin at compile
/// time (no dedicated `Exp` bytecode opcode exists). The
/// `rewrite_exponentiation_operator` sugar pass inverts that lowering to
/// restore the source-level binary form.
pub(super) fn is_exponentiation_operator(id: u32) -> Option<()> {
    (builtin_name(id) == "HermesBuiltin.exponentiationOperator").then_some(())
}

/// Test whether a builtin id names `HermesBuiltin.copyRestArgs`. Hermes
/// lowers `function f(...rest) { ... }` to a leading
/// `var rest = HermesBuiltin.copyRestArgs(startIdx)` in the function
/// body, where `startIdx` counts the non-rest declared params. The
/// `rewrite_rest_params_sugar` emit-time pass inverts that lowering:
/// hoist the call into the function signature as `...rest` and rewrite
/// use sites.
pub(super) fn is_copy_rest_args(id: u32) -> Option<()> {
    (builtin_name(id) == "HermesBuiltin.copyRestArgs").then_some(())
}

/// Test whether a builtin id names `HermesBuiltin.arraySpread`. Hermes
/// lowers array-literal spread `[a, ...src, b]` to a 3-instruction
/// cluster: `NewArrayWithBuffer` (pre-alloc with leading literals) +
/// `CallBuiltin arraySpread(target, src, startIdx)` (copies src into
/// target, returns next free idx) + `DefineOwnByVal(target, value,
/// returnedIdx)` (writes trailing element). The
/// `rewrite_array_spread_sugar` pass folds the cluster into a single
/// synthetic op rendered as `Expr::ArrayLit` with `Expr::Spread` in the
/// middle.
pub(super) fn is_array_spread(id: u32) -> Option<()> {
    (builtin_name(id) == "HermesBuiltin.arraySpread").then_some(())
}

/// Match builtin id → `HermesBuiltin.copyDataProperties`. Used by
/// `optimize::rewrite_object_spread_sugar` to locate object-spread
/// clusters (`{...source}`-shaped literals that hermesc lowers to
/// `NewObject + copyDataProperties(target, source)` — sometimes with
/// trailing `PutOwnByIndex` / `PutOwnById` for explicit key-value
/// entries after the spread).
pub(super) fn is_copy_data_properties(id: u32) -> Option<()> {
    (builtin_name(id) == "HermesBuiltin.copyDataProperties").then_some(())
}

/// Build a `Closure` meta-expression from a `CreateClosure*` instruction's
/// operand list, or surface a `/* missing func_id */` placeholder if no
/// `FuncId` operand is present.
///
/// Without this placeholder, the callsites fall back to `func_id: 0`
/// (rendering as `null /* <kind> #0 */`), silently referencing function
/// 0 — which is typically the global script entry. The placeholder
/// makes a missing / malformed target id syntactically distinguishable
/// from a legitimate reference to function 0. The non-FuncId arm is unreachable via
/// well-formed HBC (the closure func-id slot is a U2/U4 immediate per
/// `schemas.rs` and is explicitly mapped to `SsaOperand::FuncId` in SSA for
/// `CreateClosure`/`CreateGenerator*` instructions); the placeholder is a
/// defensive contract against future SSA refactors.
fn closure_expr_or_placeholder(ops: &[SsaOperand], kind: ClosureKind) -> Expr {
    let fid = ops.iter().find_map(|o| {
        if let SsaOperand::FuncId(f) = o {
            Some(*f)
        } else {
            None
        }
    });
    match fid {
        Some(func_id) => Expr::Meta(DecompileMeta::Closure {
            func_id,
            kind,
            name: String::new(),
        }),
        None => Expr::Raw("/* missing func_id */".into()),
    }
}

fn operand_to_expr(o: &SsaOperand) -> Expr {
    match o {
        SsaOperand::Var(v) => Expr::Var(*v),
        SsaOperand::Const(c) => Expr::Literal(Literal::Int(*c)),
        SsaOperand::ConstDouble(d) => Expr::Literal(Literal::Double(*d)),
        SsaOperand::ResolvedString(s) => Expr::Literal(Literal::String(s.clone())),
        SsaOperand::ResolvedBigInt(s) => Expr::Literal(Literal::BigInt(s.clone())),
        SsaOperand::StringId(s) => Expr::Literal(Literal::String(format!("str[{s}]"))),
        SsaOperand::FuncId(f) => Expr::Meta(DecompileMeta::Closure {
            func_id: *f,
            kind: ClosureKind::Sync,
            name: String::new(),
        }),
        SsaOperand::DstPlaceholder | SsaOperand::BlockTarget(_) => {
            Expr::Literal(Literal::Undefined)
        }
    }
}

#[cfg(test)]
mod builtin_id_tests {
    //! Regression tests: ensure that a `CallBuiltin`
    //! / `GetBuiltinClosure` whose builtin-id slot is missing or non-`Const`
    //! surfaces a `/* missing builtin_id */` placeholder rather than silently
    //! rendering id=0 (which would otherwise emit a reference to whichever
    //! builtin happens to occupy index 0 — currently `globalThis.Symbol`).
    //!
    //! These cases only arise from malformed / adversarial bytecode: the
    //! decoder reads the slot as an immediate, so in a well-formed HBC it is
    //! always `SsaOperand::Const`. The cheapest way to lock the contract is
    //! a unit test that builds an `SsaOp` directly.
    use super::*;
    use crate::decompile::decode::DecodedInst;
    use crate::decompile::ssa::{SsaOp, SsaOperand};
    use crate::opcodes::OpCode;

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

    fn no_str(_: u32) -> String {
        String::new()
    }

    #[test]
    fn call_builtin_with_non_const_id_emits_missing_placeholder() {
        // Operand slot 1 is bound to a register (Var) instead of the expected
        // immediate Const. Without this guard, we'd silently call builtin 0 (Symbol).
        let ssa_op = SsaOp {
            name: "CallBuiltin",
            op: OpCode::CallBuiltin,
            dst: None,
            operands: vec![
                SsaOperand::DstPlaceholder,
                SsaOperand::Var(crate::decompile::ssa::VarId(0, 0)),
                SsaOperand::Const(0),
            ],
            original: stub_inst("CallBuiltin", OpCode::CallBuiltin),
        };
        let out = format!("{}", build_expr(&ssa_op, &no_str));
        assert!(
            out.contains("/* missing builtin_id */"),
            "expected missing-id placeholder, got {out:?}"
        );
        assert!(
            !out.contains("globalThis.Symbol"),
            "placeholder must not fall through to builtin id 0, got {out:?}"
        );
    }

    #[test]
    fn get_builtin_closure_with_missing_id_emits_missing_placeholder() {
        // Operand slot 1 is absent entirely (truncated operand list).
        let ssa_op = SsaOp {
            name: "GetBuiltinClosure",
            op: OpCode::GetBuiltinClosure,
            dst: None,
            operands: vec![SsaOperand::DstPlaceholder],
            original: stub_inst("GetBuiltinClosure", OpCode::GetBuiltinClosure),
        };
        let out = format!("{}", build_expr(&ssa_op, &no_str));
        assert!(
            out.contains("/* missing builtin_id */"),
            "expected missing-id placeholder, got {out:?}"
        );
        assert!(
            !out.contains("globalThis.Symbol"),
            "placeholder must not fall through to builtin id 0, got {out:?}"
        );
    }

    #[test]
    fn call_builtin_with_valid_const_id_still_renders_name() {
        // Sanity check: the Const path is untouched by the fix.
        let ssa_op = SsaOp {
            name: "CallBuiltin",
            op: OpCode::CallBuiltin,
            dst: None,
            operands: vec![
                SsaOperand::DstPlaceholder,
                SsaOperand::Const(2), // Array.isArray
                SsaOperand::Const(0),
            ],
            original: stub_inst("CallBuiltin", OpCode::CallBuiltin),
        };
        let out = format!("{}", build_expr(&ssa_op, &no_str));
        assert!(
            out.contains("Array.isArray"),
            "Const-id path must render the mapped builtin name, got {out:?}"
        );
    }
}

#[cfg(test)]
mod intrinsic_global_tests {
    //! Regression tests ensuring that JS-spec intrinsic globals reached
    //! via `globalThis.<name>` are rendered as the bare identifier so the
    //! emit matches source shape (`Symbol(x)` not `globalThis.Symbol(x)`,
    //! `Math.sqrt(y)` not `globalThis.Math.sqrt(y)`). Non-intrinsic
    //! globals stay fully qualified.
    use super::*;

    #[test]
    fn member_on_global_unwraps_intrinsic() {
        let e = Expr::Member {
            object: Box::new(Expr::Global),
            property: "Symbol".into(),
        };
        assert_eq!(format!("{e}"), "Symbol");
    }

    #[test]
    fn nested_member_on_global_unwraps_intrinsic_prefix() {
        // `globalThis.Math.sqrt` → `Math.sqrt`
        let e = Expr::Member {
            object: Box::new(Expr::Member {
                object: Box::new(Expr::Global),
                property: "Math".into(),
            }),
            property: "sqrt".into(),
        };
        assert_eq!(format!("{e}"), "Math.sqrt");
    }

    #[test]
    fn member_on_global_keeps_non_intrinsic() {
        // User-defined globals stay fully qualified — matches brief's
        // "Non-intrinsic property calls unchanged" gate.
        let e = Expr::Member {
            object: Box::new(Expr::Global),
            property: "print".into(),
        };
        assert_eq!(format!("{e}"), "globalThis.print");
    }

    #[test]
    fn member_on_non_global_unaffected() {
        // `user.Symbol` (method lookup on user object) must NOT collapse.
        let e = Expr::Member {
            object: Box::new(Expr::Var(VarId(3, 5))),
            property: "Symbol".into(),
        };
        assert_eq!(format!("{e}"), "r3_5.Symbol");
    }

    #[test]
    fn global_ident_unwraps_intrinsic_suffix() {
        // `CallBuiltin 0` path: builtin_name(0) is the literal
        // `"globalThis.Symbol"` stored in a GlobalIdent.
        let e = Expr::GlobalIdent("globalThis.Symbol".into());
        assert_eq!(format!("{e}"), "Symbol");
    }

    #[test]
    fn global_ident_keeps_non_intrinsic_suffix() {
        // `builtin_name(1)` is `"globalThis.eval"` — `eval` is not on the
        // intrinsic list (it's a sloppy-mode ambiguity trap), so the
        // GlobalIdent renders verbatim.
        let e = Expr::GlobalIdent("globalThis.eval".into());
        assert_eq!(format!("{e}"), "globalThis.eval");
    }

    #[test]
    fn global_ident_preserves_dotted_builtin() {
        // `builtin_name(5)` is `"JSON.parse"` — no `globalThis.` prefix, so
        // the unwrap logic doesn't fire and the dotted name is preserved.
        let e = Expr::GlobalIdent("JSON.parse".into());
        assert_eq!(format!("{e}"), "JSON.parse");
    }

    #[test]
    fn member_on_raw_globalthis_unwraps_intrinsic() {
        // The canonical production path: `optimize::name_variables` renames
        // the `GetGlobalObject` var to the string `"globalThis"`, which
        // `structure.rs:1760` inserts into the inline_map as `Expr::Raw`.
        // Substitution produces `Member { object: Raw("globalThis"), ... }`
        // — the Display arm treats this exactly like `Expr::Global`.
        let e = Expr::Member {
            object: Box::new(Expr::Raw("globalThis".into())),
            property: "Symbol".into(),
        };
        assert_eq!(format!("{e}"), "Symbol");
    }

    #[test]
    fn raw_globalthis_dotted_intrinsic_unwraps() {
        // Multi-use intrinsic vars get `var_names[dst] = "globalThis.Symbol"`
        // from `optimize::name_variables`, inserted as `Expr::Raw`. Display
        // must strip the qualifier so the use site emits `Symbol(...)` rather
        // than `globalThis.Symbol(...)`.
        let e = Expr::Raw("globalThis.Symbol".into());
        assert_eq!(format!("{e}"), "Symbol");
    }

    #[test]
    fn raw_globalthis_dotted_non_intrinsic_preserved() {
        // User-named globals (`print`, `record`, `ID`) must keep the
        // qualifier — matches brief's "Non-intrinsic property calls
        // unchanged" gate.
        let e = Expr::Raw("globalThis.print".into());
        assert_eq!(format!("{e}"), "globalThis.print");
    }
}

#[cfg(test)]
mod regex_operand_tests {
    //! Regression tests: ensure that a `CreateRegExp` whose pattern or
    //! flags slot is missing / non-resolvable
    //! surfaces a `/* missing regex operand */` placeholder rather than
    //! silently falling to empty strings (which would emit `new RegExp("", "")`
    //! — indistinguishable from a genuine empty regex literal in source).
    //!
    //! As with `builtin_id_tests`, the non-Const/StringId/ResolvedString arms
    //! are unreachable via well-formed HBC — the two operands are `U4`
    //! immediates per `schemas.rs` and always decode to `SsaOperand::Const`
    //! (post-resolution: `StringId` or `ResolvedString`). The placeholder
    //! contract is defensive against future SSA refactors; unit tests at the
    //! direct-`SsaOp`-construction layer are the correct lock.
    use super::*;
    use crate::decompile::decode::DecodedInst;
    use crate::decompile::ssa::{SsaOp, SsaOperand};
    use crate::opcodes::OpCode;

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

    fn const_str(_: u32) -> String {
        "hi".into()
    }

    fn no_str(_: u32) -> String {
        String::new()
    }

    #[test]
    fn create_regexp_with_non_const_pattern_emits_missing_placeholder() {
        // Operand slot 1 (pattern) is bound to a register (Var) instead of the
        // expected immediate Const. Without this guard, would emit `//` (empty regex).
        let ssa_op = SsaOp {
            name: "CreateRegExp",
            op: OpCode::CreateRegExp,
            dst: None,
            operands: vec![
                SsaOperand::DstPlaceholder,
                SsaOperand::Var(crate::decompile::ssa::VarId(0, 0)),
                SsaOperand::Const(0),
                SsaOperand::Const(0),
            ],
            original: stub_inst("CreateRegExp", OpCode::CreateRegExp),
        };
        let out = format!("{}", build_expr(&ssa_op, &no_str));
        assert!(
            out.contains("/* missing regex operand */"),
            "expected missing-operand placeholder, got {out:?}"
        );
        assert!(
            !out.contains("//"),
            "placeholder must not fall through to empty regex, got {out:?}"
        );
    }

    #[test]
    fn create_regexp_with_missing_flags_emits_missing_placeholder() {
        // Operand slot 2 (flags) is absent entirely (truncated operand list).
        let ssa_op = SsaOp {
            name: "CreateRegExp",
            op: OpCode::CreateRegExp,
            dst: None,
            operands: vec![SsaOperand::DstPlaceholder, SsaOperand::Const(0)],
            original: stub_inst("CreateRegExp", OpCode::CreateRegExp),
        };
        let out = format!("{}", build_expr(&ssa_op, &const_str));
        assert!(
            out.contains("/* missing regex operand */"),
            "expected missing-operand placeholder, got {out:?}"
        );
    }

    #[test]
    fn create_regexp_with_valid_operands_still_renders_literal() {
        // Sanity check: the resolvable path is untouched by the fix.
        let ssa_op = SsaOp {
            name: "CreateRegExp",
            op: OpCode::CreateRegExp,
            dst: None,
            operands: vec![
                SsaOperand::DstPlaceholder,
                SsaOperand::ResolvedString("hi".into()),
                SsaOperand::ResolvedString("g".into()),
                SsaOperand::Const(0),
            ],
            original: stub_inst("CreateRegExp", OpCode::CreateRegExp),
        };
        let out = format!("{}", build_expr(&ssa_op, &no_str));
        assert_eq!(
            out, "/hi/g",
            "resolved-operand path must render regex literal, got {out:?}"
        );
    }
}

#[cfg(test)]
mod closure_fid_tests {
    //! Regression tests ensuring that a `CreateClosure*` / `CallDirect*` /
    //! `CallRequire` whose func-id or module-id slot is missing /
    //! non-resolvable surfaces a `/* missing func_id */` (or
    //! `/* missing module_id */`) placeholder rather than silently falling
    //! through to `#0`.
    //!
    //! Without the placeholder, every affected callsite renders as a
    //! reference to function 0 (typically the global script entry) —
    //! wrong AND indistinguishable from a legitimate reference in
    //! source. Placeholder form makes the structural failure visible.
    //!
    //! As with `builtin_id_tests` and `regex_operand_tests`, the non-resolvable
    //! arms are unreachable via well-formed HBC. The func-id / module-id slots
    //! are U2/U4 immediates per `schemas.rs` and always decode to
    //! `SsaOperand::Const` (or, for `CreateClosure`/`CreateGenerator*`,
    //! explicitly to `SsaOperand::FuncId` via ssa.rs). The placeholder contract
    //! is defensive against future SSA refactors; unit tests at the direct-
    //! `SsaOp`-construction layer are the correct lock.
    use super::*;
    use crate::decompile::decode::DecodedInst;
    use crate::decompile::ssa::{SsaOp, SsaOperand, VarId};
    use crate::opcodes::OpCode;

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

    fn no_str(_: u32) -> String {
        String::new()
    }

    // --- CreateClosure (and variants) ---

    #[test]
    fn create_closure_with_non_funcid_operands_emits_missing_placeholder() {
        // Operand list contains no SsaOperand::FuncId — e.g. the func-id slot
        // was bound to a register (Var) instead of the expected immediate.
        // Without this guard: func_id would fall to 0, rendering `null /* closure #0 */`.
        let ssa_op = SsaOp {
            name: "CreateClosure",
            op: OpCode::CreateClosure,
            dst: None,
            operands: vec![
                SsaOperand::DstPlaceholder,
                SsaOperand::Var(VarId(0, 0)),
                SsaOperand::Var(VarId(0, 1)),
            ],
            original: stub_inst("CreateClosure", OpCode::CreateClosure),
        };
        let out = format!("{}", build_expr(&ssa_op, &no_str));
        assert!(
            out.contains("/* missing func_id */"),
            "expected missing-func_id placeholder, got {out:?}"
        );
        assert!(
            !out.contains("#0"),
            "placeholder must not fall through to func_id=0, got {out:?}"
        );
    }

    #[test]
    fn create_async_closure_with_non_funcid_operands_emits_missing_placeholder() {
        let ssa_op = SsaOp {
            name: "CreateAsyncClosure",
            op: OpCode::CreateAsyncClosure,
            dst: None,
            operands: vec![SsaOperand::DstPlaceholder, SsaOperand::Const(0)],
            original: stub_inst("CreateAsyncClosure", OpCode::CreateAsyncClosure),
        };
        let out = format!("{}", build_expr(&ssa_op, &no_str));
        assert!(
            out.contains("/* missing func_id */"),
            "expected missing-func_id placeholder, got {out:?}"
        );
        assert!(
            !out.contains("#0"),
            "placeholder must not fall through to func_id=0, got {out:?}"
        );
    }

    #[test]
    fn create_generator_closure_with_non_funcid_operands_emits_missing_placeholder() {
        let ssa_op = SsaOp {
            name: "CreateGeneratorClosure",
            op: OpCode::CreateGeneratorClosure,
            dst: None,
            operands: vec![SsaOperand::DstPlaceholder],
            original: stub_inst("CreateGeneratorClosure", OpCode::CreateGeneratorClosure),
        };
        let out = format!("{}", build_expr(&ssa_op, &no_str));
        assert!(
            out.contains("/* missing func_id */"),
            "expected missing-func_id placeholder, got {out:?}"
        );
    }

    #[test]
    fn create_closure_with_valid_funcid_still_renders_closure_meta() {
        // Sanity check: the FuncId path is untouched by the fix.
        let ssa_op = SsaOp {
            name: "CreateClosure",
            op: OpCode::CreateClosure,
            dst: None,
            operands: vec![
                SsaOperand::DstPlaceholder,
                SsaOperand::Var(VarId(0, 0)),
                SsaOperand::FuncId(7),
            ],
            original: stub_inst("CreateClosure", OpCode::CreateClosure),
        };
        let out = format!("{}", build_expr(&ssa_op, &no_str));
        assert!(
            out.contains("closure #7"),
            "FuncId path must render the closure meta, got {out:?}"
        );
        assert!(
            !out.contains("missing func_id"),
            "valid FuncId must not surface placeholder, got {out:?}"
        );
    }

    // --- CallDirect ---

    #[test]
    fn call_direct_with_non_const_func_id_emits_missing_placeholder() {
        // Operand slot 2 (func_id) is bound to a register (Var) instead of the
        // expected immediate Const. Without the placeholder, func_id falls to
        // 0, rendering `/* direct #0 */(...)` — silently a reference to
        // function 0.
        let ssa_op = SsaOp {
            name: "CallDirect",
            op: OpCode::CallDirect,
            dst: None,
            operands: vec![
                SsaOperand::DstPlaceholder,
                SsaOperand::Const(0), // argcount
                SsaOperand::Var(VarId(0, 0)),
            ],
            original: stub_inst("CallDirect", OpCode::CallDirect),
        };
        let out = format!("{}", build_expr(&ssa_op, &no_str));
        assert!(
            out.contains("/* missing func_id */"),
            "expected missing-func_id placeholder, got {out:?}"
        );
        assert!(
            !out.contains("/* direct #0 */"),
            "placeholder must not fall through to direct #0, got {out:?}"
        );
    }

    #[test]
    fn call_direct_with_valid_const_func_id_still_renders_direct_comment() {
        let ssa_op = SsaOp {
            name: "CallDirect",
            op: OpCode::CallDirect,
            dst: None,
            operands: vec![
                SsaOperand::DstPlaceholder,
                SsaOperand::Const(0), // argcount
                SsaOperand::Const(42),
            ],
            original: stub_inst("CallDirect", OpCode::CallDirect),
        };
        let out = format!("{}", build_expr(&ssa_op, &no_str));
        assert!(
            out.contains("/* direct #42 */"),
            "Const-id path must render the direct-call comment, got {out:?}"
        );
    }

    // --- CallRequire ---

    #[test]
    fn call_require_with_non_const_module_id_emits_missing_placeholder() {
        // Operand slot 2 (module_id) is bound to a register (Var) instead of
        // the expected U4 immediate. Without the placeholder, id falls to 0,
        // rendering `require(0)` — silently a reference to module 0.
        let ssa_op = SsaOp {
            name: "CallRequire",
            op: OpCode::CallRequire,
            dst: None,
            operands: vec![
                SsaOperand::DstPlaceholder,
                SsaOperand::Var(VarId(0, 0)),
                SsaOperand::Var(VarId(0, 1)),
            ],
            original: stub_inst("CallRequire", OpCode::CallRequire),
        };
        let out = format!("{}", build_expr(&ssa_op, &no_str));
        assert!(
            out.contains("/* missing module_id */"),
            "expected missing-module_id placeholder, got {out:?}"
        );
        assert!(
            !out.contains("require(0)"),
            "placeholder must not fall through to require(0), got {out:?}"
        );
    }

    #[test]
    fn call_require_with_valid_const_module_id_still_renders_require_call() {
        let ssa_op = SsaOp {
            name: "CallRequire",
            op: OpCode::CallRequire,
            dst: None,
            operands: vec![
                SsaOperand::DstPlaceholder,
                SsaOperand::Var(VarId(0, 0)),
                SsaOperand::Const(3),
            ],
            original: stub_inst("CallRequire", OpCode::CallRequire),
        };
        let out = format!("{}", build_expr(&ssa_op, &no_str));
        assert!(
            out.contains("require(3)"),
            "Const-id path must render the require call, got {out:?}"
        );
    }
}
