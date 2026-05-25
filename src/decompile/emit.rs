//! Emit structured decompilation as valid JavaScript via OXC AST.
//!
//! Sanitizes SSA names, lowers phi nodes, then parses through OXC
//! (oxc_parser + oxc_codegen) for AST validation and consistent formatting.
//! String literals are protected during sanitization to prevent corruption.
#![allow(missing_docs, reason = "internal")]
#![cfg_attr(
    not(test),
    allow(
        clippy::indexing_slicing,
        clippy::string_slice,
        reason = "PROOF: emit consumes Region / StructuredFunction trees built post-parse / post-CFG / post-SSA / post-structuring / post-sugar. Pool indices (StringIdx, FunctionIdx, BigIntIdx) are validated against parser-accepted pool lengths. String slicing is on emit-internal `String` buffers, OXC-validated AST nodes, or sanitize_id outputs (UTF-8 by construction). Per-fn refinement deferred (~28 sites)."
    )
)]

use oxc_allocator::Allocator;
use oxc_codegen::{Codegen, CodegenOptions};
use oxc_parser::Parser;
use oxc_span::SourceType;

use super::structure::StructuredFunction;

/// Emit a structured function as valid JavaScript via OXC.
/// VarId uses `_` separator (r0_1) so names are valid JS identifiers — no sanitization needed.
///
/// Postconditions: if OXC parse succeeds, output is syntactically valid JS.
/// String literal contents are preserved verbatim.
/// Post-process: comment out lines that assign to reserved literals (false = x).
/// These slip through the naming/emit pipeline when LoadConstFalse names propagate
/// through phi nodes into assignment target position.
fn fix_reserved_assignments(raw: &str) -> String {
    raw.lines()
        .map(|line| {
            let trimmed = line.trim_start();
            let first = trimmed
                .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                .next()
                .unwrap_or("");
            if matches!(first, "false" | "true" | "null")
                && (trimmed.contains(" = ") || trimmed.contains("= "))
                && !trimmed.starts_with("var ")
                && !trimmed.starts_with("//")
                && !trimmed.contains("==")
            {
                format!(
                    "{}// {}",
                    &line[..line.len().saturating_sub(trimmed.len())],
                    trimmed
                )
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Strip module-level hoist-preamble leakage from decompiled JS.
///
/// The Hermes `global()` function's bytecode explicitly materializes module-scope
/// hoisting via up to three redundant instructions per hoisted binding:
///
/// 1. `DeclareGlobalVar "X"` — renders as `/* global */ var X;`
/// 2. For hoisted `function X() {}`: `CreateClosure r, fid` dst-named `X` →
///    `var X = null /* closure X #N */;` (the Closure meta-expr placeholder).
/// 3. `PutById globalThis, X, "X"` — renders as `globalThis.X = X;` (self-reassign).
///
/// These three are artifacts of hermesc's hoist lowering, not user source. The
/// actual `function X() {}` body is emitted separately at the top level (it
/// appears as a sibling `function X(...) {}` block in the output stream), so
/// the preamble is redundant at best and semantically misleading at worst (the
/// `null` closure placeholder shadows the real function if taken literally).
///
/// **Scope discipline.** Rule A fires unconditionally — `DeclareGlobalVar` has
/// no consumer in the emitted output. Rules B1 + B2 fire only as a pair,
/// matched by name within the same emitted function body: we drop a
/// `var X = null /* closure... */;` line only if a `globalThis.X = X;`
/// self-reassign appears in the same function (and vice versa). Closure
/// placeholders that are later used as the LHS of a property write
/// (`X._private = ...`) stay put — their declaration is load-bearing even if
/// the `null` value is semantically bogus (pre-existing decompile limitation).
///
/// Fix at the emit boundary — text-level since we operate after per-function
/// pseudocode has been rendered but before OXC normalization strips the
/// distinguishing `/* closure ... */` marker comment. OXC runs after this pass
/// and collapses the marker comments, so post-OXC detection would be impossible.
fn strip_module_hoist_preamble(raw: &str) -> String {
    // Two-pass: first scan the input to build the set of closure-placeholder
    // names that ALSO have a `globalThis.NAME = NAME;` self-reassign (the
    // unambiguous hoist-preamble triad). Only those name entries drive Rules
    // B1+B2; other `null /* closure */` placeholders survive so later property
    // writes don't reference an undeclared identifier.
    let mut closure_decls: std::collections::BTreeSet<String> =
        std::collections::BTreeSet::new();
    let mut self_reassigns: std::collections::BTreeSet<String> =
        std::collections::BTreeSet::new();
    for line in raw.lines() {
        let trimmed = line.trim_start();
        if let Some(name) = parse_closure_placeholder(trimmed) {
            closure_decls.insert(name);
        }
        if let Some(name) = parse_global_self_reassign(trimmed) {
            self_reassigns.insert(name);
        }
    }
    let drop_pair: std::collections::BTreeSet<&String> = closure_decls
        .intersection(&self_reassigns)
        .collect();

    let mut out = String::with_capacity(raw.len());
    for line in raw.lines() {
        let trimmed = line.trim_start();

        // Rule A: drop `/* global */ var NAME;` declarations. Always redundant
        // — either the name is later stored via `globalThis.NAME = ...`
        // (implicit hoist) or a sibling top-level `function NAME(){}` hoists it.
        if trimmed.starts_with("/* global */ var ") && trimmed.ends_with(';') {
            continue;
        }

        // Rule B1: drop `var NAME = null /* closure... */;` only when paired
        // with a matching `globalThis.NAME = NAME;` self-reassign.
        if let Some(name) = parse_closure_placeholder(trimmed)
            && drop_pair.contains(&name)
        {
            continue;
        }

        // Rule B2: drop `globalThis.NAME = NAME;` only when paired with its
        // closure placeholder. Real module-var assignments like
        // `globalThis.x = r0_1;` use distinct names and are preserved.
        if let Some(name) = parse_global_self_reassign(trimmed)
            && drop_pair.contains(&name)
        {
            continue;
        }

        out.push_str(line);
        out.push('\n');
    }
    // Preserve trailing-newline discipline: StructuredFunction::emit ends with "}\n",
    // so the last line we pushed is "}" and we added a newline — matches original.
    if !raw.ends_with('\n') && out.ends_with('\n') {
        out.pop();
    }
    out
}

/// Extract NAME from `var NAME = null /* {closure|async|generator} ... */;`
/// where the comment marker is the distinguishing trace from the Closure
/// meta-expr (expr.rs `Expr::Meta(Closure)` formatter).
fn parse_closure_placeholder(trimmed: &str) -> Option<String> {
    let rest = trimmed.strip_prefix("var ")?;
    let (name, tail) = rest.split_once(" = null /* ")?;
    if !is_bare_ident(name) {
        return None;
    }
    let kind_end = tail.find([' ', '#'])?;
    let kind = &tail[..kind_end];
    if !matches!(kind, "closure" | "async" | "generator") {
        return None;
    }
    if !tail.ends_with("*/;") {
        return None;
    }
    Some(name.to_string())
}

/// Extract NAME from `globalThis.NAME = NAME;` self-reassignments.
fn parse_global_self_reassign(trimmed: &str) -> Option<String> {
    let rest = trimmed.strip_prefix("globalThis.")?;
    let semi = rest.strip_suffix(';')?;
    let (lhs, rhs) = semi.split_once(" = ")?;
    if lhs == rhs && is_bare_ident(lhs) {
        Some(lhs.to_string())
    } else {
        None
    }
}

fn is_bare_ident(s: &str) -> bool {
    let mut cs = s.chars();
    match cs.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' || c == '$' => {}
        _ => return false,
    }
    cs.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
}

pub fn emit_js(func: &StructuredFunction, get_str: &dyn Fn(u32) -> String) -> String {
    let raw = fix_reserved_assignments(&strip_module_hoist_preamble(&func.emit(get_str)));

    let allocator = Allocator::default();
    // Use JSX source type if the output contains JSX syntax
    let source_type = if raw.contains("</") || raw.contains("/>") {
        SourceType::jsx()
    } else {
        SourceType::mjs()
    };
    let parse_result = Parser::new(&allocator, &raw, source_type).parse();

    let out = if parse_result.errors.is_empty() {
        let options = CodegenOptions {
            minify: false,
            ..Default::default()
        };
        Codegen::new()
            .with_options(options)
            .build(&parse_result.program)
            .code
    } else {
        // Pinpoint: use OXC error spans to show exact line and column
        let mut diagnostics = String::new();
        for err in &parse_result.errors {
            let msg = format!("{err}");
            // OxcDiagnostic has labels via miette::Diagnostic trait — access the inner span
            let span = err
                .labels
                .as_ref()
                .and_then(|labels| labels.first())
                .map(|label| label.inner().offset());
            if let Some(offset) = span {
                let offset = offset.min(raw.len());
                let line_num = raw[..offset].matches('\n').count().saturating_add(1);
                let line_start = raw[..offset]
                    .rfind('\n')
                    .map(|p| p.saturating_add(1))
                    .unwrap_or(0);
                let line_end = raw[offset..]
                    .find('\n')
                    .map(|p| offset.saturating_add(p))
                    .unwrap_or(raw.len());
                let line_text = &raw[line_start..line_end];
                let col = offset.saturating_sub(line_start);
                // Show full line (no truncation — rule 11), but cap the caret indent
                diagnostics.push_str(&format!(
                    "// OXC error: {msg} (line {line_num}, col {col})\n//   {line_text}\n//   {}^\n",
                    " ".repeat(col.min(200)),
                ));
            } else {
                diagnostics.push_str(&format!("// OXC error: {msg}\n"));
            }
        }
        format!(
            "// WARNING: OXC validation failed — output is approximate pseudocode\n{diagnostics}{raw}"
        )
    };
    droidsaw_common::diag::stage_dump("emit", &out);
    out
}

/// Emit as OXC-formatted JS. Returns (formatted_code, oxc_parsed_ok).
pub fn emit_js_with_status(
    func: &StructuredFunction,
    get_str: &dyn Fn(u32) -> String,
) -> (String, bool) {
    let raw = fix_reserved_assignments(&strip_module_hoist_preamble(&func.emit(get_str)));

    let allocator = Allocator::default();
    let source_type = if raw.contains("</") || raw.contains("/>") {
        SourceType::jsx()
    } else {
        SourceType::mjs()
    };
    let parse_result = Parser::new(&allocator, &raw, source_type).parse();

    if parse_result.errors.is_empty() {
        let options = CodegenOptions {
            minify: false,
            ..Default::default()
        };
        let code = Codegen::new()
            .with_options(options)
            .build(&parse_result.program)
            .code;
        (code, true)
    } else {
        (raw, false)
    }
}

/// Sanitize pseudocode into valid JS.
/// - Convert phi comments to var declarations
/// - Replace SSA dots in variable names (r0.1 → r0_1)
/// - Preserve string literal contents (no substitution inside quotes)
pub fn sanitize_for_js(code: &str) -> String {
    // Pre-pass: lower phi comments to var declarations
    let code = code
        .lines()
        .map(|line| {
            let trimmed = line.trim();
            if trimmed.starts_with("// var r") && trimmed.contains("/* phi(") {
                let indent = &line[..line.len().saturating_sub(trimmed.len())];
                if let Some(rest) = trimmed.strip_prefix("// ") {
                    if let Some(phi_start) = rest.find(" /* phi(") {
                        let assignment = &rest[..phi_start];
                        let comment = rest[phi_start.saturating_add(4)..]
                            .trim_end_matches(" */");
                        return format!("{indent}{assignment}; // {comment}");
                    }
                    if let Some(eq_pos) = rest.find(" = phi(") {
                        let var_name = &rest[4..eq_pos];
                        return format!("{indent}var {var_name}; {trimmed}");
                    }
                }
            }
            line.to_string()
        })
        .collect::<Vec<_>>()
        .join("\n");
    let code = &code;

    // Main pass: replace SSA dots with underscores, preserving string contents
    let mut result = String::with_capacity(code.len());
    let chars: Vec<char> = code.chars().collect();
    let mut i: usize = 0;
    let mut in_string = false;
    let mut string_char = '"';

    while i < chars.len() {
        // Track string literal boundaries — never modify inside strings
        if !in_string && (chars[i] == '"' || chars[i] == '\'' || chars[i] == '`') {
            in_string = true;
            string_char = chars[i];
            result.push(chars[i]);
            i = i.saturating_add(1);
            continue;
        }
        if in_string {
            if chars[i] == string_char {
                // Count consecutive preceding backslashes to check parity
                let mut bs: usize = 0;
                while bs < i && chars[i.saturating_sub(1).saturating_sub(bs)] == '\\' {
                    bs = bs.saturating_add(1);
                }
                // Even number of backslashes means the quote is NOT escaped
                if bs.is_multiple_of(2) {
                    in_string = false;
                }
            }
            result.push(chars[i]);
            i = i.saturating_add(1);
            continue;
        }

        // SSA variable name: rN.M → rN_M
        if chars[i] == 'r'
            && i.saturating_add(1) < chars.len()
            && chars[i.saturating_add(1)].is_ascii_digit()
        {
            let start = i;
            i = i.saturating_add(1);
            while i < chars.len() && chars[i].is_ascii_digit() {
                i = i.saturating_add(1);
            }
            if i < chars.len()
                && chars[i] == '.'
                && i.saturating_add(1) < chars.len()
                && chars[i.saturating_add(1)].is_ascii_digit()
            {
                result.push_str(&chars[start..i].iter().collect::<String>());
                result.push('_');
                i = i.saturating_add(1);
                while i < chars.len() && chars[i].is_ascii_digit() {
                    result.push(chars[i]);
                    i = i.saturating_add(1);
                }
            } else {
                result.push_str(&chars[start..i].iter().collect::<String>());
            }
        } else {
            result.push(chars[i]);
            i = i.saturating_add(1);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_legacy() {
        // sanitize_for_js is retained for backward compatibility; VarId
        // uses _ separator directly so the main emit path bypasses it.
        assert_eq!(sanitize_for_js("var r0.1 = r2.3;"), "var r0_1 = r2_3;");
        assert_eq!(sanitize_for_js("r1.1.exports"), "r1_1.exports");
        assert_eq!(sanitize_for_js("return r0.6;"), "return r0_6;");
        assert_eq!(sanitize_for_js("obj.prop"), "obj.prop");
        assert_eq!(sanitize_for_js("function foo() {}"), "function foo() {}");
    }

    #[test]
    fn test_sanitize_preserves_strings() {
        assert_eq!(
            sanitize_for_js("var x = \"r0.1 is a var\";"),
            "var x = \"r0.1 is a var\";"
        );
    }

    #[test]
    fn strip_preamble_drops_function_hoist_triad() {
        let raw = concat!(
            "function global() {\n",
            "  /* global */ var foo;\n",
            "  var foo = null /* closure foo #1 */;\n",
            "  globalThis.foo = foo;\n",
            "  var r2_6 = globalThis.foo(1);\n",
            "  return r2_6;\n",
            "}\n",
        );
        let out = strip_module_hoist_preamble(raw);
        assert!(!out.contains("/* global */"), "declare-global leaked: {out}");
        assert!(!out.contains("null /* closure"), "closure placeholder leaked: {out}");
        assert!(!out.contains("globalThis.foo = foo"), "self-reassign leaked: {out}");
        assert!(out.contains("globalThis.foo(1)"), "real call dropped: {out}");
    }

    #[test]
    fn strip_preamble_preserves_real_assigns() {
        // Shape 2: `/* global */ var x;` drops, but `globalThis.x = r0_1;` stays
        // (real value store; LHS name != RHS name).
        let raw = concat!(
            "function global() {\n",
            "  /* global */ var x;\n",
            "  var r0_1 = 42;\n",
            "  globalThis.x = r0_1;\n",
            "}\n",
        );
        let out = strip_module_hoist_preamble(raw);
        assert!(!out.contains("/* global */"), "declare-global leaked: {out}");
        assert!(out.contains("globalThis.x = r0_1"), "real store dropped: {out}");
        assert!(out.contains("var r0_1 = 42"), "literal def dropped: {out}");
    }

    #[test]
    fn strip_preamble_drops_async_and_generator_paired_placeholders() {
        // With matching self-reassigns, async/generator placeholders are stripped
        // — same pattern as the sync-closure triad, different meta-expr kind.
        let raw = concat!(
            "function global() {\n",
            "  var g = null /* generator g #2 */;\n",
            "  globalThis.g = g;\n",
            "  var h = null /* async h #3 */;\n",
            "  globalThis.h = h;\n",
            "}\n",
        );
        let out = strip_module_hoist_preamble(raw);
        assert!(!out.contains("null /* generator"), "generator placeholder leaked: {out}");
        assert!(!out.contains("null /* async"), "async placeholder leaked: {out}");
        assert!(!out.contains("globalThis.g = g"), "generator self-reassign leaked: {out}");
        assert!(!out.contains("globalThis.h = h"), "async self-reassign leaked: {out}");
    }

    #[test]
    fn strip_preamble_preserves_unpaired_closure_placeholder() {
        // When a `var X = null /* closure */;` line has no matching
        // `globalThis.X = X;` self-reassign in the same function, the
        // placeholder survives — dropping it would leave property writes
        // (`X._private = ...`) referencing an undeclared identifier.
        let raw = concat!(
            "function global() {\n",
            "  if (cond) {} else {\n",
            "    var r1_12 = null /* closure #3 */;\n",
            "    r1_12._private = r2_1;\n",
            "  }\n",
            "}\n",
        );
        let out = strip_module_hoist_preamble(raw);
        assert!(
            out.contains("var r1_12 = null /* closure #3 */"),
            "unpaired closure placeholder dropped: {out}"
        );
    }
}
