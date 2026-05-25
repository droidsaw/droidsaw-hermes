//! Hermes decompiler pipeline modules.
#![allow(missing_docs, reason = "internal")]
pub mod cfg;
#[cfg(any(test, kani, fuzzing))]
pub mod cfg_oracle;
pub mod decode;
pub mod emit;
pub mod expr;
pub mod ipa;
pub mod optimize;
pub mod region;
pub mod schemas;
mod sentinel_diag;
pub mod ssa;
pub mod structure;
pub mod sugar;
pub mod verify;

/// Decompile a single function to a string.
///
/// Returns pseudocode (default) or OXC-validated JS when `emit_js` is `true`.
/// Returns an empty string if `func_id` is out of range or the function body
/// is truncated in the buffer.
///
/// This is the primary stable entry point for library consumers. The
/// lower-level pipeline stages (`decode`, `cfg`, `ssa`, `optimize`,
/// `structure`, `emit`) remain public for advanced use.
///
/// **Note:** this entry point does not run inter-procedural argument-name
/// recovery (`ipa::collect_param_names`). IPA walks every function in the
/// bundle, so doing it per single-function call would multiply cost by
/// `function_count`. Use [`decompile_bundle`] when decompiling the whole
/// bundle to get IPA-recovered parameter names in the emitted output.
///
/// # Example
/// ```no_run
/// use droidsaw_hermes::{parser, decompile};
///
/// let data = std::fs::read("app.hbc").unwrap();
/// let hbc = parser::HbcFile::parse(&data, None).unwrap();
/// // Callers that want the lenient-empty-String semantic translate explicitly:
/// //   let js = decompile_function(&hbc, &data, 0, true).unwrap_or_default();
/// let js = decompile::decompile_function(&hbc, &data, 0, true)
///     .unwrap_or_else(|_| String::new());
/// println!("{js}");
/// ```
pub fn decompile_function(
    hbc: &crate::parser::HbcFile,
    data: &[u8],
    func_id: u32,
    emit_js: bool,
) -> Result<String, crate::HermesError> {
    droidsaw_common::diag::with_input_hash(hbc.input_hash(), || {
        decompile_one(hbc, data, func_id, emit_js, None)
    })
}

/// Decompile every function in the bundle with inter-procedural argument-name
/// recovery enabled.
///
/// Runs [`ipa::collect_param_names`] once over the whole bundle and reuses the
/// resulting `func_id → param_idx → name` map across all per-function emits,
/// so callee parameters appear in the emitted output as the names their callers
/// passed (e.g. `function _fn42(userId, email, ts)` instead of
/// `function _fn42(a0, a1, a2)`). When IPA recovers no name for a given slot,
/// or when an earlier intra-procedural pass (`optimize`) has already named the
/// slot, the existing fallback chain stands.
///
/// Returns one `Result<String, HermesError>` per `func_id` in
/// `0..hbc.function_count`, so a single corrupt function does not invalidate
/// the surrounding slots. **Slot-position invariant**: `result[fid]` is the
/// outcome for `func_id == fid` regardless of which slots succeeded — callers
/// that already index by `func_id` keep that contract.
///
/// Returns a typed Err on failure. Callers that want the lenient-empty-String
/// semantic translate explicitly per slot:
/// `r.unwrap_or_default()`. Callers that want fail-fast (parser-style) use
/// `into_iter().collect::<Result<Vec<_>, _>>()`.
///
/// # Example
/// ```no_run
/// use droidsaw_hermes::{parser, decompile};
///
/// let data = std::fs::read("app.hbc").unwrap();
/// let hbc = parser::HbcFile::parse(&data, None).unwrap();
/// for (fid, slot) in decompile::decompile_bundle(&hbc, &data, true).iter().enumerate() {
///     let js = slot.as_ref().map(String::as_str).unwrap_or("");
///     println!("// function {fid}\n{js}\n");
/// }
/// ```
pub fn decompile_bundle(
    hbc: &crate::parser::HbcFile,
    data: &[u8],
    emit_js: bool,
) -> Vec<Result<String, crate::HermesError>> {
    droidsaw_common::diag::with_input_hash(hbc.input_hash(), || {
        let get_str = make_get_str(hbc);
        let get_func_name = make_get_func_name(hbc);
        let ipa_names = ipa::collect_param_names(hbc, data, &get_str, &get_func_name);
        (0..hbc.function_count)
            .map(|fid| decompile_one(hbc, data, fid, emit_js, Some(&ipa_names)))
            .collect()
    })
}

/// Merge IPA-recovered parameter names into a function's `param_names` map.
///
/// Entries already present (typically populated by `optimize::optimize`'s
/// intra-procedural heuristics, e.g. UI-props detection) are preserved —
/// IPA only fills the strictly-empty slots. This keeps every existing
/// optimizer-derived rename load-bearing while letting IPA upgrade the
/// remaining generic `a{N}` parameters.
fn merge_ipa_names(ssa: &mut ssa::SsaFunction<ssa::Resolved>, ipa: &ipa::IpaNames, func_id: u32) {
    let Some(per_func) = ipa.get(&func_id) else {
        return;
    };
    for (idx, name) in per_func {
        ssa.param_names
            .entry(*idx)
            .or_insert_with(|| name.clone());
    }
}

fn make_get_str<'a>(hbc: &'a crate::parser::HbcFile<'a>) -> impl Fn(u32) -> String + 'a {
    // Lenient policy: decompile output renders an opaque token on
    // failure rather than aborting. Typed-Err signal is preserved
    // via the predecessor stream's `HermesFinding` side-channel from
    // `string_get` (still emitted on OOR), so the corruption mask is
    // still observable for triage / `audit` consumers.
    |id: u32| -> String {
        if id < hbc.string_count {
            hbc.string_as_str_or_empty(id).into_owned()
        } else {
            format!("<{id}>")
        }
    }
}

fn make_get_func_name<'a>(hbc: &'a crate::parser::HbcFile<'a>) -> impl Fn(u32) -> String + 'a {
    // Lenient policy mirroring `make_get_str` — a corrupted name
    // entry renders as empty rather than aborting decompile.
    |fid: u32| -> String {
        if fid < hbc.function_count {
            let fi = hbc.function_get(fid);
            if fi.name_id < hbc.string_count {
                return hbc.string_as_str_or_empty(fi.name_id).into_owned();
            }
        }
        String::new()
    }
}

/// Debug escape hatch: when `DROIDSAW_PANIC_ON_DECOMPILE_ERR=1` is set in the
/// environment, typed `HermesError` returns from the decompile pipeline are
/// promoted to `panic!()` with `func_id`/`stage`/`err` context. Unset: the
/// error passes through unchanged (callers then swallow to `String::new()` per
/// the soft-fail contract of [`decompile_function`] / [`decompile_bundle`]).
///
/// Purpose: routes typed-Err paths through the existing panic-hook + diag-wire
/// infrastructure so every failure produces a diagnostic bundle, enabling
/// bulk-classification on test262 / adversarial corpora without altering the
/// production soft-fail contract. Mirrors the dex-side sibling which uses the
/// same env var name (one debug knob for both crates).
#[allow(
    clippy::panic,
    reason = "debug-knob escape hatch; only fires when DROIDSAW_PANIC_ON_DECOMPILE_ERR is set. \
              The production soft-fail path (env unset) never reaches the panic!() arm."
)]
fn maybe_panic_on_err<T>(
    result: Result<T, crate::HermesError>,
    func_id: u32,
    stage: &'static str,
) -> Result<T, crate::HermesError> {
    if let Err(ref err) = result
        && std::env::var_os("DROIDSAW_PANIC_ON_DECOMPILE_ERR").is_some()
    {
        panic!("hermes-decompile-panic-on-err: fid={func_id} stage={stage} err={err}");
    }
    result
}

fn decompile_one(
    hbc: &crate::parser::HbcFile,
    data: &[u8],
    func_id: u32,
    emit_js: bool,
    ipa_names: Option<&ipa::IpaNames>,
) -> Result<String, crate::HermesError> {
    if func_id >= hbc.function_count {
        return Err(crate::HermesError::FunctionIdOutOfRange {
            id: func_id,
            function_count: hbc.function_count,
        });
    }
    let f = hbc.function_get(func_id);
    let fname = if f.name_id < hbc.string_count {
        // Lenient policy: corrupted function-name renders as empty.
        // Typed signal preserved via `HermesFinding` side-channel from
        // `string_get` (still emitted on OOR). This branch is not an
        // error path — corrupted name does not abort decompile.
        hbc.string_as_str_or_empty(f.name_id).into_owned()
    } else {
        String::new()
    };
    // Attacker-controlled `f.offset` + `f.size` can wrap — use checked arithmetic
    // and surface the overflow as a typed error.
    let Some(end) = u64::from(f.offset).checked_add(u64::from(f.size)) else {
        return Err(crate::HermesError::ArithmeticOverflow {
            context: "function_offset_u64 + function_size_u64",
        });
    };
    #[allow(clippy::as_conversions, reason = "usize→u64 / u32→usize widen on every project-supported target. Bounds gated by `end > data.len() as u64` check; slice index ranges are valid by construction from the parsed function-header offsets.")]
    let data_len_u64 = data.len() as u64;
    if end > data_len_u64 {
        return Err(crate::HermesError::FunctionBodyExceedsBuffer {
            offset: f.offset,
            size: f.size,
            buf_len: data.len(),
        });
    }
    let Ok(end_usize) = usize::try_from(end) else {
        return Err(crate::HermesError::ArithmeticOverflow {
            context: "function_end as usize",
        });
    };
    let code_end = end_usize.saturating_add(256).min(data.len());
    #[allow(clippy::as_conversions, reason = "Spec-bounded value-domain narrowing (parser-validated field; preceding PROOF documents the bit-width invariant).")]
    let Some(code) = data.get(f.offset as usize..code_end) else {
        return Err(crate::HermesError::FunctionBodyExceedsBuffer {
            offset: f.offset,
            size: f.size,
            buf_len: data.len(),
        });
    };
    let Some(fn_end) = f.offset.checked_add(f.size) else {
        return Err(crate::HermesError::ArithmeticOverflow {
            context: "function_offset + function_size (u32)",
        });
    };
    #[allow(clippy::as_conversions, reason = "Spec-bounded value-domain narrowing (parser-validated field; preceding PROOF documents the bit-width invariant).")]
    let Some(fn_slice) = data.get(f.offset as usize..fn_end as usize) else {
        return Err(crate::HermesError::FunctionBodyExceedsBuffer {
            offset: f.offset,
            size: f.size,
            buf_len: data.len(),
        });
    };
    let instructions = maybe_panic_on_err(
        decode::decode_function(fn_slice, hbc.opcode_version()),
        func_id,
        "decode",
    )?;
    let exc_count = hbc.function_exception_count(func_id);
    let mut exc_handlers = Vec::new();
    for i in 0..exc_count {
        let eh = hbc.function_exception_get(func_id, i);
        exc_handlers.push(cfg::ExcHandler {
            start: eh.start,
            end: eh.end,
            target: eh.target,
        });
    }
    let graph = maybe_panic_on_err(
        cfg::Cfg::build(&instructions, &exc_handlers, code),
        func_id,
        "cfg",
    )?;
    let ssa_func =
        maybe_panic_on_err(ssa::build_ssa(&graph, f.frame_size), func_id, "ssa")?;
    let get_str = make_get_str(hbc);
    let get_literal =
        |buf_type: u8, offset: u32, num_items: u32, index: u32| -> (u8, u32, i32, f64) {
            let val = hbc.literal_get(buf_type, offset, num_items, index);
            (val.tag, val.str_id, val.ival, val.dval)
        };
    // Lenient policy: corrupted / missing shape entry renders as
    // `(0, 0)` so the optimizer's resolve-buffers walk treats the
    // shape as empty (no props). The typed `None` is now
    // distinguishable from a legitimate empty shape, but the
    // downstream consumer at `optimize::resolve_buffers` interprets
    // both `(0, 0)` returns the same way (no resolution); the
    // precision win is at the in-band `string_get` typed-Err and the
    // `cjs_module_get` / `regexp_get` callers that DO branch on the
    // None — see `droidsaw/src/commands/mod.rs`.
    let get_shape = |index: u32| -> (u32, u32) {
        match hbc.object_shape_get(index) {
            Some(shape) => (shape.key_buffer_offset, shape.num_props),
            None => (0, 0),
        }
    };
    let get_func_name = make_get_func_name(hbc);
    let get_bigint = |idx: u32| -> Option<String> { hbc.bigint_as_str(idx) };
    let mut ssa_func = optimize::optimize(
        ssa_func,
        &get_str,
        &get_literal,
        &get_shape,
        &get_func_name,
        &get_bigint,
    );
    if let Some(names) = ipa_names {
        merge_ipa_names(&mut ssa_func, names, func_id);
    }
    let structured = structure::structure_function(&ssa_func, fname, f.param_count, f.flags);
    Ok(if emit_js {
        emit::emit_js(&structured, &get_str)
    } else {
        structured.emit(&get_str)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn synth_ssa_with_param_count() -> ssa::SsaFunction<ssa::Resolved> {
        ssa::SsaFunction::<ssa::Resolved> {
            blocks: Vec::new(),
            block_order: Vec::new(),
            var_names: BTreeMap::new(),
            param_names: BTreeMap::new(),
            param_vars: Vec::new(),
            _phase: std::marker::PhantomData,
        }
    }

    #[test]
    fn merge_ipa_fills_empty_param_names() {
        let mut ssa = synth_ssa_with_param_count();
        let mut ipa: ipa::IpaNames = BTreeMap::new();
        let mut params: BTreeMap<u32, String> = BTreeMap::new();
        params.insert(0, "userId".into());
        params.insert(1, "email".into());
        ipa.insert(7, params);
        merge_ipa_names(&mut ssa, &ipa, 7);
        assert_eq!(ssa.param_names.get(&0).map(String::as_str), Some("userId"));
        assert_eq!(ssa.param_names.get(&1).map(String::as_str), Some("email"));
    }

    #[test]
    fn merge_ipa_preserves_optimizer_renames_on_conflict() {
        let mut ssa = synth_ssa_with_param_count();
        ssa.param_names.insert(0, "props".into());
        let mut ipa: ipa::IpaNames = BTreeMap::new();
        let mut params: BTreeMap<u32, String> = BTreeMap::new();
        params.insert(0, "state".into());
        params.insert(1, "callback".into());
        ipa.insert(3, params);
        merge_ipa_names(&mut ssa, &ipa, 3);
        assert_eq!(ssa.param_names.get(&0).map(String::as_str), Some("props"));
        assert_eq!(
            ssa.param_names.get(&1).map(String::as_str),
            Some("callback")
        );
    }

    #[test]
    fn merge_ipa_no_entry_is_noop() {
        let mut ssa = synth_ssa_with_param_count();
        let ipa: ipa::IpaNames = BTreeMap::new();
        merge_ipa_names(&mut ssa, &ipa, 42);
        assert!(ssa.param_names.is_empty());
    }

    /// End-to-end emit assertion: the structure → emit pipeline picks up
    /// IPA-recovered names from `ssa.param_names`. Constructs an empty-body
    /// `SsaFunction` (`param_count = 3`: `this`, `userId`, `email`), seeds
    /// `param_names` as the wire would, runs `structure_function` + `.emit()`,
    /// and asserts the recovered names appear in the function header.
    /// Acceptance gate: emitted output uses an IPA-recovered name in
    /// place of a generic a{N} param.
    #[test]
    fn emit_uses_ipa_recovered_param_names() {
        let mut ssa = synth_ssa_with_param_count();
        ssa.param_names.insert(0, "userId".into());
        ssa.param_names.insert(1, "email".into());
        let structured =
            structure::structure_function(&ssa, "myFunc".into(), 3, 0);
        let get_str = |_id: u32| -> String { String::new() };
        let out = structured.emit(&get_str);
        assert!(
            out.contains("function myFunc(userId, email)"),
            "emit must show IPA-recovered names; got:\n{out}"
        );
        assert!(
            !out.contains("a0") && !out.contains("a1"),
            "generic param names must be replaced; got:\n{out}"
        );
    }

    /// Regression guard: when no IPA name exists for a slot, emit falls back
    /// to the canonical `a{N}` form. Locks the fallback contract documented in
    /// the merge-helper docstring.
    #[test]
    fn emit_falls_back_to_generic_when_no_ipa_name() {
        let ssa = synth_ssa_with_param_count();
        let structured =
            structure::structure_function(&ssa, "noNames".into(), 3, 0);
        let get_str = |_id: u32| -> String { String::new() };
        let out = structured.emit(&get_str);
        assert!(
            out.contains("function noNames(a0, a1)"),
            "fallback must use canonical a{{N}}; got:\n{out}"
        );
    }
}
