//! Adversarial fixtures locking the typed-Err contract for crashers
//! surfaced by hermes-fuzz.
//!
//! Each fuzz/crashes/<target>/<hash>.note sits alongside the input; a copy
//! of the note text is reproduced above its test here so the panic → Err
//! conversion stays load-bearing if anyone refactors the version lookup.

use droidsaw_hermes::HermesError;
use droidsaw_hermes::decompile::cfg::{Cfg, ExcHandler};
use droidsaw_hermes::decompile::decode::decode_function;
use droidsaw_hermes::decompile::ssa::build_ssa;
use droidsaw_hermes::parser::HbcFile;

/// Mirrors the `fuzz_cfg` target's per-function loop: parse, walk every
/// function, attempt `Cfg::build`. Returns the first non-`UnsupportedVersion`
/// Err encountered, or `None` if every function succeeds. Used by the
/// Invariant-7 fixtures to assert the typed-Err contract without having to
/// hand-pick the offending function id from each adversarial input.
fn first_cfg_build_err(data: &[u8]) -> Option<HermesError> {
    let hbc = match HbcFile::parse(data, None) {
        Ok(h) => h,
        Err(e) => return Some(e),
    };
    let limit = hbc.function_count.min(256);
    let version = hbc.opcode_version();
    let mut first_decode_err: Option<HermesError> = None;

    for i in 0..limit {
        let f = hbc.function_get(i);
        let start = f.offset as usize;
        let end = start.checked_add(f.size as usize)?;
        if end > data.len() {
            continue;
        }
        let code = &data[start..end];
        let instructions = match decode_function(code, version) {
            Ok(insts) => insts,
            Err(e) => {
                if first_decode_err.is_none() {
                    first_decode_err = Some(e);
                }
                continue;
            }
        };

        let exc_count = hbc.function_exception_count(i).min(64);
        let mut exc_handlers: Vec<ExcHandler> = Vec::with_capacity(exc_count as usize);
        for j in 0..exc_count {
            let eh = hbc.function_exception_get(i, j);
            exc_handlers.push(ExcHandler {
                start: eh.start,
                end: eh.end,
                target: eh.target,
            });
        }

        if let Err(e) = Cfg::build(&instructions, &exc_handlers, code) {
            return Some(e);
        }
    }
    // No function reached CFG-build with an Err — surface the first decode-
    // layer Err if any function tripped the decode cap.
    first_decode_err
}

// .note from fuzz/crashes/fuzz_cfg/15e6a48b0466.note:
//
// stage: cfg (panics inside decode_function called from fuzz_cfg target)
// panic: unsupported bytecode version 65623
// site: src/opcodes.rs:9857:14
//
// Parse-time dispatch rejects out-of-range versions before any
// layout-dependent parsing, so the late-rejection path through
// `decode_function` is unreachable for this fixture. The test now
// asserts the fail-closed path catches the same input at the parser
// entry — same error variant, observed-version field carries the same
// `65623`.
#[test]
fn fuzz_cfg_15e6a48b0466_returns_unsupported_version() {
    let data = std::fs::read("tests/fixtures/adversarial/fuzz_cfg/15e6a48b0466.hbc")
        .expect("adversarial fixture must be checked in");
    let err = HbcFile::parse(&data, None)
        .map(|_| ())
        .expect_err("fail-closed parser must reject out-of-range version");
    assert!(
        matches!(
            err,
            HermesError::UnsupportedVersion {
                observed: 65623,
                ..
            }
        ),
        "expected UnsupportedVersion {{ observed: 65623, .. }}, got {err:?}"
    );
}

// .note from fuzz/crashes/fuzz_ssa/0ee9925d6f02.note:
//
// stage: cfg→ssa (panics inside decode_function called before SSA construction)
// panic: unsupported bytecode version 25088
// site: src/opcodes.rs:9857:14
//
// Same migration as `fuzz_cfg_15e6a48b0466_*` above — parser entry now
// rejects fail-closed; `decode_function` path is unreachable.
#[test]
fn fuzz_ssa_0ee9925d6f02_returns_unsupported_version() {
    let data = std::fs::read("tests/fixtures/adversarial/fuzz_ssa/0ee9925d6f02.hbc")
        .expect("adversarial fixture must be checked in");
    let err = HbcFile::parse(&data, None)
        .map(|_| ())
        .expect_err("fail-closed parser must reject out-of-range version");
    assert!(
        matches!(
            err,
            HermesError::UnsupportedVersion {
                observed: 25088,
                ..
            }
        ),
        "expected UnsupportedVersion {{ observed: 25088, .. }}, got {err:?}"
    );
}

// .note from fuzz/crashes/fuzz_cfg/515ce46d6dac.note:
//
// stage: cfg (debug_assert fires inside Cfg::build)
// panic: "catch handler must appear after all its try-region blocks in RPO"
// site: src/decompile/cfg.rs:441:13
//
// Invariant 7 violation: an exception handler block ends up earlier in
// RPO than one of the try-region blocks that lists it as its handler.
// The debug_assert was converted into a typed
// `HermesError::InvalidExceptionLayout { catch, try_region }`.
//
// **Earlier rejection now also covered.** This fixture's header has
// `buf[108] = 0xc6` and `buf[112] = 0xc1`; both fail the v98
// `BytecodeOptions & 0xF8 == 0` MBZ check. The v98-form
// disambiguation gauge added by the adversarial-review §H-1 fix
// returns `Err(AmbiguousV98Form)` at parse, BEFORE the file ever
// reaches `Cfg::build`. The InvalidExceptionLayout signal remains
// the documented downstream behavior if the parse-stage gate is
// ever relaxed; this test accepts either rejection.
#[test]
fn fuzz_cfg_515ce46d6dac_returns_invalid_exception_layout() {
    let data = std::fs::read("tests/fixtures/adversarial/fuzz_cfg/515ce46d6dac.hbc")
        .expect("adversarial fixture must be checked in");
    // First try the parse-stage gate (post-§H-1-fix shape).
    if let Err(HermesError::AmbiguousV98Form { .. }) = HbcFile::parse(&data, None) {
        return;
    }
    // Otherwise the file reached Cfg::build; assert the original
    // Invariant-7 signal at that stage.
    let err = first_cfg_build_err(&data)
        .expect("fixture must surface a parse-stage or Cfg::build error");
    assert!(
        matches!(err, HermesError::InvalidExceptionLayout { .. }),
        "expected AmbiguousV98Form (parse-stage) or InvalidExceptionLayout (cfg-stage), got {err:?}"
    );
}

// .note from fuzz/crashes/fuzz_ssa/0cfc3d8e2713.note:
//
// stage: cfg (debug_assert fires inside Cfg::build, before SSA construction)
// panic: "catch handler must appear after all its try-region blocks in RPO"
// site: src/decompile/cfg.rs:441:13
//
// Same Invariant 7 root cause as fuzz_cfg/515ce46d6dac; fuzz_ssa routes
// through `Cfg::build` before touching SSA so surfaces the same bug class
// first. Locks the typed-Err contract from the SSA-stream path as well.
#[test]
fn fuzz_ssa_0cfc3d8e2713_returns_invalid_exception_layout() {
    // This fixture's corrupted bytecode is now caught at the decode layer
    // before CFG::build sees it. Either rejection point is acceptable;
    // both preserve the safety contract.
    let data = std::fs::read("tests/fixtures/adversarial/fuzz_ssa/0cfc3d8e2713.hbc")
        .expect("adversarial fixture must be checked in");
    let err = first_cfg_build_err(&data)
        .expect("fixture must surface a typed Err on some function");
    assert!(
        matches!(
            err,
            HermesError::InvalidExceptionLayout { .. }
                | HermesError::UnknownOpcode { .. }
                | HermesError::TruncatedInstructionStream { .. }
                | HermesError::FunctionBodyOutOfBytecodeRegion { .. }
                | HermesError::FunctionBodyOverlap { .. }
                | HermesError::ExceptionHandlerOutOfFunctionRange { .. }
        ),
        "expected InvalidExceptionLayout | UnknownOpcode | TruncatedInstructionStream | \
         FunctionBodyOutOfBytecodeRegion | FunctionBodyOverlap | \
         ExceptionHandlerOutOfFunctionRange, got {err:?}"
    );
}

/// Mirrors the `fuzz_ssa` target's per-function loop: parse, walk every
/// function, decode, `Cfg::build`, then attempt `build_ssa`. Returns the
/// first `build_ssa` error encountered (skipping functions where earlier
/// stages already failed), or `None` if every reachable `build_ssa`
/// succeeds. Used by the OOM fixtures to assert the typed-Err contract
/// from the SSA path without having to hand-pick the offending function
/// id from each input.
///
/// `parse` now rejects v94..v99 inputs whose debug_info header violates
/// `lexical_data_offset <= debug_data_size`. The OOM fixtures below
/// were minimised to crash the SSA pipeline; in passing, their fuzzed
/// debug-info headers can fail the spec invariant first. Capture the
/// parse-layer Err so callers can assert "input rejected somewhere in
/// the parse/decode/CFG/SSA chain" without overspecifying which stage.
/// The `InconsistentDebugHeader` typed-Err is a stricter rejection
/// point than the earlier SSA OOM path, so the assertion is
/// monotonically tighter, not weaker.
fn first_build_ssa_err(data: &[u8]) -> Option<HermesError> {
    let hbc = match HbcFile::parse(data, None) {
        Ok(h) => h,
        Err(e) => return Some(e),
    };
    let limit = hbc.function_count.min(256);
    let version = hbc.opcode_version();
    // `decode_function` rejects unknown-opcode / OOB-operand inputs at
    // the decode layer with typed Err. The OOM fixtures below earlier
    // surfaced at SSA via the truncated stream; the same shape is now
    // caught earlier. Capture the first decode-layer Err so callers can
    // assert either rejection point without overspecifying.
    let mut first_decode_err: Option<HermesError> = None;

    for i in 0..limit {
        let f = hbc.function_get(i);
        let start = f.offset as usize;
        let end = start.checked_add(f.size as usize)?;
        if end > data.len() {
            continue;
        }
        let code = &data[start..end];
        let instructions = match decode_function(code, version) {
            Ok(insts) => insts,
            Err(e) => {
                if first_decode_err.is_none() {
                    first_decode_err = Some(e);
                }
                continue;
            }
        };

        let exc_count = hbc.function_exception_count(i).min(64);
        let mut exc_handlers: Vec<ExcHandler> = Vec::with_capacity(exc_count as usize);
        for j in 0..exc_count {
            let eh = hbc.function_exception_get(i, j);
            exc_handlers.push(ExcHandler {
                start: eh.start,
                end: eh.end,
                target: eh.target,
            });
        }

        let Ok(cfg) = Cfg::build(&instructions, &exc_handlers, code) else {
            continue;
        };
        if let Err(e) = build_ssa(&cfg, f.frame_size) {
            return Some(e);
        }
    }
    // No function reached SSA with an Err — surface the first decode-layer
    // Err if any function tripped the decode cap.
    first_decode_err
}

// .note from fuzz/crashes/fuzz_ssa/47d147c4c0f9.note:
//
// stage: ssa (libFuzzer OOM, process RSS exceeded 2048 MB)
// class: OOM
// site: build_ssa → variadic Call argc loop at src/decompile/ssa.rs:305-310
//
// argc is capped against the function's total instruction count;
// `HermesError::CountExceedsInput` is returned rather than iterating
// a u32-wide argc.
#[test]
fn fuzz_ssa_47d147c4c0f9_returns_count_exceeds_input() {
    // This fixture's corrupted bytecode is caught at the decode layer
    // (UnknownOpcode / TruncatedInstructionStream) rather than at SSA via
    // CountExceedsInput on some builds. Either rejection point is
    // acceptable; both pre-
    // serve the safety contract.
    let data = std::fs::read("tests/fixtures/adversarial/oom/fuzz_ssa/47d147c4c0f9.hbc")
        .expect("adversarial fixture must be checked in");
    let err = first_build_ssa_err(&data)
        .expect("fixture must surface a typed Err on some function");
    assert!(
        matches!(
            err,
            HermesError::CountExceedsInput { .. }
                | HermesError::UnknownOpcode { .. }
                | HermesError::TruncatedInstructionStream { .. }
                | HermesError::InconsistentDebugHeader { .. }
                | HermesError::FunctionBodyOutOfBytecodeRegion { .. }
                | HermesError::FunctionBodyOverlap { .. }
                | HermesError::ExceptionHandlerOutOfFunctionRange { .. }
        ),
        "expected CountExceedsInput | UnknownOpcode | TruncatedInstructionStream | \
         InconsistentDebugHeader | FunctionBodyOutOfBytecodeRegion | FunctionBodyOverlap | \
         ExceptionHandlerOutOfFunctionRange, got {err:?}"
    );
}

// .note from fuzz/crashes/fuzz_ssa/c54279df956b.note:
//
// stage: ssa (libFuzzer OOM, 469 B input)
// class: OOM
// site: same build_ssa variadic argc loop
#[test]
fn fuzz_ssa_c54279df956b_returns_count_exceeds_input() {
    // See note on `fuzz_ssa_47d147c4c0f9_returns_count_exceeds_input` above —
    // decode-layer rejection is now an acceptable outcome.
    let data = std::fs::read("tests/fixtures/adversarial/oom/fuzz_ssa/c54279df956b.hbc")
        .expect("adversarial fixture must be checked in");
    let err = first_build_ssa_err(&data)
        .expect("fixture must surface a typed Err on some function");
    assert!(
        matches!(
            err,
            HermesError::CountExceedsInput { .. }
                | HermesError::UnknownOpcode { .. }
                | HermesError::TruncatedInstructionStream { .. }
                | HermesError::InconsistentDebugHeader { .. }
                | HermesError::FunctionBodyOutOfBytecodeRegion { .. }
                | HermesError::FunctionBodyOverlap { .. }
                | HermesError::ExceptionHandlerOutOfFunctionRange { .. }
        ),
        "expected CountExceedsInput | UnknownOpcode | TruncatedInstructionStream | \
         InconsistentDebugHeader | FunctionBodyOutOfBytecodeRegion | FunctionBodyOverlap | \
         ExceptionHandlerOutOfFunctionRange, got {err:?}"
    );
}

// .note from fuzz/crashes/fuzz_ssa/ec54a00b120f.note:
//
// stage: ssa (libFuzzer OOM, 346 B input — first OOM to surface during
// the non-fork 15-min campaign)
// class: OOM
// site: same build_ssa variadic argc loop
#[test]
fn fuzz_ssa_ec54a00b120f_returns_count_exceeds_input() {
    // Note: see `fuzz_ssa_47d147c4c0f9_returns_count_exceeds_input` —
    // decode-layer Errs are also acceptable. This fixture happens to
    // still reach SSA on this build (one or more functions decode
    // cleanly before the offending one fires CountExceedsInput).
    let data = std::fs::read("tests/fixtures/adversarial/oom/fuzz_ssa/ec54a00b120f.hbc")
        .expect("adversarial fixture must be checked in");
    let err = first_build_ssa_err(&data)
        .expect("fixture must surface a typed Err on some function");
    assert!(
        matches!(
            err,
            HermesError::CountExceedsInput { .. }
                | HermesError::UnknownOpcode { .. }
                | HermesError::TruncatedInstructionStream { .. }
                | HermesError::InconsistentDebugHeader { .. }
                | HermesError::FunctionBodyOutOfBytecodeRegion { .. }
                | HermesError::FunctionBodyOverlap { .. }
                | HermesError::ExceptionHandlerOutOfFunctionRange { .. }
        ),
        "expected CountExceedsInput | UnknownOpcode | TruncatedInstructionStream | \
         InconsistentDebugHeader | FunctionBodyOutOfBytecodeRegion | FunctionBodyOverlap | \
         ExceptionHandlerOutOfFunctionRange, got {err:?}"
    );
}

// .note from fuzz/crashes/fuzz_ssa/ff30d198a579.note:
//
// stage: ssa (libFuzzer OOM, 291 B input — smallest of the 4 OOMs;
// best reduction candidate for `cargo fuzz tmin`)
// class: OOM
// site: same build_ssa variadic argc loop
#[test]
fn fuzz_ssa_ff30d198a579_returns_count_exceeds_input() {
    // Note: see `fuzz_ssa_47d147c4c0f9_returns_count_exceeds_input`.
    let data = std::fs::read("tests/fixtures/adversarial/oom/fuzz_ssa/ff30d198a579.hbc")
        .expect("adversarial fixture must be checked in");
    let err = first_build_ssa_err(&data)
        .expect("fixture must surface a typed Err on some function");
    assert!(
        matches!(
            err,
            HermesError::CountExceedsInput { .. }
                | HermesError::UnknownOpcode { .. }
                | HermesError::TruncatedInstructionStream { .. }
                | HermesError::InconsistentDebugHeader { .. }
                | HermesError::FunctionBodyOutOfBytecodeRegion { .. }
                | HermesError::FunctionBodyOverlap { .. }
                | HermesError::ExceptionHandlerOutOfFunctionRange { .. }
        ),
        "expected CountExceedsInput | UnknownOpcode | TruncatedInstructionStream | \
         InconsistentDebugHeader | FunctionBodyOutOfBytecodeRegion | FunctionBodyOverlap | \
         ExceptionHandlerOutOfFunctionRange, got {err:?}"
    );
}

/// Synthesized arithmetic-overflow pin for `Cfg::build`. A `DecodedInst`
/// whose `offset + size` wraps `u32::MAX` must surface
/// `HermesError::ArithmeticOverflow`, not panic or succeed with a bogus
/// boundary.
///
/// Reachable only via an adversarially synthesized inst (legitimate HBC is
/// <4 GiB so `offset` never approaches `u32::MAX`), but the hardening contract
/// is that defense-in-depth `checked_*` on `inst.offset + inst.size as u32`
/// fires cleanly instead of wrapping.
#[test]
fn crafted_inst_offset_plus_size_overflow_returns_arithmetic_overflow() {
    use droidsaw_hermes::decompile::decode::{DecodedInst, OpType};
    use droidsaw_hermes::opcodes::OpCode;

    // offset = u32::MAX, size = 1 → next_offset computation wraps.
    let inst = DecodedInst {
        offset: u32::MAX,
        size: 1,
        opcode: 0,
        name: "Unreachable",
        op: OpCode::Unreachable,
        operands: vec![],
        op_types: &[] as &[OpType],
    };

    let err = Cfg::build(&[inst], &[], &[])
        .expect_err("Cfg::build must Err on wrapping instruction boundary");
    assert!(
        matches!(err, HermesError::ArithmeticOverflow { context } if context.contains("next-offset")),
        "expected ArithmeticOverflow with `next-offset` context, got {err:?}"
    );
}

// ── Budget exhaustion ──────────────────────────────────────────────────

#[test]
fn parse_budgeted_rejects_oversized_hbc_input_with_memory_error() {
    use droidsaw_common::budget::{BudgetExhausted, BudgetKind, Budget};

    // 200-byte input, 50-byte budget. charge(200, 0, "hermes-parse-input")
    // must fire BudgetExhausted(Memory) before any HBC parsing.
    let data = vec![0u8; 200];
    let mut budget = Budget {
        memory_bytes_remaining: 50,
        steps_remaining: usize::MAX,
        deadline: None,
    };
    let err = HbcFile::parse(&data, Some(&mut budget))
        .map(|_| ())
        .expect_err("must reject input exceeding memory budget");
    match err {
        HermesError::Budget(BudgetExhausted {
            kind: BudgetKind::Memory,
            context: "hermes-parse-input",
        }) => {}
        other => panic!(
            "expected Budget(Memory, \"hermes-parse-input\"), got {other:?}"
        ),
    }
}

// ── Parser-header bound_count amplification defense ─────────────────────────
//
// Each fixture is a deterministic 128-byte HBC v96 header where exactly
// one of the four primary header counts (function/string/overflow_string/
// reg_exp) is set to `u32::MAX` and the others are zero. The matching
// `bound_count` call in `parse_inner` (right after `func_header_size`
// is computed) must reject with `HermesError::BoundCountExceeded`
// (`droidsaw_common::guard::CountExceeded`-shaped) before any
// `Vec::with_capacity` / section-cursor work.
//
// Without the bound_count call, `section!`'s `cursor + size > buf.len()`
// would still reject these inputs — but with `SectionExceedsBounds`,
// not the typed `CountExceeded` variant. The variant-shift documents
// the diagnostic improvement: the count itself is too large, regardless
// of cursor state. Mirrors `DexError::BoundCountExceeded`.

fn assert_bound_count_rejected(path: &str, expected_item: &str) {
    let data = std::fs::read(path).expect("adversarial fixture must be checked in");
    let err = droidsaw_hermes::parser::HbcFile::parse(&data, None)
        .map(|_| ())
        .expect_err("inflated header count must reject at parse-time bound_count");
    match err {
        HermesError::BoundCountExceeded(ref ce) => {
            assert_eq!(
                ce.got,
                u64::from(u32::MAX),
                "expected got=u32::MAX, fixture={path}, err={err:?}",
            );
            assert_eq!(
                ce.item, expected_item,
                "expected item={expected_item}, fixture={path}, err={err:?}",
            );
        }
        other => panic!(
            "expected BoundCountExceeded for {path}, got {other:?}"
        ),
    }
}

#[test]
fn parser_header_function_count_exceeds_input_returns_bound_count_exceeded() {
    assert_bound_count_rejected(
        "tests/fixtures/adversarial/oom/parser_header/function_count_exceeds_input.hbc",
        "function_headers",
    );
}

#[test]
fn parser_header_string_count_exceeds_input_returns_bound_count_exceeded() {
    assert_bound_count_rejected(
        "tests/fixtures/adversarial/oom/parser_header/string_count_exceeds_input.hbc",
        "small_string_table",
    );
}

#[test]
fn parser_header_overflow_string_count_exceeds_input_returns_overflow_exceeds_string_count() {
    // This fixture has string_count=0, overflow_string_count=u32::MAX.
    // A cross-validation gate fires *before* the bound_count calls: since
    // overflow_string_count (u32::MAX) > string_count (0), the gate fires
    // first and returns the more informative OverflowStringCountExceedsStringCount
    // variant. The input is still rejected at parse time; the variant has
    // shifted to the structural check. The bound_count gate
    // (overflow_string_table) is not reachable for this input shape.
    let data = std::fs::read(
        "tests/fixtures/adversarial/oom/parser_header/overflow_string_count_exceeds_input.hbc",
    )
    .expect("adversarial fixture must be checked in");
    let err = droidsaw_hermes::parser::HbcFile::parse(&data, None)
        .map(|_| ())
        .expect_err("overflow_string_count > string_count must reject at parse time");
    match err {
        HermesError::OverflowStringCountExceedsStringCount {
            overflow: 4_294_967_295,
            total: 0,
        } => {}
        other => panic!(
            "expected OverflowStringCountExceedsStringCount {{ overflow: u32::MAX, total: 0 }}, \
             got {other:?}"
        ),
    }
}

#[test]
fn parser_header_reg_exp_count_exceeds_input_returns_bound_count_exceeded() {
    assert_bound_count_rejected(
        "tests/fixtures/adversarial/oom/parser_header/reg_exp_count_exceeds_input.hbc",
        "regexp_table",
    );
}

// ── decode_function typed-Err migration (silent-truncation closure) ─────────
//
// `decode_function` returns typed `Err` on unknown opcode and OOB
// operand width. The decoder must not silently truncate the stream
// and return `Ok(partial_vec)` — that would flow into CFG/SSA as if
// the partial stream were a complete function, breaking roundtrip
// (non-negotiable §2) and the no-silent-accept invariant (§1). A
// `break` mid-operand-loop would also push a partial `DecodedInst`
// with `operands.len() < op_types.len()` onto the result, giving
// any consumer iterating via `op_types.len()` an OOB index.

/// `opcode_byte >= num_opcodes` must yield `HermesError::UnknownOpcode`
/// carrying the offending byte. We use the lowest supported version
/// (v40), which has fewer opcodes than 256, so `0xFF` is guaranteed
/// outside the table.
#[test]
fn decode_function_unknown_opcode_returns_typed_err() {
    let (sizes, _, _) = droidsaw_hermes::opcodes::get_version_tables(40)
        .expect("v40 is supported");
    let num_opcodes = sizes.len();
    // We need an opcode_byte the table doesn't cover; assert the
    // precondition is reachable before exercising the fix.
    assert!(
        num_opcodes < 256,
        "v40 must expose < 256 opcodes for the unknown-opcode path to be u8-reachable; \
         num_opcodes = {num_opcodes}"
    );
    let bad: u8 = u8::MAX; // 0xFF >= num_opcodes(40) trivially
    let code = [bad];
    let err = decode_function(&code, 40)
        .expect_err("unknown opcode must Err, not Ok(partial)");
    match err {
        HermesError::UnknownOpcode { offset, opcode_id, num_opcodes: nopc } => {
            assert_eq!(offset, 0, "the offending byte is at offset 0");
            assert_eq!(opcode_id, bad, "variant carries the offending byte");
            assert_eq!(nopc, num_opcodes, "variant carries num_opcodes");
        }
        other => panic!("expected UnknownOpcode, got {other:?}"),
    }
}

/// A declared multi-byte opcode followed by < inst_size bytes must yield
/// `HermesError::TruncatedInstructionStream`, not `Ok` with a partial
/// `DecodedInst`. We locate the smallest multi-byte opcode in v96's
/// table at runtime, then feed only the opcode byte (no operands).
#[test]
fn decode_function_truncated_instruction_returns_typed_err() {
    let version: u32 = 96;
    let (sizes, _, _) = droidsaw_hermes::opcodes::get_version_tables(version)
        .expect("v96 is supported");
    let multi_byte_idx = sizes
        .iter()
        .position(|&sz| sz > 1)
        .expect("v96 must have at least one multi-byte opcode");
    assert!(
        multi_byte_idx <= usize::from(u8::MAX),
        "multi-byte opcode index must fit in u8 ({multi_byte_idx})"
    );
    #[allow(
        clippy::cast_possible_truncation,
        reason = "PROOF: multi_byte_idx ≤ u8::MAX asserted above; cast is exact."
    )]
    let opcode_byte = multi_byte_idx as u8;
    let code = [opcode_byte]; // only the opcode, no operands
    let err = decode_function(&code, version)
        .expect_err("multi-byte opcode with no operand bytes must Err");
    match err {
        HermesError::TruncatedInstructionStream { offset, opcode_id } => {
            assert_eq!(offset, 0, "the truncated instruction starts at offset 0");
            assert_eq!(opcode_id, opcode_byte, "variant carries the opcode");
        }
        other => panic!("expected TruncatedInstructionStream, got {other:?}"),
    }
}

/// Belt-and-suspenders: a 1-byte input with a known unknown opcode must
/// not produce a partial DecodedInst on the success path either.
/// Without the typed Err, this case returns `Ok(vec![])` — an empty
/// vec because the loop `break`s before the push. The contract: return
/// the typed Err.
#[test]
fn decode_function_unknown_opcode_does_not_return_empty_ok() {
    let code = [u8::MAX]; // guaranteed unknown for v40
    assert!(
        decode_function(&code, 40).is_err(),
        "must not return Ok(empty_vec) — that masks the malformed input"
    );
}
