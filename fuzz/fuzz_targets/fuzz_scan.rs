#![no_main]

//! Fuzz target for `droidsaw_hermes::scanner::scan_parsed_with_mode`.
//!
//! Outer shape: arbitrary bytes → `HbcFile::parse` → on success, run
//! the scanner in each of the four mode combinations and assert
//! invariants on the returned `ScanResult`.
//!
//! Invariants on every iteration:
//!
//!   1. No panic on any input.
//!   2. Determinism: two calls in the same mode on the same input
//!      produce identical `ScanResult` (catches accidental HashMap
//!      iteration leak or thread-local state).
//!   3. Mode-monotonicity: the result of `(xrefs=true, callgraph=true)`
//!      is the union of `(xrefs=true, callgraph=false)` and
//!      `(xrefs=false, callgraph=true)` — disabling a mode never
//!      shrinks the entries from the other mode.
//!   4. Bounds: every function index in `string_refs` / `call_graph`
//!      / `closure_refs` values is `< hbc.function_count()`.

use droidsaw_hermes::parser::HbcFile;
use droidsaw_hermes::scanner::{scan_parsed_with_mode, ScanMode};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // First parse: most random bytes will fail, that's fine.
    let Ok(hbc) = HbcFile::parse(data, None) else {
        return;
    };

    let modes = [
        ScanMode { xrefs: true, callgraph: true },
        ScanMode { xrefs: true, callgraph: false },
        ScanMode { xrefs: false, callgraph: true },
        ScanMode { xrefs: false, callgraph: false },
    ];

    let results: Vec<_> = modes
        .iter()
        .map(|m| scan_parsed_with_mode(&hbc, data, m))
        .collect();

    // (2) Determinism: second call equals first for each mode.
    for (i, m) in modes.iter().enumerate() {
        let again = scan_parsed_with_mode(&hbc, data, m);
        let first = &results[i];
        assert_eq!(
            first.string_refs, again.string_refs,
            "mode {i} string_refs nondeterministic"
        );
        assert_eq!(
            first.call_graph, again.call_graph,
            "mode {i} call_graph nondeterministic"
        );
        assert_eq!(
            first.closure_refs, again.closure_refs,
            "mode {i} closure_refs nondeterministic"
        );
    }

    // (3) Mode-monotonicity: disabling xrefs → string_refs empty.
    // Disabling callgraph → call_graph empty (closure_refs may still
    // populate from CreateClosure opcodes regardless of mode, per
    // scanner internals).
    let full = &results[0]; // (true, true)
    let xrefs_only = &results[1]; // (true, false)
    let call_only = &results[2]; // (false, true)
    let neither = &results[3]; // (false, false)

    // xrefs-only must have the same string_refs as full (callgraph
    // off doesn't affect xref accumulation).
    assert_eq!(
        xrefs_only.string_refs, full.string_refs,
        "mode-monotonicity: xrefs_only string_refs differs from full"
    );
    // call-only must have the same call_graph as full.
    assert_eq!(
        call_only.call_graph, full.call_graph,
        "mode-monotonicity: call_only call_graph differs from full"
    );
    // neither mode produces empty xrefs + empty call_graph.
    assert!(
        neither.string_refs.is_empty(),
        "neither mode: string_refs should be empty"
    );
    assert!(
        neither.call_graph.is_empty(),
        "neither mode: call_graph should be empty"
    );

    // (4) Bounds: every function index < hbc.function_count.
    let func_count = u32::try_from(hbc.function_count).unwrap_or(u32::MAX);
    for (src, dsts) in &full.string_refs {
        // string_index is u32, no inherent bound to check
        let _ = src;
        for &f in dsts {
            assert!(
                f < func_count,
                "string_refs value func_idx={f} >= function_count={func_count}"
            );
        }
    }
    for (caller, callees) in &full.call_graph {
        assert!(
            *caller < func_count,
            "call_graph key caller={caller} >= function_count={func_count}"
        );
        for &callee in callees {
            assert!(
                callee < func_count,
                "call_graph value callee={callee} >= function_count={func_count}"
            );
        }
    }
    for (creator, closures) in &full.closure_refs {
        assert!(
            *creator < func_count,
            "closure_refs key creator={creator} >= function_count={func_count}"
        );
        for &closure in closures {
            assert!(
                closure < func_count,
                "closure_refs value closure={closure} >= function_count={func_count}"
            );
        }
    }
});
