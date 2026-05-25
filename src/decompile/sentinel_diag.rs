//! Thread-local one-shot diagnostic channel for defensive-contract fallbacks
//! in the structurer / region builder.
//!
//! Motivation: most sentinel fallbacks in `structure.rs` / `region.rs`
//! are unreachable via well-formed HBC — the
//! operand schemas guarantee that a `Var` / `Const` / `Double` slot post-SSA
//! is always of the expected shape. We still keep the fallback arms because
//! they defend against future SSA-layer refactors.
//!
//! For branches whose fallback produces a *placeholder string* (LoadConstDouble,
//! LoadParam, switch discriminant) the fallback itself is the signal — the
//! comment shows up in the emitted JS. But one site — `min_case=0` in
//! `structure.rs`'s `SwitchImm` handling — has a numerically valid fallback
//! (0 is a legitimate min_case): no emitted-JS difference is visible. For
//! that site we need an observational signal separate from the rendered
//! output.
//!
//! This module provides a minimal thread-local `Vec<String>` that records
//! one-shot warnings. The expected consumers are (a) unit tests that want to
//! assert the defensive arm fired and (b) future diagnostic tooling. The
//! channel is intentionally small — no ordering guarantees across threads,
//! no severity levels, no structured payload. If we need more, promote to
//! `droidsaw-common`.
#![allow(missing_docs, reason = "internal")]

use std::cell::RefCell;
use std::collections::BTreeSet;

thread_local! {
    /// Warnings emitted on this thread's defensive-contract paths.
    static WARNINGS: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
    /// One-shot gating: each `site` string records at most one warning per
    /// thread. Prevents loops over many malformed ops from spamming.
    static SEEN_SITES: RefCell<BTreeSet<String>> = const { RefCell::new(BTreeSet::new()) };
}

/// Record a one-shot defensive-contract warning. Deduplicated per `site` per
/// thread — the first call for a given site records, later calls are no-ops.
///
/// `site` is a stable static key identifying the fallback path (e.g.
/// `"structure::switch_min_case_fallback"`). `detail` is free-form context
/// (function id, opcode, whatever is useful for triage).
pub(super) fn warn_once(site: &'static str, detail: String) {
    let fire = SEEN_SITES.with(|s| s.borrow_mut().insert(site.to_string()));
    if !fire {
        return;
    }
    WARNINGS.with(|w| {
        w.borrow_mut().push(format!("{site}: {detail}"));
    });
}

/// Drain and return the thread-local warning buffer. Primarily for tests.
#[cfg(test)]
pub(super) fn drain_warnings() -> Vec<String> {
    let out = WARNINGS.with(|w| std::mem::take(&mut *w.borrow_mut()));
    SEEN_SITES.with(|s| s.borrow_mut().clear());
    out
}
