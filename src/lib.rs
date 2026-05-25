// SPDX-License-Identifier: BSD-3-Clause

//! droidsaw-hermes — Hermes bytecode analysis library.
//!
//! Provides programmatic access to the Hermes bytecode parser, string/call-graph
//! scanner, and full decompiler pipeline (decode → CFG → SSA → optimize →
//! structure → emit). Library crate within the DROIDSAW RE toolkit.
//!
//! ## Quick start
//!
//! ```no_run
//! use droidsaw_hermes::{parser, decompile, scanner};
//!
//! let data = std::fs::read("app.hbc").unwrap();
//! let hbc = parser::HbcFile::parse(&data, None).unwrap();
//!
//! // High-level: decompile a function to JS
//! let js = decompile::decompile_function(&hbc, &data, 0, true)
//!     .unwrap_or_else(|_| String::new());
//! println!("{js}");
//!
//! // Scanner: which functions reference each string?
//! let scan = scanner::scan_parsed(&hbc, &data);
//! println!("{} strings cross-referenced", scan.string_refs.len());
//! ```

#![forbid(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable,
        clippy::todo,
        clippy::arithmetic_side_effects,
        clippy::indexing_slicing,
        clippy::string_slice,
        clippy::let_underscore_future,
        clippy::await_holding_lock,
        clippy::await_holding_refcell_ref,
        clippy::if_let_mutex,
        clippy::large_futures,
        clippy::as_underscore,
        clippy::cast_lossless,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss,
        clippy::cast_possible_wrap,
        clippy::unused_result_ok,
        clippy::let_underscore_must_use,
        clippy::map_err_ignore,
        clippy::allow_attributes_without_reason,
    )
)]
// `clippy::as_conversions` is `deny`-d crate-wide on non-test builds.
// Cold files (scanner.rs + decompile/{ssa,ipa,mod,sugar,region}.rs) and
// hot files (parser.rs + decompile/{optimize,cfg,structure,expr,decode}.rs)
// were both swept. Survival sites carry per-site / function-level /
// impl-block `#[allow(clippy::as_conversions)]` plus a `// WHY:` line
// citing the dominator (HBC header bound, parser-validated section
// size, JS-spec arithmetic semantic, etc.). Hermes cast-hygiene matches
// dex/apk/top discipline.
#![cfg_attr(not(test), deny(clippy::as_conversions))]
#![warn(missing_docs)]
#![warn(unreachable_pub)]

pub mod decompile;
pub mod emit;
pub mod error;
pub mod finding;
pub mod header;
pub mod opcodes;
pub mod parser;
pub mod parser_oracle;
pub mod scanner;

pub use error::{HermesError, Result};

// Kani Tier-1 proof bodies live in `proofs/` (sibling to `src/`), gated
// on `cfg(kani)` so normal builds / tests / clippy never see them.
// Pattern mirrors `droidsaw-common/src/lib.rs` + `droidsaw-apk/src/lib.rs`.
#[cfg(kani)]
#[path = "../proofs/decode_function_truncation.rs"]
mod proof_decode_function_truncation;

#[cfg(kani)]
#[path = "../proofs/literal_buffer_truncation.rs"]
mod proof_literal_buffer_truncation;

#[cfg(kani)]
#[path = "../proofs/source_locations_resync.rs"]
mod proof_source_locations_resync;

#[cfg(kani)]
#[path = "../proofs/exception_count_cap.rs"]
mod proof_exception_count_cap;

#[cfg(kani)]
#[path = "../proofs/function_get_overflow_oob.rs"]
mod proof_function_get_overflow_oob;

// v98 SmallFuncHeader overflow predicate + large-offset shift-discriminant.
// Closes the "wrong-layout-shift" attack window where attacker-controlled
// raw_offset routes into the wrong bit region.
#[cfg(kani)]
#[path = "../proofs/overflowed_and_large_off.rs"]
mod proof_overflowed_and_large_off;

// scanner::read_operand size dispatch correctness — closes a
// regression accepting size=3 silently OOB'ing downstream readers.
#[cfg(kani)]
#[path = "../proofs/read_operand_size_dispatch.rs"]
mod proof_read_operand_size_dispatch;

// V98 disambiguator HEADER_END plausibility floor — closes the
// BytecodeOptions-overlap case where an Early-v98 file with stripped
// debug + a low-bits-set BytecodeOptions byte at 108 was silently
// misclassified as Late-v98 via the loose `debug_with > 0` predicate.
// Proof harness constructs the overlap class directly (bounded
// 0..=0x07 symbolic over the option byte) and asserts the C-1
// AmbiguousV98Form escalation fires.
#[cfg(kani)]
#[path = "../proofs/disambiguate_both_options_valid.rs"]
mod proof_disambiguate_both_options_valid;
