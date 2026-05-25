# droidsaw-hermes

Hermes bytecode parser and decompiler for the [droidsaw](https://github.com/droidsaw/droidsaw) workspace. Parses the format Meta's React Native JS engine emits and decompiles it back to JavaScript. Versions v40 through v100 are accepted at parse time; v98 ships in two incompatible header layouts and both are detected at load. Every decompiled function is parsed back through OXC; output OXC rejects is annotated and returned, never silently dropped. Pure Rust, BSD-3-Clause.

## Pipeline

```
parse
  → decode         (bytecode → typed instructions; per-version operand schemas in src/decompile/schemas.rs)
  → cfg            (basic blocks; exception handlers as separate predecessor map)
  → ssa            (Braun CC 2013, iterative — no stack overflow on long chains)
  → optimize       (copy propagation, constant folding, DCE, variable naming from LoadParam / GetById / CreateClosure)
  → structure      (region-based; post-dominators via droidsaw_common::post_dominators_with_virtual_exit)
  → sugar          (flatten_early_returns, recover_switch, recover_for_in, recover_try_catch,
                    recover_destructuring, recover_class, linearize_async, strip_tdz_traps)
  → emit           (Region IR → JS via oxc_codegen)
  → verify         (syntactic via OXC; semantic via verify_body)
```

Algorithm code lives in `droidsaw-common` and is generic over the `Instr` trait (CFG, dominators, SSA scaffolding). The Hermes-specific `Insn` type and per-version opcode / schema tables stay in this crate (`src/opcodes.rs`, `src/decompile/schemas.rs`). Opcode knowledge does not cross the trait boundary.

## Version coverage

HBC versions v40 through v100 are accepted at parse time. The header is a version-conditional state machine — which fields are present depends on the parsed version. `src/header.rs` reads the version first and dispatches to one of five layout-equivalence variants:

| Variant | Versions | Discriminator |
|---|---|---|
| `PreV84` | v40..=v83 | pre-bigint, pre-`function_source_count`, 16-byte `SmallFuncHeader` |
| `V84to86` | v84..=v86 | adds `function_source_count` |
| `V87to96` | v87..=v96 | adds `big_int_count` + `big_int_storage_size` |
| `V97toV98Early` | v97 + v98 early-form | swaps `obj_value_buffer_size` for `obj_shape_table_count`; 12-byte `SmallFuncHeader` |
| `V98LateToV99` | v98 late-form + v99..= | adds `num_string_switch_imms`; widens `param_count` field |

v98-early vs v98-late is detected via the `BytecodeOptions` byte at offsets 108 / 112 with `debug_info_offset` disambiguation. Out-of-range versions fail closed at parse entry with `HermesError::UnsupportedVersion { observed, supported_min, supported_max }` before any layout-dependent read runs. See `tests/version_dispatch.rs` for the acceptance test.

Round-trip emit is implemented for V84 / V96 / V98 / V99 — `tests/hbc_corpus_roundtrip.rs` iterates all four version buckets.

## Scanner

`scanner::scan_parsed` makes a single bytecode pass using per-version opcode lookup tables:

- `string_refs[str_id]` → functions referencing that string
- `call_graph[func_id]` → directly called function IDs
- `closure_refs[func_id]` → closures created by that function

Operand sizes (1 / 2 / 4 bytes) are read from the version table; no instruction decoding is required. Fuzzed via `fuzz_scan`. Hardened against truncated debug-info streams.

## Library API

The stable surface lives in `src/lib.rs`:

```rust
use droidsaw_hermes::{parser, decompile, scanner};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let data = std::fs::read("app.hbc")?;
    let hbc = parser::HbcFile::parse(&data, None)?;

    // Decompile one function. With emit_js=true, output is OXC-validated.
    let js = decompile::decompile_function(&hbc, &data, 0, true)?;
    println!("{js}");

    // Scan: string ↔ function and call-graph indices.
    let _scan = scanner::scan_parsed(&hbc, &data);
    Ok(())
}
```

`decompile_function` does not run inter-procedural parameter-name recovery — `ipa::collect_param_names` walks every function and multiplies cost by `function_count` when called per-function. Use `decompile_bundle` for whole-bundle decompile with IPA-recovered parameter names.

## Correctness

### Round-trip equivalence

`HbcFileEquiv<V>` (`src/parser/round_trip.rs`) is the `PartialEq` instance that is the round-trip specification — four version-tagged variants `V84` / `V96` / `V98` / `V99`. Quotient laws (reflexivity, symmetry, transitivity) are proptested independently in `tests/quotient_laws_proptest.rs` so the relation is a real equivalence.

Locks on top:

- `tests/roundtrip_hbc_proptest.rs` — 256 proptest cases (default) seed-mutating a v96 fixture, asserting `HbcFileEquiv<V96>` on every parser-accepted mutant.
- `tests/hbc_corpus_roundtrip.rs` — env-gated (`DROIDSAW_HERMES_V96_CORPUS`) sweep over a directory of `.hbc` files. Asserts `HbcFileEquiv<V>` plus byte-identical round-trip on each sample. Skips cleanly when the env var isn't set.

Verified clean on public v96 corpus samples: header, global string table, and function table match byte-for-byte.

### Fixture ratchet

Language-coverage fixtures live at `tests/fixtures/language_surface/` — 36 entries spanning arrow / async / await / class (static fields) / closure / coalesce / computed-property / destructuring / for-loop / generators / if-else / labeled break-continue / object spread / optional chaining / promise chain / regex (named groups) / rest params / spread / Symbol (iterator) / tagged template (raw) / template / try-catch / while-loop. Each entry has `src.js` + `expected.txt`; `manifest.toml` carries the `status` field.

`tests/fixture_ratchet.rs` runs `hermesc(src.js) → HbcFile::parse → decompile_bundle → hermesc` on every entry and asserts `RatchetResult::is_clean`. `SEMANTIC_FAIL` stays at 0; `COMPILE_FAIL` decreases monotonically. A fixture flip blocks merge.

Multi-version smoke fixtures live at `tests/fixtures/multi_version/{v40,v76,v96}/`; driven by `tests/fixture_matrix_multi_version.rs`.

### Adversarial fuzz

libFuzzer targets (`fuzz/fuzz_targets/`):

| Target | Surface |
|---|---|
| `fuzz_parser` | `HbcFile::parse` on arbitrary bytes |
| `fuzz_opcode_decode` | per-version instruction-stream decoder |
| `fuzz_decode_source_locations` | source-locations resync after truncation |
| `fuzz_cfg` | basic-block + exception-handler graph build |
| `fuzz_ssa` | Braun SSA construction |
| `fuzz_emit_roundtrip_hbc` | `parse(emit_hbc(parse(bytes))) ≡ first parse` under instrumentation |
| `fuzz_scan` | string / call-graph / closure scanner |
| `parser_differential` | parse-side differential vs an oracle |
| `cfg_differential` | CFG-side differential vs an oracle |

The four parse-and-decode targets ran for extended campaigns with zero panics, zero artifacts.

Adversarial corpus under `tests/fixtures/adversarial/` covers `version_dispatch`, `bound_count_amplification`, `bigint_decimal_quadratic_bomb`, `object_shape_num_props_bomb`, `overflow_string_oor`, `file_length_disagree`, plus reduced fuzz-found OOM seeds under `oom/`.

### Cross-tool differential

vs `hbcdump` (Meta's official disassembler), the v96 corpus has been compared on two axes:

- **Structural** (header + global string table + function table, byte-for-byte): public v96 bundles agreed byte-for-byte.
- **Instruction-level** (per-function `(opname, operand_count)` tuples on the intersection of function ids): 12,000 sampled tuples compared across v96 bundles, zero opcode disagreements.

The harness lives in `droidsaw-bench` (sibling crate, not a runtime dependency).

### OXC round-trip

`src/decompile/emit.rs` parses every decompiled function through `oxc_parser` and reformats via `oxc_codegen`. If OXC rejects the output, diagnostic annotations are prepended and the raw output is returned. Invalid JavaScript is never silently emitted.

`src/decompile/verify.rs` is the semantic companion: OXC validates syntax, `verify_body` validates that every name used in the structured output has a definition in the body. Pipeline bugs that produce syntactically valid but semantically free-variable output surface as warnings.

### Kani

20 harnesses across 8 files under `proofs/` (gated on `cfg(kani)`):

| Harness | Property |
|---|---|
| `decode_function_truncation` | unknown-opcode + truncated-instruction-stream both yield typed `HermesError` rather than silent `break` (2 harnesses) |
| `disambiguate_both_options_valid` | v98 early/late detection via `BytecodeOptions` + `debug_info_offset` is unambiguous (1 harness) |
| `exception_count_cap` | function-header exception-handler count is bounded by parser-validated sections (3 harnesses) |
| `function_get_overflow_oob` | `function_table[idx]` out-of-bounds access yields typed error (4 harnesses) |
| `literal_buffer_truncation` | literal-buffer reads past end produce typed `Err`, not partial decode (4 harnesses) |
| `overflowed_and_large_off` | field overflow detection during offset calculations (4 harnesses) |
| `read_operand_size_dispatch` | per-version operand-size dispatch on instruction stream (1 harness) |
| `source_locations_resync` | source-locations stream resyncs deterministically on truncation (1 harness) |

The compile-time floor on every non-test module:

```rust
#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable,
    clippy::todo,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::as_conversions,
    // … plus the cast-class group (cast_possible_truncation, cast_sign_loss, …)
)]
```

See `src/lib.rs` for the full block. Suppression sites carry a `// WHY:` comment stating the bound (HBC header bound, parser-validated section size, JS-spec arithmetic). No panics on adversarial input.

## Inputs

`HbcFile::parse(bytes, opts)` accepts raw HBC bytes. The top binary extracts `assets/index.android.bundle` (and `*.hbc` variants) from APK / XAPK containers; this crate consumes the extracted bytes. The byte buffer is caller-owned — `HbcFile<'a>` borrows from it; no internal copy.

## Performance

- `parser/round_trip.rs::parse_literal_buffer` uses `Vec::with_capacity(num_items.min(buf.len()))`. Capped at `buf.len()` because each literal needs at least one byte tag, so adversarial `num_items = u32::MAX` cannot allocate more than the input.
- `decompile/sugar.rs` uses `Vec::with_capacity(stmts.len())` at sugar passes where the result-vec is bounded by the input statement count.
- `decompile/optimize.rs` uses `FxHashMap` for SSA-id-keyed maps on paths where ordering is not load-bearing.

## Workspace

- `droidsaw-common` — generic CFG / dominators / SSA / region algorithms this crate parameterizes over.
- `droidsaw-dex` — sibling decompiler; shares the same pipeline middle stages from `droidsaw-common`.
- `droidsaw-apk` — APK container parsing; produces the `.hbc` bytes this crate consumes.
- `droidsaw` — top binary; exposes `hbc info` / `hbc functions` / `hbc strings` / `hbc decompile` / `hbc disassemble` subcommands.

## License

BSD-3-Clause.
