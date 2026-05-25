# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-05-25

### Added

- HBC parser: v40–v100 accepted; version-conditional header state machine dispatching to 5 layout variants: `PreV84` (v40–v83), `V84to86`, `V87to96`, `V97toV98Early`, `V98LateToV99`
- v98 early/late detection via `BytecodeOptions` byte at offsets 108/112 with `debug_info_offset` disambiguation
- Out-of-range versions fail closed before any layout-dependent read with `HermesError::UnsupportedVersion { observed, supported_min, supported_max }`
- Round-trip emit for V84/V96/V98/V99; `HbcFileEquiv<V>` with independently proptested quotient laws; byte-identical on public v96 corpus samples
- Decompile pipeline: decode → CFG → SSA (Braun, iterative) → optimize (copy propagation, constant folding, DCE, parameter-name recovery from `LoadParam`/`GetById`/`CreateClosure`) → structure → sugar → emit via `oxc_codegen` → verify
- Sugar passes: `flatten_early_returns`, `recover_switch`, `recover_for_in`, `recover_try_catch`, `recover_destructuring`, `recover_class`, `linearize_async`, `strip_tdz_traps`
- OXC round-trip: every decompiled function parsed back through `oxc_parser`; output OXC rejects is annotated and returned, never silently dropped
- `verify_body`: semantic verification that every name used in structured output has a definition in the body
- Scanner (`scanner::scan_parsed`): single-pass `string_refs` / `call_graph` / `closure_refs` indices without instruction decoding; operand sizes read from per-version table
- IPA parameter-name recovery: `ipa::collect_param_names` for whole-bundle decompile with interprocedural names
- 36-entry language-coverage fixture matrix: arrow, async/await, class (static fields), closure, coalesce, computed-property, destructuring, for-loop, generators, if-else, labeled break-continue, object spread, optional chaining, promise chain, regex (named groups), rest params, spread, Symbol (iterator), tagged template (raw), template, try-catch, while-loop; 0 semantic-fail, 0 compile-fail
- Multi-version smoke fixtures at `tests/fixtures/multi_version/{v40,v76,v96}/`
- `hbcdump` differential on v96 corpus: header + global string table + function table byte-for-byte; 12,000 sampled `(opname, operand_count)` tuples across functions, zero disagreements
- 9 libFuzzer targets: `fuzz_parser`, `fuzz_opcode_decode`, `fuzz_decode_source_locations`, `fuzz_cfg`, `fuzz_ssa`, `fuzz_emit_roundtrip_hbc`, `fuzz_scan`, `parser_differential`, `cfg_differential`
- 20 Kani harnesses across 8 files: opcode decode truncation (unknown opcode + truncated stream → typed `HermesError`), v98 disambiguation unambiguity, exception count cap, function-get out-of-bounds overflow guard (u128 oracle), literal buffer truncation, offset overflow detection, operand-size dispatch, source-locations resync
- Adversarial corpus: `version_dispatch`, `bound_count_amplification`, `bigint_decimal_quadratic_bomb`, `object_shape_num_props_bomb`, `overflow_string_oor`, `file_length_disagree`; OOM seeds under `fuzz/seeds/*/oom/`
- `hbc_triage` example: forensic classifier reporting version, counts, debug-info classification, filename-storage disclosure, source-info coverage ratio, and RE-interpretation remarks

[1.0.0]: https://github.com/droidsaw/droidsaw-hermes/releases/tag/v1.0.0
