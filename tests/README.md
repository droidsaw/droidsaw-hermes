# droidsaw-hermes integration tests

## Layout

```
tests/
  adversarial.rs               # existing adversarial-input tests
  fixture_ratchet.rs           # tier-1 language-coverage ratchet
  fixtures/
    adversarial/               # existing fuzzer-derived crash inputs
    language_surface/          # tier-1 ratchet corpus
      manifest.toml            # declares CompileStatus per fixture
      <category>/<name>/
        src.js                 # ECMAScript source
        expected.txt           # golden decompile bundle output
        README.md              # what this fixture covers + known quirks
```

## Toolchain

`tests/fixture_ratchet.rs` drives `hermesc` → `HbcFile::parse` → `decompile_bundle` → `hermesc` via `droidsaw-fixture-harness`. It requires `hermesc` on `PATH` or pointed at via the `DROIDSAW_HERMESC` environment variable.

If `hermesc` isn't available, the test skips with an `eprintln` rather than hard-failing — matching the bench-side `hbc_corpus_regression` and the dex sibling's javac/d8 skip pattern.

### Installing `hermesc`

No platform package ships Hermes. Build from source from the upstream `facebook/hermes` tree:

```sh
cmake -S /path/to/hermes -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build --target hermesc
export DROIDSAW_HERMESC=/path/to/hermes/build/bin/hermesc
```

`hermesc` version is pinned by whichever revision you build. The fixtures were baseline-locked against **Hermes 1.0.0, HBC bytecode version 99, LLVM 8.0.0svn Release**. Different HBC versions may produce byte-different compiled output, which is fine — the ratchet compares decompile text, not HBC bytes.

## The ratchet contract

`tests/fixture_ratchet.rs` runs every entry in `manifest.toml` serially (`setrlimit` is process-global), builds the full pipeline outcome, and passes everything through `droidsaw_fixture_harness::check_ratchet`. The test **fails** on:

- Any `SemanticFail` (decompile text drifted from `expected.txt`).
- Any `ResourceLimitExceeded` (RSS or wall-time cap hit).
- A `compile_pass → compile_fail` regression.
- A `compile_fail → compile_pass` improvement (these must be accepted by bumping the manifest deliberately, not silently).
- Any fixture missing from the manifest or present in outcomes but not the manifest.

### Promoting the baseline

When a decompiler change legitimately updates the output of fixtures or promotes `compile_fail` entries to `compile_pass`, regenerate in one pass:

```sh
DROIDSAW_HERMESC=/path/to/hermesc \
  cargo test -p droidsaw-hermes --test fixture_ratchet regen_fixtures \
  -- --ignored --nocapture
```

`regen_fixtures` rewrites every `expected.txt` to the live decompile output and resets each `status` based on whether `hermesc` accepts the decompile. Commit the result — that's the new baseline.

## Adding a fixture

1. Create `fixtures/language_surface/<category>/<name>/src.js` with a minimal program (one feature per fixture).
2. Add an entry to `manifest.toml`:
   ```toml
   [[fixture]]
   name = "category_name"
   source = "<category>/<name>/src.js"
   expected_stdout = "<category>/<name>/expected.txt"
   status = "compile_fail"   # regen will promote if hermesc roundtrips
   ```
3. Write `<category>/<name>/README.md` covering the feature and any obvious quirks in the decompiled output.
4. Run `regen_fixtures` (above) to populate `expected.txt` and lock `status`.
5. Run `cargo test -p droidsaw-hermes --test fixture_ratchet` to confirm clean.

## Relation to `droidsaw-bench`'s `hbc_corpus_regression`

Bench's `tests/hbc_corpus_regression.rs` consumes the same `droidsaw-fixture-harness` library but runs it against **pre-compiled `.hbc` files** from a curated React Native corpus. This ratchet runs against **source-level `.js` fixtures** that go through `hermesc` at test time — different shape, different purpose. No overlap:

- Bench catches real-world drift in HBC parse / decompile behaviour.
- This ratchet catches language-surface regressions on hand-crafted inputs where the expected output is stable.
