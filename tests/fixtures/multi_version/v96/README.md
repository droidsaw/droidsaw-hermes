# multi_version/v96 — env-gated corpus convention

The hermes language fixture matrix's v96 column is **populated at test run-time from a user-staged corpus directory**, not from committed bytes.

**Why env-gated, not committed**: the portability scrub discipline forbids tests + committed code from referencing third-party production apps by name or hard-coding production-sample content. v96 HBC bundles are produced only by older `hermesc` builds (current upstream's `BYTECODE_VERSION = 99`); generating fresh v96 samples in the local toolchain is not currently possible. The corpus convention matches the existing `tests/hbc_corpus_roundtrip.rs` precedent.

## Staging the v96 corpus

Set `DROIDSAW_HERMES_MULTI_VERSION_CORPUS` to a directory containing per-version subdirs:

```bash
mkdir -p /tmp/hermes-mv-corpus/v96
# Drop one or more v96 *.hbc files in there. For example, extract from
# a React Native APK whose index.android.bundle decodes to version 96:
unzip -p /path/to/your-rn-app.apk assets/index.android.bundle \
    > /tmp/hermes-mv-corpus/v96/sample_a.hbc

DROIDSAW_HERMES_MULTI_VERSION_CORPUS=/tmp/hermes-mv-corpus \
    cargo test -p droidsaw-hermes --test fixture_matrix_multi_version -- --nocapture
```

The matrix test:
- Iterates `$DROIDSAW_HERMES_MULTI_VERSION_CORPUS/{v40,v76,v96}/*.hbc`.
- For each sample: `parse → decompile → recompile-via-hermesc`.
- Asserts `SEMANTIC_FAIL = 0` across v96 SUCCESS rows.
- Reports v40/v76 placeholder counts in test stdout (no assertion contribution until corpus is staged).
- Skips cleanly with `eprintln` if env not set or hermesc not available.

## Current state

The matrix is v96-only at present: v40 + v76 columns are placeholders pending corpus sourcing. The matrix's ratchet invariant `∀ v ∈ {v96}, ∀ s ∈ samples(v96), if decompile(v96, s) succeeds → SEMANTIC_FAIL(v96, s) = 0` widens automatically when those columns populate.
