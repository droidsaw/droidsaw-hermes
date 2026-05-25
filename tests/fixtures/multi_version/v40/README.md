# multi_version/v40 — pending corpus

The hermes language fixture matrix's v40 column is currently a
placeholder: no v40 HBC samples are available, and npm sourcing of
`hermes-engine@<v40-era-version>` requires explicit authorization.

**v40 era**: HBC bytecode version 40 ships with React Native ~0.56–0.68 (RN ~5 years old). Significant historical installed base; rare in current-shipping corpora.

**Re-entry trigger**: a v40 HBC sample obtained via any of:
- A staged sample dropped into this directory (drop a `*.hbc` file alongside this README; the multi-version matrix test will pick it up via `$DROIDSAW_HERMES_MULTI_VERSION_CORPUS`).
- An RN-0.56–0.68-era APK containing `assets/index.android.bundle` whose magic header decodes to version 40.
- An older `hermesc`/`hermes-engine` build authorized for npm/source acquisition.

When this column populates, the matrix's `∀ v ∈ {v96}` SEMANTIC_FAIL=0 invariant widens to `∀ v ∈ {v40, v96}`.
