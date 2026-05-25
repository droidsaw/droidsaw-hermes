# multi_version/v76 — pending corpus

The hermes language fixture matrix's v76 column is currently a
placeholder: no v76 HBC samples are available, and npm sourcing of
`hermes-engine@<v76-era-version>` requires explicit authorization.

**v76 era**: HBC bytecode version 76 ships with React Native ~0.72. Significant installed base in transitional production fleets that haven't migrated to RN ~0.73+.

**Re-entry trigger**: a v76 HBC sample obtained via any of:
- A staged sample dropped into this directory (drop a `*.hbc` file alongside this README; the multi-version matrix test will pick it up via `$DROIDSAW_HERMES_MULTI_VERSION_CORPUS`).
- An RN-0.72-era APK containing `assets/index.android.bundle` whose magic header decodes to version 76.
- An older `hermesc`/`hermes-engine` build authorized for npm/source acquisition.

When this column populates, the matrix's `∀ v ∈ {v96}` SEMANTIC_FAIL=0 invariant widens to `∀ v ∈ {v76, v96}`.
