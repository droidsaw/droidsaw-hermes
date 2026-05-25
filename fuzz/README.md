# droidsaw-hermes fuzz harness

libFuzzer targets for `droidsaw-hermes`. Each target exercises a P0 invariant.

## Targets

| Target               | Invariant                                                                    |
|----------------------|------------------------------------------------------------------------------|
| `fuzz_parser`        | `HbcFile::parse(bytes)` never panics on arbitrary input.                     |
| `fuzz_opcode_decode` | `decode::decode_function(bytes, version)` never panics.                      |
| `fuzz_cfg`           | Parse → walk functions → `Cfg::build` never panics.                          |
| `fuzz_ssa`           | Parse → walk functions → `Cfg::build` → `build_ssa` never panics.            |

`fuzz_opcode_decode` stands in for the "opcode encode/decode involution" row
of the roadmap property matrix until a Hermes bytecode re-encoder exists.

## Prerequisites

- `cargo-fuzz` (`cargo install cargo-fuzz`).
- Rust nightly toolchain (nightly is required by libFuzzer's sanitizer flags).

## Run

From `droidsaw-hermes/`:

```sh
export PATH="$HOME/.cargo/bin:$PATH"
export RUSTUP_TOOLCHAIN=nightly-2025-11-21

cargo fuzz run fuzz_parser                                 # until you ctrl-c
cargo fuzz run fuzz_opcode_decode  -- -max_total_time=60   # bounded 60s smoke
cargo fuzz run fuzz_cfg            -- -max_total_time=60
cargo fuzz run fuzz_ssa            -- -max_total_time=60
```

Corpus-only sanity check (build + load seeds, no mutation):

```sh
cargo fuzz run <target> -- -runs=0
```

## Dictionaries

libFuzzer dictionaries under `fuzz/dictionaries/` anchor mutation to
HBC magic, the version field's known dispatch buckets, and common
opcode bytes. Provenance cited in each file's header.

| Target                          | Dictionary                  |
|---------------------------------|-----------------------------|
| `fuzz_parser`                   | `dictionaries/hermes.dict`  |
| `parser_differential`           | `dictionaries/hermes.dict`  |
| `fuzz_opcode_decode`            | `dictionaries/hermes.dict`  |
| `fuzz_emit_roundtrip_hbc`       | `dictionaries/hermes.dict`  |
| `fuzz_cfg`                      | `dictionaries/hermes.dict`  |
| `cfg_differential`              | `dictionaries/hermes.dict`  |
| `fuzz_ssa`                      | `dictionaries/hermes.dict`  |
| `fuzz_decode_source_locations`  | `dictionaries/hermes.dict`  |
| `fuzz_scan`                     | `dictionaries/hermes.dict`  |

Append `-- -dict=fuzz/dictionaries/<name>.dict` to any `cargo fuzz run`:

```sh
cargo fuzz run fuzz_parser -- -dict=fuzz/dictionaries/hermes.dict
cargo fuzz run fuzz_opcode_decode -- -dict=fuzz/dictionaries/hermes.dict -max_total_time=60
```

## Layout

```
fuzz/
├── Cargo.toml
├── fuzz_targets/
│   └── fuzz_*.rs
├── seeds/
│   └── <target>/    — tracked, hand-curated seeds (this is the canonical set)
├── corpus/
│   └── <target>/    — libFuzzer's runtime working corpus (gitignored; machine-local)
└── crashes/
    └── <target>/    — tracked reproducers (short input-hash filenames) + .note files
```

Before a run, seed the working corpus from `seeds/`:

```sh
for t in fuzz_parser fuzz_opcode_decode fuzz_cfg fuzz_ssa; do
    cp -n fuzz/seeds/$t/* fuzz/corpus/$t/ 2>/dev/null || true
done
```

`corpus/*/*` is gitignored except `.gitkeep`. Mutation artefacts stay local.

## Crash triage

If a run produces a crash:

1. `cargo fuzz tmin <target> <input>` to minimize (skip if the input is
   already <= a few KB).
2. Move the (minimized) input to `fuzz/crashes/<target>/<hash>` (12-char
   input hash prefix is fine).
3. Write a companion `fuzz/crashes/<target>/<hash>.note` with:
   - stage that panicked (parser / decode / cfg / ssa)
   - panic message (one line, trimmed)
   - site: `src/path.rs:line[:col]`
   - repro: `cargo fuzz run <target> fuzz/crashes/<target>/<hash>`
   - two-sentence root-cause guess if obvious.

Fixing the underlying panic is out of scope for this harness — that
work belongs to a hardening pass. This harness only stands up the
fuzz infrastructure.
