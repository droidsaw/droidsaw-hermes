# arrow_identity

Two arrow-function expressions (`id`, `inc`) bound via `const`, with a call-chain at the top level. Covers arrow-function lowering and `const` emission.

Known quirks: arrow functions appear as ordinary `function` declarations in the decompiled output — Hermes compiles them identically to regular functions, and the decompiler has no syntactic signal to distinguish them at emit time. The roundtrip is still accepted by `hermesc`.
