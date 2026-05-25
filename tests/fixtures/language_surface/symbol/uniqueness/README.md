# symbol_uniqueness

Exercises `Symbol()` constructor uniqueness — each invocation returns a fresh
unique value, even with the same description argument.

**test262 source**: `test/built-ins/Symbol/uniqueness.js`

**Adaptation**: `assert.notSameValue(Symbol(x), Symbol(x), '...')` rewritten
as `print(Symbol(x) === Symbol(x))`. Because both Symbols are fresh, `===`
is always `false` — output is deterministic four lines of `false`. The
original `assert.notSameValue` form would have required the fixture harness
to special-case a pass-if-inequality outcome; direct `=== ` + `print`
sidesteps that.

**Classification**: `compile_fail` baseline pending hermesc-equipped regen.

**Rationale**: `Symbol(...)` calls resolve to the `Symbol` built-in
constructor. The decompiler must preserve the bare call syntax (not unfold
to `Object(new Symbol(...))` or similar lowered form) — Hermes has a
`HermesInternal.getSymbolConstructor`-style indirection that can confuse
naive name resolution. Not verified without hermesc on this host.

**Candidate fix**: resolve `Symbol` to its builtin identifier cleanly
if the decompiler currently fails. Well-known symbols like
`Symbol.iterator` / `Symbol.asyncIterator` are a separate surface.
