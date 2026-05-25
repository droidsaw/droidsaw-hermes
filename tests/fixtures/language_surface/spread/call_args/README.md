# spread_call_args

Exercises `...[literal]` spread in a `Function.prototype.apply` argument list
mixed with non-spread args — the `[5, ...[6,7,8], 9]` shape.

**test262 source**: `test/language/expressions/array/spread-mult-literal.js`

**Adaptation**: replaced the `(function() { ... }).apply(null, [...])` IIFE
scaffolding + `arguments.length` / `arguments[i]` / `callCount` assertions
with a named `record(a, b, c, d, e)` function that `print`s each positional
parameter. The spread-in-apply call site is preserved verbatim —
`record.apply(null, [5, ...[6, 7, 8], 9])` — which is the structural
feature under test. Named-function form also gives the decompiler a
cleaner anchor than an anonymous IIFE.

**Classification**: `compile_fail` baseline pending hermesc-equipped regen.

**Rationale**: HBC encodes array-literal-with-spread via specialized
`LoadConstArray` + per-element emit or via `NewArrayWithBuffer`; the
decompiler must round-trip the `...[...]` syntactic form. Not verified
without hermesc on this host.

**Candidate fix**: round-trip the `...` spread notation if the
decompiler currently emits a literal concatenation or pre-expanded
array instead of `[5, ...[6,7,8], 9]`.
