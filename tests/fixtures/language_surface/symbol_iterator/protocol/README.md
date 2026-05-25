# symbol_iterator_protocol

Exercises the `[Symbol.iterator]` protocol — assigning a generator function to
`obj[Symbol.iterator]`, then consuming via `for-of`.

**test262 source**: `test/built-ins/Symbol/iterator/` (SHA `4a1e962`)

**Adaptation**: the test262 tests in this directory verify property descriptors
via the `verifyProperty` harness helper; this fixture substitutes a live
protocol implementation + `for-of` consumer with `print()`-based output so it's
harness-free and deterministic.

**Classification**: `compile_pass` — hermesc roundtrip closes through both
`src.js → HBC → decompile` and `decompile → HBC` arms. Semantic equivalence is
NOT verified by the ratchet; the decompiled output has real defects (see below).

**Known decompile defects**:

1. **Inline arrow/function expression lost at call-site.** The assignment
   `o[Symbol.iterator] = function() { ... }` decompiles as
   `globalThis.o[Symbol.iterator] = null` — the function argument is replaced
   by a sentinel `null`, and the function body is emitted as a separate
   `// ==hermes-fixture-function== 1` block. Same shape as the promise-chain /
   findIndex arrow-arg loss — a shared-lever pattern, not Symbol-specific.
2. **for-of structure garbled.** The consumer loop
   `for (var x of o) { print(x); }` becomes a `while (r3 === undefined)` loop
   probing the wrong iterator slot; `for-of` lowering isn't being recovered.

**Candidate fix**: recover the inline arrow-arg pattern that recurs
across this fixture, `promise_chain`, and `array_methods_es6` — likely
one root cause covering all three. Separately, recover the
iteration-protocol shape that lowers `for-of` so it round-trips.
