# array_methods_es6_find_fill_includes

Exercises ES6 `Array.prototype` methods: `findIndex`, `fill`, `includes`,
`copyWithin`.

**test262 source**: `test/built-ins/Array/prototype/{findIndex,fill,includes,copyWithin}/`
(SHA `4a1e962`)

**Adaptation**: test262 entries for each method use the `propertyHelper` +
`assert.sameValue` harness; this fixture calls the methods directly on a
fixed-shape array + prints results.

**Classification**: `compile_pass`.

**Known decompile defects**:

1. **Inline callback lost.** `a.findIndex(function(x) { return x > 3; })`
   decompiles as `globalThis.a.findIndex(null)` + a separate function block.
   Same shared-lever pattern as `symbol_iterator` / `promise_chain`.

Otherwise method-call + index-access round-trips cleanly — the ES6 Array API
surface itself is not a decompile gap.

**Candidate fix**: recover the inline arrow-arg pattern at the
callable site (shared root cause with symbol_iterator + promise_chain).
