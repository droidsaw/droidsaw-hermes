# forloop_for_of_array

Exercises `for (var x of array)` iteration — the for-of statement over an
Array, including the corner that `array.pop()` mid-iteration cuts the loop
short at one element.

**test262 source**: `test/language/statements/for-of/array-contract.js`

**Adaptation**: two `assert.sameValue(x, 0)` / `assert.sameValue(iterationCount, 1)`
calls replaced with `print(x)` / `print(iterationCount)`. The for-of loop +
`array.pop()` mutation body preserved verbatim.

**Classification**: `compile_fail` baseline pending hermesc-equipped regen.

**Rationale**: HBC lowers `for (x of array)` via `IteratorBegin` +
`IteratorNext` + `IteratorClose` opcodes; the decompiler must fold the
iterator-protocol opcode sequence back into the syntactic
`for (... of ...)` form rather than emitting the raw
`while (true) { iter.next(); if (done) break; ... }` unfold. Not verified
without hermesc on this host.

**Candidate fix**: fold the iterator-unfolded form back to
`for (... of ...)` syntax at emit. The sibling `forloop/` directory
already holds `forloop/sum` (classic C-style for), so placing for-of
here (rather than a top-level `for_of/` category) keeps iteration
forms colocated.
