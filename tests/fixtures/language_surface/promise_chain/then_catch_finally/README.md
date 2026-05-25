# promise_chain_then_catch_finally

Exercises synchronous-path `Promise` chain: `.then`/`.catch`/`.finally` plus
value-returning chain progression. Async/await was covered in batch1's
`async_await_identifier`; this fixture picks the distinct chain-of-methods form.

**test262 source**: `test/built-ins/Promise/prototype/{then,catch,finally}/`
(SHA `4a1e962`)

**Adaptation**: test262 entries use harness + microtask queue inspection.
This fixture builds two chains on `Promise.resolve` / `Promise.reject` and
prints per-step; microtask ordering is deterministic within a single Hermes
tick.

**Classification**: `compile_pass`.

**Known decompile defects**:

1. **All 7 inline arrow arguments lost.** Every `.then(v => ...)` /
   `.catch(e => ...)` / `.finally(() => ...)` decompiles as `.then(null)` /
   etc., with the arrow body emitted as a separate function block. Recurs
   across this fixture, `symbol_iterator`, `array_methods_es6`.
2. The chain structure itself (`r5_4 → r5_8 → r5_11 → r5_14`) is preserved
   correctly — it's just the callback arguments that collapse to `null`.

**Candidate fix**: recover the inline arrow-arg pattern at the
callable site (shared root cause with symbol_iterator +
array_methods_es6 — one shared-lever fix likely covers all three).
