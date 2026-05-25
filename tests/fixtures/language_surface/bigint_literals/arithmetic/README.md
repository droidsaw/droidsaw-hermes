# bigint_literals_arithmetic

Exercises BigInt literal syntax (`123n`) + arithmetic (`+`, `-`, `*`, `/`,
`%`, `**`) + `typeof` + method dispatch (`toString`).

**test262 source**: `test/built-ins/BigInt/` (SHA `4a1e962`)

**Adaptation**: test262 entries use the harness assertion machinery on
boundary-value arithmetic. This fixture picks a minimal arithmetic sweep +
large-literal case + `typeof`.

**Classification**: `compile_pass`.

**Known decompile defects** (severe):

1. **BigInt literal value collapsed to table index.** Source literals
   `10n` / `3n` / `123456789012345678901234567890n` / `1n` / `2n` decompile as
   `0n` / `1n` / `3n` / etc. — the emitter is printing the BigInt-table
   INDEX rather than the literal VALUE. The HBC file has a bigint table
   (same shape as the string table) and the decompiler is de-referencing
   incorrectly.
2. **`**` operator leaks HermesBuiltin call.** `a ** 2n` decompiles as
   `HermesBuiltin.exponentiationOperator(3)` — same leakage class as
   regex-named-groups. Should lower to `a ** 2n` syntax at emit.

**Candidate fix**: resolve the BigInt-table index to the literal value
at emit (highest-severity gap — literals carrying the table index
instead of the value means ANY BigInt-heavy code decompiles with wrong
numbers). Separately, lower `HermesBuiltin.exponentiationOperator` back
to `**` syntax at emit.
