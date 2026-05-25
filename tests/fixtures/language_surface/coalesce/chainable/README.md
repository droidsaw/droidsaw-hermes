# coalesce_chainable

Exercises `??` nullish-coalescing chained multiple times
(`null ?? undefined ?? 42`, etc.) — left-to-right fallthrough to the first
non-nullish value.

**test262 source**: `test/language/expressions/coalesce/chainable.js`

**Adaptation**: four `assert.sameValue(x, 42, '...')` calls replaced with
`print(x)`. The four `??`-chain assignments are preserved verbatim.

**Classification**: `compile_fail` baseline pending hermesc-equipped regen.

**Rationale**: HBC lowers `??` via a two-branch guard
(`JmpUndefinedOrNull` → rhs, otherwise lhs); chained `?? ??` becomes a
nested guard. The decompiler must fold the nested branch back into the
`??` operator rather than emitting `if (lhs == null) x = rhs;`. Not
verified without hermesc on this host.

**Candidate fix**: pattern-match the `JmpUndefinedOrNull`-guarded shape
in the structurer and fold it back to `??`. Often grouped with `?.`
reconstruction (same `JmpUndefinedOrNull` primitive).
