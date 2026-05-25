# optional_chaining_short_circuit

Exercises `?.` optional chaining with both short-form (`a?.[expr]`) and
long-form (`a?.b.c(expr).d`) where the head is `undefined` — verifying the
RHS is never evaluated (the `++x` side-effect fires only in the
reachable-branch).

**test262 source**:
`test/language/expressions/optional-chaining/short-circuiting.js`

**Adaptation**: `assert.sameValue(1, x)` replaced with `print(x)`. Original
four `?.`-expression statements preserved verbatim; they are the structural
feature under test.

**Classification**: `compile_fail` baseline pending hermesc-equipped regen.

**Rationale**: HBC lowers `?.` via a conditional branch over a
`JmpUndefinedOrNull`-style guard; the decompiler must reconstruct the
surface `?.` operator rather than emitting an explicit `if (x == null) ...`
ternary — losing the `?.` sigil is a soft-correctness failure (still correct
semantically, but syntactically regressed). Not verified without hermesc on
this host.

**Candidate fix**: reconstruct the `?.` operator from its lowered form
(`JmpUndefinedOrNull`-guarded shape).
