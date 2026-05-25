# rest_params_apply

Exercises `function f(...a)` rest parameters collecting into an Array, invoked
via `Function.prototype.apply` with variable-length argument arrays —
including the sparse-hole case `[1, , 2]`.

**test262 source**:
`test/language/rest-parameters/rest-parameters-apply.js`

**Adaptation**: four `assert.sameValue(af.apply(null, X), N, '...')` calls
replaced with `print(af.apply(null, X))`. The rest-parameter declaration
`function af(...a) { return a.length; }` preserved verbatim.

**Classification**: `compile_fail` baseline pending hermesc-equipped regen.

**Rationale**: HBC lowers `...a` rest parameters via a specialized
`LoadRestParams` / `ReifyArguments`-style opcode depending on version;
the decompiler must reconstruct the syntactic `...identifier` at the
FormalParameter site rather than emitting
`Array.prototype.slice.call(arguments, N)` at the body head. Not verified
without hermesc on this host.

**Candidate fix**: surface `...a` at the parameter list if the
decompiler currently emits the lowered `copyRestArgs` / `slice.call`
shape. Often pairs with spread-element recovery (different AST site,
same syntactic surface).
