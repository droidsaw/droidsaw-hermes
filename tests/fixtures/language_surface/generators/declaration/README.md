# generators_declaration

Exercises `function *` generator declaration + `yield` + `.next()` consumption
— the basic generator-coroutine shape.

**test262 source**: `test/language/statements/generators/declaration.js`

**Adaptation**: `assert.sameValue(g.next().value, 4)` → `print(g.next().value)`;
`assert.sameValue(g.next().done, true)` → `print(g.next().done)`. No other
structural changes.

**Classification**: `compile_fail` baseline pending hermesc-equipped regen.

**Rationale**: generators are encoded in HBC with `CreateGenerator` /
`SaveGenerator` / `StartGenerator` / `ResumeGenerator` / `CompleteGenerator`
opcodes; emitting the syntactic `function *` form + mid-body `yield`
expressions requires the structurer to recognize those opcodes as coroutine
state-machine markers rather than generic dispatch. Not verified without
hermesc on this host.

**Candidate fix**: round-trip generator function syntax
(`function *foo() { yield ...; return; }`) if the decompiler currently
emits a low-fidelity / opcode-literal representation.
