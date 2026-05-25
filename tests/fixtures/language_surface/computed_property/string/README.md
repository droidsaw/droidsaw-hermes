# computed_property_string

Exercises `[computed]: value` computed property names on an object literal —
both the literal-string form `['b']:` and the call-expression form
`[ID('d')]:`.

**test262 source**: `test/language/computed-property-names/basics/string.js`

**Adaptation**: dropped the `compareArray.js` harness include + the
`assert.compareArray(Object.getOwnPropertyNames(object), [...])` assertion
(Hermes fixture harness has no compareArray polyfill). Remaining
`assert.sameValue(object.X, ...)` calls replaced with `print(object.X)`. The
literal `{a: 'A', ['b']: 'B', c: 'C', [ID('d')]: 'D'}` is preserved — that's
the structural feature under test.

**Classification**: `compile_fail` baseline pending hermesc-equipped regen.

**Rationale**: HBC lowers computed property names through
`NewObjectWithBuffer` + `PutNewOwnByVal` (for call-expr keys) instead of the
static-key `PutOwnByIndex` / `PutNewOwnById` path; the decompiler must
recognize the dynamic-key sequence and round-trip `[expr]:` syntax rather
than materializing `Object.defineProperty` or similar low-fidelity fallbacks.
Not verified without hermesc on this host.

**Candidate fix**: pattern-match the literal-shape resolution and emit
the computed key inline if the decompiler currently falls back.
