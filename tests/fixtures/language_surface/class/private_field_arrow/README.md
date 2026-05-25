# class_private_field_arrow

Exercises a private class field (`#m`) holding an arrow function, accessed via
`this.#m()` from a regular method — the tightest private-field + arrow +
private-access combo.

**test262 source**:
`test/language/statements/class/elements/private-field-as-arrow-function.js`

**Adaptation**: `assert.sameValue(c.method(), 'test262')` replaced with
`print(c.method())`. The class declaration + private field `#m = () =>
'test262'` + `this.#m()` access are all preserved.

**Classification**: `compile_fail` baseline pending hermesc-equipped regen.

**Rationale**: HBC encodes `#`-private fields via WeakMap-style
`PrivateNameBrand` installs at construction + per-access
`GetPrivateName` / `PutPrivateName` opcodes (or HBC's equivalent). The
decompiler must reconstruct `#identifier` syntax + recognize that a WeakMap
`.get(this)` pattern inside a method is a private-field access — not a
raw WeakMap call. Not verified without hermesc on this host.

**Candidate fix**: fold the raw WeakMap / brand-check call shape back
to `#field` syntax at emit. Likely covers both private fields and
private methods since they share the same HBC primitive.
