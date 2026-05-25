# destructuring_default_computed_object_pattern

Exercises object-pattern destructuring with computed keys (`{ [key]: val }`) +
default values (`{ x = default } = obj`) + nested + renamed forms.

**test262 source**: `test/language/statements/variable/dstr/` +
`test/language/expressions/assignment/dstr/` (SHA `4a1e962`)

**Adaptation**: test262 uses heavily-structured dstr templates. This fixture
exercises the four combinations (computed + default, missing, nested +
renamed + default, nested-missing) compactly.

**Classification**: `compile_pass`.

**Known decompile defects** (structural):

1. **Local variables mangle into hypothetical objects.** `var { [key]: val = 99 } = obj;`
   decompiles as `r2_8.val = inner;` — the `val` binding got "hoisted" into
   a synthetic object `r2_8`, plus `globalThis.print` and other fixture-scope
   references became property accesses on that object. Root cause is likely
   in the scope/var-tracker for destructuring-introduced locals: they're
   being treated as "properties of something" rather than fresh local
   bindings.
2. **Nested-object literal broken.** `{ outer: { inner: 7 } }` decompiles as
   `{ outer: null }` + `r3_25[0] = { inner: 7 }` — same pattern as the
   inline-callable arg-loss, but for object literals in a destructuring
   context.
3. The `if (inner === undefined) { inner = 99; }` default-fallback machinery
   is recovered correctly — the emitter knows about the default-value branch.

**Candidate fix**: recover destructuring-introduced bindings as locals,
not synthetic object properties. May be closely related to the
inline-callable-args recovery if the root cause is a shared
var-scope tracking gap.
