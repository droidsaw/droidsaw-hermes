# tagged_template_raw_string_raw

Exercises tagged template literals: the built-in `String.raw\`...\`` tag +
a custom tag accessing `.raw` and indexed cooked strings.

**test262 source**: `test/language/expressions/tagged-template/` +
`test/built-ins/String/raw/` (SHA `4a1e962`)

**Adaptation**: test262 uses the harness for comparison assertions. This
fixture prints directly.

**Classification**: `compile_pass`.

**Known decompile defects**:

1. **Template-args collapsed to single integer.** `String.raw\`Hello\n${1+2}World\t!\``
   decompiles as `String.raw(r7_10, 3)` — the template-strings array
   (cooked + raw chunks) collapsed to a `HermesBuiltin.getTemplateObject(7)`
   opaque handle, and the interpolation value (`1+2 = 3`) is the only
   user-visible argument. Losing the template-strings array means the source
   cooked/raw chunks can't be recovered.
2. The custom-tag body (`function tag(...) { return strings.raw[0] + ... }`)
   decompiles cleanly — only the call-site shape suffers.

**Candidate fix**: recover the template-strings array at emit; drop
the opaque `HermesBuiltin.getTemplateObject(N)` in favor of the
source chunks.
