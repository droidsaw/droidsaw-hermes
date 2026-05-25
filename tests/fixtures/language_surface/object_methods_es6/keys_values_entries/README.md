# object_methods_es6_keys_values_entries

Exercises ES6 static `Object` methods: `Object.assign`, `Object.keys`,
`Object.values`, `Object.entries`.

**test262 source**: `test/built-ins/Object/{assign,keys,values,entries}/`
(SHA `4a1e962`)

**Adaptation**: test262 entries use the property-descriptor / harness
assertion machinery. This fixture exercises each method on a
literal-initialized object + prints the results.

**Classification**: `compile_pass`.

**Decompile quality**: clean — method calls + property-accesses round-trip
faithfully. No candidate fix; this fixture documents working behavior
rather than surfacing a gap.
