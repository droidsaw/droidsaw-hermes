# regex_named_groups_capture

Exercises named capture groups (`(?<name>...)`) + `groups.<name>` access +
`$<name>` backreferences in `replace`.

**test262 source**: `test/built-ins/RegExp/named-groups/` (SHA `4a1e962`)

**Adaptation**: test262 entries use the harness + duplicate-name /
match-indices corners; this fixture is the minimal happy path: parse a
date, reshuffle digit-letter pairs.

**Classification**: `compile_pass`.

**Known decompile defects**:

1. **`HermesBuiltin.initRegexNamedGroups(N)` leakage.** Each regex-literal
   construction emits a leading call to `HermesBuiltin.initRegexNamedGroups(3)`
   — a private Hermes builtin that populates the group-name table at VM
   level. The decompiler should either hoist this into the regex literal's
   syntax (the `(?<year>...)` form already names the groups at source level,
   so the runtime call is redundant) or suppress it entirely. Currently
   surfaces as production output that would fail a roundtrip-to-ECMAScript
   check.
2. The regex literal itself is preserved correctly — the named groups + flags
   survive. Only the paired builtin call is out of place.

**Candidate fix**: suppress the redundant
`HermesBuiltin.initRegexNamedGroups` at emit when it's paired with a
named-groups regex literal.
