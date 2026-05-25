# object_spread_basic

Exercises ES2018 object-literal spread `{...source}` in three shapes:

- `simple_spread`: prefix-prop + one spread source (`{a: 1, ...src}`)
- `multi_spread`: two spread sources + suffix prop (`{...a, ...b, c: 3}`)
- `mixed_spread`: spread between explicit key-value pairs (`{a: 1, ...src, c: 3}`)

Fixture-first baseline for object-spread sugar. The current decompile
output renders the unfolded `HermesBuiltin.copyDataProperties(target,
source, excluded)` call form that Hermes lowers spread to; the fold
pass collapses the cluster back to `{a: 1, ...src}`-shaped output via
a new `Expr::ObjectLit` spread-entry variant.

**Classification**: `compile_pass`. The golden locks the pre-fold
baseline so the fold pass can be verified by regen-diff rather than
by hand-authoring both before + after.

**Out of scope**: destructuring-rest (`const {x, ...rest} = obj`) —
that compiles to a distinct `HermesInternal.copyRestArgs`-adjacent
shape and overlaps with the destructuring-recovery surface.
