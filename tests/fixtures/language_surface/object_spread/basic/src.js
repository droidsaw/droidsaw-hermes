// Exercises ES2018 object-spread `{...source}` in several shapes:
//
//  - simple_spread: one prefix prop + one spread source
//  - multi_spread:  two spread sources + one suffix prop
//  - mixed_spread:  spread between explicit key-value pairs
//
// Hermes lowers `{...src}` to `HermesBuiltin.copyDataProperties(target,
// src, excluded)`. The decompile baseline golden for this fixture
// therefore renders the unfolded call form; the fold pass collapses
// it back to `{a: 1, ...src}`-shaped output via a new
// `Expr::ObjectLit` spread-entry variant.
//
// Destructuring-rest (`const {x, ...rest} = obj`) is deliberately
// out-of-scope for this fixture — it compiles to a distinct
// HermesInternal.copyRestArgs-ish shape and overlaps with the
// destructuring-recovery surface.

function simple_spread(src) {
    const x = {a: 1, ...src};
    print(x.a);
    print(x.b);
}

function multi_spread(a, b) {
    const x = {...a, ...b, c: 3};
    print(x.a);
    print(x.b);
    print(x.c);
}

function mixed_spread(src) {
    const x = {a: 1, ...src, c: 3};
    print(x.a);
    print(x.b);
    print(x.c);
}

simple_spread({b: 2});
multi_spread({a: 1}, {b: 2});
mixed_spread({b: 2});
