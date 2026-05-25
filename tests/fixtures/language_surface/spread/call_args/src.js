// adapted from test262 test/language/expressions/array/spread-mult-literal.js (BSD-licensed)
// Trimmed: use a named function with plain `.apply` rather than IIFE+arguments+callCount scaffolding.
// Exercises SpreadElement `...[ ... ]` in argument list.

function record(a, b, c, d, e) {
    print(a);
    print(b);
    print(c);
    print(d);
    print(e);
}

record.apply(null, [5, ...[6, 7, 8], 9]);
