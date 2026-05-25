// adapted from test262 test/language/expressions/optional-chaining/short-circuiting.js (BSD-licensed)
// Original assertions (assert.sameValue) replaced with `print` for hermes fixture harness.

const a = undefined;
let x = 1;

a?.[++x]; // short-circuiting.
a?.b.c(++x).d; // long short-circuiting.

undefined?.[++x]; // short-circuiting.
undefined?.b.c(++x).d; // long short-circuiting.

print(x);
