// adapted from test262 test/language/expressions/await/await-in-function.js (BSD-licensed)
// Original assertions (assert.sameValue) replaced with `print` for hermes fixture harness.

function foo(await) { return await; }
print(foo(1));
