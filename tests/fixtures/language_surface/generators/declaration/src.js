// adapted from test262 test/language/statements/generators/declaration.js (BSD-licensed)
// Original assertions (assert.sameValue) replaced with `print` for hermes fixture harness.

function *foo(a) { yield a + 1; return; }

var g = foo(3);
print(g.next().value);
print(g.next().done);
