// adapted from test262 test/language/expressions/coalesce/chainable.js (BSD-licensed)
// Original assertions (assert.sameValue) replaced with `print` for hermes fixture harness.

var x;

x = null ?? undefined ?? 42;
print(x);

x = undefined ?? null ?? 42;
print(x);

x = null ?? null ?? 42;
print(x);

x = undefined ?? undefined ?? 42;
print(x);
