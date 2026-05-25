// adapted from test262 test/language/rest-parameters/rest-parameters-apply.js (BSD-licensed)
// Original assertions (assert.sameValue) replaced with `print` for hermes fixture harness.

function af(...a) {
    return a.length;
}

print(af.apply(null, []));
print(af.apply(null, [1]));
print(af.apply(null, [1, 2]));
print(af.apply(null, [1, , 2]));
