// adapted from test262 test/language/statements/for-of/array-contract.js (BSD-licensed)
// Original assertions (assert.sameValue) replaced with `print` for hermes fixture harness.

var array = [0, 1];
var iterationCount = 0;

for (var x of array) {
    print(x);
    array.pop();
    iterationCount += 1;
}

print(iterationCount);
