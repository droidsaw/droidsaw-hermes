// adapted from test262 test/built-ins/Symbol/iterator/ (BSD-licensed)
// Minimal [Symbol.iterator] protocol implementation + for-of consumption.
// Original harness uses verifyProperty / assert.sameValue — replaced with
// print() so output is deterministic.

var o = {};
o[Symbol.iterator] = function() {
    var i = 0;
    return {
        next: function() {
            if (i < 3) {
                return { value: i++, done: false };
            }
            return { value: undefined, done: true };
        }
    };
};

for (var x of o) {
    print(x);
}
print(typeof Symbol.iterator);
