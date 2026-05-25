// adapted from test262 test/language/computed-property-names/basics/string.js (BSD-licensed)
// Dropped the compareArray import + assertions; kept the computed-name object literal
// and swapped assert.sameValue for direct `print` reads.

function ID(x) {
    return x;
}

var object = {
    a: 'A',
    ['b']: 'B',
    c: 'C',
    [ID('d')]: 'D',
};

print(object.a);
print(object.b);
print(object.c);
print(object.d);
