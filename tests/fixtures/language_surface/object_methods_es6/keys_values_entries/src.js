// adapted from test262 test/built-ins/Object/{assign,keys,values,entries}/ (BSD-licensed)
// Exercises ES6 Object static methods. Deterministic key-insertion order so
// outputs don't drift across engines.

var src = { a: 1, b: 2, c: 3 };
var dst = Object.assign({}, src);
print(dst.a);
print(dst.b);
print(dst.c);

var keys = Object.keys(src);
print(keys[0]);
print(keys[1]);
print(keys[2]);

var values = Object.values(src);
print(values[0]);
print(values[1]);
print(values[2]);

var entries = Object.entries(src);
print(entries[0][0]);
print(entries[0][1]);
print(entries[1][0]);
print(entries[1][1]);
