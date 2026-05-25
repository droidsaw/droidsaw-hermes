// adapted from test262 test/built-ins/Array/prototype/{findIndex,fill,includes,copyWithin}/ (BSD-licensed)
// Exercises ES6 Array prototype methods. Harness-free — uses print for output.

var a = [1, 2, 3, 4, 5];
print(a.findIndex(function(x) { return x > 3; }));
print(a.includes(3));
print(a.includes(99));

var b = [0, 0, 0, 0];
b.fill(7, 1, 3);
print(b[0]);
print(b[1]);
print(b[2]);
print(b[3]);

var c = [1, 2, 3, 4, 5];
c.copyWithin(0, 3);
print(c[0]);
print(c[1]);
print(c[2]);
