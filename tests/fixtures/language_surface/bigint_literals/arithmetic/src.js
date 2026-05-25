// adapted from test262 test/built-ins/BigInt/ (BSD-licensed)
// BigInt literals + arithmetic. Hermes may not support BigInt at all — this
// fixture probes parse-side acceptance independent of runtime semantics.

var a = 10n;
var b = 3n;
print((a + b).toString());
print((a - b).toString());
print((a * b).toString());
print((a / b).toString());
print((a % b).toString());
print((a ** 2n).toString());

var big = 123456789012345678901234567890n;
print(big.toString());
print(typeof 1n);
