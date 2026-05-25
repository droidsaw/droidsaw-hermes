// adapted from test262 test/built-ins/Symbol/uniqueness.js (BSD-licensed)
// Original assert.notSameValue replaced with equality prints so the output is deterministic
// across runs (both `Symbol('')` values are fresh, so === is always false).

print(Symbol('') === Symbol(''));
print(Symbol() === Symbol());
print(Symbol(null) === Symbol(null));
print(Symbol('x') === Symbol('x'));
