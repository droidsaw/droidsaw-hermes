// adapted from test262 test/language/statements/class/elements/private-field-as-arrow-function.js (BSD-licensed)
// Original `assert.sameValue(c.method(), 'test262')` replaced with `print(c.method())`.

class C {
    #m = () => 'test262';

    method() {
        return this.#m();
    }
}

let c = new C();
print(c.method());
