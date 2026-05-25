// adapted from test262 test/language/statements/class/elements/ (BSD-licensed)
// Static public + private fields. Exercises class-body static initialization
// order + private-name mangling.

class Counter {
    static count = 0;
    static #secret = 42;

    static bump() {
        Counter.count += 1;
        return Counter.count;
    }

    static reveal() {
        return Counter.#secret;
    }
}

print(Counter.count);
print(Counter.bump());
print(Counter.bump());
print(Counter.bump());
print(Counter.count);
print(Counter.reveal());
