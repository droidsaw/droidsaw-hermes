function makeCounter() {
    let n = 0;
    return function () {
        n = n + 1;
        return n;
    };
}

const c = makeCounter();
print(c());
print(c());
print(c());
