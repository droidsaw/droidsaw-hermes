// adapted from test262 test/language/statements/labeled/{cptn-break,continue}.js (BSD-licensed)
// Labeled break + continue across nested loops. Structurer should recover
// the label names, not synthesize gotos.

outer: for (var i = 0; i < 3; i++) {
    inner: for (var j = 0; j < 3; j++) {
        if (i === 1 && j === 1) {
            break outer;
        }
        if (j === 2) {
            continue outer;
        }
        print(i + "," + j);
    }
}

search: {
    for (var k = 0; k < 5; k++) {
        if (k === 3) {
            print("found:" + k);
            break search;
        }
    }
    print("not reached");
}
print("after");
