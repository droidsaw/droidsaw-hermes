// Rest-param after declared non-rest params. Sugar must preserve
// the declared `x` and `y` before `...tail`.

function sum(x, y, ...tail) {
    var total = x + y;
    for (var i = 0; i < tail.length; i++) {
        total = total + tail[i];
    }
    return total;
}

print(sum(1, 2));
print(sum(1, 2, 3));
print(sum(1, 2, 3, 4, 5));
