// adapted from test262 test/language/expressions/tagged-template/ (BSD-licensed)
// String.raw built-in tag + custom tag accessing .raw. Exercises escape-sequence
// cooked vs raw form.

print(String.raw`Hello\n${1 + 2}World\t!`);

function tag(strings, val) {
    return strings.raw[0] + "|" + strings[0] + "|" + val;
}
print(tag`line1\nline2 ${99}`);
