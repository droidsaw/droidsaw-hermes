// adapted from test262 test/language/statements/variable/dstr/ (BSD-licensed)
// Object destructuring with computed keys + default values.

var key = "x";
var obj = { x: 10 };

var { [key]: val = 99 } = obj;
print(val);

var missing = {};
var { [key]: val2 = 99 } = missing;
print(val2);

// Nested + renamed + defaults.
var data = { outer: { inner: 7 } };
var { outer: { inner: renamed = 0 } } = data;
print(renamed);

var empty = { outer: {} };
var { outer: { inner: renamed2 = 0 } } = empty;
print(renamed2);
