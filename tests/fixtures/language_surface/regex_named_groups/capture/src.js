// adapted from test262 test/built-ins/RegExp/named-groups/ (BSD-licensed)
// Named capture groups + groups-object access. Minimal — avoids
// test262's named-groups-matchAll / duplicate-name corners.

var re = /(?<year>\d{4})-(?<month>\d{2})-(?<day>\d{2})/;
var m = re.exec("2024-03-15");
print(m.groups.year);
print(m.groups.month);
print(m.groups.day);

var s = "a1 b2 c3".replace(/(?<letter>[a-z])(?<digit>\d)/g, "$<digit>$<letter>");
print(s);
