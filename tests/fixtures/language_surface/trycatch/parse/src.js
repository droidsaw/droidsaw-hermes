function safeParse(s) {
    try {
        return JSON.parse(s);
    } catch (e) {
        return null;
    }
}

print(safeParse('{"x":1}').x);
print(safeParse("not json"));
