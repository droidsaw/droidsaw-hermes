function swap(pair) {
    const { a, b } = pair;
    return { a: b, b: a };
}

const r = swap({ a: 1, b: 2 });
print(r.a);
print(r.b);
