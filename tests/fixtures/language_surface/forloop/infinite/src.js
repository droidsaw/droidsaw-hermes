function forever(limit) {
    let n = 0;
    for (;;) {
        n = n + 1;
        if (n >= limit) {
            return n;
        }
    }
}

print(forever(5));
