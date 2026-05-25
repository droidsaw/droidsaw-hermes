function poll(limit) {
    let n = 0;
    do {
        n = n + 1;
        if (n >= limit) {
            return n;
        }
    } while (true);
}

print(poll(4));
