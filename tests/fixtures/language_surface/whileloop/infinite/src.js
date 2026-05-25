function serve() {
    let n = 0;
    while (true) {
        n = n + 1;
        if (n > 10) {
            return n;
        }
    }
}

print(serve());
