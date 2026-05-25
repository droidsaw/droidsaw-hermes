function sumTo(n) {
    let total = 0;
    for (let i = 1; i <= n; i = i + 1) {
        total = total + i;
    }
    return total;
}

print(sumTo(10));
