class Point {
    constructor(x, y) {
        this.x = x;
        this.y = y;
    }
    distance(other) {
        const dx = this.x - other.x;
        const dy = this.y - other.y;
        return Math.sqrt(dx * dx + dy * dy);
    }
}

const a = new Point(0, 0);
const b = new Point(3, 4);
print(a.distance(b));
