# destructuring_pair

Object destructuring (`const { a, b } = pair`) inside a function that returns a new object literal with the fields swapped. Covers destructuring lowering and object-literal emission.

Known quirks: destructuring patterns lower to explicit member reads in Hermes bytecode — the decompiled output shows those reads rather than the original pattern.
