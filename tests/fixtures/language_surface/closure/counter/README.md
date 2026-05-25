# closure_counter

Factory function returning an inner function that captures `let n` from the enclosing scope. Covers closure-environment tracking and captured-variable emission.

Known quirks: captured `n` appears as an `environments[...]`-style access in the decompiled output rather than a lexical name. `hermesc` still accepts the expression syntactically — semantic equivalence isn't claimed.
