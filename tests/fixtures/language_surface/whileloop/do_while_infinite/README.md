# whileloop_do_while_infinite

`do { ... } while (true);` — a tail-tested loop with a literal-`true`
guard. Hermes compiles this to the same unconditional-`Jmp` back-edge
shape as `while(true)` and `for(;;)`. The decompiler renders this as
`while (true) { ... }`; rebuilding the syntactic `do-while` form would
require tracking "the exit check lives at the loop tail, not the head"
through the structurer, which is deferred.
