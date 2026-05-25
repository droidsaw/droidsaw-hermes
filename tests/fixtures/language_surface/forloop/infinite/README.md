# forloop_infinite

`for (;;) { ... }` — a C-style infinite for-loop with no init, no
condition, no step. The HBC shape is identical to `while (true)`:
the loop-header terminator is `Jmp` / `JmpLong`. The decompile output
may normalise to `while (true) { ... }` rather than preserving the
`for(;;)` syntactic form — that's expected, the ratchet checks that
the output recompiles, not that the surface form is bytewise
preserved.
