# whileloop_infinite

`while (true) { ... }` — an unconditional loop exited via an inner
`return`. The HBC loop header terminates with `Jmp` / `JmpLong`
(no condition), which the structurer used to coerce into the sentinel
`Condition::Truthy(VarId::MAX)` and emit as
`while (r4294967295_4294967295) { ... }`. With `Stmt::While { cond:
Option<Condition>, .. }` the `None` case renders as the literal
`while (true)`.
