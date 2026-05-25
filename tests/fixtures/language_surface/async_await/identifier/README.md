# async_await_identifier

Exercises `await` as a legal identifier in sloppy-mode non-async functions — a
corner of async-await surface that trips up naive keyword classifiers.

**test262 source**: `test/language/expressions/await/await-in-function.js`

**Adaptation**: original `assert.sameValue(foo(1), 1)` rewritten as
`print(foo(1))`. Header + license line preserved in spirit via attribution
comment; no other changes.

**Classification**: `compile_fail` baseline pending hermesc-equipped regen.

**Rationale**: hermesc is not installed on this host, so neither the
`expected.txt` golden nor the `DROIDSAW_PANIC_ON_DECOMPILE_ERR=1` bundle
classification pipeline could be run. The entry lands as `compile_fail`; a
later run on a hermesc-equipped host will regen `expected.txt` and the
ratchet's `Improvement::CompileFailNowPasses` signal will graduate it to
`compile_pass` if the decompiler handles it.

**Candidate fix** if the decompiler *does* struggle with
`await`-as-identifier: handle the lexical-context distinction at emit.
Broader async/await decompile surface (actual `async function` /
`await` expressions) is separate work — this fixture intentionally
exercises only the *identifier* corner because the full
`async function` surface is better covered by a dedicated fixture.
