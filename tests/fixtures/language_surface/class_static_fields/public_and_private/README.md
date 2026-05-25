# class_static_fields_public_and_private

Exercises class-body static fields: `static count = 0` (public) + `static #secret = 42`
(private), plus static methods that reference them.

**test262 source**: `test/language/statements/class/elements/` (SHA `4a1e962`)

**Adaptation**: test262 entries here are syntax-only `after-same-line-gen-rs-*`
lexer/parser tests. This fixture authors a minimal functional example + prints
results.

**Classification**: `compile_pass`.

**Known decompile defects** (severe):

1. **Private-field initializer target inversion.** `static #secret = 42`
   decompiles as `42 ._private = r2_1` — the literal `42` became the
   assignment TARGET rather than the initializer VALUE. Structurally this is
   `42.prop = undef` which is nonsensical JS. Root cause likely in the
   static-field-init lowering: the HBC PutById slot-0/slot-1 pair is being
   emit-decoded with source/dest swapped.
2. **Class body hoisted out of scope.** The `Counter` class body appears as
   an anonymous `class r4_4 { ... }` with `bump` / `reveal` bodies emitted
   as empty stubs + separate function blocks for the real bodies. Class-body
   method-defs aren't being recovered into the class literal.

**Candidate fix**: address both the private-init target-inversion and
the public static-field initialization ordering. Class-body method-def
recovery is a separate existing gap — this fixture is evidence for
both.
