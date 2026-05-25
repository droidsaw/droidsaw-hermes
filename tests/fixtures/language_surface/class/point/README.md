# class_point

ES6 class with a constructor, an instance method, and a `new` call at the top level. Covers Hermes's class-lowering (constructor + prototype-method assignment) and `this.` member emission.

Known quirks: classes compile down to `function` + prototype assignment in Hermes bytecode; the decompiled output reflects that rather than the original `class`/`constructor` syntax. `hermesc` accepts the lowered form on recompile.
