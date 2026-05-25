# template_greet

Template literal with two interpolations. Covers template-string lowering and multi-argument string concatenation.

Known quirks: template literals lower to `+`-concatenation in Hermes bytecode; the decompiled output re-emits the concatenation rather than the original backtick syntax.
