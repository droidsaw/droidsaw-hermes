# function_hello

Plain function declaration with a string-concat return and a top-level call. Covers function-declaration decode, string-constant emission, and the global-scope function wrapper that Hermes inserts around every bundle.

Known quirks in the decompiled output: `global()` emits a redundant `var greet` prelude (decompiler doesn't currently elide the pre-binding that Hermes' compiler inserts for hoisted function declarations). Syntactically valid JS — `hermesc` accepts it on recompile.
