# labeled_break_continue_nested_loops

Exercises labeled control-flow: `outer: for (...) { inner: for (...) { break outer; } }`
across nested for-loops + a `search: { ... break search; }` labeled block.

**test262 source**: `test/language/statements/labeled/{cptn-break.js,continue.js}`
(SHA `4a1e962`)

**Adaptation**: test262 tests verify completion-record propagation via the
harness; this fixture prints in-loop progress + post-loop marker.

**Classification**: `compile_pass`.

**Known decompile defects** (severe, structural):

1. **Label names erased.** The `outer:` / `inner:` / `search:` labels are
   gone; the structurer has no representation for source-level labels and
   `break outer` / `continue outer` have been lowered to unlabeled
   `break` / `continue` within a reshuffled control-flow graph.
2. **Loop polarity inverted.** Source `for (var j = 0; j < 3; j++)` decompiles
   as `while (j >= r3)` (where `r3 = 3`) — the sense of the test is flipped
   relative to the hoist-preamble / loop-polarity fixes from the shared-lever
   trio. This may indicate a polarity gap those fixes missed for
   label-reached loops specifically, OR a residual re-ordering artifact from
   the labeled-break unwind.
3. **Outer `if` wrap.** The outer for-loop is wrapped in an `if (globalThis.i < r3) { ... }`
   guard that doesn't correspond to source. Probably the structurer's
   "single-iteration-possible" pre-test lowering interacting badly with the
   labeled-continue.

**Candidate fix**: thread label-tracking through the structurer so
labels survive emission and cross-label break/continue reconstructs.
If the polarity inversion turns out to be a separate root cause from
the label-recovery, address it independently.

**Open flag**: the polarity inversion here (`j >= r3` where source is
`j < 3`) overlaps with what the prior loop-return-reconstruction fix
should have addressed. Either that fix has a gap for labeled loops, or
this is a different root cause.
