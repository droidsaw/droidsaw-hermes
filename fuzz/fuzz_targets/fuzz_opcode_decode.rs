#![no_main]

//! `fuzz_opcode_decode` — Hermes instruction decoder structural-invariant gate.
//!
//! **Asserts (on any input where `decode_function` succeeds):**
//! 1. No two instructions share the same `offset` (duplicate-offset
//!    invariant). Two instructions at the same offset would make the
//!    instruction stream ambiguous for downstream CFG + SSA.
//! 2. Each instruction's `offset + size` does not overflow u32 (no
//!    wrap-around offsets in the decoded stream).
//! 3. Every instruction offset is within the input byte slice. An
//!    out-of-range offset is a decoder bug.
//!
//! Verifies panic-freedom and structural-invariant constraints on the
//! opcode decoder across the range of supported Hermes versions.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    // First byte selects a Hermes opcode-schema version. Valid versions the
    // parser accepts range roughly 76..=99; anything else is irrelevant to
    // decode (opcodes module falls back to a sentinel). We pick a small
    // fixed set covering the three opcode-table shapes.
    let version = match data[0] % 4 {
        0 => 76,
        1 => 96,
        2 => 98,
        _ => 99,
    };
    let code = &data[1..];
    let Ok(insns) = droidsaw_hermes::decompile::decode::decode_function(code, version) else {
        return;
    };

    // Inv 1: no duplicate offsets.
    let mut seen_offsets = std::collections::BTreeSet::new();
    for insn in &insns {
        assert!(
            seen_offsets.insert(insn.offset),
            "duplicate instruction offset 0x{:x} in decoded stream",
            insn.offset,
        );
    }

    // Inv 2: offset + size does not overflow u32.
    for insn in &insns {
        let end = insn.offset.checked_add(insn.size as u32);
        assert!(
            end.is_some(),
            "instruction at offset 0x{:x} with size {} overflows u32",
            insn.offset,
            insn.size,
        );
    }

    // Inv 3: every instruction offset is within the input code slice.
    let code_len = code.len() as u64;
    for insn in &insns {
        assert!(
            (insn.offset as u64) < code_len,
            "instruction offset 0x{:x} >= code.len() 0x{:x}",
            insn.offset,
            code_len,
        );
    }
});
