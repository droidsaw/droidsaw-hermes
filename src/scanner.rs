//! Bytecode scanner for cross-references and call graph.
//! Uses version-specific opcode tables from opcodes.rs.
#![allow(missing_docs, reason = "internal")]
#![cfg_attr(
    not(test),
    allow(
        clippy::indexing_slicing,
        clippy::string_slice,
        reason = "PROOF: scanner consumes parsed HBC where every function-table / string-table / instruction-stream offset is parser-validated. opcode-table dispatch uses `op as usize` against fixed-size [_; 256] tables. Pool-index accesses (StringIdx, FunctionIdx) check against parser-validated pool lengths. v1.x refinement candidate (~16 sites)."
    )
)]

use std::collections::BTreeMap;

use crate::opcodes;

#[derive(serde::Serialize)]
pub struct ScanResult {
    /// string_index → vec of function indices that reference it
    pub string_refs: BTreeMap<u32, Vec<u32>>,
    /// func_index → vec of directly-called function indices
    pub call_graph: BTreeMap<u32, Vec<u32>>,
    /// func_index → vec of function indices created as closures within it
    pub closure_refs: BTreeMap<u32, Vec<u32>>,
}

/// What to scan for (avoids building unused data structures).
pub struct ScanMode {
    pub xrefs: bool,
    pub callgraph: bool,
}

/// Pre-built lookup table for O(1) opcode matching.
struct OpLookup {
    /// For each opcode: Some((byte_offset, operand_size)) if it references a string
    str_ops: [Option<(u8, u8)>; 256],
    /// For each opcode: Some((byte_offset, operand_size)) if it's a direct call
    call_ops: [Option<(u8, u8)>; 256],
}

impl OpLookup {
    fn build(str_ops: &[(u8, u8, u8)], call_ops: &[(u8, u8, u8)]) -> Self {
        let mut s = [None; 256];
        let mut c = [None; 256];
        for &(op, off, sz) in str_ops {
            s[usize::from(op)] = Some((off, sz));
        }
        for &(op, off, sz) in call_ops {
            c[usize::from(op)] = Some((off, sz));
        }
        OpLookup {
            str_ops: s,
            call_ops: c,
        }
    }
}

/// Safe scanner using the pure Rust parser.
pub fn scan_parsed(hbc: &crate::parser::HbcFile, data: &[u8]) -> ScanResult {
    scan_parsed_with_mode(
        hbc,
        data,
        &ScanMode {
            xrefs: true,
            callgraph: true,
        },
    )
}

pub fn scan_parsed_with_mode(
    hbc: &crate::parser::HbcFile,
    data: &[u8],
    mode: &ScanMode,
) -> ScanResult {
    let version = hbc.opcode_version();
    let (Ok((sizes, str_ops, call_ops)), Ok(names)) = (
        opcodes::get_version_tables(version),
        opcodes::get_version_names(version),
    ) else {
        return ScanResult {
            string_refs: BTreeMap::new(),
            call_graph: BTreeMap::new(),
            closure_refs: BTreeMap::new(),
        };
    };
    let num_opcodes = sizes.len();
    let lookup = OpLookup::build(str_ops, call_ops);

    // Build closure opcode lookup: CreateClosure/CreateClosureLongIndex/CreateAsyncClosure etc.
    // The func_id operand is after (Reg8:dst, Reg8:env) = 2 bytes, as UInt16 or UInt32.
    let mut closure_ops: [Option<(u8, u8)>; 256] = [None; 256]; // (byte_offset, operand_size)
    for (i, &name) in names.iter().enumerate() {
        if name.starts_with("CreateClosure")
            || name.starts_with("CreateAsyncClosure")
            || name.starts_with("CreateGeneratorClosure")
            || name == "CreateGenerator"
            || name == "CreateGeneratorLongIndex"
        {
            // Operands: Reg8, Reg8, UInt16/UInt32
            // func_id at byte offset 3 (opcode + 2 Reg8)
            let op_size = if name.ends_with("LongIndex") || name.ends_with("Long") {
                4u8
            } else {
                2
            };
            closure_ops[i] = Some((3, op_size));
        }
    }

    let mut string_refs: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
    let mut call_graph: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
    let mut closure_refs: BTreeMap<u32, Vec<u32>> = BTreeMap::new();

    for fi in 0..hbc.function_count {
        let f = hbc.function_get(fi);
        #[allow(clippy::as_conversions, reason = "u32→usize is a widen on every project-supported target (32-bit-or-wider). The downstream `checked_add` + `end > data.len()` gates catch any subsequent overflow.")]
        let offset = f.offset as usize;
        #[allow(clippy::as_conversions, reason = "Spec-bounded value-domain narrowing (parser-validated field; preceding PROOF documents the bit-width invariant).")]
        let size = f.size as usize;
        let Some(end) = offset.checked_add(size) else {
            continue;
        };
        if size == 0 || end > data.len() {
            continue;
        }

        // WHY: `end = offset + size` computed via `checked_add` above and bounds-
        // checked against `data.len()`; the slice expression below cannot wrap.
        #[allow(clippy::arithmetic_side_effects, reason = "`end = offset + size` computed via `checked_add` above and bounds- checked against `data.len()`; the slice expression below cannot wrap.")]
        let code = &data[offset..offset + size];
        let mut pos: usize = 0;

        while pos < code.len() {
            let opcode = usize::from(code[pos]);
            if opcode >= num_opcodes {
                break;
            }
            let inst_size = usize::from(sizes[opcode]);
            let Some(inst_end) = pos.checked_add(inst_size) else {
                break;
            };
            if inst_size == 0 || inst_end > code.len() {
                break;
            }

            if mode.xrefs
                && let Some((byte_off, op_size)) = lookup.str_ops[opcode]
                && let Some(operand_pos) = pos.checked_add(usize::from(byte_off))
                && let Some(str_id) = read_operand(code, operand_pos, op_size)
                && str_id < hbc.string_count
            {
                let funcs = string_refs.entry(str_id).or_default();
                if funcs.last() != Some(&fi) {
                    funcs.push(fi);
                }
            }

            if mode.callgraph {
                if let Some((byte_off, op_size)) = lookup.call_ops[opcode]
                    && let Some(operand_pos) = pos.checked_add(usize::from(byte_off))
                    && let Some(callee) = read_operand(code, operand_pos, op_size)
                    && callee < hbc.function_count
                {
                    let callees = call_graph.entry(fi).or_default();
                    if callees.last() != Some(&callee) {
                        callees.push(callee);
                    }
                }
                // Closure references: CreateClosure/CreateAsyncClosure/CreateGenerator
                if let Some((byte_off, op_size)) = closure_ops[opcode]
                    && let Some(operand_pos) = pos.checked_add(usize::from(byte_off))
                    && let Some(target) = read_operand(code, operand_pos, op_size)
                    && target < hbc.function_count
                {
                    let refs = closure_refs.entry(fi).or_default();
                    if refs.last() != Some(&target) {
                        refs.push(target);
                    }
                }
            }

            // WHY: `inst_end = pos + inst_size` was validated via `checked_add`
            // + `inst_end <= code.len()` above; this advance stays within slice bounds.
            #[allow(clippy::arithmetic_side_effects, reason = "`inst_end = pos + inst_size` was validated via `checked_add` + `inst_end <= code.len()` above; this advance stays within slice bounds.")]
            {
                pos += inst_size;
            }
        }
    }

    let result = ScanResult {
        string_refs,
        call_graph,
        closure_refs,
    };
    droidsaw_common::diag::stage_dump("scanner", &result);
    result
}

pub(crate) fn read_operand(code: &[u8], pos: usize, size: u8) -> Option<u32> {
    let end = pos.checked_add(usize::from(size))?;
    let bytes = code.get(pos..end)?;
    match size {
        1 => Some(u32::from(bytes[0])),
        2 => Some(u32::from(u16::from_le_bytes([bytes[0], bytes[1]]))),
        4 => Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])),
        _ => None,
    }
}
