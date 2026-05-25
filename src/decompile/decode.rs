//! Instruction decoder: bytecodes → `Vec<DecodedInst>` with typed operands.
#![allow(missing_docs, reason = "internal")]

use crate::opcodes;

/// Operand type for schema tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum OpType {
    R,  // Reg8 (1 byte)
    R4, // Reg32 (4 bytes)
    U1, // UInt8 (1 byte)
    U2, // UInt16 (2 bytes)
    U4, // UInt32 (4 bytes)
    A1, // Addr8 (1 byte, signed offset)
    A4, // Addr32 (4 bytes, signed offset)
    I4, // Imm32 (4 bytes, signed)
    D,  // Double (8 bytes)
}

impl OpType {
    pub fn byte_size(self) -> usize {
        match self {
            OpType::R | OpType::U1 | OpType::A1 => 1,
            OpType::U2 => 2,
            OpType::R4 | OpType::U4 | OpType::A4 | OpType::I4 => 4,
            OpType::D => 8,
        }
    }
}

/// A decoded operand value.
#[derive(Debug, Clone, serde::Serialize)]
pub enum Operand {
    Reg(u8),
    Reg32(u32),
    UInt(u32),
    Int(i32),
    Double(f64),
    Addr(i32), // signed relative offset from instruction start
}

impl Operand {
    pub fn as_reg(&self) -> Option<u32> {
        match self {
            Operand::Reg(r) => Some(u32::from(*r)),
            Operand::Reg32(r) => Some(*r),
            _ => None,
        }
    }
}

/// A fully decoded instruction with typed operands.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DecodedInst {
    pub offset: u32,
    pub size: u8,
    pub opcode: u8,
    pub name: &'static str,
    pub op: crate::opcodes::OpCode,
    pub operands: Vec<Operand>,
    pub op_types: &'static [OpType],
}

impl DecodedInst {
    /// For jump/branch instructions, compute the absolute target address.
    /// Returns `None` when the signed relative offset would push `self.offset`
    /// out of `u32` range (adversarial only — HBC legitimate branches stay
    /// within the containing function's bytecode span).
    pub fn branch_target(&self) -> Option<u32> {
        if let Some(Operand::Addr(rel)) = self.operands.first() {
            self.offset.checked_add_signed(*rel)
        } else {
            None
        }
    }

    // ORACLE-OPCODE-LOCKSTEP-BEGIN
    // Canonical CF opcode names used by the production CF predicates below.
    // build.rs parses this section and cross-checks it against cfg_oracle.rs.
    // If a new CF opcode is added here, it MUST also appear in the oracle section.
    //
    // Unconditional jumps:   "Jmp"  "JmpLong"
    // Switch (any variant):  "SwitchImm"  "StringSwitchImm"
    // Return:                "Ret"
    // Throw (block-ending):  "Throw"
    // Unreachable:           "Unreachable"
    // ORACLE-OPCODE-LOCKSTEP-END

    /// Is this a jump instruction?
    pub fn is_jump(&self) -> bool {
        self.name.starts_with('J') || self.name.contains("SwitchImm")
    }

    /// Is this a conditional branch?
    pub fn is_conditional_branch(&self) -> bool {
        self.name.starts_with('J') && self.name != "Jmp" && self.name != "JmpLong"
    }

    /// Is this an unconditional jump?
    pub fn is_unconditional_jump(&self) -> bool {
        self.name == "Jmp" || self.name == "JmpLong"
    }

    /// Is this a return?
    pub fn is_return(&self) -> bool {
        self.name == "Ret"
    }

    /// Is this an unconditional throw (terminates the block)?
    /// ThrowIfEmpty is conditional — only throws if operand is empty, otherwise falls through.
    pub fn is_throw(&self) -> bool {
        self.name == "Throw"
    }

    /// Is this a terminator (ends a basic block)?
    pub fn is_terminator(&self) -> bool {
        self.is_jump() || self.is_return() || self.is_throw() || self.name == "Unreachable"
    }
}

/// Get the operand schema for a given bytecode version and opcode.
#[allow(
    clippy::indexing_slicing,
    reason = "PROOF: explicit `if idx < schemas.len()` guard immediately above; the indexed branch is unreachable on the false path. `idx = usize::from(opcode: u8)` so `idx ≤ 255` (already small)."
)]
fn get_schema(
    schemas: &'static [(&'static str, &'static [OpType])],
    opcode: u8,
) -> (&'static str, &'static [OpType]) {
    let idx = usize::from(opcode);
    if idx < schemas.len() {
        schemas[idx]
    } else {
        ("Unknown", &[])
    }
}

/// Decode all instructions in a function's bytecode.
///
/// Returns `Err(HermesError::UnsupportedVersion)` if `version` is outside the
/// supported set (40..=100 plus `parser::V98_LATE`).
#[allow(
    clippy::indexing_slicing,
    reason = "PROOF: every byte-stream read is bounded by an explicit guard immediately above:\n  • `code[pos]` — guarded by `while pos < code.len()`\n  • `sizes[opcode_idx]` — guarded by `if opcode_idx >= num_opcodes { return Err(UnknownOpcode) }` with `num_opcodes = sizes.len()`\n  • `names[opcode_idx]` — guarded by `if opcode_idx < names.len()` predicate on the branch\n  • `code[op_pos]` / `code[op_pos.wrapping_add(k)]` for k in 0..byte_size — guarded by `if op_end > inst_end { return Err(TruncatedInstructionStream) }` where `op_end = op_pos + byte_size` and `inst_end ≤ code.len()`. So every `op_pos + k < op_end ≤ inst_end ≤ code.len()`.\n  • `opcode_table[opcode_idx]` — guarded by `if opcode_idx < opcode_table.len()` predicate on the branch.\nAdversarial input takes the typed-Err early-return path; valid input is in-bounds by construction."
)]
pub fn decode_function(code: &[u8], version: u32) -> crate::Result<Vec<DecodedInst>> {
    let (sizes, _, _) = opcodes::get_version_tables(version)?;
    let names = opcodes::get_version_names(version)?;
    let opcode_table = opcodes::get_version_opcodes(version)?;
    let schemas = super::schemas::get_version_schemas(version)?;
    let num_opcodes = sizes.len();

    let mut instructions = Vec::new();
    let mut pos: usize = 0;

    while pos < code.len() {
        let opcode = code[pos];
        let opcode_idx = usize::from(opcode);
        if opcode_idx >= num_opcodes {
            return Err(crate::error::HermesError::UnknownOpcode {
                offset: pos,
                opcode_id: opcode,
                num_opcodes,
            });
        }

        let inst_size = sizes[opcode_idx];
        let Some(inst_end) = pos.checked_add(usize::from(inst_size)) else {
            return Err(crate::error::HermesError::TruncatedInstructionStream {
                offset: pos,
                opcode_id: opcode,
            });
        };
        if inst_size == 0 || inst_end > code.len() {
            return Err(crate::error::HermesError::TruncatedInstructionStream {
                offset: pos,
                opcode_id: opcode,
            });
        }

        let (schema_name, op_types) = get_schema(schemas, opcode);
        let name = if opcode_idx < names.len() && !names[opcode_idx].is_empty() {
            names[opcode_idx]
        } else {
            schema_name
        };

        // Decode operands
        let mut operands = Vec::with_capacity(op_types.len());
        // `pos + 1` is safe because `inst_end = pos + inst_size >= pos + 1`
        // (inst_size >= 1 validated above) — no wrap.
        let Some(mut op_pos) = pos.checked_add(1) else {
            return Err(crate::error::HermesError::TruncatedInstructionStream {
                offset: pos,
                opcode_id: opcode,
            });
        };

        for &ot in op_types {
            let Some(op_end) = op_pos.checked_add(ot.byte_size()) else {
                return Err(crate::error::HermesError::TruncatedInstructionStream {
                    offset: pos,
                    opcode_id: opcode,
                });
            };
            if op_end > inst_end {
                return Err(crate::error::HermesError::TruncatedInstructionStream {
                    offset: pos,
                    opcode_id: opcode,
                });
            }
            // WHY: `op_end = op_pos + byte_size <= inst_end <= code.len()` (validated
            // above); every `code[op_pos + k]` with `k < byte_size` is in-range.
            // `wrapping_add` keeps clippy arithmetic_side_effects quiet while
            // preserving bounds-backed semantics.
            let operand = match ot {
                OpType::R => {
                    let v = code[op_pos];
                    Operand::Reg(v)
                }
                OpType::R4 => {
                    let v = u32::from_le_bytes([
                        code[op_pos],
                        code[op_pos.wrapping_add(1)],
                        code[op_pos.wrapping_add(2)],
                        code[op_pos.wrapping_add(3)],
                    ]);
                    Operand::Reg32(v)
                }
                OpType::U1 => {
                    let v = u32::from(code[op_pos]);
                    Operand::UInt(v)
                }
                OpType::U2 => {
                    let v = u32::from(u16::from_le_bytes([
                        code[op_pos],
                        code[op_pos.wrapping_add(1)],
                    ]));
                    Operand::UInt(v)
                }
                OpType::U4 => {
                    let v = u32::from_le_bytes([
                        code[op_pos],
                        code[op_pos.wrapping_add(1)],
                        code[op_pos.wrapping_add(2)],
                        code[op_pos.wrapping_add(3)],
                    ]);
                    Operand::UInt(v)
                }
                OpType::A1 => {
                    #[allow(clippy::as_conversions, clippy::cast_possible_wrap, reason = "u8→i8 reinterpret (sign-extend) for the A1 signed-byte branch displacement; intentional bit-pattern wrap to recover signed semantics. i8→i32 widens via From.")]
                    let signed = code[op_pos] as i8;
                    Operand::Addr(i32::from(signed))
                }
                OpType::A4 => {
                    let v = i32::from_le_bytes([
                        code[op_pos],
                        code[op_pos.wrapping_add(1)],
                        code[op_pos.wrapping_add(2)],
                        code[op_pos.wrapping_add(3)],
                    ]);
                    Operand::Addr(v)
                }
                OpType::I4 => {
                    let v = i32::from_le_bytes([
                        code[op_pos],
                        code[op_pos.wrapping_add(1)],
                        code[op_pos.wrapping_add(2)],
                        code[op_pos.wrapping_add(3)],
                    ]);
                    Operand::Int(v)
                }
                OpType::D => {
                    let v = f64::from_le_bytes([
                        code[op_pos],
                        code[op_pos.wrapping_add(1)],
                        code[op_pos.wrapping_add(2)],
                        code[op_pos.wrapping_add(3)],
                        code[op_pos.wrapping_add(4)],
                        code[op_pos.wrapping_add(5)],
                        code[op_pos.wrapping_add(6)],
                        code[op_pos.wrapping_add(7)],
                    ]);
                    Operand::Double(v)
                }
            };
            operands.push(operand);
            op_pos = op_end;
        }

        let op = if opcode_idx < opcode_table.len() {
            opcode_table[opcode_idx]
        } else {
            opcodes::OpCode::Unreachable // fallback for unknown opcodes
        };

        // WHY: usize→u32 narrows; `pos` is bounded by the function's
        // bytecode `code.len()`, which the parser caps via the
        #[allow(clippy::as_conversions, clippy::cast_possible_truncation, reason = "usize→u32 narrows; `pos` is bounded by the function's bytecode `code.len()`, which the parser caps via the `SectionExceedsBounds` typed Err (file at most 4 GiB so truncation cannot fire).")]
        let offset = pos as u32;
        instructions.push(DecodedInst {
            offset,
            size: inst_size,
            opcode,
            name,
            op,
            operands,
            op_types,
        });

        pos = inst_end;
    }

    droidsaw_common::diag::stage_dump("decode", &instructions);
    Ok(instructions)
}
