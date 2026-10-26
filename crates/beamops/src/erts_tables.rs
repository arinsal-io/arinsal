//! The opcode tables erts generates with `beam_makeops` (beam_opcodes.c / beam_opcodes.h):
//! `gen_opc[]` for the generic instructions, `opc[]` for the specific ones, the `genop_*` numbers
//! and the operand tags.

/// `OpEntry` of beam_opcodes.h: a specific instruction.
#[derive(Clone, Copy, Debug)]
pub(crate) struct OpEntry {
    /// The print name, `<name>_<operand types>`.
    pub name: &'static str,
    /// The bit masks that select this instruction among several for one generic instruction.
    pub mask: [u32; 3],
    /// The operand types.
    pub sign: &'static str,
}

/// `GenOpEntry` of beam_opcodes.h: a generic instruction.
#[derive(Clone, Copy, Debug)]
pub(crate) struct GenOpEntry {
    /// The instruction name.
    pub name: &'static str,
    /// The number of operands.
    pub arity: usize,
    /// Index in `OPC` of the first specific instruction, `-1` for none.
    pub specific: i32,
    /// The number of specific instructions.
    pub num_specific: usize,
    /// Whether the transform engine has rules for this instruction.
    pub transform: bool,
}

include!(concat!(env!("OUT_DIR"), "/erts_tables.rs"));

/// The tables as text, one line per entry, for comparison with the tables of a real erts build.
pub(crate) fn dump() -> String {
    let mut out = String::new();
    for (index, entry) in GEN_OPC.iter().enumerate() {
        out.push_str(&format!(
            "gen {index} {:?} {} {} {} {}\n",
            entry.name,
            entry.arity,
            entry.specific,
            entry.num_specific,
            u8::from(entry.transform)
        ));
    }
    for (index, entry) in OPC.iter().enumerate() {
        out.push_str(&format!(
            "opc {index} {:?} {:?} {:#x} {:#x} {:#x}\n",
            entry.name, entry.sign, entry.mask[0], entry.mask[1], entry.mask[2]
        ));
    }
    out.push_str(&format!(
        "max_generic_opcode {MAX_GENERIC_OPCODE}\nnum_generic_ops {NUM_GENERIC_OPS}\nnum_specific_ops {NUM_SPECIFIC_OPS}\n"
    ));
    out
}
