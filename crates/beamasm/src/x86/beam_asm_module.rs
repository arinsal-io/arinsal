//! Port of the x86 `BeamModuleAssembler` state and patch sites: `BeamModuleAssemblerCommon`
//! of erts/emulator/beam/jit/beam_jit_common.hpp (rawLabels, patch lists), the constructor
//! of erts/emulator/beam/jit/beam_jit_common.cpp (label creation) and
//! erts/emulator/beam/jit/x86/beam_asm.hpp (make_move_patch, make_word_patch,
//! resolve_beam_label), OTP-29.1.1.

use std::collections::HashMap;

use arinsal_x64::buf::Label;
use arinsal_x64::enc::Gp;

use super::beam_asm::{AsmError, BeamAssembler};

/// `struct patch`: a word in the code to fill in once the value is known, `ptr_offs` bytes
/// after the label `where`, with `val_offs` added to the value.
// Port of erts/emulator/beam/jit/beam_jit_common.hpp:141-145 (struct patch), OTP-29.1.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Patch {
    /// `where`.
    pub at: Label,
    /// `ptr_offs`.
    pub ptr_offs: usize,
    /// `val_offs`.
    pub val_offs: usize,
}

/// erts `class BeamModuleAssembler : public BeamAssembler, public BeamModuleAssemblerCommon`.
// Port of erts/emulator/beam/jit/x86/beam_asm.hpp:1130-1875 and
// erts/emulator/beam/jit/beam_jit_common.hpp:130-198 (BeamModuleAssemblerCommon), OTP-29.1.1.
#[derive(Debug)]
pub struct BeamModuleAssembler {
    /// The `BeamAssembler` base.
    pub asm: BeamAssembler,
    /// `rawLabels`: the asmjit label of every BEAM label `1..num_labels`.
    raw_labels: HashMap<u32, Label>,
    /// `imports[index].patches`.
    pub imports: HashMap<u32, Vec<Patch>>,
    /// `lambdas[index].patches`.
    pub lambdas: HashMap<u32, Vec<Patch>>,
    /// `literals[index].patches`.
    pub literals: HashMap<u32, Vec<Patch>>,
    /// `strings`: every string patch.
    pub strings: Vec<Patch>,
}

impl BeamModuleAssembler {
    /// A module assembler for `num_labels` BEAM labels, unnamed as when no assembly dump is
    /// requested.
    // Port of erts/emulator/beam/jit/beam_jit_common.cpp:275-355
    // (BeamModuleAssembler::BeamModuleAssembler, the unnamed-label branch), OTP-29.1.1.
    pub fn new(num_labels: u32) -> Self {
        let mut asm = BeamAssembler::new();
        let raw_labels = (1..num_labels).map(|i| (i, asm.new_label())).collect();
        Self {
            asm,
            raw_labels,
            imports: HashMap::new(),
            lambdas: HashMap::new(),
            literals: HashMap::new(),
            strings: Vec::new(),
        }
    }

    /// `resolve_beam_label(Lbl)`: `rawLabels.at(Lbl)`.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:1529-1531 (resolve_beam_label),
    // OTP-29.1.1.
    pub fn resolve_beam_label(&self, label: u32) -> Option<Label> {
        self.raw_labels.get(&label).copied()
    }

    /// `make_move_patch(to, patches, offset)`: a `mov to, imm64` whose 8-byte payload is
    /// patched with the value later.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:1555-1565 (make_move_patch), OTP-29.1.1.
    pub fn make_move_patch(
        asm: &mut BeamAssembler,
        to: Gp,
        patches: &mut Vec<Patch>,
        offset: usize,
    ) -> Result<(), AsmError> {
        const MOV_IMM64_PAYLOAD_OFFSET: usize = 2;
        let label = asm.new_label();
        asm.bind(label)?;
        // `a.long_().mov(to, imm(LLONG_MAX))`: LLONG_MAX fits neither imm32 form, so this is
        // the 10-byte `REX.W B8+r imm64`.
        asm.emit(|e| e.mov_ri(to.r64(), i64::MAX))?;
        patches.push(Patch {
            at: label,
            ptr_offs: MOV_IMM64_PAYLOAD_OFFSET,
            val_offs: offset,
        });
        Ok(())
    }

    /// `make_word_patch(patches)`: an embedded word patched with the value later.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:1567-1574 (make_word_patch), OTP-29.1.1.
    pub fn make_word_patch(
        asm: &mut BeamAssembler,
        patches: &mut Vec<Patch>,
    ) -> Result<(), AsmError> {
        let label = asm.new_label();
        asm.bind(label)?;
        asm.a.append_u64(i64::MAX as u64);
        patches.push(Patch {
            at: label,
            ptr_offs: 0,
            val_offs: 0,
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x86::beam_asm::register::{ARG1, ARG4};
    use arinsal_x64::buf::Section;

    #[test]
    fn labels_cover_beam_labels() {
        let m = BeamModuleAssembler::new(5);
        assert!(m.resolve_beam_label(0).is_none());
        assert!(m.resolve_beam_label(4).is_some());
        assert!(m.resolve_beam_label(5).is_none());
    }

    #[test]
    fn move_and_word_patches() {
        let mut m = BeamModuleAssembler::new(1);
        let mut patches = Vec::new();
        BeamModuleAssembler::make_move_patch(&mut m.asm, ARG4, &mut patches, 3).unwrap();
        BeamModuleAssembler::make_word_patch(&mut m.asm, &mut patches).unwrap();
        BeamModuleAssembler::make_move_patch(&mut m.asm, ARG1.r32(), &mut patches, 0).unwrap();
        let code = m.asm.a.bytes(Section::Code);
        // movabs rcx, 0x7fffffffffffffff; .quad 0x7fff...; movabs rdi, 0x7fff...
        let max = i64::MAX.to_le_bytes();
        assert_eq!(&code[..2], &[0x48, 0xb9]);
        assert_eq!(&code[2..10], &max);
        assert_eq!(&code[10..18], &max);
        assert_eq!(&code[18..20], &[0x48, 0xbf]);
        assert_eq!(code.len(), 28);
        let at = |p: &Patch| m.asm.a.label_location(p.at).unwrap().offset;
        assert_eq!(
            patches
                .iter()
                .map(|p| (at(p), p.ptr_offs, p.val_offs))
                .collect::<Vec<_>>(),
            [(0, 2, 3), (10, 0, 0), (18, 2, 0)]
        );
    }
}
