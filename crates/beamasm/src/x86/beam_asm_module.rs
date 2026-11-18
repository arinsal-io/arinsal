//! Port of the x86 `BeamModuleAssembler` state and patch sites: `BeamModuleAssemblerCommon`
//! of erts/emulator/beam/jit/beam_jit_common.hpp (rawLabels, patch lists), the constructor
//! of erts/emulator/beam/jit/beam_jit_common.cpp (label creation) and
//! erts/emulator/beam/jit/x86/beam_asm.hpp (make_move_patch, make_word_patch,
//! resolve_beam_label), OTP-29.1.1.

use std::collections::HashMap;

use arinsal_x64::buf::Label;
use arinsal_x64::enc::{Gp, Mem, MemBase};

use super::beam_asm::register::{ARG1, ARG3, ARG4, ARG5, ARG6, E, REGISTERS, RET, TMP1, TMP2};
use super::beam_asm::{AsmError, BeamAssembler, Distance, get_arg_ref};
use crate::common::args::ArgVal;
use crate::common::register_cache::{CacheMem, RegisterCache};

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
    /// `literals[index].patches`. Arinsal's [`ArgVal::Literal`] carries the literal's term,
    /// so the patches are keyed by that term, the value they are filled with.
    pub literals: HashMap<u64, Vec<Patch>>,
    /// `strings`: every string patch.
    pub strings: Vec<Patch>,
    /// `reg_cache`: `RegisterCache<20, x86::Mem, x86::Gp>` over X slots from `registers` and
    /// Y slots from `E`. ARG2 is excluded as it points to the currently active tuple.
    reg_cache: RegisterCache<20, Mem, Gp>,
    /// `_dispatchTable`: the module-local label of every global fragment called, bound to a
    /// thunk jumping to the fragment.
    dispatch_table: HashMap<usize, Label>,
    /// `last_error_offset`: the last code offset that may raise.
    pub last_error_offset: usize,
}

// Port of erts/emulator/beam/jit/x86/beam_asm.hpp:1137-1142 (reg_cache), OTP-29.1.1.
impl CacheMem<Gp> for Mem {
    fn base_reg(&self) -> Option<Gp> {
        match self.base {
            Some(MemBase::Gp(base)) => Some(base),
            _ => None,
        }
    }

    /// `entry.mem.clone_adjusted(-bytes)`: erts keeps every Y entry, renumbered.
    fn trimmed(&self, bytes: u32) -> Option<Self> {
        Some(self.adjusted(-(bytes as i32)))
    }
}

/// asmjit `Support::is_int_n<32>`.
const fn is_int32(value: i64) -> bool {
    value as i32 as i64 == value
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
            reg_cache: RegisterCache::with_temporaries(
                REGISTERS,
                E,
                &[TMP1, TMP2, ARG3, ARG4, ARG5, ARG6, ARG1, RET],
            ),
            dispatch_table: HashMap::new(),
            last_error_offset: 0,
        }
    }

    fn offset(&self) -> usize {
        self.asm.a.offset()
    }

    /// `find_cache(mem)`.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:1144-1146 (find_cache), OTP-29.1.1.
    pub fn find_cache(&mut self, mem: Mem) -> Option<Gp> {
        let offset = self.offset();
        self.reg_cache.find(offset, mem)
    }

    /// `store_cache(src, mem_dst)`: stores a register and records it in the cache.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:1148-1154 (store_cache), OTP-29.1.1.
    pub fn store_cache(&mut self, src: Gp, mem_dst: Mem) -> Result<(), AsmError> {
        let offset = self.offset();
        self.reg_cache.consolidate(offset);
        self.asm.emit(|e| e.mov_mr(mem_dst, src))?;
        self.reg_cache.put(mem_dst, src);
        let offset = self.offset();
        self.reg_cache.update(offset);
        Ok(())
    }

    /// `load_cached(dst, mem)`: loads a BEAM register, reusing a cached copy.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:1156-1176 (load_cached), OTP-29.1.1.
    pub fn load_cached(&mut self, dst: Gp, mem: Mem) -> Result<(), AsmError> {
        match self.find_cache(mem) {
            Some(cached) if cached == dst => {}
            Some(cached) => {
                self.asm.emit(|e| e.mov_rr(dst, cached))?;
                self.reg_cache.invalidate_reg(dst);
                let offset = self.offset();
                self.reg_cache.update(offset);
            }
            None => {
                self.asm.emit(|e| e.mov_rm(dst, mem))?;
                self.reg_cache.invalidate_reg(dst);
                self.reg_cache.put(mem, dst);
                let offset = self.offset();
                self.reg_cache.update(offset);
            }
        }
        Ok(())
    }

    /// `preserve_cache(generate, clobber...)`: runs `generate`, which leaves the cached
    /// registers intact except `regs` and the slots `mems`, and keeps the cache valid across
    /// it if it was valid before.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:1178-1191 (preserve_cache), OTP-29.1.1.
    pub fn preserve_cache<T>(
        &mut self,
        regs: &[Gp],
        mems: &[Mem],
        generate: impl FnOnce(&mut Self) -> Result<T, AsmError>,
    ) -> Result<T, AsmError> {
        let valid = self.reg_cache.valid_at(self.offset());
        let result = generate(self)?;
        if valid {
            for reg in regs {
                self.reg_cache.invalidate_reg(*reg);
            }
            for mem in mems {
                self.reg_cache.invalidate_slot(*mem);
            }
            let offset = self.offset();
            self.reg_cache.update(offset);
        }
        Ok(result)
    }

    /// `trim_preserve_cache(Words)`: drops `words` from the frame, renumbering cached Y slots.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:1193-1202 (trim_preserve_cache),
    // OTP-29.1.1.
    pub fn trim_preserve_cache(&mut self, words: u32) -> Result<(), AsmError> {
        if words > 0 {
            assert!(words <= 1023);
            self.preserve_cache(&[], &[], |m| {
                let bytes = words * 8;
                m.asm.emit(|e| e.add_ri(E, i64::from(bytes)))?;
                m.reg_cache.trim_yregs(bytes);
                Ok(())
            })?;
        }
        Ok(())
    }

    /// `mov_preserve_cache(Mem dst, Gp src)`.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:1204-1210, OTP-29.1.1.
    pub fn mov_preserve_cache_store(&mut self, dst: Mem, src: Gp) -> Result<(), AsmError> {
        self.preserve_cache(&[], &[dst], |m| m.asm.emit(|e| e.mov_mr(dst, src)))
    }

    /// `mov_preserve_cache(Gp dst, Gp src)`.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:1212-1218, OTP-29.1.1.
    pub fn mov_preserve_cache_rr(&mut self, dst: Gp, src: Gp) -> Result<(), AsmError> {
        self.preserve_cache(&[dst], &[], |m| m.asm.emit(|e| e.mov_rr(dst, src)))
    }

    /// `mov_preserve_cache(Gp dst, Mem src)`.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:1220-1226, OTP-29.1.1.
    pub fn mov_preserve_cache_load(&mut self, dst: Gp, src: Mem) -> Result<(), AsmError> {
        self.preserve_cache(&[dst], &[], |m| m.asm.emit(|e| e.mov_rm(dst, src)))
    }

    /// `cmp_preserve_cache(Gp, Gp)`.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:1228-1232, OTP-29.1.1.
    pub fn cmp_preserve_cache_rr(&mut self, reg1: Gp, reg2: Gp) -> Result<(), AsmError> {
        self.preserve_cache(&[], &[], |m| m.asm.emit(|e| e.cmp_rr(reg1, reg2)))
    }

    /// `cmp_preserve_cache(Mem, Gp)`.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:1234-1238, OTP-29.1.1.
    pub fn cmp_preserve_cache_mr(&mut self, mem: Mem, reg: Gp) -> Result<(), AsmError> {
        self.preserve_cache(&[], &[], |m| m.asm.emit(|e| e.cmp_mr(mem, reg)))
    }

    /// `alloc_temp_reg()`: a temporary register, preferring one not in the cache.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:1240-1244 (alloc_temp_reg), OTP-29.1.1.
    pub fn alloc_temp_reg(&mut self) -> Gp {
        let offset = self.offset();
        self.reg_cache.allocate(offset)
    }

    /// `resolve_fragment(fragment)`: the module-local label standing for a global fragment;
    /// the thunk behind it is emitted with the module's dispatch table.
    // Port of erts/emulator/beam/jit/x86/beam_asm_module.cpp:576-584 (resolve_fragment),
    // OTP-29.1.1.
    pub fn resolve_fragment(&mut self, fragment: usize) -> Label {
        let asm = &mut self.asm;
        *self
            .dispatch_table
            .entry(fragment)
            .or_insert_with(|| asm.new_label())
    }

    /// `emit_is_boxed(Fail, Src, dist)` keeping the register cache.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:1324-1328 (emit_is_boxed), OTP-29.1.1.
    pub fn emit_is_boxed(&mut self, fail: Label, src: Gp, dist: Distance) -> Result<(), AsmError> {
        self.preserve_cache(&[], &[], |m| m.asm.emit_is_boxed(fail, src, dist))
    }

    /// `emit_is_cons(Fail, Src, dist)` keeping the register cache.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:1344-1353 (emit_is_cons), OTP-29.1.1.
    pub fn emit_is_cons(&mut self, fail: Label, src: Gp, dist: Distance) -> Result<(), AsmError> {
        self.preserve_cache(&[], &[], |m| m.asm.emit_is_cons(fail, src, dist))
    }

    /// `emit_is_not_cons(Fail, Src, dist)` keeping the register cache.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:1355-1364 (emit_is_not_cons),
    // OTP-29.1.1.
    pub fn emit_is_not_cons(
        &mut self,
        fail: Label,
        src: Gp,
        dist: Distance,
    ) -> Result<(), AsmError> {
        self.preserve_cache(&[], &[], |m| m.asm.emit_is_not_cons(fail, src, dist))
    }

    fn arg_ref(arg: ArgVal) -> Result<Mem, AsmError> {
        get_arg_ref(arg, 8).ok_or(AsmError::Operand("BEAM register operand"))
    }

    /// `mov_arg(Gp to, ArgVal from, spill)`; may clear flags.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:1672-1719 (mov_arg), OTP-29.1.1.
    pub fn mov_arg_to_reg(&mut self, to: Gp, from: ArgVal) -> Result<(), AsmError> {
        match from {
            ArgVal::Export(index) => {
                let mut patches = self.imports.remove(&index).unwrap_or_default();
                let result = Self::make_move_patch(&mut self.asm, to, &mut patches, 0);
                self.imports.insert(index, patches);
                result
            }
            ArgVal::Immediate(value) => {
                self.preserve_cache(&[to], &[], |m| m.asm.mov_imm(to, value))
            }
            ArgVal::Literal(term) => self.preserve_cache(&[to], &[], |m| {
                let mut patches = m.literals.remove(&term).unwrap_or_default();
                let result = Self::make_move_patch(&mut m.asm, to, &mut patches, 0);
                m.literals.insert(term, patches);
                result
            }),
            ArgVal::X(_) | ArgVal::Y(_) => {
                let mem = Self::arg_ref(from)?;
                self.load_cached(to, mem)
            }
            ArgVal::Label(_) => Err(AsmError::Operand("mov_arg with incompatible type")),
        }
    }

    /// `mov_arg(Mem to, ArgVal from, spill)`.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:1721-1762 (mov_arg), OTP-29.1.1.
    pub fn mov_arg_to_mem(&mut self, to: Mem, from: ArgVal, spill: Gp) -> Result<(), AsmError> {
        match from {
            ArgVal::Immediate(value) if is_int32(value as i64) => {
                self.preserve_cache(&[], &[to], |m| m.asm.emit(|e| e.mov_mi(to, value as i64)))
            }
            ArgVal::Immediate(value) => self.preserve_cache(&[spill], &[to], |m| {
                m.asm.emit(|e| e.mov_ri(spill, value as i64))?;
                m.asm.emit(|e| e.mov_mr(to, spill))
            }),
            _ => {
                self.mov_arg_to_reg(spill, from)?;
                self.mov_preserve_cache_store(to, spill)
            }
        }
    }

    /// `mov_arg(ArgRegister to, Gp from, spill)`: stores and caches.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:1764-1769 (mov_arg), OTP-29.1.1.
    pub fn mov_arg_from_reg(&mut self, to: ArgVal, from: Gp) -> Result<(), AsmError> {
        let mem = Self::arg_ref(to)?;
        self.store_cache(from, mem)
    }

    /// `mov_arg(ArgRegister to, Mem from, spill)`.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:1771-1774 (mov_arg), OTP-29.1.1.
    pub fn mov_arg_from_mem(&mut self, to: ArgVal, from: Mem, spill: Gp) -> Result<(), AsmError> {
        let mem = Self::arg_ref(to)?;
        self.asm.emit(|e| e.mov_rm(spill, from))?;
        self.asm.emit(|e| e.mov_mr(mem, spill))
    }

    /// `mov_arg(ArgRegister to, BeamInstr from, spill)`.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:1776-1788 (mov_arg), OTP-29.1.1.
    pub fn mov_arg_word(&mut self, to: ArgVal, from: u64, spill: Gp) -> Result<(), AsmError> {
        let mem = Self::arg_ref(to)?;
        self.preserve_cache(&[spill], &[mem], |m| {
            if is_int32(from as i64) {
                m.asm.emit(|e| e.mov_mi(mem, from as i64))
            } else {
                m.asm.emit(|e| e.mov_ri(spill, from as i64))?;
                m.mov_arg_from_reg(to, spill)
            }
        })
    }

    /// `mov_arg(ArgRegister to, ArgVal from, spill)`.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:1790-1806 (mov_arg), OTP-29.1.1.
    pub fn mov_arg(&mut self, to: ArgVal, from: ArgVal, spill: Gp) -> Result<(), AsmError> {
        if !matches!(from, ArgVal::X(_) | ArgVal::Y(_)) {
            let mem = Self::arg_ref(to)?;
            return self.mov_arg_to_mem(mem, from, ARG1);
        }
        let from_reg = match self.find_cache(Self::arg_ref(from)?) {
            Some(cached) => cached,
            None => {
                self.mov_arg_to_reg(spill, from)?;
                spill
            }
        };
        self.mov_arg_from_reg(to, from_reg)
    }

    /// `cmp_arg(Mem, val, spill)`.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:1591-1624 (cmp_arg), OTP-29.1.1.
    pub fn cmp_arg_mem(&mut self, mem: Mem, val: ArgVal, spill: Gp) -> Result<(), AsmError> {
        let imm32 = match val {
            ArgVal::Immediate(value) if is_int32(value as i64) => Some(value as i64),
            _ => None,
        };
        match (self.find_cache(mem), imm32) {
            (Some(reg), Some(imm)) => {
                self.preserve_cache(&[], &[], |m| m.asm.emit(|e| e.cmp_ri(reg, imm)))
            }
            (Some(reg), None) if reg != spill => {
                self.mov_arg_to_reg(spill, val)?;
                self.cmp_preserve_cache_rr(reg, spill)
            }
            (None, Some(imm)) => {
                self.preserve_cache(&[], &[], |m| m.asm.emit(|e| e.cmp_mi(mem, imm)))
            }
            _ => {
                self.mov_arg_to_reg(spill, val)?;
                self.cmp_preserve_cache_mr(mem, spill)
            }
        }
    }

    /// `cmp_arg(Gp, val, spill)`.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:1626-1636 (cmp_arg), OTP-29.1.1.
    pub fn cmp_arg_reg(&mut self, gp: Gp, val: ArgVal, spill: Gp) -> Result<(), AsmError> {
        match val {
            ArgVal::Immediate(value) if is_int32(value as i64) => {
                self.preserve_cache(&[], &[], |m| m.asm.emit(|e| e.cmp_ri(gp, value as i64)))
            }
            _ => {
                self.mov_arg_to_reg(spill, val)?;
                self.cmp_preserve_cache_rr(gp, spill)
            }
        }
    }

    /// `cmp(gp, val, spill)`.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:1638-1652 (cmp), OTP-29.1.1.
    pub fn cmp(&mut self, gp: Gp, val: i64, spill: Gp) -> Result<(), AsmError> {
        if is_int32(val) {
            self.preserve_cache(&[], &[], |m| m.asm.emit(|e| e.cmp_ri(gp, val)))
        } else if gp.size() == 4 {
            self.asm.mov_imm(spill, val as u64)?;
            self.preserve_cache(&[], &[], |m| m.asm.emit(|e| e.cmp_rr(gp, spill.r32())))
        } else {
            self.asm.mov_imm(spill, val as u64)?;
            self.cmp_preserve_cache_rr(gp, spill)
        }
    }

    /// `sub(gp, val, spill)`.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:1654-1670 (sub), OTP-29.1.1.
    pub fn sub(&mut self, gp: Gp, val: i64, spill: Gp) -> Result<(), AsmError> {
        if is_int32(val) {
            self.preserve_cache(&[gp], &[], |m| m.asm.emit(|e| e.sub_ri(gp, val)))
        } else {
            self.preserve_cache(&[gp, spill], &[], |m| {
                m.asm.mov_imm(spill, val as u64)?;
                m.asm.emit(|e| e.sub_rr(gp, spill))
            })
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
