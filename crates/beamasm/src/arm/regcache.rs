//! Register cache of the BeamAsm module emitter: the arm instantiation of
//! erts/emulator/beam/jit/beam_jit_register_cache.hpp and the cache-aware load/store helpers
//! of erts/emulator/beam/jit/arm/beam_asm.hpp, OTP-29.1.1.

use arinsal_a64::enc::Gpr;

use crate::module::{BeamModuleAssembler, ModuleError};

const SUPER_TMP: Gpr = Gpr::x(17);
const CACHE_SIZE: usize = 16;

/// `RegisterCache<16, a64::Mem, a64::Gp>` of erts/emulator/beam/jit/arm/beam_asm.hpp, keyed
/// by [`Slot`] and pinned to the code offset and the number of labels bound.
pub(crate) type RegCache =
    crate::common::register_cache::RegisterCache<CACHE_SIZE, Slot, Gpr, (usize, u64)>;

/// The `a64::Mem` operand the cache is keyed by: base register and byte offset.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Slot {
    pub(crate) base: Gpr,
    pub(crate) offset: u32,
}

impl crate::common::register_cache::CacheMem<Gpr> for Slot {
    fn base_reg(&self) -> Option<Gpr> {
        Some(self.base)
    }

    fn trimmed(&self, bytes: u32) -> Option<Self> {
        self.offset.checked_sub(bytes).map(|offset| Slot {
            base: self.base,
            offset,
        })
    }
}

impl RegCache {
    /// An empty cache over X slots addressed from `xregs` and Y slots from `yregs`, with no
    /// temporaries to allocate from.
    // Port of beam_jit_register_cache.hpp:66-70 (RegisterCache::RegisterCache), OTP-29.1.1.
    pub(crate) fn new(xregs: Gpr, yregs: Gpr) -> Self {
        Self::with_temporaries(xregs, yregs, &[])
    }
}

impl BeamModuleAssembler {
    fn cache_here(&self) -> (usize, u64) {
        (self.code.offset(), self.code.bind_count())
    }

    /// Whether the cache describes the registers at the current code position.
    pub(crate) fn cache_valid(&self) -> bool {
        self.reg_cache.position == Some(self.cache_here())
    }

    /// Drops the cache unless it is valid at the current position, then pins it here.
    // Port of beam_jit_register_cache.hpp:64-70 (consolidate), OTP-29.1.1.
    pub(crate) fn cache_consolidate(&mut self) {
        if !self.cache_valid() {
            self.reg_cache.invalidate_all();
        }
        self.reg_cache.position = Some(self.cache_here());
    }

    /// Declares the cache valid after the instructions emitted so far.
    // Port of beam_jit_register_cache.hpp:218-220 (update), OTP-29.1.1.
    pub(crate) fn cache_update(&mut self) {
        self.reg_cache.position = Some(self.cache_here());
    }

    /// Removes `words` from the top of the frame and renumbers the cached Y slots, keeping the
    /// cache valid if it was valid before.
    // Port of erts/emulator/beam/jit/arm/beam_asm.hpp:1052-1063 (trim_preserve_cache) and
    // beam_jit_register_cache.hpp (trim_yregs), OTP-29.1.1.
    pub(crate) fn trim_preserve_cache(&mut self, words: u32) -> Result<(), ModuleError> {
        if words == 0 {
            return Ok(());
        }
        let valid = self.cache_valid();
        self.deallocate(words)?;
        if valid {
            self.reg_cache.trim_yregs(words * 8);
            self.cache_update();
        }
        Ok(())
    }

    /// Forgets the entries that live in `reg`.
    pub(crate) fn cache_invalidate_reg(&mut self, reg: Gpr) {
        self.reg_cache.invalidate_reg(reg);
    }

    /// The register that currently holds `slot`, if any.
    // Port of beam_jit_register_cache.hpp:72-87 (find), OTP-29.1.1.
    pub(crate) fn cache_find(&mut self, slot: Slot) -> Option<Gpr> {
        self.cache_consolidate();
        self.reg_cache
            .entries
            .iter()
            .find(|(mem, _)| *mem == slot)
            .map(|(_, reg)| *reg)
    }

    // Port of beam_asm.hpp:982-988 (reg_cache_put), OTP-29.1.1.
    fn cache_put(&mut self, slot: Slot, reg: Gpr) {
        if reg == SUPER_TMP {
            self.reg_cache.invalidate_slot(slot);
        } else {
            self.reg_cache.put(slot, reg);
        }
    }

    /// Runs `generate`, which emits instructions that leave the cached registers intact except
    /// `clobber`, and keeps the cache valid across them if it was valid before.
    // Port of beam_asm.hpp:1046-1059 (preserve_cache), OTP-29.1.1.
    pub(crate) fn preserve_cache<T>(
        &mut self,
        clobber: &[Gpr],
        generate: impl FnOnce(&mut Self) -> Result<T, ModuleError>,
    ) -> Result<T, ModuleError> {
        let valid = self.cache_valid();
        let result = generate(self)?;
        if valid {
            for reg in clobber {
                self.reg_cache.invalidate_reg(*reg);
            }
            self.cache_update();
        }
        Ok(result)
    }

    /// `ldr` that looks in the cache first.
    // Port of beam_asm.hpp:1023-1045 (ldr_cached), OTP-29.1.1.
    pub(crate) fn ldr_cached(&mut self, dst: Gpr, slot: Slot) -> Result<(), ModuleError> {
        match self.cache_find(slot) {
            Some(reg) if reg == dst => {}
            Some(reg) => {
                self.code.emit(|e| e.mov_reg(dst, reg))?;
                self.reg_cache.invalidate_reg(dst);
                self.cache_update();
            }
            None => {
                self.code
                    .emit(|e| e.ldr_uoff(dst, slot.base, slot.offset))?;
                self.reg_cache.invalidate_reg(dst);
                self.cache_put(slot, dst);
                self.cache_update();
            }
        }
        Ok(())
    }

    /// `str` that records the stored register in the cache.
    // Port of beam_asm.hpp:994-1003 (str_cache), OTP-29.1.1.
    pub(crate) fn str_cache(&mut self, src: Gpr, slot: Slot) -> Result<(), ModuleError> {
        self.cache_consolidate();
        self.reg_cache.invalidate_reg(src);
        self.code
            .emit(|e| e.str_uoff(src, slot.base, slot.offset))?;
        self.cache_put(slot, src);
        self.cache_update();
        Ok(())
    }

    /// `stp` that records both stored registers in the cache.
    // Port of beam_asm.hpp:1005-1021 (stp_cache), OTP-29.1.1.
    pub(crate) fn stp_cache(
        &mut self,
        first: Gpr,
        second: Gpr,
        base: Gpr,
        offset: u32,
    ) -> Result<(), ModuleError> {
        self.cache_consolidate();
        self.reg_cache.invalidate_reg(first);
        self.reg_cache.invalidate_reg(second);
        self.safe_stp(first, second, base, offset)?;
        self.cache_put(Slot { base, offset }, first);
        self.cache_put(
            Slot {
                base,
                offset: offset + 8,
            },
            second,
        );
        self.cache_update();
        Ok(())
    }
}
