//! Port of erts/emulator/beam/jit/beam_jit_register_cache.hpp (`RegisterCache<Size, Mem,
//! Reg>`), OTP-29.1.1: which temporary register still holds the value of an X register slot
//! in the scheduler array or of a Y slot on the stack. Each emitter instantiates it with its
//! own memory operand, register type and base registers.

/// The memory operand a cache entry is keyed by (`Mem` of the template): its base register
/// and the operand after `bytes` are dropped from the top of the frame (`trim_yregs`).
pub(crate) trait CacheMem<Reg>: Copy + Eq {
    /// `mem.base_reg()`; `None` without a base register (`!mem.has_base()`).
    fn base_reg(&self) -> Option<Reg>;
    /// The Y operand once `bytes` have been removed from the top of the frame, or `None`
    /// when the slot no longer exists.
    fn trimmed(&self, bytes: u32) -> Option<Self>;
}

/// erts `RegisterCache<Size, Mem, Reg>`. `position` is the code position the cache is valid
/// at (`size_t position`; `None` is erts' `SIZE_MAX`): any lookup at another position drops
/// the cache first.
// Port of erts/emulator/beam/jit/beam_jit_register_cache.hpp:29-223 (RegisterCache),
// OTP-29.1.1.
#[derive(Debug)]
pub(crate) struct RegisterCache<const SIZE: usize, M, Reg, P = usize> {
    /// `cache[0..entries]`.
    pub(crate) entries: Vec<(M, Reg)>,
    /// `position`.
    pub(crate) position: Option<P>,
    /// `temporaries`, in preference order.
    temporaries: Vec<Reg>,
    xregs_base: Reg,
    yregs_base: Reg,
}

impl<const SIZE: usize, M: CacheMem<Reg>, Reg: Copy + Eq, P: Copy + Eq>
    RegisterCache<SIZE, M, Reg, P>
{
    /// `RegisterCache(xregs, yregs, tmps)`: [`Self::allocate`] picks from `tmps`.
    // Port of beam_jit_register_cache.hpp:66-70 (RegisterCache::RegisterCache), OTP-29.1.1.
    pub(crate) fn with_temporaries(xregs: Reg, yregs: Reg, tmps: &[Reg]) -> Self {
        Self {
            entries: Vec::with_capacity(SIZE),
            position: None,
            temporaries: tmps.to_vec(),
            xregs_base: xregs,
            yregs_base: yregs,
        }
    }

    // Port of beam_jit_register_cache.hpp:58-62 (isCached), OTP-29.1.1.
    fn is_cached(&self, reg: Reg) -> bool {
        self.entries.iter().any(|(_, cached)| *cached == reg)
    }

    /// `consolidate(offset)`: drops the cache unless it is valid at `offset`, then pins it
    /// there.
    // Port of beam_jit_register_cache.hpp:72-78 (consolidate), OTP-29.1.1.
    pub(crate) fn consolidate(&mut self, offset: P) {
        if !self.valid_at(offset) {
            self.invalidate_all();
        }
        self.position = Some(offset);
    }

    /// `find(offset, mem)`: the register holding `mem` at `offset`.
    // Port of beam_jit_register_cache.hpp:80-94 (find), OTP-29.1.1.
    pub(crate) fn find(&mut self, offset: P, mem: M) -> Option<Reg> {
        self.consolidate(offset);
        self.entries
            .iter()
            .find(|(cached, _)| *cached == mem)
            .map(|(_, reg)| *reg)
    }

    /// `invalidate()`.
    // Port of beam_jit_register_cache.hpp:130-133 (invalidate), OTP-29.1.1.
    pub(crate) fn invalidate_all(&mut self) {
        self.position = None;
        self.entries.clear();
    }

    /// `invalidate(Mem)`: the last entry takes the removed entry's place.
    // Port of beam_jit_register_cache.hpp:96-112 (invalidate(Mem)), OTP-29.1.1.
    pub(crate) fn invalidate_slot(&mut self, slot: M) {
        if let Some(index) = self.entries.iter().position(|(mem, _)| *mem == slot) {
            self.entries.swap_remove(index);
        }
    }

    /// `invalidate(Reg)`.
    // Port of beam_jit_register_cache.hpp:114-128 (invalidate(Reg)), OTP-29.1.1.
    pub(crate) fn invalidate_reg(&mut self, reg: Reg) {
        let mut index = 0;
        while index < self.entries.len() {
            if self.entries[index].1 == reg {
                self.entries.swap_remove(index);
            } else {
                index += 1;
            }
        }
    }

    /// `trim_yregs(-bytes)`: renumbers the cached Y slots after `bytes` are dropped from the
    /// frame.
    // Port of beam_jit_register_cache.hpp:135-143 (trim_yregs), OTP-29.1.1.
    pub(crate) fn trim_yregs(&mut self, bytes: u32) {
        let yregs_base = self.yregs_base;
        self.entries.retain_mut(|(slot, _)| {
            if slot.base_reg() != Some(yregs_base) {
                return true;
            }
            match slot.trimmed(bytes) {
                Some(trimmed) => {
                    *slot = trimmed;
                    true
                }
                None => false,
            }
        });
    }

    /// `allocate(offset)`: a temporary register, preferring one not in the cache.
    // Port of beam_jit_register_cache.hpp:151-172 (allocate), OTP-29.1.1.
    pub(crate) fn allocate(&mut self, offset: P) -> Reg {
        self.consolidate(offset);
        match self.temporaries.iter().find(|reg| !self.is_cached(**reg)) {
            Some(reg) => *reg,
            None => self.temporaries[0],
        }
    }

    /// `put(mem, reg)`: only X and Y slots are cached; a full cache replaces its first entry.
    // Port of beam_jit_register_cache.hpp:174-203 (put), OTP-29.1.1.
    pub(crate) fn put(&mut self, slot: M, reg: Reg) {
        let Some(base) = slot.base_reg() else {
            return;
        };
        if base != self.xregs_base && base != self.yregs_base {
            return;
        }
        if let Some(entry) = self.entries.iter_mut().find(|(mem, _)| *mem == slot) {
            entry.1 = reg;
        } else if self.entries.len() == SIZE {
            self.entries[0] = (slot, reg);
        } else {
            self.entries.push((slot, reg));
        }
    }

    /// `validAt(offset)`.
    // Port of beam_jit_register_cache.hpp:205-207 (validAt), OTP-29.1.1.
    pub(crate) fn valid_at(&self, offset: P) -> bool {
        self.position == Some(offset)
    }

    /// `update(offset)`.
    // Port of beam_jit_register_cache.hpp:209-211 (update), OTP-29.1.1.
    pub(crate) fn update(&mut self, offset: P) {
        self.position = Some(offset);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct Slot {
        base: u8,
        offset: u32,
    }

    impl CacheMem<u8> for Slot {
        fn base_reg(&self) -> Option<u8> {
            Some(self.base)
        }

        fn trimmed(&self, bytes: u32) -> Option<Self> {
            self.offset.checked_sub(bytes).map(|offset| Slot {
                base: self.base,
                offset,
            })
        }
    }

    type Cache = RegisterCache<2, Slot, u8>;

    #[test]
    fn erts_cache_semantics() {
        let mut cache = Cache::with_temporaries(1, 2, &[10, 11, 12]);
        let x0 = Slot { base: 1, offset: 0 };
        let y1 = Slot { base: 2, offset: 8 };
        assert_eq!(cache.find(0, x0), None);
        cache.put(x0, 10);
        cache.put(Slot { base: 9, offset: 0 }, 11);
        assert_eq!(cache.entries.len(), 1);
        cache.update(4);
        assert_eq!(cache.find(4, x0), Some(10));
        assert_eq!(cache.allocate(4), 11);
        // Any other position drops the cache.
        assert_eq!(cache.find(5, x0), None);
        cache.put(x0, 10);
        cache.put(y1, 11);
        cache.put(Slot { base: 1, offset: 8 }, 12);
        assert_eq!(cache.entries[0], (Slot { base: 1, offset: 8 }, 12));
        assert_eq!(cache.allocate(5), 10);
        cache.trim_yregs(8);
        assert_eq!(cache.entries[1], (Slot { base: 2, offset: 0 }, 11));
        cache.invalidate_reg(12);
        assert_eq!(cache.entries, [(Slot { base: 2, offset: 0 }, 11)]);
        assert!(cache.valid_at(5));
        cache.invalidate_all();
        assert!(!cache.valid_at(5));
    }
}
