//! Port of erts/emulator/beam/jit/beam_jit_register_cache.hpp (`RegisterCache<Size, Mem,
//! Reg>`), OTP-29.1.1: which temporary register still holds the value of an X register slot
//! in the scheduler array or of a Y slot on the stack. Each emitter instantiates it with its
//! own register type and base registers.

/// Memory word whose value a register holds: base register and byte offset.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Slot<Reg> {
    pub(crate) base: Reg,
    pub(crate) offset: u32,
}

/// Port of erts/emulator/beam/jit/beam_jit_register_cache.hpp (RegisterCache<16, Mem, Gp>),
/// OTP-29.1.1. The cache is valid only at the code position and label count it was last
/// updated at: emitting any instruction outside the cache-aware helpers, or binding a label,
/// drops it on the next lookup.
#[derive(Debug)]
pub(crate) struct RegCache<const SIZE: usize, Reg> {
    pub(crate) entries: Vec<(Slot<Reg>, Reg)>,
    pub(crate) position: Option<(usize, u64)>,
    xregs_base: Reg,
    yregs_base: Reg,
}

impl<const SIZE: usize, Reg: Copy + Eq> RegCache<SIZE, Reg> {
    /// An empty cache over X slots addressed from `xregs` and Y slots from `yregs`.
    // Port of beam_jit_register_cache.hpp (RegisterCache::RegisterCache), OTP-29.1.1.
    pub(crate) fn new(xregs: Reg, yregs: Reg) -> Self {
        Self {
            entries: Vec::new(),
            position: None,
            xregs_base: xregs,
            yregs_base: yregs,
        }
    }

    pub(crate) fn invalidate_all(&mut self) {
        self.position = None;
        self.entries.clear();
    }

    pub(crate) fn invalidate_slot(&mut self, slot: Slot<Reg>) {
        if let Some(index) = self.entries.iter().position(|(mem, _)| *mem == slot) {
            self.entries.swap_remove(index);
        }
    }

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

    pub(crate) fn trim_yregs(&mut self, bytes: u32) {
        self.entries.retain_mut(|(slot, _)| {
            if slot.base != self.yregs_base {
                return true;
            }
            match slot.offset.checked_sub(bytes) {
                Some(offset) => {
                    slot.offset = offset;
                    true
                }
                None => false,
            }
        });
    }

    pub(crate) fn put(&mut self, slot: Slot<Reg>, reg: Reg) {
        if slot.base != self.xregs_base && slot.base != self.yregs_base {
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
}
