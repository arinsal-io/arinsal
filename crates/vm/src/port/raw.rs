use std::alloc::Layout;
use std::sync::atomic::{AtomicU64, Ordering};

use arinsal_alloc::typed::{AllocBlock, ErtsAlcType};
use arinsal_sched::Scheduler;
use arinsal_term::{HeapAlloc, Term, TermError, copy_struct};

use crate::Process;

use super::PortDataBlock;

/// The atomic `prt->data` word: an immediate term or a pointer to its heap block.
pub(super) struct PortDataCell(AtomicU64);

impl PortDataCell {
    /// Create the cell with the port's initial immediate term.
    pub(super) const fn new(initial: u64) -> Self {
        Self(AtomicU64::new(initial))
    }

    /// Load an immediate value without copying a heap block.
    // Port of erts/emulator/beam/erl_bif_port.c:769 (`erts_port_data_read`), OTP-29.1.1.
    pub(super) fn load_immediate(&self) -> Option<Term> {
        let word = self.0.load(Ordering::Acquire);
        (word != 0 && word & 3 != 0)
            .then(|| Term::from_immed_word(word))
            .flatten()
    }

    /// Copy the current port data to the caller's process heap while the port-table lookup is
    /// protected by thread progress.
    // Port of erts/emulator/beam/erl_bif_port.c:743 (`port_get_data_1`), OTP-29.1.1.
    pub(super) fn copy_term(&self, heap: &mut impl HeapAlloc) -> Result<Term, TermError> {
        let word = self.0.load(Ordering::Acquire);
        if word == 0 {
            return Err(TermError::BadArg);
        }
        if word & 3 != 0 {
            return Term::from_immed_word(word).ok_or(TermError::BadArg);
        }
        let pointer = word as *const PortDataBlock;
        // SAFETY: `PortTable::with_from` keeps this managed-thread lookup in its thread-progress
        // section. Writers atomically exchange the word and defer freeing the old block until
        // every such lookup has passed a later thread-progress point, as erts does for port data.
        let block = unsafe { &*pointer };
        copy_struct(block.term, heap, block.hsize)
    }

    /// Atomically replace the immediate or heap-block pointer, matching `erts_atomic_xchg_wb`.
    // Port of erts/emulator/beam/erl_bif_port.c:720 (`port_set_data_2`), OTP-29.1.1.
    pub(super) fn swap(&self, new_word: u64) -> u64 {
        self.0.swap(new_word, Ordering::AcqRel)
    }
}

/// Allocate the header and copied words together, as `ErtsPortDataHeap` does.
// Port of erts/emulator/beam/erl_bif_port.c:704-716 (`port_set_data_2`), OTP-29.1.1.
pub(super) fn new_data_word(term: Term, hsize: usize) -> Result<u64, TermError> {
    let (layout, words_offset) = Layout::new::<PortDataBlock>()
        .extend(Layout::array::<std::mem::MaybeUninit<u64>>(hsize).map_err(|_| TermError::BadArg)?)
        .map_err(|_| TermError::BadArg)?;
    let layout = layout.pad_to_align();
    let allocation_words = layout.size() / std::mem::size_of::<u64>();
    let mut allocation = AllocBlock::new(ErtsAlcType::PORT_DATA_HEAP, allocation_words)
        .expect("port data heap allocation failed");
    let base = allocation.as_mut_slice().as_mut_ptr().cast::<u8>();
    let block = base.cast::<PortDataBlock>();
    // SAFETY: the allocation is aligned and large enough for the header and `hsize` trailing words.
    unsafe {
        block.write(PortDataBlock {
            term,
            hsize,
            _owners: arinsal_term::message::InlineHeapOwners::new(),
        });
    }
    // SAFETY: the computed offset lies within this allocation.
    let words = unsafe { base.add(words_offset) }.cast::<std::mem::MaybeUninit<u64>>();
    // SAFETY: `words` points to the trailing `hsize` slots in this live allocation.
    let words = unsafe { std::slice::from_raw_parts_mut(words, hsize) };
    // SAFETY: the owner header is exclusively borrowed while this block is being initialized.
    let owners = unsafe { &mut (*block)._owners };
    let copied = {
        let mut heap = arinsal_term::message::InlineHeapAlloc::new(words, owners);
        copy_struct(term, &mut heap, hsize)
    };
    match copied {
        Ok(copied) => {
            // SAFETY: this allocation remains exclusively owned until published in the atomic word.
            unsafe { (*block).term = copied };
            Ok(allocation.into_raw().as_ptr() as u64)
        }
        Err(error) => {
            // SAFETY: the header was initialized above; dropping it releases linked off-heap owners.
            unsafe { std::ptr::drop_in_place(block) };
            Err(error)
        }
    }
}

/// Release an old heap block after any thread that loaded its `prt->data` word has quiesced.
// Port of erts/emulator/beam/erl_bif_port.c:626-636 (`cleanup_old_port_data`) and
// erl_process.c (`erts_schedule_thr_prgr_later_cleanup_op`), OTP-29.1.1.
pub(super) fn retire_data(word: u64, scheduler: &Scheduler<Process>) {
    if word == 0 || word & 3 != 0 {
        return;
    }
    scheduler.thread_progress_later(move || {
        let pointer = word as *mut PortDataBlock;
        // SAFETY: the atomic exchange transferred ownership and thread progress excludes readers.
        let hsize = unsafe { (*pointer).hsize };
        let (layout, _) = Layout::new::<PortDataBlock>()
            .extend(
                Layout::array::<std::mem::MaybeUninit<u64>>(hsize).expect("valid port heap size"),
            )
            .expect("valid port data layout");
        let allocation_words = layout.pad_to_align().size() / std::mem::size_of::<u64>();
        // SAFETY: the exchange transferred this exact live ERTS allocation to retirement and
        // thread progress excludes readers; `hsize` recovers its original extent.
        unsafe { std::ptr::drop_in_place(pointer) };
        // SAFETY: this non-null pointer and allocation type/word count identify the same live block.
        let allocation = unsafe {
            AllocBlock::from_raw(
                std::ptr::NonNull::new_unchecked(pointer.cast()),
                ErtsAlcType::PORT_DATA_HEAP,
                allocation_words,
            )
        };
        drop(allocation);
    });
}
