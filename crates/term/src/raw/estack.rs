//! The work stack of the iterative term walkers: the one place that touches its memory.
//!
//! Port of erts/emulator/beam/global.h (DECLARE_ESTACK / DECLARE_WSTACK, ESTACK_PUSH,
//! ESTACK_POP, ESTACK_COUNT, DESTROY_ESTACK) and erts/emulator/beam/utils.c
//! (erl_grow_estack, erl_grow_wstack), OTP-29.1.1. erts keeps `start/sp/end` pointers into a
//! default array on the C stack; a Rust value moves, so the stack keeps `sp` and `end` as
//! offsets from `start`, and `start` is the default array until the first growth
//! (`start != edefault`), then an `ERTS_ALC_T_ESTACK` block that grows by `erts_realloc`.

use std::mem::MaybeUninit;
use std::ptr::NonNull;

/// A work stack of `T` with a default array of `N` entries (DEF_ESTACK_SIZE for `N = 16`).
pub struct WStack<T, const N: usize> {
    /// `sp - start`: entries in use.
    sp: usize,
    /// `end - start`: entries the active array holds.
    end: usize,
    /// `start` once the stack left its default array; `None` while it uses `default`.
    grown: Option<NonNull<T>>,
    /// The default array (`ESTK_DEF_STACK`).
    default: [MaybeUninit<T>; N],
}

// SAFETY: the stack owns its entries like a `Vec<T>` does.
unsafe impl<T: Send, const N: usize> Send for WStack<T, N> {}
// SAFETY: shared access only reads entries, as for `Vec<T>`.
unsafe impl<T: Sync, const N: usize> Sync for WStack<T, N> {}

impl<T, const N: usize> Default for WStack<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T, const N: usize> WStack<T, N> {
    const ALIGNED: () = assert!(
        std::mem::align_of::<T>() <= std::mem::align_of::<u64>() && std::mem::size_of::<T>() != 0,
        "allocator blocks are word aligned"
    );

    /// An empty stack on its default array (DECLARE_ESTACK); allocates nothing.
    #[inline(always)]
    pub fn new() -> Self {
        Self {
            sp: 0,
            end: N,
            grown: None,
            default: [const { MaybeUninit::uninit() }; N],
        }
    }

    /// `start`.
    #[inline(always)]
    fn start(&self) -> *const T {
        match self.grown {
            Some(start) => start.as_ptr(),
            None => self.default.as_ptr().cast(),
        }
    }

    /// `start`, writable.
    #[inline(always)]
    fn start_mut(&mut self) -> *mut T {
        match self.grown {
            Some(start) => start.as_ptr(),
            None => self.default.as_mut_ptr().cast(),
        }
    }

    /// ESTACK_PUSH: `ESTACK_RESERVE(s, 1); *sp++ = x`.
    #[inline(always)]
    pub fn push(&mut self, value: T) {
        let sp = self.sp;
        if sp == self.end {
            self.grow(1);
        }
        // SAFETY: `sp < end`, so the slot is inside the active array and not initialized.
        unsafe { self.start_mut().add(sp).write(value) };
        self.sp = sp + 1;
    }

    /// ESTACK_POP: `*--sp`, `None` when empty.
    #[inline(always)]
    pub fn pop(&mut self) -> Option<T> {
        let sp = self.sp.checked_sub(1)?;
        self.sp = sp;
        // SAFETY: the slot below the old `sp` holds an entry, now given up by the stack.
        Some(unsafe { self.start_mut().add(sp).read() })
    }

    /// Port of utils.c (erl_grow_estack): double, or more for a larger `need`; the default
    /// array is copied into a new block, a grown block is reallocated.
    #[cold]
    #[inline(never)]
    fn grow(&mut self, need: usize) {
        let () = Self::ALIGNED;
        let old_size = self.end.max(1);
        let new_size = if need < old_size {
            2 * old_size
        } else {
            (need / old_size + 2) * old_size
        };
        let entry = std::mem::size_of::<T>();
        let new_bytes = new_size.checked_mul(entry).expect("estack size fits");
        let block = match self.grown {
            Some(start) => {
                arinsal_alloc::typed::estack_realloc(start.cast(), self.end * entry, new_bytes)
            }
            None => arinsal_alloc::typed::estack_alloc(new_bytes).inspect(|block| {
                // SAFETY: the first `sp` default entries are initialized; the new block has
                // room for `new_size >= sp` entries and does not overlap the default array.
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        self.default.as_ptr().cast::<T>(),
                        block.as_ptr().cast::<T>(),
                        self.sp,
                    );
                }
            }),
        };
        let Ok(block) = block else {
            std::alloc::handle_alloc_error(
                std::alloc::Layout::array::<T>(new_size).expect("estack size fits"),
            )
        };
        self.grown = Some(block.cast());
        self.end = new_size;
    }

    /// ESTACK_COUNT.
    #[inline(always)]
    pub fn len(&self) -> usize {
        self.sp
    }

    /// ESTACK_ISEMPTY.
    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.sp == 0
    }

    /// The entries from the bottom to the top.
    #[inline(always)]
    pub fn as_slice(&self) -> &[T] {
        // SAFETY: the first `sp` entries of the active array are initialized.
        unsafe { std::slice::from_raw_parts(self.start(), self.sp) }
    }

    /// The entries from the bottom to the top, writable.
    #[inline(always)]
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        let sp = self.sp;
        // SAFETY: as in `as_slice`, borrowed exclusively.
        unsafe { std::slice::from_raw_parts_mut(self.start_mut(), sp) }
    }

    /// Roll back to `len` entries (WSTACK_ROLLBACK), dropping the ones above.
    #[inline(always)]
    pub fn truncate(&mut self, len: usize) {
        if len >= self.sp {
            return;
        }
        let old = self.sp;
        self.sp = len;
        // SAFETY: entries `len..old` were initialized and are no longer part of the stack.
        unsafe {
            std::ptr::drop_in_place(std::ptr::slice_from_raw_parts_mut(
                self.start_mut().add(len),
                old - len,
            ));
        }
    }
}

impl<T, const N: usize> Drop for WStack<T, N> {
    /// DESTROY_ESTACK: the entries are dropped and a grown block is freed.
    fn drop(&mut self) {
        self.truncate(0);
        if let Some(start) = self.grown {
            arinsal_alloc::typed::estack_free(start.cast(), self.end * std::mem::size_of::<T>());
        }
    }
}
