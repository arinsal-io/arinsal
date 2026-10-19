//! Per-thread cache of the atoms the port drivers name by literal.
//!
//! erts keeps these as compile-time atom indices (`am_tcp`, `am_inet_reply`, ...); here each
//! literal is interned once per thread and found again by the address of its text.

use arinsal_term::{Term, global_atoms};
use std::cell::RefCell;
use std::collections::HashMap;
use std::hash::{BuildHasherDefault, Hasher};

/// Hashes the (address, length) pair of a literal: already well spread, nothing to mix.
#[derive(Default)]
struct PtrHasher(u64);

impl Hasher for PtrHasher {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.0 = self.0.rotate_left(8) ^ u64::from(*byte);
        }
    }

    fn write_usize(&mut self, value: usize) {
        self.0 = (self.0 ^ value as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    }
}

type Cache = HashMap<(usize, usize), Term, BuildHasherDefault<PtrHasher>>;

thread_local! {
    static CACHE: RefCell<Cache> = RefCell::new(Cache::default());
}

/// The atom named by the literal `name`.
pub(crate) fn atom(name: &'static str) -> Term {
    let key = (name.as_ptr() as usize, name.len());
    CACHE.with(|cache| {
        *cache
            .borrow_mut()
            .entry(key)
            .or_insert_with(|| Term::atom(global_atoms().intern(name).expect("port atom")))
    })
}
