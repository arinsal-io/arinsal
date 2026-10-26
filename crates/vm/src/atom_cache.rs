//! Cache of the atoms the port drivers name by literal.
//!
//! erts keeps these as compile-time atom indices (`am_tcp`, `am_inet_reply`, ...); here each
//! literal is interned once and found again by the address of its text in a small direct-mapped
//! table, so a lookup is two atomic loads with no thread-local access.

use arinsal_term::{Atom, Term, global_atoms};
use std::sync::atomic::{AtomicU64, Ordering};

const SLOTS: usize = 1024;

/// `key` is the address of the literal's text (zero when empty), `value` the atom index plus one.
struct Slot {
    key: AtomicU64,
    value: AtomicU64,
}

static CACHE: [Slot; SLOTS] = [const {
    Slot {
        key: AtomicU64::new(0),
        value: AtomicU64::new(0),
    }
}; SLOTS];

/// The atom named by the literal `name`.
pub(crate) fn atom(name: &'static str) -> Term {
    // Addresses are 48 bits; the length (an atom has at most 255 characters) goes above them.
    let key = (name.as_ptr() as u64 & 0xFFFF_FFFF_FFFF) | ((name.len() as u64) << 48);
    let slot = &CACHE[((key >> 3) ^ (key >> 13) ^ (key >> 48)) as usize % SLOTS];
    if slot.key.load(Ordering::Acquire) == key {
        let value = slot.value.load(Ordering::Relaxed);
        // A writer clears `key` before it changes `value`, so an unchanged key means the value
        // belongs to it.
        if slot.key.load(Ordering::Acquire) == key && value != 0 {
            return Term::atom(Atom((value - 1) as u32));
        }
    }
    let atom = global_atoms().intern(name).expect("port atom");
    slot.key.store(0, Ordering::Release);
    slot.value.store(u64::from(atom.0) + 1, Ordering::Relaxed);
    slot.key.store(key, Ordering::Release);
    Term::atom(atom)
}
