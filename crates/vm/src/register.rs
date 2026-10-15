//! Process and port name registry.
//!
//! Port of erts/emulator/beam/register.c and the chained hash it uses
//! (erts/emulator/beam/hash.c, hash.h), OTP-29.1.1. One table, keyed by atom
//! index (`REG_HASH` = `atom_val`), guarded by `regtab_rwmtx`
//! (`ERTS_RWMTX_TYPE_FREQUENT_READ`). `whereis`, `register`, `unregister`,
//! `registered` and send-to-name are one lookup.

use arinsal_sched::Pid;
use arinsal_term::FrequentReadRwLock;
use arinsal_term::{Atom, global_atoms};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

/// `p->common.u.alive.reg == NULL`. Atom indices stay below the table limit.
pub(crate) const NO_REG_ATOM: u32 = u32::MAX;

/// Initial `hash_init` size (`PREG_HASH_SIZE`).
const PREG_HASH_SIZE: u32 = 10;
/// `ERTS_SIZEOF_TERM * 8` on a 64-bit build (`MAX_SHIFT`).
const MAX_SHIFT: u32 = 64;
/// 2^64 / golden ratio, from hash.h `hash_get_slot`.
const FIB64: u64 = 11_400_714_819_323_198_485;

/// What a name resolves to. A `RegProc` has exactly one of `p` and `pt`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RegId {
    Proc(Pid),
    Port(u64),
}

struct Entry {
    next: Option<u32>,
    /// `HashBucket.hvalue`. For this table it is `atom_val(name)`.
    hvalue: u64,
    name: Atom,
    kind: Kind,
}

enum Kind {
    Vacant,
    Proc(Pid),
    Port { id: u64, word: Arc<AtomicU32> },
}

/// `struct hash process_reg` specialized to `RegProc`.
pub(crate) struct ProcessReg {
    shift: u32,
    max_shift: u32,
    shrink_threshold: i32,
    grow_threshold: i32,
    nobjs: i32,
    buckets: Vec<Option<u32>>,
    entries: Vec<Entry>,
    free: Vec<u32>,
}

/// `regtab_rwmtx`. Readers (`whereis`, `registered`, send) share the lock.
pub(crate) struct RegisterTable {
    inner: FrequentReadRwLock<ProcessReg>,
}

impl RegisterTable {
    // Port of erts/emulator/beam/register.c:141 (init_register_table), OTP-29.1.1.
    pub(crate) fn new() -> Self {
        Self {
            inner: FrequentReadRwLock::new(ProcessReg::new()),
        }
    }

    pub(crate) fn read(&self) -> arinsal_term::FrequentReadGuard<'_, ProcessReg> {
        self.inner.read()
    }

    pub(crate) fn write(&self) -> arinsal_term::FrequentWriteGuard<'_, ProcessReg> {
        self.inner.write()
    }

    /// `erts_whereis_name_to_id`: one fetch, no liveness sweep.
    pub(crate) fn whereis(&self, name: Atom) -> Option<RegId> {
        self.read().fetch(name)
    }

    pub(crate) fn whereis_proc(&self, name: Atom) -> Option<Pid> {
        match self.whereis(name) {
            Some(RegId::Proc(pid)) => Some(pid),
            _ => None,
        }
    }

    pub(crate) fn whereis_port(&self, name: Atom) -> Option<u64> {
        match self.whereis(name) {
            Some(RegId::Port(id)) => Some(id),
            _ => None,
        }
    }

    /// Resolve a name that is already interned. A missing atom is not registered.
    pub(crate) fn whereis_proc_str(&self, name: &str) -> Option<Pid> {
        self.whereis_proc(global_atoms().get(name)?)
    }

    pub(crate) fn whereis_port_str(&self, name: &str) -> Option<u64> {
        self.whereis_port(global_atoms().get(name)?)
    }
}

impl ProcessReg {
    // Port of erts/emulator/beam/hash.c:121 (hash_init), OTP-29.1.1.
    fn new() -> Self {
        let mut pow = 1u32;
        while (1u32 << pow) < PREG_HASH_SIZE {
            pow += 1;
        }
        let shift = MAX_SHIFT - pow;
        let mut table = Self {
            shift,
            max_shift: shift,
            shrink_threshold: -1,
            grow_threshold: 0,
            nobjs: 0,
            buckets: Vec::new(),
            entries: Vec::new(),
            free: Vec::new(),
        };
        table.buckets = vec![None; table.slots()];
        table.set_thresholds();
        table
    }

    fn slots(&self) -> usize {
        1usize << (MAX_SHIFT - self.shift)
    }

    // Port of erts/emulator/beam/hash.c:108 (set_thresholds), OTP-29.1.1.
    fn set_thresholds(&mut self) {
        let slots = self.slots() as i32;
        self.grow_threshold = (8 * slots) / 5;
        if self.shift < self.max_shift {
            self.shrink_threshold = slots / 5;
        } else {
            self.shrink_threshold = -1;
        }
    }

    // Port of erts/emulator/beam/hash.h:108 (hash_get_slot), OTP-29.1.1.
    fn slot(&self, mut hv: u64) -> usize {
        hv ^= hv >> self.shift;
        ((FIB64.wrapping_mul(hv)) >> self.shift) as usize
    }

    // Port of erts/emulator/beam/hash.h:133 (hash_fetch) / hash.c:227 (hash_get).
    pub(crate) fn fetch(&self, name: Atom) -> Option<RegId> {
        let index = self.fetch_index(name)?;
        Some(self.entries[index as usize].id())
    }

    pub(crate) fn contains(&self, name: Atom) -> bool {
        self.fetch_index(name).is_some()
    }

    fn fetch_index(&self, name: Atom) -> Option<u32> {
        let hval = u64::from(name.0);
        let mut link = self.buckets[self.slot(hval)];
        while let Some(index) = link {
            let entry = &self.entries[index as usize];
            if entry.hvalue == hval && entry.name == name {
                return Some(index);
            }
            link = entry.next;
        }
        None
    }

    /// `hash_put`. False when `name` is already in the table (the old object is kept).
    // Port of erts/emulator/beam/hash.c:235 (hash_put), OTP-29.1.1.
    pub(crate) fn insert_proc(&mut self, name: Atom, pid: Pid) -> bool {
        self.insert(name, Kind::Proc(pid))
    }

    pub(crate) fn insert_port(&mut self, name: Atom, id: u64, word: Arc<AtomicU32>) -> bool {
        self.insert(name, Kind::Port { id, word })
    }

    fn insert(&mut self, name: Atom, kind: Kind) -> bool {
        let hval = u64::from(name.0);
        if self.fetch_index(name).is_some() {
            return false;
        }
        let index = if let Some(index) = self.free.pop() {
            index
        } else {
            let index = u32::try_from(self.entries.len()).expect("register table index");
            self.entries.push(Entry {
                next: None,
                hvalue: 0,
                name,
                kind: Kind::Vacant,
            });
            index
        };
        let bucket = self.slot(hval);
        self.entries[index as usize] = Entry {
            next: self.buckets[bucket],
            hvalue: hval,
            name,
            kind,
        };
        self.buckets[bucket] = Some(index);
        self.nobjs += 1;
        if self.nobjs > self.grow_threshold {
            self.rehash(true);
        }
        true
    }

    /// `hash_erase`. Clears the port's `reg` word before the object is dropped.
    // Port of erts/emulator/beam/hash.c:262 (hash_erase), OTP-29.1.1.
    pub(crate) fn erase(&mut self, name: Atom) -> Option<RegId> {
        let hval = u64::from(name.0);
        let bucket = self.slot(hval);
        let mut prev: Option<u32> = None;
        let mut link = self.buckets[bucket];
        while let Some(index) = link {
            let entry = &self.entries[index as usize];
            if entry.hvalue == hval && entry.name == name {
                let next = entry.next;
                if let Some(prev) = prev {
                    self.entries[prev as usize].next = next;
                } else {
                    self.buckets[bucket] = next;
                }
                let kind = std::mem::replace(&mut self.entries[index as usize].kind, Kind::Vacant);
                if let Kind::Port { word, .. } = &kind {
                    word.store(NO_REG_ATOM, Ordering::Release);
                }
                let id = kind.id();
                self.free.push(index);
                self.nobjs -= 1;
                if self.nobjs < self.shrink_threshold {
                    self.rehash(false);
                }
                return Some(id);
            }
            prev = Some(index);
            link = self.entries[index as usize].next;
        }
        None
    }

    /// `registered/0`. Each name is consed onto the front, so the list is the
    /// reverse of the bucket walk.
    // Port of erts/emulator/beam/register.c:567 (registered_foreach), OTP-29.1.1.
    pub(crate) fn registered_atoms(&self) -> Vec<Atom> {
        let mut names = Vec::with_capacity(self.nobjs.max(0) as usize);
        for head in &self.buckets {
            let mut link = *head;
            while let Some(index) = link {
                let entry = &self.entries[index as usize];
                names.push(entry.name);
                link = entry.next;
            }
        }
        names.reverse();
        names
    }

    // Port of erts/emulator/beam/hash.c:187 (rehash), OTP-29.1.1.
    fn rehash(&mut self, grow: bool) {
        if grow {
            self.shift -= 1;
        } else if self.shift == self.max_shift {
            return;
        } else {
            self.shift += 1;
        }
        let n = self.slots();
        let old = std::mem::take(&mut self.buckets);
        self.buckets = vec![None; n];
        for head in old.into_iter().flatten() {
            let mut link = Some(head);
            while let Some(index) = link {
                let next = self.entries[index as usize].next;
                let bucket = self.slot(self.entries[index as usize].hvalue);
                self.entries[index as usize].next = self.buckets[bucket];
                self.buckets[bucket] = Some(index);
                link = next;
            }
        }
        self.set_thresholds();
    }
}

impl Entry {
    fn id(&self) -> RegId {
        self.kind.id()
    }
}

impl Kind {
    fn id(&self) -> RegId {
        match self {
            Kind::Proc(pid) => RegId::Proc(*pid),
            Kind::Port { id, .. } => RegId::Port(*id),
            Kind::Vacant => unreachable!("vacant register entry is not linked"),
        }
    }
}

/// A name table chosen by namespace: root's own, or the one on a namespace entry.
pub(crate) enum RegRef<'a> {
    Root(&'a RegisterTable),
    Ns(Arc<crate::namespace::NsEntry>),
}

impl std::ops::Deref for RegRef<'_> {
    type Target = RegisterTable;

    fn deref(&self) -> &RegisterTable {
        match self {
            RegRef::Root(table) => table,
            RegRef::Ns(entry) => entry.names(),
        }
    }
}

impl crate::process::Runtime {
    /// The table `register/2` and `unregister/1` of a process in `ns` write to. `None` for a
    /// namespace that does not exist.
    pub(crate) fn reg_for(&self, ns: u32) -> Option<RegRef<'_>> {
        if ns == 0 {
            return Some(RegRef::Root(&self.reg));
        }
        self.namespaces.get(ns).map(RegRef::Ns)
    }

    /// Resolve `name` for a process in `ns`. A namespace sees its own names first, then the
    /// root processes marked shared. Ports are visible from root only.
    pub(crate) fn whereis_in(&self, ns: u32, name: Atom) -> Option<RegId> {
        if ns == 0 {
            return self.reg.whereis(name);
        }
        self.whereis_ns(ns, name)
    }

    pub(crate) fn whereis_proc_in(&self, ns: u32, name: Atom) -> Option<Pid> {
        match self.whereis_in(ns, name) {
            Some(RegId::Proc(pid)) => Some(pid),
            _ => None,
        }
    }

    pub(crate) fn whereis_proc_str_in(&self, ns: u32, name: &str) -> Option<Pid> {
        self.whereis_proc_in(ns, global_atoms().get(name)?)
    }

    fn whereis_ns(&self, ns: u32, name: Atom) -> Option<RegId> {
        let entry = self.namespaces.get(ns)?;
        if let Some(id) = entry
            .names_if_created()
            .and_then(|table| table.whereis(name))
        {
            return Some(id);
        }
        let RegId::Proc(pid) = self.reg.whereis(name)? else {
            return None;
        };
        let word = self.scheduler().ok()?.ns_word(pid)?;
        (word & arinsal_sched::NS_SHARED != 0).then_some(RegId::Proc(pid))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_put_get_erase_grow_and_shrink() {
        let mut table = ProcessReg::new();
        let mut names = Vec::new();
        for index in 0..40 {
            let atom = global_atoms()
                .intern(&format!("reg_hash_{index}"))
                .expect("atom");
            assert!(table.insert_proc(atom, Pid::from_data((index + 1) as u64)));
            assert!(!table.insert_proc(atom, Pid::from_data((index + 100) as u64)));
            names.push(atom);
        }
        for (index, atom) in names.iter().copied().enumerate() {
            assert_eq!(
                table.fetch(atom),
                Some(RegId::Proc(Pid::from_data(index as u64 + 1)))
            );
        }
        assert_eq!(table.registered_atoms().len(), names.len());
        for atom in names.iter().take(30) {
            assert!(table.erase(*atom).is_some());
            assert!(table.fetch(*atom).is_none());
        }
        assert_eq!(table.registered_atoms().len(), 10);
        for atom in names.iter().take(30) {
            assert!(table.insert_proc(*atom, Pid::from_data(7)));
            assert_eq!(table.fetch(*atom), Some(RegId::Proc(Pid::from_data(7))));
        }
    }
}
