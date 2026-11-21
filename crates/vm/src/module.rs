//! The module table: one `Module` per module atom, with `curr` / `old` / `on_load`.
//!
//! Port of erts/emulator/beam/module.c and module.h, OTP-29.1.1. Lookup is the
//! `IndexTable` of index.c over the chained hash of hash.c, keyed by atom index
//! (`module_hash` = `x->module`). `erlang:loaded/0` walks `module_code(i)` in
//! creation order. Staging copies this table (`module_start_staging`).

use arinsal_term::{Atom, global_atoms};

/// A module name usable as a [`ModuleIndex`] key: an atom, or text that is resolved to one.
pub(crate) trait ModuleKey {
    fn atom(&self) -> Option<Atom>;
}

impl ModuleKey for Atom {
    fn atom(&self) -> Option<Atom> {
        Some(*self)
    }
}

impl ModuleKey for str {
    fn atom(&self) -> Option<Atom> {
        global_atoms().get(self)
    }
}

impl ModuleKey for String {
    fn atom(&self) -> Option<Atom> {
        self.as_str().atom()
    }
}

impl<K: ModuleKey + ?Sized> ModuleKey for &K {
    fn atom(&self) -> Option<Atom> {
        (**self).atom()
    }
}

/// `MODULE_SIZE` (module.c): `hash_init` size passed as `3 * MODULE_SIZE / 4`.
const MODULE_SIZE: i32 = 50;
/// `MODULE_LIMIT` (module.c): IndexTable cap for `module_code`.
const MODULE_LIMIT: usize = 64 * 1024;
/// `ERTS_SIZEOF_TERM * 8` on a 64-bit build (`MAX_SHIFT` in hash.c).
const MAX_SHIFT: i32 = 64;
/// 2^64 / golden ratio, from hash.h `hash_get_slot`.
const FIB64: u64 = 11_400_714_819_323_198_485;

/// `Hash` (hash.h) of `module_tables[ix].htable`.
///
/// Bucket chains store slot indices rather than pointers so the staging code
/// index can copy the table (`CodeTables` clone = `module_start_staging`).
#[derive(Clone)]
struct Hash {
    shift: i32,
    max_shift: i32,
    shrink_threshold: i32,
    grow_threshold: i32,
    nobjs: i32,
    buckets: Vec<Option<u32>>,
}

impl Hash {
    // Port of erts/emulator/beam/hash.c:121 (hash_init), OTP-29.1.1.
    fn init(size: i32) -> Self {
        let mut pow = 1i32;
        while (1i32 << pow) < size {
            pow += 1;
        }
        let shift = MAX_SHIFT - pow;
        let mut hash = Self {
            shift,
            max_shift: shift,
            shrink_threshold: -1,
            grow_threshold: 0,
            nobjs: 0,
            buckets: Vec::new(),
        };
        hash.buckets = vec![None; hash.slots()];
        hash.set_thresholds();
        hash
    }

    fn slots(&self) -> usize {
        // Port of hash.c:41 (hash_get_slots).
        1usize << (MAX_SHIFT - self.shift)
    }

    // Port of hash.c:108 (set_thresholds), OTP-29.1.1.
    fn set_thresholds(&mut self) {
        let slots = self.slots() as i32;
        self.grow_threshold = (8 * slots) / 5;
        self.shrink_threshold = if self.shift < self.max_shift {
            slots / 5
        } else {
            -1
        };
    }

    // Port of hash.h:108 (hash_get_slot), the fibonacci mapping.
    fn slot_of(&self, mut hv: u64) -> usize {
        let shift = self.shift as u32;
        hv ^= hv >> shift;
        (FIB64.wrapping_mul(hv) >> shift) as usize
    }

    // Port of hash.c:187 (rehash), OTP-29.1.1.
    fn rehash(&mut self, grow: bool, slots: &mut [Module]) {
        let old_size = self.slots();
        if grow {
            self.shift -= 1;
        } else {
            if self.shift == self.max_shift {
                return;
            }
            self.shift += 1;
        }
        let mut new_bucket = vec![None; self.slots()];
        for ix in 0..old_size {
            let mut b = self.buckets[ix];
            while let Some(slot) = b {
                let next = slots[slot as usize].next;
                let mapped = self.slot_of(slots[slot as usize].hvalue);
                slots[slot as usize].next = new_bucket[mapped];
                new_bucket[mapped] = Some(slot);
                b = next;
            }
        }
        self.buckets = new_bucket;
        self.set_thresholds();
    }
}

/// One `Module` of `module_tables[ix]`: `IndexSlot` then atom, `seen`, `curr`, `old`, `on_load`.
/// Instance ids are `None` when the corresponding `erl_module_instance` has `code_length == 0`.
// Port of erts/emulator/beam/module.h (`Module`, `erl_module_instance`), OTP-29.1.1.
#[derive(Clone, Copy)]
pub(crate) struct Module {
    /// `HashBucket.next` as a slot index (`None` is NULL).
    next: Option<u32>,
    /// `HashBucket.hvalue` (`module_hash` = atom index).
    hvalue: u64,
    /// `IndexSlot.index`.
    #[allow(dead_code)]
    index: i32,
    /// `Module.module` (atom index).
    pub(crate) module: Atom,
    /// `Module.seen` (`finish_loading`).
    #[allow(dead_code)]
    pub(crate) seen: i32,
    /// Current code instance (`Module.curr`).
    pub(crate) curr: Option<usize>,
    /// Old code instance (`Module.old`).
    pub(crate) old: Option<usize>,
    /// Pending on_load instance (`Module.on_load`).
    pub(crate) on_load: Option<usize>,
}

/// `module_tables[ix]`: IndexTable lookup by atom hash plus a sequential index assigned at
/// first `erts_put_module`. `erlang:loaded/0` walks `module_code(i)` for `i` in `0..entries`.
/// Entries are never reused except when abort drops an uncommitted staging copy
/// (`index_erase_latest_from`).
// Port of erts/emulator/beam/module.c:47 (`module_tables`), `erts_put_module` /
// `erts_get_module` / `module_code` / `module_code_size`, and erts/emulator/beam/index.c
// (`IndexTable`), OTP-29.1.1.
#[derive(Clone)]
pub(crate) struct ModuleIndex {
    htable: Hash,
    /// `seg_table` / `module_code(i)`: creation order. Index 0 is the first `erts_put_module`.
    slots: Vec<Module>,
}

impl Default for ModuleIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl ModuleIndex {
    /// Port of module.c `init_module_table` / index.c `erts_index_init` for one code index.
    pub(crate) fn new() -> Self {
        Self {
            htable: Hash::init(3 * MODULE_SIZE / 4),
            slots: Vec::new(),
        }
    }

    /// Port of module.c `module_hash`: the untagged atom index.
    fn module_hash(atom: Atom) -> u64 {
        u64::from(atom.0)
    }

    // Port of hash.h:133 (hash_fetch) / hash.c:226 (hash_get) / module.c `module_cmp`.
    fn hash_get(&self, atom: Atom) -> Option<usize> {
        let hval = Self::module_hash(atom);
        let mut b = self.htable.buckets[self.htable.slot_of(hval)];
        while let Some(ix) = b {
            let obj = &self.slots[ix as usize];
            if obj.hvalue == hval && obj.module == atom {
                return Some(ix as usize);
            }
            b = obj.next;
        }
        None
    }

    // Port of hash.c:235 (hash_put) and index.c:74 (index_put_entry), OTP-29.1.1.
    fn put_atom(&mut self, atom: Atom) -> usize {
        if let Some(ix) = self.hash_get(atom) {
            return ix;
        }
        let ix = self.slots.len();
        if ix >= MODULE_LIMIT {
            // Port of index.c:89 (`erts_exit(ERTS_DUMP_EXIT, "no more index entries in %s")`).
            panic!("no more index entries in module_code (max={MODULE_LIMIT})");
        }
        let hval = Self::module_hash(atom);
        let mapped = self.htable.slot_of(hval);
        self.slots.push(Module {
            next: self.htable.buckets[mapped],
            hvalue: hval,
            index: ix as i32,
            module: atom,
            seen: 0,
            curr: None,
            old: None,
            on_load: None,
        });
        self.htable.buckets[mapped] = Some(ix as u32);
        self.htable.nobjs += 1;
        if self.htable.nobjs > self.htable.grow_threshold {
            self.htable.rehash(true, &mut self.slots);
        }
        ix
    }

    // Port of hash.c:262 (hash_erase), OTP-29.1.1.
    fn hash_erase(&mut self, ix: usize) {
        let hval = self.slots[ix].hvalue;
        let mapped = self.htable.slot_of(hval);
        let mut b = self.htable.buckets[mapped];
        let mut prev: Option<u32> = None;
        while let Some(cur) = b {
            let next = self.slots[cur as usize].next;
            if cur as usize == ix {
                if let Some(prev) = prev {
                    self.slots[prev as usize].next = next;
                } else {
                    self.htable.buckets[mapped] = next;
                }
                self.htable.nobjs -= 1;
                if self.htable.nobjs < self.htable.shrink_threshold {
                    self.htable.rehash(false, &mut self.slots);
                }
                return;
            }
            prev = Some(cur);
            b = next;
        }
    }

    /// Port of index.c `index_erase_latest_from` (`module_end_staging` abort).
    #[allow(dead_code)]
    pub(crate) fn erase_latest_from(&mut self, from_ix: usize) {
        if from_ix < self.slots.len() {
            for ix in from_ix..self.slots.len() {
                self.hash_erase(ix);
            }
            self.slots.truncate(from_ix);
        }
    }

    /// Current-code instance id (`erts_get_module` then `modp->curr`).
    pub(crate) fn get<K: ModuleKey + ?Sized>(&self, key: &K) -> Option<&usize> {
        self.entry(key)?.curr.as_ref()
    }

    /// Whether the module has current code (`module_loaded` / `curr.code_hdr != NULL`).
    pub(crate) fn contains_key<K: ModuleKey + ?Sized>(&self, key: &K) -> bool {
        self.get(key).is_some()
    }

    /// Port of module.c `erts_get_module`.
    pub(crate) fn entry<K: ModuleKey + ?Sized>(&self, key: &K) -> Option<&Module> {
        let atom = key.atom()?;
        let ix = self.hash_get(atom)?;
        self.slots.get(ix)
    }

    fn entry_mut<K: ModuleKey + ?Sized>(&mut self, key: &K) -> Option<&mut Module> {
        let atom = key.atom()?;
        let ix = self.hash_get(atom)?;
        self.slots.get_mut(ix)
    }

    /// Port of module.c `put_module` / `erts_put_module` and index.c `index_put_entry`.
    /// First insert of a name gets `entries`; a later put returns the same index.
    pub(crate) fn put_module(&mut self, name: &str) -> Option<usize> {
        let atom = global_atoms().intern(name).ok()?;
        Some(self.put_atom(atom))
    }

    /// Makes `id` the current instance (`modp->curr`). Puts the module first.
    /// `beam_make_current_old` / `delete_code` must have moved the previous `curr` into `old`
    /// before this writes the new instance; this only replaces `curr`.
    // Port of erts/emulator/beam/module.c (`erts_put_module` then `modp->curr`), OTP-29.1.1.
    pub(crate) fn insert(&mut self, name: &str, id: usize) -> Option<usize> {
        let ix = self.put_module(name)?;
        self.slots[ix].curr.replace(id)
    }

    /// `delete_code` without a new `curr`: current code becomes old (delete_module).
    // Port of erts/emulator/beam/beam_bif_load.c:2453-2454 (delete_code), OTP-29.1.1.
    pub(crate) fn make_current_old<K: ModuleKey + ?Sized>(&mut self, key: &K) -> Option<usize> {
        let current = self.remove(key)?;
        if let Some(entry) = self.entry_mut(key) {
            entry.old = Some(current);
        }
        Some(current)
    }

    /// Clears current code without dropping the table slot (delete_module: curr → old).
    pub(crate) fn remove<K: ModuleKey + ?Sized>(&mut self, key: &K) -> Option<usize> {
        self.entry_mut(key)?.curr.take()
    }

    /// `Module.old` instance id.
    pub(crate) fn old<K: ModuleKey + ?Sized>(&self, key: &K) -> Option<usize> {
        self.entry(key)?.old
    }

    /// Whether `Module.old` has code (`old.code_length != 0`).
    pub(crate) fn has_old<K: ModuleKey + ?Sized>(&self, key: &K) -> bool {
        self.old(key).is_some()
    }

    /// Sets `Module.old`, putting the module first as `erts_put_module` does.
    pub(crate) fn set_old(&mut self, name: &str, id: usize) -> Option<usize> {
        let ix = self.put_module(name)?;
        self.slots[ix].old.replace(id)
    }

    /// Clears `Module.old` (`purge` complete).
    pub(crate) fn take_old<K: ModuleKey + ?Sized>(&mut self, key: &K) -> Option<usize> {
        self.entry_mut(key)?.old.take()
    }

    /// `Module.on_load` instance id.
    pub(crate) fn on_load<K: ModuleKey + ?Sized>(&self, key: &K) -> Option<usize> {
        self.entry(key)?.on_load
    }

    /// Whether `Module.on_load` is set.
    pub(crate) fn has_on_load<K: ModuleKey + ?Sized>(&self, key: &K) -> bool {
        self.on_load(key).is_some()
    }

    /// Sets `Module.on_load`, putting the module first.
    pub(crate) fn set_on_load(&mut self, name: &str, id: usize) -> Option<usize> {
        let ix = self.put_module(name)?;
        self.slots[ix].on_load.replace(id)
    }

    /// Clears `Module.on_load` (`finish_after_on_load` / `prepare_on_load`).
    pub(crate) fn take_on_load<K: ModuleKey + ?Sized>(&mut self, key: &K) -> Option<usize> {
        self.entry_mut(key)?.on_load.take()
    }

    /// Port of module.c `module_code_size` (`module_tables[ix].entries`).
    pub(crate) fn code_size(&self) -> usize {
        self.slots.len()
    }

    /// Port of module.c `module_code(i, code_ix)`.
    pub(crate) fn module_code(&self, i: usize) -> Option<&Module> {
        self.slots.get(i)
    }

    /// Current-code instance ids (`modp->curr` for every slot with code).
    #[allow(dead_code)]
    pub(crate) fn values(&self) -> impl Iterator<Item = &usize> {
        self.slots.iter().filter_map(|entry| entry.curr.as_ref())
    }

    /// Bytes of the hash buckets and index slots (`module_table_sz` without the Module objects
    /// of `CodeTables.modules`).
    pub(crate) fn table_bytes(&self) -> usize {
        size_of::<Self>()
            + self.htable.buckets.capacity() * size_of::<Option<u32>>()
            + self.slots.capacity() * size_of::<Module>()
    }
}

#[cfg(test)]
mod tests {
    use super::ModuleIndex;
    use arinsal_term::global_atoms;

    fn name_at(index: &ModuleIndex, i: usize) -> String {
        global_atoms()
            .text(index.module_code(i).expect("slot").module)
            .expect("atom text")
            .to_owned()
    }

    #[test]
    fn put_module_index_is_creation_order() {
        let mut index = ModuleIndex::new();
        similar_asserts::assert_eq!(index.put_module("mi_first"), Some(0));
        similar_asserts::assert_eq!(index.put_module("mi_second"), Some(1));
        similar_asserts::assert_eq!(index.put_module("mi_first"), Some(0));
        similar_asserts::assert_eq!(index.insert("mi_first", 11), None);
        similar_asserts::assert_eq!(index.insert("mi_second", 22), None);
        similar_asserts::assert_eq!(index.insert("mi_third", 33), None);
        similar_asserts::assert_eq!(index.code_size(), 3);
        similar_asserts::assert_eq!(name_at(&index, 0), "mi_first");
        similar_asserts::assert_eq!(name_at(&index, 1), "mi_second");
        similar_asserts::assert_eq!(name_at(&index, 2), "mi_third");
        similar_asserts::assert_eq!(index.get("mi_first").copied(), Some(11));
        similar_asserts::assert_eq!(index.remove("mi_first"), Some(11));
        assert!(index.get("mi_first").is_none());
        assert!(!index.contains_key("mi_first"));
        similar_asserts::assert_eq!(index.code_size(), 3);
        similar_asserts::assert_eq!(index.insert("mi_first", 44), None);
        similar_asserts::assert_eq!(index.get("mi_first").copied(), Some(44));
        similar_asserts::assert_eq!(index.module_code(0).unwrap().curr, Some(44));

        // loaded_0 CONS-walk: reverse creation order of slots that have curr or old.
        index.set_old("mi_second", 22);
        let mut loaded = Vec::new();
        for i in 0..index.code_size() {
            let entry = index.module_code(i).unwrap();
            if entry.curr.is_some() || entry.old.is_some() {
                loaded.push(name_at(&index, i));
            }
        }
        loaded.reverse();
        similar_asserts::assert_eq!(
            loaded,
            vec![
                "mi_third".to_string(),
                "mi_second".to_string(),
                "mi_first".to_string()
            ]
        );
    }

    #[test]
    fn curr_old_on_load_share_one_module_slot() {
        let mut index = ModuleIndex::new();
        similar_asserts::assert_eq!(index.put_module("mi_one"), Some(0));
        similar_asserts::assert_eq!(index.insert("mi_one", 1), None);
        similar_asserts::assert_eq!(index.set_old("mi_one", 2), None);
        similar_asserts::assert_eq!(index.set_on_load("mi_one", 3), None);
        similar_asserts::assert_eq!(index.code_size(), 1);
        let entry = index.module_code(0).unwrap();
        similar_asserts::assert_eq!(entry.curr, Some(1));
        similar_asserts::assert_eq!(entry.old, Some(2));
        similar_asserts::assert_eq!(entry.on_load, Some(3));
        similar_asserts::assert_eq!(index.get("mi_one").copied(), Some(1));
        similar_asserts::assert_eq!(index.old("mi_one"), Some(2));
        similar_asserts::assert_eq!(index.on_load("mi_one"), Some(3));
        similar_asserts::assert_eq!(index.take_old("mi_one"), Some(2));
        similar_asserts::assert_eq!(index.take_on_load("mi_one"), Some(3));
        assert!(!index.has_old("mi_one"));
        assert!(!index.has_on_load("mi_one"));
        similar_asserts::assert_eq!(index.get("mi_one").copied(), Some(1));
        similar_asserts::assert_eq!(index.code_size(), 1);
    }

    #[test]
    fn make_current_old_then_insert_keeps_previous_curr_as_old() {
        // Port of beam_bif_load.c `delete_code` then `beam_load_finalize_code` writing curr.
        let mut index = ModuleIndex::new();
        similar_asserts::assert_eq!(index.insert("mi_reload", 1), None);
        similar_asserts::assert_eq!(index.make_current_old("mi_reload"), Some(1));
        similar_asserts::assert_eq!(index.get("mi_reload").copied(), None);
        similar_asserts::assert_eq!(index.old("mi_reload"), Some(1));
        similar_asserts::assert_eq!(index.insert("mi_reload", 2), None);
        similar_asserts::assert_eq!(index.get("mi_reload").copied(), Some(2));
        similar_asserts::assert_eq!(index.old("mi_reload"), Some(1));
        // A staging copy_module clone mutates dst only (`module_start_staging`).
        let mut staged = index.clone();
        similar_asserts::assert_eq!(staged.make_current_old("mi_reload"), Some(2));
        similar_asserts::assert_eq!(staged.insert("mi_reload", 3), None);
        similar_asserts::assert_eq!(index.get("mi_reload").copied(), Some(2));
        similar_asserts::assert_eq!(index.old("mi_reload"), Some(1));
        similar_asserts::assert_eq!(staged.get("mi_reload").copied(), Some(3));
        similar_asserts::assert_eq!(staged.old("mi_reload"), Some(2));
    }

    #[test]
    fn staging_clone_copies_curr_old_on_load() {
        // Port of module.c `copy_module` / `module_start_staging`.
        let mut src = ModuleIndex::new();
        src.insert("mi_staged", 7);
        src.set_old("mi_staged", 8);
        src.set_on_load("mi_other", 9);
        let dst = src.clone();
        similar_asserts::assert_eq!(dst.code_size(), src.code_size());
        similar_asserts::assert_eq!(dst.get("mi_staged").copied(), Some(7));
        similar_asserts::assert_eq!(dst.old("mi_staged"), Some(8));
        similar_asserts::assert_eq!(dst.on_load("mi_other"), Some(9));
        similar_asserts::assert_eq!(name_at(&dst, 0), "mi_staged");
        similar_asserts::assert_eq!(name_at(&dst, 1), "mi_other");
    }

    #[test]
    fn abort_erases_modules_put_after_staging_started() {
        // Port of module.c `module_end_staging` abort / index.c `index_erase_latest_from`.
        let mut index = ModuleIndex::new();
        index.put_module("mi_keep");
        let entries = index.code_size();
        index.put_module("mi_aborted");
        index.insert("mi_aborted", 1);
        index.erase_latest_from(entries);
        similar_asserts::assert_eq!(index.code_size(), entries);
        assert!(index.entry("mi_keep").is_some());
        assert!(index.entry("mi_aborted").is_none());
        assert!(!index.contains_key("mi_aborted"));
        similar_asserts::assert_eq!(index.put_module("mi_keep"), Some(0));
        similar_asserts::assert_eq!(index.put_module("mi_new"), Some(1));
    }

    #[test]
    fn hash_grows_and_clone_keeps_every_module() {
        let mut index = ModuleIndex::new();
        for i in 0..300 {
            let name = format!("mi_grow_{i}");
            similar_asserts::assert_eq!(index.put_module(&name), Some(i));
            similar_asserts::assert_eq!(index.insert(&name, i + 1000), None);
        }
        similar_asserts::assert_eq!(index.code_size(), 300);
        assert!(index.htable.buckets.len() > 64, "rehash should have grown");
        for i in 0..300 {
            let name = format!("mi_grow_{i}");
            similar_asserts::assert_eq!(index.get(&name).copied(), Some(i + 1000));
            similar_asserts::assert_eq!(index.module_code(i).unwrap().curr, Some(i + 1000));
        }
        let cloned = index.clone();
        similar_asserts::assert_eq!(cloned.code_size(), 300);
        for i in 0..300 {
            let name = format!("mi_grow_{i}");
            similar_asserts::assert_eq!(cloned.get(&name).copied(), Some(i + 1000));
        }
    }

    #[test]
    fn module_hash_is_atom_index() {
        let mut index = ModuleIndex::new();
        let atom = global_atoms().intern("mi_hash").expect("atom");
        index.put_module("mi_hash");
        let entry = index.entry(&atom).expect("module");
        similar_asserts::assert_eq!(entry.hvalue, u64::from(atom.0));
        similar_asserts::assert_eq!(entry.module, atom);
        similar_asserts::assert_eq!(entry.index, 0);
    }
}
