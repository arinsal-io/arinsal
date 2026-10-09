//! Append-only atom storage. Per-shard read locks keep unrelated lookups independent.
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, OnceLock, RwLock};

/// Stable atom index. Its value matches the OTP preloaded atom order at startup.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Atom(pub u32);

/// Atom interning failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AtomError {
    /// More than 255 Unicode scalar values.
    TooLong,
    /// The configured table limit was reached.
    SystemLimit,
}

/// Generated constants for all entries in OTP's `atom.names`; `PREDEFINED` is the
/// whole generated `erl_atom_table.c` (`atom.names`, then the `bif.tab` atoms).
pub mod atoms {
    include!(concat!(env!("OUT_DIR"), "/atoms.rs"));
}

type AtomShard = RwLock<HashMap<Arc<str>, Atom>>;

const ATOM_CHUNK_SIZE: usize = 4096;

type AtomChunk = OnceLock<Box<[OnceLock<AtomEntry>]>>;

#[derive(Clone, Debug)]
struct AtomEntry {
    text: Arc<str>,
    otp_hash: u32,
}

// Port of erts/emulator/beam/atom.c:83 (atom_hash), OTP-29.1.1.
pub(crate) fn otp_atom_hash(text: &str) -> u32 {
    let bytes = text.as_bytes();
    let mut h = 0_u32;
    let mut i = 0;
    while i < bytes.len() {
        let mut v = bytes[i];
        if i + 1 < bytes.len() && (v & 0xfe) == 0xc2 && bytes[i + 1] & 0xc0 == 0x80 {
            v = (v << 6) | (bytes[i + 1] & 0x3f);
            i += 1;
        }
        h = (h << 4).wrapping_add(v as u32);
        let g = h & 0xf000_0000;
        if g != 0 {
            h ^= (g >> 24) ^ g;
        }
        i += 1;
    }
    h
}

/// Global, append-only table. Shared string owners avoid intentional leaks in Miri.
pub struct AtomTable {
    shards: Box<[AtomShard]>,
    names: RwLock<Vec<AtomEntry>>,
    entries: Box<[AtomChunk]>,
    limit: usize,
}

impl AtomTable {
    /// Create a table with the given maximum, including predefined atoms.
    pub fn new(limit: usize) -> Self {
        let shards = (0..64).map(|_| RwLock::new(HashMap::new())).collect();
        let index_limit = limit.min(u32::MAX as usize);
        let table = Self {
            shards,
            names: RwLock::new(Vec::new()),
            entries: (0..index_limit.div_ceil(ATOM_CHUNK_SIZE))
                .map(|_| OnceLock::new())
                .collect(),
            limit,
        };
        for name in atoms::PREDEFINED {
            let _ = table.intern(name).expect("predefined atoms fit");
        }
        table
    }

    fn shard(&self, name: &str) -> usize {
        let mut h = std::collections::hash_map::DefaultHasher::new();
        name.hash(&mut h);
        (h.finish() as usize) & (self.shards.len() - 1)
    }

    /// Find an atom without writing to the table.
    pub fn get(&self, name: &str) -> Option<Atom> {
        self.shards[self.shard(name)]
            .read()
            .unwrap()
            .get(name)
            .copied()
    }

    /// Intern UTF-8 atom text, preserving the first assigned index.
    pub fn intern(&self, name: &str) -> Result<Atom, AtomError> {
        if name.chars().count() > 255 {
            return Err(AtomError::TooLong);
        }
        if let Some(atom) = self.get(name) {
            return Ok(atom);
        }
        let mut shard = self.shards[self.shard(name)].write().unwrap();
        if let Some(atom) = shard.get(name) {
            return Ok(*atom);
        }
        let mut names = self.names.write().unwrap();
        if names.len() >= self.limit || names.len() >= u32::MAX as usize {
            return Err(AtomError::SystemLimit);
        }
        let text: Arc<str> = Arc::from(name);
        let atom = Atom(names.len() as u32);
        let entry = AtomEntry {
            otp_hash: otp_atom_hash(name),
            text: Arc::clone(&text),
        };
        names.push(entry.clone());
        let chunk_index = atom.0 as usize / ATOM_CHUNK_SIZE;
        let chunk_start = chunk_index * ATOM_CHUNK_SIZE;
        let chunk_len = (self.limit - chunk_start).min(ATOM_CHUNK_SIZE);
        let chunk = self.entries[chunk_index]
            .get_or_init(|| (0..chunk_len).map(|_| OnceLock::new()).collect());
        chunk[atom.0 as usize % ATOM_CHUNK_SIZE]
            .set(entry)
            .expect("atom indices are published once");
        shard.insert(text, atom);
        Ok(atom)
    }

    /// Return immutable atom text for a valid index without taking a lock.
    // Port of erts/emulator/beam/atom.c:107 (erts_atom_get_name), OTP-29.1.1.
    pub fn text(&self, atom: Atom) -> Option<&str> {
        let index = atom.0 as usize;
        self.entries
            .get(index / ATOM_CHUNK_SIZE)?
            .get()?
            .get(index % ATOM_CHUNK_SIZE)?
            .get()
            .map(|entry| entry.text.as_ref())
    }

    /// OTP's stable atom hash, computed when the atom is interned.
    pub fn hash(&self, atom: Atom) -> Option<u32> {
        let index = atom.0 as usize;
        self.entries
            .get(index / ATOM_CHUNK_SIZE)?
            .get()?
            .get(index % ATOM_CHUNK_SIZE)?
            .get()
            .map(|entry| entry.otp_hash)
    }

    /// Number of atoms currently interned.
    pub fn len(&self) -> usize {
        self.names.read().unwrap().len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

static GLOBAL: OnceLock<AtomTable> = OnceLock::new();

/// The process-wide atom table, with OTP's default 1,048,576 entry limit.
pub fn global_atoms() -> &'static AtomTable {
    GLOBAL.get_or_init(|| AtomTable::new(1_048_576))
}
