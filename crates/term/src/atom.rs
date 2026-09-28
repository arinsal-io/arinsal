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

/// Generated constants for all entries in OTP's `atom.names`.
pub mod atoms {
    include!(concat!(env!("OUT_DIR"), "/atoms.rs"));
}

type AtomShard = RwLock<HashMap<Arc<str>, Atom>>;
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
    limit: usize,
}

impl AtomTable {
    /// Create a table with the given maximum, including predefined atoms.
    pub fn new(limit: usize) -> Self {
        let shards = (0..64).map(|_| RwLock::new(HashMap::new())).collect();
        let table = Self {
            shards,
            names: RwLock::new(Vec::new()),
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
        names.push(AtomEntry {
            otp_hash: otp_atom_hash(name),
            text: text.clone(),
        });
        shard.insert(text, atom);
        Ok(atom)
    }

    /// Return atom text for a valid index.
    pub fn text(&self, atom: Atom) -> Option<Arc<str>> {
        self.names
            .read()
            .unwrap()
            .get(atom.0 as usize)
            .map(|entry| entry.text.clone())
    }

    /// OTP's stable atom hash, computed when the atom is interned.
    pub fn hash(&self, atom: Atom) -> Option<u32> {
        self.names
            .read()
            .unwrap()
            .get(atom.0 as usize)
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
