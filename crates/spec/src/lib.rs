//! OTP 29.1.1 generic opcode and BIF tables, generated from the bundled specs.

#![forbid(unsafe_code)]

/// Loader handling class of a BIF.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BifKind {
    /// Ordinary BIF.
    Bif,
    /// Operator or guard BIF.
    Ubif,
    /// BIF requiring garbage collection or the caller's location; invoked through an export entry.
    Hbif,
}

/// One declaration from OTP's `bif.tab`.
#[derive(Clone, Copy, Debug)]
pub struct BifSpec {
    /// Zero-based position in `bif.tab`.
    pub index: u16,
    /// Loader handling class.
    pub kind: BifKind,
    /// Defining module.
    pub module: &'static str,
    /// Unquoted function atom.
    pub name: &'static str,
    /// Function arity.
    pub arity: u8,
    /// Optional C entry point.
    pub c_name: Option<&'static str>,
}

include!(concat!(env!("OUT_DIR"), "/tables.rs"));

/// FNV-1a over the key bytes: the keys are static MFA names, so no hash flooding concern.
#[derive(Default)]
struct FnvHasher(u64);

impl std::hash::Hasher for FnvHasher {
    fn write(&mut self, bytes: &[u8]) {
        let mut hash = if self.0 == 0 {
            0xcbf2_9ce4_8422_2325
        } else {
            self.0
        };
        for byte in bytes {
            hash = (hash ^ u64::from(*byte)).wrapping_mul(0x0100_0000_01b3);
        }
        self.0 = hash;
    }

    fn finish(&self) -> u64 {
        self.0
    }
}

type BifIndex = std::collections::HashMap<
    (&'static str, &'static str, u8),
    usize,
    std::hash::BuildHasherDefault<FnvHasher>,
>;

// OTP registers these internal continuations from bif.c rather than listing them in the
// published bif.tab. Keep them after the generated table so the frozen spec stays untouched.
const DIRTY_CONTINUATION_BIFS: [BifSpec; 5] = [
    BifSpec {
        index: 553,
        kind: BifKind::Bif,
        module: "erts_internal",
        name: "dirty_bif_result",
        arity: 1,
        c_name: None,
    },
    BifSpec {
        index: 554,
        kind: BifKind::Bif,
        module: "erts_internal",
        name: "dirty_bif_exception",
        arity: 2,
        c_name: None,
    },
    BifSpec {
        index: 555,
        kind: BifKind::Bif,
        module: "erts_internal",
        name: "dirty_bif_trap",
        arity: 1,
        c_name: None,
    },
    BifSpec {
        index: 556,
        kind: BifKind::Bif,
        module: "erts_internal",
        name: "dirty_bif_trap",
        arity: 2,
        c_name: None,
    },
    BifSpec {
        index: 557,
        kind: BifKind::Bif,
        module: "erts_internal",
        name: "dirty_bif_trap",
        arity: 3,
        c_name: None,
    },
];

/// Find a BIF by MFA using an index built once. Port of erts/emulator/beam/export.c (the BIF
/// export lookup is a hash probe, not a search), OTP-29.1.1.
pub fn bif_lookup(module: &str, name: &str, arity: u8) -> Option<&'static BifSpec> {
    use std::sync::OnceLock;
    static INDEX: OnceLock<BifIndex> = OnceLock::new();
    let index = INDEX.get_or_init(|| {
        let mut index = BifIndex::default();
        for (at, bif) in BIFS.iter().enumerate() {
            // The first entry wins, as the sorted search did on duplicates.
            index.entry((bif.module, bif.name, bif.arity)).or_insert(at);
        }
        for bif in &DIRTY_CONTINUATION_BIFS {
            index
                .entry((bif.module, bif.name, bif.arity))
                .or_insert(BIFS.len() + (bif.index as usize - BIFS.len()));
        }
        index
    });
    let at = *index.get(&(module, name, arity))?;
    BIFS.get(at)
        .or_else(|| DIRTY_CONTINUATION_BIFS.get(at - BIFS.len()))
}
