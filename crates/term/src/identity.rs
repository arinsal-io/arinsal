//! Node and external identity layouts.
use crate::{
    Atom, EXTERNAL_PID, EXTERNAL_PORT, EXTERNAL_REF, REF, Term, TermError, atoms, global_atoms,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// Immutable node-table entry retained by every referencing heap.
#[derive(Debug)]
pub struct Node {
    /// Node name atom.
    pub name: Atom,
    /// Distribution creation number.
    pub creation: u32,
}
impl Node {
    /// Create a node-table entry.
    pub fn new(name: Atom, creation: u32) -> Arc<Self> {
        let node = Arc::new(Self { name, creation });
        live_node_registry()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(Arc::downgrade(&node));
        node
    }

    /// Return node identities retained by live external terms.
    pub fn live_nodes() -> Vec<Arc<Self>> {
        let mut registry = live_node_registry()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut nodes = Vec::new();
        registry.retain(|entry| {
            if let Some(node) = entry.upgrade() {
                nodes.push(node);
                true
            } else {
                false
            }
        });
        nodes
    }
}

fn live_node_registry() -> &'static std::sync::Mutex<Vec<std::sync::Weak<Node>>> {
    static NODES: std::sync::OnceLock<std::sync::Mutex<Vec<std::sync::Weak<Node>>>> =
        std::sync::OnceLock::new();
    NODES.get_or_init(|| std::sync::Mutex::new(Vec::new()))
}

/// Process identifier, port, or ordinary reference decoded from a tagged term.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Identity {
    /// Process index and generation on a node.
    Pid {
        node: Atom,
        creation: u32,
        index: u32,
        serial: u32,
    },
    /// Port number on a node.
    Port { node: Atom, creation: u32, id: u64 },
    /// Ordinary reference numbers on a node.
    Ref {
        node: Atom,
        creation: u32,
        ids: smallvec::SmallVec<[u32; 5]>,
    },
}
impl Term {
    /// Numbers of a local ordinary reference without allocating, as `identity` reads them.
    pub fn local_ref_numbers(self) -> Option<[u32; 3]> {
        let header = self.header()?;
        if header & 63 != REF {
            return None;
        }
        // SAFETY: a REF thing has at least the header and two data words.
        let (one, two) = unsafe {
            let p = self.raw_ptr();
            (*p.add(1), *p.add(2))
        };
        if crate::is_magic_ref_thing_with_hdr(header, one) {
            return None;
        }
        Some([(one >> 32) as u32, two as u32, (two >> 32) as u32])
    }

    /// Numbers of a local magic reference, read through its magic binary like
    /// erts `internal_magic_ref_numbers` reads `mb->refn`.
    // Port of erts/emulator/beam/erl_term.h:1083-1087 (internal_magic_thing_ref_numbers), OTP-29.1.1.
    pub(crate) fn magic_ref_numbers(self) -> Option<[u32; 3]> {
        // SAFETY: the magic binary is retained by the off-heap list of the term's heap.
        let id = unsafe { self.magic_ref() }?.id();
        Some([id as u32, (id >> 32) as u32, u32::MAX])
    }

    /// Read an identity as owned numeric fields.
    pub fn identity(self) -> Option<Identity> {
        if let Some((index, serial)) = self.as_pid() {
            return Some(Identity::Pid {
                node: atoms::NONAME,
                creation: 0,
                index,
                serial,
            });
        }
        if let Some(id) = self.as_port() {
            return Some(Identity::Port {
                node: atoms::NONAME,
                creation: 0,
                id,
            });
        }
        let header = self.header()?;
        // SAFETY: a valid identity's header determines initialized payload fields.
        let p = unsafe { self.raw_ptr() };
        match header & 63 {
            REF => Some(Identity::Ref {
                node: atoms::NONAME,
                creation: 0,
                ids: self
                    .local_ref_numbers()
                    .or_else(|| self.magic_ref_numbers())?
                    .into_iter()
                    .collect(),
            }),
            EXTERNAL_PID | EXTERNAL_PORT | EXTERNAL_REF => {
                // SAFETY: external thing stores a retained Node pointer at word one.
                let node = unsafe { &*(*p.add(1) as *const Node) };
                match header & 63 {
                    EXTERNAL_PID => {
                        // SAFETY: packed number and serial occupy one data word.
                        let data = unsafe { *p.add(3) };
                        Some(Identity::Pid {
                            node: node.name,
                            creation: node.creation,
                            index: data as u32,
                            serial: (data >> 32) as u32,
                        })
                    }
                    EXTERNAL_PORT => {
                        // SAFETY: port id occupies one data word.
                        let id = unsafe { *p.add(3) };
                        Some(Identity::Port {
                            node: node.name,
                            creation: node.creation,
                            id,
                        })
                    }
                    _ => {
                        // OTP packs the ETF arity before the 32-bit ids in the data words.
                        // SAFETY: the live reference header bounds its count and packed ids.
                        let ids = unsafe {
                            let count = (*p.add(3) as u32) as usize;
                            (0..count)
                                .map(|i| {
                                    let index = i + 1;
                                    let word = *p.add(3 + index / 2);
                                    if index % 2 == 0 {
                                        word as u32
                                    } else {
                                        (word >> 32) as u32
                                    }
                                })
                                .collect::<Vec<_>>()
                        };
                        Some(Identity::Ref {
                            node: node.name,
                            creation: node.creation,
                            ids: ids.into(),
                        })
                    }
                }
            }
            _ => None,
        }
    }
}

pub(crate) fn node_order(a: Atom, b: Atom) -> std::cmp::Ordering {
    global_atoms().text(a).cmp(&global_atoms().text(b))
}

/// Return a typed error if an external identity cannot fit the OTP layout.
pub(crate) fn check_external_ref(ids: &[u32]) -> Result<(), TermError> {
    if (1..=5).contains(&ids.len()) {
        Ok(())
    } else {
        Err(TermError::BadArg)
    }
}

/// `erts_this_node`: the name and creation that internal pids, ports and references compare
/// with, packed as `name << 32 | creation`. Set by the node table when the node gets its name.
static THIS_NODE: AtomicU64 = AtomicU64::new(0);

/// Publish the local node identity, as `erts_set_this_node` does for `erts_this_node`.
// Port of erts/emulator/beam/erl_node_tables.c (erts_set_this_node), OTP-29.1.1.
pub fn set_this_node(name: Atom, creation: u32) {
    THIS_NODE.store(
        (u64::from(name.0) << 32) | u64::from(creation),
        Ordering::Release,
    );
}

/// The local node name and creation; `nonode@nohost` and 0 until the node is named.
pub fn this_node() -> (Atom, u32) {
    match THIS_NODE.load(Ordering::Acquire) {
        0 => (atoms::NONAME, 0),
        packed => (Atom((packed >> 32) as u32), packed as u32),
    }
}
