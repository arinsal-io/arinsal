//! Node and external identity layouts.
use crate::{
    Atom, EXTERNAL_PID, EXTERNAL_PORT, EXTERNAL_REF, MAGIC_REF, REF, Term, TermError, atoms,
    global_atoms,
};
use std::sync::Arc;

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
        Arc::new(Self { name, creation })
    }
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
        ids: Vec<u32>,
    },
}
impl Term {
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
            MAGIC_REF => {
                // SAFETY: magic reference identity occupies word two.
                let id = unsafe { *p.add(2) };
                Some(Identity::Ref {
                    node: atoms::NONAME,
                    creation: 0,
                    ids: vec![id as u32, (id >> 32) as u32, u32::MAX],
                })
            }
            REF => {
                // SAFETY: ordinary reference has marker and three packed numbers.
                let (one, two) = unsafe { (*p.add(1), *p.add(2)) };
                Some(Identity::Ref {
                    node: atoms::NONAME,
                    creation: 0,
                    ids: vec![(one >> 32) as u32, two as u32, (two >> 32) as u32],
                })
            }
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
                        let count = if header >> 6 == 4 { 3 } else { 5 };
                        let mut ids = Vec::with_capacity(count);
                        for i in 0..count {
                            // SAFETY: ref header includes 2 or 3 packed data words.
                            let word = unsafe { *p.add(3 + i / 2) };
                            ids.push(if i % 2 == 0 {
                                word as u32
                            } else {
                                (word >> 32) as u32
                            });
                        }
                        Some(Identity::Ref {
                            node: node.name,
                            creation: node.creation,
                            ids,
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
    if ids.len() == 3 || ids.len() == 5 {
        Ok(())
    } else {
        Err(TermError::BadArg)
    }
}
