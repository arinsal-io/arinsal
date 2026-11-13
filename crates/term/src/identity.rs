//! Node and external identity layouts.
use crate::{
    Atom, EXTERNAL_PID, EXTERNAL_PORT, EXTERNAL_REF, REF, Term, TermError, atoms, global_atoms,
};

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
    /// Decode a local creator PID from its serialized PID-reference words.
    ///
    /// Port of erts/emulator/beam/erl_bif_unique.h (`erts_get_pid_of_ref`), OTP-29.1.1.
    pub fn local_pid_ref_data_from_words(pid_low: u32, pid_high: u32) -> Option<u64> {
        Term(u64::from(pid_low) | (u64::from(pid_high) << 32)).as_pid_data()
    }

    /// Creator PID data stored in this local PID reference, if it is one.
    pub fn local_pid_ref_pid_data(self) -> Option<u64> {
        self.local_pid_ref_pid_word()?
            .and_then(|word| Term(word).as_pid_data())
    }

    /// Encoded creator PID word for a local PID reference; ordinary refs return `None` inside
    /// the outer option, while non-reference terms return no outer value.
    pub fn local_pid_ref_pid_word(self) -> Option<Option<u64>> {
        self.local_ref_parts().map(|(_, pid_word)| pid_word)
    }

    /// Numbers of a local ordinary reference without allocating, as `identity` reads them.
    pub fn local_ref_numbers(self) -> Option<[u32; 3]> {
        self.local_ref_parts().map(|(numbers, _)| numbers)
    }

    fn local_ref_parts(self) -> Option<([u32; 3], Option<u64>)> {
        let header = self.header()?;
        if header & 63 != REF {
            return None;
        }
        // SAFETY: ordinary and magic refs have three words; PID refs have four as identified
        // by their distinct header.
        let (one, two, pid_word) = unsafe {
            let p = self.raw_ptr();
            (
                *p.add(1),
                *p.add(2),
                (header == crate::PID_REF_THING_HEADER).then(|| *p.add(3)),
            )
        };
        if crate::is_magic_ref_thing_with_hdr(header, one) {
            return None;
        }
        Some((
            [(one >> 32) as u32, two as u32, (two >> 32) as u32],
            pid_word,
        ))
    }

    /// Numbers of a local magic reference, read through its magic binary like
    /// erts `internal_magic_ref_numbers` reads `mb->refn`.
    // Port of erts/emulator/beam/erl_term.h:1083-1087 (internal_magic_thing_ref_numbers), OTP-29.1.1.
    pub(crate) fn magic_ref_numbers(self) -> Option<[u32; 3]> {
        // SAFETY: the magic binary is retained by the off-heap list of the term's heap.
        unsafe { self.magic_ref() }?.ref_numbers().into()
    }

    /// Read an identity as owned numeric fields.
    // Port of erts/emulator/beam/external.c (`enc_term`, `REF_DEF`), OTP-29.1.1: a local PID
    // reference contributes its three ref numbers and the two words of its creator PID.
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
            REF => {
                let mut ids = self
                    .local_ref_numbers()
                    .or_else(|| self.magic_ref_numbers())?
                    .into_iter()
                    .collect::<smallvec::SmallVec<[u32; 5]>>();
                if let Some(Some(pid_word)) = self.local_pid_ref_pid_word() {
                    ids.push(pid_word as u32);
                    ids.push((pid_word >> 32) as u32);
                }
                Some(Identity::Ref {
                    node: atoms::NONAME,
                    creation: 0,
                    ids,
                })
            }
            EXTERNAL_PID | EXTERNAL_PORT | EXTERNAL_REF => {
                // SAFETY: a live external thing's node word names a referenced `ErlNode`.
                let node = crate::raw::node_entry(unsafe { *p.add(1) } as usize);
                match header & 63 {
                    EXTERNAL_PID => {
                        // SAFETY: packed number and serial occupy one data word.
                        let data = unsafe { *p.add(3) };
                        Some(Identity::Pid {
                            node: node.sysname(),
                            creation: node.creation(),
                            index: data as u32,
                            serial: (data >> 32) as u32,
                        })
                    }
                    EXTERNAL_PORT => {
                        // SAFETY: port id occupies one data word.
                        let id = unsafe { *p.add(3) };
                        Some(Identity::Port {
                            node: node.sysname(),
                            creation: node.creation(),
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
                            node: node.sysname(),
                            creation: node.creation(),
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
