//! `ErtsDistExternal`: the still encoded payload of a distribution message, and its decode on
//! the receiving side.
//!
//! Port of erts/emulator/beam/external.h (`ErtsDistExternal`, `ErtsDistExternalData`,
//! `ERTS_DIST_EXT_*`) and erts/emulator/beam/external.c (`erts_decode_dist_ext_size`,
//! `erts_decode_dist_ext`, `bad_dist_ext`), OTP-29.1.1.

use super::external_dec_size::{B2tSizeState, decoded_size};
use super::external_dec_term::{DecFlags, dec_term};
use arinsal_term::raw::{HeapSlotPtr, term_from_bits};
use arinsal_term::{Atom, HeapReservation, Term};

/// `ERTS_DIST_EXT_DFLAG_HDR`: the payload follows a distribution header, without a
/// `VERSION_MAGIC` byte.
pub(crate) const ERTS_DIST_EXT_DFLAG_HDR: u32 = 0x1;
/// `ERTS_DIST_EXT_ATOM_TRANS_TAB`: `attab` translates `ATOM_CACHE_REF`s.
pub(crate) const ERTS_DIST_EXT_ATOM_TRANS_TAB: u32 = 0x2;

/// `VERSION_MAGIC`.
const VERSION_MAGIC: u8 = 131;

/// `ErtsDistExternalData`: the received bytes (`binp`) and the part not yet decoded
/// (`extp`..`ext_endp`, as offsets into `binp`). The fragments of a fragmented message are
/// joined by the dist entry before the message is queued (`reassemble_port_fragment`), so one
/// data block with `frag_id == 1` is all a message carries and `seq_id`/`frag_id` are not kept.
pub(crate) struct ErtsDistExternalData {
    pub(crate) extp: usize,
    pub(crate) ext_endp: usize,
    pub(crate) binp: Box<[u8]>,
}

/// `ErtsDistExternal` (external.h): what `erts_queue_dist_message` attaches to a message whose
/// term is `THE_NON_VALUE` until the receiver decodes it.
pub(crate) struct ErtsDistExternal {
    pub(crate) data: ErtsDistExternalData,
    pub(crate) flags: u32,
    pub(crate) connection_id: u32,
    /// `heap_size`: the decoded size in words, `-1` until `erts_decode_dist_ext_size` ran.
    pub(crate) heap_size: isize,
    /// `dep->sysname`.
    pub(crate) dep: Atom,
    /// `attab.atom[0..attab.size]`.
    pub(crate) attab: Box<[Atom]>,
    /// The completed `decoded_size` walk behind `heap_size`, which lets `dec_term` read the
    /// bytes it checked without walking them again.
    pub(crate) size_state: B2tSizeState,
}

impl ErtsDistExternal {
    /// The bytes not yet decoded (`extp`..`ext_endp`).
    fn ext(&self) -> &[u8] {
        &self.data.binp[self.data.extp..self.data.ext_endp]
    }

    /// The term bytes after the optional `VERSION_MAGIC`: with `ERTS_DIST_EXT_DFLAG_HDR` the
    /// payload must not start with it, without it the payload must.
    fn term_bytes(&self) -> Option<(usize, &[u8])> {
        let ext = self.ext();
        let first = *ext.first()?;
        if self.flags & ERTS_DIST_EXT_DFLAG_HDR != 0 {
            (first != VERSION_MAGIC).then_some((0, ext))
        } else {
            (first == VERSION_MAGIC).then_some((1, &ext[1..]))
        }
    }
}

/// `bad_dist_ext`: a payload that does not decode takes the connection down.
// Port of erts/emulator/beam/external.c (bad_dist_ext), OTP-29.1.1.
fn bad_dist_ext(runtime: Option<&crate::process::Runtime>, edep: &ErtsDistExternal) {
    let Some(runtime) = runtime else {
        return;
    };
    if let Some(node) = arinsal_term::global_atoms().text(edep.dep) {
        let _ = crate::dist::kill_connection(runtime, node, edep.connection_id);
    }
}

/// `erts_decode_dist_ext_size(edep, kill_connection, payload)`: the heap words the payload
/// decodes to, `-1` when it is malformed (the connection is killed when `kill_connection`).
/// A fragmented payload is joined when the dist entry reassembles it, before the message is
/// queued, so `frag_id` is always 1 here.
// Port of erts/emulator/beam/external.c (erts_decode_dist_ext_size), OTP-29.1.1.
pub(crate) fn erts_decode_dist_ext_size(
    runtime: Option<&crate::process::Runtime>,
    edep: &mut ErtsDistExternal,
    kill_connection: bool,
) -> isize {
    let mut sc = B2tSizeState::default();
    let size = edep.term_bytes().and_then(|(_, bytes)| {
        let mut reds = i64::MAX;
        decoded_size(bytes, &mut sc, &mut reds).ok().flatten()
    });
    edep.size_state = sc;
    match size {
        Some(words) => words as isize,
        None => {
            if kill_connection {
                bad_dist_ext(runtime, edep);
            }
            -1
        }
    }
}

/// `erts_decode_dist_ext(factory, edep, kill_connection)`: decode the next term of the
/// payload on `fac` and advance `extp` past it; `None` (`THE_NON_VALUE`) when it is malformed,
/// the caller undoing the factory (`erts_factory_undo`).
// Port of erts/emulator/beam/external.c (erts_decode_dist_ext), OTP-29.1.1.
pub(crate) fn erts_decode_dist_ext<H: arinsal_term::HeapAlloc + ?Sized>(
    runtime: Option<&crate::process::Runtime>,
    fac: &mut HeapReservation<'_, H>,
    edep: &mut ErtsDistExternal,
    kill_connection: bool,
) -> Option<Term> {
    let decoded = decode_term(fac, edep);
    match decoded {
        Some((obj, used)) => {
            edep.data.extp += used;
            Some(obj)
        }
        None => {
            if kill_connection {
                bad_dist_ext(runtime, edep);
            }
            None
        }
    }
}

/// `dec_term(edep, factory, ep, &obj, NULL, 0)` over the payload: the term and the bytes
/// consumed, counting the `VERSION_MAGIC`.
fn decode_term<H: arinsal_term::HeapAlloc + ?Sized>(
    fac: &mut HeapReservation<'_, H>,
    edep: &ErtsDistExternal,
) -> Option<(Term, usize)> {
    let (magic, bytes) = edep.term_bytes()?;
    // dec_term reads only a payload `erts_decode_dist_ext_size` accepted.
    let validated = edep.size_state.validated_bytes(bytes)?;
    let mut flags = DecFlags {
        safe: false,
        internal_nc: false,
        this_node: arinsal_term::this_node(),
        attab: (edep.flags & ERTS_DIST_EXT_ATOM_TRANS_TAB != 0).then_some(&edep.attab[..]),
    };
    let mut obj: u64 = 0;
    let slot = HeapSlotPtr::from_ptr(&mut obj)?;
    let ep = dec_term(fac, validated, 0, Some(slot), None, &mut flags)
        .ok()
        .flatten()?;
    Some((term_from_bits(obj), magic + ep))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn edep(payload: &[u8], attab: &[Atom]) -> ErtsDistExternal {
        ErtsDistExternal {
            data: ErtsDistExternalData {
                extp: 0,
                ext_endp: payload.len(),
                binp: payload.into(),
            },
            flags: ERTS_DIST_EXT_DFLAG_HDR | ERTS_DIST_EXT_ATOM_TRANS_TAB,
            connection_id: 0,
            heap_size: -1,
            dep: arinsal_term::atoms::NONAME,
            attab: attab.into(),
            size_state: B2tSizeState::default(),
        }
    }

    fn decode(edep: &mut ErtsDistExternal) -> Option<(Term, arinsal_term::message::NodeFragment)> {
        let need = erts_decode_dist_ext_size(None, edep, false);
        if need < 0 {
            return None;
        }
        let mut hfrag = arinsal_term::message::NodeFragment::new_message_buffer(need as usize);
        let term = {
            let mut target = hfrag.fragment_mut();
            let mut fac = HeapReservation::new(&mut target, need as usize).ok()?;
            erts_decode_dist_ext(None, &mut fac, edep, false)?
        };
        Some((term, hfrag))
    }

    /// `{ATOM_CACHE_REF 0, 1}` with `attab = [ok]` decodes to `{ok, 1}` and `extp` moves past
    /// the term.
    #[test]
    fn atom_cache_ref_translates_through_attab() {
        let mut edep = edep(&[104, 2, 82, 0, 97, 1], &[arinsal_term::atoms::OK]);
        let (term, _hfrag) = decode(&mut edep).expect("decodes");
        let tuple = arinsal_term::to_owned(term).unwrap();
        assert_eq!(
            tuple,
            arinsal_etf::OwnedTerm::Tuple(vec![
                arinsal_etf::OwnedTerm::atom("ok"),
                arinsal_etf::OwnedTerm::Int(1)
            ])
        );
        assert_eq!(edep.data.extp, edep.data.ext_endp);
    }

    /// A reference past `attab`, a `VERSION_MAGIC` after a distribution header and a truncated
    /// term do not decode (erts_decode_dist_ext_size / dec_atom errors).
    #[test]
    fn bad_payloads_do_not_decode() {
        assert!(decode(&mut edep(&[82, 1], &[arinsal_term::atoms::OK])).is_none());
        assert!(decode(&mut edep(&[131, 97, 1], &[])).is_none());
        assert!(decode(&mut edep(&[104, 2, 97], &[])).is_none());
    }
}
