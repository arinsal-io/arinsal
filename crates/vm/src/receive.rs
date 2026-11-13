//! Selective receive state owned by the running process: the receive marker block and the
//! save pointer operations of the message queue.

use crate::process::{Message, MessageNode, SaveField, queued_term};
use crate::{Process, VmError};
use arinsal_sched::{
    Event, RECV_MARKER_TYPE_PRIO_Q_CONT, RECV_MARKER_TYPE_PRIO_Q_END, RECV_MARKER_TYPE_RECV,
    RECV_MARKER_TYPE_YIELD, RecvMarker,
};
use arinsal_term::Term;
use std::sync::atomic::Ordering;

// Port of erts/emulator/beam/erl_message.h:322 (ERTS_RECV_MARKER_BLOCK_SIZE)
// and erl_proc_sig_queue.h:276 (ERTS_RECV_MARKER_PASS_MAX), OTP-29.1.1.
const MARKER_SLOTS: usize = 8;
const MARKER_PASS_MAX: i8 = 4;

type Marker = RecvMarker<Event<Message>>;

/// `blkp->ref[ix]`: what a marker of the block is bound to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum MarkerRef {
    /// `am_free`: the marker is on the free list.
    Free,
    /// `am_undefined`: cleared or bound to a non-reference; reused first.
    Undefined,
    /// `NIL`: the marker of `erts_msgq_recv_marker_create_insert_set_save`.
    Nil,
    /// The small integer `recv_marker_reserve` returned.
    Id(i64),
    /// The ordinary reference the marker was bound to (its key).
    Ref(u64),
}

/// A marker node never becomes a signal value: the queues hand marker nodes back to the
/// block (`ERTS_SIG_Q_OP_RECV_MARK` is handled on the node itself).
fn marker_value(_: std::ptr::NonNull<u8>) -> Event<Message> {
    unreachable!("a receive marker node has no signal value")
}

/// `ErtsRecvMarkerBlock`: the receive markers of a process, allocated when the first is.
// Port of erts/emulator/beam/erl_message.h:324-332 (ErtsRecvMarkerBlock), OTP-29.1.1.
pub(crate) struct ReceiveMarkers {
    refs: [MarkerRef; MARKER_SLOTS],
    marker: [Marker; MARKER_SLOTS],
    free_ix: i8,
    used_ix: i8,
    unused: i8,
    pending_set_save_ix: i8,
    set_save_ix: i8,
}

impl ReceiveMarkers {
    /// A block with marker 0 allocated for `uniq` and the rest on the free list.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:4102 (recv_marker_alloc_block),
    // OTP-29.1.1.
    fn new_block(uniq: MarkerRef) -> Box<Self> {
        let mut blk = Box::new(Self {
            refs: [MarkerRef::Free; MARKER_SLOTS],
            marker: Default::default(),
            free_ix: 1,
            used_ix: 0,
            unused: 0,
            pending_set_save_ix: -1,
            set_save_ix: -1,
        });
        blk.refs[0] = uniq;
        blk.marker[0].next_ix = 0;
        blk.marker[0].prev_ix = 0;
        for ix in 1..MARKER_SLOTS {
            blk.marker[ix].next_ix = if ix == MARKER_SLOTS - 1 {
                -1
            } else {
                ix as i8 + 1
            };
        }
        blk
    }

    /// The index of the marker at `addr`.
    fn ix_of(&self, addr: usize) -> usize {
        let base = self.marker.as_ptr() as usize;
        let ix = (addr - base) / std::mem::size_of::<Marker>();
        debug_assert!(ix < MARKER_SLOTS && std::ptr::from_ref(&self.marker[ix]) as usize == addr);
        ix
    }

    fn find(&self, id: MarkerRef) -> Option<usize> {
        self.refs.iter().position(|&r| r == id)
    }

    /// `ERTS_PROC_SIG_RECV_MARK_CLEAR_PENDING_SET_SAVE__`.
    fn clear_pending_set_save(&mut self) {
        if self.pending_set_save_ix >= 0 {
            let ix = self.pending_set_save_ix as usize;
            debug_assert!(self.marker[ix].in_msgq == 0 && self.marker[ix].set_save != 0);
            self.marker[ix].set_save = 0;
            self.pending_set_save_ix = -1;
        }
    }

    /// Return marker `ix` to the free list; `true` when it was the last allocated marker and
    /// the block is to be freed.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:3999 (recv_marker_deallocate),
    // OTP-29.1.1.
    fn deallocate(&mut self, ix: usize) -> bool {
        debug_assert_eq!(self.marker[ix].mark_type, RECV_MARKER_TYPE_RECV);
        let nix = self.marker[ix].next_ix;
        if nix as usize == ix {
            return true;
        }
        let pix = self.marker[ix].prev_ix;
        if self.refs[ix] == MarkerRef::Undefined {
            self.unused -= 1;
        }
        self.marker[pix as usize].next_ix = nix;
        self.marker[nix as usize].prev_ix = pix;
        if self.used_ix as usize == ix {
            self.used_ix = nix;
        }
        self.marker[ix].next_ix = self.free_ix;
        self.free_ix = ix as i8;
        self.refs[ix] = MarkerRef::Free;
        false
    }

    #[cfg(any(test, feature = "pf-mem-counters"))]
    pub(crate) fn len(&self) -> usize {
        self.refs
            .iter()
            .filter(|r| !matches!(r, MarkerRef::Free | MarkerRef::Undefined))
            .count()
    }
}

/// `sig_qs.flags` bits of the prio queue (erl_process.h:1675-1677).
pub(crate) const FS_PRIO_MQ_SAVE: u8 = 1 << 0;
pub(crate) const FS_PRIO_MQ_END_MARK: u8 = 1 << 1;
/// The save info of `sig_qs.flags` (erl_process.h:1705-1710): how the save pointer was set.
const FS_SET_SAVE_INFO_MASK: u8 = 3 << 2;
const FS_SET_SAVE_INFO_FIRST: u8 = 0;
const FS_SET_SAVE_INFO_RCVM: u8 = 1 << 2;
const FS_SET_SAVE_INFO_MARK: u8 = 2 << 2;
const FS_SET_SAVE_INFO_LAST: u8 = 3 << 2;

const PRIO_Q_MARK_END: usize = 0;
const PRIO_Q_MARK_CONT: usize = 1;

/// `ErtsPrioQInfo`: the end marker of the prio queue and the marker where a receive
/// continues once it passed the prio queue.
// Port of erts/emulator/beam/erl_proc_sig_queue.c:247-258 (ErtsPrioQInfo) and 9005
// (create_prio_q_info), OTP-29.1.1.
pub(crate) struct PrioQInfo {
    saved_save_info: u8,
    marker: [Marker; 2],
}

impl PrioQInfo {
    fn new() -> Box<Self> {
        let mut pq = Box::new(Self {
            saved_save_info: 0,
            marker: Default::default(),
        });
        pq.marker[PRIO_Q_MARK_END].mark_type = RECV_MARKER_TYPE_PRIO_Q_END;
        pq.marker[PRIO_Q_MARK_CONT].mark_type = RECV_MARKER_TYPE_PRIO_Q_CONT;
        for marker in &mut pq.marker {
            marker.pass = 100;
            marker.next_ix = -100;
            marker.prev_ix = -100;
        }
        pq
    }
}

/// The marker structures of the process, taken out of its cold part for an operation on
/// them and the queues together (the boxes keep the markers in place).
#[derive(Default)]
struct Markers {
    blk: Option<Box<ReceiveMarkers>>,
    pq: Option<Box<PrioQInfo>>,
}

/// Which marker a marker node is.
enum WhichMarker {
    Recv(usize),
    PrioEnd,
    PrioCont,
}

impl Markers {
    fn which(&self, addr: usize) -> WhichMarker {
        if let Some(pq) = self.pq.as_ref() {
            if std::ptr::from_ref(&pq.marker[PRIO_Q_MARK_END]) as usize == addr {
                return WhichMarker::PrioEnd;
            }
            if std::ptr::from_ref(&pq.marker[PRIO_Q_MARK_CONT]) as usize == addr {
                return WhichMarker::PrioCont;
            }
        }
        WhichMarker::Recv(
            self.blk
                .as_ref()
                .expect("a queued marker has its block")
                .ix_of(addr),
        )
    }
}

// Port of erts/emulator/beam/erl_proc_sig_queue.c:9138-9297, OTP-29.1.1.
fn contains_reference(term: &arinsal_etf::OwnedTerm, reference: u64) -> bool {
    use arinsal_etf::OwnedTerm;

    match term {
        OwnedTerm::Ref {
            node,
            creation: 0,
            ids,
        } if node == "nonode@nohost"
            && ids.len() == 3
            && arinsal_bifs::ordinary_ref_key([ids[0], ids[1], ids[2]]) == reference =>
        {
            true
        }
        OwnedTerm::List { elems, tail } => {
            elems.iter().any(|term| contains_reference(term, reference))
                || contains_reference(tail, reference)
        }
        OwnedTerm::Tuple(elements) => elements
            .iter()
            .any(|term| contains_reference(term, reference)),
        OwnedTerm::Map(pairs) => pairs.iter().any(|(key, value)| {
            contains_reference(key, reference) || contains_reference(value, reference)
        }),
        OwnedTerm::Fun { pid, free_vars, .. } => {
            contains_reference(pid, reference)
                || free_vars
                    .iter()
                    .any(|term| contains_reference(term, reference))
        }
        OwnedTerm::Record { fields, .. } => fields
            .iter()
            .any(|(_, term)| contains_reference(term, reference)),
        _ => false,
    }
}

impl Process {
    fn take_markers(&mut self) -> Markers {
        match self.cold.as_mut() {
            Some(cold) => Markers {
                blk: cold.receive_markers.take(),
                pq: cold.prio_q.take(),
            },
            None => Markers::default(),
        }
    }

    fn put_markers(&mut self, markers: Markers) {
        if markers.blk.is_none() && markers.pq.is_none() && self.cold.is_none() {
            return;
        }
        let cold = self.cold_mut();
        cold.receive_markers = markers.blk;
        cold.prio_q = markers.pq;
    }

    /// Run `f` with the marker structures taken out of the process; what `f` leaves goes back.
    fn with_markers<R>(&mut self, f: impl FnOnce(&mut Self, &mut Markers) -> R) -> R {
        let mut markers = self.take_markers();
        let result = f(self, &mut markers);
        self.put_markers(markers);
        result
    }

    /// Run `f` with the marker block taken out of the process.
    fn with_marker_block<R>(
        &mut self,
        f: impl FnOnce(&mut Self, &mut Option<Box<ReceiveMarkers>>) -> R,
    ) -> R {
        self.with_markers(|process, markers| f(process, &mut markers.blk))
    }

    fn save_info(&self) -> u8 {
        self.inbox.flags & FS_SET_SAVE_INFO_MASK
    }

    fn set_save_info(&mut self, info: u8) {
        self.inbox.flags = (self.inbox.flags & !FS_SET_SAVE_INFO_MASK) | info;
    }

    /// `remove_prio_q_marker`.
    fn remove_prio_q_marker(&mut self, pq: &mut PrioQInfo, which: usize) {
        self.inbox.entries.remove_marker(&mut pq.marker[which]);
        pq.marker[which].in_msgq = 0;
        pq.marker[which].in_sigq = 0;
    }

    /// `destroy_prio_q_info`: the prio queue markers leave the message queue.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:9065 (destroy_prio_q_info), OTP-29.1.1.
    fn destroy_prio_q_info(&mut self, markers: &mut Markers) {
        if let Some(mut pq) = markers.pq.take() {
            for which in [PRIO_Q_MARK_END, PRIO_Q_MARK_CONT] {
                if pq.marker[which].in_msgq != 0 {
                    self.remove_prio_q_marker(&mut pq, which);
                }
            }
        }
        if let Some(blk) = markers.blk.as_mut() {
            for marker in &mut blk.marker {
                marker.in_prioq = 0;
            }
        }
    }

    /// Pass the markers starting at `field`: a receive marker passed more than
    /// `ERTS_RECV_MARKER_PASS_MAX` times (or any, when `leading`) is dequeued; the end of
    /// the prio queue sends the save pointer where the receive continues.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:4431 (msgq_pass_recv_markers) and
    // 4046 (recv_marker_dequeue), OTP-29.1.1.
    fn msgq_pass_recv_markers(
        &mut self,
        markers: &mut Markers,
        mut field: SaveField,
        leading: bool,
    ) -> SaveField {
        while let Some(addr) = self.inbox.entries.marker_at(field) {
            match markers.which(addr) {
                WhichMarker::Recv(ix) => {
                    let b = markers.blk.as_mut().expect("a queued marker has its block");
                    match b.marker[ix].mark_type {
                        RECV_MARKER_TYPE_RECV => {
                            let dequeue = leading || {
                                b.marker[ix].pass += 1;
                                b.marker[ix].pass > MARKER_PASS_MAX
                            };
                            if !dequeue {
                                field = b.marker[ix].next_field();
                                continue;
                            }
                            debug_assert!(b.marker[ix].in_sigq > 0 && b.marker[ix].in_msgq != 0);
                            self.inbox.entries.remove_marker(&mut b.marker[ix]);
                            let marker = &mut b.marker[ix];
                            marker.in_prioq = 0;
                            marker.in_msgq = 0;
                            marker.in_sigq = 0;
                            if b.deallocate(ix) {
                                markers.blk = None;
                            }
                        }
                        RECV_MARKER_TYPE_YIELD => field = b.marker[ix].next_field(),
                        kind => unreachable!("marker type {kind} in the marker block"),
                    }
                }
                WhichMarker::PrioEnd => {
                    if leading && self.save_info() == FS_SET_SAVE_INFO_FIRST {
                        // Empty prio queue; remove the end marker.
                        self.inbox.flags &= !(FS_PRIO_MQ_SAVE | FS_PRIO_MQ_END_MARK);
                        self.destroy_prio_q_info(markers);
                    } else {
                        self.inbox.flags &= !FS_PRIO_MQ_SAVE;
                        if self.save_info() != FS_SET_SAVE_INFO_FIRST {
                            return self.msgq_pass_recv_markers_prioq_end(markers);
                        }
                        field = markers.pq.as_mut().expect("prio queue info").marker
                            [PRIO_Q_MARK_END]
                            .next_field();
                    }
                }
                WhichMarker::PrioCont => {
                    let pq = markers.pq.as_mut().expect("prio queue info");
                    self.remove_prio_q_marker(pq, PRIO_Q_MARK_CONT);
                }
            }
        }
        field
    }

    /// The end of the prio queue was reached: continue where the save pointer was before
    /// the prio queue got its messages.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:4484 (msgq_pass_recv_markers_prioq_end),
    // OTP-29.1.1.
    fn msgq_pass_recv_markers_prioq_end(&mut self, markers: &mut Markers) -> SaveField {
        let field = match self.save_info() {
            FS_SET_SAVE_INFO_MARK => {
                let pq = markers.pq.as_mut().expect("prio queue info");
                let saved = pq.saved_save_info;
                let field = pq.marker[PRIO_Q_MARK_CONT].prev_next();
                self.remove_prio_q_marker(pq, PRIO_Q_MARK_CONT);
                self.set_save_info(saved);
                field
            }
            FS_SET_SAVE_INFO_RCVM => {
                let blk = markers.blk.as_mut().expect("a receive marker block");
                let ix = blk.set_save_ix as usize;
                if blk.marker[ix].in_msgq != 0 {
                    blk.marker[ix].next_field()
                } else {
                    self.recv_marker_pending_set_save(blk, ix);
                    self.inbox.entries.last_field()
                }
            }
            _ => unreachable!("invalid message queue state at the end of the prio queue"),
        };
        self.msgq_pass_recv_markers(markers, field, false)
    }

    /// Pass the markers at the save pointer, if any (`erts_msgq_pass_recv_markers`).
    #[inline(always)]
    pub(crate) fn pass_markers_at_save(&mut self) {
        let save = self.inbox.entries.save_field();
        if self.inbox.entries.marker_at(save).is_some() {
            self.with_markers(|process, markers| {
                let field = process.msgq_pass_recv_markers(markers, save, false);
                process.inbox.pass_save_to(field);
            });
        }
    }

    /// `erts_msgq_set_save_first`: leave the receive; leading markers are passed (receive
    /// markers removed, an empty prio queue's end marker too).
    // Port of erts/emulator/beam/erl_proc_sig_queue.h:2331 (erts_msgq_set_save_first) and
    // erl_proc_sig_queue.c:4591 (erts_msgq_remove_leading_recv_markers_set_save_first),
    // OTP-29.1.1.
    pub(crate) fn msgq_set_save_first(&mut self) {
        if let Some(blk) = self
            .cold
            .as_mut()
            .and_then(|cold| cold.receive_markers.as_mut())
        {
            blk.clear_pending_set_save();
        }
        if self.inbox.flags & FS_PRIO_MQ_END_MARK != 0 {
            self.inbox.flags |= FS_PRIO_MQ_SAVE;
        }
        self.set_save_info(FS_SET_SAVE_INFO_FIRST);
        self.inbox.set_save_first();
        let first = self.inbox.entries.save_field();
        if self.inbox.entries.marker_at(first).is_some() {
            self.with_markers(|process, markers| {
                let field = process.msgq_pass_recv_markers(markers, first, true);
                process.inbox.pass_save_to(field);
            });
        }
    }

    /// `erts_msgq_set_save_end`.
    // Port of erts/emulator/beam/erl_proc_sig_queue.h:2397, OTP-29.1.1 (the caller fetched).
    pub(crate) fn msgq_set_save_end(&mut self) {
        if self.sig_cont_empty() {
            self.inbox.set_save_end();
            self.inbox.flags &= !FS_PRIO_MQ_SAVE;
        } else {
            self.recv_marker_create_insert_set_save();
        }
        self.set_save_info(FS_SET_SAVE_INFO_LAST);
    }

    /// Link a priority message at the end of the prio queue; a save pointer outside the prio
    /// queue moves before it, a marker remembering where to continue.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:9300
    // (insert_prepared_prio_msg_attached), OTP-29.1.1.
    pub(crate) fn insert_prio_message(&mut self, node: MessageNode) -> Result<Term, VmError> {
        let message = queued_term(&node);
        let mut markers = self.take_markers();
        let result = self.insert_prio_message_with(&mut markers, node, message);
        self.put_markers(markers);
        result.map(|()| message)
    }

    fn insert_prio_message_with(
        &mut self,
        markers: &mut Markers,
        node: MessageNode,
        message: Term,
    ) -> Result<(), VmError> {
        let empty_prio_q = self.inbox.flags & FS_PRIO_MQ_END_MARK == 0;
        if let Some(blk) = markers.blk.as_mut() {
            // References of receive markers seen in this prio message (`in_prioq`).
            let mut owned = None;
            for ix in 0..MARKER_SLOTS {
                if empty_prio_q {
                    blk.marker[ix].in_prioq = 0;
                }
                if let MarkerRef::Ref(reference) = blk.refs[ix]
                    && blk.marker[ix].in_sigq != 0
                    && blk.marker[ix].in_prioq == 0
                {
                    if owned.is_none() {
                        owned = Some(arinsal_term::to_owned(message).map_err(|error| {
                            VmError::Unsupported(format!(
                                "priority marker message copy ({:?}): {error:?}",
                                message.classify()
                            ))
                        })?);
                    }
                    if contains_reference(owned.as_ref().expect("copied"), reference) {
                        blk.marker[ix].in_prioq = 1;
                    }
                }
            }
        }
        let mut pq = markers.pq.take().unwrap_or_else(PrioQInfo::new);
        if self.inbox.flags & FS_PRIO_MQ_SAVE == 0 {
            let set_save = match self.save_info() {
                FS_SET_SAVE_INFO_FIRST => true,
                FS_SET_SAVE_INFO_LAST => false,
                FS_SET_SAVE_INFO_RCVM => markers
                    .blk
                    .as_ref()
                    .is_some_and(|blk| blk.marker[blk.set_save_ix as usize].in_prioq != 0),
                _ => unreachable!("save mark set while save is outside the prio queue"),
            };
            if empty_prio_q {
                let first = self.inbox.entries.first_field();
                self.inbox.entries.insert_marker_at(
                    first,
                    &mut pq.marker[PRIO_Q_MARK_END],
                    marker_value,
                );
                self.inbox.flags |= FS_PRIO_MQ_END_MARK;
            }
            if set_save {
                if pq.marker[PRIO_Q_MARK_CONT].in_msgq != 0 {
                    self.remove_prio_q_marker(&mut pq, PRIO_Q_MARK_CONT);
                }
                let save = self.inbox.entries.save_field();
                self.inbox.entries.insert_marker_at(
                    save,
                    &mut pq.marker[PRIO_Q_MARK_CONT],
                    marker_value,
                );
                pq.saved_save_info = self.save_info();
                self.set_save_info(FS_SET_SAVE_INFO_MARK);
                let end = pq.marker[PRIO_Q_MARK_END].prev_next();
                self.inbox.entries.set_save_field(end);
                self.inbox.flags |= FS_PRIO_MQ_SAVE;
            }
        }
        self.inbox
            .entries
            .insert_before_marker(&mut pq.marker[PRIO_Q_MARK_END], node);
        markers.pq = Some(pq);
        Ok(())
    }

    /// Allocate a marker for `uniq`: a free one, or the least recently allocated (preferably
    /// unused) one that is in the message queue. `None` when every marker waits in the
    /// middle queue.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:4148 (recv_marker_reuse) and 4243
    // (recv_marker_alloc), OTP-29.1.1.
    fn recv_marker_alloc(
        &mut self,
        blk: &mut Option<Box<ReceiveMarkers>>,
        uniq: MarkerRef,
    ) -> Option<usize> {
        let Some(b) = blk.as_mut() else {
            *blk = Some(ReceiveMarkers::new_block(uniq));
            return Some(0);
        };
        let ix = if b.free_ix >= 0 {
            let ix = b.free_ix as usize;
            let used_ix = b.used_ix;
            b.free_ix = b.marker[ix].next_ix;
            let pix = b.marker[used_ix as usize].prev_ix;
            b.marker[ix].prev_ix = pix;
            b.marker[ix].next_ix = used_ix;
            b.marker[pix as usize].next_ix = ix as i8;
            b.marker[used_ix as usize].prev_ix = ix as i8;
            ix
        } else {
            let used_ix = b.used_ix as usize;
            if b.marker[used_ix].in_msgq == 0 {
                return None;
            }
            let ix = if b.unused == 0 || b.refs[used_ix] == MarkerRef::Undefined {
                if b.refs[used_ix] == MarkerRef::Undefined {
                    b.unused -= 1;
                }
                b.used_ix = b.marker[used_ix].next_ix;
                used_ix
            } else {
                let mut ix = b.marker[used_ix].next_ix as usize;
                let found = loop {
                    if b.marker[ix].in_msgq == 0 {
                        break None;
                    }
                    if b.refs[ix] == MarkerRef::Undefined {
                        b.unused -= 1;
                        break Some(ix);
                    }
                    ix = b.marker[ix].next_ix as usize;
                };
                match found {
                    None => {
                        b.used_ix = b.marker[used_ix].next_ix;
                        used_ix
                    }
                    Some(ix) => {
                        // Move it to be the most recently allocated marker.
                        let pix = b.marker[ix].prev_ix;
                        let nix = b.marker[ix].next_ix;
                        b.marker[pix as usize].next_ix = nix;
                        b.marker[nix as usize].prev_ix = pix;
                        let pix = b.marker[used_ix].prev_ix;
                        b.marker[used_ix].prev_ix = ix as i8;
                        b.marker[pix as usize].next_ix = ix as i8;
                        b.marker[ix].next_ix = used_ix as i8;
                        b.marker[ix].prev_ix = pix;
                        ix
                    }
                }
            };
            debug_assert!(b.marker[ix].in_sigq != 0 && b.marker[ix].set_save == 0);
            self.inbox.entries.remove_marker(&mut b.marker[ix]);
            let marker = &mut b.marker[ix];
            marker.in_prioq = 0;
            marker.in_msgq = 0;
            marker.in_sigq = 0;
            ix
        };
        b.refs[ix] = uniq;
        Some(ix)
    }

    /// Link marker `ix` at the end of the message queue, or of the middle queue when signals
    /// wait there.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:4290 (recv_marker_insert), OTP-29.1.1.
    fn recv_marker_insert(&mut self, blk: &mut ReceiveMarkers, ix: usize, setting: bool) {
        let cont = !self.sig_cont().is_empty();
        let marker = &mut blk.marker[ix];
        marker.mark_type = RECV_MARKER_TYPE_RECV;
        marker.pass = 0;
        marker.set_save = 0;
        marker.in_sigq = 1;
        marker.in_prioq = 0;
        if !cont {
            marker.in_msgq = 1;
            self.inbox.entries.push_back(marker.signal(marker_value));
            if !setting && self.inbox.entries.save_field() == marker.prev_next() {
                // A marker that just entered the message queue through the middle queue.
                marker.pass += 1;
                let last = self.inbox.entries.last_field();
                self.inbox.pass_save_to(last);
            }
        } else {
            marker.in_msgq = 0;
            self.sig_cont_mut()
                .push_back_node(marker.signal(marker_value));
        }
    }

    /// Insert a receive marker after everything fetched so far, or `undefined` when both the
    /// message queue and the middle signal queue are empty or no marker can be had. The
    /// caller fetched the outer queue first.
    // Port of erts/emulator/beam/erl_proc_sig_queue.h:2226 (erts_msgq_recv_marker_insert)
    // and erl_proc_sig_queue.c:4366 (erts_msgq_recv_marker_create_insert), OTP-29.1.1.
    pub(crate) fn reserve_receive_marker(&mut self) -> Result<Term, VmError> {
        let undefined = Term::atom(arinsal_term::atoms::UNDEFINED);
        if self.sig_cont().is_empty() && self.inbox.is_empty() {
            return Ok(undefined);
        }
        // Port of erts/emulator/beam/erl_proc_sig_queue.c:4084 (recv_marker_uniq), OTP-29.1.1.
        let uniq = self
            .cold
            .as_ref()
            .map_or(0, |cold| cold.receive_marker_uniq);
        let id = arinsal_term::MIN_SMALL
            .checked_add(uniq)
            .filter(|id| Term::small(*id).is_some())
            .ok_or_else(|| VmError::Unsupported("receive marker id exceeds small range".into()))?;
        let inserted = self.with_marker_block(|process, blk| {
            let ix = process.recv_marker_alloc(blk, MarkerRef::Id(id))?;
            process.recv_marker_insert(blk.as_mut().expect("allocated"), ix, false);
            Some(())
        });
        if inserted.is_none() {
            return Ok(undefined);
        }
        self.cold_mut().receive_marker_uniq += 1;
        Ok(Term::small(id).expect("checked receive marker id"))
    }

    /// Insert a marker into the middle queue that sets the save pointer when it enters the
    /// message queue and is removed there.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:4380
    // (erts_msgq_recv_marker_create_insert_set_save), OTP-29.1.1.
    pub(crate) fn recv_marker_create_insert_set_save(&mut self) {
        self.with_markers(|process, markers| {
            let Some(ix) = process.recv_marker_alloc(&mut markers.blk, MarkerRef::Nil) else {
                return;
            };
            process.recv_marker_insert(markers.blk.as_mut().expect("allocated"), ix, true);
            process.recv_marker_set_save(markers, ix);
            let b = markers.blk.as_mut().expect("allocated");
            debug_assert!(b.marker[ix].in_msgq == 0 && b.marker[ix].set_save != 0);
            b.marker[ix].in_sigq = -1;
        });
    }

    /// Whether the middle signal queue is empty (`!c_p->sig_qs.cont`).
    pub(crate) fn sig_cont_empty(&self) -> bool {
        self.sig_cont().is_empty()
    }

    /// `ERTS_SIG_Q_OP_RECV_MARK`: a marker taken from the middle queue enters the message
    /// queue, or is deallocated when marked for removal; a pending set-save is applied.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:6893-6945, OTP-29.1.1.
    pub(crate) fn recv_marker_enter_msgq(
        &mut self,
        node: arinsal_sched::OwnedSignal<Event<Message>>,
    ) {
        let addr = RecvMarker::from_signal(node);
        self.with_marker_block(|process, blk| {
            let b = blk.as_mut().expect("a queued marker has its block");
            let ix = b.ix_of(addr);
            if b.marker[ix].in_sigq < 0 {
                if b.marker[ix].set_save != 0 {
                    process.inbox.set_save_end();
                    b.pending_set_save_ix = -1;
                    // All receive markers are outside of the prio queue.
                    process.inbox.flags &= !FS_PRIO_MQ_SAVE;
                }
                let marker = &mut b.marker[ix];
                marker.in_prioq = 0;
                marker.in_msgq = 0;
                marker.in_sigq = 0;
                marker.set_save = 0;
                if b.deallocate(ix) {
                    *blk = None;
                }
            } else {
                let marker = &mut b.marker[ix];
                marker.in_msgq = 1;
                process.inbox.entries.push_back(marker.signal(marker_value));
                if marker.set_save != 0 {
                    marker.set_save = 0;
                    // `save = &markp->sig.common.next`: the marker is the last node.
                    process.inbox.set_save_end();
                    b.pending_set_save_ix = -1;
                    process.inbox.flags &= !FS_PRIO_MQ_SAVE;
                }
            }
        });
    }

    /// `erts_msgq_recv_marker_bind`: a non-reference leaves the marker unused.
    // Port of erts/emulator/beam/erl_proc_sig_queue.h:2238, OTP-29.1.1.
    pub(crate) fn bind_receive_marker(&mut self, marker: Term, reference: Term) {
        if let Some(id) = marker.as_small()
            && let Some(blk) = self
                .cold
                .as_mut()
                .and_then(|cold| cold.receive_markers.as_mut())
            && let Some(ix) = blk.find(MarkerRef::Id(id))
        {
            match crate::signals::ref_id(reference) {
                Some(key) => blk.refs[ix] = MarkerRef::Ref(key),
                None => {
                    blk.unused += 1;
                    blk.refs[ix] = MarkerRef::Undefined;
                    blk.marker[ix].pass = MARKER_PASS_MAX;
                }
            }
        }
    }

    /// `erts_msgq_recv_marker_clear`.
    // Port of erts/emulator/beam/erl_proc_sig_queue.h:2203, OTP-29.1.1.
    pub(crate) fn clear_receive_marker(&mut self, term: Term) {
        let id = match crate::signals::ref_id(term) {
            Some(key) => MarkerRef::Ref(key),
            None => match term.as_small() {
                Some(id) => MarkerRef::Id(id),
                None => return,
            },
        };
        if let Some(blk) = self
            .cold
            .as_mut()
            .and_then(|cold| cold.receive_markers.as_mut())
            && let Some(ix) = blk.find(id)
        {
            blk.unused += 1;
            blk.refs[ix] = MarkerRef::Undefined;
            blk.marker[ix].pass = MARKER_PASS_MAX;
        }
    }

    /// `erts_msgq_recv_marker_pending_set_save__`: the marker is still in the middle queue;
    /// save at the end of the message queue so that `loop_rec` handles signals, and set the
    /// save pointer when the marker enters the message queue.
    // Port of erts/emulator/beam/erl_proc_sig_queue.h:2123, OTP-29.1.1.
    fn recv_marker_pending_set_save(&mut self, blk: &mut ReceiveMarkers, ix: usize) {
        self.inbox.set_save_end();
        // Save past the prio queue.
        self.inbox.flags &= !FS_PRIO_MQ_SAVE;
        blk.marker[ix].set_save = 1;
        debug_assert_eq!(blk.pending_set_save_ix, -1);
        blk.pending_set_save_ix = ix as i8;
    }

    /// `erts_msgq_recv_marker_set_save__`.
    // Port of erts/emulator/beam/erl_proc_sig_queue.h:2151, OTP-29.1.1.
    fn recv_marker_set_save(&mut self, markers: &mut Markers, ix: usize) {
        let blk = markers.blk.as_mut().expect("a receive marker block");
        blk.clear_pending_set_save();
        debug_assert!(blk.marker[ix].set_save == 0 && blk.marker[ix].in_sigq != 0);
        if blk.marker[ix].in_msgq == 0 {
            self.recv_marker_pending_set_save(blk, ix);
        } else {
            let field =
                if blk.marker[ix].in_prioq != 0 && self.inbox.flags & FS_PRIO_MQ_END_MARK != 0 {
                    // Messages with the reference were seen in the prio queue: scan it first.
                    self.inbox.flags |= FS_PRIO_MQ_SAVE;
                    self.inbox.entries.first_field()
                } else {
                    // The prio queue is empty or has no message with the reference.
                    blk.marker[ix].in_prioq = 0;
                    self.inbox.flags &= !FS_PRIO_MQ_SAVE;
                    blk.marker[ix].next_field()
                };
            let field = if self.inbox.entries.marker_at(field).is_some() {
                self.msgq_pass_recv_markers(markers, field, false)
            } else {
                field
            };
            self.inbox.set_save_field(field);
        }
        self.set_save_info(FS_SET_SAVE_INFO_RCVM);
        if let Some(blk) = markers.blk.as_mut() {
            blk.set_save_ix = ix as i8;
        }
    }

    /// `erts_msgq_recv_marker_set_save`: move the save pointer past the marker of
    /// `reference`.
    // Port of erts/emulator/beam/erl_proc_sig_queue.h:2281, OTP-29.1.1.
    pub(crate) fn use_receive_marker(&mut self, term: Term) {
        let Some(key) = crate::signals::ref_id(term) else {
            return;
        };
        self.with_markers(|process, markers| {
            let Some(ix) = markers
                .blk
                .as_ref()
                .and_then(|blk| blk.find(MarkerRef::Ref(key)))
            else {
                return;
            };
            process.recv_marker_set_save(markers, ix);
        });
    }

    pub(crate) fn loop_rec_end(&mut self) {
        // Port of erts/emulator/beam/erl_proc_sig_queue.h:2384 (erts_msgq_set_save_next),
        // OTP-29.1.1.
        self.inbox.set_save_next();
        self.pass_markers_at_save();
    }

    /// Removes the first message of a plain receive: no priority range, no receive marker, no
    /// memory breakpoint and no seq_trace token to apply. `Ok(false)` means the general path
    /// must run; nothing was changed then.
    // Port of erts/emulator/beam/erl_proc_sig_queue.h (erts_msgq_unlink_msg_set_save_first
    // with the save pointer at the first message), OTP-29.1.1.
    #[inline]
    pub(crate) fn remove_first_message(&mut self) -> Result<bool, VmError> {
        if !self.inbox.entries.save_is_first()
            || self.cold.as_ref().is_some_and(|cold| {
                cold.prio_q.is_some()
                    || cold.receive_markers.is_some()
                    || !cold.call_memory.is_empty()
            })
            || !self
                .inbox
                .pop_front_untokened(&mut self.heap, self.seq_trace_token.is_some())?
        {
            return Ok(false);
        }
        self.delay_gc = false;
        crate::natives::erts_debug::after_message_queue_change(self);
        self.cancel_receive_timer();
        Ok(true)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn remove_message(
        &mut self,
        ctx: Option<&mut arinsal_sched::RunCtx<'_, crate::process::Message>>,
    ) -> Result<(), VmError> {
        self.remove_message_inner(None, ctx)
    }

    fn remove_message_inner(
        &mut self,
        vm: Option<&mut crate::Vm>,
        ctx: Option<&mut arinsal_sched::RunCtx<'_, crate::process::Message>>,
    ) -> Result<(), VmError> {
        // Port of erts/emulator/beam/erl_message.c:975 (erts_save_message_in_proc,
        // erts_adjust_message_break), OTP-29.1.1: a message that was copied onto the heap is
        // counted by call_memory when it is received.
        let on_heap_words = if self
            .cold
            .as_ref()
            .is_some_and(|cold| !cold.call_memory.is_empty())
            && self.inbox.is_on_heap_at_save()
        {
            self.inbox
                .peek()
                .map_or(0, |term| arinsal_term::size_object(*term))
        } else {
            0
        };
        let removed_message = self.inbox.remove_to_heap_with_token(&mut self.heap)?;
        // Port of erts/emulator/beam/jit/beam_jit_common.cpp:1168-1171 (beam_jit_remove_message:
        // erts_save_message_in_proc, then F_DELAY_GC cleared), OTP-29.1.1.
        self.delay_gc = false;
        if on_heap_words != 0 {
            crate::trace_bp::adjust_memory_break(self, on_heap_words as i64);
        }
        let (term, state) = removed_message
            .ok_or_else(|| VmError::Unsupported("remove_message without current message".into()))?;

        // Native code removes messages without the run context; the process knows its pid.
        if crate::seq_trace::needs_receive(&state, self)
            && let Some(pid) = ctx
                .as_deref()
                .map(|run_ctx| run_ctx.pid())
                .or(self.self_pid)
        {
            let message =
                arinsal_term::to_owned(term).unwrap_or(arinsal_etf::OwnedTerm::atom("undefined"));
            crate::seq_trace::on_receive(vm, self, ctx, pid, state, message);
        }
        // Port of erts/emulator/beam/erl_proc_sig_queue.h:2367
        // (erts_msgq_unlink_msg_set_save_first), OTP-29.1.1.
        crate::natives::erts_debug::after_message_queue_change(self);
        self.msgq_set_save_first();
        self.cancel_receive_timer();
        Ok(())
    }

    #[inline(always)]
    pub(crate) fn timeout(&mut self) {
        // `timeout` leaves the current receive and prepares the next one.
        // Port of erts/emulator/beam/emu/msg_instrs.tab (`timeout`) and
        // erl_proc_sig_queue.h:2331 (`erts_msgq_set_save_first`), OTP-29.1.1.
        self.msgq_set_save_first();
        self.cancel_receive_timer();
    }

    /// `CANCEL_TIMER(c_p)`: leaves the receive (F_INSLPQUEUE / F_TIMO cleared) and cancels a
    /// receive timer the scheduler set for it.
    // Port of erts/emulator/beam/erl_process.h:1841-1849 (CANCEL_TIMER) and
    // erl_hl_timer.c:2832-2846 (erts_cancel_proc_timer), OTP-29.1.1.
    #[inline(always)]
    pub(crate) fn cancel_receive_timer(&mut self) {
        self.receive_infinity = false;
        if self.receive_timeout_pos.take().is_some() {
            self.receive_timeout_next = 0;
            if let Some(probe) = self.signal_probe() {
                probe.receive_timer().cancel();
            }
        }
    }

    /// `ERTS_PTMR_IS_TIMED_OUT(c_p)`.
    #[inline]
    pub(crate) fn receive_timer_timed_out(&self) -> bool {
        self.signal_probe()
            .is_some_and(|probe| probe.receive_timer().timed_out())
    }

    /// Schedule-in of a process whose receive timer fired: it continues at the `timeout`
    /// instruction of its receive (`p->i = def_arg_reg[0]`), whatever it was doing in the
    /// receive loop, and the timer word is cleared.
    // Port of erts/emulator/beam/erl_process.c:10451-10459 (erts_schedule), OTP-29.1.1.
    pub(crate) fn receive_timeout_schedule_in(&mut self) {
        let next = self.receive_timeout_next;
        let Some(probe) = self.signal_probe() else {
            return;
        };
        if next == 0
            || probe.proc_flags().load(Ordering::Acquire) & arinsal_sched::proc_flags::EXITING != 0
            || !probe.receive_timer().timed_out()
        {
            return;
        }
        // ERTS_PTMR_CLEAR; F_INSLPQUEUE becomes F_TIMO (`receive_timeout_pos` stays set until
        // `timeout` runs).
        probe.receive_timer().cancel();
        self.set_native_pc(Some(next));
    }

    /// `i_wait_timeout`: sets the receive timer once per receive. `Some(0)` takes the
    /// timeout now, `Some(pos)` waits with the timer at wheel position `pos` (see
    /// [`arinsal_sched::RunOutcome::WaitTimer`]), `None` waits without a timer.
    pub(crate) fn wait_timeout(&mut self, value: Term) -> Result<Option<u64>, VmError> {
        // Port of erts/emulator/beam/emu/msg_instrs.tab:231 (F_DELAY_GC cleared), OTP-29.1.1.
        self.delay_gc = false;
        // Port of erts/emulator/beam/jit/beam_jit_common.cpp:1208-1240
        // (beam_jit_wait_timeout), OTP-29.1.1: with F_INSLPQUEUE or F_TIMO set the timer is
        // already set and the operand is not read again (no X register is live across the
        // wait); the position computed when it was set is kept.
        if let Some(pos) = self.receive_timeout_pos {
            // No clock is read: the timer word says whether the timer fired
            // (ERTS_PTMR_IS_TIMED_OUT, which beam_jit_wait_locked tests), and a timer that has
            // not fired stays set.
            return Ok(Some(if self.receive_timer_timed_out() {
                0
            } else {
                pos
            }));
        }
        if self.receive_infinity {
            return Ok(None);
        }
        // Port of erts/emulator/beam/jit/beam_jit_common.cpp:1216-1218: with no timer set,
        // literal zero selects RET_next without consulting time.
        if value.as_small() == Some(0) {
            return Ok(Some(0));
        }
        if value.as_atom() == Some(arinsal_term::atoms::INFINITY) {
            self.receive_infinity = true;
            return Ok(None);
        }
        let timeout_value = || {
            VmError::Trap(crate::exceptions::Trap::error(Term::atom(
                arinsal_term::atoms::TIMEOUT_VALUE,
            )))
        };
        // Port of erts/emulator/beam/erl_hl_timer.c:2786-2806 (erts_set_proc_timer_term:
        // negative, non-integer and > 2^32-1 values are rejected) and msg_instrs.tab:342-345
        // (an invalid timer resets the save pointer), OTP-29.1.1.
        let ms = match value.as_small() {
            Some(ms) if (0..=i64::from(u32::MAX)).contains(&ms) => ms as u64,
            _ => {
                self.timeout();
                return Err(timeout_value());
            }
        };
        // Port of erts/emulator/beam/erl_hl_timer.c:2786-2806 (erts_set_proc_timer_term),
        // OTP-29.1.1: one monotonic clock read gives the wheel position the timer keeps.
        let pos = arinsal_sched::receive_timeout_pos(ms);
        self.receive_timeout_pos = Some(pos);
        Ok(Some(pos))
    }
}

#[cfg(test)]
mod tests {
    use super::{MARKER_SLOTS, Process, Term};

    #[test]
    fn marker_block_is_allocated_only_for_a_nonempty_mailbox() {
        let mut process = Process::new();
        arinsal_sched::Task::init_in_place(&mut process);
        assert_eq!(
            process.reserve_receive_marker().unwrap(),
            Term::atom(arinsal_term::atoms::UNDEFINED)
        );
        assert!(process.cold.is_none());
        process.inbox.push_back(Term::small(7).unwrap());
        let first = process.reserve_receive_marker().unwrap();
        assert_eq!(first, Term::small(arinsal_term::MIN_SMALL).unwrap());
        assert!(
            process
                .cold
                .as_ref()
                .is_some_and(|cold| cold.receive_markers.is_some())
        );
        process.remove_message(None).unwrap();
        assert!(
            process
                .cold
                .as_ref()
                .is_some_and(|cold| cold.receive_markers.is_none())
        );
        process.inbox.push_back(Term::small(8).unwrap());
        assert_ne!(first, process.reserve_receive_marker().unwrap());
    }

    #[test]
    fn exhausted_small_marker_ids_return_a_typed_error() {
        let mut process = Process::new();
        arinsal_sched::Task::init_in_place(&mut process);
        process.inbox.push_back(Term::small(7).unwrap());
        process.cold_mut().receive_marker_uniq =
            arinsal_term::MAX_SMALL - arinsal_term::MIN_SMALL + 1;
        assert!(matches!(
            process.reserve_receive_marker(),
            Err(super::VmError::Unsupported(_))
        ));
    }

    #[test]
    fn marker_count_stays_bounded_through_100k_call_cycles() {
        let mut process = Process::new();
        arinsal_sched::Task::init_in_place(&mut process);
        for i in 0..100_000 {
            process.inbox.push_back(Term::small(i).unwrap());
            let marker = process.reserve_receive_marker().unwrap();
            // Bound to a non-reference: the marker is unused and reused first.
            process.bind_receive_marker(marker, Term::atom(arinsal_term::atoms::UNDEFINED));
            let live = process
                .cold
                .as_ref()
                .and_then(|cold| cold.receive_markers.as_ref())
                .map_or(0, |markers| markers.len());
            assert!(live <= MARKER_SLOTS);
            process.remove_message(None).unwrap();
        }
        // The leading markers went with the last message.
        assert!(
            process
                .cold
                .as_ref()
                .is_none_or(|cold| cold.receive_markers.is_none())
        );
        assert!(process.inbox.is_empty());
    }
}
