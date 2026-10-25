//! Selective receive state owned by the running process.

use crate::{Process, VmError};
use arinsal_loader::Arg;
use arinsal_term::Term;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

// Port of erts/emulator/beam/erl_message.h:322 (ERTS_RECV_MARKER_BLOCK_SIZE)
// and erl_proc_sig_queue.h:276 (ERTS_RECV_MARKER_PASS_MAX), OTP-29.1.1.
const MARKER_SLOTS: usize = 8;
const MARKER_PASS_MAX: u8 = 4;

#[derive(Clone, Copy, PartialEq, Eq)]
enum MarkerId {
    Reserved(i64),
    Bound(u64),
    Cleared,
}

#[derive(Clone, Copy)]
struct ReceiveMarker {
    id: MarkerId,
    position: usize,
    priority_position: Option<usize>,
    inserted: u64,
    passes: u8,
    /// `in_sigq` without `in_msgq`: the marker waits in the middle signal queue (`sig_cont`)
    /// and enters the message queue once every signal fetched before it was taken from there.
    /// The value is the `sig_cont_taken` count at which that happens.
    in_sigq: Option<u64>,
    /// `set_save`: the save pointer moves past the marker when it enters the message queue.
    set_save: bool,
    /// `in_sigq < 0`: marked for removal when it enters the message queue.
    remove: bool,
}

/// Where `recv_marker_use` leaves the save pointer.
#[derive(Debug, PartialEq, Eq)]
enum SetSave {
    /// In the message queue, with the priority-queue position when one was recorded.
    At(usize, Option<usize>),
    /// The marker is still in the middle queue.
    Pending,
}

/// Bounded receive-marker state corresponding to the erts marker block.
#[derive(Default)]
pub(crate) struct ReceiveMarkers {
    slots: [Option<ReceiveMarker>; MARKER_SLOTS],
    inserted: u64,
}

impl ReceiveMarkers {
    // Port of erl_proc_sig_queue.c:9358-9454 (priority insertion and save-marker placement), OTP-29.1.1.
    fn priority_inserted(&mut self, index: usize, message: &arinsal_etf::OwnedTerm) {
        for marker in self.slots.iter_mut().flatten() {
            if marker.in_sigq.is_none() && marker.position >= index {
                if let MarkerId::Bound(reference) = marker.id
                    && contains_reference(message, reference)
                    && marker.priority_position.is_none()
                {
                    marker.priority_position = Some(index);
                }
                marker.position += 1;
            }
        }
    }

    fn reserve(&mut self, position: usize, in_sigq: Option<u64>, id: i64) {
        self.inserted = self.inserted.wrapping_add(1);
        // Port of erts/emulator/beam/erl_proc_sig_queue.c:4148
        // (recv_marker_reuse), OTP-29.1.1. Prefer an unused marker when full.
        let slot = self
            .slots
            .iter()
            .position(Option::is_none)
            .unwrap_or_else(|| {
                self.slots
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, marker)| {
                        let marker = marker.expect("full marker block");
                        (marker.id != MarkerId::Cleared, marker.inserted)
                    })
                    .expect("eight marker slots")
                    .0
            });
        self.slots[slot] = Some(ReceiveMarker {
            id: MarkerId::Reserved(id),
            position,
            priority_position: None,
            inserted: self.inserted,
            passes: 0,
            in_sigq,
            set_save: false,
            remove: false,
        });
    }

    /// Insert a marker into the middle queue before signal number `in_sigq` that sets the
    /// save pointer when it enters the message queue and is removed there.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:4366
    // (erts_msgq_recv_marker_create_insert_set_save) and erl_proc_sig_queue.h:2151
    // (erts_msgq_recv_marker_set_save__ clearing the pending set-save), OTP-29.1.1.
    fn insert_set_save(&mut self, in_sigq: u64) {
        for marker in self.slots.iter_mut().flatten() {
            if marker.in_sigq.is_some() {
                marker.set_save = false;
            }
        }
        self.reserve(0, Some(in_sigq), 0);
        let inserted = self.inserted;
        if let Some(marker) = self
            .slots
            .iter_mut()
            .flatten()
            .find(|marker| marker.inserted == inserted)
        {
            marker.id = MarkerId::Cleared;
            marker.set_save = true;
            marker.remove = true;
        }
    }

    fn bind(&mut self, id: i64, reference: Option<u64>) {
        // Port of erts/emulator/beam/erl_proc_sig_queue.h:2238
        // (erts_msgq_recv_marker_bind), OTP-29.1.1.
        if let Some(marker) = self
            .slots
            .iter_mut()
            .flatten()
            .find(|marker| marker.id == MarkerId::Reserved(id))
        {
            if let Some(reference) = reference {
                marker.id = MarkerId::Bound(reference);
            } else {
                marker.id = MarkerId::Cleared;
                marker.passes = MARKER_PASS_MAX;
            }
        }
    }

    fn clear(&mut self, id: MarkerId) {
        // Port of erts/emulator/beam/erl_proc_sig_queue.h:2203
        // (erts_msgq_recv_marker_clear), OTP-29.1.1.
        if let Some(marker) = self
            .slots
            .iter_mut()
            .flatten()
            .find(|marker| marker.id == id)
        {
            marker.id = MarkerId::Cleared;
            marker.passes = MARKER_PASS_MAX;
        }
    }

    fn set_save(&mut self, reference: u64) -> Option<SetSave> {
        let selected = self
            .slots
            .iter_mut()
            .flatten()
            .find(|marker| marker.id == MarkerId::Bound(reference))?;
        // Port of erts/emulator/beam/erl_proc_sig_queue.h:2128
        // (erts_msgq_recv_marker_pending_set_save__), OTP-29.1.1: a marker still in the
        // middle queue sets the save pointer when it enters the message queue.
        if selected.in_sigq.is_some() {
            selected.set_save = true;
            return Some(SetSave::Pending);
        }
        let selected = *selected;
        // Markers inserted at the same boundary after this one are passed
        // while erts advances its save pointer past the selected marker.
        // Port of erts/emulator/beam/erl_proc_sig_queue.h:2193
        // (erts_msgq_recv_marker_set_save__), OTP-29.1.1.
        for slot in &mut self.slots {
            if let Some(marker) = slot.as_mut()
                && marker.in_sigq.is_none()
                && marker.position == selected.position
                && marker.inserted > selected.inserted
            {
                marker.passes += 1;
                if marker.passes > MARKER_PASS_MAX {
                    *slot = None;
                }
            }
        }
        Some(SetSave::At(selected.position, selected.priority_position))
    }

    /// Whether a marker waits in the middle queue right before the signal that is taken
    /// as number `taken`.
    fn due(&self, taken: u64) -> bool {
        self.slots
            .iter()
            .flatten()
            .any(|marker| marker.in_sigq == Some(taken))
    }

    /// Whether any marker still waits in the middle queue.
    fn in_sigq(&self) -> bool {
        self.slots
            .iter()
            .flatten()
            .any(|marker| marker.in_sigq.is_some())
    }

    /// Move the markers due at `taken` into the message queue at `position`; returns the
    /// save position a pending `set_save` asked for.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:6895-6945 (ERTS_SIG_Q_OP_RECV_MARK),
    // OTP-29.1.1.
    fn enter_msgq(&mut self, taken: u64, position: usize) -> Option<usize> {
        let mut save = None;
        for slot in &mut self.slots {
            if let Some(marker) = slot.as_mut()
                && marker.in_sigq == Some(taken)
            {
                marker.in_sigq = None;
                marker.position = position;
                if std::mem::take(&mut marker.set_save) {
                    save = Some(position);
                }
                // erl_proc_sig_queue.c:6899-6913: a marker marked for removal is
                // deallocated as it enters the message queue.
                if marker.remove {
                    *slot = None;
                }
            }
        }
        save
    }
    fn passed(&mut self, position: usize) {
        // Port of erts/emulator/beam/erl_proc_sig_queue.c:4431
        // (msgq_pass_recv_markers), OTP-29.1.1.
        for slot in &mut self.slots {
            if let Some(marker) = slot.as_mut()
                && marker.in_sigq.is_none()
                && marker.position == position
            {
                marker.passes += 1;
                if marker.passes > MARKER_PASS_MAX {
                    *slot = None;
                }
            }
        }
    }

    fn removed(&mut self, index: usize) {
        for marker in self
            .slots
            .iter_mut()
            .flatten()
            .filter(|m| m.in_sigq.is_none())
        {
            if marker.position > index {
                marker.position -= 1;
            }
            if marker
                .priority_position
                .is_some_and(|position| position > index)
            {
                marker.priority_position = marker.priority_position.map(|position| position - 1);
            }
        }
        self.clear_leading();
    }

    fn clear_leading(&mut self) {
        // Port of erts/emulator/beam/erl_proc_sig_queue.c:4591
        // (erts_msgq_remove_leading_recv_markers_set_save_first), OTP-29.1.1.
        for slot in &mut self.slots {
            if slot
                .as_ref()
                .is_some_and(|marker| marker.in_sigq.is_none() && marker.position == 0)
            {
                *slot = None;
            }
        }
    }

    fn is_empty(&self) -> bool {
        self.slots.iter().all(Option::is_none)
    }

    #[cfg(any(test, feature = "pf-mem-counters"))]
    pub(crate) fn len(&self) -> usize {
        self.slots
            .iter()
            .flatten()
            .filter(|marker| marker.id != MarkerId::Cleared)
            .count()
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
    /// Preserve the old save boundary while priority entries are scanned first.
    // Port of erl_proc_sig_queue.c:9358-9454 (insert_prepared_prio_msg_attached), OTP-29.1.1.
    pub(crate) fn priority_item_inserted(
        &mut self,
        old_prio_len: usize,
        message: Term,
    ) -> Result<(), VmError> {
        let cursor = self.inbox.save();
        if self
            .cold
            .as_ref()
            .and_then(|cold| cold.priority_resume_cursor)
            .is_some()
        {
            *self
                .cold_mut()
                .priority_resume_cursor
                .as_mut()
                .expect("resume cursor checked") += 1;
        } else if cursor >= old_prio_len {
            self.cold_mut().priority_resume_cursor = Some(cursor + 1);
            self.inbox.set_save(old_prio_len);
        }
        if let Some(markers) = self
            .cold
            .as_mut()
            .and_then(|cold| cold.receive_markers.as_mut())
        {
            let message = arinsal_term::to_owned(message).map_err(|error| {
                VmError::Unsupported(format!(
                    "priority marker message copy ({:?}): {error:?}",
                    message.classify()
                ))
            })?;
            markers.priority_inserted(old_prio_len, &message);
        }
        Ok(())
    }

    fn release_empty_marker_block(&mut self) {
        if let Some(cold) = self.cold.as_mut()
            && cold
                .receive_markers
                .as_ref()
                .is_some_and(|markers| markers.is_empty())
        {
            cold.receive_markers = None;
        }
    }

    /// Insert a receive marker after everything fetched so far, or `undefined` when both the
    /// message queue and the middle signal queue are empty. The caller fetched the outer
    /// queue first.
    // Port of erts/emulator/beam/erl_proc_sig_queue.h:2226 (erts_msgq_recv_marker_insert)
    // and erl_proc_sig_queue.c:4084 (erts_msgq_recv_marker_create_insert) with
    // recv_marker_insert (erl_proc_sig_queue.c:4290), OTP-29.1.1.
    pub(crate) fn reserve_receive_marker(&mut self) -> Result<Term, VmError> {
        // `c_p->sig_qs.cont || c_p->sig_qs.first`.
        let cont = !self.sig_cont_empty();
        if !cont && self.inbox.is_empty() {
            return Ok(crate::signals::atom("undefined"));
        }
        // Without a middle queue the marker goes to the end of the message queue; otherwise
        // to the end of the middle queue.
        let position = self.inbox.len();
        let in_sigq = cont.then(|| self.sig_cont_taken + self.sig_cont.len() as u64);
        let cold = self.cold_mut();
        // Port of erts/emulator/beam/erl_proc_sig_queue.c:4084
        // (recv_marker_uniq), OTP-29.1.1.
        let id = arinsal_term::MIN_SMALL
            .checked_add(cold.receive_marker_uniq)
            .filter(|id| Term::small(*id).is_some())
            .ok_or_else(|| VmError::Unsupported("receive marker id exceeds small range".into()))?;
        cold.receive_marker_uniq += 1;
        cold.receive_markers
            .get_or_insert_with(|| Box::new(ReceiveMarkers::default()))
            .reserve(position, in_sigq, id);
        Ok(Term::small(id).expect("checked receive marker id"))
    }

    /// Insert a removable set-save receive marker before the middle-queue signal at
    /// `index`, or at the end of the middle queue.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:4366
    // (erts_msgq_recv_marker_create_insert_set_save), OTP-29.1.1.
    pub(crate) fn recv_marker_create_insert_set_save(&mut self, index: Option<usize>) {
        let index = index.unwrap_or(self.sig_cont.len());
        let in_sigq = self.sig_cont_taken + index as u64;
        self.cold_mut()
            .receive_markers
            .get_or_insert_with(|| Box::new(ReceiveMarkers::default()))
            .insert_set_save(in_sigq);
    }

    /// Whether the middle signal queue is empty (`!c_p->sig_qs.cont`): no fetched signal is
    /// unhandled and no receive marker waits there.
    pub(crate) fn sig_cont_empty(&self) -> bool {
        self.sig_cont.is_empty()
            && self
                .cold
                .as_ref()
                .and_then(|cold| cold.receive_markers.as_ref())
                .is_none_or(|markers| !markers.in_sigq())
    }

    /// Whether a receive marker sits before the next signal of the middle queue.
    pub(crate) fn recv_marker_due(&self) -> bool {
        self.cold
            .as_ref()
            .and_then(|cold| cold.receive_markers.as_ref())
            .is_some_and(|markers| markers.due(self.sig_cont_taken))
    }

    /// Handle the receive markers at the head of the middle queue: they enter the message
    /// queue at its end.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:6895-6945 (ERTS_SIG_Q_OP_RECV_MARK),
    // OTP-29.1.1.
    pub(crate) fn recv_marker_enter_msgq(&mut self) {
        let position = self.inbox.len();
        let taken = self.sig_cont_taken;
        if let Some(save) = self
            .cold
            .as_mut()
            .and_then(|cold| cold.receive_markers.as_mut())
            .and_then(|markers| markers.enter_msgq(taken, position))
        {
            self.inbox.set_save(save);
            self.cold_mut().priority_resume_cursor = None;
        }
    }

    pub(crate) fn bind_receive_marker(&mut self, marker: Term, reference: Term) {
        if let Some(id) = marker.as_small()
            && let Some(cold) = self.cold.as_mut()
            && let Some(markers) = cold.receive_markers.as_mut()
        {
            markers.bind(id, crate::signals::ref_id(reference));
        }
    }

    pub(crate) fn clear_receive_marker(&mut self, term: Term) {
        let id = crate::signals::ref_id(term)
            .map(MarkerId::Bound)
            .or_else(|| term.as_small().map(MarkerId::Reserved));
        if let Some(id) = id
            && let Some(cold) = self.cold.as_mut()
            && let Some(markers) = cold.receive_markers.as_mut()
        {
            markers.clear(id);
        }
    }

    pub(crate) fn use_receive_marker(&mut self, term: Term) {
        if let Some(reference) = crate::signals::ref_id(term)
            && let Some(set_save) = self
                .cold
                .as_mut()
                .and_then(|cold| cold.receive_markers.as_mut())
                .and_then(|markers| markers.set_save(reference))
        {
            let (position, priority_position) = match set_save {
                SetSave::At(position, priority_position) => (position, priority_position),
                // Port of erts/emulator/beam/erl_proc_sig_queue.h:2128
                // (erts_msgq_recv_marker_pending_set_save__), OTP-29.1.1: save at the end of
                // the message queue, past the priority queue, so `loop_rec` handles signals.
                SetSave::Pending => {
                    self.cold_mut().priority_resume_cursor = None;
                    self.inbox.set_save(self.inbox.len());
                    return;
                }
            };
            // Port of erts/emulator/beam/erl_proc_sig_queue.h:2281
            // (erts_msgq_recv_marker_set_save), OTP-29.1.1.
            let prio_len = self.cold.as_ref().map_or(0, |cold| cold.prio_len);
            if let Some(priority_position) =
                priority_position.filter(|&position| position < prio_len)
            {
                self.inbox.set_save(priority_position);
                self.cold_mut().priority_resume_cursor = Some(position);
            } else {
                self.inbox.set_save(position);
            }
        }
    }

    // Port of erts/emulator/beam/emu/msg_instrs.tab (receive instructions), OTP-29.1.1.
    pub(crate) fn loop_rec(&mut self, dst: Arg) -> Result<bool, VmError> {
        // Port of erts/emulator/beam/erl_proc_sig_queue.c:9605 (save pointer loop), OTP-29.1.1.
        // Port of erts/emulator/beam/emu/msg_instrs.tab:59-67, 110 (F_DELAY_GC from loop_rec
        // until remove_message or wait), OTP-29.1.1.
        if let Some(&message) = self.inbox.get(self.inbox.save()) {
            self.delay_gc = true;
            self.write(dst, message)?;
            Ok(true)
        } else {
            self.delay_gc = false;
            Ok(false)
        }
    }

    pub(crate) fn loop_rec_end(&mut self) {
        self.inbox.set_save(self.inbox.save() + 1);
        // Port of erl_proc_sig_queue.c:9360-9454 (continue after priority queue), OTP-29.1.1.
        let prio_len = self.cold.as_ref().map_or(0, |cold| cold.prio_len);
        if self.inbox.save() == prio_len
            && let Some(resume) = self
                .cold
                .as_mut()
                .and_then(|cold| cold.priority_resume_cursor.take())
        {
            self.inbox.set_save(resume);
        }
        if self.inbox.save() >= prio_len
            && let Some(markers) = self
                .cold
                .as_mut()
                .and_then(|cold| cold.receive_markers.as_mut())
        {
            markers.passed(self.inbox.save());
        }
        self.release_empty_marker_block();
    }

    pub(crate) fn message_removed(&mut self, index: usize) {
        if let Some(resume) = self
            .cold
            .as_mut()
            .and_then(|cold| cold.priority_resume_cursor.as_mut())
            && *resume > index
        {
            *resume -= 1;
        }
        if let Some(markers) = self
            .cold
            .as_mut()
            .and_then(|cold| cold.receive_markers.as_mut())
        {
            markers.removed(index);
        }
        self.release_empty_marker_block();
        if self.inbox.save() > index {
            self.inbox.set_save(self.inbox.save() - 1);
        }
        crate::natives::erts_debug::after_message_queue_change(self);
    }

    /// Removes the first message of a plain receive: no priority range, no receive marker, no
    /// memory breakpoint and no seq_trace token to apply. `Ok(false)` means the general path
    /// must run; nothing was changed then.
    // Port of erts/emulator/beam/erl_proc_sig_queue.h (erts_msgq_unlink_msg_set_save_first
    // with the save pointer at the first message), OTP-29.1.1.
    #[inline]
    pub(crate) fn remove_first_message(&mut self) -> Result<bool, VmError> {
        if self.inbox.save() != 0
            || self.cold.as_ref().is_some_and(|cold| {
                cold.prio_len != 0
                    || cold.priority_resume_cursor.is_some()
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
        self.receive_deadline = None;
        self.receive_deadline_ms = None;
        self.receive_infinity = false;
        Ok(true)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn remove_message(
        &mut self,
        ctx: Option<&mut arinsal_sched::RunCtx<'_, crate::process::Message>>,
    ) -> Result<(), VmError> {
        self.remove_message_inner(None, ctx)
    }

    pub(crate) fn remove_message_with_vm(
        &mut self,
        vm: &mut crate::Vm,
        ctx: Option<&mut arinsal_sched::RunCtx<'_, crate::process::Message>>,
    ) -> Result<(), VmError> {
        self.remove_message_inner(Some(vm), ctx)
    }

    fn remove_message_inner(
        &mut self,
        vm: Option<&mut crate::Vm>,
        ctx: Option<&mut arinsal_sched::RunCtx<'_, crate::process::Message>>,
    ) -> Result<(), VmError> {
        let removed = self.inbox.save();
        let old_prio_len = self.cold.as_ref().map_or(0, |cold| cold.prio_len);
        // Port of erts/emulator/beam/erl_message.c:975 (erts_save_message_in_proc,
        // erts_adjust_message_break), OTP-29.1.1: a message that was copied onto the heap is
        // counted by call_memory when it is received.
        let on_heap_words = if self
            .cold
            .as_ref()
            .is_some_and(|cold| !cold.call_memory.is_empty())
            && self.inbox.is_on_heap(removed)
        {
            self.inbox
                .get(removed)
                .map_or(0, |term| arinsal_term::size_object(*term))
        } else {
            0
        };
        let (removed_message, new_prio_len) =
            self.inbox
                .remove_to_heap_with_token(removed, &mut self.heap, old_prio_len)?;
        // Port of erts/emulator/beam/jit/beam_jit_common.cpp:1168-1171 (beam_jit_remove_message:
        // erts_save_message_in_proc, then F_DELAY_GC cleared), OTP-29.1.1.
        self.delay_gc = false;
        if on_heap_words != 0 {
            crate::trace_bp::adjust_memory_break(self, on_heap_words as i64);
        }
        self.cold_mut().prio_len = new_prio_len;
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
        self.message_removed(removed);
        self.inbox.set_save(0);
        if let Some(cold) = self.cold.as_mut() {
            cold.priority_resume_cursor = None;
        }
        self.receive_deadline = None;
        self.receive_deadline_ms = None;
        self.receive_infinity = false;
        Ok(())
    }

    pub(crate) fn timeout(&mut self) {
        self.delay_gc = false;
        // `timeout` leaves the current receive and prepares the next one.
        // Port of erts/emulator/beam/emu/msg_instrs.tab (`timeout`) and
        // erl_proc_sig_queue.h:2331 (`erts_msgq_set_save_first`), OTP-29.1.1.
        self.inbox.set_save(0);
        if let Some(cold) = self.cold.as_mut() {
            cold.priority_resume_cursor = None;
        }
        self.receive_deadline = None;
        self.receive_deadline_ms = None;
        self.receive_infinity = false;
        if let Some(markers) = self
            .cold
            .as_mut()
            .and_then(|cold| cold.receive_markers.as_mut())
        {
            markers.clear_leading();
        }
        self.release_empty_marker_block();
    }

    pub(crate) fn wait_timeout(&mut self, value: Term) -> Result<Option<u64>, VmError> {
        // Port of erts/emulator/beam/emu/msg_instrs.tab:231 (F_DELAY_GC cleared), OTP-29.1.1.
        self.delay_gc = false;
        // Port of erts/emulator/beam/jit/beam_jit_common.cpp:1214-1218
        // (beam_jit_wait_timeout), OTP-29.1.1: with no installed receive timer, literal zero
        // immediately selects RET_next without consulting scheduler time.
        if !self.receive_infinity
            && self.receive_deadline.is_none()
            && self.receive_deadline_ms.is_none()
            && value.as_small() == Some(0)
        {
            return Ok(Some(0));
        }
        // Port of erts/emulator/beam/emu/msg_instrs.tab:329-334 (wait.src), OTP-29.1.1:
        // once the timer is set (F_TIMO), a re-executed wait_timeout must not read
        // its operand again; no X register is live across the wait.
        let simulated = self
            .runtime
            .as_ref()
            .is_some_and(|runtime| runtime.simulated);
        if simulated {
            if let (Some(deadline), Some(runtime)) =
                (self.receive_deadline_ms, self.runtime.as_ref())
            {
                let now = runtime.virtual_ms.load(Ordering::Relaxed);
                return Ok(Some(deadline.saturating_sub(now)));
            }
        } else if let Some(deadline) = self.receive_deadline {
            let now = Instant::now();
            if now >= deadline {
                return Ok(Some(0));
            }
            let remaining = deadline.saturating_duration_since(now).as_millis() as u64;
            return Ok(Some(remaining.max(1)));
        }
        if self.receive_infinity {
            return Ok(None);
        }
        if value.as_atom() == Some(arinsal_term::atoms::INFINITY) {
            self.receive_infinity = true;
            return Ok(None);
        }
        let timeout_value = || {
            VmError::Trap(crate::exceptions::Trap::error(crate::signals::atom(
                "timeout_value",
            )))
        };
        let Some(ms) = value.as_small() else {
            // Port of erts/emulator/beam/emu/msg_instrs.tab:342-345
            // (invalid timer resets the save pointer), OTP-29.1.1.
            self.timeout();
            return Err(timeout_value());
        };
        if ms < 0 {
            // Port of erts/emulator/beam/emu/msg_instrs.tab:342-345
            // (invalid timer resets the save pointer), OTP-29.1.1.
            self.timeout();
            return Err(timeout_value());
        }
        if ms > u32::MAX as i64 {
            // Port of erts/emulator/beam/erl_hl_timer.c:2799-2804
            // (erts_set_proc_timer_term), OTP-29.1.1.
            self.timeout();
            return Err(timeout_value());
        }
        if let Some(runtime) = self.runtime.as_ref()
            && runtime.simulated
        {
            let now = runtime.virtual_ms.load(Ordering::Relaxed);
            let deadline = *self
                .receive_deadline_ms
                .get_or_insert_with(|| now.saturating_add(ms as u64));
            let remaining = deadline.saturating_sub(now);
            return Ok(Some(remaining));
        }
        let now = Instant::now();
        let deadline = *self
            .receive_deadline
            .get_or_insert_with(|| now + Duration::from_millis(ms as u64));
        let remaining = deadline.saturating_duration_since(now).as_millis() as u64;
        if now >= deadline {
            return Ok(Some(0));
        }
        Ok(Some(remaining.max(1)))
    }
}

#[cfg(test)]
mod tests {
    use super::{MARKER_SLOTS, MarkerId, Process, ReceiveMarkers, SetSave, Term};

    #[test]
    fn marker_block_is_allocated_only_for_a_nonempty_mailbox() {
        let mut process = Process::new();
        assert_eq!(
            process.reserve_receive_marker().unwrap(),
            crate::signals::atom("undefined")
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
        let mut markers = ReceiveMarkers::default();
        let mut peak = 0;
        for reference in 1..=100_000 {
            let reservation = -i64::try_from(reference).unwrap();
            markers.reserve(1, None, reservation);
            markers.bind(reservation, Some(reference));
            assert_eq!(markers.set_save(reference), Some(SetSave::At(1, None)));
            peak = peak.max(markers.len());
            markers.clear(MarkerId::Bound(reference));
            markers.passed(1);
        }
        assert!(peak <= MARKER_SLOTS);
        assert_eq!(markers.len(), 0);
        assert!(markers.slots.iter().all(Option::is_none));
    }

    #[test]
    fn marker_reuse_and_message_removal_preserve_boundaries() {
        let mut markers = ReceiveMarkers::default();
        let oldest = -1;
        markers.reserve(2, None, oldest);
        markers.bind(oldest, Some(1));
        for reference in 2..=MARKER_SLOTS as u64 {
            let reservation = -i64::try_from(reference).unwrap();
            markers.reserve(3, None, reservation);
            markers.bind(reservation, Some(reference));
        }
        let reservation = -9;
        markers.reserve(4, None, reservation);
        markers.bind(reservation, Some(9));
        assert_eq!(markers.set_save(1), None);
        assert_eq!(markers.set_save(9), Some(SetSave::At(4, None)));
        assert_eq!(markers.len(), MARKER_SLOTS);
        markers.removed(0);
        assert_eq!(markers.set_save(9), Some(SetSave::At(3, None)));
        markers.removed(0);
        markers.removed(0);
        markers.removed(0);
        assert_eq!(markers.set_save(9), None);
        assert_eq!(markers.len(), 0);
    }

    #[test]
    fn using_an_older_marker_passes_newer_markers_at_the_same_boundary() {
        let mut markers = ReceiveMarkers::default();
        markers.reserve(2, None, -1);
        markers.bind(-1, Some(1));
        markers.reserve(2, None, -2);
        markers.bind(-2, Some(2));
        for _ in 0..=super::MARKER_PASS_MAX {
            assert_eq!(markers.set_save(1), Some(SetSave::At(2, None)));
        }
        assert_eq!(markers.set_save(2), None);
        assert_eq!(markers.len(), 1);
    }
}
