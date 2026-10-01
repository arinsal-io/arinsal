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
    scheduler: Option<arinsal_sched::ReceiveMarker>,
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
            if marker.position >= index {
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

    fn reserve(
        &mut self,
        position: usize,
        id: i64,
        scheduler: Option<arinsal_sched::ReceiveMarker>,
    ) {
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
            scheduler,
        });
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

    fn set_save(&mut self, reference: u64) -> Option<(usize, Option<usize>)> {
        let selected = self
            .slots
            .iter()
            .flatten()
            .find(|marker| marker.id == MarkerId::Bound(reference))
            .copied()?;
        // Markers inserted at the same boundary after this one are passed
        // while erts advances its save pointer past the selected marker.
        // Port of erts/emulator/beam/erl_proc_sig_queue.h:2193
        // (erts_msgq_recv_marker_set_save__), OTP-29.1.1.
        for slot in &mut self.slots {
            if let Some(marker) = slot.as_mut()
                && marker.position == selected.position
                && marker.inserted > selected.inserted
            {
                marker.passes += 1;
                if marker.passes > MARKER_PASS_MAX {
                    *slot = None;
                }
            }
        }
        Some((selected.position, selected.priority_position))
    }

    fn position(&self, reference: u64) -> Option<usize> {
        self.slots
            .iter()
            .flatten()
            .find(|marker| marker.id == MarkerId::Bound(reference))
            .map(|marker| marker.position)
    }

    fn passed(&mut self, position: usize) {
        // Port of erts/emulator/beam/erl_proc_sig_queue.c:4431
        // (msgq_pass_recv_markers), OTP-29.1.1.
        for slot in &mut self.slots {
            if let Some(marker) = slot.as_mut()
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
        for marker in self.slots.iter_mut().flatten() {
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
            if slot.as_ref().is_some_and(|marker| marker.position == 0) {
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
            && ids[2] == 0
            && (ids[0] as u64 | ((ids[1] as u64) << 32)) == reference =>
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
    /// Return the mailbox boundary associated with a live internal reference.
    pub(crate) fn receive_marker_position(&self, reference: u64) -> Option<usize> {
        self.cold
            .as_ref()?
            .receive_markers
            .as_ref()?
            .position(reference)
    }

    /// Preserve the old save boundary while priority entries are scanned first.
    // Port of erl_proc_sig_queue.c:9358-9454 (insert_prepared_prio_msg_attached), OTP-29.1.1.
    pub(crate) fn priority_item_inserted(
        &mut self,
        old_prio_len: usize,
        message: Term,
    ) -> Result<(), VmError> {
        let cursor = self.receive_cursor;
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
            self.receive_cursor = old_prio_len;
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

    /// Reserve a marker in the process queue only. Native code runs on messages the bridge
    /// already fetched, so the scheduler-side marker (which bounds a later fetch) is not needed.
    pub(crate) fn reserve_receive_marker(&mut self) -> Result<Term, VmError> {
        self.reserve_receive_marker_inner(None)
    }

    pub(crate) fn reserve_scheduled_receive_marker(
        &mut self,
        scheduler: arinsal_sched::ReceiveMarker,
    ) -> Result<Term, VmError> {
        self.reserve_receive_marker_inner(Some(scheduler))
    }

    fn reserve_receive_marker_inner(
        &mut self,
        scheduler: Option<arinsal_sched::ReceiveMarker>,
    ) -> Result<Term, VmError> {
        // An empty queue has no boundary to mark. OTP returns `undefined`.
        if self.inbox.is_empty() && scheduler.is_none() {
            return Ok(crate::signals::atom("undefined"));
        }
        let position = self.inbox.len();
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
            .reserve(position, id, scheduler);
        Ok(Term::small(id).expect("checked receive marker id"))
    }

    pub(crate) fn bind_receive_marker(
        &mut self,
        marker: Term,
        reference: Term,
    ) -> Option<arinsal_sched::ReceiveMarker> {
        if let Some(id) = marker.as_small()
            && let Some(cold) = self.cold.as_mut()
            && let Some(markers) = cold.receive_markers.as_mut()
        {
            let reference = crate::signals::ref_id(reference);
            markers.bind(id, reference);
            return reference.and_then(|reference| {
                markers
                    .slots
                    .iter()
                    .flatten()
                    .find(|entry| entry.id == MarkerId::Bound(reference))
                    .and_then(|entry| entry.scheduler)
            });
        }
        None
    }

    pub(crate) fn clear_receive_marker(
        &mut self,
        term: Term,
    ) -> Option<arinsal_sched::ReceiveMarker> {
        let id = crate::signals::ref_id(term)
            .map(MarkerId::Bound)
            .or_else(|| term.as_small().map(MarkerId::Reserved));
        if let Some(id) = id
            && let Some(cold) = self.cold.as_mut()
            && let Some(markers) = cold.receive_markers.as_mut()
        {
            let scheduler = markers
                .slots
                .iter()
                .flatten()
                .find(|entry| entry.id == id)
                .and_then(|entry| entry.scheduler);
            markers.clear(id);
            return scheduler;
        }
        None
    }

    pub(crate) fn use_receive_marker(&mut self, term: Term) {
        if let Some(reference) = crate::signals::ref_id(term)
            && let Some((position, priority_position)) = self
                .cold
                .as_mut()
                .and_then(|cold| cold.receive_markers.as_mut())
                .and_then(|markers| markers.set_save(reference))
        {
            // Port of erts/emulator/beam/erl_proc_sig_queue.h:2281
            // (erts_msgq_recv_marker_set_save), OTP-29.1.1.
            let prio_len = self.cold.as_ref().map_or(0, |cold| cold.prio_len);
            if let Some(priority_position) =
                priority_position.filter(|&position| position < prio_len)
            {
                self.receive_cursor = priority_position;
                self.cold_mut().priority_resume_cursor = Some(position);
            } else {
                self.receive_cursor = position;
            }
        }
    }

    // Port of erts/emulator/beam/emu/msg_instrs.tab (receive instructions), OTP-29.1.1.
    pub(crate) fn loop_rec(&mut self, dst: Arg) -> Result<bool, VmError> {
        // Port of erts/emulator/beam/erl_proc_sig_queue.c:9605 (save pointer loop), OTP-29.1.1.
        if let Some(&message) = self.inbox.get(self.receive_cursor) {
            self.write(dst, message)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub(crate) fn loop_rec_end(&mut self) {
        self.receive_cursor += 1;
        // Port of erl_proc_sig_queue.c:9360-9454 (continue after priority queue), OTP-29.1.1.
        let prio_len = self.cold.as_ref().map_or(0, |cold| cold.prio_len);
        if self.receive_cursor == prio_len
            && let Some(resume) = self
                .cold
                .as_mut()
                .and_then(|cold| cold.priority_resume_cursor.take())
        {
            self.receive_cursor = resume;
        }
        if self.receive_cursor >= prio_len
            && let Some(markers) = self
                .cold
                .as_mut()
                .and_then(|cold| cold.receive_markers.as_mut())
        {
            markers.passed(self.receive_cursor);
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
        if self.receive_cursor > index {
            self.receive_cursor -= 1;
        }
        crate::natives::erts_debug::after_message_queue_change(self);
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
        let removed = self.receive_cursor;
        let old_prio_len = self.cold.as_ref().map_or(0, |cold| cold.prio_len);
        let (removed_message, new_prio_len) =
            self.inbox
                .remove_to_heap_with_token(removed, &mut self.heap, old_prio_len)?;
        self.cold_mut().prio_len = new_prio_len;
        let (term, token) = removed_message
            .ok_or_else(|| VmError::Unsupported("remove_message without current message".into()))?;
        let mut ctx = ctx;
        if token.is_some()
            && let Some(run_ctx) = ctx.as_deref_mut()
        {
            let message =
                arinsal_term::to_owned(term).unwrap_or(arinsal_etf::OwnedTerm::atom("undefined"));
            let pid = run_ctx.pid();
            crate::seq_trace::on_receive(vm, self, run_ctx, pid, token, message);
        }
        // Port of erts/emulator/beam/erl_proc_sig_queue.h:2367
        // (erts_msgq_unlink_msg_set_save_first), OTP-29.1.1.
        self.message_removed(removed);
        self.receive_cursor = 0;
        if let Some(cold) = self.cold.as_mut() {
            cold.priority_resume_cursor = None;
        }
        self.receive_deadline = None;
        self.receive_deadline_ms = None;
        if let Some(run_ctx) = ctx {
            run_ctx.reset_save();
        }
        Ok(())
    }

    pub(crate) fn timeout(&mut self) {
        // `timeout` leaves the current receive and prepares the next one.
        // Port of erts/emulator/beam/emu/msg_instrs.tab (`timeout`) and
        // erl_proc_sig_queue.h:2331 (`erts_msgq_set_save_first`), OTP-29.1.1.
        self.receive_cursor = 0;
        if let Some(cold) = self.cold.as_mut() {
            cold.priority_resume_cursor = None;
        }
        self.receive_deadline = None;
        self.receive_deadline_ms = None;
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
        if value.as_atom() == Some(arinsal_term::atoms::INFINITY) {
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
    use super::{MARKER_SLOTS, MarkerId, Process, ReceiveMarkers, Term};

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
            markers.reserve(1, reservation, None);
            markers.bind(reservation, Some(reference));
            assert_eq!(markers.set_save(reference), Some((1, None)));
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
        markers.reserve(2, oldest, None);
        markers.bind(oldest, Some(1));
        for reference in 2..=MARKER_SLOTS as u64 {
            let reservation = -i64::try_from(reference).unwrap();
            markers.reserve(3, reservation, None);
            markers.bind(reservation, Some(reference));
        }
        let reservation = -9;
        markers.reserve(4, reservation, None);
        markers.bind(reservation, Some(9));
        assert_eq!(markers.set_save(1), None);
        assert_eq!(markers.set_save(9), Some((4, None)));
        assert_eq!(markers.len(), MARKER_SLOTS);
        markers.removed(0);
        assert_eq!(markers.set_save(9), Some((3, None)));
        markers.removed(0);
        markers.removed(0);
        markers.removed(0);
        assert_eq!(markers.set_save(9), None);
        assert_eq!(markers.len(), 0);
    }

    #[test]
    fn using_an_older_marker_passes_newer_markers_at_the_same_boundary() {
        let mut markers = ReceiveMarkers::default();
        markers.reserve(2, -1, None);
        markers.bind(-1, Some(1));
        markers.reserve(2, -2, None);
        markers.bind(-2, Some(2));
        for _ in 0..=super::MARKER_PASS_MAX {
            assert_eq!(markers.set_save(1), Some((2, None)));
        }
        assert_eq!(markers.set_save(2), None);
        assert_eq!(markers.len(), 1);
    }
}
