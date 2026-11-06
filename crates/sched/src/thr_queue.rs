//! Multi-producer queue for work handed to one scheduler (aux work, timer requests).
//!
//! Stands in for erts' `erts_thr_q` / `ErtsMiscAuxWorkQ` (erts/emulator/beam/erl_process.c,
//! `erts_schedule_misc_aux_work`; erts/lib_src/common/ethr_aux.c `ethr_thr_queue`), OTP-29.1.1.
//! Remaining difference: erts' queue is lock-free; this one takes a short lock to enqueue and
//! dequeue and keeps an atomic length for the emptiness check done on every scheduling pass.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};

use parking_lot::Mutex;

/// FIFO queue with a lock-free emptiness check.
pub(crate) struct ThrQueue<T> {
    items: Mutex<VecDeque<T>>,
    len: AtomicUsize,
}

impl<T> ThrQueue<T> {
    pub(crate) fn new() -> Self {
        Self {
            items: Mutex::new(VecDeque::new()),
            len: AtomicUsize::new(0),
        }
    }

    pub(crate) fn push(&self, item: T) {
        let mut items = self.items.lock();
        items.push_back(item);
        self.len.fetch_add(1, Ordering::Release);
    }

    pub(crate) fn pop(&self) -> Option<T> {
        if self.is_empty() {
            return None;
        }
        let mut items = self.items.lock();
        let item = items.pop_front();
        if item.is_some() {
            self.len.fetch_sub(1, Ordering::Release);
        }
        item
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.len.load(Ordering::Acquire) == 0
    }
}
