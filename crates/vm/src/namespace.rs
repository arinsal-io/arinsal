//! Namespace table: one entry per `(tenant, project)` namespace of a node.
//!
//! Namespace 0 is root and has no entry. Ids are handed out in order and never reused on a
//! node, so a stale id cannot name a later namespace.

use arinsal_sched::{NsCounters, Scheduler, Task};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, RwLock};

/// No cap.
pub(crate) const UNLIMITED: u64 = u64::MAX;

/// One namespace.
pub(crate) struct NsEntry {
    pub(crate) id: u32,
    pub(crate) tenant: Vec<u8>,
    pub(crate) project: Vec<u8>,
    /// Cap from `create/3`; enforcement comes with the accounting step.
    pub(crate) max_bytes: u64,
    /// Live heap of the namespace's processes, in words. Updated after collections once the
    /// heap accounting step lands; 0 until then.
    pub(crate) heap_words: AtomicI64,
    /// Process and reduction counters and the process cap, shared with the scheduler.
    pub(crate) counters: Arc<NsCounters>,
    alive: AtomicBool,
}

impl NsEntry {
    pub(crate) fn is_alive(&self) -> bool {
        self.alive.load(Ordering::Acquire)
    }
}

/// The namespaces of a node.
#[derive(Default)]
pub(crate) struct NsTable {
    entries: RwLock<Vec<Arc<NsEntry>>>,
}

impl NsTable {
    /// Create a namespace and register it with the scheduler.
    pub(crate) fn create<T: Task>(
        &self,
        scheduler: &Scheduler<T>,
        tenant: Vec<u8>,
        project: Vec<u8>,
        max_processes: u64,
        max_bytes: u64,
    ) -> Arc<NsEntry> {
        let mut entries = self.entries.write().unwrap_or_else(|e| e.into_inner());
        let id = entries.len() as u32 + 1;
        let entry = Arc::new(NsEntry {
            id,
            tenant,
            project,
            max_bytes,
            heap_words: AtomicI64::new(0),
            counters: scheduler.ns_register(id, max_processes),
            alive: AtomicBool::new(true),
        });
        entries.push(entry.clone());
        entry
    }

    /// The entry of `id`, destroyed or not.
    pub(crate) fn get(&self, id: u32) -> Option<Arc<NsEntry>> {
        let index = usize::try_from(id.checked_sub(1)?).ok()?;
        self.entries
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(index)
            .cloned()
    }

    /// The entry of `id` while it is alive.
    pub(crate) fn live(&self, id: u32) -> Option<Arc<NsEntry>> {
        self.get(id).filter(|entry| entry.is_alive())
    }

    /// Ids of the namespaces that are alive.
    pub(crate) fn list(&self) -> Vec<u32> {
        self.entries
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|entry| entry.is_alive())
            .map(|entry| entry.id)
            .collect()
    }

    /// Mark `id` destroyed and make the scheduler refuse every later spawn into it. False
    /// when it was unknown or already destroyed.
    pub(crate) fn close(&self, id: u32) -> bool {
        let Some(entry) = self.get(id) else {
            return false;
        };
        entry.counters.close();
        entry.alive.swap(false, Ordering::AcqRel)
    }
}
