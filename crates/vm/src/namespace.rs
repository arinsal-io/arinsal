//! Namespace table: one entry per `(tenant, project)` namespace of a node.
//!
//! Namespace 0 is root and has no entry. Ids are handed out in order and never reused on a
//! node, so a stale id cannot name a later namespace.

use crate::register::RegisterTable;
use std::sync::{Arc, OnceLock, RwLock};

/// No cap.
pub(crate) const UNLIMITED: u64 = u64::MAX;

/// One namespace.
#[allow(dead_code)] // the caps and names are read by `info/1` and the accounting step
pub(crate) struct NsEntry {
    pub(crate) id: u32,
    pub(crate) tenant: Vec<u8>,
    pub(crate) project: Vec<u8>,
    /// Caps from `create/3`; enforcement comes with the accounting step.
    pub(crate) max_processes: u64,
    pub(crate) max_bytes: u64,
    /// Registered names of this namespace, created on the first `register/2`.
    names: OnceLock<RegisterTable>,
}

impl NsEntry {
    /// The name table, created on first use.
    pub(crate) fn names(&self) -> &RegisterTable {
        self.names.get_or_init(RegisterTable::new)
    }

    /// The name table when something was ever registered in this namespace.
    pub(crate) fn names_if_created(&self) -> Option<&RegisterTable> {
        self.names.get()
    }
}

/// The namespaces of a node.
#[derive(Default)]
pub(crate) struct NsTable {
    entries: RwLock<Vec<Arc<NsEntry>>>,
}

impl NsTable {
    /// Create a namespace.
    pub(crate) fn create(
        &self,
        tenant: Vec<u8>,
        project: Vec<u8>,
        max_processes: u64,
        max_bytes: u64,
    ) -> Arc<NsEntry> {
        let mut entries = self.entries.write().unwrap_or_else(|e| e.into_inner());
        let entry = Arc::new(NsEntry {
            id: entries.len() as u32 + 1,
            tenant,
            project,
            max_processes,
            max_bytes,
            names: OnceLock::new(),
        });
        entries.push(entry.clone());
        entry
    }

    /// The entry of `id`.
    pub(crate) fn get(&self, id: u32) -> Option<Arc<NsEntry>> {
        let index = usize::try_from(id.checked_sub(1)?).ok()?;
        self.entries
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(index)
            .cloned()
    }
}
