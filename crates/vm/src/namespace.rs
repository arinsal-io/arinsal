//! Namespace table: one entry per `(tenant, project)` namespace of a node.
//!
//! Namespace 0 is root and has no entry. Ids are handed out in order and never reused on a
//! node, so a stale id cannot name a later namespace.

use crate::register::RegisterTable;
use arinsal_sched::{NsCounters, Scheduler, Task};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, Ordering};
use std::sync::{Arc, OnceLock, RwLock};

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
    /// What `erlang:system_info(schedulers | schedulers_online)` answers inside this namespace
    /// (`schedulers` option of `create/3`, default 1), so partitioned libraries start one
    /// partition per namespace instead of one per scheduler of the node.
    pub(crate) schedulers: AtomicU32,
    /// Process and reduction counters and the process cap, shared with the scheduler.
    pub(crate) counters: Arc<NsCounters>,
    alive: AtomicBool,
    /// Registered names of this namespace, created on the first `register/2`.
    names: OnceLock<RegisterTable>,
    /// OS environment of the namespace: a set value, or `None` for a variable that was
    /// unset. Variables not listed here fall back to [`ENV_ALLOWLIST`] of the node.
    env: RwLock<BTreeMap<OsString, Option<OsString>>>,
    /// Code lookup chain of every process of this namespace; `None` resolves in the base only.
    pub(crate) code_chain: Option<crate::code_domains::DomainChain>,
    /// The chain's first domain was created for this namespace and is dropped with it.
    pub(crate) owns_code_domain: bool,
}

/// Variables a namespace still reads from the process-wide environment. Everything else of
/// the node environment (tokens, credentials) is invisible to tenants.
pub(crate) const ENV_ALLOWLIST: &[&str] = &["PATH", "HOME", "LANG", "TZ"];

impl NsEntry {
    /// Set a variable of the namespace environment.
    pub(crate) fn env_put(&self, name: OsString, value: OsString) {
        self.env
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(name, Some(value));
    }

    /// Unset a variable; an allowlisted one stays hidden from then on.
    pub(crate) fn env_unset(&self, name: OsString) {
        self.env
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(name, None);
    }

    /// The environment overlay, read by the `os` environment BIFs.
    pub(crate) fn env(&self) -> &RwLock<BTreeMap<OsString, Option<OsString>>> {
        &self.env
    }

    /// The name table, created on first use.
    pub(crate) fn names(&self) -> &RegisterTable {
        self.names.get_or_init(RegisterTable::new)
    }

    /// The name table when something was ever registered in this namespace.
    pub(crate) fn names_if_created(&self) -> Option<&RegisterTable> {
        self.names.get()
    }
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
        code: crate::code_domains::NsCode,
    ) -> Arc<NsEntry> {
        let mut entries = self.entries.write().unwrap_or_else(|e| e.into_inner());
        let id = entries.len() as u32 + 1;
        let entry = Arc::new(NsEntry {
            id,
            tenant,
            project,
            max_bytes,
            heap_words: AtomicI64::new(0),
            schedulers: AtomicU32::new(1),
            counters: scheduler.ns_register(id, max_processes),
            alive: AtomicBool::new(true),
            names: OnceLock::new(),
            env: RwLock::new(BTreeMap::new()),
            code_chain: code.chain,
            owns_code_domain: code.owns_first,
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
