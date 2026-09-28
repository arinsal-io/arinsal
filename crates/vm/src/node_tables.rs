//! Runtime-wide node names, distribution entries, and node monitors.

use arinsal_etf::{AtomCache, OwnedTerm};
use arinsal_sched::Pid;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::atomic::{AtomicI64, AtomicU32, AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::Instant;

/// Connection lifecycle for one [`NodeEntry`].
///
/// Port of erts/emulator/beam/erl_node_tables.h (`ERTS_DE_STATE_*`), OTP-29.1.1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ConnState {
    Idle,
    Pending,
    Connected,
    Exiting,
}

/// One node-table entry, including whether it currently has a connection.
#[derive(Clone, Debug)]
pub(crate) struct NodeEntry {
    pub(crate) name: String,
    pub(crate) creation: u32,
    /// Current connection id (masked to 24 bits, matching `ERTS_DIST_CON_ID_MASK`).
    pub(crate) connection_id: u32,
    /// Stable id used as the magic-ref half of a distribution handle.
    pub(crate) entry_ref: u64,
    pub(crate) state: ConnState,
    pub(crate) visible: bool,
    pub(crate) connected: bool,
    pub(crate) dist: Option<DistState>,
    /// Signals queued while the connection is still pending (auto-connect).
    pub(crate) pending_out: VecDeque<(OwnedTerm, Option<OwnedTerm>)>,
    /// Remote monitors armed before the distribution channel exists.
    pub(crate) pending_monitors: BTreeMap<u64, OwnedTerm>,
}

/// Controller-owned state for one active distribution connection.
#[derive(Clone, Debug)]
pub(crate) struct DistState {
    pub(crate) handle: u64,
    /// Real inet TCP port acting as DistCtrlr, when using the port-controller path.
    pub(crate) port_id: Option<u64>,
    pub(crate) owner: Pid,
    pub(crate) input_handler: Pid,
    pub(crate) output: VecDeque<Vec<u8>>,
    pub(crate) incoming_cache: AtomCache,
    pub(crate) outgoing_cache: AtomCache,
    pub(crate) get_size: bool,
    pub(crate) notify: bool,
    pub(crate) read: u64,
    pub(crate) written: u64,
    pub(crate) pending_bytes: u64,
    pub(crate) flags: u64,
    pub(crate) remote_pids: HashMap<(u32, u32, u32), Pid>,
    /// Reverse map for local proxy pids created by [`Self::remote_pids`].
    pub(crate) proxy_to_remote: HashMap<Pid, OwnedTerm>,
    pub(crate) remote_monitors: BTreeMap<u64, OwnedTerm>,
    pub(crate) spawn_requests: BTreeMap<u64, SpawnRequest>,
}

/// Outstanding `spawn_request` waiting for `DOP_SPAWN_REPLY`.
#[derive(Clone, Debug)]
pub(crate) struct SpawnRequest {
    pub(crate) caller: Pid,
    pub(crate) tag: OwnedTerm,
    pub(crate) monitor: bool,
    /// `{reply, error_only}` / `{reply, no}` — suppress success mailbox message.
    pub(crate) no_success_msg: bool,
}

impl DistState {
    pub(crate) fn new(handle: u64, owner: Pid, flags: u64) -> Self {
        Self {
            handle,
            port_id: None,
            owner,
            input_handler: owner,
            output: VecDeque::new(),
            incoming_cache: AtomCache::new(),
            outgoing_cache: AtomCache::new(),
            get_size: false,
            notify: false,
            read: 0,
            written: 0,
            pending_bytes: 0,
            flags,
            remote_pids: HashMap::new(),
            proxy_to_remote: HashMap::new(),
            remote_monitors: BTreeMap::new(),
            spawn_requests: BTreeMap::new(),
        }
    }

    pub(crate) fn queue_term(&mut self, control: OwnedTerm, message: Option<OwnedTerm>) {
        let _negotiated_flags = self.flags;
        let packet = if let Some(message) = message {
            arinsal_etf::encode_dist_packet_terms(
                &[&control, &message],
                &mut self.outgoing_cache,
                None,
            )
        } else {
            arinsal_etf::encode_dist_packet(&control, &mut self.outgoing_cache, None)
        };
        self.pending_bytes = self.pending_bytes.saturating_add(packet.len() as u64);
        self.output.push_back(packet);
    }

    /// Encode one signal and return the packet bytes (also tracked in pending).
    ///
    /// Callers that hold [`lock`] must relabel local identities first — this
    /// method must not take the node-tables lock.
    pub(crate) fn encode_term(
        &mut self,
        control: OwnedTerm,
        message: Option<OwnedTerm>,
    ) -> Vec<u8> {
        let packet = if let Some(message) = message {
            arinsal_etf::encode_dist_packet_terms(
                &[&control, &message],
                &mut self.outgoing_cache,
                None,
            )
        } else {
            arinsal_etf::encode_dist_packet(&control, &mut self.outgoing_cache, None)
        };
        self.pending_bytes = self.pending_bytes.saturating_add(packet.len() as u64);
        packet
    }
}

/// Rewrite `nonode@nohost` pid/port/ref identities to this node's name/creation.
///
/// Port of external.c encode path for internal things on a live node, OTP-29.1.1.
pub(crate) fn relabel_local_node(mut term: OwnedTerm, local: &str, creation: u32) -> OwnedTerm {
    match &mut term {
        OwnedTerm::Pid {
            node, creation: c, ..
        } if node.as_str() == "nonode@nohost" => {
            *node = local.to_string();
            *c = creation;
        }
        OwnedTerm::Port {
            node, creation: c, ..
        } if node.as_str() == "nonode@nohost" => {
            *node = local.to_string();
            *c = creation;
        }
        OwnedTerm::Ref {
            node, creation: c, ..
        } if node.as_str() == "nonode@nohost" => {
            *node = local.to_string();
            *c = creation;
        }
        OwnedTerm::Tuple(parts) => {
            for part in parts.iter_mut() {
                let taken = std::mem::replace(part, OwnedTerm::Nil);
                *part = relabel_local_node(taken, local, creation);
            }
        }
        OwnedTerm::List { elems, tail } => {
            for elem in elems.iter_mut() {
                let taken = std::mem::replace(elem, OwnedTerm::Nil);
                *elem = relabel_local_node(taken, local, creation);
            }
            let taken = std::mem::replace(tail.as_mut(), OwnedTerm::Nil);
            *tail.as_mut() = relabel_local_node(taken, local, creation);
        }
        OwnedTerm::Map(entries) => {
            for (key, value) in entries.iter_mut() {
                let taken_k = std::mem::replace(key, OwnedTerm::Nil);
                *key = relabel_local_node(taken_k, local, creation);
                let taken_v = std::mem::replace(value, OwnedTerm::Nil);
                *value = relabel_local_node(taken_v, local, creation);
            }
        }
        _ => {}
    }
    term
}

#[derive(Clone, Debug)]
pub(crate) struct NodeMonitor {
    pub(crate) pid: Pid,
    pub(crate) node: String,
    pub(crate) references: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NodeKind {
    This,
    Visible,
    Hidden,
    Known,
}

#[derive(Debug)]
pub(crate) struct NodeTables {
    pub(crate) local_name: String,
    pub(crate) local_creation: u32,
    pub(crate) alive: bool,
    pub(crate) entries: BTreeMap<String, NodeEntry>,
    pub(crate) monitors: Vec<NodeMonitor>,
    pending_delete: HashMap<String, Instant>,
}

impl Default for NodeTables {
    fn default() -> Self {
        let mut entries = BTreeMap::new();
        entries.insert(
            "nonode@nohost".into(),
            NodeEntry {
                name: "nonode@nohost".into(),
                creation: 0,
                connection_id: 0,
                entry_ref: 0,
                state: ConnState::Idle,
                visible: true,
                connected: false,
                dist: None,
                pending_out: VecDeque::new(),
                pending_monitors: BTreeMap::new(),
            },
        );
        Self {
            local_name: "nonode@nohost".into(),
            local_creation: 0,
            alive: false,
            entries,
            monitors: Vec::new(),
            pending_delete: HashMap::new(),
        }
    }
}

impl NodeTables {
    fn prune_deleted(&mut self) {
        let now = Instant::now();
        let expired = self
            .pending_delete
            .iter()
            .filter_map(|(node, deadline)| (*deadline <= now).then_some(node.clone()))
            .collect::<Vec<_>>();
        for node in expired {
            self.pending_delete.remove(&node);
            if node != self.local_name
                && !self.entries.get(&node).is_some_and(|entry| entry.connected)
                && !self.monitors.iter().any(|monitor| monitor.node == node)
            {
                self.entries.remove(&node);
            }
        }
    }
}

static TABLES: OnceLock<Mutex<NodeTables>> = OnceLock::new();
static NEXT_ENTRY_REF: AtomicU64 = AtomicU64::new(1);
static NODE_TAB_DELETE_DELAY_MS: AtomicI64 = AtomicI64::new(-1);
static NEXT_CONN_SEED: AtomicU32 = AtomicU32::new(1);

/// Ports currently acting as distribution controllers (`port_id` → node name).
static DIST_PORTS: OnceLock<Mutex<HashMap<u64, String>>> = OnceLock::new();

pub(crate) fn lock() -> MutexGuard<'static, NodeTables> {
    let mut tables = TABLES
        .get_or_init(|| Mutex::new(NodeTables::default()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    tables.prune_deleted();
    tables
}

fn dist_ports() -> MutexGuard<'static, HashMap<u64, String>> {
    DIST_PORTS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// True when `port_id` is the DistCtrlr for an active connection.
pub(crate) fn is_dist_port(port_id: u64) -> bool {
    dist_ports().contains_key(&port_id)
}

/// Node name for a distribution port, if any.
#[allow(dead_code)] // retained for DistCtrlr diagnostics / future teardown
pub(crate) fn dist_port_node(port_id: u64) -> Option<String> {
    dist_ports().get(&port_id).cloned()
}

pub(crate) fn register_dist_port(port_id: u64, node: String) {
    dist_ports().insert(port_id, node);
}

pub(crate) fn unregister_dist_port(port_id: u64) -> Option<String> {
    dist_ports().remove(&port_id)
}

const CON_ID_MASK: u32 = 0x00ff_ffff;

fn fresh_entry(name: String) -> NodeEntry {
    NodeEntry {
        name,
        creation: 0,
        connection_id: NEXT_CONN_SEED.fetch_add(1, Ordering::Relaxed) & CON_ID_MASK,
        entry_ref: NEXT_ENTRY_REF.fetch_add(1, Ordering::Relaxed),
        state: ConnState::Idle,
        visible: true,
        connected: false,
        dist: None,
        pending_out: VecDeque::new(),
        pending_monitors: BTreeMap::new(),
    }
}

impl NodeTables {
    pub(crate) fn local_identity(&self) -> (&str, u32) {
        let entry = self
            .entries
            .get(&self.local_name)
            .expect("the local distribution entry is always present");
        debug_assert_eq!(entry.creation, self.local_creation);
        (&entry.name, entry.creation)
    }

    /// Return whether a pid's distribution entry advertises Unicode I/O.
    ///
    /// Port of erts/emulator/beam/dist.c:6670 (net_kernel_dflag_unicode_io_1), OTP-29.1.1.
    pub(crate) fn pid_unicode_io(&self, node: &str) -> bool {
        if node == self.local_name {
            return true;
        }
        self.entries
            .get(node)
            .and_then(|entry| entry.dist.as_ref())
            .is_some_and(|dist| dist.flags & DFLAG_UNICODE_IO != 0)
    }

    /// Port of erts/emulator/beam/dist.c:4978 (setnode_2), OTP-29.1.1.
    pub(crate) fn set_local_node(&mut self, name: String, creation: u32) -> bool {
        if self.alive || name == "nonode@nohost" || !is_node_name(&name) {
            return false;
        }
        let creation = creation.max(4);
        self.pending_delete.remove(&self.local_name);
        self.entries.remove(&self.local_name);
        self.local_name = name.clone();
        self.local_creation = creation;
        self.alive = true;
        self.entries.insert(
            name.clone(),
            NodeEntry {
                name,
                creation,
                connection_id: 0,
                entry_ref: NEXT_ENTRY_REF.fetch_add(1, Ordering::Relaxed),
                state: ConnState::Idle,
                visible: true,
                connected: false,
                dist: None,
                pending_out: VecDeque::new(),
                pending_monitors: BTreeMap::new(),
            },
        );
        true
    }

    /// Port of erts/emulator/beam/dist.c:5588 (erts_internal_new_connection_1), OTP-29.1.1.
    ///
    /// Returns `(connection_id, entry_ref)` for the distribution handle.
    pub(crate) fn new_connection(&mut self, node: &str) -> Option<(u32, u64)> {
        if !is_node_name(node) || node == self.local_name {
            return None;
        }
        self.pending_delete.remove(node);
        let entry = self
            .entries
            .entry(node.to_string())
            .or_insert_with(|| fresh_entry(node.to_string()));
        match entry.state {
            ConnState::Connected | ConnState::Exiting | ConnState::Pending => {}
            ConnState::Idle => {
                // Port of erl_node_tables.c:689 (erts_set_dist_entry_pending), OTP-29.1.1.
                entry.connection_id = (entry.connection_id + 1) & CON_ID_MASK;
                entry.state = ConnState::Pending;
                entry.connected = false;
                entry.dist = None;
            }
        }
        Some((entry.connection_id, entry.entry_ref))
    }

    /// Port of erts/emulator/beam/dist.c:5693 (erts_internal_abort_pending_connection_2), OTP-29.1.1.
    ///
    /// Returns `Ok(true)` when the abort applied to a non-connected entry (OTP
    /// returns `true` when `was_connected` is false).
    pub(crate) fn abort_pending(
        &mut self,
        node: &str,
        conn_id: u32,
        entry_ref: u64,
    ) -> Option<bool> {
        if node == self.local_name {
            return None;
        }
        let entry = self.entries.get_mut(node)?;
        if entry.entry_ref != entry_ref {
            return None;
        }
        if entry.connection_id != conn_id {
            return Some(true);
        }
        let was_connected = entry.state == ConnState::Connected;
        if entry.state == ConnState::Pending {
            entry.state = ConnState::Idle;
            entry.connected = false;
            entry.dist = None;
            entry.pending_out.clear();
            entry.pending_monitors.clear();
        }
        Some(!was_connected)
    }

    /// Port of erts/emulator/beam/erl_node_tables.c:733 (set connected dist entry), OTP-29.1.1.
    #[allow(dead_code)] // used by tests / forthcoming connection bookkeeping
    pub(crate) fn connect(
        &mut self,
        name: String,
        creation: u32,
        connection_id: u32,
        visible: bool,
    ) {
        self.pending_delete.remove(&name);
        let entry_ref = self
            .entries
            .get(&name)
            .map(|entry| entry.entry_ref)
            .unwrap_or_else(|| NEXT_ENTRY_REF.fetch_add(1, Ordering::Relaxed));
        self.entries.insert(
            name.clone(),
            NodeEntry {
                name,
                creation,
                connection_id,
                entry_ref,
                state: ConnState::Connected,
                visible,
                connected: true,
                dist: None,
                pending_out: VecDeque::new(),
                pending_monitors: BTreeMap::new(),
            },
        );
    }

    /// Record a monitor and return true when an immediate down event is due.
    pub(crate) fn monitor(&mut self, pid: Pid, node: String, enabled: bool) -> bool {
        if node == self.local_name {
            return false;
        }
        if !enabled {
            if let Some(index) = self
                .monitors
                .iter()
                .position(|monitor| monitor.pid == pid && monitor.node == node)
            {
                if self.monitors[index].references > 1 {
                    self.monitors[index].references -= 1;
                } else {
                    self.monitors.remove(index);
                }
            }
            return false;
        }
        self.pending_delete.remove(&node);
        if let Some(monitor) = self
            .monitors
            .iter_mut()
            .find(|monitor| monitor.pid == pid && monitor.node == node)
        {
            monitor.references += 1;
        } else {
            self.monitors.push(NodeMonitor {
                pid,
                node: node.clone(),
                references: 1,
            });
        }
        if self.entries.get(&node).is_some_and(|entry| entry.connected) {
            return false;
        }
        self.entries
            .entry(node.clone())
            .or_insert_with(|| fresh_entry(node.clone()));
        !self.disconnect(&node).is_empty()
    }

    /// Remove a connection and return its subscribed monitors for nodedown delivery.
    pub(crate) fn disconnect(&mut self, node: &str) -> Vec<NodeMonitor> {
        if let Some(entry) = self.entries.get_mut(node) {
            entry.connected = false;
            entry.state = ConnState::Idle;
            if let Some(state) = entry.dist.take()
                && let Some(port_id) = state.port_id
            {
                drop(unregister_dist_port(port_id));
            }
        }
        let delay = NODE_TAB_DELETE_DELAY_MS.load(Ordering::Acquire);
        if delay < 0 {
            self.pending_delete.remove(node);
        } else if let Some(deadline) =
            Instant::now().checked_add(std::time::Duration::from_millis(delay as u64))
        {
            self.pending_delete.insert(node.to_owned(), deadline);
        }
        self.monitors
            .iter()
            .filter(|monitor| monitor.node == node)
            .cloned()
            .collect()
    }
}

pub(crate) fn is_node_name(name: &str) -> bool {
    let Some((short, host)) = name.split_once('@') else {
        return false;
    };
    !short.is_empty() && !host.is_empty() && !host.contains('@')
}

/// Distribution capability record returned by `erts_internal:get_dflags/0`.
///
/// Values match OTP-29.1.1 `DFLAG_DIST_*` on this platform (verified against `erl`).
pub(crate) const DFLAG_DIST_DEFAULT: u64 = 468_283_523_004;
pub(crate) const DFLAG_DIST_MANDATORY: u64 = 17_230_663_572;
pub(crate) const DFLAG_DIST_ADDABLE: u64 = 468_283_523_004;
pub(crate) const DFLAG_DIST_REJECTABLE: u64 = 8_396_866;
pub(crate) const DFLAG_DIST_STRICT_ORDER: u64 = 8_192;
pub(crate) const DFLAG_UNICODE_IO: u64 = 0x1000;

static TEST_REMOVE_DFLAGS: AtomicU64 = AtomicU64::new(0);

/// Set or read the distribution flags masked by the internal-state test BIF.
/// Port of erts/emulator/beam/dist.c:185 and erl_bif_info.c:5378, OTP-29.1.1.
pub(crate) fn test_remove_dflags(value: Option<u64>) -> u64 {
    if let Some(value) = value {
        TEST_REMOVE_DFLAGS.store(value, Ordering::Release);
    }
    TEST_REMOVE_DFLAGS.load(Ordering::Acquire)
}

/// Set the delayed node table deletion interval used by the internal-state test BIF.
/// Port of erts/emulator/beam/erl_node_tables.c:2571-2579, OTP-29.1.1.
pub(crate) fn test_node_tab_delayed_delete(milliseconds: i64) {
    NODE_TAB_DELETE_DELAY_MS.store(
        if milliseconds < 0 { -1 } else { milliseconds },
        Ordering::Release,
    );
}

#[cfg(test)]
mod tests {
    use super::{ConnState, NodeTables};

    #[test]
    fn setnode_initializes_local_node_and_clamps_creation() {
        let mut tables = NodeTables::default();
        assert!(tables.set_local_node("test@localhost".into(), 1));
        assert!(tables.alive);
        assert_eq!(tables.local_identity(), ("test@localhost", 4));
        assert!(!tables.set_local_node("other@localhost".into(), 4));
    }

    #[test]
    fn setnode_rejects_invalid_or_reserved_names() {
        let mut tables = NodeTables::default();
        assert!(!tables.set_local_node("nonode@nohost".into(), 4));
        assert!(!tables.set_local_node("missing-host".into(), 4));
        assert!(!tables.alive);
    }

    #[test]
    fn monitor_node_creates_known_entry_and_disconnect_reports_watchers() {
        let mut tables = NodeTables::default();
        assert!(tables.set_local_node("test@localhost".into(), 4));
        let pid = arinsal_sched::Pid {
            index: 1,
            generation: 0,
        };
        assert!(tables.monitor(pid, "unknown@host".into(), true));
        let watchers = tables.disconnect("unknown@host");
        assert_eq!(watchers.len(), 1);
        assert_eq!(watchers[0].pid, pid);
        assert_eq!(watchers[0].node, "unknown@host");
    }

    #[test]
    fn connected_node_is_reported_with_connection_metadata() {
        let mut tables = NodeTables::default();
        tables.connect("peer@localhost".into(), 9, 12, true);
        let entry = &tables.entries["peer@localhost"];
        assert!(entry.connected);
        assert!(entry.visible);
        assert_eq!(entry.creation, 9);
        assert_eq!(entry.connection_id, 12);
        assert_eq!(entry.state, ConnState::Connected);
    }

    #[test]
    fn new_connection_moves_idle_to_pending_and_reuses_id() {
        let mut tables = NodeTables::default();
        assert!(tables.set_local_node("a@host".into(), 4));
        let (id1, ref1) = tables.new_connection("b@host").unwrap();
        let entry = &tables.entries["b@host"];
        assert_eq!(entry.state, ConnState::Pending);
        assert_eq!(entry.connection_id, id1);
        assert_eq!(entry.entry_ref, ref1);
        let (id2, ref2) = tables.new_connection("b@host").unwrap();
        assert_eq!(id1, id2);
        assert_eq!(ref1, ref2);
    }

    #[test]
    fn abort_pending_clears_pending_and_rejects_local() {
        let mut tables = NodeTables::default();
        assert!(tables.set_local_node("a@host".into(), 4));
        let (id, eref) = tables.new_connection("b@host").unwrap();
        assert_eq!(tables.abort_pending("b@host", id, eref), Some(true));
        assert_eq!(tables.entries["b@host"].state, ConnState::Idle);
        assert!(tables.abort_pending("a@host", id, eref).is_none());
    }
}
