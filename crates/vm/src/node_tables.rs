//! Runtime-wide node names, distribution entries, and node monitors.

use arinsal_etf::{AtomCache, DistributionPacket, OwnedTerm};
use arinsal_sched::Pid;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::atomic::{AtomicI64, AtomicU32, AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::Instant;

pub(crate) const DFLAG_FRAGMENTS: u64 = 0x0080_0000;
pub(crate) const DFLAG_EXIT_PAYLOAD: u64 = 0x0040_0000;

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
    /// Distributed spawn requests retained while auto-connect is pending.
    pub(crate) pending_spawn_requests: BTreeMap<u64, SpawnRequest>,
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
    /// Number of FIFO head packets prepared for the port scheduler.
    pub(crate) output_ready_packets: usize,
    /// Serializes port writes so concurrent schedulers cannot reorder atom-cache headers.
    pub(crate) flushing_output: bool,
    /// Encoded fragment tails retained until the sending process continues.
    pub(crate) fragment_continuations: VecDeque<DistFragmentContinuation>,
    pub(crate) incoming_cache: AtomCache,
    pub(crate) outgoing_sequence_id: u64,
    /// Incomplete incoming fragmented signals, keyed by OTP sequence id.
    pub(crate) incoming_fragments: HashMap<u64, IncomingDistFragment>,
    pub(crate) outgoing_cache: AtomCache,
    pub(crate) get_size: bool,
    pub(crate) notify: bool,
    pub(crate) read: u64,
    pub(crate) written: u64,
    pub(crate) pending_bytes: u64,
    pub(crate) busy_limit: u64,
    pub(crate) busy: bool,
    /// The inet port's own busy state is separate from the dist entry queue.
    pub(crate) port_busy: bool,
    pub(crate) suspended_senders: Vec<Pid>,
    pub(crate) flags: u64,
    pub(crate) remote_pids: HashMap<(u32, u32, u32), Pid>,
    /// Reverse map for local proxy pids created by [`Self::remote_pids`].
    pub(crate) proxy_to_remote: HashMap<Pid, OwnedTerm>,
    pub(crate) remote_monitors: BTreeMap<u64, OwnedTerm>,
    /// Original ETF refs from remote monitor requests, preserving all reference words.
    pub(crate) remote_monitor_refs: BTreeMap<u64, OwnedTerm>,
    pub(crate) spawn_requests: BTreeMap<u64, SpawnRequest>,
}

#[derive(Clone, Debug)]
pub(crate) struct DistFragmentContinuation {
    /// `None` is output from a no-suspend controller/exit path.
    pub(crate) sender: Option<Pid>,
    pub(crate) remaining_packets: usize,
}

/// Reassembly state for an OTP `DIST_FRAG_HEADER` signal.
#[derive(Clone, Debug)]
pub(crate) struct IncomingDistFragment {
    pub(crate) next_fragment_id: u64,
    pub(crate) packet: DistributionPacket,
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
            output_ready_packets: 0,
            flushing_output: false,
            fragment_continuations: VecDeque::new(),
            incoming_cache: AtomCache::new(),
            outgoing_sequence_id: 1,
            incoming_fragments: HashMap::new(),
            outgoing_cache: AtomCache::new(),
            get_size: false,
            notify: false,
            read: 0,
            written: 0,
            pending_bytes: 0,
            busy_limit: 1024 * 1024,
            busy: false,
            port_busy: false,
            suspended_senders: Vec::new(),
            flags,
            remote_pids: HashMap::new(),
            proxy_to_remote: HashMap::new(),
            remote_monitors: BTreeMap::new(),
            remote_monitor_refs: BTreeMap::new(),
            spawn_requests: BTreeMap::new(),
        }
    }

    pub(crate) fn queue_term(
        &mut self,
        control: OwnedTerm,
        message: Option<OwnedTerm>,
    ) -> Result<(), arinsal_etf::DecodeError> {
        let packets = self.encode_packets(&control, message.as_ref())?;
        self.pending_bytes = self
            .pending_bytes
            .saturating_add(packets.iter().map(|packet| packet.len() as u64).sum());
        self.output.extend(packets);
        Ok(())
    }

    fn encode_packets(
        &mut self,
        control: &OwnedTerm,
        message: Option<&OwnedTerm>,
    ) -> Result<Vec<Vec<u8>>, arinsal_etf::DecodeError> {
        let sequence_id = self.outgoing_sequence_id;
        self.outgoing_sequence_id = self.outgoing_sequence_id.wrapping_add(1).max(1);
        let mut terms = vec![control];
        if let Some(message) = message {
            terms.push(message);
        }
        let packets = if self.flags & DFLAG_FRAGMENTS != 0 {
            arinsal_etf::encode_dist_packet_terms_fragmented(
                &terms,
                &mut self.outgoing_cache,
                sequence_id,
                64 * 1024,
            )?
        } else {
            vec![arinsal_etf::encode_dist_packet_terms(
                &terms,
                &mut self.outgoing_cache,
                None,
            )]
        };
        Ok(packets)
    }

    /// Encode one signal as ordered framed distribution packets.
    ///
    /// Callers that hold [`lock`] must relabel local identities first — this
    /// method must not take the node-tables lock.
    pub(crate) fn encode_term(
        &mut self,
        control: OwnedTerm,
        message: Option<OwnedTerm>,
    ) -> Result<Vec<Vec<u8>>, arinsal_etf::DecodeError> {
        let packets = self.encode_packets(&control, message.as_ref())?;
        self.pending_bytes = self
            .pending_bytes
            .saturating_add(packets.iter().map(|packet| packet.len() as u64).sum());
        Ok(packets)
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
        OwnedTerm::Record { fields, .. } => {
            for (_, value) in fields {
                let taken = std::mem::replace(value, OwnedTerm::Nil);
                *value = relabel_local_node(taken, local, creation);
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

#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct NodeMonitorOptions {
    pub(crate) info_map: bool,
    pub(crate) list: bool,
    pub(crate) connection_id: bool,
    pub(crate) visible: bool,
    pub(crate) hidden: bool,
    pub(crate) nodedown_reason: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct NodesMonitor {
    pub(crate) pid: Pid,
    pub(crate) options: NodeMonitorOptions,
    pub(crate) references: usize,
}

#[derive(Clone, Debug)]
pub(crate) struct NodesMonitorEvent {
    pub(crate) pid: Pid,
    pub(crate) message: OwnedTerm,
}

/// Decode and validate the options accepted by `process_flag({monitor_nodes, Map}, Bool)`.
/// Port of erts/emulator/beam/dist.c:6732-6790, OTP-29.1.1.
pub(crate) fn parse_nodes_monitor_options(options: &OwnedTerm) -> Result<NodeMonitorOptions, ()> {
    let OwnedTerm::Map(entries) = options else {
        return Err(());
    };
    let mut result = NodeMonitorOptions {
        info_map: true,
        ..NodeMonitorOptions::default()
    };
    for (key, value) in entries {
        let OwnedTerm::Atom(key) = key else {
            return Err(());
        };
        match key.as_str() {
            "list" => match value {
                OwnedTerm::Atom(value) if value == "true" => {
                    result.list = true;
                    result.info_map = false;
                }
                _ => return Err(()),
            },
            "connection_id" => match value {
                OwnedTerm::Atom(value) if value == "true" => result.connection_id = true,
                OwnedTerm::Atom(value) if value == "false" => {}
                _ => return Err(()),
            },
            "node_type" => match value {
                OwnedTerm::Atom(value) if value == "visible" => result.visible = true,
                OwnedTerm::Atom(value) if value == "hidden" => result.hidden = true,
                OwnedTerm::Atom(value) if value == "all" => {
                    result.visible = true;
                    result.hidden = true;
                }
                _ => return Err(()),
            },
            "nodedown_reason" => match value {
                OwnedTerm::Atom(value) if value == "true" => result.nodedown_reason = true,
                OwnedTerm::Atom(value) if value == "false" => {}
                _ => return Err(()),
            },
            _ => return Err(()),
        }
    }
    Ok(result)
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
    pub(crate) distribution_buffer_busy_limit: u64,
    pub(crate) entries: BTreeMap<String, NodeEntry>,
    pub(crate) monitors: Vec<NodeMonitor>,
    pending_delete: HashMap<String, Instant>,
    pub(crate) nodes_monitors: Vec<NodesMonitor>,
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
                pending_spawn_requests: BTreeMap::new(),
            },
        );
        Self {
            local_name: "nonode@nohost".into(),
            local_creation: 0,
            alive: false,
            distribution_buffer_busy_limit: 1024 * 1024,
            entries,
            monitors: Vec::new(),
            pending_delete: HashMap::new(),
            nodes_monitors: Vec::new(),
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

/// Set (under the table lock) whenever a fragmented send is deferred; cleared by
/// `continue_fragmented_send` once no entry holds one.
pub(crate) static ANY_FRAGMENT_CONTINUATION: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// `erts_this_node->sysname`: the local node name atom, which native `node/0` loads
/// without a runtime call; [`set_this_node`] updates it.
static THIS_NODE_SYSNAME: AtomicU64 = AtomicU64::new(0);

fn node_atom_word(name: &str) -> u64 {
    arinsal_term::global_atoms()
        .intern(name)
        .map_or(0, |atom| arinsal_term::Term::atom(atom).tagged_word())
}

/// The word holding the local node name atom; generated code reads it by address.
pub(crate) fn this_node_sysname() -> &'static AtomicU64 {
    if THIS_NODE_SYSNAME.load(Ordering::Acquire) == 0 {
        let word = node_atom_word(&lock().local_name);
        let _ = THIS_NODE_SYSNAME.compare_exchange(0, word, Ordering::AcqRel, Ordering::Acquire);
    }
    &THIS_NODE_SYSNAME
}

/// Makes `name` the local node of the node table, as `setnode/2` does, and publishes it to
/// native `node/0`.
// Port of erts/emulator/beam/erl_node_tables.c:1042-1075 (erts_set_this_node), OTP-29.1.1.
pub(crate) fn set_this_node(name: String, creation: u32) -> bool {
    let mut tables = lock();
    let word = node_atom_word(&name);
    if !tables.set_local_node(name, creation) {
        return false;
    }
    THIS_NODE_SYSNAME.store(word, Ordering::Release);
    if let Ok(atom) = arinsal_term::global_atoms().intern(&tables.local_name) {
        arinsal_term::set_this_node(atom, tables.local_creation);
    }
    true
}

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
        pending_spawn_requests: BTreeMap::new(),
    }
}

impl NodeTables {
    pub(crate) fn set_distribution_buffer_busy_limit(&mut self, limit: u64) {
        if !self.alive {
            self.distribution_buffer_busy_limit = limit.max(1);
        }
    }

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
                pending_spawn_requests: BTreeMap::new(),
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
                pending_spawn_requests: BTreeMap::new(),
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

    /// Register an emulator-level node monitor and return its previous reference count.
    /// Port of erts/emulator/beam/dist.c:6732-6848 (`erts_monitor_nodes`), OTP-29.1.1.
    pub(crate) fn monitor_nodes(
        &mut self,
        pid: Pid,
        options: NodeMonitorOptions,
        enabled: bool,
    ) -> usize {
        if let Some(monitor) = self
            .nodes_monitors
            .iter_mut()
            .find(|monitor| monitor.pid == pid && monitor.options == options)
        {
            let previous = monitor.references;
            if enabled {
                monitor.references += 1;
            } else if monitor.references > 1 {
                monitor.references -= 1;
            } else {
                self.nodes_monitors
                    .retain(|monitor| monitor.pid != pid || monitor.options != options);
            }
            previous
        } else if enabled {
            self.nodes_monitors.push(NodesMonitor {
                pid,
                options,
                references: 1,
            });
            0
        } else {
            0
        }
    }

    /// Forget all node monitor registrations owned by a terminating process.
    pub(crate) fn forget_node_monitors(&mut self, pid: Pid) {
        self.monitors.retain(|monitor| monitor.pid != pid);
        self.nodes_monitors.retain(|monitor| monitor.pid != pid);
    }

    /// Build nodeup/nodedown notifications for subscriptions matching this connection.
    /// Port of erts/emulator/beam/dist.c:7040-7090 (`send_nodes_mon_msgs`), OTP-29.1.1.
    pub(crate) fn nodes_monitor_events(
        &self,
        what: &str,
        node: &str,
        connection_id: u32,
        visible: bool,
        reason: Option<&str>,
    ) -> Vec<NodesMonitorEvent> {
        let node_type = if visible { "visible" } else { "hidden" };
        let node_term = OwnedTerm::Atom(node.to_owned());
        self.nodes_monitors
            .iter()
            .filter(|monitor| {
                if visible {
                    !(monitor.options.visible || monitor.options.hidden) || monitor.options.visible
                } else {
                    monitor.options.hidden
                }
            })
            .map(|monitor| {
                let options = monitor.options;
                let event = if !options.info_map
                    && !options.list
                    && !options.connection_id
                    && !options.visible
                    && !options.hidden
                    && !options.nodedown_reason
                {
                    OwnedTerm::Tuple(vec![OwnedTerm::atom(what), node_term.clone()])
                } else {
                    let mut info = Vec::new();
                    if options.visible || options.hidden {
                        info.push((OwnedTerm::atom("node_type"), OwnedTerm::atom(node_type)));
                    }
                    if what == "nodedown" && options.nodedown_reason {
                        info.push((
                            OwnedTerm::atom("nodedown_reason"),
                            OwnedTerm::atom(reason.unwrap_or("connection_closed")),
                        ));
                    }
                    let info = if options.info_map {
                        if options.connection_id {
                            info.push((
                                OwnedTerm::atom("connection_id"),
                                if connection_id == u32::MAX {
                                    OwnedTerm::atom("undefined")
                                } else {
                                    OwnedTerm::Int(i64::from(connection_id))
                                },
                            ));
                        }
                        OwnedTerm::Map(info)
                    } else {
                        if options.connection_id {
                            info.push((
                                OwnedTerm::atom("connection_id"),
                                if connection_id == u32::MAX {
                                    OwnedTerm::atom("undefined")
                                } else {
                                    OwnedTerm::Int(i64::from(connection_id))
                                },
                            ));
                        }
                        OwnedTerm::List {
                            elems: info
                                .into_iter()
                                .rev()
                                .map(|(key, value)| OwnedTerm::Tuple(vec![key, value]))
                                .collect(),
                            tail: Box::new(OwnedTerm::Nil),
                        }
                    };
                    OwnedTerm::Tuple(vec![OwnedTerm::atom(what), node_term.clone(), info])
                };
                NodesMonitorEvent {
                    pid: monitor.pid,
                    message: event,
                }
            })
            .collect()
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
        let pid = arinsal_sched::Pid::new(1, 0);
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
