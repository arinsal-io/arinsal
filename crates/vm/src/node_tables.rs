//! Runtime-wide node names, distribution entries, and node monitors.

use arinsal_etf::{AtomCache, DistributionPacket, OwnedTerm};
use arinsal_sched::Pid;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicI64, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
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
    /// Distributed spawn requests retained while auto-connect is pending.
    pub(crate) pending_spawn_requests: BTreeMap<u64, SpawnRequest>,
    /// `dep->mld`: the links and monitors of the current (pending or up) connection.
    pub(crate) mld: Option<std::sync::Arc<crate::monitor_link::MonLnkDist>>,
}

/// One element of the dist table: a (potential) connection to a node, keyed by name.
///
/// Port of erts/emulator/beam/erl_node_tables.h (`struct dist_entry_`), OTP-29.1.1. The
/// `Arc` strong count is `dep->refc`: the table, the controlling port
/// (`ERTS_PRTSD_DIST_ENTRY`) and in-flight senders each hold a reference, and the table only
/// erases an entry nobody else references (`try_delete_dist_entry`). `rwmtx` protects the
/// connection state; the table lock protects membership only. Lock order: table, then entry;
/// code holding an entry lock never takes the table lock.
#[derive(Debug)]
pub(crate) struct DistEntry {
    /// `dep->sysname`.
    pub(crate) sysname: String,
    /// `dep->rwmtx`: state, connection id, `mld`, the controller's queues and caches.
    rwmtx: parking_lot::Mutex<NodeEntry>,
}

impl DistEntry {
    fn new(entry: NodeEntry) -> Arc<Self> {
        Arc::new(Self {
            sysname: entry.name.clone(),
            rwmtx: parking_lot::Mutex::new(entry),
        })
    }

    /// `erts_de_rwlock(dep)`.
    pub(crate) fn lock(&self) -> parking_lot::MutexGuard<'_, NodeEntry> {
        self.rwmtx.lock()
    }
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
    /// Serializes port writes so concurrent schedulers cannot reorder atom-cache headers.
    pub(crate) flushing_output: bool,
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
    pub(crate) spawn_requests: BTreeMap<u64, SpawnRequest>,
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
    /// `{reply, success_only}` / `{reply, no}` — suppress error mailbox message
    /// (ERTS_ML_FLG_SPAWN_NO_EMSG).
    pub(crate) no_error_msg: bool,
    /// `ERTS_ML_FLG_SPAWN_ABANDONED`: `spawn_request_abandon/1` was called on a request with
    /// link; the reply sends the child an `abandoned` exit (bif.c:1166).
    pub(crate) abandoned: bool,
    /// `ERTS_ML_FLG_SPAWN_LINK` of the pending-spawn origin monitor.
    pub(crate) link: bool,
    /// The parent is exiting: erts moved the target half of the monitor to
    /// `dist->dist_pend_spawn_exit` (dist.c:665 erts_dist_pend_spawn_exit_parent_setup).
    pub(crate) parent_exiting: bool,
    /// `mdp->origin.other.item` once a reply was saved for the exiting parent: the child pid,
    /// or the error atom of a failed spawn. `None` is `am_pending`.
    pub(crate) child: Option<OwnedTerm>,
    /// `mdp->u.target.other.ptr`: the parent suspended until the reply arrives
    /// (dist.c:758-790 erts_dist_pend_spawn_exit_parent_wait). Dropping it resumes the
    /// parent, also when the connection goes down (dist.c:326
    /// dist_pend_spawn_exit_connection_down).
    pub(crate) waiter: Option<arinsal_sched::ExitWaiter<crate::Process>>,
}

impl DistState {
    pub(crate) fn new(handle: u64, owner: Pid, flags: u64) -> Self {
        Self {
            handle,
            port_id: None,
            owner,
            input_handler: owner,
            output: VecDeque::new(),
            flushing_output: false,
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
            arinsal_etf::encode_dist_packet_terms_fragmented_indexed(
                &terms,
                &mut self.outgoing_cache,
                sequence_id,
                64 * 1024,
                |name| arinsal_term::global_atoms().get(name).map(|atom| atom.0),
            )?
        } else {
            vec![arinsal_etf::encode_dist_packet_terms_indexed(
                &terms,
                &mut self.outgoing_cache,
                None,
                |name| arinsal_term::global_atoms().get(name).map(|atom| atom.0),
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
        // The queue size grows when the fragments enter `output` (dist.c PHASE_SEND,
        // update_qsizes), not when they are encoded.
        self.encode_packets(&control, message.as_ref())
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
        // Port of erts/emulator/beam/external.c:3970-3992 (`enc_term`, FUN_DEF), OTP-29.1.1.
        // The creator pid and environment are encoded as ordinary terms.
        OwnedTerm::Fun { pid, free_vars, .. } => {
            let creator = std::mem::replace(pid.as_mut(), OwnedTerm::Nil);
            **pid = relabel_local_node(creator, local, creation);
            for value in free_vars.iter_mut() {
                let taken = std::mem::replace(value, OwnedTerm::Nil);
                *value = relabel_local_node(taken, local, creation);
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
    /// `erts_dist_table`: name to entry; this table lock covers membership only.
    pub(crate) entries: BTreeMap<String, Arc<DistEntry>>,
    pub(crate) monitors: Vec<NodeMonitor>,
    pending_delete: HashMap<String, Instant>,
    pub(crate) nodes_monitors: Vec<NodesMonitor>,
}

pub(crate) struct NodeTablesGuard(MutexGuard<'static, NodeTables>);

impl Deref for NodeTablesGuard {
    type Target = NodeTables;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for NodeTablesGuard {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // Port of erl_node_tables.c (erts_schedule_delete_node/try_delete_node):
        // delayed removals are serviced by the writer path, not by node lookups.
        self.0.prune_deleted();
        &mut self.0
    }
}

impl Default for NodeTables {
    fn default() -> Self {
        let mut entries = BTreeMap::new();
        entries.insert(
            "nonode@nohost".into(),
            DistEntry::new(NodeEntry {
                name: "nonode@nohost".into(),
                creation: 0,
                connection_id: 0,
                entry_ref: 0,
                state: ConnState::Idle,
                visible: true,
                connected: false,
                dist: None,
                pending_out: VecDeque::new(),
                pending_spawn_requests: BTreeMap::new(),
                mld: None,
            }),
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
            // Port of erl_node_tables.c (try_delete_dist_entry), OTP-29.1.1: an entry is
            // only erased once the table holds the last reference (`refc` reached zero).
            if node != self.local_name
                && self
                    .entries
                    .get(&node)
                    .is_some_and(|dep| Arc::strong_count(dep) == 1 && !dep.lock().connected)
                && !self.monitors.iter().any(|monitor| monitor.node == node)
            {
                self.entries.remove(&node);
            }
        }
    }
}

static TABLES: OnceLock<Mutex<NodeTables>> = OnceLock::new();
static NEXT_ENTRY_REF: AtomicU64 = AtomicU64::new(1);
/// `node_tab_delete_delay` in milliseconds, negative for "never".
// Port of erts/emulator/beam/erl_node_tables.c (node_tab_delete_delay), OTP-29.1.1; the initial
// value is `ERTS_NODE_TAB_DELAY_GC_DEFAULT` (60 s) until `init_node_tab_delete_delay` runs.
static NODE_TAB_DELETE_DELAY_MS: AtomicI64 = AtomicI64::new(60 * 1000);
/// `ERTS_NODE_TAB_DELAY_GC_INFINITY` (erl_node_tables.h): `ERTS_NODE_TAB_DELAY_GC_MAX + 1`.
pub(crate) const NODE_TAB_DELAY_GC_INFINITY: u64 = 100 * 1000 * 1000 + 1;
static NEXT_CONN_SEED: AtomicU32 = AtomicU32::new(1);

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

pub(crate) fn lock() -> NodeTablesGuard {
    NodeTablesGuard(
        TABLES
            .get_or_init(|| Mutex::new(NodeTables::default()))
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
    )
}

/// `erts_this_node`: the local node name and creation, read without the table lock.
///
/// Port of erts/emulator/beam/erl_node_tables.c (erts_this_node), OTP-29.1.1: published by
/// [`set_this_node`] and only changed by `setnode/2`.
pub(crate) fn this_node() -> (&'static str, u32) {
    let (atom, creation) = arinsal_term::this_node();
    (
        arinsal_term::global_atoms()
            .text(atom)
            .unwrap_or("nonode@nohost"),
        creation,
    )
}

/// `erts_is_alive`.
pub(crate) fn is_alive() -> bool {
    arinsal_term::this_node().0 != arinsal_term::atoms::NONAME
}

/// `find_dist_entry`: a reference to the entry for `sysname`, holding the table lock only for
/// the lookup.
// Port of erts/emulator/beam/erl_node_tables.c (erts_find_dist_entry), OTP-29.1.1.
pub(crate) fn find_dist_entry(sysname: &str) -> Option<Arc<DistEntry>> {
    lock().entries.get(sysname).cloned()
}

/// `erts_prtsd_get(prt, ERTS_PRTSD_DIST_ENTRY)` of `port_id`; callers check
/// `dep->cid == prt->common.id` under the entry lock.
// Port of erts/emulator/beam/dist.c:3999 (erts_dist_command), OTP-29.1.1.
pub(crate) fn port_dist_entry(
    runtime: &crate::process::Runtime,
    port_id: u64,
) -> Option<Arc<DistEntry>> {
    runtime.ports.get(port_id)?.dist_entry()
}

/// `dep->cid == port`: `port_id` is the controller of the entry's current connection.
pub(crate) fn dep_controls_port(dep: &DistEntry, port_id: u64) -> bool {
    dep.lock()
        .dist
        .as_ref()
        .is_some_and(|state| state.port_id == Some(port_id))
}

/// True when the port handle controls a live distribution connection.
pub(crate) fn is_dist_port(handle: &crate::port::PortHandle) -> bool {
    handle
        .dist_entry()
        .is_some_and(|dep| dep_controls_port(&dep, handle.id()))
}

const CON_ID_MASK: u32 = 0x00ff_ffff;

/// Port of erts/emulator/beam/erl_node_tables.c (erts_set_dist_entry_pending: the new
/// connection's `ErtsMonLnkDist`), OTP-29.1.1.
pub(crate) fn new_mld(
    node: &str,
    connection_id: u32,
) -> std::sync::Arc<crate::monitor_link::MonLnkDist> {
    let sysname = arinsal_term::global_atoms()
        .intern(node)
        .map_or(0, |atom| atom.0);
    std::sync::Arc::new(crate::monitor_link::MonLnkDist::with_connection(
        sysname,
        connection_id,
    ))
}

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
        pending_spawn_requests: BTreeMap::new(),
        mld: None,
    }
}

impl NodeTables {
    pub(crate) fn set_distribution_buffer_busy_limit(&mut self, limit: u64) {
        if !self.alive {
            self.distribution_buffer_busy_limit = limit.max(1);
        }
    }

    pub(crate) fn local_identity(&self) -> (&str, u32) {
        let dep = self
            .entries
            .get(&self.local_name)
            .expect("the local distribution entry is always present");
        debug_assert_eq!(dep.lock().creation, self.local_creation);
        (&dep.sysname, self.local_creation)
    }

    /// The entry whose current connection has distribution handle `handle` (the
    /// `DistEntry` pointer of an erts dhandle).
    pub(crate) fn dep_by_handle(&self, handle: u64) -> Option<Arc<DistEntry>> {
        self.entries
            .values()
            .find(|dep| {
                dep.lock()
                    .dist
                    .as_ref()
                    .is_some_and(|state| state.handle == handle)
            })
            .cloned()
    }

    /// The entry a distribution handle `{ConnId, Ref}` names, while that connection is up
    /// (erts `erts_dhandle_to_dist_entry` plus its connection id check).
    pub(crate) fn dep_by_dhandle(&self, conn_id: u32, entry_ref: u64) -> Option<Arc<DistEntry>> {
        self.entries
            .values()
            .find(|dep| {
                let entry = dep.lock();
                entry.entry_ref == entry_ref
                    && entry.connection_id == conn_id
                    && entry.dist.is_some()
            })
            .cloned()
    }

    /// `erts_find_or_insert_dist_entry`.
    // Port of erts/emulator/beam/erl_node_tables.c (erts_find_or_insert_dist_entry), OTP-29.1.1.
    pub(crate) fn find_or_insert(&mut self, sysname: &str) -> Arc<DistEntry> {
        self.entries
            .entry(sysname.to_string())
            .or_insert_with(|| DistEntry::new(fresh_entry(sysname.to_string())))
            .clone()
    }

    /// Return whether a pid's distribution entry advertises Unicode I/O.
    ///
    /// Port of erts/emulator/beam/dist.c:6670 (net_kernel_dflag_unicode_io_1), OTP-29.1.1.
    pub(crate) fn pid_unicode_io(&self, node: &str) -> bool {
        if node == self.local_name {
            return true;
        }
        self.entries.get(node).is_some_and(|dep| {
            dep.lock()
                .dist
                .as_ref()
                .is_some_and(|dist| dist.flags & DFLAG_UNICODE_IO != 0)
        })
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
            DistEntry::new(NodeEntry {
                name,
                creation,
                connection_id: 0,
                entry_ref: NEXT_ENTRY_REF.fetch_add(1, Ordering::Relaxed),
                state: ConnState::Idle,
                visible: true,
                connected: false,
                dist: None,
                pending_out: VecDeque::new(),
                pending_spawn_requests: BTreeMap::new(),
                mld: None,
            }),
        );
        true
    }

    /// Port of erts/emulator/beam/dist.c:5588 (erts_internal_new_connection_1), OTP-29.1.1.
    ///
    /// Returns `(connection_id, entry_ref)` for the distribution handle.
    pub(crate) fn new_connection(&mut self, node: &str) -> Option<(u32, u64)> {
        if node == self.local_name {
            return None;
        }
        self.pending_delete.remove(node);
        let dep = self.find_or_insert(node);
        let mut entry = dep.lock();
        match entry.state {
            ConnState::Connected | ConnState::Exiting | ConnState::Pending => {}
            ConnState::Idle => {
                // Port of erl_node_tables.c:689 (erts_set_dist_entry_pending), OTP-29.1.1.
                entry.connection_id = (entry.connection_id + 1) & CON_ID_MASK;
                entry.state = ConnState::Pending;
                entry.connected = false;
                entry.dist = None;
                entry.mld = Some(new_mld(&entry.name, entry.connection_id));
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
        let mut entry = self.entries.get(node)?.lock();
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
            entry.mld = None;
            entry.pending_out.clear();
            // The aborted connection takes its pending-spawn monitors along; dropping a
            // suspended parent's waiter resumes it (dist.c:326
            // dist_pend_spawn_exit_connection_down).
            entry.pending_spawn_requests.clear();
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
        let mld = Some(new_mld(&name, connection_id));
        let dep = self.find_or_insert(&name);
        let mut entry = dep.lock();
        // Port of erl_node_tables.c (erts_set_dist_entry_connected), OTP-29.1.1: the entry is
        // updated in place; references to it stay valid.
        entry.creation = creation;
        entry.connection_id = connection_id;
        entry.state = ConnState::Connected;
        entry.visible = visible;
        entry.connected = true;
        entry.dist = None;
        entry.pending_out.clear();
        entry.pending_spawn_requests.clear();
        entry.mld = mld;
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
        if self
            .entries
            .get(&node)
            .is_some_and(|dep| dep.lock().connected)
        {
            return false;
        }
        self.find_or_insert(&node);
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
    /// Take `dep->mld` before the connection state goes (dist.c erts_do_net_exits).
    pub(crate) fn take_mld(
        &mut self,
        node: &str,
    ) -> Option<std::sync::Arc<crate::monitor_link::MonLnkDist>> {
        self.entries.get(node)?.lock().mld.take()
    }

    pub(crate) fn disconnect(&mut self, node: &str) -> Vec<NodeMonitor> {
        // Port of erl_node_tables.c (erts_set_dist_entry_not_connected), OTP-29.1.1. The
        // controlling port keeps its `ERTS_PRTSD_DIST_ENTRY` reference until it terminates;
        // `dep->cid` is reset here, so the port no longer counts as this entry's controller.
        if let Some(dep) = self.entries.get(node) {
            let mut entry = dep.lock();
            entry.connected = false;
            entry.state = ConnState::Idle;
            entry.mld = None;
            entry.dist = None;
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

/// Apply `+zdntgc` at boot.
// Port of erts/emulator/beam/erl_node_tables.c (erts_init_node_tables), OTP-29.1.1.
pub(crate) fn init_node_tab_delete_delay(flag: Option<arinsal_args::DelayedNodeTableGc>) {
    use arinsal_args::DelayedNodeTableGc;
    let milliseconds = match flag {
        None => 60 * 1000,
        Some(DelayedNodeTableGc::Infinity) => -1,
        Some(DelayedNodeTableGc::Seconds(secs)) => i64::from(secs) * 1000,
    };
    NODE_TAB_DELETE_DELAY_MS.store(milliseconds, Ordering::Release);
}

/// The delay in seconds that `system_info(delayed_node_table_gc)` reports, rounded up;
/// `NODE_TAB_DELAY_GC_INFINITY` for "never".
// Port of erts/emulator/beam/erl_node_tables.c (erts_delayed_node_table_gc), OTP-29.1.1.
pub(crate) fn delayed_node_table_gc() -> u64 {
    match NODE_TAB_DELETE_DELAY_MS.load(Ordering::Acquire) {
        delay if delay < 0 => NODE_TAB_DELAY_GC_INFINITY,
        0 => 0,
        delay => ((delay - 1) / 1000 + 1) as u64,
    }
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
    use similar_asserts::assert_eq;

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
        let entry = tables.entries["peer@localhost"].lock();
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
        {
            let entry = tables.entries["b@host"].lock();
            assert_eq!(entry.state, ConnState::Pending);
            assert_eq!(entry.connection_id, id1);
            assert_eq!(entry.entry_ref, ref1);
        }
        let (id2, ref2) = tables.new_connection("b@host").unwrap();
        assert_eq!(id1, id2);
        assert_eq!(ref1, ref2);
    }

    #[test]
    fn new_connection_accepts_unqualified_node_atoms() {
        let mut tables = NodeTables::default();
        assert!(tables.set_local_node("a@host".into(), 4));
        let (id, entry_ref) = tables.new_connection("gurka").unwrap();
        let entry = tables.entries["gurka"].lock();
        assert_eq!(entry.state, ConnState::Pending);
        assert_eq!(entry.connection_id, id);
        assert_eq!(entry.entry_ref, entry_ref);
    }

    #[test]
    fn abort_pending_clears_pending_and_rejects_local() {
        let mut tables = NodeTables::default();
        assert!(tables.set_local_node("a@host".into(), 4));
        let (id, eref) = tables.new_connection("b@host").unwrap();
        assert_eq!(tables.abort_pending("b@host", id, eref), Some(true));
        assert_eq!(tables.entries["b@host"].lock().state, ConnState::Idle);
        assert!(tables.abort_pending("a@host", id, eref).is_none());
    }
}
