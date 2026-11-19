//! Local OS ports backed by child processes.
use crate::process::Message;
use crate::{Process, Vm, VmError};
use arinsal_etf::OwnedTerm;
use arinsal_sched::{HaltProgress, Pid, RunCtx, Scheduler};
use arinsal_term::{
    HeapAlloc, ProcessHeap, Term, TermBuilder, TermKind, VecHeap, copy_term, from_owned,
    global_atoms, to_owned,
};
use parking_lot::Mutex;
use std::ffi::{OsStr, OsString};
use std::os::fd::{FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, Weak};

mod drv_sig;
mod raw;

// Port of erts/emulator/beam/erl_bif_port.c:824 (open_port defaults), OTP-29.1.1.
const DEFAULT_HIGH: usize = 8192;
const DEFAULT_LOW: usize = 4096;
const CHILD_FLAG_USE_STDIO: i32 = 1 << 0;
const CHILD_FLAG_EXIT_STATUS: i32 = 1 << 1;
const CHILD_FLAG_DO_READ: i32 = 1 << 2;
const CHILD_FLAG_DO_WRITE: i32 = 1 << 3;

// Port of erts/emulator/sys/unix/sys_drivers.c (`spawn_start`) and
// erts/emulator/sys/unix/erl_child_setup.c (`start_new_child`), OTP-29.1.1.
#[allow(clippy::too_many_arguments)]
fn child_setup_payload(
    executable: bool,
    name: &str,
    program: &OsStr,
    args: &[OsString],
    arg0: Option<&OsStr>,
    cwd: Option<&OsStr>,
    env: &crate::erl_osenv::ErlOsEnv,
    use_stdio: bool,
    read_write: u8,
    exit_status: bool,
) -> std::io::Result<Vec<u8>> {
    fn push_cstring(payload: &mut Vec<u8>, value: &[u8]) -> std::io::Result<()> {
        if value.contains(&0) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "NUL in child setup string",
            ));
        }
        payload.extend_from_slice(value);
        payload.push(0);
        Ok(())
    }

    fn push_i32(payload: &mut Vec<u8>, value: usize) -> std::io::Result<()> {
        let value = i32::try_from(value).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "child setup field too large",
            )
        })?;
        payload.extend_from_slice(&value.to_be_bytes());
        Ok(())
    }

    let mut flags = 0;
    if use_stdio {
        flags |= CHILD_FLAG_USE_STDIO;
    }
    if exit_status {
        flags |= CHILD_FLAG_EXIT_STATUS;
    }
    if read_write & 1 != 0 {
        flags |= CHILD_FLAG_DO_READ;
    }
    if read_write & 2 != 0 {
        flags |= CHILD_FLAG_DO_WRITE;
    }
    let mut payload = Vec::new();
    payload.extend_from_slice(&flags.to_be_bytes());
    if executable {
        push_cstring(&mut payload, program.as_bytes())?;
    } else {
        let mut command = b"exec ".to_vec();
        command.extend_from_slice(name.as_bytes());
        push_cstring(&mut payload, &command)?;
    }
    let current_directory = std::env::current_dir()?;
    push_cstring(&mut payload, current_directory.as_os_str().as_bytes())?;
    if let Some(wd) = cwd {
        push_cstring(&mut payload, wd.as_bytes())?;
        payload.push(0);
    } else {
        payload.push(0);
    }
    push_i32(&mut payload, env.len())?;
    payload.reserve(env.spawn_block_size());
    for (key, value) in env.iter() {
        payload.extend_from_slice(key);
        payload.push(b'=');
        payload.extend_from_slice(value);
        payload.push(0);
    }
    if executable {
        push_i32(&mut payload, args.len() + 1)?;
        push_cstring(&mut payload, arg0.unwrap_or(program).as_bytes())?;
        for arg in args {
            push_cstring(&mut payload, arg.as_bytes())?;
        }
    }
    let size = u32::try_from(payload.len()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "child setup payload too large",
        )
    })?;
    let mut request = Vec::with_capacity(payload.len() + 4);
    request.extend_from_slice(&size.to_ne_bytes());
    request.extend_from_slice(&payload);
    Ok(request)
}

/// `Port ! Message` from a running process: `erts_port_command` of `do_send`'s `port_common`.
/// `suspend` off is `ERTS_PORT_SIG_FLG_NOSUSPEND`. The result is the `ERTS_PORT_OP_*` code
/// `do_send` maps to its send result; a busy port with `suspend` on has already suspended the
/// sender (`erts_suspend` on the port's busy waiter list).
// Port of erts/emulator/beam/bif.c (do_send: port_common) and io.c (erts_port_command,
// erts_port_output), OTP-29.1.1.
pub(crate) fn process_send(
    process: &mut Process,
    ctx: Option<&mut RunCtx<'_, crate::Process>>,
    port: Term,
    message: Term,
    suspend: bool,
) -> Result<PortSend, VmError> {
    send_from_process(process, port, message, !suspend, ctx)
}

/// Output-queue and message-queue busy limits from `open_port` options.
#[derive(Clone, Copy)]
struct BusyLimits {
    port_low: usize,
    port_high: usize,
    port_enabled: bool,
    msgq_low: usize,
    msgq_high: usize,
    msgq_enabled: bool,
}

struct PortState {
    bytes_in: u64,
    bytes_out: u64,
    busy_port: bool,
    busy_msgq: bool,
    exit_complete: bool,
    suspended: Suspended,
    closed: bool,
    broken: bool,
}

/// Processes suspended on a busy port: none until the port is busy.
// Boxed on purpose: the pointer is 8 bytes where an empty `Vec` is 24.
#[allow(clippy::box_collection)]
#[derive(Default)]
struct Suspended(Option<Box<Vec<Pid>>>);

impl Suspended {
    fn push(&mut self, pid: Pid) {
        self.0.get_or_insert_with(Default::default).push(pid);
    }

    fn take(&mut self) -> Vec<Pid> {
        self.0.take().map(|pids| *pids).unwrap_or_default()
    }
}

// An `Arc<PortHandle>` (16 bytes of counts plus the handle) should stay within the 640-byte size
// class of the system allocator; the next class up is 768 bytes for every port.
const _: () = assert!(std::mem::size_of::<PortHandle>() <= 624);

/// The connected process of a port (`prt->connected`), one word.
struct OwnerCell(AtomicU64);

impl OwnerCell {
    fn new(pid: Pid) -> Self {
        Self(AtomicU64::new(pid.data()))
    }

    fn get(&self) -> Pid {
        Pid::from_data(self.0.load(Ordering::Acquire))
    }

    fn set(&self, pid: Pid) {
        self.0.store(pid.data(), Ordering::Release);
    }
}

/// The rarely used parts of a [`PortHandle`].
#[derive(Default)]
struct HandleCold {
    /// The `open_port` waiting for `erl_drv_init_ack`: reference id and opener.
    async_open: Option<(u64, Pid)>,
    /// `port->common.u.alive.reg->name`, shared with the register table entry.
    reg_word: Option<Arc<AtomicU32>>,
    halt_progress: Option<HaltProgress>,
    /// `erts_prtsd_get(prt, ERTS_PRTSD_DIST_ENTRY)`: the distribution entry this port controls,
    /// set by `setnode/3` and cleared when the port terminates (dist.c:5299, io.c:3917). erts
    /// keeps it in the separately allocated port-specific data, so it lives in the cold part.
    dist_entry: Option<Arc<crate::node_tables::DistEntry>>,
}

/// State retained for a live child or fd port.
pub(crate) struct PortHandle {
    id: u64,
    /// `prt->common.id`: the tagged port identifier, compared by lookups.
    word: u64,
    started_interval: AtomicU64,
    owner: OwnerCell,
    /// `ERTS_P_LINKS`: an intrusive link tree, including the pending-unlink id on each node.
    links: Mutex<crate::monitor_link::MonLnkTree<crate::monitor_link::Link>>,
    /// `ERTS_P_MONITORS`: driver monitor origin halves; user port monitors are in `lt_monitors`.
    monitors: Mutex<crate::proc_create::MonitorTree>,
    /// `ERTS_P_LT_MONITORS`: process-origin monitor target halves, in insertion order.
    lt_monitors: Mutex<crate::proc_create::TargetMonitorList>,
    name: Box<str>,
    parallelism: bool,
    state: Mutex<PortState>,
    scheduler: Arc<Scheduler<Process>>,
    /// The runtime the port belongs to (`ERTS_...` trace scope is its address).
    runtime: &'static crate::process::Runtime,
    /// `port_set_data/2` term. `undefined` until the first store.
    data: raw::PortDataCell,
    /// `tcp_inet` / `tcp_inet6` port. I/O is owned by `inet_drv`, not a stdio worker.
    /// Dynamically loaded (`erl_ddll`) driver port.
    driver: Option<arinsal_drv::DriverPort>,
    /// State most ports never need, allocated on first use (erts keeps these as null pointers
    /// in the port or its common part).
    cold: Mutex<Option<Box<HandleCold>>>,
    /// Set when the port is removed, before its name is erased.
    reg_closing: AtomicBool,
    /// The driver's own state (`prt->drv_data`): the tcp or udp socket, or the ram_file data
    /// from `rfile_start` until `rfile_stop`.
    drv_data: Mutex<Option<Arc<crate::ram_file_drv::RamPort>>>,
}

/// Inspect or move the next local port id for `erts_debug` table tests.
/// Port of erts/emulator/beam/erl_ptab.c:1356-1460 (`erts_ptab_test_next_id`), OTP-29.1.1.
pub(crate) fn test_next_port_id(
    runtime: &crate::process::Runtime,
    set: bool,
    next_id: u64,
) -> Option<u64> {
    let _ports = runtime.ports.lock();
    Some(
        runtime
            .port_ids
            .test_next_id(set, next_id, |pix| runtime.ports.occupied(pix)),
    )
}

type PortSlot = arinsal_sched::ProgressSlot<PortHandle>;

/// The port table (`erts_port` ptab): an array indexed by the port id's table index bits
/// (`erts_ptab_data2pix`), so a lookup is a shift, a mask and a slot load without hashing.
/// Pages of slots are materialized on first use. `list` is `ptab->list.data.rwmtx`: it orders
/// table-wide scans, `test_next_id`, and insert/remove against each other, as in erts.
///
/// Port of erts/emulator/beam/erl_ptab.c (erts_ptab_pix2intptr_ddrb, erts_ptab_new_element,
/// erts_ptab_delete_element), OTP-29.1.1.
pub(crate) struct PortTable {
    list: std::sync::RwLock<()>,
    /// Number of published ports (`ptab->r.o.nobjs`).
    count: std::sync::atomic::AtomicUsize,
    /// One slot per table index, allocated once (`erts_ptab_init_table`).
    slots: Box<[PortSlot]>,
    /// `ptab->r.o.pix_mask`.
    pix_mask: usize,
    /// The thread progress domain that frees removed elements, attached when the scheduler
    /// exists (`erts_schedule_thr_prgr_later_cleanup_op` in `erts_ptab_delete_element`).
    progress: OnceLock<arinsal_sched::Progress>,
    interval: std::sync::atomic::AtomicU64,
    list_deleted: Mutex<arinsal_sched::PtabListLog<u64>>,
}

impl Default for PortTable {
    fn default() -> Self {
        Self::new(arinsal_term::ptab::port_table_layout())
    }
}

impl PortTable {
    /// Bytes of the table's slot array and free identifier ring.
    // Port of erts/emulator/beam/erl_ptab.c:349 (erts_ptab_mem_size), OTP-29.1.1, for this
    // table's eagerly allocated slots and separately stored free-ID ring.
    pub(crate) fn memory_bytes(&self, ids: &arinsal_term::ptab::PtabIdRing) -> u64 {
        (self.slots.len() * std::mem::size_of::<PortSlot>() + ids.free_id_bytes()) as u64
    }

    pub(crate) fn new(layout: arinsal_term::ptab::PtabLayout) -> Self {
        let slots = (0..layout.max() as usize)
            .map(|_| arinsal_sched::ProgressSlot::new())
            .collect();
        Self {
            list: std::sync::RwLock::new(()),
            count: std::sync::atomic::AtomicUsize::new(0),
            slots,
            pix_mask: layout.max() as usize - 1,
            progress: OnceLock::new(),
            interval: std::sync::atomic::AtomicU64::new(0),
            list_deleted: Mutex::new(arinsal_sched::PtabListLog::default()),
        }
    }

    /// Exclusive access for inserting and removing ports and for table-wide exclusion.
    pub(crate) fn lock(&self) -> std::sync::LockResult<std::sync::RwLockWriteGuard<'_, ()>> {
        self.list.write()
    }

    /// Shared access that excludes `lock()` holders: a port cannot be inserted or removed
    /// while it is held.
    pub(crate) fn read(&self) -> std::sync::LockResult<std::sync::RwLockReadGuard<'_, ()>> {
        self.list.read()
    }

    fn slot(&self, id: u64) -> Option<&PortSlot> {
        let pix = arinsal_term::ptab::port_table_layout().data2pix(id) as usize;
        self.slot_at(pix)
    }

    fn slot_at(&self, pix: usize) -> Option<&PortSlot> {
        self.slots.get(pix)
    }

    /// `erts_port_lookup_raw`'s slot: `internal_port_index(id)` is the mask of the identifier's
    /// payload (`erts_ptab_id2pix`).
    fn slot_of_word(&self, word: u64) -> Option<&PortSlot> {
        self.slot_at((word >> 4) as usize & self.pix_mask)
    }

    /// Run `f` on the live port with the tagged identifier `word`, a managed caller or not
    /// (`erts_port_lookup_raw`: load the slot, compare `common.id`).
    pub(crate) fn with_word<R>(
        &self,
        word: u64,
        managed: bool,
        f: impl FnOnce(&PortHandle) -> R,
    ) -> Option<R> {
        let slot = self.slot_of_word(word)?;
        let found = |handle: &PortHandle| (handle.word == word).then(|| f(handle));
        if managed {
            slot.with_managed(found)
        } else {
            slot.with(self.progress.get()?, false, found)
        }
        .flatten()
    }

    /// A counted reference to the live port with the tagged identifier `word`.
    pub(crate) fn get_word(&self, word: u64, managed: bool) -> Option<Arc<PortHandle>> {
        self.slot_of_word(word)?
            .load_arc_if(self.progress.get()?, managed, |handle| handle.word == word)
    }

    /// Attach the scheduler's thread progress domain: removed ports are freed after it.
    pub(crate) fn attach(&self, progress: arinsal_sched::Progress) {
        let _ = self.progress.set(progress);
    }

    /// `erts_port_lookup_raw`: the handle of the live port `id`.
    pub(crate) fn get(&self, id: u64) -> Option<Arc<PortHandle>> {
        self.get_from(id, false)
    }

    /// [`PortTable::get`] for a caller that is a managed scheduler thread (`managed`): the
    /// lookup then delays nothing.
    pub(crate) fn get_from(&self, id: u64, managed: bool) -> Option<Arc<PortHandle>> {
        self.slot(id)?
            .load_arc_if(self.progress.get()?, managed, |handle| handle.id == id)
    }

    /// Run `f` on the live port `id` without taking a counted reference to it.
    pub(crate) fn with<R>(&self, id: u64, f: impl FnOnce(&PortHandle) -> R) -> Option<R> {
        self.with_from(id, false, f)
    }

    /// [`PortTable::with`] for a caller that is a managed scheduler thread (`managed`).
    pub(crate) fn with_from<R>(
        &self,
        id: u64,
        managed: bool,
        f: impl FnOnce(&PortHandle) -> R,
    ) -> Option<R> {
        self.slot(id)?
            .with(self.progress.get()?, managed, |handle| {
                (handle.id == id).then(|| f(handle))
            })
            .flatten()
    }

    /// Whether port `id` is live.
    pub(crate) fn contains(&self, id: u64) -> bool {
        self.with(id, |_| ()).is_some()
    }

    /// Whether any live port occupies table index `pix`.
    fn occupied(&self, pix: u32) -> bool {
        let pix = pix as usize;
        self.slot_at(pix).is_some_and(PortSlot::is_occupied)
    }

    /// Publish a new port in its slot (`erts_ptab_new_element`, under the table lock).
    pub(crate) fn insert(&self, id: u64, handle: Arc<PortHandle>) {
        let _list = self.list.write().unwrap();
        let started = self.interval.load(Ordering::Acquire);
        handle.started_interval.store(started, Ordering::Release);
        let pix = arinsal_term::ptab::port_table_layout().data2pix(id) as usize;
        self.slots[pix].store(handle, self.progress.get());
        self.count.fetch_add(1, Ordering::Relaxed);
    }

    // Port of erts/emulator/beam/erl_ptab.c:675 (erts_ptab_delete_element), OTP-29.1.1.
    /// Clear one port while the caller holds `list` write-locked across id release.
    fn remove_locked(&self, id: u64) -> Option<Arc<PortHandle>> {
        let slot = self.slot(id)?;
        let progress = self.progress.get()?;
        // The caller holds the table lock, so the slot cannot change between the check and the swap.
        if slot
            .with(progress, false, |handle| handle.id == id)
            .unwrap_or(false)
        {
            let removed = slot.take(progress)?;
            raw::retire_data(removed.data.swap(0), &removed.scheduler);
            self.count.fetch_sub(1, Ordering::Relaxed);
            let started_interval = removed.started_interval.load(Ordering::Acquire);
            let deleted_interval = self.interval.load(Ordering::Acquire);
            let index = arinsal_term::ptab::port_table_layout().data2pix(id);
            let entry = arinsal_sched::PtabListDeleted {
                index,
                id,
                started_interval,
                deleted_interval,
            };
            self.list_deleted.lock().record(entry);
            Some(removed)
        } else {
            None
        }
    }

    /// `erts_ptab_count(&erts_port)`: the live ports, the forker port (port 0) among them.
    pub(crate) fn live_count(&self) -> usize {
        self.count.load(Ordering::Relaxed)
    }

    /// Ids of the live ports in table order.
    pub(crate) fn ids(&self) -> Vec<u64> {
        self.handles().iter().map(|handle| handle.id).collect()
    }

    /// Live ports in table order (`erts_ptab_processes` scan order).
    pub(crate) fn handles(&self) -> Vec<Arc<PortHandle>> {
        let Some(progress) = self.progress.get() else {
            return Vec::new();
        };
        // erts_ptab_list reads every index and skips the empty ones after the one load.
        self.slots
            .iter()
            .filter(|slot| slot.is_occupied())
            .filter_map(|slot| slot.load_arc(progress, false))
            .collect()
    }

    // Port of erts/emulator/beam/erl_ptab.c (erts_ptab_list / ptab_list_bif_engine), OTP-29.1.1.
    pub(crate) fn begin_ptab_list_chunk(
        &'static self,
        limit: u32,
        track_deletions: bool,
        reserve_ids: impl FnOnce(usize),
        mut append_id: impl FnMut(u64),
    ) -> (PortPtabListSnapshot, u64, usize) {
        let _list = self.list.write().unwrap();
        let count = self.count.load(Ordering::Relaxed);
        let invocation_interval = if track_deletions {
            self.interval.fetch_add(1, Ordering::AcqRel).wrapping_add(1)
        } else {
            self.interval.load(Ordering::Acquire)
        };
        let marker = if track_deletions {
            Some(self.list_deleted.lock().begin(invocation_interval))
        } else {
            None
        };
        reserve_ids(count);
        for slot in self.slots.iter().take(limit as usize) {
            slot.with_managed(|handle| {
                if !track_deletions
                    || handle.started_interval.load(Ordering::Acquire) < invocation_interval
                {
                    append_id(handle.id);
                }
            });
        }
        (
            PortPtabListSnapshot {
                table: self,
                marker,
                invocation_interval,
                active: marker.is_some(),
            },
            invocation_interval,
            count,
        )
    }
}

/// State shared by one trapping `ports/0` table scan.
pub(crate) struct PortPtabListSnapshot {
    table: &'static PortTable,
    marker: Option<usize>,
    invocation_interval: u64,
    active: bool,
}

impl PortPtabListSnapshot {
    // Port of erts/emulator/beam/erl_ptab.c:888 (ptab_list_bif_engine), OTP-29.1.1.
    pub(crate) fn scan_chunk_with(
        &self,
        first: u32,
        limit: u32,
        mut append_id: impl FnMut(u64),
    ) -> u64 {
        let _list = self.table.list.write().unwrap();
        let chunk_interval = self
            .table
            .interval
            .fetch_add(1, Ordering::AcqRel)
            .wrapping_add(1);
        let layout = arinsal_term::ptab::port_table_layout();
        for index in first..limit.min(layout.max()) {
            let Some(slot) = self.table.slot_at(index as usize) else {
                continue;
            };
            // The table write lock excludes insert/remove until this scan chunk completes.
            slot.with_managed(|handle| {
                if handle.started_interval.load(Ordering::Acquire) < self.invocation_interval {
                    append_id(handle.id);
                }
            });
        }
        chunk_interval
    }

    pub(crate) fn inspect_deleted_with(
        &mut self,
        chunk_intervals: &[u64],
        max_reds: u32,
        append_id: impl FnMut(u64),
    ) -> (u32, bool) {
        let Some(marker) = self.marker else {
            self.active = false;
            return (0, true);
        };
        let _list = self.table.list.write().unwrap();
        let result = self.table.list_deleted.lock().inspect(
            marker,
            self.invocation_interval,
            chunk_intervals,
            max_reds,
            append_id,
        );
        self.active = !result.1;
        result
    }
}

impl Drop for PortPtabListSnapshot {
    fn drop(&mut self) {
        if self.active
            && let Some(marker) = self.marker
        {
            let _list = self.table.list.write().unwrap();
            self.table.list_deleted.lock().cancel(marker);
        }
    }
}

/// Port of erts/emulator/beam/erl_ptab.c:500, 675 (new/delete element), OTP-29.1.1.
/// A reserved local port id is returned to the ptab ring if construction fails.
struct PortIdReservation<'a> {
    runtime: &'a crate::process::Runtime,
    id: u64,
    committed: bool,
}

impl PortIdReservation<'_> {
    fn id(&self) -> u64 {
        self.id
    }

    fn commit(mut self) -> u64 {
        self.committed = true;
        self.id
    }
}

impl Drop for PortIdReservation<'_> {
    fn drop(&mut self) {
        if !self.committed {
            let _ports = self.runtime.ports.lock();
            self.runtime.port_ids.release(self.id);
        }
    }
}

fn reserve_port_id(runtime: &crate::process::Runtime) -> Result<PortIdReservation<'_>, VmError> {
    let _ports = runtime.ports.lock();
    // Port exhaustion is the `driver_create_port` failure mapped to `system_limit` in
    // erts/emulator/drivers/common/inet_drv.c:11834-11837, OTP-29.1.1.
    let id = runtime.port_ids.reserve().ok_or_else(|| {
        VmError::Trap(crate::exceptions::Trap::error(Term::atom(
            arinsal_term::atoms::SYSTEM_LIMIT,
        )))
    })?;
    Ok(PortIdReservation {
        runtime,
        id,
        committed: false,
    })
}

fn remove_port(runtime: &crate::process::Runtime, id: u64) -> Option<Arc<PortHandle>> {
    let ports = runtime.ports.lock();
    let handle = runtime.ports.remove_locked(id)?;
    runtime.port_ids.release(id);
    drop(ports);
    release_port_name(runtime, &handle);
    crate::trace::port_closed(runtime, id);
    Some(handle)
}

fn release_port_name(runtime: &crate::process::Runtime, handle: &PortHandle) {
    // Closing is published before the register lock so a concurrent register/2,
    // which checks it under that lock, cannot insert a name for a dead port.
    handle.mark_reg_closing();
    let mut table = runtime.reg.write();
    let Some(name) = handle.take_registered_atom() else {
        return;
    };
    if matches!(table.fetch(name), Some(crate::register::RegId::Port(id)) if id == handle.id()) {
        table.erase(name);
        drop(table);
        crate::trace::emit_port_event(
            runtime,
            handle.id(),
            crate::trace::PORTS,
            "unregister",
            &[Term::atom(name)],
        );
    }
}

impl PortHandle {
    /// The runtime this port belongs to.
    pub(crate) fn runtime(&self) -> Option<&'static crate::process::Runtime> {
        Some(self.runtime)
    }

    /// The trace scope of port messages: the address of the runtime.
    fn trace_scope(&self) -> usize {
        self.runtime as *const crate::process::Runtime as usize
    }

    /// The driver port of a port made by a driver (everything but ram_file and spawn ports).
    pub(crate) fn drv_port(&self) -> Option<arinsal_drv::PortRef> {
        self.driver.as_ref().map(arinsal_drv::DriverPort::arc)
    }

    /// The embedded driver state, when this port has one.
    pub(crate) fn drv_port_state(&self) -> Option<&arinsal_drv::DriverPort> {
        self.driver.as_ref()
    }

    pub(crate) fn owner_pid(&self) -> Pid {
        self.owner.get()
    }
    pub(crate) fn scheduler(&self) -> Arc<Scheduler<Process>> {
        Arc::clone(&self.scheduler)
    }
    pub(crate) fn port_name(&self) -> String {
        self.name.to_string()
    }

    fn add_bytes_in(&self, count: usize) {
        let mut state = self.state.lock();
        state.bytes_in = state.bytes_in.wrapping_add(count as u64);
    }

    fn add_bytes_out(&self, count: usize) {
        let mut state = self.state.lock();
        state.bytes_out = state.bytes_out.wrapping_add(count as u64);
    }

    /// The ram_file data (`prt->drv_data` of `ram_file_drv`).
    fn ram_file_data(&self) -> Option<Arc<crate::ram_file_drv::RamPort>> {
        self.drv_data.lock().clone()
    }

    fn set_ram_file_data(&self, data: Arc<crate::ram_file_drv::RamPort>) {
        *self.drv_data.lock() = Some(data);
    }

    fn take_ram_file_data(&self) -> Option<Arc<crate::ram_file_drv::RamPort>> {
        self.drv_data.lock().take()
    }

    /// The tcp socket of a `tcp_inet` port (`prt->drv_data`, the one copy kept with the driver
    /// state) until `tcp_inet_stop`.
    pub(crate) fn tcp_driver_data(&self) -> Option<Arc<crate::inet_drv::Sock>> {
        self.driver
            .as_ref()?
            .native_data::<crate::inet_drv::Sock>()
            .filter(|sock| !sock.stopped())
    }

    /// The distribution entry this port is the controller of, if any.
    pub(crate) fn dist_entry(&self) -> Option<Arc<crate::node_tables::DistEntry>> {
        self.peek_cold(|cold| cold.dist_entry.clone()).flatten()
    }

    /// Bind (or with `None`, unbind) the distribution entry this port controls.
    // Port of erts/emulator/beam/dist.c:5299 (setup_connection: erts_prtsd_set) and
    // io.c:3911-3917 (terminate_port), OTP-29.1.1.
    pub(crate) fn set_dist_entry(
        &self,
        dep: Option<Arc<crate::node_tables::DistEntry>>,
    ) -> Option<Arc<crate::node_tables::DistEntry>> {
        match dep {
            Some(dep) => self.with_cold(|cold| cold.dist_entry.replace(dep)),
            None => self.peek_cold(|cold| cold.dist_entry.take()).flatten(),
        }
    }

    pub(crate) fn id(&self) -> u64 {
        self.id
    }

    /// The word shared with the register table entry, allocated by the first registration
    /// (`port->common.u.alive.reg` is NULL until then).
    pub(crate) fn reg_word(&self) -> Arc<AtomicU32> {
        self.with_cold(|cold| {
            Arc::clone(
                cold.reg_word
                    .get_or_insert_with(|| Arc::new(AtomicU32::new(crate::register::NO_REG_ATOM))),
            )
        })
    }

    /// Runs `f` on the cold state, allocating it first.
    fn with_cold<R>(&self, f: impl FnOnce(&mut HandleCold) -> R) -> R {
        f(self.cold.lock().get_or_insert_with(Default::default))
    }

    /// Runs `f` on the cold state when it exists.
    fn peek_cold<R>(&self, f: impl FnOnce(&mut HandleCold) -> R) -> Option<R> {
        self.cold.lock().as_deref_mut().map(f)
    }

    pub(crate) fn reg_closing(&self) -> bool {
        self.reg_closing.load(Ordering::Acquire)
    }

    /// Port is gone: later `register/2` must fail even if it already cloned this handle.
    pub(crate) fn mark_reg_closing(&self) {
        self.reg_closing.store(true, Ordering::Release);
    }

    pub(crate) fn registered_atom(&self) -> Option<arinsal_term::Atom> {
        let index = self.peek_cold(|cold| {
            cold.reg_word
                .as_ref()
                .map(|word| word.load(Ordering::Acquire))
        })??;
        (index != crate::register::NO_REG_ATOM).then_some(arinsal_term::Atom(index))
    }

    pub(crate) fn set_registered_atom(&self, atom: arinsal_term::Atom) {
        self.reg_word().store(atom.0, Ordering::Release);
    }

    pub(crate) fn take_registered_atom(&self) -> Option<arinsal_term::Atom> {
        let index = self.peek_cold(|cold| {
            cold.reg_word
                .as_ref()
                .map(|word| word.swap(crate::register::NO_REG_ATOM, Ordering::AcqRel))
        })??;
        (index != crate::register::NO_REG_ATOM).then_some(arinsal_term::Atom(index))
    }

    pub(crate) fn exit_complete(&self) -> bool {
        self.state.lock().exit_complete
    }

    fn track_halt(&self, progress: HaltProgress) {
        progress.port_started();
        let mut cold = self.cold.lock();
        if self.state.lock().exit_complete {
            progress.port_finished();
        } else {
            cold.get_or_insert_with(Default::default).halt_progress = Some(progress);
        }
    }

    fn finish_halt(&self) {
        if let Some(progress) = self.peek_cold(|cold| cold.halt_progress.take()).flatten() {
            progress.port_finished();
        }
    }
}

fn atom_dyn(s: &str) -> Term {
    Term::atom(global_atoms().intern(s).expect("built-in atom"))
}
fn badarg() -> VmError {
    VmError::Trap(crate::exceptions::Trap::error(Term::atom(
        arinsal_term::atoms::BADARG,
    )))
}
fn list(t: Term) -> Option<Vec<Term>> {
    let mut out = Vec::new();
    let mut cur = t;
    while cur.classify() == TermKind::List {
        // SAFETY: The source term remains in the live caller heap for this BIF.
        let (h, tail) = unsafe { cur.cons_ref()? };
        out.push(h);
        cur = tail;
    }
    (cur == Term::NIL).then_some(out)
}
fn bytes(t: Term) -> Option<Vec<u8>> {
    if let Some(n) = t.as_small() {
        return (0..=255).contains(&n).then_some(vec![n as u8]);
    }
    let mut out = Vec::new();
    let mut pending = vec![t];
    while let Some(term) = pending.pop() {
        if let Some(n) = term.as_small() {
            if !(0..=255).contains(&n) {
                return None;
            }
            out.push(n as u8);
        } else if term.classify() == TermKind::List {
            // SAFETY: The list is traversed before the caller's process heap can move.
            let (head, tail) = unsafe { term.cons_ref()? };
            pending.push(tail);
            pending.push(head);
        } else if term == Term::NIL {
        } else {
            append_binary(term, &mut out)?;
        }
    }
    Some(out)
}
/// Append a binary's significant bytes: the window `[start_bit, start_bit + bit_len)`
/// of its owner, which is not the owner's whole backing data for a sub-binary.
/// A bitstring whose size is not a multiple of 8 is not iodata.
fn append_binary(term: Term, out: &mut Vec<u8>) -> Option<()> {
    let bits = arinsal_bifs::bitstring_bit_len(term).ok()?;
    if !bits.is_multiple_of(8) {
        return None;
    }
    let start = out.len();
    out.resize(start + bits / 8, 0);
    arinsal_bifs::copy_binary_range(term, 0, &mut out[start..]).ok()
}
fn string_bytes(t: Term) -> Option<Vec<u8>> {
    filename_bytes(t, true, true)
}
// Port of erts/emulator/beam/erl_unicode.c (erts_convert_filename_to_native), OTP-29.1.1.
fn filename_bytes(t: Term, allow_empty: bool, allow_atom: bool) -> Option<Vec<u8>> {
    if allow_atom && let Some(atom) = t.as_atom() {
        return Some(global_atoms().text(atom)?.as_bytes().to_vec());
    }
    if t.classify() == TermKind::Bitstring {
        let mut out = Vec::new();
        append_binary(t, &mut out)?;
        return Some(out);
    }
    let characters = list(t)?;
    if characters.is_empty() && !allow_empty {
        return None;
    }
    let mut out = String::new();
    for character in characters {
        let codepoint = u32::try_from(character.as_small()?).ok()?;
        out.push(char::from_u32(codepoint)?);
    }
    Some(out.into_bytes())
}
/// An off-heap, non-writable binary of more than `ERL_ONHEAP_BINARY_LIMIT` bytes as a kept
/// reference, instead of a copy of its bytes.
// Port of erts/emulator/beam/erl_iolist.c (erts_ioq_iolist_to_vec: `binv` holds the Binary of
// a refc binary and its `iov` entry points into it), OTP-29.1.1.
fn refc_segment(term: Term) -> Option<arinsal_drv::RefcSegment> {
    let bits = arinsal_bifs::bitstring_bit_len(term).ok()?;
    let len = bits / 8;
    if !bits.is_multiple_of(8) || len <= arinsal_drv::ERL_ONHEAP_BINARY_LIMIT {
        return None;
    }
    let (off_heap, base, start_bit) = arinsal_bifs::with_binary_bytes(term, |view| {
        (
            view.is_off_heap(),
            view.bytes().as_ptr() as usize,
            view.start_bit(),
        )
    })
    .ok()?;
    if !off_heap || !start_bit.is_multiple_of(8) {
        return None;
    }
    let arinsal_term::BinaryOwner::Binary(owner) = arinsal_term::binary_owner(term)? else {
        return None;
    };
    if owner.is_writable() {
        return None;
    }
    let offset = (base + start_bit / 8).checked_sub(owner.payload_ptr() as usize)?;
    arinsal_drv::RefcSegment::new(owner, offset, len)
}

/// The command iolist as a vector: bytes copied, refc binaries referenced. A command without
/// a refc binary is one `Bytes` element, as `iodata` gives it.
// Port of erts/emulator/beam/io.c:1715 (erts_port_output builds the ErlIOVec with
// erts_ioq_iolist_to_vec), OTP-29.1.1.
fn command_pieces(t: Term) -> Option<arinsal_drv::CommandVector> {
    use arinsal_drv::CommandPiece;
    // The bytes that will be copied, so the buffer is allocated once (erts_iolist_size);
    // binaries over the on-heap limit may be referenced instead.
    let mut copied = 0usize;
    walk_iodata(t, false, &mut |chunk| {
        copied += match chunk {
            IoChunk::Byte(_) => 1,
            IoChunk::Binary(term) => {
                let len = arinsal_bifs::bitstring_bit_len(term).ok()? / 8;
                if len <= arinsal_drv::ERL_ONHEAP_BINARY_LIMIT {
                    len
                } else {
                    0
                }
            }
        };
        Some(())
    })?;
    let mut out = smallvec::SmallVec::new();
    let mut current = Vec::with_capacity(copied);
    walk_iodata(t, false, &mut |chunk| match chunk {
        IoChunk::Byte(byte) => {
            current.push(byte);
            Some(())
        }
        IoChunk::Binary(term) => {
            if let Some(segment) = refc_segment(term) {
                if !current.is_empty() {
                    out.push(CommandPiece::Bytes(std::mem::take(&mut current)));
                }
                out.push(CommandPiece::Refc(segment));
                Some(())
            } else {
                append_binary(term, &mut current)
            }
        }
    })?;
    if !current.is_empty() || out.is_empty() {
        out.push(CommandPiece::Bytes(current));
    }
    Some(out)
}

/// One leaf of an iolist.
enum IoChunk {
    Byte(u8),
    Binary(Term),
}

/// Visit the leaves of an iolist in order. The spine is walked in a loop: long lists must
/// not recurse per cell.
fn walk_iodata(
    mut term: Term,
    mut tail: bool,
    visit: &mut impl FnMut(IoChunk) -> Option<()>,
) -> Option<()> {
    while term.classify() == TermKind::List {
        // SAFETY: The list is traversed before the caller's process heap can move.
        let (head, rest) = unsafe { term.cons_ref()? };
        walk_iodata(head, false, visit)?;
        term = rest;
        tail = true;
    }
    if term == Term::NIL {
        Some(())
    } else if term.classify() == TermKind::Bitstring {
        visit(IoChunk::Binary(term))
    } else if !tail {
        let value = term.as_small()?;
        if !(0..=255).contains(&value) {
            return None;
        }
        visit(IoChunk::Byte(value as u8))
    } else {
        None
    }
}

/// The control payload in an inline buffer (`erts_port_control` converts into a temp buffer
/// of 8 KB first, so the common small payload allocates nothing).
fn control_input(t: Term) -> Option<smallvec::SmallVec<[u8; 256]>> {
    let mut out = smallvec::SmallVec::new();
    walk_iodata(t, false, &mut |chunk| match chunk {
        IoChunk::Byte(byte) => {
            out.push(byte);
            Some(())
        }
        IoChunk::Binary(term) => {
            let bits = arinsal_bifs::bitstring_bit_len(term).ok()?;
            if !bits.is_multiple_of(8) {
                return None;
            }
            let start = out.len();
            out.resize(start + bits / 8, 0);
            arinsal_bifs::copy_binary_range(term, 0, &mut out[start..]).ok()
        }
    })?;
    Some(out)
}

fn iodata(t: Term) -> Option<Vec<u8>> {
    // Port of erts/emulator/beam/erl_iolist.c (erts_iolist_size, erts_iolist_to_buf): size the
    // result first so the flat buffer is allocated once.
    fn size(mut term: Term, mut tail: bool) -> Option<usize> {
        let mut total = 0usize;
        while term.classify() == TermKind::List {
            // SAFETY: The list is traversed before the caller's process heap can move.
            let (head, rest) = unsafe { term.cons_ref()? };
            total = total.checked_add(size(head, false)?)?;
            term = rest;
            tail = true;
        }
        if term == Term::NIL {
            Some(total)
        } else if term.classify() == TermKind::Bitstring {
            let bits = arinsal_bifs::bitstring_bit_len(term).ok()?;
            bits.is_multiple_of(8).then_some(total + bits / 8)
        } else if !tail && matches!(term.as_small(), Some(0..=255)) {
            Some(total + 1)
        } else {
            None
        }
    }
    if t.as_small().is_some() {
        return None;
    }
    let mut out = Vec::with_capacity(size(t, false)?);
    walk_iodata(t, false, &mut |chunk| match chunk {
        IoChunk::Byte(byte) => {
            out.push(byte);
            Some(())
        }
        IoChunk::Binary(term) => append_binary(term, &mut out),
    })?;
    Some(out)
}
fn tuple(t: Term) -> Option<Vec<Term>> {
    // SAFETY: The borrowed tuple is collected while the caller heap remains live.
    unsafe { t.tuple_ref() }.map(|v| v.iter().collect())
}
fn unsigned_term(term: Term) -> Option<u64> {
    match &to_owned(term).ok()? {
        OwnedTerm::Int(value) => u64::try_from(*value).ok(),
        OwnedTerm::BigInt(value) => num_traits::ToPrimitive::to_u64(value),
        _ => None,
    }
}
struct PortOptions {
    binary: bool,
    framing: Option<(u8, usize)>,
    exit_status: bool,
    eof: bool,
    args: Vec<Vec<u8>>,
    args_set: bool,
    arg0: Option<Vec<u8>>,
    cwd: Option<Vec<u8>>,
    env: Vec<(Vec<u8>, Option<Vec<u8>>)>,
    stderr_to_stdout: bool,
    use_stdio: bool,
    rw: u8,
    parallelism: bool,
    limits: BusyLimits,
}
fn options(t: Term) -> Option<PortOptions> {
    let mut opts = PortOptions {
        binary: false,
        framing: None,
        exit_status: false,
        eof: false,
        args: Vec::new(),
        args_set: false,
        arg0: None,
        cwd: None,
        env: Vec::new(),
        stderr_to_stdout: false,
        use_stdio: true,
        rw: 0,
        parallelism: false,
        limits: BusyLimits {
            port_low: DEFAULT_LOW,
            port_high: DEFAULT_HIGH,
            port_enabled: true,
            msgq_low: DEFAULT_LOW,
            msgq_high: DEFAULT_HIGH,
            msgq_enabled: true,
        },
    };
    for item in list(t)? {
        if item == Term::atom(arinsal_term::atoms::BINARY) {
            opts.binary = true;
        } else if item == Term::atom(arinsal_term::atoms::EXIT_STATUS) {
            opts.exit_status = true;
        } else if item == Term::atom(arinsal_term::atoms::EOF) {
            opts.eof = true;
        } else if item == Term::atom(arinsal_term::atoms::LINE) {
            // Port of erts/emulator/beam/erl_bif_port.c:985, OTP-29.1.1.
            if opts.framing.is_some_and(|(mode, _)| mode != 1) {
                return None;
            }
            opts.framing = Some((1, 512));
        } else if item == Term::atom(arinsal_term::atoms::STREAM)
            || item == Term::atom(arinsal_term::atoms::HIDE)
            || item == Term::atom(arinsal_term::atoms::OVERLAPPED_IO)
        {
        } else if item == Term::atom(arinsal_term::atoms::USE_STDIO) {
            opts.use_stdio = true;
        } else if item == Term::atom(arinsal_term::atoms::NOUSE_STDIO) {
            opts.use_stdio = false;
        } else if item == Term::atom(arinsal_term::atoms::STDERR_TO_STDOUT) {
            opts.stderr_to_stdout = true;
        } else if item == Term::atom(arinsal_term::atoms::IN) {
            opts.rw |= 1;
        } else if item == Term::atom(arinsal_term::atoms::OUT) {
            opts.rw |= 2;
        } else {
            let pair = tuple(item)?;
            if pair.len() == 2
                && pair[0] == Term::atom(arinsal_term::atoms::PACKET)
                && matches!(pair[1].as_small(), Some(1 | 2 | 4))
            {
                // Port of erts/emulator/beam/erl_bif_port.c (open_port packet 1|2|4), OTP-29.1.1.
                let n = pair[1].as_small().unwrap() as u8;
                if opts.framing.is_some_and(|(mode, _)| mode == 1) {
                    return None;
                }
                opts.framing = Some((2, n as usize));
            } else if pair.len() == 2 && pair[0] == Term::atom(arinsal_term::atoms::LINE) {
                let n = pair[1].as_small()?;
                if n <= 0 {
                    return None;
                }
                if opts.framing.is_some_and(|(mode, _)| mode != 1) {
                    return None;
                }
                opts.framing = Some((1, n as usize));
            } else if pair.len() == 2 && pair[0] == Term::atom(arinsal_term::atoms::ARGS) {
                opts.args = list(pair[1])?
                    .into_iter()
                    .map(string_bytes)
                    .collect::<Option<Vec<_>>>()?;
                opts.args_set = true;
            } else if pair.len() == 2 && pair[0] == Term::atom(arinsal_term::atoms::ARG0) {
                opts.arg0 = Some(filename_bytes(pair[1], true, true)?);
            } else if pair.len() == 2 && pair[0] == Term::atom(arinsal_term::atoms::CD) {
                opts.cwd = Some(filename_bytes(pair[1], false, true)?);
            } else if pair.len() == 2 && pair[0] == Term::atom(arinsal_term::atoms::ENV) {
                opts.env.clear();
                for entry in list(pair[1])? {
                    let env = tuple(entry)?;
                    if env.len() != 2 {
                        return None;
                    }
                    let name = bytes(env[0])?;
                    if name.contains(&b'=') || name.contains(&0) {
                        return None;
                    }
                    let value = if env[1] == Term::atom(arinsal_term::atoms::FALSE) {
                        None
                    } else {
                        let value = bytes(env[1])?;
                        if value.contains(&0) {
                            return None;
                        }
                        Some(value)
                    };
                    opts.env.push((name, value));
                }
            } else if pair.len() == 2 && pair[0] == Term::atom(arinsal_term::atoms::PARALLELISM) {
                // Port of erts/emulator/beam/erl_bif_port.c:913 (open_port parallelism), OTP-29.1.1.
                if pair[1] == Term::atom(arinsal_term::atoms::TRUE) {
                    opts.parallelism = true;
                } else if pair[1] == Term::atom(arinsal_term::atoms::FALSE) {
                    opts.parallelism = false;
                } else {
                    return None;
                }
            } else if pair.len() == 2
                && (pair[0] == Term::atom(arinsal_term::atoms::BUSY_LIMITS_PORT)
                    || pair[0] == Term::atom(arinsal_term::atoms::BUSY_LIMITS_MSGQ))
            {
                // Port of erts/emulator/beam/erl_bif_port.c:920 (busy_limits_port / busy_limits_msgq), OTP-29.1.1.
                let port_limit = pair[0] == Term::atom(arinsal_term::atoms::BUSY_LIMITS_PORT);
                let (low, high, enabled) = if pair[1] == Term::atom(arinsal_term::atoms::DISABLED) {
                    (0, 0, false)
                } else {
                    let limits = tuple(pair[1])?;
                    if limits.len() != 2 {
                        return None;
                    }
                    // Port of term_to_Uint in erl_bif_port.c:928-930, OTP-29.1.1.
                    let mut low = usize::try_from(unsigned_term(limits[0])?).ok()?;
                    let high = usize::try_from(unsigned_term(limits[1])?).ok()?;
                    // ERL_DRV_BUSY_MSGQ_LIM_MAX is Uint max minus one; Uint max is reserved.
                    if low == 0 || high == 0 || low == usize::MAX || high == usize::MAX {
                        return None;
                    }
                    if low > high {
                        low = high;
                    }
                    (low, high, true)
                };
                if port_limit {
                    opts.limits.port_low = low;
                    opts.limits.port_high = high;
                    opts.limits.port_enabled = enabled;
                } else {
                    opts.limits.msgq_low = low;
                    opts.limits.msgq_high = high;
                    opts.limits.msgq_enabled = enabled;
                }
            } else {
                return None;
            }
        }
    }
    // Port of erts/emulator/beam/erl_bif_port.c:1014 (default read_write), OTP-29.1.1.
    if opts.rw == 0 {
        opts.rw = 3;
    }
    if opts.stderr_to_stdout && !opts.use_stdio {
        return None;
    }
    Some(opts)
}
fn term_data(heap: &mut ProcessHeap, bytes: &[u8], binary: bool) -> Result<Term, VmError> {
    let mut b = TermBuilder::new(heap);
    if binary {
        b.binary(bytes)
    } else {
        b.list_from_iter(bytes.iter().map(|x| Term::small(*x as i64).unwrap()))
    }
    .map_err(|e| VmError::Unsupported(format!("port data allocation: {e:?}")))
}
fn publish(scheduler: &Scheduler<Process>, owner: Pid, port: Term, msg: Term) {
    let Ok(envelope) = Message::copy_from(msg) else {
        return;
    };
    let _ = scheduler.send(owner, owner, envelope);
    let _ = port;
}
fn output_message(
    scheduler: &Scheduler<Process>,
    owner: Pid,
    port_id: u64,
    bytes: &[u8],
    binary: bool,
    trace_scope: usize,
) {
    let Some(port) = Term::port(port_id) else {
        return;
    };
    let mut heap = ProcessHeap::with_words(output_heap_words(bytes.len(), binary, 24));
    let Ok(data) = term_data(&mut heap, bytes, binary) else {
        return;
    };
    let data = TermBuilder::new(&mut heap).tuple(&[Term::atom(arinsal_term::atoms::DATA), data]);
    let Ok(data) = data else { return };
    let Ok(msg) = TermBuilder::new(&mut heap).tuple(&[port, data]) else {
        return;
    };
    trace_port_send(scheduler, trace_scope, port_id, owner, msg);
    publish(scheduler, owner, port, msg);
}

// Port of erts/emulator/drivers/common/ram_file_drv.c:217-229 (driver_output2 replies).
pub(crate) fn static_driver_output(handle: &PortHandle, bytes: &[u8]) {
    handle.add_bytes_in(bytes.len());
    output_message(
        &handle.scheduler,
        handle.owner_pid(),
        handle.id,
        bytes,
        false,
        handle.trace_scope(),
    );
}

// Port of erts/emulator/drivers/common/ram_file_drv.c:465-470, :479-484 and :506-510.
pub(crate) fn static_driver_output_binary(
    handle: &PortHandle,
    header: &[u8],
    bytes: &[u8],
    binary: bool,
) {
    if !binary {
        let mut reply = Vec::with_capacity(header.len() + bytes.len());
        reply.extend_from_slice(header);
        reply.extend_from_slice(bytes);
        static_driver_output(handle, &reply);
        return;
    }
    handle.add_bytes_in(header.len() + bytes.len());
    let Some(port) = Term::port(handle.id) else {
        return;
    };
    let mut heap =
        ProcessHeap::with_words(output_heap_words(header.len() + bytes.len(), false, 32));
    let build = |heap: &mut ProcessHeap| -> Result<Term, arinsal_term::TermError> {
        let mut data = TermBuilder::new(heap).binary(bytes)?;
        for byte in header.iter().rev() {
            data = TermBuilder::new(heap).cons(Term::small(i64::from(*byte)).unwrap(), data)?;
        }
        let message =
            TermBuilder::new(heap).tuple(&[Term::atom(arinsal_term::atoms::DATA), data])?;
        TermBuilder::new(heap).tuple(&[port, message])
    };
    if let Ok(message) = build(&mut heap) {
        trace_port_send(
            &handle.scheduler,
            handle.trace_scope(),
            handle.id,
            handle.owner_pid(),
            message,
        );
        publish(&handle.scheduler, handle.owner_pid(), port, message);
    }
}

fn output_heap_words(byte_len: usize, binary: bool, overhead: usize) -> usize {
    if binary {
        byte_len / 4 + overhead
    } else {
        // A list byte per output byte needs two young-heap words per cons cell.
        byte_len.saturating_mul(2).saturating_add(overhead)
    }
}
fn event_message(
    scheduler: &Scheduler<Process>,
    owner: Pid,
    port_id: u64,
    trace_scope: usize,
    event: Term,
) {
    let Some(port) = Term::port(port_id) else {
        return;
    };
    let mut heap = ProcessHeap::with_words(24);
    if let Ok(msg) = TermBuilder::new(&mut heap).tuple(&[port, event]) {
        // terminate_port traces the `closed` atom even though the delivered message is
        // `{Port, closed}` (io.c:3755, OTP-29.1.1).
        trace_port_send(
            scheduler,
            trace_scope,
            port_id,
            owner,
            if event == Term::atom(arinsal_term::atoms::CLOSED) {
                event
            } else {
                msg
            },
        );
        publish(scheduler, owner, port, msg);
    }
}

fn connected_message(
    runtime: &crate::process::Runtime,
    scheduler: &Scheduler<Process>,
    owner: Pid,
    port_id: u64,
    trace_scope: usize,
    deliver: bool,
) {
    // Port of erts/emulator/beam/io.c:2324-2410 (set_port_connected), OTP-29.1.1.
    let Some(port) = Term::port(port_id) else {
        return;
    };
    let mut heap = ProcessHeap::with_words(24);
    let Ok(message) =
        TermBuilder::new(&mut heap).tuple(&[port, Term::atom(arinsal_term::atoms::CONNECTED)])
    else {
        return;
    };
    trace_port_send(scheduler, trace_scope, port_id, owner, message);
    if !deliver {
        return;
    }
    let traced = crate::trace::emit_external_process_event(
        runtime,
        owner,
        crate::trace::RECEIVE,
        "receive",
        &[message],
    );
    let Ok(mut envelope) = Message::copy_from(message) else {
        return;
    };
    if traced {
        envelope = envelope.with_receive_traced();
    }
    let _ = scheduler.send(owner, owner, envelope);
}

fn trace_port_send(
    scheduler: &Scheduler<Process>,
    trace_scope: usize,
    port_id: u64,
    receiver: Pid,
    message: Term,
) {
    // Port of erts/emulator/beam/erl_trace.c:2221 (trace_port_send), OTP-29.1.1.
    if let Some(receiver) = receiver.to_term() {
        crate::trace::emit_port_event_scoped(
            trace_scope,
            scheduler,
            port_id,
            crate::trace::SEND,
            "send",
            &[message, receiver],
        );
    }
}

fn start(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &RunCtx<'_, crate::Process>,
    spec: Term,
    opts: Term,
) -> Result<Term, VmError> {
    let parsed_opts = options(opts).ok_or_else(badarg)?;
    let spec = tuple(spec).ok_or_else(badarg)?;
    // Port of erts/emulator/beam/erl_bif_port.c:1086-1091, OTP-29.1.1.
    // An argv vector is valid only for an explicit spawn_executable port.
    if (parsed_opts.args_set || parsed_opts.arg0.is_some())
        && !spec
            .first()
            .is_some_and(|kind| *kind == Term::atom(arinsal_term::atoms::SPAWN_EXECUTABLE))
    {
        return Err(badarg());
    }
    if let [kind, input, output] = spec.as_slice() {
        if *kind != Term::atom(arinsal_term::atoms::FD) {
            return Err(badarg());
        }
        let input = input.as_small().filter(|fd| *fd >= 0).ok_or_else(badarg)? as RawFd;
        let output = output.as_small().filter(|fd| *fd >= 0).ok_or_else(badarg)? as RawFd;
        return start_fd(vm, process, ctx, input, output, &parsed_opts);
    }
    let PortOptions {
        binary,
        framing,
        exit_status: want_status,
        eof: want_eof,
        args,
        arg0,
        cwd,
        env,
        stderr_to_stdout,
        use_stdio,
        rw,
        parallelism,
        limits,
        ..
    } = parsed_opts;
    if let [kind, cmd] = spec.as_slice()
        && (*kind == Term::atom(arinsal_term::atoms::SPAWN_DRIVER)
            || *kind == Term::atom(arinsal_term::atoms::SPAWN))
    {
        // erts_convert_filename_to_encoding also takes an atom name.
        let name = match cmd.as_atom() {
            Some(name) => global_atoms()
                .text(name)
                .map(|text| text.to_string())
                .ok_or_else(badarg)?,
            None => String::from_utf8(bytes(*cmd).ok_or_else(badarg)?).map_err(|_| badarg())?,
        };
        // Port of erts/emulator/beam/io.c:579-620 (erts_open_driver): the first word of
        // the command names the driver; `spawn` falls back to the spawn driver.
        let first = name.split(' ').next().unwrap_or_default();
        match crate::ddll::find_driver(first) {
            Some(crate::ddll::Found::Static) => {
                let line = framing.and_then(|(mode, n)| (mode == 1).then_some(n));
                return start_driver(
                    process,
                    ctx,
                    name,
                    binary,
                    DriverIoFlags {
                        msgq: limits
                            .msgq_enabled
                            .then_some((limits.msgq_low, limits.msgq_high)),
                        binary,
                        eof: want_eof,
                        line,
                        parallelism,
                    },
                );
            }
            None if *kind == Term::atom(arinsal_term::atoms::SPAWN_DRIVER) => return Err(badarg()),
            Some(found) => {
                if let Some((handle_id, driver)) = found.into_loaded() {
                    if want_status {
                        return Err(badarg());
                    }
                    let line = framing.and_then(|(mode, n)| (mode == 1).then_some(n));
                    return start_dyn_driver(
                        process,
                        ctx,
                        handle_id,
                        driver,
                        name,
                        DriverIoFlags {
                            msgq: limits
                                .msgq_enabled
                                .then_some((limits.msgq_low, limits.msgq_high)),
                            binary,
                            eof: want_eof,
                            line,
                            parallelism,
                        },
                    );
                }
            }
            None => {}
        }
    }
    let (name, executable, child_program, child_args) = match spec.as_slice() {
        [kind, path] if *kind == Term::atom(arinsal_term::atoms::SPAWN_EXECUTABLE) => {
            let path = filename_bytes(*path, false, true).ok_or_else(badarg)?;
            let name = String::from_utf8_lossy(&path).into_owned();
            let args = args.into_iter().map(OsString::from_vec).collect::<Vec<_>>();
            let executable_path = if path.contains(&b'/') {
                OsString::from_vec(path)
            } else {
                let mut relative = b"./".to_vec();
                relative.extend_from_slice(&path);
                OsString::from_vec(relative)
            };
            (name, true, executable_path, args)
        }
        [kind, cmd] if *kind == Term::atom(arinsal_term::atoms::SPAWN) => {
            let cmd = bytes(*cmd).ok_or_else(badarg)?;
            let name = String::from_utf8(cmd).map_err(|_| badarg())?;
            (
                name.clone(),
                false,
                OsString::from("/bin/sh"),
                vec![OsString::from("-c"), OsString::from(name)],
            )
        }
        _ => return Err(badarg()),
    };
    let child_arg0 = if executable {
        arg0.map(OsString::from_vec)
    } else {
        None
    };
    let child_cwd = cwd.map(OsString::from_vec);
    // Port of erts/emulator/beam/erl_bif_port.c:1024 (default child environment), OTP-29.1.1.
    let mut child_env = crate::erl_osenv::port_env(&env);
    // Keep `erl` child launchers on this VM's selected installation when the port changes cwd.
    if erl_launcher(&name, executable)
        && let Some(root) = crate::erl_init::erts_root_dir()
    {
        let mut paths = vec![root.join("bin")];
        if let Some(path) = child_env.get(b"PATH") {
            paths.extend(std::env::split_paths(&crate::erl_osenv::os_string(path)));
        }
        if let Ok(path) = std::env::join_paths(paths) {
            child_env.put(b"PATH", path.as_os_str().as_bytes());
        }
    }
    let runtime = process.runtime.ok_or_else(badarg)?;
    let reservation = reserve_port_id(runtime)?;
    if executable
        && let Err(error) = rustix::fs::access(&child_program, rustix::fs::Access::EXEC_OK)
    {
        return Ok(atom_dyn(&arinsal_drv::errno_id(error.raw_os_error())));
    }
    let setup = child_setup_payload(
        executable,
        &name,
        &child_program,
        &child_args,
        child_arg0.as_deref(),
        child_cwd.as_deref(),
        &child_env,
        use_stdio,
        rw,
        want_status,
    )
    .map_err(|_| badarg())?;
    let spawned = match crate::child_setup::spawn_pipes(&setup, stderr_to_stdout) {
        Ok(spawned) => spawned,
        Err(error) => {
            if let Some(errno) = error.raw_os_error() {
                // Port of erts/emulator/beam/erl_bif_port.c:69-89 and
                // erts/emulator/sys/unix/sys_drivers.c:471-501 (spawn_start), OTP-29.1.1.
                // OS launch failures return their errno atom; badarg is reserved for invalid
                // open_port arguments. In particular, a full descriptor table is `emfile`.
                return Ok(atom_dyn(&arinsal_drv::errno_id(errno)));
            }
            return Err(badarg());
        }
    };
    let crate::child_setup::SpawnedChild {
        input,
        output,
        setup_rest,
        child_fds,
    } = spawned;
    // Port of sys_drivers.c (`spawn_start`): the port exists at once; the OS pid arrives with
    // the forker's `Go` frame as port input, and `erl_drv_init_ack` answers the opener.
    let start = crate::spawn_drv::SpawnStart {
        ifd: output.into_raw_fd(),
        ofd: input.into_raw_fd(),
        packet_bytes: framing
            .and_then(|(mode, n)| (mode == 2).then_some(n))
            .unwrap_or(0),
        exit_status: want_status,
        do_read: rw & 1 != 0,
        do_write: rw & 2 != 0,
        high_watermark: if limits.port_enabled {
            limits.port_high
        } else {
            usize::MAX
        },
        low_watermark: limits.port_low,
        setup_rest,
        child_fds,
        runtime,
    };
    let _ = vm;
    open_driver_port(
        process,
        ctx,
        reservation,
        None,
        crate::spawn_drv::driver(),
        name,
        DriverIoFlags {
            msgq: limits
                .msgq_enabled
                .then_some((limits.msgq_low, limits.msgq_high)),
            binary,
            eof: want_eof,
            line: framing.and_then(|(mode, n)| (mode == 1).then_some(n)),
            parallelism,
        },
        Some(crate::spawn_drv::SysStart::Spawn(start)),
    )
}

// Port of erts/emulator/drivers/common/inet_drv.c:1361 (tcp_inet driver entry), OTP-29.1.1.
// `tcp_inet6` is the same driver; OPEN carries the address family.
// g_inet_udp: `udp_inet` is the only datagram driver erts registers.
// `udp_inet6` and `sctp_inet` are absent, so `open_port` stays `badarg`
// and `prim_inet` maps that onto `{error, eprotonosupport}`.
fn start_driver(
    process: &mut Process,
    ctx: &RunCtx<'_, crate::Process>,
    name: String,
    _binary: bool,
    io: DriverIoFlags,
) -> Result<Term, VmError> {
    let udp = name == "udp_inet";
    let ram_file = name == "ram_file_drv";
    if name != "tcp_inet" && name != "tcp_inet6" && !udp && !ram_file {
        return Err(badarg());
    }
    if !ram_file {
        // Port of erts/emulator/beam/io.c:542 (erts_open_driver) for the linked-in
        // tcp_inet and udp_inet drivers: ports on the generic port machinery.
        let driver = if udp {
            crate::inet_udp::driver()
        } else {
            crate::inet_drv::driver()
        };
        return start_dyn_driver(process, ctx, None, driver, name, io);
    }
    let runtime = process.runtime.ok_or_else(badarg)?;
    let scheduler = runtime.scheduler_arc()?;
    let reservation = reserve_port_id(runtime)?;
    let port_id = reservation.id();
    let port = Term::port(port_id).ok_or_else(badarg)?;
    let handle = make_driver_handle(port_id, ctx.pid(), name, false, scheduler, runtime, None)?;
    runtime.ports.insert(port_id, Arc::clone(&handle));
    link_opener(process, port_id);
    crate::trace::port_opened(runtime, port_id);
    reservation.commit();
    handle.set_ram_file_data(crate::ram_file_drv::start(_binary));
    Ok(port)
}

/// `open_port` options that become driver port state flags.
struct DriverIoFlags {
    /// `{busy_limits_msgq, {Low, High}}`, `None` when disabled.
    msgq: Option<(usize, usize)>,
    binary: bool,
    eof: bool,
    line: Option<usize>,
    parallelism: bool,
}

/// `ERL_DRV_FLAG_USE_INIT_ACK`.
const ERL_DRV_FLAG_USE_INIT_ACK: i32 = 1 << 3;
const ERL_DRV_FLAG_NO_BUSY_MSGQ: i32 = 1 << 2;
/// `ERL_DRV_FLAG_USE_PORT_LOCKING` (erl_driver.h).
const ERL_DRV_FLAG_USE_PORT_LOCKING: i32 = 1 << 0;

/// Port of erts/emulator/beam/io.c:542 (erts_open_driver) for a dynamically loaded
/// driver, with the state flags erl_bif_port.c:1140 sets after `start`.
fn start_dyn_driver(
    process: &mut Process,
    ctx: &RunCtx<'_, crate::Process>,
    handle_id: Option<u64>,
    driver: Arc<arinsal_drv::Driver>,
    name: String,
    io: DriverIoFlags,
) -> Result<Term, VmError> {
    let runtime = process.runtime.ok_or_else(badarg)?;
    let reservation = reserve_port_id(runtime)?;
    open_driver_port(process, ctx, reservation, handle_id, driver, name, io, None)
}

/// Port of erts/emulator/beam/io.c:542 (erts_open_driver) once the port id is taken;
/// `spawn` is what `spawn_start` set up before the driver data exists.
/// `erts_open_driver(driver, make_internal_pid(0), name, ...)` of a port the runtime opens
/// for itself (sys_drivers.c:170 erl_sys_late_init opens the forker this way): no process
/// opened it, so nothing links to it and `start` is the driver's own `attach`. The port id.
// Port of erts/emulator/beam/io.c:542 (erts_open_driver), OTP-29.1.1.
pub(crate) fn open_sys_driver_port(
    runtime: &'static crate::process::Runtime,
    driver: Arc<arinsal_drv::Driver>,
    name: &str,
    start: impl FnOnce(&arinsal_drv::DriverPort) -> Result<(), VmError>,
) -> Result<u64, VmError> {
    let scheduler = runtime.scheduler()?;
    install_hooks();
    let reservation = reserve_port_id(runtime)?;
    let port_id = reservation.id();
    // `opts.parallelism = erts_port_parallelism`.
    let parallelism = arinsal_args::active_scheduler_options()
        .0
        .port_parallelism
        .unwrap_or(false);
    let handle = make_driver_handle(
        port_id,
        Pid::from_data(0),
        name.to_owned(),
        parallelism,
        Arc::clone(scheduler),
        runtime,
        Some((driver, runtime)),
    )?;
    // erl_bif_port.c links the opener of open_port; erts_open_driver itself links nobody.
    *handle.links.lock() = crate::proc_create::LinkTree::default();
    install_poll_backend();
    let drv_port = handle.drv_port().expect("driver state embedded");
    drv_port.init_run_queue(scheduler.current_run_queue());
    drv_port.set_parallelism(parallelism);
    start(&drv_port)?;
    runtime.ports.insert(port_id, Arc::clone(&handle));
    crate::trace::port_opened(runtime, port_id);
    reservation.commit();
    if let Err(error) = drv_port.start(name, packed_pid(Pid::from_data(0))) {
        remove_port(runtime, port_id);
        drv_port.abandon();
        release_io(&handle);
        return Err(VmError::Load(format!(
            "cannot open the {name} port: {error:?}"
        )));
    }
    Ok(port_id)
}

#[allow(clippy::too_many_arguments)]
fn open_driver_port(
    process: &mut Process,
    ctx: &RunCtx<'_, crate::Process>,
    reservation: PortIdReservation<'_>,
    handle_id: Option<u64>,
    driver: Arc<arinsal_drv::Driver>,
    name: String,
    io: DriverIoFlags,
    sys: Option<crate::spawn_drv::SysStart>,
) -> Result<Term, VmError> {
    let runtime = process.runtime.ok_or_else(badarg)?;
    let scheduler = runtime.scheduler()?;
    install_hooks();
    let port_id = reservation.id();
    let port = Term::port(port_id).ok_or_else(badarg)?;
    let handle = make_driver_handle(
        port_id,
        ctx.pid(),
        name.clone(),
        io.parallelism,
        Arc::clone(scheduler),
        runtime,
        Some((Arc::clone(&driver), runtime)),
    )?;
    install_poll_backend();
    let drv_port = handle.drv_port().expect("driver state embedded");
    drv_port.init_run_queue(scheduler.current_run_queue());
    if let Some(handle_id) = handle_id {
        crate::ddll::port_opened(handle_id, &drv_port);
    }
    // Port of io.c:318 and io.c:683: drivers without ERL_DRV_FLAG_NO_BUSY_MSGQ have a busy
    // port message queue; open_port limits are set before `start`.
    if let Some((low, high)) = io.msgq {
        drv_port.set_msgq_limits(low, high);
    } else if driver.flags() & ERL_DRV_FLAG_NO_BUSY_MSGQ != 0 {
        drv_port.set_msgq_limits(
            arinsal_drv::BUSY_MSGQ_DISABLED,
            arinsal_drv::BUSY_MSGQ_DISABLED,
        );
    }
    drv_port.set_parallelism(io.parallelism);
    if driver.is_native() {
        if let Some(start) = &sys {
            start.attach(&handle, &drv_port);
        } else if driver.name() == "udp_inet" {
            crate::inet_udp::attach(&handle, &drv_port);
        } else {
            crate::inet_drv::attach(runtime, &handle, &drv_port);
        }
    }
    runtime.ports.insert(port_id, Arc::clone(&handle));
    crate::trace::port_opened(runtime, port_id);
    reservation.commit();
    // Port of erts/emulator/beam/io.c:673-680 (erts_open_driver): the open trace and its
    // driver-name atom put happen after port creation and before the driver's start callback.
    if crate::trace::port_trace_enabled(runtime, port_id, crate::trace::PORTS)
        && let Some(caller) = ctx.pid().to_term()
    {
        crate::trace::emit_port_event(
            runtime,
            port_id,
            crate::trace::PORTS,
            "open",
            &[
                caller,
                global_atoms()
                    .put(name.as_bytes(), arinsal_term::AtomEncoding::Latin1, true)
                    .map_or(Term::NIL, Term::atom),
            ],
        );
    }
    let caller = packed_pid(ctx.pid());
    if let Err(error) = drv_port.start(&name, caller) {
        remove_port(runtime, port_id);
        drv_port.abandon();
        release_io(&handle);
        if handle_id.is_some() {
            crate::ddll::port_closed(scheduler, &driver);
        }
        // Port of erts/emulator/beam/erl_bif_port.c:69-89 (open_port error atoms).
        return Ok(match error {
            arinsal_drv::StartError::General => Term::atom(arinsal_term::atoms::EINVAL),
            arinsal_drv::StartError::Errno(errno) => atom_dyn(&arinsal_drv::errno_id(errno)),
            arinsal_drv::StartError::Badarg => Term::atom(arinsal_term::atoms::BADARG),
        });
    }
    link_opener(process, port_id);
    drv_port.set_io_flags(io.binary, io.eof, io.line);
    // Port of erts/emulator/beam/erl_bif_port.c:1123-1124: open_port emits getting_linked
    // after erts_open_driver succeeds.
    if crate::trace::port_trace_enabled(runtime, port_id, crate::trace::PORTS)
        && let Some(caller) = ctx.pid().to_term()
    {
        crate::trace::emit_port_event(
            runtime,
            port_id,
            crate::trace::PORTS,
            "getting_linked",
            &[caller],
        );
    }
    let init_ack = driver.flags() & ERL_DRV_FLAG_USE_INIT_ACK != 0;
    let reference = init_ack.then(|| runtime.next_ref());
    if let Some(reference) = reference {
        handle.with_cold(|cold| cold.async_open = Some((reference, ctx.pid())));
        drv_port.expect_init_ack();
    }
    if let Some(start) = sys {
        start.begin(&drv_port);
    }
    if let Some(reference) = reference {
        // Port of erts/emulator/beam/erl_bif_port.c:102: the opener gets a
        // reference and the port, or the error, in `{Ref, Result}` from `erl_drv_init_ack`.
        let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
        return TermBuilder::new(&mut heap)
            .local_ref(arinsal_sched::unique::ordinary_ref_words(reference))
            .map_err(|_| badarg());
    }
    Ok(port)
}

/// Caller identity for drivers (`prt->caller`): the erts pid data word.
fn packed_pid(pid: Pid) -> u64 {
    pid.data()
}

/// `PortHost` for a dynamically loaded driver port.
struct DrvHost {
    runtime: &'static crate::process::Runtime,
    /// The port itself: `stop` still delivers output after the port left the table
    /// (io.c:3698 terminate_port runs after erts_deliver_port_exit unlinked it).
    own: Weak<PortHandle>,
}

impl DrvHost {
    fn handle(&self, id: u64) -> Option<Arc<PortHandle>> {
        self.runtime.ports.get(id).or_else(|| self.own.upgrade())
    }
}

impl arinsal_drv::PortHost for DrvHost {
    // Port of erts/emulator/beam/erl_trace.c:2299-2324 (trace_sched_ports_where), OTP-29.1.1.
    fn trace_sched_port(
        &self,
        port: &arinsal_drv::DriverPort,
        scheduled_in: bool,
        where_: Option<&str>,
    ) {
        if !crate::trace::tracing_enabled() {
            return;
        }
        let runtime = self.runtime;
        let where_term = where_.map_or_else(|| Term::small(0).unwrap(), crate::atom_cache::put);
        crate::trace::emit_port_event(
            runtime,
            port.id(),
            crate::trace::RUNNING_PORTS,
            if scheduled_in { "in" } else { "out" },
            &[where_term],
        );
    }

    fn task_done(&self, port: &arinsal_drv::DriverPort, op: &str, elapsed_ns: u64) {
        let runtime = self.runtime;
        if !crate::natives::erts_debug::runtime_long_schedule_monitored(runtime) {
            return;
        }
        let Some(handle) = runtime.ports.get(port.id()) else {
            return;
        };
        if let Some(term) = Term::port(port.id()) {
            crate::natives::erts_debug::after_port_task(
                runtime,
                term,
                handle.owner_pid(),
                op,
                elapsed_ns,
            );
        }
    }

    // Port of erts/emulator/beam/io.c:3357 (deliver_read_message), OTP-29.1.1.
    fn deliver_data(
        &self,
        port: &arinsal_drv::DriverPort,
        header: &[u8],
        data: Option<&[u8]>,
        binary: bool,
        line: Option<bool>,
    ) {
        let Some(handle) = self.handle(port.id()) else {
            return;
        };
        let Some(port_term) = Term::port(port.id()) else {
            return;
        };
        let owner = handle.owner_pid();
        let len = data.map_or(0, <[u8]>::len) + header.len();
        handle.add_bytes_in(len + usize::from(line == Some(true)));
        let mut heap = ProcessHeap::with_words(output_heap_words(len, false, 32));
        let build = |heap: &mut ProcessHeap| -> Result<Term, arinsal_term::TermError> {
            let mut list = match data {
                Some(bytes) if binary => TermBuilder::new(heap).binary(bytes)?,
                Some(bytes) => TermBuilder::new(heap)
                    .list_from_iter(bytes.iter().map(|b| Term::small(*b as i64).unwrap()))?,
                None => Term::NIL,
            };
            for byte in header.iter().rev() {
                list = TermBuilder::new(heap).cons(Term::small(*byte as i64).unwrap(), list)?;
            }
            if let Some(eol) = line {
                list = TermBuilder::new(heap).tuple(&[
                    Term::atom(if eol {
                        arinsal_term::atoms::EOL
                    } else {
                        arinsal_term::atoms::NOEOL
                    }),
                    list,
                ])?;
            }
            let data =
                TermBuilder::new(heap).tuple(&[Term::atom(arinsal_term::atoms::DATA), list])?;
            TermBuilder::new(heap).tuple(&[port_term, data])
        };
        if let Ok(message) = build(&mut heap) {
            trace_port_send(
                &handle.scheduler,
                handle.trace_scope(),
                port.id(),
                owner,
                message,
            );
            publish(&handle.scheduler, owner, port_term, message);
        }
    }

    fn deliver_eof(&self, port: &arinsal_drv::DriverPort) {
        if let Some(handle) = self.handle(port.id()) {
            event_message(
                &handle.scheduler,
                handle.owner_pid(),
                port.id(),
                handle.trace_scope(),
                Term::atom(arinsal_term::atoms::EOF),
            );
        }
    }

    fn exit(&self, port: &arinsal_drv::DriverPort, reason: arinsal_drv::ExitReason) {
        let runtime = self.runtime;
        let reason = match reason {
            arinsal_drv::ExitReason::Normal => Term::atom(arinsal_term::atoms::NORMAL),
            arinsal_drv::ExitReason::Code(code) => Term::small(i64::from(code))
                .unwrap_or_else(|| Term::atom(arinsal_term::atoms::NORMAL)),
            arinsal_drv::ExitReason::Atom(name) => atom_dyn(&name),
        };
        driver_port_exit(runtime, port.id(), reason);
    }

    fn unlink_connected(&self, port: &arinsal_drv::DriverPort) {
        if let Some(handle) = self.handle(port.id()) {
            let owner = handle.owner_pid();
            // Port of erts/emulator/beam/io.c:2889 (unlink_proc), OTP-29.1.1: the unlink
            // signal goes only where the port still has a link; a process that unlinked
            // already may have linked the port again since.
            if handle.links.lock().remove(owner.data()).is_some() {
                let _ = handle.scheduler.signal(
                    owner,
                    owner,
                    arinsal_sched::Signal::PortUnlink(handle.id),
                );
            }
        }
    }

    // Port of erts/emulator/beam/utils.c (erts_send_error_to_logger_nogl), OTP-29.1.1.
    fn log_error(&self, text: &str) {
        crate::utils::send_error_to_logger_nogl(self.runtime, None, text);
    }

    fn ddll_reference(&self, port: &arinsal_drv::DriverPort) {
        crate::ddll::reference_referenced(port.driver());
    }

    fn ddll_dereference(&self, port: &arinsal_drv::DriverPort) {
        if let Ok(scheduler) = self.runtime.scheduler() {
            crate::ddll::dereference_referenced(scheduler, port.driver());
        }
    }

    // Port of erts/emulator/beam/io.c:3496 (deliver_vec_message), OTP-29.1.1.
    fn deliver_vec(
        &self,
        port: &arinsal_drv::DriverPort,
        header: &[u8],
        segments: &[Vec<u8>],
        binary: bool,
    ) {
        let Some(handle) = self.handle(port.id()) else {
            return;
        };
        let Some(port_term) = Term::port(port.id()) else {
            return;
        };
        let total: usize = segments.iter().map(Vec::len).sum();
        handle.add_bytes_in(header.len() + total);
        let words = if binary {
            total / 4 + segments.len() * 12
        } else {
            total * 2
        } + header.len() * 2
            + 32;
        let mut heap = ProcessHeap::with_words(words);
        let build = |heap: &mut ProcessHeap| -> Result<Term, arinsal_term::TermError> {
            let mut list = Term::NIL;
            if binary {
                // erts conses every binary but the last onto it, so the tail of the
                // list is the last binary itself and a single binary is not a list.
                for (at, segment) in segments.iter().enumerate().rev() {
                    let bin = TermBuilder::new(heap).binary(segment)?;
                    list = if at + 1 == segments.len() {
                        bin
                    } else {
                        TermBuilder::new(heap).cons(bin, list)?
                    };
                }
            } else {
                for byte in segments.iter().flatten().rev() {
                    list = TermBuilder::new(heap)
                        .cons(Term::small(i64::from(*byte)).unwrap(), list)?;
                }
            }
            for byte in header.iter().rev() {
                list = TermBuilder::new(heap).cons(Term::small(i64::from(*byte)).unwrap(), list)?;
            }
            let data =
                TermBuilder::new(heap).tuple(&[Term::atom(arinsal_term::atoms::DATA), list])?;
            TermBuilder::new(heap).tuple(&[port_term, data])
        };
        if let Ok(message) = build(&mut heap) {
            let owner = handle.owner_pid();
            trace_port_send(
                &handle.scheduler,
                handle.trace_scope(),
                port.id(),
                owner,
                message,
            );
            publish(&handle.scheduler, owner, port_term, message);
        }
    }

    // Port of erts/emulator/beam/io.c:5658 (driver_deliver_term, message queueing), OTP-29.1.1.
    fn deliver_term(
        &self,
        port: &arinsal_drv::DriverPort,
        to: Option<u64>,
        term: &OwnedTerm,
        trace: bool,
    ) -> bool {
        let Some(handle) = self.handle(port.id()) else {
            return false;
        };
        let target = to.map_or_else(|| handle.owner_pid(), Pid::from_data);
        let mut heap = VecHeap::new();
        let Ok(built) = from_owned(term, &mut heap) else {
            return false;
        };
        let exists = handle.scheduler.lookup(target);
        if trace && let Some(receiver) = target.to_term() {
            crate::trace::emit_port_event_scoped(
                handle.trace_scope(),
                &handle.scheduler,
                port.id(),
                crate::trace::SEND,
                if exists {
                    "send"
                } else {
                    "send_to_non_existing_process"
                },
                &[built, receiver],
            );
        }
        if !exists {
            return false;
        }
        let Ok(message) = Message::copy_from(built) else {
            return false;
        };
        handle.scheduler.send(target, target, message).is_ok()
    }

    fn trace_timeout(&self, port: &arinsal_drv::DriverPort) {
        let runtime = self.runtime;
        // Port of erts/emulator/beam/erl_port_task.c:1770, OTP-29.1.1.
        crate::trace::emit_port_event(
            runtime,
            port.id(),
            crate::trace::RECEIVE,
            "receive",
            &[Term::atom(arinsal_term::atoms::TIMEOUT)],
        );
    }

    fn connected(&self, port: &arinsal_drv::DriverPort) -> u64 {
        self.handle(port.id())
            .map_or(0, |handle| handle.owner_pid().data())
    }

    // Port of erts/emulator/beam/io.c:5203 (set_busy_port), OTP-29.1.1.
    fn set_busy(&self, port: &arinsal_drv::DriverPort, on: bool) {
        let Some(handle) = self.handle(port.id()) else {
            return;
        };
        handle.state.lock().busy_port = on;
    }

    // Port of erts/emulator/beam/erl_port_task.c:107 (profile_runnable_port), OTP-29.1.1.
    fn profile_runnable_port(&self, port: &arinsal_drv::DriverPort, active: bool) {
        if !crate::natives::misc::profile_ports_enabled() {
            return;
        }
        let Some(_handle) = self.handle(port.id()) else {
            return;
        };
        crate::natives::misc::profile_port_event(port.id(), active);
    }

    // Port of erts/emulator/beam/erl_process.c:9413 (erts_resume_processes), OTP-29.1.1.
    fn schedule_async_ready(&self, sched_id: usize, ready: Box<dyn FnOnce() + Send>) {
        match self.runtime.scheduler() {
            Ok(scheduler) => scheduler.request_aux_work(sched_id, ready),
            // Without schedulers the job is completed here so its data is released.
            _ => ready(),
        }
    }

    // Port of erts/emulator/beam/erl_hl_timer.c:3031 (erts_set_port_timer), OTP-29.1.1.
    fn start_port_timer(&self, ms: u64, expired: Box<dyn FnOnce() + Send>) -> Option<u64> {
        let runtime = self.runtime;
        runtime
            .scheduler()
            .ok()?
            .start_port_timer(ms, expired)
            .ok()
            .map(arinsal_sched::TimerRef::to_bits)
    }

    // Port of erts/emulator/beam/erl_hl_timer.c:3063 (erts_cancel_port_timer), OTP-29.1.1.
    fn cancel_port_timer(&self, handle: u64) {
        if let Ok(scheduler) = self.runtime.scheduler() {
            scheduler.cancel_port_timer(arinsal_sched::TimerRef::from_bits(handle));
        }
    }

    fn enqueue_port(&self, port: arinsal_drv::PortRef) {
        let runtime = self.runtime;
        if let Ok(scheduler) = runtime.scheduler() {
            scheduler.enqueue_port(port.into_run());
        }
    }

    fn resume_processes(&self, _port: &arinsal_drv::DriverPort, pids: Vec<u64>) {
        let runtime = self.runtime;
        let Ok(scheduler) = runtime.scheduler() else {
            return;
        };
        for pid in pids {
            let pid = Pid::from_data(pid);
            if runtime.resume_internal(pid) {
                let _ = scheduler.wake(pid);
            }
        }
    }

    // Port of erts/emulator/beam/io.c:7006 (do_driver_monitor_process), OTP-29.1.1.
    fn monitor_process(&self, port: &arinsal_drv::DriverPort, pid: u64, monitor: u64) -> bool {
        let Some(handle) = self.handle(port.id()) else {
            return false;
        };
        let target = Pid::from_data(pid);
        if !handle.scheduler.lookup(target) {
            return false;
        }
        // erts_monitor_create(ERTS_MON_TYPE_PORT): the port keeps the origin half, the target
        // process gets the other one in a monitor signal.
        let (origin, target_half) = crate::proc_create::create_monitor(
            monitor,
            port.id(),
            pid,
            crate::proc_create::MonitorInfo::default(),
            crate::proc_create::OriginMonitor::PortOrigin,
        );
        handle.monitors.lock().insert(origin);
        let owner = handle.owner_pid();
        let sent = handle.scheduler.signal(
            owner,
            target,
            arinsal_sched::Signal::Monitor {
                reference: monitor,
                shared: target_half.into_shared(),
            },
        );
        if sent.is_err() {
            handle.monitors.lock().remove(monitor);
            return false;
        }
        true
    }

    fn demonitor_process(&self, port: &arinsal_drv::DriverPort, monitor: u64) {
        if let Some(handle) = self.handle(port.id()) {
            // erts_proc_sig_send_demonitor: the origin half goes to the target, which drops
            // its half.
            if let Some(origin) = handle.monitors.lock().remove(monitor) {
                let pid = Pid::from_data(origin.view().other());
                let _ = handle.scheduler.signal(
                    handle.owner_pid(),
                    pid,
                    arinsal_sched::Signal::DemonitorOrigin(origin.into_shared()),
                );
            }
        }
    }

    // Port of erts/emulator/beam/io.c:7318 (driver_lock_driver), OTP-29.1.1.
    fn lock_driver(&self, port: &arinsal_drv::DriverPort) -> bool {
        self.handle(port.id())
            .is_some_and(|handle| crate::ddll::lock_driver(&handle.scheduler, port.driver()))
    }

    // Port of erts/emulator/beam/io.c:2912 (init_ack_send_reply), OTP-29.1.1.
    fn init_ack(&self, port: &arinsal_drv::DriverPort, reply: arinsal_drv::InitAck) {
        let Some(handle) = self.handle(port.id()) else {
            return;
        };
        let result = match reply {
            arinsal_drv::InitAck::Opened => Ok(()),
            arinsal_drv::InitAck::Failed(error) => Err(atom_dyn(&match error {
                arinsal_drv::StartError::General => "einval".to_owned(),
                arinsal_drv::StartError::Errno(errno) => arinsal_drv::errno_id(errno),
                arinsal_drv::StartError::Badarg => "badarg".to_owned(),
            })),
        };
        send_open_reply(&handle, result);
    }

    // Port of erts/emulator/beam/io.c:781 (driver_create_port), OTP-29.1.1.
    fn create_port(
        &self,
        creator: &arinsal_drv::DriverPort,
        owner: u64,
        name: &str,
        drv_data: usize,
    ) -> Option<arinsal_drv::PortRef> {
        let runtime = self.runtime;
        let scheduler = runtime.scheduler().ok()?;
        let owner = Pid::from_data(owner);
        if !scheduler.lookup(owner) {
            return None;
        }
        let reservation = reserve_port_id(runtime).ok()?;
        let port_id = reservation.id();
        let handle = make_driver_handle(
            port_id,
            owner,
            name.to_owned(),
            false,
            Arc::clone(scheduler),
            runtime,
            Some((Arc::clone(creator.driver()), runtime)),
        )
        .ok()?;
        let driver = Arc::clone(creator.driver());
        let drv_port = handle.drv_port().expect("driver state embedded");
        drv_port.init_run_queue(scheduler.current_run_queue());
        drv_port.adopt(drv_data);
        crate::ddll::port_opened_for(&driver, &drv_port);
        runtime.ports.insert(port_id, handle);
        // The owner holds its half of the link to the new port (`erts_port_link` of the
        // creator's owner): inserted when the signal is handled.
        let _ = scheduler.signal(owner, owner, arinsal_sched::Signal::PortLink(port_id));
        crate::trace::port_opened(runtime, port_id);
        reservation.commit();
        Some(drv_port)
    }
}

/// Answer the `open_port` waiting for `erl_drv_init_ack`: `{Ref, Port}` on success, `{Ref, Errno}`
/// on failure (the opener is no longer linked to a port that failed to open).
// Port of erts/emulator/beam/io.c:2912 (init_ack_send_reply), OTP-29.1.1.
fn send_open_reply(handle: &PortHandle, result: Result<(), Term>) {
    let Some((reference, opener)) = handle.peek_cold(|cold| cold.async_open.take()).flatten()
    else {
        return;
    };
    let Some(port_term) = Term::port(handle.id) else {
        return;
    };
    let result = match result {
        Ok(()) => port_term,
        Err(errno) => {
            // unlink_proc (io.c:2889): only a link the port still has.
            if handle.links.lock().remove(opener.data()).is_some() {
                let _ = handle.scheduler.signal(
                    opener,
                    opener,
                    arinsal_sched::Signal::PortUnlink(handle.id),
                );
            }
            errno
        }
    };
    let mut heap = ProcessHeap::with_words(16);
    let Ok(reference) =
        TermBuilder::new(&mut heap).local_ref(arinsal_sched::unique::ordinary_ref_words(reference))
    else {
        return;
    };
    if let Ok(message) = TermBuilder::new(&mut heap).tuple(&[reference, result]) {
        publish(&handle.scheduler, opener, port_term, message);
    }
}

/// The shared descriptor table as the `driver_select` state of each descriptor.
struct VmFdTable;

impl arinsal_drv::FdTable for VmFdTable {
    fn with_slot(&self, fd: i32, f: &mut dyn FnMut(&mut arinsal_drv::SelSlot)) -> i32 {
        crate::check_io::with_sel(fd, f)
    }
}

/// Process-wide services for the driver API (`arinsal_drv::SystemHooks`).
struct VmHooks {
    offset: OnceLock<i128>,
}

impl arinsal_drv::SystemHooks for VmHooks {
    fn monotonic_nanos(&self) -> i128 {
        arinsal_sched::erl_time_sup::monotonic_time_nanos()
    }

    fn time_offset_nanos(&self) -> i128 {
        *self.offset.get_or_init(|| {
            let wall = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as i128;
            wall - arinsal_sched::erl_time_sup::monotonic_time_nanos()
        })
    }

    fn getenv(&self, key: &[u8]) -> Option<Vec<u8>> {
        crate::erl_osenv::get(key)
    }

    fn putenv(&self, key: &[u8], value: &[u8]) {
        crate::erl_osenv::put(key, value);
    }

    fn async_threads(&self) -> usize {
        // Port of erts/emulator/beam/erl_bif_info.c:3032-3037, OTP-29.1.1.
        arinsal_args::active_emulator_flags()
            .async_threads
            .unwrap_or(1)
            .max(1) as usize
    }

    fn scheduler_threads(&self) -> usize {
        crate::natives::sys::schedulers_total()
    }

    fn add_driver(&self, driver: Arc<arinsal_drv::Driver>) {
        crate::ddll::add_linked(driver);
    }

    fn remove_driver(&self, entry: usize) -> i32 {
        crate::ddll::remove_linked(entry)
    }
}

/// Install the shared poller as the `driver_select`/`enif_select` poll set.
pub(crate) fn install_poll_backend() {
    static INSTALLED: std::sync::Once = std::sync::Once::new();
    INSTALLED.call_once(|| {
        arinsal_drv::set_fd_table(Arc::new(VmFdTable));
        crate::check_io::install_scheduler_polling();
    });
}

/// `erts_send_error_to_logger_nogl` for `runtime`.
pub(crate) fn log_error_for(runtime: &'static crate::process::Runtime, text: &str) {
    arinsal_drv::PortHost::log_error(
        &DrvHost {
            runtime,
            own: Weak::new(),
        },
        text,
    );
}

/// Install the driver API hooks once, before the first driver code runs.
pub(crate) fn install_hooks() {
    static INSTALLED: std::sync::Once = std::sync::Once::new();
    INSTALLED.call_once(|| {
        arinsal_drv::set_system_hooks(Arc::new(VmHooks {
            offset: OnceLock::new(),
        }));
    });
}

/// A driver that fails (`driver_failure*`, `driver_exit`): the port exits with `reason`
/// from itself.
// Port of erts/emulator/beam/io.c (driver_failure_term → erts_deliver_port_exit(prt,
// prt->common.id, reason, 0, 0)), OTP-29.1.1.
pub(crate) fn driver_port_exit(runtime: &crate::process::Runtime, id: u64, reason: Term) {
    let Some(owner) = runtime.ports.get(id).map(|handle| handle.owner_pid()) else {
        return;
    };
    erts_deliver_port_exit(runtime, id, owner, reason, None);
}

fn erl_launcher(name: &str, executable: bool) -> bool {
    let program = if executable {
        name
    } else {
        let command = name.trim_start();
        command
            .strip_prefix('"')
            .unwrap_or(command)
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .strip_suffix('"')
            .unwrap_or_else(|| {
                command
                    .strip_prefix('"')
                    .unwrap_or(command)
                    .split_whitespace()
                    .next()
                    .unwrap_or_default()
            })
    };
    std::path::Path::new(program)
        .file_name()
        .is_some_and(|file| file == "erl")
}

/// Failure while creating the accepted TCP port.
pub(crate) enum InetPortAllocError {
    /// The runtime port table has no free identifiers.
    SystemLimit,
    /// Creating the scheduler or OS port resources failed.
    NoMemory,
}

/// Allocate a connected `tcp_inet` port for an accepted socket.
///
/// Port of erts/emulator/beam/io.c:781 (driver_create_port) as `tcp_inet_copy` uses it:
/// a port of the creator's driver owned by (and linked to) `owner`, on the run queue of
/// the creating scheduler. `attach` installs the driver state before the port is visible.
pub(crate) fn alloc_inet_port(
    runtime: &'static crate::process::Runtime,
    owner: Pid,
    name: String,
    driver: Arc<arinsal_drv::Driver>,
    attach: impl FnOnce(&Arc<PortHandle>, &arinsal_drv::DriverPort),
) -> Result<(u64, Arc<PortHandle>, arinsal_drv::PortRef), InetPortAllocError> {
    let scheduler = runtime
        .scheduler()
        .map_err(|_| InetPortAllocError::NoMemory)?;
    let reservation = reserve_port_id(runtime).map_err(|_| InetPortAllocError::SystemLimit)?;
    let port_id = reservation.id();
    let handle = make_driver_handle(
        port_id,
        owner,
        name,
        false,
        Arc::clone(scheduler),
        runtime,
        Some((driver, runtime)),
    )
    .map_err(|_| InetPortAllocError::NoMemory)?;
    let drv_port = handle.drv_port().expect("driver state embedded");
    drv_port.init_run_queue(scheduler.current_run_queue());
    attach(&handle, &drv_port);
    runtime.ports.insert(port_id, Arc::clone(&handle));
    let _ = scheduler.signal(owner, owner, arinsal_sched::Signal::PortLink(port_id));
    crate::trace::port_opened(runtime, port_id);
    reservation.commit();
    Ok((port_id, handle, drv_port))
}

fn notify_links_monitors(
    handle: &PortHandle,
    id: u64,
    scheduler: &Scheduler<Process>,
    from: Pid,
    skip_owner: bool,
    reason: Term,
) {
    // Port of erts/emulator/beam/io.c:3815 (`monitor_port_exit`), OTP-29.1.1.
    let Some(port) = Term::port(id) else {
        return;
    };
    for link in handle.links.lock().iter() {
        let linked = Pid::from_data(link.other());
        if skip_owner && linked == from {
            continue;
        }
        if let (Ok(port_message), Ok(reason_message)) =
            (Message::copy_from(port), Message::copy_from(reason))
        {
            let _ = scheduler.signal(
                from,
                linked,
                arinsal_sched::Signal::PortExit(Box::new(arinsal_sched::PortExitSignal {
                    port: port_message,
                    reason: reason_message,
                })),
            );
        }
    }
    // Port of io.c (monitor_port_exit): origin halves are demonitor signals; target halves
    // are DOWNs. The tree's drain follows erts' postorder foreach-delete traversal.
    let mut origins = handle.monitors.lock();
    for origin in origins.drain() {
        let target = Pid::from_data(origin.view().other());
        let _ = scheduler.signal(
            from,
            target,
            arinsal_sched::Signal::DemonitorOrigin(origin.into_shared()),
        );
    }
    drop(origins);

    // Keep the target list locked while queuing DOWNs, as erts holds the driver monitor lock.
    let mut guard = handle.lt_monitors.lock();
    for target in guard.drain() {
        let monitor = target.view();
        let reference = monitor.reference();
        let pid = Pid::from_data(monitor.other());
        let name = monitor.info().port_name();
        let mut heap = ProcessHeap::with_words(32);
        if reason.is_pointer() {
            let Ok(reference_term) = TermBuilder::new(&mut heap)
                .local_ref(arinsal_sched::unique::ordinary_ref_words(reference))
            else {
                continue;
            };
            let Ok(object) = crate::signals::port_monitor_object(&mut heap, Some(id), name) else {
                continue;
            };
            // The monitor's `{tag, Tag}` option replaces 'DOWN', as for process monitors
            // (erl_proc_sig_queue.c:2836-2900 builds the DOWN from the monitor data).
            let tag = match monitor.info().tag() {
                Some(tag) => match copy_term(tag, &mut heap) {
                    Ok(tag) => tag,
                    Err(_) => continue,
                },
                None => Term::atom(arinsal_term::atoms::DOWN),
            };
            let Ok(down) = TermBuilder::new(&mut heap).tuple(&[
                tag,
                reference_term,
                Term::atom(arinsal_term::atoms::PORT),
                object,
                reason,
            ]) else {
                continue;
            };
            if let Ok(message) = Message::copy_from(down) {
                // Port of erl_proc_sig_queue.c (erts_proc_sig_send_monitor_down), OTP-29.1.1.
                let _ = scheduler.signal(
                    from,
                    pid,
                    arinsal_sched::Signal::MonitorDownMsg {
                        reference,
                        message: Box::new(message),
                    },
                );
            }
        } else if let Ok(reason) = Message::copy_from(reason) {
            // The reference and monitor type stay in the signal for immediate exit reasons.
            let _ = scheduler.signal(
                from,
                pid,
                arinsal_sched::Signal::MonitorDown {
                    reference,
                    reason: Box::new(reason),
                },
            );
        }
    }
}

fn signal_port_exit(handle: &PortHandle, id: u64, reason: Term) {
    let Some(port) = Term::port(id) else {
        return;
    };
    let owner = handle.owner.get();
    if let (Ok(port), Ok(reason)) = (Message::copy_from(port), Message::copy_from(reason)) {
        let _ = handle.scheduler.signal(
            owner,
            owner,
            arinsal_sched::Signal::PortExit(Box::new(arinsal_sched::PortExitSignal {
                port,
                reason,
            })),
        );
    }
}

fn signal_badsig(handle: &PortHandle, id: u64) {
    signal_port_exit(handle, id, Term::atom(arinsal_term::atoms::BADSIG));
}

/// Mutual exclusion between descriptor creation and `Command::spawn`.
///
/// `pipe`/`dup`/`socket`/`accept` then `FD_CLOEXEC` is not atomic. A port child
/// spawned in that window inherits the descriptor. `erl_child_setup` never has
/// this window: it closes every fd above 3 at start and sets CLOEXEC before any
/// child exists (erl_child_setup.c:466-470, OTP-29.1.1).
pub(crate) fn cloexec_publish<R>(body: impl FnOnce() -> R) -> R {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _guard = LOCK.lock().unwrap_or_else(|error| error.into_inner());
    body()
}

pub(crate) fn duplicate_fd(fd: RawFd) -> std::io::Result<OwnedFd> {
    cloexec_publish(|| {
        unsafe extern "C" {
            fn dup(fd: i32) -> i32;
        }
        // SAFETY: dup returns a fresh descriptor; setting CLOEXEC before the lock is
        // released prevents a concurrently spawned port child from inheriting it.
        let copy = unsafe {
            let copy = dup(fd);
            if copy >= 0 && libc::fcntl(copy, libc::F_SETFD, libc::FD_CLOEXEC) < 0 {
                let error = std::io::Error::last_os_error();
                libc::close(copy);
                return Err(error);
            }
            copy
        };
        if copy < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: copy is a fresh descriptor owned by this OwnedFd.
        Ok(unsafe { OwnedFd::from_raw_fd(copy) })
    })
}

impl arinsal_sched::RunPort for PortHandle {
    fn run_queue(&self) -> &arinsal_sched::PortRunQueue {
        arinsal_sched::RunPort::run_queue(
            self.driver
                .as_ref()
                .expect("only driver ports are run-queued"),
        )
    }

    fn execute(&self, scheduler_id: usize) -> arinsal_sched::PortExecution {
        arinsal_sched::RunPort::execute(
            self.driver
                .as_ref()
                .expect("only driver ports are run-queued"),
            scheduler_id,
        )
    }
}

impl arinsal_drv::PortOwner for PortHandle {
    fn driver_port(&self) -> &arinsal_drv::DriverPort {
        self.driver.as_ref().expect("a PortOwner has driver state")
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// Port handle of a loaded driver, with the driver state embedded (the one `Port` struct of
/// erl_port.h): no wake pipe, so a full port table does not need two descriptors per port.
#[allow(clippy::too_many_arguments)]
fn make_driver_handle(
    id: u64,
    owner: Pid,
    name: String,
    parallelism: bool,
    scheduler: Arc<Scheduler<Process>>,
    runtime: &'static crate::process::Runtime,
    driver: Option<(Arc<arinsal_drv::Driver>, &'static crate::process::Runtime)>,
) -> Result<Arc<PortHandle>, VmError> {
    let handle = Arc::new_cyclic(|me: &std::sync::Weak<PortHandle>| PortHandle {
        id,
        word: Term::port(id).map_or(0, Term::tagged_word),
        started_interval: AtomicU64::new(0),
        owner: OwnerCell::new(owner),
        links: Mutex::new({
            let mut links = crate::proc_create::LinkTree::default();
            links.insert(crate::proc_create::port_peer_link(owner));
            links
        }),
        monitors: Mutex::new(crate::proc_create::MonitorTree::default()),
        lt_monitors: Mutex::new(crate::proc_create::TargetMonitorList::default()),
        name: name.into_boxed_str(),
        parallelism,
        state: Mutex::new(PortState {
            bytes_in: 0,
            bytes_out: 0,
            busy_port: false,
            busy_msgq: false,
            exit_complete: false,
            suspended: Suspended::default(),
            closed: false,
            broken: false,
        }),
        scheduler,
        runtime,
        data: raw::PortDataCell::new(PORT_DATA_UNDEFINED),
        driver: driver.map(|(driver, runtime)| {
            let owner_ref: std::sync::Weak<dyn arinsal_drv::PortOwner> = me.clone();
            arinsal_drv::DriverPort::new(
                driver,
                id,
                Box::new(DrvHost {
                    runtime,
                    own: me.clone(),
                }),
                arinsal_drv::WeakPortRef::new(owner_ref),
            )
        }),
        cold: Mutex::new(None),
        reg_closing: AtomicBool::new(false),
        drv_data: Mutex::new(None),
    });
    Ok(handle)
}

fn start_fd(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &RunCtx<'_, crate::Process>,
    input_fd: RawFd,
    output_fd: RawFd,
    opts: &PortOptions,
) -> Result<Term, VmError> {
    let runtime = process.runtime.ok_or_else(badarg)?;
    // Port of erts/emulator/sys/unix/sys_drivers.c:822 (fd_start: descriptors beyond the
    // poll set fail with ERL_DRV_ERROR_GENERAL).
    let max_files = crate::erl_poll::erts_poll_max_fds();
    let do_read = opts.rw & 1 != 0;
    let do_write = opts.rw & 2 != 0;
    if (do_read && input_fd as usize >= max_files) || (do_write && output_fd as usize >= max_files)
    {
        return Ok(Term::atom(arinsal_term::atoms::EINVAL));
    }
    let reservation = reserve_port_id(runtime)?;
    let limits = opts.limits;
    let start = crate::spawn_drv::FdStart {
        ifd: input_fd,
        ofd: output_fd,
        packet_bytes: opts
            .framing
            .and_then(|(mode, n)| (mode == 2).then_some(n))
            .unwrap_or(0),
        do_read,
        do_write,
        high_watermark: if limits.port_enabled {
            limits.port_high
        } else {
            usize::MAX
        },
        low_watermark: limits.port_low,
    };
    let _ = vm;
    open_driver_port(
        process,
        ctx,
        reservation,
        None,
        crate::spawn_drv::fd_driver(),
        format!("{input_fd}/{output_fd}"),
        DriverIoFlags {
            msgq: limits
                .msgq_enabled
                .then_some((limits.msgq_low, limits.msgq_high)),
            binary: opts.binary,
            eof: opts.eof,
            line: opts.framing.and_then(|(mode, n)| (mode == 1).then_some(n)),
            parallelism: opts.parallelism,
        },
        Some(crate::spawn_drv::SysStart::Fd(start)),
    )
}

fn wake_suspended(scheduler: &Scheduler<Process>, pids: Vec<Pid>) {
    for pid in pids {
        // A busy-port sender owns one internal suspend until the port falls below its low
        // watermark. The port task releases it before making the retried send runnable.
        let _ = scheduler.signal(pid, pid, arinsal_sched::Signal::SuspendResume);
        // Wakes a waiting process without entering its mailbox.
        let _ = scheduler.wake(pid);
    }
}

/// Port of erts/emulator/beam/io.c:1203 (erts_schedule_proc2port_signal, the caller side of a
/// reply reference), OTP-29.1.1: called before the port signal is scheduled, so the reply cannot
/// be queued before the save pointer moves. The receive that waits for the reply then starts at
/// the end of the message queue.
// Port of erts/emulator/beam/erl_proc_sig_queue.h:2397 (erts_msgq_set_save_end), OTP-29.1.1.
pub(crate) fn set_save_end(process: &mut Process, ctx: &mut RunCtx<'_, crate::Process>) {
    // erts_proc_sig_fetch(c_p). Fetching links queued messages and cannot fail: `push_message`
    // only appends, so the Result is an internal invariant.
    process
        .fetch_signals(ctx)
        .expect("fetching signals links queued messages and cannot fail");
    process.msgq_set_save_end();
}

/// Port of erts/emulator/beam/erl_process.c:9369 (erts_suspend) with a busy port: `false`
/// when the port stopped being busy, and the operation is to be retried at once.
fn suspend_on_busy(
    process: &mut Process,
    handle: &PortHandle,
    drv: &arinsal_drv::DriverPort,
    pid: Pid,
) -> bool {
    let Some(runtime) = process.runtime else {
        return false;
    };
    // Suspended before it is queued on the port, so a resume racing with this cannot be lost.
    if process.self_pid == Some(pid) {
        crate::suspend::suspend_self(process);
    }
    if !drv.save_suspend_process(packed_pid(pid)) {
        runtime.resume_internal(pid);
        return false;
    }
    crate::natives::erts_debug::notify_busy_port(process, pid, handle.id);
    true
}

fn exit_status_message(
    scheduler: &Scheduler<Process>,
    owner: Pid,
    id: u64,
    trace_scope: usize,
    code: i64,
) {
    let mut heap = ProcessHeap::with_words(16);
    if let Ok(event) = TermBuilder::new(&mut heap).tuple(&[
        Term::atom(arinsal_term::atoms::EXIT_STATUS),
        Term::small(code).unwrap(),
    ]) {
        event_message(scheduler, owner, id, trace_scope, event);
    }
}

/// Port of erts/emulator/beam/io.c:5181 (driver_report_exit): `{Port, {exit_status, Status}}`
/// to the connected process.
pub(crate) fn driver_report_exit(handle: &PortHandle, id: u64, status: i64) {
    exit_status_message(
        &handle.scheduler,
        handle.owner_pid(),
        id,
        handle.trace_scope(),
        status,
    );
}

fn lookup_port(process: &Process, term: Term) -> Result<Arc<PortHandle>, VmError> {
    if term.is_port()
        && let Some(runtime) = process.runtime.as_ref()
    {
        return runtime
            .ports
            .get_word(term.tagged_word(), process.on_managed)
            .ok_or_else(badarg);
    }
    let id = port_id(process, term).ok_or_else(badarg)?;
    process
        .runtime
        .as_ref()
        .and_then(|runtime| runtime.ports.get_from(id, process.on_managed))
        .ok_or_else(badarg)
}

/// Resolve a port identifier or its registered name as `erts_whereis_name_to_id` does.
fn port_id(process: &Process, term: Term) -> Option<u64> {
    if let Some(id) = term.as_port() {
        return Some(id);
    }
    let name = term.as_atom()?;
    process.runtime.as_ref()?.reg.whereis_port(name)
}

pub(crate) fn is_live(process: &Process, id: u64) -> bool {
    process
        .runtime
        .as_ref()
        .is_some_and(|runtime| runtime_port_live(runtime, id))
}

/// Whether local port `id` of `runtime` exists and has not finished exiting.
pub(crate) fn runtime_port_live(runtime: &crate::process::Runtime, id: u64) -> bool {
    let handle = runtime.ports.get(id);
    handle.is_some_and(|handle| !handle.state.lock().exit_complete)
}

/// `prt->data` (erl_port.h): an immediate term is stored as its own word, while a zero-tag word
/// is the pointer to the heap block of a non-immediate term (`ErtsPortDataHeap`). Zero marks a
/// port whose data was cleared during termination.
const PORT_DATA_UNDEFINED: u64 = Term::atom(arinsal_term::atoms::UNDEFINED).tagged_word();

/// The word `port_set_data_2` stores for an immediate `data`.
fn port_data_word(term: Term) -> Option<u64> {
    term.is_immed().then(|| term.tagged_word())
}

/// The term of `port_set_data/2` in a heap block of its own (`ErtsPortDataHeap`: the term and
/// the heap fragment it was copied into, with the off-heap list).
// Port of erts/emulator/beam/erl_port.h (ErtsPortDataHeap), OTP-29.1.1.
#[repr(C)]
struct PortDataBlock {
    /// The number of trailing words holding the copied term, as `ErtsPortDataHeap::hsize`.
    hsize: usize,
    term: Term,
    /// Off-heap links for objects in the trailing words; the words follow this header inline.
    _owners: arinsal_term::message::InlineHeapOwners,
}

/// Errors of a port BIF as the exception a light BIF raises; any other failure declines.
fn light_result(result: Result<Term, VmError>) -> Option<Result<Term, crate::exceptions::Trap>> {
    match result {
        Ok(term) => Some(Ok(term)),
        Err(VmError::Trap(trap)) => Some(Err(trap)),
        Err(_) => None,
    }
}

/// `erts_internal:port_info/1,2` called from the generated code with `c_p` only.
// Port of erts/emulator/beam/erl_bif_port.c (erts_internal_port_info_1/2), OTP-29.1.1.
pub(crate) fn port_info_light(
    process: &mut Process,
    args: &[Term],
) -> Option<Result<Term, crate::exceptions::Trap>> {
    match args {
        [port] => light_result(port_info(process, *port, None)),
        [port, item] => light_result(port_info(process, *port, Some(*item))),
        _ => None,
    }
}

/// `erts_internal:port_connect/2` called from the generated code with `c_p` only.
// Port of erts/emulator/beam/erl_bif_port.c (erts_internal_port_connect_2), OTP-29.1.1.
pub(crate) fn port_connect_light(
    process: &mut Process,
    args: &[Term],
) -> Option<Result<Term, crate::exceptions::Trap>> {
    let [port, pid] = args else {
        return None;
    };
    light_result(connect(process, *port, *pid, None))
}

/// `erts_internal:port_close/1` called from the generated code with `c_p` only: the close
/// signal executes at once when the port is free, else it is scheduled and the caller gets the
/// reference to wait for.
// Port of erts/emulator/beam/erl_bif_port.c:405 (erts_internal_port_close_1), OTP-29.1.1.
pub(crate) fn port_close_light(
    process: &mut Process,
    args: &[Term],
) -> Option<Result<Term, crate::exceptions::Trap>> {
    let [port] = args else {
        return None;
    };
    if crate::trace::active() {
        return None;
    }
    let caller = process.self_pid?;
    light_result(port_close(process, None, caller, *port))
}

/// `erlang:port_get_data/1` for the thin light-BIF call site.
pub(crate) struct PortGetData;

impl crate::natives::ThinProcessBif for PortGetData {
    const ARITY: usize = 1;

    #[inline(always)]
    fn call(process: &mut Process, args: &[Term]) -> Result<Term, Box<crate::exceptions::Trap>> {
        // The data word of a live port holds an atom or a small integer (`inet_db` stores the
        // module atom): one lookup and one load, as `erts_port_data_read` does.
        if args[0].is_port()
            && let Some(runtime) = process.runtime.as_ref()
            && let Some(term) = runtime
                .ports
                .with_word(args[0].tagged_word(), process.on_managed, |handle| {
                    handle.data.load_immediate()
                })
                .flatten()
        {
            return Ok(term);
        }
        port_get_data(process, args[0]).map_err(thin_failure)
    }
}

/// `erlang:port_set_data/2` for the thin light-BIF call site.
pub(crate) struct PortSetData;

impl crate::natives::ThinProcessBif for PortSetData {
    const ARITY: usize = 2;

    #[inline(always)]
    fn call(process: &mut Process, args: &[Term]) -> Result<Term, Box<crate::exceptions::Trap>> {
        port_set_data(process, args[0], args[1]).map_err(thin_failure)
    }
}

/// The exception of a port BIF that cannot decline.
#[cold]
fn thin_failure(error: VmError) -> Box<crate::exceptions::Trap> {
    match error {
        VmError::Trap(trap) => Box::new(trap),
        _ => Box::new(crate::exceptions::Trap::error(Term::atom(
            arinsal_term::atoms::BADARG,
        ))),
    }
}

/// `erlang:port_get_data/1` called from the generated code with `c_p` only.
// Port of erts/emulator/beam/erl_bif_port.c:734 (port_get_data_1), OTP-29.1.1.
pub(crate) fn port_get_data_light(
    process: &mut Process,
    args: &[Term],
) -> Option<Result<Term, crate::exceptions::Trap>> {
    let [port] = args else {
        return None;
    };
    light_result(port_get_data(process, *port))
}

/// `erlang:port_set_data/2` called from the generated code with `c_p` only.
// Port of erts/emulator/beam/erl_bif_port.c:687 (port_set_data_2), OTP-29.1.1.
pub(crate) fn port_set_data_light(
    process: &mut Process,
    args: &[Term],
) -> Option<Result<Term, crate::exceptions::Trap>> {
    let [port, data] = args else {
        return None;
    };
    light_result(port_set_data(process, *port, *data))
}

// Port of erts/emulator/beam/erl_bif_port.c:734 (port_get_data_1), OTP-29.1.1.
fn port_get_data(process: &mut Process, port: Term) -> Result<Term, VmError> {
    let id = port_id(process, port).ok_or_else(badarg)?;
    let runtime = process.runtime.as_ref().ok_or_else(badarg)?;
    let managed = process.on_managed;
    let heap = &mut process.heap;
    runtime
        .ports
        .with_from(id, managed, |handle| {
            let mut heap = arinsal_bifs::ProcessHeapHandle(heap);
            handle.data.copy_term(&mut heap).map_err(|_| badarg())
        })
        .ok_or_else(badarg)?
}

// Port of erts/emulator/beam/erl_bif_port.c:687 (port_set_data_2), OTP-29.1.1.
fn port_set_data(process: &Process, port: Term, data: Term) -> Result<Term, VmError> {
    let handle = lookup_port(process, port)?;
    let new_data = if let Some(word) = port_data_word(data) {
        word
    } else {
        let size = arinsal_term::size_object(data);
        raw::new_data_word(data, size).map_err(|_| badarg())?
    };
    let old_data = handle.data.swap(new_data);
    if old_data == 0 {
        raw::retire_data(handle.data.swap(0), &handle.scheduler);
        return Err(badarg());
    }
    raw::retire_data(old_data, &handle.scheduler);
    Ok(Term::atom(arinsal_term::atoms::TRUE))
}

pub(crate) fn family(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, crate::Process>,
    module: &str,
    function: &str,
    args: &[Term],
) -> Option<Result<Term, VmError>> {
    if module != "erts_internal" && module != "erlang" {
        return None;
    }
    let result = match (function, args) {
        ("open_port", [spec, opts]) if module == "erts_internal" => {
            start(vm, process, ctx, *spec, *opts)
        }
        ("port_command", [port, data, _]) if module == "erts_internal" => {
            port_command(process, ctx, *port, *data, args)
        }
        ("port_close", [port]) if module == "erts_internal" => {
            let caller = ctx.pid();
            port_close(process, Some(ctx), caller, *port)
        }
        ("port_connect", [port, pid]) if module == "erts_internal" => {
            connect(process, *port, *pid, None)
        }
        // Port of erts/emulator/beam/erl_bif_port.c:322 (erts_internal_port_control_3), OTP-29.1.1.
        // Spawn and fd ports have no driver control. The internal BIF returns the
        // atom `badarg`; `erlang:port_control/3` turns that atom into an exception.
        ("port_control", [port, op, data]) if module == "erts_internal" => {
            port_control(process, ctx, *port, *op, *data)
        }
        // Port of erts/emulator/beam/erl_bif_port.c:263 (erts_internal_port_call_3), OTP-29.1.1.
        // Spawn/fd/inet ports here have no driver call path; return the atom `badarg`.
        ("port_call", [port, op, data]) if module == "erts_internal" => {
            port_call(process, ctx.pid(), *port, *op, *data)
        }
        ("port_get_data", [port]) if module == "erlang" => port_get_data(process, *port),
        ("port_set_data", [port, data]) if module == "erlang" => {
            port_set_data(process, *port, *data)
        }
        ("port_info", [port]) if module == "erts_internal" => port_info(process, *port, None),
        ("port_info", [port, item]) if module == "erts_internal" => {
            port_info(process, *port, Some(*item))
        }
        _ => return None,
    };
    Some(result)
}

// Port of erts/emulator/beam/erl_bif_port.c:322 (erts_internal_port_control_3), OTP-29.1.1.
// Non-inet ports still return the atom `badarg`. `tcp_inet` returns a byte list.
fn port_control(
    process: &mut Process,
    ctx: &mut RunCtx<'_, crate::Process>,
    port: Term,
    op: Term,
    data: Term,
) -> Result<Term, VmError> {
    let caller = ctx.pid();
    let Some(id) = port_id(process, port) else {
        return Ok(Term::atom(arinsal_term::atoms::BADARG));
    };
    let Some(handle) = process
        .runtime
        .as_ref()
        .and_then(|runtime| runtime.ports.get(id))
    else {
        return Ok(Term::atom(arinsal_term::atoms::BADARG));
    };
    if let Some(drv_port) = handle.driver.as_ref() {
        return driver_control(process, ctx, caller, drv_port, op, data);
    }
    Ok(Term::atom(arinsal_term::atoms::BADARG))
}

pub(crate) use drv_sig::command_light as port_command_light;
pub(crate) use drv_sig::control_light as port_control_light;

// Port of erts/emulator/beam/erl_bif_port.c:263 (erts_internal_port_call_3), OTP-29.1.1.
fn port_call(
    process: &mut Process,
    caller: Pid,
    port: Term,
    op: Term,
    data: Term,
) -> Result<Term, VmError> {
    let Some(id) = port_id(process, port) else {
        return Ok(Term::atom(arinsal_term::atoms::BADARG));
    };
    let Some(handle) = process
        .runtime
        .as_ref()
        .and_then(|runtime| runtime.ports.get(id))
    else {
        return Ok(Term::atom(arinsal_term::atoms::BADARG));
    };
    let Some(op) = op.as_small().and_then(|n| u32::try_from(n).ok()) else {
        return Ok(Term::atom(arinsal_term::atoms::BADARG));
    };
    if let Some(drv_port) = handle.driver.as_ref() {
        // Port of erts/emulator/beam/io.c:4618 (erts_port_call).
        let Ok(owned) = to_owned(data) else {
            return Ok(Term::atom(arinsal_term::atoms::BADARG));
        };
        let encoded = arinsal_etf::encode(&owned, arinsal_etf::EncodeOptions::default());
        trace_port_receive_indexed(process, caller, id, "call", op, &encoded);
        let Some(reply) = drv_port.call(op, &encoded, packed_pid(caller)) else {
            return Ok(Term::atom(arinsal_term::atoms::BADARG));
        };
        if let Some(port) = Term::port(id) {
            let mut trace_heap = VecHeap::new();
            if let Ok(binary) = TermBuilder::new(&mut trace_heap).binary(&reply)
                && let Ok(call) = TermBuilder::new(&mut trace_heap)
                    .tuple(&[Term::atom(arinsal_term::atoms::CALL), binary])
                && let Ok(message) = TermBuilder::new(&mut trace_heap).tuple(&[port, call])
            {
                trace_port_send(&handle.scheduler, handle.trace_scope(), id, caller, message);
            }
        }
        let Ok((term, _)) = arinsal_etf::decode_prefix(&reply) else {
            return Ok(Term::atom(arinsal_term::atoms::BADARG));
        };
        let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
        let term = from_owned(&term, &mut heap).map_err(|_| badarg())?;
        return TermBuilder::new(&mut heap)
            .tuple(&[Term::atom(arinsal_term::atoms::OK), term])
            .map_err(|_| badarg());
    }
    // No driver currently implements call; match OTP spawn/inet ports on this machine.
    Ok(Term::atom(arinsal_term::atoms::BADARG))
}

const ERL_DRV_FLAG_SOFT_BUSY: i32 = 1 << 1;

/// Port of erts/emulator/beam/erl_io_queue.c:441 (erts_ioq_iolist_to_vec) input walk:
/// pieces in order, `true` for a reference-counted binary (larger than
/// ERL_ONHEAP_BINARY_LIMIT).
fn io_pieces(term: Term, out: &mut Vec<(Vec<u8>, bool)>) -> Option<()> {
    fn walk(term: &OwnedTerm, tail: bool, out: &mut Vec<(Vec<u8>, bool)>) -> Option<()> {
        match term {
            OwnedTerm::Nil => Some(()),
            OwnedTerm::List { elems, tail: rest } => {
                for elem in elems {
                    walk(elem, false, out)?;
                }
                walk(rest, true, out)
            }
            OwnedTerm::Binary(bytes) => {
                let refc = bytes.len() > arinsal_drv::ERL_ONHEAP_BINARY_LIMIT;
                out.push((bytes.clone(), refc));
                Some(())
            }
            OwnedTerm::Int(value) if !tail && (0..=255).contains(value) => {
                match out.last_mut() {
                    Some((bytes, false)) => bytes.push(*value as u8),
                    _ => out.push((vec![*value as u8], false)),
                }
                Some(())
            }
            _ => None,
        }
    }
    if term.as_small().is_some() {
        return None;
    }
    walk(&to_owned(term).ok()?, false, out)
}

// Port of erts/emulator/beam/erl_bif_port.c:322 (erts_internal_port_control_3) and
// io.c:4268 (erts_port_control) for a loaded driver.
fn driver_control(
    process: &mut Process,
    ctx: &mut RunCtx<'_, crate::Process>,
    caller: Pid,
    drv_port: &arinsal_drv::DriverPort,
    op: Term,
    data: Term,
) -> Result<Term, VmError> {
    let Some(opcode) = op.as_small().and_then(|n| u32::try_from(n).ok()) else {
        return Ok(Term::atom(arinsal_term::atoms::BADARG));
    };
    // Port of erts/emulator/beam/io.c:4268 (erts_port_control): the iolist is flattened into one
    // buffer sized by erts_iolist_size.
    let Some(bytes) = control_input(data) else {
        return Ok(Term::atom(arinsal_term::atoms::BADARG));
    };
    drv_sig::control(process, ctx, caller, drv_port, opcode, bytes)
}

/// Next local port id for `open_port`, or `system_limit` when the port table is full.
// Port of erts/emulator/beam/erl_ptab.c (erts_ptab_new_element), OTP-29.1.1.
fn notsup() -> VmError {
    VmError::Trap(crate::exceptions::Trap::error(Term::atom(
        arinsal_term::atoms::NOTSUP,
    )))
}

/// `ERTS_PORT_OP_BUSY` without `nosuspend`, after `erts_suspend(BIF_P, ERTS_PROC_LOCK_MAIN,
/// prt)`: `ERTS_BIF_YIELD3(BIF_TRAP_EXPORT(BIF_erts_internal_port_command_3), ...)`. The
/// suspended process redoes the command through its own export once the port is not busy.
// Port of erts/emulator/beam/erl_bif_port.c (erts_internal_port_command_3: ERTS_PORT_OP_BUSY)
// and bif.h (ERTS_BIF_YIELD3), OTP-29.1.1.
#[cold]
#[inline(never)]
fn port_command_yield(process: &mut Process, args: &[Term]) -> VmError {
    crate::bif_traps::vbump_all_reds(process);
    VmError::TrapExport(crate::ExportTrap::new(
        process,
        "erts_internal:port_command/3",
        args.to_vec(),
    ))
}

fn port_command(
    process: &mut Process,
    ctx: &mut RunCtx<'_, crate::Process>,
    port: Term,
    data: Term,
    args: &[Term],
) -> Result<Term, VmError> {
    // Port of erts/emulator/beam/erl_bif_port.c:168 (erts_internal_port_command_3), OTP-29.1.1.
    let id = port_id(process, port).ok_or_else(badarg)?;
    let handle = process
        .runtime
        .as_ref()
        .and_then(|runtime| runtime.ports.get(id))
        .ok_or_else(badarg)?;
    let mut nosuspend = false;
    let mut force = false;
    if args.len() == 3 {
        let options = list(args[2]).ok_or_else(badarg)?;
        for option in options {
            if option == Term::atom(arinsal_term::atoms::NOSUSPEND) {
                nosuspend = true;
            } else if option == Term::atom(arinsal_term::atoms::FORCE) {
                force = true;
                // tcp_inet sets ERL_DRV_FLAG_SOFT_BUSY (inet_drv.c driver flags).
                // spawn/fd drivers do not, so `force` is `notsup` there.
                let soft_busy = handle
                    .driver
                    .as_ref()
                    .is_some_and(|d| d.driver().flags() & ERL_DRV_FLAG_SOFT_BUSY != 0);
                if !soft_busy {
                    return Err(notsup());
                }
            } else {
                return Err(badarg());
            }
        }
    }
    if let Some(drv_port) = handle.drv_port() {
        // Port of erts/emulator/beam/erl_bif_port.c:168 (erts_internal_port_command_3).
        let flags = drv_sig::OutputFlags {
            bang: false,
            nosuspend,
            force,
        };
        loop {
            let pid = ctx.pid();
            match drv_sig::output(
                process,
                Some(ctx),
                pid,
                &handle,
                &drv_port,
                pid,
                data,
                flags,
                true,
            ) {
                drv_sig::PortOp::Done => return Ok(Term::atom(arinsal_term::atoms::TRUE)),
                drv_sig::PortOp::Dropped | drv_sig::PortOp::Badarg => {
                    return Ok(Term::atom(arinsal_term::atoms::BADARG));
                }
                drv_sig::PortOp::Busy if nosuspend => {
                    return Ok(Term::atom(arinsal_term::atoms::FALSE));
                }
                drv_sig::PortOp::Busy => {
                    if suspend_on_busy(process, &handle, &drv_port, pid) {
                        return Err(port_command_yield(process, args));
                    }
                }
                drv_sig::PortOp::BusyScheduled(reference)
                | drv_sig::PortOp::Scheduled(reference) => {
                    return match reference {
                        Some(reference) => drv_sig::reference_term(process, reference),
                        None => Ok(Term::atom(arinsal_term::atoms::TRUE)),
                    };
                }
            }
        }
    }
    // Every other port is a driver port; ram_file_drv is the one port without a driver
    // record.
    let framed = iodata(data).ok_or_else(badarg)?;
    let bytes_out = framed.len();
    let Some(ram_file) = handle.ram_file_data() else {
        return Err(badarg());
    };
    let state = handle.state.lock();
    if state.closed || state.broken {
        return Err(badarg());
    }
    drop(state);
    trace_command_received_data(process, ctx.pid(), id, data, &framed);
    let result = crate::ram_file_drv::command(&ram_file, &handle, &framed);
    if result.is_ok() {
        handle.add_bytes_out(bytes_out);
    }
    result
        .map(|()| Term::atom(arinsal_term::atoms::TRUE))
        .map_err(|()| badarg())
}

// Port of erts/emulator/beam/io.c:1508 (trace_port_receive command), OTP-29.1.1.
fn trace_command_received(
    process: &Process,
    caller: Pid,
    id: u64,
    pieces: &[arinsal_drv::IoPiece<'_>],
    outputv_segments: Option<Vec<Vec<u8>>>,
) {
    if !crate::trace::tracing_enabled() {
        return;
    }
    let Some(runtime) = process.runtime.as_ref() else {
        return;
    };
    let Some(caller) = caller.to_term() else {
        return;
    };
    let mut heap = VecHeap::new();
    let data = if let Some(segments) = outputv_segments {
        let mut binaries = Vec::with_capacity(segments.len());
        for segment in segments {
            let Ok(binary) = TermBuilder::new(&mut heap).binary(&segment) else {
                return;
            };
            binaries.push(binary);
        }
        let Ok(list) = TermBuilder::new(&mut heap).list_from_iter(binaries) else {
            return;
        };
        list
    } else {
        let bytes = pieces
            .iter()
            .flat_map(|piece| match piece {
                arinsal_drv::IoPiece::Copied(bytes) | arinsal_drv::IoPiece::Refc(bytes) => {
                    bytes.iter().copied()
                }
            })
            .collect::<Vec<_>>();
        let Ok(binary) = TermBuilder::new(&mut heap).binary(&bytes) else {
            return;
        };
        binary
    };
    let Ok(command) =
        TermBuilder::new(&mut heap).tuple(&[Term::atom(arinsal_term::atoms::COMMAND), data])
    else {
        return;
    };
    let Ok(event) = TermBuilder::new(&mut heap).tuple(&[caller, command]) else {
        return;
    };
    crate::trace::emit_port_event(runtime, id, crate::trace::RECEIVE, "receive", &[event]);
}

fn trace_command_received_data(process: &Process, caller: Pid, id: u64, data: Term, bytes: &[u8]) {
    if !crate::trace::tracing_enabled() {
        return;
    }

    let Some(runtime) = process.runtime.as_ref() else {
        return;
    };
    let Some(caller) = caller.to_term() else {
        return;
    };
    let mut heap = VecHeap::new();
    let binary_list = to_owned(data).ok().is_some_and(|owned| {
        matches!(&owned, arinsal_etf::OwnedTerm::List { elems, tail }
            if **tail == arinsal_etf::OwnedTerm::Nil
                && !elems.is_empty()
                && elems.iter().all(|item| matches!(item, arinsal_etf::OwnedTerm::Binary(_)))
        )
    });
    let data = if binary_list {
        copy_term(data, &mut heap)
    } else {
        TermBuilder::new(&mut heap).binary(bytes)
    };
    let (Ok(caller), Ok(data)) = (copy_term(caller, &mut heap), data) else {
        return;
    };
    let Ok(command) =
        TermBuilder::new(&mut heap).tuple(&[Term::atom(arinsal_term::atoms::COMMAND), data])
    else {
        return;
    };
    let Ok(event) = TermBuilder::new(&mut heap).tuple(&[caller, command]) else {
        return;
    };
    crate::trace::emit_port_event(runtime, id, crate::trace::RECEIVE, "receive", &[event]);
}

fn trace_port_receive_term(process: &Process, caller: Pid, id: u64, message: Term) {
    if !crate::trace::tracing_enabled() {
        return;
    }

    let Some(runtime) = process.runtime.as_ref() else {
        return;
    };
    let Some(caller) = caller.to_term() else {
        return;
    };
    let mut heap = VecHeap::new();
    let (Ok(caller), Ok(message)) = (copy_term(caller, &mut heap), copy_term(message, &mut heap))
    else {
        return;
    };
    let Ok(event) = TermBuilder::new(&mut heap).tuple(&[caller, message]) else {
        return;
    };
    crate::trace::emit_port_event(runtime, id, crate::trace::RECEIVE, "receive", &[event]);
}

fn trace_port_receive_indexed(
    process: &Process,
    caller: Pid,
    id: u64,
    name: &str,
    index: u32,
    data: &[u8],
) {
    if let Some(runtime) = process.runtime.as_ref() {
        trace_port_receive_indexed_rt(runtime, caller, id, name, index, data);
    }
}

/// `trace_port_receive(prt, caller, Name, Index, Data)` (erl_trace.c) without a process.
fn trace_port_receive_indexed_rt(
    runtime: &crate::process::Runtime,
    caller: Pid,
    id: u64,
    name: &str,
    index: u32,
    data: &[u8],
) {
    if !crate::trace::tracing_enabled() {
        return;
    }
    let Some(caller) = caller.to_term() else {
        return;
    };
    let mut heap = VecHeap::new();
    let Ok(data) = TermBuilder::new(&mut heap).binary(data) else {
        return;
    };
    let Ok(arg) =
        TermBuilder::new(&mut heap).tuple(&[Term::small(i64::from(index)).unwrap(), data])
    else {
        return;
    };
    let Ok(message) = TermBuilder::new(&mut heap).tuple(&[atom_dyn(name), arg]) else {
        return;
    };
    let Ok(event) = TermBuilder::new(&mut heap).tuple(&[caller, message]) else {
        return;
    };
    crate::trace::emit_port_event(runtime, id, crate::trace::RECEIVE, "receive", &[event]);
}

// Port of erts/emulator/sys/unix/sys_drivers.c:1039 (stop), OTP-29.1.1.
// Closing a port releases its descriptors; the child may have detached from them.
fn release_io(handle: &PortHandle) {
    release_io_flushing(handle, false);
}

/// [`release_io`] for an exit delivered with a reason other than `kill`: a driver port whose
/// queue still holds data is flushed and terminates once its driver empties it
/// (io.c:3940 erts_deliver_port_exit, flush_port).
pub(crate) fn release_io_flushing(handle: &PortHandle, flush: bool) {
    // rfile_stop: release the ram_file_drv port data.
    handle.take_ram_file_data();
    // Port of erts/emulator/beam/io.c:3698 (terminate_port) for a dynamic driver.
    if let Some(drv_port) = handle.driver.as_ref()
        && (if flush {
            drv_port.close_or_flush()
        } else {
            drv_port.terminate()
        })
        && !drv_port.driver().is_native()
    {
        crate::ddll::port_closed(&handle.scheduler, drv_port.driver());
    }
    let waiters = {
        let mut st = handle.state.lock();
        st.closed = true;
        st.broken = true;
        st.busy_port = false;
        st.busy_msgq = false;
        st.exit_complete = true;
        st.suspended.take()
    };
    wake_suspended(&handle.scheduler, waiters);
    handle.finish_halt();
}

/// Deliver an exit to port `id`: the port goes away (a second exit finds it gone, as erts'
/// `DEAD | EXITING | CLOSING` check), its name is unregistered, a distribution port runs
/// `erts_do_net_exits(dep, modified_reason)` and drops its `ERTS_PRTSD_DIST_ENTRY`, links and
/// monitors get `modified_reason` (`kill` → `killed`) from `from`, then the port is flushed
/// (reason other than `kill`) or terminated; `send_closed` gets `{Port, closed}` from
/// terminate_port. Returns whether the exit was delivered.
// Port of erts/emulator/beam/io.c:3841 (erts_deliver_port_exit), OTP-29.1.1.
pub(crate) fn erts_deliver_port_exit(
    runtime: &crate::process::Runtime,
    id: u64,
    from: Pid,
    reason: Term,
    send_closed: Option<Pid>,
) -> bool {
    let modified_reason = if reason == Term::atom(arinsal_term::atoms::KILL) {
        Term::atom(arinsal_term::atoms::KILLED)
    } else {
        reason
    };
    let ports = runtime.ports.lock();
    let Some(handle) = runtime.ports.remove_locked(id) else {
        return false;
    };
    runtime.port_ids.release(id);
    drop(ports);
    crate::trace::emit_port_event(runtime, id, crate::trace::PORTS, "closed", &[reason]);
    release_port_name(runtime, &handle);
    if let Some(dep) = handle.set_dist_entry(None) {
        let _ = crate::dist::erts_do_net_exits_ctrl(
            runtime,
            &dep,
            crate::natives::erts_debug::DistCid::Port(id),
            modified_reason,
        );
    }
    notify_links_monitors(&handle, id, &handle.scheduler, from, false, modified_reason);
    release_io_flushing(&handle, reason != Term::atom(arinsal_term::atoms::KILL));
    if let Some(to) = send_closed {
        event_message(
            &handle.scheduler,
            to,
            id,
            handle.trace_scope(),
            Term::atom(arinsal_term::atoms::CLOSED),
        );
    }
    // The port's trace state goes last: `{Port, closed}` above is still traced.
    crate::trace::port_closed(runtime, id);
    true
}

fn close(process: &Process, term: Term) -> Result<Term, VmError> {
    close_inner(process, term, true)
}

fn close_inner(process: &Process, term: Term, trace_receive: bool) -> Result<Term, VmError> {
    let sender = process.self_pid.ok_or_else(badarg)?;
    let runtime = process.runtime.as_ref().ok_or_else(badarg)?;
    let id = port_id(process, term).ok_or_else(badarg)?;
    if trace_receive && let Some(caller) = sender.to_term() {
        let mut heap = VecHeap::new();
        if let Ok(event) =
            TermBuilder::new(&mut heap).tuple(&[caller, Term::atom(arinsal_term::atoms::CLOSE)])
        {
            crate::trace::emit_port_event(runtime, id, crate::trace::RECEIVE, "receive", &[event]);
        }
    }
    if erts_deliver_port_exit(
        runtime,
        id,
        sender,
        Term::atom(arinsal_term::atoms::NORMAL),
        None,
    ) {
        Ok(Term::atom(arinsal_term::atoms::TRUE))
    } else {
        Err(badarg())
    }
}

// Port of erts/emulator/beam/erl_bif_port.c:233 (erts_internal_port_close_1), OTP-29.1.1.
fn port_close(
    process: &mut Process,
    ctx: Option<&mut RunCtx<'_, crate::Process>>,
    caller: Pid,
    port: Term,
) -> Result<Term, VmError> {
    if let Some(id) = port_id(process, port)
        && let Some(handle) = process
            .runtime
            .as_ref()
            .and_then(|runtime| runtime.ports.get(id))
        && let Some(drv) = handle.drv_port()
    {
        // The `{Caller, close}` receive trace is emitted when the exit signal executes
        // (drv_sig::exit, io.c:2196 call_deliver_port_exit).
        let normal = OwnedTerm::Atom("normal".into());
        return match drv_sig::exit(
            process, ctx, caller, &handle, &drv, false, caller, normal, true,
        ) {
            Ok(Some(reference)) => drv_sig::reference_term(process, reference),
            Ok(None) => Ok(Term::atom(arinsal_term::atoms::TRUE)),
            // The light BIF has no scheduler context to schedule the signal with.
            Err(error @ VmError::Unsupported(_)) => Err(error),
            // erl_bif_port.c:405: a dropped close answers `badarg`.
            Err(_) => Ok(Term::atom(arinsal_term::atoms::BADARG)),
        };
    }
    close(process, port)
}

/// Apply an exit signal to a port and deliver its reason to linked processes.
pub(crate) fn exit_port(process: &mut Process, port: Term, reason: Term) -> Result<(), VmError> {
    let id = port.as_port().ok_or_else(badarg)?;
    // `kill` reaches links as `killed` in erts_deliver_port_exit (io.c:3854).
    let Some(runtime) = process.runtime.as_ref() else {
        return Ok(());
    };
    let handle = runtime.ports.get(id);
    if let Some(handle) = handle
        && let Some(drv) = handle.drv_port()
    {
        let reason = to_owned(reason).map_err(|_| badarg())?;
        let pid = process.self_pid.ok_or_else(badarg)?;
        // An exit signal to a port that is gone is dropped (bif.c:1794).
        let _ = drv_sig::exit(process, None, pid, &handle, &drv, false, pid, reason, false);
        return Ok(());
    }
    let caller = process.self_pid.ok_or_else(badarg)?;
    erts_deliver_port_exit(runtime, id, caller, reason, None);
    Ok(())
}

/// Reap every live port during an orderly halt, leaving `heart_port` alive.
///
/// Port of erts/emulator/beam/erl_process.c:2537-2581 (`handle_reap_ports`), OTP-29.1.1.
pub(crate) fn halt_reap_ports(runtime: &'static crate::process::Runtime, progress: HaltProgress) {
    let heart = global_atoms().intern("heart_port").ok();
    let ports: Vec<_> = runtime.ports.handles();
    for handle in ports {
        if heart.is_some() && handle.registered_atom() == heart {
            continue;
        }
        handle.track_halt(progress.clone());
        if handle.driver.as_ref().is_some() {
            drv_sig::exit_for_halt(
                runtime,
                Arc::clone(&handle),
                handle.owner_pid(),
                OwnedTerm::Atom("killed".into()),
            );
            continue;
        }
        erts_deliver_port_exit(
            runtime,
            handle.id,
            handle.owner_pid(),
            Term::atom(arinsal_term::atoms::KILLED),
            None,
        );
    }
}

fn connect(process: &Process, port: Term, pid: Term, notify: Option<Pid>) -> Result<Term, VmError> {
    let id = port_id(process, port).ok_or_else(badarg)?;
    let pid = Pid::from_term(pid).ok_or_else(badarg)?;
    let runtime = process.runtime.as_ref().ok_or_else(badarg)?;
    let handle = runtime.ports.get(id).ok_or_else(badarg)?;
    if !runtime.scheduler()?.lookup(pid) {
        return Err(badarg());
    }
    let old_owner = handle.owner_pid();
    let _ = handle
        .links
        .lock()
        .lookup_insert(crate::proc_create::port_peer_link(pid));
    handle.owner.set(pid);
    let _ = runtime
        .scheduler()?
        .signal(pid, pid, arinsal_sched::Signal::PortLink(id));
    if notify.is_none()
        && old_owner != pid
        && let Some(pid_term) = pid.to_term()
    {
        crate::trace::emit_port_event(
            runtime,
            id,
            crate::trace::PORTS,
            "getting_linked",
            &[pid_term],
        );
    }
    if notify.is_none()
        && let Some(from) = process.self_pid
        && let Some(target) = pid.to_term()
    {
        let mut heap = VecHeap::new();
        if let Ok(message) =
            TermBuilder::new(&mut heap).tuple(&[Term::atom(arinsal_term::atoms::CONNECT), target])
        {
            trace_port_receive_term(process, from, id, message);
        }
    }
    let scheduler = runtime.scheduler()?;
    if let Some(from) = notify.or(process.self_pid) {
        // Port of erts/emulator/beam/io.c:2324-2351 and 3304-3332 (set_port_connected,
        // deliver_result), OTP-29.1.1. `port_connect/2` traces the result but only
        // `! {connect, ...}` queues it.
        connected_message(
            runtime,
            scheduler,
            from,
            id,
            handle.trace_scope(),
            notify.is_some(),
        );
    }
    if notify.is_none()
        && old_owner != pid
        && let Some(port) = Term::port(id)
    {
        crate::trace::emit_external_process_event(
            runtime,
            pid,
            crate::trace::PROCS,
            "getting_linked",
            &[port],
        );
    }
    Ok(Term::atom(arinsal_term::atoms::TRUE))
}

/// Exit the ports linked to a process when it terminates: the process walks its own links and
/// hands each port one exit signal.
///
/// Port of erts/emulator/beam/erl_process.c:14068 (erts_proc_exit_handle_link), ERTS_LNK_TYPE_PORT
/// case, OTP-29.1.1.
pub(crate) fn owner_exit(
    runtime: &'static crate::process::Runtime,
    owner: Pid,
    reason: Term,
    port_links: &[u64],
) {
    let abnormal = reason != Term::atom(arinsal_term::atoms::NORMAL);
    let affected = {
        let _ports = runtime.ports.lock();
        port_links
            .iter()
            .filter_map(|id| {
                let handle = runtime.ports.get(*id)?;
                let is_owner = handle.owner.get() == owner;
                let linked = if handle.driver.as_ref().is_some() {
                    handle.links.lock().get(owner.data()).is_some()
                } else {
                    handle.links.lock().remove(owner.data()).is_some()
                };
                (is_owner || (abnormal && linked)).then_some((*id, handle))
            })
            .collect::<Vec<_>>()
    };
    for (port_id, handle) in affected {
        if handle.driver.as_ref().is_some() {
            let exit_reason = to_owned(reason).unwrap_or_else(|_| OwnedTerm::Atom("normal".into()));
            drv_sig::exit_for_process_termination(runtime, handle, owner, exit_reason);
            continue;
        }
        erts_deliver_port_exit(runtime, port_id, owner, reason, None);
    }
}

/// A process that a driver port monitors exited: the port runs its `process_exit` callback and
/// drops its origin half.
// Port of erts/emulator/beam/io.c:7143 (erts_fire_port_monitor), OTP-29.1.1.
pub(crate) fn fire_port_monitor(runtime: &crate::process::Runtime, port_id: u64, monitor: u64) {
    let Some(handle) = runtime.ports.get(port_id) else {
        return;
    };
    let Some(drv_port) = handle.driver.as_ref() else {
        return;
    };
    if handle.monitors.lock().remove(monitor).is_some() {
        drv_port.arc().process_exit(monitor);
    }
}

/// The opener's half of its link to a port it just created: the opening process is the caller,
/// so the half goes straight into its link tree (`erts_open_driver` links the port to the
/// connected process).
fn link_opener(process: &mut Process, id: u64) {
    let _ = process
        .links
        .lookup_insert(crate::proc_create::port_link(id));
}

/// Add or remove a process from a port's link set.
///
/// Port of erts/emulator/beam/bif.c (link_1/unlink_1 for a port): the calling process updates
/// its own link tree first, then the port gets the signal.
pub(crate) fn link(
    process: &mut Process,
    port: Term,
    pid: Pid,
    linked: bool,
) -> Result<bool, VmError> {
    let id = port.as_port().ok_or_else(badarg)?;
    let runtime: &'static crate::process::Runtime = process.runtime.ok_or_else(badarg)?;
    let Some(handle) = runtime.ports.get(id) else {
        return Ok(!linked);
    };
    if !linked {
        // The unlinking process traces `unlink` when it sends the signal (bif.c unlink_1).
        crate::trace::emit_external_process_event(
            runtime,
            pid,
            crate::trace::PROCS,
            "unlink",
            &[port],
        );
        let key = crate::proc_create::port_link_key(id);
        match process.links.get(key) {
            Some(link) if link.unlinking() == 0 => {}
            _ => return Ok(true),
        }
        let unlink_id = next_port_unlink_id(&mut process.uniq_counter);
        let mut prio = false;
        if let Some(mut link) = process.links.get_mut(key) {
            // bif.c unlink_1 (is_internal_port): unlink_clear_prio, then `ilnk->unlinking`.
            prio = link.view().is_priority();
            link.set_priority(false);
            link.set_unlinking(unlink_id);
        }
        if prio {
            process.prio_item_deleted(crate::receive::PrioItemType::Link);
        }
        if let Some(drv) = handle.drv_port() {
            if !drv_sig::link(runtime, &handle, &drv, pid, false, unlink_id) {
                // `erts_port_unlink` acknowledges an invalid port lookup through
                // `port_unlink_failure` instead of scheduling a port task.
                let _ = handle.scheduler.signal(
                    pid,
                    pid,
                    arinsal_sched::Signal::PortUnlinkAck {
                        port: id,
                        unlink_id,
                    },
                );
            }
            return Ok(true);
        }
        // Port of erts/emulator/beam/io.c:2514 (port_unlink), OTP-29.1.1: trace the port half
        // before deleting it, then acknowledge the process-side unlink.
        let mut links = handle.links.lock();
        let has_link = links
            .get(pid.data())
            .is_some_and(|link| link.unlinking() == 0);
        if has_link && let Some(pid_term) = pid.to_term() {
            crate::trace::emit_port_event(
                runtime,
                id,
                crate::trace::PORTS,
                "getting_unlinked",
                &[pid_term],
            );
        }
        links.remove(pid.data());
        drop(links);
        let _ = handle.scheduler.signal(
            pid,
            pid,
            arinsal_sched::Signal::PortUnlinkAck {
                port: id,
                unlink_id,
            },
        );
        return Ok(true);
    }
    let runtime = process.runtime.as_ref().ok_or_else(badarg)?;
    if let Some(drv) = handle.drv_port() {
        let done = drv_sig::link(runtime, &handle, &drv, pid, linked, 0);
        return Ok(done || !linked);
    }
    // Termination removes the port from the table and drains `links` in one critical section
    // of the table lock (`erts_deliver_port_exit`); taking the locks in the same order makes this
    // registration either visible to it or refused.
    let ports = runtime.ports.read().unwrap();
    if linked && !runtime.ports.contains(id) {
        return Ok(false);
    }
    let mut links = handle.links.lock();
    if linked {
        let _ = links.lookup_insert(crate::proc_create::process_link(pid, false));
    }
    drop(links);
    drop(ports);
    if let Some(pid_term) = pid.to_term() {
        crate::trace::emit_port_event(
            runtime,
            id,
            crate::trace::PORTS,
            if linked {
                "getting_linked"
            } else {
                "getting_unlinked"
            },
            &[pid_term],
        );
    }
    Ok(true)
}

/// Port of erts/emulator/beam/erl_proc_sig_queue.h:1908-1929
/// (`erts_proc_sig_new_unlink_id`), OTP-29.1.1.
fn next_port_unlink_id(uniq: &mut i64) -> u64 {
    loop {
        let id = *uniq as u64;
        *uniq = uniq.wrapping_add(1);
        if id != 0 {
            return id;
        }
    }
}

/// Register or remove a process monitor on a port the caller already looked up
/// (`erts_port_lookup` in bif.c monitor, then `erts_port_monitor`). A port that vanished
/// in between is refused and the caller sends DOWN noproc.
pub(crate) fn monitor(
    process: &Process,
    id: u64,
    handle: &PortHandle,
    target: crate::proc_create::ProcessMonitor,
    monitored: bool,
) -> Result<bool, VmError> {
    if monitored && let Some(drv_port) = handle.driver.as_ref() {
        // Port of erts/emulator/beam/io.c:6787 (erts_port_monitor): the request is a port
        // signal, handled once the callback holding the port lock has returned.
        return drv_port.serialized(|| register_monitor(process, id, handle, target, monitored));
    }
    register_monitor(process, id, handle, target, monitored)
}

fn register_monitor(
    process: &Process,
    id: u64,
    handle: &PortHandle,
    target: crate::proc_create::ProcessMonitor,
    monitored: bool,
) -> Result<bool, VmError> {
    if monitored && handle.state.lock().exit_complete {
        return Ok(false);
    }
    // See `link`: same lock order as termination (table, then monitors).
    let _ports = process
        .runtime
        .as_ref()
        .map(|runtime| runtime.ports.read().unwrap());
    if monitored
        && !process.runtime.as_ref().is_some_and(|runtime| {
            runtime
                .ports
                .with_from(id, process.on_managed, |_| ())
                .is_some()
        })
    {
        return Ok(false);
    }
    if monitored {
        handle.lt_monitors.lock().insert(target);
    } else {
        drop(target);
    }
    Ok(true)
}

/// Demonitor one port. The caller already removed the origin from its monitor tree.
///
/// Port of erts/emulator/beam/bif.c:504-510 and io.c:2850 (`erts_port_demonitor`),
/// OTP-29.1.1. A loaded driver gets a proc-to-port demonitor signal (immediate when
/// the port is free). A spawn or fd port has no driver task queue; the target half
/// is dropped under the port's monitor lock, which is that port's `try_imm` path.
pub(crate) fn demonitor_port(
    process: &Process,
    caller: Pid,
    port_id: u64,
    origin: crate::proc_create::ProcessMonitor,
) {
    let Some(runtime) = process.runtime.as_ref() else {
        return;
    };
    // The common case runs on the borrowed handle; a port that is busy takes a counted one.
    let free = runtime
        .ports
        .with_from(port_id, process.on_managed, |handle| {
            match handle.driver.as_ref() {
                Some(drv) => drv_sig::demonitor_now(handle, drv, &origin),
                None => {
                    let _ = handle.lt_monitors.lock().remove_target_of(&origin);
                    true
                }
            }
        });
    // `erts_port_lookup` failed: `ERTS_PORT_OP_DROPPED`, origin already released.
    if free != Some(false) {
        return;
    }
    if let Some(handle) = runtime.ports.get(port_id)
        && let Some(drv) = handle.drv_port()
    {
        drv_sig::demonitor(&handle, &drv, caller, origin);
    }
}

/// Port of erts/emulator/beam/io.c:1715 (erts_port_output) for `{command, Data}`; also
/// the body of `erts_port_output_async` (`enif_port_command`). Failures signal the port.
fn output_command(
    runtime: &'static crate::process::Runtime,
    handle: &Arc<PortHandle>,
    id: u64,
    from: Pid,
    data: Term,
    tracer: Option<&Process>,
) {
    if let Some(drv_port) = handle.driver.as_ref() {
        // Port of erts/emulator/beam/io.c:1715 (erts_port_output) for `Port ! {Pid, {command, D}}`.
        let mut pieces = Vec::new();
        if io_pieces(data, &mut pieces).is_none() {
            signal_badsig(handle, id);
            return;
        }
        let bytes_out = pieces.iter().map(|(bytes, _)| bytes.len()).sum();
        let pieces = pieces
            .iter()
            .map(|(bytes, refc)| {
                if *refc {
                    arinsal_drv::IoPiece::Refc(bytes)
                } else {
                    arinsal_drv::IoPiece::Copied(bytes)
                }
            })
            .collect::<Vec<_>>();
        if let Some(process) = tracer {
            trace_command_received(
                process,
                from,
                id,
                &pieces,
                drv_port.outputv_trace_segments(&pieces),
            );
        }
        if drv_port.output(&pieces, packed_pid(from)) {
            handle.add_bytes_out(bytes_out);
        } else if runtime.ports.contains(id) {
            signal_badsig(handle, id);
        }
        return;
    }
    let Some(data) = iodata(data) else {
        // io.c:2160 bad_port_signal with ERTS_PORT_SIG_FLG_BAD_OUTPUT: badsig_received logs
        // the bad value before the badsig exit signal.
        crate::utils::send_error_to_logger_nogl(
            runtime,
            tracer.and_then(|process| process.self_pid),
            &format!("Bad value on output port '{}'\n", handle.port_name()),
        );
        signal_badsig(handle, id);
        return;
    };
    let bytes_out = data.len();
    if let Some(process) = tracer {
        trace_command_received(
            process,
            from,
            id,
            &[arinsal_drv::IoPiece::Copied(&data)],
            None,
        );
    }
    // Every other port is a driver port; ram_file_drv is the one port without a driver
    // record.
    let Some(ram_file) = handle.ram_file_data() else {
        signal_badsig(handle, id);
        return;
    };
    if crate::ram_file_drv::command(&ram_file, handle, &data).is_err() {
        signal_badsig(handle, id);
    } else {
        handle.add_bytes_out(bytes_out);
    }
}

/// Port of erts/emulator/beam/erl_nif.c:1097 (enif_port_command): `erts_port_output_async`
/// of `data` on behalf of `from`; `false` when the port is gone.
pub(crate) fn nif_port_command(
    runtime: &'static crate::process::Runtime,
    port: Term,
    from: Pid,
    data: Term,
) -> bool {
    let Some(id) = port.as_port() else {
        return false;
    };
    let Some(handle) = runtime.ports.get(id) else {
        return false;
    };
    if handle.state.lock().exit_complete {
        return false;
    }
    // Port of erts/emulator/beam/io.c:1603-1605 (erts_port_output_async): data that is not
    // iodata is refused (`bad_value`, result 0) without signalling the port.
    if io_pieces(data, &mut Vec::new()).is_none() {
        return false;
    }
    output_command(runtime, &handle, id, from, data, None);
    true
}

pub(crate) fn send_message(
    process: &mut Process,
    port: Term,
    message: Term,
) -> Result<(), VmError> {
    send_message_inner(process, port, message, false, None).map(|_| ())
}

/// Outcome of `Port ! Message` from a process (erts_send to a port, bif.c:2560).
pub(crate) enum PortSend {
    /// Sent or dropped: the send is complete.
    Sent,
    /// Sent, and the sender is now suspended on the busy port (`SEND_YIELD_RETURN`).
    SentSuspended,
    /// Nothing was sent: the port is busy (`SEND_YIELD`). The sender is suspended
    /// unless `nosuspend` was given.
    Busy,
}

/// `Port ! Message` from process code; `nosuspend` is `erlang:send/3` with `[nosuspend]`.
pub(crate) fn send_from_process(
    process: &mut Process,
    port: Term,
    message: Term,
    nosuspend: bool,
    mut ctx: Option<&mut RunCtx<'_, crate::Process>>,
) -> Result<PortSend, VmError> {
    loop {
        match send_message_inner(process, port, message, nosuspend, ctx.as_deref_mut())? {
            (PortSend::Busy, Some((handle, drv))) if !nosuspend => {
                let pid = process.self_pid.ok_or_else(badarg)?;
                if suspend_on_busy(process, &handle, &drv, pid) {
                    return Ok(PortSend::Busy);
                }
            }
            // ERTS_PORT_OP_BUSY_SCHEDULED: sent; only a suspending send waits on the port.
            (PortSend::SentSuspended, Some((handle, drv))) if !nosuspend => {
                let pid = process.self_pid.ok_or_else(badarg)?;
                if suspend_on_busy(process, &handle, &drv, pid) {
                    return Ok(PortSend::SentSuspended);
                }
                return Ok(PortSend::Sent);
            }
            (PortSend::SentSuspended, _) if nosuspend => return Ok(PortSend::Sent),
            (outcome, _) => return Ok(outcome),
        }
    }
}

type DrvTarget = Option<(Arc<PortHandle>, arinsal_drv::PortRef)>;

fn send_message_inner(
    process: &mut Process,
    port: Term,
    message: Term,
    nosuspend: bool,
    mut ctx: Option<&mut RunCtx<'_, crate::Process>>,
) -> Result<(PortSend, DrvTarget), VmError> {
    let id = port.as_port().ok_or_else(badarg)?;
    let runtime = process.runtime.as_ref().ok_or_else(badarg)?;
    // A message to a dead local port is dropped (erts_port_command DROPPED).
    let Some(handle) = runtime.ports.get(id) else {
        return Ok(sent());
    };
    let Some(parts) = tuple(message) else {
        signal_badsig(&handle, id);
        return Ok(sent());
    };
    // Port of erts/emulator/beam/io.c:3991 (erts_port_command): the first element names the
    // connected process (checked per operation), not necessarily the sender.
    let from = if parts.len() == 2 {
        Pid::from_term(parts[0])
    } else {
        None
    };
    let Some(from) = from else {
        signal_badsig(&handle, id);
        return Ok(sent());
    };
    let from_connected = handle.owner.get() == from;
    let drv = handle.drv_port();
    if let Some(drv) = &drv
        && (parts[1] == Term::atom(arinsal_term::atoms::CLOSE)
            || tuple(parts[1]).is_some_and(|command| {
                command.len() == 2
                    && command[0] == Term::atom(arinsal_term::atoms::CONNECT)
                    && command[1].as_pid().is_some()
            }))
    {
        // Port of erts/emulator/beam/io.c:3975 (erts_port_command): `close` and `connect`
        // are port signals checked against the connected process when they execute.
        let sender = process.self_pid.unwrap_or(from);
        if from_connected {
            trace_port_receive_term(process, from, id, parts[1]);
        }
        if parts[1] == Term::atom(arinsal_term::atoms::CLOSE) {
            let normal = OwnedTerm::Atom("normal".into());
            let _ = drv_sig::exit(
                process,
                ctx.as_deref_mut(),
                sender,
                &handle,
                drv,
                true,
                from,
                normal,
                false,
            );
        } else {
            let command = tuple(parts[1]).unwrap_or_default();
            let pid = Pid::from_term(command[1]).ok_or_else(badarg)?;
            drv_sig::connect(process, sender, &handle, drv, from, pid);
        }
        return Ok(sent());
    }
    if parts[1] == Term::atom(arinsal_term::atoms::CLOSE) {
        if !from_connected {
            signal_badsig(&handle, id);
            return Ok(sent());
        }
        trace_port_receive_term(process, from, id, parts[1]);
        // Only ram_file_drv ports have no driver record; their close is immediate.
        event_message(
            &handle.scheduler,
            from,
            id,
            handle.trace_scope(),
            Term::atom(arinsal_term::atoms::CLOSED),
        );
        let _ = close_inner(process, port, false);
        return Ok(sent());
    }
    let Some(command) = tuple(parts[1]) else {
        signal_badsig(&handle, id);
        return Ok(sent());
    };
    if command.len() == 2
        && command[0] == Term::atom(arinsal_term::atoms::COMMAND)
        && !from_connected
        && drv.is_none()
    {
        // io.c:1887 (erts_port_output, bang op): only the connected process may command.
        signal_badsig(&handle, id);
        return Ok(sent());
    }
    if command.len() == 2
        && command[0] == Term::atom(arinsal_term::atoms::COMMAND)
        && let Some(drv_port) = drv
    {
        // Port of erts/emulator/beam/io.c:1715 (erts_port_output) for `Port ! {Pid, {command, D}}`.
        let flags = drv_sig::OutputFlags {
            bang: true,
            nosuspend,
            force: false,
        };
        let sender = process.self_pid.unwrap_or(from);
        return Ok(
            match drv_sig::output(
                process, ctx, sender, &handle, &drv_port, from, command[1], flags, false,
            ) {
                drv_sig::PortOp::Busy => (PortSend::Busy, Some((handle, drv_port))),
                drv_sig::PortOp::BusyScheduled(_) => {
                    (PortSend::SentSuspended, Some((handle, drv_port)))
                }
                _ => sent(),
            },
        );
    }
    if command.len() == 2 && command[0] == Term::atom(arinsal_term::atoms::COMMAND) {
        // Port of erts/emulator/beam/io.c:1715-1754 (erts_port_output), OTP-29.1.1.
        // `SEND_YIELD` leaves an already-busy port command unsent and retries it after resume.
        if drv.is_none() {
            let mut state = handle.state.lock();
            if state.busy_port || state.busy_msgq {
                if !nosuspend {
                    // erts_suspend(c_p, ERTS_PROC_LOCK_MAIN, prt): the sender, not the
                    // connected process the message names.
                    let pid = process.self_pid.ok_or_else(badarg)?;
                    crate::suspend::suspend_self(process);
                    state.suspended.push(pid);
                    let busy_port = state.busy_port;
                    drop(state);
                    if busy_port {
                        crate::natives::erts_debug::notify_busy_port(process, pid, id);
                    }
                }
                return Ok((PortSend::Busy, None));
            }
        }
        output_command(runtime, &handle, id, from, command[1], Some(process));
        return Ok(sent());
    }
    if command.len() == 2 && command[0] == Term::atom(arinsal_term::atoms::CONNECT) {
        if !from_connected || command[1].as_pid().is_none() {
            signal_badsig(&handle, id);
            return Ok(sent());
        }
        trace_port_receive_term(process, from, id, parts[1]);
        if connect(process, port, command[1], Some(from)).is_err() && runtime.ports.contains(id) {
            signal_badsig(&handle, id);
        }
        return Ok(sent());
    }
    signal_badsig(&handle, id);
    Ok(sent())
}

fn sent() -> (PortSend, DrvTarget) {
    (PortSend::Sent, None)
}

/// Send an ETF encoded trace event through the tracer port's command channel.
// Port of erts/emulator/nifs/common/erl_tracer_nif.c:251-260 (enif_port_command), OTP-29.1.1.
pub(crate) fn trace_command(process: &mut Process, port: Term, event: Term) -> Result<(), VmError> {
    let id = port.as_port().ok_or_else(badarg)?;
    let owner = process
        .runtime
        .as_ref()
        .and_then(|runtime| runtime.ports.get(id))
        .map(|handle| handle.owner_pid())
        .ok_or_else(badarg)?;
    // enif_term_to_binary: erts_encode_ext_size + erts_encode_ext of the event, then the bytes
    // become the binary of the `{command, Bin}` message.
    let encoded = {
        let bytes = arinsal_external::encode_term_to_binary(event).map_err(|_| badarg())?;
        let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
        TermBuilder::new(&mut heap)
            .binary(&bytes)
            .map_err(|_| badarg())?
    };
    let command = {
        let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
        TermBuilder::new(&mut heap)
            .tuple(&[Term::atom(arinsal_term::atoms::COMMAND), encoded])
            .map_err(|_| badarg())?
    };
    let envelope = {
        let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
        TermBuilder::new(&mut heap)
            .tuple(&[owner.to_term().ok_or_else(badarg)?, command])
            .map_err(|_| badarg())?
    };
    send_message(process, port, envelope)
}

fn port_counter_term(heap: &mut impl HeapAlloc, counter: u64) -> Result<Term, VmError> {
    TermBuilder::new(heap)
        .int_from_bigint(&num_bigint::BigInt::from(counter))
        .map_err(|e| VmError::Unsupported(format!("port info counter: {e:?}")))
}

fn port_info(process: &mut Process, port: Term, item: Option<Term>) -> Result<Term, VmError> {
    let id = match (port.as_port(), port.as_atom()) {
        (Some(id), _) => id,
        (None, Some(name)) => {
            let Some(id) = process
                .runtime
                .as_ref()
                .and_then(|runtime| runtime.reg.whereis_port(name))
            else {
                return Ok(Term::atom(arinsal_term::atoms::UNDEFINED));
            };
            id
        }
        (None, None) => return Err(badarg()),
    };
    let Some(handle) = process.runtime.as_ref().and_then(|r| r.ports.get(id)) else {
        return Ok(Term::atom(arinsal_term::atoms::UNDEFINED));
    };
    let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
    let name = TermBuilder::new(&mut heap)
        .string_to_list(&handle.name)
        .map_err(|e| VmError::Unsupported(format!("port info name: {e:?}")))?;
    let connected = handle.owner.get().to_term().ok_or_else(badarg)?;
    let links = TermBuilder::new(&mut heap)
        .list_from_iter(
            handle
                .links
                .lock()
                .iter()
                .filter_map(|link| Pid::from_data(link.other()).to_term()),
        )
        .map_err(|e| VmError::Unsupported(format!("port info links: {e:?}")))?;
    let mut monitored_pids = handle
        .lt_monitors
        .lock()
        .iter()
        .filter_map(|monitor| Pid::from_data(monitor.other()).to_term())
        .collect::<Vec<_>>();
    monitored_pids.reverse();
    let drv_port = handle.driver.as_ref();
    let mut process_monitors = handle
        .monitors
        .lock()
        .iter()
        .map(|monitor| {
            let pid = Pid::from_data(monitor.other())
                .to_term()
                .ok_or_else(badarg)?;
            TermBuilder::new(&mut heap)
                .tuple(&[Term::atom(arinsal_term::atoms::PROCESS), pid])
                .map_err(|e| VmError::Unsupported(format!("port info monitors: {e:?}")))
        })
        .collect::<Result<Vec<_>, _>>()?;
    process_monitors.reverse();
    let port_monitors = !process_monitors.is_empty();
    let monitors = TermBuilder::new(&mut heap)
        .list_from_iter(process_monitors)
        .map_err(|e| VmError::Unsupported(format!("port info monitors: {e:?}")))?;
    // Port of erts/emulator/beam/erl_bif_info.c:3825 (port_info memory): link_size and
    // monitor_size *assign* the element size, so the walk of ERTS_P_LINKS, ERTS_P_MONITORS
    // and ERTS_P_LT_MONITORS leaves the size of the last element visited: a local link is
    // `sizeof(ErtsLink)`, a local monitor half `sizeof(ErtsMonitorDataHeap) / refc`.
    const LINK_SIZE: usize = 48;
    const MONITOR_HALF_SIZE: usize = 72;
    let memory = if !monitored_pids.is_empty() || port_monitors {
        MONITOR_HALF_SIZE
    } else if handle.links.lock().iter().next().is_some() {
        LINK_SIZE
    } else {
        0
    };
    let (input_count, output_count) = {
        let state = handle.state.lock();
        (state.bytes_in, state.bytes_out)
    };
    let input = port_counter_term(&mut heap, input_count)?;
    let output = port_counter_term(&mut heap, output_count)?;
    let queue_size = match handle.tcp_driver_data() {
        Some(sock) => sock.out_queue_size(),
        None => drv_port.map_or(0, |drv| drv.queue_size()),
    };
    // Port of erts/emulator/beam/io.c (port_info os_pid): a driver that never
    // called `erl_drv_set_os_pid` reports `undefined`.
    let os_pid = match drv_port.map(|drv| drv.os_pid()) {
        Some(pid) if pid < 0 => Term::atom(arinsal_term::atoms::UNDEFINED),
        Some(pid) => Term::small(pid).unwrap(),
        None => Term::atom(arinsal_term::atoms::UNDEFINED),
    };
    let monitored_by = TermBuilder::new(&mut heap)
        .list_from_iter(monitored_pids)
        .map_err(|error| VmError::Unsupported(format!("port monitored_by: {error:?}")))?;
    let registered_atom = handle.registered_atom();
    let has_registered_name = registered_atom.is_some();
    let registered_name = registered_atom
        .map(Term::atom)
        .unwrap_or_else(|| Term::atom(arinsal_term::atoms::UNDEFINED));
    let fields = [
        ("registered_name", registered_name),
        ("name", name),
        ("links", links),
        ("id", Term::small(id as i64).unwrap()),
        ("connected", connected),
        ("input", input),
        ("output", output),
        ("os_pid", os_pid),
        ("monitors", monitors),
        ("monitored_by", monitored_by),
        ("memory", Term::small(memory as i64).unwrap()),
        ("queue_size", Term::small(queue_size as i64).unwrap()),
        // Port of erl_bif_info.c:3862 (port_info locking): ERTS_PORT_SFLG_PORT_SPECIFIC_LOCK
        // is set for drivers with ERL_DRV_FLAG_USE_PORT_LOCKING.
        (
            "locking",
            crate::atom_cache::put(
                if drv_port
                    .is_none_or(|drv| drv.driver().flags() & ERL_DRV_FLAG_USE_PORT_LOCKING != 0)
                {
                    "port_level"
                } else {
                    "driver_level"
                },
            ),
        ),
        (
            "parallelism",
            Term::atom(if handle.parallelism {
                arinsal_term::atoms::TRUE
            } else {
                arinsal_term::atoms::FALSE
            }),
        ),
    ];
    if let Some(item) = item {
        let key = global_atoms()
            .text(item.as_atom().ok_or_else(badarg)?)
            .ok_or_else(badarg)?;
        let value = fields
            .iter()
            .find_map(|(name, value)| (*name == key).then_some(*value))
            .ok_or_else(badarg)?;
        if key == "registered_name" && value == Term::atom(arinsal_term::atoms::UNDEFINED) {
            return Ok(Term::NIL);
        }
        return TermBuilder::new(&mut heap)
            .tuple(&[item, value])
            .map_err(|e| VmError::Unsupported(format!("port info: {e:?}")));
    }
    let tuples: Vec<Term> = fields
        .into_iter()
        .filter(|(key, value)| {
            *key != "registered_name" || *value != Term::atom(arinsal_term::atoms::UNDEFINED)
        })
        .take(if has_registered_name { 8 } else { 7 })
        .map(|(key, value)| {
            let key = crate::atom_cache::put(key);
            TermBuilder::new(&mut heap)
                .tuple(&[key, value])
                .map_err(|e| VmError::Unsupported(format!("port info: {e:?}")))
        })
        .collect::<Result<_, _>>()?;
    TermBuilder::new(&mut heap)
        .list_from_iter(tuples)
        .map_err(|e| VmError::Unsupported(format!("port info: {e:?}")))
}

/// Sizes of the `PortHandle` fields, for the layout test in `inet_drv`.
#[cfg(test)]
pub(crate) fn layout_sizes() -> Vec<String> {
    use std::mem::size_of;
    vec![
        format!("PortState={}", size_of::<PortState>()),
        format!("LinkTree={}", size_of::<crate::proc_create::LinkTree>()),
        format!(
            "MonitorTree={}",
            size_of::<crate::proc_create::MonitorTree>()
        ),
        format!(
            "MonitorList={}",
            size_of::<crate::proc_create::TargetMonitorList>()
        ),
        format!("Option<HaltProgress>={}", size_of::<Option<HaltProgress>>()),
    ]
}
