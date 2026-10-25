//! `driver_select`: the driver event table.
//!
//! Port of erts/emulator/sys/common/erl_check_io.c (driver_select :988, deselect :878,
//! drv_select_steal :1711, iready/oready :1874, erts_check_io task execution and
//! `erts_io_notify_port_task_executed`), OTP-29.1.1, for a kqueue poll set: updates are
//! applied synchronously (`wake_poller == 0`), so `stop_select` runs inside the
//! `driver_select` call that removes the last event. `enif_select` (erl_check_io.c:1236)
//! shares the table like `ErtsDrvEventState` does: an fd is either a driver or a NIF
//! selection, and the other kind steals it.

use std::collections::HashMap;
use std::ffi::c_int;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, mpsc};

use crate::task::{call2, event_of};
use crate::{DriverPort, PortRef, REDS_INPUT, layout, poll};

/// `ERL_DRV_READ`.
pub const READ: c_int = layout::ERL_DRV_READ as c_int;
/// `ERL_DRV_WRITE`.
pub const WRITE: c_int = layout::ERL_DRV_WRITE as c_int;
/// `ERL_DRV_USE`.
pub const USE: c_int = layout::ERL_DRV_USE as c_int;
/// `ERL_DRV_USE_NO_CALLBACK`.
pub(crate) const USE_NO_CALLBACK: c_int = layout::ERL_DRV_USE_NO_CALLBACK as c_int;

const DIRS: [c_int; 2] = [READ, WRITE];

/// `inport`/`outport` with the armed and in-flight state of that direction.
#[derive(Default)]
struct Dir {
    /// Port that selected this direction (`select->inport`/`outport`).
    owner: Option<PortRef>,
    /// Registration in the poll set (`active_events`).
    reg: Option<u64>,
    /// The ready task running or queued (`is_iotask_active`); the event is re-armed after it.
    running: Option<u64>,
    /// `ready_input`/`ready_output` has acquired the port lock and entered the callback.
    executing: bool,
}

/// A message `enif_select` prepared for one direction (`struct erts_nif_select_event`).
pub trait NifSelectMessage: Send {
    /// Queue the message to its recipient (`send_select_msg`); dropping it discards it
    /// (`clear_select_event`).
    fn deliver(self: Box<Self>);
    /// Text of the recipient for the steal report.
    fn recipient(&self) -> String;
}

/// The resource behind an `enif_select` (`state->driver.stop.resource`).
pub trait NifSelectResource: Send + Sync {
    /// Identity of the resource (its data address).
    fn id(&self) -> usize;
    /// `Module:Name` of the resource type.
    fn type_name(&self) -> String;
    /// `enif_keep_resource`.
    fn keep(&self);
    /// `enif_release_resource`.
    fn release(&self);
    /// `erts_resource_stop`.
    fn stop(&self, fd: i32, direct: bool);
    /// `erts_send_error_to_logger_nogl`.
    fn log_error(&self, text: &str);
}

/// `ErtsDrvEventState` of type `ERTS_EV_TYPE_NIF`: the selecting resource and the
/// messages waiting for READ (0) and WRITE (1).
struct NifSel {
    resource: Arc<dyn NifSelectResource>,
    messages: [Option<Box<dyn NifSelectMessage>>; 2],
}

/// `ErtsDrvEventState` of type `ERTS_EV_TYPE_DRV_SEL` or `ERTS_EV_TYPE_NIF`.
#[derive(Default)]
struct FdState {
    /// `state->driver.nif` while the type is `ERTS_EV_TYPE_NIF`; a pointer, as erts keeps it in
    /// the union of the descriptor state.
    nif: Option<Box<NifSel>>,
    /// `state->events`: `READ | WRITE`.
    events: c_int,
    /// `ERTS_EV_FLAG_USED`: `ERL_DRV_USE` was given when the events were set.
    used: bool,
    dirs: [Dir; 2],
}

/// The descriptor event table (`ErtsDrvEventState` array), split in shards by descriptor
/// so selections of different descriptors do not contend (erl_check_io.c locks per
/// descriptor state; `fd_status` is a lock array indexed by fd).
const SHARDS: usize = 64;

fn shard(fd: i32) -> &'static Mutex<HashMap<i32, FdState>> {
    static TABLE: OnceLock<Vec<Mutex<HashMap<i32, FdState>>>> = OnceLock::new();
    &TABLE.get_or_init(|| (0..SHARDS).map(|_| Mutex::new(HashMap::new())).collect())
        [fd as usize % SHARDS]
}

fn table(fd: i32) -> MutexGuard<'static, HashMap<i32, FdState>> {
    shard(fd).lock().unwrap()
}

fn next_registration() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

/// Arm direction `dir` of `fd` if it is selected, not armed and not running
/// (`state->active_events |= ...` plus `erts_io_control`). `false` when the poller
/// rejected the descriptor (`ERTS_POLL_EV_NVAL`).
fn arm_dir(fd: i32, state: &mut FdState, dir: usize) -> bool {
    let slot = &mut state.dirs[dir];
    if state.events & DIRS[dir] == 0 || slot.reg.is_some() || slot.running.is_some() {
        return true;
    }
    let id = next_registration();
    slot.reg = Some(id);
    // A driver selection becomes an I/O task of its port right on the poller thread
    // (erl_check_io.c:2102 iready/oready); everything that needs the descriptor table
    // goes through the notifier, since the poller must not take the table lock.
    let owner = state.nif.is_none().then(|| slot.owner.clone()).flatten();
    let ready: Box<dyn FnOnce() + Send> = match owner {
        Some(owner) => Box::new(move || {
            if !owner.schedule_io(fd, dir, id) {
                fired(fd, dir, id);
            }
        }),
        None => Box::new(move || fired(fd, dir, id)),
    };
    let notified = match poll::backend() {
        Some(backend) => backend.register(id, fd, dir == 1, ready).is_ok(),
        None => false,
    };
    if !notified {
        state.dirs[dir].reg = None;
    }
    notified
}

/// `arm_dir` for a driver: a rejected descriptor is reported ready at once
/// (`new_events & (ERR|NVAL)` in driver_select) and the driver finds the error.
fn arm(fd: i32, state: &mut FdState, dir: usize) {
    if !arm_dir(fd, state, dir) {
        let id = next_registration();
        state.dirs[dir].reg = Some(id);
        let scheduled = state.dirs[dir]
            .owner
            .as_ref()
            .is_some_and(|owner| owner.schedule_io(fd, dir, id));
        if !scheduled {
            notify(fd, dir, id);
        }
    }
}

fn disarm(state: &mut FdState, dir: usize) {
    // erl_check_io.c:1161-1164 (`abort_tasks`): deselection cancels a ready task
    // that has been scheduled but has not acquired the port lock yet.
    if !state.dirs[dir].executing {
        state.dirs[dir].running = None;
    }
    if let Some(id) = state.dirs[dir].reg.take()
        && let Some(backend) = poll::backend()
    {
        backend.deregister(id);
    }
}

/// Port of erl_check_io.c:878 (deselect): drop `mode` (all when zero); an entry without
/// events leaves the table (`ERTS_EV_TYPE_NONE`).
fn deselect(table: &mut HashMap<i32, FdState>, fd: i32, mode: c_int) {
    let Some(state) = table.get_mut(&fd) else {
        return;
    };
    let mode = if mode == 0 { READ | WRITE } else { mode };
    for (dir, bit) in DIRS.iter().enumerate() {
        if mode & bit != 0 {
            disarm(state, dir);
            state.dirs[dir].owner = None;
            state.events &= !bit;
        }
    }
    if state.events == 0 {
        table.remove(&fd);
    }
}

/// Port of io.c:5463 (print_driver_name), without the port id: the port and driver names
/// with a trailing space.
fn name_part(port: &DriverPort) -> String {
    let name = port.command_name();
    let driver = port.driver.name();
    if name.is_empty() || name == driver {
        format!("{driver} ")
    } else {
        format!("{driver} ({name}) ")
    }
}

fn mode_text(mode: c_int, on: bool) -> String {
    format!(
        "{}{}{}{}, {}",
        if mode & READ != 0 {
            " ERL_DRV_READ"
        } else {
            ""
        },
        if mode & WRITE != 0 {
            " ERL_DRV_WRITE"
        } else {
            ""
        },
        if mode & USE != 0 { " ERL_DRV_USE" } else { "" },
        if mode & (USE_NO_CALLBACK & !USE) != 0 {
            "_NO_CALLBACK"
        } else {
            ""
        },
        c_int::from(on)
    )
}

/// Port of io.c:5421 (erts_stale_drv_select) for the report only.
fn report_stale(owner: &DriverPort, mode: c_int) {
    let kind = match mode {
        m if m == READ | WRITE => "Input/Output",
        WRITE => "Output",
        READ => "Input",
        _ => "",
    };
    let name = owner.command_name();
    let name = if name.is_empty() { "<unknown>" } else { &name };
    owner.host.log_error(&format!(
        "#Port<0.{}>: {name}: {kind} driver gone away without deselecting!\n",
        owner.id
    ));
}

/// Port of erl_check_io.c:1530 (need2steal/chk_stale): `true` when a live port other
/// than the new selector holds `mode`; a dead owner is reported and deselected.
fn need_to_steal(table: &mut HashMap<i32, FdState>, fd: i32, mode: c_int) -> bool {
    let mut steal = false;
    for (dir, bit) in DIRS.iter().enumerate() {
        if mode & bit == 0 {
            continue;
        }
        let Some(owner) = table.get(&fd).and_then(|s| s.dirs[dir].owner.clone()) else {
            continue;
        };
        if owner.live() {
            steal = true;
        } else {
            report_stale(&owner, *bit);
            deselect(table, fd, *bit);
        }
    }
    steal
}

/// Port of erl_check_io.c:1711 (drv_select_steal) and :1616 (steal).
fn steal(table: &mut HashMap<i32, FdState>, fd: i32, port: &DriverPort, mode: c_int, on: bool) {
    if !need_to_steal(table, fd, mode) {
        return;
    }
    // Port of io.c:5476 (print_drv_select_op).
    let mut text = format!(
        "driver_select({:#x}, {fd},{}) by {}driver #Port<0.{}> stealing control of fd={fd} from ",
        port.handle() as usize,
        mode_text(mode, on),
        name_part(port),
        port.id
    );
    let mut deselect_mode = 0;
    if let Some(state) = table.get(&fd) {
        for (dir, bit) in DIRS.iter().enumerate() {
            if mode & bit == 0 {
                continue;
            }
            if let Some(owner) = &state.dirs[dir].owner {
                if deselect_mode != 0 {
                    text.push_str("and ");
                }
                text.push_str(if dir == 0 {
                    "input driver "
                } else {
                    "output driver "
                });
                text.push_str(&format!("{}#Port<0.{}> ", name_part(owner), owner.id));
                deselect_mode |= bit;
            }
        }
    }
    text.push('\n');
    if deselect_mode != 0 {
        deselect(table, fd, deselect_mode);
    }
    port.host.log_error(&text);
}

/// Port of erl_check_io.c:988 (driver_select). `fd` is the descriptor behind the
/// `ErlDrvEvent`.
pub(crate) fn driver_select(port: &DriverPort, fd: i32, mode: c_int, on: bool) -> c_int {
    if fd < 0 {
        return -1;
    }
    let mut mode = mode;
    let mut table = table(fd);
    if !on {
        if !table.contains_key(&fd) {
            drop(table);
            // Fast track to stop_select for an fd that was never selected.
            if mode & USE_NO_CALLBACK == USE {
                port.stop_select(fd);
            }
            return 0;
        }
        // erts does not clear the events for ERL_DRV_USE_NO_CALLBACK.
        if mode & USE_NO_CALLBACK == USE {
            mode |= READ | WRITE;
        }
    }
    // erl_check_io.c:1049: `ERTS_EV_TYPE_NIF` goes through `drv_select_steal`.
    let released = if table.get(&fd).is_some_and(|s| s.nif.is_some()) {
        steal_from_nif(&mut table, fd, port, mode, on)
    } else {
        None
    };
    // `new_drv_ev_state`: an entry of type NONE until something is selected.
    table.entry(fd).or_default();
    for (dir, bit) in DIRS.iter().enumerate() {
        if mode & bit == 0 {
            continue;
        }
        let other = table.get(&fd).and_then(|s| s.dirs[dir].owner.as_ref());
        if other.is_some_and(|owner| owner.id != port.id) {
            steal(&mut table, fd, port, mode, on);
        }
    }
    let state = table.entry(fd).or_default();
    let ctl = mode & (READ | WRITE);
    let mut stop_select = false;
    if on {
        let ctl = ctl & !state.events;
        state.events |= ctl;
        for (dir, bit) in DIRS.iter().enumerate() {
            if ctl & bit != 0 {
                state.dirs[dir].owner = Some(port.arc());
                arm(fd, state, dir);
            }
        }
        if ctl != 0 && mode & USE != 0 {
            state.used = true;
        }
    } else {
        let ctl = ctl & state.events;
        state.events &= !ctl;
        for (dir, bit) in DIRS.iter().enumerate() {
            if ctl & bit != 0 {
                disarm(state, dir);
                state.dirs[dir].owner = None;
            }
        }
        // Keep a used entry; the fd will probably be selected again.
        if state.events == 0 && (mode & USE != 0 || !state.used) {
            table.remove(&fd);
            // The entry is gone; below `state` must not be used.
        }
        stop_select = mode & USE_NO_CALLBACK == USE;
    }
    // check_fd_cleanup: an entry that never got an event is not kept.
    if table
        .get(&fd)
        .is_some_and(|state| state.events == 0 && !state.used)
    {
        table.remove(&fd);
    }
    drop(table);
    if let Some(resource) = released {
        resource.release();
    }
    if stop_select {
        port.stop_select(fd);
    }
    0
}

/// Port of erl_check_io.c:878 (deselect) for `ERTS_EV_TYPE_NIF` with mode 0: drop the
/// events and pending messages and hand back the resource the selection kept; the
/// caller releases it once the table is unlocked.
fn deselect_nif(table: &mut HashMap<i32, FdState>, fd: i32) -> Option<Arc<dyn NifSelectResource>> {
    let state = table.get_mut(&fd)?;
    for dir in 0..2 {
        disarm(state, dir);
    }
    state.events = 0;
    let nif = state.nif.take();
    if !state.used {
        table.remove(&fd);
    }
    nif.map(|nif| nif.resource)
}

/// `steal` text for a `ERTS_EV_TYPE_NIF` victim (erl_check_io.c:1638).
fn nif_victim_text(state: &FdState) -> String {
    let Some(nif) = &state.nif else {
        return "no one\n".into();
    };
    let mut text = format!("resource {}", nif.resource.type_name());
    let mut with = "with";
    for (message, label) in nif.messages.iter().zip(["in-pid", "out-pid"]) {
        if let Some(message) = message {
            text.push_str(&format!(" {with} {label} {}", message.recipient()));
            with = "and";
        }
    }
    text.push('\n');
    text
}

/// Port of erl_check_io.c:1711 (drv_select_steal) when the victim is a NIF selection.
fn steal_from_nif(
    table: &mut HashMap<i32, FdState>,
    fd: i32,
    port: &DriverPort,
    mode: c_int,
    on: bool,
) -> Option<Arc<dyn NifSelectResource>> {
    let victim = nif_victim_text(table.get(&fd)?);
    let text = format!(
        "driver_select({:#x}, {fd},{}) by {}driver #Port<0.{}> stealing control of fd={fd} from {victim}",
        port.handle() as usize,
        mode_text(mode, on),
        name_part(port),
        port.id
    );
    let released = deselect_nif(table, fd);
    port.host.log_error(&text);
    released
}

/// Port of erl_check_io.c:1236 (enif_select_x). `mode` holds `ErlNifSelectFlags`;
/// `messages` are the READ and WRITE messages prepared for an `on` selection. Failures
/// carry `INT_MIN`, like erts.
pub fn nif_select(
    resource: Arc<dyn NifSelectResource>,
    fd: i32,
    mode: c_int,
    messages: [Option<Box<dyn NifSelectMessage>>; 2],
) -> c_int {
    const STOP: c_int = 1 << 2;
    const CANCEL: c_int = 1 << 3;
    const ERROR: c_int = 1 << 5;
    const STOP_CALLED: c_int = 1;
    const INVALID_EVENT: c_int = 1 << 2;
    const FAILED: c_int = 1 << 3;
    const READ_CANCELLED: c_int = 1 << 4;
    const WRITE_CANCELLED: c_int = 1 << 5;
    const NOTSUP: c_int = 1 << 7;
    if fd < 0 {
        return i32::MIN | INVALID_EVENT;
    }
    let mut table = table(fd);
    let known = table.contains_key(&fd);
    let (on, mode) = if mode & STOP != 0 {
        if !known {
            // Fast track to the stop callback.
            drop(table);
            resource.stop(fd, true);
            return STOP_CALLED;
        }
        (false, READ | WRITE | USE)
    } else {
        // The kqueue poll set has no error event (ERTS_POLL_EV_ERR).
        if mode & ERROR != 0 {
            return i32::MIN | NOTSUP;
        }
        (mode & CANCEL == 0, mode)
    };
    let stop_mode = mode & USE != 0;
    // Stealing: another resource, or a driver holding one of the selected directions.
    let mut released = None;
    if table.get(&fd).is_some_and(|s| s.nif.is_some()) {
        let other = table
            .get(&fd)
            .and_then(|s| s.nif.as_ref())
            .is_some_and(|nif| nif.resource.id() != resource.id());
        if other {
            // Port of erl_check_io.c:1722 (nif_select_steal).
            let text = format!(
                "enif_select(_, {fd},{}, {}) stealing control of fd={fd} from {}",
                nif_mode_text(mode),
                resource.type_name(),
                nif_victim_text(&table[&fd])
            );
            released = deselect_nif(&mut table, fd);
            resource.log_error(&text);
        }
    } else if table.contains_key(&fd) && need_to_steal(&mut table, fd, mode & (READ | WRITE)) {
        let mut text = format!(
            "enif_select(_, {fd},{}, {}) stealing control of fd={fd} from ",
            nif_mode_text(mode),
            resource.type_name()
        );
        let mut deselect_mode = 0;
        if let Some(state) = table.get(&fd) {
            for (dir, bit) in DIRS.iter().enumerate() {
                if mode & bit == 0 {
                    continue;
                }
                if let Some(owner) = &state.dirs[dir].owner {
                    if deselect_mode != 0 {
                        text.push_str("and ");
                    }
                    text.push_str(if dir == 0 {
                        "input driver "
                    } else {
                        "output driver "
                    });
                    text.push_str(&format!("{}#Port<0.{}> ", name_part(owner), owner.id));
                    deselect_mode |= bit;
                }
            }
        }
        text.push('\n');
        if deselect_mode != 0 {
            deselect(&mut table, fd, deselect_mode);
        }
        resource.log_error(&text);
    }
    let state = table.entry(fd).or_default();
    let old_events = state.events;
    let mut ctl = mode & (READ | WRITE);
    let mut ret = 0;
    let mut failed = false;
    if on {
        ctl &= !old_events;
        state.events |= ctl;
        if state.nif.is_none() && ctl != 0 {
            state.nif = Some(Box::new(NifSel {
                resource: Arc::clone(&resource),
                messages: [None, None],
            }));
            resource.keep();
        }
        for (dir, bit) in DIRS.iter().enumerate() {
            if ctl & bit != 0 && !arm_dir(fd, state, dir) {
                failed = true;
            }
        }
        if failed {
            // `new_events & ERTS_POLL_EV_NVAL`: a fresh selection is undone.
            if old_events == 0
                && let Some(nif) = state.nif.take()
            {
                state.events = 0;
                released = Some(nif.resource);
            }
            ret = i32::MIN | FAILED;
        } else if let Some(nif) = state.nif.as_mut() {
            for (dir, message) in messages.into_iter().enumerate() {
                if mode & DIRS[dir] != 0 {
                    nif.messages[dir] = message;
                }
            }
        }
    } else {
        ctl &= old_events;
        state.events &= !ctl;
        for (dir, bit) in DIRS.iter().enumerate() {
            if ctl & bit != 0 {
                disarm(state, dir);
            }
        }
        if let Some(nif) = state.nif.as_mut() {
            if mode & READ != 0 && nif.messages[0].take().is_some() {
                ret |= READ_CANCELLED;
            }
            if mode & WRITE != 0 && nif.messages[1].take().is_some() {
                ret |= WRITE_CANCELLED;
            }
        }
        if stop_mode {
            // wake_poller == 0: the descriptor is out of the poll set, call stop now.
            let had_nif = state.nif.take();
            state.used = false;
            released = had_nif.map(|nif| nif.resource);
            ret |= STOP_CALLED;
        }
    }
    // check_fd_cleanup
    if table
        .get(&fd)
        .is_some_and(|s| s.events == 0 && s.nif.is_none() && !s.used)
    {
        table.remove(&fd);
    }
    drop(table);
    if stop_mode {
        resource.stop(fd, true);
    }
    if let Some(released) = released {
        released.release();
    }
    ret
}

fn nif_mode_text(mode: c_int) -> String {
    format!(
        "{}{}{}",
        if mode & 1 != 0 { " READ" } else { "" },
        if mode & 2 != 0 { " WRITE" } else { "" },
        if mode & 4 != 0 {
            " STOP"
        } else if mode & 8 != 0 {
            " CANCEL"
        } else {
            ""
        }
    )
}

/// Hand a fired registration that needs the descriptor table to the notifier thread.
fn notify(fd: i32, dir: usize, reg: u64) {
    static NOTIFIER: OnceLock<Mutex<mpsc::Sender<(i32, usize, u64)>>> = OnceLock::new();
    let sender = NOTIFIER.get_or_init(|| {
        let (tx, rx) = mpsc::channel::<(i32, usize, u64)>();
        std::thread::Builder::new()
            .name("arinsal-drv-select".into())
            .spawn(move || {
                for (fd, dir, reg) in rx {
                    fired_locked(table(fd), fd, dir, reg);
                }
            })
            .expect("start select notifier");
        Mutex::new(tx)
    });
    let _ = sender.lock().unwrap().send((fd, dir, reg));
}

/// A poll registration fired (erl_check_io.c:2102, erts_check_io) and could not become a
/// port task directly: a NIF selection sends its message; a driver selection becomes an
/// input or output task of the owning port, or is reported stale.
fn fired(fd: i32, dir: usize, reg: u64) {
    // The poller thread handles the event itself (erl_check_io.c iready/oready run in the
    // thread that polled). A callback that fires inside `driver_select` on a thread that
    // holds the shard cannot take it again: that one goes to the notifier.
    match shard(fd).try_lock() {
        Ok(guard) => fired_locked(guard, fd, dir, reg),
        Err(std::sync::TryLockError::Poisoned(poison)) => {
            fired_locked(poison.into_inner(), fd, dir, reg)
        }
        Err(std::sync::TryLockError::WouldBlock) => notify(fd, dir, reg),
    }
}

fn fired_locked(held: MutexGuard<'static, HashMap<i32, FdState>>, fd: i32, dir: usize, reg: u64) {
    let owner = {
        let mut table = held;
        let Some(state) = table.get_mut(&fd) else {
            return;
        };
        if state.dirs[dir].reg != Some(reg) {
            return;
        }
        if let Some(nif) = state.nif.as_mut() {
            // erl_check_io.c:2121 (`ERTS_EV_TYPE_NIF` in erts_check_io): the selection is
            // one-shot; the prepared message goes to its recipient.
            state.dirs[dir].reg = None;
            state.events &= !DIRS[dir];
            let message = nif.messages[dir].take();
            drop(table);
            if let Some(message) = message {
                message.deliver();
            }
            return;
        }
        let Some(owner) = state.dirs[dir].owner.clone() else {
            state.dirs[dir].reg = None;
            return;
        };
        if !owner.live() {
            // erl_check_io.c:1884 (stale_drv_select): the port died with the fd selected.
            state.dirs[dir].reg = None;
            report_stale(&owner, DIRS[dir]);
            deselect(&mut table, fd, DIRS[dir]);
            return;
        }
        owner
    };
    if !owner.schedule_io(fd, dir, reg) {
        // The port is exiting and takes no more tasks (erl_port_task.c:1517 fail).
        let mut table = table(fd);
        if let Some(state) = table.get_mut(&fd)
            && state.dirs[dir].reg == Some(reg)
        {
            state.dirs[dir].reg = None;
        }
    }
}

/// Execute the input or output task of `port` for registration `reg`: run
/// `ready_input`/`ready_output`, then re-arm the event if it is still selected
/// (`erts_io_notify_port_task_executed`). Returns the task's reductions.
///
/// Port of erts/emulator/beam/erl_port_task.c:1776-1806 (ERTS_PORT_TASK_INPUT/OUTPUT),
/// OTP-29.1.1.
pub(crate) fn ready(port: &DriverPort, fd: i32, dir: usize, reg: u64) -> i32 {
    let owner = {
        let mut table = table(fd);
        let Some(state) = table.get_mut(&fd) else {
            return 0;
        };
        if state.dirs[dir].reg != Some(reg) {
            return 0;
        }
        state.dirs[dir].reg = None;
        let Some(owner) = state.dirs[dir]
            .owner
            .clone()
            .filter(|owner| owner.id == port.id)
        else {
            return 0;
        };
        if !port.live() {
            // erl_check_io.c:1884 (stale_drv_select): the port died with the fd selected.
            report_stale(port, DIRS[dir]);
            deselect(&mut table, fd, DIRS[dir]);
            return 0;
        }
        state.dirs[dir].running = Some(reg);
        owner
    };
    let ran = owner.run_io(dir, fd, reg);
    let mut table = table(fd);
    if let Some(state) = table.get_mut(&fd)
        && state.dirs[dir].running == Some(reg)
    {
        state.dirs[dir].running = None;
        state.dirs[dir].executing = false;
        arm(fd, state, dir);
    }
    // ERTS_PORT_REDS_INPUT and ERTS_PORT_REDS_OUTPUT are equal (erl_port.h:365-366).
    if ran { REDS_INPUT } else { 0 }
}

/// Whether a scheduled ready task still owns the selected direction after taking the
/// port lock (`abort_tasks` in erl_check_io.c:662-682).
pub(crate) fn begin_io_task(port: &DriverPort, fd: i32, dir: usize, reg: u64) -> bool {
    let mut table = table(fd);
    table.get_mut(&fd).is_some_and(|state| {
        let current = io_task_matches(state, dir, reg)
            && !state.dirs[dir].executing
            && state.events & DIRS[dir] != 0
            && state.dirs[dir]
                .owner
                .as_ref()
                .is_some_and(|owner| owner.id == port.id);
        if current {
            state.dirs[dir].executing = true;
        }
        current
    })
}

fn io_task_matches(state: &FdState, dir: usize, reg: u64) -> bool {
    state.dirs[dir].running == Some(reg)
}

impl DriverPort {
    /// Port of erl_port_task.c:1776 (ERTS_PORT_TASK_INPUT/OUTPUT) with the default
    /// callbacks of io.c:7517 (no_ready_input_callback/no_ready_output_callback).
    /// `true` when a callback (or the missing-callback report) ran.
    pub(crate) fn run_io(&self, dir: usize, fd: i32, reg: u64) -> bool {
        let _guard = self.guard();
        if !self.live() || !begin_io_task(self, fd, dir, reg) {
            return false;
        }
        if let Some(native) = &self.driver.native {
            let started = std::time::Instant::now();
            if dir == 0 {
                native.ready_input(self, fd);
            } else {
                native.ready_output(self, fd);
            }
            let op = if dir == 0 { "input" } else { "output" };
            self.host
                .task_done(self, op, started.elapsed().as_nanos() as u64);
            return true;
        }
        let callback = if dir == 0 {
            self.driver.callbacks.ready_input
        } else {
            self.driver.callbacks.ready_output
        };
        match callback {
            Some(callback) => {
                let started = std::time::Instant::now();
                call2(callback, self.data(), event_of(fd));
                let op = if dir == 0 { "input" } else { "output" };
                self.host
                    .task_done(self, op, started.elapsed().as_nanos() as u64);
            }
            None => {
                let (kind, callback, bit) = if dir == 0 {
                    ("Input", "ready_input()", READ)
                } else {
                    ("Output", "ready_output()", WRITE)
                };
                self.host.log_error(&format!(
                    "#Port<0.{}>: {kind} driver '{}' {}does not implement the {callback} callback!\n",
                    self.id,
                    self.driver.name(),
                    {
                        let name = self.command_name();
                        if name == self.driver.name() || name.is_empty() {
                            String::new()
                        } else {
                            format!("({name}) ")
                        }
                    },
                ));
                driver_select(self, fd, bit | USE_NO_CALLBACK, false);
            }
        }
        true
    }

    /// Call `stop_select(event, NULL)` of the driver (io.c:7541 when it has none).
    pub(crate) fn stop_select(&self, fd: i32) {
        if let Some(native) = &self.driver.native {
            native.stop_select(fd);
            return;
        }
        match self.driver.callbacks.stop_select {
            Some(callback) => call2(callback, event_of(fd), std::ptr::null_mut()),
            None => self.host.log_error(&format!(
                "Driver does not implement stop_select callback (event={fd}, private=0x0)!\n"
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{FdState, READ, disarm, io_task_matches};

    #[test]
    fn deselect_cancels_a_queued_ready_callback() {
        let mut state = FdState {
            events: READ,
            ..FdState::default()
        };
        state.dirs[0].running = Some(17);

        assert!(io_task_matches(&state, 0, 17));
        disarm(&mut state, 0);
        assert!(!io_task_matches(&state, 0, 17));
    }

    #[test]
    fn deselect_keeps_an_executing_callback_serialized() {
        let mut state = FdState {
            events: READ,
            ..FdState::default()
        };
        state.dirs[0].running = Some(17);
        state.dirs[0].executing = true;

        disarm(&mut state, 0);
        assert!(io_task_matches(&state, 0, 17));
        assert!(state.dirs[0].running.is_some());
    }
}
