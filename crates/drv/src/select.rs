//! `driver_select`: the driver event state of a descriptor.
//!
//! Port of erts/emulator/sys/common/erl_check_io.c (driver_select :988, deselect :878,
//! drv_select_steal :1711, iready/oready :1874, erts_check_io task execution and
//! `erts_io_notify_port_task_executed`), OTP-29.1.1, for a kqueue poll set: updates are
//! applied synchronously (`wake_poller == 0`), so `stop_select` runs inside the
//! `driver_select` call that removes the last event. `enif_select` (erl_check_io.c:1236)
//! shares the state like `ErtsDrvEventState` does: an fd is either a driver or a NIF
//! selection, and the other kind steals it.
//!
//! The state lives in the VM's one descriptor table (`ErtsDrvEventState` array): [`FdTable`]
//! gives this module the slot of a descriptor under its lock, and the poller hands readiness
//! back through [`poll_event`] while it holds the same lock, so there is no second table.

use std::ffi::c_int;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use crate::task::{call2, event_of};
use crate::{DriverPort, PortRef, REDS_INPUT, layout};

/// `ERL_DRV_READ`.
pub const READ: c_int = layout::ERL_DRV_READ as c_int;
/// `ERL_DRV_WRITE`.
pub const WRITE: c_int = layout::ERL_DRV_WRITE as c_int;
/// `ERL_DRV_USE`.
pub const USE: c_int = layout::ERL_DRV_USE as c_int;
/// `ERL_DRV_USE_NO_CALLBACK`.
pub(crate) const USE_NO_CALLBACK: c_int = layout::ERL_DRV_USE_NO_CALLBACK as c_int;

const DIRS: [c_int; 2] = [READ, WRITE];

/// The descriptor table of the VM as seen by `driver_select` (the `ErtsDrvEventState` array of
/// erl_check_io.c behind `erts_io_control`).
pub trait FdTable: Send + Sync {
    /// Run `f` on the selection slot of `fd` under the descriptor's lock, then bring the poll
    /// set in line with the directions [`FdSel`] wants polled. The result is the mask of
    /// directions the poller rejected (`ERTS_POLL_EV_NVAL`), `READ | WRITE` bits, which the
    /// table has already cleared with [`rejected`].
    fn with_slot(&self, fd: i32, f: &mut dyn FnMut(&mut SelSlot)) -> c_int;
}

static TABLE: OnceLock<Arc<dyn FdTable>> = OnceLock::new();

/// Install the process-wide descriptor table; later calls are ignored.
pub fn set_fd_table(table: Arc<dyn FdTable>) {
    let _ = TABLE.set(table);
}

/// Work to do once the descriptor lock is released.
pub type Action = Box<dyn FnOnce() + Send>;

/// `inport`/`outport` with the armed and in-flight state of that direction.
#[derive(Default)]
struct Dir {
    /// Port that selected this direction (`select->inport`/`outport`).
    owner: Option<PortRef>,
    /// Registration of the armed event or of its ready task (`active_events`).
    reg: Option<u64>,
    /// The poll set holds this direction (`reg` is set and no readiness was seen yet).
    polled: bool,
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
pub struct FdSel {
    /// `state->driver.nif` while the type is `ERTS_EV_TYPE_NIF`; a pointer, as erts keeps it in
    /// the union of the descriptor state.
    nif: Option<Box<NifSel>>,
    /// `state->events`: `READ | WRITE`.
    events: c_int,
    /// `ERTS_EV_FLAG_USED`: `ERL_DRV_USE` was given when the events were set.
    used: bool,
    dirs: [Dir; 2],
}

/// The selection state of one descriptor in the table: allocated by the first selection,
/// released when nothing is selected any more (`ERTS_EV_TYPE_NONE`).
pub type SelSlot = Option<Box<FdSel>>;

/// The directions the poll set must hold for `slot` (`active_events`), as `(read, write)`.
pub fn wanted(slot: &SelSlot) -> (bool, bool) {
    slot.as_ref().map_or((false, false), |sel| {
        (sel.dirs[0].polled, sel.dirs[1].polled)
    })
}

/// Whether the polled directions belong to a driver (`driver_select`) rather than a NIF.
pub fn is_driver_selection(slot: &SelSlot) -> bool {
    slot.as_ref().is_some_and(|sel| sel.nif.is_none())
}

/// Polled directions of a driver selection and of a NIF selection, for `check_io_debug`.
pub fn selection_counts(slot: &SelSlot) -> (usize, usize) {
    let Some(sel) = slot else {
        return (0, 0);
    };
    let polled = sel.dirs.iter().filter(|dir| dir.polled).count();
    if sel.nif.is_some() {
        (0, polled)
    } else {
        (polled, 0)
    }
}

/// The poller rejected the descriptor (`ERTS_POLL_EV_NVAL`): nothing is polled any more. The
/// result is the mask of directions that were.
pub fn rejected(slot: &mut SelSlot) -> c_int {
    let Some(sel) = slot else {
        return 0;
    };
    let mut mask = 0;
    for (dir, bit) in DIRS.iter().enumerate() {
        if std::mem::take(&mut sel.dirs[dir].polled) {
            mask |= bit;
        }
    }
    mask
}

/// The slot with the fd lock held, as the erl_check_io.c functions see `ErtsDrvEventState`.
struct Table<'a>(&'a mut SelSlot);

impl Table<'_> {
    fn get(&self) -> Option<&FdSel> {
        self.0.as_deref()
    }

    fn get_mut(&mut self) -> Option<&mut FdSel> {
        self.0.as_deref_mut()
    }

    fn contains(&self) -> bool {
        self.0.is_some()
    }

    fn remove(&mut self) {
        *self.0 = None;
    }

    /// `new_drv_ev_state`: an entry of type NONE until something is selected.
    fn entry(&mut self) -> &mut FdSel {
        self.0.get_or_insert_with(Default::default)
    }
}

/// Run `f` on the slot of `fd` under its lock. The second result is the mask of directions the
/// poller rejected while the table brought the poll set in line.
fn locked<R>(fd: i32, f: impl FnOnce(&mut Table) -> R) -> (R, c_int) {
    let mut f = Some(f);
    let mut out = None;
    let mut run = |slot: &mut SelSlot| {
        if let Some(f) = f.take() {
            out = Some(f(&mut Table(slot)));
        }
    };
    let rejected_mask = match TABLE.get() {
        Some(table) => table.with_slot(fd, &mut run),
        // No table (no VM): nothing can be polled.
        None => {
            let mut slot = None;
            run(&mut slot);
            rejected(&mut slot)
        }
    };
    (out.expect("the slot callback ran"), rejected_mask)
}

/// `locked` for a driver selection: a rejected descriptor is reported ready at once
/// (`new_events & (ERR|NVAL)` in driver_select) and the driver finds the error.
fn locked_driver<R>(fd: i32, f: impl FnOnce(&mut Table) -> R) -> R {
    let (result, mask) = locked(fd, f);
    if mask != 0 {
        ready_now(fd, mask);
    }
    result
}

fn ready_now(fd: i32, mask: c_int) {
    let (scheduled, _) = locked(fd, |table| {
        let mut scheduled = Vec::new();
        if let Some(state) = table.get_mut() {
            for (dir, bit) in DIRS.iter().enumerate() {
                if mask & bit != 0
                    && state.nif.is_none()
                    && let Some(owner) = state.dirs[dir].owner.clone()
                {
                    let id = next_registration();
                    state.dirs[dir].reg = Some(id);
                    scheduled.push((owner, dir, id));
                }
            }
        }
        scheduled
    });
    for (owner, dir, id) in scheduled {
        if !owner.schedule_io(fd, dir, id) {
            clear_reg(fd, dir, id);
        }
    }
}

/// The port is exiting and takes no more tasks (erl_port_task.c:1517 fail).
fn clear_reg(fd: i32, dir: usize, reg: u64) {
    locked(fd, |table| {
        if let Some(state) = table.get_mut()
            && state.dirs[dir].reg == Some(reg)
        {
            state.dirs[dir].reg = None;
        }
    });
}

fn next_registration() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

/// Arm direction `dir` if it is selected, not armed and not running
/// (`state->active_events |= ...` plus `erts_io_control`); the table updates the poll set when
/// the slot is released.
fn arm_dir(state: &mut FdSel, dir: usize) {
    let slot = &mut state.dirs[dir];
    if state.events & DIRS[dir] == 0 || slot.reg.is_some() || slot.running.is_some() {
        return;
    }
    slot.reg = Some(next_registration());
    slot.polled = true;
}

fn disarm(state: &mut FdSel, dir: usize) {
    // erl_check_io.c:1161-1164 (`abort_tasks`): deselection cancels a ready task
    // that has been scheduled but has not acquired the port lock yet.
    if !state.dirs[dir].executing {
        state.dirs[dir].running = None;
    }
    state.dirs[dir].reg = None;
    state.dirs[dir].polled = false;
}

/// Port of erl_check_io.c:878 (deselect): drop `mode` (all when zero); an entry without
/// events leaves the table (`ERTS_EV_TYPE_NONE`).
fn deselect(table: &mut Table, mode: c_int) {
    let Some(state) = table.get_mut() else {
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
        table.remove();
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
fn need_to_steal(table: &mut Table, mode: c_int) -> bool {
    let mut steal = false;
    for (dir, bit) in DIRS.iter().enumerate() {
        if mode & bit == 0 {
            continue;
        }
        let Some(owner) = table.get().and_then(|s| s.dirs[dir].owner.clone()) else {
            continue;
        };
        if owner.live() {
            steal = true;
        } else {
            report_stale(&owner, *bit);
            deselect(table, *bit);
        }
    }
    steal
}

/// Port of erl_check_io.c:1711 (drv_select_steal) and :1616 (steal).
fn steal(table: &mut Table, fd: i32, port: &DriverPort, mode: c_int, on: bool) {
    if !need_to_steal(table, mode) {
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
    if let Some(state) = table.get() {
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
        deselect(table, deselect_mode);
    }
    port.host.log_error(&text);
}

/// Port of erl_check_io.c:988 (driver_select). `fd` is the descriptor behind the
/// `ErlDrvEvent`.
pub(crate) fn driver_select(port: &DriverPort, fd: i32, mode: c_int, on: bool) -> c_int {
    if fd < 0 {
        return -1;
    }
    type Outcome = (Option<bool>, Option<Arc<dyn NifSelectResource>>, bool);
    let (outcome, rejected_mask): (Outcome, c_int) = locked(fd, |table| {
        let mut mode = mode;
        if !on {
            if !table.contains() {
                // Fast track to stop_select for an fd that was never selected.
                return (Some(mode & USE_NO_CALLBACK == USE), None, false);
            }
            // erts does not clear the events for ERL_DRV_USE_NO_CALLBACK.
            if mode & USE_NO_CALLBACK == USE {
                mode |= READ | WRITE;
            }
        }
        // erl_check_io.c:1049: `ERTS_EV_TYPE_NIF` goes through `drv_select_steal`.
        let released = if table.get().is_some_and(|s| s.nif.is_some()) {
            steal_from_nif(table, fd, port, mode, on)
        } else {
            None
        };
        // `new_drv_ev_state`: an entry of type NONE until something is selected.
        table.entry();
        for (dir, bit) in DIRS.iter().enumerate() {
            if mode & bit == 0 {
                continue;
            }
            let other = table.get().and_then(|s| s.dirs[dir].owner.as_ref());
            if other.is_some_and(|owner| owner.id != port.id) {
                steal(table, fd, port, mode, on);
            }
        }
        let state = table.entry();
        let ctl = mode & (READ | WRITE);
        let mut stop_select = false;
        if on {
            let ctl = ctl & !state.events;
            state.events |= ctl;
            for (dir, bit) in DIRS.iter().enumerate() {
                if ctl & bit != 0 {
                    state.dirs[dir].owner = Some(port.arc());
                    arm_dir(state, dir);
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
                table.remove();
                // The entry is gone; below `state` must not be used.
            }
            stop_select = mode & USE_NO_CALLBACK == USE;
        }
        // check_fd_cleanup: an entry that never got an event is not kept.
        if table
            .get()
            .is_some_and(|state| state.events == 0 && !state.used)
        {
            table.remove();
        }
        (None, released, stop_select)
    });
    let (early_stop, released, stop_select) = outcome;
    if let Some(stop) = early_stop {
        if stop {
            port.stop_select(fd);
        }
        return 0;
    }
    if rejected_mask != 0 {
        ready_now(fd, rejected_mask);
    }
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
fn deselect_nif(table: &mut Table) -> Option<Arc<dyn NifSelectResource>> {
    let state = table.get_mut()?;
    for dir in 0..2 {
        disarm(state, dir);
    }
    state.events = 0;
    let nif = state.nif.take();
    if !state.used {
        table.remove();
    }
    nif.map(|nif| nif.resource)
}

/// `steal` text for a `ERTS_EV_TYPE_NIF` victim (erl_check_io.c:1638).
fn nif_victim_text(state: &FdSel) -> String {
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
    table: &mut Table,
    fd: i32,
    port: &DriverPort,
    mode: c_int,
    on: bool,
) -> Option<Arc<dyn NifSelectResource>> {
    let victim = nif_victim_text(table.get()?);
    let text = format!(
        "driver_select({:#x}, {fd},{}) by {}driver #Port<0.{}> stealing control of fd={fd} from {victim}",
        port.handle() as usize,
        mode_text(mode, on),
        name_part(port),
        port.id
    );
    let released = deselect_nif(table);
    port.host.log_error(&text);
    released
}

/// What the first pass of [`nif_select`] decided.
enum NifPass {
    /// STOP of a descriptor nobody selected: straight to the stop callback.
    Fast,
    Ran {
        on: bool,
        mode: c_int,
        stop_mode: bool,
        released: Option<Arc<dyn NifSelectResource>>,
        ret: c_int,
        old_events: c_int,
        ctl: c_int,
        prev: [Option<Box<dyn NifSelectMessage>>; 2],
    },
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
    // The kqueue poll set has no error event (ERTS_POLL_EV_ERR).
    if mode & STOP == 0 && mode & ERROR != 0 {
        return i32::MIN | NOTSUP;
    }
    let mut messages = Some(messages);
    let (pass, rejected_mask) = locked(fd, |table| {
        let known = table.contains();
        let (on, mode) = if mode & STOP != 0 {
            if !known {
                // Fast track to the stop callback.
                return NifPass::Fast;
            }
            (false, READ | WRITE | USE)
        } else {
            (mode & CANCEL == 0, mode)
        };
        let stop_mode = mode & USE != 0;
        // Stealing: another resource, or a driver holding one of the selected directions.
        let mut released = None;
        if table.get().is_some_and(|s| s.nif.is_some()) {
            let other = table
                .get()
                .and_then(|s| s.nif.as_ref())
                .is_some_and(|nif| nif.resource.id() != resource.id());
            if other {
                // Port of erl_check_io.c:1722 (nif_select_steal).
                let text = format!(
                    "enif_select(_, {fd},{}, {}) stealing control of fd={fd} from {}",
                    nif_mode_text(mode),
                    resource.type_name(),
                    table.get().map(nif_victim_text).unwrap_or_default()
                );
                released = deselect_nif(table);
                resource.log_error(&text);
            }
        } else if table.contains() && need_to_steal(table, mode & (READ | WRITE)) {
            let mut text = format!(
                "enif_select(_, {fd},{}, {}) stealing control of fd={fd} from ",
                nif_mode_text(mode),
                resource.type_name()
            );
            let mut deselect_mode = 0;
            if let Some(state) = table.get() {
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
                deselect(table, deselect_mode);
            }
            resource.log_error(&text);
        }
        let state = table.entry();
        let old_events = state.events;
        let mut ctl = mode & (READ | WRITE);
        let mut ret = 0;
        let mut prev: [Option<Box<dyn NifSelectMessage>>; 2] = [None, None];
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
                if ctl & bit != 0 {
                    arm_dir(state, dir);
                }
            }
            if let Some(nif) = state.nif.as_mut() {
                let messages = messages.take().expect("messages are consumed once");
                for (dir, message) in messages.into_iter().enumerate() {
                    if mode & DIRS[dir] != 0 {
                        prev[dir] = std::mem::replace(&mut nif.messages[dir], message);
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
            .get()
            .is_some_and(|s| s.events == 0 && s.nif.is_none() && !s.used)
        {
            table.remove();
        }
        NifPass::Ran {
            on,
            mode,
            stop_mode,
            released,
            ret,
            old_events,
            ctl,
            prev,
        }
    });
    let NifPass::Ran {
        on,
        mode,
        stop_mode,
        mut released,
        mut ret,
        old_events,
        ctl,
        mut prev,
    } = pass
    else {
        resource.stop(fd, true);
        return STOP_CALLED;
    };
    let mut extra = None;
    if on && rejected_mask & ctl != 0 {
        // `new_events & ERTS_POLL_EV_NVAL`: the poller took none of the new directions.
        let (undone, _) = locked(fd, |table| {
            let mut undone = None;
            if let Some(state) = table.get_mut() {
                for (dir, bit) in DIRS.iter().enumerate() {
                    if rejected_mask & ctl & bit != 0 {
                        state.dirs[dir].reg = None;
                    }
                }
                if old_events == 0 {
                    // A fresh selection is undone.
                    if let Some(nif) = state.nif.take() {
                        state.events = 0;
                        undone = Some(nif.resource);
                    }
                } else if let Some(nif) = state.nif.as_mut() {
                    for dir in 0..2 {
                        if mode & DIRS[dir] != 0 {
                            nif.messages[dir] = prev[dir].take();
                        }
                    }
                }
            }
            if table
                .get()
                .is_some_and(|s| s.events == 0 && s.nif.is_none() && !s.used)
            {
                table.remove();
            }
            undone
        });
        extra = undone;
        ret = i32::MIN | FAILED;
    }
    if stop_mode {
        resource.stop(fd, true);
    }
    for resource in [released.take(), extra].into_iter().flatten() {
        resource.release();
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

/// The poller saw `readable`/`writable`/`error` on `fd` (erl_check_io.c:2102, erts_check_io),
/// with the descriptor lock held. A NIF selection sends its message; a driver selection becomes
/// an input or output task of the owning port, or is reported stale. The result is the work to
/// do once the lock is released, and the number of driver reads that fired (the re-enable count
/// of `erts_io_notify_port_task_executed`).
pub fn poll_event(
    slot: &mut SelSlot,
    fd: i32,
    readable: bool,
    writable: bool,
    error: bool,
) -> (Vec<Action>, u32) {
    let mut actions: Vec<Action> = Vec::new();
    let mut driver_reads = 0;
    #[allow(clippy::needless_range_loop)]
    for dir in 0..2 {
        let Some(state) = slot.as_deref_mut() else {
            break;
        };
        let seen = if dir == 0 { readable } else { writable };
        if !state.dirs[dir].polled || !(error || seen) {
            continue;
        }
        state.dirs[dir].polled = false;
        let Some(reg) = state.dirs[dir].reg else {
            continue;
        };
        if let Some(nif) = state.nif.as_mut() {
            // erl_check_io.c:2121 (`ERTS_EV_TYPE_NIF` in erts_check_io): the selection is
            // one-shot; the prepared message goes to its recipient.
            state.dirs[dir].reg = None;
            state.events &= !DIRS[dir];
            if let Some(message) = nif.messages[dir].take() {
                actions.push(Box::new(move || message.deliver()));
            }
            continue;
        }
        let Some(owner) = state.dirs[dir].owner.clone() else {
            state.dirs[dir].reg = None;
            continue;
        };
        if !owner.live() {
            // erl_check_io.c:1884 (stale_drv_select): the port died with the fd selected.
            state.dirs[dir].reg = None;
            report_stale(&owner, DIRS[dir]);
            deselect(&mut Table(slot), DIRS[dir]);
            continue;
        }
        if dir == 0 {
            driver_reads += 1;
        }
        actions.push(Box::new(move || {
            if !owner.schedule_io(fd, dir, reg) {
                // The port is exiting and takes no more tasks (erl_port_task.c:1517 fail).
                clear_reg(fd, dir, reg);
            }
        }));
    }
    (actions, driver_reads)
}

/// Execute the input or output task of `port` for registration `reg`: run
/// `ready_input`/`ready_output`, then re-arm the event if it is still selected
/// (`erts_io_notify_port_task_executed`). Returns the task's reductions.
///
/// Port of erts/emulator/beam/erl_port_task.c:1776-1806 (ERTS_PORT_TASK_INPUT/OUTPUT),
/// OTP-29.1.1.
pub(crate) fn ready(port: &DriverPort, fd: i32, dir: usize, reg: u64) -> i32 {
    let owner = locked_driver(fd, |table| {
        let state = table.get_mut()?;
        if state.dirs[dir].reg != Some(reg) {
            return None;
        }
        state.dirs[dir].reg = None;
        let owner = state.dirs[dir]
            .owner
            .clone()
            .filter(|owner| owner.id == port.id)?;
        if !port.live() {
            // erl_check_io.c:1884 (stale_drv_select): the port died with the fd selected.
            report_stale(port, DIRS[dir]);
            deselect(table, DIRS[dir]);
            return None;
        }
        table.get_mut()?.dirs[dir].running = Some(reg);
        Some(owner)
    });
    let Some(owner) = owner else {
        return 0;
    };
    let ran = owner.run_io(dir, fd, reg);
    locked_driver(fd, |table| {
        if let Some(state) = table.get_mut()
            && state.dirs[dir].running == Some(reg)
        {
            state.dirs[dir].running = None;
            state.dirs[dir].executing = false;
            arm_dir(state, dir);
        }
    });
    // ERTS_PORT_REDS_INPUT and ERTS_PORT_REDS_OUTPUT are equal (erl_port.h:365-366).
    if ran { REDS_INPUT } else { 0 }
}

/// Whether a scheduled ready task still owns the selected direction after taking the
/// port lock (`abort_tasks` in erl_check_io.c:662-682).
pub(crate) fn begin_io_task(port: &DriverPort, fd: i32, dir: usize, reg: u64) -> bool {
    locked(fd, |table| {
        table.get_mut().is_some_and(|state| {
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
    })
    .0
}

fn io_task_matches(state: &FdSel, dir: usize, reg: u64) -> bool {
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
    use super::{FdSel, READ, disarm, io_task_matches};

    #[test]
    fn deselect_cancels_a_queued_ready_callback() {
        let mut state = FdSel {
            events: READ,
            ..FdSel::default()
        };
        state.dirs[0].running = Some(17);

        assert!(io_task_matches(&state, 0, 17));
        disarm(&mut state, 0);
        assert!(!io_task_matches(&state, 0, 17));
    }

    #[test]
    fn deselect_keeps_an_executing_callback_serialized() {
        let mut state = FdSel {
            events: READ,
            ..FdSel::default()
        };
        state.dirs[0].running = Some(17);
        state.dirs[0].executing = true;

        disarm(&mut state, 0);
        assert!(io_task_matches(&state, 0, 17));
        assert!(state.dirs[0].running.is_some());
    }
}
