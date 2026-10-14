//! Independent environments, time, ETF, and VM extension hooks.
use crate::{ErlNifBinary, ErlNifEnv, terms};
use arinsal_term::{Term, TermBuilder, VecHeap, copy_term, from_owned};
use std::ffi::{CStr, c_char, c_int, c_uint, c_void};
use std::hint::black_box;
use std::ptr;
use std::sync::{Arc, Mutex, OnceLock};

/// The VM may register services once processes and the reactor are connected.
/// A message `enif_select` prepared for one direction: it owns its heap.
pub struct SelectMessage {
    /// Pid that gets the message.
    pub recipient: Term,
    /// Message term, living on the private heap.
    pub message: Term,
    _heap: VecHeap,
}
/// One `enif_select_x` call, handed to the VM's check-io table.
pub struct SelectRequest {
    /// `ErlNifEvent`.
    pub fd: c_int,
    /// `ErlNifSelectFlags`.
    pub flags: c_int,
    /// Resource data address (`obj`).
    pub resource: usize,
    /// READ and WRITE messages, prepared when the call selects (not cancel or stop).
    pub messages: [Option<SelectMessage>; 2],
}
/// Insert a resource monitor into a process: target pid, monitor reference, target half.
pub type ResourceMonitorHook = fn(Term, u64, Arc<crate::ResourceMonitor>) -> bool;
/// `enif_select_x` implementation (erl_check_io.c:1236).
pub type SelectHook = fn(SelectRequest) -> i32;
/// Local port lookup by registered name.
pub type WhereisPortHook = fn(Term) -> Option<Term>;
/// Whether a port term denotes a live local port.
pub type PortAliveHook = fn(Term) -> bool;
/// `enif_port_command`: sender pid, port, data.
pub type PortCommandHook = fn(Option<Term>, Term, Term) -> bool;
#[derive(Default, Clone, Copy)]
pub struct VmHooks {
    /// Deliver a term to a local process.
    pub send: Option<fn(Term, Term) -> bool>,
    /// Resolve an atom name to a pid.
    pub whereis_pid: Option<fn(Term) -> Option<Term>>,
    /// Check whether a local process is present in the caller's runtime.
    pub is_process_alive: Option<fn(Term, Term) -> bool>,
    /// `enif_select_x`.
    pub select: Option<SelectHook>,
    /// Resolve an atom name to a port.
    pub whereis_port: Option<WhereisPortHook>,
    /// Whether a port is alive.
    pub port_alive: Option<PortAliveHook>,
    /// Send a command to a port.
    pub port_command: Option<PortCommandHook>,
    /// `enif_thread_type` value of the calling thread.
    pub thread_type: Option<fn() -> c_int>,
    /// Whether the process the calling thread executes a NIF for is exiting.
    pub current_process_exiting: Option<fn() -> bool>,
    /// Send a resource monitor to a process (`erts_proc_sig_send_monitor`); false when the
    /// process cannot receive it.
    pub resource_monitor: Option<ResourceMonitorHook>,
    /// Send a demonitor signal for a resource monitor (`erts_proc_sig_send_demonitor`).
    pub resource_demonitor: Option<fn(Term, u64)>,
}
static HOOKS: OnceLock<Mutex<VmHooks>> = OnceLock::new();
pub(crate) fn hooks() -> &'static Mutex<VmHooks> {
    HOOKS.get_or_init(|| Mutex::new(VmHooks::default()))
}
/// Install VM service callbacks; each callback must keep terms live during its invocation.
pub fn set_vm_hooks(h: VmHooks) {
    *hooks().lock().unwrap() = h;
}
/// A message retained by the test hook when no VM delivery callback is installed.
pub struct SentMessage {
    pub to: Term,
    pub message: Term,
    _heap: VecHeap,
}
static MESSAGES: OnceLock<Mutex<Vec<SentMessage>>> = OnceLock::new();
fn messages() -> &'static Mutex<Vec<SentMessage>> {
    MESSAGES.get_or_init(|| Mutex::new(Vec::new()))
}
/// Drain messages recorded by the standalone host.
pub fn take_test_messages() -> Vec<SentMessage> {
    std::mem::take(&mut *messages().lock().unwrap())
}

/// Read a pid or port term the NIF caller keeps live for the callback.
fn load(p: *const Term) -> Term {
    // SAFETY: The NIF caller retains this storage for the callback.
    unsafe { *p }
}
/// Write a term to caller-provided storage, if any.
fn store(out: *mut Term, value: Term) {
    if !out.is_null() {
        // SAFETY: The NIF caller retains this storage for the callback.
        unsafe { *out = value }
    }
}
/// The calling process of a NIF environment.
fn env_pid(e: *mut ErlNifEnv) -> Option<Term> {
    // SAFETY: the NIF caller passes its live environment.
    unsafe { e.as_ref() }.and_then(|env| env.pid)
}

#[unsafe(no_mangle)]
pub extern "C" fn enif_alloc_env() -> *mut ErlNifEnv {
    Box::into_raw(Box::new(ErlNifEnv::independent()))
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_free_env(e: *mut ErlNifEnv) {
    if !e.is_null() {
        // SAFETY: enif_alloc_env returned this unique allocation.
        unsafe { drop(Box::from_raw(e)) }
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_clear_env(e: *mut ErlNifEnv) {
    if e.is_null() {
        return;
    };
    // SAFETY: The NIF caller or VM hook retains this storage for the callback.
    let env = unsafe { &mut *e };
    if env.independent {
        *env = ErlNifEnv::independent()
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_send(
    env: *mut ErlNifEnv,
    pid: *const Term,
    _msg_env: *mut ErlNifEnv,
    msg: Term,
) -> c_int {
    if pid.is_null() {
        return 0;
    };
    // SAFETY: The NIF caller or VM hook retains this storage for the callback.
    let to = load(pid);
    if to.as_pid().is_none() {
        return 0;
    };
    let (send, thread_type, exiting) = {
        let hooks = hooks().lock().unwrap();
        (hooks.send, hooks.thread_type, hooks.current_process_exiting)
    };
    // Port of erts/emulator/beam/erl_nif.c:860-885 (enif_send: a process-bound env on a dirty
    // scheduler whose process is exiting sends nothing), OTP-29.1.1.
    if !env.is_null()
        && thread_type.is_some_and(|thread_type| thread_type() > ERL_NIF_THR_NORMAL_SCHEDULER)
        && exiting.is_some_and(|exiting| exiting())
    {
        return 0;
    }
    if let Some(hook) = send {
        return i32::from(hook(to, msg));
    };
    let mut heap = VecHeap::new();
    let Ok(copy) = copy_term(msg, &mut heap) else {
        return 0;
    };
    messages().lock().unwrap().push(SentMessage {
        to,
        message: copy,
        _heap: heap,
    });
    1
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_whereis_pid(_: *mut ErlNifEnv, name: Term, out: *mut Term) -> c_int {
    let Some(hook) = hooks().lock().unwrap().whereis_pid else {
        return 0;
    };
    let Some(pid) = hook(name) else { return 0 };
    store(out, pid);
    1
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_whereis_port(_: *mut ErlNifEnv, name: Term, out: *mut Term) -> c_int {
    if name.as_atom().is_none() {
        return 0;
    }
    let Some(hook) = hooks().lock().unwrap().whereis_port else {
        return 0;
    };
    let Some(port) = hook(name) else { return 0 };
    store(out, port);
    1
}
#[unsafe(no_mangle)]
// Port of erts/emulator/beam/erl_nif.c:2323 (enif_is_process_alive), OTP-29.1.1.
pub extern "C" fn enif_is_process_alive(e: *mut ErlNifEnv, pid: *const Term) -> c_int {
    if e.is_null() || pid.is_null() {
        return 0;
    };
    let target = load(pid);
    if target.as_pid().is_none() {
        return 0;
    }
    let Some(caller) = env_pid(e) else {
        return 0;
    };
    let Some(hook) = hooks().lock().unwrap().is_process_alive else {
        return 0;
    };
    i32::from(hook(caller, target))
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_is_port_alive(_: *mut ErlNifEnv, port: *const Term) -> c_int {
    if port.is_null() {
        return 0;
    }
    let Some(hook) = hooks().lock().unwrap().port_alive else {
        return 0;
    };
    i32::from(hook(load(port)))
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_port_command(
    e: *mut ErlNifEnv,
    port: *const Term,
    _msg_env: *mut ErlNifEnv,
    msg: Term,
) -> c_int {
    if port.is_null() {
        return 0;
    }
    let Some(hook) = hooks().lock().unwrap().port_command else {
        return 0;
    };
    i32::from(hook(env_pid(e), load(port), msg))
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_select(
    e: *mut ErlNifEnv,
    event: c_int,
    flags: c_int,
    obj: *mut c_void,
    pid: *const Term,
    msg: Term,
) -> c_int {
    enif_select_x(e, event, flags, obj, pid, msg, ptr::null_mut())
}
const SELECT_READ: c_int = 1;
const SELECT_WRITE: c_int = 1 << 1;
const SELECT_STOP: c_int = 1 << 2;
const SELECT_CANCEL: c_int = 1 << 3;
const SELECT_CUSTOM_MSG: c_int = 1 << 4;
const SELECT_FAILED: c_int = 1 << 3;
/// Port of erts/emulator/sys/common/erl_check_io.c:699 (prepare_select_msg).
fn prepare_select_msg(
    recipient: Term,
    flags: c_int,
    resource: *mut c_void,
    msg: Term,
    event: &str,
) -> Option<SelectMessage> {
    let mut heap = VecHeap::new();
    let message = if flags & SELECT_CUSTOM_MSG != 0 {
        copy_term(msg, &mut heap).ok()?
    } else {
        // {select, Resource, Ref, EventAtom}
        let resource = crate::resources::resource_term(resource, &mut heap)?;
        let reference = copy_term(msg, &mut heap).ok()?;
        let atoms = arinsal_term::global_atoms();
        let tag = Term::atom(atoms.intern("select").ok()?);
        let event = Term::atom(atoms.intern(event).ok()?);
        TermBuilder::new(&mut heap)
            .tuple(&[tag, resource, reference, event])
            .ok()?
    };
    Some(SelectMessage {
        recipient,
        message,
        _heap: heap,
    })
}
/// Port of erts/emulator/sys/common/erl_check_io.c:1236 (enif_select_x), OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn enif_select_x(
    e: *mut ErlNifEnv,
    event: c_int,
    flags: c_int,
    obj: *mut c_void,
    pid: *const Term,
    msg: Term,
    _msg_env: *mut ErlNifEnv,
) -> c_int {
    let Some(hook) = hooks().lock().unwrap().select else {
        return i32::MIN | 128;
    };
    let mut messages = [None, None];
    if flags & (SELECT_STOP | SELECT_CANCEL) == 0 {
        let recipient = if pid.is_null() {
            env_pid(e)
        } else {
            Some(load(pid))
        };
        let Some(recipient) = recipient else {
            return i32::MIN | SELECT_FAILED;
        };
        for (slot, (bit, name)) in messages
            .iter_mut()
            .zip([(SELECT_READ, "ready_input"), (SELECT_WRITE, "ready_output")])
        {
            if flags & bit != 0 {
                *slot = prepare_select_msg(recipient, flags, obj, msg, name);
            }
        }
    }
    hook(SelectRequest {
        fd: event,
        flags,
        resource: obj as usize,
        messages,
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_compare_monitors(a: *const [u8; 32], b: *const [u8; 32]) -> c_int {
    if a.is_null() || b.is_null() {
        return 0;
    };
    // SAFETY: The NIF caller or VM hook retains this storage for the callback.
    unsafe { (*a).cmp(&*b) as c_int }
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_make_monitor_term(e: *mut ErlNifEnv, m: *const [u8; 32]) -> Term {
    if m.is_null() {
        return terms::enif_make_badarg(e);
    };
    // SAFETY: The NIF caller or VM hook retains this storage for the callback.
    let bytes = unsafe { &*m };
    let id = u64::from_ne_bytes(bytes[..8].try_into().unwrap());
    // SAFETY: The NIF caller or VM hook retains this storage for the callback.
    let env = unsafe { &mut *e };
    TermBuilder::new(&mut env.heap)
        .local_ref(arinsal_bifs::ordinary_ref_words(id))
        .unwrap_or_else(|_| terms::enif_make_badarg(e))
}

#[unsafe(no_mangle)]
pub extern "C" fn enif_term_to_binary(
    _e: *mut ErlNifEnv,
    value: Term,
    out: *mut ErlNifBinary,
) -> c_int {
    if out.is_null() {
        return 0;
    };
    let Ok(encoded) = arinsal_bifs::encode_term_to_binary(value) else {
        return 0;
    };
    if terms::enif_alloc_binary(encoded.len(), out) == 0 {
        return 0;
    };
    // SAFETY: The NIF caller or VM hook retains this storage for the callback.
    unsafe { ptr::copy_nonoverlapping(encoded.as_ptr(), (*out).data, encoded.len()) };
    1
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_binary_to_term(
    e: *mut ErlNifEnv,
    data: *const u8,
    len: usize,
    out: *mut Term,
    opts: c_uint,
) -> usize {
    if data.is_null() || out.is_null() || !matches!(opts, 0 | 0x20000000) {
        return 0;
    };
    // SAFETY: The NIF caller or VM hook retains this storage for the callback.
    let bytes = unsafe { std::slice::from_raw_parts(data, len) };
    let Ok((owned, consumed)) = arinsal_etf::decode_prefix(bytes) else {
        return 0;
    };
    // ERL_NIF_BIN2TERM_SAFE: a term that would create an atom fails (binary_to_term/2 [safe]).
    if opts == 0x2000_0000 && has_new_atom(&owned) {
        return 0;
    }
    // SAFETY: The NIF caller or VM hook retains this storage for the callback.
    let env = unsafe { &mut *e };
    let Ok(decoded) = from_owned(&owned, &mut env.heap) else {
        return 0;
    };
    // SAFETY: The NIF caller or VM hook retains this storage for the callback.
    unsafe { *out = decoded };
    consumed
}

/// Whether decoding `term` would create an atom (or a node name).
fn has_new_atom(term: &arinsal_etf::OwnedTerm) -> bool {
    use arinsal_etf::OwnedTerm as T;
    let new = |name: &str| arinsal_term::global_atoms().get(name).is_none();
    match term {
        T::Atom(name) => new(name),
        T::List { elems, tail } => elems.iter().any(has_new_atom) || has_new_atom(tail),
        T::Tuple(items) => items.iter().any(has_new_atom),
        T::Map(pairs) => pairs
            .iter()
            .any(|(k, v)| has_new_atom(k) || has_new_atom(v)),
        T::Pid { node, .. } | T::Port { node, .. } | T::Ref { node, .. } => new(node),
        T::Export {
            module, function, ..
        } => new(module) || new(function),
        T::Fun {
            module,
            pid,
            free_vars,
            ..
        } => new(module) || has_new_atom(pid) || free_vars.iter().any(has_new_atom),
        T::Record {
            module,
            name,
            fields,
            ..
        } => {
            new(module)
                || new(name)
                || fields
                    .iter()
                    .any(|(field, value)| new(field) || has_new_atom(value))
        }
        _ => false,
    }
}

fn freq(unit: c_int) -> Option<i128> {
    match unit {
        0 => Some(1),
        1 => Some(1_000),
        2 => Some(1_000_000),
        3 => Some(1_000_000_000),
        _ => None,
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_convert_time_unit(n: i64, from: c_int, to: c_int) -> i64 {
    let (Some(f), Some(t)) = (freq(from), freq(to)) else {
        return i64::MIN;
    };
    i64::try_from((n as i128 * t).div_euclid(f)).unwrap_or(i64::MIN)
}
/// Port of erts/emulator/beam/erl_nif.c (enif_monotonic_time, enif_time_offset,
/// enif_now_time), OTP-29.1.1: the clocks are the ones of `erlang:monotonic_time/0`,
/// `erlang:time_offset/0` and `erlang:now/0`.
fn convert_nanos(nanos: i128, unit: c_int) -> i64 {
    let Some(f) = freq(unit) else { return i64::MIN };
    i64::try_from((nanos * f).div_euclid(1_000_000_000)).unwrap_or(i64::MIN)
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_monotonic_time(unit: c_int) -> i64 {
    convert_nanos(arinsal_bifs::monotonic_time_nanos(), unit)
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_time_offset(unit: c_int) -> i64 {
    match arinsal_bifs::time_offset_nanos_value() {
        Some(offset) => convert_nanos(offset, unit),
        None => i64::MIN,
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_now_time(e: *mut ErlNifEnv) -> Term {
    let Ok(micros) = arinsal_bifs::next_now_micros() else {
        return terms::enif_make_badarg(e);
    };
    let parts = [
        Term::small(micros / 1_000_000_000_000).unwrap(),
        Term::small((micros / 1_000_000) % 1_000_000).unwrap(),
        Term::small(micros % 1_000_000).unwrap(),
    ];
    terms::enif_make_tuple_from_array(e, parts.as_ptr(), 3)
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_cpu_time(e: *mut ErlNifEnv) -> Term {
    unsafe extern "C" {
        fn arinsal_nif_cpu_micros() -> i64;
    }
    // SAFETY: the shim reads the OS process clock and owns no Rust state.
    let micros = unsafe { arinsal_nif_cpu_micros() };
    if micros < 0 {
        return terms::enif_make_badarg(e);
    }
    let parts = [
        Term::small(micros / 1_000_000_000).unwrap(),
        Term::small((micros / 1_000_000) % 1000).unwrap(),
        Term::small(micros % 1_000_000).unwrap(),
    ];
    terms::enif_make_tuple_from_array(e, parts.as_ptr(), 3)
}
// Port of erts/emulator/beam/erl_bif_unique.c (enif_make_unique_integer via
// erts_make_unique_integer): ERL_NIF_UNIQUE_POSITIVE is 1, ERL_NIF_UNIQUE_MONOTONIC is 2.
#[unsafe(no_mangle)]
pub extern "C" fn enif_make_unique_integer(e: *mut ErlNifEnv, properties: c_int) -> Term {
    let positive = properties & 1 != 0;
    if properties & 2 != 0 {
        if positive {
            let value = arinsal_bifs::next_unique_monotonic_positive();
            return match i64::try_from(value) {
                Ok(small) => terms::enif_make_long(e, small),
                Err(_) => terms::enif_make_ulong(e, value),
            };
        }
        return terms::enif_make_long(e, arinsal_bifs::next_unique_monotonic());
    }
    match arinsal_bifs::next_unique_integer(positive) {
        arinsal_bifs::UniqueInt::Small(value) => terms::enif_make_long(e, value),
        arinsal_bifs::UniqueInt::Big(value) => {
            // SAFETY: the NIF passes its live environment.
            let env = unsafe { &mut *e };
            TermBuilder::new(&mut env.heap)
                .int_from_bigint(&value)
                .unwrap_or_else(|_| terms::enif_make_badarg(e))
        }
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_getenv(key: *const c_char, value: *mut c_char, size: *mut usize) -> c_int {
    if key.is_null() || size.is_null() {
        return -1;
    };
    // SAFETY: The NIF caller or VM hook retains this storage for the callback.
    let key = unsafe { CStr::from_ptr(key) }.to_string_lossy();
    let Ok(s) = std::env::var(key.as_ref()) else {
        return 1;
    };
    let data = s.as_bytes();
    // SAFETY: The NIF caller or VM hook retains this storage for the callback.
    let cap = unsafe { *size };
    // SAFETY: The NIF caller or VM hook retains this storage for the callback.
    unsafe { *size = data.len() + 1 };
    if cap < data.len() + 1 || value.is_null() {
        return -2;
    };
    // SAFETY: The NIF caller or VM hook retains this storage for the callback.
    unsafe {
        ptr::copy_nonoverlapping(data.as_ptr(), value.cast(), data.len());
        *value.add(data.len()) = 0
    };
    0
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_thread_type() -> c_int {
    // Port of erts/emulator/beam/erl_nif.c:3593 (enif_thread_type), OTP-29.1.1.
    let hook = hooks()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
        .thread_type;
    hook.map_or(ERL_NIF_THR_UNDEFINED, |thread_type| thread_type())
}
/// `ERL_NIF_THR_UNDEFINED` from erl_nif.h.
const ERL_NIF_THR_UNDEFINED: c_int = 0;
/// `ERL_NIF_THR_NORMAL_SCHEDULER` from erl_nif.h; dirty scheduler types are larger.
const ERL_NIF_THR_NORMAL_SCHEDULER: c_int = 1;

pub(crate) fn retain_exports() {
    let exports: &[usize] = &[
        enif_alloc_env as *const () as usize,
        enif_free_env as *const () as usize,
        enif_send as *const () as usize,
        enif_term_to_binary as *const () as usize,
        enif_binary_to_term as *const () as usize,
    ];
    black_box(exports);
}
