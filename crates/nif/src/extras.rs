//! Independent environments, time, ETF, and VM extension hooks.
use crate::{ErlNifBinary, ErlNifEnv, term, terms};
use arinsal_bifs::Ctx;
use arinsal_term::{Term, TermBuilder, VecHeap, copy_term, from_owned};
use std::ffi::{CStr, c_char, c_int, c_uint, c_void};
use std::hint::black_box;
use std::ptr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// The VM may register services once processes and the reactor are connected.
/// Reactor event registration callback.
pub type SelectHook = fn(usize, i32, usize, Option<Term>, Term) -> i32;
/// Resource process monitor registration callback.
pub type MonitorHook = fn(usize, Term, &mut [u8; 32]) -> i32;
#[derive(Default, Clone, Copy)]
pub struct VmHooks {
    /// Deliver a term to a local process.
    pub send: Option<fn(Term, Term) -> bool>,
    /// Resolve an atom name to a pid.
    pub whereis_pid: Option<fn(Term) -> Option<Term>>,
    /// Register or cancel a reactor event.
    pub select: Option<SelectHook>,
    /// Register a process monitor for a native resource.
    pub monitor: Option<MonitorHook>,
    /// Remove a process monitor.
    pub demonitor: Option<fn(usize, &[u8; 32]) -> i32>,
    /// `enif_thread_type` value of the calling thread.
    pub thread_type: Option<fn() -> c_int>,
    /// Whether the process the calling thread executes a NIF for is exiting.
    pub current_process_exiting: Option<fn() -> bool>,
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
    _: *mut ErlNifEnv,
    pid: *const Term,
    _msg_env: *mut ErlNifEnv,
    msg: Term,
) -> c_int {
    if pid.is_null() {
        return 0;
    };
    // SAFETY: The NIF caller or VM hook retains this storage for the callback.
    let to = unsafe { *pid };
    if to.as_pid().is_none() {
        return 0;
    };
    if let Some(hook) = hooks().lock().unwrap().send {
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
    if !out.is_null() {
        // SAFETY: The NIF caller or VM hook retains this storage for the callback.
        unsafe { *out = pid }
    };
    1
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_whereis_port(_: *mut ErlNifEnv, _name: Term, _out: *mut Term) -> c_int {
    0
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_is_process_alive(e: *mut ErlNifEnv, pid: *const Term) -> c_int {
    if pid.is_null() {
        return 0;
    };
    i32::from(
        // SAFETY: The NIF caller or VM hook retains this storage for the callback.
        unsafe { *pid } == unsafe { (*e).pid }.unwrap_or(term(0)),
    )
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_is_port_alive(_: *mut ErlNifEnv, _port: *const Term) -> c_int {
    0
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_port_command(
    _: *mut ErlNifEnv,
    _port: *const Term,
    _msg_env: *mut ErlNifEnv,
    _msg: Term,
) -> c_int {
    0
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_select(
    e: *mut ErlNifEnv,
    event: usize,
    flags: c_int,
    obj: *mut c_void,
    pid: *const Term,
    reference: Term,
) -> c_int {
    let _ = e;
    let Some(hook) = hooks().lock().unwrap().select else {
        return 128;
    };
    let target = if pid.is_null() {
        None
    } else {
        Some(
            // SAFETY: The NIF caller or VM hook retains this storage for the callback.
            unsafe { *pid },
        )
    };
    hook(event, flags, obj as usize, target, reference)
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_select_x(
    e: *mut ErlNifEnv,
    event: usize,
    flags: c_int,
    obj: *mut c_void,
    pid: *const Term,
    msg: Term,
    _msg_env: *mut ErlNifEnv,
) -> c_int {
    enif_select(e, event, flags, obj, pid, msg)
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_monitor_process(
    _: *mut ErlNifEnv,
    obj: *mut c_void,
    pid: *const Term,
    monitor: *mut [u8; 32],
) -> c_int {
    if pid.is_null() || monitor.is_null() {
        return -1;
    };
    let Some(hook) = hooks().lock().unwrap().monitor else {
        return 1;
    };
    hook(
        obj as usize,
        // SAFETY: The NIF caller or VM hook retains this storage for the callback.
        unsafe { *pid },
        // SAFETY: The NIF caller or VM hook retains this storage for the callback.
        unsafe { &mut *monitor },
    )
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_demonitor_process(
    _: *mut ErlNifEnv,
    obj: *mut c_void,
    monitor: *const [u8; 32],
) -> c_int {
    if monitor.is_null() {
        return -1;
    };
    let Some(hook) = hooks().lock().unwrap().demonitor else {
        return 1;
    };
    hook(
        obj as usize,
        // SAFETY: The NIF caller or VM hook retains this storage for the callback.
        unsafe { &*monitor },
    )
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
        .local_ref([id as u32, (id >> 32) as u32, 0])
        .unwrap_or_else(|_| terms::enif_make_badarg(e))
}

#[unsafe(no_mangle)]
pub extern "C" fn enif_term_to_binary(
    e: *mut ErlNifEnv,
    value: Term,
    out: *mut ErlNifBinary,
) -> c_int {
    if out.is_null() {
        return 0;
    };
    // SAFETY: The NIF caller or VM hook retains this storage for the callback.
    let env = unsafe { &mut *e };
    let mut ctx = Ctx::new(&mut env.heap);
    let Some(f) = arinsal_bifs::lookup("erlang", "term_to_binary", 1) else {
        return 0;
    };
    let Ok(encoded) = f(&mut ctx, &[value]) else {
        return 0;
    };
    let mut b = ErlNifBinary::default();
    if terms::enif_inspect_binary(e, encoded, &mut b) == 0 {
        return 0;
    };
    if terms::enif_alloc_binary(b.size, out) == 0 {
        return 0;
    };
    // SAFETY: The NIF caller or VM hook retains this storage for the callback.
    unsafe { ptr::copy_nonoverlapping(b.data, (*out).data, b.size) };
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
    // SAFETY: The NIF caller or VM hook retains this storage for the callback.
    let env = unsafe { &mut *e };
    let Ok(decoded) = from_owned(&owned, &mut env.heap) else {
        return 0;
    };
    // SAFETY: The NIF caller or VM hook retains this storage for the callback.
    unsafe { *out = decoded };
    consumed
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
static START: OnceLock<Instant> = OnceLock::new();
#[unsafe(no_mangle)]
pub extern "C" fn enif_monotonic_time(unit: c_int) -> i64 {
    let Some(f) = freq(unit) else { return i64::MIN };
    let nanos = START.get_or_init(Instant::now).elapsed().as_nanos() as i128;
    i64::try_from(nanos * f / 1_000_000_000).unwrap_or(i64::MIN)
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_time_offset(unit: c_int) -> i64 {
    let Some(f) = freq(unit) else { return i64::MIN };
    let wall = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as i128;
    let mono = START.get_or_init(Instant::now).elapsed().as_nanos() as i128;
    i64::try_from((wall - mono) * f / 1_000_000_000).unwrap_or(i64::MIN)
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_now_time(e: *mut ErlNifEnv) -> Term {
    let micros = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as i64;
    let parts = [
        Term::small(micros / 1_000_000_000).unwrap(),
        Term::small((micros / 1_000_000) % 1000).unwrap(),
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
static UNIQUE: AtomicU64 = AtomicU64::new(0);
#[unsafe(no_mangle)]
pub extern "C" fn enif_make_unique_integer(e: *mut ErlNifEnv, properties: c_int) -> Term {
    let n = UNIQUE.fetch_add(1, Ordering::Relaxed);
    let value = if properties & 1 != 0 {
        n as i64
    } else {
        -(n as i64) - 1
    };
    terms::enif_make_long(e, value)
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
