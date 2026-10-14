//! Unix implementations of the OTP 29.1.1 `prim_socket` and `prim_net` NIFs.
//!
//! Socket resources use local references. The scheduler supplies a [`Reactor`]
//! and calls [`owner_died`] when a controlling process exits. No socket call
//! waits for readiness on a scheduler thread.

use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use arinsal_bifs::{BifError, BifFn, Ctx};
use arinsal_etf::OwnedTerm as O;
use arinsal_term::{ExportEntry, FunEntry, HeapAlloc, Node, Term, from_owned, to_owned};

mod net;
mod socket;

/// `ERL_NIF_SELECT_STOP_CALLED`: the stop callback ran directly.
pub const SELECT_STOP_CALLED: i32 = 1 << 0;
/// `ERL_NIF_SELECT_STOP_SCHEDULED`: the stop callback runs later.
pub const SELECT_STOP_SCHEDULED: i32 = 1 << 1;
/// `ERL_NIF_SELECT_INVALID_EVENT`.
pub const SELECT_INVALID_EVENT: i32 = 1 << 2;
/// `ERL_NIF_SELECT_FAILED`.
pub const SELECT_FAILED: i32 = 1 << 3;
/// `ERL_NIF_SELECT_READ_CANCELLED`: a pending read selection was cancelled.
pub const SELECT_READ_CANCELLED: i32 = 1 << 4;
/// `ERL_NIF_SELECT_WRITE_CANCELLED`: a pending write selection was cancelled.
pub const SELECT_WRITE_CANCELLED: i32 = 1 << 5;

/// The scheduler services the socket NIFs use: `enif_self`, `enif_select`,
/// `enif_send` and `enif_monitor_process`.
///
/// Every `enif_select` style method returns the erts result: a negative value
/// is a failure (`INT_MIN | ERL_NIF_SELECT_*`), otherwise the flag bits.
pub trait Reactor: Send + Sync {
    /// The process executing the current NIF call, `enif_self`.
    fn self_pid(&self) -> Option<O>;
    /// `enif_select(env, fd, ERL_NIF_SELECT_READ, obj, pid, msg)`: a one-shot
    /// input selection. The select message goes to `pid`. A selection that is
    /// still pending for the same fd and mode is replaced.
    fn register_read(&self, fd: i32, pid: &O, handle: &O, reference: &O) -> i32;
    /// `enif_select(env, fd, ERL_NIF_SELECT_WRITE, obj, pid, msg)`; see
    /// [`Reactor::register_read`].
    fn register_write(&self, fd: i32, pid: &O, handle: &O, reference: &O) -> i32;
    /// `enif_select(env, fd, ERL_NIF_SELECT_CANCEL | mode, obj, NULL, undefined)`.
    /// Returns `SELECT_READ_CANCELLED` or `SELECT_WRITE_CANCELLED` when a
    /// selection was still pending (its message not yet sent), else 0. erts
    /// cancels by fd and mode, so `reference` is not used to match.
    fn cancel(&self, fd: i32, read: bool, reference: &O) -> i32;
    /// `enif_select(env, fd, ERL_NIF_SELECT_STOP, obj, NULL, undefined)`: drop
    /// every selection of `fd`. Returns `SELECT_STOP_CALLED` or `SELECT_STOP_SCHEDULED`.
    fn stop(&self, fd: i32) -> i32;
    /// `enif_send(env, pid, NULL, msg)`. Returns whether the message was sent.
    fn send(&self, pid: &O, message: &O) -> bool;
    /// `enif_monitor_process(env, obj, pid, &mon)`. Returns a monitor handle,
    /// or `None` when the runtime has no monitor facility for resources.
    fn monitor(&self, _pid: &O, _handle: &O) -> Option<u64> {
        None
    }
    /// `enif_demonitor_process(env, obj, &mon)`.
    fn demonitor(&self, _monitor: u64) {}
}

/// A pending selection of the [`BlockingReactor`].
struct BlockingSelection {
    fd: i32,
    pid: O,
    reference: O,
    events: i16,
}

/// A poll-based reactor for tests and a single-threaded bootstrap VM.
#[derive(Default)]
pub struct BlockingReactor {
    pending: Mutex<Vec<BlockingSelection>>,
    caller: Mutex<Option<O>>,
    sent: Mutex<Vec<(O, O)>>,
}

impl BlockingReactor {
    /// Set the process reported by [`Reactor::self_pid`].
    pub fn set_caller(&self, pid: O) {
        *self.caller.lock().unwrap() = Some(pid);
    }

    /// Messages sent through [`Reactor::send`], with their destination.
    pub fn sent(&self) -> Vec<(O, O)> {
        self.sent.lock().unwrap().clone()
    }

    /// Wait until one registered fd is ready, returning its pid and select reference.
    pub fn wait(&self, timeout: Duration) -> Option<(O, O)> {
        let mut fds: Vec<libc::pollfd> = {
            let pending = self.pending.lock().unwrap();
            pending
                .iter()
                .map(|selection| libc::pollfd {
                    fd: selection.fd,
                    events: selection.events,
                    revents: 0,
                })
                .collect()
        };
        if fds.is_empty() {
            return None;
        }
        let milliseconds = timeout.as_millis().min(i32::MAX as u128) as i32;
        // SAFETY: fds is writable and its length matches nfds.
        let ready =
            unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, milliseconds) };
        if ready <= 0 {
            return None;
        }
        let index = fds.iter().position(|fd| fd.revents != 0)?;
        let mut pending = self.pending.lock().unwrap();
        let index = pending
            .iter()
            .position(|selection| selection.fd == fds[index].fd)?;
        let selection = pending.remove(index);
        Some((selection.pid, selection.reference))
    }

    fn select(&self, fd: i32, pid: &O, reference: &O, events: i16) -> i32 {
        let mut pending = self.pending.lock().unwrap();
        pending.retain(|selection| selection.fd != fd || selection.events != events);
        pending.push(BlockingSelection {
            fd,
            pid: pid.clone(),
            reference: reference.clone(),
            events,
        });
        0
    }
}

impl Reactor for BlockingReactor {
    fn self_pid(&self) -> Option<O> {
        self.caller.lock().unwrap().clone()
    }
    fn register_read(&self, fd: i32, pid: &O, _handle: &O, reference: &O) -> i32 {
        self.select(fd, pid, reference, libc::POLLIN)
    }
    fn register_write(&self, fd: i32, pid: &O, _handle: &O, reference: &O) -> i32 {
        self.select(fd, pid, reference, libc::POLLOUT)
    }
    fn cancel(&self, fd: i32, read: bool, _reference: &O) -> i32 {
        let events = if read { libc::POLLIN } else { libc::POLLOUT };
        let mut pending = self.pending.lock().unwrap();
        let before = pending.len();
        pending.retain(|selection| selection.fd != fd || selection.events != events);
        match (pending.len() != before, read) {
            (false, _) => 0,
            (true, true) => SELECT_READ_CANCELLED,
            (true, false) => SELECT_WRITE_CANCELLED,
        }
    }
    fn stop(&self, fd: i32) -> i32 {
        self.pending
            .lock()
            .unwrap()
            .retain(|selection| selection.fd != fd);
        SELECT_STOP_CALLED
    }
    fn send(&self, pid: &O, message: &O) -> bool {
        self.sent
            .lock()
            .unwrap()
            .push((pid.clone(), message.clone()));
        true
    }
}

/// Install the scheduler's reactor. Replacing it also supports isolated tests.
pub fn set_reactor(reactor: Option<Arc<dyn Reactor>>) {
    *socket::reactor().lock().unwrap() = reactor;
}

/// Associate a resource with its controlling process.
pub fn set_owner(handle: &O, pid: O) -> Result<(), BifError> {
    socket::set_owner(handle, pid)
}

/// Close every socket owned by a process that has exited.
pub fn owner_died(pid: &O) {
    socket::owner_died(pid);
}

/// Release a ref-shaped socket resource when the VM drops its last reference.
pub fn release(handle: &O) -> Result<(), BifError> {
    socket::release(handle)
}

/// Build the OTP readiness message for a reactor notification.
pub fn select_message(handle: &O, reference: &O) -> O {
    O::tuple(vec![
        atom("$socket"),
        pair(atom("$socket"), handle.clone()),
        atom("select"),
        reference.clone(),
    ])
}

/// Build the OTP abort message for a canceled selection.
pub fn abort_message(handle: &O, reference: &O, reason: &O) -> O {
    O::tuple(vec![
        atom("$socket"),
        pair(atom("$socket"), handle.clone()),
        atom("abort"),
        pair(reference.clone(), reason.clone()),
    ])
}

/// Resolve a NIF entry in `prim_socket` or `prim_net`.
pub fn lookup(module: &str, name: &str, arity: u8) -> Option<BifFn> {
    lookup_entry(module, name, arity)
}

/// Whether the `prim_socket` or `prim_net` NIF `name/arity` is flagged
/// `ERL_NIF_DIRTY_JOB_IO_BOUND`, so the VM runs it on a dirty IO scheduler.
pub fn dirty_io(module: &str, name: &str, arity: u8) -> bool {
    match module {
        "prim_socket" => socket::dirty_io(name, arity),
        "prim_net" => net::dirty_io(name, arity),
        _ => false,
    }
}

struct Heap<'a, H: HeapAlloc + ?Sized>(&'a mut H);
impl<H: HeapAlloc + ?Sized> HeapAlloc for Heap<'_, H> {
    fn alloc(&mut self, words: usize) -> Option<*mut u64> {
        self.0.alloc(words)
    }
    fn retain_binary(&mut self, value: Arc<arinsal_term::RefcBinary>) {
        self.0.retain_binary(value)
    }
    fn link_bin_ref(
        &mut self,
        bin_ref: *mut u64,
        writable: bool,
        overhead_words: u64,
        owner: Option<arinsal_term::OwnedBinaryRef>,
    ) -> Result<(), arinsal_term::TermError> {
        HeapAlloc::link_bin_ref(self.0, bin_ref, writable, overhead_words, owner)
    }
    fn retain_writable_binary(
        &mut self,
        value: Arc<arinsal_term::WritableBinary>,
    ) -> Result<(), arinsal_term::TermError> {
        self.0.retain_writable_binary(value)
    }
    fn supports_writable_binary(&self) -> bool {
        self.0.supports_writable_binary()
    }
    fn retain_node(&mut self, value: Arc<Node>) {
        self.0.retain_node(value)
    }
    fn retain_fun(&mut self, value: Arc<FunEntry>) {
        self.0.retain_fun(value)
    }
    fn retain_export(&mut self, value: Arc<ExportEntry>) {
        self.0.retain_export(value)
    }
}

thread_local! {
    static RAISED: std::cell::RefCell<Option<O>> = const { std::cell::RefCell::new(None) };
}

/// Raise `error:Reason` from the NIF currently running on this thread, like
/// `enif_raise_exception`. Return the result from the NIF body.
pub(crate) fn raise(reason: O) -> BifError {
    RAISED.with(|raised| *raised.borrow_mut() = Some(reason));
    BifError::Unsupported("enif_raise_exception")
}

fn call(
    ctx: &mut Ctx<'_>,
    args: &[Term],
    f: impl FnOnce(&[O]) -> Result<O, BifError>,
) -> Result<Term, BifError> {
    let args = args
        .iter()
        .map(|a| to_owned(*a).map_err(|_| BifError::BADARG))
        .collect::<Result<Vec<_>, _>>()?;
    RAISED.with(|raised| raised.borrow_mut().take());
    let result = match f(&args) {
        Ok(result) => result,
        Err(error) => {
            return match RAISED.with(|raised| raised.borrow_mut().take()) {
                Some(reason) => from_owned(&reason, &mut Heap(&mut ctx.heap))
                    .map_err(|_| BifError::SystemLimit)
                    .and_then(|reason| Err(BifError::Error(reason))),
                None => Err(error),
            };
        }
    };
    from_owned(&result, &mut Heap(&mut ctx.heap)).map_err(|_| BifError::SystemLimit)
}

macro_rules! entries {
    ($module:literal, $dispatch:path; $(($function:ident, $name:literal, $arity:literal)),* $(,)?) => {
        $(fn $function(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
            if args.len() != $arity { return Err(BifError::BADARG); }
            call(ctx, args, |owned| $dispatch($name, owned))
        })*
    };
}

entries!("prim_socket", socket::dispatch;
    (s_info0,"nif_info",0),(s_info1,"nif_info",1),(s_supports0,"nif_supports",0),(s_supports1,"nif_supports",1),
    (s_command,"nif_command",1),(s_open2,"nif_open",2),(s_open4,"nif_open",4),(s_bind2,"nif_bind",2),
    (s_bind3,"nif_bind",3),(s_connect1,"nif_connect",1),(s_connect3,"nif_connect",3),(s_listen,"nif_listen",2),
    (s_accept,"nif_accept",2),(s_peeloff,"nif_peeloff",2),(s_send,"nif_send",4),(s_sendto,"nif_sendto",5),
    (s_sendmsg,"nif_sendmsg",5),(s_sendmmsg,"nif_sendmmsg",4),(s_sendv,"nif_sendv",3),
    (s_sendfile1,"nif_sendfile",1),(s_sendfile4,"nif_sendfile",4),
    (s_recv,"nif_recv",4),(s_recvfrom,"nif_recvfrom",4),(s_recvmsg,"nif_recvmsg",5),
    (s_recvmmsg,"nif_recvmmsg",6),(s_close,"nif_close",1),(s_finalize_close,"nif_finalize_close",1),
    (s_shutdown,"nif_shutdown",2),(s_setopt,"nif_setopt",5),(s_getopt3,"nif_getopt",3),
    (s_getopt5,"nif_getopt",5),(s_sockname,"nif_sockname",1),(s_socknames,"nif_socknames",2),
    (s_peername,"nif_peername",1),(s_peernames,"nif_peernames",2),(s_ioctl2,"nif_ioctl",2),
    (s_ioctl3,"nif_ioctl",3),(s_ioctl4,"nif_ioctl",4),(s_cancel,"nif_cancel",3));
entries!("prim_net", net::dispatch;
    (n_info,"nif_info",0),(n_command,"nif_command",1),(n_hostname,"nif_gethostname",0),
    (n_nameinfo,"nif_getnameinfo",2),(n_addrinfo,"nif_getaddrinfo",3),(n_ifaddrs,"nif_getifaddrs",1),
    (n_adapters,"nif_get_adapters_addresses",1),(n_if_entry,"nif_get_if_entry",1),
    (n_interface_info,"nif_get_interface_info",1),(n_ip_table,"nif_get_ip_address_table",1),
    (n_servname,"nif_getservbyname",2),(n_servport,"nif_getservbyport",2),
    (n_name2index,"nif_if_name2index",1),(n_index2name,"nif_if_index2name",1),(n_if_names,"nif_if_names",0));

fn s_sendfile5(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    if args.len() != 5 {
        return Err(BifError::BADARG);
    }
    let get_fd = arinsal_nif_file::lookup("prim_file", "get_handle_nif", 1)
        .expect("prim_file descriptor entry");
    let descriptor = get_fd(ctx, &args[4..5])?;
    let fd = to_owned(descriptor).map_err(|_| BifError::BADARG)?;
    let O::Binary(bytes) = &fd else {
        return Err(BifError::BADARG);
    };
    let fd = i32::from_ne_bytes(bytes.as_slice().try_into().map_err(|_| BifError::BADARG)?);
    call(ctx, args, |owned| {
        let mut owned = owned.to_vec();
        owned[4] = O::Int(fd.into());
        socket::dispatch("nif_sendfile", &owned)
    })
}

/// Return the exact entry function pointer used by the BIF registry.
pub fn lookup_entry(module: &str, name: &str, arity: u8) -> Option<BifFn> {
    Some(match (module, name, arity) {
        ("prim_socket", "nif_info", 0) => s_info0,
        ("prim_socket", "nif_info", 1) => s_info1,
        ("prim_socket", "nif_supports", 0) => s_supports0,
        ("prim_socket", "nif_supports", 1) => s_supports1,
        ("prim_socket", "nif_command", 1) => s_command,
        ("prim_socket", "nif_open", 2) => s_open2,
        ("prim_socket", "nif_open", 4) => s_open4,
        ("prim_socket", "nif_bind", 2) => s_bind2,
        ("prim_socket", "nif_bind", 3) => s_bind3,
        ("prim_socket", "nif_connect", 1) => s_connect1,
        ("prim_socket", "nif_connect", 3) => s_connect3,
        ("prim_socket", "nif_listen", 2) => s_listen,
        ("prim_socket", "nif_accept", 2) => s_accept,
        ("prim_socket", "nif_peeloff", 2) => s_peeloff,
        ("prim_socket", "nif_send", 4) => s_send,
        ("prim_socket", "nif_sendto", 5) => s_sendto,
        ("prim_socket", "nif_sendmsg", 5) => s_sendmsg,
        ("prim_socket", "nif_sendmmsg", 4) => s_sendmmsg,
        ("prim_socket", "nif_sendv", 3) => s_sendv,
        ("prim_socket", "nif_sendfile", 1) => s_sendfile1,
        ("prim_socket", "nif_sendfile", 4) => s_sendfile4,
        ("prim_socket", "nif_sendfile", 5) => s_sendfile5,
        ("prim_socket", "nif_recv", 4) => s_recv,
        ("prim_socket", "nif_recvfrom", 4) => s_recvfrom,
        ("prim_socket", "nif_recvmsg", 5) => s_recvmsg,
        ("prim_socket", "nif_recvmmsg", 6) => s_recvmmsg,
        ("prim_socket", "nif_close", 1) => s_close,
        ("prim_socket", "nif_finalize_close", 1) => s_finalize_close,
        ("prim_socket", "nif_shutdown", 2) => s_shutdown,
        ("prim_socket", "nif_setopt", 5) => s_setopt,
        ("prim_socket", "nif_getopt", 3) => s_getopt3,
        ("prim_socket", "nif_getopt", 5) => s_getopt5,
        ("prim_socket", "nif_sockname", 1) => s_sockname,
        ("prim_socket", "nif_socknames", 2) => s_socknames,
        ("prim_socket", "nif_peername", 1) => s_peername,
        ("prim_socket", "nif_peernames", 2) => s_peernames,
        ("prim_socket", "nif_ioctl", 2) => s_ioctl2,
        ("prim_socket", "nif_ioctl", 3) => s_ioctl3,
        ("prim_socket", "nif_ioctl", 4) => s_ioctl4,
        ("prim_socket", "nif_cancel", 3) => s_cancel,
        ("prim_net", "nif_info", 0) => n_info,
        ("prim_net", "nif_command", 1) => n_command,
        ("prim_net", "nif_gethostname", 0) => n_hostname,
        ("prim_net", "nif_getnameinfo", 2) => n_nameinfo,
        ("prim_net", "nif_getaddrinfo", 3) => n_addrinfo,
        ("prim_net", "nif_getifaddrs", 1) => n_ifaddrs,
        ("prim_net", "nif_get_adapters_addresses", 1) => n_adapters,
        ("prim_net", "nif_get_if_entry", 1) => n_if_entry,
        ("prim_net", "nif_get_interface_info", 1) => n_interface_info,
        ("prim_net", "nif_get_ip_address_table", 1) => n_ip_table,
        ("prim_net", "nif_getservbyname", 2) => n_servname,
        ("prim_net", "nif_getservbyport", 2) => n_servport,
        ("prim_net", "nif_if_name2index", 1) => n_name2index,
        ("prim_net", "nif_if_index2name", 1) => n_index2name,
        ("prim_net", "nif_if_names", 0) => n_if_names,
        _ => return None,
    })
}

pub(crate) fn atom(s: &str) -> O {
    O::atom(s)
}
pub(crate) fn pair(a: O, b: O) -> O {
    O::tuple(vec![a, b])
}
pub(crate) fn ok(v: O) -> O {
    pair(atom("ok"), v)
}
pub(crate) fn error(s: &str) -> O {
    pair(atom("error"), atom(s))
}
pub(crate) fn map(entries: &[(&str, O)]) -> O {
    O::Map(entries.iter().map(|(k, v)| (atom(k), v.clone())).collect())
}
pub(crate) fn field<'a>(map: &'a O, key: &str) -> Option<&'a O> {
    let O::Map(entries) = map else { return None };
    entries
        .iter()
        .find_map(|(k, v)| (k == &atom(key)).then_some(v))
}
pub(crate) fn name(value: &O) -> Option<&str> {
    if let O::Atom(s) = value {
        Some(s)
    } else {
        None
    }
}
pub(crate) fn number(value: &O) -> Option<i64> {
    if let O::Int(n) = value {
        Some(*n)
    } else {
        None
    }
}
pub(crate) fn list(value: &O) -> Option<&[O]> {
    match value {
        O::Nil => Some(&[]),
        O::List { elems, tail } if **tail == O::Nil => Some(elems),
        _ => None,
    }
}
pub(crate) fn string(value: &O) -> Option<String> {
    if let Some(chars) = list(value) {
        chars
            .iter()
            .map(|c| {
                number(c)
                    .and_then(|n| u32::try_from(n).ok())
                    .and_then(char::from_u32)
            })
            .collect()
    } else if let O::Binary(bytes) = value {
        String::from_utf8(bytes.clone()).ok()
    } else {
        None
    }
}
pub(crate) fn errno(code: i32) -> O {
    let reason = match code {
        libc::EAGAIN => "eagain",
        libc::EINPROGRESS => "einprogress",
        libc::EALREADY => "ealready",
        libc::EINTR => "eintr",
        libc::EBADF => "ebadf",
        libc::EINVAL => "einval",
        libc::ENOTCONN => "enotconn",
        libc::EADDRINUSE => "eaddrinuse",
        libc::EADDRNOTAVAIL => "eaddrnotavail",
        libc::ECONNREFUSED => "econnrefused",
        libc::ECONNRESET => "econnreset",
        libc::ETIMEDOUT => "etimedout",
        libc::EPIPE => "epipe",
        libc::EACCES => "eacces",
        libc::EPERM => "eperm",
        libc::ENOMEM => "enomem",
        libc::ENOBUFS => "enobufs",
        libc::EAFNOSUPPORT => "eafnosupport",
        libc::EPROTONOSUPPORT => "eprotonosupport",
        libc::EISCONN => "eisconn",
        libc::EDESTADDRREQ => "edestaddrreq",
        libc::EMSGSIZE => "emsgsize",
        libc::ENOPROTOOPT => "enoprotoopt",
        libc::ENOTSOCK => "enotsock",
        libc::ENETUNREACH => "enetunreach",
        libc::EHOSTUNREACH => "ehostunreach",
        _ => return error(&format!("errno_{code}")),
    };
    error(reason)
}
pub(crate) fn last_error() -> O {
    errno(
        std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EINVAL),
    )
}

pub(crate) fn notsup() -> BifError {
    BifError::Error(arinsal_term::Term::atom(
        arinsal_term::global_atoms().intern("notsup").unwrap(),
    ))
}

#[cfg(test)]
mod dirty_tests {
    use super::*;

    #[test]
    fn nif_tables_list_every_entry_the_lookup_resolves() {
        for (module, table) in [
            ("prim_socket", &socket::NIF_FUNCS[..]),
            ("prim_net", &net::NIF_FUNCS[..]),
        ] {
            for (name, arity, _) in table {
                assert!(
                    lookup_entry(module, name, *arity).is_some(),
                    "{module}:{name}/{arity}"
                );
            }
        }
        assert_eq!(socket::NIF_FUNCS.len(), 40);
        assert_eq!(net::NIF_FUNCS.len(), 15);
    }

    #[test]
    fn dirty_io_entries_are_the_flagged_ones() {
        let socket_dirty: Vec<_> = socket::NIF_FUNCS
            .iter()
            .filter(|(_, _, dirty)| *dirty)
            .map(|(name, arity, _)| (*name, *arity))
            .collect();
        assert_eq!(
            socket_dirty,
            [
                ("nif_sendfile", 5),
                ("nif_sendfile", 4),
                ("nif_sendfile", 1),
                ("nif_ioctl", 2),
                ("nif_ioctl", 3),
                ("nif_ioctl", 4),
                ("nif_finalize_close", 1),
            ]
        );
        let net_dirty: Vec<_> = net::NIF_FUNCS
            .iter()
            .filter(|(_, _, dirty)| *dirty)
            .map(|(name, arity, _)| (*name, *arity))
            .collect();
        assert_eq!(
            net_dirty,
            [
                ("nif_getifaddrs", 1),
                ("nif_get_adapters_addresses", 1),
                ("nif_get_if_entry", 1),
                ("nif_get_interface_info", 1),
                ("nif_get_ip_address_table", 1),
                ("nif_getservbyname", 2),
                ("nif_getservbyport", 2),
            ]
        );
        assert!(dirty_io("prim_net", "nif_getifaddrs", 1));
        assert!(dirty_io("prim_socket", "nif_ioctl", 3));
        assert!(!dirty_io("prim_socket", "nif_ioctl", 1));
        assert!(!dirty_io("prim_net", "nif_getaddrinfo", 3));
        assert!(!dirty_io("prim_socket", "nif_sendmmsg", 4));
        assert!(!dirty_io("prim_file", "nif_ioctl", 3));
    }
}
