// Port of erts/etc/common/erlc.c (EI compile-server calls), OTP-29.1.1.

use std::ffi::{CStr, CString, OsStr, OsString, c_char, c_int, c_long, c_uint, c_void};
use std::io;
use std::net::TcpListener;
use std::os::fd::{FromRawFd, RawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};

const MAXATOMLEN: usize = 256;
const MAXATOMLEN_UTF8: usize = 1021;
const EI_MAXHOSTNAMELEN: usize = MAXATOMLEN - 2;
const EI_MAX_COOKIE_SIZE: usize = 512;

/// EI's timeout result returned by `ei_connect` and `ei_rpc_from`.
pub const EI_TIMEOUT: c_int = -5;

#[repr(C)]
struct ErlangPid {
    node: [c_char; MAXATOMLEN_UTF8],
    num: u32,
    serial: u32,
    creation: u32,
}

#[repr(C)]
struct EiCnode {
    thishostname: [c_char; EI_MAXHOSTNAMELEN + 1],
    thisnodename: [c_char; MAXATOMLEN + 1],
    thisalivename: [c_char; EI_MAXHOSTNAMELEN + 1],
    ei_connect_cookie: [c_char; EI_MAX_COOKIE_SIZE + 1],
    creation: u32,
    self_pid: ErlangPid,
    callbacks: *mut c_void,
    setup_context: *mut c_void,
    pidsn: u32,
}

#[repr(C)]
struct EiXBuff {
    buff: *mut c_char,
    buffsz: c_int,
    index: c_int,
}

#[repr(C)]
struct InAddr {
    s_addr: u32,
}

#[repr(C)]
struct SockAddrIn {
    family: u16,
    port: u16,
    address: InAddr,
    zero: [u8; 8],
}

#[repr(C)]
struct SockAddr {
    family: u16,
    data: [c_char; 14],
}

#[repr(C)]
struct HostEnt {
    name: *mut c_char,
    aliases: *mut *mut c_char,
    address_type: c_int,
    address_length: c_int,
    address_list: *mut *mut c_char,
}

#[repr(C)]
struct EiTermValue {
    bytes: [u64; 130],
}

#[repr(C)]
struct EiTerm {
    ei_type: c_char,
    arity: c_int,
    size: c_int,
    value: EiTermValue,
}

#[repr(C)]
struct ErlangTrace {
    serial: c_long,
    prev: c_long,
    from: ErlangPid,
    label: c_long,
    flags: c_long,
}

#[repr(C)]
struct ErlangMsg {
    msgtype: c_long,
    from: ErlangPid,
    to: ErlangPid,
    toname: [c_char; MAXATOMLEN_UTF8],
    cookie: [c_char; MAXATOMLEN_UTF8],
    token: ErlangTrace,
}

unsafe extern "C" {
    fn ei_init() -> c_int;
    fn ei_connect_init(
        node: *mut EiCnode,
        name: *const c_char,
        cookie: *const c_char,
        creation: u32,
    ) -> c_int;
    fn ei_connect_xinit(
        node: *mut EiCnode,
        hostname: *const c_char,
        alive: *const c_char,
        nodename: *const c_char,
        address: *mut InAddr,
        cookie: *const c_char,
        creation: c_uint,
    ) -> c_int;
    fn ei_gethostbyname(name: *const c_char) -> *mut HostEnt;
    fn gethostname(name: *mut c_char, len: usize) -> c_int;
    fn ei_thishostname(node: *const EiCnode) -> *const c_char;
    fn ei_connect(node: *mut EiCnode, remote: *mut c_char) -> c_int;
    fn ei_connect_host_port(node: *mut EiCnode, hostname: *mut c_char, port: c_int) -> c_int;
    fn ei_x_new(buffer: *mut EiXBuff) -> c_int;
    fn ei_x_new_with_version(buffer: *mut EiXBuff) -> c_int;
    fn ei_x_encode_list_header(buffer: *mut EiXBuff, arity: c_long) -> c_int;
    fn ei_x_encode_map_header(buffer: *mut EiXBuff, arity: c_long) -> c_int;
    fn ei_x_encode_tuple_header(buffer: *mut EiXBuff, arity: c_long) -> c_int;
    fn ei_x_encode_atom(buffer: *mut EiXBuff, atom: *const c_char) -> c_int;
    fn ei_x_encode_binary(buffer: *mut EiXBuff, bytes: *const c_void, len: c_int) -> c_int;
    fn ei_x_encode_string(buffer: *mut EiXBuff, string: *const c_char) -> c_int;
    fn ei_x_encode_empty_list(buffer: *mut EiXBuff) -> c_int;
    fn ei_x_format_wo_ver(buffer: *mut EiXBuff, format: *const c_char, ...) -> c_int;
    fn ei_rpc(
        node: *mut EiCnode,
        fd: c_int,
        module: *mut c_char,
        function: *mut c_char,
        input: *const c_char,
        input_len: c_int,
        reply: *mut EiXBuff,
    ) -> c_int;
    fn ei_xrpc_to(
        node: *mut EiCnode,
        fd: c_int,
        module: *mut c_char,
        function: *mut c_char,
        input: *const c_char,
        input_len: c_int,
        flags: c_int,
    ) -> c_int;
    fn ei_rpc_from(
        node: *mut EiCnode,
        fd: c_int,
        timeout: c_int,
        message: *mut ErlangMsg,
        reply: *mut EiXBuff,
    ) -> c_int;
    fn ei_decode_atom(buffer: *const c_char, index: *mut c_int, atom: *mut c_char) -> c_int;
    fn ei_decode_tuple_header(buffer: *const c_char, index: *mut c_int, arity: *mut c_int)
    -> c_int;
    fn ei_get_type(
        buffer: *const c_char,
        index: *const c_int,
        kind: *mut c_int,
        size: *mut c_int,
    ) -> c_int;
    fn ei_decode_binary(
        buffer: *const c_char,
        index: *mut c_int,
        bytes: *mut c_void,
        len: *mut c_long,
    ) -> c_int;
    fn ei_decode_version(buffer: *const c_char, index: *mut c_int, version: *mut c_int) -> c_int;
    fn ei_decode_ei_term(buffer: *const c_char, index: *mut c_int, term: *mut EiTerm) -> c_int;
    fn ei_s_print_term(output: *mut *mut c_char, buffer: *const c_char, index: *mut c_int)
    -> c_int;
    fn ei_x_free(buffer: *mut EiXBuff) -> c_int;
    fn ei_free(pointer: *mut c_void);
    fn alarm(seconds: c_uint) -> c_uint;
    fn time(timer: *mut c_long) -> c_long;
    fn ctime(timer: *const c_long) -> *mut c_char;
    fn fork() -> c_int;
    fn close(fd: c_int) -> c_int;
    fn dup2(source: c_int, target: c_int) -> c_int;
    fn __erl_errno_place() -> *mut c_int;
    fn socket(domain: c_int, kind: c_int, protocol: c_int) -> c_int;
    fn setsockopt(
        socket: c_int,
        level: c_int,
        option: c_int,
        value: *const c_void,
        length: u32,
    ) -> c_int;
    fn bind(socket: c_int, address: *const SockAddr, length: u32) -> c_int;
    fn getsockname(socket: c_int, address: *mut SockAddr, length: *mut u32) -> c_int;
    fn listen(socket: c_int, backlog: c_int) -> c_int;
}

/// A canonical host name and its first IPv4 address as returned by EI.
pub struct ResolvedHost {
    /// Canonical host name from `hostent.h_name`.
    pub name: Vec<u8>,
    /// First address from `hostent.h_addr_list` in network byte order.
    pub address: [u8; 4],
}

/// An initialized Erl_Interface node and its current distribution connection.
pub struct ErlCallClient {
    node: EiCnode,
}

/// Result of the Unix `fork` used by `erl_start_sys`.
pub enum ForkResult {
    /// The parent receives the child process identifier.
    Parent(i32),
    /// The caller is the forked child.
    Child,
}

struct XBuffer(EiXBuff);

impl Drop for XBuffer {
    fn drop(&mut self) {
        if !self.0.buff.is_null() {
            // SAFETY: This buffer was allocated by EI and has not been freed.
            unsafe {
                ei_x_free(&mut self.0);
            }
        }
    }
}

impl XBuffer {
    fn new(version: bool) -> Result<Self, c_int> {
        let mut buffer = EiXBuff {
            buff: std::ptr::null_mut(),
            buffsz: 0,
            index: 0,
        };
        // SAFETY: EI initializes the caller-owned output buffer.
        let result = unsafe {
            if version {
                ei_x_new_with_version(&mut buffer)
            } else {
                ei_x_new(&mut buffer)
            }
        };
        if result < 0 {
            return Err(result);
        }
        Ok(Self(buffer))
    }

    fn bytes(&self) -> &[u8] {
        let length = self.0.index.max(0) as usize;
        // SAFETY: EI owns `buff` for at least `index` bytes while this guard is alive.
        unsafe { std::slice::from_raw_parts(self.0.buff.cast(), length) }
    }
}

/// Returns the local host name using the system call used by `erl_call.c`.
// Port of lib/erl_interface/src/prog/erl_call.c (main), OTP-29.1.1.
pub fn local_hostname() -> Result<Vec<u8>, c_int> {
    let mut hostname = [c_char::default(); EI_MAXHOSTNAMELEN + 1];
    // SAFETY: `hostname` is writable for its full advertised length.
    let result = unsafe { gethostname(hostname.as_mut_ptr(), hostname.len()) };
    if result < 0 {
        return Err(io::Error::last_os_error().raw_os_error().unwrap_or(0));
    }
    // SAFETY: `gethostname` writes a NUL-terminated name when passed the extra byte.
    Ok(unsafe { CStr::from_ptr(hostname.as_ptr()) }
        .to_bytes()
        .to_vec())
}

/// Resolves a host with EI's host lookup and copies the first IPv4 result.
// Port of lib/erl_interface/src/prog/erl_call.c (main, get_addr), OTP-29.1.1.
pub fn resolve_host(hostname: &CStr) -> Option<ResolvedHost> {
    // SAFETY: EI reads the live, NUL-terminated host name and returns its hostent storage.
    let host = unsafe { ei_gethostbyname(hostname.as_ptr()) };
    if host.is_null() {
        return None;
    }
    // SAFETY: A successful hostent has a name and a NULL-terminated address list.
    unsafe {
        let name = CStr::from_ptr((*host).name).to_bytes().to_vec();
        let first_address = *(*host).address_list;
        if first_address.is_null() || (*host).address_length < 4 {
            return None;
        }
        let mut address = [0; 4];
        std::ptr::copy_nonoverlapping(first_address.cast::<u8>(), address.as_mut_ptr(), 4);
        Some(ResolvedHost { name, address })
    }
}

impl ErlCallClient {
    // Port of lib/erl_interface/src/prog/erl_call.c (main), OTP-29.1.1.
    /// Initializes a C node with the fields supplied to `ei_connect_xinit`.
    pub fn new(
        hostname: &CStr,
        alive: Option<&CStr>,
        nodename: Option<&CStr>,
        address: [u8; 4],
        cookie: Option<&CStr>,
        creation: u32,
    ) -> Result<Self, c_int> {
        // SAFETY: `EiCnode` is the zero-valid OTP ei_cnode layout.
        let mut node: EiCnode = unsafe { std::mem::zeroed() };
        let mut address = InAddr {
            s_addr: u32::from_ne_bytes(address),
        };
        let alive = alive.map_or(std::ptr::null(), CStr::as_ptr);
        let nodename = nodename.map_or(std::ptr::null(), CStr::as_ptr);
        let cookie = cookie.map_or(std::ptr::null(), CStr::as_ptr);
        // SAFETY: All strings and the address remain live for the synchronous EI call.
        let result = unsafe {
            ei_connect_xinit(
                &mut node,
                hostname.as_ptr(),
                alive,
                nodename,
                &mut address,
                cookie,
                creation,
            )
        };
        if result < 0 {
            return Err(result);
        }
        Ok(Self { node })
    }

    // Port of lib/erl_interface/src/prog/erl_call.c (main), OTP-29.1.1.
    /// Returns the hostname stored in the initialized C node.
    pub fn hostname(&self) -> Vec<u8> {
        // SAFETY: EI returns a NUL-terminated string owned by the initialized node.
        let hostname = unsafe { ei_thishostname(&self.node) };
        // SAFETY: `ei_thishostname` returns a non-null C string for an initialized node.
        unsafe { CStr::from_ptr(hostname) }.to_bytes().to_vec()
    }

    // Port of lib/erl_interface/src/prog/erl_call.c (main, do_connect), OTP-29.1.1.
    /// Connects to a named Erlang node through EI.
    pub fn connect(&mut self, nodename: &CStr) -> c_int {
        // SAFETY: EI reads the live, NUL-terminated node name during the call.
        unsafe { ei_connect(&mut self.node, nodename.as_ptr().cast_mut()) }
    }

    // Port of lib/erl_interface/src/prog/erl_call.c (main), OTP-29.1.1.
    /// Connects to a node at an explicit host and EPMD port through EI.
    pub fn connect_host_port(&mut self, hostname: &CStr, port: c_int) -> c_int {
        // SAFETY: EI reads the live, NUL-terminated hostname during the call.
        unsafe { ei_connect_host_port(&mut self.node, hostname.as_ptr().cast_mut(), port) }
    }

    // Port of lib/erl_interface/src/prog/erl_call.c (main, rpc_print_node_stdout), OTP-29.1.1.
    /// Executes one EI RPC and returns the reply term without its version byte.
    pub fn rpc(
        &mut self,
        fd: c_int,
        module: &CStr,
        function: &CStr,
        input: &[u8],
        fetch_stdout: bool,
    ) -> Result<Vec<u8>, c_int> {
        let mut reply = XBuffer::new(true)?;
        let module = module.as_ptr().cast_mut();
        let function = function.as_ptr().cast_mut();
        let input_len = c_int::try_from(input.len()).map_err(|_| -1)?;
        if fetch_stdout {
            return self.rpc_fetch_stdout(fd, module, function, input, input_len, &mut reply);
        }
        // SAFETY: EI reads the live input and names and writes to the initialized reply buffer.
        let result = unsafe {
            ei_rpc(
                &mut self.node,
                fd,
                module,
                function,
                input.as_ptr().cast(),
                input_len,
                &mut reply.0,
            )
        };
        if result < 0 {
            return Err(result);
        }
        Ok(reply.bytes().to_vec())
    }

    // Port of lib/erl_interface/src/prog/erl_call.c (rpc_print_node_stdout), OTP-29.1.1.
    fn rpc_fetch_stdout(
        &mut self,
        fd: c_int,
        module: *mut c_char,
        function: *mut c_char,
        input: &[u8],
        input_len: c_int,
        reply: &mut XBuffer,
    ) -> Result<Vec<u8>, c_int> {
        // SAFETY: EI reads live names/input, and the flag requests erl_call's stdout protocol.
        let result = unsafe {
            ei_xrpc_to(
                &mut self.node,
                fd,
                module,
                function,
                input.as_ptr().cast(),
                input_len,
                1,
            )
        };
        if result < 0 {
            return Err(result);
        }
        let initial_index = reply.0.index;
        // SAFETY: `erlang_msg` contains only integer fields and fixed-size C arrays.
        let mut message: ErlangMsg = unsafe { std::mem::zeroed() };
        loop {
            // SAFETY: EI writes the next distribution message and ETF payload to owned buffers.
            let received =
                unsafe { ei_rpc_from(&mut self.node, fd, -1, &mut message, &mut reply.0) };
            if received < 0 {
                return Err(received);
            }
            if received == 0 {
                continue;
            }
            let mut index = 0;
            let mut version = 0;
            // SAFETY: The EI reply payload is live; both output locations are writable.
            let decoded = unsafe { ei_decode_version(reply.0.buff, &mut index, &mut version) };
            if decoded < 0 {
                return Err(-1);
            }
            let mut term = EiTerm {
                ei_type: 0,
                arity: 0,
                size: 0,
                value: EiTermValue { bytes: [0; 130] },
            };
            // SAFETY: `term` is at least as large and aligned as OTP's ei_term output.
            let decoded = unsafe { ei_decode_ei_term(reply.0.buff, &mut index, &mut term) };
            if decoded < 0 || !matches!(term.ei_type as u8, b'h' | b'i') || term.arity != 2 {
                return Err(-1);
            }
            let mut atom = [c_char::default(); MAXATOMLEN];
            // SAFETY: The reply payload is live and `atom` has MAXATOMLEN writable bytes.
            let decoded = unsafe { ei_decode_atom(reply.0.buff, &mut index, atom.as_mut_ptr()) };
            if decoded < 0 {
                return Err(-1);
            }
            // SAFETY: `atom` is NUL-terminated by ei_decode_atom.
            let atom = unsafe { CStr::from_ptr(atom.as_ptr()) }.to_bytes();
            if atom == b"rex_stdout" {
                let mut kind = 0;
                let mut size = 0;
                // SAFETY: EI reads the live payload/index and writes the two output fields.
                let typed = unsafe { ei_get_type(reply.0.buff, &index, &mut kind, &mut size) };
                if typed < 0 || kind != b'm' as c_int || size < 0 {
                    return Err(-1);
                }
                let mut bytes = vec![0; size as usize];
                let mut actual_size = 0;
                // SAFETY: `bytes` has the advertised ETF binary length and is writable.
                let decoded = unsafe {
                    ei_decode_binary(
                        reply.0.buff,
                        &mut index,
                        bytes.as_mut_ptr().cast(),
                        &mut actual_size,
                    )
                };
                if decoded < 0 || actual_size < 0 {
                    return Err(-1);
                }
                bytes.truncate(actual_size as usize);
                let output_length = bytes
                    .iter()
                    .position(|byte| *byte == 0)
                    .unwrap_or(bytes.len());
                use std::io::Write;
                let mut stdout = std::io::stdout().lock();
                let _ = stdout.write_all(&bytes[..output_length]);
                let _ = stdout.flush();
                reply.0.index = initial_index;
                continue;
            }
            if atom != b"rex" {
                return Err(-1);
            }
            let length = reply.0.index.saturating_sub(index).max(0) as usize;
            // SAFETY: EI owns a payload of `reply.index` bytes and `index` is in its bounds.
            unsafe {
                std::ptr::copy(reply.0.buff.add(index as usize), reply.0.buff, length);
            }
            reply.0.index = length as c_int;
            return Ok(reply.bytes().to_vec());
        }
    }
}

/// Encodes an Erlang argument expression with OTP's `ei_x_format_wo_ver` parser.
// Port of lib/erl_interface/src/prog/erl_call.c (main), OTP-29.1.1.
pub fn encode_apply_arguments(arguments: &CStr) -> Result<Vec<u8>, c_int> {
    let mut buffer = XBuffer::new(false)?;
    // SAFETY: EI parses the live NUL-terminated term expression into the initialized buffer.
    let result = unsafe { ei_x_format_wo_ver(&mut buffer.0, arguments.as_ptr()) };
    if result < 0 {
        return Err(result);
    }
    Ok(buffer.bytes().to_vec())
}

/// Encodes the `[Binary]` argument passed to `erl_eval:eval_str/1`.
// Port of lib/erl_interface/src/prog/erl_call.c (main), OTP-29.1.1.
pub fn encode_eval_arguments(input: &[u8]) -> Result<Vec<u8>, c_int> {
    let mut buffer = XBuffer::new(false)?;
    // SAFETY: Each EI encoder appends to the initialized buffer while `input` remains live.
    unsafe {
        let result = ei_x_encode_list_header(&mut buffer.0, 1);
        if result < 0 {
            return Err(result);
        }
        let result = ei_x_encode_binary(
            &mut buffer.0,
            input.as_ptr().cast(),
            c_int::try_from(input.len()).map_err(|_| -1)?,
        );
        if result < 0 {
            return Err(result);
        }
        let result = ei_x_encode_empty_list(&mut buffer.0);
        if result < 0 {
            return Err(result);
        }
    }
    Ok(buffer.bytes().to_vec())
}

/// Encodes `file:write_file/2` arguments for `erl_call -m`.
// Port of lib/erl_interface/src/prog/erl_call.c (main), OTP-29.1.1.
pub fn encode_file_write(filename: &CStr, contents: &[u8]) -> Result<Vec<u8>, c_int> {
    let mut buffer = XBuffer::new(false)?;
    // SAFETY: EI encoders read live input and append to the initialized buffer.
    unsafe {
        let result = ei_x_encode_list_header(&mut buffer.0, 2);
        if result < 0 {
            return Err(result);
        }
        let result = ei_x_encode_string(&mut buffer.0, filename.as_ptr());
        if result < 0 {
            return Err(result);
        }
        let result = ei_x_encode_binary(
            &mut buffer.0,
            contents.as_ptr().cast(),
            c_int::try_from(contents.len()).map_err(|_| -1)?,
        );
        if result < 0 {
            return Err(result);
        }
        let result = ei_x_encode_empty_list(&mut buffer.0);
        if result < 0 {
            return Err(result);
        }
    }
    Ok(buffer.bytes().to_vec())
}

/// Encodes the `[Filename, [], []]` argument passed to `c:c/1`.
// Port of lib/erl_interface/src/prog/erl_call.c (main), OTP-29.1.1.
pub fn encode_compile_file(filename: &CStr) -> Result<Vec<u8>, c_int> {
    let mut buffer = XBuffer::new(false)?;
    // SAFETY: EI encoders read the live atom and append to the initialized buffer.
    unsafe {
        let result = ei_x_encode_list_header(&mut buffer.0, 2);
        if result < 0 {
            return Err(result);
        }
        let result = ei_x_encode_atom(&mut buffer.0, filename.as_ptr());
        if result < 0 {
            return Err(result);
        }
        let result = ei_x_encode_empty_list(&mut buffer.0);
        if result < 0 {
            return Err(result);
        }
        let result = ei_x_encode_empty_list(&mut buffer.0);
        if result < 0 {
            return Err(result);
        }
    }
    Ok(buffer.bytes().to_vec())
}

/// Encodes the empty argument list used for `erlang:halt/0`.
// Port of lib/erl_interface/src/prog/erl_call.c (main), OTP-29.1.1.
pub fn encode_empty_arguments() -> Result<Vec<u8>, c_int> {
    let mut buffer = XBuffer::new(false)?;
    // SAFETY: EI appends the empty-list term to the initialized buffer.
    let result = unsafe { ei_x_encode_empty_list(&mut buffer.0) };
    if result < 0 {
        return Err(result);
    }
    Ok(buffer.bytes().to_vec())
}

/// Formats a reply term with Erl_Interface's term printer.
// Port of lib/erl_interface/src/prog/erl_call.c (main), OTP-29.1.1.
pub fn print_term(term: &[u8]) -> Result<Vec<u8>, c_int> {
    let mut output = std::ptr::null_mut();
    let mut index = 0;
    // SAFETY: EI reads the live term and allocates a NUL-terminated output string.
    let result = unsafe { ei_s_print_term(&mut output, term.as_ptr().cast(), &mut index) };
    if result < 0 || output.is_null() {
        return Err(result);
    }
    // SAFETY: `ei_s_print_term` appends a NUL terminator and returns EI-owned storage.
    let printed = unsafe { CStr::from_ptr(output) }.to_bytes().to_vec();
    // SAFETY: EI allocated the returned string with its allocator.
    unsafe { ei_free(output.cast()) };
    Ok(printed)
}

/// Installs the process alarm used by the `-timeout` option.
// Port of lib/erl_interface/src/prog/erl_call.c (start_timeout), OTP-29.1.1.
pub fn start_alarm(seconds: u32) {
    // SAFETY: `alarm` only updates the calling process's alarm timer.
    unsafe {
        alarm(seconds);
    }
}

/// Waits for readability with the `select` operation used by `wait_for_erlang`.
// Port of lib/erl_interface/src/prog/erl_call.c (wait_for_erlang), OTP-29.1.1.
pub fn wait_readable(fd: i32, seconds: i64, nanoseconds: i64) -> Result<bool, i32> {
    use rustix::event::{FdSetElement, Timespec, fd_set_insert, fd_set_num_elements, select};

    let mut read_set = vec![FdSetElement::default(); fd_set_num_elements(1, fd + 1)];
    fd_set_insert(&mut read_set, fd);
    let timeout = Timespec {
        tv_sec: seconds,
        tv_nsec: nanoseconds as _,
    };
    // SAFETY: `fd` is an open listener descriptor owned by the caller.
    match unsafe { select(fd + 1, Some(&mut read_set), None, None, Some(&timeout)) } {
        Ok(ready) => Ok(ready != 0),
        Err(error) => Err(error.raw_os_error()),
    }
}

/// Returns the C `ctime` rendering used by the `-d` startup log.
// Port of lib/erl_interface/src/prog/erl_call.c (exec_erlang), OTP-29.1.1.
pub fn ctime_now() -> Vec<u8> {
    let mut timestamp = 0;
    // SAFETY: The C time functions write/read one `time_t` and return a static string.
    let text = unsafe {
        time(&mut timestamp);
        ctime(&timestamp)
    };
    if text.is_null() {
        return Vec::new();
    }
    // SAFETY: `ctime` returns a NUL-terminated static string.
    unsafe { CStr::from_ptr(text) }.to_bytes().to_vec()
}

/// Returns the current EI error number.
// Port of lib/erl_interface/src/prog/erl_call.c (main), OTP-29.1.1.
pub fn ei_error_number() -> c_int {
    let error_number = ei_error_number_pointer();
    // SAFETY: EI guarantees a valid pointer to the process-local error code.
    unsafe { *error_number }
}

/// Forks the process as `erl_start_sys` does before `exec_erlang`.
// Port of lib/erl_interface/src/prog/erl_call.c (erl_start_sys), OTP-29.1.1.
pub fn fork_process() -> Result<ForkResult, c_int> {
    // SAFETY: The caller performs only the `erl_call` child startup path after fork.
    let result = unsafe { fork() };
    if result < 0 {
        Err(io::Error::last_os_error().raw_os_error().unwrap_or(0))
    } else if result == 0 {
        Ok(ForkResult::Child)
    } else {
        Ok(ForkResult::Parent(result))
    }
}

/// Closes the descriptor range closed by the Unix `exec_erlang` child.
// Port of lib/erl_interface/src/prog/erl_call.c (exec_erlang), OTP-29.1.1.
pub fn close_exec_descriptors() {
    for fd in 0..64 {
        // SAFETY: `close` accepts every integer descriptor; errors are ignored like C.
        unsafe {
            close(fd);
        }
    }
}

/// Duplicates a descriptor to one of the standard descriptor numbers.
// Port of lib/erl_interface/src/prog/erl_call.c (exec_erlang), OTP-29.1.1.
pub fn duplicate_descriptor(source: i32, target: i32) -> Result<(), c_int> {
    // SAFETY: The caller owns `source` and `target` is a standard descriptor number.
    if unsafe { dup2(source, target) } < 0 {
        Err(io::Error::last_os_error().raw_os_error().unwrap_or(0))
    } else {
        Ok(())
    }
}

/// Creates the listening socket with the setup used by `erl_start_sys`.
// Port of lib/erl_interface/src/prog/erl_call.c (erl_start_sys), OTP-29.1.1.
pub fn start_listener() -> io::Result<(TcpListener, u16)> {
    // SAFETY: This requests an IPv4 stream socket with the constants used by OTP's socket call.
    let fd = unsafe { socket(2, 1, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    let reuse_address: c_int = 1;
    // SAFETY: `reuse_address` remains live for the call and its size matches the C integer value.
    if unsafe {
        setsockopt(
            fd,
            1,
            2,
            (&reuse_address as *const c_int).cast(),
            std::mem::size_of_val(&reuse_address) as u32,
        )
    } < 0
    {
        let error = io::Error::last_os_error();
        // SAFETY: `fd` is the socket just created above and not yet owned elsewhere.
        unsafe { close(fd) };
        return Err(error);
    }

    let mut address = SockAddrIn {
        family: 2,
        port: 0,
        address: InAddr { s_addr: 0 },
        zero: [0; 8],
    };
    // SAFETY: `address` is a complete IPv4 sockaddr and `fd` is an open socket.
    if unsafe {
        bind(
            fd,
            (&address as *const SockAddrIn).cast(),
            std::mem::size_of::<SockAddrIn>() as u32,
        )
    } < 0
    {
        let error = io::Error::last_os_error();
        // SAFETY: `fd` is the socket just created above and not yet owned elsewhere.
        unsafe { close(fd) };
        return Err(error);
    }

    let mut address_length = std::mem::size_of::<SockAddrIn>() as u32;
    // SAFETY: `address` and its length are writable sockaddr_in outputs.
    if unsafe {
        getsockname(
            fd,
            (&mut address as *mut SockAddrIn).cast(),
            &mut address_length,
        )
    } < 0
    {
        let error = io::Error::last_os_error();
        // SAFETY: `fd` is the socket just created above and not yet owned elsewhere.
        unsafe { close(fd) };
        return Err(error);
    }
    // SAFETY: The socket is bound and open; backlog 5 matches `erl_start_sys`.
    if unsafe { listen(fd, 5) } < 0 {
        let error = io::Error::last_os_error();
        // SAFETY: `fd` is the socket just created above and not yet owned elsewhere.
        unsafe { close(fd) };
        return Err(error);
    }

    // SAFETY: The successful socket is transferred to the returned listener exactly once.
    let listener = unsafe { TcpListener::from_raw_fd(fd as RawFd) };
    Ok((listener, u16::from_be(address.port)))
}

fn initialize_ei() {
    // SAFETY: `ei_init` initializes process-local EI state and takes no arguments.
    unsafe {
        ei_init();
    }
}

fn connect_init(node: &mut EiCnode, name: &CStr, cookie: &CStr) -> c_int {
    // SAFETY: The node layout matches OTP's ei_cnode and both C strings remain live for the call.
    unsafe { ei_connect_init(node, name.as_ptr(), cookie.as_ptr(), 1) }
}

fn this_hostname(node: &EiCnode) -> Vec<u8> {
    // SAFETY: EI returns a NUL-terminated hostname owned by the initialized node.
    let pointer = unsafe { ei_thishostname(node) };
    // SAFETY: `ei_thishostname` guarantees a non-null, NUL-terminated pointer.
    unsafe { CStr::from_ptr(pointer).to_bytes().to_vec() }
}

fn connect(node: &mut EiCnode, remote: &CStr) -> c_int {
    // SAFETY: EI reads the live, NUL-terminated remote node name during the call.
    unsafe { ei_connect(node, remote.as_ptr() as *mut c_char) }
}

fn new_buffer(buffer: &mut EiXBuff) {
    // SAFETY: EI initializes the output buffer owned by this process.
    unsafe {
        ei_x_new_with_version(buffer);
    }
}

fn encode_list_header(buffer: &mut EiXBuff, arity: c_long) {
    // SAFETY: The buffer was initialized by EI and the arity mirrors erlc.c's encoding sequence.
    unsafe {
        ei_x_encode_list_header(buffer, arity);
    }
}

fn encode_map_header(buffer: &mut EiXBuff, arity: c_long) {
    // SAFETY: The buffer was initialized by EI and the arity mirrors erlc.c's encoding sequence.
    unsafe {
        ei_x_encode_map_header(buffer, arity);
    }
}

fn encode_tuple_header(buffer: &mut EiXBuff, arity: c_long) {
    // SAFETY: The buffer was initialized by EI and the arity mirrors erlc.c's encoding sequence.
    unsafe {
        ei_x_encode_tuple_header(buffer, arity);
    }
}

fn encode_atom(buffer: &mut EiXBuff, atom: &CStr) {
    // SAFETY: The buffer was initialized by EI and the atom is a live C string.
    unsafe {
        ei_x_encode_atom(buffer, atom.as_ptr());
    }
}

fn encode_binary(buffer: &mut EiXBuff, bytes: &[u8]) {
    // SAFETY: The buffer and byte slice remain live for the synchronous EI encoding call.
    unsafe {
        ei_x_encode_binary(buffer, bytes.as_ptr().cast(), bytes.len() as c_int);
    }
}

fn encode_string(buffer: &mut EiXBuff, value: &CStr) {
    // SAFETY: The buffer was initialized by EI and the value is a live C string.
    unsafe {
        ei_x_encode_string(buffer, value.as_ptr());
    }
}

fn encode_empty_list(buffer: &mut EiXBuff) {
    // SAFETY: The buffer was initialized by EI.
    unsafe {
        ei_x_encode_empty_list(buffer);
    }
}

fn rpc(
    node: &mut EiCnode,
    fd: c_int,
    input: *const c_char,
    input_len: c_int,
    reply: &mut EiXBuff,
) -> c_int {
    // SAFETY: Buffers remain live through the synchronous RPC; names are static NUL-terminated strings.
    unsafe {
        ei_rpc(
            node,
            fd,
            c"erl_compile_server".as_ptr() as *mut c_char,
            c"compile".as_ptr() as *mut c_char,
            input,
            input_len,
            reply,
        )
    }
}

fn decode_atom(buffer: *const c_char, index: &mut c_int, atom: &mut [c_char]) -> c_int {
    // SAFETY: The EI reply buffer is live and `atom` has MAXATOMLEN bytes.
    unsafe { ei_decode_atom(buffer, index, atom.as_mut_ptr()) }
}

fn decode_tuple_header(buffer: *const c_char, index: &mut c_int, arity: &mut c_int) -> c_int {
    // SAFETY: The EI reply buffer is live and `arity` is writable.
    unsafe { ei_decode_tuple_header(buffer, index, arity) }
}

fn get_type(buffer: *const c_char, index: &c_int, kind: &mut c_int, size: &mut c_int) -> c_int {
    // SAFETY: The EI reply buffer and index are live and the output fields are writable.
    unsafe { ei_get_type(buffer, index, kind, size) }
}

fn decode_binary_ffi(
    buffer: *const c_char,
    index: &mut c_int,
    bytes: &mut [u8],
    len: &mut c_long,
) -> c_int {
    // SAFETY: The EI reply buffer and output byte slice are live for decoding.
    unsafe { ei_decode_binary(buffer, index, bytes.as_mut_ptr().cast(), len) }
}

fn ei_error_number_pointer() -> *mut c_int {
    // SAFETY: EI returns its process-local error-number pointer.
    unsafe { __erl_errno_place() }
}

/// Outcome of the EI call in `erlc.c`.
pub enum CompileServerResult {
    /// The C code's `start_compile_server` label is reached.
    StartServer(OsString),
    /// The server returned output and the process exits without starting `erl`.
    Reply {
        status: i32,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
    },
}

/// Initializes Erl_Interface as `main` does before option parsing.
pub fn ei_init_port() {
    initialize_ei();
}

/// Runs `call_compile_server` through the OTP EI API and returns its next C control-flow action.
pub fn call_compile_server(
    argv: &[OsString],
    source_file: &OsStr,
    cwd: &OsStr,
    envs: &[(&str, &OsStr)],
    debug: i32,
) -> Result<CompileServerResult, String> {
    let user = user_name();
    let server_id = std::env::var_os("ERLC_SERVER_ID").unwrap_or_default();
    if server_id
        .as_bytes()
        .iter()
        .any(|byte| b",@.!#$%^&=+*/()[]{}|'\"`~?".contains(byte))
    {
        return Err(
            "ERLC_SERVER_ID must not contain characters that are invalid in node names.\n"
                .to_string(),
        );
    }

    let node_name = CString::new(
        [
            b"erlc_client_".as_slice(),
            user.as_bytes(),
            b"_".as_slice(),
            std::process::id().to_string().as_bytes(),
        ]
        .concat(),
    )
    .map_err(|_| "Invalid client node name".to_string())?;
    let cookie = c"erlc_compile_server_cookie";
    // SAFETY: `EiCnode` mirrors the OTP-29.1.1 `ei_cnode` layout and contains only zero-valid fields.
    let mut cnode: EiCnode = unsafe { std::mem::zeroed() };
    let init = connect_init(&mut cnode, &node_name, cookie);
    if init < 0 {
        if debug > 1 {
            eprintln!(
                "\ncan't create C node {}: {}",
                node_name.to_string_lossy(),
                ei_error()
            );
        }
        return Ok(CompileServerResult::StartServer(server_node(
            &server_id, &user, b"host",
        )?));
    }

    let host = this_hostname(&cnode);
    let remote = remote_node(&server_id, &user, &host)?;
    let remote_c =
        CString::new(remote.as_bytes()).map_err(|_| "Invalid server node name".to_string())?;
    let fd = connect(&mut cnode, &remote_c);
    if fd < 0 {
        if debug > 1 {
            eprintln!(
                "failed to connect to compile server {}: {}",
                remote.to_string_lossy(),
                ei_error()
            );
        }
        return Ok(CompileServerResult::StartServer(server_node(
            &server_id, &user, &host,
        )?));
    }

    let mut args = new_versioned_buffer();
    encode_request(&mut args, argv, cwd, envs)?;
    let mut reply = new_versioned_buffer();
    // SAFETY: `args.buff` points into the EI-owned versioned ETF buffer and index is at least one.
    let input = unsafe { args.buff.add(1) };
    let reply_size = rpc(&mut cnode, fd, input, args.index - 1, &mut reply);
    if reply_size < 0 {
        if debug > 1 {
            eprintln!(
                "failed to rpc to node {}: {}",
                remote.to_string_lossy(),
                ei_error()
            );
        }
        return Ok(CompileServerResult::StartServer(server_node(
            &server_id, &user, &host,
        )?));
    }
    decode_reply(&reply, source_file, debug, &remote)
}

fn user_name() -> OsString {
    ["LOGNAME", "USER"]
        .into_iter()
        .find_map(std::env::var_os)
        .unwrap_or_else(|| OsString::from("nouser"))
}

fn remote_node(server_id: &OsStr, user: &OsStr, host: &[u8]) -> Result<OsString, String> {
    let mut bytes = b"erl_compile_server_".to_vec();
    bytes.extend_from_slice(server_id.as_bytes());
    bytes.push(b'_');
    bytes.extend_from_slice(user.as_bytes());
    bytes.push(b'@');
    bytes.extend_from_slice(host);
    if bytes.len() >= 256 {
        return Err(format!(
            "Compile server node name is too long.\n\tERL_SERVER_ID = {}\n\tuser name = {}\n",
            server_id.to_string_lossy(),
            user.to_string_lossy()
        ));
    }
    Ok(OsString::from_vec(bytes))
}

fn server_node(server_id: &OsStr, user: &OsStr, host: &[u8]) -> Result<OsString, String> {
    let remote = remote_node(server_id, user, host)?;
    let bytes = remote.as_bytes();
    let at = bytes
        .iter()
        .position(|byte| *byte == b'@')
        .unwrap_or(bytes.len());
    Ok(OsString::from_vec(bytes[..at].to_vec()))
}

fn new_versioned_buffer() -> EiXBuff {
    let mut buffer = EiXBuff {
        buff: std::ptr::null_mut(),
        buffsz: 0,
        index: 0,
    };
    new_buffer(&mut buffer);
    buffer
}

fn encode_request(
    buffer: &mut EiXBuff,
    argv: &[OsString],
    cwd: &OsStr,
    envs: &[(&str, &OsStr)],
) -> Result<(), String> {
    encode_list_header(buffer, 1);
    encode_map_header(buffer, 4);
    encode_atom(buffer, c"encoding");
    let encoding = get_encoding();
    encode_atom(buffer, encoding);
    encode_atom(buffer, c"cwd");
    encode_binary(buffer, cwd.as_bytes());
    encode_atom(buffer, c"env");
    encode_env(buffer, envs)?;
    encode_atom(buffer, c"command_line");
    for arg in argv {
        encode_list_header(buffer, 1);
        encode_binary(buffer, arg.as_bytes());
    }
    encode_empty_list(buffer);
    encode_empty_list(buffer);
    Ok(())
}

fn encode_env(buffer: &mut EiXBuff, overrides: &[(&str, &OsStr)]) -> Result<(), String> {
    const NAMES: [&str; 6] = [
        "ERL_AFLAGS",
        "ERL_FLAGS",
        "ERL_ZFLAGS",
        "ERL_COMPILER_OPTIONS",
        "ERL_LIBS",
        "ERLC_CONFIGURATION",
    ];
    for name in NAMES {
        let value = overrides
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| value.to_os_string())
            .or_else(|| std::env::var_os(name));
        let Some(value) = value else { continue };
        let name_c = CString::new(name).map_err(|_| "Invalid environment key".to_string())?;
        let value_c =
            CString::new(value.as_bytes()).map_err(|_| "NUL in environment value".to_string())?;
        encode_list_header(buffer, 1);
        encode_tuple_header(buffer, 2);
        encode_string(buffer, &name_c);
        encode_string(buffer, &value_c);
    }
    encode_empty_list(buffer);
    Ok(())
}

fn get_encoding() -> &'static std::ffi::CStr {
    for name in ["LC_ALL", "LC_CTYPE", "LANG"] {
        if let Some(value) = std::env::var_os(name) {
            return if value.as_bytes().windows(5).any(|window| window == b"UTF-8") {
                c"utf8"
            } else {
                c"latin1"
            };
        }
    }
    c"latin1"
}

fn decode_reply(
    reply: &EiXBuff,
    source_file: &OsStr,
    debug: i32,
    remote: &OsStr,
) -> Result<CompileServerResult, String> {
    let mut index = 0;
    let mut atom = [c_char::default(); MAXATOMLEN];
    if decode_atom(reply.buff, &mut index, &mut atom) == 0 && atom_equals(&atom, b"wrong_config") {
        if debug > 1 {
            eprintln!("wrong configuration");
        }
        let node_name = remote
            .as_bytes()
            .split(|byte| *byte == b'@')
            .next()
            .unwrap_or_default();
        return Ok(CompileServerResult::StartServer(OsString::from_vec(
            node_name.to_vec(),
        )));
    }
    let mut arity = 0;
    if decode_tuple_header(reply.buff, &mut index, &mut arity) == 0 {
        atom[0] = c_char::default();
        if arity >= 2 {
            decode_atom(reply.buff, &mut index, &mut atom);
        }
        let status = (atom[0] == b'e' as c_char) as i32;
        if arity == 2 && atom_equals(&atom, b"ok") {
            let output = decode_binary(reply, &mut index);
            if debug > 0 {
                eprintln!("called server for {} => ok", source_file.to_string_lossy());
            }
            if let Some(stdout) = output {
                return Ok(CompileServerResult::Reply {
                    status: 0,
                    stdout,
                    stderr: Vec::new(),
                });
            }
        } else if arity == 3 {
            if debug > 0 {
                eprintln!(
                    "called server for {} => {}",
                    source_file.to_string_lossy(),
                    if status != 0 { "error" } else { "ok" }
                );
            }
            let stdout = decode_binary(reply, &mut index).unwrap_or_default();
            let stderr = decode_binary(reply, &mut index).unwrap_or_default();
            return Ok(CompileServerResult::Reply {
                status,
                stdout,
                stderr,
            });
        }
    }
    let node_name = remote
        .as_bytes()
        .split(|byte| *byte == b'@')
        .next()
        .unwrap_or_default();
    Ok(CompileServerResult::StartServer(OsString::from_vec(
        node_name.to_vec(),
    )))
}

fn decode_binary(reply: &EiXBuff, index: &mut c_int) -> Option<Vec<u8>> {
    let mut kind = 0;
    let mut size = 0;
    get_type(reply.buff, index, &mut kind, &mut size);
    let mut bytes = vec![0; size.max(0) as usize];
    let mut decoded_len: c_long = 0;
    if decode_binary_ffi(reply.buff, index, &mut bytes, &mut decoded_len) < 0 {
        return None;
    }
    bytes.truncate(decoded_len.max(0) as usize);
    Some(bytes)
}

fn ei_error() -> io::Error {
    let error_number = ei_error_number_pointer();
    // SAFETY: EI guarantees a valid pointer to the process-local error code.
    let errno = unsafe { *error_number };
    io::Error::from_raw_os_error(errno)
}

fn atom_equals(atom: &[c_char], value: &[u8]) -> bool {
    atom.len() > value.len()
        && atom[..value.len()]
            .iter()
            .zip(value)
            .all(|(actual, expected)| *actual == *expected as c_char)
        && atom[value.len()] == 0
}
