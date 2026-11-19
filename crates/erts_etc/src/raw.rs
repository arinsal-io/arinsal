// Port of erts/etc/common/erlc.c (EI compile-server calls), OTP-29.1.1.

use std::ffi::{CStr, CString, OsStr, OsString, c_char, c_int, c_long, c_void};
use std::io;
use std::os::unix::ffi::{OsStrExt, OsStringExt};

const MAXATOMLEN: usize = 256;
const MAXATOMLEN_UTF8: usize = 1021;
const EI_MAXHOSTNAMELEN: usize = MAXATOMLEN - 2;
const EI_MAX_COOKIE_SIZE: usize = 512;

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

unsafe extern "C" {
    fn ei_init() -> c_int;
    fn ei_connect_init(
        node: *mut EiCnode,
        name: *const c_char,
        cookie: *const c_char,
        creation: u32,
    ) -> c_int;
    fn ei_thishostname(node: *const EiCnode) -> *const c_char;
    fn ei_connect(node: *mut EiCnode, remote: *mut c_char) -> c_int;
    fn ei_x_new_with_version(buffer: *mut EiXBuff) -> c_int;
    fn ei_x_encode_list_header(buffer: *mut EiXBuff, arity: c_long) -> c_int;
    fn ei_x_encode_map_header(buffer: *mut EiXBuff, arity: c_long) -> c_int;
    fn ei_x_encode_tuple_header(buffer: *mut EiXBuff, arity: c_long) -> c_int;
    fn ei_x_encode_atom(buffer: *mut EiXBuff, atom: *const c_char) -> c_int;
    fn ei_x_encode_binary(buffer: *mut EiXBuff, bytes: *const c_void, len: c_int) -> c_int;
    fn ei_x_encode_string(buffer: *mut EiXBuff, string: *const c_char) -> c_int;
    fn ei_x_encode_empty_list(buffer: *mut EiXBuff) -> c_int;
    fn ei_rpc(
        node: *mut EiCnode,
        fd: c_int,
        module: *mut c_char,
        function: *mut c_char,
        input: *const c_char,
        input_len: c_int,
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
    fn __erl_errno_place() -> *mut c_int;
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
