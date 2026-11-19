// Port of lib/erl_interface/src/prog/erl_call.c, OTP-29.1.1.

use arinsal_erts_etc::raw::{self, ErlCallClient, ResolvedHost};
use rustix::process::{Pid, Signal, WaitOptions, kill_process, waitpid};
use std::ffi::{CString, OsStr, OsString};
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MAX_HOSTNAME: usize = 253;
const MAX_NODE: usize = 257;

#[derive(Default)]
struct Flags {
    start: bool,
    cookie_set: bool,
    module: bool,
    eval: bool,
    random: bool,
    dynamic_name: bool,
    long_name: bool,
    localhost_fallback: bool,
    debug: bool,
    verbose: bool,
    halt: bool,
    fetch_stdout: bool,
    print_result: bool,
    port: Option<i64>,
    hostname: Option<OsString>,
    cookie: Option<OsString>,
    node: Option<OsString>,
    hidden: Option<OsString>,
    apply: Option<OsString>,
    script: Option<OsString>,
}

fn main() {
    std::process::exit(run());
}

// Port of lib/erl_interface/src/prog/erl_call.c (main), OTP-29.1.1.
fn run() -> i32 {
    let argv: Vec<OsString> = std::env::args_os().collect();
    let program = argv
        .first()
        .map(|arg| arg.to_string_lossy().into_owned())
        .unwrap_or_else(|| "erl_call".to_owned());
    raw::ei_init_port();

    let mut flags = match parse_args(&argv[1..], &program) {
        Ok(flags) => flags,
        Err(status) => return status,
    };
    if (flags.module && flags.eval)
        || (flags.port.is_some() && flags.start)
        || (flags.port.is_some() && flags.node.is_some())
    {
        usage(&program);
        return 0;
    }

    let module_source = if flags.module {
        match read_stdin() {
            Ok(source) => Some(source),
            Err(errno) => {
                eprint!("erl_call: can't read stdin, errno = {errno}");
                return 1;
            }
        }
    } else {
        None
    };
    let module_name = module_source.as_deref().and_then(get_module_name);

    if flags.verbose || flags.debug {
        eprintln!(
            "erl_call: node = {}\nCookie = {}\nflags = {} {} {}\nmodule: name = {} , size = {}\napply = {}",
            flags.node.as_deref().map_or("", os_text),
            flags.cookie.as_deref().map_or("", os_text),
            if flags.start { "startp" } else { "" },
            if flags.verbose { "verbosep" } else { "" },
            if flags.debug { "debugp" } else { "" },
            module_name.as_deref().map_or("", bytes_text),
            module_source.as_ref().map_or(0, Vec::len),
            flags.apply.as_deref().map_or("", os_text),
        );
    }

    if flags.node.is_none() && flags.port.is_none() {
        usage(&program);
        return 0;
    }

    if !flags.cookie_set {
        flags.cookie = None;
    }
    let creation = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .wrapping_add(1) as u32;
    if flags.hidden.is_none() && !flags.dynamic_name {
        let index = if flags.random {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                % 997
        } else {
            17
        };
        flags.hidden = Some(OsString::from(format!("c{index}")));
    }

    let mut local_hostname = match raw::local_hostname() {
        Ok(hostname) => hostname,
        Err(errno) => {
            eprintln!("erl_call: failed to get host name: {errno}");
            return 1;
        }
    };
    let initial_host = cstring(&local_hostname).ok();
    let mut local_resolved = if flags.localhost_fallback {
        None
    } else {
        initial_host.as_deref().and_then(raw::resolve_host)
    };
    if local_resolved.is_none() {
        let localhost = c"localhost";
        local_resolved = raw::resolve_host(localhost);
        flags.localhost_fallback = true;
        local_hostname = format_node_hostname(&flags, &local_hostname);
    } else if let Some(resolved) = &local_resolved {
        local_hostname = format_node_hostname(&flags, &resolved.name);
    }
    let Some(local_resolved) = local_resolved else {
        eprintln!("erl_call: can't ei_gethostbyname(localhost)");
        return 1;
    };

    let alive = flags.hidden.as_deref().map(os_bytes);
    let nodename = if flags.dynamic_name {
        None
    } else {
        let Some(alive) = alive else {
            return 1;
        };
        let mut name = alive.to_vec();
        name.push(b'@');
        name.extend_from_slice(&local_hostname);
        if name.len() > MAX_NODE {
            eprintln!(
                "erl_call: hostname too long: {}",
                bytes_text(&local_hostname)
            );
            return 1;
        }
        Some(name)
    };
    let (Ok(local_hostname_c), Ok(alive_c), Ok(nodename_c), Ok(cookie_c)) = (
        cstring(&local_hostname),
        alive.map(cstring).transpose(),
        nodename.as_deref().map(cstring).transpose(),
        flags
            .cookie
            .as_deref()
            .map(|cookie| cstring(os_bytes(cookie)))
            .transpose(),
    ) else {
        eprintln!("erl_call: can't create C node");
        return 1;
    };
    let creation = ((creation as u16) as i16 as i32) as u32;
    let mut client = match ErlCallClient::new(
        &local_hostname_c,
        alive_c.as_deref(),
        nodename_c.as_deref(),
        local_resolved.address,
        cookie_c.as_deref(),
        creation,
    ) {
        Ok(client) => client,
        Err(_) => {
            eprintln!(
                "erl_call: can't create C node {}; {}",
                nodename.as_deref().map_or("", bytes_text),
                raw::ei_error_number(),
            );
            return 1;
        }
    };

    let node_bytes = flags.node.as_deref().map(os_bytes);
    let mut node_name = node_bytes.map(<[u8]>::to_vec);
    let (host, base_node) = if flags.port.is_some() && flags.hostname.is_some() {
        (
            flags
                .hostname
                .as_deref()
                .map(os_bytes)
                .unwrap_or_default()
                .to_vec(),
            None,
        )
    } else if flags.port.is_some() || !node_bytes.is_some_and(|node| node.contains(&b'@')) {
        (client.hostname(), node_name.as_deref())
    } else {
        let node = node_name.as_mut().expect("node is present");
        let at = node.iter().position(|byte| *byte == b'@').unwrap();
        let host = node[at + 1..].to_vec();
        node.truncate(at);
        (host, Some(node.as_slice()))
    };

    let host_c = match cstring(&host) {
        Ok(host) => host,
        Err(_) => {
            eprintln!("erl_call: can't ei_gethostbyname({})", bytes_text(&host));
            return 1;
        }
    };
    let resolved_target = if flags.localhost_fallback && host == client.hostname() {
        None
    } else {
        let Some(resolved) = raw::resolve_host(&host_c) else {
            eprintln!("erl_call: can't ei_gethostbyname({})", bytes_text(&host));
            return 1;
        };
        Some(resolved)
    };
    let host_name = resolved_target
        .as_ref()
        .map(|resolved| format_node_hostname(&flags, &resolved.name))
        .unwrap_or_else(|| client.hostname());
    let remote_node = if flags.port.is_none() {
        let Some(base_node) = base_node else {
            eprintln!("erl_call: nodename too long: {}", bytes_text(&host_name));
            return 1;
        };
        let mut remote = base_node.to_vec();
        remote.push(b'@');
        remote.extend_from_slice(&host_name);
        if remote.len() > MAX_NODE {
            eprintln!("erl_call: nodename too long: {}", bytes_text(base_node));
            return 1;
        }
        Some(remote)
    } else {
        None
    };

    let fd = if flags.start && !flags.halt {
        let node = remote_node.as_deref().unwrap_or_default();
        match connect_node(&mut client, &flags, node) {
            Ok(fd) => fd,
            Err(status) => return status,
        }
    } else if let Some(remote_node) = remote_node.as_deref() {
        let remote = match cstring(remote_node) {
            Ok(remote) => remote,
            Err(_) => return 1,
        };
        client.connect(&remote)
    } else {
        client.connect_host_port(&host_c, flags.port.unwrap_or_default() as i32)
    };

    if fd < 0 {
        if flags.halt {
            return 0;
        }
        if let Some(remote_node) = remote_node.as_deref() {
            eprintln!(
                "erl_call: failed to connect to node {}",
                bytes_text(remote_node)
            );
        } else {
            eprintln!(
                "erl_call: failed to connect to node with address \"{}:{}\"",
                flags.hostname.as_deref().map_or("", os_text),
                flags.port.unwrap_or_default()
            );
        }
        return 1;
    }

    if flags.halt && fd != 0 {
        if let Ok(input) = raw::encode_empty_arguments() {
            let _ = client.rpc(fd, c"erlang", c"halt", &input, false);
        }
        return 0;
    }
    if flags.verbose {
        if let Some(remote_node) = remote_node.as_deref() {
            eprintln!(
                "erl_call: we are now connected to node \"{}\"",
                bytes_text(remote_node)
            );
        } else {
            eprintln!(
                "erl_call: we are now connected to node with address \"{}:{}\"",
                flags.hostname.as_deref().map_or("", os_text),
                flags.port.unwrap_or_default()
            );
        }
    }

    if flags.module
        && let (Some(source), Some(name)) = (module_source.as_deref(), module_name.as_deref())
    {
        if name.len() + 5 > 256 {
            eprintln!("erl_call: module name too long: {}", bytes_text(name));
            return 1;
        }
        let mut filename = name.to_vec();
        filename.extend_from_slice(b".erl");
        let filename_c = match cstring(&filename) {
            Ok(filename) => filename,
            Err(_) => return 1,
        };
        let input = match raw::encode_file_write(&filename_c, source) {
            Ok(input) => input,
            Err(_) => return 1,
        };
        if client
            .rpc(fd, c"file", c"write_file", &input, false)
            .is_err()
        {
            eprintln!(
                "erl_call: can't write to source file {}",
                bytes_text(&filename)
            );
            return 1;
        }
        let input = match raw::encode_compile_file(&filename_c) {
            Ok(input) => input,
            Err(_) => return 1,
        };
        if client.rpc(fd, c"c", c"c", &input, false).is_err() {
            eprintln!("erl_call: can't compile file {}", bytes_text(&filename));
        }
    }

    if flags.eval {
        let eval_source = match read_stdin() {
            Ok(source) => source,
            Err(errno) => {
                eprint!("erl_call: can't read stdin, errno = {errno}");
                return 1;
            }
        };
        let input = match raw::encode_eval_arguments(&eval_source) {
            Ok(input) => input,
            Err(_) => return 1,
        };
        match client.rpc(fd, c"erl_eval", c"eval_str", &input, flags.fetch_stdout) {
            Ok(reply) => {
                if flags.print_result {
                    print_reply(&reply);
                }
            }
            Err(_) => {
                eprintln!(
                    "erl_call: evaluating input failed: {}",
                    bytes_text(&eval_source)
                );
                return 1;
            }
        }
    }

    if let Some(apply) = flags.apply.as_deref() {
        let Some((module, function, arguments)) = split_apply(os_bytes(apply)) else {
            eprintln!("erl_call: wrong format of apply string (1)");
            return 1;
        };
        if flags.verbose {
            eprintln!(
                "erl_call: module = {}, function = {}, args = {}",
                bytes_text(&module),
                bytes_text(&function),
                bytes_text(&arguments)
            );
        }
        let module_c = match cstring(&module) {
            Ok(module) => module,
            Err(_) => return 1,
        };
        let function_c = match cstring(&function) {
            Ok(function) => function,
            Err(_) => return 1,
        };
        let arguments_c = match cstring(&arguments) {
            Ok(arguments) => arguments,
            Err(_) => return 1,
        };
        let input = match raw::encode_apply_arguments(&arguments_c) {
            Ok(input) => input,
            Err(_) => {
                eprintln!(
                    "erl_call: Failed to parse arguments,\nsee the documentation for allowed term types.\nArguments: {}",
                    bytes_text(&arguments)
                );
                return 255;
            }
        };
        match client.rpc(fd, &module_c, &function_c, &input, flags.fetch_stdout) {
            Ok(reply) => {
                if flags.print_result {
                    print_reply(&reply);
                }
            }
            Err(_) => return 255,
        }
    }

    0
}

// Port of lib/erl_interface/src/prog/erl_call.c (main option parsing), OTP-29.1.1.
fn parse_args(args: &[OsString], program: &str) -> Result<Flags, i32> {
    let mut flags = Flags {
        print_result: true,
        ..Flags::default()
    };
    let mut index = 0;
    while index < args.len() {
        let arg = args[index].as_bytes();
        if arg.first() != Some(&b'-') {
            usage_error(program, &args[index].to_string_lossy());
            return Err(1);
        }
        match arg {
            b"-sname" => {
                let Some(value) = args.get(index + 1) else {
                    usage_arg(program, "-sname ");
                    return Err(1);
                };
                flags.node = Some(value.clone());
                flags.long_name = false;
                index += 1;
            }
            b"-name" => {
                let Some(value) = args.get(index + 1) else {
                    usage_arg(program, "-name ");
                    return Err(1);
                };
                flags.node = Some(value.clone());
                flags.long_name = true;
                index += 1;
            }
            b"-address" => {
                let Some(value) = args.get(index + 1) else {
                    usage_arg(program, "-address ");
                    return Err(1);
                };
                let value = value.as_bytes();
                if let Some(colon) = value.iter().position(|byte| *byte == b':') {
                    let host = &value[..colon];
                    let port = parse_c_long(&value[colon + 1..]);
                    flags.hostname = (!host.is_empty()).then(|| OsString::from_vec(host.to_vec()));
                    flags.port = Some(port);
                } else {
                    flags.hostname = None;
                    flags.port = Some(parse_c_long(value));
                }
                if !flags.port.is_some_and(|port| (1..=65535).contains(&port)) {
                    usage_error(program, "-address");
                    return Err(1);
                }
                index += 1;
            }
            b"-timeout" => {
                let Some(value) = args.get(index + 1) else {
                    usage_arg(program, "-timeout ");
                    return Err(1);
                };
                let timeout = parse_c_long(value.as_bytes());
                if timeout <= 0 || timeout >= (1 << 20) {
                    usage_error(program, "-timeout");
                    return Err(1);
                }
                raw::start_alarm(timeout as u32);
                index += 1;
            }
            b"-fetch_stdout" => flags.fetch_stdout = true,
            b"-no_result_term" => flags.print_result = false,
            b"-__uh_test__" => flags.localhost_fallback = true,
            _ => {
                if arg.len() != 2 {
                    usage_error(program, &args[index].to_string_lossy());
                    return Err(1);
                }
                match arg[1] {
                    b's' => flags.start = true,
                    b'q' => flags.halt = true,
                    b'v' => flags.verbose = true,
                    b'd' => flags.debug = true,
                    b'r' => flags.random = true,
                    b'R' => flags.dynamic_name = true,
                    b'e' => flags.eval = true,
                    b'm' => flags.module = true,
                    b'c' | b'n' | b'h' | b'x' | b'a' => {
                        let Some(value) = args.get(index + 1) else {
                            usage_arg(
                                program,
                                match arg[1] {
                                    b'c' => "-c ",
                                    b'n' => "-n ",
                                    b'h' => "-h ",
                                    b'x' => "-x ",
                                    _ => "-a ",
                                },
                            );
                            return Err(1);
                        };
                        match arg[1] {
                            b'c' => {
                                flags.cookie = Some(value.clone());
                                flags.cookie_set = true;
                            }
                            b'n' => {
                                flags.node = Some(value.clone());
                                flags.long_name = true;
                            }
                            b'h' => flags.hidden = Some(value.clone()),
                            b'x' => flags.script = Some(value.clone()),
                            _ => flags.apply = Some(value.clone()),
                        }
                        index += 1;
                    }
                    b'?' => {
                        usage(program);
                        return Err(0);
                    }
                    _ => {
                        usage_error(program, &args[index].to_string_lossy());
                        return Err(1);
                    }
                }
            }
        }
        index += 1;
    }
    Ok(flags)
}

// Port of lib/erl_interface/src/prog/erl_call.c (usage), OTP-29.1.1.
fn usage(program: &str) {
    eprintln!("\nUsage: {program} [-[demqrsv]] [-c Cookie] [-h HiddenName] ");
    eprintln!("            [-x ErlScript] [-a [Mod [Fun [Args]]]] [-timeout Secs]");
    eprintln!("            (-n Node | -sname Node | -name Node | -address [HOSTNAME:]PORT)\n");
    eprintln!("  where: -a  apply(Mod,Fun,Args) (e.g -a 'erlang length [[a,b,c]]'");
    eprintln!("         -c  cookie string; by default read from ~/.erlang.cookie");
    eprintln!("         -d  direct Erlang output to ~/.erl_call.out.<Nodename>");
    eprintln!(
        "         -e  evaluate contents of standard input (e.g., echo \"X=1,Y=2,{{X,Y}}.\"|{program} -e ...)"
    );
    eprintln!("         -fetch_stdout");
    eprintln!("           execute the code, specified with the -a or -e option, in a new");
    eprintln!("           process that has a group leader that forwards all stdout (standard");
    eprintln!("           output) data so that it is printed to stdout of the");
    eprintln!(
        "           {program} process. See the {program} man page for additional information."
    );
    eprintln!("         -h  specify a name for the erl_call client node");
    eprintln!("         -m  read and compile Erlang module from stdin");
    eprintln!("         -n  name of Erlang node, same as -name");
    eprintln!("         -name  name of Erlang node, expanded to a fully qualified");
    eprintln!("         -sname name of Erlang node, short form will be used");
    eprintln!("         -address [HOSTNAME:]PORT of Erlang node");
    eprintln!("                  (the default hostname is the hostname of the local manchine)");
    eprintln!("                  (e.g., {program} -address my_host:36303 ...)");
    eprintln!("                  (cannot be combinated with -s, -n, -name and -sname)");
    eprintln!("         -no_result_term  do not print the result term");
    eprintln!("         -timeout  command timeout, in seconds");
    eprintln!("         -q  halt the Erlang node (overrides the -s switch)");
    eprintln!("         -r  use a random name for the erl_call client node");
    eprintln!("         -s  start a new Erlang node if necessary");
    eprintln!("         -v  verbose mode, i.e print some information on stderr");
    eprintln!("         -x  use specified erl start script, default is erl");
}

// Port of lib/erl_interface/src/prog/erl_call.c (usage_arg), OTP-29.1.1.
fn usage_arg(program: &str, option: &str) {
    eprintln!("Missing argument(s) for '{option}'.");
    usage(program);
}

// Port of lib/erl_interface/src/prog/erl_call.c (usage_error), OTP-29.1.1.
fn usage_error(program: &str, option: &str) {
    eprintln!("Illegal argument '{option}'.");
    usage(program);
}

fn parse_c_long(value: &[u8]) -> i64 {
    let mut index = 0;
    while value.get(index).is_some_and(u8::is_ascii_whitespace) {
        index += 1;
    }
    let negative = match value.get(index) {
        Some(b'-') => {
            index += 1;
            true
        }
        Some(b'+') => {
            index += 1;
            false
        }
        _ => false,
    };
    let mut parsed = 0i64;
    let mut found = false;
    while let Some(digit @ b'0'..=b'9') = value.get(index) {
        found = true;
        parsed = parsed
            .saturating_mul(10)
            .saturating_add(i64::from(*digit - b'0'));
        index += 1;
    }
    if !found {
        0
    } else if negative {
        parsed.saturating_neg()
    } else {
        parsed
    }
}

// Port of lib/erl_interface/src/prog/erl_call.c (read_stdin), OTP-29.1.1.
fn read_stdin() -> Result<Vec<u8>, i32> {
    let mut input = Vec::new();
    let mut buffer = vec![0; 8192];
    let mut stdin = std::io::stdin().lock();
    loop {
        match stdin.read(&mut buffer) {
            Ok(0) => return Ok(input),
            Ok(size) => input.extend_from_slice(&buffer[..size]),
            Err(error) => return Err(error.raw_os_error().unwrap_or(0)),
        }
    }
}

// Port of lib/erl_interface/src/prog/erl_call.c (get_module), OTP-29.1.1.
fn get_module_name(source: &[u8]) -> Option<Vec<u8>> {
    let marker = b"-module(";
    let at = source
        .windows(marker.len())
        .position(|part| part == marker)?
        + marker.len();
    let mut start = at;
    while source.get(start) == Some(&b' ') {
        start += 1;
    }
    let mut end = start;
    while source
        .get(end)
        .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
    {
        end += 1;
    }
    Some(source[start..end].to_vec())
}

// Port of lib/erl_interface/src/prog/erl_call.c (split_apply_string), OTP-29.1.1.
fn split_apply(input: &[u8]) -> Option<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let mut index = 0;
    skip_space(input, &mut index);
    if index == input.len() {
        return None;
    }
    let module_start = index;
    eat_word(input, &mut index);
    let module = input[module_start..index].to_vec();
    skip_space(input, &mut index);
    if index == input.len() {
        return Some((module, b"start".to_vec(), b"[]".to_vec()));
    }
    let function_start = index;
    eat_word(input, &mut index);
    let function = input[function_start..index].to_vec();
    skip_space(input, &mut index);
    let arguments = if index == input.len() {
        b"[]".to_vec()
    } else {
        input[index..].to_vec()
    };
    Some((module, function, arguments))
}

fn skip_space(input: &[u8], index: &mut usize) {
    while input.get(*index).is_some_and(u8::is_ascii_whitespace) {
        *index += 1;
    }
}

fn eat_word(input: &[u8], index: &mut usize) {
    while input
        .get(*index)
        .is_some_and(|byte| !byte.is_ascii_whitespace())
    {
        *index += 1;
    }
}

// Port of lib/erl_interface/src/prog/erl_call.c (format_node_hostname), OTP-29.1.1.
fn format_node_hostname(flags: &Flags, hostname: &[u8]) -> Vec<u8> {
    let mut formatted = hostname[..hostname.len().min(MAX_HOSTNAME)].to_vec();
    if !flags.long_name
        && let Some(dot) = formatted.iter().position(|byte| *byte == b'.')
    {
        formatted.truncate(dot);
    }
    formatted
}

// Port of lib/erl_interface/src/prog/erl_call.c (do_connect), OTP-29.1.1.
fn connect_node(client: &mut ErlCallClient, flags: &Flags, nodename: &[u8]) -> Result<i32, i32> {
    let nodename_c = cstring(nodename).map_err(|_| 1)?;
    let mut fd = client.connect(&nodename_c);
    if fd >= 0 {
        if flags.verbose {
            eprintln!("erl_call: now connected to node {}", bytes_text(nodename));
        }
        return Ok(fd);
    }

    let at = nodename.iter().rposition(|byte| *byte == b'@');
    let Some(at) = at else {
        return Ok(-52);
    };
    let alive = &nodename[..at];
    let target_host = &nodename[at + 1..];
    let target_c = cstring(target_host).map_err(|_| 1)?;
    let Some(target_resolved) = raw::resolve_host(&target_c) else {
        return Ok(-99);
    };
    let start_flags = (if flags.long_name { 0x0004 } else { 0 })
        | (if flags.verbose { 0x0020 } else { 0 })
        | (if flags.debug { 0x0010 } else { 0 });
    let start = start_system(client, alive, target_resolved, start_flags, flags);
    if start < 0 {
        eprintln!("erl_call: unable to start node, error = {start}");
        return Err(1);
    }
    fd = client.connect(&nodename_c);
    if fd >= 0 {
        if flags.verbose {
            eprintln!(
                "erl_call: now connected to node \"{}\"",
                bytes_text(nodename)
            );
        }
        return Ok(fd);
    }
    match fd {
        -2 => eprintln!("erl_call: no epmd running"),
        -4 => eprintln!("erl_call: connect failed"),
        -3 => eprintln!("erl_call: node is not running"),
        -5 => eprintln!("erl_call: connect timed out"),
        _ => eprintln!("erl_call: error during connect"),
    }
    Err(1)
}

fn start_system(
    client: &ErlCallClient,
    alive: &[u8],
    target: ResolvedHost,
    flags_value: i32,
    flags: &Flags,
) -> i32 {
    // Port of lib/erl_interface/src/prog/erl_call.c (erl_start_sys), OTP-29.1.1.
    let (listener, port) = match raw::start_listener() {
        Ok(listener) => listener,
        Err(_) => return -99,
    };
    let local_host = match cstring(&client.hostname()) {
        Ok(hostname) => hostname,
        Err(_) => return -99,
    };
    let Some(local) = raw::resolve_host(&local_host) else {
        return -99;
    };
    let local_ip = Ipv4Addr::from(local.address);
    let target_ip = Ipv4Addr::from(target.address);
    match raw::fork_process() {
        Ok(raw::ForkResult::Child) => {
            exec_erlang_child(alive, local_ip, target_ip, port, flags_value, flags)
        }
        Ok(raw::ForkResult::Parent(pid)) => {
            match wait_for_erlang(&listener, pid, Duration::from_secs(10)) {
                Ok(true) => 0,
                Ok(false) => {
                    terminate_child(pid);
                    raw::EI_TIMEOUT
                }
                Err(_) => -99,
            }
        }
        Err(_) => -99,
    }
}

fn exec_erlang_child(
    alive: &[u8],
    local_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
    port: u16,
    flags_value: i32,
    flags: &Flags,
) -> ! {
    // Port of lib/erl_interface/src/prog/erl_call.c (exec_erlang), OTP-29.1.1.
    let program = flags.script.as_deref().map(os_bytes).unwrap_or(b"erl");
    let name_flag = if flags_value & 0x0004 != 0 {
        b"-name".as_slice()
    } else {
        b"-sname".as_slice()
    };
    let mut command_line = b"exec ".to_vec();
    command_line.extend_from_slice(program);
    command_line.extend_from_slice(b" -noinput ");
    command_line.extend_from_slice(name_flag);
    command_line.push(b' ');
    command_line.extend_from_slice(alive);
    command_line.extend_from_slice(b" -s erl_reply reply ");
    command_line.extend_from_slice(local_ip.to_string().as_bytes());
    command_line.push(b' ');
    command_line.extend_from_slice(port.to_string().as_bytes());
    command_line.push(b' ');
    command_line.extend_from_slice(std::process::id().to_string().as_bytes());
    if let Some(cookie) = flags.cookie.as_deref() {
        command_line.extend_from_slice(b" -setcookie ");
        command_line.extend_from_slice(os_bytes(cookie));
    }
    if command_line.len() + 1 > 8192 {
        std::process::exit(1);
    }

    let is_local = local_ip == target_ip;
    let (program_name, first_argument) = if is_local {
        (b"sh".as_slice(), b"-c".to_vec())
    } else {
        (
            b"/usr/bin/ssh".as_slice(),
            target_ip.to_string().into_bytes(),
        )
    };
    let command_text = String::from_utf8_lossy(&command_line);
    if flags.verbose {
        eprintln!(
            "erl_call: {} {} {}",
            String::from_utf8_lossy(program_name),
            String::from_utf8_lossy(&first_argument),
            command_text
        );
    }
    raw::close_exec_descriptors();

    if flags_value & 0x0010 != 0 {
        let home = std::env::var_os("HOME").unwrap_or_default();
        let mut path = PathBuf::from(home);
        let mut filename = b".erl_start.out.".to_vec();
        filename.extend_from_slice(alive);
        path.push(OsString::from_vec(filename));
        if let Ok(mut log) = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o644)
            .open(path)
        {
            let _ = log.write_all(b"\n\n===== Log started ======\n");
            let _ = log.write_all(&raw::ctime_now());
            let _ = log.write_all(b" \nerl_call: ");
            let _ = log.write_all(program_name);
            let _ = log.write_all(b" ");
            let _ = log.write_all(&first_argument);
            let _ = log.write_all(b" ");
            let _ = log.write_all(&command_line);
            let _ = log.write_all(b"\n");
            if let Ok(duplicate) = log.try_clone() {
                let descriptor = duplicate.as_raw_fd();
                let _ = raw::duplicate_descriptor(descriptor, 1);
                let _ = raw::duplicate_descriptor(descriptor, 2);
            }
        }
    }

    let mut command = Command::new(OsStr::from_bytes(program_name));
    command.arg(OsStr::from_bytes(&first_argument));
    command.arg(OsString::from_vec(command_line.clone()));
    let error = command.exec();
    if flags.debug {
        eprintln!(
            "erl_call: exec failed: ({}) {} {} {}",
            error.raw_os_error().unwrap_or(0),
            String::from_utf8_lossy(program_name),
            String::from_utf8_lossy(&first_argument),
            command_text
        );
    }
    std::process::exit(1)
}

fn terminate_child(pid: i32) {
    let Some(pid) = Pid::from_raw(pid) else {
        return;
    };
    let _ = kill_process(pid, Signal::INT);
    thread::sleep(Duration::from_secs(1));
    if waitpid(Some(pid), WaitOptions::NOHANG)
        .ok()
        .flatten()
        .is_none()
    {
        let _ = kill_process(pid, Signal::KILL);
        thread::sleep(Duration::from_secs(1));
        let _ = waitpid(Some(pid), WaitOptions::NOHANG);
    }
}

/// `gettimeofday(&now, NULL)` as `(tv_sec, tv_usec)`.
fn gettimeofday() -> (i64, i64) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    (now.as_secs() as i64, i64::from(now.subsec_micros()))
}

// Port of lib/erl_interface/src/prog/erl_call.c (wait_for_erlang), OTP-29.1.1.
fn wait_for_erlang(listener: &TcpListener, magic: i32, timeout: Duration) -> Result<bool, i32> {
    // gettimeofday(&now, NULL); stop_time = now + timeout, normalised as erl_call.c does.
    let now = gettimeofday();
    let mut stop_sec = now.0 + timeout.as_secs() as i64;
    let mut stop_usec = now.1 + i64::from(timeout.subsec_micros());
    while stop_usec > 1_000_000 {
        stop_sec += 1;
        stop_usec -= 1_000_000;
    }
    loop {
        // Adjust the timeout to (stop_time - now).
        let now = gettimeofday();
        let mut to_sec = stop_sec - now.0;
        let mut to_usec = stop_usec - now.1;
        while to_usec < 0 && to_sec > 0 {
            to_usec += 1_000_000;
            to_sec -= 1;
        }
        if to_sec < 0 {
            return Ok(false);
        }
        match raw::wait_readable(listener.as_raw_fd(), to_sec, to_usec * 1000) {
            Ok(false) => return Ok(false),
            Err(errno) => return Err(errno),
            Ok(true) => {}
        }
        let (mut stream, _) = match listener.accept() {
            Ok(connection) => connection,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(error) => return Err(error.raw_os_error().unwrap_or(0)),
        };
        let mut message = [0; 16];
        let size = stream
            .read(&mut message)
            .map_err(|error| error.raw_os_error().unwrap_or(0))?;
        if parse_c_long(&message[..size]) == i64::from(magic) {
            return Ok(true);
        }
    }
}

// Port of lib/erl_interface/src/prog/erl_call.c (result printing), OTP-29.1.1.
fn print_reply(reply: &[u8]) {
    if let Ok(term) = raw::print_term(reply) {
        let mut stdout = std::io::stdout().lock();
        let _ = stdout.write_all(&term);
        let _ = stdout.flush();
    }
}

fn cstring(value: &[u8]) -> Result<CString, std::ffi::NulError> {
    CString::new(value)
}

fn os_bytes(value: &OsStr) -> &[u8] {
    value.as_bytes()
}

fn os_text(value: &OsStr) -> &str {
    std::str::from_utf8(value.as_bytes()).unwrap_or("")
}

fn bytes_text(value: &[u8]) -> &str {
    std::str::from_utf8(value).unwrap_or("")
}
