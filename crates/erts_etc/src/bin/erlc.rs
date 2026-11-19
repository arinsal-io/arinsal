// Port of erts/etc/common/erlc.c, OTP-29.1.1.

use arinsal_erts_etc::raw;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::Write;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};

const MAX_PATH: usize = if cfg!(target_os = "macos") {
    1024
} else {
    4096
};

fn is(arg: &OsStr, value: &str) -> bool {
    arg == OsStr::new(value)
}

fn error(message: impl std::fmt::Display) -> ! {
    eprintln!("erlc: {message}");
    std::process::exit(1);
}

// Port of get_default_emulator and file_exists in erts/etc/common/erlc.c.
fn get_default_emulator(program: &OsStr) -> OsString {
    let bytes = program.as_bytes();
    if bytes.len() < MAX_PATH
        && let Some(slash) = bytes.iter().rposition(|byte| *byte == b'/')
    {
        let mut sibling = bytes[..=slash].to_vec();
        sibling.extend_from_slice(b"erl");
        if sibling.len() < MAX_PATH
            && rustix::fs::access(OsStr::from_bytes(&sibling), rustix::fs::Access::EXEC_OK).is_ok()
        {
            return OsString::from_vec(sibling);
        }
    }
    OsString::from("erl")
}

// Port of find_executable and safe_realpath in erts/etc/common/erlc.c.
fn find_executable(program: &OsStr) -> OsString {
    if program.as_bytes().contains(&b'/') {
        return program.to_os_string();
    }
    let path = std::env::var_os("PATH").unwrap_or_else(|| OsString::from("/bin:/usr/bin"));
    for directory in path.as_bytes().split(|byte| *byte == b':') {
        let directory = if directory.is_empty() {
            OsStr::new(".")
        } else {
            OsStr::from_bytes(directory)
        };
        let candidate = Path::new(directory).join(program);
        if let Ok(absolute) = fs::canonicalize(&candidate)
            && fs::metadata(&absolute).is_ok_and(|metadata| metadata.is_file())
        {
            return absolute.into_os_string();
        }
    }
    program.to_os_string()
}

fn compile_server_setting() -> bool {
    let Some(value) = std::env::var_os("ERLC_USE_SERVER") else {
        return false;
    };
    match value.to_str() {
        Some("false" | "no") => false,
        Some("true" | "yes") => true,
        _ => {
            eprintln!(
                "erlc: Warning: Ignoring unrecognized value '{}' for environment value ERLC_USE_SERVER",
                value.to_string_lossy()
            );
            false
        }
    }
}

// Port of start_compile_server in erts/etc/common/erlc.c.
fn start_compile_server(node_name: &OsStr, argv: &[OsString], envs: &[(&str, &OsStr)], debug: i32) {
    let mut server_argv = Vec::with_capacity(argv.len() + 16);
    let mut index = 0;
    while index < argv.len() && !is(&argv[index], "-mode") {
        if is(&argv[index], "+P") || is(&argv[index], "+Q") {
            index += 2;
        } else {
            server_argv.push(argv[index].clone());
            index += 1;
        }
    }
    server_argv.extend([
        OsString::from("-boot"),
        OsString::from("$ROOT/no_dot_erlang"),
        OsString::from("-sname"),
        node_name.to_os_string(),
        OsString::from("-setcookie"),
        OsString::from("erlc_compile_server_cookie"),
        OsString::from("-hidden"),
        OsString::from("-detached"),
        OsString::from("-kernel"),
        OsString::from("start_compile_server"),
        OsString::from("true"),
        OsString::from("-eval"),
        OsString::from("is_pid(whereis(erl_compile_server)) orelse halt(1)"),
    ]);
    if debug == 1 {
        eprintln!("starting compile server {}", node_name.to_string_lossy());
    } else if debug > 1 {
        eprintln!("starting compile server {}:", node_name.to_string_lossy());
        for arg in &server_argv {
            eprint!("{} ", arg.to_string_lossy());
        }
        eprintln!();
    }
    let mut command = Command::new(&argv[0]);
    command
        .args(&server_argv[1..])
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    for (key, value) in envs {
        command.env(key, value);
    }
    if let Err(error) = command.spawn() {
        let errno = error.raw_os_error().unwrap_or(0);
        eprintln!(
            "erlc: Error {errno} executing '{}'.",
            argv[0].to_string_lossy()
        );
    }
}

// Port of run_erlang in erts/etc/common/erlc.c.
fn run_erlang(argv: &[OsString], envs: &[(&str, &OsStr)], source_file: &OsStr, debug: i32) -> ! {
    if debug > 0 {
        eprint!("spawning erl for {}", source_file.to_string_lossy());
        if debug > 1 {
            eprint!(":\n  ");
            for arg in argv {
                eprint!("{} ", arg.to_string_lossy());
            }
        }
        eprintln!();
    }
    let mut command = Command::new(&argv[0]);
    command.args(&argv[1..]);
    for (key, value) in envs {
        command.env(key, value);
    }
    let error = command.exec();
    let errno = error.raw_os_error().unwrap_or(0);
    eprintln!(
        "erlc: Error {errno} executing '{}'.",
        argv[0].to_string_lossy()
    );
    std::process::exit(1);
}

fn main() {
    let argv: Vec<OsString> = std::env::args_os().collect();
    let Some(script_name) = argv.first() else {
        error("Insufficient memory");
    };
    let mut use_server = compile_server_setting();
    raw::ei_init_port();
    let emulator =
        std::env::var_os("ERLC_EMULATOR").unwrap_or_else(|| get_default_emulator(script_name));
    if emulator.as_bytes().len() >= MAX_PATH {
        error("Value of environment variable ERLC_EMULATOR is too large");
    }
    let configuration = find_executable(&emulator);
    let envs = [
        ("ESCRIPT_NAME", script_name.as_os_str()),
        ("ERLC_CONFIGURATION", configuration.as_os_str()),
    ];

    // Port of main's centered eargv construction and compiler option translation.
    let mut base_argv = vec![emulator];
    let mut prefix_argv = Vec::new();
    let mut erl_argv = vec![
        OsString::from("+sbtu"),
        OsString::from("+A0"),
        OsString::from("+P"),
        OsString::from("65536"),
        OsString::from("+Q"),
        OsString::from("1024"),
        OsString::from("-noinput"),
        OsString::from("-mode"),
        OsString::from("minimal"),
        OsString::from("-boot"),
        OsString::from("no_dot_erlang"),
        OsString::from("-s"),
        OsString::from("erl_compile"),
        OsString::from("compile_cmdline"),
        OsString::from("-extra"),
    ];
    let mut debug = 0;
    let mut source_file = OsStr::new("<no source>");
    let mut index = 1;
    while index < argv.len() {
        source_file = OsStr::new("<no source>");
        let arg = &argv[index];
        let bytes = arg.as_bytes();
        if bytes.first() == Some(&b'+') {
            erl_argv.push(arg.clone());
        } else if bytes.first() == Some(&b'-') {
            match bytes.get(1).copied() {
                Some(b'd') if bytes.len() == 2 => debug += 1,
                Some(b'd') => erl_argv.push(arg.clone()),
                Some(b'n') if is(arg, "-no-server") => use_server = false,
                Some(b'n') => erl_argv.push(arg.clone()),
                Some(b'p') => {
                    let option = bytes.get(2).copied();
                    if option != Some(b'a') && option != Some(b'z') {
                        erl_argv.push(arg.clone());
                    } else {
                        let value = option_value(&argv, &mut index, option.unwrap());
                        prefix_argv.splice(
                            0..0,
                            [OsString::from_vec(vec![b'-', b'p', option.unwrap()]), value],
                        );
                    }
                }
                Some(b's') if is(arg, "-smp") => {
                    prefix_argv.insert(0, arg.clone());
                }
                Some(b's') if is(arg, "-server") => use_server = true,
                _ => erl_argv.push(arg.clone()),
            }
        } else {
            source_file = arg;
            erl_argv.push(arg.clone());
        }
        index += 1;
    }

    if !use_server {
        prefix_argv.insert(0, OsString::from("+S1"));
    }
    base_argv.extend(prefix_argv);
    base_argv.extend(erl_argv);

    if use_server {
        let cwd = std::env::current_dir().unwrap_or_else(|_| {
            eprintln!("erlc: failed to get current working directory");
            std::process::exit(2);
        });
        let action =
            raw::call_compile_server(&base_argv, source_file, cwd.as_os_str(), &envs, debug)
                .unwrap_or_else(|message| error(message));
        match action {
            raw::CompileServerResult::StartServer(node_name) => {
                start_compile_server(&node_name, &base_argv, &envs, debug);
            }
            raw::CompileServerResult::Reply {
                status,
                stdout,
                stderr,
            } => {
                let mut out = std::io::stdout().lock();
                let _ = out.write_all(&stdout);
                let _ = out.flush();
                let mut err = std::io::stderr().lock();
                let _ = err.write_all(&stderr);
                let _ = err.flush();
                std::process::exit(status);
            }
        }
    }
    run_erlang(&base_argv, &envs, source_file, debug);
}

fn option_value(argv: &[OsString], index: &mut usize, option: u8) -> OsString {
    let arg = argv[*index].as_bytes();
    if arg.len() > 3 {
        return OsString::from_vec(arg[3..].to_vec());
    }
    let next = *index + 1;
    if next >= argv.len() || argv[next].as_bytes().first() == Some(&b'-') {
        let option = option as char;
        error(format_args!("No value given to -{option} option"));
    }
    *index = next;
    argv[next].clone()
}
