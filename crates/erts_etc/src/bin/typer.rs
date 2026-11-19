// Port of erts/etc/common/typer.c, OTP-29.1.1.

use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::process::CommandExt;
use std::process::Command;

const MAX_PATH: usize = if cfg!(target_os = "macos") {
    1024
} else {
    4096
};

// Port of get_default_emulator and file_exists in erts/etc/common/typer.c.
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

// Port of run_erlang in erts/etc/common/typer.c.
fn run_erlang(argv: &[OsString], script_name: &OsStr) -> ! {
    let program = &argv[0];
    let mut command = Command::new(program);
    command.args(&argv[1..]).env("ESCRIPT_NAME", script_name);
    let error = command.exec();
    let errno = error.raw_os_error().unwrap_or(0);
    eprintln!(
        "typer: Error {errno} executing '{}'.",
        program.to_string_lossy()
    );
    std::process::exit(1);
}

fn main() {
    let argv: Vec<OsString> = std::env::args_os().collect();
    let Some(script_name) = argv.first() else {
        eprintln!("typer: Insufficient memory");
        std::process::exit(1);
    };
    let emulator = get_default_emulator(script_name);
    let mut erl_argv = vec![emulator];
    let mut user_args = argv[1..].to_vec();
    if user_args.first().is_some_and(|arg| arg == "-smp") {
        erl_argv.push(OsString::from("-smpauto"));
        user_args.remove(0);
    }
    erl_argv.extend([
        OsString::from("+B"),
        OsString::from("-boot"),
        OsString::from("$ROOT/no_dot_erlang"),
        OsString::from("-run"),
        OsString::from("typer"),
        OsString::from("start"),
        OsString::from("-extra"),
    ]);
    let mut need_shell = false;
    for arg in user_args {
        if arg == "--shell" {
            need_shell = true;
        } else {
            erl_argv.push(arg);
        }
    }
    if !need_shell {
        erl_argv.insert(1, OsString::from("-noinput"));
    }

    run_erlang(&erl_argv, script_name);
}
