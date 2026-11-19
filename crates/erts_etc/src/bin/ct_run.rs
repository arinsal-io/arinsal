// Port of erts/etc/common/ct_run.c, OTP-29.1.1.

use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::process::CommandExt;
use std::process::Command;

const MAX_PATH: usize = if cfg!(target_os = "macos") {
    1024
} else {
    4096
};

fn is(arg: &OsStr, value: &str) -> bool {
    arg == OsStr::new(value)
}

fn c_buffer(value: &OsStr, size: usize) -> OsString {
    let mut bytes = value.as_bytes().to_vec();
    bytes.truncate(size - 1);
    OsString::from_vec(bytes)
}

// Port of get_default_emulator and file_exists in erts/etc/common/ct_run.c.
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

// Port of run_erlang in erts/etc/common/ct_run.c.
fn run_erlang(argv: &[OsString], script_name: &OsStr) -> ! {
    let program = &argv[0];
    let mut command = Command::new(program);
    command.args(&argv[1..]).env("ESCRIPT_NAME", script_name);
    let error = command.exec();
    let errno = error.raw_os_error().unwrap_or(0);
    eprintln!(
        "ct_run: Error {errno} executing '{}'.",
        program.to_string_lossy()
    );
    std::process::exit(1);
}

fn main() {
    let argv: Vec<OsString> = std::env::args_os().collect();
    let Some(program) = argv.first() else {
        eprintln!("ct_run: Insufficient memory");
        std::process::exit(1);
    };
    let emulator = get_default_emulator(program);
    let mut erl_argv = vec![emulator];
    let mut node_name = OsString::from("ct");
    let mut browser = OsString::new();
    let mut full_name = false;
    let mut mode = 0_u8;
    let mut erl_args = argv.len();

    // Port of the flag scan in main in erts/etc/common/ct_run.c.
    let mut index = 1;
    while index < argv.len() {
        if is(&argv[index], "-erl_args") {
            erl_args = index;
        } else if is(&argv[index], "-sname") {
            if let Some(value) = argv.get(index + 1) {
                node_name = c_buffer(value, 100);
            }
            index += 1;
        } else if is(&argv[index], "-name") {
            if let Some(value) = argv.get(index + 1) {
                node_name = c_buffer(value, 100);
            }
            full_name = true;
            index += 1;
        } else if index < erl_args {
            if is(&argv[index], "-vts") {
                mode = 1;
            } else if is(&argv[index], "-browser") {
                if let Some(value) = argv.get(index + 1) {
                    browser = c_buffer(value, 100);
                }
                index += 1;
            } else if is(&argv[index], "-shell") {
                mode = 2;
            } else if is(&argv[index], "-ctmaster") {
                node_name = OsString::from("ct_master");
                mode = 3;
            } else if is(&argv[index], "-ctname") {
                if let Some(value) = argv.get(index + 1) {
                    node_name = c_buffer(value, 100);
                }
                mode = 4;
                index += 1;
            }
        }
        index += 1;
    }

    if full_name {
        erl_argv.extend([OsString::from("-name"), node_name]);
    } else {
        erl_argv.extend([OsString::from("-sname"), node_name]);
    }

    match mode {
        1 => {
            erl_argv.extend([
                OsString::from("-s"),
                OsString::from("ct_webtool"),
                OsString::from("script_start"),
                OsString::from("vts"),
            ]);
            if !browser.is_empty() {
                erl_argv.push(browser);
            }
            erl_argv.extend([
                OsString::from("-s"),
                OsString::from("ct_run"),
                OsString::from("script_start"),
            ]);
        }
        2 => erl_argv.extend([
            OsString::from("-s"),
            OsString::from("ct_run"),
            OsString::from("script_start"),
        ]),
        0 => erl_argv.extend([
            OsString::from("-s"),
            OsString::from("ct_run"),
            OsString::from("script_start"),
            OsString::from("-s"),
            OsString::from("erlang"),
            OsString::from("halt"),
        ]),
        _ => {}
    }

    // Port of the second argument pass in main in erts/etc/common/ct_run.c.
    index = 1;
    while index < argv.len() {
        let arg = &argv[index];
        if is(arg, "-erl_args") {
            erl_argv.push(OsString::from("-ct_erl_args"));
        } else if is(arg, "-sname") || is(arg, "-name") {
            index += 1;
        } else if index < erl_args {
            let translated = if is(arg, "-config") {
                Some("-ct_config")
            } else if is(arg, "-decrypt_key") {
                Some("-ct_decrypt_key")
            } else if is(arg, "-decrypt_file") {
                Some("-ct_decrypt_file")
            } else {
                None
            };
            erl_argv.push(translated.map_or_else(|| arg.clone(), OsString::from));
        } else {
            erl_argv.push(arg.clone());
        }
        index += 1;
    }

    run_erlang(&erl_argv, program);
}
