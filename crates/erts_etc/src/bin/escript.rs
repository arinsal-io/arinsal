// Port of erts/etc/common/escript.c, OTP-29.1.1.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::Read;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;

const PMAX: usize = if cfg!(target_os = "macos") {
    1024
} else {
    4096
};
const LINEBUFSZ: usize = 1024;

fn error(message: impl std::fmt::Display) -> ! {
    eprintln!("escript: {message}");
    std::process::exit(1);
}

// Port of get_default_emulator and file_exists in erts/etc/common/escript.c.
fn get_default_emulator(program: &OsStr) -> OsString {
    let bytes = program.as_bytes();
    if bytes.len() < PMAX
        && let Some(slash) = bytes.iter().rposition(|byte| *byte == b'/')
    {
        let prefix = &bytes[..=slash];
        let mut sibling = prefix.to_vec();
        sibling.extend_from_slice(b"erl");
        if sibling.len() < PMAX
            && rustix::fs::access(OsStr::from_bytes(&sibling), rustix::fs::Access::EXEC_OK).is_ok()
        {
            return OsString::from_vec(sibling);
        }
        let mut nested = prefix.to_vec();
        nested.extend_from_slice(b"bin/erl");
        if nested.len() < PMAX
            && rustix::fs::access(OsStr::from_bytes(&nested), rustix::fs::Access::EXEC_OK).is_ok()
        {
            return OsString::from_vec(nested);
        }
    }
    OsString::from("erl")
}

// Port of find_prog in erts/etc/common/escript.c.
fn find_prog(original: &OsStr) -> OsString {
    if original.as_bytes().len() >= PMAX {
        error("Path too long");
    }
    if !original.as_bytes().contains(&b'/')
        && let Some(path) = std::env::var_os("PATH")
    {
        for directory in path.as_bytes().split(|byte| *byte == b':') {
            if directory.len() >= PMAX {
                continue;
            }
            let directory = OsStr::from_bytes(directory);
            if let Ok(entries) = fs::read_dir(directory)
                && entries.flatten().any(|entry| entry.file_name() == original)
            {
                let candidate = Path::new(directory).join(original);
                if let Ok(absolute) = fs::canonicalize(candidate) {
                    return absolute.into_os_string();
                }
            }
        }
    }
    fs::canonicalize(original)
        .map(|path| path.into_os_string())
        .unwrap_or_else(|_| original.to_os_string())
}

fn read_c_line(file: &mut fs::File) -> Option<Vec<u8>> {
    let mut line = Vec::with_capacity(LINEBUFSZ - 1);
    while line.len() < LINEBUFSZ - 1 {
        let mut byte = [0];
        match file.read(&mut byte) {
            Ok(0) => break,
            Ok(_) => {
                line.push(byte[0]);
                if byte[0] == b'\n' {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    (!line.is_empty()).then_some(line)
}

// Port of append_shebang_args in erts/etc/common/escript.c.
fn append_shebang_args(script_name: &OsStr, argv: &mut Vec<OsString>) {
    let mut file = fs::File::open(script_name).unwrap_or_else(|_| {
        error(format_args!(
            "Failed to open file: {}",
            script_name.to_string_lossy()
        ))
    });
    if read_c_line(&mut file).is_none() {
        return;
    }
    let second = read_c_line(&mut file);
    let line = match second {
        Some(line) if line.starts_with(b"%%!") => Some(line),
        _ => read_c_line(&mut file).filter(|line| line.starts_with(b"%%!")),
    };
    let Some(line) = line else {
        return;
    };
    let mut index = 3;
    while index < line.len() {
        while index < line.len() && line[index] == b' ' {
            index += 1;
        }
        if index >= line.len() || line[index] == b'\n' {
            break;
        }
        let start = index;
        while index < line.len() && line[index] != b' ' && line[index] != b'\n' {
            index += 1;
        }
        if start == index {
            break;
        }
        argv.push(OsString::from_vec(line[start..index].to_vec()));
        if index < line.len() && line[index] == b'\n' {
            break;
        }
    }
}

// Port of run_erlang in erts/etc/common/escript.c.
fn run_erlang(argv: &[OsString], script_name: &OsStr) -> ! {
    let program = &argv[0];
    let mut command = Command::new(program);
    command.args(&argv[1..]).env("ESCRIPT_NAME", script_name);
    let error = command.exec();
    let errno = error.raw_os_error().unwrap_or(0);
    eprintln!(
        "escript: Error executing '{}': {errno}",
        program.to_string_lossy()
    );
    std::process::exit(1);
}

fn main() {
    let argv: Vec<OsString> = std::env::args_os().collect();
    let Some(program) = argv.first() else {
        error("Insufficient memory");
    };
    let basename = Path::new(program)
        .file_name()
        .unwrap_or_else(|| OsStr::new(""));
    let invoked_as_escript = basename == "escript";
    let mut first_option_end = 0;
    let script_name;
    let user_args;
    let emulator_lookup_path;

    if invoked_as_escript {
        let mut index = 1;
        while index < argv.len() && argv[index].as_bytes().first() == Some(&b'-') {
            index += 1;
        }
        if index >= argv.len() {
            error("Missing filename\n");
        }
        first_option_end = index;
        script_name =
            OsString::from_vec(argv[index].as_bytes()[..argv[index].len().min(PMAX - 1)].to_vec());
        user_args = argv[index + 1..].to_vec();
        emulator_lookup_path = program.to_os_string();
    } else {
        let mut bytes = find_prog(program).into_vec();
        bytes.extend_from_slice(b".escript");
        bytes.truncate(PMAX - 1);
        script_name = OsString::from_vec(bytes);
        user_args = argv[1..].to_vec();
        emulator_lookup_path = script_name.clone();
    }

    let emulator = std::env::var_os("ESCRIPT_EMULATOR")
        .unwrap_or_else(|| get_default_emulator(&emulator_lookup_path));
    if emulator.as_bytes().len() >= PMAX {
        error("Value of environment variable ESCRIPT_EMULATOR is too large");
    }

    let mut erl_argv = vec![
        emulator,
        OsString::from("+B"),
        OsString::from("-noshell"),
        OsString::from("-boot"),
        OsString::from("$ROOT/no_dot_erlang"),
    ];
    append_shebang_args(&script_name, &mut erl_argv);
    erl_argv.extend([
        OsString::from("-run"),
        OsString::from("escript"),
        OsString::from("start"),
    ]);
    if invoked_as_escript {
        for option in &argv[1..first_option_end] {
            erl_argv.push(OsString::from_vec(option.as_bytes()[1..].to_vec()));
        }
    }
    erl_argv.push(OsString::from("-extra"));
    erl_argv.push(script_name.clone());
    erl_argv.extend(user_args);

    run_erlang(&erl_argv, &script_name);
}
