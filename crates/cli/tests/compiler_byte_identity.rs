use similar_asserts::assert_eq;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = Path::new("/tmp").join(format!("arinsal-compiler-byte-identity-{nonce}"));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn otp_root() -> PathBuf {
    std::env::var_os("ARINSAL_TEST_OTP_ROOT")
        .or_else(|| std::env::var_os("ARINSAL_OTP_ROOT"))
        .map(PathBuf::from)
        .or_else(|| arinsal_args::discover_otp_root(&arinsal_args::ProcessEnv).map(PathBuf::from))
        .expect("set ARINSAL_TEST_OTP_ROOT or put OTP 29.1.1 erl on PATH")
}

fn timeout_program() -> PathBuf {
    std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
        .map(|directory| directory.join("timeout"))
        .find(|candidate| candidate.is_file())
        .expect("timeout must be installed to bound child processes")
}

fn timed(command: Command, seconds: &str) -> Output {
    let mut timeout = Command::new(timeout_program());
    timeout
        .arg(seconds)
        .arg(command.get_program())
        .args(command.get_args());
    for (key, value) in command.get_envs() {
        match value {
            Some(value) => {
                timeout.env(key, value);
            }
            None => {
                timeout.env_remove(key);
            }
        }
    }
    if let Some(directory) = command.get_current_dir() {
        timeout.current_dir(directory);
    }
    timeout.output().expect("run command under timeout")
}

fn erlang_string(path: &Path) -> String {
    path.to_str()
        .expect("OTP source paths must be UTF-8")
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
}

fn compile_to_directory(
    executable: &Path,
    source_files: &[PathBuf],
    include_directory: &Path,
    output_directory: &Path,
    otp_root: &Path,
    arinsal: bool,
) -> Output {
    fs::create_dir_all(output_directory).unwrap();
    let source_list = source_files
        .iter()
        .map(|path| format!("\"{}\"", erlang_string(path)))
        .collect::<Vec<_>>()
        .join(",");
    let output = erlang_string(output_directory);
    let include = erlang_string(include_directory);
    let expression = format!(
        "lists:foreach(fun(Source) -> {{ok, Module, Beam}} = case compile:file(Source, [{{i, \"{include}\"}}, binary, return]) of {{ok, M, B}} -> {{ok, M, B}}; {{ok, M, B, _Warnings}} -> {{ok, M, B}}; Other -> erlang:error({{compile_failed, Source, Other}}) end, ok = file:write_file(filename:join(\"{output}\", atom_to_list(Module) ++ \".beam\"), Beam) end, [{source_list}]), halt()."
    );
    let mut command = Command::new(executable);
    if arinsal {
        command
            .args(["-noshell", "-eval"])
            .arg(expression)
            .env("ARINSAL_OTP_ROOT", otp_root)
            .env_remove("ERL_ROOTDIR")
            .env_remove("ROOTDIR")
            .env_remove("BINDIR");
    } else {
        command
            .args(["-noshell", "-eval"])
            .arg(expression)
            .env_remove("ERL_ROOTDIR")
            .env_remove("ROOTDIR")
            .env_remove("BINDIR");
    }
    command
        .env_remove("ERL_FLAGS")
        .env_remove("ERL_AFLAGS")
        .env_remove("ERL_ZFLAGS")
        .current_dir(output_directory);
    timed(command, "600")
}

#[test]
fn otp_compiler_beams_match_erl_byte_for_byte() {
    let otp_root = otp_root();
    let stdlib = fs::read_dir(otp_root.join("lib"))
        .unwrap()
        .filter_map(Result::ok)
        .find(|entry| entry.file_name().to_string_lossy().starts_with("stdlib-"))
        .map(|entry| entry.path().join("src"))
        .expect("OTP root must contain stdlib sources");
    let kernel_include = fs::read_dir(otp_root.join("lib"))
        .unwrap()
        .filter_map(Result::ok)
        .find(|entry| entry.file_name().to_string_lossy().starts_with("kernel-"))
        .map(|entry| entry.path().join("include"))
        .expect("OTP root must contain kernel headers");
    let repository = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let sources = [
        repository.join("crates/cli/tests/fixtures/compiler_byte_identity/t1.erl"),
        repository.join("tests/otp/erts/emulator/test/hello_SUITE_data/hello.erl"),
        stdlib.join("lists.erl"),
        stdlib.join("maps.erl"),
        stdlib.join("sets.erl"),
        stdlib.join("string.erl"),
        stdlib.join("gen_server.erl"),
        stdlib.join("base64.erl"),
    ];
    for source in &sources {
        assert!(
            source.is_file(),
            "missing compiler regression source: {}",
            source.display()
        );
    }

    let temp = TempDir::new();
    let expected_directory = temp.0.join("erl");
    let actual_directory = temp.0.join("arinsal");
    let reference_erl = otp_root.join("bin/erl");
    let expected = compile_to_directory(
        &reference_erl,
        &sources,
        &kernel_include,
        &expected_directory,
        &otp_root,
        false,
    );
    assert!(
        expected.status.success(),
        "erl compiler failed: {}",
        String::from_utf8_lossy(&expected.stderr)
    );

    let arinsal = std::env::var_os("ARINSAL_COMPILER_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_arinsal")));
    let actual = compile_to_directory(
        &arinsal,
        &sources,
        &kernel_include,
        &actual_directory,
        &otp_root,
        true,
    );
    assert!(
        actual.status.success(),
        "Arinsal compiler failed: {}",
        String::from_utf8_lossy(&actual.stderr)
    );

    for source in &sources {
        let module = source.file_stem().unwrap();
        let filename = format!("{}.beam", module.to_string_lossy());
        let expected = fs::read(expected_directory.join(&filename)).unwrap();
        let actual = fs::read(actual_directory.join(&filename)).unwrap();
        assert_eq!(actual, expected, "compiled beam differs: {filename}");
    }
}
