//! The `zstd` module (`lib/stdlib/src/zstd.erl`) loads its built-in NIF library and behaves like
//! erl 29.1.1 (`erts/emulator/nifs/common/zstd_nif.c`).

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use arinsal_difftest::RefErl;

const MODULE: &str = "zstd_compat_probe";

const SOURCE: &str = r#"
-module(zstd_compat_probe).
-export([oneshot/0]).

inputs() ->
    Text = iolist_to_binary(lists:duplicate(2000, <<"the quick brown fox jumps over the lazy dog ">>)),
    Mixed = iolist_to_binary([<<N:32>> || N <- lists:seq(1, 5000)]),
    [<<>>, <<"hello">>, binary_to_list(<<"iolist input">>), [<<"io">>, [<<"list">>, $!]], Text, Mixed].

oneshot() ->
    Rows = [row(Level, Data) || Level <- [1, 3, 19], Data <- inputs()],
    io:format("~w~n", [Rows]),
    Default = [iolist_to_binary(zstd:compress(Data)) || Data <- inputs()],
    io:format("~w~n", [[erlang:md5(C) || C <- Default]]).

row(Level, Data) ->
    Compressed = iolist_to_binary(zstd:compress(Data, #{compressionLevel => Level})),
    Plain = iolist_to_binary(Data),
    Back = iolist_to_binary(zstd:decompress(Compressed)),
    {Level, byte_size(Plain), byte_size(Compressed), erlang:md5(Compressed), Back =:= Plain}.
"#;

type Run = (bool, String, String);

fn run(program: &Path, args: &[&str], dir: &Path) -> Run {
    let mut command = Command::new(program);
    command
        .args(args)
        .current_dir(dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // A temp dir has no .tool-versions: pin both runtimes to the reference OTP root.
    if let Some(root) = arinsal_difftest::reference::otp_root() {
        if program == Path::new("erl") {
            command = Command::new(root.join("bin/erl"));
            command
                .args(args)
                .current_dir(dir)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
        } else {
            command.env("ERL_ROOTDIR", root);
        }
    }
    let mut child = command
        .spawn()
        .unwrap_or_else(|error| panic!("spawn {}: {error}", program.display()));
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => {
                let output = child.wait_with_output().expect("output");
                return (
                    output.status.success(),
                    String::from_utf8_lossy(&output.stdout).trim().to_string(),
                    String::from_utf8_lossy(&output.stderr).trim().to_string(),
                );
            }
            Ok(None) if started.elapsed() > Duration::from_secs(120) => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("{} timed out", program.display());
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(error) => panic!("wait {}: {error}", program.display()),
        }
    }
}

/// Runs `Module:Function()` on erl and on Arinsal and returns both outputs.
fn both(function: &str) -> Option<(Run, Run)> {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping zstd differential test");
        return None;
    };
    let beam = reference
        .compile_named(MODULE, SOURCE, &[])
        .expect("compile zstd probe");
    drop(reference);
    let dir = std::env::temp_dir().join(format!("arinsal-zstd-compat-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    std::fs::write(dir.join(format!("{MODULE}.beam")), &beam).expect("write beam");
    let arinsal = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/arinsal");
    assert!(arinsal.is_file(), "build target/debug/arinsal first");
    let eval = format!("{MODULE}:{function}(), halt().");
    let args = [
        "-noshell",
        "-pa",
        dir.to_str().expect("utf-8 path"),
        "-eval",
        &eval,
    ];
    let expected = run(Path::new("erl"), &args, &dir);
    let actual = run(&arinsal, &args, &dir);
    let _ = std::fs::remove_dir_all(&dir);
    Some((expected, actual))
}

#[test]
fn oneshot_compress_decompress_matches_erl() {
    let Some((expected, actual)) = both("oneshot") else {
        return;
    };
    assert!(expected.0, "erl failed: {}", expected.2);
    assert!(
        expected.1.contains(",true}"),
        "erl output has no round trip: {}",
        expected.1
    );
    assert!(actual.0, "arinsal failed: {}\n{}", actual.2, actual.1);
    similar_asserts::assert_eq!(actual.1, expected.1, "stderr {}", actual.2);
}
