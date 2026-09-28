use std::path::PathBuf;
use std::process::Command;

#[test]
fn unmodified_nb_matches_erl_arithmetic() {
    if Command::new("erl").arg("-version").output().is_err() {
        eprintln!("skipping differential NIF test: erl is unavailable");
        return;
    }
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let dir = std::env::temp_dir().join(format!("arinsal-nif-spike-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temporary directory");
    let nif = dir.join("nb.so");
    let erl_root = Command::new("erl")
        .args([
            "-noshell",
            "-eval",
            "io:format(\"~s\",[code:root_dir()]), halt().",
        ])
        .output()
        .expect("query erl root");
    assert!(erl_root.status.success());
    let include =
        PathBuf::from(String::from_utf8(erl_root.stdout).expect("root UTF-8")).join("usr/include");
    let mut cc = Command::new("cc");
    cc.args(["-O2", "-fPIC"]);
    if cfg!(target_os = "macos") {
        cc.args(["-bundle", "-undefined", "dynamic_lookup"]);
    } else {
        cc.arg("-shared");
    }
    assert!(
        cc.arg(format!("-I{}", include.display()))
            .arg(root.join("bench/nif/nb.c"))
            .arg("-o")
            .arg(&nif)
            .status()
            .expect("compile nb.c")
            .success()
    );
    let output = Command::new(env!("CARGO_BIN_EXE_nif_spike"))
        .arg(&nif)
        .output()
        .expect("run spike");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("spike UTF-8");
    let expected = Command::new("erl").args(["-noshell", "-eval",
        "io:format(\"~p ~p ~p ~p\",[7,2+3,lists:sum(binary_to_list(<<1,2,3>>)),lists:sum([1,2,3])]), halt()."])
        .output().expect("reference Erlang arithmetic");
    assert!(expected.status.success());
    let values: Vec<_> = stdout
        .lines()
        .filter_map(|line| line.split_once(": "))
        .filter(|(name, _)| ["noop", "add", "bsum", "lsum"].contains(name))
        .map(|(_, value)| value.to_owned())
        .collect();
    assert_eq!(
        values.join(" "),
        String::from_utf8(expected.stdout).expect("Erlang UTF-8")
    );
}

#[test]
fn installed_crypto_load_callback_succeeds() {
    if !cfg!(target_os = "macos") {
        eprintln!("skipping installed crypto test: macOS fixture");
        return;
    }
    let root = PathBuf::from("$HOME/.asdf/installs/erlang/29.1.1/lib");
    let Ok(versions) = std::fs::read_dir(root) else {
        eprintln!("skipping installed crypto test: OTP 29.1.1 missing");
        return;
    };
    let crypto = versions
        .filter_map(Result::ok)
        .map(|e| e.path().join("priv/lib/crypto.so"))
        .find(|path| path.exists())
        .expect("installed OTP crypto.so");
    let output = Command::new(env!("CARGO_BIN_EXE_nif_spike"))
        .arg(&crypto)
        .arg("--load")
        .output()
        .expect("run crypto load");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("load returned 0"));
}
