//! Packaging-independent launch of the reference OTP emulator.
//!
//! The installed `erl` program is a shell script that derives `ROOTDIR` and
//! `BINDIR` from its own path, sets `PROGNAME` from `$0`, and then `exec`s
//! `erlexec`. Distribution packagers rewrite that script: Nix moves it aside
//! as `.erl-wrapped` and inserts its own wrapper, so `PROGNAME` becomes
//! `.erl-wrapped` and leaks into `init:get_arguments()` and
//! `erl -emu_args_exit`.
//!
//! Differential tests must compare against OTP semantics, not against a
//! packaging artifact. This module therefore launches `erlexec` directly with
//! the environment the stock `erl` script would have produced, including
//! `PROGNAME=erl`.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

/// Installed OTP root directory, as `code:root_dir()` reports it.
///
/// `ARINSAL_OTP_ROOT` wins when it names a directory; otherwise the installed
/// OTP `erl` program is asked. The value is resolved once per process.
pub fn otp_root() -> Option<PathBuf> {
    static ROOT: OnceLock<Option<PathBuf>> = OnceLock::new();
    ROOT.get_or_init(resolve_otp_root).clone()
}

fn resolve_otp_root() -> Option<PathBuf> {
    if let Some(root) = std::env::var_os("ARINSAL_OTP_ROOT") {
        let root = PathBuf::from(root);
        if root.is_dir() {
            return Some(root);
        }
    }
    let output = Command::new(program("erl"))
        .args([
            "-noshell",
            "-eval",
            "io:format(\"~s\",[code:root_dir()]),halt().",
        ])
        .env("ERL_AFLAGS", "")
        .env("ERL_FLAGS", "")
        .env("ERL_ZFLAGS", "")
        .output()
        .ok()?;
    let root = PathBuf::from(String::from_utf8(output.stdout).ok()?);
    (output.status.success() && root.is_dir()).then_some(root)
}

fn erts_bin_for(root: &Path) -> Option<PathBuf> {
    let versions: Vec<PathBuf> = std::fs::read_dir(root)
        .ok()?
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("erts-"))
        })
        .collect();
    let mut versions = versions;
    versions.sort();
    versions.into_iter().rev().find_map(|erts| {
        let bin = erts.join("bin");
        bin.join(program("erlexec")).is_file().then_some(bin)
    })
}

/// A reference emulator `Command`, launched the way the stock OTP `erl` script
/// launches it: directly through `erlexec`, with the derived environment and
/// `PROGNAME=erl`.
///
/// Returns `None` when the OTP root or emulator executable cannot be found.
pub fn erl() -> Option<Command> {
    let root = otp_root()?;
    let bin = erts_bin_for(&root)?;
    let mut command = Command::new(bin.join(program("erlexec")));
    command
        .env("ROOTDIR", &root)
        .env("BINDIR", &bin)
        .env("EMU", "beam")
        .env("PROGNAME", "erl");
    Some(command)
}

fn program(name: &str) -> String {
    if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_owned()
    }
}
