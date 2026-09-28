use std::{path::PathBuf, process::Command};

pub fn otp_root() -> Option<PathBuf> {
    std::env::var_os("ARINSAL_OTP_ROOT")
        .map(PathBuf::from)
        .or_else(|| command_path("erl", "io:format(\"~s\",[code:root_dir()]),halt()."))
}

#[allow(dead_code)]
pub fn elixir_lib() -> Option<PathBuf> {
    std::env::var_os("ARINSAL_ELIXIR_ROOT")
        .map(PathBuf::from)
        .map(|root| {
            if root.ends_with("lib") {
                root
            } else {
                root.join("lib")
            }
        })
        .or_else(|| {
            command_path("elixir", "IO.write(:code.lib_dir(:elixir))")
                .and_then(|ebin| ebin.parent()?.parent().map(PathBuf::from))
        })
}

fn command_path(program: &str, expression: &str) -> Option<PathBuf> {
    let output = if program == "elixir" {
        Command::new(program)
            .args(["-e", expression])
            .output()
            .ok()?
    } else {
        Command::new(program)
            .args(["-noshell", "-eval", expression])
            .output()
            .ok()?
    };
    if !output.status.success() {
        return None;
    }
    let path = PathBuf::from(String::from_utf8(output.stdout).ok()?);
    path.exists().then_some(path)
}
