use std::env;
use std::process::Command;

/// erts reports the configure triple of the machine it was built for (`config.guess`), such as
/// `aarch64-apple-darwin24.6.0`, `aarch64-unknown-linux-gnu` or `x86_64-pc-linux-gnu`, so the value is fixed here at
/// build time rather than read from the running host.
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let arch = match env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
        Ok("aarch64") => "aarch64".to_string(),
        Ok(other) => other.to_string(),
        Err(_) => "unknown".to_string(),
    };
    let triple = match env::var("CARGO_CFG_TARGET_OS").as_deref() {
        Ok("macos") => format!("{arch}-apple-darwin{}", darwin_release()),
        // Port of erts/autoconf/config.guess:1003 (aarch64 Linux: `$CPU-unknown-linux-$LIBCABI`)
        // and :1213 (x86_64 Linux: `$CPU-pc-linux-$LIBCABI`), OTP-29.1.1; arm64 Darwin is :1453-1455.
        Ok("linux") => {
            let vendor = if matches!(arch.as_str(), "x86_64" | "x86") {
                "pc"
            } else {
                "unknown"
            };
            let env = env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
            let env = if env.is_empty() {
                "gnu".to_string()
            } else {
                env
            };
            format!("{arch}-{vendor}-linux-{env}")
        }
        Ok(os) => format!("{arch}-unknown-{os}"),
        Err(_) => format!("{arch}-unknown-unknown"),
    };
    println!("cargo:rustc-env=ARINSAL_SYSTEM_ARCHITECTURE={triple}");
}

/// The Darwin kernel release `config.guess` appends (`uname -r`); empty if it cannot be read.
fn darwin_release() -> String {
    Command::new("uname")
        .arg("-r")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|release| release.trim().to_string())
        .unwrap_or_default()
}
