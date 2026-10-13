use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    match env::var("CARGO_CFG_TARGET_OS").as_deref() {
        Ok("macos") => {
            println!("cargo:rustc-link-arg-tests=-Wl,-export_dynamic");
        }
        Ok("linux") => {
            println!("cargo:rustc-link-arg-tests=-rdynamic");
        }
        _ => {}
    }
    so_bindtodevice_cfg();
}

/// erts handles `bind_to_device` only `#ifdef SO_BINDTODEVICE` (inet_drv.c:7847, 9598,
/// OTP-29.1.1), so the option exists exactly when the platform headers define it.
/// Linux always does; macOS SDKs added it recently.
fn so_bindtodevice_cfg() {
    println!("cargo:rustc-check-cfg=cfg(have_so_bindtodevice)");
    println!("cargo:rerun-if-env-changed=SDKROOT");
    let defined = match env::var("CARGO_CFG_TARGET_OS").as_deref() {
        Ok("linux") => true,
        Ok("macos") => macos_sdk_root().is_some_and(|sdk| {
            fs::read_to_string(sdk.join("usr/include/sys/socket.h")).is_ok_and(|header| {
                header.lines().any(|line| {
                    let mut words = line.split_whitespace();
                    words.next() == Some("#define") && words.next() == Some("SO_BINDTODEVICE")
                })
            })
        }),
        _ => false,
    };
    if defined {
        println!("cargo:rustc-cfg=have_so_bindtodevice");
    }
}

fn macos_sdk_root() -> Option<PathBuf> {
    if let Some(sdk) = env::var_os("SDKROOT") {
        return Some(PathBuf::from(sdk));
    }
    let output = std::process::Command::new("xcrun")
        .arg("--show-sdk-path")
        .output()
        .ok()?;
    let path = String::from_utf8(output.stdout).ok()?;
    output.status.success().then(|| PathBuf::from(path.trim()))
}
