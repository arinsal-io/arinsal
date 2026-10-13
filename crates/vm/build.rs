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
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    let mut table = String::from("&[");
    for index in 0..DYNAMIC_NIF_TRAMPOLINES {
        table.push_str(&format!("dyn_call::<{index}>,"));
    }
    table.push(']');
    fs::write(out.join("nif_trampolines.rs"), table).expect("write trampoline table");
    fs::write(
        out.join("nif_trampoline_count.rs"),
        DYNAMIC_NIF_TRAMPOLINES.to_string(),
    )
    .expect("write trampoline count");
}

/// How many dynamically loaded NIF functions can be bound at once, across every loaded
/// library. erts has no such limit; one real application (Explorer's Polars backend alone
/// declares 436 NIFs, plus ADBC and crypto) needs several hundred.
const DYNAMIC_NIF_TRAMPOLINES: usize = 1024;

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
