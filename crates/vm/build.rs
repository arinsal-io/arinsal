use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    system_info_build_constants();
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

/// Configure-time values read by `erlang:system_info/1` in erts are compiled into the runtime.
// Port of erts/emulator/beam/erl_bif_info.c (system_architecture, system_info_1, c_compiler_used),
// OTP-29.1.1, and erts/emulator/utils/make_version (ERLANG_ARCHITECTURE).
fn system_info_build_constants() {
    println!("cargo:rerun-if-env-changed=CC");
    let target = env::var("TARGET").expect("Cargo provides the target triple");
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_else(|_| "unknown".into());
    let architecture = build_target_architecture(&target);
    println!("cargo:rustc-env=ARINSAL_SYSTEM_ARCHITECTURE={architecture}");
    println!("cargo:rustc-env=ARINSAL_OTP_RELEASE=29");
    println!("cargo:rustc-env=ARINSAL_ERTS_VERSION=17.1");
    println!(
        "cargo:rustc-env=ARINSAL_BUILD_TYPE={}",
        if env::var("PROFILE").as_deref() == Ok("debug") {
            "debug"
        } else {
            "opt"
        }
    );
    println!(
        "cargo:rustc-env=ARINSAL_KERNEL_POLL={}",
        matches!(
            target_os.as_str(),
            "macos" | "linux" | "freebsd" | "openbsd" | "netbsd"
        )
    );
    let (compiler, version) = c_compiler_used();
    println!("cargo:rustc-env=ARINSAL_C_COMPILER={compiler}");
    println!("cargo:rustc-env=ARINSAL_C_COMPILER_VERSION={version}");
}

/// `ERLANG_ARCHITECTURE` describes the target passed to erts configure.
fn build_target_architecture(target: &str) -> String {
    let mut parts = target.split('-');
    let cpu = parts.next().expect("Cargo target triple has a CPU");
    let vendor = parts.next().expect("Cargo target triple has a vendor");
    let os = parts.next().expect("Cargo target triple has an OS");
    match os {
        "darwin" => format!("{cpu}-apple-darwin{}", darwin_release()),
        "linux" => {
            let environment = parts.next().unwrap_or("gnu");
            let vendor = if matches!(cpu, "x86_64" | "i386" | "i486" | "i586" | "i686") {
                "pc"
            } else {
                "unknown"
            };
            format!("{cpu}-{vendor}-linux-{environment}")
        }
        _ => format!("{cpu}-{vendor}-{os}"),
    }
}

/// `config.guess` includes the build host's kernel release in Darwin's triplet.
fn darwin_release() -> String {
    let output = Command::new("uname")
        .arg("-r")
        .output()
        .expect("uname -r must be available when building for a Darwin host");
    assert!(output.status.success(), "uname -r failed");
    String::from_utf8(output.stdout)
        .expect("uname -r output is UTF-8")
        .trim()
        .to_owned()
}

/// Match the compiler preprocessor macros that select the `c_compiler_used` tuple in erts.
fn c_compiler_used() -> (String, String) {
    let compiler = env::var("CC").unwrap_or_else(|_| "cc".into());
    let Ok(output) = Command::new(compiler)
        .args(["-dM", "-E", "-x", "c", "-"])
        .stdin(Stdio::null())
        .output()
    else {
        return ("undefined".into(), "undefined".into());
    };
    if !output.status.success() {
        return ("undefined".into(), "undefined".into());
    }
    let macros = String::from_utf8_lossy(&output.stdout);
    let value = |name: &str| {
        macros
            .lines()
            .find_map(|line| line.strip_prefix(&format!("#define {name} ")))
    };
    if let Some(major) = value("__GNUC__") {
        let mut version = vec![major.to_owned()];
        if let Some(minor) = value("__GNUC_MINOR__") {
            version.push(minor.to_owned());
            if let Some(patch) = value("__GNUC_PATCHLEVEL__") {
                version.push(patch.to_owned());
            }
        }
        return ("gnuc".into(), version.join(","));
    }
    if let Some(version) = value("_MSC_VER") {
        return ("msc".into(), version.to_owned());
    }
    ("undefined".into(), "undefined".into())
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
