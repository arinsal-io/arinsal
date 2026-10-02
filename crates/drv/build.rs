use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let otp = Command::new("erl")
        .args([
            "-noshell",
            "-eval",
            "io:format(\"~s/usr/include\",[code:root_dir()]), halt().",
        ])
        .output()
        .expect("erl is required for generated driver header configuration");
    assert!(otp.status.success(), "erl include directory query failed");
    let installed = PathBuf::from(String::from_utf8(otp.stdout).expect("UTF-8 OTP root"));
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    println!("cargo:rerun-if-changed=layout.c");
    let compiler = cc::Build::new().get_compiler();
    let probe = out.join("drv_layout_probe");
    let status = compiler
        .to_command()
        .arg("-I")
        .arg(&installed)
        .arg("layout.c")
        .arg("-o")
        .arg(&probe)
        .status()
        .expect("compile layout probe");
    assert!(status.success(), "layout probe compilation failed");
    let output = Command::new(probe).output().expect("run layout probe");
    assert!(output.status.success(), "layout probe failed");
    let mut layout = String::from("// Generated from OTP 29.1.1 erl_driver.h.\n");
    for line in String::from_utf8(output.stdout)
        .expect("UTF-8 layout")
        .lines()
    {
        let (name, value) = line.split_once('=').expect("layout pair");
        let ty = if name.starts_with("SIZE_") || name.starts_with("OFF_") {
            "usize"
        } else {
            "i64"
        };
        layout.push_str(&format!("pub const {name}: {ty} = {value};\n"));
    }
    fs::write(out.join("layout.rs"), layout).expect("write layout");
    println!("cargo:rerun-if-changed=errno_probe.c");
    let errno_probe = out.join("drv_errno_probe");
    let status = compiler
        .to_command()
        .arg("errno_probe.c")
        .arg("-o")
        .arg(&errno_probe)
        .status()
        .expect("compile errno probe");
    assert!(status.success(), "errno probe compilation failed");
    let output = Command::new(errno_probe).output().expect("run errno probe");
    assert!(output.status.success(), "errno probe failed");
    let mut errno = String::from(
        "// Generated from errno_probe.c (erl_errno_str.c names on this platform).\n\
         pub(crate) const ERRNO_NAMES: &[(i32, &str)] = &[\n",
    );
    for line in String::from_utf8(output.stdout)
        .expect("UTF-8 errno names")
        .lines()
    {
        let (code, name) = line.split_once('=').expect("errno pair");
        errno.push_str(&format!("    ({code}, \"{name}\"),\n"));
    }
    errno.push_str("];\n");
    fs::write(out.join("errno.rs"), errno).expect("write errno names");
    match env::var("CARGO_CFG_TARGET_OS").as_deref() {
        Ok("macos") => println!("cargo:rustc-link-arg-tests=-Wl,-export_dynamic"),
        Ok("linux") => println!("cargo:rustc-link-arg-tests=-rdynamic"),
        _ => {}
    }
}
