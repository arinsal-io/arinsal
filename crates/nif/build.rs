use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let include = root.join("spec/otp-29.1.1");
    let otp = Command::new("erl")
        .args([
            "-noshell",
            "-eval",
            "io:format(\"~s/usr/include\",[code:root_dir()]), halt().",
        ])
        .output()
        .expect("erl is required for generated NIF header configuration");
    assert!(otp.status.success(), "erl include directory query failed");
    let installed = PathBuf::from(String::from_utf8(otp.stdout).expect("UTF-8 OTP root"));
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    println!("cargo:rerun-if-changed=layout.c");
    println!("cargo:rerun-if-changed=shim.c");
    println!(
        "cargo:rerun-if-changed={}",
        include.join("erl_nif.h").display()
    );
    let compiler = cc::Build::new().get_compiler();
    let probe = out.join("nif_layout_probe");
    let status = compiler
        .to_command()
        .arg("-I")
        .arg(&include)
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
    let mut layout = String::from("// Generated from OTP 29.1.1 erl_nif.h.\n");
    for line in String::from_utf8(output.stdout)
        .expect("UTF-8 layout")
        .lines()
    {
        let (name, value) = line.split_once('=').expect("layout pair");
        layout.push_str(&format!("pub const {name}: usize = {value};\n"));
    }
    fs::write(out.join("layout.rs"), layout).expect("write layout");
    cc::Build::new()
        .include(include)
        .include(installed)
        .file("shim.c")
        .compile("arinsal_nif_shim");
    match env::var("CARGO_CFG_TARGET_OS").as_deref() {
        Ok("macos") => {
            println!("cargo:rustc-link-arg-examples=-Wl,-export_dynamic");
            println!("cargo:rustc-link-arg-tests=-Wl,-export_dynamic");
        }
        Ok("linux") => {
            println!("cargo:rustc-link-arg-examples=-rdynamic");
            println!("cargo:rustc-link-arg-tests=-rdynamic");
        }
        _ => {}
    }
}
