use std::path::PathBuf;
use std::process::Command;

fn main() {
    let source = "src/stencil_source.rs";
    println!("cargo:rerun-if-changed={source}");
    let out = PathBuf::from(std::env::var_os("OUT_DIR").unwrap()).join("stencil.o");
    let status = Command::new(std::env::var_os("RUSTC").unwrap())
        .args(["--crate-type=lib", "--emit=obj", "--edition=2024"])
        .args(["-C", "opt-level=3", "-C", "panic=abort"])
        .arg(source)
        .arg("-o")
        .arg(out)
        .status()
        .unwrap();
    assert!(status.success(), "stencil rustc failed");
}
