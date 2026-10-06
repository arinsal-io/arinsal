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
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    let mut table = String::from("&[");
    for index in 0..160 {
        table.push_str(&format!("dyn_call::<{index}>,"));
    }
    table.push(']');
    fs::write(out.join("nif_trampolines.rs"), table).expect("write trampoline table");
}
