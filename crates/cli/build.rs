fn main() {
    match std::env::var("CARGO_CFG_TARGET_OS").as_deref() {
        Ok("macos") => println!("cargo:rustc-link-arg-bins=-Wl,-export_dynamic"),
        Ok("linux") => println!("cargo:rustc-link-arg-bins=-rdynamic"),
        _ => {}
    }
}
