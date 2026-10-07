use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const IMPLEMENTED: &[&str] = &[
    "enif_priv_data",
    "enif_alloc",
    "enif_free",
    "enif_get_int",
    "enif_make_int",
    "enif_get_long",
    "enif_make_long",
    "enif_make_ulong",
    "enif_get_list_cell",
    "enif_make_atom",
    "enif_make_badarg",
    "enif_is_list",
    "enif_inspect_binary",
    "enif_get_tuple",
    "enif_alloc_binary",
    "enif_release_binary",
    "enif_snprintf",
    "enif_open_resource_type",
    "enif_mutex_create",
    "enif_mutex_destroy",
    "enif_mutex_lock",
    "enif_mutex_unlock",
    "enif_set_option",
    "enif_dlopen",
    "enif_dlsym",
];

fn main() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let header = root.join("spec/otp-29.1.1/erl_nif_api_funcs.h");
    let include = env::var("ERL_NIF_INCLUDE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let output = Command::new("erl")
                .args([
                    "-noshell",
                    "-eval",
                    "io:format(\"~s/usr/include\",[code:root_dir()]), halt().",
                ])
                .output()
                .expect("erl required, or set ERL_NIF_INCLUDE");
            assert!(
                output.status.success(),
                "failed to query installed Erlang include directory"
            );
            PathBuf::from(String::from_utf8(output.stdout).expect("Erlang root is UTF-8"))
        });
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    println!("cargo:rerun-if-changed=layout.c");
    println!("cargo:rerun-if-changed=shim.c");
    println!("cargo:rerun-if-changed={}", header.display());
    println!("cargo:rerun-if-env-changed=ERL_NIF_INCLUDE");

    let compiler = cc::Build::new().get_compiler();
    let probe = out.join("nif_layout_probe");
    let status = compiler
        .to_command()
        .arg("-I")
        .arg(&include)
        .arg("layout.c")
        .arg("-o")
        .arg(&probe)
        .status()
        .expect("compile layout probe");
    assert!(status.success(), "layout probe compilation failed");
    let result = Command::new(&probe).output().expect("run layout probe");
    assert!(result.status.success(), "layout probe failed");
    let mut layout = String::from("// Generated from the installed OTP header.\n");
    for line in String::from_utf8(result.stdout)
        .expect("probe output is UTF-8")
        .lines()
    {
        let (name, value) = line.split_once('=').expect("probe key=value");
        layout.push_str(&format!("pub const {name}: usize = {value};\n"));
    }
    fs::write(out.join("layout.rs"), layout).expect("write layout");

    let source = fs::read_to_string(header).expect("read API declarations");
    let mut names = Vec::new();
    for line in source.lines() {
        if let Some(rest) = line.strip_prefix("ERL_NIF_API_FUNC_DECL(") {
            let mut fields = rest.splitn(3, ',');
            let _return_type = fields.next();
            let name = fields.next().expect("API name").trim();
            assert!(name.starts_with("enif_"), "unexpected API name: {name}");
            names.push(name.to_owned());
        }
    }
    assert_eq!(names.len(), 180, "unexpected OTP 29.1.1 API list");
    let mut stubs = format!("pub const API_COUNT: usize = {};\n", names.len());
    let missing: Vec<_> = names
        .iter()
        .filter(|n| !IMPLEMENTED.contains(&n.as_str()))
        .collect();
    stubs.push_str(&format!(
        "pub static STUBS: [extern \"C\" fn(); {}] = [\n",
        missing.len()
    ));
    for name in &missing {
        stubs.push_str(&format!("{name},\n"));
    }
    stubs.push_str("];\n");
    for name in missing {
        stubs.push_str(&format!(
            "#[unsafe(no_mangle)] pub extern \"C\" fn {name}() {{ eprintln!(\"unimplemented {name}\"); std::process::abort(); }}\n"
        ));
    }
    fs::write(out.join("stubs.rs"), stubs).expect("write stubs");

    cc::Build::new()
        .include(&include)
        .file("shim.c")
        .compile("nif_spike_shim");

    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        println!("cargo:rustc-link-arg-bins=-Wl,-export_dynamic");
    } else if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux") {
        println!("cargo:rustc-link-arg-bins=-rdynamic");
    }
}
