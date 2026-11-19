// EI sources ported from lib/erl_interface/src/Makefile.in, OTP-29.1.1.

use std::env;
use std::fs;
use std::path::PathBuf;

const SOURCES: &[&str] = &[
    "connect/ei_connect.c",
    "connect/ei_resolve.c",
    "connect/eirecv.c",
    "connect/send_reg.c",
    "decode/decode_atom.c",
    "decode/decode_big.c",
    "decode/decode_binary.c",
    "decode/decode_double.c",
    "decode/decode_fun.c",
    "decode/decode_list_header.c",
    "decode/decode_long.c",
    "decode/decode_pid.c",
    "decode/decode_port.c",
    "decode/decode_ref.c",
    "decode/decode_skip.c",
    "decode/decode_string.c",
    "decode/decode_trace.c",
    "decode/decode_tuple_header.c",
    "decode/decode_version.c",
    "encode/encode_atom.c",
    "encode/encode_binary.c",
    "encode/encode_list_header.c",
    "encode/encode_long.c",
    "encode/encode_pid.c",
    "encode/encode_string.c",
    "encode/encode_trace.c",
    "encode/encode_tuple_header.c",
    "encode/encode_version.c",
    "epmd/epmd_port.c",
    "misc/ei_decode_term.c",
    "misc/ei_init.c",
    "misc/ei_locking.c",
    "misc/ei_malloc.c",
    "misc/ei_portio.c",
    "misc/ei_pthreads.c",
    "misc/ei_trace.c",
    "misc/ei_x_encode.c",
    "misc/get_type.c",
    "misc/show_msg.c",
    "erts/erl_md5.c",
];

fn main() {
    let root = PathBuf::from("c/erl_interface");
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    let target_os = env::var("CARGO_CFG_TARGET_OS").expect("target operating system");
    let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();

    let mut config = String::from(
        "#define HAVE_ISFINITE 1\n\
         #define HAVE_PTHREAD_H 1\n\
         #define HAVE_SOCKLEN_T 1\n\
         #define HAVE_SYS_SELECT_H 1\n\
         #define HAVE_SYS_TIME_H 1\n\
         #define HAVE_SYS_UIO_H 1\n\
         #define HAVE_SYSCONF 1\n\
         #define HAVE_WRITEV 1\n",
    );
    if target_os == "linux" && target_env == "gnu" {
        config.push_str("#define HAVE_GETHOSTBYNAME_R 1\n");
    }
    fs::write(out.join("config.h"), config).expect("write EI target config");

    let mut build = cc::Build::new();
    build
        .include(&out)
        .include(root.join("include"))
        .include(root.join("connect"))
        .include(root.join("decode"))
        .include(root.join("encode"))
        .include(root.join("epmd"))
        .include(root.join("misc"))
        .include(root.join("erts"))
        .define("EI_NO_DEPR_WARN", None)
        .define("ERL_INTERFACE", None)
        .define("_REENTRANT", None)
        .flag_if_supported("-pthread");

    for source in SOURCES {
        let path = root.join(source);
        println!("cargo:rerun-if-changed={}", path.display());
        build.file(path);
    }
    for directory in [
        "connect", "decode", "encode", "epmd", "misc", "include", "erts",
    ] {
        println!("cargo:rerun-if-changed={}", root.join(directory).display());
    }
    if target_os == "linux" {
        println!("cargo:rustc-link-lib=pthread");
    }
    build.compile("arinsal_erl_interface");
}
