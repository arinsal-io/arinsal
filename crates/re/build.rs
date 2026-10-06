use std::env;
use std::fs;
use std::path::PathBuf;

const SOURCES: &[&str] = &[
    "auto_possess",
    "chartables",
    "chkdint",
    "compile",
    "compile_cgroup",
    "compile_class",
    "config",
    "context",
    "error",
    "extuni",
    "find_bracket",
    "match",
    "match_data",
    "newline",
    "ord2utf",
    "pattern_info",
    "script_run",
    "serialize",
    "string_utils",
    "study",
    "substring",
    "tables",
    "ucd",
    "valid_utf",
    "xclass",
];

fn main() {
    let source = fs::read_to_string("pcre2/pcre2_match.c").expect("vendored PCRE2 match source");
    let mut loops = String::new();
    let mut memchr = String::new();
    let mut coverage = String::new();
    let mut count = 0;
    for (index, line) in source.lines().enumerate() {
        let n = index + 1;
        let loop_point =
            line.contains("COST_CHK(") && !line.contains("define") && !line.contains("DBG_FAKE_");
        let memchr_point = line.contains("MEMCHR_ERLANG(") && !line.contains("define");
        if loop_point {
            loops.push_str(&format!("case {n}: goto L_LOOP_COUNT_{n};\n"));
        }
        if memchr_point {
            memchr.push_str(&format!(
                "case {n}: goto ERLANG_PCRE2_MATCH_YIELD_LINE_{n};\n"
            ));
        }
        if loop_point || memchr_point {
            coverage.push_str(&format!("#define ERLANG_YIELD_POINT_{n} {count}\n{n},\n"));
            count += 1;
        }
    }
    coverage.push_str(&format!("#define ERLANG_YIELD_POINT_CNT {count}\n"));
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    fs::write(out.join("pcre2_match_loop_break_cases.gen.h"), loops).unwrap();
    fs::write(out.join("pcre2_match_memchr_break_cases.gen.h"), memchr).unwrap();
    fs::write(out.join("pcre2_match_yield_coverage.gen.h"), coverage).unwrap();

    let mut build = cc::Build::new();
    build
        .include("pcre2")
        .include(&out)
        .define("ERLANG_INTEGRATION", None);
    build.flag_if_supported("-fvisibility=hidden");
    for source in SOURCES {
        build.file(format!("pcre2/pcre2_{source}.c"));
    }
    build.file("src/bridge.c").compile("arinsal_otp_pcre2");
    println!("cargo:rerun-if-changed=pcre2");
    println!("cargo:rerun-if-changed=src/bridge.c");
}
