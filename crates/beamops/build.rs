use std::{collections::BTreeSet, env, fs, path::PathBuf};

#[path = "build/emit.rs"]
mod emit;
#[path = "build/engine_emit.rs"]
mod engine_emit;
#[path = "build/makeops.rs"]
mod makeops;
#[path = "build/transform.rs"]
mod transform;

fn main() {
    generate_erts_tables();
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let ops = fs::read_to_string(root.join("tab/ops.tab")).expect("ops.tab");
    let _predicates = fs::read_to_string(root.join("tab/predicates.tab")).expect("predicates.tab");
    let _common_predicates =
        fs::read_to_string(root.join("tab/common_predicates.tab")).expect("common predicates.tab");
    let _generators = fs::read_to_string(root.join("tab/generators.tab")).expect("generators.tab");
    let _common_generators =
        fs::read_to_string(root.join("tab/common_generators.tab")).expect("common generators.tab");
    for path in [
        "ops.tab",
        "predicates.tab",
        "common_predicates.tab",
        "generators.tab",
        "common_generators.tab",
        "genop.tab",
    ] {
        println!(
            "cargo:rerun-if-changed={}",
            root.join("tab").join(path).display()
        );
    }
    let mut names = BTreeSet::new();
    for raw in ops.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('%') {
            continue;
        }
        if line.contains("=>") {
            continue;
        }
        if line.contains('|') || line.contains('(') {
            continue;
        }
        let Some(first) = line.split_whitespace().next() else {
            continue;
        };
        let name = first.split('/').next().unwrap_or(first);
        if name.chars().next().is_some_and(|c| c.is_ascii_lowercase())
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            names.insert(name.to_owned());
        }
    }
    let mut out = String::from(
        "// The operation names declared in OTP-29.1.1 ops.tab.\n/// All operation names declared in OTP's ARM64 ops table.\npub static SPECIFIC_OP_NAMES: &[&str] = &[\n",
    );
    for name in &names {
        out.push_str(&format!("{name:?},\n"));
    }
    out.push_str("];\n");
    fs::write(
        PathBuf::from(env::var("OUT_DIR").unwrap()).join("specific_ops.rs"),
        out,
    )
    .unwrap();
}

/// The generic and specific instruction tables of `beam_makeops` (`gen_opc[]`, `opc[]`,
/// `genop_*`), built from the tables in the order the OTP build gives them to the script:
/// genop.tab, the shared predicates and generators, then the arm64 ops, predicates and generators.
fn generate_erts_tables() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let names = [
        "genop.tab",
        "common_predicates.tab",
        "common_generators.tab",
        "ops.tab",
        "predicates.tab",
        "generators.tab",
    ];
    let texts: Vec<String> = names
        .iter()
        .map(|name| fs::read_to_string(root.join("tab").join(name)).expect("tab file"))
        .collect();
    let files: Vec<(&str, &str)> = names
        .iter()
        .zip(&texts)
        .map(|(name, text)| (*name, text.as_str()))
        .collect();
    // The definitions of the OTP build: 64-bit, no VM probes.
    let defs = [("ARCH_32", 0), ("ARCH_64", 1), ("USE_VM_PROBES", 0)]
        .into_iter()
        .map(|(name, value)| (name.to_owned(), value))
        .collect();
    let tables = makeops::Makeops::parse(&files, &defs);
    fs::write(
        PathBuf::from(env::var("OUT_DIR").unwrap()).join("erts_tables.rs"),
        tables.emit_tables(),
    )
    .unwrap();
    let programs = tables.tr_gen();
    fs::write(
        PathBuf::from(env::var("OUT_DIR").unwrap()).join("erts_programs.txt"),
        makeops::Makeops::dump_programs(&programs),
    )
    .unwrap();
    println!("cargo:rerun-if-changed=build/makeops.rs");
    println!("cargo:rerun-if-changed=build/emit.rs");
    fs::write(
        PathBuf::from(env::var("OUT_DIR").unwrap()).join("erts_transform_engine.rs"),
        tables.emit_engine(&programs),
    )
    .unwrap();
    println!("cargo:rerun-if-changed=build/transform.rs");
    println!("cargo:rerun-if-changed=build/engine_emit.rs");
}
