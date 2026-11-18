use std::{collections::BTreeSet, env, fs, path::PathBuf};

#[path = "build/emit.rs"]
mod emit;
#[path = "build/engine_emit.rs"]
mod engine_emit;
#[path = "build/makeops.rs"]
mod makeops;
#[path = "build/transform.rs"]
mod transform;

/// The JIT architecture whose tables the build uses, as erts' Makefile picks
/// `beam/jit/$(JIT_ARCH)/{ops,predicates,generators}.tab` for the target
/// (erts/emulator/Makefile.in:73-76, OTP-29.1.1).
fn jit_arch() -> &'static str {
    match env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
        Ok("x86_64") => "x86",
        Ok("aarch64") => "arm",
        other => panic!("BeamAsm has no JIT for target architecture {other:?}"),
    }
}

fn main() {
    generate_erts_tables();
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let arch = jit_arch();
    let ops = fs::read_to_string(root.join("tab").join(arch).join("ops.tab")).expect("ops.tab");
    for path in [
        format!("{arch}/ops.tab"),
        format!("{arch}/predicates.tab"),
        "common_predicates.tab".to_owned(),
        format!("{arch}/generators.tab"),
        "common_generators.tab".to_owned(),
        "genop.tab".to_owned(),
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
        "// The operation names declared in OTP-29.1.1 ops.tab.\n/// All operation names declared in the target's JIT ops table.\npub static SPECIFIC_OP_NAMES: &[&str] = &[\n",
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
/// genop.tab, the shared predicates and generators, then the target JIT's ops, predicates and
/// generators.
fn generate_erts_tables() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let arch = jit_arch();
    let names = [
        "genop.tab".to_owned(),
        "common_predicates.tab".to_owned(),
        "common_generators.tab".to_owned(),
        format!("{arch}/ops.tab"),
        format!("{arch}/predicates.tab"),
        format!("{arch}/generators.tab"),
    ];
    let texts: Vec<String> = names
        .iter()
        .map(|name| fs::read_to_string(root.join("tab").join(name)).expect("tab file"))
        .collect();
    let files: Vec<(&str, &str)> = names
        .iter()
        .zip(&texts)
        .map(|(name, text)| (name.as_str(), text.as_str()))
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
    fs::write(
        PathBuf::from(env::var("OUT_DIR").unwrap()).join("beamasm_emit.rs"),
        tables.emit_beamasm_glue(),
    )
    .unwrap();
    // Both JIT architectures' `opc[]`, for build scripts that run on the host but generate
    // code for the target (beamjit's arm dispatch): when this crate is a build-dependency,
    // `CARGO_CFG_TARGET_ARCH` above is the host's.
    let mut generics = String::from("// Generated from the OTP-29.1.1 tables by build.rs.\n");
    for (jit, ident) in [("arm", "OPC_GENERICS_ARM"), ("x86", "OPC_GENERICS_X86")] {
        let names = [
            "genop.tab".to_owned(),
            "common_predicates.tab".to_owned(),
            "common_generators.tab".to_owned(),
            format!("{jit}/ops.tab"),
            format!("{jit}/predicates.tab"),
            format!("{jit}/generators.tab"),
        ];
        let texts: Vec<String> = names
            .iter()
            .map(|name| fs::read_to_string(root.join("tab").join(name)).expect("tab file"))
            .collect();
        let files: Vec<(&str, &str)> = names
            .iter()
            .zip(&texts)
            .map(|(name, text)| (name.as_str(), text.as_str()))
            .collect();
        let defs = [("ARCH_32", 0), ("ARCH_64", 1), ("USE_VM_PROBES", 0)]
            .into_iter()
            .map(|(name, value)| (name.to_owned(), value))
            .collect();
        generics.push_str(&makeops::Makeops::parse(&files, &defs).emit_opc_generics(ident));
    }
    fs::write(
        PathBuf::from(env::var("OUT_DIR").unwrap()).join("opc_generics.rs"),
        generics,
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
