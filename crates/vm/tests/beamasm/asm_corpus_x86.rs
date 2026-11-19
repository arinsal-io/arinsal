use std::path::{Path, PathBuf};

fn collect_beams(root: &Path, output: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_beams(&path, output);
        } else if path
            .extension()
            .is_some_and(|extension| extension == "beam")
        {
            output.push(path);
        }
    }
}

fn command_path(program: &str, args: &[&str]) -> Option<PathBuf> {
    let output = std::process::Command::new(program)
        .args(args)
        .output()
        .ok()?;
    let text = String::from_utf8(output.stdout).ok()?;
    let text = text.trim();
    (output.status.success() && !text.is_empty()).then(|| PathBuf::from(text))
}

#[test]
fn otp_and_elixir_corpus_loads_through_x86_beamasm() {
    let roots = [
        std::env::var_os("ARINSAL_OTP_ROOT")
            .map(PathBuf::from)
            .or_else(|| {
                command_path(
                    "erl",
                    &[
                        "-noshell",
                        "-eval",
                        "io:format(\"~s\",[code:root_dir()]),halt().",
                    ],
                )
            })
            .expect("OTP 29.1.1 root: set ARINSAL_OTP_ROOT or put erl on PATH"),
        std::env::var_os("ARINSAL_ELIXIR_ROOT")
            .map(PathBuf::from)
            .or_else(|| {
                command_path("elixir", &["-e", "IO.write(:code.lib_dir(:elixir))"])
                    .and_then(|lib| lib.parent()?.parent().map(PathBuf::from))
            })
            .expect("Elixir root: set ARINSAL_ELIXIR_ROOT or put elixir on PATH"),
    ];
    let mut paths = Vec::new();
    for root in &roots {
        collect_beams(root, &mut paths);
    }
    if let Some(module) = std::env::var_os("ARINSAL_BEAMASM_CORPUS_MODULE") {
        let module = module.to_string_lossy();
        paths.retain(|path| path.file_stem().is_some_and(|stem| stem == module.as_ref()));
    }
    assert!(!paths.is_empty(), "OTP and Elixir BEAM corpus is absent");

    let mut vm = crate::common::node();
    let mut issues = Vec::new();
    let mut accepted = 0usize;
    for path in &paths {
        let bytes =
            std::fs::read(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        let beam = arinsal_beam::parse(&bytes)
            .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        match vm.load_bytes(&bytes) {
            Ok(_) => accepted += 1,
            Err(error) => issues.push(format!(
                "{}: x86 BeamAsm load failed: {error:?}",
                beam.module
            )),
        }
    }
    issues.sort();
    eprintln!(
        "x86 BeamAsm corpus: {} modules loaded, {} issues",
        accepted,
        issues.len()
    );
    for issue in &issues {
        eprintln!("  {issue}");
    }
    assert!(
        issues.is_empty(),
        "x86 BeamAsm corpus has {} load or compile failures",
        issues.len()
    );
}

#[test]
fn extended_x_fixtures_load_through_x86_beamasm() {
    let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("asm_corpus_xmem");
    std::fs::create_dir_all(&root).unwrap();
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("../beamjit/tests/fixtures");
    let mut vm = crate::common::node();
    for (file, module) in [
        ("jit_xmem.erl", "jit_xmem"),
        ("jit_xmem_asm.S", "jit_xmem_asm"),
        ("jit_big_range.erl", "jit_big_range"),
    ] {
        let output = std::process::Command::new("erlc")
            .arg("-o")
            .arg(&root)
            .arg(fixtures.join(file))
            .output()
            .expect("erlc must be on PATH");
        assert!(
            output.status.success(),
            "erlc {file}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let bytes = std::fs::read(root.join(format!("{module}.beam"))).unwrap();
        vm.load_bytes(&bytes)
            .unwrap_or_else(|error| panic!("{file}: x86 BeamAsm load failed: {error:?}"));
    }
}
