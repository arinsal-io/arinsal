use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

mod support;

fn collect(path: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(path) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect(&path, out);
        } else if path.extension().is_some_and(|e| e == "beam") {
            out.push(path);
        }
    }
}

#[test]
fn sample_matches_beam_lib_and_disasm() {
    let mut paths = Vec::new();
    if let Some(otp) = support::otp_root() {
        collect(&otp.join("lib"), &mut paths);
    }
    if let Some(elixir) = support::elixir_lib() {
        collect(&elixir, &mut paths);
    }
    if paths.is_empty() {
        eprintln!("installed OTP/Elixir absent; skipping");
        return;
    }
    paths.sort();
    let required = [
        "lists",
        "maps",
        "erlang",
        "gen_server",
        "elixir_expand",
        "Elixir.Enum",
        "beam_ssa_codegen",
    ];
    let mut sample: Vec<_> = paths.iter().take(50).cloned().collect();
    for name in required {
        let path = paths
            .iter()
            .find(|p| p.file_stem().is_some_and(|stem| stem == name))
            .unwrap();
        if !sample.contains(path) {
            sample.push(path.clone());
        }
    }
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/reference.escript");
    let output = Command::new("escript").arg(script).args(&sample).output();
    let Ok(output) = output else {
        eprintln!("escript absent; skipping differential check");
        return;
    };
    assert!(
        output.status.success(),
        "reference failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).unwrap();
    assert_eq!(text.lines().count(), sample.len());
    for (path, line) in sample.iter().zip(text.lines()) {
        let columns: Vec<_> = line.split('\t').collect();
        assert_eq!(columns.len(), 9, "{}", path.display());
        assert_eq!(columns[0], path.to_str().unwrap());
        let beam = arinsal_beam::parse(&fs::read(path).unwrap()).unwrap();
        let actual = [
            beam.atoms.len(),
            beam.imports.len(),
            beam.exports.len(),
            beam.lambdas.len(),
            beam.code.function_count as usize,
            beam.code.label_count as usize,
        ];
        for (i, count) in actual.iter().enumerate() {
            assert_eq!(
                *count,
                columns[i + 1].parse::<usize>().unwrap(),
                "{} count {i}",
                path.display()
            );
        }
        let ops: Vec<_> = beam
            .code
            .instructions
            .iter()
            .filter(|instr| instr.op.name() != "int_code_end")
            .map(|instr| instr.op.name())
            .collect();
        assert_eq!(
            ops.len(),
            columns[7].parse::<usize>().unwrap(),
            "{} instruction count",
            path.display()
        );
        let expected: Vec<_> = columns[8].split(',').collect();
        if ops != expected {
            let at = ops
                .iter()
                .zip(&expected)
                .position(|(a, b)| a != b)
                .unwrap_or(ops.len().min(expected.len()));
            panic!(
                "{} opcode sequence differs at {at}: rust {:?}, erl {:?}",
                path.display(),
                ops.get(at),
                expected.get(at)
            );
        }
    }
    eprintln!(
        "cross-checked {} modules against beam_lib and beam_disasm",
        sample.len()
    );
}
