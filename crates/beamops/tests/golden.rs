//! The transformation of every module of OTP's every OTP application on the code path (and of
//! Elixir's standard library when it is installed) yields exactly the specific operations the
//! recorded hashes stand for: a change of the transform engine that alters any output of any of
//! these modules fails here.
//!
//! `BEAMOPS_GOLDEN_WRITE=1 cargo test --release -p arinsal-beamops --test golden` rewrites the
//! fixtures from the current engine.

use arinsal_beam::parse;
use arinsal_beamops::{transform_module_typed, transform_module_with_line_breakpoints};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

fn fnv(hash: &mut u64, text: &str) {
    for byte in text.bytes() {
        *hash = (*hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3);
    }
}

/// The text of an operation that does not depend on the order in which this process created its
/// atoms: atoms by name, and the key hashes (functions of the atom indexes) left out.
fn stable_text(op: &arinsal_beamops::SpecificOp) -> String {
    use arinsal_beamops::SpecificOperand;
    let hash_at = |index: usize| match op.name() {
        "i_get_hash" => index == 1,
        "i_get_map_element_hash" => index == 3,
        "i_get_map_elements" => index >= 3 && (index - 3) % 3 == 2,
        _ => false,
    };
    let mut text = format!("{}(", op.name());
    for (index, operand) in op.operands().iter().enumerate() {
        match operand {
            SpecificOperand::Atom(atom) => {
                text.push_str(&format!("Atom({:?}), ", arinsal_beamops::atom_name(*atom)));
            }
            _ if hash_at(index) => text.push_str("Hash, "),
            other => text.push_str(&format!("{other:?}, ")),
        }
    }
    text.push(')');
    text
}

fn hash_module(bytes: &[u8]) -> Option<(u64, u64)> {
    let beam = parse(bytes).ok()?;
    let digest = |functions: Vec<Vec<arinsal_beamops::SpecificOp>>| {
        let mut hash = 0xcbf2_9ce4_8422_2325_u64;
        for function in functions {
            fnv(&mut hash, "|function|");
            for op in function {
                fnv(&mut hash, &stable_text(&op));
            }
        }
        hash
    };
    Some((
        digest(transform_module_typed(&beam, false).ok()?),
        digest(transform_module_with_line_breakpoints(&beam, false).ok()?),
    ))
}

fn erl_output(expression: &str) -> Option<String> {
    let output = std::process::Command::new("erl")
        .args(["-noshell", "-eval", expression])
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8(output.stdout).ok())
        .flatten()
}

fn module_hashes(ebin: &Path, hashes: &mut BTreeMap<String, (u64, u64)>) {
    let Ok(entries) = std::fs::read_dir(ebin) else {
        return;
    };
    let mut paths: Vec<_> = entries.flatten().map(|entry| entry.path()).collect();
    paths.sort();
    for path in paths {
        if path.extension().is_none_or(|extension| extension != "beam") {
            continue;
        }
        let name = path.file_stem().unwrap().to_string_lossy().into_owned();
        let bytes = std::fs::read(&path).expect("beam file");
        if let Some(pair) = hash_module(&bytes) {
            hashes.insert(name, pair);
        }
    }
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn render(hashes: &BTreeMap<String, (u64, u64)>) -> String {
    hashes
        .iter()
        .map(|(name, (typed, plain))| format!("{name} {typed:016x} {plain:016x}\n"))
        .collect()
}

fn check(fixture_name: &str, hashes: &BTreeMap<String, (u64, u64)>) {
    let path = fixture(fixture_name);
    let actual = render(hashes);
    if std::env::var_os("BEAMOPS_GOLDEN_WRITE").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, actual).unwrap();
        return;
    }
    let expected =
        std::fs::read_to_string(&path).expect("fixture (BEAMOPS_GOLDEN_WRITE=1 makes it)");
    let expected_lines: BTreeMap<_, _> = expected
        .lines()
        .filter_map(|line| line.split_once(' '))
        .collect();
    let mut differing = Vec::new();
    for line in actual.lines() {
        let (name, rest) = line.split_once(' ').unwrap();
        // A module absent from the fixture comes from another OTP build; only recorded modules count.
        if let Some(recorded) = expected_lines.get(name)
            && *recorded != rest
        {
            differing.push(name.to_owned());
        }
    }
    assert!(
        differing.is_empty(),
        "{} modules transform differently: {:?}",
        differing.len(),
        &differing[..differing.len().min(20)]
    );
}

/// One test, so the process creates its atoms in one fixed order: erts sorts select values and map
/// keys by atom, so the output depends on the order of the atoms, and the digests with it.
#[test]
fn modules_transform_as_recorded() {
    otp_modules_transform_as_recorded();
    elixir_modules_transform_as_recorded();
}

fn otp_modules_transform_as_recorded() {
    let Some(dirs) = erl_output(
        "io:format(\"~s\", [string:join([P || P <- code:get_path(), P =/= \".\"], \"\\n\")]), halt().",
    ) else {
        eprintln!("erl unavailable; skipping");
        return;
    };
    let mut hashes = BTreeMap::new();
    for dir in dirs.lines() {
        module_hashes(Path::new(dir), &mut hashes);
    }
    assert!(hashes.len() > 200, "OTP modules found: {}", hashes.len());
    check("transform_golden_otp.txt", &hashes);
}

fn elixir_modules_transform_as_recorded() {
    let Some(dir) = erl_output("io:format(\"~s\", [filename:dirname(code:which(lists))]), halt().")
        .and_then(|_| {
            std::process::Command::new("elixir")
                .args(["-e", "IO.write(:code.lib_dir(:elixir))"])
                .output()
                .ok()
                .filter(|output| output.status.success())
                .and_then(|output| String::from_utf8(output.stdout).ok())
        })
    else {
        eprintln!("Elixir unavailable; skipping");
        return;
    };
    let mut hashes = BTreeMap::new();
    module_hashes(&Path::new(&dir).join("ebin"), &mut hashes);
    assert!(hashes.len() > 200, "Elixir modules found: {}", hashes.len());
    check("transform_golden_elixir.txt", &hashes);
}
