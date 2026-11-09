use arinsal_term::Term;
use arinsal_vm::Vm;
use std::process::Command;
use std::time::Instant;

#[test]
fn beam_asm_kernels_match_erts() {
    if std::env::var_os("ARINSAL_BEAMASM").as_deref() != Some(std::ffi::OsStr::new("1")) {
        eprintln!("set ARINSAL_BEAMASM=1 to run the BeamAsm integration kernels");
        return;
    }
    let dir = std::env::temp_dir().join(format!("arinsal-beamasm-kernels-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let source =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/kernels.erl");
    let compiled = Command::new("erlc")
        .arg("-o")
        .arg(&dir)
        .arg(source)
        .output()
        .expect("erlc must be available");
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let beam = std::fs::read(dir.join("kernels.beam")).unwrap();
    let mut vm = Vm::new([dir.clone()]);
    assert_eq!(arinsal_beam::parse(&beam).unwrap().module, "kernels");

    let cases = [
        ("tail", 20_000),
        ("list", 600),
        ("fib", 5),
        ("tuple", 600),
        ("binary", 600),
    ];
    for (function, n) in cases {
        let started = Instant::now();
        let interpreted = vm
            .eval_exported("kernels", function, &[Term::small(n).unwrap()])
            .unwrap();
        let interpreter_ns = started.elapsed().as_nanos();
        let interpreted_term = arinsal_term::to_owned(interpreted.term).unwrap();
        let started = Instant::now();
        let actual = vm
            .eval_scheduled("kernels", function, &[Term::small(n).unwrap()], 1, None)
            .unwrap();
        let native_ns = started.elapsed().as_nanos();
        assert_eq!(
            actual.term, interpreted_term,
            "{function}/{n} interpreter differential"
        );
        let expr = format!("io:format(\"~w\", [kernels:{function}({n})]), halt().");
        let started = Instant::now();
        let expected = Command::new("erl")
            .arg("-pa")
            .arg(&dir)
            .args(["-noshell", "-eval", &expr])
            .output()
            .expect("erl must be available");
        let erts_ns = started.elapsed().as_nanos();
        assert!(
            expected.status.success(),
            "{}",
            String::from_utf8_lossy(&expected.stderr)
        );
        let expected = String::from_utf8(expected.stdout).unwrap();
        assert_eq!(actual.text, expected, "{function}/{n}");
        eprintln!(
            "kernel {function}/{n}: Arinsal (interpreter) {interpreter_ns} ns/op; Arinsal (BeamAsm) {native_ns} ns/op; erts {erts_ns} ns/op"
        );
    }
    let _ = std::fs::remove_dir_all(dir);
}
