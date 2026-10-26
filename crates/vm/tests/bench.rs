use arinsal_term::Term;
use arinsal_vm::Vm;
use std::process::Command;

#[test]
fn process_is_send_and_op_is_compact() {
    fn assert_send<T: Send>() {}
    assert_send::<arinsal_vm::Process>();
    let size = std::mem::size_of::<arinsal_loader::Instr>();
    eprintln!("Instr size: {size} bytes");
    assert!(size <= 24);
}

#[test]
fn benchmark_kernels_match_otp_small_cases() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let dir = std::env::temp_dir().join(format!("arinsal-bench-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let compiled = Command::new("erlc")
        .arg("-o")
        .arg(&dir)
        .arg(root.join("tools/bench/kernels/bench.erl"))
        .output();
    let Ok(compiled) = compiled else {
        eprintln!("erlc unavailable; skipping differential benchmark test");
        return;
    };
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let beam = std::fs::read(dir.join("bench.beam")).unwrap();
    let parsed = arinsal_beam::parse(&beam).unwrap();
    let loaded = arinsal_loader::load(&parsed).unwrap();
    let specialized = loaded
        .code
        .iter()
        .filter(|instr| {
            !matches!(
                instr,
                arinsal_loader::Instr::Generic(_) | arinsal_loader::Instr::Unsupported(_)
            )
        })
        .count();
    eprintln!(
        "bench.beam specialized {specialized}/{} instructions",
        loaded.code.len()
    );
    let fib_start = loaded.export("fib", 1).unwrap();
    let fib_end = loaded
        .functions
        .iter()
        .find(|(index, _, _)| *index > fib_start)
        .unwrap()
        .0;
    let fib_code = &loaded.code[fib_start..fib_end];
    assert!(
        !fib_code
            .iter()
            .any(|instr| matches!(instr, arinsal_loader::Instr::Generic(_)))
    );
    assert!(
        fib_code
            .iter()
            .any(|instr| matches!(instr, arinsal_loader::Instr::MoveCallLocal { .. }))
    );
    assert!(
        fib_code
            .iter()
            .any(|instr| matches!(instr, arinsal_loader::Instr::DeallocateReturn { .. }))
    );
    assert!(
        fib_code
            .iter()
            .any(|instr| matches!(instr, arinsal_loader::Instr::IsLtXCReturn { .. }))
    );
    let mut vm = Vm::new([dir.clone()]);
    for (function, n) in [("fib", 20), ("trees", 12), ("nbody", 100), ("idle", 0)] {
        let expression = format!("io:format(\"~p\", [bench:{function}({n})]), halt().");
        let otp = Command::new("erl")
            .args(["-noshell", "-pa"])
            .arg(&dir)
            .args(["-eval", &expression])
            .output()
            .unwrap();
        assert!(
            otp.status.success(),
            "{}",
            String::from_utf8_lossy(&otp.stderr)
        );
        let expected = String::from_utf8(otp.stdout).unwrap();
        let result = vm
            .eval_exported("bench", function, &[Term::small(n).unwrap()])
            .unwrap();
        let actual = if let Some(n) = result.term.as_small() {
            n.to_string()
        } else {
            // SAFETY: EvalResult keeps the process heap alive while formatting.
            arinsal_float::format_shortest(unsafe { result.term.float_ref() }.unwrap().get())
        };
        assert_eq!(actual, expected, "{function}({n})");
    }
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn select_tables_match_otp() {
    let dir = std::env::temp_dir().join(format!("arinsal-select-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let source = dir.join("select_fast.erl");
    std::fs::write(&source, "-module(select_fast).\n-export([dense/1,sparse/1,arity/1]).\ndense(0)->a; dense(1)->b; dense(2)->c; dense(3)->d; dense(4)->e; dense(_)->other.\nsparse(-100)->a; sparse(0)->b; sparse(100)->c; sparse(1000)->d; sparse(10000)->e; sparse(_)->other.\narity({})->a; arity({1})->b; arity({1,2})->c; arity({1,2,3})->d; arity(_)->other.\n").unwrap();
    let compiled = match Command::new("erlc")
        .arg("-o")
        .arg(&dir)
        .arg(&source)
        .output()
    {
        Ok(output) => output,
        Err(_) => {
            eprintln!("erlc unavailable; skipping select differential test");
            return;
        }
    };
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let beam = std::fs::read(dir.join("select_fast.beam")).unwrap();
    let parsed = arinsal_beam::parse(&beam).unwrap();
    let loaded = arinsal_loader::load(&parsed).unwrap();
    let selects = loaded
        .code
        .iter()
        .filter(|instr| matches!(instr, arinsal_loader::Instr::Select { .. }))
        .count();
    assert!(
        selects >= 2,
        "compiler emitted only {selects} select instructions"
    );
    assert!(
        loaded
            .selects
            .iter()
            .any(|table| matches!(table, arinsal_loader::SelectTable::Dense { .. }))
    );
    assert!(
        loaded
            .selects
            .iter()
            .any(|table| matches!(table, arinsal_loader::SelectTable::Sorted(_)))
    );
    let mut vm = Vm::new([dir.clone()]);
    for (function, values) in [
        ("dense", vec![-1, 0, 1, 2, 3, 4, 5]),
        ("sparse", vec![-100, -1, 0, 100, 1000, 10000]),
    ] {
        for n in values {
            let expression = format!("io:format(\"~p\", [select_fast:{function}({n})]), halt().");
            let otp = Command::new("erl")
                .args(["-noshell", "-pa"])
                .arg(&dir)
                .args(["-eval", &expression])
                .output()
                .unwrap();
            assert!(otp.status.success());
            let actual = vm
                .eval_exported("select_fast", function, &[Term::small(n).unwrap()])
                .unwrap();
            assert_eq!(
                actual.term.to_string(),
                String::from_utf8(otp.stdout).unwrap(),
                "{function}({n})"
            );
        }
    }
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn continuations_survive_stack_collection() {
    let dir = std::env::temp_dir().join(format!("arinsal-stack-gc-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let source = dir.join("stack_gc.erl");
    std::fs::write(
        &source,
        "-module(stack_gc).\n-export([f/1]).\nf(0)->0; f(N)->T={N,N}, f(N-1)+element(1,T).\n",
    )
    .unwrap();
    let compiled = match Command::new("erlc")
        .arg("-o")
        .arg(&dir)
        .arg(&source)
        .output()
    {
        Ok(output) => output,
        Err(_) => {
            eprintln!("erlc unavailable; skipping stack GC differential test");
            return;
        }
    };
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let otp = Command::new("erl")
        .args(["-noshell", "-pa"])
        .arg(&dir)
        .args(["-eval", "io:format(\"~p\", [stack_gc:f(1000)]), halt()."])
        .output()
        .unwrap();
    assert!(otp.status.success());
    let mut vm = Vm::new([dir.clone()]);
    let result = vm
        .eval_exported("stack_gc", "f", &[Term::small(1000).unwrap()])
        .unwrap();
    assert_eq!(
        result.term.to_string(),
        String::from_utf8(otp.stdout).unwrap()
    );
    assert!(
        result.stats.gc.collections > 0,
        "recursion did not exercise stack collection"
    );
    let _ = std::fs::remove_dir_all(dir);
}
