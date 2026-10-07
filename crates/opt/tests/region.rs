use arinsal_difftest::{CallResult, CompareMode, RefErl, Vm as DifferentialVm, compare_with_stack};
use arinsal_etf::OwnedTerm;
use arinsal_jit::JitState;
use arinsal_loader::load;
use arinsal_opt::{Engine, ir::Region};
use arinsal_term::Term;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT_FIXTURE: AtomicUsize = AtomicUsize::new(0);

fn fixture() -> Option<(arinsal_loader::Module, Vec<u8>)> {
    let dir = std::env::temp_dir().join(format!(
        "arinsal-opt-test-{}-{}",
        std::process::id(),
        NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/integers.erl");
    let result = Command::new("erlc")
        .args(["-o", dir.to_str().unwrap(), source.to_str().unwrap()])
        .output();
    let Ok(result) = result else {
        eprintln!("skipping: erlc is unavailable");
        return None;
    };
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let bytes = std::fs::read(dir.join("integers.beam")).unwrap();
    let beam = arinsal_beam::parse(&bytes).unwrap();
    Some((load(&beam).unwrap(), bytes))
}

#[test]
fn fib_has_state_maps_at_guards_and_arithmetic() {
    let Some((module, _)) = fixture() else { return };
    let entry = module.export("fib", 1).unwrap();
    if std::env::var_os("ARINSAL_TEST_DUMP").is_some() {
        for (pc, instr) in module
            .code
            .iter()
            .enumerate()
            .filter(|(pc, _)| *pc < 60 || (130..185).contains(pc))
        {
            eprintln!("{pc}: {instr:?}");
        }
    }
    let region = Region::lower(&module, entry).unwrap();
    let fib = &region.functions[&entry];
    assert!(fib.blocks.iter().all(|block| block.deopt.pc == block.pc));
    assert!(fib.blocks.iter().any(|block| !block.deopt.live.is_empty()));
}

#[test]
fn variant_regions_lower() {
    let Some((module, _)) = fixture() else { return };
    for (name, arity) in [
        ("fib_guard", 1),
        ("fib_three", 1),
        ("fib_swapped", 1),
        ("helper_fib", 1),
        ("tail_sum", 2),
        ("ackermann", 2),
        ("tak", 3),
    ] {
        let entry = module.export(name, arity).unwrap();
        let region = Region::lower(&module, entry).unwrap_or_else(|error| {
            if let arinsal_opt::ir::LowerError::Unsupported { pc, .. } = error {
                panic!("{name}: {error:?}; {:?}", module.code[pc]);
            }
            panic!("{name}: {error:?}");
        });
        assert!(region.functions.contains_key(&entry));
    }
}

extern "C" fn empty_frame_materialization(
    _: *mut JitState,
    _: u64,
    cp: u64,
    _: *const u64,
    slots: u32,
) -> u32 {
    u32::from(cp != 0 || slots != 0)
}

fn execute(
    engine: &mut Engine,
    module: &arinsal_loader::Module,
    name: &str,
    args: &[i64],
) -> (u32, [u64; 32], u32) {
    let entry = module.export(name, args.len() as u8).unwrap();
    let native = engine.compile(0, module, entry).unwrap();
    let mut x = [0_u64; 32];
    for (index, &value) in args.iter().enumerate() {
        // SAFETY: Small integers do not contain heap pointers.
        x[index] = unsafe { Term::small(value).unwrap().raw_bits() };
    }
    let mut fr = [0.0; 4];
    let mut stack = [0_u64; 8];
    // SAFETY: The pointer remains within this fixed stack buffer.
    let end = unsafe { stack.as_mut_ptr().add(stack.len()) };
    let mut state = JitState {
        x: x.as_mut_ptr(),
        fr: fr.as_mut_ptr(),
        stop: end,
        htop: stack.as_mut_ptr(),
        stack_end: end,
        process: std::ptr::null_mut(),
        module: 0,
        reds: 4000,
        ip: entry as u32,
        depth: 0,
        x_live: 0,
    };
    // SAFETY: The finalized entry uses JitState C ABI; all arrays outlive the call.
    let status = unsafe { native(&mut state) };
    (status, x, state.ip)
}

#[test]
fn compiled_variants_match_otp() {
    let Some((module, bytes)) = fixture() else {
        return;
    };
    let reference = RefErl::start().unwrap();
    reference.load("integers", &bytes).unwrap();
    let mut engine = Engine::new(empty_frame_materialization).unwrap();
    for (name, args) in [
        ("fib", vec![10]),
        ("fib_guard", vec![10]),
        ("fib_three", vec![10]),
        ("fib_swapped", vec![10]),
        ("helper_fib", vec![10]),
        ("tail_sum", vec![100, 0]),
        ("ackermann", vec![2, 4]),
        ("tak", vec![10, 6, 3]),
    ] {
        let (status, x, ip) = execute(&mut engine, &module, name, &args);
        assert_eq!(status, 0, "{name} exited to the interpreter at {}", ip);
        let expected = reference.call(
            "integers",
            name,
            &args.iter().map(|&n| OwnedTerm::Int(n)).collect::<Vec<_>>(),
        );
        assert_eq!(
            expected,
            CallResult::Ok(OwnedTerm::Int((x[0] as i64) >> 4)),
            "{name}"
        );
    }
}

#[test]
fn integer_ops_match_otp_and_overflow_deopts() {
    let Some((module, bytes)) = fixture() else {
        return;
    };
    let reference = RefErl::start().unwrap();
    reference.load("integers", &bytes).unwrap();
    let mut engine = Engine::new(empty_frame_materialization).unwrap();
    for (name, args) in [
        ("sum_overflow", [11, 7]),
        ("difference", [11, 7]),
        ("product", [11, 7]),
        ("quotient", [-11, 3]),
        ("remainder", [-11, 3]),
        ("bit_and", [11, 7]),
        ("bit_or", [11, 7]),
        ("left_shift", [11, 2]),
        ("right_shift", [-20, 2]),
    ] {
        let (status, x, ip) = execute(&mut engine, &module, name, &args);
        assert_eq!(status, 0, "{name} deoptimized at {ip}");
        let expected = reference.call("integers", name, &args.map(OwnedTerm::Int));
        assert_eq!(
            expected,
            CallResult::Ok(OwnedTerm::Int((x[0] as i64) >> 4)),
            "{name}"
        );
    }
    for (name, args) in [
        ("sum_overflow", [arinsal_term::MAX_SMALL, 1]),
        ("difference", [arinsal_term::MIN_SMALL, 1]),
        ("product", [arinsal_term::MAX_SMALL, 2]),
        ("quotient", [arinsal_term::MIN_SMALL, -1]),
        ("left_shift", [arinsal_term::MAX_SMALL, 1]),
    ] {
        let (status, x, ip) = execute(&mut engine, &module, name, &args);
        assert_eq!(
            status, 1,
            "{name} should exit before the big integer at {ip}"
        );
        for (index, &value) in args.iter().enumerate() {
            // SAFETY: Test values are immediate small integers.
            let expected = unsafe { Term::small(value).unwrap().raw_bits() };
            assert_eq!(x[index], expected, "{name} lost X{index}");
        }
        let expected = reference.call("integers", name, &args.map(OwnedTerm::Int));
        assert!(
            match expected {
                CallResult::Ok(OwnedTerm::Int(n)) =>
                    !(arinsal_term::MIN_SMALL..=arinsal_term::MAX_SMALL).contains(&n),
                CallResult::Ok(OwnedTerm::BigInt(_)) => true,
                _ => false,
            },
            "{name}"
        );
    }
    let (status, _, _) = execute(&mut engine, &module, "quotient", &[11, 0]);
    assert_eq!(status, 1);
    assert!(
        matches!(reference.call("integers","quotient",&[OwnedTerm::Int(11),OwnedTerm::Int(0)]),CallResult::Exception {class,..} if class=="error")
    );
}

#[test]
fn vm_side_exits_match_otp_results_and_stack_tops() {
    let Some((_, bytes)) = fixture() else { return };
    let reference = RefErl::start().unwrap();
    reference.load("integers", &bytes).unwrap();
    let mut vm = arinsal_vm::Vm::new([]);
    vm.load_bytes(&bytes).unwrap();
    for (name, args) in [
        ("fib_three", vec![OwnedTerm::Int(4)]),
        ("fail_after", vec![OwnedTerm::Int(0), OwnedTerm::Int(0)]),
        (
            "overflow_recursive",
            vec![OwnedTerm::Int(0), OwnedTerm::Int(arinsal_term::MAX_SMALL)],
        ),
    ] {
        for _ in 0..1001 {
            let _ = DifferentialVm::call(&mut vm, "integers", name, &args);
        }
    }
    for name in [
        "sum_overflow",
        "difference",
        "product",
        "quotient",
        "left_shift",
    ] {
        for _ in 0..1001 {
            let _ = DifferentialVm::call(
                &mut vm,
                "integers",
                name,
                &[OwnedTerm::Int(2), OwnedTerm::Int(1)],
            );
        }
    }
    for (name, args, check_stack) in [
        ("fib_three", vec![OwnedTerm::Int(-1)], true),
        (
            "fail_after",
            vec![OwnedTerm::Int(5), OwnedTerm::Int(0)],
            true,
        ),
        (
            "overflow_recursive",
            vec![OwnedTerm::Int(5), OwnedTerm::Int(arinsal_term::MAX_SMALL)],
            false,
        ),
        (
            "ackermann",
            vec![OwnedTerm::Int(3), OwnedTerm::Int(6)],
            false,
        ),
        (
            "ackermann",
            vec![OwnedTerm::Int(3), OwnedTerm::Int(7)],
            false,
        ),
        (
            "tak",
            vec![OwnedTerm::Int(18), OwnedTerm::Int(12), OwnedTerm::Int(6)],
            false,
        ),
        (
            "tail_sum",
            vec![OwnedTerm::Int(10_000), OwnedTerm::Int(0)],
            false,
        ),
        (
            "sum_overflow",
            vec![OwnedTerm::Int(arinsal_term::MAX_SMALL), OwnedTerm::Int(1)],
            false,
        ),
        (
            "difference",
            vec![OwnedTerm::Int(arinsal_term::MIN_SMALL), OwnedTerm::Int(1)],
            false,
        ),
        (
            "product",
            vec![OwnedTerm::Int(arinsal_term::MAX_SMALL), OwnedTerm::Int(2)],
            false,
        ),
        (
            "quotient",
            vec![OwnedTerm::Int(arinsal_term::MIN_SMALL), OwnedTerm::Int(-1)],
            false,
        ),
        (
            "left_shift",
            vec![OwnedTerm::Int(arinsal_term::MAX_SMALL), OwnedTerm::Int(1)],
            false,
        ),
        (
            "quotient",
            vec![OwnedTerm::Int(11), OwnedTerm::Int(0)],
            true,
        ),
    ] {
        let expected = reference.call("integers", name, &args);
        let mut actual = DifferentialVm::call(&mut vm, "integers", name, &args);
        if let CallResult::Exception {
            stack_top: Some(OwnedTerm::List { elems, .. }),
            ..
        } = &actual
        {
            let top = elems.first().cloned();
            if let CallResult::Exception { stack_top, .. } = &mut actual {
                *stack_top = top;
            }
        }
        compare_with_stack(&actual, &expected, CompareMode::Exact, check_stack).unwrap_or_else(
            |error| panic!("{name}({args:?}): {error}; actual={actual:?}; expected={expected:?}"),
        );
    }
}
