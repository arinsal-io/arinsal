use arinsal_a64::enc::Gpr;
use arinsal_beam::BeamFile;
use arinsal_beamasm::{
    ExitReason, ProcessHeader, SchedulerRegisters, module::BeamModuleAssembler, rt::read_heap_word,
};
use arinsal_beamjit::{ModuleEnv, compile_module_with_env};
use std::{
    fs,
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
    time::Instant,
};

static MAP_LOOKUP_RESULT: AtomicU64 = AtomicU64::new(0);
static MAP_LOOKUP_KEY: AtomicU64 = AtomicU64::new(0);

extern "C" fn build_stacktrace_for_compile(_header: *mut ProcessHeader, _trace: u64) -> u64 {
    0
}

struct TestEnv;

impl ModuleEnv for TestEnv {
    fn raise_class_helper(&self) -> usize {
        1
    }

    fn this_node_sysname(&self) -> usize {
        1
    }

    fn sys_perf_counter(&self) -> usize {
        1
    }

    fn build_stacktrace_helper(&self) -> Option<arinsal_beamasm::catch::BuildStacktraceHook> {
        Some(build_stacktrace_for_compile)
    }

    fn atom(&self, _beam: &BeamFile, index: u32) -> Result<u64, String> {
        Ok((u64::from(index) << 6) | 0x0b)
    }

    fn add_literal(&self, _index: u32, _word: u64) -> Result<(), String> {
        Ok(())
    }

    fn literal(&self, beam: &BeamFile, index: u32) -> Result<u64, String> {
        if index as usize >= beam.literals.len() {
            return Ok(0);
        }
        beam.literal(index)
            .map(|_| 0)
            .map_err(|error| error.to_string())
    }

    fn import(&self, beam: &BeamFile, index: u32) -> Result<u32, String> {
        beam.imports
            .get(index as usize)
            .map(|_| index)
            .ok_or_else(|| format!("import index {index} is out of range"))
    }

    fn lambda_fun_entry(&self, beam: &BeamFile, index: u32) -> Result<(usize, u8), String> {
        // The module is compiled for its own functions only; its funs are never created.
        beam.lambdas
            .iter()
            .find(|lambda| lambda.index == index)
            .map(|lambda| {
                (
                    0x2000 + 64 * index as usize,
                    (lambda.arity - lambda.num_free) as u8,
                )
            })
            .ok_or_else(|| format!("lambda {index} is missing"))
    }

    fn zero_capture_fun(&self, _beam: &BeamFile, lambda: u32) -> Result<u64, String> {
        Ok(0x1000 + 16 * u64::from(lambda))
    }

    fn export_entry(&self, _beam: &BeamFile, index: u32) -> Result<usize, String> {
        // The module is compiled for its own functions only; its external calls are never run.
        Ok(0x1000 + 8 * index as usize)
    }

    fn arithmetic_helper(&self) -> arinsal_beamasm::arith::ArithHelper {
        arithmetic_helper
    }

    fn guard_helper(&self) -> arinsal_beamasm::guard::GuardHelper {
        guard_helper
    }

    fn guard_helper3(&self) -> arinsal_beamasm::guard::GuardHelper3 {
        guard_helper3
    }

    fn gc_hook(&self) -> arinsal_beamasm::construct::GcHook {
        gc_hook
    }

    fn map_lookup_helper(&self) -> arinsal_beamjit::MapLookupHelper {
        map_lookup_helper
    }

    fn bif_mfa_helper(&self) -> arinsal_beamjit::BifMfaHelper {
        bif_mfa_helper
    }

    fn bs_match_helper(&self) -> arinsal_beamasm::bs_match::BsMatchHelper {
        bs_match_helper
    }

    fn map_runtime(&self) -> arinsal_beamasm::map::MapRuntime {
        arinsal_beamasm::map::MapRuntime {
            get: map_get_helper,
            get_elements: map_get_elements_helper,
            lookup_module: 0,
            new_map: map_update_helper,
            update_assoc: map_update_helper,
            update_exact: map_update_helper,
            put_single: map_update_helper,
            update_single_assoc_shared: map_fragments(map_get_helper, map_update_helper)
                .update_single_assoc_shared(),
            update_assoc_shared: map_fragments(map_get_helper, map_update_helper)
                .update_assoc_shared(),
            update_exact_shared: map_fragments(map_get_helper, map_update_helper)
                .update_exact_shared(),
            update_single_exact_shared: map_fragments(map_get_helper, map_update_helper)
                .update_single_exact_shared(),
            get_element_shared: map_fragments(map_get_helper, map_update_helper)
                .get_element_shared(),
            get_element_hash_shared: map_fragments(map_get_helper, map_update_helper)
                .get_element_hash_shared(),
        }
    }

    fn bs_create_bin_helper(&self) -> arinsal_beamasm::bs_construct::BsCreateBinHelper {
        bs_create_bin_helper
    }

    fn exception_resolver(&self) -> arinsal_beamasm::catch::ExceptionResolver {
        exception_resolver
    }

    fn fun_resolver(&self) -> arinsal_beamasm::fun::FunResolver {
        fun_resolver
    }
}

extern "C" fn bs_match_helper(
    _process: *mut ProcessHeader,
    _op: u32,
    _context: u64,
    _value: u64,
    _unit: u64,
) -> u64 {
    0
}

extern "C" fn map_get_helper(
    _process: *mut ProcessHeader,
    _map: u64,
    _key: u64,
    _hash: u64,
) -> u64 {
    0
}

extern "C" fn map_get_elements_helper(
    _process: *mut ProcessHeader,
    _map: u64,
    _module: u64,
    _table: u64,
    _stack: u64,
) -> u64 {
    0
}

extern "C" fn map_update_helper(
    _process: *mut ProcessHeader,
    _map: u64,
    _registers: u64,
    _live: u64,
    _count: u64,
) -> u64 {
    0
}

extern "C" fn bs_create_bin_helper(_process: *mut ProcessHeader, _a: u64, _b: u64, _c: u64) -> u64 {
    0
}

extern "C" fn exception_resolver(
    _process: *mut ProcessHeader,
    _registers: *mut SchedulerRegisters,
    _stack: *mut u64,
) -> usize {
    0
}

extern "C" fn fun_resolver(_process: *mut ProcessHeader, _fun: u64, _arity: u32) -> usize {
    0
}

extern "C" fn map_lookup_helper(
    _process: *mut ProcessHeader,
    _registers: *mut SchedulerRegisters,
    _map: u64,
    key: u64,
    _hash: u64,
    _hashed: u64,
) -> u64 {
    MAP_LOOKUP_KEY.store(key, Ordering::SeqCst);
    MAP_LOOKUP_RESULT.load(Ordering::SeqCst)
}

extern "C" fn bif_mfa_helper(
    _process: *mut ProcessHeader,
    _registers: *mut SchedulerRegisters,
    _module: u64,
    _function: u64,
    _arity: u64,
) -> u64 {
    0
}

extern "C" fn arithmetic_helper(
    _process: *mut ProcessHeader,
    _op: u32,
    _lhs: u64,
    _rhs: u64,
    _extra: u64,
) -> u64 {
    0
}

extern "C" fn guard_helper(
    _process: *mut ProcessHeader,
    _op: u32,
    _first: u64,
    _second: u64,
) -> u64 {
    0
}

extern "C" fn guard_helper3(
    _process: *mut ProcessHeader,
    _op: u32,
    _first: u64,
    _second: u64,
    _third: u64,
) -> u64 {
    0
}

extern "C" fn gc_hook(
    _header: *mut ProcessHeader,
    _registers: *mut SchedulerRegisters,
    _words: usize,
    _live: usize,
    _fcalls: i32,
) -> i32 {
    0
}

#[test]
fn erlc_add_function_runs_through_native_bridge() {
    if !cfg!(target_arch = "aarch64") {
        eprintln!("native bridge test requires AArch64");
        return;
    }
    let root = std::env::temp_dir().join(format!("beamjit-native-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    let source = root.join("native_add.erl");
    fs::write(
        &source,
        "-module(native_add).\n-export([add/2]).\nadd(A, B) -> A + B.\n",
    )
    .unwrap();
    let output = Command::new("erlc")
        .args(["-o", root.to_str().unwrap(), source.to_str().unwrap()])
        .output()
        .expect("erlc must be installed for the BEAM integration test");
    assert!(
        output.status.success(),
        "erlc failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let bytes = fs::read(root.join("native_add.beam")).unwrap();
    let module = compile_module_with_env(&bytes, &TestEnv).unwrap();
    let function = module
        .functions
        .iter()
        .find(|function| function.name == "add")
        .unwrap_or_else(|| panic!("add/2 did not compile natively",));

    let mut stack = [0_u64; 64];
    let mut heap = [0_u64; 64];
    let mut header = ProcessHeader {
        htop: heap.as_mut_ptr(),
        stop: stack.as_mut_ptr().wrapping_add(stack.len()),
        heap: heap.as_mut_ptr(),
        hend: heap.as_mut_ptr().wrapping_add(heap.len()),
        fcalls: 100,
        ..ProcessHeader::default()
    };
    let mut registers = SchedulerRegisters::default();
    registers.x_reg_array[0] = arinsal_beamasm::rt::fixture_term(tagged_small(19));
    registers.x_reg_array[1] = arinsal_beamasm::rt::fixture_term(tagged_small(23));
    let target =
        module.native.entries[&function.label] as usize + arinsal_beamasm::module::FUNC_INFO_BYTES;
    let caller = caller_module(target, 0xffff_fffe);
    let caller_entry = caller.entry(0xffff_fffe).unwrap();
    let result = arinsal_beamasm::enter_native(&mut header, &mut registers, &caller_entry);
    assert_eq!(result, ExitReason::Returned);
    assert_eq!(
        registers.x_reg_array[0],
        arinsal_beamasm::rt::fixture_term(tagged_small(42))
    );
    let _ = fs::remove_dir_all(root);
}

#[test]
fn erlc_list_tuple_guards_run_natively() {
    if !cfg!(target_arch = "aarch64") {
        eprintln!("native bridge test requires AArch64");
        return;
    }
    let root = std::env::temp_dir().join(format!("beamjit-collections-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    let source = root.join("native_collections.erl");
    fs::write(
        &source,
        "-module(native_collections).\n-export([first_integer/2, tuple_list/2]).\nfirst_integer(_Ignored, [Value|_]) when is_integer(Value) -> Value.\ntuple_list(_Ignored, {Value, _}) when is_integer(Value) -> [Value].\n",
    )
    .unwrap();
    let output = Command::new("erlc")
        .args(["-o", root.to_str().unwrap(), source.to_str().unwrap()])
        .output()
        .expect("erlc must be installed for the BEAM integration test");
    assert!(
        output.status.success(),
        "erlc failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let bytes = fs::read(root.join("native_collections.beam")).unwrap();
    let module = compile_module_with_env(&bytes, &TestEnv).unwrap();
    let tuple_list = module
        .functions
        .iter()
        .find(|function| function.name == "tuple_list")
        .unwrap_or_else(|| panic!("tuple_list/2 not native"));
    let first_integer = module
        .functions
        .iter()
        .find(|function| function.name == "first_integer")
        .unwrap_or_else(|| panic!("first_integer/2 not native"));

    let mut stack = [0_u64; 64];
    let mut heap = [0_u64; 64];
    heap[0] = tagged_small(77);
    heap[1] = 0x3b;
    let mut header = ProcessHeader {
        htop: heap.as_mut_ptr().wrapping_add(2),
        stop: stack.as_mut_ptr().wrapping_add(stack.len()),
        heap: heap.as_mut_ptr(),
        hend: heap.as_mut_ptr().wrapping_add(heap.len()),
        fcalls: 100,
        ..ProcessHeader::default()
    };
    let mut registers = SchedulerRegisters::default();
    registers.x_reg_array[0] = arinsal_beamasm::rt::fixture_term(tagged_small(0));
    registers.x_reg_array[1] = arinsal_beamasm::rt::fixture_term(heap.as_mut_ptr() as u64 + 1);
    let list_target = module.native.entries[&first_integer.label] as usize
        + arinsal_beamasm::module::FUNC_INFO_BYTES;
    let list_caller = caller_module(list_target, 0xffff_fffe);
    let list_entry = list_caller.entry(0xffff_fffe).unwrap();
    let result = arinsal_beamasm::enter_native(&mut header, &mut registers, &list_entry);
    assert_eq!(result, ExitReason::Returned);
    assert_eq!(
        registers.x_reg_array[0],
        arinsal_beamasm::rt::fixture_term(tagged_small(77))
    );

    heap[0] = 2 << 6;
    heap[1] = tagged_small(99);
    heap[2] = tagged_small(1);
    header.htop = heap.as_mut_ptr().wrapping_add(3);
    registers.x_reg_array[0] = arinsal_beamasm::rt::fixture_term(tagged_small(0));
    registers.x_reg_array[1] = arinsal_beamasm::rt::fixture_term(heap.as_mut_ptr() as u64 + 2);
    let tuple_target = module.native.entries[&tuple_list.label] as usize
        + arinsal_beamasm::module::FUNC_INFO_BYTES;
    let tuple_caller = caller_module(tuple_target, 0xffff_fffe);
    let tuple_entry = tuple_caller.entry(0xffff_fffe).unwrap();
    let result = arinsal_beamasm::enter_native(&mut header, &mut registers, &tuple_entry);
    assert_eq!(result, ExitReason::Returned);
    assert_eq!(
        registers.x_reg_array[0],
        arinsal_beamasm::rt::fixture_term(heap.as_mut_ptr() as u64 + 25)
    );
    assert_eq!(heap[3], tagged_small(99));
    assert_eq!(heap[4], 0x3b);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn recursive_sum_and_fib_run_natively() {
    if !cfg!(target_arch = "aarch64") {
        eprintln!("native recursive benchmark requires AArch64");
        return;
    }
    let root = std::env::temp_dir().join(format!("beamjit-recursive-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    let source = root.join("native_recursive.erl");
    fs::write(
        &source,
        "-module(native_recursive).\n-export([sum/2, fib/1]).\nsum(0, Acc) -> Acc;\nsum(N, Acc) -> sum(N - 1, Acc + N).\nfib(N) -> fib_loop(N, 0, 1).\nfib_loop(0, A, _B) -> A;\nfib_loop(N, A, B) -> fib_loop(N - 1, B, A + B).\n",
    )
    .unwrap();
    let output = Command::new("erlc")
        .args(["-o", root.to_str().unwrap(), source.to_str().unwrap()])
        .output()
        .expect("erlc must be installed for the BEAM integration test");
    assert!(
        output.status.success(),
        "erlc failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let beam = fs::read(root.join("native_recursive.beam")).unwrap();
    let module = compile_module_with_env(&beam, &TestEnv).unwrap();
    let sum = module
        .functions
        .iter()
        .find(|function| function.name == "sum")
        .unwrap_or_else(|| panic!("sum/2 did not compile natively"));
    let fib = module
        .functions
        .iter()
        .find(|function| function.name == "fib")
        .unwrap_or_else(|| panic!("fib/1 did not compile natively"));

    let expected = Command::new("erl")
        .args([
            "-noshell",
            "-noinput",
            "-pa",
            root.to_str().unwrap(),
            "-eval",
            "io:format(\"~p ~p~n\", [native_recursive:sum(10000000, 0), native_recursive:fib(25)]), halt().",
        ])
        .output()
        .expect("erl must be installed for the differential test");
    assert!(
        expected.status.success(),
        "erl failed: {}",
        String::from_utf8_lossy(&expected.stderr)
    );
    let values: Vec<i64> = String::from_utf8(expected.stdout)
        .unwrap()
        .split_whitespace()
        .map(|value| value.parse().unwrap())
        .collect();
    assert_eq!(values.len(), 2, "unexpected erts output: {values:?}");

    let mut stack = [0_u64; 64];
    let mut heap = [0_u64; 64];
    let stack_end = stack.as_mut_ptr().wrapping_add(stack.len());
    let mut header = ProcessHeader {
        htop: heap.as_mut_ptr(),
        stop: stack_end,
        heap: heap.as_mut_ptr(),
        hend: heap.as_mut_ptr().wrapping_add(heap.len()),
        fcalls: 100_000,
        ..ProcessHeader::default()
    };
    let mut registers = SchedulerRegisters::default();
    registers.x_reg_array[0] = arinsal_beamasm::rt::fixture_term(tagged_small(10_000_000));
    registers.x_reg_array[1] = arinsal_beamasm::rt::fixture_term(tagged_small(0));
    let target =
        module.native.entries[&sum.label] as usize + arinsal_beamasm::module::FUNC_INFO_BYTES;
    let caller = caller_module(target, 0xffff_fffe);
    let entry = caller.entry(0xffff_fffe).unwrap();
    let started = Instant::now();
    let mut yields = 0_u32;
    loop {
        match arinsal_beamasm::enter_native(&mut header, &mut registers, &entry) {
            ExitReason::Returned => break,
            ExitReason::Yield => {
                yields += 1;
                assert!(yields < 10_000, "sum/2 yielded too many times");
                header.fcalls = 100_000;
                header.stop = stack_end;
            }
            other => panic!("unexpected native sum exit: {other:?}"),
        }
    }
    let sum_elapsed = started.elapsed().as_nanos();
    assert_eq!(
        registers.x_reg_array[0],
        arinsal_beamasm::rt::fixture_term(tagged_small(values[0] as u64))
    );
    println!("sum_10m_native_ok {}", sum_elapsed);

    registers.x_reg_array[0] = arinsal_beamasm::rt::fixture_term(tagged_small(25));
    registers.x_reg_array[1] = arinsal_beamasm::rt::fixture_term(0);
    let target =
        module.native.entries[&fib.label] as usize + arinsal_beamasm::module::FUNC_INFO_BYTES;
    let caller = caller_module(target, 0xffff_fffd);
    let entry = caller.entry(0xffff_fffd).unwrap();
    let started = Instant::now();
    let mut yields = 0_u32;
    loop {
        match arinsal_beamasm::enter_native(&mut header, &mut registers, &entry) {
            ExitReason::Returned => break,
            ExitReason::Yield => {
                yields += 1;
                assert!(yields < 10_000, "fib/1 yielded too many times");
                header.fcalls = 100_000;
                header.stop = stack_end;
            }
            other => panic!("unexpected native fib exit: {other:?}"),
        }
    }
    let fib_elapsed = started.elapsed().as_micros();
    assert_eq!(
        registers.x_reg_array[0],
        arinsal_beamasm::rt::fixture_term(tagged_small(values[1] as u64))
    );
    println!("fib25_native_ok {fib_elapsed}us yields={yields}");
    let _ = fs::remove_dir_all(root);
}

#[test]
fn otp_logger_reply_return_returns_the_reply_map() {
    if !cfg!(target_arch = "aarch64") {
        return;
    }
    // The function of logger_olp, compiled alone: a whole OTP module needs every runtime helper.
    let bytes = erlc_fixture("jit_reply_return.erl");
    // The atoms of the transformed code are global atom indexes.
    let atom = |name: &str| {
        let index = arinsal_beamops::global_atom_index(name).unwrap();
        (u64::from(index) << 6) | 0x0b
    };
    let module = compile_module_with_env(&bytes, &TestEnv).unwrap();
    let function = module
        .functions
        .iter()
        .find(|function| function.name == "reply_return" && function.arity == 2)
        .unwrap_or_else(|| panic!("reply_return/2 was not compiled"));

    let mut heap = [0_u64; 128];
    let heap_start = heap.as_mut_ptr();
    heap[0] = 1 << 6;
    heap[1] = atom("idle");
    heap[2] = 0x12c;
    heap[3] = 1;
    heap[4] = heap_start as u64 | 2;
    heap[5] = atom("true");
    let state = heap_start.wrapping_add(2) as u64 | 2;
    let htop = heap_start.wrapping_add(6);
    let stop = heap_start.wrapping_add(heap.len());
    let heap_end = stop;
    let mut header = ProcessHeader {
        htop,
        stop,
        heap: heap_start,
        hend: heap_end,
        fcalls: 100,
        ..ProcessHeader::default()
    };
    let reply = tagged_small(77);
    MAP_LOOKUP_RESULT.store(atom("true"), Ordering::SeqCst);
    MAP_LOOKUP_KEY.store(0, Ordering::SeqCst);
    let mut registers = SchedulerRegisters::default();
    registers.x_reg_array[0] = arinsal_beamasm::rt::fixture_term(reply);
    registers.x_reg_array[1] = arinsal_beamasm::rt::fixture_term(state);
    let exit = arinsal_beamjit::enter_native(&module, function, &mut header, &mut registers);
    assert_eq!(
        exit,
        ExitReason::Returned,
        "fcalls={} i={:?}",
        header.fcalls,
        header.i
    );
    let result = registers.x_reg_array[0];
    // Port of erts/emulator/beam/jit/arm/instr_map.cpp:362-390, OTP-29.1.1: a flatmap
    // lookup of an immediate key stays inline and never reaches the runtime hook.
    assert_eq!(MAP_LOOKUP_KEY.load(Ordering::SeqCst), 0);
    assert_eq!(read_heap_word(result.tagged_word(), 0), 3 << 6);
    assert_eq!(read_heap_word(result.tagged_word(), 1), atom("reply"));
    assert_eq!(read_heap_word(result.tagged_word(), 2), reply);
    assert_eq!(read_heap_word(result.tagged_word(), 3), state);
    MAP_LOOKUP_RESULT.store(0, Ordering::SeqCst);
}

fn caller_module(target: usize, label: u32) -> arinsal_beamasm::module::FinalizedModule {
    let mut assembler = BeamModuleAssembler::new();
    assembler.emit_i_func_label(label).unwrap();
    assembler
        .emit_raw(|encoder| {
            encoder.mov_const(Gpr::x(17), target as u64)?;
            encoder.br(Gpr::x(17))
        })
        .unwrap();
    assembler.finalize().unwrap()
}

const fn tagged_small(value: u64) -> u64 {
    (value << 4) | 0xf
}

fn erlc_fixture(file: &str) -> Vec<u8> {
    let root = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("beamjit-xmem");
    fs::create_dir_all(&root).unwrap();
    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(file);
    let output = Command::new("erlc")
        .arg("-o")
        .arg(&root)
        .arg(&source)
        .output()
        .expect("erlc must be installed for the BEAM integration test");
    assert!(
        output.status.success(),
        "erlc {file} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stem = file.rsplit_once('.').unwrap().0;
    fs::read(root.join(format!("{stem}.beam"))).unwrap()
}

fn extended_x_ops(bytes: &[u8]) -> std::collections::BTreeSet<String> {
    fn extended(operand: &arinsal_beamops::SpecificOperand) -> bool {
        match operand {
            arinsal_beamops::SpecificOperand::X(index) => *index >= 6,
            _ => false,
        }
    }
    let beam = arinsal_beam::parse(bytes).unwrap();
    arinsal_beamops::transform_module(&beam)
        .unwrap()
        .iter()
        .flatten()
        .filter(|op| op.operands().iter().any(extended))
        .map(|op| op.name().to_owned())
        .collect()
}

/// The X6+ fixtures (compiled natively by `vm/tests/asm_corpus.rs` and run against `erl` by
/// `vm/tests/jit_xmem.rs`) keep operands above the register cache in every op family listed.
#[test]
fn extended_x_fixtures_cover_op_families() {
    for (file, required) in [
        (
            "jit_xmem.erl",
            &[
                "i_plus",
                "i_bxor",
                "put_tuple2",
                "put_list",
                "get_list",
                "i_get_tuple_element",
                "i_select_val_lins",
                "i_bs_create_bin",
                "update_record",
                "case_end",
                "load_two_xregs",
            ][..],
        ),
        (
            "jit_xmem_asm.S",
            &[
                "swap",
                "store_two_values",
                "i_call_fun2",
                "recv_marker_reserve",
                "recv_marker_bind",
                "recv_marker_use",
                "raise",
            ][..],
        ),
    ] {
        let bytes = erlc_fixture(file);
        let used = extended_x_ops(&bytes);
        eprintln!("{file}: {} specific ops use X6+: {used:?}", used.len());
        for name in required {
            assert!(
                used.contains(*name),
                "{file}: {name} does not use X6+ ({used:?})"
            );
        }
    }
}

fn map_fragments(
    get: arinsal_beamasm::map::MapGetHelper,
    update: arinsal_beamasm::map::MapUpdateHelper,
) -> &'static arinsal_beamasm::map::MapFragments {
    Box::leak(Box::new(
        arinsal_beamasm::map::MapFragments::new(get, update).unwrap(),
    ))
}
