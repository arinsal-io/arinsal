use arinsal_a64::buf::CodeBuffer;
use arinsal_a64::enc::Gpr;
use arinsal_a64::exec::CodeMemory;
use arinsal_beamasm::{ExitReason, SchedulerRegisters};
use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::{EncodeOptions, OwnedTerm, decode, encode};
use arinsal_term::{Term, is_native_code_pointer};
use arinsal_vm::{NativeFunction, Process, Vm, register_native_function, run_native};
use std::process::Command;
use std::sync::Mutex;

static NATIVE_TEST_LOCK: Mutex<()> = Mutex::new(());

#[test]
#[cfg(target_arch = "aarch64")]
fn loaded_native_function_returns_x0_and_gc_preserves_its_cp() {
    let _serial = NATIVE_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let reference = RefErl::start().expect("OTP 29.1.1 is required to compile the test module");
    let beam = reference
        .compile_named(
            "native_abi_test",
            "-module(native_abi_test). -export([bridge/0]). bridge() -> 0.",
            &[],
        )
        .unwrap();

    let mut code = CodeBuffer::new();
    // SAFETY: A small integer is an immediate term with no heap pointer.
    let result = unsafe { Term::small(42).unwrap().raw_bits() };
    code.emit(|emitter| {
        emitter.mov_const(Gpr::x(25), result)?;
        emitter.mov_const(Gpr::x(0), 0)?;
        emitter.ret(Gpr::x(30))
    })
    .unwrap();
    let bytes: Vec<u8> = code
        .finish()
        .unwrap()
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect();
    let mut memory = CodeMemory::new(4096).unwrap();
    let offset = memory.alloc(bytes.len()).unwrap();
    memory.write_bytes(offset, &bytes).unwrap();
    let entry = memory.ptr_at(offset) as usize;
    register_native_function(NativeFunction {
        start: entry,
        end: entry + bytes.len(),
        module: "native_abi_test".into(),
        function: "bridge".into(),
        arity: 0,
        line: Some(17),
        file: Some("native_abi_test.erl".into()),
    })
    .unwrap();

    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let result = vm
        .eval_scheduled("native_abi_test", "bridge", &[], 1, None)
        .unwrap();
    assert_eq!(result.term, OwnedTerm::Int(42));
    assert_eq!(
        arinsal_vm::native_function_at(entry).unwrap().function,
        "bridge"
    );

    let mut process = Process::new();
    process.push_native_continuation(entry).unwrap();
    assert!(is_native_code_pointer(entry));
    process.heap.collect(&mut process.x, &mut [], 0).unwrap();
    // SAFETY: The value is the registered raw CP just pushed above.
    let continuation = unsafe { process.heap.stack_get(0).unwrap().raw_bits() };
    assert_eq!(continuation, entry as u64);

    let mut registers = SchedulerRegisters::default();
    let exit = run_native(&mut process, &mut registers, entry).unwrap();
    assert_eq!(exit, ExitReason::Returned);
    assert_eq!(process.x[0].as_small(), Some(42));
    let _ = Box::leak(Box::new(memory));
}

#[test]
#[cfg(target_arch = "aarch64")]
fn forced_jit_gc_large_append_keeps_native_stack() {
    const CHILD: &str = "ARINSAL_FORCED_JIT_GC_APPEND_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "forced_jit_gc_large_append_keeps_native_stack",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .env("ARINSAL_BEAMASM", "1")
            .env("ARINSAL_BEAMASM_MODULES", "beamasm_gc_append_vm_test")
            .env("ARINSAL_BEAMASM_STATS", "1")
            .env("ARINSAL_BEAMASM_LIFETIME", "1")
            .status()
            .unwrap();
        assert!(status.success(), "forced JIT GC child exited with {status}");
        return;
    }

    let reference = RefErl::start().expect("OTP 29.1.1 is required for this test");
    let source = r#"-module(beamasm_gc_append_vm_test).
        -export([run/2]).
        run(N, Size) -> repeat(N, lists:seq(1, Size), [], []).
        repeat(0, _Base, _Tail, Acc) -> length(Acc);
        repeat(N, Base, Tail, Acc) ->
            repeat(N - 1, Base, Tail, [length(Base ++ Tail) | Acc]).
    "#;
    let beam = reference
        .compile_named("beamasm_gc_append_vm_test", source, &[])
        .unwrap();
    reference.load("beamasm_gc_append_vm_test", &beam).unwrap();
    let arguments = [OwnedTerm::Int(500), OwnedTerm::Int(256)];
    let expected = reference.call("beamasm_gc_append_vm_test", "run", &arguments);

    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled(
            "beamasm_gc_append_vm_test",
            "run",
            &[Term::small(500).unwrap(), Term::small(256).unwrap()],
            1,
            None,
        )
        .unwrap();
    let canonical = decode(&encode(&actual.term, EncodeOptions::default())).unwrap();
    assert_eq!(expected, CallResult::Ok(canonical));
    assert!(
        actual.stats.gc.collections > 0,
        "test must collect during native calls"
    );
}

#[test]
#[cfg(target_arch = "aarch64")]
fn native_vm_bif_trap_returns_into_continuation() {
    const CHILD: &str = "ARINSAL_NATIVE_VM_BIF_TRAP_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "native_vm_bif_trap_returns_into_continuation",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .env("ARINSAL_BEAMASM", "1")
            .env("ARINSAL_BEAMASM_MODULES", "native_vm_bif_trap_test")
            .status()
            .unwrap();
        assert!(
            status.success(),
            "native BIF trap child exited with {status}"
        );
        return;
    }

    let reference = RefErl::start().expect("OTP 29.1.1 is required for this test");
    let module = "native_vm_bif_trap_test";
    let source = r#"-module(native_vm_bif_trap_test).
        -export([run/0]).
        run() ->
            Debug = erlang:system_info(debug_compiled),
            Old = put(trap_value, 17),
            Dict = get(trap_value),
            Tid = ets:new(trap_bif, [set, public]),
            Inserted = ets:insert(Tid, {key, Dict}),
            Lookup = ets:lookup(Tid, key),
            Port = open_port({spawn, "cat"}, [binary]),
            Message = {self(), {command, <<>>}},
            Sent = element(2, Port ! Message),
            Closed = port_close(Port),
            {Debug, Old, Dict, Inserted, Lookup, Sent, Closed}.
    "#;
    let beam = reference.compile_named(module, source, &[]).unwrap();
    reference.load(module, &beam).unwrap();
    let expected = reference.call(module, "run", &[]);

    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm.eval_scheduled(module, "run", &[], 1, None).unwrap();
    let canonical = decode(&encode(&actual.term, EncodeOptions::default())).unwrap();
    assert_eq!(expected, CallResult::Ok(canonical));
}

#[test]
#[cfg(target_arch = "aarch64")]
fn native_send_matches_interpreter_for_names_ports_and_tracing() {
    const CHILD: &str = "ARINSAL_NATIVE_SEND_CHILD";
    const MODULE: &str = "native_send_vm_test";
    if let Some(beam_path) = std::env::var_os(CHILD) {
        let beam = std::fs::read(beam_path).unwrap();
        let mut vm = Vm::new([]);
        vm.load_bytes(&beam).unwrap();
        let actual = vm.eval_scheduled(MODULE, "run", &[], 1, None).unwrap();
        println!("RESULT:{}", actual.text);
        return;
    }

    let _serial = NATIVE_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let reference = RefErl::start().expect("OTP 29.1.1 is required for this test");
    let source = r#"-module(native_send_vm_test).
        -export([run/0]).
        run() ->
            Self = self(),
            true = register(native_send_target, Self),
            erlang:trace(Self, true, [send]),
            native_send_target ! registered_message,
            TraceResult = receive
                {trace, Self, send, registered_message, Self} -> traced
            after 1000 -> timeout
            end,
            receive registered_message -> ok after 1000 -> timeout end,
            erlang:trace(Self, false, [send]),
            Port = open_port({spawn, "cat"}, [binary]),
            Port ! {Self, {command, <<"ping">>}},
            PortResult = receive
                {Port, {data, <<"ping">>}} -> received
            after 1000 -> timeout
            end,
            true = port_close(Port),
            {TraceResult, PortResult}.
    "#;
    let beam = reference.compile_named(MODULE, source, &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();
    let expected = reference.call(MODULE, "run", &[]);

    let dir = std::env::temp_dir().join(format!("arinsal-native-send-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let beam_path = dir.join("native_send_vm_test.beam");
    std::fs::write(&beam_path, beam).unwrap();
    let run_child = |native: bool| {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "native_send_matches_interpreter_for_names_ports_and_tracing",
                "--nocapture",
            ])
            .env(CHILD, &beam_path)
            .env("ARINSAL_BEAMASM", if native { "1" } else { "0" })
            .env("ARINSAL_BEAMASM_MODULES", MODULE)
            .env("ARINSAL_BEAMASM_STATS", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{} child failed: {}",
            if native { "native" } else { "interpreter" },
            String::from_utf8_lossy(&output.stderr)
        );
        if native {
            assert!(
                String::from_utf8_lossy(&output.stderr).contains("modules=1"),
                "native child must compile the tested module with BeamAsm: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let stdout = String::from_utf8(output.stdout).unwrap();
        stdout
            .lines()
            .find_map(|line| line.strip_prefix("RESULT:"))
            .expect("child prints a result")
            .to_owned()
    };
    let interpreted = run_child(false);
    let native = run_child(true);
    let expected = match expected {
        CallResult::Ok(term) => format!("{}", term),
        other => panic!("reference call failed: {other:?}"),
    };
    assert_eq!(interpreted, expected, "interpreter result must match OTP");
    assert_eq!(native, interpreted, "BeamAsm send must match interpreter");
    let _ = std::fs::remove_dir_all(dir);
}

fn compile_module(reference: &RefErl, module: &str, source: &str) -> (Vec<u8>, usize) {
    let beam = reference.compile_named(module, source, &[]).unwrap();
    let parsed = arinsal_beam::parse(&beam).unwrap();
    let loaded = arinsal_loader::load(&parsed).unwrap();
    let helper = loaded.export("helper", 0).unwrap();
    (beam, helper)
}

fn executable(code: CodeBuffer) -> (CodeMemory, usize, usize) {
    let bytes: Vec<u8> = code
        .finish()
        .unwrap()
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect();
    let mut memory = CodeMemory::new(4096).unwrap();
    let offset = memory.alloc(bytes.len()).unwrap();
    memory.write_bytes(offset, &bytes).unwrap();
    let entry = memory.ptr_at(offset) as usize;
    (memory, entry, bytes.len())
}

fn register_native(
    module: &str,
    function: &str,
    arity: u8,
    memory: CodeMemory,
    entry: usize,
    len: usize,
    line: u32,
) {
    register_native_function(NativeFunction {
        start: entry,
        end: entry + len,
        module: module.into(),
        function: function.into(),
        arity,
        line: Some(line),
        file: Some(format!("{module}.erl")),
    })
    .unwrap();
    let _ = Box::leak(Box::new(memory));
}

fn mixed_native(helper: usize, preserve_y: bool) -> CodeBuffer {
    let mut code = CodeBuffer::new();
    let resume = code.new_label();
    code.emit(|e| {
        e.sub_imm(Gpr::x(20), Gpr::x(20), 8, false)?;
        e.str_uoff(Gpr::x(25), Gpr::x(20), 0)?;
        Ok(())
    })
    .unwrap();
    code.adr(Gpr::x(14), resume).unwrap();
    code.emit(|e| {
        e.sub_imm(Gpr::x(20), Gpr::x(20), 8, false)?;
        e.str_uoff(Gpr::x(14), Gpr::x(20), 0)?;
        e.mov_const(Gpr::x(1), helper as u64)?;
        e.mov_const(Gpr::x(0), 2)?;
        e.ret(Gpr::x(30))
    })
    .unwrap();
    code.bind(resume).unwrap();
    code.emit(|e| {
        if preserve_y {
            e.ldr_uoff(Gpr::x(25), Gpr::x(20), 0)?;
        } else {
            // Erlang small integers share the same low tag, so adding the shifted
            // payload adds 35 to the helper's returned small integer.
            e.add_imm(Gpr::x(25), Gpr::x(25), 35 << 4, false)?;
        }
        e.add_imm(Gpr::x(20), Gpr::x(20), 8, false)?;
        e.mov_const(Gpr::x(0), 0)?;
        e.ret(Gpr::x(30))
    })
    .unwrap();
    code
}

#[test]
#[cfg(target_arch = "aarch64")]
fn mixed_call_unported_roundtrip() {
    let _serial = NATIVE_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let reference = RefErl::start().unwrap();
    let module = "native_mixed_roundtrip";
    let (beam, helper) = compile_module(
        &reference,
        module,
        "-module(native_mixed_roundtrip). -export([bridge/0, native_caller/1, helper/0]).\nbridge() -> native_caller(12) + 0.\nnative_caller(Value) -> Value.\nhelper() -> 7.",
    );
    reference.load(module, &beam).unwrap();
    let (memory, entry, len) = executable(mixed_native(helper, false));
    register_native(module, "native_caller", 1, memory, entry, len, 3);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm.eval_scheduled(module, "bridge", &[], 1, None).unwrap();
    assert_eq!(actual.term, OwnedTerm::Int(42));
}

#[test]
#[cfg(target_arch = "aarch64")]
fn gc_during_mixed_frame() {
    let _serial = NATIVE_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let reference = RefErl::start().unwrap();
    let module = "native_mixed_gc";
    let (beam, helper) = compile_module(
        &reference,
        module,
        "-module(native_mixed_gc). -export([bridge/0, native_caller/1, helper/0]).\nbridge() -> element(1, native_caller({saved,[1,2,3]})).\nnative_caller(Value) -> Value.\nhelper() -> make(180), 7.\nmake(0) -> []; make(N) -> [N|make(N-1)].",
    );
    let (memory, entry, len) = executable(mixed_native(helper, true));
    register_native(module, "native_caller", 1, memory, entry, len, 3);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm.eval_scheduled(module, "bridge", &[], 1, None).unwrap();
    assert_eq!(actual.term, OwnedTerm::Atom("saved".into()));
}

#[test]
#[cfg(target_arch = "aarch64")]
fn native_frame_in_stacktrace() {
    let _serial = NATIVE_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let reference = RefErl::start().unwrap();
    let module = "native_mixed_trace";
    let native_source = "-module(native_mixed_trace). -export([bridge/0, native_caller/1, helper/0]).\nbridge() -> native_caller(1) + 0.\nnative_caller(Value) -> Value.\nhelper() -> erlang:error(boom).";
    let interpreted_source = "-module(native_mixed_trace). -export([interpreted/0, native_caller/1, helper/0]).\ninterpreted() -> try {wrapped, native_caller(1)} catch error:boom:Stack -> Stack end.\nnative_caller(Value) -> Result = helper(), {Result, Value}.\nhelper() -> erlang:error(boom).";
    let beam = reference.compile_named(module, native_source, &[]).unwrap();
    let interpreted_beam = reference
        .compile_named(module, interpreted_source, &[])
        .unwrap();
    reference.load(module, &interpreted_beam).unwrap();
    let parsed = arinsal_beam::parse(&beam).unwrap();
    let helper = arinsal_loader::load(&parsed)
        .unwrap()
        .export("helper", 0)
        .unwrap();
    let (memory, entry, len) = executable(mixed_native(helper, false));
    register_native(module, "native_caller", 1, memory, entry, len, 3);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let error = match vm.eval_scheduled(module, "bridge", &[], 1, None) {
        Ok(_) => panic!("expected helper exception"),
        Err(error) => error,
    };
    let arinsal_vm::VmError::Raised(actual) = error else {
        panic!("expected a raised Erlang exception, got {error}");
    };
    let reference_trace = match reference.call(module, "interpreted", &[]) {
        arinsal_difftest::CallResult::Ok(trace) => trace,
        result => panic!("expected interpreted OTP trace, got {result:?}"),
    };
    let OwnedTerm::List {
        elems: actual_frames,
        ..
    } = &actual.stack
    else {
        panic!("expected Arinsal stack trace list");
    };
    let OwnedTerm::List {
        elems: expected_frames,
        ..
    } = &reference_trace
    else {
        panic!("expected OTP stack trace list");
    };
    fn native_frame<'a>(frames: &'a [OwnedTerm], module: &str) -> Option<&'a OwnedTerm> {
        frames.iter().find(|frame| {
            matches!(frame, OwnedTerm::Tuple(parts) if parts.len() == 4 && parts[0] == OwnedTerm::Atom(module.into()) && parts[1] == OwnedTerm::Atom("native_caller".into()))
        })
    }
    let Some(OwnedTerm::Tuple(native_parts)) = native_frame(actual_frames, module) else {
        panic!("native caller frame missing: {actual_frames:?}");
    };
    assert_eq!(native_parts[0], OwnedTerm::Atom(module.into()));
    assert_eq!(native_parts[1], OwnedTerm::Atom("native_caller".into()));
    assert_eq!(native_parts[2], OwnedTerm::Int(1));
    let Some(OwnedTerm::List {
        elems: location, ..
    }) = native_parts.get(3)
    else {
        panic!("native caller location missing: {native_parts:?}");
    };
    assert!(location.iter().any(|entry| {
        matches!(entry, OwnedTerm::Tuple(pair) if pair.len() == 2 && pair[0] == OwnedTerm::Atom("line".into()) && pair[1] == OwnedTerm::Int(3))
    }));
    assert!(expected_frames.iter().any(|frame| {
        matches!(frame, OwnedTerm::Tuple(parts) if parts.len() == 4 && parts[1] == OwnedTerm::Atom("helper".into()))
    }));
}

#[test]
#[cfg(target_arch = "aarch64")]
fn native_exception_unwinds_to_interpreted_catch() {
    let _serial = NATIVE_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let reference = RefErl::start().unwrap();
    let module = "native_mixed_exception";
    let source = "-module(native_mixed_exception). -export([bridge/0, native_raise/0]).\nbridge() -> try native_raise() catch C:R -> {C,R} end.\nnative_raise() -> ok.";
    let beam = reference.compile_named(module, source, &[]).unwrap();
    let mut code = CodeBuffer::new();
    let reason = arinsal_term::global_atoms().intern("badarith").unwrap();
    // SAFETY: The reason atom is an immediate atom term.
    let reason = unsafe { Term::atom(reason).raw_bits() };
    let hook = arinsal_vm::arinsal_native_raise as *const () as usize;
    code.emit(|e| {
        e.mov_reg(Gpr::x(0), Gpr::x(21))?;
        e.mov_const(Gpr::x(1), 1)?;
        e.mov_const(Gpr::x(2), reason)?;
        e.mov_const(Gpr::x(16), hook as u64)?;
        e.mov_reg(Gpr::x(14), Gpr::x(30))?;
        e.blr(Gpr::x(16))?;
        e.mov_reg(Gpr::x(30), Gpr::x(14))?;
        e.ret(Gpr::x(30))
    })
    .unwrap();
    let (memory, entry, len) = executable(code);
    register_native(module, "native_raise", 0, memory, entry, len, 3);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let result = vm.eval_scheduled(module, "bridge", &[], 1, None).unwrap();
    assert_eq!(
        result.term,
        OwnedTerm::Tuple(vec![
            OwnedTerm::Atom("error".into()),
            OwnedTerm::Atom("badarith".into())
        ])
    );
}
