use arinsal_a64::buf::CodeBuffer;
use arinsal_a64::enc::Gpr;
use arinsal_a64::exec::CodeMemory;
use arinsal_beamasm::{ExitReason, SchedulerRegisters};
use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::{EncodeOptions, OwnedTerm, decode, encode};
use arinsal_term::{Term, TermBuilder, is_native_code_pointer};
use arinsal_vm::{NativeFunction, Process, Vm, register_native_function, run_native};
use std::process::Command;
use std::sync::Mutex;

static NATIVE_TEST_LOCK: Mutex<()> = Mutex::new(());

#[test]
#[cfg(target_arch = "aarch64")]
fn native_try_end_keeps_success_value_for_fun_call() {
    const CHILD: &str = "ARINSAL_NATIVE_TRY_END_CHILD";
    const MODULE: &str = "native_try_end_test";
    if let Some(path) = std::env::var_os(CHILD) {
        let mut vm = Vm::new([]);
        vm.load_bytes(&std::fs::read(path).unwrap()).unwrap();
        let mut input_heap = Process::new();
        let input = TermBuilder::new(&mut input_heap.heap)
            .binary(&[1, 2, 3])
            .unwrap();
        let actual = vm.eval_scheduled(MODULE, "run", &[input], 1, None).unwrap();
        println!("RESULT:{}", actual.text);
        return;
    }

    let _serial = NATIVE_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let reference = RefErl::start().expect("OTP 29.1.1 is required for this test");
    let source = r#"-module(native_try_end_test).
        -export([run/1]).
        run(Input) ->
            Fun = fun(Data) -> {ok, Data} end,
            try binary_to_list(Input) of
                Data -> Fun(Data)
            catch
                error:badarg -> bad
            end.
    "#;
    let beam = reference.compile_named(MODULE, source, &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();
    let expected = match reference.call(MODULE, "run", &[OwnedTerm::Binary(vec![1, 2, 3])]) {
        CallResult::Ok(term) => format!("{term}"),
        other => panic!("OTP try-end call failed: {other:?}"),
    };
    let path = std::env::temp_dir().join(format!(
        "arinsal-native-try-end-{}.beam",
        std::process::id()
    ));
    std::fs::write(&path, beam).unwrap();
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "native_try_end_keeps_success_value_for_fun_call",
            "--nocapture",
        ])
        .env(CHILD, &path)
        .env("ARINSAL_BEAMASM", "1")
        .env("ARINSAL_BEAMASM_MODULES", MODULE)
        .env("ARINSAL_BEAMASM_VALIDATE", "1")
        .env("ARINSAL_BEAMASM_STATS", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "native try-end child failed: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("native_functions=4"),
        "try-end module did not compile natively: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let actual = stdout
        .lines()
        .find_map(|line| line.strip_prefix("RESULT:"))
        .expect("child prints the try-end result");
    assert_eq!(actual, expected);
    let _ = std::fs::remove_file(path);
}

#[test]
#[cfg(target_arch = "aarch64")]
fn native_external_return_preserves_tuple_for_native_guards() {
    const CHILD: &str = "ARINSAL_NATIVE_EXT_RETURN_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "native_external_return_preserves_tuple_for_native_guards",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .env("ARINSAL_BEAMASM", "1")
            .env("ARINSAL_BEAMASM_MODULES", "native_tail_ext_test")
            .status()
            .unwrap();
        assert!(
            status.success(),
            "native tail-call child exited with {status}"
        );
        return;
    }

    let reference = RefErl::start().expect("OTP 29.1.1 is required for this test");
    let module = "native_tail_ext_test";
    let target = "native_tail_ext_target";
    let target_source = r#"-module(native_tail_ext_target).
        -export([translate/2]).
        translate({A,B,C,D}, inet) -> {A,B,C,D};
        translate(IP, _) -> IP.
    "#;
    let target_beam = reference.compile_named(target, target_source, &[]).unwrap();
    reference.load(target, &target_beam).unwrap();
    let source = r#"-module(native_tail_ext_test).
        -export([run/1]).
        run(IP) ->
            case native_tail_ext_target:translate(IP, inet) of
                {A,B,C,D} -> A bor B bor C bor D;
                _ -> false
            end.
    "#;
    let beam = reference.compile_named(module, source, &[]).unwrap();
    reference.load(module, &beam).unwrap();
    let expected_input = OwnedTerm::Tuple(vec![
        OwnedTerm::Int(1),
        OwnedTerm::Int(2),
        OwnedTerm::Int(3),
        OwnedTerm::Int(4),
    ]);
    assert_eq!(
        reference.call(module, "run", std::slice::from_ref(&expected_input)),
        CallResult::Ok(OwnedTerm::Int(7))
    );

    let mut vm = Vm::new([]);
    vm.load_bytes(&target_beam).unwrap();
    vm.load_bytes(&beam).unwrap();
    let mut input_heap = Process::new();
    let input = TermBuilder::new(&mut input_heap.heap)
        .tuple(&[
            Term::small(1).unwrap(),
            Term::small(2).unwrap(),
            Term::small(3).unwrap(),
            Term::small(4).unwrap(),
        ])
        .unwrap();
    let direct = vm
        .eval_scheduled(
            target,
            "translate",
            &[
                input,
                Term::atom(arinsal_term::global_atoms().intern("inet").unwrap()),
            ],
            1,
            None,
        )
        .unwrap();
    assert_eq!(
        decode(&encode(&direct.term, EncodeOptions::default())).unwrap(),
        expected_input
    );
    let actual = vm.eval_scheduled(module, "run", &[input], 1, None).unwrap();
    assert_eq!(
        decode(&encode(&actual.term, EncodeOptions::default())).unwrap(),
        OwnedTerm::Int(7)
    );
}

#[test]
#[cfg(target_arch = "aarch64")]
fn native_tail_export_transitions_preserve_cp_only_frames() {
    const CHILD: &str = "ARINSAL_NATIVE_CP_TRANSITIONS_CHILD";
    const MODULE: &str = "native_cp_transition_wrapper";
    if let Some(dir) = std::env::var_os(CHILD) {
        let path = std::path::Path::new(&dir);
        let mut vm = Vm::new([]);
        for name in [
            "native_cp_transition_target",
            "native_cp_transition_native",
            MODULE,
        ] {
            vm.load_bytes(&std::fs::read(path.join(format!("{name}.beam"))).unwrap())
                .unwrap();
        }
        let actual = vm.eval_scheduled(MODULE, "run", &[], 1, None).unwrap();
        println!("RESULT:{}", actual.text);
        return;
    }

    let _serial = NATIVE_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let reference = RefErl::start().expect("OTP 29.1.1 is required for this test");
    let modules = [
        (
            "native_cp_transition_target",
            "-module(native_cp_transition_target). -export([identity/1]). identity(Value) -> Value.",
        ),
        (
            "native_cp_transition_native",
            "-module(native_cp_transition_native). -export([tail/1, chain/1]). tail(Value) -> Saved = {native_frame, Value}, native_cp_transition_target:identity(Saved). chain(Value) -> native_cp_transition_target:identity(Value).",
        ),
        (
            MODULE,
            "-module(native_cp_transition_wrapper). -export([run/0]). run() -> {native_cp_transition_native:tail(first), {continued, native_cp_transition_native:chain(second)}}.",
        ),
    ];
    let dir = std::env::temp_dir().join(format!("arinsal-native-cp-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    for (name, source) in modules {
        let beam = reference.compile_named(name, source, &[]).unwrap();
        reference.load(name, &beam).unwrap();
        std::fs::write(dir.join(format!("{name}.beam")), beam).unwrap();
    }
    let expected = match reference.call(MODULE, "run", &[]) {
        CallResult::Ok(term) => format!("{term}"),
        other => panic!("OTP CP transition call failed: {other:?}"),
    };
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "native_tail_export_transitions_preserve_cp_only_frames",
            "--nocapture",
        ])
        .env(CHILD, &dir)
        .env("ARINSAL_BEAMASM", "1")
        .env("ARINSAL_BEAMASM_MODULES", "native_cp_transition_native")
        .env("ARINSAL_BEAMASM_STATS", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "native CP transition child failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("native_functions=4"),
        "BeamAsm must compile both native callers: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let actual = stdout
        .lines()
        .find_map(|line| line.strip_prefix("RESULT:"))
        .expect("child prints a result");
    assert_eq!(
        actual,
        expected,
        "child stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
#[cfg(target_arch = "aarch64")]
fn native_tail_fun_returns_preserve_recursive_y_frames() {
    const CHILD: &str = "ARINSAL_NATIVE_TAIL_FUN_CHILD";
    const MODULE: &str = "native_tail_fun_frame_test";
    let source = r#"-module(native_tail_fun_frame_test).
        -export([run/1, eval_script/2, debug/2, debug/3]).
        -record(es, {a,b,c,d,e,f,g,h,i,j,debug=false,result=[]}).
        run(Debug) ->
            Es = #es{a=1,b=2,c=3,d=4,e=5,f=6,g=7,h=8,i=9,j=10,debug=Debug},
            eval_script([{progress, boot}, {path, "boot"}], Es).
        eval_script([{progress, Info}|T], #es{debug=Debug}=Es) ->
            debug(Debug, {progress, Info}),
            self() ! {self(), progress, Info},
            eval_script(T, Es);
        eval_script([{path, Path}|T], #es{debug=Debug}=Es) ->
            Value = debug(Debug, {path, Path}, fun() ->
                {Es#es.a,Es#es.b,Es#es.c,Es#es.d,Es#es.e,
                 Es#es.f,Es#es.g,Es#es.h,Es#es.i,Es#es.j}
            end),
            eval_script(T, Es#es{result=[Value|Es#es.result]});
        eval_script([], #es{result=Result}) -> lists:reverse(Result).
        debug(false, _) -> erlang:garbage_collect();
        debug(_, Term) -> erlang:display(Term).
        debug(false, _, Fun) -> erlang:garbage_collect(), Fun();
        debug(_, Term, Fun) ->
            erlang:display(Term),
            Start = erlang:monotonic_time(),
            Value = Fun(),
            Stop = erlang:monotonic_time(),
            erlang:display({done_in_microseconds,
                erlang:convert_time_unit(Stop-Start,native,microsecond)}),
            Value.
    "#;
    if let Some(dir) = std::env::var_os(CHILD) {
        let mut vm = Vm::new([]);
        vm.load_bytes(
            &std::fs::read(std::path::Path::new(&dir).join(format!("{MODULE}.beam"))).unwrap(),
        )
        .unwrap();
        let result = vm
            .eval_scheduled(
                MODULE,
                "run",
                &[Term::atom(
                    arinsal_term::global_atoms().intern("false").unwrap(),
                )],
                1,
                None,
            )
            .unwrap();
        println!("RESULT:false:{}", result.text);
        return;
    }

    let _serial = NATIVE_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let reference = RefErl::start().expect("OTP 29.1.1 is required for this test");
    let beam = reference.compile_named(MODULE, source, &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();
    let expected = match reference.call(MODULE, "run", &[OwnedTerm::Atom("false".to_owned())]) {
        CallResult::Ok(term) => format!("{term}"),
        other => panic!("OTP tail fun frame call failed: {other:?}"),
    };
    let dir = std::env::temp_dir().join(format!("arinsal-native-tail-fun-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(format!("{MODULE}.beam")), beam).unwrap();
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "native_tail_fun_returns_preserve_recursive_y_frames",
            "--nocapture",
        ])
        .env(CHILD, &dir)
        .env("ARINSAL_BEAMASM", "1")
        .env("ARINSAL_BEAMASM_MODULES", MODULE)
        .env("ARINSAL_BEAMASM_STATS", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "native tail fun child failed ({:?}): {}{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("native_functions=7"),
        "BeamAsm must compile the seven supported reproducer functions: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let actual = stdout
        .lines()
        .find_map(|line| line.strip_prefix("RESULT:false:"))
        .unwrap_or_else(|| panic!("missing result for debug=false: {stdout}"));
    assert_eq!(
        actual,
        expected,
        "child stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let _ = std::fs::remove_dir_all(dir);
}

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
        line_table: Vec::new(),
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
fn native_boolean_bifs_keep_tagged_comparison_results() {
    const CHILD: &str = "ARINSAL_NATIVE_BOOLEAN_BIF_CHILD";
    const MODULE: &str = "native_boolean_bif_test";
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
    let source = r#"-module(native_boolean_bif_test).
        -export([run/0]).
        run() ->
            Equal = compare(1, 1),
            Unequal = compare(1, 2),
            {Equal and Unequal, Equal or Unequal, not Unequal}.
        compare(Left, Right) -> Left =:= Right.
    "#;
    let beam = reference.compile_named(MODULE, source, &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();
    let expected = match reference.call(MODULE, "run", &[]) {
        CallResult::Ok(term) => format!("{term}"),
        other => panic!("reference call failed: {other:?}"),
    };

    let dir = std::env::temp_dir().join(format!("arinsal-native-bool-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let beam_path = dir.join("native_boolean_bif_test.beam");
    std::fs::write(&beam_path, beam).unwrap();
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "native_boolean_bifs_keep_tagged_comparison_results",
            "--nocapture",
        ])
        .env(CHILD, &beam_path)
        .env("ARINSAL_BEAMASM", "1")
        .env("ARINSAL_BEAMASM_MODULES", MODULE)
        .env("ARINSAL_BEAMASM_STATS", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "native boolean BIF child failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("modules=1"),
        "BeamAsm must compile the tested module: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let actual = stdout
        .lines()
        .find_map(|line| line.strip_prefix("RESULT:"))
        .expect("child prints a result");
    assert_eq!(
        actual,
        expected,
        "child stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
#[cfg(target_arch = "aarch64")]
fn inet_udp_open_trace_matches_otp_with_native_open() {
    const CHILD: &str = "ARINSAL_INET_UDP_TRACE_CHILD";
    const MODULE: &str = "inet_udp_trace_compare_test";
    if let Some(dir) = std::env::var_os(CHILD) {
        let read_beam = |name: &str| std::fs::read(std::path::Path::new(&dir).join(name)).unwrap();
        let inet_udp = read_beam("inet_udp.beam");
        let inet = read_beam("inet.beam");
        let wrapper = read_beam("wrapper.beam");
        let mut vm = Vm::new([]);
        vm.load_bytes(&inet_udp).unwrap();
        vm.load_bytes(&inet).unwrap();
        vm.load_bytes(&wrapper).unwrap();
        let actual = vm.eval_scheduled(MODULE, "run", &[], 1, None).unwrap();
        println!("RESULT:{}", actual.text);
        return;
    }

    let _serial = NATIVE_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let reference = RefErl::start().expect("OTP 29.1.1 is required for this test");
    let module_beam = |module: &str| {
        let object = reference
            .eval(&format!("element(2,code:get_object_code({module}))"))
            .unwrap();
        match &object {
            OwnedTerm::Binary(beam) => beam.clone(),
            other => panic!("OTP did not return {module}'s BEAM: {other:?}"),
        }
    };
    let inet_udp = module_beam("inet_udp");
    let inet = module_beam("inet");
    let source = r#"-module(inet_udp_trace_compare_test).
        -export([run/0]).
        run() ->
            code:ensure_loaded(inet_udp),
            code:ensure_loaded(inet),
            case ets:whereis(ac_tab) of
                undefined -> ets:new(ac_tab, [named_table, public, set]);
                _ -> ok
            end,
            {ok, Socket} = inet_udp:open(0, []),
            {ok, inet_udp:close(Socket)}.
    "#;
    let wrapper = reference.compile_named(MODULE, source, &[]).unwrap();
    reference.load(MODULE, &wrapper).unwrap();
    let expected = match reference.call(MODULE, "run", &[]) {
        CallResult::Ok(term) => format!("{term}"),
        other => panic!("OTP trace call failed: {other:?}"),
    };

    let dir = std::env::temp_dir().join(format!("arinsal-inet-udp-trace-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("inet_udp.beam"), inet_udp).unwrap();
    std::fs::write(dir.join("inet.beam"), inet).unwrap();
    std::fs::write(dir.join("wrapper.beam"), wrapper).unwrap();
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "inet_udp_open_trace_matches_otp_with_native_open",
            "--nocapture",
        ])
        .env(CHILD, &dir)
        .env("ARINSAL_BEAMASM", "1")
        .env("ARINSAL_BEAMASM_MODULES", "inet_udp")
        .env("ARINSAL_BEAMASM_FUNCS", "open/2")
        .env("ARINSAL_BEAMASM_STATS", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "native inet_udp trace child failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("modules=1"),
        "BeamAsm must compile inet_udp:open/2: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let actual = stdout
        .lines()
        .find_map(|line| line.strip_prefix("RESULT:"))
        .expect("child prints a result");
    assert_eq!(
        actual,
        expected,
        "native child stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
#[cfg(target_arch = "aarch64")]
fn unaligned_binary_order_matches_interpreter_and_beamasm() {
    const CHILD: &str = "ARINSAL_UNALIGNED_ORDER_CHILD";
    const MODULE: &str = "unaligned_literal_order_vm_test";
    if let Some(path) = std::env::var_os(CHILD) {
        let beam = std::fs::read(path).unwrap();
        let mut vm = Vm::new([]);
        vm.load_bytes(&beam).unwrap();
        let result = vm.eval_scheduled(MODULE, "run", &[], 1, None).unwrap();
        assert_eq!(result.term, OwnedTerm::Atom("ok".into()));
        println!("RESULT:ok");
        return;
    }

    let reference = RefErl::start().expect("OTP 29.1.1 is required for this test");
    let source = r#"-module(unaligned_literal_order_vm_test).
        -export([run/0]).
        run() ->
            B1 = list_to_binary([7,8,9]),
            {_,B2} = split_binary(list_to_binary([0,1,3,1,2,3,4]),3),
            B3 = list_to_binary([1,2,3,5]),
            U = erts_debug:unaligned_bitstring(B2,3),
            false = B1 == B2,
            false = B1 =:= B2,
            true = B1 /= B2,
            true = B1 =/= B2,
            true = B1 > B2,
            true = B2 < B3,
            true = B2 =< B1,
            true = B2 =< B3,
            true = B2 =:= U,
            true = B2 == U,
            true = U < B3,
            true = U =< B3,
            ExactU = erts_debug:unaligned_bitstring(<<1,2,3,4>>,3),
            true = ExactU < <<1,2,3,5>>,
            true = ExactU =< <<1,2,3,5>>,
            true = B1 > 0,
            ok.
    "#;
    let beam = reference.compile_named(MODULE, source, &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();
    assert_eq!(
        reference.call(MODULE, "run", &[]),
        CallResult::Ok(OwnedTerm::Atom("ok".into()))
    );

    let dir = std::env::temp_dir().join(format!("arinsal-unaligned-order-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let beam_path = dir.join(format!("{MODULE}.beam"));
    std::fs::write(&beam_path, beam).unwrap();
    for native in [false, true] {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "unaligned_binary_order_matches_interpreter_and_beamasm",
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
            "{} run failed: {}",
            if native { "BeamAsm" } else { "interpreter" },
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("RESULT:ok"),
            "{} run did not return ok",
            if native { "BeamAsm" } else { "interpreter" }
        );
        if native {
            let stats = String::from_utf8_lossy(&output.stderr);
            assert!(
                stats.contains("modules=1"),
                "BeamAsm did not compile the module: {stats}"
            );
            assert!(
                !stats.contains("native_functions=0"),
                "BeamAsm did not compile any functions: {stats}"
            );
            assert!(
                !stats.contains("native_calls=0"),
                "BeamAsm did not execute native code: {stats}"
            );
        }
    }
}

#[test]
fn malformed_etf_trap_does_not_leak_into_following_bifs() {
    const MODULE: &str = "malformed_etf_trap_vm_test";
    let reference = RefErl::start().expect("OTP 29.1.1 is required for this test");
    let source = r#"-module(malformed_etf_trap_vm_test).
        -export([run/0]).
        run() ->
            B1 = <<7,8,9>>,
            B2 = <<7,8,8>>,
            Malformed = <<131,(binary:copy(<<104,1>>,270000))/binary,255>>,
            _ = erts_debug:set_internal_state(available_internal_state, true),
            _ = erts_debug:set_internal_state(reds_left, 1),
            badarg = try binary_to_term(Malformed) of
                         _ -> unexpected_success
                     catch
                         error:badarg -> badarg
                     end,
            true = B1 > B2,
            true = B1 > 0,
            true = is_binary(B1),
            {B1 > B2, B1 > 0, is_binary(B1)}.
    "#;
    let beam = reference.compile_named(MODULE, source, &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();
    assert_eq!(
        reference.call(MODULE, "run", &[]),
        CallResult::Ok(OwnedTerm::Tuple(vec![
            OwnedTerm::atom("true"),
            OwnedTerm::atom("true"),
            OwnedTerm::atom("true"),
        ]))
    );
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm.eval_scheduled(MODULE, "run", &[], 1, None).unwrap();
    let canonical = decode(&encode(&actual.term, EncodeOptions::default())).unwrap();
    assert_eq!(
        canonical,
        OwnedTerm::Tuple(vec![
            OwnedTerm::atom("true"),
            OwnedTerm::atom("true"),
            OwnedTerm::atom("true"),
        ])
    );
}

#[test]
fn compressed_etf_decode_resumes_across_output_chunks() {
    const MODULE: &str = "compressed_etf_trap_vm_test";
    let reference = RefErl::start().expect("OTP 29.1.1 is required to compile the test module");
    let source = r#"-module(compressed_etf_trap_vm_test).
        -export([run/0]).
        run() ->
            Value = list_to_tuple(lists:duplicate(300000, repeated_atom)),
            Encoded = term_to_binary(Value, [compressed]),
            tuple_size(binary_to_term(Encoded)).
    "#;
    let beam = reference.compile_named(MODULE, source, &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();
    assert_eq!(
        reference.call(MODULE, "run", &[]),
        CallResult::Ok(OwnedTerm::Int(300000))
    );

    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm.eval_scheduled(MODULE, "run", &[], 1, None).unwrap();
    assert_eq!(actual.term, OwnedTerm::Int(300000));
}

#[test]
fn nested_map_etf_decode_resumes_after_low_reductions() {
    const MODULE: &str = "nested_map_etf_trap_vm_test";
    let reference = RefErl::start().expect("OTP 29.1.1 is required to compile the test module");
    let source = r#"-module(nested_map_etf_trap_vm_test).
        -export([run/0]).
        run() ->
            Small = #{a => 1, b => 2, c => 3},
            Left = maps:from_list([{list_to_atom(integer_to_list(16#cafe + N*N*N, 36)), N}
                                   || N <- lists:seq(1, 33)]),
            Right = maps:from_list([{list_to_atom(integer_to_list(16#dead + N, 36)), N}
                                    || N <- lists:seq(1, 50)]),
            Extra = #{Small => a, Left => Right, Right => Left,
                      [Left, Right] => Left, <<"abc">> => Small,
                      <<"qrs">> => Left, <<"xyz">> => Right},
            Term = maps:merge(Left, Extra),
            Bin = term_to_binary(Term, [deterministic]),
            Plain = term_to_binary(Term),
            Minor1 = term_to_binary(Term, [{minor_version, 1}]),
            Compressed = term_to_binary(Term, [compressed]),
            Unaligned = erts_debug:unaligned_bitstring(Plain, 3),
            Extended = <<Plain/binary, 1, 2, 3>>,
            CompressedUnaligned = erts_debug:unaligned_bitstring(Compressed, 3),
            CompressedExtended = <<Compressed/binary, 1, 2, 3>>,
            _ = erts_debug:set_internal_state(available_internal_state, true),
            {check(Bin, [], Term),
             check(Plain, [safe], Term),
             check(Minor1, [], Term),
             check(Compressed, [], Term),
             check(Unaligned, [], Term),
             check(Extended, [], Term),
             check_used(Plain, Term, byte_size(Plain)),
             check_used(Extended, Term, byte_size(Plain)),
             check_used(Unaligned, Term, byte_size(Plain)),
             check_used(Compressed, Term, byte_size(Compressed)),
             check_used(CompressedUnaligned, Term, byte_size(Compressed)),
             check_used(CompressedExtended, Term, byte_size(Compressed)),
             map_size(Term)}.
        check(Bin, Options, Term) ->
            _ = erts_debug:set_internal_state(reds_left, 1),
            try binary_to_term(Bin, Options) of
                Term -> true;
                _ -> false
            catch error:badarg -> false
            end.
        check_used(Bin, Term, Used) ->
            _ = erts_debug:set_internal_state(reds_left, 1),
            try binary_to_term(Bin, [used]) of
                {Term, Used} -> true;
                _ -> false
            catch error:badarg -> false
            end.
    "#;
    let beam = reference.compile_named(MODULE, source, &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();
    assert_eq!(
        reference.call(MODULE, "run", &[]),
        CallResult::Ok(OwnedTerm::Tuple(vec![
            OwnedTerm::atom("true"),
            OwnedTerm::atom("true"),
            OwnedTerm::atom("true"),
            OwnedTerm::atom("true"),
            OwnedTerm::atom("true"),
            OwnedTerm::atom("true"),
            OwnedTerm::atom("true"),
            OwnedTerm::atom("true"),
            OwnedTerm::atom("true"),
            OwnedTerm::atom("true"),
            OwnedTerm::atom("true"),
            OwnedTerm::atom("true"),
            OwnedTerm::Int(40),
        ]))
    );

    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm.eval_scheduled(MODULE, "run", &[], 1, None).unwrap();
    assert_eq!(
        actual.term,
        OwnedTerm::Tuple(vec![
            OwnedTerm::atom("true"),
            OwnedTerm::atom("true"),
            OwnedTerm::atom("true"),
            OwnedTerm::atom("true"),
            OwnedTerm::atom("true"),
            OwnedTerm::atom("true"),
            OwnedTerm::atom("true"),
            OwnedTerm::atom("true"),
            OwnedTerm::atom("true"),
            OwnedTerm::atom("true"),
            OwnedTerm::atom("true"),
            OwnedTerm::atom("true"),
            OwnedTerm::Int(40),
        ])
    );
}

#[test]
fn code_mod_permission_waiter_yields_to_the_lock_owner() {
    const MODULE: &str = "code_mod_permission_trap_vm_test";
    let _serial = NATIVE_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let reference = RefErl::start().expect("OTP 29.1.1 is required to compile the test module");
    let source = r#"-module(code_mod_permission_trap_vm_test).
        -export([run/0]).
        run() ->
            _ = erts_debug:set_internal_state(available_internal_state, true),
            true = erts_debug:set_internal_state(code_mod_permission, true),
            Parent = self(),
            _Pid = spawn(fun() ->
                Parent ! attempting,
                true = erts_debug:set_internal_state(code_mod_permission, true),
                Parent ! acquired,
                true = erts_debug:set_internal_state(code_mod_permission, false)
            end),
            receive attempting -> ok end,
            erlang:bump_reductions(100000),
            true = erts_debug:set_internal_state(code_mod_permission, false),
            receive acquired -> released_after_yield after 1000 -> timeout end.
    "#;
    let beam = reference.compile_named(MODULE, source, &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();
    assert_eq!(
        reference.call(MODULE, "run", &[]),
        CallResult::Ok(OwnedTerm::atom("released_after_yield"))
    );

    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm.eval_scheduled(MODULE, "run", &[], 1, None).unwrap();
    assert_eq!(actual.term, OwnedTerm::atom("released_after_yield"));
}

#[test]
fn apply_yield_keeps_completed_bif_result_in_x0() {
    const MODULE: &str = "apply_yield_result_vm_test";
    let reference = RefErl::start().expect("OTP 29.1.1 is required to compile the test module");
    let source = r#"-module(apply_yield_result_vm_test).
        -export([run/0]).
        run() -> loop(200000).
        loop(0) -> true;
        loop(N) ->
            true = try apply(erlang, '>', [<<7,8,9>>, N]) of
                       Value -> Value
                   catch
                       _:_ -> x
                   end,
            loop(N - 1).
    "#;
    let beam = reference.compile_named(MODULE, source, &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();
    assert_eq!(
        reference.call(MODULE, "run", &[]),
        CallResult::Ok(OwnedTerm::atom("true"))
    );

    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm.eval_scheduled(MODULE, "run", &[], 1, None).unwrap();
    assert_eq!(actual.term, OwnedTerm::atom("true"));
}

#[test]
fn deferred_gc_after_applied_binary_to_term_keeps_caller_roots() {
    const MODULE: &str = "apply_binary_to_term_gc_vm_test";
    let reference = RefErl::start().expect("OTP 29.1.1 is required to compile the test module");
    let source = r#"-module(apply_binary_to_term_gc_vm_test).
        -export([run/0, worker/4]).
        run() ->
            Pid = spawn(apply_binary_to_term_gc_vm_test, worker,
                        [binary_to_term,
                         fun() -> [term_to_binary(lists:duplicate(2000000, 2000000))] end,
                         1000, self()]),
            receive ok -> ok end,
            Ref = make_ref(),
            erlang:garbage_collect(Pid, [{async, Ref}]),
            receive after 1 -> ok end,
            exit(Pid, kill),
            receive {garbage_collect, Ref, _} -> ok after 30000 -> timeout end.
        worker(Bif, ArgFun, N, Parent) ->
            Args = ArgFun(),
            Parent ! ok,
            loop(Bif, Args, N).
        loop(_, _, 0) -> ok;
        loop(Bif, Args, N) ->
            apply(erlang, Bif, Args),
            loop(Bif, Args, N - 1).
    "#;
    let beam = reference.compile_named(MODULE, source, &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();
    assert_eq!(
        reference.call(MODULE, "run", &[]),
        CallResult::Ok(OwnedTerm::atom("ok"))
    );

    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm.eval_scheduled(MODULE, "run", &[], 1, None).unwrap();
    assert_eq!(actual.term, OwnedTerm::atom("ok"));
}

#[test]
fn traced_apply_resumes_trap_without_caller_import() {
    // The caller neither imports the BIF nor calls it statically, and the running trace
    // makes every yield observable: a trap that restarted on resume would never finish.
    const MODULE: &str = "traced_apply_trap_vm_test";
    let reference = RefErl::start().expect("OTP 29.1.1 is required to compile the test module");
    let source = r#"-module(traced_apply_trap_vm_test).
        -export([run/0]).
        run() ->
            {M, F} = binary_to_term(<<131,104,2,100,0,6,"erlang",100,0,14,"list_to_binary">>),
            Self = self(),
            {Pid, Mon} = spawn_monitor(fun() ->
                A = [[ok_list(lists:seq(1, 1000000)), oops]],
                try
                    erlang:yield(),
                    erlang:trace(self(), true, [running, {tracer, Self}]),
                    apply(M, F, [A])
                catch error:badarg:Stk ->
                    erlang:trace(self(), false, [running, {tracer, Self}]),
                    [{M, F, [A], _} | _] = Stk,
                    exit(normal)
                end
            end),
            normal = receive {'DOWN', Mon, process, Pid, Reason} -> Reason end,
            Td = erlang:trace_delivered(Pid),
            receive {trace_delivered, Pid, Td} -> ok end,
            yields(Pid, 0) > 2.
        ok_list(L) -> [X rem 256 || X <- L].
        yields(Pid, N) ->
            receive
                {trace, Pid, out, {erts_internal, list_to_bitstring_continue, 1}} ->
                    yields(Pid, N + 1);
                {trace, Pid, _, _} -> yields(Pid, N)
            after 0 -> N
            end.
    "#;
    let beam = reference.compile_named(MODULE, source, &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();
    assert_eq!(
        reference.call(MODULE, "run", &[]),
        CallResult::Ok(OwnedTerm::atom("true"))
    );

    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm.eval_scheduled(MODULE, "run", &[], 1, None).unwrap();
    assert_eq!(actual.term, OwnedTerm::atom("true"));
}

#[test]
fn deterministic_etf_map_order_survives_bif_yields() {
    const MODULE: &str = "deterministic_etf_yield_vm_test";
    let reference = RefErl::start().expect("OTP 29.1.1 is required to compile the test module");
    let source = r#"-module(deterministic_etf_yield_vm_test).
        -export([run/0]).
        run() ->
            Left = maps:from_list([{N, N*N} || N <- lists:seq(1, 33)]),
            Right = maps:from_list([{N, N} || N <- lists:seq(1, 50)]),
            Small = #{a => 1, b => 2, c => 3},
            Extra = #{Small => a, Left => Right, Right => Left,
                      [Left, Right] => Left},
            Map = maps:merge(maps:merge(#{1 => a, 1.0 => b},
                                        maps:from_list([{N, N} || N <- lists:seq(1, 10000)])),
                             Extra),
            Bin = term_to_binary(Map, [deterministic]),
            Map = binary_to_term(Bin),
            Expected = lists:sort(fun(A, B) -> erts_internal:cmp_term(A, B) =< 0 end,
                                  maps:to_list(Map)),
            first_difference(Expected, decode_ext_map(Bin)).
        decode_ext_map(<<131, 116, Size:32, Rest/binary>>) ->
            decode_ext_pairs(binary_to_term(<<131, 108, (2*Size):32, Rest/binary, 106>>)).
        decode_ext_pairs([Key, Value | Rest]) ->
            [{Key, Value} | decode_ext_pairs(Rest)];
        decode_ext_pairs([]) -> [].
        first_difference([A | As], [B | Bs]) when A =:= B ->
            first_difference(As, Bs);
        first_difference([Expected | _], [Actual | _]) ->
            {false, Expected, Actual};
        first_difference([], []) -> true.
    "#;
    let beam = reference.compile_named(MODULE, source, &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();
    assert_eq!(
        reference.call(MODULE, "run", &[]),
        CallResult::Ok(OwnedTerm::atom("true"))
    );

    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm.eval_scheduled(MODULE, "run", &[], 1, None).unwrap();
    assert_eq!(
        actual.term,
        OwnedTerm::atom("true"),
        "first deterministic ETF map-order mismatch"
    );
}

#[test]
fn list_to_binary_error_after_yield_keeps_original_bif_frame() {
    const MODULE: &str = "list_to_binary_error_after_yield_vm_test";
    let reference = RefErl::start().expect("OTP 29.1.1 is required to compile the test module");
    let source = r#"-module(list_to_binary_error_after_yield_vm_test).
        -export([run/0]).
        run() ->
            {Pid, Monitor} = spawn_monitor(fun() ->
                Input = [[mk_list(1000000), oops]],
                try
                    erlang:yield(),
                    apply(erlang, list_to_binary, [Input]),
                    exit(unexpected_success)
                catch
                    error:badarg:Stack ->
                        [{erlang, list_to_binary, _, _} | _] = Stack
                end
            end),
            receive {'DOWN', Monitor, process, Pid, normal} -> ok end,
            ok.
        mk_list(Size) when Size >= 1024*1024 ->
            Left = (Size - (512*1024+10)) div 2,
            Right = Size - (512*1024+10) - Left,
            [mk_list(Left), list_to_binary(mk_list(512*1024+10)), mk_list(Right)];
        mk_list(Size) -> mk_list(Size, []).
        mk_list(0, Acc) -> Acc;
        mk_list(N, Acc) -> mk_list(N - 1, [$A + (N band 63) | Acc]).
    "#;
    let beam = reference.compile_named(MODULE, source, &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();
    assert!(matches!(
        reference.call(MODULE, "run", &[]),
        CallResult::Ok(_)
    ));

    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm.eval_scheduled(MODULE, "run", &[], 1, None).unwrap();
    assert_eq!(actual.term, OwnedTerm::atom("ok"));
}

#[test]
fn malformed_large_etf_trap_keeps_original_binary_to_term_frame() {
    const MODULE: &str = "malformed_large_etf_trap_vm_test";
    let reference = RefErl::start().expect("OTP 29.1.1 is required to compile the test module");
    let source = r#"-module(malformed_large_etf_trap_vm_test).
        -export([run/0]).
        run() ->
            TupleSize = 2000000,
            <<131, AtomExt/binary>> = term_to_binary(an_atom_we_use_for_this),
            BadAtomExt = <<100, 65535:16/big, "oops">>,
            Bin = <<131, 105, TupleSize:32/big,
                    (binary:copy(AtomExt, TupleSize - 1))/binary, BadAtomExt/binary>>,
            try
                binary_to_term(Bin),
                unexpected_success
            catch
                error:badarg:Stack ->
                    [{erlang, binary_to_term, [Bin], _} | _] = Stack,
                    badarg
            end.
    "#;
    let beam = reference.compile_named(MODULE, source, &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();
    assert_eq!(
        reference.call(MODULE, "run", &[]),
        CallResult::Ok(OwnedTerm::atom("badarg"))
    );

    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm.eval_scheduled(MODULE, "run", &[], 1, None).unwrap();
    assert_eq!(actual.term, OwnedTerm::atom("badarg"));
}

#[test]
fn binary_search_bifs_resume_after_budget_exhaustion() {
    const MODULE: &str = "binary_search_trap_vm_test";
    let reference = RefErl::start().expect("OTP 29.1.1 is required to compile the test module");
    let source = r#"-module(binary_search_trap_vm_test).
        -export([run/0]).
        run() ->
            Prefix = binary:copy(<<"x">>, 100000),
            Subject = <<Prefix/binary, "needle", Prefix/binary, "needle">>,
            {binary:match(Subject, <<"needle">>),
             binary:matches(Subject, [<<"needle">>, <<"xneedle">>]),
             binary:split(Subject, <<"needle">>, [global])}.
    "#;
    let beam = reference.compile_named(MODULE, source, &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();
    let expected = reference.call(MODULE, "run", &[]);

    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm.eval_scheduled(MODULE, "run", &[], 1, None).unwrap();
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
            Recursive = send_loop(500, self(), []),
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
            {TraceResult, PortResult, Recursive}.
        send_loop(0, _Pid, Acc) -> Acc;
        send_loop(N, Pid, Acc) ->
            Pid ! {send_loop, N},
            receive {send_loop, N} -> send_loop(N - 1, Pid, [N | Acc]) end.
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
            "{} child failed ({:?}): stdout={} stderr={}",
            if native { "native" } else { "interpreter" },
            output.status,
            String::from_utf8_lossy(&output.stdout),
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

#[test]
#[cfg(target_arch = "aarch64")]
fn native_node_instruction_matches_interpreter_and_otp() {
    const CHILD: &str = "ARINSAL_NATIVE_NODE_CHILD";
    const MODULE: &str = "native_node_instruction_test";
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
    let beam = reference
        .compile_named(
            MODULE,
            "-module(native_node_instruction_test). -export([run/0]). run() -> node().",
            &[],
        )
        .unwrap();
    reference.load(MODULE, &beam).unwrap();
    let expected = match reference.call(MODULE, "run", &[]) {
        CallResult::Ok(term) => format!("{term}"),
        other => panic!("OTP node/0 call failed: {other:?}"),
    };

    let dir = std::env::temp_dir().join(format!("arinsal-native-node-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let beam_path = dir.join(format!("{MODULE}.beam"));
    std::fs::write(&beam_path, beam).unwrap();
    let run_child = |native: bool| {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "native_node_instruction_matches_interpreter_and_otp",
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
            "{} child failed ({:?}): stdout={} stderr={}",
            if native { "native" } else { "interpreter" },
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        if native {
            assert!(
                String::from_utf8_lossy(&output.stderr).contains("modules=1"),
                "BeamAsm must compile the tested module: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .find_map(|line| line.strip_prefix("RESULT:"))
            .expect("child prints a result")
            .to_owned()
    };
    let interpreted = run_child(false);
    let native = run_child(true);
    assert_eq!(interpreted, expected, "interpreter result must match OTP");
    assert_eq!(
        native, interpreted,
        "BeamAsm node result must match interpreter"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
#[cfg(target_arch = "aarch64")]
fn native_build_stacktrace_matches_interpreter_and_otp() {
    const CHILD: &str = "ARINSAL_NATIVE_BUILD_STACKTRACE_CHILD";
    const MODULE: &str = "native_build_stacktrace_test";
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
    let beam = reference
        .compile_named(
            MODULE,
            "-module(native_build_stacktrace_test).\n-export([run/0]).\nrun() ->\n    _ = ok,\n    try binary_to_integer(<<\"boom\">>)\n    catch Class:Reason:Stack ->\n        Frames = [{M,F,A,case M of erlang -> []; _ -> Info end} || {M,F,A,Info} <- lists:sublist(Stack, 2)],\n        {Class,Reason,Frames}\n    end.\n",
            &[],
        )
        .unwrap();
    reference.load(MODULE, &beam).unwrap();
    let expected = match reference.call(MODULE, "run", &[]) {
        CallResult::Ok(term) => format!("{term}"),
        other => panic!("OTP stacktrace call failed: {other:?}"),
    };

    let dir = std::env::temp_dir().join(format!(
        "arinsal-native-build-stacktrace-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let beam_path = dir.join(format!("{MODULE}.beam"));
    std::fs::write(&beam_path, beam).unwrap();
    let run_child = |native: bool| {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "native_build_stacktrace_matches_interpreter_and_otp",
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
            "{} child failed ({:?}): stdout={} stderr={}",
            if native { "native" } else { "interpreter" },
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        if native {
            assert!(
                String::from_utf8_lossy(&output.stderr).contains("modules=1"),
                "BeamAsm must compile the tested module: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .find_map(|line| line.strip_prefix("RESULT:"))
            .expect("child prints a result")
            .to_owned()
    };
    let interpreted = run_child(false);
    let native = run_child(true);
    assert_eq!(
        native, interpreted,
        "BeamAsm stacktrace must match interpreter"
    );
    assert_eq!(interpreted, expected, "interpreter result must match OTP");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
#[cfg(target_arch = "aarch64")]
fn native_spawn_entry_catch_preserves_arguments_after_throw() {
    const CHILD: &str = "ARINSAL_NATIVE_SPAWN_CATCH_CHILD";
    const MODULE: &str = "native_spawn_entry_catch_test";
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
    let source = r#"-module(native_spawn_entry_catch_test).
        -export([run/0, spawned_entry/2]).
        run() ->
            Starter = self(),
            Parent = make_ref(),
            Child = spawn(native_spawn_entry_catch_test, spawned_entry, [Starter, Parent]),
            receive {caught, Child, Parent, spawn_entry_throw} -> ok
            after 5000 -> timeout
            end.
        spawned_entry(Starter, Parent) ->
            Caught = catch first_call(),
            Starter ! {caught, self(), Parent, Caught}.
        first_call() -> second_call().
        second_call() -> throw(spawn_entry_throw).
    "#;
    let beam = reference.compile_named(MODULE, source, &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();
    let expected = match reference.call(MODULE, "run", &[]) {
        CallResult::Ok(term) => format!("{term}"),
        other => panic!("OTP spawned-entry catch failed: {other:?}"),
    };

    let dir =
        std::env::temp_dir().join(format!("arinsal-native-spawn-catch-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let beam_path = dir.join(format!("{MODULE}.beam"));
    std::fs::write(&beam_path, beam).unwrap();
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "native_spawn_entry_catch_preserves_arguments_after_throw",
            "--nocapture",
        ])
        .env(CHILD, &beam_path)
        .env("ARINSAL_BEAMASM", "1")
        .env("ARINSAL_BEAMASM_MODULES", MODULE)
        .env("ARINSAL_BEAMASM_STATS", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "native spawned-entry catch failed ({:?}): stdout={} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("modules=1"),
        "BeamAsm must compile the tested module: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let actual = stdout
        .lines()
        .find_map(|line| line.strip_prefix("RESULT:"))
        .expect("child prints the caught result")
        .to_owned();
    assert_eq!(actual, expected);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
#[cfg(target_arch = "aarch64")]
fn native_body_recursion_grows_a_minimum_heap_before_stack_collision() {
    const CHILD: &str = "ARINSAL_NATIVE_GC_RECURSION_CHILD";
    const MODULE: &str = "native_gc_recursion_test";
    if let Some(beam_path) = std::env::var_os(CHILD) {
        let beam = std::fs::read(beam_path).unwrap();
        let mut vm = Vm::new([]);
        vm.load_bytes(&beam).unwrap();
        let actual = vm
            .eval_scheduled(MODULE, "run", &[Term::small(10_000).unwrap()], 1, None)
            .unwrap();
        println!("RESULT:{}", actual.text);
        return;
    }

    let _serial = NATIVE_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let reference = RefErl::start().expect("OTP 29.1.1 is required for this test");
    let source = r#"-module(native_gc_recursion_test).
        -export([run/1, child/2]).
        run(N) ->
            Parent = self(),
            Child = spawn_opt(native_gc_recursion_test, child, [Parent, N], [{min_heap_size, 233}]),
            receive {Child, List} -> List after 30000 -> timeout end.
        child(Parent, N) -> Parent ! {self(), recurse(N)}.
        recurse(0) -> [];
        recurse(N) -> [N | recurse(N - 1)].
    "#;
    let beam = reference.compile_named(MODULE, source, &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();
    let expected = match reference.call(MODULE, "run", &[OwnedTerm::Int(10_000)]) {
        CallResult::Ok(term) => format!("{term}"),
        other => panic!("OTP minimum-heap recursion failed: {other:?}"),
    };

    let dir = std::env::temp_dir().join(format!(
        "arinsal-native-gc-recursion-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let beam_path = dir.join(format!("{MODULE}.beam"));
    std::fs::write(&beam_path, beam).unwrap();
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "native_body_recursion_grows_a_minimum_heap_before_stack_collision",
            "--nocapture",
        ])
        .env(CHILD, &beam_path)
        .env("ARINSAL_BEAMASM", "1")
        .env("ARINSAL_BEAMASM_MODULES", MODULE)
        .env("ARINSAL_BEAMASM_VALIDATE", "1")
        .env("ARINSAL_GC_TRACE", "1")
        .env("ARINSAL_BEAMASM_STATS", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "native minimum-heap recursion failed ({:?}): stdout={} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("modules=1"),
        "module was not compiled: {stderr}"
    );
    assert!(
        stderr.contains("GC minor") || stderr.contains("GC major"),
        "minimum-heap recursion must exercise the moving collector: {stderr}"
    );
    assert!(
        stderr
            .split_whitespace()
            .find_map(|field| field.strip_prefix("native_functions="))
            .and_then(|count| count.parse::<usize>().ok())
            .is_some_and(|count| count >= 3),
        "run/1, child/2 and recurse/1 must compile natively: {stderr}"
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let actual = stdout
        .lines()
        .find_map(|line| line.strip_prefix("RESULT:"))
        .expect("child prints the native result");
    assert_eq!(actual, expected);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
#[cfg(target_arch = "aarch64")]
fn native_large_bif_result_keeps_the_heap_redzone_before_a_fun_call() {
    const CHILD: &str = "ARINSAL_NATIVE_HEAP_REDZONE_CHILD";
    const MODULE: &str = "native_heap_redzone_test";
    if let Some(beam_path) = std::env::var_os(CHILD) {
        let beam = std::fs::read(beam_path).unwrap();
        let mut vm = Vm::new([]);
        vm.load_bytes(&beam).unwrap();
        let actual = vm.eval_scheduled(MODULE, "run", &[], 0, None).unwrap();
        println!("RESULT:{}", actual.text);
        return;
    }

    let _serial = NATIVE_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let reference = RefErl::start().expect("OTP 29.1.1 is required for this test");
    let source = r#"-module(native_heap_redzone_test).
        -export([run/0]).
        run() ->
            Large = erlang:binary_to_list(<<0:16000>>),
            Fun = fun() -> {length(Large), hd(Large), lists:last(Large)} end,
            Fun().
    "#;
    let beam = reference.compile_named(MODULE, source, &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();
    let expected = match reference.call(MODULE, "run", &[]) {
        CallResult::Ok(term) => format!("{term}"),
        other => panic!("OTP large-BIF heap-redzone case failed: {other:?}"),
    };

    let dir = std::env::temp_dir().join(format!(
        "arinsal-native-heap-redzone-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let beam_path = dir.join(format!("{MODULE}.beam"));
    std::fs::write(&beam_path, beam).unwrap();
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "native_large_bif_result_keeps_the_heap_redzone_before_a_fun_call",
            "--nocapture",
        ])
        .env(CHILD, &beam_path)
        .env("ARINSAL_BEAMASM", "1")
        .env("ARINSAL_BEAMASM_MODULES", MODULE)
        .env("ARINSAL_BEAMASM_VALIDATE", "1")
        .env("ARINSAL_BEAMASM_STATS", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "native large-BIF heap-redzone case failed ({:?}): stdout={} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("modules=1"),
        "native heap-redzone module was not compiled: {stderr}"
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let actual = stdout
        .lines()
        .find_map(|line| line.strip_prefix("RESULT:"))
        .expect("child prints the large-BIF result");
    assert_eq!(actual, expected);
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
        line_table: Vec::new(),
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
        e.str_uoff(Gpr::x(0), Gpr::x(19), 16_408)?;
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
