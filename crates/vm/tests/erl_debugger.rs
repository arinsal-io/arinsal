use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;
use std::collections::HashMap;
use std::process::{Command, Stdio};
use std::sync::Mutex;

static TEST_LOCK: Mutex<()> = Mutex::new(());

fn serial_test() -> std::sync::MutexGuard<'static, ()> {
    TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[test]
fn erl_debugger_supported_matches_otp_without_debug_flag() {
    let _serial = serial_test();
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping debugger support differential test");
        return;
    };
    let beam = reference
        .compile_named(
            "erl_debugger_supported_fixture",
            "-module(erl_debugger_supported_fixture). -export([run/0]). run() -> erl_debugger:supported().",
            &[],
        )
        .expect("compile debugger support fixture");
    reference
        .load("erl_debugger_supported_fixture", &beam)
        .expect("load OTP fixture");
    let expected = reference.call("erl_debugger_supported_fixture", "run", &[]);
    let mut vm = Vm::new([]);
    let actual = vm
        .load_bytes(&beam)
        .and_then(|_| vm.eval_scheduled("erl_debugger_supported_fixture", "run", &[], 1, None))
        .unwrap_or_else(|error| panic!("erl_debugger:supported/0: {error}"));
    assert_eq!(expected, CallResult::Ok(actual.term));
}

#[test]
fn erl_debugger_plus_d_enables_otp_support() {
    let _serial = serial_test();
    let output = Command::new("timeout")
        .args([
            "30",
            "erl",
            "+D",
            "+Dibpl",
            "false",
            "-noshell",
            "-eval",
            "io:format(\"~p|~p\", [erl_debugger:supported(), erl_debugger:instrumentations()]), halt().",
        ])
        .output()
        .expect("run one-shot OTP debugger flag probe");
    assert!(
        output.status.success(),
        "erl failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "true|#{line_breakpoint => false}"
    );

    let args = ["erl", "+D", "+Dibpl", "false"];
    let launch = arinsal_args::parse(&args, &HashMap::new()).expect("parse debugger flags");
    assert!(launch.emulator.debugger_support);
    assert_eq!(launch.emulator.debugger_line_breakpoints, Some(false));
}

#[test]
fn erl_debugger_internal_state_toggle_enables_support() {
    let _serial = serial_test();
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping debugger internal-state differential test");
        return;
    };
    let beam = reference
        .compile_named(
            "erl_debugger_internal_state_fixture",
            "-module(erl_debugger_internal_state_fixture). -export([run/0]). run() -> false = erts_debug:set_internal_state(available_internal_state, true), ok = erts_debug:set_internal_state(debugger_support, true), Supported = erl_debugger:supported(), Internal = erts_debug:get_internal_state(debugger_support), true = erts_debug:set_internal_state(available_internal_state, false), {Internal, Supported}.",
            &[],
        )
        .expect("compile debugger internal-state fixture");
    reference
        .load("erl_debugger_internal_state_fixture", &beam)
        .expect("load OTP fixture");
    let expected = reference.call("erl_debugger_internal_state_fixture", "run", &[]);
    let mut vm = Vm::new([]);
    let actual = vm
        .load_bytes(&beam)
        .and_then(|_| vm.eval_scheduled("erl_debugger_internal_state_fixture", "run", &[], 1, None))
        .unwrap_or_else(|error| panic!("debugger internal-state toggle: {error}"));
    assert_eq!(expected, CallResult::Ok(actual.term));
    let _reset = Vm::new_with_debugger_flags(Vec::<std::path::PathBuf>::new(), false, true);
}

#[test]
fn erl_debugger_line_metadata_loads_from_beam_debug_info() {
    let _serial = serial_test();
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping debugger line metadata differential test");
        return;
    };
    let source = "-module(erl_debugger_line_fixture).\n-export([run/1]).\nrun(Value) ->\n    Copy = Value,\n    Copy.\n";
    let beam = reference
        .compile_named(
            "erl_debugger_line_fixture",
            source,
            &[arinsal_etf::OwnedTerm::Atom("beam_debug_info".into())],
        )
        .expect("compile OTP debug-line fixture");
    let parsed = arinsal_beam::parse(&beam).expect("parse compiled BEAM");
    let module = arinsal_loader::load_with_instrumentations(
        &parsed,
        arinsal_loader::CoverageMode::None,
        true,
    )
    .expect("load debug-line fixture with instrumentation");
    assert!(module.line_breakpoints_supported);
    assert!(
        module
            .debug_line_points
            .iter()
            .any(|(_, line, _)| *line == 4)
    );
    reference
        .load("erl_debugger_line_fixture", &beam)
        .expect("load OTP fixture");
    let expected = reference.call(
        "erl_debugger_line_fixture",
        "run",
        &[arinsal_etf::OwnedTerm::Atom("sample".into())],
    );
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load VM fixture");
    let actual = vm
        .eval_scheduled(
            "erl_debugger_line_fixture",
            "run",
            &[arinsal_term::Term::atom(
                arinsal_term::global_atoms().intern("sample").unwrap(),
            )],
            1,
            None,
        )
        .expect("run VM fixture");
    assert_eq!(expected, CallResult::Ok(actual.term));
}

#[test]
fn erl_debugger_default_instrumentation_toggle_accepts_empty_map_in_otp() {
    let _serial = serial_test();
    let output = Command::new("timeout")
        .args([
            "30",
            "erl",
            "+D",
            "-noshell",
            "-eval",
            "ok = erl_debugger:toggle_instrumentations(#{}), io:format(\"~p\", [erl_debugger:instrumentations()]), halt().",
        ])
        .output()
        .expect("run one-shot OTP debugger instrumentation probe");
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "#{line_breakpoint => true}"
    );
}

#[test]
fn erl_debugger_line_hit_inspection_and_resume_match_otp() {
    let _serial = serial_test();
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping debugger hit differential test");
        return;
    };
    let source = r#"-module(erl_debugger_active_fixture).
-export([run/0, hit/2]).
run() ->
    ok = erl_debugger:toggle_instrumentations(#{line_breakpoint => true}),
    {ok, Session} = erl_debugger:register(self()),
    ok = erl_debugger:breakpoint(erl_debugger_active_fixture, 23, true),
    Parent = self(),
    Worker = spawn(fun() -> hit(Parent, 42) end),
    receive
        {debugger_event, Session, {breakpoint, Worker, {erl_debugger_active_fixture, hit, 2}, 23, Resume}} ->
            true = erlang:suspend_process(Worker),
            Frames = erl_debugger:stack_frames(Worker, 10),
            XCount = erl_debugger:xregs_count(Worker),
            X0 = erl_debugger:peek_xreg(Worker, 0, 10),
            {FrameNo, '<breakpoint>', _} = hd([F || F = {_, '<breakpoint>', _} <- Frames]),
            Slot = erl_debugger:peek_stack_frame_slot(Worker, FrameNo, 0, 10),
            Resume(),
            true = erlang:resume_process(Worker),
            {XCount, compact(X0), compact(Slot), compact_frames(Frames)}
    after 5000 -> no_debugger_event
    end.
hit(Parent, Value) ->
    Parent ! {hit, Value},
    Value.
compact({value, Value}) when is_pid(Value) -> {value, pid};
compact({value, Value}) when is_reference(Value) -> {value, ref};
compact(Value) -> Value.
compact_frames(Frames) ->
    [{No, compact_fun(Fun), [compact(Slot) || Slot <- Slots]}
     || {No, Fun, #{slots := Slots}} <- Frames].
compact_fun(#{function := MFA, line := Line}) -> {MFA, Line};
compact_fun(Fun) -> Fun.
"#;
    let beam = reference
        .compile_named(
            "erl_debugger_active_fixture",
            source,
            &[arinsal_etf::OwnedTerm::Atom("beam_debug_info".into())],
        )
        .expect("compile debugger hit fixture");
    let reference_dir = std::env::temp_dir().join(format!(
        "erl_debugger_{}_{}",
        std::process::id(),
        std::thread::current().name().unwrap_or("test")
    ));
    std::fs::create_dir_all(&reference_dir).expect("create temporary BEAM directory");
    let beam_path = reference_dir.join("erl_debugger_active_fixture.beam");
    std::fs::write(&beam_path, &beam).expect("write temporary BEAM file");
    let result_path = reference_dir.join("result.etf");
    let eval = format!(
        "ok = file:write_file(\"{}\", term_to_binary(erl_debugger_active_fixture:run())), halt().",
        result_path.display()
    );
    let child = Command::new("timeout")
        .args([
            "30",
            "erl",
            "+D",
            "-noshell",
            "-pa",
            reference_dir.to_str().unwrap(),
            "-eval",
            &eval,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start one-shot OTP debugger fixture");
    let output = child
        .wait_with_output()
        .expect("wait for OTP debugger fixture");
    let expected_bytes = if output.status.success() {
        std::fs::read(&result_path).expect("read OTP debugger result")
    } else {
        Vec::new()
    };
    std::fs::remove_file(&beam_path).expect("remove temporary BEAM file");
    if result_path.exists() {
        std::fs::remove_file(&result_path).expect("remove temporary result file");
    }
    std::fs::remove_dir(&reference_dir).expect("remove temporary BEAM directory");
    assert!(
        output.status.success(),
        "OTP debugger fixture failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let expected = arinsal_etf::decode(&expected_bytes).expect("decode OTP debugger result");
    assert_ne!(
        expected,
        arinsal_etf::OwnedTerm::Atom("no_debugger_event".into())
    );

    let preloaded = reference
        .eval("element(2, code:get_object_code(erts_internal))")
        .expect("read OTP's preloaded breakpoint wrapper");
    let arinsal_etf::OwnedTerm::Binary(preloaded) = &preloaded else {
        panic!("OTP erts_internal object code was not a binary");
    };
    let mut vm = Vm::new_with_debugger_flags([], true, true);
    vm.load_bytes(preloaded)
        .expect("load OTP's preloaded breakpoint wrapper");
    vm.load_bytes(&beam).expect("load debugger hit fixture");
    let actual = vm
        .eval_scheduled("erl_debugger_active_fixture", "run", &[], 8, None)
        .unwrap_or_else(|error| panic!("run debugger hit fixture: {error}"));
    let _reset = Vm::new_with_debugger_flags(Vec::<std::path::PathBuf>::new(), false, true);
    assert_ne!(
        actual.term,
        arinsal_etf::OwnedTerm::Atom("no_debugger_event".into())
    );
    assert_eq!(expected, actual.term);
}

/// Runs `module:run/0` of `source` (compiled with `+beam_debug_info`) on OTP with `+D` and
/// on Arinsal, and asserts both return the same term.
fn assert_debugger_fixture_matches_otp(module: &str, source: &str) {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping debugger differential test");
        return;
    };
    let beam = reference
        .compile_named(
            module,
            source,
            &[arinsal_etf::OwnedTerm::Atom("beam_debug_info".into())],
        )
        .expect("compile debugger fixture");
    let dir = std::env::temp_dir().join(format!("erl_debugger_{}_{module}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temporary BEAM directory");
    std::fs::write(dir.join(format!("{module}.beam")), &beam).expect("write BEAM file");
    let result_path = dir.join("result.etf");
    let eval = format!(
        "ok = file:write_file(\"{}\", term_to_binary({module}:run())), halt().",
        result_path.display()
    );
    let output = Command::new("timeout")
        .args([
            "30",
            "erl",
            "+D",
            "-noshell",
            "-pa",
            dir.to_str().unwrap(),
            "-eval",
            &eval,
        ])
        .stdin(Stdio::null())
        .output()
        .expect("run OTP debugger fixture");
    let expected_bytes = std::fs::read(&result_path).unwrap_or_default();
    std::fs::remove_dir_all(&dir).expect("remove temporary directory");
    assert!(
        output.status.success(),
        "OTP debugger fixture failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let expected = arinsal_etf::decode(&expected_bytes).expect("decode OTP result");

    let preloaded = reference
        .eval("element(2, code:get_object_code(erts_internal))")
        .expect("read OTP's preloaded breakpoint wrapper");
    let arinsal_etf::OwnedTerm::Binary(preloaded) = &preloaded else {
        panic!("OTP erts_internal object code was not a binary");
    };
    let mut vm = Vm::new_with_debugger_flags([], true, true);
    vm.load_bytes(preloaded).expect("load breakpoint wrapper");
    vm.load_bytes(&beam).expect("load debugger fixture");
    let actual = vm
        .eval_scheduled(module, "run", &[], 8, None)
        .unwrap_or_else(|error| panic!("run debugger fixture: {error}"));
    let _reset = Vm::new_with_debugger_flags(Vec::<std::path::PathBuf>::new(), false, true);
    assert_eq!(expected, actual.term);
}

/// Every line breakpoint of a function with more live X registers than the register cache
/// holds must hit, resume and restore all arguments in native code (line hits restore through
/// the code emitted after the trampoline).
#[test]
fn erl_debugger_line_hits_restore_many_live_xregs_match_otp() {
    let _serial = serial_test();
    let source = r#"-module(erl_debugger_xregs_fixture).
-export([run/0, many/9]).
run() ->
    ok = erl_debugger:toggle_instrumentations(#{line_breakpoint => true}),
    {ok, Session} = erl_debugger:register(self()),
    ok = erl_debugger:breakpoint(erl_debugger_xregs_fixture, 23, true),
    Parent = self(),
    Worker = spawn(fun() ->
        Parent ! {result, many(3, 1, 2, 3, 4, 5, 6, 7, 8)} end),
    loop(Session, Worker, []).
loop(Session, Worker, Hits) ->
    receive
        {debugger_event, Session, {breakpoint, Worker, MFA, Line, Resume}} ->
            Resume(),
            loop(Session, Worker, [{MFA, Line} | Hits]);
        {result, Result} ->
            {Result, lists:reverse(Hits)}
    after 5000 -> timeout
    end.
many(0, A, B, C, D, E, F, G, H) ->
    A + B + C + D + E + F + G + H;
many(N, A, B, C, D, E, F, G, H) ->
    many(N - 1, A + 1, B, C, D, E, F, G, H + A).
"#;
    assert_debugger_fixture_matches_otp("erl_debugger_xregs_fixture", source);
}
