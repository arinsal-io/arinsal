use arinsal_difftest::{CallOptions, CallResult, RefErl};
use arinsal_vm::Vm;
use std::collections::HashMap;
use std::process::Command;
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
    similar_asserts::assert_eq!(expected, CallResult::Ok(actual.term));
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
    similar_asserts::assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "true|#{line_breakpoint => false}"
    );

    let args = ["erl", "+D", "+Dibpl", "false"];
    let launch = arinsal_args::parse(&args, &HashMap::new()).expect("parse debugger flags");
    assert!(launch.emulator.debugger_support);
    similar_asserts::assert_eq!(launch.emulator.debugger_line_breakpoints, Some(false));
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
    similar_asserts::assert_eq!(expected, CallResult::Ok(actual.term));
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
    similar_asserts::assert_eq!(expected, CallResult::Ok(actual.term));
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
    similar_asserts::assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "#{line_breakpoint => true}"
    );
}

#[test]
fn erl_debugger_bifs_match_otp_with_debugger_enabled() {
    let _serial = serial_test();
    let Ok(reference) = RefErl::start_with_erl_args(&["+D"]) else {
        eprintln!("erl unavailable; skipping debugger BIF differential test");
        return;
    };
    let module = "erl_debugger_bifs_fixture";
    let source = r#"-module(erl_debugger_bifs_fixture).
-export([run/0, target/1]).
run() ->
    Supported = erl_debugger:supported(),
    Initial = erl_debugger:instrumentations(),
    ok = erl_debugger:toggle_instrumentations(#{line_breakpoint => false}),
    Disabled = erl_debugger:instrumentations(),
    ok = erl_debugger:toggle_instrumentations(#{}),
    EmptyToggle = erl_debugger:instrumentations(),
    ok = erl_debugger:toggle_instrumentations(#{line_breakpoint => true}),
    Enabled = erl_debugger:instrumentations(),
    Where0 = erl_debugger:whereis(),
    Dead = spawn(fun() -> ok end),
    Monitor = erlang:monitor(process, Dead),
    receive {'DOWN', Monitor, process, Dead, _} -> ok end,
    {ok, DeadSession} = erl_debugger:register(Dead),
    DeadRegistration = {is_integer(DeadSession), erl_debugger:whereis()},
    {ok, Session} = erl_debugger:register(self()),
    Registration = {is_integer(Session), erl_debugger:whereis() =:= self()},
    Duplicate = erl_debugger:register(self()),
    WrongSession = capture(fun() -> erl_debugger:unregister(self(), Session bxor 1) end),
    Other = spawn(fun() -> receive stop -> ok end end),
    DuplicateOther = erl_debugger:register(Other),
    WrongPidNegativeSession = erl_debugger:unregister(Other, -1),
    Running = {erl_debugger:stack_frames(Other, 10),
               erl_debugger:peek_stack_frame_slot(Other, 0, 0, 10),
               erl_debugger:xregs_count(Other),
               erl_debugger:peek_xreg(Other, 0, 10)},
    Other ! stop,
    ok = erl_debugger:unregister(self(), Session),
    Where1 = erl_debugger:whereis(),
    {ok, AllBefore} = erl_debugger:breakpoints(erl_debugger_bifs_fixture),
    {ok, TargetBefore} = erl_debugger:breakpoints(erl_debugger_bifs_fixture, target, 1),
    [Line | _] = maps:keys(TargetBefore),
    WideSetResult = erl_debugger:breakpoint(
        erl_debugger_bifs_fixture, Line + 4294967296, true),
    {ok, AllEnabled} = erl_debugger:breakpoints(erl_debugger_bifs_fixture),
    {ok, TargetEnabled} = erl_debugger:breakpoints(erl_debugger_bifs_fixture, target, 1),
    ClearResult = erl_debugger:breakpoint(erl_debugger_bifs_fixture, Line, false),
    {ok, TargetCleared} = erl_debugger:breakpoints(erl_debugger_bifs_fixture, target, 1),
    Badargs = [
        capture(fun() -> erl_debugger:toggle_instrumentations([]) end),
        capture(fun() -> erl_debugger:toggle_instrumentations(#{line_breakpoint => faux}) end),
        capture(fun() -> erl_debugger:toggle_instrumentations(#{unknown => true}) end),
        capture(fun() -> erl_debugger:toggle_instrumentations(#{line_breakpoint => false, unknown => true}) end),
        capture(fun() -> erl_debugger:register(not_a_pid) end),
        capture(fun() -> erl_debugger:unregister(not_a_pid, 0) end),
        capture(fun() -> erl_debugger:unregister(self(), 1.0) end),
        capture(fun() -> erl_debugger:unregister(self(), -1) end),
        capture(fun() -> erl_debugger:breakpoint(not_an_atom, 1, true) end),
        capture(fun() -> erl_debugger:breakpoint(erl_debugger_bifs_fixture, line, true) end),
        capture(fun() -> erl_debugger:breakpoint(erl_debugger_bifs_fixture, 1, yes) end),
        capture(fun() -> erl_debugger:breakpoint(erl_debugger_bifs_fixture, 2147483648, true) end),
        capture(fun() -> erl_debugger:breakpoints(42) end),
        capture(fun() -> erl_debugger:breakpoints(erl_debugger_bifs_fixture, 42, 1) end),
        capture(fun() -> erl_debugger:breakpoints(erl_debugger_bifs_fixture, target, 1.0) end),
        capture(fun() -> erl_debugger:breakpoints(erl_debugger_missing_fixture, 42, 1) end),
        capture(fun() -> erl_debugger:breakpoints(erl_debugger_missing_fixture, target, 1.0) end),
        capture(fun() -> erl_debugger:stack_frames(not_a_pid, 1) end),
        capture(fun() -> erl_debugger:stack_frames(self(), 1) end),
        capture(fun() -> erl_debugger:stack_frames(Other, -1) end),
        capture(fun() -> erl_debugger:stack_frames(Other, 1.0) end),
        capture(fun() -> erl_debugger:stack_frames(Other, 2147483648) end),
        capture(fun() -> erl_debugger:peek_stack_frame_slot(not_a_pid, 0, 0, 10) end),
        capture(fun() -> erl_debugger:peek_stack_frame_slot(self(), 0, 0, 10) end),
        capture(fun() -> erl_debugger:peek_stack_frame_slot(Other, -1, 0, 10) end),
        capture(fun() -> erl_debugger:peek_stack_frame_slot(Other, 2147483648, 0, 10) end),
        capture(fun() -> erl_debugger:peek_stack_frame_slot(Other, 0, -1, 10) end),
        capture(fun() -> erl_debugger:peek_stack_frame_slot(Other, 0, 0, -1) end),
        capture(fun() -> erl_debugger:xregs_count(not_a_pid) end),
        capture(fun() -> erl_debugger:xregs_count(self()) end),
        capture(fun() -> erl_debugger:peek_xreg(not_a_pid, 0, 10) end),
        capture(fun() -> erl_debugger:peek_xreg(self(), 0, 10) end),
        capture(fun() -> erl_debugger:peek_xreg(Other, -1, 10) end),
        capture(fun() -> erl_debugger:peek_xreg(Other, 2147483648, 10) end),
        capture(fun() -> erl_debugger:peek_xreg(Other, 0, -1) end)
    ],
    #{supported => Supported, initial => Initial, disabled => Disabled,
      empty_toggle => EmptyToggle, enabled => Enabled, where0 => Where0,
      dead_registration => DeadRegistration, registration => Registration,
      duplicate => Duplicate, wrong_session => WrongSession,
      duplicate_other => DuplicateOther,
      wrong_pid_negative_session => WrongPidNegativeSession, running => Running,
      where1 => Where1, breakpoints_before => AllBefore,
      target_before => TargetBefore, wide_set_result => WideSetResult,
      breakpoints_enabled => AllEnabled, target_enabled => TargetEnabled,
      clear_result => ClearResult, target_cleared => TargetCleared,
      final_instrumentations => erl_debugger:instrumentations(),
      missing_module => erl_debugger:breakpoints(erl_debugger_missing_fixture),
      badargs => Badargs}.
target(Value) -> Value + 1.
capture(Fun) ->
    try Fun() of Value -> {returned, Value}
    catch error:badarg -> badarg
    end.
"#;
    let beam = reference
        .compile_named(
            module,
            source,
            &[arinsal_etf::OwnedTerm::Atom("beam_debug_info".into())],
        )
        .expect("compile debugger BIF fixture");
    reference.load(module, &beam).expect("load OTP fixture");
    let mut expected = reference
        .call_opts(
            module,
            "run",
            &[],
            &CallOptions {
                timeout_ms: Some(30_000),
                ..CallOptions::default()
            },
        )
        .result;
    assert!(
        matches!(&expected, CallResult::Ok(_)),
        "OTP fixture: {expected:?}"
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
    vm.load_bytes(&beam).expect("load debugger BIF fixture");
    let actual = vm
        .eval_scheduled(module, "run", &[], 8, None)
        .unwrap_or_else(|error| panic!("run debugger BIF fixture: {error}"));
    let _reset = Vm::new_with_debugger_flags(Vec::<std::path::PathBuf>::new(), false, true);
    let mut actual = CallResult::Ok(actual.term);
    arinsal_difftest::compare(&expected, &actual, arinsal_difftest::CompareMode::Exact)
        .unwrap_or_else(|mismatch| panic!("debugger BIF semantic mismatch: {mismatch}"));
    canonicalize_call_result(&mut expected);
    canonicalize_call_result(&mut actual);
    similar_asserts::assert_eq!(expected, actual);
}

fn canonicalize_call_result(result: &mut CallResult) {
    if let CallResult::Ok(term) = result {
        canonicalize_maps(term);
    }
}

// Erlang maps compare without regard to iteration order, while OwnedTerm preserves ETF order.
fn canonicalize_maps(term: &mut arinsal_etf::OwnedTerm) {
    use arinsal_etf::OwnedTerm;
    match term {
        OwnedTerm::Tuple(elements) => elements.iter_mut().for_each(canonicalize_maps),
        OwnedTerm::List { elems, tail } => {
            elems.iter_mut().for_each(canonicalize_maps);
            canonicalize_maps(tail);
        }
        OwnedTerm::Map(entries) => {
            for (key, value) in entries.iter_mut() {
                canonicalize_maps(key);
                canonicalize_maps(value);
            }
            entries.sort_by_key(|(key, _)| format!("{key:?}"));
        }
        _ => {}
    }
}

#[test]
fn erl_debugger_line_hit_inspection_and_resume_match_otp() {
    let _serial = serial_test();
    let Ok(reference) = RefErl::start_with_erl_args(&["+D"]) else {
        eprintln!("erl unavailable; skipping debugger hit differential test");
        return;
    };
    let source = r#"-module(erl_debugger_active_fixture).
-export([run/0, hit/2]).
run() ->
    ok = erl_debugger:toggle_instrumentations(#{line_breakpoint => true}),
    {ok, Session} = erl_debugger:register(self()),
    {ok, HitBreakpoints} = erl_debugger:breakpoints(erl_debugger_active_fixture, hit, 2),
    [Line | _] = maps:keys(HitBreakpoints),
    ok = erl_debugger:breakpoint(erl_debugger_active_fixture, Line, true),
    Parent = self(),
    Worker = spawn(fun() -> hit(Parent, 42) end),
    receive
        {debugger_event, Session, {breakpoint, Worker, {erl_debugger_active_fixture, hit, 2}, Line, Resume}} ->
            true = erlang:suspend_process(Worker),
            Frames = erl_debugger:stack_frames(Worker, 10),
            XCount = erl_debugger:xregs_count(Worker),
            X0 = erl_debugger:peek_xreg(Worker, 0, 10),
            X0Wide = erl_debugger:peek_xreg(Worker, 4294967296, 10),
            X0WideMax = erl_debugger:peek_xreg(Worker, 0, 4294967296),
            {FrameNo, '<breakpoint>', _} = hd([F || F = {_, '<breakpoint>', _} <- Frames]),
            Slot = erl_debugger:peek_stack_frame_slot(Worker, FrameNo, 0, 10),
            SlotWide = erl_debugger:peek_stack_frame_slot(
                Worker, FrameNo + 4294967296, 4294967296, 10),
            SlotWideMax = erl_debugger:peek_stack_frame_slot(
                Worker, FrameNo, 0, 4294967296),
            Resume(),
            true = erlang:resume_process(Worker),
            {XCount, compact(X0), compact(X0Wide), compact(X0WideMax),
             compact(Slot), compact(SlotWide), compact(SlotWideMax), compact_frames(Frames)}
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
    reference
        .load("erl_debugger_active_fixture", &beam)
        .expect("load OTP debugger hit fixture");
    let expected = reference
        .call_opts(
            "erl_debugger_active_fixture",
            "run",
            &[],
            &CallOptions {
                timeout_ms: Some(30_000),
                ..CallOptions::default()
            },
        )
        .result;
    let CallResult::Ok(expected) = expected else {
        panic!("OTP debugger fixture failed: {expected:?}");
    };
    assert!(expected != arinsal_etf::OwnedTerm::Atom("no_debugger_event".into()));

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
    assert!(actual.term != arinsal_etf::OwnedTerm::Atom("no_debugger_event".into()));
    similar_asserts::assert_eq!(expected, actual.term);
}

/// Runs `module:run/0` of `source` (compiled with `+beam_debug_info`) on OTP with `+D` and
/// on Arinsal, and asserts both return the same term.
fn assert_debugger_fixture_matches_otp(module: &str, source: &str) {
    let Ok(reference) = RefErl::start_with_erl_args(&["+D"]) else {
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
    reference
        .load(module, &beam)
        .expect("load OTP debugger fixture");
    let expected = reference
        .call_opts(
            module,
            "run",
            &[],
            &CallOptions {
                timeout_ms: Some(30_000),
                ..CallOptions::default()
            },
        )
        .result;
    let CallResult::Ok(expected) = expected else {
        panic!("OTP debugger fixture failed: {expected:?}");
    };

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
    similar_asserts::assert_eq!(expected, actual.term);
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
