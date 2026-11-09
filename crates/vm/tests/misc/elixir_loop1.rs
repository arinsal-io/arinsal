use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_term::{VecHeap, from_owned};
use arinsal_vm::Vm;

#[test]
fn pid_to_list_matches_otp_29() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping pid_to_list differential test");
        return;
    };
    let source = "-module(elixir_loop1_pid). -export([render/1]).
        render(X) -> try erlang:pid_to_list(X) catch error:badarg -> badarg end.";
    let beam = reference
        .compile_named("elixir_loop1_pid", source, &[])
        .unwrap();
    reference.load("elixir_loop1_pid", &beam).unwrap();
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    for input in [
        OwnedTerm::Pid {
            node: "nonode@nohost".into(),
            id: 42,
            serial: 17,
            creation: 0,
        },
        OwnedTerm::Pid {
            node: "nonode@nohost".into(),
            id: 0,
            serial: 0,
            creation: 0,
        },
        OwnedTerm::Int(1),
    ] {
        let expected = reference.call("elixir_loop1_pid", "render", std::slice::from_ref(&input));
        let mut heap = VecHeap::new();
        let arg = from_owned(&input, &mut heap).unwrap();
        let actual = vm
            .eval_scheduled("elixir_loop1_pid", "render", &[arg], 1, Some(79))
            .unwrap();
        assert_eq!(expected, CallResult::Ok(actual.term), "{input:?}");
    }
}

#[test]
fn hibernate_zero_waits_and_resumes_at_the_call_site() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping hibernate/0 differential test");
        return;
    };
    let source = "-module(elixir_loop1_hibernate). -export([run/0]).
        run() ->
            Parent = self(),
            Child = spawn(fun() -> Parent ! ready,
                                  ok = erlang:hibernate(),
                                  Parent ! awake end),
            receive ready -> ok end,
            Premature = receive awake -> true after 0 -> false end,
            Child ! wake,
            Result = receive awake -> resumed after 1000 -> timeout end,
            {Premature, Result}.";
    let beam = reference
        .compile_named("elixir_loop1_hibernate", source, &[])
        .unwrap();
    reference.load("elixir_loop1_hibernate", &beam).unwrap();
    let expected = reference.call("elixir_loop1_hibernate", "run", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("elixir_loop1_hibernate", "run", &[], 2, Some(83))
        .unwrap();
    assert_eq!(expected, CallResult::Ok(actual.term));
}

#[test]
fn fun_info_mfa_matches_otp_29() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping fun_info_mfa differential test");
        return;
    };
    let source = "-module(elixir_loop1_fun). -export([run/0,dynamic/2]).
        run() ->
            {erlang:fun_info_mfa(fun run/0),
             erlang:fun_info_mfa(fun(X) -> X end),
             try erlang:fun_info_mfa(1) catch error:badarg -> badarg end}.
        dynamic(M,F) -> apply(M,F,[fun run/0]).";
    let beam = reference
        .compile_named("elixir_loop1_fun", source, &[])
        .unwrap();
    reference.load("elixir_loop1_fun", &beam).unwrap();
    let expected = reference.call("elixir_loop1_fun", "run", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("elixir_loop1_fun", "run", &[], 1, Some(89))
        .unwrap();
    assert_eq!(expected, CallResult::Ok(actual.term));
    let args = [
        OwnedTerm::Atom("erlang".into()),
        OwnedTerm::Atom("fun_info_mfa".into()),
    ];
    let expected = reference.call("elixir_loop1_fun", "dynamic", &args);
    let mut heap = VecHeap::new();
    let terms: Vec<_> = args
        .iter()
        .map(|arg| from_owned(arg, &mut heap).unwrap())
        .collect();
    let actual = vm
        .eval_scheduled("elixir_loop1_fun", "dynamic", &terms, 1, Some(91))
        .unwrap();
    assert_eq!(expected, CallResult::Ok(actual.term));
}

#[test]
fn dynamic_apply_of_re_import_matches_otp_29() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping dynamic re:import differential test");
        return;
    };
    let source = "-module(elixir_loop1_re). -export([run/2]).
        run(M,F) ->
            {ok, Exported} = re:compile(<<\"a\">>, [export]),
            Pattern = apply(M,F,[Exported]),
            re:run(<<\"banana\">>, Pattern, [global,{capture,none}]).";
    let beam = reference
        .compile_named("elixir_loop1_re", source, &[])
        .unwrap();
    reference.load("elixir_loop1_re", &beam).unwrap();
    let args = [
        OwnedTerm::Atom("re".into()),
        OwnedTerm::Atom("import".into()),
    ];
    let expected = reference.call("elixir_loop1_re", "run", &args);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let mut heap = VecHeap::new();
    let terms: Vec<_> = args
        .iter()
        .map(|arg| from_owned(arg, &mut heap).unwrap())
        .collect();
    let actual = vm
        .eval_scheduled("elixir_loop1_re", "run", &terms, 1, Some(97))
        .unwrap();
    assert_eq!(expected, CallResult::Ok(actual.term));
}
