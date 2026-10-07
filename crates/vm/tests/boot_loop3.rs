use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::{EncodeOptions, OwnedTerm, decode, encode};
use arinsal_term::{Term, global_atoms};
use arinsal_vm::Vm;

#[test]
fn full_width_integer_operands_match_erts() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping integer operand differential test");
        return;
    };
    let source = r#"-module(boot_loop3_integer). -export([run/0]).
        run() -> [probe(X) || X <-
            [36028797018963968, -36028797018963968,
             72057594037927936, -72057594037927936,
             144115188075855872, -144115188075855872,
             288230376151711743, -288230376151711744,
             576460752303423488, -576460752303423488,
             1208925819614629174706177, -1208925819614629174706177]].
        probe(X) ->
            {X, X + 288230376151711743,
             X band 288230376151711743,
             X =:= 288230376151711743,
             X < 576460752303423488,
             case X of
                 36028797018963968 -> small_positive;
                 -288230376151711744 -> small_negative;
                 576460752303423488 -> big_positive;
                 -1208925819614629174706177 -> big_negative;
                 _ -> other
             end,
             select(X),
             {36028797018963968, [288230376151711743,
                                   576460752303423488,
                                   -1208925819614629174706177]}}.
        select(36028797018963968) -> one;
        select(-36028797018963968) -> two;
        select(288230376151711743) -> three;
        select(576460752303423488) -> four;
        select(-1208925819614629174706177) -> five;
        select(_) -> other.
    "#;
    let beam = reference
        .compile_named("boot_loop3_integer", source, &[])
        .unwrap();
    reference.load("boot_loop3_integer", &beam).unwrap();
    let expected = reference.call("boot_loop3_integer", "run", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("boot_loop3_integer", "run", &[], 1, Some(43))
        .unwrap();
    let canonical = decode(&encode(&actual.term, EncodeOptions::default())).unwrap();
    assert_eq!(expected, CallResult::Ok(canonical));
}

#[test]
fn rand_seed_and_uniform_match_erts_for_each_algorithm() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping rand differential test");
        return;
    };
    let source = r#"-module(boot_loop3_rand). -export([sample/1]).
        sample(Alg) ->
            Old = rand:seed(Alg, {1, 2, 3}),
            OldState = case Old of
                undefined -> undefined;
                {AlgMap, State} -> {maps:get(type, AlgMap), State}
            end,
            {Alg, OldState, rand:uniform(576460752303423488),
             rand:uniform(1000000), rand:uniform()}.
    "#;
    let beam = reference
        .compile_named("boot_loop3_rand", source, &[])
        .unwrap();
    reference.load("boot_loop3_rand", &beam).unwrap();
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    for algorithm in [
        "exs64",
        "exsplus",
        "exsp",
        "exsss",
        "exs1024",
        "exs1024s",
        "exrop",
        "exro928ss",
    ] {
        let arg = OwnedTerm::Atom(algorithm.into());
        let expected = reference.call("boot_loop3_rand", "sample", std::slice::from_ref(&arg));
        eprintln!("checking rand algorithm {algorithm}");
        let term = Term::atom(global_atoms().intern(algorithm).unwrap());
        let actual = vm
            .eval_scheduled("boot_loop3_rand", "sample", &[term], 1, Some(47))
            .unwrap();
        let canonical = decode(&encode(&actual.term, EncodeOptions::default())).unwrap();
        assert_eq!(expected, CallResult::Ok(canonical), "{algorithm}");
    }
}

#[test]
fn system_logger_flag_matches_erts() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping system logger differential test");
        return;
    };
    let source = r#"-module(boot_loop3_logger). -export([run/0]).
        run() ->
            Initial = erlang:system_flag(system_logger, undefined),
            Old = erlang:system_flag(system_logger, self()),
            Me = erlang:system_flag(system_logger, undefined),
            Logger = erlang:system_flag(system_logger, logger),
            _ = erlang:system_flag(system_logger, Initial),
            {Me =:= self(), Old, Logger,
             try erlang:system_flag(system_logger, bad)
             catch error:badarg -> badarg end}.
    "#;
    let beam = reference
        .compile_named("boot_loop3_logger", source, &[])
        .unwrap();
    reference.load("boot_loop3_logger", &beam).unwrap();
    let expected = reference.call("boot_loop3_logger", "run", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("boot_loop3_logger", "run", &[], 1, Some(53))
        .unwrap();
    assert_eq!(expected, CallResult::Ok(actual.term));
}

#[test]
fn scheduler_wall_time_toggle_matches_erts() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping scheduler wall time differential test");
        return;
    };
    let source = r#"-module(boot_loop3_wall). -export([run/0]).
        run() ->
            Old = erts_internal:scheduler_wall_time(false),
            WasOff = erts_internal:scheduler_wall_time(true),
            WasOn = erts_internal:scheduler_wall_time(false),
            _ = erts_internal:scheduler_wall_time(Old),
            {WasOff, WasOn}.
    "#;
    let beam = reference
        .compile_named("boot_loop3_wall", source, &[])
        .unwrap();
    reference.load("boot_loop3_wall", &beam).unwrap();
    let expected = reference.call("boot_loop3_wall", "run", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("boot_loop3_wall", "run", &[], 1, Some(53))
        .unwrap();
    assert_eq!(expected, CallResult::Ok(actual.term));
}

#[test]
fn asynchronous_timer_queries_match_erts() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping timer differential test");
        return;
    };
    let source = r#"-module(boot_loop3_timer). -export([run/0]).
        run() ->
            R = erlang:send_after(10000, self(), tick),
            ReadReturn = erlang:read_timer(R, [{async,true}]),
            ReadMessage = receive
                {read_timer,R,T1} when is_integer(T1) -> present
            after 1000 -> missing end,
            CancelReturn = erlang:cancel_timer(R, [{async,true}]),
            CancelMessage = receive
                {cancel_timer,R,T2} when is_integer(T2) -> present
            after 1000 -> missing end,
            MissingReturn = erlang:cancel_timer(R, [{async,true}]),
            MissingMessage = receive
                {cancel_timer,R,false} -> false_reply
            after 1000 -> missing end,
            R2 = erlang:send_after(10000, self(), tick),
            NoInfoReturn = erlang:cancel_timer(R2, [{async,true},{info,false}]),
            {ReadReturn,ReadMessage,CancelReturn,CancelMessage,
             MissingReturn,MissingMessage,NoInfoReturn}.
    "#;
    let beam = reference
        .compile_named("boot_loop3_timer", source, &[])
        .unwrap();
    reference.load("boot_loop3_timer", &beam).unwrap();
    let expected = reference.call("boot_loop3_timer", "run", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("boot_loop3_timer", "run", &[], 1, Some(53))
        .unwrap();
    assert_eq!(expected, CallResult::Ok(actual.term));
}

#[test]
fn dtrace_tag_bifs_match_erts_without_probes() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping DTrace differential test");
        return;
    };
    let source = r#"-module(boot_loop3_dt). -export([run/0]).
        run() ->
            {erlang:dt_get_tag(), erlang:dt_get_tag_data(),
             erlang:dt_put_tag(42), erlang:dt_spread_tag(true),
             erlang:dt_spread_tag(false), erlang:dt_restore_tag(true),
             erlang:dt_prepend_vm_tag_data(foo),
             erlang:dt_append_vm_tag_data(foo),
             try erlang:dt_spread_tag(undefined)
             catch error:badarg -> badarg end}.
    "#;
    let beam = reference
        .compile_named("boot_loop3_dt", source, &[])
        .unwrap();
    reference.load("boot_loop3_dt", &beam).unwrap();
    let expected = reference.call("boot_loop3_dt", "run", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("boot_loop3_dt", "run", &[], 1, Some(53))
        .unwrap();
    assert_eq!(expected, CallResult::Ok(actual.term));
}

#[test]
fn local_unicode_io_flag_matches_erts() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping Unicode I/O differential test");
        return;
    };
    let source = r#"-module(boot_loop3_unicode). -export([run/0]).
        run() ->
            {net_kernel:dflag_unicode_io(self()),
             try net_kernel:dflag_unicode_io(foo)
             catch error:badarg -> badarg end}.
    "#;
    let beam = reference
        .compile_named("boot_loop3_unicode", source, &[])
        .unwrap();
    reference.load("boot_loop3_unicode", &beam).unwrap();
    let expected = reference.call("boot_loop3_unicode", "run", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("boot_loop3_unicode", "run", &[], 1, Some(53))
        .unwrap();
    assert_eq!(expected, CallResult::Ok(actual.term));
}
