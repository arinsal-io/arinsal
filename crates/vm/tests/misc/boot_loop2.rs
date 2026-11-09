use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;

#[test]
fn caught_exit_does_not_replace_later_link_reason() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping caught exit differential test");
        return;
    };
    let source = "-module(boot_loop2_exit). -export([run/0]).
        run() ->
            process_flag(trap_exit, true),
            Parent = self(),
            Child = spawn_link(fun() ->
                _ = catch exit({stale, lists:seq(1, 50)}),
                _ = lists:seq(1, 200),
                erlang:error(oops)
            end),
            receive {'EXIT', Child, Reason} -> {Parent =:= self(), Reason} end.";
    let beam = reference
        .compile_named("boot_loop2_exit", source, &[])
        .unwrap();
    reference.load("boot_loop2_exit", &beam).unwrap();
    let expected = reference.call("boot_loop2_exit", "run", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("boot_loop2_exit", "run", &[], 1, Some(49))
        .unwrap();
    assert_eq!(expected, CallResult::Ok(actual.term));
}

#[test]
fn boot_term_printing_matches_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping boot term printing differential test");
        return;
    };
    let source = "-module(boot_loop2_print). -export([run/0]).
        run() ->
            [erts_internal:term_to_string(#{a => 1})] ++
            [erts_internal:term_to_string(T, L) || {T,L} <-
                [{hello,undefined}, {\"ok\",undefined}, {[1,2],undefined},
                 {<<1,2>>,undefined}, {<<\"abc\">>,undefined},
                 {{abc,[1,2]},5}, {3.14,undefined}, {#{a => 1},undefined}]] ++
            [try erts_internal:term_to_string(42, 1)
             catch error:badarg -> badarg end].";
    let beam = reference
        .compile_named("boot_loop2_print", source, &[])
        .unwrap();
    reference.load("boot_loop2_print", &beam).unwrap();
    let expected = reference.call("boot_loop2_print", "run", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("boot_loop2_print", "run", &[], 1, Some(53))
        .unwrap();
    assert_eq!(expected, CallResult::Ok(actual.term));
}

#[test]
fn process_info_dictionary_lookup_matches_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping process_info dictionary differential test");
        return;
    };
    let source = "-module(boot_loop2_dictionary). -export([run/0]).
        run() -> put(trace_key, trace_value),
            {process_info(self(), [{dictionary, trace_key}]),
             process_info(self(), [{dictionary, missing_key}])}.";
    let beam = reference
        .compile_named("boot_loop2_dictionary", source, &[])
        .unwrap();
    reference.load("boot_loop2_dictionary", &beam).unwrap();
    let expected = reference.call("boot_loop2_dictionary", "run", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("boot_loop2_dictionary", "run", &[], 1, Some(47))
        .unwrap();
    assert_eq!(expected, CallResult::Ok(actual.term));
}

#[test]
fn flatmap_updates_share_the_key_tuple_like_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping flatmap key tuple sharing differential test");
        return;
    };
    let source = "-module(boot_loop2_map_keys). -export([run/0]).
        run() -> Complex = id(#{nested => map}),
            M0 = id(#{1=>a,2=>b,3.0=>c,4=>d,5=>e,complex=>Complex}),
            M1 = M0#{1=>new_value,complex=>Complex#{extra=>key}},
            K0 = erts_internal:map_to_tuple_keys(M0),
            K1 = erts_internal:map_to_tuple_keys(M1),
            Literal = #{literal_a => 1, literal_b => 2},
            LK0 = erts_internal:map_to_tuple_keys(Literal),
            LK1 = erts_internal:map_to_tuple_keys(Literal),
            Mutable = maps:put(literal_a, 3, maps:remove(literal_a, Literal)),
            MK0 = erts_internal:map_to_tuple_keys(Mutable),
            Merged = maps:merge(Literal, Mutable),
            {erts_debug:same(K0,K1), erts_debug:same(K0,K0),
             erts_debug:same(LK0,LK1), erts_debug:same(MK0,LK0),
             erts_debug:same(Merged,Mutable),
             erts_debug:same(erts_internal:map_to_tuple_keys(Mutable),LK0)}.
        id(T) -> T.";
    let beam = reference
        .compile_named("boot_loop2_map_keys", source, &[])
        .unwrap();
    reference.load("boot_loop2_map_keys", &beam).unwrap();
    let expected = reference.call("boot_loop2_map_keys", "run", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("boot_loop2_map_keys", "run", &[], 1, Some(49))
        .unwrap();
    assert_eq!(expected, CallResult::Ok(actual.term));
}

#[test]
fn local_erts_debug_copy_shared_export_uses_its_native_body() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping local copy_shared differential test");
        return;
    };
    let source = "-module(boot_loop2_copy_shared). -export([run/0]).
        run() -> lists:sort(maps:to_list(erts_debug:copy_shared(#{a => [1, 2], b => {value, 3}}))).";
    let beam = reference
        .compile_named("boot_loop2_copy_shared", source, &[])
        .unwrap();
    reference.load("boot_loop2_copy_shared", &beam).unwrap();
    let expected = reference.call("boot_loop2_copy_shared", "run", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("boot_loop2_copy_shared", "run", &[], 1, Some(53))
        .unwrap();
    assert_eq!(expected, CallResult::Ok(actual.term));
}

#[test]
fn display_returns_true_like_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping display differential test");
        return;
    };
    let output = std::process::Command::new("erl")
        .args([
            "-noshell",
            "-eval",
            "true = erlang:display({boot_loop2,ok}), halt().",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, b"{boot_loop2,ok}\r\n");
    let source = "-module(boot_loop2_display). -export([run/0]).
        run() -> erlang:display({boot_loop2, ok}).";
    let beam = reference
        .compile_named("boot_loop2_display", source, &[])
        .unwrap();
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("boot_loop2_display", "run", &[], 1, Some(67))
        .unwrap();
    assert_eq!(actual.term, arinsal_etf::OwnedTerm::Atom("true".into()));
}
