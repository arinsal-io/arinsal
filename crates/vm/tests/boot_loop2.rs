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
