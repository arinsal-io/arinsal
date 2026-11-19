#[allow(dead_code)]
#[path = "common/mod.rs"]
mod common;

#[test]
fn wide_export_arity_matches_otp() {
    const MODULE: &str = "export_arity_wide_diff";
    const SOURCE: &str = r#"
        -module(export_arity_wide_diff).
        -export([run_make_fun_256/0, run_function_exported_256/0, run_apply_256/0,
                 run_eval_fun_256/0, run_make_fun_255/0, run_external_fun_256/0]).
        guarded(G) ->
            try G() of
                V when is_function(V) -> {ok, is_function(V), erlang:fun_info(V, arity)};
                V -> {ok, V}
            catch
                error:Reason -> {error, Reason}
            end.
        run_make_fun_256() -> guarded(fun() -> erlang:make_fun(m, f, 256) end).
        run_function_exported_256() -> erlang:function_exported(m, f, 256).
        run_apply_256() -> guarded(fun() -> erlang:apply(m, f, lists:seq(1, 256)) end).
        run_eval_fun_256() ->
            FunAst = {list_to_atom("fun"), 1,
                      {function, {atom, 1, m}, {atom, 1, f}, {integer, 1, 256}}},
            guarded(fun() -> erl_eval:expr(FunAst, [], none, none) end).
        run_make_fun_255() -> guarded(fun() -> erlang:make_fun(m, f, 255) end).
        run_external_fun_256() ->
            (fun() ->
              EncodedExport = <<131, 113, 100, 0, 1, $m, 100, 0, 1, $f, 98, 0, 0, 1, 0>>,
              ExternalFun = binary_to_term(EncodedExport),
              {erlang:fun_info(ExternalFun, arity),
               erlang:fun_info_mfa(ExternalFun),
               term_to_binary(ExternalFun)}
            end)().
    "#;
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping wide export arity differential test");
        return;
    };
    let beam = reference.compile_named(MODULE, SOURCE, &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();
    let mut vm = common::node();
    let lists_object = reference
        .eval("element(2, code:get_object_code(lists))")
        .unwrap();
    let lists_beam = match &lists_object {
        arinsal_etf::OwnedTerm::Binary(beam) => beam.clone(),
        other => panic!("OTP returned no lists BEAM: {other:?}"),
    };
    common::load_fresh(&mut vm, &lists_beam);
    let erl_eval_object = reference
        .eval("element(2, code:get_object_code(erl_eval))")
        .unwrap();
    let erl_eval_beam = match &erl_eval_object {
        arinsal_etf::OwnedTerm::Binary(beam) => beam.clone(),
        other => panic!("OTP returned no erl_eval BEAM: {other:?}"),
    };
    common::load_fresh(&mut vm, &erl_eval_beam);
    let orddict_object = reference
        .eval("element(2, code:get_object_code(orddict))")
        .unwrap();
    let orddict_beam = match &orddict_object {
        arinsal_etf::OwnedTerm::Binary(beam) => beam.clone(),
        other => panic!("OTP returned no orddict BEAM: {other:?}"),
    };
    common::load_fresh(&mut vm, &orddict_beam);
    common::load_fresh(&mut vm, &beam);
    for function in [
        "run_make_fun_256",
        "run_function_exported_256",
        "run_apply_256",
        "run_eval_fun_256",
        "run_make_fun_255",
        "run_external_fun_256",
    ] {
        let expected = reference.eval(&format!("{MODULE}:{function}()")).unwrap();
        let actual = vm.eval_scheduled(MODULE, function, &[], 1).unwrap().term;
        similar_asserts::assert_eq!(expected, actual, "{function}");
    }
}
use arinsal_difftest::RefErl;
