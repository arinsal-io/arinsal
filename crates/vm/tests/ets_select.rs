use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(ets_select_diff).
-export([selections/0, mutations/0, compiled/0, errors/0, info/0]).

collect_select(T, Spec, Limit) ->
  case ets:select(T, Spec, Limit) of
    {Rows, '$end_of_table'} -> Rows;
    {Rows, Cont} -> Rows ++ collect_select_cont(Cont);
    Rows -> Rows
  end.
collect_select_cont(Cont) ->
  case Cont of '$end_of_table' -> []; _ -> collect_select_cont1(Cont) end.
collect_select_cont1(Cont) ->
  case ets:select(Cont) of
    '$end_of_table' -> [];
    {Rows, '$end_of_table'} -> Rows;
    {Rows, Next} -> Rows ++ collect_select_cont(Next);
    Rows -> Rows
  end.
collect_reverse(T, Spec, Limit) ->
  case ets:select_reverse(T, Spec, Limit) of
    {Rows, '$end_of_table'} -> Rows;
    {Rows, Cont} -> Rows ++ collect_reverse_cont(Cont);
    Rows -> Rows
  end.
collect_reverse_cont(Cont) ->
  case Cont of '$end_of_table' -> []; _ -> collect_reverse_cont1(Cont) end.
collect_reverse_cont1(Cont) ->
  case ets:select_reverse(Cont) of
    '$end_of_table' -> [];
    {Rows, '$end_of_table'} -> Rows;
    {Rows, Next} -> Rows ++ collect_reverse_cont(Next);
    Rows -> Rows
  end.
collect_match(T, Pattern, Limit) ->
  case ets:match(T, Pattern, Limit) of
    {Rows, '$end_of_table'} -> Rows;
    {Rows, Cont} -> Rows ++ collect_match_cont(Cont);
    Rows -> Rows
  end.
collect_match_cont(Cont) ->
  case Cont of '$end_of_table' -> []; _ -> collect_match_cont1(Cont) end.
collect_match_cont1(Cont) ->
  case ets:match(Cont) of
    '$end_of_table' -> [];
    {Rows, '$end_of_table'} -> Rows;
    {Rows, Next} -> Rows ++ collect_match_cont(Next);
    Rows -> Rows
  end.
collect_objects(T, Pattern, Limit) ->
  case ets:match_object(T, Pattern, Limit) of
    {Rows, '$end_of_table'} -> Rows;
    {Rows, Cont} -> Rows ++ collect_objects_cont(Cont);
    Rows -> Rows
  end.
collect_objects_cont(Cont) ->
  case Cont of '$end_of_table' -> []; _ -> collect_objects_cont1(Cont) end.
collect_objects_cont1(Cont) ->
  case ets:match_object(Cont) of
    '$end_of_table' -> [];
    {Rows, '$end_of_table'} -> Rows;
    {Rows, Next} -> Rows ++ collect_objects_cont(Next);
    Rows -> Rows
  end.
selections() ->
  {select_type(set),select_type(ordered_set),select_type(bag)}.
select_type(Type) ->
  Results = [{a,1},{b,2},{c,3},{d,4},{e,5},{f,6},{f,7}],
  T=ets:new(sel,[Type,public]), ets:insert(T,Results),
  MS=[{{'$1','$2'},[],['$_']}],
  A=lists:sort(collect_select(T,MS,1)),
  B=lists:sort(collect_select(T,MS,3)),
  C=lists:sort(collect_reverse(T,MS,1)),
  M=lists:sort(collect_match(T,{'$1','$2'},1)),
  O=lists:sort(collect_objects(T,{'$1','$2'},3)),
  Count=ets:select_count(T,[{{'$1','_'},[],[true]}]),
  ets:delete(T), {A,B,C,M,O,Count}.
mutations() ->
  T=ets:new(mut,[set,public]), ets:insert(T,{a,1}),
  U=ets:update_counter(T,missing,2,{missing,40}),
  V=ets:update_element(T,missing,{2,99},{missing,5}),
  X=ets:lookup_element(T,missing,2,none),
  ets:insert(T,[{b,2},{c,3}]),
  D=ets:select_delete(T,[{{b,'_'},[],[true]}]),
  R=ets:select_replace(T,[{{c,'$1'},[],[{{c,8}}]}]),
  {U,V,X,D,R,lists:sort(ets:tab2list(T))}.
compiled() ->
  MS=[{{'$1','$2'},[],['$_']}],
  C=ets:match_spec_compile(MS),
  Is=ets:is_compiled_ms(C),
  Run=ets:match_spec_run_r([{a,1},{b,2}],C,[]),
  {Is,Run,ets:is_compiled_ms(MS)}.
errors() ->
  T=ets:new(err,[set]),
  A=try ets:select(T,[],0) catch error:badarg -> badarg end,
  B=try ets:select(T,[],not_a_limit) catch error:badarg -> badarg end,
  C=try ets:match(T,not_a_tuple) catch error:badarg -> badarg end,
  D=try ets:lookup_element(T,missing,1) catch error:badarg -> badarg end,
  E=try ets:update_counter(T,missing,1) catch error:badarg -> badarg end,
  {A,B,C,D,E}.
info() ->
  T=ets:new(meta,[set,{write_concurrency,true},{decentralized_counters,true}]),
  {ets:info(T,decentralized_counters),ets:info(T,id)=/=undefined}.
"#;

#[test]
fn ets_select_family_matches_otp_29() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping ETS select differential scenarios");
        return;
    };
    let beam = reference
        .compile_named("ets_select_diff", SOURCE, &[])
        .unwrap();
    reference.load("ets_select_diff", &beam).unwrap();
    for function in ["selections", "mutations", "errors", "info"] {
        let expected = reference.call("ets_select_diff", function, &[]);
        let mut vm = Vm::new([]);
        vm.load_bytes(&beam).unwrap();
        let actual = vm
            .eval_scheduled("ets_select_diff", function, &[], 2, Some(81))
            .unwrap_or_else(|error| panic!("{function}: {error}"));
        assert_eq!(expected, CallResult::Ok(actual.term), "{function}");
    }
}
