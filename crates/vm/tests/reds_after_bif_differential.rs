use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(reds_after_bif).
-export([run/0]).
id(X) -> X.
l_plain(0) -> ok;
l_plain(I) -> l_plain(I - 1).
l_sysinfo(0) -> ok;
l_sysinfo(I) -> erlang:system_info(schedulers), l_sysinfo(I - 1).
l_ostype(0) -> ok;
l_ostype(I) -> os:type(), l_ostype(I - 1).
l_upd_exact(0, _) -> ok;
l_upd_exact(I, M) -> _ = M#{a := I, b := I}, l_upd_exact(I - 1, M).
l_upd_assoc(0, _) -> ok;
l_upd_assoc(I, M) -> _ = M#{c => I, d => I, e => I}, l_upd_assoc(I - 1, M).
l_upd_one(0, _) -> ok;
l_upd_one(I, M) -> _ = M#{a := I}, l_upd_one(I - 1, M).
l_cat(0, _, _) -> ok;
l_cat(I, A, B) -> _ = <<A/binary, B/binary>>, l_cat(I - 1, A, B).
l_append(0, _) -> ok;
l_append(I, B) -> _ = <<B/binary, 7>>, l_append(I - 1, B).
l_format(0) -> ok;
l_format(I) -> _ = io_lib:format("~w ~s", [I, "x"]), l_format(I - 1).
l_gc(0, L) -> L;
l_gc(I, L) -> l_gc(I - 1, [I, {I, I}, [I] | lists:sublist(L, 50)]).
l_try(0) -> ok;
l_try(I) -> try error(boom) catch error:boom -> ok end, l_try(I - 1).
l_big(0, _) -> ok;
l_big(I, B) -> _ = B * B + 1, l_big(I - 1, B).
l_bs_int(0, _) -> ok;
l_bs_int(I, Bin) -> <<X:200, _/binary>> = Bin, _ = X, l_bs_int(I - 1, Bin).
l_priv(0, Acc) -> Acc;
l_priv(I, Acc) -> l_priv(I - 1, <<Acc/binary, I:8>>).
l_map_new(0) -> ok;
l_map_new(I) -> _ = #{a => I, b => I, c => I}, l_map_new(I - 1).
l_fun(0, _) -> ok;
l_fun(I, F) -> _ = F(I), l_fun(I - 1, F).
l_rev(0, _) -> ok;
l_rev(I, L) -> _ = lists:reverse(L), l_rev(I - 1, L).
l_mem(0, _) -> ok;
l_mem(I, L) -> _ = lists:member(0, L), l_mem(I - 1, L).
l_len(0, _) -> ok;
l_len(I, L) -> _ = length(L), l_len(I - 1, L).
l_lg(0, _) -> ok;
l_lg(I, L) when length(L) > 3 -> l_lg(I - 1, L).
l_app(0, _) -> ok;
l_app(I, L) -> _ = L ++ [1], l_app(I - 1, L).
l_bigcat(0, _) -> ok;
l_bigcat(I, B) -> _ = <<B/binary, B/binary>>, l_bigcat(I - 1, B).
l_bigmatch(0, _) -> ok;
l_bigmatch(I, B) -> <<_:8, R/binary>> = B, _ = R, l_bigmatch(I - 1, B).
l_bigcopy(0, _) -> ok;
l_bigcopy(I, B) -> _ = binary:copy(B), l_bigcopy(I - 1, B).
cases() ->
    M = id(#{a => 1, b => 2}),
    A = id(<<"abc">>),
    B = id(<<"defg">>),
    [{plain, fun() -> l_plain(20000) end},
     {system_info, fun() -> l_sysinfo(20000) end},
     {os_type, fun() -> l_ostype(20000) end},
     {map_update_exact_two, fun() -> l_upd_exact(20000, M) end},
     {map_update_assoc_three, fun() -> l_upd_assoc(20000, M) end},
     {map_update_exact_one, fun() -> l_upd_one(20000, M) end},
     {binary_concat, fun() -> l_cat(20000, A, B) end},
     {binary_append, fun() -> l_append(20000, A) end},
     {gc_heavy, fun() -> l_gc(20000, []) end},
     {try_catch, fun() -> l_try(20000) end},
     {bignum_arith, fun() -> l_big(20000, id(1 bsl 100)) end},
     {bs_get_big_int, fun() -> l_bs_int(20000, id(binary:copy(<<255>>, 40))) end},
     {private_append, fun() -> l_priv(20000, <<>>) end},
     {map_new, fun() -> l_map_new(20000) end},
     {fun_call, fun() -> l_fun(20000, fun(X) -> X + 1 end) end},
     {lists_reverse, fun() -> l_rev(20000, lists:seq(1, 20)) end},
     {lists_member, fun() -> l_mem(20000, lists:seq(1, 20)) end},
     {length_bif, fun() -> l_len(20000, lists:seq(1, 20)) end},
     {length_guard, fun() -> l_lg(20000, lists:seq(1, 100)) end},
     {list_append, fun() -> l_app(20000, lists:seq(1, 20)) end},
     {big_binary_concat, fun() -> l_bigcat(20000, binary:copy(<<7>>, 20000)) end},
     {big_binary_match, fun() -> l_bigmatch(20000, binary:copy(<<7>>, 20000)) end},
     {big_binary_copy, fun() -> l_bigcopy(20000, binary:copy(<<7>>, 20000)) end},
     {io_lib_format, fun() -> l_format(2000) end}].
observe({Name, Fun}) ->
    Parent = self(),
    Pid = spawn_opt(fun() ->
        receive start ->
            {reductions, Before} = process_info(self(), reductions),
            _ = Fun(),
            {reductions, After} = process_info(self(), reductions),
            Parent ! {done, self(), After - Before}
        end
    end, [{min_heap_size, 4000000}]),
    1 = erlang:trace(Pid, true, [running, {tracer, Parent}]),
    Pid ! start,
    receive
        {done, Pid, Delta} ->
            Ref = erlang:trace_delivered(Pid),
            {Name, Delta, count_in(Pid, Ref, 0)}
    after 60000 ->
        exit(Pid, kill),
        {Name, timeout, 0}
    end.
count_in(Pid, Ref, Count) ->
    receive
        {trace, Pid, in, _} -> count_in(Pid, Ref, Count + 1);
        {trace_delivered, Pid, Ref} -> Count;
        _ -> count_in(Pid, Ref, Count)
    after 60000 ->
        0
    end.
run() -> [observe(Case) || Case <- cases()].
"#;

fn rows(term: &OwnedTerm) -> Vec<(String, i64, i64)> {
    let OwnedTerm::List { elems, .. } = term else {
        panic!("not a list: {term:?}");
    };
    elems
        .iter()
        .map(|elem| {
            let OwnedTerm::Tuple(fields) = elem else {
                panic!("not a tuple: {elem:?}");
            };
            let [
                OwnedTerm::Atom(name),
                OwnedTerm::Int(reds),
                OwnedTerm::Int(ins),
            ] = &fields[..]
            else {
                panic!("unexpected row: {elem:?}");
            };
            (name.clone(), *reds, *ins)
        })
        .collect()
}

// Loops around instructions and BIFs that publish the process header again must charge their
// reductions and be preempted like on erts.
#[test]
fn reductions_and_preemption_survive_bif_and_instruction_helpers() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping reductions differential test");
        return;
    };
    let beam = reference
        .compile_named("reds_after_bif", SOURCE, &[])
        .unwrap();
    reference.load("reds_after_bif", &beam).unwrap();
    let CallResult::Ok(expected) = reference.call("reds_after_bif", "run", &[]) else {
        panic!("reference run failed");
    };

    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("reds_after_bif", "run", &[], 1, None)
        .unwrap_or_else(|error| panic!("reductions run: {error}"));

    let (expected, actual) = (rows(&expected), rows(&actual.term));
    assert_eq!(expected.len(), actual.len());
    let mut mismatches = Vec::new();
    for ((name, want_reds, want_ins), (_, got_reds, got_ins)) in expected.iter().zip(&actual) {
        assert!(
            *want_reds > 10_000,
            "{name}: reference reductions {want_reds} too small"
        );
        if (want_reds - got_reds).abs() > *want_reds / 100 {
            mismatches.push(format!("{name}: reductions {got_reds}, erts {want_reds}"));
        }
        if (want_ins - got_ins).abs() > 1 + want_ins / 50 {
            mismatches.push(format!("{name}: schedule-ins {got_ins}, erts {want_ins}"));
        }
    }
    assert!(mismatches.is_empty(), "{mismatches:#?}");
}
