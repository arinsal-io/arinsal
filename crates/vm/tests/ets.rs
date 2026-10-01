use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(ets_vm_diff).
-export([basic/0, private_access/0, heir/0, owner_exit/0, giveaway/0, errors/0, fixed_locks/0, private_fixed_concurrency/0, compressed_fun/0, select_chunk_ends/0, match_zero_variable/0, fix_time/0, binary_info/0, compressed_binary_info/0]).
id(X) -> X.
basic() ->
  T=ets:new(vm_table,[named_table,set,public,{keypos,1}]),
  true=ets:insert(T,[{a,1},{b,2}]),
  [{a,1}]=ets:lookup(vm_table,a),
  true=ets:member(T,b),
  2=ets:update_counter(T,a,1),
  true=ets:update_element(T,b,{2,9}),
  true=ets:insert_new(T,{c,3}), false=ets:insert_new(T,{c,4}),
  3=ets:select_count(T,[{{'$1','_'},[],[true]}]),
  [[a],[b],[c]]=lists:sort(ets:match(T,{'$1','_'})),
  [{c,3}]=ets:take(T,c),
  [{a,2},{b,9}]=lists:sort(ets:tab2list(T)),
  true=ets:delete(T,a),
  {ets:whereis(vm_table)=:=T,ets:info(T,size),ets:lookup(T,a)}.
private_access() ->
  T=ets:new(private_table,[private]), Parent=self(),
  P=spawn(fun() -> Parent ! (try ets:lookup(T,key), unexpected catch error:badarg -> badarg end) end),
  receive badarg -> true after 1000 -> {timeout,P} end.
heir() ->
  Parent=self(),
  spawn(fun() -> T=ets:new(owned,[set,{heir,Parent,token}]), ets:insert(T,{key,value}), Parent!{table,T} end),
  receive {table,T} -> ok end,
  receive {'ETS-TRANSFER',T,_From,token} -> {ets:info(T,owner)=:=self(),ets:lookup(T,key)} after 1000 -> timeout end.
owner_exit() ->
  Parent=self(),
  spawn(fun() -> T=ets:new(doomed,[]), Parent!{table,T} end),
  receive {table,T} -> ok end,
  timer:sleep(1),
  try ets:lookup(T,key), alive catch error:badarg -> deleted end.
giveaway() ->
  Parent=self(), Receiver=spawn(fun() -> receive {'ETS-TRANSFER',T,_,gift} -> Parent!{received,ets:lookup(T,key)} end end),
  T=ets:new(giveaway,[set]), ets:insert(T,{key,value}), true=ets:give_away(T,Receiver,gift),
  receive {received,Value} -> Value after 1000 -> timeout end.
errors() ->
  A=try ets:lookup(no_such_table,key), unexpected catch error:badarg -> badarg end,
  T=ets:new(err_table,[set]), ets:insert(T,{key,value}),
  B=try ets:lookup_element(T,key,3), unexpected catch error:badarg -> badarg end,
  C=try ets:insert_new(T,{key,other}), unexpected catch error:badarg -> badarg end,
  {A,B,C}.
fixed_locks() ->
  T=ets:new(fixed_locks,[set,{write_concurrency,{debug_hash_fixed_number_of_locks,2049}}]),
  true=ets:insert(T,{key,value}),
  {{debug_hash_fixed_number_of_locks,2048},true,[{key,value}]} =
    {ets:info(T,write_concurrency),ets:info(T,decentralized_counters),ets:lookup(T,key)}.
private_fixed_concurrency() ->
  T=ets:new(private_fixed_concurrency,[private,{write_concurrency,{debug_hash_fixed_number_of_locks,1024}}]),
  ets:info(T,write_concurrency).
compressed_fun() ->
  T=ets:new(compressed_fun,[{keypos,2},compressed,set]),
  F=fun(X) -> {T,1,X} end,
  true=ets:insert(T,{F,1}),
  {ets:info(T,size),ets:info(T,compressed)}.
select_chunk_ends() ->
  T=ets:new(select_chunk_ends,[set]),
  true=ets:insert(T,{a,1}),
  A=list_to_atom("$1"), B=list_to_atom("$2"), S=list_to_atom("$_"),
  MS=[{{A,B},[],[S]}],
  One=ets:select(T,MS,100),
  true=ets:delete_all_objects(T),
  Empty=ets:select(T,MS,100),
  {One,Empty}.
match_zero_variable() ->
  T=ets:new(match_zero_variable,[set]),
  true=ets:insert(T,[{{one,4},4},{{one,5},5}]),
  U=list_to_atom("_"), Z=list_to_atom("$0"),
  lists:sort(ets:match(T,{{one,U},Z})).
fix_time() ->
  T=ets:new(fix_time,[set]), Before=erlang:monotonic_time(),
  true=ets:safe_fixtable(T,true), After=erlang:monotonic_time(),
  {Fixed,[{_,1}]}=ets:info(T,safe_fixed_monotonic_time),
  true=ets:safe_fixtable(T,false),
  {Before =< Fixed, Fixed =< After, ets:info(T,safe_fixed_monotonic_time)}.
binary_info() ->
  T=ets:new(binary_info,[set]), B=list_to_binary(lists:seq(1,100)),
  true=ets:insert(T,[{key1,B},{key2,B}]), Before=ets:info(T,binary),
  true=ets:safe_fixtable(T,true), true=ets:delete(T,key2), During=ets:info(T,binary),
  true=ets:safe_fixtable(T,false),
  Keep=byte_size(id(B)),
  Shape=fun(Items) -> {length(Items),lists:sort([element(2,I) || I <- Items]),
                       lists:sort([element(3,I) || I <- Items])} end,
  {Shape(Before),Shape(During),Shape(ets:info(T,binary)),Keep}.
compressed_binary_info() ->
  T=ets:new(compressed_binary_info,[set,compressed]),
  B=list_to_binary(lists:seq(1,100)), true=ets:insert(T,{B,key}),
  Info=ets:info(T,binary), {length(Info),element(2,hd(Info)),byte_size(id(B))}.
"#;

#[test]
fn ets_process_semantics_match_otp_29() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping ETS VM differential scenarios");
        return;
    };
    let beam = reference.compile_named("ets_vm_diff", SOURCE, &[]).unwrap();
    reference.load("ets_vm_diff", &beam).unwrap();
    for function in [
        "basic",
        "private_access",
        "heir",
        "owner_exit",
        "giveaway",
        "errors",
        "fixed_locks",
        "private_fixed_concurrency",
        "compressed_fun",
        "select_chunk_ends",
        "match_zero_variable",
        "fix_time",
        "binary_info",
        "compressed_binary_info",
    ] {
        let expected = reference.call("ets_vm_diff", function, &[]);
        let mut vm = Vm::new([]);
        vm.load_bytes(&beam).unwrap();
        let actual = vm
            .eval_scheduled(function_module(), function, &[], 2, Some(81))
            .unwrap_or_else(|error| panic!("{function}: {error}"));
        assert_eq!(expected, CallResult::Ok(actual.term), "{function}");
    }
}

fn function_module() -> &'static str {
    "ets_vm_diff"
}

const LOOKUP_SOURCE: &str = r#"
-module(ets_lookup_diff).
-export([run/0]).
run() ->
  Set = ets:new(lookup_set, [set, public]),
  true = ets:insert(Set, [{b,2},{a,1},{c,3}]),
  Bag = ets:new(lookup_bag, [bag, public]),
  true = ets:insert(Bag, [{k,1},{k,2},{k,1},{z,9}]),
  Dup = ets:new(lookup_dup, [duplicate_bag, public]),
  true = ets:insert(Dup, [{k,1},{k,1}]),
  Ord = ets:new(lookup_ord, [ordered_set, public]),
  true = ets:insert(Ord, [{2,b},{1,a},{3,c}]),
  Empty = ets:new(lookup_empty, [set, public]),
  First = ets:first_lookup(Set),
  {lists:sort(walk(Set)), lists:sort(walk(Bag)), lists:sort(walk(Dup)), walk(Ord),
   ets:first_lookup(Empty), ets:last_lookup(Empty),
   First =:= ets:last_lookup(Set),
   ets:next_lookup(Set, element(1, First)) =:= ets:prev_lookup(Set, element(1, First)),
   ets:last_lookup(Ord), ets:prev_lookup(Ord, 3),
   ets:next_lookup(Ord, 0), ets:next_lookup(Ord, 1.5), ets:prev_lookup(Ord, 4),
   lists:sort(ets:foldl(fun(Object, Acc) -> [Object|Acc] end, [], Set)),
   lists:reverse(ets:foldl(fun(Object, Acc) -> [Object|Acc] end, [], Ord)),
   caught(fun() -> ets:next_lookup(Set, missing) end),
   caught(fun() -> ets:prev_lookup(Set, '$end_of_table') end),
   caught(fun() -> ets:first_lookup(nope) end),
   caught(fun() -> ets:first_lookup(1) end),
   caught(fun() -> ets:next_lookup(Ord, '$end_of_table') end),
   caught(fun() -> ets:prev(Ord, '$end_of_table') end),
   parallel_bag()}.
walk(T) -> walk(T, ets:first_lookup(T), []).
walk(_T, '$end_of_table', Acc) -> lists:reverse(Acc);
walk(T, {Key, Objects}, Acc) -> walk(T, ets:next_lookup(T, Key), [{Key, Objects}|Acc]).
caught(Fun) -> try Fun() catch error:badarg -> badarg end.
parallel_bag() ->
  Shared = ets:new(lookup_shared, [duplicate_bag, public]),
  Parent = self(),
  Pids = [spawn(fun() ->
    T = ets:new(lookup_priv, [duplicate_bag, public]),
    ets:insert(T, [{{accumulate, tests}, 1}, {{accumulate, tag}, I}, {{accumulate, tests}, 2}]),
    Taken = ets:take(T, {accumulate, tag}),
    Left = ets:lookup_element(T, {accumulate, tests}, 2),
    ets:insert(Shared, {{accumulate, tests}, I}),
    Parent ! {self(), {Left, Taken}}
  end) || I <- lists:seq(1, 8)],
  Own = [receive {Pid, V} -> V after 2000 -> timeout end || Pid <- Pids],
  SharedVals = lists:sort(ets:lookup_element(Shared, {accumulate, tests}, 2)),
  {lists:sort(Own), SharedVals}.
"#;

#[test]
fn ets_lookup_traversal_matches_otp_29() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping ETS lookup differential test");
        return;
    };
    let beam = reference
        .compile_named("ets_lookup_diff", LOOKUP_SOURCE, &[])
        .unwrap();
    reference.load("ets_lookup_diff", &beam).unwrap();
    let expected = reference.call("ets_lookup_diff", "run", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("ets_lookup_diff", "run", &[], 4, Some(81))
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(expected, CallResult::Ok(actual.term));
}
