use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(ets_bifs_diff).
-export([match_spec/0, raw_walk/0, setopts_delete/0, bad_super_user/0,
         super_user_access/0, binary_info/0, setopts_heir/0]).

match_spec() ->
  MS = [{{'$1','_'}, [], [{{'$1',ok}}]}],
  {erlang:match_spec_test({a,1}, MS, table),
   erlang:match_spec_test([{a,1},{b,2}], [{{'$1','_'},[],[return_trace]}], trace)}.

raw_walk() ->
  T = ets:new(raw_bifs, [ordered_set, private]),
  true = ets:insert(T, [{3,c},{1,a},{2,b}]),
  First = erts_internal:ets_raw_first(T),
  Second = erts_internal:ets_raw_next(T, First),
  Third = erts_internal:ets_raw_next(T, Second),
  End = erts_internal:ets_raw_next(T, Third),
  H = ets:new(raw_hash_bifs, [set, private]),
  true = ets:insert(H, [{3,c},{1,a},{2,b}]),
  {First,Second,Third,End,
   lists:sort(raw_collect(H, erts_internal:ets_raw_first(H), []))}.

raw_collect(_Table, '$end_of_table', Acc) -> lists:reverse(Acc);
raw_collect(Table, Key, Acc) ->
  raw_collect(Table, erts_internal:ets_raw_next(Table, Key), [Key|Acc]).

setopts_delete() ->
  T = ets:new(setopts_bifs, [set, private]),
  true = ets:setopts(T, {protection, public}),
  true = ets:insert(T, [{a,1},{b,2}]),
  Count = ets:internal_delete_all(T, undefined),
  {ets:info(T, protection), Count, ets:info(T, size), ets:setopts(T, [])}.

bad_super_user() ->
  {erts_internal:ets_super_user(false),
   try erts_internal:ets_super_user(no) catch error:badarg -> badarg end}.

super_user_access() ->
  T = ets:new(super_user_bifs, [private]),
  true = ets:insert(T, {key, value}),
  ok = erts_internal:ets_super_user(true),
  Found = ets:lookup(T, key),
  ok = erts_internal:ets_super_user(false),
  Found.

binary_info() ->
  T = ets:new(binary_bifs, [set, public]),
  Bin = binary:copy(<<7>>, 100),
  true = ets:insert(T, {key, Bin}),
  lists:sort([{Size, Refc} || {_, Size, Refc} <-
    erts_internal:ets_lookup_binary_info(T, key)]).

setopts_heir() ->
  Parent = self(),
  Child = spawn(fun() ->
    T = ets:new(setopts_heir_bifs, [set, public]),
    true = ets:setopts(T, {heir, Parent, gift}),
    ets:insert(T, {key, value}),
    Parent ! {table, T}
  end),
  receive {table, T} ->
    receive {'ETS-TRANSFER', T, Child, gift} -> ets:info(T, owner) =:= self()
    after 1000 -> timeout end
  after 1000 -> {timeout, Child} end.
"#;

fn run(function: &str, reference: &RefErl, beam: &[u8]) {
    let expected = reference.call("ets_bifs_diff", function, &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(beam).unwrap();
    let actual = vm
        .eval_scheduled("ets_bifs_diff", function, &[], 2, Some(91))
        .unwrap_or_else(|error| panic!("{function}: {error}"));
    assert_eq!(expected, CallResult::Ok(actual.term), "{function}");
}

#[test]
fn ets_bifs_match_spec_test_matches_otp_29() {
    let reference = RefErl::start().expect("OTP 29 reference runtime");
    let beam = reference
        .compile_named("ets_bifs_diff", SOURCE, &[])
        .unwrap();
    reference.load("ets_bifs_diff", &beam).unwrap();
    run("match_spec", &reference, &beam);
}

#[test]
fn ets_bifs_raw_key_walk_matches_otp_29() {
    let reference = RefErl::start().expect("OTP 29 reference runtime");
    let beam = reference
        .compile_named("ets_bifs_diff", SOURCE, &[])
        .unwrap();
    reference.load("ets_bifs_diff", &beam).unwrap();
    run("raw_walk", &reference, &beam);
}

#[test]
fn ets_bifs_setopts_and_delete_all_match_otp_29() {
    let reference = RefErl::start().expect("OTP 29 reference runtime");
    let beam = reference
        .compile_named("ets_bifs_diff", SOURCE, &[])
        .unwrap();
    reference.load("ets_bifs_diff", &beam).unwrap();
    run("setopts_delete", &reference, &beam);
    run("bad_super_user", &reference, &beam);
    run("super_user_access", &reference, &beam);
    run("binary_info", &reference, &beam);
    run("setopts_heir", &reference, &beam);
}
