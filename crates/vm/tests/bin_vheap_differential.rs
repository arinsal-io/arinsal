//! Virtual binary heap counters, process information, options, and GC triggers.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_vm::Vm;
use similar_asserts::assert_eq;

const MODULE: &str = "bin_vheap_differential";
const SOURCE: &str = r#"
-module(bin_vheap_differential).
-export([minimum/0, flag/0, gc_info/0, spawn_minimum/0, spawn_minimum_only/0,
         allocation_gc/0, private_append_info/0, message_binary/0, sub_binary_tails/0,
         match_alias_tails/0]).
minimum() -> {erlang:system_info(min_bin_vheap_size), process_info(self(), min_bin_vheap_size)}.
flag() -> Old=process_flag(min_bin_vheap_size, 80000), {Old,process_info(self(), min_bin_vheap_size)}.
gc_info() ->
    garbage_collect(),
    G=element(2,process_info(self(),garbage_collection)),
    I=element(2,process_info(self(),garbage_collection_info)),
    {proplists:get_value(min_bin_vheap_size,G),
     [{K,proplists:get_value(K,I)} || K <- [bin_vheap_size,bin_vheap_block_size,
                                             bin_old_vheap_size,bin_old_vheap_block_size]]}.
spawn_minimum() -> P=spawn_opt(fun() -> receive stop -> ok end end,
                               [{min_heap_size,233},{min_bin_vheap_size,80000}]),
                   Info=process_info(P,min_bin_vheap_size), P!stop, Info.
spawn_minimum_only() -> P=spawn_opt(fun() -> receive stop -> ok end end,
                                     [{min_bin_vheap_size,80000}]),
                         Info=process_info(P,min_bin_vheap_size), P!stop, Info.
allocation_gc() ->
    Parent=self(),
    spawn_opt(fun() ->
        Seed=lists:seq(1,100),
        {Before,_,_}=erlang:statistics(garbage_collection),
        {Rows,Bins}=lists:foldl(fun(_,{Rows0,Bins0}) ->
            Bin=binary:copy(<<0>>,500000),
            G=element(2,process_info(self(),garbage_collection)),
            I=element(2,process_info(self(),garbage_collection_info)),
            Row=[proplists:get_value(minor_gcs,G)|
                 [proplists:get_value(K,I) || K <- [bin_vheap_size,bin_vheap_block_size,
                                                    bin_old_vheap_size,bin_old_vheap_block_size]]],
            {[Row|Rows0],[Bin|Bins0]}
        end,{[],[]},lists:seq(1,8)),
        {After,_,_}=erlang:statistics(garbage_collection),
        Parent!{allocation_result,After>Before,lists:reverse(Rows),length(Bins),length(Seed)}
    end,[{min_heap_size,10000}]),
    receive {allocation_result,_,_,_,_}=Result -> Result end.
private_append_info() ->
    Parent=self(),
    spawn_opt(fun() ->
        {garbage_collection,G0}=process_info(self(),garbage_collection),
        {garbage_collection_info,I0}=process_info(self(),garbage_collection_info),
        Bin=append_loop(1000,<<>>),
        {garbage_collection,G1}=process_info(self(),garbage_collection),
        {garbage_collection_info,I}=process_info(self(),garbage_collection_info),
        Keys=[mbuf_size,bin_vheap_size,bin_vheap_block_size],
        Parent!{private_append_info,
                {byte_size(Bin),
                 proplists:get_value(minor_gcs,G1)-proplists:get_value(minor_gcs,G0),
                 [{K,proplists:get_value(K,I0)} || K <- Keys],
                 [{K,proplists:get_value(K,I)} || K <- Keys]}}
    end,[{min_heap_size,233}]),
    receive {private_append_info,Info} -> Info end.
message_binary() ->
    Parent=self(),
    MessageInfo=fun() ->
        {binary,Binaries}=process_info(self(),binary),
        [{BinarySize,RefCount} || {_Address,BinarySize,RefCount} <- Binaries]
    end,
    Receiver=spawn_opt(fun() ->
        process_flag(message_queue_data,on_heap),
        Parent!ready,
        receive gc ->
            QueuedInfo=MessageInfo(),
            true=erlang:garbage_collect(),
            CollectedInfo=MessageInfo(),
            Parent!{collected,QueuedInfo,CollectedInfo}
        end,
        receive {payload,Bin} ->
            Size=byte_size(Bin),
            Referenced=binary:referenced_byte_size(Bin),
            ReceivedInfo=MessageInfo(),
            true=erlang:garbage_collect(),
            PostGcInfo=MessageInfo(),
            Parent!{message_binary,Size,Referenced,ReceivedInfo,PostGcInfo}
        end
    end,[{min_heap_size,233}]),
    receive ready -> ok end,
    Base=binary:copy(<<7>>,4096),
    Bin=binary:part(Base,10,128),
    Receiver!{payload,Bin},
    Receiver!gc,
    receive {collected,QueuedInfo,CollectedInfo} -> ok end,
    receive {message_binary,Size,Referenced,ReceivedInfo,PostGcInfo} ->
        {Size,Referenced,QueuedInfo,CollectedInfo,ReceivedInfo,PostGcInfo}
    end.
sub_binary_tails() ->
    Parent=self(),
    Child=spawn_opt(fun() ->
        B=binary:copy(<<"abcdefgh">>,4000),
        {garbage_collection,G0}=process_info(self(),garbage_collection),
        L=lists:foldl(fun(I,Acc) -> [tail(B,I rem 7)|Acc] end,[],lists:seq(1,100)),
        {garbage_collection,G1}=process_info(self(),garbage_collection),
        {garbage_collection_info,I}=process_info(self(),garbage_collection_info),
        {binary,Bins}=process_info(self(),binary),
        Parent!{sub_binary_tails,
                length(L),
                proplists:get_value(minor_gcs,G1)-proplists:get_value(minor_gcs,G0),
                [{K,proplists:get_value(K,I)} || K <- [bin_vheap_size,bin_vheap_block_size]],
                [{Size,Refc} || {_,Size,Refc} <- Bins]},
        receive stop -> keep(L) end
    end,[{min_heap_size,4000}]),
    receive {sub_binary_tails,_,_,_,_}=Result ->
        Heap=process_info(Child,[heap_size,total_heap_size]),
        Child!stop,
        erlang:append_element(Result,Heap)
    end.
keep(L) -> length(L).
tail(B,K) -> <<_:K/binary,R/binary>> = B, R.
match_alias_tails() ->
    Parent=self(),
    Child=spawn_opt(fun() ->
        B=binary:copy(<<"FOR1abcd">>,4000),
        {garbage_collection,G0}=process_info(self(),garbage_collection),
        L=lists:foldl(fun(_,Acc) -> [alias(B),rest(B)|Acc] end,[],lists:seq(1,50)),
        {garbage_collection,G1}=process_info(self(),garbage_collection),
        {garbage_collection_info,I}=process_info(self(),garbage_collection_info),
        Parent!{match_alias_tails,
                length(L),
                proplists:get_value(minor_gcs,G1)-proplists:get_value(minor_gcs,G0),
                [{K,proplists:get_value(K,I)} || K <- [bin_vheap_size,bin_vheap_block_size]]},
        receive stop -> keep(L) end
    end,[{min_heap_size,4000}]),
    receive {match_alias_tails,_,_,_}=Result ->
        Heap=process_info(Child,[heap_size,total_heap_size]),
        Child!stop,
        erlang:append_element(Result,Heap)
    end.
alias(<<"FOR1",_/bits>>=C) -> C.
rest(<<"FOR1",R/bits>>) -> R.
append_loop(0,Acc) -> Acc;
append_loop(N,Acc) -> append_loop(N-1,<<Acc/binary,N:8>>).
"#;

fn calls(function: &str) -> (CallResult, CallResult) {
    let reference = RefErl::start().expect("OTP 29.1.1");
    let beam = reference.compile_named(MODULE, SOURCE, &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();
    let expected = reference.call(MODULE, function, &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled(MODULE, function, &[], 1, Some(82))
        .map(|outcome| CallResult::Ok(outcome.term))
        .unwrap_or_else(|error| CallResult::TransportError(format!("{error:?}")));
    (expected, actual)
}

fn assert_equal(function: &str) -> OwnedTerm {
    let (expected, actual) = calls(function);
    assert_eq!(expected, actual, "{function}");
    let CallResult::Ok(value) = expected else {
        panic!("OTP call failed: {expected:?}");
    };
    value
}

#[test]
fn bin_vheap_system_and_process_minimum_match_otp() {
    let value = assert_equal("minimum");
    assert!(matches!(value, OwnedTerm::Tuple(ref fields) if fields.len() == 2));
}

#[test]
fn bin_vheap_process_flag_updates_the_process_minimum() {
    assert_equal("flag");
}

#[test]
fn bin_vheap_garbage_collection_info_fields_match_otp() {
    let (CallResult::Ok(expected), CallResult::Ok(actual)) = calls("gc_info") else {
        panic!("process_info(gc_info) failed");
    };
    for result in [expected, actual] {
        let OwnedTerm::Tuple(fields) = &result else {
            panic!("expected GC info tuple: {result:?}");
        };
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0], OwnedTerm::Int(46_422));
        let OwnedTerm::List { elems, tail } = &fields[1] else {
            panic!("expected binary GC info list: {:?}", fields[1]);
        };
        assert!(matches!(tail.as_ref(), OwnedTerm::Nil));
        assert_eq!(elems.len(), 4);
        assert!(elems.iter().all(|row| matches!(row, OwnedTerm::Tuple(parts)
            if parts.len() == 2 && matches!(parts[1], OwnedTerm::Int(_)) )));
    }
}

#[test]
fn bin_vheap_spawn_option_sets_child_minimum() {
    assert_equal("spawn_minimum");
}

#[test]
fn bin_vheap_spawn_option_without_heap_options_matches_otp() {
    assert_equal("spawn_minimum_only");
}

#[test]
fn bin_vheap_large_binary_allocations_trigger_matching_gc() {
    // The system-wide GC count of `statistics(garbage_collection)` is noisy; the per-process
    // minor GC counter and virtual heap sizes after every allocation are deterministic.
    let value = assert_equal("allocation_gc");
    let OwnedTerm::Tuple(fields) = &value else {
        panic!("expected allocation result tuple");
    };
    assert_eq!(fields[1], OwnedTerm::Atom("true".into()));
}

#[test]
fn private_append_fragment_and_vheap_counters_match_otp() {
    let value = assert_equal("private_append_info");
    let OwnedTerm::Tuple(fields) = &value else {
        panic!("expected binary append info tuple: {value:?}");
    };
    assert_eq!(fields.len(), 4);
}

#[test]
fn queued_binary_fragment_gc_matches_otp() {
    let value = assert_equal("message_binary");
    let OwnedTerm::Tuple(fields) = &value else {
        panic!("expected queued binary info: {value:?}");
    };
    assert_eq!(fields.len(), 6);
}

#[test]
fn sub_binary_tails_share_the_referenced_binary_like_otp() {
    let value = assert_equal("sub_binary_tails");
    let OwnedTerm::Tuple(fields) = &value else {
        panic!("expected sub-binary info tuple: {value:?}");
    };
    assert_eq!(fields.len(), 6);
}

#[test]
fn match_alias_and_tail_do_not_charge_the_binary_again() {
    let value = assert_equal("match_alias_tails");
    let OwnedTerm::Tuple(fields) = &value else {
        panic!("expected alias info tuple: {value:?}");
    };
    assert_eq!(fields.len(), 5);
}
