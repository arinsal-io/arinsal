use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(ets_sweep_probe).
-compile({parse_transform,ms_transform}).
-export([case01/0,case02/0,case03/0,case04/0,case05/0,case06/0,case07/0,case08/0,case09/0,case10/0,
         case11/0,case12/0,case13/0,case14/0,case15/0,case16/0,case17/0,case18/0,case19/0,case20/0,
         case21/0,case22/0,case23/0,case24/0,case25/0,case26/0,case27/0,case28/0,case29/0,case30/0,case31/0,case32/0,case33/0,case34/0,case35/0,case36/0,case37/0,case38/0]).

case01() -> options([set,protected]).
case02() -> options([ordered_set,public,{write_concurrency,auto}]).
case03() -> options([bag,{keypos,2},{read_concurrency,true}]).
case04() -> options([duplicate_bag,{keypos,2},{decentralized_counters,true}]).
case05() -> T=ets:new(ets_sweep_compressed,[set,compressed]), true=ets:insert(T,{large,lists:duplicate(128,compressed_value)}), {options([set,compressed]),ets:lookup(T,large),ets:info(T,compressed)}.
options(Opts) -> T=ets:new(ets_sweep_opt,Opts), {ets:info(T,type),ets:info(T,keypos),ets:info(T,protection),ets:info(T,compressed),ets:info(T,read_concurrency),ets:info(T,write_concurrency),ets:info(T,decentralized_counters)}.

case06() -> T=ets:new(ets_sweep_named,[named_table]), ets_sweep_renamed=ets:rename(T,ets_sweep_renamed), {ets:whereis(ets_sweep_named),ets:whereis(ets_sweep_renamed)=:=T,ets:info(T,name)}.
case07() -> T=ets:new(ets_sweep_keypos,[{keypos,2}]), true=ets:insert(T,{row,k,v}), {ets:lookup(T,k),ets:lookup_element(T,k,3)}.
case08() -> T=ets:new(ets_sweep_bag,[bag]), true=ets:insert(T,[{k,1},{k,1},{k,2}]), {ets:lookup(T,k),ets:insert_new(T,{k,3}),ets:take(T,k)}.
case09() -> T=ets:new(ets_sweep_dup,[duplicate_bag]), true=ets:insert(T,[{k,1},{k,1}]), {ets:lookup(T,k),ets:delete_object(T,{k,1}),ets:lookup(T,k)}.
case10() -> T=ets:new(ets_sweep_order,[ordered_set]), true=ets:insert(T,[{1,a},{1.0,b},{foo,c},{-1,d}]), {ets:tab2list(T),ets:lookup(T,1),ets:lookup(T,1.0)}.

case11() -> T=ets:new(ets_sweep_mut,[set]), true=ets:insert(T,{k,1,2}), {ets:insert_new(T,{k,8,9}),ets:member(T,k),ets:lookup_element(T,k,2),ets:lookup_element(T,k,3,default),ets:take(T,k)}.
case12() -> T=ets:new(ets_sweep_default,[set]), {ets:lookup_element(T,k,2,missing),ets:update_element(T,k,{2,7}, {k,1}),ets:lookup(T,k)}.
case13() -> T=ets:new(ets_sweep_counter,[set]), {ets:update_counter(T,k,1,{k,10}),ets:update_counter(T,k,{2,3}),ets:lookup(T,k)}.
case14() -> T=ets:new(ets_sweep_counter2,[set]), true=ets:insert(T,{k,5}), {ets:update_counter(T,k,{2,4,8,0}),ets:update_counter(T,k,[{2,2},{2,-1}]),ets:lookup(T,k)}.
case15() -> T=ets:new(ets_sweep_update,[set]), true=ets:insert(T,{k,1,2}), {ets:update_element(T,k,[{2,a},{3,b}]),ets:update_element(T,z,{2,x},{z,0}),ets:lookup(T,k),ets:lookup(T,z)}.

case16() -> T=ets:new(ets_sweep_walk,[ordered_set]), true=ets:insert(T,[{2,b},{1,a},{3,c}]), {ets:first(T),ets:last(T),ets:next(T,1.5),ets:prev(T,2.5),ets:first_lookup(T),ets:last_lookup(T)}.
case17() -> T=ets:new(ets_sweep_hashwalk,[set]), true=ets:insert(T,[{a,1},{b,2},{c,3}]), {ets:first_lookup(T),ets:last_lookup(T),ets:tab2list(T)}.
case18() -> T=ets:new(ets_sweep_slot,[set]), true=ets:insert(T,[{3,c},{1,a},{2,b}]), {lists:sort(ets:tab2list(T)),[caught(fun()->ets:slot(T,I) end)||I<-lists:seq(0,2)],caught(fun()->ets:slot(T,-1) end),caught(fun()->ets:slot(ets:new(ets_sweep_slot_ord,[ordered_set]),0) end)}.
case19() -> T=ets:new(ets_sweep_match,[bag]), true=ets:insert(T,[{a,1},{a,2},{b,2}]), {ets:match(T,{'$1',2}),ets:match_object(T,{'$1',2}),ets:foldl(fun(X,A)->[X|A] end,[],T)}.
case20() -> T=ets:new(ets_sweep_select,[set]), true=ets:insert(T,[{a,1},{b,2},{c,3}]), MS=[{{'$1','$2'},[],['$_']}], {ets:select(T,MS),ets:select_count(T,MS),ets:select_delete(T,[{{b,'_'},[],[true]}]),ets:tab2list(T)}.

case21() -> T=ets:new(ets_sweep_replace,[set]), true=ets:insert(T,{a,1}), {ets:select_replace(T,[{{a,'$1'},[],[{{a,2}}]}]),ets:lookup(T,a)}.
case22() -> T=ets:new(ets_sweep_pages,[ordered_set]), true=ets:insert(T,[{1,a},{2,b},{3,c},{4,d}]), MS=[{{'$1','$2'},[],['$1']}], collect(ets:select(T,MS,2),[]).
collect('$end_of_table',A) -> lists:reverse(A);
collect(Rows,A) when is_list(Rows) -> lists:reverse(A)++Rows;
collect({Rows, '$end_of_table'},A) -> lists:reverse(A)++Rows;
collect({Rows,Cont},A) -> collect(ets:select(Cont),lists:reverse(Rows)++A).
case23() -> T=ets:new(ets_sweep_reverse,[ordered_set]), true=ets:insert(T,[{1,a},{2,b},{3,c}]), MS=[{{'$1','$2'},[],['$1']}], collect_reverse(ets:select_reverse(T,MS,2),[]).
collect_reverse('$end_of_table',A) -> lists:reverse(A);
collect_reverse(Rows,A) when is_list(Rows) -> lists:reverse(A)++Rows;
collect_reverse({Rows, '$end_of_table'},A) -> lists:reverse(A)++Rows;
collect_reverse({Rows,Cont},A) -> collect_reverse(ets:select_reverse(Cont),lists:reverse(Rows)++A).
case24() -> T=ets:new(ets_sweep_fix,[set]), true=ets:insert(T,[{a,1},{b,2}]), {ets:safe_fixtable(T,true),ets:safe_fixtable(T,false),ets:info(T,size)}.
case25() -> T=ets:new(ets_sweep_info,[set]), true=ets:insert(T,{k,v}), I=ets:info(T), Keys=[id,decentralized_counters,read_concurrency,write_concurrency,compressed,memory,owner,heir,name,size,node,named_table,type,keypos,protection], Normalized=[{K,normalize_info(K,V)}||{K,V}<-I], {proplists:get_keys(I)=:=Keys,Normalized}.
normalize_info(id,V) -> is_reference(V);
normalize_info(owner,V) -> is_pid(V);
normalize_info(memory,V) -> is_integer(V) andalso V>0;
normalize_info(_K,V) -> V.

case26() -> T=ets:new(ets_sweep_setopts,[set,private]), {ets:setopts(T,{protection,public}),ets:info(T,protection),ets:insert(T,{k,v})}.
case27() -> T=ets:new(ets_sweep_error,[set]), {caught(fun()->ets:insert(T,not_tuple) end),caught(fun()->ets:lookup(T,k) end),caught(fun()->ets:next(T,'$end_of_table') end),caught(fun()->ets:lookup_element(T,k,0) end)}.
caught(F) -> try F() catch error:R -> R end.
case28() -> T=ets:new(ets_sweep_ms,[set]), true=ets:insert(T,{a,1}), MS=[{{'$1','$2'},[],['$_']}], C=ets:match_spec_compile(MS), {ets:is_compiled_ms(C),ets:is_compiled_ms(MS),ets:select(T,MS),ets:test_ms({a,1},MS),ets:match_spec_run([{a,1}],C)}.
case29() -> T=ets:new(ets_sweep_delete,[set]), true=ets:insert(T,[{a,1},{b,2}]), {ets:delete(T,a),ets:info(T,size),ets:delete(T),ets:info(T)}.
case30() -> T=ets:new(ets_sweep_named_all,[named_table]), {lists:member(T,ets:all()),ets:whereis(ets_sweep_named_all)=:=T,ets:info(T,size)}.
case31() -> T=ets:new(ets_sweep_fun2ms,[set]), true=ets:insert(T,[{a,1},{b,3}]), MS=ets:fun2ms(fun({K,V}) when V > 1 -> K end), {MS,ets:select(T,MS)}.
case32() -> T=ets:new(ets_sweep_repair,[ordered_set]), true=ets:insert(T,[{1,a},{2,b},{3,c},{4,d}]), MS=[{{'$1','$2'},[],['$1']}], {_Rows,Cont}=ets:select(T,MS,2), Repaired=ets:repair_continuation(Cont,MS), collect(ets:select(Repaired),[]).
case33() -> T=ets:new(ets_sweep_heir_option,[{heir,self()}]), {is_pid(ets:info(T,heir)),caught(fun()->ets:new(ets_sweep_bad_heir,[{heir,make_ref()}]) end)}.
case34() -> T=ets:new(ets_sweep_delete_all,[set]), true=ets:insert(T,[{a,1},{b,2}]), {ets:delete_all_objects(T),ets:info(T,size),ets:lookup(T,a)}.
case35() -> [memory_probe(Type,Compressed)||Type<-[set,bag,ordered_set],Compressed<-[false,true]].
memory_probe(Type,Compressed) -> Opts=[Type]++case Compressed of true->[compressed];false->[] end, T=ets:new(ets_sweep_memory,Opts), Empty=ets:info(T,memory), true=ets:insert(T,[{a,1},{b,2}]), Small=ets:info(T,memory), true=ets:insert(T,{c,lists:duplicate(20,hello)}), Large=ets:info(T,memory), {Type,Compressed,Empty,Small,Large,ets:lookup(T,c),ets:match_object(T,{'_', '_'})}.
case36() -> T=ets:new(ets_sweep_hash_growth,[set]), true=ets:insert(T,[{I,I}||I<-lists:seq(1,257)]), {ets:info(T,memory),ets:info(T,size)}.
case37() -> T=ets:new(ets_sweep_identity_compressed,[set,compressed]), R=make_ref(), true=ets:insert(T,{k,{self(),R}}), [{k,{P,R2}}]=ets:lookup(T,k), {is_pid(P),is_reference(R2),R=:=R2,P=:=self(),ets:info(T,memory)}.
case38() -> T=ets:new(ets_sweep_compressed_mutation,[ordered_set,compressed]), true=ets:insert(T,{k,{nested,[a,b]},4}), Before=ets:lookup_element(T,k,2), true=ets:update_element(T,k,{2,{changed,[c]}}), MS=[{{k,'$1','$2'},[],['$_']}], {Before,ets:select(T,MS),ets:select_replace(T,[{{k,'$1','$2'},[],[{{k,done,'$2'}}]}]),ets:lookup(T,k)}.
"#;

fn assert_case(function: &str) {
    let reference = RefErl::start().expect("OTP 29.1.1 reference runtime");
    let beam = reference
        .compile_named("ets_sweep_probe", SOURCE, &[])
        .unwrap();
    reference.load("ets_sweep_probe", &beam).unwrap();
    let expected = reference.call("ets_sweep_probe", function, &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("ets_sweep_probe", function, &[], 2, Some(81))
        .unwrap_or_else(|error| panic!("{function}: {error}"));
    assert_eq!(expected, CallResult::Ok(actual.term), "{function}");
}

macro_rules! sweep_test {
    ($test:ident, $function:literal) => {
        #[test]
        fn $test() {
            assert_case($function);
        }
    };
}

sweep_test!(ets_sweep_01_creation_options, "case01");
sweep_test!(ets_sweep_02_ordered_concurrency, "case02");
sweep_test!(ets_sweep_03_bag_keypos, "case03");
sweep_test!(ets_sweep_04_duplicate_bag_options, "case04");
sweep_test!(ets_sweep_05_compressed_tables, "case05");
sweep_test!(ets_sweep_06_named_rename_whereis, "case06");
sweep_test!(ets_sweep_07_nonfirst_keypos, "case07");
sweep_test!(ets_sweep_08_bag_duplicate_rules, "case08");
sweep_test!(ets_sweep_09_duplicate_bag_delete_object, "case09");
sweep_test!(ets_sweep_10_ordered_mixed_numbers, "case10");
sweep_test!(ets_sweep_11_insert_lookup_take, "case11");
sweep_test!(ets_sweep_12_default_forms, "case12");
sweep_test!(ets_sweep_13_counter_defaults, "case13");
sweep_test!(ets_sweep_14_counter_thresholds, "case14");
sweep_test!(ets_sweep_15_update_element_forms, "case15");
sweep_test!(ets_sweep_16_ordered_iteration, "case16");
sweep_test!(ets_sweep_17_hash_lookup_iteration, "case17");
sweep_test!(ets_sweep_18_ordered_slots, "case18");
sweep_test!(ets_sweep_19_match_foldl, "case19");
sweep_test!(ets_sweep_20_select_count_delete, "case20");
sweep_test!(ets_sweep_21_select_replace, "case21");
sweep_test!(ets_sweep_22_select_continuations, "case22");
sweep_test!(ets_sweep_23_reverse_select_pages, "case23");
sweep_test!(ets_sweep_24_safe_fixtable_info, "case24");
sweep_test!(ets_sweep_25_info_items_memory_words, "case25");
sweep_test!(ets_sweep_26_setopts_protection, "case26");
sweep_test!(ets_sweep_27_badarg_paths, "case27");
sweep_test!(ets_sweep_28_match_spec_apis, "case28");
sweep_test!(ets_sweep_29_delete_table, "case29");
sweep_test!(ets_sweep_30_all_and_named_table, "case30");
sweep_test!(ets_sweep_31_fun2ms_match_spec, "case31");
sweep_test!(ets_sweep_32_repair_continuation, "case32");
sweep_test!(ets_sweep_33_heir_option_forms, "case33");
sweep_test!(ets_sweep_34_delete_all_objects, "case34");
sweep_test!(ets_sweep_35_compressed_memory_formula, "case35");
sweep_test!(ets_sweep_36_hash_segment_memory, "case36");
sweep_test!(ets_sweep_37_compressed_identity_roundtrip, "case37");
sweep_test!(ets_sweep_38_compressed_update_select, "case38");
