use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;
use similar_asserts::assert_eq;

const MODULE: &str = "ets_process_exit_lifetime";
const SOURCE: &str = r#"
-module(ets_process_exit_lifetime).
-export([named_table_recreated_after_owner_exit/0, heir_transfer_order_is_newest_first/0]).

named_table_recreated_after_owner_exit() ->
    Parent = self(),
    Name = ets_exit_lifetime_named_table,
    OldOwner = spawn(fun() ->
        Table = ets:new(Name, [named_table, public]),
        Parent ! {old_table, ets:info(Table, id)},
        receive stop -> ok end
    end),
    OldRef = receive {old_table, Ref} -> Ref after 1000 -> erlang:error(old_table_timeout) end,
    OldMonitor = monitor(process, OldOwner),
    exit(OldOwner, kill),
    receive {'DOWN', OldMonitor, process, OldOwner, killed} -> ok
    after 1000 -> erlang:error(old_owner_timeout) end,
    NameFreed = ets:whereis(Name) =:= undefined,
    NewOwner = spawn(fun() ->
        Table = ets:new(Name, [named_table, public]),
        Parent ! {new_table, ets:info(Table, id)},
        receive stop -> ok end
    end),
    NewRef = receive {new_table, Ref2} -> Ref2 after 1000 -> erlang:error(new_table_timeout) end,
    NewOwnerAlive = is_process_alive(NewOwner),
    exit(NewOwner, kill),
    {NameFreed, OldRef =/= NewRef, NewOwnerAlive}.

heir_transfer_order_is_newest_first() ->
    Parent = self(),
    Owner = spawn(fun() ->
        ets:new(ets_exit_order_first, [named_table, public, {heir, Parent, first}]),
        ets:new(ets_exit_order_second, [named_table, public, {heir, Parent, second}]),
        ets:new(ets_exit_order_third, [named_table, public, {heir, Parent, third}]),
        Parent ! tables_ready,
        receive stop -> ok end
    end),
    receive tables_ready -> ok after 1000 -> erlang:error(tables_timeout) end,
    exit(Owner, kill),
    receive {'ETS-TRANSFER', _, Owner, First} ->
        receive {'ETS-TRANSFER', _, Owner, Second} ->
            receive {'ETS-TRANSFER', _, Owner, Third} -> [First, Second, Third]
            after 1000 -> erlang:error(third_transfer_timeout) end
        after 1000 -> erlang:error(second_transfer_timeout) end
    after 1000 -> erlang:error(first_transfer_timeout) end.
"#;

#[test]
fn named_table_name_is_released_and_new_tid_allocated_after_owner_exit() {
    let reference = RefErl::start().expect("OTP 29 reference runtime");
    let beam = reference.compile_named(MODULE, SOURCE, &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();
    let expected = reference.call(MODULE, "named_table_recreated_after_owner_exit", &[]);

    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled(
            MODULE,
            "named_table_recreated_after_owner_exit",
            &[],
            2,
            Some(91),
        )
        .unwrap_or_else(|error| panic!("ETS owner exit: {error}"));

    assert_eq!(expected, CallResult::Ok(actual.term));
}

#[test]
fn exiting_owner_transfers_tables_in_erts_owned_list_order() {
    let reference = RefErl::start().expect("OTP 29 reference runtime");
    let beam = reference.compile_named(MODULE, SOURCE, &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();
    let expected = reference.call(MODULE, "heir_transfer_order_is_newest_first", &[]);

    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled(
            MODULE,
            "heir_transfer_order_is_newest_first",
            &[],
            2,
            Some(92),
        )
        .unwrap_or_else(|error| panic!("ETS heir transfer order: {error}"));

    assert_eq!(expected, CallResult::Ok(actual.term));
}
