use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_term::{VecHeap, from_owned, to_owned};
use arinsal_vm::Vm;

#[test]
fn re_native_binding_matches_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping re binding differential test");
        return;
    };
    let source = "-module(boot_loop1_re). -export([run/0]).
        run() -> re:run(\"abc\", \"b\", [{capture,none}]).";
    let beam = reference
        .compile_named("boot_loop1_re", source, &[])
        .unwrap();
    reference.load("boot_loop1_re", &beam).unwrap();
    let expected = reference.call("boot_loop1_re", "run", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm.eval("boot_loop1_re", "run", &[]).unwrap();
    assert_eq!(expected, CallResult::Ok(to_owned(actual.term).unwrap()));
}

#[test]
fn kernel_process_flags_match_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping process flag differential test");
        return;
    };
    let source = "-module(boot_loop1_flags). -export([run/0]).
        run() -> {process_flag(async_dist,true),
                  process_flag(async_dist,false),
                  process_flag(monitor_nodes,true),
                  process_flag(monitor_nodes,false)}.";
    let beam = reference
        .compile_named("boot_loop1_flags", source, &[])
        .unwrap();
    reference.load("boot_loop1_flags", &beam).unwrap();
    let expected = reference.call("boot_loop1_flags", "run", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("boot_loop1_flags", "run", &[], 1, Some(31))
        .unwrap();
    assert_eq!(expected, CallResult::Ok(actual.term));
}

#[test]
fn local_node_queries_match_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping nodes differential test");
        return;
    };
    let source = "-module(boot_loop1_nodes). -export([run/0]).
        run() -> {erlang:nodes(), erlang:nodes(visible, #{connection_id => true})}.";
    let beam = reference
        .compile_named("boot_loop1_nodes", source, &[])
        .unwrap();
    reference.load("boot_loop1_nodes", &beam).unwrap();
    let expected = reference.call("boot_loop1_nodes", "run", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("boot_loop1_nodes", "run", &[], 1, Some(41))
        .unwrap();
    assert_eq!(expected, CallResult::Ok(actual.term));
}

#[test]
fn foreign_registered_name_and_stacktrace_match_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping process_info differential test");
        return;
    };
    let source = "-module(boot_loop1_info). -export([run/0]).
        run() -> Parent=self(), true=register(boot_loop1_foreign_name,Parent),
                 Child=spawn(fun() -> Parent ! {self(),process_info(Parent,registered_name)} end),
                 receive {Child,Name} ->
                     true=unregister(boot_loop1_foreign_name),
                     {current_stacktrace,[{Mod,Fun,Arity,_}|_]} =
                         process_info(self(),current_stacktrace),
                     {Name,Mod,Fun,Arity}
                 end.";
    let beam = reference
        .compile_named("boot_loop1_info", source, &[])
        .unwrap();
    reference.load("boot_loop1_info", &beam).unwrap();
    let expected = reference.call("boot_loop1_info", "run", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("boot_loop1_info", "run", &[], 2, Some(37))
        .unwrap();
    assert_eq!(expected, CallResult::Ok(actual.term));
}

#[test]
fn tuple_arity_selection_matches_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping tuple arity differential test");
        return;
    };
    let source = "-module(boot_loop1_select). -export([choose/1]).
        choose({}) -> empty;
        choose({A}) -> {one,A};
        choose({A,B}) -> {two,A,B};
        choose({A,B,C}) -> {three,A,B,C};
        choose(_) -> other.";
    let beam = reference
        .compile_named("boot_loop1_select", source, &[])
        .unwrap();
    reference.load("boot_loop1_select", &beam).unwrap();
    let parsed = arinsal_beam::parse(&beam).unwrap();
    let module = arinsal_loader::load(&parsed).unwrap();
    assert!(module.code.iter().any(|instr| matches!(
        instr,
        arinsal_loader::Instr::Select {
            tuple_arity: true,
            ..
        }
    )));
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    for input in [
        OwnedTerm::Tuple(vec![]),
        OwnedTerm::Tuple(vec![OwnedTerm::Int(1)]),
        OwnedTerm::Tuple(vec![OwnedTerm::Int(1), OwnedTerm::Int(2)]),
        OwnedTerm::Tuple(vec![
            OwnedTerm::Int(1),
            OwnedTerm::Int(2),
            OwnedTerm::Int(3),
        ]),
        OwnedTerm::Int(1),
    ] {
        let expected = reference.call("boot_loop1_select", "choose", std::slice::from_ref(&input));
        let mut heap = VecHeap::new();
        let arg = from_owned(&input, &mut heap).unwrap();
        let actual = vm
            .eval("boot_loop1_select", "choose", &[arg])
            .map(|result| to_owned(result.term).unwrap());
        match (expected, actual) {
            (CallResult::Ok(expected), Ok(actual)) => assert_eq!(actual, expected),
            (expected, actual) => panic!("input {input:?}: reference {expected:?}, VM {actual:?}"),
        }
    }
}

#[test]
fn is_pid_instruction_matches_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping is_pid differential test");
        return;
    };
    let source = "-module(boot_loop1_pid). -export([choose/1]).
        choose(X) when is_pid(X) -> pid;
        choose(_) -> other.";
    let beam = reference
        .compile_named("boot_loop1_pid", source, &[])
        .unwrap();
    reference.load("boot_loop1_pid", &beam).unwrap();
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    for input in [reference.eval("self()").unwrap(), OwnedTerm::Int(1)] {
        let expected = reference.call("boot_loop1_pid", "choose", std::slice::from_ref(&input));
        let mut heap = VecHeap::new();
        let arg = from_owned(&input, &mut heap).unwrap();
        let actual = vm
            .eval("boot_loop1_pid", "choose", &[arg])
            .map(|result| to_owned(result.term).unwrap());
        match (expected, actual) {
            (CallResult::Ok(expected), Ok(actual)) => assert_eq!(actual, expected),
            (expected, actual) => panic!("input {input:?}: reference {expected:?}, VM {actual:?}"),
        }
    }
}

#[test]
fn update_record_instruction_matches_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping update_record differential test");
        return;
    };
    let source = "-module(boot_loop1_record). -export([change/2]).
        -record(state, {a,b,c,d}).
        change(S,V) -> S#state{b=V,d=V}.";
    let beam = reference
        .compile_named("boot_loop1_record", source, &[])
        .unwrap();
    reference.load("boot_loop1_record", &beam).unwrap();
    let parsed = arinsal_beam::parse(&beam).unwrap();
    assert!(
        parsed
            .code
            .instructions
            .iter()
            .any(|instruction| { instruction.op == arinsal_spec::Opcode::UpdateRecord })
    );
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let input = OwnedTerm::Tuple(vec![
        OwnedTerm::Atom("state".into()),
        OwnedTerm::Int(1),
        OwnedTerm::Int(2),
        OwnedTerm::Int(3),
        OwnedTerm::Int(4),
    ]);
    for value in [OwnedTerm::Int(2), OwnedTerm::Int(7)] {
        let expected = reference.call(
            "boot_loop1_record",
            "change",
            &[input.clone(), value.clone()],
        );
        let mut heap = VecHeap::new();
        let args = [
            from_owned(&input, &mut heap).unwrap(),
            from_owned(&value, &mut heap).unwrap(),
        ];
        let actual = vm
            .eval("boot_loop1_record", "change", &args)
            .map(|result| to_owned(result.term).unwrap());
        match (expected, actual) {
            (CallResult::Ok(expected), Ok(actual)) => assert_eq!(actual, expected),
            (expected, actual) => panic!("reference {expected:?}, VM {actual:?}"),
        }
    }
}

#[test]
fn process_priority_flag_previous_value_matches_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping process priority differential test");
        return;
    };
    let source = "-module(boot_loop1_priority). -export([run/0]).
        run() -> A=process_flag(priority,max), B=process_flag(priority,normal), {A,B}.";
    let beam = reference
        .compile_named("boot_loop1_priority", source, &[])
        .unwrap();
    reference.load("boot_loop1_priority", &beam).unwrap();
    let expected = reference.call("boot_loop1_priority", "run", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("boot_loop1_priority", "run", &[], 1, Some(17))
        .unwrap();
    assert_eq!(expected, CallResult::Ok(actual.term));
}

#[test]
fn registered_name_process_info_matches_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping process_info differential test");
        return;
    };
    let source = "-module(boot_loop1_process_info). -export([run/0]).
        run() -> Before=process_info(self(),registered_name),
                 true=register(boot_loop1_test_name,self()),
                 During=process_info(self(),registered_name),
                 true=unregister(boot_loop1_test_name),
                 {Before,During}.";
    let beam = reference
        .compile_named("boot_loop1_process_info", source, &[])
        .unwrap();
    reference.load("boot_loop1_process_info", &beam).unwrap();
    let expected = reference.call("boot_loop1_process_info", "run", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("boot_loop1_process_info", "run", &[], 1, Some(19))
        .unwrap();
    assert_eq!(expected, CallResult::Ok(actual.term));
}

#[test]
fn process_dictionary_get_put_erase_matches_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping process dictionary differential test");
        return;
    };
    let source = "-module(boot_loop1_dictionary). -export([run/0]).
        run() -> A=get(boot_loop1_dict_key) =:= undefined,
                 B=put(boot_loop1_dict_key,{1,2}) =:= undefined,
                 C=get(boot_loop1_dict_key) =:= {1,2},
                 D=put(boot_loop1_dict_key,[a,b]) =:= {1,2},
                 E=erase(boot_loop1_dict_key) =:= [a,b],
                 F=get(boot_loop1_dict_key) =:= undefined,
                 {A,B,C,D,E,F}.";
    let beam = reference
        .compile_named("boot_loop1_dictionary", source, &[])
        .unwrap();
    reference.load("boot_loop1_dictionary", &beam).unwrap();
    let expected = reference.call("boot_loop1_dictionary", "run", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("boot_loop1_dictionary", "run", &[], 1, Some(23))
        .unwrap();
    assert_eq!(expected, CallResult::Ok(actual.term));
}

#[test]
fn group_leader_self_change_matches_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping group_leader differential test");
        return;
    };
    let source = "-module(boot_loop1_group_leader). -export([run/0]).
        run() -> Before=is_pid(group_leader()),
                 true=group_leader(self(),self()),
                 {Before,group_leader() =:= self()}.";
    let beam = reference
        .compile_named("boot_loop1_group_leader", source, &[])
        .unwrap();
    reference.load("boot_loop1_group_leader", &beam).unwrap();
    let expected = reference.call("boot_loop1_group_leader", "run", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("boot_loop1_group_leader", "run", &[], 1, Some(29))
        .unwrap();
    assert_eq!(expected, CallResult::Ok(actual.term));
}

#[test]
fn undef_stacktrace_names_missing_dynamic_target() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping undef stacktrace differential test");
        return;
    };
    let source = "-module(boot_loop1_undef). -export([run/0]).
        run() -> try apply(boot_loop1_undef,absent,[7]) of
                     _ -> unexpected
                 catch error:undef:Stack ->
                     case Stack of
                         [{boot_loop1_undef,absent,[7],_}|_] -> ok;
                         _ -> wrong_stack
                     end
                 end.";
    let beam = reference
        .compile_named("boot_loop1_undef", source, &[])
        .unwrap();
    reference.load("boot_loop1_undef", &beam).unwrap();
    let expected = reference.call("boot_loop1_undef", "run", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("boot_loop1_undef", "run", &[], 1, Some(31))
        .unwrap();
    assert_eq!(expected, CallResult::Ok(actual.term));
}

#[test]
fn is_boolean_instruction_matches_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping is_boolean differential test");
        return;
    };
    let source = "-module(boot_loop1_boolean). -export([choose/1]).
        choose(X) when is_boolean(X) -> yes;
        choose(_) -> no.";
    let beam = reference
        .compile_named("boot_loop1_boolean", source, &[])
        .unwrap();
    reference.load("boot_loop1_boolean", &beam).unwrap();
    let parsed = arinsal_beam::parse(&beam).unwrap();
    assert!(
        parsed
            .code
            .instructions
            .iter()
            .any(|instruction| { instruction.op == arinsal_spec::Opcode::IsBoolean })
    );
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    for input in [
        OwnedTerm::Atom("true".into()),
        OwnedTerm::Atom("false".into()),
        OwnedTerm::Atom("maybe".into()),
        OwnedTerm::Int(1),
    ] {
        let expected = reference.call("boot_loop1_boolean", "choose", std::slice::from_ref(&input));
        let mut heap = VecHeap::new();
        let arg = from_owned(&input, &mut heap).unwrap();
        let actual = vm
            .eval("boot_loop1_boolean", "choose", &[arg])
            .map(|result| to_owned(result.term).unwrap());
        match (expected, actual) {
            (CallResult::Ok(expected), Ok(actual)) => assert_eq!(actual, expected),
            (expected, actual) => panic!("reference {expected:?}, VM {actual:?}"),
        }
    }
}

#[test]
fn monitor_registered_name_matches_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping named monitor differential test");
        return;
    };
    let source = "-module(boot_loop1_monitor_name). -export([run/0]).
        run() -> true=register(boot_loop1_named_target,self()),
                 Ref=monitor(process,boot_loop1_named_target),
                 true=demonitor(Ref,[flush]),
                 true=unregister(boot_loop1_named_target),
                 Missing=monitor(process,boot_loop1_missing_target),
                 receive {'DOWN',Missing,process,
                          {boot_loop1_missing_target,nonode@nohost},noproc} -> ok
                 after 1000 -> timeout end.";
    let beam = reference
        .compile_named("boot_loop1_monitor_name", source, &[])
        .unwrap();
    reference.load("boot_loop1_monitor_name", &beam).unwrap();
    let expected = reference.call("boot_loop1_monitor_name", "run", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("boot_loop1_monitor_name", "run", &[], 1, Some(37))
        .unwrap();
    assert_eq!(expected, CallResult::Ok(actual.term));
}
