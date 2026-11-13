use arinsal_difftest::{CallResult, RefErl};

#[test]
fn function_exported_matches_otp_for_exports_bifs_and_stubs() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping function_exported differential test");
        return;
    };
    let source = r#"
        -module(prim_lookup_function_exported).
        -export([run/0, unresolved/0]).
        run() -> Base={lists:reverse([loaded]) =:= [loaded],
                       erlang:function_exported(lists,reverse,1),
                       erlang:function_exported(erlang,self,0),
                       erlang:function_exported(erlang,apply,2),
                       erlang:function_exported(erlang,yield,0),
                       erlang:function_exported(prim_lookup_missing_module,f,0),
                       erlang:function_exported(prim_lookup_function_exported,missing,0)},
                 Before=erlang:function_exported(prim_lookup_function_exported,run,0),
                 true=erlang:delete_module(prim_lookup_function_exported),
                 After=erlang:function_exported(prim_lookup_function_exported,run,0),
                 {Base,Before,After}.
        unresolved() -> prim_lookup_missing_module:f().
    "#;
    let beam = reference
        .compile_named("prim_lookup_function_exported", source, &[])
        .unwrap();
    reference
        .load("prim_lookup_function_exported", &beam)
        .unwrap();
    let expected = reference.call("prim_lookup_function_exported", "run", &[]);
    let mut vm = crate::common::node();
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("prim_lookup_function_exported", "run", &[], 1)
        .unwrap();
    similar_asserts::assert_eq!(expected, CallResult::Ok(actual.term));
}

#[test]
fn get_all_matches_otp_for_empty_and_multiple_entries() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping get/0 differential test");
        return;
    };
    let source = r#"
        -module(prim_lookup_get_all).
        -export([empty/0, run/0]).
        empty() -> get().
        run() -> put(prim_lookup_key_a, first), put(prim_lookup_key_b, second),
                 Result=get(), erase(), Result.
    "#;
    let beam = reference
        .compile_named("prim_lookup_get_all", source, &[])
        .unwrap();
    // erts hashes a dictionary atom key by its atom index (erl_process_dict.c MAKE_HASH), so
    // the order of get/0 follows the atom table of the node: a booted node of its own on
    // each side, like erl, not the test binary's shared node.
    let expression = "{prim_lookup_get_all:empty(), prim_lookup_get_all:run()}";
    let expected =
        crate::common::erl_once("prim_lookup_get_all", source, expression).expect("erl one-shot");
    let actual = crate::common::arinsal_once("prim_lookup_get_all", &beam, expression);
    similar_asserts::assert_eq!(expected, actual);
}
