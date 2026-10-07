use arinsal_difftest::{CallResult, CompareMode, RefErl, compare};
use arinsal_vm::{Vm, VmError};

const SOURCE: &str = "-module(vm_records_bifs).\n\
    -export([create_query_update/0, errors/0, definition/0, native_syntax/0, native_record_order/0, native_record_roundtrip/0, internal_hash_record/0]).\n\
    -record(user, {id = 7, name = guest, active = true}).\n\
    -record #empty{}.\n\
    -record #order{zzzz = 0, true = 1, aaaa = 2, wwww = 3}.\n\
    create_query_update() ->\n\
        R = records:create(vm_records_bifs, user, [{name, alice}, {id, 11}], #{is_exported => true}),\n\
        U = records:update(R, '_', '_', #{id => 12}),\n\
        {records:get_module(R), records:get_name(R), records:is_exported(R),\n\
         records:get_field_names(R), records:get(id, U), records:get(name, U)}.\n\
    errors() ->\n\
        F = fun(Fun) -> try Fun() of V -> {ok, V} catch Class:Reason -> {Class, Reason} end end,\n\
        {F(fun() -> records:create(1, user, [], #{is_exported => true}) end),\n\
         F(fun() -> records:create(m, n, [], nope) end),\n\
         F(fun() -> records:create(m, n, [{1, value}], #{is_exported => true}) end),\n\
         F(fun() -> records:get(name, nope) end),\n\
         F(fun() -> records:get_field_names(nope) end)}.\n\
    definition() -> records:get_definition(vm_records_bifs, user).\n\
    native_syntax() ->\n\
        R = #user{}, U = R#user{name = alice, id = 9},\n\
        {R#user.id, R#user.name, U#user.id, U#user.name, record_info(fields, user)}.\n\
    native_record_order() ->\n\
        R = #order{},\n\
        B = records:create(vm_records_bifs, order,\n\
            [{zzzz, 0}, {true, 1}, {aaaa, 2}, {wwww, 3}], #{is_exported => false}),\n\
        {records:get_field_names(R),\n\
         [records:get(K, R) || K <- [zzzz, true, aaaa, wwww]],\n\
         [records:get(K, B) || K <- [zzzz, true, aaaa, wwww]]}.\n\
    native_record_roundtrip() ->\n\
        R = #order{}, P = binary_to_term(term_to_binary(R)),\n\
        {records:get_field_names(P), [records:get(K, P) || K <- [zzzz, true, aaaa, wwww]]}.\n\
    internal_hash_record() ->\n\
        erts_debug:set_internal_state(available_internal_state, true),\n\
        R = #empty{}, H = erts_debug:get_internal_state({internal_hash, R}),\n\
        erts_debug:set_internal_state(available_internal_state, false), H.\n";

fn run(function: &str) {
    let reference = RefErl::start().expect("OTP 29.1.1");
    let beam = reference
        .compile_named("vm_records_bifs", SOURCE, &[])
        .unwrap();
    reference.load("vm_records_bifs", &beam).unwrap();
    let expected = reference.call("vm_records_bifs", function, &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = match vm.eval_scheduled("vm_records_bifs", function, &[], 1, None) {
        Ok(outcome) => CallResult::Ok(outcome.term),
        Err(VmError::Raised(raised)) => CallResult::Exception {
            class: format!("{:?}", raised.class).to_lowercase(),
            reason: raised.reason,
            stack_top: Some(raised.stack),
        },
        Err(error) => CallResult::TransportError(error.to_string()),
    };
    compare(&expected, &actual, CompareMode::Exact)
        .unwrap_or_else(|diff| panic!("{function}: {diff}"));
}

#[test]
fn records_bifs_create_get_and_update_match_otp() {
    run("create_query_update");
}

#[test]
fn records_bifs_errors_match_otp() {
    run("errors");
}

#[test]
fn records_bifs_definition_uses_loaded_recs_chunk() {
    run("definition");
}

#[test]
fn records_bifs_native_record_syntax_matches_otp() {
    run("native_syntax");
}

#[test]
fn records_bifs_native_record_order_and_values_match_otp() {
    run("native_record_order");
}

#[test]
fn native_record_etf_roundtrip_preserves_field_order_and_values() {
    run("native_record_roundtrip");
}

#[test]
fn erts_debug_internal_hash_accepts_native_records() {
    run("internal_hash_record");
}
