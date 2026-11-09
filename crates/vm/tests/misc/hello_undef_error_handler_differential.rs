use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;
use similar_asserts::assert_eq;

const MODULE: &str = "hello_undef_error_handler_diff";
const SOURCE: &str = r#"
-module(hello_undef_error_handler_diff).
-export([run/0]).

run() ->
    Old = process_flag(error_handler, missing_error_handler_diff),
    try
        Module = id(bad_module),
        DynamicArgs = try Module:whatever(42)
                      catch error:undef:DynamicStack ->
                          [{bad_module, whatever, DynamicArgsInStack, _} | _] = DynamicStack,
                          DynamicArgsInStack
                      end,
        ApplyArgs = try apply(Module, whatever, [42])
                    catch error:undef:ApplyStack ->
                        [{bad_module, whatever, ApplyArgsInStack, _} | _] = ApplyStack,
                        ApplyArgsInStack
                    end,
        {DynamicArgs, ApplyArgs}
    after
        process_flag(error_handler, Old)
    end.

id(Value) -> Value.
"#;

#[test]
fn missing_error_handler_keeps_original_undefined_call_arguments() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping differential check");
        return;
    };
    let beam = reference.compile_named(MODULE, SOURCE, &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();
    let expected = reference.call(MODULE, "run", &[]);

    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm.eval_scheduled(MODULE, "run", &[], 1, None).unwrap();
    assert_eq!(expected, CallResult::Ok(actual.term));
}
