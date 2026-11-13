use arinsal_difftest::RefErl;
use similar_asserts::assert_eq;

#[test]
fn heap_size_schedule_matches_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping heap-size schedule differential test");
        return;
    };
    let module = "heap_sizes_differential";
    let beam = reference
        .compile_named(
            module,
            "-module(heap_sizes_differential). -export([run/0]). run() -> erlang:system_info(heap_sizes).",
            &[],
        )
        .unwrap();
    let expected = reference.eval("erlang:system_info(heap_sizes)").unwrap();
    let mut vm = crate::common::node();
    vm.load_bytes(&beam).unwrap();
    let actual = vm.eval_scheduled(module, "run", &[], 1).unwrap().term;

    assert_eq!(actual, expected);
}
