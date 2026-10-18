use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(proc_receive_timeout_diff).
-export([run/0]).

run() -> [fails(T) || T <- [
    -1, 0.0, 3.14, 16#100000000,
    392347129847294724972398472984729847129874,
    16#3fffffffffffffff, 16#ffffffffffffffff,
    -16#100000000, -3891278094774921784123987129848, invalid_timeout
]].

fails(Timeout) ->
    {'EXIT', {timeout_value, _}} = (catch receive after Timeout -> ok end),
    true.
"#;

#[test]
fn invalid_receive_timeouts_match_erts() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping receive timeout differential");
        return;
    };
    let beam = reference
        .compile_named("proc_receive_timeout_diff", SOURCE, &[])
        .expect("compile receive timeout differential");
    reference
        .load("proc_receive_timeout_diff", &beam)
        .expect("load receive timeout differential");
    let expected = reference.call("proc_receive_timeout_diff", "run", &[]);

    let mut vm = Vm::new([]);
    vm.load_bytes(&beam)
        .expect("load receive timeout differential");
    let actual = vm
        .eval_scheduled("proc_receive_timeout_diff", "run", &[], 2, None)
        .expect("run receive timeout differential")
        .term;

    let all_invalid = OwnedTerm::List {
        elems: vec![OwnedTerm::atom("true"); 10],
        tail: Box::new(OwnedTerm::Nil),
    };
    similar_asserts::assert_eq!(expected, CallResult::Ok(all_invalid), "erts timeout errors");
    similar_asserts::assert_eq!(expected, CallResult::Ok(actual), "Arinsal timeout errors");
}
