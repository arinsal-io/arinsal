//! Trapped gc_bifs write their results to their encoded destination registers.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_term::global_atoms;
use arinsal_vm::Vm;
use similar_asserts::assert_eq;

const MODULE: &str = "interp_len_trap";
const SOURCE: &str = r#"-module(interp_len_trap).
-export([run/0]).
run() ->
    Seen = lists:duplicate(200000, item),
    Big = lists:duplicate(200000, $x),
    {done, 7, length(Seen), erlang:iolist_size(Big)}.
"#;

#[test]
fn trapping_gc_bifs_preserve_destinations() {
    let reference = RefErl::start().expect("erl reference");
    let beam = reference
        .compile_named(MODULE, SOURCE, &[])
        .expect("compile module");
    reference.load(MODULE, &beam).expect("load module");
    let want = match reference.call(MODULE, "run", &[]) {
        CallResult::Ok(term) => term,
        other => panic!("reference call failed: {other:?}"),
    };
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm.eval_scheduled(MODULE, "run", &[], 2, None).unwrap();
    let _ = global_atoms();
    assert_eq!(format!("{:?}", actual.term), format!("{want:?}"));
}
