//! `select_val` on atoms and integers must dispatch every value to its own clause and send every
//! other value to the fallback, whether the pairs are searched linearly or in a binary tree, and
//! whatever order the compiler wrote the clauses in.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;

const MODULE: &str = r#"
-module(select_val_probe).
-compile(export_all).
-compile(nowarn_export_all).

few_atoms(zulu) -> 1;
few_atoms(alpha) -> 2;
few_atoms(undefined) -> 3;
few_atoms(mike) -> 4;
few_atoms(ordered) -> 5;
few_atoms(reversed) -> 6;
few_atoms(bravo) -> 7;
few_atoms(_) -> other.

ten_atoms(j) -> 1;
ten_atoms(i) -> 2;
ten_atoms(h) -> 3;
ten_atoms(g) -> 4;
ten_atoms(f) -> 5;
ten_atoms(e) -> 6;
ten_atoms(d) -> 7;
ten_atoms(c) -> 8;
ten_atoms(b) -> 9;
ten_atoms(a) -> 10;
ten_atoms(_) -> other.

many_atoms(m26) -> 26;
many_atoms(m3) -> 3;
many_atoms(m17) -> 17;
many_atoms(m9) -> 9;
many_atoms(m21) -> 21;
many_atoms(m1) -> 1;
many_atoms(m12) -> 12;
many_atoms(m24) -> 24;
many_atoms(m6) -> 6;
many_atoms(m14) -> 14;
many_atoms(m19) -> 19;
many_atoms(m2) -> 2;
many_atoms(m23) -> 23;
many_atoms(m8) -> 8;
many_atoms(m15) -> 15;
many_atoms(m5) -> 5;
many_atoms(m25) -> 25;
many_atoms(m11) -> 11;
many_atoms(m4) -> 4;
many_atoms(m22) -> 22;
many_atoms(m13) -> 13;
many_atoms(m7) -> 7;
many_atoms(m18) -> 18;
many_atoms(m10) -> 10;
many_atoms(m20) -> 20;
many_atoms(m16) -> 16;
many_atoms(_) -> other.

few_ints(900) -> a;
few_ints(-5) -> b;
few_ints(40) -> c;
few_ints(7) -> d;
few_ints(1000000) -> e;
few_ints(0) -> f;
few_ints(-1000) -> g;
few_ints(_) -> other.

runs(14) -> x;
runs(3) -> y;
runs(11) -> x;
runs(2) -> y;
runs(12) -> x;
runs(1) -> y;
runs(13) -> x;
runs(40) -> z;
runs(_) -> other.

same_target(q) -> hit;
same_target(w) -> hit;
same_target(e) -> hit;
same_target(r) -> miss;
same_target(t) -> hit;
same_target(_) -> other.

atoms() ->
    [zulu, alpha, undefined, mike, ordered, reversed, bravo, a, b, c, d, e, f, g, h, i, j,
     q, w, r, t, none, nil, true, false, '' | [list_to_atom("m" ++ integer_to_list(N)) || N <- lists:seq(0, 28)]].

ints() ->
    [900, -5, 40, 7, 1000000, 0, -1000, 1, 2, 3, 4, 11, 12, 13, 14, 15, 39, 41, -6, 901, 16#7fffffff,
     1 bsl 70, -(1 bsl 70)].

others() -> [1.0, <<>>, [], {a}, #{}].

run() ->
    As = atoms() ++ others(),
    Is = ints() ++ others(),
    {[{A, few_atoms(A), ten_atoms(A), many_atoms(A), same_target(A)} || A <- As],
     [{I, few_ints(I), runs(I)} || I <- Is]}.
"#;

#[test]
fn select_val_dispatches_every_value_like_erts() {
    let reference = RefErl::start().expect("OTP 29.1.1 is required for this test");
    let beam = reference
        .compile_named("select_val_probe", MODULE, &[])
        .unwrap();
    reference.load("select_val_probe", &beam).unwrap();
    let expected = reference.call("select_val_probe", "run", &[]);

    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("select_val_probe", "run", &[], 1, None)
        .unwrap();

    assert_eq!(expected, CallResult::Ok(actual.term));
}
