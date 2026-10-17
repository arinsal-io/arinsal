//! Differential test (against the reference `erl`) for the BeamAsm `update_record` instruction.
//!
//! The fixture is generated: for tuple records of many sizes (around the 16 word inline copy
//! limit and the vector loop, odd and even tails) and many shapes of updated fields (single,
//! adjacent pair, gapped pair, runs, every field) it updates a record with the values it already
//! holds, with new values, with equal but distinct values and with a mix. A single update
//! compiles to `update_record reuse`: erts returns the source tuple itself when the new value is
//! the stored one, which the fixture observes with `erts_debug:same/2`. Operands live in X
//! registers, in Y registers (after a call) and the result is parked in a Y register.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;
use std::fmt::Write as _;

const SIZES: &[usize] = &[
    2, 3, 4, 5, 6, 7, 8, 9, 15, 16, 17, 18, 19, 20, 21, 24, 25, 26,
];

fn shapes(n: usize) -> Vec<Vec<usize>> {
    let mut shapes: Vec<Vec<usize>> = vec![vec![1], vec![n]];
    if n > 2 {
        shapes.push(vec![n / 2 + 1]);
    }
    if n >= 2 {
        shapes.push(vec![1, 2]);
        shapes.push(vec![n - 1, n]);
        shapes.push(vec![1, n]);
    }
    if n >= 4 {
        shapes.push(vec![2, 3, 4]);
        shapes.push(vec![1, 3, n]);
    }
    if n >= 6 {
        shapes.push(vec![2, 5]);
        shapes.push(vec![1, 3, 5]);
    }
    if n <= 9 {
        shapes.push((1..=n).collect());
    }
    shapes.sort();
    shapes.dedup();
    shapes
}

fn fixture() -> String {
    let mut src = String::from(
        "-module(jit_update_record_fx).\n-export([run/0]).\n-compile(nowarn_unused_record).\n\
         id(X) -> X.\n",
    );
    let mut parts = Vec::new();
    for &n in SIZES {
        let mut cases = Vec::new();
        let fields: Vec<String> = (1..=n).map(|k| format!("f{k}")).collect();
        writeln!(src, "-record(r{n}, {{{}}}).", fields.join(",")).unwrap();
        let init: Vec<String> = (1..=n).map(|k| format!("f{k}=[I,{k}]")).collect();
        writeln!(src, "mk{n}(I) -> #r{n}{{{}}}.", init.join(",")).unwrap();
        for ks in shapes(n) {
            let tag = format!(
                "{n}_{}",
                ks.iter()
                    .map(usize::to_string)
                    .collect::<Vec<_>>()
                    .join("_")
            );
            let vars: Vec<String> = (1..=ks.len()).map(|i| format!("V{i}")).collect();
            let args = vars.join(",");
            let sets: Vec<String> = ks
                .iter()
                .zip(&vars)
                .map(|(k, v)| format!("f{k}={v}"))
                .collect();
            let sets = sets.join(",");
            writeln!(src, "ux_{tag}(R,{args}) -> R#r{n}{{{sets}}}.").unwrap();
            writeln!(
                src,
                "uy_{tag}(R,{args}) -> A = id(R), id(0), A#r{n}{{{sets}}}."
            )
            .unwrap();
            writeln!(
                src,
                "ud_{tag}(R,{args}) -> Z = R#r{n}{{{sets}}}, id(Z), id(0), Z."
            )
            .unwrap();
            let ks_list = ks
                .iter()
                .map(usize::to_string)
                .collect::<Vec<_>>()
                .join(",");
            for variant in ["ux", "uy", "ud"] {
                cases.push(format!(
                    "case_(mk{n}(id(7)), [{ks_list}], fun {variant}_{tag}/{})",
                    ks.len() + 1
                ));
            }
        }
        writeln!(src, "part{n}() -> [{}].", cases.join(",\n    ")).unwrap();
        parts.push(format!("part{n}()"));
    }
    src.push_str(
        r#"
case_(R, Ks, F) ->
    Cur = [element(K + 1, R) || K <- Ks],
    Same = apply(F, [R | Cur]),
    Diff = apply(F, [R | [{new, K} || K <- Ks]]),
    Copy = apply(F, [R | [binary_to_term(term_to_binary(V)) || V <- Cur]]),
    Mixed = apply(F, [R | [case I of 1 -> V; _ -> {mix, I} end
                           || {I, V} <- lists:zip(lists:seq(1, length(Cur)), Cur)]]),
    Last = apply(F, [R | [case I of 1 -> {last, I}; _ -> V end
                          || {I, V} <- lists:zip(lists:seq(1, length(Cur)), Cur)]]),
    {Ks, erts_debug:same(R, Same), Same, Diff, erts_debug:same(R, Copy), Copy,
     erts_debug:same(R, Mixed), Mixed, erts_debug:same(R, Last), Last, R}.

imm_same(R) -> R2 = R#r5{f3 = foo}, {erts_debug:same(R, R2), R2}.
imm_keep(R) -> R2 = R#r5{f3 = id(foo)}, {erts_debug:same(R, R2), R2}.

loop(0, R) -> R;
loop(N, R) -> loop(N - 1, R#r5{f2 = N rem 3}).

chain(R0, V) ->
    R1 = R0#r17{f9 = V},
    R2 = R1#r17{f9 = V},
    R3 = R2#r17{f17 = id(R2#r17.f17)},
    {erts_debug:same(R0, R1), erts_debug:same(R1, R2), erts_debug:same(R2, R3), R3}.

gc_loop(0, Acc) -> Acc;
gc_loop(N, Acc) ->
    R = mk26(N),
    R2 = R#r26{f26 = [N | Acc]},
    R3 = R2#r26{f26 = element(27, R2)},
    gc_loop(N - 1, [length(element(27, R3)) | lists:sublist(Acc, 3)]).

run() ->
    lists:append([
"#,
    );
    src.push_str(&parts.join(",\n    "));
    src.push_str(
        r#"]) ++ [
    {imm_same, imm_same(setelement(4, mk5(id(1)), foo)), imm_same(mk5(id(1)))},
    {imm_keep, imm_keep(setelement(4, mk5(id(1)), foo))},
    {loop, loop(1000, mk5(id(2)))},
    {chain, chain(mk17(id(1)), id(x)), chain(setelement(10, mk17(id(1)), x), id(x))},
    {gc, gc_loop(3000, [])}
    ].
"#,
    );
    src
}

#[test]
fn update_record_matches_erts() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping update_record differential test");
        return;
    };
    let source = fixture();
    let beam = reference
        .compile_named("jit_update_record_fx", &source, &[])
        .expect("compile update_record fixture");
    reference
        .load("jit_update_record_fx", &beam)
        .expect("load reference fixture");
    let expected = reference.call("jit_update_record_fx", "run", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load VM fixture");
    let actual = vm
        .eval_scheduled("jit_update_record_fx", "run", &[], 2, None)
        .unwrap_or_else(|error| panic!("run: {error}"));
    let CallResult::Ok(expected_term) = expected else {
        panic!("reference failed: {expected:?}");
    };
    let (
        arinsal_etf::OwnedTerm::List { elems: want, .. },
        arinsal_etf::OwnedTerm::List { elems: got, .. },
    ) = (&expected_term, &actual.term)
    else {
        panic!(
            "expected lists, got {expected_term:?} and {:?}",
            actual.term
        );
    };
    assert_eq!(want.len(), got.len(), "case count");
    for (index, (want, got)) in want.iter().zip(got).enumerate() {
        assert_eq!(want, got, "case {index}");
    }
}
