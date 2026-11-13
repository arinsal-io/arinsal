//! Trapping BIFs called through `apply` (`erlang:F(..)`, `apply/3`) at sizes that exhaust the
//! reductions, with the reductions left varying between iterations: the result must be the
//! BIF's value, never the non-value of an installed continuation. Funs of BIF exports reach
//! the same BIFs through the export trampoline.
use arinsal_difftest::{CallResult, CompareMode, RefErl, compare};
use arinsal_etf::OwnedTerm;
use arinsal_term::{VecHeap, from_owned};
use arinsal_vm::VmError;

#[allow(dead_code)]
#[path = "common/mod.rs"]
mod common;

const SOURCE: &str = r#"
-module(vm_apply_trap_diff).
-export([run/1]).
id(X) -> X.
burn(0) -> ok;
burn(N) -> id(N), burn(N - 1).
red(V) when is_list(V) -> {list, length(V), erlang:phash2(V)};
red(V) -> V.
one(I, N) ->
    G = lists:seq(1, N),
    Bin = list_to_binary([X rem 256 || X <- lists:seq(1, N)]),
    L = id(length), E = id(erlang), Rv = id(reverse), Mb = id(member), Ap = id('++'),
    Sb = id('--'), Kf = id(keyfind), B2l = id(binary_to_list), Ph = id(phash2),
    Lists = id(lists), Apply = id(apply),
    burn(I * 13),
    A = erlang:L(G),
    burn(I * 7),
    B = apply(E, L, [G]),
    burn(I * 5),
    C = red(Lists:Rv(G, [])),
    burn(I * 3),
    D = Lists:Mb(N + 1, G),
    burn(I),
    F = red(E:Ap(G, [x])),
    burn(I * 11),
    H = red(E:Sb(G, [1, 2, 3])),
    burn(I * 2),
    K = Lists:Kf(N + 1, 1, [{X, X} || X <- G]),
    burn(I * 17),
    M = red(E:B2l(Bin)),
    burn(I * 19),
    P = E:Ph(G),
    Q = apply(Lists, Rv, [G, [a]]),
    R = E:Apply(E, L, [G]),
    Fl = id(fun erlang:length/1), Fr = id(fun lists:reverse/2),
    burn(I * 23),
    S = Fl(G),
    burn(I * 29),
    T = red(Fr(G, [b])),
    {A, B, red(C), D, F, H, K, M, P, red(Q), R, S, T}.
run(N) ->
    [one(I, N) || I <- lists:seq(1, 60)].
"#;

#[test]
fn trapping_bifs_through_apply_match_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping apply trap differential test");
        return;
    };
    let beam = reference
        .compile_named("vm_apply_trap_diff", SOURCE, &[])
        .unwrap();
    reference.load("vm_apply_trap_diff", &beam).unwrap();
    for size in [60_000i64, 250_000] {
        let args = [OwnedTerm::Int(size)];
        let expected = reference.call("vm_apply_trap_diff", "run", &args);

        let mut vm = common::node();
        common::load_fresh(&mut vm, &beam);
        let mut heap = VecHeap::new();
        let term = from_owned(&args[0], &mut heap).unwrap();
        let actual = match vm.eval_scheduled("vm_apply_trap_diff", "run", &[term], 1) {
            Ok(outcome) => CallResult::Ok(outcome.term),
            Err(VmError::Raised(raised)) => CallResult::Exception {
                class: format!("{:?}", raised.class).to_lowercase(),
                reason: raised.reason,
                stack_top: Some(raised.stack),
            },
            Err(error) => CallResult::TransportError(error.to_string()),
        };
        compare(&expected, &actual, CompareMode::Exact)
            .unwrap_or_else(|error| panic!("apply trap mismatch at size {size}: {error}"));
    }
}
