//! Relational and equality guards, `is_int_ge`, range guards and `element/2` must give the same
//! results as erts for every pairing of small, big, float, atom and compound operands, whether
//! the fast path or the shared compare fragment decides.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;

const MODULE: &str = r#"
-module(guard_compare_probe).
-compile(export_all).
-compile(nowarn_export_all).

eq(X, Y) when X == Y -> true;
eq(_, _) -> false.
ne(X, Y) when X /= Y -> true;
ne(_, _) -> false.
lt(X, Y) when X < Y -> true;
lt(_, _) -> false.
ge(X, Y) when X >= Y -> true;
ge(_, _) -> false.
ge_const(X) when X >= 5 -> true;
ge_const(_) -> false.
const_ge(X) when 5 >= X -> true;
const_ge(_) -> false.
lt_const(X) when X < 5 -> true;
lt_const(_) -> false.
const_lt(X) when 5 < X -> true;
const_lt(_) -> false.
int_ge(X) when is_integer(X), X >= 10 -> true;
int_ge(_) -> false.
int_range(X) when is_integer(X), X >= 1, X =< 100 -> true;
int_range(_) -> false.
range(X) when X >= 1, X =< 100 -> true;
range(_) -> false.
ge_lt(X) when X >= 5, X < 10 -> true;
ge_lt(_) -> false.
both_ints(X, Y) when is_integer(X), is_integer(Y), X < Y -> true;
both_ints(_, _) -> false.
both_ints_ge(X, Y) when is_integer(X), is_integer(Y), X >= Y -> true;
both_ints_ge(_, _) -> false.
small_vs_int(X, Y) when is_integer(Y), (X band 16#ff) < Y -> true;
small_vs_int(_, _) -> false.
small_vs_int_ge(X, Y) when is_integer(Y), (X band 16#ff) >= Y -> true;
small_vs_int_ge(_, _) -> false.
int_vs_small(X, Y) when is_integer(X), X < (Y band 16#ff) -> true;
int_vs_small(_, _) -> false.
int_vs_small_ge(X, Y) when is_integer(X), X >= (Y band 16#ff) -> true;
int_vs_small_ge(_, _) -> false.
lit_cmp_lt(X) when X < {a, b} -> true;
lit_cmp_lt(_) -> false.
lit_cmp_ge(X) when X >= [a, b] -> true;
lit_cmp_ge(_) -> false.
bool_ge(X, Y) -> X >= Y.
bool_lt(X, Y) -> X < Y.
bool_eq(X, Y) -> X == Y.
elg(N, T) when element(N, T) =:= x -> true;
elg(_, _) -> false.
elg_const(T) when element(2, T) == x -> true;
elg_const(_) -> false.
elb(N, T) -> element(N, T).
elb_const(T) -> element(2, T).
elb_tuple(N, T) when is_tuple(T) -> element(N, T);
elb_tuple(_, _) -> none.
elb_tuple2(T) when is_tuple(T) -> element(2, T);
elb_tuple2(_) -> none.
elb_tuple_big(T) when is_tuple(T) -> element(200000000, T);
elb_tuple_big(_) -> none.

vals() ->
    [0, 1, -1, 5, 9, 10, 100, 101, (1 bsl 59) - 1, 1 bsl 59, -(1 bsl 59), -(1 bsl 59) - 1,
     1 bsl 70, -(1 bsl 70), 0.0, 1.0, 5.0, -2.5, 1.0e300, a, b, ok, [], [1], [a | b], [a, b],
     {}, {1}, {a, b}, {a, b, c}, <<>>, <<1>>, #{}, #{a => 1}, "abc", 16#ffff].

tuples() -> [{}, {a}, {a, x}, {a, b, c}, {x, x}, 1, [a], <<>>, #{}, {1, 2, 3, 4, 5, 6, 7, 8, 9}].
positions() -> [0, 1, 2, 3, 9, 10, -1, 1 bsl 70, -(1 bsl 70), a, 1.0, [], {1}].

t(F) ->
    try F() of
        V -> {ok, V}
    catch
        C:R:S -> {C, R, top(S)}
    end.

top([{M, F, A, _} | _]) -> {M, F, A};
top(S) -> S.

run() ->
    Vs = vals(),
    Pairs = [{X, Y} || X <- Vs, Y <- Vs],
    Two = [eq, ne, lt, ge, both_ints, both_ints_ge, small_vs_int, small_vs_int_ge,
           int_vs_small, int_vs_small_ge, bool_ge, bool_lt, bool_eq],
    One = [ge_const, const_ge, lt_const, const_lt, int_ge, int_range, range, ge_lt,
           lit_cmp_lt, lit_cmp_ge],
    R2 = [{F, [t(fun() -> guard_compare_probe:F(X, Y) end) || {X, Y} <- Pairs]} || F <- Two],
    R1 = [{F, [t(fun() -> guard_compare_probe:F(X) end) || X <- Vs]} || F <- One],
    EP = [{N, T} || N <- positions(), T <- tuples()],
    RE = [{F, [t(fun() -> guard_compare_probe:F(N, T) end) || {N, T} <- EP]} || F <- [elg, elb, elb_tuple]],
    RC = [{F, [t(fun() -> guard_compare_probe:F(T) end) || T <- tuples()]} || F <- [elg_const, elb_const, elb_tuple2, elb_tuple_big]],
    {R2, R1, RE, RC}.
"#;

#[test]
fn guard_comparisons_and_element_match_erts() {
    let reference = RefErl::start().expect("OTP 29.1.1 is required for this test");
    let beam = reference
        .compile_named("guard_compare_probe", MODULE, &[])
        .unwrap();
    reference.load("guard_compare_probe", &beam).unwrap();
    let expected = reference.call("guard_compare_probe", "run", &[]);

    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("guard_compare_probe", "run", &[], 1, None)
        .unwrap();

    assert_eq!(expected, CallResult::Ok(actual.term));
}
