//! Differential regressions for BeamAsm code paths: native results must match the
//! interpreter and OTP 29.1.1.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;
use std::process::Command;

const CHILD: &str = "ARINSAL_NATIVE_REGRESS_CHILD";
const CHILD_MODULE: &str = "ARINSAL_NATIVE_REGRESS_MODULE";
const MODULE: &str = "native_regress_test";
const GC_MODULE: &str = "native_regress_gc";
const FRAMES_MODULE: &str = "native_regress_frames";
// Value-producing comparison BIFs (`bif_is_eq_exact`, `bif_is_ne_exact`, `bif_is_lt`,
// `bif_is_ge`): immediate, small-typed and generic operand paths.
const COMPARE_MODULE: &str = "native_compare_bifs";
const COMPARE_SOURCE: &str = r#"-module(native_compare_bifs).
-export([run/0]).
-compile(no_inline).
eq0(X) -> X =:= 0.
ne0(X) -> X =/= 0.
eqa(X) -> X =:= ok.
eqg(X, Y) -> X =:= Y.
neg(X, Y) -> X =/= Y.
lt(X, Y) -> X < Y.
ge(X, Y) -> X >= Y.
ge5(X) -> X >= 5.
lt5(X) -> X < 5.
gei(X) when is_integer(X) -> {X >= 5, 5 >= X, X < 5, 5 < X}.
gesm(X, Y) when is_integer(X), X > -10, X < 10, is_integer(Y) -> {X >= Y, Y >= X, X < Y, Y < X}.
geib(X, Y) when is_integer(X), is_tuple(Y) -> {X >= Y, X < Y, Y >= X, Y < X}.
run() ->
    Vs = [0, 1, -1, 5, 4, 6, 1 bsl 70, -(1 bsl 70), 0.0, 5.0, 4.9, ok, [], [1], {}, {1}, <<>>, self(), #{}, "a"],
    R = [{eq0(A), ne0(A), eqa(A), ge5(A), lt5(A),
          [{eqg(A,B), neg(A,B), lt(A,B), ge(A,B)} || B <- Vs]} || A <- Vs],
    I = [gei(A) || A <- [0, 5, 4, 6, 1 bsl 70, -(1 bsl 70)]],
    S = [gesm(A, B) || A <- [-9, 0, 5, 9], B <- [-9, 0, 5, 9, 1 bsl 70, -(1 bsl 70)]],
    B = [geib(A, T) || A <- [0, 1 bsl 70], T <- [{}, {1}]],
    {R, I, S, B}.
"#;
const BIF_FRAMES_MODULE: &str = "native_bif_frames";

const BIF_FRAMES_SOURCE: &str = r#"-module(native_bif_frames).
-export([run/0]).

frames([{M, F, A, Info}, {CallerM, CallerF, CallerA, _} | _]) ->
    [{M, F, A, Info}, {CallerM, CallerF, CallerA}].
set_state() ->
    try erts_debug:set_internal_state(foo, foo)
    catch Class:Reason:Stack -> {Class, Reason, frames(Stack)} end.
run() ->
    Dirty1 = try erts_debug:dirty_cpu(reschedule, 1001)
             catch Class1:Reason1:Stack1 -> {Class1, Reason1, frames(Stack1)} end,
    Dirty2 = try erts_debug:dirty_cpu(reschedule, 1001)
             catch Class2:Reason2:Stack2 -> {Class2, Reason2, frames(Stack2)} end,
    [Dirty1, Dirty2, set_state(), set_state()].
"#;

// A failing BIF is the top frame and the calling function the next one, including BIFs
// the scheduler runs for native code (spawn/3) and BIF calls in tail position.
const FRAMES_SOURCE: &str = r#"-module(native_regress_frames).
-export([run/0]).

bad(e_node) -> node(xxx);
bad(e_plus) -> 1 + b;
bad(e_spawn) -> spawn({}, {}, {});
bad(e_tail_spawn) -> erlang:spawn(id({}), {}, {}).
id(X) -> X.
f(W) -> catch bad(W).

run() ->
    [begin {'EXIT', {R, S}} = f(W), {R, [{M, F, A} || {M, F, A, _} <- lists:sublist(S, 3)]} end
     || W <- [e_node, e_plus, e_spawn, e_tail_spawn]].
"#;

// Match contexts, extracted binaries and tails must survive a collection at every allocation,
// including one inside a call made while the context is saved in a Y register.
const GC_SOURCE: &str = r#"-module(native_regress_gc).
-export([run/0]).

lines(<<>>, Acc) -> lists:reverse(Acc);
lines(Bin, Acc) ->
    case line(Bin, Bin, []) of
        {stop, Line, Rest} -> lines(Rest, [Line | Acc]);
        More -> lists:reverse([More | Acc])
    end.

line(<<$\n, T/binary>>, Data, Stack) ->
    N = byte_size(Data) - byte_size(T),
    <<Line:N/binary, _/binary>> = Data,
    {stop, rev(Stack, [Line]), T};
line(<<$\r, $\n, T/binary>>, Data, Stack) ->
    N = byte_size(Data) - byte_size(T) - 2,
    <<Line:N/binary, _/binary>> = Data,
    {stop, rev(Stack, [Line, $\n]), T};
line(<<_, T/binary>>, Data, Stack) -> line(T, Data, Stack);
line(<<>>, Data, Stack) -> [Data | Stack].

rev(L, T) -> list_to_binary(lists:reverse(L, T)).

floats(<<F:32/float, R/binary>>, Acc) -> floats(R, [F | Acc]);
floats(<<>>, Acc) -> Acc.

run() ->
    Text = iolist_to_binary([[integer_to_list(I), " line\r\n", binary:copy(<<"x">>, I), "\n"]
                             || I <- lists:seq(1, 90)]),
    Floats = << <<(float(I)):32/float>> || I <- lists:seq(1, 50) >>,
    {lines(Text, []), lists:sum(floats(Floats, [])),
     [binary_part(Text, 0, 70) =:= Chunk || <<Chunk:70/binary, _/binary>> <- [Text]]}.
"#;

// Each case is evaluated separately so one mismatch names its case. Stack frames are cut to
// {M,F,Arity-or-Args} because line information of the caller differs between runs.
const SOURCE: &str = r#"-module(native_regress_test).
-export([run/0]).

top({'EXIT', {Reason, [{M, F, A, _} | _]}}) -> {Reason, M, F, A};
top(Other) -> Other.

id(X) -> X.

ib(B) when is_binary(B) -> yes;
ib(_) -> no.

ge(X) when is_integer(X), X >= 3 -> big;
ge(_) -> small.

fc1(one) -> ok.
fc3(a, b, c) -> ok.

call1(F) -> F(1).
call2(F, A) -> F(A, 2).

e(N, T) -> element(N, T).
h(L) -> hd(L).
t(L) -> tl(L).
g(N, T) when element(N, T) =:= a -> yes;
g(_, _) -> no.

cc(X) -> case X of a -> 1 end.
bm(X) -> {ok, _} = X.
tc(X) -> try X of a -> 1 after ok end.

wide(K, [A], F, Adj, P, Pad, Enc, Str, Ord, CL, I) when K =:= $p ->
    narrow(A, -1, F, Adj, P, Pad, Enc, list, Str, Ord, CL, I);
wide(_, _, _, _, _, _, _, _, _, _, _) -> other.

narrow(A, B, C, D, E, F, G, H, I, J, K, L) -> {A, B, C, D, E, F, G, H, I, J, K, L}.

bs(X) -> {byte_size(X), bit_size(X)}.
gbs(X) when byte_size(X) > 1 -> big;
gbs(X) when bit_size(X) >= 0 -> small;
gbs(_) -> other.
misc(X) -> [catch length(X), catch abs(X), catch tuple_size(X), catch map_size(X)].

rr(X) -> try throw(X) catch error:_ -> no end.

ov(<<_:144115188075855872/binary-unit:128, 0, _/binary>>) -> 2;
ov(<<_:33554432/binary-unit:128, 0, _/binary>>) -> 1;
ov(_) -> nomatch.
sk(N, B) -> <<_:N/binary, R/binary>> = B, R.
ar(A, B) -> {A + B, A div B}.
nzm(A, B) -> <<(A * B)/float>>.
nzn(A) -> <<(-A)/float>>.
hmf(#{a := _, b := _}) -> ab;
hmf(#{[] := _, 42.0 := _}) -> boxed;
hmf(#{#{k => v} := V}) -> {map_key, V};
hmf(#{}) -> none.
body_key_loop(0, _M, _K, Acc) -> Acc;
body_key_loop(N, M, K, Acc) ->
    Present = is_map_key(K, M),
    Value = case Present of true -> 1; false -> 0 end,
    body_key_loop(N - 1, M, K, Acc + Value).
body_get_loop(0, _M, _K, Acc) -> Acc;
body_get_loop(N, M, K, Acc) -> body_get_loop(N - 1, M, K, Acc + map_get(K, M)).
body_map_bifs() ->
    Flat = #{a => 1},
    Hash = maps:from_list([{I, I + 1} || I <- lists:seq(0, 39)]),
    Boxed = #{{k} => 41},
    [is_map_key(a, Flat), is_map_key(c, Flat), map_get(a, Flat),
     is_map_key(27, Hash), map_get(27, Hash),
     is_map_key({k}, Boxed), map_get({k}, Boxed),
     tmk(Boxed), tmk(Flat), tmk(maps:put({k}, 0, Hash)), tmk(Hash),
     top(catch is_map_key(a, not_a_map)), top(catch map_get(a, not_a_map)),
     top(catch map_get(c, Flat)),
     body_key_loop(100, Flat, a, 0), body_key_loop(100, Flat, c, 0),
     body_get_loop(100, Flat, a, 0),
     body_key_loop(100, Hash, 27, 0), body_get_loop(100, Hash, 27, 0)].
tmk(M) when is_map(M) -> is_map_key({k}, M).
gar(A) when A + 1 > 2 -> big;
gar(_) -> small.
gl(L) when length(L) >= 0 -> ok;
gl(_) -> error.
ga(X) when abs(X) > 1 -> big;
ga(_) -> small.
gn(P) when node(P) =:= nonode@nohost -> local;
gn(_) -> other.
gm(K, M) when map_get(K, M) =:= 1 -> one;
gm(_, _) -> other.
gk(K, M) when is_map_key(K, M) -> yes;
gk(_, _) -> no.
rr2() -> try e(5, {a}) catch throw:_ -> no end.
tsz(A) -> tuple_size(A).
cec() -> try cec1(fun() -> throw(arne) end) catch C:R -> {C, R} end.
cec1(F) -> try cec2(F) after ok end.
cec2(F) -> try F() catch throw:R:S -> erlang:raise(error, R, S) end.
lnc(W) ->
    try
        lnc1(W),
        lnc1(crash)
    catch error:crash:S -> [L || {_, _, _, [_, {line, L}]} <- lists:sublist(S, 2)]
    end.
lnc1(W) -> case id(W) of crash -> erlang:error(crash); _ -> ok end.
ea(T) -> try ea1(T) catch error:oops:S -> [{M, F, A} || {M, F, A, _} <- lists:sublist(S, 2)] end.
ea1(apply) -> erlang:apply(id(erlang), id(error), id([oops, [apply]])), ok;
ea1(apply_last) -> erlang:apply(id(erlang), id(error), id([oops, [apply_last]]));
ea1(double) -> erlang:apply(id(erlang), id(apply), [id(erlang), id(error), id([oops, [double]])]), ok;
ea1(fixed) -> erlang:apply(erlang, apply, [erlang, error, [oops, [fixed]]]), ok.
rec(0) -> erlang:error(oops);
rec(N) -> rec(N - 1), id(ok).
recs() -> try rec(3) catch error:oops:S -> length([x || {_, rec, _, _} <- S]) end.
bsz(S) -> <<0:S>>.
bsi() -> try bsz(id(bad)) catch error:badarg:S -> [{_, _, _, L} | _] = S, lists:keyfind(error_info, 1, L) end.
cl() -> {current_location, {_, F, A, [_, Line]}} = process_info(self(), current_location), {F, A, Line}.
burn(0) -> ok;
burn(N) -> burn(N - 1).
rd() -> {R0, _} = statistics(reductions), burn(id(100000)), {R1, _} = statistics(reductions), R1 - R0 >= 100000.
% `ok` predates the fresh atom, so flatmap (atom index) order differs from name order.
mkm(L, F) -> #{ok => L, aaa_fresh_key => F}.

run() ->
    Buf = prim_buffer:new(),
    [[ge(1), ge(3), ge(a), ge(3.5)],
     top(catch fc1(two)),
     top(catch fc3(a, b, x)),
     top(catch call1(fun(A, B) -> A + B end)),
     top(catch call1(not_a_fun)),
     top(catch call2(fun lists:reverse/1, x)),
     call1(erlang:make_fun(erlang, abs, 1)),
     erlang:fun_info(erlang:make_fun(lists, reverse, 1), arity),
     [catch apply(F, A) || {F, A} <- [{fun erlang:element/2, [1, {a}]},
                                       {fun erlang:max/2, [1, 2]}]],
     [top(catch e(N, T)) || {N, T} <- [{1, {a, b}}, {3, {a}}, {0, {a}}, {x, {a}}, {1, x}]],
     [g(1, {a}), g(2, {a}), g(1, x)],
     [top(catch h(L)) || L <- [[1], [], x]],
     [top(catch t(L)) || L <- [[1, 2], <<1>>]],
     [top(catch cc(b)), top(catch bm(x)), top(catch tc(b))],
     wide($p, [{a, 1}], 3, 4, 5, 6, 7, 8, 9, 10, 11),
     prim_buffer:size(Buf),
     top(catch prim_buffer:size(x)),
     lists:flatten(io_lib:format("~p ~w ~s", [{a, "b", 1.5}, [1, 2], "c"])),
     [bs(B) || B <- [<<>>, <<1>>, <<1:9>>, <<1,2,3:5>>, binary:part(<<1,2,3,4>>, 1, 2)]],
     [top(catch bs(X)) || X <- [x, 1, [1], {1}]],
     [gbs(X) || X <- [<<1,2>>, <<1>>, <<1:3>>, x, [], 1.0]],
     [[case R of {'EXIT', {Reason, _}} -> Reason; _ -> R end || R <- misc(X)]
      || X <- [[1, 2], [1 | 2], -5, 1 bsl 70, {a, b}, #{a => 1}, x]],
     catch rr(x),
     [top(catch ar(1, 0)), top(catch ar(1, ok)), top(catch -id(a)), top(catch bnot id(1.0)),
      gar(5), nzm(id(-1.0), id(0.0)), nzm(id(0), id(-0.0)), nzm(id(-1), id(0.0)), nzn(id(0.0))],
     [hmf(M) || M <- [#{a => 1, b => 2}, #{[] => 1, 42.0 => 2}, #{#{k => v} => 3}, #{42.0 => 1}, #{}]],
     body_map_bifs(),
     [top(catch length(id([1 | 2]))), top(catch abs(id(a))),
      top(catch map_get(a, id(#{}))), top(catch map_get(a, id(x))), top(catch is_map_key(a, id(x)))],
     [gl([1, 2]), gl([1 | 2]), gl(x), ga(-5), ga(x), ga(0), gn(self()), gn(x),
      gm(a, #{a => 1}), gm(b, #{a => 1}), gm(a, x), gk(a, #{a => 1}), gk(b, #{}), gk(a, x)],
     [ov(<<0:64, 0>>), sk(2, <<1, 2, 3>>), top(catch sk(-1, <<1>>)), top(catch sk(a, <<1>>))],
     re:replace(<<"a\nb\nc">>, "\n", "<br />", [global, {return, binary}]),
     erlang:phash2([lists:flatten(io_lib:format("      ~w: { sorter: '~s' },\n", [I, "CTValSorter"]))
                    || I <- lists:seq(1, 300)]),
     try rr2() catch C:R:S -> {C, R, [{M, F} || {M, F, _, _} <- lists:sublist(S, 2)]} end,
     [mkm(1, 2) =:= maps:from_list([{aaa_fresh_key, 2}, {ok, 1}]),
      [mkm(1, 2)] =:= binary_to_term(term_to_binary([mkm(1, 2)])),
      (id(mkm(1, 2)))#{ok := 3, aaa_fresh_key => 4} =:= #{ok => 3, aaa_fresh_key => 4},
      map_size((id(mkm(1, 2)))#{ok => 5}), maps:get(ok, (id(mkm(1, 2)))#{ok => 5}),
      maps:keys(mkm(1, 2))],
     [top(catch tsz(id([a]))), cec(), lnc(crash), lnc(x),
      try erlang:fun_info(id(abc), module) catch C2:R2 -> {C2, R2} end],
     [max(id({1.0, b}), id({1, b})), min(id(1), id(1.0)), recs(),
      [ea(T) || T <- [apply, apply_last, double, fixed]]],
     [bsi(), cl(), rd()],
     begin
         Off = list_to_binary(lists:duplicate(80, $a)),
         Part = binary:part(Off, 1, 3),
         [ib(Part), ib(Off), ib(<<"literal">>), ib(<<>>), ib(<<5:3>>), ib(id(<<"x">>)), ib(a)]
     end].
"#;

/// Runs `module:run/0` in a child test process when this process is one; returns whether it was.
fn run_child_case() -> bool {
    let Some(beam_path) = std::env::var_os(CHILD) else {
        return false;
    };
    let module = std::env::var(CHILD_MODULE).unwrap();
    let mut vm = Vm::new([]);
    vm.load_bytes(&std::fs::read(beam_path).unwrap()).unwrap();
    let actual = vm.eval_scheduled(&module, "run", &[], 1, None).unwrap();
    println!("RESULT:{}", actual.text);
    true
}

/// Compares `module:run/0` under BeamAsm, under the interpreter and under OTP 29.1.1.
fn assert_native_matches(
    test: &str,
    module: &str,
    source: &str,
    native: &str,
    env: &[(&str, &str)],
) {
    assert_native_matches_with(test, module, source, native, env, true);
}

/// Like [`assert_native_matches`]; `compare_interpreter` is false where the interpreter still
/// diverges from OTP, so only BeamAsm is held to the OTP result.
fn assert_native_matches_with(
    test: &str,
    module: &str,
    source: &str,
    native: &str,
    env: &[(&str, &str)],
    compare_interpreter: bool,
) {
    let reference = RefErl::start().expect("OTP 29.1.1 is required for this test");
    let beam = reference.compile_named(module, source, &[]).unwrap();
    reference.load(module, &beam).unwrap();
    let expected = match reference.call(module, "run", &[]) {
        CallResult::Ok(term) => format!("{term}"),
        other => panic!("OTP call failed: {other:?}"),
    };

    let dir = std::env::temp_dir().join(format!("arinsal-{test}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let beam_path = dir.join(format!("{module}.beam"));
    std::fs::write(&beam_path, beam).unwrap();
    let run_child = |beamasm: bool| {
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test, "--nocapture"])
            .env(CHILD, &beam_path)
            .env(CHILD_MODULE, module)
            .env("ARINSAL_BEAMASM", if beamasm { "1" } else { "0" })
            .env("ARINSAL_BEAMASM_MODULES", native)
            .envs(env.iter().copied())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{} child failed ({:?}): stdout={} stderr={}",
            if beamasm { "native" } else { "interpreter" },
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .find_map(|line| line.strip_prefix("RESULT:"))
            .expect("child prints a result")
            .to_owned()
    };
    let native = run_child(true);
    if compare_interpreter {
        let interpreted = run_child(false);
        assert_eq!(
            native, interpreted,
            "BeamAsm result must match the interpreter"
        );
        assert_eq!(interpreted, expected, "interpreter result must match OTP");
    } else {
        assert_eq!(native, expected, "BeamAsm result must match OTP");
    }
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
#[cfg(target_arch = "aarch64")]
fn native_regressions_match_interpreter_and_otp() {
    if run_child_case() {
        return;
    }
    assert_native_matches(
        "native_regressions_match_interpreter_and_otp",
        MODULE,
        SOURCE,
        &format!("{MODULE},io_lib_format,re"),
        &[],
    );
}

#[test]
#[cfg(target_arch = "aarch64")]
fn native_comparison_bifs_match_otp() {
    if run_child_case() {
        return;
    }
    assert_native_matches(
        "native_comparison_bifs_match_otp",
        COMPARE_MODULE,
        COMPARE_SOURCE,
        COMPARE_MODULE,
        &[],
    );
}

#[test]
#[cfg(target_arch = "aarch64")]
fn native_bit_syntax_survives_gc_stress() {
    if run_child_case() {
        return;
    }
    assert_native_matches(
        "native_bit_syntax_survives_gc_stress",
        GC_MODULE,
        GC_SOURCE,
        GC_MODULE,
        &[("ARINSAL_GC_STRESS", "1")],
    );
}

#[test]
#[cfg(target_arch = "aarch64")]
fn native_bif_error_frames_match_otp() {
    if run_child_case() {
        return;
    }
    assert_native_matches_with(
        "native_bif_error_frames_match_otp",
        FRAMES_MODULE,
        FRAMES_SOURCE,
        FRAMES_MODULE,
        &[],
        false,
    );
}

#[test]
#[cfg(target_arch = "aarch64")]
fn native_lazy_debug_bif_frames_match_otp() {
    if run_child_case() {
        return;
    }
    assert_native_matches(
        "native_lazy_debug_bif_frames_match_otp",
        BIF_FRAMES_MODULE,
        BIF_FRAMES_SOURCE,
        BIF_FRAMES_MODULE,
        &[],
    );
}
