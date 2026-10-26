//! Every `bs_create_bin` shape followed by stores that rely on the instruction's `Alloc` words
//! (a tuple and list cells merged into the same heap test): the fixed, UTF-8, append, private
//! append and generic native helpers must reserve their own words plus `Alloc` exactly as
//! erts does (instr_bs.cpp, `extra_words` of `erts_bs_append_checked`/`beam_jit_bs_init_bits`).
//! The native cursor validation catches a store past the heap end; the result is compared with
//! erl. The cases run in a child because the validation flag is read once per process.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;
use std::process::Command;

const CHILD: &str = "ARINSAL_BS_CREATE_BIN_ALLOC_CHILD";
const MODULE: &str = "bs_create_bin_alloc";
const SOURCE: &str = r#"
-module(bs_create_bin_alloc).
-export([run/0]).
id(X) -> X.
run() -> [{K, run(K)} || K <- lists:seq(1, 21)] ++ [{{two, K}, run2(K)} || K <- lists:seq(1, 8)].
run(K) -> go(K, 3000, [], 0).
go(_K, 0, L, Acc) -> {Acc, length(L)};
go(K, N, L, Acc) ->
    S = id(N rem 97), P = id(lists:duplicate(N rem 41, N)),
    T = shape(K, N, S),
    Sz = erlang:external_size(T),
    go(K, N - 1, [T | lists:sublist(L, 4)], (Acc + Sz + length(P)) rem 1000003).
bin(N) -> id(binary:copy(<<"x">>, N)).
shape(1, N, _S) -> A = id(N band 255), B = id(N band 65535), X = <<A:8, B:16>>, {X, {A, B}, [A, B, X]};
shape(2, N, _S) -> C = id(16#80 + (N rem 5000)), X = <<C/utf8>>, {X, {C, X}, [C, X, C]};
shape(3, N, S) -> A = bin(S), X = <<"abc", A/binary>>, {X, {A, X}, [X, A, X]};
shape(4, N, S) -> A = bin(S), X = <<A/binary, 1, 2>>, {X, {A, X}, [X, A, X]};
shape(5, N, S) -> A = bin(S + 70), X = <<A/binary, 1, 2>>, {X, {A, X}, [X, A, X]};
shape(6, N, S) -> F = id(N * 1.5), X = <<F/float, 1:3>>, {X, {F, X}, [X, F, X]};
shape(7, N, S) -> A = id(<<1:(S rem 13)>>), X = <<A/bitstring, 5:3>>, {X, {A, X}, [X, A, X]};
shape(8, N, S) -> Z = id(S), X = <<N:Z>>, {X, {Z, X}, [X, Z, X]};
shape(9, N, S) -> C = id(N rem 1000), X = <<C/utf16, C/utf32>>, {X, {C, X}, [C, X, C]};
shape(10, N, S) -> A = bin(S), B = bin(97 - S), X = <<A/binary, B/binary>>, {X, {A, B}, [A, B, X]};
shape(11, N, S) -> A = bin(S), B = bin(97 - S), X = <<A/binary, B/binary, B/binary>>, {X, {A, B}, [A, B, X]};
shape(12, N, S) -> A = id(N), X = <<A:64, A:64, A:8>>, {X, {A, X}, [A, X]};
shape(13, N, S) -> Z = id(S * 3), X = <<N:Z, 1:8>>, {X, {Z, X}, [X, Z, X]};
shape(14, N, S) -> A = bin(S + 100), X = <<A/binary>>, {X, {A, X}, [X, A, X]};
shape(15, N, S) -> Acc = acc(<<>>, S rem 20 + 3), {Acc, {S, Acc}, [Acc, S]};
shape(16, N, S) -> Acc = acc(bin(S + 60), 3), {Acc, {S, Acc}, [Acc, S]};
shape(17, N, S) -> A = id(N rem 100000), X = <<A:3/little-signed-integer-unit:8, 1:1>>, {X, {A, X}, [A, X]};
shape(18, N, S) -> A = bin(S), X = <<A:(S div 2)/binary, N:4>>, {X, {A, X}, [A, X]};
shape(19, N, S) -> A = bin(S + 70), X = <<N:5, A/bitstring>>, {X, {A, X}, [A, X]};
shape(21, N, _S) ->
    A = id(binary:copy(<<"a">>, 20 + N rem 30)), B = id(binary:copy(<<"b">>, 30 - (N rem 11))),
    join(A, B);
shape(20, N, S) -> A = id(N rem 255), X = <<A, A, A, A>>, {X, {A, X}, [A, X]}.
%% The accumulator of a loop is the shape the compiler lowers to an append.
join(Acc, B) -> {<<Acc/binary, B/binary>>, {B, Acc, B}, [B, Acc, B]}.
acc(B, 0) -> {B, [B]};
acc(B, K) -> acc(<<B/binary, K:8>>, K - 1).
run2(K) -> go2(K, 3000, [], 0).
go2(_K, 0, L, Acc) -> {Acc, length(L)};
go2(K, N, L, Acc) ->
    S = id(N rem 97), P = id(lists:duplicate(N rem 41, N)),
    T = sh2(K, N, S),
    Sz = erlang:external_size(T),
    go2(K, N - 1, [T | lists:sublist(L, 4)], (Acc + Sz + length(P)) rem 1000003).
sh2(1, N, S) -> A = sub(bin(S + 10), S rem 7, S), X = <<A/binary, N:8>>, {X, {A, X}, [A, X]};
sh2(2, N, S) -> A = sub(bin(S + 80), S rem 7, S + 70), X = <<A/binary>>, {X, {A, X}, [A, X]};
sh2(3, N, S) -> A = sub(bin(S + 80), S rem 7, S + 70), X = <<A/binary, A/binary>>, {X, {A, X}, [A, X]};
sh2(4, N, S) -> A0 = id(<<N:(S+3)>>), <<_:1, A:S/bitstring, _/bitstring>> = A0, X = <<A/bitstring, 3:2>>, {X, {A, X}, [A, X]};
sh2(5, N, S) -> A = id(<<N:(S+520)>>), X = <<A/bitstring, 3:2>>, {X, {A, X}, [A, X]};
sh2(6, N, S) -> A = bin(S), X = <<A:(S rem 5)/binary, A:(S rem 3)/binary, N:3>>, {X, {A, X}, [A, X]};
sh2(7, N, S) -> A = bin(S+600), X = <<A:(S+500)/binary, N:3, A:3/binary>>, {X, {A, X}, [A, X]};
sh2(8, N, S) -> A = bin(40), B = bin(S), X = <<A/binary, B/binary, 1:1>>, {X, {A, X}, [A, X]}.
sub(B, Off, Len) when Off + Len =< byte_size(B) -> binary:part(B, Off, Len);
sub(B, _, _) -> B.

"#;

#[test]
fn bs_create_bin_helpers_reserve_the_alloc_words() {
    if let Some(path) = std::env::var_os(CHILD) {
        let mut vm = Vm::new([]);
        vm.load_bytes(&std::fs::read(path).unwrap()).unwrap();
        let actual = vm.eval_scheduled(MODULE, "run", &[], 2, None).unwrap();
        println!("RESULT:{}", actual.term);
        return;
    }
    let reference = RefErl::start().expect("OTP 29.1.1");
    let beam = reference.compile_named(MODULE, SOURCE, &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();
    let expected = match reference.call(MODULE, "run", &[]) {
        CallResult::Ok(term) => format!("{term}"),
        other => panic!("erl run failed: {other:?}"),
    };
    let dir = std::env::temp_dir().join(format!("arinsal-bs-alloc-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(format!("{MODULE}.beam"));
    std::fs::write(&path, &beam).unwrap();
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "bs_create_bin_helpers_reserve_the_alloc_words",
            "--nocapture",
        ])
        .env(CHILD, &path)
        .env("ARINSAL_BEAMASM", "1")
        .env("ARINSAL_BEAMASM_VALIDATE", "1")
        .output()
        .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        output.status.success(),
        "child failed: {stdout}{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let actual = stdout
        .lines()
        .find_map(|line| line.strip_prefix("RESULT:"))
        .expect("child prints the result");
    similar_asserts::assert_eq!(actual, expected);
}
