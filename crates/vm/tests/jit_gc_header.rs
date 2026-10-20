//! Differential stress for the native-helper heap handoff: binary construction and
//! base64/hex round trips in processes with tiny heaps, so collections happen inside
//! `bs_create_bin` / append helpers and the helpers after them must see the moved heap
//! (Elixir `base_test` / `calendar/iso_test` segfaulted here), against OTP 29.1.1.

use arinsal_difftest::{CallOptions, CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_term::{VecHeap, from_owned};
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(jit_gc_header).
-export([run/1]).

run(Case) ->
    Self = self(),
    Ps = [spawn_opt(fun() -> Self ! {done, self(), work(Case, I)} end,
                    [{min_heap_size, 20 + I * 3}]) || I <- lists:seq(1, 16)],
    [receive {done, P, R} -> R end || P <- Ps].

work(concat, Seed) -> concat(0, Seed, 0);
work(codec, Seed) -> codec(0, Seed, 0);
work(nested, Seed) -> nested(0, Seed, []).

concat(1500, _, Acc) -> Acc;
concat(N, Seed, Acc) ->
    LA = 20 + (N + Seed) rem 25,
    LB = 12 + (N * 7 + Seed) rem 30,
    A = binary:copy(<<7>>, LA),
    B = binary:copy(<<9>>, LB),
    C = <<A/binary, B/binary>>,
    D = <<C/binary, A/binary, (N rem 256):8, B/binary>>,
    L = lists:seq(1, (N + Seed) rem 11),
    concat(N + 1, Seed, Acc + byte_size(D) + length(L) + erlang:phash2(C, 1000)).

codec(300, _, Acc) -> Acc;
codec(N, Seed, Acc) ->
    Data = list_to_binary([(I * 31 + N + Seed) band 255 || I <- lists:seq(1, N rem 130)]),
    E64 = base64:encode(Data),
    Hex = binary:encode_hex(Data),
    Data = base64:decode(E64),
    Data = binary:decode_hex(Hex),
    codec(N + 1, Seed, Acc + byte_size(E64) + byte_size(Hex) + erlang:phash2(Data)).

nested(400, _, Acc) -> erlang:phash2(Acc);
nested(N, Seed, Acc) ->
    Chunk = <<N:16, (list_to_binary(lists:duplicate((N + Seed) rem 40, N rem 250)))/binary>>,
    Joined = iolist_to_binary([Chunk, <<"-">>, integer_to_binary(N), Chunk]),
    nested(N + 1, Seed, lists:sublist([Joined | Acc], 12)).
"#;

fn run_case(reference: &RefErl, vm: &mut Vm, case_name: &str) {
    let input = OwnedTerm::Atom(case_name.into());
    let expected = reference
        .call_opts(
            "jit_gc_header",
            "run",
            std::slice::from_ref(&input),
            &CallOptions {
                timeout_ms: Some(120_000),
                ..CallOptions::default()
            },
        )
        .result;
    let mut heap = VecHeap::new();
    let arg = from_owned(&input, &mut heap).unwrap();
    let actual = vm
        .eval_scheduled("jit_gc_header", "run", &[arg], 4, None)
        .unwrap_or_else(|error| panic!("{case_name}: {error}"));
    assert_eq!(expected, CallResult::Ok(actual.term), "{case_name}");
}

#[test]
fn binary_construction_with_collections_matches_erts() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping jit_gc_header differential test");
        return;
    };
    let beam = reference
        .compile_named("jit_gc_header", SOURCE, &[])
        .expect("compile jit_gc_header");
    reference
        .load("jit_gc_header", &beam)
        .expect("load reference module");
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load arinsal module");
    for case in ["concat", "codec", "nested"] {
        run_case(&reference, &mut vm, case);
    }
}
