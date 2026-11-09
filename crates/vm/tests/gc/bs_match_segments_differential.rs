//! Differential checks for `bs_match` command lists under BeamAsm.
//!
//! Port coverage of beam_jit_bs.cpp (`beam_jit_opt_bsm_segments`) and instr_bs.cpp
//! (`emit_read_bits`, `emit_extract_integer`, `emit_extract_bitstring`): every pattern shape
//! runs on aligned binaries, sub-binaries, bitstrings at every bit offset and bitstrings with
//! trailing bits, and must give the same result as OTP 29.1.1 `erl`.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::{EncodeOptions, OwnedTerm, decode, encode};
use arinsal_vm::Vm;

const MODULE: &str = "bs_match_segments_differential";

/// Pattern shapes: segments, then the variables returned next to the tail `R`.
const SHAPES: &[(&str, &str)] = &[
    // Headers and mixed widths in one read.
    ("A:16/big, B:32/little, C:64", "A,B,C"),
    ("A:8, B:8, C:8, D:8", "A,B,C,D"),
    ("A:1, B:7, C:16/signed", "A,B,C"),
    ("A:4, B:4, C:24/little, D:32/signed", "A,B,C,D"),
    ("A:12, B:12, C:12, D:28", "A,B,C,D"),
    ("A:3, B:5, C:7, D:9, E:11, F:13, G:16", "A,B,C,D,E,F,G"),
    ("A:32/little-signed, B:32/big-signed", "A,B"),
    ("A:56, B:8", "A,B"),
    ("A:57, B:7", "A,B"),
    ("A:60, B:4", "A,B"),
    ("A:64/signed, B:16/little", "A,B"),
    ("A:64/little, B:64", "A,B"),
    (
        "A:24/little-signed, B:24/big-signed, C:16/native-unsigned",
        "A,B,C",
    ),
    ("A:40/little, B:24", "A,B"),
    ("A:48/signed, B:16", "A,B"),
    ("A:20/little, B:12/signed, C:32", "A,B,C"),
    // Equality tests, coalesced into the previous read.
    ("16#47:8", ""),
    ("\"GET \"", ""),
    ("\"GET \", A:8, \" \", B:16", "A,B"),
    ("16#12345:20, A:4", "A"),
    ("0:1, 1:1, 0:6, A:8", "A"),
    ("16#DEADBEEF:32, A:32", "A"),
    ("16#DEADBEEF:32/little, A:32/little", "A"),
    ("16#FFFFFFFFFFFFFFFF:64", ""),
    ("16#0123456789ABCDEF:64, A:8", "A"),
    ("\"abc\"", ""),
    ("1:1, A:7", "A"),
    ("5:3, A:5, 9:4, B:4", "A,B"),
    ("A:8, 16#42:8, B:8", "A,B"),
    ("A:16, 16#CAFE:16, B:16, 255:8", "A,B"),
    // Skips, merged into the read when they fit.
    ("_:3, A:5", "A"),
    ("_:8, A:16, _:16", "A"),
    ("_:13, A:3, _:40, B:8", "A,B"),
    ("A:8, _:56, B:8", "A,B"),
    ("_:70, A:8", "A"),
    ("A:4, _:4, B:4, _:4, C:4", "A,B,C"),
    // Binary and bitstring fields.
    ("A:0/binary", "A"),
    ("A:1/binary", "A"),
    ("A:2/binary, B:2/binary", "A,B"),
    ("A:7/binary", "A"),
    ("A:8/binary", "A"),
    ("A:9/binary, B:1/binary", "A,B"),
    ("A:63/binary", "A"),
    ("A:64/binary", "A"),
    ("A:65/binary", "A"),
    ("A:100/binary", "A"),
    ("A:3/bitstring", "A"),
    ("A:5/bitstring, B:7/bitstring", "A,B"),
    ("A:63/bitstring", "A"),
    ("A:64/bitstring", "A"),
    ("A:513/bitstring", "A"),
    ("_:3, A:4/binary-unit:8", "A"),
    ("T:8, A:3/binary, B:2/bitstring", "T,A,B"),
    ("A:8, B:5/binary, C:8", "A,B,C"),
    // Variable sizes and units.
    ("T:8, L:16, V:L/binary", "T,L,V"),
    ("N:8, V:N/bitstring", "N,V"),
    ("N:8, V:N/integer-unit:4", "N,V"),
    ("N:4, V:N/little-signed-integer-unit:8", "N,V"),
    ("N:8, V:N/binary-unit:16", "N,V"),
    ("N:8, A:N/binary, B:N/binary", "N,A,B"),
    // Floats and UTF.
    ("F:64/float", "F"),
    ("F:32/float-little", "F"),
    ("F:16/float", "F"),
    ("F:64/float-little, G:32/float", "F,G"),
    ("A:8, F:32/float, B:8", "A,F,B"),
    ("C/utf8", "C"),
    ("A:8, C/utf8, B:8", "A,C,B"),
    ("C/utf16-big", "C"),
    ("C/utf16-little", "C"),
    ("C/utf32-big", "C"),
    ("C/utf32-little", "C"),
];

/// Integer widths exercised alone with all four endian/sign combinations.
const WIDTHS: &[u32] = &[
    1, 2, 3, 4, 5, 7, 8, 9, 12, 15, 16, 17, 24, 31, 32, 33, 40, 47, 48, 56, 57, 59, 60, 61, 63, 64,
    65, 100,
];
const FIRST: &[u32] = &[3, 8, 13, 16, 24, 32, 40, 48, 64];
const SECOND: &[u32] = &[8, 16, 32, 64];

fn module_source() -> String {
    let mut shapes: Vec<(String, String)> = SHAPES
        .iter()
        .map(|(pattern, vars)| ((*pattern).to_owned(), (*vars).to_owned()))
        .collect();
    for &width in WIDTHS {
        for flags in ["", "/little", "/signed", "/little-signed"] {
            shapes.push((format!("A:{width}{flags}"), "A".to_owned()));
        }
    }
    for &first in FIRST {
        for &second in SECOND {
            for (one, two) in [("", ""), ("/little", "/signed"), ("/signed", "/little")] {
                shapes.push((format!("A:{first}{one}, B:{second}{two}"), "A,B".to_owned()));
            }
        }
    }
    let mut source = String::from(
        "-module(bs_match_segments_differential).\n-compile([export_all, nowarn_export_all]).\n",
    );
    let mut names = Vec::new();
    for (index, (pattern, vars)) in shapes.iter().enumerate() {
        let result = if vars.is_empty() {
            "{ok, R}".to_owned()
        } else {
            format!("{{ok, {vars}, R}}")
        };
        source.push_str(&format!(
            "p{index}(B) -> case B of <<{pattern}, R/bitstring>> -> {result}; _ -> no end.\n"
        ));
        names.push(format!("p{index}"));
    }
    source.push_str(&format!("names() -> [{}].\n", names.join(", ")));
    source.push_str(
        r#"
run(Name) -> [{B, [apply(bs_match_segments_differential, Name, [V]) || V <- variants(B)]} || B <- inputs()].

%% Aligned, sub-binary, every bit offset, and trailing bits.
variants(B) ->
    [B, binary:part(<<0, B/binary, 0>>, 1, byte_size(B))]
    ++ [shifted(B, N) || N <- lists:seq(1, 7)]
    ++ [<<B/bitstring, 5:3>>, <<B/bitstring, 1:1>>].

shifted(B, N) ->
    <<_:N, S/bitstring>> = <<(1 bsl N - 1):N, B/binary>>,
    S.

inputs() ->
    Lengths = [0, 1, 2, 3, 4, 5, 7, 8, 9, 12, 16, 17, 23, 32, 33, 64, 65, 100, 130],
    Fixed = [<<>>, <<255>>, <<0>>, <<128>>,
             binary:copy(<<255>>, 20), binary:copy(<<0>>, 20), binary:copy(<<128>>, 20),
             binary:copy(<<127>>, 20), <<"GET /index.html HTTP/1.1">>,
             <<16#DEADBEEF:32, 16#DEADBEEF:32>>, <<16#EFBEADDE:32, 16#EFBEADDE:32>>,
             <<16#0123456789ABCDEF:64, 7>>, <<16#FFFFFFFFFFFFFFFF:64>>,
             <<"abc">>, <<"é€😀"/utf8, "é€😀"/utf16, "é€😀"/utf32>>,
             <<7:8, 5:16, "hello", 9>>, <<3:8, "abcdef">>, <<2:8, 1, 2, 3, 4, 5, 6>>,
             <<1.5:64/float, 2.5:32/float-little>>, <<1.5:32/float-little, 2.5:64/float-little>>,
             <<(-0.0):64/float, 0.5:16/float>>],
    {_, Random} = lists:foldl(fun(Len, {Seed, Acc}) ->
        {Next, Bytes} = bytes(Seed, Len, []),
        {Next, [Bytes | Acc]}
    end, {12345, []}, Lengths ++ Lengths),
    Fixed ++ Random.

bytes(Seed, 0, Acc) -> {Seed, list_to_binary(Acc)};
bytes(Seed, N, Acc) ->
    Next = (Seed * 1103515245 + 12345) band 16#7fffffff,
    bytes(Next, N - 1, [(Next bsr 8) band 255 | Acc]).

scan8(B) -> scan8(B, 0).
scan8(<<X:8, R/binary>>, A) -> scan8(R, A * 31 + X);
scan8(<<>>, A) -> A;
scan8(Other, A) -> {A, Other}.

scan16le(B) -> scan16le(B, []).
scan16le(<<X:16/little-signed, R/binary>>, A) -> scan16le(R, [X | A]);
scan16le(Other, A) -> {lists:reverse(A), Other}.

sum32(B) -> sum32(B, 0).
sum32(<<A:16, B:16, R/binary>>, S) -> sum32(R, S + A * B);
sum32(Other, S) -> {S, Other}.

eq_loop(B) -> eq_loop(B, 0).
eq_loop(<<"ab", R/binary>>, N) -> eq_loop(R, N + 1);
eq_loop(<<16#ff:8, 16#00:8, R/binary>>, N) -> eq_loop(R, N + 100);
eq_loop(Other, N) -> {N, Other}.
"#,
    );
    source
}

fn call(reference: &RefErl, vm: &mut Vm, function: &str, argument: OwnedTerm) {
    let expected = reference.call(MODULE, function, std::slice::from_ref(&argument));
    let mut heap = arinsal_term::VecHeap::new();
    let term = arinsal_term::from_owned(&argument, &mut heap).expect("convert argument");
    let actual = vm
        .eval_scheduled(MODULE, function, &[term], 1, None)
        .unwrap_or_else(|error| panic!("{function}: VM raised unexpectedly: {error:?}"));
    let actual = decode(&encode(&actual.term, EncodeOptions::default())).unwrap();
    similar_asserts::assert_eq!(CallResult::Ok(actual), expected, "{function}");
}

#[test]
fn bs_match_segments_match_otp() {
    let reference = RefErl::start().expect("OTP 29.1.1 reference runtime");
    assert!(reference.otp_version().starts_with("29.1.1"));
    let source = module_source();
    let beam = reference
        .compile_named(MODULE, &source, &[])
        .expect("compile bs_match differential module");
    reference
        .load(MODULE, &beam)
        .expect("load reference module");
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load VM module");

    let count = SHAPES.len() + WIDTHS.len() * 4 + FIRST.len() * SECOND.len() * 3;
    for index in 0..count {
        call(
            &reference,
            &mut vm,
            "run",
            OwnedTerm::Atom(format!("p{index}")),
        );
    }
}

#[test]
fn bs_match_loops_match_otp() {
    let reference = RefErl::start().expect("OTP 29.1.1 reference runtime");
    let source = module_source();
    let beam = reference
        .compile_named(MODULE, &source, &[])
        .expect("compile bs_match differential module");
    reference
        .load(MODULE, &beam)
        .expect("load reference module");
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load VM module");
    for name in ["scan8", "scan16le", "sum32", "eq_loop"] {
        call(&reference, &mut vm, "run", OwnedTerm::Atom(name.to_owned()));
    }
}
