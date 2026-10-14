use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;

#[test]
fn large_iolist_conversion_and_size_match_otp_after_yields() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping large iolist differential test");
        return;
    };
    let source = r#"
-module(binary_iolist_differential).
-export([run/0]).

run() ->
    List = lists:seq(0, 255) ++ lists:duplicate(300000, 97),
    ListBin = list_to_binary(List),
    Chunk = binary:copy(<<173>>, 64),
    Chunks = lists:duplicate(20000, Chunk),
    Iolist = [[Chunks, [<<1,2>>, [4,5]]], binary:copy(<<6>>, 131072)],
    Flat = iolist_to_binary(Iolist),
    {byte_size(ListBin), erlang:crc32(ListBin),
     iolist_size(Iolist), byte_size(Flat), erlang:crc32(Flat)}.
"#;
    let beam = reference
        .compile_named("binary_iolist_differential", source, &[])
        .unwrap();
    reference.load("binary_iolist_differential", &beam).unwrap();
    let expected = reference.call("binary_iolist_differential", "run", &[]);

    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("binary_iolist_differential", "run", &[], 1, None)
        .unwrap_or_else(|error| panic!("large iolist conversion: {error}"));

    similar_asserts::assert_eq!(expected, CallResult::Ok(actual.term));
}

#[test]
fn binary_substring_and_conversion_entries_match_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping binary substring differential test");
        return;
    };
    let source = r#"
-module(binary_iolist_differential).
-export([substrings/0]).

substrings() ->
    Small = <<0:512>>,
    SmallPart = binary:part(Small, 1, 20),
    SmallRangePart = erlang:binary_part(Small, {3, 20}),
    Large = binary:copy(<<173>>, 1024),
    LargePart = binary:part(Large, 11, 100),
    LargeRangePart = erlang:binary_part(Large, {13, 100}),
    HugeInteger = (1 bsl 1024) - 1,
    Iolist = [[1, 2], [<<3, 4>>, [5, 6]]],
    {binary:referenced_byte_size(SmallPart),
     binary:referenced_byte_size(SmallRangePart),
     binary:referenced_byte_size(LargePart),
     binary:referenced_byte_size(LargeRangePart),
     binary_to_list(LargePart, 2, 4),
     iolist_size(Iolist), list_to_binary(Iolist),
     integer_to_binary(-1234567890123), integer_to_binary(HugeInteger)}.
"#;
    let beam = reference
        .compile_named("binary_iolist_differential", source, &[])
        .unwrap();
    reference.load("binary_iolist_differential", &beam).unwrap();
    let expected = reference.call("binary_iolist_differential", "substrings", &[]);

    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("binary_iolist_differential", "substrings", &[], 1, None)
        .unwrap_or_else(|error| panic!("binary substring/conversion differential: {error}"));

    similar_asserts::assert_eq!(expected, CallResult::Ok(actual.term));
}
