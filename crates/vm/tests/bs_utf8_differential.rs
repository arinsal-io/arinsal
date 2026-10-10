//! Differential checks for UTF bit syntax matching and construction.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::{EncodeOptions, OwnedTerm, decode, encode};
use arinsal_term::{VecHeap, from_owned};
use arinsal_vm::Vm;

const MODULE: &str = "bs_utf8_differential";
const SOURCE: &str = r#"
-module(bs_utf8_differential).
-export([
    match_utf8_cases/1, match_utf8_offset_cases/1, match_utf8_unaligned_cases/1,
    match_utf8_subbinary_cases/1, scan_utf8_cases/1, build_utf8_cases/1,
    match_utf16_cases/1, match_utf16_offset_cases/1, match_utf16_unaligned_cases/1,
    match_utf16_subbinary_cases/1, scan_utf16_cases/1, build_utf16_cases/1,
    match_utf16_le_cases/1, match_utf16_le_offset_cases/1,
    match_utf16_le_unaligned_cases/1, match_utf16_le_subbinary_cases/1,
    scan_utf16_le_cases/1, build_utf16_le_cases/1,
    match_utf32_cases/1, match_utf32_offset_cases/1, match_utf32_unaligned_cases/1,
    match_utf32_subbinary_cases/1, scan_utf32_cases/1, build_utf32_cases/1,
    match_utf32_le_cases/1, match_utf32_le_offset_cases/1,
    match_utf32_le_unaligned_cases/1, match_utf32_le_subbinary_cases/1,
    scan_utf32_le_cases/1, build_utf32_le_cases/1
]).

match_utf8_cases(Bins) -> [match_utf8(B) || B <- Bins].
match_utf8(B) -> case B of <<C/utf8, R/bitstring>> -> {ok, C, R}; _ -> no end.
match_utf8_offset_cases(Pairs) -> [match_utf8_offset(B, N) || {B, N} <- Pairs].
match_utf8_offset(B, N) ->
    Padded = <<0:N, B/binary>>,
    case Padded of <<_:N, C/utf8, R/bitstring>> -> {ok, C, R}; _ -> no end.
match_utf8_unaligned_cases(Pairs) -> [match_utf8_unaligned(B, N) || {B, N} <- Pairs].
match_utf8_unaligned(B, N) ->
    Padded = <<0:N, B/binary>>,
    <<_:N, Subject/bitstring>> = Padded,
    match_utf8(Subject).
match_utf8_subbinary_cases(Bins) ->
    [match_utf8(binary:part(<<0, B/binary, 0>>, 1, byte_size(B))) || B <- Bins].
scan_utf8_cases(Bins) -> [scan_utf8(B) || B <- Bins].
scan_utf8(<<>>) -> [];
scan_utf8(B) -> case B of
    <<C/utf8, R/bitstring>> -> [C | scan_utf8(R)];
    _ -> no
end.
build_utf8_cases(Values) -> [build_utf8(V) || V <- Values].
build_utf8(V) -> capture_build(fun() -> <<V/utf8>> end).

match_utf16_cases(Bins) -> [match_utf16(B) || B <- Bins].
match_utf16(B) -> case B of <<C/utf16, R/bitstring>> -> {ok, C, R}; _ -> no end.
match_utf16_offset_cases(Pairs) -> [match_utf16_offset(B, N) || {B, N} <- Pairs].
match_utf16_offset(B, N) ->
    Padded = <<0:N, B/binary>>,
    case Padded of <<_:N, C/utf16, R/bitstring>> -> {ok, C, R}; _ -> no end.
match_utf16_unaligned_cases(Pairs) -> [match_utf16_unaligned(B, N) || {B, N} <- Pairs].
match_utf16_unaligned(B, N) ->
    Padded = <<0:N, B/binary>>,
    <<_:N, Subject/bitstring>> = Padded,
    match_utf16(Subject).
match_utf16_subbinary_cases(Bins) ->
    [match_utf16(binary:part(<<0, B/binary, 0>>, 1, byte_size(B))) || B <- Bins].
scan_utf16_cases(Bins) -> [scan_utf16(B) || B <- Bins].
scan_utf16(<<>>) -> [];
scan_utf16(B) -> case B of
    <<C/utf16, R/bitstring>> -> [C | scan_utf16(R)];
    _ -> no
end.
build_utf16_cases(Values) -> [build_utf16(V) || V <- Values].
build_utf16(V) -> capture_build(fun() -> <<V/utf16>> end).

match_utf16_le_cases(Bins) -> [match_utf16_le(B) || B <- Bins].
match_utf16_le(B) -> case B of <<C/utf16-little, R/bitstring>> -> {ok, C, R}; _ -> no end.
match_utf16_le_offset_cases(Pairs) -> [match_utf16_le_offset(B, N) || {B, N} <- Pairs].
match_utf16_le_offset(B, N) ->
    Padded = <<0:N, B/binary>>,
    case Padded of <<_:N, C/utf16-little, R/bitstring>> -> {ok, C, R}; _ -> no end.
match_utf16_le_unaligned_cases(Pairs) ->
    [match_utf16_le_unaligned(B, N) || {B, N} <- Pairs].
match_utf16_le_unaligned(B, N) ->
    Padded = <<0:N, B/binary>>,
    <<_:N, Subject/bitstring>> = Padded,
    match_utf16_le(Subject).
match_utf16_le_subbinary_cases(Bins) ->
    [match_utf16_le(binary:part(<<0, B/binary, 0>>, 1, byte_size(B))) || B <- Bins].
scan_utf16_le_cases(Bins) -> [scan_utf16_le(B) || B <- Bins].
scan_utf16_le(<<>>) -> [];
scan_utf16_le(B) -> case B of
    <<C/utf16-little, R/bitstring>> -> [C | scan_utf16_le(R)];
    _ -> no
end.
build_utf16_le_cases(Values) -> [build_utf16_le(V) || V <- Values].
build_utf16_le(V) -> capture_build(fun() -> <<V/utf16-little>> end).

match_utf32_cases(Bins) -> [match_utf32(B) || B <- Bins].
match_utf32(B) -> case B of <<C/utf32, R/bitstring>> -> {ok, C, R}; _ -> no end.
match_utf32_offset_cases(Pairs) -> [match_utf32_offset(B, N) || {B, N} <- Pairs].
match_utf32_offset(B, N) ->
    Padded = <<0:N, B/binary>>,
    case Padded of <<_:N, C/utf32, R/bitstring>> -> {ok, C, R}; _ -> no end.
match_utf32_unaligned_cases(Pairs) -> [match_utf32_unaligned(B, N) || {B, N} <- Pairs].
match_utf32_unaligned(B, N) ->
    Padded = <<0:N, B/binary>>,
    <<_:N, Subject/bitstring>> = Padded,
    match_utf32(Subject).
match_utf32_subbinary_cases(Bins) ->
    [match_utf32(binary:part(<<0, B/binary, 0>>, 1, byte_size(B))) || B <- Bins].
scan_utf32_cases(Bins) -> [scan_utf32(B) || B <- Bins].
scan_utf32(<<>>) -> [];
scan_utf32(B) -> case B of
    <<C/utf32, R/bitstring>> -> [C | scan_utf32(R)];
    _ -> no
end.
build_utf32_cases(Values) -> [build_utf32(V) || V <- Values].
build_utf32(V) -> capture_build(fun() -> <<V/utf32>> end).

match_utf32_le_cases(Bins) -> [match_utf32_le(B) || B <- Bins].
match_utf32_le(B) -> case B of <<C/utf32-little, R/bitstring>> -> {ok, C, R}; _ -> no end.
match_utf32_le_offset_cases(Pairs) -> [match_utf32_le_offset(B, N) || {B, N} <- Pairs].
match_utf32_le_offset(B, N) ->
    Padded = <<0:N, B/binary>>,
    case Padded of <<_:N, C/utf32-little, R/bitstring>> -> {ok, C, R}; _ -> no end.
match_utf32_le_unaligned_cases(Pairs) ->
    [match_utf32_le_unaligned(B, N) || {B, N} <- Pairs].
match_utf32_le_unaligned(B, N) ->
    Padded = <<0:N, B/binary>>,
    <<_:N, Subject/bitstring>> = Padded,
    match_utf32_le(Subject).
match_utf32_le_subbinary_cases(Bins) ->
    [match_utf32_le(binary:part(<<0, B/binary, 0>>, 1, byte_size(B))) || B <- Bins].
scan_utf32_le_cases(Bins) -> [scan_utf32_le(B) || B <- Bins].
scan_utf32_le(<<>>) -> [];
scan_utf32_le(B) -> case B of
    <<C/utf32-little, R/bitstring>> -> [C | scan_utf32_le(R)];
    _ -> no
end.
build_utf32_le_cases(Values) -> [build_utf32_le(V) || V <- Values].
build_utf32_le(V) -> capture_build(fun() -> <<V/utf32-little>> end).

capture_build(Fun) ->
    try Fun() of Bin -> {ok, Bin}
    catch error:Reason:Stack ->
        {_Module, _Function, _Args, Location} = hd(Stack),
        {error, Reason, proplists:get_value(error_info, Location, undefined)}
    end.
"#;

#[derive(Clone, Copy)]
struct Encoding {
    suffix: &'static str,
    little: bool,
    width: usize,
}

const ENCODINGS: [Encoding; 5] = [
    Encoding {
        suffix: "utf8",
        little: false,
        width: 1,
    },
    Encoding {
        suffix: "utf16",
        little: false,
        width: 2,
    },
    Encoding {
        suffix: "utf16_le",
        little: true,
        width: 2,
    },
    Encoding {
        suffix: "utf32",
        little: false,
        width: 4,
    },
    Encoding {
        suffix: "utf32_le",
        little: true,
        width: 4,
    },
];

fn list(values: Vec<OwnedTerm>) -> OwnedTerm {
    if values.is_empty() {
        OwnedTerm::Nil
    } else {
        OwnedTerm::List {
            elems: values,
            tail: Box::new(OwnedTerm::Nil),
        }
    }
}

fn encode_codepoint(value: u32, encoding: Encoding) -> Vec<u8> {
    if encoding.width == 1 {
        if value < 0x80 {
            return vec![value as u8];
        }
        if value < 0x800 {
            return vec![0xc0 | (value >> 6) as u8, 0x80 | (value & 0x3f) as u8];
        }
        if value < 0x1_0000 {
            return vec![
                0xe0 | (value >> 12) as u8,
                0x80 | ((value >> 6) & 0x3f) as u8,
                0x80 | (value & 0x3f) as u8,
            ];
        }
        return vec![
            0xf0 | (value >> 18) as u8,
            0x80 | ((value >> 12) & 0x3f) as u8,
            0x80 | ((value >> 6) & 0x3f) as u8,
            0x80 | (value & 0x3f) as u8,
        ];
    }

    if encoding.width == 2 {
        let unit = value as u16;
        let bytes = if encoding.little {
            unit.to_le_bytes()
        } else {
            unit.to_be_bytes()
        };
        return if value <= 0xffff {
            bytes.to_vec()
        } else {
            let scalar = value - 0x1_0000;
            let high = 0xd800 | (scalar >> 10) as u16;
            let low = 0xdc00 | (scalar & 0x3ff) as u16;
            let high = if encoding.little {
                high.to_le_bytes()
            } else {
                high.to_be_bytes()
            };
            let low = if encoding.little {
                low.to_le_bytes()
            } else {
                low.to_be_bytes()
            };
            [high.as_slice(), low.as_slice()].concat()
        };
    }

    let value = if encoding.little {
        value.to_le_bytes()
    } else {
        value.to_be_bytes()
    };
    value.to_vec()
}

fn valid_codepoints() -> Vec<u32> {
    let mut values = vec![0, 0x7f, 0x80, 0x7ff, 0x800, 0xffff, 0x1_0000, 0x10_ffff];
    let mut state = 0x8f31_5a27_u32;
    while values.len() < 136 {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        let value = state % 0x11_0000;
        if !(0xd800..=0xdfff).contains(&value) {
            values.push(value);
        }
    }
    values
}

fn random_valid_strings() -> Vec<Vec<u32>> {
    let mut state = 0x3e79_4b15_u32;
    (0..12)
        .map(|index| {
            (0..8 + index)
                .map(|_| {
                    loop {
                        state ^= state << 13;
                        state ^= state >> 17;
                        state ^= state << 5;
                        let value = state % 0x11_0000;
                        if !(0xd800..=0xdfff).contains(&value) {
                            break value;
                        }
                    }
                })
                .collect()
        })
        .collect()
}

fn invalid_utf8() -> Vec<Vec<u8>> {
    let mut values = vec![
        vec![0xc0, 0x80],
        vec![0xe0, 0x80, 0x80],
        vec![0xf0, 0x80, 0x80, 0x80],
        vec![0xf4, 0x90, 0x80, 0x80],
        vec![0xf4, 0xbf, 0xbf, 0xbf],
        vec![0xc2],
        vec![0xe2],
        vec![0xe2, 0x82],
        vec![0xf0],
        vec![0xf0, 0x90],
        vec![0xf0, 0x90, 0x80],
        vec![0xc2, 0x20],
        vec![0xe2, 0x20, 0x80],
        vec![0xe2, 0x82, 0x20],
        vec![0xf0, 0x20, 0x80, 0x80],
        vec![0xf0, 0x90, 0x20, 0x80],
        vec![0xf0, 0x90, 0x80, 0x20],
    ];
    values.extend((0x80..=0xbf).map(|lead| vec![lead]));
    values.extend((0xf5..=0xff).map(|lead| vec![lead, 0x80, 0x80, 0x80]));
    values.extend((0xd800..=0xdfff).map(|surrogate| encode_codepoint(surrogate, ENCODINGS[0])));
    values
}

fn invalid_utf16(encoding: Encoding) -> Vec<Vec<u8>> {
    let mut values = vec![vec![0], vec![0xd8]];
    values.extend((0xd800..=0xdfff).map(|surrogate| encode_codepoint(surrogate, encoding)));
    for high in 0xd800..=0xdbff {
        let mut bytes = encode_codepoint(high, encoding);
        bytes.extend(encode_codepoint(0x41, encoding));
        values.push(bytes);
    }
    values
}

fn invalid_utf32(encoding: Encoding) -> Vec<Vec<u8>> {
    let mut values = vec![vec![0], vec![0, 0], vec![0, 0, 0]];
    values.extend((0xd800..=0xdfff).map(|surrogate| encode_codepoint(surrogate, encoding)));
    values.push(encode_codepoint(0x11_0000, encoding));
    values.push(encode_codepoint(u32::MAX, encoding));
    values
}

fn as_terms(values: impl IntoIterator<Item = Vec<u8>>) -> OwnedTerm {
    list(values.into_iter().map(OwnedTerm::Binary).collect())
}

fn pairs(values: &[Vec<u8>]) -> OwnedTerm {
    list(
        values
            .iter()
            .flat_map(|bytes| {
                (1..=7).map(move |offset| {
                    OwnedTerm::Tuple(vec![
                        OwnedTerm::Binary(bytes.clone()),
                        OwnedTerm::Int(offset as i64),
                    ])
                })
            })
            .collect(),
    )
}

fn call(reference: &RefErl, vm: &mut Vm, function: &str, argument: OwnedTerm) -> OwnedTerm {
    let expected = reference.call(MODULE, function, std::slice::from_ref(&argument));
    let mut heap = VecHeap::new();
    let term = from_owned(&argument, &mut heap).expect("convert differential argument");
    let actual = vm
        .eval_scheduled(MODULE, function, &[term], 1, None)
        .unwrap_or_else(|error| panic!("{function}: VM raised unexpectedly: {error:?}"));
    let actual = decode(&encode(&actual.term, EncodeOptions::default())).unwrap();
    assert_eq!(expected, CallResult::Ok(actual.clone()), "{function}");
    actual
}

fn assert_encoding(reference: &RefErl, vm: &mut Vm, encoding: Encoding) {
    let valid = valid_codepoints();
    let invalid = match encoding.width {
        1 => invalid_utf8(),
        2 => invalid_utf16(encoding),
        _ => invalid_utf32(encoding),
    };
    let match_function = format!("match_{}_cases", encoding.suffix);
    let mut match_cases = valid
        .iter()
        .map(|codepoint| {
            let mut bytes = encode_codepoint(*codepoint, encoding);
            bytes.extend([0xa5, 0x5a]);
            bytes
        })
        .collect::<Vec<_>>();
    match_cases.extend(invalid.iter().cloned());
    let matched = call(
        reference,
        vm,
        &match_function,
        as_terms(match_cases.clone()),
    );
    assert!(
        matches!(matched, OwnedTerm::List { ref elems, .. } if elems.len() == match_cases.len())
    );

    let offset_cases = valid
        .iter()
        .take(8)
        .map(|codepoint| {
            let mut bytes = encode_codepoint(*codepoint, encoding);
            bytes.extend([0x11, 0x22]);
            bytes
        })
        .chain(invalid.iter().take(24).cloned())
        .collect::<Vec<_>>();
    for function in [
        format!("match_{}_offset_cases", encoding.suffix),
        format!("match_{}_unaligned_cases", encoding.suffix),
    ] {
        let result = call(reference, vm, &function, pairs(&offset_cases));
        assert!(matches!(result, OwnedTerm::List { ref elems, .. }
            if elems.len() == offset_cases.len() * 7));
    }

    let mut long = valid
        .iter()
        .flat_map(|codepoint| encode_codepoint(*codepoint, encoding))
        .collect::<Vec<_>>();
    long.extend([0x44, 0x55]);
    assert!(long.len() > 64);
    let mut subbinary_cases = vec![long.clone()];
    let mut malformed = invalid[0].clone();
    malformed.extend(long);
    subbinary_cases.push(malformed);
    let result = call(
        reference,
        vm,
        &format!("match_{}_subbinary_cases", encoding.suffix),
        as_terms(subbinary_cases.clone()),
    );
    assert!(matches!(result, OwnedTerm::List { ref elems, .. }
        if elems.len() == subbinary_cases.len()));

    let strings = random_valid_strings()
        .iter()
        .map(|codepoints| {
            codepoints
                .iter()
                .flat_map(|codepoint| encode_codepoint(*codepoint, encoding))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let scanned = call(
        reference,
        vm,
        &format!("scan_{}_cases", encoding.suffix),
        as_terms(strings),
    );
    assert!(matches!(scanned, OwnedTerm::List { ref elems, .. }
        if elems.len() == 12 && elems.iter().enumerate().all(|(index, item)|
            matches!(item, OwnedTerm::List { elems: cps, .. } if cps.len() == 8 + index))));

    let values = valid
        .iter()
        .copied()
        .map(|value| OwnedTerm::Int(i64::from(value)));
    let built = call(
        reference,
        vm,
        &format!("build_{}_cases", encoding.suffix),
        list(values.collect()),
    );
    assert!(matches!(built, OwnedTerm::List { ref elems, .. }
        if elems.len() == valid.len() && elems.iter().all(|item|
            matches!(item, OwnedTerm::Tuple(parts) if matches!(parts.first(), Some(OwnedTerm::Atom(ok)) if ok == "ok")))));

    let invalid_values = [
        OwnedTerm::Int(-1),
        OwnedTerm::Int(0xd800),
        OwnedTerm::Int(0xdfff),
        OwnedTerm::Int(0x11_0000),
        OwnedTerm::Float(1.5),
        OwnedTerm::Atom("not_integer".into()),
    ];
    let built = call(
        reference,
        vm,
        &format!("build_{}_cases", encoding.suffix),
        list(invalid_values.to_vec()),
    );
    assert!(
        matches!(built, OwnedTerm::List { ref elems, .. }
        if elems.len() == invalid_values.len() && elems.iter().all(|item|
            matches!(item, OwnedTerm::Tuple(parts) if parts.len() == 3
                && matches!(&parts[0], OwnedTerm::Atom(class) if class == "error")
                && matches!(&parts[1], OwnedTerm::Atom(reason) if reason == "badarg")
                && matches!(&parts[2], OwnedTerm::Map(_))))),
        "{} must report badarg with error_info for each invalid construction",
        encoding.suffix
    );
}

#[test]
fn utf_segments_match_otp_for_boundaries_invalid_data_offsets_subbinaries_and_builds() {
    let reference = RefErl::start().expect("OTP 29.1.1 reference runtime");
    assert!(reference.otp_version().starts_with("29.1.1"));
    let beam = reference
        .compile_named(MODULE, SOURCE, &[])
        .expect("compile UTF segment differential module");
    reference
        .load(MODULE, &beam)
        .expect("load reference module");
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load VM module");

    for encoding in ENCODINGS {
        assert_encoding(&reference, &mut vm, encoding);
    }
}
