//! Differential test of the `%T` printer against `erts_internal:term_to_string/2` of the
//! reference `erl` (the printer behind `erlang:display/1`), with several print budgets.

use arinsal_etf::decode;
use arinsal_term::printf_term::erts_printf_t;
use arinsal_term::{VecHeap, from_owned, global_atoms};
use std::process::Command;

fn unhex(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let digit = |byte| (byte as char).to_digit(16).unwrap() as u8;
            (digit(pair[0]) << 4) | digit(pair[1])
        })
        .collect()
}

/// `{name, erlang expression}` pairs; the expression yields the term to print.
const CASES: &[(&str, &str)] = &[
    ("nil", "[]"),
    (
        "small",
        "{0, -1, 134217727, -134217728, 1 bsl 59, -(1 bsl 59)}",
    ),
    ("big", "{1 bsl 64, -(1 bsl 100), (1 bsl 200) + 12345}"),
    (
        "floats",
        "[1.5, -0.0, 0.0, 1.0e100, 123456789.123, 1.0e-300, 3.14159265358979]",
    ),
    (
        "atoms_plain",
        "[a, hello_World1, a@b, true, false, undefined, 'ñ', 'élan']",
    ),
    (
        "atoms_quoted",
        "['Hello', 'hello world', '', 'it\\'s', 'a\\\\b', 'a\\nb', '\\t', 'Ünï', 'x-y']",
    ),
    (
        "atoms_control",
        "['\\x{1}\\x{7}', '\\x{85}', '\\x{7f}', 'a\\x{b}\\x{c}\\x{8}\\r']",
    ),
    (
        "atoms_unicode",
        "['\\x{65e5}\\x{672c}', 'a\\x{20ac}', '\\x{1f600}', 'caf\\x{e9}']",
    ),
    (
        "strings",
        "[\"hello\", \"a\\nb\\\"c\", \"tab\\there\", \"\\r\\n\", [200, 201], \"caf\\xe9\"]",
    ),
    (
        "not_strings",
        "[[0, 1], [127], [128, 129], [159], [65 | b], [$a, $b | c], [$a, 1000], [$a, -1]]",
    ),
    ("improper", "[1, 2, 3 | 4]"),
    ("nested_lists", "[[1, [2, [3, []]]], [[]], [[], []]]"),
    (
        "tuples",
        "{{}, {a}, {a, b}, {{{{}}}}, {[], \"s\", <<\"b\">>}}",
    ),
    (
        "flatmap",
        "#{1 => a, 2 => #{3 => [x, y]}, \"k\" => {1, 2}, <<\"b\">> => 4.5, 7.5 => z}",
    ),
    ("empty_map", "#{}"),
    (
        "hamt",
        "maps:from_list([{N, N * N} || N <- lists:seq(1, 100)])",
    ),
    (
        "hamt_big",
        "maps:from_list([{{N, N}, [N]} || N <- lists:seq(1, 2000)])",
    ),
    (
        "hamt_nested",
        "maps:from_list([{N, #{N => maps:from_list([{M, M} || M <- lists:seq(1, 40)])}} || N <- lists:seq(1, 40)])",
    ),
    (
        "binaries",
        "[<<>>, <<\"abc\">>, <<1, 2, 3>>, <<\"a\\\"b\">>, <<\"\\n\">>, <<200>>, <<127>>, <<\"~\">>]",
    ),
    (
        "bitstrings",
        "[<<1:1>>, <<5:3>>, <<255, 1:5>>, <<\"ab\", 3:2>>, <<7:7, 1:1, 2:2>>, <<0:1>>]",
    ),
    ("large_binary", "binary:copy(<<\"0123456789\">>, 500)"),
    ("large_binary_bytes", "binary:copy(<<1, 2, 3, 200>>, 300)"),
    (
        "export_funs",
        "[fun lists:map/2, fun 'My Mod':'a b'/0, fun erlang:'+'/2]",
    ),
    ("local_pid", "erlang:list_to_pid(\"<0.77.5>\")"),
    ("local_port", "erlang:list_to_port(\"#Port<0.12>\")"),
    ("local_ref", "erlang:list_to_ref(\"#Ref<0.1.2.3>\")"),
    (
        "ext_pid",
        "binary_to_term(<<131,88,119,7,\"foo@bar\",0,0,0,5,0,0,0,1,0,0,0,2>>)",
    ),
    (
        "ext_port",
        "binary_to_term(<<131,89,119,7,\"foo@bar\",0,0,0,9,0,0,0,2>>)",
    ),
    (
        "ext_port_v4",
        "binary_to_term(<<131,120,119,7,\"foo@bar\",0,0,0,1,0,0,0,9,0,0,0,2>>)",
    ),
    (
        "ext_ref",
        "binary_to_term(<<131,90,0,3,119,7,\"foo@bar\",0,0,0,1,0,0,0,10,0,0,0,11,0,0,0,12>>)",
    ),
    (
        "ext_mixed",
        "{binary_to_term(<<131,88,119,7,\"foo@bar\",0,0,0,5,0,0,0,1,0,0,0,2>>), [binary_to_term(<<131,89,119,7,\"foo@bar\",0,0,0,9,0,0,0,2>>)]}",
    ),
    (
        "deep_list",
        "lists:foldl(fun(_, A) -> [A] end, [], lists:seq(1, 20000))",
    ),
    (
        "deep_tuple",
        "lists:foldl(fun(_, A) -> {A} end, {}, lists:seq(1, 20000))",
    ),
    (
        "deep_map",
        "lists:foldl(fun(N, A) -> #{N => A} end, #{}, lists:seq(1, 5000))",
    ),
    ("long_list", "lists:seq(1, 30000)"),
    ("long_string", "lists:duplicate(5000, $x)"),
    ("long_improper", "lists:seq(1, 1000) ++ tail"),
    ("long_atom", "list_to_atom(lists:duplicate(200, $a))"),
    ("long_quoted_atom", "list_to_atom(lists:duplicate(100, $A))"),
    (
        "mixed",
        "[{a, 1, \"s\"}, #{b => <<\"x\">>}, 2.5, make, {1 bsl 70}, [\"x\" | y]]",
    ),
];

#[test]
fn printer_matches_erts_term_to_string() {
    arinsal_term::init_global_literals();
    let cases = CASES
        .iter()
        .map(|(name, expression)| format!("{{\"{name}\", fun() -> {expression} end}}"))
        .collect::<Vec<_>>()
        .join(",\n");
    let script = format!(
        r##"
        Hex = fun(L) -> string:lowercase(binary:encode_hex(iolist_to_binary(L))) end,
        Probe = binary_to_term(<<131,88,119,7,"foo@bar",0,0,0,5,0,0,0,1,0,0,0,2>>),
        [$<|ProbeText] = erts_internal:term_to_string(Probe, undefined),
        Channel = hd(string:tokens(ProbeText, ".")),
        Norm = fun(S) ->
            lists:foldl(fun(P, Acc) ->
                lists:flatten(string:replace(Acc, P ++ Channel ++ ".", P ++ "\x{{1}}.", all))
            end, S, ["<", "#Port<", "#Ref<"])
        end,
        Cases = [
{cases}
        ],
        lists:foreach(fun({{Name, F}}) ->
            T = F(),
            Row = [Name, Hex(term_to_binary(T))] ++
                [Hex(Norm(erts_internal:term_to_string(T, Limit))) || Limit <- [undefined, 2, 3, 7, 20, 100, 1000]],
            io:format("~s~n", [lists:join(" ", Row)])
        end, Cases),
        halt().
        "##
    );
    let output = match Command::new("$HOME/.asdf/installs/erlang/29.1.1/bin/erl")
        .args(["-noshell", "-eval", &script])
        .output()
    {
        Ok(output) => output,
        Err(_) => {
            eprintln!("skipping: erl unavailable");
            return;
        }
    };
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(stdout.lines().count(), CASES.len());
    let channel = global_atoms().intern("foo@bar").unwrap().0.to_string();
    let limits = [i32::MAX, 2, 3, 7, 20, 100, 1000];
    let mut failures = Vec::new();
    for row in stdout.lines() {
        let fields: Vec<_> = row.split_whitespace().collect();
        assert_eq!(fields.len(), 2 + limits.len(), "{row}");
        let mut heap = VecHeap::new();
        let term = from_owned(&decode(&unhex(fields[1])).unwrap(), &mut heap).unwrap();
        for (index, limit) in limits.iter().enumerate() {
            let mut out = Vec::new();
            erts_printf_t(&mut out, term, *limit);
            let expected = unhex(fields[2 + index]);
            let expected = String::from_utf8_lossy(&expected).replace('\u{1}', &channel);
            let got = String::from_utf8_lossy(&out).into_owned();
            if got != expected {
                let cut = |s: &str| s.chars().take(300).collect::<String>();
                failures.push(format!(
                    "{} limit {limit}:\n  erts: {}\n  ours: {}",
                    fields[0],
                    cut(&expected),
                    cut(&got)
                ));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
