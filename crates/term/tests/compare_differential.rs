use arinsal_etf::decode;
use arinsal_term::{VecHeap, cmp, cmp_exact, exact_eq, from_owned, loose_eq};
use std::cmp::Ordering;
use std::process::Command;

fn hex_bytes(hex: &str) -> Vec<u8> {
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

fn sign(order: Ordering) -> i8 {
    match order {
        Ordering::Less => -1,
        Ordering::Equal => 0,
        Ordering::Greater => 1,
    }
}

#[test]
fn compound_term_comparison_matches_erts() {
    let expression = r#"
        BasePairs = [
            {{alpha, 1, {nested, [a, 2]}}, {alpha, 1, {nested, [a, 2]}}},
            {{alpha, 1, beta}, {alpha, 2, beta}},
            {[a, 1, b, 2], [a, 1, b, 3]},
            {[a, 1], [a, 1, b]},
            {#{1 => a, 2 => b}, #{1 => a, 2 => c}},
            {#{1 => a, 2 => b}, #{1 => a, 3 => b}},
            {#{zz_cmp_key => a, aa_cmp_key => b}, #{zz_cmp_key => a, aa_cmp_key => c}},
            {#{zz_cmp_key => a, bb_cmp_key => b}, #{zz_cmp_key => a, aa_cmp_key => b}},
            {#{1 => a, aa_cmp_key => b, {z, 1} => c},
             #{1 => a, aa_cmp_key => c, {z, 1} => c}},
            {#{number_key => 1}, #{number_key => 1.0}},
            {maps:from_list([{#{x => 1}, a}, {#{y => 2}, b}]),
             maps:from_list([{#{x => 1}, a}, {#{y => 3}, b}])},
            {maps:from_list([{#{x => 1}, nested} |
                             [{N, N} || N <- lists:seq(1, 40)]]),
             maps:from_list([{#{x => 2}, nested} |
                             [{N, N} || N <- lists:seq(1, 40)]])},
            {#{1 => #{x => 1}, 2 => {a, [2]}},
             #{1 => #{x => 2}, 2 => {a, [2]}}},
            {maps:from_list([{N, N} || N <- lists:seq(1, 40)]),
             maps:from_list([{N, N + 1} || N <- lists:seq(1, 40)])},
            {maps:from_list([{N, N} || N <- lists:seq(1, 40)]),
             maps:from_list([{N, N} || N <- lists:seq(2, 41)])},
            {maps:from_list([{N, N} || N <- lists:seq(1, 40)]),
             maps:from_list([{N, if N == 10 -> -1; true -> N end}
                             || N <- lists:seq(1, 39)] ++ [{41, 41}])},
            {maps:from_list([{N, N} || N <- lists:seq(1, 40)]),
             maps:from_list([{N, if N == 39 -> -1; true -> N end}
                             || N <- lists:seq(1, 39)] ++ [{41, 41}])},
            {maps:from_list([{N, N} || N <- lists:seq(1, 100)]),
             maps:from_list([{N, N} || N <- lists:seq(1, 99)] ++ [{101, 101}])},
            {maps:from_list([{N, if N == 1 -> #{x => 1}; true -> N end}
                             || N <- lists:seq(1, 40)]),
             maps:from_list([{N, if N == 1 -> #{x => 2}; true -> N end}
                             || N <- lists:seq(1, 40)])}
        ],
        LongLeft = lists:seq(1, 4096),
        LongRight = lists:seq(1, 4095) ++ [0],
        TupleLeft = list_to_tuple(lists:seq(1, 2048)),
        TupleRight = list_to_tuple(lists:seq(1, 2047) ++ [0]),
        DeepLeft = lists:foldl(fun(_, Acc) -> {branch, Acc} end,
                               leaf, lists:seq(1, 512)),
        DeepRight = lists:foldl(fun(_, Acc) -> {branch, Acc} end,
                                other_leaf, lists:seq(1, 512)),
        MapPairs = lists:append([
            begin
                Entries = [{K, K} || K <- lists:seq(1, N)],
                Map = maps:from_list(Entries),
                Reordered = maps:from_list(lists:reverse(Entries)),
                Changed = maps:from_list([{K, K + 1} || K <- lists:seq(1, N)]),
                [{Map, Reordered}, {Map, Changed}]
            end
            || N <- lists:seq(0, 40)
        ]),
        NumberPairs = [
            {9007199254740993, 9007199254740992.0},
            {9007199254740992, 9007199254740992.0},
            {(1 bsl 128) + 17, float(1 bsl 128)},
            {-(1 bsl 127) - 7, -float(1 bsl 127)}
        ],
        MixedPairs = [
            {[a, {b, [1, 2]}], [a, {b, [1, 3]}]}
        ],
        Pairs = BasePairs ++ MapPairs ++ NumberPairs ++ MixedPairs ++
                [{LongLeft, LongRight}, {TupleLeft, TupleRight},
                 {DeepLeft, DeepRight}],
        lists:foreach(fun({A, B}) ->
            Order = if A < B -> -1; A > B -> 1; true -> 0 end,
            ExactOrder = erts_internal:cmp_term(A, B),
            io:format("~B ~B ~B ~B ~s ~s~n", [
                Order, ExactOrder, if A == B -> 1; true -> 0 end,
                if A =:= B -> 1; true -> 0 end,
                binary:encode_hex(term_to_binary(A)),
                binary:encode_hex(term_to_binary(B))])
        end, Pairs),
        halt().
    "#;
    let output = match Command::new("erl")
        .args(["-noshell", "-eval", expression])
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
    let mut heap = VecHeap::new();
    for (index, row) in stdout.lines().enumerate() {
        let fields: Vec<_> = row.split_whitespace().collect();
        similar_asserts::assert_eq!(fields.len(), 6, "row {index}: {row}");
        let left = from_owned(&decode(&hex_bytes(fields[4])).unwrap(), &mut heap).unwrap();
        let right = from_owned(&decode(&hex_bytes(fields[5])).unwrap(), &mut heap).unwrap();
        similar_asserts::assert_eq!(
            sign(cmp(left, right)),
            fields[0].parse::<i8>().unwrap(),
            "order {index}"
        );
        similar_asserts::assert_eq!(
            sign(cmp_exact(left, right)),
            fields[1].parse::<i8>().unwrap(),
            "exact order {index}"
        );
        similar_asserts::assert_eq!(
            loose_eq(left, right),
            fields[2] == "1",
            "loose equality {index}"
        );
        similar_asserts::assert_eq!(
            exact_eq(left, right),
            fields[3] == "1",
            "exact equality {index}"
        );
    }
    similar_asserts::assert_eq!(stdout.lines().count(), 109);
}
