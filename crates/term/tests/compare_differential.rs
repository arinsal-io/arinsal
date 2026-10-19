use arinsal_etf::decode;
use arinsal_term::{VecHeap, cmp, cmp_exact, exact_eq, from_owned, loose_eq};
use similar_asserts::assert_eq;
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
        Pairs = [
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
        assert_eq!(fields.len(), 6, "row {index}: {row}");
        let left = from_owned(&decode(&hex_bytes(fields[4])).unwrap(), &mut heap).unwrap();
        let right = from_owned(&decode(&hex_bytes(fields[5])).unwrap(), &mut heap).unwrap();
        assert_eq!(
            sign(cmp(left, right)),
            fields[0].parse::<i8>().unwrap(),
            "order {index}"
        );
        assert_eq!(
            sign(cmp_exact(left, right)),
            fields[1].parse::<i8>().unwrap(),
            "exact order {index}"
        );
        assert_eq!(
            loose_eq(left, right),
            fields[2] == "1",
            "loose equality {index}"
        );
        assert_eq!(
            exact_eq(left, right),
            fields[3] == "1",
            "exact equality {index}"
        );
    }
    assert_eq!(stdout.lines().count(), 17);
}
