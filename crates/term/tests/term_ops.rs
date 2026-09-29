use arinsal_etf::{EncodeOptions, decode, encode};
use arinsal_term::{
    Term, TermBuilder, VecHeap, build_hamt_from_unique, cmp, copy_term, exact_eq, from_owned,
    make_hash2, size_object, to_owned,
};
use std::cmp::Ordering;
use std::process::Command;

fn hex_bytes(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let digit = |byte: u8| (byte as char).to_digit(16).unwrap() as u8;
            (digit(pair[0]) << 4) | digit(pair[1])
        })
        .collect()
}

#[test]
fn differential_generated_terms_and_etf_roundtrip() {
    let expression = "F=fun(N)->case N rem 7 of 0->N-128;1->{N rem 11,[N,N+1],ok};2->lists:seq(N rem 9,N rem 9+5);3->#{(N rem 13)=>N,ok=>[N,N+1]};4-><<(N band 255),((N bsr 2) band 255)>>;5->(N-128)/7;6->(1 bsl (60+N rem 9))+N end end,lists:foreach(fun(N)->T=F(N),U=F((N*37+11) rem 257),C=case T<U of true-> -1;false->case T==U of true->0;false->1 end end,io:format(\"~B ~B ~B ~B ~s ~s~n\",[case T=:=U of true->1;false->0 end,C,erlang:phash2(T,4294967296),erts_debug:flat_size(T),binary:encode_hex(term_to_binary(T)),binary:encode_hex(term_to_binary(U))]) end,lists:seq(0,255)),halt().";
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
    let mut source = VecHeap::new();
    let mut destination = VecHeap::new();
    for (index, row) in stdout.lines().enumerate() {
        let fields: Vec<_> = row.split_whitespace().collect();
        assert_eq!(fields.len(), 6, "row {index}: {row}");
        let term = from_owned(&decode(&hex_bytes(fields[4])).unwrap(), &mut source).unwrap();
        let other = from_owned(&decode(&hex_bytes(fields[5])).unwrap(), &mut source).unwrap();
        let expected_eq = fields[0] == "1";
        let expected_order = fields[1].parse::<i8>().unwrap();
        let order = match cmp(term, other) {
            Ordering::Less => -1,
            Ordering::Equal => 0,
            Ordering::Greater => 1,
        };
        assert_eq!(exact_eq(term, other), expected_eq, "equality case {index}");
        assert_eq!(order, expected_order, "ordering case {index}");
        assert_eq!(
            make_hash2(term),
            fields[2].parse::<u32>().unwrap(),
            "hash case {index}"
        );
        let before = destination.used_words();
        let copied = copy_term(term, &mut destination).unwrap();
        assert!(exact_eq(term, copied), "copy case {index}");
        assert_eq!(destination.used_words() - before, size_object(term));
        let encoded = encode(&to_owned(copied).unwrap(), EncodeOptions::default());
        let decoded = from_owned(&decode(&encoded).unwrap(), &mut source).unwrap();
        assert!(exact_eq(term, decoded), "ETF case {index}");
    }
    assert_eq!(stdout.lines().count(), 256);
}

#[test]
fn reordered_maps_and_nested_cons_copy() {
    let pairs: Vec<_> = (0..64)
        .map(|n| (Term::small(n).unwrap(), Term::small(n * 3).unwrap()))
        .collect();
    let mut first_heap = VecHeap::new();
    let mut second_heap = VecHeap::new();
    let first = build_hamt_from_unique(&pairs, &mut first_heap).unwrap();
    let second = build_hamt_from_unique(
        &pairs.iter().copied().rev().collect::<Vec<_>>(),
        &mut second_heap,
    )
    .unwrap();
    assert!(exact_eq(first, second));

    let mut source = VecHeap::new();
    let mut list = Term::small(99).unwrap();
    for n in 0..2_048 {
        let head = if n % 3 == 0 {
            TermBuilder::new(&mut source)
                .tuple(&[Term::small(n).unwrap(), first])
                .unwrap()
        } else {
            Term::small(n).unwrap()
        };
        list = TermBuilder::new(&mut source).cons(head, list).unwrap();
    }
    let mut destination = VecHeap::new();
    let copied = copy_term(list, &mut destination).unwrap();
    assert!(exact_eq(list, copied));
    assert_eq!(destination.used_words(), size_object(list));
}

#[test]
fn arith_red_exact_atom_equality_uses_canonical_atom_ids() {
    let table = arinsal_term::global_atoms();
    let first = Term::atom(table.intern("arith_red_atom").unwrap());
    let same = Term::atom(table.intern("arith_red_atom").unwrap());
    let different = Term::atom(table.intern("arith_red_other_atom").unwrap());

    assert!(exact_eq(first, same));
    assert!(!exact_eq(first, different));
}
