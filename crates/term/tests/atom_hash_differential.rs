//! Atom-table hash against OTP 29.1.1.
//! `phash2(Term, 1 bsl 32)` is `make_hash2`: the low 32 bits of `atom_hash`.

use std::process::Command;

use arinsal_term::{AtomEncoding, AtomError, AtomTable, DEFAULT_ATOM_TABLE_LIMIT, global_atoms};

fn erl_stdout(expr: &str) -> Option<String> {
    let output = Command::new("erl")
        .args(["-noshell", "-eval", expr])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout).ok()
}

#[test]
fn atom_hash_low_32_matches_make_hash2() {
    let Some(text) = erl_stdout(
        "Names = [false, true, erlang, '', hello_world_atom,
                  list_to_atom(lists:duplicate(40, $x)),
                  list_to_atom([229, 228, 246]),
                  list_to_atom([16#1F600])],
         io:format(\"~p~n\", [[erlang:phash2(N, 1 bsl 32) || N <- Names]]),
         halt().",
    ) else {
        eprintln!("erl unavailable; skipping atom hash differential");
        return;
    };
    let hashes: Vec<u32> = text
        .trim()
        .trim_matches(['[', ']'])
        .split(',')
        .map(|part| part.trim().parse().expect("hash"))
        .collect();
    let long = "x".repeat(40);
    let names = [
        "false",
        "true",
        "erlang",
        "",
        "hello_world_atom",
        long.as_str(),
        "åäö",
        "😀",
    ];
    assert_eq!(hashes.len(), names.len(), "{text}");
    let table = global_atoms();
    for (name, hash) in names.into_iter().zip(hashes) {
        let atom = table
            .get(name)
            .unwrap_or_else(|| table.intern(name).unwrap());
        assert_eq!(table.hash(atom), Some(hash), "make_hash2({name})");
    }
}

#[test]
fn latin1_round_trip_and_limits_match_erl() {
    let Some(text) = erl_stdout(
        "A = list_to_atom([0, 127, 128, 255]),
         Reason = fun(B) -> element(1, element(2, catch binary_to_atom(B, utf8))) end,
         io:format(\"~w ~w ~p ~p ~p~n\", [
             binary_to_list(atom_to_binary(A, utf8)),
             binary_to_list(atom_to_binary(A, latin1)),
             Reason(<<255,255>>),
             Reason(list_to_binary(lists:duplicate(256, $a))),
             Reason(list_to_binary(lists:duplicate(1021, 255)))]),
         halt().",
    ) else {
        eprintln!("erl unavailable; skipping atom encoding differential");
        return;
    };
    let mut parts = text.split_whitespace();
    let utf8 = parts.next().unwrap();
    let latin1 = parts.next().unwrap();
    let bad = parts.next().unwrap();
    let too_long = parts.next().unwrap();
    let too_many_bytes = parts.next().unwrap();

    let table = AtomTable::new(DEFAULT_ATOM_TABLE_LIMIT);
    let atom = table
        .put(&[0, 127, 128, 255], AtomEncoding::Latin1, false)
        .unwrap();
    let stored: Vec<u8> = table.text(atom).unwrap().bytes().collect();
    assert_eq!(
        format!("{stored:?}").replace(' ', ""),
        utf8.replace(' ', "")
    );
    assert_eq!(
        format!("{:?}", table.latin1_bytes(atom).unwrap()).replace(' ', ""),
        latin1.replace(' ', "")
    );
    assert_eq!(
        table.put(&[255, 255], AtomEncoding::Utf8, false),
        Err(AtomError::BadEncoding)
    );
    assert_eq!(
        table.put(&vec![b'a'; 256], AtomEncoding::Utf8, false),
        Err(AtomError::TooLong)
    );
    assert_eq!(
        table.put(&vec![0xff; 1021], AtomEncoding::Utf8, false),
        Err(AtomError::TooLong)
    );
    assert!(bad.contains("badarg"), "{bad}");
    assert!(too_long.contains("system_limit"), "{too_long}");
    assert!(too_many_bytes.contains("system_limit"), "{too_many_bytes}");
}
