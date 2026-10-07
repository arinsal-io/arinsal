use arinsal_etf::{DecodeError, EncodeOptions, OwnedTerm, decode, decode_prefix, encode};
use std::process::Command;

fn next<'a>(bytes: &mut &'a [u8], n: usize) -> &'a [u8] {
    let (head, rest) = bytes.split_at(n);
    *bytes = rest;
    head
}
fn u32be(bytes: &mut &[u8]) -> usize {
    u32::from_be_bytes(next(bytes, 4).try_into().unwrap()) as usize
}

#[test]
fn otp_corpus() {
    if Command::new("escript").arg("--help").output().is_err() {
        eprintln!("skipping OTP corpus: escript is not installed");
        return;
    }
    let path = std::env::temp_dir().join(format!("arinsal-etf-corpus-{}", std::process::id()));
    let result = Command::new("escript")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/gen_corpus.escript"
        ))
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let data = std::fs::read(&path).unwrap();
    std::fs::remove_file(&path).unwrap();
    let mut input = data.as_slice();
    let count = u32be(&mut input);
    let options = [
        EncodeOptions::default(),
        EncodeOptions {
            minor_version: Some(0),
            ..Default::default()
        },
        EncodeOptions {
            minor_version: Some(1),
            ..Default::default()
        },
        EncodeOptions {
            compressed: Some(6),
            ..Default::default()
        },
        EncodeOptions {
            compressed: Some(9),
            ..Default::default()
        },
        EncodeOptions {
            deterministic: true,
            ..Default::default()
        },
    ];
    for _ in 0..count {
        let id = u32be(&mut input);
        for (index, opts) in options.iter().enumerate() {
            let n = u32be(&mut input);
            let bytes = next(&mut input, n);
            let term = decode(bytes).unwrap_or_else(|e| panic!("id {id} option {index}: {e}"));
            let actual = encode(&term, *opts);
            assert_eq!(actual, bytes, "id {id} option {index}, term {term:?}");
        }
    }
    assert_eq!(count, 385);
    assert!(input.is_empty());
}

#[test]
fn malformed_never_panics() {
    let terms: [&[u8]; 7] = [
        &[131, 110, 1],
        &[131, 77, 0, 0, 0, 1, 0, 0],
        &[131, 82, 0],
        &[131, 117],
        &[131, 70, 127, 248, 0, 0, 0, 0, 0, 0],
        &[131, 119, 1, 255],
        &[131, 108, 255, 255, 255, 255],
    ];
    for term in terms {
        for n in 0..=term.len() {
            let _ = decode(&term[..n]);
        }
    }
    let mut seed = 1_u64;
    for len in 0..64 {
        for _ in 0..100 {
            let mut bytes = vec![131];
            for _ in 0..len {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                bytes.push(seed as u8);
            }
            let _ = decode(&bytes);
        }
    }
}

#[test]
fn prefix_and_legacy_rejections() {
    assert_eq!(
        decode_prefix(&[131, 97, 1, 97, 2]),
        Ok((OwnedTerm::Int(1), 3))
    );
    assert_eq!(decode(&[131, 97, 1, 97, 2]), Err(DecodeError::Trailing(3)));
    assert!(decode(&[131, 82, 0]).is_err());
    assert!(decode(&[131, 117]).is_err());
}

#[test]
fn million_deep_tuple() {
    let depth = 1_000_000;
    let mut bytes = Vec::with_capacity(depth * 2 + 3);
    bytes.push(131);
    for _ in 0..depth {
        bytes.extend_from_slice(&[104, 1]);
    }
    bytes.extend_from_slice(&[97, 42]);
    let term = decode(&bytes).unwrap();
    let encoded = encode(&term, EncodeOptions::default());
    assert!(encoded == bytes, "deep round trip differs");
    drop(term);
}

#[test]
fn million_deep_list() {
    let depth = 1_000_000;
    let mut bytes = Vec::with_capacity(depth * 7 + 3);
    bytes.push(131);
    for _ in 0..depth {
        bytes.extend_from_slice(&[108, 0, 0, 0, 1]);
    }
    bytes.extend_from_slice(&[119, 1, 97]);
    bytes.extend(std::iter::repeat_n(106, depth));
    let term = decode(&bytes).unwrap();
    let encoded = encode(&term, EncodeOptions::default());
    assert!(encoded == bytes, "deep round trip differs");
    drop(term);
}

#[test]
fn legacy_tags_and_normalization() {
    let node = [
        119, 14, b'r', b'e', b'm', b'o', b't', b'e', b'@', b'f', b'i', b'x', b't', b'u', b'r', b'e',
    ];
    let mut cases: Vec<(Vec<u8>, OwnedTerm)> = vec![
        (vec![131, 98, 0, 0, 0, 1], OwnedTerm::Int(1)),
        (vec![131, 100, 0, 1, 233], OwnedTerm::atom("é")),
        (vec![131, 115, 1, 233], OwnedTerm::atom("é")),
        (vec![131, 118, 0, 2, 195, 169], OwnedTerm::atom("é")),
        (
            vec![131, 105, 0, 0, 0, 1, 97, 1],
            OwnedTerm::tuple(vec![OwnedTerm::Int(1)]),
        ),
        (vec![131, 108, 0, 0, 0, 0, 97, 1], OwnedTerm::Int(1)),
        (vec![131, 110, 1, 0, 1], OwnedTerm::Int(1)),
        (vec![131, 111, 0, 0, 0, 1, 1, 1], OwnedTerm::Int(-1)),
        (
            vec![131, 77, 0, 0, 0, 1, 8, 255],
            OwnedTerm::Binary(vec![255]),
        ),
        (
            vec![131, 77, 0, 0, 0, 1, 1, 255],
            OwnedTerm::BitString {
                bytes: vec![128],
                bits: 1,
            },
        ),
    ];
    let mut pid = vec![131, 103];
    pid.extend(node);
    pid.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 2, 3]);
    cases.push((
        pid,
        OwnedTerm::Pid {
            node: "remote@fixture".into(),
            id: 1,
            serial: 2,
            creation: 3,
        },
    ));
    let mut port = vec![131, 89];
    port.extend(node);
    port.extend_from_slice(&[0, 0, 0, 7, 0, 0, 0, 3]);
    cases.push((
        port,
        OwnedTerm::Port {
            node: "remote@fixture".into(),
            id: 7,
            creation: 3,
        },
    ));
    let mut reference = vec![131, 114, 0, 1];
    reference.extend(node);
    reference.extend_from_slice(&[3, 0, 0, 0, 7]);
    cases.push((
        reference,
        OwnedTerm::Ref {
            node: "remote@fixture".into(),
            creation: 3,
            ids: vec![7],
        },
    ));
    for (bytes, expected) in cases {
        let actual = decode(&bytes).unwrap();
        assert_eq!(actual, expected);
        assert_eq!(
            decode(&encode(&actual, EncodeOptions::default())).unwrap(),
            expected
        );
    }
}

#[test]
fn local_ext_is_opaque() {
    if Command::new("erl").arg("-version").output().is_err() {
        eprintln!("skipping LOCAL_EXT test: erl is not installed");
        return;
    }
    let result = Command::new("erl")
        .args([
            "-noshell",
            "-eval",
            "io:format(\"~w\",[binary_to_list(term_to_binary({a,1},[local]))]),halt().",
        ])
        .output()
        .unwrap();
    assert!(result.status.success());
    let text = String::from_utf8(result.stdout).unwrap();
    let bytes: Vec<u8> = text
        .trim_matches(['[', ']'])
        .split(',')
        .map(|s| s.parse().unwrap())
        .collect();
    let term = decode(&bytes).unwrap();
    assert!(matches!(term, OwnedTerm::Other { tag: 121, .. }));
    assert_eq!(encode(&term, EncodeOptions::default()), bytes);
}

#[test]
fn nested_atom_map_key_order_limit() {
    if Command::new("erl").arg("-version").output().is_err() {
        eprintln!("skipping map-key order limit: erl is not installed");
        return;
    }
    let eval = "Z=list_to_atom(\"zz_etf_map_key_gap_20260925\"),A=list_to_atom(\"aa_etf_map_key_gap_20260925\"),M1=maps:from_list([{Z,1},{A,2}]),M2=maps:from_list([{Z,2},{A,1}]),M=#{M1=>1,M2=>2},io:format(\"~w\",[binary_to_list(term_to_binary(M,[deterministic]))]),halt().";
    let output = Command::new("erl")
        .args(["-noshell", "-eval", eval])
        .output()
        .unwrap();
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    let bytes: Vec<u8> = text
        .trim_matches(['[', ']'])
        .split(',')
        .map(|s| s.parse().unwrap())
        .collect();
    let decoded = decode(&bytes).unwrap();
    let ours = encode(
        &decoded,
        EncodeOptions {
            deterministic: true,
            ..Default::default()
        },
    );
    assert_ne!(
        ours, bytes,
        "the frozen Map variant cannot retain inner atom indexes"
    );
}
