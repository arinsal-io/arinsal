use std::fs;
use std::process::Command;

use arinsal_etf::{EncodeOptions, OwnedTerm as O, decode, encode};

use super::{atom, zlib, zstd};

fn call_zlib(name: &str, args: &[O]) -> O {
    zlib::dispatch(name, args, &None).unwrap_or_else(|_| panic!("{name} failed"))
}
fn call_zstd(name: &str, args: &[O]) -> O {
    zstd::dispatch(name, args, &None).unwrap_or_else(|_| panic!("{name} failed"))
}
fn chunks(result: O) -> (String, Vec<u8>, Option<O>) {
    let O::Tuple(ref items) = result else {
        panic!("not tuple")
    };
    let O::Atom(tag) = &items[0] else {
        panic!("not atom")
    };
    let mut out = Vec::new();
    let payload = items.last().unwrap();
    if let O::List { elems, .. } = payload {
        for item in elems {
            let O::Binary(b) = item else {
                panic!("not binary")
            };
            out.extend(b);
        }
    } else if let O::Binary(b) = payload {
        out.extend(b);
    }
    (
        tag.clone(),
        out,
        if items.len() == 3 {
            Some(items[1].clone())
        } else {
            None
        },
    )
}
fn reference(cases: &O, body: &str) -> Option<O> {
    if Command::new("erl").arg("-version").output().is_err() {
        eprintln!("skipping OTP differential: erl missing");
        return None;
    }
    let dir = std::env::temp_dir().join(format!(
        "arinsal-zlib-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    fs::create_dir_all(&dir).unwrap();
    let input = dir.join("input.etf");
    let output = dir.join("output.etf");
    fs::write(&input, encode(cases, EncodeOptions::default())).unwrap();
    let eval = format!(
        "{{ok, B}} = file:read_file(\"{}\"), Cases = binary_to_term(B), Results = {}, ok = file:write_file(\"{}\", term_to_binary(Results)), halt().",
        input.display(),
        body,
        output.display()
    );
    let result = Command::new("erl")
        .args(["-noshell", "-eval", &eval])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "OTP failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let expected = decode(&fs::read(output).unwrap()).unwrap();
    fs::remove_dir_all(dir).unwrap();
    Some(expected)
}
fn random(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}
fn cases(count: usize) -> Vec<Vec<u8>> {
    let mut seed = 0x9178_35ab_662e_5d01u64;
    (0..count)
        .map(|i| {
            let n = match i % 100 {
                0 => 1_048_576,
                1 => 0,
                2 => 1,
                3..=8 => (random(&mut seed) % 16) as usize,
                9..=88 => (random(&mut seed) % 8192) as usize,
                _ => (random(&mut seed) % 65536) as usize,
            };
            let mut data = vec![0; n];
            for byte in &mut data {
                *byte = match i % 3 {
                    0 => (random(&mut seed) % 4) as u8,
                    1 => i as u8,
                    _ => random(&mut seed) as u8,
                };
            }
            data
        })
        .collect()
}
fn run_deflate(
    data: &[u8],
    level: i64,
    window: i64,
    mem: i64,
    strategy: i64,
    dict: &[u8],
) -> (O, Vec<u8>) {
    let h = call_zlib("open_nif", &[]);
    assert_eq!(
        call_zlib(
            "deflateInit_nif",
            &[
                h.clone(),
                O::Int(level),
                O::Int(8),
                O::Int(window),
                O::Int(mem),
                O::Int(strategy)
            ]
        ),
        atom("ok")
    );
    let checksum = if dict.is_empty() {
        atom("none")
    } else {
        call_zlib(
            "deflateSetDictionary_nif",
            &[h.clone(), O::Binary(dict.to_vec())],
        )
    };
    if !data.is_empty() {
        assert_eq!(
            call_zlib(
                "enqueue_nif",
                &[h.clone(), O::list(vec![O::Binary(data.to_vec())])]
            ),
            atom("ok")
        );
    }
    let mut output = Vec::new();
    loop {
        let (tag, b, _) = chunks(call_zlib(
            "deflate_nif",
            &[h.clone(), O::Int(8192), O::Int(8192), O::Int(4)],
        ));
        output.extend(b);
        if tag == "finished" {
            break;
        }
        assert_eq!(tag, "continue");
    }
    assert_eq!(
        call_zlib("deflateEnd_nif", std::slice::from_ref(&h)),
        atom("ok")
    );
    assert_eq!(call_zlib("close_nif", &[h]), atom("ok"));
    (checksum, output)
}
fn run_inflate(compressed: &[u8], window: i64, dict: &[u8]) -> Vec<u8> {
    let h = call_zlib("open_nif", &[]);
    assert_eq!(
        call_zlib("inflateInit_nif", &[h.clone(), O::Int(window), O::Int(2)]),
        atom("ok")
    );
    if window < 0 && !dict.is_empty() {
        assert_eq!(
            call_zlib(
                "inflateSetDictionary_nif",
                &[h.clone(), O::Binary(dict.to_vec())]
            ),
            atom("ok")
        );
    }
    assert_eq!(
        call_zlib(
            "enqueue_nif",
            &[h.clone(), O::list(vec![O::Binary(compressed.to_vec())])]
        ),
        atom("ok")
    );
    let mut output = Vec::new();
    loop {
        let (tag, part, _) = chunks(call_zlib(
            "inflate_nif",
            &[h.clone(), O::Int(8192), O::Int(16384), O::Int(0)],
        ));
        output.extend(part);
        if tag == "need_dictionary" {
            assert_eq!(
                call_zlib(
                    "inflateSetDictionary_nif",
                    &[h.clone(), O::Binary(dict.to_vec())]
                ),
                atom("ok")
            );
        } else if tag == "finished" {
            break;
        } else {
            assert_eq!(tag, "continue");
        }
    }
    assert_eq!(
        call_zlib("inflateEnd_nif", std::slice::from_ref(&h)),
        atom("ok")
    );
    assert_eq!(call_zlib("close_nif", &[h]), atom("ok"));
    output
}
#[test]
fn otp_zlib_deflate_differential() {
    let count = std::env::var("ARINSAL_ZLIB_CASES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(2000);
    let windows = [-15, -9, 9, 15, 25, 31];
    let strategies = ["default", "filtered", "huffman_only", "rle"];
    let mut input = Vec::new();
    for (i, data) in cases(count).into_iter().enumerate() {
        let window = windows[i % windows.len()];
        let dict = if window < 16 && i % 4 == 0 {
            b"dictionary-abcabcabcabc".to_vec()
        } else {
            Vec::new()
        };
        input.push(O::Tuple(vec![
            O::Binary(data),
            O::Int((i % 10) as i64),
            O::Int(window),
            O::Int(1 + (i % 9) as i64),
            atom(strategies[i % 4]),
            O::Binary(dict),
        ]));
    }
    let body = "[begin Z=zlib:open(), ok=zlib:deflateInit(Z,L,deflated,W,M,S), Dsum=case D of <<>> -> none; _ -> zlib:deflateSetDictionary(Z,D) end, Out=iolist_to_binary(zlib:deflate(Z,X,finish)), ok=zlib:deflateEnd(Z), ok=zlib:close(Z), {Dsum,Out} end || {X,L,W,M,S,D} <- Cases]";
    let Some(reference_output) = reference(&O::list(input.clone()), body) else {
        return;
    };
    let O::List {
        elems: expected, ..
    } = &reference_output
    else {
        panic!("not list")
    };
    for (i, (case, reference)) in input.iter().zip(expected).enumerate() {
        let O::Tuple(fields) = case else {
            unreachable!()
        };
        let O::Binary(data) = &fields[0] else {
            unreachable!()
        };
        let O::Binary(dict) = &fields[5] else {
            unreachable!()
        };
        let O::Atom(strategy) = &fields[4] else {
            unreachable!()
        };
        let strategy = match strategy.as_str() {
            "default" => 0,
            "filtered" => 1,
            "huffman_only" => 2,
            "rle" => 3,
            _ => unreachable!(),
        };
        let actual = run_deflate(
            data,
            (i % 10) as i64,
            super::number(&fields[2]).unwrap() as i64,
            1 + (i % 9) as i64,
            strategy,
            dict,
        );
        assert_eq!(
            &O::Tuple(vec![actual.0, O::Binary(actual.1)]),
            reference,
            "zlib case {i}"
        );
        let O::Tuple(parts) = reference else {
            unreachable!()
        };
        let O::Binary(ref_compressed) = &parts[1] else {
            unreachable!()
        };
        assert_eq!(
            run_inflate(
                ref_compressed,
                super::number(&fields[2]).unwrap() as i64,
                dict
            ),
            *data,
            "inflate case {i}"
        );
    }
}
fn run_zstd(name: &str, data: &[u8], pledge: bool) -> Vec<u8> {
    let init = if name == "compress" {
        "init_compress_nif"
    } else {
        "init_decompress_nif"
    };
    let stream = if name == "compress" {
        "compress_stream_nif"
    } else {
        "decompress_stream_nif"
    };
    let close = if name == "compress" {
        "compress_close_nif"
    } else {
        "decompress_close_nif"
    };
    let h = call_zstd(init, &[]);
    if pledge {
        assert_eq!(
            call_zstd(
                "set_pledged_src_size_nif",
                &[h.clone(), O::Int(data.len() as i64)]
            ),
            atom("ok")
        );
    }
    let mut rem = data.to_vec();
    let mut out = Vec::new();
    loop {
        let (tag, part, remaining) =
            chunks(call_zstd(stream, &[h.clone(), O::Binary(rem), O::Int(2)]));
        out.extend(part);
        if tag == "done" {
            break;
        }
        rem = if let Some(O::Binary(ref b)) = remaining {
            b.clone()
        } else {
            Vec::new()
        };
        assert!(tag == "flush" || tag == "continue");
    }
    assert_eq!(call_zstd(close, &[h]), atom("ok"));
    out
}
#[test]
fn otp_zstd_roundtrip_differential() {
    let count = std::env::var("ARINSAL_ZSTD_CASES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(2000);
    let input = cases(count).into_iter().map(O::Binary).collect::<Vec<_>>();
    let body = "[begin C=iolist_to_binary(zstd:compress(X)), {C, iolist_to_binary(zstd:decompress(C))} end || X <- Cases]";
    let Some(reference_output) = reference(&O::list(input.clone()), body) else {
        return;
    };
    let O::List {
        elems: expected, ..
    } = &reference_output
    else {
        panic!("not list")
    };
    for (i, (data, reference)) in input.iter().zip(expected).enumerate() {
        let O::Binary(data) = data else {
            unreachable!()
        };
        let O::Tuple(parts) = reference else {
            unreachable!()
        };
        let compressed = run_zstd("compress", data, true);
        assert_eq!(
            O::Binary(compressed.clone()),
            parts[0],
            "zstd bytes case {i}"
        );
        assert_eq!(
            run_zstd("decompress", &compressed, false),
            *data,
            "zstd own decode case {i}"
        );
        let O::Binary(otp_compressed) = &parts[0] else {
            unreachable!()
        };
        assert_eq!(
            run_zstd("decompress", otp_compressed, false),
            *data,
            "zstd OTP decode case {i}"
        );
        assert_eq!(parts[1], O::Binary(data.clone()), "OTP decode case {i}");
    }
}

#[test]
fn otp_zstd_dictionary_and_options() {
    let dict = b"common dictionary for the common payload and another common phrase".to_vec();
    let input = cases(100).into_iter().map(O::Binary).collect::<Vec<_>>();
    let body = "[begin D = <<\"common dictionary for the common payload and another common phrase\">>, C=iolist_to_binary(zstd:compress(X, #{dictionary => D, compressionLevel => 5})), P=iolist_to_binary(zstd:decompress(C, #{dictionary => D})), {C,P} end || X <- Cases]";
    let Some(reference_output) = reference(&O::list(input.clone()), body) else {
        return;
    };
    let O::List {
        elems: expected, ..
    } = &reference_output
    else {
        panic!("not list")
    };
    for (i, (data, reference)) in input.iter().zip(expected).enumerate() {
        let O::Binary(data) = data else {
            unreachable!()
        };
        let O::Tuple(parts) = reference else {
            unreachable!()
        };
        let h = call_zstd("init_compress_nif", &[]);
        assert_eq!(
            call_zstd(
                "set_compress_parameter_nif",
                &[h.clone(), atom("compressionLevel"), O::Int(5)]
            ),
            atom("ok")
        );
        assert_eq!(
            call_zstd(
                "load_compress_dictionary_nif",
                &[h.clone(), O::Binary(dict.clone())]
            ),
            atom("ok")
        );
        assert_eq!(
            call_zstd(
                "set_pledged_src_size_nif",
                &[h.clone(), O::Int(data.len() as i64)]
            ),
            atom("ok")
        );
        let mut rem = data.clone();
        let mut compressed = Vec::new();
        loop {
            let (tag, part, remainder) = chunks(call_zstd(
                "compress_stream_nif",
                &[h.clone(), O::Binary(rem), O::Int(2)],
            ));
            compressed.extend(part);
            if tag == "done" {
                break;
            }
            rem = if let Some(O::Binary(ref b)) = remainder {
                b.clone()
            } else {
                Vec::new()
            };
        }
        assert_eq!(call_zstd("compress_close_nif", &[h]), atom("ok"));
        assert_eq!(
            O::Binary(compressed.clone()),
            parts[0],
            "dictionary bytes case {i}"
        );
        let dctx = call_zstd("init_decompress_nif", &[]);
        assert_eq!(
            call_zstd(
                "load_decompress_dictionary_nif",
                &[dctx.clone(), O::Binary(dict.clone())]
            ),
            atom("ok")
        );
        let mut rem = compressed;
        let mut plain = Vec::new();
        loop {
            let (tag, part, remainder) = chunks(call_zstd(
                "decompress_stream_nif",
                &[dctx.clone(), O::Binary(rem), O::Int(2)],
            ));
            plain.extend(part);
            if tag == "done" {
                break;
            }
            rem = if let Some(O::Binary(ref b)) = remainder {
                b.clone()
            } else {
                Vec::new()
            };
            assert_eq!(tag, "continue");
        }
        assert_eq!(plain, *data, "dictionary decode case {i}");
        assert_eq!(call_zstd("decompress_close_nif", &[dctx]), atom("ok"));
        assert_eq!(parts[1], O::Binary(data.clone()));
    }
}

#[test]
fn state_and_error_behavior() {
    let h = call_zlib("open_nif", &[]);
    assert!(
        matches!(zlib::dispatch("inflate_nif", &[h.clone(), O::Int(8192), O::Int(16384), O::Int(0)], &None), Err(super::Fault::Reason(r)) if r == atom("not_initialized"))
    );
    assert_eq!(
        call_zlib(
            "deflateInit_nif",
            &[
                h.clone(),
                O::Int(6),
                O::Int(8),
                O::Int(15),
                O::Int(8),
                O::Int(0)
            ]
        ),
        atom("ok")
    );
    assert!(
        matches!(zlib::dispatch("deflateInit_nif", &[h.clone(), O::Int(6), O::Int(8), O::Int(15), O::Int(8), O::Int(0)], &None), Err(super::Fault::Reason(r)) if r == atom("already_initialized"))
    );
    assert!(
        matches!(zlib::dispatch("inflate_nif", &[h.clone(), O::Int(8192), O::Int(16384), O::Int(0)], &None), Err(super::Fault::Reason(r)) if r == atom("not_initialized"))
    );
    assert_eq!(
        call_zlib("deflateEnd_nif", std::slice::from_ref(&h)),
        atom("ok")
    );
    assert_eq!(
        call_zlib("inflateInit_nif", &[h.clone(), O::Int(15), O::Int(2)]),
        atom("ok")
    );
    assert_eq!(
        call_zlib(
            "enqueue_nif",
            &[h.clone(), O::list(vec![O::Binary(vec![1, 2, 3, 4, 5])])]
        ),
        atom("ok")
    );
    assert!(
        matches!(zlib::dispatch("inflate_nif", &[h.clone(), O::Int(8192), O::Int(16384), O::Int(0)], &None), Err(super::Fault::Reason(r)) if r == atom("data_error"))
    );
    assert!(
        matches!(zlib::dispatch("inflateEnd_nif", std::slice::from_ref(&h), &None), Err(super::Fault::Reason(r)) if r == atom("data_error"))
    );
    assert_eq!(call_zlib("close_nif", std::slice::from_ref(&h)), atom("ok"));
    assert!(
        matches!(zlib::dispatch("close_nif", &[h], &None), Err(super::Fault::Reason(r)) if r == atom("not_initialized"))
    );

    let c = call_zstd("init_compress_nif", &[]);
    assert!(matches!(
        zstd::dispatch(
            "set_compress_parameter_nif",
            &[c.clone(), atom("bogus"), O::Int(1)],
            &None
        ),
        Err(super::Fault::Reason(O::Tuple(_)))
    ));
    assert!(matches!(
        zstd::dispatch(
            "decompress_stream_nif",
            &[c.clone(), O::Binary(vec![]), O::Int(2)],
            &None
        ),
        Err(super::Fault::Badarg)
    ));
    assert_eq!(
        call_zstd(
            "set_compress_parameter_nif",
            &[c.clone(), atom("checksumFlag"), atom("true")]
        ),
        atom("ok")
    );
    assert_eq!(
        call_zstd(
            "get_compress_parameter_nif",
            &[c.clone(), atom("checksumFlag")]
        ),
        atom("false")
    );
    assert_eq!(
        call_zstd("compress_close_nif", std::slice::from_ref(&c)),
        atom("ok")
    );
    assert!(matches!(
        zstd::dispatch(
            "compress_stream_nif",
            &[c, O::Binary(vec![]), O::Int(2)],
            &None
        ),
        Err(super::Fault::Badarg)
    ));
}

fn error_reason(result: super::Outcome) -> O {
    match result {
        Err(super::Fault::Reason(reason)) => reason,
        Err(super::Fault::Badarg) => atom("badarg"),
        other => panic!("expected error, got {other:?}"),
    }
}
#[test]
fn otp_error_reasons() {
    let body = "[(fun() -> Z=zlib:open(), R=try zlib:inflate(Z, <<1>>) of _ -> none catch error:E -> E end, zlib:close(Z), R end)(), (fun() -> Z=zlib:open(), zlib:deflateInit(Z), R=try zlib:inflate(Z, <<1>>) of _ -> none catch error:E -> E end, try zlib:deflateEnd(Z) catch _:_ -> ok end, zlib:close(Z), R end)(), (fun() -> Z=zlib:open(), zlib:inflateInit(Z), R=try zlib:inflate(Z, <<1,2,3,4,5>>) of _ -> none catch error:E -> E end, try zlib:inflateEnd(Z) catch _:_ -> ok end, zlib:close(Z), R end)(), (fun() -> {ok,C}=zstd:context(compress), R=try zstd:set_parameter(C,bogus,1) of _ -> none catch error:E -> E end, zstd:close(C), R end)(), (fun() -> R=try zstd:decompress(<<1,2,3>>) of _ -> none catch error:E -> E end, R end)()]";
    let Some(expected) = reference(&O::Nil, body) else {
        return;
    };
    let O::List { elems, .. } = &expected else {
        panic!("not list")
    };
    let h = call_zlib("open_nif", &[]);
    assert_eq!(
        error_reason(zlib::dispatch(
            "enqueue_nif",
            &[h.clone(), O::list(vec![O::Binary(vec![1])])],
            &None
        )),
        elems[0]
    );
    assert_eq!(
        call_zlib(
            "deflateInit_nif",
            &[
                h.clone(),
                O::Int(6),
                O::Int(8),
                O::Int(15),
                O::Int(8),
                O::Int(0)
            ]
        ),
        atom("ok")
    );
    assert_eq!(
        error_reason(zlib::dispatch(
            "inflate_nif",
            &[h.clone(), O::Int(8192), O::Int(16384), O::Int(0)],
            &None
        )),
        elems[1]
    );
    assert_eq!(
        call_zlib("deflateEnd_nif", std::slice::from_ref(&h)),
        atom("ok")
    );
    assert_eq!(
        call_zlib("inflateInit_nif", &[h.clone(), O::Int(15), O::Int(2)]),
        atom("ok")
    );
    assert_eq!(
        call_zlib(
            "enqueue_nif",
            &[h.clone(), O::list(vec![O::Binary(vec![1, 2, 3, 4, 5])])]
        ),
        atom("ok")
    );
    assert_eq!(
        error_reason(zlib::dispatch(
            "inflate_nif",
            &[h, O::Int(8192), O::Int(16384), O::Int(0)],
            &None
        )),
        elems[2]
    );
    let c = call_zstd("init_compress_nif", &[]);
    assert_eq!(
        error_reason(zstd::dispatch(
            "set_compress_parameter_nif",
            &[c, atom("bogus"), O::Int(1)],
            &None
        )),
        elems[3]
    );
    let d = call_zstd("init_decompress_nif", &[]);
    assert_eq!(
        error_reason(zstd::dispatch(
            "decompress_stream_nif",
            &[d, O::Binary(vec![1, 2, 3]), O::Int(2)],
            &None
        )),
        elems[4]
    );
}

#[test]
fn otp_zstd_referenced_dictionaries() {
    let dict = b"common dictionary for the common payload and another common phrase".to_vec();
    let input = cases(20).into_iter().map(O::Binary).collect::<Vec<_>>();
    let body = "[begin D = <<\"common dictionary for the common payload and another common phrase\">>, {ok,CD}=zstd:dict(compress,D,#{compressionLevel=>5}), C=iolist_to_binary(zstd:compress(X,#{dictionary=>CD})), {ok,DD}=zstd:dict(decompress,D), P=iolist_to_binary(zstd:decompress(C,#{dictionary=>DD})), {C,P} end || X <- Cases]";
    let Some(reference_output) = reference(&O::list(input.clone()), body) else {
        return;
    };
    let O::List {
        elems: expected, ..
    } = &reference_output
    else {
        panic!("not list")
    };
    let cd = call_zstd("create_cdict_nif", &[O::Binary(dict.clone()), O::Int(5)]);
    let dd = call_zstd("create_ddict_nif", &[O::Binary(dict)]);
    assert_eq!(
        call_zstd("getDictId_fromCDict_nif", std::slice::from_ref(&cd)),
        O::Int(0)
    );
    assert_eq!(
        call_zstd("getDictId_fromDDict_nif", std::slice::from_ref(&dd)),
        O::Int(0)
    );
    for (i, (data, reference)) in input.iter().zip(expected).enumerate() {
        let O::Binary(data) = data else {
            unreachable!()
        };
        let O::Tuple(parts) = reference else {
            unreachable!()
        };
        let c = call_zstd("init_compress_nif", &[]);
        assert_eq!(
            call_zstd("ref_compress_dictionary_nif", &[c.clone(), cd.clone()]),
            atom("ok")
        );
        assert_eq!(
            call_zstd(
                "set_pledged_src_size_nif",
                &[c.clone(), O::Int(data.len() as i64)]
            ),
            atom("ok")
        );
        let mut rem = data.clone();
        let mut compressed = Vec::new();
        loop {
            let (tag, part, remainder) = chunks(call_zstd(
                "compress_stream_nif",
                &[c.clone(), O::Binary(rem), O::Int(2)],
            ));
            compressed.extend(part);
            if tag == "done" {
                break;
            }
            rem = if let Some(O::Binary(ref b)) = remainder {
                b.clone()
            } else {
                Vec::new()
            };
        }
        let O::Binary(otp_bytes) = &parts[0] else {
            unreachable!()
        };
        if &compressed != otp_bytes {
            let first = compressed.iter().zip(otp_bytes).position(|(a, b)| a != b);
            panic!(
                "cdict bytes case {i}: lengths {} vs {}, first mismatch {first:?}",
                compressed.len(),
                otp_bytes.len()
            );
        }
        let d = call_zstd("init_decompress_nif", &[]);
        assert_eq!(
            call_zstd("ref_decompress_dictionary_nif", &[d.clone(), dd.clone()]),
            atom("ok")
        );
        let mut rem = compressed;
        let mut plain = Vec::new();
        loop {
            let (tag, part, remainder) = chunks(call_zstd(
                "decompress_stream_nif",
                &[d.clone(), O::Binary(rem), O::Int(2)],
            ));
            plain.extend(part);
            if tag == "done" {
                break;
            }
            rem = if let Some(O::Binary(ref b)) = remainder {
                b.clone()
            } else {
                Vec::new()
            };
        }
        assert_eq!(plain, *data, "ddict decode case {i}");
        assert_eq!(parts[1], O::Binary(data.clone()));
    }
}

#[test]
fn caller_pid_controls_resources() {
    let p1 = O::Pid {
        node: "nonode@nohost".into(),
        id: 11,
        serial: 0,
        creation: 0,
    };
    let p2 = O::Pid {
        node: "nonode@nohost".into(),
        id: 12,
        serial: 0,
        creation: 0,
    };
    let h = zlib::dispatch("open_nif", &[], &Some(p1.clone())).unwrap();
    assert_eq!(
        error_reason(zlib::dispatch(
            "close_nif",
            std::slice::from_ref(&h),
            &Some(p2.clone())
        )),
        atom("not_on_controlling_process")
    );
    assert_eq!(
        zlib::dispatch(
            "set_controller_nif",
            &[h.clone(), p2.clone()],
            &Some(p1.clone())
        )
        .unwrap(),
        atom("ok")
    );
    assert_eq!(
        error_reason(zlib::dispatch(
            "close_nif",
            std::slice::from_ref(&h),
            &Some(p1.clone())
        )),
        atom("not_on_controlling_process")
    );
    assert_eq!(
        zlib::dispatch("close_nif", &[h], &Some(p2.clone())).unwrap(),
        atom("ok")
    );
    let c = zstd::dispatch("init_compress_nif", &[], &Some(p1.clone())).unwrap();
    assert_eq!(
        error_reason(zstd::dispatch(
            "compress_close_nif",
            std::slice::from_ref(&c),
            &Some(p2)
        )),
        atom("not_on_controlling_process")
    );
    assert_eq!(
        zstd::dispatch("compress_close_nif", &[c], &Some(p1)).unwrap(),
        atom("ok")
    );
}

#[test]
fn otp_zstd_frame_headers() {
    let input = cases(12).into_iter().map(O::Binary).collect::<Vec<_>>();
    let body = "[zstd:get_frame_header(iolist_to_binary(zstd:compress(X))) || X <- Cases]";
    let Some(reference_output) = reference(&O::list(input.clone()), body) else {
        return;
    };
    let O::List {
        elems: expected, ..
    } = &reference_output
    else {
        panic!("not list")
    };
    for (i, (data, expected)) in input.iter().zip(expected).enumerate() {
        let O::Binary(data) = data else {
            unreachable!()
        };
        let frame = run_zstd("compress", data, true);
        assert_eq!(
            call_zstd("getDictId_fromFrame_nif", &[O::Binary(frame.clone())]),
            O::Int(0)
        );
        let actual = call_zstd("get_frame_header_nif", &[O::Binary(frame)]);
        let O::Tuple(actual_pair) = &actual else {
            panic!("not tuple")
        };
        let O::Tuple(expected_pair) = expected else {
            panic!("not tuple")
        };
        assert_eq!(actual_pair[0], expected_pair[0]);
        let O::Map(actual_fields) = &actual_pair[1] else {
            panic!("not map")
        };
        let O::Map(expected_fields) = &expected_pair[1] else {
            panic!("not map")
        };
        for (key, value) in actual_fields {
            let otp_value = expected_fields
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v)
                .unwrap();
            assert_eq!(value, otp_value, "header field {key:?}, case {i}");
        }
    }
}

#[test]
fn otp_inflate_chunk_protocol() {
    let input = cases(100).into_iter().map(O::Binary).collect::<Vec<_>>();
    let body = "begin P=self(), T=spawn(fun F() -> receive {barrier,N} -> P!{barrier,N}, F(); M -> P!{trace,M}, F() end end), G=fun G(Acc,N) -> receive {barrier,N} -> lists:reverse(Acc); {trace,{trace,_,return_from,{zlib,inflate_nif,4},R}} -> G([R|Acc],N); {trace,_} -> G(Acc,N) end end, erlang:trace_pattern({zlib,inflate_nif,4}, [{'_',[],[{return_trace}]}],[local]), erlang:trace(self(),true,[call,{tracer,T}]), [begin Compressed=zlib:compress(X), Z=zlib:open(), zlib:inflateInit(Z), _=zlib:inflate(Z,Compressed), zlib:inflateEnd(Z), zlib:close(Z), Ref=erlang:trace_delivered(self()), receive {trace_delivered,_,Ref} -> ok end, T!{barrier,I}, {Compressed,G([],I)} end || {X,I} <- lists:zip(Cases,lists:seq(1,length(Cases)))] end";
    let Some(reference_output) = reference(&O::list(input), body) else {
        return;
    };
    let O::List {
        elems: expected, ..
    } = &reference_output
    else {
        panic!("not list")
    };
    for (i, case) in expected.iter().enumerate() {
        let O::Tuple(parts) = case else {
            panic!("not tuple")
        };
        let O::Binary(compressed) = &parts[0] else {
            panic!("not binary")
        };
        let trace: &[O] = match &parts[1] {
            O::List { elems, .. } => elems,
            O::Nil => &[],
            _ => panic!("not trace list"),
        };
        let h = call_zlib("open_nif", &[]);
        assert_eq!(
            call_zlib("inflateInit_nif", &[h.clone(), O::Int(15), O::Int(2)]),
            atom("ok")
        );
        assert_eq!(
            call_zlib(
                "enqueue_nif",
                &[h.clone(), O::list(vec![O::Binary(compressed.clone())])]
            ),
            atom("ok")
        );
        let mut actual = Vec::new();
        loop {
            let result = call_zlib(
                "inflate_nif",
                &[h.clone(), O::Int(8192), O::Int(16384), O::Int(0)],
            );
            let O::Tuple(fields) = &result else {
                panic!("not tuple")
            };
            let done = fields[0] == atom("finished");
            actual.push(result);
            if done {
                break;
            }
        }
        assert_eq!(&actual, trace, "chunk protocol case {i}");
        assert_eq!(
            call_zlib("inflateEnd_nif", std::slice::from_ref(&h)),
            atom("ok")
        );
        assert_eq!(call_zlib("close_nif", &[h]), atom("ok"));
    }
}

#[test]
fn direct_nif_chunk_size_edges() {
    let h = call_zlib("open_nif", &[]);
    assert_eq!(
        call_zlib(
            "deflateInit_nif",
            &[
                h.clone(),
                O::Int(6),
                O::Int(8),
                O::Int(15),
                O::Int(8),
                O::Int(0)
            ]
        ),
        atom("ok")
    );
    assert_eq!(
        call_zlib("deflate_nif", &[h.clone(), O::Int(0), O::Int(0), O::Int(0)]),
        super::pair(atom("continue"), O::Nil)
    );
    assert_eq!(
        call_zlib(
            "deflate_nif",
            &[h.clone(), O::Int(1), O::Int(-1), O::Int(0)]
        ),
        atom("mem_error")
    );
    assert_eq!(
        call_zlib("enqueue_nif", &[h.clone(), O::Binary(vec![1])]),
        atom("ok")
    );
    assert_eq!(
        error_reason(zlib::dispatch(
            "deflate_nif",
            &[h.clone(), O::Int(0), O::Int(8192), O::Int(0)],
            &None
        )),
        atom("data_error")
    );
    assert_eq!(
        error_reason(zlib::dispatch(
            "deflateEnd_nif",
            std::slice::from_ref(&h),
            &None
        )),
        atom("data_error")
    );
    assert_eq!(call_zlib("close_nif", &[h]), atom("ok"));
}

#[test]
fn public_dispatch_and_pid_api() {
    use arinsal_bifs::{BifError, Ctx, ProcessHeapHandle};
    use arinsal_term::{ProcessHeap, from_owned, to_owned};
    fn invoke(name: &str, args: &[O], pid: Option<O>) -> Result<O, O> {
        let mut heap = ProcessHeap::with_words(256);
        let mut alloc = ProcessHeapHandle(&mut heap);
        let terms = args
            .iter()
            .map(|v| from_owned(v, &mut alloc).unwrap())
            .collect::<Vec<_>>();
        let caller = pid.map(|v| from_owned(&v, &mut alloc).unwrap());
        let mut ctx = Ctx::new(&mut alloc);
        match super::call_with_pid(&mut ctx, "zlib", name, &terms, caller) {
            Ok(term) => Ok(to_owned(term).unwrap()),
            Err(BifError::Error(reason)) => Err(to_owned(reason).unwrap()),
            Err(other) => panic!("unexpected BIF error {other:?}"),
        }
    }
    let p1 = O::Pid {
        node: "nonode@nohost".into(),
        id: 41,
        serial: 0,
        creation: 0,
    };
    let p2 = O::Pid {
        node: "nonode@nohost".into(),
        id: 42,
        serial: 0,
        creation: 0,
    };
    let h = invoke("open_nif", &[], Some(p1.clone())).unwrap();
    assert_eq!(
        invoke("close_nif", std::slice::from_ref(&h), Some(p2)),
        Err(atom("not_on_controlling_process"))
    );
    assert_eq!(invoke("close_nif", &[h], Some(p1)), Ok(atom("ok")));
    assert!(super::lookup("zlib", "open_nif", 0).is_some());
    assert!(super::lookup("zstd", "get_frame_header_nif", 1).is_some());
    assert!(super::lookup("zlib", "open_nif", 1).is_none());
}
