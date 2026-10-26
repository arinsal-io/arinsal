use arinsal_bifs::{BifError, Ctx, ProcessHeapHandle};
use arinsal_difftest::{CallResult, Error as RefError, RefErl};
use arinsal_etf::OwnedTerm as O;
use arinsal_packet::{
    HTTP_HEADERS, HttpPacket, Packet, PacketOptions, PacketResult, PacketState, PacketType,
    parse_with_state,
};
use arinsal_term::{ProcessHeap, from_owned, to_owned};

fn atom(s: &str) -> O {
    O::atom(s)
}
fn option(name: &str, value: u32) -> O {
    O::Tuple(vec![atom(name), O::Int(value as i64)])
}
fn local(args: &[O]) -> CallResult {
    let mut heap = ProcessHeap::with_words(4096);
    let mut alloc = ProcessHeapHandle(&mut heap);
    let terms = args
        .iter()
        .map(|arg| from_owned(arg, &mut alloc).unwrap())
        .collect::<Vec<_>>();
    let mut state = arinsal_bifs::BifState::default();
    let mut ctx = Ctx::new(&mut alloc, &mut state);
    let bif = arinsal_packet::lookup("erlang", "decode_packet", 3).unwrap();
    match bif(&mut ctx, &terms) {
        Ok(value) => CallResult::Ok(to_owned(value).unwrap()),
        Err(BifError::Badarg { .. }) => CallResult::Exception {
            class: "error".into(),
            reason: atom("badarg"),
            stack_top: None,
        },
        Err(error) => panic!("unexpected error: {error:?}"),
    }
}
fn same(a: &CallResult, b: &CallResult) -> bool {
    match (a, b) {
        (CallResult::Ok(x), CallResult::Ok(y)) => x == y,
        (
            CallResult::Exception {
                class: ac,
                reason: ar,
                ..
            },
            CallResult::Exception {
                class: bc,
                reason: br,
                ..
            },
        ) => ac == bc && ar == br,
        _ => false,
    }
}
fn next(seed: &mut u64) -> u64 {
    *seed ^= *seed << 13;
    *seed ^= *seed >> 7;
    *seed ^= *seed << 17;
    *seed
}
fn data(kind: usize, i: usize, seed: &mut u64) -> Vec<u8> {
    let payload = match i % 9 {
        0 => b"".to_vec(),
        1 => b"x".to_vec(),
        2 => b"hello".to_vec(),
        3 => b"abc\r\ndef".to_vec(),
        4 => (0..(i % 40)).map(|_| next(seed) as u8).collect(),
        5 => vec![0, 1, 127, 128, 255],
        6 => b"GET /path HTTP/1.1\r\n".to_vec(),
        7 => b"01234567890123456789".to_vec(),
        _ => b"\r\n".to_vec(),
    };
    let mut bytes = match kind {
        0 => payload.clone(),
        1 => {
            let mut b = vec![payload.len() as u8];
            b.extend_from_slice(&payload);
            b
        }
        2 => {
            let mut b = (payload.len() as u16).to_be_bytes().to_vec();
            b.extend_from_slice(&payload);
            b
        }
        3 => {
            let mut b = (payload.len() as u32).to_be_bytes().to_vec();
            b.extend_from_slice(&payload);
            b
        }
        4 => {
            let mut b = if i.is_multiple_of(4) {
                vec![0x1f, 0x81, 0x01, 0x82, 0, payload.len() as u8]
            } else if i % 4 == 1 {
                vec![0x30, 0x81, payload.len() as u8]
            } else {
                vec![0x30, payload.len() as u8]
            };
            b.extend_from_slice(&payload);
            b
        }
        5 => {
            let mut b = (payload.len() as u32 | if i.is_multiple_of(2) { 0x8000_0000 } else { 0 })
                .to_be_bytes()
                .to_vec();
            b.extend_from_slice(&payload);
            b
        }
        6 => {
            let mut b = b"GIOP\x01\x02".to_vec();
            if i.is_multiple_of(2) {
                b.extend_from_slice(&[1, 0]);
                b.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            } else {
                b.extend_from_slice(&[0, 0]);
                b.extend_from_slice(&(payload.len() as u32).to_be_bytes());
            }
            b.extend_from_slice(&payload);
            b
        }
        7 => {
            let mut b = vec![1, 6, 0, 1];
            b.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            b.extend_from_slice(&[(i % 4) as u8, 0]);
            b.extend_from_slice(&payload);
            b.extend(vec![0; i % 4]);
            b
        }
        8 => {
            let mut b = payload.clone();
            if !i.is_multiple_of(3) {
                b.push(b'\n');
            }
            b
        }
        9 => {
            let mut b = vec![3, 0];
            b.extend_from_slice(&((payload.len() + 4) as u16).to_be_bytes());
            b.extend_from_slice(&payload);
            b
        }
        10 | 11 => {
            let uri = match i % 10 {
                0 => "*",
                1 => "/",
                2 => "/a?q=1",
                3 => "http://example.com:8080/a",
                4 => "HTTPS://[::1]:443/x",
                5 => "foo:bar",
                6 => "relative",
                7 => "http://host",
                8 => "https://x:bogus/z",
                _ => "http://[::1]/",
            };
            match i % 6 {
                0 => format!("GET {uri} HTTP/1.1\r\n").into_bytes(),
                1 => format!("CONNECT {uri} HTTP/2.0\n").into_bytes(),
                2 => format!("POST {uri}\r\n").into_bytes(),
                3 => b"HTTP/1.1 200 OK\r\n".to_vec(),
                4 => b"HTTP/2.0 404\n".to_vec(),
                _ => payload.clone(),
            }
        }
        12 | 13 => {
            let name = HTTP_HEADERS[i % HTTP_HEADERS.len()];
            match i % 7 {
                0 => format!("{name}: Value\r\nX").into_bytes(),
                1 => format!("{}:\tHello\nX", name.to_ascii_lowercase()).into_bytes(),
                2 => format!("{name}: one\r\n two\r\nX").into_bytes(),
                3 => b"X-Strange-Thing: a\r\nX".to_vec(),
                4 => b"\r\n".to_vec(),
                5 => b"Bad Header: x\nX".to_vec(),
                _ => format!("{name}: value\n").into_bytes(),
            }
        }
        14 => {
            let mut b = vec![22, 3, 3];
            b.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            b.extend_from_slice(&payload);
            b
        }
        _ => unreachable!(),
    };
    if i.is_multiple_of(11) && !bytes.is_empty() {
        bytes[0] ^= 0x7f;
    }
    if i.is_multiple_of(13) {
        bytes.truncate((next(seed) as usize) % (bytes.len() + 1));
    }
    if i.is_multiple_of(17) {
        bytes.extend_from_slice(b"trailing");
    }
    bytes
}

#[test]
fn differential_otp_29_generated() {
    let reference = match RefErl::shared() {
        Ok(value) => value,
        Err(RefError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("skipping OTP differential: erl or erlc not found");
            return;
        }
        Err(error) => panic!("OTP reference failed: {error}"),
    };
    let kinds = [
        O::Int(0),
        O::Int(1),
        O::Int(2),
        O::Int(4),
        atom("asn1"),
        atom("sunrm"),
        atom("cdr"),
        atom("fcgi"),
        atom("line"),
        atom("tpkt"),
        atom("http"),
        atom("http_bin"),
        atom("httph"),
        atom("httph_bin"),
        atom("ssl_tls"),
    ];
    let count = std::env::var("PACKET_CASES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(20_250usize);
    let mut seed = 0x9925_5512_3765_1983u64;
    for j in 0..count {
        let kind = j % kinds.len();
        let i = j / kinds.len();
        let bytes = data(kind, i, &mut seed);
        let mut opts = Vec::new();
        if i.is_multiple_of(5) {
            opts.push(option("packet_size", (i % 24 + 1) as u32));
        }
        if i.is_multiple_of(7) {
            opts.push(option("line_length", (i % 18 + 1) as u32));
        }
        if kind == 8 && i.is_multiple_of(9) {
            opts.push(option("line_delimiter", b'\r' as u32));
        }
        let args = [kinds[kind].clone(), O::Binary(bytes), O::list(opts)];
        let expected = reference.call("erlang", "decode_packet", &args);
        let actual = local(&args);
        assert!(
            same(&actual, &expected),
            "case {j} kind {kind} args {args:?}\nactual {actual:?}\nexpected {expected:?}"
        );
    }
    eprintln!("matched {count} generated OTP 29 decode_packet cases");
}

#[test]
fn registry_and_option_validation() {
    assert!(arinsal_packet::lookup("erlang", "decode_packet", 3).is_some());
    assert!(arinsal_packet::lookup("erlang", "decode_packet", 2).is_none());
    assert!(arinsal_packet::lookup("inet", "decode_packet", 3).is_none());
    for args in [
        [
            atom("raw"),
            O::Binary(vec![1]),
            O::list(vec![option("other", 1)]),
        ],
        [
            atom("http"),
            O::Binary(vec![1]),
            O::list(vec![option("line_delimiter", 10)]),
        ],
        [
            atom("raw"),
            O::Binary(vec![1]),
            O::list(vec![option("packet_size", u32::MAX)]),
        ],
    ] {
        if let O::List { .. } = &args[2] {
            let result = local(&args);
            if args[2] == O::list(vec![option("packet_size", u32::MAX)]) {
                assert!(matches!(result, CallResult::Ok(_)));
            } else {
                assert!(matches!(result, CallResult::Exception { .. }));
            }
        }
    }
}

#[test]
fn http_stream_state() {
    let mut state = PacketState::default();
    let bytes = b"GET / HTTP/1.1\r\nHost: example\r\n\r\n";
    let mut rest = bytes.as_slice();
    let mut events = Vec::new();
    for _ in 0..3 {
        let PacketResult::Ok {
            packet,
            rest: remaining,
        } = parse_with_state(PacketType::Http, rest, PacketOptions::default(), &mut state)
        else {
            panic!("complete HTTP stream");
        };
        let Packet::Http(http) = packet else {
            panic!("HTTP event");
        };
        events.push(http);
        rest = remaining;
    }
    assert!(matches!(events[0], HttpPacket::Request { .. }));
    assert!(matches!(events[1], HttpPacket::Header { .. }));
    assert!(matches!(events[2], HttpPacket::Eoh));
    assert!(rest.is_empty());
}

#[test]
fn differential_random_frames() {
    let reference = match RefErl::shared() {
        Ok(value) => value,
        Err(RefError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("skipping OTP differential: erl or erlc not found");
            return;
        }
        Err(error) => panic!("OTP reference failed: {error}"),
    };
    let kinds = [
        O::Int(0),
        O::Int(1),
        O::Int(2),
        O::Int(4),
        atom("asn1"),
        atom("sunrm"),
        atom("cdr"),
        atom("fcgi"),
        atom("line"),
        atom("tpkt"),
        atom("http"),
        atom("http_bin"),
        atom("httph"),
        atom("httph_bin"),
        atom("ssl_tls"),
    ];
    let mut seed = 0x619d_17b3_9f02_8351u64;
    for j in 0..4_500 {
        let kind = j % kinds.len();
        let len = (next(&mut seed) % 48) as usize;
        let bytes = (0..len).map(|_| next(&mut seed) as u8).collect();
        let mut opts = Vec::new();
        if j % 3 == 0 {
            opts.push(option("packet_size", (next(&mut seed) % 24 + 1) as u32));
        }
        if j % 4 == 0 {
            opts.push(option("line_length", (next(&mut seed) % 24 + 1) as u32));
        }
        let args = [kinds[kind].clone(), O::Binary(bytes), O::list(opts)];
        let expected = reference.call("erlang", "decode_packet", &args);
        let actual = local(&args);
        assert!(
            same(&actual, &expected),
            "random case {j} kind {kind} args {args:?}\nactual {actual:?}\nexpected {expected:?}"
        );
    }
    eprintln!("matched 4500 random OTP 29 decode_packet cases");
}
