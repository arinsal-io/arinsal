use arinsal_arith as arith;
use arinsal_etf::{OwnedTerm, decode};
use arinsal_term::{Term, TermBuilder, VecHeap, from_owned, to_owned};
use num_bigint::BigInt;
use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Write};
use std::process::Command;

const OPS: [&str; 24] = [
    "+",
    "-",
    "*",
    "/",
    "div",
    "rem",
    "band",
    "bor",
    "bxor",
    "bsl",
    "bsr",
    "-",
    "+",
    "abs",
    "bnot",
    "float",
    "trunc",
    "round",
    "ceil",
    "floor",
    "integer_to_list",
    "integer_to_binary",
    "list_to_integer",
    "binary_to_integer",
];

fn mix(mut x: u64) -> u64 {
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}
fn integer(seed: u64) -> OwnedTerm {
    let v = match seed % 18 {
        0 => BigInt::from(1u64) << 1000,
        1 => -(BigInt::from(1u64) << 1000usize),
        2 => BigInt::from(1u64) << 64,
        3 => -(BigInt::from(1u64) << 64usize),
        4 => BigInt::from(1u64) << 63,
        5 => -(BigInt::from(1u64) << 63usize),
        6 => BigInt::from(1u64) << 59,
        7 => -(BigInt::from(1u64) << 59usize),
        8 => (BigInt::from(1u64) << 53) + 1,
        9 => BigInt::from(0),
        10 => BigInt::from(1),
        11 => BigInt::from(-1),
        12 => {
            (BigInt::from(1u64) << 1000usize)
                + (BigInt::from(seed) << 900usize)
                + BigInt::from(mix(seed))
        }
        13 => {
            (BigInt::from(1u64) << 1024usize)
                - (BigInt::from(1u64) << 971usize)
                - BigInt::from(seed)
        }
        15 => (BigInt::from(1u64) << 53usize) + 3,
        16 => (BigInt::from(1u64) << 63usize) + 1,
        17 => -((BigInt::from(1u64) << 63usize) + BigInt::from(1u64)),
        _ => BigInt::from((seed as i64) >> 8),
    };
    if let Ok(n) = i64::try_from(&v) {
        OwnedTerm::Int(n)
    } else {
        OwnedTerm::BigInt(v)
    }
}
fn number(seed: u64) -> OwnedTerm {
    if seed.is_multiple_of(7) {
        return OwnedTerm::Atom("foo".into());
    }
    if seed.is_multiple_of(3) {
        return OwnedTerm::Float(match (seed >> 6) % 10 {
            0 => -0.0,
            1 => f64::MAX,
            2 => f64::from_bits(1),
            3 => 0.5,
            4 => -0.5,
            5 => 1.5,
            6 => -1.5,
            7 => 2.0_f64.powi(53),
            _ => ((seed as i32) as f64) / 1024.0,
        });
    }
    integer(seed)
}
fn string(seed: u64, base: u32) -> String {
    match seed % 13 {
        0 => String::new(),
        1 => "+".into(),
        2 => "-".into(),
        3 => " 1".into(),
        4 => "1 ".into(),
        5 => "0x10".into(),
        6 => "16#FF".into(),
        7 => "--1".into(),
        8 => "-0".into(),
        9 => "+001".into(),
        _ => {
            let n = match &integer(seed >> 9) {
                OwnedTerm::Int(x) => BigInt::from(*x),
                OwnedTerm::BigInt(x) => x.clone(),
                _ => unreachable!(),
            };
            n.to_str_radix(base).to_ascii_uppercase()
        }
    }
}
fn case(index: usize) -> (&'static str, OwnedTerm, Option<OwnedTerm>) {
    let op = OPS[index % OPS.len()];
    let seed = mix(index as u64 + 0x5a17_9c02);
    let other = mix(seed);
    match index % OPS.len() {
        9 | 10 => {
            let shift = match other % 11 {
                0 => OwnedTerm::BigInt(BigInt::from(1u64) << 64),
                1 => OwnedTerm::BigInt(-(BigInt::from(1u64) << 64usize)),
                2 => OwnedTerm::Int(1000),
                3 => OwnedTerm::Int(-1000),
                4 => OwnedTerm::Int(64),
                5 => OwnedTerm::Int(-64),
                6 => OwnedTerm::Int(59),
                7 => OwnedTerm::Int(-59),
                8 => OwnedTerm::Int(0),
                9 => OwnedTerm::Float(1.0),
                _ => OwnedTerm::Int(1),
            };
            (op, integer(seed), Some(shift))
        }
        11..=19 => (op, number(seed), None),
        20 | 21 => (
            op,
            number(seed),
            Some(OwnedTerm::Int(2 + (other % 37) as i64)),
        ),
        22 | 23 => {
            let base = 2 + (other % 37) as u32;
            let s = string(seed, base.min(36));
            let value = if index % OPS.len() == 22 {
                OwnedTerm::list(s.bytes().map(|b| OwnedTerm::Int(b as i64)).collect())
            } else {
                OwnedTerm::Binary(s.into_bytes())
            };
            (op, value, Some(OwnedTerm::Int(base as i64)))
        }
        _ => (op, number(seed), Some(number(other))),
    }
}
fn literal(value: &OwnedTerm) -> String {
    match value {
        OwnedTerm::Int(v) => v.to_string(),
        OwnedTerm::BigInt(v) => v.to_string(),
        OwnedTerm::Float(v) => format!("{v:.17e}"),
        OwnedTerm::Atom(v) => v.clone(),
        OwnedTerm::Nil => "[]".into(),
        OwnedTerm::List { elems, tail } if **tail == OwnedTerm::Nil => {
            let mut s = "[".to_string();
            for (i, elem) in elems.iter().enumerate() {
                if i > 0 {
                    s.push(',');
                }
                write!(s, "{}", literal(elem)).unwrap();
            }
            s.push(']');
            s
        }
        OwnedTerm::Binary(bytes) => {
            let mut s = "<<".to_string();
            for (i, byte) in bytes.iter().enumerate() {
                if i > 0 {
                    s.push(',');
                }
                write!(s, "{byte}").unwrap();
            }
            s.push_str(">>");
            s
        }
        _ => unreachable!(),
    }
}
fn local(op: &str, a: Term, b: Option<Term>, heap: &mut VecHeap) -> arith::ArithResult {
    match op {
        "+" if b.is_none() => arith::plus(a, heap),
        "-" if b.is_none() => arith::neg(a, heap),
        "+" => arith::add(a, b.unwrap(), heap),
        "-" => arith::sub(a, b.unwrap(), heap),
        "*" => arith::mul(a, b.unwrap(), heap),
        "/" => arith::fdiv(a, b.unwrap(), heap),
        "div" => arith::int_div(a, b.unwrap(), heap),
        "rem" => arith::rem(a, b.unwrap(), heap),
        "band" => arith::band(a, b.unwrap(), heap),
        "bor" => arith::bor(a, b.unwrap(), heap),
        "bxor" => arith::bxor(a, b.unwrap(), heap),
        "bsl" => arith::bsl(a, b.unwrap(), heap),
        "bsr" => arith::bsr(a, b.unwrap(), heap),
        "abs" => arith::abs(a, heap),
        "bnot" => arith::bnot(a, heap),
        "float" => arith::to_float(a, heap),
        "trunc" => arith::trunc(a, heap),
        "round" => arith::round(a, heap),
        "ceil" => arith::ceil(a, heap),
        "floor" => arith::floor(a, heap),
        "integer_to_list" => arith::integer_to_list(a, b.unwrap(), heap),
        "integer_to_binary" => arith::integer_to_binary(a, b.unwrap(), heap),
        "list_to_integer" => arith::list_to_integer(a, b.unwrap(), heap),
        "binary_to_integer" => arith::binary_to_integer(a, b.unwrap(), heap),
        _ => unreachable!(),
    }
}
fn decode_hex(s: &str) -> OwnedTerm {
    let data: Vec<u8> = s
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect();
    decode(&data).unwrap()
}
fn normalized(v: OwnedTerm) -> String {
    match &v {
        OwnedTerm::BigInt(n) if let Ok(i) = i64::try_from(n) => format!("Int({i})"),
        OwnedTerm::Float(f) => format!("FloatBits({:016x})", f.to_bits()),
        other => format!("{other:?}"),
    }
}
#[test]
fn differential_200_000() {
    if Command::new("escript").arg("-v").output().is_err() {
        eprintln!("skipping differential_200_000: escript missing");
        return;
    }
    let dir = std::env::temp_dir().join(format!(
        "arinsal-arith-diff-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&dir).unwrap();
    let input = dir.join("cases.tsv");
    let output = dir.join("expected.tsv");
    let mut writer = std::io::BufWriter::new(std::fs::File::create(&input).unwrap());
    for i in 0..200_000 {
        let (op, a, b) = case(i);
        writeln!(
            writer,
            "{op}\t{}\t{}",
            literal(&a),
            b.as_ref().map(literal).unwrap_or_default()
        )
        .unwrap();
    }
    writer.flush().unwrap();
    let status = Command::new("escript")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/reference.escript"
        ))
        .arg(&input)
        .arg(&output)
        .status()
        .unwrap();
    assert!(status.success());
    let reader = BufReader::new(std::fs::File::open(output).unwrap());
    let mut count = 0;
    for (i, line) in reader.lines().enumerate() {
        let line = line.unwrap();
        let (kind, expected) = line.split_once('\t').unwrap();
        let (op, a, b) = case(i);
        let mut heap = VecHeap::new();
        let at = from_owned(&a, &mut heap).unwrap();
        let bt = b.as_ref().map(|v| from_owned(v, &mut heap).unwrap());
        let actual = local(op, at, bt, &mut heap);
        match (kind, actual) {
            ("O", Ok(term)) => {
                let actual = normalized(to_owned(term).unwrap());
                let expected = normalized(decode_hex(expected));
                assert_eq!(actual, expected, "case {i}: {op} {a:?} {b:?}");
            }
            ("E", Err(e)) => {
                let reason = match e {
                    arith::ArithError::Badarith => "badarith",
                    arith::ArithError::Badarg => "badarg",
                    arith::ArithError::SystemLimit => "system_limit",
                    arith::ArithError::HeapFull { .. } => "heap_full",
                };
                assert_eq!(reason, expected, "case {i}: {op} {a:?} {b:?}");
            }
            other => panic!("case {i}: {op} {a:?} {b:?}: {other:?}, expected {kind} {expected}"),
        }
        count += 1;
    }
    assert_eq!(count, 200_000);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn all_base_round_trips() {
    let mut heap = VecHeap::new();
    for base in 2..=36 {
        let base = Term::small(base).unwrap();
        for value in [
            BigInt::from(0),
            BigInt::from(-1),
            BigInt::from(1u64) << 1000,
            -(BigInt::from(1u64) << 1000usize),
        ] {
            let n = TermBuilder::new(&mut heap).int_from_bigint(&value).unwrap();
            let list = arith::integer_to_list(n, base, &mut heap).unwrap();
            let parsed = arith::list_to_integer(list, base, &mut heap).unwrap();
            let result = to_owned(parsed).unwrap();
            assert_eq!(
                normalized(result),
                normalized(OwnedTerm::BigInt(value.clone()))
            );
        }
    }
}
