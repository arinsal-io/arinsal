use arinsal_float::{
    FloatFormatError, FloatFormatOpts, FloatNotation, float_to_list, format_shortest, list_to_float,
};
use std::fs::{File, create_dir_all};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tmp/float-otp29-200000.tsv.gz")
}

#[test]
fn otp_29_differential() {
    if Command::new("escript").arg("--version").output().is_err() {
        eprintln!("skipping OTP float differential fixture: escript is unavailable");
        return;
    }
    let path = fixture_path();
    create_dir_all(path.parent().unwrap()).unwrap();
    if !path.exists() {
        let raw = path.with_extension("");
        let status = Command::new("escript")
            .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/gen.escript"))
            .arg(&raw)
            .arg("200000")
            .status()
            .unwrap();
        assert!(status.success(), "fixture generation failed");
        let compressed = File::create(&path).unwrap();
        let status = Command::new("gzip")
            .arg("-c")
            .arg(&raw)
            .stdout(Stdio::from(compressed))
            .status()
            .unwrap();
        assert!(status.success(), "fixture compression failed");
        std::fs::remove_file(raw).unwrap();
    }
    let mut decompressor = Command::new("gzip")
        .arg("-dc")
        .arg(&path)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let reader = BufReader::new(decompressor.stdout.take().unwrap());
    let mut float_count = 0;
    let mut parse_count = 0;
    let mut mismatches = Vec::new();
    for line in reader.lines() {
        let line = line.unwrap();
        let fields: Vec<_> = line.split('\t').collect();
        match fields[0] {
            "F" => {
                float_count += 1;
                assert_eq!(fields.len(), 26);
                let bits = u64::from_str_radix(fields[1], 16).unwrap();
                let f = f64::from_bits(bits);
                let mut actual = vec![float_to_list(f, &FloatFormatOpts::default())];
                actual.push(float_to_list(
                    f,
                    &FloatFormatOpts {
                        notation: FloatNotation::Short,
                        compact: false,
                    },
                ));
                for d in [0, 1, 5, 10, 17, 20, 40] {
                    actual.push(float_to_list(
                        f,
                        &FloatFormatOpts {
                            notation: FloatNotation::Scientific(d),
                            compact: false,
                        },
                    ));
                }
                for d in [0, 1, 2, 4, 10, 20, 40] {
                    for compact in [false, true] {
                        actual.push(float_to_list(
                            f,
                            &FloatFormatOpts {
                                notation: FloatNotation::Decimals(d),
                                compact,
                            },
                        ));
                    }
                }
                actual.push(Ok(format_shortest(f)));
                for (index, (got, want)) in actual.iter().zip(&fields[2..]).enumerate() {
                    let result = got.as_deref().unwrap_or("!");
                    if result != *want && mismatches.len() < 20 {
                        mismatches.push(format!(
                            "bits={bits:016x} option={index} got={result} want={want}"
                        ));
                    }
                }
            }
            "P" => {
                parse_count += 1;
                assert_eq!(fields.len(), 3);
                let (pairs, remainder) = fields[1].as_bytes().as_chunks::<2>();
                assert!(remainder.is_empty());
                let input = pairs
                    .iter()
                    .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
                    .collect::<Vec<_>>();
                let got = list_to_float(&input);
                let want = fields[2];
                let matches = match got {
                    Ok(value) => {
                        want != "!" && value.to_bits() == u64::from_str_radix(want, 16).unwrap()
                    }
                    Err(_) => want == "!",
                };
                if !matches && mismatches.len() < 20 {
                    mismatches.push(format!(
                        "parse={:?} got={got:?} want={want}",
                        String::from_utf8_lossy(&input)
                    ));
                }
            }
            other => panic!("unexpected record {other}"),
        }
    }
    assert!(decompressor.wait().unwrap().success());
    assert!(float_count >= 200_000, "only {float_count} float cases");
    assert!(parse_count >= 100_000, "only {parse_count} parse cases");
    assert!(
        mismatches.is_empty(),
        "{} float cases, {} parse cases: {}",
        float_count,
        parse_count,
        mismatches.join("\n")
    );
    eprintln!("PASS: {float_count} float cases × 24 formats; {parse_count} parse cases");
}

#[test]
fn boundary_precision_differential() {
    let output = match Command::new("escript")
        .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/gen.escript"))
        .arg("--bounds")
        .output()
    {
        Ok(output) => output,
        Err(_) => {
            eprintln!("skipping precision boundary test: escript is unavailable");
            return;
        }
    };
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    let mut count = 0;
    for line in text.lines() {
        let fields: Vec<_> = line.split('\t').collect();
        assert_eq!(fields.len(), 5);
        let f = f64::from_bits(u64::from_str_radix(fields[1], 16).unwrap());
        let d: u16 = fields[3].parse().unwrap();
        let notation = match fields[2] {
            "s" => FloatNotation::Scientific(d),
            "d" | "c" => FloatNotation::Decimals(d),
            other => panic!("unknown format {other}"),
        };
        let opts = FloatFormatOpts {
            notation,
            compact: fields[2] == "c",
        };
        let got = float_to_list(f, &opts);
        assert_eq!(got.as_deref().unwrap_or("!"), fields[4], "{line}");
        count += 1;
    }
    assert_eq!(count, 6 * (252 + 256 * 2));
    eprintln!("PASS: {count} precision boundary formats");
}

#[test]
fn bounds_and_syntax() {
    let f = 1.0;
    assert_eq!(
        float_to_list(
            f,
            &FloatFormatOpts {
                notation: FloatNotation::Scientific(250),
                compact: false,
            }
        ),
        Err(FloatFormatError::BadArg)
    );
    assert_eq!(
        float_to_list(
            f,
            &FloatFormatOpts {
                notation: FloatNotation::Decimals(254),
                compact: false,
            }
        ),
        Err(FloatFormatError::BadArg)
    );
    assert_eq!(list_to_float(b"+1,0").unwrap().to_bits(), 1.0f64.to_bits());
    assert!(list_to_float(b"1e1").is_err());
}

#[test]
#[ignore = "Run with cargo test -p arinsal-float --test differential million_short_proptest -- --ignored --nocapture"]
fn million_short_proptest() {
    use proptest::prelude::*;
    let mut child = Command::new("escript")
        .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/gen.escript"))
        .arg("--port")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let io = std::cell::RefCell::new((
        BufWriter::new(child.stdin.take().unwrap()),
        BufReader::new(child.stdout.take().unwrap()),
        String::new(),
    ));
    let mut runner = proptest::test_runner::TestRunner::new(proptest::test_runner::Config {
        cases: 1_000_000,
        failure_persistence: None,
        ..Default::default()
    });
    runner
        .run(&any::<u64>(), |bits| {
            let mut io = io.borrow_mut();
            let (stdin, stdout, line) = &mut *io;
            writeln!(stdin, "{bits:x}").unwrap();
            stdin.flush().unwrap();
            line.clear();
            stdout.read_line(line).unwrap();
            let f = f64::from_bits(bits);
            let expected = line.trim_end();
            let got = if f.is_finite() {
                format_shortest(f)
            } else {
                "!".to_owned()
            };
            prop_assert_eq!(got, expected);
            Ok(())
        })
        .unwrap();
    drop(io);
    assert!(child.wait().unwrap().success());
    eprintln!("PASS: 1,000,000 live Erlang short format cases");
}

#[test]
#[ignore = "Run with cargo test -p arinsal-float --release --test differential short_timing -- --ignored --nocapture"]
fn short_timing() {
    use std::hint::black_box;
    use std::time::Instant;

    let mut bits = 0x1234_5678_9abc_def0_u64;
    let values: Vec<f64> = (0..1_000_000)
        .filter_map(|_| {
            bits = bits.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = bits;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            let f = f64::from_bits(z ^ (z >> 31));
            f.is_finite().then_some(f)
        })
        .collect();
    let start = Instant::now();
    for &f in &values {
        let mut buffer = ryu::Buffer::new();
        black_box(buffer.format_finite(black_box(f)));
    }
    let raw_ryu = start.elapsed();
    let start = Instant::now();
    for &f in &values {
        let mut buffer = ryu::Buffer::new();
        black_box(buffer.format_finite(black_box(f)).to_owned());
    }
    let plain = start.elapsed();
    let start = Instant::now();
    for &f in &values {
        black_box(format_shortest(black_box(f)));
    }
    let otp = start.elapsed();
    eprintln!(
        "{} values: raw ryu={:.3}s ryu+String={:.3}s OTP-short={:.3}s ratios={:.2}x raw/{:.2}x String",
        values.len(),
        raw_ryu.as_secs_f64(),
        plain.as_secs_f64(),
        otp.as_secs_f64(),
        otp.as_secs_f64() / raw_ryu.as_secs_f64(),
        otp.as_secs_f64() / plain.as_secs_f64()
    );
    assert!(otp.as_secs_f64() <= raw_ryu.as_secs_f64() * 2.0);
}
