//! Run with `cargo test -p arinsal-etf --test live -- --ignored`.
use arinsal_etf::{EncodeOptions, OwnedTerm, decode, encode};
use proptest::prelude::*;
use proptest::test_runner::{Config, TestCaseError, TestRunner};
use std::cell::{Cell, RefCell};
use std::io::{Read, Write};
use std::process::{Command, Stdio};

fn terms() -> impl Strategy<Value = OwnedTerm> {
    let leaves = prop_oneof![
        any::<i64>().prop_map(OwnedTerm::Int),
        any::<u64>().prop_filter_map("finite", |n| {
            let f = f64::from_bits(n);
            f.is_finite().then_some(OwnedTerm::Float(f))
        }),
        "[a-z]{0,12}".prop_map(OwnedTerm::Atom),
        prop::collection::vec(any::<u8>(), 0..80).prop_map(OwnedTerm::Binary),
        Just(OwnedTerm::Nil),
    ];
    leaves.prop_recursive(5, 128, 8, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 1..8).prop_map(OwnedTerm::list),
            prop::collection::vec(inner.clone(), 0..8).prop_map(OwnedTerm::tuple),
            prop::collection::vec(inner, 0..8).prop_map(|values| OwnedTerm::Map(
                values
                    .into_iter()
                    .enumerate()
                    .map(|(i, v)| (OwnedTerm::Int(i as i64), v))
                    .collect()
            )),
        ]
    })
}

#[test]
#[ignore = "10,000 live Erlang port cases; run with --ignored"]
fn live_port_proptest() {
    if Command::new("erl").arg("-version").output().is_err() {
        eprintln!("skipping live OTP test: erl is not installed");
        return;
    }
    let server = r#"P=open_port({fd,0,1},[binary,{packet,4},eof]), F=fun R()->receive {P,{data,<<Mode,B/binary>>}}->Opts=case Mode of 0->[];1->[{minor_version,0}];2->[{minor_version,1}];3->[compressed];4->[{compressed,9}];5->[deterministic] end, Reply=try term_to_binary(binary_to_term(B),Opts) catch C:E->term_to_binary({server_error,C,E}) end,port_command(P,Reply),R();{P,closed}->ok;{P,eof}->ok end end,F(),halt()."#;
    let mut child = Command::new("erl")
        .args(["-noshell", "-noinput", "-eval", server])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdin = RefCell::new(child.stdin.take().unwrap());
    let stdout = RefCell::new(child.stdout.take().unwrap());
    let mut runner = TestRunner::new(Config {
        cases: 10_000,
        max_shrink_iters: 0,
        ..Config::default()
    });
    let strategy = terms();
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
    let count = Cell::new(0_usize);
    runner
        .run(&strategy, |term| {
            let mode = count.get() % options.len();
            count.set(count.get() + 1);
            let input = encode(&term, EncodeOptions::default());
            let len = (input.len() + 1) as u32;
            stdin.borrow_mut().write_all(&len.to_be_bytes()).unwrap();
            stdin.borrow_mut().write_all(&[mode as u8]).unwrap();
            stdin.borrow_mut().write_all(&input).unwrap();
            stdin.borrow_mut().flush().unwrap();
            let mut header = [0; 4];
            stdout.borrow_mut().read_exact(&mut header).unwrap();
            let reply_len = u32::from_be_bytes(header) as usize;
            assert!(reply_len < 1_000_000);
            let mut reply = vec![0; reply_len];
            stdout.borrow_mut().read_exact(&mut reply).unwrap();
            let ours = encode(&decode(&input).unwrap(), options[mode]);
            if ours != reply {
                let offset = ours
                    .iter()
                    .zip(&reply)
                    .position(|(a, b)| a != b)
                    .unwrap_or(ours.len().min(reply.len()));
                return Err(TestCaseError::fail(format!(
                    "case {}, mode {mode}, first difference {offset}, term {term:?}, reply {:?}",
                    count.get(),
                    decode(&reply)
                )));
            }
            Ok(())
        })
        .unwrap();
    assert_eq!(count.get(), 10_000);
    drop(stdin);
    drop(stdout);
    let _ = child.kill();
    let _ = child.wait();
}
