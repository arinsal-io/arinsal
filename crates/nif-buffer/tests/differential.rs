use arinsal_bifs::{BifError, Ctx, ProcessHeapHandle};
use arinsal_difftest::RefErl;
use arinsal_etf::OwnedTerm as O;
use arinsal_term::{ProcessHeap, from_owned, to_owned};

fn atom(value: &str) -> O {
    O::atom(value)
}

#[test]
fn registry_matches_the_otp_nif_entries() {
    for (name, arity) in [
        ("new", 0),
        ("size", 1),
        ("peek_head", 1),
        ("copying_read", 2),
        ("write", 2),
        ("skip", 2),
        ("find_byte_index", 2),
        ("try_lock", 1),
        ("unlock", 1),
    ] {
        assert!(arinsal_nif_buffer::lookup("prim_buffer", name, arity).is_some());
    }
    assert!(arinsal_nif_buffer::lookup("other", "new", 0).is_none());
    assert!(arinsal_nif_buffer::lookup("prim_buffer", "read", 2).is_none());
}

fn nif(name: &str, args: &[O]) -> Result<O, BifError> {
    let mut heap = ProcessHeap::with_words(4096);
    let mut alloc = ProcessHeapHandle(&mut heap);
    let terms = args
        .iter()
        .map(|arg| from_owned(arg, &mut alloc).unwrap())
        .collect::<Vec<_>>();
    let mut ctx = Ctx::new(&mut alloc);
    let f = arinsal_nif_buffer::lookup("prim_buffer", name, args.len() as u8).unwrap();
    f(&mut ctx, &terms).map(|term| to_owned(term).unwrap())
}

fn local_call(name: &str, args: &[O]) -> Result<O, BifError> {
    nif(name, args)
}

fn local_read_iovec(buffer: &O, size: i64) -> Result<O, BifError> {
    if size <= 64 {
        return nif("copying_read", &[buffer.clone(), O::Int(size)])
            .map(|binary| O::list(vec![binary]));
    }
    let head = nif("peek_head", std::slice::from_ref(buffer))?;
    let O::Binary(bytes) = &head else {
        unreachable!()
    };
    let head_size = bytes.len() as i64;
    if head_size - size > 512 && size <= 512 {
        return nif("copying_read", &[buffer.clone(), O::Int(size)])
            .map(|binary| O::list(vec![binary]));
    }
    if head_size > size {
        nif("skip", &[buffer.clone(), O::Int(size)])?;
        return Ok(O::list(vec![O::Binary(bytes[..size as usize].to_vec())]));
    }
    if head_size == size {
        nif("skip", &[buffer.clone(), O::Int(size)])?;
        return Ok(O::list(vec![O::Binary(bytes.clone())]));
    }
    nif("skip", &[buffer.clone(), O::Int(head_size)])?;
    let rest = local_read_iovec(buffer, size - head_size)?;
    let O::List { elems, tail } = &rest else {
        unreachable!()
    };
    let mut result = vec![O::Binary(bytes.clone())];
    result.extend(elems.iter().cloned());
    if **tail != O::Nil {
        return Ok(O::List {
            elems: result,
            tail: tail.clone(),
        });
    }
    Ok(O::list(result))
}

fn local_read(buffer: &O, size: i64) -> Result<O, BifError> {
    if size <= 64 {
        nif("copying_read", &[buffer.clone(), O::Int(size)])
    } else {
        let value = local_read_iovec(buffer, size)?;
        let O::List { elems, .. } = &value else {
            unreachable!()
        };
        let mut bytes = Vec::new();
        for elem in elems {
            let O::Binary(part) = elem else {
                unreachable!()
            };
            bytes.extend_from_slice(part);
        }
        Ok(O::Binary(bytes))
    }
}

fn normalized(result: Result<O, BifError>) -> O {
    match result {
        Ok(value) => value,
        Err(BifError::Badarg { .. }) => {
            O::Tuple(vec![atom("exception"), atom("error"), atom("badarg")])
        }
        Err(BifError::Error(term)) => O::Tuple(vec![
            atom("exception"),
            atom("error"),
            to_owned(term).unwrap(),
        ]),
        other => panic!("unexpected local outcome: {other:?}"),
    }
}

#[derive(Clone)]
enum Action {
    Nif(&'static str, Vec<O>),
    Read(&'static str, i64),
}

fn action_call(action: &Action, local_buffer: &O) -> Result<O, BifError> {
    match action {
        Action::Nif("size", _) => local_call("size", std::slice::from_ref(local_buffer)),
        Action::Nif("write", args) => local_call("write", &[local_buffer.clone(), args[1].clone()]),
        Action::Nif("skip", args) => local_call("skip", &[local_buffer.clone(), args[1].clone()]),
        Action::Nif("find_byte_index", args) => {
            local_call("find_byte_index", &[local_buffer.clone(), args[1].clone()])
        }
        Action::Nif("try_lock", _) => local_call("try_lock", std::slice::from_ref(local_buffer)),
        Action::Nif("unlock", _) => local_call("unlock", std::slice::from_ref(local_buffer)),
        Action::Read("read", size) => local_read(local_buffer, *size),
        Action::Read("read_iovec", size) => local_read_iovec(local_buffer, *size),
        _ => unreachable!(),
    }
}

fn reference_action(action: &Action) -> O {
    match action {
        Action::Nif(name, args) => O::Tuple(vec![
            atom("nif"),
            atom(name),
            O::list(args.iter().skip(1).cloned().collect()),
        ]),
        Action::Read(name, size) => O::Tuple(vec![atom("read"), atom(name), O::Int(*size)]),
    }
}

fn next(seed: &mut u64) -> u64 {
    *seed = seed
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    *seed
}

#[test]
fn random_sequences_match_otp() {
    let reference = RefErl::shared().expect("OTP 29.1.1 reference");
    let local_buffer = local_call("new", &[]).unwrap();
    let mut seed = 0x6a09_e667_f3bc_c909;
    let mut actions = Vec::with_capacity(3_000);
    for index in 0..3_000 {
        let choice = next(&mut seed) % 10;
        let action = match choice {
            0 | 1 => {
                let count = (next(&mut seed) % 3) as usize;
                let chunks = (0..count)
                    .map(|_| {
                        let len = (next(&mut seed) % 100) as usize;
                        O::Binary((0..len).map(|_| next(&mut seed) as u8).collect())
                    })
                    .collect();
                Action::Nif("write", vec![O::Nil, O::list(chunks)])
            }
            2 => Action::Nif("size", vec![]),
            3 => {
                let size = if index % 9 == 0 {
                    -1
                } else {
                    (next(&mut seed) % 180) as i64
                };
                Action::Read("read", size)
            }
            4 => {
                let size = if index % 11 == 0 {
                    -1
                } else {
                    (next(&mut seed) % 180) as i64
                };
                Action::Read("read_iovec", size)
            }
            5 => Action::Nif(
                "skip",
                vec![
                    O::Nil,
                    O::Int(if index % 7 == 0 {
                        -1
                    } else {
                        (next(&mut seed) % 180) as i64
                    }),
                ],
            ),
            6 => Action::Nif(
                "find_byte_index",
                vec![
                    O::Nil,
                    O::Int(if index % 8 == 0 {
                        256
                    } else {
                        (next(&mut seed) % 256) as i64
                    }),
                ],
            ),
            7 => Action::Nif("try_lock", vec![]),
            8 => Action::Nif("unlock", vec![]),
            _ => Action::Nif("size", vec![]),
        };
        actions.push(action);
    }

    let mut local_results = Vec::with_capacity(actions.len());
    for action in &actions {
        local_results.push(normalized(action_call(action, &local_buffer)));
    }

    // Keep the generated workload in compiled Erlang code; one 3,000-form
    // eval spends the reference worker's timeout scanning and parsing text.
    let source = r#"
-module(nif_buffer_sequence_probe).
-export([run/1]).
run(Actions) -> run(Actions, prim_buffer:new(), []).
run([], _Buffer, Results) -> lists:reverse(Results);
run([Action | Rest], Buffer, Results) ->
    Result = try run_action(Action, Buffer)
             catch Class:Reason -> {exception, Class, Reason}
             end,
    run(Rest, Buffer, [Result | Results]).
run_action({nif, Name, Args}, Buffer) ->
    apply(prim_buffer, Name, [Buffer | Args]);
run_action({read, Name, Size}, Buffer) ->
    apply(prim_buffer, Name, [Buffer, Size]).
"#;
    let beam = reference
        .compile_named("nif_buffer_sequence_probe", source, &[])
        .expect("compile reference sequence probe");
    reference
        .load("nif_buffer_sequence_probe", &beam)
        .expect("load reference sequence probe");
    let reference_actions = O::list(actions.iter().map(reference_action).collect());
    let remote_results =
        match reference.call("nif_buffer_sequence_probe", "run", &[reference_actions]) {
            arinsal_difftest::CallResult::Ok(value) => value,
            other => panic!("reference sequence call: {other:?}"),
        };
    similar_asserts::assert_eq!(remote_results, O::list(local_results));
}
