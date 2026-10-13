use arinsal_bifs::{BifError, Ctx, ProcessHeapHandle};
use arinsal_nif::{LoadInfo, load_nif, take_test_messages};
use arinsal_term::{ProcessHeap, Term, to_owned};
use std::path::PathBuf;
use std::process::Command;

#[test]
fn c_api_groups_match_otp() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let Ok(erl) = Command::new("erl")
        .args([
            "-noshell",
            "-eval",
            "io:format(\"~s/usr/include\",[code:root_dir()]), halt().",
        ])
        .output()
    else {
        eprintln!("skipping: erl missing");
        return;
    };
    assert!(erl.status.success());
    let include = String::from_utf8(erl.stdout).unwrap();
    let tmp = root.join("tmp/nif_differential");
    std::fs::create_dir_all(&tmp).unwrap();
    let source = root.join("crates/nif/tests/c");
    let library = tmp.join("test_nif.so");
    let status = Command::new("cc")
        .args(["-O2", "-fPIC"])
        .args(if cfg!(target_os = "macos") {
            &["-bundle", "-undefined", "dynamic_lookup"][..]
        } else {
            &["-shared"][..]
        })
        .arg(format!("-I{include}"))
        .arg(source.join("test_nif.c"))
        .arg("-o")
        .arg(&library)
        .status()
        .unwrap();
    assert!(status.success());
    assert!(
        Command::new("erlc")
            .arg("-o")
            .arg(&tmp)
            .arg(source.join("test_nif.erl"))
            .status()
            .unwrap()
            .success()
    );
    let expected_path = tmp.join("expected.etf");
    let eval = "Results=[test_nif:basic(42),test_nif:atom_string_probe(),test_nif:compare_probe(),test_nif:system_info_probe(),test_nif:schedule_probe(),test_nif:map_probe(),test_nif:iolist_probe(),test_nif:env_probe(),test_nif:binary_probe(),test_nif:resource_probe(),test_nif:resource_binary_probe(),test_nif:dynamic_probe(),test_nif:format_probe(),test_nif:etf_probe(),test_nif:time_probe(),test_nif:hash_probe(),test_nif:ioq_probe(),test_nif:iovec_probe(),test_nif:thread_probe(),test_nif:send_probe(),try test_nif:exception_probe() catch error:Reason -> Reason end], ok=file:write_file(os:getenv(\"OUT\"),term_to_binary(Results)),halt().";
    let reference = Command::new("erl")
        .arg("-noshell")
        .arg("-pa")
        .arg(&tmp)
        .arg("-eval")
        .arg(eval)
        .env("TEST_NIF_PATH", library.with_extension(""))
        .env("OUT", &expected_path)
        .output()
        .unwrap();
    assert!(
        reference.status.success(),
        "{}",
        String::from_utf8_lossy(&reference.stderr)
    );
    let expected = arinsal_etf::decode(&std::fs::read(expected_path).unwrap()).unwrap();
    let nif = load_nif(
        &library,
        LoadInfo {
            module: "test_nif",
            term: Term::small(0).unwrap(),
        },
    )
    .unwrap();
    let mut heap = ProcessHeap::with_words(65_536);
    let mut actual = Vec::new();
    for (name, args) in [
        ("basic", vec![Term::small(42).unwrap()]),
        ("atom_string_probe", vec![]),
        ("compare_probe", vec![]),
        ("system_info_probe", vec![]),
        ("schedule_probe", vec![]),
        ("map_probe", vec![]),
        ("iolist_probe", vec![]),
        ("env_probe", vec![]),
        ("binary_probe", vec![]),
        ("resource_probe", vec![]),
        ("resource_binary_probe", vec![]),
        ("dynamic_probe", vec![]),
        ("format_probe", vec![]),
        ("etf_probe", vec![]),
        ("time_probe", vec![]),
        ("hash_probe", vec![]),
        ("ioq_probe", vec![]),
        ("iovec_probe", vec![]),
        ("thread_probe", vec![]),
        ("send_probe", vec![]),
        ("exception_probe", vec![]),
    ] {
        let mut ctx = Ctx::with_allocator(ProcessHeapHandle(&mut heap));
        let callback = nif.lookup(name, args.len()).unwrap();
        let result = if name == "send_probe" {
            callback.call_with_pid(&mut ctx, &args, Term::pid(1, 0))
        } else {
            callback.call(&mut ctx, &args)
        };
        let term = match result {
            Ok(value) => value,
            Err(BifError::Error(reason)) => reason,
            Err(other) => panic!("{name}: {other:?}"),
        };
        actual.push(to_owned(term).unwrap());
    }
    let actual = arinsal_etf::OwnedTerm::List {
        elems: actual,
        tail: Box::new(arinsal_etf::OwnedTerm::Nil),
    };
    assert_eq!(actual, expected);
    let sent = take_test_messages();
    assert_eq!(sent.len(), 1);
    assert_eq!(
        to_owned(sent[0].message).unwrap(),
        arinsal_etf::OwnedTerm::Atom("delivered".into())
    );
    drop(heap);
    let mut check_heap = ProcessHeap::with_words(1024);
    let mut ctx = Ctx::with_allocator(ProcessHeapHandle(&mut check_heap));
    let destroyed = nif
        .lookup("dtor_count", 0)
        .unwrap()
        .call(&mut ctx, &[])
        .unwrap();
    assert!(destroyed.as_small().unwrap() >= 2);
}
