use arinsal_bifs::Ctx;
use arinsal_bifs::ProcessHeapHandle;
use arinsal_etf::OwnedTerm;
use arinsal_nif::{LoadInfo, load_nif};
use arinsal_term::{ProcessHeap, Term, TermBuilder, VecHeap, global_atoms, to_owned};
use std::path::PathBuf;
use std::process::Command;

#[test]
fn otp_crypto_callbacks_match_erl() {
    let Ok(path) = Command::new("erl")
        .args([
            "-noshell",
            "-eval",
            "io:format(\"~s\",[code:lib_dir(crypto)]),halt().",
        ])
        .output()
    else {
        eprintln!("skipping: erl missing");
        return;
    };
    assert!(path.status.success());
    let path = PathBuf::from(String::from_utf8(path.stdout).unwrap()).join("priv/lib/crypto.so");
    if !path.exists() {
        eprintln!("skipping: OTP crypto.so missing");
        return;
    }
    let path_text = path.to_string_lossy();
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let expected_path = root.join("tmp/crypto_expected.etf");
    std::fs::create_dir_all(expected_path.parent().unwrap()).unwrap();
    let eval = "Results=[crypto:hash(sha256,<<\"abc\">>),crypto:mac(hmac,sha256,<<\"key\">>,<<\"abc\">>),byte_size(crypto:strong_rand_bytes(32)),crypto:crypto_one_time(aes_128_ctr,<<0:128>>,<<0:128>>,<<\"abc\">>,true)],ok=file:write_file(os:getenv(\"OUT\"),term_to_binary(Results)),halt().";
    let result = Command::new("erl")
        .args(["-noshell", "-eval", eval])
        .env("OUT", &expected_path)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let expected = arinsal_etf::decode(&std::fs::read(expected_path).unwrap()).unwrap();
    let mut heap = VecHeap::new();
    let mut builder = TermBuilder::new(&mut heap);
    let path_bin = builder.binary(path_text.as_bytes()).unwrap();
    let false_atom = Term::atom(global_atoms().get("false").unwrap());
    let info = builder
        .tuple(&[Term::small(302).unwrap(), path_bin, false_atom])
        .unwrap();
    let nif = load_nif(
        &path,
        LoadInfo {
            module: "crypto",
            term: info,
        },
    )
    .unwrap();
    let sha = Term::atom(global_atoms().intern("sha256").unwrap());
    let hmac = Term::atom(global_atoms().intern("hmac").unwrap());
    let aes = Term::atom(global_atoms().intern("aes_128_ctr").unwrap());
    let yes = Term::atom(global_atoms().get("true").unwrap());
    let mut builder = TermBuilder::new(&mut heap);
    let abc = builder.binary(b"abc").unwrap();
    let key = builder.binary(&[0; 16]).unwrap();
    let iv = builder.binary(&[0; 16]).unwrap();
    let hmac_key = builder.binary(b"key").unwrap();
    let mut actual = Vec::new();
    let mut output_heap = ProcessHeap::with_words(4096);
    for (name, args) in [
        ("hash_nif", vec![sha, abc]),
        ("mac_nif", vec![hmac, sha, hmac_key, abc]),
        ("strong_rand_bytes_nif", vec![Term::small(32).unwrap()]),
        ("ng_crypto_one_time_nif", vec![aes, key, iv, abc, yes]),
    ] {
        let mut ctx = Ctx::with_allocator(ProcessHeapHandle(&mut output_heap));
        let t = nif
            .lookup(name, args.len())
            .unwrap()
            .call(&mut ctx, &args)
            .unwrap();
        let value = to_owned(t).unwrap();
        actual.push(if name == "strong_rand_bytes_nif" {
            match &value {
                OwnedTerm::Binary(bytes) => OwnedTerm::Int(bytes.len() as i64),
                other => panic!("random result: {other:?}"),
            }
        } else {
            value
        });
    }
    assert_eq!(
        OwnedTerm::List {
            elems: actual,
            tail: Box::new(OwnedTerm::Nil)
        },
        expected
    );
}
