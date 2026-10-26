use arinsal_bifs::{Ctx, ProcessHeapHandle};
use arinsal_nif::{LoadInfo, load_nif};
use arinsal_term::{ProcessHeap, Term, TermBuilder, VecHeap};
use std::path::PathBuf;
use std::process::Command;

#[test]
fn benchmark_nif_callbacks() {
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
    let output = root.join("tmp/nb_test.so");
    std::fs::create_dir_all(output.parent().unwrap()).unwrap();
    let status = Command::new("cc")
        .args(["-O2", "-fPIC"])
        .args(if cfg!(target_os = "macos") {
            &["-bundle", "-undefined", "dynamic_lookup"][..]
        } else {
            &["-shared"][..]
        })
        .arg(format!("-I{include}"))
        .arg(root.join("tools/bench/nif/nb.c"))
        .arg("-o")
        .arg(&output)
        .status()
        .unwrap();
    assert!(status.success());
    let lib = load_nif(
        &output,
        LoadInfo {
            module: "nb",
            term: Term::NIL,
        },
    )
    .unwrap();
    let mut heap = VecHeap::new();
    let binary = TermBuilder::new(&mut heap).binary(&[1, 2, 3]).unwrap();
    let list = TermBuilder::new(&mut heap)
        .list_from_iter([1, 2, 3].map(|n| Term::small(n).unwrap()))
        .unwrap();
    let mut output_heap = ProcessHeap::with_words(4096);
    for (name, args, expected) in [
        ("noop", vec![Term::small(7).unwrap()], 7),
        ("dnoop", vec![Term::small(7).unwrap()], 7),
        (
            "add",
            vec![Term::small(2).unwrap(), Term::small(3).unwrap()],
            5,
        ),
        ("bsum", vec![binary], 6),
        ("lsum", vec![list], 6),
    ] {
        let mut state = arinsal_bifs::BifState::default();
        let mut ctx = Ctx::with_allocator(ProcessHeapHandle(&mut output_heap), &mut state);
        assert_eq!(
            lib.lookup(name, args.len())
                .unwrap()
                .call(&mut ctx, &args)
                .unwrap()
                .as_small(),
            Some(expected),
            "{name}"
        );
    }
}
