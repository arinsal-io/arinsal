use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_term::{VecHeap, from_owned};
use arinsal_vm::Vm;

/// `raise/2` after an `after` body must keep the caught class. The body may
/// clobber the X registers that held the class (`gen_server:reply/2` does).
#[test]
fn try_after_reraise_keeps_class() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping try/after re-raise differential test");
        return;
    };
    let source = "-module(mix_loop1_reraise). -export([run/1]).
        run(Kind) ->
            erase(touched),
            Result = try body(Kind) catch C:R -> {C, R} end,
            {Result, get(touched)}.
        body(error) -> try error(reason) after touch() end;
        body(exit) -> try exit(reason) after touch() end;
        body(throw) -> try throw(reason) after touch() end.
        touch() -> put(touched, true).";
    let beam = reference
        .compile_named("mix_loop1_reraise", source, &[])
        .unwrap();
    reference.load("mix_loop1_reraise", &beam).unwrap();
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    for kind in ["error", "exit", "throw"] {
        let input = OwnedTerm::Atom(kind.into());
        let expected = reference.call("mix_loop1_reraise", "run", std::slice::from_ref(&input));
        let mut heap = VecHeap::new();
        let arg = from_owned(&input, &mut heap).unwrap();
        let actual = vm
            .eval_scheduled("mix_loop1_reraise", "run", &[arg], 1, Some(79))
            .unwrap();
        assert_eq!(expected, CallResult::Ok(actual.term), "{kind}");
    }
}

/// `ets:insert` of an Elixir-shaped cache tuple must keep binaries built by
/// append. Those are writable proc bins; the table has to retain their owner.
#[test]
fn ets_insert_keeps_appended_binary() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping ets writable-binary differential test");
        return;
    };
    let source = "-module(mix_loop1_ets_bin). -export([run/0]).
        run() ->
            Bin = grow(<<>>, 0),
            T = ets:new(mix_loop1_ets_bin, [set, public]),
            true = ets:insert(T, {{cache, key}, {call, Bin}}),
            More = grow(Bin, 0),
            [{_, {call, Got}}] = ets:lookup(T, {cache, key}),
            {Got, More}.
        grow(Acc, 32) -> Acc;
        grow(Acc, N) -> grow(<<Acc/binary, (N band 255)>>, N + 1).";
    let beam = reference
        .compile_named("mix_loop1_ets_bin", source, &[])
        .unwrap();
    reference.load("mix_loop1_ets_bin", &beam).unwrap();
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let expected = reference.call("mix_loop1_ets_bin", "run", &[]);
    let actual = vm
        .eval_scheduled("mix_loop1_ets_bin", "run", &[], 0, Some(79))
        .unwrap();
    assert_eq!(expected, CallResult::Ok(actual.term));
}

/// `os:env/0` is `{Name, Value}` pairs. `os:getenv/0` is `"Name=Value"` strings.
#[test]
fn os_env_pairs_match_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping os:env/0 differential test");
        return;
    };
    let source = "-module(mix_loop1_os_env). -export([run/0]).
        run() ->
            true = os:putenv(\"ARINSAL_MIX_ENV\", \"pair\"),
            true = os:putenv(\"ARINSAL_MIX_EMPTY\", \"\"),
            {lists:keyfind(\"ARINSAL_MIX_ENV\", 1, os:env()),
             lists:keyfind(\"ARINSAL_MIX_EMPTY\", 1, os:env())}.";
    let beam = reference
        .compile_named("mix_loop1_os_env", source, &[])
        .unwrap();
    reference.load("mix_loop1_os_env", &beam).unwrap();
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let expected = reference.call("mix_loop1_os_env", "run", &[]);
    let actual = vm
        .eval_scheduled("mix_loop1_os_env", "run", &[], 1, Some(79))
        .unwrap();
    assert_eq!(expected, CallResult::Ok(actual.term));
}

/// A module added with `code:add_pathz/1` after boot is visible to the code
/// server, and the first call must autoload it. `-pa` at startup is a different
/// path, already copied into the VM loader.
#[test]
fn code_path_autoload_matches_otp() {
    let dir = std::env::temp_dir().join(format!("mix_loop1_autoload_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let source = dir.join("mix_loop1_autoload.erl");
    std::fs::write(
        &source,
        "-module(mix_loop1_autoload). -export([run/0]). run() -> loaded.\n",
    )
    .unwrap();
    let otp_bin = "$HOME/.asdf/installs/erlang/29.1.1/bin";
    let compiled = std::process::Command::new(format!("{otp_bin}/erlc"))
        .arg("-o")
        .arg(&dir)
        .arg(&source)
        .status()
        .expect("erlc");
    assert!(compiled.success());
    let expr = format!(
        "code:add_pathz(\"{}\"), file:write_file(\"{}/out\", atom_to_list(mix_loop1_autoload:run())), halt().",
        dir.display(),
        dir.display()
    );
    let expected_out = dir.join("expected");
    let expected_expr = format!(
        "code:add_pathz(\"{}\"), file:write_file(\"{}\", atom_to_list(mix_loop1_autoload:run())), halt().",
        dir.display(),
        expected_out.display()
    );
    let erl = std::process::Command::new(format!("{otp_bin}/erl"))
        .args(["-noshell", "-eval", &expected_expr])
        .status()
        .expect("erl");
    assert!(erl.success(), "erl autoload");
    let bin = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/arinsal");
    assert!(bin.is_file(), "build arinsal-cli before this test");
    let mut child = std::process::Command::new(&bin)
        .args(["-noshell", "-eval", &expr])
        .spawn()
        .expect("arinsal");
    let started = std::time::Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().expect("wait") {
            break status;
        }
        if started.elapsed() > std::time::Duration::from_secs(40) {
            let _ = child.kill();
            panic!("arinsal autoload timed out");
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    };
    assert!(status.success(), "arinsal autoload");
    let actual = std::fs::read(dir.join("out")).expect("arinsal output");
    let expected = std::fs::read(&expected_out).expect("erl output");
    assert_eq!(actual, expected);
    let _ = std::fs::remove_dir_all(&dir);
}
