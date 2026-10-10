use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_vm::Vm;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const MODULE: &str = "procdict_differential";
const SOURCE: &str = r#"
-module(procdict_differential).
-export([atom_count/0, pad_to/1, run0/0, run1/0, run10/0, run5000/0, run_aligned/2, run_aligned_info/2, run_aligned_digest/2, run_aligned_preview/2, run_aligned_checkpoints/2, run_ints/0, run_nonatoms/0, bench/0]).

atom_count() -> erlang:system_info(atom_count).
pad_to(Target) -> pad_to(erlang:system_info(atom_count), Target, 1).
pad_to(Count, Target, _) when Count >= Target -> ok;
pad_to(_, Target, N) ->
    _ = list_to_atom("pd_padding_" ++ integer_to_list(N)),
    pad_to(erlang:system_info(atom_count), Target, N + 1).

key(N) -> case N rem 4 of
    0 -> N;
    1 -> list_to_atom("pd_key_" ++ integer_to_list(N));
    2 -> {list_to_atom("pd_key_" ++ integer_to_list(N)), N};
    3 -> <<N:32/unsigned>>
end.

run0() -> run(0).
run1() -> run(1).
run10() -> run(10).
run5000() -> run(5000).
run_aligned(Target, N) ->
    pad_to(Target),
    Target = atom_count(),
    run(N).
run_aligned_info(Target, N) -> element(4, element(4, run_aligned(Target, N))).
run_aligned_digest(Target, N) ->
    pad_to(Target),
    Target = atom_count(),
    Result = run(N),
    After = element(6, Result),
    {erlang:phash2(element(1, Result)), erlang:phash2(element(2, Result)),
     erlang:phash2(element(3, Result)), erlang:phash2(element(4, Result)),
     erlang:phash2(element(5, Result)),
     {erlang:phash2(element(1, After)), erlang:phash2(element(2, After)),
      erlang:phash2(element(3, After)), erlang:phash2(element(4, After))},
     erlang:phash2(element(7, Result)), erlang:phash2(element(8, Result)),
     erlang:phash2(element(9, Result))}.
run_aligned_preview(Target, N) ->
    After = element(6, run_aligned(Target, N)),
    {lists:sublist(element(1, After), 100), lists:sublist(element(2, After), 100)}.
run_aligned_checkpoints(Target, N) ->
    pad_to(Target),
    Target = atom_count(),
    Ks = [key(I) || I <- lists:seq(1, N)],
    [put(K, I) || {K, I} <- lists:zip(Ks, lists:seq(1, N))],
    [put(K, {updated, I}) || {K, I} <- lists:zip(Ks, lists:seq(1, N))],
    checkpoint_erases([K || {K, I} <- lists:zip(Ks, lists:seq(1, N)), I rem 2 =:= 0], 10, []).
checkpoint_erases(Keys, Chunk, Acc) ->
    case length(Keys) of
        0 -> lists:reverse(Acc);
        _ ->
            Count = min(Chunk, length(Keys)),
            {Now, Rest} = lists:split(Count, Keys),
            [erase(K) || K <- Now],
            checkpoint_erases(Rest, Chunk, [erlang:phash2(get()) | Acc])
    end.
run_ints() ->
    Ks = lists:seq(1, 10),
    [put(K, K) || K <- Ks],
    {get(), get_keys(), [get(K) || K <- Ks]}.

run_nonatoms() ->
    Ks = [case I rem 3 of 0 -> I; 1 -> {I, I}; 2 -> <<I:32/unsigned>> end || I <- lists:seq(1,10)],
    [put(K, I) || {K,I} <- lists:zip(Ks, lists:seq(1,10))],
    {get(), get_keys()}.

run(N) ->
    Ks = [key(I) || I <- lists:seq(1, N)],
    Put = [put(K, case I rem 2 of 0 -> even; _ -> odd end) || {K,I} <- lists:zip(Ks, lists:seq(1,N))],
    Old = [put(K, {updated, I}) || {K,I} <- lists:zip(Ks, lists:seq(1,N))],
    Gets = [get(K) || K <- Ks],
    Before = {get(), get_keys(), get_keys({updated, 2}), process_info(self(), dictionary)},
    Erased = [erase(K) || {K,I} <- lists:zip(Ks, lists:seq(1,N)), I rem 2 =:= 0],
    After = {get(), get_keys(), get_keys({updated, 1}), process_info(self(), dictionary)},
    All = erase(),
    {Put, Old, Gets, Before, Erased, After, All, get(), get_keys()}.

bench() ->
    N = 2000,
    Ks = [key(I) || I <- lists:seq(1,N)],
    TPut = timer:tc(fun() -> [put(K, I) || {K,I} <- lists:zip(Ks, lists:seq(1,N))] end),
    TGet = timer:tc(fun() -> [get(K) || K <- Ks] end),
    TErase = timer:tc(fun() -> [erase(K) || K <- Ks] end),
    {element(1, TPut) * 1000 div N, element(1, TGet) * 1000 div N,
     element(1, TErase) * 1000 div N}.
"#;

fn run(reference: &RefErl, vm: &mut Vm, function: &str) -> (CallResult, OwnedTerm) {
    let expected = reference.call(MODULE, function, &[]);
    let actual = vm
        .eval_scheduled(MODULE, function, &[], 1, None)
        .unwrap_or_else(|error| panic!("{function}: {error}"));
    (expected, actual.term)
}

#[test]
fn process_dictionary_non_atom_sequences_match_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping process dictionary differential test");
        return;
    };
    let beam = reference
        .compile_named(MODULE, SOURCE, &[])
        .expect("compile process dictionary fixture");
    drop(reference);
    let reference = RefErl::start().expect("start isolated reference node");
    reference
        .load(MODULE, &beam)
        .expect("load reference module");
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load VM module");
    for function in ["run_ints", "run_nonatoms"] {
        let (expected, actual) = run(&reference, &mut vm, function);
        assert_eq!(expected, CallResult::Ok(actual), "{function}");
    }
}

fn timed_output(program: &Path, args: &[&str]) -> String {
    let mut child = Command::new("timeout")
        .arg("120")
        .arg(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|error| panic!("spawn {}: {error}", program.display()));
    let mut stdout = child.stdout.take().expect("capture stdout");
    let stdout_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout.read_to_end(&mut bytes).expect("read stdout");
        bytes
    });
    let mut stderr = child.stderr.take().expect("capture stderr");
    let stderr_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        stderr.read_to_end(&mut bytes).expect("read stderr");
        bytes
    });
    let started = Instant::now();
    while child.try_wait().expect("wait for child").is_none() {
        assert!(
            started.elapsed() < Duration::from_secs(125),
            "{} timed out",
            program.display()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let status = child.wait().expect("wait for child");
    let stdout = stdout_reader.join().expect("join stdout reader");
    let stderr = stderr_reader.join().expect("join stderr reader");
    assert!(
        status.success(),
        "{} failed ({:?}): {}",
        program.display(),
        status,
        String::from_utf8_lossy(&stderr)
    );
    String::from_utf8_lossy(&stdout).trim().to_owned()
}

fn compile_fixture() -> PathBuf {
    let reference = RefErl::start().expect("start Erlang compiler node");
    let beam = reference
        .compile_named(MODULE, SOURCE, &[])
        .expect("compile process dictionary fixture");
    drop(reference);
    let dir = std::env::temp_dir().join(format!("arinsal-procdict-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create fixture directory");
    std::fs::write(dir.join(format!("{MODULE}.beam")), &beam).expect("write fixture beam");
    dir
}

fn one_shot_args(dir: &Path, eval: &str) -> Vec<String> {
    vec![
        "-noshell".into(),
        "-pa".into(),
        dir.display().to_string(),
        "-eval".into(),
        eval.into(),
    ]
}

fn atom_count(program: &Path, dir: &Path) -> usize {
    let args = one_shot_args(
        dir,
        &format!("io:format(\"~p~n\", [{MODULE}:atom_count()]), halt()."),
    );
    let args = args.iter().map(String::as_str).collect::<Vec<_>>();
    timed_output(program, &args)
        .parse()
        .unwrap_or_else(|error| panic!("invalid atom_count output: {error}"))
}

#[test]
fn process_dictionary_bucket_order_matches_one_shot_otp() {
    let dir = compile_fixture();
    let erl = Path::new("erl");
    let arinsal = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/arinsal");
    assert!(arinsal.is_file(), "build target/debug/arinsal first");
    let target_count = atom_count(erl, &dir).max(atom_count(&arinsal, &dir));
    for count in [0, 1, 10, 100, 1000, 5000] {
        let function = "run_aligned";
        let eval =
            format!("io:format(\"~w~n\", [{MODULE}:{function}({target_count}, {count})]), halt().");
        let args = one_shot_args(&dir, &eval);
        let args = args.iter().map(String::as_str).collect::<Vec<_>>();
        let expected = timed_output(erl, &args);
        let actual = timed_output(&arinsal, &args);
        let mismatch = actual
            .bytes()
            .zip(expected.bytes())
            .position(|(left, right)| left != right);
        assert!(
            actual == expected,
            "{count} process dictionary keys differ at byte {mismatch:?}; lengths {} vs {}; actual {:?}; expected {:?}",
            actual.len(),
            expected.len(),
            mismatch.map(|at| &actual[at.saturating_sub(1000)..(at + 1000).min(actual.len())]),
            mismatch.map(|at| &expected[at.saturating_sub(1000)..(at + 1000).min(expected.len())]),
        );
    }
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn process_dictionary_release_operation_timings() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping process dictionary timing comparison");
        return;
    };
    let beam = reference
        .compile_named(MODULE, SOURCE, &[])
        .expect("compile process dictionary benchmark");
    reference
        .load(MODULE, &beam)
        .expect("load reference benchmark");
    let started = Instant::now();
    let actual = {
        let mut vm = Vm::new([]);
        vm.load_bytes(&beam).expect("load VM benchmark");
        vm.eval_scheduled(MODULE, "bench", &[], 1, None)
            .expect("run VM benchmark")
            .term
    };
    let arinsal_elapsed = started.elapsed();
    let expected = reference.call(MODULE, "bench", &[]);
    eprintln!(
        "process dictionary benchmark (ns/op, 2,000 keys): erl={expected:?}; arinsal={actual:?}; vm_total={arinsal_elapsed:?}"
    );
}
