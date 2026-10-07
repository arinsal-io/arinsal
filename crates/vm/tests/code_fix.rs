//! Code-loading loose ends, compared with OTP 29.1.1.

use arinsal_difftest::{CallResult, CompareMode, RefErl, compare};
use arinsal_etf::OwnedTerm;
use arinsal_term::Term;
use arinsal_vm::Vm;

const CANDIDATES: &[&str] = &[
    "lists",
    "maps",
    "proplists",
    "string",
    "unicode",
    "array",
    "queue",
    "dict",
    "sets",
    "orddict",
    "ordsets",
    "gb_sets",
    "gb_trees",
    "digraph",
    "sofs",
    "calendar",
    "math",
    "filename",
    "io_lib",
    "re",
    "binary",
    "timer",
    "gen",
    "gen_server",
    "proc_lib",
    "filelib",
    "beam_lib",
    "base64",
    "rand",
    "uri_string",
    "ets",
    "supervisor",
];

const PROBE: &str = r#"
-module(code_fix_probe).
-export([full/1, exports/1, parts/1, bad_info/0, code_ops/3, async_check/0, errors/0, onload/1, reclaim/2]).
full(M) -> M:module_info().
exports(M) -> M:module_info(exports).
parts(M) ->
    {M:module_info(functions),
     M:module_info(attributes),
     M:module_info(compile),
     M:module_info(md5),
     M:module_info(nifs)}.
bad_info() ->
    {try erlang:get_module_info(code_fix_no_such) catch error:R1 -> R1 end,
     try erlang:get_module_info(lists, nope) catch error:R2 -> R2 end,
     try erlang:get_module_info(1) catch error:R3 -> R3 end}.
code_ops(Mod, File, Bin) ->
    Loaded = code:load_binary(Mod, File, Bin),
    Is = code:is_loaded(Mod),
    Which = code:which(Mod),
    Found = lists:keyfind(Mod, 1, code:all_loaded()),
    Purged = code:purge(Mod),
    Soft = code:soft_purge(Mod),
    Deleted = code:delete(Mod),
    Is2 = code:is_loaded(Mod),
    Missing = code:which(code_fix_no_such_module_zz),
    Again = code:delete(Mod),
    {Loaded, Is, Which, Found, Deleted, Is2, Purged, Soft, Missing, Again}.
async_check() ->
    R = erlang:check_process_code(self(), code_fix_probe, [{allow_gc, false}, {async, myid}]),
    M = receive {check_process_code, myid, Res} -> Res after 1000 -> timeout end,
    R2 = erlang:check_process_code(self(), code_fix_probe, [{async, a}, {allow_gc, true}, {async, b}]),
    M2 = receive {check_process_code, b, Res2} -> Res2 after 1000 -> timeout end,
    Sync = erlang:check_process_code(self(), code_fix_probe, [{allow_gc, true}]),
    {R, M, R2, M2, Sync}.
errors() ->
    {try code:delete(1) catch error:R1 -> R1 end,
     try code:is_loaded(1) catch error:R2 -> R2 end,
     try code:which(1) catch error:R3 -> R3 end,
     try code:purge(1) catch error:R4 -> R4 end,
     try code:soft_purge(1) catch error:R5 -> R5 end,
     try code:load_binary(1, "f", <<>>) catch error:R6 -> R6 end,
     code:load_binary(code_fix_probe, [bad], <<>>),
     try erlang:check_process_code(self(), lists, [bad]) catch error:R7 -> R7 end,
     try erlang:check_process_code(self(), lists, [{allow_gc, nope}]) catch error:R8 -> R8 end,
     try erlang:check_process_code(1, lists, []) catch error:R9 -> R9 end,
     try erts_internal:check_dirty_process_code(self(), lists) catch error:R10 -> R10 end,
     try erts_internal:check_dirty_process_code(1, x) catch error:R11 -> R11 end}.
onload(Bin) ->
    %% init/0 calls self/0 and put/1. Both sides must still return {module,_}:
    %% the callback ran far enough to return ok.
    {code:load_binary(code_fix_onload, "mem", Bin), code:is_loaded(code_fix_onload)}.
reclaim(0, _) -> ok;
reclaim(N, Bin) when N > 0 ->
    {module, code_fix_reclaim} = code:load_binary(code_fix_reclaim, "mem", Bin),
    true = code:delete(code_fix_reclaim),
    false = code:purge(code_fix_reclaim),
    reclaim(N - 1, Bin).
"#;

fn atom_term(name: &str) -> Term {
    Term::atom(
        arinsal_term::global_atoms()
            .intern(name)
            .expect("short atom"),
    )
}

fn object_code(reference: &RefErl, module: &str) -> Vec<u8> {
    let result = reference.call("code", "get_object_code", &[OwnedTerm::atom(module)]);
    let CallResult::Ok(term) = &result else {
        panic!("{module}: get_object_code {result:?}");
    };
    let OwnedTerm::Tuple(parts) = term else {
        panic!("{module}: get_object_code {term:?}");
    };
    parts
        .iter()
        .find_map(|part| match part {
            OwnedTerm::Binary(bytes) => Some(bytes.clone()),
            _ => None,
        })
        .unwrap_or_else(|| panic!("{module}: object code has no binary"))
}

fn load_order(reference: &RefErl) -> Vec<String> {
    let result = reference.call("erlang", "loaded", &[]);
    let CallResult::Ok(term) = &result else {
        panic!("erlang:loaded/0 {result:?}");
    };
    let OwnedTerm::List { elems, .. } = term else {
        panic!("erlang:loaded/0 {term:?}");
    };
    let mut names = elems
        .iter()
        .map(|term| match term {
            OwnedTerm::Atom(name) => name.clone(),
            other => panic!("loaded entry {other:?}"),
        })
        .collect::<Vec<_>>();
    names.reverse();
    names
}

fn run(vm: &mut Vm, function: &str, owned_args: &[OwnedTerm], terms: &[Term]) -> OwnedTerm {
    vm.eval_scheduled("code_fix_probe", function, terms, 1, None)
        .unwrap_or_else(|error| panic!("{function} {owned_args:?}: {error}"))
        .term
}

fn diff(reference: &RefErl, vm: &mut Vm, function: &str, args: &[OwnedTerm], terms: &[Term]) {
    let expected = reference.call("code_fix_probe", function, args);
    let actual = CallResult::Ok(run(vm, function, args, terms));
    compare(&actual, &expected, CompareMode::Exact)
        .unwrap_or_else(|error| panic!("{function}: {error}"));
}

#[test]
fn lists_module_info_matches_erts_export_order() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping module_info differential test");
        return;
    };
    for module in CANDIDATES {
        reference.call("code", "ensure_loaded", &[OwnedTerm::atom(*module)]);
    }
    let order = load_order(&reference);
    let mut beams = std::collections::HashMap::new();
    let mut vm = Vm::new([]);
    for name in &order {
        let bytes = object_code(&reference, name);
        vm.note_beam_exports(&bytes)
            .unwrap_or_else(|error| panic!("note {name}: {error}"));
        beams.insert(name.clone(), bytes);
    }
    let mut loaded = Vec::new();
    for module in CANDIDATES {
        let Some(bytes) = beams.get(*module) else {
            continue;
        };
        if vm.load_bytes(bytes).is_ok() {
            loaded.push(*module);
        }
        if loaded.len() == 20 && loaded.contains(&"lists") {
            break;
        }
    }
    assert!(
        loaded.contains(&"lists"),
        "lists.beam did not load: {loaded:?}"
    );
    assert!(
        loaded.len() >= 20,
        "only {} modules loaded: {loaded:?}",
        loaded.len()
    );
    let probe = reference
        .compile_named("code_fix_probe", PROBE, &[])
        .unwrap();
    reference.load("code_fix_probe", &probe).unwrap();
    vm.load_bytes(&probe).unwrap();

    diff(
        &reference,
        &mut vm,
        "full",
        &[OwnedTerm::atom("lists")],
        &[atom_term("lists")],
    );
    for module in &loaded {
        diff(
            &reference,
            &mut vm,
            "exports",
            &[OwnedTerm::atom(*module)],
            &[atom_term(module)],
        );
        diff(
            &reference,
            &mut vm,
            "parts",
            &[OwnedTerm::atom(*module)],
            &[atom_term(module)],
        );
    }
    diff(&reference, &mut vm, "bad_info", &[], &[]);
}

#[test]
fn code_server_ops_async_check_and_onload_match_erts() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping code server differential test");
        return;
    };
    let probe = reference
        .compile_named("code_fix_probe", PROBE, &[])
        .unwrap();
    let reclaim = reference
        .compile_named(
            "code_fix_reclaim",
            "-module(code_fix_reclaim). -export([value/0]). value() -> ok.",
            &[],
        )
        .unwrap();
    let onload = reference
        .compile_named(
            "code_fix_onload",
            "-module(code_fix_onload). -on_load(init/0). -export([value/0]). init() -> put(onload_self, self()), ok. value() -> get(onload_self).",
            &[],
        )
        .unwrap();
    reference.load("code_fix_probe", &probe).unwrap();
    let mem = {
        let chars = "mem"
            .chars()
            .map(|ch| OwnedTerm::Int(i64::from(ch as u32)))
            .collect();
        OwnedTerm::List {
            elems: chars,
            tail: Box::new(OwnedTerm::Nil),
        }
    };
    let call_ok =
        |function: &str, args: &[OwnedTerm]| match reference.call("code_fix_probe", function, args)
        {
            CallResult::Ok(term) => term,
            other => panic!("{function}: {other:?}"),
        };
    let expected = OwnedTerm::Tuple(vec![
        call_ok(
            "code_ops",
            &[
                OwnedTerm::atom("code_fix_reclaim"),
                mem,
                OwnedTerm::Binary(reclaim.clone()),
            ],
        ),
        call_ok("async_check", &[]),
        call_ok("errors", &[]),
        call_ok("onload", &[OwnedTerm::Binary(onload.clone())]),
    ]);

    let temp = std::env::temp_dir().join(format!("arinsal_code_fix_{}", std::process::id()));
    std::fs::create_dir_all(&temp).unwrap();
    let output = temp.join("actual.etf");
    std::fs::write(temp.join("code_fix_probe.beam"), &probe).unwrap();
    std::fs::write(temp.join("code_fix_reclaim.beam"), &reclaim).unwrap();
    std::fs::write(temp.join("code_fix_onload.beam"), &onload).unwrap();
    let eval = format!(
        "{{ok,R}}=file:read_file(\"{}\"), {{ok,O}}=file:read_file(\"{}\"), Result={{code_fix_probe:code_ops(code_fix_reclaim,\"mem\",R),code_fix_probe:async_check(),code_fix_probe:errors(),code_fix_probe:onload(O)}}, ok=file:write_file(\"{}\",term_to_binary(Result)), halt().",
        temp.join("code_fix_reclaim.beam").display(),
        temp.join("code_fix_onload.beam").display(),
        output.display(),
    );
    let bin = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/arinsal");
    assert!(bin.is_file(), "build arinsal-cli before this test");
    let mut child = std::process::Command::new(&bin)
        .args(["-noshell", "-pa"])
        .arg(&temp)
        .args(["-eval", &eval])
        .spawn()
        .expect("arinsal code_server probe");
    let started = std::time::Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().expect("wait for arinsal") {
            break status;
        }
        if started.elapsed() > std::time::Duration::from_secs(40) {
            let _ = child.kill();
            panic!("arinsal code_server probe timed out");
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    };
    assert!(status.success(), "arinsal code_server probe: {status}");
    let actual = arinsal_etf::decode(&std::fs::read(&output).unwrap()).unwrap();
    assert_eq!(actual, expected);
    std::fs::remove_dir_all(temp).unwrap();
}

#[test]
fn purged_module_versions_stay_bounded() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping reclaim test");
        return;
    };
    let probe = reference
        .compile_named("code_fix_probe", PROBE, &[])
        .unwrap();
    let reclaim = reference
        .compile_named(
            "code_fix_reclaim",
            "-module(code_fix_reclaim). -export([value/0]). value() -> ok.",
            &[],
        )
        .unwrap();
    reference.load("code_fix_probe", &probe).unwrap();
    let expected = reference.call(
        "code_fix_probe",
        "reclaim",
        &[OwnedTerm::Int(1000), OwnedTerm::Binary(reclaim.clone())],
    );
    assert_eq!(expected, CallResult::Ok(OwnedTerm::atom("ok")));
    let mut vm = Vm::new([]);
    vm.load_bytes(&reclaim).unwrap();
    for _ in 0..1000 {
        vm.load_next_version(&reclaim).unwrap();
    }
    let stored = vm.module_storage_count();
    let len = vm.module_table_len();
    assert!(
        stored <= 3 && len <= 4,
        "module storage grew: live {stored}, table {len}"
    );
}
