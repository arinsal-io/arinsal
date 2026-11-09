//! Fun and export terms survive code purge in each erts storage class.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use similar_asserts::assert_eq;
use std::path::Path;
use std::process::{Command, Output};

const TARGET_V1: &str = r#"
-module(purge_roots_target).
-export([make/0, f/1]).
make() -> fun() -> old_value end.
f(X) -> {old, X}.
"#;

const TARGET_V2: &str = r#"
-module(purge_roots_target).
-export([make/0, f/1]).
make() -> fun() -> new_value end.
f(X) -> {new, X}.
"#;

const DRIVER: &str = r#"
-module(purge_roots_driver).
-export([run/5]).

run(Kind, Root, Purge, V1Path, V2Path) ->
    {ok, V1} = file:read_file(V1Path),
    {module, purge_roots_target} = code:load_binary(purge_roots_target, V1Path, V1),
    Holder = make_holder(Kind, Root),
    Deleted = code:delete(purge_roots_target),
    Purged = case Purge of
        soft -> code:soft_purge(purge_roots_target);
        hard -> code:purge(purge_roots_target)
    end,
    Before = inspect(Kind, Root, Holder),
    Alive = alive(Root, Holder),
    {ok, V2} = file:read_file(V2Path),
    Reloaded = code:load_binary(purge_roots_target, V2Path, V2),
    After = inspect(Kind, Root, Holder),
    AliveAfter = alive(Root, Holder),
    cleanup(Root, Holder),
    {Deleted, Purged, Before, Alive, Reloaded, After, AliveAfter, alive_vm}.

make_holder(local, literal) ->
    {module, purge_roots_local_literal} = code:ensure_loaded(purge_roots_local_literal),
    literal;
make_holder(external, literal) ->
    {module, purge_roots_external_literal} = code:ensure_loaded(purge_roots_external_literal),
    literal;
make_holder(Kind, Root) ->
    Fun = case Kind of
        local -> purge_roots_target:make();
        external -> erlang:make_fun(purge_roots_target, f, 1)
    end,
    case Root of
        heap ->
            Parent = self(),
            Pid = spawn(fun() -> hold(Fun, Parent) end),
            receive {ready, Pid} -> {process, Pid} after 3000 -> exit(holder_start_timeout) end;
        mailbox ->
            Parent = self(),
            Pid = spawn(fun() -> receive go -> receive {held_fun, F} -> hold(F, Parent) end end end),
            Pid ! {held_fun, Fun},
            {process, Pid};
        ets ->
            Table = ets:new(purge_roots, [set]),
            true = ets:insert(Table, {fun_term, Fun}),
            {ets, Table};
        persistent ->
            persistent_term:put({purge_roots, self()}, Fun),
            persistent;
        _ -> literal
    end.

hold(Fun, Parent) ->
    Parent ! {ready, self()},
    hold_loop(Fun).
hold_loop(Fun) ->
    receive
        {inspect, From} -> From ! {inspected, self(), inspect_fun(Fun)}, hold_loop(Fun);
        stop -> ok
    end.

inspect(Kind, Root, Holder) ->
    case Root of
        heap -> inspect_process(Holder);
        mailbox ->
            {process, Pid} = Holder,
            Pid ! go,
            inspect_process(Holder);
        _ ->
            Fun = case Root of
                ets ->
                    {ets, Table} = Holder,
                    [{fun_term, Value}] = ets:lookup(Table, fun_term),
                    Value;
                persistent -> persistent_term:get({purge_roots, self()});
                literal when Kind =:= local -> purge_roots_local_literal:local_fun();
                literal -> purge_roots_external_literal:external_fun()
            end,
            inspect_fun(Fun)
    end.

inspect_process({process, Pid}) ->
    Pid ! {inspect, self()},
    receive {inspected, Pid, Result} -> Result after 3000 -> timeout end.

inspect_fun(Fun) ->
    Info = lists:keydelete(pid, 1, erlang:fun_info(Fun)),
    Call = try apply_fun(Fun)
           catch error:{badfun, _} -> {error, badfun}; Class:Reason -> {Class, Reason}
           end,
    {Info, Call}.
apply_fun(Fun) ->
    case erlang:fun_info(Fun, arity) of
        {arity, 0} -> Fun();
        {arity, 1} -> Fun(argument)
    end.

alive(Root, {process, Pid}) when Root =:= heap; Root =:= mailbox -> is_process_alive(Pid);
alive(_, _) -> not_applicable.
cleanup(Root, {process, Pid}) when Root =:= heap; Root =:= mailbox -> Pid ! stop, ok;
cleanup(ets, {ets, Table}) -> ets:delete(Table), ok;
cleanup(persistent, _) -> persistent_term:erase({purge_roots, self()}), ok;
cleanup(_, _) -> ok.
"#;

const BUILDER: &str = r#"
-module(purge_roots_builder).
-export([local_literal/2]).

local_literal(Holder, HolderBeam) ->
    File = filename:join(os:getenv("TMPDIR", "/tmp"), atom_to_list(Holder) ++ ".beam"),
    ok = file:write_file(File, HolderBeam),
    {ok, Holder, Chunks} = beam_lib:all_chunks(File),
    LocalFun = purge_roots_target:make(),
    ETF = term_to_binary(LocalFun, [{minor_version, 2}, deterministic]),
    LitT = <<0:32, 1:32, (byte_size(ETF)):32, ETF/binary>>,
    Patched = [{Id, case Id of "LitT" -> LitT; _ -> Data end} || {Id, Data} <- Chunks],
    {ok, Beam} = beam_lib:build_module(Patched),
    Beam.
"#;

#[test]
fn fun_roots_and_export_literals_match_erts_through_purge_and_reload() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping fun purge roots differential test");
        return;
    };
    let target_v1 = reference
        .compile_named("purge_roots_target", TARGET_V1, &[])
        .unwrap();
    let target_v2 = reference
        .compile_named("purge_roots_target", TARGET_V2, &[])
        .unwrap();
    let external_literal = reference
        .compile_named(
            "purge_roots_external_literal",
            "-module(purge_roots_external_literal). -export([external_fun/0]). external_fun() -> fun purge_roots_target:f/1.",
            &[],
        )
        .unwrap();
    let local_literal = reference
        .compile_named(
            "purge_roots_local_literal",
            "-module(purge_roots_local_literal). -export([local_fun/0]). local_fun() -> fun purge_roots_target:f/1.",
            &[],
        )
        .unwrap();
    let driver = reference
        .compile_named("purge_roots_driver", DRIVER, &[])
        .unwrap();
    let builder = reference
        .compile_named("purge_roots_builder", BUILDER, &[])
        .unwrap();
    reference.load("purge_roots_target", &target_v1).unwrap();
    reference.load("purge_roots_builder", &builder).unwrap();
    let literal_result = reference.call(
        "purge_roots_builder",
        "local_literal",
        &[
            OwnedTerm::atom("purge_roots_local_literal"),
            OwnedTerm::Binary(local_literal),
        ],
    );
    let local_literal = match &literal_result {
        CallResult::Ok(OwnedTerm::Binary(beam)) => beam.clone(),
        other => panic!("build local fun literal: {other:?}"),
    };

    let files = std::env::temp_dir().join(format!("purge_roots_{}", std::process::id()));
    std::fs::create_dir_all(&files).unwrap();
    let v1_path = files.join("purge_roots_target_v1.beam");
    let v2_path = files.join("purge_roots_target_v2.beam");
    std::fs::write(&v1_path, target_v1).unwrap();
    std::fs::write(&v2_path, target_v2).unwrap();
    std::fs::write(files.join("purge_roots_driver.beam"), driver).unwrap();
    std::fs::write(
        files.join("purge_roots_external_literal.beam"),
        external_literal,
    )
    .unwrap();
    std::fs::write(files.join("purge_roots_local_literal.beam"), local_literal).unwrap();

    let scenarios = [
        ("local", "heap"),
        ("local", "ets"),
        ("local", "mailbox"),
        ("local", "persistent"),
        ("local", "literal"),
        ("external", "heap"),
        ("external", "ets"),
        ("external", "mailbox"),
        ("external", "persistent"),
        ("external", "literal"),
    ];
    let arinsal = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/release/arinsal");
    assert!(arinsal.is_file(), "build target/release/arinsal first");

    for (kind, root) in scenarios {
        for purge in ["soft", "hard"] {
            let expression = format!(
                "io:format(\"~tp~n\", [purge_roots_driver:run({kind}, {root}, {purge}, \"{}\", \"{}\")]), halt().",
                erlang_string(&v1_path),
                erlang_string(&v2_path),
            );
            let expected = run_vm("erl", &files, &expression);
            let actual = run_vm(arinsal.to_str().unwrap(), &files, &expression);
            assert_eq!(expected.stdout, actual.stdout, "{kind}/{root}/{purge}");
        }
    }
}

fn run_vm(executable: &str, beam_dir: &Path, expression: &str) -> Output {
    let output = Command::new("timeout")
        .args(["60", executable, "-noshell", "-pa"])
        .arg(beam_dir)
        .args(["-eval", expression])
        .output()
        .unwrap_or_else(|error| panic!("start {executable}: {error}"));
    assert!(
        output.status.success(),
        "{executable} failed: status={} stdout={} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    output
}

fn erlang_string(path: &Path) -> String {
    path.to_str()
        .expect("temporary path is UTF-8")
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
}
