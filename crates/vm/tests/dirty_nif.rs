//! Dirty NIFs and dirty `enif_schedule_nif` continuations against erl 29.1.1.

use std::path::{Path, PathBuf};
use std::process::Command;

use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;

const NIF_SOURCE: &str = r#"
#include <unistd.h>
#include "erl_nif.h"

static ERL_NIF_TERM type_of(ErlNifEnv* env) {
    return enif_make_int(env, enif_thread_type());
}
static ERL_NIF_TERM thread_type(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    (void)argc; (void)argv;
    return type_of(env);
}
static ERL_NIF_TERM sleep_type(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    int ms;
    (void)argc;
    if (!enif_get_int(env, argv[0], &ms))
        return enif_make_badarg(env);
    usleep(ms * 1000);
    return type_of(env);
}
static ERL_NIF_TERM step_normal(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    (void)argc;
    return enif_make_list_cell(env, type_of(env), argv[0]);
}
static ERL_NIF_TERM step_io(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    ERL_NIF_TERM acc = enif_make_list_cell(env, type_of(env), argv[0]);
    (void)argc;
    return enif_schedule_nif(env, "step_normal", 0, step_normal, 1, &acc);
}
static ERL_NIF_TERM step_cpu(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    ERL_NIF_TERM acc = enif_make_list_cell(env, type_of(env), argv[0]);
    (void)argc;
    return enif_schedule_nif(env, "step_io", ERL_NIF_DIRTY_JOB_IO_BOUND, step_io, 1, &acc);
}
static ERL_NIF_TERM chain(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    ERL_NIF_TERM acc = enif_make_list_cell(env, type_of(env), argv[0]);
    (void)argc;
    return enif_schedule_nif(env, "step_cpu", ERL_NIF_DIRTY_JOB_CPU_BOUND, step_cpu, 1, &acc);
}
static ERL_NIF_TERM both_flags(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    (void)argc;
    return enif_schedule_nif(env, "thread_type", 3, thread_type, 0, argv);
}
static ERL_NIF_TERM bad_flags(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    (void)argc;
    return enif_schedule_nif(env, "thread_type", 4, thread_type, 0, argv);
}
static ERL_NIF_TERM dirty_raise(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    (void)argc;
    return enif_raise_exception(env, argv[0]);
}
static ERL_NIF_TERM to_dirty_raise(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    (void)argc;
    return enif_schedule_nif(env, "dirty_raise", ERL_NIF_DIRTY_JOB_CPU_BOUND, dirty_raise, 1, argv);
}
static ErlNifFunc funcs[] = {
    {"thread_type", 0, thread_type, 0},
    {"cpu_type", 0, thread_type, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"io_type", 0, thread_type, ERL_NIF_DIRTY_JOB_IO_BOUND},
    {"cpu_sleep", 1, sleep_type, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"io_sleep", 1, sleep_type, ERL_NIF_DIRTY_JOB_IO_BOUND},
    {"chain", 1, chain, 0},
    {"io_chain", 1, step_io, ERL_NIF_DIRTY_JOB_IO_BOUND},
    {"both_flags", 0, both_flags, 0},
    {"bad_flags", 0, bad_flags, 0},
    {"to_dirty_raise", 1, to_dirty_raise, 0},
};
ERL_NIF_INIT(dirty_nif, funcs, NULL, NULL, NULL, NULL)
"#;

const REDS_NIF_SOURCE: &str = r#"
#include <unistd.h>
#include "erl_nif.h"
static ERL_NIF_TERM sleep_ms(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    int ms;
    (void)argc;
    if (!enif_get_int(env, argv[0], &ms))
        return enif_make_badarg(env);
    usleep(ms * 1000);
    return enif_make_atom(env, "ok");
}
static ErlNifFunc funcs[] = {
    {"cpu_sleep", 1, sleep_ms, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"io_sleep", 1, sleep_ms, ERL_NIF_DIRTY_JOB_IO_BOUND},
};
ERL_NIF_INIT(dirty_nif_reds, funcs, NULL, NULL, NULL, NULL)
"#;

const REDS_ERL_SOURCE: &str = r#"
-module(dirty_nif_reds).
-export([run/0, run/1, cpu_sleep/1, io_sleep/1]).
-nifs([cpu_sleep/1, io_sleep/1]).

run(Path) ->
    ok = erlang:load_nif(Path, []),
    Cpu = [delta(fun() -> cpu_sleep(20) end) || _ <- lists:seq(1, 3)],
    Io = [delta(fun() -> io_sleep(20) end) || _ <- lists:seq(1, 3)],
    {lists:all(fun(D) -> D >= 80000 andalso D =< 280000 end, Cpu),
     lists:all(fun(D) -> D =< 100 end, Io)}.

delta(Fun) ->
    {reductions, R0} = process_info(self(), reductions),
    _ = Fun(),
    {reductions, R1} = process_info(self(), reductions),
    R1 - R0.

cpu_sleep(_) -> erlang:nif_error(undef).
io_sleep(_) -> erlang:nif_error(undef).
"#;

const BAD_SOURCE: &str = r#"
#include "erl_nif.h"
static ERL_NIF_TERM f(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    (void)argc; (void)argv;
    return enif_make_int(env, 0);
}
static ErlNifFunc funcs[] = {{"f", 0, f, 3}};
ERL_NIF_INIT(dirty_nif_bad, funcs, NULL, NULL, NULL, NULL)
"#;

const ERL_SOURCE: &str = r#"
-module(dirty_nif).
-export([run/0, run/1, thread_type/0, cpu_type/0, io_type/0, cpu_sleep/1, io_sleep/1, chain/1,
         io_chain/1, both_flags/0, bad_flags/0, to_dirty_raise/1]).
-nifs([thread_type/0, cpu_type/0, io_type/0, cpu_sleep/1, io_sleep/1, chain/1, io_chain/1,
       both_flags/0, bad_flags/0, to_dirty_raise/1]).

err(F) ->
    try F() of
        Value -> {ok, Value}
    catch
        Class:Reason -> {Class, Reason}
    end.

run(Path) ->
    ok = erlang:load_nif(Path, []),
    Me = self(),
    Sleeper = spawn(fun() -> Me ! {slept, self(), cpu_sleep(300)} end),
    receive after 100 -> ok end,
    Dirty = erts_internal:is_process_executing_dirty(Sleeper),
    Slept = receive {slept, Sleeper, T} -> T after 5000 -> timeout end,
    {thread_type(), cpu_type(), io_type(), thread_type(),
     chain([]), io_chain([]), both_flags(), err(fun bad_flags/0),
     err(fun() -> to_dirty_raise(boom) end),
     [io_sleep(1) || _ <- lists:seq(1, 3)],
     Dirty, Slept, erts_internal:is_process_executing_dirty(self())}.

thread_type() -> erlang:nif_error(undef).
cpu_type() -> erlang:nif_error(undef).
io_type() -> erlang:nif_error(undef).
cpu_sleep(_) -> erlang:nif_error(undef).
io_sleep(_) -> erlang:nif_error(undef).
chain(_) -> erlang:nif_error(undef).
io_chain(_) -> erlang:nif_error(undef).
both_flags() -> erlang:nif_error(undef).
bad_flags() -> erlang:nif_error(undef).
to_dirty_raise(_) -> erlang:nif_error(undef).
"#;

const BAD_ERL_SOURCE: &str = r#"
-module(dirty_nif_bad).
-export([run/0, run/1, f/0]).
-nifs([f/0]).
run(Path) -> erlang:load_nif(Path, []).
f() -> erlang:nif_error(undef).
"#;

const TRACE_NIF_SOURCE: &str = r#"
#include <unistd.h>
#include "erl_nif.h"
static ERL_NIF_TERM send_wait(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    ErlNifPid pid;
    ERL_NIF_TERM result;
    (void)argc;
    if (!enif_get_local_pid(env, argv[0], &pid)) return enif_make_badarg(env);
    result = enif_make_tuple2(env, enif_make_atom(env, "ok"), enif_make_pid(env, &pid));
    if (!enif_send(env, &pid, NULL, result)) return enif_make_badarg(env);
    sleep(2);
    return result;
}
static ErlNifFunc funcs[] = {{"send_wait", 1, send_wait, ERL_NIF_DIRTY_JOB_IO_BOUND}};
ERL_NIF_INIT(dirty_nif_trace, funcs, NULL, NULL, NULL, NULL)
"#;

const TRACE_ERL_SOURCE: &str = r#"
-module(dirty_nif_trace).
-export([run/0, trace_run/1, send_wait/1]).
-nifs([send_wait/1]).
send_wait(_) -> erlang:nif_error(undef).

trace_run(Path) ->
    ok = erlang:load_nif(Path, []),
    Parent = self(),
    Rcvr = spawn(fun() -> receive {ok, Self} -> Parent ! {Self, received} end end),
    Sndr = spawn(fun() ->
        receive {Parent, go} -> ok end,
        {ok, Rcvr} = send_wait(Rcvr),
        Parent ! {self(), sent}
    end),
    1 = erlang:trace(Sndr, true, [send, running]),
    Sndr ! {Parent, go},
    trace_sequence(Sndr, undefined).

trace_sequence(Pid, LastIn) ->
    receive
        {trace, Pid, in, MFA} -> trace_sequence(Pid, MFA);
        {trace, Pid, out, _MFA} -> trace_sequence(Pid, LastIn);
        {trace, Pid, send, _Message, _To} ->
            {trace, Pid, out, {erts_internal, dirty_nif_finalizer, 1}} = recv_trace(Pid),
            {trace, Pid, in, {erts_internal, dirty_nif_finalizer, 1}} = recv_trace(Pid),
            {dirty_nif_trace, send_wait, 1} = LastIn,
            {LastIn, send, out, in}
    end.

recv_trace(Pid) ->
    receive
        M when element(1, M) =:= trace, element(2, M) =:= Pid -> M
    end.
"#;

fn otp_include() -> PathBuf {
    let output = Command::new("erl")
        .args([
            "-noshell",
            "-eval",
            "io:format(\"~s\",[code:root_dir()]),halt().",
        ])
        .output()
        .expect("erl on PATH");
    PathBuf::from(String::from_utf8(output.stdout).unwrap()).join("usr/include")
}

fn compile_so(dir: &Path, name: &str, source: &str) -> PathBuf {
    let source_path = dir.join(format!("{name}.c"));
    let object = dir.join(name);
    std::fs::write(&source_path, source).unwrap();
    let status = Command::new("cc")
        .args(["-shared", "-fPIC", "-undefined", "dynamic_lookup", "-I"])
        .arg(otp_include())
        .arg(&source_path)
        .arg("-o")
        .arg(object.with_extension("so"))
        .status()
        .expect("cc");
    assert!(status.success(), "compile {name}.so");
    object
}

fn check_entry(module: &str, c_source: &str, erl_source: &str, entry: &str) {
    let Ok(erl) = RefErl::start() else {
        eprintln!("erl unavailable; skipping dirty NIF differential test");
        return;
    };
    let dir =
        std::env::temp_dir().join(format!("arinsal-dirtynif-{}-{module}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let object = compile_so(&dir, module, c_source);
    let source = format!(
        "{erl_source}\nrun() -> {entry}(\"{}\").\n",
        object.display()
    );
    let bytes = erl.compile_named(module, &source, &[]).unwrap();
    std::fs::write(dir.join(format!("{module}.beam")), &bytes).unwrap();
    erl.load(module, &bytes).unwrap();
    let expected = match erl.call(module, "run", &[]) {
        CallResult::Ok(term) => term,
        other => panic!("{module}:run/0 on erl: {other:?}"),
    };
    let mut vm = Vm::new([dir.clone()]);
    let actual = match vm.eval_scheduled(module, "run", &[], 4, None) {
        Ok(result) => result.term,
        Err(error) => panic!("{module}:run/0 failed on Arinsal: {error}"),
    };
    assert_eq!(actual, expected, "{module}:run/0");
    let _ = std::fs::remove_dir_all(&dir);
}

fn check(module: &str, c_source: &str, erl_source: &str) {
    check_entry(module, c_source, erl_source, "run");
}

#[test]
fn dirty_nifs_and_scheduled_continuations_match_erts() {
    check("dirty_nif", NIF_SOURCE, ERL_SOURCE);
}

#[test]
fn dirty_cpu_nif_is_charged_by_time_like_erts() {
    check("dirty_nif_reds", REDS_NIF_SOURCE, REDS_ERL_SOURCE);
}

#[test]
fn illegal_dirty_flags_fail_load_like_erts() {
    check("dirty_nif_bad", BAD_SOURCE, BAD_ERL_SOURCE);
}

#[test]
fn dirty_nif_send_trace_sequence_matches_erts() {
    check_entry(
        "dirty_nif_trace",
        TRACE_NIF_SOURCE,
        TRACE_ERL_SOURCE,
        "trace_run",
    );
}
