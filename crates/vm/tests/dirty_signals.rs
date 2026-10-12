//! Signals to processes executing long dirty C NIFs are handled by the dirty signal
//! handler processes while the NIF runs, against erl 29.1.1.

use std::path::{Path, PathBuf};
use std::process::Command;

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_term::{Term, global_atoms};
use arinsal_vm::Vm;

const NIF_SOURCE: &str = r#"
#include <unistd.h>
#include "erl_nif.h"

static ERL_NIF_TERM sleep_type(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    int ms;
    (void)argc;
    if (!enif_get_int(env, argv[0], &ms))
        return enif_make_badarg(env);
    usleep(ms * 1000);
    return enif_make_tuple2(env, enif_make_int(env, enif_thread_type()), argv[0]);
}
static ERL_NIF_TERM alive_wait(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    int ms, waited = 0;
    ErlNifPid to;
    (void)argc;
    if (!enif_get_int(env, argv[0], &ms) || !enif_get_local_pid(env, argv[1], &to))
        return enif_make_badarg(env);
    while (waited < ms && enif_is_current_process_alive(env)) {
        usleep(10000);
        waited += 10;
    }
    if (!enif_is_current_process_alive(env)) {
        ErlNifEnv *msg_env = enif_alloc_env();
        enif_send(NULL, &to, msg_env, enif_make_atom(msg_env, "noticed_exit"));
        enif_free_env(msg_env);
    }
    return enif_make_int(env, waited);
}
static ErlNifFunc funcs[] = {
    {"cpu_alive_wait", 2, alive_wait, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"io_alive_wait", 2, alive_wait, ERL_NIF_DIRTY_JOB_IO_BOUND},
    {"cpu_sleep", 1, sleep_type, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"io_sleep", 1, sleep_type, ERL_NIF_DIRTY_JOB_IO_BOUND},
};
ERL_NIF_INIT(dirty_signals, funcs, NULL, NULL, NULL, NULL)
"#;

const ERL_SOURCE: &str = r#"
-module(dirty_signals).
-export([run/1, run/2, cpu_sleep/1, io_sleep/1, cpu_alive_wait/2, io_alive_wait/2]).
-nifs([cpu_sleep/1, io_sleep/1, cpu_alive_wait/2, io_alive_wait/2]).

sleep_ms() -> 1500.

run(Path, Case) ->
    case erlang:load_nif(Path, []) of
        ok -> ok;
        {error, {reload, _}} -> ok
    end,
    process_flag(trap_exit, true),
    Cpu = fun cpu_sleep/1,
    Io = fun io_sleep/1,
    case Case of
        exit_kill -> {exit_kill(Cpu), exit_kill(Io)};
        info -> {info(Cpu), info(Io)};
        group_leader -> {group_leader_change(Cpu), group_leader_change(Io)};
        link_monitor -> {link_monitor(Cpu), link_monitor(Io)};
        exit_trapped -> {exit_trapped(Cpu), exit_trapped(Io)};
        high_priority -> high_priority(Cpu);
        alive_check -> {alive_check(fun cpu_alive_wait/2), alive_check(fun io_alive_wait/2)};
        queued_status -> queued_status(fun cpu_sleep/1)
    end.

start(Sleep) -> start(Sleep, fun() -> ok end).

start(Sleep, Setup) ->
    Me = self(),
    P = spawn(fun() ->
                      Setup(),
                      Me ! {started, self()},
                      R = Sleep(sleep_ms()),
                      Me ! {slept, self(), R},
                      receive stop -> ok end
              end),
    receive {started, P} -> ok end,
    wait_dirty(P),
    P.

wait_dirty(P) ->
    case erts_internal:is_process_executing_dirty(P) of
        true -> ok;
        false -> receive after 1 -> wait_dirty(P) end
    end.

now_ms() -> erlang:monotonic_time(millisecond).

%% A reply that had to wait for the dirty NIF to return would take ~sleep_ms().
fast(T0) -> now_ms() - T0 < sleep_ms() div 2.

slept(P) ->
    R = receive {slept, P, X} -> X after 5000 -> timeout end,
    P ! stop,
    R.

exit_kill(Sleep) ->
    P = start(Sleep),
    M = monitor(process, P),
    T0 = now_ms(),
    exit(P, kill),
    Down = receive {'DOWN', M, process, P, R} -> R after 5000 -> timeout end,
    {Down, fast(T0), is_process_alive(P)}.

info(Sleep) ->
    P = start(Sleep),
    T0 = now_ms(),
    %% `status` is not compared here: a process executing the NIF answers `running`
    %% (ERTS_PSFLG_DIRTY_RUNNING) on OTP and Arinsal alike, see `queued_status/1`.
    Info = process_info(P, [trap_exit, priority, message_queue_len, links]),
    Fast = fast(T0),
    {Info, Fast, slept(P)}.

%% Every dirty CPU scheduler sleeps in a NIF, so the next NIF call waits in the dirty queue:
%% that process is queued for a dirty scheduler and not executing, which erts reports as
%% `runnable` (ERTS_PSFLG_DIRTY_ACTIVE_SYS, erl_process.c:9305).
queued_status(Sleep) ->
    Me = self(),
    Busy = [spawn(fun() -> Me ! {busy_started, self()}, Sleep(sleep_ms()), Me ! {busy_done, self()} end)
            || _ <- lists:seq(1, erlang:system_info(dirty_cpu_schedulers))],
    [receive {busy_started, B} -> ok end || B <- Busy],
    [wait_dirty(B) || B <- Busy],
    Q = spawn(fun() -> Sleep(sleep_ms()), Me ! {queued_done, self()} end),
    Status = sample_runnable(Q, now_ms() + sleep_ms() div 2),
    receive {queued_done, Q} -> ok after 5000 -> timeout end,
    [receive {busy_done, B} -> ok after 5000 -> timeout end || B <- Busy],
    Status.

sample_runnable(Q, Deadline) ->
    {status, Status} = process_info(Q, status),
    case Status of
        runnable -> runnable;
        _ ->
            case now_ms() < Deadline of
                true -> receive after 1 -> sample_runnable(Q, Deadline) end;
                false -> {last, Status}
            end
    end.

group_leader_change(Sleep) ->
    New = spawn(fun() -> receive stop -> ok end end),
    P = start(Sleep),
    T0 = now_ms(),
    Set = group_leader(New, P),
    {group_leader, G} = process_info(P, group_leader),
    Fast = fast(T0),
    R = slept(P),
    New ! stop,
    {Set, G =:= New, Fast, R}.

link_monitor(Sleep) ->
    P = start(Sleep),
    T0 = now_ms(),
    Linked = link(P),
    M = monitor(process, P),
    {links, Links} = process_info(P, links),
    Fast = fast(T0),
    exit(P, boom),
    Exit = receive {'EXIT', P, R1} -> R1 after 5000 -> timeout end,
    Down = receive {'DOWN', M, process, P, R2} -> R2 after 5000 -> timeout end,
    {Linked, Links =:= [self()], Fast, Exit, Down, fast(T0)}.

exit_trapped(Sleep) ->
    P = start(Sleep, fun() -> process_flag(trap_exit, true) end),
    T0 = now_ms(),
    exit(P, hello),
    {message_queue_len, Len} = process_info(P, message_queue_len),
    Fast = fast(T0),
    M = monitor(process, P),
    R = slept(P),
    Down = receive {'DOWN', M, process, P, Why} -> Why after 5000 -> timeout end,
    {Len, Fast, R, Down}.

high_priority(Sleep) ->
    P = start(Sleep, fun() -> process_flag(priority, high) end),
    T0 = now_ms(),
    Info = process_info(P, priority),
    Fast = fast(T0),
    {Info, Fast, slept(P)}.

%% enif_is_current_process_alive/1 turns false in a dirty NIF once its process is killed.
alive_check(Wait) ->
    Me = self(),
    P = spawn(fun() -> Me ! {started, self()}, Wait(3000, Me) end),
    receive {started, P} -> ok end,
    wait_dirty(P),
    T0 = now_ms(),
    exit(P, kill),
    receive noticed_exit -> fast(T0) after 5000 -> timeout end.

cpu_alive_wait(_, _) -> erlang:nif_error(undef).
io_alive_wait(_, _) -> erlang:nif_error(undef).
cpu_sleep(_) -> erlang:nif_error(undef).
io_sleep(_) -> erlang:nif_error(undef).
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

#[test]
fn signals_to_long_dirty_nifs_are_handled_while_they_run() {
    let module = "dirty_signals";
    let Ok(erl) = RefErl::start() else {
        eprintln!("erl unavailable; skipping dirty signal differential test");
        return;
    };
    let dir = std::env::temp_dir().join(format!("arinsal-dirtysig-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let object = compile_so(&dir, module, NIF_SOURCE);
    let source = format!(
        "{ERL_SOURCE}\nrun(Case) -> run(\"{}\", Case).\n",
        object.display()
    );
    let bytes = erl.compile_named(module, &source, &[]).unwrap();
    std::fs::write(dir.join(format!("{module}.beam")), &bytes).unwrap();
    erl.load(module, &bytes).unwrap();
    // One call per case keeps each erl call within the reference node's call timeout.
    for case in [
        "exit_kill",
        "info",
        "group_leader",
        "link_monitor",
        "exit_trapped",
        "high_priority",
        "alive_check",
        "queued_status",
    ] {
        let expected = match erl.call(module, "run", &[OwnedTerm::Atom(case.into())]) {
            CallResult::Ok(term) => term,
            other => panic!("{module}:run({case}) on erl: {other:?}"),
        };
        let mut vm = Vm::new([dir.clone()]);
        let arg = Term::atom(global_atoms().intern(case).unwrap());
        let actual = match vm.eval_scheduled(module, "run", &[arg], 4, None) {
            Ok(result) => result.term,
            Err(error) => panic!("{module}:run({case}) failed on Arinsal: {error}"),
        };
        assert_eq!(actual, expected, "{module}:run({case})");
        if case == "queued_status" {
            // The sampled process must have been seen queued, not after its NIF ran.
            assert_eq!(
                actual,
                OwnedTerm::Atom("runnable".into()),
                "queued status on OTP and Arinsal"
            );
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}
