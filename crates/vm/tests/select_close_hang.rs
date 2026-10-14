//! Closing a descriptor that was in the shared poll set must not race the poll thread.
//!
//! The one-shot users of the poll set (spawn and fd ports, the socket NIF reactor, the
//! `driver_select` and `enif_select` tables) hand a descriptor to the closing thread
//! after a readiness callback. The poll thread used to run the callback first and take
//! the descriptor out of the kernel poll set afterwards, so a `kevent` of the poll thread
//! could overlap the `close(2)` of the same descriptor. Such a close never returned on
//! macOS and left an unkillable `?E` process behind. erts brings the poll set to its new
//! state before it runs `iready`/`oready` and deselects before a descriptor is closed.
//!
//! Each case runs child `arinsal` processes that loop open/close cycles of one kind of
//! selected descriptor. A child that does not exit within the deadline is signalled and
//! the test fails without waiting for it.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const CHILDREN: usize = 3;
const DEADLINE: Duration = Duration::from_secs(240);

fn arinsal() -> PathBuf {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/arinsal");
    assert!(path.is_file(), "build target/debug/arinsal first");
    path
}

struct Run {
    children: Vec<Child>,
    /// Keeps the parent ends of the child pipes open until the children finished.
    _pipes: Vec<(
        Option<std::process::ChildStdin>,
        Option<std::process::ChildStdout>,
    )>,
}

fn run_children(eval: &str, extra_args: &[&str], piped_stdio: bool, env: &[(&str, &Path)]) {
    // The cases share the per-user thread limit of the machine: run one at a time.
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _serial = SERIAL.lock().unwrap_or_else(|poison| poison.into_inner());
    let mut run = Run {
        children: Vec::new(),
        _pipes: Vec::new(),
    };
    for _ in 0..CHILDREN {
        let mut command = Command::new(arinsal());
        command.args(["+S", "2:2", "-noshell"]).args(extra_args);
        command.args(["-eval", eval]);
        for (key, value) in env {
            command.env(key, value);
        }
        command.stderr(Stdio::null());
        if piped_stdio {
            command.stdin(Stdio::piped()).stdout(Stdio::piped());
        } else {
            command.stdin(Stdio::null()).stdout(Stdio::null());
        }
        let mut child = command.spawn().expect("spawn arinsal");
        run._pipes.push((child.stdin.take(), child.stdout.take()));
        run.children.push(child);
    }
    let started = Instant::now();
    let mut finished = vec![None; CHILDREN];
    while finished.iter().any(Option::is_none) {
        if started.elapsed() > DEADLINE {
            // A child stuck in close(2) cannot be reaped: signal it and fail without waiting.
            let stuck: Vec<u32> = run
                .children
                .iter_mut()
                .zip(&finished)
                .filter(|(_, status)| status.is_none())
                .map(|(child, _)| {
                    let _ = child.kill();
                    child.id()
                })
                .collect();
            panic!("arinsal children {stuck:?} did not exit within {DEADLINE:?}");
        }
        for (child, status) in run.children.iter_mut().zip(finished.iter_mut()) {
            if status.is_none() {
                *status = child.try_wait().expect("try_wait");
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    for status in finished.into_iter().flatten() {
        assert!(status.success(), "arinsal exited with {status}");
    }
}

#[test]
fn spawn_port_open_close_loops_finish() {
    let eval = "lists:foreach(fun(I) -> \
                    P = open_port({spawn_executable, \"/bin/cat\"}, [binary, stream, eof, use_stdio]), \
                    case I rem 2 of \
                        0 -> port_command(P, <<\"x\">>), \
                             receive {P, {data, _}} -> ok after 10000 -> exit(no_echo) end; \
                        1 -> ok \
                    end, \
                    port_close(P), \
                    case I rem 32 of 0 -> timer:sleep(1); _ -> ok end \
                end, lists:seq(1, 1500)), halt().";
    run_children(eval, &[], false, &[]);
}

#[test]
fn fd_port_open_close_loops_finish() {
    let eval = "lists:foreach(fun(I) -> \
                    P = open_port({fd, 0, 1}, [binary, stream]), \
                    port_close(P), \
                    case I rem 32 of 0 -> timer:sleep(1); _ -> ok end \
                end, lists:seq(1, 6000)), halt().";
    run_children(eval, &[], true, &[]);
}

#[test]
fn socket_nif_select_close_loops_finish() {
    let eval = "lists:foreach(fun(I) -> \
                    {ok, S} = socket:open(inet, dgram, udp, #{owner => self()}), \
                    ok = socket:bind(S, #{family => inet, addr => {127,0,0,1}, port => 0}), \
                    {select, {select_info, _, Ref}} = socket:recvfrom(S, 0, nowait), \
                    case I rem 2 of \
                        0 -> {ok, Addr} = socket:sockname(S), \
                             ok = socket:sendto(S, <<\"x\">>, Addr), \
                             receive {'$socket', S, select, Ref} -> ok \
                             after 10000 -> exit(no_select) end; \
                        1 -> ok \
                    end, \
                    ok = socket:close(S) \
                end, lists:seq(1, 15000)), halt().";
    run_children(eval, &[], false, &[]);
}

const SELECT_NIF_C: &str = r#"
#include <erl_nif.h>
#include <fcntl.h>
#include <unistd.h>

typedef struct { int rd; int wr; } Pipe;
static ErlNifResourceType* pipe_type;

static void pipe_dtor(ErlNifEnv* env, void* obj) {
    Pipe* p = obj;
    if (p->wr >= 0) close(p->wr);
    if (p->rd >= 0) close(p->rd);
}

static void pipe_stop(ErlNifEnv* env, void* obj, ErlNifEvent event, int is_direct_call) {
    Pipe* p = obj;
    close(event);
    p->rd = -1;
}

static int load(ErlNifEnv* env, void** priv, ERL_NIF_TERM info) {
    ErlNifResourceTypeInit init = {pipe_dtor, pipe_stop, NULL};
    pipe_type = enif_init_resource_type(env, "select_pipe", &init, ERL_NIF_RT_CREATE, NULL);
    return pipe_type == NULL;
}

static ERL_NIF_TERM new_pipe(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    int fds[2];
    if (pipe(fds) != 0) return enif_make_badarg(env);
    for (int i = 0; i < 2; i++) {
        fcntl(fds[i], F_SETFD, FD_CLOEXEC);
        fcntl(fds[i], F_SETFL, O_NONBLOCK);
    }
    Pipe* p = enif_alloc_resource(pipe_type, sizeof(Pipe));
    p->rd = fds[0];
    p->wr = fds[1];
    ERL_NIF_TERM term = enif_make_resource(env, p);
    enif_release_resource(p);
    return term;
}

static ERL_NIF_TERM select_read(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    Pipe* p;
    if (!enif_get_resource(env, argv[0], pipe_type, (void**)&p)) return enif_make_badarg(env);
    int ret = enif_select(env, p->rd, ERL_NIF_SELECT_READ, p, NULL, argv[1]);
    return enif_make_int(env, ret);
}

static ERL_NIF_TERM poke(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    Pipe* p;
    if (!enif_get_resource(env, argv[0], pipe_type, (void**)&p)) return enif_make_badarg(env);
    return enif_make_int(env, (int)write(p->wr, "x", 1));
}

static ERL_NIF_TERM stop(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    Pipe* p;
    if (!enif_get_resource(env, argv[0], pipe_type, (void**)&p)) return enif_make_badarg(env);
    int ret = enif_select(env, p->rd, ERL_NIF_SELECT_STOP, p, NULL, enif_make_atom(env, "undefined"));
    return enif_make_int(env, ret);
}

static ErlNifFunc funcs[] = {
    {"new_pipe", 0, new_pipe},
    {"select_read", 2, select_read},
    {"poke", 1, poke},
    {"stop", 1, stop},
};

ERL_NIF_INIT(select_close_nif, funcs, load, NULL, NULL, NULL)
"#;

const SELECT_NIF_ERL: &str = r#"
-module(select_close_nif).
-export([cycles/1]).
-nifs([new_pipe/0, select_read/2, poke/1, stop/1]).
-on_load(init/0).

init() -> erlang:load_nif(os:getenv("SELECT_CLOSE_NIF"), 0).

new_pipe() -> erlang:nif_error(nif_not_loaded).
select_read(_, _) -> erlang:nif_error(nif_not_loaded).
poke(_) -> erlang:nif_error(nif_not_loaded).
stop(_) -> erlang:nif_error(nif_not_loaded).

cycles(N) ->
    lists:foreach(
        fun(I) ->
            Pipe = new_pipe(),
            Ref = make_ref(),
            0 = select_read(Pipe, Ref),
            case I rem 2 of
                0 ->
                    1 = poke(Pipe),
                    receive {select, Pipe, Ref, ready_input} -> ok
                    after 10000 -> exit(no_select) end;
                1 ->
                    ok
            end,
            %% ERL_NIF_SELECT_STOP_CALLED (1) or ERL_NIF_SELECT_STOP_SCHEDULED (2).
            case stop(Pipe) band 3 of
                0 -> exit(stop_not_called);
                _ -> ok
            end
        end,
        lists:seq(1, N)).
"#;

fn otp_include() -> PathBuf {
    let root = std::env::var_os("ARINSAL_OTP_ROOT")
        .map(PathBuf::from)
        .or_else(|| {
            let output = Command::new("erl")
                .args([
                    "-noshell",
                    "-eval",
                    "io:format(\"~s\",[code:root_dir()]),halt().",
                ])
                .output()
                .ok()?;
            output
                .status
                .success()
                .then(|| String::from_utf8(output.stdout).ok())
                .flatten()
                .map(PathBuf::from)
        })
        .expect("OTP root: set ARINSAL_OTP_ROOT or put erl on PATH");
    root.join("usr/include")
}

#[test]
fn nif_select_stop_loops_finish() {
    let dir = std::env::temp_dir().join(format!("arinsal-selclose-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("select_close_nif.c"), SELECT_NIF_C).unwrap();
    std::fs::write(dir.join("select_close_nif.erl"), SELECT_NIF_ERL).unwrap();
    let status = Command::new("cc")
        .args(["-shared", "-fPIC", "-undefined", "dynamic_lookup", "-I"])
        .arg(otp_include())
        .arg(dir.join("select_close_nif.c"))
        .arg("-o")
        .arg(dir.join("select_close_nif.so"))
        .status()
        .expect("cc");
    assert!(status.success(), "compile select_close_nif.so");
    let status = Command::new("erlc")
        .arg("-o")
        .arg(&dir)
        .arg(dir.join("select_close_nif.erl"))
        .status()
        .expect("erlc");
    assert!(status.success(), "compile select_close_nif.erl");
    let so = dir.join("select_close_nif");
    run_children(
        "select_close_nif:cycles(15000), halt().",
        &["-pa", dir.to_str().unwrap()],
        false,
        &[("SELECT_CLOSE_NIF", &so)],
    );
    let _ = std::fs::remove_dir_all(&dir);
}
