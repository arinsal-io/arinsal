//! `enif_send` from a NIF-created (non-scheduler) thread, with `env == NULL` and with an
//! `enif_alloc_env` (process-independent) env.
//
// Port of erts/emulator/beam/erl_nif.c:860-1075 (enif_send) and erl_trace.c:887-895
// (trace_receive_session), OTP-29.1.1. Both envs have `c_p == NULL`, so `from` is
// `am_undefined` and `erts_queue_message` forces the seq token to `am_undefined` (the
// receiver keeps its token; there is no `send` trace, because there is no caller).
// A receive match spec `[{['$1','$2','_'],[],[{message,{{'$1','$2'}}}]}]` appends
// `{undefined, undefined}`. A process-bound env sends as the caller pid.

use std::path::Path;

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_vm::Vm;

fn otp_include() -> std::path::PathBuf {
    let root = std::env::var_os("ARINSAL_OTP_ROOT")
        .map(std::path::PathBuf::from)
        .or_else(|| {
            let output = std::process::Command::new("erl")
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
                .map(std::path::PathBuf::from)
        })
        .expect("OTP root: set ARINSAL_OTP_ROOT or put erl on PATH");
    root.join("usr/include")
}

fn work_dir(name: &str) -> std::path::PathBuf {
    let dir =
        std::env::temp_dir().join(format!("arinsal-nifthr-env-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn compile_so(dir: &Path, name: &str, source: &str) -> std::path::PathBuf {
    let source_path = dir.join(format!("{name}.c"));
    let object = dir.join(name);
    std::fs::write(&source_path, source).unwrap();
    let status = std::process::Command::new("cc")
        .args([
            "-shared",
            "-fPIC",
            #[cfg(target_os = "macos")]
            "-undefined",
            #[cfg(target_os = "macos")]
            "dynamic_lookup",
            "-I",
        ])
        .arg(otp_include())
        .arg(&source_path)
        .arg("-o")
        .arg(object.with_extension("so"))
        .status()
        .expect("cc");
    assert!(status.success(), "compile {name}.so");
    object
}

fn compile_beam(erl: &RefErl, dir: &Path, module: &str, source: &str) {
    let bytes = erl
        .compile_named(module, source, &[])
        .unwrap_or_else(|error| panic!("compile {module}: {error}"));
    std::fs::write(dir.join(format!("{module}.beam")), &bytes).unwrap();
    erl.load(module, &bytes).unwrap();
}

fn scheduled(dir: &Path, module: &str) -> OwnedTerm {
    let mut vm = Vm::new([dir.to_path_buf()]);
    match vm.eval_scheduled(module, "run", &[], 1, Some(1)) {
        Ok(result) => result.term,
        Err(error) => panic!("{module}:run/0 failed on Arinsal: {error}"),
    }
}

fn reference(erl: &RefErl, module: &str) -> OwnedTerm {
    match erl.call(module, "run", &[]) {
        CallResult::Ok(term) => term,
        other => panic!("{module}:run/0 on erl: {other:?}"),
    }
}

#[test]
fn nif_thread_send_null_and_alloc_env_match_erts() {
    let Ok(erl) = RefErl::start() else {
        eprintln!("erl unavailable; skipping NIF thread send env differential test");
        return;
    };
    let dir = work_dir("thread_send_env");
    compile_so(
        &dir,
        "nifthr_env",
        r#"
        #include "erl_nif.h"
        struct send_arg { ErlNifPid to; };
        static void *send_thread(void *p) {
            struct send_arg *a = (struct send_arg *)p;
            ErlNifPid to = a->to;
            /* env == NULL: c_p == NULL, from = am_undefined. */
            {
                ErlNifEnv *msg_env = enif_alloc_env();
                ERL_NIF_TERM msg = enif_make_tuple2(msg_env,
                    enif_make_atom(msg_env, "null_env"), enif_make_int(msg_env, 1));
                enif_send(NULL, &to, msg_env, msg);
                enif_free_env(msg_env);
            }
            /* env == enif_alloc_env() (process-independent): c_p == NULL, from = am_undefined. */
            {
                ErlNifEnv *env = enif_alloc_env();
                ERL_NIF_TERM msg = enif_make_tuple2(env,
                    enif_make_atom(env, "alloc_env"), enif_make_int(env, 2));
                enif_send(env, &to, env, msg);
                enif_free_env(env);
            }
            return NULL;
        }
        static ERL_NIF_TERM send_from_proc(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
            ErlNifPid to;
            ErlNifEnv *msg_env;
            ERL_NIF_TERM msg;
            if (argc != 1 || !enif_get_local_pid(env, argv[0], &to)) return enif_make_badarg(env);
            /* Process-bound env: c_p is the caller, from = caller pid. */
            msg_env = enif_alloc_env();
            msg = enif_make_tuple2(msg_env, enif_make_atom(msg_env, "proc_env"), enif_make_int(msg_env, 3));
            enif_send(env, &to, msg_env, msg);
            enif_free_env(msg_env);
            return enif_make_atom(env, "ok");
        }
        static ERL_NIF_TERM send_from_thread(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
            struct send_arg *a;
            ErlNifTid tid;
            void *r;
            int started;
            if (argc != 1) return enif_make_badarg(env);
            a = enif_alloc(sizeof(struct send_arg));
            if (!a) return enif_make_badarg(env);
            if (!enif_get_local_pid(env, argv[0], &a->to)) { enif_free(a); return enif_make_badarg(env); }
            started = enif_thread_create("nifthr_env", &tid, send_thread, a, NULL) == 0;
            if (started) enif_thread_join(tid, &r);
            enif_free(a);
            return enif_make_atom(env, started ? "ok" : "no_thread");
        }
        static ErlNifFunc funcs[] = {
            {"send_from_thread", 1, send_from_thread, 0},
            {"send_from_proc", 1, send_from_proc, 0}};
        ERL_NIF_INIT(nifthr_env, funcs, NULL, NULL, NULL, NULL)
        "#,
    );
    let source = format!(
        r#"-module(nifthr_env).
        -export([run/0, send_from_thread/1, send_from_proc/1]).
        -nifs([send_from_thread/1, send_from_proc/1]).
        send_from_thread(_) -> erlang:nif_error(not_loaded).
        send_from_proc(_) -> erlang:nif_error(not_loaded).
        drain(Acc) ->
            receive M -> drain([M|Acc]) after 0 -> lists:reverse(Acc) end.
        tracer(Acc) ->
            receive
                {{stop, From}} -> From ! {{events, lists:reverse(Acc)}};
                E -> tracer([E|Acc])
            end.
        %% The caller's pid number differs between the two nodes. Replace that pid so the
        %% comparison is the sender identity: parent, or the atom undefined.
        norm(P, Parent) when P =:= Parent -> parent;
        norm(T, Parent) when is_tuple(T) ->
            list_to_tuple([norm(E, Parent) || E <- tuple_to_list(T)]);
        norm([H|T], Parent) -> [norm(H, Parent)|norm(T, Parent)];
        norm(T, _) -> T.
        run() ->
            ok = erlang:load_nif("{}", 0),
            Parent = self(),
            %% Load seq_trace before tracing. The first call is a code_server round trip,
            %% and those messages are not part of enif_send.
            seq_trace:set_token(label, 1),
            seq_trace:set_token([]),
            _ = drain([]),
            Tracer = spawn(fun() -> tracer([]) end),
            %% {{message, {{'$1','$2'}}}} appends {{Node, Sender}}. A thread send's from is
            %% am_undefined, so both slots are the atom undefined (erl_trace.c).
            1 = erlang:trace_pattern('receive', [{{['$1', '$2', '_'], [], [{{message, {{{{'$1', '$2'}}}}}}]}}], []),
            1 = erlang:trace(Parent, true, ['receive', send, {{tracer, Tracer}}]),
            seq_trace:set_token(label, 3),
            ok = send_from_thread(Parent),
            ThreadMsgs = drain([]),
            %% erts_queue_message forces the token to am_undefined, so the label survives.
            Label = seq_trace:get_token(label),
            seq_trace:set_token([]),
            ok = send_from_proc(Parent),
            ProcMsgs = drain([]),
            erlang:trace(Parent, false, [send, 'receive']),
            erlang:trace_pattern('receive', false, []),
            Tracer ! {{stop, self()}},
            Events = receive {{events, E}} -> E after 2000 -> timeout end,
            norm({{ThreadMsgs, Label, ProcMsgs, lists:sort(Events)}}, Parent)."#,
        dir.join("nifthr_env").display()
    );
    compile_beam(&erl, &dir, "nifthr_env", &source);
    let expected = reference(&erl, "nifthr_env");
    let actual = scheduled(&dir, "nifthr_env");
    similar_asserts::assert_eq!(actual, expected, "nifthr_env:run/0");
    let _ = std::fs::remove_dir_all(&dir);
}
