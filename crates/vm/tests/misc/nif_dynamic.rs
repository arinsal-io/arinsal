//! Dynamic `load_nif`, OTP `crypto.so`, and `erl_tracer` against erl 29.1.1.

use std::path::{Path, PathBuf};
use std::process::Command;

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_vm::Vm;

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

fn work_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("arinsal-nifdyn-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn compile_so(dir: &Path, name: &str, source: &str) -> PathBuf {
    let source_path = dir.join(format!("{name}.c"));
    let object = dir.join(name);
    std::fs::write(&source_path, source).unwrap();
    let status = Command::new("cc")
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

fn scheduled_cli(dir: &Path, module: &str) -> OwnedTerm {
    let output = dir.join(format!("{module}.etf"));
    let arinsal = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/arinsal");
    let eval = format!(
        "ok=file:write_file(\"{}\",term_to_binary({module}:run())), halt().",
        output.display()
    );
    let result = Command::new("timeout")
        .arg("40")
        .arg(arinsal)
        .args(["-noshell", "-pa"])
        .arg(dir)
        .args(["-eval", &eval])
        .output()
        .expect("timeout arinsal");
    assert!(
        result.status.success(),
        "{module}:run/0 on Arinsal CLI failed: {}{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    arinsal_etf::decode(&std::fs::read(&output).expect("Arinsal ETF output")).unwrap()
}

fn reference(erl: &RefErl, module: &str) -> OwnedTerm {
    match erl.call(module, "run", &[]) {
        CallResult::Ok(term) => term,
        other => panic!("{module}:run/0 on erl: {other:?}"),
    }
}

fn charlist_string(term: &OwnedTerm) -> Option<String> {
    let OwnedTerm::List { elems, tail } = term else {
        return None;
    };
    if !matches!(tail.as_ref(), OwnedTerm::Nil) {
        return None;
    }
    let mut text = String::new();
    for elem in elems {
        let OwnedTerm::Int(value) = elem else {
            return None;
        };
        text.push(char::from_u32(u32::try_from(*value).ok()?)?);
    }
    Some(text)
}

fn normalize_message(text: &str) -> String {
    let mut text = text.to_owned();
    if let Some(start) = text.find("dlsym(0x")
        && let Some(relative) = text[start..].find(',')
    {
        text.replace_range(start..start + relative, "dlsym(HANDLE");
    }
    if let Some(open) = text.find("dlopen(")
        && let Some(relative) = text[open..].find("):")
    {
        text.truncate(open + relative + "):".len());
    }
    text
}

fn normalize(term: &OwnedTerm) -> OwnedTerm {
    match term {
        OwnedTerm::List { elems, tail } => {
            let list = OwnedTerm::List {
                elems: elems.clone(),
                tail: tail.clone(),
            };
            if let Some(text) = charlist_string(&list)
                && (text.contains("dlopen(") || text.contains("dlsym("))
            {
                return OwnedTerm::charlist(&normalize_message(&text));
            }
            OwnedTerm::List {
                elems: elems.iter().map(normalize).collect(),
                tail: Box::new(normalize(tail)),
            }
        }
        OwnedTerm::Tuple(items) => OwnedTerm::Tuple(items.iter().map(normalize).collect()),
        other => other.clone(),
    }
}

fn assert_same(dir: &Path, erl: &RefErl, module: &str) {
    let expected = normalize(&reference(erl, module));
    let actual = normalize(&scheduled(dir, module));
    similar_asserts::assert_eq!(actual, expected, "{module}:run/0");
}

fn assert_crypto_same(erl: &RefErl, name: &str, body: &str) {
    let dir = work_dir(name);
    let source = format!(
        "-module({name}).\n-export([run/0]).\nrun() ->\n    {{module, crypto}} = code:ensure_loaded(crypto),\n    {body}.\n"
    );
    compile_beam(erl, &dir, name, &source);
    similar_asserts::assert_eq!(
        scheduled_cli(&dir, name),
        reference(erl, name),
        "{name}:run/0"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

fn tracer_module_case(mode: &str, test_name: &str) {
    let Ok(erl) = RefErl::start() else {
        eprintln!("erl unavailable; skipping module tracer differential test");
        return;
    };
    let dir = work_dir(test_name);
    let module = test_name.to_owned();
    let library = compile_so(
        &dir,
        &module,
        &format!(
            r#"
            #include "erl_nif.h"
            static ERL_NIF_TERM enabled(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {{
                const ERL_NIF_TERM *state;
                int arity;
                (void)argc;
                if (enif_is_identical(argv[0], enif_make_atom(env, "trace_status")))
                    return enif_make_atom(env, "trace");
                if (!enif_is_identical(argv[0], enif_make_atom(env, "send")) &&
                    !enif_is_identical(argv[0], enif_make_atom(env, "seq_trace")))
                    return enif_make_atom(env, "discard");
                if (enif_get_tuple(env, argv[1], &arity, &state) && arity == 2 &&
                    enif_is_identical(state[1], enif_make_atom(env, "{mode}")))
                    return enif_make_atom(env, "{mode}");
                return enif_make_atom(env, "trace");
            }}
            static ERL_NIF_TERM trace(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {{
                const ERL_NIF_TERM *state;
                ERL_NIF_TERM message;
                ErlNifPid pid;
                int arity;
                (void)argc;
                if (enif_get_tuple(env, argv[1], &arity, &state) && arity == 2 &&
                    enif_get_local_pid(env, state[0], &pid)) {{
                    message = enif_make_tuple4(env, enif_make_atom(env, "module_trace"),
                                               argv[2], argv[0], argv[3]);
                    enif_send(env, &pid, NULL, message);
                }}
                return enif_make_atom(env, "ok");
            }}
            static ErlNifFunc funcs[] = {{
                {{"enabled", 3, enabled, 0}}, {{"trace", 5, trace, 0}}
            }};
            ERL_NIF_INIT({module}, funcs, NULL, NULL, NULL, NULL)
            "#
        ),
    );
    let source = if test_name.contains("seq_trace") {
        format!(
            r#"
            -module({test_name}).
            -export([run/0, enabled/3, trace/5]).
            -nifs([enabled/3, trace/5]).
            enabled(_, _, _) -> erlang:nif_error(undef).
            trace(_, _, _, _, _) -> erlang:nif_error(undef).
            run() ->
                ok = erlang:load_nif("{}", []),
                Parent = self(),
                false = seq_trace:set_system_tracer({{{module}, {{Parent, {mode}}}}}),
                seq_trace:set_token(label, label),
                seq_trace:set_token(send, true),
                Child = spawn(fun() -> receive go -> Parent ! payload end end),
                Child ! go,
                Seen = receive
                    {{module_trace, Child, seq_trace, {{send, _, _, _, payload}}}} -> true
                after 1000 -> false
                end,
                seq_trace:set_system_tracer(false),
                {{Seen, is_pid(Child)}}.
            "#,
            library.display()
        )
    } else {
        format!(
            r#"
        -module({test_name}).
        -export([run/0, enabled/3, trace/5]).
        -nifs([enabled/3, trace/5]).
        enabled(_, _, _) -> erlang:nif_error(undef).
        trace(_, _, _, _, _) -> erlang:nif_error(undef).
        run() ->
            ok = erlang:load_nif("{}", []),
            Parent = self(),
            Session = trace:session_create(module_tracer, {{{module}, {{Parent, {mode}}}}}, []),
            Child = spawn(fun() -> receive go -> Parent ! payload end end),
            1 = trace:process(Session, Child, true, [send]),
            Child ! go,
            Seen = receive
                {{module_trace, Child, send, payload}} -> true
            after 1000 -> false
            end,
            trace:session_destroy(Session),
            {{Seen, is_pid(Child)}}.
        "#,
            library.display()
        )
    };
    compile_beam(&erl, &dir, test_name, &source);
    let expected = reference(&erl, test_name);
    let actual = scheduled(&dir, test_name);
    similar_asserts::assert_eq!(actual, expected, "{test_name}:run/0");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn tracer_mod_nif_trace_matches_erts() {
    tracer_module_case("trace", "nifdyn_tracer_mod_trace");
}

#[test]
fn tracer_mod_nif_discard_matches_erts() {
    tracer_module_case("discard", "nifdyn_tracer_mod_discard");
}

#[test]
fn tracer_mod_sequential_tracer_matches_erts() {
    tracer_module_case("trace", "nifdyn_tracer_mod_seq_trace");
}

/// Run `module:run/0` through the CLI with extra environment variables (e.g. the interpreter).
fn scheduled_cli_env(dir: &Path, module: &str, env: &[(&str, &str)]) -> OwnedTerm {
    let output = dir.join(format!("{module}.etf"));
    let arinsal = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/arinsal");
    let eval = format!(
        "ok=file:write_file(\"{}\",term_to_binary({module}:run())), halt().",
        output.display()
    );
    let result = Command::new("timeout")
        .arg("120")
        .arg(arinsal)
        .args(["-noshell", "-pa"])
        .arg(dir)
        .args(["-eval", &eval])
        .envs(env.iter().copied())
        .output()
        .expect("timeout arinsal");
    assert!(
        result.status.success(),
        "{module}:run/0 on Arinsal CLI {env:?} failed: {}{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    arinsal_etf::decode(&std::fs::read(&output).expect("Arinsal ETF output")).unwrap()
}

/// Dirty flags of function `index` of a wide library: normal, dirty CPU, dirty I/O in turn.
fn wide_flags(index: usize) -> &'static str {
    match index % 3 {
        0 => "0",
        1 => "ERL_NIF_DIRTY_JOB_CPU_BOUND",
        _ => "ERL_NIF_DIRTY_JOB_IO_BOUND",
    }
}

/// A NIF library for `module` with `count` functions `f<N>/0`, each returning
/// `{Tag, N, enif_thread_type()}` and with the dirty flags `flags(N)`, and `extra` C code and
/// `ErlNifFunc` entries after them.
fn wide_nif_source(
    module: &str,
    count: usize,
    tag: i32,
    flags: fn(usize) -> &'static str,
    extra: (&str, &str),
) -> String {
    let mut source = String::from("#include \"erl_nif.h\"\n");
    for index in 0..count {
        source.push_str(&format!(
            "static ERL_NIF_TERM f{index}(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {{ (void)argc; (void)argv; return enif_make_tuple3(env, enif_make_int(env, {tag}), enif_make_int(env, {index}), enif_make_int(env, enif_thread_type())); }}\n"
        ));
    }
    source.push_str(extra.0);
    source.push_str("static ErlNifFunc funcs[] = {");
    for index in 0..count {
        source.push_str(&format!("{{\"f{index}\", 0, f{index}, {}}},", flags(index)));
    }
    source.push_str(extra.1);
    source.push_str(&format!(
        "}};\nERL_NIF_INIT({module}, funcs, NULL, NULL, NULL, NULL)\n"
    ));
    source
}

/// An Erlang module whose `f<N>/0` (and `extra_nifs`) are NIFs of `library`, with `load/0`
/// calling `erlang:load_nif/2` and `local/0` calling every `f<N>/0` locally. `extra` holds
/// attributes and functions to add.
fn wide_module_source(
    module: &str,
    count: usize,
    library: &Path,
    extra_nifs: &[&str],
    (attributes, body): (&str, &str),
) -> String {
    let mut nifs = (0..count)
        .map(|index| format!("f{index}/0"))
        .collect::<Vec<_>>();
    nifs.extend(extra_nifs.iter().map(|nif| (*nif).to_owned()));
    let nifs = nifs.join(", ");
    let stubs = (0..count)
        .map(|index| format!("f{index}() -> erlang:nif_error(undef).\n"))
        .collect::<String>();
    // Calls in chunks: one list expression of more than 1024 calls exceeds the X registers.
    let chunks = (0..count).collect::<Vec<_>>();
    let chunks = chunks.chunks(200).collect::<Vec<_>>();
    let calls = (0..chunks.len())
        .map(|chunk| format!("local{chunk}()"))
        .collect::<Vec<_>>()
        .join(", ");
    let calls = format!("lists:append([{calls}])");
    let stubs = chunks
        .iter()
        .enumerate()
        .map(|(chunk, indexes)| {
            let calls = indexes
                .iter()
                .map(|index| format!("f{index}()"))
                .collect::<Vec<_>>()
                .join(", ");
            format!("local{chunk}() -> [{calls}].\n")
        })
        .chain(std::iter::once(stubs))
        .collect::<String>();
    format!(
        "-module({module}).\n-export([load/0, local/0, {nifs}]).\n-nifs([{nifs}]).\n{attributes}\
         load() -> erlang:load_nif(\"{}\", []).\nlocal() -> {calls}.\n{stubs}{body}",
        library.display()
    )
}

/// Compile a wide library and its module into `dir`.
fn wide_module(erl: &RefErl, dir: &Path, module: &str, count: usize, tag: i32) {
    let library = compile_so(
        dir,
        module,
        &wide_nif_source(module, count, tag, wide_flags, ("", "")),
    );
    compile_beam(
        erl,
        dir,
        module,
        &wide_module_source(module, count, &library, &[], ("", "")),
    );
}

/// Compare `module:run/0` on erl with Arinsal's BeamAsm and interpreter, each on a booted node.
fn assert_same_jit_and_interp(dir: &Path, erl: &RefErl, module: &str) {
    let expected = normalize(&reference(erl, module));
    similar_asserts::assert_eq!(
        normalize(&scheduled_cli_env(dir, module, &[("ARINSAL_BEAMASM", "1")])),
        expected,
        "{module}:run/0 (BeamAsm)"
    );
    similar_asserts::assert_eq!(
        normalize(&scheduled_cli_env(dir, module, &[("ARINSAL_INTERP", "1")])),
        expected,
        "{module}:run/0 (interpreter)"
    );
}

/// Erlang code returning `{Loaded, Local, Remote}` for the wide module `module`.
fn wide_calls(module: &str, count: usize) -> String {
    format!(
        "{{{module}:load(), {module}:local(), \
         [{module}:F() || F <- [list_to_atom(\"f\" ++ integer_to_list(I)) || I <- lists:seq(0, {count} - 1)]]}}"
    )
}

#[test]
fn library_with_more_nifs_than_the_old_table_matches_erts() {
    let Ok(erl) = RefErl::start() else {
        eprintln!("erl unavailable; skipping dynamic NIF differential test");
        return;
    };
    const COUNT: usize = 300;
    let dir = work_dir("wide");
    let mut c_source = String::from("#include \"erl_nif.h\"\n");
    for index in 0..COUNT {
        c_source.push_str(&format!(
            "static ERL_NIF_TERM f{index}(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {{ (void)argc; (void)argv; return enif_make_int(env, {index}); }}\n"
        ));
    }
    c_source.push_str("static ErlNifFunc funcs[] = {");
    for index in 0..COUNT {
        c_source.push_str(&format!("{{\"f{index}\", 0, f{index}, 0}},"));
    }
    c_source.push_str("};\nERL_NIF_INIT(nifdyn_wide, funcs, NULL, NULL, NULL, NULL)\n");
    let library = compile_so(&dir, "nifdyn_wide", &c_source);
    let names = (0..COUNT)
        .map(|index| format!("f{index}/0"))
        .collect::<Vec<_>>()
        .join(", ");
    let stubs = (0..COUNT)
        .map(|index| format!("f{index}() -> erlang:nif_error(undef).\n"))
        .collect::<String>();
    let calls = (0..COUNT)
        .map(|index| format!("f{index}()"))
        .collect::<Vec<_>>()
        .join(", ");
    let module_src = format!(
        "-module(nifdyn_wide).\n-export([run/0, {names}]).\n-nifs([{names}]).\nrun() ->\n    Loaded = erlang:load_nif(\"{}\", []),\n    Values = [{calls}],\n    {{Loaded, length(Values), lists:sum(Values), hd(Values), lists:last(Values)}}.\n{stubs}",
        library.display()
    );
    compile_beam(&erl, &dir, "nifdyn_wide", &module_src);
    assert_same_jit_and_interp(&dir, &erl, "nifdyn_wide");
    let _ = std::fs::remove_dir_all(&dir);
}

// Port of erts/emulator/beam/erl_nif.c:4840-4942 (erts_load_nif allocates one ErtsNifBeamStub
// per function of the library), OTP-29.1.1: there is no limit on the functions of a library.
#[test]
fn library_with_more_nifs_than_the_stopgap_table_matches_erts() {
    let Ok(erl) = RefErl::start() else {
        eprintln!("erl unavailable; skipping dynamic NIF differential test");
        return;
    };
    const COUNT: usize = 1100;
    let dir = work_dir("wider");
    wide_module(&erl, &dir, "nifdyn_wider", COUNT, 7);
    let runner = format!(
        "-module(nifdyn_wider_run).\n-export([run/0]).\nrun() -> {}.\n",
        wide_calls("nifdyn_wider", COUNT)
    );
    compile_beam(&erl, &dir, "nifdyn_wider_run", &runner);
    assert_same_jit_and_interp(&dir, &erl, "nifdyn_wider_run");
    let _ = std::fs::remove_dir_all(&dir);
}

// Port of erts/emulator/beam/erl_nif.c:93-124 and 4825-4842 (each library is its own
// erl_module_nif with its own stubs), OTP-29.1.1.
#[test]
fn several_nif_libraries_loaded_at_once_match_erts() {
    let Ok(erl) = RefErl::start() else {
        eprintln!("erl unavailable; skipping dynamic NIF differential test");
        return;
    };
    const COUNT: usize = 250;
    let dir = work_dir("multi");
    let modules = [
        "nifdyn_multi_a",
        "nifdyn_multi_b",
        "nifdyn_multi_c",
        "nifdyn_multi_d",
    ];
    for (tag, module) in modules.iter().enumerate() {
        wide_module(&erl, &dir, module, COUNT, tag as i32);
    }
    let runner = format!(
        r#"
        -module(nifdyn_multi_run).
        -export([run/0]).
        run() ->
            Mods = [{mods}],
            Loaded = [M:load() || M <- Mods],
            Interleaved = [M:F() || F <- [f0, f1, f2, f124, f248, f249], M <- Mods],
            Local = [lists:usort([element(1, T) || T <- M:local()]) || M <- Mods],
            Counts = [length(M:local()) || M <- Mods],
            Nifs = [length(M:module_info(nifs)) || M <- Mods],
            {{Loaded, Interleaved, Local, Counts, Nifs}}.
        "#,
        mods = modules.join(", ")
    );
    compile_beam(&erl, &dir, "nifdyn_multi_run", &runner);
    assert_same_jit_and_interp(&dir, &erl, "nifdyn_multi_run");
    let _ = std::fs::remove_dir_all(&dir);
}

// Port of erts/emulator/beam/erl_nif.c:5334-5373 (erts_unload_nif releases the stubs when the
// module instance is purged) and 4774-4777 (a module instance takes one library), OTP-29.1.1.
#[test]
fn nif_module_purge_and_load_again_matches_erts() {
    let Ok(erl) = RefErl::start() else {
        eprintln!("erl unavailable; skipping dynamic NIF differential test");
        return;
    };
    const COUNT: usize = 300;
    let dir = work_dir("cycle");
    let library = compile_so(
        &dir,
        "nifdyn_cycle",
        // Normal NIFs only: purging after dirty calls trips a separate shadow-heap bug.
        &wide_nif_source("nifdyn_cycle", COUNT, 3, |_| "0", ("", "")),
    );
    let on_load = (
        "-on_load(init/0).\n",
        "init() -> persistent_term:put(nifdyn_cycle, load()), ok.\n",
    );
    compile_beam(
        &erl,
        &dir,
        "nifdyn_cycle",
        &wide_module_source("nifdyn_cycle", COUNT, &library, &[], on_load),
    );
    let runner = format!(
        r#"
        -module(nifdyn_cycle_run).
        -export([run/0]).
        run() ->
            Dir = "{}",
            true = code:add_patha(Dir),
            Cycles = [cycle() || _ <- lists:seq(1, 12)],
            Explicit = nifdyn_cycle:load(),
            purge(),
            {{lists:usort(Cycles), Explicit}}.
        cycle() ->
            purge(),
            {{module, nifdyn_cycle}} = code:load_file(nifdyn_cycle),
            Loaded = persistent_term:get(nifdyn_cycle),
            Local = nifdyn_cycle:local(),
            Remote = [nifdyn_cycle:f0(), nifdyn_cycle:f150(), nifdyn_cycle:f299()],
            {{Loaded, length(Local), lists:last(Local), Remote,
              length(nifdyn_cycle:module_info(nifs))}}.
        purge() ->
            code:purge(nifdyn_cycle),
            code:delete(nifdyn_cycle),
            code:purge(nifdyn_cycle).
        "#,
        dir.display()
    );
    compile_beam(&erl, &dir, "nifdyn_cycle_run", &runner);
    // The reference node loaded nifdyn_cycle while compiling; start from no loaded code.
    let _ = erl.call("code", "purge", &[OwnedTerm::Atom("nifdyn_cycle".into())]);
    let _ = erl.call("code", "delete", &[OwnedTerm::Atom("nifdyn_cycle".into())]);
    let _ = erl.call("code", "purge", &[OwnedTerm::Atom("nifdyn_cycle".into())]);
    assert_same_jit_and_interp(&dir, &erl, "nifdyn_cycle_run");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A library for `nifdyn_upg` whose `who/0` returns `name` and `get/0` the integer its
/// private data points to (0 without private data).
fn upgrade_nif_source(name: &str, load: &str, upgrade: &str) -> String {
    format!(
        r#"
        #include "erl_nif.h"
        static int one = 1, two = 2, seventy = 70, ninety = 90;
        static ERL_NIF_TERM who(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {{
            (void)argc; (void)argv;
            return enif_make_atom(env, "{name}");
        }}
        static ERL_NIF_TERM get(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {{
            int *value = enif_priv_data(env);
            (void)argc; (void)argv;
            return enif_make_int(env, value ? *value : 0);
        }}
        static int load(ErlNifEnv* env, void** priv, ERL_NIF_TERM info) {{
            (void)env; (void)info; (void)one; (void)two; (void)seventy; (void)ninety;
            {load}
        }}
        static int upgrade(ErlNifEnv* env, void** priv, void** old_priv, ERL_NIF_TERM info) {{
            (void)env; (void)info; (void)old_priv;
            {upgrade}
        }}
        static ErlNifFunc funcs[] = {{ {{"who", 0, who, 0}}, {{"get", 0, get, 0}} }};
        ERL_NIF_INIT(nifdyn_upg, funcs, load, NULL, {upgrade_ptr}, NULL)
        "#,
        upgrade_ptr = if upgrade.is_empty() {
            "NULL"
        } else {
            "upgrade"
        },
        upgrade = if upgrade.is_empty() {
            "return 0;"
        } else {
            upgrade
        },
    )
}

// Port of erts/emulator/beam/erl_nif.c:4758-4772 (`prev_mi`) and 4956-4987 (the upgrade or
// load callback), OTP-29.1.1: a library loaded while the previous code of the module has one is
// upgraded from it; the upgrade may replace the old library's private data, a veto restores it.
#[test]
fn nif_module_upgrade_matches_erts() {
    let Ok(erl) = RefErl::start() else {
        eprintln!("erl unavailable; skipping NIF upgrade differential test");
        return;
    };
    let dir = work_dir("upgrade");
    let versions = [
        ("v1", "*priv = &one; return 0;", ""),
        (
            "v2",
            "*priv = &two; return 0;",
            "*priv = &two; *old_priv = &seventy; return 0;",
        ),
        ("v3", "*priv = &two; return 0;", ""),
        ("v4", "return 0;", "*old_priv = &ninety; return 7;"),
    ];
    let mut binaries = Vec::new();
    for (name, load, upgrade) in versions {
        let library = compile_so(
            &dir,
            &format!("nifdyn_upg_{name}"),
            &upgrade_nif_source(name, load, upgrade),
        );
        let source = format!(
            r#"
            -module(nifdyn_upg).
            -on_load(init/0).
            -export([who/0, get/0, getter/0]).
            -nifs([who/0, get/0]).
            init() ->
                persistent_term:put({{nifdyn_upg, {name}}}, erlang:load_nif("{}", 0)),
                ok.
            getter() -> fun() -> {{who(), get()}} end.
            who() -> erlang:nif_error(undef).
            get() -> erlang:nif_error(undef).
            "#,
            library.display()
        );
        let beam = erl
            .compile_named("nifdyn_upg", &source, &[])
            .unwrap_or_else(|error| panic!("compile nifdyn_upg {name}: {error}"));
        binaries.push(byte_binary(&beam));
    }
    let runner = format!(
        r#"
        -module(nifdyn_upg_run).
        -export([run/0]).
        run() ->
            purge(),
            A = step(fun() -> load(v1, {v1}), {{result(v1), now()}} end),
            %% v2 upgrades from v1, which keeps running with the data v2's upgrade gave it.
            B = step(fun() ->
                         Old = nifdyn_upg:getter(),
                         load(v2, {v2}),
                         {{result(v2), now(), Old()}}
                     end),
            %% v4 vetoes its upgrade from v2: v2 keeps its data.
            C = step(fun() ->
                         code:purge(nifdyn_upg),
                         Old = nifdyn_upg:getter(),
                         load(v4, {v4}),
                         {{result(v4), Old(), call(who), call(get)}}
                     end),
            %% v1 is loaded fresh (the current v4 code has no library), v3 cannot upgrade.
            D = step(fun() ->
                         code:purge(nifdyn_upg),
                         load(v1, {v1}),
                         First = {{result(v1), now()}},
                         code:purge(nifdyn_upg),
                         Old = nifdyn_upg:getter(),
                         load(v3, {v3}),
                         {{First, result(v3), Old(), call(who)}}
                     end),
            %% With no previous code v2 loads instead of upgrading.
            E = step(fun() -> purge(), load(v2, {v2}), {{result(v2), now()}} end),
            purge(),
            {{A, B, C, D, E}}.
        load(Name, Bin) ->
            {{module, nifdyn_upg}} =
                code:load_binary(nifdyn_upg, atom_to_list(Name) ++ ".beam", Bin).
        result(Name) -> persistent_term:get({{nifdyn_upg, Name}}).
        now() -> {{nifdyn_upg:who(), nifdyn_upg:get()}}.
        call(F) -> try nifdyn_upg:F() catch Class:Reason -> {{Class, Reason}} end.
        step(Fun) ->
            Parent = self(),
            {{Pid, Ref}} = spawn_monitor(fun() -> Parent ! {{self(), Fun()}} end),
            receive {{Pid, Result}} -> receive {{'DOWN', Ref, _, _, _}} -> Result end;
                    {{'DOWN', Ref, _, _, Reason}} -> {{died, Reason}}
            end.
        purge() ->
            code:purge(nifdyn_upg),
            code:delete(nifdyn_upg),
            code:purge(nifdyn_upg).
        "#,
        v1 = binaries[0],
        v2 = binaries[1],
        v3 = binaries[2],
        v4 = binaries[3],
    );
    compile_beam(&erl, &dir, "nifdyn_upg_run", &runner);
    assert_same_jit_and_interp(&dir, &erl, "nifdyn_upg_run");
    let _ = std::fs::remove_dir_all(&dir);
}

// Port of erts/emulator/beam/erl_nif.c:4903-4940 (call_nif[1] of a dirty NIF is
// static_schedule_dirty_{io,cpu}_nif, call_nif[3] the NIF) and 3540-3583 (enif_schedule_nif),
// OTP-29.1.1: dirty flags are part of each function's binding, however many the library has.
#[test]
fn dirty_nifs_of_a_wide_library_match_erts() {
    let Ok(erl) = RefErl::start() else {
        eprintln!("erl unavailable; skipping dirty NIF differential test");
        return;
    };
    const COUNT: usize = 300;
    let dir = work_dir("wide_dirty");
    let extra_c = r#"
        static ERL_NIF_TERM cont(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
            (void)argc;
            return enif_make_tuple3(env, enif_make_atom(env, "cont"), argv[0],
                                    enif_make_int(env, enif_thread_type()));
        }
        static ERL_NIF_TERM resched(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
            int flags = 0;
            enif_get_int(env, argv[0], &flags);
            return enif_schedule_nif(env, "cont", flags, cont, argc, argv);
        }
    "#;
    let library = compile_so(
        &dir,
        "nifdyn_wide_dirty",
        &wide_nif_source(
            "nifdyn_wide_dirty",
            COUNT,
            5,
            wide_flags,
            (
                extra_c,
                "{\"resched\", 1, resched, ERL_NIF_DIRTY_JOB_IO_BOUND},",
            ),
        ),
    );
    compile_beam(
        &erl,
        &dir,
        "nifdyn_wide_dirty",
        &wide_module_source(
            "nifdyn_wide_dirty",
            COUNT,
            &library,
            &["resched/1"],
            ("", "resched(_) -> erlang:nif_error(undef).\n"),
        ),
    );
    let runner = format!(
        r#"
        -module(nifdyn_wide_dirty_run).
        -export([run/0]).
        run() ->
            {{Loaded, Local, Remote}} = {calls},
            Types = lists:usort([{{N rem 3, Type}} || {{_, N, Type}} <- Local ++ Remote]),
            Resched = [nifdyn_wide_dirty:resched(Flags) || Flags <- [0, 1, 2]],
            {{Loaded, Local, Types, Resched}}.
        "#,
        calls = wide_calls("nifdyn_wide_dirty", COUNT)
    );
    compile_beam(&erl, &dir, "nifdyn_wide_dirty_run", &runner);
    assert_same_jit_and_interp(&dir, &erl, "nifdyn_wide_dirty_run");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn load_nif_from_module_loaded_off_the_code_path_matches_erts() {
    let Ok(erl) = RefErl::start() else {
        eprintln!("erl unavailable; skipping dynamic NIF differential test");
        return;
    };
    let dir = work_dir("offpath");
    let late = dir.join("late");
    std::fs::create_dir_all(&late).unwrap();
    let library = compile_so(
        &late,
        "nifdyn_offpath",
        r#"
        #include "erl_nif.h"
        static ERL_NIF_TERM add(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
            int a, b;
            (void)argc;
            if (!enif_get_int(env, argv[0], &a) || !enif_get_int(env, argv[1], &b))
                return enif_make_badarg(env);
            return enif_make_int(env, a + b);
        }
        static ErlNifFunc funcs[] = {{"add", 2, add, 0}};
        ERL_NIF_INIT(nifdyn_offpath, funcs, NULL, NULL, NULL, NULL)
        "#,
    );
    let module_src = format!(
        "-module(nifdyn_offpath).\n-export([init/0, add/2]).\n-nifs([add/2]).\ninit() -> erlang:load_nif(\"{}\", []).\nadd(_, _) -> erlang:nif_error(undef).\n",
        library.display()
    );
    let beam = erl
        .compile_named("nifdyn_offpath", &module_src, &[])
        .unwrap_or_else(|error| panic!("compile nifdyn_offpath: {error}"));
    let beam_path = late.join("nifdyn_offpath.beam");
    std::fs::write(&beam_path, &beam).unwrap();
    let runner_src = format!(
        "-module(nifdyn_offpath_run).\n-export([run/0]).\nrun() ->\n    {{ok, Bin}} = prim_file:read_file(\"{}\"),\n    {{module, nifdyn_offpath}} = erlang:load_module(nifdyn_offpath, Bin),\n    Loaded = nifdyn_offpath:init(),\n    {{Loaded, nifdyn_offpath:add(20, 22)}}.\n",
        beam_path.display()
    );
    compile_beam(&erl, &dir, "nifdyn_offpath_run", &runner_src);
    assert_same(&dir, &erl, "nifdyn_offpath_run");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn load_nif_binds_any_function_of_a_module_without_nif_start_like_erts() {
    let Ok(erl) = RefErl::start() else {
        eprintln!("erl unavailable; skipping dynamic NIF differential test");
        return;
    };
    let dir = work_dir("nostart");
    let library = compile_so(
        &dir,
        "nifdyn_nostart",
        r#"
        #include "erl_nif.h"
        static ERL_NIF_TERM add(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
            int a, b;
            (void)argc;
            if (!enif_get_int(env, argv[0], &a) || !enif_get_int(env, argv[1], &b))
                return enif_make_badarg(env);
            return enif_make_int(env, a + b);
        }
        static ERL_NIF_TERM twice(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
            int a;
            (void)argc;
            if (!enif_get_int(env, argv[0], &a))
                return enif_make_badarg(env);
            return enif_make_int(env, 2 * a);
        }
        static ErlNifFunc funcs[] = {{"add", 2, add, 0}, {"twice", 1, twice, 0}};
        ERL_NIF_INIT(nifdyn_nostart, funcs, NULL, NULL, NULL, NULL)
        "#,
    );
    let module_src = format!(
        "-module(nifdyn_nostart).\n-export([run/0, add/2]).\nrun() ->\n    Loaded = load(erlang),\n    {{Loaded, try add(20, 22) catch error:A -> A end, try twice(21) catch error:T -> T end}}.\nload(M) -> M:load_nif(\"{}\", []).\nadd(_, _) -> erlang:nif_error(undef).\ntwice(_) -> erlang:nif_error(undef).\n",
        library.display()
    );
    compile_beam(&erl, &dir, "nifdyn_nostart", &module_src);
    assert_same(&dir, &erl, "nifdyn_nostart");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn load_nif_rejects_a_function_missing_from_nifs_like_erts() {
    let Ok(erl) = RefErl::start() else {
        eprintln!("erl unavailable; skipping dynamic NIF differential test");
        return;
    };
    let dir = work_dir("undeclared");
    let library = compile_so(
        &dir,
        "nifdyn_undeclared",
        r#"
        #include "erl_nif.h"
        static ERL_NIF_TERM add(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
            (void)argc;
            (void)argv;
            return enif_make_int(env, 1);
        }
        static ERL_NIF_TERM sub(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
            (void)argc;
            (void)argv;
            return enif_make_int(env, 2);
        }
        static ErlNifFunc funcs[] = {{"add", 2, add, 0}, {"sub", 2, sub, 0}};
        ERL_NIF_INIT(nifdyn_undeclared, funcs, NULL, NULL, NULL, NULL)
        "#,
    );
    let module_src = format!(
        "-module(nifdyn_undeclared).\n-export([run/0, add/2, sub/2]).\n-nifs([add/2]).\nrun() ->\n    Loaded = erlang:load_nif(\"{}\", []),\n    {{Loaded, try add(1, 2) catch error:A -> A end}}.\nadd(_, _) -> erlang:nif_error(undef).\nsub(_, _) -> 0.\n",
        library.display()
    );
    compile_beam(&erl, &dir, "nifdyn_undeclared", &module_src);
    assert_same(&dir, &erl, "nifdyn_undeclared");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn load_errors_and_roundtrip_match_erts() {
    let Ok(erl) = RefErl::start() else {
        eprintln!("erl unavailable; skipping dynamic NIF differential test");
        return;
    };
    let dir = work_dir("load");
    let dummy = compile_so(&dir, "nifdyn_dummy", "int nifdyn_dummy_anchor;\n");
    let add = compile_so(
        &dir,
        "nifdyn_add",
        r#"
        #include "erl_nif.h"
        static ERL_NIF_TERM add(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
            int a, b;
            (void)argc;
            if (!enif_get_int(env, argv[0], &a) || !enif_get_int(env, argv[1], &b))
                return enif_make_badarg(env);
            return enif_make_int(env, a + b);
        }
        static ErlNifFunc funcs[] = {{"add", 2, add, 0}};
        ERL_NIF_INIT(nifdyn_add, funcs, NULL, NULL, NULL, NULL)
        "#,
    );
    let missing_fn = compile_so(
        &dir,
        "nifdyn_missing_fn",
        r#"
        #include "erl_nif.h"
        static ERL_NIF_TERM nope(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
            (void)argc; (void)argv;
            return enif_make_atom(env, "nope");
        }
        static ErlNifFunc funcs[] = {{"nope", 1, nope, 0}};
        ERL_NIF_INIT(nifdyn_missing_fn, funcs, NULL, NULL, NULL, NULL)
        "#,
    );
    let plain = compile_so(
        &dir,
        "nifdyn_plain",
        r#"
        #include "erl_nif.h"
        static ERL_NIF_TERM plain(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
            (void)argc;
            return argv[0];
        }
        static ErlNifFunc funcs[] = {{"plain", 1, plain, 0}};
        ERL_NIF_INIT(nifdyn_plain, funcs, NULL, NULL, NULL, NULL)
        "#,
    );
    let veto = compile_so(
        &dir,
        "nifdyn_veto",
        r#"
        #include "erl_nif.h"
        static int load(ErlNifEnv* env, void** priv, ERL_NIF_TERM info) {
            (void)env; (void)priv; (void)info;
            return 7;
        }
        static ERL_NIF_TERM run_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
            (void)argc; (void)argv;
            return enif_make_atom(env, "ok");
        }
        static ErlNifFunc funcs[] = {{"run_nif", 0, run_nif, 0}};
        ERL_NIF_INIT(nifdyn_veto, funcs, load, NULL, NULL, NULL)
        "#,
    );
    compile_beam(
        &erl,
        &dir,
        "nifdyn_miss",
        r#"
        -module(nifdyn_miss).
        -export([run/0]).
        run() -> erlang:load_nif("/no/such/nif_dyn_missing", []).
        "#,
    );
    compile_beam(
        &erl,
        &dir,
        "nifdyn_badarg",
        r#"
        -module(nifdyn_badarg).
        -export([run/0]).
        run() ->
            try erlang:load_nif(1, []) of
                Value -> {ok, Value}
            catch
                error:Reason -> {error, Reason}
            end.
        "#,
    );
    let dummy_src = format!(
        "-module(nifdyn_dummy).\n-export([run/0]).\nrun() -> erlang:load_nif(\"{}\", []).\n",
        dummy.display()
    );
    compile_beam(&erl, &dir, "nifdyn_dummy", &dummy_src);
    let add_src = format!(
        "-module(nifdyn_add).\n-export([run/0, add/2]).\n-nifs([add/2]).\nrun() ->\n    First = erlang:load_nif(\"{}\", []),\n    Second = erlang:load_nif(\"{}\", []),\n    {{First, add(20, 22), Second}}.\nadd(_, _) -> erlang:nif_error(undef).\n",
        add.display(),
        add.display()
    );
    compile_beam(&erl, &dir, "nifdyn_add", &add_src);
    let missing_src = format!(
        "-module(nifdyn_missing_fn).\n-export([run/0]).\nrun() -> erlang:load_nif(\"{}\", []).\n",
        missing_fn.display()
    );
    compile_beam(&erl, &dir, "nifdyn_missing_fn", &missing_src);
    let plain_src = format!(
        "-module(nifdyn_plain).\n-export([run/0, plain/1]).\nrun() -> erlang:load_nif(\"{}\", []).\nplain(X) -> X.\n",
        plain.display()
    );
    compile_beam(&erl, &dir, "nifdyn_plain", &plain_src);
    let veto_src = format!(
        "-module(nifdyn_veto).\n-export([run/0, run_nif/0]).\n-nifs([run_nif/0]).\nrun() -> erlang:load_nif(\"{}\", []).\nrun_nif() -> erlang:nif_error(undef).\n",
        veto.display()
    );
    compile_beam(&erl, &dir, "nifdyn_veto", &veto_src);

    assert_same(&dir, &erl, "nifdyn_miss");
    assert_same(&dir, &erl, "nifdyn_badarg");
    assert_same(&dir, &erl, "nifdyn_dummy");
    assert_same(&dir, &erl, "nifdyn_add");
    assert_same(&dir, &erl, "nifdyn_missing_fn");
    assert_same(&dir, &erl, "nifdyn_plain");
    assert_same(&dir, &erl, "nifdyn_veto");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn crypto_hash_mac_random_match_erts() {
    let Ok(erl) = RefErl::start() else {
        eprintln!("erl unavailable; skipping crypto differential test");
        return;
    };
    assert_crypto_same(
        &erl,
        "nifdyn_crypto_hash_mac",
        r#"
            H0 = crypto:hash_init(sha256),
            H1 = crypto:hash_update(H0, <<"a">>),
            Hash = crypto:hash_final(crypto:hash_update(H1, [<<"b">>, [99]])),
            M0 = crypto:mac_init(hmac, sha256, <<"key">>),
            M1 = crypto:mac_update(M0, [<<"da">>, <<"ta">>]),
            Hmac = crypto:mac_final(M1),
            Cmac = crypto:mac(cmac, aes_128_cbc, <<0:128>>, <<"data">>),
            ok = crypto:rand_seed(<<"test-seed">>),
            RandomLength = byte_size(crypto:strong_rand_bytes(16)),
            Uniform = crypto:rand_uniform(5, 10),
            {Hash, Hmac, Cmac, RandomLength, Uniform >= 5 andalso Uniform < 10}
        "#,
    );
}

#[test]
fn crypto_cipher_stream_and_aead_match_erts() {
    let Ok(erl) = RefErl::start() else {
        eprintln!("erl unavailable; skipping crypto differential test");
        return;
    };
    assert_crypto_same(
        &erl,
        "nifdyn_crypto_cipher",
        r#"
            Key = <<0:128>>,
            Iv = <<0:128>>,
            State = crypto:crypto_init(aes_128_ctr, Key, Iv, true),
            Stream1 = crypto:crypto_update(State, [<<"stream-">>, [100,97,116,97]]),
            Stream2 = crypto:crypto_update(State, <<"next">>),
            StreamFinal = crypto:crypto_final(State),
            Ecb = crypto:crypto_one_time(aes_128_ecb, Key, <<"0123456789abcdef">>, true),
            {GcmCipher, GcmTag} = crypto:crypto_one_time_aead(aes_128_gcm, Key, <<0:96>>, <<"plain">>, <<"aad">>, true),
            GcmPlain = crypto:crypto_one_time_aead(aes_128_gcm, Key, <<0:96>>, GcmCipher, <<"aad">>, GcmTag, false),
            ChaChaKey = <<0:256>>,
            {ChaChaCipher, ChaChaTag} = crypto:crypto_one_time_aead(chacha20_poly1305, ChaChaKey, <<0:96>>, <<"plain">>, <<"aad">>, true),
            ChaChaPlain = crypto:crypto_one_time_aead(chacha20_poly1305, ChaChaKey, <<0:96>>, ChaChaCipher, <<"aad">>, ChaChaTag, false),
            {Stream1, Stream2, StreamFinal, Ecb, GcmPlain, ChaChaPlain}
        "#,
    );
}

#[test]
fn crypto_kdf_and_xor_match_erts() {
    let Ok(erl) = RefErl::start() else {
        eprintln!("erl unavailable; skipping crypto differential test");
        return;
    };
    assert_crypto_same(
        &erl,
        "nifdyn_crypto_kdf",
        r#"
            Derived = crypto:pbkdf2_hmac(sha256, <<"password">>, <<"salt">>, 101, 24),
            Xored = crypto:exor(<<1,2,3,4>>, <<4,3,2,1>>),
            {Derived, Xored}
        "#,
    );
}

#[test]
fn crypto_public_key_sign_verify_match_erts() {
    let Ok(erl) = RefErl::start() else {
        eprintln!("erl unavailable; skipping crypto differential test");
        return;
    };
    assert_crypto_same(
        &erl,
        "nifdyn_crypto_sign",
        r#"
            {RsaPublic, RsaPrivate} = crypto:generate_key(rsa, {512, 65537}),
            RsaSignature = crypto:sign(rsa, sha256, <<"message">>, RsaPrivate, []),
            RsaValid = crypto:verify(rsa, sha256, <<"message">>, RsaSignature, RsaPublic, []),
            {EcPublic, EcPrivate} = crypto:generate_key(ecdh, secp256r1),
            EcSignature = crypto:sign(ecdsa, sha256, <<"message">>, [EcPrivate, secp256r1]),
            EcValid = crypto:verify(ecdsa, sha256, <<"message">>, EcSignature, [EcPublic, secp256r1]),
            {RsaValid, EcValid, is_list(RsaPublic), byte_size(RsaSignature) > 0}
        "#,
    );
}

#[test]
fn crypto_ecdh_and_x25519_keygen_match_erts() {
    let Ok(erl) = RefErl::start() else {
        eprintln!("erl unavailable; skipping crypto differential test");
        return;
    };
    assert_crypto_same(
        &erl,
        "nifdyn_crypto_ecdh",
        r#"
            {APublic, APrivate} = crypto:generate_key(ecdh, secp256r1, <<1:256>>),
            {BPublic, BPrivate} = crypto:generate_key(ecdh, secp256r1, <<2:256>>),
            ASecret = crypto:compute_key(ecdh, BPublic, APrivate, secp256r1),
            BSecret = crypto:compute_key(ecdh, APublic, BPrivate, secp256r1),
            {XPublic, XPrivate} = crypto:generate_key(ecdh, x25519, <<1:256>>),
            {YPublic, YPrivate} = crypto:generate_key(ecdh, x25519, <<2:256>>),
            XSecret = crypto:compute_key(ecdh, YPublic, XPrivate, x25519),
            YSecret = crypto:compute_key(ecdh, XPublic, YPrivate, x25519),
            {byte_size(APublic), byte_size(BPublic), ASecret =:= BSecret,
             byte_size(XPublic), byte_size(YPublic), XSecret =:= YSecret}
        "#,
    );
}

#[test]
fn crypto_invalid_arguments_match_erts() {
    let Ok(erl) = RefErl::start() else {
        eprintln!("erl unavailable; skipping crypto differential test");
        return;
    };
    assert_crypto_same(
        &erl,
        "nifdyn_crypto_badarg",
        r#"
            BadDigest = try crypto:hash(no_such_digest, <<"data">>) of
                _ -> false
            catch
                error:_ -> true
            end,
            BadIolist = try crypto:hash(sha256, [256]) of
                _ -> false
            catch
                error:_ -> true
            end,
            {BadDigest, BadIolist}
        "#,
    );
}

#[test]
fn erl_tracer_enabled_and_trace_match_erts() {
    let Ok(erl) = RefErl::start() else {
        eprintln!("erl unavailable; skipping erl_tracer differential test");
        return;
    };
    let dir = work_dir("tracer");
    compile_beam(
        &erl,
        &dir,
        "nifdyn_tracer",
        r#"
        -module(nifdyn_tracer).
        -export([run/0]).
        run() ->
            Reload = reload(2),
            Me = self(),
            Dead = spawn(fun() -> ok end),
            spin(20000),
            DeadState = case erlang:is_process_alive(Dead) of
                true -> alive;
                false -> dead
            end,
            Other = spawn(fun() -> receive _ -> ok end end),
            EnabledAlive = erl_tracer:enabled(send, Other, Me),
            EnabledSame = erl_tracer:enabled(send, Me, Me),
            EnabledDeadStatus = erl_tracer:enabled(trace_status, Dead, Me),
            EnabledDeadSend = erl_tracer:enabled(send, Dead, Me),
            EnabledAtom = erl_tracer:enabled(send, not_a_pid, Me),
            EnabledAtomStatus = erl_tracer:enabled(trace_status, not_a_pid, Me),
            ok = erl_tracer:trace(send, Me, other, hello, #{}),
            Sent = receive M -> norm(M) end,
            ok = erl_tracer:trace(seq_trace, Me, 7, msg, #{}),
            Seq = receive M2 -> M2 end,
            ok = erl_tracer:trace(send, Me, other, msg, #{extra => more}),
            Extra = receive M3 -> norm_extra(M3) end,
            {Reload, DeadState, EnabledAlive, EnabledSame, EnabledDeadStatus,
             EnabledDeadSend, EnabledAtom, EnabledAtomStatus, Sent, Seq, Extra}.
        reload(0) -> failed;
        reload(N) ->
            try erl_tracer:on_load() of
                ok -> reload(N - 1)
            catch
                error:{case_clause, {error, {reload, Msg}}} -> Msg
            end.
        spin(0) -> ok;
        spin(N) -> spin(N - 1).
        norm({trace, _, Tag, Msg}) -> {trace, Tag, Msg};
        norm(Other) -> {bad, Other}.
        norm_extra({trace, _, Tag, Msg, Extra}) -> {trace, Tag, Msg, Extra};
        norm_extra(Other) -> {bad, Other}.
        "#,
    );
    assert_same(&dir, &erl, "nifdyn_tracer");
    let _ = std::fs::remove_dir_all(&dir);
}

/// OTP's `tracer_SUITE` tracer NIF (`tracer_test.c` and `tracer_test.erl`).
fn otp_tracer_test(erl: &RefErl, dir: &Path) {
    let suite = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/otp/erts/emulator/test");
    let source = std::fs::read_to_string(suite.join("tracer_SUITE_data/tracer_test.c"))
        .expect("tracer_test.c");
    compile_so(dir, "tracer_test", &source);
    // The module uses the preprocessor (`?MODULE`), so erlc compiles it.
    let status = Command::new("erlc")
        .arg("-o")
        .arg(dir)
        .arg(suite.join("tracer_test.erl"))
        .status()
        .expect("erlc");
    assert!(status.success(), "erlc tracer_test.erl");
    let bytes = std::fs::read(dir.join("tracer_test.beam")).expect("tracer_test.beam");
    erl.load("tracer_test", &bytes).unwrap();
}

// Port of erts/emulator/beam/erl_trace.c:1037-1160 and :1194-1240 (erts_call_trace and the
// return events), erl_nif.c:4744-4772 (erts_load_nif caller) and beam_bif_load.c:2254-2258
// (purge unloads the NIF library), OTP-29.1.1.
#[test]
fn tracer_module_return_trace_and_nif_reload_cycles_match_erts() {
    let Ok(erl) = RefErl::start() else {
        eprintln!("erl unavailable; skipping tracer module reload differential test");
        return;
    };
    let dir = work_dir("tracer_reload");
    otp_tracer_test(&erl, &dir);
    let source = format!(
        r#"
        -module(nifdyn_tracer_reload).
        -export([run/0, call_test/1]).
        run() ->
            Dir = "{}",
            true = code:add_patha(Dir),
            First = cycle(Dir),
            Calls = calls(),
            %% More load/purge cycles than the runtime has NIF trampolines.
            Cycles = lists:usort([cycle(Dir) || _ <- lists:seq(1, 100)]),
            Config = spawn(fun F() -> receive {{get, P}} -> P ! Dir, F() end end),
            register(tracer_test_config, Config),
            OnLoad = lists:usort([on_load_cycle() || _ <- lists:seq(1, 12)]),
            unregister(tracer_test_config),
            exit(Config, kill),
            purge(),
            {{First, Calls, Cycles, OnLoad}}.
        call_test(Arg) -> Arg.
        purge() ->
            case erlang:module_loaded(tracer_test) of
                true ->
                    code:purge(tracer_test),
                    true = code:delete(tracer_test),
                    code:purge(tracer_test);
                false -> ok
            end.
        status() ->
            try tracer_test:enabled(trace_status, self(), {{#{{}}, self(), []}})
            catch Class:_ -> Class
            end.
        cycle(Dir) ->
            purge(),
            Before = status(),
            Load = tracer_test:load(Dir),
            Tracee = spawn(fun() -> receive _ -> ok end end),
            Trace = try erlang:trace(Tracee, true, [procs, {{tracer, tracer_test, {{#{{}}, self(), []}}}}])
                    catch Class:Reason -> {{Class, Reason}}
                    end,
            exit(Tracee, kill),
            {{Before, Load, Trace}}.
        on_load_cycle() ->
            Autoloaded = status(),
            {{module, tracer_test}} = code:load_file(tracer_test),
            Reloaded = status(),
            false = code:purge(tracer_test),
            true = code:delete(tracer_test),
            false = code:purge(tracer_test),
            {{Autoloaded, Reloaded}}.
        calls() ->
            Self = self(),
            Tracee = spawn(fun F() -> receive A when is_function(A) -> A(), F() end end),
            1 = erlang:trace_pattern({{nifdyn_tracer_reload, call_test, 1}}, [{{'_', [], [{{return_trace}}]}}], [local]),
            Events = [begin
                          State = {{#{{call => Mode}}, Self, []}},
                          1 = erlang:trace(Tracee, true, [call, {{tracer, tracer_test, State}}]),
                          Tracee ! fun() -> call_test(Mode), Self ! done end,
                          receive done -> ok end,
                          Ref = erlang:trace_delivered(Tracee),
                          receive {{trace_delivered, Tracee, Ref}} -> ok end,
                          1 = erlang:trace(Tracee, false, [call]),
                          {{Mode, flush()}}
                      end || Mode <- [trace, discard]],
            erlang:trace_pattern({{nifdyn_tracer_reload, call_test, 1}}, false, [local]),
            exit(Tracee, kill),
            Events.
        flush() ->
            receive
                {{Tag, {{_, _, _}}, _, Data, Opts}} -> [{{Tag, Data, Opts}} | flush()]
            after 0 -> []
            end.
        "#,
        dir.display()
    );
    compile_beam(&erl, &dir, "nifdyn_tracer_reload", &source);
    similar_asserts::assert_eq!(
        scheduled_cli(&dir, "nifdyn_tracer_reload"),
        reference(&erl, "nifdyn_tracer_reload"),
        "nifdyn_tracer_reload:run/0"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// Port of erts/emulator/beam/erl_trace.c:3017-3060 and :3150-3260 (load_tracer_nif and
// send_to_tracer_nif), OTP-29.1.1: tracer callbacks resolve from the current module after reload.
#[test]
fn tracer_reload_uses_new_nif_callbacks_like_erts() {
    let Ok(erl) = RefErl::start() else {
        eprintln!("erl unavailable; skipping tracer NIF reload differential test");
        return;
    };
    let dir = work_dir("tracer_nif_callback_reload");
    for (version, marker) in [("v1", "old_nif"), ("v2", "new_nif")] {
        compile_so(
            &dir,
            &format!("nifdyn_tracer_pin_{version}"),
            &format!(
                r#"
                #include "erl_nif.h"
                static ERL_NIF_TERM enabled(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {{
                    (void)argc;
                    if (enif_is_identical(argv[0], enif_make_atom(env, "trace_status")))
                        return enif_make_atom(env, "trace");
                    return enif_make_atom(env, "discard");
                }}
                static ERL_NIF_TERM trace(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {{
                    ErlNifPid pid;
                    (void)argc;
                    if (enif_get_local_pid(env, argv[1], &pid)) {{
                        ERL_NIF_TERM message = enif_make_tuple4(
                            env, enif_make_atom(env, "{marker}"), enif_make_atom(env, "generic"),
                            argv[0], argv[3]);
                        enif_send(env, &pid, NULL, message);
                    }}
                    return enif_make_atom(env, "ok");
                }}
                static ERL_NIF_TERM enabled_send(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {{
                    (void)argc;
                    return enif_is_identical(argv[0], enif_make_atom(env, "send"))
                        ? enif_make_atom(env, "trace") : enif_make_atom(env, "discard");
                }}
                static ERL_NIF_TERM trace_send(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {{
                    ErlNifPid pid;
                    (void)argc;
                    if (enif_get_local_pid(env, argv[1], &pid)) {{
                        ERL_NIF_TERM message = enif_make_tuple4(
                            env, enif_make_atom(env, "{marker}"), enif_make_atom(env, "specialized"),
                            argv[0], argv[3]);
                        enif_send(env, &pid, NULL, message);
                    }}
                    return enif_make_atom(env, "ok");
                }}
                static ErlNifFunc funcs[] = {{
                    {{"enabled", 3, enabled, 0}}, {{"trace", 5, trace, 0}},
                    {{"enabled_send", 3, enabled_send, 0}}, {{"trace_send", 5, trace_send, 0}}
                }};
                static int upgrade(ErlNifEnv* env, void** priv, void** old_priv, ERL_NIF_TERM info) {{
                    (void)env; (void)priv; (void)old_priv; (void)info;
                    return 0;
                }}
                ERL_NIF_INIT(nifdyn_tracer_pin, funcs, NULL, NULL, upgrade, NULL)
                "#
            ),
        );
        let source = format!(
            r#"
            -module(nifdyn_tracer_pin).
            -on_load(load/0).
            -export([load/0, enabled/3, trace/5, enabled_send/3, trace_send/5]).
            -nifs([enabled/3, trace/5, enabled_send/3, trace_send/5]).
            load() -> erlang:load_nif("{}", []).
            enabled(_, _, _) -> erlang:nif_error(undef).
            trace(_, _, _, _, _) -> erlang:nif_error(undef).
            enabled_send(_, _, _) -> erlang:nif_error(undef).
            trace_send(_, _, _, _, _) -> erlang:nif_error(undef).
            "#,
            dir.join(format!("nifdyn_tracer_pin_{version}")).display()
        );
        let beam = erl
            .compile_named("nifdyn_tracer_pin", &source, &[])
            .unwrap_or_else(|error| panic!("compile tracer {version}: {error}"));
        std::fs::write(dir.join(format!("nifdyn_tracer_pin_{version}.beam")), beam).unwrap();
    }
    std::fs::copy(
        dir.join("nifdyn_tracer_pin_v2.beam"),
        dir.join("nifdyn_tracer_pin.beam"),
    )
    .unwrap();
    let runner = format!(
        r#"
            -module(nifdyn_tracer_pin_runner).
            -export([run/0]).
            run() ->
                V1 = {},
                {{module, nifdyn_tracer_pin}} = load(V1),
                Parent = self(),
                Session = trace:session_create(tracer_reload, {{nifdyn_tracer_pin, Parent}}, []),
                Tracee = spawn(fun Loop() -> receive Msg -> Parent ! Msg, Loop() end end),
                1 = trace:process(Session, Tracee, true, [send]),
                Tracee ! before_reload,
                Old = receive {{old_nif, specialized, send, before_reload}} -> old_nif after 1000 -> timeout end,
                V2 = {},
                {{module, nifdyn_tracer_pin}} = load(V2),
                Tracee ! after_reload,
                New = receive {{new_nif, specialized, send, after_reload}} -> new_nif after 1000 -> timeout end,
                exit(Tracee, kill),
                trace:session_destroy(Session),
                {{Old, New}}.
        load(Bin) ->
            Prepared = erlang:prepare_loading(nifdyn_tracer_pin, Bin),
            {{on_load, [nifdyn_tracer_pin]}} = erlang:finish_loading([Prepared]),
            ok = erlang:call_on_load_function(nifdyn_tracer_pin),
            true = erlang:finish_after_on_load(nifdyn_tracer_pin, true),
            {{module, nifdyn_tracer_pin}}.
        "#,
        byte_binary(&std::fs::read(dir.join("nifdyn_tracer_pin_v1.beam")).unwrap()),
        byte_binary(&std::fs::read(dir.join("nifdyn_tracer_pin_v2.beam")).unwrap())
    );
    compile_beam(&erl, &dir, "nifdyn_tracer_pin_runner", &runner);
    similar_asserts::assert_eq!(
        scheduled(&dir, "nifdyn_tracer_pin_runner"),
        reference(&erl, "nifdyn_tracer_pin_runner"),
        "tracer callbacks after NIF reload"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

fn byte_binary(bytes: &[u8]) -> String {
    format!(
        "<<{}>>",
        bytes
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn nif_api2_case(test_name: &str, body: &str) {
    let Ok(erl) = RefErl::start() else {
        eprintln!("erl unavailable; skipping {test_name}");
        return;
    };
    let dir = work_dir(test_name);
    let library = compile_so(
        &dir,
        test_name,
        &format!(
            r#"
            #include <stdint.h>
            #include "erl_nif.h"
            static ERL_NIF_TERM run(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {{
                (void)argc; (void)argv;
                {body}
            }}
            static ErlNifFunc funcs[] = {{ {{"go", 0, run, 0}} }};
            ERL_NIF_INIT({test_name}, funcs, NULL, NULL, NULL, NULL)
            "#
        ),
    );
    let source = format!(
        "-module({test_name}).\n-export([run/0, go/0]).\n-nifs([go/0]).\nrun() -> ok = erlang:load_nif(\"{}\", []), go().\ngo() -> erlang:nif_error(undef).\n",
        library.display()
    );
    compile_beam(&erl, &dir, test_name, &source);
    assert_same(&dir, &erl, test_name);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn nif_api2_type_predicates_match_erts() {
    nif_api2_case(
        "nif_api2_types",
        r#"
            ERL_NIF_TERM values[] = {
                enif_make_atom(env, "atom"), enif_make_ref(env),
                enif_make_tuple1(env, enif_make_int(env, 1)),
                enif_make_list1(env, enif_make_int(env, 2)),
                enif_make_new_map(env), enif_make_int(env, 3),
                enif_make_double(env, 1.5), enif_make_atom(env, "not_a_pid")
            };
            ERL_NIF_TERM rows[8];
            for (int i = 0; i < 8; i++) {
                rows[i] = enif_make_tuple2(env,
                    enif_make_int(env, enif_term_type(env, values[i])),
                    enif_make_int(env, enif_is_atom(env, values[i]) +
                        enif_is_fun(env, values[i]) + enif_is_list(env, values[i]) +
                        enif_is_map(env, values[i]) + enif_is_number(env, values[i]) +
                        enif_is_pid(env, values[i]) + enif_is_port(env, values[i]) +
                        enif_is_ref(env, values[i]) + enif_is_tuple(env, values[i])));
            }
            return enif_make_tuple_from_array(env, rows, 8);
        "#,
    );
}

#[test]
fn nif_api2_time_functions_match_erts() {
    nif_api2_case(
        "nif_api2_time",
        r#"
            ErlNifTime converted = enif_convert_time_unit(123456, ERL_NIF_MSEC,
                                                          ERL_NIF_USEC);
            ErlNifTime monotonic = enif_monotonic_time(ERL_NIF_MSEC);
            ErlNifTime offset = enif_time_offset(ERL_NIF_MSEC);
            return enif_make_tuple3(env, enif_make_int64(env, converted),
                enif_make_int(env, monotonic != INT64_MIN),
                enif_make_int(env, offset != INT64_MIN));
        "#,
    );
}

#[test]
fn nif_api2_format_and_sync_names_match_erts() {
    nif_api2_case(
        "nif_api2_format",
        r#"
            char buffer[128];
            int n = enif_snprintf(buffer, sizeof(buffer), "%d:%T", 7,
                                  enif_make_atom(env, "ok"));
            ErlNifMutex *mtx = enif_mutex_create("nif_api2_lock");
            if (!mtx) return enif_make_atom(env, "allocation_failed");
            ERL_NIF_TERM name = enif_make_string(env, enif_mutex_name(mtx), ERL_NIF_LATIN1);
            enif_mutex_lock(mtx);
            enif_mutex_unlock(mtx);
            enif_mutex_destroy(mtx);
            return enif_make_tuple2(env, enif_make_int(env, n), name);
        "#,
    );
}

#[test]
fn nif_api2_set_option_matches_erts() {
    let Ok(erl) = RefErl::start() else {
        eprintln!("erl unavailable; skipping nif_api2_set_option_matches_erts");
        return;
    };
    let dir = work_dir("nif_api2_set_option");
    let module = "nif_api2_set_option";
    let library = compile_so(
        &dir,
        module,
        r#"
        #include "erl_nif.h"
        #include <errno.h>
        static int options[7];
        static void on_halt(void *data) { (void)data; }
        static ERL_NIF_TERM go(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
            (void)argc; (void)argv;
            int *values = enif_priv_data(env);
            ERL_NIF_TERM result[7];
            for (int i = 0; i < 7; i++) result[i] = enif_make_int(env, values[i]);
            return enif_make_tuple_from_array(env, result, 7);
        }
        static int load(ErlNifEnv *env, void **priv, ERL_NIF_TERM info) {
            (void)info;
            options[0] = enif_set_option(env, ERL_NIF_OPT_DELAY_HALT);
            options[1] = enif_set_option(env, ERL_NIF_OPT_DELAY_HALT);
            options[2] = enif_set_option(env, ERL_NIF_OPT_ON_HALT, on_halt);
            options[3] = enif_set_option(env, ERL_NIF_OPT_ON_HALT, on_halt);
            options[4] = enif_set_option(env, ERL_NIF_OPT_ON_UNLOAD_THREAD, on_halt);
            options[5] = enif_set_option(env, ERL_NIF_OPT_ON_UNLOAD_THREAD, on_halt);
            options[6] = enif_set_option(env, (ErlNifOption)99);
            *priv = options;
            return 0;
        }
        static ErlNifFunc funcs[] = {{"go", 0, go, 0}};
        ERL_NIF_INIT(nif_api2_set_option, funcs, load, NULL, NULL, NULL)
        "#,
    );
    let source = format!(
        "-module({module}).\n-export([run/0, go/0]).\n-nifs([go/0]).\nrun() -> ok = erlang:load_nif(\"{}\", []), go().\ngo() -> erlang:nif_error(undef).\n",
        library.display()
    );
    compile_beam(&erl, &dir, module, &source);
    assert_same(&dir, &erl, module);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn nif_api2_halt_callback_and_delay_match_erts() {
    let Ok(erl) = RefErl::start() else {
        eprintln!("erl unavailable; skipping nif_api2_halt_callback_and_delay_match_erts");
        return;
    };
    let dir = work_dir("nif_api2_halt");
    let module = "nif_api2_halt";
    let marker = dir.join("events.log");
    let marker_literal = marker
        .to_string_lossy()
        .replace('\\', "\\\\")
        .replace('"', "\\\"");
    let library = compile_so(
        &dir,
        module,
        &format!(
            r#"
            #include "erl_nif.h"
            #include <stdio.h>
            #include <time.h>
            static const char *path = "{marker_literal}";
            static void record(const char *event) {{
                FILE *file = fopen(path, "a");
                if (file) {{ fprintf(file, "%s\n", event); fclose(file); }}
            }}
            static void on_halt(void *data) {{ (void)data; record("on_halt"); }}
            static ERL_NIF_TERM slow(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {{
                (void)argc; (void)argv;
                struct timespec delay = {{0, 150000000}};
                record("call_start");
                nanosleep(&delay, NULL);
                record("call_done");
                return enif_make_atom(env, "ok");
            }}
            static int load(ErlNifEnv *env, void **priv, ERL_NIF_TERM info) {{
                (void)priv; (void)info;
                if (enif_set_option(env, ERL_NIF_OPT_DELAY_HALT) != 0) return 1;
                return enif_set_option(env, ERL_NIF_OPT_ON_HALT, on_halt) != 0;
            }}
            static ErlNifFunc funcs[] = {{
                {{"slow", 0, slow, ERL_NIF_DIRTY_JOB_CPU_BOUND}}
            }};
            ERL_NIF_INIT({module}, funcs, load, NULL, NULL, NULL)
            "#
        ),
    );
    let source = format!(
        "-module({module}).\n-export([run/0, slow/0]).\n-nifs([slow/0]).\nrun() -> ok = erlang:load_nif(\"{}\", []), spawn(fun() -> slow() end), receive after 20 -> erlang:halt(0, []) end.\nslow() -> erlang:nif_error(undef).\n",
        library.display()
    );
    compile_beam(&erl, &dir, module, &source);

    let run_child = |program: &str, args: &[&str], label: &str| {
        let output = Command::new("timeout")
            .arg("10")
            .arg(program)
            .args(args)
            .output()
            .unwrap_or_else(|error| panic!("start {label}: {error}"));
        assert!(
            output.status.success(),
            "{label} exited with {}: {}{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        std::fs::read_to_string(&marker).unwrap_or_default()
    };
    let expected = run_child(
        "erl",
        &[
            "+S",
            "2:2",
            "-noshell",
            "-pa",
            dir.to_str().unwrap(),
            "-eval",
            &format!("{module}:run()."),
        ],
        "erl halt child",
    );
    let _ = std::fs::remove_file(&marker);
    let arinsal = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/arinsal");
    let actual = run_child(
        arinsal.to_str().unwrap(),
        &[
            "+S",
            "2:2",
            "-noshell",
            "-pa",
            dir.to_str().unwrap(),
            "-eval",
            &format!("{module}:run()."),
        ],
        "Arinsal halt child",
    );
    let mut actual_events: Vec<_> = actual.lines().collect();
    let mut expected_events: Vec<_> = expected.lines().collect();
    actual_events.sort_unstable();
    expected_events.sort_unstable();
    similar_asserts::assert_eq!(
        actual_events,
        expected_events,
        "NIF halt events differ from erl"
    );
    assert!(
        expected.contains("call_start\n"),
        "missing NIF call: {expected:?}"
    );
    assert!(
        expected.contains("call_done\n"),
        "missing completed NIF call: {expected:?}"
    );
    assert!(
        expected.contains("on_halt\n"),
        "missing on-halt callback: {expected:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// `enif_self`, `enif_send` and `enif_whereis_pid` from a scheduler and from a NIF-created
/// thread: the caller identity a NIF sees is the process currently running on its scheduler.
#[test]
fn nif_thread_send_whereis_and_self_match_erts() {
    let Ok(erl) = RefErl::start() else {
        eprintln!("erl unavailable; skipping NIF thread send differential test");
        return;
    };
    let dir = work_dir("thread_send");
    compile_so(
        &dir,
        "nifthr",
        r#"
        #include "erl_nif.h"
        typedef struct { ErlNifPid to; ERL_NIF_TERM name; ErlNifEnv* env; int sent; } job_t;
        static ERL_NIF_TERM self_pid(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
            ErlNifPid pid;
            (void)argc; (void)argv;
            if (!enif_self(env, &pid)) return enif_make_atom(env, "no_self");
            return enif_make_pid(env, &pid);
        }
        static ERL_NIF_TERM env_send(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
            ErlNifPid to, me;
            ErlNifEnv* msg_env = enif_alloc_env();
            ERL_NIF_TERM msg;
            int sent;
            (void)argc;
            if (!enif_get_local_pid(env, argv[0], &to) || !enif_self(env, &me))
                return enif_make_badarg(env);
            msg = enif_make_tuple2(msg_env, enif_make_atom(msg_env, "from_env"),
                                   enif_make_pid(msg_env, &me));
            sent = enif_send(env, &to, msg_env, msg);
            enif_free_env(msg_env);
            return sent ? enif_make_atom(env, "ok") : enif_make_atom(env, "not_sent");
        }
        static void* thread_main(void* arg) {
            job_t* job = (job_t*)arg;
            ErlNifPid found;
            ErlNifEnv* msg_env = enif_alloc_env();
            ERL_NIF_TERM name = enif_make_copy(msg_env, job->name);
            int known = enif_whereis_pid(NULL, name, &found);
            ERL_NIF_TERM same = (known && enif_compare(enif_make_pid(msg_env, &found),
                                                      enif_make_pid(msg_env, &job->to)) == 0)
                ? enif_make_atom(msg_env, "true") : enif_make_atom(msg_env, "false");
            ERL_NIF_TERM msg = enif_make_tuple3(msg_env, enif_make_atom(msg_env, "from_thread"),
                enif_make_atom(msg_env, known ? "known" : "unknown"), same);
            job->sent = enif_send(NULL, &job->to, msg_env, msg);
            enif_free_env(msg_env);
            return NULL;
        }
        static ERL_NIF_TERM thread_send(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
            job_t job;
            ErlNifTid tid;
            (void)argc;
            if (!enif_get_local_pid(env, argv[0], &job.to)) return enif_make_badarg(env);
            job.env = enif_alloc_env();
            job.name = enif_make_copy(job.env, argv[1]);
            job.sent = 0;
            if (enif_thread_create("nifthr", &tid, thread_main, &job, NULL) != 0)
                return enif_make_atom(env, "no_thread");
            enif_thread_join(tid, NULL);
            enif_free_env(job.env);
            return job.sent ? enif_make_atom(env, "ok") : enif_make_atom(env, "not_sent");
        }
        static ErlNifFunc funcs[] = {
            {"self_pid", 0, self_pid, 0},
            {"env_send", 1, env_send, 0},
            {"thread_send", 2, thread_send, 0}};
        ERL_NIF_INIT(nifthr, funcs, NULL, NULL, NULL, NULL)
        "#,
    );
    let source = format!(
        r#"-module(nifthr).
        -export([run/0, self_pid/0, env_send/1, thread_send/2]).
        -nifs([self_pid/0, env_send/1, thread_send/2]).
        self_pid() -> erlang:nif_error(not_loaded).
        env_send(_) -> erlang:nif_error(not_loaded).
        thread_send(_, _) -> erlang:nif_error(not_loaded).
        recv() -> receive M -> M after 2000 -> timeout end.
        run() ->
            ok = erlang:load_nif("{}", 0),
            Parent = self(),
            SelfOk = self_pid() =:= Parent,
            true = register(nifthr_target, Parent),
            Sent = thread_send(Parent, nifthr_target),
            FromThread = recv(),
            Missing = thread_send(Parent, nifthr_no_such_name),
            FromThread2 = recv(),
            %% Processes taking turns on the schedulers each see themselves as the caller.
            Workers = [spawn(fun() ->
                           Me = self(),
                           Me = self_pid(),
                           ok = env_send(Parent),
                           ok = thread_send(Parent, nifthr_target),
                           erlang:yield(),
                           Parent ! {{worker, Me, self_pid() =:= Me}}
                       end) || _ <- lists:seq(1, 8)],
            Results = [receive {{worker, W, Same}} -> Same after 2000 -> timeout end
                       || W <- Workers],
            FromEnv = [receive {{from_env, W}} -> W after 2000 -> timeout end || W <- Workers],
            Threads = [recv() || _ <- Workers],
            unregister(nifthr_target),
            {{SelfOk, Sent, FromThread, Missing, FromThread2, Results, FromEnv =:= Workers, Threads}}."#,
        dir.join("nifthr").display()
    );
    compile_beam(&erl, &dir, "nifthr", &source);
    assert_same(&dir, &erl, "nifthr");
    let _ = std::fs::remove_dir_all(&dir);
}

// Port of erts/emulator/beam/erl_term.h (erts_write_heap_filler) and beam_common.c
// (save_stacktrace sizes its block exactly), OTP-29.1.1: a raise whose saved stacktrace
// outgrew the estimated block left an uninitialized gap in the young heap, which the linear
// heap scan of the next code purge (`check_process_code`) read as a header ("invalid boxed
// subtag"). Every cycle raises `nif_error` and purges the module it came from.
#[test]
fn raise_stacktrace_block_tail_is_walkable_by_purge_scan() {
    let dir = work_dir("stacktrace_filler");
    for (module, source) in [
        (
            "nifdyn_filler_raiser",
            "-module(nifdyn_filler_raiser).\n-export([f/3]).\n\
             f(_, _, _) -> erlang:nif_error(nif_not_loaded).\n",
        ),
        (
            "nifdyn_filler_run",
            "-module(nifdyn_filler_run).\n-export([run/0]).\n\
             run() ->\n\
                 {_, Beam, File} = code:get_object_code(nifdyn_filler_raiser),\n\
                 [begin\n\
                      try nifdyn_filler_raiser:f(trace_status, self(), {#{}, self(), []})\n\
                      catch C:_ -> C end,\n\
                      code:purge(nifdyn_filler_raiser),\n\
                      code:delete(nifdyn_filler_raiser),\n\
                      code:purge(nifdyn_filler_raiser),\n\
                      {module, nifdyn_filler_raiser} =\n\
                          code:load_binary(nifdyn_filler_raiser, File, Beam)\n\
                  end || _ <- lists:seq(1, 300)],\n\
                 ok.\n",
        ),
    ] {
        let path = dir.join(format!("{module}.erl"));
        std::fs::write(&path, source).unwrap();
        let status = Command::new("erlc")
            .arg("-o")
            .arg(&dir)
            .arg(&path)
            .status()
            .expect("erlc");
        assert!(status.success(), "erlc {module}");
    }
    similar_asserts::assert_eq!(
        scheduled_cli(&dir, "nifdyn_filler_run"),
        OwnedTerm::atom("ok")
    );
    let _ = std::fs::remove_dir_all(&dir);
}
