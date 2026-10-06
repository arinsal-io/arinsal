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
    assert_eq!(actual, expected, "{module}:run/0");
}

fn assert_crypto_same(erl: &RefErl, name: &str, body: &str) {
    let dir = work_dir(name);
    let source = format!(
        "-module({name}).\n-export([run/0]).\nrun() ->\n    {{module, crypto}} = code:ensure_loaded(crypto),\n    {body}.\n"
    );
    compile_beam(erl, &dir, name, &source);
    assert_eq!(
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
    assert_eq!(actual, expected, "{test_name}:run/0");
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
    assert_eq!(
        actual_events, expected_events,
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
