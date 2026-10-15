//! Adversarial end-to-end suite: two tenants A and B plus root. Tenant B owns a victim process
//! (registered name, ETS tables, persistent term, a module only loaded in its code domain) and
//! root owns a canary with the same kinds of state. A process of A attacks; afterwards the victim
//! and the canary must have seen nothing and still hold their state. One test per attack, so the
//! isolation gate prints one row each.
//!
//! The victim reports through `Coll`, a root process exposed to every namespace, because a
//! namespace process cannot message an unshared root process. The attacks skip `Coll`.

use arinsal_difftest::RefErl;
use arinsal_etf::OwnedTerm;
use arinsal_vm::Vm;
use std::sync::Mutex;

static TEST_LOCK: Mutex<()> = Mutex::new(());

const B_ONLY: &str = "-module(b_only).\n-export([f/0]).\nf() -> b_secret_mod.\n";

const SOURCE: &str = r#"
-module(ns_attack_t).
-compile([export_all, nowarn_export_all]).

%% Servers --------------------------------------------------------------------------------

coll(Me) -> receive M -> Me ! M, coll(Me) end.

victim(Coll) ->
    process_flag(trap_exit, true),
    true = register(b_svc, self()),
    b_tab = ets:new(b_tab, [named_table, public]),
    true = ets:insert(b_tab, {secret, 42}),
    Priv = ets:new(b_priv, [public]),
    true = ets:insert(Priv, {secret, 43}),
    put(priv, Priv),
    ok = persistent_term:put(b_secret, b),
    Mod = (dyn_mod()):f(),
    Coll ! {victim_ready, self(), Priv},
    victim_loop(Coll, [], group_leader(), Mod).

victim_loop(Coll, Seen, GL, Mod) ->
    receive
        {report, Ref} ->
            {links, Links} = process_info(self(), links),
            {monitored_by, MonBy} = process_info(self(), monitored_by),
            Coll ! {report, Ref, #{
                seen => lists:reverse(Seen),
                tab => ets:lookup(b_tab, secret),
                priv => ets:tab2list(get(priv)),
                pterm => persistent_term:get(b_secret, gone),
                gl_same => group_leader() =:= GL,
                mod => Mod,
                links => Links,
                monitored_by => MonBy,
                named => whereis(b_svc) =:= self()}},
            victim_loop(Coll, Seen, GL, Mod);
        Other ->
            victim_loop(Coll, [Other | Seen], GL, Mod)
    end.

canary(Me) ->
    process_flag(trap_exit, true),
    true = register(root_svc, self()),
    root_tab = ets:new(root_tab, [named_table, public]),
    true = ets:insert(root_tab, {secret, 1}),
    ok = persistent_term:put(root_secret, r),
    canary_loop(Me, []).

canary_loop(Me, Seen) ->
    receive
        {report, Ref} ->
            Me ! {canary_report, Ref, #{
                seen => lists:reverse(Seen),
                tab => ets:lookup(root_tab, secret),
                pterm => persistent_term:get(root_secret, gone)}},
            canary_loop(Me, Seen);
        Other ->
            canary_loop(Me, [Other | Seen])
    end.

%% The module is named at run time, so the call resolves through the process's code chain.
dyn_mod() -> list_to_atom(lists:flatten("b_" ++ "only")).

shared_svc() ->
    process_flag(trap_exit, true),
    true = register(shared_svc, self()),
    shared_loop(self(), []).

shared_loop(Me, Seen) ->
    receive
        {svc_report, From, Ref} -> From ! {svc_report, Ref, lists:reverse(Seen)}, shared_loop(Me, Seen);
        Other -> shared_loop(Me, [Other | Seen])
    end.

%% Harness --------------------------------------------------------------------------------

wrapper(Fun) ->
    receive go -> ok end,
    exit({r, Fun()}).

start_in(Ns, Fun) ->
    P = arinsal_ns:spawn(Ns, ns_attack_t, wrapper, [Fun]),
    Ref = erlang:monitor(process, P),
    {P, Ref}.

go({P, _Ref} = H) -> P ! go, H.

await({P, Ref}) ->
    receive
        {'DOWN', Ref, process, P, {r, R}} -> R;
        {'DOWN', Ref, process, P, Other} -> {crashed, Other}
    after 10000 -> timeout
    end.

in_ns(Ns, Fun) -> await(go(start_in(Ns, Fun))).

setup(AOpts) ->
    Me = self(),
    process_flag(trap_exit, true),
    true = os:putenv("ARL_ATTACK_ROOT_SECRET", "root-only"),
    Coll = spawn(fun() -> coll(Me) end),
    ok = arinsal_ns:expose(Coll),
    Canary = spawn(fun() -> canary(Me) end),
    Svc = spawn(fun() -> shared_svc() end),
    ok = arinsal_ns:expose(Svc),
    {ok, B} = arinsal_ns:create(<<"b">>, <<"p">>, #{}),
    #{code_chain := [Own | _]} = arinsal_ns:info(B),
    ok = arinsal_code:load(Own, [{b_only, beam_b()}]),
    {ok, A} = arinsal_ns:create(<<"a">>, <<"p">>, AOpts),
    Victim = arinsal_ns:spawn(B, ns_attack_t, victim, [Coll]),
    VRef = erlang:monitor(process, Victim),
    Priv = receive
        {victim_ready, Victim, P} -> P;
        {'DOWN', VRef, process, Victim, Why} -> exit({victim_died, Why})
    after 5000 -> exit(victim_not_ready)
    end,
    erlang:demonitor(VRef, [flush]),
    %% Registered root processes are system services; the guessing attacks leave them alone.
    Skip = [P0 || P0 <- processes(), P0 =/= Me, P0 =/= Canary, P0 =/= Victim],
    #{me => Me, coll => Coll, canary => Canary, svc => Svc, skip => Skip, a => A, b => B, victim => Victim, priv => Priv,
      schedulers_online => erlang:system_info(schedulers_online)}.

clean(#{victim := V, canary := C, b := B, schedulers_online := Sched}) ->
    R = make_ref(),
    V ! {report, R},
    VS = receive {report, R, S} -> S after 3000 -> victim_dead end,
    C ! {report, R},
    CS = receive {canary_report, R, S2} -> S2 after 3000 -> canary_dead end,
    BProcs = maps:get(processes, arinsal_ns:info(B)),
    Env = os:getenv("ARL_ATTACK_ROOT_SECRET"),
    Want = #{seen => [], tab => [{secret, 42}], priv => [{secret, 43}], pterm => b, gl_same => true,
             mod => b_secret_mod, links => [], monitored_by => [], named => true},
    WantC = #{seen => [], tab => [{secret, 1}], pterm => r},
    Stray = receive M -> {stray, M} after 0 -> none end,
    case {VS, CS, BProcs, Env, erlang:system_info(schedulers_online), Stray} of
        {Want, WantC, 1, "root-only", Sched, none} -> ok;
        Other -> {unclean, Other}
    end.

finish(Ctx, Res, Pred) ->
    Clean = clean(Ctx),
    case {Pred(Res), Clean} of
        {true, ok} -> ok;
        _ -> {bad, Res, Clean}
    end.

no_leaks(Res) -> Res =:= [].

probes(List) -> [Name || {Name, true} <- List].

is_exit({'EXIT', _}) -> true;
is_exit(_) -> false.

%% Attacks --------------------------------------------------------------------------------

guess_pids(Victim) ->
    "<0." ++ Rest = pid_to_list(Victim),
    [NS, SS0] = string:tokens(Rest, "."),
    N = list_to_integer(NS),
    S = lists:takewhile(fun(C) -> C =/= $> end, SS0),
    Max = N + 300,
    [P || I <- lists:seq(0, Max),
          S2 <- lists:usort([S, "0"]),
          P <- [try list_to_pid("<0." ++ integer_to_list(I) ++ "." ++ S2 ++ ">") catch _:_ -> none end],
          P =/= none].

guess_attack(Op) ->
    Ctx = #{victim := V, skip := Skip} = setup(#{}),
    Res = in_ns(maps:get(a, Ctx), fun() ->
        process_flag(trap_exit, true),
        Pids = [P || P <- guess_pids(V), P =/= self(), not lists:member(P, Skip)],
        lists:foreach(fun(P) ->
            catch case Op of
                send -> P ! attack;
                link -> link(P);
                monitor -> erlang:monitor(process, P);
                exit_die -> exit(P, die);
                exit_kill -> exit(P, kill)
            end
        end, Pids),
        lists:member(V, Pids)
    end),
    finish(Ctx, Res, fun(R) -> R =:= true end).

ns_attack_pid_guess_send() -> guess_attack(send).
ns_attack_pid_guess_link() -> guess_attack(link).
ns_attack_pid_guess_monitor() -> guess_attack(monitor).
ns_attack_pid_guess_exit_die() -> guess_attack(exit_die).
ns_attack_pid_guess_exit_kill() -> guess_attack(exit_kill).

ns_attack_real_pid_ops() ->
    Ctx = #{victim := V} = setup(#{}),
    Res = in_ns(maps:get(a, Ctx), fun() ->
        process_flag(trap_exit, true),
        V ! attack,
        Link = catch link(V),
        LinkDown = receive {'EXIT', V, Why0} -> Why0 after 1000 -> established end,
        Mon = erlang:monitor(process, V),
        Down = receive {'DOWN', Mon, process, V, Why} -> Why after 2000 -> alive end,
        Info = timed(fun() -> process_info(V, [links, status]) end),
        probes([
            {link_established, LinkDown =:= established},
            {monitor_attached, Down =:= alive},
            {process_info, is_list(Info) orelse (is_tuple(Info) andalso not is_exit(Info) andalso Info =/= timeout)},
            {register, (catch register(stolen, V)) =:= true},
            {suspend, (catch erlang:suspend_process(V)) =:= true},
            {leader, (catch group_leader(self(), V)) =:= true andalso false},
            {exit_normal, begin catch exit(V, normal), false end},
            {exit_kill, begin catch exit(V, kill), false end}
        ])
    end),
    finish(Ctx, Res, fun no_leaks/1).

leaked(Fun) ->
    {P, Ref} = spawn_monitor(fun() -> exit({r, catch Fun()}) end),
    receive
        {'DOWN', Ref, process, P, {r, R}} -> not is_exit(R);
        {'DOWN', Ref, process, P, _} -> false
    after 5000 -> true
    end.

timed(Fun) ->
    Me = self(),
    Pid = spawn(fun() -> Me ! {timed, self(), catch Fun()} end),
    receive {timed, Pid, R} -> R after 3000 -> timeout end.

ns_attack_registry() ->
    Ctx = #{priv := Priv} = setup(#{}),
    Res = in_ns(maps:get(a, Ctx), fun() ->
        All = ets:all(),
        probes([
            {whereis_b, whereis(b_svc) =/= undefined},
            {whereis_root, whereis(root_svc) =/= undefined},
            {registered_b, lists:member(b_svc, registered())},
            {registered_root, lists:member(root_svc, registered())},
            {send_named_b, (catch (b_svc ! x)) =:= x},
            {send_named_root, (catch (root_svc ! x)) =:= x},
            {ets_all_b, lists:member(b_tab, All) orelse lists:member(Priv, All)},
            {ets_all_root, lists:member(root_tab, All)},
            {ets_lookup_named_b, not is_exit(catch ets:lookup(b_tab, secret))},
            {ets_lookup_named_root, not is_exit(catch ets:lookup(root_tab, secret))},
            {ets_lookup_tid_b, not is_exit(catch ets:lookup(Priv, secret))},
            {ets_insert_tid_b, not is_exit(catch ets:insert(Priv, {secret, 666}))},
            {ets_delete_tid_b, not is_exit(catch ets:delete(Priv))},
            {ets_delete_named_b, not is_exit(catch ets:delete(b_tab))},
            {ets_info_tid_b, ets:info(Priv) =/= undefined},
            {ets_whereis_b, ets:whereis(b_tab) =/= undefined},
            {ets_giveaway_tid_b, not is_exit(catch ets:give_away(Priv, self(), x))}
        ])
    end),
    finish(Ctx, Res, fun no_leaks/1).

ns_attack_persistent_term() ->
    Ctx = setup(#{}),
    Res = in_ns(maps:get(a, Ctx), fun() ->
        Keys = [K || {K, _} <- persistent_term:get()],
        probes([
            {get_b, persistent_term:get(b_secret, none) =/= none},
            {get_root, persistent_term:get(root_secret, none) =/= none},
            {get_all_b, lists:member(b_secret, Keys)},
            {get_all_root, lists:member(root_secret, Keys)},
            {erase_b, persistent_term:erase(b_secret)},
            {erase_root, persistent_term:erase(root_secret)},
            {put_overwrites, begin persistent_term:put(b_secret, evil), false end}
        ])
    end),
    finish(Ctx, Res, fun no_leaks/1).

ns_attack_os_env() ->
    Ctx = setup(#{}),
    Res = in_ns(maps:get(a, Ctx), fun() ->
        probes([
            {getenv, os:getenv("ARL_ATTACK_ROOT_SECRET") =/= false},
            {env_list, lists:keymember("ARL_ATTACK_ROOT_SECRET", 1, os:env())},
            {putenv_reaches_root, begin os:putenv("ARL_ATTACK_ROOT_SECRET", "evil"), false end},
            {unsetenv_reaches_root, begin os:unsetenv("ARL_ATTACK_ROOT_SECRET"), false end}
        ])
    end),
    finish(Ctx, Res, fun no_leaks/1).

ns_attack_foreign_module() ->
    Ctx = setup(#{}),
    Res = in_ns(maps:get(a, Ctx), fun() ->
        BMod = dyn_mod(),
        Mon = spawn_monitor(BMod, f, []),
        SpawnExit = case Mon of {Pid, Ref} -> receive {'DOWN', Ref, process, Pid, R} -> R after 2000 -> timeout end end,
        M = BMod,
        probes([
            {apply, (catch apply(BMod, f, [])) =:= b_secret_mod},
            {dynamic_call, (catch M:f()) =:= b_secret_mod},
            {spawn_ran, SpawnExit =:= normal},
            {ensure_loaded, (catch code:ensure_loaded(BMod)) =:= {module, BMod}},
            {module_loaded, erlang:module_loaded(BMod)},
            {function_exported, erlang:function_exported(BMod, f, 0)}
        ])
    end),
    finish(Ctx, Res, fun no_leaks/1).

ns_attack_shared_service() ->
    Ctx = #{svc := Svc} = setup(#{}),
    Res = in_ns(maps:get(a, Ctx), fun() ->
        P = whereis(shared_svc),
        P ! legit,
        _ = catch link(P),
        _ = catch exit(P, kill),
        _ = catch exit(P, shutdown),
        P =:= Svc
    end),
    timer_wait(),
    R = make_ref(),
    Svc ! {svc_report, self(), R},
    Seen = receive {svc_report, R, S} -> S after 2000 -> service_dead end,
    finish(Ctx, {Res, Seen}, fun({true, [legit]}) -> true; (_) -> false end).

timer_wait() -> receive after 300 -> ok end.

ns_attack_system_flag() ->
    Ctx = setup(#{}),
    Res = in_ns(maps:get(a, Ctx), fun() ->
        probes([
            {schedulers_online, not is_exit(catch erlang:system_flag(schedulers_online, 1))},
            {multi_scheduling, not is_exit(catch erlang:system_flag(multi_scheduling, block))}
        ])
    end),
    finish(Ctx, Res, fun no_leaks/1).

ns_attack_open_port() ->
    Ctx = setup(#{}),
    Res = in_ns(maps:get(a, Ctx), fun() ->
        probes([
            {spawn, not is_exit(catch open_port({spawn, "echo attack"}, []))},
            {spawn_executable, not is_exit(catch open_port({spawn_executable, "/bin/echo"}, [{args, ["attack"]}]))},
            {ports, leaked(fun() -> erlang:ports() end)}
        ])
    end),
    finish(Ctx, Res, fun no_leaks/1).

ns_attack_trace() ->
    Ctx = #{victim := V} = setup(#{}),
    Res = in_ns(maps:get(a, Ctx), fun() ->
        probes([
            {trace_self, not is_exit(catch erlang:trace(self(), true, [call]))},
            {trace_victim, not is_exit(catch erlang:trace(V, true, [send, receive_event]))},
            {trace_all, not is_exit(catch erlang:trace(all, true, [procs]))},
            {trace_pattern, not is_exit(catch erlang:trace_pattern({lists, '_', '_'}, true, []))}
        ])
    end),
    finish(Ctx, Res, fun no_leaks/1).

ns_attack_load_nif() ->
    Ctx = setup(#{}),
    Res = in_ns(maps:get(a, Ctx), fun() ->
        probes([{load_nif, not is_exit(catch erlang:load_nif("/nonexistent/arl_attack", 0))}])
    end),
    finish(Ctx, Res, fun no_leaks/1).

ns_attack_halt() ->
    Ctx = #{a := A} = setup(#{}),
    Res = in_ns(A, fun() -> erlang:halt(), survived end),
    Gone = not lists:member(A, arinsal_ns:list()),
    finish(Ctx, Res, fun(R) -> R =:= {crashed, killed} andalso Gone end).

ns_attack_init_stop() ->
    Ctx = #{a := A} = setup(#{}),
    Res = in_ns(A, fun() -> catch init:stop(), receive after 500 -> survived end end),
    case Res of
        survived -> finish(Ctx, Res, fun(_) -> true end);
        _ -> finish(Ctx, Res, fun(R) -> R =:= {crashed, killed} end)
    end.

ns_attack_spawn_bomb() ->
    Ctx = setup(#{max_processes => 50}),
    Res = in_ns(maps:get(a, Ctx), fun() ->
        Pids = [catch spawn(fun() -> receive stop -> ok end end) || _ <- lists:seq(1, 500)],
        Ok = length([P || P <- Pids, is_pid(P)]),
        Errors = lists:usort([element(1, E) || {'EXIT', E} <- Pids]),
        {Ok, Errors}
    end),
    BOk = in_ns(maps:get(b, Ctx), fun() -> is_pid(spawn(fun() -> ok end)) end),
    RootOk = is_pid(spawn(fun() -> ok end)),
    ClusterAfter = case Res of
        {Ok, [system_limit]} when Ok > 0, Ok =< 50 -> true;
        _ -> false
    end,
    case {ClusterAfter, BOk, RootOk} of
        {true, true, true} -> finish_spawn(Ctx);
        Other -> {bad, Res, Other}
    end.

finish_spawn(Ctx) ->
    Clean = clean(Ctx),
    case Clean of
        {unclean, {S, C, BProcs, E, Sched}} when BProcs =:= 1 -> {bad, S, C, E, Sched};
        Other -> Other
    end.

ns_attack_memory_bomb() ->
    Ctx = #{a := A} = setup(#{max_bytes => 2000000}),
    Res = in_ns(A, fun() ->
        L = lists:seq(1, 1000000),
        erlang:garbage_collect(),
        receive never -> L end
    end),
    Gone = not lists:member(A, arinsal_ns:list()),
    finish(Ctx, Res, fun(R) -> R =:= {crashed, killed} andalso Gone end).


ns_attack_group_leader() ->
    Ctx = #{victim := V} = setup(#{}),
    Res = in_ns(maps:get(a, Ctx), fun() ->
        Own = group_leader(),
        Set = catch group_leader(V, self()),
        _ = catch io:format("attack~n"),
        Steal = catch group_leader(self(), V),
        probes([
            {leader_is_victim, group_leader() =:= V},
            {set_returned_true_and_took_effect, Set =:= true andalso group_leader() =:= V},
            {steal_returned_true, Steal =:= true andalso false},
            {own_lost, group_leader() =/= Own andalso group_leader() =/= V andalso false}
        ])
    end),
    finish(Ctx, Res, fun no_leaks/1).
"#;

const ATTACKS: &[&str] = &[
    "ns_attack_shared_service",
    "ns_attack_pid_guess_send",
    "ns_attack_pid_guess_link",
    "ns_attack_pid_guess_monitor",
    "ns_attack_pid_guess_exit_die",
    "ns_attack_pid_guess_exit_kill",
    "ns_attack_real_pid_ops",
    "ns_attack_registry",
    "ns_attack_persistent_term",
    "ns_attack_os_env",
    "ns_attack_foreign_module",
    "ns_attack_system_flag",
    "ns_attack_open_port",
    "ns_attack_trace",
    "ns_attack_load_nif",
    "ns_attack_halt",
    "ns_attack_init_stop",
    "ns_attack_spawn_bomb",
    "ns_attack_memory_bomb",
    "ns_attack_group_leader",
];

/// An Erlang binary literal of `bytes`.
fn binary_literal(bytes: &[u8]) -> String {
    let body: Vec<String> = bytes.iter().map(u8::to_string).collect();
    format!("<<{}>>", body.join(","))
}

fn run(entry: &str) {
    assert!(ATTACKS.contains(&entry), "{entry} is not in ATTACKS");
    let _serial = TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping {entry}");
        return;
    };
    let b_beam = reference
        .compile_named("b_only", B_ONLY, &[])
        .expect("compile b_only");
    let source = format!("{SOURCE}\nbeam_b() -> {}.\n", binary_literal(&b_beam));
    let beam = reference
        .compile_named("ns_attack_t", &source, &[])
        .expect("compile ns_attack_t");
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load ns_attack_t");
    let actual = vm
        .eval_scheduled("ns_attack_t", entry, &[], 2, None)
        .unwrap_or_else(|error| panic!("{entry}: {error}"));
    assert_eq!(actual.term, OwnedTerm::Atom("ok".into()), "{entry}");
}

macro_rules! attacks {
    ($($name:ident),* $(,)?) => {
        $(
            #[test]
            fn $name() {
                run(stringify!($name));
            }
        )*
    };
}

attacks!(
    ns_attack_shared_service,
    ns_attack_pid_guess_send,
    ns_attack_pid_guess_link,
    ns_attack_pid_guess_monitor,
    ns_attack_pid_guess_exit_die,
    ns_attack_pid_guess_exit_kill,
    ns_attack_real_pid_ops,
    ns_attack_registry,
    ns_attack_persistent_term,
    ns_attack_os_env,
    ns_attack_foreign_module,
    ns_attack_system_flag,
    ns_attack_open_port,
    ns_attack_trace,
    ns_attack_load_nif,
    ns_attack_halt,
    ns_attack_init_stop,
    ns_attack_spawn_bomb,
    ns_attack_memory_bomb,
    ns_attack_group_leader,
);
