//! Namespace word, spawn inheritance and the delivery check.
//!
//! A namespace process cannot message root (root is not shared), so each test runs its probe
//! in a namespace process and reads the result from the exit reason that the root monitor sees.

use arinsal_difftest::RefErl;
use arinsal_etf::OwnedTerm;
use arinsal_vm::Vm;
use std::sync::Mutex;

static TEST_LOCK: Mutex<()> = Mutex::new(());

const SOURCE: &str = r#"
-module(ns_core_t).
-compile([export_all, nowarn_export_all]).

mk(Name) ->
    {ok, Ns} = arinsal_ns:create(Name, <<"shop">>, #{}),
    Ns.

wrapper(Fun) ->
    receive go -> ok end,
    exit({r, Fun()}).

start_in(Ns, Fun) ->
    P = arinsal_ns:spawn(Ns, ns_core_t, wrapper, [Fun]),
    Ref = erlang:monitor(process, P),
    {P, Ref}.

result({P, Ref}) ->
    P ! go,
    await(P, Ref).

await(P, Ref) ->
    receive
        {'DOWN', Ref, process, P, {r, R}} -> R;
        {'DOWN', Ref, process, P, Other} -> {crashed, Other}
    after 5000 -> timeout
    end.

in_ns(Ns, Fun) -> result(start_in(Ns, Fun)).

%% A process of Ns that returns the first message it receives.
receiver(Ns) ->
    start_in(Ns, fun() -> receive M -> {got, M} end end).

ns_spawn_inherits_ns() ->
    Ns = mk(<<"acme">>),
    {Own, Child, ChildOfChild} =
        in_ns(Ns, fun() ->
            Me = self(),
            C = spawn(fun() ->
                receive {From, q} -> From ! {ns, arinsal_ns:'of'(self()), arinsal_ns:'of'(From)} end
            end),
            C ! {Me, q},
            receive {ns, N, Parent} -> {arinsal_ns:'of'(Me), N, Parent} after 2000 -> timeout end
        end),
    case {Own, Child, ChildOfChild, arinsal_ns:'of'(self())} of
        {Ns, Ns, Ns, 0} when Ns > 0 -> ok;
        Other -> {bad, Ns, Other}
    end.

ns_delivery_same_ns_ok() ->
    Ns = mk(<<"acme">>),
    case in_ns(Ns, fun() ->
            Me = self(),
            B = spawn(fun() -> receive {From, ping} -> From ! pong end end),
            B ! {Me, ping},
            receive pong -> same_ns_ok after 2000 -> timeout end
        end) of
        same_ns_ok -> ok;
        Other -> {bad, Other}
    end.

ns_delivery_cross_ns_dropped() ->
    N1 = mk(<<"acme">>),
    N2 = mk(<<"globex">>),
    {PB, RefB} = receiver(N2),
    PB ! go,
    Sent = in_ns(N1, fun() -> PB ! hello end),
    PB ! release,
    Got = await(PB, RefB),
    case {Sent, Got} of
        {hello, {got, release}} -> ok;
        Other -> {bad, Other}
    end.

ns_root_can_send_into_ns() ->
    Ns = mk(<<"acme">>),
    {PB, RefB} = receiver(Ns),
    PB ! go,
    PB ! ping,
    case await(PB, RefB) of
        {got, ping} -> ok;
        Other -> {bad, Other}
    end.

ns_link_cross_ns_noproc() ->
    N1 = mk(<<"acme">>),
    N2 = mk(<<"globex">>),
    {PB, RefB} = start_in(N2, fun() -> receive stop -> stopped end end),
    PB ! go,
    Reason = in_ns(N1, fun() ->
        process_flag(trap_exit, true),
        link(PB),
        receive {'EXIT', PB, R} -> R after 2000 -> timeout end
    end),
    PB ! stop,
    Stopped = await(PB, RefB),
    case {Reason, Stopped} of
        {noproc, stopped} -> ok;
        Other -> {bad, Other}
    end.

%% gen_server callbacks, for the alias test
init(_) -> {ok, s}.
handle_call(ping, _From, S) -> {reply, pong, S}.

ns_pids(Ns) -> [P || P <- erlang:processes(), arinsal_ns:'of'(P) =:= Ns].

wait_count(Ns, _N, 0) -> ns_pids(Ns);
wait_count(Ns, N, Tries) ->
    case ns_pids(Ns) of
        L when length(L) >= N -> L;
        _ ->
            receive after 10 -> ok end,
            wait_count(Ns, N, Tries - 1)
    end.

ns_root_requests_reply() ->
    Ns = mk(<<"acme">>),
    {PB, RefB} = start_in(Ns, fun() -> receive stop -> stopped end end),
    PB ! go,
    Links = process_info(PB, links),
    Alive = is_process_alive(PB),
    Gc = erlang:garbage_collect(PB),
    PB ! stop,
    Stopped = await(PB, RefB),
    case {Links, Alive, Gc, Stopped} of
        {{links, []}, true, true, stopped} -> ok;
        Other -> {bad, Other}
    end.

ns_request_to_root_refused() ->
    Ns = mk(<<"acme">>),
    Root = self(),
    case in_ns(Ns, fun() -> {process_info(Root, status), is_process_alive(Root)} end) of
        {undefined, false} -> ok;
        Other -> {bad, Other}
    end.

ns_alias_gen_server() ->
    Ns = mk(<<"acme">>),
    P = in_ns(Ns, fun() -> {ok, Pid} = gen_server:start(ns_core_t, [], []), Pid end),
    case gen_server:call(P, ping, 3000) of
        pong -> ok;
        Other -> {bad, Other}
    end.

%% A root process that reports the first message it gets to the caller.
root_receiver() ->
    Me = self(),
    spawn(fun() -> receive M -> Me ! {root_got, M} end end).

root_probe(Pid) ->
    receive {root_got, M} -> M after 3000 -> timeout end.

ns_shared_root_reachable() ->
    Ns = mk(<<"acme">>),
    R = root_receiver(),
    ok = arinsal_ns:expose(R),
    hello = in_ns(Ns, fun() -> R ! hello end),
    case root_probe(R) of
        hello -> ok;
        Other -> {bad, Other}
    end.

ns_unshared_root_unreachable() ->
    Ns = mk(<<"acme">>),
    R = root_receiver(),
    hello = in_ns(Ns, fun() -> R ! hello end),
    R ! release,
    case root_probe(R) of
        release -> ok;
        Other -> {bad, Other}
    end.

ns_natives_root_only() ->
    Ns = mk(<<"acme">>),
    Self = self(),
    Res = in_ns(Ns, fun() ->
        [catch arinsal_ns:create(<<"a">>, <<"b">>, #{}),
         catch arinsal_ns:spawn(1, erlang, self, []),
         catch arinsal_ns:destroy(1),
         catch arinsal_ns:expose(self())]
    end),
    case Res of
        [{'EXIT', {notsup, _}}, {'EXIT', {notsup, _}}, {'EXIT', {notsup, _}}, {'EXIT', {notsup, _}}] -> ok;
        Other -> {bad, Other, Self}
    end.

ns_destroy_kills_all() ->
    Ns = mk(<<"acme">>),
    Spawner = fun() ->
        spawn(fun() -> receive stop -> ok end end),
        receive stop -> ok end
    end,
    Waiter = fun() -> receive stop -> ok end end,
    _ = arinsal_ns:spawn(Ns, ns_core_t, run_fun, [Spawner]),
    _ = arinsal_ns:spawn(Ns, ns_core_t, run_fun, [Waiter]),
    Pids = wait_count(Ns, 3, 300),
    Refs = [erlang:monitor(process, P) || P <- Pids],
    ok = arinsal_ns:destroy(Ns),
    ok = arinsal_ns:destroy(Ns),
    Reasons = [receive {'DOWN', R, process, _, Why} -> Why after 3000 -> timeout end || R <- Refs],
    After = (catch arinsal_ns:spawn(Ns, erlang, self, [])),
    case {length(Pids), lists:usort(Reasons), ns_pids(Ns), After} of
        {3, [killed], [], {'EXIT', {badarg, _}}} -> ok;
        Other -> {bad, Other}
    end.

run_fun(Fun) -> Fun().

waiter() -> receive stop -> ok end.

%% Wait until fun Pred(Info) holds for the info map of Ns, at most ~3s.
wait_info(Ns, Pred) -> wait_info(Ns, Pred, 300).
wait_info(Ns, Pred, 0) -> arinsal_ns:info(Ns);
wait_info(Ns, Pred, N) ->
    Info = arinsal_ns:info(Ns),
    case Pred(Info) of
        true -> Info;
        false -> receive after 10 -> ok end, wait_info(Ns, Pred, N - 1)
    end.

ns_process_cap_system_limit() ->
    {ok, Ns} = arinsal_ns:create(<<"acme">>, <<"shop">>, #{max_processes => 3}),
    Ws = [arinsal_ns:spawn(Ns, ns_core_t, run_fun, [fun waiter/0]) || _ <- [1, 2, 3]],
    Root = (catch arinsal_ns:spawn(Ns, ns_core_t, run_fun, [fun waiter/0])),
    Refs = [erlang:monitor(process, W) || W <- Ws],
    [W ! stop || W <- Ws],
    [receive {'DOWN', R, process, _, _} -> ok after 3000 -> timeout end || R <- Refs],
    #{processes := Left} = wait_info(Ns, fun(#{processes := N}) -> N =:= 0 end),
    Again = in_ns(Ns, fun() ->
        A = spawn(fun waiter/0), B = spawn(fun waiter/0),
        Over = (catch spawn(fun waiter/0)),
        A ! stop, B ! stop,
        Over
    end),
    case {Root, Left, Again} of
        {{'EXIT', {system_limit, _}}, 0, {'EXIT', {system_limit, _}}} -> ok;
        Other -> {bad, Other}
    end.

ns_destroy_closes_spawns() ->
    Ns = mk(<<"acme">>),
    Spawner = fun() ->
        Loop = fun L() -> spawn(fun waiter/0), receive after 1 -> ok end, L() end,
        Loop()
    end,
    _ = arinsal_ns:spawn(Ns, ns_core_t, run_fun, [Spawner]),
    Pids0 = wait_count(Ns, 20, 300),
    ok = arinsal_ns:destroy(Ns),
    Refs = [erlang:monitor(process, P) || P <- Pids0],
    [receive {'DOWN', R, process, _, _} -> ok after 5000 -> timeout end || R <- Refs],
    #{processes := Left} = wait_info(Ns, fun(#{processes := N}) -> N =:= 0 end),
    Pids = ns_pids(Ns),
    case {length(Pids0) >= 20, Left, Pids} of
        {true, 0, []} -> ok;
        Other -> {bad, Other}
    end.

ns_info_counts() ->
    {ok, Ns} = arinsal_ns:create(<<"acme">>, <<"shop">>, #{max_processes => 10}),
    Before = arinsal_ns:info(Ns),
    {PB, RefB} = start_in(Ns, fun() -> receive stop -> stopped end end),
    #{processes := One} = wait_info(Ns, fun(#{processes := N}) -> N =:= 1 end),
    PB ! go, PB ! stop,
    stopped = await(PB, RefB),
    sum = in_ns(Ns, fun() -> _ = lists:sum(lists:seq(1, 200000)), sum end),
    After = wait_info(Ns, fun(#{processes := N}) -> N =:= 0 end),
    case {Before, One, After} of
        {#{tenant := <<"acme">>, project := <<"shop">>, processes := 0, max_processes := 10,
           max_bytes := infinity, heap_words := H0}, 1,
         #{processes := 0, reductions := R, max_processes := 10}}
          when is_integer(H0), R > 1000 -> ok;
        Other -> {bad, Other}
    end.

ns_list() ->
    Empty = arinsal_ns:list(),
    N1 = mk(<<"a">>),
    N2 = mk(<<"b">>),
    Both = arinsal_ns:list(),
    ok = arinsal_ns:destroy(N1),
    Rest = arinsal_ns:list(),
    #{tenant := T} = arinsal_ns:info(N1),
    case {Empty, Both, Rest, T, N1, N2} of
        {[], [N1, N2], [N2], <<"a">>, 1, 2} -> ok;
        Other -> {bad, Other}
    end.

ns_processes_filtered() ->
    N1 = mk(<<"a">>),
    N2 = mk(<<"b">>),
    Inner = in_ns(N1, fun() ->
        C = spawn(fun waiter/0),
        Ps = processes(),
        C ! stop,
        {length(Ps), lists:all(fun(P) -> arinsal_ns:'of'(P) =:= arinsal_ns:'of'(self()) end, Ps)}
    end),
    Other = in_ns(N2, fun() -> length(processes()) end),
    RootSees = processes(),
    case {Inner, Other, lists:member(self(), RootSees), length(RootSees) > 2} of
        {{2, true}, 1, true, true} -> ok;
        Bad -> {bad, Bad}
    end.
"#;

fn run(entry: &str) {
    let _serial = TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping {entry}");
        return;
    };
    let beam = reference
        .compile_named("ns_core_t", SOURCE, &[])
        .expect("compile ns_core_t");
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load ns_core_t");
    let actual = vm
        .eval_scheduled("ns_core_t", entry, &[], 2, None)
        .unwrap_or_else(|error| panic!("{entry}: {error}"));
    assert_eq!(actual.term, OwnedTerm::Atom("ok".into()), "{entry}");
}

#[test]
fn ns_spawn_inherits_ns() {
    run("ns_spawn_inherits_ns");
}

#[test]
fn ns_delivery_same_ns_ok() {
    run("ns_delivery_same_ns_ok");
}

#[test]
fn ns_delivery_cross_ns_dropped() {
    run("ns_delivery_cross_ns_dropped");
}

#[test]
fn ns_root_can_send_into_ns() {
    run("ns_root_can_send_into_ns");
}

#[test]
fn ns_link_cross_ns_noproc() {
    run("ns_link_cross_ns_noproc");
}

#[test]
fn ns_root_requests_reply() {
    run("ns_root_requests_reply");
}

#[test]
fn ns_request_to_root_refused() {
    run("ns_request_to_root_refused");
}

#[test]
fn ns_alias_gen_server() {
    run("ns_alias_gen_server");
}

#[test]
fn ns_shared_root_reachable() {
    run("ns_shared_root_reachable");
}

#[test]
fn ns_unshared_root_unreachable() {
    run("ns_unshared_root_unreachable");
}

#[test]
fn ns_natives_root_only() {
    run("ns_natives_root_only");
}

#[test]
fn ns_destroy_kills_all() {
    run("ns_destroy_kills_all");
}

#[test]
fn ns_process_cap_system_limit() {
    run("ns_process_cap_system_limit");
}

#[test]
fn ns_destroy_closes_spawns() {
    run("ns_destroy_closes_spawns");
}

#[test]
fn ns_info_counts() {
    run("ns_info_counts");
}

#[test]
fn ns_list() {
    run("ns_list");
}

#[test]
fn ns_processes_filtered() {
    run("ns_processes_filtered");
}
