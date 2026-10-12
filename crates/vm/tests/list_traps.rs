//! Long list BIFs trap on the same budgets as OTP-29.1.1 and return the same terms.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(list_traps).
-export([values/0, reds/0, responsive/0, child/3, tick/1, bench/0]).

values() ->
    Short = [{1, a}, {2, b}, {3, c}, {4, d}, {5, e}],
    L200 = [{I, I} || I <- lists:seq(1, 200)],
    Big = lists:seq(1, 100000),
    Pairs = [{I, I} || I <- Big],
    Huge = lists:seq(1, 1000000),
    {
      lists:keyfind(1, 1, Short),
      lists:keyfind(200, 1, L200),
      lists:keyfind(100000, 1, Pairs),
      lists:keyfind(miss, 1, Pairs),
      lists:keymember(100000, 1, Pairs),
      lists:keymember(miss, 1, Pairs),
      lists:keysearch(1, 1, Pairs),
      lists:keysearch(miss, 1, Pairs),
      lists:member(1, Big),
      lists:member(100000, Big),
      lists:member(miss, Big),
      lists:member(1000000, Huge),
      lists:member(nope, Huge),
      length(Big ++ [0]),
      hd(Big ++ [0]),
      lists:last(Big ++ [0]),
      length(Big -- Big),
      [1,2,3] -- [2],
      [1,2] ++ 3,
      [] ++ not_a_list,
      lists:reverse([1,2,3,4,5], [9])
    }.

reds() ->
    %% A large young heap keeps '++' on the 60-cells-per-reduction path.
    %% A heap that is already full falls into the 40-cell alloc path and may
    %% collect, and that cost is not part of the BIF's per-cell budget.
    erlang:process_flag(min_heap_size, 500000),
    Short = [{1, a}, {2, b}, {3, c}, {4, d}, {5, e}],
    L200 = [{I, I} || I <- lists:seq(1, 200)],
    Member = lists:seq(1, 10000),
    Left = lists:seq(1, 8000),
    Right = lists:seq(1, 8000),
    Plus = lists:seq(1, 8000),
    erlang:yield(),
    {
      delta(fun() -> lists:keyfind(1, 1, Short) end),
      delta(fun() -> lists:keyfind(200, 1, L200) end),
      delta(fun() -> lists:keymember(5, 1, Short) end),
      delta(fun() -> lists:keysearch(200, 1, L200) end),
      delta(fun() -> lists:member(10000, Member) end),
      delta(fun() -> lists:member(no, Member) end),
      delta(fun() -> Left -- Right end),
      delta(fun() -> Plus ++ [0] end),
      delta(fun() -> Plus ++ [] end)
    }.

delta(Fun) ->
    erlang:statistics(reductions),
    Value = Fun(),
    erlang:yield(),
    {_, Delta} = erlang:statistics(reductions),
    {Delta, Value}.

responsive() ->
    L = lists:seq(1, 100000),
    R = lists:seq(1, 100000),
    Parent = self(),
    spawn(list_traps, child, [Parent, L, R]),
    receive started -> ok end,
    spawn(list_traps, tick, [Parent]),
    receive
        tick -> tick;
        sub_done -> sub_done
    after 20000 -> timeout
    end.
child(Parent, L, R) ->
    Parent ! started,
    _ = L -- R,
    Parent ! sub_done.
tick(Parent) ->
    Parent ! tick.
bench() ->
    L5 = [{1, a}, {2, b}, {3, c}, {4, d}, {5, e}],
    L200 = [{I, I} || I <- lists:seq(1, 200)],
    {time(fun() -> lists:keyfind(1, 1, L5) end),
     time(fun() -> lists:keyfind(200, 1, L200) end)}.
time(Fun) ->
    N = 50000,
    [sample(Fun, N) || _ <- lists:seq(1, 5)].
sample(Fun, N) ->
    T0 = erlang:monotonic_time(nanosecond),
    burn(Fun, N),
    (erlang:monotonic_time(nanosecond) - T0) / N.
burn(_, 0) -> ok;
burn(Fun, N) ->
    Fun(),
    burn(Fun, N - 1).
"#;

#[test]
fn long_list_bifs_match_erts() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping list trap differential test");
        return;
    };
    let beam = reference.compile_named("list_traps", SOURCE, &[]).unwrap();
    reference.load("list_traps", &beam).unwrap();
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();

    let expected = reference.call("list_traps", "values", &[]);
    let actual = vm
        .eval_scheduled_reductions("list_traps", "values", &[], 1, Some(0x7157), 4_000)
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(expected, CallResult::Ok(actual.term));

    let expected = reference.call("list_traps", "reds", &[]);
    let actual = vm
        .eval_scheduled_reductions("list_traps", "reds", &[], 1, Some(0x7158), 4_000)
        .unwrap_or_else(|error| panic!("{error}"));
    let vm_term = actual.term;
    let CallResult::Ok(erl_term) = expected else {
        panic!("erl reds: {expected:?}");
    };
    let erl = ints(&erl_term);
    let ours = ints(&vm_term);
    assert_eq!(erl.len(), ours.len());
    eprintln!("reduction deltas erl={erl:?} vm={ours:?}");
    for (index, (erl_n, vm_n)) in erl.iter().zip(ours.iter()).enumerate() {
        let slack = (*erl_n / 10).max(15);
        let lo = erl_n - slack;
        let hi = erl_n + slack;
        assert!(
            (lo..=hi).contains(vm_n),
            "reduction delta {index}: erl {erl_n} vm {vm_n} (band {lo}..={hi})"
        );
    }

    let expected = reference.call("list_traps", "responsive", &[]);
    let actual = vm
        .eval_scheduled_reductions("list_traps", "responsive", &[], 1, Some(0x7159), 4_000)
        .unwrap_or_else(|error| panic!("{error}"));
    let tick = OwnedTerm::Atom("tick".to_string());
    assert_eq!(
        actual.term, tick,
        "subtract of two 100000 lists did not yield to another process"
    );
    assert_eq!(expected, CallResult::Ok(tick));
}

#[test]
fn keyfind_short_hits_bench() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping keyfind bench");
        return;
    };
    let beam = reference.compile_named("list_traps", SOURCE, &[]).unwrap();
    reference.load("list_traps", &beam).unwrap();
    let expected = reference.call("list_traps", "bench", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled_reductions("list_traps", "bench", &[], 1, Some(0xBEE5), 4_000)
        .unwrap_or_else(|error| panic!("{error}"));
    let CallResult::Ok(erl_term) = expected else {
        panic!("erl bench: {expected:?}");
    };
    let erl = pair_of_samples(&erl_term);
    let vm_samples = pair_of_samples(&actual.term);
    for (label, erl_s, vm_s) in [
        ("keyfind hit at 5", &erl[0], &vm_samples[0]),
        ("keyfind hit at 200", &erl[1], &vm_samples[1]),
    ] {
        let (emin, emed, emax) = spread(erl_s);
        let (vmin, vmed, vmax) = spread(vm_s);
        eprintln!(
            "{label}: erl median {emed:.1} ns/op (min {emin:.1}, max {emax:.1}); vm median {vmed:.1} ns/op (min {vmin:.1}, max {vmax:.1})"
        );
    }
}

fn pair_of_samples(term: &OwnedTerm) -> [Vec<f64>; 2] {
    let OwnedTerm::Tuple(items) = term else {
        panic!("expected two sample lists, got {term:?}");
    };
    [samples(&items[0]), samples(&items[1])]
}

fn samples(term: &OwnedTerm) -> Vec<f64> {
    let OwnedTerm::List { elems, .. } = term else {
        panic!("expected a sample list, got {term:?}");
    };
    elems
        .iter()
        .map(|item| match item {
            OwnedTerm::Float(value) => *value,
            OwnedTerm::Int(value) => *value as f64,
            _ => panic!("expected a sample, got {item:?}"),
        })
        .collect()
}

fn spread(samples: &[f64]) -> (f64, f64, f64) {
    let mut ordered = samples.to_vec();
    ordered.sort_by(f64::total_cmp);
    let min = ordered[0];
    let max = ordered[ordered.len() - 1];
    let median = ordered[ordered.len() / 2];
    (min, median, max)
}

fn ints(term: &OwnedTerm) -> Vec<i64> {
    let OwnedTerm::Tuple(items) = term else {
        panic!("expected a tuple of reduction deltas, got {term:?}");
    };
    items
        .iter()
        .map(|item| {
            let OwnedTerm::Tuple(pair) = item else {
                panic!("expected a {{Delta, Value}} pair, got {item:?}");
            };
            let OwnedTerm::Int(value) = pair[0] else {
                panic!("expected an integer delta, got {item:?}");
            };
            value
        })
        .collect()
}
