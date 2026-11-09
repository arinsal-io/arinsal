use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_term::Term;
use arinsal_vm::Vm;

const MODULE: &str = "heap_gc_root_probe";
const SOURCE: &str = r#"
-module(heap_gc_root_probe).
-export([run/1, worker/2]).

run(Kind) ->
    Parent = self(),
    Pid = spawn(fun() -> worker(Parent, Kind) end),
    receive {ready, Pid} -> ok end,
    1 = erlang:trace(Pid, true, [garbage_collection]),
    Pid ! go,
    receive
        {done, Before} ->
            BeforeEvents = traces(Pid, []),
            Pid ! force,
            receive
                {forced, After} ->
                    {Before, BeforeEvents, After, traces(Pid, [])}
            end
    end.

worker(Parent, Kind) ->
    Map = #{1 => 1, 2 => 2, 3 => 3, 4 => 4, 5 => 5, 6 => 6, 7 => 7, 8 => 8},
    Workload = case Kind of
        0 -> {map, Map};
        1 -> {map, Map};
        2 -> {map, Map};
        3 -> {list, lists:seq(1, 10000)}
    end,
    Parent ! {ready, self()},
    receive go -> ok end,
    Before = element(1, erlang:statistics(garbage_collection)),
    run_workload(Kind, Workload),
    After = element(1, erlang:statistics(garbage_collection)),
    Parent ! {done, {After - Before, process_info(self(), [heap_size, total_heap_size])}},
    receive force ->
        true = erts_internal:garbage_collect(major),
        Parent ! {forced, process_info(self(), [heap_size, total_heap_size])}
    end.

run_workload(0, {map, Map}) -> map_to_list_loop(500000, Map);
run_workload(1, {map, Map}) -> map_fold_loop(20000, Map);
run_workload(2, {map, Map}) -> iterator_loop(20000, Map);
run_workload(3, {list, List}) -> lists:reverse(List).

map_to_list_loop(0, _Map) -> ok;
map_to_list_loop(N, Map) ->
    maps:to_list(Map),
    map_to_list_loop(N - 1, Map).

map_fold_loop(0, _Map) -> ok;
map_fold_loop(N, Map) ->
    maps:fold(fun(K, V, A) -> K + V + A end, 0, Map),
    map_fold_loop(N - 1, Map).

iterator_loop(0, _Map) -> ok;
iterator_loop(N, Map) ->
    iterator_next(maps:iterator(Map)),
    iterator_loop(N - 1, Map).

iterator_next(Iterator) ->
    case maps:next(Iterator) of
        none -> ok;
        {_, _, Next} -> iterator_next(Next)
    end.

traces(Pid, Acc) ->
    receive
        {trace, Pid, Tag, Info} when Tag =:= gc_minor_start; Tag =:= gc_minor_end;
                                    Tag =:= gc_major_start; Tag =:= gc_major_end ->
            traces(Pid, [{Tag, Info} | Acc])
    after 0 ->
        lists:reverse(Acc)
    end.
"#;

#[test]
fn gc_trace_roots_for_map_and_reverse_workloads_match_otp() {
    let reference = RefErl::start().expect("start OTP 29.1.1");
    let beam = reference
        .compile_named(MODULE, SOURCE, &[])
        .expect("compile heap trace probe");
    reference
        .load(MODULE, &beam)
        .expect("load heap trace probe");
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load probe into Arinsal");

    for (kind, name) in [
        (0, "maps:to_list/1 x 500,000"),
        (1, "maps:fold/3 x 20,000"),
        (2, "maps iterator x 20,000"),
        (3, "lists:reverse/1 of 10,000"),
    ] {
        let input = [OwnedTerm::Int(kind)];
        let expected = match reference.call(MODULE, "run", &input) {
            CallResult::Ok(term) => term,
            other => panic!("OTP {name} failed: {other:?}"),
        };
        let outcome = vm
            .eval_scheduled(
                MODULE,
                "run",
                &[Term::small(kind).expect("workload id")],
                1,
                None,
            )
            .unwrap_or_else(|error| panic!("Arinsal {name} failed: {error:?}"));
        let expected = phases(&expected, "OTP", name);
        let actual = phases(&outcome.term, "Arinsal", name);
        let otp_rows = trace_rows(expected.1);
        let arinsal_rows = trace_rows(actual.1);
        let otp_forced_rows = trace_rows(expected.3);
        let arinsal_forced_rows = trace_rows(actual.3);
        let otp_count = gc_count(&otp_rows);
        let arinsal_count = gc_count(&arinsal_rows);
        let diff = first_trace_difference(&otp_rows, &arinsal_rows);
        let otp_done = done_fields(expected.0, "OTP", name);
        let arinsal_done = done_fields(actual.0, "Arinsal", name);
        eprintln!(
            "{name}: traced starts OTP={otp_count} Arinsal={arinsal_count}; statistics GCs OTP={} Arinsal={}; pre-force heap_size OTP={} Arinsal={}; first trace difference {diff}",
            integer(otp_done.0),
            integer(arinsal_done.0),
            process_info_size(otp_done.1, "heap_size"),
            process_info_size(arinsal_done.1, "heap_size")
        );
        similar_asserts::assert_eq!(otp_count, arinsal_count, "GC trace starts for {name}");
        similar_asserts::assert_eq!(
            integer(otp_done.0),
            integer(arinsal_done.0),
            "statistics GC counts for {name}"
        );
        similar_asserts::assert_eq!(
            process_info_size(otp_done.1, "heap_size"),
            process_info_size(arinsal_done.1, "heap_size"),
            "final young heap size for {name}"
        );
        if kind == 3 {
            let otp_peak = major_start_peak(&otp_rows).max(major_start_peak(&otp_forced_rows));
            let arinsal_peak =
                major_start_peak(&arinsal_rows).max(major_start_peak(&arinsal_forced_rows));
            eprintln!(
                "reverse10k workload events OTP {:?}; Arinsal {:?}; forced GC OTP {:?}; Arinsal {:?}; major-start recent_size OTP={otp_peak} Arinsal={arinsal_peak}",
                otp_rows, arinsal_rows, otp_forced_rows, arinsal_forced_rows
            );
            assert!(
                arinsal_peak == otp_peak,
                "reverse result liveness differs: major-start recent_size Arinsal={arinsal_peak}, OTP={otp_peak}"
            );
        }
    }
}

fn done_fields<'a>(
    term: &'a OwnedTerm,
    runtime: &str,
    workload: &str,
) -> (&'a OwnedTerm, &'a OwnedTerm) {
    let OwnedTerm::Tuple(values) = term else {
        panic!("{runtime} {workload} done payload is not a tuple: {term:?}");
    };
    if values.len() != 2 {
        panic!(
            "{runtime} {workload} done payload has {} fields",
            values.len()
        );
    }
    (&values[0], &values[1])
}

fn integer(term: &OwnedTerm) -> i64 {
    match term {
        OwnedTerm::Int(value) => *value,
        OwnedTerm::BigInt(value) => value.to_string().parse().expect("GC count"),
        _ => panic!("expected integer, got {term:?}"),
    }
}

fn phases<'a>(
    term: &'a OwnedTerm,
    runtime: &str,
    workload: &str,
) -> (&'a OwnedTerm, &'a OwnedTerm, &'a OwnedTerm, &'a OwnedTerm) {
    let OwnedTerm::Tuple(values) = term else {
        panic!("{runtime} {workload} did not return phases: {term:?}");
    };
    if values.len() != 4 {
        panic!("{runtime} {workload} returned {} phases", values.len());
    }
    (&values[0], &values[1], &values[2], &values[3])
}

fn trace_rows(trace: &OwnedTerm) -> Vec<(String, [i64; 6])> {
    let OwnedTerm::List { elems, .. } = trace else {
        panic!("expected trace list, got {trace:?}");
    };
    elems
        .iter()
        .map(|event| {
            let OwnedTerm::Tuple(fields) = event else {
                panic!("expected trace event tuple, got {event:?}");
            };
            let OwnedTerm::Atom(tag) = &fields[0] else {
                panic!("expected trace event name, got {:?}", fields[0]);
            };
            let names = [
                "heap_size",
                "heap_block_size",
                "mbuf_size",
                "recent_size",
                "stack_size",
                "old_heap_block_size",
            ];
            let values = names.map(|name| process_info_size(&fields[1], name));
            (tag.clone(), values)
        })
        .collect()
}

fn process_info_size(info: &OwnedTerm, name: &str) -> i64 {
    let OwnedTerm::List { elems, .. } = info else {
        panic!("expected information list, got {info:?}");
    };
    let pair = elems.iter().find_map(|entry| {
        let OwnedTerm::Tuple(pair) = entry else {
            return None;
        };
        (pair.first() == Some(&OwnedTerm::Atom(name.into())))
            .then(|| pair.get(1))
            .flatten()
    });
    match pair {
        Some(OwnedTerm::Int(value)) => *value,
        Some(OwnedTerm::BigInt(value)) => value.to_string().parse().expect("GC value"),
        _ => panic!("missing {name} in {info:?}"),
    }
}

fn gc_count(rows: &[(String, [i64; 6])]) -> usize {
    rows.iter()
        .filter(|(tag, _)| tag.ends_with("_start"))
        .count()
}

fn major_start_peak(rows: &[(String, [i64; 6])]) -> i64 {
    rows.iter()
        .filter(|(tag, _)| tag == "gc_major_start")
        .map(|(_, values)| values[3])
        .max()
        .unwrap_or(0)
}

fn first_trace_difference(otp: &[(String, [i64; 6])], arinsal: &[(String, [i64; 6])]) -> String {
    let common = otp.len().min(arinsal.len());
    for index in 0..common {
        if otp[index] != arinsal[index] {
            return format!(
                "at {index}: OTP {:?}, Arinsal {:?}",
                otp[index], arinsal[index]
            );
        }
    }
    if otp.len() != arinsal.len() {
        format!(
            "after {common} matching events: OTP {} events, Arinsal {}",
            otp.len(),
            arinsal.len()
        )
    } else {
        format!("none across {} events", otp.len())
    }
}
