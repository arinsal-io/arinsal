use arinsal_difftest::{CallResult, CompareMode, RefErl, compare};
use arinsal_etf::OwnedTerm;
use arinsal_term::{Term, from_owned};
use arinsal_vm::Vm;

fn on_load_case(callback: &str, module: &str) {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping loader_ops on_load differential test");
        return;
    };
    let source = format!(
        "-module({module}). -on_load(init/0). -export([init/0,value/0]). init() -> {callback}. value() -> loaded."
    );
    let beam = reference.compile_named(module, &source, &[]).unwrap();
    let control_name = format!("{module}_control");
    let control_source = format!(
        "-module({control_name}). -export([run/1]). run(Bin) -> Prep=erlang:prepare_loading({module},Bin), case erlang:finish_loading([Prep]) of {{on_load,[{module}]}} -> Keep=try erlang:call_on_load_function({module}) =:= ok catch _:_ -> false end, true=erlang:finish_after_on_load({module},Keep), case Keep of true -> {{module,{module}}}; false -> {{error,on_load_failure}} end; Other -> Other end."
    );
    let control = reference
        .compile_named(&control_name, &control_source, &[])
        .unwrap();
    reference.load(&control_name, &control).unwrap();
    let expected = reference.call(&control_name, "run", &[OwnedTerm::Binary(beam.clone())]);

    let mut vm = Vm::new([]);
    vm.load_bytes(&control).unwrap();
    let mut heap = arinsal_term::VecHeap::new();
    let argument = from_owned(&OwnedTerm::Binary(beam), &mut heap).unwrap();
    let actual = vm
        .eval_scheduled(&control_name, "run", &[argument], 2, None)
        .map(|result| CallResult::Ok(result.term))
        .unwrap_or_else(|error| CallResult::Exception {
            class: "error".into(),
            reason: OwnedTerm::Atom(format!("{error}")),
            stack_top: None,
        });
    compare(&actual, &expected, CompareMode::Exact).unwrap();
}

#[test]
fn loader_ops_on_load_returns_ok() {
    on_load_case("ok", "loader_ops_on_load_ok");
}

#[test]
fn loader_ops_on_load_returns_error() {
    on_load_case("error", "loader_ops_on_load_error");
}

#[test]
fn loader_ops_on_load_crashes() {
    on_load_case("erlang:error(on_load_crash)", "loader_ops_on_load_crash");
}

#[test]
fn loader_ops_bif3_guard_matches_erl() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping loader_ops bif3 differential test");
        return;
    };
    let module = "loader_ops_bif3";
    let source = format!(
        "-module({module}). -export([run/3]). run(Value,Min,Max) when is_integer(Value,Min,Max) -> true; run(_,_,_) -> false."
    );
    let beam = reference.compile_named(module, &source, &[]).unwrap();
    reference.load(module, &beam).unwrap();
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    for inputs in [
        [OwnedTerm::Int(5), OwnedTerm::Int(1), OwnedTerm::Int(9)],
        [OwnedTerm::Int(0), OwnedTerm::Int(1), OwnedTerm::Int(9)],
    ] {
        let expected = reference.call(module, "run", &inputs);
        let mut heap = arinsal_term::VecHeap::new();
        let args = inputs
            .iter()
            .map(|term| from_owned(term, &mut heap).unwrap())
            .collect::<Vec<Term>>();
        let actual = vm
            .eval_scheduled(module, "run", &args, 2, None)
            .map(|result| CallResult::Ok(result.term))
            .unwrap_or_else(|error| CallResult::Exception {
                class: "error".into(),
                reason: OwnedTerm::Atom(format!("{error}")),
                stack_top: None,
            });
        compare(&actual, &expected, CompareMode::Exact).unwrap();
    }
}
