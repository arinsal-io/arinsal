use arinsal_difftest::RefErl;
use arinsal_etf::OwnedTerm;
use arinsal_vm::Vm;

#[test]
fn standard_io_port_is_registered_and_orders_below_binary() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping ports differential test");
        return;
    };
    let module = "binary_ports_compat";
    let beam = reference
        .compile_named(
            module,
            "-module(binary_ports_compat). -export([run/0]). run() -> P = hd(erlang:ports()), {is_port(P), <<1>> > P}.",
            &[],
        )
        .expect("compile ports probe");
    let expected = reference
        .eval("P = hd(erlang:ports()), {is_port(P), <<1>> > P}")
        .unwrap();
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm.eval_scheduled(module, "run", &[], 1, None).unwrap().term;
    assert_eq!(expected, OwnedTerm::Tuple(vec![OwnedTerm::atom("true"); 2]));
    assert_eq!(actual, expected);
}
