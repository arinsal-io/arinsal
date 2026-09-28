use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_term::{VecHeap, from_owned};
use arinsal_vm::Vm;

fn render(vm: &mut Vm, reference: &RefErl, function: &str, input: &OwnedTerm) -> OwnedTerm {
    let expected = reference.call("mix_loop6", function, std::slice::from_ref(input));
    let mut heap = VecHeap::new();
    let arg = from_owned(input, &mut heap).unwrap();
    let actual = vm
        .eval_scheduled("mix_loop6", function, &[arg], 1, Some(79))
        .unwrap();
    assert_eq!(expected, CallResult::Ok(actual.term.clone()), "{input:?}");
    actual.term
}

#[test]
fn ref_port_fun_to_list_match_otp_29() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping ref/port/fun_to_list differential test");
        return;
    };
    let source = "-module(mix_loop6). -export([ref/1, port/1, funl/1, local/0, export/0, wide/0]).
        ref(X) -> try erlang:ref_to_list(X) catch error:badarg -> badarg end.
        port(X) -> try erlang:port_to_list(X) catch error:badarg -> badarg end.
        funl(X) -> try erlang:fun_to_list(X) catch error:badarg -> badarg end.
        local() -> erlang:fun_to_list(fun(X) -> X end).
        export() -> erlang:fun_to_list(fun erlang:abs/1).
        wide() ->
            A1=1,A2=2,A3=3,A4=4,A5=5,A6=6,A7=7,A8=8,A9=9,A10=10,
            A11=11,A12=12,A13=13,A14=14,A15=15,A16=16,A17=17,A18=18,A19=19,A20=20,
            A21=21,A22=22,A23=23,A24=24,A25=25,A26=26,A27=27,A28=28,A29=29,A30=30,
            A31=31,A32=32,A33=33,A34=34,A35=35,A36=36,A37=37,A38=38,A39=39,A40=40,
            F = fun() ->
                A1+A2+A3+A4+A5+A6+A7+A8+A9+A10+
                A11+A12+A13+A14+A15+A16+A17+A18+A19+A20+
                A21+A22+A23+A24+A25+A26+A27+A28+A29+A30+
                A31+A32+A33+A34+A35+A36+A37+A38+A39+A40
            end,
            F().";
    let beam = reference.compile_named("mix_loop6", source, &[]).unwrap();
    reference.load("mix_loop6", &beam).unwrap();
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();

    let reference_term = OwnedTerm::Ref {
        node: "nonode@nohost".into(),
        creation: 0,
        ids: vec![1, 2, 3],
    };
    render(&mut vm, &reference, "ref", &reference_term);
    render(&mut vm, &reference, "ref", &OwnedTerm::Int(1));

    render(
        &mut vm,
        &reference,
        "port",
        &OwnedTerm::Port {
            node: "nonode@nohost".into(),
            id: 7,
            creation: 0,
        },
    );
    render(&mut vm, &reference, "port", &OwnedTerm::Int(1));
    render(&mut vm, &reference, "funl", &OwnedTerm::Int(1));

    for function in ["local", "export", "wide"] {
        let expected = reference.call("mix_loop6", function, &[]);
        let actual = vm
            .eval_scheduled("mix_loop6", function, &[], 1, Some(79))
            .unwrap();
        assert_eq!(expected, CallResult::Ok(actual.term), "{function}");
    }
}
