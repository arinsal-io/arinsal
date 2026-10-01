use arinsal_a64::enc::Gpr;
use arinsal_beamasm::{
    ExitReason, SchedulerRegisters,
    arith::ArithHelper,
    construct::GcHook,
    enter_native_raw,
    guard::GuardHelper,
    module::{ArgVal, BeamModuleAssembler},
};
use arinsal_difftest::RefErl;
use arinsal_term::{ProcessHeap, Term, TermBuilder, TermKind, to_owned};
use arinsal_vm::{Process, arinsal_beamasm_arith, arinsal_beamasm_gc, arinsal_beamasm_guard};

fn run(
    process: &mut Process,
    registers: &mut SchedulerRegisters,
    emit: impl FnOnce(&mut BeamModuleAssembler),
) -> ExitReason {
    let mut asm = BeamModuleAssembler::new();
    asm.emit_i_func_label(1).unwrap();
    emit(&mut asm);
    asm.emit_raw(|e| {
        e.mov_reg(Gpr::x(0), Gpr::xzr())?;
        e.ret(Gpr::x(30))
    })
    .unwrap();
    let module = asm.finalize().unwrap();
    let saved_ftrace = process.native_header().ftrace;
    process.native_header().ftrace = (registers as *mut SchedulerRegisters).cast();
    // SAFETY: The code follows the BeamAsm ABI and the process plus register
    // storage remain exclusively borrowed for this synchronous native call.
    let result = unsafe {
        enter_native_raw(
            process.native_header(),
            registers,
            module.entries[&1].cast(),
        )
    };
    process.native_header().ftrace = saved_ftrace;
    result
}

fn bits(term: Term) -> u64 {
    // SAFETY: Each test keeps the owning process heap alive through execution.
    unsafe { term.raw_bits() }
}

fn from_bits(bits: u64) -> Term {
    // SAFETY: Native X values contain tagged BEAM terms.
    unsafe { Term::from_raw_bits(bits) }
}

fn make_big(heap: &mut ProcessHeap, value: i128) -> Term {
    TermBuilder::new(heap).int_from_i128(value).unwrap()
}

#[test]
fn arith_overflow_makes_bignum() {
    let mut process = Process::new();
    let lhs = make_big(&mut process.heap, (1_i128 << 59) - 1);
    let rhs = Term::small(1).unwrap();
    process.x[0] = lhs;
    process.x[1] = rhs;
    let mut registers = SchedulerRegisters::default();
    registers.x_reg_array[0] = bits(lhs);
    registers.x_reg_array[1] = bits(rhs);
    assert_eq!(
        run(&mut process, &mut registers, |asm| {
            let helper: ArithHelper = arinsal_beamasm_arith;
            asm.emit_i_plus(ArgVal::X(0), ArgVal::X(1), ArgVal::X(1), helper)
                .unwrap();
        }),
        ExitReason::Returned
    );
    let result = from_bits(registers.x_reg_array[1]);
    assert_eq!(result.classify(), TermKind::Number);
    assert!(matches!(
        to_owned(result).unwrap(),
        arinsal_etf::OwnedTerm::BigInt(_)
    ));
}

#[test]
fn badarith_caught_by_interpreted_try() {
    let mut process = Process::new();
    let lhs = Term::atom(arinsal_term::atoms::TRUE);
    let rhs = Term::small(1).unwrap();
    process.x[0] = lhs;
    process.x[1] = rhs;
    let mut registers = SchedulerRegisters::default();
    registers.x_reg_array[0] = bits(lhs);
    registers.x_reg_array[1] = bits(rhs);
    assert_eq!(
        run(&mut process, &mut registers, |asm| {
            let helper: ArithHelper = arinsal_beamasm_arith;
            asm.emit_i_plus(ArgVal::X(0), ArgVal::X(1), ArgVal::X(1), helper)
                .unwrap();
        }),
        ExitReason::Returned
    );
    assert_eq!(process.native_header().freason, 1);
    let badarith = arinsal_term::global_atoms().intern("badarith").unwrap();
    assert_eq!(
        from_bits(process.native_header().fvalue).as_atom(),
        Some(badarith)
    );

    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping interpreted try portion");
        return;
    };
    let beam = reference
        .compile_named(
            "native_hook_try",
            "-module(native_hook_try). -export([caught/0]). caught() -> try 1 div 0 catch error:badarith -> caught end.",
            &[],
        )
        .unwrap();
    let mut vm = arinsal_vm::Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let result = vm.eval("native_hook_try", "caught", &[]).unwrap();
    let atom = result.term.as_atom().unwrap();
    assert_eq!(arinsal_term::global_atoms().text(atom), Some("caught"));
}

#[test]
fn compare_bignum_float_and_mixed() {
    let mut process = Process::new();
    let integer = make_big(&mut process.heap, (1_i128 << 80) + 1);
    let float = TermBuilder::new(&mut process.heap)
        .float(2_f64.powi(80))
        .unwrap();
    process.x[0] = integer;
    process.x[1] = float;
    let mut registers = SchedulerRegisters::default();
    registers.x_reg_array[0] = bits(integer);
    registers.x_reg_array[1] = bits(float);
    run(&mut process, &mut registers, |asm| {
        let helper: GuardHelper = arinsal_beamasm_guard;
        asm.emit_is_lt(ArgVal::X(0), ArgVal::X(1), 2, helper)
            .unwrap();
        asm.move_(
            ArgVal::Immediate(bits(Term::small(2).unwrap())),
            ArgVal::X(0),
        )
        .unwrap();
        asm.jump(3).unwrap();
        asm.emit_i_func_label(2).unwrap();
        asm.move_(
            ArgVal::Immediate(bits(Term::small(1).unwrap())),
            ArgVal::X(0),
        )
        .unwrap();
        asm.emit_i_func_label(3).unwrap();
    });
    assert_eq!(registers.x_reg_array[0], bits(Term::small(1).unwrap()));
}

#[test]
fn gc_hook_moves_terms_and_reloads_x() {
    let mut process = Process::new();
    let big = make_big(&mut process.heap, 1_i128 << 120);
    process.x[0] = big;
    let mut registers = SchedulerRegisters::default();
    registers.x_reg_array[0] = bits(big);
    let before = registers.x_reg_array[0];
    run(&mut process, &mut registers, |asm| {
        let hook: GcHook = arinsal_beamasm_gc;
        asm.emit_test_heap(4096, 1, hook).unwrap();
    });
    let after = registers.x_reg_array[0];
    assert_ne!(after, before);
    assert!(matches!(
        to_owned(from_bits(after)).unwrap(),
        arinsal_etf::OwnedTerm::BigInt(_)
    ));
}

#[test]
fn map_get_on_hashmap_via_hook() {
    let mut process = Process::new();
    let mut map_heap = ProcessHeap::with_words(8192);
    let pairs: Vec<_> = (0..40)
        .map(|index| {
            (
                Term::small(index).unwrap(),
                Term::small(index + 10).unwrap(),
            )
        })
        .collect();
    let map = arinsal_maps::from_pairs(&pairs, &mut map_heap).unwrap();
    assert!(map.is_hashmap());
    let key = Term::small(27).unwrap();
    process.x[0] = key;
    process.x[1] = map;
    let mut registers = SchedulerRegisters::default();
    registers.x_reg_array[0] = bits(key);
    registers.x_reg_array[1] = bits(map);
    run(&mut process, &mut registers, |asm| {
        let helper: GuardHelper = arinsal_beamasm_guard;
        asm.emit_bif_map_get(0, ArgVal::X(0), ArgVal::X(1), ArgVal::X(0), helper)
            .unwrap();
    });
    assert_eq!(from_bits(registers.x_reg_array[0]).as_small(), Some(37));
}
