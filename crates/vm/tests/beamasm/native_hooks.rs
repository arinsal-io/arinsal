use arinsal_a64::enc::Gpr;
use arinsal_beamasm::{
    ExitReason, SchedulerRegisters, enter_native_raw,
    module::{ArgVal, BeamModuleAssembler},
    types::{ArgType, TypedArg},
};
use arinsal_difftest::RefErl;
use arinsal_term::{ProcessHeap, Term, TermBuilder, TermKind, to_owned};
use arinsal_vm::Process;

fn run(
    process: &mut Process,
    registers: &mut SchedulerRegisters,
    emit: impl FnOnce(&mut BeamModuleAssembler),
) -> ExitReason {
    let mut asm = BeamModuleAssembler::new();
    asm.set_bif_fragments(bif_fragments());
    asm.set_yield_fragments(yield_fragments().entries());
    asm.emit_i_func_label(1).unwrap();
    // Fragment calls clobber LR; keep the return address in scratch memory (a stack word
    // would be scanned by the GC cases).
    let cp_slot = std::mem::offset_of!(SchedulerRegisters, tmp_mem) as u32 + 7 * 8;
    asm.emit_raw(|e| e.str_uoff(Gpr::x(30), Gpr::x(19), cp_slot))
        .unwrap();
    emit(&mut asm);
    asm.emit_raw(|e| {
        e.mov_reg(Gpr::x(0), Gpr::xzr())?;
        e.ldr_uoff(Gpr::x(30), Gpr::x(19), cp_slot)?;
        e.ret(Gpr::x(30))
    })
    .unwrap();
    let module = asm.finalize().unwrap();
    let saved = process.x.saved_arity();
    // SAFETY: The code follows the BeamAsm ABI and the process plus register
    // storage remain exclusively borrowed for this synchronous native call, and
    // `detach_save` below ends the attachment of `registers`.
    let result = unsafe {
        process.x.attach(registers);
        enter_native_raw(
            process.native_header(),
            registers,
            module.entries[&1].cast(),
        )
    };
    process.x.detach_save(saved);
    result
}

// The VM's `erts_garbage_collect_nobump` (erl_gc.rs), the function the VM's own
// `garbage_collect` fragment calls.
unsafe extern "C" {
    safe fn erts_garbage_collect_nobump(
        c_p: *mut arinsal_beamasm::ProcessHeader,
        need: usize,
        objv: *mut u64,
        nobj: i32,
        fcalls: i32,
    ) -> i32;
}

/// The process-wide `ga` fragments, built as the VM builds them.
fn yield_fragments() -> &'static arinsal_beamasm::yield_frag::YieldFragments {
    use arinsal_beamasm::yield_frag::YieldFragments;
    static YIELD: std::sync::OnceLock<YieldFragments> = std::sync::OnceLock::new();
    YIELD.get_or_init(|| {
        YieldFragments::new(
            erts_garbage_collect_nobump as *const () as usize,
            arinsal_vm::PROCESS_STATE_OFFSET as u32,
        )
        .unwrap()
    })
}

/// The process-wide fragments; the arithmetic ones call the VM's erts runtime symbols
/// (erl_arith.rs). No case here raises, so the exception resolver is never entered.
fn bif_fragments() -> arinsal_beamasm::raise_frag::BifFragments {
    use arinsal_beamasm::raise_frag::RaiseFragments;
    use std::sync::OnceLock;
    static RAISE: OnceLock<RaiseFragments> = OnceLock::new();
    extern "C" fn unused() {
        unreachable!("no case raises")
    }
    RAISE
        .get_or_init(|| {
            let context_switch = yield_fragments().context_switch();
            RaiseFragments::new(
                unused as *const () as usize,
                unused as *const () as usize,
                context_switch,
            )
            .unwrap()
        })
        .bif_fragments()
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
    registers.x_reg_array[0] = arinsal_beamasm::rt::fixture_term(bits(lhs));
    registers.x_reg_array[1] = arinsal_beamasm::rt::fixture_term(bits(rhs));
    assert_eq!(
        run(&mut process, &mut registers, |asm| {
            asm.emit_i_plus(
                TypedArg::new(ArgVal::X(0), ArgType::ANY),
                TypedArg::new(ArgVal::X(1), ArgType::ANY),
                ArgVal::X(1),
            )
            .unwrap();
        }),
        ExitReason::Returned
    );
    let result = from_bits(registers.x_reg_array[1].tagged_word());
    assert_eq!(result.classify(), TermKind::Number);
    assert!(matches!(
        to_owned(result).unwrap(),
        arinsal_etf::OwnedTerm::BigInt(_)
    ));
}

// erts emit_i_plus with a failure label: `erts_mixed_plus` returns THE_NON_VALUE with
// `c_p->freason` BADARITH and the code branches to the label, the destination untouched.
#[test]
fn guard_badarith_branches_to_the_fail_label() {
    let mut process = Process::new();
    let lhs = Term::atom(arinsal_term::atoms::TRUE);
    let rhs = Term::small(1).unwrap();
    process.x[0] = lhs;
    process.x[1] = rhs;
    let mut registers = SchedulerRegisters::default();
    registers.x_reg_array[0] = arinsal_beamasm::rt::fixture_term(bits(lhs));
    registers.x_reg_array[1] = arinsal_beamasm::rt::fixture_term(bits(rhs));
    assert_eq!(
        run(&mut process, &mut registers, |asm| {
            asm.emit_i_plus_with_fail(
                TypedArg::new(ArgVal::X(0), ArgType::ANY),
                TypedArg::new(ArgVal::X(1), ArgType::ANY),
                ArgVal::X(1),
                2,
            )
            .unwrap();
            asm.emit_label(2).unwrap();
        }),
        ExitReason::Returned
    );
    assert_eq!(registers.x_reg_array[1].tagged_word(), bits(rhs));
    assert_eq!(
        process.native_header().exc.freason,
        arinsal_beamasm::exc::EXC_BADARITH
    );
    let badarith = arinsal_term::global_atoms().intern("badarith").unwrap();
    assert_eq!(
        from_bits(process.native_header().exc.fvalue).as_atom(),
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
    let mut vm = crate::common::node();
    vm.load_bytes(&beam).unwrap();
    let result = vm.eval_exported("native_hook_try", "caught", &[]).unwrap();
    let atom = result.term.as_atom().unwrap();
    assert_eq!(arinsal_term::global_atoms().text(atom), Some("caught"));
}
