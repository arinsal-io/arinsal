#![cfg(target_arch = "aarch64")]

use arinsal_a64::enc::Gpr;
use arinsal_beamasm::{
    ExitReason, ProcessHeader, SchedulerRegisters,
    bs_segments::BsmCommand,
    enter_native,
    module::{ArgVal, BeamModuleAssembler},
};
use arinsal_term::{ProcessHeap, Term, TermBuilder};
use similar_asserts::assert_eq;

/// The process native code runs on: the native prefix at `c_p` and the `ERTS_PSFLG_*` word
/// at `offsetof(Process, state)`, which the garbage-collection fragment reads.
#[repr(C)]
struct TestProcess {
    header: ProcessHeader,
    state: u32,
}

const STATE_OFFSET: u32 = std::mem::offset_of!(TestProcess, state) as u32;

/// `erts_garbage_collect_nobump` of these cases: the heap always has room.
extern "C" fn gc_helper(
    _c_p: *mut ProcessHeader,
    _need: usize,
    _objv: *mut u64,
    _nobj: i32,
    _fcalls: i32,
) -> i32 {
    0
}

/// The process-wide fragments (`ga`), built once as the VM builds them.
fn yield_entries() -> arinsal_beamasm::yield_frag::YieldEntries {
    use arinsal_beamasm::yield_frag::YieldFragments;
    static FRAGMENTS: std::sync::OnceLock<YieldFragments> = std::sync::OnceLock::new();
    FRAGMENTS
        .get_or_init(|| YieldFragments::new(gc_helper as *const () as usize, STATE_OFFSET).unwrap())
        .entries()
}

fn run_native(
    emit: impl FnOnce(&mut BeamModuleAssembler) -> Result<(), arinsal_beamasm::module::ModuleError>,
    bit_offset: usize,
) -> (u64, u64) {
    let mut heap = ProcessHeap::with_words(4096);
    let mut builder = TermBuilder::new(&mut heap);
    let binary = builder.binary(&[0x5a; 1000]).unwrap();
    let sliced = builder
        .sub_binary(binary, bit_offset, 8000 - bit_offset)
        .unwrap();
    let context = builder.match_context(sliced).unwrap();

    let mut asm = BeamModuleAssembler::new();
    asm.set_yield_fragments(yield_entries());
    asm.emit_i_func_label(1).unwrap();
    asm.emit_enter_frame().unwrap();
    emit(&mut asm).unwrap();
    asm.emit_leave_frame().unwrap();
    asm.emit_raw(|e| {
        e.mov_reg(Gpr::x(0), Gpr::xzr())?;
        e.ret(Gpr::x(30))
    })
    .unwrap();
    asm.emit_i_func_label(99).unwrap();
    asm.emit_leave_frame().unwrap();
    asm.emit_raw(|e| {
        e.mov_const(Gpr::x(26), 77)?;
        e.mov_reg(Gpr::x(0), Gpr::xzr())?;
        e.ret(Gpr::x(30))
    })
    .unwrap();
    let module = asm.finalize().unwrap();
    let mut registers = SchedulerRegisters::default();
    registers.x_reg_array[0] = context;
    registers.x_reg_array[1] = Term::small(1).unwrap();
    let mut stack = [0_u64; 128];
    let (htop, hend) = heap.heap_cursor();
    let (heap_start, _) = heap.heap_bounds();
    let mut process = TestProcess {
        header: ProcessHeader {
            htop,
            heap: heap_start,
            hend,
            stop: stack.as_mut_ptr().wrapping_add(stack.len()),
            fcalls: 100,
            ..ProcessHeader::default()
        },
        state: 0,
    };
    assert_eq!(
        enter_native(
            &mut process.header,
            &mut registers,
            &module.entry(1).unwrap()
        ),
        ExitReason::Returned
    );
    (
        registers.x_reg_array[1].tagged_word(),
        registers.x_reg_array[2].tagged_word(),
    )
}

#[test]
fn native_i_bs_match_test_heap_checks_the_minimum_remaining_bits() {
    run_native(
        |asm| {
            asm.emit_i_bs_match_segments(
                ArgVal::X(0),
                99,
                0,
                1,
                &[BsmCommand::EnsureAtLeast { size: 8, unit: 1 }],
            )
        },
        0,
    );
}

#[test]
fn native_i_bs_get_position_returns_the_cursor() {
    let (_, position) = run_native(
        |asm| asm.emit_i_bs_get_position(ArgVal::X(0), ArgVal::X(2)),
        16,
    );
    assert_eq!(position, Term::small(16).unwrap().tagged_word());
}

#[test]
fn native_i_bs_set_position_restores_the_cursor() {
    let (_, position) = run_native(
        |asm| {
            asm.emit_i_bs_set_position(ArgVal::X(0), ArgVal::X(1))?;
            asm.emit_i_bs_get_position(ArgVal::X(0), ArgVal::X(2))
        },
        0,
    );
    assert_eq!(position, Term::small(1).unwrap().tagged_word());
}

#[test]
fn native_bs_test_unit_accepts_a_multiple_of_the_unit() {
    run_native(|asm| asm.emit_bs_test_unit(ArgVal::X(0), 8, 99), 0);
}

#[test]
fn native_bs_test_tail_branches_when_the_remaining_size_differs() {
    let (result, _) = run_native(
        |asm| {
            asm.emit_bs_test_tail2(
                ArgVal::X(0),
                ArgVal::Immediate(Term::small(7999).unwrap().tagged_word()),
                99,
            )
        },
        0,
    );
    assert_eq!(result, 77);
}

#[test]
fn native_i_bs_skip_bits2_advances_the_cursor() {
    let (_, position) = run_native(
        |asm| {
            asm.emit_i_bs_skip_bits2(
                ArgVal::X(0),
                ArgVal::Immediate(Term::small(2).unwrap().tagged_word()),
                8,
                99,
            )?;
            asm.emit_i_bs_get_position(ArgVal::X(0), ArgVal::X(2))
        },
        0,
    );
    assert_eq!(position, Term::small(16).unwrap().tagged_word());
}

#[test]
fn native_unaligned_match_context_fails_a_tail_size_check() {
    let (result, _) = run_native(
        |asm| {
            asm.emit_bs_test_tail2(
                ArgVal::X(0),
                ArgVal::Immediate(Term::small(8000).unwrap().tagged_word()),
                99,
            )
        },
        1,
    );
    assert_eq!(result, 77);
}
