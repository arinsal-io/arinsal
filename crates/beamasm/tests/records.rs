#![cfg(target_arch = "aarch64")]

use std::sync::{Mutex, OnceLock};

use arinsal_a64::enc::Gpr;
use arinsal_beamasm::{
    ExitReason, ProcessHeader, SchedulerRegisters, enter_native,
    module::{ArgVal, BeamModuleAssembler, FinalizedModule},
    rt,
};
use arinsal_term::{Atom, ProcessHeap, Term, TermBuilder, global_atoms};
use similar_asserts::assert_eq;

static FIXTURE: OnceLock<Mutex<(ProcessHeap, Term, Term)>> = OnceLock::new();

fn fixture() -> (u64, u64) {
    let fixture = FIXTURE.get_or_init(|| {
        let mut heap = ProcessHeap::with_words(128);
        let module = global_atoms().intern("record_native_test").unwrap();
        let name = global_atoms().intern("sample").unwrap();
        let field = global_atoms().intern("value").unwrap();
        let record = TermBuilder::new(&mut heap)
            .native_record(module, name, true, &[(field, Term::small(42).unwrap())])
            .unwrap();
        let updated = TermBuilder::new(&mut heap)
            .native_record(module, name, true, &[(field, Term::small(99).unwrap())])
            .unwrap();
        Mutex::new((heap, record, updated))
    });
    let guard = fixture.lock().unwrap();
    (rt::term_bits(guard.1), rt::term_bits(guard.2))
}

fn run_native(
    emit: impl FnOnce(&mut BeamModuleAssembler) -> Result<(), arinsal_beamasm::module::ModuleError>,
    setup: impl FnOnce(&mut [u64; 128], &mut ProcessHeader, &mut SchedulerRegisters),
) -> (ExitReason, ProcessHeader, [u64; 1024], [u64; 128]) {
    run_native_with_literals(&[], emit, setup)
}

fn run_native_with_literals(
    literals: &[(i64, u64)],
    emit: impl FnOnce(&mut BeamModuleAssembler) -> Result<(), arinsal_beamasm::module::ModuleError>,
    setup: impl FnOnce(&mut [u64; 128], &mut ProcessHeader, &mut SchedulerRegisters),
) -> (ExitReason, ProcessHeader, [u64; 1024], [u64; 128]) {
    let mut asm = BeamModuleAssembler::new();
    for &(index, word) in literals {
        asm.set_beam_literal(index, word);
    }
    asm.emit_i_func_label(1).unwrap();
    asm.emit_enter_frame().unwrap();
    emit(&mut asm).unwrap();
    asm.emit_raw(|e| {
        e.mov_reg(Gpr::x(0), Gpr::xzr())?;
        e.ldr_post(Gpr::x(30), Gpr::x(20), 8)?;
        e.ret(Gpr::x(30))
    })
    .unwrap();
    let mut module: FinalizedModule = asm.finalize().unwrap();
    for &(index, word) in literals {
        module.patch_literal(index, word).unwrap();
    }
    let mut heap = [0_u64; 128];
    let base = heap.as_mut_ptr();
    let mut header = ProcessHeader {
        htop: base,
        heap: base,
        hend: base.wrapping_add(heap.len()),
        stop: base.wrapping_add(heap.len()),
        fcalls: 100,
        ..ProcessHeader::default()
    };
    let mut regs = SchedulerRegisters::default();
    setup(&mut heap, &mut header, &mut regs);
    let exit = enter_native(&mut header, &mut regs, &module.entry(1).unwrap());
    (
        exit,
        header,
        rt::fixture_words(&regs.x_reg_array).try_into().unwrap(),
        heap,
    )
}

fn atom(name: &str) -> Atom {
    global_atoms().intern(name).unwrap()
}

fn tagged_small(value: i64) -> u64 {
    ((value as u64) << 4) | 15
}

#[test]
fn native_is_native_record() {
    let (record, _) = fixture();
    let module = rt::term_bits(Term::atom(atom("record_native_test")));
    let name = rt::term_bits(Term::atom(atom("sample")));
    let (exit, _, regs, _) = run_native(
        |asm| {
            asm.emit_is_any_native_record(2, ArgVal::X(0))?;
            asm.emit_is_native_record(
                2,
                ArgVal::X(0),
                ArgVal::Immediate(module),
                ArgVal::Immediate(name),
            )?;
            asm.move_(ArgVal::Immediate(tagged_small(1)), ArgVal::X(1))?;
            asm.emit_raw(|e| {
                e.mov_reg(Gpr::x(0), Gpr::xzr())?;
                e.ldr_post(Gpr::x(30), Gpr::x(20), 8)?;
                e.ret(Gpr::x(30))
            })?;
            asm.emit_i_func_label(2)?;
            asm.move_(ArgVal::Immediate(tagged_small(2)), ArgVal::X(1))?;
            asm.emit_raw(|e| {
                e.mov_reg(Gpr::x(0), Gpr::xzr())?;
                e.ldr_post(Gpr::x(30), Gpr::x(20), 8)?;
                e.ret(Gpr::x(30))
            })
        },
        |_, _, regs| regs.x_reg_array[0] = arinsal_beamasm::rt::fixture_term(record),
    );
    assert_eq!(exit, ExitReason::Returned);
    assert_eq!(regs[1], tagged_small(1));
    let (exit, _, regs, _) = run_native(
        |asm| {
            asm.emit_is_any_native_record(2, ArgVal::X(0))?;
            asm.emit_is_native_record(
                2,
                ArgVal::X(0),
                ArgVal::Immediate(module),
                ArgVal::Immediate(name),
            )?;
            asm.move_(ArgVal::Immediate(tagged_small(1)), ArgVal::X(1))?;
            asm.emit_raw(|e| {
                e.mov_reg(Gpr::x(0), Gpr::xzr())?;
                e.ldr_post(Gpr::x(30), Gpr::x(20), 8)?;
                e.ret(Gpr::x(30))
            })?;
            asm.emit_i_func_label(2)?;
            asm.move_(ArgVal::Immediate(tagged_small(2)), ArgVal::X(1))?;
            asm.emit_raw(|e| {
                e.mov_reg(Gpr::x(0), Gpr::xzr())?;
                e.ldr_post(Gpr::x(30), Gpr::x(20), 8)?;
                e.ret(Gpr::x(30))
            })
        },
        |_, _, regs| regs.x_reg_array[0] = Term::small(7).unwrap(),
    );
    assert_eq!(exit, ExitReason::Returned);
    assert_eq!(regs[1], tagged_small(2));
}

#[test]
fn native_record_accessibility() {
    let (record, _) = fixture();
    for external in [true, false] {
        let module = rt::term_bits(Term::atom(atom("record_native_test")));
        let (exit, _, regs, _) = run_native(
            |asm| {
                asm.emit_is_record_accessible(
                    2,
                    ArgVal::X(0),
                    external,
                    ArgVal::Immediate(module),
                )?;
                asm.move_(ArgVal::Immediate(tagged_small(1)), ArgVal::X(1))?;
                asm.emit_raw(|e| {
                    e.mov_reg(Gpr::x(0), Gpr::xzr())?;
                    e.ldr_post(Gpr::x(30), Gpr::x(20), 8)?;
                    e.ret(Gpr::x(30))
                })?;
                asm.emit_i_func_label(2)?;
                asm.move_(ArgVal::Immediate(tagged_small(2)), ArgVal::X(1))?;
                asm.emit_raw(|e| {
                    e.mov_reg(Gpr::x(0), Gpr::xzr())?;
                    e.ldr_post(Gpr::x(30), Gpr::x(20), 8)?;
                    e.ret(Gpr::x(30))
                })
            },
            |_, _, regs| regs.x_reg_array[0] = arinsal_beamasm::rt::fixture_term(record),
        );
        assert_eq!(exit, ExitReason::Returned);
        assert_eq!(regs[1], tagged_small(1));
    }
}

/// A record of `module` that is not exported, kept alive in a leaked heap for the test.
fn private_record(module: &str) -> u64 {
    let heap = Box::leak(Box::new(ProcessHeap::with_words(64)));
    let record = TermBuilder::new(heap)
        .native_record(
            atom(module),
            atom("sample"),
            false,
            &[(atom("value"), Term::small(1).unwrap())],
        )
        .unwrap();
    rt::term_bits(record)
}

/// Returns 1 when `is_record_accessible` falls through and 2 when it takes the fail label.
fn accessible(record: u64, external: bool, current_module: &str) -> u64 {
    let module = rt::term_bits(Term::atom(atom(current_module)));
    let (exit, _, regs, _) = run_native(
        |asm| {
            asm.emit_is_record_accessible(2, ArgVal::X(0), external, ArgVal::Immediate(module))?;
            asm.move_(ArgVal::Immediate(tagged_small(1)), ArgVal::X(1))?;
            asm.emit_raw(|e| {
                e.mov_reg(Gpr::x(0), Gpr::xzr())?;
                e.ldr_post(Gpr::x(30), Gpr::x(20), 8)?;
                e.ret(Gpr::x(30))
            })?;
            asm.emit_i_func_label(2)?;
            asm.move_(ArgVal::Immediate(tagged_small(2)), ArgVal::X(1))?;
            asm.emit_raw(|e| {
                e.mov_reg(Gpr::x(0), Gpr::xzr())?;
                e.ldr_post(Gpr::x(30), Gpr::x(20), 8)?;
                e.ret(Gpr::x(30))
            })
        },
        |_, _, regs| regs.x_reg_array[0] = arinsal_beamasm::rt::fixture_term(record),
    );
    assert_eq!(exit, ExitReason::Returned);
    regs[1] >> 4
}

#[test]
fn unexported_records_are_accessible_only_from_their_module() {
    let private = private_record("record_private_owner");
    // An external access always needs an exported record; a local one also accepts the
    // defining module.
    assert_eq!(accessible(private, true, "record_private_owner"), 2);
    assert_eq!(accessible(private, false, "record_private_owner"), 1);
    assert_eq!(accessible(private, false, "record_private_other"), 2);
    let (exported, _) = fixture();
    assert_eq!(accessible(exported, true, "record_private_other"), 1);
    assert_eq!(accessible(exported, false, "record_private_other"), 1);
}
