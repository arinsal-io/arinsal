use std::{cell::Cell, process::Command, sync::atomic::AtomicPtr};

use arinsal_a64::enc::Gpr;
use arinsal_beamasm::{
    ExitReason, ProcessHeader, SchedulerRegisters, enter_native,
    map::MapRuntime,
    module::{ArgVal, BeamModuleAssembler, FinalizedModule, ModuleError},
};
use arinsal_term::{ProcessHeap, Term, TermBuilder};

thread_local! { static RESULT: Cell<u64> = const { Cell::new(0) }; static HASHMAP_VALUE: Cell<u64> = const { Cell::new(0) }; static HASHMAP_STAGE: Cell<u64> = const { Cell::new(0) }; }
static ACTIVE_REGS: AtomicPtr<SchedulerRegisters> = AtomicPtr::new(std::ptr::null_mut());

extern "C" fn panic_get(_p: *mut ProcessHeader, _map: u64, _key: u64, _stage: u64) -> u64 {
    panic!("flatmap lookup must stay inline")
}
extern "C" fn hashmap_get(_p: *mut ProcessHeader, _map: u64, _key: u64, stage: u64) -> u64 {
    HASHMAP_STAGE.with(|value| value.set(stage));
    HASHMAP_VALUE.with(Cell::get)
}
extern "C" fn get_elements(
    _process: *mut ProcessHeader,
    _map: u64,
    _module: u64,
    _table: u64,
    _stack: u64,
) -> u64 {
    arinsal_beamasm::rt::scheduler_registers_mut(
        ACTIVE_REGS.load(std::sync::atomic::Ordering::Relaxed),
        |registers| {
            registers.x_reg_array[2] = Term::small(42).unwrap();
            registers.x_reg_array[3] = Term::small(43).unwrap();
        },
    );
    1
}
extern "C" fn update(_p: *mut ProcessHeader, _a: u64, _b: u64, _c: u64, _d: u64) -> u64 {
    RESULT.with(Cell::get)
}
extern "C" fn guard_helper(_p: *mut ProcessHeader, _op: u32, _a: u64, _b: u64) -> u64 {
    0
}

fn runtime() -> MapRuntime {
    runtime_with(hashmap_get)
}
/// A runtime whose lookup fragments are built around `get`.
fn runtime_with(get: arinsal_beamasm::map::MapGetHelper) -> MapRuntime {
    let fragments = Box::leak(Box::new(
        arinsal_beamasm::map::MapFragments::new(get, update).unwrap(),
    ));
    MapRuntime {
        get,
        get_elements,
        lookup_module: 0,
        new_map: update,
        update_assoc: update,
        update_exact: update,
        put_single: update,
        update_single_exact_shared: fragments.update_single_exact_shared(),
        get_element_shared: fragments.get_element_shared(),
        get_element_hash_shared: fragments.get_element_hash_shared(),
    }
}
fn bits(term: Term) -> u64 {
    arinsal_beamasm::rt::term_bits(term)
}
fn erl(expr: &str) -> String {
    let eval = format!("io:format(\"~p\",[{}]),halt().", expr);
    let output = Command::new("erl")
        .args(["-noshell", "-eval", &eval])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "erl failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}
fn erl_int(expr: &str) -> i64 {
    erl(expr).parse().unwrap()
}

fn run(
    emit: impl FnOnce(&mut BeamModuleAssembler) -> Result<(), ModuleError>,
    regs0: u64,
    regs1: u64,
) -> u64 {
    let mut asm = BeamModuleAssembler::new();
    asm.emit_i_func_label(1).unwrap();
    // Like a compiled function: CP lives on the stack because fragment calls clobber LR.
    asm.emit_raw(|e| e.str_pre(Gpr::x(30), Gpr::x(20), -8))
        .unwrap();
    emit(&mut asm).unwrap();
    asm.move_(ArgVal::X(2), ArgVal::X(0)).unwrap();
    asm.emit_raw(|e| e.mov_reg(Gpr::x(0), Gpr::xzr())).unwrap();
    asm.emit_raw(|e| e.ldr_post(Gpr::x(30), Gpr::x(20), 8))
        .unwrap();
    asm.emit_raw(|e| e.ret(Gpr::x(30))).unwrap();
    asm.emit_i_func_label(90).unwrap();
    asm.emit_raw(|e| e.mov_const(Gpr::x(25), 0x3f0)).unwrap();
    asm.emit_raw(|e| e.mov_reg(Gpr::x(0), Gpr::xzr())).unwrap();
    asm.emit_raw(|e| e.ldr_post(Gpr::x(30), Gpr::x(20), 8))
        .unwrap();
    asm.emit_raw(|e| e.ret(Gpr::x(30))).unwrap();
    let module: FinalizedModule = asm.finalize().unwrap();
    let mut heap = [0_u64; 128];
    let mut header = ProcessHeader {
        htop: heap.as_mut_ptr(),
        stop: heap.as_mut_ptr().wrapping_add(heap.len()),
        heap: heap.as_mut_ptr(),
        hend: heap.as_mut_ptr().wrapping_add(heap.len()),
        fcalls: 100,
        ..ProcessHeader::default()
    };
    let mut regs = SchedulerRegisters::default();
    regs.x_reg_array[0] = arinsal_beamasm::rt::fixture_term(regs0);
    regs.x_reg_array[1] = arinsal_beamasm::rt::fixture_term(regs1);
    ACTIVE_REGS.store(&mut regs, std::sync::atomic::Ordering::Relaxed);
    let reason = enter_native(&mut header, &mut regs, &module.entry(1).unwrap());
    ACTIVE_REGS.store(std::ptr::null_mut(), std::sync::atomic::Ordering::Relaxed);
    assert_eq!(reason, ExitReason::Returned);
    regs.x_reg_array[0].tagged_word()
}

fn flatmap() -> (ProcessHeap, Term, Term) {
    let mut heap = ProcessHeap::with_words(256);
    let a = Term::small(7).unwrap();
    let b = Term::small(42).unwrap();
    let map = TermBuilder::new(&mut heap)
        .flatmap_from_pairs(&[(a, b)])
        .unwrap();
    (heap, map, a)
}

#[test]
fn native_flatmap_get_inline() {
    let (_heap, map, key) = flatmap();
    let runtime = runtime_with(panic_get);
    let result = run(
        |m| {
            m.emit_i_get_map_element(
                90,
                ArgVal::X(0),
                ArgVal::Immediate(bits(key)),
                ArgVal::X(2),
                runtime,
            )?;
            Ok(())
        },
        bits(map),
        bits(key),
    );
    assert_eq!((result >> 4) as i64, erl_int("maps:get(7, #{7 => 42})"));
}

#[test]
fn native_flatmap_miss() {
    let (_heap, map, _) = flatmap();
    let runtime = runtime_with(panic_get);
    let key = Term::small(99).unwrap();
    let result = run(
        |m| {
            m.emit_i_get_map_element(
                90,
                ArgVal::X(0),
                ArgVal::Immediate(bits(key)),
                ArgVal::X(2),
                runtime,
            )?;
            Ok(())
        },
        bits(map),
        bits(key),
    );
    assert_eq!(result, 0x3f0);
}

#[test]
fn native_dynamic_key_uses_runtime_lookup() {
    let (_heap, map, key) = flatmap();
    HASHMAP_VALUE.with(|value| value.set(bits(Term::small(42).unwrap())));
    let result = run(
        |m| {
            m.emit_i_get_map_element(90, ArgVal::X(0), ArgVal::X(1), ArgVal::X(2), runtime())?;
            Ok(())
        },
        bits(map),
        bits(key),
    );
    assert_eq!((result >> 4) as i64, erl_int("maps:get(7, #{7 => 42})"));
}

#[test]
fn native_hashmap_get() {
    // OTP's map representation changes to a HAMT after 32 entries.
    let mut heap = ProcessHeap::with_words(4096);
    let pairs = (0..40)
        .map(|n| (Term::small(n).unwrap(), Term::small(n + 100).unwrap()))
        .collect::<Vec<_>>();
    let map = TermBuilder::new(&mut heap)
        .flatmap_from_pairs(&pairs)
        .unwrap();
    HASHMAP_VALUE.with(|value| value.set(bits(Term::small(139).unwrap())));
    HASHMAP_STAGE.with(|value| value.set(0));
    let result = run(
        |m| {
            m.emit_i_get_map_element(
                90,
                ArgVal::X(0),
                ArgVal::Immediate(bits(Term::small(39).unwrap())),
                ArgVal::X(2),
                runtime(),
            )?;
            Ok(())
        },
        bits(map),
        bits(Term::small(39).unwrap()),
    );
    assert_eq!(
        (result >> 4) as i64,
        erl_int("maps:get(39, maps:from_list([{N,N+100} || N <- lists:seq(0,39)]))")
    );
    HASHMAP_STAGE
        .with(|stage| assert_eq!(stage.get(), 0, "HAMT lookup should find its leaf inline"));
}

#[test]
fn native_get_elements() {
    let mut heap = ProcessHeap::with_words(256);
    let key7 = Term::small(7).unwrap();
    let key8 = Term::small(8).unwrap();
    let map = TermBuilder::new(&mut heap)
        .flatmap_from_pairs(&[
            (key7, Term::small(42).unwrap()),
            (key8, Term::small(43).unwrap()),
        ])
        .unwrap();
    let result = run(
        |m| {
            m.emit_i_get_map_elements(
                90,
                ArgVal::X(0),
                &[
                    ArgVal::Immediate(bits(Term::small(7).unwrap())),
                    ArgVal::X(2),
                    ArgVal::Immediate(0),
                    ArgVal::Immediate(bits(Term::small(8).unwrap())),
                    ArgVal::X(3),
                    ArgVal::Immediate(0),
                ],
                runtime(),
            )
        },
        bits(map),
        0,
    );
    assert_eq!(
        (result >> 4) as i64,
        erl_int("maps:get(7, #{7 => 42, 8 => 43})")
    );
}

#[test]
fn native_new_map() {
    let (_heap, map, _) = flatmap();
    RESULT.with(|value| value.set(bits(map)));
    assert_eq!(
        run(|m| m.emit_new_map(ArgVal::X(2), 0, &[], runtime()), 0, 0),
        bits(map)
    );
    assert_eq!(erl_int("maps:size(#{} )"), 0);
}

#[test]
fn native_update_assoc() {
    let (_heap, map, _) = flatmap();
    RESULT.with(|value| value.set(bits(map)));
    assert_eq!(
        run(
            |m| m.emit_update_map_assoc(
                ArgVal::X(0),
                ArgVal::X(2),
                0,
                &[
                    ArgVal::Immediate(bits(Term::small(8).unwrap())),
                    ArgVal::Immediate(bits(Term::small(99).unwrap()))
                ],
                runtime()
            ),
            bits(map),
            0
        ),
        bits(map)
    );
    assert_eq!(erl_int("maps:get(7, #{7 => 42})"), 42);
}

#[test]
fn native_update_exact() {
    let (_heap, map, _) = flatmap();
    RESULT.with(|value| value.set(bits(map)));
    assert_eq!(
        run(
            |m| m.emit_update_map_exact(
                ArgVal::X(0),
                90,
                ArgVal::X(2),
                0,
                &[
                    ArgVal::Immediate(bits(Term::small(7).unwrap())),
                    ArgVal::Immediate(bits(Term::small(99).unwrap()))
                ],
                runtime()
            ),
            bits(map),
            0
        ),
        bits(map)
    );
    assert_eq!(erl_int("maps:get(7, #{7 => 42})"), 42);
}

#[test]
fn native_update_exact_badkey() {
    RESULT.with(|value| value.set(0));
    assert_eq!(
        run(
            |m| m.emit_update_map_exact(
                ArgVal::X(0),
                90,
                ArgVal::X(2),
                0,
                &[
                    ArgVal::Immediate(bits(Term::small(9).unwrap())),
                    ArgVal::Immediate(bits(Term::small(1).unwrap()))
                ],
                runtime()
            ),
            0,
            0
        ),
        0x3f0
    );
    assert!(erl("catch maps:update(9, 1, #{})").contains("badkey"));
}

#[test]
fn native_bool_ops_and_or() {
    for (expected, op) in [(0x0b_u64, false), (0x4b_u64, true)] {
        let result = run(
            |m| {
                if op {
                    m.emit_bif_or(90, ArgVal::X(0), ArgVal::X(1), ArgVal::X(2), guard_helper)
                } else {
                    m.emit_bif_and(90, ArgVal::X(0), ArgVal::X(1), ArgVal::X(2), guard_helper)
                }
            },
            0x4b,
            0x0b,
        );
        assert_eq!(result, expected);
    }
    assert_eq!(erl("false and true"), "false");
}

#[test]
fn native_bool_ops_not() {
    let result = run(
        |m| m.emit_bif_not(90, ArgVal::X(0), ArgVal::X(2), guard_helper),
        0x4b,
        0,
    );
    assert_eq!(result, 0x0b);
    assert_eq!(erl("not true"), "false");
}

#[test]
fn native_bool_ops_badarg() {
    let and_result = run(
        |m| m.emit_bif_and(90, ArgVal::X(0), ArgVal::X(1), ArgVal::X(2), guard_helper),
        bits(Term::small(1).unwrap()),
        0x4b,
    );
    let not_result = run(
        |m| m.emit_bif_not(90, ArgVal::X(0), ArgVal::X(2), guard_helper),
        bits(Term::small(1).unwrap()),
        0,
    );
    assert_eq!(and_result, 0x3f0);
    assert_eq!(not_result, 0x3f0);
    assert!(erl("catch (1 and true)").contains("badarg"));
    assert!(erl("catch (not 1)").contains("badarg"));
}
