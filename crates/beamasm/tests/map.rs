#![cfg(target_arch = "aarch64")]

use std::process::Command;

use arinsal_a64::enc::Gpr;
use arinsal_beamasm::{
    ExitReason, ProcessHeader, SchedulerRegisters, enter_native,
    map::MapRuntime,
    module::{ArgVal, BeamModuleAssembler, FinalizedModule, ModuleError},
};
use arinsal_term::{ProcessHeap, Term, TermBuilder};

fn runtime() -> MapRuntime {
    Box::leak(Box::new(
        arinsal_beamasm::map::MapFragments::new(0).unwrap(),
    ))
    .runtime()
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
    let reason = enter_native(&mut header, &mut regs, &module.entry(1).unwrap());
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
    let runtime = runtime();
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
    let runtime = runtime();
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
fn native_bool_ops_and_or() {
    for (expected, op) in [(0x0b_u64, false), (0x4b_u64, true)] {
        let result = run(
            |m| {
                if op {
                    m.emit_bif_or(90, ArgVal::X(0), ArgVal::X(1), ArgVal::X(2))
                } else {
                    m.emit_bif_and(90, ArgVal::X(0), ArgVal::X(1), ArgVal::X(2))
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
    let result = run(|m| m.emit_bif_not(90, ArgVal::X(0), ArgVal::X(2)), 0x4b, 0);
    assert_eq!(result, 0x0b);
    assert_eq!(erl("not true"), "false");
}

#[test]
fn native_bool_ops_badarg() {
    let and_result = run(
        |m| m.emit_bif_and(90, ArgVal::X(0), ArgVal::X(1), ArgVal::X(2)),
        bits(Term::small(1).unwrap()),
        0x4b,
    );
    let not_result = run(
        |m| m.emit_bif_not(90, ArgVal::X(0), ArgVal::X(2)),
        bits(Term::small(1).unwrap()),
        0,
    );
    assert_eq!(and_result, 0x3f0);
    assert_eq!(not_result, 0x3f0);
    assert!(erl("catch (1 and true)").contains("badarg"));
    assert!(erl("catch (not 1)").contains("badarg"));
}
