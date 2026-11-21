#![cfg(target_arch = "aarch64")]

use std::{cell::RefCell, collections::HashMap, process::Command, sync::Arc};

use arinsal_a64::enc::Gpr;
use arinsal_beamasm::{
    ExitReason, ProcessHeader, SchedulerRegisters, enter_native,
    module::{ArgVal, BeamModuleAssembler, ModuleError},
    rt,
    types::{ArgType, TypedArg, type_id},
};
use arinsal_term::{
    ExportEntry, FunEntry, ProcessHeap, Term, TermBuilder, TermKind, atoms, exact_eq, global_atoms,
};
use similar_asserts::assert_eq;

thread_local! {
    static ROOTS: RefCell<HashMap<u64, Term>> = RefCell::new(HashMap::new());
    static SELF_TERM: RefCell<Option<Term>> = const { RefCell::new(None) };
}

struct Terms {
    _heap: ProcessHeap,
    values: Vec<(&'static str, Term)>,
    one: Term,
    one_float: Term,
    tuple: Term,
    list: Term,
    binary: Term,
    bitstring: Term,
    map: Term,
    pid: Term,
    alpha: Term,
}

fn terms() -> Terms {
    let mut heap = ProcessHeap::with_words(2048);
    let mut b = TermBuilder::new(&mut heap);
    let alpha_atom = global_atoms().intern("guard_alpha").unwrap();
    let beta = global_atoms().intern("guard_beta").unwrap();
    let one = Term::small(1).unwrap();
    let one_float = b.float(1.0).unwrap();
    let tuple = b.tuple(&[Term::atom(alpha_atom)]).unwrap();
    let pair = b.tuple(&[Term::atom(beta), one]).unwrap();
    let list = b.cons(one, Term::NIL).unwrap();
    let binary = b.binary(&[0xa5]).unwrap();
    let bitstring = b.bitstring(&[0xa0], 3).unwrap();
    let map = b
        .flatmap_from_pairs(&[(Term::atom(alpha_atom), one)])
        .unwrap();
    let big = b.int_from_i128(1_i128 << 80).unwrap();
    let pid = Term::pid(4, 2).unwrap();
    let port = Term::port(7).unwrap();
    let reference = b.local_ref([1, 2, 3]).unwrap();
    let module = global_atoms().intern("guard_test").unwrap();
    let fun_entry = Arc::new(FunEntry {
        dispatch_target: Default::default(),
        pend_purge_address: Default::default(),
        module,
        arity: 1,
        index: 1,
        uniq: [0; 16],
        old_uniq: 1,
        old_index: 1,
        pid,
        dispatch: Default::default(),
        dispatch_epoch: Default::default(),
    });
    let function = b.local_fun(&fun_entry, &[]).unwrap();
    let export = b
        .export_fun(Arc::new(ExportEntry::new(module, alpha_atom, 0)))
        .unwrap();
    let values = vec![
        ("small", one),
        ("bignum", big),
        ("float", one_float),
        ("atom", Term::atom(alpha_atom)),
        ("true", Term::atom(atoms::TRUE)),
        ("false", Term::atom(atoms::FALSE)),
        ("nil", Term::NIL),
        ("list", list),
        ("tuple", tuple),
        ("pair", pair),
        ("map", map),
        ("binary", binary),
        ("bitstring", bitstring),
        ("pid", pid),
        ("port", port),
        ("reference", reference),
        ("function", function),
        ("export", export),
    ];
    let fixture = Terms {
        _heap: heap,
        values,
        one,
        one_float,
        tuple,
        list,
        binary,
        bitstring,
        map,
        pid,
        alpha: Term::atom(alpha_atom),
    };
    register(&fixture);
    fixture
}

fn register(fixture: &Terms) {
    ROOTS.with(|roots| {
        let mut roots = roots.borrow_mut();
        roots.clear();
        for (_, term) in &fixture.values {
            roots.insert(bits(*term), *term);
        }
        for value in [-9, -1, 0, 1, 2, 3, 8] {
            let term = Term::small(value).unwrap();
            roots.insert(bits(term), term);
        }
    });
    SELF_TERM.with(|this| *this.borrow_mut() = Some(fixture.pid));
}

fn bits(term: Term) -> u64 {
    rt::term_bits(term)
}

fn bit_len(value: Term) -> Option<usize> {
    rt::binary_bit_len(value)
}

fn arity_matches(value: Term, arity: Option<Term>) -> bool {
    let Some(arity) = arity.and_then(Term::as_small) else {
        return false;
    };
    rt::tuple_ref(value).is_some_and(|tuple| tuple.len() == arity as usize)
}

fn function_arity(value: Term, arity: Option<Term>) -> bool {
    let Some(arity) = arity.and_then(Term::as_small) else {
        return false;
    };
    rt::fun_ref(value).is_some_and(|fun| match fun {
        arinsal_term::FunRef::Local { entry, .. } => i64::from(entry.arity) == arity,
        arinsal_term::FunRef::Export { entry } => i64::from(entry.arity()) == arity,
    })
}

fn module(
    emit: impl FnOnce(&mut BeamModuleAssembler) -> Result<(), ModuleError>,
) -> arinsal_beamasm::module::FinalizedModule {
    module_with_literals(&[], emit)
}

fn module_with_literals(
    literals: &[(i64, u64)],
    emit: impl FnOnce(&mut BeamModuleAssembler) -> Result<(), ModuleError>,
) -> arinsal_beamasm::module::FinalizedModule {
    let mut asm = BeamModuleAssembler::new();
    for &(index, word) in literals {
        asm.set_beam_literal(index, word);
    }
    asm.emit_i_func_label(1).unwrap();
    emit(&mut asm).unwrap();
    asm.emit_raw(|e| {
        e.mov_reg(Gpr::x(0), Gpr::xzr())?;
        e.ret(Gpr::x(30))
    })
    .unwrap();
    let mut module = asm.finalize().unwrap();
    for &(index, word) in literals {
        module.patch_literal(index, word).unwrap();
    }
    module
}

fn run(
    module: &arinsal_beamasm::module::FinalizedModule,
    first: Term,
    second: Term,
) -> [u64; 1024] {
    let mut regs = SchedulerRegisters::default();
    regs.x_reg_array[0] = arinsal_beamasm::rt::fixture_term(bits(first));
    regs.x_reg_array[1] = arinsal_beamasm::rt::fixture_term(bits(second));
    let mut stack = [0u64; 128];
    let stack_end = stack.as_mut_ptr().wrapping_add(stack.len());
    let mut header = ProcessHeader {
        stop: stack_end,
        fcalls: 10,
        self_pid: SELF_TERM.with(|this| this.borrow().map(bits).unwrap_or(0)),
        ..ProcessHeader::default()
    };
    let exit = enter_native(&mut header, &mut regs, &module.entry(1).unwrap());
    assert_eq!(exit, ExitReason::Returned);
    arinsal_beamasm::rt::fixture_words(&regs.x_reg_array)
        .try_into()
        .unwrap()
}

fn native_predicate(
    emit: impl FnOnce(&mut BeamModuleAssembler) -> Result<(), ModuleError>,
    expected: impl Fn(Term, Term) -> bool,
    second_for: impl Fn(Term) -> Term,
) {
    let fixture = terms();
    let finalized = module(|asm| {
        emit(asm)?;
        asm.move_(ArgVal::Immediate(1), ArgVal::X(1))?;
        asm.emit_raw(|e| {
            e.mov_reg(Gpr::x(0), Gpr::xzr())?;
            e.ret(Gpr::x(30))
        })?;
        asm.emit_i_func_label(2)?;
        asm.move_(ArgVal::Immediate(0), ArgVal::X(1))
    });
    for (_, value) in &fixture.values {
        let second = second_for(*value);
        let regs = run(&finalized, *value, second);
        assert_eq!(
            regs[1],
            u64::from(expected(*value, second)),
            "term {value:?}"
        );
    }
}

fn native_value(
    emit: impl FnOnce(&mut BeamModuleAssembler) -> Result<(), ModuleError>,
    first: Term,
    second: Term,
    expected: u64,
) {
    let _fixture = terms();
    let finalized = module(|asm| {
        // Like a compiled function: CP lives on the stack because fragment calls clobber LR.
        asm.emit_raw(|e| e.str_pre(Gpr::x(30), Gpr::x(20), -8))?;
        emit(asm)?;
        asm.move_(ArgVal::X(0), ArgVal::X(1))?;
        asm.emit_raw(|e| {
            e.mov_reg(Gpr::x(0), Gpr::xzr())?;
            e.ldr_post(Gpr::x(30), Gpr::x(20), 8)?;
            e.ret(Gpr::x(30))
        })
    });
    ROOTS.with(|roots| {
        let mut roots = roots.borrow_mut();
        roots.insert(bits(first), first);
        roots.insert(bits(second), second);
    });
    let regs = run(&finalized, first, second);
    assert_eq!(regs[1], expected);
}

fn native_guard(
    emit: impl FnOnce(&mut BeamModuleAssembler) -> Result<(), ModuleError>,
    first: Term,
    second: Term,
    expected: bool,
) {
    native_guard_with_literals(&[], emit, first, second, expected);
}

fn native_guard_literal(
    emit: impl FnOnce(&mut BeamModuleAssembler) -> Result<(), ModuleError>,
    literal: Term,
    first: Term,
    second: Term,
    expected: bool,
) {
    native_guard_with_literals(&[(0, bits(literal))], emit, first, second, expected);
}

fn native_guard_with_literals(
    literals: &[(i64, u64)],
    emit: impl FnOnce(&mut BeamModuleAssembler) -> Result<(), ModuleError>,
    first: Term,
    second: Term,
    expected: bool,
) {
    let _fixture = terms();
    let finalized = module_with_literals(literals, |asm| {
        emit(asm)?;
        asm.move_(ArgVal::Immediate(1), ArgVal::X(1))?;
        asm.emit_raw(|e| {
            e.mov_reg(Gpr::x(0), Gpr::xzr())?;
            e.ret(Gpr::x(30))
        })?;
        asm.emit_i_func_label(2)?;
        asm.move_(ArgVal::Immediate(0), ArgVal::X(1))
    });
    ROOTS.with(|roots| {
        let mut roots = roots.borrow_mut();
        roots.insert(bits(first), first);
        roots.insert(bits(second), second);
    });
    let regs = run(&finalized, first, second);
    assert_eq!(regs[1], u64::from(expected));
}

fn small(n: i64) -> Term {
    Term::small(n).unwrap()
}
fn zero_term(_: Term) -> Term {
    small(0)
}
fn type_matches(op: u32, value: Term, second: Term) -> bool {
    match op {
        0 => value.as_small().is_some() || value.header().is_some_and(|h| matches!(h & 63, 8 | 12)),
        1 => value.as_atom().is_some(),
        2 => matches!(value.classify(), TermKind::List | TermKind::Nil),
        3 => value.classify() == TermKind::List,
        4 => value == Term::NIL,
        5 => value.classify() == TermKind::Tuple,
        6 => arity_matches(value, Some(second)),
        8 => value
            .as_atom()
            .is_some_and(|atom| atom == atoms::TRUE || atom == atoms::FALSE),
        9 => bit_len(value).is_some_and(|bits| bits.is_multiple_of(8)),
        10 => value.classify() == TermKind::Bitstring,
        11 => value.header().is_some_and(|h| h & 63 == 24),
        12 => value.classify() == TermKind::Number,
        13 => value.classify() == TermKind::Pid,
        14 => value.classify() == TermKind::Port,
        15 => value.classify() == TermKind::Ref,
        16 => value.classify() == TermKind::Map,
        17 => value.classify() == TermKind::Fun,
        18 => function_arity(value, Some(second)),
        _ => unreachable!(),
    }
}

#[test]
fn native_is_integer() {
    native_predicate(
        |a| a.emit_is_integer(ArgVal::X(0), 2),
        |x, y| type_matches(0, x, y),
        zero_term,
    );
}
#[test]
fn native_is_atom() {
    native_predicate(
        |a| a.emit_is_atom(ArgVal::X(0), 2),
        |x, y| type_matches(1, x, y),
        zero_term,
    );
}
#[test]
fn native_is_list() {
    native_predicate(
        |a| a.emit_is_list(ArgVal::X(0), 2),
        |x, y| type_matches(2, x, y),
        zero_term,
    );
}
#[test]
fn native_is_nonempty_list() {
    native_predicate(
        |a| a.emit_is_nonempty_list(ArgVal::X(0), 2),
        |x, y| type_matches(3, x, y),
        zero_term,
    );
}
#[test]
fn native_is_nil() {
    native_predicate(
        |a| a.emit_is_nil(ArgVal::X(0), 2),
        |x, y| type_matches(4, x, y),
        zero_term,
    );
}
#[test]
fn native_is_tuple() {
    native_predicate(
        |a| a.emit_is_tuple(ArgVal::X(0), 2),
        |x, y| type_matches(5, x, y),
        zero_term,
    );
}
#[test]
fn native_test_arity() {
    native_predicate(
        |a| {
            a.emit_is_tuple(ArgVal::X(0), 2)?;
            a.emit_test_arity(ArgVal::X(0), ArgVal::Immediate(1 << 6), 2)
        },
        |x, y| type_matches(6, x, y),
        |_| small(1),
    );
}
#[test]
fn native_is_tagged_tuple() {
    let fixture = terms();
    let tag = fixture.alpha;
    let finalized = module(|a| {
        a.emit_is_tagged_tuple(ArgVal::X(0), ArgVal::Immediate(1 << 6), ArgVal::X(2), 2)?;
        a.move_(ArgVal::Immediate(1), ArgVal::X(1))?;
        a.emit_raw(|e| {
            e.mov_reg(Gpr::x(0), Gpr::xzr())?;
            e.ret(Gpr::x(30))
        })?;
        a.emit_i_func_label(2)?;
        a.move_(ArgVal::Immediate(0), ArgVal::X(1))
    });
    for (_, value) in &fixture.values {
        let mut regs = SchedulerRegisters::default();
        regs.x_reg_array[0] = arinsal_beamasm::rt::fixture_term(bits(*value));
        regs.x_reg_array[1] = arinsal_beamasm::rt::fixture_term(bits(small(1)));
        regs.x_reg_array[2] = arinsal_beamasm::rt::fixture_term(bits(tag));
        let mut stack = [0u64; 128];
        let stop = stack.as_mut_ptr().wrapping_add(stack.len());
        let mut header = ProcessHeader {
            stop,
            fcalls: 10,
            ..ProcessHeader::default()
        };
        let exit = enter_native(&mut header, &mut regs, &finalized.entry(1).unwrap());
        assert_eq!(exit, ExitReason::Returned);
        // Fixture tuple has its atom tag; the other table terms do not match.
        assert_eq!(
            regs.x_reg_array[1],
            arinsal_beamasm::rt::fixture_term(u64::from(*value == fixture.tuple))
        );
    }
}
#[test]
fn native_is_boolean() {
    native_predicate(
        |a| a.emit_is_boolean(ArgVal::X(0), 2),
        |x, y| type_matches(8, x, y),
        zero_term,
    );
}
#[test]
fn native_is_binary() {
    native_predicate(
        |a| a.emit_is_binary(ArgVal::X(0), 2),
        |x, y| type_matches(9, x, y),
        zero_term,
    );
}
#[test]
fn native_is_bitstring() {
    native_predicate(
        |a| a.emit_is_bitstring(ArgVal::X(0), 2),
        |x, y| type_matches(10, x, y),
        zero_term,
    );
}
#[test]
fn native_is_float() {
    native_predicate(
        |a| a.emit_is_float(ArgVal::X(0), 2),
        |x, y| type_matches(11, x, y),
        zero_term,
    );
}
#[test]
fn native_is_number() {
    native_predicate(
        |a| a.emit_is_number(ArgVal::X(0), 2),
        |x, y| type_matches(12, x, y),
        zero_term,
    );
}
#[test]
fn native_is_pid() {
    native_predicate(
        |a| a.emit_is_pid(ArgVal::X(0), 2),
        |x, y| type_matches(13, x, y),
        zero_term,
    );
}
#[test]
fn native_is_port() {
    native_predicate(
        |a| a.emit_is_port(ArgVal::X(0), 2),
        |x, y| type_matches(14, x, y),
        zero_term,
    );
}
#[test]
fn native_is_reference() {
    native_predicate(
        |a| a.emit_is_reference(ArgVal::X(0), 2),
        |x, y| type_matches(15, x, y),
        zero_term,
    );
}
#[test]
fn native_is_map() {
    native_predicate(
        |a| a.emit_is_map(ArgVal::X(0), 2),
        |x, y| type_matches(16, x, y),
        zero_term,
    );
}

#[test]
fn native_is_map_with_map_type() {
    let f = terms();
    native_guard(
        |a| {
            a.emit_is_map(
                TypedArg::new(
                    ArgVal::X(0),
                    ArgType {
                        union_bits: type_id::MAP,
                        min: None,
                        max: None,
                        unit: 1,
                    },
                ),
                2,
            )
        },
        f.map,
        small(0),
        true,
    );
}

#[test]
fn native_is_map_with_integer_type() {
    native_guard(
        |a| {
            a.emit_is_map(
                TypedArg::new(
                    ArgVal::X(0),
                    ArgType {
                        union_bits: type_id::INTEGER,
                        min: None,
                        max: None,
                        unit: 1,
                    },
                ),
                2,
            )
        },
        small(20_000),
        small(0),
        false,
    );
}

#[test]
fn native_is_reference_with_reference_type_matches_otp() {
    let Some(expected) = erlang_type_matrix() else {
        return;
    };
    let fixture = terms();
    let index = fixture
        .values
        .iter()
        .position(|(name, _)| *name == "reference")
        .unwrap();
    let value = fixture.values[index].1;
    native_guard(
        |a| {
            a.emit_is_reference(
                TypedArg::new(
                    ArgVal::X(0),
                    ArgType {
                        union_bits: type_id::REFERENCE,
                        min: None,
                        max: None,
                        unit: 1,
                    },
                ),
                2,
            )
        },
        value,
        small(0),
        expected[15][index],
    );
}

#[test]
fn native_is_function() {
    native_predicate(
        |a| a.emit_is_function(ArgVal::X(0), 2),
        |x, y| type_matches(17, x, y),
        zero_term,
    );
}
#[test]
fn native_is_function2() {
    native_predicate(
        |a| a.emit_is_function2_guard(ArgVal::X(0), ArgVal::Immediate(bits(small(1))), 2),
        |x, y| type_matches(18, x, y),
        |_| small(1),
    );
}

#[test]
fn native_is_eq_exact() {
    let f = terms();
    native_guard(
        |a| {
            a.emit_is_eq_exact(
                ArgVal::X(0),
                ArgVal::X(1),
                2,
                (eq_helper as extern "C" fn(u64, u64) -> i32) as usize,
            )
        },
        f.one,
        f.one_float,
        false,
    );
}

#[test]
fn typed_atom_exact_compare_does_not_call_the_runtime() {
    let fixture = terms();
    let atom = fixture
        .values
        .iter()
        .find(|(name, _)| *name == "atom")
        .unwrap()
        .1;
    let typed = TypedArg::new(
        ArgVal::X(0),
        ArgType {
            union_bits: type_id::ATOM,
            min: None,
            max: None,
            unit: 1,
        },
    );
    native_guard(
        |a| {
            a.emit_is_eq_exact(
                typed,
                ArgVal::X(1),
                2,
                (exploding_eq as extern "C" fn(u64, u64) -> i32) as usize,
            )
        },
        atom,
        atom,
        true,
    );
    native_guard(
        |a| {
            a.emit_is_ne_exact(
                typed,
                ArgVal::X(1),
                2,
                (exploding_eq as extern "C" fn(u64, u64) -> i32) as usize,
            )
        },
        atom,
        fixture.tuple,
        true,
    );
}

/// The C `eq` the general path calls: exact equality of two terms.
extern "C" fn eq_helper(a: u64, b: u64) -> i32 {
    i32::from(exact_eq(rt::fixture_term(a), rt::fixture_term(b)))
}

extern "C" fn exploding_eq(_: u64, _: u64) -> i32 {
    panic!("always-immediate comparison must not call the runtime");
}

#[test]
fn exact_comparisons_against_small_and_atom_immediates_are_inline() {
    let fixture = terms();
    native_guard(
        |a| {
            a.emit_is_eq_exact(
                ArgVal::X(0),
                ArgVal::Immediate(bits(fixture.one)),
                2,
                (eq_helper as extern "C" fn(u64, u64) -> i32) as usize,
            )
        },
        fixture.one,
        fixture.one,
        true,
    );
    native_guard(
        |a| {
            a.emit_is_ne_exact(
                ArgVal::X(0),
                ArgVal::Immediate(bits(fixture.one)),
                2,
                (eq_helper as extern "C" fn(u64, u64) -> i32) as usize,
            )
        },
        fixture.one_float,
        fixture.one,
        true,
    );
    let atom = Term::atom(global_atoms().intern("guard_alpha").unwrap());
    native_guard(
        |a| {
            a.emit_is_eq_exact(
                ArgVal::X(0),
                ArgVal::Immediate(bits(atom)),
                2,
                (eq_helper as extern "C" fn(u64, u64) -> i32) as usize,
            )
        },
        atom,
        atom,
        true,
    );
}
#[test]
fn native_is_ne_exact() {
    let f = terms();
    native_guard(
        |a| {
            a.emit_is_ne_exact(
                ArgVal::X(0),
                ArgVal::X(1),
                2,
                (eq_helper as extern "C" fn(u64, u64) -> i32) as usize,
            )
        },
        f.one,
        f.one_float,
        true,
    );
}

#[test]
fn native_bif_element() {
    let f = terms();
    native_value(
        |a| a.emit_bif_element(0, ArgVal::X(0), ArgVal::X(1), ArgVal::X(0)),
        small(1),
        f.tuple,
        bits(f.alpha),
    );
}
#[test]
fn native_bif_hd() {
    let f = terms();
    native_value(
        |a| a.emit_bif_hd(ArgVal::X(0), ArgVal::X(0)),
        f.list,
        small(0),
        bits(f.one),
    );
}
#[test]
fn native_bif_tl() {
    let f = terms();
    native_value(
        |a| a.emit_bif_tl(ArgVal::X(0), ArgVal::X(0)),
        f.list,
        small(0),
        bits(Term::NIL),
    );
}
#[test]
fn native_bif_tuple_size() {
    let f = terms();
    native_value(
        |a| a.emit_bif_tuple_size(0, ArgVal::X(0), ArgVal::X(0)),
        f.tuple,
        small(0),
        bits(small(1)),
    );
}
#[test]
fn native_bif_map_size() {
    let f = terms();
    native_value(
        |a| a.emit_bif_map_size(0, ArgVal::X(0), ArgVal::X(0)),
        f.map,
        small(0),
        bits(small(1)),
    );
}

#[test]
fn native_bif_map_size_with_map_type() {
    let f = terms();
    native_value(
        |a| {
            a.emit_bif_map_size_typed(
                0,
                TypedArg::new(
                    ArgVal::X(0),
                    ArgType {
                        union_bits: type_id::MAP,
                        min: None,
                        max: None,
                        unit: 1,
                    },
                ),
                ArgVal::X(0),
            )
        },
        f.map,
        small(0),
        bits(small(1)),
    );
}

#[test]
fn native_bif_map_size_with_integer_type() {
    native_guard(
        |a| {
            a.emit_bif_map_size_typed(
                2,
                TypedArg::new(
                    ArgVal::X(0),
                    ArgType {
                        union_bits: type_id::INTEGER,
                        min: None,
                        max: None,
                        unit: 1,
                    },
                ),
                ArgVal::X(0),
            )
        },
        small(20_000),
        small(0),
        false,
    );
}

#[test]
fn native_bif_byte_size() {
    let f = terms();
    native_value(
        |a| a.emit_bif_byte_size(0, ArgVal::X(0), ArgVal::X(0)),
        f.binary,
        small(0),
        bits(small(1)),
    );
}
#[test]
fn native_bif_bit_size() {
    let f = terms();
    native_value(
        |a| a.emit_bif_bit_size(0, ArgVal::X(0), ArgVal::X(0)),
        f.bitstring,
        small(0),
        bits(small(3)),
    );
}
#[test]
fn native_bif_self() {
    let f = terms();
    native_value(
        |a| a.emit_bif_self(ArgVal::X(0)),
        small(0),
        small(0),
        bits(f.pid),
    );
}

#[test]
fn native_is_tuple_of_arity() {
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:1611-1625 (emit_i_is_tuple_of_arity),
    // OTP-29.1.1.
    for arity in [1, 2] {
        native_predicate(
            |a| {
                a.emit_is_tuple_of_arity(ArgVal::X(0), ArgVal::Immediate((arity as u64) << 6), 2, 2)
            },
            |x, _| arity_matches(x, Some(small(arity))),
            zero_term,
        );
    }
}

#[test]
fn native_is_tuple_of_arity_ff() {
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:1627-1653
    // (emit_i_is_tuple_of_arity_ff), OTP-29.1.1: a non-tuple fails to the first label, a
    // tuple of another arity to the second.
    let fixture = terms();
    for arity in [1, 2] {
        let finalized = module(|a| {
            a.emit_is_tuple_of_arity(ArgVal::X(0), ArgVal::Immediate((arity as u64) << 6), 2, 3)?;
            a.move_(ArgVal::Immediate(1), ArgVal::X(1))?;
            a.emit_raw(|e| {
                e.mov_reg(Gpr::x(0), Gpr::xzr())?;
                e.ret(Gpr::x(30))
            })?;
            a.emit_i_func_label(2)?;
            a.move_(ArgVal::Immediate(0), ArgVal::X(1))?;
            a.emit_raw(|e| {
                e.mov_reg(Gpr::x(0), Gpr::xzr())?;
                e.ret(Gpr::x(30))
            })?;
            a.emit_i_func_label(3)?;
            a.move_(ArgVal::Immediate(2), ArgVal::X(1))
        });
        for (_, value) in &fixture.values {
            let regs = run(&finalized, *value, zero_term(*value));
            let expected = if value.classify() != TermKind::Tuple {
                0
            } else if arity_matches(*value, Some(small(arity))) {
                1
            } else {
                2
            };
            assert_eq!(regs[1], expected, "term {value:?} arity {arity}");
        }
    }
}

fn erlang_type_matrix() -> Option<Vec<Vec<bool>>> {
    let eval = r#"Port=open_port({spawn,"/usr/bin/true"},[]),Values=[1,1 bsl 80,1.0,guard_alpha,true,false,[],[1],{guard_alpha},{guard_beta,1},#{guard_alpha=>1},<<16#a5>>,<<5:3>>,self(),Port,make_ref(),fun(X)->X end,fun erlang:node/0],Ps=[fun erlang:is_integer/1,fun erlang:is_atom/1,fun erlang:is_list/1,fun(V)->is_list(V) andalso V=/=[] end,fun(V)->V=:=[] end,fun erlang:is_tuple/1,fun(V)->is_tuple(V) andalso tuple_size(V)=:=1 end,fun(V)->is_tuple(V) andalso tuple_size(V)=:=1 andalso element(1,V)=:=guard_alpha end,fun erlang:is_boolean/1,fun erlang:is_binary/1,fun erlang:is_bitstring/1,fun erlang:is_float/1,fun erlang:is_number/1,fun erlang:is_pid/1,fun erlang:is_port/1,fun erlang:is_reference/1,fun erlang:is_map/1,fun erlang:is_function/1,fun(V)->is_function(V,1) end],io:format("~w",[[[P(V)||V<-Values]||P<-Ps]]),halt()."#;
    let output = match Command::new("timeout")
        .args(["30", "erl", "-noshell", "-eval", eval])
        .output()
    {
        Ok(output) => output,
        Err(error) => {
            eprintln!("skipping OTP type differential: cannot run timeout: {error}");
            return None;
        }
    };
    if output.status.code() == Some(127) {
        eprintln!("skipping OTP type differential: erl is not installed");
        return None;
    }
    assert!(
        output.status.success(),
        "OTP type matrix failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let booleans = String::from_utf8_lossy(&output.stdout)
        .split(|ch: char| !ch.is_ascii_alphabetic())
        .filter_map(|word| match word {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(booleans.len(), 19 * 18, "unexpected OTP type matrix");
    Some(booleans.chunks(18).map(<[bool]>::to_vec).collect())
}

#[test]
fn native_type_guards_match_otp_29() {
    let Some(expected) = erlang_type_matrix() else {
        return;
    };
    let fixture = terms();
    assert_eq!(fixture.values.len(), 18);
    let one = ArgVal::Immediate(1 << 6);
    let function_one = ArgVal::Immediate(bits(small(1)));
    let tag = ArgVal::Immediate(bits(fixture.alpha));
    type Emitter = Box<dyn Fn(&mut BeamModuleAssembler) -> Result<(), ModuleError>>;
    let cases: Vec<(usize, Emitter)> = vec![
        (0, Box::new(|asm| asm.emit_is_integer(ArgVal::X(0), 2))),
        (1, Box::new(|asm| asm.emit_is_atom(ArgVal::X(0), 2))),
        (2, Box::new(|asm| asm.emit_is_list(ArgVal::X(0), 2))),
        (
            3,
            Box::new(|asm| asm.emit_is_nonempty_list(ArgVal::X(0), 2)),
        ),
        (4, Box::new(|asm| asm.emit_is_nil(ArgVal::X(0), 2))),
        (5, Box::new(|asm| asm.emit_is_tuple(ArgVal::X(0), 2))),
        (
            6,
            Box::new(move |asm| {
                asm.emit_is_tuple(ArgVal::X(0), 2)?;
                asm.emit_test_arity(ArgVal::X(0), one, 2)
            }),
        ),
        (
            6,
            Box::new(move |asm| asm.emit_is_tuple_of_arity(ArgVal::X(0), one, 2, 2)),
        ),
        (
            7,
            Box::new(move |asm| asm.emit_is_tagged_tuple(ArgVal::X(0), one, tag, 2)),
        ),
        (
            7,
            Box::new(move |asm| asm.emit_is_tagged_tuple_ff(ArgVal::X(0), one, tag, 2, 2)),
        ),
        (8, Box::new(|asm| asm.emit_is_boolean(ArgVal::X(0), 2))),
        (9, Box::new(|asm| asm.emit_is_binary(ArgVal::X(0), 2))),
        (10, Box::new(|asm| asm.emit_is_bitstring(ArgVal::X(0), 2))),
        (11, Box::new(|asm| asm.emit_is_float(ArgVal::X(0), 2))),
        (12, Box::new(|asm| asm.emit_is_number(ArgVal::X(0), 2))),
        (13, Box::new(|asm| asm.emit_is_pid(ArgVal::X(0), 2))),
        (14, Box::new(|asm| asm.emit_is_port(ArgVal::X(0), 2))),
        (15, Box::new(|asm| asm.emit_is_reference(ArgVal::X(0), 2))),
        (16, Box::new(|asm| asm.emit_is_map(ArgVal::X(0), 2))),
        (17, Box::new(|asm| asm.emit_is_function(ArgVal::X(0), 2))),
        (
            18,
            Box::new(move |asm| asm.emit_is_function2_guard(ArgVal::X(0), function_one, 2)),
        ),
    ];
    for (row, emit) in cases {
        let finalized = module(|asm| {
            emit(asm)?;
            asm.move_(ArgVal::Immediate(1), ArgVal::X(1))?;
            asm.emit_raw(|e| {
                e.mov_reg(Gpr::x(0), Gpr::xzr())?;
                e.ret(Gpr::x(30))
            })?;
            asm.emit_i_func_label(2)?;
            asm.move_(ArgVal::Immediate(0), ArgVal::X(1))
        });
        for (index, (_, value)) in fixture.values.iter().enumerate() {
            let regs = run(&finalized, *value, zero_term(*value));
            assert_eq!(
                regs[1],
                u64::from(expected[row][index]),
                "OTP type row {row}, term {}",
                fixture.values[index].0
            );
        }
    }
}

/// Literal terms and the values compared with them, for the inline `=:=` / `=/=` shapes.
struct ShapeFixture {
    _heap: ProcessHeap,
    c: Term,
    one: Term,
    three: Term,
    one_float: Term,
    pair_c3: Term,
    pair_c4: Term,
    pair_d3: Term,
    triple_c3c: Term,
    pair_c_float: Term,
    map_one: Term,
    map_empty: Term,
    list1: Term,
    list_c: Term,
    list_11: Term,
    bin_empty: Term,
    bin_one: Term,
}

fn shape_fixture() -> ShapeFixture {
    let mut heap = ProcessHeap::with_words(2048);
    let mut b = TermBuilder::new(&mut heap);
    let c = Term::atom(global_atoms().intern("guard_c").unwrap());
    let d = Term::atom(global_atoms().intern("guard_d").unwrap());
    let one = small(1);
    let three = small(3);
    let one_float = b.float(1.0).unwrap();
    let pair_c3 = b.tuple(&[c, three]).unwrap();
    let pair_c4 = b.tuple(&[c, small(4)]).unwrap();
    let pair_d3 = b.tuple(&[d, three]).unwrap();
    let triple_c3c = b.tuple(&[c, three, c]).unwrap();
    let pair_c_float = b.tuple(&[c, one_float]).unwrap();
    let map_one = b.flatmap_from_pairs(&[(c, one)]).unwrap();
    let map_empty = b.flatmap_from_pairs(&[]).unwrap();
    let list1 = b.cons(one, Term::NIL).unwrap();
    let list_c = b.cons(c, Term::NIL).unwrap();
    let list_11 = b.cons(one, list1).unwrap();
    let bin_empty = b.binary(&[]).unwrap();
    let bin_one = b.binary(&[0xa5]).unwrap();
    ShapeFixture {
        _heap: heap,
        c,
        one,
        three,
        one_float,
        pair_c3,
        pair_c4,
        pair_d3,
        triple_c3c,
        pair_c_float,
        map_one,
        map_empty,
        list1,
        list_c,
        list_11,
        bin_empty,
        bin_one,
    }
}

/// Checks `=:=` and `=/=` against a literal shape for each `(value, equal)` case.
fn check_shape(literal: Term, cases: &[(Term, bool)]) {
    for &(value, equal) in cases {
        native_guard_literal(
            |a| {
                a.emit_is_eq_exact(
                    ArgVal::X(0),
                    ArgVal::Literal(0),
                    2,
                    (eq_helper as extern "C" fn(u64, u64) -> i32) as usize,
                )
            },
            literal,
            value,
            literal,
            equal,
        );
        native_guard_literal(
            |a| {
                a.emit_is_ne_exact(
                    ArgVal::X(0),
                    ArgVal::Literal(0),
                    2,
                    (eq_helper as extern "C" fn(u64, u64) -> i32) as usize,
                )
            },
            literal,
            value,
            literal,
            !equal,
        );
    }
}

#[test]
fn shallow_tuple_literal_matches_inline() {
    let f = shape_fixture();
    check_shape(
        f.pair_c3,
        &[
            (f.pair_c3, true),
            // Wrong element: same arity and header.
            (f.pair_c4, false),
            (f.pair_d3, false),
            // Wrong arity.
            (f.triple_c3c, false),
            // Wrong header: a map with the same first word count.
            (f.map_one, false),
            // Element is boxed (a float) and must not match an immediate.
            (f.pair_c_float, false),
            // Non-boxed operand.
            (f.three, false),
            (f.c, false),
        ],
    );
}

#[test]
fn list_of_immediates_literal_matches_inline() {
    let f = shape_fixture();
    check_shape(
        f.list1,
        &[
            (f.list1, true),
            // Wrong head.
            (f.list_c, false),
            // Wrong length: the tail is a cons, not nil.
            (f.list_11, false),
            // Non-boxed and wrong-tag operands.
            (f.three, false),
            (f.pair_c3, false),
        ],
    );
    check_shape(
        f.list_11,
        &[(f.list_11, true), (f.list1, false), (f.list_c, false)],
    );
}

#[test]
fn empty_binary_literal_matches_inline() {
    let f = shape_fixture();
    check_shape(
        f.bin_empty,
        &[
            (f.bin_empty, true),
            (f.bin_one, false),
            (f.three, false),
            (f.pair_c3, false),
        ],
    );
}

#[test]
fn empty_map_literal_matches_inline() {
    let f = shape_fixture();
    check_shape(
        f.map_empty,
        &[
            (f.map_empty, true),
            (f.map_one, false),
            (f.pair_c3, false),
            (f.three, false),
        ],
    );
}

#[test]
fn generic_literal_takes_the_eq_call() {
    let f = shape_fixture();
    // `1 =:= 1.0` is false: the float is boxed and only the general path can tell.
    native_guard_literal(
        |a| {
            a.emit_is_eq_exact(
                ArgVal::X(0),
                ArgVal::Literal(0),
                2,
                (eq_helper as extern "C" fn(u64, u64) -> i32) as usize,
            )
        },
        f.one_float,
        f.one,
        f.one_float,
        false,
    );
    native_guard_literal(
        |a| {
            a.emit_is_eq_exact(
                ArgVal::X(0),
                ArgVal::Literal(0),
                2,
                (eq_helper as extern "C" fn(u64, u64) -> i32) as usize,
            )
        },
        f.one_float,
        f.one_float,
        f.one_float,
        true,
    );
}

/// Like erts' `emit_enter_runtime()` with its default live count, the deep exact comparison
/// keeps X4 and X5 (caller-saved machine registers) across the C `eq` call, whose caller does
/// not tell how many X registers are live.
#[test]
fn exact_comparison_runtime_call_keeps_x4_and_x5() {
    let fixture = terms();
    let mut clobber = BeamModuleAssembler::new();
    clobber
        .emit_raw(|e| {
            e.mov_const(Gpr::x(15), 0xdead_0015)?;
            e.mov_const(Gpr::x(16), 0xdead_0016)?;
            e.mov_const(Gpr::x(0), 1)?;
            e.ret(Gpr::x(30))
        })
        .unwrap();
    let clobber = clobber.finalize().unwrap();
    let eq = clobber.memory.ptr_at(0) as usize;
    let finalized = module(|asm| {
        asm.emit_is_eq_exact(ArgVal::X(0), ArgVal::X(1), 2, eq)?;
        asm.emit_raw(|e| {
            e.mov_reg(Gpr::x(0), Gpr::xzr())?;
            e.ret(Gpr::x(30))
        })?;
        asm.emit_i_func_label(2)?;
        asm.emit_raw(|e| {
            e.mov_reg(Gpr::x(0), Gpr::xzr())?;
            e.ret(Gpr::x(30))
        })
    });
    let mut regs = SchedulerRegisters::default();
    for index in 0..6 {
        regs.x_reg_array[index] = rt::fixture_term(0x1000 + index as u64);
    }
    regs.x_reg_array[0] = rt::fixture_term(bits(fixture.tuple));
    regs.x_reg_array[1] = rt::fixture_term(bits(fixture.binary));
    let mut stack = [0u64; 128];
    let mut header = ProcessHeader {
        stop: stack.as_mut_ptr().wrapping_add(stack.len()),
        fcalls: 10,
        ..ProcessHeader::default()
    };
    let exit = enter_native(&mut header, &mut regs, &finalized.entry(1).unwrap());
    assert_eq!(exit, ExitReason::Returned);
    for index in 4..6 {
        assert_eq!(
            regs.x_reg_array[index],
            rt::fixture_term(0x1000 + index as u64)
        );
    }
}
