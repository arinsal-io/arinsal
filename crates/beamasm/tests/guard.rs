use std::{cell::RefCell, cmp::Ordering, collections::HashMap, process::Command, sync::Arc};

use arinsal_a64::enc::Gpr;
use arinsal_beamasm::{
    ExitReason, ProcessHeader, SchedulerRegisters, enter_native,
    module::{ArgVal, BeamModuleAssembler, ModuleError},
    rt,
    types::{ArgType, TypedArg, type_id},
};
use arinsal_term::{
    ExportEntry, FunEntry, ProcessHeap, Term, TermBuilder, TermKind, atoms, cmp, exact_eq,
    global_atoms, loose_eq,
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
    let function = b
        .local_fun(
            Arc::new(FunEntry {
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
                dispatch_code: Default::default(),
                dispatch_epoch: Default::default(),
            }),
            &[],
        )
        .unwrap();
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

fn term(word: u64) -> Option<Term> {
    ROOTS.with(|roots| roots.borrow().get(&word).copied())
}

fn bit_len(value: Term) -> Option<usize> {
    rt::binary_bit_len(value)
}

fn tuple_element(value: Term, index: usize) -> Option<Term> {
    rt::tuple_ref(value)?.get(index)
}

fn list_head_tail(value: Term) -> Option<(Term, Term)> {
    rt::cons_ref(value)
}

fn tuple_len(value: Term) -> Option<usize> {
    rt::tuple_ref(value).map(|tuple| tuple.len())
}

fn map_len(value: Term) -> Option<usize> {
    rt::flatmap_ref(value).map(|map| map.len())
}

fn map_lookup(map: Term, key: Term) -> Option<Term> {
    rt::flatmap_ref(map)?.get(key)
}

extern "C" fn guard_helper(_process: *mut ProcessHeader, op: u32, first: u64, second: u64) -> u64 {
    if op == 34 {
        return SELF_TERM.with(|this| this.borrow().map(bits).unwrap_or(u64::MAX));
    }
    if op == 43 {
        return u64::from(function_arity(
            term(first).unwrap_or(Term::NIL),
            term(second),
        ));
    }
    let Some(a) = term(first) else {
        return u64::MAX;
    };
    let b = term(second);
    let truth = |yes: bool| u64::from(yes);
    match op {
        0 => truth(a.as_small().is_some() || a.header().is_some_and(|h| matches!(h & 63, 8 | 12))),
        1 => truth(a.as_atom().is_some()),
        2 => truth(matches!(a.classify(), TermKind::List | TermKind::Nil)),
        3 => truth(a.classify() == TermKind::List),
        4 => truth(a == Term::NIL),
        5 => truth(a.classify() == TermKind::Tuple),
        6 => truth(arity_matches(a, b)),
        8 => truth(
            a.as_atom()
                .is_some_and(|atom| atom == atoms::TRUE || atom == atoms::FALSE),
        ),
        9 => truth(bit_len(a).is_some_and(|bits| bits.is_multiple_of(8))),
        10 => truth(a.classify() == TermKind::Bitstring),
        11 => truth(a.header().is_some_and(|h| h & 63 == 24)),
        12 => truth(a.classify() == TermKind::Number),
        13 => truth(a.classify() == TermKind::Pid),
        14 => truth(a.classify() == TermKind::Port),
        15 => truth(a.classify() == TermKind::Ref),
        16 => truth(a.classify() == TermKind::Map),
        17 => truth(a.classify() == TermKind::Fun),
        18 => truth(function_arity(a, b)),
        19 => truth(b.is_some_and(|rhs| exact_eq(a, rhs))),
        20 => truth(b.is_some_and(|rhs| !exact_eq(a, rhs))),
        21 => truth(b.is_some_and(|rhs| loose_eq(a, rhs))),
        22 => truth(b.is_some_and(|rhs| !loose_eq(a, rhs))),
        23 => truth(b.is_some_and(|rhs| cmp(a, rhs) == Ordering::Less)),
        24 => truth(b.is_some_and(|rhs| cmp(a, rhs) != Ordering::Less)),
        25 => b
            .and_then(|tuple| {
                a.as_small()
                    .and_then(|n| (n > 0).then_some(n as usize - 1))
                    .and_then(|i| tuple_element(tuple, i))
                    .map(bits)
            })
            .unwrap_or(u64::MAX),
        26 => list_head_tail(a)
            .map(|(head, _)| bits(head))
            .unwrap_or(u64::MAX),
        27 => list_head_tail(a)
            .map(|(_, tail)| bits(tail))
            .unwrap_or(u64::MAX),
        28 => tuple_len(a)
            .and_then(|len| Term::small(len as i64))
            .map(bits)
            .unwrap_or(u64::MAX),
        29 => map_len(a)
            .and_then(|len| Term::small(len as i64))
            .map(bits)
            .unwrap_or(u64::MAX),
        30 => b
            .and_then(|map| map_len(map).map(|_| map_lookup(map, a).is_some()))
            .map(|has_key| Term::atom(if has_key { atoms::TRUE } else { atoms::FALSE }))
            .map(bits)
            .unwrap_or(u64::MAX),
        31 => b
            .and_then(|map| map_lookup(map, a))
            .map(bits)
            .unwrap_or(u64::MAX),
        32 => bit_len(a)
            .and_then(|bits| bits.checked_div(8))
            .and_then(|n| Term::small(n as i64))
            .map(bits)
            .unwrap_or(u64::MAX),
        33 => bit_len(a)
            .and_then(|bits| Term::small(bits as i64))
            .map(bits)
            .unwrap_or(u64::MAX),
        34 => SELF_TERM.with(|this| this.borrow().map(bits).unwrap_or(u64::MAX)),
        35 => list_length(a)
            .and_then(|n| Term::small(n).map(bits))
            .unwrap_or(u64::MAX),
        36 => b
            .map(|rhs| {
                if cmp(a, rhs) == Ordering::Greater {
                    bits(rhs)
                } else {
                    bits(a)
                }
            })
            .unwrap_or(u64::MAX),
        37 => b
            .map(|rhs| {
                if cmp(a, rhs) == Ordering::Less {
                    bits(rhs)
                } else {
                    bits(a)
                }
            })
            .unwrap_or(u64::MAX),
        38 => a
            .as_small()
            .and_then(i64::checked_abs)
            .and_then(Term::small)
            .map(bits)
            .unwrap_or(u64::MAX),
        39 => a
            .identity()
            .map(|_| bits(Term::atom(atoms::NONAME)))
            .unwrap_or(u64::MAX),
        _ => u64::MAX,
    }
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
        arinsal_term::FunRef::Export { entry } => i64::from(entry.arity) == arity,
    })
}

fn list_length(value: Term) -> Option<i64> {
    let mut count = 0;
    let mut next = value;
    while next != Term::NIL {
        let (_, tail) = rt::cons_ref(next)?;
        count += 1;
        next = tail;
    }
    Some(count)
}

fn module(
    emit: impl FnOnce(&mut BeamModuleAssembler) -> Result<(), ModuleError>,
) -> arinsal_beamasm::module::FinalizedModule {
    let mut asm = BeamModuleAssembler::new();
    asm.emit_i_func_label(1).unwrap();
    emit(&mut asm).unwrap();
    asm.emit_raw(|e| {
        e.mov_reg(Gpr::x(0), Gpr::xzr())?;
        e.ret(Gpr::x(30))
    })
    .unwrap();
    asm.finalize().unwrap()
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
    let _fixture = terms();
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
            a.emit_test_arity(ArgVal::X(0), ArgVal::Immediate(bits(small(1))), 2)
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
        a.emit_is_tagged_tuple(
            ArgVal::X(0),
            ArgVal::Immediate(bits(small(1))),
            ArgVal::X(2),
            2,
        )?;
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
        |a| a.emit_is_eq_exact(ArgVal::X(0), ArgVal::X(1), 2, guard_helper),
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
        },
    );
    native_guard(
        |a| a.emit_is_eq_exact(typed, ArgVal::X(1), 2, exploding_helper),
        atom,
        atom,
        true,
    );
    native_guard(
        |a| a.emit_is_ne_exact(typed, ArgVal::X(1), 2, exploding_helper),
        atom,
        fixture.tuple,
        true,
    );
}

extern "C" fn exploding_helper(_: *mut ProcessHeader, _: u32, _: u64, _: u64) -> u64 {
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
                guard_helper,
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
                guard_helper,
            )
        },
        fixture.one_float,
        fixture.one,
        true,
    );
    let atom = Term::atom(global_atoms().intern("guard_alpha").unwrap());
    native_guard(
        |a| a.emit_is_eq_exact(ArgVal::X(0), ArgVal::Immediate(bits(atom)), 2, guard_helper),
        atom,
        atom,
        true,
    );
}
#[test]
fn native_is_ne_exact() {
    let f = terms();
    native_guard(
        |a| a.emit_is_ne_exact(ArgVal::X(0), ArgVal::X(1), 2, guard_helper),
        f.one,
        f.one_float,
        true,
    );
}
#[test]
fn unequal_immediates_skip_the_compare_helper() {
    let fixture = terms();
    let alpha = fixture
        .values
        .iter()
        .find(|(name, _)| *name == "atom")
        .unwrap()
        .1;
    let beta = Term::atom(global_atoms().intern("guard_beta").unwrap());
    native_guard(
        |a| a.emit_is_eq(ArgVal::X(0), ArgVal::X(1), 2, exploding_helper),
        alpha,
        beta,
        false,
    );
    native_guard(
        |a| a.emit_is_ne(ArgVal::X(0), ArgVal::X(1), 2, exploding_helper),
        alpha,
        beta,
        true,
    );
    native_guard(
        |a| a.emit_is_eq_exact(ArgVal::X(0), ArgVal::X(1), 2, exploding_helper),
        alpha,
        beta,
        false,
    );
    native_guard(
        |a| a.emit_is_ne_exact(ArgVal::X(0), ArgVal::X(1), 2, exploding_helper),
        alpha,
        beta,
        true,
    );
    native_guard(
        |a| a.emit_is_eq(ArgVal::X(0), ArgVal::X(1), 2, exploding_helper),
        alpha,
        alpha,
        true,
    );
}

#[test]
fn native_is_eq() {
    let f = terms();
    native_guard(
        |a| a.emit_is_eq(ArgVal::X(0), ArgVal::X(1), 2, guard_helper),
        f.one,
        f.one_float,
        true,
    );
}
#[test]
fn native_is_ne() {
    let f = terms();
    native_guard(
        |a| a.emit_is_ne(ArgVal::X(0), ArgVal::X(1), 2, guard_helper),
        f.one,
        f.one_float,
        false,
    );
}
#[test]
fn native_is_lt() {
    let f = terms();
    native_guard(
        |a| a.emit_is_lt(ArgVal::X(0), ArgVal::X(1), 2, guard_helper),
        f.one,
        Term::atom(atoms::TRUE),
        true,
    );
}

#[test]
fn relative_comparisons_use_small_immediates_and_fallback_for_bignums() {
    let fixture = terms();
    let two = small(2);
    native_guard(
        |a| a.emit_is_lt(ArgVal::X(0), ArgVal::Immediate(bits(two)), 2, guard_helper),
        fixture.one,
        two,
        true,
    );
    native_guard(
        |a| a.emit_is_ge(ArgVal::Immediate(bits(two)), ArgVal::X(0), 2, guard_helper),
        fixture.one,
        two,
        true,
    );
    let big = fixture
        .values
        .iter()
        .find(|(name, _)| *name == "bignum")
        .unwrap()
        .1;
    native_guard(
        |a| a.emit_is_ge(ArgVal::X(0), ArgVal::Immediate(bits(two)), 2, guard_helper),
        big,
        two,
        true,
    );
}
#[test]
fn native_is_ge() {
    let f = terms();
    native_guard(
        |a| a.emit_is_ge(ArgVal::X(0), ArgVal::X(1), 2, guard_helper),
        Term::atom(atoms::TRUE),
        f.one,
        true,
    );
}

#[test]
fn native_bif_element() {
    let f = terms();
    native_value(
        |a| a.emit_bif_element(0, ArgVal::X(0), ArgVal::X(1), ArgVal::X(0), guard_helper),
        small(1),
        f.tuple,
        bits(f.alpha),
    );
}
#[test]
fn native_bif_hd() {
    let f = terms();
    native_value(
        |a| a.emit_bif_hd(ArgVal::X(0), ArgVal::X(0), guard_helper),
        f.list,
        small(0),
        bits(f.one),
    );
}
#[test]
fn native_bif_tl() {
    let f = terms();
    native_value(
        |a| a.emit_bif_tl(ArgVal::X(0), ArgVal::X(0), guard_helper),
        f.list,
        small(0),
        bits(Term::NIL),
    );
}
#[test]
fn native_bif_tuple_size() {
    let f = terms();
    native_value(
        |a| a.emit_bif_tuple_size(0, ArgVal::X(0), ArgVal::X(0), guard_helper),
        f.tuple,
        small(0),
        bits(small(1)),
    );
}
#[test]
fn native_bif_map_size() {
    let f = terms();
    native_value(
        |a| a.emit_bif_map_size(0, ArgVal::X(0), ArgVal::X(0), guard_helper),
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
                    },
                ),
                ArgVal::X(0),
                guard_helper,
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
                    },
                ),
                ArgVal::X(0),
                guard_helper,
            )
        },
        small(20_000),
        small(0),
        false,
    );
}

#[test]
fn native_bif_is_map_key() {
    let f = terms();
    native_value(
        |a| {
            a.emit_bif_is_map_key(
                0,
                ArgVal::X(0),
                ArgVal::X(1),
                ArgVal::X(0),
                guard_helper,
                true,
                true,
                map_runtime(),
            )
        },
        f.alpha,
        f.map,
        bits(Term::atom(atoms::TRUE)),
    );
}

#[test]
fn native_bif_is_map_key_with_map_type() {
    let f = terms();
    native_value(
        |a| {
            a.emit_bif_is_map_key_typed(
                0,
                TypedArg::new(ArgVal::X(0), ArgType::ANY),
                TypedArg::new(
                    ArgVal::X(1),
                    ArgType {
                        union_bits: type_id::MAP,
                        min: None,
                        max: None,
                    },
                ),
                ArgVal::X(0),
                guard_helper,
                map_runtime(),
            )
        },
        f.alpha,
        f.map,
        bits(Term::atom(atoms::TRUE)),
    );
}
#[test]
fn native_bif_map_get() {
    let f = terms();
    native_value(
        |a| {
            a.emit_bif_map_get(
                0,
                ArgVal::X(0),
                ArgVal::X(1),
                ArgVal::X(0),
                guard_helper,
                true,
                true,
                map_runtime(),
            )
        },
        f.alpha,
        f.map,
        bits(f.one),
    );
}
#[test]
fn native_bif_byte_size() {
    let f = terms();
    native_value(
        |a| a.emit_bif_byte_size(0, ArgVal::X(0), ArgVal::X(0), guard_helper),
        f.binary,
        small(0),
        bits(small(1)),
    );
}
#[test]
fn native_bif_bit_size() {
    let f = terms();
    native_value(
        |a| a.emit_bif_bit_size(0, ArgVal::X(0), ArgVal::X(0), guard_helper),
        f.bitstring,
        small(0),
        bits(small(3)),
    );
}
#[test]
fn native_bif_self() {
    let f = terms();
    native_value(
        |a| a.emit_bif_self(ArgVal::X(0), guard_helper),
        small(0),
        small(0),
        bits(f.pid),
    );
}
#[test]
fn native_bif_node() {
    let f = terms();
    native_value(
        |a| a.emit_bif_node(0, ArgVal::X(0), ArgVal::X(0), guard_helper),
        f.pid,
        small(0),
        bits(Term::atom(atoms::NONAME)),
    );
}
#[test]
fn native_bif_length() {
    let f = terms();
    native_value(
        |a| a.emit_bif_length(0, ArgVal::X(0), ArgVal::X(0), guard_helper),
        f.list,
        small(0),
        bits(small(1)),
    );
}
#[test]
fn native_bif_min() {
    let f = terms();
    native_value(
        |a| a.emit_bif_min(ArgVal::X(0), ArgVal::X(1), ArgVal::X(0), guard_helper),
        f.one,
        f.one_float,
        bits(f.one),
    );
}
#[test]
fn native_bif_max() {
    let f = terms();
    native_value(
        |a| a.emit_bif_max(ArgVal::X(0), ArgVal::X(1), ArgVal::X(0), guard_helper),
        f.one,
        f.one_float,
        bits(f.one),
    );
}
#[test]
fn native_bif_abs() {
    let _f = terms();
    native_value(
        |a| a.emit_bif_abs(0, ArgVal::X(0), ArgVal::X(0), guard_helper),
        small(-9),
        small(0),
        bits(small(9)),
    );
}

extern "C" fn unused_map_get(_p: *mut ProcessHeader, _map: u64, _key: u64, _hash: u64) -> u64 {
    0
}
extern "C" fn unused_get_elements(
    _p: *mut ProcessHeader,
    _a: u64,
    _b: u64,
    _c: u64,
    _d: u64,
) -> u64 {
    0
}
extern "C" fn unused_map_update(_p: *mut ProcessHeader, _a: u64, _b: u64, _c: u64, _d: u64) -> u64 {
    0
}

/// Map runtime with real lookup fragments; the other helpers are unused by `map_get`.
fn map_runtime() -> arinsal_beamasm::map::MapRuntime {
    let fragments = Box::leak(Box::new(
        arinsal_beamasm::map::MapFragments::new(unused_map_get, unused_map_update).unwrap(),
    ));
    arinsal_beamasm::map::MapRuntime {
        get: unused_map_get,
        get_elements: unused_get_elements,
        new_map: unused_map_update,
        update_assoc: unused_map_update,
        update_exact: unused_map_update,
        put_single: unused_map_update,
        update_single_exact_shared: fragments.update_single_exact_shared(),
        get_element_shared: fragments.get_element_shared(),
        get_element_hash_shared: fragments.get_element_hash_shared(),
    }
}

#[test]
fn native_is_tuple_of_arity() {
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:1611-1625 (emit_i_is_tuple_of_arity),
    // OTP-29.1.1.
    for arity in [1, 2] {
        native_predicate(
            |a| a.emit_is_tuple_of_arity(ArgVal::X(0), ArgVal::Immediate(bits(small(arity))), 2, 2),
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
            a.emit_is_tuple_of_arity(ArgVal::X(0), ArgVal::Immediate(bits(small(arity))), 2, 3)?;
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

fn erlang_dynamic_function_matrix() -> Option<Vec<Vec<bool>>> {
    let eval = r#"Values=[1,1 bsl 80,1.0,guard_alpha,true,false,[],[1],{guard_alpha},{guard_beta,1},#{guard_alpha=>1},<<16#a5>>,<<5:3>>,self(),open_port({spawn,"/usr/bin/true"},[]),make_ref(),fun(X)->X end,fun erlang:node/0],io:format("~w",[[[if is_function(F,A)->true; true->false end||A<-Values]||F<-Values]]),halt()."#;
    let output = match Command::new("timeout")
        .args(["30", "erl", "-noshell", "-eval", eval])
        .output()
    {
        Ok(output) => output,
        Err(error) => {
            eprintln!("skipping OTP dynamic function differential: cannot run timeout: {error}");
            return None;
        }
    };
    if output.status.code() == Some(127) {
        eprintln!("skipping OTP dynamic function differential: erl is not installed");
        return None;
    }
    assert!(
        output.status.success(),
        "OTP dynamic function matrix failed: {}",
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
    assert_eq!(
        booleans.len(),
        18 * 18,
        "unexpected OTP dynamic function matrix"
    );
    Some(booleans.chunks(18).map(<[bool]>::to_vec).collect())
}

#[test]
fn native_type_guards_match_otp_29() {
    let Some(expected) = erlang_type_matrix() else {
        return;
    };
    let Some(dynamic_expected) = erlang_dynamic_function_matrix() else {
        return;
    };
    let fixture = terms();
    assert_eq!(fixture.values.len(), 18);
    let one = ArgVal::Immediate(bits(small(1)));
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
            Box::new(move |asm| asm.emit_is_function2_guard(ArgVal::X(0), one, 2)),
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

    let finalized = module(|asm| {
        asm.emit_is_function2(
            ArgVal::X(0),
            one,
            arinsal_beamasm::guard::Function2TestTarget::LegacyBoolean(guard_helper),
        )
    });
    for (index, (_, value)) in fixture.values.iter().enumerate() {
        let regs = run(&finalized, *value, zero_term(*value));
        assert_eq!(
            regs[0],
            u64::from(expected[18][index]),
            "OTP function arity row, term {}",
            fixture.values[index].0
        );
    }

    let finalized = module(|asm| {
        asm.emit_is_function2_guard_with_helper(ArgVal::X(0), ArgVal::X(1), 2, guard_helper)?;
        asm.move_(ArgVal::Immediate(1), ArgVal::X(1))?;
        asm.emit_raw(|e| {
            e.mov_reg(Gpr::x(0), Gpr::xzr())?;
            e.ret(Gpr::x(30))
        })?;
        asm.emit_i_func_label(2)?;
        asm.move_(ArgVal::Immediate(0), ArgVal::X(1))
    });
    for (function_index, (_, function)) in fixture.values.iter().enumerate() {
        for (arity_index, (_, arity)) in fixture.values.iter().enumerate() {
            let regs = run(&finalized, *function, *arity);
            assert_eq!(
                regs[1],
                u64::from(dynamic_expected[function_index][arity_index]),
                "dynamic function arity for {function:?} and {arity:?}"
            );
        }
    }
}
