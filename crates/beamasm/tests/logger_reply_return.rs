use arinsal_beamasm::{
    ExitReason, ProcessHeader, SchedulerRegisters, enter_native,
    map::MapRuntime,
    module::{ArgVal, BeamModuleAssembler, FinalizedModule},
    rt::{read_heap_word, term_bits},
};
use arinsal_term::{ProcessHeap, Term, TermBuilder, global_atoms};

extern "C" fn unused_map_get(_p: *mut ProcessHeader, _map: u64, _key: u64, _hash: u64) -> u64 {
    atom("true")
}

extern "C" fn unused_get_elements(
    _p: *mut ProcessHeader,
    _map: u64,
    _registers: u64,
    _stack: u64,
    _count: u64,
) -> u64 {
    panic!("reply_return uses the inline flatmap lookup")
}

extern "C" fn unused_map_update(
    _p: *mut ProcessHeader,
    _source: u64,
    _registers: u64,
    _live: u64,
    _count: u64,
) -> u64 {
    0
}

fn atom(name: &str) -> u64 {
    Term::atom(global_atoms().intern(name).unwrap()).tagged_word()
}

fn reply_return(idle: bool) -> (u64, u64, u64) {
    let mut heap = ProcessHeap::with_words(128);
    let idle_atom = global_atoms().intern("idle").unwrap();
    let idle_value = Term::atom(
        global_atoms()
            .intern(if idle { "true" } else { "false" })
            .unwrap(),
    );
    let state = TermBuilder::new(&mut heap)
        .flatmap_from_pairs(&[(Term::atom(idle_atom), idle_value)])
        .unwrap();

    let mut asm = BeamModuleAssembler::new();
    asm.emit_i_func_label(1).unwrap();
    asm.emit_enter_frame().unwrap();
    asm.emit_is_map(ArgVal::X(1), 90).unwrap();
    asm.emit_i_get_map_element_hash(
        90,
        ArgVal::X(1),
        ArgVal::Immediate(atom("idle")),
        ArgVal::Immediate(0),
        ArgVal::X(2),
        MapRuntime {
            get: unused_map_get,
            get_elements: unused_get_elements,
            new_map: unused_map_update,
            update_assoc: unused_map_update,
            update_exact: unused_map_update,
            put_single: unused_map_update,
            update_single: unused_map_update,
        },
    )
    .unwrap();
    let mut alternatives = [
        (atom("false"), ArgVal::Label(20)),
        (atom("true"), ArgVal::Label(10)),
    ];
    alternatives.sort_by_key(|(value, _)| *value);
    let values = alternatives
        .iter()
        .map(|(value, _)| ArgVal::Immediate(*value));
    let labels = alternatives.iter().map(|(_, label)| *label);
    let args = values.chain(labels).collect::<Vec<_>>();
    asm.emit_i_select_val_lins(ArgVal::X(2), ArgVal::Label(90), 4, &args)
        .unwrap();
    asm.emit_i_func_label(10).unwrap();
    asm.emit_put_tuple2(
        ArgVal::X(0),
        &[ArgVal::Immediate(atom("reply")), ArgVal::X(0), ArgVal::X(1)],
    )
    .unwrap();
    asm.return_().unwrap();
    asm.emit_i_func_label(20).unwrap();
    asm.emit_put_tuple2(
        ArgVal::X(0),
        &[
            ArgVal::Immediate(atom("reply")),
            ArgVal::X(0),
            ArgVal::X(1),
            ArgVal::Immediate(Term::small(100).unwrap().tagged_word()),
        ],
    )
    .unwrap();
    asm.return_().unwrap();
    asm.emit_i_func_label(90).unwrap();
    asm.emit_raw(|e| {
        e.udf(0);
        Ok(())
    })
    .unwrap();
    let module: FinalizedModule = asm.finalize().unwrap();

    let (htop, stop) = heap.heap_cursor();
    let (heap_start, heap_end) = heap.heap_bounds();
    let mut header = ProcessHeader {
        htop,
        stop,
        heap: heap_start,
        hend: heap_end,
        fcalls: 100,
        ..ProcessHeader::default()
    };
    let mut registers = SchedulerRegisters::default();
    let reply = Term::small(77).unwrap();
    registers.x_reg_array[0] = reply.tagged_word();
    registers.x_reg_array[1] = state.tagged_word();
    assert_eq!(
        enter_native(&mut header, &mut registers, &module.entry(1).unwrap()),
        ExitReason::Returned
    );

    let tuple = registers.x_reg_array[0];
    let arity = if idle { 3 } else { 4 };
    assert_eq!(read_heap_word(tuple, 0), (arity as u64) << 6);
    assert_eq!(read_heap_word(tuple, 1), atom("reply"));
    assert_eq!(read_heap_word(tuple, 2), reply.tagged_word());
    assert_eq!(read_heap_word(tuple, 3), state.tagged_word());
    (tuple, term_bits(state), term_bits(reply))
}

#[test]
fn reply_return_preserves_reply_and_state_for_both_idle_states() {
    let (_, state, _) = reply_return(true);
    assert_ne!(state, 0);
    let (_, state, _) = reply_return(false);
    assert_ne!(state, 0);
}
