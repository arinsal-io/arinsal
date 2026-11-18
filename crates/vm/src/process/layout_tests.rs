use super::{Message, Process, ProcessHeap, Term, TermBuilder};
use similar_asserts::assert_eq;

fn envelope() -> Message {
    let mut source = ProcessHeap::with_words(8);
    let term = TermBuilder::new(&mut source)
        .tuple(&[Term::small(17).unwrap()])
        .unwrap();
    Message::copy_from(term).unwrap()
}

#[test]
fn off_heap_message_fragment_stays_outside_gc_roots_until_removed() {
    let mut process = Process::new();
    arinsal_sched::Task::init_in_place(&mut process);
    process.cold_mut().off_heap_msgq = true;
    let heap_words = process.heap.total_heap_size_words();
    process.inbox.push_message(envelope()).unwrap();

    assert!(process.inbox.gc_root_snapshot().1.is_empty());
    assert_eq!(process.heap.total_heap_size_words(), heap_words);
    process
        .collect_heap_roots_objv(&mut [], &mut [], 0)
        .unwrap();
    let term = process
        .inbox
        .remove_to_heap(&mut process.heap)
        .unwrap()
        .unwrap();
    assert_eq!(
        arinsal_term::to_owned(term).unwrap(),
        arinsal_etf::OwnedTerm::Tuple(vec![arinsal_etf::OwnedTerm::Int(17)])
    );
    assert!(process.heap.total_heap_size_words() > heap_words);
}

#[test]
fn on_heap_message_is_a_gc_root_in_the_process_heap() {
    let mut process = Process::new();
    arinsal_sched::Task::init_in_place(&mut process);
    process.inbox.push_message(envelope()).unwrap();

    // The fetched message keeps its fragment until a collection moves it onto the heap.
    assert!(process.inbox.gc_root_snapshot().1.is_empty());
    assert!(!process.inbox.is_on_heap_at_save());
    process
        .collect_heap_roots_objv(&mut [], &mut [], 0)
        .unwrap();
    assert_eq!(process.inbox.gc_root_snapshot().1.len(), 1);
    assert_eq!(process.inbox.entries.len(), 1);
    assert!(
        super::queued(process.inbox.entries.peek().unwrap())
            .data
            .is_none()
    );
    process
        .collect_heap_roots_objv(&mut [], &mut [], 0)
        .unwrap();
    let term = process
        .inbox
        .remove_to_heap(&mut process.heap)
        .unwrap()
        .unwrap();
    assert_eq!(
        arinsal_term::to_owned(term).unwrap(),
        arinsal_etf::OwnedTerm::Tuple(vec![arinsal_etf::OwnedTerm::Int(17)])
    );
}

/// Regression for the Elixir `base_test`/`calendar/iso_test` crashes: a collection inside a
/// native helper that returns an error (or any path without its own header sync) left
/// `heap`/`hend` of the ABI prefix on the old heap, and the next helper committed cursors of
/// the new heap against the old base.
#[test]
fn collection_publishes_the_new_heap_to_the_native_header() {
    let mut process = Process::new();
    arinsal_sched::Task::init_in_place(&mut process);
    let before = (process.heap.abi.heap, process.heap.abi.hend);
    // Force a collection that grows the young heap.
    process.ensure_objv(1 << 14, &mut []).unwrap();
    let (heap, hend) = process.heap.heap_bounds();
    let (htop, stop) = process.heap.heap_cursor();
    assert_ne!(
        (heap, hend),
        before,
        "the collection must move or grow the heap"
    );
    assert_eq!(process.heap.abi.heap, heap);
    assert_eq!(process.heap.abi.hend, hend);
    assert_eq!(process.heap.abi.htop, htop);
    assert_eq!(process.heap.abi.stop, stop);
}

#[test]
fn partial_cursor_sync_also_publishes_heap_bounds() {
    let mut process = Process::new();
    arinsal_sched::Task::init_in_place(&mut process);
    let _ = process.heap.heap_bounds();
    process.heap.delay_collection(0);
    process.heap.abi.heap = std::ptr::null_mut();
    process.heap.abi.hend = std::ptr::null_mut();
    assert_eq!(process.heap.abi.heap, process.heap.heap_bounds().0);
    assert_eq!(process.heap.abi.hend, process.heap.heap_bounds().1);
}

#[test]
fn post_bif_result_root_survives_collection_in_the_fast_arm() {
    let mut process = Process::new();
    arinsal_sched::Task::init_in_place(&mut process);
    let elements = [
        Term::small(1).unwrap(),
        Term::small(2).unwrap(),
        Term::small(3).unwrap(),
    ];
    let result = TermBuilder::new(&mut process.heap)
        .tuple(&elements)
        .unwrap();
    let expected = arinsal_term::to_owned(result).unwrap();
    let mut roots = [result];
    let stats = process
        .collect_heap_roots_objv(&mut [], &mut roots, 0)
        .unwrap();
    assert_eq!(stats.collections, 1);
    assert_ne!(roots[0], result);
    assert_eq!(arinsal_term::to_owned(roots[0]).unwrap(), expected);
}

#[test]
fn trace_frame_kinds_round_trip_through_their_return_addresses() {
    use crate::trace::TraceFrameKind;
    for kind in [
        TraceFrameKind::ReturnTrace,
        TraceFrameKind::ExceptionTrace,
        TraceFrameKind::ReturnToTrace,
        TraceFrameKind::CallTraceReturn,
    ] {
        assert_eq!(TraceFrameKind::of(kind.address()), Some(kind));
        assert_eq!(TraceFrameKind::of(kind.address() + 4), None);
    }
}

#[test]
fn check_process_code_sees_the_function_of_a_return_trace_frame() {
    // A return trace frame names its traced function by a pc in it (erts `&mfa`); a purge of
    // that code has to find it.
    let mut process = Process::new();
    arinsal_sched::Task::init_in_place(&mut process);
    let range = (0x4000_usize, 0x5000_usize);
    let stub = crate::trace::TraceFrameKind::ReturnTrace.address();
    assert!(process.heap.reserve_stack(4));
    let words = [
        crate::proc_create::native_continuation_term(stub),
        Term::small(0x4468).unwrap(),
        Term::NIL,
        Term::small(0).unwrap(),
    ];
    for (index, word) in words.into_iter().enumerate() {
        process.heap.stack_set(index, word);
    }
    assert!(process.references_code(usize::MAX, |address| {
        range.0 <= address && address < range.1
    }));
    assert!(!process.references_code(usize::MAX, |address| (0x8000..0x9000).contains(&address)));
    assert!(!process.references_code(usize::MAX, |_| false));
}

/// `check_process_code` drops a saved exception trace that names the module and still
/// answers false. A trace for another module, and a process whose own code is the module,
/// are left alone (the latter answers true).
#[test]
fn check_process_code_clears_ftrace_that_names_the_module() {
    fn packed(module: usize, ip: usize) -> u64 {
        (1 << 63) | ((module as u64) << 32) | ip as u64
    }
    fn install(process: &mut Process, pc: u64, current: u64, trace: &[u64]) {
        let mut digits = vec![
            arinsal_beamasm::exc::EXC_ERROR,
            pc,
            current,
            trace.len() as u64 | ((trace.len() as u64) << 32),
        ];
        digits.extend_from_slice(trace);
        let stack = TermBuilder::new(&mut process.heap)
            .pos_bignum_from_digits(&digits)
            .unwrap();
        let ftrace = TermBuilder::new(&mut process.heap)
            .tuple3(stack, Term::NIL, Term::NIL)
            .unwrap();
        process.heap.abi.exc.freason = arinsal_beamasm::exc::EXC_ERROR;
        process.heap.abi.exc.fvalue = Term::small(1).unwrap().tagged_word();
        process.heap.abi.exc.ftrace = ftrace.tagged_word();
    }

    let mut process = Process::new();
    arinsal_sched::Task::init_in_place(&mut process);
    install(&mut process, packed(7, 4), 0, &[]);
    assert!(!process.references_code(7, |_| false));
    assert_eq!(process.heap.abi.exc.freason, 0);
    assert_eq!(process.heap.abi.exc.fvalue, 0);
    assert_eq!(process.heap.abi.exc.ftrace, 0);

    install(&mut process, 0, packed(7, 9), &[]);
    assert!(!process.references_code(7, |_| false));
    assert_eq!(process.heap.abi.exc.ftrace, 0);

    install(&mut process, 0, 0, &[packed(7, 3)]);
    assert!(!process.references_code(7, |_| false));
    assert_eq!(process.heap.abi.exc.ftrace, 0);

    install(&mut process, 0x4500, 0, &[]);
    assert!(!process.references_code(7, |address| address == 0x4500));
    assert_eq!(process.heap.abi.exc.ftrace, 0);

    install(&mut process, 0, 0, &[0x4500]);
    assert!(!process.references_code(7, |address| address == 0x4500));
    assert_eq!(process.heap.abi.exc.ftrace, 0);

    // Another module, and a BIF MFA in `current` (atom pair, not a code pointer).
    install(&mut process, packed(9, 1), (20 << 32) | 30, &[packed(9, 2)]);
    let other = process.heap.abi.exc.ftrace;
    assert!(!process.references_code(7, |_| true));
    assert_eq!(process.heap.abi.exc.ftrace, other);
    assert_eq!(
        process.heap.abi.exc.freason,
        arinsal_beamasm::exc::EXC_ERROR
    );

    // The process itself is in the module (`rp->i`): erts returns before looking at ftrace.
    process.set_native_pc(Some(0x7000));
    install(&mut process, packed(7, 4), 0, &[]);
    let live = process.heap.abi.exc.ftrace;
    assert!(process.references_code(7, |address| address == 0x7000));
    assert_eq!(process.heap.abi.exc.ftrace, live);

    process.set_native_pc(None);
    process.heap.abi.exc.ftrace = 0;
    process.heap.abi.exc.freason = arinsal_beamasm::exc::EXC_ERROR;
    assert!(!process.references_code(7, |_| false));
    assert_eq!(
        process.heap.abi.exc.freason,
        arinsal_beamasm::exc::EXC_ERROR
    );
}

#[test]
fn worker_panic_is_not_recovered() {
    const TEST_NAME: &str = "process::layout_tests::worker_panic_is_not_recovered";
    if std::env::var_os("ARINSAL_TEST_WORKER_PANIC").is_some() {
        panic!("worker panic sentinel");
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", TEST_NAME, "--nocapture"])
        .env("ARINSAL_TEST_WORKER_PANIC", "1")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("worker panic sentinel"));
}

#[test]
fn idle_process_layout_stays_compact() {
    // `first`, `last`, `save` and `mq_len` of erts `ErtsSignalPrivQueues` and the prio queue
    // / save-info bits of `sig_qs.flags`.
    assert_eq!(std::mem::size_of::<super::MessageQueue>(), 5 * 8);
    // Before `MessageHeapBlock`, the enum was the same size as its 240-byte ProcessHeap
    // payload; the NodeFragment variant needed no extra discriminant space.
    // The native ABI words (erts c_p htop/stop/heap/hend/fcalls/freason) moved into the heap.
    assert!(
        std::mem::size_of::<arinsal_term::ProcessHeap>()
            <= 160
                + std::mem::size_of::<arinsal_term::NativeAbi>()
                + arinsal_term::ProcessHeap::OWNERS_SIZE
    );
    eprintln!(
        "Process={} ProcessHeap={} MessageHeap={} PreviousMessageHeap={} VecDeque={} RunOutcome={}",
        std::mem::size_of::<crate::Process>(),
        std::mem::size_of::<arinsal_term::ProcessHeap>(),
        std::mem::size_of::<arinsal_term::message::MessageHeap>(),
        std::mem::size_of::<arinsal_term::ProcessHeap>(),
        std::mem::size_of::<std::collections::VecDeque<arinsal_term::Term>>(),
        std::mem::size_of::<arinsal_sched::RunOutcome>()
    );
}

#[test]
fn monitor_data_is_one_small_block() {
    // Both halves of a monitor in one allocation (erts `ErtsMonitorData`); each half is
    // queued as its own signal, so the signal nodes cost nothing. The rare tag and name are
    // boxed separately.
    assert_eq!(
        std::mem::size_of::<crate::proc_create::ProcessMonitorData>(),
        136
    );
}

#[test]
fn queued_event_stays_compact() {
    // Every message and signal crosses the in-queue and the middle queue as an `Event`, so
    // its size is copied on each send and fetch. Wide signal payloads and timer messages are
    // boxed, keeping the event below one 64-byte cache line.
    // Timer ids live with the fragment, so the common message envelope is 32 bytes.
    assert_eq!(std::mem::size_of::<Message>(), 32);
    assert_eq!(std::mem::size_of::<arinsal_sched::Signal<Message>>(), 24);
    assert_eq!(std::mem::size_of::<arinsal_sched::Payload<Message>>(), 32);
    assert_eq!(std::mem::size_of::<arinsal_sched::Event<Message>>(), 40);
    assert_eq!(
        std::mem::size_of::<arinsal_term::message::SignalNode<arinsal_sched::Event<Message>>>(),
        56
    );
}

/// The state word is past the native prefix and in reach of a 32-bit load with an unsigned
/// scaled immediate from `c_p` (arm64 `ldr w, [c_p, #imm]`: up to 4095 * 4), as erts keeps
/// `c_p->state` addressable by a single displacement.
#[test]
fn process_state_word_offset_is_a_single_load_from_c_p() {
    let offset = super::PROCESS_STATE_OFFSET;
    eprintln!("PROCESS_STATE_OFFSET = {offset:#x}");
    assert!(offset >= size_of::<arinsal_term::NativeAbi>());
    assert_eq!(offset % 4, 0);
    assert!(offset <= 4095 * 4, "state word at {offset:#x}");
}

/// `sig_qs.save` and `ErtsMessage.m[0]` as generated code reads them: the word at
/// `PROCESS_SIGQ_SAVE_OFFSET` names the `next` field holding the node at the save pointer, and
/// the term of that node is at `ERTS_MESSAGE_TERM_OFFSET`. The fields are in reach of one
/// `ldr x, [c_p, #imm]` (unsigned scaled immediate: up to 4095 * 8).
#[test]
fn sig_qs_fields_are_at_their_exported_offsets() {
    let mut queue = super::MessageQueue::default();
    queue.init_in_place();
    let term = Term::small(42).expect("small");
    queue.push_back(term);
    let node = queue
        .entries
        .peek_node()
        .expect("a message at the save pointer");
    let save = queue.entries.save_field();
    assert_eq!(queue.entries.first_field(), save);
    let term_at = node.as_ptr() as usize + super::ERTS_MESSAGE_TERM_OFFSET;
    assert_eq!(
        std::ptr::from_ref(queue.peek().expect("peek")) as usize,
        term_at
    );
    assert_eq!(
        super::PROCESS_SIGQ_FIRST_OFFSET,
        std::mem::offset_of!(Process, inbox) + std::mem::offset_of!(super::MessageQueue, entries)
    );
    for offset in [
        super::PROCESS_SIGQ_FIRST_OFFSET,
        super::PROCESS_SIGQ_LAST_OFFSET,
        super::PROCESS_SIGQ_SAVE_OFFSET,
        super::PROCESS_SIGQ_MQ_LEN_OFFSET,
        super::PROCESS_SIGQ_CONT_OFFSET,
    ] {
        eprintln!("sig_qs field at {offset:#x}");
        assert_eq!(offset % 8, 0);
        assert!(offset <= 4095 * 8, "sig_qs field at {offset:#x}");
    }
    assert_eq!(queue.len(), 1);
}
