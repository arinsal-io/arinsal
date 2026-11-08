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
    process.cold_mut().off_heap_msgq = true;
    let heap_words = process.heap.total_heap_size_words();
    let prio_len = 0;
    process.inbox.push_message(envelope(), prio_len).unwrap();

    assert!(process.inbox.gc_root_snapshot().1.is_empty());
    assert_eq!(process.heap.total_heap_size_words(), heap_words);
    process.collect_heap_roots(0, &mut [], 0).unwrap();
    let term = process
        .inbox
        .remove_to_heap(0, &mut process.heap, prio_len)
        .unwrap()
        .0
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
    let prio_len = 0;
    process.inbox.push_message(envelope(), prio_len).unwrap();

    // The fetched message keeps its fragment until a collection moves it onto the heap.
    assert!(process.inbox.gc_root_snapshot().1.is_empty());
    assert!(!process.inbox.is_on_heap(0));
    process.collect_heap_roots(0, &mut [], 0).unwrap();
    assert_eq!(process.inbox.gc_root_snapshot().1.len(), 1);
    assert_eq!(process.inbox.entries.len(), 1);
    assert!(
        super::queued(process.inbox.entries.get(0).unwrap())
            .fragment
            .is_none()
    );
    process.collect_heap_roots(0, &mut [], 0).unwrap();
    let term = process
        .inbox
        .remove_to_heap(0, &mut process.heap, prio_len)
        .unwrap()
        .0
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
    let before = (process.heap.abi.heap, process.heap.abi.hend);
    // Force a collection that grows the young heap.
    process.ensure(1 << 14, 0).unwrap();
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
    let stats = process.collect_heap_roots(0, &mut roots, 0).unwrap();
    assert_eq!(stats.collections, 1);
    assert_ne!(roots[0], result);
    assert_eq!(arinsal_term::to_owned(roots[0]).unwrap(), expected);
}

#[test]
fn check_process_code_sees_the_return_address_of_a_native_trace_frame() {
    // A traced native function leaves its return address on the stack as a small integer;
    // a purge of the code it returns into has to find it.
    let mut process = Process::new();
    let range = (0x4000_usize, 0x5000_usize);
    let marker = crate::trace::native_trace_marker();
    assert!(process.heap.reserve_stack(4));
    let words = [
        crate::proc_create::native_continuation_term(marker),
        Term::NIL,
        Term::small(0x4468).unwrap(),
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

#[test]
fn worker_panic_aborts_instead_of_hanging() {
    const TEST_NAME: &str = "process::layout_tests::worker_panic_aborts_instead_of_hanging";
    if std::env::var_os("ARINSAL_TEST_WORKER_PANIC").is_some() {
        super::abort_on_worker_panic(|| panic!("worker panic sentinel"));
        return;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", TEST_NAME, "--nocapture"])
        .env("ARINSAL_TEST_WORKER_PANIC", "1")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("arinsal: VM panic in scheduler worker: worker panic sentinel")
    );
}

#[test]
fn idle_process_layout_stays_compact() {
    // `first`, `last`, the length, the non-message count and the save cursor (position and
    // node), like the inner queue of erts `ErtsSignalPrivQueues`.
    assert_eq!(std::mem::size_of::<super::MessageQueue>(), 8 * 8);
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
        144
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
