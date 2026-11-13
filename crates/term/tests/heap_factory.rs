//! `ErtsHeapFactory` of a process (`FACTORY_HALLOC`): prealloc init, park/open, close, undo.

use arinsal_term::{HeapFactory, ProcessHeap};

fn fill(block: &mut arinsal_term::HeapReservation<'_, ProcessHeap>, words: usize) {
    let cur = block.cursor();
    block.set_cursor(cur.wrapping_add(words));
}

#[test]
fn close_releases_the_unused_tail() {
    let mut heap = ProcessHeap::with_words(64);
    let before = heap.used_words();
    let mut factory = HeapFactory::proc_prealloc_init(&mut heap, 16).unwrap();
    let mut block = factory.open(&mut heap);
    fill(&mut block, 5);
    factory.park(block);
    factory.close(&mut heap);
    assert_eq!(heap.used_words(), before + 5);
}

#[test]
fn parked_block_keeps_its_cursor_between_slices() {
    let mut heap = ProcessHeap::with_words(64);
    let before = heap.used_words();
    let mut factory = HeapFactory::proc_prealloc_init(&mut heap, 16).unwrap();
    for _ in 0..3 {
        let mut block = factory.open(&mut heap);
        fill(&mut block, 4);
        factory.park(block);
    }
    factory.close(&mut heap);
    assert_eq!(heap.used_words(), before + 12);
}

#[test]
fn undo_restores_the_heap_top() {
    let mut heap = ProcessHeap::with_words(64);
    let before = heap.used_words();
    let mut factory = HeapFactory::proc_prealloc_init(&mut heap, 16).unwrap();
    let mut block = factory.open(&mut heap);
    fill(&mut block, 9);
    factory.park(block);
    factory.undo(&mut heap);
    assert_eq!(heap.used_words(), before);
}

#[test]
fn undo_after_a_dropped_block_and_a_fragment_restores_the_state() {
    let mut heap = ProcessHeap::with_words(8);
    let before = heap.used_words();
    // Larger than the young heap: lands in a heap fragment, which `undo` frees.
    let mut factory = HeapFactory::proc_prealloc_init(&mut heap, 100).unwrap();
    let mut block = factory.open(&mut heap);
    fill(&mut block, 30);
    drop(block);
    factory.undo(&mut heap);
    assert_eq!(heap.used_words(), before);
}
