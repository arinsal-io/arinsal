use arinsal_term::{
    ExportEntry, FunEntry, HeapAlloc, Node, ProcessHeap, S_REDZONE, S_RESERVED, Term, TermBuilder,
    VecHeap, binary_memory_bytes, copy_term, exact_eq, global_atoms, make_hash2, match_position,
    set_match_position, size_object, to_owned, writable_bytes_mut, writable_capacity,
    writable_extend_private,
};
use arinsal_term::{ExternalBinary, MagicRef};
use similar_asserts::assert_eq;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

struct DropCounter(Arc<AtomicUsize>);
impl Drop for DropCounter {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn process_heap_allocator_leaves_the_native_stack_redzone() {
    let reserve = S_REDZONE;
    let words = reserve + 16;
    let mut heap = ProcessHeap::with_words(words);
    assert_eq!(S_REDZONE, 3);
    assert_eq!(S_RESERVED, 4);
    assert_eq!(heap.heap_limit_words(), words - reserve);
    assert_eq!(heap.allocation_reserve(), 0);
    assert!(heap.alloc(words).is_some());
    let mut heap = ProcessHeap::with_words(words);
    heap.set_native_allocation(true);
    assert_eq!(heap.allocation_reserve(), reserve);
    assert!(heap.alloc(words - reserve).is_some());
    assert!(heap.alloc(1).is_none());
}

#[test]
fn halloc_reserves_the_stack_redzone_before_using_a_fragment() {
    let words = S_REDZONE + 16;
    let mut heap = ProcessHeap::with_words(words);
    assert_eq!(heap.halloc_words_left(), Some(16));
    assert!(heap.alloc_halloc(16).is_some());
    assert_eq!(heap.halloc_words_left(), Some(0));
    assert!(heap.alloc_halloc(1).is_none());
}

#[test]
fn hrelease_shrinks_and_reuses_the_current_heap_fragment() {
    let mut heap = ProcessHeap::with_words(16);
    let block = heap.heap_fragment(16);
    HeapAlloc::release(&mut heap, block.wrapping_add(16), block.wrapping_add(4));
    assert_eq!(heap.mbuf_size(), 4);
    assert_eq!(heap.fragment_count(), 1);

    let reused = heap.heap_fragment(12);
    assert_eq!(reused, block.wrapping_add(4));
    assert_eq!(heap.mbuf_size(), 16);
    assert_eq!(heap.fragment_count(), 1);
}

#[test]
fn adopted_message_keeps_term_and_off_heap_owner_through_gc() {
    let mut source = VecHeap::new();
    let binary = TermBuilder::new(&mut source).binary(&[0x5a; 100]).unwrap();
    let list = TermBuilder::new(&mut source)
        .cons(Term::small(7).unwrap(), Term::NIL)
        .unwrap();
    let message = TermBuilder::new(&mut source)
        .tuple(&[binary, list])
        .unwrap();
    let expected = to_owned(message).unwrap();
    let mut envelope = ProcessHeap::with_words(size_object(message));
    let copied = copy_term(message, &mut envelope).unwrap();
    let mut receiver = ProcessHeap::new();
    receiver.adopt_message_fragment(envelope).unwrap();
    drop(source);
    assert_eq!(receiver.off_heap_count(), 1);
    let mut roots = [copied];
    receiver.collect(&mut roots, &mut [], 0).unwrap();
    assert_eq!(receiver.off_heap_count(), 1);
    assert_eq!(to_owned(roots[0]).unwrap(), expected);
}

#[test]
fn gc_rebases_message_binary_chains_before_releasing_fragments() {
    let mut message_heap = ProcessHeap::with_words(128);
    let payload = vec![0x5a; 100];
    let binary = TermBuilder::new(&mut message_heap)
        .binary(&payload)
        .unwrap();
    let message = TermBuilder::new(&mut message_heap)
        .tuple(&[binary])
        .unwrap();
    let expected = to_owned(message).unwrap();

    let mut receiver = ProcessHeap::with_words(256);
    let mut messages = [(message, Some(message_heap))];
    receiver
        .collect_with_messages(&mut [], &mut [], 0, &mut messages)
        .unwrap();
    assert!(messages[0].1.is_none());
    assert_eq!(receiver.off_heap_count(), 1);
    assert_eq!(to_owned(messages[0].0).unwrap(), expected);

    let mut roots = [messages[0].0];
    receiver.collect(&mut roots, &mut [], 0).unwrap();
    assert_eq!(receiver.off_heap_count(), 1);
    assert_eq!(to_owned(roots[0]).unwrap(), expected);
}

#[test]
fn magic_reference_survives_copy_and_gc_then_releases() {
    let count = Arc::new(AtomicUsize::new(0));
    let owner = MagicRef::new(DropCounter(count.clone()));
    let mut source = VecHeap::new();
    let term = TermBuilder::new(&mut source)
        .magic_ref(owner.clone())
        .unwrap();
    let ordinary = TermBuilder::new(&mut source)
        .local_ref([owner.id() as u32, (owner.id() >> 32) as u32, 0])
        .unwrap();
    assert!(!exact_eq(term, ordinary));
    let mut heap = ProcessHeap::with_words(128);
    let mut roots = [copy_term(term, &mut heap).unwrap()];
    drop(owner);
    drop(source);
    heap.collect(&mut roots, &mut [], 0).unwrap();
    // SAFETY: the root and its copied owner remain live on this process heap.
    assert!(unsafe { roots[0].magic_ref() }.is_some());
    assert_eq!(count.load(Ordering::SeqCst), 0);
    heap.collect(&mut [], &mut [], 0).unwrap();
    assert_eq!(count.load(Ordering::SeqCst), 1);
}

#[test]
fn magic_reference_leaves_the_registry_with_its_last_reference() {
    let count = Arc::new(AtomicUsize::new(0));
    let mut heap = ProcessHeap::with_words(1 << 16);
    let mut ids = Vec::new();
    for _ in 0..10_000 {
        let owner = MagicRef::new(DropCounter(count.clone()));
        ids.push(owner.id());
        let term = TermBuilder::new(&mut heap).magic_ref(owner).unwrap();
        assert!(term.is_magic_ref());
    }
    assert!(ids.iter().all(|id| MagicRef::is_registered(*id)));
    assert!(ids.iter().all(|id| MagicRef::live_by_id(*id).is_some()));
    assert_eq!(count.load(Ordering::SeqCst), 0);
    heap.collect(&mut [], &mut [], 0).unwrap();
    heap.collect(&mut [], &mut [], 0).unwrap();
    assert_eq!(count.load(Ordering::SeqCst), 10_000);
    assert!(ids.iter().all(|id| !MagicRef::is_registered(*id)));
    assert!(ids.iter().all(|id| MagicRef::live_by_id(*id).is_none()));
}

#[test]
fn magic_reference_stays_registered_while_any_heap_holds_it() {
    let count = Arc::new(AtomicUsize::new(0));
    let owner = MagicRef::new(DropCounter(count.clone()));
    let id = owner.id();
    let mut source = VecHeap::new();
    let term = TermBuilder::new(&mut source)
        .magic_ref(owner.clone())
        .unwrap();
    let mut heap = ProcessHeap::with_words(128);
    let mut roots = [copy_term(term, &mut heap).unwrap()];
    drop(owner);
    drop(source);
    assert!(MagicRef::is_registered(id));
    assert_eq!(count.load(Ordering::SeqCst), 0);
    heap.collect(&mut roots, &mut [], 0).unwrap();
    assert!(MagicRef::is_registered(id));
    assert_eq!(MagicRef::live_by_id(id).unwrap().id(), id);
    heap.collect(&mut [], &mut [], 0).unwrap();
    assert_eq!(count.load(Ordering::SeqCst), 1);
    assert!(!MagicRef::is_registered(id));
}

struct ExternalPayload {
    bytes: Box<[u8]>,
    _counter: DropCounter,
}
#[test]
fn external_binary_keeps_resource_through_copy_and_gc() {
    let count = Arc::new(AtomicUsize::new(0));
    let owner = MagicRef::new(ExternalPayload {
        bytes: vec![1, 2, 3].into_boxed_slice(),
        _counter: DropCounter(count.clone()),
    });
    let bytes = &owner.downcast_ref::<ExternalPayload>().unwrap().bytes;
    // SAFETY: the ExternalBinary retains owner, which owns these three bytes.
    let external = unsafe { ExternalBinary::new(bytes.as_ptr(), bytes.len(), owner.clone()) };
    let mut source = VecHeap::new();
    let term = TermBuilder::new(&mut source)
        .external_binary(external)
        .unwrap();
    let mut heap = ProcessHeap::with_words(128);
    let mut roots = [copy_term(term, &mut heap).unwrap()];
    drop(owner);
    drop(source);
    heap.collect(&mut roots, &mut [], 0).unwrap();
    // SAFETY: collection retained the external owner for the live root.
    let view = unsafe { roots[0].binary_ref() }.unwrap();
    assert_eq!(view.bytes(), &[1, 2, 3]);
    assert_eq!(count.load(Ordering::SeqCst), 0);
    heap.collect(&mut [], &mut [], 0).unwrap();
    assert_eq!(count.load(Ordering::SeqCst), 1);
}

#[test]
fn deep_list_is_iterative() {
    let count = if cfg!(miri) { 100 } else { 1_000_000 };
    let mut heap = ProcessHeap::with_words(count * 2 + 128);
    let mut root = Term::NIL;
    for i in 0..count {
        root = TermBuilder::new(&mut heap)
            .cons(Term::small((i % 17) as i64).unwrap(), root)
            .unwrap();
    }
    let mut roots = [root];
    heap.collect(&mut roots, &mut [], 64).unwrap();
    let mut cursor = roots[0];
    let mut seen = 0;
    // SAFETY: The collected heap remains live and stable during traversal.
    while let Some((_, tail)) = unsafe { cursor.cons_ref() } {
        seen += 1;
        cursor = tail;
    }
    assert_eq!(seen, count);
    assert_eq!(cursor, Term::NIL);
}

#[test]
fn sharing_and_stack_roots_survive() {
    let mut heap = ProcessHeap::with_words(256);
    let child = TermBuilder::new(&mut heap)
        .cons(Term::small(42).unwrap(), Term::NIL)
        .unwrap();
    let parent = TermBuilder::new(&mut heap).tuple(&[child, child]).unwrap();
    assert!(heap.reserve_stack(1));
    assert!(heap.stack_set(0, parent));
    let mut roots = [parent];
    heap.collect(&mut roots, &mut [], 32).unwrap();
    // SAFETY: The collected heap remains live and stable during inspection.
    let tuple = unsafe { roots[0].tuple_ref() }.unwrap();
    assert_eq!(tuple.get(0), tuple.get(1));
    assert_eq!(heap.stack_get(0), Some(roots[0]));
}

#[test]
fn dead_off_heap_binary_is_released() {
    let mut heap = ProcessHeap::with_words(256);
    let _binary = TermBuilder::new(&mut heap).binary(&[7; 100]).unwrap();
    assert_eq!(heap.off_heap_count(), 1);
    heap.collect(&mut [], &mut [], 1).unwrap();
    assert_eq!(heap.off_heap_count(), 0);
}

#[test]
fn reachable_fragment_is_merged() {
    let mut heap = ProcessHeap::with_words(64);
    let pointer = heap.gc_fragment(2);
    // SAFETY: The fragment reserves exactly two initialized cons words and stays live until GC.
    let fragment_term = unsafe {
        *pointer = Term::small(7).unwrap().raw_bits();
        *pointer.add(1) = Term::NIL.raw_bits();
        std::mem::transmute::<u64, Term>((pointer as u64) | 1)
    };
    let mut roots = [fragment_term];
    heap.collect(&mut roots, &mut [], 0).unwrap();
    // SAFETY: The collected heap retains the rewritten cons cell.
    let (head, tail) = unsafe { roots[0].cons_ref() }.unwrap();
    assert_eq!(head.as_small(), Some(7));
    assert_eq!(tail, Term::NIL);
}

#[test]
fn heap_fragment_is_merged() {
    let mut heap = ProcessHeap::with_words(64);
    let pointer = heap.heap_fragment(2);
    // SAFETY: the stored fragment reserves two initialized cons words.
    let fragment_term = unsafe {
        *pointer = Term::small(11).unwrap().raw_bits();
        *pointer.add(1) = Term::NIL.raw_bits();
        std::mem::transmute::<u64, Term>((pointer as u64) | 1)
    };
    let mut roots = [fragment_term];
    heap.collect(&mut roots, &mut [], 0).unwrap();
    // SAFETY: collection moved the cell into the new stable process heap.
    let head = unsafe { roots[0].cons_ref() }.unwrap().0;
    assert_eq!(head.as_small(), Some(11));
}

#[test]
fn heap_alloc_fills_the_newest_fragment_before_adding_one() {
    // erts_heap_alloc (utils.c:135): HAlloc fragments are exact-size, and a request goes
    // to the newest fragment while it has room, as a delayed-GC heap joining mbuf does.
    let mut heap = ProcessHeap::with_words(64);
    heap.heap_fragment(3);
    heap.heap_fragment(2);
    assert_eq!(heap.fragment_count(), 2);
    heap.delay_collection(8);
    heap.delay_collection(8);
    let fragments = heap.fragment_count();
    heap.heap_fragment(1);
    assert_eq!(heap.fragment_count(), fragments);
    assert_eq!(heap.fragment_words(), 6);
}

#[test]
fn collection_moves_fragment_terms_and_keeps_the_global_empty_tuple() {
    let empty = arinsal_term::global_empty_tuple();
    let mut heap = ProcessHeap::with_words(64);
    let pointer = heap.heap_fragment(3);
    // SAFETY: the fragment reserves the three words of a 2-tuple.
    let tuple = unsafe {
        *pointer = 2 << 6;
        *pointer.add(1) = empty.raw_bits();
        *pointer.add(2) = Term::small(7).unwrap().raw_bits();
        std::mem::transmute::<u64, Term>((pointer as u64) | 2)
    };
    let mut roots = [tuple, empty];
    heap.collect(&mut roots, &mut [], 0).unwrap();
    assert_eq!(heap.fragment_count(), 0);
    assert!(heap.owns_term(roots[0]));
    assert_eq!(roots[1], empty);
    // SAFETY: the tuple now lives in the collected heap.
    let elements = unsafe { roots[0].tuple_ref() }.unwrap();
    assert_eq!(elements.get(0), Some(empty));
    assert_eq!(elements.get(1).unwrap().as_small(), Some(7));
}

#[test]
fn sparse_heap_shrinks_after_full_collection() {
    let mut heap = ProcessHeap::with_words(10_000);
    let mut roots = [TermBuilder::new(&mut heap)
        .tuple(&[Term::small(1).unwrap()])
        .unwrap()];
    heap.collect(&mut roots, &mut [], 0).unwrap();
    assert!(heap.capacity_words() < 10_000);
    // SAFETY: the tuple is still live in the shrunken heap.
    let element = unsafe { roots[0].tuple_ref() }.unwrap().get(0).unwrap();
    assert_eq!(element.as_small(), Some(1));
}

#[test]
fn random_shared_graphs_survive_repeated_collections() {
    let mut heap = ProcessHeap::with_words(2048);
    let mut roots = [Term::NIL; 16];
    let mut seed = 0x1234_5678_u64;
    for step in 0..if cfg!(miri) { 100 } else { 1000 } {
        if heap.free_words() < 64 {
            heap.collect(&mut roots, &mut [], 64).unwrap();
        }
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        let source = roots[(seed as usize) % roots.len()];
        let next = if step % 2 == 0 {
            TermBuilder::new(&mut heap).cons(source, source).unwrap()
        } else {
            TermBuilder::new(&mut heap)
                .tuple(&[source, source])
                .unwrap()
        };
        roots[(seed as usize / 3) % roots.len()] = next;
        if step % 100 == 99 {
            heap.collect(&mut roots, &mut [], 64).unwrap();
        }
    }
    for root in roots {
        // SAFETY: All roots point into the live, stable heap.
        if let Some(tuple) = unsafe { root.tuple_ref() } {
            assert_eq!(tuple.get(0), tuple.get(1));
        }
        // SAFETY: All roots point into the live, stable heap.
        if let Some((head, tail)) = unsafe { root.cons_ref() } {
            assert_eq!(head, tail);
        }
    }
}

#[test]
fn hamt_sizes_survive_repeated_collections() {
    let sizes: &[usize] = if cfg!(miri) {
        &[33, 48]
    } else {
        &[33, 48, 64, 257, 1_000, 5_000]
    };
    for &size in sizes {
        let mut heap = ProcessHeap::with_words(size * 8 + 256);
        let pairs = (0..size)
            .map(|i| {
                (
                    Term::small(i as i64).unwrap(),
                    Term::small((i * 7) as i64).unwrap(),
                )
            })
            .collect::<Vec<_>>();
        let map = TermBuilder::new(&mut heap)
            .flatmap_from_pairs(&pairs)
            .unwrap();
        assert!(map.is_hashmap());
        let expected = to_owned(map).unwrap();
        let hash = make_hash2(map);
        let words = size_object(map);
        let mut roots = [map];
        for _ in 0..if cfg!(miri) { 2 } else { 8 } {
            heap.collect(&mut roots, &mut [], 0).unwrap();
            assert_eq!(to_owned(roots[0]).unwrap(), expected);
            assert_eq!(make_hash2(roots[0]), hash);
            assert_eq!(size_object(roots[0]), words);
        }
    }
}

#[test]
fn match_context_aliases_keep_one_cursor_and_moved_base() {
    let mut heap = ProcessHeap::with_words(256);
    let source = TermBuilder::new(&mut heap).binary(&[0xa5; 32]).unwrap();
    let context = TermBuilder::new(&mut heap).match_context(source).unwrap();
    assert!(set_match_position(context, 19));
    let mut roots = [context, context];
    heap.collect(&mut roots, &mut [], 0).unwrap();
    assert_eq!(roots[0], roots[1]);
    assert_eq!(match_position(roots[0]), Some(19));
    assert!(set_match_position(roots[0], 37));
    assert_eq!(match_position(roots[1]), Some(37));
    // SAFETY: the new heap and its moved HeapBits owner remain live.
    let view = unsafe { roots[1].binary_ref() }.unwrap();
    assert_eq!(view.bytes()[0], 0xa5);
    assert_eq!(view.start_bit(), 37);
}

#[test]
fn writable_append_survives_collections_and_releases_dead_owners() {
    let mut heap = ProcessHeap::with_words(256);
    let mut roots = [TermBuilder::new(&mut heap)
        .writable_binary(&[], 0, 1_048_576)
        .unwrap()];
    let capacity = writable_capacity(roots[0]).unwrap();
    for block in 0..if cfg!(miri) { 4 } else { 64 } {
        let block_size = if cfg!(miri) { 256 } else { 16_384 };
        let end = (block + 1) * block_size;
        assert!(writable_extend_private(roots[0], end * 8).unwrap());
        // SAFETY: this process owns the active writer and no view is retained.
        unsafe { writable_bytes_mut(roots[0]) }.unwrap()[block * block_size..end].fill(block as u8);
        heap.collect(&mut roots, &mut [], 0).unwrap();
        assert_eq!(writable_capacity(roots[0]), Some(capacity));
    }
    // SAFETY: the collected heap retains the writable owner and no append runs.
    let view = unsafe { roots[0].binary_ref() }.unwrap();
    let block_size = if cfg!(miri) { 256 } else { 16_384 };
    assert_eq!(
        view.bit_len(),
        (if cfg!(miri) { 4 } else { 64 }) * block_size * 8
    );
    for (block, chunk) in view.bytes().chunks(block_size).enumerate() {
        assert!(chunk.iter().all(|&byte| byte == block as u8));
    }
    for _ in 0..3 {
        let _dead = TermBuilder::new(&mut heap)
            .writable_binary(&[1; 100], 800, 4_096)
            .unwrap();
    }
    assert_eq!(heap.off_heap_count(), 4);
    heap.collect(&mut roots, &mut [], 0).unwrap();
    assert_eq!(heap.off_heap_count(), 1);
}

#[test]
fn owner_arcs_are_released_when_unreachable() {
    let mut heap = ProcessHeap::with_words(256);
    let module = global_atoms().intern("gc_owner_module").unwrap();
    let function = global_atoms().intern("gc_owner_function").unwrap();
    let node = Node::new(module, 1);
    let fun = Arc::new(FunEntry {
        dispatch_target: Default::default(),
        pend_purge_address: Default::default(),
        module,
        arity: 0,
        uniq: [1; 16],
        index: 1,
        old_index: 1,
        old_uniq: 1,
        pid: Term::pid(1, 0).unwrap(),
        dispatch: Default::default(),
        dispatch_code: Default::default(),
        dispatch_epoch: Default::default(),
    });
    let export = Arc::new(ExportEntry::new(module, function, 0));
    let _identity = TermBuilder::new(&mut heap)
        .external_pid(node.clone(), 1, 0)
        .unwrap();
    let _fun = TermBuilder::new(&mut heap)
        .local_fun(fun.clone(), &[])
        .unwrap();
    let _export = TermBuilder::new(&mut heap)
        .export_fun(export.clone())
        .unwrap();
    let binary_bytes_before = binary_memory_bytes();
    let _binary = TermBuilder::new(&mut heap).binary(&[9; 100]).unwrap();
    assert!(binary_memory_bytes() > binary_bytes_before);
    heap.collect(&mut [], &mut [], 0).unwrap();
    assert_eq!(binary_memory_bytes(), binary_bytes_before);
    assert_eq!(Arc::strong_count(&node), 1);
    assert_eq!(Arc::strong_count(&fun), 1);
    assert_eq!(Arc::strong_count(&export), 1);
}

#[test]
fn shared_writable_owner_is_retained_once_and_then_released() {
    let mut heap = ProcessHeap::with_words(256);
    let binary_bytes_before = binary_memory_bytes();
    let writable = TermBuilder::new(&mut heap)
        .writable_binary(&[5; 100], 800, 1_024)
        .unwrap();
    let sub = TermBuilder::new(&mut heap)
        .sub_binary(writable, 8, 400)
        .unwrap();
    let mut roots = [writable, sub];
    heap.collect(&mut roots, &mut [], 0).unwrap();
    let binary_info = heap.off_heap_binary_info();
    assert_eq!(binary_info.len(), 2);
    assert!(binary_info.iter().all(|entry| entry.2 == 2));
    heap.collect(&mut [], &mut [], 0).unwrap();
    assert_eq!(binary_memory_bytes(), binary_bytes_before);
}

#[test]
fn stack_skips_return_addresses_and_catch_markers() {
    let mut heap = ProcessHeap::with_words(128);
    assert!(heap.reserve_stack(2));
    // SAFETY: a raw aligned code address is a stack word, never dereferenced here.
    let code = unsafe { std::mem::transmute::<u64, Term>(0x1000) };
    assert!(heap.stack_set(0, code));
    assert!(heap.stack_set(1, Term::catch(42)));
    heap.collect(&mut [], &mut [], 0).unwrap();
    assert_eq!(heap.stack_get(0), Some(code));
    assert_eq!(heap.stack_get(1), Some(Term::catch(42)));
}

#[test]
fn mixed_boxed_graph_survives_one_hundred_collections() {
    let mut heap = ProcessHeap::with_words(32_768);
    let module = global_atoms().intern("gc_graph_module").unwrap();
    let name = global_atoms().intern("gc_graph_name").unwrap();
    let node = Node::new(module, 3);
    let number = TermBuilder::new(&mut heap)
        .int_from_i128(1_i128 << 100)
        .unwrap();
    let float = TermBuilder::new(&mut heap).float(1.25).unwrap();
    let local_ref = TermBuilder::new(&mut heap).local_ref([1, 2, 3]).unwrap();
    let heap_bits = TermBuilder::new(&mut heap)
        .bitstring(&[0xab; 32], 253)
        .unwrap();
    let context = TermBuilder::new(&mut heap)
        .match_context(heap_bits)
        .unwrap();
    let off_heap = TermBuilder::new(&mut heap).binary(&[0xcd; 100]).unwrap();
    let sub_bits = TermBuilder::new(&mut heap)
        .sub_binary(off_heap, 5, 700)
        .unwrap();
    let flatmap = TermBuilder::new(&mut heap)
        .flatmap_from_pairs(&[
            (Term::small(1).unwrap(), number),
            (Term::small(2).unwrap(), float),
        ])
        .unwrap();
    let pairs = (0..40)
        .map(|i| (Term::small(i).unwrap(), Term::small(i * 3).unwrap()))
        .collect::<Vec<_>>();
    let hamt = TermBuilder::new(&mut heap)
        .flatmap_from_pairs(&pairs)
        .unwrap();
    let record = TermBuilder::new(&mut heap)
        .native_record(module, name, true, &[(name, flatmap)])
        .unwrap();
    let fun_entry = Arc::new(FunEntry {
        dispatch_target: Default::default(),
        pend_purge_address: Default::default(),
        module,
        arity: 1,
        uniq: [7; 16],
        index: 2,
        old_index: 2,
        old_uniq: 7,
        pid: Term::pid(1, 0).unwrap(),
        dispatch: Default::default(),
        dispatch_code: Default::default(),
        dispatch_epoch: Default::default(),
    });
    let fun = TermBuilder::new(&mut heap)
        .local_fun(fun_entry, &[record, hamt])
        .unwrap();
    let export = TermBuilder::new(&mut heap)
        .export_fun(Arc::new(ExportEntry::new(module, name, 2)))
        .unwrap();
    let pid = TermBuilder::new(&mut heap)
        .external_pid(node.clone(), 10, 2)
        .unwrap();
    let port = TermBuilder::new(&mut heap)
        .external_port(node.clone(), 999)
        .unwrap();
    let reference = TermBuilder::new(&mut heap)
        .external_ref(node, &[1, 2, 3])
        .unwrap();
    let samples = [
        number, float, local_ref, heap_bits, context, off_heap, sub_bits, flatmap, hamt, record,
        fun, export, pid, port, reference,
    ];
    let mut root = TermBuilder::new(&mut heap).tuple(&samples).unwrap();
    let mut seed = 0x9e37_79b9_u64;
    for _ in 0..if cfg!(miri) { 6 } else { 32 } {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        let leaf = samples[(seed as usize) % samples.len()];
        root = if seed & 1 == 0 {
            TermBuilder::new(&mut heap).tuple(&[leaf, root]).unwrap()
        } else {
            TermBuilder::new(&mut heap).cons(leaf, root).unwrap()
        };
    }
    let mut reference_heap = VecHeap::new();
    let expected = copy_term(root, &mut reference_heap).unwrap();
    let mut roots = [root];
    for _ in 0..if cfg!(miri) { 10 } else { 100 } {
        heap.collect(&mut roots, &mut [], 0).unwrap();
        assert!(heap.old_generation_is_closed());
        assert!(exact_eq(roots[0], expected));
    }
}

#[test]
#[ignore = "release-mode throughput measurement"]
fn gc_throughput() {
    arinsal_term::set_gc_clock_for_long_gc(true);
    fn measure(label: &str, mut heap: ProcessHeap, root: Term) {
        heap.set_fullsweep_after(0);
        let mut roots = [root];
        let live_bytes = heap.used_words() * 8;
        let mut nanos = 0_u64;
        let mut copied = 0_u64;
        for _ in 0..5 {
            let stats = heap.collect(&mut roots, &mut [], 0).unwrap();
            nanos += stats.nanoseconds;
            copied += stats.words_copied;
        }
        let mbps = (copied as f64 * 8.0 / 1_000_000.0) / (nanos as f64 / 1e9);
        println!("{label}: {live_bytes} live bytes, {mbps:.1} MB/s fullsweep copy");
    }

    let mut list_heap = ProcessHeap::with_words(2_000_128);
    let mut list = Term::NIL;
    for i in 0..1_000_000 {
        list = TermBuilder::new(&mut list_heap)
            .cons(Term::small(i).unwrap(), list)
            .unwrap();
    }
    measure("list", list_heap, list);

    let mut tree_heap = ProcessHeap::with_words(1_000_000);
    let mut level = (0..(1 << 18))
        .map(|i| Term::small(i).unwrap())
        .collect::<Vec<_>>();
    while level.len() > 1 {
        level = level
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| TermBuilder::new(&mut tree_heap).tuple(pair).unwrap())
            .collect();
    }
    measure("tuple tree", tree_heap, level[0]);

    let mut map_heap = ProcessHeap::with_words(100_000);
    let pairs = (0..10_000)
        .map(|i| (Term::small(i).unwrap(), Term::small(i * 2).unwrap()))
        .collect::<Vec<_>>();
    let map = TermBuilder::new(&mut map_heap)
        .flatmap_from_pairs(&pairs)
        .unwrap();
    measure("10k HAMT", map_heap, map);
}

#[test]
fn promotion_closes_old_graph_without_young_references() {
    let mut heap = ProcessHeap::with_words(512);
    let leaf = TermBuilder::new(&mut heap)
        .cons(Term::small(9).unwrap(), Term::NIL)
        .unwrap();
    let mut roots = [TermBuilder::new(&mut heap).tuple(&[leaf, leaf]).unwrap()];
    // erts runs the first collection of a heap without old heap or mature data as a full
    // sweep (erl_gc.c:1461-1488); the second one then tenures the data.
    let first = heap.collect(&mut roots, &mut [], 0).unwrap();
    assert_eq!(first.major_collections, 1);
    assert_eq!(heap.old_used_words(), 0);
    let second = heap.collect(&mut roots, &mut [], 0).unwrap();
    assert!(second.words_promoted >= 5);
    assert!(heap.old_generation_contains(roots[0]));
    assert!(heap.old_generation_is_closed());
    let old_parent = roots[0];
    // SAFETY: The old heap remains allocated across minor collections.
    let tuple = unsafe { roots[0].tuple_ref() }.unwrap();
    let old_leaf = tuple.get(0).unwrap();
    assert_eq!(tuple.get(1), Some(old_leaf));
    assert!(heap.old_generation_contains(old_leaf));
    let young = TermBuilder::new(&mut heap)
        .tuple(&[Term::small(99).unwrap()])
        .unwrap();
    let mut extra = [young];
    heap.collect(&mut roots, &mut extra, 0).unwrap();
    assert_eq!(roots[0], old_parent);
    assert!(!heap.old_generation_contains(extra[0]));
    assert!(heap.old_generation_is_closed());
    // SAFETY: Promotion preserved the complete old graph.
    let tuple = unsafe { roots[0].tuple_ref() }.unwrap();
    assert!(heap.old_generation_contains(tuple.get(0).unwrap()));
}

#[test]
fn fullsweep_after_zero_never_builds_old_generation() {
    let mut heap = ProcessHeap::with_words(256);
    heap.set_fullsweep_after(0);
    let mut roots = [TermBuilder::new(&mut heap)
        .tuple(&[Term::small(1).unwrap()])
        .unwrap()];
    for _ in 0..5 {
        let stats = heap.collect(&mut roots, &mut [], 0).unwrap();
        assert_eq!(stats.major_collections, 1);
        assert_eq!(stats.minor_collections, 0);
        assert_eq!(heap.old_used_words(), 0);
    }
}

#[test]
fn fullsweep_shrinks_heap_with_many_dead_objects() {
    let mut heap = ProcessHeap::with_words(12_000);
    heap.set_fullsweep_after(0);
    let mut roots = [TermBuilder::new(&mut heap)
        .tuple(&[Term::small(7).unwrap()])
        .unwrap()];
    for i in 0..if cfg!(miri) { 100 } else { 3_000 } {
        let value = Term::small(i).unwrap();
        let _dead = TermBuilder::new(&mut heap).tuple(&[value, value]).unwrap();
    }
    heap.collect(&mut roots, &mut [], 0).unwrap();
    assert!(heap.capacity_words() < 1_000);
    // SAFETY: The root was rewritten by the full sweep and remains live.
    let tuple = unsafe { roots[0].tuple_ref() }.unwrap();
    assert_eq!(tuple.get(0).unwrap().as_small(), Some(7));
}

#[test]
fn young_owners_release_on_minor_and_old_owners_on_major() {
    let mut heap = ProcessHeap::with_words(1024);
    let mut roots = [TermBuilder::new(&mut heap).binary(&[1; 100]).unwrap()];
    heap.collect(&mut roots, &mut [], 0).unwrap();
    heap.collect(&mut roots, &mut [], 0).unwrap();
    assert!(heap.old_generation_contains(roots[0]));
    assert_eq!(heap.off_heap_count(), 1);
    let _dead_young = TermBuilder::new(&mut heap).binary(&[2; 100]).unwrap();
    assert_eq!(heap.off_heap_count(), 2);
    heap.collect(&mut roots, &mut [], 0).unwrap();
    assert_eq!(heap.off_heap_count(), 1);
    roots[0] = Term::NIL;
    heap.collect(&mut roots, &mut [], 0).unwrap();
    assert_eq!(heap.off_heap_count(), 1);
    heap.set_fullsweep_after(0);
    heap.collect(&mut roots, &mut [], 0).unwrap();
    assert_eq!(heap.off_heap_count(), 0);
}

#[test]
fn trees_like_short_lived_tuples_copy_few_words() {
    let mut heap = ProcessHeap::with_words(2048);
    heap.set_min_heap_size(2048);
    let leaves = (0..256)
        .map(|i| Term::small(i).unwrap())
        .collect::<Vec<_>>();
    let mut roots = [TermBuilder::new(&mut heap).tuple(&leaves).unwrap()];
    // The first collection is a full sweep without an old heap (erl_gc.c:1461-1488);
    // run it up front so the measured loop only sees minor collections.
    assert_eq!(
        heap.collect(&mut roots, &mut [], 0)
            .unwrap()
            .major_collections,
        1
    );
    let mut minor = 0;
    let mut major = 0;
    let mut copied = 0;
    let mut promoted = 0;
    let mut nanos = 0;
    for _ in 0..if cfg!(miri) { 4 } else { 40 } {
        for i in 0..200 {
            let value = Term::small(i).unwrap();
            let _temporary = TermBuilder::new(&mut heap).tuple(&[value, value]).unwrap();
        }
        let stats = heap.collect(&mut roots, &mut [], 0).unwrap();
        minor += stats.minor_collections;
        major += stats.major_collections;
        copied += stats.words_copied;
        promoted += stats.words_promoted;
        nanos += stats.nanoseconds;
    }
    assert_eq!(major, 0);
    assert_eq!(minor, if cfg!(miri) { 4 } else { 40 });
    assert!(copied <= 257);
    assert!(promoted <= 257);
    assert!(heap.old_generation_contains(roots[0]));
    println!(
        "trees-like: {minor} minor, {major} major, {copied} copied words, {promoted} promoted words, {nanos} ns GC"
    );
}

#[test]
fn repeated_short_lived_bursts_do_not_expand_young_heap() {
    let mut heap = ProcessHeap::with_words(512);
    let mut roots = [TermBuilder::new(&mut heap)
        .tuple(&[Term::small(1).unwrap()])
        .unwrap()];
    for _ in 0..if cfg!(miri) { 4 } else { 40 } {
        while heap.free_words() >= 3 {
            let _dead = TermBuilder::new(&mut heap)
                .tuple(&[Term::small(2).unwrap(), Term::small(3).unwrap()])
                .unwrap();
        }
        heap.collect(&mut roots, &mut [], 3).unwrap();
        assert!(heap.capacity_words() < 1_000);
    }
}

#[test]
fn high_survival_grows_young_without_oversizing_old() {
    let mut heap = ProcessHeap::with_words(512);
    heap.set_min_heap_size(512);
    let values = [Term::small(1).unwrap(); 127];
    let mut roots = [TermBuilder::new(&mut heap).tuple(&values).unwrap()];
    heap.collect(&mut roots, &mut [], 0).unwrap();
    for _ in 0..190 {
        roots[0] = TermBuilder::new(&mut heap)
            .cons(Term::small(2).unwrap(), roots[0])
            .unwrap();
    }
    let stats = heap.collect(&mut roots, &mut [], 0).unwrap();
    assert_eq!(stats.major_collections, 0);
    assert!(heap.capacity_words() > 512);
    assert_eq!(heap.old_used_words(), 128);
    let old_capacity = heap.total_heap_size_words() - heap.capacity_words();
    // Port of erl_gc.c:1445-1471: the old heap uses
    // erts_next_heap_size(size_before, 1). This setup has 508 young words;
    // the next strictly larger OTP ladder entry is 987.
    assert_eq!(old_capacity, 987);
    assert!(heap.old_generation_is_closed());

    roots[0] = Term::NIL;
    heap.set_fullsweep_after(0);
    heap.collect(&mut roots, &mut [], 0).unwrap();
    assert_eq!(heap.old_used_words(), 0);
    assert_eq!(heap.total_heap_size_words(), heap.capacity_words());
    assert_eq!(heap.capacity_words(), 610);
}

#[test]
fn minor_gc_shrinks_a_dead_heap_without_a_presizing_walk() {
    let mut heap = ProcessHeap::with_words(16_000);
    let bits = TermBuilder::new(&mut heap).binary(&[0xab; 32]).unwrap();
    let off_heap = TermBuilder::new(&mut heap).binary(&[0xcd; 80]).unwrap();
    let sub = TermBuilder::new(&mut heap)
        .sub_binary(off_heap, 1, 16)
        .unwrap();
    let live = TermBuilder::new(&mut heap).tuple(&[bits, sub]).unwrap();
    assert!(heap.reserve_stack(2));
    assert!(heap.stack_set(0, live));
    assert!(heap.stack_set(1, Term::catch(7)));
    for i in 0..if cfg!(miri) { 40 } else { 3_000 } {
        let value = Term::small(i).unwrap();
        let _dead = TermBuilder::new(&mut heap).tuple(&[value, value]).unwrap();
    }
    let mut reference = VecHeap::new();
    let expected = copy_term(live, &mut reference).unwrap();
    let mut roots = [live];
    heap.collect(&mut roots, &mut [], 8).unwrap();
    assert!(heap.capacity_words() < 2_000);
    assert!(heap.free_words() >= 8);
    assert_eq!(heap.stack_get(0), Some(roots[0]));
    assert_eq!(heap.stack_get(1), Some(Term::catch(7)));
    assert!(exact_eq(roots[0], expected));
    assert!(heap.old_generation_is_closed());
}
