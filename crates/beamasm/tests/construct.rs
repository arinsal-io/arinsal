use std::sync::{
    Mutex, OnceLock,
    atomic::{AtomicUsize, Ordering},
};

use arinsal_a64::enc::Gpr;
use arinsal_beamasm::{
    ExitReason, ProcessHeader, SchedulerRegisters,
    construct::GcHook,
    enter_native,
    module::{ArgVal, BeamModuleAssembler, FinalizedModule},
    rt,
};

static MOVED_AREAS: OnceLock<Mutex<Vec<Box<[u64]>>>> = OnceLock::new();
static GC_CALLS: AtomicUsize = AtomicUsize::new(0);
static Y_ROOT_GC_CALLS: AtomicUsize = AtomicUsize::new(0);

extern "C" fn arithmetic_fallback(
    _header: *mut ProcessHeader,
    _op: u32,
    _lhs: u64,
    _rhs: u64,
) -> u64 {
    0
}

extern "C" fn moving_gc(
    header_pointer: *mut ProcessHeader,
    regs_pointer: *mut SchedulerRegisters,
    need_words: usize,
    live: usize,
    _fcalls: i32,
) -> i32 {
    rt::process_header_mut(header_pointer, |header| {
        rt::scheduler_registers_mut(regs_pointer, |regs| {
            let old_heap = header.heap;
            let old_top = header.htop;
            let used = (old_top as usize - old_heap as usize) / std::mem::size_of::<u64>();
            let capacity = used + need_words + 64;
            let mut new_area = vec![0u64; capacity].into_boxed_slice();
            let new_heap = new_area.as_mut_ptr();
            rt::copy_words(old_heap, new_heap, used);
            let old_start = old_heap as usize;
            let old_end = old_top as usize;
            for root in regs.x_reg_array.iter_mut().take(live.min(6)) {
                let tag = *root & 7;
                if tag == 1 || tag == 2 {
                    let pointer = (*root & !7) as usize;
                    if (old_start..old_end).contains(&pointer) {
                        *root = ((*root & !7)
                            .wrapping_add((new_heap as usize).wrapping_sub(old_start) as u64))
                            | tag;
                    }
                }
            }
            header.heap = new_heap;
            header.htop = new_heap.wrapping_add(used);
            header.hend = new_heap.wrapping_add(capacity);
            MOVED_AREAS
                .get_or_init(Default::default)
                .lock()
                .unwrap()
                .push(new_area);
            GC_CALLS.fetch_add(1, Ordering::SeqCst);
            0
        })
    })
}

extern "C" fn moving_gc_with_y_root(
    header_pointer: *mut ProcessHeader,
    regs_pointer: *mut SchedulerRegisters,
    need_words: usize,
    live: usize,
    _fcalls: i32,
) -> i32 {
    rt::process_header_mut(header_pointer, |header| {
        rt::scheduler_registers_mut(regs_pointer, |regs| {
            let old_heap = header.heap;
            let old_top = header.htop;
            let old_start = old_heap as usize;
            let old_end = old_top as usize;
            let used = (old_end - old_start) / std::mem::size_of::<u64>();
            let capacity = used + need_words + 64;
            let mut new_area = vec![0u64; capacity].into_boxed_slice();
            let new_heap = new_area.as_mut_ptr();
            rt::copy_words(old_heap, new_heap, used);
            for root in regs.x_reg_array.iter_mut().take(live.min(6)) {
                relocate_test_root(root, old_start, old_end, new_heap);
            }
            let mut y_root = 0;
            rt::copy_words(header.stop, &mut y_root, 1);
            relocate_test_root(&mut y_root, old_start, old_end, new_heap);
            rt::copy_words(&y_root, header.stop, 1);
            header.heap = new_heap;
            header.htop = new_heap.wrapping_add(used);
            header.hend = new_heap.wrapping_add(capacity);
            MOVED_AREAS
                .get_or_init(Default::default)
                .lock()
                .unwrap()
                .push(new_area);
            Y_ROOT_GC_CALLS.fetch_add(1, Ordering::SeqCst);
            0
        })
    })
}

fn relocate_test_root(root: &mut u64, old_start: usize, old_end: usize, new_heap: *mut u64) {
    let tag = *root & 7;
    if tag == 1 || tag == 2 {
        let pointer = (*root & !7) as usize;
        if (old_start..old_end).contains(&pointer) {
            *root = ((*root & !7).wrapping_add((new_heap as usize).wrapping_sub(old_start) as u64))
                | tag;
        }
    }
}

fn run_native(
    emit: impl FnOnce(
        &mut BeamModuleAssembler,
        GcHook,
    ) -> Result<(), arinsal_beamasm::module::ModuleError>,
    setup: impl FnOnce(&mut [u64; 128], &mut ProcessHeader, &mut SchedulerRegisters),
) -> (ProcessHeader, [u64; 1024], [u64; 128], usize) {
    let mut asm = BeamModuleAssembler::new();
    asm.emit_i_func_label(1).unwrap();
    emit(&mut asm, moving_gc).unwrap();
    asm.emit_raw(|e| {
        e.mov_reg(Gpr::x(0), Gpr::xzr())?;
        e.ret(Gpr::x(30))
    })
    .unwrap();
    let module: FinalizedModule = asm.finalize().unwrap();
    let mut area = [0u64; 128];
    let base = area.as_mut_ptr();
    let stop = base.wrapping_add(area.len());
    let hend = base.wrapping_add(96);
    let mut header = ProcessHeader {
        htop: base,
        stop,
        heap: base,
        hend,
        fcalls: 100,
        ..ProcessHeader::default()
    };
    let mut regs = SchedulerRegisters::default();
    setup(&mut area, &mut header, &mut regs);
    let result = enter_native(&mut header, &mut regs, &module.entry(1).unwrap());
    assert_eq!(result, ExitReason::Returned);
    (header, regs.x_reg_array, area, base as usize)
}

fn word_ptr(words: &mut [u64], index: usize) -> *mut u64 {
    words.as_mut_ptr().wrapping_add(index)
}

fn native_put_list() {
    let (_, regs, heap, base) = run_native(
        |m, _| m.emit_put_list(ArgVal::X(0), ArgVal::X(1), ArgVal::X(2)),
        |_, _, regs| {
            regs.x_reg_array[0] = tagged_small(13);
            regs.x_reg_array[1] = 0x3b;
        },
    );
    assert_eq!(regs[2], base as u64 | 1);
    assert_eq!(&heap[..2], &[tagged_small(13), 0x3b]);
}

fn native_put_tuple2() {
    let (_, regs, heap, base) = run_native(
        |m, _| m.emit_put_tuple2(ArgVal::X(3), &[ArgVal::X(0), ArgVal::Immediate(0x3b)]),
        |_, _, regs| {
            regs.x_reg_array[0] = tagged_small(4);
        },
    );
    assert_eq!(regs[3], base as u64 | 2);
    assert_eq!(&heap[..3], &[2 << 6, tagged_small(4), 0x3b]);
}

fn native_get_list() {
    let (_, regs, _, _) = run_native(
        |m, _| m.emit_get_list(ArgVal::X(0), ArgVal::X(1), ArgVal::X(2)),
        |heap, _, regs| {
            heap[..2].copy_from_slice(&[tagged_small(8), 0x3b]);
            regs.x_reg_array[0] = heap.as_ptr() as u64 | 1;
        },
    );
    assert_eq!((regs[1], regs[2]), (tagged_small(8), 0x3b));
}

#[test]
fn native_get_list_alias_survives_y_frame_return() {
    let (header, regs, _, base) = run_native(
        |m, hook| {
            m.emit_is_tuple(ArgVal::X(0), 100)?;
            m.emit_test_arity(ArgVal::X(0), ArgVal::Immediate(tagged_small(2)), 101)?;
            m.emit_get_tuple_element(ArgVal::X(0), 8, ArgVal::X(1))?;
            m.emit_get_tuple_element(ArgVal::X(0), 16, ArgVal::X(2))?;
            m.emit_is_nonempty_list(ArgVal::X(1), 102)?;
            m.emit_get_list(ArgVal::X(1), ArgVal::X(3), ArgVal::X(4))?;
            m.emit_is_nil(ArgVal::X(4), 103)?;
            m.emit_is_nil(ArgVal::X(2), 39)?;
            m.emit_i_func_label(39)?;
            m.emit_is_nonempty_list(ArgVal::X(2), 105)?;
            m.emit_get_list(ArgVal::X(2), ArgVal::X(3), ArgVal::X(2))?;
            m.emit_is_nil(ArgVal::X(2), 106)?;
            m.emit_is_list(ArgVal::X(1), 107)?;
            m.allocate_checked(2, 4, hook)?;
            m.init_yregs(0, 1)?;
            m.move_(ArgVal::X(3), ArgVal::Y(1))?;
            m.emit_is_nonempty_list(ArgVal::X(1), 108)?;
            m.emit_get_list(ArgVal::X(1), ArgVal::X(0), ArgVal::X(2))?;
            m.emit_is_nonempty_list(ArgVal::X(2), 40)?;
            m.emit_i_func_label(40)?;
            m.emit_is_nil(ArgVal::X(2), 110)?;
            m.emit_test_heap(3, 2, hook)?;
            m.emit_put_tuple2(ArgVal::X(0), &[ArgVal::Immediate(0x3b), ArgVal::X(1)])?;
            m.emit_test_heap(6, 1, hook)?;
            m.emit_put_tuple2(
                ArgVal::X(1),
                &[ArgVal::Immediate(tagged_small(99)), ArgVal::Y(1)],
            )?;
            m.emit_put_tuple2(ArgVal::X(0), &[ArgVal::X(1), ArgVal::X(0)])?;
            m.deallocate(2)?;
            m.return_()?;
            for label in [100, 101, 102, 103, 105, 106, 107, 108, 110] {
                m.emit_i_func_label(label)?;
                m.move_(
                    ArgVal::Immediate(tagged_small(i64::from(label))),
                    ArgVal::X(0),
                )?;
                m.emit_raw(|e| {
                    e.mov_reg(Gpr::x(0), Gpr::xzr())?;
                    e.ret(Gpr::x(30))
                })?;
            }
            Ok(())
        },
        |heap, header, regs| {
            let base = heap.as_mut_ptr();
            heap[..7].copy_from_slice(&[
                2 << 6,
                base.wrapping_add(3) as u64 | 1,
                base.wrapping_add(5) as u64 | 1,
                (1 << 6) | 0x0b,
                0x3b,
                (2 << 6) | 0x0b,
                0x3b,
            ]);
            header.htop = word_ptr(heap, 7);
            header.stop = word_ptr(heap, 126);
            heap[126] = 0;
            heap[127] = arinsal_beamasm::rt::arinsal_enter_native_return as *const () as u64;
            regs.x_reg_array[0] = base as u64 | 2;
        },
    );

    assert_eq!(regs[0], (base + 13 * 8) as u64 | 2);
    let outer = regs[0];
    let value_tuple = rt::read_heap_word(outer, 1);
    let queue_tuple = rt::read_heap_word(outer, 2);
    assert_eq!(rt::read_heap_word(value_tuple, 1), tagged_small(99));
    assert_eq!(rt::read_heap_word(value_tuple, 2), (2 << 6) | 0x0b);
    assert_eq!(rt::read_heap_word(queue_tuple, 1), 0x3b);
    assert_eq!(
        rt::read_heap_word(queue_tuple, 2),
        (base + 3 * 8) as u64 | 1
    );
    assert_eq!(header.htop as usize, base + 16 * 8);
    assert_eq!(header.stop as usize, base + 128 * 8);
}

fn native_list_tail_survives_tuple_field_loads() {
    let (_, regs, _, base) = run_native(
        |m, _| {
            m.emit_get_list(ArgVal::X(0), ArgVal::X(3), ArgVal::X(4))?;
            m.emit_get_tuple_element(ArgVal::X(3), 8, ArgVal::X(0))?;
            m.emit_i_plus(
                ArgVal::X(1),
                ArgVal::X(0),
                ArgVal::X(0),
                arithmetic_fallback,
            )?;
            m.emit_get_tuple_element(ArgVal::X(3), 16, ArgVal::X(1))?;
            m.emit_i_plus(
                ArgVal::X(1),
                ArgVal::Immediate(tagged_small(0)),
                ArgVal::X(2),
                arithmetic_fallback,
            )?;
            m.move_(ArgVal::X(0), ArgVal::X(1))?;
            m.move_(ArgVal::X(4), ArgVal::X(0))
        },
        |heap, _, regs| {
            let base = heap.as_mut_ptr();
            heap[..5].copy_from_slice(&[
                2 << 6,
                tagged_small(3),
                tagged_small(4),
                base as u64 | 2,
                base.wrapping_add(6) as u64 | 1,
            ]);
            regs.x_reg_array[0] = base.wrapping_add(3) as u64 | 1;
            regs.x_reg_array[1] = tagged_small(2);
            regs.x_reg_array[2] = tagged_small(0);
        },
    );
    assert_eq!(regs[0], (base as u64 + 48) | 1);
    assert_eq!(regs[1], tagged_small(5));
    assert_eq!(regs[2], tagged_small(4));
}

fn native_get_hd() {
    let (_, regs, _, _) = run_native(
        |m, _| m.emit_get_hd(ArgVal::X(0), ArgVal::X(1)),
        |heap, _, regs| {
            heap[0] = tagged_small(21);
            regs.x_reg_array[0] = heap.as_ptr() as u64 | 1;
        },
    );
    assert_eq!(regs[1], tagged_small(21));
}

fn native_get_tl() {
    let (_, regs, _, _) = run_native(
        |m, _| m.emit_get_tl(ArgVal::X(0), ArgVal::X(1)),
        |heap, _, regs| {
            heap[1] = tagged_small(22);
            regs.x_reg_array[0] = heap.as_ptr() as u64 | 1;
        },
    );
    assert_eq!(regs[1], tagged_small(22));
}

fn native_get_tuple_element() {
    let (_, regs, _, _) = run_native(
        |m, _| m.emit_get_tuple_element(ArgVal::X(0), 16, ArgVal::X(1)),
        |heap, _, regs| {
            heap[..3].copy_from_slice(&[(2 << 6) | 2, tagged_small(3), tagged_small(9)]);
            regs.x_reg_array[0] = heap.as_ptr() as u64 | 2;
        },
    );
    assert_eq!(regs[1], tagged_small(9));
}

fn native_i_get_tuple_element2() {
    let (_, regs, _, _) = run_native(
        |m, _| m.emit_i_get_tuple_element2(ArgVal::X(0), 8, ArgVal::X(1)),
        |heap, _, regs| {
            heap[1] = tagged_small(31);
            regs.x_reg_array[0] = heap.as_ptr() as u64;
        },
    );
    assert_eq!(regs[1], tagged_small(31));
}

fn native_load_tuple_ptr() {
    let (_, regs, _, base) = run_native(
        |m, _| m.emit_load_tuple_ptr(ArgVal::X(0), ArgVal::X(1)),
        |heap, _, regs| {
            regs.x_reg_array[0] = heap.as_ptr() as u64 | 2;
        },
    );
    // OTP leaves the tagged source register alone and parks the untagged
    // pointer in ARG1 (x0), not in an X register.
    assert_eq!(regs[0], base as u64 | 2);
    assert_eq!(regs[1], 0);
}

#[test]
fn tuple_pointer_operation_preserves_y_root_across_moving_gc() {
    Y_ROOT_GC_CALLS.store(0, Ordering::SeqCst);
    let (_, regs, _, _) = run_native(
        |m, _| {
            m.move_(ArgVal::X(0), ArgVal::Y(0))?;
            m.emit_load_tuple_ptr(ArgVal::Y(0), ArgVal::Y(0))?;
            m.emit_test_heap(100, 1, moving_gc_with_y_root)?;
            m.move_(ArgVal::Y(0), ArgVal::X(1))
        },
        |area, header, regs| {
            area[..3].copy_from_slice(&[2 << 6, tagged_small(41), tagged_small(42)]);
            header.htop = word_ptr(area, 3);
            header.hend = word_ptr(area, 4);
            header.stop = word_ptr(area, 8);
            regs.x_reg_array[0] = area.as_ptr() as u64 | 2;
        },
    );
    assert_eq!(Y_ROOT_GC_CALLS.load(Ordering::SeqCst), 1);
    assert_eq!(regs[0], regs[1]);
    assert_eq!(rt::read_heap_word(regs[1], 2), tagged_small(42));
}

fn native_set_tuple_element() {
    let (_, _, heap, _) = run_native(
        |m, _| m.emit_set_tuple_element(ArgVal::X(1), ArgVal::X(0), 16),
        |heap, _, regs| {
            heap[2] = tagged_small(1);
            regs.x_reg_array[0] = heap.as_ptr() as u64 | 2;
            regs.x_reg_array[1] = tagged_small(42);
        },
    );
    assert_eq!(heap[2], tagged_small(42));
}

fn native_update_record() {
    let (_, regs, heap, base) = run_native(
        |m, _| {
            m.emit_update_record(
                ArgVal::X(0),
                ArgVal::X(1),
                2,
                &[(2, ArgVal::Immediate(0x3b))],
            )
        },
        |heap, header, regs| {
            heap[..3].copy_from_slice(&[(2 << 6) | 2, tagged_small(5), tagged_small(6)]);
            header.htop = word_ptr(heap, 3);
            regs.x_reg_array[0] = heap.as_ptr() as u64 | 2;
        },
    );
    assert_eq!(regs[1], (base + 24) as u64 | 2);
    assert_eq!(&heap[3..6], &[(2 << 6) | 2, tagged_small(5), 0x3b]);
}

fn native_update_record_in_place_reuses_young_tuple() {
    let (header, regs, heap, base) = run_native(
        |m, _| m.emit_update_record_in_place(ArgVal::X(0), ArgVal::X(1), 2, &[(2, ArgVal::X(2))]),
        |heap, header, regs| {
            heap[..3].copy_from_slice(&[(2 << 6) | 2, tagged_small(5), tagged_small(6)]);
            header.htop = word_ptr(heap, 3);
            header.high_water = word_ptr(heap, 0);
            regs.x_reg_array[0] = heap.as_ptr() as u64 | 2;
            regs.x_reg_array[2] = tagged_small(42);
        },
    );
    assert_eq!(regs[1], base as u64 | 2);
    assert_eq!(
        &heap[..3],
        &[(2 << 6) | 2, tagged_small(5), tagged_small(42)]
    );
    assert_eq!(header.htop as usize, base + 24);
}

fn native_update_record_in_place_copies_old_tuple() {
    let (header, regs, heap, base) = run_native(
        |m, _| m.emit_update_record_in_place(ArgVal::X(0), ArgVal::X(1), 2, &[(2, ArgVal::X(2))]),
        |heap, header, regs| {
            heap[..3].copy_from_slice(&[(2 << 6) | 2, tagged_small(5), tagged_small(6)]);
            header.htop = word_ptr(heap, 3);
            header.high_water = word_ptr(heap, 3);
            regs.x_reg_array[0] = heap.as_ptr() as u64 | 2;
            regs.x_reg_array[2] = tagged_small(42);
        },
    );
    assert_eq!(regs[1], (base + 24) as u64 | 2);
    assert_eq!(
        &heap[..3],
        &[(2 << 6) | 2, tagged_small(5), tagged_small(6)]
    );
    assert_eq!(
        &heap[3..6],
        &[(2 << 6) | 2, tagged_small(5), tagged_small(42)]
    );
    assert_eq!(header.htop as usize, base + 48);
}

fn native_test_heap() {
    let before = GC_CALLS.load(Ordering::SeqCst);
    let (header, regs, _, base) = run_native(
        |m, hook| m.emit_test_heap(1, 1, hook),
        |heap, header, regs| {
            heap[..2].copy_from_slice(&[(1 << 6) | 2, tagged_small(77)]);
            header.htop = word_ptr(heap, 2);
            header.stop = word_ptr(heap, 2);
            header.hend = word_ptr(heap, 2);
            regs.x_reg_array[0] = heap.as_ptr() as u64 | 2;
        },
    );
    assert!(GC_CALLS.load(Ordering::SeqCst) > before);
    assert_ne!(header.heap as usize, base);
    assert_eq!(header.heap as u64, regs[0] & !7);
    let moved_value = rt::read_heap_word(regs[0], 1);
    assert_eq!(moved_value, tagged_small(77));
}

fn native_allocate_heap() {
    let before = GC_CALLS.load(Ordering::SeqCst);
    let (header, _, _, _) = run_native(
        |m, hook| m.emit_allocate_heap(1, 1, 1, hook),
        |heap, header, _| {
            header.htop = word_ptr(heap, 2);
            header.stop = word_ptr(heap, 2);
            header.hend = word_ptr(heap, 2);
        },
    );
    assert!(GC_CALLS.load(Ordering::SeqCst) > before);
    assert_eq!(header.htop as usize - header.heap as usize, 16);
}

fn native_allocate_heap_zero() {
    let before = GC_CALLS.load(Ordering::SeqCst);
    let (header, _, area, _) = run_native(
        |m, hook| m.emit_allocate_heap_zero(1, 1, 1, hook),
        |heap, header, _| {
            header.htop = word_ptr(heap, 2);
            header.stop = word_ptr(heap, 2);
            header.hend = word_ptr(heap, 2);
        },
    );
    assert!(GC_CALLS.load(Ordering::SeqCst) > before);
    // Stack remains at the old test address; the slot below its original top is initialized.
    assert_eq!(area[1], 0x3b);
    let _ = header;
}

fn tagged_small(value: i64) -> u64 {
    ((value as u64) << 4) | 15
}

#[test]
fn native_construction_and_access_ops() {
    native_put_list();
    native_put_tuple2();
    native_get_list();
    native_list_tail_survives_tuple_field_loads();
    native_get_hd();
    native_get_tl();
    native_get_tuple_element();
    native_i_get_tuple_element2();
    native_load_tuple_ptr();
    native_set_tuple_element();
    native_update_record();
    native_update_record_in_place_reuses_young_tuple();
    native_update_record_in_place_copies_old_tuple();
}

#[test]
fn native_heap_checks_collect_moving_live_roots() {
    native_test_heap();
    native_allocate_heap();
    native_allocate_heap_zero();
}
