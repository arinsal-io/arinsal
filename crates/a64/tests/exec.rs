//! Tests for executable memory, JIT allocation, W^X toggling, and cache invalidation.

use arinsal_a64::exec::{CODE_ALIGNMENT, CodeMemory, ExecError};

#[test]
fn code_memory_spans_share_allocator_block() {
    let first = CodeMemory::new(4096).expect("allocate first code span");
    let second = CodeMemory::new(4096).expect("allocate second code span");
    let first_ptr = first.as_ptr() as usize;
    let second_ptr = second.as_ptr() as usize;

    assert_ne!(first_ptr, second_ptr);
    assert!(first_ptr.abs_diff(second_ptr) < 32 * 1024 * 1024);
}

/// The primary acceptance test required for Task p3_exec:
/// 1. Write the 2-instruction function `add x0, x0, x1; ret` (words `0x8b010000`, `0xd65f03c0`) into a block.
/// 2. Call it as `extern "C" fn(u64, u64) -> u64`, check 2+3=5.
/// 3. Write a second block after the first is executing.
/// 4. Patch the first (change `add` to `sub` `0xcb010000`), flush icache.
/// 5. Call again and check the new result.
#[test]
fn test_exec_add_execute_patch_sub() {
    let mut mem = CodeMemory::new(4096).expect("allocate CodeMemory");

    // 1. Allocate block 1 with 16-byte alignment.
    let b1 = mem.alloc(8).expect("alloc block 1");
    assert_eq!(
        b1 % CODE_ALIGNMENT,
        0,
        "block 1 must be 16-byte aligned, got {b1}"
    );

    // Write `add x0, x0, x1; ret` into block 1.
    // Word 0: 0x8b010000 -> add x0, x0, x1
    // Word 1: 0xd65f03c0 -> ret
    mem.write(b1, 8, |bytes| {
        bytes[0..4].copy_from_slice(&0x8b01_0000u32.to_le_bytes());
        bytes[4..8].copy_from_slice(&0xd65f_03c0u32.to_le_bytes());
    })
    .expect("write block 1");

    // 2. Call it as `extern "C" fn(u64, u64) -> u64`, check 2 + 3 = 5.
    type BinOp = extern "C" fn(u64, u64) -> u64;
    // SAFETY: b1 contains valid machine code with ABI extern "C" fn(u64, u64) -> u64.
    let bin_fn: BinOp = mem.entry::<BinOp>(b1).get();
    let res = bin_fn(2, 3);
    assert_eq!(res, 5, "add(2, 3) must equal 5");

    // 3. Write a second block after the first is executing.
    let b2 = mem.alloc(8).expect("alloc block 2");
    assert_eq!(
        b2 % CODE_ALIGNMENT,
        0,
        "block 2 must be 16-byte aligned, got {b2}"
    );
    assert!(
        b2 >= b1 + CODE_ALIGNMENT,
        "block 2 must start after block 1 with alignment"
    );

    mem.write(b2, 8, |bytes| {
        bytes[0..4].copy_from_slice(&0x8b01_0000u32.to_le_bytes());
        bytes[4..8].copy_from_slice(&0xd65f_03c0u32.to_le_bytes());
    })
    .expect("write block 2");

    // SAFETY: b2 contains valid machine code with ABI extern "C" fn(u64, u64) -> u64.
    let fn2: BinOp = mem.entry::<BinOp>(b2).get();
    assert_eq!(fn2(10, 20), 30, "second block add(10, 20) must equal 30");

    // 4. Patch the first (change word 0 to `sub x0, x0, x1` = 0xcb010000), flush.
    mem.write(b1, 4, |bytes| {
        bytes[0..4].copy_from_slice(&0xcb01_0000u32.to_le_bytes());
    })
    .expect("patch block 1 to sub");

    mem.flush(b1, 4).expect("flush patched block 1");

    // 5. Call again and check the new result.
    let res_sub1 = bin_fn(10, 3);
    assert_eq!(res_sub1, 7, "patched sub(10, 3) must equal 7");

    let res_sub2 = bin_fn(2, 3);
    assert_eq!(
        res_sub2,
        2u64.wrapping_sub(3),
        "patched sub(2, 3) must equal 2 - 3 wrapping"
    );
}

#[test]
fn test_bump_allocation_alignment() {
    let mut mem = CodeMemory::new(4096).expect("allocate CodeMemory");

    // Request blocks of odd sizes; each should be padded to 16-byte alignment.
    let sizes = [1, 5, 12, 16, 17, 33, 64];
    let mut prev_offset = None;

    for &sz in &sizes {
        let offset = mem.alloc(sz).expect("alloc block");
        assert_eq!(
            offset % CODE_ALIGNMENT,
            0,
            "offset {offset} for size {sz} must be 16-byte aligned"
        );
        if let Some(prev) = prev_offset {
            assert!(
                offset > prev,
                "current offset {offset} must exceed previous {prev}"
            );
        }
        prev_offset = Some(offset);
    }

    assert_eq!(mem.blocks().len(), sizes.len());
}

#[test]
fn test_out_of_memory() {
    let mut mem = CodeMemory::new(4096).expect("allocate CodeMemory");
    let cap = mem.capacity();

    let b = mem.alloc(cap).expect("alloc full capacity");
    assert_eq!(b, 0);

    // Subsequent allocation must fail with OutOfMemory.
    match mem.alloc(1) {
        Err(ExecError::OutOfMemory {
            requested,
            available,
        }) => {
            assert_eq!(requested, 1);
            assert_eq!(available, 0);
        }
        other => panic!("expected OutOfMemory error, got {other:?}"),
    }
}

#[test]
fn test_out_of_bounds_write() {
    let mut mem = CodeMemory::new(4096).expect("allocate CodeMemory");
    let cap = mem.capacity();

    let err = mem.write(cap, 4, |_| ()).unwrap_err();
    match err {
        ExecError::OutOfBounds {
            offset,
            len,
            capacity,
        } => {
            assert_eq!(offset, cap);
            assert_eq!(len, 4);
            assert_eq!(capacity, cap);
        }
        other => panic!("expected OutOfBounds, got {other:?}"),
    }
}

#[test]
fn test_write_helpers() {
    let mut mem = CodeMemory::new(4096).expect("allocate CodeMemory");
    let b = mem.alloc(8).expect("alloc block");

    // Write via write_bytes helper
    let code: [u32; 2] = [0x8b01_0000, 0xd65f_03c0];
    let mut bytes = [0u8; 8];
    bytes[0..4].copy_from_slice(&code[0].to_le_bytes());
    bytes[4..8].copy_from_slice(&code[1].to_le_bytes());

    mem.write_bytes(b, &bytes).expect("write_bytes");

    type BinOp = extern "C" fn(u64, u64) -> u64;
    // SAFETY: b contains valid add function.
    let f: BinOp = mem.entry::<BinOp>(b).get();
    assert_eq!(f(50, 25), 75);

    // Write via write_block helper
    let sub_code: [u32; 2] = [0xcb01_0000, 0xd65f_03c0];
    mem.write_block(b, |dest| {
        dest[0..4].copy_from_slice(&sub_code[0].to_le_bytes());
        dest[4..8].copy_from_slice(&sub_code[1].to_le_bytes());
    })
    .expect("write_block");

    assert_eq!(f(50, 25), 25);
}

#[test]
fn test_multithreaded_execution() {
    use std::sync::Arc;
    use std::thread;

    let mut mem = CodeMemory::new(4096).expect("allocate CodeMemory");
    let b = mem.alloc(8).expect("alloc block");
    mem.write(b, 8, |bytes| {
        bytes[0..4].copy_from_slice(&0x8b01_0000u32.to_le_bytes());
        bytes[4..8].copy_from_slice(&0xd65f_03c0u32.to_le_bytes());
    })
    .expect("write block");

    type BinOp = extern "C" fn(u64, u64) -> u64;
    // SAFETY: b contains valid add function with 'static lifetime as long as mem lives.
    let bin_fn: BinOp = mem.entry::<BinOp>(b).get();

    let mem_arc = Arc::new(mem);
    let mut handles = Vec::new();

    for i in 0..8 {
        let _mem_ref = Arc::clone(&mem_arc);
        handles.push(thread::spawn(move || {
            for j in 0..1000 {
                let res = bin_fn(i, j);
                assert_eq!(res, i + j);
            }
        }));
    }

    for h in handles {
        h.join().expect("thread panicked");
    }
}
