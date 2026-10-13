//! `write_nif`/`pwrite_nif` write large refc and resource-backed binaries from the iovec
//! erts' `enif_inspect_iovec` builds, and partial writes continue from the unwritten
//! remainder. The unit tests in `src/iovec.rs` check that the iovec points at the binaries'
//! own bytes.

use std::io::Read;
use std::os::fd::{IntoRawFd, OwnedFd};
use std::sync::Arc;
use std::time::Instant;

use arinsal_bifs::{BifError, Ctx, ProcessHeapHandle};
use arinsal_etf::OwnedTerm as O;
use arinsal_term::{
    ExternalBinary, MagicRef, ProcessHeap, Term, TermBuilder, from_owned, to_owned,
};

const MIB: usize = 1024 * 1024;

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

fn atom(name: &str) -> O {
    O::atom(name)
}

fn nif(name: &str, arity: u8) -> arinsal_bifs::BifFn {
    arinsal_nif_file::lookup("prim_file", name, arity).unwrap()
}

fn call_owned(heap: &mut ProcessHeap, name: &str, args: &[O]) -> Result<O, BifError> {
    let mut alloc = ProcessHeapHandle(heap);
    let terms = args
        .iter()
        .map(|a| from_owned(a, &mut alloc).unwrap())
        .collect::<Vec<_>>();
    let mut ctx = Ctx::new(&mut alloc);
    nif(name, args.len() as u8)(&mut ctx, &terms).map(|value| to_owned(value).unwrap())
}

/// Call `name` with live terms.
fn call_terms(heap: &mut ProcessHeap, name: &str, args: &[Term]) -> O {
    let mut alloc = ProcessHeapHandle(heap);
    let mut ctx = Ctx::new(&mut alloc);
    let result = nif(name, args.len() as u8)(&mut ctx, args).unwrap();
    to_owned(result).unwrap()
}

fn open(heap: &mut ProcessHeap, path: &std::path::Path) -> O {
    let mut bytes = path.as_os_str().as_encoded_bytes().to_vec();
    bytes.push(0);
    let opened = call_owned(
        heap,
        "open_nif",
        &[O::Binary(bytes), O::list(vec![atom("read"), atom("write")])],
    )
    .unwrap();
    let O::Tuple(ref parts) = opened else {
        panic!("open: {opened:?}")
    };
    assert_eq!(parts[0], atom("ok"));
    parts[1].clone()
}

fn close(heap: &mut ProcessHeap, handle: &O) {
    assert_eq!(
        call_owned(heap, "close_nif", std::slice::from_ref(handle)).unwrap(),
        atom("ok")
    );
}

#[test]
fn write_of_256_mib_refc_binary() {
    let root = tempfile::tempdir().unwrap();
    let file = root.path().join("big");
    let mut heap = ProcessHeap::with_words(4096);
    let handle = open(&mut heap, &file);
    let data = pattern(256 * MIB);
    let (handle_term, list, offset) = {
        let mut alloc = ProcessHeapHandle(&mut heap);
        let handle_term = from_owned(&handle, &mut alloc).unwrap();
        let binary = TermBuilder::new(&mut alloc).binary(&data).unwrap();
        let list = TermBuilder::new(&mut alloc)
            .cons(binary, Term::NIL)
            .unwrap();
        let offset = Term::small(0).unwrap();
        (handle_term, list, offset)
    };
    let started = Instant::now();
    let result = call_terms(&mut heap, "write_nif", &[handle_term, list]);
    let write = started.elapsed();
    assert_eq!(result, atom("ok"));
    let result = call_terms(&mut heap, "pwrite_nif", &[handle_term, offset, list]);
    assert_eq!(result, atom("ok"));
    let started = Instant::now();
    let copy = data.clone();
    let memcpy = started.elapsed();
    eprintln!("256 MiB: write_nif {write:?}, one memcpy {memcpy:?}");
    drop(copy);
    close(&mut heap, &handle);
    assert!(std::fs::read(&file).unwrap() == data);
}

#[test]
fn write_of_resource_binary_references_its_bytes() {
    let root = tempfile::tempdir().unwrap();
    let file = root.path().join("resource");
    let mut heap = ProcessHeap::with_words(4096);
    let handle = open(&mut heap, &file);
    let bytes: Arc<Vec<u8>> = Arc::new(pattern(64 * MIB + 3));
    let owner = MagicRef::new(Arc::clone(&bytes));
    // SAFETY: `owner` keeps the `bytes` allocation alive and unmodified.
    let external = unsafe { ExternalBinary::new(bytes.as_ptr(), bytes.len(), owner) };
    let (handle_term, list) = {
        let mut alloc = ProcessHeapHandle(&mut heap);
        let handle_term = from_owned(&handle, &mut alloc).unwrap();
        let binary = TermBuilder::new(&mut alloc)
            .external_binary(external)
            .unwrap();
        let small = TermBuilder::new(&mut alloc).binary(b"tail").unwrap();
        let mut builder = TermBuilder::new(&mut alloc);
        let rest = builder.cons(small, Term::NIL).unwrap();
        (handle_term, builder.cons(binary, rest).unwrap())
    };
    let result = call_terms(&mut heap, "write_nif", &[handle_term, list]);
    assert_eq!(result, atom("ok"));
    close(&mut heap, &handle);
    let written = std::fs::read(&file).unwrap();
    assert_eq!(written.len(), bytes.len() + 4);
    assert!(written[..bytes.len()] == bytes[..]);
    assert_eq!(&written[bytes.len()..], b"tail");
}

#[test]
fn partial_writes_continue_with_the_unwritten_remainder() {
    // A pipe takes at most its buffer per writev, so efile_writev loops and shifts the
    // iovec across segment boundaries (unix_prim_file.c:270-290 and 343-391).
    let (mut reader, writer) = std::io::pipe().unwrap();
    // The handle owns the write end from here.
    let write_fd = OwnedFd::from(writer).into_raw_fd();
    let segments: Vec<Vec<u8>> = (0..5)
        .map(|n| {
            pattern(MIB + 4099 * n)
                .into_iter()
                .map(|b| b ^ n as u8)
                .collect()
        })
        .collect();
    let expected = segments.concat();
    let total = expected.len();
    let drain = std::thread::spawn(move || {
        let mut got = Vec::new();
        reader.read_to_end(&mut got).unwrap();
        got
    });
    let mut heap = ProcessHeap::with_words(4096);
    let opened = call_owned(
        &mut heap,
        "file_desc_to_ref_nif",
        &[O::Int(i64::from(write_fd))],
    )
    .unwrap();
    let O::Tuple(ref parts) = opened else {
        panic!("file_desc_to_ref: {opened:?}")
    };
    let handle = parts[1].clone();
    let (handle_term, list) = {
        let mut alloc = ProcessHeapHandle(&mut heap);
        let handle_term = from_owned(&handle, &mut alloc).unwrap();
        let binaries = segments
            .iter()
            .map(|segment| TermBuilder::new(&mut alloc).binary(segment).unwrap())
            .collect::<Vec<_>>();
        let mut list = Term::NIL;
        for binary in binaries.into_iter().rev() {
            list = TermBuilder::new(&mut alloc).cons(binary, list).unwrap();
        }
        (handle_term, list)
    };
    let result = call_terms(&mut heap, "write_nif", &[handle_term, list]);
    assert_eq!(result, atom("ok"));
    // pwrite on a pipe fails like erts: {error, espipe}.
    let offset = {
        let mut alloc = ProcessHeapHandle(&mut heap);
        from_owned(&O::Int(0), &mut alloc).unwrap()
    };
    let result = call_terms(&mut heap, "pwrite_nif", &[handle_term, offset, list]);
    assert_eq!(result, O::Tuple(vec![atom("error"), atom("espipe")]));
    close(&mut heap, &handle);
    let got = drain.join().unwrap();
    assert_eq!(got.len(), total);
    assert!(got == expected);
}
