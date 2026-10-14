//! OTP 29.1.1 `prim_buffer` NIF operations.
//!
//! Handles are local refs `[0x42554646, low32(id), high32(id)]`. The table
//! keeps buffers alive for the VM lifetime; stage 4 must connect resource
//! destruction to handle removal.

#![forbid(unsafe_code)]

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use arinsal_bifs::{BifError, BifFn, Ctx};
use arinsal_etf::OwnedTerm as O;
use arinsal_term::{
    ExportEntry, FunEntry, HeapAlloc, Node, Term, from_owned, global_atoms, to_owned,
};
use num_traits::ToPrimitive;

const MAGIC: u32 = 0x4255_4646;
static NEXT_ID: AtomicU64 = AtomicU64::new(1);
static HANDLES: OnceLock<Mutex<HashMap<u64, Arc<BufferHandle>>>> = OnceLock::new();

struct BufferHandle {
    state: Mutex<BufferState>,
    locked: AtomicBool,
}

#[derive(Default)]
struct BufferState {
    chunks: VecDeque<Vec<u8>>,
    accumulator: Vec<u8>,
    front_offset: usize,
    size: u64,
}

fn handles() -> &'static Mutex<HashMap<u64, Arc<BufferHandle>>> {
    HANDLES.get_or_init(|| Mutex::new(HashMap::new()))
}

struct Heap<'a, H: HeapAlloc + ?Sized>(&'a mut H);
impl<H: HeapAlloc + ?Sized> HeapAlloc for Heap<'_, H> {
    fn alloc(&mut self, words: usize) -> Option<*mut u64> {
        self.0.alloc(words)
    }
    fn retain_binary(&mut self, value: Arc<arinsal_term::RefcBinary>) {
        self.0.retain_binary(value)
    }
    fn link_bin_ref(
        &mut self,
        bin_ref: *mut u64,
        writable: bool,
        overhead_words: u64,
        owner: Option<arinsal_term::OwnedBinaryRef>,
    ) -> Result<(), arinsal_term::TermError> {
        HeapAlloc::link_bin_ref(self.0, bin_ref, writable, overhead_words, owner)
    }
    fn retain_writable_binary(
        &mut self,
        value: Arc<arinsal_term::WritableBinary>,
    ) -> Result<(), arinsal_term::TermError> {
        self.0.retain_writable_binary(value)
    }
    fn supports_writable_binary(&self) -> bool {
        self.0.supports_writable_binary()
    }
    fn retain_node(&mut self, value: Arc<Node>) {
        self.0.retain_node(value)
    }
    fn retain_fun(&mut self, value: Arc<FunEntry>) {
        self.0.retain_fun(value)
    }
    fn retain_export(&mut self, value: Arc<ExportEntry>) {
        self.0.retain_export(value)
    }
}

/// Return the native implementation for a `prim_buffer` NIF entry.
pub fn lookup(module: &str, name: &str, arity: u8) -> Option<BifFn> {
    if module != "prim_buffer" {
        return None;
    }
    let f: BifFn = match (name, arity) {
        ("new", 0) => new,
        ("size", 1) => size,
        ("peek_head", 1) => peek_head,
        ("copying_read", 2) => copying_read,
        ("write", 2) => write,
        ("skip", 2) => skip,
        ("find_byte_index", 2) => find_byte_index,
        ("try_lock", 1) => try_lock,
        ("unlock", 1) => unlock,
        _ => return None,
    };
    Some(f)
}

type Outcome = Result<O, BifError>;
fn call(
    ctx: &mut Ctx<'_>,
    args: &[Term],
    op: impl FnOnce(&[O]) -> Outcome,
) -> Result<Term, BifError> {
    let args = args
        .iter()
        .map(|arg| to_owned(*arg).map_err(|_| BifError::BADARG))
        .collect::<Result<Vec<_>, _>>()?;
    let value = op(&args)?;
    from_owned(&value, &mut Heap(&mut ctx.heap)).map_err(|_| BifError::SystemLimit)
}

fn atom(name: &str) -> O {
    O::atom(name)
}

fn handle_id(value: &O) -> Result<u64, BifError> {
    match value {
        O::Ref {
            node,
            creation,
            ids,
        } if node == "nonode@nohost" && *creation == 0 && ids.len() == 3 && ids[0] == MAGIC => {
            Ok(u64::from(ids[1]) | (u64::from(ids[2]) << 32))
        }
        _ => Err(BifError::BADARG),
    }
}

fn handle(value: &O) -> Result<Arc<BufferHandle>, BifError> {
    let id = handle_id(value)?;
    handles()
        .lock()
        .unwrap()
        .get(&id)
        .cloned()
        .ok_or(BifError::BADARG)
}

fn reference(id: u64) -> O {
    O::Ref {
        node: "nonode@nohost".into(),
        creation: 0,
        ids: vec![MAGIC, id as u32, (id >> 32) as u32],
    }
}

fn new(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    call(ctx, args, |args| {
        if !args.is_empty() {
            return Err(BifError::BADARG);
        }
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        handles().lock().unwrap().insert(
            id,
            Arc::new(BufferHandle {
                state: Mutex::new(BufferState::default()),
                locked: AtomicBool::new(false),
            }),
        );
        Ok(reference(id))
    })
}

fn size(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    call(ctx, args, |args| {
        let [buffer] = args else {
            return Err(BifError::BADARG);
        };
        let buffer = handle(buffer)?;
        let state = buffer.state.lock().unwrap();
        Ok(integer(state.size))
    })
}

fn peek_head(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    call(ctx, args, |args| {
        let [buffer] = args else {
            return Err(BifError::BADARG);
        };
        let buffer = handle(buffer)?;
        let mut state = buffer.state.lock().unwrap();
        flush_accumulator(&mut state);
        let chunk = state.chunks.front().ok_or(BifError::BADARG)?;
        Ok(O::Binary(chunk[state.front_offset..].to_vec()))
    })
}

fn copying_read(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    call(ctx, args, |args| {
        let [buffer, count] = args else {
            return Err(BifError::BADARG);
        };
        let count = unsigned(count).ok_or(BifError::BADARG)?;
        let buffer = handle(buffer)?;
        let mut state = buffer.state.lock().unwrap();
        flush_accumulator(&mut state);
        if count > state.size {
            return Err(BifError::BADARG);
        }
        let bytes = consume(&mut state, count, true);
        Ok(O::Binary(bytes))
    })
}

fn write(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    call(ctx, args, |args| {
        let [buffer, iovec] = args else {
            return Err(BifError::BADARG);
        };
        let buffer = handle(buffer)?;
        let chunks = iovec_chunks(iovec)?;
        let mut state = buffer.state.lock().unwrap();
        let write_size = chunks.iter().map(Vec::len).sum::<usize>();
        if state.accumulator.len() + write_size >= 2048 && write_size >= 1024 {
            flush_accumulator(&mut state);
        } else if state.accumulator.len() + write_size >= 2048 {
            flush_accumulator(&mut state);
            for chunk in chunks {
                state.accumulator.extend_from_slice(&chunk);
            }
            state.size = state
                .size
                .checked_add(write_size as u64)
                .ok_or(BifError::SystemLimit)?;
            return Ok(atom("ok"));
        } else {
            for chunk in chunks {
                state.accumulator.extend_from_slice(&chunk);
            }
            state.size = state
                .size
                .checked_add(write_size as u64)
                .ok_or(BifError::SystemLimit)?;
            return Ok(atom("ok"));
        }
        for chunk in chunks {
            if !chunk.is_empty() {
                state.size = state
                    .size
                    .checked_add(chunk.len() as u64)
                    .ok_or(BifError::SystemLimit)?;
                state.chunks.push_back(chunk);
            }
        }
        Ok(atom("ok"))
    })
}

fn skip(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    call(ctx, args, |args| {
        let [buffer, count] = args else {
            return Err(BifError::BADARG);
        };
        let count = unsigned(count).ok_or(BifError::BADARG)?;
        let buffer = handle(buffer)?;
        let mut state = buffer.state.lock().unwrap();
        flush_accumulator(&mut state);
        if count > state.size {
            return Err(BifError::BADARG);
        }
        consume(&mut state, count, false);
        Ok(atom("ok"))
    })
}

fn find_byte_index(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    call(ctx, args, |args| {
        let [buffer, needle] = args else {
            return Err(BifError::BADARG);
        };
        let O::Int(needle) = needle else {
            return Err(BifError::BADARG);
        };
        let needle: u8 = (*needle).try_into().map_err(|_| BifError::BADARG)?;
        let buffer = handle(buffer)?;
        let mut state = buffer.state.lock().unwrap();
        flush_accumulator(&mut state);
        let mut offset = 0u64;
        for (index, chunk) in state.chunks.iter().enumerate() {
            let bytes = if index == 0 {
                &chunk[state.front_offset..]
            } else {
                chunk
            };
            if let Some(found) = bytes.iter().position(|byte| *byte == needle) {
                let result = offset + found as u64;
                return Ok(O::Tuple(vec![atom("ok"), integer(result)]));
            }
            offset += bytes.len() as u64;
        }
        Ok(atom("not_found"))
    })
}

fn try_lock(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    call(ctx, args, |args| {
        let [buffer] = args else {
            return Err(BifError::BADARG);
        };
        let buffer = handle(buffer)?;
        Ok(atom(
            if buffer
                .locked
                .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                "acquired"
            } else {
                "busy"
            },
        ))
    })
}

fn unlock(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    call(ctx, args, |args| {
        let [buffer] = args else {
            return Err(BifError::BADARG);
        };
        let buffer = handle(buffer)?;
        if buffer
            .locked
            .compare_exchange(true, false, Ordering::Release, Ordering::Relaxed)
            .is_err()
        {
            let reason = Term::atom(
                global_atoms()
                    .intern("lock_order_violation")
                    .expect("short atom"),
            );
            return Err(BifError::Error(reason));
        }
        Ok(atom("ok"))
    })
}

fn iovec_chunks(value: &O) -> Result<Vec<Vec<u8>>, BifError> {
    let elems = match value {
        O::Nil => return Ok(Vec::new()),
        O::List { elems, tail } if **tail == O::Nil => elems,
        O::Binary(bytes) => return Ok(vec![bytes.clone()]),
        _ => return Err(BifError::BADARG),
    };
    elems
        .iter()
        .map(|elem| match elem {
            O::Binary(bytes) => Ok(bytes.clone()),
            _ => Err(BifError::BADARG),
        })
        .collect()
}

fn unsigned(value: &O) -> Option<u64> {
    match value {
        O::Int(n) => (*n).try_into().ok(),
        O::BigInt(n) => n.to_u64(),
        _ => None,
    }
}

fn integer(value: u64) -> O {
    i64::try_from(value)
        .map(O::Int)
        .unwrap_or_else(|_| O::BigInt(value.into()))
}

fn consume(state: &mut BufferState, count: u64, copy: bool) -> Vec<u8> {
    let mut remaining = count as usize;
    let mut output = if copy {
        Vec::with_capacity(remaining)
    } else {
        Vec::new()
    };
    while remaining > 0 {
        let chunk = state.chunks.front().expect("size invariant");
        let available = chunk.len() - state.front_offset;
        let take = remaining.min(available);
        if copy {
            output.extend_from_slice(&chunk[state.front_offset..state.front_offset + take]);
        }
        remaining -= take;
        state.size -= take as u64;
        state.front_offset += take;
        if state.front_offset == chunk.len() {
            state.chunks.pop_front();
            state.front_offset = 0;
        }
    }
    output
}

fn flush_accumulator(state: &mut BufferState) {
    if !state.accumulator.is_empty() {
        state
            .chunks
            .push_back(std::mem::take(&mut state.accumulator));
    }
}
