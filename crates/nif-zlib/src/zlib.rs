//! Port of erts/emulator/nifs/common/zlib_nif.c, OTP-29.1.1.

use std::collections::{HashMap, VecDeque};
use std::ffi::c_void;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use arinsal_etf::OwnedTerm as O;
use libz_sys as z;

use crate::{
    Fault, Outcome, atom, bytes, int, number, owner_check, pair, reference, reference_id, tuple,
};

const MAGIC: u32 = 0x1_4942;
static NEXT_ID: AtomicU64 = AtomicU64::new(1);
static HANDLES: OnceLock<Mutex<HashMap<u64, Arc<Mutex<Handle>>>>> = OnceLock::new();
fn handles() -> &'static Mutex<HashMap<u64, Arc<Mutex<Handle>>>> {
    HANDLES.get_or_init(|| Mutex::new(HashMap::new()))
}

unsafe extern "C" fn alloc(_: *mut c_void, items: z::uInt, size: z::uInt) -> *mut c_void {
    // SAFETY: libc allocates a zeroed region for zlib's requested item count and size.
    unsafe { libc::calloc(items as usize, size as usize) }
}
unsafe extern "C" fn free(_: *mut c_void, ptr: *mut c_void) {
    // SAFETY: zlib passes only pointers returned by `alloc`.
    unsafe { libc::free(ptr) }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    None,
    Deflate,
    Inflate,
    Closed,
}

struct Handle {
    stream: Box<z::z_stream>,
    state: State,
    owner: Option<O>,
    queue: VecDeque<Vec<u8>>,
    stash: Option<O>,
    eos_behavior: i32,
    eos_seen: bool,
    raw: bool,
}

// SAFETY: all zlib stream access is serialized by the handle's Mutex. No zlib
// pointer is retained outside a call; the Box keeps `z_stream` at a fixed address.
unsafe impl Send for Handle {}

impl Handle {
    fn new(owner: Option<O>) -> Self {
        let stream = Box::new(z::z_stream {
            next_in: std::ptr::null_mut(),
            avail_in: 0,
            total_in: 0,
            next_out: std::ptr::null_mut(),
            avail_out: 0,
            total_out: 0,
            msg: std::ptr::null_mut(),
            state: std::ptr::null_mut(),
            zalloc: alloc,
            zfree: free,
            opaque: std::ptr::null_mut(),
            data_type: z::Z_BINARY,
            adler: 0,
            reserved: 0,
        });
        Self {
            stream,
            state: State::None,
            owner,
            queue: VecDeque::new(),
            stash: None,
            eos_behavior: 2,
            eos_seen: false,
            raw: false,
        }
    }
    fn clear(&mut self) {
        self.queue.clear();
        self.stash = None;
    }
    fn close(&mut self) {
        // SAFETY: stream state matches the zlib initializer previously called.
        unsafe {
            match self.state {
                State::Deflate => {
                    z::deflateEnd(&mut *self.stream);
                }
                State::Inflate => {
                    z::inflateEnd(&mut *self.stream);
                }
                _ => {}
            }
        }
        self.state = State::Closed;
        self.clear();
    }
    fn queued(&self) -> usize {
        self.queue.iter().map(Vec::len).sum()
    }
}
impl Drop for Handle {
    fn drop(&mut self) {
        if self.state != State::Closed {
            self.close();
        }
    }
}

fn fail(name: &str) -> Fault {
    Fault::Reason(atom(name))
}
fn status(code: i32) -> Outcome {
    // Port of erts/emulator/nifs/common/zlib_nif.c:246 (zlib_return), OTP-29.1.1.
    match code {
        z::Z_OK => Ok(atom("ok")),
        z::Z_STREAM_END => Ok(atom("stream_end")),
        z::Z_ERRNO => Ok(O::Int(
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as i64,
        )),
        z::Z_STREAM_ERROR => Err(fail("stream_error")),
        z::Z_DATA_ERROR => Err(fail("data_error")),
        z::Z_MEM_ERROR => Ok(atom("mem_error")),
        z::Z_BUF_ERROR => Ok(atom("buf_error")),
        z::Z_VERSION_ERROR => Ok(atom("version_error")),
        _ => Ok(atom("unknown_error")),
    }
}
fn handle(value: &O) -> Result<Arc<Mutex<Handle>>, Fault> {
    let id = reference_id(value, MAGIC)?;
    let h = handles()
        .lock()
        .unwrap()
        .get(&id)
        .cloned()
        .ok_or(Fault::Badarg)?;
    Ok(h)
}
fn expect(h: &Handle, state: State) -> Result<(), Fault> {
    if h.state == state {
        Ok(())
    } else {
        Err(fail("not_initialized"))
    }
}
fn dictionary(arg: &O) -> Result<Vec<u8>, Fault> {
    bytes(arg)
}

fn codec(
    h: &mut Handle,
    input_limit: i32,
    output_limit: i32,
    flush: i32,
    inflate: bool,
) -> Outcome {
    // Port of erts/emulator/nifs/common/zlib_nif.c:408 (zlib_codec), OTP-29.1.1.
    if output_limit < 0 {
        return Ok(atom("mem_error"));
    }
    let input_limit = input_limit as isize as usize;
    let out_len = output_limit as usize;
    let mut output = Vec::new();
    if output.try_reserve_exact(out_len).is_err() {
        return Ok(atom("mem_error"));
    }
    output.resize(out_len, 0);
    h.stream.next_out = output.as_mut_ptr();
    h.stream.avail_out = output_limit as u32;
    let mut code = z::Z_OK;
    let mut consumed = 0usize;
    while code == z::Z_OK && consumed < input_limit && !h.queue.is_empty() {
        let front = h.queue.front().unwrap();
        let block = front.len().min(input_limit - consumed);
        h.stream.next_in = front.as_ptr() as *mut u8;
        h.stream.avail_in = block as u32;
        // SAFETY: zlib reads from the queued block and writes within `output`.
        code = unsafe {
            if inflate {
                z::inflate(&mut *h.stream, z::Z_NO_FLUSH)
            } else {
                z::deflate(&mut *h.stream, z::Z_NO_FLUSH)
            }
        };
        let used = block - h.stream.avail_in as usize;
        consumed += used;
        if used == front.len() {
            h.queue.pop_front();
        } else if used > 0 {
            h.queue.front_mut().unwrap().drain(..used);
        }
        if used == 0 || h.stream.avail_out == 0 {
            break;
        }
    }
    if code == z::Z_OK && h.queue.is_empty() && h.stream.avail_out > 0 {
        h.stream.next_in = std::ptr::null_mut();
        h.stream.avail_in = 0;
        // SAFETY: the output buffer still has `avail_out` bytes and no input is read.
        code = unsafe {
            if inflate {
                z::inflate(&mut *h.stream, flush)
            } else {
                z::deflate(&mut *h.stream, flush)
            }
        };
    }
    let produced = out_len - h.stream.avail_out as usize;
    let adler = h.stream.adler;
    h.stream.next_in = std::ptr::null_mut();
    h.stream.avail_in = 0;
    h.stream.next_out = std::ptr::null_mut();
    h.stream.avail_out = 0;
    if code < 0 && code != z::Z_BUF_ERROR {
        return status(code);
    }
    if code == z::Z_STREAM_END {
        h.eos_seen = true;
    }
    if consumed == 0 && produced == 0 && !h.queue.is_empty() {
        return Err(fail("data_error"));
    }
    output.truncate(produced);
    let chunks = if output.is_empty() {
        O::Nil
    } else {
        O::list(vec![O::Binary(output)])
    };
    if h.queue.is_empty() && produced < out_len {
        Ok(pair(atom("finished"), chunks))
    } else if code == z::Z_NEED_DICT {
        Ok(tuple(vec![atom("need_dictionary"), int(adler), chunks]))
    } else {
        Ok(pair(atom("continue"), chunks))
    }
}

// `inflateGetDictionary` is present in the system zlib used by OTP on macOS,
// but libz-sys omits it from its portable binding.
unsafe extern "C" {
    fn inflateGetDictionary(
        stream: *mut z::z_stream,
        dictionary: *mut u8,
        length: *mut z::uInt,
    ) -> i32;
}

pub(super) fn dispatch(name: &str, args: &[O], caller: &Option<O>) -> Outcome {
    if name == "open_nif" {
        if !args.is_empty() {
            return Err(Fault::Badarg);
        }
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        handles()
            .lock()
            .unwrap()
            .insert(id, Arc::new(Mutex::new(Handle::new(caller.clone()))));
        return Ok(reference(MAGIC, id));
    }
    let Some(first) = args.first() else {
        return Err(Fault::Badarg);
    };
    let h = handle(first)?;
    let mut h = h.lock().unwrap();
    owner_check(&h.owner, caller)?;
    match (name, args) {
        ("close_nif", [_]) => {
            if h.state == State::Closed {
                Err(fail("not_initialized"))
            } else {
                h.close();
                Ok(atom("ok"))
            }
        }
        ("set_controller_nif", [_, O::Pid { .. }]) => {
            h.owner = Some(args[1].clone());
            Ok(atom("ok"))
        }
        ("deflateInit_nif", [_, level, method, window, mem, strategy]) => {
            if h.state != State::None {
                return Err(fail("already_initialized"));
            }
            let (level, method, window, mem, strategy) = (
                number(level)?,
                number(method)?,
                number(window)?,
                number(mem)?,
                number(strategy)?,
            );
            // SAFETY: the boxed C stream is stable and initialized with zlib allocators.
            let code = unsafe {
                z::deflateInit2_(
                    &mut *h.stream,
                    level,
                    method,
                    window,
                    mem,
                    strategy,
                    z::zlibVersion(),
                    std::mem::size_of::<z::z_stream>() as i32,
                )
            };
            if code == z::Z_OK {
                h.state = State::Deflate;
                h.raw = window < 0;
                h.eos_seen = false;
            }
            status(code)
        }
        ("inflateInit_nif", [_, window, eos]) => {
            if h.state != State::None {
                return Err(fail("already_initialized"));
            }
            let (window, eos) = (number(window)?, number(eos)?);
            // SAFETY: the boxed C stream is stable and initialized with zlib allocators.
            let code = unsafe {
                z::inflateInit2_(
                    &mut *h.stream,
                    window,
                    z::zlibVersion(),
                    std::mem::size_of::<z::z_stream>() as i32,
                )
            };
            if code == z::Z_OK {
                h.state = State::Inflate;
                h.eos_behavior = eos;
                h.raw = window < 0;
                h.eos_seen = false;
            }
            status(code)
        }
        ("deflateSetDictionary_nif", [_, data]) => {
            expect(&h, State::Deflate)?;
            let b = dictionary(data)?;
            // SAFETY: zlib reads only the supplied dictionary bytes.
            let code =
                unsafe { z::deflateSetDictionary(&mut *h.stream, b.as_ptr(), b.len() as u32) };
            if code == z::Z_OK {
                if h.raw {
                    // SAFETY: zlib reads only the supplied dictionary bytes.
                    Ok(int(
                        unsafe { z::adler32(0, b.as_ptr(), b.len() as u32) } as u64
                    ))
                } else {
                    Ok(int(h.stream.adler))
                }
            } else {
                status(code)
            }
        }
        ("inflateSetDictionary_nif", [_, data]) => {
            expect(&h, State::Inflate)?;
            let b = dictionary(data)?;
            // SAFETY: zlib reads only the supplied dictionary bytes.
            status(unsafe { z::inflateSetDictionary(&mut *h.stream, b.as_ptr(), b.len() as u32) })
        }
        ("inflateGetDictionary_nif", [_]) => {
            expect(&h, State::Inflate)?;
            let mut b = vec![0u8; 32768];
            let mut len: u32 = 0;
            // SAFETY: the buffer has 32768 bytes, the largest zlib window.
            let code = unsafe { inflateGetDictionary(&mut *h.stream, b.as_mut_ptr(), &mut len) };
            if code != z::Z_OK {
                status(code)
            } else {
                b.truncate(len as usize);
                Ok(O::Binary(b))
            }
        }
        ("deflateReset_nif", [_]) => {
            expect(&h, State::Deflate)?;
            h.clear();
            h.eos_seen = false; /* SAFETY: initialized deflate stream. */
            status(unsafe { z::deflateReset(&mut *h.stream) })
        }
        ("inflateReset_nif", [_]) => {
            expect(&h, State::Inflate)?;
            h.clear();
            h.eos_seen = false; /* SAFETY: initialized inflate stream. */
            status(unsafe { z::inflateReset(&mut *h.stream) })
        }
        ("deflateEnd_nif", [_]) => {
            expect(&h, State::Deflate)?;
            let pending = h.queued();
            // SAFETY: initialized deflate stream.
            let mut code = unsafe { z::deflateEnd(&mut *h.stream) };
            if code == z::Z_OK && pending > 0 {
                code = z::Z_DATA_ERROR;
            }
            h.clear();
            h.state = State::None;
            status(code)
        }
        ("inflateEnd_nif", [_]) => {
            expect(&h, State::Inflate)?;
            let pending = h.queued();
            let eos = h.eos_seen;
            // SAFETY: initialized inflate stream.
            let mut code = unsafe { z::inflateEnd(&mut *h.stream) };
            if code == z::Z_OK && (!eos || pending > 0) {
                code = z::Z_DATA_ERROR;
            }
            h.clear();
            h.state = State::None;
            status(code)
        }
        ("deflateParams_nif", [_, level, strategy]) => {
            expect(&h, State::Deflate)?;
            let (level, strategy) = (number(level)?, number(strategy)?);
            let mut dummy = 0u8;
            h.stream.next_out = &mut dummy;
            h.stream.avail_out = 1;
            // SAFETY: zlib writes at most the one dummy output byte.
            let code = unsafe { z::deflateParams(&mut *h.stream, level, strategy) };
            let exhausted = h.stream.avail_out == 0;
            h.stream.next_out = std::ptr::null_mut();
            h.stream.avail_out = 0;
            if exhausted {
                Err(fail("stream_error"))
            } else {
                status(code)
            }
        }
        ("deflate_nif", [_, input, output, flush]) => {
            expect(&h, State::Deflate)?;
            codec(
                &mut h,
                number(input)?,
                number(output)?,
                number(flush)?,
                false,
            )
        }
        ("inflate_nif", [_, input, output, flush]) => {
            expect(&h, State::Inflate)?;
            if h.eos_seen && h.queued() > 0 {
                match h.eos_behavior {
                    0 => return Err(fail("data_error")),
                    1 => {
                        /* SAFETY: initialized inflate stream. */
                        status(unsafe { z::inflateReset(&mut *h.stream) })?;
                        h.eos_seen = false;
                    }
                    2 => h.clear(),
                    _ => return Err(Fault::Badarg),
                }
            }
            codec(
                &mut h,
                number(input)?,
                number(output)?,
                number(flush)?,
                true,
            )
        }
        ("enqueue_nif", [_, input]) => {
            if !matches!(h.state, State::Deflate | State::Inflate) {
                return Err(fail("not_initialized"));
            }
            let binary;
            let elements = match input {
                O::Nil => &[][..],
                O::Binary(_) => {
                    binary = [input.clone()];
                    &binary[..]
                }
                O::List { elems, tail } if **tail == O::Nil => elems.as_slice(),
                _ => return Err(Fault::Badarg),
            };
            let mut taken = 0;
            for element in elements.iter().take(256) {
                let b = bytes(element)?;
                if !b.is_empty() {
                    h.queue.push_back(b);
                }
                taken += 1;
            }
            if taken < elements.len() {
                Ok(pair(atom("continue"), O::list(elements[taken..].to_vec())))
            } else {
                Ok(atom("ok"))
            }
        }
        ("getStash_nif", [_]) => Ok(h
            .stash
            .clone()
            .map(|v| pair(atom("ok"), v))
            .unwrap_or_else(|| atom("empty"))),
        ("setStash_nif", [_, value]) => {
            if h.stash.is_some() {
                Err(fail("error"))
            } else {
                h.stash = Some(value.clone());
                Ok(atom("ok"))
            }
        }
        ("clearStash_nif", [_]) => {
            if h.stash.take().is_some() {
                Ok(atom("ok"))
            } else {
                Err(fail("error"))
            }
        }
        _ => Err(Fault::Badarg),
    }
}
