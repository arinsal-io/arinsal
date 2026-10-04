//! Symbolic stack traces from BEAM continuations.

use crate::{Process, VmError};
use arinsal_bifs::{Class, FragmentingHeap};
use arinsal_etf::OwnedTerm;
use arinsal_loader::Module;
use arinsal_term::{
    Atom, HeapAlloc, ProcessHeap, Term, TermBuilder, TermKind, from_owned, global_atoms, to_owned,
};
use arinsal_term::{ExportEntry, ExternalBinary, FunEntry, MagicRef, Node, WritableBinary};
use std::sync::{Arc, Mutex, OnceLock};

// Reserve the last encodable handler module index for the empty-trace markers.
const RAW_TRACE_PREFIX: u64 = (1 << 26) - 1;
const CONTINUATION_BIT: u64 = 1 << 57;

fn interpreted_catch_ids() -> &'static Mutex<std::collections::HashMap<(usize, usize), u32>> {
    static IDS: OnceLock<Mutex<std::collections::HashMap<(usize, usize), u32>>> = OnceLock::new();
    IDS.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}

/// Allocator for stack trace terms.
///
/// Port of erts/emulator/beam/beam_common.c:1205 (build_stacktrace), OTP-29.1.1: the
/// whole trace is sized first and allocated as one block (`HAlloc`, falling back to a
/// single heap fragment), instead of one heap fragment per term.
struct TraceHeap<'a> {
    heap: &'a mut ProcessHeap,
    block: *mut u64,
    capacity: usize,
    used: usize,
    /// Heap top right after the block when it was taken from the young heap.
    block_end: Option<usize>,
}

impl<'a> TraceHeap<'a> {
    fn new(heap: &'a mut ProcessHeap) -> Self {
        Self {
            heap,
            block: std::ptr::null_mut(),
            capacity: 0,
            used: 0,
            block_end: None,
        }
    }

    /// Reserves one block that later allocations are carved from.
    fn with_block(heap: &'a mut ProcessHeap, words: usize) -> Self {
        let mut trace = Self::new(heap);
        trace.capacity = words;
        if let Some(block) = HeapAlloc::alloc(trace.heap, words) {
            trace.block = block;
            // A detached heap hands out blocks outside the young heap; there is no top to trim.
            trace.block_end = (!trace.heap.is_detached()).then(|| trace.heap.used_words());
        } else {
            trace.block = trace.heap.gc_fragment(words);
        }
        trace
    }
}

impl Drop for TraceHeap<'_> {
    fn drop(&mut self) {
        // Give the unused tail of the block back when nothing was allocated after it.
        if let Some(end) = self.block_end
            && self.heap.used_words() == end
        {
            self.heap.set_heap_top(self.block.wrapping_add(self.used));
        }
    }
}

impl HeapAlloc for TraceHeap<'_> {
    fn alloc(&mut self, words: usize) -> Option<*mut u64> {
        if words <= self.capacity - self.used {
            let ptr = self.block.wrapping_add(self.used);
            self.used += words;
            return Some(ptr);
        }
        HeapAlloc::alloc(self.heap, words).or_else(|| Some(self.heap.gc_fragment(words)))
    }

    fn retain_binary(&mut self, binary: Arc<Vec<u8>>) {
        HeapAlloc::retain_binary(self.heap, binary);
    }

    fn retain_writable_binary(
        &mut self,
        binary: Arc<WritableBinary>,
    ) -> Result<(), arinsal_term::TermError> {
        HeapAlloc::retain_writable_binary(self.heap, binary)
    }

    fn supports_writable_binary(&self) -> bool {
        true
    }

    fn retain_external_binary(
        &mut self,
        binary: Arc<ExternalBinary>,
    ) -> Result<(), arinsal_term::TermError> {
        HeapAlloc::retain_external_binary(self.heap, binary)
    }

    fn supports_external_binary(&self) -> bool {
        true
    }

    fn retain_node(&mut self, node: Arc<Node>) {
        HeapAlloc::retain_node(self.heap, node);
    }

    fn retain_fun(&mut self, entry: Arc<FunEntry>) {
        HeapAlloc::retain_fun(self.heap, entry);
    }

    fn retain_export(&mut self, entry: Arc<ExportEntry>) {
        HeapAlloc::retain_export(self.heap, entry);
    }

    fn retain_magic(&mut self, owner: Arc<MagicRef>) {
        HeapAlloc::retain_magic(self.heap, owner);
    }

    fn supports_magic(&self) -> bool {
        true
    }
}

/// Continuation addresses saved before exception unwinding.
#[derive(Default)]
pub(super) struct RawTrace {
    class: Option<Class>,
    explicit: Option<OwnedTerm>,
    top: Option<StoredTopFrame>,
    module: Option<Arc<Module>>,
    ip: usize,
    /// Native function and pc that raised the exception, when it came from native code.
    native_top: Option<usize>,
    continuations: Vec<Continuation>,
    frames: Vec<Term>,
    depth: usize,
}

enum Continuation {
    Interpreted(Arc<Module>, usize),
    Native(usize),
}

#[derive(Clone, Debug)]
pub(super) enum BifArgs {
    Inline {
        values: [Term; 4],
        len: u8,
    },
    /// Shared so a rebuilt trace never deep-clones a deeply nested argument.
    Owned(Arc<OwnedTerm>),
}

impl BifArgs {
    pub(super) fn from_terms(args: &[Term]) -> Result<Self, VmError> {
        if args.len() <= 4 {
            let mut values = [Term::NIL; 4];
            values[..args.len()].copy_from_slice(args);
            return Ok(Self::Inline {
                values,
                len: args.len() as u8,
            });
        }
        let elems = args
            .iter()
            .map(|term| {
                to_owned(*term)
                    .map_err(|error| VmError::Unsupported(format!("exception arg {error:?}")))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self::Owned(Arc::new(OwnedTerm::List {
            elems,
            tail: Box::new(OwnedTerm::Nil),
        })))
    }

    /// Copy for storage in a saved trace: the payload is invisible to GC, so inline
    /// heap pointers are turned into an owned copy; immediates cannot dangle.
    fn detached(&self) -> Result<Self, VmError> {
        match self {
            Self::Inline { values, len }
                if values[..usize::from(*len)].iter().any(|t| t.is_pointer()) =>
            {
                let elems = values[..usize::from(*len)]
                    .iter()
                    .map(|term| {
                        to_owned(*term).map_err(|error| {
                            VmError::Unsupported(format!("exception arg {error:?}"))
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(Self::Owned(Arc::new(OwnedTerm::List {
                    elems,
                    tail: Box::new(OwnedTerm::Nil),
                })))
            }
            other => Ok(other.clone()),
        }
    }

    pub(super) fn root_terms(&self, roots: &mut Vec<Term>) -> Option<(usize, usize)> {
        let Self::Inline { values, len } = self else {
            return None;
        };
        let start = roots.len();
        roots.extend_from_slice(&values[..usize::from(*len)]);
        Some((start, usize::from(*len)))
    }

    pub(super) fn update_root_terms(&mut self, roots: &[Term], start: usize, len: usize) {
        if let Self::Inline { values, .. } = self {
            values[..len].copy_from_slice(&roots[start..start + len]);
        }
    }

    fn to_term(&self, heap: &mut TraceHeap) -> Result<Term, VmError> {
        match self {
            Self::Inline { values, len } => TermBuilder::new(heap)
                .list_from_slice(&values[..usize::from(*len)])
                .map_err(|error| VmError::Unsupported(format!("exception args {error:?}"))),
            Self::Owned(args) => from_owned(args, heap)
                .map_err(|error| VmError::Unsupported(format!("exception args {error:?}"))),
        }
    }
}

enum StoredTopFrame {
    Bif {
        module: Atom,
        function: Atom,
        args: BifArgs,
        info: BifErrorInfo,
    },
    CurrentArgs(OwnedTerm),
    CurrentArgsWithInfo(Option<OwnedTerm>, Box<OwnedTerm>),
}

/// Port of erts/emulator/beam/beam_common.c:781 (gather_stacktrace), OTP-29.1.1.
pub(super) fn capture(
    raw: &mut RawTrace,
    class: Option<Class>,
    top: Option<&TopFrame>,
    modules: &[Arc<Module>],
    current: (usize, usize),
    heap: &ProcessHeap,
    depth: usize,
) -> Result<(), VmError> {
    // Port of beam_common.c:600-614 (`erts_inspect_frame`) and beam_common.h:301-315,
    // OTP-29.1.1: continuations are raw CP words resolved back to code metadata.
    let (module, ip) = current;
    raw.class = class;
    raw.explicit = None;
    raw.top = top
        .map(|top| match top {
            TopFrame::Bif {
                module,
                function,
                args,
                info,
            } => Ok(StoredTopFrame::Bif {
                module: *module,
                function: *function,
                args: args.detached()?,
                info: *info,
            }),
            TopFrame::CurrentArgs(args) => Ok(StoredTopFrame::CurrentArgs(
                to_owned(*args)
                    .map_err(|e| VmError::Unsupported(format!("exception args {e:?}")))?,
            )),
            TopFrame::CurrentArgsWithInfo(args, info) => Ok(StoredTopFrame::CurrentArgsWithInfo(
                args.map(|args| {
                    to_owned(args)
                        .map_err(|e| VmError::Unsupported(format!("exception args {e:?}")))
                })
                .transpose()?,
                info.clone(),
            )),
        })
        .transpose()?;
    raw.module = modules.get(module).cloned();
    raw.ip = ip;
    raw.depth = depth.max(1);
    raw.continuations.clear();
    raw.continuations.reserve(raw.depth.min(16));
    raw.native_top = None;
    // OTP starts with the failing instruction as `prev` and compares it with
    // each continuation after moving that continuation back to its call site.
    let mut previous = Some((module, ip));
    // Native return addresses share erts' single `prev`, so the two trackers reset each other.
    let mut previous_native: Option<usize> = None;
    let mut index = 0;
    while index < heap.stack_words() {
        if raw.continuations.len() + 1 >= raw.depth {
            break;
        }
        let Some(word) = heap.stack_get(index) else {
            index += 1;
            continue;
        };
        let raw_address = word.tagged_word() as usize;
        if raw_address == crate::native_bridge::native_continuation_return_address() {
            // The bridge CP returns to the interpreter and has no BEAM stack frame.
            index += 1;
            continue;
        }
        if raw_address == crate::native_bridge::native_trace_return_address() {
            // Port of erts/emulator/beam/beam_common.c:803-815 (save_stacktrace), OTP-29.1.1:
            // trace frames are skipped; the caller's own continuation follows the frame.
            let action_count = heap
                .stack_get(index + 3)
                .and_then(Term::as_small)
                .and_then(|count| usize::try_from(count).ok())
                .unwrap_or(0);
            index += 4usize.saturating_add(action_count.saturating_mul(2));
            continue;
        }
        if raw_address & 3 == 0 && arinsal_term::may_be_native_code_pointer(raw_address) {
            // Port of erts/emulator/beam/beam_common.c:815-835 (save_stacktrace), OTP-29.1.1:
            // only non-duplicate return addresses are recorded, each looked up one byte back,
            // inside its call instruction. Like erts' is_CP test this only checks the word's
            // shape (plus the lock-free native hull); the function is looked up in `build`.
            if previous_native != Some(raw_address) {
                previous_native = Some(raw_address);
                previous = None;
                raw.continuations
                    .push(Continuation::Native(raw_address - 1));
            }
            index += 1;
            continue;
        }
        let Some((handler, module, ip)) = decode_tag(word) else {
            index += 1;
            continue;
        };
        if let Some(code) = modules.get(module)
            && !handler
            && (ip == code.return_trace_ip || ip == code.return_to_trace_ip)
        {
            index += if ip == code.return_trace_ip { 6 } else { 2 };
            continue;
        }
        let call_site = ip.saturating_sub(1);
        if handler || previous == Some((module, call_site)) {
            index += 1;
            continue;
        }
        previous = Some((module, call_site));
        previous_native = None;
        if let Some(module) = modules.get(module) {
            raw.continuations
                .push(Continuation::Interpreted(Arc::clone(module), ip));
        }
        index += 1;
    }
    Ok(())
}

/// Records the native function and pc at which the exception was raised.
pub(super) fn set_native_top(raw: &mut RawTrace, pc: usize) {
    let tag = arinsal_beamasm::module::RETURN_SITE_TAG;
    if pc & tag != 0 {
        // Port of erts/emulator/beam/beam_common.c:792-835 (save_stacktrace), OTP-29.1.1:
        // the raising pc is the call's return address, so the identical continuation is not
        // recorded again; its line is looked up inside the call instruction.
        let site = (pc & !tag) - 1;
        if matches!(raw.continuations.first(),
            Some(Continuation::Native(address)) if *address == site)
        {
            raw.continuations.remove(0);
        }
        raw.native_top = Some(site);
        return;
    }
    raw.native_top = Some(pc);
}

/// Preserve an explicit `raise/3` stacktrace with its class across `try/after`.
pub(super) fn save_explicit(
    raw: &mut RawTrace,
    class: Class,
    trace: Term,
    depth: usize,
) -> Result<(), VmError> {
    raw.class = Some(class);
    let mut explicit =
        to_owned(trace).map_err(|e| VmError::Unsupported(format!("exception stack {e:?}")))?;
    if let OwnedTerm::List { elems, .. } = &mut explicit {
        elems.truncate(depth.max(1));
    }
    raw.explicit = Some(explicit);
    raw.top = None;
    raw.module = None;
    raw.continuations.clear();
    Ok(())
}

/// Saved trace stored in a process-heap magic reference.
///
/// Port of erts/emulator/beam/beam_common.c:880 (save_stacktrace), OTP-29.1.1: erts keeps
/// `struct StackTrace` in an opaque heap object, so GC copies and reclaims it with the process.
pub(super) struct SavedTrace(Mutex<RawTrace>);

/// Allocate `raw` as a heap term of `p`; the heap owns it until GC finds it unreachable.
pub(super) fn store(p: &mut Process, raw: RawTrace) -> Result<Term, VmError> {
    let owner = MagicRef::new(SavedTrace(Mutex::new(raw)));
    TermBuilder::new(&mut FragmentingHeap(&mut p.heap))
        .magic_ref(owner)
        .map_err(|e| VmError::Unsupported(format!("raw stacktrace {e:?}")))
}

/// Run `f` on the saved trace behind `term`, or return `None` when it is not one.
pub(super) fn with_saved<R>(term: Term, f: impl FnOnce(&mut RawTrace) -> R) -> Option<R> {
    // SAFETY: the term is reachable from a live process register or stack, so its heap
    // and the retained owner stay valid for this call; nothing below collects.
    let saved = unsafe { term.magic_ref() }?.downcast_ref::<SavedTrace>()?;
    let mut raw = saved.0.lock().unwrap_or_else(|e| e.into_inner());
    Some(f(&mut raw))
}

/// True when `term` is a saved raw trace.
pub(super) fn is_saved(term: Term) -> bool {
    with_saved(term, |_| ()).is_some()
}

/// Exception class saved with a raw trace for a later `raise` instruction.
pub(super) fn raw_class(_p: &Process, term: Term) -> Option<Class> {
    with_saved(term, |raw| raw.class).flatten()
}

/// Port of erts/emulator/beam/beam_common.c:1148-1178 (raw_raise).
pub(super) fn set_raw_class(_p: &mut Process, term: Term, class: Class) -> bool {
    with_saved(term, |raw| raw.class = Some(class)).is_some()
}

/// What `save_stacktrace` puts in a BIF frame's `error_info`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum BifErrorInfo {
    /// Not a BIF failure (`undef`): no `error_info`.
    None,
    /// `#{module => FormatModule}`.
    Plain,
    /// `EXF_HAS_EXT_INFO`: `#{cause => c_p->fvalue, module => FormatModule}`.
    Cause(Atom),
}

#[derive(Debug)]
pub(super) enum TopFrame {
    /// A failing BIF, or the MFA of an `undef` call.
    Bif {
        module: Atom,
        function: Atom,
        args: BifArgs,
        info: BifErrorInfo,
    },
    CurrentArgs(Term),
    CurrentArgsWithInfo(Option<Term>, Box<OwnedTerm>),
}

pub(super) fn handler_tag(module: usize, ip: usize) -> Result<Term, VmError> {
    // Per-thread cache in front of the shared table: erts keeps the handler's code pointer in
    // the stack slot, so `catch` must not take a lock or hash with SipHash.
    thread_local! {
        static CACHE: std::cell::RefCell<std::collections::HashMap<(usize, usize), u32, CodeKeyHasher>> =
            std::cell::RefCell::new(std::collections::HashMap::default());
    }
    let key = (module, ip);
    if let Some(index) = CACHE.with(|cache| cache.borrow().get(&key).copied()) {
        return Ok(Term::catch(u64::from(index)));
    }
    let index = handler_tag_shared(key)?;
    CACHE.with(|cache| cache.borrow_mut().insert(key, index));
    Ok(Term::catch(u64::from(index)))
}

/// Multiplicative hasher for `(module, ip)` keys; they are small dense integers.
#[derive(Default)]
struct CodeKeyHasher(u64);

impl std::hash::Hasher for CodeKeyHasher {
    fn finish(&self) -> u64 {
        self.0
    }
    fn write(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.write_u64(u64::from(*byte));
        }
    }
    fn write_usize(&mut self, value: usize) {
        self.write_u64(value as u64);
    }
    fn write_u64(&mut self, value: u64) {
        self.0 = (self.0.rotate_left(5) ^ value).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    }
}

impl std::hash::BuildHasher for CodeKeyHasher {
    type Hasher = CodeKeyHasher;
    fn build_hasher(&self) -> CodeKeyHasher {
        CodeKeyHasher(0)
    }
}

fn handler_tag_shared(key: (usize, usize)) -> Result<u32, VmError> {
    let (module, ip) = key;
    let mut ids = interpreted_catch_ids()
        .lock()
        .map_err(|_| VmError::Unsupported("catch table lock".into()))?;
    let index = if let Some(index) = ids.get(&key) {
        *index
    } else {
        let base = arinsal_beamasm::catch::reserve_catch_indices(1)
            .map_err(|_| VmError::Unsupported("catch table exhausted".into()))?;
        crate::native_bridge::register_interpreted_catch(base, module, ip);
        ids.insert(key, base);
        base
    };
    Ok(index)
}

/// Encodes an interpreter continuation without colliding with catch-table indices.
pub(crate) fn continuation_tag(module: usize, ip: usize) -> Result<Term, VmError> {
    let module = u64::try_from(module).map_err(|_| VmError::Unsupported("module index".into()))?;
    let ip = u32::try_from(ip).map_err(|_| VmError::Unsupported("code index".into()))?;
    if module >= (1 << 25) {
        return Err(VmError::Unsupported("module index".into()));
    }
    Ok(Term::catch(CONTINUATION_BIT | module << 32 | u64::from(ip)))
}

/// Handler address of a stack word that is a catch tag of native code.
pub(crate) fn native_catch_address(term: Term) -> Option<usize> {
    if term.tagged_word() & 63 != 0x1b || term.classify() != TermKind::Catch {
        return None;
    }
    // SAFETY: CATCH is an immediate and carries no heap pointer.
    let payload = unsafe { term.raw_bits() } >> 6;
    if payload >> 32 != 0 || payload & CONTINUATION_BIT != 0 {
        return None;
    }
    crate::native_bridge::native_catch(u32::try_from(payload).ok()?)
}

pub(super) fn decode_tag(term: Term) -> Option<(bool, usize, usize)> {
    if term.tagged_word() & 63 != 0x1b || term.classify() != TermKind::Catch {
        return None;
    }
    // SAFETY: CATCH is an immediate and carries no heap pointer.
    let payload = unsafe { term.raw_bits() } >> 6;
    if payload >> 32 == RAW_TRACE_PREFIX {
        // Empty-trace marker, not a continuation.
        return None;
    }
    // Interpreter continuations use an immediate module/IP pair. Catch tags
    // themselves are process-independent indices into the shared catch table.
    if payload & CONTINUATION_BIT != 0 {
        return Some((
            false,
            ((payload & !CONTINUATION_BIT) >> 32) as usize,
            payload as u32 as usize,
        ));
    }
    if payload >> 32 != 0 {
        return Some((false, (payload >> 32) as usize, payload as u32 as usize));
    }
    let index = u32::try_from(payload).ok()?;
    let (module, ip) = crate::native_bridge::interpreted_catch(index)?;
    Some((true, module, ip))
}

fn atom(name: &str) -> Result<Term, VmError> {
    global_atoms()
        .intern(name)
        .map(Term::atom)
        .map_err(|_| VmError::Unsupported(format!("atom {name}")))
}

struct TraceAtoms {
    file: Atom,
    line: Atom,
    module: Atom,
    cause: Atom,
    /// BIF module to `format_error` module, as in beam_common.c:937-990.
    format_modules: [(Atom, Atom); 14],
    error_info: Atom,
    unknown: Atom,
}

fn trace_atoms() -> &'static TraceAtoms {
    static ATOMS: OnceLock<TraceAtoms> = OnceLock::new();
    ATOMS.get_or_init(|| {
        let table = global_atoms();
        let intern = |name| table.intern(name).expect("stacktrace atom is valid");
        TraceAtoms {
            file: intern("file"),
            line: intern("line"),
            module: intern("module"),
            cause: intern("cause"),
            format_modules: [
                ("atomics", "erl_erts_errors"),
                ("counters", "erl_erts_errors"),
                ("erlang", "erl_erts_errors"),
                ("erts_internal", "erl_erts_errors"),
                ("persistent_term", "erl_erts_errors"),
                ("code", "erl_kernel_errors"),
                ("os", "erl_kernel_errors"),
                ("binary", "erl_stdlib_errors"),
                ("ets", "erl_stdlib_errors"),
                ("lists", "erl_stdlib_errors"),
                ("maps", "erl_stdlib_errors"),
                ("math", "erl_stdlib_errors"),
                ("re", "erl_stdlib_errors"),
                ("unicode", "erl_stdlib_errors"),
            ]
            .map(|(bif, format)| (intern(bif), intern(format))),
            error_info: intern("error_info"),
            unknown: intern("?"),
        }
    })
}

/// The `error_info` map of a failing BIF frame.
// Port of erts/emulator/beam/beam_common.c:932-998 (save_stacktrace), OTP-29.1.1.
fn bif_error_info(
    heap: &mut TraceHeap,
    module: Atom,
    info: BifErrorInfo,
) -> Result<Option<Term>, VmError> {
    let cause = match info {
        BifErrorInfo::None => return Ok(None),
        BifErrorInfo::Plain => None,
        BifErrorInfo::Cause(cause) => Some(cause),
    };
    let atoms = trace_atoms();
    let Some(&(_, format_module)) = atoms.format_modules.iter().find(|(bif, _)| *bif == module)
    else {
        return Ok(None);
    };
    let module_pair = (Term::atom(atoms.module), Term::atom(format_module));
    let mut builder = TermBuilder::new(heap);
    let map = match cause {
        Some(cause) => {
            builder.flatmap_from_pairs(&[(Term::atom(atoms.cause), Term::atom(cause)), module_pair])
        }
        None => builder.flatmap_from_pairs(&[module_pair]),
    }
    .map_err(|e| VmError::Unsupported(format!("BIF error info {e:?}")))?;
    Ok(Some(map))
}

fn build_frame(
    heap: &mut TraceHeap,
    module: Atom,
    function: Atom,
    arity_or_args: Term,
    location: Option<(Term, u64)>,
    bif: bool,
    error_info: Option<Term>,
) -> Result<Term, VmError> {
    let module = Term::atom(module);
    let function = Term::atom(function);
    let file = Term::atom(trace_atoms().file);
    let line = Term::atom(trace_atoms().line);
    let mut builder = TermBuilder::new(heap);
    let mut info = [Term::NIL; 3];
    let mut info_len = 0;
    if bif && let Some(error_info) = error_info {
        info[info_len] = builder
            .tuple(&[Term::atom(trace_atoms().error_info), error_info])
            .map_err(|e| VmError::Unsupported(format!("error info tuple {e:?}")))?;
        info_len += 1;
    }
    if !bif && let Some((name, number)) = location {
        let number = Term::small(number as i64)
            .ok_or_else(|| VmError::Unsupported("source line number".into()))?;
        info[info_len] = builder
            .tuple(&[file, name])
            .map_err(|e| VmError::Unsupported(format!("stack file {e:?}")))?;
        info_len += 1;
        info[info_len] = builder
            .tuple(&[line, number])
            .map_err(|e| VmError::Unsupported(format!("stack line {e:?}")))?;
        info_len += 1;
    }
    if !bif && let Some(error_info) = error_info {
        info[info_len] = builder
            .tuple(&[Term::atom(trace_atoms().error_info), error_info])
            .map_err(|e| VmError::Unsupported(format!("error info tuple {e:?}")))?;
        info_len += 1;
    }
    let location = builder
        .list_from_slice(&info[..info_len])
        .map_err(|e| VmError::Unsupported(format!("stack frame info {e:?}")))?;
    builder
        .tuple(&[module, function, arity_or_args, location])
        .map_err(|e| VmError::Unsupported(format!("stack frame {e:?}")))
}

/// Port of erts/emulator/beam/beam_common.c:781 (gather_stacktrace), OTP-29.1.1.
/// A continuation points after the call; the preceding instruction owns its line.
pub(super) fn build(
    modules: &[Arc<Module>],
    p: &mut Process,
    top: Option<&TopFrame>,
    depth: usize,
) -> Result<Term, VmError> {
    let mut raw = RawTrace::default();
    capture(
        &mut raw,
        None,
        top,
        modules,
        (p.module, p.ip),
        &p.heap,
        depth,
    )?;
    // A process inside a native BIF call raises at that call's pc, as in `exceptions.rs`.
    let native_pc = p.cold.as_ref().map_or(0, |cold| cold.native_call_pc);
    if native_pc != 0 && crate::native_bridge::is_native_function_at(native_pc) {
        set_native_top(&mut raw, native_pc);
    } else if let Some(pc) = p.native_pc
        && crate::native_bridge::is_native_function_at(pc)
    {
        // A process suspended inside native code: `p.module`/`p.ip` still hold the last
        // interpreter position, so the current function comes from its native resume pc.
        set_native_top(&mut raw, pc);
    }
    build_saved(p, &mut raw)
}

/// Port of erts/emulator/beam/beam_common.c:1205 (build_stacktrace), OTP-29.1.1.
pub(super) fn build_saved(p: &mut Process, raw: &mut RawTrace) -> Result<Term, VmError> {
    if let Some(explicit) = &raw.explicit {
        return from_owned(explicit, &mut FragmentingHeap(&mut p.heap))
            .map_err(|e| VmError::Unsupported(format!("exception stack {e:?}")));
    }
    let top = raw
        .top
        .as_ref()
        .map(|top| match top {
            StoredTopFrame::Bif {
                module,
                function,
                args,
                info,
            } => Ok(TopFrame::Bif {
                module: *module,
                function: *function,
                args: args.clone(),
                info: *info,
            }),
            StoredTopFrame::CurrentArgs(args) => Ok(TopFrame::CurrentArgs(
                from_owned(args, &mut FragmentingHeap(&mut p.heap))
                    .map_err(|e| VmError::Unsupported(format!("exception args {e:?}")))?,
            )),
            StoredTopFrame::CurrentArgsWithInfo(args, info) => {
                let args = args
                    .as_ref()
                    .map(|args| {
                        from_owned(args, &mut FragmentingHeap(&mut p.heap))
                            .map_err(|e| VmError::Unsupported(format!("exception args {e:?}")))
                    })
                    .transpose()?;
                Ok(TopFrame::CurrentArgsWithInfo(args, info.clone()))
            }
        })
        .transpose()?;
    let top = top.as_ref();
    raw.frames.clear();
    // Upper bound per frame: 4-tuple, 3-element info list, file/line/error_info tuples
    // and the one-pair error_info map; plus the result list and BIF argument list.
    let bif_args = match top {
        Some(TopFrame::Bif { args, .. }) => match args {
            BifArgs::Inline { len, .. } => usize::from(*len),
            BifArgs::Owned(_) => 0,
        },
        _ => 0,
    };
    let block_words = (raw.depth + 2) * 30 + 2 * bif_args;
    let mut heap = TraceHeap::with_block(&mut p.heap, block_words);
    let current = raw
        .module
        .as_ref()
        .ok_or_else(|| VmError::Unsupported("stacktrace module".into()))?;
    let (frame_module, function, arity, location) = if let Some((native, pc)) = raw
        .native_top
        .and_then(|pc| crate::native_function_at(pc).map(|native| (native, pc)))
    {
        // The frame's own file term: `raw.module` is only the last interpreter module.
        let location = crate::native_bridge::native_stack_frame_at(pc).and_then(|frame| {
            let line = frame.line?;
            frame
                .file_term
                .or_else(|| {
                    frame
                        .file
                        .as_deref()
                        .and_then(|file| current.line_file_terms.get(file).copied())
                })
                .map(|file| (file, u64::from(line)))
        });
        (
            native.module_atom,
            native.function_atom,
            native.arity,
            location,
        )
    } else {
        let (function, arity) = current
            .function_atom_at(raw.ip)
            .unwrap_or((trace_atoms().unknown, 0));
        (
            current.name_atom,
            function,
            arity,
            current.line_term_at(raw.ip),
        )
    };
    let top_frame = if let Some(TopFrame::Bif {
        module,
        function,
        args,
        info,
    }) = top
    {
        let args = args.to_term(&mut heap)?;
        let error_info = bif_error_info(&mut heap, *module, *info)?;
        build_frame(&mut heap, *module, *function, args, None, true, error_info)?
    } else {
        let top_args = match top {
            Some(TopFrame::CurrentArgs(args)) => *args,
            Some(TopFrame::CurrentArgsWithInfo(Some(args), _)) => *args,
            Some(TopFrame::CurrentArgsWithInfo(None, _)) => {
                Term::small(i64::from(arity)).expect("arity is small")
            }
            _ => Term::small(i64::from(arity)).expect("arity is small"),
        };
        let error_info = match top {
            Some(TopFrame::CurrentArgsWithInfo(_, info)) => Some(
                from_owned(info.as_ref(), &mut heap)
                    .map_err(|e| VmError::Unsupported(format!("exception info {e:?}")))?,
            ),
            _ => None,
        };
        build_frame(
            &mut heap,
            frame_module,
            function,
            top_args,
            location,
            false,
            error_info,
        )?
    };
    raw.frames.push(top_frame);
    if matches!(top, Some(TopFrame::Bif { .. })) && raw.frames.len() < raw.depth {
        raw.frames.push(build_frame(
            &mut heap,
            frame_module,
            function,
            Term::small(i64::from(arity)).expect("arity is small"),
            location,
            false,
            None,
        )?);
    }
    for continuation in &raw.continuations {
        if raw.frames.len() >= raw.depth {
            break;
        }
        if let Continuation::Native(address) = continuation {
            // Resolved lazily like erts, which saves raw pcs and decodes them in build_stacktrace.
            let Some(function) = crate::native_bridge::native_stack_frame_at(*address) else {
                continue;
            };
            let location = function.line.and_then(|line| {
                function
                    .file_term
                    .or_else(|| {
                        function
                            .file
                            .as_deref()
                            .and_then(|file| current.line_file_terms.get(file).copied())
                    })
                    .map(|file| (file, u64::from(line)))
            });
            raw.frames.push(build_frame(
                &mut heap,
                function.module_atom,
                function.function_atom,
                Term::small(i64::from(function.arity)).expect("arity is small"),
                location,
                false,
                None,
            )?);
            continue;
        }
        let Continuation::Interpreted(module, ip) = continuation else {
            unreachable!()
        };
        let call_site = ip.saturating_sub(1);
        let Some((function, arity)) = module.function_atom_at(call_site) else {
            continue;
        };
        raw.frames.push(build_frame(
            &mut heap,
            module.name_atom,
            function,
            Term::small(i64::from(arity)).expect("arity is small"),
            module.line_term_at(call_site),
            false,
            None,
        )?);
    }
    TermBuilder::new(&mut heap)
        .list_from_slice(&raw.frames)
        .map_err(|e| VmError::Unsupported(format!("stacktrace {e:?}")))
}

pub(super) fn atom_term(name: &str) -> Result<Term, VmError> {
    atom(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bif_arguments_keep_pointer_terms_inline_and_rewrite_gc_roots() {
        let mut heap = ProcessHeap::new();
        let pointer = TermBuilder::new(&mut heap).tuple(&[]).unwrap();
        assert!(pointer.is_pointer());
        let mut args = BifArgs::from_terms(&[pointer, Term::small(3).unwrap()]).unwrap();
        assert!(matches!(&args, BifArgs::Inline { .. }));
        let mut roots = Vec::new();
        let (start, len) = args.root_terms(&mut roots).unwrap();
        let replacement = Term::small(7).unwrap();
        roots[start] = replacement;
        args.update_root_terms(&roots, start, len);
        assert!(matches!(args, BifArgs::Inline { values, .. } if values[0] == replacement));
    }
}
