//! Pure BIFs implemented against stable heap terms.

use std::cell::Cell;
use std::cmp::Ordering;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::time::{SystemTime, UNIX_EPOCH};

use arinsal_term::{
    ExportEntry, ExternalBinary, FunEntry, HeapAlloc, MagicRef, Node, Term, TermBuilder, TermError,
    TermKind, atoms, cmp, copy_term, exact_eq, flat_size, global_atoms, loose_eq, phash, phash2,
    phash2_range, writable_bytes_mut, writable_extend_private, writable_finalize,
};
use num_bigint::{BigInt, Sign};
use num_traits::{FromPrimitive, ToPrimitive};

use crate::{BifError, BifFn, Class, Ctx};

const BADARG: BifError = BifError::BADARG;
static NEXT_REF: AtomicU64 = AtomicU64::new(1);
static NEXT_UNIQUE: AtomicU64 = AtomicU64::new(1);

// Port of erts/emulator/beam/erl_bif_unique.c (per-scheduler reference counters), OTP-29.1.1.
// Thread-local counter block avoids atomic contention on every `make_ref/0`.
const REF_BLOCK_SIZE: u64 = 4096;

thread_local! {
    static REF_BLOCK: Cell<(u64, u64)> = const { Cell::new((0, 0)) };
}

/// Generate the next unique 64-bit reference ID from a thread-local block.
/// Port of erts/emulator/beam/erl_bif_unique.c (per-scheduler reference counters), OTP-29.1.1.
#[inline(always)]
pub fn next_ref_id() -> u64 {
    REF_BLOCK.with(|cell| {
        let (current, limit) = cell.get();
        if current < limit {
            cell.set((current + 1, limit));
            current
        } else {
            let start = NEXT_REF.fetch_add(REF_BLOCK_SIZE, AtomicOrdering::Relaxed);
            cell.set((start + 1, start + REF_BLOCK_SIZE));
            start
        }
    })
}

pub(super) struct Heap<'a>(pub(super) &'a mut dyn HeapAlloc);
impl HeapAlloc for Heap<'_> {
    fn alloc(&mut self, words: usize) -> Option<*mut u64> {
        self.0.alloc(words)
    }
    fn retain_binary(&mut self, value: Arc<Vec<u8>>) {
        self.0.retain_binary(value)
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

// Consecutive cons cells must not request a fresh heap fragment per element.
// Each BIF reserves its output cells once and hands them to TermBuilder.
struct ConsBlock<'a> {
    backing: &'a mut dyn HeapAlloc,
    next: *mut u64,
    remaining: usize,
}

impl<'a> ConsBlock<'a> {
    fn new(backing: &'a mut dyn HeapAlloc, cells: usize) -> Self {
        let words = cells
            .checked_mul(2)
            .expect("list size exceeds address space");
        let next = backing.alloc(words).expect("infallible BIF heap");
        Self {
            backing,
            next,
            remaining: words,
        }
    }
}

impl HeapAlloc for ConsBlock<'_> {
    fn alloc(&mut self, words: usize) -> Option<*mut u64> {
        if words > self.remaining {
            return self.backing.alloc(words);
        }
        let result = self.next;
        // SAFETY: `next` points into the single reservation and `remaining`
        // proves that advancing by `words` stays inside it.
        self.next = unsafe { self.next.add(words) };
        self.remaining -= words;
        Some(result)
    }
    fn retain_binary(&mut self, value: Arc<Vec<u8>>) {
        self.backing.retain_binary(value)
    }
    fn retain_writable_binary(
        &mut self,
        value: Arc<arinsal_term::WritableBinary>,
    ) -> Result<(), TermError> {
        self.backing.retain_writable_binary(value)
    }
    fn supports_writable_binary(&self) -> bool {
        self.backing.supports_writable_binary()
    }
    fn retain_external_binary(&mut self, value: Arc<ExternalBinary>) -> Result<(), TermError> {
        self.backing.retain_external_binary(value)
    }
    fn supports_external_binary(&self) -> bool {
        self.backing.supports_external_binary()
    }
    fn retain_node(&mut self, value: Arc<Node>) {
        self.backing.retain_node(value)
    }
    fn retain_fun(&mut self, value: Arc<FunEntry>) {
        self.backing.retain_fun(value)
    }
    fn retain_export(&mut self, value: Arc<ExportEntry>) {
        self.backing.retain_export(value)
    }
    fn retain_magic(&mut self, value: Arc<MagicRef>) {
        self.backing.retain_magic(value)
    }
    fn supports_magic(&self) -> bool {
        self.backing.supports_magic()
    }
}

pub(super) fn lookup(module: &str, name: &str, arity: u8) -> Option<BifFn> {
    let f: BifFn = match (module, name, arity) {
        ("erlang", "length", 1) => length,
        ("erlang", "abs", 1) => abs,
        ("erlang", "float", 1) => to_float,
        ("erlang", "trunc", 1) => trunc,
        ("erlang", "round", 1) => round,
        ("erlang", "ceil", 1) => ceil,
        ("erlang", "floor", 1) => floor,
        ("erlang", "hd", 1) => hd,
        ("erlang", "tl", 1) => tl,
        ("erlang", "element", 2) => element,
        ("erlang", "setelement", 3) => setelement,
        ("erlang", "tuple_size", 1) => tuple_size,
        ("erlang", "size", 1) => size,
        ("erlang", "byte_size", 1) => byte_size,
        ("erlang", "bit_size", 1) => bit_size,
        ("erlang", "node", 0 | 1) => node,
        ("erlang", "self", 0) => self_bif,
        ("erlang", "min", 2) => min,
        ("erlang", "max", 2) => max,
        ("erlang", "not", 1) => not,
        ("erlang", "and", 2) => and,
        ("erlang", "or", 2) => or,
        ("erlang", "xor", 2) => xor,
        ("erlang", "==", 2) => eq,
        ("erlang", "/=", 2) => ne,
        ("erlang", "=:=", 2) => exact_eq_bif,
        ("erlang", "=/=", 2) => exact_ne,
        ("erlang", "<", 2) => lt,
        ("erlang", "=<", 2) => le,
        ("erlang", ">", 2) => gt,
        ("erlang", ">=", 2) => ge,
        ("erlang", "phash2", 1 | 2) => phash2_bif,
        ("erlang", "phash", 2) => phash_bif,
        ("erlang", "make_ref", 0) => make_ref,
        ("erlang", "unique_integer", 0 | 1) => unique_integer,
        ("erlang" | "os", "system_time", 0 | 1) => system_time,
        ("erts_internal", "time_unit" | "perf_counter_unit", 0) => time_unit,
        ("erlang", "tuple_to_list", 1) => tuple_to_list,
        ("erlang", "list_to_tuple", 1) => list_to_tuple,
        ("erlang", "make_tuple", 2 | 3) => make_tuple,
        ("erlang", "append_element", 2) => append_element,
        ("erlang", "delete_element", 2) => delete_element,
        ("erlang", "insert_element", 3) => insert_element,
        ("erlang", "++" | "append", 2) => append,
        ("erlang", "--" | "subtract", 2) => subtract,
        ("lists", "reverse", 2) => reverse,
        ("lists", "member", 2) => member,
        ("lists", "keyfind", 3) => keyfind,
        ("lists", "keymember", 3) => keymember,
        ("lists", "keysearch", 3) => keysearch,
        ("erlang", "atom_to_list", 1) => atom_to_list,
        ("erlang", "list_to_atom", 1) => list_to_atom,
        ("erlang", "list_to_existing_atom", 1) => list_to_existing_atom,
        ("erlang", "atom_to_binary", 2) => atom_to_binary,
        ("erlang", "binary_to_atom", 2) => binary_to_atom,
        ("erlang", "binary_to_existing_atom", 2) => binary_to_existing_atom,
        ("erlang", "float_to_list", 1 | 2) => float_to_list,
        ("erlang", "float_to_binary", 1 | 2) => float_to_binary,
        ("erlang", "list_to_float", 1) => list_to_float,
        ("erlang", "binary_to_float", 1) => binary_to_float,
        ("erlang", "integer_to_list", 1 | 2) => integer_to_list,
        ("erlang", "integer_to_binary", 1 | 2) => integer_to_binary,
        ("erlang", "binary_to_list", 1 | 3) => erlang_binary_to_list,
        ("erlang", "list_to_binary", 1) => list_to_binary,
        ("erlang", "iolist_to_binary", 1) => iolist_to_binary,
        ("erlang", "iolist_to_iovec", 1) => iolist_to_iovec,
        ("erlang", "iolist_size", 1) => iolist_size,
        ("erlang", "bitstring_to_list", 1) => bitstring_to_list,
        ("erlang", "list_to_bitstring", 1) => list_to_bitstring,
        ("erlang", "split_binary", 2) => split_binary,
        ("erlang", "binary_part", 2 | 3) => binary_part,
        ("binary", "part", 2 | 3) => binary_part,
        ("binary", "first", 1) => binary_first,
        ("binary", "last", 1) => binary_last,
        ("binary", "at", 2) => binary_at,
        ("binary", "copy", 1 | 2) => binary_copy,
        ("binary", "referenced_byte_size", 1) => referenced_byte_size,
        ("binary", "longest_common_prefix", 1) => longest_common_prefix,
        ("binary", "longest_common_suffix", 1) => longest_common_suffix,
        ("binary", "compile_pattern", 1) => compile_pattern,
        ("binary", "match", 2 | 3) => binary_match,
        ("binary", "matches", 2 | 3) => binary_matches,
        ("binary", "split", 2 | 3) => binary_split,
        ("binary", "encode_unsigned", 1 | 2) => encode_unsigned,
        ("binary", "decode_unsigned", 1 | 2) => decode_unsigned,
        ("binary", "list_to_bin", 1) => list_to_binary,
        ("erlang", "is_atom", 1) => is_atom,
        ("erlang", "is_list", 1) => is_list,
        ("erlang", "is_tuple", 1) => is_tuple,
        ("erlang", "is_float", 1) => is_float,
        ("erlang", "is_integer", 1) => is_integer,
        ("erlang", "is_integer", 3) => is_integer_range,
        ("erlang", "is_number", 1) => is_number,
        ("erlang", "is_pid", 1) => is_pid,
        ("erlang", "is_port", 1) => is_port,
        ("erlang", "is_reference", 1) => is_reference,
        ("erlang", "is_binary", 1) => is_binary,
        ("erlang", "is_bitstring", 1) => is_bitstring,
        ("erlang", "is_function", 1 | 2) => is_function,
        ("erlang", "is_record", 1..=3) => is_record,
        ("erlang", "is_boolean", 1) => is_boolean,
        ("erlang", "is_map", 1) => is_map,
        ("erlang", "is_map_key", 2) => is_map_key,
        ("erlang", "map_get", 2) => map_get,
        ("erlang", "map_size", 1) => map_size,
        ("erlang", "is_builtin", 3) => is_builtin,
        ("erlang", "error", 1..=3) => error,
        ("erlang", "exit", 1) => exit,
        ("erlang", "throw", 1) => throw,
        ("erlang", "raise", 3) => raise,
        ("erts_internal", "cmp_term", 2) => cmp_term,
        ("erts_debug", "copy_shared", 2) => debug_copy_shared,
        ("erts_debug", "flat_size", 1) => debug_flat_size,
        ("erts_debug", "same", 2) => debug_same,
        ("unicode", "bin_is_7bit", 1) => bin_is_7bit,
        ("math", "cos", 1) => math_cos,
        ("math", "cosh", 1) => math_cosh,
        ("math", "sin", 1) => math_sin,
        ("math", "sinh", 1) => math_sinh,
        ("math", "tan", 1) => math_tan,
        ("math", "tanh", 1) => math_tanh,
        ("math", "acos", 1) => math_acos,
        ("math", "acosh", 1) => math_acosh,
        ("math", "asin", 1) => math_asin,
        ("math", "asinh", 1) => math_asinh,
        ("math", "atan", 1) => math_atan,
        ("math", "atanh", 1) => math_atanh,
        ("math", "erf", 1) => math_erf,
        ("math", "erfc", 1) => math_erfc,
        ("math", "exp", 1) => math_exp,
        ("math", "log", 1) => math_log,
        ("math", "log2", 1) => math_log2,
        ("math", "log10", 1) => math_log10,
        ("math", "sqrt", 1) => math_sqrt,
        ("math", "floor", 1) => math_floor,
        ("math", "ceil", 1) => math_ceil,
        ("math", "atan2", 2) => math_atan2,
        ("math", "pow", 2) => math_pow,
        ("math", "fmod", 2) => math_fmod,
        _ => return None,
    };
    // A registry entry must correspond to the supported OTP release.
    arinsal_spec::bif_lookup(module, name, arity).map(|_| f)
}

pub(super) fn bool_term(value: bool) -> Term {
    Term::atom(if value { atoms::TRUE } else { atoms::FALSE })
}

fn bool_value(term: Term) -> Result<bool, BifError> {
    match term.as_atom() {
        Some(atom) if atom == atoms::TRUE => Ok(true),
        Some(atom) if atom == atoms::FALSE => Ok(false),
        _ => Err(BADARG),
    }
}

pub(super) fn integer(ctx: &mut Ctx<'_>, value: usize) -> Result<Term, BifError> {
    TermBuilder::new(&mut Heap(ctx.heap))
        .int_from_i128(value as i128)
        .map_err(|_| BifError::SystemLimit)
}

pub(super) fn tuple(term: Term) -> Result<Vec<Term>, BifError> {
    // SAFETY: Ctx keeps all argument heaps live and stable during the BIF.
    unsafe { term.tuple_ref() }
        .map(|view| view.iter().collect())
        .ok_or(BADARG)
}

pub(super) fn list(term: Term) -> Result<Vec<Term>, BifError> {
    list_with_limit(term, usize::MAX)
}

fn list_with_limit(term: Term, limit: usize) -> Result<Vec<Term>, BifError> {
    let mut out = Vec::new();
    let mut tail = term;
    while tail.classify() == TermKind::List {
        if out.len() == limit {
            return Err(BADARG);
        }
        // SAFETY: The source heap remains live and stable for the call.
        let (head, next) = unsafe { tail.cons_ref() }.ok_or(BADARG)?;
        out.push(head);
        tail = next;
    }
    if tail != Term::NIL {
        Err(BADARG)
    } else {
        Ok(out)
    }
}

const MAX_TUPLE_SIZE: usize = (1 << 24) - 1;

fn check_tuple_arity(size: usize) -> Result<(), BifError> {
    if size <= MAX_TUPLE_SIZE {
        Ok(())
    } else {
        Err(BADARG)
    }
}

pub(super) fn make_list(
    ctx: &mut Ctx<'_>,
    items: impl IntoIterator<Item = Term>,
    tail: Term,
) -> Term {
    let mut result = tail;
    let items: Vec<_> = items.into_iter().collect();
    if items.is_empty() {
        return result;
    }
    let mut heap = ConsBlock::new(ctx.heap, items.len());
    let mut builder = TermBuilder::new(&mut heap);
    for item in items.into_iter().rev() {
        result = builder.cons(item, result).expect("infallible BIF heap");
    }
    result
}

pub(super) fn tuple_build(ctx: &mut Ctx<'_>, values: &[Term]) -> Term {
    TermBuilder::new(&mut Heap(ctx.heap))
        .tuple(values)
        .expect("infallible BIF heap")
}

fn length(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    integer(ctx, list(args[0])?.len())
}
fn hd(_: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    // SAFETY: The input heap is live and stable.
    unsafe { args[0].cons_ref() }
        .map(|(head, _)| head)
        .ok_or(BADARG)
}
fn tl(_: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    // SAFETY: The input heap is live and stable.
    unsafe { args[0].cons_ref() }
        .map(|(_, tail)| tail)
        .ok_or(BADARG)
}
fn element(_: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let index = args[0].as_small().ok_or(BADARG)?;
    if index < 1 {
        return Err(BADARG);
    }
    tuple(args[1])?
        .get(index as usize - 1)
        .copied()
        .ok_or(BADARG)
}
fn setelement(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let index = args[0].as_small().ok_or(BADARG)?;
    let mut values = tuple(args[1])?;
    if index < 1 || index as usize > values.len() {
        return Err(BADARG);
    }
    values[index as usize - 1] = args[2];
    Ok(tuple_build(ctx, &values))
}
fn tuple_size(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    integer(ctx, tuple(args[0])?.len())
}
fn size(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    match args[0].classify() {
        TermKind::Tuple => tuple_size(ctx, args),
        TermKind::Bitstring => {
            // SAFETY: The source binary and owner remain live for this call.
            let view = unsafe { args[0].binary_ref() }.ok_or(BADARG)?;
            integer(ctx, view.bit_len() / 8)
        }
        _ => Err(BADARG),
    }
}
fn bit_size(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    // SAFETY: The input heap and off-heap binary owner are live.
    let view = unsafe { args[0].binary_ref() }.ok_or(BADARG)?;
    integer(ctx, view.bit_len())
}
fn byte_size(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    // SAFETY: The input heap and off-heap binary owner are live.
    let view = unsafe { args[0].binary_ref() }.ok_or(BADARG)?;
    integer(ctx, view.bit_len().div_ceil(8))
}
fn node(_: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    if args.is_empty() {
        return Ok(Term::atom(atoms::NONAME));
    }
    let identity = args[0].identity().ok_or(BADARG)?;
    let name = match identity {
        arinsal_term::Identity::Pid { node, .. }
        | arinsal_term::Identity::Port { node, .. }
        | arinsal_term::Identity::Ref { node, .. } => node,
    };
    Ok(Term::atom(name))
}
fn self_bif(_: &mut Ctx<'_>, _: &[Term]) -> Result<Term, BifError> {
    Err(BifError::Unsupported("self requires the calling process"))
}
fn min(_: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    Ok(if cmp(args[0], args[1]) == Ordering::Greater {
        args[1]
    } else {
        args[0]
    })
}
fn max(_: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    Ok(if cmp(args[0], args[1]) == Ordering::Less {
        args[1]
    } else {
        args[0]
    })
}
fn not(_: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    Ok(bool_term(!bool_value(args[0])?))
}
fn and(_: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    Ok(bool_term(bool_value(args[0])? & bool_value(args[1])?))
}
fn or(_: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    Ok(bool_term(bool_value(args[0])? | bool_value(args[1])?))
}
fn xor(_: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    Ok(bool_term(bool_value(args[0])? ^ bool_value(args[1])?))
}

macro_rules! compare {
    ($name:ident, $body:expr) => {
        fn $name(_: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
            Ok(bool_term($body(args[0], args[1])))
        }
    };
}
compare!(eq, loose_eq);
compare!(exact_eq_bif, exact_eq);
compare!(ne, |a, b| !loose_eq(a, b));
compare!(exact_ne, |a, b| !exact_eq(a, b));
compare!(lt, |a, b| cmp(a, b) == Ordering::Less);
compare!(le, |a, b| cmp(a, b) != Ordering::Greater);
compare!(gt, |a, b| cmp(a, b) == Ordering::Greater);
compare!(ge, |a, b| cmp(a, b) != Ordering::Less);

fn phash2_bif(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let value = if args.len() == 1 {
        phash2(args[0])
    } else {
        let range = args[1].as_small().ok_or(BADARG)?;
        phash2_range(args[0], range.try_into().map_err(|_| BADARG)?).ok_or(BADARG)?
    };
    integer(ctx, value as usize)
}
fn phash_bif(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let range = args[1].as_small().ok_or(BADARG)?;
    let value = phash(args[0], range.try_into().map_err(|_| BADARG)?).ok_or(BADARG)?;
    integer(ctx, value as usize)
}
fn make_ref(ctx: &mut Ctx<'_>, _: &[Term]) -> Result<Term, BifError> {
    let id = next_ref_id();
    Term::local_ref(ctx.heap, [id as u32, (id >> 32) as u32, 0]).map_err(|_| BifError::SystemLimit)
}
fn unique_integer(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let mut positive = false;
    if let Some(options) = args.first() {
        for option in list(*options)? {
            let name = atom_name(option).ok_or(BADARG)?;
            if name.as_ref() != "positive" && name.as_ref() != "monotonic" {
                return Err(BADARG);
            }
            positive |= name.as_ref() == "positive";
        }
    }
    let value = NEXT_UNIQUE.fetch_add(1, AtomicOrdering::Relaxed);
    if positive {
        integer(ctx, value as usize)
    } else {
        Ok(Term::small(-(1_i64 << 59) + value as i64).expect("counter in small range"))
    }
}
fn system_time(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let units_per_second = if let Some(unit) = args.first() {
        if let Some(name) = atom_name(*unit) {
            // Port of erts/emulator/beam/erl_time_sup.c:2277 (time_unit_conversion), OTP-29.1.1.
            // Plural atoms (`nano_seconds` and the rest) are aliases of the singular units.
            BigInt::from(match name.as_ref() {
                "native" | "nanosecond" | "nano_seconds" => 1_000_000_000,
                "microsecond" | "micro_seconds" => 1_000_000,
                "millisecond" | "milli_seconds" => 1_000,
                "second" | "seconds" => 1,
                _ => return Err(BADARG),
            })
        } else {
            let value = bigint(*unit)?;
            if value.sign() != Sign::Plus {
                return Err(BADARG);
            }
            value
        }
    } else {
        BigInt::from(1_000_000_000)
    };
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| BifError::SystemLimit)?;
    let value = BigInt::from(elapsed.as_nanos()) * units_per_second / 1_000_000_000_u64;
    TermBuilder::new(&mut Heap(ctx.heap))
        .int_from_bigint(&value)
        .map_err(|_| BifError::SystemLimit)
}
fn time_unit(_: &mut Ctx<'_>, _: &[Term]) -> Result<Term, BifError> {
    Ok(Term::small(1_000_000_000).expect("small time unit"))
}

fn tuple_to_list(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    Ok(make_list(ctx, tuple(args[0])?, Term::NIL))
}
fn list_to_tuple(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    // Port of erts/emulator/beam/bif.c:3789 (list_to_tuple_1), OTP-29.1.1.
    // Check proper-list length before allocating the output tuple.
    let values = list_with_limit(args[0], MAX_TUPLE_SIZE)?;
    Ok(tuple_build(ctx, &values))
}
fn make_tuple(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    // Port of erts/emulator/beam/bif.c:3006,3027 (make_tuple_2/3), OTP-29.1.1.
    let n = args[0].as_small().ok_or(BADARG)?;
    if n < 0 || check_tuple_arity(n as usize).is_err() {
        return Err(BADARG);
    }
    let mut values = vec![args[1]; n as usize];
    if args.len() == 3 {
        for entry in list(args[2])? {
            let pair = tuple(entry)?;
            if pair.len() != 2 {
                return Err(BADARG);
            }
            let index = pair[0].as_small().ok_or(BADARG)?;
            if index < 1 || index > n {
                return Err(BADARG);
            }
            values[index as usize - 1] = pair[1];
        }
    }
    Ok(tuple_build(ctx, &values))
}
fn append_element(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    // Port of erts/emulator/beam/bif.c:3083 (append_element_2), OTP-29.1.1.
    let mut values = tuple(args[0])?;
    check_tuple_arity(values.len() + 1)?;
    values.push(args[1]);
    Ok(tuple_build(ctx, &values))
}
fn delete_element(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let index = args[0].as_small().ok_or(BADARG)?;
    let mut values = tuple(args[1])?;
    if index < 1 || index as usize > values.len() {
        return Err(BADARG);
    }
    values.remove(index as usize - 1);
    Ok(tuple_build(ctx, &values))
}
fn insert_element(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let index = args[0].as_small().ok_or(BADARG)?;
    let mut values = tuple(args[1])?;
    if index < 1 || index as usize > values.len() + 1 {
        return Err(BADARG);
    }
    values.insert(index as usize - 1, args[2]);
    Ok(tuple_build(ctx, &values))
}

#[cfg(test)]
mod tuple_limit_tests {
    use super::{MAX_TUPLE_SIZE, check_tuple_arity};

    #[test]
    fn tuple_arity_limit_matches_erts_header_capacity() {
        assert!(check_tuple_arity(MAX_TUPLE_SIZE).is_ok());
        assert!(check_tuple_arity(MAX_TUPLE_SIZE + 1).is_err());
    }
}
fn append(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    // Erlang permits any right-hand tail, including an improper one.
    Ok(make_list(ctx, list(args[0])?, args[1]))
}
fn subtract(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let mut left = list(args[0])?;
    for removed in list(args[1])? {
        if let Some(index) = left.iter().position(|&x| exact_eq(x, removed)) {
            left.remove(index);
        }
    }
    Ok(make_list(ctx, left, Term::NIL))
}
fn reverse(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    // Port of erts/emulator/beam/erl_bif_lists.c:1144 (lists_reverse_alloc), OTP-29.1.1.
    // Count and validate before reserving the full output in one allocation.
    if args[0] == Term::NIL {
        return Ok(args[1]);
    }
    let mut source = args[0];
    let mut count = 0usize;
    while source.classify() == TermKind::List {
        // SAFETY: the source list remains live for the BIF call.
        source = unsafe { source.cons_ref() }.ok_or(BADARG)?.1;
        count += 1;
    }
    if source != Term::NIL {
        return Err(BADARG);
    }
    let mut heap = ConsBlock::new(ctx.heap, count);
    let mut builder = TermBuilder::new(&mut heap);
    let mut result = args[1];
    source = args[0];
    while source.classify() == TermKind::List {
        // SAFETY: the source list remains live and the BIF heap never moves it.
        let (head, next) = unsafe { source.cons_ref() }.ok_or(BADARG)?;
        result = builder.cons(head, result).expect("infallible BIF heap");
        source = next;
    }
    Ok(result)
}
fn member(_: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let mut rest = args[1];
    while rest.classify() == TermKind::List {
        // SAFETY: The source heap remains live throughout this call.
        let (head, tail) = unsafe { rest.cons_ref() }.ok_or(BADARG)?;
        if exact_eq(head, args[0]) {
            return Ok(bool_term(true));
        }
        rest = tail;
    }
    if rest != Term::NIL {
        return Err(BADARG);
    }
    Ok(bool_term(false))
}
fn key_search(args: &[Term]) -> Result<Option<Term>, BifError> {
    let index = args[1].as_small().ok_or(BADARG)?;
    if index < 1 {
        return Err(BADARG);
    }
    let mut rest = args[2];
    while rest.classify() == TermKind::List {
        // SAFETY: The source heap remains live throughout this call.
        let (value, tail) = unsafe { rest.cons_ref() }.ok_or(BADARG)?;
        if let Ok(items) = tuple(value)
            && let Some(&candidate) = items.get(index as usize - 1)
            && loose_eq(args[0], candidate)
        {
            return Ok(Some(value));
        }
        rest = tail;
    }
    if rest != Term::NIL {
        return Err(BADARG);
    }
    Ok(None)
}
fn keyfind(_: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    Ok(key_search(args)?.unwrap_or(bool_term(false)))
}
fn keymember(_: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    Ok(bool_term(key_search(args)?.is_some()))
}
fn keysearch(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    Ok(match key_search(args)? {
        Some(value) => tuple_build(ctx, &[Term::atom(atoms::VALUE), value]),
        None => bool_term(false),
    })
}

pub(super) fn atom_name(term: Term) -> Option<std::sync::Arc<str>> {
    global_atoms().text(term.as_atom()?)
}
fn atom_to_list(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let text = atom_name(args[0]).ok_or(BADARG)?;
    Ok(make_list(
        ctx,
        text.chars().map(|c| Term::small(c as i64).unwrap()),
        Term::NIL,
    ))
}
fn charlist(term: Term) -> Result<String, BifError> {
    let mut out = String::new();
    for item in list(term)? {
        let point = item
            .as_small()
            .and_then(|n| u32::try_from(n).ok())
            .ok_or(BADARG)?;
        out.push(char::from_u32(point).ok_or(BADARG)?);
    }
    Ok(out)
}
fn intern(text: &str, existing: bool) -> Result<Term, BifError> {
    let table = global_atoms();
    let atom = if existing {
        table.get(text).ok_or(BADARG)?
    } else {
        table.intern(text).map_err(|error| match error {
            arinsal_term::AtomError::TooLong => BADARG,
            arinsal_term::AtomError::SystemLimit => BifError::SystemLimit,
        })?
    };
    Ok(Term::atom(atom))
}
fn list_to_atom(_: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    intern(&charlist(args[0])?, false)
}
fn list_to_existing_atom(_: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    intern(&charlist(args[0])?, true)
}
fn encoding(term: Term) -> Result<&'static str, BifError> {
    match atom_name(term).as_deref() {
        Some("utf8" | "unicode") => Ok("utf8"),
        Some("latin1") => Ok("latin1"),
        _ => Err(BADARG),
    }
}
fn atom_to_binary(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let text = atom_name(args[0]).ok_or(BADARG)?;
    let bytes = match encoding(args[1])? {
        "utf8" => text.as_bytes().to_vec(),
        _ => text
            .chars()
            .map(|c| u8::try_from(c as u32).map_err(|_| BADARG))
            .collect::<Result<Vec<_>, _>>()?,
    };
    Ok(TermBuilder::new(&mut Heap(ctx.heap))
        .binary(&bytes)
        .expect("infallible BIF heap"))
}
pub(super) fn binary_bytes(term: Term) -> Result<Vec<u8>, BifError> {
    Ok(binary_input(term)?.as_ref().to_vec())
}
fn binary_input<'a>(term: Term) -> Result<std::borrow::Cow<'a, [u8]>, BifError> {
    // SAFETY: The binary and its off-heap owner remain live for this call.
    let view = unsafe { term.binary_ref() }.ok_or(BADARG)?;
    if view.bit_len() % 8 != 0 {
        return Err(BADARG);
    }
    if view.start_bit().is_multiple_of(8) {
        let start = view.start_bit() / 8;
        let len = view.bit_len() / 8;
        // SAFETY: the process heap and retained binary owner outlive this BIF
        // call; the checked range is inside the initialized binary backing.
        Ok(std::borrow::Cow::Borrowed(unsafe {
            std::slice::from_raw_parts(view.bytes().as_ptr().add(start), len)
        }))
    } else {
        let offset = view.start_bit() % 8;
        let bytes = view.bytes();
        let mut aligned = Vec::with_capacity(view.bit_len() / 8);
        for index in 0..view.bit_len() / 8 {
            let byte = view.start_bit() / 8 + index;
            aligned.push((bytes[byte] << offset) | (bytes[byte + 1] >> (8 - offset)));
        }
        Ok(std::borrow::Cow::Owned(aligned))
    }
}
fn binary_to_atom_inner(args: &[Term], existing: bool) -> Result<Term, BifError> {
    let bytes = binary_bytes(args[0])?;
    let text = match encoding(args[1])? {
        "utf8" => std::str::from_utf8(&bytes).map_err(|_| BADARG)?.to_owned(),
        _ => bytes.into_iter().map(char::from).collect(),
    };
    intern(&text, existing)
}
fn binary_to_atom(_: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    binary_to_atom_inner(args, false)
}
fn binary_to_existing_atom(_: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    binary_to_atom_inner(args, true)
}
fn float_opts(args: &[Term]) -> Result<arinsal_float::FloatFormatOpts, BifError> {
    let mut opts = arinsal_float::FloatFormatOpts::default();
    if args.len() == 1 {
        return Ok(opts);
    }
    for entry in list(args[1])? {
        if let Some(name) = atom_name(entry) {
            match name.as_ref() {
                "compact" => opts.compact = true,
                "short" => opts.notation = arinsal_float::FloatNotation::Short,
                _ => return Err(BADARG),
            }
        } else {
            let pair = tuple(entry)?;
            if pair.len() != 2 {
                return Err(BADARG);
            }
            let count = pair[1]
                .as_small()
                .and_then(|n| u16::try_from(n).ok())
                .ok_or(BADARG)?;
            opts.notation = match atom_name(pair[0]).as_deref() {
                Some("decimals") => arinsal_float::FloatNotation::Decimals(count),
                Some("scientific") => arinsal_float::FloatNotation::Scientific(count),
                _ => return Err(BADARG),
            };
        }
    }
    Ok(opts)
}
fn formatted_float(args: &[Term]) -> Result<String, BifError> {
    // SAFETY: The float's heap remains live during this BIF.
    let value = unsafe { args[0].float_ref() }.ok_or(BADARG)?.get();
    arinsal_float::float_to_list(value, &float_opts(args)?).map_err(|_| BADARG)
}
fn float_to_list(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let text = formatted_float(args)?;
    Ok(make_list(
        ctx,
        text.bytes().map(|b| Term::small(b as i64).unwrap()),
        Term::NIL,
    ))
}
fn float_to_binary(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let text = formatted_float(args)?;
    Ok(TermBuilder::new(&mut Heap(ctx.heap))
        .binary(text.as_bytes())
        .expect("infallible BIF heap"))
}
fn list_to_float(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let bytes = list(args[0])?
        .into_iter()
        .map(|t| {
            t.as_small()
                .and_then(|n| u8::try_from(n).ok())
                .ok_or(BADARG)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let value = arinsal_float::list_to_float(&bytes).map_err(|_| BADARG)?;
    Ok(TermBuilder::new(&mut Heap(ctx.heap))
        .float(value)
        .expect("infallible BIF heap"))
}
fn binary_to_float(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let value = arinsal_float::list_to_float(&binary_bytes(args[0])?).map_err(|_| BADARG)?;
    Ok(TermBuilder::new(&mut Heap(ctx.heap))
        .float(value)
        .expect("infallible BIF heap"))
}
fn integer_text(args: &[Term]) -> Result<String, BifError> {
    let base = if args.len() == 2 {
        args[1].as_small().ok_or(BADARG)?
    } else {
        10
    };
    if !(2..=36).contains(&base) {
        return Err(BADARG);
    }
    Ok(bigint(args[0])?.to_str_radix(base as u32).to_uppercase())
}
fn integer_to_list(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let text = integer_text(args)?;
    Ok(make_list(
        ctx,
        text.bytes().map(|b| Term::small(b as i64).unwrap()),
        Term::NIL,
    ))
}
fn integer_to_binary(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let text = integer_text(args)?;
    Ok(TermBuilder::new(&mut Heap(ctx.heap))
        .binary(text.as_bytes())
        .expect("infallible BIF heap"))
}
fn erlang_binary_to_list(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let bytes = binary_input(args[0])?;
    let selected = if args.len() == 3 {
        let start = args[1].as_small().ok_or(BADARG)?;
        let end = args[2].as_small().ok_or(BADARG)?;
        if start < 1 || end < start || end as usize > bytes.len() {
            return Err(BADARG);
        }
        &bytes[start as usize - 1..end as usize]
    } else {
        &bytes
    };
    byte_list(ctx, selected)
}
fn byte_list(ctx: &mut Ctx<'_>, selected: &[u8]) -> Result<Term, BifError> {
    ctx.charge_reductions(selected.len());
    if selected.is_empty() {
        return Ok(Term::NIL);
    }
    let words = selected.len().checked_mul(2).ok_or(BifError::SystemLimit)?;
    let cells = ctx.heap.alloc(words).ok_or(BifError::SystemLimit)?;
    let mut result = Term::NIL;
    for index in (0..selected.len()).rev() {
        // SAFETY: one allocation reserved two words for each indexed cons cell.
        let cell = unsafe { cells.add(index * 2) };
        let head = Term::small(i64::from(selected[index])).unwrap();
        // SAFETY: all terms are immediate or point to initialized cells in this heap.
        unsafe {
            *cell = head.raw_bits();
            *cell.add(1) = result.raw_bits();
            result = std::mem::transmute::<u64, Term>((cell as u64) | 1);
        }
    }
    Ok(result)
}
fn list_to_binary(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    if !matches!(args[0].classify(), TermKind::List | TermKind::Nil) {
        return Err(BADARG);
    }
    let bytes = iolist_bytes(args[0])?;
    ctx.charge_reductions(bytes.len());
    Ok(TermBuilder::new(&mut Heap(ctx.heap))
        .binary(&bytes)
        .expect("infallible BIF heap"))
}
fn iolist_to_binary(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let bytes = iolist_bytes(args[0])?;
    ctx.charge_reductions(bytes.len());
    Ok(TermBuilder::new(&mut Heap(ctx.heap))
        .binary(&bytes)
        .expect("infallible BIF heap"))
}
fn iolist_to_iovec(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let bytes = iolist_bytes(args[0])?;
    ctx.charge_reductions(bytes.len());
    if bytes.is_empty() {
        return Ok(Term::NIL);
    }
    let binary = TermBuilder::new(&mut Heap(ctx.heap))
        .binary(&bytes)
        .expect("infallible BIF heap");
    Ok(TermBuilder::new(&mut Heap(ctx.heap))
        .list_from_iter([binary])
        .expect("infallible BIF heap"))
}
pub(super) fn iolist_bytes(root: Term) -> Result<Vec<u8>, BifError> {
    let mut output = Vec::new();
    let mut work = vec![(root, false)];
    while let Some((term, byte_allowed)) = work.pop() {
        match term.classify() {
            TermKind::Nil => {}
            TermKind::List => {
                let (head, tail) = iolist_cons(term)?;
                work.push((tail, false));
                work.push((head, true));
            }
            TermKind::Bitstring => output.extend(binary_bytes(term)?),
            TermKind::Number if byte_allowed => output.push(
                term.as_small()
                    .and_then(|n| u8::try_from(n).ok())
                    .ok_or(BADARG)?,
            ),
            _ => return Err(BADARG),
        }
    }
    Ok(output)
}
fn iolist_cons(term: Term) -> Result<(Term, Term), BifError> {
    // SAFETY: The source heap remains live throughout the BIF call.
    unsafe { term.cons_ref() }.ok_or(BADARG)
}
fn iolist_size(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    // Port of erts/emulator/beam/erl_iolist.c:114 (generic_iolist_size), OTP-29.1.1.
    // Size queries count bitstrings directly; materializing an iolist can turn
    // a small shared term graph into a multi-gigabyte temporary buffer.
    let mut size = BigInt::from(0_u8);
    let mut work = vec![(args[0], false)];
    while let Some((term, byte_allowed)) = work.pop() {
        match term.classify() {
            TermKind::Nil => {}
            TermKind::List => {
                let (head, tail) = iolist_cons(term)?;
                work.push((tail, false));
                work.push((head, true));
            }
            TermKind::Bitstring => {
                size += BigInt::from(binary_input(term)?.len());
            }
            TermKind::Number if byte_allowed => {
                if !term.as_small().is_some_and(|n| (0..=255).contains(&n)) {
                    return Err(BADARG);
                }
                size += 1_u8;
            }
            _ => return Err(BADARG),
        }
    }
    ctx.charge_reductions(size.to_usize().unwrap_or(usize::MAX));
    TermBuilder::new(&mut Heap(ctx.heap))
        .int_from_bigint(&size)
        .map_err(|_| BifError::SystemLimit)
}
fn bitstring_to_list(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    // SAFETY: The source bitstring and owner remain live.
    let view = unsafe { args[0].binary_ref() }.ok_or(BADARG)?;
    let mut data = Vec::with_capacity(view.bit_len().div_ceil(8));
    for i in 0..view.bit_len() {
        let source = view.start_bit() + i;
        if i % 8 == 0 {
            data.push(0_u8);
        }
        let bit = (view.bytes()[source / 8] >> (7 - source % 8)) & 1;
        let last = data.last_mut().expect("byte");
        *last |= bit << (7 - i % 8);
    }
    let full = view.bit_len() / 8;
    ctx.charge_reductions(full);
    let mut values = data[..full]
        .iter()
        .map(|&b| Term::small(b as i64).unwrap())
        .collect::<Vec<_>>();
    if view.bit_len() % 8 != 0 {
        values.push(
            TermBuilder::new(&mut Heap(ctx.heap))
                .bitstring(&data[full..], view.bit_len() % 8)
                .expect("infallible BIF heap"),
        );
    }
    Ok(make_list(ctx, values, Term::NIL))
}
fn list_to_bitstring(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    if !matches!(args[0].classify(), TermKind::List | TermKind::Nil) {
        return Err(BADARG);
    }
    let mut work = vec![(args[0], false)];
    let mut data = Vec::new();
    let mut bits = 0_usize;
    while let Some((term, byte_allowed)) = work.pop() {
        match term.classify() {
            TermKind::Nil => {}
            TermKind::List => {
                // SAFETY: The input list heap remains live.
                let (head, tail) = unsafe { term.cons_ref() }.ok_or(BADARG)?;
                work.push((tail, false));
                work.push((head, true));
            }
            TermKind::Number if byte_allowed && term.as_small().is_some() => {
                let byte = u8::try_from(term.as_small().expect("checked")).map_err(|_| BADARG)?;
                for bit in 0..8 {
                    append_bit(&mut data, &mut bits, (byte >> (7 - bit)) & 1);
                }
            }
            TermKind::Bitstring => {
                // SAFETY: The input bitstring and owner remain live.
                let view = unsafe { term.binary_ref() }.ok_or(BADARG)?;
                for i in 0..view.bit_len() {
                    let at = view.start_bit() + i;
                    append_bit(
                        &mut data,
                        &mut bits,
                        (view.bytes()[at / 8] >> (7 - at % 8)) & 1,
                    );
                }
            }
            _ => return Err(BADARG),
        }
    }
    ctx.charge_reductions(data.len());
    Ok(TermBuilder::new(&mut Heap(ctx.heap))
        .bitstring(&data, bits)
        .expect("infallible BIF heap"))
}
fn append_bit(bytes: &mut Vec<u8>, length: &mut usize, bit: u8) {
    if (*length).is_multiple_of(8) {
        bytes.push(0);
    }
    *bytes.last_mut().expect("byte") |= bit << (7 - *length % 8);
    *length += 1;
}
fn range(bytes: &[u8], start: i64, length: i64) -> Result<&[u8], BifError> {
    let end = start.checked_add(length).ok_or(BADARG)?;
    let (lo, hi) = if length < 0 {
        (end, start)
    } else {
        (start, end)
    };
    if lo < 0 || hi < 0 {
        return Err(BADARG);
    }
    bytes.get(lo as usize..hi as usize).ok_or(BADARG)
}
fn binary_part(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let bytes = binary_bytes(args[0])?;
    let (start, len) = if args.len() == 2 {
        let pair = tuple(args[1])?;
        if pair.len() != 2 {
            return Err(BADARG);
        }
        (
            pair[0].as_small().ok_or(BADARG)?,
            pair[1].as_small().ok_or(BADARG)?,
        )
    } else {
        (
            args[1].as_small().ok_or(BADARG)?,
            args[2].as_small().ok_or(BADARG)?,
        )
    };
    Ok(TermBuilder::new(&mut Heap(ctx.heap))
        .binary(range(&bytes, start, len)?)
        .expect("infallible BIF heap"))
}
fn split_binary(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let bytes = binary_bytes(args[0])?;
    let at = args[1].as_small().ok_or(BADARG)?;
    if at < 0 || at as usize > bytes.len() {
        return Err(BADARG);
    }
    let mut heap = Heap(ctx.heap);
    let mut builder = TermBuilder::new(&mut heap);
    let left = builder
        .binary(&bytes[..at as usize])
        .expect("infallible BIF heap");
    let right = builder
        .binary(&bytes[at as usize..])
        .expect("infallible BIF heap");
    Ok(builder.tuple(&[left, right]).expect("infallible BIF heap"))
}
fn binary_first(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    integer(ctx, *binary_bytes(args[0])?.first().ok_or(BADARG)? as usize)
}
fn binary_last(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    integer(ctx, *binary_bytes(args[0])?.last().ok_or(BADARG)? as usize)
}
fn binary_at(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let bytes = binary_bytes(args[0])?;
    let index = args[1].as_small().ok_or(BADARG)?;
    if index < 0 {
        return Err(BADARG);
    }
    integer(ctx, *bytes.get(index as usize).ok_or(BADARG)? as usize)
}
fn binary_copy(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let bytes = binary_input(args[0])?;
    let count = if args.len() == 2 {
        args[1].as_small().ok_or(BADARG)?
    } else {
        1
    };
    if count < 0 {
        return Err(BADARG);
    }
    let len = bytes
        .len()
        .checked_mul(count as usize)
        .ok_or(BifError::SystemLimit)?;
    if len > (1 << 30) {
        return Err(BifError::SystemLimit);
    }
    if !ctx.heap.supports_writable_binary() {
        let mut output = Vec::with_capacity(len);
        for _ in 0..count {
            output.extend_from_slice(&bytes);
        }
        return Ok(TermBuilder::new(&mut Heap(ctx.heap))
            .binary(&output)
            .expect("infallible BIF heap"));
    }
    // vm_binparse2: one exact-size owner serves every binary:copy/2 caller.
    let result = TermBuilder::new(&mut Heap(ctx.heap))
        .writable_binary(&[], 0, len)
        .map_err(|_| BifError::SystemLimit)?;
    writable_extend_private(result, len * 8).map_err(|_| BifError::SystemLimit)?;
    // SAFETY: `result` is a fresh private writer; its source is a different term.
    let output = unsafe { writable_bytes_mut(result) }.ok_or(BifError::SystemLimit)?;
    if len > 0 && !bytes.is_empty() {
        output[..bytes.len()].copy_from_slice(&bytes);
        let mut filled = bytes.len();
        while filled < len {
            let copy = filled.min(len - filled);
            output.copy_within(0..copy, filled);
            filled += copy;
        }
    }
    writable_finalize(result);
    Ok(result)
}
fn referenced_byte_size(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    // SAFETY: The source heap and binary owner remain live.
    let view = unsafe { args[0].binary_ref() }.ok_or(BADARG)?;
    let mut bytes = view.bytes().len();
    if args[0].header().is_some_and(|header| header & 63 == 0x24) {
        // A SubBits stores its retained BinRef owner at word four; BinaryRef's
        // slice ends at the subbinary boundary and omits later backing bytes.
        // SAFETY: TermBuilder::sub_binary writes a live owner term in word four.
        let owner = unsafe { *args[0].raw_ptr().add(4) };
        let owner_ptr = (owner & !7) as *const u64;
        // SAFETY: The tagged owner points to a retained BinRef allocation.
        if unsafe { *owner_ptr } & 63 == 0x28 {
            // SAFETY: BinRef word one points to the retained Arc<Vec<u8>> data.
            let backing = unsafe { *owner_ptr.add(1) } as *const Vec<u8>;
            // SAFETY: The process heap retains this Arc for the BIF call.
            bytes = unsafe { &*backing }.len();
        }
    }
    integer(ctx, bytes)
}
fn longest_common_prefix(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let binaries = list(args[0])?
        .into_iter()
        .map(binary_bytes)
        .collect::<Result<Vec<_>, _>>()?;
    let first = binaries.first().ok_or(BADARG)?;
    let length = (0..first.len())
        .take_while(|&i| binaries.iter().all(|b| b.get(i) == first.get(i)))
        .count();
    integer(ctx, length)
}
fn longest_common_suffix(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let binaries = list(args[0])?
        .into_iter()
        .map(binary_bytes)
        .collect::<Result<Vec<_>, _>>()?;
    let first = binaries.first().ok_or(BADARG)?;
    let length = (0..first.len())
        .take_while(|&i| {
            binaries
                .iter()
                .all(|b| b.iter().rev().nth(i) == first.iter().rev().nth(i))
        })
        .count();
    integer(ctx, length)
}
fn patterns(term: Term) -> Result<Vec<Vec<u8>>, BifError> {
    let source = if let Ok(compiled) = tuple(term) {
        if compiled.len() != 2 {
            return Err(BADARG);
        }
        let tag = atom_name(compiled[0]).ok_or(BADARG)?;
        if tag.as_ref() != "bm" && tag.as_ref() != "ac" {
            return Err(BADARG);
        }
        compiled[1]
    } else {
        term
    };
    let candidates = if source.classify() == TermKind::Bitstring {
        vec![source]
    } else {
        list(source)?
    };
    if candidates.is_empty() {
        return Err(BADARG);
    }
    let mut result = Vec::new();
    for candidate in candidates {
        let bytes = binary_bytes(candidate)?;
        if bytes.is_empty() {
            return Err(BADARG);
        }
        result.push(bytes);
    }
    Ok(result)
}
fn compile_pattern(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    patterns(args[0])?;
    let tag = if args[0].classify() == TermKind::Bitstring {
        "bm"
    } else {
        "ac"
    };
    let atom = Term::atom(global_atoms().intern(tag).expect("atom"));
    Ok(tuple_build(ctx, &[atom, args[0]]))
}
fn match_scope(len: usize, options: Term) -> Result<(usize, usize), BifError> {
    let mut scope = (0, len);
    for option in list(options)? {
        scope = scope_option(len, option)?;
    }
    Ok(scope)
}
fn scope_option(len: usize, option: Term) -> Result<(usize, usize), BifError> {
    let pair = tuple(option)?;
    if pair.len() != 2 || atom_name(pair[0]).as_deref() != Some("scope") {
        return Err(BADARG);
    }
    let range = tuple(pair[1])?;
    if range.len() != 2 {
        return Err(BADARG);
    }
    let start = range[0].as_small().ok_or(BADARG)?;
    let length = range[1].as_small().ok_or(BADARG)?;
    let end = start.checked_add(length).ok_or(BADARG)?;
    let (lo, hi) = if length < 0 {
        (end, start)
    } else {
        (start, end)
    };
    if lo < 0 || hi < 0 || hi as usize > len {
        return Err(BADARG);
    }
    Ok((lo as usize, hi as usize))
}
fn matches_in(
    bytes: &[u8],
    patterns: &[Vec<u8>],
    scope: (usize, usize),
    first_only: bool,
) -> Vec<(usize, usize)> {
    crate::binary_mod::matches_in(bytes, patterns, scope, first_only)
}
fn match_result(ctx: &mut Ctx<'_>, position: usize, length: usize) -> Result<Term, BifError> {
    let pos = integer(ctx, position)?;
    let len = integer(ctx, length)?;
    Ok(tuple_build(ctx, &[pos, len]))
}
fn binary_match(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let subject = binary_input(args[0])?;
    let bytes = subject.as_ref();
    let patterns = patterns(args[1])?;
    let scope = if args.len() == 3 {
        match_scope(bytes.len(), args[2])?
    } else {
        (0, bytes.len())
    };
    match matches_in(bytes, &patterns, scope, true).first() {
        Some(&(pos, len)) => match_result(ctx, pos, len),
        None => Ok(Term::atom(global_atoms().intern("nomatch").expect("atom"))),
    }
}
fn binary_matches(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let subject = binary_input(args[0])?;
    let bytes = subject.as_ref();
    let patterns = patterns(args[1])?;
    let scope = if args.len() == 3 {
        match_scope(bytes.len(), args[2])?
    } else {
        (0, bytes.len())
    };
    let mut values = Vec::new();
    for (pos, len) in matches_in(bytes, &patterns, scope, false) {
        values.push(match_result(ctx, pos, len)?);
    }
    Ok(make_list(ctx, values, Term::NIL))
}
fn split_options(
    len: usize,
    options: Term,
) -> Result<(bool, bool, bool, (usize, usize)), BifError> {
    let mut global = false;
    let mut trim = false;
    let mut trim_all = false;
    let mut scope = (0, len);
    for option in list(options)? {
        match atom_name(option).as_deref() {
            Some("global") => global = true,
            Some("trim") => trim = true,
            Some("trim_all") => trim_all = true,
            _ => {
                scope = scope_option(len, option)?;
            }
        }
    }
    Ok((global, trim, trim_all, scope))
}
fn binary_split(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let subject = binary_input(args[0])?;
    let bytes = subject.as_ref();
    let patterns = patterns(args[1])?;
    let (global, trim, trim_all, scope) = if args.len() == 3 {
        split_options(bytes.len(), args[2])?
    } else {
        (false, false, false, (0, bytes.len()))
    };
    let mut parts = Vec::new();
    let mut previous = 0;
    for (pos, len) in matches_in(bytes, &patterns, scope, !global) {
        parts.push(&bytes[previous..pos]);
        previous = pos + len;
    }
    parts.push(&bytes[previous..]);
    if trim_all {
        parts.retain(|part| !part.is_empty());
    } else if trim {
        while parts.last().is_some_and(|part| part.is_empty()) {
            parts.pop();
        }
    }
    let mut values = Vec::with_capacity(parts.len());
    for part in parts {
        values.push(
            TermBuilder::new(&mut Heap(ctx.heap))
                .binary(part)
                .expect("infallible BIF heap"),
        );
    }
    Ok(make_list(ctx, values, Term::NIL))
}
fn byte_order(args: &[Term]) -> Result<bool, BifError> {
    if args.len() == 1 {
        return Ok(false);
    }
    match atom_name(args[1]).as_deref() {
        Some("big") => Ok(false),
        Some("little") => Ok(true),
        _ => Err(BADARG),
    }
}
pub(super) fn bigint(term: Term) -> Result<BigInt, BifError> {
    if let Some(n) = term.as_small() {
        return Ok(BigInt::from(n));
    }
    // SAFETY: The number heap remains live for this call.
    unsafe { term.big_ref() }
        .map(|view| view.to_bigint())
        .ok_or(BADARG)
}
fn encode_unsigned(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let value = bigint(args[0])?;
    if value.sign() == Sign::Minus {
        return Err(BADARG);
    }
    let mut bytes = value.to_bytes_be().1;
    if bytes.is_empty() {
        bytes.push(0);
    }
    if byte_order(args)? {
        bytes.reverse();
    }
    Ok(TermBuilder::new(&mut Heap(ctx.heap))
        .binary(&bytes)
        .expect("infallible BIF heap"))
}
fn decode_unsigned(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let mut bytes = binary_bytes(args[0])?;
    if byte_order(args)? {
        bytes.reverse();
    }
    let value = BigInt::from_bytes_be(Sign::Plus, &bytes);
    TermBuilder::new(&mut Heap(ctx.heap))
        .int_from_bigint(&value)
        .map_err(|_| BifError::SystemLimit)
}

macro_rules! predicate {
    ($name:ident, $body:expr) => {
        fn $name(_: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
            Ok(bool_term($body(args[0])))
        }
    };
}
predicate!(is_atom, |t: Term| t.classify() == TermKind::Atom);
predicate!(is_list, |t: Term| matches!(
    t.classify(),
    TermKind::List | TermKind::Nil
));
predicate!(is_tuple, |t: Term| t.classify() == TermKind::Tuple);
predicate!(is_float, |t: Term| t.classify() == TermKind::Number
    && t.as_small().is_none()
    && {
        // SAFETY: A live boxed number can be queried through its typed view.
        unsafe { t.float_ref() }.is_some()
    });
predicate!(is_integer, |t: Term| t.as_small().is_some() || {
    // SAFETY: A live boxed number can be queried through its typed view.
    unsafe { t.big_ref() }.is_some()
});
predicate!(is_number, |t: Term| t.classify() == TermKind::Number);
predicate!(is_pid, |t: Term| t.classify() == TermKind::Pid);
predicate!(is_port, |t: Term| t.classify() == TermKind::Port);
predicate!(is_reference, |t: Term| t.classify() == TermKind::Ref);
predicate!(is_bitstring, |t: Term| t.classify() == TermKind::Bitstring);
predicate!(is_binary, |t: Term| {
    // SAFETY: The source heap and binary owner remain live.
    unsafe { t.binary_ref() }.is_some_and(|b| b.bit_len() % 8 == 0)
});
predicate!(
    is_boolean,
    |t: Term| matches!(t.as_atom(), Some(a) if a == atoms::TRUE || a == atoms::FALSE)
);
predicate!(is_map, |t: Term| t.classify() == TermKind::Map);

fn is_integer_range(_: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    // Port of erts/emulator/beam/erl_bif_guard.c:337 (is_integer_3), OTP-29.1.1.
    let lower = bigint(args[1])?;
    let upper = bigint(args[2])?;
    Ok(bool_term(
        bigint(args[0]).is_ok_and(|value| lower <= value && value <= upper),
    ))
}
fn is_function(_: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    if args.len() == 1 {
        return Ok(bool_term(args[0].classify() == TermKind::Fun));
    }
    let arity = args[1].as_small().ok_or(BADARG)?;
    if !(0..=255).contains(&arity) {
        return Err(BADARG);
    }
    if args[0].classify() != TermKind::Fun {
        return Ok(bool_term(false));
    }
    // SAFETY: The source fun and its retained entry remain live for the call.
    let view = unsafe { args[0].fun_ref() }.ok_or(BADARG)?;
    let actual = match view {
        arinsal_term::FunRef::Local { entry, .. } => entry.arity,
        arinsal_term::FunRef::Export { entry } => entry.arity,
    };
    Ok(bool_term(actual as i64 == arity))
}
fn is_record(_: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    if args.len() == 1 {
        return Ok(bool_term(args[0].classify() == TermKind::Record));
    }
    if args[1].as_atom().is_none() {
        return Err(BADARG);
    }
    let arity = if args.len() == 3 {
        if args[2].classify() == TermKind::Number && args[2].as_small().is_none() {
            return Err(BADARG);
        }
        Some(args[2].as_small())
    } else {
        None
    };
    let Ok(values) = tuple(args[0]) else {
        return Ok(bool_term(false));
    };
    Ok(bool_term(
        !values.is_empty()
            && values[0] == args[1]
            && arity.is_none_or(|n| n == Some(values.len() as i64)),
    ))
}
fn cmp_term(_: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    // Port of erts/emulator/beam/bif.c:5417-5427 and erl_utils.h:122, OTP-29.1.1.
    let order = arinsal_term::cmp_exact(args[0], args[1]);
    let n = match order {
        Ordering::Less => -1,
        Ordering::Equal => 0,
        Ordering::Greater => 1,
    };
    Ok(Term::small(n).expect("small comparison"))
}
/// Port of erts/emulator/beam/beam_debug.c:170-193 (erts_debug_copy_shared_2), OTP-29.1.1.
fn debug_copy_shared(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    if args[1] != Term::atom(global_atoms().intern("true").expect("built-in atom"))
        && args[1] != Term::atom(global_atoms().intern("false").expect("built-in atom"))
    {
        return Err(BifError::BADARG);
    }
    copy_term(args[0], ctx.heap).map_err(|_| BifError::SystemLimit)
}
fn debug_flat_size(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    integer(ctx, flat_size(args[0]))
}
fn debug_same(_: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    Ok(bool_term(args[0] == args[1]))
}
fn bin_is_7bit(_: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    Ok(bool_term(
        binary_bytes(args[0]).is_ok_and(|bytes| bytes.iter().all(u8::is_ascii)),
    ))
}
fn map_entries(ctx: &mut Ctx<'_>, term: Term) -> Result<Vec<(Term, Term)>, BifError> {
    if term.classify() != TermKind::Map {
        let reason = tuple_build(
            ctx,
            &[
                Term::atom(global_atoms().intern("badmap").expect("atom")),
                term,
            ],
        );
        return Err(BifError::Error(reason));
    }
    // SAFETY: The source map heap remains live and stable.
    unsafe { term.flatmap_ref() }
        .map(|map| map.iter().collect())
        .ok_or(BADARG)
}
fn map_size(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let len = map_entries(ctx, args[0])?.len();
    integer(ctx, len)
}
fn is_map_key(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    Ok(bool_term(
        map_entries(ctx, args[1])?
            .iter()
            .any(|(k, _)| exact_eq(*k, args[0])),
    ))
}
fn map_get(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    match map_entries(ctx, args[1])?
        .into_iter()
        .find(|(k, _)| exact_eq(*k, args[0]))
    {
        Some((_, value)) => Ok(value),
        None => Err(BifError::Error(tuple_build(
            ctx,
            &[
                Term::atom(global_atoms().intern("badkey").expect("atom")),
                args[0],
            ],
        ))),
    }
}
fn is_builtin(_: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let module = atom_name(args[0]).ok_or(BADARG)?;
    let name = atom_name(args[1]).ok_or(BADARG)?;
    let arity = args[2].as_small().ok_or(BADARG)?;
    if arity < 0 {
        return Err(BADARG);
    }
    Ok(bool_term(
        u8::try_from(arity)
            .ok()
            .and_then(|n| arinsal_spec::bif_lookup(&module, &name, n))
            .is_some(),
    ))
}
fn error(_: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    Err(BifError::Raise {
        class: Class::Error,
        reason: args[0],
        stacktrace: None,
    })
}
fn exit(_: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    Err(BifError::Raise {
        class: Class::Exit,
        reason: args[0],
        stacktrace: None,
    })
}
fn throw(_: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    Err(BifError::Raise {
        class: Class::Throw,
        reason: args[0],
        stacktrace: None,
    })
}
fn raise(_: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let invalid = || Term::atom(global_atoms().intern("badarg").expect("atom"));
    let class = match atom_name(args[0]).as_deref() {
        Some("error") => Class::Error,
        Some("exit") => Class::Exit,
        Some("throw") => Class::Throw,
        _ => return Ok(invalid()),
    };
    if list(args[2]).is_err() {
        return Ok(invalid());
    }
    Err(BifError::Raise {
        class,
        reason: args[1],
        stacktrace: Some(args[2]),
    })
}

fn numeric_float(term: Term) -> Result<f64, BifError> {
    if let Some(n) = term.as_small() {
        return Ok(n as f64);
    }
    // SAFETY: The source number's heap remains live during this call.
    if let Some(view) = unsafe { term.float_ref() } {
        return Ok(view.get());
    }
    // SAFETY: The source number's heap remains live during this call.
    if let Some(view) = unsafe { term.big_ref() } {
        return view.to_bigint().to_f64().ok_or(BifError::Badarith);
    }
    Err(BADARG)
}
fn abs(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    // SAFETY: The source float heap remains live during this call.
    if let Some(view) = unsafe { args[0].float_ref() } {
        return Ok(TermBuilder::new(&mut Heap(ctx.heap))
            .float(view.get().abs())
            .expect("infallible BIF heap"));
    }
    let value = bigint(args[0])?;
    let positive = if value.sign() == Sign::Minus {
        -value
    } else {
        value
    };
    TermBuilder::new(&mut Heap(ctx.heap))
        .int_from_bigint(&positive)
        .map_err(|_| BifError::SystemLimit)
}
fn to_float(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    // SAFETY: The source float heap remains live during this call.
    if unsafe { args[0].float_ref() }.is_some() {
        return Ok(args[0]);
    }
    let value = bigint(args[0])?.to_f64().ok_or(BADARG)?;
    Ok(TermBuilder::new(&mut Heap(ctx.heap))
        .float(value)
        .expect("infallible BIF heap"))
}
fn float_integer(ctx: &mut Ctx<'_>, term: Term, op: fn(f64) -> f64) -> Result<Term, BifError> {
    // SAFETY: The source float heap remains live during this call.
    let Some(view) = (unsafe { term.float_ref() }) else {
        bigint(term)?;
        return Ok(term);
    };
    let value = BigInt::from_f64(op(view.get())).ok_or(BADARG)?;
    TermBuilder::new(&mut Heap(ctx.heap))
        .int_from_bigint(&value)
        .map_err(|_| BifError::SystemLimit)
}
fn trunc(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    float_integer(ctx, args[0], f64::trunc)
}
fn round(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    float_integer(ctx, args[0], f64::round)
}
fn ceil(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    float_integer(ctx, args[0], f64::ceil)
}
fn floor(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    float_integer(ctx, args[0], f64::floor)
}
fn math_result(ctx: &mut Ctx<'_>, result: f64) -> Result<Term, BifError> {
    if !result.is_finite() {
        return Err(BifError::Badarith);
    }
    Ok(TermBuilder::new(&mut Heap(ctx.heap))
        .float(result)
        .expect("infallible BIF heap"))
}
macro_rules! math_unary {
    ($($name:ident => $method:expr),* $(,)?) => {$(
        fn $name(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
            math_result(ctx, $method(numeric_float(args[0])?))
        }
    )*};
}
// OTP's math BIFs call the platform libm. These three Rust/libm-crate
// implementations round differently on macOS, including observable last bits.
#[link(name = "m")]
unsafe extern "C" {
    fn atanh(x: f64) -> f64;
    fn erf(x: f64) -> f64;
    fn erfc(x: f64) -> f64;
}
fn c_atanh(x: f64) -> f64 {
    // SAFETY: The C math function accepts and returns a plain IEEE 754 double.
    unsafe { atanh(x) }
}
fn c_erf(x: f64) -> f64 {
    // SAFETY: The C math function accepts and returns a plain IEEE 754 double.
    unsafe { erf(x) }
}
fn c_erfc(x: f64) -> f64 {
    // SAFETY: The C math function accepts and returns a plain IEEE 754 double.
    unsafe { erfc(x) }
}
math_unary!(
    math_cos => f64::cos,
    math_cosh => f64::cosh,
    math_sin => f64::sin,
    math_sinh => f64::sinh,
    math_tan => f64::tan,
    math_tanh => f64::tanh,
    math_acos => f64::acos,
    math_acosh => f64::acosh,
    math_asin => f64::asin,
    math_asinh => f64::asinh,
    math_atan => f64::atan,
    math_atanh => c_atanh,
    math_erf => c_erf,
    math_erfc => c_erfc,
    math_exp => f64::exp,
    math_log => f64::ln,
    math_log2 => f64::log2,
    math_log10 => f64::log10,
    math_sqrt => f64::sqrt,
    math_floor => f64::floor,
    math_ceil => f64::ceil,
);
macro_rules! math_binary {
    ($($name:ident => $method:expr),* $(,)?) => {$(
        fn $name(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
            math_result(ctx, $method(numeric_float(args[0])?, numeric_float(args[1])?))
        }
    )*};
}
math_binary!(
    math_atan2 => f64::atan2,
    math_pow => f64::powf,
    math_fmod => |x: f64, y: f64| x % y,
);
