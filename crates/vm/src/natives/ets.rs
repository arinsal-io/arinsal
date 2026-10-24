//! ETS BIFs whose storage and access policy belong to the scheduled runtime.

use crate::proc_create::{EtsFree, EtsInsert, SelectStage};
use crate::process::Message;
use crate::{Process, Vm, VmError};
use arinsal_ets::match_spec::MatchDialect;
use arinsal_ets::match_spec::MatchProgram;
use arinsal_ets::{
    BigCounterOp, CounterOp, ElementLookup, EtsError, Heir, Protection, Table, TableOptions,
    TableType, Tid, WriteConcurrency,
};
use arinsal_sched::{Pid, RunCtx};
use arinsal_term::{HeapAlloc, MagicRef, Term, TermBuilder, TermKind, copy_term, global_atoms};
use num_bigint::BigInt;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

// Only atoms of the static erts table: interning others here would give them
// indices erts does not (erts creates e.g. `safe_fixed` only when it is used).
static ETS_ATOMS: LazyLock<HashMap<&'static str, arinsal_term::Atom>> = LazyLock::new(|| {
    [
        "badarg",
        "system_limit",
        "function_clause",
        "named_table",
        "set",
        "ordered_set",
        "bag",
        "duplicate_bag",
        "private",
        "protected",
        "public",
        "compressed",
        "binary",
        "keypos",
        "read_concurrency",
        "write_concurrency",
        "debug_hash_fixed_number_of_locks",
        "auto",
        "heir",
        "none",
        "decentralized_counters",
        "undefined",
        "nonode@nohost",
        "ok",
        "table",
        "trace",
        "$end_of_table",
        "ETS-TRANSFER",
        "id",
        "name",
        "type",
        "protection",
        "owner",
        "size",
        "memory",
        "node",
        "named_table",
        "true",
        "false",
    ]
    .into_iter()
    .map(|name| (name, global_atoms().intern(name).expect("built-in atom")))
    .collect()
});

// Port of erts/emulator/beam/erl_db.c (`erts_internal_ets_super_user_1`),
// OTP-29.1.1. Process currently has no ETS-specific flag word.
static ETS_SUPER_USERS: LazyLock<Mutex<HashSet<Term>>> =
    LazyLock::new(|| Mutex::new(HashSet::new()));

#[inline]
fn boolean_term(value: bool) -> Term {
    Term::atom(if value {
        arinsal_term::atoms::TRUE
    } else {
        arinsal_term::atoms::FALSE
    })
}

#[inline(always)]
fn atom(name: &'static str) -> Term {
    Term::atom(match name {
        "true" => arinsal_term::atoms::TRUE,
        "false" => arinsal_term::atoms::FALSE,
        _ => ETS_ATOMS[name],
    })
}
/// A BIF that sends or traps was called without a scheduler context; the direct path never
/// routes those, so this only guards the invariant.
fn needs_context() -> VmError {
    VmError::Unsupported("ETS BIF needs the scheduler context".into())
}
fn badarg() -> VmError {
    VmError::Trap(crate::exceptions::Trap::error(Term::atom(
        arinsal_term::atoms::BADARG,
    )))
}
thread_local! {
    /// The extended error information of the failing ETS BIF, as erts keeps it in
    /// `p->fvalue` next to `BADARG | EXF_HAS_EXT_INFO` (erl_db.c), OTP-29.1.1.
    static BIF_CAUSE: std::cell::Cell<Option<&'static str>> = const { std::cell::Cell::new(None) };
}

thread_local! {
    /// Atoms of the cause names raised so far, keyed by the literal's address. There are a few
    /// dozen causes, so a scan beats hashing on the failure path.
    static BIF_NAME_ATOMS: std::cell::RefCell<Vec<(usize, usize, arinsal_term::Atom)>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

fn bif_name_atom(name: &'static str) -> Result<arinsal_term::Atom, VmError> {
    let key = (name.as_ptr() as usize, name.len());
    if let Some(atom) = BIF_NAME_ATOMS.with(|names| {
        names
            .borrow()
            .iter()
            .find(|entry| (entry.0, entry.1) == key)
            .map(|entry| entry.2)
    }) {
        return Ok(atom);
    }
    let atom = global_atoms()
        .intern(name)
        .map_err(|_| VmError::Unsupported(format!("BIF frame atom {name}")))?;
    BIF_NAME_ATOMS.with(|names| names.borrow_mut().push((key.0, key.1, atom)));
    Ok(atom)
}

/// `badarg` with an erts `EXI_*` cause for the BIF frame's `error_info`.
fn badarg_cause(cause: &'static str) -> VmError {
    BIF_CAUSE.with(|slot| slot.set(Some(cause)));
    badarg()
}

/// Attach the failing BIF as the top stack frame, as erts does for every ETS BIF.
// Port of erts/emulator/beam/beam_common.c (save_stacktrace), OTP-29.1.1.
fn bif_frame(
    module: &'static str,
    function: &'static str,
    args: &[Term],
    result: Result<Term, VmError>,
) -> Result<Term, VmError> {
    let cause = BIF_CAUSE.with(std::cell::Cell::take);
    let Err(VmError::Trap(mut trap)) = result else {
        return result;
    };
    if trap.class == arinsal_bifs::Class::Error && trap.top.is_none() && trap.trace.is_none() {
        trap.top = Some(crate::stacktrace::TopFrame::Bif {
            module: bif_name_atom(module)?,
            function: bif_name_atom(function)?,
            args: crate::stacktrace::BifArgs::from_terms(args)?,
            info: match cause {
                Some(cause) => {
                    crate::stacktrace::BifErrorInfo::Cause(Term::atom(bif_name_atom(cause)?))
                }
                None => crate::stacktrace::BifErrorInfo::Plain,
            },
        });
    }
    Err(VmError::Trap(trap))
}

fn system_limit() -> VmError {
    VmError::Trap(crate::exceptions::Trap::error(Term::atom(
        arinsal_term::atoms::SYSTEM_LIMIT,
    )))
}
fn binary_info_err(error: EtsError) -> VmError {
    match error {
        EtsError::Term(
            arinsal_term::TermError::HeapFull | arinsal_term::TermError::SystemLimit,
        ) => system_limit(),
        error => err(error),
    }
}
fn list_next(term: Term) -> Option<(Term, Term)> {
    // SAFETY: every caller keeps the source list on the active process heap while traversing it.
    unsafe { term.cons_ref() }
}
fn advance_list(cursor: &mut Term) -> Result<Option<Term>, VmError> {
    if *cursor == Term::NIL {
        return Ok(None);
    }
    let (head, tail) = list_next(*cursor).ok_or_else(badarg)?;
    *cursor = tail;
    Ok(Some(head))
}
fn list(term: Term) -> Option<Vec<Term>> {
    let mut result = Vec::new();
    let mut tail = term;
    while tail.classify() == TermKind::List {
        let (head, next) = list_next(tail)?;
        result.push(head);
        tail = next;
    }
    (tail == Term::NIL).then_some(result)
}
fn info_item_name(term: Term) -> Option<&'static str> {
    let atom = term.as_atom()?;
    [
        "id",
        "name",
        "type",
        "keypos",
        "protection",
        "owner",
        "heir",
        "size",
        "memory",
        "stats",
        "node",
        "named_table",
        "read_concurrency",
        "write_concurrency",
        "decentralized_counters",
        "compressed",
        "binary",
        "fixed",
        "safe_fixed",
        "safe_fixed_monotonic_time",
    ]
    .into_iter()
    .find(|name| global_atoms().text(atom) == Some(*name))
}
fn end_of_table(term: Term) -> bool {
    term.as_atom() == ETS_ATOMS.get("$end_of_table").copied()
}
fn boolean(term: Term) -> Result<bool, VmError> {
    match term.as_atom() {
        Some(value) if value == arinsal_term::atoms::TRUE => Ok(true),
        Some(value) if value == arinsal_term::atoms::FALSE => Ok(false),
        _ => Err(badarg()),
    }
}
fn integer(term: Term) -> Option<BigInt> {
    if let Some(value) = term.as_small() {
        return Some(BigInt::from(value));
    }
    // SAFETY: the integer term is rooted in the active process heap.
    unsafe { term.big_ref().map(|value| value.to_bigint()) }
}
fn err(error: EtsError) -> VmError {
    match error {
        EtsError::NoTable => badarg_cause("id"),
        EtsError::BadArgCause(cause) => badarg_cause(cause),
        EtsError::BadArg | EtsError::NameTaken => badarg(),
        EtsError::Unsupported(_) => badarg(),
        // Port of erts/emulator/beam/erl_db.c: the BIF traps and runs again.
        EtsError::Busy => VmError::Yield,
        // Port of erts/emulator/beam/erl_db.c (DB_ERROR_SYSRES -> SYSTEM_LIMIT), OTP-29.1.1.
        EtsError::Term(arinsal_term::TermError::SystemLimit) => system_limit(),
        EtsError::Term(_) => badarg(),
    }
}
enum ResolveFail {
    /// Not an atom and not an ETS table reference.
    BadType,
    /// Atom or table reference that does not name a live table.
    Missing,
}

/// The registry lock held by one ETS BIF.
enum RegistryAccess<'a> {
    Shared(std::sync::RwLockReadGuard<'a, arinsal_ets::Registry>),
    Exclusive(std::sync::RwLockWriteGuard<'a, arinsal_ets::Registry>),
}

impl std::ops::Deref for RegistryAccess<'_> {
    type Target = arinsal_ets::Registry;

    fn deref(&self) -> &arinsal_ets::Registry {
        match self {
            Self::Shared(registry) => registry,
            Self::Exclusive(registry) => registry,
        }
    }
}

impl RegistryAccess<'_> {
    fn exclusive(&mut self) -> Result<&mut arinsal_ets::Registry, VmError> {
        match self {
            Self::Exclusive(registry) => Ok(registry),
            Self::Shared(_) => Err(VmError::Unsupported(
                "ETS registry change under a shared lock".into(),
            )),
        }
    }
}

enum TableGuard<'a> {
    Read(arinsal_ets::TableReadGuard<'a, arinsal_ets::Table>),
    Write(arinsal_ets::TableWriteGuard<'a, arinsal_ets::Table>),
}

impl std::ops::Deref for TableGuard<'_> {
    type Target = arinsal_ets::Table;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Read(table) => table,
            Self::Write(table) => table,
        }
    }
}

impl std::ops::DerefMut for TableGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            Self::Write(table) => table,
            Self::Read(_) => panic!("cannot mutably access a read-locked ETS table"),
        }
    }
}

// Port of erts/emulator/beam/erl_db.c (db_lock read/write modes), OTP-29.1.1.
fn table_guard<'a>(
    registry: &'a RegistryAccess<'_>,
    tid: Tid,
    shared: bool,
) -> Result<TableGuard<'a>, VmError> {
    if shared {
        Ok(TableGuard::Read(registry.get_shared(tid).map_err(err)?))
    } else {
        Ok(TableGuard::Write(registry.get_mut(tid).map_err(err)?))
    }
}

fn resolve(registry: &arinsal_ets::Registry, term: Term) -> Result<Tid, ResolveFail> {
    if let Some(tid) = Tid::from_term(term) {
        return if registry.shared(tid).is_ok() {
            Ok(tid)
        } else {
            Err(ResolveFail::Missing)
        };
    }
    if let Some(name) = term.as_atom() {
        return registry.whereis(name).ok_or(ResolveFail::Missing);
    }
    Err(ResolveFail::BadType)
}

// Port of erts/emulator/beam/erl_db.c (tid2tab) and :805-910
// (db_get_table_aux), OTP-29.1.1.
fn handle(registry: &arinsal_ets::Registry, term: Term) -> Result<Tid, VmError> {
    resolve(registry, term).map_err(|fail| match fail {
        ResolveFail::BadType => badarg_cause("type"),
        ResolveFail::Missing => badarg_cause("id"),
    })
}

/// `erlang:system_info(schedulers)`. `ets:all/0` receives exactly this many replies.
fn scheduler_count() -> usize {
    arinsal_alloc::cpuinfo::default_schedulers().0
}

/// Live tables as `ets:all/0` prints them: names for named tables, ids otherwise.
fn live_table_terms<H: HeapAlloc>(
    registry: &arinsal_ets::Registry,
    heap: &mut H,
) -> Result<Vec<Term>, VmError> {
    registry
        .all()
        .into_iter()
        .map(|tid| {
            let table = registry.get(tid).map_err(err)?;
            if table.options.named_table {
                Ok(Term::atom(table.options.name))
            } else {
                registry.tid_term(tid, heap).map_err(err)
            }
        })
        .collect()
}
#[inline(always)]
fn allowed(table: &arinsal_ets::Table, caller: Term, write: bool) -> bool {
    // Port of erts/emulator/beam/erl_db.c (db_get_table_aux), OTP-29.1.1.
    // Access depends on stored flags, not the table-wide statistics in info().
    // The cheap owner and protection tests come first; the global super-user set is the
    // last resort so ordinary calls never take its lock.
    caller == table.options.owner
        || match table.options.protection {
            Protection::Private => false,
            Protection::Protected => !write,
            Protection::Public => true,
        }
        || ETS_SUPER_USERS.lock().unwrap().contains(&caller)
}
/// A one-based element position as erts reads `signed_val(Pos)`; positions below 1
/// become 0 so the table reports `position`.
fn position(term: Term) -> Option<usize> {
    let value = term.as_small()?;
    Some(usize::try_from(value).unwrap_or(0))
}

/// Parse an update_counter `Incr | Op | [Op]` whose operands are all small integers, for
/// [`Table::update_counter_in_place`]; `None` leaves the call to the general path. The flag
/// is set when the result is a single counter rather than a list.
// Port of erts/emulator/beam/erl_db.c (do_update_counter, the UpdateOp forms),
// OTP-29.1.1.
fn small_counter_ops(
    keypos: usize,
    operation: Term,
) -> Option<(smallvec::SmallVec<[CounterOp; 4]>, bool)> {
    if let Some(increment) = operation.as_small() {
        let op = CounterOp {
            position: keypos + 1,
            increment,
            threshold: None,
        };
        return Some((smallvec::smallvec![op], true));
    }
    let parse = |entry: Term| -> Option<CounterOp> {
        let items = tuple_items(entry)?;
        let threshold = match items.as_slice() {
            [_, _] => None,
            [_, _, threshold, warp] => Some((threshold.as_small()?, warp.as_small()?)),
            _ => return None,
        };
        Some(CounterOp {
            position: position(items[0])?,
            increment: items[1].as_small()?,
            threshold,
        })
    };
    let single = operation.classify() == TermKind::Tuple;
    let mut ops = smallvec::SmallVec::new();
    if single {
        ops.push(parse(operation)?);
    } else {
        let mut rest = operation;
        while rest != Term::NIL {
            let (entry, tail) = list_next(rest)?;
            ops.push(parse(entry)?);
            rest = tail;
        }
    }
    Some((ops, single))
}

/// Return the counters of an in-place update in the shape the operation asked for.
fn counter_results<H: HeapAlloc>(
    heap: &mut H,
    values: &[Term],
    single: bool,
) -> Result<Term, VmError> {
    if single {
        values.first().copied().ok_or_else(badarg)
    } else {
        output_list_slice(heap, values)
    }
}

/// Parse `Op | [Op]` for update_element/update_counter. A malformed entry or an
/// improper tail ends the list with `None`, as the erts verification loop stops there.
fn update_list<T>(spec: Term, mut parse: impl FnMut(Term) -> Option<T>) -> Vec<Option<T>> {
    if spec.classify() == TermKind::Tuple {
        return vec![parse(spec)];
    }
    let mut parsed = Vec::new();
    let mut rest = spec;
    while rest != Term::NIL {
        // SAFETY: list cells are rooted in the caller's process heap.
        let Some((head, tail)) = (unsafe { rest.cons_ref() }) else {
            parsed.push(None);
            break;
        };
        let entry = parse(head);
        let malformed = entry.is_none();
        parsed.push(entry);
        if malformed {
            break;
        }
        rest = tail;
    }
    parsed
}

/// Check the `Default` argument of update_element/4 and update_counter/4.
// Port of erts/emulator/beam/erl_db.c and :1718-1726, OTP-29.1.1.
fn default_object(
    table: &arinsal_ets::Table,
    default: Option<Term>,
) -> Result<Option<Term>, VmError> {
    let Some(default) = default else {
        return Ok(None);
    };
    match tuple_items(default) {
        Some(items) if items.len() >= table.options.keypos => Ok(Some(default)),
        _ => Err(badarg_cause("default")),
    }
}

/// The elements of a tuple argument.
pub(crate) fn tuple_items(term: Term) -> Option<smallvec::SmallVec<[Term; 8]>> {
    // SAFETY: BIF arguments are rooted in the caller's process heap.
    let tuple = unsafe { term.tuple_ref() }?;
    Some(tuple.iter().collect())
}

fn output_list<H: HeapAlloc>(heap: &mut H, items: Vec<Term>) -> Result<Term, VmError> {
    output_list_slice(heap, &items)
}

// Port of erts/emulator/beam/erl_db.c:do_update_counter, OTP-29.1.1: reserve the result list
// once, then fill it in result order while the BIF constructs its return value.
fn output_list_slice<H: HeapAlloc>(heap: &mut H, items: &[Term]) -> Result<Term, VmError> {
    TermBuilder::new(heap)
        .list_from_slice(items)
        .map_err(|_| badarg())
}

/// Caller pid as a term; an invalid pid never reaches a BIF, so the fallback only keeps
/// the table's access check failing closed.
fn caller_of(ctx: &RunCtx<'_, Message>) -> Term {
    ctx.pid().to_term().unwrap_or(Term::NIL)
}

/// A read-mostly ETS BIF that native code runs without leaving the generated code.
///
/// Returns `None` when the call must go through the scheduler path instead (any error, so
/// the BIF frame is built there, or state the direct path does not handle); it has no
/// effect on the table in that case.
pub(crate) type DirectEts =
    fn(&mut Process, &[Term], arinsal_term::Atom, arinsal_term::Atom) -> Option<Term>;

/// Direct entry for `ets:function/arity`, if it has one.
pub(crate) fn direct_entry(module: &str, function: &str, arity: u8) -> Option<DirectEts> {
    if module == "erlang" && function == "system_info" && arity == 1 {
        return Some(direct_system_info);
    }
    if module != "ets" {
        return None;
    }
    // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:378-471 (call_light_bif), OTP-29.1.1:
    // erts calls every ETS BIF as an ordinary BIF from the generated code. Only the ones that
    // send messages or trap (give_away, request_all, delete/1, internal_delete_all) need the
    // scheduler context and keep the scheduler path.
    match (function, arity) {
        ("lookup", 2) => Some(direct_lookup),
        ("member", 2) => Some(direct_member),
        ("lookup_element", 3 | 4) => Some(direct_lookup_element),
        ("insert", 2) => Some(direct_insert),
        ("insert_new", 2) => Some(direct_insert_new),
        ("update_counter", 3 | 4) => Some(direct_update_counter),
        ("new", 2) => Some(direct_bif::<{ EtsBif::New as u8 }>),
        ("whereis", 1) => Some(direct_bif::<{ EtsBif::Whereis as u8 }>),
        ("rename", 2) => Some(direct_bif::<{ EtsBif::Rename as u8 }>),
        ("info", 1) => Some(direct_bif::<{ EtsBif::Info as u8 }>),
        ("info", 2) => Some(direct_info_2),
        ("delete", 2) => Some(direct_delete),
        ("take", 2) => Some(direct_bif::<{ EtsBif::Take as u8 }>),
        ("slot", 2) => Some(direct_bif::<{ EtsBif::Slot as u8 }>),
        ("first", 1) => Some(direct_bif::<{ EtsBif::First as u8 }>),
        ("first_lookup", 1) => Some(direct_bif::<{ EtsBif::FirstLookup as u8 }>),
        ("last", 1) => Some(direct_bif::<{ EtsBif::Last as u8 }>),
        ("last_lookup", 1) => Some(direct_bif::<{ EtsBif::LastLookup as u8 }>),
        ("next", 2) => Some(direct_bif::<{ EtsBif::Next as u8 }>),
        ("next_lookup", 2) => Some(direct_bif::<{ EtsBif::NextLookup as u8 }>),
        ("prev", 2) => Some(direct_bif::<{ EtsBif::Prev as u8 }>),
        ("prev_lookup", 2) => Some(direct_bif::<{ EtsBif::PrevLookup as u8 }>),
        ("safe_fixtable", 2) => Some(direct_bif::<{ EtsBif::SafeFixtable as u8 }>),
        ("delete_object", 2) => Some(direct_bif::<{ EtsBif::DeleteObject as u8 }>),
        ("select", 1..=3) => Some(direct_bif::<{ EtsBif::Select as u8 }>),
        ("select_reverse", 1..=3) => Some(direct_bif::<{ EtsBif::SelectReverse as u8 }>),
        ("match", 1..=3) => Some(direct_bif::<{ EtsBif::Match as u8 }>),
        ("match_object", 1..=3) => Some(direct_bif::<{ EtsBif::MatchObject as u8 }>),
        ("match_spec_compile", 1) => Some(direct_bif::<{ EtsBif::MatchSpecCompile as u8 }>),
        ("is_compiled_ms", 1) => Some(direct_bif::<{ EtsBif::IsCompiledMs as u8 }>),
        ("match_spec_run_r", 3) => Some(direct_bif::<{ EtsBif::MatchSpecRunR as u8 }>),
        ("select_count", 2) => Some(direct_bif::<{ EtsBif::SelectCount as u8 }>),
        ("internal_select_delete", 2) => Some(direct_bif::<{ EtsBif::InternalSelectDelete as u8 }>),
        ("select_replace", 2) => Some(direct_bif::<{ EtsBif::SelectReplace as u8 }>),
        ("update_element", 3 | 4) => Some(direct_bif::<{ EtsBif::UpdateElement as u8 }>),
        _ => None,
    }
}

/// Run a table BIF from the caller pid alone, once. A failure is raised from here with the
/// BIF frame, as erts' BIF returns THE_NON_VALUE with `freason` set and BeamAsm raises it.
fn direct_bif<const BIF: u8>(
    process: &mut Process,
    args: &[Term],
    module: arinsal_term::Atom,
    function_atom: arinsal_term::Atom,
) -> Option<Term> {
    let caller = process.self_pid?;
    let function = EtsBif::from_u8(BIF);
    let result = call_inner(process, None, caller, function, args);
    finish_direct(process, module, function_atom, args, result)
}

/// `ets:info/2`: the `binary` item traps to an Erlang export, which only the scheduler path runs.
// Port of erts/emulator/beam/erl_db.c (ets_info_2: BIF_TRAP1 ets_info_binary_trap),
// OTP-29.1.1.
fn direct_info_2(
    process: &mut Process,
    args: &[Term],
    module: arinsal_term::Atom,
    function: arinsal_term::Atom,
) -> Option<Term> {
    if args.get(1).copied() == Some(atom("binary")) {
        return None;
    }
    direct_bif::<{ EtsBif::Info as u8 }>(process, args, module, function)
}

/// Value of a finished direct call, or `Some` dummy with `freason` set after the failure has
/// been parked for the native exit. Never declines: the call already ran.
fn finish_direct(
    process: &mut Process,
    module: arinsal_term::Atom,
    function: arinsal_term::Atom,
    args: &[Term],
    result: Result<Term, VmError>,
) -> Option<Term> {
    // The value of a succeeded call is returned without moving the (large) error type again.
    let result = match result {
        Ok(value) => {
            BIF_CAUSE.with(std::cell::Cell::take);
            return Some(value);
        }
        Err(error) => Err(error),
    };
    match bif_register_frame(module, function, args.len(), result) {
        Ok(value) => Some(value),
        Err(VmError::Trap(trap)) => {
            let class = match trap.class {
                arinsal_bifs::Class::Error => 1,
                arinsal_bifs::Class::Exit => 2,
                arinsal_bifs::Class::Throw => 3,
            };
            let fvalue = crate::native_hooks::raw(trap.reason);
            process.header.freason = class;
            process.header.fvalue = fvalue;
            process.cold_mut().native_trap = Some(Box::new(crate::proc_create::NativeTrap {
                trap,
                freason: class,
                fvalue,
            }));
            Some(Term::NIL)
        }
        // Not an Erlang exception (yield, unsupported): redo on the scheduler path.
        Err(_) => None,
    }
}

// Port of erts/emulator/beam/beam_common.c (`save_stacktrace`), OTP-29.1.1.
/// Keeps the BIF operands in the X registers until `save_stacktrace` materializes its argument list.
#[cold]
#[inline(never)]
fn bif_register_frame(
    module: arinsal_term::Atom,
    function: arinsal_term::Atom,
    arity: usize,
    result: Result<Term, VmError>,
) -> Result<Term, VmError> {
    let cause = BIF_CAUSE.with(std::cell::Cell::take);
    let Err(VmError::Trap(mut trap)) = result else {
        return result;
    };
    if trap.class == arinsal_bifs::Class::Error && trap.top.is_none() && trap.trace.is_none() {
        let info = match cause {
            Some(cause) => {
                let cause_atom = bif_name_atom(cause)?;
                crate::stacktrace::BifErrorInfo::Cause(Term::atom(cause_atom))
            }
            None => crate::stacktrace::BifErrorInfo::Plain,
        };
        trap.top = Some(crate::stacktrace::TopFrame::BifRegisters {
            module,
            function,
            arity,
            info,
        });
    }
    Err(VmError::Trap(trap))
}

/// `erlang:system_info(scheduler_id)` from the generated code: the process knows its scheduler,
/// as erts reads `c_p->scheduler_data`. Every other item takes the scheduler path.
// Port of erts/emulator/beam/erl_bif_info.c (system_info scheduler_id), OTP-29.1.1.
fn direct_system_info(
    process: &mut Process,
    args: &[Term],
    _module: arinsal_term::Atom,
    _function: arinsal_term::Atom,
) -> Option<Term> {
    static SCHEDULER_ID: std::sync::OnceLock<Term> = std::sync::OnceLock::new();
    let scheduler_id = *SCHEDULER_ID.get_or_init(|| {
        Term::atom(
            arinsal_term::global_atoms()
                .intern("scheduler_id")
                .expect("built-in atom"),
        )
    });
    if args.first().copied() != Some(scheduler_id) || process.scheduler_id == 0 {
        return None;
    }
    Term::small(i64::from(process.scheduler_id))
}

/// `allowed(.., write = false)` for a reader whose pid term is built only when the table's
/// protection does not already grant access. Port of erts/emulator/beam/erl_db.c
/// (db_get_table_aux, DB_READ access test), OTP-29.1.1.
#[inline(always)]
fn read_allowed(table: &arinsal_ets::Table, pid: arinsal_sched::Pid) -> bool {
    match table.options.protection {
        Protection::Public | Protection::Protected => true,
        Protection::Private => pid
            .to_term()
            .is_some_and(|caller| allowed(table, caller, false)),
    }
}

/// The reader group of the calling scheduler: `erts_get_scheduler_id() - 1`.
#[inline]
fn reader_group(process: &Process) -> usize {
    match process.scheduler_id {
        0 => arinsal_term::current_reader_group(),
        id => id as usize - 1,
    }
}

fn direct_caller(process: &Process) -> Option<Term> {
    process.self_pid?.to_term()
}

/// Run `body` on the table a tid reference points at: `None` for anything but the reference
/// of a table (named tables take the name-table path). The reference thing leads to the
/// magic binary that owns the table, so no cache, hash or reference count is involved.
// Port of erts/emulator/beam/erl_db.c (db_get_table_aux): `erts_magic_ref2bin` and the
// destructor check, then `ERTS_MAGIC_BIN_DATA`, OTP-29.1.1.
#[inline(always)]
fn with_cached_table<R>(
    process: &mut Process,
    target: Term,
    body: impl FnOnce(&arinsal_ets::TableLock, &TableOptions, &mut Process) -> Option<R>,
) -> Option<R> {
    target
        .with_magic_payload::<arinsal_ets::TableLock, _>(|lock| {
            let options = lock.options();
            body(lock, &options, process)
        })
        .flatten()
}

fn direct_lookup(
    process: &mut Process,
    args: &[Term],
    module: arinsal_term::Atom,
    function: arinsal_term::Atom,
) -> Option<Term> {
    if args[0].is_magic_ref() {
        direct_lookup_cached(process, args)
            .or_else(|| direct_plain(process, args, module, function, lookup_args_member))
    } else if args[0].as_atom().is_some() {
        direct_lookup_named(process, args)
            .or_else(|| direct_plain(process, args, module, function, lookup_args_member))
    } else {
        direct_plain(process, args, module, function, lookup_args_member)
    }
}

/// Successful `ets:lookup/2` for a named table, with the same lookup, lock, and copy steps as
/// the BIF path. Errors decline to the scheduler path so it can build the proper exception.
// Port of erts/emulator/beam/erl_db.c (ets_lookup_2, db_get_table_aux), OTP-29.1.1.
fn direct_lookup_named(process: &mut Process, args: &[Term]) -> Option<Term> {
    let name = args[0].as_atom()?;
    let pid = process.self_pid?;
    let group = reader_group(process);
    let rt = process.runtime.as_ref()?;
    rt.named_ets
        .with_table(name, |shared| {
            let table = shared.read_at(group);
            if table.is_detached()
                || !table.options.named_table
                || table.options.name != name
                || table.is_busy()
                || !read_allowed(&table, pid)
            {
                return None;
            }
            let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
            table.lookup_list_at(args[1], group, &mut heap).ok()
        })
        .flatten()
}

/// `lookup`/`member`/`insert`/`insert_new` through the registry, for named tables and
/// anything the cached path declines.
fn direct_plain(
    process: &mut Process,
    args: &[Term],
    module: arinsal_term::Atom,
    function: arinsal_term::Atom,
    run: fn(&mut Process, Term, Term, Term) -> Result<Term, VmError>,
) -> Option<Term> {
    let caller = direct_caller(process)?;
    let result = run(process, caller, args[0], args[1]);
    finish_direct(process, module, function, args, result)
}

fn lookup_args_member(
    process: &mut Process,
    caller: Term,
    target: Term,
    key: Term,
) -> Result<Term, VmError> {
    lookup_args(process, caller, false, target, key)
}

fn direct_lookup_cached(process: &mut Process, args: &[Term]) -> Option<Term> {
    let pid = process.self_pid?;
    let key = args[1];
    let group = reader_group(process);
    with_cached_table(process, args[0], |shared, _options, process| {
        let table = shared.read_at(group);
        if table.is_detached() || table.is_busy() || !read_allowed(&table, pid) {
            return None;
        }
        let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
        // Port of erts/emulator/beam/erl_db_hash.c (db_get_hash) and
        // erl_db_tree.c (db_get_tree), OTP-29.1.1: a set holds at most one object,
        // consed straight onto the process heap.
        table.lookup_list_at(key, group, &mut heap).ok()
    })
}

fn direct_member(
    process: &mut Process,
    args: &[Term],
    module: arinsal_term::Atom,
    function: arinsal_term::Atom,
) -> Option<Term> {
    direct_member_cached(process, args).or_else(|| {
        direct_plain(
            process,
            args,
            module,
            function,
            |process, caller, target, key| lookup_args(process, caller, true, target, key),
        )
    })
}

fn direct_member_cached(process: &mut Process, args: &[Term]) -> Option<Term> {
    let pid = process.self_pid?;
    let key = args[1];
    let group = reader_group(process);
    with_cached_table(process, args[0], |shared, _options, _| {
        let table = shared.read_at(group);
        if table.is_detached() || table.is_busy() || !read_allowed(&table, pid) {
            return None;
        }
        Some(boolean_term(table.member_at(key, group)))
    })
}

/// `ets:lookup_element/3,4` through a stable table handle and the table's native read lock.
// Port of erts/emulator/beam/erl_db.c (ets_lookup_element_3/4), OTP-29.1.1.
fn direct_lookup_element(
    process: &mut Process,
    args: &[Term],
    module: arinsal_term::Atom,
    function: arinsal_term::Atom,
) -> Option<Term> {
    direct_lookup_element_hit(process, args)
        .or_else(|| direct_lookup_element_cached(process, args, module, function))
        .or_else(|| direct_bif::<{ EtsBif::LookupElement as u8 }>(process, args, module, function))
}

/// The successful `lookup_element/3` of a set-like table, without a `Result` or an exception
/// frame. Any failure declines, and the general path repeats the lookup and raises.
// Port of erts/emulator/beam/erl_db.c (ets_lookup_element_3), OTP-29.1.1.
fn direct_lookup_element_hit(process: &mut Process, args: &[Term]) -> Option<Term> {
    if args.len() != 3 {
        return None;
    }
    let pid = process.self_pid?;
    let (key, position) = (args[1], usize::try_from(args[2].as_small()?).ok()?);
    let group = reader_group(process);
    with_cached_table(process, args[0], |shared, _, process| {
        let table = shared.read_at(group);
        if table.is_detached()
            || table.is_busy()
            || !read_allowed(&table, pid)
            || matches!(
                table.options.table_type,
                TableType::Bag | TableType::DuplicateBag
            )
        {
            return None;
        }
        let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
        table
            .lookup_element_one_at(key, position, group, &mut heap)
            .ok()
    })
}

fn direct_lookup_element_cached(
    process: &mut Process,
    args: &[Term],
    module: arinsal_term::Atom,
    function: arinsal_term::Atom,
) -> Option<Term> {
    let caller = direct_caller(process)?;
    let group = reader_group(process);
    let (target, key, position, default) = (args[0], args[1], args[2], args.get(3).copied());
    let result = if target.is_magic_ref() {
        with_cached_table(process, target, |shared, _, process| {
            let table = shared.read_at(group);
            if table.is_detached() || table.is_busy() {
                return None;
            }
            let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
            Some(lookup_element_locked(
                &table, group, caller, key, position, default, &mut heap,
            ))
        })
    } else if let Some(name) = target.as_atom() {
        let rt = process.runtime.as_ref()?;
        match rt.named_ets.with_table(name, |shared| {
            let table = shared.read_at(group);
            if table.is_detached() || !table.options.named_table || table.options.name != name {
                return Some(Err(badarg_cause("id")));
            }
            if table.is_busy() {
                return None;
            }
            let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
            Some(lookup_element_locked(
                &table, group, caller, key, position, default, &mut heap,
            ))
        }) {
            Some(result) => result,
            None => Some(Err(badarg_cause("id"))),
        }
    } else {
        None
    };
    result.and_then(|result| finish_direct(process, module, function, args, result))
}

fn direct_insert(
    process: &mut Process,
    args: &[Term],
    module: arinsal_term::Atom,
    function: arinsal_term::Atom,
) -> Option<Term> {
    direct_insert_cached(process, args).or_else(|| {
        direct_plain(
            process,
            args,
            module,
            function,
            |process, caller, target, objects| {
                insert_args(process, None, caller, false, target, objects)
            },
        )
    })
}

fn direct_insert_new(
    process: &mut Process,
    args: &[Term],
    module: arinsal_term::Atom,
    function: arinsal_term::Atom,
) -> Option<Term> {
    direct_insert_new_cached(process, args).or_else(|| {
        direct_plain(
            process,
            args,
            module,
            function,
            |process, caller, target, objects| {
                insert_args(process, None, caller, true, target, objects)
            },
        )
    })
}

/// `ets:delete/2` through the table lock and the storage's key-level write lock.
// Port of erts/emulator/beam/erl_db.c (ets_delete_2), OTP-29.1.1.
fn direct_delete(
    process: &mut Process,
    args: &[Term],
    module: arinsal_term::Atom,
    function: arinsal_term::Atom,
) -> Option<Term> {
    direct_delete_cached(process, args, module, function)
        .or_else(|| direct_bif::<{ EtsBif::Delete as u8 }>(process, args, module, function))
}

fn direct_delete_cached(
    process: &mut Process,
    args: &[Term],
    module: arinsal_term::Atom,
    function: arinsal_term::Atom,
) -> Option<Term> {
    let caller = direct_caller(process)?;
    let group = reader_group(process);
    let target = args[0];
    let key = args[1];
    let result = if target.is_magic_ref() {
        with_cached_table(process, target, |shared, options, _| {
            direct_delete_from_shared(shared, group, options, caller, key, None)
        })
    } else if let Some(name) = target.as_atom() {
        let rt = process.runtime.as_ref()?;
        rt.named_ets
            .with_table(name, |shared| {
                direct_delete_from_shared(shared, group, &shared.options(), caller, key, Some(name))
            })
            .flatten()
    } else {
        None
    };
    result.and_then(|result| finish_direct(process, module, function, args, Ok(result)))
}

fn direct_delete_from_shared(
    shared: &arinsal_ets::TableLock,
    group: usize,
    options: &TableOptions,
    caller: Term,
    key: Term,
    name: Option<arinsal_term::Atom>,
) -> Option<Term> {
    if options.write_concurrency != WriteConcurrency::Disabled {
        let table = shared.read_at(group);
        if table.is_detached()
            || name.is_some_and(|name| !table.options.named_table || table.options.name != name)
            || table.is_busy()
            || !allowed(&table, caller, true)
        {
            return None;
        }
        let deleted = table.delete_key_shared(key);
        drop(table);
        if deleted {
            return Some(atom("true"));
        }
    }
    let mut table = shared.write();
    if table.is_detached()
        || name.is_some_and(|name| !table.options.named_table || table.options.name != name)
        || table.is_busy()
        || !allowed(&table, caller, true)
    {
        return None;
    }
    table.delete_key(key);
    Some(atom("true"))
}

fn direct_insert_cached(process: &mut Process, args: &[Term]) -> Option<Term> {
    direct_insert_one_cached(process, args, false)
}

fn direct_insert_new_cached(process: &mut Process, args: &[Term]) -> Option<Term> {
    direct_insert_one_cached(process, args, true)
}

// Port of erts/emulator/beam/erl_db.c (ets_insert_2/insert_new_2), OTP-29.1.1.
fn direct_insert_one_cached(
    process: &mut Process,
    args: &[Term],
    insert_new: bool,
) -> Option<Term> {
    if args[1].classify() != TermKind::Tuple {
        return None;
    }
    let caller = direct_caller(process)?;
    let group = reader_group(process);
    let object = args[1];
    let target = args[0];
    if target.is_magic_ref() {
        with_cached_table(process, target, |shared, options, _| {
            direct_insert_one_from_shared(shared, group, options, caller, None, object, insert_new)
        })
    } else if let Some(name) = target.as_atom() {
        let rt = process.runtime.as_ref()?;
        rt.named_ets
            .with_table(name, |shared| {
                direct_insert_one_from_shared(
                    shared,
                    group,
                    &shared.options(),
                    caller,
                    Some(name),
                    object,
                    insert_new,
                )
            })
            .flatten()
    } else {
        None
    }
}

// Port of erts/emulator/beam/erl_db.c and erl_db_hash.c, OTP-29.1.1.
fn direct_insert_one_from_shared(
    shared: &arinsal_ets::TableLock,
    group: usize,
    options: &TableOptions,
    caller: Term,
    name: Option<arinsal_term::Atom>,
    object: Term,
    insert_new: bool,
) -> Option<Term> {
    if options.write_concurrency != WriteConcurrency::Disabled {
        let table = shared.read_at(group);
        if table.is_detached()
            || name.is_some_and(|name| !table.options.named_table || table.options.name != name)
            || table.is_busy()
            || !allowed(&table, caller, true)
        {
            return None;
        }
        return table
            .insert_term_shared(object, insert_new)
            .ok()
            .map(boolean_term);
    }

    let mut table = shared.write();
    if table.is_detached()
        || name.is_some_and(|name| !table.options.named_table || table.options.name != name)
        || table.is_busy()
        || !allowed(&table, caller, true)
    {
        return None;
    }
    let inserted = table.insert_term(object, insert_new).ok()?;
    Some(boolean_term(inserted))
}

/// `ets:update_counter/3,4` on small counters, updated in place under the table lock.
// Port of erts/emulator/beam/erl_db.c (do_update_counter, ets_update_counter_3/4),
// OTP-29.1.1.
fn direct_update_counter(
    process: &mut Process,
    args: &[Term],
    module: arinsal_term::Atom,
    function: arinsal_term::Atom,
) -> Option<Term> {
    direct_update_counter_cached(process, args, module, function)
        .or_else(|| direct_bif::<{ EtsBif::UpdateCounter as u8 }>(process, args, module, function))
}

fn direct_update_counter_cached(
    process: &mut Process,
    args: &[Term],
    module: arinsal_term::Atom,
    function: arinsal_term::Atom,
) -> Option<Term> {
    let caller = direct_caller(process)?;
    let group = reader_group(process);
    let target = args[0];
    let result = if target.is_magic_ref() {
        with_cached_table(process, target, |shared, options, process| {
            direct_update_counter_from_shared(
                shared,
                group,
                options,
                caller,
                None,
                args,
                &mut process.heap,
            )
        })
    } else if let Some(name) = target.as_atom() {
        let rt = process.runtime.as_ref()?;
        match rt.named_ets.with_table(name, |shared| {
            direct_update_counter_from_shared(
                shared,
                group,
                &shared.options(),
                caller,
                Some(name),
                args,
                &mut process.heap,
            )
        }) {
            Some(result) => result,
            None => Some(Err(badarg_cause("id"))),
        }
    } else {
        None
    };
    result.and_then(|result| finish_direct(process, module, function, args, result))
}

fn direct_update_counter_from_shared(
    shared: &arinsal_ets::TableLock,
    group: usize,
    options: &TableOptions,
    caller: Term,
    name: Option<arinsal_term::Atom>,
    args: &[Term],
    heap: &mut arinsal_term::ProcessHeap,
) -> Option<Result<Term, VmError>> {
    if options.write_concurrency != WriteConcurrency::Disabled {
        let table = shared.read_at(group);
        if table.is_detached()
            || name.is_some_and(|name| !table.options.named_table || table.options.name != name)
            || table.is_busy()
        {
            return None;
        }
        let request = match counter_request(&table, caller, args) {
            Ok(Some(request)) => request,
            Ok(None) => return None,
            Err(error) => return Some(Err(error)),
        };
        let values = table.update_counter_in_place_shared(request.0, &request.1)?;
        let mut process_heap = arinsal_bifs::ProcessHeapHandle(heap);
        return Some(counter_results(&mut process_heap, &values, request.2));
    }

    let mut table = shared.write();
    if table.is_detached()
        || name.is_some_and(|name| !table.options.named_table || table.options.name != name)
        || table.is_busy()
    {
        return None;
    }
    let request = match counter_request(&table, caller, args) {
        Ok(Some(request)) => request,
        Ok(None) => return None,
        Err(error) => return Some(Err(error)),
    };
    let values = table.update_counter_in_place(request.0, &request.1)?;
    let mut process_heap = arinsal_bifs::ProcessHeapHandle(heap);
    Some(counter_results(&mut process_heap, &values, request.2))
}

/// Key, counter operations, and whether the caller asked for a single result.
type CounterRequest = (Term, smallvec::SmallVec<[CounterOp; 4]>, bool);

fn counter_request(
    table: &arinsal_ets::Table,
    caller: Term,
    args: &[Term],
) -> Result<Option<CounterRequest>, VmError> {
    if !allowed(table, caller, true) {
        return Err(badarg_cause("access"));
    }
    // ets_update_counter_4 validates Default before do_update_counter checks table type.
    if let Some(default) = args.get(3).copied()
        && tuple_items(default).is_none_or(|items| items.len() < table.options.keypos)
    {
        return Err(badarg_cause("default"));
    }
    if !matches!(
        table.options.table_type,
        TableType::Set | TableType::OrderedSet
    ) {
        return Err(badarg_cause("table_type"));
    }
    let Some((operations, single)) = small_counter_ops(table.options.keypos, args[2]) else {
        return Ok(None);
    };
    Ok(Some((args[1], operations, single)))
}

fn insert_args(
    process: &mut Process,
    ctx: Option<&mut RunCtx<'_, Message>>,
    caller: Term,
    insert_new: bool,
    target: Term,
    objects: Term,
) -> Result<Term, VmError> {
    // SAFETY: object terms remain in the caller's live process heap for this BIF.
    let single = unsafe { objects.tuple_ref() }.is_some();
    // Port of erts/emulator/beam/erl_db.c (ets_insert_2: a list of two or more
    // objects, or a trapped continuation, goes to ets_insert_2_list_driver).
    if !single
        && (process
            .cold
            .as_ref()
            .is_some_and(|cold| cold.ets_insert.is_some())
            || list_next(objects)
                .and_then(|(_, tail)| list_next(tail))
                .is_some())
    {
        // A list insert traps, which only the scheduler path can do.
        let ctx = ctx.ok_or(VmError::Yield)?;
        return insert_list(process, ctx, caller, insert_new, target, objects);
    }
    let rt = process.runtime.as_ref().ok_or_else(badarg)?;
    let registry = rt.ets.read().unwrap();
    let tid = handle(&registry, target)?;
    let shared = registry.shared(tid).map_err(err)?.clone();
    let options = shared.options();
    if single
        && options.write_concurrency != WriteConcurrency::Disabled
        && options.table_type != TableType::OrderedSet
    {
        let table = shared.read();
        if table.is_busy() {
            return Err(VmError::Yield);
        }
        if !allowed(&table, caller, true) {
            return Err(badarg_cause("access"));
        }
        let yes = table.insert_term_shared(objects, insert_new).map_err(err)?;
        return Ok(if insert_new {
            boolean_term(yes)
        } else {
            boolean_term(true)
        });
    }
    let mut table = registry.get_mut(tid).map_err(err)?;
    if !allowed(&table, caller, true) {
        return Err(badarg_cause("access"));
    }
    let yes = if single {
        if insert_new {
            table.insert_new(&[objects]).map_err(err)?
        } else {
            table.insert(&[objects]).map_err(err)?;
            true
        }
    } else {
        let items = list(objects).ok_or_else(badarg)?;
        if insert_new {
            table.insert_new(&items).map_err(err)?
        } else {
            table.insert(&items).map_err(err)?;
            true
        }
    };
    Ok(if insert_new {
        boolean_term(yes)
    } else {
        boolean_term(true)
    })
}

/// `ets:insert/2` and `ets:insert_new/2` with a list of two or more objects.
///
/// Port of erts/emulator/beam/erl_db.c (ets_insert_2_list, ets_insert_2_list_driver),
/// OTP-29.1.1. A list that fits the reductions left and is not for a bag goes in directly. Any
/// other list is first copied into table form without the table lock, then locked in and
/// inserted a slice at a time; when it does not finish, the rest is installed in the table, which
/// turns busy so that every other user helps and this process collects the result.
fn insert_list(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    caller: Term,
    insert_new: bool,
    target: Term,
    objects: Term,
) -> Result<Term, VmError> {
    const ITERATIONS_PER_RED: isize = 8;
    let rt = process.runtime.ok_or_else(badarg)?;
    let mut state = process
        .cold
        .as_mut()
        .and_then(|cold| cold.ets_insert.take());
    let initial = ctx.remaining() as isize;
    let mut loops = initial * ITERATIONS_PER_RED;
    let done = |process: &mut Process, ctx: &mut RunCtx<'_, Message>, loops: isize, yes: bool| {
        let used = (initial * ITERATIONS_PER_RED - loops) / ITERATIONS_PER_RED;
        bump_reds(process, ctx, used);
        Ok(boolean_term(yes))
    };
    if let Some(EtsInsert::Global(outcome)) = state.as_deref() {
        // The table is no longer busy (or gone): the operation completed or was aborted by
        // someone else.
        return match outcome.load(std::sync::atomic::Ordering::Acquire) {
            1 => Ok(boolean_term(true)),
            2 => Ok(boolean_term(false)),
            _ => Err(badarg_cause("id")),
        };
    }
    let registry = rt.ets.read().unwrap();
    let tid = handle(&registry, target)?;
    let shared = registry.shared(tid).map_err(err)?.clone();
    let options = shared.options();
    // Keep the table alive by its shared handle. Holding the registry lock while waiting for a
    // table writer prevents ets:delete/1 from detaching the table, unlike erts' btid reference.
    drop(registry);
    // Port of erts/emulator/beam/erl_db.c (ets_insert_2_list_check), OTP-29.1.1: the
    // check pass is a yieldable loop that takes one iteration per object.
    let check_failure = || {
        let table = shared.read();
        if table.is_detached()
            || target
                .as_atom()
                .is_some_and(|name| table.options.named_table && table.options.name != name)
        {
            err(EtsError::NoTable)
        } else if !allowed(&table, caller, true) {
            badarg_cause("access")
        } else {
            badarg()
        }
    };
    let (mut cursor, mut checked, prepared) = match state.take().map(|boxed| *boxed) {
        None => (objects, 0, None),
        Some(EtsInsert::Check { cursor, count }) => (cursor, count, None),
        Some(EtsInsert::Copy { cursor, prepared }) => (cursor, 0, Some(prepared)),
        Some(EtsInsert::Global(_)) => unreachable!("global state returned above"),
    };
    // Port of erts/emulator/beam/erl_db.c (ets_insert_2_list_check), OTP-29.1.1: the
    // check pass advances a saved list cursor, so a trap never rescans its prefix.
    if prepared.is_none() {
        while cursor.classify() == TermKind::List {
            // YCF consumes the automatic loop reduction before entering its body and yields
            // at that point when the counter reaches zero.
            loops -= 1;
            if loops <= 0 {
                process.cold_mut().ets_insert = Some(Box::new(EtsInsert::Check {
                    cursor,
                    count: checked,
                }));
                bump_reds(process, ctx, isize::MAX);
                return Err(VmError::Yield);
            }
            let object = match advance_list(&mut cursor) {
                Ok(Some(object)) => object,
                Ok(None) => unreachable!(),
                Err(_) => return Err(check_failure()),
            };
            if Table::check_object(&options, object).is_err() {
                return Err(check_failure());
            }
            checked += 1;
        }
        if cursor != Term::NIL {
            return Err(check_failure());
        }
    }
    if prepared.is_none()
        && options.table_type != TableType::Bag
        && options.table_type != TableType::DuplicateBag
        // Port of erts/emulator/beam/erl_db.c (can_insert_without_yield), OTP-29.1.1.
        && checked as isize <= loops
    {
        // Enough reductions to insert straight from the heap.
        let mut table = shared.write();
        if table.is_detached()
            || target
                .as_atom()
                .is_some_and(|name| table.options.named_table && table.options.name != name)
        {
            return Err(err(EtsError::NoTable));
        }
        if table.is_busy() {
            return Err(err(EtsError::Busy));
        }
        if !allowed(&table, caller, true) {
            return Err(badarg_cause("access"));
        }
        let mut check_cursor = objects;
        if insert_new {
            while check_cursor.classify() == TermKind::List {
                loops -= 1;
                let object = advance_list(&mut check_cursor)?.expect("list cursor checked");
                if table.member_object(object).map_err(err)? {
                    return done(process, ctx, loops, false);
                }
            }
        }
        let mut insert_cursor = objects;
        while insert_cursor.classify() == TermKind::List {
            // Port of erts/emulator/beam/erl_db.c (ets_insert_2_list_from_p_heap): the
            // generated loop consumes one reduction before db_put, which consumes at least one.
            loops -= 1;
            let object = advance_list(&mut insert_cursor)?.expect("list cursor checked");
            let prepared = Table::prepare_object(&options, object).map_err(err)?;
            let extra_reds = table.insert_prepared_counted(prepared);
            loops -= 1 + extra_reds as isize;
        }
        let yes = true;
        return done(process, ctx, loops, yes);
    }
    // erts keeps the table identity alive while copying but releases the global table registry
    // lock. A concurrent delete must be able to detach the table during this yielding phase.
    // Copy the list into table form so that other processes can help.
    let mut prepared = prepared.unwrap_or_else(|| Vec::with_capacity(checked.min(1 << 20)));
    if cursor == Term::NIL && prepared.is_empty() {
        cursor = objects;
    }
    while cursor.classify() == TermKind::List {
        // Port of erts/emulator/beam/erl_db.c (ets_insert_2_list_copy_term_list): the
        // generated loop yields before copying the current object when this consumes the slice.
        loops -= 1;
        if loops <= 0 {
            process.cold_mut().ets_insert = Some(Box::new(EtsInsert::Copy { cursor, prepared }));
            bump_reds(process, ctx, isize::MAX);
            return Err(VmError::Yield);
        }
        let object = match advance_list(&mut cursor) {
            Ok(Some(object)) => object,
            Ok(None) => unreachable!(),
            Err(_) => return Err(check_failure()),
        };
        match Table::prepare_object(&options, object) {
            Ok(object) => prepared.push(object),
            Err(error) => {
                if error == EtsError::BadArg {
                    return Err(check_failure());
                }
                return Err(err(error));
            }
        }
    }
    if cursor != Term::NIL {
        return Err(check_failure());
    }
    // Acquire the table lock independently of the registry, as in ets_insert_2_list_lock_tbl.
    let mut table = shared.write();
    if table.is_detached()
        || target
            .as_atom()
            .is_some_and(|name| table.options.named_table && table.options.name != name)
    {
        return Err(err(EtsError::NoTable));
    }
    if table.is_busy() {
        drop(table);
        process.cold_mut().ets_insert = Some(Box::new(EtsInsert::Copy { cursor, prepared }));
        return Err(err(EtsError::Busy));
    }
    if !allowed(&table, caller, true) {
        return Err(badarg_cause("access"));
    }
    let mut member_cursor = None;
    let mut destroy_copied = false;
    if insert_new {
        let mut index = 0;
        while index < prepared.len() {
            // Port of erts/emulator/beam/erl_db.c (ets_insert_new_2_dbterm_list_has_member).
            loops -= 1;
            if loops <= 0 {
                member_cursor = Some(index);
                break;
            }
            if table.member_prepared(&prepared[index]) {
                destroy_copied = true;
                break;
            }
            index += 1;
        }
    }
    let mut pending: std::collections::VecDeque<_> = prepared.into();
    if destroy_copied {
        // Port of erts/emulator/beam/erl_db.c (ets_insert_2_list_destroy_copied_dbterms):
        // copied objects are released by a yieldable loop after insert_new finds a key.
        table.destroy_prepared_batch(&mut pending, &mut loops);
    } else if member_cursor.is_none() {
        table.insert_prepared_batch(&mut pending, &mut loops);
    }
    if pending.is_empty() && loops > 0 {
        return done(process, ctx, loops, !destroy_copied);
    }
    let outcome: arinsal_ets::InsertOutcome = Default::default();
    table.begin_busy_insert_list(
        pending,
        member_cursor,
        destroy_copied,
        std::sync::Arc::clone(&outcome),
    );
    process.cold_mut().ets_insert = Some(Box::new(EtsInsert::Global(outcome)));
    bump_reds(process, ctx, isize::MAX);
    Err(VmError::Yield)
}

fn lookup_args(
    process: &mut Process,
    caller: Term,
    member: bool,
    target: Term,
    key: Term,
) -> Result<Term, VmError> {
    let group = reader_group(process);
    let rt = process.runtime.as_ref().ok_or_else(badarg)?;
    if let Some(name) = target.as_atom() {
        // Port of erts/emulator/beam/erl_db.c (db_get_table_aux), OTP-29.1.1.
        // Keep the atom-hashed snapshot alive across the table lock instead of cloning its Arc.
        let lookup = rt.named_ets.with_table(name, |shared| {
            let table = shared.read_at(group);
            if table.is_detached() || !table.options.named_table || table.options.name != name {
                return Err(badarg_cause("id"));
            }
            if table.is_busy() {
                return Err(err(arinsal_ets::EtsError::Busy));
            }
            if !allowed(&table, caller, false) {
                return Err(badarg_cause("access"));
            }
            if member {
                return Ok(boolean_term(table.member_at(key, group)));
            }
            let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
            table.lookup_list_at(key, group, &mut heap).map_err(err)
        });
        return lookup.unwrap_or_else(|| Err(badarg_cause("id")));
    }

    let registry = rt.ets.read().unwrap();
    let tid = handle(&registry, target)?;
    let table = registry.get_shared(tid).map_err(err)?;
    if !allowed(&table, caller, false) {
        return Err(badarg_cause("access"));
    }
    if member {
        Ok(boolean_term(table.member(key)))
    } else {
        let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
        table.lookup_list(key, &mut heap).map_err(err)
    }
}

fn lookup_element_locked(
    table: &arinsal_ets::Table,
    group: usize,
    caller: Term,
    key: Term,
    position: Term,
    default: Option<Term>,
    heap: &mut arinsal_bifs::ProcessHeapHandle<'_>,
) -> Result<Term, VmError> {
    if !allowed(table, caller, false) {
        return Err(badarg_cause("access"));
    }
    // Port of erts/emulator/beam/erl_db.c ets_lookup_element_3: the table is looked up and its
    // access checked before the position is validated.
    let position =
        usize::try_from(position.as_small().ok_or_else(badarg)?).map_err(|_| badarg())?;
    if default.is_none()
        && !matches!(
            table.options.table_type,
            TableType::Bag | TableType::DuplicateBag
        )
    {
        return table
            .lookup_element_one_at(key, position, group, heap)
            .map_err(err);
    }
    let Some(default) = default else {
        // Bag and duplicate_bag: the list is consed on the heap without an intermediate vector.
        return table
            .lookup_element_list_at(key, position, group, heap)
            .map_err(err);
    };
    let values = match table
        .lookup_element_default(key, position, default, heap)
        .map_err(err)?
    {
        ElementLookup::Values(values) => values,
        ElementLookup::Default(value) => return Ok(value),
    };
    if matches!(
        table.options.table_type,
        TableType::Bag | TableType::DuplicateBag
    ) {
        TermBuilder::new(heap)
            .list_from_iter(values)
            .map_err(|_| badarg())
    } else {
        values.first().copied().ok_or_else(badarg)
    }
}

/// `{Key, Objects}` as returned by `db_copy_key_and_objects_hash`.
fn lookup_pair<H: HeapAlloc>(heap: &mut H, key: Term, objects: Vec<Term>) -> Result<Term, VmError> {
    let objects = TermBuilder::new(heap)
        .list_from_iter(objects)
        .map_err(|_| badarg())?;
    TermBuilder::new(heap)
        .tuple(&[key, objects])
        .map_err(|_| badarg())
}

struct ProcessMatchContext(Term, Term, Term);
impl arinsal_ets::match_spec::MatchContext for ProcessMatchContext {
    fn self_pid(&self) -> Option<Term> {
        Some(self.0)
    }

    fn trace_control_word(&self) -> Option<Term> {
        Some(self.1)
    }

    fn trace_operation(
        &self,
        name: &str,
        _arguments: &[Term],
    ) -> Result<Term, arinsal_ets::EtsError> {
        match name {
            "get_seq_token" => Ok(self.2),
            "is_seq_trace" => Ok(if self.2 == Term::NIL {
                crate::signals::atom("false")
            } else {
                crate::signals::atom("true")
            }),
            _ => Err(arinsal_ets::EtsError::BadArg),
        }
    }
}

/// Charge `used` reductions to the process and the scheduler quantum.
///
/// Port of erts/emulator/beam/erl_bif_info.c (BUMP_REDS), OTP-29.1.1.
fn bump_reds(process: &mut Process, ctx: &mut RunCtx<'_, Message>, used: isize) {
    let used = used.clamp(0, ctx.remaining() as isize) as u32;
    process.reductions -= used as i32;
    process.reductions_used = process.reductions_used.saturating_add(u64::from(used));
    ctx.consume(used);
}

/// Charge `used` reductions from a BIF that runs from native code, where the live counter is
/// the one in the process header.
///
/// Port of erts/emulator/beam/bif.h, BUMP_REDS, OTP-29.1.1.
fn bump_direct(process: &mut Process, used: isize) {
    let used = used.clamp(0, i32::MAX as isize) as i32;
    let live = process.header.fcalls.saturating_sub(used).max(0);
    process.header.fcalls = live;
    process.reductions = live;
}

/// Whether the BIF looks its first argument up as a table (`db_get_table`), and so has to wait
/// for a busy table.
fn gated_by_busy(function: EtsBif) -> bool {
    !matches!(
        function,
        EtsBif::MatchSpecTest
            | EtsBif::SuperUser
            | EtsBif::New
            | EtsBif::Whereis
            | EtsBif::MatchSpecCompile
            | EtsBif::IsCompiledMs
            | EtsBif::MatchSpecRunR
    )
}

fn compiled_match_program(reference: Term) -> Option<Arc<MatchProgram>> {
    reference
        .magic_owner()?
        .downcast_ref::<Arc<MatchProgram>>()
        .cloned()
}

/// Help finish the operation a busy table waits for, then trap so that the BIF runs again.
///
/// Port of erts/emulator/beam/erl_db.c (handle_lacking_permission with DB_BUSY):
/// a process that finds the table busy runs the delete_all or list-insert continuation with its
/// own reductions and then retries.
fn help_busy_table(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    target: Term,
    own_list_insert: bool,
) -> Result<(), VmError> {
    let Some(rt) = process.runtime.as_ref() else {
        return Ok(());
    };
    let tid = {
        let registry = rt.ets.read().unwrap();
        match resolve(&registry, target) {
            Ok(tid) if registry.shared(tid).is_ok_and(|shared| shared.is_busy()) => tid,
            _ => return Ok(()),
        }
    };
    let rt = process.runtime.ok_or_else(badarg)?;
    let initial = ctx.remaining() as isize;
    let mut reds = initial;
    {
        let registry = rt.ets.read().unwrap();
        let Ok(shared) = registry.shared(tid) else {
            return Ok(());
        };
        let mut table = shared.write();
        if !table.continue_busy(&mut reds) {
            reds = initial + 1;
        }
    }
    bump_reds(
        process,
        ctx,
        if reds > initial {
            isize::MAX
        } else {
            initial - reds
        },
    );
    // Port of erts/emulator/beam/erl_db.c (ets_insert_2_list_continuation), OTP-29.1.1:
    // the process that started the list insert returns its result as soon as it finishes it.
    if own_list_insert && reds <= initial {
        return Ok(());
    }
    Err(VmError::Yield)
}

/// `ets:delete/1` and `ets:internal_delete_all/2`: release the storage a slice of reductions
/// at a time, trapping to the same BIF until it is all released.
///
/// Port of erts/emulator/beam/erl_db.c (ets_delete_1), :3234 (ets_internal_delete_all_2),
/// :5378 (ets_delete_trap) and :5405 (free_table_continue), OTP-29.1.1.
fn delete_or_clear(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    function: EtsBif,
    args: &[Term],
    caller: Term,
) -> Result<Term, VmError> {
    let rt = process.runtime.ok_or_else(badarg)?;
    let initial = ctx.remaining() as isize;
    let mut reds = initial;
    let mut state = process.cold.as_mut().and_then(|cold| cold.ets_free.take());
    let done = if let Some(state) = state.as_mut() {
        match state.tid {
            None => state.garbage.step(&mut reds),
            // Trapped before: the table stopped being busy (whoever finished it), so the
            // objects are gone and only the count is left to return.
            Some(_) => true,
        }
    } else if function == EtsBif::Delete {
        let mut registry = rt.ets.write().unwrap();
        let tid = handle(&registry, args[0])?;
        if !allowed(&*registry.get(tid).map_err(err)?, caller, true) {
            return Err(badarg_cause("access"));
        }
        let (garbage, fixations) = registry.detach(tid).map_err(err)?;
        drop(registry);
        reds -= fixations as isize;
        let mut fresh = EtsFree {
            tid: None,
            nitems: 0,
            garbage,
        };
        let done = fresh.garbage.step(&mut reds);
        state = Some(Box::new(fresh));
        done
    } else {
        let registry = rt.ets.read().unwrap();
        let tid = handle(&registry, args[0])?;
        let mut table = registry.get_mut(tid).map_err(err)?;
        if !allowed(&table, caller, true) {
            return Err(badarg_cause("access"));
        }
        if args[1] != atom("undefined") {
            return Err(badarg());
        }
        let nitems = table.len();
        let mut garbage = table.take_garbage(false);
        let done = table.free_garbage(&mut garbage, &mut reds);
        if !done {
            // Port of erts/emulator/beam/erl_db.c (ets_internal_delete_all_2): the
            // table turns busy and every process that meets it continues the release.
            table.begin_busy_delete_all(garbage);
        }
        state = Some(Box::new(EtsFree {
            tid: Some(tid),
            nitems,
            garbage: arinsal_ets::Garbage::empty(),
        }));
        done
    };
    let state = state.expect("delete state present");
    if !done {
        bump_reds(process, ctx, isize::MAX);
        process.cold_mut().ets_free = Some(state);
        return Err(VmError::Yield);
    }
    bump_reds(process, ctx, initial - reds);
    if function == EtsBif::Delete {
        return Ok(atom("true"));
    }
    let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
    TermBuilder::new(&mut heap)
        .int_from_i128(state.nitems as i128)
        .map_err(|_| badarg())
}

/// Fix a table for `caller`, stamping the first fixation with the current times.
///
/// Port of erts/emulator/beam/erl_db.c, fix_table_locked, OTP-29.1.1.
fn fix_table<H: HeapAlloc>(heap: &mut H, table: &mut Table, caller: Term) -> Result<(), VmError> {
    let micros = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| badarg())?
        .as_micros();
    let system_time = TermBuilder::new(heap)
        .tuple(&[
            Term::small((micros / 1_000_000_000_000) as i64).ok_or_else(badarg)?,
            Term::small(((micros / 1_000_000) % 1_000_000) as i64).ok_or_else(badarg)?,
            Term::small((micros % 1_000_000) as i64).ok_or_else(badarg)?,
        ])
        .map_err(|_| system_limit())?;
    let monotonic_time = TermBuilder::new(heap)
        .int_from_i128(arinsal_bifs::monotonic_time_nanos())
        .map_err(|_| system_limit())?;
    table
        .safe_fixtable_for_at(caller, true, system_time, monotonic_time)
        .map_err(err)
}

mod select_chunk;

/// Results of one cycle of a table traversal.
struct SelectCycle {
    /// Objects left of the budget; below zero when the last bucket ran past it.
    iterations_left: isize,
    /// Where a trapped call resumes: the slot of a hash table, or on an ordered table the key
    /// of the last object visited when the cycle stopped before the table or the range ended.
    resume: Option<arinsal_ets::ScanPosition>,
    /// The bucket a hash table's chunk filled in, as the slot after it.
    chunk_slot: Option<usize>,
    results: Vec<Term>,
    counted: usize,
    /// Results a chunked call holds once the cycle is over.
    held: usize,
}

/// What a traversal visits: the buckets of a hash table or the key range of an ordered one.
enum ScanPlan {
    Hash(arinsal_ets::HashScanPlan),
    Tree(arinsal_ets::TreeScanPlan),
}

/// What one cycle of a traversal does.
#[derive(Clone, Copy)]
struct CycleShape<'a> {
    count: bool,
    backwards: bool,
    chunk: usize,
    held: usize,
    from: Option<&'a arinsal_ets::ScanPosition>,
}

fn select_cycle<H: HeapAlloc>(
    table: &Table,
    plan: &ScanPlan,
    program: &MatchProgram,
    shape: CycleShape<'_>,
    heap: &mut H,
) -> Result<SelectCycle, EtsError> {
    use arinsal_ets::ScanPosition;
    let CycleShape {
        count,
        backwards,
        chunk,
        held,
        from,
    } = shape;
    let chunk = arinsal_ets::Chunk { size: chunk, held };
    match plan {
        ScanPlan::Hash(plan) => {
            let slot = match from {
                Some(ScanPosition::Slot(slot)) => *slot,
                _ => 0,
            };
            let (end, results, counted, held) = if count {
                let (end, counted) = table.hash_count_cycle(plan, program, slot)?;
                (end, Vec::new(), counted, 0)
            } else {
                let (end, results, held) =
                    table.hash_select_cycle(plan, program, slot, chunk, heap)?;
                (end, results, 0, held)
            };
            Ok(SelectCycle {
                iterations_left: end.iterations_left,
                resume: end.trap_slot.map(ScanPosition::Slot),
                chunk_slot: end.chunk_slot,
                results,
                counted,
                held,
            })
        }
        ScanPlan::Tree(plan) => {
            let after = match from {
                Some(ScanPosition::After(key)) => Some(key.term()),
                _ => None,
            };
            let (end, results, counted, held) = if count {
                let (end, counted) = table.tree_count_cycle(plan, program, after)?;
                (end, Vec::new(), counted, 0)
            } else if chunk.size > 0 {
                let (end, results, held) =
                    table.tree_chunk_cycle(plan, program, backwards, after, chunk, heap)?;
                (end, results, 0, held)
            } else {
                let (end, results) =
                    table.tree_select_cycle(plan, program, backwards, after, heap)?;
                (end, results, 0, 0)
            };
            Ok(SelectCycle {
                iterations_left: end.iterations_left,
                resume: end.resume_key.map(ScanPosition::After),
                chunk_slot: None,
                results,
                counted,
                held,
            })
        }
    }
}

/// What a call does with the cycle it just ran.
enum Next {
    /// The call returns its result.
    Return,
    /// The call traps and continues from the position.
    Trap(arinsal_ets::ScanPosition),
    /// An ordered table's chunk traps to `ets:reverse/3`, which returns the results and the
    /// continuation after the key, or the end of the table.
    Reverse(Option<arinsal_ets::SavedKey>),
}

/// Where a call starts.
struct Start {
    tid: Tid,
    program: Arc<MatchProgram>,
    program_owner: Arc<MagicRef>,
    count: bool,
    chunk: usize,
    backwards: bool,
    position: Option<arinsal_ets::ScanPosition>,
    got: usize,
    saved: arinsal_ets::SavedMatches,
    safety: arinsal_ets::IterSafety,
    plan: ScanPlan,
    fresh_plan: bool,
    continued: bool,
}

/// What an ordered table's chunk does after a cycle.
// Port of erts/emulator/beam/erl_db_tree.c, db_select_chunk_tree_common and
// db_select_continue_tree_common, OTP-29.1.1.
fn tree_chunk_next(
    plan: &arinsal_ets::TreeScanPlan,
    chunk: usize,
    backwards: bool,
    continued: bool,
    cycle: &mut SelectCycle,
) -> Next {
    let key = cycle.resume.take();
    let held = cycle.held;
    let finished = |held: usize| {
        if held == 0 {
            Next::Return
        } else {
            Next::Reverse(None)
        }
    };
    if cycle.iterations_left > 0 || held == chunk {
        return match key {
            Some(arinsal_ets::ScanPosition::After(key)) if held == chunk => {
                Next::Reverse(Some(key))
            }
            _ => finished(held),
        };
    }
    match key {
        Some(arinsal_ets::ScanPosition::After(key))
            if !(continued && plan.past_end(backwards, key.term())) =>
        {
            Next::Trap(arinsal_ets::ScanPosition::After(key))
        }
        _ => finished(held),
    }
}

/// `ets:select/1,2,3`, `select_reverse/2,3`, `match/1,2,3`, `match_object/1,2,3` and
/// `select_count/2`: a cycle visits up to 1000 objects, charges a reduction for each and
/// traps as `ets:select_trap/1` (`ets:count_trap/1`) on a hash table and as `ets:select/1`
/// (`ets:count_trap/1`) on an ordered one, until the table is exhausted or, for a chunk, the
/// page is full. A hash table another process may write is fixed while the call is trapped.
/// A chunk of an ordered table always traps to `ets:reverse/3`, which returns the page.
/// `Ok(None)` leaves a call that names one key of an ordered table to the caller.
///
/// Port of erts/emulator/beam/erl_db.c (ets_match_2, ets_match_3, ets_select2, ets_select3,
/// ets_select_trap_1, ets_select1, ets_select_count_2, ets_select_count_1), erl_db_hash.c
/// (match_traverse, match_traverse_continue, the select_chunk_* and select_count_*
/// callbacks, db_select_continue_hash) and erl_db_tree.c (db_select_tree_common,
/// db_select_chunk_tree_common, db_select_continue_tree_common, db_select_count_tree_common,
/// db_select_count_continue_tree_common, ets_select_reverse), OTP-29.1.1.
fn hash_select(
    process: &mut Process,
    mut ctx: Option<&mut RunCtx<'_, Message>>,
    caller_pid: Pid,
    function: EtsBif,
    args: &[Term],
) -> Result<Option<Term>, VmError> {
    use arinsal_ets::{IterSafety, ScanPosition};
    let caller = caller_pid.to_term().ok_or_else(badarg)?;
    let rt = process.runtime.ok_or_else(badarg)?;
    let count = function == EtsBif::SelectCount;
    if ctx.is_none()
        && process
            .cold
            .as_ref()
            .is_some_and(|cold| cold.ets_select.is_some())
    {
        return Err(VmError::Yield);
    }
    let resumed = process
        .cold
        .as_mut()
        .and_then(|cold| cold.ets_select.take().map(|boxed| *boxed));
    if resumed
        .as_ref()
        .is_some_and(|state| matches!(state.stage, SelectStage::Reverse { .. }))
    {
        let state = resumed.ok_or_else(badarg)?;
        return reverse_trap(process, ctx, state).map(Some);
    }
    let was_resumed = resumed.is_some();
    let items = if resumed.is_none() && args.len() == 1 {
        if end_of_table(args[0]) {
            return Ok(Some(atom("$end_of_table")));
        }
        Some(select_chunk::continuation_items(args[0])?)
    } else {
        None
    };
    let empty_result = |chunked: bool| -> Result<Term, VmError> {
        if chunked {
            Ok(atom("$end_of_table"))
        } else if count {
            Term::small(0).ok_or_else(badarg)
        } else {
            Ok(Term::NIL)
        }
    };
    let iterations = arinsal_ets::HASH_SELECT_ITERATIONS;

    // Cycle under the table's read lock.
    let (start, hash, cycle) = {
        let registry = rt.ets.read().unwrap();
        let tid = match (resumed.as_ref(), items.as_ref()) {
            (Some(state), _) => state.tid,
            (None, Some(items)) => handle(&registry, items[0])?,
            (None, None) => handle(&registry, args[0])?,
        };
        let table = match registry.get_shared(tid) {
            Ok(table) => table,
            Err(EtsError::Busy) => {
                if let Some(state) = resumed {
                    process.cold_mut().ets_select = Some(Box::new(state));
                }
                return Err(VmError::Yield);
            }
            Err(error) => return Err(err(error)),
        };
        if !allowed(&table, caller, false) {
            return Err(badarg_cause("access"));
        }
        let hash = table.is_hash();
        let start = match resumed {
            Some(state) => Start {
                tid,
                plan: if hash {
                    ScanPlan::Hash(arinsal_ets::HashScanPlan::all_slots())
                } else {
                    ScanPlan::Tree(table.tree_scan_plan(&state.program))
                },
                program: state.program,
                program_owner: state.program_owner,
                count: state.count,
                chunk: state.chunk,
                backwards: state.backwards,
                position: Some(state.position),
                got: state.got,
                saved: state.saved,
                safety: state.safety,
                fresh_plan: false,
                continued: true,
            },
            None if items.is_some() => {
                let items = items.as_deref().ok_or_else(badarg)?;
                let run = if hash {
                    select_chunk::decode_hash(&registry, items)?
                } else {
                    select_chunk::decode_tree(&registry, items)?
                };
                Start {
                    tid,
                    plan: if hash {
                        ScanPlan::Hash(arinsal_ets::HashScanPlan::all_slots())
                    } else {
                        ScanPlan::Tree(table.tree_scan_plan(&run.program))
                    },
                    program: run.program,
                    program_owner: run.program_owner,
                    count: false,
                    chunk: run.chunk,
                    backwards: run.backwards,
                    position: Some(run.position),
                    got: 0,
                    saved: run.saved,
                    safety: if hash {
                        table.iteration_safety(caller)
                    } else {
                        IterSafety::Safe
                    },
                    fresh_plan: false,
                    continued: true,
                }
            }
            None => {
                let chunk = match args.get(2) {
                    Some(limit) => limit
                        .as_small()
                        .and_then(|n| usize::try_from(n).ok())
                        .filter(|&n| n > 0)
                        .ok_or_else(badarg)?,
                    None => 0,
                };
                if args[1] == Term::NIL
                    && function != EtsBif::Match
                    && function != EtsBif::MatchObject
                {
                    return empty_result(chunk > 0).map(Some);
                }
                let program = match function {
                    EtsBif::Match => MatchProgram::from_pattern(args[1], false),
                    EtsBif::MatchObject => MatchProgram::from_pattern(args[1], true),
                    _ => MatchProgram::compile(args[1]),
                }
                .map_err(err)?;
                let program = Arc::new(program);
                let program_owner = select_chunk::new_match_program_owner(&program);
                let (plan, safety) = if hash {
                    let plan = table.hash_scan_plan(&program);
                    if !plan.something_can_match() {
                        return empty_result(chunk > 0).map(Some);
                    }
                    (ScanPlan::Hash(plan), table.iteration_safety(caller))
                } else {
                    let plan = table.tree_scan_plan(&program);
                    if plan.impossible() {
                        return empty_result(chunk > 0).map(Some);
                    }
                    if plan.key_bound() {
                        if chunk == 0 {
                            return Ok(None);
                        }
                        let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
                        let rows = table
                            .select_limit(&program, false, usize::MAX, &mut heap)
                            .map_err(err)?;
                        if rows.is_empty() {
                            return Ok(Some(atom("$end_of_table")));
                        }
                        let rows = TermBuilder::new(&mut heap)
                            .list_from_iter(rows)
                            .map_err(|_| badarg())?;
                        return TermBuilder::new(&mut heap)
                            .tuple(&[rows, atom("$end_of_table")])
                            .map(Some)
                            .map_err(|_| badarg());
                    }
                    (ScanPlan::Tree(plan), IterSafety::Safe)
                };
                Start {
                    tid,
                    plan,
                    program,
                    program_owner,
                    count,
                    chunk,
                    backwards: if chunk > 0 {
                        function == EtsBif::SelectReverse
                    } else {
                        function != EtsBif::SelectReverse
                    },
                    position: None,
                    got: 0,
                    saved: arinsal_ets::SavedMatches::new(),
                    safety,
                    fresh_plan: true,
                    continued: false,
                }
            }
        };
        let shape = CycleShape {
            count: start.count,
            backwards: start.backwards,
            chunk: start.chunk,
            held: start.saved.len(),
            from: start.position.as_ref(),
        };
        // The results are built on the process heap in both modes; a direct call that has to
        // trap declines afterwards, and the scheduler path redoes the cycle.
        let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
        let cycle = select_cycle(&table, &start.plan, &start.program, shape, &mut heap);
        (start, hash, cycle)
    };
    let Start {
        tid,
        program,
        program_owner,
        count,
        chunk,
        backwards,
        position,
        got,
        mut saved,
        safety,
        plan,
        fresh_plan,
        continued,
    } = start;
    let mut cycle = match cycle {
        Ok(cycle) => cycle,
        Err(error) => {
            if was_resumed && safety != IterSafety::Safe {
                unfix_table(rt, tid, caller);
            }
            return Err(err(error));
        }
    };
    let next_of = |cycle: &mut SelectCycle| -> Next {
        if let ScanPlan::Tree(plan) = &plan
            && chunk > 0
            && !count
        {
            return tree_chunk_next(plan, chunk, backwards, continued, cycle);
        }
        match cycle.resume.take() {
            Some(position) => Next::Trap(position),
            None => Next::Return,
        }
    };
    let mut next = next_of(&mut cycle);
    let mut fixed_now = false;
    if !matches!(next, Next::Return) && !was_resumed {
        // The first trap of a table that other processes may write: fix it under the write
        // lock, redoing the cycle in case the table changed in between.
        if ctx.is_none() {
            return Err(VmError::Yield);
        }
        if hash && safety != IterSafety::Safe {
            let registry = rt.ets.read().unwrap();
            let mut table = registry.get_mut(tid).map_err(err)?;
            let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
            let redo = if fresh_plan {
                ScanPlan::Hash(table.hash_scan_plan(&program))
            } else {
                ScanPlan::Hash(arinsal_ets::HashScanPlan::all_slots())
            };
            let shape = CycleShape {
                count,
                backwards,
                chunk,
                held: saved.len(),
                from: position.as_ref(),
            };
            cycle = select_cycle(&table, &redo, &program, shape, &mut heap).map_err(err)?;
            next = next_of(&mut cycle);
            if !matches!(next, Next::Return) {
                fix_table(&mut heap, &mut table, caller)?;
                fixed_now = true;
            }
        }
    }
    if fixed_now {
        rt.ets.write().unwrap().note_fixation(caller, tid);
        // erl_db.c, fix_table_locked: a fixation sets F_USING_DB on the fixing process.
        let _ = rt.publish_proc_flag(caller_pid, arinsal_sched::proc_flags::USING_DB);
    }
    let used = iterations - cycle.iterations_left.min(iterations);
    match next {
        Next::Trap(position) => {
            saved.extend(&cycle.results).map_err(err)?;
            let tree = matches!(position, ScanPosition::After(_));
            process.cold_mut().ets_select = Some(Box::new(crate::proc_create::EtsSelect {
                tid,
                program,
                count,
                position,
                backwards,
                got: if chunk > 0 {
                    cycle.held
                } else {
                    got + cycle.counted
                },
                saved,
                safety,
                chunk,
                program_owner,
                stage: SelectStage::Scan,
                end: None,
            }));
            let ctx = ctx.as_deref_mut().ok_or_else(needs_context)?;
            // A hash traversal charges all the reductions it has left, an ordered one the
            // objects it visited.
            bump_reds(process, ctx, if tree { used } else { isize::MAX });
            return Err(VmError::Yield);
        }
        Next::Reverse(key) => {
            saved.extend(&cycle.results).map_err(err)?;
            let end = match (&plan, &key) {
                (ScanPlan::Tree(plan), Some(_)) => plan
                    .end_condition_term(backwards)
                    .map(arinsal_ets::SavedKey::new)
                    .transpose()
                    .map_err(err)?,
                _ => None,
            };
            let eot = key.is_none();
            process.cold_mut().ets_select = Some(Box::new(crate::proc_create::EtsSelect {
                tid,
                program,
                count,
                position: key
                    .map(ScanPosition::After)
                    .unwrap_or(ScanPosition::Slot(usize::MAX)),
                backwards,
                got: cycle.held,
                saved,
                safety,
                chunk,
                program_owner,
                stage: SelectStage::Reverse { done: 0, eot },
                end,
            }));
            let ctx = ctx.as_deref_mut().ok_or_else(needs_context)?;
            bump_reds(process, ctx, used);
            return Err(VmError::Yield);
        }
        Next::Return => {}
    }
    let unfix = was_resumed && safety != IterSafety::Safe;
    let nothing_visited = !continued && cycle.iterations_left == iterations;
    if !(hash && chunk > 0 && nothing_visited) {
        match ctx {
            Some(ctx) => bump_reds(process, ctx, used),
            None => bump_direct(process, used),
        }
    }
    let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
    if count {
        if unfix {
            unfix_table(rt, tid, caller);
        }
        return TermBuilder::new(&mut heap)
            .int_from_i128((got + cycle.counted) as i128)
            .map(Some)
            .map_err(|_| badarg());
    }
    let mut values = saved.into_terms();
    values.extend(cycle.results);
    let result = if chunk == 0 {
        values.reverse();
        TermBuilder::new(&mut heap)
            .list_from_iter(values)
            .map_err(|_| badarg())?
    } else if !hash || nothing_visited {
        atom("$end_of_table")
    } else {
        let tid_term = rt
            .ets
            .read()
            .unwrap()
            .tid_term(tid, &mut heap)
            .map_err(err)?;
        select_chunk::hash_loop_ended(
            &mut heap,
            tid_term,
            &program_owner,
            chunk,
            values,
            cycle.chunk_slot,
            continued,
        )?
    };
    if unfix {
        unfix_table(rt, tid, caller);
    }
    Ok(Some(result))
}

/// A pass of `ets:reverse/3`, to which an ordered table's chunk trapped with its results: it
/// reverses up to 40000 cells and traps again, or returns the page and the continuation.
///
/// Port of erts/emulator/beam/erl_db_tree.c, ets_select_reverse, OTP-29.1.1.
fn reverse_trap(
    process: &mut Process,
    ctx: Option<&mut RunCtx<'_, Message>>,
    mut state: crate::proc_create::EtsSelect,
) -> Result<Term, VmError> {
    let SelectStage::Reverse { done, eot } = state.stage else {
        return Err(badarg());
    };
    match select_chunk::reverse_pass(state.saved.len() - done) {
        select_chunk::ReversePass::Trap { cells } => {
            state.stage = SelectStage::Reverse {
                done: done + cells,
                eot,
            };
            process.cold_mut().ets_select = Some(Box::new(state));
            let ctx = ctx.ok_or_else(needs_context)?;
            bump_reds(process, ctx, isize::MAX);
            Err(VmError::Yield)
        }
        select_chunk::ReversePass::Done { reds } => {
            let ctx = ctx.ok_or_else(needs_context)?;
            bump_reds(process, ctx, reds);
            let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
            let values = state.saved.terms().to_vec();
            let list = TermBuilder::new(&mut heap)
                .list_from_iter(values)
                .map_err(|_| badarg())?;
            let tid_term = process
                .runtime
                .as_ref()
                .ok_or_else(badarg)?
                .ets
                .read()
                .unwrap()
                .tid_term(state.tid, &mut heap)
                .map_err(err)?;
            let continuation = match (&state.position, eot) {
                (arinsal_ets::ScanPosition::After(key), false) => select_chunk::tree_continuation(
                    &mut heap,
                    tid_term,
                    &state.program_owner,
                    state.chunk,
                    state.backwards,
                    key,
                    state.end.as_ref(),
                )?,
                _ => atom("$end_of_table"),
            };
            TermBuilder::new(&mut heap)
                .tuple(&[list, continuation])
                .map_err(|_| badarg())
        }
    }
}

/// Release the fixation a trapped traversal held.
///
/// Port of erts/emulator/beam/erl_db.c, unfix_table_locked, OTP-29.1.1.
fn unfix_table(rt: &crate::process::Runtime, tid: Tid, caller: Term) {
    let registry = rt.ets.read().unwrap();
    if let Ok(shared) = registry.shared(tid) {
        let _ = shared.write().safe_fixtable_for(caller, false);
    }
}

/// Run one ETS BIF. `ctx` is only present on the scheduler path: erts sends messages
/// (give_away, request_all) and traps (delete) through the process, so those need it; every
/// other table operation runs from the caller pid alone, as erts runs them from BeamAsm.
fn call_inner(
    process: &mut Process,
    mut ctx: Option<&mut RunCtx<'_, Message>>,
    caller_pid: Pid,
    function: EtsBif,
    args: &[Term],
) -> Result<Term, VmError> {
    let caller = caller_pid.to_term().ok_or_else(badarg)?;
    if function == EtsBif::MatchSpecTest {
        // Port of erts/emulator/beam/erl_db_util.c
        // (`match_spec_test_3`, `match_spec_test`), OTP-29.1.1.
        let [against, specification, dialect] = args else {
            return Err(badarg());
        };
        let dialect = match dialect.as_atom() {
            Some(value) if Some(value) == ETS_ATOMS.get("table").copied() => MatchDialect::Table,
            Some(value) if Some(value) == ETS_ATOMS.get("trace").copied() => MatchDialect::Trace,
            _ => return Err(badarg()),
        };
        let seq_token = crate::seq_trace::get_token_term(process, caller_pid)?;
        let trace_control_word =
            Term::small(crate::natives::sys::trace_control_word_value(process))
                .ok_or_else(badarg)?;
        let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
        return arinsal_ets::match_spec::match_spec_test(
            *against,
            *specification,
            dialect,
            &mut heap,
            &ProcessMatchContext(caller, trace_control_word, seq_token),
        )
        .map_err(err);
    }
    if function == EtsBif::SuperUser {
        let [flag] = args else {
            return Err(badarg());
        };
        let mut users = ETS_SUPER_USERS.lock().unwrap();
        if *flag == atom("true") {
            users.insert(caller);
            return Ok(atom("ok"));
        }
        if *flag == atom("false") {
            users.remove(&caller);
            return Ok(atom("ok"));
        }
        return Err(badarg());
    }
    if let Some(ctx) = ctx.as_deref_mut()
        && gated_by_busy(function)
        && let Some(&target) = args.first()
    {
        help_busy_table(process, ctx, target, false)?;
    }
    if matches!(
        (function, args.len()),
        (EtsBif::Delete, 1) | (EtsBif::InternalDeleteAll, 2)
    ) {
        let ctx = ctx.ok_or_else(needs_context)?;
        return delete_or_clear(process, ctx, function, args, caller);
    }
    if matches!(
        (function, args.len()),
        (
            EtsBif::Select
                | EtsBif::SelectReverse
                | EtsBif::Match
                | EtsBif::MatchObject
                | EtsBif::SelectCount,
            2
        ) | (
            EtsBif::Select | EtsBif::SelectReverse | EtsBif::Match | EtsBif::MatchObject,
            1 | 3
        )
    ) && let Some(value) = hash_select(process, ctx.as_deref_mut(), caller_pid, function, args)?
    {
        return Ok(value);
    }
    let rt = process.runtime.as_ref().ok_or_else(badarg)?;
    // Port of erts/emulator/beam/erl_db.c (db_lock), OTP-29.1.1: table operations
    // lock only their table; the registry is exclusive only while its maps change.
    let exclusive = matches!(
        (function, args.len()),
        (EtsBif::New, _)
            | (EtsBif::Rename, _)
            | (EtsBif::Delete, 1)
            | (EtsBif::GiveAway, _)
            | (EtsBif::SafeFixtable, _)
    );
    let mut registry = if exclusive {
        RegistryAccess::Exclusive(rt.ets.write().unwrap())
    } else {
        RegistryAccess::Shared(rt.ets.read().unwrap())
    };
    let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
    match (function, args) {
        (EtsBif::New, [name, options]) => {
            // Port of erts/emulator/beam/erl_db.c (ets_new_2 option state), OTP-29.1.1.
            let mut opts = TableOptions {
                name: name.as_atom().ok_or_else(badarg)?,
                named_table: false,
                table_type: TableType::Set,
                keypos: 1,
                protection: Protection::Protected,
                owner: caller,
                heir: None,
                read_concurrency: false,
                write_concurrency: WriteConcurrency::Disabled,
                decentralized_counters: false,
                compressed: false,
            };
            let mut decentralized_counters_option = None;
            for option in list(*options).ok_or_else(badarg)? {
                if option == atom("named_table") {
                    opts.named_table = true;
                } else if option == atom("set") {
                    opts.table_type = TableType::Set;
                } else if option == atom("ordered_set") {
                    opts.table_type = TableType::OrderedSet;
                    opts.decentralized_counters = true;
                } else if option == atom("bag") {
                    opts.table_type = TableType::Bag;
                } else if option == atom("duplicate_bag") {
                    opts.table_type = TableType::DuplicateBag;
                } else if option == atom("private") {
                    opts.protection = Protection::Private;
                } else if option == atom("protected") {
                    opts.protection = Protection::Protected;
                } else if option == atom("public") {
                    opts.protection = Protection::Public;
                } else if option == atom("compressed") {
                    opts.compressed = true;
                // SAFETY: this option is still in the caller's live process heap.
                } else if let Some(pair) = unsafe { option.tuple_ref() } {
                    if pair.len() < 2 || pair.len() > 3 {
                        return Err(badarg());
                    }
                    let key = pair.get(0).unwrap().as_atom().ok_or_else(badarg)?;
                    let value = pair.get(1).unwrap();
                    if pair.len() == 3 && Some(key) != ETS_ATOMS.get("heir").copied() {
                        return Err(badarg());
                    }
                    if Some(key) == ETS_ATOMS.get("keypos").copied() {
                            opts.keypos = usize::try_from(value.as_small().ok_or_else(badarg)?)
                                .map_err(|_| badarg())?
                    } else if Some(key) == ETS_ATOMS.get("read_concurrency").copied() {
                        opts.read_concurrency = boolean(value)?;
                    } else if Some(key) == ETS_ATOMS.get("write_concurrency").copied() {
                        opts.write_concurrency = if value.as_atom()
                            == Some(arinsal_term::atoms::TRUE)
                        {
                            WriteConcurrency::Enabled
                        } else if value.as_atom() == ETS_ATOMS.get("auto").copied() {
                            WriteConcurrency::Auto
                        } else if let Ok(arinsal_etf::OwnedTerm::Tuple(ref parts)) =
                            arinsal_term::to_owned(value)
                            && let [
                                arinsal_etf::OwnedTerm::Atom(name),
                                arinsal_etf::OwnedTerm::Int(count),
                            ] = parts.as_slice()
                            && name == "debug_hash_fixed_number_of_locks"
                            && (1..=32_768).contains(count)
                        {
                            // Port of erts/emulator/beam/erl_db.c, OTP-29.1.1.
                            opts.decentralized_counters = true;
                            let count = *count as usize;
                            // Port of erts/emulator/beam/erl_db_hash.c:
                            // lock arrays round down to the nearest power of two.
                            WriteConcurrency::Fixed(1 << (usize::BITS - 1 - count.leading_zeros()))
                        } else if value.as_atom() == Some(arinsal_term::atoms::FALSE) {
                            WriteConcurrency::Disabled
                        } else {
                            return Err(badarg());
                        };
                        if opts.write_concurrency == WriteConcurrency::Auto {
                            opts.decentralized_counters = true;
                        } else if opts.write_concurrency == WriteConcurrency::Enabled
                            && opts.table_type != TableType::OrderedSet
                        {
                            opts.decentralized_counters = false;
                        }
                    } else if Some(key) == ETS_ATOMS.get("heir").copied() {
                        if !(2..=3).contains(&pair.len()) {
                            return Err(badarg());
                        }
                        let pid = value;
                        if pid != atom("none") {
                            let heir_pid = Pid::from_term(pid).ok_or_else(badarg)?;
                            // Port of erts/emulator/beam/erl_db.c (set_heir),
                            // OTP-29.1.1: a dead heir leaves the table without one.
                            opts.heir = None;
                            if let Some(started_interval) = rt
                                .scheduler()
                                .map_err(|_| badarg())?
                                .heir_started_interval(heir_pid)
                            {
                                opts.heir = Some(Heir {
                                started_interval,
                                pid,
                                data: if pair.len() == 3 {
                                    pair.get(2).unwrap()
                                } else {
                                    atom("undefined")
                                },
                                transfer: pair.len() == 3,
                            });
                            }
                        } else if pair.len() != 2 {
                            return Err(badarg());
                        }
                    } else if Some(key) == ETS_ATOMS.get("decentralized_counters").copied() {
                        decentralized_counters_option = Some(boolean(value)?);
                    } else if Some(key) == ETS_ATOMS.get("compressed").copied() {
                        opts.compressed = boolean(value)?;
                    } else {
                        return Err(badarg());
                    }
                } else {
                    return Err(badarg());
                }
            }
            opts.decentralized_counters = decentralized_counters_option
                .unwrap_or(opts.decentralized_counters)
                && opts.write_concurrency != WriteConcurrency::Disabled;
            // Port of erts/emulator/beam/erl_db.c (ets_new_2), OTP-29.1.1.
            let tid = registry
                .exclusive()?
                .create(opts)
                .map_err(|error| match error {
                    EtsError::NameTaken => badarg_cause("already_exists"),
                    error => err(error),
                })?;
            // erl_db.c: BIF_P->flags |= F_USING_DB so exit can find the table.
            if !rt.publish_proc_flag(caller_pid, arinsal_sched::proc_flags::USING_DB) {
                registry.exclusive()?.detach(tid).ok();
                return Err(badarg());
            }
            if registry.get(tid).map_err(err)?.options.named_table {
                Ok(Term::atom(name.as_atom().unwrap()))
            } else {
                registry.tid_term(tid, &mut heap).map_err(err)
            }
        }
        (EtsBif::Whereis, [name]) => Ok(registry
            .whereis(name.as_atom().ok_or_else(badarg)?)
            .map(|tid| registry.tid_term(tid, &mut heap))
            .transpose()
            .map_err(err)?
            .unwrap_or(atom("undefined"))),
        (EtsBif::Rename, [target, name]) => {
            // Port of erts/emulator/beam/erl_db.c (ets_rename_2), OTP-29.1.1:
            // the table needs write access, and is looked up even for a bad name.
            let tid = handle(&registry, *target)?;
            let named = {
                let table = registry.get(tid).map_err(err)?;
                if table.is_busy() {
                    return Err(VmError::Yield);
                }
                if !allowed(&table, caller, true) {
                    return Err(badarg_cause("access"));
                }
                table.options.named_table
            };
            let new_name = name.as_atom().ok_or_else(badarg)?;
            registry.exclusive()?.rename(tid, new_name).map_err(err)?;
            // Unnamed tables keep their id; only the displayed name changes.
            // Port of erts/emulator/beam/erl_db.c (ets_rename_2), OTP-29.1.1.
            if named { Ok(*name) } else { Ok(*target) }
        }
        (EtsBif::Info, [target]) | (EtsBif::Info, [target, _]) => {
            // Missing tables yield `undefined`; a non-id argument is `badarg`.
            // Port of erts/emulator/beam/erl_db.c and :4544, OTP-29.1.1.
            let tid = match resolve(&registry, *target) {
                Ok(tid) => tid,
                Err(ResolveFail::Missing) => return Ok(atom("undefined")),
                Err(ResolveFail::BadType) => return Err(badarg_cause("type")),
            };
            // Port of erts/emulator/beam/erl_db.c (ets_info_2, DB_INFO/LCK_READ),
            // OTP-29.1.1.
            if args.len() == 1 {
                let table = table_guard(&registry, tid, true)?;
                let schedulers = rt.scheduler()?.scheduler_count();
                table
                    .info_list_for_schedulers(atom("nonode@nohost"), &mut heap, schedulers)
                    .map_err(err)
            } else {
                let key = info_item_name(args[1]).ok_or_else(badarg)?;
                let table = table_guard(&registry, tid, true)?;
                let schedulers = if key == "memory" {
                    rt.scheduler()?.scheduler_count()
                } else {
                    1
                };
                table
                    .info_item_for_schedulers(key, atom("nonode@nohost"), &mut heap, schedulers)
                    .map_err(err)
            }
        }
        (EtsBif::Delete, [target, key]) => {
            let tid = handle(&registry, *target)?;
            if registry
                .shared(tid)
                .map_err(err)?
                .options()
                .write_concurrency
                != WriteConcurrency::Disabled
            {
                let table = registry.get_shared(tid).map_err(err)?;
                if !allowed(&table, caller, true) {
                    return Err(badarg_cause("access"));
                }
                if table.delete_key_shared(*key) {
                    return Ok(atom("true"));
                }
            }
            let mut table = registry.get_mut(tid).map_err(err)?;
            if !allowed(&table, caller, true) {
                return Err(badarg_cause("access"));
            }
            table.delete_key(*key);
            Ok(atom("true"))
        }
        // Port of erts/emulator/beam/erl_db.c and erl_db_hash.c,
        // OTP-29.1.1.
        (EtsBif::LookupBinaryInfo, [target, key]) => {
            let tid = handle(&registry, *target)?;
            let table = registry.get_shared(tid).map_err(err)?;
            if !allowed(&table, caller, false) {
                return Err(badarg_cause("access"));
            }
            let binaries = table
                .lookup_binary_info(*key, &mut heap)
                .map_err(binary_info_err)?;
            TermBuilder::new(&mut heap)
                .list_from_iter(binaries)
                .map_err(|_| system_limit())
        }
        // Port of erts/emulator/beam/erl_db.c (`ets_setopts_2`),
        // OTP-29.1.1.
        (EtsBif::SetOpts, [target, options]) => {
            let tid = handle(&registry, *target)?;
            let mut table = registry.get_mut(tid).map_err(err)?;
            if !allowed(&table, caller, true) {
                return Err(badarg_cause("access"));
            }
            if table.options.owner != caller {
                return Err(badarg());
            }
            let entries = if options.classify() == TermKind::Tuple {
                vec![*options]
            } else {
                list(*options).ok_or_else(badarg)?
            };
            let mut protection = None;
            let mut heir: Option<Option<Heir>> = None;
            for option in entries {
                let owned = arinsal_term::to_owned(option).map_err(|_| badarg())?;
                let arinsal_etf::OwnedTerm::Tuple(fields) = &owned else {
                    return Err(badarg());
                };
                if fields.len() < 2 {
                    return Err(badarg());
                }
                let arinsal_etf::OwnedTerm::Atom(name) = &fields[0] else {
                    return Err(badarg());
                };
                let name = global_atoms().intern(name).map_err(|_| badarg())?;
                if Some(name) == ETS_ATOMS.get("protection").copied() {
                    if fields.len() != 2 || protection.is_some() {
                        return Err(badarg());
                    }
                    let arinsal_etf::OwnedTerm::Atom(value) = &fields[1] else {
                        return Err(badarg());
                    };
                    protection = Some(match value.as_str() {
                        "private" => Protection::Private,
                        "protected" => Protection::Protected,
                        "public" => Protection::Public,
                        _ => return Err(badarg()),
                    });
                } else if Some(name) == ETS_ATOMS.get("heir").copied() {
                    if heir.is_some() {
                        return Err(badarg());
                    }
                    if fields.len() == 2
                        && fields[1] == arinsal_etf::OwnedTerm::Atom("none".to_owned())
                    {
                        heir = Some(None);
                    } else if fields.len() == 2 || fields.len() == 3 {
                        let pid_term = arinsal_term::from_owned(&fields[1], &mut heap)
                            .map_err(|_| badarg())?;
                        let pid = Pid::from_term(pid_term).ok_or_else(badarg)?;
                        let data = if fields.len() == 2 {
                            atom("undefined")
                        } else {
                            arinsal_term::from_owned(&fields[2], &mut heap)
                                .map_err(|_| badarg())?
                        };
                        let started = rt
                            .scheduler()
                            .map_err(|_| badarg())?
                            .heir_started_interval(pid);
                        heir = Some(started.map(|started_interval| Heir {
                            pid: pid_term,
                            data,
                            transfer: fields.len() == 3,
                            started_interval,
                        }));
                    } else {
                        return Err(badarg());
                    }
                } else {
                    return Err(badarg());
                }
            }
            table
                .set_access_options(protection, heir.flatten())
                .map_err(err)?;
            if matches!(heir, Some(None)) {
                table.options.heir = None;
            }
            Ok(atom("true"))
        }
        // Port of erts/emulator/beam/erl_db.c (`erts_internal_ets_raw_first_1`),
        // OTP-29.1.1.
        (EtsBif::RawFirst, [target]) => {
            let tid = handle(&registry, *target)?;
            let table = registry.get_shared(tid).map_err(err)?;
            if !allowed(&table, caller, false) {
                return Err(badarg_cause("access"));
            }
            Ok(table
                .raw_first(&mut heap)
                .map_err(err)?
                .unwrap_or(atom("$end_of_table")))
        }
        // Port of erts/emulator/beam/erl_db.c (`erts_internal_ets_raw_next_2`),
        // OTP-29.1.1.
        (EtsBif::RawNext, [target, key]) => {
            let tid = handle(&registry, *target)?;
            let table = registry.get_shared(tid).map_err(err)?;
            if !allowed(&table, caller, false) {
                return Err(badarg_cause("access"));
            }
            Ok(table
                .raw_next(*key, &mut heap)
                .map_err(err)?
                .unwrap_or(atom("$end_of_table")))
        }
        (EtsBif::Take, [target, key]) => {
            let tid = handle(&registry, *target)?;
            if registry
                .shared(tid)
                .map_err(err)?
                .options()
                .write_concurrency
                != WriteConcurrency::Disabled
            {
                let table = registry.get_shared(tid).map_err(err)?;
                if !allowed(&table, caller, true) {
                    return Err(badarg_cause("access"));
                }
                if table.options.table_type != TableType::OrderedSet {
                    let values = table.take_shared(*key, &mut heap).map_err(err)?;
                    return output_list(&mut heap, values);
                }
            }
            let mut table = registry.get_mut(tid).map_err(err)?;
            if !allowed(&table, caller, true) {
                return Err(badarg_cause("access"));
            }
            let values = table.take(*key, &mut heap).map_err(err)?;
            output_list(&mut heap, values)
        }
        (EtsBif::Slot, [target, index]) => {
            let tid = handle(&registry, *target)?;
            let table = registry.get_shared(tid).map_err(err)?;
            if !allowed(&table, caller, false) {
                return Err(badarg_cause("access"));
            }
            let slot =
                usize::try_from(index.as_small().ok_or_else(badarg)?).map_err(|_| badarg())?;
            Ok(table
                .slot(slot, &mut heap)
                .map_err(err)?
                .unwrap_or(atom("$end_of_table")))
        }
        (EtsBif::First | EtsBif::Last, [target]) => {
            let tid = handle(&registry, *target)?;
            let table = table_guard(&registry, tid, true)?;
            if !allowed(&table, caller, false) {
                return Err(badarg_cause("access"));
            }
            Ok(table
                .edge(function == EtsBif::Last, &mut heap)
                .map_err(err)?
                .unwrap_or(atom("$end_of_table")))
        }
        (EtsBif::Next | EtsBif::Prev, [target, key]) => {
            // `'$end_of_table'` is DB_ERROR_BADKEY in db_next_tree / db_prev_tree.
            // Port of erts/emulator/beam/erl_db_tree.c, OTP-29.1.1.
            if end_of_table(*key) {
                return Err(badarg());
            }
            let tid = handle(&registry, *target)?;
            let table = table_guard(&registry, tid, true)?;
            if !allowed(&table, caller, false) {
                return Err(badarg_cause("access"));
            }
            Ok((if function == EtsBif::Next {
                table.next(*key, &mut heap)
            } else {
                table.prev(*key, &mut heap)
            })
            .map_err(err)?
            .unwrap_or(atom("$end_of_table")))
        }
        // Port of erts/emulator/beam/erl_db.c (ets_first_lookup_1),
        // :1238 (ets_next_lookup_2), :1286 (ets_last_lookup_1) and
        // :1332 (ets_prev_lookup_2), OTP-29.1.1. Hash tables treat last as
        // first and prev as next (erl_db_hash.c).
        (EtsBif::FirstLookup | EtsBif::LastLookup, [target]) => {
            let tid = handle(&registry, *target)?;
            let table = table_guard(&registry, tid, true)?;
            if !allowed(&table, caller, false) {
                return Err(badarg_cause("access"));
            }
            match table
                .edge_lookup(function == EtsBif::LastLookup, &mut heap)
                .map_err(err)?
            {
                None => Ok(atom("$end_of_table")),
                Some((key, objects)) => lookup_pair(&mut heap, key, objects),
            }
        }
        (EtsBif::NextLookup | EtsBif::PrevLookup, [target, key]) => {
            if end_of_table(*key) {
                return Err(badarg());
            }
            let tid = handle(&registry, *target)?;
            let table = table_guard(&registry, tid, true)?;
            if !allowed(&table, caller, false) {
                return Err(badarg_cause("access"));
            }
            match table
                .adjacent_lookup(*key, function == EtsBif::PrevLookup, &mut heap)
                .map_err(err)?
            {
                None => Ok(atom("$end_of_table")),
                Some((found, objects)) => lookup_pair(&mut heap, found, objects),
            }
        }
        (EtsBif::SafeFixtable, [target, fixed]) => {
            let tid = handle(&registry, *target)?;
            let mut table = registry.get_mut(tid).map_err(err)?;
            if !allowed(&table, caller, false) {
                return Err(badarg_cause("access"));
            }
            let fixed = boolean(*fixed)?;
            if fixed {
                fix_table(&mut heap, &mut table, caller)?;
                drop(table);
                registry.exclusive()?.note_fixation(caller, tid);
                // erl_db.c and 5187: a fixation sets F_USING_DB on the fixing process.
                let _ = rt.publish_proc_flag(caller_pid, arinsal_sched::proc_flags::USING_DB);
            } else {
                table.safe_fixtable_for(caller, false).map_err(err)?;
            }
            Ok(atom("true"))
        }
        (EtsBif::DeleteObject, [target, object]) => {
            let tid = handle(&registry, *target)?;
            if registry
                .shared(tid)
                .map_err(err)?
                .options()
                .write_concurrency
                != WriteConcurrency::Disabled
            {
                let table = registry.get_shared(tid).map_err(err)?;
                if !allowed(&table, caller, true) {
                    return Err(badarg_cause("access"));
                }
                if table.delete_object_shared(*object).map_err(err)? {
                    return Ok(atom("true"));
                }
            }
            let mut table = registry.get_mut(tid).map_err(err)?;
            if !allowed(&table, caller, true) {
                return Err(badarg_cause("access"));
            }
            table.delete_object(*object).map_err(err)?;
            Ok(atom("true"))
        }
        (EtsBif::GiveAway, [target, new_owner, data]) => {
            // Port of erts/emulator/beam/erl_db.c (ets_give_away_3), OTP-29.1.1:
            // table errors come first, then the receiver, then ownership.
            let tid = handle(&registry, *target)?;
            {
                let table = registry.get(tid).map_err(err)?;
                if !allowed(&table, caller, true) {
                    return Err(badarg_cause("access"));
                }
            }
            let pid = Pid::from_term(*new_owner).ok_or_else(badarg)?;
            if *new_owner != caller && !rt.scheduler().map_err(|_| badarg())?.lookup(pid) {
                return Err(badarg());
            }
            let options = registry.get(tid).map_err(err)?.options;
            if options.owner != caller {
                return Err(badarg_cause("not_owner"));
            }
            if *new_owner == caller {
                return Err(badarg_cause("owner"));
            }
            // Port of erts/emulator/beam/erl_db.c (send_ets_transfer_message),
            // OTP-29.1.1: a named table is identified by its name.
            let tab = if options.named_table {
                Term::atom(options.name)
            } else {
                registry.tid_term(tid, &mut heap).map_err(err)?
            };
            let transfer = TermBuilder::new(&mut heap)
                .tuple(&[atom("ETS-TRANSFER"), tab, caller, *data])
                .map_err(|_| badarg())?;
            registry.exclusive()?.give_away(tid, *new_owner).map_err(err)?;
            // erl_db.c: the receiver's F_USING_DB is set so its exit deletes the table.
            if !rt.publish_proc_flag(pid, arinsal_sched::proc_flags::USING_DB) {
                return Err(badarg());
            }
            ctx.as_deref_mut()
                .ok_or_else(needs_context)?
                .send(pid, Message::copy_from(transfer)?)
                .map_err(|_| badarg())?;
            Ok(atom("true"))
        }
        (EtsBif::Select | EtsBif::SelectReverse, [target, spec])
        | (EtsBif::Match, [target, spec])
        | (EtsBif::MatchObject, [target, spec]) => {
            let tid = handle(&registry, *target)?;
            let table = table_guard(&registry, tid, true)?;
            if !allowed(&table, caller, false) {
                return Err(badarg_cause("access"));
            }
            if matches!(function, EtsBif::Select | EtsBif::SelectReverse)
                && *spec == Term::NIL
            {
                return Ok(Term::NIL);
            }
            let program = if matches!(function, EtsBif::Select | EtsBif::SelectReverse) {
                MatchProgram::compile(*spec)
            } else {
                MatchProgram::from_pattern(*spec, function == EtsBif::MatchObject)
            }
            .map_err(err)?;
            let values = if function == EtsBif::Match {
                table.match_pattern(*spec, &mut heap)
            } else if function == EtsBif::MatchObject {
                table.match_object(*spec, &mut heap)
            } else {
                table.select(&program, function == EtsBif::SelectReverse, &mut heap)
            }
            .map_err(err)?;
            TermBuilder::new(&mut heap)
                .list_from_iter(values)
                .map_err(|_| badarg())
        }
        (EtsBif::MatchSpecCompile, [spec]) => {
            // Port of erts/emulator/beam/erl_db.c
            // (ets_match_spec_compile_1), OTP-29.1.1. The program lifetime follows
            // the magic reference through the process heap and its garbage collector.
            let program = Arc::new(MatchProgram::compile(*spec).map_err(err)?);
            let payload_size = program.erts_magic_payload_size();
            TermBuilder::new(&mut heap)
                .magic_ref(MagicRef::with_erts_payload_size(
                    program,
                    payload_size,
                ))
                .map_err(|_| badarg())
        }
        (EtsBif::IsCompiledMs, [value]) => {
            // Port of erts/emulator/beam/erl_db.c
            // (ets_is_compiled_ms_1), OTP-29.1.1.
            // Continuation references retain their program through the magic reference, as
            // does a reference returned by match_spec_compile/1.
            Ok(boolean_term(
                compiled_match_program(*value).is_some() || registry.match_program(*value).is_some(),
            ))
        }
        (EtsBif::InternalRequestAll, []) => {
            // Port of erts/emulator/beam/erl_db.c (ets_internal_request_all_0)
            // and lib/stdlib/src/ets.erl:318 (all/0), OTP-29.1.1.
            // Each scheduler sends `{Ref, Tables}`. This VM keeps every table in
            // one registry, so one reply carries them and the rest are empty.
            // `ets:all/0` waits for `erlang:system_info(schedulers)` replies.
            let id = rt.next_ref();
            let reference = Term::local_ref(&mut heap, arinsal_bifs::ordinary_ref_words(id))
                .map_err(|_| badarg())?;
            let tables = live_table_terms(&registry, &mut heap)?;
            let table_list = TermBuilder::new(&mut heap)
                .list_from_iter(tables)
                .map_err(|_| badarg())?;
            let caller = caller_pid;
            let ctx = ctx.ok_or_else(needs_context)?;
            for index in 0..scheduler_count() {
                let payload = if index == 0 { table_list } else { Term::NIL };
                let message = TermBuilder::new(&mut heap)
                    .tuple(&[reference, payload])
                    .map_err(|_| badarg())?;
                ctx.send(caller, Message::copy_from(message)?)
                    .map_err(|_| badarg())?;
            }
            Ok(reference)
        }
        (EtsBif::MatchSpecRunR, [objects, compiled, accumulator]) => {
            // Port of erts/emulator/beam/erl_db.c (ets_match_spec_run_r_3), OTP-29.1.1.
            // The return value is the accumulator with each match consed in front.
            if objects.classify() != TermKind::List && *objects != Term::NIL {
                return Err(badarg());
            }
            let program = compiled_match_program(*compiled)
                .or_else(|| registry.match_program(*compiled))
                .ok_or_else(badarg)?;
            if *objects == Term::NIL {
                return Ok(*accumulator);
            }
            let objects = list(*objects).ok_or_else(badarg)?;
            let mut matched = Vec::new();
            for object in objects {
                if let Some(result) = program.run(object, &mut heap).map_err(err)? {
                    matched.push(result);
                }
            }
            let mut out = *accumulator;
            for result in matched {
                out = TermBuilder::new(&mut heap)
                    .cons(result, out)
                    .map_err(|_| badarg())?;
            }
            Ok(out)
        }
        (EtsBif::SelectCount, [target, spec])
        // Port of erts/emulator/beam/erl_db.c (ets_internal_select_delete_2), OTP-29.1.1.
        // The BIF has no delete-all special case; `[]` returns 0 and a match spec deletes.
        | (EtsBif::InternalSelectDelete, [target, spec])
        | (EtsBif::SelectReplace, [target, spec]) => {
            let tid = handle(&registry, *target)?;
            if function == EtsBif::SelectReplace
                && registry
                    .shared(tid)
                    .map_err(err)?
                    .options()
                    .write_concurrency
                    != WriteConcurrency::Disabled
            {
                let table = registry.get_shared(tid).map_err(err)?;
                if !allowed(&table, caller, true) {
                    return Err(badarg_cause("access"));
                }
                if table.options.table_type == TableType::Bag {
                    return Err(badarg_cause("table_type"));
                }
                if *spec == Term::NIL {
                    return Term::small(0).ok_or_else(badarg);
                }
                let program = MatchProgram::compile(*spec).map_err(err)?;
                if let Some(count) = table
                    .select_replace_key_shared(&program)
                    .map_err(err)?
                {
                    return TermBuilder::new(&mut heap)
                        .int_from_i128(count as i128)
                        .map_err(|_| badarg());
                }
            }
            if function == EtsBif::SelectCount {
                let table = registry.get_shared(tid).map_err(err)?;
                if !allowed(&table, caller, false) {
                    return Err(badarg_cause("access"));
                }
                if *spec == Term::NIL {
                    return Term::small(0).ok_or_else(badarg);
                }
                let program = MatchProgram::compile(*spec).map_err(err)?;
                let count = table.select_count(&program).map_err(err)?;
                return TermBuilder::new(&mut heap)
                    .int_from_i128(count as i128)
                    .map_err(|_| badarg());
            }
            let mut table = registry.get_mut(tid).map_err(err)?;
            if !allowed(&table, caller, function != EtsBif::SelectCount) {
                return Err(badarg_cause("access"));
            }
            // Port of erts/emulator/beam/erl_db.c (ets_select_replace_2), OTP-29.1.1.
            if function == EtsBif::SelectReplace && table.options.table_type == TableType::Bag {
                return Err(badarg_cause("table_type"));
            }
            if *spec == Term::NIL {
                return Term::small(0).ok_or_else(badarg);
            }
            let program = MatchProgram::compile(*spec).map_err(err)?;
            let count = match function {
                EtsBif::SelectCount => table.select_count(&program),
                EtsBif::InternalSelectDelete => table.select_delete(&program),
                EtsBif::SelectReplace => table.select_replace(&program),
                _ => unreachable!(),
            }
            .map_err(err)?;
            TermBuilder::new(&mut heap)
                .int_from_i128(count as i128)
                .map_err(|_| badarg())
        }
        (EtsBif::LookupElement, [target, key, position])
        | (EtsBif::LookupElement, [target, key, position, _]) => {
            let tid = handle(&registry, *target)?;
            let table = registry.get_shared(tid).map_err(err)?;
            lookup_element_locked(
                &table,
                arinsal_term::current_reader_group(),
                caller,
                *key,
                *position,
                args.get(3).copied(),
                &mut heap,
            )
        }
        (EtsBif::UpdateElement, [target, key, updates])
        | (EtsBif::UpdateElement, [target, key, updates, _]) => {
            let tid = handle(&registry, *target)?;
            if registry
                .shared(tid)
                .map_err(err)?
                .options()
                .write_concurrency
                != WriteConcurrency::Disabled
            {
                let table = registry.get_shared(tid).map_err(err)?;
                if table.options.table_type == TableType::Set {
                    if !allowed(&table, caller, true) {
                        return Err(badarg_cause("access"));
                    }
                    let default = default_object(&table, args.get(3).copied())?;
                    let parsed = update_list(*updates, |entry| {
                        match tuple_items(entry)?.as_slice() {
                            [position_term, value] => Some((position(*position_term)?, *value)),
                            _ => None,
                        }
                    });
                    return Ok(boolean_term(
                        table
                            .update_element_shared(*key, &parsed, default)
                            .map_err(err)?,
                    ));
                }
            }
            let mut table = registry.get_mut(tid).map_err(err)?;
            if !allowed(&table, caller, true) {
                return Err(badarg_cause("access"));
            }
            let default = default_object(&table, args.get(3).copied())?;
            // Port of erts/emulator/beam/erl_db.c (do_update_element), OTP-29.1.1:
            // a malformed `{Pos, Value}` fails only after the key lookup.
            let parsed = update_list(*updates, |entry| match tuple_items(entry)?.as_slice() {
                [position_term, value] => Some((position(*position_term)?, *value)),
                _ => None,
            });
            let updated = table
                .update_element(*key, &parsed, default)
                .map_err(err)?;
            Ok(boolean_term(updated))
        }
        (EtsBif::UpdateCounter, [target, key, operation])
        | (EtsBif::UpdateCounter, [target, key, operation, _]) => {
            let tid = handle(&registry, *target)?;
            if registry
                .shared(tid)
                .map_err(err)?
                .options()
                .write_concurrency
                != WriteConcurrency::Disabled
            {
                let table = registry.get_shared(tid).map_err(err)?;
                if matches!(
                    table.options.table_type,
                    TableType::Set | TableType::OrderedSet
                ) {
                    if !allowed(&table, caller, true) {
                        return Err(badarg_cause("access"));
                    }
                    let default = default_object(&table, args.get(3).copied())?;
                    let single = integer(*operation).is_some()
                        || operation.classify() == TermKind::Tuple;
                    if let Some((operations, _)) =
                        small_counter_ops(table.options.keypos, *operation)
                        && let Some(values) =
                            table.update_counter_in_place_shared(*key, &operations)
                    {
                        return counter_results(&mut heap, &values, single);
                    }
                    let parse = |entry: Term| -> Option<BigCounterOp> {
                        let (position_term, increment, threshold) =
                            match tuple_items(entry)?.as_slice() {
                                [position_term, increment] => (*position_term, *increment, None),
                                [position_term, increment, threshold, warp] => (
                                    *position_term,
                                    *increment,
                                    Some((integer(*threshold)?, integer(*warp)?)),
                                ),
                                _ => return None,
                            };
                        Some(BigCounterOp {
                            position: position(position_term)?,
                            increment: integer(increment)?,
                            threshold,
                        })
                    };
                    let operations = if let Some(increment) = integer(*operation) {
                        vec![Some(BigCounterOp {
                            position: table.options.keypos + 1,
                            increment,
                            threshold: None,
                        })]
                    } else {
                        update_list(*operation, parse)
                    };
                    let values = table
                        .update_counter_big_shared(*key, &operations, default, &mut heap)
                        .map_err(err)?
                        .ok_or_else(badarg)?;
                    return if single {
                        values.first().copied().ok_or_else(badarg)
                    } else {
                        output_list(&mut heap, values)
                    };
                }
            }
            let mut table = registry.get_mut(tid).map_err(err)?;
            if !allowed(&table, caller, true) {
                return Err(badarg_cause("access"));
            }
            let default = default_object(&table, args.get(3).copied())?;
            if let Some((operations, single)) = small_counter_ops(table.options.keypos, *operation)
                && let Some(values) = table.update_counter_in_place(*key, &operations)
            {
                return counter_results(&mut heap, &values, single);
            }
            // Port of erts/emulator/beam/erl_db.c (do_update_counter), OTP-29.1.1.
            // An integer increments the element after the key; a list returns a list.
            let parse = |entry: Term| -> Option<BigCounterOp> {
                let (position_term, increment, threshold) = match tuple_items(entry)?.as_slice() {
                    [position_term, increment] => (*position_term, *increment, None),
                    [position_term, increment, threshold, warp] => (
                        *position_term,
                        *increment,
                        Some((integer(*threshold)?, integer(*warp)?)),
                    ),
                    _ => return None,
                };
                Some(BigCounterOp {
                    position: position(position_term)?,
                    increment: integer(increment)?,
                    threshold,
                })
            };
            let single = integer(*operation).is_some() || operation.classify() == TermKind::Tuple;
            let operations = if let Some(increment) = integer(*operation) {
                vec![Some(BigCounterOp {
                    position: table.options.keypos + 1,
                    increment,
                    threshold: None,
                })]
            } else {
                update_list(*operation, parse)
            };
            let values = table
                .update_counter_big(*key, &operations, default)
                .map_err(err)?;
            let copied = values
                .into_iter()
                .map(|value| copy_term(value, &mut heap).map_err(|_| badarg()))
                .collect::<Result<Vec<_>, _>>()?;
            if single {
                copied.first().copied().ok_or_else(badarg)
            } else {
                TermBuilder::new(&mut heap)
                    .list_from_iter(copied)
                    .map_err(|_| badarg())
            }
        }
        _ => {
            debug_assert!(
                false,
                "ets BIF {function:?}/{} has no match arm",
                args.len()
            );
            Err(badarg())
        }
    }
}

/// ETS BIFs. [`call`] admits every function name in this table; [`call_inner`]
/// implements the listed arities and returns `badarg` for any other arity.
pub(crate) const IMPLEMENTED: &[(&str, &str, u8)] = &[
    ("erlang", "match_spec_test", 3),
    ("erts_internal", "ets_lookup_binary_info", 2),
    ("erts_internal", "ets_raw_first", 1),
    ("erts_internal", "ets_raw_next", 2),
    ("erts_internal", "ets_super_user", 1),
    ("ets", "new", 2),
    ("ets", "whereis", 1),
    ("ets", "rename", 2),
    ("ets", "info", 1),
    ("ets", "info", 2),
    ("ets", "delete", 1),
    ("ets", "delete", 2),
    ("ets", "internal_delete_all", 2),
    ("ets", "setopts", 2),
    ("ets", "insert", 2),
    ("ets", "insert_new", 2),
    ("ets", "lookup", 2),
    ("ets", "member", 2),
    ("ets", "take", 2),
    ("ets", "slot", 2),
    ("ets", "first", 1),
    ("ets", "first_lookup", 1),
    ("ets", "last", 1),
    ("ets", "last_lookup", 1),
    ("ets", "next", 2),
    ("ets", "next_lookup", 2),
    ("ets", "prev", 2),
    ("ets", "prev_lookup", 2),
    ("ets", "safe_fixtable", 2),
    ("ets", "delete_object", 2),
    ("ets", "give_away", 3),
    ("ets", "select", 1),
    ("ets", "select", 2),
    ("ets", "select", 3),
    ("ets", "select_reverse", 1),
    ("ets", "select_reverse", 2),
    ("ets", "select_reverse", 3),
    ("ets", "match", 1),
    ("ets", "match", 2),
    ("ets", "match", 3),
    ("ets", "match_object", 1),
    ("ets", "match_object", 2),
    ("ets", "match_object", 3),
    ("ets", "match_spec_compile", 1),
    ("ets", "is_compiled_ms", 1),
    ("ets", "internal_request_all", 0),
    ("ets", "match_spec_run_r", 3),
    ("ets", "select_count", 2),
    ("ets", "internal_select_delete", 2),
    ("ets", "select_replace", 2),
    ("ets", "lookup_element", 3),
    ("ets", "lookup_element", 4),
    ("ets", "update_element", 3),
    ("ets", "update_element", 4),
    ("ets", "update_counter", 3),
    ("ets", "update_counter", 4),
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum EtsBif {
    MatchSpecTest,
    LookupBinaryInfo,
    RawFirst,
    RawNext,
    SuperUser,
    New,
    Whereis,
    Rename,
    Info,
    Delete,
    InternalDeleteAll,
    SetOpts,
    Take,
    Slot,
    First,
    FirstLookup,
    Last,
    LastLookup,
    Next,
    NextLookup,
    Prev,
    PrevLookup,
    SafeFixtable,
    DeleteObject,
    GiveAway,
    Select,
    SelectReverse,
    Match,
    MatchObject,
    MatchSpecCompile,
    IsCompiledMs,
    InternalRequestAll,
    MatchSpecRunR,
    SelectCount,
    InternalSelectDelete,
    SelectReplace,
    LookupElement,
    UpdateElement,
    UpdateCounter,
}

impl EtsBif {
    const ALL: [EtsBif; 39] = [
        EtsBif::MatchSpecTest,
        EtsBif::LookupBinaryInfo,
        EtsBif::RawFirst,
        EtsBif::RawNext,
        EtsBif::SuperUser,
        EtsBif::New,
        EtsBif::Whereis,
        EtsBif::Rename,
        EtsBif::Info,
        EtsBif::Delete,
        EtsBif::InternalDeleteAll,
        EtsBif::SetOpts,
        EtsBif::Take,
        EtsBif::Slot,
        EtsBif::First,
        EtsBif::FirstLookup,
        EtsBif::Last,
        EtsBif::LastLookup,
        EtsBif::Next,
        EtsBif::NextLookup,
        EtsBif::Prev,
        EtsBif::PrevLookup,
        EtsBif::SafeFixtable,
        EtsBif::DeleteObject,
        EtsBif::GiveAway,
        EtsBif::Select,
        EtsBif::SelectReverse,
        EtsBif::Match,
        EtsBif::MatchObject,
        EtsBif::MatchSpecCompile,
        EtsBif::IsCompiledMs,
        EtsBif::InternalRequestAll,
        EtsBif::MatchSpecRunR,
        EtsBif::SelectCount,
        EtsBif::InternalSelectDelete,
        EtsBif::SelectReplace,
        EtsBif::LookupElement,
        EtsBif::UpdateElement,
        EtsBif::UpdateCounter,
    ];

    /// The variant with discriminant `value` (const-generic direct entries carry it).
    fn from_u8(value: u8) -> EtsBif {
        Self::ALL[usize::from(value)]
    }
}

macro_rules! ets_entry {
    ($entry:ident, $id:ident, $arity:literal, $module:literal, $function:literal) => {
        fn $entry(
            vm: &mut Vm,
            process: &mut Process,
            ctx: &mut RunCtx<'_, Message>,
            args: super::NativeArgs<'_>,
        ) -> Option<Result<Term, VmError>> {
            if args.len() != $arity {
                return Some(Err(badarg()));
            }
            let _ = vm;
            let ctx_pid = ctx.pid();
            Some(args.with_values(process, |process, values| {
                let result = call_inner(process, Some(ctx), ctx_pid, EtsBif::$id, values);
                bif_frame($module, $function, values, result)
            }))
        }
    };
}

fn entry_insert(
    _vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    args: super::NativeArgs<'_>,
) -> Option<Result<Term, VmError>> {
    if args.len() != 2 {
        return Some(Err(badarg()));
    }
    let (Some(target), Some(objects)) = (args.get(process, 0), args.get(process, 1)) else {
        return Some(Err(badarg()));
    };
    let own_list_insert = matches!(
        process
            .cold
            .as_ref()
            .and_then(|cold| cold.ets_insert.as_deref()),
        Some(EtsInsert::Global(_))
    );
    if let Err(error) = help_busy_table(process, ctx, target, own_list_insert) {
        return Some(Err(error));
    }
    let result = {
        let caller = caller_of(ctx);
        insert_args(process, Some(ctx), caller, false, target, objects)
    };
    Some(bif_frame("ets", "insert", &[target, objects], result))
}

fn entry_insert_new(
    _vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    args: super::NativeArgs<'_>,
) -> Option<Result<Term, VmError>> {
    if args.len() != 2 {
        return Some(Err(badarg()));
    }
    let (Some(target), Some(objects)) = (args.get(process, 0), args.get(process, 1)) else {
        return Some(Err(badarg()));
    };
    let own_list_insert = matches!(
        process
            .cold
            .as_ref()
            .and_then(|cold| cold.ets_insert.as_deref()),
        Some(EtsInsert::Global(_))
    );
    if let Err(error) = help_busy_table(process, ctx, target, own_list_insert) {
        return Some(Err(error));
    }
    let result = {
        let caller = caller_of(ctx);
        insert_args(process, Some(ctx), caller, true, target, objects)
    };
    Some(bif_frame("ets", "insert_new", &[target, objects], result))
}

fn entry_lookup(
    _vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    args: super::NativeArgs<'_>,
) -> Option<Result<Term, VmError>> {
    if args.len() != 2 {
        return Some(Err(badarg()));
    }
    let (Some(target), Some(key)) = (args.get(process, 0), args.get(process, 1)) else {
        return Some(Err(badarg()));
    };
    if let Err(error) = help_busy_table(process, ctx, target, false) {
        return Some(Err(error));
    }
    let result = lookup_args(process, caller_of(ctx), false, target, key);
    Some(bif_frame("ets", "lookup", &[target, key], result))
}

fn entry_member(
    _vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    args: super::NativeArgs<'_>,
) -> Option<Result<Term, VmError>> {
    if args.len() != 2 {
        return Some(Err(badarg()));
    }
    let (Some(target), Some(key)) = (args.get(process, 0), args.get(process, 1)) else {
        return Some(Err(badarg()));
    };
    if let Err(error) = help_busy_table(process, ctx, target, false) {
        return Some(Err(error));
    }
    let result = lookup_args(process, caller_of(ctx), true, target, key);
    Some(bif_frame("ets", "member", &[target, key], result))
}

ets_entry!(entry_new, New, 2, "ets", "new");
ets_entry!(
    entry_match_spec_test,
    MatchSpecTest,
    3,
    "erlang",
    "match_spec_test"
);
ets_entry!(
    entry_lookup_binary_info,
    LookupBinaryInfo,
    2,
    "erts_internal",
    "ets_lookup_binary_info"
);
ets_entry!(
    entry_raw_first,
    RawFirst,
    1,
    "erts_internal",
    "ets_raw_first"
);
ets_entry!(entry_raw_next, RawNext, 2, "erts_internal", "ets_raw_next");
ets_entry!(
    entry_super_user,
    SuperUser,
    1,
    "erts_internal",
    "ets_super_user"
);
ets_entry!(
    entry_internal_delete_all,
    InternalDeleteAll,
    2,
    "ets",
    "internal_delete_all"
);
ets_entry!(entry_setopts, SetOpts, 2, "ets", "setopts");
ets_entry!(entry_whereis, Whereis, 1, "ets", "whereis");
ets_entry!(entry_rename, Rename, 2, "ets", "rename");
ets_entry!(entry_info_1, Info, 1, "ets", "info");
fn entry_info_2(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    args: super::NativeArgs<'_>,
) -> Option<Result<Term, VmError>> {
    if args.len() != 2 {
        return Some(Err(badarg()));
    }
    let (Some(target), Some(item)) = (args.get(process, 0), args.get(process, 1)) else {
        return Some(Err(badarg()));
    };
    if item == atom("binary") {
        // Port of erts/emulator/beam/erl_db.c (ets_info_2 traps to
        // ets_info_binary_trap), OTP-29.1.1. The Erlang export owns the walk so
        // each raw ETS operation has its own reductions and releases its table lock.
        return Some(Err(VmError::TrapExport(crate::ExportTrap {
            continuation: "erts_internal:ets_info_binary/1",
            args: vec![target],
        })));
    }
    let _ = vm;
    let ctx_pid = ctx.pid();
    Some(args.with_values(process, |process, values| {
        let result = call_inner(process, Some(ctx), ctx_pid, EtsBif::Info, values);
        bif_frame("ets", "info", values, result)
    }))
}
ets_entry!(entry_delete_1, Delete, 1, "ets", "delete");
ets_entry!(entry_delete_2, Delete, 2, "ets", "delete");
ets_entry!(entry_take, Take, 2, "ets", "take");
ets_entry!(entry_slot, Slot, 2, "ets", "slot");
ets_entry!(entry_first, First, 1, "ets", "first");
ets_entry!(entry_first_lookup, FirstLookup, 1, "ets", "first_lookup");
ets_entry!(entry_last, Last, 1, "ets", "last");
ets_entry!(entry_last_lookup, LastLookup, 1, "ets", "last_lookup");
ets_entry!(entry_next, Next, 2, "ets", "next");
ets_entry!(entry_next_lookup, NextLookup, 2, "ets", "next_lookup");
ets_entry!(entry_prev, Prev, 2, "ets", "prev");
ets_entry!(entry_prev_lookup, PrevLookup, 2, "ets", "prev_lookup");
ets_entry!(entry_safe_fixtable, SafeFixtable, 2, "ets", "safe_fixtable");
ets_entry!(entry_delete_object, DeleteObject, 2, "ets", "delete_object");
ets_entry!(entry_give_away, GiveAway, 3, "ets", "give_away");
ets_entry!(entry_select_1, Select, 1, "ets", "select");
ets_entry!(entry_select_2, Select, 2, "ets", "select");
ets_entry!(entry_select_3, Select, 3, "ets", "select");
ets_entry!(
    entry_select_reverse_1,
    SelectReverse,
    1,
    "ets",
    "select_reverse"
);
ets_entry!(
    entry_select_reverse_2,
    SelectReverse,
    2,
    "ets",
    "select_reverse"
);
ets_entry!(
    entry_select_reverse_3,
    SelectReverse,
    3,
    "ets",
    "select_reverse"
);
ets_entry!(entry_match_1, Match, 1, "ets", "match");
ets_entry!(entry_match_2, Match, 2, "ets", "match");
ets_entry!(entry_match_3, Match, 3, "ets", "match");
ets_entry!(entry_match_object_1, MatchObject, 1, "ets", "match_object");
ets_entry!(entry_match_object_2, MatchObject, 2, "ets", "match_object");
ets_entry!(entry_match_object_3, MatchObject, 3, "ets", "match_object");
ets_entry!(
    entry_match_spec_compile,
    MatchSpecCompile,
    1,
    "ets",
    "match_spec_compile"
);
ets_entry!(
    entry_is_compiled_ms,
    IsCompiledMs,
    1,
    "ets",
    "is_compiled_ms"
);
ets_entry!(
    entry_internal_request_all,
    InternalRequestAll,
    0,
    "ets",
    "internal_request_all"
);
ets_entry!(
    entry_match_spec_run_r,
    MatchSpecRunR,
    3,
    "ets",
    "match_spec_run_r"
);
ets_entry!(entry_select_count, SelectCount, 2, "ets", "select_count");
ets_entry!(
    entry_internal_select_delete,
    InternalSelectDelete,
    2,
    "ets",
    "internal_select_delete"
);
ets_entry!(
    entry_select_replace,
    SelectReplace,
    2,
    "ets",
    "select_replace"
);
ets_entry!(
    entry_lookup_element_3,
    LookupElement,
    3,
    "ets",
    "lookup_element"
);
ets_entry!(
    entry_lookup_element_4,
    LookupElement,
    4,
    "ets",
    "lookup_element"
);
ets_entry!(
    entry_update_element_3,
    UpdateElement,
    3,
    "ets",
    "update_element"
);
ets_entry!(
    entry_update_element_4,
    UpdateElement,
    4,
    "ets",
    "update_element"
);
ets_entry!(
    entry_update_counter_3,
    UpdateCounter,
    3,
    "ets",
    "update_counter"
);
ets_entry!(
    entry_update_counter_4,
    UpdateCounter,
    4,
    "ets",
    "update_counter"
);

pub(crate) fn handler(module: &str, function: &str, arity: u8) -> Option<super::ResolvedNative> {
    match (module, function, arity) {
        ("erlang", "match_spec_test", 3) => return Some(entry_match_spec_test),
        ("erts_internal", "ets_lookup_binary_info", 2) => return Some(entry_lookup_binary_info),
        ("erts_internal", "ets_raw_first", 1) => return Some(entry_raw_first),
        ("erts_internal", "ets_raw_next", 2) => return Some(entry_raw_next),
        ("erts_internal", "ets_super_user", 1) => return Some(entry_super_user),
        ("ets", "internal_delete_all", 2) => return Some(entry_internal_delete_all),
        ("ets", "setopts", 2) => return Some(entry_setopts),
        _ if module != "ets" => return None,
        _ => {}
    }
    match (function, arity) {
        ("new", 2) => Some(entry_new),
        ("whereis", 1) => Some(entry_whereis),
        ("rename", 2) => Some(entry_rename),
        ("info", 1) => Some(entry_info_1),
        ("info", 2) => Some(entry_info_2),
        ("delete", 1) => Some(entry_delete_1),
        ("delete", 2) => Some(entry_delete_2),
        ("insert", 2) => Some(entry_insert),
        ("insert_new", 2) => Some(entry_insert_new),
        ("lookup", 2) => Some(entry_lookup),
        ("member", 2) => Some(entry_member),
        ("take", 2) => Some(entry_take),
        ("slot", 2) => Some(entry_slot),
        ("first", 1) => Some(entry_first),
        ("first_lookup", 1) => Some(entry_first_lookup),
        ("last", 1) => Some(entry_last),
        ("last_lookup", 1) => Some(entry_last_lookup),
        ("next", 2) => Some(entry_next),
        ("next_lookup", 2) => Some(entry_next_lookup),
        ("prev", 2) => Some(entry_prev),
        ("prev_lookup", 2) => Some(entry_prev_lookup),
        ("safe_fixtable", 2) => Some(entry_safe_fixtable),
        ("delete_object", 2) => Some(entry_delete_object),
        ("give_away", 3) => Some(entry_give_away),
        ("select", 1) => Some(entry_select_1),
        ("select", 2) => Some(entry_select_2),
        ("select", 3) => Some(entry_select_3),
        ("select_reverse", 1) => Some(entry_select_reverse_1),
        ("select_reverse", 2) => Some(entry_select_reverse_2),
        ("select_reverse", 3) => Some(entry_select_reverse_3),
        ("match", 1) => Some(entry_match_1),
        ("match", 2) => Some(entry_match_2),
        ("match", 3) => Some(entry_match_3),
        ("match_object", 1) => Some(entry_match_object_1),
        ("match_object", 2) => Some(entry_match_object_2),
        ("match_object", 3) => Some(entry_match_object_3),
        ("match_spec_compile", 1) => Some(entry_match_spec_compile),
        ("is_compiled_ms", 1) => Some(entry_is_compiled_ms),
        ("internal_request_all", 0) => Some(entry_internal_request_all),
        ("match_spec_run_r", 3) => Some(entry_match_spec_run_r),
        ("select_count", 2) => Some(entry_select_count),
        ("internal_select_delete", 2) => Some(entry_internal_select_delete),
        ("select_replace", 2) => Some(entry_select_replace),
        ("lookup_element", 3) => Some(entry_lookup_element_3),
        ("lookup_element", 4) => Some(entry_lookup_element_4),
        ("update_element", 3) => Some(entry_update_element_3),
        ("update_element", 4) => Some(entry_update_element_4),
        ("update_counter", 3) => Some(entry_update_counter_3),
        ("update_counter", 4) => Some(entry_update_counter_4),
        _ => None,
    }
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn recognizes(module: &str, function: &str, arity: u8) -> bool {
    super::listed(IMPLEMENTED, module, function, arity)
}

pub(crate) fn call(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    module: &str,
    function: &str,
    args: super::NativeArgs<'_>,
) -> Option<Result<Term, VmError>> {
    let entry = handler(module, function, u8::try_from(args.len()).ok()?)?;
    entry(vm, process, ctx, args)
}
