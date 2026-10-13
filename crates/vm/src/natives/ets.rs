//! ETS BIFs whose storage and access policy belong to the scheduled runtime.

use crate::proc_create::EtsFree;
use crate::process::Message;
use crate::{Process, Vm, VmError};
use arinsal_ets::match_spec::MatchDialect;
use arinsal_ets::match_spec::MatchProgram;
use arinsal_ets::{
    BigCounterOp, CounterOp, ElementLookup, EtsError, Heir, Protection, SelectContinuation, Table,
    TableOptions, TableType, Tid, WriteConcurrency,
};
use arinsal_sched::{Pid, RunCtx};
use arinsal_term::{HeapAlloc, Term, TermBuilder, TermKind, copy_term, global_atoms};
use num_bigint::BigInt;
use std::collections::{HashMap, HashSet};
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

// Port of erts/emulator/beam/erl_db.c:4713 (`erts_internal_ets_super_user_1`),
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
    /// `p->fvalue` next to `BADARG | EXF_HAS_EXT_INFO` (erl_db.c:53-63), OTP-29.1.1.
    static BIF_CAUSE: std::cell::Cell<Option<&'static str>> = const { std::cell::Cell::new(None) };
}

/// `badarg` with an erts `EXI_*` cause for the BIF frame's `error_info`.
fn badarg_cause(cause: &'static str) -> VmError {
    BIF_CAUSE.with(|slot| slot.set(Some(cause)));
    badarg()
}

/// Attach the failing BIF as the top stack frame, as erts does for every ETS BIF.
// Port of erts/emulator/beam/beam_common.c:900-998 (save_stacktrace), OTP-29.1.1.
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
        // Per-thread cache keyed by the literal's address: every failing ETS BIF passes
        // through here, and the shared atom table takes a lock plus a SipHash per name.
        thread_local! {
            static NAMES: std::cell::RefCell<std::collections::HashMap<(usize, usize), arinsal_term::Atom>> =
                std::cell::RefCell::new(std::collections::HashMap::new());
        }
        let intern = |name: &'static str| {
            let key = (name.as_ptr() as usize, name.len());
            if let Some(atom) = NAMES.with(|names| names.borrow().get(&key).copied()) {
                return Ok(atom);
            }
            let atom = arinsal_term::global_atoms()
                .intern(name)
                .map_err(|_| VmError::Unsupported(format!("BIF frame atom {name}")))?;
            NAMES.with(|names| names.borrow_mut().insert(key, atom));
            Ok(atom)
        };
        trap.top = Some(crate::stacktrace::TopFrame::Bif {
            module: intern(module)?,
            function: intern(function)?,
            args: crate::stacktrace::BifArgs::from_terms(args)?,
            info: match cause {
                Some(cause) => crate::stacktrace::BifErrorInfo::Cause(Term::atom(intern(cause)?)),
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
fn list(term: Term) -> Option<Vec<Term>> {
    let mut result = Vec::new();
    let mut tail = term;
    while tail.classify() == TermKind::List {
        // SAFETY: the BIF call keeps the caller heap stable.
        let (head, next) = unsafe { tail.cons_ref()? };
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
        // Port of erts/emulator/beam/erl_db.c:1450 (DB_ERROR_SYSRES -> SYSTEM_LIMIT), OTP-29.1.1.
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

// Port of erts/emulator/beam/erl_db.c:446-500 (db_lock read/write modes), OTP-29.1.1.
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

// Port of erts/emulator/beam/erl_db.c:280-306 (tid2tab) and :805-910
// (db_get_table_aux), OTP-29.1.1.
fn handle(registry: &arinsal_ets::Registry, term: Term) -> Result<Tid, VmError> {
    resolve(registry, term).map_err(|fail| match fail {
        ResolveFail::BadType => badarg_cause("type"),
        ResolveFail::Missing => badarg_cause("id"),
    })
}

/// `erlang:system_info(schedulers)`. `ets:all/0` receives exactly this many replies.
fn scheduler_count() -> usize {
    std::thread::available_parallelism().map_or(1, usize::from)
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
                tid.to_term(heap).map_err(|_| badarg())
            }
        })
        .collect()
}
fn allowed(table: &arinsal_ets::Table, caller: Term, write: bool) -> bool {
    // Port of erts/emulator/beam/erl_db.c:800 (db_get_table_aux), OTP-29.1.1.
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
// Port of erts/emulator/beam/erl_db.c:1517-1529 (do_update_counter, the UpdateOp forms),
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
    let ops = update_list(operation, parse)
        .into_iter()
        .collect::<Option<smallvec::SmallVec<_>>>()?;
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
        output_list(heap, values.to_vec())
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
// Port of erts/emulator/beam/erl_db.c:1480-1488 and :1718-1726, OTP-29.1.1.
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
fn tuple_items(term: Term) -> Option<Vec<Term>> {
    // SAFETY: BIF arguments are rooted in the caller's process heap.
    let tuple = unsafe { term.tuple_ref() }?;
    Some(tuple.iter().collect())
}

fn output_list<H: HeapAlloc>(heap: &mut H, items: Vec<Term>) -> Result<Term, VmError> {
    TermBuilder::new(heap)
        .list_from_iter(items)
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
pub(crate) type DirectEts = fn(&mut Process, &[Term]) -> Option<Term>;

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
        ("insert", 2) => Some(direct_insert),
        ("insert_new", 2) => Some(direct_insert_new),
        ("update_counter", 3 | 4) => Some(direct_update_counter),
        ("new", 2) => Some(direct_bif::<{ EtsBif::New as u8 }>),
        ("whereis", 1) => Some(direct_bif::<{ EtsBif::Whereis as u8 }>),
        ("rename", 2) => Some(direct_bif::<{ EtsBif::Rename as u8 }>),
        ("info", 1) => Some(direct_bif::<{ EtsBif::Info as u8 }>),
        ("info", 2) => Some(direct_info_2),
        ("delete", 2) => Some(direct_bif::<{ EtsBif::Delete as u8 }>),
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
        ("lookup_element", 3 | 4) => Some(direct_bif::<{ EtsBif::LookupElement as u8 }>),
        ("update_element", 3 | 4) => Some(direct_bif::<{ EtsBif::UpdateElement as u8 }>),
        _ => None,
    }
}

/// Run a table BIF from the caller pid alone, once. A failure is raised from here with the
/// BIF frame, as erts' BIF returns THE_NON_VALUE with `freason` set and BeamAsm raises it.
fn direct_bif<const BIF: u8>(process: &mut Process, args: &[Term]) -> Option<Term> {
    let caller = process.self_pid?;
    let function = EtsBif::from_u8(BIF);
    let result = call_inner(process, None, caller, function, args);
    finish_direct(process, function.name(), args, result)
}

/// `ets:info/2`: the `binary` item traps to an Erlang export, which only the scheduler path runs.
// Port of erts/emulator/beam/erl_db.c:4541-4542 (ets_info_2: BIF_TRAP1 ets_info_binary_trap),
// OTP-29.1.1.
fn direct_info_2(process: &mut Process, args: &[Term]) -> Option<Term> {
    if args.get(1).copied() == Some(atom("binary")) {
        return None;
    }
    direct_bif::<{ EtsBif::Info as u8 }>(process, args)
}

/// Value of a finished direct call, or `Some` dummy with `freason` set after the failure has
/// been parked for the native exit. Never declines: the call already ran.
fn finish_direct(
    process: &mut Process,
    function: &'static str,
    args: &[Term],
    result: Result<Term, VmError>,
) -> Option<Term> {
    match bif_frame("ets", function, args, result) {
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
            process.cold_mut().native_trap = Some(crate::proc_create::NativeTrap {
                trap,
                freason: class,
                fvalue,
            });
            Some(Term::NIL)
        }
        // Not an Erlang exception (yield, unsupported): redo on the scheduler path.
        Err(_) => None,
    }
}

/// `erlang:system_info(scheduler_id)` from the generated code: the process knows its scheduler,
/// as erts reads `c_p->scheduler_data`. Every other item takes the scheduler path.
// Port of erts/emulator/beam/erl_bif_info.c:2784 (system_info scheduler_id), OTP-29.1.1.
fn direct_system_info(process: &mut Process, args: &[Term]) -> Option<Term> {
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

fn direct_caller(process: &Process) -> Option<Term> {
    process.self_pid?.to_term()
}

/// Runtime, table identity, lock handle and creation options of a cached table.
type CachedTable = (usize, Tid, arinsal_ets::SharedTable, TableOptions);

thread_local! {
    /// Per-scheduler handles of recently used tables, keyed by runtime and table identity, so
    /// a call takes no registry lock: erts reaches a table through its lock-free
    /// `meta_main_tab` (erl_db.c:805 db_get_table_aux). A deleted table is caught by its
    /// `detached` flag under the table lock.
    static TABLE_CACHE: std::cell::RefCell<[Option<CachedTable>; 32]> =
        const { std::cell::RefCell::new([const { None }; 32]) };
}

/// Run `body` on the locked-table handle of a table reference, `None` for anything but a
/// live unnamed table (named tables take the scheduler path).
fn with_cached_table<R>(
    process: &mut Process,
    target: Term,
    body: impl FnOnce(&arinsal_ets::SharedTable, &TableOptions, &mut Process) -> Option<R>,
) -> Option<R> {
    let tid = Tid::from_term(target)?;
    let rt_id = std::sync::Arc::as_ptr(process.runtime.as_ref()?) as usize;
    let slot = (tid.0.wrapping_mul(0x9e37_79b9_7f4a_7c15) >> 59) as usize;
    TABLE_CACHE.with(|cache| {
        let hit = cache.borrow()[slot]
            .as_ref()
            .is_some_and(|(cached_rt, cached, ..)| *cached_rt == rt_id && *cached == tid);
        if !hit {
            let rt = process.runtime.as_ref()?;
            let shared = rt.ets.read().unwrap().shared(tid).ok()?.clone();
            let options = shared.read().options;
            cache.borrow_mut()[slot] = Some((rt_id, tid, shared, options));
        }
        let cache = cache.borrow();
        let (_, _, shared, options) = cache[slot].as_ref()?;
        body(shared, options, process)
    })
}

fn direct_lookup(process: &mut Process, args: &[Term]) -> Option<Term> {
    direct_lookup_cached(process, args)
        .or_else(|| direct_plain(process, args, "lookup", lookup_args_member))
}

/// `lookup`/`member`/`insert`/`insert_new` through the registry, for named tables and
/// anything the cached path declines.
fn direct_plain(
    process: &mut Process,
    args: &[Term],
    function: &'static str,
    run: fn(&mut Process, Term, Term, Term) -> Result<Term, VmError>,
) -> Option<Term> {
    let caller = direct_caller(process)?;
    let result = run(process, caller, args[0], args[1]);
    finish_direct(process, function, args, result)
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
    let caller = direct_caller(process)?;
    let key = args[1];
    with_cached_table(process, args[0], |shared, _options, process| {
        let table = shared.read();
        if table.is_detached() || !allowed(&table, caller, false) {
            return None;
        }
        let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
        // Port of erts/emulator/beam/erl_db_hash.c:1492 (db_get_hash) and
        // erl_db_tree.c:1046 (db_get_tree), OTP-29.1.1: a set holds at most one object,
        // consed straight onto the process heap.
        if matches!(
            table.options.table_type,
            TableType::Set | TableType::OrderedSet
        ) {
            let found = table.lookup_one(key, &mut heap).ok()?;
            let mut builder = TermBuilder::new(&mut heap);
            return match found {
                Some(object) => builder.cons(object, Term::NIL).ok(),
                None => Some(Term::NIL),
            };
        }
        let values = table.lookup(key, &mut heap).ok()?;
        output_list(&mut heap, values).ok()
    })
}

fn direct_member(process: &mut Process, args: &[Term]) -> Option<Term> {
    direct_member_cached(process, args).or_else(|| {
        direct_plain(process, args, "member", |process, caller, target, key| {
            lookup_args(process, caller, true, target, key)
        })
    })
}

fn direct_member_cached(process: &mut Process, args: &[Term]) -> Option<Term> {
    let caller = direct_caller(process)?;
    let key = args[1];
    with_cached_table(process, args[0], |shared, _options, _| {
        let table = shared.read();
        if table.is_detached() || !allowed(&table, caller, false) {
            return None;
        }
        Some(boolean_term(table.member(key)))
    })
}

fn direct_insert(process: &mut Process, args: &[Term]) -> Option<Term> {
    direct_insert_cached(process, args).or_else(|| {
        direct_plain(
            process,
            args,
            "insert",
            |process, caller, target, objects| insert_args(process, caller, false, target, objects),
        )
    })
}

fn direct_insert_new(process: &mut Process, args: &[Term]) -> Option<Term> {
    direct_plain(
        process,
        args,
        "insert_new",
        |process, caller, target, objects| insert_args(process, caller, true, target, objects),
    )
}

fn direct_insert_cached(process: &mut Process, args: &[Term]) -> Option<Term> {
    // A failed list insert may have stored a prefix, which a redo through the scheduler
    // path would store again.
    // SAFETY: the object term lives in the caller's process heap for this call.
    unsafe { args[1].tuple_ref() }?;
    let caller = direct_caller(process)?;
    let object = args[1];
    with_cached_table(process, args[0], |shared, options, _| {
        // The copy into table storage is the long part of an insert: do it before the
        // exclusive lock so readers are not held up behind it.
        let prepared = Table::prepare_object(options, object).ok()?;
        // Fine-grained hash tables and CA trees take their bucket or route locks.
        let prepared = if options.write_concurrency != WriteConcurrency::Disabled {
            let table = shared.read();
            if table.is_detached() || !allowed(&table, caller, true) {
                return None;
            }
            match table.insert_shared(prepared) {
                None => return Some(boolean_term(true)),
                Some(prepared) => prepared,
            }
        } else {
            prepared
        };
        let mut table = shared.write();
        if table.is_detached() || !allowed(&table, caller, true) {
            return None;
        }
        table.insert_prepared(prepared);
        Some(boolean_term(true))
    })
}

/// `ets:update_counter/3,4` on small counters, updated in place under the table lock.
// Port of erts/emulator/beam/erl_db.c:1494-1728 (do_update_counter, ets_update_counter_3/4),
// OTP-29.1.1.
fn direct_update_counter(process: &mut Process, args: &[Term]) -> Option<Term> {
    direct_update_counter_cached(process, args)
        .or_else(|| direct_bif::<{ EtsBif::UpdateCounter as u8 }>(process, args))
}

fn direct_update_counter_cached(process: &mut Process, args: &[Term]) -> Option<Term> {
    let caller = direct_caller(process)?;
    let (key, operation, default) = (args[1], args[2], args.get(3).copied());
    with_cached_table(process, args[0], |shared, options, process| {
        let (operations, single) = small_counter_ops(options.keypos, operation)?;
        // erl_db.c:1718-1726: a malformed default fails even when the key exists.
        if let Some(default) = default
            && tuple_items(default)?.len() < options.keypos
        {
            return None;
        }
        let values = if options.write_concurrency != WriteConcurrency::Disabled
            && options.table_type == TableType::Set
        {
            let table = shared.read();
            if table.is_detached() || !allowed(&table, caller, true) {
                return None;
            }
            table.update_counter_in_place_shared(key, &operations)?
        } else {
            let mut table = shared.write();
            if table.is_detached() || !allowed(&table, caller, true) {
                return None;
            }
            table.update_counter_in_place(key, &operations)?
        };
        // The counters are immediates: only a result list needs the heap, and the process
        // heap grows rather than fail, so the update is never redone.
        let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
        counter_results(&mut heap, &values, single).ok()
    })
}

fn insert_args(
    process: &mut Process,
    caller: Term,
    insert_new: bool,
    target: Term,
    objects: Term,
) -> Result<Term, VmError> {
    let rt = process.runtime.as_ref().ok_or_else(badarg)?;
    let registry = rt.ets.read().unwrap();
    let tid = handle(&registry, target)?;
    // SAFETY: object terms remain in the caller's live process heap for this BIF.
    let single = unsafe { objects.tuple_ref() }.is_some();
    let shared = registry.shared(tid).map_err(err)?;
    let options = shared.read().options;
    if single
        && options.write_concurrency != WriteConcurrency::Disabled
        && options.table_type != TableType::OrderedSet
    {
        let table = shared.read();
        if !allowed(&table, caller, true) {
            return Err(badarg_cause("access"));
        }
        let prepared = Table::prepare_object(&options, objects).map_err(err)?;
        let yes = if insert_new {
            table.insert_new_prepared_shared(prepared).map_err(err)?
        } else {
            if table.insert_shared(prepared).is_some() {
                return Err(badarg());
            }
            true
        };
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

fn lookup_args(
    process: &mut Process,
    caller: Term,
    member: bool,
    target: Term,
    key: Term,
) -> Result<Term, VmError> {
    let rt = process.runtime.as_ref().ok_or_else(badarg)?;
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
        let values = table.lookup(key, &mut heap).map_err(err)?;
        output_list(&mut heap, values)
    }
}

fn lookup_element_locked(
    table: &arinsal_ets::Table,
    caller: Term,
    key: Term,
    position: usize,
    default: Option<Term>,
    heap: &mut arinsal_bifs::ProcessHeapHandle<'_>,
) -> Result<Term, VmError> {
    if !allowed(table, caller, false) {
        return Err(badarg_cause("access"));
    }
    if default.is_none()
        && !matches!(
            table.options.table_type,
            TableType::Bag | TableType::DuplicateBag
        )
    {
        return table.lookup_element_one(key, position, heap).map_err(err);
    }
    let values = if let Some(default) = default {
        match table
            .lookup_element_default(key, position, default, heap)
            .map_err(err)?
        {
            ElementLookup::Values(values) => values,
            ElementLookup::Default(value) => return Ok(value),
        }
    } else {
        table.lookup_element(key, position, heap).map_err(err)?
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

/// `ets:delete/1` and `ets:internal_delete_all/2`: release the storage a slice of reductions
/// at a time, trapping to the same BIF until it is all released.
///
/// Port of erts/emulator/beam/erl_db.c:3006 (ets_delete_1), :3234 (ets_internal_delete_all_2),
/// :5378 (ets_delete_trap) and :5405 (free_table_continue), OTP-29.1.1.
fn delete_or_clear(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    function: EtsBif,
    args: &[Term],
    caller: Term,
) -> Result<Term, VmError> {
    let rt = process.runtime.clone().ok_or_else(badarg)?;
    let initial = ctx.remaining() as isize;
    let mut reds = initial;
    let mut state = process.cold.as_mut().and_then(|cold| cold.ets_free.take());
    let done = if let Some(state) = state.as_mut() {
        // Trapped before: the table is already unreachable (delete) or empty (delete_all).
        match state.tid {
            None => state.garbage.step(&mut reds),
            Some(tid) => {
                let registry = rt.ets.read().unwrap();
                let mut table = registry.get_mut(tid).map_err(err)?;
                table.free_garbage(&mut state.garbage, &mut reds)
            }
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
        state = Some(fresh);
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
        let mut fresh = EtsFree {
            tid: Some(tid),
            nitems,
            garbage: table.take_garbage(false),
        };
        let done = table.free_garbage(&mut fresh.garbage, &mut reds);
        state = Some(fresh);
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
        // Port of erts/emulator/beam/erl_db_util.c:6045-6121
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
    if matches!(
        (function, args.len()),
        (EtsBif::Delete, 1) | (EtsBif::InternalDeleteAll, 2)
    ) {
        let ctx = ctx.as_deref_mut().ok_or_else(needs_context)?;
        return delete_or_clear(process, ctx, function, args, caller);
    }
    let rt = process.runtime.as_ref().ok_or_else(badarg)?;
    // Port of erts/emulator/beam/erl_db.c:446-500 (db_lock), OTP-29.1.1: table operations
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
            // Port of erts/emulator/beam/erl_db.c:2560-2715 (ets_new_2 option state), OTP-29.1.1.
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
                            // Port of erts/emulator/beam/erl_db.c:2642-2649, OTP-29.1.1.
                            opts.decentralized_counters = true;
                            let count = *count as usize;
                            // Port of erts/emulator/beam/erl_db_hash.c:1044-1048:
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
                            // Port of erts/emulator/beam/erl_db.c:5319-5337 (set_heir),
                            // OTP-29.1.1: a dead heir leaves the table without one.
                            opts.heir = None;
                            if let Some(started_interval) = rt
                                .scheduler()
                                .map_err(|_| badarg())?
                                .started_interval(heir_pid)
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
            // Port of erts/emulator/beam/erl_db.c:2810-2831 (ets_new_2), OTP-29.1.1.
            let tid = registry
                .exclusive()?
                .create(opts)
                .map_err(|error| match error {
                    EtsError::NameTaken => badarg_cause("already_exists"),
                    error => err(error),
                })?;
            // erl_db.c:2834: BIF_P->flags |= F_USING_DB so exit can find the table.
            if !rt.publish_proc_flag(caller_pid, arinsal_sched::proc_flags::USING_DB) {
                registry.exclusive()?.detach(tid).ok();
                return Err(badarg());
            }
            if registry.get(tid).map_err(err)?.options.named_table {
                Ok(Term::atom(name.as_atom().unwrap()))
            } else {
                tid.to_term(&mut heap).map_err(|_| badarg())
            }
        }
        (EtsBif::Whereis, [name]) => Ok(registry
            .whereis(name.as_atom().ok_or_else(badarg)?)
            .map(|tid| tid.to_term(&mut heap))
            .transpose()
            .map_err(|_| badarg())?
            .unwrap_or(atom("undefined"))),
        (EtsBif::Rename, [target, name]) => {
            // Port of erts/emulator/beam/erl_db.c:2444-2503 (ets_rename_2), OTP-29.1.1:
            // the table needs write access, and is looked up even for a bad name.
            let tid = handle(&registry, *target)?;
            let named = {
                let table = registry.get(tid).map_err(err)?;
                if !allowed(&table, caller, true) {
                    return Err(badarg_cause("access"));
                }
                table.options.named_table
            };
            let new_name = name.as_atom().ok_or_else(badarg)?;
            registry.exclusive()?.rename(tid, new_name).map_err(err)?;
            // Unnamed tables keep their id; only the displayed name changes.
            // Port of erts/emulator/beam/erl_db.c:2523 (ets_rename_2), OTP-29.1.1.
            if named { Ok(*name) } else { Ok(*target) }
        }
        (EtsBif::Info, [target]) | (EtsBif::Info, [target, _]) => {
            // Missing tables yield `undefined`; a non-id argument is `badarg`.
            // Port of erts/emulator/beam/erl_db.c:4434 and :4544, OTP-29.1.1.
            let tid = match resolve(&registry, *target) {
                Ok(tid) => tid,
                Err(ResolveFail::Missing) => return Ok(atom("undefined")),
                Err(ResolveFail::BadType) => return Err(badarg_cause("type")),
            };
            // Port of erts/emulator/beam/erl_db.c:4532-4564 (ets_info_2, DB_INFO/LCK_READ),
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
                .read()
                .options
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
        // Port of erts/emulator/beam/erl_db.c:4648 and erl_db_hash.c:4117,
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
        // Port of erts/emulator/beam/erl_db.c:3146 (`ets_setopts_2`),
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
                            .started_interval(pid);
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
        // Port of erts/emulator/beam/erl_db.c:4672 (`erts_internal_ets_raw_first_1`),
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
        // Port of erts/emulator/beam/erl_db.c:4692 (`erts_internal_ets_raw_next_2`),
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
                .read()
                .options
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
            // Port of erts/emulator/beam/erl_db_tree.c:654, OTP-29.1.1.
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
        // Port of erts/emulator/beam/erl_db.c:1193 (ets_first_lookup_1),
        // :1238 (ets_next_lookup_2), :1286 (ets_last_lookup_1) and
        // :1332 (ets_prev_lookup_2), OTP-29.1.1. Hash tables treat last as
        // first and prev as next (erl_db_hash.c:893).
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
                // Port of erts/emulator/beam/erl_db.c:5148-5161 (fix_table_locked), OTP-29.1.1.
                let micros = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|_| badarg())?
                    .as_micros();
                let system_time = TermBuilder::new(&mut heap)
                    .tuple(&[
                        Term::small((micros / 1_000_000_000_000) as i64).ok_or_else(badarg)?,
                        Term::small(((micros / 1_000_000) % 1_000_000) as i64)
                            .ok_or_else(badarg)?,
                        Term::small((micros % 1_000_000) as i64).ok_or_else(badarg)?,
                    ])
                    .map_err(|_| system_limit())?;
                let monotonic_time = TermBuilder::new(&mut heap)
                    .int_from_i128(arinsal_bifs::monotonic_time_nanos())
                    .map_err(|_| system_limit())?;
                table
                    .safe_fixtable_for_at(caller, true, system_time, monotonic_time)
                    .map_err(err)?;
                drop(table);
                registry.exclusive()?.note_fixation(caller, tid);
                // erl_db.c:3048 and 5187: a fixation sets F_USING_DB on the fixing process.
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
                .read()
                .options
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
            // Port of erts/emulator/beam/erl_db.c:3087-3124 (ets_give_away_3), OTP-29.1.1:
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
            // Port of erts/emulator/beam/erl_db.c:4959-4962 (send_ets_transfer_message),
            // OTP-29.1.1: a named table is identified by its name.
            let tab = if options.named_table {
                Term::atom(options.name)
            } else {
                tid.to_term(&mut heap).map_err(|_| badarg())?
            };
            let transfer = TermBuilder::new(&mut heap)
                .tuple(&[atom("ETS-TRANSFER"), tab, caller, *data])
                .map_err(|_| badarg())?;
            registry.exclusive()?.give_away(tid, *new_owner).map_err(err)?;
            // erl_db.c:3128: the receiver's F_USING_DB is set so its exit deletes the table.
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
        (EtsBif::Select | EtsBif::SelectReverse, [target, spec, limit])
        | (EtsBif::Match, [target, spec, limit])
        | (EtsBif::MatchObject, [target, spec, limit]) => {
            let tid = handle(&registry, *target)?;
            let (program, result, retain) = {
                let table = table_guard(&registry, tid, true)?;
                if !allowed(&table, caller, false) {
                    return Err(badarg_cause("access"));
                }
                // Table errors precede the chunk size check (erl_db.c:3792-3841).
                let limit = limit
                    .as_small()
                    .and_then(|n| usize::try_from(n).ok())
                    .ok_or_else(badarg)?;
                // Chunk size is strictly greater than 0. Port of erl_db.c:3828, OTP-29.1.1.
                if limit == 0 {
                    return Err(badarg());
                }
                if matches!(function, EtsBif::Select | EtsBif::SelectReverse)
                    && *spec == Term::NIL
                {
                    return Ok(atom("$end_of_table"));
                }
                let program = match function {
                    EtsBif::Select | EtsBif::SelectReverse => MatchProgram::compile(*spec),
                    EtsBif::Match => MatchProgram::from_pattern(*spec, false),
                    EtsBif::MatchObject => MatchProgram::from_pattern(*spec, true),
                    _ => unreachable!(),
                }
                .map_err(err)?;
                let page = table
                    .select_chunk(
                        &program,
                        function == EtsBif::SelectReverse,
                        limit,
                        &mut heap,
                    )
                    .map_err(err)?;
                let rows = TermBuilder::new(&mut heap)
                    .list_from_iter(page.rows)
                    .map_err(|_| badarg())?;
                let (result, retain) = if let Some(continuation) = page.continuation {
                    let next = continuation.to_term(&table, &mut heap).map_err(err)?;
                    (
                        TermBuilder::new(&mut heap)
                            .tuple(&[rows, next])
                            .map_err(|_| badarg())?,
                        true,
                    )
                } else if rows == Term::NIL {
                    // Port of erts/emulator/beam/erl_db_hash.c:2189-2246,
                    // OTP-29.1.1: exhaustion is an end marker, with the final
                    // non-empty chunk paired with the same marker.
                    (atom("$end_of_table"), false)
                } else {
                    (
                        TermBuilder::new(&mut heap)
                            .tuple(&[rows, atom("$end_of_table")])
                            .map_err(|_| badarg())?,
                        false,
                    )
                };
                (program, result, retain)
            };
            if retain {
                registry.retain_match_program(program);
            }
            Ok(result)
        }
        (EtsBif::Select | EtsBif::SelectReverse, [continuation])
        | (EtsBif::Match, [continuation])
        | (EtsBif::MatchObject, [continuation]) => {
            // Port of erts/emulator/beam/erl_db.c:3955-3960 (ets_select1), OTP-29.1.1.
            if end_of_table(*continuation) {
                return Ok(atom("$end_of_table"));
            }
            // SAFETY: the continuation is rooted in the caller's process heap.
            let tuple = unsafe { continuation.tuple_ref() }.ok_or_else(badarg)?;
            let tid = Tid::from_term(tuple.get(0).ok_or_else(badarg)?).ok_or_else(badarg)?;
            let table = table_guard(&registry, tid, true)?;
            if !allowed(&table, caller, false) {
                return Err(badarg_cause("access"));
            }
            let program_pos = if table.options.table_type == TableType::OrderedSet {
                4
            } else {
                3
            };
            let reference = tuple.get(program_pos).ok_or_else(badarg)?;
            let program = registry.match_program(reference).ok_or_else(badarg)?;
            let state = SelectContinuation::from_term(&table, &program, *continuation).map_err(err)?;
            let page = table
                .select_chunk_continue(&program, state, &mut heap)
                .map_err(err)?;
            let keep_program = page.continuation.is_some();
            let rows = TermBuilder::new(&mut heap)
                .list_from_iter(page.rows)
                .map_err(|_| badarg())?;
            let result = if let Some(next) = page.continuation {
                let next = next.to_term(&table, &mut heap).map_err(err)?;
                TermBuilder::new(&mut heap)
                    .tuple(&[rows, next])
                    .map_err(|_| badarg())
            } else if rows == Term::NIL {
                // Port of erts/emulator/beam/erl_db_hash.c:2389-2399
                // (select_chunk_continue_on_loop_ended), OTP-29.1.1.
                Ok(atom("$end_of_table"))
            } else {
                TermBuilder::new(&mut heap)
                    .tuple(&[rows, atom("$end_of_table")])
                    .map_err(|_| badarg())
            }?;
            drop(table);
            if !keep_program {
                registry.release_match_program(reference);
            }
            Ok(result)
        }
        (EtsBif::MatchSpecCompile, [spec]) => {
            let program = MatchProgram::compile(*spec).map_err(err)?;
            let reference = program.reference(&mut heap).map_err(err)?;
            registry.retain_match_program(program);
            Ok(reference)
        }
        (EtsBif::IsCompiledMs, [value]) => {
            Ok(boolean_term(MatchProgram::is_compiled_reference(*value)))
        }
        (EtsBif::InternalRequestAll, []) => {
            // Port of erts/emulator/beam/erl_db.c:3714 (ets_internal_request_all_0)
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
            // Port of erts/emulator/beam/erl_db.c:4605 (ets_match_spec_run_r_3), OTP-29.1.1.
            // The return value is the accumulator with each match consed in front.
            if objects.classify() != TermKind::List && *objects != Term::NIL {
                return Err(badarg());
            }
            let program = registry.match_program(*compiled).ok_or_else(badarg)?;
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
        // Port of erts/emulator/beam/erl_db.c:3433 (ets_internal_select_delete_2), OTP-29.1.1.
        // The BIF has no delete-all special case; `[]` returns 0 and a match spec deletes.
        | (EtsBif::InternalSelectDelete, [target, spec])
        | (EtsBif::SelectReplace, [target, spec]) => {
            let tid = handle(&registry, *target)?;
            if function == EtsBif::SelectReplace
                && registry
                    .shared(tid)
                    .map_err(err)?
                    .read()
                    .options
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
            // Port of erts/emulator/beam/erl_db.c:4195-4202 (ets_select_replace_2), OTP-29.1.1.
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
            let pos =
                usize::try_from(position.as_small().ok_or_else(badarg)?).map_err(|_| badarg())?;
            let table = registry.get_shared(tid).map_err(err)?;
            lookup_element_locked(&table, caller, *key, pos, args.get(3).copied(), &mut heap)
        }
        (EtsBif::UpdateElement, [target, key, updates])
        | (EtsBif::UpdateElement, [target, key, updates, _]) => {
            let tid = handle(&registry, *target)?;
            if registry
                .shared(tid)
                .map_err(err)?
                .read()
                .options
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
            // Port of erts/emulator/beam/erl_db.c:1386-1414 (do_update_element), OTP-29.1.1:
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
                .read()
                .options
                .write_concurrency
                != WriteConcurrency::Disabled
            {
                let table = registry.get_shared(tid).map_err(err)?;
                if table.options.table_type == TableType::Set {
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
            // Port of erts/emulator/beam/erl_db.c:1505-1603 (do_update_counter), OTP-29.1.1.
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

    /// The `ets` export name of the BIF, for the frame of a failure.
    fn name(self) -> &'static str {
        match self {
            EtsBif::MatchSpecTest => "match_spec_test",
            EtsBif::LookupBinaryInfo => "lookup_binary_info",
            EtsBif::RawFirst => "raw_first",
            EtsBif::RawNext => "raw_next",
            EtsBif::SuperUser => "super_user",
            EtsBif::New => "new",
            EtsBif::Whereis => "whereis",
            EtsBif::Rename => "rename",
            EtsBif::Info => "info",
            EtsBif::Delete => "delete",
            EtsBif::InternalDeleteAll => "internal_delete_all",
            EtsBif::SetOpts => "set_opts",
            EtsBif::Take => "take",
            EtsBif::Slot => "slot",
            EtsBif::First => "first",
            EtsBif::FirstLookup => "first_lookup",
            EtsBif::Last => "last",
            EtsBif::LastLookup => "last_lookup",
            EtsBif::Next => "next",
            EtsBif::NextLookup => "next_lookup",
            EtsBif::Prev => "prev",
            EtsBif::PrevLookup => "prev_lookup",
            EtsBif::SafeFixtable => "safe_fixtable",
            EtsBif::DeleteObject => "delete_object",
            EtsBif::GiveAway => "give_away",
            EtsBif::Select => "select",
            EtsBif::SelectReverse => "select_reverse",
            EtsBif::Match => "match",
            EtsBif::MatchObject => "match_object",
            EtsBif::MatchSpecCompile => "match_spec_compile",
            EtsBif::IsCompiledMs => "is_compiled_ms",
            EtsBif::InternalRequestAll => "internal_request_all",
            EtsBif::MatchSpecRunR => "match_spec_run_r",
            EtsBif::SelectCount => "select_count",
            EtsBif::InternalSelectDelete => "internal_select_delete",
            EtsBif::SelectReplace => "select_replace",
            EtsBif::LookupElement => "lookup_element",
            EtsBif::UpdateElement => "update_element",
            EtsBif::UpdateCounter => "update_counter",
        }
    }

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
    let result = insert_args(process, caller_of(ctx), false, target, objects);
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
    let result = insert_args(process, caller_of(ctx), true, target, objects);
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
        // Port of erts/emulator/beam/erl_db.c:4541-4542 (ets_info_2 traps to
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
