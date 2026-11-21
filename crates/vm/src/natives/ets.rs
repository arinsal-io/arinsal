//! ETS BIFs whose storage and access policy belong to the scheduled runtime.
// Port of erts/emulator/beam/erl_db.c, OTP-29.1.1.

use crate::proc_create::EtsInsert;
use crate::process::Message;
use crate::{Process, VmError};
use arinsal_ets::match_spec::MatchDialect;
use arinsal_ets::match_spec::MatchProgram;
use arinsal_ets::{
    BigCounterOp, CounterOp, ElementLookup, EtsError, Heir, Protection, Table, TableOptions,
    TableType, Tid, WriteConcurrency,
};
use arinsal_sched::{ErtsThrPrgrLaterOp, Pid, RunCtx};
use arinsal_term::{HeapAlloc, MagicBin, ProcessHeap, Term, TermBuilder, TermKind, global_atoms};
use num_bigint::BigInt;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicBool, AtomicIsize, Ordering as AtomicOrdering};
use std::time::{SystemTime, UNIX_EPOCH};

// Only atoms of the static erts table: interning others here would give them
// indices erts does not (erts creates e.g. `safe_fixed` only when it is used).
static ETS_ATOMS: LazyLock<HashMap<&'static str, arinsal_term::Atom>> = LazyLock::new(|| {
    [
        "badarg",
        "system_limit",
        "function_clause",
        "named_table",
        "access",
        "already_exists",
        "badkey",
        "default",
        "not_owner",
        "owner",
        "keypos",
        "position",
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
        "table_type",
        "protection",
        "size",
        "memory",
        "node",
        "true",
        "false",
    ]
    .into_iter()
    .map(|name| (name, global_atoms().intern(name).expect("built-in atom")))
    .collect()
});

/// `p->flags & F_ETS_SUPER_USER` of the calling process (db_get_table_aux).
#[inline(always)]
fn ets_super_user(process: &Process) -> bool {
    process
        .heap
        .has_flag(arinsal_term::pflags::F_ETS_SUPER_USER)
}

#[inline]
fn boolean_term(value: bool) -> Term {
    Term::atom(if value {
        arinsal_term::atoms::TRUE
    } else {
        arinsal_term::atoms::FALSE
    })
}

/// A BIF that sends or traps was called without a scheduler context; the direct path never
/// routes those, so this only guards the invariant.
fn needs_context() -> VmError {
    VmError::Unsupported("ETS BIF needs the scheduler context".into())
}
/// `BIF_ERROR(BIF_P, BADARG)`.
fn badarg() -> VmError {
    VmError::Freason(arinsal_term::exc::EXC_BADARG)
}
/// `p->fvalue = EXI_*` of `db_get_table_aux` / `handle_lacking_permission`; the local
/// `freason__` is `BADARG | EXF_HAS_EXT_INFO`, which `db_bif_fail` stores in `p->freason`.
// Port of erts/emulator/beam/erl_db.c (`db_get_table_aux`, `handle_lacking_permission`), OTP-29.1.1.
fn badarg_cause(heap: &mut ProcessHeap, cause: &'static str) -> VmError {
    let cause = *ETS_ATOMS.get(cause).expect("ETS error cause atom");
    heap.abi.exc.fvalue = crate::native_hooks::raw(Term::atom(cause));
    VmError::Freason(arinsal_term::exc::EXC_BADARG | arinsal_term::exc::EXF_HAS_EXT_INFO)
}

/// `BIF_ERROR(BIF_P, SYSTEM_LIMIT)` (`DB_ERROR_SYSRES`).
fn system_limit() -> VmError {
    VmError::Freason(arinsal_term::exc::EXC_SYSTEM_LIMIT)
}
fn binary_info_err(heap: &mut ProcessHeap, error: EtsError) -> VmError {
    match error {
        EtsError::Term(
            arinsal_term::TermError::HeapFull | arinsal_term::TermError::SystemLimit,
        ) => system_limit(),
        error => err(heap, error),
    }
}
/// `is_list(arg2) && CDR(arg2) != NIL`: a list for `ets_insert_2_list_driver`.
pub(crate) fn is_list_insert(objects: Term) -> bool {
    list_next(objects).is_some_and(|(_, tail)| tail != Term::NIL)
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
fn err(heap: &mut ProcessHeap, error: EtsError) -> VmError {
    match error {
        EtsError::NoTable => badarg_cause(heap, "id"),
        EtsError::BadArgCause(cause) => badarg_cause(heap, cause),
        EtsError::BadArg | EtsError::NameTaken => badarg(),
        EtsError::Unsupported(_) => badarg(),
        // Port of erts/emulator/beam/erl_db.c: the BIF traps and runs again.
        EtsError::Busy => VmError::Yield,
        // Port of erts/emulator/beam/erl_db.c (DB_ERROR_SYSRES -> SYSTEM_LIMIT), OTP-29.1.1.
        EtsError::Term(arinsal_term::TermError::SystemLimit) => system_limit(),
        EtsError::Term(_) => badarg(),
    }
}

/// Translate `SavedKey::new` errors, which can only come from copying its term into a local heap.
pub(super) fn saved_key_error(error: EtsError) -> VmError {
    match error {
        EtsError::Term(arinsal_term::TermError::SystemLimit) => system_limit(),
        EtsError::Term(_) => badarg(),
        _ => unreachable!("SavedKey::new only reports term-copy errors"),
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
    heap: &mut ProcessHeap,
) -> Result<TableGuard<'a>, VmError> {
    if shared {
        Ok(TableGuard::Read(
            registry.get_shared(tid).map_err(|error| err(heap, error))?,
        ))
    } else {
        Ok(TableGuard::Write(
            registry.get_mut(tid).map_err(|error| err(heap, error))?,
        ))
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
fn handle(
    heap: &mut ProcessHeap,
    registry: &arinsal_ets::Registry,
    term: Term,
) -> Result<Tid, VmError> {
    resolve(registry, term).map_err(|fail| match fail {
        ResolveFail::BadType => badarg_cause(heap, "type"),
        ResolveFail::Missing => badarg_cause(heap, "id"),
    })
}

/// `erlang:system_info(schedulers)`. `ets:all/0` receives exactly this many replies.
fn scheduler_count() -> usize {
    arinsal_alloc::cpuinfo::default_schedulers().0
}

/// Live tables as `ets:all/0` prints them: names for named tables, ids otherwise.
fn live_table_terms(
    registry: &arinsal_ets::Registry,
    heap: &mut ProcessHeap,
) -> Result<Vec<Term>, VmError> {
    let mut heap = arinsal_bifs::ProcessHeapHandle(heap);
    registry
        .all()
        .into_iter()
        .map(|tid| {
            let table = registry
                .get(tid)
                .map_err(|error| err(&mut *heap.0, error))?;
            if table.options.named_table {
                Ok(Term::atom(table.options.name))
            } else {
                registry
                    .tid_term(tid, &mut heap)
                    .map_err(|error| err(&mut *heap.0, error))
            }
        })
        .collect()
}
#[inline(always)]
fn allowed(table: &arinsal_ets::Table, caller: Term, super_user: bool, write: bool) -> bool {
    // Port of erts/emulator/beam/erl_db.c:780-792 (db_get_table_aux: owner, protection, then
    // `p->flags & F_ETS_SUPER_USER`), OTP-29.1.1.
    caller == table.options.owner
        || match table.options.protection {
            Protection::Private => false,
            Protection::Protected => !write,
            Protection::Public => true,
        }
        || super_user
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
    heap: &mut ProcessHeap,
    table: &arinsal_ets::Table,
    default: Option<Term>,
) -> Result<Option<Term>, VmError> {
    let Some(default) = default else {
        return Ok(None);
    };
    match tuple_items(default) {
        Some(items) if items.len() >= table.options.keypos => Ok(Some(default)),
        _ => Err(badarg_cause(heap, "default")),
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

/// `allowed(.., write = false)` for a reader whose pid term is built only when the table's
/// protection does not already grant access. Port of erts/emulator/beam/erl_db.c
/// (db_get_table_aux, DB_READ access test), OTP-29.1.1.
#[inline(always)]
fn read_allowed(table: &arinsal_ets::Table, pid: arinsal_sched::Pid, super_user: bool) -> bool {
    match table.options.protection {
        Protection::Public | Protection::Protected => true,
        Protection::Private => pid
            .to_term()
            .is_some_and(|caller| allowed(table, caller, super_user, false)),
    }
}

/// The reader group of the calling scheduler: `erts_get_scheduler_id() - 1`.
#[inline]
fn reader_group(process: &Process) -> usize {
    match crate::proc_create::raw::erts_psd_get_word(
        &process.psd,
        crate::proc_create::raw::ERTS_PSD_SCHED_ID,
    ) {
        0 => arinsal_term::current_reader_group(),
        id => id - 1,
    }
}

fn direct_caller(process: &Process) -> Option<Term> {
    process.self_pid()?.to_term()
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
            body(lock, options, process)
        })
        .flatten()
}

/// `ets:lookup/2`.
// Port of erts/emulator/beam/erl_db.c (ets_lookup_2, db_get_table_aux), OTP-29.1.1.
pub(crate) fn ets_lookup_2(process: &mut Process, args: &[Term]) -> Result<Term, VmError> {
    if args[0].is_magic_ref() {
        if let Some(value) = direct_lookup_cached(process, args) {
            return Ok(value);
        }
    } else if args[0].as_atom().is_some()
        && let Some(value) = direct_lookup_named(process, args)
    {
        return Ok(value);
    }
    help_busy_table(process, args[0], false)?;
    let caller = direct_caller(process).ok_or_else(badarg)?;
    lookup_args(process, caller, false, args[0], args[1])
}

/// Successful `ets:lookup/2` for a named table, with the same lookup, lock, and copy steps as
/// the BIF path. Errors decline to the scheduler path so it can build the proper exception.
// Port of erts/emulator/beam/erl_db.c (ets_lookup_2, db_get_table_aux), OTP-29.1.1.
fn direct_lookup_named(process: &mut Process, args: &[Term]) -> Option<Term> {
    let super_user = ets_super_user(process);
    let name = args[0].as_atom()?;
    let pid = process.self_pid()?;
    let group = reader_group(process);
    let rt = process.runtime.as_ref()?;
    rt.named_ets
        .with_table(name, |shared| {
            let table = shared.read_at(group);
            if table.is_detached()
                || !table.options.named_table
                || table.options.name != name
                || table.is_busy()
                || !read_allowed(&table, pid, super_user)
            {
                return None;
            }
            let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
            table.lookup_list_at(args[1], group, &mut heap).ok()
        })
        .flatten()
}

fn direct_lookup_cached(process: &mut Process, args: &[Term]) -> Option<Term> {
    let super_user = ets_super_user(process);
    let pid = process.self_pid()?;
    let key = args[1];
    let group = reader_group(process);
    with_cached_table(process, args[0], |shared, _options, process| {
        let table = shared.read_at(group);
        if table.is_detached() || table.is_busy() || !read_allowed(&table, pid, super_user) {
            return None;
        }
        let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
        // Port of erts/emulator/beam/erl_db_hash.c (db_get_hash) and
        // erl_db_tree.c (db_get_tree), OTP-29.1.1: a set holds at most one object,
        // consed straight onto the process heap.
        table.lookup_list_at(key, group, &mut heap).ok()
    })
}

/// `ets:member/2`.
// Port of erts/emulator/beam/erl_db.c (ets_member_2, db_get_table_aux), OTP-29.1.1.
pub(crate) fn ets_member_2(process: &mut Process, args: &[Term]) -> Result<Term, VmError> {
    if let Some(value) = direct_member_cached(process, args) {
        return Ok(value);
    }
    help_busy_table(process, args[0], false)?;
    let caller = direct_caller(process).ok_or_else(badarg)?;
    lookup_args(process, caller, true, args[0], args[1])
}

fn direct_member_cached(process: &mut Process, args: &[Term]) -> Option<Term> {
    let super_user = ets_super_user(process);
    let pid = process.self_pid()?;
    let key = args[1];
    let group = reader_group(process);
    with_cached_table(process, args[0], |shared, _options, _| {
        let table = shared.read_at(group);
        if table.is_detached() || table.is_busy() || !read_allowed(&table, pid, super_user) {
            return None;
        }
        Some(boolean_term(table.member_at(key, group)))
    })
}

/// `ets:lookup_element/3,4` through a stable table handle and the table's native read lock.
// Port of erts/emulator/beam/erl_db.c (ets_lookup_element_3/4), OTP-29.1.1.
pub(crate) fn ets_lookup_element(process: &mut Process, args: &[Term]) -> Result<Term, VmError> {
    if let Some(value) = direct_lookup_element_hit(process, args) {
        return Ok(value);
    }
    if let Some(result) = direct_lookup_element_cached(process, args) {
        return result;
    }
    ets_call(process, EtsBif::LookupElement, args)
}

/// The successful `lookup_element/3` of a set-like table, without a `Result` or an exception
/// frame. Any failure declines, and the general path repeats the lookup and raises.
// Port of erts/emulator/beam/erl_db.c (ets_lookup_element_3), OTP-29.1.1.
fn direct_lookup_element_hit(process: &mut Process, args: &[Term]) -> Option<Term> {
    let super_user = ets_super_user(process);
    if args.len() != 3 {
        return None;
    }
    let pid = process.self_pid()?;
    let (key, position) = (args[1], usize::try_from(args[2].as_small()?).ok()?);
    let group = reader_group(process);
    with_cached_table(process, args[0], |shared, _, process| {
        let table = shared.read_at(group);
        if table.is_detached()
            || table.is_busy()
            || !read_allowed(&table, pid, super_user)
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
) -> Option<Result<Term, VmError>> {
    let caller = direct_caller(process)?;
    let group = reader_group(process);
    let (target, key, position, default) = (args[0], args[1], args[2], args.get(3).copied());
    if target.is_magic_ref() {
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
                return Some(Err(badarg_cause(&mut process.heap, "id")));
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
            None => Some(Err(badarg_cause(&mut process.heap, "id"))),
        }
    } else {
        None
    }
}

/// `ets:delete/2` through the table lock and the storage's key-level write lock.
// Port of erts/emulator/beam/erl_db.c (ets_delete_2), OTP-29.1.1.
pub(crate) fn ets_delete_2(process: &mut Process, args: &[Term]) -> Result<Term, VmError> {
    if let Some(value) = direct_delete_cached(process, args) {
        return Ok(value);
    }
    ets_call(process, EtsBif::Delete, args)
}

fn direct_delete_cached(process: &mut Process, args: &[Term]) -> Option<Term> {
    let super_user = ets_super_user(process);
    let caller = direct_caller(process)?;
    let group = reader_group(process);
    let target = args[0];
    let key = args[1];
    if target.is_magic_ref() {
        with_cached_table(process, target, |shared, options, _| {
            direct_delete_from_shared(shared, group, options, caller, super_user, key, None)
        })
    } else if let Some(name) = target.as_atom() {
        let rt = process.runtime.as_ref()?;
        rt.named_ets
            .with_table(name, |shared| {
                direct_delete_from_shared(
                    shared,
                    group,
                    shared.options(),
                    caller,
                    super_user,
                    key,
                    Some(name),
                )
            })
            .flatten()
    } else {
        None
    }
}

fn direct_delete_from_shared(
    shared: &arinsal_ets::TableLock,
    group: usize,
    options: &TableOptions,
    caller: Term,
    super_user: bool,
    key: Term,
    name: Option<arinsal_term::Atom>,
) -> Option<Term> {
    if options.write_concurrency != WriteConcurrency::Disabled {
        let table = shared.read_at(group);
        if table.is_detached()
            || name.is_some_and(|name| !table.options.named_table || table.options.name != name)
            || table.is_busy()
            || !allowed(&table, caller, super_user, true)
        {
            return None;
        }
        let deleted = table.delete_key_shared(key);
        drop(table);
        if deleted {
            return Some(Term::atom(arinsal_term::atoms::TRUE));
        }
    }
    let mut table = shared.write();
    if table.is_detached()
        || name.is_some_and(|name| !table.options.named_table || table.options.name != name)
        || table.is_busy()
        || !allowed(&table, caller, super_user, true)
    {
        return None;
    }
    table.delete_key(key);
    Some(Term::atom(arinsal_term::atoms::TRUE))
}

/// `ets:insert/2` and `ets:insert_new/2`: one tuple is stored in place, anything else (lists,
/// the empty list, errors, a busy table) takes the general body.
// Port of erts/emulator/beam/erl_db.c (ets_insert_2, ets_insert_new_2), OTP-29.1.1.
pub(crate) fn ets_insert_2<const NEW: bool>(
    process: &mut Process,
    args: &[Term],
) -> Result<Term, VmError> {
    if let Some(value) = insert_one::<NEW>(process, args) {
        return Ok(value);
    }
    help_busy_table(process, args[0], false)?;
    let caller = direct_caller(process).ok_or_else(badarg)?;
    insert_args(process, caller, NEW, args[0], args[1])
}

/// Run one ETS BIF on the scheduler's data, as erts runs it through `c_p`'s scheduler.
// Port of erts/emulator/beam/erl_db.c (the ets BIF bodies reach `esdp` through
// `erts_proc_sched_data(c_p)`), OTP-29.1.1.
pub(crate) fn ets_call(
    process: &mut Process,
    function: EtsBif,
    args: &[Term],
) -> Result<Term, VmError> {
    let pid = process.self_pid().ok_or_else(badarg)?;
    arinsal_sched::erts_proc_sched_data(process, |process, esdp| {
        arinsal_sched::RunCtx::with_current(esdp, |ctx| {
            call_inner(process, Some(ctx), pid, function, args)
        })
    })
    .flatten()
    .expect("native code runs inside an executor slice, which publishes its scheduler data")
}

/// One tuple inserted into a set, bag or CA-tree table: table lookup, access check, bucket
/// store. `None` declines to the general path (lists, errors, a busy table).
// Port of erts/emulator/beam/erl_db.c (ets_insert_2/insert_new_2, db_get_table_aux) and
// erl_db_hash.c (db_put_hash), OTP-29.1.1.
#[inline]
fn insert_one<const NEW: bool>(process: &mut Process, args: &[Term]) -> Option<Term> {
    let super_user = ets_super_user(process);
    if args[1].classify() != TermKind::Tuple {
        return None;
    }
    let caller = direct_caller(process)?;
    let group = reader_group(process);
    let object = args[1];
    let target = args[0];
    let insert = |shared: &arinsal_ets::TableLock, name: Option<arinsal_term::Atom>| {
        let options = shared.options();
        if options.write_concurrency != WriteConcurrency::Disabled {
            let table = shared.read_at(group);
            if table.is_detached()
                || name.is_some_and(|name| !table.options.named_table || table.options.name != name)
                || table.is_busy()
                || !allowed(&table, caller, super_user, true)
            {
                return None;
            }
            return table.insert_term_shared(object, NEW).ok().map(boolean_term);
        }
        let mut table = shared.write();
        if table.is_detached()
            || name.is_some_and(|name| !table.options.named_table || table.options.name != name)
            || table.is_busy()
            || !allowed(&table, caller, super_user, true)
        {
            return None;
        }
        let inserted = table.insert_term(object, NEW).ok()?;
        Some(boolean_term(inserted))
    };
    if target.is_magic_ref() {
        target
            .with_magic_payload::<arinsal_ets::TableLock, _>(|shared| insert(shared, None))
            .flatten()
    } else if let Some(name) = target.as_atom() {
        let rt = process.runtime.as_ref()?;
        rt.named_ets
            .with_table(name, |shared| insert(shared, Some(name)))
            .flatten()
    } else {
        None
    }
}

/// `ets:update_counter/3,4` on small counters, updated in place under the table lock.
// Port of erts/emulator/beam/erl_db.c (do_update_counter, ets_update_counter_3/4),
// OTP-29.1.1.
pub(crate) fn ets_update_counter(process: &mut Process, args: &[Term]) -> Result<Term, VmError> {
    if let Some(result) = direct_update_counter_cached(process, args) {
        return result;
    }
    ets_call(process, EtsBif::UpdateCounter, args)
}

fn direct_update_counter_cached(
    process: &mut Process,
    args: &[Term],
) -> Option<Result<Term, VmError>> {
    let caller = direct_caller(process)?;
    let group = reader_group(process);
    let target = args[0];
    if target.is_magic_ref() {
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
                shared.options(),
                caller,
                Some(name),
                args,
                &mut process.heap,
            )
        }) {
            Some(result) => result,
            None => Some(Err(badarg_cause(&mut process.heap, "id"))),
        }
    } else {
        None
    }
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
    let super_user = heap.has_flag(arinsal_term::pflags::F_ETS_SUPER_USER);
    if options.write_concurrency != WriteConcurrency::Disabled {
        let table = shared.read_at(group);
        if table.is_detached()
            || name.is_some_and(|name| !table.options.named_table || table.options.name != name)
            || table.is_busy()
        {
            return None;
        }
        if let Some(increment) = args.get(2).and_then(|operation| operation.as_small()) {
            if let Err(error) = validate_counter_request(heap, &table, caller, super_user, args) {
                return Some(Err(error));
            }
            if let Some(value) = table.update_counter_one_in_place_shared(args[1], increment) {
                return Some(Ok(value));
            }
        }
        let request = match counter_request(heap, &table, caller, super_user, args) {
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
    if let Some(increment) = args.get(2).and_then(|operation| operation.as_small()) {
        if let Err(error) = validate_counter_request(heap, &table, caller, super_user, args) {
            return Some(Err(error));
        }
        if let Some(value) = table.update_counter_one_in_place(args[1], increment) {
            return Some(Ok(value));
        }
    }
    let request = match counter_request(heap, &table, caller, super_user, args) {
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
    heap: &mut ProcessHeap,
    table: &arinsal_ets::Table,
    caller: Term,
    super_user: bool,
    args: &[Term],
) -> Result<Option<CounterRequest>, VmError> {
    validate_counter_request(heap, table, caller, super_user, args)?;
    let Some((operations, single)) = small_counter_ops(table.options.keypos, args[2]) else {
        return Ok(None);
    };
    Ok(Some((args[1], operations, single)))
}

fn validate_counter_request(
    heap: &mut ProcessHeap,
    table: &arinsal_ets::Table,
    caller: Term,
    super_user: bool,
    args: &[Term],
) -> Result<(), VmError> {
    if !allowed(table, caller, super_user, true) {
        return Err(badarg_cause(heap, "access"));
    }
    // ets_update_counter_4 validates Default before do_update_counter checks table type.
    if let Some(default) = args.get(3).copied()
        && tuple_items(default).is_none_or(|items| items.len() < table.options.keypos)
    {
        return Err(badarg_cause(heap, "default"));
    }
    if !matches!(
        table.options.table_type,
        TableType::Set | TableType::OrderedSet
    ) {
        return Err(badarg_cause(heap, "table_type"));
    }
    Ok(())
}

pub(crate) fn insert_args(
    process: &mut Process,
    caller: Term,
    insert_new: bool,
    target: Term,
    objects: Term,
) -> Result<Term, VmError> {
    let super_user = ets_super_user(process);
    // SAFETY: object terms remain in the caller's live process heap for this BIF.
    let is_tuple = unsafe { objects.tuple_ref() }.is_some();

    // Port of erts/emulator/beam/erl_db.c (ets_insert_2), OTP-29.1.1: a singleton list
    // supplies its object directly, while an empty list only resolves and checks the table.
    let object = if is_tuple {
        Some(objects)
    } else {
        list_next(objects).and_then(|(object, tail)| (tail == Term::NIL).then_some(object))
    };
    let single = object.is_some();
    let object = object.unwrap_or(objects);
    let group = reader_group(process);
    let heap = &mut process.heap;
    let rt = process.runtime.as_ref().ok_or_else(badarg)?;
    let mut insert = |shared: &arinsal_ets::TableLock,
                      name: Option<arinsal_term::Atom>|
     -> Result<Term, VmError> {
        let options = shared.options();
        if objects == Term::NIL && options.write_concurrency != WriteConcurrency::Disabled {
            let table = shared.read_at(group);
            if table.is_detached()
                || name.is_some_and(|name| !table.options.named_table || table.options.name != name)
            {
                return Err(badarg_cause(heap, "id"));
            }
            if table.is_busy() {
                return Err(VmError::Yield);
            }
            if !allowed(&table, caller, super_user, true) {
                return Err(badarg_cause(heap, "access"));
            }
            return Ok(boolean_term(true));
        }
        if single && options.write_concurrency != WriteConcurrency::Disabled {
            let table = shared.read_at(group);
            if table.is_detached()
                || name.is_some_and(|name| !table.options.named_table || table.options.name != name)
            {
                return Err(badarg_cause(heap, "id"));
            }
            if table.is_busy() {
                return Err(VmError::Yield);
            }
            if !allowed(&table, caller, super_user, true) {
                return Err(badarg_cause(heap, "access"));
            }
            let yes = table
                .insert_term_shared(object, insert_new)
                .map_err(|error| err(heap, error))?;
            return Ok(if insert_new {
                boolean_term(yes)
            } else {
                boolean_term(true)
            });
        }

        let mut table = shared.write();
        if table.is_detached()
            || name.is_some_and(|name| !table.options.named_table || table.options.name != name)
        {
            return Err(badarg_cause(heap, "id"));
        }
        if table.is_busy() {
            return Err(VmError::Yield);
        }
        if !allowed(&table, caller, super_user, true) {
            return Err(badarg_cause(heap, "access"));
        }
        let yes = if single {
            table
                .insert_term(object, insert_new)
                .map_err(|error| err(heap, error))?
        } else {
            let items = list(objects).ok_or_else(badarg)?;
            if insert_new {
                table.insert_new(&items).map_err(|error| err(heap, error))?
            } else {
                table.insert(&items).map_err(|error| err(heap, error))?;
                true
            }
        };
        Ok(if insert_new {
            boolean_term(yes)
        } else {
            boolean_term(true)
        })
    };

    if let Some(name) = target.as_atom() {
        return rt
            .named_ets
            .with_table(name, |shared| insert(shared, Some(name)))
            .unwrap_or_else(|| Err(badarg_cause(heap, "id")));
    }
    target
        .with_magic_payload::<arinsal_ets::TableLock, _>(|shared| insert(shared, None))
        .unwrap_or_else(|| Err(badarg_cause(heap, "type")))
}

/// `ets:insert/2` and `ets:insert_new/2` with a list of two or more objects.
///
/// Port of erts/emulator/beam/erl_db.c (ets_insert_2_list, ets_insert_2_list_driver),
/// OTP-29.1.1. A list that fits the reductions left and is not for a bag goes in directly. Any
/// other list is first copied into table form without the table lock, then locked in and
/// inserted a slice at a time; when it does not finish, the rest is installed in the table, which
/// turns busy so that every other user helps and this process collects the result.
pub(crate) fn insert_list(
    process: &mut Process,
    caller: Term,
    insert_new: bool,
    target: Term,
    objects: Term,
    mut state: Option<EtsInsert>,
) -> Result<ListInsert, VmError> {
    let super_user = ets_super_user(process);
    const ITERATIONS_PER_RED: isize = 8;
    let rt = process.runtime.ok_or_else(badarg)?;
    let initial = process.heap.abi.fcalls.max(0) as isize;
    let mut loops = initial * ITERATIONS_PER_RED;
    let done = |process: &mut Process, loops: isize, yes: bool| {
        let used = (initial * ITERATIONS_PER_RED - loops) / ITERATIONS_PER_RED;
        bump_direct(process, used);
        Ok(ListInsert::Value(boolean_term(yes)))
    };
    if let Some(EtsInsert::Global(outcome)) = state.as_ref() {
        // The table is no longer busy (or gone): the operation completed or was aborted by
        // someone else.
        return match outcome.load(std::sync::atomic::Ordering::Acquire) {
            1 => Ok(ListInsert::Value(boolean_term(true))),
            2 => Ok(ListInsert::Value(boolean_term(false))),
            _ => Err(badarg_cause(&mut process.heap, "id")),
        };
    }
    let registry = rt.ets.read().unwrap();
    let tid = handle(&mut process.heap, &registry, target)?;
    let shared = registry
        .shared(tid)
        .map_err(|error| err(&mut process.heap, error))?
        .clone();
    let options = shared.options();
    // Keep the table alive by its shared handle. Holding the registry lock while waiting for a
    // table writer prevents ets:delete/1 from detaching the table, unlike erts' btid reference.
    drop(registry);
    // Port of erts/emulator/beam/erl_db.c (ets_insert_2_list_check), OTP-29.1.1: the
    // check pass is a yieldable loop that takes one iteration per object.
    let check_failure = |heap: &mut ProcessHeap| {
        let table = shared.read();
        if table.is_detached()
            || target
                .as_atom()
                .is_some_and(|name| table.options.named_table && table.options.name != name)
        {
            err(heap, EtsError::NoTable)
        } else if !allowed(&table, caller, super_user, true) {
            badarg_cause(heap, "access")
        } else {
            badarg()
        }
    };
    let (mut cursor, mut checked, prepared) = match state.take() {
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
                return Ok(ListInsert::Trap(EtsInsert::Check {
                    cursor,
                    count: checked,
                }));
            }
            let object = match advance_list(&mut cursor) {
                Ok(Some(object)) => object,
                Ok(None) => unreachable!(),
                Err(_) => return Err(check_failure(&mut process.heap)),
            };
            if Table::check_object(options, object).is_err() {
                return Err(check_failure(&mut process.heap));
            }
            checked += 1;
        }
        if cursor != Term::NIL {
            return Err(check_failure(&mut process.heap));
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
            return Err(err(&mut process.heap, EtsError::NoTable));
        }
        if table.is_busy() {
            return Err(err(&mut process.heap, EtsError::Busy));
        }
        if !allowed(&table, caller, super_user, true) {
            return Err(badarg_cause(&mut process.heap, "access"));
        }
        let mut check_cursor = objects;
        if insert_new {
            while check_cursor.classify() == TermKind::List {
                loops -= 1;
                let object = advance_list(&mut check_cursor)?.expect("list cursor checked");
                if table
                    .member_object(object)
                    .map_err(|error| err(&mut process.heap, error))?
                {
                    return done(process, loops, false);
                }
            }
        }
        let mut insert_cursor = objects;
        while insert_cursor.classify() == TermKind::List {
            // Port of erts/emulator/beam/erl_db.c (ets_insert_2_list_from_p_heap): the
            // generated loop consumes one reduction before db_put, which consumes at least one.
            loops -= 1;
            let object = advance_list(&mut insert_cursor)?.expect("list cursor checked");
            let prepared = Table::prepare_object(options, object)
                .map_err(|error| err(&mut process.heap, error))?;
            let extra_reds = table.insert_prepared_counted(prepared);
            loops -= 1 + extra_reds as isize;
        }
        let yes = true;
        return done(process, loops, yes);
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
            return Ok(ListInsert::Trap(EtsInsert::Copy { cursor, prepared }));
        }
        let object = match advance_list(&mut cursor) {
            Ok(Some(object)) => object,
            Ok(None) => unreachable!(),
            Err(_) => return Err(check_failure(&mut process.heap)),
        };
        match Table::prepare_object(options, object) {
            Ok(object) => prepared.push(object),
            Err(error) => {
                if error == EtsError::BadArg {
                    return Err(check_failure(&mut process.heap));
                }
                return Err(err(&mut process.heap, error));
            }
        }
    }
    if cursor != Term::NIL {
        return Err(check_failure(&mut process.heap));
    }
    // Acquire the table lock independently of the registry, as in ets_insert_2_list_lock_tbl.
    let mut table = shared.write();
    if table.is_detached()
        || target
            .as_atom()
            .is_some_and(|name| table.options.named_table && table.options.name != name)
    {
        return Err(err(&mut process.heap, EtsError::NoTable));
    }
    if table.is_busy() {
        drop(table);
        return Ok(ListInsert::Trap(EtsInsert::Copy { cursor, prepared }));
    }
    if !allowed(&table, caller, super_user, true) {
        return Err(badarg_cause(&mut process.heap, "access"));
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
        return done(process, loops, !destroy_copied);
    }
    let outcome: arinsal_ets::InsertOutcome = Default::default();
    table.begin_busy_insert_list(
        pending,
        member_cursor,
        destroy_copied,
        std::sync::Arc::clone(&outcome),
    );
    Ok(ListInsert::Trap(EtsInsert::Global(outcome)))
}

/// The end of one `ets_insert_2_list_driver` slice: the result, or the state to trap with.
pub(crate) enum ListInsert {
    Value(Term),
    Trap(EtsInsert),
}

fn lookup_args(
    process: &mut Process,
    caller: Term,
    member: bool,
    target: Term,
    key: Term,
) -> Result<Term, VmError> {
    let super_user = ets_super_user(process);
    let group = reader_group(process);
    let rt = process.runtime.as_ref().ok_or_else(badarg)?;
    let mut lookup = |shared: &arinsal_ets::TableLock,
                      name: Option<arinsal_term::Atom>|
     -> Result<Term, VmError> {
        let table = shared.read_at(group);
        if table.is_detached()
            || name.is_some_and(|name| !table.options.named_table || table.options.name != name)
        {
            return Err(badarg_cause(&mut process.heap, "id"));
        }
        if table.is_busy() {
            return Err(err(&mut process.heap, arinsal_ets::EtsError::Busy));
        }
        if !allowed(&table, caller, super_user, false) {
            return Err(badarg_cause(&mut process.heap, "access"));
        }
        if member {
            return Ok(boolean_term(table.member_at(key, group)));
        }
        let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
        table
            .lookup_list_at(key, group, &mut heap)
            .map_err(|error| err(&mut *heap.0, error))
    };
    if let Some(name) = target.as_atom() {
        // Port of erts/emulator/beam/erl_db.c (db_get_table_aux), OTP-29.1.1.
        // Keep the atom-hashed snapshot alive across the table lock instead of cloning its Arc.
        let lookup = rt
            .named_ets
            .with_table(name, |shared| lookup(shared, Some(name)));
        return lookup.unwrap_or_else(|| Err(badarg_cause(&mut process.heap, "id")));
    }
    target
        .with_magic_payload::<arinsal_ets::TableLock, _>(|shared| lookup(shared, None))
        .unwrap_or_else(|| Err(badarg_cause(&mut process.heap, "type")))
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
    let super_user = heap.0.has_flag(arinsal_term::pflags::F_ETS_SUPER_USER);
    if !allowed(table, caller, super_user, false) {
        return Err(badarg_cause(&mut *heap.0, "access"));
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
            .map_err(|error| err(&mut *heap.0, error));
    }
    let Some(default) = default else {
        // Bag and duplicate_bag: the list is consed on the heap without an intermediate vector.
        return table
            .lookup_element_list_at(key, position, group, heap)
            .map_err(|error| err(&mut *heap.0, error));
    };
    let values = match table
        .lookup_element_default(key, position, default, heap)
        .map_err(|error| err(&mut *heap.0, error))?
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
                Term::atom(arinsal_term::atoms::FALSE)
            } else {
                Term::atom(arinsal_term::atoms::TRUE)
            }),
            _ => Err(arinsal_ets::EtsError::BadArg),
        }
    }
}

/// Charge `used` reductions from a BIF that runs from native code, where the live counter is
/// the one in the process header.
///
/// Port of erts/emulator/beam/bif.h, BUMP_REDS, OTP-29.1.1.
pub(crate) fn bump_direct(process: &mut Process, used: isize) {
    let used = used.clamp(0, i32::MAX as isize) as i32;
    let live = process.heap.abi.fcalls.saturating_sub(used).max(0);
    process.heap.abi.fcalls = live;
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
        .downcast_ref::<select_chunk::MatchProgRef>()
        .map(|prog| Arc::clone(&prog.0))
}

/// Help finish the operation a busy table waits for, then trap so that the BIF runs again.
///
/// Port of erts/emulator/beam/erl_db.c (handle_lacking_permission with DB_BUSY):
/// a process that finds the table busy runs the delete_all or list-insert continuation with its
/// own reductions and then retries.
pub(crate) fn help_busy_table(
    process: &mut Process,
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
    let initial = process.heap.abi.fcalls.max(0) as isize;
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
    bump_direct(
        process,
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
/// at a time. `ets:delete/1` traps to `ets:delete_trap/1` with its state binary,
/// `ets:internal_delete_all/2` to itself with `(Tid, NItems)`.
///
/// Port of erts/emulator/beam/erl_db.c (ets_delete_1), :3234 (ets_internal_delete_all_2),
/// :5378 (ets_delete_trap) and :5405 (free_table_continue), OTP-29.1.1.
fn delete_or_clear(
    process: &mut Process,
    function: EtsBif,
    args: &[Term],
    caller: Term,
) -> Result<Term, VmError> {
    let super_user = ets_super_user(process);
    let rt = process.runtime.ok_or_else(badarg)?;
    let initial = process.heap.abi.fcalls.max(0) as isize;
    let mut reds = initial;
    if function == EtsBif::Delete {
        let mut registry = rt.ets.write().unwrap();
        let tid = handle(&mut process.heap, &registry, args[0])?;
        if !allowed(
            &*registry
                .get(tid)
                .map_err(|error| err(&mut process.heap, error))?,
            caller,
            super_user,
            true,
        ) {
            return Err(badarg_cause(&mut process.heap, "access"));
        }
        let (mut garbage, fixations) = registry
            .detach(tid)
            .map_err(|error| err(&mut process.heap, error))?;
        drop(registry);
        reds -= fixations as isize;
        if !garbage.step(&mut reds) {
            bump_direct(process, isize::MAX);
            let state = crate::natives::erl_db::new_free_state(process, garbage)?;
            return Err(VmError::TrapExport(crate::ExportTrap::new(
                process,
                "ets:delete_trap/1",
                vec![state],
            )));
        }
        bump_direct(process, initial - reds);
        return Ok(Term::atom(arinsal_term::atoms::TRUE));
    }
    let registry = rt.ets.read().unwrap();
    let tid = handle(&mut process.heap, &registry, args[0])?;
    let mut table = registry
        .get_mut(tid)
        .map_err(|error| err(&mut process.heap, error))?;
    if !allowed(&table, caller, super_user, true) {
        return Err(badarg_cause(&mut process.heap, "access"));
    }
    // `BIF_ARG_2 != undefined`: this is the continuation, and the table is no longer busy.
    if args[1] != Term::atom(arinsal_term::atoms::UNDEFINED) {
        return Ok(args[1]);
    }
    let nitems = table.len();
    let mut garbage = table.take_garbage(false);
    let done = table.free_garbage(&mut garbage, &mut reds);
    if !done {
        // Port of erts/emulator/beam/erl_db.c (ets_internal_delete_all_2): the
        // table turns busy and every process that meets it continues the release.
        table.begin_busy_delete_all(garbage);
    }
    let tid_term = if args[0].as_atom().is_some() {
        registry
            .tid_term(tid, &mut arinsal_bifs::ProcessHeapHandle(&mut process.heap))
            .map_err(|error| err(&mut process.heap, error))?
    } else {
        args[0]
    };
    drop(table);
    drop(registry);
    let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
    let holder = TermBuilder::new(&mut heap)
        .int_from_i128(nitems as i128)
        .map_err(|_| badarg())?;
    if !done {
        bump_direct(process, isize::MAX);
        return Err(VmError::TrapExport(crate::ExportTrap::new(
            process,
            "ets:internal_delete_all/2",
            vec![tid_term, holder],
        )));
    }
    bump_direct(process, initial - reds);
    Ok(holder)
}

/// Fix a table for `caller`, stamping the first fixation with the current times.
///
/// Port of erts/emulator/beam/erl_db.c, fix_table_locked, OTP-29.1.1.
fn fix_table(
    heap: &mut arinsal_bifs::ProcessHeapHandle<'_>,
    table: &mut Table,
    caller: Term,
) -> Result<(), VmError> {
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
        .int_from_i128(arinsal_sched::erl_time_sup::monotonic_time_nanos())
        .map_err(|_| system_limit())?;
    table
        .safe_fixtable_for_at(caller, true, system_time, monotonic_time)
        .map_err(|error| err(&mut *heap.0, error))
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
    program_owner: MagicBin,
    count: bool,
    chunk: usize,
    backwards: bool,
    position: Option<arinsal_ets::ScanPosition>,
    got: usize,
    accum: (Term, usize),
    safety: arinsal_ets::IterSafety,
    plan: ScanPlan,
    continued: bool,
    /// A trap continuation: the call is the resumption of a trapped traversal.
    trapped: bool,
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
    caller_pid: Pid,
    function: EtsBif,
    args: &[Term],
) -> Result<Option<Term>, VmError> {
    let super_user = ets_super_user(process);
    use arinsal_ets::{IterSafety, ScanPosition};
    let caller = caller_pid.to_term().ok_or_else(badarg)?;
    let rt = process.runtime.ok_or_else(badarg)?;
    let count = function == EtsBif::SelectCount;
    let items = if args.len() == 1 {
        if end_of_table(args[0]) {
            return Ok(Some(Term::atom(arinsal_term::atoms::EOT)));
        }
        Some(select_chunk::continuation_items(args[0])?)
    } else {
        None
    };
    let empty_result = |chunked: bool| -> Result<Term, VmError> {
        if chunked {
            Ok(Term::atom(arinsal_term::atoms::EOT))
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
        let tid = match items.as_ref() {
            Some(items) => handle(&mut process.heap, &registry, items[0])?,
            None => handle(&mut process.heap, &registry, args[0])?,
        };
        let table = match registry.get_shared(tid) {
            Ok(table) => table,
            // The trap target runs again with the same continuation once the table is idle.
            Err(EtsError::Busy) => return Err(VmError::Yield),
            Err(error) => return Err(err(&mut process.heap, error)),
        };
        if !allowed(&table, caller, super_user, false) {
            return Err(badarg_cause(&mut process.heap, "access"));
        }
        let hash = table.is_hash();
        let start = match () {
            _ if items.is_some() => {
                let items = items.as_deref().ok_or_else(badarg)?;
                let run = if count {
                    select_chunk::decode_count(&registry, hash, items)?
                } else if hash {
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
                    count: run.count,
                    chunk: run.chunk,
                    backwards: run.backwards,
                    position: Some(run.position),
                    got: run.got,
                    accum: run.accum,
                    safety: match run.safety {
                        Some(safety) => safety,
                        None if hash => table.iteration_safety(caller),
                        None => IterSafety::Safe,
                    },
                    continued: true,
                    trapped: run.safety.is_some(),
                }
            }
            _ => {
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
                .map_err(|error| err(&mut process.heap, error))?;
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
                            .map_err(|error| err(&mut *heap.0, error))?;
                        if rows.is_empty() {
                            return Ok(Some(Term::atom(arinsal_term::atoms::EOT)));
                        }
                        let rows = TermBuilder::new(&mut heap)
                            .list_from_iter(rows)
                            .map_err(|_| badarg())?;
                        return TermBuilder::new(&mut heap)
                            .tuple(&[rows, Term::atom(arinsal_term::atoms::EOT)])
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
                    accum: (Term::NIL, 0),
                    safety,
                    continued: false,
                    trapped: false,
                }
            }
        };
        let shape = CycleShape {
            count: start.count,
            backwards: start.backwards,
            chunk: start.chunk,
            held: start.accum.1,
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
        program: _,
        program_owner,
        count,
        chunk,
        backwards,
        position: _,
        got,
        accum,
        safety,
        plan,
        continued,
        trapped: was_resumed,
    } = start;
    let mut cycle = match cycle {
        Ok(cycle) => cycle,
        Err(error) => {
            if was_resumed && safety != IterSafety::Safe {
                unfix_table(rt, tid, caller);
            }
            return Err(err(&mut process.heap, error));
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
    let next = next_of(&mut cycle);
    let mut fixed_now = false;
    if !matches!(next, Next::Return) && !was_resumed {
        // Port of erts/emulator/beam/erl_db.c (ets_select2, ets_select3), OTP-29.1.1:
        // fix immediately after the first trap; the traversal is not replayed.
        if hash && safety != IterSafety::Safe {
            let registry = rt.ets.read().unwrap();
            let mut table = registry
                .get_mut(tid)
                .map_err(|error| err(&mut process.heap, error))?;
            let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
            fix_table(&mut heap, &mut table, caller)?;
            fixed_now = true;
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
            let tree = matches!(position, ScanPosition::After(_));
            let got = got + cycle.counted;
            // A hash traversal charges all the reductions it has left (BUMP_ALL_REDS), an
            // ordered one the objects it visited.
            bump_direct(process, if tree { used } else { isize::MAX });
            let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
            let tid_term = rt
                .ets
                .read()
                .unwrap()
                .tid_term(tid, &mut heap)
                .map_err(|error| err(&mut *heap.0, error))?;
            // The matches so far, newest first: an unchunked call conses the cycle's onto the
            // list it got, a chunk is rebuilt from the at most one page it holds.
            let matches = if count {
                (Term::NIL, 0)
            } else {
                accumulated(&mut heap, accum, &cycle.results)?
            };
            let (continuation, export) = match (&position, count) {
                (_, true) => (
                    select_chunk::count_trap_continuation(
                        &mut heap,
                        tid_term,
                        &program_owner,
                        &position,
                        got,
                        safety,
                    )?,
                    "ets:count_trap/1",
                ),
                (ScanPosition::Slot(slot), false) => (
                    select_chunk::hash_trap_continuation(
                        &mut heap,
                        tid_term,
                        &program_owner,
                        *slot,
                        chunk,
                        matches,
                        safety,
                    )?,
                    "ets:select_trap/1",
                ),
                (ScanPosition::After(key), false) => (
                    select_chunk::tree_trap_continuation(
                        &mut heap,
                        tid_term,
                        &program_owner,
                        chunk,
                        backwards,
                        key,
                        matches,
                    )?,
                    "ets:select/1",
                ),
            };
            return Err(VmError::TrapExport(crate::ExportTrap::new(
                process,
                export,
                vec![continuation],
            )));
        }
        Next::Reverse(key) => {
            let end = match (&plan, &key) {
                (ScanPlan::Tree(plan), Some(_)) => plan
                    .end_condition_term(backwards)
                    .map(arinsal_ets::SavedKey::new)
                    .transpose()
                    .map_err(saved_key_error)?,
                _ => None,
            };
            bump_direct(process, used);
            let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
            let tid_term = rt
                .ets
                .read()
                .unwrap()
                .tid_term(tid, &mut heap)
                .map_err(|error| err(&mut *heap.0, error))?;
            let continuation = match &key {
                Some(key) => select_chunk::tree_continuation(
                    &mut heap,
                    tid_term,
                    &program_owner,
                    chunk,
                    backwards,
                    key,
                    end.as_ref(),
                )?,
                None => Term::atom(arinsal_term::atoms::EOT),
            };
            // `bif_trap3(&ets_select_reverse_exp, p, sc.accum, NIL, continuation)`: the
            // results newest first.
            let (accum, _) = accumulated(&mut heap, accum, &cycle.results)?;
            return Err(VmError::TrapExport(crate::ExportTrap::new(
                process,
                "ets:reverse/3",
                vec![accum, Term::NIL, continuation],
            )));
        }
        Next::Return => {}
    }
    let unfix = was_resumed && safety != IterSafety::Safe;
    let nothing_visited = !continued && cycle.iterations_left == iterations;
    if !(hash && chunk > 0 && nothing_visited) {
        bump_direct(process, used);
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
    let result = if chunk == 0 {
        // The list of an unchunked call is newest first: the results of this cycle go on the
        // front of what the trapped cycles left.
        let mut list = accum.0;
        for result in cycle.results {
            list = TermBuilder::new(&mut heap)
                .cons(result, list)
                .map_err(|_| badarg())?;
        }
        list
    } else if !hash || nothing_visited {
        Term::atom(arinsal_term::atoms::EOT)
    } else {
        let tid_term = rt
            .ets
            .read()
            .unwrap()
            .tid_term(tid, &mut heap)
            .map_err(|error| err(&mut *heap.0, error))?;
        // The accumulator is newest first; the chunk's results are in visit order.
        let mut values = select_chunk::expand(accum.0)?;
        values.extend(cycle.results);
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

/// The matches a trapping traversal hands on, newest first, and how many there are: the cycle's
/// results consed onto the list the call got, which is never rebuilt.
// Port of erts/emulator/beam/erl_db_hash.c (select_chunk_on_trap: `ctx->match_list`),
// OTP-29.1.1.
fn accumulated<H: HeapAlloc>(
    heap: &mut H,
    accum: (Term, usize),
    results: &[Term],
) -> Result<(Term, usize), VmError> {
    let mut list = accum.0;
    for &result in results {
        list = TermBuilder::new(heap)
            .cons(result, list)
            .map_err(|_| badarg())?;
    }
    Ok((list, accum.1 + results.len()))
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

// Port of erl_flxctr.c (`erts_flxctr_read_ctx_bin_dtor`).
arinsal_term::magic_payload!(DecentralizedReadSnapshotInfo => erts_flxctr_read_ctx_bin_dtor);
// Port of erl_flxctr.c (`erts_flxctr_wait_dtor`).
arinsal_term::magic_payload!(ErtsFlxCtrWakeUpLaterInfo => erts_flxctr_wait_dtor);

/// Port of erts/emulator/beam/erl_flxctr.c (`DecentralizedReadSnapshotInfo`), OTP-29.1.1.
struct DecentralizedReadSnapshotInfo {
    later_op: ErtsThrPrgrLaterOp,
    runtime: &'static crate::process::Runtime,
    pid: Pid,
    work: arinsal_ets::flxctr::BegunSnapshot,
    completed: AtomicBool,
    result: [AtomicIsize; arinsal_ets::flxctr::ATOMICS_PER_CACHE_LINE],
    structure_words: usize,
}

impl DecentralizedReadSnapshotInfo {
    fn counters(&self) -> arinsal_ets::CounterValues {
        arinsal_ets::CounterValues {
            size: self.result[arinsal_ets::NITEMS_COUNTER_ID].load(AtomicOrdering::Acquire),
            memory_words: self.structure_words
                + self.result[arinsal_ets::MEM_COUNTER_ID]
                    .load(AtomicOrdering::Acquire)
                    .max(0) as usize,
        }
    }
}

/// Port of erts/emulator/beam/erl_flxctr.c (`ErtsFlxCtrWakeUpLaterInfo`), OTP-29.1.1.
struct ErtsFlxCtrWakeUpLaterInfo {
    later_op: ErtsThrPrgrLaterOp,
    runtime: &'static crate::process::Runtime,
    pid: Pid,
}

/// `erts_flxctr_is_snapshot_result` and `erts_flxctr_get_snapshot_result_after_trap`.
fn snapshot_result_of(term: Term) -> Option<arinsal_ets::CounterValues> {
    term.with_magic_payload::<DecentralizedReadSnapshotInfo, _>(
        DecentralizedReadSnapshotInfo::counters,
    )
}

fn retain_magic_for_later(bin: &MagicBin) -> *mut () {
    std::mem::forget(bin.clone());
    MagicBin::as_ptr(bin) as *mut ()
}

struct NoopHost;

impl arinsal_ets::flxctr::SnapshotHost for NoopHost {
    fn suspend_and_run_later(&mut self, _op: Box<dyn FnOnce() + Send + 'static>) {
        unreachable!("a centralized snapshot does not suspend");
    }
}

/// Port of erts/emulator/beam/erl_flxctr.c:299-318 (snapshot magic bin + later op), OTP-29.1.1.
fn schedule_snapshot_later_op(
    process: &mut Process,
    ctx: Option<&mut RunCtx<'_, crate::Process>>,
    bin: MagicBin,
) -> Result<(), VmError> {
    let Some(ctx) = ctx else {
        return Err(needs_context());
    };
    crate::suspend::suspend_self(process);
    crate::bif_traps::vbump_all_reds(process);
    let lop = crate::code_ix::raw_magic_payload::<DecentralizedReadSnapshotInfo>(&bin)
        .later_op
        .as_list_node();
    let data = retain_magic_for_later(&bin);
    ctx.erts_schedule_thr_prgr_later_op(thr_prg_wake_up_and_count, data, lop);
    Ok(())
}

/// Port of erts/emulator/beam/erl_flxctr.c:154 (`suspend_until_thr_prg`), OTP-29.1.1.
fn suspend_until_thr_prg(
    process: &mut Process,
    ctx: Option<&mut RunCtx<'_, crate::Process>>,
    pid: Pid,
) -> Result<(), VmError> {
    let (Some(runtime), Some(ctx)) = (process.runtime, ctx) else {
        return Err(needs_context());
    };
    let bin = MagicBin::with_erts_payload_size(
        ErtsFlxCtrWakeUpLaterInfo {
            later_op: ErtsThrPrgrLaterOp::new(),
            runtime,
            pid,
        },
        std::mem::size_of::<ErtsFlxCtrWakeUpLaterInfo>(),
    );
    crate::suspend::suspend_self(process);
    crate::bif_traps::vbump_all_reds(process);
    let lop = crate::code_ix::raw_magic_payload::<ErtsFlxCtrWakeUpLaterInfo>(&bin)
        .later_op
        .as_list_node();
    let data = retain_magic_for_later(&bin);
    ctx.erts_schedule_thr_prgr_later_op(thr_prg_wake_up_later, data, lop);
    Ok(())
}

/// Port of erts/emulator/beam/erl_flxctr.c:125 (`thr_prg_wake_up_later`), OTP-29.1.1.
fn thr_prg_wake_up_later(data: *mut ()) {
    let bin = crate::code_ix::magic_from_later_data(data);
    let info = crate::code_ix::raw_magic_payload::<ErtsFlxCtrWakeUpLaterInfo>(&bin);
    crate::natives::code::resume_suspended(info.runtime, info.pid);
}

/// Port of erts/emulator/beam/erl_flxctr.c:75 (`thr_prg_wake_up_and_count`), OTP-29.1.1.
fn thr_prg_wake_up_and_count(data: *mut ()) {
    let bin = crate::code_ix::magic_from_later_data(data);
    let info = crate::code_ix::raw_magic_payload::<DecentralizedReadSnapshotInfo>(&bin);
    if !info.completed.swap(true, AtomicOrdering::AcqRel) {
        let mut values = [0isize; arinsal_ets::flxctr::ATOMICS_PER_CACHE_LINE];
        info.work.complete(&mut values);
        for (slot, value) in info.result.iter().zip(values) {
            slot.store(value, AtomicOrdering::Release);
        }
    }
    crate::natives::code::resume_suspended(info.runtime, info.pid);
}

/// `erts_make_integer`.
fn make_integer(process: &mut Process, value: i128) -> Result<Term, VmError> {
    TermBuilder::new(&mut arinsal_bifs::ProcessHeapHandle(&mut process.heap))
        .int_from_i128(value)
        .map_err(|_| badarg())
}

/// `ets:info/1` and the `size` and `memory` items of `ets:info/2`: the table counters are read
/// as one snapshot. A decentralized table swaps its counter array, suspends the caller until
/// thread progress and traps with the snapshot (`ets_info_1`/`ets_info_2` of erl_db.c);
/// `Ok(None)` leaves every other item to the generic path.
// Port of erts/emulator/beam/erl_db.c (ets_info_1, ets_info_2) and erl_flxctr.c
// (erts_flxctr_snapshot), OTP-29.1.1.
fn info_counters(
    process: &mut Process,
    ctx: Option<&mut RunCtx<'_, crate::Process>>,
    caller_pid: Pid,
    args: &[Term],
) -> Result<Option<Term>, VmError> {
    let rt = process.runtime.ok_or_else(badarg)?;
    let am_memory = ETS_ATOMS.get("memory").copied();
    let key = match args {
        [snapshot, key] => {
            if let Some(counters) = snapshot_result_of(*snapshot) {
                let value = if key.as_atom() == am_memory {
                    counters.memory_words as i128
                } else {
                    counters.size as i128
                };
                return make_integer(process, value).map(Some);
            }
            match info_item_name(*key) {
                Some(name @ ("size" | "memory")) => Some(name),
                _ => return Ok(None),
            }
        }
        _ => None,
    };
    // `ets:info/1` after the trap gets `{Snapshot, Table}`.
    let (table_arg, mut snapshot) = match args {
        [table] => {
            // SAFETY: the argument is in the caller's live process heap.
            match unsafe { table.tuple_ref() } {
                Some(pair) if pair.len() == 2 => {
                    let state = snapshot_result_of(pair.get(0).unwrap());
                    match state {
                        Some(counters) => (pair.get(1).unwrap(), Some(counters)),
                        None => (*table, None),
                    }
                }
                _ => (*table, None),
            }
        }
        [table, _] => (*table, None),
        _ => return Ok(None),
    };
    let registry = RegistryAccess::Shared(rt.ets.read().unwrap());
    let tid = match resolve(&registry, table_arg) {
        Ok(tid) => tid,
        Err(ResolveFail::Missing) => {
            return Ok(Some(Term::atom(arinsal_term::atoms::UNDEFINED)));
        }
        Err(ResolveFail::BadType) => return Err(badarg_cause(&mut process.heap, "type")),
    };
    let table = table_guard(&registry, tid, true, &mut process.heap)?;
    let schedulers = if key == Some("size") {
        1
    } else {
        rt.scheduler()?.scheduler_count()
    };
    enum TrapKind {
        Wait,
        Snapshot(MagicBin),
    }
    let mut trap_with = None;
    if snapshot.is_none() {
        let counters = table.counters();
        if ctx.is_none() && counters.is_decentralized() {
            // The direct call cannot suspend the process: the scheduler path takes the snapshot.
            return Err(needs_context());
        }
        if !counters.is_decentralized() {
            match counters.snapshot(&mut NoopHost) {
                arinsal_ets::flxctr::SnapshotResult::Done(values) => {
                    snapshot = Some(arinsal_ets::CounterValues {
                        size: values[arinsal_ets::NITEMS_COUNTER_ID],
                        memory_words: table.structure_memory_words_for_schedulers(schedulers)
                            + values[arinsal_ets::MEM_COUNTER_ID].max(0) as usize,
                    });
                }
                _ => return Err(badarg()),
            }
        } else if let Some(work) = counters.try_begin_snapshot() {
            let runtime = process.runtime.ok_or_else(needs_context)?;
            trap_with = Some(TrapKind::Snapshot(MagicBin::with_erts_payload_size(
                DecentralizedReadSnapshotInfo {
                    later_op: ErtsThrPrgrLaterOp::new(),
                    runtime,
                    pid: caller_pid,
                    work,
                    completed: AtomicBool::new(false),
                    result: std::array::from_fn(|_| AtomicIsize::new(0)),
                    structure_words: table.structure_memory_words_for_schedulers(schedulers),
                },
                std::mem::size_of::<DecentralizedReadSnapshotInfo>(),
            )));
        } else {
            trap_with = Some(TrapKind::Wait);
        }
    }
    if let Some(kind) = trap_with {
        // `db_unlock` before the trap.
        drop(table);
        drop(registry);
        let state_term = match &kind {
            TrapKind::Snapshot(bin) => Some(
                TermBuilder::new(&mut arinsal_bifs::ProcessHeapHandle(&mut process.heap))
                    .magic_ref(bin.clone())
                    .map_err(|_| badarg())?,
            ),
            TrapKind::Wait => None,
        };
        match kind {
            TrapKind::Wait => suspend_until_thr_prg(process, ctx, caller_pid)?,
            TrapKind::Snapshot(bin) => {
                schedule_snapshot_later_op(process, ctx, bin)?;
            }
        }
        let trap_args = if args.len() == 2 {
            vec![state_term.unwrap_or(args[0]), args[1]]
        } else if let Some(state) = state_term {
            let tuple = TermBuilder::new(&mut arinsal_bifs::ProcessHeapHandle(&mut process.heap))
                .tuple(&[state, table_arg])
                .map_err(|_| badarg())?;
            vec![tuple]
        } else {
            vec![table_arg]
        };
        let continuation = if args.len() == 2 {
            "ets:info/2"
        } else {
            "ets:info/1"
        };
        return Err(VmError::TrapExport(crate::ExportTrap::new(
            process,
            continuation,
            trap_args,
        )));
    }
    let counters = snapshot.expect("the snapshot is complete");
    let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
    let node = Term::atom(arinsal_term::atoms::NONAME);
    let value = match key {
        Some(key) => {
            table.info_item_with_counters(key, node, &mut heap, schedulers, Some(counters))
        }
        None => table.info_list_with_counters(node, &mut heap, schedulers, Some(counters)),
    };
    value
        .map(Some)
        .map_err(|error| err(&mut process.heap, error))
}

/// Run one ETS BIF. `ctx` is only present on the scheduler path: erts sends messages
/// (give_away, request_all) and traps (delete) through the process, so those need it; every
/// other table operation runs from the caller pid alone, as erts runs them from BeamAsm.
fn call_inner(
    process: &mut Process,
    mut ctx: Option<&mut RunCtx<'_, crate::Process>>,
    caller_pid: Pid,
    function: EtsBif,
    args: &[Term],
) -> Result<Term, VmError> {
    let super_user = ets_super_user(process);
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
        .map_err(|error| err(&mut *heap.0, error));
    }
    if function == EtsBif::SuperUser {
        let [flag] = args else {
            return Err(badarg());
        };
        // Port of erts/emulator/beam/erl_db.c:4712-4721 (erts_internal_ets_super_user_1),
        // OTP-29.1.1.
        let on = if *flag == Term::atom(arinsal_term::atoms::TRUE) {
            true
        } else if *flag == Term::atom(arinsal_term::atoms::FALSE) {
            false
        } else {
            return Err(badarg());
        };
        process
            .heap
            .set_flag(arinsal_term::pflags::F_ETS_SUPER_USER, on);
        return Ok(Term::atom(arinsal_term::atoms::OK));
    }
    if ctx.is_some()
        && gated_by_busy(function)
        && let Some(&target) = args.first()
    {
        help_busy_table(process, target, false)?;
    }
    if matches!(
        (function, args.len()),
        (EtsBif::Delete, 1) | (EtsBif::InternalDeleteAll, 2)
    ) {
        return delete_or_clear(process, function, args, caller);
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
        ) | (EtsBif::SelectCount, 1)
    ) && let Some(value) = hash_select(process, caller_pid, function, args)?
    {
        return Ok(value);
    }
    if function == EtsBif::Info
        && let Some(value) = info_counters(process, ctx.as_deref_mut(), caller_pid, args)?
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
    let table_refn = (function == EtsBif::New)
        .then(|| arinsal_sched::unique::ordinary_ref_words(process.next_ref()));
    let match_program_refn = (function == EtsBif::MatchSpecCompile)
        .then(|| arinsal_sched::unique::ordinary_ref_words(process.next_ref()));
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
                if option == Term::atom(arinsal_term::atoms::NAMED_TABLE) {
                    opts.named_table = true;
                } else if option == Term::atom(arinsal_term::atoms::SET) {
                    opts.table_type = TableType::Set;
                } else if option == Term::atom(arinsal_term::atoms::ORDERED_SET) {
                    opts.table_type = TableType::OrderedSet;
                    opts.decentralized_counters = true;
                } else if option == Term::atom(arinsal_term::atoms::BAG) {
                    opts.table_type = TableType::Bag;
                } else if option == Term::atom(arinsal_term::atoms::DUPLICATE_BAG) {
                    opts.table_type = TableType::DuplicateBag;
                } else if option == Term::atom(arinsal_term::atoms::PRIVATE) {
                    opts.protection = Protection::Private;
                } else if option == Term::atom(arinsal_term::atoms::PROTECTED) {
                    opts.protection = Protection::Protected;
                } else if option == Term::atom(arinsal_term::atoms::PUBLIC) {
                    opts.protection = Protection::Public;
                } else if option == Term::atom(arinsal_term::atoms::COMPRESSED) {
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
                        if pid != Term::atom(arinsal_term::atoms::NONE) {
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
                                    Term::atom(arinsal_term::atoms::UNDEFINED)
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
                .unwrap_or(opts.decentralized_counters);
            opts.normalize_erts_lock_flags()
                .map_err(|error| err(&mut *heap.0, error))?;
            // Port of erts/emulator/beam/erl_db.c (ets_new_2), OTP-29.1.1.
            // db_create_table allocates its btid magic binary on this scheduler.
            let tid = registry
                .exclusive()?
                .create_with_magic_ref_numbers(opts, table_refn.unwrap())
                .map_err(|error| match error {
                    EtsError::NameTaken => badarg_cause(&mut *heap.0, "already_exists"),
                    error => err(&mut *heap.0, error),
                })?;
            // erl_db.c: BIF_P->flags |= F_USING_DB so exit can find the table.
            if !rt.publish_proc_flag(caller_pid, arinsal_sched::proc_flags::USING_DB) {
                registry.exclusive()?.detach(tid).ok();
                return Err(badarg());
            }
            if registry
                .get(tid)
                .map_err(|error| err(&mut *heap.0, error))?
                .options
                .named_table
            {
                Ok(Term::atom(name.as_atom().unwrap()))
            } else {
                registry
                    .tid_term(tid, &mut heap)
                    .map_err(|error| err(&mut *heap.0, error))
            }
        }
        (EtsBif::Whereis, [name]) => Ok(registry
            .whereis(name.as_atom().ok_or_else(badarg)?)
            .map(|tid| registry.tid_term(tid, &mut heap))
            .transpose()
            .map_err(|error| err(&mut *heap.0, error))?
            .unwrap_or(Term::atom(arinsal_term::atoms::UNDEFINED))),
        (EtsBif::Rename, [target, name]) => {
            // Port of erts/emulator/beam/erl_db.c (ets_rename_2), OTP-29.1.1:
            // the table needs write access, and is looked up even for a bad name.
            let tid = handle(&mut *heap.0, &registry, *target)?;
            let named = {
                let table = registry
                    .get(tid)
                    .map_err(|error| err(&mut *heap.0, error))?;
                if table.is_busy() {
                    return Err(VmError::Yield);
                }
                if !allowed(&table, caller, super_user, true) {
                    return Err(badarg_cause(&mut *heap.0, "access"));
                }
                table.options.named_table
            };
            let new_name = name.as_atom().ok_or_else(badarg)?;
            registry
                .exclusive()?
                .rename(tid, new_name)
                .map_err(|error| err(&mut *heap.0, error))?;
            // Unnamed tables keep their id; only the displayed name changes.
            // Port of erts/emulator/beam/erl_db.c (ets_rename_2), OTP-29.1.1.
            if named { Ok(*name) } else { Ok(*target) }
        }
        (EtsBif::Info, [target]) | (EtsBif::Info, [target, _]) => {
            // Missing tables yield `undefined`; a non-id argument is `badarg`.
            // Port of erts/emulator/beam/erl_db.c and :4544, OTP-29.1.1.
            let tid = match resolve(&registry, *target) {
                Ok(tid) => tid,
                Err(ResolveFail::Missing) => return Ok(Term::atom(arinsal_term::atoms::UNDEFINED)),
                Err(ResolveFail::BadType) => return Err(badarg_cause(&mut *heap.0, "type")),
            };
            // Port of erts/emulator/beam/erl_db.c (ets_info_2, DB_INFO/LCK_READ),
            // OTP-29.1.1.
            if args.len() == 1 {
                let table = table_guard(&registry, tid, true, &mut *heap.0)?;
                let schedulers = rt.scheduler()?.scheduler_count();
                table
                    .info_list_for_schedulers(Term::atom(arinsal_term::atoms::NONAME), &mut heap, schedulers)
                    .map_err(|error| err(&mut *heap.0, error))
            } else {
                let key = info_item_name(args[1]).ok_or_else(badarg)?;
                let table = table_guard(&registry, tid, true, &mut *heap.0)?;
                let schedulers = if key == "memory" {
                    rt.scheduler()?.scheduler_count()
                } else {
                    1
                };
                table
                    .info_item_for_schedulers(key, Term::atom(arinsal_term::atoms::NONAME), &mut heap, schedulers)
                    .map_err(|error| err(&mut *heap.0, error))
            }
        }
        (EtsBif::Delete, [target, key]) => {
            let tid = handle(&mut *heap.0, &registry, *target)?;
            if registry
                .shared(tid)
                .map_err(|error| err(&mut *heap.0, error))?
                .options()
                .write_concurrency
                != WriteConcurrency::Disabled
            {
                let table = registry
                    .get_shared(tid)
                    .map_err(|error| err(&mut *heap.0, error))?;
                if !allowed(&table, caller, super_user, true) {
                    return Err(badarg_cause(&mut *heap.0, "access"));
                }
                if table.delete_key_shared(*key) {
                    return Ok(Term::atom(arinsal_term::atoms::TRUE));
                }
            }
            let mut table = registry
                .get_mut(tid)
                .map_err(|error| err(&mut *heap.0, error))?;
            if !allowed(&table, caller, super_user, true) {
                return Err(badarg_cause(&mut *heap.0, "access"));
            }
            table.delete_key(*key);
            Ok(Term::atom(arinsal_term::atoms::TRUE))
        }
        // Port of erts/emulator/beam/erl_db.c and erl_db_hash.c,
        // OTP-29.1.1.
        (EtsBif::LookupBinaryInfo, [target, key]) => {
            let tid = handle(&mut *heap.0, &registry, *target)?;
            let table = registry
                .get_shared(tid)
                .map_err(|error| err(&mut *heap.0, error))?;
            if !allowed(&table, caller, super_user, false) {
                return Err(badarg_cause(&mut *heap.0, "access"));
            }
            let binaries = table
                .lookup_binary_info(*key, &mut heap)
                .map_err(|error| binary_info_err(&mut *heap.0, error))?;
            TermBuilder::new(&mut heap)
                .list_from_iter(binaries)
                .map_err(|_| system_limit())
        }
        // Port of erts/emulator/beam/erl_db.c (`ets_setopts_2`),
        // OTP-29.1.1.
        (EtsBif::SetOpts, [target, options]) => {
            let tid = handle(&mut *heap.0, &registry, *target)?;
            let mut table = registry
                .get_mut(tid)
                .map_err(|error| err(&mut *heap.0, error))?;
            if !allowed(&table, caller, super_user, true) {
                return Err(badarg_cause(&mut *heap.0, "access"));
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
                            Term::atom(arinsal_term::atoms::UNDEFINED)
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
                .map_err(|error| err(&mut *heap.0, error))?;
            if matches!(heir, Some(None)) {
                table.options.heir = None;
            }
            Ok(Term::atom(arinsal_term::atoms::TRUE))
        }
        // Port of erts/emulator/beam/erl_db.c (`erts_internal_ets_raw_first_1`),
        // OTP-29.1.1.
        (EtsBif::RawFirst, [target]) => {
            let tid = handle(&mut *heap.0, &registry, *target)?;
            let table = registry
                .get_shared(tid)
                .map_err(|error| err(&mut *heap.0, error))?;
            if !allowed(&table, caller, super_user, false) {
                return Err(badarg_cause(&mut *heap.0, "access"));
            }
            Ok(table
                .raw_first(&mut heap)
                .map_err(|error| err(&mut *heap.0, error))?
                .unwrap_or(Term::atom(arinsal_term::atoms::EOT)))
        }
        // Port of erts/emulator/beam/erl_db.c (`erts_internal_ets_raw_next_2`),
        // OTP-29.1.1.
        (EtsBif::RawNext, [target, key]) => {
            let tid = handle(&mut *heap.0, &registry, *target)?;
            let table = registry
                .get_shared(tid)
                .map_err(|error| err(&mut *heap.0, error))?;
            if !allowed(&table, caller, super_user, false) {
                return Err(badarg_cause(&mut *heap.0, "access"));
            }
            Ok(table
                .raw_next(*key, &mut heap)
                .map_err(|error| err(&mut *heap.0, error))?
                .unwrap_or(Term::atom(arinsal_term::atoms::EOT)))
        }
        (EtsBif::Take, [target, key]) => {
            let tid = handle(&mut *heap.0, &registry, *target)?;
            if registry
                .shared(tid)
                .map_err(|error| err(&mut *heap.0, error))?
                .options()
                .write_concurrency
                != WriteConcurrency::Disabled
            {
                let table = registry
                    .get_shared(tid)
                    .map_err(|error| err(&mut *heap.0, error))?;
                if !allowed(&table, caller, super_user, true) {
                    return Err(badarg_cause(&mut *heap.0, "access"));
                }
                if table.options.table_type != TableType::OrderedSet {
                    let values = table
                        .take_shared(*key, &mut heap)
                        .map_err(|error| err(&mut *heap.0, error))?;
                    return output_list(&mut heap, values);
                }
            }
            let mut table = registry
                .get_mut(tid)
                .map_err(|error| err(&mut *heap.0, error))?;
            if !allowed(&table, caller, super_user, true) {
                return Err(badarg_cause(&mut *heap.0, "access"));
            }
            let values = table
                .take(*key, &mut heap)
                .map_err(|error| err(&mut *heap.0, error))?;
            output_list(&mut heap, values)
        }
        (EtsBif::Slot, [target, index]) => {
            let tid = handle(&mut *heap.0, &registry, *target)?;
            let table = registry
                .get_shared(tid)
                .map_err(|error| err(&mut *heap.0, error))?;
            if !allowed(&table, caller, super_user, false) {
                return Err(badarg_cause(&mut *heap.0, "access"));
            }
            let slot =
                usize::try_from(index.as_small().ok_or_else(badarg)?).map_err(|_| badarg())?;
            Ok(table
                .slot(slot, &mut heap)
                .map_err(|error| err(&mut *heap.0, error))?
                .unwrap_or(Term::atom(arinsal_term::atoms::EOT)))
        }
        (EtsBif::First | EtsBif::Last, [target]) => {
            let tid = handle(&mut *heap.0, &registry, *target)?;
            let table = table_guard(&registry, tid, true, &mut *heap.0)?;
            if !allowed(&table, caller, super_user, false) {
                return Err(badarg_cause(&mut *heap.0, "access"));
            }
            Ok(table
                .edge(function == EtsBif::Last, &mut heap)
                .map_err(|error| err(&mut *heap.0, error))?
                .unwrap_or(Term::atom(arinsal_term::atoms::EOT)))
        }
        (EtsBif::Next | EtsBif::Prev, [target, key]) => {
            // `'$end_of_table'` is DB_ERROR_BADKEY in db_next_tree / db_prev_tree.
            // Port of erts/emulator/beam/erl_db_tree.c, OTP-29.1.1.
            if end_of_table(*key) {
                return Err(badarg());
            }
            let tid = handle(&mut *heap.0, &registry, *target)?;
            let table = table_guard(&registry, tid, true, &mut *heap.0)?;
            if !allowed(&table, caller, super_user, false) {
                return Err(badarg_cause(&mut *heap.0, "access"));
            }
            Ok((if function == EtsBif::Next {
                table.next(*key, &mut heap)
            } else {
                table.prev(*key, &mut heap)
            })
            .map_err(|error| err(&mut *heap.0, error))?
            .unwrap_or(Term::atom(arinsal_term::atoms::EOT)))
        }
        // Port of erts/emulator/beam/erl_db.c (ets_first_lookup_1),
        // :1238 (ets_next_lookup_2), :1286 (ets_last_lookup_1) and
        // :1332 (ets_prev_lookup_2), OTP-29.1.1. Hash tables treat last as
        // first and prev as next (erl_db_hash.c).
        (EtsBif::FirstLookup | EtsBif::LastLookup, [target]) => {
            let tid = handle(&mut *heap.0, &registry, *target)?;
            let table = table_guard(&registry, tid, true, &mut *heap.0)?;
            if !allowed(&table, caller, super_user, false) {
                return Err(badarg_cause(&mut *heap.0, "access"));
            }
            match table
                .edge_lookup(function == EtsBif::LastLookup, &mut heap)
                .map_err(|error| err(&mut *heap.0, error))?
            {
                None => Ok(Term::atom(arinsal_term::atoms::EOT)),
                Some((key, objects)) => lookup_pair(&mut heap, key, objects),
            }
        }
        (EtsBif::NextLookup | EtsBif::PrevLookup, [target, key]) => {
            if end_of_table(*key) {
                return Err(badarg());
            }
            let tid = handle(&mut *heap.0, &registry, *target)?;
            let table = table_guard(&registry, tid, true, &mut *heap.0)?;
            if !allowed(&table, caller, super_user, false) {
                return Err(badarg_cause(&mut *heap.0, "access"));
            }
            match table
                .adjacent_lookup(*key, function == EtsBif::PrevLookup, &mut heap)
                .map_err(|error| err(&mut *heap.0, error))?
            {
                None => Ok(Term::atom(arinsal_term::atoms::EOT)),
                Some((found, objects)) => lookup_pair(&mut heap, found, objects),
            }
        }
        (EtsBif::SafeFixtable, [target, fixed]) => {
            let tid = handle(&mut *heap.0, &registry, *target)?;
            let mut table = registry
                .get_mut(tid)
                .map_err(|error| err(&mut *heap.0, error))?;
            if !allowed(&table, caller, super_user, false) {
                return Err(badarg_cause(&mut *heap.0, "access"));
            }
            let fixed = boolean(*fixed)?;
            if fixed {
                fix_table(&mut heap, &mut table, caller)?;
                drop(table);
                registry.exclusive()?.note_fixation(caller, tid);
                // erl_db.c and 5187: a fixation sets F_USING_DB on the fixing process.
                let _ = rt.publish_proc_flag(caller_pid, arinsal_sched::proc_flags::USING_DB);
            } else {
                table
                    .safe_fixtable_for(caller, false)
                    .map_err(|error| err(&mut *heap.0, error))?;
            }
            Ok(Term::atom(arinsal_term::atoms::TRUE))
        }
        (EtsBif::DeleteObject, [target, object]) => {
            let tid = handle(&mut *heap.0, &registry, *target)?;
            if registry
                .shared(tid)
                .map_err(|error| err(&mut *heap.0, error))?
                .options()
                .write_concurrency
                != WriteConcurrency::Disabled
            {
                let table = registry
                    .get_shared(tid)
                    .map_err(|error| err(&mut *heap.0, error))?;
                if !allowed(&table, caller, super_user, true) {
                    return Err(badarg_cause(&mut *heap.0, "access"));
                }
                if table
                    .delete_object_shared(*object)
                    .map_err(|error| err(&mut *heap.0, error))?
                {
                    return Ok(Term::atom(arinsal_term::atoms::TRUE));
                }
            }
            let mut table = registry
                .get_mut(tid)
                .map_err(|error| err(&mut *heap.0, error))?;
            if !allowed(&table, caller, super_user, true) {
                return Err(badarg_cause(&mut *heap.0, "access"));
            }
            table
                .delete_object(*object)
                .map_err(|error| err(&mut *heap.0, error))?;
            Ok(Term::atom(arinsal_term::atoms::TRUE))
        }
        (EtsBif::GiveAway, [target, new_owner, data]) => {
            // Port of erts/emulator/beam/erl_db.c (ets_give_away_3), OTP-29.1.1:
            // table errors come first, then the receiver, then ownership.
            let tid = handle(&mut *heap.0, &registry, *target)?;
            {
                let table = registry
                    .get(tid)
                    .map_err(|error| err(&mut *heap.0, error))?;
                if !allowed(&table, caller, super_user, true) {
                    return Err(badarg_cause(&mut *heap.0, "access"));
                }
            }
            let pid = Pid::from_term(*new_owner).ok_or_else(badarg)?;
            if *new_owner != caller && !rt.scheduler().map_err(|_| badarg())?.lookup(pid) {
                return Err(badarg());
            }
            let options = registry
                .get(tid)
                .map_err(|error| err(&mut *heap.0, error))?
                .options;
            if options.owner != caller {
                return Err(badarg_cause(&mut *heap.0, "not_owner"));
            }
            if *new_owner == caller {
                return Err(badarg_cause(&mut *heap.0, "owner"));
            }
            // Port of erts/emulator/beam/erl_db.c (send_ets_transfer_message),
            // OTP-29.1.1: a named table is identified by its name.
            let tab = if options.named_table {
                Term::atom(options.name)
            } else {
                registry
                    .tid_term(tid, &mut heap)
                    .map_err(|error| err(&mut *heap.0, error))?
            };
            let transfer = TermBuilder::new(&mut heap)
                .tuple(&[Term::atom(arinsal_term::atoms::ETS_TRANSFER), tab, caller, *data])
                .map_err(|_| badarg())?;
            registry
                .exclusive()?
                .give_away(tid, *new_owner)
                .map_err(|error| err(&mut *heap.0, error))?;
            // erl_db.c: the receiver's F_USING_DB is set so its exit deletes the table.
            if !rt.publish_proc_flag(pid, arinsal_sched::proc_flags::USING_DB) {
                return Err(badarg());
            }
            ctx.as_deref_mut()
                .ok_or_else(needs_context)?
                .send(pid, Message::copy_from(transfer)?)
                .map_err(|_| badarg())?;
            Ok(Term::atom(arinsal_term::atoms::TRUE))
        }
        (EtsBif::Select | EtsBif::SelectReverse, [target, spec])
        | (EtsBif::Match, [target, spec])
        | (EtsBif::MatchObject, [target, spec]) => {
            let tid = handle(&mut *heap.0, &registry, *target)?;
            let table = table_guard(&registry, tid, true, &mut *heap.0)?;
            if !allowed(&table, caller, super_user, false) {
                return Err(badarg_cause(&mut *heap.0, "access"));
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
            .map_err(|error| err(&mut *heap.0, error))?;
            let values = if function == EtsBif::Match {
                table.match_pattern(*spec, &mut heap)
            } else if function == EtsBif::MatchObject {
                table.match_object(*spec, &mut heap)
            } else {
                table.select(&program, function == EtsBif::SelectReverse, &mut heap)
            }
            .map_err(|error| err(&mut *heap.0, error))?;
            TermBuilder::new(&mut heap)
                .list_from_iter(values)
                .map_err(|_| badarg())
        }
        (EtsBif::MatchSpecCompile, [spec]) => {
            // Port of erts/emulator/beam/erl_db.c
            // (ets_match_spec_compile_1), OTP-29.1.1. The program lifetime follows
            // the magic reference through the process heap and its garbage collector.
            let program = Arc::new(
                MatchProgram::compile(*spec).map_err(|error| err(&mut *heap.0, error))?,
            );
            let payload_size = program.erts_magic_payload_size();
            TermBuilder::new(&mut heap)
                .magic_ref(MagicBin::with_erts_payload_size_and_refn(
                    select_chunk::MatchProgRef(program),
                    payload_size,
                    match_program_refn.expect("match-spec compile reference numbers"),
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
            let reference = Term::local_ref(&mut heap, arinsal_sched::unique::ordinary_ref_words(id))
                .map_err(|_| badarg())?;
            let tables = live_table_terms(&registry, &mut *heap.0)?;
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
                if let Some(result) = program
                    .run(object, &mut heap)
                    .map_err(|error| err(&mut *heap.0, error))?
                {
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
            let tid = handle(&mut *heap.0, &registry, *target)?;
            if function == EtsBif::SelectReplace
                && registry
                    .shared(tid)
                    .map_err(|error| err(&mut *heap.0, error))?
                    .options()
                    .write_concurrency
                    != WriteConcurrency::Disabled
            {
                let table = registry
                    .get_shared(tid)
                    .map_err(|error| err(&mut *heap.0, error))?;
                if !allowed(&table, caller, super_user, true) {
                    return Err(badarg_cause(&mut *heap.0, "access"));
                }
                if table.options.table_type == TableType::Bag {
                    return Err(badarg_cause(&mut *heap.0, "table_type"));
                }
                if *spec == Term::NIL {
                    return Term::small(0).ok_or_else(badarg);
                }
                let program = MatchProgram::compile(*spec)
                    .map_err(|error| err(&mut *heap.0, error))?;
                if let Some(count) = table
                    .select_replace_key_shared(&program)
                    .map_err(|error| err(&mut *heap.0, error))?
                {
                    return TermBuilder::new(&mut heap)
                        .int_from_i128(count as i128)
                        .map_err(|_| badarg());
                }
            }
            if function == EtsBif::SelectCount {
                let table = registry
                    .get_shared(tid)
                    .map_err(|error| err(&mut *heap.0, error))?;
                if !allowed(&table, caller, super_user, false) {
                    return Err(badarg_cause(&mut *heap.0, "access"));
                }
                if *spec == Term::NIL {
                    return Term::small(0).ok_or_else(badarg);
                }
                let program = MatchProgram::compile(*spec)
                    .map_err(|error| err(&mut *heap.0, error))?;
                let count = table
                    .select_count(&program)
                    .map_err(|error| err(&mut *heap.0, error))?;
                return TermBuilder::new(&mut heap)
                    .int_from_i128(count as i128)
                    .map_err(|_| badarg());
            }
            let mut table = registry
                .get_mut(tid)
                .map_err(|error| err(&mut *heap.0, error))?;
            if !allowed(&table, caller, super_user, function != EtsBif::SelectCount) {
                return Err(badarg_cause(&mut *heap.0, "access"));
            }
            // Port of erts/emulator/beam/erl_db.c (ets_select_replace_2), OTP-29.1.1.
            if function == EtsBif::SelectReplace && table.options.table_type == TableType::Bag {
                return Err(badarg_cause(&mut *heap.0, "table_type"));
            }
            if *spec == Term::NIL {
                return Term::small(0).ok_or_else(badarg);
            }
            let program = MatchProgram::compile(*spec)
                .map_err(|error| err(&mut *heap.0, error))?;
            let count = match function {
                EtsBif::SelectCount => table.select_count(&program),
                EtsBif::InternalSelectDelete => table.select_delete(&program),
                EtsBif::SelectReplace => table.select_replace(&program),
                _ => unreachable!(),
            }
            .map_err(|error| err(&mut *heap.0, error))?;
            TermBuilder::new(&mut heap)
                .int_from_i128(count as i128)
                .map_err(|_| badarg())
        }
        (EtsBif::LookupElement, [target, key, position])
        | (EtsBif::LookupElement, [target, key, position, _]) => {
            let tid = handle(&mut *heap.0, &registry, *target)?;
            let table = registry
                .get_shared(tid)
                .map_err(|error| err(&mut *heap.0, error))?;
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
            let tid = handle(&mut *heap.0, &registry, *target)?;
            if registry
                .shared(tid)
                .map_err(|error| err(&mut *heap.0, error))?
                .options()
                .write_concurrency
                != WriteConcurrency::Disabled
            {
                let table = registry
                    .get_shared(tid)
                    .map_err(|error| err(&mut *heap.0, error))?;
                if table.options.table_type == TableType::Set {
                    if !allowed(&table, caller, super_user, true) {
                        return Err(badarg_cause(&mut *heap.0, "access"));
                    }
                    let default = default_object(&mut *heap.0, &table, args.get(3).copied())?;
                    let parsed = update_list(*updates, |entry| {
                        match tuple_items(entry)?.as_slice() {
                            [position_term, value] => Some((position(*position_term)?, *value)),
                            _ => None,
                        }
                    });
                    return Ok(boolean_term(
                        table
                            .update_element_shared(*key, &parsed, default)
                            .map_err(|error| err(&mut *heap.0, error))?,
                    ));
                }
            }
            let mut table = registry
                .get_mut(tid)
                .map_err(|error| err(&mut *heap.0, error))?;
            if !allowed(&table, caller, super_user, true) {
                return Err(badarg_cause(&mut *heap.0, "access"));
            }
            let default = default_object(&mut *heap.0, &table, args.get(3).copied())?;
            // Port of erts/emulator/beam/erl_db.c (do_update_element), OTP-29.1.1:
            // a malformed `{Pos, Value}` fails only after the key lookup.
            let parsed = update_list(*updates, |entry| match tuple_items(entry)?.as_slice() {
                [position_term, value] => Some((position(*position_term)?, *value)),
                _ => None,
            });
            let updated = table
                .update_element(*key, &parsed, default)
                .map_err(|error| err(&mut *heap.0, error))?;
            Ok(boolean_term(updated))
        }
        (EtsBif::UpdateCounter, [target, key, operation])
        | (EtsBif::UpdateCounter, [target, key, operation, _]) => {
            let tid = handle(&mut *heap.0, &registry, *target)?;
            if registry
                .shared(tid)
                .map_err(|error| err(&mut *heap.0, error))?
                .options()
                .write_concurrency
                != WriteConcurrency::Disabled
            {
                let table = registry
                    .get_shared(tid)
                    .map_err(|error| err(&mut *heap.0, error))?;
                if matches!(
                    table.options.table_type,
                    TableType::Set | TableType::OrderedSet
                ) {
                    if !allowed(&table, caller, super_user, true) {
                        return Err(badarg_cause(&mut *heap.0, "access"));
                    }
                    let default = default_object(&mut *heap.0, &table, args.get(3).copied())?;
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
                        .map_err(|error| err(&mut *heap.0, error))?
                        .ok_or_else(badarg)?;
                    return if single {
                        values.first().copied().ok_or_else(badarg)
                    } else {
                        output_list(&mut heap, values)
                    };
                }
            }
            let mut table = registry
                .get_mut(tid)
                .map_err(|error| err(&mut *heap.0, error))?;
            if !allowed(&table, caller, super_user, true) {
                return Err(badarg_cause(&mut *heap.0, "access"));
            }
            let default = default_object(&mut *heap.0, &table, args.get(3).copied())?;
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
                .update_counter_big(*key, &operations, default, &mut heap)
                .map_err(|error| err(&mut *heap.0, error))?;
            if single {
                values.first().copied().ok_or_else(badarg)
            } else {
                TermBuilder::new(&mut heap)
                    .list_from_iter(values)
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum EtsBif {
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
