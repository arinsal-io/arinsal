//! ETS BIFs whose storage and access policy belong to the scheduled runtime.

use crate::process::Message;
use crate::{Process, Vm, VmError};
use arinsal_ets::match_spec::MatchDialect;
use arinsal_ets::match_spec::MatchProgram;
use arinsal_ets::{
    BigCounterOp, ElementLookup, EtsError, Heir, Protection, SelectContinuation, TableOptions,
    TableType, Tid, WriteConcurrency,
};
use arinsal_sched::{Pid, RunCtx};
use arinsal_term::{HeapAlloc, Term, TermBuilder, TermKind, copy_term, global_atoms};
use num_bigint::BigInt;
use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;
use std::sync::Mutex;

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
        "keypos",
        "read_concurrency",
        "write_concurrency",
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
        "stats",
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
fn badarg() -> VmError {
    VmError::Trap(crate::exceptions::Trap::error(atom("badarg")))
}
fn system_limit() -> VmError {
    VmError::Trap(crate::exceptions::Trap::error(atom("system_limit")))
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
    ]
    .into_iter()
    .find(|name| ETS_ATOMS.get(name).copied() == Some(atom))
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
        EtsError::NoTable | EtsError::BadArg | EtsError::NameTaken => badarg(),
        EtsError::Unsupported(_) => badarg(),
        EtsError::Term(_) => badarg(),
    }
}
enum ResolveFail {
    /// Not an atom and not an ETS table reference.
    BadType,
    /// Atom or table reference that does not name a live table.
    Missing,
}

fn resolve(registry: &arinsal_ets::Registry, term: Term) -> Result<Tid, ResolveFail> {
    if let Some(tid) = Tid::from_term(term) {
        return if registry.get(tid).is_ok() {
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

fn handle(registry: &arinsal_ets::Registry, term: Term) -> Result<Tid, VmError> {
    resolve(registry, term).map_err(|_| badarg())
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
    ETS_SUPER_USERS.lock().unwrap().contains(&caller)
        || caller == table.options.owner
        || match table.options.protection {
            Protection::Private => false,
            Protection::Protected => !write,
            Protection::Public => true,
        }
}
fn output_list<H: HeapAlloc>(heap: &mut H, items: Vec<Term>) -> Result<Term, VmError> {
    TermBuilder::new(heap)
        .list_from_iter(items)
        .map_err(|_| badarg())
}

fn insert_args(
    process: &mut Process,
    ctx: &RunCtx<'_, Message>,
    insert_new: bool,
    target: Term,
    objects: Term,
) -> Result<Term, VmError> {
    let caller = ctx.pid().to_term().ok_or_else(badarg)?;
    let rt = process.runtime.as_ref().ok_or_else(badarg)?;
    let mut registry = rt.ets.lock().unwrap();
    let tid = handle(&registry, target)?;
    let table = registry.get_mut(tid).map_err(err)?;
    if !allowed(table, caller, true) {
        return Err(badarg());
    }
    // SAFETY: object terms remain in the caller's live process heap for this BIF.
    let single = unsafe { objects.tuple_ref() }.is_some();
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
    ctx: &RunCtx<'_, Message>,
    member: bool,
    target: Term,
    key: Term,
) -> Result<Term, VmError> {
    let rt = process.runtime.as_ref().ok_or_else(badarg)?;
    let caller = ctx.pid().to_term().ok_or_else(badarg)?;
    let registry = rt.ets.lock().unwrap();
    let tid = handle(&registry, target)?;
    let table = registry.get(tid).map_err(err)?;
    if !allowed(table, caller, false) {
        return Err(badarg());
    }
    if member {
        Ok(boolean_term(table.member(key)))
    } else {
        let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
        let values = table.lookup(key, &mut heap).map_err(err)?;
        output_list(&mut heap, values)
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

struct ProcessMatchContext(Term);
impl arinsal_ets::match_spec::MatchContext for ProcessMatchContext {
    fn self_pid(&self) -> Option<Term> {
        Some(self.0)
    }
}

fn call_inner(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    function: EtsBif,
    args: &[Term],
) -> Result<Term, VmError> {
    let caller = ctx.pid().to_term().ok_or_else(badarg)?;
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
        let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
        return arinsal_ets::match_spec::match_spec_test(
            *against,
            *specification,
            dialect,
            &mut heap,
            &ProcessMatchContext(caller),
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
    let rt = process.runtime.as_ref().ok_or_else(badarg)?;
    let mut registry = rt.ets.lock().unwrap();
    let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
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
                        } else if Some(value.as_atom().ok_or_else(badarg)?)
                            == ETS_ATOMS.get("auto").copied()
                        {
                            WriteConcurrency::Auto
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
                            if !rt.scheduler().map_err(|_| badarg())?.lookup(heir_pid) {
                                return Err(badarg());
                            }
                            opts.heir = Some(Heir {
                                pid,
                                data: if pair.len() == 3 {
                                    pair.get(2).unwrap()
                                } else {
                                    atom("undefined")
                                },
                            });
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
            let tid = registry.create(opts).map_err(err)?;
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
            let tid = handle(&registry, *target)?;
            let new_name = name.as_atom().ok_or_else(badarg)?;
            let named = registry.get(tid).map_err(err)?.options.named_table;
            registry.rename(tid, new_name).map_err(err)?;
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
                Err(ResolveFail::BadType) => return Err(badarg()),
            };
            let table = registry.get(tid).map_err(err)?;
            if args.len() == 1 {
                table
                    .info_list(atom("nonode@nohost"), &mut heap)
                    .map_err(err)
            } else {
                let key = info_item_name(args[1]).ok_or_else(badarg)?;
                table
                    .info_item(key, atom("nonode@nohost"), &mut heap)
                    .map_err(err)
            }
        }
        (EtsBif::Delete, [target]) => {
            let tid = handle(&registry, *target)?;
            let table = registry.get(tid).map_err(err)?;
            if !allowed(table, caller, true) {
                return Err(badarg());
            }
            registry.delete(tid).map_err(err)?;
            Ok(atom("true"))
        }
        (EtsBif::Delete, [target, key]) => {
            let tid = handle(&registry, *target)?;
            let table = registry.get_mut(tid).map_err(err)?;
            if !allowed(table, caller, true) {
                return Err(badarg());
            }
            table.delete_key(*key);
            Ok(atom("true"))
        }
        // Port of erts/emulator/beam/erl_db.c:3234 (`ets_internal_delete_all_2`),
        // OTP-29.1.1. Table deletion is synchronous under this VM's registry lock.
        (EtsBif::InternalDeleteAll, [target, holder]) => {
            let tid = handle(&registry, *target)?;
            let table = registry.get_mut(tid).map_err(err)?;
            if !allowed(table, caller, true) || *holder != atom("undefined") {
                return Err(badarg());
            }
            let count = table.len();
            table.delete_all_objects();
            TermBuilder::new(&mut heap)
                .int_from_i128(count as i128)
                .map_err(|_| badarg())
        }
        // Port of erts/emulator/beam/erl_db.c:4648 and erl_db_hash.c:4117,
        // OTP-29.1.1.
        (EtsBif::LookupBinaryInfo, [target, key]) => {
            let tid = handle(&registry, *target)?;
            let table = registry.get(tid).map_err(err)?;
            if !allowed(table, caller, false) {
                return Err(badarg());
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
            let table = registry.get_mut(tid).map_err(err)?;
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
                        let live = rt
                            .scheduler()
                            .map_err(|_| badarg())?
                            .lookup(pid);
                        heir = Some(live.then_some(Heir {
                            pid: pid_term,
                            data,
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
            let table = registry.get(tid).map_err(err)?;
            if !allowed(table, caller, false) {
                return Err(badarg());
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
            let table = registry.get(tid).map_err(err)?;
            if !allowed(table, caller, false) {
                return Err(badarg());
            }
            Ok(table
                .raw_next(*key, &mut heap)
                .map_err(err)?
                .unwrap_or(atom("$end_of_table")))
        }
        (EtsBif::Take, [target, key]) => {
            let tid = handle(&registry, *target)?;
            let table = registry.get_mut(tid).map_err(err)?;
            if !allowed(table, caller, true) {
                return Err(badarg());
            }
            let values = table.take(*key, &mut heap).map_err(err)?;
            output_list(&mut heap, values)
        }
        (EtsBif::Slot, [target, index]) => {
            let tid = handle(&registry, *target)?;
            let table = registry.get(tid).map_err(err)?;
            if !allowed(table, caller, false) {
                return Err(badarg());
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
            let table = registry.get(tid).map_err(err)?;
            if !allowed(table, caller, false) {
                return Err(badarg());
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
            let table = registry.get(tid).map_err(err)?;
            if !allowed(table, caller, false) {
                return Err(badarg());
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
            let table = registry.get(tid).map_err(err)?;
            if !allowed(table, caller, false) {
                return Err(badarg());
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
            let table = registry.get(tid).map_err(err)?;
            if !allowed(table, caller, false) {
                return Err(badarg());
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
            let table = registry.get_mut(tid).map_err(err)?;
            if !allowed(table, caller, false) {
                return Err(badarg());
            }
            table
                .safe_fixtable_for(caller, boolean(*fixed)?)
                .map_err(err)?;
            Ok(atom("true"))
        }
        (EtsBif::DeleteObject, [target, object]) => {
            let tid = handle(&registry, *target)?;
            let table = registry.get_mut(tid).map_err(err)?;
            if !allowed(table, caller, true) {
                return Err(badarg());
            }
            table.delete_object(*object).map_err(err)?;
            Ok(atom("true"))
        }
        (EtsBif::GiveAway, [target, new_owner, data]) => {
            let tid = handle(&registry, *target)?;
            let pid = Pid::from_term(*new_owner).ok_or_else(badarg)?;
            if *new_owner == caller || !rt.scheduler().map_err(|_| badarg())?.lookup(pid) {
                return Err(badarg());
            }
            if registry.get(tid).map_err(err)?.options.owner != caller {
                return Err(badarg());
            }
            let tab = tid.to_term(&mut heap).map_err(|_| badarg())?;
            let transfer = TermBuilder::new(&mut heap)
                .tuple(&[atom("ETS-TRANSFER"), tab, caller, *data])
                .map_err(|_| badarg())?;
            registry.give_away(tid, *new_owner).map_err(err)?;
            ctx.send(pid, Message::copy_from(transfer)?)
                .map_err(|_| badarg())?;
            Ok(atom("true"))
        }
        (EtsBif::Select | EtsBif::SelectReverse, [target, spec])
        | (EtsBif::Match, [target, spec])
        | (EtsBif::MatchObject, [target, spec]) => {
            let tid = handle(&registry, *target)?;
            let table = registry.get(tid).map_err(err)?;
            if !allowed(table, caller, false) {
                return Err(badarg());
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
            let limit =
                usize::try_from(limit.as_small().ok_or_else(badarg)?).map_err(|_| badarg())?;
            let tid = handle(&registry, *target)?;
            let (program, result, retain) = {
                let table = registry.get(tid).map_err(err)?;
                if !allowed(table, caller, false) {
                    return Err(badarg());
                }
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
                let retain = page.continuation.is_some();
                let result = if let Some(continuation) = page.continuation {
                    let next = continuation.to_term(table, &mut heap).map_err(err)?;
                    TermBuilder::new(&mut heap)
                        .tuple(&[rows, next])
                        .map_err(|_| badarg())?
                } else {
                    rows
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
            // SAFETY: the continuation is rooted in the caller's process heap.
            let tuple = unsafe { continuation.tuple_ref() }.ok_or_else(badarg)?;
            let tid = Tid::from_term(tuple.get(0).ok_or_else(badarg)?).ok_or_else(badarg)?;
            let table = registry.get(tid).map_err(err)?;
            if !allowed(table, caller, false) {
                return Err(badarg());
            }
            let program_pos = if table.options.table_type == TableType::OrderedSet {
                4
            } else {
                3
            };
            let reference = tuple.get(program_pos).ok_or_else(badarg)?;
            let program = registry.match_program(reference).ok_or_else(badarg)?;
            let state =
                SelectContinuation::from_term(table, program, *continuation).map_err(err)?;
            let page = table
                .select_chunk_continue(program, state, &mut heap)
                .map_err(err)?;
            let rows = TermBuilder::new(&mut heap)
                .list_from_iter(page.rows)
                .map_err(|_| badarg())?;
            if let Some(next) = page.continuation {
                let next = next.to_term(table, &mut heap).map_err(err)?;
                TermBuilder::new(&mut heap)
                    .tuple(&[rows, next])
                    .map_err(|_| badarg())
            } else {
                Ok(rows)
            }
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
            let reference = Term::local_ref(&mut heap, [id as u32, (id >> 32) as u32, 0])
                .map_err(|_| badarg())?;
            let tables = live_table_terms(&registry, &mut heap)?;
            let table_list = TermBuilder::new(&mut heap)
                .list_from_iter(tables)
                .map_err(|_| badarg())?;
            let caller = ctx.pid();
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
            let table = registry.get_mut(tid).map_err(err)?;
            if !allowed(table, caller, function != EtsBif::SelectCount) {
                return Err(badarg());
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
            let table = registry.get(tid).map_err(err)?;
            if !allowed(table, caller, false) {
                return Err(badarg());
            }
            let pos =
                usize::try_from(position.as_small().ok_or_else(badarg)?).map_err(|_| badarg())?;
            let values = if args.len() == 4 {
                match table
                    .lookup_element_default(*key, pos, args[3], &mut heap)
                    .map_err(err)?
                {
                    ElementLookup::Values(values) => values,
                    ElementLookup::Default(value) => return Ok(value),
                }
            } else {
                table.lookup_element(*key, pos, &mut heap).map_err(err)?
            };
            if matches!(
                table.options.table_type,
                TableType::Bag | TableType::DuplicateBag
            ) {
                TermBuilder::new(&mut heap)
                    .list_from_iter(values)
                    .map_err(|_| badarg())
            } else {
                values.first().copied().ok_or_else(badarg)
            }
        }
        (EtsBif::UpdateElement, [target, key, updates])
        | (EtsBif::UpdateElement, [target, key, updates, _]) => {
            let tid = handle(&registry, *target)?;
            let table = registry.get_mut(tid).map_err(err)?;
            if !allowed(table, caller, true) {
                return Err(badarg());
            }
            // SAFETY: update specifications remain in the caller's live process heap.
            let entries = if unsafe { updates.tuple_ref() }.is_some() {
                vec![*updates]
            } else {
                list(*updates).ok_or_else(badarg)?
            };
            let parsed = entries
                .into_iter()
                .map(|entry| {
                    // SAFETY: each update term is rooted in the caller's process heap.
                    let tuple = unsafe { entry.tuple_ref() }.ok_or_else(badarg)?;
                    if tuple.len() != 2 {
                        return Err(badarg());
                    }
                    let position =
                        usize::try_from(tuple.get(0).unwrap().as_small().ok_or_else(badarg)?)
                            .map_err(|_| badarg())?;
                    Ok((position, tuple.get(1).unwrap()))
                })
                .collect::<Result<Vec<_>, VmError>>()?;
            let updated = if args.len() == 4 {
                table.update_element_default(*key, &parsed, args[3])
            } else {
                table.update_element(*key, &parsed)
            }
            .map_err(err)?;
            Ok(boolean_term(updated))
        }
        (EtsBif::UpdateCounter, [target, key, operation])
        | (EtsBif::UpdateCounter, [target, key, operation, _]) => {
            let tid = handle(&registry, *target)?;
            let table = registry.get_mut(tid).map_err(err)?;
            if !allowed(table, caller, true) {
                return Err(badarg());
            }
            // SAFETY: operation is rooted in the caller's process heap.
            let entries =
                if operation.as_small().is_some() || unsafe { operation.tuple_ref() }.is_some() {
                    vec![*operation]
                } else {
                    list(*operation).ok_or_else(badarg)?
                };
            let operations = entries
                .into_iter()
                .map(|entry| {
                    if let Some(increment) = entry.as_small() {
                        return Ok(BigCounterOp {
                            position: 2,
                            increment: BigInt::from(increment),
                            threshold: None,
                        });
                    }
                    // SAFETY: each counter operation is rooted in the caller's process heap.
                    let tuple = unsafe { entry.tuple_ref() }.ok_or_else(badarg)?;
                    if !(2..=4).contains(&tuple.len()) {
                        return Err(badarg());
                    }
                    let number =
                        |index: usize| integer(tuple.get(index).unwrap()).ok_or_else(badarg);
                    let position =
                        usize::try_from(tuple.get(0).unwrap().as_small().ok_or_else(badarg)?)
                            .map_err(|_| badarg())?;
                    let increment = number(1)?;
                    let threshold = if tuple.len() == 4 {
                        Some((number(2)?, number(3)?))
                    } else {
                        None
                    };
                    Ok(BigCounterOp {
                        position,
                        increment,
                        threshold,
                    })
                })
                .collect::<Result<Vec<_>, VmError>>()?;
            let default = if args.len() == 4 { Some(args[3]) } else { None };
            let values = table
                .update_counter_big(*key, &operations, default)
                .map_err(err)?;
            let copied = values
                .into_iter()
                .map(|value| copy_term(value, &mut heap).map_err(|_| badarg()))
                .collect::<Result<Vec<_>, _>>()?;
            if copied.len() == 1 {
                Ok(copied[0])
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

macro_rules! ets_entry {
    ($entry:ident, $id:ident, $arity:literal) => {
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
            Some(args.with_values(process, |process, values| {
                call_inner(process, ctx, EtsBif::$id, values)
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
    Some(insert_args(process, ctx, false, target, objects))
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
    Some(insert_args(process, ctx, true, target, objects))
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
    Some(lookup_args(process, ctx, false, target, key))
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
    Some(lookup_args(process, ctx, true, target, key))
}

ets_entry!(entry_new, New, 2);
ets_entry!(entry_match_spec_test, MatchSpecTest, 3);
ets_entry!(entry_lookup_binary_info, LookupBinaryInfo, 2);
ets_entry!(entry_raw_first, RawFirst, 1);
ets_entry!(entry_raw_next, RawNext, 2);
ets_entry!(entry_super_user, SuperUser, 1);
ets_entry!(entry_internal_delete_all, InternalDeleteAll, 2);
ets_entry!(entry_setopts, SetOpts, 2);
ets_entry!(entry_whereis, Whereis, 1);
ets_entry!(entry_rename, Rename, 2);
ets_entry!(entry_info_1, Info, 1);
ets_entry!(entry_info_2, Info, 2);
ets_entry!(entry_delete_1, Delete, 1);
ets_entry!(entry_delete_2, Delete, 2);
ets_entry!(entry_take, Take, 2);
ets_entry!(entry_slot, Slot, 2);
ets_entry!(entry_first, First, 1);
ets_entry!(entry_first_lookup, FirstLookup, 1);
ets_entry!(entry_last, Last, 1);
ets_entry!(entry_last_lookup, LastLookup, 1);
ets_entry!(entry_next, Next, 2);
ets_entry!(entry_next_lookup, NextLookup, 2);
ets_entry!(entry_prev, Prev, 2);
ets_entry!(entry_prev_lookup, PrevLookup, 2);
ets_entry!(entry_safe_fixtable, SafeFixtable, 2);
ets_entry!(entry_delete_object, DeleteObject, 2);
ets_entry!(entry_give_away, GiveAway, 3);
ets_entry!(entry_select_1, Select, 1);
ets_entry!(entry_select_2, Select, 2);
ets_entry!(entry_select_3, Select, 3);
ets_entry!(entry_select_reverse_1, SelectReverse, 1);
ets_entry!(entry_select_reverse_2, SelectReverse, 2);
ets_entry!(entry_select_reverse_3, SelectReverse, 3);
ets_entry!(entry_match_1, Match, 1);
ets_entry!(entry_match_2, Match, 2);
ets_entry!(entry_match_3, Match, 3);
ets_entry!(entry_match_object_1, MatchObject, 1);
ets_entry!(entry_match_object_2, MatchObject, 2);
ets_entry!(entry_match_object_3, MatchObject, 3);
ets_entry!(entry_match_spec_compile, MatchSpecCompile, 1);
ets_entry!(entry_is_compiled_ms, IsCompiledMs, 1);
ets_entry!(entry_internal_request_all, InternalRequestAll, 0);
ets_entry!(entry_match_spec_run_r, MatchSpecRunR, 3);
ets_entry!(entry_select_count, SelectCount, 2);
ets_entry!(entry_internal_select_delete, InternalSelectDelete, 2);
ets_entry!(entry_select_replace, SelectReplace, 2);
ets_entry!(entry_lookup_element_3, LookupElement, 3);
ets_entry!(entry_lookup_element_4, LookupElement, 4);
ets_entry!(entry_update_element_3, UpdateElement, 3);
ets_entry!(entry_update_element_4, UpdateElement, 4);
ets_entry!(entry_update_counter_3, UpdateCounter, 3);
ets_entry!(entry_update_counter_4, UpdateCounter, 4);

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
