//! The map BIFs of erl_map.c.
//!
//! Port of erts/emulator/beam/erl_map.c (maps_from_list_1, maps_from_keys_2, maps_keys_1,
//! maps_values_1 and their YCF helpers; erts_debug_map_info_1,
//! erts_internal_map_to_tuple_keys_1, erts_internal_term_type_1,
//! erts_internal_map_hashmap_children_1, erts_internal_map_next_3) and
//! erts/emulator/beam/utils.c (erts_ycf_trap_driver, erts_ycf_trap_driver_trap_helper),
//! OTP-29.1.1. Each BIF is `bif_table[].f` with `(c_p, reg, I)`. A call that runs out of
//! reductions keeps its walk in a magic binary, disables collection, and `BIF_TRAP`s to its
//! own export with the magic reference in X0 and the other arguments unchanged; the export
//! calls the same body, which recognises its state.

use crate::VmError;
use crate::bif_traps::TrapContext;
use crate::natives::bif::{bif_badarg, bif_ret, bif_system_limit};
use arinsal_beamasm::ProcessHeader;
use arinsal_bifs::BifError;
use arinsal_bifs::ProcessHeapHandle;
use arinsal_maps::{HashmapMergeContext, MAP_MERGE_LOOP_FACTOR, MapError};
use arinsal_term::raw::{Cons, MapListValidator, Tuple, ValidatedMapPairs};
use arinsal_term::{MagicBin, Term, TermBuilder, TermKind, atoms, hashmap_node_children};

/// `sizeof(erts_ycf_trap_driver_state_holder)` on a 64-bit build: the magic binary's
/// `orig_size`.
// Port of erts/emulator/beam/utils.c (erts_ycf_trap_driver_state_holder), OTP-29.1.1.
const ERTS_YCF_TRAP_HOLDER_SIZE: usize = 24;

/// `iterations_per_red` of maps_from_list_1 and maps_from_keys_2.
const FROM_LIST_ITERATIONS_PER_RED: i64 = 40;
/// `iterations_per_red` of maps_keys_1 and maps_values_1.
const PROJECTION_ITERATIONS_PER_RED: i64 = 15;

/// The YCF trap state of `maps:from_list/1` and `maps:from_keys/2`.
type BuildState = TrapContext<Option<MapBuildWalk>>;
/// The YCF trap state of `maps:keys/1` and `maps:values/1`.
type ProjectionState = TrapContext<Option<MapProjectionWalk>>;

/// `maps:from_list/1`.
// Port of erts/emulator/beam/erl_map.c (maps_from_list_1), OTP-29.1.1.
pub(crate) extern "C" fn maps_from_list_1(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    maps_build(c_p, reg, i, "maps:from_list/1", false)
}

/// `maps:from_keys/2`.
// Port of erts/emulator/beam/erl_map.c (maps_from_keys_2), OTP-29.1.1.
pub(crate) extern "C" fn maps_from_keys_2(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    maps_build(c_p, reg, i, "maps:from_keys/2", true)
}

/// `maps:keys/1`.
// Port of erts/emulator/beam/erl_map.c (maps_keys_1), OTP-29.1.1.
pub(crate) extern "C" fn maps_keys_1(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    maps_projection(c_p, reg, i, "maps:keys/1", true)
}

/// `maps:values/1`.
// Port of erts/emulator/beam/erl_map.c (maps_values_1), OTP-29.1.1.
pub(crate) extern "C" fn maps_values_1(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    maps_projection(c_p, reg, i, "maps:values/1", false)
}

/// `map_size/1`.
// Port of erts/emulator/beam/erl_map.c (map_size_1), OTP-29.1.1.
pub(crate) extern "C" fn map_size_1(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let [map] = crate::bif_table::bif_args::<1>(reg);
    match arinsal_maps::size(map) {
        // A map's size is far below the small integer limit.
        Ok(size) => Term::small(size as i64).map_or(0, crate::native_hooks::raw),
        Err(_) => bif_error_tagged(
            c_p,
            reg,
            i,
            process,
            "erlang:map_size/1",
            1,
            Term::atom(atoms::BADMAP),
            map,
        ),
    }
}

/// `map_get/2`.
// Port of erts/emulator/beam/erl_map.c (map_get_2), OTP-29.1.1.
pub(crate) extern "C" fn map_get_2(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let [key, map] = crate::bif_table::bif_args::<2>(reg);
    if map.is_flatmap() || map.is_hashmap() {
        if let Ok(Some(value)) = arinsal_maps::get(map, key) {
            return crate::native_hooks::raw(value);
        }
        return bif_error_tagged(
            c_p,
            reg,
            i,
            process,
            "erlang:map_get/2",
            2,
            Term::atom(atoms::BADKEY),
            key,
        );
    }
    bif_error_tagged(
        c_p,
        reg,
        i,
        process,
        "erlang:map_get/2",
        2,
        Term::atom(atoms::BADMAP),
        map,
    )
}

/// `is_map_key/2`.
// Port of erts/emulator/beam/erl_map.c (is_map_key_2), OTP-29.1.1.
pub(crate) extern "C" fn is_map_key_2(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let [key, map] = crate::bif_table::bif_args::<2>(reg);
    if map.is_flatmap() || map.is_hashmap() {
        let found = matches!(arinsal_maps::get(map, key), Ok(Some(_)));
        return crate::native_hooks::raw(Term::atom(if found {
            atoms::TRUE
        } else {
            atoms::FALSE
        }));
    }
    bif_error_tagged(
        c_p,
        reg,
        i,
        process,
        "erlang:is_map_key/2",
        2,
        Term::atom(atoms::BADMAP),
        map,
    )
}

/// `const long reds = iterations_per_red * ERTS_BIF_REDS_LEFT(p)`.
#[inline(always)]
fn ycf_reds(process: &crate::Process, iterations_per_red: i64) -> i64 {
    i64::from(process.heap.abi.fcalls.max(0)) * iterations_per_red
}

/// `BUMP_REDS(p, (init_reds - nr_of_reductions) / iterations_per_red)`.
// Port of erts/emulator/beam/utils.c (erts_ycf_trap_driver) and bif.h (BUMP_REDS), OTP-29.1.1.
#[inline(always)]
fn ycf_bump_reds(process: &mut crate::Process, init: i64, left: i64, iterations_per_red: i64) {
    let used = ((init - left) / iterations_per_red).clamp(0, i64::from(i32::MAX));
    let fcalls = i64::from(process.heap.abi.fcalls) - used;
    process.heap.abi.fcalls = fcalls.max(0) as i32;
}

/// `is_boxed(term)`: the primary tag test `is_internal_magic_ref` starts with.
#[inline(always)]
fn is_boxed(term: Term) -> bool {
    term.tagged_word() & 3 == 2
}

/// Resumable `maps:keys/1` and `maps:values/1` walk over a HAMT.
// Port of erts/emulator/beam/erl_map.c:2801-2878 (hashmap_keys, hashmap_values), OTP-29.1.1.
struct MapProjectionWalk {
    iter: arinsal_term::MapReverseIter,
    keys: bool,
    remaining: usize,
    pending: Option<Term>,
    output: arinsal_term::ConsListBuilder,
}

impl MapProjectionWalk {
    /// The flatmap helpers build a list without entering a YCF loop.
    // Port of erts/emulator/beam/erl_map.c:1207-1237 and :2262-2292, OTP-29.1.1.
    #[inline]
    fn start_flat(
        map: Term,
        keys: bool,
        heap: &mut ProcessHeapHandle<'_>,
    ) -> Result<Option<Term>, MapError> {
        let checked = arinsal_maps::checked_map(map)?;
        match checked.kind() {
            arinsal_maps::CheckedMapKind::Flatmap(flat) => {
                if flat.size() == 0 {
                    return Ok(Some(Term::NIL));
                }
                arinsal_maps::flatmap_projection_list(flat, keys, heap).map(Some)
            }
            arinsal_maps::CheckedMapKind::Hashmap(_) => Ok(None),
        }
    }

    /// Reserve the full result and initialize a reversed HAMT iterator before yielding.
    // Port of erts/emulator/beam/erl_map.c:2825-2827 and :2869-2871, OTP-29.1.1.
    #[inline(never)]
    fn start_hashmap(
        map: Term,
        keys: bool,
        heap: &mut ProcessHeapHandle<'_>,
    ) -> Result<Self, MapError> {
        let checked = arinsal_maps::checked_map(map)?;
        let iter = arinsal_term::MapReverseIter::new(map).expect("checked hashmap");
        let output = TermBuilder::new(heap)
            .reserve_cons_list(checked.size())
            .map_err(|_| MapError::Allocation)?;
        Ok(Self {
            iter,
            keys,
            remaining: checked.size(),
            pending: None,
            output,
        })
    }

    /// Run the YCF loop, retaining the condition's current leaf when its loop budget expires.
    fn step(&mut self, reds: &mut i64) -> Result<bool, MapError> {
        if let Some(item) = self.pending.take() {
            self.output
                .prepend_chunk(1, std::iter::once(item))
                .map_err(|_| MapError::Badarg(Term::NIL))?;
            self.remaining -= 1;
        }
        while self.remaining != 0 {
            let Some((key, value)) = self.iter.next() else {
                return Err(MapError::Badarg(Term::NIL));
            };
            let item = if self.keys { key } else { value };
            *reds -= 1;
            if *reds <= 0 {
                self.pending = Some(item);
                return Ok(false);
            }
            self.output
                .prepend_chunk(1, std::iter::once(item))
                .map_err(|_| MapError::Badarg(Term::NIL))?;
            self.remaining -= 1;
        }
        Ok(true)
    }

    /// Finish after the reverse iterator has exhausted every map entry.
    fn finish(self) -> Term {
        self.output
            .finish(Term::NIL)
            .expect("all hashmap entries were projected")
    }
}

#[derive(Clone, Copy)]
enum MapBuildPhase {
    Validate,
    ValidateBody,
    Leaves,
    LeavesBody,
    Build,
}

/// Resumable validation, leaf construction and HAMT building for map constructors.
// Port of erts/emulator/beam/erl_map.c:278-366 and :482-591, OTP-29.1.1.
struct MapBuildWalk {
    list: Term,
    fill: Option<Term>,
    phase: MapBuildPhase,
    cursor: Term,
    size: usize,
    validator: Option<MapListValidator<'static>>,
    pairs: Option<ValidatedMapPairs<'static>>,
    leaves_written: usize,
    build: Option<arinsal_maps::HashmapFromPairs>,
}

impl MapBuildWalk {
    // Port of erts/emulator/beam/erl_map.c:321-366 (maps_from_list_1_helper), OTP-29.1.1.
    fn from_list(list: Term) -> Self {
        Self::new(list, None)
    }

    // Port of erts/emulator/beam/erl_map.c:279-309 (maps_from_keys_2_helper), OTP-29.1.1.
    fn from_keys(list: Term, value: Term) -> Self {
        Self::new(list, Some(value))
    }

    // Port of erts/emulator/beam/erl_map.c:279-366 (constructor state), OTP-29.1.1.
    fn new(list: Term, fill: Option<Term>) -> Self {
        Self {
            list,
            fill,
            phase: MapBuildPhase::Validate,
            cursor: list,
            size: 0,
            validator: fill.is_none().then(|| MapListValidator::new(list)),
            pairs: None,
            leaves_written: 0,
            build: None,
        }
    }

    fn badarg() -> MapError {
        MapError::Badarg(Term::NIL)
    }

    fn cell(cursor: Term) -> Result<(Term, Term), MapError> {
        Cons::try_from(cursor)
            .map(Cons::pair)
            .map_err(|_| Self::badarg())
    }

    fn element(fill: Option<Term>, item: Term) -> Result<(Term, Term), MapError> {
        if let Some(value) = fill {
            return Ok((item, value));
        }
        let tuple = Tuple::try_from(item).map_err(|_| Self::badarg())?;
        if tuple.arity() != 2 {
            return Err(Self::badarg());
        }
        let mut fields = tuple.elements();
        Ok((
            fields.next().ok_or_else(Self::badarg)?,
            fields.next().ok_or_else(Self::badarg)?,
        ))
    }

    /// Continue the two YCF list loops and the HAMT builder with the current reduction budget.
    // Port of erts/emulator/beam/erl_map.c:279-366 and :482-591 (YCF helper loops), OTP-29.1.1.
    fn step(
        &mut self,
        heap: &mut ProcessHeapHandle<'_>,
        reds: &mut i64,
    ) -> Result<Option<Term>, MapError> {
        loop {
            if matches!(self.phase, MapBuildPhase::Validate) {
                let mut cursor = self.cursor;
                let mut size = self.size;
                let mut remaining_reds = *reds;
                if self.fill.is_some() {
                    while let Ok(cons) = Cons::try_from(cursor) {
                        remaining_reds -= 1;
                        if remaining_reds <= 0 {
                            self.phase = MapBuildPhase::ValidateBody;
                            self.cursor = cursor;
                            self.size = size;
                            *reds = remaining_reds;
                            return Ok(None);
                        }
                        size += 1;
                        cursor = cons.tail();
                    }
                } else {
                    loop {
                        let cons = self
                            .validator
                            .as_mut()
                            .expect("from_list validation state")
                            .current()
                            .map_err(|_| Self::badarg())?;
                        let Some(cons) = cons else { break };
                        remaining_reds -= 1;
                        if remaining_reds <= 0 {
                            self.phase = MapBuildPhase::ValidateBody;
                            self.cursor = cursor;
                            self.size = size;
                            *reds = remaining_reds;
                            return Ok(None);
                        }
                        cons.advance().map_err(|_| Self::badarg())?;
                        size += 1;
                    }
                }
                self.cursor = cursor;
                self.size = size;
                *reds = remaining_reds;
                let validated = if self.fill.is_none() {
                    Some(
                        self.validator
                            .take()
                            .expect("from_list validation state")
                            .finish()
                            .map_err(|_| Self::badarg())?,
                    )
                } else {
                    if self.cursor != Term::NIL {
                        return Err(Self::badarg());
                    }
                    None
                };
                if self.size <= 32 {
                    let pairs = if let Some(validated) = validated {
                        validated.pairs()
                    } else {
                        let fill = self.fill;
                        let mut cursor = self.list;
                        let pairs = std::iter::from_fn(|| {
                            let (head, tail) = Self::cell(cursor).ok()?;
                            cursor = tail;
                            Self::element(fill, head).ok()
                        });
                        return arinsal_maps::from_small_pairs(self.size, pairs, heap)
                            .map(Some)
                            .map_err(|_| Self::badarg());
                    };
                    return arinsal_maps::from_small_pairs(self.size, pairs, heap)
                        .map(Some)
                        .map_err(|_| Self::badarg());
                }
                self.cursor = self.list;
                if let Some(validated) = validated {
                    self.pairs = Some(validated.pairs());
                }
                self.build = Some(
                    arinsal_maps::HashmapFromPairs::new(self.size, heap)
                        .map_err(|_| Self::badarg())?,
                );
                self.phase = MapBuildPhase::Leaves;
            }

            if matches!(
                self.phase,
                MapBuildPhase::Leaves | MapBuildPhase::LeavesBody
            ) {
                let mut resumed_body = matches!(self.phase, MapBuildPhase::LeavesBody);
                loop {
                    if self.fill.is_none() {
                        if resumed_body {
                            let (key, value) = self
                                .pairs
                                .as_mut()
                                .expect("validated pair iterator")
                                .next()
                                .expect("remaining validated map pair");
                            self.build
                                .as_mut()
                                .expect("hashmap leaf builder")
                                .push(key, value)
                                .map_err(|_| Self::badarg())?;
                            self.leaves_written += 1;
                            self.phase = MapBuildPhase::Leaves;
                            resumed_body = false;
                            continue;
                        }
                        if self.leaves_written < self.size {
                            *reds -= 1;
                            if *reds <= 0 {
                                self.phase = MapBuildPhase::LeavesBody;
                                return Ok(None);
                            }
                            let count = (self.size - self.leaves_written).min(*reds as usize);
                            self.build
                                .as_mut()
                                .expect("hashmap leaf builder")
                                .push_chunk(
                                    count,
                                    self.pairs
                                        .as_mut()
                                        .expect("validated pair iterator")
                                        .by_ref(),
                                )
                                .map_err(|_| Self::badarg())?;
                            self.leaves_written += count;
                            *reds -= count.saturating_sub(1) as i64;
                            continue;
                        }
                        self.build
                            .as_mut()
                            .expect("hashmap leaf builder")
                            .finish_leaves();
                        self.pairs = None;
                        self.phase = MapBuildPhase::Build;
                        break;
                    }
                    if resumed_body {
                        let (head, tail) = Self::cell(self.cursor)?;
                        let (key, value) = Self::element(self.fill, head)?;
                        self.build
                            .as_mut()
                            .expect("hashmap leaf builder")
                            .push(key, value)
                            .map_err(|_| Self::badarg())?;
                        self.cursor = tail;
                        self.leaves_written += 1;
                        self.phase = MapBuildPhase::Leaves;
                        resumed_body = false;
                        continue;
                    }
                    if let Ok(cons) = Cons::try_from(self.cursor) {
                        *reds -= 1;
                        if *reds <= 0 {
                            self.phase = MapBuildPhase::LeavesBody;
                            return Ok(None);
                        }
                        let count = (self.size - self.leaves_written).min(*reds as usize);
                        let fill = self.fill;
                        let (head, mut cursor) = cons.pair();
                        let first = Self::element(fill, head)?;
                        let rest = std::iter::from_fn(|| {
                            let (head, tail) = Self::cell(cursor).ok()?;
                            cursor = tail;
                            Self::element(fill, head).ok()
                        });
                        self.build
                            .as_mut()
                            .expect("hashmap leaf builder")
                            .push_chunk(count, std::iter::once(first).chain(rest))
                            .map_err(|_| Self::badarg())?;
                        self.cursor = cursor;
                        self.leaves_written += count;
                        *reds -= count.saturating_sub(1) as i64;
                        continue;
                    }
                    self.build
                        .as_mut()
                        .expect("hashmap leaf builder")
                        .finish_leaves();
                    self.phase = MapBuildPhase::Build;
                    break;
                }
            }

            match self.phase {
                MapBuildPhase::Validate => unreachable!("validation loop handles this phase"),
                MapBuildPhase::ValidateBody => {
                    if self.fill.is_some() {
                        self.cursor = Self::cell(self.cursor)?.1;
                    } else {
                        self.validator
                            .as_mut()
                            .expect("from_list validation state")
                            .current()
                            .map_err(|_| Self::badarg())?
                            .expect("validation body has current cell")
                            .advance()
                            .map_err(|_| Self::badarg())?;
                    }
                    self.size += 1;
                    self.phase = MapBuildPhase::Validate;
                }
                MapBuildPhase::Leaves | MapBuildPhase::LeavesBody => {
                    unreachable!("leaf loop handles these phases")
                }
                MapBuildPhase::Build => {
                    return self
                        .build
                        .as_mut()
                        .expect("hashmap builder")
                        .step(reds, heap)
                        .map_err(|_| Self::badarg());
                }
            }
        }
    }
}

/// `BIF_ERROR(p, reason)` of a body below.
#[cold]
#[inline(never)]
fn map_error(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
    process: &mut crate::Process,
    export: &'static str,
    arity: usize,
    error: MapError,
) -> u64 {
    let error = match error {
        MapError::Badmap(value) => tagged_bif_error(process, atoms::BADMAP, value),
        MapError::Badkey(value) => tagged_bif_error(process, atoms::BADKEY, value),
        MapError::Badarg(_) => BifError::BADARG,
        MapError::Allocation => BifError::SystemLimit,
    };
    ycf_error(c_p, reg, i, process, export, arity, error)
}

/// Construct `fvalue` for `BIF_ERROR(p, BADMAP|BADKEY)`, then raise it with the BIF frame.
// Port of erts/emulator/beam/erl_map.c (BIF_ERROR sites in the four moved BIFs), OTP-29.1.1.
fn tagged_bif_error(
    process: &mut crate::Process,
    tag: arinsal_term::Atom,
    value: Term,
) -> BifError {
    let mut heap = ProcessHeapHandle(&mut process.heap);
    match TermBuilder::new(&mut heap).tuple2(Term::atom(tag), value) {
        Ok(reason) => BifError::Error(reason),
        Err(_) => BifError::SystemLimit,
    }
}

/// `BIF_ERROR` of the existing map BIF bodies that report a process-independent error value.
#[cold]
#[inline(never)]
fn ycf_error(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
    process: &mut crate::Process,
    export: &'static str,
    arity: usize,
    error: BifError,
) -> u64 {
    let (module, rest) = export.split_once(':').unwrap_or(("maps", export));
    let function = rest.split_once('/').map_or(rest, |(function, _)| function);
    let args = crate::bif_table::bif_arg_vec(reg, arity);
    let error = crate::exceptions::bif_error(process, module, function, &args, error);
    bif_ret(c_p, i, Err(error))
}

/// `erts_ycf_trap_driver_trap_helper`: `reg[0]` is the state, the rest are the BIF's own
/// arguments, and the trap goes to the BIF's export.
// Port of erts/emulator/beam/utils.c (erts_ycf_trap_driver_trap_helper), OTP-29.1.1.
#[cold]
#[inline(never)]
fn ycf_trap(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
    process: &mut crate::Process,
    export: &'static str,
    arity: usize,
    state_mref: Term,
) -> u64 {
    let mut args = crate::bif_table::bif_arg_vec(reg, arity);
    args[0] = state_mref;
    let trap = VmError::TrapExport(crate::ExportTrap::new(process, export, args));
    bif_ret(c_p, i, Err(trap))
}

/// `erts_create_magic_binary(sizeof(erts_ycf_trap_driver_state_holder), …)` and
/// `erts_mk_magic_ref` of a new trap state.
// Port of erts/emulator/beam/utils.c (erts_ycf_trap_driver: the "We need to trap" arm),
// OTP-29.1.1.
fn create_state_mref<T: arinsal_term::MagicPayload>(
    process: &mut crate::Process,
    state: T,
    c_payload_size: usize,
) -> Result<Term, VmError> {
    let state: MagicBin = MagicBin::with_erts_payload_size_and_refn(
        state,
        c_payload_size,
        arinsal_sched::unique::next_ref_words(),
    );
    let mut heap = ProcessHeapHandle(&mut process.heap);
    TermBuilder::new(&mut heap).magic_ref(state).map_err(|_| {
        VmError::Trap(crate::exceptions::Trap::error(Term::atom(
            atoms::SYSTEM_LIMIT,
        )))
    })
}

/// `erts_ycf_trap_driver` over `maps_from_list_1_helper` / `maps_from_keys_2_helper`.
// Port of erts/emulator/beam/utils.c (erts_ycf_trap_driver) and erl_map.c
// (maps_from_keys_2_helper, maps_from_list_1_helper, hashmap_from_validated_list), OTP-29.1.1.
#[inline(always)]
fn maps_build(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
    export: &'static str,
    from_keys: bool,
) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let arity = if from_keys { 2 } else { 1 };
    let (list, fill) = if from_keys {
        let [list, fill] = crate::bif_table::bif_args::<2>(reg);
        (list, fill)
    } else {
        (crate::bif_table::bif_args::<1>(reg)[0], Term::NIL)
    };
    let init = ycf_reds(process, FROM_LIST_ITERATIONS_PER_RED);
    let mut reds = init;
    // Continue a trapped call: the state is ours when its holder is a `BuildState`.
    let resumed = is_boxed(list).then(|| {
        list.with_magic_payload_mut::<BuildState, _>(|state| {
            // erts_set_gc_state(p, 1)
            process.set_gc_enabled(true);
            let guard = &mut state.0;
            let walk = guard.as_mut()?;
            let mut heap = ProcessHeapHandle(&mut process.heap);
            let step = walk.step(&mut heap, &mut reds);
            if !matches!(step, Ok(None)) {
                // The trap state is gone: ycf_continue returned without a new trap state.
                *guard = None;
            }
            Some(step)
        })
    });
    let step = match resumed.flatten() {
        Some(Some(step)) => {
            ycf_bump_reds(process, init, reds, FROM_LIST_ITERATIONS_PER_RED);
            match step {
                Ok(Some(value)) => return crate::native_hooks::raw(value),
                Ok(None) => {
                    process.set_gc_enabled(false);
                    return ycf_trap(c_p, reg, i, process, export, arity, list);
                }
                Err(error) => return map_error(c_p, reg, i, process, export, arity, error),
            }
        }
        // A spent state (its holder has no trap state) starts a new call, as erts does.
        _ => {
            let mut walk = if from_keys {
                MapBuildWalk::from_keys(list, fill)
            } else {
                MapBuildWalk::from_list(list)
            };
            let step = {
                let mut heap = ProcessHeapHandle(&mut process.heap);
                walk.step(&mut heap, &mut reds)
            };
            (walk, step)
        }
    };
    let (walk, step) = step;
    ycf_bump_reds(process, init, reds, FROM_LIST_ITERATIONS_PER_RED);
    match step {
        Ok(Some(value)) => crate::native_hooks::raw(value),
        Ok(None) => build_first_trap(c_p, reg, i, process, export, arity, walk),
        Err(error) => map_error(c_p, reg, i, process, export, arity, error),
    }
}

/// The first yield of a `maps:from_list/1` / `maps:from_keys/2` call: its state binary, then
/// `erts_set_gc_state(p, 0)` and the trap.
#[cold]
#[inline(never)]
fn build_first_trap(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
    process: &mut crate::Process,
    export: &'static str,
    arity: usize,
    walk: MapBuildWalk,
) -> u64 {
    let state_mref = match create_state_mref::<BuildState>(
        process,
        TrapContext::new(Some(walk)),
        ERTS_YCF_TRAP_HOLDER_SIZE,
    ) {
        Ok(state_mref) => state_mref,
        Err(error) => return bif_ret(c_p, i, Err(error)),
    };
    process.set_gc_enabled(false);
    ycf_trap(c_p, reg, i, process, export, arity, state_mref)
}

/// `erts_ycf_trap_driver` over `maps_keys_1_helper` / `maps_values_1_helper`.
// Port of erts/emulator/beam/utils.c (erts_ycf_trap_driver) and erl_map.c (maps_keys_1_helper,
// maps_values_1_helper, hashmap_keys, hashmap_values), OTP-29.1.1.
#[inline(always)]
fn maps_projection(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
    export: &'static str,
    keys: bool,
) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let [map] = crate::bif_table::bif_args::<1>(reg);
    // `is_internal_magic_ref(bif_args[0])` with the driver's destructor: continue a trapped
    // call before looking at the argument as a map.
    if is_boxed(map)
        && map.with_magic_payload_mut::<ProjectionState, _>(|state| state.0.is_some()) == Some(true)
    {
        return projection_resume(c_p, reg, i, process, export, map);
    }
    // The flatmap arm runs without consuming YCF reductions and never yields.
    let flat = {
        let mut heap = ProcessHeapHandle(&mut process.heap);
        MapProjectionWalk::start_flat(map, keys, &mut heap)
    };
    match flat {
        Ok(Some(value)) => crate::native_hooks::raw(value),
        Ok(None) => projection_hashmap(c_p, reg, i, process, export, keys, map),
        Err(error) => map_error(c_p, reg, i, process, export, 1, error),
    }
}

/// The hashmap arm of a new `maps:keys/1` / `maps:values/1` call.
#[inline(never)]
fn projection_hashmap(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
    process: &mut crate::Process,
    export: &'static str,
    keys: bool,
    map: Term,
) -> u64 {
    let init = ycf_reds(process, PROJECTION_ITERATIONS_PER_RED);
    let mut reds = init;
    let started = {
        let mut heap = ProcessHeapHandle(&mut process.heap);
        MapProjectionWalk::start_hashmap(map, keys, &mut heap)
    };
    let mut walk = match started {
        Ok(walk) => walk,
        Err(error) => return map_error(c_p, reg, i, process, export, 1, error),
    };
    let done = match walk.step(&mut reds) {
        Ok(done) => done,
        Err(error) => return map_error(c_p, reg, i, process, export, 1, error),
    };
    ycf_bump_reds(process, init, reds, PROJECTION_ITERATIONS_PER_RED);
    if done {
        return crate::native_hooks::raw(walk.finish());
    }
    let state_mref = match create_state_mref::<ProjectionState>(
        process,
        TrapContext::new(Some(walk)),
        ERTS_YCF_TRAP_HOLDER_SIZE,
    ) {
        Ok(state_mref) => state_mref,
        Err(error) => return bif_ret(c_p, i, Err(error)),
    };
    process.set_gc_enabled(false);
    ycf_trap(c_p, reg, i, process, export, 1, state_mref)
}

/// X0 is the trap state of a yielded call: the next slice of its walk.
// Port of erts/emulator/beam/utils.c (erts_ycf_trap_driver: "Continue a trapped call"),
// OTP-29.1.1.
#[cold]
#[inline(never)]
fn projection_resume(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
    process: &mut crate::Process,
    export: &'static str,
    state_mref: Term,
) -> u64 {
    let init = ycf_reds(process, PROJECTION_ITERATIONS_PER_RED);
    let mut reds = init;
    let resumed = state_mref.with_magic_payload_mut::<ProjectionState, _>(|state| {
        let guard = &mut state.0;
        let walk = guard.as_mut()?;
        match walk.step(&mut reds) {
            Ok(false) => Some(Ok(None)),
            Ok(true) => guard.take().map(|walk| Ok(Some(walk.finish()))),
            Err(error) => {
                guard.take();
                Some(Err(error))
            }
        }
    });
    let Some(Some(result)) = resumed else {
        unreachable!("the caller checked the trap state");
    };
    // erts_set_gc_state(p, 1) before ycf_continue; BUMP_REDS after it.
    process.set_gc_enabled(true);
    ycf_bump_reds(process, init, reds, PROJECTION_ITERATIONS_PER_RED);
    match result {
        Ok(Some(value)) => crate::native_hooks::raw(value),
        Ok(None) => {
            process.set_gc_enabled(false);
            ycf_trap(c_p, reg, i, process, export, 1, state_mref)
        }
        Err(error) => map_error(c_p, reg, i, process, export, 1, error),
    }
}

/// `sizeof(HashmapMergeContext)` on a 64-bit build: the magic binary's `orig_size`.
// Port of erts/emulator/beam/erl_map.c (HashmapMergeContext), OTP-29.1.1.
const ERTS_HASHMAP_MERGE_CONTEXT_SIZE: usize = 56;

/// The trap state of `hashmap_merge`: the `HashmapMergeContext` of its magic binary.
type MergeState = TrapContext<Option<HashmapMergeContext>>;

/// `BIF_P->fvalue = value; BIF_ERROR(BIF_P, BADMAP)` (`tag` is `badmap`) or `BADKEY`: the
/// `{Tag, Value}` reason `expand_error_value` builds, raised with the BIF's frame.
// Port of erts/emulator/beam/beam_common.c (expand_error_value), OTP-29.1.1.
#[cold]
#[inline(never)]
#[allow(clippy::too_many_arguments)]
fn bif_error_tagged(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
    process: &mut crate::Process,
    export: &'static str,
    arity: usize,
    tag: Term,
    value: Term,
) -> u64 {
    let mut heap = ProcessHeapHandle(&mut process.heap);
    let reason = match TermBuilder::new(&mut heap).tuple2(tag, value) {
        Ok(reason) => reason,
        Err(_) => return system_limit(c_p, i),
    };
    let _ = (reg, process, export, arity);
    bif_ret(
        c_p,
        i,
        Err(VmError::Trap(crate::exceptions::Trap::error(reason))),
    )
}

/// `BIF_ERROR(p, SYSTEM_LIMIT)` of a failed `HAlloc`, which erts cannot hit (the heap grows).
#[cold]
#[inline(never)]
fn system_limit(c_p: *mut ProcessHeader, i: u64) -> u64 {
    bif_ret(
        c_p,
        i,
        Err(VmError::Trap(crate::exceptions::Trap::error(Term::atom(
            atoms::SYSTEM_LIMIT,
        )))),
    )
}

/// `maps:merge/2`.
// Port of erts/emulator/beam/erl_map.c (maps_merge_2, flatmap_merge, map_merge_mixed),
// OTP-29.1.1.
pub(crate) extern "C" fn maps_merge_2(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let [map_a, map_b] = crate::bif_table::bif_args::<2>(reg);
    if map_a == map_b {
        // Merging upon itself always returns itself.
        if map_a.is_flatmap() || map_a.is_hashmap() {
            return crate::native_hooks::raw(map_a);
        }
        return bif_error_tagged(
            c_p,
            reg,
            i,
            process,
            "maps:merge/2",
            2,
            Term::atom(atoms::BADMAP),
            map_a,
        );
    }
    if map_a.is_flatmap() {
        if map_b.is_flatmap() {
            let mut heap = ProcessHeapHandle(&mut process.heap);
            return match arinsal_maps::flatmap_merge(map_a, map_b, &mut heap) {
                Ok(value) => crate::native_hooks::raw(value),
                Err(_) => system_limit(c_p, i),
            };
        }
        if map_b.is_hashmap() {
            // Will always become a tree.
            return map_merge_mixed(c_p, reg, i, process, map_a, map_b, false);
        }
        return bif_error_tagged(
            c_p,
            reg,
            i,
            process,
            "maps:merge/2",
            2,
            Term::atom(atoms::BADMAP),
            map_b,
        );
    }
    if map_a.is_hashmap() {
        if map_b.is_hashmap() {
            let merge = HashmapMergeContext::new(map_a, map_b, false);
            return hashmap_merge(c_p, reg, i, process, merge, None);
        }
        if map_b.is_flatmap() {
            return map_merge_mixed(c_p, reg, i, process, map_b, map_a, true);
        }
        return bif_error_tagged(
            c_p,
            reg,
            i,
            process,
            "maps:merge/2",
            2,
            Term::atom(atoms::BADMAP),
            map_b,
        );
    }
    bif_error_tagged(
        c_p,
        reg,
        i,
        process,
        "maps:merge/2",
        2,
        Term::atom(atoms::BADMAP),
        map_a,
    )
}

/// Convert the flatmap to a HAMT, then `hashmap_merge`.
// Port of erts/emulator/beam/erl_map.c (map_merge_mixed), OTP-29.1.1.
fn map_merge_mixed(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
    process: &mut crate::Process,
    flat: Term,
    tree: Term,
    swap_args: bool,
) -> u64 {
    let converted = {
        let mut heap = ProcessHeapHandle(&mut process.heap);
        arinsal_maps::map_merge_mixed_hashmap(flat, &mut heap)
    };
    match converted {
        Ok(None) => crate::native_hooks::raw(tree),
        Ok(Some(res)) => {
            let merge = HashmapMergeContext::new(res, tree, swap_args);
            hashmap_merge(c_p, reg, i, process, merge, None)
        }
        Err(_) => system_limit(c_p, i),
    }
}

/// `maps:merge_trap/1`, `hashmap_merge_trap_export`.
// Port of erts/emulator/beam/erl_map.c (maps_merge_trap_1), OTP-29.1.1.
pub(crate) extern "C" fn maps_merge_trap_1(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let [state_mref] = crate::bif_table::bif_args::<1>(reg);
    // `erts_magic_ref2bin(BIF_ARG_1)`: only `hashmap_merge` traps here, with its own state.
    let merge = state_mref
        .with_magic_payload_mut::<MergeState, _>(|state| state.0.take())
        .flatten();
    match merge {
        Some(merge) => hashmap_merge(c_p, reg, i, process, merge, Some(state_mref)),
        None => ycf_error(
            c_p,
            reg,
            i,
            process,
            "maps:merge_trap/1",
            1,
            arinsal_bifs::BifError::BADARG,
        ),
    }
}

/// `hashmap_merge`: runs the merge for `MAP_MERGE_LOOP_FACTOR * ERTS_BIF_REDS_LEFT(p)` loop
/// steps, then returns the map (re-enabling collection after a trap) or `BIF_TRAP1`s to
/// `hashmap_merge_trap_export` with the context's magic reference.
// Port of erts/emulator/beam/erl_map.c (hashmap_merge: the ctx == NULL / resume_from_trap
// entries, `BUMP_REDS`, and the `trap:` label), OTP-29.1.1.
fn hashmap_merge(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
    process: &mut crate::Process,
    mut merge: HashmapMergeContext,
    trap_bin: Option<Term>,
) -> u64 {
    let factor = MAP_MERGE_LOOP_FACTOR;
    let initial_reds = (process.heap.abi.fcalls.max(0) as isize).saturating_mul(factor);
    let mut reds = initial_reds;
    let merged = {
        let mut heap = ProcessHeapHandle(&mut process.heap);
        arinsal_maps::hashmap_merge(&mut merge, &mut reds, &mut heap)
    };
    match merged {
        Ok(Some(value)) => {
            if trap_bin.is_some() {
                // erts_set_gc_state(p, 1)
                process.set_gc_enabled(true);
            }
            ycf_bump_reds(process, initial_reds as i64, reds as i64, factor as i64);
            crate::native_hooks::raw(value)
        }
        Ok(None) => {
            let state_mref = match trap_bin {
                Some(state_mref) => {
                    let _ = state_mref.with_magic_payload_mut::<MergeState, _>(|state| {
                        state.0 = Some(merge);
                    });
                    state_mref
                }
                None => {
                    let created = create_state_mref::<MergeState>(
                        process,
                        TrapContext::new(Some(merge)),
                        ERTS_HASHMAP_MERGE_CONTEXT_SIZE,
                    );
                    match created {
                        Ok(state_mref) => {
                            process.set_gc_enabled(false);
                            state_mref
                        }
                        Err(error) => return bif_ret(c_p, i, Err(error)),
                    }
                }
            };
            // BUMP_ALL_REDS(p); BIF_TRAP1(&hashmap_merge_trap_export, p, ctx->trap_bin)
            crate::natives::erl_bif_chksum::bump_all_reds(process);
            let trap = crate::natives::erl_bif_lists::bif_trap(
                process,
                "maps:merge_trap/1",
                vec![state_mref],
            );
            bif_ret(c_p, i, Err(trap))
        }
        Err(_) => ycf_error(
            c_p,
            reg,
            i,
            process,
            "maps:merge/2",
            2,
            arinsal_bifs::BifError::SystemLimit,
        ),
    }
}

/// `maps:find/2`.
// Port of erts/emulator/beam/erl_map.c (maps_find_2), OTP-29.1.1.
pub(crate) extern "C" fn maps_find_2(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let [key, map] = crate::bif_table::bif_args::<2>(reg);
    if !(map.is_flatmap() || map.is_hashmap()) {
        return bif_error_tagged(
            c_p,
            reg,
            i,
            process,
            "maps:find/2",
            2,
            Term::atom(atoms::BADMAP),
            map,
        );
    }
    match arinsal_maps::get(map, key) {
        Ok(Some(value)) => {
            let mut heap = ProcessHeapHandle(&mut process.heap);
            match TermBuilder::new(&mut heap).tuple2(Term::atom(atoms::OK), value) {
                Ok(res) => crate::native_hooks::raw(res),
                Err(_) => system_limit(c_p, i),
            }
        }
        Ok(None) => crate::native_hooks::raw(Term::atom(atoms::ERROR)),
        Err(_) => bif_error_tagged(
            c_p,
            reg,
            i,
            process,
            "maps:find/2",
            2,
            Term::atom(atoms::BADMAP),
            map,
        ),
    }
}

/// `maps:get/2`.
// Port of erts/emulator/beam/erl_map.c (maps_get_2), OTP-29.1.1.
pub(crate) extern "C" fn maps_get_2(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let [key, map] = crate::bif_table::bif_args::<2>(reg);
    if map.is_flatmap() || map.is_hashmap() {
        if let Ok(Some(value)) = arinsal_maps::get(map, key) {
            return crate::native_hooks::raw(value);
        }
        return bif_error_tagged(
            c_p,
            reg,
            i,
            process,
            "maps:get/2",
            2,
            Term::atom(atoms::BADKEY),
            key,
        );
    }
    bif_error_tagged(
        c_p,
        reg,
        i,
        process,
        "maps:get/2",
        2,
        Term::atom(atoms::BADMAP),
        map,
    )
}

/// `maps:is_key/2`.
// Port of erts/emulator/beam/erl_map.c (maps_is_key_2), OTP-29.1.1.
pub(crate) extern "C" fn maps_is_key_2(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let [key, map] = crate::bif_table::bif_args::<2>(reg);
    if map.is_flatmap() || map.is_hashmap() {
        let found = matches!(arinsal_maps::get(map, key), Ok(Some(_)));
        return crate::native_hooks::raw(Term::atom(if found {
            atoms::TRUE
        } else {
            atoms::FALSE
        }));
    }
    bif_error_tagged(
        c_p,
        reg,
        i,
        process,
        "maps:is_key/2",
        2,
        Term::atom(atoms::BADMAP),
        map,
    )
}

/// The failure of a map operation as `BIF_ERROR` with the BIF's frame: `{badmap, Map}` or
/// `{badkey, Key}`.
// Port of erts/emulator/beam/erl_map.c (BIF_ERROR(BADMAP) / BIF_ERROR(BADKEY) of
// maps_put_3, maps_remove_2, maps_update_3, maps_take_2), OTP-29.1.1.
#[cold]
#[inline(never)]
fn map_failure(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
    process: &mut crate::Process,
    export: &'static str,
    arity: usize,
    error: arinsal_maps::MapError,
) -> u64 {
    use arinsal_maps::MapError;
    match error {
        MapError::Badmap(map) => bif_error_tagged(
            c_p,
            reg,
            i,
            process,
            export,
            arity,
            Term::atom(atoms::BADMAP),
            map,
        ),
        MapError::Badkey(key) => bif_error_tagged(
            c_p,
            reg,
            i,
            process,
            export,
            arity,
            Term::atom(atoms::BADKEY),
            key,
        ),
        MapError::Allocation => system_limit(c_p, i),
        _ => ycf_error(c_p, reg, i, process, export, arity, BifError::BADARG),
    }
}

/// `maps:put/3`.
// Port of erts/emulator/beam/erl_map.c (maps_put_3, erts_maps_put), OTP-29.1.1.
pub(crate) extern "C" fn maps_put_3(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let [key, value, map] = crate::bif_table::bif_args::<3>(reg);
    let result = {
        let mut heap = ProcessHeapHandle(&mut process.heap);
        arinsal_maps::put(map, key, value, &mut heap)
    };
    match result {
        Ok(res) => crate::native_hooks::raw(res),
        Err(error) => map_failure(c_p, reg, i, process, "maps:put/3", 3, error),
    }
}

/// `maps:update/3`.
// Port of erts/emulator/beam/erl_map.c (maps_update_3, erts_maps_update), OTP-29.1.1.
pub(crate) extern "C" fn maps_update_3(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let [key, value, map] = crate::bif_table::bif_args::<3>(reg);
    let result = {
        let mut heap = ProcessHeapHandle(&mut process.heap);
        arinsal_maps::update(map, key, value, &mut heap)
    };
    match result {
        Ok(res) => crate::native_hooks::raw(res),
        Err(error) => map_failure(c_p, reg, i, process, "maps:update/3", 3, error),
    }
}

/// `maps:remove/2`.
// Port of erts/emulator/beam/erl_map.c (maps_remove_2, erts_maps_remove), OTP-29.1.1.
pub(crate) extern "C" fn maps_remove_2(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let [key, map] = crate::bif_table::bif_args::<2>(reg);
    let result = {
        let mut heap = ProcessHeapHandle(&mut process.heap);
        arinsal_maps::remove(map, key, &mut heap)
    };
    match result {
        Ok(res) => crate::native_hooks::raw(res),
        Err(error) => map_failure(c_p, reg, i, process, "maps:remove/2", 2, error),
    }
}

/// `maps:take/2`.
// Port of erts/emulator/beam/erl_map.c (maps_take_2), OTP-29.1.1.
pub(crate) extern "C" fn maps_take_2(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let [key, map] = crate::bif_table::bif_args::<2>(reg);
    let mut heap = ProcessHeapHandle(&mut process.heap);
    let result = arinsal_maps::take(map, key, &mut heap).and_then(|taken| match taken {
        Some((value, rest)) => TermBuilder::new(&mut heap)
            .tuple2(value, rest)
            .map(Some)
            .map_err(|_| arinsal_maps::MapError::Allocation),
        None => Ok(None),
    });
    match result {
        Ok(Some(res)) => crate::native_hooks::raw(res),
        Ok(None) => crate::native_hooks::raw(Term::atom(atoms::ERROR)),
        Err(error) => map_failure(c_p, reg, i, process, "maps:take/2", 2, error),
    }
}

/// `BIF_P->fvalue = value; BIF_ERROR(BIF_P, BADMAP)`.
// Port of erts/emulator/beam/bif.h (BIF_ERROR) and erl_map.c (BADMAP sites), OTP-29.1.1.
fn bif_badmap(c_p: *mut ProcessHeader, value: Term) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.abi.exc.freason = arinsal_term::exc::EXC_BADMAP;
    process.heap.abi.exc.fvalue = value.word();
    arinsal_term::THE_NON_VALUE
}

/// `erts_debug:map_info/1`.
// Port of erts/emulator/beam/erl_map.c (erts_debug_map_info_1, hashmap_info), OTP-29.1.1.
pub(crate) extern "C" fn erts_debug_map_info_1(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    _i: u64,
) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let [node] = crate::bif_table::bif_args::<1>(reg);
    if node.is_hashmap() {
        match hashmap_info(process, node) {
            Ok(result) => crate::native_hooks::raw(result),
            Err(()) => bif_system_limit(c_p),
        }
    } else if node.is_flatmap() {
        bif_badarg(c_p)
    } else {
        bif_badmap(c_p, node)
    }
}

/// Port of erts/emulator/beam/erl_map.c:3464 (hashmap_info), OTP-29.1.1.
/// A malformed node is `ASSERT` / `ERTS_ASSERT` in erts (abort in debug); `Err(())` is only
/// `SYSTEM_LIMIT` from heap growth (`HAlloc` does not fail in erts).
fn hashmap_info(process: &mut crate::Process, node: Term) -> Result<Term, ()> {
    // Port of erts/emulator/beam/erl_map.h:220 (`HAMT_MAX_LEVEL` on a 64-bit `erts_ihash_t`).
    const HAMT_MAX_LEVEL: usize = 16;
    // `_HEADER_MAP_SUBTAG_MASK`: two HAMT-type bits plus the map subtag.
    const HEADER_MAP_SUBTAG_MASK: u64 = 0xff;
    const HAMT_SUBTAG_NODE_BITMAP: u64 = (1 << 6) | 0x2c;
    const HAMT_SUBTAG_HEAD_ARRAY: u64 = (2 << 6) | 0x2c;
    const HAMT_SUBTAG_HEAD_BITMAP: u64 = (3 << 6) | 0x2c;
    let mut leaf_usage = [0usize; HAMT_MAX_LEVEL + 2];
    let mut bitmap_usage = [0usize; 16];
    let mut collision_usage = [0usize; 16];
    let mut nleaf = 0usize;
    let mut nbitmap = 0usize;
    let mut narray = 0usize;
    let mut ncollision = 0usize;
    let mut max_depth = 0usize;
    let mut stack = vec![(0usize, node)];
    while let Some((clvl, node)) = stack.pop() {
        if node.classify() == TermKind::List {
            nleaf += 1;
            leaf_usage[clvl] += 1;
            continue;
        }
        let Some(hdr) = node.header() else {
            debug_assert!(
                false,
                "hashmap_info boxed node (erts ASSERT(is_header) then walks ptr[sz+1])"
            );
            continue;
        };
        let children = hashmap_node_children(node);
        debug_assert!(
            children.is_some(),
            "hashmap_info boxed node (erts ASSERT(is_header) then walks ptr[sz+1])"
        );
        let children = children.unwrap_or_default();
        let sz = match hdr & HEADER_MAP_SUBTAG_MASK {
            HAMT_SUBTAG_NODE_BITMAP => {
                nbitmap += 1;
                let sz = children.len();
                debug_assert!(sz < 17);
                sz
            }
            HAMT_SUBTAG_HEAD_BITMAP => {
                nbitmap += 1;
                children.len()
            }
            HAMT_SUBTAG_HEAD_ARRAY => {
                narray += 1;
                16
            }
            _ => {
                // ERTS_ASSERT(is_arity_value(hdr)): always on.
                assert_eq!(hdr & 63, 0, "hashmap_info collision node");
                debug_assert_eq!(clvl, HAMT_MAX_LEVEL);
                ncollision += 1;
                let sz = children.len();
                debug_assert!(sz >= 2);
                sz
            }
        };
        debug_assert!(sz >= 1);
        match hdr & HEADER_MAP_SUBTAG_MASK {
            HAMT_SUBTAG_NODE_BITMAP | HAMT_SUBTAG_HEAD_BITMAP => {
                bitmap_usage[sz - 1] += 1;
            }
            _ if hdr & 63 == 0 => collision_usage[sz.min(16) - 1] += 1,
            _ => {}
        }
        let clvl = clvl + 1;
        debug_assert!(clvl <= HAMT_MAX_LEVEL + 1);
        if max_depth < clvl {
            max_depth = clvl;
        }
        // erts `while (sz--) { ESTACK_PUSH(clvl); ESTACK_PUSH(ptr[sz+1]); }`: last child first.
        for child in children.into_iter().rev() {
            stack.push((clvl, child));
        }
    }
    let mut heap = ProcessHeapHandle(&mut process.heap);
    let mut builder = TermBuilder::new(&mut heap);
    let mut uint_tuple = |values: &[usize]| -> Result<Term, ()> {
        let mut terms = Vec::with_capacity(values.len());
        for value in values {
            terms.push(builder.int_from_u64(*value as u64).map_err(|_| ())?);
        }
        builder.tuple(&terms).map_err(|_| ())
    };
    let leaf_info = uint_tuple(&leaf_usage)?;
    let bitmap_info = uint_tuple(&bitmap_usage)?;
    let collision_info = uint_tuple(&collision_usage)?;
    let entries = [
        ("leafs", nleaf, leaf_info),
        ("bitmaps", nbitmap, bitmap_info),
        ("collisions", ncollision, collision_info),
    ];
    let mut result = Term::NIL;
    for (name, count, info) in entries {
        let count_term = builder.int_from_u64(count as u64).map_err(|_| ())?;
        let item = builder
            .tuple(&[crate::atom_cache::put(name), count_term, info])
            .map_err(|_| ())?;
        result = builder.cons(item, result).map_err(|_| ())?;
    }
    let arrays_count = builder.int_from_u64(narray as u64).map_err(|_| ())?;
    let arrays_item = builder
        .tuple(&[crate::atom_cache::put("arrays"), arrays_count, Term::NIL])
        .map_err(|_| ())?;
    result = builder.cons(arrays_item, result).map_err(|_| ())?;
    let depth_count = builder.int_from_u64(max_depth as u64).map_err(|_| ())?;
    let depth_item = builder
        .tuple(&[crate::atom_cache::put("depth"), depth_count])
        .map_err(|_| ())?;
    builder.cons(depth_item, result).map_err(|_| ())
}

/// `erts_internal:map_to_tuple_keys/1`.
// Port of erts/emulator/beam/erl_map.c (erts_internal_map_to_tuple_keys_1), OTP-29.1.1.
pub(crate) extern "C" fn erts_internal_map_to_tuple_keys_1(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    _i: u64,
) -> u64 {
    let [value] = crate::bif_table::bif_args::<1>(reg);
    if value.is_flatmap() {
        match value.flatmap_keys_tuple() {
            Some(keys) => crate::native_hooks::raw(keys),
            None => bif_badarg(c_p),
        }
    } else if value.is_hashmap() {
        bif_badarg(c_p)
    } else {
        bif_badmap(c_p, value)
    }
}

/// `erts_internal:term_type/1`.
// Port of erts/emulator/beam/erl_map.c (erts_internal_term_type_1), OTP-29.1.1.
pub(crate) extern "C" fn erts_internal_term_type_1(
    _c_p: *mut ProcessHeader,
    reg: *mut u64,
    _i: u64,
) -> u64 {
    let [value] = crate::bif_table::bif_args::<1>(reg);
    crate::native_hooks::raw(term_type(value))
}

fn term_type(value: Term) -> Term {
    let name = match value.classify() {
        TermKind::Number => match value.header().map(|header| header & 63) {
            Some(0x18) => "hfloat",
            Some(0x08 | 0x0c) => "bignum",
            _ => "fixnum",
        },
        TermKind::Atom => "atom",
        TermKind::Ref => match value.header().map(|header| header & 63) {
            Some(0x10) => "reference",
            _ => "external_reference",
        },
        TermKind::Fun => {
            if value.header().is_some_and(|header| (header >> 24) & 1 != 0) {
                "export"
            } else {
                "fun"
            }
        }
        TermKind::Port => {
            if value.header().is_some() {
                "external_port"
            } else {
                "port"
            }
        }
        TermKind::Pid => {
            if value.header().is_some() {
                "external_pid"
            } else {
                "pid"
            }
        }
        TermKind::Tuple => "tuple",
        TermKind::Record => "tuple",
        TermKind::Map => match value.header().map(|header| (header >> 6) & 3) {
            Some(0) => "flatmap",
            Some(1) => "hashmap_node",
            Some(2 | 3) => "hashmap",
            _ => "hashmap",
        },
        TermKind::Nil => "nil",
        TermKind::List => "list",
        TermKind::Bitstring => match value.header().map(|header| header & 63) {
            Some(0x20) => "heap_binary",
            Some(0x24) => "sub_binary",
            _ => "refc_binary",
        },
        TermKind::BinRef => "refc_binary",
        TermKind::Catch => "catch",
        TermKind::Invalid => "invalid",
    };
    crate::atom_cache::put(name)
}

/// `erts_internal:map_hashmap_children/1`.
// Port of erts/emulator/beam/erl_map.c (erts_internal_map_hashmap_children_1), OTP-29.1.1.
pub(crate) extern "C" fn erts_internal_map_hashmap_children_1(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    _i: u64,
) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let [value] = crate::bif_table::bif_args::<1>(reg);
    if value.classify() != TermKind::Map {
        return bif_badmap(c_p, value);
    }
    let Some(children) = hashmap_node_children(value) else {
        return bif_badarg(c_p);
    };
    let mut heap = ProcessHeapHandle(&mut process.heap);
    let mut builder = TermBuilder::new(&mut heap);
    let mut result = Term::NIL;
    for child in children {
        match builder.cons(child, result) {
            Ok(list) => result = list,
            Err(_) => return bif_system_limit(c_p),
        }
    }
    crate::native_hooks::raw(result)
}

/// `erts_internal:map_next/3`.
// Port of erts/emulator/beam/erl_map.c (erts_internal_map_next_3), OTP-29.1.1.
pub(crate) extern "C" fn erts_internal_map_next_3(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    _i: u64,
) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let args = crate::bif_table::bif_args::<3>(reg);
    match crate::natives::maps::map_next(process, &args) {
        Ok(value) => crate::native_hooks::raw(value),
        Err(crate::natives::maps::MapNextError::Badarg) => bif_badarg(c_p),
        Err(crate::natives::maps::MapNextError::SystemLimit) => bif_system_limit(c_p),
    }
}

arinsal_term::magic_payload!(
    BuildState => maps_from_keys_destructor,
    ProjectionState => maps_projection_destructor,
    MergeState => hashmap_merge_ctx_destructor,
);
