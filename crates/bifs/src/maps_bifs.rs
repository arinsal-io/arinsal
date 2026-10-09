//! Map BIF adapters over flatmaps and HAMTs.

use arinsal_maps::{self, MapError, MapResult};
use arinsal_term::{Term, TermKind, global_atoms};

use crate::pure::{bool_term, integer, list, make_list, tuple_build};
use crate::{BifError, BifFn, Ctx};

pub(super) fn lookup(module: &str, name: &str, arity: u8) -> Option<BifFn> {
    let f: BifFn = match (module, name, arity) {
        ("erlang", "map_size", 1) => map_size,
        ("erlang", "map_get", 2) => map_get,
        ("erlang", "is_map_key", 2) => is_map_key,
        ("maps", "find", 2) => find,
        ("maps", "get", 2) => get,
        ("maps", "is_key", 2) => is_key,
        ("maps", "from_list", 1) => from_list,
        ("maps", "from_keys", 2) => from_keys,
        ("maps", "keys", 1) => keys,
        ("maps", "values", 1) => values,
        ("maps", "merge", 2) => merge,
        ("maps", "put", 3) => put,
        ("maps", "remove", 2) => remove,
        ("maps", "update", 3) => update,
        ("maps", "take", 2) => take,
        _ => return None,
    };
    arinsal_spec::bif_lookup(module, name, arity).map(|_| f)
}

fn atom(name: &str) -> Term {
    Term::atom(global_atoms().intern(name).expect("OTP atom"))
}

// `UnsupportedKey` is deprecated and never produced any more, but the match
// must stay exhaustive.
#[allow(deprecated)]
fn map_error(ctx: &mut Ctx<'_>, error: MapError) -> BifError {
    match error {
        MapError::Badmap(map) => BifError::Error(tuple_build(ctx, &[atom("badmap"), map])),
        MapError::Badkey(key) => BifError::Error(tuple_build(ctx, &[atom("badkey"), key])),
        MapError::Badarg(_) => BifError::BADARG,
        MapError::UnsupportedKey(_) => BifError::Unsupported("HAMT nested map key"),
        MapError::HeapFull { .. } => panic!("infallible BIF heap returned HeapFull"),
    }
}

fn mapped<T>(ctx: &mut Ctx<'_>, result: MapResult<T>) -> Result<T, BifError> {
    result.map_err(|error| map_error(ctx, error))
}

fn map_size(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let size = mapped(ctx, arinsal_maps::size(args[0]))?;
    integer(ctx, size)
}
fn map_get(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    mapped(ctx, arinsal_maps::get(args[1], args[0]))?
        .ok_or_else(|| map_error(ctx, MapError::Badkey(args[0])))
}
fn is_map_key(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    Ok(bool_term(mapped(
        ctx,
        arinsal_maps::is_key(args[1], args[0]),
    )?))
}
fn get(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    map_get(ctx, args)
}
fn is_key(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    is_map_key(ctx, args)
}
fn find(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    match mapped(ctx, arinsal_maps::find(args[1], args[0]))? {
        Some(value) => Ok(tuple_build(ctx, &[atom("ok"), value])),
        None => Ok(atom("error")),
    }
}
fn from_list(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let mut pairs = Vec::new();
    for item in list(args[0])? {
        // SAFETY: argument heap is live for the BIF call.
        let tuple = unsafe { item.tuple_ref() }.ok_or(BifError::BADARG)?;
        if tuple.len() != 2 {
            return Err(BifError::BADARG);
        }
        pairs.push((tuple.get(0).unwrap(), tuple.get(1).unwrap()));
    }
    let result = arinsal_maps::from_list(&pairs, ctx.heap);
    mapped(ctx, result)
}
fn from_keys(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let keys = list(args[0])?;
    let result = arinsal_maps::from_keys(&keys, args[1], ctx.heap);
    mapped(ctx, result)
}
fn keys(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let items = mapped(ctx, arinsal_maps::keys(args[0]))?;
    Ok(make_list(ctx, items, Term::NIL))
}
fn values(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let items = mapped(ctx, arinsal_maps::values(args[0]))?;
    Ok(make_list(ctx, items, Term::NIL))
}

/// Resumable `maps:keys/1` / `maps:values/1` over a hashmap.
///
/// Port of erts/emulator/beam/erl_map.c:2801-2880 (hashmap_keys, hashmap_values), OTP-29.1.1:
/// the entries are walked backwards and consed on, one reduction per entry. The partial list
/// cannot be written into heap space across yields in safe code, so the visited items wait in
/// a vector and are consed when the walk ends.
pub struct MapsProjectionWalk {
    iter: arinsal_term::MapReverseIter,
    keys: bool,
    items: Vec<Term>,
}

/// Outcome of starting a projection.
pub enum ProjectionStart {
    /// A flatmap: erts builds its list without yielding.
    Done(Term),
    /// A hashmap to walk with [`MapsProjectionWalk::step`].
    Walk(MapsProjectionWalk),
}

impl MapsProjectionWalk {
    /// Validate the map argument and start (`maps_keys_1_helper`, `maps_values_1_helper`).
    pub fn start(ctx: &mut Ctx<'_>, map: Term, keys: bool) -> Result<ProjectionStart, BifError> {
        mapped(ctx, arinsal_maps::size(map))?;
        let Some(iter) = arinsal_term::MapReverseIter::new(map) else {
            let items = mapped(
                ctx,
                if keys {
                    arinsal_maps::keys(map)
                } else {
                    arinsal_maps::values(map)
                },
            )?;
            return Ok(ProjectionStart::Done(make_list(ctx, items, Term::NIL)));
        };
        Ok(ProjectionStart::Walk(Self {
            iter,
            keys,
            items: Vec::new(),
        }))
    }

    /// Walk entries while `reds` (the YCF reduction counter) stays positive. Returns whether
    /// the walk is complete.
    pub fn step(&mut self, reds: &mut i64) -> bool {
        for (key, value) in self.iter.by_ref() {
            self.items.push(if self.keys { key } else { value });
            *reds -= 1;
            if *reds <= 0 {
                return false;
            }
        }
        true
    }

    /// Cons the visited items; the backwards walk leaves them in reverse list order.
    pub fn finish(mut self, ctx: &mut Ctx<'_>) -> Term {
        self.items.reverse();
        make_list(ctx, self.items, Term::NIL)
    }
}

#[derive(Clone, Copy)]
enum BuildPhase {
    /// First loop of `maps_from_list_1_helper` / `maps_from_keys_2_helper`: check the list.
    Validate,
    /// Second loop of `hashmap_from_validated_list`: hash every entry.
    Leaves,
    /// `hashmap_from_unsorted_array` and what it calls.
    Build,
}

/// Port of erts/emulator/beam/erl_map.h (MAP_SMALL_MAP_LIMIT), OTP-29.1.1.
const MAP_SMALL_MAP_LIMIT: usize = 32;

/// Resumable `maps:from_list/1` and `maps:from_keys/2`.
///
/// Port of erts/emulator/beam/erl_map.c:278-366 (maps_from_keys_2_helper,
/// maps_from_list_1_helper) and :482-591 (hashmap_from_validated_list), OTP-29.1.1. Both list
/// loops cost one reduction per element; the construction below them is
/// [`arinsal_term::HashmapBuild`]. The leaves are allocated together once every entry is hashed,
/// where C allocates them before the loop and fills them in.
pub struct MapsBuildWalk {
    list: Term,
    /// The shared value of `maps:from_keys/2`.
    fill: Option<Term>,
    phase: BuildPhase,
    cursor: Term,
    size: usize,
    entries: Vec<(u64, Term, Term)>,
    build: Option<arinsal_maps::HashmapFromPairs>,
}

impl MapsBuildWalk {
    /// Start `maps:from_list/1` on `list`.
    pub fn from_list(list: Term) -> Self {
        Self::new(list, None)
    }

    /// Start `maps:from_keys/2` on `list` with the shared `value`.
    pub fn from_keys(list: Term, value: Term) -> Self {
        Self::new(list, Some(value))
    }

    fn new(list: Term, fill: Option<Term>) -> Self {
        Self {
            list,
            fill,
            phase: BuildPhase::Validate,
            cursor: list,
            size: 0,
            entries: Vec::new(),
            build: None,
        }
    }

    /// The key and value of a list element (`from_list` elements must be 2-tuples).
    fn element(&self, item: Term) -> Result<(Term, Term), BifError> {
        if let Some(value) = self.fill {
            return Ok((item, value));
        }
        // SAFETY: the input list stays live while the call is trapped (GC is disabled).
        let tuple = unsafe { item.tuple_ref() }.ok_or(BifError::BADARG)?;
        if tuple.len() != 2 {
            return Err(BifError::BADARG);
        }
        Ok((
            tuple.get(0).ok_or(BifError::BADARG)?,
            tuple.get(1).ok_or(BifError::BADARG)?,
        ))
    }

    /// One cell of the input list.
    fn cell(cursor: Term) -> Result<(Term, Term), BifError> {
        // SAFETY: the input list stays live while the call is trapped (GC is disabled).
        unsafe { cursor.cons_ref() }.ok_or(BifError::BADARG)
    }

    /// Run with `reds` reductions of budget (the YCF counter); the finished map, or `None`
    /// after a yield.
    pub fn step(&mut self, ctx: &mut Ctx<'_>, reds: &mut i64) -> Result<Option<Term>, BifError> {
        loop {
            match self.phase {
                BuildPhase::Validate => {
                    while self.cursor.classify() == TermKind::List {
                        *reds -= 1;
                        let (head, tail) = Self::cell(self.cursor)?;
                        self.element(head)?;
                        self.size += 1;
                        self.cursor = tail;
                        if *reds <= 0 {
                            return Ok(None);
                        }
                    }
                    if self.cursor != Term::NIL {
                        return Err(BifError::BADARG);
                    }
                    if self.size <= MAP_SMALL_MAP_LIMIT {
                        // No yielding while constructing a flatmap: the list is short.
                        let mut pairs = Vec::with_capacity(self.size);
                        let mut cursor = self.list;
                        while cursor.classify() == TermKind::List {
                            let (head, tail) = Self::cell(cursor)?;
                            pairs.push(self.element(head)?);
                            cursor = tail;
                        }
                        let result = if let Some(value) = self.fill {
                            let keys: Vec<Term> = pairs.iter().map(|pair| pair.0).collect();
                            arinsal_maps::from_keys(&keys, value, ctx.heap)
                        } else {
                            arinsal_maps::from_list(&pairs, ctx.heap)
                        };
                        return mapped(ctx, result).map(Some);
                    }
                    self.cursor = self.list;
                    self.entries.reserve(self.size);
                    self.phase = BuildPhase::Leaves;
                }
                BuildPhase::Leaves => {
                    while self.cursor.classify() == TermKind::List {
                        *reds -= 1;
                        let (head, tail) = Self::cell(self.cursor)?;
                        let (key, value) = self.element(head)?;
                        self.entries
                            .push((arinsal_term::hashmap_key_hash(key), key, value));
                        self.cursor = tail;
                        if *reds <= 0 {
                            return Ok(None);
                        }
                    }
                    let built = arinsal_maps::HashmapFromPairs::new(&self.entries, ctx.heap);
                    let build = mapped(ctx, built)?;
                    self.entries = Vec::new();
                    self.build = Some(build);
                    self.phase = BuildPhase::Build;
                }
                BuildPhase::Build => {
                    let build = self.build.as_mut().ok_or(BifError::BADARG)?;
                    let result = build.step(reds, ctx.heap);
                    return mapped(ctx, result);
                }
            }
        }
    }
}

fn merge(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let result = arinsal_maps::merge(args[0], args[1], ctx.heap);
    mapped(ctx, result)
}
/// First, non-yielding part of `maps:merge/2`; a HAMT result continues with
/// [`arinsal_maps::hashmap_merge`] under a reduction budget.
///
/// Port of erts/emulator/beam/erl_map.c:1257-1284 (maps_merge_2), OTP-29.1.1.
pub fn maps_merge_start(
    ctx: &mut Ctx<'_>,
    args: &[Term],
) -> Result<arinsal_maps::MergeStart, BifError> {
    let result = arinsal_maps::merge_start(args[0], args[1], ctx.heap);
    mapped(ctx, result)
}
fn put(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let result = arinsal_maps::put(args[2], args[0], args[1], ctx.heap);
    mapped(ctx, result)
}
fn remove(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let result = arinsal_maps::remove(args[1], args[0], ctx.heap);
    mapped(ctx, result)
}
fn update(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let result = arinsal_maps::update(args[2], args[0], args[1], ctx.heap);
    mapped(ctx, result)
}
fn take(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let value = mapped(ctx, arinsal_maps::get(args[1], args[0]))?;
    match value {
        Some(value) => {
            let result = arinsal_maps::remove(args[1], args[0], ctx.heap);
            let map = mapped(ctx, result)?;
            Ok(tuple_build(ctx, &[value, map]))
        }
        None => Ok(atom("error")),
    }
}
