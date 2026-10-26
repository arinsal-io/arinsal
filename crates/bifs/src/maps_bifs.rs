//! Map BIF adapters over flatmaps and HAMTs.

use arinsal_maps::{self, MapError, MapResult};
use arinsal_term::{Term, atoms};

use crate::pure::{bool_term, integer};
use crate::{BifError, Ctx};

pub(super) fn lookup<V: crate::BifTableVisitor>(
    module: &str,
    name: &str,
    arity: u8,
    v: &mut V,
) -> Option<V::Output> {
    let f = match (module, name, arity) {
        ("erlang", "map_size", 1) => v.entry::<word_bodies::map_size>(),
        ("erlang", "map_get", 2) => v.entry::<word_bodies::map_get>(),
        ("erlang", "is_map_key", 2) => v.entry::<word_bodies::is_map_key>(),
        ("maps", "find", 2) => v.entry::<word_bodies::find>(),
        ("maps", "get", 2) => v.entry::<word_bodies::get>(),
        ("maps", "is_key", 2) => v.entry::<word_bodies::is_key>(),
        ("maps", "from_list", 1) => v.entry::<word_bodies::from_list>(),
        ("maps", "from_keys", 2) => v.entry::<word_bodies::from_keys>(),
        ("maps", "keys", 1) => v.entry::<word_bodies::keys>(),
        ("maps", "values", 1) => v.entry::<word_bodies::values>(),
        ("maps", "merge", 2) => v.entry::<bodies::merge>(),
        ("maps", "put", 3) => v.entry::<word_bodies::put>(),
        ("maps", "remove", 2) => v.entry::<word_bodies::remove>(),
        ("maps", "update", 3) => v.entry::<word_bodies::update>(),
        ("maps", "take", 2) => v.entry::<word_bodies::take>(),
        _ => return None,
    };
    arinsal_spec::bif_lookup(module, name, arity).map(|_| f)
}

// `UnsupportedKey` is deprecated and never produced any more, but the match
// must stay exhaustive.
#[allow(deprecated)]
fn map_error(ctx: &mut Ctx<'_>, error: MapError) -> BifError {
    match error {
        MapError::Badmap(map) => BifError::Error(tuple2(ctx, Term::atom(atoms::BADMAP), map)),
        MapError::Badkey(key) => BifError::Error(tuple2(ctx, Term::atom(atoms::BADKEY), key)),
        MapError::Badarg(_) => BifError::BADARG,
        MapError::UnsupportedKey(_) => BifError::Unsupported("HAMT nested map key"),
        MapError::HeapFull { .. } => panic!("infallible BIF heap returned HeapFull"),
    }
}

#[inline(always)]
fn tuple2(ctx: &mut Ctx<'_>, first: Term, second: Term) -> Term {
    arinsal_term::TermBuilder::new(&mut ctx.heap)
        .tuple2(first, second)
        .expect("infallible BIF heap")
}

fn mapped<T>(ctx: &mut Ctx<'_>, result: MapResult<T>) -> Result<T, BifError> {
    result.map_err(|error| map_error(ctx, error))
}

fn map_size(ctx: &mut Ctx<'_>, args: &[Term]) -> Term {
    match mapped(ctx, arinsal_maps::size(args[0])).and_then(|size| integer(ctx, size)) {
        Ok(value) => value,
        Err(error) => ctx.fail(error),
    }
}
fn map_get(ctx: &mut Ctx<'_>, args: &[Term]) -> Term {
    match mapped(ctx, arinsal_maps::get(args[1], args[0])) {
        Ok(Some(value)) => value,
        Ok(None) => {
            let error = map_error(ctx, MapError::Badkey(args[0]));
            ctx.fail(error)
        }
        Err(error) => ctx.fail(error),
    }
}
fn is_map_key(ctx: &mut Ctx<'_>, args: &[Term]) -> Term {
    match mapped(ctx, arinsal_maps::is_key(args[1], args[0])) {
        Ok(value) => bool_term(value),
        Err(error) => ctx.fail(error),
    }
}
fn get(ctx: &mut Ctx<'_>, args: &[Term]) -> Term {
    map_get(ctx, args)
}
fn is_key(ctx: &mut Ctx<'_>, args: &[Term]) -> Term {
    is_map_key(ctx, args)
}
fn find(ctx: &mut Ctx<'_>, args: &[Term]) -> Term {
    match mapped(ctx, arinsal_maps::find(args[1], args[0])) {
        Ok(Some(value)) => tuple2(ctx, Term::atom(atoms::OK), value),
        Ok(None) => Term::atom(atoms::ERROR),
        Err(error) => ctx.fail(error),
    }
}
fn from_list(ctx: &mut Ctx<'_>, args: &[Term]) -> Term {
    let mut walk = MapsBuildWalk::from_list(args[0]);
    let mut reds = i64::MAX;
    match walk.step(ctx, &mut reds) {
        Ok(Some(value)) => value,
        Ok(None) => ctx.badarg(),
        Err(error) => ctx.fail(error),
    }
}
fn from_keys(ctx: &mut Ctx<'_>, args: &[Term]) -> Term {
    let mut walk = MapsBuildWalk::from_keys(args[0], args[1]);
    let mut reds = i64::MAX;
    match walk.step(ctx, &mut reds) {
        Ok(Some(value)) => value,
        Ok(None) => ctx.badarg(),
        Err(error) => ctx.fail(error),
    }
}
#[inline]
fn keys(ctx: &mut Ctx<'_>, args: &[Term]) -> Term {
    match projection(ctx, args[0], true) {
        Ok(value) => value,
        Err(error) => ctx.fail(error),
    }
}
fn values(ctx: &mut Ctx<'_>, args: &[Term]) -> Term {
    match projection(ctx, args[0], false) {
        Ok(value) => value,
        Err(error) => ctx.fail(error),
    }
}

#[inline]
fn projection(ctx: &mut Ctx<'_>, map: Term, keys: bool) -> Result<Term, BifError> {
    match MapsProjectionWalk::start(ctx, map, keys)? {
        ProjectionStart::Done(value) => Ok(value),
        ProjectionStart::Walk(mut walk) => {
            let mut reds = i64::MAX;
            while !walk.step(&mut reds) {}
            Ok(walk.finish())
        }
    }
}

/// Resumable `maps:keys/1` / `maps:values/1` over a hashmap.
///
/// Port of erts/emulator/beam/erl_map.c:2801-2880 (hashmap_keys, hashmap_values), OTP-29.1.1:
/// the entries are walked backwards and consed on, one reduction per entry. The full output
/// block is reserved before the walk, so each step writes its cons cell directly into it.
pub struct MapsProjectionWalk {
    iter: arinsal_term::MapReverseIter,
    keys: bool,
    remaining: usize,
    output: arinsal_term::ConsListBuilder,
}

/// Outcome of starting a projection.
// Keep the reverse iterator's 16-entry inline stack in the trap state, as OTP does with its
// stack-local WStack. Boxing this variant would add a heap allocation to every HAMT projection.
#[allow(clippy::large_enum_variant)]
pub enum ProjectionStart {
    /// A flatmap: erts builds its list without yielding.
    Done(Term),
    /// A hashmap to walk with [`MapsProjectionWalk::step`].
    Walk(MapsProjectionWalk),
}

impl MapsProjectionWalk {
    /// The flatmap case of `maps_keys_1_helper`/`maps_values_1_helper`: erts builds the list
    /// without yielding. `None` for a hashmap, which [`Self::start_hashmap`] walks.
    // Port of erts/emulator/beam/erl_map.c:1207-1241 and :2262-2298, OTP-29.1.1.
    #[inline]
    pub fn start_flat(ctx: &mut Ctx<'_>, map: Term, keys: bool) -> Result<Option<Term>, BifError> {
        let checked = mapped(ctx, arinsal_maps::checked_map(map))?;
        match checked.kind() {
            arinsal_maps::CheckedMapKind::Flatmap(flat) => {
                if flat.size() == 0 {
                    // Port of erts/emulator/beam/erl_map.c:1223, OTP-29.1.1:
                    // an empty flatmap returns NIL without entering the list builder.
                    return Ok(Some(Term::NIL));
                }
                let result = arinsal_maps::flatmap_projection_list(flat, keys, &mut ctx.heap);
                Ok(Some(mapped(ctx, result)?))
            }
            arinsal_maps::CheckedMapKind::Hashmap(_) => Ok(None),
        }
    }

    /// The hashmap case: reserve the whole list and return the walk to step. Kept out of line
    /// so the flatmap path does not carry the walk's inline stack in its frame.
    // Port of erts/emulator/beam/erl_map.c:2847 / :2888, OTP-29.1.1.
    #[inline(never)]
    pub fn start_hashmap(ctx: &mut Ctx<'_>, map: Term, keys: bool) -> Result<Self, BifError> {
        let checked = mapped(ctx, arinsal_maps::checked_map(map))?;
        let iter = arinsal_term::MapReverseIter::new(map).expect("checked hashmap");
        // Port of erl_map.c:2847 / :2888: reserve the entire CONS block before walking.
        let output = arinsal_term::TermBuilder::new(&mut ctx.heap)
            .reserve_cons_list(checked.size())
            .expect("infallible BIF heap");
        Ok(Self {
            iter,
            keys,
            remaining: checked.size(),
            output,
        })
    }

    /// Validate the map argument and start (`maps_keys_1_helper`, `maps_values_1_helper`).
    pub fn start(ctx: &mut Ctx<'_>, map: Term, keys: bool) -> Result<ProjectionStart, BifError> {
        match Self::start_flat(ctx, map, keys)? {
            Some(value) => Ok(ProjectionStart::Done(value)),
            None => Ok(ProjectionStart::Walk(Self::start_hashmap(ctx, map, keys)?)),
        }
    }

    /// Walk entries while `reds` (the YCF reduction counter) stays positive. Returns whether
    /// the walk is complete.
    pub fn step(&mut self, reds: &mut i64) -> bool {
        if self.remaining == 0 {
            return true;
        }
        let budget = usize::try_from((*reds).max(1)).unwrap_or(usize::MAX);
        let count = self.remaining.min(budget);
        self.output
            .prepend_chunk(
                count,
                self.iter
                    .by_ref()
                    .map(|(key, value)| if self.keys { key } else { value }),
            )
            .expect("reserved projection list length");
        self.remaining -= count;
        *reds = reds.saturating_sub(i64::try_from(count).unwrap_or(i64::MAX));
        self.remaining == 0 && *reds > 0
    }

    /// Cons the visited items; the backwards walk leaves them in reverse list order.
    pub fn finish(self) -> Term {
        self.output
            .finish(Term::NIL)
            .expect("all hashmap entries were projected")
    }
}

#[derive(Clone, Copy)]
enum BuildPhase {
    /// First loop of `maps_from_list_1_helper` / `maps_from_keys_2_helper`: check the list.
    Validate,
    /// The body after `YCF_CONSUME_REDS(1)` at the top of the validation loop.
    ValidateBody,
    /// Second loop of `hashmap_from_validated_list`: hash every entry.
    Leaves,
    /// The body after `YCF_CONSUME_REDS(1)` at the top of the leaf loop.
    LeavesBody,
    /// `hashmap_from_unsorted_array` and what it calls.
    Build,
}

/// Port of erts/emulator/beam/erl_map.h (MAP_SMALL_MAP_LIMIT), OTP-29.1.1.
const MAP_SMALL_MAP_LIMIT: usize = 32;

/// Resumable `maps:from_list/1` and `maps:from_keys/2`.
///
/// Port of erts/emulator/beam/erl_map.c:278-366 (maps_from_keys_2_helper,
/// maps_from_list_1_helper) and :482-591 (hashmap_from_validated_list), OTP-29.1.1. Both list
/// [`arinsal_term::HashmapBuild`]. The leaves are allocated together once every entry is hashed,
/// where C allocates them before the loop and fills them in.
pub struct MapsBuildWalk {
    list: Term,
    /// The shared value of `maps:from_keys/2`.
    fill: Option<Term>,
    phase: BuildPhase,
    cursor: Term,
    size: usize,
    leaves_written: usize,
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
            leaves_written: 0,
            build: None,
        }
    }

    /// The key and value of a list element (`from_list` elements must be 2-tuples).
    fn element(&self, item: Term) -> Result<(Term, Term), BifError> {
        Self::element_of(self.fill, item, true)
    }

    fn element_after_validation(&self, item: Term) -> Result<(Term, Term), BifError> {
        Self::element_of(self.fill, item, false)
    }

    fn element_of(
        fill: Option<Term>,
        item: Term,
        check_arity: bool,
    ) -> Result<(Term, Term), BifError> {
        if let Some(value) = fill {
            return Ok((item, value));
        }
        // SAFETY: the input list stays live while the call is trapped (GC is disabled).
        let tuple = unsafe { item.tuple_ref() }.ok_or(BifError::BADARG)?;
        if check_arity && tuple.len() != 2 {
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
            if matches!(self.phase, BuildPhase::Validate) {
                // Port of `maps_from_keys_2_helper` and `maps_from_list_1_helper`,
                // erts/emulator/beam/erl_map.c:279-366, OTP-29.1.1.
                // Keep its steady-state list walk in one loop; ValidateBody is only needed
                // when YCF yields after consuming a reduction and before the loop body.
                if self.fill.is_some() {
                    // Port of `maps_from_keys_2_helper`: count cells without inspecting heads.
                    while self.cursor.tagged_word() & 3 == 1 {
                        *reds -= 1;
                        if *reds <= 0 {
                            self.phase = BuildPhase::ValidateBody;
                            return Ok(None);
                        }
                        let (_, tail) = Self::cell(self.cursor)?;
                        self.size += 1;
                        self.cursor = tail;
                    }
                } else {
                    while self.cursor.tagged_word() & 3 == 1 {
                        *reds -= 1;
                        if *reds <= 0 {
                            self.phase = BuildPhase::ValidateBody;
                            return Ok(None);
                        }
                        let (head, tail) = Self::cell(self.cursor)?;
                        self.element(head)?;
                        self.size += 1;
                        self.cursor = tail;
                    }
                }
                if self.cursor != Term::NIL {
                    return Err(BifError::BADARG);
                }
                if self.size <= MAP_SMALL_MAP_LIMIT {
                    // No yielding while constructing a flatmap: the list is short. The
                    // list was validated above, so every cell is a well-formed element.
                    let fill = self.fill;
                    let mut cursor = self.list;
                    let pairs = std::iter::from_fn(|| {
                        let (head, tail) = Self::cell(cursor).ok()?;
                        cursor = tail;
                        Self::element_of(fill, head, false).ok()
                    });
                    let result = arinsal_maps::from_small_pairs(self.size, pairs, &mut ctx.heap);
                    return mapped(ctx, result).map(Some);
                }
                self.cursor = self.list;
                let build = arinsal_maps::HashmapFromPairs::new(self.size, &mut ctx.heap);
                self.build = Some(mapped(ctx, build)?);
                self.phase = BuildPhase::Leaves;
            }
            match self.phase {
                BuildPhase::Validate => unreachable!("validation loop handles this phase"),
                BuildPhase::ValidateBody => {
                    let tail = if self.fill.is_some() {
                        Self::cell(self.cursor)?.1
                    } else {
                        let (head, tail) = Self::cell(self.cursor)?;
                        self.element(head)?;
                        tail
                    };
                    self.size += 1;
                    self.cursor = tail;
                    self.phase = BuildPhase::Validate;
                }
                BuildPhase::Leaves => {
                    if self.cursor.tagged_word() & 3 == 1 {
                        self.phase = BuildPhase::LeavesBody;
                        *reds -= 1;
                        if *reds <= 0 {
                            return Ok(None);
                        }
                        // The current cell has paid its YCF iteration. Consume the
                        // remaining available entries in the same direct-fill loop.
                        let remaining = self.size - self.leaves_written;
                        let count = remaining.min(*reds as usize);
                        let fill = self.fill;
                        let mut cursor = self.cursor;
                        let pairs = std::iter::from_fn(|| {
                            let (head, tail) = Self::cell(cursor).ok()?;
                            cursor = tail;
                            Self::element_of(fill, head, false).ok()
                        })
                        .take(count);
                        self.build
                            .as_mut()
                            .expect("hashmap leaf builder")
                            .push_chunk(count, pairs)
                            .map_err(|error| map_error(ctx, error))?;
                        self.cursor = cursor;
                        self.leaves_written += count;
                        *reds -= count.saturating_sub(1) as i64;
                        self.phase = BuildPhase::Leaves;
                        continue;
                    }
                    self.build
                        .as_mut()
                        .expect("hashmap leaf builder")
                        .finish_leaves();
                    self.phase = BuildPhase::Build;
                }
                BuildPhase::LeavesBody => {
                    let (head, tail) = Self::cell(self.cursor)?;
                    let (key, value) = self.element_after_validation(head)?;
                    self.build
                        .as_mut()
                        .expect("hashmap leaf builder")
                        .push(key, value)
                        .map_err(|error| map_error(ctx, error))?;
                    self.cursor = tail;
                    self.leaves_written += 1;
                    self.phase = BuildPhase::Leaves;
                }
                BuildPhase::Build => {
                    let build = self.build.as_mut().ok_or(BifError::BADARG)?;
                    let result = build.step(reds, &mut ctx.heap);
                    return mapped(ctx, result);
                }
            }
        }
    }
}

fn merge(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let result = arinsal_maps::merge(args[0], args[1], &mut ctx.heap);
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
    let result = arinsal_maps::merge_start(args[0], args[1], &mut ctx.heap);
    mapped(ctx, result)
}

/// Start `maps:merge/2` directly on the process heap; map errors need a BIF context only off the
/// successful path.
///
/// Port of `maps_merge_2` calling `flatmap_merge` directly in
/// erts/emulator/beam/erl_map.c:1257-1284, OTP-29.1.1.
#[inline(always)]
pub fn maps_merge_start_on_process_heap(
    heap: &mut crate::ProcessHeapHandle<'_>,
    left: Term,
    right: Term,
) -> Result<arinsal_maps::MergeStart, BifError> {
    match arinsal_maps::merge_start(left, right, heap) {
        Ok(result) => Ok(result),
        Err(error) => {
            let mut state = crate::BifState::default();
            let mut ctx = Ctx::new(heap, &mut state);
            Err(map_error(&mut ctx, error))
        }
    }
}

fn put(ctx: &mut Ctx<'_>, args: &[Term]) -> Term {
    let result = arinsal_maps::put(args[2], args[0], args[1], &mut ctx.heap);
    match mapped(ctx, result) {
        Ok(value) => value,
        Err(error) => ctx.fail(error),
    }
}
fn remove(ctx: &mut Ctx<'_>, args: &[Term]) -> Term {
    let result = arinsal_maps::remove(args[1], args[0], &mut ctx.heap);
    match mapped(ctx, result) {
        Ok(value) => value,
        Err(error) => ctx.fail(error),
    }
}
fn update(ctx: &mut Ctx<'_>, args: &[Term]) -> Term {
    let result = arinsal_maps::update(args[2], args[0], args[1], &mut ctx.heap);
    match mapped(ctx, result) {
        Ok(value) => value,
        Err(error) => ctx.fail(error),
    }
}
fn take(ctx: &mut Ctx<'_>, args: &[Term]) -> Term {
    // Port of erts/emulator/beam/erl_map.c:1910-1925 (maps_take_2), OTP-29.1.1.
    let result = arinsal_maps::take(args[1], args[0], &mut ctx.heap);
    match mapped(ctx, result) {
        Ok(Some((value, map))) => tuple2(ctx, value, map),
        Ok(None) => Term::atom(atoms::ERROR),
        Err(error) => ctx.fail(error),
    }
}

crate::word_bif_bodies_in!(word_bodies;
    map_size, map_get, is_map_key, find, get, is_key, from_list, from_keys, keys, values,
    put, remove, update, take,
);
crate::process_bif_bodies!(merge);
