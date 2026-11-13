//! Map BIF adapters over flatmaps and HAMTs.

use arinsal_maps::{self, MapError, MapResult};
use arinsal_term::{
    Term, atoms,
    raw::{Cons, MapListValidator, Tuple, ValidatedMapPairs},
};

use crate::{BifError, Ctx};

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
    /// Incremental validation and the no-recheck iterator for `maps:from_list/1`.
    validator: Option<MapListValidator<'static>>,
    pairs: Option<ValidatedMapPairs<'static>>,
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
        let validator = fill.is_none().then(|| MapListValidator::new(list));
        Self {
            list,
            fill,
            phase: BuildPhase::Validate,
            cursor: list,
            size: 0,
            validator,
            pairs: None,
            leaves_written: 0,
            build: None,
        }
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
        let tuple = Tuple::try_from(item).map_err(|_| BifError::BADARG)?;
        if check_arity && tuple.arity() != 2 {
            return Err(BifError::BADARG);
        }
        let mut elements = tuple.elements();
        Ok((
            elements.next().ok_or(BifError::BADARG)?,
            elements.next().ok_or(BifError::BADARG)?,
        ))
    }

    /// One cell of the input list.
    fn cell(cursor: Term) -> Result<(Term, Term), BifError> {
        Cons::try_from(cursor)
            .map(Cons::pair)
            .map_err(|_| BifError::BADARG)
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
                let mut cursor = self.cursor;
                let mut size = self.size;
                let mut remaining_reds = *reds;
                if self.fill.is_some() {
                    // Port of `maps_from_keys_2_helper`: count cells without inspecting heads.
                    while let Ok(cons) = Cons::try_from(cursor) {
                        remaining_reds -= 1;
                        if remaining_reds <= 0 {
                            self.phase = BuildPhase::ValidateBody;
                            self.cursor = cursor;
                            self.size = size;
                            *reds = remaining_reds;
                            return Ok(None);
                        }
                        let tail = cons.tail();
                        size += 1;
                        cursor = tail;
                    }
                } else {
                    loop {
                        let cons = self
                            .validator
                            .as_mut()
                            .expect("from_list validation state")
                            .current()
                            .map_err(|_| BifError::BADARG)?;
                        let Some(cons) = cons else {
                            break;
                        };
                        remaining_reds -= 1;
                        if remaining_reds <= 0 {
                            self.phase = BuildPhase::ValidateBody;
                            self.cursor = cursor;
                            self.size = size;
                            *reds = remaining_reds;
                            return Ok(None);
                        }
                        cons.advance().map_err(|_| BifError::BADARG)?;
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
                            .map_err(|_| BifError::BADARG)?,
                    )
                } else {
                    if self.cursor != Term::NIL {
                        return Err(BifError::BADARG);
                    }
                    None
                };
                if self.size <= MAP_SMALL_MAP_LIMIT {
                    // No yielding while constructing a flatmap: the list is short. The
                    // list was validated above, so every cell is a well-formed element.
                    let result = if self.fill.is_none() {
                        arinsal_maps::from_small_pairs(
                            self.size,
                            validated.expect("validated from_list").pairs(),
                            &mut ctx.heap,
                        )
                    } else {
                        let fill = self.fill;
                        let mut cursor = self.list;
                        let pairs = std::iter::from_fn(|| {
                            let (head, tail) = Self::cell(cursor).ok()?;
                            cursor = tail;
                            Self::element_of(fill, head, false).ok()
                        });
                        arinsal_maps::from_small_pairs(self.size, pairs, &mut ctx.heap)
                    };
                    return mapped(ctx, result).map(Some);
                }
                self.cursor = self.list;
                if let Some(validated) = validated {
                    self.pairs = Some(validated.pairs());
                }
                let build = arinsal_maps::HashmapFromPairs::new(self.size, &mut ctx.heap);
                self.build = Some(mapped(ctx, build)?);
                self.phase = BuildPhase::Leaves;
            }
            if matches!(self.phase, BuildPhase::Leaves | BuildPhase::LeavesBody) {
                let mut resumed_body = matches!(self.phase, BuildPhase::LeavesBody);
                loop {
                    if self.fill.is_none() {
                        if resumed_body {
                            let (key, value) = self
                                .pairs
                                .as_mut()
                                .expect("validated map pair iterator")
                                .next()
                                .expect("remaining validated map pair");
                            self.build
                                .as_mut()
                                .expect("hashmap leaf builder")
                                .push(key, value)
                                .map_err(|error| map_error(ctx, error))?;
                            self.leaves_written += 1;
                            self.phase = BuildPhase::Leaves;
                            resumed_body = false;
                            continue;
                        }
                        if self.leaves_written < self.size {
                            *reds -= 1;
                            if *reds <= 0 {
                                self.phase = BuildPhase::LeavesBody;
                                return Ok(None);
                            }
                            let remaining = self.size - self.leaves_written;
                            let count = remaining.min(*reds as usize);
                            self.build
                                .as_mut()
                                .expect("hashmap leaf builder")
                                .push_chunk(
                                    count,
                                    self.pairs
                                        .as_mut()
                                        .expect("validated map pair iterator")
                                        .by_ref(),
                                )
                                .map_err(|error| map_error(ctx, error))?;
                            self.leaves_written += count;
                            *reds -= count.saturating_sub(1) as i64;
                            continue;
                        }
                        self.build
                            .as_mut()
                            .expect("hashmap leaf builder")
                            .finish_leaves();
                        self.pairs = None;
                        self.phase = BuildPhase::Build;
                        break;
                    }

                    if resumed_body {
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
                        resumed_body = false;
                        continue;
                    }
                    if let Ok(cons) = Cons::try_from(self.cursor) {
                        *reds -= 1;
                        if *reds <= 0 {
                            self.phase = BuildPhase::LeavesBody;
                            return Ok(None);
                        }
                        // The current cell has paid its YCF iteration. Consume the
                        // remaining available entries in the same direct-fill loop.
                        let remaining = self.size - self.leaves_written;
                        let count = remaining.min(*reds as usize);
                        let fill = self.fill;
                        let (head, mut cursor) = cons.pair();
                        let first = Self::element_of(fill, head, false)?;
                        let rest = std::iter::from_fn(|| {
                            let (head, tail) = Self::cell(cursor).ok()?;
                            cursor = tail;
                            Self::element_of(fill, head, false).ok()
                        });
                        let pairs = std::iter::once(first).chain(rest);
                        self.build
                            .as_mut()
                            .expect("hashmap leaf builder")
                            .push_chunk(count, pairs)
                            .map_err(|error| map_error(ctx, error))?;
                        self.cursor = cursor;
                        self.leaves_written += count;
                        *reds -= count.saturating_sub(1) as i64;
                        continue;
                    }
                    self.build
                        .as_mut()
                        .expect("hashmap leaf builder")
                        .finish_leaves();
                    self.phase = BuildPhase::Build;
                    break;
                }
            }
            match self.phase {
                BuildPhase::Validate => unreachable!("validation loop handles this phase"),
                BuildPhase::ValidateBody => {
                    if self.fill.is_some() {
                        self.cursor = Self::cell(self.cursor)?.1;
                    } else {
                        let cons = self
                            .validator
                            .as_mut()
                            .expect("from_list validation state")
                            .current()
                            .map_err(|_| BifError::BADARG)?
                            .expect("validation body has a current list cell");
                        cons.advance().map_err(|_| BifError::BADARG)?;
                    }
                    self.size += 1;
                    self.phase = BuildPhase::Validate;
                }
                BuildPhase::Leaves | BuildPhase::LeavesBody => {
                    unreachable!("leaf loop handles these phases")
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
