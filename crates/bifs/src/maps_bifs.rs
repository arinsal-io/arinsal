//! Map BIF adapters over flatmaps and HAMTs.

use arinsal_maps::{self, MapError, MapResult};
use arinsal_term::{Term, global_atoms};

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
