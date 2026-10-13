//! BEAM map instruction handlers.

use crate::{Process, VmError, exceptions};
use arinsal_loader::{Arg, GenericOp, Module};
use arinsal_maps::{self, MapError};
use arinsal_spec::Opcode;
use arinsal_term::{Term, TermBuilder, global_atoms};

fn has_label(label: Arg) -> bool {
    label.kind() == Arg::LABEL && label.value() != u32::MAX as u64
}

#[inline]
fn failure(p: &mut Process, label: Arg) -> Result<(), VmError> {
    if label.kind() != Arg::LABEL || label.value() == u32::MAX as u64 {
        return Err(VmError::Unsupported("map failure label zero".into()));
    }
    p.ip = label.value() as usize;
    Ok(())
}

/// Raise `{badmap, M}`, `{badkey, K}` or `badarg` as a structured exception.
#[allow(deprecated)]
fn exception(p: &mut Process, error: MapError) -> VmError {
    let (tag, culprit) = match error {
        MapError::Badmap(map) => ("badmap", map),
        MapError::Badkey(key) => ("badkey", key),
        MapError::Badarg(_) => {
            return match global_atoms().intern("badarg") {
                Ok(atom) => VmError::Trap(exceptions::Trap::error(Term::atom(atom))),
                Err(_) => VmError::Unsupported("exception atom".into()),
            };
        }
        MapError::UnsupportedKey(_) => return VmError::Unsupported("map key".into()),
        MapError::HeapFull { .. } => return VmError::Unsupported("map heap".into()),
    };
    let reason = (|| {
        p.x[0] = culprit;
        p.ensure(3, 1)?;
        let culprit = p.x[0];
        let tag = global_atoms()
            .intern(tag)
            .map_err(|_| VmError::Unsupported("exception atom".into()))?;
        TermBuilder::new(&mut p.heap)
            .tuple(&[Term::atom(tag), culprit])
            .map_err(|e| VmError::Unsupported(format!("exception allocation {e:?}")))
    })();
    match reason {
        Ok(reason) => VmError::Trap(exceptions::Trap::error(reason)),
        Err(error) => error,
    }
}

/// Execute an opcode from the map family. The caller has synchronized its heap cursor.
#[inline]
pub(super) fn execute(
    p: &mut Process,
    module: &Module,
    op: &GenericOp,
    _frame: &str,
) -> Result<(), VmError> {
    let [fail, source, destination] = op.args;
    match op.opcode() {
        Opcode::PutMapAssoc | Opcode::PutMapExact => {
            // Port of erts/emulator/beam/emu/map_instrs.tab:124-170 (update_map_assoc,
            // update_map_exact) and beam_common.c:1863-2344, OTP-29.1.1.
            let exact = op.opcode() == Opcode::PutMapExact;
            let live = module.arg(op, 3).value() as usize;
            let args = &module.lists[module.arg(op, 4).value() as usize];
            let n = args.len();
            let mut map = p.read(source)?;
            let need = if exact {
                arinsal_maps::update_map_exact_need(map)
            } else {
                arinsal_maps::update_map_assoc_need(map, n)
            };
            // reg[live] = map: the collection keeps it as the extra root.
            if p.heap.words_left() < need {
                if live >= p.x.len() {
                    return Err(VmError::Unsupported("live X register count".into()));
                }
                p.x[live] = map;
                p.ensure(need, live + 1)?;
                map = p.x[live];
            }
            let result = if let [key_arg, value_arg] = args.as_ref() {
                let (key, value) = (p.read(*key_arg)?, p.read(*value_arg)?);
                let arg = |i: usize| if i == 0 { key } else { value };
                let mut heap = crate::ProcessHeapHandle(&mut p.heap);
                if exact {
                    arinsal_maps::gc_update_map_exact(map, n, arg, &mut heap)
                } else {
                    arinsal_maps::gc_update_map_assoc(map, n, arg, &mut heap)
                }
            } else {
                // The emulator's loader sorts the vector (`map_key_sort`); the generic
                // instruction is sorted here instead.
                let mut pairs = args
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|pair| Ok((p.read(pair[0])?, p.read(pair[1])?)))
                    .collect::<Result<Vec<(Term, Term)>, VmError>>()?;
                pairs.sort_by(|a, b| arinsal_maps::flatmap_key_cmp(a.0, b.0));
                let arg = |i: usize| {
                    let (key, value) = pairs[i / 2];
                    if i.is_multiple_of(2) { key } else { value }
                };
                let mut heap = crate::ProcessHeapHandle(&mut p.heap);
                if exact {
                    arinsal_maps::gc_update_map_exact(map, n, arg, &mut heap)
                } else {
                    arinsal_maps::gc_update_map_assoc(map, n, arg, &mut heap)
                }
            };
            match result {
                Ok(value) => {
                    p.write(destination, value)?;
                    p.ip += 1;
                    Ok(())
                }
                Err(MapError::Badkey(_)) if exact && has_label(fail) => failure(p, fail),
                Err(error) => Err(exception(p, error)),
            }
        }
        Opcode::GetMapElements => {
            let map = p.read(source)?;
            if matches!(arinsal_maps::size(map), Err(MapError::Badmap(_))) {
                return failure(p, fail);
            }
            let args = &module.lists[destination.value() as usize];
            let mut values = Vec::with_capacity(args.len() / 2);
            for pair in args.as_chunks::<2>().0 {
                match arinsal_maps::get(map, p.read(pair[0])?) {
                    Ok(Some(value)) => values.push((pair[1], value)),
                    Ok(None) | Err(MapError::Badmap(_)) => return failure(p, fail),
                    Err(error) => return Err(exception(p, error)),
                }
            }
            for (dst, value) in values {
                p.write(dst, value)?;
            }
            p.ip += 1;
            Ok(())
        }
        Opcode::HasMapFields => {
            let map = p.read(source)?;
            if matches!(arinsal_maps::size(map), Err(MapError::Badmap(_))) {
                return failure(p, fail);
            }
            for key in &module.lists[destination.value() as usize] {
                match arinsal_maps::get(map, p.read(*key)?) {
                    Ok(Some(_)) => {}
                    Ok(None) | Err(MapError::Badmap(_)) => return failure(p, fail),
                    Err(error) => return Err(exception(p, error)),
                }
            }
            p.ip += 1;
            Ok(())
        }
        _ => Err(VmError::Unsupported(format!(
            "map opcode {}",
            op.opcode().name()
        ))),
    }
}
