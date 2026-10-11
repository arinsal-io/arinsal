//! Lambda table resolution and fun instruction specialization.

use crate::{Arg, Instr, LoadError};
use arinsal_beam::BeamFile;
use arinsal_spec::Opcode;
use arinsal_term::{FunEntry, Term, global_atoms};
use md5::{Digest, Md5};
use std::collections::HashMap;
use std::sync::Arc;

/// A retained local fun entry and its code address.
#[derive(Clone)]
pub struct FunSlot {
    /// Identity and arity exposed to the term heap.
    pub entry: Arc<FunEntry>,
    /// Entry instruction in this module.
    pub target: usize,
    /// Number of environment values appended after arguments.
    pub num_free: usize,
}

impl FunSlot {
    /// Publish this lambda's resolved target in its shared fun entry.
    // Port of erts/emulator/beam/erl_fun.c:48-52 (erts_set_fun_code), OTP-29.1.1.
    pub fn set_dispatch(&self, code_index: usize, module_id: usize, code_base: usize, epoch: u64) {
        self.entry
            .set_dispatch(code_index, module_id, self.target, code_base, epoch);
    }
}

/// Compute the OTP 29 module checksum carried by local fun identities.
pub fn module_uniq(bytes: &[u8]) -> Result<[u8; 16], LoadError> {
    // Port of erts/emulator/beam/beam_file.c:1753 (module checksum), OTP-29.1.1.
    let mut chunks = HashMap::<[u8; 4], &[u8]>::new();
    let mut position = 12_usize;
    while position + 8 <= bytes.len() {
        let id: [u8; 4] = bytes[position..position + 4]
            .try_into()
            .map_err(|_| LoadError::Limit)?;
        let length = u32::from_be_bytes(
            bytes[position + 4..position + 8]
                .try_into()
                .map_err(|_| LoadError::Limit)?,
        ) as usize;
        let end = position
            .checked_add(8)
            .and_then(|value| value.checked_add(length))
            .ok_or(LoadError::Limit)?;
        let data = bytes.get(position + 8..end).ok_or(LoadError::Limit)?;
        chunks.insert(id, data);
        position = (end + 3) & !3;
    }
    let mut digest = Md5::new();
    for id in [*b"AtU8", *b"Code", *b"StrT", *b"ImpT", *b"ExpT"] {
        if let Some(data) = chunks.get(&id) {
            digest.update(data);
        }
    }
    if let Some(fun_t) = chunks.get(b"FunT") {
        if fun_t.len() < 4 || (fun_t.len() - 4) % 24 != 0 {
            return Err(LoadError::Limit);
        }
        digest.update(&fun_t[..4]);
        for entry in fun_t[4..].as_chunks::<24>().0 {
            digest.update(&entry[..20]);
            digest.update([0; 4]);
        }
    }
    for id in [*b"LitT", *b"Meta", *b"Recs", *b"DbgB"] {
        if let Some(data) = chunks.get(&id) {
            digest.update(data);
        }
    }
    Ok(digest.finalize().into())
}

/// Return one nonempty IFF chunk payload from a BEAM image.
pub fn beamfile_chunk(bytes: &[u8], chunk_id: [u8; 4]) -> Result<Option<Vec<u8>>, LoadError> {
    // Port of erts/emulator/beam/beam_bif_load.c:166-203, OTP-29.1.1.
    if bytes.get(..4) != Some(b"FOR1") || bytes.get(8..12) != Some(b"BEAM") {
        return Ok(None);
    }
    let Some(form_len) = bytes
        .get(4..8)
        .and_then(|x| x.try_into().ok())
        .map(u32::from_be_bytes)
    else {
        return Ok(None);
    };
    if form_len as usize != bytes.len().saturating_sub(8) {
        return Ok(None);
    }
    let mut offset = 12usize;
    while offset < bytes.len() {
        let Some(header) = bytes.get(offset..offset.saturating_add(8)) else {
            return Ok(None);
        };
        let id: [u8; 4] = header[..4].try_into().map_err(|_| LoadError::Limit)?;
        let len =
            u32::from_be_bytes(header[4..].try_into().map_err(|_| LoadError::Limit)?) as usize;
        let start = offset.checked_add(8).ok_or(LoadError::Limit)?;
        let end = start.checked_add(len).ok_or(LoadError::Limit)?;
        let Some(payload) = bytes.get(start..end) else {
            return Ok(None);
        };
        if id == chunk_id {
            return Ok((!payload.is_empty()).then(|| payload.to_vec()));
        }
        offset = end.checked_add((4 - len % 4) % 4).ok_or(LoadError::Limit)?;
    }
    Ok(None)
}

pub(crate) fn load_funs(
    file: &BeamFile,
    labels: &HashMap<u32, usize>,
) -> Result<Vec<FunSlot>, LoadError> {
    let module = global_atoms()
        .intern(&file.module)
        .map_err(|_| LoadError::Atom(file.module.clone()))?;
    let mut slots = Vec::with_capacity(file.lambdas.len());
    for lambda in &file.lambdas {
        let total = usize::try_from(lambda.arity).map_err(|_| LoadError::Limit)?;
        let free = usize::try_from(lambda.num_free).map_err(|_| LoadError::Limit)?;
        let arity = total.checked_sub(free).ok_or(LoadError::Limit)?;
        let arity = u8::try_from(arity).map_err(|_| LoadError::Limit)?;
        let target = *labels
            .get(&lambda.label)
            .ok_or(LoadError::Index("label", lambda.label))?;
        slots.push(FunSlot {
            entry: Arc::new(FunEntry {
                dispatch_target: Default::default(),
                pend_purge_address: Default::default(),
                module,
                arity,
                index: lambda.index,
                uniq: [0; 16],
                old_uniq: lambda.old_uniq,
                old_index: lambda.index,
                pid: Term::pid(0, 0).expect("initial process pid fits"),
                dispatch: Default::default(),
                dispatch_code: Default::default(),
                dispatch_epoch: Default::default(),
            }),
            target,
            num_free: free,
        });
    }
    Ok(slots)
}

pub(crate) fn specialize(op: Opcode, [a, b, c]: [Arg; 3], lists: &[Box<[Arg]>]) -> Option<Instr> {
    let u16_value = |arg: Arg| {
        (arg.kind() == Arg::U)
            .then(|| u16::try_from(arg.value()).ok())
            .flatten()
    };
    match op {
        Opcode::MakeFun3 if a.kind() == Arg::U && c.kind() == Arg::LIST => {
            lists.get(c.value() as usize)?;
            Some(Instr::MakeFun {
                index: u32::try_from(a.value()).ok()?,
                dst: b,
                env: u32::try_from(c.value()).ok()?,
            })
        }
        Opcode::CallFun => Some(Instr::CallFun {
            arity: u16_value(a)?,
            src: Arg::new(Arg::X, a.value()),
            dealloc: 0,
            tail: false,
        }),
        Opcode::CallFun2 => Some(Instr::CallFun {
            arity: u16_value(b)?,
            src: c,
            dealloc: 0,
            tail: false,
        }),
        Opcode::Apply | Opcode::ApplyLast => Some(Instr::Apply {
            arity: u16_value(a)?,
            dealloc: if op == Opcode::ApplyLast {
                u16_value(b)?
            } else {
                0
            },
            tail: op == Opcode::ApplyLast,
        }),
        Opcode::IsFunction2 => Some(Instr::IsFunction2 {
            fail: u32::try_from(a.value()).ok()?,
            src: b,
            arity: c,
        }),
        _ => None,
    }
}
