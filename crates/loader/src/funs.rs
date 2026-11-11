//! Lambda table resolution.

use crate::LoadError;
use arinsal_beam::BeamFile;
use arinsal_term::{FunEntry, Term, global_atoms};
use md5::{Digest, Md5};
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

/// Compute the OTP 29 module checksum carried by local fun identities.
pub fn module_uniq(bytes: &[u8]) -> Result<[u8; 16], LoadError> {
    // Port of erts/emulator/beam/beam_file.c:1753 (module checksum), OTP-29.1.1.
    // The ids the checksum covers, in the order erts hashes them; a later duplicate replaces an
    // earlier chunk, as the table insert did.
    const IDS: [[u8; 4]; 10] = [
        *b"AtU8", *b"Code", *b"StrT", *b"ImpT", *b"ExpT", *b"FunT", *b"LitT", *b"Meta", *b"Recs",
        *b"DbgB",
    ];
    let mut slots = [None::<&[u8]>; 10];
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
        if let Some(slot) = IDS.iter().position(|wanted| *wanted == id) {
            slots[slot] = Some(data);
        }
        position = (end + 3) & !3;
    }
    let mut digest = Md5::new();
    for data in slots[..5].iter().flatten() {
        digest.update(data);
    }
    if let Some(fun_t) = slots[5] {
        if fun_t.len() < 4 || (fun_t.len() - 4) % 24 != 0 {
            return Err(LoadError::Limit);
        }
        digest.update(&fun_t[..4]);
        for entry in fun_t[4..].as_chunks::<24>().0 {
            digest.update(&entry[..20]);
            digest.update([0; 4]);
        }
    }
    for data in slots[6..].iter().flatten() {
        digest.update(data);
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

/// The lambda table; the targets come later (`Module::finish_native`).
pub(crate) fn load_funs(file: &BeamFile) -> Result<Vec<FunSlot>, LoadError> {
    let module = global_atoms()
        .intern(&file.module)
        .map_err(|_| LoadError::Atom(file.module.clone()))?;
    let mut slots = Vec::with_capacity(file.lambdas.len());
    for lambda in &file.lambdas {
        let total = usize::try_from(lambda.arity).map_err(|_| LoadError::Limit)?;
        let free = usize::try_from(lambda.num_free).map_err(|_| LoadError::Limit)?;
        let arity = total.checked_sub(free).ok_or(LoadError::Limit)?;
        let arity = u8::try_from(arity).map_err(|_| LoadError::Limit)?;
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
                dispatch_epoch: Default::default(),
            }),
            target: 0,
            num_free: free,
        });
    }
    Ok(slots)
}
