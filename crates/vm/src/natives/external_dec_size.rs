//! `decoded_size` of `binary_to_term`: the size pass that validates every length.
//!
//! Port of erts/emulator/beam/external.c (`decoded_size`), OTP-29.1.1.

use arinsal_bifs::BifError;

/// `ctx->u.sc`: the state of `decoded_size` between slices.
// Port of erts/emulator/beam/external.c (B2TContext.u.sc), OTP-29.1.1.
#[derive(Default)]
pub(crate) struct B2tSizeState {
    /// `lext_state`: the block hash of a `LOCAL_EXT` term that yielded.
    lext_state: Option<arinsal_bifs::BlockHashWalk>,
    started: bool,
    ep: usize,
    atom_extra_skip: usize,
    heap_size: usize,
    /// `lext_hash` as the hash value and the offset after it, and `lext_term_end`.
    lext_hash: Option<(u32, usize)>,
    lext_term_end: u32,
    terms: u32,
}

/// `decoded_size(ep, endp, 0, ctx)` of a body that follows the version byte: the heap size in
/// words once every term was walked, `None` when `reds` ran out first. Every length is
/// checked against `endp` here; `dec_term` relies on it.
// Port of erts/emulator/beam/external.c (decoded_size), OTP-29.1.1.
pub(crate) fn decoded_size(
    bytes: &[u8],
    sc: &mut B2tSizeState,
    reds: &mut i64,
) -> Result<Option<usize>, BifError> {
    const SMALL_MAP_LIMIT: usize = 32;
    const ERL_ONHEAP_BIN_LIMIT: usize = 64;
    const EXTERNAL_THING_HEAD_SIZE: usize = 3;
    let endp = bytes.len();
    if !sc.started {
        *sc = B2tSizeState {
            started: true,
            terms: 1,
            lext_term_end: u32::MAX,
            ..B2tSizeState::default()
        };
    }
    let mut ep = sc.ep;
    let mut atom_extra_skip = sc.atom_extra_skip;
    let mut lext_state = sc.lext_state.take();
    let mut heap_size = sc.heap_size;
    let mut lext_hash = sc.lext_hash;
    let mut lext_term_end = sc.lext_term_end;
    let mut terms = sc.terms;
    let error = || BifError::BADARG;
    macro_rules! chksize {
        ($sz:expr) => {
            if $sz > endp - ep {
                return Err(error());
            }
        };
    }
    macro_rules! skip {
        ($sz:expr) => {{
            let sz: usize = $sz;
            if sz > endp - ep {
                return Err(error());
            }
            ep += sz;
        }};
    }
    macro_rules! skip2 {
        ($sz1:expr, $sz2:expr) => {{
            let sz = usize::checked_add($sz1, $sz2).ok_or_else(error)?;
            skip!(sz);
        }};
    }
    macro_rules! addterms {
        ($n:expr) => {{
            let n = u32::try_from($n).map_err(|_| error())?;
            terms = terms.checked_add(n).ok_or_else(error)?;
        }};
    }
    macro_rules! words {
        ($n:expr) => {{
            heap_size = heap_size.checked_add($n).ok_or_else(error)?;
        }};
    }
    let u8_at = |ep: usize| bytes[ep];
    let u16_at = |ep: usize| u16::from_be_bytes([bytes[ep], bytes[ep + 1]]);
    let u32_at = |ep: usize| u32::from_be_bytes(bytes[ep..ep + 4].try_into().unwrap());
    // `goto continue_check_lext`: a hash that yielded resumes at the check, not at a tag.
    let mut resume_lext = terms == lext_term_end && lext_hash.is_some();
    loop {
        'tag: {
            if std::mem::take(&mut resume_lext) {
                break 'tag;
            }
            chksize!(1);
            let tag = u8_at(ep);
            ep += 1;
            match tag {
                97 => skip!(1),
                98 => skip!(4),
                110 => {
                    chksize!(1);
                    let n = u8_at(ep) as usize;
                    ep += 1;
                    skip2!(n, 1);
                    words!(1 + n.div_ceil(8));
                }
                111 => {
                    chksize!(4);
                    let n = u32_at(ep) as usize;
                    ep += 4;
                    if n > 65_535 * 4 {
                        return Err(error());
                    }
                    skip2!(n, 1);
                    words!(2 + n.div_ceil(8));
                }
                100 | 118 => {
                    chksize!(2);
                    let n = u16_at(ep) as usize;
                    ep += 2;
                    if (tag == 118 && n > 1020) || (tag == 100 && n > 255) {
                        return Err(error());
                    }
                    skip2!(n, atom_extra_skip);
                    atom_extra_skip = 0;
                }
                115 | 119 => {
                    chksize!(1);
                    let n = u8_at(ep) as usize;
                    ep += 1;
                    skip2!(n, atom_extra_skip);
                    atom_extra_skip = 0;
                }
                82 => {
                    skip2!(1, atom_extra_skip);
                    atom_extra_skip = 0;
                }
                73 => {
                    skip2!(2, atom_extra_skip);
                    atom_extra_skip = 0;
                }
                75 => {
                    skip2!(3, atom_extra_skip);
                    atom_extra_skip = 0;
                }
                103 | 88 | 102 | 89 | 120 => {
                    atom_extra_skip = match tag {
                        103 => 9,
                        88 => 12,
                        102 => 5,
                        89 => 8,
                        _ => 12,
                    };
                    addterms!(1usize);
                    words!(4);
                }
                101 | 114 | 90 => {
                    let (id_words, extra) = if tag == 101 {
                        (1usize, 5usize)
                    } else {
                        chksize!(2);
                        let n = u16_at(ep) as usize;
                        ep += 2;
                        if n > 5 {
                            return Err(error());
                        }
                        (n, if tag == 114 { 1 + n * 4 } else { 4 + n * 4 })
                    };
                    atom_extra_skip = extra;
                    words!(EXTERNAL_THING_HEAD_SIZE + id_words / 2 + 1);
                    addterms!(1usize);
                }
                106 => {
                    if atom_extra_skip != 0 {
                        if lext_hash.is_none() {
                            return Err(error());
                        }
                        skip!(atom_extra_skip);
                        atom_extra_skip = 0;
                    }
                }
                108 => {
                    chksize!(4);
                    let n = u32_at(ep) as usize;
                    ep += 4;
                    if n.checked_add(1).is_none_or(|count| count > endp - ep) {
                        return Err(error());
                    }
                    addterms!(n);
                    addterms!(1usize);
                    words!(n.checked_mul(2).ok_or_else(error)?);
                }
                104 | 105 => {
                    let n = if tag == 104 {
                        chksize!(1);
                        ep += 1;
                        u8_at(ep - 1) as usize
                    } else {
                        chksize!(4);
                        ep += 4;
                        u32_at(ep - 4) as usize
                    };
                    if n > (1 << 24) - 1 || n > endp - ep {
                        return Err(error());
                    }
                    addterms!(n);
                    if n > 0 {
                        words!(n + 1);
                    }
                }
                116 => {
                    chksize!(4);
                    let n = u32_at(ep) as usize;
                    ep += 4;
                    if n > (1 << 31) - 1 {
                        return Err(error());
                    }
                    let children = n.checked_mul(2).ok_or_else(error)?;
                    if children > endp - ep {
                        return Err(error());
                    }
                    if n <= SMALL_MAP_LIMIT {
                        words!(3 + n + usize::from(n > 0) * (1 + n));
                    } else {
                        words!(
                            n.checked_mul(3)
                                .and_then(|base| base.checked_add(n.saturating_mul(8) / 10))
                                .ok_or_else(error)?
                        );
                    }
                    addterms!(children);
                }
                107 => {
                    chksize!(2);
                    let n = u16_at(ep) as usize;
                    ep += 2;
                    skip!(n);
                    words!(n.checked_mul(2).ok_or_else(error)?);
                }
                99 => {
                    skip!(31);
                    words!(3);
                }
                70 => {
                    skip!(8);
                    words!(3);
                }
                109 => {
                    chksize!(4);
                    let n = u32_at(ep) as usize;
                    ep += 4;
                    skip!(n);
                    words!(if n <= ERL_ONHEAP_BIN_LIMIT {
                        2 + n.div_ceil(8)
                    } else {
                        8
                    });
                }
                77 => {
                    chksize!(5);
                    let n = u32_at(ep) as usize;
                    let bits = u8_at(ep + 4);
                    ep += 5;
                    if !(1..=8).contains(&bits) || n == 0 {
                        return Err(error());
                    }
                    skip!(n);
                    words!(if n <= ERL_ONHEAP_BIN_LIMIT {
                        2 + n.div_ceil(8)
                    } else {
                        8
                    });
                }
                113 => addterms!(3usize),
                112 => {
                    // The Size field is ignored by dec_term; it has historical OTP bugs.
                    chksize!(4 + 1 + 16 + 4 + 4);
                    let free = u32_at(ep + 25) as usize;
                    ep += 29;
                    if free > 255 {
                        return Err(error());
                    }
                    addterms!(4 + free);
                    words!(2 + free);
                }
                121 => {
                    chksize!(4);
                    let hash = u32_at(ep);
                    ep += 4;
                    if lext_hash.is_some() {
                        return Err(error());
                    }
                    lext_hash = Some((hash, ep));
                    lext_term_end = terms.checked_sub(1).ok_or_else(error)?;
                    addterms!(1usize);
                }
                67 => {
                    chksize!(4);
                    let n = u32_at(ep) as usize;
                    ep += 4;
                    let record_words = n
                        .checked_mul(2)
                        .and_then(|fields| fields.checked_add(8))
                        .ok_or_else(error)?;
                    skip!(1);
                    words!(record_words);
                    if n > 0 {
                        words!(n + 1);
                    }
                    addterms!(2usize);
                    addterms!(n);
                    addterms!(n);
                }
                _ => return Err(error()),
            }
            terms = terms.checked_sub(1).ok_or_else(error)?;
        }
        if terms == lext_term_end {
            let (expected, start) = lext_hash.ok_or_else(error)?;
            if ep <= start {
                return Err(error());
            }
            let walk =
                lext_state.get_or_insert_with(|| arinsal_bifs::BlockHashWalk::local(ep - start));
            // `chunk_len = reds`: the hash yields when the reductions run out.
            let (done, hashed) = walk.step(&bytes[start..ep], (*reds).max(0) as usize);
            if !done {
                // Yield: erts only zeroes `reds` here; the `--reds <= 0 && terms != 0` test
                // below saves the state, and a hash that is the last term is never checked.
                *reds = 0;
            } else {
                *reds -= hashed as i64;
                if walk.hash() != Some(expected) {
                    return Err(error());
                }
                lext_state = None;
                lext_hash = None;
                lext_term_end = u32::MAX;
            }
        }
        *reds -= 1;
        if *reds <= 0 && terms != 0 {
            *sc = B2tSizeState {
                lext_state,
                started: true,
                ep,
                atom_extra_skip,
                heap_size,
                lext_hash,
                lext_term_end,
                terms,
            };
            return Ok(None);
        }
        if terms == 0 {
            return Ok(Some(heap_size));
        }
    }
}
