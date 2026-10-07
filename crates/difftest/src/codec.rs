//! Small ETF codec for transport bootstrap. `full-etf` selects S0.5 instead.
use arinsal_etf::OwnedTerm;
#[cfg(not(feature = "full-etf"))]
use num_bigint::{BigInt, Sign};
#[cfg(not(feature = "full-etf"))]
use num_traits::ToPrimitive;

#[derive(Debug, thiserror::Error)]
pub enum CodecError {
    #[error("unsupported ETF term: {0}")]
    Unsupported(String),
    #[error("malformed ETF at byte {0}")]
    Malformed(usize),
}

#[cfg(feature = "full-etf")]
pub fn encode(term: &OwnedTerm) -> Result<Vec<u8>, CodecError> {
    Ok(arinsal_etf::encode(term, Default::default()))
}
#[cfg(feature = "full-etf")]
pub fn decode(bytes: &[u8]) -> Result<OwnedTerm, CodecError> {
    arinsal_etf::decode(bytes).map_err(|e| CodecError::Unsupported(e.to_string()))
}

#[cfg(not(feature = "full-etf"))]
pub fn encode(term: &OwnedTerm) -> Result<Vec<u8>, CodecError> {
    let mut out = vec![131];
    write_term(term, &mut out)?;
    Ok(out)
}
#[cfg(not(feature = "full-etf"))]
pub fn decode(bytes: &[u8]) -> Result<OwnedTerm, CodecError> {
    let mut r = Reader { bytes, at: 0 };
    if r.byte()? != 131 {
        return Err(CodecError::Malformed(0));
    }
    let term = r.term()?;
    if r.at != bytes.len() {
        return Err(CodecError::Malformed(r.at));
    }
    Ok(term)
}

#[cfg(not(feature = "full-etf"))]
fn write_atom(s: &str, out: &mut Vec<u8>) -> Result<(), CodecError> {
    let b = s.as_bytes();
    if b.len() < 256 {
        out.extend_from_slice(&[119, b.len() as u8]);
    } else if b.len() <= u16::MAX as usize {
        out.push(118);
        out.extend_from_slice(&(b.len() as u16).to_be_bytes());
    } else {
        return Err(CodecError::Unsupported(
            "atom longer than 65535 bytes".into(),
        ));
    }
    out.extend_from_slice(b);
    Ok(())
}

#[cfg(not(feature = "full-etf"))]
fn write_term(t: &OwnedTerm, out: &mut Vec<u8>) -> Result<(), CodecError> {
    match t {
        OwnedTerm::Int(i) if (0..=255).contains(i) => out.extend_from_slice(&[97, *i as u8]),
        OwnedTerm::Int(i) if i32::try_from(*i).is_ok() => {
            out.push(98);
            out.extend_from_slice(&(*i as i32).to_be_bytes());
        }
        OwnedTerm::Int(i) => write_big(&BigInt::from(*i), out),
        OwnedTerm::BigInt(i) => write_big(i, out),
        OwnedTerm::Float(f) => {
            out.push(70);
            out.extend_from_slice(&f.to_bits().to_be_bytes());
        }
        OwnedTerm::Atom(s) => write_atom(s, out)?,
        OwnedTerm::Nil => out.push(106),
        OwnedTerm::List { elems, tail } => {
            out.push(108);
            out.extend_from_slice(&(elems.len() as u32).to_be_bytes());
            for e in elems {
                write_term(e, out)?;
            }
            write_term(tail, out)?;
        }
        OwnedTerm::Tuple(xs) => {
            if xs.len() < 256 {
                out.extend_from_slice(&[104, xs.len() as u8]);
            } else {
                out.push(105);
                out.extend_from_slice(&(xs.len() as u32).to_be_bytes());
            }
            for x in xs {
                write_term(x, out)?;
            }
        }
        OwnedTerm::Map(xs) => {
            out.push(116);
            out.extend_from_slice(&(xs.len() as u32).to_be_bytes());
            for (k, v) in xs {
                write_term(k, out)?;
                write_term(v, out)?;
            }
        }
        OwnedTerm::Binary(b) => {
            out.push(109);
            out.extend_from_slice(&(b.len() as u32).to_be_bytes());
            out.extend_from_slice(b);
        }
        OwnedTerm::BitString { bytes, bits } => {
            out.push(77);
            out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
            out.push(*bits);
            out.extend_from_slice(bytes);
        }
        OwnedTerm::Pid {
            node,
            id,
            serial,
            creation,
        } => {
            out.push(88);
            write_atom(node, out)?;
            out.extend_from_slice(&id.to_be_bytes());
            out.extend_from_slice(&serial.to_be_bytes());
            out.extend_from_slice(&creation.to_be_bytes());
        }
        OwnedTerm::Port { node, id, creation } => {
            out.push(120);
            write_atom(node, out)?;
            out.extend_from_slice(&id.to_be_bytes());
            out.extend_from_slice(&creation.to_be_bytes());
        }
        OwnedTerm::Ref {
            node,
            creation,
            ids,
        } => {
            out.push(90);
            out.extend_from_slice(&(ids.len() as u16).to_be_bytes());
            write_atom(node, out)?;
            out.extend_from_slice(&creation.to_be_bytes());
            for id in ids {
                out.extend_from_slice(&id.to_be_bytes());
            }
        }
        OwnedTerm::Export {
            module,
            function,
            arity,
        } => {
            out.push(113);
            write_atom(module, out)?;
            write_atom(function, out)?;
            out.extend_from_slice(&[97, *arity]);
        }
        _ => return Err(CodecError::Unsupported(format!("{t:?}"))),
    }
    Ok(())
}
#[cfg(not(feature = "full-etf"))]
fn write_big(i: &BigInt, out: &mut Vec<u8>) {
    let (sign, bytes) = i.to_bytes_le();
    if bytes.len() < 256 {
        out.extend_from_slice(&[110, bytes.len() as u8]);
    } else {
        out.push(111);
        out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    }
    out.push(u8::from(sign == Sign::Minus));
    out.extend_from_slice(&bytes);
}

#[cfg(not(feature = "full-etf"))]
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}
#[cfg(not(feature = "full-etf"))]
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], CodecError> {
        let end = self
            .at
            .checked_add(n)
            .ok_or(CodecError::Malformed(self.at))?;
        let b = self
            .bytes
            .get(self.at..end)
            .ok_or(CodecError::Malformed(self.at))?;
        self.at = end;
        Ok(b)
    }
    fn byte(&mut self) -> Result<u8, CodecError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, CodecError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32, CodecError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn atom(&mut self) -> Result<String, CodecError> {
        let tag = self.byte()?;
        let len = match tag {
            119 | 115 => self.byte()? as usize,
            118 | 100 => self.u16()? as usize,
            _ => return Err(CodecError::Malformed(self.at - 1)),
        };
        let b = self.take(len)?;
        if tag == 115 || tag == 100 {
            Ok(b.iter().map(|&c| char::from(c)).collect())
        } else {
            String::from_utf8(b.to_vec()).map_err(|_| CodecError::Malformed(self.at - len))
        }
    }
    fn term(&mut self) -> Result<OwnedTerm, CodecError> {
        let tag = self.byte()?;
        Ok(match tag {
            97 => OwnedTerm::Int(self.byte()? as i64),
            98 => OwnedTerm::Int(i32::from_be_bytes(self.take(4)?.try_into().unwrap()) as i64),
            110 | 111 => {
                let n = if tag == 110 {
                    self.byte()? as usize
                } else {
                    self.u32()? as usize
                };
                let sign = if self.byte()? == 0 {
                    Sign::Plus
                } else {
                    Sign::Minus
                };
                let x = BigInt::from_bytes_le(sign, self.take(n)?);
                x.to_i64().map_or(OwnedTerm::BigInt(x), OwnedTerm::Int)
            }
            70 => OwnedTerm::Float(f64::from_bits(u64::from_be_bytes(
                self.take(8)?.try_into().unwrap(),
            ))),
            119 | 115 | 118 | 100 => {
                self.at -= 1;
                OwnedTerm::Atom(self.atom()?)
            }
            106 => OwnedTerm::Nil,
            107 => {
                let n = self.u16()? as usize;
                let xs = self
                    .take(n)?
                    .iter()
                    .map(|x| OwnedTerm::Int(*x as i64))
                    .collect();
                OwnedTerm::List {
                    elems: xs,
                    tail: Box::new(OwnedTerm::Nil),
                }
            }
            108 => {
                let n = self.u32()? as usize;
                let mut elems = Vec::with_capacity(n.min(100_000));
                for _ in 0..n {
                    elems.push(self.term()?);
                }
                let tail = Box::new(self.term()?);
                OwnedTerm::List { elems, tail }
            }
            104 | 105 => {
                let n = if tag == 104 {
                    self.byte()? as usize
                } else {
                    self.u32()? as usize
                };
                let mut xs = Vec::with_capacity(n.min(100_000));
                for _ in 0..n {
                    xs.push(self.term()?);
                }
                OwnedTerm::Tuple(xs)
            }
            116 => {
                let n = self.u32()? as usize;
                let mut xs = Vec::with_capacity(n.min(100_000));
                for _ in 0..n {
                    xs.push((self.term()?, self.term()?));
                }
                OwnedTerm::Map(xs)
            }
            109 => {
                let n = self.u32()? as usize;
                OwnedTerm::Binary(self.take(n)?.to_vec())
            }
            77 => {
                let n = self.u32()? as usize;
                let bits = self.byte()?;
                OwnedTerm::BitString {
                    bytes: self.take(n)?.to_vec(),
                    bits,
                }
            }
            88 => {
                let node = self.atom()?;
                let id = self.u32()?;
                let serial = self.u32()?;
                let creation = self.u32()?;
                OwnedTerm::Pid {
                    node,
                    id,
                    serial,
                    creation,
                }
            }
            120 => {
                let node = self.atom()?;
                let id = u64::from_be_bytes(self.take(8)?.try_into().unwrap());
                let creation = self.u32()?;
                OwnedTerm::Port { node, id, creation }
            }
            90 => {
                let n = self.u16()? as usize;
                let node = self.atom()?;
                let creation = self.u32()?;
                let mut ids = Vec::with_capacity(n);
                for _ in 0..n {
                    ids.push(self.u32()?);
                }
                OwnedTerm::Ref {
                    node,
                    creation,
                    ids,
                }
            }
            113 => {
                let module = self.atom()?;
                let function = self.atom()?;
                let arity = match self.term()? {
                    OwnedTerm::Int(n) if (0..=255).contains(&n) => n as u8,
                    _ => return Err(CodecError::Malformed(self.at)),
                };
                OwnedTerm::Export {
                    module,
                    function,
                    arity,
                }
            }
            _ => return Err(CodecError::Unsupported(format!("ETF tag {tag}"))),
        })
    }
}
