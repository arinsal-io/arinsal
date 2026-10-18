//! OTP 29.1.1 packet framing and `erlang:decode_packet/3`.

#![forbid(unsafe_code)]

mod parser;

pub use parser::{
    HTTP_HEADERS, HttpPacket, HttpUri, Packet, PacketOptions, PacketResult, PacketState,
    PacketType, parse, parse_with_state,
};

use std::sync::Arc;

use arinsal_bifs::{BifError, BifFn, Ctx, for_each_list_term, tuple_pair, with_binary_bytes};
use arinsal_etf::OwnedTerm as O;
use arinsal_term::{HeapAlloc, Node, Term, TermBuilder, atoms, from_owned};

/// `erlang:decode_packet/3`, callable without a name lookup.
pub const DECODE_PACKET_3: BifFn = decode_packet;

/// Return the `erlang:decode_packet/3` BIF implementation.
pub fn lookup(module: &str, name: &str, arity: u8) -> Option<BifFn> {
    (module == "erlang" && name == "decode_packet" && arity == 3).then_some(decode_packet)
}

struct Heap<'a, H: HeapAlloc + ?Sized>(&'a mut H);
impl<H: HeapAlloc + ?Sized> HeapAlloc for Heap<'_, H> {
    fn alloc(&mut self, words: usize) -> Option<*mut u64> {
        self.0.alloc(words)
    }
    // The sub binaries are `HAlloc`ed while the factory holds `HEAP_TOP == HEAP_LIMIT`, so they
    // always land in heap fragments.
    // Port of erts/emulator/beam/erl_bif_port.c (decode_packet_3, erts_factory_proc_init), OTP-29.1.1.
    fn alloc_fragment_only(&mut self, words: usize) -> Option<*mut u64> {
        self.0.alloc_fragment_only(words)
    }
    fn retain_binary(&mut self, value: Arc<arinsal_term::RefcBinary>) {
        self.0.retain_binary(value)
    }
    fn link_bin_ref(
        &mut self,
        bin_ref: *mut u64,
        writable: bool,
        overhead_words: u64,
        owner: Option<arinsal_term::OwnedBinaryRef>,
    ) -> Result<(), arinsal_term::TermError> {
        HeapAlloc::link_bin_ref(self.0, bin_ref, writable, overhead_words, owner)
    }
    fn retain_writable_binary(
        &mut self,
        value: Arc<arinsal_term::WritableBinary>,
    ) -> Result<(), arinsal_term::TermError> {
        self.0.retain_writable_binary(value)
    }
    fn supports_writable_binary(&self) -> bool {
        self.0.supports_writable_binary()
    }
    fn link_node(&mut self, thing: *mut u64, value: Arc<Node>) {
        self.0.link_node(thing, value)
    }
}

fn atom(s: &str) -> O {
    O::atom(s)
}
fn tuple(xs: Vec<O>) -> O {
    O::Tuple(xs)
}
fn byte_string(bytes: &[u8], binary: bool) -> O {
    if binary {
        O::Binary(bytes.to_vec())
    } else {
        O::list(bytes.iter().map(|b| O::Int(*b as i64)).collect())
    }
}
fn integer(value: Term) -> Option<u32> {
    u32::try_from(value.as_small()?).ok()
}
fn type_of(value: Term) -> Option<PacketType> {
    if let Some(number) = value.as_small() {
        return match number {
            0 => Some(PacketType::Raw),
            1 => Some(PacketType::Length1),
            2 => Some(PacketType::Length2),
            4 => Some(PacketType::Length4),
            _ => None,
        };
    }
    Some(match value.as_atom()? {
        atoms::RAW => PacketType::Raw,
        atoms::ASN1 => PacketType::Asn1,
        atoms::SUNRM => PacketType::Sunrm,
        atoms::CDR => PacketType::Cdr,
        atoms::FCGI => PacketType::Fcgi,
        atoms::LINE => PacketType::Line,
        atoms::TPKT => PacketType::Tpkt,
        atoms::HTTP => PacketType::Http,
        atoms::HTTPH => PacketType::Httph,
        atoms::HTTP_BIN => PacketType::HttpBin,
        atoms::HTTPH_BIN => PacketType::HttphBin,
        atoms::SSL_TLS => PacketType::SslTls,
        _ => return None,
    })
}
fn options(value: Term, ty: PacketType) -> Result<PacketOptions, BifError> {
    let mut result = PacketOptions::default();
    for_each_list_term(value, |item| {
        let (name, value) = tuple_pair(item).ok_or(BifError::BADARG)?;
        let name = name.as_atom().ok_or(BifError::BADARG)?;
        let n = integer(value).ok_or(BifError::BADARG)?;
        match name {
            atoms::PACKET_SIZE => result.packet_size = n,
            atoms::LINE_LENGTH => result.line_length = n,
            atoms::LINE_DELIMITER if ty == PacketType::Line && n <= 255 => {
                result.line_delimiter = n as u8
            }
            _ => return Err(BifError::BADARG),
        }
        Ok(())
    })?;
    Ok(result)
}

/// What `decode_packet` found in the binary, with the binary positions of the parts that
/// erts returns as sub-binaries of its argument.
enum Decoded {
    Invalid,
    More(Option<usize>),
    Packet {
        body: Body,
        rest_start: usize,
        rest_len: usize,
    },
}

enum Body {
    Sub { start: usize, len: usize },
    Term(O),
}

fn offset_of(data: &[u8], part: &[u8]) -> usize {
    (part.as_ptr() as usize).saturating_sub(data.as_ptr() as usize)
}

fn decode(data: &[u8], ty: PacketType, opts: PacketOptions) -> Decoded {
    match parse(ty, data, opts) {
        PacketResult::Error => Decoded::Invalid,
        PacketResult::More(length) => Decoded::More(length),
        PacketResult::Ok { packet, rest } => {
            let body = match packet {
                Packet::Bytes(bytes) => Body::Sub {
                    start: offset_of(data, bytes),
                    len: bytes.len(),
                },
                Packet::Http(http) => Body::Term(http_term(
                    http,
                    matches!(ty, PacketType::HttpBin | PacketType::HttphBin),
                )),
                Packet::SslTls {
                    content_type,
                    major,
                    minor,
                    data,
                } => Body::Term(tuple(vec![
                    atom("ssl_tls"),
                    O::Nil,
                    O::Int(content_type as i64),
                    tuple(vec![O::Int(major as i64), O::Int(minor as i64)]),
                    O::Binary(data),
                ])),
            };
            Decoded::Packet {
                body,
                rest_start: offset_of(data, rest),
                rest_len: rest.len(),
            }
        }
    }
}

// Port of erts/emulator/beam/erl_bif_port.c:1476 (decode_packet_3), OTP-29.1.1.
fn decode_packet(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let [ty, data, opts] = args else {
        return Err(BifError::BADARG);
    };
    let Some(ty) = type_of(*ty) else {
        return Err(BifError::Badarg {
            cause: Some(Term::atom(atoms::BADOPT)),
        });
    };
    let opts = options(*opts, ty)?;
    let decoded = with_binary_bytes(*data, |view| {
        if view.bit_len() % 8 != 0 {
            return None;
        }
        let (first, length) = (view.start_bit() / 8, view.bit_len() / 8);
        if view.start_bit() % 8 == 0 {
            return Some(decode(&view.bytes()[first..first + length], ty, opts));
        }
        let mut aligned = vec![0_u8; length];
        copy_bitstring_bytes(&mut aligned, view.bytes(), view.start_bit());
        Some(decode(&aligned, ty, opts))
    })?
    .ok_or(BifError::BADARG)?;
    let mut heap = Heap(&mut ctx.heap);
    let value = match decoded {
        Decoded::Invalid => TermBuilder::new(&mut heap)
            .tuple(&[Term::atom(atoms::ERROR), Term::atom(atoms::INVALID)]),
        Decoded::More(length) => match length {
            None => TermBuilder::new(&mut heap)
                .tuple(&[Term::atom(atoms::MORE), Term::atom(atoms::UNDEFINED)]),
            Some(n) => match Term::small(n as i64) {
                Some(small) => TermBuilder::new(&mut heap).tuple(&[Term::atom(atoms::MORE), small]),
                None => from_owned(&tuple(vec![atom("more"), O::Int(n as i64)]), &mut heap),
            },
        },
        Decoded::Packet {
            body,
            rest_start,
            rest_len,
        } => {
            let ok = Term::atom(atoms::OK);
            let body = match body {
                Body::Sub { start, len } => TermBuilder::new(&mut heap)
                    .sub_binary_bif(*data, start * 8, len * 8)
                    .map_err(|_| BifError::SystemLimit)?,
                Body::Term(term) => {
                    from_owned(&term, &mut heap).map_err(|_| BifError::SystemLimit)?
                }
            };
            let mut builder = TermBuilder::new(&mut heap);
            let rest = builder
                .sub_binary_bif(*data, rest_start * 8, rest_len * 8)
                .map_err(|_| BifError::SystemLimit)?;
            return builder
                .tuple(&[ok, body, rest])
                .map_err(|_| BifError::SystemLimit);
        }
    };
    value.map_err(|_| BifError::SystemLimit)
}

/// Copy `out.len()` whole bytes starting at bit `start_bit` of `source`.
fn copy_bitstring_bytes(out: &mut [u8], source: &[u8], start_bit: usize) {
    let (first, shift) = (start_bit / 8, start_bit % 8);
    for (index, byte) in out.iter_mut().enumerate() {
        let high = source[first + index] << shift;
        let low = source
            .get(first + index + 1)
            .map_or(0, |next| next >> (8 - shift));
        *byte = high | low;
    }
}

fn http_term(http: HttpPacket, binary: bool) -> O {
    match http {
        HttpPacket::Eoh => atom("http_eoh"),
        HttpPacket::Error(line) => tuple(vec![atom("http_error"), byte_string(&line, binary)]),
        HttpPacket::Response {
            major,
            minor,
            status,
            phrase,
        } => tuple(vec![
            atom("http_response"),
            tuple(vec![O::Int(major as i64), O::Int(minor as i64)]),
            O::Int(status as i64),
            byte_string(&phrase, binary),
        ]),
        HttpPacket::Request {
            method,
            known_method,
            uri,
            major,
            minor,
        } => {
            let method = if known_method {
                atom(std::str::from_utf8(&method).unwrap())
            } else {
                byte_string(&method, binary)
            };
            tuple(vec![
                atom("http_request"),
                method,
                uri_term(uri, binary),
                tuple(vec![O::Int(major as i64), O::Int(minor as i64)]),
            ])
        }
        HttpPacket::Header {
            index,
            known_name,
            name,
            original_name,
            value,
        } => {
            let name = if let Some(known) = known_name {
                atom(known)
            } else {
                byte_string(&name, binary)
            };
            tuple(vec![
                atom("http_header"),
                O::Int(index as i64),
                name,
                byte_string(&original_name, binary),
                byte_string(&value, binary),
            ])
        }
    }
}
fn uri_term(uri: HttpUri, binary: bool) -> O {
    match uri {
        HttpUri::Star => atom("*"),
        HttpUri::String(s) => byte_string(&s, binary),
        HttpUri::AbsPath(s) => tuple(vec![atom("abs_path"), byte_string(&s, binary)]),
        HttpUri::Scheme { scheme, rest } => tuple(vec![
            atom("scheme"),
            byte_string(&scheme, binary),
            byte_string(&rest, binary),
        ]),
        HttpUri::Absolute {
            scheme,
            host,
            port,
            path,
        } => tuple(vec![
            atom("absoluteURI"),
            atom(scheme),
            byte_string(&host, binary),
            port.map_or_else(|| atom("undefined"), |p| O::Int(p as i64)),
            byte_string(&path, binary),
        ]),
    }
}
