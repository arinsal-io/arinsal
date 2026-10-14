//! OTP 29.1.1 packet framing and `erlang:decode_packet/3`.

#![forbid(unsafe_code)]

mod parser;

pub use parser::{
    HTTP_HEADERS, HttpPacket, HttpUri, Packet, PacketOptions, PacketResult, PacketState,
    PacketType, parse, parse_with_state,
};

use std::sync::Arc;

use arinsal_bifs::{BifError, BifFn, Ctx};
use arinsal_etf::OwnedTerm as O;
use arinsal_term::{ExportEntry, FunEntry, HeapAlloc, Node, Term, from_owned, to_owned};
use num_traits::ToPrimitive;

/// Return the `erlang:decode_packet/3` BIF implementation.
pub fn lookup(module: &str, name: &str, arity: u8) -> Option<BifFn> {
    (module == "erlang" && name == "decode_packet" && arity == 3).then_some(decode_packet)
}

struct Heap<'a, H: HeapAlloc + ?Sized>(&'a mut H);
impl<H: HeapAlloc + ?Sized> HeapAlloc for Heap<'_, H> {
    fn alloc(&mut self, words: usize) -> Option<*mut u64> {
        self.0.alloc(words)
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
    fn retain_node(&mut self, value: Arc<Node>) {
        self.0.retain_node(value)
    }
    fn retain_fun(&mut self, value: Arc<FunEntry>) {
        self.0.retain_fun(value)
    }
    fn retain_export(&mut self, value: Arc<ExportEntry>) {
        self.0.retain_export(value)
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
fn integer(value: &O) -> Option<u32> {
    match value {
        O::Int(n) => u32::try_from(*n).ok(),
        O::BigInt(n) => n.to_u32(),
        _ => None,
    }
}
fn type_of(value: &O) -> Option<PacketType> {
    Some(match value {
        O::Int(0) => PacketType::Raw,
        O::Int(1) => PacketType::Length1,
        O::Int(2) => PacketType::Length2,
        O::Int(4) => PacketType::Length4,
        O::Atom(s) if s == "raw" => PacketType::Raw,
        O::Atom(s) if s == "asn1" => PacketType::Asn1,
        O::Atom(s) if s == "sunrm" => PacketType::Sunrm,
        O::Atom(s) if s == "cdr" => PacketType::Cdr,
        O::Atom(s) if s == "fcgi" => PacketType::Fcgi,
        O::Atom(s) if s == "line" => PacketType::Line,
        O::Atom(s) if s == "tpkt" => PacketType::Tpkt,
        O::Atom(s) if s == "http" => PacketType::Http,
        O::Atom(s) if s == "httph" => PacketType::Httph,
        O::Atom(s) if s == "http_bin" => PacketType::HttpBin,
        O::Atom(s) if s == "httph_bin" => PacketType::HttphBin,
        O::Atom(s) if s == "ssl_tls" => PacketType::SslTls,
        _ => return None,
    })
}
fn options(value: &O, ty: PacketType) -> Result<PacketOptions, BifError> {
    let mut result = PacketOptions::default();
    let O::List { elems, tail } = value else {
        return if *value == O::Nil {
            Ok(result)
        } else {
            Err(BifError::BADARG)
        };
    };
    if **tail != O::Nil {
        return Err(BifError::BADARG);
    }
    for item in elems {
        let O::Tuple(pair) = item else {
            return Err(BifError::BADARG);
        };
        let [O::Atom(name), value] = pair.as_slice() else {
            return Err(BifError::BADARG);
        };
        let n = integer(value).ok_or(BifError::BADARG)?;
        match name.as_str() {
            "packet_size" => result.packet_size = n,
            "line_length" => result.line_length = n,
            "line_delimiter" if ty == PacketType::Line && n <= 255 => {
                result.line_delimiter = n as u8
            }
            _ => return Err(BifError::BADARG),
        }
    }
    Ok(result)
}

// Port of erts/emulator/beam/erl_bif_port.c:1476 (decode_packet_3), OTP-29.1.1.
fn decode_packet(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let [ty, data, opts] = args else {
        return Err(BifError::BADARG);
    };
    let ty = to_owned(*ty).map_err(|_| BifError::BADARG)?;
    let Some(ty) = type_of(&ty) else {
        let cause = from_owned(&atom("badopt"), &mut Heap(&mut ctx.heap))
            .map_err(|_| BifError::SystemLimit)?;
        return Err(BifError::Badarg { cause: Some(cause) });
    };
    let data = to_owned(*data).map_err(|_| BifError::BADARG)?;
    let opts = to_owned(*opts).map_err(|_| BifError::BADARG)?;
    let O::Binary(ref data) = data else {
        return Err(BifError::BADARG);
    };
    let opts = options(&opts, ty)?;
    let value = match parse(ty, data, opts) {
        PacketResult::Error => tuple(vec![atom("error"), atom("invalid")]),
        PacketResult::More(length) => tuple(vec![
            atom("more"),
            length.map_or_else(|| atom("undefined"), |n| O::Int(n as i64)),
        ]),
        PacketResult::Ok { packet, rest } => {
            let packet = match packet {
                Packet::Bytes(bytes) => O::Binary(bytes.to_vec()),
                Packet::Http(http) => http_term(
                    http,
                    matches!(ty, PacketType::HttpBin | PacketType::HttphBin),
                ),
                Packet::SslTls {
                    content_type,
                    major,
                    minor,
                    data,
                } => tuple(vec![
                    atom("ssl_tls"),
                    O::Nil,
                    O::Int(content_type as i64),
                    tuple(vec![O::Int(major as i64), O::Int(minor as i64)]),
                    O::Binary(data),
                ]),
            };
            tuple(vec![atom("ok"), packet, O::Binary(rest.to_vec())])
        }
    };
    from_owned(&value, &mut Heap(&mut ctx.heap)).map_err(|_| BifError::SystemLimit)
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
