//! Byte-oriented port of `packet_parser.c`, OTP-29.1.1.

/// Packet framing and protocol mode used by `inet_drv` and `decode_packet/3`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketType {
    Raw,
    Length1,
    Length2,
    Length4,
    Asn1,
    Sunrm,
    Cdr,
    Fcgi,
    Line,
    Tpkt,
    Http,
    Httph,
    HttpBin,
    HttphBin,
    SslTls,
}

/// Length limits and line delimiter. Zero disables a limit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketOptions {
    pub packet_size: u32,
    pub line_length: u32,
    pub line_delimiter: u8,
}

impl Default for PacketOptions {
    fn default() -> Self {
        Self {
            packet_size: 0,
            line_length: 0,
            line_delimiter: b'\n',
        }
    }
}

/// Parsed result, with the unconsumed suffix borrowing the input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PacketResult<'a> {
    Ok { packet: Packet<'a>, rest: &'a [u8] },
    More(Option<usize>),
    Error,
}

/// HTTP parsing state retained between packets on a stream.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PacketState {
    http_headers: bool,
}

/// A framed packet body or a decoded protocol event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Packet<'a> {
    Bytes(&'a [u8]),
    Http(HttpPacket),
    SslTls {
        content_type: u8,
        major: u8,
        minor: u8,
        data: Vec<u8>,
    },
}

/// URI form recognized by the OTP HTTP parser.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HttpUri {
    Star,
    String(Vec<u8>),
    AbsPath(Vec<u8>),
    Scheme {
        scheme: Vec<u8>,
        rest: Vec<u8>,
    },
    Absolute {
        scheme: &'static str,
        host: Vec<u8>,
        port: Option<i32>,
        path: Vec<u8>,
    },
}

/// One HTTP start line, header line, or end of headers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HttpPacket {
    Request {
        method: Vec<u8>,
        known_method: bool,
        uri: HttpUri,
        major: i32,
        minor: i32,
    },
    Response {
        major: i32,
        minor: i32,
        status: i32,
        phrase: Vec<u8>,
    },
    Header {
        index: usize,
        known_name: Option<&'static str>,
        name: Vec<u8>,
        original_name: Vec<u8>,
        value: Vec<u8>,
    },
    Eoh,
    Error(Vec<u8>),
}

/// Canonical HTTP names in the exact OTP bit index order.
pub const HTTP_HEADERS: &[&str] = &[
    "Cache-Control",
    "Connection",
    "Date",
    "Pragma",
    "Transfer-Encoding",
    "Upgrade",
    "Via",
    "Accept",
    "Accept-Charset",
    "Accept-Encoding",
    "Accept-Language",
    "Authorization",
    "From",
    "Host",
    "If-Modified-Since",
    "If-Match",
    "If-None-Match",
    "If-Range",
    "If-Unmodified-Since",
    "Max-Forwards",
    "Proxy-Authorization",
    "Range",
    "Referer",
    "User-Agent",
    "Age",
    "Location",
    "Proxy-Authenticate",
    "Public",
    "Retry-After",
    "Server",
    "Vary",
    "Warning",
    "Www-Authenticate",
    "Allow",
    "Content-Base",
    "Content-Encoding",
    "Content-Language",
    "Content-Length",
    "Content-Location",
    "Content-Md5",
    "Content-Range",
    "Content-Type",
    "Etag",
    "Expires",
    "Last-Modified",
    "Accept-Ranges",
    "Set-Cookie",
    "Set-Cookie2",
    "X-Forwarded-For",
    "Cookie",
    "Keep-Alive",
    "Proxy-Connection",
];

const HTTP_METHODS: &[&[u8]] = &[
    b"OPTIONS", b"GET", b"HEAD", b"POST", b"PUT", b"DELETE", b"TRACE",
];

/// Decode one packet from a byte slice, preserving any remaining bytes.
pub fn parse<'a>(ty: PacketType, bytes: &'a [u8], opts: PacketOptions) -> PacketResult<'a> {
    parse_with_state(ty, bytes, opts, &mut PacketState::default())
}

/// Decode one packet while retaining HTTP request/header state for the next call.
pub fn parse_with_state<'a>(
    ty: PacketType,
    bytes: &'a [u8],
    opts: PacketOptions,
    state: &mut PacketState,
) -> PacketResult<'a> {
    if matches!(ty, PacketType::Httph | PacketType::HttphBin) {
        state.http_headers = true;
    }
    let len = match packet_length(ty, bytes, opts, state.http_headers) {
        Ok(Some(n)) if n <= bytes.len() => n,
        Ok(value) => return PacketResult::More(value),
        Err(()) => return PacketResult::Error,
    };
    let frame = &bytes[..len];
    let body = match ty {
        PacketType::Length1 => &frame[1..],
        PacketType::Length2 => &frame[2..],
        PacketType::Length4 => &frame[4..],
        PacketType::Fcgi => &frame[..len - frame[6] as usize],
        _ => frame,
    };
    let packet = match ty {
        PacketType::Http | PacketType::Httph | PacketType::HttpBin | PacketType::HttphBin => {
            let http = parse_http(frame, state.http_headers);
            match http {
                HttpPacket::Request { .. } | HttpPacket::Response { .. } => {
                    state.http_headers = true;
                }
                HttpPacket::Eoh => state.http_headers = false,
                _ => {}
            }
            Packet::Http(http)
        }
        PacketType::SslTls => {
            if frame[0] & 0x80 != 0 && frame[2] == 1 {
                let mut data = vec![1, 0, 0, 0];
                let n = (len - 3) as u32;
                data[1..4].copy_from_slice(&n.to_be_bytes()[1..]);
                data.extend_from_slice(&frame[3..]);
                Packet::SslTls {
                    content_type: 22,
                    major: frame[3],
                    minor: frame[4],
                    data,
                }
            } else {
                Packet::SslTls {
                    content_type: frame[0],
                    major: frame[1],
                    minor: frame[2],
                    data: frame[5..].to_vec(),
                }
            }
        }
        _ => Packet::Bytes(body),
    };
    PacketResult::Ok {
        packet,
        rest: &bytes[len..],
    }
}

// Port of erts/emulator/beam/packet_parser.c:266 (packet_get_length), OTP-29.1.1.
fn packet_length(
    ty: PacketType,
    bytes: &[u8],
    opts: PacketOptions,
    http_headers: bool,
) -> Result<Option<usize>, ()> {
    let n = bytes.len();
    let max = opts.packet_size as usize;
    let fixed = match ty {
        PacketType::Raw => return Ok((n > 0).then_some(n)),
        PacketType::Length1 => Some(1),
        PacketType::Length2 => Some(2),
        PacketType::Length4 | PacketType::Sunrm => Some(4),
        PacketType::Cdr => Some(12),
        PacketType::Fcgi => Some(8),
        PacketType::Tpkt => Some(4),
        PacketType::SslTls => Some(5),
        _ => None,
    };
    if let Some(header) = fixed {
        if n < header {
            return Ok(None);
        }
        let payload = match ty {
            PacketType::Length1 => bytes[0] as usize,
            PacketType::Length2 => u16::from_be_bytes([bytes[0], bytes[1]]) as usize,
            PacketType::Length4 | PacketType::Sunrm => {
                let value = u32::from_be_bytes(bytes[..4].try_into().unwrap());
                (if ty == PacketType::Sunrm {
                    value & 0x7fff_ffff
                } else {
                    value
                }) as usize
            }
            PacketType::Cdr => {
                if &bytes[..4] != b"GIOP" {
                    return Err(());
                }
                let sz: [u8; 4] = bytes[8..12].try_into().unwrap();
                if bytes[6] & 1 != 0 {
                    u32::from_le_bytes(sz) as usize
                } else {
                    u32::from_be_bytes(sz) as usize
                }
            }
            PacketType::Fcgi => {
                if bytes[0] != 1 {
                    return Err(());
                }
                u16::from_be_bytes([bytes[4], bytes[5]]) as usize + bytes[6] as usize
            }
            PacketType::Tpkt => {
                if bytes[0] != 3 {
                    return Err(());
                }
                let total = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
                total.checked_sub(4).ok_or(())?
            }
            PacketType::SslTls => {
                if bytes[0] & 0x80 != 0 && bytes[2] == 1 {
                    (u16::from_be_bytes([bytes[0], bytes[1]]) as usize & 0x7fff)
                        .checked_sub(3)
                        .ok_or(())?
                } else {
                    u16::from_be_bytes([bytes[3], bytes[4]]) as usize
                }
            }
            _ => unreachable!(),
        };
        if payload
            > if max == 0 {
                i32::MAX as usize - header
            } else {
                max
            }
        {
            return Err(());
        }
        return Ok(Some(header + payload));
    }
    match ty {
        PacketType::Line => {
            let end = bytes
                .iter()
                .position(|b| *b == opts.line_delimiter)
                .map(|x| x + 1);
            if let Some(len) = end {
                if max != 0 && len > max {
                    return Err(());
                }
                Ok(Some(if opts.line_length != 0 {
                    len.min(opts.line_length as usize)
                } else {
                    len
                }))
            } else if max != 0 && n > max {
                Err(())
            } else if opts.line_length != 0 && n >= opts.line_length as usize {
                Ok(Some(opts.line_length as usize))
            } else {
                Ok(None)
            }
        }
        PacketType::Asn1 => asn1_length(bytes, max),
        PacketType::Http | PacketType::Httph | PacketType::HttpBin | PacketType::HttphBin => {
            let header = http_headers;
            let max = if max == 0 {
                opts.line_length as usize
            } else {
                max
            };
            if bytes == b"\n" || bytes == b"\r\n" {
                return Ok(Some(n));
            }
            let mut start = 0;
            loop {
                let Some(rel) = bytes[start..].iter().position(|b| *b == b'\n') else {
                    return if max != 0 && n >= max {
                        Err(())
                    } else {
                        Ok(None)
                    };
                };
                let end = start + rel + 1;
                if !header || end < n && !(end > 2 && matches!(bytes[end], b' ' | b'\t')) {
                    return if max != 0 && end > max {
                        Err(())
                    } else {
                        Ok(Some(end))
                    };
                }
                if max != 0 && end > max {
                    return Err(());
                }
                if end == n {
                    return Ok(None);
                }
                start = end;
            }
        }
        _ => unreachable!(),
    }
}

fn asn1_length(bytes: &[u8], max: usize) -> Result<Option<usize>, ()> {
    if bytes.len() < 2 {
        return Ok(None);
    }
    let mut pos = 1;
    if bytes[0] & 0x1f == 0x1f {
        while pos < bytes.len() && bytes[pos] & 0x80 != 0 {
            pos += 1;
        }
        if bytes.len() < pos + 2 {
            return Ok(None);
        }
        pos += 1;
    }
    let length = bytes[pos];
    pos += 1;
    let payload = if length & 0x80 == 0 {
        (length & 0x7f) as usize
    } else {
        let count = (length & 0x7f) as usize;
        if bytes.len() < pos + count {
            return Ok(None);
        }
        if count > 4 {
            return Err(());
        }
        let mut value = 0usize;
        for byte in &bytes[pos..pos + count] {
            value = value << 8 | *byte as usize;
        }
        pos += count;
        value
    };
    if payload
        > if max == 0 {
            i32::MAX as usize - pos
        } else {
            max
        }
    {
        return Err(());
    }
    Ok(Some(pos + payload))
}

fn space(c: u8) -> bool {
    c == b' ' || c == b'\t'
}
fn digit(c: u8) -> bool {
    c.is_ascii_digit()
}
fn special(c: u8) -> bool {
    !(33..127).contains(&c) || b"()<>@,;:\\\"/[]?={} \t".contains(&c)
}
fn number(bytes: &[u8], pos: &mut usize) -> Option<i32> {
    let start = *pos;
    let mut n = 0i32;
    while *pos < bytes.len() && digit(bytes[*pos]) {
        n = n.wrapping_mul(10).wrapping_add((bytes[*pos] - b'0') as i32);
        *pos += 1;
    }
    (*pos > start).then_some(n)
}
fn spaces(bytes: &[u8], pos: &mut usize) -> bool {
    let start = *pos;
    while *pos < bytes.len() && space(bytes[*pos]) {
        *pos += 1;
    }
    *pos > start
}

// Port of erts/emulator/beam/packet_parser.c:645 (packet_parse_http), OTP-29.1.1.
fn parse_http(frame: &[u8], header: bool) -> HttpPacket {
    let mut line = frame;
    if line.len() >= 2 && line[line.len() - 2] == b'\r' {
        line = &line[..line.len() - 2];
    } else if line.last() == Some(&b'\n') {
        line = &line[..line.len() - 1];
    }
    let parsed = if header {
        parse_header(line)
    } else if line.starts_with(b"HTTP/") {
        parse_response(line)
    } else {
        parse_request(line)
    };
    parsed.unwrap_or_else(|| HttpPacket::Error(frame.to_vec()))
}

fn parse_response(line: &[u8]) -> Option<HttpPacket> {
    let mut pos = 5;
    let major = number(line, &mut pos)?;
    if line.get(pos) != Some(&b'.') {
        return None;
    }
    pos += 1;
    let minor = number(line, &mut pos)?;
    if !spaces(line, &mut pos) {
        return None;
    }
    let status = number(line, &mut pos).unwrap_or(0);
    if !spaces(line, &mut pos) && pos < line.len() {
        return None;
    }
    Some(HttpPacket::Response {
        major,
        minor,
        status,
        phrase: line[pos..].to_vec(),
    })
}

fn parse_request(line: &[u8]) -> Option<HttpPacket> {
    let mut pos = 0;
    while pos < line.len() && !special(line[pos]) {
        pos += 1;
    }
    if pos == 0 || pos == line.len() || !space(line[pos]) {
        return None;
    }
    let method = line[..pos].to_vec();
    let known_method = HTTP_METHODS.contains(&method.as_slice());
    spaces(line, &mut pos);
    let uri_start = pos;
    while pos < line.len() && !space(line[pos]) {
        pos += 1;
    }
    if pos == uri_start {
        return None;
    }
    let uri = parse_uri(&line[uri_start..pos]);
    spaces(line, &mut pos);
    if pos == line.len() {
        return Some(HttpPacket::Request {
            method,
            known_method,
            uri,
            major: 0,
            minor: 9,
        });
    }
    if line.len() - pos < 8 || !line[pos..].starts_with(b"HTTP/") {
        return None;
    }
    pos += 5;
    let major = number(line, &mut pos)?;
    if line.get(pos) != Some(&b'.') {
        return None;
    }
    pos += 1;
    let minor = number(line, &mut pos)?;
    Some(HttpPacket::Request {
        method,
        known_method,
        uri,
        major,
        minor,
    })
}

fn parse_header(line: &[u8]) -> Option<HttpPacket> {
    if line.is_empty() {
        return Some(HttpPacket::Eoh);
    }
    let mut pos = 0;
    let mut canonical = Vec::new();
    let mut upper = true;
    while pos < line.len() && !special(line[pos]) {
        if canonical.len() < 50 {
            let c = line[pos];
            let c = if upper {
                upper = false;
                c.to_ascii_uppercase()
            } else if c.is_ascii_uppercase() {
                c.to_ascii_lowercase()
            } else {
                if c == b'-' {
                    upper = true;
                }
                c
            };
            canonical.push(c);
        }
        pos += 1;
    }
    if line.get(pos) != Some(&b':') {
        return None;
    }
    let original_name = line[..pos].to_vec();
    let name = if pos > 50 {
        original_name.clone()
    } else {
        canonical
    };
    let (index, known_name) = HTTP_HEADERS
        .iter()
        .enumerate()
        .find(|(_, s)| s.as_bytes() == name.as_slice())
        .map_or((0, None), |(i, s)| (i + 1, Some(*s)));
    pos += 1;
    spaces(line, &mut pos);
    Some(HttpPacket::Header {
        index,
        known_name,
        name,
        original_name,
        value: line[pos..].to_vec(),
    })
}

// Port of erts/emulator/beam/packet_parser.c:512 (http_parse_uri), OTP-29.1.1.
fn parse_uri(uri: &[u8]) -> HttpUri {
    if uri == b"*" {
        return HttpUri::Star;
    }
    if uri.len() <= 1 || uri[0] == b'/' {
        return HttpUri::AbsPath(uri.to_vec());
    }
    if uri.len() >= 7 && uri[..7].eq_ignore_ascii_case(b"http://") {
        return absolute_uri("http", &uri[7..]);
    }
    if uri.len() >= 8 && uri[..8].eq_ignore_ascii_case(b"https://") {
        return absolute_uri("https", &uri[8..]);
    }
    if let Some(colon) = uri.iter().position(|b| *b == b':') {
        HttpUri::Scheme {
            scheme: uri[..colon].to_vec(),
            rest: uri[colon + 1..].to_vec(),
        }
    } else {
        HttpUri::String(uri.to_vec())
    }
}

// Port of erts/emulator/beam/packet_parser.c:478 (http_parse_absoluteURI), OTP-29.1.1.
fn absolute_uri(scheme: &'static str, uri: &[u8]) -> HttpUri {
    let host_end = uri.iter().position(|b| *b == b'/').unwrap_or(uri.len());
    let authority = &uri[..host_end];
    let path = if host_end == uri.len() {
        b"/".to_vec()
    } else {
        uri[host_end..].to_vec()
    };
    let mut host_end = authority.len();
    let mut port = None;
    if let Some(colon) = authority.iter().position(|b| *b == b':') {
        if authority.first() == Some(&b'[') {
            if let Some(close) = authority.iter().position(|b| *b == b']') {
                host_end = close + 1;
                if authority.get(close + 1) == Some(&b':')
                    && authority.iter().rposition(|b| *b == b':') == Some(close + 1)
                {
                    port = parse_port(&authority[close + 2..]);
                }
            } else {
                host_end = colon;
            }
        } else {
            host_end = colon;
            port = parse_port(&authority[colon + 1..]);
        }
    }
    HttpUri::Absolute {
        scheme,
        host: authority[..host_end].to_vec(),
        port,
        path,
    }
}

fn parse_port(bytes: &[u8]) -> Option<i32> {
    if bytes.iter().all(|b| digit(*b)) {
        let mut port = 0i32;
        for byte in bytes {
            port = port.wrapping_mul(10).wrapping_add((byte - b'0') as i32);
        }
        if port != 0 {
            return Some(port);
        }
    }
    None
}
