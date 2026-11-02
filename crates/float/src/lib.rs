//! Erlang/OTP 29.1.1 float conversion without VM term dependencies.

#![forbid(unsafe_code)]

use std::fmt::Write;

/// Size of the stack buffer used by the float formatting BIFs in erts.
pub const FLOAT_BUFFER_SIZE: usize = 256;

/// The final format selector in an Erlang float option list.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum FloatNotation {
    /// Equivalent to an empty option list.
    #[default]
    ScientificDefault,
    /// Scientific notation with the given fractional digit count.
    Scientific(u16),
    /// Fixed notation with the given fractional digit count.
    Decimals(u16),
    /// The shortest round-trip representation.
    Short,
}

/// Options for `float_to_list/2`; later format selectors replace earlier ones in erts.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FloatFormatOpts {
    /// The selected notation.
    pub notation: FloatNotation,
    /// Trim trailing zeroes when using fixed notation.
    pub compact: bool,
}

/// Error equivalent to `badarg` from float formatting BIFs.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum FloatFormatError {
    /// The float is nonfinite or the requested output cannot fit in the erts buffer.
    #[error("badarg")]
    BadArg,
}

/// Error equivalent to `badarg` from float parsing BIFs.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ParseError {
    /// The input is not an Erlang float or overflows to infinity.
    #[error("badarg")]
    BadArg,
}

/// Format a float as `erlang:float_to_list/2` does in OTP 29.1.1.
pub fn float_to_list(f: f64, opts: &FloatFormatOpts) -> Result<String, FloatFormatError> {
    let mut buffer = [0_u8; FLOAT_BUFFER_SIZE];
    let len = float_to_buffer(f, opts, &mut buffer)?;
    Ok(std::str::from_utf8(&buffer[..len])
        .expect("float formatting is ASCII")
        .to_owned())
}

/// Format a float into the caller's erts-sized stack buffer and return the byte count.
pub fn float_to_buffer(
    f: f64,
    opts: &FloatFormatOpts,
    buffer: &mut [u8; FLOAT_BUFFER_SIZE],
) -> Result<usize, FloatFormatError> {
    // Port of erts/emulator/beam/bif.c (do_float_to_charbuf), OTP-29.1.1.
    if !f.is_finite() {
        return Err(FloatFormatError::BadArg);
    }
    match opts.notation {
        FloatNotation::Short => shortest_into(f, buffer),
        FloatNotation::ScientificDefault => scientific_into(f, 20, buffer),
        FloatNotation::Scientific(d) if d <= 249 => scientific_into(f, usize::from(d), buffer),
        FloatNotation::Decimals(d) if d <= 253 => {
            fixed_into(f, usize::from(d), opts.compact, buffer)
        }
        _ => Err(FloatFormatError::BadArg),
    }
}

struct BufferWriter<'a> {
    bytes: &'a mut [u8; FLOAT_BUFFER_SIZE],
    len: usize,
}

impl BufferWriter<'_> {
    fn new(bytes: &mut [u8; FLOAT_BUFFER_SIZE]) -> BufferWriter<'_> {
        BufferWriter { bytes, len: 0 }
    }

    fn bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    fn truncate(&mut self, len: usize) {
        self.len = len;
    }

    fn push(&mut self, byte: u8) -> Result<(), FloatFormatError> {
        if self.len + 1 >= self.bytes.len() {
            return Err(FloatFormatError::BadArg);
        }
        self.bytes[self.len] = byte;
        self.len += 1;
        Ok(())
    }

    fn finish(self) -> Result<usize, FloatFormatError> {
        if self.len >= self.bytes.len() {
            return Err(FloatFormatError::BadArg);
        }
        self.bytes[self.len] = 0;
        Ok(self.len)
    }

    fn trim_compact(&mut self) {
        while self.len != 0 && self.bytes[self.len - 1] == b'0' {
            self.len -= 1;
        }
        if self.len != 0 && self.bytes[self.len - 1] == b'.' {
            self.bytes[self.len] = b'0';
            self.len += 1;
        }
    }
}

impl std::fmt::Write for BufferWriter<'_> {
    fn write_str(&mut self, text: &str) -> std::fmt::Result {
        let end = self.len.checked_add(text.len()).ok_or(std::fmt::Error)?;
        if end >= self.bytes.len() {
            return Err(std::fmt::Error);
        }
        self.bytes[self.len..end].copy_from_slice(text.as_bytes());
        self.len = end;
        Ok(())
    }
}

fn scientific_into(
    f: f64,
    decimals: usize,
    buffer: &mut [u8; FLOAT_BUFFER_SIZE],
) -> Result<usize, FloatFormatError> {
    // Port of erts/emulator/sys/unix/sys_float.c:55 (sys_double_to_chars_ext), OTP-29.1.1.
    let mut out = BufferWriter::new(buffer);
    write!(&mut out, "{f:.decimals$e}").map_err(|_| FloatFormatError::BadArg)?;
    let e = out
        .bytes()
        .iter()
        .rposition(|&byte| byte == b'e')
        .expect("Rust scientific format");
    let exponent = std::str::from_utf8(&out.bytes()[e + 1..])
        .expect("Rust scientific exponent is ASCII")
        .parse::<i32>()
        .expect("Rust scientific exponent");
    out.truncate(e);
    write!(&mut out, "e{exponent:+03}").map_err(|_| FloatFormatError::BadArg)?;
    out.finish()
}

const POW10: [f64; 19] = [
    1e0, 1e1, 1e2, 1e3, 1e4, 1e5, 1e6, 1e7, 1e8, 1e9, 1e10, 1e11, 1e12, 1e13, 1e14, 1e15, 1e16,
    1e17, 1e18,
];

fn fixed_into(
    f: f64,
    decimals: usize,
    compact: bool,
    buffer: &mut [u8; FLOAT_BUFFER_SIZE],
) -> Result<usize, FloatFormatError> {
    // Port of erts/emulator/sys/common/erl_sys_common_misc.c:161
    // (sys_double_to_chars_fast), OTP-29.1.1.
    let af = f.abs();
    let has_decimals = decimals != 0;
    let mut out = BufferWriter::new(buffer);
    if af > 9_007_199_254_740_992.0 || decimals >= POW10.len() {
        write!(&mut out, "{f:.decimals$}").map_err(|_| FloatFormatError::BadArg)?;
        if compact {
            out.trim_compact();
        }
    } else {
        let mut int_part;
        let mut frac_part = 0_u64;
        if decimals != 0 {
            let int_f = af.floor();
            let frac_f = ((af - int_f) * POW10[decimals]).round();
            int_part = int_f as u64;
            frac_part = frac_f as u64;
            if frac_f >= POW10[decimals] {
                int_part += 1;
                frac_part = 0;
            }
        } else {
            int_part = af.round() as u64;
        }

        if has_decimals {
            if frac_part == 0 {
                for _ in 0..decimals {
                    out.push(b'0')?;
                }
            } else {
                for _ in 0..decimals {
                    let quotient = frac_part / 10;
                    out.push((frac_part - quotient * 10) as u8 + b'0')?;
                    frac_part = quotient;
                }
            }
            out.push(b'.')?;
        }

        if int_part == 0 {
            out.push(b'0')?;
        } else {
            while int_part != 0 {
                let quotient = int_part / 10;
                out.push((int_part - quotient * 10) as u8 + b'0')?;
                int_part = quotient;
            }
        }
        if f.is_sign_negative() {
            out.push(b'-')?;
        }

        out.bytes[..out.len].reverse();
        if compact && has_decimals {
            out.trim_compact();
        }
    }
    out.finish()
}

/// Format the shortest round-trip float used by `io_lib_format:fwrite_g/1`.
pub fn format_shortest(f: f64) -> String {
    let mut buffer = [0_u8; FLOAT_BUFFER_SIZE];
    let len = shortest_into(f, &mut buffer).expect("shortest float fits the erts buffer");
    std::str::from_utf8(&buffer[..len])
        .expect("float formatting is ASCII")
        .to_owned()
}

fn shortest_into(f: f64, buffer: &mut [u8; FLOAT_BUFFER_SIZE]) -> Result<usize, FloatFormatError> {
    // Port of erts/emulator/ryu/to_chars.h:36 (to_chars), OTP-29.1.1.
    // Ryu supplies the shortest decimal; OTP's modified layout chooses fixed
    // or scientific form and requires a fractional digit in either form.
    let mut out = BufferWriter::new(buffer);
    if !f.is_finite() {
        out.write_str(ryu::Buffer::new().format(f))
            .map_err(|_| FloatFormatError::BadArg)?;
        return out.finish();
    }
    if f == 0.0 {
        out.write_str(if f.is_sign_negative() { "-0.0" } else { "0.0" })
            .map_err(|_| FloatFormatError::BadArg)?;
        return out.finish();
    }
    let mut buf = ryu::Buffer::new();
    let raw = buf.format_finite(f);
    // Ryū's scientific form with a fractional significand already matches
    // the OTP layout; only fixed forms and one-digit significands need work.
    if raw.contains('e') && raw.contains('.') {
        out.write_str(raw).map_err(|_| FloatFormatError::BadArg)?;
        return out.finish();
    }
    let negative = raw.starts_with('-');
    let raw = raw.trim_start_matches('-');
    let (base, exp) = match raw.split_once(['e', 'E']) {
        Some((base, exp)) => (base, exp.parse::<i32>().expect("Ryu exponent")),
        None => (raw, 0),
    };
    let mut digits = [0_u8; 32];
    let mut n = 0;
    let mut point = 0_i32;
    let mut after_point = false;
    for b in base.bytes() {
        if b == b'.' {
            after_point = true;
        } else {
            assert!(n < digits.len(), "Ryu output {raw}");
            digits[n] = b;
            n += 1;
            if !after_point {
                point += 1;
            }
        }
    }
    let leading = digits[..n].iter().position(|&b| b != b'0').unwrap_or(n);
    let mut exponent = exp + point - n as i32;
    if leading > 0 {
        digits.copy_within(leading..n, 0);
        n -= leading;
    }
    while n > 1 && digits[n - 1] == b'0' {
        n -= 1;
        exponent += 1;
    }
    let scientific_exponent = exponent + n as i32 - 1;
    let lower = if n == 1 { -4 } else { -(n as i32 + 2) };
    let upper = if n == 1 || scientific_exponent >= 10 {
        2
    } else {
        1
    };
    let mantissa = digits[..n]
        .iter()
        .fold(0_u64, |v, &d| v * 10 + u64::from(d - b'0'));
    let force_scientific = (mantissa >= (1_u64 << 53) && exponent == 0)
        || (mantissa > (1_u64 << 52) / 5 && exponent == 1)
        || (mantissa > (1_u64 << 51) / 25 && exponent == 2);
    if negative {
        out.push(b'-')?;
    }
    if exponent >= lower && exponent <= upper && !force_scientific {
        let whole = n as i32 + exponent;
        if exponent >= 0 {
            for &digit in &digits[..n] {
                out.push(digit)?;
            }
            for _ in 0..exponent {
                out.push(b'0')?;
            }
            out.write_str(".0").map_err(|_| FloatFormatError::BadArg)?;
        } else if whole > 0 {
            for &digit in &digits[..whole as usize] {
                out.push(digit)?;
            }
            out.push(b'.')?;
            for &digit in &digits[whole as usize..n] {
                out.push(digit)?;
            }
        } else {
            out.write_str("0.").map_err(|_| FloatFormatError::BadArg)?;
            for _ in 0..-whole {
                out.push(b'0')?;
            }
            for &digit in &digits[..n] {
                out.push(digit)?;
            }
        }
    } else {
        out.push(digits[0])?;
        out.push(b'.')?;
        if n == 1 {
            out.push(b'0')?;
        } else {
            for &digit in &digits[1..n] {
                out.push(digit)?;
            }
        }
        out.push(b'e')?;
        write!(&mut out, "{scientific_exponent}").map_err(|_| FloatFormatError::BadArg)?;
    }
    out.finish()
}

/// Parse the strict syntax accepted by `erlang:list_to_float/1` in OTP 29.1.1.
pub fn list_to_float(s: &[u8]) -> Result<f64, ParseError> {
    // Port of erts/emulator/sys/unix/sys_float.c:73 (sys_chars_to_double), OTP-29.1.1.
    // BIFs pass a NUL-terminated buffer, so bytes after the first NUL are unseen.
    let s = s.split(|&b| b == 0).next().unwrap_or_default();
    let mut i = 0;
    if matches!(s.get(i), Some(b'+' | b'-')) {
        i += 1;
    }
    let start = i;
    while matches!(s.get(i), Some(b'0'..=b'9')) {
        i += 1;
    }
    if i == start || !matches!(s.get(i), Some(b'.' | b',')) {
        return Err(ParseError::BadArg);
    }
    let comma = s[i] == b',';
    i += 1;
    let start = i;
    while matches!(s.get(i), Some(b'0'..=b'9')) {
        i += 1;
    }
    if i == start {
        return Err(ParseError::BadArg);
    }
    if matches!(s.get(i), Some(b'e' | b'E')) {
        i += 1;
        if matches!(s.get(i), Some(b'+' | b'-')) {
            i += 1;
        }
        let start = i;
        while matches!(s.get(i), Some(b'0'..=b'9')) {
            i += 1;
        }
        if i == start {
            return Err(ParseError::BadArg);
        }
    }
    if i != s.len() {
        return Err(ParseError::BadArg);
    }
    let parsed = if comma {
        let mut normalized = s.to_vec();
        if let Some(pos) = normalized.iter().position(|&b| b == b',') {
            normalized[pos] = b'.';
        }
        std::str::from_utf8(&normalized)
            .map_err(|_| ParseError::BadArg)?
            .parse::<f64>()
    } else {
        std::str::from_utf8(s)
            .map_err(|_| ParseError::BadArg)?
            .parse::<f64>()
    };
    let f = parsed.map_err(|_| ParseError::BadArg)?;
    if f.is_finite() {
        Ok(f)
    } else {
        Err(ParseError::BadArg)
    }
}
