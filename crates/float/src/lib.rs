//! Erlang/OTP 29.1.1 float conversion without VM term dependencies.

#![forbid(unsafe_code)]

use std::fmt::Write;

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
    if !f.is_finite() {
        return Err(FloatFormatError::BadArg);
    }
    match opts.notation {
        FloatNotation::Short => Ok(format_shortest(f)),
        FloatNotation::ScientificDefault => scientific(f, 20),
        FloatNotation::Scientific(d) if d <= 249 => scientific(f, usize::from(d)),
        FloatNotation::Decimals(d) if d <= 253 => fixed(f, usize::from(d), opts.compact),
        _ => Err(FloatFormatError::BadArg),
    }
}

fn scientific(f: f64, decimals: usize) -> Result<String, FloatFormatError> {
    // Port of erts/emulator/sys/unix/sys_float.c:55 (sys_double_to_chars_ext), OTP-29.1.1.
    // Rust and C both round the exact binary value to nearest, ties to even.
    let mut out = String::with_capacity(decimals + 10);
    let _ = write!(out, "{f:.decimals$e}");
    let e = out.rfind('e').expect("Rust scientific format");
    let exponent: i32 = out[e + 1..].parse().expect("Rust scientific exponent");
    out.truncate(e);
    let _ = write!(out, "e{exponent:+03}");
    if out.len() >= 256 {
        Err(FloatFormatError::BadArg)
    } else {
        Ok(out)
    }
}

const POW10: [f64; 19] = [
    1e0, 1e1, 1e2, 1e3, 1e4, 1e5, 1e6, 1e7, 1e8, 1e9, 1e10, 1e11, 1e12, 1e13, 1e14, 1e15, 1e16,
    1e17, 1e18,
];

fn fixed(f: f64, decimals: usize, compact: bool) -> Result<String, FloatFormatError> {
    // Port of erts/emulator/sys/common/erl_sys_common_misc.c:161
    // (sys_double_to_chars_fast), OTP-29.1.1.
    let af = f.abs();
    let mut out = if af > 9_007_199_254_740_992.0 || decimals >= POW10.len() {
        format!("{f:.decimals$}")
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
        let mut out = String::with_capacity(32);
        if f.is_sign_negative() {
            out.push('-');
        }
        let _ = write!(out, "{int_part}");
        if decimals != 0 {
            let _ = write!(out, ".{frac_part:0decimals$}");
        }
        out
    };
    if out.len() >= 256 {
        return Err(FloatFormatError::BadArg);
    }
    if compact && (decimals != 0 || af > 9_007_199_254_740_992.0) {
        // The fallback trims even an integer with D=0; preserve this erts quirk.
        let len = out.trim_end_matches('0').len();
        out.truncate(len);
        if out.ends_with('.') {
            out.push('0');
        }
    }
    Ok(out)
}

/// Format the shortest round-trip float used by `io_lib_format:fwrite_g/1`.
pub fn format_shortest(f: f64) -> String {
    // Port of erts/emulator/ryu/to_chars.h:36 (to_chars), OTP-29.1.1.
    // Ryu supplies the shortest decimal; OTP's modified layout chooses fixed
    // or scientific form and requires a fractional digit in either form.
    if !f.is_finite() {
        return ryu::Buffer::new().format(f).to_owned();
    }
    if f == 0.0 {
        return if f.is_sign_negative() { "-0.0" } else { "0.0" }.to_owned();
    }
    let mut buf = ryu::Buffer::new();
    let raw = buf.format_finite(f);
    // Ryū's scientific form with a fractional significand already matches
    // the OTP layout; only fixed forms and one-digit significands need work.
    if raw.contains('e') && raw.contains('.') {
        return raw.to_owned();
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
    let mut out = String::with_capacity(26);
    if negative {
        out.push('-');
    }
    if exponent >= lower && exponent <= upper && !force_scientific {
        let whole = n as i32 + exponent;
        if exponent >= 0 {
            for &digit in &digits[..n] {
                out.push(char::from(digit));
            }
            for _ in 0..exponent {
                out.push('0');
            }
            out.push_str(".0");
        } else if whole > 0 {
            for &digit in &digits[..whole as usize] {
                out.push(char::from(digit));
            }
            out.push('.');
            for &digit in &digits[whole as usize..n] {
                out.push(char::from(digit));
            }
        } else {
            out.push_str("0.");
            for _ in 0..-whole {
                out.push('0');
            }
            for &digit in &digits[..n] {
                out.push(char::from(digit));
            }
        }
    } else {
        out.push(char::from(digits[0]));
        out.push('.');
        if n == 1 {
            out.push('0');
        } else {
            for &digit in &digits[1..n] {
                out.push(char::from(digit));
            }
        }
        out.push('e');
        let _ = write!(out, "{scientific_exponent}");
    }
    out
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
