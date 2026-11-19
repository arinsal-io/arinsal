// Port of erts/etc/unix/safe_string.c, OTP-29.1.1.

use std::io::Write;

// Port of erts/etc/unix/safe_string.c (strn_cpy), OTP-29.1.1.
pub fn copy(source: &[u8], size: usize) -> Vec<u8> {
    if source.len() >= size {
        overflow(&source[..size.saturating_sub(1)]);
    }
    source.to_vec()
}

// Port of erts/etc/unix/safe_string.c (strn_cat), OTP-29.1.1.
pub fn append(destination: &mut Vec<u8>, source: &[u8], size: usize) {
    if destination.len() >= size {
        let mut message = b"Buffer already overflowed '".to_vec();
        message.extend_from_slice(&destination[..size.min(destination.len())]);
        message.extend_from_slice(b"'\n");
        let _ = std::io::stderr().write_all(&message);
        std::process::exit(1);
    }
    if destination.len() + source.len() >= size {
        let accepted = size - destination.len() - 1;
        let mut truncated = destination.clone();
        truncated.extend_from_slice(&source[..accepted]);
        overflow(&truncated);
    }
    destination.extend_from_slice(source);
}

// Port of erts/etc/unix/safe_string.c (find_str), OTP-29.1.1.
pub fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(
            haystack
                .iter()
                .position(|byte| *byte == 0)
                .unwrap_or(haystack.len()),
        );
    }
    if haystack.len() < needle.len() {
        return None;
    }
    (0..=haystack.len() - needle.len()).find(|index| &haystack[*index..][..needle.len()] == needle)
}

// Port of erts/etc/unix/safe_string.c (string_overflow_handler), OTP-29.1.1.
fn overflow(value: &[u8]) -> ! {
    let mut message = b"Buffer truncated '".to_vec();
    message.extend_from_slice(value);
    message.extend_from_slice(b"'\n");
    let _ = std::io::stderr().write_all(&message);
    std::process::exit(1)
}
