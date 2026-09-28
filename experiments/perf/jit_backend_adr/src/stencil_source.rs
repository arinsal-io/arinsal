#[unsafe(no_mangle)]
pub extern "C" fn stencil_add(value: i64) -> i64 {
    value.wrapping_add(0x12ab)
}

unsafe extern "C" {
    fn adr_helper(value: i64) -> i64;
}

#[unsafe(no_mangle)]
pub extern "C" fn stencil_helper(value: i64) -> i64 {
    // SAFETY: This symbol is intentionally unresolved; the object is inspected, not linked.
    unsafe { adr_helper(value) }
}
