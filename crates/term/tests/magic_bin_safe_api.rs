use arinsal_term::MagicBin;

struct Payload;
arinsal_term::magic_payload!(Payload => destroy_payload);

#[test]
#[should_panic(expected = "magic binary trailing alignment")]
fn trailing_allocation_rejects_zero_alignment() {
    let _ = MagicBin::with_trailing_and_refn(Payload, 1, 0, 0, [0; 3]);
}

#[test]
fn trailing_pointer_rejects_invalid_alignment() {
    let bin = MagicBin::with_trailing_and_refn(Payload, 1, 1, 0, [0; 3]);
    assert!(bin.trailing_ptr::<Payload>(0).is_none());
    assert!(bin.trailing_ptr::<Payload>(usize::MAX).is_none());
}
