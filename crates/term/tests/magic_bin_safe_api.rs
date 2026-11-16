use arinsal_term::{ExternalBinary, MagicBin, MagicRef, TermBuilder, VecHeap};

struct Payload;
arinsal_term::magic_payload!(Payload => destroy_payload);

struct TrapState(usize);
arinsal_term::magic_payload!(TrapState => destroy_trap_state);
arinsal_term::exclusive_magic_payload!(TrapState);

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

#[test]
fn exclusive_payload_mutation_uses_the_inline_magic_data() {
    let owner = MagicBin::new(TrapState(3));
    similar_asserts::assert_eq!(
        owner.with_payload_mut::<TrapState, _>(|state| {
            state.0 += 4;
            state.0
        }),
        Some(7)
    );

    let mut heap = VecHeap::new();
    let term = TermBuilder::new(&mut heap)
        .magic_ref(owner.clone())
        .unwrap();
    similar_asserts::assert_eq!(
        term.with_magic_payload_mut::<TrapState, _>(|state| state.0),
        Some(7)
    );
}

struct BytePayload([u8; 4]);
fn byte_payload_data<'a>(payload: &'a BytePayload, _: &'a MagicRef) -> Option<&'a [u8]> {
    Some(&payload.0)
}
arinsal_term::magic_payload!(BytePayload => destroy_byte_payload, data = byte_payload_data);

#[test]
fn external_binary_requires_bytes_owned_by_its_typed_magic_payload() {
    let owner = MagicBin::new(BytePayload([1, 2, 3, 4]));
    let bytes = owner.downcast_ref::<BytePayload>().unwrap().0.as_ptr();
    assert!(ExternalBinary::new::<BytePayload>(bytes, 4, owner.clone()).is_some());
    assert!(ExternalBinary::new::<BytePayload>(bytes, 5, owner.clone()).is_none());
    assert!(ExternalBinary::new::<Payload>(bytes, 1, owner).is_none());
}
