//! Register views and constants match asmjit's ids.

use arinsal_x64::enc::*;

#[test]
fn views_and_ids() {
    assert_eq!(RAX.r32(), EAX);
    assert_eq!(R13.r8(), R13B);
    assert_eq!(RBX.r8_hi(), BH);
    assert_eq!(R9D.r64(), R9);
    assert_eq!(SPL.r16(), SP);
    assert_eq!((R15.id, R15.size()), (15, 8));
    assert_eq!((AH.id, AH.size(), AH.kind), (0, 1, GpKind::B8Hi));
    assert_eq!(Xmm(3).ymm(), Ymm(3));
    assert_eq!(
        qword_ptr(RBX, 8).adjusted(-8).with_size(4),
        dword_ptr(RBX, 0)
    );
}
