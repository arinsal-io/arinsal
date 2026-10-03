use arinsal_a64::enc::Gpr;
use arinsal_beamasm::{
    ExitReason, ProcessHeader, SchedulerRegisters, dispatch, enter_native,
    module::BeamModuleAssembler,
};

/// A disabled line breakpoint site is an aligned `b next` that skips the trap, the trap is
/// never reached, and the site table names the line, the patch word and its restore value.
#[test]
fn disabled_line_breakpoint_skips_trap_and_is_patchable() {
    let mut asm = BeamModuleAssembler::new();
    asm.emit_i_func_label(1).unwrap();
    asm.emit_i_debug_line(7, 9).unwrap();
    // 0x1000 is never called: the branch skips the trampoline body.
    asm.emit_i_line_breakpoint_trampoline(0x1000).unwrap();
    asm.emit_raw(|e| {
        e.mov_const(Gpr::x(25), 0x77)?;
        e.mov_reg(Gpr::x(0), Gpr::xzr())?;
        e.ret(Gpr::x(30))
    })
    .unwrap();
    // An i_line_breakpoint_trampoline needs its i_debug_line.
    assert!(asm.emit_i_line_breakpoint_trampoline(0x1000).is_err());
    let module = asm.finalize().unwrap();

    let [(line, offset, branch)] = module.line_breakpoints[..] else {
        panic!("expected exactly one line breakpoint site");
    };
    assert_eq!(line, 7);
    assert_eq!(offset % 8, 0, "the patched branch is word aligned");
    // B with a positive word offset past the trap sequence.
    assert_eq!(branch & 0xfc00_0000, 0x1400_0000);
    assert!(branch & 0x03ff_ffff > 2);
    let [(resume, site)] = module.line_breakpoint_returns[..] else {
        panic!("expected exactly one hit return address");
    };
    assert_eq!(site, offset + 4, "frame address lies just inside the site");
    assert!(resume > site);

    let mut header = ProcessHeader::default();
    let mut regs = SchedulerRegisters::default();
    let mut stack = [0_u64; 64];
    header.stop = stack.as_mut_ptr().wrapping_add(stack.len());
    header.fcalls = 100;
    let result = enter_native(&mut header, &mut regs, &module.entry(1).unwrap());
    assert!(matches!(result, ExitReason::Returned));
}

#[test]
fn line_breakpoint_identity_round_trips() {
    for (line, live) in [(1, 0), (24_000_000, 1023), (u32::MAX, u16::MAX)] {
        let identity = dispatch::line_breakpoint_identity(line, live);
        assert_eq!(
            dispatch::decode_line_breakpoint_identity(identity),
            Some((line, live))
        );
    }
    assert_eq!(
        dispatch::decode_line_breakpoint_identity(dispatch::BREAKPOINT_DISPATCH_IDENTITY),
        None
    );
    assert_eq!(dispatch::decode_line_breakpoint_identity(5), None);
}
