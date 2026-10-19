//! Load-time selection of compact, register-specific interpreter instructions.

use crate::{Arg, FastBif, Import, ImportClass, ImportFastOp, LoadError, Module};
use arinsal_etf::OwnedTerm;
use arinsal_spec::Opcode;
use arinsal_term::{Term, TermKind, to_owned};

/// An executable instruction. Variable-sized operands live in module side tables.
#[derive(Clone, Copy, Debug)]
pub enum Instr {
    /// Coverage-only probe inserted at a function or executable-line entry.
    CoverageProbe { index: u32 },
    /// X to X move.
    MoveXX { src: u16, dst: u16 },
    /// Move X to X and immediately enter a local call.
    MoveCallLocal { src: u16, dst: u16, target: u32 },
    /// Y to X move.
    MoveYX { src: u16, dst: u16 },
    /// X to Y move.
    MoveXY { src: u16, dst: u16 },
    /// Y to Y move.
    MoveYY { src: u16, dst: u16 },
    /// Immediate to X move.
    MoveCX { value: Term, dst: u16 },
    /// Immediate to Y move.
    MoveCY { value: Term, dst: u16 },
    /// Exchange two X registers.
    SwapXX { a: u16, b: u16 },
    /// Exchange a Y and X register.
    SwapYX { y: u16, x: u16 },
    /// Return to the continuation on the process stack.
    ReturnInstr,
    /// Invoke a VM-bound native body with the function's X arguments.
    ///
    /// `index` selects `Vm`'s native table. Static NIFs store a `BifFn`.
    /// Dynamic NIFs store a trampoline that calls the library through the
    /// OTP 29 C ABI on a process-heap `ErlNifEnv`. Dirty NIFs use the same
    /// entry and run on the calling scheduler.
    NativeBody { index: u32 },
    /// Patched function entry; `index` selects its original instruction.
    Breakpoint { index: u32 },
    /// Export entry trampoline installed for a `global` trace pattern.
    ExportBreakpoint { index: u32 },
    /// Traced function return continuation.
    ReturnTrace,
    /// Call-time or call-memory accounting return continuation.
    ReturnCallAccTrace,
    /// `return_to` continuation installed by a traced process flag.
    ReturnToTrace,
    /// Drop a Y frame and immediately return.
    DeallocateReturn { slots: u16 },
    /// Unconditional resolved local jump.
    Jump { target: u32 },
    /// Non-tail local call.
    CallLocal { target: u32 },
    /// Tail local call after Y deallocation.
    CallLast { target: u32, dealloc: u16 },
    /// Tail local call without deallocation.
    CallOnly { target: u32 },
    /// External call through a load-time-bound import entry.
    CallExternal {
        import: u32,
        arity: u16,
        dealloc: u16,
        tail: bool,
    },
    /// Call a BIF resolved from an external import during VM binding.
    CallBif {
        bif: arinsal_bifs::BifFn,
        fast_op: ImportFastOp,
        import: u32,
        arity: u16,
        dealloc: u16,
        tail: bool,
    },
    /// Reserve Y stack slots.
    Allocate { slots: u16, words: u32, live: u16 },
    /// Discard Y stack slots.
    Deallocate { slots: u16 },
    /// Drop the leading Y slots while retaining the rest of a frame.
    Trim { slots: u16 },
    /// Initialize the Y slots named by a decoded list.
    InitYregs { list: u32 },
    /// Check heap headroom before construction.
    TestHeap { words: u32, live: u16 },
    /// IsLt with two X sources.
    IsLtXX { a: u16, b: u16, fail: u32 },
    /// IsLt with an X source and immediate right operand.
    IsLtXC { a: u16, b: Term, fail: u32 },
    /// Return immediately when an X versus constant less-than test passes.
    IsLtXCReturn { a: u16, b: Term, fail: u32 },
    /// IsLt with an immediate left operand and X source.
    IsLtCX { a: Term, b: u16, fail: u32 },
    /// IsGe with two X sources.
    IsGeXX { a: u16, b: u16, fail: u32 },
    /// IsGe with an X source and immediate right operand.
    IsGeXC { a: u16, b: Term, fail: u32 },
    /// IsGe with an immediate left operand and X source.
    IsGeCX { a: Term, b: u16, fail: u32 },
    /// IsEq with two X sources.
    IsEqXX { a: u16, b: u16, fail: u32 },
    /// IsEq with an X source and immediate right operand.
    IsEqXC { a: u16, b: Term, fail: u32 },
    /// IsEq with an immediate left operand and X source.
    IsEqCX { a: Term, b: u16, fail: u32 },
    /// IsNe with two X sources.
    IsNeXX { a: u16, b: u16, fail: u32 },
    /// IsNe with an X source and immediate right operand.
    IsNeXC { a: u16, b: Term, fail: u32 },
    /// IsNe with an immediate left operand and X source.
    IsNeCX { a: Term, b: u16, fail: u32 },
    /// IsEqExact with two X sources.
    IsEqExactXX { a: u16, b: u16, fail: u32 },
    /// IsEqExact with an X source and immediate right operand.
    IsEqExactXC { a: u16, b: Term, fail: u32 },
    /// IsEqExact with an immediate left operand and X source.
    IsEqExactCX { a: Term, b: u16, fail: u32 },
    /// IsNeExact with two X sources.
    IsNeExactXX { a: u16, b: u16, fail: u32 },
    /// IsNeExact with an X source and immediate right operand.
    IsNeExactXC { a: u16, b: Term, fail: u32 },
    /// IsNeExact with an immediate left operand and X source.
    IsNeExactCX { a: Term, b: u16, fail: u32 },
    /// Extract a tuple element from X to X.
    GetTupleElementXX { src: u16, index: u16, dst: u16 },
    /// Extract a tuple element into X and convert it to an FR register.
    GetTupleFloat {
        src: u16,
        index: u16,
        dst_x: u16,
        dst_fr: u16,
    },
    /// Extract a tuple element from Y to X.
    GetTupleElementYX { src: u16, index: u16, dst: u16 },
    /// Extract a tuple element from X to Y.
    GetTupleElementXY { src: u16, index: u16, dst: u16 },
    /// Construct a two-element tuple from X registers.
    PutTupleXX { a: u16, b: u16, dst: u16 },
    /// Construct a tuple from a predecoded operand list.
    PutTuple { list: u32, dst: u16 },
    /// Construct a cons cell from X registers.
    PutListXXX { head: u16, tail: u16, dst: u16 },
    /// Construct a cons cell from mixed X, Y, or immediate sources.
    PutList { head: Arg, tail: Arg, dst: u16 },
    /// Destructure a list cell into X registers.
    GetListXXX { src: u16, head: u16, tail: u16 },
    /// Destructure a list into mixed X and Y destinations.
    GetList { src: u16, head: Arg, tail: Arg },
    /// Read the head of a list cell into X.
    GetHdXX { src: u16, dst: u16 },
    /// Read the tail of a list cell into X.
    GetTlXX { src: u16, dst: u16 },
    /// Small-integer arithmetic with X sources and X destination.
    ArithXXX {
        kind: FastBif,
        a: u16,
        b: u16,
        dst: u16,
        fail: u32,
        import: u32,
    },
    /// Small-integer arithmetic with a Y and X source and X destination.
    ArithYXX {
        kind: FastBif,
        a: u16,
        b: u16,
        dst: u16,
        fail: u32,
        import: u32,
    },
    /// Small-integer arithmetic with a register and constant right operand.
    ArithRC {
        kind: FastBif,
        src: u16,
        from_y: bool,
        value: Term,
        dst: u16,
        fail: u32,
        import: u32,
    },
    /// Small-integer arithmetic with a constant right operand and Y destination.
    ArithRCY {
        kind: FastBif,
        src: u16,
        from_y: bool,
        value: Term,
        dst: u16,
        fail: u32,
        import: u32,
    },
    /// Boxed float in X to float register.
    FmoveXFr { src: u16, dst: u16 },
    /// Boxed float in Y to float register.
    FmoveYFr { src: u16, dst: u16 },
    /// Literal float to float register.
    FmoveCFr { value: f64, dst: u16 },
    /// Float register to X with boxing.
    FmoveFrX { src: u16, dst: u16 },
    /// Float register to Y with boxing.
    FmoveFrY { src: u16, dst: u16 },
    /// Float register to float register.
    FmoveFrFr { src: u16, dst: u16 },
    /// Fadd on float registers.
    Fadd { a: u16, b: u16, dst: u16 },
    /// Fsub on float registers.
    Fsub { a: u16, b: u16, dst: u16 },
    /// Fmul on float registers.
    Fmul { a: u16, b: u16, dst: u16 },
    /// Fdiv on float registers.
    Fdiv { a: u16, b: u16, dst: u16 },
    /// Float arithmetic form retained for callers constructing instructions directly.
    FloatBin {
        kind: Opcode,
        a: u16,
        b: u16,
        dst: u16,
    },
    /// Test whether an X register holds a tuple.
    IsTupleX { src: u16, fail: u32 },
    /// Test tuple type and arity with distinct failure labels.
    IsTupleOfArity {
        src: u16,
        arity: u16,
        fail_type: u32,
        fail_arity: u32,
    },
    /// Test whether an X register holds NIL.
    IsNilX { src: u16, fail: u32 },
    /// Test whether an X register holds a cons cell.
    IsNonemptyListX { src: u16, fail: u32 },
    /// Test whether an X register holds an integer.
    IsIntegerX { src: u16, fail: u32 },
    /// Test the arity of an X tuple.
    TestArityX { src: u16, arity: u16, fail: u32 },
    /// Switch through a precomputed per-module select table.
    Select {
        src: u16,
        from_y: bool,
        table: u32,
        fallback: u32,
        tuple_arity: bool,
    },
    // ---- processes and messages ----
    /// Send the term in X1 to the pid or name in X0.
    Send,
    /// Examine the current mailbox save position.
    LoopRec { empty: u32, dst: Arg },
    /// Advance the save position and retry the receive loop.
    LoopRecEnd { target: u32 },
    /// Remove the matched message and cancel its receive timer.
    RemoveMessage,
    /// Suspend until a message arrives.
    Wait { target: u32 },
    /// Suspend until a message arrives or the timeout expires.
    WaitTimeout { target: u32, time: Arg },
    /// Reset receive state after the timeout branch.
    Timeout,
    /// Test a tuple's arity and first element.
    IsTaggedTuple {
        fail: u32,
        src: Arg,
        arity: u16,
        tag: Term,
    },
    /// Reserve an optimized receive start position.
    RecvMarkerReserve { dst: Arg },
    /// Bind a receive marker to a reference.
    RecvMarkerBind { marker: Arg, reference: Arg },
    /// Clear a receive marker.
    RecvMarkerClear { reference: Arg },
    /// Start scanning at a bound receive marker.
    RecvMarkerUse { reference: Arg },
    /// Index into [`crate::Module::generic`].
    Generic(u32),
    /// Index into [`crate::Module::unsupported_reasons`].
    Unsupported(u32),
    // ---- vm_maps_bits ----
    /// Map or bit syntax operation with decoded operands in [`crate::Module::generic`].
    MapsBits(u32),
    // vm_binparse: decoded bit commands avoid atom lookup and operand lists per match.
    /// Compare the remaining bit count with a constant.
    BsEnsure {
        context: u16,
        bits: u32,
        unit: u16,
        fail: u32,
        exact: bool,
    },
    /// Read a 32-bit big-endian unsigned integer after a length check.
    BsReadU32 { context: u16, dst: u16, fail: u32 },
    /// Read a bounded unsigned big-endian field from a match context.
    // Decode the general bit-syntax operation so matching operands avoid a side-table lookup.
    BsReadUint {
        context: u16,
        dst: u16,
        fail: u32,
        ensure_bits: u32,
        unit: u16,
        bits: u8,
    },
    /// Append an eight-bit integer to a private writable binary.
    // bits_cursor: this decodes one ordinary bs_create_bin segment pair.
    BsAppendByte {
        source: u16,
        value: u16,
        dst: u16,
        fallback: u32,
    },
    /// Extract a byte-sized binary field whose size is held in an X register.
    BsBinaryReg {
        context: u16,
        size: u16,
        dst: u16,
        live: u16,
        fail: u32,
    },
    /// Return the unmatched tail into an X register.
    BsTail { context: u16, dst: u16, live: u16 },
    /// Match a unit-aligned tail and place it in an X register.
    BsMatchTail {
        context: u16,
        dst: u16,
        live: u16,
        unit: u16,
        fail: u32,
    },
    /// Reuse a match context when a start-match source is already a context.
    BsStartReuse {
        source: u16,
        dst: u16,
        fallback: u32,
    },
    /// Read a match position as a small integer without a heap allocation.
    BsPositionSmall {
        context: u16,
        dst: u16,
        fallback: u32,
    },
    /// Terminates a code allocation if control falls through its last opcode.
    CodeEnd,
    /// A compiler debug location retained for debugger line breakpoints.
    DebugLine { line: u32, live: u16, import: u32 },
    /// Restores live X registers after `erts_internal:breakpoint/4` returns.
    DebugLineCleanup { live: u16 },
    // ---- vm_funs ----
    /// Construct a local closure from a lambda table entry.
    MakeFun { index: u32, dst: Arg, env: u32 },
    /// Invoke a fun with arguments in X registers.
    ///
    /// `tail` is set when the loader fused `call_fun2 + deallocate + return` (erts
    /// `i_call_fun_last`), so the caller frame of `dealloc` slots is released first.
    CallFun {
        arity: u16,
        src: Arg,
        dealloc: u16,
        tail: bool,
    },
    /// Invoke an exported function named by X[arity] and X[arity + 1].
    Apply {
        arity: u16,
        dealloc: u16,
        tail: bool,
    },
    /// Test a fun's callable arity.
    IsFunction2 { fail: u32, src: Arg, arity: Arg },
    // ---- vm_exc ----
    /// Exception handler, raise, or exceptional terminator.
    Exc { op: Opcode, a: Arg, b: Arg },
}

/// Rewrites bound external BIF calls to direct function-pointer instructions.
///
/// The VM calls this after classifying imports, so native overrides retain
/// their normal call path, and so do BIFs that may trap to a continuation.
// Port of erts/emulator/beam/emu/ops.tab:923-925, OTP-29.1.1.
pub fn specialize_bif_calls(module: &mut Module) {
    for instruction in &mut module.code {
        let Instr::CallExternal {
            import,
            arity,
            dealloc,
            tail,
        } = *instruction
        else {
            continue;
        };
        let Some(entry) = module.imports.get(import as usize) else {
            continue;
        };
        if entry.class() != ImportClass::Pure || entry.fast_op == ImportFastOp::Trapping {
            continue;
        }
        let Some(bif) = entry.bif_fn() else {
            continue;
        };
        *instruction = Instr::CallBif {
            bif,
            fast_op: entry.fast_op,
            import,
            arity,
            dealloc,
            tail,
        };
    }
}
// ---- vm_exc ----
const _: () = assert!(std::mem::size_of::<Instr>() == 24);

/// Precomputed select dispatch data. Dense tables use `u32::MAX` for a hole.
#[derive(Clone)]
pub enum SelectTable {
    /// Few cases or structural terms requiring Erlang exact equality.
    Linear(Vec<(Term, u32)>),
    /// Immediate keys sorted by tagged word.
    Sorted(Vec<(u64, u32)>),
    /// Compact small-integer range.
    Dense { min: i64, targets: Vec<u32> },
}

/// Original decoded operands for uncommon opcode or addressing combinations.
#[derive(Clone, Copy, Debug)]
pub struct GenericOp {
    /// Opcode and 24-bit index into out-of-line tails.
    pub meta: u32,
    /// First three decoded operands.
    pub args: [Arg; 3],
}
impl GenericOp {
    /// Build an opcode with an optional out-of-line operand tail.
    pub fn execute(opcode: Opcode, args: [Arg; 3], extra: u32) -> Result<Self, LoadError> {
        if extra > 0x00ff_ffff {
            return Err(LoadError::Limit);
        }
        Ok(Self {
            meta: ((opcode as u32) << 24) | extra,
            args,
        })
    }
    /// Decode the opcode stored by [`Self::execute`].
    #[inline]
    pub fn opcode(self) -> Opcode {
        Opcode::from_u8((self.meta >> 24) as u8).expect("GenericOp::execute stores a valid opcode")
    }
}

fn reg(arg: Arg, kind: u8) -> Option<u16> {
    (arg.kind() == kind && arg.value() < 1024).then_some(arg.value() as u16)
}
fn index(arg: Arg) -> Option<u32> {
    (arg.kind() == Arg::LABEL && arg.value() <= u32::MAX as u64).then_some(arg.value() as u32)
}
fn constant(arg: Arg) -> Option<Term> {
    match arg.kind() {
        Arg::TERM => Some(arg.term()),
        Arg::INT => Term::small(arg.signed()),
        _ => None,
    }
}
fn unsigned(arg: Arg) -> Option<u32> {
    (arg.kind() == Arg::U)
        .then(|| u32::try_from(arg.value()).ok())
        .flatten()
}
fn source(arg: Arg) -> bool {
    reg(arg, Arg::X).is_some() || reg(arg, Arg::Y).is_some() || constant(arg).is_some()
}
fn destination(arg: Arg) -> bool {
    reg(arg, Arg::X).is_some() || reg(arg, Arg::Y).is_some()
}

/// Select a fast instruction only when every operand satisfies its access invariant.
pub(crate) fn specialize(
    op: Opcode,
    a: [Arg; 3],
    tail: &[Arg],
    imports: &[Import],
    lists: &[Box<[Arg]>],
    selects: &mut Vec<SelectTable>,
) -> Option<Instr> {
    let [x, y, z] = a;
    // ---- vm_exc ----
    if matches!(
        op,
        Opcode::Try
            | Opcode::TryEnd
            | Opcode::TryCase
            | Opcode::TryCaseEnd
            | Opcode::Catch
            | Opcode::CatchEnd
            | Opcode::Raise
            | Opcode::RawRaise
            | Opcode::BuildStacktrace
            | Opcode::Badmatch
            | Opcode::CaseEnd
            | Opcode::IfEnd
            | Opcode::FuncInfo
            | Opcode::Badrecord
    ) {
        return Some(Instr::Exc { op, a: x, b: y });
    }
    let extra = |n: usize| tail.get(n).copied();
    // ---- vm_funs ----
    if let Some(instr) = crate::funs::specialize(op, a, lists) {
        return Some(instr);
    }
    Some(match op {
        Opcode::Move => match (x.kind(), y.kind()) {
            (Arg::X, Arg::X) => Instr::MoveXX {
                src: reg(x, Arg::X)?,
                dst: reg(y, Arg::X)?,
            },
            (Arg::Y, Arg::X) => Instr::MoveYX {
                src: reg(x, Arg::Y)?,
                dst: reg(y, Arg::X)?,
            },
            (Arg::X, Arg::Y) => Instr::MoveXY {
                src: reg(x, Arg::X)?,
                dst: reg(y, Arg::Y)?,
            },
            (Arg::Y, Arg::Y) => Instr::MoveYY {
                src: reg(x, Arg::Y)?,
                dst: reg(y, Arg::Y)?,
            },
            (Arg::TERM | Arg::INT, Arg::X) => Instr::MoveCX {
                value: constant(x)?,
                dst: reg(y, Arg::X)?,
            },
            (Arg::TERM | Arg::INT, Arg::Y) => Instr::MoveCY {
                value: constant(x)?,
                dst: reg(y, Arg::Y)?,
            },
            _ => return None,
        },
        Opcode::Swap => match (x.kind(), y.kind()) {
            (Arg::X, Arg::X) => Instr::SwapXX {
                a: reg(x, Arg::X)?,
                b: reg(y, Arg::X)?,
            },
            (Arg::Y, Arg::X) => Instr::SwapYX {
                y: reg(x, Arg::Y)?,
                x: reg(y, Arg::X)?,
            },
            _ => return None,
        },
        Opcode::Return => Instr::ReturnInstr,
        Opcode::Jump => Instr::Jump { target: index(x)? },
        Opcode::Call => Instr::CallLocal { target: index(y)? },
        Opcode::CallLast => Instr::CallLast {
            target: index(y)?,
            dealloc: reg(z, Arg::U)?,
        },
        Opcode::CallOnly => Instr::CallOnly { target: index(y)? },
        Opcode::CallExt | Opcode::CallExtLast | Opcode::CallExtOnly => {
            let import = unsigned(y)?;
            imports.get(import as usize)?;
            Instr::CallExternal {
                import,
                arity: reg(x, Arg::U)?,
                dealloc: if op == Opcode::CallExtLast {
                    reg(z, Arg::U)?
                } else {
                    0
                },
                tail: op != Opcode::CallExt,
            }
        }
        Opcode::Allocate => Instr::Allocate {
            slots: reg(x, Arg::U)?,
            words: 0,
            live: reg(y, Arg::U)?,
        },
        Opcode::AllocateHeap => Instr::Allocate {
            slots: reg(x, Arg::U)?,
            words: unsigned(y)?,
            live: reg(z, Arg::U)?,
        },
        Opcode::Deallocate => Instr::Deallocate {
            slots: reg(x, Arg::U)?,
        },
        Opcode::Trim => Instr::Trim {
            slots: reg(x, Arg::U)?,
        },
        Opcode::InitYregs => {
            if x.kind() != Arg::LIST {
                return None;
            }
            if !lists
                .get(x.value() as usize)?
                .iter()
                .copied()
                .all(|arg| reg(arg, Arg::Y).is_some())
            {
                return None;
            }
            Instr::InitYregs {
                list: x.value() as u32,
            }
        }
        Opcode::TestHeap => Instr::TestHeap {
            words: unsigned(x)?,
            live: reg(y, Arg::U)?,
        },
        Opcode::IsLt
        | Opcode::IsGe
        | Opcode::IsEq
        | Opcode::IsNe
        | Opcode::IsEqExact
        | Opcode::IsNeExact => {
            let fail = index(x)?;
            if y.kind() == Arg::X && z.kind() == Arg::X {
                let a = reg(y, Arg::X)?;
                let b = reg(z, Arg::X)?;
                match op {
                    Opcode::IsLt => Instr::IsLtXX { a, b, fail },
                    Opcode::IsGe => Instr::IsGeXX { a, b, fail },
                    Opcode::IsEq => Instr::IsEqXX { a, b, fail },
                    Opcode::IsNe => Instr::IsNeXX { a, b, fail },
                    Opcode::IsEqExact => Instr::IsEqExactXX { a, b, fail },
                    Opcode::IsNeExact => Instr::IsNeExactXX { a, b, fail },
                    _ => unreachable!(),
                }
            } else if y.kind() == Arg::X {
                let a = reg(y, Arg::X)?;
                let b = constant(z)?;
                match op {
                    Opcode::IsLt => Instr::IsLtXC { a, b, fail },
                    Opcode::IsGe => Instr::IsGeXC { a, b, fail },
                    Opcode::IsEq => Instr::IsEqXC { a, b, fail },
                    Opcode::IsNe => Instr::IsNeXC { a, b, fail },
                    Opcode::IsEqExact => Instr::IsEqExactXC { a, b, fail },
                    Opcode::IsNeExact => Instr::IsNeExactXC { a, b, fail },
                    _ => unreachable!(),
                }
            } else if z.kind() == Arg::X {
                let a = constant(y)?;
                let b = reg(z, Arg::X)?;
                match op {
                    Opcode::IsLt => Instr::IsLtCX { a, b, fail },
                    Opcode::IsGe => Instr::IsGeCX { a, b, fail },
                    Opcode::IsEq => Instr::IsEqCX { a, b, fail },
                    Opcode::IsNe => Instr::IsNeCX { a, b, fail },
                    Opcode::IsEqExact => Instr::IsEqExactCX { a, b, fail },
                    Opcode::IsNeExact => Instr::IsNeExactCX { a, b, fail },
                    _ => unreachable!(),
                }
            } else {
                return None;
            }
        }
        Opcode::GetTupleElement => match (x.kind(), z.kind()) {
            (Arg::X, Arg::X) => Instr::GetTupleElementXX {
                src: reg(x, Arg::X)?,
                index: reg(y, Arg::U)?,
                dst: reg(z, Arg::X)?,
            },
            (Arg::Y, Arg::X) => Instr::GetTupleElementYX {
                src: reg(x, Arg::Y)?,
                index: reg(y, Arg::U)?,
                dst: reg(z, Arg::X)?,
            },
            (Arg::X, Arg::Y) => Instr::GetTupleElementXY {
                src: reg(x, Arg::X)?,
                index: reg(y, Arg::U)?,
                dst: reg(z, Arg::Y)?,
            },
            _ => return None,
        },
        Opcode::PutTuple2 => {
            if y.kind() != Arg::LIST {
                return None;
            }
            let items = lists.get(y.value() as usize)?;
            if items.len() == 2 && items.iter().all(|item| item.kind() == Arg::X) {
                Instr::PutTupleXX {
                    a: reg(items[0], Arg::X)?,
                    b: reg(items[1], Arg::X)?,
                    dst: reg(x, Arg::X)?,
                }
            } else {
                if !items.iter().copied().all(source) {
                    return None;
                }
                Instr::PutTuple {
                    list: y.value() as u32,
                    dst: reg(x, Arg::X)?,
                }
            }
        }
        Opcode::PutList => {
            if let (Some(head), Some(tail), Some(dst)) =
                (reg(x, Arg::X), reg(y, Arg::X), reg(z, Arg::X))
            {
                Instr::PutListXXX { head, tail, dst }
            } else {
                if !source(x) || !source(y) {
                    return None;
                }
                Instr::PutList {
                    head: x,
                    tail: y,
                    dst: reg(z, Arg::X)?,
                }
            }
        }
        Opcode::GetList => {
            if let (Some(src), Some(head), Some(tail)) =
                (reg(x, Arg::X), reg(y, Arg::X), reg(z, Arg::X))
            {
                Instr::GetListXXX { src, head, tail }
            } else {
                if !destination(y) || !destination(z) {
                    return None;
                }
                Instr::GetList {
                    src: reg(x, Arg::X)?,
                    head: y,
                    tail: z,
                }
            }
        }
        Opcode::GetHd => Instr::GetHdXX {
            src: reg(x, Arg::X)?,
            dst: reg(y, Arg::X)?,
        },
        Opcode::GetTl => Instr::GetTlXX {
            src: reg(x, Arg::X)?,
            dst: reg(y, Arg::X)?,
        },
        Opcode::GcBif2 | Opcode::Bif2 => {
            let (import, lhs, rhs, dst, fail) = if op == Opcode::GcBif2 {
                (unsigned(z)?, extra(0)?, extra(1)?, extra(2)?, index(x)?)
            } else {
                (unsigned(y)?, z, extra(0)?, extra(1)?, index(x)?)
            };
            let import_slot = imports.get(import as usize)?;
            // Port of erts/emulator/beam/emu/generators.tab:657 (gen.element),
            // OTP-29.1.1: resolve a literal position at load instead of each call.
            if import_slot.module == "erlang"
                && import_slot.function == "element"
                && import_slot.arity == 2
                && fail == u32::MAX
                && let Some(position) = constant(lhs).and_then(|term| term.as_small())
                && (1..=65536).contains(&position)
            {
                let index = (position - 1) as u16;
                return Some(match (rhs.kind(), dst.kind()) {
                    (Arg::X, Arg::X) => Instr::GetTupleElementXX {
                        src: reg(rhs, Arg::X)?,
                        index,
                        dst: reg(dst, Arg::X)?,
                    },
                    (Arg::Y, Arg::X) => Instr::GetTupleElementYX {
                        src: reg(rhs, Arg::Y)?,
                        index,
                        dst: reg(dst, Arg::X)?,
                    },
                    (Arg::X, Arg::Y) => Instr::GetTupleElementXY {
                        src: reg(rhs, Arg::X)?,
                        index,
                        dst: reg(dst, Arg::Y)?,
                    },
                    _ => return None,
                });
            }
            let kind = import_slot.fast;
            if kind == FastBif::None {
                return None;
            }
            if let (Some(a), Some(b), Some(dst)) =
                (reg(lhs, Arg::X), reg(rhs, Arg::X), reg(dst, Arg::X))
            {
                Instr::ArithXXX {
                    kind,
                    a,
                    b,
                    dst,
                    fail,
                    import,
                }
            } else if let (Some(a), Some(b), Some(dst)) =
                (reg(lhs, Arg::Y), reg(rhs, Arg::X), reg(dst, Arg::X))
            {
                Instr::ArithYXX {
                    kind,
                    a,
                    b,
                    dst,
                    fail,
                    import,
                }
            } else if let (Some(src), Some(value), Some(dst)) = (
                reg(lhs, Arg::X).or_else(|| reg(lhs, Arg::Y)),
                constant(rhs),
                reg(dst, Arg::X),
            ) {
                Instr::ArithRC {
                    kind,
                    src,
                    from_y: lhs.kind() == Arg::Y,
                    value,
                    dst,
                    fail,
                    import,
                }
            } else if let (Some(src), Some(value), Some(dst)) = (
                reg(lhs, Arg::X).or_else(|| reg(lhs, Arg::Y)),
                constant(rhs),
                reg(dst, Arg::Y),
            ) {
                Instr::ArithRCY {
                    kind,
                    src,
                    from_y: lhs.kind() == Arg::Y,
                    value,
                    dst,
                    fail,
                    import,
                }
            } else if matches!(kind, FastBif::Add | FastBif::Mul)
                && let (Some(value), Some(src), Some(dst)) =
                    (constant(lhs), reg(rhs, Arg::X), reg(dst, Arg::X))
            {
                Instr::ArithRC {
                    kind,
                    src,
                    from_y: false,
                    value,
                    dst,
                    fail,
                    import,
                }
            } else {
                return None;
            }
        }
        Opcode::Fmove | Opcode::Fconv => match (x.kind(), y.kind()) {
            (Arg::X, Arg::FR) => Instr::FmoveXFr {
                src: reg(x, Arg::X)?,
                dst: reg(y, Arg::FR)?,
            },
            (Arg::Y, Arg::FR) => Instr::FmoveYFr {
                src: reg(x, Arg::Y)?,
                dst: reg(y, Arg::FR)?,
            },
            (Arg::TERM | Arg::INT, Arg::FR) => {
                let term = constant(x)?;
                let value = term.as_small().map(|n| n as f64).or_else(|| {
                    if term.classify() != TermKind::Number {
                        return None;
                    }
                    let owned = to_owned(term).ok()?;
                    match &owned {
                        OwnedTerm::Float(value) => Some(*value),
                        _ => None,
                    }
                })?;
                Instr::FmoveCFr {
                    value,
                    dst: reg(y, Arg::FR)?,
                }
            }
            (Arg::FR, Arg::X) => Instr::FmoveFrX {
                src: reg(x, Arg::FR)?,
                dst: reg(y, Arg::X)?,
            },
            (Arg::FR, Arg::Y) => Instr::FmoveFrY {
                src: reg(x, Arg::FR)?,
                dst: reg(y, Arg::Y)?,
            },
            (Arg::FR, Arg::FR) => Instr::FmoveFrFr {
                src: reg(x, Arg::FR)?,
                dst: reg(y, Arg::FR)?,
            },
            _ => return None,
        },
        Opcode::Fadd | Opcode::Fsub | Opcode::Fmul | Opcode::Fdiv => {
            let a = reg(y, Arg::FR)?;
            let b = reg(z, Arg::FR)?;
            let dst = reg(extra(0)?, Arg::FR)?;
            match op {
                Opcode::Fadd => Instr::Fadd { a, b, dst },
                Opcode::Fsub => Instr::Fsub { a, b, dst },
                Opcode::Fmul => Instr::Fmul { a, b, dst },
                Opcode::Fdiv => Instr::Fdiv { a, b, dst },
                _ => unreachable!(),
            }
        }
        Opcode::IsTuple => Instr::IsTupleX {
            src: reg(y, Arg::X)?,
            fail: index(x)?,
        },
        Opcode::IsNil => Instr::IsNilX {
            src: reg(y, Arg::X)?,
            fail: index(x)?,
        },
        Opcode::IsNonemptyList => Instr::IsNonemptyListX {
            src: reg(y, Arg::X)?,
            fail: index(x)?,
        },
        Opcode::IsInteger => Instr::IsIntegerX {
            src: reg(y, Arg::X)?,
            fail: index(x)?,
        },
        Opcode::TestArity => Instr::TestArityX {
            src: reg(y, Arg::X)?,
            arity: reg(z, Arg::U)?,
            fail: index(x)?,
        },
        Opcode::SelectVal | Opcode::SelectTupleArity => {
            let src = reg(x, Arg::X).or_else(|| reg(x, Arg::Y))?;
            let fallback = index(y)?;
            if z.kind() != Arg::LIST {
                return None;
            }
            let list = lists.get(z.value() as usize)?;
            let mut entries = Vec::with_capacity(list.len() / 2);
            for pair in list.as_chunks::<2>().0 {
                // OTP-29.1.1 genop.tab declares tuple arities as untagged U values.
                let key = if op == Opcode::SelectTupleArity {
                    (pair[0].kind() == Arg::U)
                        .then(|| i64::try_from(pair[0].value()).ok())
                        .flatten()
                        .and_then(Term::small)?
                } else {
                    constant(pair[0])?
                };
                entries.push((key, index(pair[1])?));
            }
            let table = build_select(entries);
            let table_index = u32::try_from(selects.len()).ok()?;
            selects.push(table);
            Instr::Select {
                src,
                from_y: x.kind() == Arg::Y,
                table: table_index,
                fallback,
                tuple_arity: op == Opcode::SelectTupleArity,
            }
        }
        // ---- processes and messages ----
        Opcode::Send => Instr::Send,
        Opcode::LoopRec => Instr::LoopRec {
            empty: index(x)?,
            dst: y,
        },
        Opcode::LoopRecEnd => Instr::LoopRecEnd { target: index(x)? },
        Opcode::RemoveMessage => Instr::RemoveMessage,
        Opcode::Wait => Instr::Wait { target: index(x)? },
        Opcode::WaitTimeout => Instr::WaitTimeout {
            target: index(x)?,
            time: y,
        },
        Opcode::Timeout => Instr::Timeout,
        Opcode::IsTaggedTuple => Instr::IsTaggedTuple {
            fail: index(x)?,
            src: y,
            arity: reg(z, Arg::U)?,
            tag: constant(extra(0)?)?,
        },
        Opcode::RecvMarkerReserve => Instr::RecvMarkerReserve { dst: x },
        Opcode::RecvMarkerBind => Instr::RecvMarkerBind {
            marker: x,
            reference: y,
        },
        Opcode::RecvMarkerClear => Instr::RecvMarkerClear { reference: x },
        Opcode::RecvMarkerUse => Instr::RecvMarkerUse { reference: x },
        _ => return None,
    })
}

fn build_select(entries: Vec<(Term, u32)>) -> SelectTable {
    if entries.len() <= 4 || entries.iter().any(|(term, _)| term.is_pointer()) {
        return SelectTable::Linear(entries);
    }
    let smalls: Option<Vec<_>> = entries
        .iter()
        .map(|(term, target)| Some((term.as_small()?, *target)))
        .collect();
    if let Some(smalls) = smalls {
        let min = smalls.iter().map(|(key, _)| *key).min().unwrap_or(0);
        let max = smalls.iter().map(|(key, _)| *key).max().unwrap_or(0);
        if let Some(width) = max.checked_sub(min).and_then(|n| n.checked_add(1))
            && width <= 4096
            && width as usize <= smalls.len() * 4
        {
            let mut targets = vec![u32::MAX; width as usize];
            for (key, target) in smalls {
                let slot = &mut targets[(key - min) as usize];
                if *slot == u32::MAX {
                    *slot = target;
                }
            }
            return SelectTable::Dense { min, targets };
        }
    }
    let mut seen = std::collections::HashSet::new();
    if entries.iter().any(|(term, _)| {
        // SAFETY: The pointer-bearing cases returned the linear table above.
        !seen.insert(unsafe { term.raw_bits() })
    }) {
        return SelectTable::Linear(entries);
    }
    let mut sorted: Vec<_> = entries
        .into_iter()
        .map(|(term, target)| {
            // SAFETY: Immediate keys contain no heap address.
            (unsafe { term.raw_bits() }, target)
        })
        .collect();
    sorted.sort_unstable_by_key(|(bits, _)| *bits);
    SelectTable::Sorted(sorted)
}
