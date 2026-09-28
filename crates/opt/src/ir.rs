//! Backend-independent SSA for integer call regions.

use arinsal_loader::{Arg, FastBif, Instr, Module, SelectTable};
use arinsal_spec::Opcode;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// An SSA value local to one function.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ValueId(pub u32);

/// Representation of an SSA value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValueType {
    /// An ordinary tagged BEAM word.
    Term,
    /// An unboxed integer whose range is guarded before tagging.
    I64,
    /// An unboxed floating-point value, reserved for the next tier step.
    F64,
    /// A branch predicate.
    Bool,
    /// A tuple whose fields remain SSA values until an observable exit.
    VirtualTuple,
}

/// A logical BEAM register.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Location {
    /// An argument or temporary register.
    X(u16),
    /// A process-stack slot.
    Y(u16),
    /// An unboxed floating-point register.
    Fr(u16),
}

/// How a value is restored at an interpreter exit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Recipe {
    /// Use a tagged SSA word directly.
    Tagged(ValueId),
    /// Range-check and tag an unboxed small integer.
    Small(ValueId),
    /// Materialize an unboxed float; reserved for the next tier step.
    Float(ValueId),
    /// Materialize a virtual tuple; reserved for the next tier step.
    VirtualTuple(ValueId),
}

/// Interpreter state reconstructed before the instruction at `pc`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeoptMap {
    /// Resolved BEAM instruction offset.
    pub pc: usize,
    /// Number of currently allocated Y slots.
    pub frame_slots: u16,
    /// Only registers live at this PC need reconstruction.
    pub live: Vec<(Location, Recipe)>,
}

/// A source in the integer subset.
#[derive(Clone, Copy, Debug)]
pub enum Source {
    /// An SSA value.
    Value(ValueId),
    /// A small-integer literal.
    Constant(i64),
}

/// Integer comparison in a guard.
#[derive(Clone, Copy, Debug)]
pub enum Compare {
    /// `<`.
    Lt,
    /// `>=`.
    Ge,
    /// `=:=` or integer `==`.
    Eq,
    /// `=/=` or integer `/=`.
    Ne,
}

/// Integer operations accepted by the specialized region.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntOp {
    /// Addition.
    Add,
    /// Subtraction.
    Sub,
    /// Multiplication.
    Mul,
    /// Truncating integer division.
    Div,
    /// Remainder with the dividend's sign.
    Rem,
    /// Bitwise AND.
    Band,
    /// Bitwise OR.
    Bor,
    /// Left shift.
    Bsl,
    /// Arithmetic right shift.
    Bsr,
}
impl IntOp {
    fn fast(kind: FastBif, pc: usize) -> Result<Self, LowerError> {
        match kind {
            FastBif::Add => Ok(Self::Add),
            FastBif::Sub => Ok(Self::Sub),
            FastBif::Mul => Ok(Self::Mul),
            FastBif::None => Err(LowerError::Unsupported {
                pc,
                reason: "unknown arithmetic BIF",
            }),
        }
    }
    fn named(name: &str) -> Option<Self> {
        Some(match name {
            "+" => Self::Add,
            "-" => Self::Sub,
            "*" => Self::Mul,
            "div" => Self::Div,
            "rem" => Self::Rem,
            "band" => Self::Band,
            "bor" => Self::Bor,
            "bsl" => Self::Bsl,
            "bsr" => Self::Bsr,
            _ => return None,
        })
    }
}

/// Integer instruction semantics with resolved control flow.
#[derive(Clone, Debug)]
pub enum Operation {
    /// Copy an SSA value into a register.
    Move { source: Source, target: Location },
    /// Add, subtract, or multiply with a checked small-integer result.
    Arithmetic {
        kind: IntOp,
        lhs: Source,
        rhs: Source,
        target: Location,
    },
    /// Branch to `fail` if the predicate is false.
    Guard {
        kind: Compare,
        lhs: Source,
        rhs: Source,
        fail: usize,
        return_on_pass: bool,
    },
    /// A type guard discharged by the small-integer entry guard.
    IntegerGuard { source: Source },
    /// An exact small-integer switch.
    Select {
        source: Source,
        cases: Vec<(i64, usize)>,
        fallback: usize,
    },
    /// Create a logical process frame.
    Allocate { slots: u16 },
    /// Discard a logical process frame.
    Deallocate { slots: u16 },
    /// Drop leading Y slots and renumber the rest.
    Trim { slots: u16 },
    /// Initialize slots to NIL; unboxed reads before an integer write are rejected.
    InitYregs { registers: Vec<u16> },
    /// A direct local call. The result is assigned to X0 on return.
    Call {
        target: usize,
        arity: u8,
        tail: bool,
        resume: usize,
    },
    /// A loader-fused register move followed by a direct call.
    MoveCall {
        source: Source,
        destination: Location,
        target: usize,
        arity: u8,
        resume: usize,
    },
    /// An unconditional branch.
    Jump { target: usize },
    /// Return X0.
    Return,
}

/// One BEAM instruction is an SSA block; the incoming values are its phi parameters.
#[derive(Clone, Debug)]
pub struct Block {
    /// Resolved BEAM instruction offset.
    pub pc: usize,
    /// Incoming X values followed by Y values.
    pub parameters: Vec<ValueId>,
    /// The lowered instruction.
    pub operation: Operation,
    /// Outgoing X values followed by Y values.
    pub outgoing: Vec<ValueId>,
    /// Interpreter reconstruction before this instruction.
    pub deopt: DeoptMap,
}

/// One direct-call target in the region.
#[derive(Clone, Debug)]
pub struct Function {
    /// Resolved BEAM entry offset.
    pub entry: usize,
    /// Function arity.
    pub arity: u8,
    /// Number of X locations needed by this body.
    pub x_count: usize,
    /// Number of logical Y locations needed by this body.
    pub y_count: usize,
    /// SSA value types indexed by `ValueId`.
    pub types: Vec<ValueType>,
    /// Reachable instruction blocks in PC order.
    pub blocks: Vec<Block>,
}

/// A hot function and its direct local call closure.
#[derive(Clone, Debug)]
pub struct Region {
    /// Requested entry offset.
    pub entry: usize,
    /// Direct-call functions, including recursive cycles.
    pub functions: BTreeMap<usize, Function>,
}

/// A region that cannot yet prove a safe integer specialization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LowerError {
    /// The requested offset is not a function entry.
    Entry(usize),
    /// An instruction needs the interpreter or a later tier step.
    Unsupported { pc: usize, reason: &'static str },
    /// Control flow crosses a function boundary or has inconsistent frame depth.
    InvalidFlow(usize),
}

impl std::fmt::Display for LowerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for LowerError {}

fn small(term: arinsal_term::Term, pc: usize) -> Result<Source, LowerError> {
    term.as_small()
        .map(Source::Constant)
        .ok_or(LowerError::Unsupported {
            pc,
            reason: "non-integer literal",
        })
}

fn generic_positions(opcode: Opcode) -> Option<(usize, usize, usize)> {
    match opcode {
        Opcode::GcBif2 => Some((2, 3, 5)),
        Opcode::Bif2 => Some((1, 2, 4)),
        _ => None,
    }
}

fn generic_arithmetic(
    module: &Module,
    index: u32,
    pc: usize,
    state: &[ValueId],
    x_count: usize,
) -> Result<Operation, LowerError> {
    let op = module
        .generic
        .get(index as usize)
        .ok_or(LowerError::InvalidFlow(pc))?;
    let (import_pos, first, dst_pos) =
        generic_positions(op.opcode()).ok_or(LowerError::Unsupported {
            pc,
            reason: "non-arithmetic generic instruction",
        })?;
    let import_arg = module.arg(op, import_pos);
    if import_arg.kind() != Arg::U {
        return Err(LowerError::Unsupported {
            pc,
            reason: "unresolved arithmetic import",
        });
    }
    let import = module
        .imports
        .get(import_arg.value() as usize)
        .ok_or(LowerError::InvalidFlow(pc))?;
    if import.module != "erlang" || import.arity != 2 {
        return Err(LowerError::Unsupported {
            pc,
            reason: "non-integer import",
        });
    }
    let kind = IntOp::named(&import.function).ok_or(LowerError::Unsupported {
        pc,
        reason: "non-integer BIF",
    })?;
    let source = |arg: Arg| -> Result<Source, LowerError> {
        Ok(match arg.kind() {
            Arg::X => loc(state, x_count, Location::X(arg.value() as u16)),
            Arg::Y => loc(state, x_count, Location::Y(arg.value() as u16)),
            Arg::INT => Source::Constant(arg.signed()),
            Arg::TERM => small(arg.term(), pc)?,
            _ => {
                return Err(LowerError::Unsupported {
                    pc,
                    reason: "non-integer BIF operand",
                });
            }
        })
    };
    let lhs = source(module.arg(op, first))?;
    let rhs = source(module.arg(op, first + 1))?;
    let dst = module.arg(op, dst_pos);
    let target = match dst.kind() {
        Arg::X => Location::X(dst.value() as u16),
        Arg::Y => Location::Y(dst.value() as u16),
        _ => {
            return Err(LowerError::Unsupported {
                pc,
                reason: "non-register BIF destination",
            });
        }
    };
    Ok(Operation::Arithmetic {
        kind,
        lhs,
        rhs,
        target,
    })
}

fn fresh(types: &mut Vec<ValueType>) -> ValueId {
    let id = ValueId(types.len() as u32);
    types.push(ValueType::I64);
    id
}

fn loc(state: &[ValueId], x_count: usize, place: Location) -> Source {
    let index = match place {
        Location::X(n) => n as usize,
        Location::Y(n) => x_count + n as usize,
        Location::Fr(_) => unreachable!("float lowering is deferred"),
    };
    Source::Value(state[index])
}

fn write_index(x_count: usize, target: Location) -> usize {
    match target {
        Location::X(n) => n as usize,
        Location::Y(n) => x_count + n as usize,
        Location::Fr(_) => unreachable!("float lowering is deferred"),
    }
}

fn source_known(source: Source, block: &Block, known: &[bool]) -> bool {
    match source {
        Source::Constant(_) => true,
        Source::Value(id) => block
            .parameters
            .iter()
            .position(|value| *value == id)
            .is_some_and(|index| known[index]),
    }
}

fn validate_numeric(
    module: &Module,
    entry: usize,
    blocks: &[Block],
    x_count: usize,
    y_count: usize,
    arity: u8,
) -> Result<(), LowerError> {
    let positions = blocks
        .iter()
        .enumerate()
        .map(|(n, block)| (block.pc, n))
        .collect::<BTreeMap<_, _>>();
    let mut known = vec![None::<Vec<bool>>; blocks.len()];
    let mut initial = vec![false; x_count + y_count];
    for flag in initial.iter_mut().take(arity as usize) {
        *flag = true;
    }
    known[positions[&entry]] = Some(initial);
    loop {
        let mut changed = false;
        for (i, block) in blocks.iter().enumerate() {
            let Some(before) = known[i].as_ref() else {
                continue;
            };
            let mut after = before.clone();
            match &block.operation {
                Operation::Move { source, target } => {
                    after[write_index(x_count, *target)] = source_known(*source, block, before)
                }
                Operation::Arithmetic {
                    lhs, rhs, target, ..
                } => {
                    after[write_index(x_count, *target)] =
                        source_known(*lhs, block, before) && source_known(*rhs, block, before);
                }
                Operation::Allocate { slots } | Operation::Deallocate { slots } => {
                    for n in 0..*slots as usize {
                        after[x_count + n] = false;
                    }
                }
                Operation::InitYregs { registers } => {
                    for &n in registers {
                        after[x_count + n as usize] = false;
                    }
                }
                Operation::Trim { slots } => {
                    for n in 0..y_count {
                        after[x_count + n] = before
                            .get(x_count + n + *slots as usize)
                            .copied()
                            .unwrap_or(false);
                    }
                }
                Operation::Call { tail: false, .. } | Operation::MoveCall { .. } => {
                    for flag in after.iter_mut().take(x_count) {
                        *flag = false;
                    }
                    after[0] = true;
                }
                _ => {}
            }
            for next in successors(module, module.code[block.pc], block.pc)? {
                let Some(&j) = positions.get(&next) else {
                    continue;
                };
                if let Some(current) = known[j].as_mut() {
                    for (value, new) in current.iter_mut().zip(&after) {
                        if *value && !new {
                            *value = false;
                            changed = true;
                        }
                    }
                } else {
                    known[j] = Some(after.clone());
                    changed = true;
                }
            }
        }
        if !changed {
            break;
        }
    }
    for (i, block) in blocks.iter().enumerate() {
        let Some(before) = known[i].as_ref() else {
            return Err(LowerError::InvalidFlow(block.pc));
        };
        let require = |source: Source| -> Result<(), LowerError> {
            if source_known(source, block, before) {
                Ok(())
            } else {
                Err(LowerError::Unsupported {
                    pc: block.pc,
                    reason: "unproven integer location",
                })
            }
        };
        match &block.operation {
            Operation::Move { source, .. }
            | Operation::IntegerGuard { source }
            | Operation::Select { source, .. } => require(*source)?,
            Operation::Arithmetic { lhs, rhs, .. } | Operation::Guard { lhs, rhs, .. } => {
                require(*lhs)?;
                require(*rhs)?;
            }
            Operation::Call { arity, .. } => {
                for &flag in before.iter().take(*arity as usize) {
                    if !flag {
                        return Err(LowerError::Unsupported {
                            pc: block.pc,
                            reason: "unproven call argument",
                        });
                    }
                }
            }
            Operation::MoveCall {
                source,
                destination,
                arity,
                ..
            } => {
                require(*source)?;
                for (n, &flag) in before.iter().enumerate().take(*arity as usize) {
                    if !flag && *destination != Location::X(n as u16) {
                        return Err(LowerError::Unsupported {
                            pc: block.pc,
                            reason: "unproven call argument",
                        });
                    }
                }
            }
            Operation::Return if !before[0] => {
                return Err(LowerError::Unsupported {
                    pc: block.pc,
                    reason: "unproven return",
                });
            }
            _ => {}
        }
        for (place, _) in &block.deopt.live {
            if !before[write_index(x_count, *place)] {
                return Err(LowerError::Unsupported {
                    pc: block.pc,
                    reason: "unproven deopt value",
                });
            }
        }
    }
    Ok(())
}

fn select_cases(module: &Module, table: u32, pc: usize) -> Result<Vec<(i64, usize)>, LowerError> {
    let Some(table) = module.selects.get(table as usize) else {
        return Err(LowerError::InvalidFlow(pc));
    };
    let cases = match table {
        SelectTable::Linear(entries) => entries
            .iter()
            .map(|(term, target)| term.as_small().map(|n| (n, *target as usize)))
            .collect::<Option<Vec<_>>>(),
        SelectTable::Sorted(entries) => entries
            .iter()
            .map(|(bits, target)| {
                if bits & 15 == 15 {
                    Some(((*bits as i64) >> 4, *target as usize))
                } else {
                    None
                }
            })
            .collect::<Option<Vec<_>>>(),
        SelectTable::Dense { min, targets } => targets
            .iter()
            .enumerate()
            .filter(|(_, target)| **target != u32::MAX)
            .map(|(offset, target)| {
                min.checked_add(offset as i64)
                    .map(|n| (n, *target as usize))
            })
            .collect::<Option<Vec<_>>>(),
    };
    cases
        .filter(|cases| cases.len() <= 64)
        .ok_or(LowerError::Unsupported {
            pc,
            reason: "non-integer select",
        })
}

fn successors(module: &Module, instr: Instr, pc: usize) -> Result<Vec<usize>, LowerError> {
    Ok(match instr {
        Instr::ReturnInstr | Instr::DeallocateReturn { .. } => Vec::new(),
        Instr::Jump { target } | Instr::CallOnly { target } | Instr::CallLast { target, .. } => {
            if matches!(instr, Instr::Jump { .. }) {
                vec![target as usize]
            } else {
                Vec::new()
            }
        }
        Instr::IsLtXX { fail, .. }
        | Instr::IsLtXC { fail, .. }
        | Instr::IsLtCX { fail, .. }
        | Instr::IsGeXX { fail, .. }
        | Instr::IsGeXC { fail, .. }
        | Instr::IsGeCX { fail, .. }
        | Instr::IsEqXX { fail, .. }
        | Instr::IsEqXC { fail, .. }
        | Instr::IsEqCX { fail, .. }
        | Instr::IsNeXX { fail, .. }
        | Instr::IsNeXC { fail, .. }
        | Instr::IsNeCX { fail, .. }
        | Instr::IsEqExactXX { fail, .. }
        | Instr::IsEqExactXC { fail, .. }
        | Instr::IsEqExactCX { fail, .. }
        | Instr::IsNeExactXX { fail, .. }
        | Instr::IsNeExactXC { fail, .. }
        | Instr::IsNeExactCX { fail, .. } => vec![pc + 1, fail as usize],
        Instr::IsLtXCReturn { fail, .. } => vec![fail as usize],
        Instr::Select {
            table,
            fallback,
            tuple_arity: false,
            ..
        } => {
            let mut next = select_cases(module, table, pc)?
                .into_iter()
                .map(|(_, target)| target)
                .collect::<Vec<_>>();
            next.push(fallback as usize);
            next
        }
        Instr::IsIntegerX { fail, .. } => vec![pc + 1, fail as usize],
        Instr::MoveCallLocal { .. } => vec![pc + 2],
        _ => vec![pc + 1],
    })
}

fn register_bounds(module: &Module, instr: Instr, x: &mut usize, y: &mut usize) {
    let mut add = |place: Location| match place {
        Location::X(n) => *x = (*x).max(n as usize + 1),
        Location::Y(n) => *y = (*y).max(n as usize + 1),
        Location::Fr(_) => {}
    };
    match instr {
        Instr::MoveXX { src, dst } => {
            add(Location::X(src));
            add(Location::X(dst));
        }
        Instr::MoveYX { src, dst } => {
            add(Location::Y(src));
            add(Location::X(dst));
        }
        Instr::MoveXY { src, dst } => {
            add(Location::X(src));
            add(Location::Y(dst));
        }
        Instr::MoveYY { src, dst } => {
            add(Location::Y(src));
            add(Location::Y(dst));
        }
        Instr::MoveCX { dst, .. } => add(Location::X(dst)),
        Instr::MoveCY { dst, .. } => add(Location::Y(dst)),
        Instr::MoveCallLocal { src, dst, .. } => {
            add(Location::X(src));
            add(Location::X(dst));
            add(Location::X(0));
        }
        Instr::IsLtXX { a, b, .. }
        | Instr::IsGeXX { a, b, .. }
        | Instr::IsEqXX { a, b, .. }
        | Instr::IsNeXX { a, b, .. }
        | Instr::IsEqExactXX { a, b, .. }
        | Instr::IsNeExactXX { a, b, .. } => {
            add(Location::X(a));
            add(Location::X(b));
        }
        Instr::IsLtXC { a, .. }
        | Instr::IsGeXC { a, .. }
        | Instr::IsEqXC { a, .. }
        | Instr::IsNeXC { a, .. }
        | Instr::IsEqExactXC { a, .. }
        | Instr::IsNeExactXC { a, .. }
        | Instr::IsLtXCReturn { a, .. } => add(Location::X(a)),
        Instr::IsLtCX { b, .. }
        | Instr::IsGeCX { b, .. }
        | Instr::IsEqCX { b, .. }
        | Instr::IsNeCX { b, .. }
        | Instr::IsEqExactCX { b, .. }
        | Instr::IsNeExactCX { b, .. } => add(Location::X(b)),
        Instr::ArithXXX { a, b, dst, .. } => {
            add(Location::X(a));
            add(Location::X(b));
            add(Location::X(dst));
        }
        Instr::ArithYXX { a, b, dst, .. } => {
            add(Location::Y(a));
            add(Location::X(b));
            add(Location::X(dst));
        }
        Instr::ArithRC {
            src, from_y, dst, ..
        } => {
            add(if from_y {
                Location::Y(src)
            } else {
                Location::X(src)
            });
            add(Location::X(dst));
        }
        Instr::ArithRCY {
            src, from_y, dst, ..
        } => {
            add(if from_y {
                Location::Y(src)
            } else {
                Location::X(src)
            });
            add(Location::Y(dst));
        }
        Instr::Generic(index) => {
            if let Some(op) = module.generic.get(index as usize)
                && let Some((_, first, dst)) = generic_positions(op.opcode())
            {
                for position in [first, first + 1, dst] {
                    let arg = module.arg(op, position);
                    match arg.kind() {
                        Arg::X => add(Location::X(arg.value() as u16)),
                        Arg::Y => add(Location::Y(arg.value() as u16)),
                        _ => {}
                    }
                }
            }
        }
        Instr::IsIntegerX { src, .. } => add(Location::X(src)),
        Instr::Select { src, from_y, .. } => add(if from_y {
            Location::Y(src)
        } else {
            Location::X(src)
        }),
        Instr::Allocate { slots, .. }
        | Instr::Deallocate { slots }
        | Instr::DeallocateReturn { slots }
        | Instr::Trim { slots } => *y = (*y).max(slots as usize),
        Instr::ReturnInstr
        | Instr::CallLocal { .. }
        | Instr::CallOnly { .. }
        | Instr::CallLast { .. } => add(Location::X(0)),
        _ => {}
    }
}

impl Region {
    /// Lower the direct-call closure rooted at a resolved function entry.
    pub fn lower(module: &Module, entry: usize) -> Result<Self, LowerError> {
        let mut functions = BTreeMap::new();
        let mut pending = vec![entry];
        while let Some(target) = pending.pop() {
            if functions.contains_key(&target) {
                continue;
            }
            let function = Function::lower(module, target)?;
            for block in &function.blocks {
                if let Operation::Call { target, .. } | Operation::MoveCall { target, .. } =
                    block.operation
                {
                    pending.push(target);
                }
            }
            functions.insert(target, function);
        }
        Ok(Self { entry, functions })
    }
}

impl Function {
    fn lower(module: &Module, entry: usize) -> Result<Self, LowerError> {
        let Some((start, _, arity)) = module.functions.iter().find(|(pc, _, _)| *pc + 1 == entry)
        else {
            return Err(LowerError::Entry(entry));
        };
        let end = module
            .functions
            .iter()
            .find(|(pc, _, _)| *pc > *start)
            .map_or(module.code.len() - 1, |(pc, _, _)| *pc);
        let mut reachable = BTreeSet::new();
        let mut queue = VecDeque::from([entry]);
        let mut depths = BTreeMap::from([(entry, 0_u16)]);
        while let Some(pc) = queue.pop_front() {
            if !(entry..end).contains(&pc) {
                return Err(LowerError::InvalidFlow(pc));
            }
            if !reachable.insert(pc) {
                continue;
            }
            let instr = module.code[pc];
            let before = depths[&pc];
            let after = match instr {
                Instr::Allocate {
                    slots, words: 0, ..
                } => before.checked_add(slots),
                Instr::Deallocate { slots } | Instr::Trim { slots } => before.checked_sub(slots),
                Instr::DeallocateReturn { slots } | Instr::CallLast { dealloc: slots, .. } => {
                    before.checked_sub(slots)
                }
                _ => Some(before),
            }
            .ok_or(LowerError::InvalidFlow(pc))?;
            for next in successors(module, instr, pc)? {
                if next == *start {
                    continue;
                }
                if !(entry..end).contains(&next) {
                    return Err(LowerError::InvalidFlow(next));
                }
                if let Some(old) = depths.insert(next, after)
                    && old != after
                {
                    return Err(LowerError::InvalidFlow(next));
                }
                queue.push_back(next);
            }
        }
        let mut x_count = *arity as usize;
        let mut y_count = 0;
        for &pc in &reachable {
            register_bounds(module, module.code[pc], &mut x_count, &mut y_count);
        }
        for &pc in &reachable {
            let target = match module.code[pc] {
                Instr::CallLocal { target }
                | Instr::CallOnly { target }
                | Instr::CallLast { target, .. }
                | Instr::MoveCallLocal { target, .. } => Some(target as usize),
                _ => None,
            };
            if let Some(target) = target {
                let callee = module
                    .functions
                    .iter()
                    .find(|(start, _, _)| *start + 1 == target)
                    .ok_or(LowerError::Entry(target))?;
                x_count = x_count.max(callee.2 as usize);
            }
        }
        if x_count > 32 || y_count > 32 {
            return Err(LowerError::Unsupported {
                pc: entry,
                reason: "large register frame",
            });
        }
        let mut types = Vec::new();
        let mut blocks = Vec::new();
        for &pc in &reachable {
            let parameters = (0..x_count + y_count)
                .map(|_| fresh(&mut types))
                .collect::<Vec<_>>();
            let mut outgoing = parameters.clone();
            let x = |n| loc(&parameters, x_count, Location::X(n));
            let y = |n| loc(&parameters, x_count, Location::Y(n));
            let call_arity = |target: u32| {
                module
                    .functions
                    .iter()
                    .find(|(start, _, _)| *start + 1 == target as usize)
                    .map(|(_, _, arity)| *arity)
                    .ok_or(LowerError::Entry(target as usize))
            };
            let operation = match module.code[pc] {
                Instr::MoveXX { src, dst } => Operation::Move {
                    source: x(src),
                    target: Location::X(dst),
                },
                Instr::MoveYX { src, dst } => Operation::Move {
                    source: y(src),
                    target: Location::X(dst),
                },
                Instr::MoveXY { src, dst } => Operation::Move {
                    source: x(src),
                    target: Location::Y(dst),
                },
                Instr::MoveYY { src, dst } => Operation::Move {
                    source: y(src),
                    target: Location::Y(dst),
                },
                Instr::MoveCX { value, dst } => Operation::Move {
                    source: small(value, pc)?,
                    target: Location::X(dst),
                },
                Instr::MoveCY { value, dst } => Operation::Move {
                    source: small(value, pc)?,
                    target: Location::Y(dst),
                },
                Instr::ArithXXX {
                    kind, a, b, dst, ..
                } => Operation::Arithmetic {
                    kind: IntOp::fast(kind, pc)?,
                    lhs: x(a),
                    rhs: x(b),
                    target: Location::X(dst),
                },
                Instr::ArithYXX {
                    kind, a, b, dst, ..
                } => Operation::Arithmetic {
                    kind: IntOp::fast(kind, pc)?,
                    lhs: y(a),
                    rhs: x(b),
                    target: Location::X(dst),
                },
                Instr::ArithRC {
                    kind,
                    src,
                    from_y,
                    value,
                    dst,
                    ..
                } => Operation::Arithmetic {
                    kind: IntOp::fast(kind, pc)?,
                    lhs: if from_y { y(src) } else { x(src) },
                    rhs: small(value, pc)?,
                    target: Location::X(dst),
                },
                Instr::ArithRCY {
                    kind,
                    src,
                    from_y,
                    value,
                    dst,
                    ..
                } => Operation::Arithmetic {
                    kind: IntOp::fast(kind, pc)?,
                    lhs: if from_y { y(src) } else { x(src) },
                    rhs: small(value, pc)?,
                    target: Location::Y(dst),
                },
                Instr::IsLtXX { a, b, fail } => Operation::Guard {
                    kind: Compare::Lt,
                    lhs: x(a),
                    rhs: x(b),
                    fail: fail as usize,
                    return_on_pass: false,
                },
                Instr::IsLtXC { a, b, fail } => Operation::Guard {
                    kind: Compare::Lt,
                    lhs: x(a),
                    rhs: small(b, pc)?,
                    fail: fail as usize,
                    return_on_pass: false,
                },
                Instr::IsLtCX { a, b, fail } => Operation::Guard {
                    kind: Compare::Lt,
                    lhs: small(a, pc)?,
                    rhs: x(b),
                    fail: fail as usize,
                    return_on_pass: false,
                },
                Instr::IsGeXX { a, b, fail } => Operation::Guard {
                    kind: Compare::Ge,
                    lhs: x(a),
                    rhs: x(b),
                    fail: fail as usize,
                    return_on_pass: false,
                },
                Instr::IsGeXC { a, b, fail } => Operation::Guard {
                    kind: Compare::Ge,
                    lhs: x(a),
                    rhs: small(b, pc)?,
                    fail: fail as usize,
                    return_on_pass: false,
                },
                Instr::IsGeCX { a, b, fail } => Operation::Guard {
                    kind: Compare::Ge,
                    lhs: small(a, pc)?,
                    rhs: x(b),
                    fail: fail as usize,
                    return_on_pass: false,
                },
                Instr::IsEqXX { a, b, fail } | Instr::IsEqExactXX { a, b, fail } => {
                    Operation::Guard {
                        kind: Compare::Eq,
                        lhs: x(a),
                        rhs: x(b),
                        fail: fail as usize,
                        return_on_pass: false,
                    }
                }
                Instr::IsEqXC { a, b, fail } | Instr::IsEqExactXC { a, b, fail } => {
                    Operation::Guard {
                        kind: Compare::Eq,
                        lhs: x(a),
                        rhs: small(b, pc)?,
                        fail: fail as usize,
                        return_on_pass: false,
                    }
                }
                Instr::IsEqCX { a, b, fail } | Instr::IsEqExactCX { a, b, fail } => {
                    Operation::Guard {
                        kind: Compare::Eq,
                        lhs: small(a, pc)?,
                        rhs: x(b),
                        fail: fail as usize,
                        return_on_pass: false,
                    }
                }
                Instr::IsNeXX { a, b, fail } | Instr::IsNeExactXX { a, b, fail } => {
                    Operation::Guard {
                        kind: Compare::Ne,
                        lhs: x(a),
                        rhs: x(b),
                        fail: fail as usize,
                        return_on_pass: false,
                    }
                }
                Instr::IsNeXC { a, b, fail } | Instr::IsNeExactXC { a, b, fail } => {
                    Operation::Guard {
                        kind: Compare::Ne,
                        lhs: x(a),
                        rhs: small(b, pc)?,
                        fail: fail as usize,
                        return_on_pass: false,
                    }
                }
                Instr::IsNeCX { a, b, fail } | Instr::IsNeExactCX { a, b, fail } => {
                    Operation::Guard {
                        kind: Compare::Ne,
                        lhs: small(a, pc)?,
                        rhs: x(b),
                        fail: fail as usize,
                        return_on_pass: false,
                    }
                }
                Instr::IsLtXCReturn { a, b, fail } => Operation::Guard {
                    kind: Compare::Lt,
                    lhs: x(a),
                    rhs: small(b, pc)?,
                    fail: fail as usize,
                    return_on_pass: true,
                },
                Instr::IsIntegerX { src, .. } => Operation::IntegerGuard { source: x(src) },
                Instr::Select {
                    src,
                    from_y,
                    table,
                    fallback,
                    tuple_arity: false,
                } => Operation::Select {
                    source: if from_y { y(src) } else { x(src) },
                    cases: select_cases(module, table, pc)?,
                    fallback: fallback as usize,
                },
                Instr::Generic(index) => {
                    generic_arithmetic(module, index, pc, &parameters, x_count)?
                }
                Instr::Allocate {
                    slots, words: 0, ..
                } => Operation::Allocate { slots },
                Instr::Deallocate { slots } => Operation::Deallocate { slots },
                Instr::Trim { slots } => Operation::Trim { slots },
                Instr::InitYregs { list } => {
                    let registers = module
                        .lists
                        .get(list as usize)
                        .ok_or(LowerError::InvalidFlow(pc))?
                        .iter()
                        .map(|arg| {
                            if arg.kind() == Arg::Y {
                                Ok(arg.value() as u16)
                            } else {
                                Err(LowerError::Unsupported {
                                    pc,
                                    reason: "non-Y init list",
                                })
                            }
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    Operation::InitYregs { registers }
                }
                Instr::ReturnInstr => Operation::Return,
                Instr::DeallocateReturn { .. } => Operation::Return,
                Instr::Jump { target } => Operation::Jump {
                    target: target as usize,
                },
                Instr::CallLocal { target } => Operation::Call {
                    target: target as usize,
                    arity: call_arity(target)?,
                    tail: false,
                    resume: pc + 1,
                },
                Instr::CallLast { target, .. } | Instr::CallOnly { target } => Operation::Call {
                    target: target as usize,
                    arity: call_arity(target)?,
                    tail: true,
                    resume: pc + 1,
                },
                Instr::MoveCallLocal { src, dst, target } => Operation::MoveCall {
                    source: x(src),
                    destination: Location::X(dst),
                    target: target as usize,
                    arity: call_arity(target)?,
                    resume: pc + 2,
                },
                _ => {
                    return Err(LowerError::Unsupported {
                        pc,
                        reason: "non-integer instruction",
                    });
                }
            };
            if let Operation::Move { target, .. } | Operation::Arithmetic { target, .. } = operation
            {
                let value = fresh(&mut types);
                outgoing[write_index(x_count, target)] = value;
            }
            if let Operation::Trim { slots } = operation {
                for n in 0..y_count {
                    outgoing[x_count + n] = if n + (slots as usize) < y_count {
                        parameters[x_count + n + slots as usize]
                    } else {
                        parameters[x_count + n]
                    };
                }
            }
            if let Operation::Call { tail: false, .. } | Operation::MoveCall { .. } = operation {
                outgoing[0] = fresh(&mut types);
            }
            let deopt = DeoptMap {
                pc,
                frame_slots: depths[&pc],
                live: Vec::new(),
            };
            blocks.push(Block {
                pc,
                parameters,
                operation,
                outgoing,
                deopt,
            });
        }
        // Compute BEAM liveness before exposing any deoptimization point. A
        // dead register may contain an arbitrary term and must stay untouched.
        let index = blocks
            .iter()
            .enumerate()
            .map(|(i, b)| (b.pc, i))
            .collect::<BTreeMap<_, _>>();
        let mut live = vec![BTreeSet::<usize>::new(); blocks.len()];
        loop {
            let mut changed = false;
            for i in (0..blocks.len()).rev() {
                let block = &blocks[i];
                let mut next = BTreeSet::new();
                for pc in successors(module, module.code[block.pc], block.pc)? {
                    if let Some(&j) = index.get(&pc) {
                        next.extend(live[j].iter().copied());
                    }
                }
                if let Operation::Trim { slots } = block.operation {
                    next = next
                        .into_iter()
                        .filter_map(|n| {
                            if n < x_count {
                                Some(n)
                            } else if n - x_count + (slots as usize) < y_count {
                                Some(n + slots as usize)
                            } else {
                                None
                            }
                        })
                        .collect();
                } else {
                    let writes = block
                        .parameters
                        .iter()
                        .zip(&block.outgoing)
                        .enumerate()
                        .filter_map(|(n, (a, b))| (a != b).then_some(n))
                        .collect::<Vec<_>>();
                    for n in writes {
                        next.remove(&n);
                    }
                }
                let mut read = |source: Source| {
                    if let Source::Value(v) = source
                        && let Some(n) = block.parameters.iter().position(|id| *id == v)
                    {
                        next.insert(n);
                    }
                };
                match block.operation {
                    Operation::Move { source, .. } => read(source),
                    Operation::IntegerGuard { source } | Operation::Select { source, .. } => {
                        read(source)
                    }
                    Operation::Arithmetic { lhs, rhs, .. } | Operation::Guard { lhs, rhs, .. } => {
                        read(lhs);
                        read(rhs);
                    }
                    Operation::Call { arity, .. } => {
                        for n in 0..arity as usize {
                            next.insert(n);
                        }
                    }
                    Operation::MoveCall {
                        source,
                        destination,
                        arity,
                        ..
                    } => {
                        read(source);
                        for n in 0..arity as usize {
                            if destination != Location::X(n as u16) {
                                next.insert(n);
                            }
                        }
                    }
                    Operation::Return => {
                        next.insert(0);
                    }
                    _ => {}
                }
                if next != live[i] {
                    live[i] = next;
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
        for (i, block) in blocks.iter_mut().enumerate() {
            block.deopt.live = live[i]
                .iter()
                .map(|&n| {
                    let place = if n < x_count {
                        Location::X(n as u16)
                    } else {
                        Location::Y((n - x_count) as u16)
                    };
                    (place, Recipe::Small(block.parameters[n]))
                })
                .collect();
        }
        validate_numeric(module, entry, &blocks, x_count, y_count, *arity)?;
        Ok(Self {
            entry,
            arity: *arity,
            x_count,
            y_count,
            types,
            blocks,
        })
    }
}
