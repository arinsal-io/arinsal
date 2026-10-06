//! Cranelift compilation of functions with recoverable interpreter exits.

use arinsal_loader::{Arg, FastBif, Instr, Module as BeamModule, SelectTable};
use arinsal_spec::Opcode;
use arinsal_term::Term;
use cranelift_codegen::ir::{self, InstBuilder, MemFlagsData, condcodes::IntCC, types};
use cranelift_frontend::{FunctionBuilder, FunctionBuilderContext, Variable};
use cranelift_jit::{JITBuilder, JITModule};
use cranelift_module::{FuncId, Linkage, Module};
use std::cell::{Cell, RefCell};
use std::collections::{BTreeSet, HashMap};
use std::ffi::c_void;

thread_local! {
    // Compilation is synchronous. Exit helpers use this list to materialize
    // float registers only where execution can leave the current native body.
    static ACTIVE_FR: RefCell<Vec<(u16, Variable)>> = const { RefCell::new(Vec::new()) };
    static ACTIVE_X: RefCell<(Vec<Variable>, Vec<u16>)> = const { RefCell::new((Vec::new(), Vec::new())) };
    static RESERVED_ALLOCATION: Cell<bool> = const { Cell::new(false) };
    static ACTIVE_Y_FLOAT: RefCell<Vec<(u16, Variable, Variable)>> = const { RefCell::new(Vec::new()) };
    static ACTIVE_ENSURE: Cell<Option<ir::FuncRef>> = const { Cell::new(None) };
    static ACTIVE_DEOPT: Cell<Option<ir::Block>> = const { Cell::new(None) };
    // Explicit X root prefix for the native body being compiled. Replaces the
    // old `1024` "every register" sentinel.
    static ACTIVE_X_WINDOW: Cell<u16> = const { Cell::new(0) };
}

const SSA_X_REGISTERS: usize = 16;

/// Native execution state shared with the interpreter. Register and shadow
/// frame values are materialized here when GC or interpreter execution needs them.
#[repr(C)]
pub struct JitState {
    /// The interpreter's X register allocation.
    pub x: *mut u64,
    /// The interpreter's unboxed float registers.
    pub fr: *mut f64,
    /// The first live process stack word.
    pub stop: *mut u64,
    /// The first free heap word.
    pub htop: *mut u64,
    /// The end of the process stack allocation, refreshed after collection.
    pub stack_end: *mut u64,
    /// Opaque interpreter process for heap growth.
    pub process: *mut c_void,
    /// Module number used in tagged continuations.
    pub module: u64,
    /// Remaining reductions.
    pub reds: i32,
    /// Exact instruction offset when native execution yields.
    pub ip: u32,
    /// Native non-tail call depth before yielding to the process stack.
    pub depth: u32,
    /// X registers this native body may still need across a collection.
    /// Materialize reads it when it has no BEAM `Live` operand. Zero means
    /// the body did not publish a window.
    pub x_live: u32,
}

/// An interpreter entry returns zero after `return`, or one with `state.ip`
/// set to resume at a slow instruction. Its argument uses the platform C ABI.
pub type NativeFn = unsafe extern "C" fn(*mut JitState) -> u32;

/// A heap growth callback. It synchronizes the native stack cursor, collects
/// if needed, and refreshes both cursors in `JitState`.
pub type EnsureFn = extern "C" fn(*mut JitState, u32, u32) -> u32;

/// Convert one native call frame into a BEAM continuation while unwinding.
pub type MaterializeFn = extern "C" fn(*mut JitState, u64, u64) -> u32;

/// Why a function was left in the interpreter.
#[derive(Debug)]
pub enum CompileError {
    /// The function contains an instruction outside this compiler's subset.
    Unsupported { ip: usize, reason: &'static str },
    /// A local callee must be compiled before this function can call it natively.
    PendingDependency { target: usize },
    /// Cranelift could not compile the function.
    Codegen(String),
}

impl std::fmt::Display for CompileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsupported { ip, reason } => write!(f, "instruction {ip}: {reason}"),
            Self::PendingDependency { target } => {
                write!(f, "local callee {target} is not compiled")
            }
            Self::Codegen(reason) => write!(f, "Cranelift: {reason}"),
        }
    }
}
impl std::error::Error for CompileError {}

/// A module-local Cranelift engine. Its executable pages outlive all returned
/// function pointers.
pub struct JitEngine {
    module: JITModule,
    context: cranelift_codegen::Context,
    fb_context: FunctionBuilderContext,
    code_bytes: usize,
    compiled: HashMap<(usize, usize), (FuncId, NativeFn, u8)>,
    ensure: FuncId,
    materialize: FuncId,
    sqrt: FuncId,
}

extern "C" fn host_sqrt(value: f64) -> f64 {
    value.sqrt()
}

impl JitEngine {
    /// Create a host-native compiler with heap growth and frame conversion callbacks.
    pub fn new(ensure: EnsureFn, materialize: MaterializeFn) -> Result<Self, CompileError> {
        let flags: &[(&str, &str)] = match std::env::var("ADR_JIT_MODE").as_deref() {
            Ok("fast") | Ok("fast_reuse") => {
                &[("opt_level", "none"), ("regalloc_algorithm", "single_pass")]
            }
            _ => &[],
        };
        let mut builder = JITBuilder::with_flags(flags, cranelift_module::default_libcall_names())
            .map_err(|e| CompileError::Codegen(e.to_string()))?;
        builder.symbol("arinsal_jit_ensure", ensure as *const u8);
        builder.symbol("arinsal_jit_materialize", materialize as *const u8);
        builder.symbol("arinsal_jit_sqrt", host_sqrt as *const u8);
        let mut module = JITModule::new(builder);
        let mut sig = module.make_signature();
        sig.params.push(ir::AbiParam::new(types::I64));
        sig.params.push(ir::AbiParam::new(types::I32));
        sig.params.push(ir::AbiParam::new(types::I32));
        sig.returns.push(ir::AbiParam::new(types::I32));
        let ensure = module
            .declare_function("arinsal_jit_ensure", Linkage::Import, &sig)
            .map_err(|e| CompileError::Codegen(e.to_string()))?;
        let mut materialize_sig = module.make_signature();
        materialize_sig.params.push(ir::AbiParam::new(types::I64));
        materialize_sig.params.push(ir::AbiParam::new(types::I64));
        materialize_sig.params.push(ir::AbiParam::new(types::I64));
        materialize_sig.returns.push(ir::AbiParam::new(types::I32));
        let materialize = module
            .declare_function("arinsal_jit_materialize", Linkage::Import, &materialize_sig)
            .map_err(|e| CompileError::Codegen(e.to_string()))?;
        let mut sqrt_sig = module.make_signature();
        sqrt_sig.params.push(ir::AbiParam::new(types::F64));
        sqrt_sig.returns.push(ir::AbiParam::new(types::F64));
        let sqrt = module
            .declare_function("arinsal_jit_sqrt", Linkage::Import, &sqrt_sig)
            .map_err(|e| CompileError::Codegen(e.to_string()))?;
        Ok(Self {
            module,
            context: cranelift_codegen::Context::new(),
            fb_context: FunctionBuilderContext::new(),
            code_bytes: 0,
            compiled: HashMap::new(),
            ensure,
            materialize,
            sqrt,
        })
    }

    /// Return a previously compiled entry point.
    pub fn get(&self, module_id: usize, entry: usize) -> Option<NativeFn> {
        self.compiled.get(&(module_id, entry)).map(|(_, f, _)| *f)
    }

    /// Number of function bodies available for native local calls.
    pub fn compiled_count(&self) -> usize {
        self.compiled.len()
    }

    /// Machine-code bytes emitted by successful function and entry-wrapper definitions.
    pub fn code_bytes(&self) -> usize {
        self.code_bytes
    }

    /// Compile a whole function after validating every reachable instruction.
    /// An unsupported operation leaves the function interpreted.
    pub fn compile(
        &mut self,
        module_id: usize,
        beam: &BeamModule,
        entry: usize,
    ) -> Result<NativeFn, CompileError> {
        if let Some(ptr) = self.get(module_id, entry) {
            return Ok(ptr);
        }
        let start = beam
            .functions
            .iter()
            .find(|(start, _, _)| *start + 1 == entry)
            .map(|(start, _, _)| *start)
            .ok_or(CompileError::Unsupported {
                ip: entry,
                reason: "not a function entry",
            })?;
        let arity = beam
            .functions
            .iter()
            .find(|(start, _, _)| *start + 1 == entry)
            .map(|(_, _, arity)| *arity)
            .expect("validated function entry");
        let end = beam
            .functions
            .iter()
            .find(|(next, _, _)| *next > start)
            .map(|(next, _, _)| *next)
            .unwrap_or(beam.code.len() - 1);
        for ip in entry..end {
            validate(
                beam,
                beam.code[ip],
                ip,
                entry,
                end,
                &self.compiled,
                module_id,
            )?;
        }
        let mut sig = self.module.make_signature();
        sig.params.push(ir::AbiParam::new(types::I64));
        for _ in 0..arity {
            sig.params.push(ir::AbiParam::new(types::I64));
        }
        sig.returns.push(ir::AbiParam::new(types::I32));
        sig.returns.push(ir::AbiParam::new(types::I64));
        let name = format!("arinsal_m{module_id}_f{entry}");
        let func_id = self
            .module
            .declare_function(&name, Linkage::Local, &sig)
            .map_err(|e| CompileError::Codegen(e.to_string()))?;
        let reuse = matches!(
            std::env::var("ADR_JIT_MODE").as_deref(),
            Ok("reuse" | "fast_reuse")
        );
        let mut context = if reuse {
            std::mem::replace(&mut self.context, cranelift_codegen::Context::new())
        } else {
            self.module.make_context()
        };
        context.clear();
        context.func.signature = sig;
        let self_ref = self.module.declare_func_in_func(func_id, &mut context.func);
        let ensure_ref = self
            .module
            .declare_func_in_func(self.ensure, &mut context.func);
        let materialize_ref = self
            .module
            .declare_func_in_func(self.materialize, &mut context.func);
        let sqrt_ref = self
            .module
            .declare_func_in_func(self.sqrt, &mut context.func);
        let callees: HashMap<usize, (ir::FuncRef, u8)> = self
            .compiled
            .iter()
            .filter(|((mid, _), _)| *mid == module_id)
            .map(|((_, target), (id, _, arity))| {
                (
                    *target,
                    (
                        self.module.declare_func_in_func(*id, &mut context.func),
                        *arity,
                    ),
                )
            })
            .collect();
        let frontend_config = self.module.isa().frontend_config();
        let reserved_allocations = reserved_allocations(beam, entry, end);
        let window = x_root_window(beam, entry, end, arity);
        ACTIVE_X_WINDOW.with(|active| active.set(window));
        let mut fb_context = if reuse {
            std::mem::take(&mut self.fb_context)
        } else {
            FunctionBuilderContext::new()
        };
        {
            let mut b = FunctionBuilder::new(&mut context.func, &mut fb_context);
            let prologue = b.create_block();
            let blocks: Vec<_> = (entry..end).map(|_| b.create_block()).collect();
            let deopt_block = b.create_block();
            b.append_block_param(deopt_block, types::I32);
            ACTIVE_DEOPT.with(|active| active.set(Some(deopt_block)));
            let state_var = b.declare_var(types::I64);
            b.append_block_params_for_function_params(prologue);
            b.switch_to_block(prologue);
            let state = b.block_params(prologue)[0];
            b.def_var(state_var, state);
            store_root_window(&mut b, state);
            // X registers above the arity are not arguments. Clearing them
            // before this body collects keeps a wider root prefix from
            // following whatever the caller left there.
            // Port of erts/emulator/beam/erl_gc.c:2639 (setup_rootset nobj), OTP-29.1.1.
            let nil = b.ins().iconst(types::I64, 0x3b);
            let x_base = field(&mut b, state, X);
            for reg in u16::from(arity)..window {
                b.ins()
                    .store(MemFlagsData::new(), nil, x_base, i32::from(reg) * 8);
            }
            let written_x = written_x_registers(beam, entry, end);
            let arguments = b.block_params(prologue).to_vec();
            let x_count = written_x
                .last()
                .map_or(arity as usize, |reg| {
                    (usize::from(*reg) + 1).max(arity as usize)
                })
                .min(SSA_X_REGISTERS);
            let x_vars = (0..x_count)
                .map(|reg| {
                    let var = b.declare_var(types::I64);
                    let value = if reg < arity as usize {
                        arguments[reg + 1]
                    } else {
                        nil
                    };
                    b.def_var(var, value);
                    var
                })
                .collect::<Vec<_>>();
            ACTIVE_X.with(|active| *active.borrow_mut() = (x_vars, written_x));
            let y_float_vars = float_y_registers(beam, entry, end)
                .into_iter()
                .map(|reg| {
                    let value_var = b.declare_var(types::F64);
                    let flag_var = b.declare_var(types::I8);
                    let zero = b.ins().f64const(0.0);
                    let no = b.ins().iconst(types::I8, 0);
                    b.def_var(value_var, zero);
                    b.def_var(flag_var, no);
                    (reg, value_var, flag_var)
                })
                .collect::<Vec<_>>();
            ACTIVE_Y_FLOAT.with(|active| *active.borrow_mut() = y_float_vars);
            let fr_vars = float_registers(beam, entry, end)
                .into_iter()
                .map(|reg| {
                    let var = b.declare_var(types::F64);
                    let ptr = field(&mut b, state, FR);
                    let value = b
                        .ins()
                        .load(types::F64, MemFlagsData::new(), ptr, reg as i32 * 8);
                    b.def_var(var, value);
                    (reg, var)
                })
                .collect::<HashMap<_, _>>();
            ACTIVE_FR.with(|active| {
                *active.borrow_mut() = fr_vars.iter().map(|(reg, var)| (*reg, *var)).collect();
            });
            b.ins().jump(blocks[0], &[]);
            for ip in entry..end {
                b.switch_to_block(blocks[ip - entry]);
                RESERVED_ALLOCATION
                    .with(|reserved| reserved.set(reserved_allocations.contains(&ip)));
                ACTIVE_ENSURE.with(|active| active.set(Some(ensure_ref)));
                let state = b.use_var(state_var);
                let step = if matches!(beam.code[ip], Instr::MoveCallLocal { .. }) {
                    2
                } else {
                    1
                };
                let next =
                    (ip + step < end).then_some(blocks[(ip + step - entry).min(blocks.len() - 1)]);
                emit(
                    &mut b,
                    beam,
                    beam.code[ip],
                    ip,
                    entry,
                    &blocks,
                    state,
                    &fr_vars,
                    next,
                    self_ref,
                    &callees,
                    ensure_ref,
                    materialize_ref,
                    sqrt_ref,
                    module_id,
                    arity,
                );
            }
            b.switch_to_block(deopt_block);
            let state = b.use_var(state_var);
            store_root_window(&mut b, state);
            flush_x(&mut b, state);
            flush_y_floats(&mut b, state);
            flush_fr(&mut b, state);
            let ip = b.block_params(deopt_block)[0];
            b.ins().store(MemFlagsData::new(), ip, state, IP);
            let slow = b.ins().iconst(types::I32, 1);
            let result = b.ins().iconst(types::I64, 0);
            b.ins().return_(&[slow, result]);
            b.seal_all_blocks();
            b.finalize(frontend_config);
            RESERVED_ALLOCATION.with(|reserved| reserved.set(false));
            ACTIVE_ENSURE.with(|active| active.set(None));
            ACTIVE_DEOPT.with(|active| active.set(None));
            ACTIVE_FR.with(|active| active.borrow_mut().clear());
            ACTIVE_X.with(|active| *active.borrow_mut() = (Vec::new(), Vec::new()));
            ACTIVE_Y_FLOAT.with(|active| active.borrow_mut().clear());
            ACTIVE_X_WINDOW.with(|active| active.set(0));
        }
        self.module
            .define_function(func_id, &mut context)
            .map_err(|e| CompileError::Codegen(format!("{e:?}")))?;
        self.code_bytes += context.compiled_code().unwrap().code_buffer().len();
        if reuse {
            self.context = context;
            self.fb_context = fb_context;
        }
        let mut wrapper_sig = self.module.make_signature();
        wrapper_sig.params.push(ir::AbiParam::new(types::I64));
        wrapper_sig.returns.push(ir::AbiParam::new(types::I32));
        let wrapper_id = self
            .module
            .declare_function(&format!("{name}_entry"), Linkage::Local, &wrapper_sig)
            .map_err(|e| CompileError::Codegen(e.to_string()))?;
        let mut wrapper_context = self.module.make_context();
        wrapper_context.func.signature = wrapper_sig;
        let fast_ref = self
            .module
            .declare_func_in_func(func_id, &mut wrapper_context.func);
        let mut wrapper_fb_context = FunctionBuilderContext::new();
        {
            let mut b = FunctionBuilder::new(&mut wrapper_context.func, &mut wrapper_fb_context);
            let block = b.create_block();
            b.append_block_params_for_function_params(block);
            b.switch_to_block(block);
            let state = b.block_params(block)[0];
            let mut args = vec![state];
            for reg in 0..arity {
                let ptr = field(&mut b, state, X);
                args.push(
                    b.ins()
                        .load(types::I64, MemFlagsData::new(), ptr, reg as i32 * 8),
                );
            }
            let call = b.ins().call(fast_ref, &args);
            let status = b.inst_results(call)[0];
            let result = b.inst_results(call)[1];
            let success = b.ins().icmp_imm_s(IntCC::Equal, status, 0);
            let write = b.create_block();
            let done = b.create_block();
            b.ins().brif(success, write, &[], done, &[]);
            b.switch_to_block(write);
            let ptr = field(&mut b, state, X);
            b.ins().store(MemFlagsData::new(), result, ptr, 0);
            b.ins().jump(done, &[]);
            b.switch_to_block(done);
            b.ins().return_(&[status]);
            b.seal_all_blocks();
            b.finalize(frontend_config);
        }
        self.module
            .define_function(wrapper_id, &mut wrapper_context)
            .map_err(|e| CompileError::Codegen(format!("{e:?}")))?;
        self.code_bytes += wrapper_context.compiled_code().unwrap().code_buffer().len();
        self.module
            .finalize_definitions()
            .map_err(|e| CompileError::Codegen(e.to_string()))?;
        let address = self.module.get_finalized_function(wrapper_id);
        // SAFETY: Cranelift emitted a function with exactly the declared C ABI
        // signature, and this engine retains the executable allocation.
        let function: NativeFn = unsafe { std::mem::transmute(address) };
        self.compiled
            .insert((module_id, entry), (func_id, function, arity));
        Ok(function)
    }
}

fn float_registers(beam: &BeamModule, entry: usize, end: usize) -> BTreeSet<u16> {
    let mut regs = BTreeSet::new();
    for instr in &beam.code[entry..end] {
        match *instr {
            Instr::GetTupleFloat { dst_fr, .. }
            | Instr::FmoveXFr { dst: dst_fr, .. }
            | Instr::FmoveYFr { dst: dst_fr, .. }
            | Instr::FmoveCFr { dst: dst_fr, .. } => {
                regs.insert(dst_fr);
            }
            Instr::FmoveFrX { src, .. } | Instr::FmoveFrY { src, .. } => {
                regs.insert(src);
            }
            Instr::FmoveFrFr { src, dst } => {
                regs.extend([src, dst]);
            }
            Instr::Fadd { a, b, dst }
            | Instr::Fsub { a, b, dst }
            | Instr::Fmul { a, b, dst }
            | Instr::Fdiv { a, b, dst }
            | Instr::FloatBin { a, b, dst, .. } => {
                regs.extend([a, b, dst]);
            }
            Instr::Generic(index) => {
                let op = beam.generic[index as usize];
                for arg in op.args.iter().chain(
                    beam.tails
                        .get((op.meta & 0x00ff_ffff) as usize)
                        .into_iter()
                        .flat_map(|tail| tail.iter()),
                ) {
                    if arg.kind() == Arg::FR && arg.value() < 1024 {
                        regs.insert(arg.value() as u16);
                    }
                }
            }
            _ => {}
        }
    }
    regs
}

fn float_y_registers(beam: &BeamModule, entry: usize, end: usize) -> BTreeSet<u16> {
    let mut regs = BTreeSet::new();
    for &instr in &beam.code[entry..end] {
        match instr {
            Instr::FmoveFrY { dst, .. } => {
                regs.insert(dst);
            }
            Instr::Generic(index) => {
                if let Some((src, dst)) = decode_generic_fmove(beam, index)
                    && src.kind() == Arg::FR
                    && dst.kind() == Arg::Y
                {
                    regs.insert(dst.value() as u16);
                }
            }
            _ => {}
        }
    }
    regs
}

/// X registers a native body may still hold across any collection inside it.
///
/// Port of erts/emulator/beam/emu/macros.tab:85 (`GC_TEST` `$Live`) and
/// erts/emulator/beam/erl_gc.c:2639 (`setup_rootset` `nobj`), OTP-29.1.1.
/// The prefix covers every X index the body names and every BEAM `Live`
/// operand, so a nil-fill cannot drop a register the body reloads.
fn widen(window: &mut u16, reg: u16) {
    if reg < 1024 {
        *window = (*window).max(reg.saturating_add(1));
    }
}

fn widen_count(window: &mut u16, live: u16) {
    *window = (*window).max(live);
}

fn x_root_window(beam: &BeamModule, entry: usize, end: usize, arity: u8) -> u16 {
    let mut window = u16::from(arity);
    for &instr in &beam.code[entry..end] {
        match instr {
            Instr::MoveXX { src, dst }
            | Instr::MoveCallLocal { src, dst, .. }
            | Instr::SwapXX { a: src, b: dst }
            | Instr::IsLtXX { a: src, b: dst, .. }
            | Instr::IsGeXX { a: src, b: dst, .. }
            | Instr::IsEqXX { a: src, b: dst, .. }
            | Instr::IsNeXX { a: src, b: dst, .. }
            | Instr::IsEqExactXX { a: src, b: dst, .. }
            | Instr::IsNeExactXX { a: src, b: dst, .. } => {
                widen(&mut window, src);
                widen(&mut window, dst);
            }
            Instr::ArithXXX { a, b, dst, .. } => {
                widen(&mut window, a);
                widen(&mut window, b);
                widen(&mut window, dst);
            }
            Instr::MoveYX { dst, .. }
            | Instr::MoveCX { dst, .. }
            | Instr::GetTupleElementYX { dst, .. }
            | Instr::IsLtXC { a: dst, .. }
            | Instr::IsLtXCReturn { a: dst, .. }
            | Instr::IsGeXC { a: dst, .. }
            | Instr::IsEqXC { a: dst, .. }
            | Instr::IsNeXC { a: dst, .. }
            | Instr::IsEqExactXC { a: dst, .. }
            | Instr::IsNeExactXC { a: dst, .. }
            | Instr::FmoveFrX { dst, .. } => widen(&mut window, dst),
            Instr::PutTuple { list, dst } => {
                widen(&mut window, dst);
                if let Some(items) = beam.lists.get(list as usize) {
                    for item in items {
                        note_arg_window(beam, *item, &mut window);
                    }
                }
            }
            Instr::MoveXY { src, .. }
            | Instr::GetTupleElementXY { src, .. }
            | Instr::IsLtCX { b: src, .. }
            | Instr::IsGeCX { b: src, .. }
            | Instr::IsEqCX { b: src, .. }
            | Instr::IsNeCX { b: src, .. }
            | Instr::IsEqExactCX { b: src, .. }
            | Instr::IsNeExactCX { b: src, .. }
            | Instr::FmoveXFr { src, .. }
            | Instr::IsTupleX { src, .. }
            | Instr::IsNilX { src, .. }
            | Instr::IsNonemptyListX { src, .. }
            | Instr::IsIntegerX { src, .. } => widen(&mut window, src),
            Instr::SwapYX { x, .. } => widen(&mut window, x),
            Instr::Allocate { live, .. } | Instr::TestHeap { live, .. } => {
                widen_count(&mut window, live)
            }
            Instr::GetTupleElementXX { src, dst, .. }
            | Instr::GetHdXX { src, dst }
            | Instr::GetTlXX { src, dst } => {
                widen(&mut window, src);
                widen(&mut window, dst);
            }
            Instr::GetTupleFloat { src, dst_x, .. } => {
                widen(&mut window, src);
                widen(&mut window, dst_x);
            }
            Instr::PutTupleXX { a, b, dst }
            | Instr::GetListXXX {
                src: a,
                head: b,
                tail: dst,
            } => {
                widen(&mut window, a);
                widen(&mut window, b);
                widen(&mut window, dst);
            }
            Instr::PutListXXX { head, tail, dst } => {
                widen(&mut window, head);
                widen(&mut window, tail);
                widen(&mut window, dst);
            }
            Instr::PutList { head, tail, dst } => {
                if head.kind() == Arg::X {
                    widen(&mut window, head.value() as u16);
                }
                if tail.kind() == Arg::X {
                    widen(&mut window, tail.value() as u16);
                }
                widen(&mut window, dst);
            }
            Instr::GetList { src, head, tail } => {
                widen(&mut window, src);
                if head.kind() == Arg::X {
                    widen(&mut window, head.value() as u16);
                }
                if tail.kind() == Arg::X {
                    widen(&mut window, tail.value() as u16);
                }
            }
            Instr::ArithYXX { b, dst, .. } => {
                widen(&mut window, b);
                widen(&mut window, dst);
            }
            Instr::ArithRC {
                src, from_y, dst, ..
            }
            | Instr::ArithRCY {
                src, from_y, dst, ..
            } => {
                if !from_y {
                    widen(&mut window, src);
                }
                if matches!(instr, Instr::ArithRC { .. }) {
                    widen(&mut window, dst);
                }
            }
            Instr::IsTupleOfArity { src, .. } | Instr::TestArityX { src, .. } => {
                widen(&mut window, src)
            }
            Instr::Select { src, from_y, .. } => {
                if !from_y {
                    widen(&mut window, src);
                }
            }
            Instr::CallExternal { arity, .. } | Instr::CallFun { arity, .. } => {
                widen_count(&mut window, arity)
            }
            Instr::Apply { arity, .. } => widen_count(&mut window, arity.saturating_add(2)),
            Instr::BsEnsure { context, .. }
            | Instr::BsReadU32 { context, .. }
            | Instr::BsReadUint { context, .. }
            | Instr::BsStartReuse {
                source: context, ..
            }
            | Instr::BsPositionSmall { context, .. } => widen(&mut window, context),
            Instr::BsAppendByte { source, dst, .. } => {
                widen(&mut window, source);
                widen(&mut window, dst);
            }
            Instr::BsBinaryReg {
                context,
                size,
                dst,
                live,
                ..
            } => {
                widen(&mut window, context);
                widen(&mut window, size);
                widen(&mut window, dst);
                widen_count(&mut window, live);
            }
            Instr::BsTail {
                context, dst, live, ..
            }
            | Instr::BsMatchTail {
                context, dst, live, ..
            } => {
                widen(&mut window, context);
                widen(&mut window, dst);
                widen_count(&mut window, live);
            }
            Instr::Send => widen_count(&mut window, 2),
            Instr::MakeFun { dst, .. } if dst.kind() == Arg::X => {
                widen(&mut window, dst.value() as u16);
            }
            Instr::Generic(index) | Instr::MapsBits(index) => {
                note_generic_window(beam, index, &mut window);
            }
            Instr::LoopRec { dst, .. } if dst.kind() == Arg::X => {
                widen(&mut window, dst.value() as u16);
            }
            _ => {}
        }
    }
    window
}

fn note_generic_window(beam: &BeamModule, index: u32, window: &mut u16) {
    let Some(op) = beam.generic.get(index as usize) else {
        return;
    };
    let note_count = |arg: Arg, window: &mut u16| {
        if arg.kind() == Arg::U && arg.value() <= 1024 {
            *window = (*window).max(arg.value() as u16);
        }
    };
    match op.opcode() {
        Opcode::GcBif1 | Opcode::GcBif2 | Opcode::GcBif3 | Opcode::TestHeap | Opcode::Allocate => {
            note_count(op.args[1], window);
        }
        Opcode::AllocateHeap => note_count(op.args[2], window),
        _ => {}
    }
    for arg in op.args {
        note_arg_window(beam, arg, window);
    }
    if let Some(tail) = beam.tails.get((op.meta & 0x00ff_ffff) as usize) {
        for arg in tail {
            note_arg_window(beam, *arg, window);
        }
    }
}

fn note_arg_window(beam: &BeamModule, arg: Arg, window: &mut u16) {
    match arg.kind() {
        Arg::X if arg.value() < 1024 => {
            *window = (*window).max((arg.value() as u16).saturating_add(1));
        }
        Arg::LIST => {
            if let Some(items) = beam.lists.get(arg.value() as usize) {
                for item in items {
                    note_arg_window(beam, *item, window);
                }
            }
        }
        _ => {}
    }
}

fn written_x_registers(beam: &BeamModule, entry: usize, end: usize) -> Vec<u16> {
    let mut written = BTreeSet::new();
    // Native callees return X0 in a machine register, so it must be copied to
    // the GC root array before another call even without an explicit BEAM move.
    written.insert(0);
    for &instr in &beam.code[entry..end] {
        match instr {
            Instr::MoveXX { dst, .. }
            | Instr::MoveYX { dst, .. }
            | Instr::MoveCX { dst, .. }
            | Instr::MoveCallLocal { dst, .. }
            | Instr::GetTupleElementXX { dst, .. }
            | Instr::GetTupleElementYX { dst, .. }
            | Instr::PutTupleXX { dst, .. }
            | Instr::PutTuple { dst, .. }
            | Instr::PutListXXX { dst, .. }
            | Instr::PutList { dst, .. }
            | Instr::GetHdXX { dst, .. }
            | Instr::GetTlXX { dst, .. }
            | Instr::FmoveFrX { dst, .. }
            | Instr::ArithXXX { dst, .. }
            | Instr::ArithYXX { dst, .. }
            | Instr::ArithRC { dst, .. } => {
                written.insert(dst);
            }
            Instr::SwapXX { a, b } => {
                written.extend([a, b]);
            }
            Instr::SwapYX { x, .. } => {
                written.insert(x);
            }
            Instr::GetTupleFloat { dst_x, .. } => {
                written.insert(dst_x);
            }
            Instr::GetListXXX { head, tail, .. } => {
                written.extend([head, tail]);
            }
            Instr::GetList { head, tail, .. } => {
                for arg in [head, tail] {
                    if arg.kind() == Arg::X {
                        written.insert(arg.value() as u16);
                    }
                }
            }
            Instr::CallExternal { import, .. } => {
                let called = &beam.imports[import as usize];
                if (called.module == "math" && called.function == "sqrt")
                    || (called.module == "lists" && called.function == "reverse")
                {
                    written.insert(0);
                }
            }
            Instr::Generic(index) => {
                let dst = decode_generic_arith(beam, index)
                    .map(|(_, _, _, reg)| Dest::X(reg))
                    .or_else(|| {
                        decode_generic_fmove(beam, index).and_then(|(_, dst)| destination(dst))
                    })
                    .or_else(|| decode_generic_tuple(beam, index).map(|(dst, _)| dst))
                    .or_else(|| decode_generic_get_tuple(beam, index).map(|(_, _, dst)| dst))
                    .or_else(|| decode_generic_list(beam, index).map(|(_, _, dst)| dst));
                if let Some(Dest::X(reg)) = dst {
                    written.insert(reg);
                }
                if let Some((a, b)) = decode_generic_swap(beam, index) {
                    for dst in [a, b] {
                        if let Dest::X(reg) = dst {
                            written.insert(reg);
                        }
                    }
                }
                if let Some((_, head, tail)) = decode_generic_get_list(beam, index) {
                    for dst in [head, tail] {
                        if let Dest::X(reg) = dst {
                            written.insert(reg);
                        }
                    }
                }
            }
            _ => {}
        }
    }
    written
        .into_iter()
        .filter(|reg| (*reg as usize) < SSA_X_REGISTERS)
        .collect()
}

fn allocation_words(beam: &BeamModule, instr: Instr) -> Option<u32> {
    match instr {
        Instr::PutTupleXX { .. } => Some(3),
        Instr::PutTuple { list, .. } => Some(beam.lists[list as usize].len() as u32 + 1),
        Instr::PutListXXX { .. } | Instr::PutList { .. } => Some(2),
        Instr::FmoveFrX { .. } | Instr::FmoveFrY { .. } => Some(2),
        Instr::Generic(index) => {
            if let Some((_, fields)) = decode_generic_tuple(beam, index) {
                Some(fields.len() as u32 + 1)
            } else if decode_generic_list(beam, index).is_some()
                || decode_generic_fmove(beam, index)
                    .is_some_and(|(src, dst)| src.kind() == Arg::FR && dst.kind() != Arg::FR)
            {
                Some(2)
            } else {
                None
            }
        }
        _ => None,
    }
}

fn branch_targets(beam: &BeamModule, entry: usize, end: usize) -> BTreeSet<usize> {
    let mut targets = BTreeSet::new();
    for &instr in &beam.code[entry..end] {
        let one = match instr {
            Instr::Jump { target }
            | Instr::CallLocal { target }
            | Instr::CallLast { target, .. }
            | Instr::CallOnly { target }
            | Instr::MoveCallLocal { target, .. } => Some(target),
            Instr::IsLtXX { fail, .. }
            | Instr::IsLtXC { fail, .. }
            | Instr::IsLtCX { fail, .. }
            | Instr::IsLtXCReturn { fail, .. }
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
            | Instr::IsNeExactCX { fail, .. }
            | Instr::IsTupleX { fail, .. }
            | Instr::IsNilX { fail, .. }
            | Instr::IsNonemptyListX { fail, .. }
            | Instr::IsIntegerX { fail, .. }
            | Instr::TestArityX { fail, .. } => Some(fail),
            Instr::IsTupleOfArity {
                fail_type,
                fail_arity,
                ..
            } => {
                targets.extend([fail_type as usize, fail_arity as usize]);
                None
            }
            Instr::Select {
                table, fallback, ..
            } => {
                targets.insert(fallback as usize);
                if let Some(entries) = select_entries(beam, table) {
                    targets.extend(entries.into_iter().map(|(_, target)| target as usize));
                }
                None
            }
            Instr::Generic(index) => decode_generic_type_test(beam, index)
                .map(|(_, _, fail)| fail)
                .or_else(|| decode_generic_test_arity(beam, index).map(|(_, _, fail)| fail)),
            _ => None,
        };
        if let Some(target) = one {
            targets.insert(target as usize);
        }
    }
    targets
}

fn reserved_allocations(beam: &BeamModule, entry: usize, end: usize) -> BTreeSet<usize> {
    let targets = branch_targets(beam, entry, end);
    let mut reserved = BTreeSet::new();
    let mut remaining = 0;
    for ip in entry..end {
        if targets.contains(&ip) {
            remaining = 0;
        }
        let instr = beam.code[ip];
        match instr {
            Instr::TestHeap { words, .. } | Instr::Allocate { words, .. } => {
                remaining = words;
            }
            _ => {
                if let Some(words) = allocation_words(beam, instr) {
                    if words <= remaining {
                        reserved.insert(ip);
                        remaining -= words;
                    } else {
                        remaining = 0;
                    }
                }
                if matches!(
                    instr,
                    Instr::CallLocal { .. }
                        | Instr::CallLast { .. }
                        | Instr::CallOnly { .. }
                        | Instr::MoveCallLocal { .. }
                        | Instr::CallExternal { .. }
                        | Instr::Jump { .. }
                        | Instr::ReturnInstr
                        | Instr::DeallocateReturn { .. }
                        | Instr::Select { .. }
                        | Instr::GetTupleFloat { .. }
                ) {
                    remaining = 0;
                }
            }
        }
    }
    reserved
}

fn validate(
    beam: &BeamModule,
    instr: Instr,
    ip: usize,
    entry: usize,
    end: usize,
    compiled: &HashMap<(usize, usize), (FuncId, NativeFn, u8)>,
    module_id: usize,
) -> Result<(), CompileError> {
    let target_valid = |target: u32| (entry..end).contains(&(target as usize));
    let branch_valid = |target: u32| target == u32::MAX || (target as usize) < beam.code.len();
    if let Instr::MoveCallLocal { target, .. }
    | Instr::CallLocal { target }
    | Instr::CallLast { target, .. }
    | Instr::CallOnly { target } = instr
        && target as usize != entry
        && !compiled.contains_key(&(module_id, target as usize))
    {
        return Err(CompileError::PendingDependency {
            target: target as usize,
        });
    }
    let supported = match instr {
        Instr::MoveXX { .. }
        | Instr::MoveYX { .. }
        | Instr::MoveXY { .. }
        | Instr::MoveYY { .. }
        | Instr::MoveCX { .. }
        | Instr::MoveCY { .. }
        | Instr::SwapXX { .. }
        | Instr::SwapYX { .. }
        | Instr::ReturnInstr
        | Instr::DeallocateReturn { .. }
        | Instr::Allocate { .. }
        | Instr::Deallocate { .. }
        | Instr::Trim { .. }
        | Instr::InitYregs { .. }
        | Instr::TestHeap { .. }
        | Instr::GetTupleElementXX { .. }
        | Instr::GetTupleElementYX { .. }
        | Instr::GetTupleElementXY { .. }
        | Instr::GetTupleFloat { .. }
        | Instr::PutTupleXX { .. }
        | Instr::PutTuple { .. }
        | Instr::PutListXXX { .. }
        | Instr::PutList { .. }
        | Instr::GetListXXX { .. }
        | Instr::GetList { .. }
        | Instr::GetHdXX { .. }
        | Instr::GetTlXX { .. }
        | Instr::FmoveXFr { .. }
        | Instr::FmoveYFr { .. }
        | Instr::FmoveCFr { .. }
        | Instr::FmoveFrX { .. }
        | Instr::FmoveFrY { .. }
        | Instr::FmoveFrFr { .. }
        | Instr::Fadd { .. }
        | Instr::Fsub { .. }
        | Instr::Fmul { .. }
        | Instr::Fdiv { .. }
        | Instr::FloatBin { .. }
        | Instr::CodeEnd => true,
        Instr::CallExternal {
            import,
            arity,
            dealloc,
            tail,
        } => {
            let called = &beam.imports[import as usize];
            !tail
                && arity == 1
                && dealloc == 0
                && ((called.module == "math" && called.function == "sqrt")
                    || (called.module == "lists" && called.function == "reverse"))
        }
        Instr::Jump { target } => target_valid(target),
        Instr::MoveCallLocal { target, .. }
        | Instr::CallLocal { target }
        | Instr::CallLast { target, .. }
        | Instr::CallOnly { target } => {
            target as usize == entry || compiled.contains_key(&(module_id, target as usize))
        }
        Instr::IsLtXX { fail, .. }
        | Instr::IsLtXC { fail, .. }
        | Instr::IsLtXCReturn { fail, .. }
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
        | Instr::IsNeExactCX { fail, .. } => branch_valid(fail),
        Instr::ArithXXX { kind, .. }
        | Instr::ArithYXX { kind, .. }
        | Instr::ArithRC { kind, .. }
        | Instr::ArithRCY { kind, .. } => {
            matches!(kind, FastBif::Add | FastBif::Sub | FastBif::Mul)
        }
        Instr::IsTupleX { fail, .. }
        | Instr::IsNilX { fail, .. }
        | Instr::IsNonemptyListX { fail, .. }
        | Instr::IsIntegerX { fail, .. }
        | Instr::TestArityX { fail, .. } => branch_valid(fail),
        Instr::IsTupleOfArity {
            fail_type,
            fail_arity,
            ..
        } => branch_valid(fail_type) && branch_valid(fail_arity),
        Instr::Select {
            table, fallback, ..
        } => select_entries(beam, table).is_some_and(|entries| {
            (fallback == u32::MAX || target_valid(fallback))
                && entries.iter().all(|(_, target)| target_valid(*target))
        }),
        Instr::Generic(index) => {
            decode_generic_arith(beam, index).is_some()
                || decode_generic_fmove(beam, index).is_some()
                || decode_generic_tuple(beam, index).is_some()
                || decode_generic_get_tuple(beam, index).is_some()
                || decode_generic_list(beam, index).is_some()
                || decode_generic_type_test(beam, index)
                    .is_some_and(|(_, _, fail)| fail == u32::MAX || target_valid(fail))
                || decode_generic_init_yregs(beam, index).is_some()
                || decode_generic_swap(beam, index).is_some()
                || decode_generic_get_list(beam, index).is_some()
                || decode_generic_test_arity(beam, index)
                    .is_some_and(|(_, _, fail)| fail == u32::MAX || target_valid(fail))
                || decode_generic_fnegate(beam, index).is_some()
        }
        _ => false,
    };
    if supported {
        Ok(())
    } else {
        Err(CompileError::Unsupported {
            ip,
            reason: "opcode or control target outside native subset",
        })
    }
}

fn select_entries(beam: &BeamModule, table: u32) -> Option<Vec<(u64, u32)>> {
    let entries = match beam.selects.get(table as usize)? {
        SelectTable::Linear(entries) => entries
            .iter()
            .map(|(term, target)| {
                if term.is_pointer() {
                    return None;
                }
                // SAFETY: Immediate terms contain no heap address.
                Some((unsafe { term.raw_bits() }, *target))
            })
            .collect::<Option<Vec<_>>>()?,
        SelectTable::Sorted(entries) => entries.clone(),
        SelectTable::Dense { min, targets } => targets
            .iter()
            .enumerate()
            .filter(|(_, target)| **target != u32::MAX)
            .map(|(i, target)| {
                let value = min.checked_add(i as i64)?;
                // SAFETY: These dense keys are tagged small integers.
                Some((unsafe { Term::small(value)?.raw_bits() }, *target))
            })
            .collect::<Option<Vec<_>>>()?,
    };
    (entries.len() <= 64).then_some(entries)
}

#[derive(Clone, Copy)]
enum Source {
    X(u16),
    Y(u16),
    Constant(Term),
}

#[derive(Clone, Copy)]
enum Dest {
    X(u16),
    Y(u16),
}

fn destination(arg: Arg) -> Option<Dest> {
    let reg = u16::try_from(arg.value()).ok().filter(|n| *n < 1024)?;
    match arg.kind() {
        Arg::X => Some(Dest::X(reg)),
        Arg::Y => Some(Dest::Y(reg)),
        _ => None,
    }
}

fn write_dest(b: &mut FunctionBuilder<'_>, state: ir::Value, dst: Dest, value: ir::Value) {
    match dst {
        Dest::X(reg) => x_write(b, state, reg, value),
        Dest::Y(reg) => y_write(b, state, reg, value),
    }
}

fn source(arg: Arg) -> Option<Source> {
    let reg = || u16::try_from(arg.value()).ok().filter(|n| *n < 1024);
    match arg.kind() {
        Arg::X => Some(Source::X(reg()?)),
        Arg::Y => Some(Source::Y(reg()?)),
        Arg::TERM => Some(Source::Constant(arg.term())),
        Arg::INT => Some(Source::Constant(Term::small(arg.signed())?)),
        _ => None,
    }
}

fn decode_generic_arith(beam: &BeamModule, index: u32) -> Option<(FastBif, Source, Source, u16)> {
    let op = beam.generic.get(index as usize)?;
    let (import, first, dst) = match op.opcode() {
        Opcode::GcBif2 => (op.args[2], 3, 5),
        Opcode::Bif2 => (op.args[1], 2, 4),
        _ => return None,
    };
    if import.kind() != Arg::U {
        return None;
    }
    let kind = beam.imports.get(import.value() as usize)?.fast;
    if !matches!(kind, FastBif::Add | FastBif::Sub | FastBif::Mul) {
        return None;
    }
    let lhs = source(beam.arg(op, first))?;
    let rhs = source(beam.arg(op, first + 1))?;
    let dst = beam.arg(op, dst);
    if dst.kind() != Arg::X {
        return None;
    }
    let dst = u16::try_from(dst.value()).ok().filter(|n| *n < 1024)?;
    Some((kind, lhs, rhs, dst))
}

fn decode_generic_fmove(beam: &BeamModule, index: u32) -> Option<(Arg, Arg)> {
    let op = beam.generic.get(index as usize)?;
    if !matches!(op.opcode(), Opcode::Fmove | Opcode::Fconv) {
        return None;
    }
    let [src, dst, _] = op.args;
    if dst.kind() == Arg::FR && dst.value() < 1024 {
        match src.kind() {
            Arg::X | Arg::Y | Arg::FR if src.value() < 1024 => Some((src, dst)),
            Arg::TERM if src.term().as_small().is_some() => Some((src, dst)),
            // SAFETY: the module owns the immutable literal area.
            Arg::TERM if unsafe { src.term().float_ref() }.is_some() => Some((src, dst)),
            _ => None,
        }
    } else if src.kind() == Arg::FR && src.value() < 1024 && destination(dst).is_some() {
        Some((src, dst))
    } else {
        None
    }
}

fn decode_generic_tuple(beam: &BeamModule, index: u32) -> Option<(Dest, Vec<Source>)> {
    let op = beam.generic.get(index as usize)?;
    if op.opcode() != Opcode::PutTuple2 {
        return None;
    }
    let dst = destination(op.args[0])?;
    let list = op.args[1];
    if list.kind() != Arg::LIST {
        return None;
    }
    let fields = beam.lists.get(list.value() as usize)?;
    if fields.len() > 255 {
        return None;
    }
    Some((
        dst,
        fields.iter().copied().map(source).collect::<Option<_>>()?,
    ))
}

fn decode_generic_get_tuple(beam: &BeamModule, index: u32) -> Option<(Source, u16, Dest)> {
    let op = beam.generic.get(index as usize)?;
    if op.opcode() != Opcode::GetTupleElement {
        return None;
    }
    let [src, position, dst] = op.args;
    if position.kind() != Arg::U {
        return None;
    }
    Some((
        source(src)?,
        u16::try_from(position.value()).ok()?,
        destination(dst)?,
    ))
}

fn decode_generic_list(beam: &BeamModule, index: u32) -> Option<(Source, Source, Dest)> {
    let op = beam.generic.get(index as usize)?;
    if op.opcode() != Opcode::PutList {
        return None;
    }
    let [head, tail, dst] = op.args;
    Some((source(head)?, source(tail)?, destination(dst)?))
}

fn decode_generic_type_test(beam: &BeamModule, index: u32) -> Option<(Opcode, Source, u32)> {
    let op = beam.generic.get(index as usize)?;
    let kind = op.opcode();
    if !matches!(
        kind,
        Opcode::IsTuple
            | Opcode::IsNil
            | Opcode::IsNonemptyList
            | Opcode::IsList
            | Opcode::IsInteger
            | Opcode::IsFloat
            | Opcode::IsNumber
            | Opcode::IsAtom
    ) {
        return None;
    }
    let [fail, src, _] = op.args;
    if fail.kind() != Arg::LABEL {
        return None;
    }
    Some((kind, source(src)?, fail.value() as u32))
}

fn decode_generic_init_yregs(beam: &BeamModule, index: u32) -> Option<Vec<u16>> {
    let op = beam.generic.get(index as usize)?;
    if op.opcode() != Opcode::InitYregs || op.args[0].kind() != Arg::LIST {
        return None;
    }
    beam.lists
        .get(op.args[0].value() as usize)?
        .iter()
        .map(|arg| {
            (arg.kind() == Arg::Y)
                .then(|| u16::try_from(arg.value()).ok().filter(|n| *n < 1024))
                .flatten()
        })
        .collect()
}

fn decode_generic_swap(beam: &BeamModule, index: u32) -> Option<(Dest, Dest)> {
    let op = beam.generic.get(index as usize)?;
    (op.opcode() == Opcode::Swap)
        .then(|| Some((destination(op.args[0])?, destination(op.args[1])?)))?
}

fn decode_generic_get_list(beam: &BeamModule, index: u32) -> Option<(Source, Dest, Dest)> {
    let op = beam.generic.get(index as usize)?;
    (op.opcode() == Opcode::GetList).then(|| {
        Some((
            source(op.args[0])?,
            destination(op.args[1])?,
            destination(op.args[2])?,
        ))
    })?
}

fn decode_generic_test_arity(beam: &BeamModule, index: u32) -> Option<(Source, u16, u32)> {
    let op = beam.generic.get(index as usize)?;
    if op.opcode() != Opcode::TestArity
        || op.args[0].kind() != Arg::LABEL
        || op.args[2].kind() != Arg::U
    {
        return None;
    }
    Some((
        source(op.args[1])?,
        u16::try_from(op.args[2].value()).ok()?,
        op.args[0].value() as u32,
    ))
}

fn decode_generic_fnegate(beam: &BeamModule, index: u32) -> Option<(u16, u16)> {
    let op = beam.generic.get(index as usize)?;
    if op.opcode() != Opcode::Fnegate
        || op.args[1].kind() != Arg::FR
        || op.args[2].kind() != Arg::FR
    {
        return None;
    }
    Some((
        u16::try_from(op.args[1].value())
            .ok()
            .filter(|n| *n < 1024)?,
        u16::try_from(op.args[2].value())
            .ok()
            .filter(|n| *n < 1024)?,
    ))
}

fn read_source(b: &mut FunctionBuilder<'_>, state: ir::Value, src: Source) -> ir::Value {
    match src {
        Source::X(reg) => x_read(b, state, reg),
        Source::Y(reg) => y_read(b, state, reg),
        Source::Constant(term) => {
            // SAFETY: the immutable BEAM module retains any literal's heap.
            b.ins()
                .iconst(types::I64, unsafe { term.raw_bits() } as i64)
        }
    }
}

const X: i32 = std::mem::offset_of!(JitState, x) as i32;
const FR: i32 = std::mem::offset_of!(JitState, fr) as i32;
const STOP: i32 = std::mem::offset_of!(JitState, stop) as i32;
const HTOP: i32 = std::mem::offset_of!(JitState, htop) as i32;
const STACK_END: i32 = std::mem::offset_of!(JitState, stack_end) as i32;
const REDS: i32 = std::mem::offset_of!(JitState, reds) as i32;
const IP: i32 = std::mem::offset_of!(JitState, ip) as i32;
const DEPTH: i32 = std::mem::offset_of!(JitState, depth) as i32;
const X_LIVE: i32 = std::mem::offset_of!(JitState, x_live) as i32;

fn root_window() -> u16 {
    ACTIVE_X_WINDOW.with(Cell::get)
}

fn store_root_window(b: &mut FunctionBuilder<'_>, state: ir::Value) {
    let window = b.ins().iconst(types::I32, i64::from(root_window()));
    b.ins().store(MemFlagsData::new(), window, state, X_LIVE);
}

fn field(b: &mut FunctionBuilder<'_>, state: ir::Value, offset: i32) -> ir::Value {
    b.ins().load(types::I64, MemFlagsData::new(), state, offset)
}
fn x_read(b: &mut FunctionBuilder<'_>, state: ir::Value, reg: u16) -> ir::Value {
    if let Some(var) = ACTIVE_X.with(|active| active.borrow().0.get(reg as usize).copied()) {
        return b.use_var(var);
    }
    let ptr = field(b, state, X);
    b.ins()
        .load(types::I64, MemFlagsData::new(), ptr, reg as i32 * 8)
}
fn x_write(b: &mut FunctionBuilder<'_>, state: ir::Value, reg: u16, value: ir::Value) {
    if let Some(var) = ACTIVE_X.with(|active| active.borrow().0.get(reg as usize).copied()) {
        b.def_var(var, value);
        return;
    }
    let ptr = field(b, state, X);
    b.ins()
        .store(MemFlagsData::new(), value, ptr, reg as i32 * 8);
}
fn flush_x(b: &mut FunctionBuilder<'_>, state: ir::Value) {
    ACTIVE_X.with(|active| {
        let active = active.borrow();
        for reg in &active.1 {
            let value = b.use_var(active.0[*reg as usize]);
            let ptr = field(b, state, X);
            b.ins()
                .store(MemFlagsData::new(), value, ptr, *reg as i32 * 8);
        }
    });
}
fn reload_x(b: &mut FunctionBuilder<'_>, state: ir::Value, live: u16) {
    ACTIVE_X.with(|active| {
        for (reg, var) in active.borrow().0.iter().enumerate() {
            // Registers outside this collection's root prefix were not updated.
            // Reloading them would replace a still-valid SSA immediate with NIL.
            if reg >= usize::from(live) {
                break;
            }
            let ptr = field(b, state, X);
            let value = b
                .ins()
                .load(types::I64, MemFlagsData::new(), ptr, reg as i32 * 8);
            b.def_var(*var, value);
        }
    });
}
fn reload_x_after_call(b: &mut FunctionBuilder<'_>, state: ir::Value) {
    ACTIVE_X.with(|active| {
        for (reg, var) in active.borrow().0.iter().enumerate().skip(1) {
            let ptr = field(b, state, X);
            let value = b
                .ins()
                .load(types::I64, MemFlagsData::new(), ptr, reg as i32 * 8);
            b.def_var(*var, value);
        }
    });
}
fn y_read(b: &mut FunctionBuilder<'_>, state: ir::Value, reg: u16) -> ir::Value {
    materialize_y_reg(b, state, reg);
    let ptr = field(b, state, STOP);
    b.ins()
        .load(types::I64, MemFlagsData::new(), ptr, reg as i32 * 8)
}
fn y_write(b: &mut FunctionBuilder<'_>, state: ir::Value, reg: u16, value: ir::Value) {
    if let Some((_, flag)) = y_float_vars(reg) {
        let no = b.ins().iconst(types::I8, 0);
        b.def_var(flag, no);
    }
    let ptr = field(b, state, STOP);
    b.ins()
        .store(MemFlagsData::new(), value, ptr, reg as i32 * 8);
}
fn y_float_vars(reg: u16) -> Option<(Variable, Variable)> {
    ACTIVE_Y_FLOAT.with(|active| {
        active
            .borrow()
            .iter()
            .find(|(candidate, _, _)| *candidate == reg)
            .map(|(_, value, flag)| (*value, *flag))
    })
}
fn set_y_float(b: &mut FunctionBuilder<'_>, state: ir::Value, reg: u16, value: ir::Value) {
    let (value_var, flag_var) = y_float_vars(reg).expect("float Y register was declared");
    b.def_var(value_var, value);
    let yes = b.ins().iconst(types::I8, 1);
    b.def_var(flag_var, yes);
    let nil = b.ins().iconst(types::I64, 0x3b);
    let ptr = field(b, state, STOP);
    b.ins().store(MemFlagsData::new(), nil, ptr, reg as i32 * 8);
}
fn clear_y_floats(b: &mut FunctionBuilder<'_>) {
    ACTIVE_Y_FLOAT.with(|active| {
        for (_, _, flag) in active.borrow().iter() {
            let no = b.ins().iconst(types::I8, 0);
            b.def_var(*flag, no);
        }
    });
}
fn ensure_y_box(b: &mut FunctionBuilder<'_>, state: ir::Value) {
    let stop = field(b, state, STOP);
    let top = field(b, state, HTOP);
    let free = b.ins().isub(stop, top);
    let insufficient = b.ins().icmp_imm_s(IntCC::UnsignedLessThan, free, 16);
    let slow = b.create_block();
    let ready = b.create_block();
    b.ins().brif(insufficient, slow, &[], ready, &[]);
    b.switch_to_block(slow);
    flush_x(b, state);
    let words = b.ins().iconst(types::I32, 2);
    // Port of erts/emulator/beam/emu/macros.tab:85 (GC_TEST $Live), OTP-29.1.1.
    // The preceding BEAM live operand, widened to every X register this body uses.
    let live = b.ins().iconst(types::I32, i64::from(root_window()));
    let ensure_ref = ACTIVE_ENSURE
        .with(Cell::get)
        .expect("active native compiler");
    let call = b.ins().call(ensure_ref, &[state, words, live]);
    reload_x(b, state, root_window());
    let status = b.inst_results(call)[0];
    let failed = b.ins().icmp_imm_s(IntCC::NotEqual, status, 0);
    let error = b.create_block();
    b.ins().brif(failed, error, &[], ready, &[]);
    b.switch_to_block(error);
    let failure = b.ins().iconst(types::I32, 3);
    let zero = b.ins().iconst(types::I64, 0);
    b.ins().return_(&[failure, zero]);
    b.switch_to_block(ready);
}
fn materialize_y_reg(b: &mut FunctionBuilder<'_>, state: ir::Value, reg: u16) {
    let Some((value_var, flag_var)) = y_float_vars(reg) else {
        return;
    };
    let flag = b.use_var(flag_var);
    let is_float = b.ins().icmp_imm_s(IntCC::NotEqual, flag, 0);
    let boxed = b.create_block();
    let done = b.create_block();
    b.ins().brif(is_float, boxed, &[], done, &[]);
    b.switch_to_block(boxed);
    ensure_y_box(b, state);
    let value = b.use_var(value_var);
    let top = field(b, state, HTOP);
    let header = b.ins().iconst(types::I64, 0x58);
    b.ins().store(MemFlagsData::new(), header, top, 0);
    b.ins().store(MemFlagsData::new(), value, top, 8);
    let next = b.ins().iadd_imm_s(top, 16);
    b.ins().store(MemFlagsData::new(), next, state, HTOP);
    let tagged = b.ins().bor_imm_s(top, 2);
    y_write(b, state, reg, tagged);
    b.ins().jump(done, &[]);
    b.switch_to_block(done);
}
fn flush_y_floats(b: &mut FunctionBuilder<'_>, state: ir::Value) {
    let regs = ACTIVE_Y_FLOAT.with(|active| {
        active
            .borrow()
            .iter()
            .map(|(reg, _, _)| *reg)
            .collect::<Vec<_>>()
    });
    for reg in regs {
        materialize_y_reg(b, state, reg);
    }
}
fn float_from_y(b: &mut FunctionBuilder<'_>, state: ir::Value, reg: u16, ip: usize) -> ir::Value {
    let Some((value_var, flag_var)) = y_float_vars(reg) else {
        let term = y_read(b, state, reg);
        return float_from_term(b, state, term, ip);
    };
    let flag = b.use_var(flag_var);
    let is_float = b.ins().icmp_imm_s(IntCC::NotEqual, flag, 0);
    let virtual_block = b.create_block();
    let boxed_block = b.create_block();
    let done = b.create_block();
    b.append_block_param(done, types::F64);
    b.ins().brif(is_float, virtual_block, &[], boxed_block, &[]);
    b.switch_to_block(virtual_block);
    let value = b.use_var(value_var);
    b.ins().jump(done, &[ir::BlockArg::Value(value)]);
    b.switch_to_block(boxed_block);
    let ptr = field(b, state, STOP);
    let term = b
        .ins()
        .load(types::I64, MemFlagsData::new(), ptr, reg as i32 * 8);
    let value = float_from_term(b, state, term, ip);
    b.ins().jump(done, &[ir::BlockArg::Value(value)]);
    b.switch_to_block(done);
    b.block_params(done)[0]
}
fn fr_read(b: &mut FunctionBuilder<'_>, fr_vars: &HashMap<u16, Variable>, reg: u16) -> ir::Value {
    b.use_var(fr_vars[&reg])
}
fn fr_write(
    b: &mut FunctionBuilder<'_>,
    _state: ir::Value,
    fr_vars: &HashMap<u16, Variable>,
    reg: u16,
    value: ir::Value,
) {
    b.def_var(fr_vars[&reg], value);
}
fn flush_fr(b: &mut FunctionBuilder<'_>, state: ir::Value) {
    ACTIVE_FR.with(|active| {
        for (reg, var) in active.borrow().iter() {
            let value = b.use_var(*var);
            let ptr = field(b, state, FR);
            b.ins()
                .store(MemFlagsData::new(), value, ptr, *reg as i32 * 8);
        }
    });
}
fn tick(b: &mut FunctionBuilder<'_>, state: ir::Value, ip: usize) {
    let old = b.ins().load(types::I32, MemFlagsData::new(), state, REDS);
    let exhausted = b.ins().icmp_imm_s(IntCC::SignedLessThanOrEqual, old, 1);
    let yield_block = b.create_block();
    let ready = b.create_block();
    b.ins().brif(exhausted, yield_block, &[], ready, &[]);
    b.switch_to_block(yield_block);
    deopt(b, state, ip);
    b.switch_to_block(ready);
    let minus = b.ins().iadd_imm_s(old, -1);
    b.ins().store(MemFlagsData::new(), minus, state, REDS);
}
fn deopt(b: &mut FunctionBuilder<'_>, _state: ir::Value, ip: usize) {
    let offset = b.ins().iconst(types::I32, ip as i64);
    let block = ACTIVE_DEOPT
        .with(Cell::get)
        .expect("active native compiler");
    b.ins().jump(block, &[ir::BlockArg::Value(offset)]);
}
fn continue_at(b: &mut FunctionBuilder<'_>, state: ir::Value, block: Option<ir::Block>) {
    if let Some(block) = block {
        b.ins().jump(block, &[]);
    } else {
        flush_x(b, state);
        flush_y_floats(b, state);
        flush_fr(b, state);
        let done = b.ins().iconst(types::I32, 0);
        let result = x_read(b, state, 0);
        b.ins().return_(&[done, result]);
    }
}

fn ensure_space(
    b: &mut FunctionBuilder<'_>,
    state: ir::Value,
    words: u32,
    live: u16,
    ensure_ref: ir::FuncRef,
    ip: usize,
) {
    if RESERVED_ALLOCATION.with(Cell::get) {
        return;
    }
    let stop = field(b, state, STOP);
    let top = field(b, state, HTOP);
    let free = b.ins().isub(stop, top);
    let insufficient = b
        .ins()
        .icmp_imm_s(IntCC::UnsignedLessThan, free, (words as i64) * 8);
    let slow = b.create_block();
    let ready = b.create_block();
    b.ins().brif(insufficient, slow, &[], ready, &[]);
    b.switch_to_block(slow);
    flush_x(b, state);
    let need = b.ins().iconst(types::I32, words as i64);
    let live_count = live;
    let live = b.ins().iconst(types::I32, i64::from(live_count));
    let call = b.ins().call(ensure_ref, &[state, need, live]);
    reload_x(b, state, live_count);
    let ok = b.inst_results(call)[0];
    let failed = b.ins().icmp_imm_s(IntCC::NotEqual, ok, 0);
    let exit = b.create_block();
    b.ins().brif(failed, exit, &[], ready, &[]);
    b.switch_to_block(exit);
    deopt(b, state, ip);
    b.switch_to_block(ready);
}

fn reserve(b: &mut FunctionBuilder<'_>, state: ir::Value, slots: u16) -> ir::Value {
    let stop = field(b, state, STOP);
    let new_stop = b.ins().iadd_imm_s(stop, -(slots as i64 * 8));
    b.ins().store(MemFlagsData::new(), new_stop, state, STOP);
    new_stop
}
fn release(b: &mut FunctionBuilder<'_>, state: ir::Value, slots: u16) {
    let stop = field(b, state, STOP);
    let new_stop = b.ins().iadd_imm_s(stop, slots as i64 * 8);
    b.ins().store(MemFlagsData::new(), new_stop, state, STOP);
}

fn guard(b: &mut FunctionBuilder<'_>, state: ir::Value, condition: ir::Value, ip: usize) {
    let pass = b.create_block();
    let fail = b.create_block();
    b.ins().brif(condition, pass, &[], fail, &[]);
    b.switch_to_block(fail);
    deopt(b, state, ip);
    b.switch_to_block(pass);
}

#[allow(clippy::too_many_arguments)]
fn branch_on_test(
    b: &mut FunctionBuilder<'_>,
    state: ir::Value,
    pass: ir::Value,
    fail: u32,
    ip: usize,
    entry: usize,
    blocks: &[ir::Block],
    next: Option<ir::Block>,
) {
    if fail == u32::MAX {
        guard(b, state, pass, ip);
        continue_at(b, state, next);
    } else if let Some(target) = (fail as usize)
        .checked_sub(entry)
        .and_then(|index| blocks.get(index))
    {
        if fail as usize <= ip {
            let backedge = b.create_block();
            b.ins()
                .brif(pass, next.expect("test fallthrough"), &[], backedge, &[]);
            b.switch_to_block(backedge);
            tick(b, state, ip);
            b.ins().jump(*target, &[]);
        } else {
            b.ins()
                .brif(pass, next.expect("test fallthrough"), &[], *target, &[]);
        }
    } else {
        let slow = b.create_block();
        b.ins()
            .brif(pass, next.expect("test fallthrough"), &[], slow, &[]);
        b.switch_to_block(slow);
        deopt(b, state, fail as usize);
    }
}

fn get_tuple(
    b: &mut FunctionBuilder<'_>,
    state: ir::Value,
    src: Source,
    index: u16,
    dst: Dest,
    known_tuple: bool,
    ip: usize,
) {
    let value = read_source(b, state, src);
    if !known_tuple {
        let tag = b.ins().band_imm_s(value, 3);
        let boxed = b.ins().icmp_imm_s(IntCC::Equal, tag, 2);
        guard(b, state, boxed, ip);
    }
    let ptr = b.ins().band_imm_s(value, -4);
    let header = b.ins().load(types::I64, MemFlagsData::new(), ptr, 0);
    if !known_tuple {
        let subtype = b.ins().band_imm_s(header, 63);
        let tuple = b.ins().icmp_imm_s(IntCC::Equal, subtype, 0);
        guard(b, state, tuple, ip);
    }
    let arity = b.ins().ushr_imm_u(header, 6);
    let in_range = b
        .ins()
        .icmp_imm_s(IntCC::UnsignedGreaterThan, arity, index as i64);
    guard(b, state, in_range, ip);
    let element = b
        .ins()
        .load(types::I64, MemFlagsData::new(), ptr, (index as i32 + 1) * 8);
    write_dest(b, state, dst, element);
}

fn tuple_proven(beam: &BeamModule, ip: usize, operand: usize) -> bool {
    // Port of erts/emulator/beam/beam_types.h:57 (BEAM_TYPE_TUPLE), OTP-29.1.1.
    beam.types[ip]
        .iter()
        .any(|(position, ty)| *position == operand && ty.union_bits == 1 << 11)
}

fn put_tuple(
    b: &mut FunctionBuilder<'_>,
    state: ir::Value,
    fields: &[Source],
    dst: Dest,
    ensure_ref: ir::FuncRef,
    ip: usize,
) {
    for src in fields {
        if let Source::Y(reg) = src {
            materialize_y_reg(b, state, *reg);
        }
    }
    ensure_space(
        b,
        state,
        fields.len() as u32 + 1,
        root_window(),
        ensure_ref,
        ip,
    );
    let ptr = field(b, state, HTOP);
    let header = b.ins().iconst(types::I64, (fields.len() as i64) << 6);
    b.ins().store(MemFlagsData::new(), header, ptr, 0);
    for (i, src) in fields.iter().enumerate() {
        let value = read_source(b, state, *src);
        b.ins()
            .store(MemFlagsData::new(), value, ptr, (i as i32 + 1) * 8);
    }
    let next = b.ins().iadd_imm_s(ptr, (fields.len() as i64 + 1) * 8);
    b.ins().store(MemFlagsData::new(), next, state, HTOP);
    let tagged = b.ins().bor_imm_s(ptr, 2);
    write_dest(b, state, dst, tagged);
}

fn put_list(
    b: &mut FunctionBuilder<'_>,
    state: ir::Value,
    head: Source,
    tail: Source,
    dst: Dest,
    ensure_ref: ir::FuncRef,
    ip: usize,
) {
    for src in [head, tail] {
        if let Source::Y(reg) = src {
            materialize_y_reg(b, state, reg);
        }
    }
    ensure_space(b, state, 2, root_window(), ensure_ref, ip);
    let ptr = field(b, state, HTOP);
    let head = read_source(b, state, head);
    let tail = read_source(b, state, tail);
    b.ins().store(MemFlagsData::new(), head, ptr, 0);
    b.ins().store(MemFlagsData::new(), tail, ptr, 8);
    let next = b.ins().iadd_imm_s(ptr, 16);
    b.ins().store(MemFlagsData::new(), next, state, HTOP);
    let tagged = b.ins().bor_imm_s(ptr, 1);
    write_dest(b, state, dst, tagged);
}

fn get_list(
    b: &mut FunctionBuilder<'_>,
    state: ir::Value,
    src: Source,
    head: Dest,
    tail: Dest,
    ip: usize,
) {
    let value = read_source(b, state, src);
    let tag = b.ins().band_imm_s(value, 3);
    let list = b.ins().icmp_imm_s(IntCC::Equal, tag, 1);
    guard(b, state, list, ip);
    let ptr = b.ins().band_imm_s(value, -4);
    let hd = b.ins().load(types::I64, MemFlagsData::new(), ptr, 0);
    let tl = b.ins().load(types::I64, MemFlagsData::new(), ptr, 8);
    write_dest(b, state, head, hd);
    write_dest(b, state, tail, tl);
}

fn reverse_list(b: &mut FunctionBuilder<'_>, state: ir::Value, ensure_ref: ir::FuncRef, ip: usize) {
    let input = x_read(b, state, 0);
    let zero = b.ins().iconst(types::I32, 0);
    let validate = b.create_block();
    b.append_block_param(validate, types::I64);
    b.append_block_param(validate, types::I32);
    b.ins().jump(
        validate,
        &[ir::BlockArg::Value(input), ir::BlockArg::Value(zero)],
    );
    b.switch_to_block(validate);
    let current = b.block_params(validate)[0];
    let length = b.block_params(validate)[1];
    let nil = b.ins().icmp_imm_s(IntCC::Equal, current, 0x3b);
    let counted = b.create_block();
    b.append_block_param(counted, types::I32);
    let cons = b.create_block();
    b.ins()
        .brif(nil, counted, &[ir::BlockArg::Value(length)], cons, &[]);
    b.switch_to_block(cons);
    let tag = b.ins().band_imm_s(current, 3);
    let valid = b.ins().icmp_imm_s(IntCC::Equal, tag, 1);
    guard(b, state, valid, ip);
    let bounded = b
        .ins()
        .icmp_imm_s(IntCC::UnsignedLessThan, length, (u32::MAX / 2) as i64);
    guard(b, state, bounded, ip);
    let ptr = b.ins().band_imm_s(current, -4);
    let tail = b.ins().load(types::I64, MemFlagsData::new(), ptr, 8);
    let next_length = b.ins().iadd_imm_s(length, 1);
    b.ins().jump(
        validate,
        &[ir::BlockArg::Value(tail), ir::BlockArg::Value(next_length)],
    );

    b.switch_to_block(counted);
    let length = b.block_params(counted)[0];
    let words = b.ins().ishl_imm_u(length, 1);
    let words64 = b.ins().uextend(types::I64, words);
    let bytes = b.ins().ishl_imm_u(words64, 3);
    let stop = field(b, state, STOP);
    let top = field(b, state, HTOP);
    let free = b.ins().isub(stop, top);
    let enough = b.ins().icmp(IntCC::UnsignedGreaterThanOrEqual, free, bytes);
    let ready = b.create_block();
    let grow = b.create_block();
    b.ins().brif(enough, ready, &[], grow, &[]);
    b.switch_to_block(grow);
    flush_x(b, state);
    let roots = root_window().max(1);
    let live = b.ins().iconst(types::I32, i64::from(roots));
    let call = b.ins().call(ensure_ref, &[state, words, live]);
    reload_x(b, state, roots);
    let status = b.inst_results(call)[0];
    let failed = b.ins().icmp_imm_s(IntCC::NotEqual, status, 0);
    let failure = b.create_block();
    b.ins().brif(failed, failure, &[], ready, &[]);
    b.switch_to_block(failure);
    deopt(b, state, ip);

    b.switch_to_block(ready);
    let current = x_read(b, state, 0);
    let nil = b.ins().iconst(types::I64, 0x3b);
    let loop_block = b.create_block();
    b.append_block_param(loop_block, types::I64);
    b.append_block_param(loop_block, types::I64);
    b.ins().jump(
        loop_block,
        &[ir::BlockArg::Value(current), ir::BlockArg::Value(nil)],
    );
    b.switch_to_block(loop_block);
    let current = b.block_params(loop_block)[0];
    let acc = b.block_params(loop_block)[1];
    let finished = b.ins().icmp_imm_s(IntCC::Equal, current, 0x3b);
    let done = b.create_block();
    b.append_block_param(done, types::I64);
    let step = b.create_block();
    b.ins()
        .brif(finished, done, &[ir::BlockArg::Value(acc)], step, &[]);
    b.switch_to_block(step);
    let source = b.ins().band_imm_s(current, -4);
    let head = b.ins().load(types::I64, MemFlagsData::new(), source, 0);
    let tail = b.ins().load(types::I64, MemFlagsData::new(), source, 8);
    let top = field(b, state, HTOP);
    b.ins().store(MemFlagsData::new(), head, top, 0);
    b.ins().store(MemFlagsData::new(), acc, top, 8);
    let next_top = b.ins().iadd_imm_s(top, 16);
    b.ins().store(MemFlagsData::new(), next_top, state, HTOP);
    let next_acc = b.ins().bor_imm_s(top, 1);
    b.ins().jump(
        loop_block,
        &[ir::BlockArg::Value(tail), ir::BlockArg::Value(next_acc)],
    );
    b.switch_to_block(done);
    let result = b.block_params(done)[0];
    x_write(b, state, 0, result);
}

fn float_from_term(
    b: &mut FunctionBuilder<'_>,
    state: ir::Value,
    term: ir::Value,
    ip: usize,
) -> ir::Value {
    let tag = b.ins().band_imm_s(term, 15);
    let small = b.ins().icmp_imm_s(IntCC::Equal, tag, 15);
    let small_block = b.create_block();
    let boxed_block = b.create_block();
    let done = b.create_block();
    b.append_block_param(done, types::F64);
    b.ins().brif(small, small_block, &[], boxed_block, &[]);
    b.switch_to_block(small_block);
    let integer = b.ins().sshr_imm_u(term, 4);
    let float = b.ins().fcvt_from_sint(types::F64, integer);
    b.ins().jump(done, &[ir::BlockArg::Value(float)]);
    b.switch_to_block(boxed_block);
    let ptr_tag = b.ins().band_imm_s(term, 3);
    let boxed = b.ins().icmp_imm_s(IntCC::Equal, ptr_tag, 2);
    guard(b, state, boxed, ip);
    let ptr = b.ins().band_imm_s(term, -4);
    let header = b.ins().load(types::I64, MemFlagsData::new(), ptr, 0);
    let subtype = b.ins().band_imm_s(header, 63);
    let is_float = b.ins().icmp_imm_s(IntCC::Equal, subtype, 0x18);
    guard(b, state, is_float, ip);
    let float = b.ins().load(types::F64, MemFlagsData::new(), ptr, 8);
    b.ins().jump(done, &[ir::BlockArg::Value(float)]);
    b.switch_to_block(done);
    b.block_params(done)[0]
}

fn finite_float(b: &mut FunctionBuilder<'_>, state: ir::Value, value: ir::Value, ip: usize) {
    let bits = b.ins().bitcast(types::I64, MemFlagsData::new(), value);
    let exponent = b.ins().band_imm_s(bits, 0x7ff0_0000_0000_0000);
    let finite = b
        .ins()
        .icmp_imm_s(IntCC::NotEqual, exponent, 0x7ff0_0000_0000_0000);
    guard(b, state, finite, ip);
}

fn box_float(
    b: &mut FunctionBuilder<'_>,
    state: ir::Value,
    value: ir::Value,
    dst: Dest,
    ensure_ref: ir::FuncRef,
    ip: usize,
) {
    finite_float(b, state, value, ip);
    ensure_space(b, state, 2, root_window(), ensure_ref, ip);
    let ptr = field(b, state, HTOP);
    let header = b.ins().iconst(types::I64, 0x58);
    b.ins().store(MemFlagsData::new(), header, ptr, 0);
    b.ins().store(MemFlagsData::new(), value, ptr, 8);
    let next = b.ins().iadd_imm_s(ptr, 16);
    b.ins().store(MemFlagsData::new(), next, state, HTOP);
    let tagged = b.ins().bor_imm_s(ptr, 2);
    write_dest(b, state, dst, tagged);
}

fn boxed_subtype(b: &mut FunctionBuilder<'_>, value: ir::Value, subtypes: &[i64]) -> ir::Value {
    let tag = b.ins().band_imm_s(value, 3);
    let boxed = b.ins().icmp_imm_s(IntCC::Equal, tag, 2);
    let yes = b.create_block();
    let no = b.create_block();
    let done = b.create_block();
    b.append_block_param(done, types::I8);
    b.ins().brif(boxed, yes, &[], no, &[]);
    b.switch_to_block(no);
    let false_value = b.ins().iconst(types::I8, 0);
    b.ins().jump(done, &[ir::BlockArg::Value(false_value)]);
    b.switch_to_block(yes);
    let ptr = b.ins().band_imm_s(value, -4);
    let header = b.ins().load(types::I64, MemFlagsData::new(), ptr, 0);
    let subtype = b.ins().band_imm_s(header, 63);
    let mut found = b.ins().iconst(types::I8, 0);
    for subtag in subtypes {
        let matches = b.ins().icmp_imm_s(IntCC::Equal, subtype, *subtag);
        found = b.ins().bor(found, matches);
    }
    b.ins().jump(done, &[ir::BlockArg::Value(found)]);
    b.switch_to_block(done);
    b.block_params(done)[0]
}

#[allow(clippy::too_many_arguments)]
fn emit_type_test(
    b: &mut FunctionBuilder<'_>,
    state: ir::Value,
    kind: Opcode,
    src: Source,
    fail: u32,
    ip: usize,
    entry: usize,
    blocks: &[ir::Block],
    next: Option<ir::Block>,
) {
    let value = read_source(b, state, src);
    let pass = match kind {
        Opcode::IsNil => b.ins().icmp_imm_s(IntCC::Equal, value, 0x3b),
        Opcode::IsNonemptyList => {
            let tag = b.ins().band_imm_s(value, 3);
            b.ins().icmp_imm_s(IntCC::Equal, tag, 1)
        }
        Opcode::IsList => {
            let tag = b.ins().band_imm_s(value, 3);
            let cons = b.ins().icmp_imm_s(IntCC::Equal, tag, 1);
            let nil = b.ins().icmp_imm_s(IntCC::Equal, value, 0x3b);
            b.ins().bor(cons, nil)
        }
        Opcode::IsAtom => {
            let tag = b.ins().band_imm_s(value, 63);
            b.ins().icmp_imm_s(IntCC::Equal, tag, 0x0b)
        }
        Opcode::IsTuple => boxed_subtype(b, value, &[0]),
        Opcode::IsFloat => boxed_subtype(b, value, &[0x18]),
        Opcode::IsInteger | Opcode::IsNumber => {
            let tag = b.ins().band_imm_s(value, 15);
            let small = b.ins().icmp_imm_s(IntCC::Equal, tag, 15);
            let subtypes: &[i64] = if kind == Opcode::IsInteger {
                &[0x08, 0x0c]
            } else {
                &[0x08, 0x0c, 0x18]
            };
            let boxed = boxed_subtype(b, value, subtypes);
            b.ins().bor(small, boxed)
        }
        _ => unreachable!("validated type test"),
    };
    branch_on_test(b, state, pass, fail, ip, entry, blocks, next);
}

#[allow(clippy::too_many_arguments)]
fn emit_arity_test(
    b: &mut FunctionBuilder<'_>,
    state: ir::Value,
    src: u16,
    arity: u16,
    fail: u32,
    ip: usize,
    entry: usize,
    blocks: &[ir::Block],
    next: Option<ir::Block>,
) {
    let value = x_read(b, state, src);
    let ptr = b.ins().band_imm_s(value, -4);
    let header = b.ins().load(types::I64, MemFlagsData::new(), ptr, 0);
    let length = b.ins().ushr_imm_u(header, 6);
    let pass = b.ins().icmp_imm_s(IntCC::Equal, length, arity as i64);
    branch_on_test(b, state, pass, fail, ip, entry, blocks, next);
}

#[allow(clippy::too_many_arguments)]
fn emit(
    b: &mut FunctionBuilder<'_>,
    beam: &BeamModule,
    instr: Instr,
    ip: usize,
    entry: usize,
    blocks: &[ir::Block],
    state: ir::Value,
    fr_vars: &HashMap<u16, Variable>,
    next: Option<ir::Block>,
    self_ref: ir::FuncRef,
    callees: &HashMap<usize, (ir::FuncRef, u8)>,
    ensure_ref: ir::FuncRef,
    materialize_ref: ir::FuncRef,
    sqrt_ref: ir::FuncRef,
    module_id: usize,
    self_arity: u8,
) {
    match instr {
        Instr::MoveXX { src, dst } => {
            let v = x_read(b, state, src);
            x_write(b, state, dst, v);
        }
        Instr::MoveYX { src, dst } => {
            let v = y_read(b, state, src);
            x_write(b, state, dst, v);
        }
        Instr::MoveXY { src, dst } => {
            let v = x_read(b, state, src);
            y_write(b, state, dst, v);
        }
        Instr::MoveYY { src, dst } => {
            let v = y_read(b, state, src);
            y_write(b, state, dst, v);
        }
        Instr::MoveCX { value, dst } => {
            // SAFETY: the immutable BEAM module retains any literal's heap.
            let v = b
                .ins()
                .iconst(types::I64, unsafe { value.raw_bits() } as i64);
            x_write(b, state, dst, v);
        }
        Instr::MoveCY { value, dst } => {
            // SAFETY: the immutable BEAM module retains any literal's heap.
            let v = b
                .ins()
                .iconst(types::I64, unsafe { value.raw_bits() } as i64);
            y_write(b, state, dst, v);
        }
        Instr::SwapXX { a, b: rhs } => {
            let lhs = x_read(b, state, a);
            let rhs_value = x_read(b, state, rhs);
            x_write(b, state, a, rhs_value);
            x_write(b, state, rhs, lhs);
        }
        Instr::SwapYX { y, x } => {
            let y_value = y_read(b, state, y);
            let x_value = x_read(b, state, x);
            y_write(b, state, y, x_value);
            x_write(b, state, x, y_value);
        }
        Instr::Allocate { slots, words, live } => {
            flush_y_floats(b, state);
            // The BEAM live operand is a prefix of every X register this body
            // still reloads. Root the wider set so the nil-fill cannot drop one.
            let roots = live.max(root_window());
            ensure_space(b, state, words + slots as u32, roots, ensure_ref, ip);
            let stop = reserve(b, state, slots);
            clear_y_floats(b);
            let nil = b.ins().iconst(types::I64, 0x3b);
            for i in 0..slots {
                b.ins().store(MemFlagsData::new(), nil, stop, i as i32 * 8);
            }
        }
        Instr::Deallocate { slots } => {
            clear_y_floats(b);
            release(b, state, slots);
        }
        Instr::Trim { slots } => {
            flush_y_floats(b, state);
            release(b, state, slots);
            clear_y_floats(b);
        }
        Instr::InitYregs { list } => {
            let nil = b.ins().iconst(types::I64, 0x3b);
            for reg in &beam.lists[list as usize] {
                y_write(b, state, reg.value() as u16, nil);
            }
        }
        Instr::TestHeap { words, live } => {
            ensure_space(b, state, words, live.max(root_window()), ensure_ref, ip);
        }
        Instr::CallExternal {
            import,
            arity,
            dealloc,
            tail,
        } => {
            let called = &beam.imports[import as usize];
            if called.module == "math"
                && called.function == "sqrt"
                && arity == 1
                && dealloc == 0
                && !tail
            {
                let term = x_read(b, state, 0);
                let arg = float_from_term(b, state, term, ip);
                let call = b.ins().call(sqrt_ref, &[arg]);
                let result = b.inst_results(call)[0];
                box_float(b, state, result, Dest::X(0), ensure_ref, ip);
            } else if called.module == "lists"
                && called.function == "reverse"
                && arity == 1
                && dealloc == 0
                && !tail
            {
                reverse_list(b, state, ensure_ref, ip);
            } else {
                deopt(b, state, ip);
                return;
            }
        }
        Instr::CodeEnd => {
            deopt(b, state, ip);
            return;
        }
        Instr::GetTupleElementXX { src, index, dst } => {
            get_tuple(
                b,
                state,
                Source::X(src),
                index,
                Dest::X(dst),
                tuple_proven(beam, ip, 0),
                ip,
            );
        }
        Instr::GetTupleElementYX { src, index, dst } => {
            get_tuple(b, state, Source::Y(src), index, Dest::X(dst), false, ip);
        }
        Instr::GetTupleElementXY { src, index, dst } => {
            get_tuple(b, state, Source::X(src), index, Dest::Y(dst), false, ip);
        }
        Instr::GetTupleFloat {
            src,
            index,
            dst_x,
            dst_fr,
        } => {
            get_tuple(b, state, Source::X(src), index, Dest::X(dst_x), false, ip);
            let term = x_read(b, state, dst_x);
            let value = float_from_term(b, state, term, ip);
            fr_write(b, state, fr_vars, dst_fr, value);
            let after_fused = blocks[ip + 2 - entry];
            b.ins().jump(after_fused, &[]);
            return;
        }
        Instr::PutTupleXX { a, b: second, dst } => {
            put_tuple(
                b,
                state,
                &[Source::X(a), Source::X(second)],
                Dest::X(dst),
                ensure_ref,
                ip,
            );
        }
        Instr::PutTuple { list, dst } => {
            let fields = beam.lists[list as usize]
                .iter()
                .map(|arg| source(*arg).expect("specialized tuple source"))
                .collect::<Vec<_>>();
            put_tuple(b, state, &fields, Dest::X(dst), ensure_ref, ip);
        }
        Instr::PutListXXX { head, tail, dst } => {
            put_list(
                b,
                state,
                Source::X(head),
                Source::X(tail),
                Dest::X(dst),
                ensure_ref,
                ip,
            );
        }
        Instr::PutList { head, tail, dst } => {
            put_list(
                b,
                state,
                source(head).expect("specialized list head"),
                source(tail).expect("specialized list tail"),
                Dest::X(dst),
                ensure_ref,
                ip,
            );
        }
        Instr::GetListXXX { src, head, tail } => {
            get_list(b, state, Source::X(src), Dest::X(head), Dest::X(tail), ip);
        }
        Instr::GetList { src, head, tail } => {
            get_list(
                b,
                state,
                Source::X(src),
                destination(head).expect("specialized list head destination"),
                destination(tail).expect("specialized list tail destination"),
                ip,
            );
        }
        Instr::GetHdXX { src, dst } | Instr::GetTlXX { src, dst } => {
            let value = x_read(b, state, src);
            let tag = b.ins().band_imm_s(value, 3);
            let list = b.ins().icmp_imm_s(IntCC::Equal, tag, 1);
            guard(b, state, list, ip);
            let ptr = b.ins().band_imm_s(value, -4);
            let offset = if matches!(instr, Instr::GetHdXX { .. }) {
                0
            } else {
                8
            };
            let item = b.ins().load(types::I64, MemFlagsData::new(), ptr, offset);
            x_write(b, state, dst, item);
        }
        Instr::FmoveXFr { src, dst } => {
            let term = x_read(b, state, src);
            let value = float_from_term(b, state, term, ip);
            fr_write(b, state, fr_vars, dst, value);
        }
        Instr::FmoveYFr { src, dst } => {
            let value = float_from_y(b, state, src, ip);
            fr_write(b, state, fr_vars, dst, value);
        }
        Instr::FmoveCFr { value, dst } => {
            let value = b.ins().f64const(value);
            fr_write(b, state, fr_vars, dst, value);
        }
        Instr::FmoveFrX { src, dst } => {
            let value = fr_read(b, fr_vars, src);
            box_float(b, state, value, Dest::X(dst), ensure_ref, ip);
        }
        Instr::FmoveFrY { src, dst } => {
            let value = fr_read(b, fr_vars, src);
            finite_float(b, state, value, ip);
            set_y_float(b, state, dst, value);
        }
        Instr::FmoveFrFr { src, dst } => {
            let value = fr_read(b, fr_vars, src);
            fr_write(b, state, fr_vars, dst, value);
        }
        Instr::Fadd { a, b: rhs, dst }
        | Instr::Fsub { a, b: rhs, dst }
        | Instr::Fmul { a, b: rhs, dst }
        | Instr::Fdiv { a, b: rhs, dst }
        | Instr::FloatBin { a, b: rhs, dst, .. } => {
            let lhs = fr_read(b, fr_vars, a);
            let rhs = fr_read(b, fr_vars, rhs);
            let kind = match instr {
                Instr::Fadd { .. } => Opcode::Fadd,
                Instr::Fsub { .. } => Opcode::Fsub,
                Instr::Fmul { .. } => Opcode::Fmul,
                Instr::Fdiv { .. } => Opcode::Fdiv,
                Instr::FloatBin { kind, .. } => kind,
                _ => unreachable!("float arithmetic arm"),
            };
            let result = match kind {
                Opcode::Fadd => b.ins().fadd(lhs, rhs),
                Opcode::Fsub => b.ins().fsub(lhs, rhs),
                Opcode::Fmul => b.ins().fmul(lhs, rhs),
                Opcode::Fdiv => b.ins().fdiv(lhs, rhs),
                _ => unreachable!("validated float instruction"),
            };
            finite_float(b, state, result, ip);
            fr_write(b, state, fr_vars, dst, result);
        }
        Instr::IsTupleX { src, fail }
        | Instr::IsNilX { src, fail }
        | Instr::IsNonemptyListX { src, fail }
        | Instr::IsIntegerX { src, fail } => {
            let kind = match instr {
                Instr::IsTupleX { .. } => Opcode::IsTuple,
                Instr::IsNilX { .. } => Opcode::IsNil,
                Instr::IsNonemptyListX { .. } => Opcode::IsNonemptyList,
                Instr::IsIntegerX { .. } => Opcode::IsInteger,
                _ => unreachable!("type test arm"),
            };
            emit_type_test(
                b,
                state,
                kind,
                Source::X(src),
                fail,
                ip,
                entry,
                blocks,
                next,
            );
            return;
        }
        Instr::TestArityX { src, arity, fail } => {
            let typed = b.create_block();
            emit_type_test(
                b,
                state,
                Opcode::IsTuple,
                Source::X(src),
                fail,
                ip,
                entry,
                blocks,
                Some(typed),
            );
            b.switch_to_block(typed);
            emit_arity_test(b, state, src, arity, fail, ip, entry, blocks, next);
            return;
        }
        Instr::IsTupleOfArity {
            src,
            arity,
            fail_type,
            fail_arity,
        } => {
            let typed = b.create_block();
            emit_type_test(
                b,
                state,
                Opcode::IsTuple,
                Source::X(src),
                fail_type,
                ip,
                entry,
                blocks,
                Some(typed),
            );
            b.switch_to_block(typed);
            emit_arity_test(
                b,
                state,
                src,
                arity,
                fail_arity,
                ip,
                entry,
                blocks,
                blocks.get(ip + 2 - entry).copied(),
            );
            return;
        }
        Instr::Select {
            src,
            from_y,
            table,
            fallback,
            tuple_arity,
        } => {
            let mut key = if from_y {
                y_read(b, state, src)
            } else {
                x_read(b, state, src)
            };
            if tuple_arity {
                let tag = b.ins().band_imm_s(key, 3);
                let boxed = b.ins().icmp_imm_s(IntCC::Equal, tag, 2);
                guard(b, state, boxed, ip);
                let ptr = b.ins().band_imm_s(key, -4);
                let header = b.ins().load(types::I64, MemFlagsData::new(), ptr, 0);
                let subtype = b.ins().band_imm_s(header, 63);
                let tuple = b.ins().icmp_imm_s(IntCC::Equal, subtype, 0);
                guard(b, state, tuple, ip);
                let arity = b.ins().ushr_imm_u(header, 6);
                let tagged = b.ins().ishl_imm_u(arity, 4);
                key = b.ins().bor_imm_s(tagged, 15);
            }
            for (value, target) in select_entries(beam, table).expect("validated select table") {
                let matches = b.ins().icmp_imm_s(IntCC::Equal, key, value as i64);
                let next_case = b.create_block();
                let backedge = (target as usize <= ip).then(|| b.create_block());
                let destination = backedge.unwrap_or(blocks[target as usize - entry]);
                b.ins().brif(matches, destination, &[], next_case, &[]);
                if let Some(backedge) = backedge {
                    b.switch_to_block(backedge);
                    tick(b, state, ip);
                    b.ins().jump(blocks[target as usize - entry], &[]);
                }
                b.switch_to_block(next_case);
            }
            if fallback == u32::MAX {
                deopt(b, state, ip);
            } else {
                if fallback as usize <= ip {
                    tick(b, state, ip);
                }
                b.ins().jump(blocks[fallback as usize - entry], &[]);
            }
            return;
        }
        Instr::Jump { target } => {
            if target as usize <= ip {
                tick(b, state, ip);
            }
            b.ins().jump(blocks[target as usize - entry], &[]);
            return;
        }
        Instr::MoveCallLocal { target, .. }
        | Instr::CallLocal { target }
        | Instr::CallLast { target, .. }
        | Instr::CallOnly { target } => {
            let ordinary = matches!(instr, Instr::MoveCallLocal { .. } | Instr::CallLocal { .. });
            let native_call = ordinary || target as usize != entry;
            if native_call {
                let depth = b.ins().load(types::I32, MemFlagsData::new(), state, DEPTH);
                let full = b
                    .ins()
                    .icmp_imm_s(IntCC::UnsignedGreaterThanOrEqual, depth, 512);
                let yield_block = b.create_block();
                let call_block = b.create_block();
                b.ins().brif(full, yield_block, &[], call_block, &[]);
                b.switch_to_block(yield_block);
                deopt(b, state, ip);
                b.switch_to_block(call_block);
            }
            tick(b, state, ip);
            if let Instr::MoveCallLocal { src, dst, .. } = instr {
                let value = x_read(b, state, src);
                x_write(b, state, dst, value);
            }
            if let Instr::CallLast { dealloc, .. } = instr {
                clear_y_floats(b);
                release(b, state, dealloc);
            }
            let parent_depth = if ordinary {
                let end = field(b, state, STACK_END);
                let stop = field(b, state, STOP);
                let bytes = b.ins().isub(end, stop);
                let words = b.ins().ushr_imm_u(bytes, 3);
                let depth = b.ins().load(types::I32, MemFlagsData::new(), state, DEPTH);
                let next_depth = b.ins().iadd_imm_s(depth, 1);
                b.ins().store(MemFlagsData::new(), next_depth, state, DEPTH);
                Some(words)
            } else {
                None
            };
            if !ordinary && target as usize == entry {
                b.ins().jump(blocks[0], &[]);
                return;
            }
            if !ordinary {
                let depth = b.ins().load(types::I32, MemFlagsData::new(), state, DEPTH);
                let next_depth = b.ins().iadd_imm_s(depth, 1);
                b.ins().store(MemFlagsData::new(), next_depth, state, DEPTH);
            }
            let (callee, callee_arity) = if target as usize == entry {
                (self_ref, self_arity)
            } else {
                callees[&(target as usize)]
            };
            flush_fr(b, state);
            flush_y_floats(b, state);
            flush_x(b, state);
            let mut args = vec![state];
            for reg in 0..callee_arity {
                args.push(x_read(b, state, reg as u16));
            }
            let call = b.ins().call(callee, &args);
            // The callee publishes its own window. Restore ours before materialize
            // collects, or its smaller prefix nils registers this body still holds.
            store_root_window(b, state);
            let status = b.inst_results(call)[0];
            let result = b.inst_results(call)[1];
            let failed = b.ins().icmp_imm_s(IntCC::NotEqual, status, 0);
            let propagate = b.create_block();
            let resume = b.create_block();
            b.ins().brif(failed, propagate, &[], resume, &[]);
            b.switch_to_block(propagate);
            if let Some(parent_depth) = parent_depth {
                let needs_frame = b.ins().icmp_imm_s(IntCC::Equal, status, 1);
                let convert = b.create_block();
                let forward = b.create_block();
                b.ins().brif(needs_frame, convert, &[], forward, &[]);
                b.switch_to_block(convert);
                let next_ip =
                    ip as u64 + u64::from(matches!(instr, Instr::MoveCallLocal { .. })) + 1;
                let cp = (((module_id as u64) << 32) | next_ip) << 6 | 0x1b;
                let cp = b.ins().iconst(types::I64, cp as i64);
                let call = b.ins().call(materialize_ref, &[state, parent_depth, cp]);
                let materialized = b.inst_results(call)[0];
                let could_not_materialize = b.ins().icmp_imm_s(IntCC::NotEqual, materialized, 0);
                let error = b.create_block();
                let ready = b.create_block();
                b.ins().brif(could_not_materialize, error, &[], ready, &[]);
                b.switch_to_block(error);
                let failure = b.ins().iconst(types::I32, 2);
                let zero = b.ins().iconst(types::I64, 0);
                b.ins().return_(&[failure, zero]);
                b.switch_to_block(ready);
                b.ins().jump(forward, &[]);
                b.switch_to_block(forward);
            }
            b.ins().return_(&[status, result]);
            b.switch_to_block(resume);
            if ordinary {
                reload_x_after_call(b, state);
                x_write(b, state, 0, result);
                for (reg, var) in fr_vars {
                    let ptr = field(b, state, FR);
                    let value = b
                        .ins()
                        .load(types::F64, MemFlagsData::new(), ptr, *reg as i32 * 8);
                    b.def_var(*var, value);
                }
                let depth = b.ins().load(types::I32, MemFlagsData::new(), state, DEPTH);
                let previous = b.ins().iadd_imm_s(depth, -1);
                b.ins().store(MemFlagsData::new(), previous, state, DEPTH);
            } else {
                b.ins().return_(&[status, result]);
                return;
            }
        }
        Instr::ReturnInstr => {
            tick(b, state, ip);
            flush_y_floats(b, state);
            flush_x(b, state);
            flush_fr(b, state);
            let done = b.ins().iconst(types::I32, 0);
            let result = x_read(b, state, 0);
            b.ins().return_(&[done, result]);
            return;
        }
        Instr::DeallocateReturn { slots } => {
            tick(b, state, ip);
            clear_y_floats(b);
            release(b, state, slots);
            flush_x(b, state);
            flush_fr(b, state);
            let done = b.ins().iconst(types::I32, 0);
            let result = x_read(b, state, 0);
            b.ins().return_(&[done, result]);
            return;
        }
        instr @ (Instr::IsLtXX { .. }
        | Instr::IsLtXC { .. }
        | Instr::IsLtCX { .. }
        | Instr::IsGeXX { .. }
        | Instr::IsGeXC { .. }
        | Instr::IsGeCX { .. }
        | Instr::IsEqXX { .. }
        | Instr::IsEqXC { .. }
        | Instr::IsEqCX { .. }
        | Instr::IsNeXX { .. }
        | Instr::IsNeXC { .. }
        | Instr::IsNeCX { .. }
        | Instr::IsEqExactXX { .. }
        | Instr::IsEqExactXC { .. }
        | Instr::IsEqExactCX { .. }
        | Instr::IsNeExactXX { .. }
        | Instr::IsNeExactXC { .. }
        | Instr::IsNeExactCX { .. }
        | Instr::IsLtXCReturn { .. }) => {
            let (lhs, rhs, kind, fail, returning) = match instr {
                Instr::IsLtXX { a, b: rhs, fail } => {
                    (Source::X(a), Source::X(rhs), Opcode::IsLt, fail, false)
                }
                Instr::IsLtXC { a, b: rhs, fail } => (
                    Source::X(a),
                    Source::Constant(rhs),
                    Opcode::IsLt,
                    fail,
                    false,
                ),
                Instr::IsLtCX { a: lhs, b, fail } => (
                    Source::Constant(lhs),
                    Source::X(b),
                    Opcode::IsLt,
                    fail,
                    false,
                ),
                Instr::IsGeXX { a, b: rhs, fail } => {
                    (Source::X(a), Source::X(rhs), Opcode::IsGe, fail, false)
                }
                Instr::IsGeXC { a, b: rhs, fail } => (
                    Source::X(a),
                    Source::Constant(rhs),
                    Opcode::IsGe,
                    fail,
                    false,
                ),
                Instr::IsGeCX { a: lhs, b, fail } => (
                    Source::Constant(lhs),
                    Source::X(b),
                    Opcode::IsGe,
                    fail,
                    false,
                ),
                Instr::IsEqXX { a, b: rhs, fail } => {
                    (Source::X(a), Source::X(rhs), Opcode::IsEq, fail, false)
                }
                Instr::IsEqXC { a, b: rhs, fail } => (
                    Source::X(a),
                    Source::Constant(rhs),
                    Opcode::IsEq,
                    fail,
                    false,
                ),
                Instr::IsEqCX { a: lhs, b, fail } => (
                    Source::Constant(lhs),
                    Source::X(b),
                    Opcode::IsEq,
                    fail,
                    false,
                ),
                Instr::IsNeXX { a, b: rhs, fail } => {
                    (Source::X(a), Source::X(rhs), Opcode::IsNe, fail, false)
                }
                Instr::IsNeXC { a, b: rhs, fail } => (
                    Source::X(a),
                    Source::Constant(rhs),
                    Opcode::IsNe,
                    fail,
                    false,
                ),
                Instr::IsNeCX { a: lhs, b, fail } => (
                    Source::Constant(lhs),
                    Source::X(b),
                    Opcode::IsNe,
                    fail,
                    false,
                ),
                Instr::IsEqExactXX { a, b: rhs, fail } => {
                    (Source::X(a), Source::X(rhs), Opcode::IsEqExact, fail, false)
                }
                Instr::IsEqExactXC { a, b: rhs, fail } => (
                    Source::X(a),
                    Source::Constant(rhs),
                    Opcode::IsEqExact,
                    fail,
                    false,
                ),
                Instr::IsEqExactCX { a: lhs, b, fail } => (
                    Source::Constant(lhs),
                    Source::X(b),
                    Opcode::IsEqExact,
                    fail,
                    false,
                ),
                Instr::IsNeExactXX { a, b: rhs, fail } => {
                    (Source::X(a), Source::X(rhs), Opcode::IsNeExact, fail, false)
                }
                Instr::IsNeExactXC { a, b: rhs, fail } => (
                    Source::X(a),
                    Source::Constant(rhs),
                    Opcode::IsNeExact,
                    fail,
                    false,
                ),
                Instr::IsNeExactCX { a: lhs, b, fail } => (
                    Source::Constant(lhs),
                    Source::X(b),
                    Opcode::IsNeExact,
                    fail,
                    false,
                ),
                Instr::IsLtXCReturn { a, b: rhs, fail } => (
                    Source::X(a),
                    Source::Constant(rhs),
                    Opcode::IsLt,
                    fail,
                    true,
                ),
                _ => unreachable!("comparison arm"),
            };
            let lhs = read_source(b, state, lhs);
            let rhs = read_source(b, state, rhs);
            if returning {
                let returned = b.create_block();
                emit_compare(
                    b,
                    state,
                    lhs,
                    rhs,
                    kind,
                    fail,
                    ip,
                    entry,
                    blocks,
                    Some(returned),
                );
                b.switch_to_block(returned);
                tick(b, state, ip);
                flush_y_floats(b, state);
                flush_x(b, state);
                flush_fr(b, state);
                let done = b.ins().iconst(types::I32, 0);
                let result = x_read(b, state, 0);
                b.ins().return_(&[done, result]);
            } else {
                emit_compare(b, state, lhs, rhs, kind, fail, ip, entry, blocks, next);
            }
            return;
        }
        Instr::ArithXXX {
            kind,
            a,
            b: rhs,
            dst,
            ..
        } => {
            let lhs = x_read(b, state, a);
            let rhs = x_read(b, state, rhs);
            emit_arith(b, state, lhs, rhs, kind, Dest::X(dst), ip);
        }
        Instr::ArithYXX {
            kind,
            a,
            b: rhs,
            dst,
            ..
        } => {
            let lhs = y_read(b, state, a);
            let rhs = x_read(b, state, rhs);
            emit_arith(b, state, lhs, rhs, kind, Dest::X(dst), ip);
        }
        Instr::ArithRC {
            kind,
            src,
            from_y,
            value,
            dst,
            ..
        } => {
            let lhs = if from_y {
                y_read(b, state, src)
            } else {
                x_read(b, state, src)
            };
            // SAFETY: the immutable BEAM module retains any literal's heap.
            let rhs = b
                .ins()
                .iconst(types::I64, unsafe { value.raw_bits() } as i64);
            emit_arith(b, state, lhs, rhs, kind, Dest::X(dst), ip);
        }
        Instr::ArithRCY {
            kind,
            src,
            from_y,
            value,
            dst,
            ..
        } => {
            let lhs = if from_y {
                y_read(b, state, src)
            } else {
                x_read(b, state, src)
            };
            // SAFETY: The immutable module retains its literal area.
            let rhs = b
                .ins()
                .iconst(types::I64, unsafe { value.raw_bits() } as i64);
            emit_arith(b, state, lhs, rhs, kind, Dest::Y(dst), ip);
        }
        Instr::Generic(index) => {
            if let Some((kind, lhs, rhs, dst)) = decode_generic_arith(beam, index) {
                let lhs = read_source(b, state, lhs);
                let rhs = read_source(b, state, rhs);
                emit_arith(b, state, lhs, rhs, kind, Dest::X(dst), ip);
            } else if let Some((src, dst)) = decode_generic_fmove(beam, index) {
                if dst.kind() == Arg::FR {
                    let value = if src.kind() == Arg::FR {
                        fr_read(b, fr_vars, src.value() as u16)
                    } else if src.kind() == Arg::TERM {
                        let term = src.term();
                        if let Some(n) = term.as_small() {
                            b.ins().f64const(n as f64)
                        } else {
                            // SAFETY: the module retains this float literal.
                            let float = unsafe { term.float_ref() }.expect("validated float");
                            b.ins().f64const(float.get())
                        }
                    } else {
                        match source(src).expect("validated source") {
                            Source::Y(reg) => float_from_y(b, state, reg, ip),
                            source => {
                                let term = read_source(b, state, source);
                                float_from_term(b, state, term, ip)
                            }
                        }
                    };
                    fr_write(b, state, fr_vars, dst.value() as u16, value);
                } else {
                    let value = fr_read(b, fr_vars, src.value() as u16);
                    let destination = destination(dst).expect("validated destination");
                    if let Dest::Y(reg) = destination {
                        finite_float(b, state, value, ip);
                        set_y_float(b, state, reg, value);
                    } else {
                        box_float(b, state, value, destination, ensure_ref, ip);
                    }
                }
            } else if let Some((dst, fields)) = decode_generic_tuple(beam, index) {
                put_tuple(b, state, &fields, dst, ensure_ref, ip);
            } else if let Some((src, position, dst)) = decode_generic_get_tuple(beam, index) {
                get_tuple(b, state, src, position, dst, tuple_proven(beam, ip, 0), ip);
            } else if let Some((head, tail, dst)) = decode_generic_list(beam, index) {
                put_list(b, state, head, tail, dst, ensure_ref, ip);
            } else if let Some((kind, src, fail)) = decode_generic_type_test(beam, index) {
                emit_type_test(b, state, kind, src, fail, ip, entry, blocks, next);
                return;
            } else if let Some(regs) = decode_generic_init_yregs(beam, index) {
                let nil = b.ins().iconst(types::I64, 0x3b);
                for reg in regs {
                    y_write(b, state, reg, nil);
                }
            } else if let Some((a, c)) = decode_generic_swap(beam, index) {
                let av = match a {
                    Dest::X(reg) => x_read(b, state, reg),
                    Dest::Y(reg) => y_read(b, state, reg),
                };
                let cv = match c {
                    Dest::X(reg) => x_read(b, state, reg),
                    Dest::Y(reg) => y_read(b, state, reg),
                };
                write_dest(b, state, a, cv);
                write_dest(b, state, c, av);
            } else if let Some((src, head, tail)) = decode_generic_get_list(beam, index) {
                get_list(b, state, src, head, tail, ip);
            } else if let Some((src, arity, fail)) = decode_generic_test_arity(beam, index) {
                let value = read_source(b, state, src);
                let tag = b.ins().band_imm_s(value, 3);
                let boxed = b.ins().icmp_imm_s(IntCC::Equal, tag, 2);
                guard(b, state, boxed, ip);
                let ptr = b.ins().band_imm_s(value, -4);
                let header = b.ins().load(types::I64, MemFlagsData::new(), ptr, 0);
                let subtype = b.ins().band_imm_s(header, 63);
                let tuple = b.ins().icmp_imm_s(IntCC::Equal, subtype, 0);
                guard(b, state, tuple, ip);
                let length = b.ins().ushr_imm_u(header, 6);
                let pass = b.ins().icmp_imm_s(IntCC::Equal, length, arity as i64);
                if fail == u32::MAX {
                    guard(b, state, pass, ip);
                    continue_at(b, state, next);
                } else {
                    b.ins().brif(
                        pass,
                        next.expect("arity test fallthrough"),
                        &[],
                        blocks[fail as usize - entry],
                        &[],
                    );
                }
                return;
            } else if let Some((src, dst)) = decode_generic_fnegate(beam, index) {
                let value = fr_read(b, fr_vars, src);
                let result = b.ins().fneg(value);
                finite_float(b, state, result, ip);
                fr_write(b, state, fr_vars, dst, result);
            } else {
                unreachable!("validated generic instruction");
            }
        }
        _ => unreachable!("validated native instruction"),
    }
    continue_at(b, state, next);
}

#[allow(clippy::too_many_arguments)]
fn emit_compare(
    b: &mut FunctionBuilder<'_>,
    state: ir::Value,
    lhs: ir::Value,
    rhs: ir::Value,
    kind: Opcode,
    fail: u32,
    ip: usize,
    entry: usize,
    blocks: &[ir::Block],
    next: Option<ir::Block>,
) {
    let both = b.ins().band(lhs, rhs);
    let tags = b.ins().band_imm_s(both, 0xf);
    let small = b.ins().icmp_imm_s(IntCC::Equal, tags, 0xf);
    let fast = b.create_block();
    let slow = b.create_block();
    b.ins().brif(small, fast, &[], slow, &[]);
    b.switch_to_block(slow);
    deopt(b, state, ip);
    b.switch_to_block(fast);
    let cond = match kind {
        Opcode::IsLt => IntCC::SignedLessThan,
        Opcode::IsGe => IntCC::SignedGreaterThanOrEqual,
        Opcode::IsEq | Opcode::IsEqExact => IntCC::Equal,
        Opcode::IsNe | Opcode::IsNeExact => IntCC::NotEqual,
        _ => unreachable!("validated comparison"),
    };
    let pass = b.ins().icmp(cond, lhs, rhs);
    branch_on_test(b, state, pass, fail, ip, entry, blocks, next);
}

fn emit_arith(
    b: &mut FunctionBuilder<'_>,
    state: ir::Value,
    lhs: ir::Value,
    rhs: ir::Value,
    kind: FastBif,
    dst: Dest,
    ip: usize,
) {
    let both = b.ins().band(lhs, rhs);
    let tags = b.ins().band_imm_s(both, 0xf);
    let small = b.ins().icmp_imm_s(IntCC::Equal, tags, 0xf);
    let fast = b.create_block();
    let slow = b.create_block();
    b.ins().brif(small, fast, &[], slow, &[]);
    b.switch_to_block(slow);
    deopt(b, state, ip);
    b.switch_to_block(fast);
    if matches!(kind, FastBif::Add | FastBif::Sub) {
        // Small integers use four tag bits. Removing the right tag before the
        // operation makes signed overflow match the BEAM small-integer range.
        let right = b.ins().iadd_imm_s(rhs, -15);
        let (tagged, overflow) = if kind == FastBif::Add {
            b.ins().sadd_overflow(lhs, right)
        } else {
            b.ins().ssub_overflow(lhs, right)
        };
        let good = b.create_block();
        let bad = b.create_block();
        b.ins().brif(overflow, bad, &[], good, &[]);
        b.switch_to_block(bad);
        deopt(b, state, ip);
        b.switch_to_block(good);
        write_dest(b, state, dst, tagged);
        return;
    }
    let a = b.ins().sshr_imm_s(lhs, 4);
    let rhs = b.ins().sshr_imm_s(rhs, 4);
    let (result, min, max) = if kind == FastBif::Mul {
        let lhs = b.ins().sextend(types::I128, a);
        let rhs = b.ins().sextend(types::I128, rhs);
        let product = b.ins().imul(lhs, rhs);
        let lower = b.ins().iconst(types::I64, -(1_i64 << 59));
        let upper = b.ins().iconst(types::I64, (1_i64 << 59) - 1);
        let lower = b.ins().sextend(types::I128, lower);
        let upper = b.ins().sextend(types::I128, upper);
        let min = b.ins().icmp(IntCC::SignedLessThan, product, lower);
        let max = b.ins().icmp(IntCC::SignedGreaterThan, product, upper);
        (b.ins().ireduce(types::I64, product), min, max)
    } else {
        let result = match kind {
            FastBif::Add => b.ins().iadd(a, rhs),
            FastBif::Sub => b.ins().isub(a, rhs),
            _ => unreachable!("validated arithmetic"),
        };
        let min = b
            .ins()
            .icmp_imm_s(IntCC::SignedLessThan, result, -(1_i64 << 59));
        let max = b
            .ins()
            .icmp_imm_s(IntCC::SignedGreaterThan, result, (1_i64 << 59) - 1);
        (result, min, max)
    };
    let overflow = b.ins().bor(min, max);
    let good = b.create_block();
    let bad = b.create_block();
    b.ins().brif(overflow, bad, &[], good, &[]);
    b.switch_to_block(bad);
    deopt(b, state, ip);
    b.switch_to_block(good);
    let shifted = b.ins().ishl_imm_s(result, 4);
    let tagged = b.ins().bor_imm_s(shifted, 0xf);
    write_dest(b, state, dst, tagged);
}
