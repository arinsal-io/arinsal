//! Cranelift lowering for the integer SSA subset.

use crate::ir::{self, Block, Compare, Function, IntOp, Location, Operation, Recipe, Source};
use arinsal_jit::JitState;
use arinsal_loader::Module as BeamModule;
use cranelift_codegen::ir::{
    self as cl, InstBuilder, MemFlagsData, StackSlotData, StackSlotKind, condcodes::IntCC, types,
};
use cranelift_frontend::{FunctionBuilder, FunctionBuilderContext};
use cranelift_jit::{JITBuilder, JITModule};
use cranelift_module::{FuncId, Linkage, Module};
use std::collections::{BTreeMap, HashMap};

const X: i32 = std::mem::offset_of!(JitState, x) as i32;
const STOP: i32 = std::mem::offset_of!(JitState, stop) as i32;
const STACK_END: i32 = std::mem::offset_of!(JitState, stack_end) as i32;
const REDS: i32 = std::mem::offset_of!(JitState, reds) as i32;
const IP: i32 = std::mem::offset_of!(JitState, ip) as i32;
const MAX_NATIVE_DEPTH: i64 = 256;

/// Native entry point with the same exit status as the baseline tier.
pub type NativeFn = unsafe extern "C" fn(*mut JitState) -> u32;

/// Materialize a logical frame at the native entry stack boundary.
pub type MaterializeFn = extern "C" fn(*mut JitState, u64, u64, *const u64, u32) -> u32;

/// Why a resolved region could not become native code.
#[derive(Debug)]
pub enum CompileError {
    /// The typed integer lowering cannot prove this region safe.
    Lower(ir::LowerError),
    /// Cranelift rejected the generated function.
    Codegen(String),
}
impl std::fmt::Display for CompileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for CompileError {}

/// Owns executable pages for compiled call regions.
pub struct Engine {
    module: JITModule,
    materialize: FuncId,
    compiled: HashMap<(usize, usize), NativeFn>,
    force_deopt: bool,
}

impl Engine {
    /// Create a Cranelift tier with a VM-owned frame materializer.
    pub fn new(materialize: MaterializeFn) -> Result<Self, CompileError> {
        let mut builder = JITBuilder::new(cranelift_module::default_libcall_names())
            .map_err(|e| CompileError::Codegen(e.to_string()))?;
        builder.symbol("arinsal_opt_materialize", materialize as *const u8);
        let mut module = JITModule::new(builder);
        let mut sig = module.make_signature();
        for _ in 0..4 {
            sig.params.push(cl::AbiParam::new(types::I64));
        }
        sig.params.push(cl::AbiParam::new(types::I32));
        sig.returns.push(cl::AbiParam::new(types::I32));
        let materialize = module
            .declare_function("arinsal_opt_materialize", Linkage::Import, &sig)
            .map_err(|e| CompileError::Codegen(e.to_string()))?;
        Ok(Self {
            module,
            materialize,
            compiled: HashMap::new(),
            force_deopt: std::env::var_os("ARINSAL_OPT_FORCE_DEOPT").is_some(),
        })
    }

    /// Retrieve a previously compiled entry.
    pub fn get(&self, module_id: usize, entry: usize) -> Option<NativeFn> {
        self.compiled.get(&(module_id, entry)).copied()
    }

    /// Compile the requested entry and every supported direct callee together.
    pub fn compile(
        &mut self,
        module_id: usize,
        beam: &BeamModule,
        entry: usize,
    ) -> Result<NativeFn, CompileError> {
        if let Some(f) = self.get(module_id, entry) {
            return Ok(f);
        }
        let region = ir::Region::lower(beam, entry).map_err(CompileError::Lower)?;
        let mut funcs = BTreeMap::new();
        for (&target, function) in &region.functions {
            let sig = fast_signature(&self.module, function.arity);
            let id = self
                .module
                .declare_function(
                    &format!("arinsal_opt_m{module_id}_r{entry}_f{target}"),
                    Linkage::Local,
                    &sig,
                )
                .map_err(|e| CompileError::Codegen(e.to_string()))?;
            funcs.insert(target, id);
        }
        for (&target, function) in &region.functions {
            self.define_fast(
                module_id,
                function,
                funcs[&target],
                &funcs,
                &region.functions,
            )?;
        }
        let root = &region.functions[&entry];
        let wrapper = self.define_wrapper(module_id, entry, root, funcs[&entry])?;
        self.module
            .finalize_definitions()
            .map_err(|e| CompileError::Codegen(e.to_string()))?;
        let ptr = self.module.get_finalized_function(wrapper);
        // SAFETY: The finalized wrapper has one JitState pointer parameter and
        // an I32 result; this Engine owns its executable page for its lifetime.
        let native: NativeFn = unsafe { std::mem::transmute(ptr) };
        self.compiled.insert((module_id, entry), native);
        Ok(native)
    }

    fn define_fast(
        &mut self,
        module_id: usize,
        function: &Function,
        id: FuncId,
        funcs: &BTreeMap<usize, FuncId>,
        functions: &BTreeMap<usize, Function>,
    ) -> Result<(), CompileError> {
        let mut context = self.module.make_context();
        context.func.signature = fast_signature(&self.module, function.arity);
        let refs = funcs
            .iter()
            .map(|(entry, id)| {
                (
                    *entry,
                    self.module.declare_func_in_func(*id, &mut context.func),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let materialize = self
            .module
            .declare_func_in_func(self.materialize, &mut context.func);
        let config = self.module.isa().frontend_config();
        let mut fb_context = FunctionBuilderContext::new();
        {
            let mut b = FunctionBuilder::new(&mut context.func, &mut fb_context);
            let prologue = b.create_block();
            b.append_block_params_for_function_params(prologue);
            let mut pcs = BTreeMap::new();
            for block in &function.blocks {
                let native = b.create_block();
                for _ in &block.parameters {
                    b.append_block_param(native, types::I64);
                }
                b.append_block_param(native, types::I32);
                pcs.insert(block.pc, native);
            }
            b.switch_to_block(prologue);
            let params = b.block_params(prologue).to_vec();
            let state = params[0];
            let budget = params[1];
            let depth = params[2];
            let boundary = params[3];
            let mut entry_values = params[4..].to_vec();
            for _ in 0..function.x_count.saturating_sub(function.arity as usize) + function.y_count
            {
                entry_values.push(b.ins().iconst(types::I64, 0));
            }
            jump(&mut b, pcs[&function.entry], &entry_values, budget);
            for block in &function.blocks {
                b.switch_to_block(pcs[&block.pc]);
                let incoming = b.block_params(pcs[&block.pc]).to_vec();
                let mut values = vec![None; function.types.len()];
                for (id, value) in block.parameters.iter().zip(&incoming) {
                    values[id.0 as usize] = Some(*value);
                }
                let current_budget = *incoming.last().expect("budget block parameter");
                let at = |source: Source,
                          values: &Vec<Option<cl::Value>>,
                          b: &mut FunctionBuilder<'_>|
                 -> cl::Value {
                    match source {
                        Source::Constant(n) => b.ins().iconst(types::I64, n),
                        Source::Value(id) => values[id.0 as usize].expect("SSA source"),
                    }
                };
                match block.operation.clone() {
                    Operation::Move { source, target } => {
                        let value = at(source, &values, &mut b);
                        define_output(block, function, target, value, &mut values);
                        branch_next(&mut b, block, &values, current_budget, &pcs);
                    }
                    Operation::Arithmetic {
                        kind,
                        lhs,
                        rhs,
                        target,
                    } => {
                        let a = at(lhs, &values, &mut b);
                        let c = at(rhs, &values, &mut b);
                        if matches!(kind, IntOp::Div | IntOp::Rem | IntOp::Bsl | IntOp::Bsr) {
                            let invalid = if matches!(kind, IntOp::Div | IntOp::Rem) {
                                b.ins().icmp_imm_s(IntCC::Equal, c, 0)
                            } else {
                                let negative = b.ins().icmp_imm_s(IntCC::SignedLessThan, c, 0);
                                let large = b.ins().icmp_imm_s(IntCC::SignedGreaterThan, c, 59);
                                b.ins().bor(negative, large)
                            };
                            let slow = b.create_block();
                            let ready = b.create_block();
                            b.ins().brif(invalid, slow, &[], ready, &[]);
                            b.switch_to_block(slow);
                            deopt(
                                &mut b,
                                block,
                                &values,
                                state,
                                current_budget,
                                boundary,
                                materialize,
                            );
                            b.switch_to_block(ready);
                        }
                        let (result, bad) = arithmetic(&mut b, kind, a, c)?;
                        let cold = b.create_block();
                        let good = b.create_block();
                        b.ins().brif(bad, cold, &[], good, &[]);
                        b.switch_to_block(cold);
                        deopt(
                            &mut b,
                            block,
                            &values,
                            state,
                            current_budget,
                            boundary,
                            materialize,
                        );
                        b.switch_to_block(good);
                        define_output(block, function, target, result, &mut values);
                        branch_next(&mut b, block, &values, current_budget, &pcs);
                    }
                    Operation::Guard {
                        kind,
                        lhs,
                        rhs,
                        fail,
                        return_on_pass,
                    } => {
                        if self.force_deopt {
                            deopt(
                                &mut b,
                                block,
                                &values,
                                state,
                                current_budget,
                                boundary,
                                materialize,
                            );
                            continue;
                        }
                        let current_budget = if fail <= block.pc && pcs.contains_key(&fail) {
                            poll(
                                &mut b,
                                block,
                                &values,
                                state,
                                current_budget,
                                boundary,
                                materialize,
                            )
                        } else {
                            current_budget
                        };
                        let a = at(lhs, &values, &mut b);
                        let c = at(rhs, &values, &mut b);
                        let predicate = b.ins().icmp(
                            match kind {
                                Compare::Lt => IntCC::SignedLessThan,
                                Compare::Ge => IntCC::SignedGreaterThanOrEqual,
                                Compare::Eq => IntCC::Equal,
                                Compare::Ne => IntCC::NotEqual,
                            },
                            a,
                            c,
                        );
                        let fail_block = if let Some(&target) = pcs.get(&fail) {
                            target
                        } else {
                            b.create_block()
                        };
                        let fail_cold = !pcs.contains_key(&fail);
                        if return_on_pass {
                            let ret = b.create_block();
                            let fail_args = args(block, &values, current_budget);
                            b.ins().brif(
                                predicate,
                                ret,
                                &[],
                                fail_block,
                                if fail_cold {
                                    &[][..]
                                } else {
                                    fail_args.as_slice()
                                },
                            );
                            b.switch_to_block(ret);
                            finish(
                                &mut b,
                                0,
                                values[block.parameters[0].0 as usize].expect("X0"),
                                current_budget,
                            );
                        } else {
                            let next = pcs[&(block.pc + 1)];
                            let arguments = args(block, &values, current_budget);
                            b.ins().brif(
                                predicate,
                                next,
                                &arguments,
                                fail_block,
                                if fail_cold {
                                    &[][..]
                                } else {
                                    arguments.as_slice()
                                },
                            );
                        }
                        if fail_cold {
                            b.switch_to_block(fail_block);
                            deopt(
                                &mut b,
                                block,
                                &values,
                                state,
                                current_budget,
                                boundary,
                                materialize,
                            );
                        }
                    }
                    Operation::IntegerGuard { source } => {
                        let _ = at(source, &values, &mut b);
                        if self.force_deopt {
                            deopt(
                                &mut b,
                                block,
                                &values,
                                state,
                                current_budget,
                                boundary,
                                materialize,
                            );
                        } else {
                            branch_next(&mut b, block, &values, current_budget, &pcs);
                        }
                    }
                    Operation::Select {
                        source,
                        cases,
                        fallback,
                    } => {
                        if self.force_deopt {
                            deopt(
                                &mut b,
                                block,
                                &values,
                                state,
                                current_budget,
                                boundary,
                                materialize,
                            );
                            continue;
                        }
                        let current_budget = if cases
                            .iter()
                            .any(|(_, target)| *target <= block.pc && pcs.contains_key(target))
                            || (fallback <= block.pc && pcs.contains_key(&fallback))
                        {
                            poll(
                                &mut b,
                                block,
                                &values,
                                state,
                                current_budget,
                                boundary,
                                materialize,
                            )
                        } else {
                            current_budget
                        };
                        let value = at(source, &values, &mut b);
                        for (key, target) in cases {
                            let yes = if let Some(&native) = pcs.get(&target) {
                                native
                            } else {
                                b.create_block()
                            };
                            let cold = !pcs.contains_key(&target);
                            let no = b.create_block();
                            let equal = b.ins().icmp_imm_s(IntCC::Equal, value, key);
                            let arguments = args(block, &values, current_budget);
                            b.ins().brif(
                                equal,
                                yes,
                                if cold { &[][..] } else { arguments.as_slice() },
                                no,
                                &[],
                            );
                            if cold {
                                b.switch_to_block(yes);
                                deopt(
                                    &mut b,
                                    block,
                                    &values,
                                    state,
                                    current_budget,
                                    boundary,
                                    materialize,
                                );
                            }
                            b.switch_to_block(no);
                        }
                        if let Some(&native) = pcs.get(&fallback) {
                            jump(&mut b, native, &outgoing(block, &values), current_budget);
                        } else {
                            deopt(
                                &mut b,
                                block,
                                &values,
                                state,
                                current_budget,
                                boundary,
                                materialize,
                            );
                        }
                    }
                    Operation::Allocate { .. }
                    | Operation::Deallocate { .. }
                    | Operation::Trim { .. }
                    | Operation::InitYregs { .. } => {
                        branch_next(&mut b, block, &values, current_budget, &pcs);
                    }
                    Operation::Jump { target } => {
                        let budget = if target <= block.pc {
                            poll(
                                &mut b,
                                block,
                                &values,
                                state,
                                current_budget,
                                boundary,
                                materialize,
                            )
                        } else {
                            current_budget
                        };
                        jump(&mut b, pcs[&target], &outgoing(block, &values), budget);
                    }
                    Operation::Return => {
                        let result = values[block.parameters[0].0 as usize].expect("X0");
                        finish(&mut b, 0, result, current_budget);
                    }
                    Operation::Call {
                        target,
                        arity,
                        tail,
                        resume,
                    } => {
                        let call_args = (0..arity as usize)
                            .map(|n| values[block.parameters[n].0 as usize].expect("call arg"))
                            .collect::<Vec<_>>();
                        emit_call(
                            &mut b,
                            block,
                            function,
                            functions,
                            module_id,
                            target,
                            arity,
                            tail,
                            resume,
                            &values,
                            &mut values.clone(),
                            state,
                            current_budget,
                            depth,
                            boundary,
                            materialize,
                            refs[&target],
                            &pcs,
                            &call_args,
                        )?;
                    }
                    Operation::MoveCall {
                        source,
                        destination,
                        target,
                        arity,
                        resume,
                    } => {
                        let moved = at(source, &values, &mut b);
                        let mut call_args = (0..arity as usize)
                            .map(|n| values[block.parameters[n].0 as usize].expect("call arg"))
                            .collect::<Vec<_>>();
                        if let Location::X(reg) = destination {
                            call_args[reg as usize] = moved;
                        }
                        emit_call(
                            &mut b,
                            block,
                            function,
                            functions,
                            module_id,
                            target,
                            arity,
                            false,
                            resume,
                            &values,
                            &mut values.clone(),
                            state,
                            current_budget,
                            depth,
                            boundary,
                            materialize,
                            refs[&target],
                            &pcs,
                            &call_args,
                        )?;
                    }
                }
            }
            b.seal_all_blocks();
            b.finalize(config);
        }
        self.module
            .define_function(id, &mut context)
            .map_err(|e| CompileError::Codegen(format!("{e:?}")))?;
        Ok(())
    }

    fn define_wrapper(
        &mut self,
        module_id: usize,
        entry: usize,
        function: &Function,
        fast: FuncId,
    ) -> Result<FuncId, CompileError> {
        let mut sig = self.module.make_signature();
        sig.params.push(cl::AbiParam::new(types::I64));
        sig.returns.push(cl::AbiParam::new(types::I32));
        let id = self
            .module
            .declare_function(
                &format!("arinsal_opt_m{module_id}_r{entry}_entry"),
                Linkage::Local,
                &sig,
            )
            .map_err(|e| CompileError::Codegen(e.to_string()))?;
        let mut context = self.module.make_context();
        context.func.signature = sig;
        let fast = self.module.declare_func_in_func(fast, &mut context.func);
        let config = self.module.isa().frontend_config();
        let mut fb_context = FunctionBuilderContext::new();
        {
            let mut b = FunctionBuilder::new(&mut context.func, &mut fb_context);
            let start = b.create_block();
            b.append_block_params_for_function_params(start);
            b.switch_to_block(start);
            let state = b.block_params(start)[0];
            let x = b.ins().load(types::I64, MemFlagsData::new(), state, X);
            let budget = b.ins().load(types::I32, MemFlagsData::new(), state, REDS);
            let stop = b.ins().load(types::I64, MemFlagsData::new(), state, STOP);
            let end = b
                .ins()
                .load(types::I64, MemFlagsData::new(), state, STACK_END);
            let bytes = b.ins().isub(end, stop);
            let boundary = b.ins().ushr_imm_u(bytes, 3);
            let mut args = vec![state, budget, b.ins().iconst(types::I32, 0), boundary];
            for reg in 0..function.arity {
                let tagged = b
                    .ins()
                    .load(types::I64, MemFlagsData::new(), x, reg as i32 * 8);
                let tag = b.ins().band_imm_s(tagged, 15);
                let is_small = b.ins().icmp_imm_s(IntCC::Equal, tag, 15);
                let good = b.create_block();
                let slow = b.create_block();
                b.ins().brif(is_small, good, &[], slow, &[]);
                b.switch_to_block(slow);
                let ip = b.ins().iconst(types::I32, entry as i64);
                b.ins().store(MemFlagsData::new(), ip, state, IP);
                let one = b.ins().iconst(types::I32, 1);
                b.ins().return_(&[one]);
                b.switch_to_block(good);
                args.push(b.ins().sshr_imm_s(tagged, 4));
            }
            let call = b.ins().call(fast, &args);
            let results = b.inst_results(call).to_vec();
            b.ins().store(MemFlagsData::new(), results[2], state, REDS);
            let success = b.ins().icmp_imm_s(IntCC::Equal, results[0], 0);
            let write = b.create_block();
            let done = b.create_block();
            b.ins().brif(success, write, &[], done, &[]);
            b.switch_to_block(write);
            let tagged = tag(&mut b, results[1]);
            b.ins().store(MemFlagsData::new(), tagged, x, 0);
            b.ins().jump(done, &[]);
            b.switch_to_block(done);
            b.ins().return_(&[results[0]]);
            b.seal_all_blocks();
            b.finalize(config);
        }
        self.module
            .define_function(id, &mut context)
            .map_err(|e| CompileError::Codegen(format!("{e:?}")))?;
        Ok(id)
    }
}

fn fast_signature(module: &JITModule, arity: u8) -> cl::Signature {
    let mut sig = module.make_signature();
    sig.params.push(cl::AbiParam::new(types::I64));
    sig.params.push(cl::AbiParam::new(types::I32));
    sig.params.push(cl::AbiParam::new(types::I32));
    sig.params.push(cl::AbiParam::new(types::I64));
    for _ in 0..arity {
        sig.params.push(cl::AbiParam::new(types::I64));
    }
    sig.returns.push(cl::AbiParam::new(types::I32));
    sig.returns.push(cl::AbiParam::new(types::I64));
    sig.returns.push(cl::AbiParam::new(types::I32));
    sig
}

fn define_output(
    block: &Block,
    function: &Function,
    target: Location,
    value: cl::Value,
    values: &mut [Option<cl::Value>],
) {
    let n = match target {
        Location::X(n) => n as usize,
        Location::Y(n) => function.x_count + n as usize,
        Location::Fr(_) => unreachable!(),
    };
    values[block.outgoing[n].0 as usize] = Some(value);
}
fn outgoing(block: &Block, values: &[Option<cl::Value>]) -> Vec<cl::Value> {
    block
        .outgoing
        .iter()
        .map(|id| values[id.0 as usize].expect("outgoing SSA value"))
        .collect()
}
fn args(block: &Block, values: &[Option<cl::Value>], budget: cl::Value) -> Vec<cl::BlockArg> {
    let mut args = outgoing(block, values)
        .into_iter()
        .map(cl::BlockArg::Value)
        .collect::<Vec<_>>();
    args.push(cl::BlockArg::Value(budget));
    args
}
fn jump(b: &mut FunctionBuilder<'_>, target: cl::Block, values: &[cl::Value], budget: cl::Value) {
    let mut args = values
        .iter()
        .copied()
        .map(cl::BlockArg::Value)
        .collect::<Vec<_>>();
    args.push(cl::BlockArg::Value(budget));
    b.ins().jump(target, &args);
}
fn branch_next(
    b: &mut FunctionBuilder<'_>,
    block: &Block,
    values: &[Option<cl::Value>],
    budget: cl::Value,
    pcs: &BTreeMap<usize, cl::Block>,
) {
    jump(b, pcs[&(block.pc + 1)], &outgoing(block, values), budget);
}
fn finish(b: &mut FunctionBuilder<'_>, status: i64, result: cl::Value, budget: cl::Value) {
    let status = b.ins().iconst(types::I32, status);
    b.ins().return_(&[status, result, budget]);
}
fn tag(b: &mut FunctionBuilder<'_>, raw: cl::Value) -> cl::Value {
    let shifted = b.ins().ishl_imm_u(raw, 4);
    b.ins().bor_imm_s(shifted, 15)
}
fn arithmetic(
    b: &mut FunctionBuilder<'_>,
    kind: IntOp,
    a: cl::Value,
    c: cl::Value,
) -> Result<(cl::Value, cl::Value), CompileError> {
    let (result, wide_bad) = match kind {
        IntOp::Add => {
            let (value, bad) = b.ins().sadd_overflow(a, c);
            (value, bad)
        }
        IntOp::Sub => {
            let (value, bad) = b.ins().ssub_overflow(a, c);
            (value, bad)
        }
        IntOp::Mul | IntOp::Bsl => {
            let lhs = b.ins().sextend(types::I128, a);
            let wide = if kind == IntOp::Mul {
                let rhs = b.ins().sextend(types::I128, c);
                b.ins().imul(lhs, rhs)
            } else {
                b.ins().ishl(lhs, c)
            };
            let min = b.ins().iconst(types::I64, arinsal_term::MIN_SMALL);
            let max = b.ins().iconst(types::I64, arinsal_term::MAX_SMALL);
            let min = b.ins().sextend(types::I128, min);
            let max = b.ins().sextend(types::I128, max);
            let lo = b.ins().icmp(IntCC::SignedLessThan, wide, min);
            let hi = b.ins().icmp(IntCC::SignedGreaterThan, wide, max);
            (b.ins().ireduce(types::I64, wide), b.ins().bor(lo, hi))
        }
        IntOp::Div => {
            let value = b.ins().sdiv(a, c);
            (value, b.ins().iconst(types::I8, 0))
        }
        IntOp::Rem => {
            let value = b.ins().srem(a, c);
            (value, b.ins().iconst(types::I8, 0))
        }
        IntOp::Band => {
            let value = b.ins().band(a, c);
            (value, b.ins().iconst(types::I8, 0))
        }
        IntOp::Bor => {
            let value = b.ins().bor(a, c);
            (value, b.ins().iconst(types::I8, 0))
        }
        IntOp::Bsr => {
            let value = b.ins().sshr(a, c);
            (value, b.ins().iconst(types::I8, 0))
        }
    };
    let lo = b
        .ins()
        .icmp_imm_s(IntCC::SignedLessThan, result, arinsal_term::MIN_SMALL);
    let hi = b
        .ins()
        .icmp_imm_s(IntCC::SignedGreaterThan, result, arinsal_term::MAX_SMALL);
    let outside = b.ins().bor(lo, hi);
    let bad = b.ins().bor(wide_bad, outside);
    Ok((result, bad))
}

fn materialize(
    b: &mut FunctionBuilder<'_>,
    block: &Block,
    values: &[Option<cl::Value>],
    state: cl::Value,
    boundary: cl::Value,
    cp: cl::Value,
    materialize: cl::FuncRef,
) -> cl::Value {
    let slots = block.deopt.frame_slots as usize;
    let slot = b.create_sized_stack_slot(StackSlotData::new(
        StackSlotKind::ExplicitSlot,
        (slots.max(1) * 8) as u32,
        3,
    ));
    for n in 0..slots {
        let tagged = if let Some((_, Recipe::Small(id))) = block
            .deopt
            .live
            .iter()
            .find(|(place, _)| *place == Location::Y(n as u16))
        {
            tag(b, values[id.0 as usize].expect("mapped Y"))
        } else {
            b.ins().iconst(types::I64, 0x3b)
        };
        b.ins()
            .stack_store(types::I64, tagged, slot, (n * 8) as i32);
    }
    let ptr = b.ins().stack_addr(types::I64, slot, 0);
    let count = b.ins().iconst(types::I32, slots as i64);
    let call = b
        .ins()
        .call(materialize, &[state, boundary, cp, ptr, count]);
    b.inst_results(call)[0]
}

fn deopt(
    b: &mut FunctionBuilder<'_>,
    block: &Block,
    values: &[Option<cl::Value>],
    state: cl::Value,
    budget: cl::Value,
    boundary: cl::Value,
    materialize_fn: cl::FuncRef,
) {
    let x = b.ins().load(types::I64, MemFlagsData::new(), state, X);
    for (place, recipe) in &block.deopt.live {
        if let Location::X(reg) = place {
            let raw = match recipe {
                Recipe::Small(id) => values[id.0 as usize].expect("mapped X"),
                _ => unreachable!(),
            };
            let tagged = tag(b, raw);
            b.ins()
                .store(MemFlagsData::new(), tagged, x, *reg as i32 * 8);
        }
    }
    let ip = b.ins().iconst(types::I32, block.pc as i64);
    b.ins().store(MemFlagsData::new(), ip, state, IP);
    b.ins().store(MemFlagsData::new(), budget, state, REDS);
    let cp = b.ins().iconst(types::I64, 0);
    let status = materialize(b, block, values, state, boundary, cp, materialize_fn);
    let fail = b.ins().icmp_imm_s(IntCC::NotEqual, status, 0);
    let two = b.ins().iconst(types::I32, 2);
    let one = b.ins().iconst(types::I32, 1);
    let code = b.ins().select(fail, two, one);
    let zero = b.ins().iconst(types::I64, 0);
    b.ins().return_(&[code, zero, budget]);
}

fn poll(
    b: &mut FunctionBuilder<'_>,
    block: &Block,
    values: &[Option<cl::Value>],
    state: cl::Value,
    budget: cl::Value,
    boundary: cl::Value,
    materialize_fn: cl::FuncRef,
) -> cl::Value {
    let exhausted = b.ins().icmp_imm_s(IntCC::SignedLessThanOrEqual, budget, 1);
    let slow = b.create_block();
    let ready = b.create_block();
    b.ins().brif(exhausted, slow, &[], ready, &[]);
    b.switch_to_block(slow);
    deopt(b, block, values, state, budget, boundary, materialize_fn);
    b.switch_to_block(ready);
    b.ins().iadd_imm_s(budget, -1)
}

#[allow(clippy::too_many_arguments)]
fn emit_call(
    b: &mut FunctionBuilder<'_>,
    block: &Block,
    function: &Function,
    functions: &BTreeMap<usize, Function>,
    module_id: usize,
    target: usize,
    arity: u8,
    tail: bool,
    resume: usize,
    original: &[Option<cl::Value>],
    out: &mut [Option<cl::Value>],
    state: cl::Value,
    budget: cl::Value,
    depth: cl::Value,
    boundary: cl::Value,
    materialize_fn: cl::FuncRef,
    callee: cl::FuncRef,
    pcs: &BTreeMap<usize, cl::Block>,
    arguments: &[cl::Value],
) -> Result<(), CompileError> {
    if arguments.len() != arity as usize || functions[&target].arity != arity {
        return Err(CompileError::Codegen("callee arity mismatch".into()));
    }
    let full = b
        .ins()
        .icmp_imm_s(IntCC::UnsignedGreaterThanOrEqual, depth, MAX_NATIVE_DEPTH);
    let exhausted = b.ins().icmp_imm_s(IntCC::SignedLessThanOrEqual, budget, 1);
    let stop = b.ins().bor(full, exhausted);
    let slow = b.create_block();
    let ready = b.create_block();
    b.ins().brif(stop, slow, &[], ready, &[]);
    b.switch_to_block(slow);
    deopt(b, block, original, state, budget, boundary, materialize_fn);
    b.switch_to_block(ready);
    let budget = b.ins().iadd_imm_s(budget, -1);
    let next_depth = if tail {
        depth
    } else {
        b.ins().iadd_imm_s(depth, 1)
    };
    let mut call_args = vec![state, budget, next_depth, boundary];
    call_args.extend_from_slice(arguments);
    if tail && target == function.entry {
        let mut loop_values = arguments.to_vec();
        for _ in arguments.len()..function.x_count + function.y_count {
            loop_values.push(b.ins().iconst(types::I64, 0));
        }
        jump(b, pcs[&function.entry], &loop_values, budget);
        return Ok(());
    }
    let call = b.ins().call(callee, &call_args);
    let results = b.inst_results(call).to_vec();
    let ok = b.ins().icmp_imm_s(IntCC::Equal, results[0], 0);
    let good = b.create_block();
    let propagate = b.create_block();
    b.ins().brif(ok, good, &[], propagate, &[]);
    b.switch_to_block(propagate);
    if !tail {
        let status_is_deopt = b.ins().icmp_imm_s(IntCC::Equal, results[0], 1);
        let make = b.create_block();
        let forward = b.create_block();
        b.ins().brif(status_is_deopt, make, &[], forward, &[]);
        b.switch_to_block(make);
        let cp_bits = ((((module_id as u64) << 32) | (resume as u64)) << 6) | 0x1b;
        let cp = b.ins().iconst(types::I64, cp_bits as i64);
        let m = materialize(b, block, original, state, boundary, cp, materialize_fn);
        let failure = b.ins().icmp_imm_s(IntCC::NotEqual, m, 0);
        let bad = b.create_block();
        b.ins().brif(failure, bad, &[], forward, &[]);
        b.switch_to_block(bad);
        let two = b.ins().iconst(types::I32, 2);
        let zero = b.ins().iconst(types::I64, 0);
        b.ins().return_(&[two, zero, results[2]]);
        b.switch_to_block(forward);
    }
    b.ins().return_(&results);
    b.switch_to_block(good);
    if tail {
        b.ins().return_(&results);
    } else {
        out[block.outgoing[0].0 as usize] = Some(results[1]);
        // X registers other than X0 are caller-clobbered. The integer subset
        // only accepts continuations that reconstruct them from Y if needed.
        for n in 1..function.x_count {
            if block.outgoing[n] != block.parameters[n] {
                out[block.outgoing[n].0 as usize] = original[block.parameters[n].0 as usize];
            }
        }
        jump(b, pcs[&resume], &outgoing(block, out), results[2]);
    }
    Ok(())
}
