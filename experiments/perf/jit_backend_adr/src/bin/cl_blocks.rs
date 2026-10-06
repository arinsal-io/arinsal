//! Isolate the cost of using one Cranelift block per modeled operation.

use cranelift_codegen::ir::{self, InstBuilder, MemFlagsData, types};
use cranelift_frontend::{FunctionBuilder, FunctionBuilderContext};
use cranelift_jit::{JITBuilder, JITModule};
use cranelift_module::{Linkage, Module};
use std::time::Instant;

fn compile(per_op_block: bool, fastalloc: bool) -> (f64, usize) {
    let start = Instant::now();
    let flags = if fastalloc {
        vec![("regalloc_algorithm", "single_pass")]
    } else {
        Vec::new()
    };
    let builder =
        JITBuilder::with_flags(&flags, cranelift_module::default_libcall_names()).unwrap();
    let mut module = JITModule::new(builder);
    let mut signature = module.make_signature();
    signature.params.push(ir::AbiParam::new(types::I64));
    signature.returns.push(ir::AbiParam::new(types::I64));
    let id = module
        .declare_function("adds", Linkage::Local, &signature)
        .unwrap();
    let mut context = module.make_context();
    context.func.signature = signature;
    let mut fb_context = FunctionBuilderContext::new();
    {
        let mut b = FunctionBuilder::new(&mut context.func, &mut fb_context);
        let blocks: Vec<_> = (0..if per_op_block { 1000 } else { 1 })
            .map(|_| b.create_block())
            .collect();
        b.append_block_params_for_function_params(blocks[0]);
        let pointer = b.block_params(blocks[0])[0];
        for (index, block) in blocks.iter().enumerate() {
            b.switch_to_block(*block);
            let iterations = if per_op_block { 1 } else { 999 };
            for _ in 0..iterations {
                if per_op_block && index == 999 {
                    break;
                }
                let value = b.ins().load(types::I64, MemFlagsData::new(), pointer, 0);
                let next = b.ins().iadd_imm_s(value, 1);
                b.ins().store(MemFlagsData::new(), next, pointer, 0);
            }
            if per_op_block && index < 999 {
                b.ins().jump(blocks[index + 1], &[]);
            } else {
                let result = b.ins().load(types::I64, MemFlagsData::new(), pointer, 0);
                b.ins().return_(&[result]);
            }
        }
        b.seal_all_blocks();
        b.finalize(module.isa().frontend_config());
    }
    module.define_function(id, &mut context).unwrap();
    let bytes = context.compiled_code().unwrap().code_buffer().len();
    module.finalize_definitions().unwrap();
    let time_us = start.elapsed().as_secs_f64() * 1_000_000.0;
    // SAFETY: Cranelift emitted the declared C ABI, and module lives through this call.
    let entry: extern "C" fn(*mut i64) -> i64 =
        unsafe { std::mem::transmute(module.get_finalized_function(id)) };
    let mut value = 0;
    assert_eq!(entry(&mut value), 999);
    (time_us, bytes)
}

fn median(mut numbers: Vec<f64>) -> f64 {
    numbers.sort_by(f64::total_cmp);
    numbers[numbers.len() / 2]
}

fn main() {
    for per_op_block in [true, false] {
        for fastalloc in [false, true] {
            let mut times = Vec::new();
            let mut bytes = 0;
            for _ in 0..5 {
                let (time, size) = compile(per_op_block, fastalloc);
                times.push(time);
                bytes = size;
            }
            println!(
                "blocks={} fastalloc={} compile_1000_ops_median_us={:.0} code_bytes={bytes}",
                if per_op_block { "per_op" } else { "single" },
                fastalloc,
                median(times)
            );
        }
    }
}
