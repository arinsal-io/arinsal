use cranelift_codegen::ir::{self, InstBuilder, MemFlagsData, condcodes::IntCC, types};
use cranelift_frontend::{FunctionBuilder, FunctionBuilderContext, Switch};
use cranelift_jit::{JITBuilder, JITModule};
use cranelift_module::{Linkage, Module};
use std::hint::black_box;
use std::time::{Duration, Instant};

#[cfg(all(target_arch = "aarch64", target_os = "macos"))]
mod a64;

#[derive(Clone, Copy)]
enum Op {
    Move(u8, u8),
    Add(u8, u8, u8),
    AddImm(u8, u8, i64),
    BranchZero(u8, usize),
    BranchGe(u8, u8, usize),
    BranchNeImm(u8, i64, usize),
    BranchLtImm(u8, i64, usize),
    Jump(usize),
    ListLoad(u8, u8),
    ListStore(u8, u8),
    TupleSet(u8),
    TupleGet(u8),
    ByteLoad(u8, u8),
    Call(usize),
    Ret,
    Halt,
    Nop,
    FusedDecIncJump(u8, u8, usize),
}

#[derive(Clone)]
#[repr(C)]
struct State {
    regs: [i64; 8],
    list: Vec<i64>,
    tuple: [i64; 3],
    binary: Vec<u8>,
    stack: Vec<(usize, [i64; 8])>,
}

#[inline(never)]
extern "C" fn slow(state: *mut State, opcode: i32, dst: i32, src: i32) -> i32 {
    // SAFETY: The JIT is called synchronously with a live, uniquely borrowed State.
    let s = unsafe { &mut *state };
    match opcode {
        0 => s.regs[dst as usize] = s.list[s.regs[src as usize] as usize],
        1 => s.list[s.regs[dst as usize] as usize] = s.regs[src as usize],
        2 => s.tuple[1] = s.regs[src as usize],
        3 => s.regs[dst as usize] = s.tuple[1],
        4 => s.regs[dst as usize] = i64::from(s.binary[s.regs[src as usize] as usize]),
        5 => {
            s.stack.push((dst as usize, s.regs));
            return src;
        }
        6 => {
            let result = s.regs[0];
            if let Some((return_ip, saved)) = s.stack.pop() {
                s.regs = saved;
                s.regs[0] = result;
                return return_ip as i32;
            }
            return -1;
        }
        _ => unreachable!(),
    }
    -2
}

fn programs(n: i64) -> Vec<(&'static str, Vec<Op>, State, i64, u64)> {
    let empty = State {
        regs: [0; 8],
        list: Vec::new(),
        tuple: [0; 3],
        binary: Vec::new(),
        stack: Vec::new(),
    };
    let mut tail = empty.clone();
    tail.regs[0] = n;
    let mut list = empty.clone();
    list.list = (1..=n).collect();
    list.regs[3] = n;
    let mut fib = empty.clone();
    let fib_n = n.clamp(0, 22);
    fib.regs[0] = fib_n;
    let (mut fib_value, mut fib_next) = (0_i64, 1_i64);
    for _ in 0..fib_n {
        (fib_value, fib_next) = (fib_next, fib_value + fib_next);
    }
    let mut tuple = empty.clone();
    tuple.regs[0] = n;
    let mut binary = empty;
    binary.binary = [1, 2, 3, 4].repeat(n as usize);
    binary.regs[3] = binary.binary.len() as i64;
    vec![
        (
            "tail",
            vec![
                Op::BranchZero(0, 4),
                Op::AddImm(0, 0, -1),
                Op::AddImm(1, 1, 1),
                Op::Jump(0),
                Op::Halt,
            ],
            tail,
            n,
            n as u64,
        ),
        (
            "list",
            vec![
                Op::BranchGe(0, 3, 7),
                Op::ListLoad(2, 0),
                Op::AddImm(2, 2, 1),
                Op::ListStore(0, 2),
                Op::Add(1, 1, 2),
                Op::AddImm(0, 0, 1),
                Op::Jump(0),
                Op::Halt,
            ],
            list,
            n * (n + 3) / 2,
            n as u64,
        ),
        (
            "fib",
            vec![
                Op::BranchLtImm(0, 2, 9),
                Op::Move(1, 0),
                Op::AddImm(0, 0, -1),
                Op::Call(0),
                Op::Move(2, 0),
                Op::AddImm(0, 1, -2),
                Op::Call(0),
                Op::Add(0, 0, 2),
                Op::Ret,
                Op::Ret,
            ],
            fib,
            fib_value,
            (2 * fib_next - 1) as u64,
        ),
        (
            "tuple",
            vec![
                Op::BranchZero(0, 6),
                Op::TupleSet(0),
                Op::TupleGet(2),
                Op::Add(1, 1, 2),
                Op::AddImm(0, 0, -1),
                Op::Jump(0),
                Op::Halt,
            ],
            tuple,
            n * (n + 1) / 2,
            n as u64,
        ),
        (
            "binary",
            vec![
                Op::BranchGe(0, 3, 6),
                Op::ByteLoad(2, 0),
                Op::BranchNeImm(2, 2, 4),
                Op::AddImm(1, 1, 1),
                Op::AddImm(0, 0, 1),
                Op::Jump(0),
                Op::Halt,
            ],
            binary,
            n,
            (4 * n) as u64,
        ),
    ]
}

fn fuse(code: &[Op]) -> Vec<Op> {
    let mut result = code.to_vec();
    let targets: Vec<_> = code
        .iter()
        .filter_map(|op| match op {
            Op::BranchZero(_, t)
            | Op::BranchGe(_, _, t)
            | Op::BranchNeImm(_, _, t)
            | Op::BranchLtImm(_, _, t)
            | Op::Jump(t)
            | Op::Call(t) => Some(*t),
            _ => None,
        })
        .collect();
    for ip in 0..code.len().saturating_sub(2) {
        if let (Op::AddImm(a, b, -1), Op::AddImm(c, d, 1), Op::Jump(target)) =
            (code[ip], code[ip + 1], code[ip + 2])
            && a == b
            && c == d
            && target < ip
            && !targets.contains(&(ip + 1))
            && !targets.contains(&(ip + 2))
        {
            result[ip] = Op::FusedDecIncJump(a, c, target);
            result[ip + 1] = Op::Nop;
            result[ip + 2] = Op::Nop;
        }
    }
    result
}

fn interpret(code: &[Op], s: &mut State) -> (i64, u64) {
    let mut ip = 0;
    let mut instructions = 0;
    loop {
        let op = code[ip];
        instructions += 1;
        match op {
            Op::Nop => {}
            Op::FusedDecIncJump(a, c, target) => {
                s.regs[a as usize] -= 1;
                s.regs[c as usize] += 1;
                ip = target;
                instructions += 2;
                continue;
            }
            Op::Move(d, a) => s.regs[d as usize] = s.regs[a as usize],
            Op::Add(d, a, b) => s.regs[d as usize] = s.regs[a as usize] + s.regs[b as usize],
            Op::AddImm(d, a, k) => s.regs[d as usize] = s.regs[a as usize] + k,
            Op::BranchZero(r, target) if s.regs[r as usize] == 0 => {
                ip = target;
                continue;
            }
            Op::BranchGe(a, b, target) if s.regs[a as usize] >= s.regs[b as usize] => {
                ip = target;
                continue;
            }
            Op::BranchNeImm(r, k, target) if s.regs[r as usize] != k => {
                ip = target;
                continue;
            }
            Op::BranchLtImm(r, k, target) if s.regs[r as usize] < k => {
                ip = target;
                continue;
            }
            Op::Jump(target) => {
                ip = target;
                continue;
            }
            Op::ListLoad(d, i) => s.regs[d as usize] = s.list[s.regs[i as usize] as usize],
            Op::ListStore(i, r) => s.list[s.regs[i as usize] as usize] = s.regs[r as usize],
            Op::TupleSet(r) => s.tuple[1] = s.regs[r as usize],
            Op::TupleGet(d) => s.regs[d as usize] = s.tuple[1],
            Op::ByteLoad(d, i) => {
                s.regs[d as usize] = i64::from(s.binary[s.regs[i as usize] as usize])
            }
            Op::Call(target) => {
                s.stack.push((ip + 1, s.regs));
                ip = target;
                continue;
            }
            Op::Ret => {
                let value = s.regs[0];
                if let Some((next, saved)) = s.stack.pop() {
                    s.regs = saved;
                    s.regs[0] = value;
                    ip = next;
                    continue;
                }
                return (value, instructions);
            }
            Op::Halt => return (s.regs[1], instructions),
            _ => {}
        }
        ip += 1;
    }
}

type Compiled = unsafe extern "C" fn(*mut State) -> i64;

fn compile(code: &[Op]) -> (JITModule, Compiled, Duration, usize) {
    let started = Instant::now();
    let mut jit_builder = JITBuilder::new(cranelift_module::default_libcall_names()).unwrap();
    jit_builder.symbol("pf_slow", slow as *const u8);
    let mut module = JITModule::new(jit_builder);
    let ptr = types::I64;
    let mut helper_sig = module.make_signature();
    helper_sig.params.extend([
        ir::AbiParam::new(ptr),
        ir::AbiParam::new(types::I32),
        ir::AbiParam::new(types::I32),
        ir::AbiParam::new(types::I32),
    ]);
    helper_sig.returns.push(ir::AbiParam::new(types::I32));
    let helper = module
        .declare_function("pf_slow", Linkage::Import, &helper_sig)
        .unwrap();
    let mut sig = module.make_signature();
    sig.params.push(ir::AbiParam::new(ptr));
    sig.returns.push(ir::AbiParam::new(types::I64));
    let function = module
        .declare_function("probe", Linkage::Local, &sig)
        .unwrap();
    let frontend_config = module.isa().frontend_config();
    let mut context = module.make_context();
    context.func.signature = sig;
    let helper_ref = module.declare_func_in_func(helper, &mut context.func);
    let mut fbctx = FunctionBuilderContext::new();
    {
        let mut b = FunctionBuilder::new(&mut context.func, &mut fbctx);
        let entry = b.create_block();
        let done = b.create_block();
        let dispatch = b.create_block();
        b.append_block_params_for_function_params(entry);
        b.append_block_param(dispatch, types::I32);
        let blocks: Vec<_> = code.iter().map(|_| b.create_block()).collect();
        b.switch_to_block(entry);
        let state = b.block_params(entry)[0];
        b.ins().jump(blocks[0], &[]);
        b.switch_to_block(dispatch);
        let next = b.block_params(dispatch)[0];
        let mut switch = Switch::new();
        for (index, block) in blocks.iter().enumerate() {
            switch.set_entry(index as u128, *block);
        }
        switch.emit(&mut b, next, done);
        let offset = std::mem::offset_of!(State, regs) as i32;
        for (index, op) in code.iter().enumerate() {
            b.switch_to_block(blocks[index]);
            let load = |b: &mut FunctionBuilder, r: u8| {
                b.ins().load(
                    types::I64,
                    MemFlagsData::new(),
                    state,
                    offset + i32::from(r) * 8,
                )
            };
            let store = |b: &mut FunctionBuilder, r: u8, v| {
                b.ins()
                    .store(MemFlagsData::new(), v, state, offset + i32::from(r) * 8);
            };
            let follow = |b: &mut FunctionBuilder| {
                b.ins().jump(blocks[index + 1], &[]);
            };
            match *op {
                Op::Move(d, a) => {
                    let v = load(&mut b, a);
                    store(&mut b, d, v);
                    follow(&mut b);
                }
                Op::Add(d, a, c) => {
                    let x = load(&mut b, a);
                    let y = load(&mut b, c);
                    let v = b.ins().iadd(x, y);
                    store(&mut b, d, v);
                    follow(&mut b);
                }
                Op::AddImm(d, a, k) => {
                    let x = load(&mut b, a);
                    let v = b.ins().iadd_imm_s(x, k);
                    store(&mut b, d, v);
                    follow(&mut b);
                }
                Op::BranchZero(r, t) | Op::BranchLtImm(r, 0, t) => {
                    let x = load(&mut b, r);
                    let test = b.ins().icmp_imm_s(IntCC::Equal, x, 0);
                    b.ins().brif(test, blocks[t], &[], blocks[index + 1], &[]);
                }
                Op::BranchGe(a, c, t) => {
                    let x = load(&mut b, a);
                    let y = load(&mut b, c);
                    let test = b.ins().icmp(IntCC::SignedGreaterThanOrEqual, x, y);
                    b.ins().brif(test, blocks[t], &[], blocks[index + 1], &[]);
                }
                Op::BranchNeImm(r, k, t) => {
                    let x = load(&mut b, r);
                    let test = b.ins().icmp_imm_s(IntCC::NotEqual, x, k);
                    b.ins().brif(test, blocks[t], &[], blocks[index + 1], &[]);
                }
                Op::BranchLtImm(r, k, t) => {
                    let x = load(&mut b, r);
                    let test = b.ins().icmp_imm_s(IntCC::SignedLessThan, x, k);
                    b.ins().brif(test, blocks[t], &[], blocks[index + 1], &[]);
                }
                Op::Jump(t) => {
                    b.ins().jump(blocks[t], &[]);
                }
                Op::Halt => {
                    let v = load(&mut b, 1);
                    b.ins().return_(&[v]);
                }
                Op::ListLoad(d, i) | Op::ByteLoad(d, i) => {
                    let kind = if matches!(op, Op::ListLoad(..)) { 0 } else { 4 };
                    let k = b.ins().iconst(types::I32, kind);
                    let d = b.ins().iconst(types::I32, i64::from(d));
                    let i = b.ins().iconst(types::I32, i64::from(i));
                    b.ins().call(helper_ref, &[state, k, d, i]);
                    follow(&mut b);
                }
                Op::ListStore(i, r) => {
                    let k = b.ins().iconst(types::I32, 1);
                    let i = b.ins().iconst(types::I32, i64::from(i));
                    let r = b.ins().iconst(types::I32, i64::from(r));
                    b.ins().call(helper_ref, &[state, k, i, r]);
                    follow(&mut b);
                }
                Op::TupleSet(r) => {
                    let k = b.ins().iconst(types::I32, 2);
                    let z = b.ins().iconst(types::I32, 0);
                    let r = b.ins().iconst(types::I32, i64::from(r));
                    b.ins().call(helper_ref, &[state, k, z, r]);
                    follow(&mut b);
                }
                Op::TupleGet(d) => {
                    let k = b.ins().iconst(types::I32, 3);
                    let d = b.ins().iconst(types::I32, i64::from(d));
                    let z = b.ins().iconst(types::I32, 0);
                    b.ins().call(helper_ref, &[state, k, d, z]);
                    follow(&mut b);
                }
                Op::Call(t) => {
                    let k = b.ins().iconst(types::I32, 5);
                    let ret = b.ins().iconst(types::I32, (index + 1) as i64);
                    let t = b.ins().iconst(types::I32, t as i64);
                    let call = b.ins().call(helper_ref, &[state, k, ret, t]);
                    let next = b.inst_results(call)[0];
                    b.ins().jump(dispatch, &[ir::BlockArg::Value(next)]);
                }
                Op::Ret => {
                    let k = b.ins().iconst(types::I32, 6);
                    let z = b.ins().iconst(types::I32, 0);
                    let call = b.ins().call(helper_ref, &[state, k, z, z]);
                    let next = b.inst_results(call)[0];
                    let end = b.ins().icmp_imm_s(IntCC::SignedLessThan, next, 0);
                    let resume = b.create_block();
                    b.ins().brif(end, done, &[], resume, &[]);
                    b.switch_to_block(resume);
                    b.ins().jump(dispatch, &[ir::BlockArg::Value(next)]);
                }
                Op::Nop => follow(&mut b),
                Op::FusedDecIncJump(a, c, t) => {
                    let x = load(&mut b, a);
                    let y = b.ins().iadd_imm_s(x, -1);
                    store(&mut b, a, y);
                    let x = load(&mut b, c);
                    let y = b.ins().iadd_imm_s(x, 1);
                    store(&mut b, c, y);
                    b.ins().jump(blocks[t], &[]);
                }
            }
        }
        b.switch_to_block(done);
        let result = b.ins().load(types::I64, MemFlagsData::new(), state, offset);
        b.ins().return_(&[result]);
        b.seal_all_blocks();
        b.finalize(frontend_config);
    }
    module.define_function(function, &mut context).unwrap();
    let bytes = context.compiled_code().unwrap().code_buffer().len();
    module.finalize_definitions().unwrap();
    let address = module.get_finalized_function(function);
    // SAFETY: Cranelift emitted exactly the declared C ABI and module owns the executable memory.
    let compiled: Compiled = unsafe { std::mem::transmute(address) };
    (module, compiled, started.elapsed(), bytes)
}

fn median(mut values: Vec<f64>) -> f64 {
    values.sort_by(f64::total_cmp);
    values[values.len() / 2]
}

fn main() {
    if std::env::args().any(|s| s == "--compile-scale") {
        let mut code = vec![Op::AddImm(0, 0, 1); 999];
        code.push(Op::Halt);
        let mut micros = Vec::new();
        let mut bytes = 0;
        for _ in 0..5 {
            let (_, _, time, size) = compile(&code);
            micros.push(time.as_micros() as f64);
            bytes = size;
        }
        println!(
            "compile_1000_ops_median_us={:.0} code_bytes={bytes}",
            median(micros)
        );
        #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
        {
            let mut micros = Vec::new();
            let mut bytes = 0;
            for _ in 0..5 {
                let (owner, _, time) = a64::compile(&code);
                micros.push(time.as_micros() as f64);
                bytes = owner.bytes;
            }
            println!(
                "a64_compile_1000_ops_median_us={:.0} code_bytes={bytes}",
                median(micros)
            );
        }
        return;
    }
    let n = std::env::args()
        .nth(1)
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(100_000);
    println!(
        "kernel,engine,ns_per_unit,beamlike_ops_per_unit,compile_us_per_1k_ops,code_bytes,result"
    );
    for (name, code, initial, expected, units) in programs(n) {
        let (_, op_count) = interpret(&code, &mut initial.clone());
        let fused_code = fuse(&code);
        let (module, compiled, compile_time, bytes) = compile(&code);
        let _keep_alive = &module;
        #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
        let (a64_owner, a64_compiled, a64_time) = a64::compile(&code);
        #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
        let _keep_a64_alive = &a64_owner;
        #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
        let engines = ["match", "fused", "cranelift", "a64"];
        #[cfg(not(all(target_arch = "aarch64", target_os = "macos")))]
        let engines = ["match", "fused", "cranelift"];
        for engine in engines {
            let mut times = Vec::new();
            for _ in 0..5 {
                let mut state = initial.clone();
                let started = Instant::now();
                let result = if engine == "cranelift" {
                    // SAFETY: Compiled code and state have matching ABI and live through the call.
                    unsafe { compiled(&mut state) }
                } else if engine == "a64" {
                    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
                    {
                        // SAFETY: The emitter uses the same State pointer ABI and its mapping is live.
                        unsafe { a64_compiled(&mut state) }
                    }
                    #[cfg(not(all(target_arch = "aarch64", target_os = "macos")))]
                    unreachable!()
                } else {
                    interpret(
                        if engine == "fused" {
                            &fused_code
                        } else {
                            &code
                        },
                        &mut state,
                    )
                    .0
                };
                let nanos = started.elapsed().as_nanos() as f64;
                assert_eq!(result, expected, "{name} {engine}");
                black_box(&state);
                times.push(nanos / units as f64);
            }
            println!(
                "{name},{engine},{:.3},{:.3},{:.1},{},{}",
                median(times),
                op_count as f64 / units as f64,
                if engine == "cranelift" {
                    compile_time.as_micros() as f64 * 1000.0 / code.len() as f64
                } else if engine == "a64" {
                    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
                    {
                        a64_time.as_micros() as f64 * 1000.0 / code.len() as f64
                    }
                    #[cfg(not(all(target_arch = "aarch64", target_os = "macos")))]
                    {
                        0.0
                    }
                } else {
                    0.0
                },
                if engine == "cranelift" {
                    bytes
                } else if engine == "a64" {
                    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
                    {
                        a64_owner.bytes
                    }
                    #[cfg(not(all(target_arch = "aarch64", target_os = "macos")))]
                    {
                        0
                    }
                } else {
                    0
                },
                expected
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_engines_agree_on_variant_sizes() {
        for n in [1, 3, 17, 1_001] {
            for (name, code, initial, expected, _) in programs(n) {
                let mut interpreted = initial.clone();
                assert_eq!(interpret(&code, &mut interpreted).0, expected, "{name} {n}");
                let mut fused = initial.clone();
                assert_eq!(
                    interpret(&fuse(&code), &mut fused).0,
                    expected,
                    "{name} {n}"
                );
                let (_module, compiled, _, _) = compile(&code);
                let mut native = initial.clone();
                // SAFETY: The compiled function and State use the same ABI.
                assert_eq!(unsafe { compiled(&mut native) }, expected, "{name} {n}");
                #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
                {
                    let (_owner, native, _) = a64::compile(&code);
                    let mut state = initial.clone();
                    // SAFETY: The emitter's mapping is alive and uses the State pointer ABI.
                    assert_eq!(unsafe { native(&mut state) }, expected, "{name} {n}");
                }
            }
        }
    }
}
